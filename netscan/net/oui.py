"""Herstellerliste (IEEE OUI) und Erkennung zufälliger MAC-Adressen. (Agent discovery)

Mitgeliefert: netscan/data/oui.tsv.gz (Zeilen "AABBCC<TAB>Hersteller", Kommentarzeilen mit #).
Aktualisierung per Knopf: lädt https://standards-oui.ieee.org/oui/oui.csv und legt
<data_dir>/oui.tsv.gz an, das dann Vorrang hat.
"""

from __future__ import annotations

import contextlib
import csv
import gzip
import http.client
import io
import logging
import os
import re
import tempfile
import time
import urllib.error
import urllib.request
import zlib
from collections.abc import Callable, Iterable
from datetime import date, datetime
from pathlib import Path

from netscan.config import BUNDLED_OUI
from netscan.core.context import ScanContext
from netscan.core.models import normalize_mac

log = logging.getLogger(__name__)

OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"
OUI_FILE = "oui.tsv.gz"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Netzwerkscanner-OUI-Update"
# Zeitgrenze je Socket-Operation (Verbindung, TLS, jedes Lesen). Kurz, damit ein Abbruch binnen 5 s greift
# (BAUPLAN §6); zwischen den Blöcken wird ctx.check_cancel() geprüft.
FETCH_TIMEOUT_S = 4.0
FETCH_TOTAL_S = 180.0  # Obergrenze für den ganzen Download (rund 6 MB)
FETCH_CHUNK = 64 * 1024
MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024  # die echte Liste hat rund 6 MB

# fetch(url) -> bytes; Standard: urllib mit Timeout und Browser-ähnlichem User-Agent
Fetcher = Callable[[str], bytes]

_PREFIX_RE = re.compile(r"[0-9A-F]{6}")
_STAND_RE = re.compile(r"Stand\s+(\d{4}-\d{2}-\d{2})")


def is_random_mac(mac: str) -> bool:
    """True, wenn das Bit „locally administered“ gesetzt ist (private Adresse, z. B. Handys)."""
    try:
        first_octet = int(normalize_mac(mac)[:2], 16)
    except ValueError:
        return False
    return bool(first_octet & 0x02)


def _parse_tsv(lines: Iterable[str]) -> tuple[dict[str, str], str | None]:
    """Liest "AABBCC<TAB>Hersteller"-Zeilen. Gibt (Tabelle, Datum aus der Kopfzeile) zurück."""
    table: dict[str, str] = {}
    stand: str | None = None
    for raw in lines:
        line = raw.rstrip("\r\n")
        if not line.strip():
            continue
        if line.lstrip().startswith("#"):
            if stand is None:
                found = _STAND_RE.search(line)
                if found:
                    stand = found.group(1)
            continue
        prefix, sep, vendor = line.partition("\t")
        prefix = prefix.strip().upper()
        vendor = vendor.strip()
        if sep and vendor and _PREFIX_RE.fullmatch(prefix):
            table[prefix] = vendor
    return table, stand


def _read_file(path: Path) -> tuple[dict[str, str], str | None]:
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
        return _parse_tsv(handle)


def _file_date(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime).date().isoformat()


class OuiDb:
    def __init__(self) -> None:
        self.entries: int = 0
        self.source: str = ""  # z. B. "mitgeliefert (Stand 2026-10-10)" oder "aktualisiert 2026-11-02"
        self._table: dict[str, str] = {}

    @classmethod
    def load(cls, data_dir: Path | None = None) -> OuiDb:
        """Lädt <data_dir>/oui.tsv.gz, falls vorhanden, sonst die mitgelieferte Liste."""
        db = cls()
        if data_dir is not None:
            updated = Path(data_dir) / OUI_FILE
            if updated.is_file():
                try:
                    table, _stand = _read_file(updated)
                    if table:
                        db._table = table
                        db.entries = len(table)
                        db.source = f"aktualisiert {_file_date(updated)}"
                        return db
                    log.warning("Herstellerliste %s ist leer, nehme die mitgelieferte.", updated)
                except (OSError, EOFError, zlib.error):
                    log.warning("Herstellerliste %s ist unlesbar, nehme die mitgelieferte.", updated, exc_info=True)
        try:
            table, stand = _read_file(Path(BUNDLED_OUI))
        except (OSError, EOFError, zlib.error):
            log.warning("Mitgelieferte Herstellerliste %s ist nicht lesbar.", BUNDLED_OUI, exc_info=True)
            table, stand = {}, None
        db._table = table
        db.entries = len(table)
        if not table:
            db.source = "keine Herstellerliste gefunden"
        else:
            db.source = f"mitgeliefert (Stand {stand})" if stand else "mitgeliefert"
        return db

    def lookup(self, mac: str) -> str | None:
        """Hersteller zur MAC. Zufällige (private) und ungültige Adressen sowie Unbekanntes ergeben None."""
        try:
            normalized = normalize_mac(mac)
        except ValueError:
            return None
        if is_random_mac(normalized):
            return None
        return self._table.get(normalized.replace(":", "")[:6].upper())


# --- Aktualisierung ------------------------------------------------------------


def _default_fetch(url: str, ctx: ScanContext | None = None) -> bytes:
    """Lädt die Liste per urllib (Browser-ähnlicher User-Agent).

    Gelesen wird in Blöcken mit kurzer Zeitgrenze je Socket-Operation; vor jedem Block prüft
    ctx.check_cancel() den Abbruch. Die Gesamtzeit ist auf FETCH_TOTAL_S begrenzt.
    """
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    deadline = time.monotonic() + FETCH_TOTAL_S
    chunks: list[bytes] = []
    size = 0
    try:
        if ctx is not None:
            ctx.check_cancel()
        with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT_S) as response:
            while True:
                if ctx is not None:
                    ctx.check_cancel()
                if time.monotonic() > deadline:
                    raise TimeoutError("der Download dauert zu lange")
                chunk = response.read1(FETCH_CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_DOWNLOAD_BYTES:
                    raise ValueError("Die heruntergeladene Herstellerliste ist unerwartet groß und wird verworfen.")
                chunks.append(chunk)
    except (urllib.error.URLError, TimeoutError, http.client.HTTPException) as exc:
        reason = getattr(exc, "reason", None) or exc
        raise OSError(f"Die Herstellerliste konnte nicht geladen werden: {reason}") from exc
    return b"".join(chunks)


def _parse_ieee_csv(raw: bytes) -> dict[str, str]:
    """Liest die IEEE-CSV (Spalten Assignment / Organization Name, mit Anführungszeichen)."""
    text = raw.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text, newline=""))
    columns = {(name or "").strip().lower(): name for name in (reader.fieldnames or [])}
    if "assignment" not in columns or "organization name" not in columns:
        raise ValueError(
            "Die heruntergeladene Datei hat nicht das erwartete Format "
            "(Spalten „Assignment“ und „Organization Name“ fehlen). Die bisherige Liste bleibt erhalten."
        )
    assignment_key, name_key = columns["assignment"], columns["organization name"]
    table: dict[str, str] = {}
    for row in reader:
        prefix = (row.get(assignment_key) or "").strip().upper()
        vendor = re.sub(r"[\t\r\n]+", " ", row.get(name_key) or "").strip()
        if vendor and _PREFIX_RE.fullmatch(prefix):
            table[prefix] = vendor
    return table


def update_from_ieee(
    data_dir: Path, fetch: Fetcher | None = None, *, min_entries: int = 10000, ctx: ScanContext | None = None
) -> int:
    """Lädt die IEEE-Liste, wandelt sie um und ersetzt <data_dir>/oui.tsv.gz atomar.
    Keine Rohdatei behalten. Gibt die Zahl der Einträge zurück. Zu kleine oder unbrauchbare Listen
    (weniger als min_entries) ergeben ValueError; die alte Liste bleibt dann unverändert.

    Mit ctx ist die Aktualisierung abbrechbar (ScanCancelled): während des Downloads je Block und noch
    einmal direkt vor dem Ersetzen der Datei – ein abgebrochener Auftrag ändert die Liste nie."""
    if fetch is not None:
        raw = fetch(OUI_URL)
    elif ctx is not None:
        raw = _default_fetch(OUI_URL, ctx)
    else:
        raw = _default_fetch(OUI_URL)
    if ctx is not None:
        ctx.check_cancel()
    table = _parse_ieee_csv(raw)
    if len(table) < min_entries:
        raise ValueError(
            f"Die heruntergeladene Herstellerliste hat nur {len(table)} Einträge "
            f"(mindestens {min_entries} erwartet). Die bisherige Liste bleibt erhalten."
        )
    folder = Path(data_dir)
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / OUI_FILE
    handle, tmp_name = tempfile.mkstemp(prefix="oui-", suffix=".tmp", dir=folder)
    os.close(handle)
    try:
        with gzip.open(tmp_name, "wt", encoding="utf-8", newline="\n") as out:
            out.write(f"# IEEE MA-L (oui.csv) - Quelle: {OUI_URL} - Stand {date.today().isoformat()}\n")
            for prefix in sorted(table):
                out.write(f"{prefix}\t{table[prefix]}\n")
        if ctx is not None:
            ctx.check_cancel()  # letzte Gelegenheit: danach ist die neue Liste in Kraft
        os.replace(tmp_name, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise
    return len(table)
