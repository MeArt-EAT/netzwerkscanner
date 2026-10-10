"""Herstellerliste (IEEE OUI) und Erkennung zufälliger MAC-Adressen. (Agent discovery)

Mitgeliefert: netscan/data/oui.tsv.gz (Zeilen "AABBCC<TAB>Hersteller", Kommentarzeilen mit #).
Aktualisierung per Knopf: lädt https://standards-oui.ieee.org/oui/oui.csv und legt
<data_dir>/oui.tsv.gz an, das dann Vorrang hat.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"

# fetch(url) -> bytes; Standard: urllib mit Timeout und Browser-ähnlichem User-Agent
Fetcher = Callable[[str], bytes]


def is_random_mac(mac: str) -> bool:
    """True, wenn das Bit „locally administered“ gesetzt ist (private Adresse, z. B. Handys)."""
    raise NotImplementedError


class OuiDb:
    def __init__(self) -> None:
        self.entries: int = 0
        self.source: str = ""  # z. B. "mitgeliefert (Stand 2026-10-10)" oder "aktualisiert 2026-11-02"

    @classmethod
    def load(cls, data_dir: Path | None = None) -> OuiDb:
        """Lädt <data_dir>/oui.tsv.gz, falls vorhanden, sonst die mitgelieferte Liste."""
        raise NotImplementedError

    def lookup(self, mac: str) -> str | None:
        raise NotImplementedError


def update_from_ieee(data_dir: Path, fetch: Fetcher | None = None) -> int:
    """Lädt die IEEE-Liste, wandelt sie um und ersetzt <data_dir>/oui.tsv.gz atomar.
    Keine Rohdatei behalten. Gibt die Zahl der Einträge zurück."""
    raise NotImplementedError
