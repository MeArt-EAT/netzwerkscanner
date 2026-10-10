"""Autostart über die Windows-Aufgabenplanung, ohne Adminrechte (BAUPLAN §31). (Agent platform)

Eine Aufgabe „Netzwerkscanner“ startet den Server bei der Anmeldung (`schtasks /SC ONLOGON`) mit
`/RL LIMITED` – nie mit höchsten Rechten: Projektordner und Python-Umgebung sind ohne Adminrechte
beschreibbar, eine Aufgabe mit höchsten Rechten wäre eine dauerhafte Rechteausweitung.

`schtasks` wird nur über den Parameter `run` aufgerufen (Standard: `_default_run`), damit Tests die
echte Aufgabenplanung nie berühren. Außerhalb von Windows gibt es keinen Autostart (Hinweis auf systemd).
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import sys
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from netscan import config

log = logging.getLogger(__name__)

TASK_NAME = "Netzwerkscanner"

# run(args, timeout) -> (Rückgabecode, Standardausgabe als Text, Fehlerausgabe als Text)
RunFn = Callable[[list[str], float], tuple[int, str, str]]

RUN_TIMEOUT_S = 10.0  # schtasks ist lokal; 10 s reichen auch bei langsamem Start
MAX_COMMAND_LEN = 261  # Grenze von schtasks /TR
ERROR_DETAIL_MAX = 200  # Länge der bereinigten Fehlerausgabe in der Meldung
CREATE_NO_WINDOW = 0x08000000  # subprocess.CREATE_NO_WINDOW, gibt es nur unter Windows

UNSUPPORTED_DETAIL = "Unter Linux als systemd-Dienst einrichten (siehe README)."
ENABLED_DETAIL = "Der Scanner startet mit der Anmeldung, ohne Adminrechte (ARP-Scan dann nicht möglich)."
DISABLED_DETAIL = "Der Scanner startet nicht automatisch."
ADMIN_HINT = (
    "Windows verlangt dafür möglicherweise Adminrechte – den Scanner über start.bat starten "
    "und erneut versuchen."
)

_ACCESS_DENIED = re.compile(r"zugriff\b.{0,40}\bverweigert|access\s+(?:is\s+)?denied", re.IGNORECASE | re.DOTALL)


class AutostartError(RuntimeError):
    """Autostart ließ sich nicht ändern (deutsche Meldung für die Oberfläche)."""


@dataclass
class AutostartStatus:
    supported: bool
    enabled: bool = False
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class _Result:
    rc: int
    out: str
    err: str


# --- Befehle ausführen ------------------------------------------------------------------


def _decode(data: bytes | bytearray | str | None) -> str:
    """Bytes zu Text: UTF-8 strikt, sonst OEM-Codepage (Fallback cp850), errors="replace".

    schtasks schreibt in der OEM-Codepage (deutsch: cp850). Text in cp850 mit Umlauten ist praktisch
    nie gültiges UTF-8, daher ist die Reihenfolge sicher (wie in platform/windows.py).
    """
    if data is None:
        return ""
    if isinstance(data, str):
        return data.lstrip("\ufeff")
    if not isinstance(data, (bytes, bytearray)):
        return str(data)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = data.decode("oem", errors="replace")
        except LookupError:  # Codec "oem" gibt es nur unter Windows
            text = data.decode("cp850", errors="replace")
    return text.lstrip("\ufeff")


def _default_run(args: list[str], timeout: float) -> tuple[int, str, str]:
    """Startet einen Befehl ohne Konsolenfenster und ohne Shell; Ausgabe als Bytes, dann dekodiert."""
    kwargs: dict[str, Any] = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", CREATE_NO_WINDOW)
    proc = subprocess.run(
        args, capture_output=True, stdin=subprocess.DEVNULL, timeout=timeout, check=False, **kwargs
    )
    return proc.returncode, _decode(proc.stdout), _decode(proc.stderr)


def _schtasks_exe() -> str:
    """Voller Pfad %SystemRoot%\\System32\\schtasks.exe (kein Suchpfad-Trick möglich)."""
    root = os.environ.get("SystemRoot") or os.environ.get("windir") or r"C:\Windows"
    return root.rstrip("\\/") + "\\System32\\schtasks.exe"


def _exec(args: list[str], run: RunFn | None) -> _Result:
    """Ruft schtasks über `run` auf. Jeder Start- oder Zeitfehler wird zu AutostartError."""
    runner = run if run is not None else _default_run
    try:
        raw = runner(list(args), RUN_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        raise AutostartError(
            f"Die Aufgabenplanung (schtasks) hat nicht innerhalb von {RUN_TIMEOUT_S:.0f} s geantwortet."
        ) from None
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise AutostartError(
            f"Die Aufgabenplanung (schtasks) lässt sich nicht starten: {_clean(str(exc))}"
        ) from exc
    try:
        rc, out, err = raw
        return _Result(int(rc), _decode(out), _decode(err))
    except (TypeError, ValueError):
        raise AutostartError("Die Aufgabenplanung (schtasks) lieferte keine auswertbare Antwort.") from None


# --- Texte bereinigen --------------------------------------------------------------------


def _clean(text: str, limit: int = ERROR_DETAIL_MAX) -> str:
    """Eine Zeile ohne Steuerzeichen, höchstens `limit` Zeichen (mit „…“, wenn gekürzt)."""
    flat = " ".join("".join(ch if ch.isprintable() else " " for ch in text).split())
    if len(flat) > limit:
        flat = flat[: max(limit - 1, 0)].rstrip() + "…"
    return flat


def _failure(action: str, result: _Result) -> AutostartError:
    """Deutsche Fehlermeldung aus einem fehlgeschlagenen schtasks-Aufruf."""
    raw = result.err if result.err.strip() else result.out
    message = f"{action} (schtasks, Code {result.rc})"
    detail = _clean(raw)
    if detail:
        message += f": {detail}"
    if _ACCESS_DENIED.search(raw):  # auf dem Rohtext prüfen, damit Kürzen den Hinweis nicht verliert
        if not message.endswith((".", "!", "?", "…")):
            message += "."
        message += f" {ADMIN_HINT}"
    return AutostartError(message)


# --- Befehl der Aufgabe -------------------------------------------------------------------


def _check_path(path: str, what: str) -> None:
    if '"' in path or any(ord(ch) < 32 or 127 <= ord(ch) <= 159 for ch in path):
        raise AutostartError(
            f"{what} enthält Anführungszeichen oder Steuerzeichen und lässt sich nicht für den "
            f"Autostart verwenden: {_clean(path, 80)}"
        )


def _build_task_command(python_exe: str, script: str) -> str:
    """Befehl der Aufgabe: "<python>" "<run_server.py>" --no-browser. Prüft Zeichen und Länge."""
    _check_path(python_exe, "Der Pfad des Python-Programms")
    _check_path(script, "Der Pfad des Startskripts")
    command = f'"{python_exe}" "{script}" --no-browser'
    if len(command) > MAX_COMMAND_LEN:
        raise AutostartError(
            f"Der Autostart-Befehl ist {len(command)} Zeichen lang; die Aufgabenplanung erlaubt höchstens "
            f"{MAX_COMMAND_LEN} (Grenze von schtasks /TR). Den Projektordner an einen kürzeren Pfad "
            "verschieben (z. B. C:\\Netzwerkscanner) und erneut versuchen."
        )
    return command


def _python_for_task() -> str:
    """pythonw.exe (ohne Konsolenfenster) neben dem laufenden Python, sonst dieses Python selbst."""
    exe = sys.executable
    if not exe:
        raise AutostartError("Das laufende Python-Programm ist nicht ermittelbar – Autostart nicht möglich.")
    windowless = os.path.join(os.path.dirname(exe), "pythonw.exe")
    return windowless if os.path.isfile(windowless) else exe


def _task_command() -> str:
    """Befehl für den aktuellen Projektordner (config.PACKAGE_DIR.parent) und die laufende Python-Umgebung."""
    project = Path(config.PACKAGE_DIR).parent
    script = os.path.join(str(project), "run_server.py")
    if not os.path.isfile(script):
        raise AutostartError(
            f"Das Startskript run_server.py fehlt im Projektordner: {_clean(str(project), 120)}"
        )
    return _build_task_command(_python_for_task(), script)


# --- Öffentliche Funktionen ---------------------------------------------------------------


def _is_windows() -> bool:
    return sys.platform == "win32"


def autostart_status(*, run: RunFn | None = None) -> AutostartStatus:
    """Ist die Aufgabe eingerichtet? Wirft nie: ein Fehler der Aufgabenplanung steht im `detail`."""
    if not _is_windows():
        return AutostartStatus(supported=False, enabled=False, detail=UNSUPPORTED_DETAIL)
    try:
        result = _exec([_schtasks_exe(), "/Query", "/TN", TASK_NAME], run)
    except AutostartError as exc:
        log.warning("Autostart-Abfrage fehlgeschlagen: %s", exc)
        return AutostartStatus(supported=True, enabled=False, detail=str(exc))
    if result.rc == 0:
        return AutostartStatus(supported=True, enabled=True, detail=ENABLED_DETAIL)
    return AutostartStatus(supported=True, enabled=False, detail=DISABLED_DETAIL)


def set_autostart(enabled: bool, *, run: RunFn | None = None) -> AutostartStatus:
    """Aufgabe anlegen (ONLOGON, LIMITED) oder entfernen; gibt den neuen Zustand zurück."""
    if not isinstance(enabled, bool):
        raise AutostartError("Ungültiger Wert für den Autostart (erwartet: an oder aus).")
    if not _is_windows():
        raise AutostartError(f"Autostart über die Aufgabenplanung gibt es nur unter Windows. {UNSUPPORTED_DETAIL}")
    if enabled:
        return _create(run)
    return _remove(run)


def _task_user() -> str:
    """Konto der Aufgabe: der angemeldete Benutzer (DOMÄNE und Name). Mit /IT läuft die Aufgabe nur, wenn dieser
    Benutzer angemeldet ist, und braucht kein gespeichertes Kennwort (Leitungsentscheidung 10.10.2026)."""
    name = (os.environ.get("USERNAME") or "").strip()
    domain = (os.environ.get("USERDOMAIN") or "").strip()
    user = domain + "\\" + name if domain and name else name
    if not name or any(ord(ch) < 32 or ch in '"/' for ch in user):
        raise AutostartError("Der angemeldete Benutzer ist nicht ermittelbar – Autostart nicht möglich.")
    return user


def _create(run: RunFn | None) -> AutostartStatus:
    command = _task_command()  # prüft Pfade und Länge, bevor schtasks überhaupt gestartet wird
    args = [
        _schtasks_exe(), "/Create", "/TN", TASK_NAME, "/SC", "ONLOGON", "/RL", "LIMITED",
        "/RU", _task_user(), "/IT", "/F", "/TR", command,
    ]
    result = _exec(args, run)
    if result.rc != 0:
        raise _failure("Der Autostart konnte nicht eingerichtet werden", result)
    log.info("Autostart eingerichtet: %s", command)
    return AutostartStatus(supported=True, enabled=True, detail=ENABLED_DETAIL)


def _remove(run: RunFn | None) -> AutostartStatus:
    result = _exec([_schtasks_exe(), "/Delete", "/TN", TASK_NAME, "/F"], run)
    if result.rc != 0:
        # Die Fehlertexte sind sprachabhängig: ob die Aufgabe gar nicht existiert, zeigt nur die Abfrage.
        try:
            still_there = _exec([_schtasks_exe(), "/Query", "/TN", TASK_NAME], run).rc == 0
        except AutostartError:
            still_there = True  # Zustand unklar: den ursprünglichen Fehler melden, nicht Erfolg vortäuschen
        if still_there:
            raise _failure("Der Autostart konnte nicht entfernt werden", result)
        log.debug("Autostart war nicht eingerichtet, nichts zu entfernen")
    else:
        log.info("Autostart entfernt")
    return AutostartStatus(supported=True, enabled=False, detail=DISABLED_DETAIL)
