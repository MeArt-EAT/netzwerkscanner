"""Pfade, Einstellungen und Logging."""

from __future__ import annotations

import logging
import logging.handlers
import os
import sys
import threading
from dataclasses import asdict, dataclass, field, fields, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from netscan.core.db import Database

APP_NAME = "Netzwerkscanner"
DEFAULT_PORT = 8765

# Schul-Hotspot: jeder Scan gesperrt. Nicht entfernbar, nicht übergehbar (Pflichtenheft, Grundsatz 6).
PERMANENT_BLOCKED_SSIDS: tuple[str, ...] = ("DE22LA000256314 8159",)

# Netzgröße: /24 und kleiner normal, /22 und /23 mit Warnung, größer abgelehnt.
PREFIX_WARN = 24
PREFIX_MIN = 22

PACKAGE_DIR = Path(__file__).resolve().parent
STATIC_DIR = PACKAGE_DIR / "web" / "static"
BUNDLED_OUI = PACKAGE_DIR / "data" / "oui.tsv.gz"


def app_home() -> Path:
    """%LOCALAPPDATA%\\Netzwerkscanner bzw. ~/.local/share/netzwerkscanner."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / APP_NAME
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / APP_NAME.lower()


def data_dir() -> Path:
    """Datenordner: NETSCAN_DATA_DIR oder <app_home>/data. Wird angelegt."""
    env = os.environ.get("NETSCAN_DATA_DIR")
    path = Path(env) if env else app_home() / "data"
    path.mkdir(parents=True, exist_ok=True)
    return path


def db_path(base: Path | None = None) -> Path:
    return (base or data_dir()) / "netscan.sqlite3"


def log_dir(base: Path | None = None) -> Path:
    path = (base or data_dir()) / "logs"
    path.mkdir(parents=True, exist_ok=True)
    return path


@dataclass
class Settings:
    rate_pps: int = 200  # Pakete bzw. Verbindungsversuche pro Sekunde
    ping_timeout_ms: int = 600
    ping_workers: int = 32
    port_timeout_ms: int = 700
    port_workers: int = 64
    arp_timeout_s: float = 1.0  # Warten je ARP-Block; /24 bei 200 Paketen/s: 2 Blöcke, mit Wiederholung (0,5 s) ≈ 5–6 s
    arp_retries: int = 1
    names_timeout_s: float = 2.0
    mdns_timeout_s: float = 3.0
    ssdp_timeout_s: float = 3.0
    blocked_ssids_extra: list[str] = field(default_factory=list)
    blocked_gateway_macs: list[str] = field(default_factory=list)  # gelernt, über die API nur lesbar
    home_gateway_macs: list[str] = field(default_factory=list)
    port_scan_excluded_categories: list[str] = field(default_factory=list)
    # Freie Nutzung: nicht gesperrte Netze ohne Rückfrage scannen (Nutzerentscheidung 10.10.2026).
    # True = frühere Regel aus dem Pflichtenheft: fremde Netze nur nach Bestätigung, Heimnetz merken.
    ask_before_foreign_scan: bool = False
    last_adapter: str | None = None
    # Stufe 2 – Überwachung (BAUPLAN §28)
    monitor_enabled: bool = True
    monitor_interval_s: int = 60
    monitor_timeout_ms: int = 1000
    alert_offline_minutes: int = 5
    alert_service_minutes: int = 2
    alert_rtt_minutes: int = 5
    alert_new_device: bool = True
    alert_new_port: bool = True

    def blocked_ssids(self) -> set[str]:
        return set(PERMANENT_BLOCKED_SSIDS) | {s for s in self.blocked_ssids_extra if s}

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["permanent_blocked_ssids"] = list(PERMANENT_BLOCKED_SSIDS)
        return d


SETTING_LIMITS: dict[str, tuple[float, float]] = {
    "rate_pps": (10, 1000),
    "ping_timeout_ms": (100, 2000),
    "ping_workers": (1, 128),
    "port_timeout_ms": (100, 2000),
    "port_workers": (1, 256),
    "arp_timeout_s": (0.2, 2.0),
    "arp_retries": (0, 3),
    "names_timeout_s": (0.2, 2.0),
    "mdns_timeout_s": (0.5, 10.0),
    "ssdp_timeout_s": (0.5, 10.0),
    "monitor_interval_s": (10, 3600),
    "monitor_timeout_ms": (200, 2000),
    "alert_offline_minutes": (1, 1440),
    "alert_service_minutes": (1, 1440),
    "alert_rtt_minutes": (1, 1440),
}

# Ziel-Einstellungen der Überwachung (BAUPLAN §28): None = Standard bzw. aus
TARGET_LIMITS: dict[str, tuple[float, float]] = {
    "offline_after_min": (1, 1440),
    "rtt_threshold_ms": (1, 10000),
    "tcp_port": (1, 65535),
}
MAX_TARGETS = 64
MAX_CHECKS_PER_TARGET = 8
DB_WARN_BYTES = 100 * 1024 * 1024  # ab dieser Dateigröße warnt die Oberfläche (Plattenhygiene)

_FIELD_NAMES = {f.name for f in fields(Settings)}


class SettingsStore:
    """Lädt und speichert Settings in der Tabelle settings (thread-sicher)."""

    def __init__(self, db: Database) -> None:
        self._db = db
        self._lock = threading.RLock()

    def load(self) -> Settings:
        with self._lock:
            stored = self._db.all_settings()
            values = {k: v for k, v in stored.items() if k in _FIELD_NAMES}
            try:
                return replace(Settings(), **values)
            except TypeError:
                logging.getLogger(__name__).warning("Einstellungen unlesbar, nehme Standard")
                return Settings()

    def save(self, settings: Settings) -> None:
        with self._lock:
            for f in fields(Settings):
                self._db.set_setting(f.name, getattr(settings, f.name))

    def update(self, **changes: Any) -> Settings:
        """Ändert einzelne Felder; unbekannte Felder -> KeyError, Grenzen -> ValueError."""
        with self._lock:
            current = self.load()
            for key, value in changes.items():
                if key not in _FIELD_NAMES:
                    raise KeyError(key)
                if key in SETTING_LIMITS:
                    lo, hi = SETTING_LIMITS[key]
                    if not isinstance(value, (int, float)) or isinstance(value, bool) or not lo <= value <= hi:
                        raise ValueError(f"{key} muss zwischen {lo:g} und {hi:g} liegen")
            new = replace(current, **changes)
            self.save(new)
            return new

    def add_to_list(self, key: str, value: str) -> Settings:
        """Fügt einen Wert zu einer Listen-Einstellung hinzu (ohne Doppelte)."""
        with self._lock:
            current = self.load()
            items = list(getattr(current, key))
            if value not in items:
                items.append(value)
                return self.update(**{key: items})
            return current


def setup_logging(base: Path | None = None, level: int = logging.INFO, console: bool = True) -> Path:
    """Rotierendes Logfile (1 MB × 3) plus Konsole. Gibt den Pfad der Logdatei zurück."""
    path = log_dir(base) / "netscan.log"
    root = logging.getLogger()
    root.setLevel(level)
    for h in list(root.handlers):
        if getattr(h, "_netscan", False):
            root.removeHandler(h)
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    fh = logging.handlers.RotatingFileHandler(path, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    fh.setFormatter(fmt)
    fh._netscan = True  # type: ignore[attr-defined]
    root.addHandler(fh)
    if console:
        ch = logging.StreamHandler()
        ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%H:%M:%S"))
        ch._netscan = True  # type: ignore[attr-defined]
        root.addHandler(ch)
    return path
