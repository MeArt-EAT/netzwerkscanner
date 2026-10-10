"""SQLite-Verbindung, Schema und Einstellungs-Tabelle. Geräte-Logik steht in inventory.py."""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL              -- JSON
);
CREATE TABLE IF NOT EXISTS devices (
    mac                TEXT PRIMARY KEY,
    ip                 TEXT NOT NULL,
    vendor             TEXT,
    mac_random         INTEGER NOT NULL DEFAULT 0,
    hostname           TEXT,
    names_json         TEXT NOT NULL DEFAULT '{}',
    ssdp_json          TEXT,
    category           TEXT NOT NULL DEFAULT 'unknown',
    category_source    TEXT NOT NULL DEFAULT 'auto',
    category_reason    TEXT NOT NULL DEFAULT '',
    custom_name        TEXT,
    note               TEXT NOT NULL DEFAULT '',
    known              INTEGER NOT NULL DEFAULT 0,
    is_gateway         INTEGER NOT NULL DEFAULT 0,
    is_self            INTEGER NOT NULL DEFAULT 0,
    port_scan_excluded INTEGER NOT NULL DEFAULT 0,
    rtt_ms             REAL,
    ttl                INTEGER,
    discovered_by      TEXT NOT NULL DEFAULT '',   -- kommagetrennt
    first_seen         TEXT NOT NULL,
    last_seen          TEXT NOT NULL,
    first_seen_scan    INTEGER,
    last_seen_scan     INTEGER
);
CREATE TABLE IF NOT EXISTS ports (
    mac        TEXT NOT NULL REFERENCES devices(mac) ON DELETE CASCADE,
    port       INTEGER NOT NULL,
    proto      TEXT NOT NULL DEFAULT 'tcp',
    service    TEXT NOT NULL DEFAULT '',
    risk       TEXT NOT NULL DEFAULT 'low',
    reason     TEXT NOT NULL DEFAULT '',
    banner     TEXT,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    PRIMARY KEY (mac, port, proto)
);
CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    kind         TEXT NOT NULL,
    adapter      TEXT,
    network      TEXT,
    started      TEXT NOT NULL,
    finished     TEXT,
    result       TEXT,
    device_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS scan_log (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER,
    ts      TEXT NOT NULL,
    level   TEXT NOT NULL,
    message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scan_log_scan ON scan_log(scan_id);
CREATE INDEX IF NOT EXISTS idx_ports_mac ON ports(mac);
"""


class Database:
    """Eine Verbindung für alle Threads, geschützt durch eine Sperre."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        if str(path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None, timeout=10)
        self.conn.row_factory = sqlite3.Row
        with self.lock:
            self.conn.execute("PRAGMA foreign_keys = ON")
            if str(path) != ":memory:":
                self.conn.execute("PRAGMA journal_mode = WAL")
            self.conn.execute("PRAGMA synchronous = NORMAL")
            self._migrate()

    def _migrate(self) -> None:
        self.conn.executescript(SCHEMA)
        row = self.conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
        current = int(row["value"]) if row else 0
        if current < SCHEMA_VERSION:
            # spätere Stufen: hier schrittweise ALTER TABLE / neue Tabellen
            self.conn.execute(
                "INSERT INTO meta(key, value) VALUES('schema_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (str(SCHEMA_VERSION),),
            )

    # --- Zugriff -------------------------------------------------------------
    def execute(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> sqlite3.Cursor:
        with self.lock:
            return self.conn.execute(sql, params)

    def executemany(self, sql: str, rows: Sequence[Sequence[Any]]) -> None:
        with self.lock:
            self.conn.executemany(sql, rows)

    def query(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> list[sqlite3.Row]:
        with self.lock:
            return self.conn.execute(sql, params).fetchall()

    def query_one(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> sqlite3.Row | None:
        with self.lock:
            return self.conn.execute(sql, params).fetchone()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """with db.transaction() as conn: ... – alles oder nichts."""
        with self.lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                yield self.conn
            except BaseException:
                self.conn.execute("ROLLBACK")
                raise
            else:
                self.conn.execute("COMMIT")

    def close(self) -> None:
        with self.lock:
            self.conn.close()

    # --- Einstellungen (JSON-Werte) -----------------------------------------
    def get_setting(self, key: str, default: Any = None) -> Any:
        row = self.query_one("SELECT value FROM settings WHERE key = ?", (key,))
        if row is None:
            return default
        try:
            return json.loads(row["value"])
        except json.JSONDecodeError:
            log.warning("Einstellung %s ist beschädigt, nehme Standard", key)
            return default

    def set_setting(self, key: str, value: Any) -> None:
        self.execute(
            "INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, json.dumps(value, ensure_ascii=False)),
        )

    def all_settings(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for row in self.query("SELECT key, value FROM settings"):
            try:
                out[row["key"]] = json.loads(row["value"])
            except json.JSONDecodeError:
                log.warning("Einstellung %s ist beschädigt, wird ignoriert", row["key"])
        return out
