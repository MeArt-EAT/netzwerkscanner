"""Schema 2: neue Datenbank, Erweiterung einer Datenbank aus Stufe 1, geprüfte Ports (BAUPLAN §20, §26)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from netscan.core.db import SCHEMA_VERSION, Database
from netscan.core.inventory import Inventory
from netscan.core.models import Device, PortResult

# Schema von Stufe 1 (Stand v1.0-stufe1-rc3), gekürzt auf das, was die Erweiterung berührt
V1_SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE devices (
    mac TEXT PRIMARY KEY, ip TEXT NOT NULL, vendor TEXT, mac_random INTEGER NOT NULL DEFAULT 0, hostname TEXT,
    names_json TEXT NOT NULL DEFAULT '{}', ssdp_json TEXT, category TEXT NOT NULL DEFAULT 'unknown',
    category_source TEXT NOT NULL DEFAULT 'auto', category_reason TEXT NOT NULL DEFAULT '', custom_name TEXT,
    note TEXT NOT NULL DEFAULT '', known INTEGER NOT NULL DEFAULT 0, is_gateway INTEGER NOT NULL DEFAULT 0,
    is_self INTEGER NOT NULL DEFAULT 0, port_scan_excluded INTEGER NOT NULL DEFAULT 0, rtt_ms REAL, ttl INTEGER,
    discovered_by TEXT NOT NULL DEFAULT '', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    first_seen_scan INTEGER, last_seen_scan INTEGER
);
CREATE TABLE ports (
    mac TEXT NOT NULL REFERENCES devices(mac) ON DELETE CASCADE, port INTEGER NOT NULL, proto TEXT NOT NULL DEFAULT 'tcp',
    service TEXT NOT NULL DEFAULT '', risk TEXT NOT NULL DEFAULT 'low', reason TEXT NOT NULL DEFAULT '', banner TEXT,
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, PRIMARY KEY (mac, port, proto)
);
CREATE TABLE scans (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, adapter TEXT, network TEXT,
    started TEXT NOT NULL, finished TEXT, result TEXT, device_count INTEGER NOT NULL DEFAULT 0);
CREATE TABLE scan_log (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER, ts TEXT NOT NULL, level TEXT NOT NULL,
    message TEXT NOT NULL);
INSERT INTO meta VALUES ('schema_version', '1');
INSERT INTO devices(mac, ip, custom_name, known, first_seen, last_seen, first_seen_scan, last_seen_scan)
    VALUES ('00:11:32:aa:bb:03', '192.168.178.3', 'NAS im Keller', 1, '2026-10-10T12:00:00+00:00',
            '2026-10-10T12:00:00+00:00', 1, 1);
INSERT INTO ports(mac, port, service, first_seen, last_seen)
    VALUES ('00:11:32:aa:bb:03', 445, 'smb', '2026-10-10T12:00:00+00:00', '2026-10-10T12:00:00+00:00');
"""

V2_TABLES = {"monitor_targets", "service_checks", "samples", "samples_hourly", "alerts"}


def _tables(db: Database) -> set[str]:
    return {r["name"] for r in db.query("SELECT name FROM sqlite_master WHERE type = 'table'")}


def test_new_database_has_schema_2(tmp_path: Path) -> None:
    db = Database(tmp_path / "neu.sqlite3")
    try:
        assert SCHEMA_VERSION == 2
        assert db.query_one("SELECT value FROM meta WHERE key = 'schema_version'")["value"] == "2"
        assert V2_TABLES <= _tables(db)
        cols = {r["name"] for r in db.query("PRAGMA table_info(devices)")}
        assert "checked_ports" in cols
    finally:
        db.close()


def test_stage1_database_is_extended_without_data_loss(tmp_path: Path) -> None:
    path = tmp_path / "alt.sqlite3"
    conn = sqlite3.connect(path)
    conn.executescript(V1_SCHEMA)
    conn.commit()
    conn.close()

    db = Database(path)
    try:
        assert db.query_one("SELECT value FROM meta WHERE key = 'schema_version'")["value"] == "2"
        assert V2_TABLES <= _tables(db)
        inv = Inventory(db)
        nas = inv.get("00:11:32:aa:bb:03")
        assert nas is not None and nas.custom_name == "NAS im Keller" and nas.known
        assert [p.port for p in nas.ports] == [445]
        assert inv.checked_ports(nas.mac) == set()  # unbekannt, welche Ports früher geprüft wurden
    finally:
        db.close()
    # zweites Öffnen ändert nichts mehr
    db = Database(path)
    try:
        assert db.query_one("SELECT value FROM meta WHERE key = 'schema_version'")["value"] == "2"
    finally:
        db.close()


def test_newer_schema_is_left_alone(tmp_path: Path) -> None:
    db = Database(tmp_path / "x.sqlite3")
    db.execute("UPDATE meta SET value = '9' WHERE key = 'schema_version'")
    db.close()
    db = Database(tmp_path / "x.sqlite3")
    try:
        assert db.query_one("SELECT value FROM meta WHERE key = 'schema_version'")["value"] == "9"
    finally:
        db.close()


def test_checked_ports_accumulate(tmp_path: Path) -> None:
    db = Database(tmp_path / "p.sqlite3")
    try:
        inv = Inventory(db)
        scan = inv.begin_scan("scan", "Ethernet", "192.168.178.0/24")
        inv.record_seen(Device(mac="00:11:32:aa:bb:03", ip="192.168.178.3"), scan)
        assert inv.checked_ports("00:11:32:aa:bb:03") == set()
        inv.set_ports("00:11:32:aa:bb:03", [22, 80, 445], [PortResult(445, service="smb")])
        inv.set_ports("00:11:32:aa:bb:03", [80, 8080], [])
        assert inv.checked_ports("00:11:32:aa:bb:03") == {22, 80, 445, 8080}
        assert inv.checked_ports("kaputt") == set()
        # Unsinn in der Datenbank (beschreibbarer Datenordner) wird übergangen
        db.execute("UPDATE devices SET checked_ports = '22,abc,,99999,-1,80' WHERE mac = '00:11:32:aa:bb:03'")
        assert inv.checked_ports("00:11:32:aa:bb:03") == {22, 80}
    finally:
        db.close()


def test_size_bytes_is_positive(tmp_path: Path) -> None:
    db = Database(tmp_path / "s.sqlite3")
    try:
        assert db.size_bytes() > 0
    finally:
        db.close()


def test_one_active_alert_per_key(tmp_path: Path) -> None:
    db = Database(tmp_path / "a.sqlite3")
    try:
        ins = "INSERT INTO alerts(rule, key, severity, title, opened, closed) VALUES('device_offline', 'k', 'warning', 't', 'x', ?)"
        db.execute(ins, (None,))
        try:
            db.execute(ins, (None,))
            raised = False
        except sqlite3.IntegrityError:
            raised = True
        assert raised, "zwei aktive Alerts mit gleichem Schlüssel dürfen nicht möglich sein"
        db.execute("UPDATE alerts SET closed = 'y' WHERE key = 'k'")
        db.execute(ins, (None,))  # nach dem Schließen wieder möglich
    finally:
        db.close()
