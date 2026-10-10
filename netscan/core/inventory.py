"""Inventar: Geräte, Ports, Scans und Scan-Protokoll in SQLite.

Grundsatz: Jedes Gerät wird über seine MAC-Adresse wiedererkannt. Nutzerfelder
(custom_name, note, known, category bei category_source == "user", port_scan_excluded)
überschreibt ein Scan nie.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from typing import Any

from netscan.core.db import Database
from netscan.core.models import (
    CATEGORIES,
    Device,
    NameInfo,
    PortResult,
    SsdpInfo,
    normalize_mac,
    utc_now_iso,
)

LOG_KEEP_SCANS = 50  # Protokolle nur der letzten 50 Scans behalten
USER_FIELDS = ("custom_name", "category", "note", "known", "port_scan_excluded")


class Inventory:
    def __init__(self, db: Database) -> None:
        self.db = db

    # --- Scans und Protokoll ---------------------------------------------------
    def begin_scan(self, kind: str, adapter: str | None, network: str | None) -> int:
        cur = self.db.execute(
            "INSERT INTO scans(kind, adapter, network, started) VALUES(?, ?, ?, ?)",
            (kind, adapter, network, utc_now_iso()),
        )
        return int(cur.lastrowid)

    def finish_scan(self, scan_id: int, result: str, device_count: int) -> None:
        """Schließt den Scan ab und löscht Protokolle von Scans außerhalb der letzten LOG_KEEP_SCANS."""
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE scans SET finished = ?, result = ?, device_count = ? WHERE id = ?",
                (utc_now_iso(), result, device_count, scan_id),
            )
            conn.execute(
                "DELETE FROM scan_log WHERE scan_id IS NOT NULL AND scan_id NOT IN "
                "(SELECT id FROM scans ORDER BY id DESC LIMIT ?)",
                (LOG_KEEP_SCANS,),
            )
            # Einträge ohne Scan (z. B. Herstellerliste) ebenfalls begrenzen
            conn.execute(
                "DELETE FROM scan_log WHERE scan_id IS NULL AND id NOT IN "
                "(SELECT id FROM scan_log WHERE scan_id IS NULL ORDER BY id DESC LIMIT 1000)"
            )

    def latest_scan_id(self, kind: str = "scan", result: str = "completed") -> int | None:
        row = self.db.query_one(
            "SELECT id FROM scans WHERE kind = ? AND result = ? ORDER BY id DESC LIMIT 1", (kind, result)
        )
        return int(row["id"]) if row else None

    def list_scans(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.db.query("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(r) for r in rows]

    def add_log(self, scan_id: int | None, level: str, message: str) -> None:
        self.db.execute(
            "INSERT INTO scan_log(scan_id, ts, level, message) VALUES(?, ?, ?, ?)",
            (scan_id, utc_now_iso(), level, message),
        )

    def get_log(self, scan_id: int | None = None, limit: int = 500) -> list[dict[str, Any]]:
        """Neueste zuletzt. Einträge: {id, scan_id, ts, level, message}."""
        if scan_id is None:
            rows = self.db.query("SELECT * FROM scan_log ORDER BY id DESC LIMIT ?", (limit,))
        else:
            rows = self.db.query("SELECT * FROM scan_log WHERE scan_id = ? ORDER BY id DESC LIMIT ?", (scan_id, limit))
        return [dict(r) for r in reversed(rows)]

    # --- Geräte ----------------------------------------------------------------
    def merge_user_fields(self, device: Device) -> Device:
        """Übernimmt gespeicherte Nutzerfelder und first_seen* in das (neu gefundene) Gerät."""
        row = self.db.query_one("SELECT * FROM devices WHERE mac = ?", (normalize_mac(device.mac),))
        if row is None:
            return device
        device.custom_name = row["custom_name"]
        device.note = row["note"] or ""
        device.known = bool(row["known"])
        device.port_scan_excluded = bool(row["port_scan_excluded"])
        if row["category_source"] == "user":
            device.category = row["category"]
            device.category_source = "user"
        device.first_seen = row["first_seen"]
        device.first_seen_scan = row["first_seen_scan"]
        return device

    def record_seen(self, device: Device, scan_id: int) -> Device:
        """Upsert nach einem Scan. Nutzerfelder bleiben. Ports werden hier NICHT gespeichert."""
        mac = normalize_mac(device.mac)
        now = utc_now_iso()
        names_json = json.dumps(device.names.to_dict(), ensure_ascii=False)
        ssdp_json = json.dumps(device.ssdp.to_dict(), ensure_ascii=False) if device.ssdp else None
        discovered = ",".join(dict.fromkeys(device.discovered_by))
        with self.db.transaction() as conn:
            row = conn.execute("SELECT category_source FROM devices WHERE mac = ?", (mac,)).fetchone()
            if row is None:
                conn.execute(
                    """INSERT INTO devices(mac, ip, vendor, mac_random, hostname, names_json, ssdp_json,
                       category, category_source, category_reason, custom_name, note, known, is_gateway, is_self,
                       port_scan_excluded, rtt_ms, ttl, discovered_by, first_seen, last_seen, first_seen_scan, last_seen_scan)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        mac, device.ip, device.vendor, int(device.mac_random), device.hostname, names_json, ssdp_json,
                        device.category, device.category_source, device.category_reason, device.custom_name,
                        device.note or "", int(device.known), int(device.is_gateway), int(device.is_self),
                        int(device.port_scan_excluded), device.rtt_ms, device.ttl, discovered, now, now, scan_id, scan_id,
                    ),
                )
            else:
                params: dict[str, Any] = {
                    "mac": mac, "ip": device.ip, "vendor": device.vendor, "mac_random": int(device.mac_random),
                    "hostname": device.hostname, "names_json": names_json, "ssdp_json": ssdp_json,
                    "is_gateway": int(device.is_gateway), "is_self": int(device.is_self), "rtt_ms": device.rtt_ms,
                    "ttl": device.ttl, "discovered_by": discovered, "last_seen": now, "scan_id": scan_id,
                    "category": device.category, "category_reason": device.category_reason,
                }
                category_sql = ""
                if row["category_source"] != "user":
                    category_sql = ", category = :category, category_reason = :category_reason"
                conn.execute(
                    f"""UPDATE devices SET ip = :ip, vendor = :vendor, mac_random = :mac_random, hostname = :hostname,
                        names_json = :names_json, ssdp_json = :ssdp_json, is_gateway = :is_gateway, is_self = :is_self,
                        rtt_ms = :rtt_ms, ttl = :ttl, discovered_by = :discovered_by, last_seen = :last_seen,
                        last_seen_scan = :scan_id{category_sql}
                        WHERE mac = :mac""",
                    params,
                )
        stored = self.get(mac)
        assert stored is not None
        return stored

    def checked_ports(self, mac: str) -> set[int]:
        """Alle Ports, die je für dieses Gerät geprüft wurden (Stufe 2: Grundlage für „neuer offener Port“)."""
        try:
            mac = normalize_mac(mac)
        except ValueError:
            return set()
        row = self.db.query_one("SELECT checked_ports FROM devices WHERE mac = ?", (mac,))
        return _parse_port_list(row["checked_ports"]) if row is not None else set()

    def set_ports(self, mac: str, scanned_ports: Iterable[int], open_ports: list[PortResult]) -> list[PortResult]:
        """Speichert offene Ports. Löscht nur geprüfte Ports, die nicht mehr offen sind.
        Gibt die Ports zurück, die vorher nicht offen gespeichert waren. Merkt sich die geprüften Ports."""
        mac = normalize_mac(mac)
        now = utc_now_iso()
        scanned = {int(p) for p in scanned_ports}
        open_by_key = {(p.port, p.proto): p for p in open_ports}
        new_ports: list[PortResult] = []
        with self.db.transaction() as conn:
            row = conn.execute("SELECT checked_ports FROM devices WHERE mac = ?", (mac,)).fetchone()
            if row is not None:
                merged = _parse_port_list(row["checked_ports"]) | scanned
                conn.execute(
                    "UPDATE devices SET checked_ports = ? WHERE mac = ?",
                    (",".join(str(p) for p in sorted(merged)), mac),
                )
            existing = {
                (r["port"], r["proto"]) for r in conn.execute("SELECT port, proto FROM ports WHERE mac = ?", (mac,))
            }
            for (port, proto) in existing:
                if port in scanned and (port, proto) not in open_by_key and proto == "tcp":
                    conn.execute("DELETE FROM ports WHERE mac = ? AND port = ? AND proto = ?", (mac, port, proto))
            for key, p in open_by_key.items():
                if key in existing:
                    conn.execute(
                        "UPDATE ports SET service = ?, risk = ?, reason = ?, banner = COALESCE(?, banner), last_seen = ? "
                        "WHERE mac = ? AND port = ? AND proto = ?",
                        (p.service, p.risk, p.reason, p.banner, now, mac, p.port, p.proto),
                    )
                else:
                    conn.execute(
                        "INSERT INTO ports(mac, port, proto, service, risk, reason, banner, first_seen, last_seen) "
                        "VALUES(?,?,?,?,?,?,?,?,?)",
                        (mac, p.port, p.proto, p.service, p.risk, p.reason, p.banner, now, now),
                    )
                    new_ports.append(p)
        return new_ports

    def get(self, mac: str) -> Device | None:
        try:
            mac = normalize_mac(mac)
        except ValueError:
            return None
        row = self.db.query_one("SELECT * FROM devices WHERE mac = ?", (mac,))
        if row is None:
            return None
        latest = self.latest_scan_id()
        return self._row_to_device(row, self._ports_for([mac]).get(mac, []), latest)

    def list_devices(self) -> list[Device]:
        """Alle Geräte mit Ports, is_new und online berechnet. Router zuerst, dann nach IP."""
        rows = self.db.query("SELECT * FROM devices")
        ports = self._ports_for(None)
        latest = self.latest_scan_id()
        devices = [self._row_to_device(r, ports.get(r["mac"], []), latest) for r in rows]
        devices.sort(key=lambda d: (not d.is_gateway, _ip_key(d.ip)))
        return devices

    def update_user_fields(self, mac: str, **fields: Any) -> Device:
        """Erlaubt: custom_name, category (oder "auto"), note, known, port_scan_excluded."""
        unknown = set(fields) - set(USER_FIELDS)
        if unknown:
            raise KeyError(", ".join(sorted(unknown)))
        mac = normalize_mac(mac)
        if self.db.query_one("SELECT 1 FROM devices WHERE mac = ?", (mac,)) is None:
            raise LookupError(mac)
        sets: list[str] = []
        params: list[Any] = []
        for key, value in fields.items():
            if key == "category":
                if value == "auto" or value is None:
                    sets.append("category_source = 'auto'")
                    continue
                if value not in CATEGORIES:
                    raise ValueError(f"Unbekannte Kategorie: {value}")
                sets.append("category = ?")
                params.append(value)
                sets.append("category_source = 'user'")
                sets.append("category_reason = ?")
                params.append("vom Nutzer festgelegt")
            elif key in ("known", "port_scan_excluded"):
                sets.append(f"{key} = ?")
                params.append(int(bool(value)))
            elif key == "custom_name":
                text = (value or "").strip() if isinstance(value, str) or value is None else str(value)
                sets.append("custom_name = ?")
                params.append(text or None)
            elif key == "note":
                sets.append("note = ?")
                params.append(str(value or ""))
        if sets:
            params.append(mac)
            self.db.execute(f"UPDATE devices SET {', '.join(sets)} WHERE mac = ?", params)
        device = self.get(mac)
        assert device is not None
        return device

    def set_auto_category(self, mac: str, category: str, reason: str) -> None:
        """Automatische Einordnung ändern, ohne last_seen zu berühren (Tiefenscan). Nutzerwahl bleibt."""
        if category not in CATEGORIES:
            raise ValueError(f"Unbekannte Kategorie: {category}")
        self.db.execute(
            "UPDATE devices SET category = ?, category_reason = ? WHERE mac = ? AND category_source = 'auto'",
            (category, reason, normalize_mac(mac)),
        )

    def inventory_view(self) -> list[dict[str, Any]]:
        """Schnittstelle für Stufe 4: [{mac, ip, name}]."""
        return [{"mac": d.mac, "ip": d.ip, "name": d.display_name} for d in self.list_devices()]

    def registered_devices(self) -> list[Device]:
        return self.list_devices()

    # --- intern ----------------------------------------------------------------
    def _ports_for(self, macs: list[str] | None) -> dict[str, list[PortResult]]:
        if macs is None:
            rows = self.db.query("SELECT * FROM ports ORDER BY port")
        else:
            marks = ",".join("?" for _ in macs)
            rows = self.db.query(f"SELECT * FROM ports WHERE mac IN ({marks}) ORDER BY port", macs)
        out: dict[str, list[PortResult]] = {}
        for r in rows:
            out.setdefault(r["mac"], []).append(
                PortResult(port=r["port"], proto=r["proto"], service=r["service"], risk=r["risk"], reason=r["reason"], banner=r["banner"])
            )
        return out

    @staticmethod
    def _row_to_device(row: sqlite3.Row, ports: list[PortResult], latest_scan: int | None) -> Device:
        try:
            names = NameInfo.from_dict(json.loads(row["names_json"] or "{}"))
        except json.JSONDecodeError:
            names = NameInfo()
        try:
            ssdp = SsdpInfo.from_dict(json.loads(row["ssdp_json"])) if row["ssdp_json"] else None
        except json.JSONDecodeError:
            ssdp = None
        known = bool(row["known"])
        return Device(
            mac=row["mac"],
            ip=row["ip"],
            vendor=row["vendor"],
            mac_random=bool(row["mac_random"]),
            hostname=row["hostname"],
            names=names,
            ssdp=ssdp,
            ports=ports,
            category=row["category"],
            category_source=row["category_source"],
            category_reason=row["category_reason"] or "",
            custom_name=row["custom_name"],
            note=row["note"] or "",
            known=known,
            is_gateway=bool(row["is_gateway"]),
            is_self=bool(row["is_self"]),
            port_scan_excluded=bool(row["port_scan_excluded"]),
            online=latest_scan is not None and row["last_seen_scan"] == latest_scan,
            rtt_ms=row["rtt_ms"],
            ttl=row["ttl"],
            discovered_by=[x for x in (row["discovered_by"] or "").split(",") if x],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            first_seen_scan=row["first_seen_scan"],
            last_seen_scan=row["last_seen_scan"],
            is_new=(not known) and latest_scan is not None and row["first_seen_scan"] == latest_scan,
        )


def _ip_key(ip: str) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in ip.split("."))
    except ValueError:
        return (999,)


def _parse_port_list(text: str | None) -> set[int]:
    """„22,80,445“ -> {22, 80, 445}; Unsinn wird übergangen (Datenbank ist nicht vertrauenswürdig)."""
    out: set[int] = set()
    for part in (text or "").split(","):
        part = part.strip()
        if part.isdigit() and 0 < int(part) < 65536:
            out.add(int(part))
    return out
