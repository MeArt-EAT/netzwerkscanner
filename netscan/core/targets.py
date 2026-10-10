"""Überwachte Ziele und ihre Dienstprüfungen in SQLite (BAUPLAN §22). Nur Datenbank, keine Netzlogik.

Die Datenbank gilt als nicht vertrauenswürdige Eingabe (beschreibbarer Datenordner): Werte werden beim Lesen
auf die bekannten Wertebereiche zurückgeführt.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from netscan import config
from netscan.core.db import Database
from netscan.core.models import (
    CHECK_KINDS,
    REACH_METHODS,
    MonitorTarget,
    ServiceCheck,
    normalize_mac,
    utc_now_iso,
)

USER_TARGET_FIELDS = ("enabled", "method", "tcp_port", "offline_after_min", "rtt_threshold_ms")
_TARGET_STATUSES = ("unknown", "online", "degraded", "offline", "paused")
_PAUSE_CODES = ("blocked", "confirm", "no_adapter", "other_network", "disabled")
_CHECK_STATUSES = ("unknown", "up", "down")
PATH_MAX_LEN = 200


class TargetExists(ValueError):
    """Das Gerät wird schon überwacht."""


class CheckExists(ValueError):
    """Diese Dienstprüfung gibt es für das Ziel schon."""


def validate_target_field(key: str, value: Any) -> Any:
    """Prüft ein Nutzerfeld eines Ziels. ValueError mit deutscher Meldung, KeyError bei unbekanntem Feld."""
    if key not in USER_TARGET_FIELDS:
        raise KeyError(key)
    if key == "enabled":
        if not isinstance(value, bool):
            raise ValueError("enabled muss true oder false sein.")
        return value
    if key == "method":
        if value not in REACH_METHODS:
            raise ValueError(f"Unbekannter Erreichbarkeitstest: {value!r} (erlaubt: auto, ping, tcp).")
        return value
    if value is None:
        return None
    lo, hi = config.TARGET_LIMITS[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value or not lo <= value <= hi:
        raise ValueError(f"{key} muss zwischen {lo:g} und {hi:g} liegen oder leer sein.")
    if key in ("tcp_port", "offline_after_min"):
        if int(value) != value:
            raise ValueError(f"{key} muss eine ganze Zahl sein.")
        return int(value)
    return float(value)


def validate_check(kind: Any, port: Any, path: Any = "/") -> tuple[str, int, str]:
    """Prüft eine Dienstprüfung. ValueError mit deutscher Meldung."""
    if kind not in CHECK_KINDS:
        raise ValueError(f"Unbekannte Dienstprüfung: {kind!r} (erlaubt: {', '.join(CHECK_KINDS)}).")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("port muss eine ganze Zahl zwischen 1 und 65535 sein.")
    if path is None:
        path = "/"
    if not isinstance(path, str) or not path.startswith("/") or len(path) > PATH_MAX_LEN:
        raise ValueError(f"path muss mit „/“ beginnen und höchstens {PATH_MAX_LEN} Zeichen lang sein.")
    if any(ord(ch) < 33 or ord(ch) == 127 for ch in path):
        raise ValueError("path darf keine Leer- oder Steuerzeichen enthalten.")
    return str(kind), int(port), path


class TargetStore:
    def __init__(self, db: Database) -> None:
        self.db = db

    # --- Ziele -----------------------------------------------------------------
    def list(self, enabled_only: bool = False) -> list[MonitorTarget]:
        sql = "SELECT * FROM monitor_targets"
        if enabled_only:
            sql += " WHERE enabled = 1"
        rows = self.db.query(sql + " ORDER BY id")
        checks = self._checks_by_target(None)
        return [self._row_to_target(r, checks.get(int(r["id"]), [])) for r in rows]

    def count(self) -> int:
        row = self.db.query_one("SELECT COUNT(*) AS n FROM monitor_targets")
        return int(row["n"]) if row else 0

    def get(self, mac: str) -> MonitorTarget | None:
        try:
            mac = normalize_mac(mac)
        except ValueError:
            return None
        row = self.db.query_one("SELECT * FROM monitor_targets WHERE mac = ?", (mac,))
        if row is None:
            return None
        return self._row_to_target(row, self._checks_by_target(int(row["id"])).get(int(row["id"]), []))

    def get_by_id(self, target_id: int) -> MonitorTarget | None:
        row = self.db.query_one("SELECT * FROM monitor_targets WHERE id = ?", (int(target_id),))
        if row is None:
            return None
        return self._row_to_target(row, self._checks_by_target(int(row["id"])).get(int(row["id"]), []))

    def add(
        self,
        mac: str,
        *,
        method: str = "auto",
        tcp_port: int | None = None,
        offline_after_min: int | None = None,
        rtt_threshold_ms: float | None = None,
        gateway_mac: str | None = None,
        network: str | None = None,
    ) -> MonitorTarget:
        """Legt ein Ziel an. TargetExists, ValueError (Werte, Obergrenze), LookupError (Gerät fehlt)."""
        mac = normalize_mac(mac)
        values = {
            "method": validate_target_field("method", method),
            "tcp_port": validate_target_field("tcp_port", tcp_port),
            "offline_after_min": validate_target_field("offline_after_min", offline_after_min),
            "rtt_threshold_ms": validate_target_field("rtt_threshold_ms", rtt_threshold_ms),
        }
        with self.db.transaction() as conn:
            if conn.execute("SELECT 1 FROM devices WHERE mac = ?", (mac,)).fetchone() is None:
                raise LookupError(mac)
            if conn.execute("SELECT 1 FROM monitor_targets WHERE mac = ?", (mac,)).fetchone() is not None:
                raise TargetExists(f"{mac} wird schon überwacht.")
            count = conn.execute("SELECT COUNT(*) FROM monitor_targets").fetchone()[0]
            if count >= config.MAX_TARGETS:
                raise ValueError(f"Höchstens {config.MAX_TARGETS} Geräte lassen sich überwachen.")
            conn.execute(
                "INSERT INTO monitor_targets(mac, method, tcp_port, offline_after_min, rtt_threshold_ms, gateway_mac, "
                "network, created) VALUES(?,?,?,?,?,?,?,?)",
                (
                    mac, values["method"], values["tcp_port"], values["offline_after_min"], values["rtt_threshold_ms"],
                    _clean_mac(gateway_mac), network, utc_now_iso(),
                ),
            )  # fmt: skip
        target = self.get(mac)
        assert target is not None
        return target

    def update(self, mac: str, **fields: Any) -> MonitorTarget:
        """Ändert Nutzerfelder (USER_TARGET_FIELDS). KeyError, ValueError, LookupError."""
        mac = normalize_mac(mac)
        clean = {key: validate_target_field(key, value) for key, value in fields.items()}
        if self.db.query_one("SELECT 1 FROM monitor_targets WHERE mac = ?", (mac,)) is None:
            raise LookupError(mac)
        if clean:
            sets = ", ".join(f"{key} = ?" for key in clean)
            params = [int(v) if isinstance(v, bool) else v for v in clean.values()]
            self.db.execute(f"UPDATE monitor_targets SET {sets} WHERE mac = ?", [*params, mac])
        target = self.get(mac)
        assert target is not None
        return target

    def remove(self, mac: str) -> MonitorTarget | None:
        target = self.get(mac)
        if target is None:
            return None
        self.db.execute("DELETE FROM monitor_targets WHERE id = ?", (target.id,))  # Checks per CASCADE
        return target

    def set_network(self, target_id: int, gateway_mac: str | None, network: str | None) -> None:
        self.db.execute(
            "UPDATE monitor_targets SET gateway_mac = ?, network = ? WHERE id = ?",
            (_clean_mac(gateway_mac), network, int(target_id)),
        )

    def save_state(self, target: MonitorTarget) -> None:
        """Speichert die Zustandsfelder des Ziels und seiner Checks (nicht die Nutzerfelder)."""
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE monitor_targets SET status = ?, status_since = ?, pause_code = ?, pause_reason = ?, "
                "last_check = ?, last_rtt_ms = ?, last_detail = ?, last_method = ?, down_since = ?, rtt_high_since = ? "
                "WHERE id = ?",
                (
                    target.status, target.status_since, target.pause_code, target.pause_reason or "",
                    target.last_check, target.last_rtt_ms, target.last_detail or "", target.last_method or "",
                    target.down_since, target.rtt_high_since, target.id,
                ),
            )  # fmt: skip
            for c in target.checks:
                conn.execute(
                    "UPDATE service_checks SET status = ?, status_since = ?, last_check = ?, last_rtt_ms = ?, "
                    "last_detail = ?, down_since = ? WHERE id = ? AND target_id = ?",
                    (c.status, c.status_since, c.last_check, c.last_rtt_ms, c.last_detail or "", c.down_since, c.id, target.id),
                )

    # --- Dienstprüfungen -------------------------------------------------------
    def add_check(self, target_id: int, kind: str, port: int, path: str = "/") -> ServiceCheck:
        kind, port, path = validate_check(kind, port, path)
        with self.db.transaction() as conn:
            if conn.execute("SELECT 1 FROM monitor_targets WHERE id = ?", (int(target_id),)).fetchone() is None:
                raise LookupError(target_id)
            if conn.execute(
                "SELECT 1 FROM service_checks WHERE target_id = ? AND kind = ? AND port = ?", (int(target_id), kind, port)
            ).fetchone() is not None:
                raise CheckExists(f"Die Prüfung {kind} {port} gibt es schon.")
            count = conn.execute("SELECT COUNT(*) FROM service_checks WHERE target_id = ?", (int(target_id),)).fetchone()[0]
            if count >= config.MAX_CHECKS_PER_TARGET:
                raise ValueError(f"Höchstens {config.MAX_CHECKS_PER_TARGET} Dienstprüfungen je Gerät.")
            try:
                cur = conn.execute(
                    "INSERT INTO service_checks(target_id, kind, port, path) VALUES(?,?,?,?)",
                    (int(target_id), kind, port, path),
                )
            except sqlite3.IntegrityError as exc:  # gleichzeitiges Anlegen
                raise CheckExists(f"Die Prüfung {kind} {port} gibt es schon.") from exc
            check_id = int(cur.lastrowid)
        check = self.get_check(check_id)
        assert check is not None
        return check

    def get_check(self, check_id: int) -> ServiceCheck | None:
        row = self.db.query_one("SELECT * FROM service_checks WHERE id = ?", (int(check_id),))
        return self._row_to_check(row) if row is not None else None

    def update_check(self, check_id: int, enabled: bool) -> ServiceCheck:
        if not isinstance(enabled, bool):
            raise ValueError("enabled muss true oder false sein.")
        cur = self.db.execute("UPDATE service_checks SET enabled = ? WHERE id = ?", (int(enabled), int(check_id)))
        if cur.rowcount == 0:
            raise LookupError(check_id)
        check = self.get_check(check_id)
        assert check is not None
        return check

    def remove_check(self, check_id: int) -> ServiceCheck | None:
        check = self.get_check(check_id)
        if check is None:
            return None
        self.db.execute("DELETE FROM service_checks WHERE id = ?", (check.id,))
        return check

    def valid_series(self) -> set[tuple[int, int]]:
        """Alle Messreihen, die es geben darf: (Ziel, 0) und (Ziel, Check) – für das Aufräumen der Messwerte."""
        out = {(int(r["id"]), 0) for r in self.db.query("SELECT id FROM monitor_targets")}
        out |= {(int(r["target_id"]), int(r["id"])) for r in self.db.query("SELECT id, target_id FROM service_checks")}
        return out

    # --- intern ----------------------------------------------------------------
    def _checks_by_target(self, target_id: int | None) -> dict[int, list[ServiceCheck]]:
        if target_id is None:
            rows = self.db.query("SELECT * FROM service_checks ORDER BY target_id, port, kind")
        else:
            rows = self.db.query("SELECT * FROM service_checks WHERE target_id = ? ORDER BY port, kind", (target_id,))
        out: dict[int, list[ServiceCheck]] = {}
        for r in rows:
            check = self._row_to_check(r)
            if check is not None:
                out.setdefault(check.target_id, []).append(check)
        return out

    @staticmethod
    def _row_to_check(row: sqlite3.Row) -> ServiceCheck | None:
        if row["kind"] not in CHECK_KINDS:
            return None  # unbekannte Art (manipulierte Datenbank) – nie ausführen
        port = row["port"]
        if not isinstance(port, int) or not 1 <= port <= 65535:
            return None
        path = row["path"] if isinstance(row["path"], str) and row["path"].startswith("/") else "/"
        return ServiceCheck(
            id=int(row["id"]),
            target_id=int(row["target_id"]),
            kind=row["kind"],
            port=port,
            path=path[:PATH_MAX_LEN],
            enabled=bool(row["enabled"]),
            status=row["status"] if row["status"] in _CHECK_STATUSES else "unknown",
            status_since=row["status_since"],
            last_check=row["last_check"],
            last_rtt_ms=row["last_rtt_ms"],
            last_detail=row["last_detail"] or "",
            down_since=row["down_since"],
        )

    @staticmethod
    def _row_to_target(row: sqlite3.Row, checks: list[ServiceCheck]) -> MonitorTarget:
        def limited(key: str) -> Any:
            try:
                return validate_target_field(key, row[key])
            except (ValueError, KeyError):
                return None

        return MonitorTarget(
            id=int(row["id"]),
            mac=row["mac"],
            enabled=bool(row["enabled"]),
            method=row["method"] if row["method"] in REACH_METHODS else "auto",
            tcp_port=limited("tcp_port"),
            offline_after_min=limited("offline_after_min"),
            rtt_threshold_ms=limited("rtt_threshold_ms"),
            gateway_mac=_clean_mac(row["gateway_mac"]),
            network=row["network"],
            created=row["created"],
            status=row["status"] if row["status"] in _TARGET_STATUSES else "unknown",
            status_since=row["status_since"],
            pause_code=row["pause_code"] if row["pause_code"] in _PAUSE_CODES else None,
            pause_reason=row["pause_reason"] or "",
            last_check=row["last_check"],
            last_rtt_ms=row["last_rtt_ms"],
            last_detail=row["last_detail"] or "",
            last_method=row["last_method"] or "",
            down_since=row["down_since"],
            rtt_high_since=row["rtt_high_since"],
            checks=checks,
        )


def _clean_mac(value: Any) -> str | None:
    if not value:
        return None
    try:
        return normalize_mac(str(value))
    except ValueError:
        return None
