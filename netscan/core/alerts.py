"""Alerts: speichern, quittieren, Regeln auswerten (BAUPLAN §25). (Agent alerts)

Zustands-Alerts (device_offline, service_down, rtt_high) enden von selbst, Ereignis-Alerts (new_device,
new_port) enden mit dem Quittieren. Je Schlüssel (`key`) gibt es höchstens einen aktiven Alert – das sichert
zusätzlich ein Teilindex der Datenbank (`WHERE closed IS NULL`).

Die Datenbank gilt als nicht vertrauenswürdige Eingabe (beschreibbarer Datenordner): Zeilen mit unbekannter
Regel werden übergangen, Texte begrenzt und von Steuerzeichen befreit, Zeiten nur als Text weitergegeben.
"""

from __future__ import annotations

import logging
import math
import sqlite3
import time
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from netscan.config import Settings
from netscan.core.models import (
    ALERT_RULE_LABELS,
    ALERT_RULES,
    RISK_LABELS,
    Alert,
    Device,
    MonitorTarget,
    PortResult,
    ScanOutcome,
    ServiceCheck,
    iso_from_ts,
    normalize_mac,
    ts_from_iso,
)

if TYPE_CHECKING:
    from netscan.config import SettingsStore
    from netscan.core.db import Database
    from netscan.core.events import EventBus

log = logging.getLogger(__name__)

EVENT_RULES = frozenset({"new_device", "new_port"})
STATE_RULES = frozenset({"device_offline", "service_down", "rtt_high"})
SEVERITIES: tuple[str, ...] = ("info", "warning", "critical")
ALERT_KEEP_DAYS = 365
ALERT_KEEP_MAX = 5000
LIST_LIMIT_MAX = 1000
FREQUENCY_DAYS_MAX = 365
TITLE_MAX = 200
MESSAGE_MAX = 1000
KEY_MAX = 200
NAME_MAX = 80

# Wörtlich aus BAUPLAN §25 (auch in der Oberfläche, §30)
SELF_FIREWALL_HINT = (
    "Eigener PC: lokal geprüft – die Windows-Firewall wird dabei nicht berücksichtigt; "
    "von anderen Geräten aus kann der Port gesperrt sein."
)
RISK_SEVERITY: dict[str, str] = {"low": "info", "medium": "warning", "high": "critical", "critical": "critical"}
_CRITICAL_CATEGORIES = frozenset({"router", "server"})  # Router und Server/NAS

# Nur Konstanten (keine Nutzereingaben) – sicher als SQL-Literal
_RULES_SQL = "(" + ",".join(f"'{r}'" for r in ALERT_RULES) + ")"
_EVENT_RULES_SQL = "(" + ",".join(f"'{r}'" for r in sorted(EVENT_RULES)) + ")"
_STATE_FILTERS: dict[str, str] = {
    "active": "closed IS NULL",
    "unacked": "acknowledged IS NULL",
    "all": "",
}
_SQLITE_INT_MIN, _SQLITE_INT_MAX = -(2**63), 2**63 - 1


class AlertStore:
    """Alert-Verlauf in der Tabelle alerts; meldet Änderungen über den EventBus (thread-sicher über db.lock)."""

    def __init__(self, db: Database, bus: EventBus) -> None:
        self.db = db
        self.bus = bus

    # --- Öffnen und Schließen -------------------------------------------------------------------
    def open(
        self,
        *,
        rule: str,
        key: str,
        severity: str,
        title: str,
        message: str,
        mac: str | None = None,
        target_id: int | None = None,
        check_id: int | None = None,
        now: float | None = None,
    ) -> Alert | None:
        """Öffnet einen Alert. None, wenn für key schon ein aktiver Alert besteht (idempotent).

        ValueError bei unbekannter Regel/Schwere, leerem Schlüssel oder ungültiger MAC.
        """
        if rule not in ALERT_RULES:
            raise ValueError(f"Unbekannte Alert-Regel: {rule!r}")
        if severity not in SEVERITIES:
            raise ValueError(f"Unbekannte Alert-Schwere: {severity!r} (erlaubt: info, warning, critical)")
        if not isinstance(key, str) or not key.strip() or len(key) > KEY_MAX:
            raise ValueError("Der Alert-Schlüssel fehlt oder ist zu lang.")
        clean_mac = normalize_mac(mac) if mac else None
        values = (
            rule,
            key,
            severity,
            _clip(title, TITLE_MAX) or ALERT_RULE_LABELS.get(rule, rule),
            _clip(message, MESSAGE_MAX),
            clean_mac,
            _db_int(target_id),
            _db_int(check_id),
            _iso(now),
        )
        # Schneller Vorabtest ohne Schreibsperre: der häufigste Fall (schon aktiv) braucht keine Transaktion.
        if self._peek_active(key) is not None:
            return None
        try:
            with self.db.transaction() as conn:
                if self._find_active(conn, key) is not None:
                    return None
                cur = conn.execute(
                    "INSERT INTO alerts(rule, key, severity, title, message, mac, target_id, check_id, opened) "
                    "VALUES(?,?,?,?,?,?,?,?,?)",
                    values,
                )
                alert_id = int(cur.lastrowid)
        except sqlite3.IntegrityError:
            # Gleichzeitiges Öffnen (z. B. zweite Verbindung): der Teilindex hat den zweiten Alert verhindert.
            log.debug("Alert %s ist schon aktiv (gleichzeitig geöffnet)", key)
            return None
        alert = self.get(alert_id)
        if alert is None:
            return None
        log.info("Alert geöffnet: %s", alert.title)
        self._publish("alert.opened", {"alert": alert.to_dict()})
        return alert

    def close(self, key: str, now: float | None = None) -> Alert | None:
        """Schließt den aktiven Alert zu key. None, wenn keiner aktiv ist."""
        if not isinstance(key, str) or not key:
            return None
        if self._peek_active(key) is None:
            return None
        iso = _iso(now)
        with self.db.transaction() as conn:
            alert_id = self._find_active(conn, key)
            if alert_id is None:
                return None
            cur = conn.execute("UPDATE alerts SET closed = ? WHERE id = ? AND closed IS NULL", (iso, alert_id))
            changed = cur.rowcount > 0
        if not changed:
            return None
        alert = self.get(alert_id)
        if alert is None:
            return None
        log.debug("Alert beendet: %s", alert.title)
        self._publish("alert.closed", {"alert": alert.to_dict()})
        return alert

    # --- Quittieren -----------------------------------------------------------------------------
    def acknowledge(self, alert_id: int, now: float | None = None) -> Alert:
        """Quittiert einen Alert (Zeit nur beim ersten Mal). Ereignis-Alerts werden dabei geschlossen.

        LookupError, wenn es den Alert nicht gibt.
        """
        aid = _id_or_none(alert_id)
        if aid is None:
            raise LookupError(alert_id)
        iso = _iso(now)
        with self.db.transaction() as conn:
            row = conn.execute(
                f"SELECT rule, closed, acknowledged FROM alerts WHERE id = ? AND rule IN {_RULES_SQL}", (aid,)
            ).fetchone()
            if row is None:
                raise LookupError(alert_id)
            changed = False
            if row["acknowledged"] is None:
                conn.execute("UPDATE alerts SET acknowledged = ? WHERE id = ?", (iso, aid))
                changed = True
            if row["rule"] in EVENT_RULES and row["closed"] is None:
                conn.execute("UPDATE alerts SET closed = ? WHERE id = ?", (iso, aid))
                changed = True
        alert = self.get(aid)
        if alert is None:  # nur bei gleichzeitigem Löschen
            raise LookupError(alert_id)
        if changed:
            self._publish("alert.acknowledged", {"ids": [aid]})
        return alert

    def acknowledge_all(self, now: float | None = None) -> int:
        """Quittiert alle unquittierten Alerts; Ereignis-Alerts enden dabei. Gibt die Anzahl zurück, ein Ereignis."""
        iso = _iso(now)
        with self.db.transaction() as conn:
            ids = [
                int(r["id"])
                for r in conn.execute(
                    f"SELECT id FROM alerts WHERE acknowledged IS NULL AND rule IN {_RULES_SQL} ORDER BY id"
                )
            ]
            if ids:
                conn.execute(
                    f"UPDATE alerts SET acknowledged = ? WHERE acknowledged IS NULL AND rule IN {_RULES_SQL}", (iso,)
                )
            # Quittierte Ereignis-Alerts sind beendet (auch Reste, die quittiert, aber noch offen sind –
            # sie würden sonst neue Alerts mit gleichem Schlüssel für immer verhindern).
            conn.execute(
                f"UPDATE alerts SET closed = ? WHERE closed IS NULL AND acknowledged IS NOT NULL "
                f"AND rule IN {_EVENT_RULES_SQL}",
                (iso,),
            )
        if ids:
            self._publish("alert.acknowledged", {"ids": ids})
        return len(ids)

    # --- Lesen ----------------------------------------------------------------------------------
    def get(self, alert_id: int) -> Alert | None:
        aid = _id_or_none(alert_id)
        if aid is None:
            return None
        row = self.db.query_one("SELECT * FROM alerts WHERE id = ?", (aid,))
        return _row_to_alert(row) if row is not None else None

    def list(self, *, state: str = "active", limit: int = 200, mac: str | None = None) -> list[Alert]:
        """Alerts, neueste zuerst. state: active | unacked | all (sonst ValueError); limit auf 1–1000 begrenzt.

        mac wird normalisiert; eine ungültige MAC passt zu keinem Alert (leere Liste).
        """
        if state not in _STATE_FILTERS:
            raise ValueError(f"Unbekannter Alert-Zustand: {state!r} (erlaubt: active, unacked, all).")
        n = _clamp_int(limit, 1, LIST_LIMIT_MAX, "limit")
        where = [f"rule IN {_RULES_SQL}"]
        params: list[Any] = []
        if _STATE_FILTERS[state]:
            where.append(_STATE_FILTERS[state])
        if mac:
            try:
                params.append(normalize_mac(mac))
            except ValueError:
                return []
            where.append("mac = ?")
        rows = self.db.query(
            f"SELECT * FROM alerts WHERE {' AND '.join(where)} ORDER BY opened DESC, id DESC LIMIT ?", [*params, n]
        )
        return [a for a in (_row_to_alert(r) for r in rows) if a is not None]

    def counts(self) -> dict[str, Any]:
        """{"active": n, "unacked": n, "by_rule": {Regel: aktive}} – alle fünf Regeln, auch mit 0."""
        by_rule = {r: 0 for r in ALERT_RULES}
        with self.db.lock:
            for row in self.db.query(
                f"SELECT rule, COUNT(*) AS n FROM alerts WHERE closed IS NULL AND rule IN {_RULES_SQL} GROUP BY rule"
            ):
                by_rule[row["rule"]] = int(row["n"])
            unacked = self.db.query_one(
                f"SELECT COUNT(*) AS n FROM alerts WHERE acknowledged IS NULL AND rule IN {_RULES_SQL}"
            )
        return {"active": sum(by_rule.values()), "unacked": int(unacked["n"]) if unacked else 0, "by_rule": by_rule}

    def active_keys(self, *, target_id: int | None = None, rules: Iterable[str] | None = None) -> list[str]:
        """Schlüssel aktiver Alerts, wahlweise nur eines Ziels und bestimmter Regeln."""
        where = ["closed IS NULL", f"rule IN {_RULES_SQL}"]
        params: list[Any] = []
        if target_id is not None:
            tid = _id_or_none(target_id)
            if tid is None:
                return []
            where.append("target_id = ?")
            params.append(tid)
        if rules is not None:
            wanted = sorted({r for r in rules if r in ALERT_RULES})
            if not wanted:
                return []
            where.append(f"rule IN ({','.join('?' for _ in wanted)})")
            params.extend(wanted)
        rows = self.db.query(f"SELECT key FROM alerts WHERE {' AND '.join(where)} ORDER BY id", params)
        return [r["key"] for r in rows if isinstance(r["key"], str) and r["key"]]

    def frequency(self, *, days: int = 30, now: float | None = None) -> list[dict[str, Any]]:
        """Geöffnete Alerts je UTC-Tag und Regel, ältester Tag zuerst; Tage ohne Alerts mit 0.

        [{day "YYYY-MM-DD", device_offline, service_down, rtt_high, new_device, new_port}], days auf 1–365 begrenzt.
        """
        n_days = _clamp_int(days, 1, FREQUENCY_DAYS_MAX, "days")
        end_day = datetime.fromtimestamp(_now(now), timezone.utc).date()
        start_day = end_day - timedelta(days=n_days - 1)
        table: dict[str, dict[str, int]] = {
            (start_day + timedelta(days=i)).isoformat(): {r: 0 for r in ALERT_RULES} for i in range(n_days)
        }
        # Textvergleich nur als Vorfilter (ein Tag Spielraum für fremde Zeitzonen-Angaben); genau zählt Python.
        lower = (start_day - timedelta(days=1)).isoformat()
        rows = self.db.query(f"SELECT rule, opened FROM alerts WHERE opened >= ? AND rule IN {_RULES_SQL}", (lower,))
        for row in rows:
            ts = ts_from_iso(row["opened"]) if isinstance(row["opened"], str) else None
            if ts is None:
                continue
            try:
                day = datetime.fromtimestamp(ts, timezone.utc).date().isoformat()
            except (OverflowError, OSError, ValueError):
                continue
            bucket = table.get(day)
            if bucket is not None:
                bucket[row["rule"]] += 1
        return [{"day": day, **counts} for day, counts in table.items()]

    # --- Aufräumen ------------------------------------------------------------------------------
    def prune(self, now: float, keep_days: int = ALERT_KEEP_DAYS, keep_max: int = ALERT_KEEP_MAX) -> int:
        """Löscht geschlossene Alerts, die vor mehr als keep_days Tagen endeten, und über keep_max Einträge
        hinaus die ältesten geschlossenen. Aktive Alerts bleiben immer. Gibt die Anzahl gelöschter zurück."""
        t = _now(now)
        days = _clamp_int(keep_days, 0, 36500, "keep_days")
        limit = max(0, _clamp_int(keep_max, 0, _SQLITE_INT_MAX, "keep_max"))
        cutoff = iso_from_ts(max(0.0, t - days * 86400))
        with self.db.transaction() as conn:
            cur = conn.execute("DELETE FROM alerts WHERE closed IS NOT NULL AND closed < ?", (cutoff,))
            removed = max(0, cur.rowcount)
            total = int(conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])
            excess = total - limit
            if excess > 0:
                cur = conn.execute(
                    "DELETE FROM alerts WHERE id IN "
                    "(SELECT id FROM alerts WHERE closed IS NOT NULL ORDER BY closed, id LIMIT ?)",
                    (excess,),
                )
                removed += max(0, cur.rowcount)
        if removed:
            log.info("Alerts aufgeräumt: %d alte Einträge gelöscht.", removed)
        return removed

    # --- intern ---------------------------------------------------------------------------------
    @staticmethod
    def _find_active(conn: Any, key: str) -> int | None:
        row = conn.execute("SELECT id FROM alerts WHERE key = ? AND closed IS NULL LIMIT 1", (key,)).fetchone()
        return int(row["id"]) if row is not None else None

    def _peek_active(self, key: str) -> int | None:
        """Vorabtest ohne Schreibsperre (unter db.lock, damit keine fremde offene Transaktion mitgelesen wird)."""
        with self.db.lock:
            return self._find_active(self.db.conn, key)

    def _publish(self, type_: str, data: dict[str, Any]) -> None:
        try:
            self.bus.publish(type_, data)
        except Exception:  # noqa: BLE001 – ein Ereignis darf das Speichern nie rückgängig machen
            log.warning("Ereignis %s nicht gesendet", type_, exc_info=True)


class AlertEngine:
    """Wertet die Regeln aus BAUPLAN §25 aus. Einstellungen werden bei jedem Aufruf frisch geladen."""

    def __init__(self, store: AlertStore, settings_store: SettingsStore) -> None:
        self.store = store
        self.settings_store = settings_store

    # --- Zustands-Alerts ------------------------------------------------------------------------
    def evaluate_target(self, target: MonitorTarget, device: Device | None, now: float) -> None:
        """device_offline und rtt_high für ein Ziel nach einem Durchlauf."""
        t = _now(now)
        mac = _clean_mac(target.mac)
        if mac is None:
            log.debug("Ziel %r ohne gültige MAC – keine Alert-Auswertung", target.mac)
            return
        offline_key, rtt_key = f"device_offline:{mac}", f"rtt_high:{mac}"
        if not target.enabled:  # abgeschaltete Überwachung beendet ihre Zustands-Alerts
            self.store.close(offline_key, t)
            self.store.close(rtt_key, t)
            return
        settings = self._settings()
        name, who = _who(device, mac)

        # Gerät offline
        if target.status == "offline":
            minutes = _minutes(target.offline_after_min, 0) or _minutes(settings.alert_offline_minutes, 5)
            since = _since(target.down_since, target.status_since)
            if since is not None and t - since >= minutes * 60:
                message = (
                    f"{who} antwortet seit {_duration(t - since)} nicht mehr (Schwelle: {_minutes_text(minutes)})."
                )
                detail = _clip(target.last_detail, 200)
                if detail:
                    message += f" Letzte Meldung: {detail}"
                self.store.open(
                    rule="device_offline", key=offline_key, severity=_offline_severity(device),
                    title=f"{name} ist offline", message=message, mac=mac, target_id=_id_or_none(target.id), now=t,
                )  # fmt: skip
        elif target.status in ("online", "degraded"):
            self.store.close(offline_key, t)
        # paused / unknown: nichts ändern

        # Antwortzeit hoch
        threshold = _positive(target.rtt_threshold_ms)
        high_since = ts_from_iso(target.rtt_high_since) if threshold is not None else None
        if threshold is None or high_since is None:
            self.store.close(rtt_key, t)  # Antwortzeit wieder darunter, Gerät offline/pausiert oder Regel aus
            return
        minutes = _minutes(settings.alert_rtt_minutes, 5)
        if t - high_since >= minutes * 60:
            message = f"{who} antwortet seit {_duration(t - high_since)} langsamer als {_ms(threshold)} ms"
            last = _positive(target.last_rtt_ms)
            message += f" (zuletzt {_ms(last)} ms)." if last is not None else "."
            self.store.open(
                rule="rtt_high", key=rtt_key, severity="info", title=f"Antwortzeit von {name} hoch",
                message=message, mac=mac, target_id=_id_or_none(target.id), now=t,
            )  # fmt: skip

    def evaluate_check(self, target: MonitorTarget, check: ServiceCheck, device: Device | None, now: float) -> None:
        """service_down für eine Dienstprüfung nach einem Durchlauf."""
        t = _now(now)
        check_id = _id_or_none(check.id)
        if check_id is None:
            return
        key = f"service_down:{check_id}"
        if not target.enabled or not check.enabled:
            self.store.close(key, t)
            return
        if check.status != "down":  # up oder unknown
            self.store.close(key, t)
            return
        settings = self._settings()
        minutes = _minutes(settings.alert_service_minutes, 2)
        since = _since(check.down_since, check.status_since)
        if since is None or t - since < minutes * 60:
            return
        mac = _clean_mac(target.mac)
        name, who = _who(device, mac or str(target.mac))
        label = _check_label(check)
        message = f"{label} auf {who} antwortet seit {_duration(t - since)} nicht"
        detail = _clip(check.last_detail, 200)
        message += f" ({detail})." if detail else "."
        if target.status in ("online", "degraded"):
            message += " Das Gerät selbst ist erreichbar."
        self.store.open(
            rule="service_down", key=key, severity="warning", title=f"{label} auf {name} ausgefallen",
            message=message, mac=mac, target_id=_id_or_none(target.id), check_id=check_id, now=t,
        )  # fmt: skip

    def on_target_removed(self, target: MonitorTarget) -> None:
        """Ziel entfernt oder abgeschaltet: schließt seine Zustands-Alerts.

        Ereignis-Alerts (new_device, new_port) bleiben bis zum Quittieren.
        """
        keys: set[str] = set()
        mac = _clean_mac(target.mac)
        if mac:
            keys |= {f"device_offline:{mac}", f"rtt_high:{mac}"}
        for c in target.checks:
            cid = _id_or_none(c.id)
            if cid is not None:
                keys.add(f"service_down:{cid}")
        try:  # auch Dienst-Alerts, deren Prüfung schon fehlt
            keys |= set(self.store.active_keys(target_id=target.id, rules=STATE_RULES))
        except Exception:  # noqa: BLE001
            log.warning("Aktive Alerts des Ziels %s nicht lesbar", target.mac, exc_info=True)
        for key in sorted(keys):
            self.store.close(key)

    def on_check_removed(self, target: MonitorTarget, check: ServiceCheck) -> None:
        cid = _id_or_none(check.id)
        if cid is not None:
            self.store.close(f"service_down:{cid}")

    # --- Ereignis-Alerts ------------------------------------------------------------------------
    def on_scan(self, outcome: ScanOutcome) -> None:
        """new_device (nur nach einem normalen Scan) und new_port (Scan und Tiefenscan)."""
        settings = self._settings()
        new_macs: set[str] = set()
        for d in outcome.new_devices or []:
            mac = _clean_mac(getattr(d, "mac", None))
            if mac:
                new_macs.add(mac)
        # Der allererste Scan ist der Grundbestand – sonst gäbe es für jedes Gerät im Netz einen Alert.
        if outcome.kind == "scan" and not outcome.baseline and _flag(settings.alert_new_device, True):
            network = getattr(outcome.adapter, "network", None)
            for d in outcome.new_devices or []:
                try:
                    self._new_device(d, network)
                except Exception:  # noqa: BLE001 – ein kaputter Eintrag stoppt die anderen nicht
                    log.warning("Alert für neues Gerät nicht angelegt", exc_info=True)
        if _flag(settings.alert_new_port, True):
            for raw_mac, port_list in (outcome.new_ports or {}).items():
                mac = _clean_mac(raw_mac)
                if mac is None or mac in new_macs:  # neue Geräte melden sich über new_device
                    continue
                try:
                    self._new_ports(mac, port_list)
                except Exception:  # noqa: BLE001
                    log.warning("Alert für neuen Port von %s nicht angelegt", mac, exc_info=True)

    def _new_device(self, device: Device, network: str | None) -> None:
        mac = _clean_mac(device.mac)
        # Der eigene PC ist nie „unbekannt“ (z. B. zweiter Adapter nach dem Wechsel von WLAN auf Kabel).
        if mac is None or device.known or device.is_self:
            return
        name, who = _who(device, mac)
        message = f"{who} ist zum ersten Mal aufgetaucht"
        message += f" (Netz {network})." if network else "."
        extra = [f"MAC {mac}"]
        if device.mac_random:
            extra.append("private (zufällige) Adresse")
        vendor = _clip(device.vendor, NAME_MAX)
        if vendor:
            extra.append(f"Hersteller {vendor}")
        message += " " + ", ".join(extra) + ". Gehört es dazu, im Inventar als „bekannt“ markieren."
        self.store.open(
            rule="new_device", key=f"new_device:{mac}", severity="warning", title=f"Neues Gerät: {name}",
            message=message, mac=mac,
        )  # fmt: skip

    def _new_ports(self, mac: str, port_list: Iterable[PortResult]) -> None:
        device = self._device_for(mac)
        name, who = _who(device, mac)
        seen: set[int] = set()
        for p in port_list or []:
            if isinstance(p, dict):
                p = PortResult.from_dict(p)
            port = p.port
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535 or port in seen:
                continue
            seen.add(port)
            risk = p.risk if p.risk in RISK_SEVERITY else "medium"
            service = _clip(p.service, NAME_MAX) or "unbekannter Dienst"
            message = (
                f"Auf {who} ist Port {port} ({service}) jetzt offen; bei früheren Scans war er geschlossen. "
                f"Risiko: {RISK_LABELS.get(risk, risk)}."
            )
            reason = _clip(p.reason, 300)
            if reason:
                message += f" {reason}"
            if device is not None and device.is_self:
                message += f" {SELF_FIREWALL_HINT}"
            self.store.open(
                rule="new_port", key=f"new_port:{mac}:{port}", severity=RISK_SEVERITY[risk],
                title=f"Neuer offener Port {port} auf {name}", message=message, mac=mac,
            )  # fmt: skip

    # --- intern ---------------------------------------------------------------------------------
    def _settings(self) -> Settings:
        try:
            return self.settings_store.load()
        except Exception:  # noqa: BLE001 – ohne lesbare Einstellungen gelten die Standards
            log.warning("Einstellungen nicht lesbar – Alert-Regeln mit Standardwerten", exc_info=True)
            return Settings()

    def _device_for(self, mac: str) -> Device | None:
        """Gerät aus dem Inventar (für Name, IP und „eigener PC“). Der ScanOutcome liefert nur die MAC."""
        db = getattr(self.store, "db", None)
        if db is None:
            return None
        try:
            from netscan.core.inventory import Inventory

            return Inventory(db).get(mac)
        except Exception:  # noqa: BLE001
            log.debug("Gerät %s nicht lesbar", mac, exc_info=True)
            return None


# --- Hilfen ------------------------------------------------------------------------------------------


def _now(now: float | None) -> float:
    if now is None:
        return time.time()
    value = float(now)
    if not math.isfinite(value) or value < 0:
        raise ValueError(f"Ungültige Zeitangabe: {now!r}")
    return value


def _iso(now: float | None) -> str:
    iso = iso_from_ts(_now(now))
    assert iso is not None
    return iso


def _clamp_int(value: Any, lo: int, hi: int, name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} muss eine ganze Zahl sein.")
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        raise ValueError(f"{name} muss eine ganze Zahl sein.") from None
    return max(lo, min(hi, number))


def _id_or_none(value: Any) -> int | None:
    """Ganzzahlige ID im SQLite-Bereich, sonst None."""
    if isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if isinstance(value, float) and number != value:
        return None
    return number if _SQLITE_INT_MIN <= number <= _SQLITE_INT_MAX else None


def _db_int(value: Any) -> int | None:
    if value is None:
        return None
    number = _id_or_none(value)
    if number is None:
        raise ValueError(f"Ungültige ID: {value!r}")
    return number


def _clean_mac(value: Any) -> str | None:
    if not value or not isinstance(value, str):
        return None
    try:
        return normalize_mac(value)
    except ValueError:
        return None


def _clip(value: Any, limit: int) -> str:
    """Text ohne Steuerzeichen, höchstens limit Zeichen (Namen kommen teils aus dem Netz)."""
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    text = "".join(" " if (ord(ch) < 32 or 127 <= ord(ch) < 160) else ch for ch in text)
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: max(0, limit - 1)].rstrip() + "…"
    return text


def _time_text(value: Any) -> str | None:
    if value is None:
        return None
    return _clip(value, 40)


def _row_to_alert(row: sqlite3.Row) -> Alert | None:
    """Zeile -> Alert; None bei unbekannter Regel oder kaputter ID (manipulierte Datenbank)."""
    rule = row["rule"]
    if rule not in ALERT_RULES:
        return None
    aid = _id_or_none(row["id"])
    if aid is None:
        return None
    severity = row["severity"] if row["severity"] in SEVERITIES else "warning"
    return Alert(
        id=aid,
        rule=rule,
        key=_clip(row["key"], KEY_MAX),
        severity=severity,
        title=_clip(row["title"], TITLE_MAX) or ALERT_RULE_LABELS.get(rule, rule),
        message=_clip(row["message"], MESSAGE_MAX),
        mac=_clean_mac(row["mac"]),
        target_id=_id_or_none(row["target_id"]) if row["target_id"] is not None else None,
        check_id=_id_or_none(row["check_id"]) if row["check_id"] is not None else None,
        opened=_time_text(row["opened"]) or "",
        closed=_time_text(row["closed"]),
        acknowledged=_time_text(row["acknowledged"]),
    )


def _minutes(value: Any, default: float) -> float:
    """Minutenwert 1–1440 (Einstellungen kommen aus der Datenbank), sonst default."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    if not math.isfinite(value) or not 1 <= value <= 1440:
        return default
    return float(value)


def _positive(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(value) or value <= 0:
        return None
    return float(value)


def _flag(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    return default


def _since(primary: str | None, fallback: str | None) -> float | None:
    """Beginn eines Zustands als Unix-Sekunden: down_since, ersatzweise status_since."""
    for text in (primary, fallback):
        ts = ts_from_iso(text) if isinstance(text, str) else None
        if ts is not None:
            return ts
    return None


def _who(device: Device | None, mac: str) -> tuple[str, str]:
    """(Name für den Titel, Name mit IP für die Meldung). Ohne Gerät gilt die MAC als Name."""
    if device is None:
        return mac, mac
    try:
        name = _clip(device.display_name, NAME_MAX)
    except Exception:  # noqa: BLE001
        name = ""
    name = name or mac
    ip = _clip(device.ip, 45)
    if ip and ip != name:
        return name, f"{name} ({ip})"
    return name, name


def _offline_severity(device: Device | None) -> str:
    if device is not None and (device.is_gateway or device.category in _CRITICAL_CATEGORIES):
        return "critical"
    return "warning"


def _check_label(check: ServiceCheck) -> str:
    label = check.label
    if check.kind in ("http", "https") and isinstance(check.path, str) and check.path not in ("", "/"):
        label += f" {_clip(check.path, 60)}"
    return label


def _ms(value: float) -> str:
    """Millisekunden deutsch: 80 / 0,5 / 12,3."""
    rounded = round(value, 1)
    text = f"{rounded:.0f}" if rounded == int(rounded) else f"{rounded:.1f}"
    return text.replace(".", ",")


def _minutes_text(minutes: float) -> str:
    n = int(minutes)
    return "1 Minute" if n == 1 else f"{n} Minuten"


def _duration(seconds: float) -> str:
    """Dauer für „seit …“: 1 Minute, 5 Minuten, 3 Stunden, 2 Tagen."""
    minutes = max(0, int(seconds // 60))
    if minutes < 1:
        return "weniger als einer Minute"
    if minutes == 1:
        return "1 Minute"
    if minutes < 120:
        return f"{minutes} Minuten"
    hours = minutes // 60
    if hours < 48:
        return f"{hours} Stunden"
    return f"{hours // 24} Tagen"
