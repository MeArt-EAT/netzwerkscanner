"""Alerts: speichern, quittieren, Regeln auswerten (BAUPLAN §25). (Agent alerts)

Platzhalter der Leitung: Signaturen sind verbindlich, die Umsetzung folgt durch Agent alerts.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from netscan.core.models import Alert, Device, MonitorTarget, ScanOutcome, ServiceCheck

if TYPE_CHECKING:
    from netscan.config import SettingsStore
    from netscan.core.db import Database
    from netscan.core.events import EventBus

EVENT_RULES = frozenset({"new_device", "new_port"})
ALERT_KEEP_DAYS = 365
ALERT_KEEP_MAX = 5000


class AlertStore:
    def __init__(self, db: Database, bus: EventBus) -> None:
        self.db = db
        self.bus = bus

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
        raise NotImplementedError

    def close(self, key: str, now: float | None = None) -> Alert | None:
        raise NotImplementedError

    def acknowledge(self, alert_id: int, now: float | None = None) -> Alert:
        raise NotImplementedError

    def acknowledge_all(self, now: float | None = None) -> int:
        raise NotImplementedError

    def get(self, alert_id: int) -> Alert | None:
        raise NotImplementedError

    def list(self, *, state: str = "active", limit: int = 200, mac: str | None = None) -> list[Alert]:
        raise NotImplementedError

    def counts(self) -> dict[str, Any]:
        raise NotImplementedError

    def frequency(self, *, days: int = 30, now: float) -> list[dict[str, Any]]:
        raise NotImplementedError

    def prune(self, now: float, keep_days: int = ALERT_KEEP_DAYS, keep_max: int = ALERT_KEEP_MAX) -> int:
        raise NotImplementedError


class AlertEngine:
    def __init__(self, store: AlertStore, settings_store: SettingsStore) -> None:
        self.store = store
        self.settings_store = settings_store

    def evaluate_target(self, target: MonitorTarget, device: Device | None, now: float) -> None:
        raise NotImplementedError

    def evaluate_check(self, target: MonitorTarget, check: ServiceCheck, device: Device | None, now: float) -> None:
        raise NotImplementedError

    def on_target_removed(self, target: MonitorTarget) -> None:
        raise NotImplementedError

    def on_check_removed(self, target: MonitorTarget, check: ServiceCheck) -> None:
        raise NotImplementedError

    def on_scan(self, outcome: ScanOutcome) -> None:
        raise NotImplementedError
