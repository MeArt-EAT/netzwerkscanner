"""Services-Container: alle langlebigen Bausteine an einer Stelle (für Server, Pipeline und Tests)."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from netscan import config
from netscan.config import SettingsStore
from netscan.core.alerts import AlertEngine, AlertStore
from netscan.core.db import Database
from netscan.core.events import EventBus
from netscan.core.guard import NetworkGuard
from netscan.core.inventory import Inventory
from netscan.core.jobs import JobRunner
from netscan.core.metrics import MetricsStore
from netscan.core.targets import TargetStore
from netscan.net.oui import OuiDb
from netscan.platform.base import Platform

if TYPE_CHECKING:
    from netscan.core.models import ScanOutcome
    from netscan.core.monitor import Monitor

log = logging.getLogger(__name__)


@dataclass
class Services:
    data_dir: Path
    platform: Platform
    db: Database
    settings: SettingsStore
    inventory: Inventory
    oui: OuiDb
    guard: NetworkGuard
    bus: EventBus
    jobs: JobRunner
    # Stufe 2 – Überwachung (BAUPLAN §22–26)
    targets: TargetStore
    metrics: MetricsStore
    alerts: AlertStore
    alert_engine: AlertEngine
    monitor: Monitor = field(init=False)
    # Empfänger der Scan-Rückmeldung (BAUPLAN §26); Fehler eines Empfängers stoppen den Scan nie
    scan_listeners: list[Callable[[ScanOutcome], None]] = field(default_factory=list)

    def notify_scan(self, outcome: ScanOutcome) -> None:
        for listener in list(self.scan_listeners):
            try:
                listener(outcome)
            except Exception:  # noqa: BLE001
                log.exception("Scan-Rückmeldung an %r fehlgeschlagen", listener)

    def close(self) -> None:
        monitor = getattr(self, "monitor", None)
        if monitor is not None:
            monitor.stop()
        self.jobs.cancel()
        self.jobs.wait(6)
        self.db.close()


def build_services(data_dir: Path | None = None, platform: Platform | None = None, oui: OuiDb | None = None) -> Services:
    """Baut alles zusammen. Tests übergeben tmp_path und eine FakePlatform. Der Monitor startet hier NICHT."""
    from netscan.core.monitor import Monitor

    base = Path(data_dir) if data_dir else config.data_dir()
    base.mkdir(parents=True, exist_ok=True)
    if platform is None:
        from netscan.platform import get_platform

        platform = get_platform()
    db = Database(config.db_path(base))
    settings = SettingsStore(db)
    inventory = Inventory(db)
    bus = EventBus()
    jobs = JobRunner(bus, settings, platform, log_sink=inventory.add_log)
    alerts = AlertStore(db, bus)
    services = Services(
        data_dir=base,
        platform=platform,
        db=db,
        settings=settings,
        inventory=inventory,
        oui=oui if oui is not None else OuiDb.load(base),
        guard=NetworkGuard(platform, settings),
        bus=bus,
        jobs=jobs,
        targets=TargetStore(db),
        metrics=MetricsStore(db),
        alerts=alerts,
        alert_engine=AlertEngine(alerts, settings),
    )
    services.monitor = Monitor(services)
    services.scan_listeners = [services.alert_engine.on_scan, services.monitor.on_scan]
    return services
