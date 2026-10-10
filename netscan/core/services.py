"""Services-Container: alle langlebigen Bausteine an einer Stelle (für Server, Pipeline und Tests)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from netscan import config
from netscan.config import SettingsStore
from netscan.core.db import Database
from netscan.core.events import EventBus
from netscan.core.guard import NetworkGuard
from netscan.core.inventory import Inventory
from netscan.core.jobs import JobRunner
from netscan.net.oui import OuiDb
from netscan.platform.base import Platform


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

    def close(self) -> None:
        self.jobs.cancel()
        self.jobs.wait(6)
        self.db.close()


def build_services(data_dir: Path | None = None, platform: Platform | None = None, oui: OuiDb | None = None) -> Services:
    """Baut alles zusammen. Tests übergeben tmp_path und eine FakePlatform."""
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
    return Services(
        data_dir=base,
        platform=platform,
        db=db,
        settings=settings,
        inventory=inventory,
        oui=oui if oui is not None else OuiDb.load(base),
        guard=NetworkGuard(platform, settings),
        bus=bus,
        jobs=jobs,
    )
