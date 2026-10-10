"""Paralleler Ping über platform.ping(). (Agent discovery)"""

from __future__ import annotations

from netscan.core.context import ScanContext
from netscan.core.models import PingResult


def ping_sweep(ctx: ScanContext, hosts: list[str]) -> dict[str, PingResult]:
    """Pingt alle hosts parallel (parallel_map, settings.ping_workers, settings.ping_timeout_ms).
    Rückgabe nur der erreichbaren Hosts. Meldet Fortschritt über ctx.progress("Ping", ...)."""
    raise NotImplementedError
