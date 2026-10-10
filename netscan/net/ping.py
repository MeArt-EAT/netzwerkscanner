"""Paralleler Ping über platform.ping(). (Agent discovery)"""

from __future__ import annotations

from netscan.core.context import ScanContext, parallel_map
from netscan.core.models import PingResult

PHASE = "Ping"
_PROGRESS_EVERY = 10  # Fortschritt höchstens alle 10 Ergebnisse (und am Ende)


def ping_sweep(ctx: ScanContext, hosts: list[str]) -> dict[str, PingResult]:
    """Pingt alle hosts parallel (parallel_map, settings.ping_workers, settings.ping_timeout_ms).
    Rückgabe nur der erreichbaren Hosts. Meldet Fortschritt über ctx.progress("Ping", ...)."""
    timeout_ms = ctx.settings.ping_timeout_ms

    def ping_one(ip: str) -> PingResult:
        return ctx.platform.ping(ip, timeout_ms)

    def report(_ip: str, _result: PingResult | None, done: int, total: int) -> None:
        if done % _PROGRESS_EVERY == 0 or done == total:
            ctx.progress(PHASE, done, total)

    results = parallel_map(ctx, ping_one, hosts, workers=ctx.settings.ping_workers, on_result=report)
    return {ip: res for ip, res in results if res is not None and res.alive}
