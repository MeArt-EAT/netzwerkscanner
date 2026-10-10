"""EventBus, JobRunner, ScanContext, parallel_map, RateLimiter."""

from __future__ import annotations

import asyncio
import threading
import time

import pytest

from netscan.core.context import GuardBlocked, RateLimiter, ScanCancelled, parallel_map
from netscan.core.events import EventBus
from netscan.core.jobs import JobBusyError


def test_bus_delivers_from_thread_to_asyncio() -> None:
    bus = EventBus()

    async def main() -> list[str]:
        bus.attach_loop(asyncio.get_running_loop())
        sub = bus.subscribe()
        t = threading.Thread(target=lambda: [bus.publish("job.log", {"message": str(i)}) for i in range(3)])
        t.start()
        got = [(await asyncio.wait_for(sub.get(), 2)).data["message"] for _ in range(3)]
        t.join()
        sub.close()
        return got

    assert asyncio.run(main()) == ["0", "1", "2"]
    assert [e.seq for e in bus.history()] == [1, 2, 3]


def test_job_runs_and_finishes(services) -> None:  # type: ignore[no-untyped-def]
    job_id = services.jobs.start("scan", "Test", lambda ctx: {"ok": True})
    assert services.jobs.wait(5)
    assert services.jobs.last_result["result"] == "completed"
    assert services.jobs.last_result["summary"] == {"ok": True}
    assert services.jobs.status().state == "idle"
    types = [e.type for e in services.bus.history() if e.job_id == job_id]
    assert types[0] == "job.started" and types[-1] == "job.finished"


def test_only_one_job_at_a_time(services) -> None:  # type: ignore[no-untyped-def]
    gate = threading.Event()
    services.jobs.start("scan", "lang", lambda ctx: gate.wait(5) and {})
    with pytest.raises(JobBusyError):
        services.jobs.start("scan", "zweiter", lambda ctx: {})
    gate.set()
    assert services.jobs.wait(5)


def test_cancel_stops_within_5_seconds(services) -> None:  # type: ignore[no-untyped-def]
    def endless(ctx):  # type: ignore[no-untyped-def]
        while True:
            ctx.sleep(0.5)

    services.jobs.start("scan", "endlos", endless)
    time.sleep(0.2)
    t0 = time.monotonic()
    assert services.jobs.cancel()
    assert services.jobs.wait(5)
    assert time.monotonic() - t0 < 5
    assert services.jobs.last_result["result"] == "cancelled"


def test_cancel_inside_parallel_map(services) -> None:  # type: ignore[no-untyped-def]
    def work(ctx):  # type: ignore[no-untyped-def]
        parallel_map(ctx, lambda i: time.sleep(1.0), range(500), workers=8, rate=False)
        return {}

    services.jobs.start("scan", "parallel", work)
    time.sleep(0.3)
    t0 = time.monotonic()
    services.jobs.cancel()
    assert services.jobs.wait(5)
    assert time.monotonic() - t0 < 5
    assert services.jobs.last_result["result"] == "cancelled"


def test_failed_and_blocked_results(services) -> None:  # type: ignore[no-untyped-def]
    def boom(ctx):  # type: ignore[no-untyped-def]
        raise RuntimeError("kaputt")

    services.jobs.start("scan", "x", boom)
    services.jobs.wait(5)
    assert services.jobs.last_result["result"] == "failed"
    assert "kaputt" in services.jobs.last_result["error"]

    def blocked(ctx):  # type: ignore[no-untyped-def]
        raise GuardBlocked(type("G", (), {"reason": "Schul-Hotspot"})())

    services.jobs.start("scan", "y", blocked)
    services.jobs.wait(5)
    assert services.jobs.last_result["result"] == "blocked"


def test_parallel_map_keeps_order_and_swallows_item_errors(make_ctx) -> None:  # type: ignore[no-untyped-def]
    ctx = make_ctx()

    def f(i: int) -> int:
        if i == 3:
            raise ValueError("x")
        return i * i

    seen: list[int] = []
    out = parallel_map(ctx, f, range(6), workers=4, on_result=lambda item, r, done, total: seen.append(done))
    assert out == [(0, 0), (1, 1), (2, 4), (3, None), (4, 16), (5, 25)]
    assert sorted(seen) == [1, 2, 3, 4, 5, 6]


def test_rate_limiter_limits() -> None:
    rl = RateLimiter(50, burst=1)
    t0 = time.monotonic()
    for _ in range(26):
        rl.acquire()
    assert time.monotonic() - t0 >= 0.45  # 25 Wartevorgänge à 20 ms


def test_rate_limiter_large_request_does_not_hang() -> None:
    rl = RateLimiter(200)  # Bucket-Größe 20
    t0 = time.monotonic()
    rl.acquire(64)  # früher Endlosschleife
    assert time.monotonic() - t0 < 1.0


def test_ctx_log_goes_to_bus_and_sink(make_ctx) -> None:  # type: ignore[no-untyped-def]
    ctx = make_ctx()
    stored: list[tuple] = []
    ctx.log_sink = lambda scan_id, level, msg: stored.append((scan_id, level, msg))
    ctx.scan_id = 7
    ctx.log("Hallo", "warning")
    assert stored == [(7, "warning", "Hallo")]
    assert ctx.bus.history()[-1].type == "job.log"
    ctx.cancel.cancel()
    with pytest.raises(ScanCancelled):
        ctx.check_cancel()
