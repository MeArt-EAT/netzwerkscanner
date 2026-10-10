"""Paralleler Ping: nur erreichbare Hosts, Fortschritt, Drosselung, Abbruch (FakePlatform, nie echtes Netz)."""

from __future__ import annotations

import threading
import time

import pytest

from netscan.core.context import ScanCancelled, parallel_map
from netscan.core.models import PingResult
from netscan.net import ping as ping_module
from netscan.net.ping import ping_sweep
from tests.fakes import FakePlatform

NET = "192.168.178"


def make_hosts(first: int = 1, last: int = 20) -> list[str]:
    return [f"{NET}.{i}" for i in range(first, last + 1)]


def progress_events(ctx):  # type: ignore[no-untyped-def]
    return [e.data for e in ctx.bus.history(type_prefix="job.progress")]


class RecordingPlatform(FakePlatform):
    """FakePlatform, die Zeitlimit und gleichzeitige Aufrufe protokolliert; optional langsam."""

    def __init__(self, delay_s: float = 0.0, failing: frozenset[str] = frozenset()) -> None:
        super().__init__()
        self.delay_s = delay_s
        self.failing = failing
        self.timeouts: list[int] = []
        self.max_parallel = 0
        self._running = 0
        self._lock = threading.Lock()

    def ping(self, ip: str, timeout_ms: int):  # type: ignore[no-untyped-def]
        with self._lock:
            self.timeouts.append(timeout_ms)
            self._running += 1
            self.max_parallel = max(self.max_parallel, self._running)
        try:
            if self.delay_s:
                time.sleep(self.delay_s)
            if ip in self.failing:
                raise OSError("ping kaputt")
            return super().ping(ip, timeout_ms)
        finally:
            with self._lock:
                self._running -= 1


class CountingRate:
    def __init__(self) -> None:
        self.calls: list[float] = []
        self._lock = threading.Lock()

    def acquire(self, n: float = 1.0) -> None:
        with self._lock:
            self.calls.append(n)


# --- Ergebnis --------------------------------------------------------------------------


def test_returns_only_reachable_hosts(make_ctx, fake_platform) -> None:  # type: ignore[no-untyped-def]
    alive_a = PingResult(alive=True, rtt_ms=1.5, ttl=64)
    alive_b = PingResult(alive=True, rtt_ms=0.5, ttl=128)
    fake_platform.alive = {f"{NET}.10": alive_a, f"{NET}.11": alive_b, f"{NET}.12": PingResult(alive=False)}
    ctx = make_ctx(rate_pps=1000)
    hosts = make_hosts()
    result = ping_sweep(ctx, hosts)
    assert result == {f"{NET}.10": alive_a, f"{NET}.11": alive_b}
    assert sorted(fake_platform.ping_calls) == sorted(hosts)  # jeder Host genau einmal


def test_nobody_answers_gives_empty_result(make_ctx) -> None:  # type: ignore[no-untyped-def]
    assert ping_sweep(make_ctx(rate_pps=1000), make_hosts()) == {}


def test_empty_host_list(make_ctx, fake_platform) -> None:  # type: ignore[no-untyped-def]
    ctx = make_ctx()
    assert ping_sweep(ctx, []) == {}
    assert fake_platform.ping_calls == []
    assert progress_events(ctx) == []


def test_failing_ping_does_not_stop_the_sweep(make_ctx) -> None:  # type: ignore[no-untyped-def]
    platform = RecordingPlatform(failing=frozenset({f"{NET}.2"}))
    platform.alive = {f"{NET}.1": PingResult(True, 1.0, 64), f"{NET}.2": PingResult(True, 1.0, 64), f"{NET}.3": PingResult(True, 1.0, 64)}
    ctx = make_ctx(platform=platform, rate_pps=1000)
    assert set(ping_sweep(ctx, make_hosts(1, 5))) == {f"{NET}.1", f"{NET}.3"}


def test_works_with_loopback_only(make_ctx, fake_platform) -> None:  # type: ignore[no-untyped-def]
    fake_platform.alive = {"127.0.0.1": PingResult(True, 0.5, 128)}
    result = ping_sweep(make_ctx(), ["127.0.0.1"])
    assert list(result) == ["127.0.0.1"]


# --- Einstellungen ---------------------------------------------------------------------


def test_uses_timeout_from_settings(make_ctx) -> None:  # type: ignore[no-untyped-def]
    platform = RecordingPlatform()
    ctx = make_ctx(platform=platform, ping_timeout_ms=450, rate_pps=1000)
    ping_sweep(ctx, make_hosts(1, 6))
    assert platform.timeouts == [450] * 6


def test_uses_parallel_map_with_configured_workers(make_ctx, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    seen: dict[str, object] = {}

    def spy(ctx, fn, items, workers, **kwargs):  # type: ignore[no-untyped-def]
        seen["workers"] = workers
        seen["rate"] = kwargs.get("rate", True)
        return parallel_map(ctx, fn, items, workers, **kwargs)

    monkeypatch.setattr(ping_module, "parallel_map", spy)
    ping_sweep(make_ctx(ping_workers=7, rate_pps=1000), make_hosts(1, 5))
    assert seen == {"workers": 7, "rate": True}


def test_pings_run_in_parallel_but_within_worker_limit(make_ctx) -> None:  # type: ignore[no-untyped-def]
    platform = RecordingPlatform(delay_s=0.1)
    ctx = make_ctx(platform=platform, ping_workers=8, rate_pps=1000)
    ping_sweep(ctx, make_hosts(1, 32))
    assert 1 < platform.max_parallel <= 8


def test_rate_limiter_is_charged_once_per_host(make_ctx) -> None:  # type: ignore[no-untyped-def]
    ctx = make_ctx()
    ctx.rate = CountingRate()  # type: ignore[assignment]
    ping_sweep(ctx, make_hosts(1, 20))
    assert len(ctx.rate.calls) == 20  # type: ignore[union-attr]


# --- Fortschritt -----------------------------------------------------------------------


def test_progress_every_ten_results_and_at_the_end(make_ctx) -> None:  # type: ignore[no-untyped-def]
    ctx = make_ctx(rate_pps=1000)
    ping_sweep(ctx, make_hosts(1, 25))
    events = progress_events(ctx)
    assert [e["done"] for e in events] == [10, 20, 25]
    assert {e["total"] for e in events} == {25}
    assert {e["phase"] for e in events} == {"Ping"}


def test_progress_for_few_hosts_only_at_the_end(make_ctx) -> None:  # type: ignore[no-untyped-def]
    ctx = make_ctx(rate_pps=1000)
    ping_sweep(ctx, make_hosts(1, 4))
    assert [(e["done"], e["total"]) for e in progress_events(ctx)] == [(4, 4)]


def test_progress_exact_multiple_of_ten_is_reported_once(make_ctx) -> None:  # type: ignore[no-untyped-def]
    ctx = make_ctx(rate_pps=1000)
    ping_sweep(ctx, make_hosts(1, 20))
    assert [e["done"] for e in progress_events(ctx)] == [10, 20]


def test_progress_is_sparse_for_a_whole_network(make_ctx) -> None:  # type: ignore[no-untyped-def]
    ctx = make_ctx(rate_pps=1000)
    ping_sweep(ctx, make_hosts(1, 254))
    done = [e["done"] for e in progress_events(ctx)]
    assert done[-1] == 254
    assert len(done) == 26  # 25 volle Zehner + Endstand
    assert done == sorted(done)


# --- Abbruch ---------------------------------------------------------------------------


def test_cancel_stops_within_5_seconds(make_ctx) -> None:  # type: ignore[no-untyped-def]
    platform = RecordingPlatform(delay_s=0.2)  # ungebremst: 400 Hosts / 4 Arbeiter · 0,2 s = 20 s
    ctx = make_ctx(platform=platform, ping_workers=4, rate_pps=1000)
    timer = threading.Timer(0.3, ctx.cancel.cancel)
    timer.start()
    t0 = time.monotonic()
    try:
        with pytest.raises(ScanCancelled):
            ping_sweep(ctx, make_hosts(1, 254) + [f"192.168.179.{i}" for i in range(1, 147)])
    finally:
        timer.cancel()
    assert time.monotonic() - t0 < 5


def test_cancelled_before_start_pings_nobody(make_ctx, fake_platform) -> None:  # type: ignore[no-untyped-def]
    ctx = make_ctx()
    ctx.cancel.cancel()
    with pytest.raises(ScanCancelled):
        ping_sweep(ctx, make_hosts())
    assert fake_platform.ping_calls == []
