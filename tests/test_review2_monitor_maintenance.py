"""Review 2, B5: Die stündliche Wartung übersteht Sprünge der Wanduhr (BAUPLAN §18 Plattenhygiene, §22, §24).

Vorwärts: Ein kurzer Sprung der Uhr um Jahre darf keinen Verlauf (Roh-, Stundenwerte, geschlossene Alerts) löschen.
Rückwärts: Danach muss die Wartung weiter stündlich laufen (monotone Uhr), statt bis zum Einholen zu ruhen.
Die monotone Uhr des Monitors wird ersetzt (Monitor._monotonic), die Wanduhr über clock bzw. run_cycle(now).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from netscan.core.models import Sample
from netscan.core.monitor import MAINTENANCE_SLACK_S, Monitor
from tests.fakes import FakeChecks, RecordingAlertStore, RecordingMetrics, seed_device

NAS_MAC, NAS_IP = "00:11:32:aa:bb:03", "192.168.178.3"
T0 = 1_760_000_000.0
DAY = 86400
THREE_YEARS = 3 * 365 * DAY


def _monitor(services, clock, mono):  # type: ignore[no-untyped-def]
    monitor = Monitor(services, clock=lambda: clock["now"])
    monitor._monotonic = lambda: mono["t"]
    services.monitor = monitor
    return monitor


@pytest.fixture
def recorded(services, monkeypatch):  # type: ignore[no-untyped-def]
    FakeChecks().install(monkeypatch)
    services.metrics = RecordingMetrics()
    services.alerts = RecordingAlertStore()
    clock, mono = {"now": T0}, {"t": 1000.0}
    monitor = _monitor(services, clock, mono)
    yield SimpleNamespace(svc=services, monitor=monitor, clock=clock, mono=mono, metrics=services.metrics,
                          alerts=services.alerts)
    monitor.stop()


def _step(env, wall: float, mono_advance: float):  # type: ignore[no-untyped-def]
    env.clock["now"] = wall
    env.mono["t"] += mono_advance
    return env.monitor.run_cycle()


def test_forward_jump_is_capped_and_backward_jump_keeps_hourly_maintenance(recorded) -> None:  # type: ignore[no-untyped-def]
    env = recorded
    _step(env, T0, 0)
    assert env.metrics.compacted == [int(T0)]
    # Uhr springt 3 Jahre vor, eine Minute später: Wartung rechnet höchstens einen Tag über die Laufzeit hinaus
    _step(env, T0 + THREE_YEARS, 60)
    assert len(env.metrics.compacted) == 2
    assert env.metrics.compacted[1] <= T0 + 60 + MAINTENANCE_SLACK_S
    assert env.alerts.pruned[1] <= T0 + 60 + MAINTENANCE_SLACK_S
    # Uhr geht wieder richtig: die Wartung läuft weiter einmal je Stunde (monoton gemessen)
    _step(env, T0 + 120, 60)
    assert len(env.metrics.compacted) == 2  # keine Stunde vergangen
    _step(env, T0 + 120 + 3600, 3600)
    assert env.metrics.compacted[2] == int(T0 + 120 + 3600)
    _step(env, T0 + 120 + 7200, 3600)
    assert env.metrics.compacted[3] == int(T0 + 120 + 7200)
    assert len(env.svc.alerts.pruned) == 4


def test_backward_jump_alone_does_not_stop_maintenance(recorded) -> None:  # type: ignore[no-untyped-def]
    env = recorded
    _step(env, T0, 0)
    _step(env, T0 - 30 * DAY, 3600)  # Uhr um 30 Tage zurückgestellt
    _step(env, T0 - 30 * DAY + 3600, 3600)
    assert len(env.metrics.compacted) == 3
    assert env.metrics.compacted[-1] == int(T0 - 30 * DAY + 3600)  # rechnet mit der (zurückgestellten) Uhr


def test_artificial_clock_is_not_a_clock_jump(recorded) -> None:  # type: ignore[no-untyped-def]
    # Tests und Demo setzen now über die Uhr bzw. run_cycle(now): eine Stunde Wanduhr reicht wie bisher
    env = recorded
    env.monitor.run_cycle()
    env.clock["now"] += 60
    env.monitor.run_cycle()
    assert len(env.metrics.compacted) == 1
    env.clock["now"] += 3600
    env.monitor.run_cycle()
    assert env.metrics.compacted == [int(T0), int(T0 + 3660)]
    env.monitor.run_cycle(now=T0 + 7300)
    assert env.metrics.compacted[-1] == int(T0 + 7300)


def test_permanent_forward_change_is_caught_up(recorded) -> None:  # type: ignore[no-untyped-def]
    # Bleibt die Uhr vorgestellt (z. B. echte Korrektur), holt die Wartung je Lauf einen Tag auf
    env = recorded
    _step(env, T0, 0)
    jumped = T0 + 3 * DAY
    for hour in range(1, 6):
        _step(env, jumped + hour * 3600, 3600)
    assert env.metrics.compacted[-1] == int(jumped + 5 * 3600)


# --- Echte Stores: der Verlauf übersteht einen kurzen Sprung --------------------------------------------


def test_forward_jump_does_not_wipe_history(services, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    FakeChecks().install(monkeypatch)
    clock, mono = {"now": T0}, {"t": 1000.0}
    monitor = _monitor(services, clock, mono)
    seed_device(services, NAS_MAC, NAS_IP)
    target = monitor.add_target(NAS_MAC)  # Messreihe gehört zu einem Ziel (sonst räumt prune_orphans sie weg)
    services.settings.update(monitor_enabled=False)  # nur Wartung, keine Prüfung
    now = int(T0)
    old = [Sample(target.id, 0, now - d * DAY - h * 3600, True, 2.0) for d in range(31, 361) for h in (0, 12)]
    recent = [Sample(target.id, 0, now - m * 600, True, 2.0) for m in range(1, 10 * 144)]
    services.metrics.record(old + recent)
    services.metrics.compact(now)  # alte Rohwerte ⇒ Stundenwerte
    before = services.metrics.counts()
    assert before["raw"] == len(recent) and before["hourly"] == len(old)
    services.alerts.open(rule="device_offline", key="device_offline:x", severity="warning", title="t", message="m",
                         now=T0 - 100 * DAY)  # fmt: skip
    services.alerts.close("device_offline:x", now=T0 - 100 * DAY + 60)
    try:
        monitor.run_cycle()  # erste Wartung zur richtigen Zeit
        clock["now"], mono["t"] = T0 + THREE_YEARS, mono["t"] + 60
        monitor.run_cycle()  # Uhr kurz 3 Jahre voraus
        assert services.metrics.counts() == before
        assert len(services.alerts.list(state="all")) == 1  # geschlossener Alert von vor 100 Tagen bleibt
        clock["now"], mono["t"] = T0 + 3600, mono["t"] + 3600
        monitor.run_cycle()  # Uhr wieder richtig
        assert services.metrics.counts() == before
    finally:
        monitor.stop()
