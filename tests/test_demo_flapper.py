"""Demo: Wechselspiel (BAUPLAN §32) – das Telnet-Gerät und der HTTP-Dienst der NAS fallen zeitweise aus.

Der Ablauf (tick) läuft hier mit einer von außen gesetzten Zeit und einer Sim-Attrappe, ohne Warten. Der Thread
läuft mit winzigen Zeiten gegen die Attrappe; das echte Sim-Netz kommt in test_demo_build.py dran.
"""

from __future__ import annotations

import logging

import pytest

from netscan import demo
from netscan.core.models import PingResult
from tests.test_demo_support import FakeLab, fake_platform, flapper_threads, wait_for

NAS = (demo.NAS_IP, demo.NAS_HTTP_PORT)


def _flapper(**kw):  # type: ignore[no-untyped-def]
    lab, platform = FakeLab(), fake_platform()
    return demo.Flapper(lab, platform, **kw), lab, platform


# --- Zeiten laut Vorgabe -------------------------------------------------------------------------


def test_default_times_follow_the_spec() -> None:
    assert (demo.TELNET_UP_S, demo.TELNET_DOWN_S) == (180.0, 360.0)  # nach 3 Minuten für 6 Minuten weg
    assert (demo.NAS_HTTP_UP_S, demo.NAS_HTTP_DOWN_S) == (600.0, 240.0)  # nach 10 Minuten für 4 Minuten weg
    assert demo.DEMO_MONITOR_INTERVAL_S == 15 and demo.DEMO_MONITOR_TIMEOUT_MS == 500


def test_telnet_device_drops_after_three_minutes_for_six() -> None:
    flapper, _lab, platform = _flapper()
    original = platform.alive[demo.TELNET_IP]
    flapper.begin(1000.0)
    flapper.tick(1000.0 + 179.9)
    assert demo.TELNET_IP in platform.alive and flapper.state()["telnet"] is False
    flapper.tick(1000.0 + 180.0)
    assert demo.TELNET_IP not in platform.alive and flapper.state()["telnet"] is True  # kein Ping mehr
    flapper.tick(1000.0 + 180.0 + 359.0)
    assert demo.TELNET_IP not in platform.alive
    flapper.tick(1000.0 + 180.0 + 360.0)
    assert platform.alive[demo.TELNET_IP] is original and flapper.state()["telnet"] is False  # wieder wie vorher


def test_nas_http_service_stops_after_ten_minutes_for_four() -> None:
    flapper, lab, _platform = _flapper()
    flapper.begin(0.0)
    flapper.tick(599.0)
    assert ("stop", *NAS) not in lab.calls
    flapper.tick(600.0)
    assert ("stop", *NAS) in lab.calls and flapper.state()["nas-http"] is True
    flapper.tick(600.0 + 239.0)
    assert ("start", *NAS) not in lab.calls
    flapper.tick(600.0 + 240.0)
    assert lab.calls[-1] == ("start", *NAS) and flapper.state()["nas-http"] is False


def test_only_the_nas_http_port_is_touched() -> None:
    flapper, lab, _platform = _flapper(http_up_s=1, http_down_s=1)
    for t in range(0, 20):
        flapper.tick(float(t))
    assert lab.calls and {c[1:] for c in lab.calls} == {NAS}  # nie ein anderes Gerät oder ein anderer Port


def test_tick_returns_the_time_to_the_next_change() -> None:
    flapper, _lab, _platform = _flapper(telnet_up_s=10, telnet_down_s=20, http_up_s=50, http_down_s=5)
    flapper.begin(0.0)
    assert flapper.tick(0.0) == pytest.approx(10.0)
    assert flapper.tick(4.0) == pytest.approx(6.0)
    assert flapper.tick(10.0) == pytest.approx(20.0)  # Telnet fällt aus, nächster Wechsel in 20 s
    assert flapper.tick(30.0) == pytest.approx(10.0)  # Telnet wieder da, nächster Ausfall in 10 s; die NAS folgt später
    assert flapper.tick(1000.0) == pytest.approx(5.0)  # nach langem Stillstand: beide fallen aus, kein Aufholen im Sturm
    assert flapper.state() == {"telnet": True, "nas-http": True}


def test_a_long_pause_does_not_replay_every_missed_change() -> None:
    flapper, lab, _platform = _flapper(telnet_up_s=1, telnet_down_s=1, http_up_s=1, http_down_s=1)
    flapper.begin(0.0)
    flapper.tick(10_000.0)  # Rechner war im Ruhezustand
    assert len(lab.calls) == 1  # genau ein Wechsel, kein Nachholen aller verpassten


def test_begin_restarts_the_schedule() -> None:
    flapper, _lab, platform = _flapper(telnet_up_s=5, telnet_down_s=5)
    flapper.begin(0.0)
    flapper.tick(5.0)
    assert demo.TELNET_IP not in platform.alive
    flapper.begin(100.0)  # Nullpunkt neu: Zustand „läuft“, Ausfall erst nach up_s
    assert flapper.state()["telnet"] is False


# --- Fehler und Eingaben -------------------------------------------------------------------------


def test_failing_switch_is_survived_and_logged(caplog: pytest.LogCaptureFixture) -> None:
    flapper, lab, platform = _flapper(http_up_s=1, http_down_s=1)
    lab.fail = RuntimeError("Sim-Netz ist zu")
    flapper.begin(0.0)
    with caplog.at_level(logging.WARNING, logger="netscan.demo"):
        flapper.tick(1.0)  # darf nicht werfen
    assert any("Wechsel fehlgeschlagen" in r.getMessage() for r in caplog.records)
    flapper.restore()  # auch das Wiederherstellen wirft nicht
    assert demo.TELNET_IP in platform.alive


def test_failed_switch_keeps_the_state_and_is_retried_soon() -> None:
    flapper, lab, _platform = _flapper(http_up_s=60, http_down_s=60, telnet_up_s=3600, telnet_down_s=3600)
    flapper.begin(0.0)
    lab.fail = RuntimeError("Port belegt")
    assert flapper.tick(60.0) == pytest.approx(demo.RETRY_S)  # nächster Versuch in 5 s, nicht erst in 60 s
    assert flapper.state()["nas-http"] is False and lab.calls == []
    lab.fail = None
    flapper.tick(60.0 + demo.RETRY_S)
    assert flapper.state()["nas-http"] is True and lab.calls == [("stop", *NAS)]  # klappt beim zweiten Versuch


@pytest.mark.parametrize("field", ["telnet_up_s", "telnet_down_s", "http_up_s", "http_down_s"])
@pytest.mark.parametrize("value", [0, -1, float("nan")])
def test_invalid_times_are_refused(field: str, value: float) -> None:
    with pytest.raises(ValueError, match="größer als 0"):
        _flapper(**{field: value})


def test_constants_are_read_when_the_flapper_is_built(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(demo, "TELNET_UP_S", 2.0)
    monkeypatch.setattr(demo, "TELNET_DOWN_S", 3.0)
    flapper, _lab, platform = _flapper()
    flapper.begin(0.0)
    flapper.tick(2.0)
    assert demo.TELNET_IP not in platform.alive
    flapper.tick(5.0)
    assert demo.TELNET_IP in platform.alive


def test_missing_ping_entry_is_replaced_by_a_default_on_recovery() -> None:
    lab, platform = FakeLab(), fake_platform()
    platform.alive.pop(demo.TELNET_IP)  # war nie da (z. B. Gerät ohne Ping)
    flapper = demo.Flapper(lab, platform, telnet_up_s=1, telnet_down_s=1)
    flapper.begin(0.0)
    flapper.tick(1.0)
    flapper.tick(2.0)
    assert platform.alive[demo.TELNET_IP] == PingResult(alive=True, rtt_ms=11.0, ttl=64)


# --- Thread --------------------------------------------------------------------------------------


def test_thread_switches_and_stops_cleanly() -> None:
    flapper, lab, platform = _flapper(telnet_up_s=0.02, telnet_down_s=0.02, http_up_s=0.02, http_down_s=0.02)
    assert not flapper.running and flapper_threads() == []
    flapper.start()
    try:
        assert flapper.running
        assert wait_for(lambda: len(lab.calls) >= 4)  # mehrere Wechsel hin und zurück
    finally:
        flapper.stop()
    assert not flapper.running and flapper_threads() == []
    assert flapper.state() == {"telnet": False, "nas-http": False}
    assert demo.TELNET_IP in platform.alive  # Normalzustand wiederhergestellt
    starts = [c for c in lab.calls if c[0] == "start"]
    stops = [c for c in lab.calls if c[0] == "stop"]
    assert starts and len(starts) == len(stops)  # jedes Anhalten wurde rückgängig gemacht


def test_stop_restores_a_running_outage() -> None:
    flapper, lab, platform = _flapper(telnet_up_s=0.01, telnet_down_s=3600, http_up_s=0.01, http_down_s=3600)
    flapper.start()
    assert wait_for(lambda: demo.TELNET_IP not in platform.alive and ("stop", *NAS) in lab.calls)
    flapper.stop()
    assert demo.TELNET_IP in platform.alive and lab.calls[-1] == ("start", *NAS)  # mitten im Ausfall angehalten
    assert flapper_threads() == []


def test_start_twice_runs_one_thread_and_stop_is_repeatable() -> None:
    flapper, _lab, _platform = _flapper(telnet_up_s=3600, telnet_down_s=3600, http_up_s=3600, http_down_s=3600)
    flapper.start()
    flapper.start()
    assert len(flapper_threads()) == 1
    flapper.stop()
    flapper.stop()  # zweites Mal harmlos
    assert flapper_threads() == []
    flapper.start()  # nach dem Anhalten wieder startbar
    assert flapper.running
    flapper.stop()
    assert flapper_threads() == []


def test_thread_survives_a_failing_switch() -> None:
    flapper, lab, _platform = _flapper(http_up_s=0.01, http_down_s=0.01, telnet_up_s=3600, telnet_down_s=3600)
    lab.fail = RuntimeError("kaputt")
    ticks: list[float] = []
    real_tick = flapper.tick
    flapper.tick = lambda now: (ticks.append(now), real_tick(now))[1]  # type: ignore[method-assign]
    flapper.start()
    try:
        assert wait_for(lambda: len(ticks) >= 5)  # jeder Wechsel scheitert, der Thread macht trotzdem weiter
        assert flapper.running
    finally:
        flapper.stop()
    assert flapper_threads() == []


def test_thread_survives_an_error_in_tick() -> None:
    flapper, _lab, _platform = _flapper(telnet_up_s=3600, telnet_down_s=3600, http_up_s=3600, http_down_s=3600)
    calls: list[float] = []

    def boom(now: float) -> float:
        calls.append(now)
        raise RuntimeError("kaputt")

    flapper.tick = boom  # type: ignore[method-assign]
    flapper.start()
    try:
        assert wait_for(lambda: calls)
        assert flapper.running  # wartet 5 s und versucht es erneut, statt zu sterben
    finally:
        flapper.stop()
    assert flapper_threads() == []


def test_stop_returns_quickly_even_with_long_times() -> None:
    import time

    flapper, _lab, _platform = _flapper()  # Standardzeiten: 3 und 10 Minuten
    flapper.start()
    t0 = time.monotonic()
    flapper.stop()
    assert time.monotonic() - t0 < 2.0 and flapper_threads() == []
