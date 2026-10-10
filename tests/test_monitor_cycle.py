"""Monitor-Durchlauf (BAUPLAN §18, §22): Wächter, Netze, Wiedererkennung, Zustände, Messwerte, Thread.

Netz gibt es hier nicht: Erreichbarkeit und Dienste liefert FakeChecks, die Plattform ist FakePlatform.
"""

from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from netscan.core.models import PortResult, ScanOutcome, ts_from_iso
from netscan.core.monitor import Monitor
from netscan.core.targets import TargetExists
from netscan.net import ports
from tests.fakes import (
    HOME_GW_MAC,
    HOTSPOT_SSID,
    FakeChecks,
    RecordingAlertEngine,
    RecordingAlertStore,
    RecordingMetrics,
    make_adapter,
    seed_device,
)

NAS_MAC, NAS_IP = "00:11:32:aa:bb:03", "192.168.178.3"
PC_MAC, PC_IP = "00:1b:21:aa:bb:05", "192.168.178.5"
T0 = 1_760_000_000.0


@pytest.fixture
def env(services, monkeypatch):  # type: ignore[no-untyped-def]
    fc = FakeChecks().install(monkeypatch)
    services.metrics = RecordingMetrics()
    services.alert_engine = RecordingAlertEngine()
    services.alerts = RecordingAlertStore()
    clock = {"now": T0}
    monitor = Monitor(services, clock=lambda: clock["now"])
    services.monitor = monitor
    nas = seed_device(services, NAS_MAC, NAS_IP, ports=[PortResult(445, service="smb"), PortResult(5000, service="http")])
    pc = seed_device(services, PC_MAC, PC_IP)
    yield SimpleNamespace(svc=services, checks=fc, monitor=monitor, clock=clock, nas=nas, pc=pc,
                          metrics=services.metrics, engine=services.alert_engine, platform=services.platform)
    monitor.stop()


def _events(svc, type_: str) -> list[dict]:  # type: ignore[no-untyped-def]
    return [e.data for e in svc.bus.history() if e.type == type_]


def _cycle(env, advance: float = 60.0):  # type: ignore[no-untyped-def]
    env.clock["now"] += advance
    return env.monitor.run_cycle()


# --- Grundzustände --------------------------------------------------------------------------


def test_idle_without_targets(env) -> None:  # type: ignore[no-untyped-def]
    status = env.monitor.run_cycle()
    assert status.state == "idle"
    assert env.checks.reach_calls == []
    assert _events(env.svc, "monitor.status")[-1]["status"]["state"] == "idle"


def test_off_when_disabled_in_settings(env) -> None:  # type: ignore[no-untyped-def]
    env.monitor.add_target(NAS_MAC)
    env.svc.settings.update(monitor_enabled=False)
    status = env.monitor.run_cycle()
    assert status.state == "off"
    assert env.checks.reach_calls == []


def test_online_target_records_sample_and_learns_router(env) -> None:  # type: ignore[no-untyped-def]
    target = env.monitor.add_target(NAS_MAC)
    assert target.gateway_mac is None
    env.checks.online(NAS_IP, rtt_ms=4.0)
    status = env.monitor.run_cycle()
    assert status.state == "running" and status.online == 1 and status.targets == 1
    stored = env.svc.targets.get(NAS_MAC)
    assert stored.status == "online" and stored.last_rtt_ms == 4.0
    assert stored.status_since is not None and stored.down_since is None
    assert stored.gateway_mac == HOME_GW_MAC and stored.network == "192.168.178.0/24"
    assert [(s.target_id, s.check_id, s.ok, s.rtt_ms) for s in env.metrics.samples] == [(target.id, 0, True, 4.0)]
    assert env.metrics.samples[0].ts == int(T0)
    # Absender ist die Adresse des Adapters im Netz des Geräts
    assert env.checks.reach_calls[0][3] == "192.168.178.20"
    cycle = _events(env.svc, "monitor.cycle")[-1]
    assert cycle["targets"][0]["mac"] == NAS_MAC and cycle["targets"][0]["status"] == "online"


def test_offline_keeps_down_since_until_back_online(env) -> None:  # type: ignore[no-untyped-def]
    env.monitor.add_target(NAS_MAC)
    env.monitor.run_cycle()  # keine Antwort
    first = env.svc.targets.get(NAS_MAC)
    assert first.status == "offline" and first.down_since is not None
    _cycle(env)
    second = env.svc.targets.get(NAS_MAC)
    assert second.down_since == first.down_since and second.status_since == first.status_since
    env.checks.online(NAS_IP)
    _cycle(env)
    third = env.svc.targets.get(NAS_MAC)
    assert third.status == "online" and third.down_since is None
    assert ts_from_iso(third.status_since) == T0 + 120
    assert [s.ok for s in env.metrics.samples] == [False, False, True]
    # Die Alert-Auswertung sah jeden Zustand
    assert [x[1] for x in env.engine.targets] == ["offline", "offline", "online"]


# --- Wächter und Netze ----------------------------------------------------------------------


def test_blocked_network_pauses_without_sending(env) -> None:  # type: ignore[no-untyped-def]
    env.monitor.add_target(NAS_MAC)
    env.checks.online(NAS_IP)
    env.platform.connect_wifi(HOTSPOT_SSID)
    status = env.monitor.run_cycle()
    assert status.state == "paused"
    assert env.checks.reach_calls == [] and env.metrics.samples == []
    t = env.svc.targets.get(NAS_MAC)
    assert t.status == "paused" and t.pause_code == "blocked" and "Gesperrt" in t.pause_reason
    guards = _events(env.svc, "guard.result")
    assert guards and guards[-1]["guard"]["decision"] == "block"
    _cycle(env)
    assert len(_events(env.svc, "guard.result")) == len(guards)  # nur bei Wechsel gemeldet


def test_confirm_pauses_too(env) -> None:  # type: ignore[no-untyped-def]
    env.monitor.add_target(NAS_MAC)
    env.platform.wifi_unreadable(profiles={})  # Sperre nicht prüfbar ⇒ confirm
    status = env.monitor.run_cycle()
    t = env.svc.targets.get(NAS_MAC)
    assert status.state == "paused" and t.pause_code == "confirm"
    assert env.checks.reach_calls == []


def test_guard_error_counts_as_block(env, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    env.monitor.add_target(NAS_MAC)

    def boom(*a, **k):  # type: ignore[no-untyped-def]
        raise RuntimeError("kaputt")

    monkeypatch.setattr(env.svc.guard, "check", boom)
    env.monitor.run_cycle()
    assert env.svc.targets.get(NAS_MAC).pause_code == "blocked"
    assert env.checks.reach_calls == []


def test_other_router_pauses_and_scan_takes_target_over(env) -> None:  # type: ignore[no-untyped-def]
    env.monitor.add_target(NAS_MAC)
    env.checks.online(NAS_IP)
    env.monitor.run_cycle()
    assert env.svc.targets.get(NAS_MAC).gateway_mac == HOME_GW_MAC
    other = "aa:bb:cc:00:00:99"
    env.platform.set_gateway("192.168.178.1", other)
    _cycle(env)
    t = env.svc.targets.get(NAS_MAC)
    assert t.status == "paused" and t.pause_code == "other_network"
    calls = len(env.checks.reach_calls)
    # Ein Scan findet das Gerät im neuen Netz ⇒ Ziel überwacht dort weiter
    env.monitor.on_scan(ScanOutcome(scan_id=9, kind="scan", adapter=make_adapter(), gateway_mac=other, seen_macs=[NAS_MAC]))
    assert env.svc.targets.get(NAS_MAC).gateway_mac == other
    _cycle(env)
    assert env.svc.targets.get(NAS_MAC).status == "online"
    assert len(env.checks.reach_calls) == calls + 1


def test_deep_scan_outcome_does_not_move_target(env) -> None:  # type: ignore[no-untyped-def]
    env.monitor.add_target(NAS_MAC)
    env.svc.targets.set_network(env.svc.targets.get(NAS_MAC).id, HOME_GW_MAC, "192.168.178.0/24")
    env.monitor.on_scan(ScanOutcome(scan_id=9, kind="deep_scan", adapter=make_adapter(), gateway_mac="aa:bb:cc:00:00:99",
                                    seen_macs=[NAS_MAC]))
    assert env.svc.targets.get(NAS_MAC).gateway_mac == HOME_GW_MAC


def test_ip_outside_connected_networks_is_paused(env) -> None:  # type: ignore[no-untyped-def]
    seed_device(env.svc, "00:1b:21:aa:bb:77", "10.20.30.40")
    env.monitor.add_target("00:1b:21:aa:bb:77")
    env.monitor.run_cycle()
    t = env.svc.targets.get("00:1b:21:aa:bb:77")
    assert t.pause_code == "no_adapter" and "10.20.30.40" in t.pause_reason
    assert env.checks.reach_calls == []


def test_vanished_source_address_pauses(env) -> None:  # type: ignore[no-untyped-def]
    env.monitor.add_target(NAS_MAC)
    env.checks.raise_gone.add(NAS_IP)
    env.monitor.run_cycle()
    t = env.svc.targets.get(NAS_MAC)
    assert t.status == "paused" and t.pause_code == "no_adapter"
    assert env.metrics.samples == []


def test_pause_resets_outage_counter(env) -> None:  # type: ignore[no-untyped-def]
    env.monitor.add_target(NAS_MAC)
    env.monitor.run_cycle()
    assert env.svc.targets.get(NAS_MAC).down_since is not None
    env.platform.connect_wifi(HOTSPOT_SSID)
    _cycle(env)
    assert env.svc.targets.get(NAS_MAC).down_since is None  # Pausen sind Lücken, keine Ausfälle


# --- Wiedererkennung --------------------------------------------------------------------------


def test_other_device_at_ip_counts_as_offline(env) -> None:  # type: ignore[no-untyped-def]
    env.monitor.add_target(NAS_MAC, checks=[{"kind": "smb", "port": 445}])
    env.checks.online(NAS_IP)
    env.platform.neighbors[NAS_IP] = "de:ad:be:ef:00:01"
    env.monitor.run_cycle()
    t = env.svc.targets.get(NAS_MAC)
    assert t.status == "offline" and "anderes Gerät" in t.last_detail and "de:ad:be:ef:00:01" in t.last_detail
    assert env.checks.service_calls == []  # nie Dienste eines fremden Geräts prüfen


def test_matching_arp_entry_is_fine(env) -> None:  # type: ignore[no-untyped-def]
    env.monitor.add_target(NAS_MAC)
    env.checks.online(NAS_IP)
    env.platform.neighbors[NAS_IP] = NAS_MAC.upper().replace(":", "-")
    env.monitor.run_cycle()
    assert env.svc.targets.get(NAS_MAC).status == "online"


# --- Dienste und Antwortzeit ------------------------------------------------------------------


def test_service_down_makes_target_degraded(env) -> None:  # type: ignore[no-untyped-def]
    t = env.monitor.add_target(NAS_MAC, checks=[{"kind": "smb", "port": 445}, {"kind": "http", "port": 5000}])
    smb, http = sorted(t.checks, key=lambda c: c.port)
    env.checks.online(NAS_IP)
    env.checks.service_up(NAS_IP, "smb", 445)
    env.checks.service_up(NAS_IP, "http", 5000)
    env.monitor.run_cycle()
    assert env.svc.targets.get(NAS_MAC).status == "online"
    env.checks.service_down(NAS_IP, "smb", 445)
    _cycle(env)
    stored = env.svc.targets.get(NAS_MAC)
    checks = {c.id: c for c in stored.checks}
    assert stored.status == "degraded"
    assert checks[smb.id].status == "down" and checks[smb.id].down_since is not None
    assert checks[http.id].status == "up"
    oks = {(s.check_id, s.ts): s.ok for s in env.metrics.samples}
    assert oks[(smb.id, int(T0 + 60))] is False and oks[(http.id, int(T0 + 60))] is True
    assert (smb.id, "down", checks[smb.id].down_since) in env.engine.checks


def test_offline_device_skips_services(env) -> None:  # type: ignore[no-untyped-def]
    t = env.monitor.add_target(NAS_MAC, checks=[{"kind": "smb", "port": 445}])
    env.monitor.run_cycle()
    stored = env.svc.targets.get(NAS_MAC)
    assert stored.status == "offline"
    assert stored.checks[0].status == "unknown" and stored.checks[0].last_detail == "Gerät nicht erreichbar"
    assert env.checks.service_calls == []
    assert [s.check_id for s in env.metrics.samples] == [0]
    assert t.checks[0].id not in {s.check_id for s in env.metrics.samples}


def test_rtt_threshold(env) -> None:  # type: ignore[no-untyped-def]
    env.monitor.add_target(NAS_MAC, rtt_threshold_ms=50)
    env.checks.online(NAS_IP, rtt_ms=80)
    env.monitor.run_cycle()
    t = env.svc.targets.get(NAS_MAC)
    assert t.status == "degraded" and t.rtt_high_since is not None
    since = t.rtt_high_since
    _cycle(env)
    assert env.svc.targets.get(NAS_MAC).rtt_high_since == since
    env.checks.online(NAS_IP, rtt_ms=10)
    _cycle(env)
    t = env.svc.targets.get(NAS_MAC)
    assert t.status == "online" and t.rtt_high_since is None


def test_fixed_tcp_port_and_fallback_ports(env) -> None:  # type: ignore[no-untyped-def]
    env.monitor.add_target(NAS_MAC, method="tcp", tcp_port=5000)
    env.monitor.add_target(PC_MAC)
    env.monitor.run_cycle()
    calls = {c[0]: c for c in env.checks.reach_calls}
    assert calls[NAS_IP][1] == "tcp" and calls[NAS_IP][2] == [5000]
    assert calls[PC_IP][1] == "auto" and calls[PC_IP][2] == []  # PC ohne offene Ports


def test_disabled_check_is_not_run(env) -> None:  # type: ignore[no-untyped-def]
    t = env.monitor.add_target(NAS_MAC, checks=[{"kind": "smb", "port": 445}])
    env.checks.online(NAS_IP)
    env.monitor.update_check(t.checks[0].id, False)
    assert env.engine.removed_checks == [t.checks[0].id]
    env.monitor.run_cycle()
    assert env.checks.service_calls == []
    assert env.svc.targets.get(NAS_MAC).checks[0].status == "unknown"


# --- Zielverwaltung ---------------------------------------------------------------------------


def test_add_target_validates_all_or_nothing(env) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(LookupError):
        env.monitor.add_target("00:00:5e:00:53:01")
    with pytest.raises(ValueError):
        env.monitor.add_target(NAS_MAC, checks=[{"kind": "smb", "port": 445}, {"kind": "telnet", "port": 23}])
    with pytest.raises(ValueError):
        env.monitor.add_target(NAS_MAC, checks=[{"kind": "smb", "port": 445}, {"kind": "smb", "port": 445}])
    with pytest.raises(ValueError):
        env.monitor.add_target(NAS_MAC, method="icmp")
    with pytest.raises(ValueError):
        env.monitor.add_target(NAS_MAC, offline_after_min=0)
    assert env.svc.targets.list() == []
    env.monitor.add_target(NAS_MAC)
    with pytest.raises(TargetExists):
        env.monitor.add_target(NAS_MAC)
    assert _events(env.svc, "monitor.targets")


def test_disable_and_enable_target(env) -> None:  # type: ignore[no-untyped-def]
    env.monitor.add_target(NAS_MAC)
    env.monitor.update_target(NAS_MAC, enabled=False)
    t = env.svc.targets.get(NAS_MAC)
    assert t.status == "paused" and t.pause_code == "disabled"
    assert env.engine.removed_targets == [NAS_MAC]
    assert env.monitor.run_cycle().state == "idle"
    env.monitor.update_target(NAS_MAC, enabled=True)
    assert env.svc.targets.get(NAS_MAC).status == "unknown"
    assert env.monitor.run_cycle().state == "running"


def test_remove_target_deletes_series(env) -> None:  # type: ignore[no-untyped-def]
    t = env.monitor.add_target(NAS_MAC, checks=[{"kind": "smb", "port": 445}])
    env.monitor.remove_check(t.checks[0].id)
    assert (t.id, t.checks[0].id) in env.metrics.deleted
    env.monitor.remove_target(NAS_MAC)
    assert (t.id, None) in env.metrics.deleted
    assert env.engine.removed_targets == [NAS_MAC]
    assert env.svc.targets.get(NAS_MAC) is None
    with pytest.raises(LookupError):
        env.monitor.remove_target(NAS_MAC)
    with pytest.raises(LookupError):
        env.monitor.remove_check(999)


def test_suggestions_mark_active_checks(env) -> None:  # type: ignore[no-untyped-def]
    env.monitor.add_target(NAS_MAC, checks=[{"kind": "tcp", "port": 445}])
    s = {(x["kind"], x["port"]): x["active"] for x in env.monitor.suggestions(NAS_MAC)}
    assert s == {("tcp", 445): True, ("tcp", 5000): False}
    with pytest.raises(LookupError):
        env.monitor.suggestions("00:00:5e:00:53:01")


# --- Wartung und Thread -----------------------------------------------------------------------


def test_maintenance_once_per_hour(env) -> None:  # type: ignore[no-untyped-def]
    env.monitor.run_cycle()
    _cycle(env, 60)
    assert len(env.metrics.compacted) == 1 and len(env.svc.alerts.pruned) == 1
    _cycle(env, 3600)
    assert len(env.metrics.compacted) == 2
    assert env.monitor.status().db_size_bytes is not None


def test_alert_errors_never_stop_the_cycle(env, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    env.monitor.add_target(NAS_MAC)

    def boom(*a, **k):  # type: ignore[no-untyped-def]
        raise RuntimeError("Alert kaputt")

    monkeypatch.setattr(env.engine, "evaluate_target", boom)
    monkeypatch.setattr(env.metrics, "record", boom)
    env.checks.online(NAS_IP)
    assert env.monitor.run_cycle().state == "running"
    assert env.svc.targets.get(NAS_MAC).status == "online"


def test_thread_runs_and_stops_quickly(env) -> None:  # type: ignore[no-untyped-def]
    env.monitor.add_target(NAS_MAC)
    env.checks.online(NAS_IP)
    env.monitor.start()
    env.monitor.start()  # idempotent
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and env.monitor.status().last_cycle is None:
        time.sleep(0.05)
    assert env.monitor.status().state == "running"
    t0 = time.monotonic()
    env.monitor.stop()
    assert time.monotonic() - t0 < 5
    assert env.monitor.status().state == "stopped" and not env.monitor.running


def test_trigger_starts_next_cycle_early(env) -> None:  # type: ignore[no-untyped-def]
    env.monitor.add_target(NAS_MAC)
    env.svc.settings.update(monitor_interval_s=3600)
    env.monitor.start()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and len(env.checks.reach_calls) < 1:
        time.sleep(0.05)
    env.monitor.trigger()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and len(env.checks.reach_calls) < 2:
        time.sleep(0.05)
    assert len(env.checks.reach_calls) >= 2
    assert env.monitor.status().next_cycle is not None


def test_stop_interrupts_slow_checks(env, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    for i in range(20):
        seed_device(env.svc, f"00:1b:21:aa:cc:{i:02x}", f"192.168.178.{100 + i}")
        env.monitor.add_target(f"00:1b:21:aa:cc:{i:02x}")
    original = env.checks.check_reachability

    def slow(ip, **kw):  # type: ignore[no-untyped-def]
        time.sleep(1.5)  # wie ein Timeout (≤ 2 s)
        return original(ip, **kw)

    from netscan.net import checks

    monkeypatch.setattr(checks, "check_reachability", slow)
    env.monitor.start()
    time.sleep(0.5)
    t0 = time.monotonic()
    env.monitor.stop()
    assert time.monotonic() - t0 < 5


def test_services_build_monitor_and_listeners(services) -> None:  # type: ignore[no-untyped-def]
    assert isinstance(services.monitor, Monitor)
    assert services.monitor.status().state == "stopped"  # build_services startet nichts
    assert len(services.scan_listeners) == 2


def test_notify_scan_swallows_listener_errors(services) -> None:  # type: ignore[no-untyped-def]
    seen = []

    def bad(outcome):  # type: ignore[no-untyped-def]
        raise RuntimeError("kaputt")

    services.scan_listeners = [bad, seen.append]
    outcome = ScanOutcome(scan_id=1, kind="scan", adapter=make_adapter())
    services.notify_scan(outcome)
    assert seen == [outcome]


def test_sourceaddressgone_is_the_stage1_class() -> None:
    # Vertrag §23: Prüfungen melden eine fehlende Absenderadresse mit derselben Ausnahme wie der Port-Scan
    assert issubclass(ports.SourceAddressGone, RuntimeError)
