"""Integration: Monitor (mit Uhr) + FakeChecks + echter AlertStore/AlertEngine/TargetStore (BAUPLAN §22, §25).

Abnahme Stufe 2: Gerät aus ⇒ nach der eingestellten Zeit Alert, wieder an ⇒ Alert endet; Dienst gestoppt bei
erreichbarem Gerät ⇒ Dienst-Alert. Netz gibt es nicht: Erreichbarkeit und Dienste liefert FakeChecks.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from netscan.core.alerts import AlertEngine, AlertStore
from netscan.core.models import Device, PortResult, ScanOutcome, iso_from_ts
from netscan.core.monitor import Monitor
from netscan.core.targets import TargetStore
from tests.fakes import FakeChecks, RecordingMetrics, make_adapter, seed_device

NAS_MAC, NAS_IP = "00:11:32:aa:bb:03", "192.168.178.3"
PC_MAC, PC_IP = "00:1b:21:aa:bb:05", "192.168.178.5"
T0 = 1_760_000_000.0


@pytest.fixture
def env(services, monkeypatch):  # type: ignore[no-untyped-def]
    assert isinstance(services.alerts, AlertStore) and isinstance(services.alert_engine, AlertEngine)
    assert isinstance(services.targets, TargetStore)
    fc = FakeChecks().install(monkeypatch)
    services.metrics = RecordingMetrics()  # Messwerte sind hier nicht Gegenstand
    clock = {"now": T0}
    monitor = Monitor(services, clock=lambda: clock["now"])
    services.monitor = monitor
    nas = seed_device(services, NAS_MAC, NAS_IP, hostname="nas", category="server",
                      ports=[PortResult(445, service="smb"), PortResult(5000, service="http")])  # fmt: skip
    pc = seed_device(services, PC_MAC, PC_IP, hostname="buero-pc", category="pc")
    yield SimpleNamespace(svc=services, checks=fc, monitor=monitor, clock=clock, nas=nas, pc=pc)
    monitor.stop()


def _cycle(env, advance: float = 60.0):  # type: ignore[no-untyped-def]
    env.clock["now"] += advance
    return env.monitor.run_cycle()


def _active(env, rule: str | None = None) -> list:  # type: ignore[no-untyped-def]
    return [a for a in env.svc.alerts.list() if rule is None or a.rule == rule]


def _events(env, type_: str) -> list[dict]:  # type: ignore[no-untyped-def]
    return [e.data for e in env.svc.bus.history() if e.type == type_]


def test_device_offline_alert_opens_after_threshold_and_closes_when_back(env) -> None:  # type: ignore[no-untyped-def]
    env.monitor.add_target(NAS_MAC)
    env.checks.online(NAS_IP)
    env.monitor.run_cycle()  # T0: online
    env.checks.offline(NAS_IP)
    _cycle(env)  # T0+60: offline seit T0+60
    down_since = env.svc.targets.get(NAS_MAC).down_since
    assert down_since == iso_from_ts(T0 + 60)
    for _ in range(4):  # bis T0+300: 4 Minuten offline – unter der Standardschwelle von 5 Minuten
        _cycle(env)
        assert _active(env) == []
    _cycle(env)  # T0+360: genau 5 Minuten
    [alert] = _active(env)
    assert alert.rule == "device_offline" and alert.key == f"device_offline:{NAS_MAC}"
    assert alert.severity == "critical"  # Server/NAS
    assert alert.title == "nas ist offline" and NAS_IP in alert.message
    target = env.svc.targets.get(NAS_MAC)
    assert alert.target_id == target.id and alert.opened == iso_from_ts(T0 + 360)
    _cycle(env)  # weiter offline: kein zweiter Alert
    assert len(_events(env, "alert.opened")) == 1
    env.checks.online(NAS_IP)
    _cycle(env)  # wieder da ⇒ Alert endet
    assert _active(env) == []
    closed = env.svc.alerts.get(alert.id)
    assert closed.closed == iso_from_ts(T0 + 480)
    assert [e["alert"]["id"] for e in _events(env, "alert.closed")] == [alert.id]
    assert env.svc.alerts.counts()["unacked"] == 1  # bleibt bis zum Quittieren im Verlauf


def test_offline_threshold_follows_settings_and_target(env) -> None:  # type: ignore[no-untyped-def]
    env.svc.settings.update(alert_offline_minutes=2)
    env.monitor.add_target(PC_MAC)
    env.monitor.add_target(NAS_MAC, offline_after_min=10)
    env.monitor.run_cycle()  # T0: beide offline
    _cycle(env)  # T0+60
    assert _active(env) == []
    _cycle(env)  # T0+120: PC nach 2 Minuten (Einstellung), NAS (10 Minuten am Ziel) noch nicht
    assert [a.mac for a in _active(env)] == [PC_MAC]
    assert _active(env)[0].severity == "warning"
    for _ in range(8):
        _cycle(env)
    assert {a.mac for a in _active(env)} == {PC_MAC, NAS_MAC}


def test_service_down_while_device_reachable(env) -> None:  # type: ignore[no-untyped-def]
    target = env.monitor.add_target(NAS_MAC, checks=[{"kind": "http", "port": 5000}, {"kind": "smb", "port": 445}])
    http = next(c for c in target.checks if c.kind == "http")
    env.checks.online(NAS_IP)
    env.checks.service_up(NAS_IP, "http", 5000)
    env.checks.service_up(NAS_IP, "smb", 445)
    env.monitor.run_cycle()  # T0: alles gut
    env.checks.service_down(NAS_IP, "http", 5000)  # Test-Webserver gestoppt, Gerät bleibt per Ping erreichbar
    _cycle(env)  # T0+60: Dienst down seit T0+60
    assert env.svc.targets.get(NAS_MAC).status == "degraded"
    _cycle(env)  # T0+120: 1 Minute – unter der Standardschwelle von 2 Minuten
    assert _active(env) == []
    _cycle(env)  # T0+180: 2 Minuten
    [alert] = _active(env)
    assert alert.rule == "service_down" and alert.key == f"service_down:{http.id}" and alert.check_id == http.id
    assert alert.title == "HTTP 5000 auf nas ausgefallen"
    assert "Das Gerät selbst ist erreichbar." in alert.message
    assert _active(env, "device_offline") == []
    env.checks.service_up(NAS_IP, "http", 5000)
    _cycle(env)
    assert _active(env) == []
    assert env.svc.targets.get(NAS_MAC).status == "online"


def test_device_offline_ends_service_alert(env) -> None:  # type: ignore[no-untyped-def]
    env.monitor.add_target(NAS_MAC, checks=[{"kind": "smb", "port": 445}])
    env.checks.online(NAS_IP)
    env.monitor.run_cycle()  # SMB down seit T0
    _cycle(env, 120)
    assert len(_active(env, "service_down")) == 1
    env.checks.offline(NAS_IP)
    _cycle(env)  # Gerät weg ⇒ Dienst „unknown“ ⇒ Dienst-Alert endet, Geräte-Alert folgt nach der Schwelle
    assert _active(env, "service_down") == []
    _cycle(env, 300)
    assert len(_active(env, "device_offline")) == 1


def test_rtt_high_via_monitor(env) -> None:  # type: ignore[no-untyped-def]
    env.svc.settings.update(alert_rtt_minutes=1)
    env.monitor.add_target(PC_MAC, rtt_threshold_ms=50)
    env.checks.online(PC_IP, rtt_ms=120)
    env.monitor.run_cycle()
    assert _active(env) == []
    _cycle(env)
    [alert] = _active(env)
    assert alert.rule == "rtt_high" and alert.severity == "info" and "120 ms" in alert.message
    env.checks.online(PC_IP, rtt_ms=5)
    _cycle(env)
    assert _active(env) == []


def test_disable_and_remove_target_close_alerts(env) -> None:  # type: ignore[no-untyped-def]
    t = env.monitor.add_target(NAS_MAC, checks=[{"kind": "smb", "port": 445}])
    env.monitor.run_cycle()
    _cycle(env, 300)
    assert len(_active(env, "device_offline")) == 1
    env.monitor.update_target(NAS_MAC, enabled=False)
    assert _active(env) == []
    env.monitor.update_target(NAS_MAC, enabled=True)
    env.checks.online(NAS_IP)
    env.monitor.run_cycle()
    _cycle(env, 120)
    assert [a.key for a in _active(env)] == [f"service_down:{t.checks[0].id}"]
    env.monitor.remove_target(NAS_MAC)
    assert _active(env) == []


def test_blocked_network_pauses_without_alert(env) -> None:  # type: ignore[no-untyped-def]
    from tests.fakes import HOTSPOT_SSID

    env.monitor.add_target(NAS_MAC)
    env.monitor.run_cycle()  # offline seit T0
    env.svc.platform.connect_wifi(HOTSPOT_SSID)
    for _ in range(10):
        _cycle(env)
    assert env.svc.targets.get(NAS_MAC).status == "paused"
    assert _active(env) == []  # Pausen sind Lücken, keine Ausfälle


def test_scan_listener_creates_event_alerts(env) -> None:  # type: ignore[no-untyped-def]
    newcomer = Device(mac="24:0a:c4:00:00:07", ip="192.168.178.42", vendor="Espressif Inc.")
    outcome = ScanOutcome(
        scan_id=5, kind="scan", adapter=make_adapter(), gateway_mac=None, seen_macs=[NAS_MAC, newcomer.mac],
        new_devices=[newcomer], new_ports={NAS_MAC: [PortResult(22, service="ssh", risk="medium")]},
    )  # fmt: skip
    env.svc.notify_scan(outcome)  # Standard-Empfänger: alert_engine.on_scan, monitor.on_scan
    alerts = {a.rule: a for a in _active(env)}
    assert set(alerts) == {"new_device", "new_port"}
    assert alerts["new_port"].title == "Neuer offener Port 22 auf nas" and "Risiko: mittel." in alerts["new_port"].message
    assert env.svc.alerts.acknowledge_all() == 2
    assert _active(env) == []  # Ereignis-Alerts enden mit dem Quittieren
