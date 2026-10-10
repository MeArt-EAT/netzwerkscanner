"""Review 2, B3 und B4: Netz eines neuen Ziels und eigener PC mit veralteter IP (BAUPLAN §18, §22).

B3: Die Router-MAC wird erst übernommen, wenn das Gerät im Durchlauf wiedererkannt wurde (erreichbar und der
ARP-Cache zeigt unter seiner IP seine MAC). B4: Der eigene PC wird nur unter einer Adresse eines aktiven Adapters
geprüft, sonst pausiert (no_adapter) – es geht nichts an das Gerät, das jetzt unter der alten IP antwortet.
Netz gibt es nicht: Erreichbarkeit und Dienste liefert FakeChecks, die Plattform ist FakePlatform.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from netscan.core.monitor import Monitor
from tests.fakes import (
    HOME_GW_IP,
    HOME_GW_MAC,
    FakeChecks,
    RecordingAlertEngine,
    RecordingAlertStore,
    RecordingMetrics,
    seed_device,
)

NAS_MAC, NAS_IP = "00:11:32:aa:bb:03", "192.168.178.3"
FRIEND_GW_MAC = "e0:28:6d:00:00:01"  # Fritzbox der Freunde, gleicher Adressbereich
STRANGER_MAC = "de:ad:be:ef:00:01"
SELF_MAC = "00:1b:21:00:00:20"  # Ethernet-Adapter der FakePlatform (192.168.178.20)
PHONE_MAC = "a4:c3:61:00:00:77"
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
    seed_device(services, NAS_MAC, NAS_IP)
    yield SimpleNamespace(svc=services, checks=fc, monitor=monitor, clock=clock, metrics=services.metrics,
                          platform=services.platform)
    monitor.stop()


def _cycle(env, advance: float = 60.0):  # type: ignore[no-untyped-def]
    env.clock["now"] += advance
    return env.monitor.run_cycle()


# --- B3: Router-MAC erst nach Wiedererkennung ---------------------------------------------------


def test_router_learned_only_after_arp_confirms_device(env) -> None:  # type: ignore[no-untyped-def]
    env.monitor.add_target(NAS_MAC)
    env.checks.online(NAS_IP)
    env.monitor.run_cycle()  # erreichbar, aber noch kein ARP-Eintrag unter der IP
    t = env.svc.targets.get(NAS_MAC)
    assert t.status == "online" and t.gateway_mac is None and t.network is None
    env.platform.neighbors[NAS_IP] = NAS_MAC
    _cycle(env)
    t = env.svc.targets.get(NAS_MAC)
    assert t.gateway_mac == HOME_GW_MAC and t.network == "192.168.178.0/24"


def test_unreachable_new_target_learns_no_router(env) -> None:  # type: ignore[no-untyped-def]
    env.monitor.add_target(NAS_MAC)
    env.monitor.run_cycle()
    t = env.svc.targets.get(NAS_MAC)
    assert t.status == "offline" and t.gateway_mac is None  # Offline-Wertung bleibt (§18), gelernt wird nichts


def test_target_added_in_foreign_network_keeps_home_monitoring(env) -> None:  # type: ignore[no-untyped-def]
    # Bei Freunden (anderer Router, gleicher Adressbereich) wird die NAS zur Überwachung ausgewählt
    env.platform.set_gateway(HOME_GW_IP, FRIEND_GW_MAC)
    env.monitor.add_target(NAS_MAC)
    env.checks.online(NAS_IP)
    env.platform.neighbors[NAS_IP] = STRANGER_MAC  # unter der IP antwortet ein fremdes Gerät
    env.monitor.run_cycle()
    t = env.svc.targets.get(NAS_MAC)
    assert t.gateway_mac is None  # fremden Router nicht gelernt
    assert t.status == "offline" and "anderes Gerät" in t.last_detail  # Wiedererkennung wie bisher (§18)
    assert env.checks.service_calls == []
    # Zurück daheim: das Ziel wird sofort weiter überwacht, nicht als „anderes Netz“ pausiert
    env.platform.set_gateway(HOME_GW_IP, HOME_GW_MAC)
    env.platform.neighbors[NAS_IP] = NAS_MAC
    _cycle(env)
    t = env.svc.targets.get(NAS_MAC)
    assert t.status == "online" and t.pause_code is None
    assert t.gateway_mac == HOME_GW_MAC


def test_learned_router_is_not_replaced_by_cycle(env) -> None:  # type: ignore[no-untyped-def]
    env.monitor.add_target(NAS_MAC)
    env.checks.online(NAS_IP)
    env.platform.neighbors[NAS_IP] = NAS_MAC
    env.monitor.run_cycle()
    assert env.svc.targets.get(NAS_MAC).gateway_mac == HOME_GW_MAC
    env.platform.set_gateway(HOME_GW_IP, FRIEND_GW_MAC)
    _cycle(env)
    t = env.svc.targets.get(NAS_MAC)
    assert t.pause_code == "other_network" and t.gateway_mac == HOME_GW_MAC  # nur ein Scan übernimmt (§26)


# --- B4: eigener PC nur unter eigener Adresse ------------------------------------------------------


def test_own_pc_with_stale_ip_is_paused_without_sending(env) -> None:  # type: ignore[no-untyped-def]
    stale = "192.168.178.34"  # aus dem letzten Scan über LAN; der PC hat jetzt nur .20/.21
    seed_device(env.svc, SELF_MAC, stale, is_self=True)
    env.monitor.add_target(SELF_MAC, checks=[{"kind": "http", "port": 8080}])
    env.checks.online(stale)
    env.checks.service_up(stale, "http", 8080)
    env.platform.neighbors[stale] = PHONE_MAC  # .34 gehört jetzt einem Handy
    status = env.monitor.run_cycle()
    t = env.svc.targets.get(SELF_MAC)
    assert t.status == "paused" and t.pause_code == "no_adapter"
    assert stale in t.pause_reason and "gehört nicht mehr zu diesem PC" in t.pause_reason
    assert env.checks.reach_calls == [] and env.checks.service_calls == []  # nichts an das Handy
    assert env.metrics.samples == []  # Pause = Lücke, kein Ausfall
    assert t.checks[0].status == "unknown"
    assert status.state == "paused" and status.paused == 1


def test_own_pc_at_own_address_is_checked(env) -> None:  # type: ignore[no-untyped-def]
    own = "192.168.178.20"
    seed_device(env.svc, SELF_MAC, own, is_self=True)
    env.monitor.add_target(SELF_MAC, checks=[{"kind": "http", "port": 8080}])
    env.checks.online(own)
    env.checks.service_up(own, "http", 8080)
    env.monitor.run_cycle()
    t = env.svc.targets.get(SELF_MAC)
    assert t.status == "online"
    assert [c[0] for c in env.checks.reach_calls] == [own]
    assert [(c[0], c[2]) for c in env.checks.service_calls] == [(own, 8080)]
    assert t.gateway_mac == HOME_GW_MAC  # eigene Adresse gilt als Wiedererkennung
