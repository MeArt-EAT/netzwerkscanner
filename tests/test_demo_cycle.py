"""Demo: der Monitor gegen das Sim-Netz (BAUPLAN §18, §22, §32).

Hier prüft der echte Monitor (run_cycle, synchron) die Demo-Geräte über die echten Sim-Sockets auf 127.0.0.x:
Ping kommt aus der FakePlatform, die Dienstprüfungen laufen über das umgeleitete checks.connect. Die Uhr der
Durchläufe wird über den Parameter `now` gesetzt – so entstehen die Alert-Schwellen ohne Warten.
"""

from __future__ import annotations

import time

from fastapi.testclient import TestClient

from netscan import demo
from netscan.core.models import PingResult
from netscan.net import checks
from netscan.web import server
from tests.test_demo_support import (  # noqa: F401  (Fixtures demo_home und demo_env)
    FIVE_MACS,
    demo_env,
    demo_home,
    flapper_threads,
    wait_for,
)

# Beginnt etwas in der Zukunft: die Messwerte der Durchläufe überschreiben so nie einen Wert des Demo-Verlaufs
START = time.time() + 600.0
ACCEPTED_CLOSED = ("Port geschlossen", "keine Antwort")  # Windows meldet geschlossene Loopback-Ports oft erst nach der Frist


def _targets(svc):  # type: ignore[no-untyped-def]
    return {t.mac: t for t in svc.targets.list()}


def _checks(target) -> dict[str, object]:  # type: ignore[no-untyped-def]
    return {c.kind: c for c in target.checks}


# --- Normalbetrieb ---------------------------------------------------------------------------------


def test_first_cycle_finds_everything_online(demo_env) -> None:  # type: ignore[no-untyped-def]
    svc = demo_env.svc
    raw_before = svc.metrics.counts()["raw"]
    status = svc.monitor.run_cycle(START)
    assert status.state == "running" and status.targets == 5
    assert (status.online, status.degraded, status.offline, status.paused) == (5, 0, 0, 0)
    targets = _targets(svc)
    assert set(targets) == FIVE_MACS
    for t in targets.values():
        assert t.status == "online" and t.pause_code is None and t.down_since is None, t.mac
        assert t.last_rtt_ms is not None and t.last_method == "ping"
    nas = _checks(targets[demo.NAS_MAC])
    assert {k: c.status for k, c in nas.items()} == {"smb": "up", "http": "up", "ssh": "up"}  # type: ignore[attr-defined]
    assert "SSH-2.0" in nas["ssh"].last_detail and nas["http"].last_detail == "HTTP 200"  # type: ignore[attr-defined]
    assert nas["smb"].last_rtt_ms is not None  # type: ignore[attr-defined]
    assert svc.metrics.counts()["raw"] == raw_before + 8  # 5 Geräte + 3 Dienste
    assert svc.alerts.counts()["active"] == 0


def test_the_guard_allows_the_demo_network(demo_env) -> None:  # type: ignore[no-untyped-def]
    svc = demo_env.svc
    svc.monitor.run_cycle(START)
    guards = [e.data["guard"] for e in svc.bus.history() if e.type == "guard.result"]
    assert guards and guards[-1]["decision"] == "allow"
    assert all(t.pause_code is None for t in svc.targets.list())  # nichts pausiert: es wurde wirklich geprüft


def test_cycle_publishes_status_and_targets(demo_env) -> None:  # type: ignore[no-untyped-def]
    svc = demo_env.svc
    svc.monitor.run_cycle(START)
    cycle = [e.data for e in svc.bus.history() if e.type == "monitor.cycle"][-1]
    assert {t["mac"] for t in cycle["targets"]} == FIVE_MACS and all(t["status"] == "online" for t in cycle["targets"])
    status = [e.data["status"] for e in svc.bus.history() if e.type == "monitor.status"][-1]
    assert status["state"] == "running" and status["interval_s"] == 15 and status["online"] == 5


def test_service_checks_bind_to_the_demo_adapter_and_stay_in_the_sim_net(demo_env) -> None:  # type: ignore[no-untyped-def]
    # Kein monkeypatch: dessen Rückbau käme nach dem Abbau der Demo und stellte die Demo-Funktion wieder her.
    seen: list[tuple[str, int, str | None]] = []
    original = checks.connect

    def spy(ip: str, port: int, timeout_s: float, source_ip: str | None = None):  # type: ignore[no-untyped-def]
        seen.append((ip, port, source_ip))
        return original(ip, port, timeout_s, source_ip)

    checks.connect = spy  # type: ignore[assignment]
    try:
        demo_env.svc.monitor.run_cycle(START)
    finally:
        checks.connect = original  # type: ignore[assignment]
    assert sorted(port for _ip, port, _src in seen) == [22, 445, 5000]  # nur die drei Dienstprüfungen der NAS (Ping kommt aus der Plattform)
    assert {ip for ip, _port, _src in seen} == {demo.NAS_IP}
    assert {src for _ip, _port, src in seen} == {demo.DEMO_ADAPTER.ipv4}  # gebunden an die Adresse des Demo-Adapters
    assert all(t.status == "online" for t in demo_env.svc.targets.list())


# --- HTTP-Dienst der NAS -----------------------------------------------------------------------------


def test_http_outage_is_down_then_alerts_after_two_minutes_then_recovers(demo_env) -> None:  # type: ignore[no-untyped-def]
    svc, lab = demo_env.svc, demo_env.lab
    svc.monitor.run_cycle(START)
    lab.stop_service(demo.NAS_IP, demo.NAS_HTTP_PORT)

    svc.monitor.run_cycle(START + 60)
    nas = _targets(svc)[demo.NAS_MAC]
    nas_checks = _checks(nas)
    assert nas.status == "degraded"  # erreichbar, aber ein Dienst ist down
    assert nas_checks["http"].status == "down" and nas_checks["http"].last_detail in ACCEPTED_CLOSED  # type: ignore[attr-defined]
    assert nas_checks["smb"].status == "up" and nas_checks["ssh"].status == "up"  # type: ignore[attr-defined]
    assert svc.alerts.list(state="active") == []  # noch keine 2 Minuten

    svc.monitor.run_cycle(START + 60 + 125)
    active = svc.alerts.list(state="active")
    assert [(a.rule, a.severity, a.mac, a.title) for a in active] == [
        ("service_down", "warning", demo.NAS_MAC, "HTTP 5000 auf NAS ausgefallen")
    ]  # fmt: skip
    assert active[0].check_id == nas_checks["http"].id  # type: ignore[attr-defined]

    lab.start_service(demo.NAS_IP, demo.NAS_HTTP_PORT)
    svc.monitor.run_cycle(START + 400)
    nas = _targets(svc)[demo.NAS_MAC]
    assert nas.status == "online" and _checks(nas)["http"].status == "up"  # type: ignore[attr-defined]
    assert svc.alerts.list(state="active") == []
    closed = svc.alerts.get(active[0].id)
    assert closed is not None and closed.closed is not None and closed.acknowledged is None  # beendet, aber unquittiert


def test_device_alert_does_not_fire_for_a_service_outage(demo_env) -> None:  # type: ignore[no-untyped-def]
    svc = demo_env.svc
    demo_env.lab.stop_service(demo.NAS_IP, demo.NAS_HTTP_PORT)
    for k in range(4):
        svc.monitor.run_cycle(START + 60 * k)
    assert {a.rule for a in svc.alerts.list(state="active")} == {"service_down"}  # kein device_offline für die NAS


# --- Telnet-Gerät --------------------------------------------------------------------------------------


def test_telnet_device_going_away_raises_an_offline_alert(demo_env) -> None:  # type: ignore[no-untyped-def]
    svc, platform = demo_env.svc, demo_env.platform
    svc.monitor.run_cycle(START)
    original = platform.alive.pop(demo.TELNET_IP)

    status = svc.monitor.run_cycle(START + 60)
    assert status.offline == 1 and status.online == 4
    telnet = _targets(svc)[demo.TELNET_MAC]
    assert telnet.status == "offline" and telnet.down_since is not None and telnet.last_rtt_ms is None
    assert svc.alerts.list(state="active") == []  # Schwelle des Ziels: 2 Minuten

    svc.monitor.run_cycle(START + 60 + 125)
    active = svc.alerts.list(state="active")
    assert [(a.rule, a.severity, a.mac, a.title) for a in active] == [
        ("device_offline", "warning", demo.TELNET_MAC, "Telnet-Gerät ist offline")
    ]  # fmt: skip

    platform.alive[demo.TELNET_IP] = original
    status = svc.monitor.run_cycle(START + 400)
    assert status.online == 5 and svc.alerts.list(state="active") == []
    assert _targets(svc)[demo.TELNET_MAC].down_since is None


def test_other_devices_stay_online_while_the_telnet_device_is_away(demo_env) -> None:  # type: ignore[no-untyped-def]
    svc = demo_env.svc
    demo_env.platform.alive.pop(demo.TELNET_IP)
    svc.monitor.run_cycle(START)
    online = {t.mac for t in svc.targets.list() if t.status == "online"}
    assert online == FIVE_MACS - {demo.TELNET_MAC}


# --- Wechselspiel und Monitor zusammen --------------------------------------------------------------------


def test_flapper_outages_are_seen_by_the_monitor(demo_env) -> None:  # type: ignore[no-untyped-def]
    svc, lab, platform = demo_env.svc, demo_env.lab, demo_env.platform
    demo_env.runtime.flapper.stop()  # kein Hintergrund-Thread: die Zeit setzt der Test
    flapper = demo.Flapper(lab, platform, telnet_up_s=5, telnet_down_s=100, http_up_s=5, http_down_s=100)
    flapper.begin(0.0)
    try:
        assert svc.monitor.run_cycle(START).online == 5
        flapper.tick(10.0)  # beide fallen aus
        assert flapper.state() == {"telnet": True, "nas-http": True}
        status = svc.monitor.run_cycle(START + 60)
        targets = _targets(svc)
        assert targets[demo.TELNET_MAC].status == "offline" and targets[demo.NAS_MAC].status == "degraded"
        assert _checks(targets[demo.NAS_MAC])["http"].status == "down"  # type: ignore[attr-defined]
        assert (status.offline, status.degraded, status.online) == (1, 1, 3)
        flapper.tick(200.0)  # beide wieder da
        status = svc.monitor.run_cycle(START + 120)
        assert status.online == 5 and flapper.state() == {"telnet": False, "nas-http": False}
    finally:
        flapper.restore()


def test_alerts_from_the_flapper_open_and_close_like_in_the_real_demo(demo_env) -> None:  # type: ignore[no-untyped-def]
    # Die Zeiten der Demo (Telnet: ab 3 Minuten für 6, HTTP: ab 10 Minuten für 4) in Schritten von 60 s nachgespielt
    svc, lab, platform = demo_env.svc, demo_env.lab, demo_env.platform
    demo_env.runtime.flapper.stop()
    flapper = demo.Flapper(lab, platform)
    flapper.begin(0.0)
    active_rules: dict[int, set[str]] = {}
    try:
        for second in range(0, 961, 60):
            flapper.tick(float(second))
            svc.monitor.run_cycle(START + second)
            active_rules[second] = {a.rule for a in svc.alerts.list(state="active")}
    finally:
        flapper.restore()
    # Telnet fällt bei 180 s aus; die Schwelle von 2 Minuten ist bei 300 s erreicht; bei 540 s ist das Gerät wieder da
    assert "device_offline" not in active_rules[240] and "device_offline" in active_rules[300]
    assert "device_offline" in active_rules[480] and "device_offline" not in active_rules[540]
    # Der HTTP-Dienst fällt bei 600 s aus; Schwelle (2 Minuten) bei 720 s; bei 840 s läuft er wieder
    assert "service_down" not in active_rules[660] and "service_down" in active_rules[720]
    assert "service_down" in active_rules[780] and "service_down" not in active_rules[840]
    # Bei 720 s fällt das Telnet-Gerät zum zweiten Mal aus (3 Minuten Pause, dann wieder 6 Minuten weg);
    # der HTTP-Alert ist längst beendet, der zweite Offline-Alert öffnet bei 840 s
    assert active_rules[960] == {"device_offline"}
    alerts = svc.alerts.list(state="all")
    assert sum(a.title == "Telnet-Gerät ist offline" and a.closed is not None for a in alerts) >= 1
    assert sum(a.title == "HTTP 5000 auf NAS ausgefallen" and a.closed is not None for a in alerts) >= 1


# --- Der echte Server mit Monitor-Thread (wie server.run) -------------------------------------------------


def test_server_with_monitor_thread_serves_the_demo(demo_env) -> None:  # type: ignore[no-untyped-def]
    svc = demo_env.svc
    app = server.create_app(svc, start_monitor=True)  # startet den Monitor wie server.run()
    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        assert wait_for(lambda: svc.monitor.status().state == "running" and svc.monitor.status().online == 5, timeout=15)
        monitor = client.get("/api/monitor").json()
        assert monitor["status"]["interval_s"] == 15 and monitor["status"]["online"] == 5
        views = {t["mac"]: t for t in monitor["targets"]}
        assert set(views) == FIVE_MACS
        nas = views[demo.NAS_MAC]
        assert nas["device"]["display_name"] == "NAS" and nas["status"] == "online"
        assert nas["availability"]["7d"]["up_pct"] is not None and nas["availability"]["24h"]["up_pct"] is not None
        assert [c["availability"]["7d"]["up_pct"] is not None for c in nas["checks"]] == [True, True, True]
        series = client.get("/api/metrics/series", params={"mac": demo.ROUTER_MAC, "range": "7d"}).json()
        assert sum(1 for p in series["points"] if p["n"]) > 100
        trend = client.get("/api/metrics/trend", params={"mac": demo.PHONE_MAC, "days": 7}).json()
        assert len(trend) == 7 and any(d["up_pct"] is not None for d in trend)
        stats = client.get("/api/alerts/stats", params={"days": 30}).json()
        assert sum(d["device_offline"] for d in stats["days"]) > 0 and sum(d["service_down"] for d in stats["days"]) > 0
        unacked = client.get("/api/alerts", params={"state": "unacked"}).json()
        assert [a["title"] for a in unacked] == ["HTTP 5000 auf NAS ausgefallen", "Telnet-Gerät ist offline"]
        overview = client.get("/api/metrics/overview").json()
        assert overview["counts"]["online"] == 5 and overview["db_warn"] is False
        status = client.get("/api/status").json()
        assert status["monitor"]["state"] == "running" and status["alerts"]["unacked"] == 2
    assert svc.monitor.running is False  # beim Beenden des Servers hält der Monitor an
    assert flapper_threads()  # das Wechselspiel läuft unabhängig davon weiter, bis die Demo abgebaut wird


def test_manual_trigger_checks_again_at_once(demo_env) -> None:  # type: ignore[no-untyped-def]
    svc = demo_env.svc
    svc.monitor.start()
    try:
        assert wait_for(lambda: svc.monitor.status().online == 5, timeout=15)
        demo_env.platform.alive.pop(demo.TELNET_IP)
        svc.monitor.trigger()  # „Jetzt prüfen“ – nicht erst nach 15 Sekunden
        assert wait_for(lambda: svc.monitor.status().offline == 1, timeout=10)
    finally:
        svc.monitor.stop()
        demo_env.platform.alive[demo.TELNET_IP] = PingResult(alive=True, rtt_ms=11.0, ttl=64)
    assert svc.monitor.running is False
