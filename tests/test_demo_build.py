"""Demo: build_demo_services() mit Sim-Netz (BAUPLAN §32) – Aufbau, Einstellungen, Umleitung ins Sim-Netz, Abbau.

Der Datenordner liegt immer in tmp_path (siehe demo_home). Alles läuft über 127.0.0.x; die Netzsperre aus
conftest.py würde jeden Versuch ins echte Netz mit einem Fehler abbrechen.
"""

from __future__ import annotations

import time

import pytest

from netscan import config, demo
from netscan.core.models import ScanRequest
from netscan.net import adapters, arp, checks, names, oui, ports, ssdp
from netscan.scan import pipeline
from tests.test_demo_support import (  # noqa: F401  (Fixtures demo_home und demo_env)
    DB_LIMIT_BYTES,
    FIVE_MACS,
    demo_env,
    demo_home,
    flapper_threads,
    wait_for,
)

# Alles, was die Demo prozessweit ersetzt – nach shutdown_demo() müssen es wieder die Originale sein
PATCHED = [
    (adapters, "list_adapters"), (adapters, "find_adapter"), (arp, "scapy_status"), (arp, "arp_scan"),
    (names, "resolve_names"), (ssdp, "ssdp_discover"), (ports, "probe_port"), (checks, "connect"),
    (oui, "update_from_ieee"), (oui, "_default_fetch"),
]  # fmt: skip


def _originals() -> dict[tuple[str, str], object]:
    return {(m.__name__, n): getattr(m, n) for m, n in PATCHED}


# --- Aufbau ---------------------------------------------------------------------------------------


def test_data_lives_in_the_redirected_folder(demo_env) -> None:  # type: ignore[no-untyped-def]
    data_dir = demo_env.svc.data_dir
    assert data_dir == demo.demo_data_dir() and demo_env.home.resolve() in data_dir.resolve().parents
    assert (data_dir / "netscan.sqlite3").is_file()
    assert not (config.app_home() / "data").exists()  # der normale Datenordner wurde nie angelegt


def test_demo_settings(demo_env) -> None:  # type: ignore[no-untyped-def]
    settings = demo_env.svc.settings.load()
    assert settings.monitor_interval_s == 15 and settings.monitor_timeout_ms == 500
    assert settings.monitor_enabled
    assert settings.names_timeout_s == 0.5 and settings.mdns_timeout_s == 1.0 and settings.ssdp_timeout_s == 1.0


def test_monitor_is_not_started_by_the_demo(demo_env) -> None:  # type: ignore[no-untyped-def]
    # Den Monitor startet server.run(), wie im echten Betrieb (BAUPLAN §18) – nicht demo.py
    assert demo_env.svc.monitor.running is False
    assert demo_env.svc.monitor.status().state == "stopped"


def test_five_devices_are_monitored_with_history(demo_env) -> None:  # type: ignore[no-untyped-def]
    svc = demo_env.svc
    targets = {t.mac: t for t in svc.targets.list()}
    assert set(targets) == FIVE_MACS
    nas = targets[demo.NAS_MAC]
    assert {(c.kind, c.port) for c in nas.checks} == {("smb", 445), ("http", 5000), ("ssh", 22)}
    assert targets[demo.TELNET_MAC].method == "ping"
    now = int(time.time())
    for t in targets.values():
        avail = svc.metrics.availability(t.id, 0, since=now - 7 * 86400, until=now + 1)
        assert avail["samples"] > 1900 and avail["up_pct"] is not None
        series = svc.metrics.series(t.id, 0, since=now - 86400, until=now)
        assert any(p["n"] for p in series["points"])
    assert svc.alerts.list(state="all", limit=1000) and svc.alerts.counts()["active"] == 0


def test_database_stays_small(demo_env) -> None:  # type: ignore[no-untyped-def]
    files = [p for p in demo_env.svc.data_dir.rglob("*") if p.is_file()]
    assert sum(p.stat().st_size for p in files) < DB_LIMIT_BYTES
    assert demo_env.svc.db.size_bytes() < DB_LIMIT_BYTES


# --- Sim-Netz: die NAS und die Umleitung ------------------------------------------------------------


def test_nas_offers_smb_http_https_and_ssh_in_the_sim_net(demo_env) -> None:  # type: ignore[no-untyped-def]
    lab = demo_env.lab
    assert set(lab.port_map[demo.NAS_IP]) == {22, 445, 5000, 5001}
    assert all(lab.service_running(demo.NAS_IP, p) for p in (22, 445, 5000, 5001))
    assert len(lab.devices) == 9  # Standardnetz (6) plus Switch, Raspberry Pi, iPhone


def test_service_checks_reach_the_sim_ports(demo_env) -> None:  # type: ignore[no-untyped-def]
    src = demo.DEMO_ADAPTER.ipv4
    ssh = checks.run_check("ssh", demo.NAS_IP, 22, 1.0, source_ip=src)
    smb = checks.run_check("smb", demo.NAS_IP, 445, 1.0, source_ip=src)
    http = checks.run_check("http", demo.NAS_IP, 5000, 1.0, source_ip=src)
    assert ssh.ok and "SSH-2.0" in ssh.detail
    assert smb.ok  # die SMB-Attrappe beantwortet die Aushandlung (nicht nur „Port offen“)
    assert http.ok and http.code == 200
    https = checks.check_http(demo.NAS_IP, 5001, 1.0, tls=True, source_ip=src)
    assert https.ok and https.code == 200  # selbstsigniertes Test-Zertifikat, ohne Prüfung


def test_unknown_ports_are_refused_and_nothing_leaves_loopback(demo_env) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ConnectionRefusedError):
        checks.connect(demo.NAS_IP, 3389, 0.5)  # die NAS hat keinen Port 3389
    with pytest.raises(ConnectionRefusedError):
        checks.connect("192.168.178.1", 80, 0.5)  # fremde Adresse: Sim lehnt ab, es wird nichts gesendet
    assert ports.probe_port("192.168.178.1", 80, 0.5, False) == (False, None)
    assert checks.run_check("tcp", "192.168.178.1", 80, 0.5).ok is False


def test_oui_update_stays_offline(demo_env) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(OSError, match="Im Demo-Modus"):
        oui.update_from_ieee(demo_env.svc.data_dir)
    with pytest.raises(OSError, match="Im Demo-Modus"):
        oui._default_fetch(oui.OUI_URL)


def test_ping_answers_with_a_different_time_per_device(demo_env) -> None:  # type: ignore[no-untyped-def]
    platform = demo_env.platform
    router = [platform.ping(demo.ROUTER_IP, 500).rtt_ms for _ in range(20)]
    phone = [platform.ping(demo.PHONE_IP, 500).rtt_ms for _ in range(20)]
    assert all(r is not None and 0.5 < r < 1.5 for r in router)
    assert all(r is not None and 15 < r < 30 for r in phone)
    assert len(set(phone)) > 1  # schwankt
    assert platform.ping("127.0.0.12", 500).alive is False  # nicht im Sim-Netz
    assert platform.ping_calls == []  # kein endloses Protokoll in der Dauerdemo


# --- Der Scan danach ---------------------------------------------------------------------------------


def test_scan_in_the_ui_finds_the_other_devices_as_new(demo_env) -> None:  # type: ignore[no-untyped-def]
    svc = demo_env.svc
    request = ScanRequest(adapter=demo.DEMO_ADAPTER.name)
    svc.jobs.start("scan", "Demo-Scan", lambda ctx: pipeline.run_scan(ctx, request, svc))
    assert svc.jobs.wait(60), "Scan hängt"
    result = svc.jobs.last_result
    assert result["result"] == "completed", result
    devices = {d.mac: d for d in svc.inventory.list_devices()}
    assert len(devices) == 10  # fünf bekannte plus Drucker, Handy, Switch, Raspberry Pi, eigener PC
    new = {d.ip for d in devices.values() if d.is_new}
    assert new == {"127.0.0.1", "127.0.0.4", "127.0.0.7", "127.0.0.8", "127.0.0.9"}
    assert not any(devices[mac].is_new for mac in FIVE_MACS) and result["summary"]["new"] == 5
    assert {p.port for p in devices[demo.NAS_MAC].ports} == {22, 445, 5000, 5001}
    assert devices[demo.NAS_MAC].display_name == "NAS"  # Anzeigename bleibt
    # Neue Geräte lösen „Neues Gerät“-Alerts aus, ein neuer Port ist es nicht (alles wie im Inventar)
    active = svc.alerts.list(state="active")
    # der eigene PC (127.0.0.1) löst nie „Neues Gerät“ aus (BAUPLAN §34)
    assert {a.rule for a in active} == {"new_device"} and len(active) == 4


# --- Abbau -------------------------------------------------------------------------------------------


def test_shutdown_restores_every_replaced_function(demo_home) -> None:  # type: ignore[no-untyped-def]
    before = _originals()
    services = demo.build_demo_services()
    runtime = demo.demo_runtime()
    lab = runtime.lab  # type: ignore[union-attr]
    try:
        replaced = _originals()
        assert all(replaced[k] is not before[k] for k in before), "Die Demo ersetzt nicht alle Stellen"
        assert demo.demo_runtime() is runtime and runtime.flapper.running  # type: ignore[union-attr]
    finally:
        services.close()
        demo.shutdown_demo()
    assert all(_originals()[k] is before[k] for k in before)
    assert demo.demo_runtime() is None and flapper_threads() == []
    assert not any(lab.service_running(ip, p) for ip, mapping in lab.port_map.items() for p in mapping)  # Sim-Netz zu


def test_shutdown_is_repeatable_and_safe_without_a_demo() -> None:
    demo.shutdown_demo()
    demo.shutdown_demo()
    assert demo.demo_runtime() is None


def test_building_twice_does_not_stack_replacements(demo_home) -> None:  # type: ignore[no-untyped-def]
    before = _originals()
    first = demo.build_demo_services()
    runtime1 = demo.demo_runtime()
    first.close()  # die Datenbank freigeben, dann baut der zweite Aufruf frisch auf
    second = demo.build_demo_services()
    try:
        runtime2 = demo.demo_runtime()
        assert runtime2 is not runtime1 and runtime1.flapper.running is False  # type: ignore[union-attr]
        assert checks.run_check("ssh", demo.NAS_IP, 22, 1.0).ok  # nur einmal übersetzt: der Port stimmt
        assert len(second.targets.list()) == 5
    finally:
        second.close()
        demo.shutdown_demo()
    assert all(_originals()[k] is before[k] for k in before)
    assert flapper_threads() == []


# --- Wechselspiel im Demo-Prozess --------------------------------------------------------------------


def test_flapper_runs_with_short_times_and_stops_cleanly(demo_home, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    for name in ("TELNET_UP_S", "TELNET_DOWN_S", "NAS_HTTP_UP_S", "NAS_HTTP_DOWN_S"):
        monkeypatch.setattr(demo, name, 0.15)
    services = demo.build_demo_services()
    try:
        runtime = demo.demo_runtime()
        assert runtime is not None and runtime.flapper is not None and runtime.flapper.running
        assert flapper_threads()
        stops: list[tuple[str, int]] = []
        real_stop = runtime.lab.stop_service
        runtime.lab.stop_service = lambda ip, port: (stops.append((ip, port)), real_stop(ip, port))[1]  # type: ignore[method-assign]
        assert wait_for(lambda: len(stops) >= 2, timeout=10)  # HTTP-Dienst fiel mehrfach aus
        assert set(stops) == {(demo.NAS_IP, demo.NAS_HTTP_PORT)}
        assert wait_for(lambda: demo.TELNET_IP not in runtime.platform.alive, timeout=10)  # Telnet-Gerät antwortet nicht
        runtime.flapper.stop()
        assert not runtime.flapper.running and flapper_threads() == []
        assert demo.TELNET_IP in runtime.platform.alive  # nach dem Anhalten wieder normal
        assert runtime.lab.service_running(demo.NAS_IP, demo.NAS_HTTP_PORT)
        assert checks.run_check("http", demo.NAS_IP, demo.NAS_HTTP_PORT, 1.0).ok
    finally:
        services.close()
        demo.shutdown_demo()
    assert flapper_threads() == []


def test_closing_the_runtime_stops_the_flapper_and_restores_the_service(demo_env) -> None:  # type: ignore[no-untyped-def]
    flapper = demo_env.runtime.flapper
    assert flapper.running and flapper_threads()
    demo_env.runtime.close()
    assert not flapper.running and flapper_threads() == []
    demo_env.runtime.close()  # zweites Mal harmlos
    assert demo.demo_runtime() is None
