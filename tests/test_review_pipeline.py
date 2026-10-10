"""Regressionstests zu Prüfbefunden am Scan-Ablauf: S2 (Modus „nur eingetragene Geräte“), S3 (Netzwechsel
während des Scans), S5/F4 (Ausnahme vom Port-Scan beim ersten Kontakt), F3 (Tiefenscan prüft die Identität),
F5 (device.updated erst nach dem Abschluss), F7 (Einordnung mit ungeprüften gespeicherten Ports).

Nur Attrappen und Loopback (127.0.0.x): ARP-Sender, Ping, Namen, SSDP und Port-Prüfung sind ersetzt.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Any

import pytest

from netscan.core.models import Device, PortResult, ScanRequest
from netscan.net import adapters, arp, names, ports, ssdp
from netscan.scan import pipeline
from tests.fakes import FakeArpSender, FakeOui, FakePlatform, make_adapter
from tests.sim import TcpService, free_port
from tests.test_pipeline_e2e import lab_env  # noqa: F401  (Fixture: simuliertes Heimnetz auf 127.0.0.0/28)

ETH = make_adapter("Ethernet")  # 192.168.178.20/24, MAC 00:1b:21:00:00:20
FOREIGN_GW_MAC = "00:11:22:33:44:01"
REGISTERED_MAC = "aa:bb:cc:00:00:30"
OTHER_AT_30 = "00:11:22:33:44:30"


@dataclass
class Recorder:
    probes: list[str] = field(default_factory=list)
    ssdp_calls: int = 0
    names_calls: list[tuple[list[str], dict[str, Any]]] = field(default_factory=list)


@pytest.fixture
def net(data_dir, monkeypatch):  # type: ignore[no-untyped-def]
    """Scan-Umgebung mit FakePlatform (Netz 192.168.178.0/24), alles Sendende ersetzt und mitgeschrieben."""
    from netscan.core.services import build_services

    platform = FakePlatform()
    services = build_services(data_dir=data_dir, platform=platform, oui=FakeOui())  # type: ignore[arg-type]
    services.settings.update(rate_pps=1000, names_timeout_s=0.2, mdns_timeout_s=0.5, ssdp_timeout_s=0.5, ask_before_foreign_scan=True)
    rec = Recorder()
    sender = FakeArpSender({})
    holder = {"adapter": ETH}

    def probe(ip, port, timeout_s, read_banner=False, **kw):  # type: ignore[no-untyped-def]
        rec.probes.append(ip)
        return (False, None)

    def resolve(ctx, ips, adapter, **kw):  # type: ignore[no-untyped-def]
        rec.names_calls.append((list(ips), dict(kw)))
        browser = kw.get("mdns_browser")
        if browser is not None:
            assert browser(adapter, 0.1) == {}
        return {}

    def discover(ctx, adapter, **kw):  # type: ignore[no-untyped-def]
        rec.ssdp_calls += 1
        return {}

    real_arp = arp.arp_scan
    monkeypatch.setattr(adapters, "find_adapter", lambda p, name: holder["adapter"] if name == "Ethernet" else None)
    monkeypatch.setattr(arp, "scapy_status", lambda **kw: (True, "Test"))
    monkeypatch.setattr(arp, "arp_scan", lambda ctx, adapter, hosts, sender_=None: real_arp(ctx, adapter, hosts, sender=sender))
    monkeypatch.setattr(ports, "probe_port", probe)
    monkeypatch.setattr(names, "resolve_names", resolve)
    monkeypatch.setattr(ssdp, "ssdp_discover", discover)
    yield services, platform, sender, rec, holder
    services.close()


def run(services, **req):  # type: ignore[no-untyped-def]
    request = ScanRequest(adapter="Ethernet", **req)
    services.jobs.start("scan", "Test", lambda ctx: pipeline.run_scan(ctx, request, services))
    assert services.jobs.wait(30)
    return services.jobs.last_result


def register(services, *devices: Device) -> None:  # type: ignore[no-untyped-def]
    scan_id = services.inventory.begin_scan("scan", "Ethernet", "192.168.178.0/24")
    for d in devices:
        services.inventory.record_seen(d, scan_id)
    services.inventory.finish_scan(scan_id, "completed", len(devices))


# --- S2: Modus „nur eingetragene Geräte“ -------------------------------------------------------------


def test_s2_registered_mode_ignores_foreign_router_and_foreign_device(net) -> None:  # type: ignore[no-untyped-def]
    services, platform, sender, rec, _ = net
    register(services, Device(mac=REGISTERED_MAC, ip="192.168.178.30"))
    platform.set_gateway("192.168.178.1", FOREIGN_GW_MAC)  # fremder Router mit gleichem Adressbereich
    sender.answers = {"192.168.178.30": OTHER_AT_30}  # an der eingetragenen IP antwortet ein anderes Gerät
    res = run(services, mode="registered", confirm_foreign=True)
    assert res["result"] == "completed", res
    assert [ip for call in sender.calls for ip in call] == ["192.168.178.30"]  # nur die eingetragene IP gefragt
    assert "192.168.178.1" not in rec.probes and "192.168.178.30" not in rec.probes
    stored = {d.mac for d in services.inventory.list_devices()}
    assert FOREIGN_GW_MAC not in stored and OTHER_AT_30 not in stored
    assert rec.ssdp_calls == 0  # kein M-SEARCH an 239.255.255.250
    for ips, kw in rec.names_calls:  # keine mDNS-Suche ins Segment, keine Namen fremder Geräte
        assert "mdns_browser" in kw
        assert "192.168.178.1" not in ips and "192.168.178.30" not in ips
    logs = " ".join(e.data["message"] for e in services.bus.history(type_prefix="job.log"))
    assert "nicht eingetragene" in logs and OTHER_AT_30 in logs


def test_s2_registered_mode_still_scans_registered_devices_and_router(net) -> None:  # type: ignore[no-untyped-def]
    services, platform, sender, rec, _ = net
    from tests.fakes import HOME_GW_IP, HOME_GW_MAC

    register(services, Device(mac=REGISTERED_MAC, ip="192.168.178.30"), Device(mac=HOME_GW_MAC, ip=HOME_GW_IP))
    services.settings.update(home_gateway_macs=[HOME_GW_MAC])
    sender.answers = {"192.168.178.30": REGISTERED_MAC}
    res = run(services, mode="registered")
    assert res["result"] == "completed", res
    assert "192.168.178.30" in rec.probes and HOME_GW_IP in rec.probes
    devs = {d.mac: d for d in services.inventory.list_devices()}
    assert devs[REGISTERED_MAC].online and devs[HOME_GW_MAC].is_gateway


def test_s2_registered_mode_keeps_stored_upnp_and_mdns(net) -> None:  # type: ignore[no-untyped-def]
    services, platform, sender, rec, _ = net
    from netscan.core.models import NameInfo, SsdpInfo

    register(services, Device(mac=REGISTERED_MAC, ip="192.168.178.30", ssdp=SsdpInfo(friendly_name="TV Wohnzimmer"),
                              names=NameInfo(mdns="tv.local", mdns_services=["_airplay._tcp"])))  # fmt: skip
    sender.answers = {"192.168.178.30": REGISTERED_MAC}
    assert run(services, mode="registered", confirm_foreign=True)["result"] == "completed"
    d = services.inventory.get(REGISTERED_MAC)
    assert d.ssdp and d.ssdp.friendly_name == "TV Wohnzimmer"
    assert d.names.mdns == "tv.local" and d.names.mdns_services == ["_airplay._tcp"]


# --- S3: Netzwechsel während des Scans --------------------------------------------------------------


def test_s3_address_change_after_arp_stops_before_ping(net, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    services, platform, sender, rec, holder = net

    def arp_then_switch(ctx, adapter, hosts, sender_=None):  # type: ignore[no-untyped-def]
        holder["adapter"] = make_adapter("Ethernet", "172.20.10.2", "172.20.10.0/28")  # Windows hat gewechselt
        return {}

    monkeypatch.setattr(arp, "arp_scan", arp_then_switch)
    res = run(services, confirm_foreign=True)
    assert res["result"] == "failed" and "Netzwechsel" in res["error"]
    assert platform.ping_calls == [] and rec.probes == []
    assert services.inventory.list_devices() == []


def test_s3_hotspot_joined_during_scan_blocks_before_the_port_scan(net, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    services, platform, sender, rec, _ = net
    from tests.fakes import HOME_GW_MAC, HOTSPOT_SSID

    services.settings.update(home_gateway_macs=[HOME_GW_MAC])
    sender.answers = {"192.168.178.40": "aa:bb:cc:00:00:40"}

    def discover_then_switch(ctx, adapter, **kw):  # type: ignore[no-untyped-def]
        rec.ssdp_calls += 1
        platform.connect_wifi(HOTSPOT_SSID)  # das WLAN springt in den gespeicherten Hotspot
        return {}

    monkeypatch.setattr(ssdp, "ssdp_discover", discover_then_switch)
    res = run(services, port_scan=True)
    assert res["result"] == "blocked", res
    assert rec.probes == []  # kein einziger Port-Versuch mehr
    assert services.inventory.list_devices() == []
    guard_events = [e.data["guard"] for e in services.bus.history(type_prefix="guard.result")]
    assert guard_events[-1]["code"] == "blocked_ssid"


def test_s3_address_change_during_names_stops_before_ssdp(net, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    services, platform, sender, rec, holder = net
    from tests.fakes import HOME_GW_MAC

    services.settings.update(home_gateway_macs=[HOME_GW_MAC])
    sender.answers = {"192.168.178.40": "aa:bb:cc:00:00:40"}

    def resolve_then_switch(ctx, ips, adapter, **kw):  # type: ignore[no-untyped-def]
        holder["adapter"] = make_adapter("Ethernet", "192.168.43.20", "192.168.43.0/24")  # neues Netz per DHCP
        return {}

    monkeypatch.setattr(names, "resolve_names", resolve_then_switch)
    res = run(services, port_scan=True)
    assert res["result"] == "failed" and "Netzwechsel" in res["error"] and "SSDP" in res["error"]
    assert rec.ssdp_calls == 0 and rec.probes == []
    assert services.inventory.list_devices() == []


def test_s3_probe_port_binds_to_adapter_address_and_refuses_when_it_is_gone() -> None:
    port = free_port("127.0.0.2")
    svc = TcpService("127.0.0.2", port, b"")
    try:
        assert ports.probe_port("127.0.0.2", port, 0.5, source_ip="127.0.0.1")[0] is True
        with pytest.raises(ports.SourceAddressGone):
            ports.probe_port("127.0.0.2", port, 0.5, source_ip="203.0.113.77")  # Adresse gehört diesem PC nicht
    finally:
        svc.close()


def test_s3_scan_ports_fails_instead_of_reporting_everything_closed(make_ctx) -> None:  # type: ignore[no-untyped-def]
    ctx = make_ctx(rate_pps=1000)
    with pytest.raises(ports.SourceAddressGone):
        ports.scan_ports(ctx, {"127.0.0.2": [1, 2, 3]}, source_ip="203.0.113.77")


def test_s3_bind_failure_happens_before_any_connect(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    connects: list[object] = []
    real = socket.socket.connect_ex
    monkeypatch.setattr(socket.socket, "connect_ex", lambda self, addr: connects.append(addr) or real(self, addr))
    with pytest.raises(ports.SourceAddressGone):
        ports.probe_port("127.0.0.2", 80, 0.2, source_ip="203.0.113.77")
    assert connects == []


# --- S5/F4: Ausnahme vom Port-Scan gilt schon beim ersten Kontakt ----------------------------------------


def test_s5_new_printer_and_iot_device_are_spared_on_first_contact(lab_env, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    services, lab, platform, _ = lab_env
    services.settings.update(port_scan_excluded_categories=["printer", "iot"])
    probed: list[str] = []
    inner = ports.probe_port

    def spy(ip, port, timeout_s, read_banner=False, **kw):  # type: ignore[no-untyped-def]
        probed.append(ip)
        return inner(ip, port, timeout_s, read_banner, **kw)

    monkeypatch.setattr(ports, "probe_port", spy)
    request = ScanRequest(adapter="Ethernet")
    services.jobs.start("scan", "x", lambda ctx: pipeline.run_scan(ctx, request, services))
    assert services.jobs.wait(60)
    assert services.jobs.last_result["result"] == "completed"
    assert "127.0.0.4" not in probed  # Brother + mDNS _ipp: Drucker
    assert "127.0.0.6" not in probed  # Espressif: IoT
    assert "127.0.0.3" in probed  # die NAS wird normal gescannt
    devs = {d.ip: d for d in services.inventory.list_devices()}
    assert devs["127.0.0.4"].category == "printer" and devs["127.0.0.4"].ports == []


def test_f4_stored_auto_category_still_counts_for_the_exclusion() -> None:
    job = pipeline.ScanJob(request=ScanRequest(adapter="x"), adapter=ETH, services=None, scan_id=1)  # type: ignore[arg-type]
    prev = Device(mac="aa:bb:cc:00:00:09", ip="192.168.178.9", category="printer", category_source="auto",
                  ports=[PortResult(port=9100)])  # fmt: skip
    job.previous[prev.mac] = prev
    now = Device(mac=prev.mac, ip=prev.ip)  # diesmal ohne Namen
    assert "printer" in pipeline._port_scan_categories(job, now)
    user = Device(mac=prev.mac, ip=prev.ip, category="pc", category_source="user")
    assert pipeline._port_scan_categories(job, user) == {"pc"}  # Nutzerwahl gilt allein


# --- F3: Tiefenscan nur, wenn die IP noch zum Gerät gehört ------------------------------------------------


def _deep(services, mac):  # type: ignore[no-untyped-def]
    services.jobs.start("deep_scan", "Tiefenscan", lambda ctx: pipeline.run_deep_scan(ctx, mac, services, "Ethernet"))
    assert services.jobs.wait(60)
    return services.jobs.last_result


def test_f3_deep_scan_refuses_when_another_device_answers(lab_env, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    services, lab, platform, _ = lab_env
    phone = Device(mac="a4:c3:61:00:00:44", ip="127.0.0.4", vendor="Apple, Inc.", category="phone", category_source="auto",
                   ports=[PortResult(port=62078)])  # fmt: skip
    register(services, phone)
    services.inventory.set_ports(phone.mac, [62078], phone.ports)
    probed: list[str] = []
    monkeypatch.setattr(ports, "probe_port", lambda ip, *a, **k: probed.append(ip) or (False, None))
    res = _deep(services, phone.mac)
    assert res["result"] == "failed" and "anderes Gerät" in res["error"]
    assert probed == []  # der Drucker unter 127.0.0.4 bekommt keine einzige Verbindung
    stored = services.inventory.get(phone.mac)
    assert [p.port for p in stored.ports] == [62078] and stored.category == "phone"


def test_f3_deep_scan_refuses_when_nobody_answers(lab_env, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    services, lab, platform, _ = lab_env
    gone = Device(mac="00:1b:21:00:00:0c", ip="127.0.0.12", ports=[PortResult(port=22)])
    register(services, gone)
    services.inventory.set_ports(gone.mac, [22], gone.ports)
    probed: list[str] = []
    monkeypatch.setattr(ports, "probe_port", lambda ip, *a, **k: probed.append(ip) or (False, None))
    res = _deep(services, gone.mac)
    assert res["result"] == "failed" and "antwortet nicht" in res["error"]
    assert probed == [] and [p.port for p in services.inventory.get(gone.mac).ports] == [22]


def test_f3_deep_scan_without_scapy_uses_ping_and_arp_cache(lab_env, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    services, lab, platform, _ = lab_env
    monkeypatch.setattr(arp, "scapy_status", lambda **kw: (False, "kein Npcap"))
    nas_mac = "00:11:32:aa:bb:03"
    register(services, Device(mac=nas_mac, ip="127.0.0.3"))
    platform.neighbors["127.0.0.3"] = nas_mac
    res = _deep(services, nas_mac)
    assert res["result"] == "completed", res
    assert "127.0.0.3" in platform.ping_calls


# --- F5: device.updated erst nach dem Abschluss -------------------------------------------------------------


def test_f5_device_updated_events_report_online_and_new(lab_env) -> None:  # type: ignore[no-untyped-def]
    services, lab, platform, _ = lab_env
    request = ScanRequest(adapter="Ethernet", port_scan=False)
    services.jobs.start("scan", "x", lambda ctx: pipeline.run_scan(ctx, request, services))
    assert services.jobs.wait(60)
    events = [e.data["device"] for e in services.bus.history(type_prefix="device.updated")]
    assert len(events) == 7
    assert all(d["online"] for d in events)
    assert all(d["is_new"] for d in events)


# --- F7: Einordnung nach dem Bestand, den set_ports speichert -----------------------------------------------


def test_f7_classification_keeps_unscanned_stored_ports() -> None:
    mac = "a4:c3:61:aa:bb:01"
    job = pipeline.ScanJob(request=ScanRequest(adapter="x"), adapter=ETH, services=None, scan_id=2)  # type: ignore[arg-type]
    job.previous[mac] = Device(mac=mac, ip="192.168.178.5", vendor="Apple, Inc.", ports=[PortResult(port=88)])
    job.scanned_ports[mac] = list(ports.COMMON_PORTS)  # Port 88 gehört nicht dazu
    d = Device(mac=mac, ip="192.168.178.5", vendor="Apple, Inc.")
    pipeline.ClassifyEnricher().run(None, job, [d])  # type: ignore[arg-type]
    assert d.category == "pc" and "88" in d.category_reason
    assert d.ports == []  # gespeichert werden weiter nur die frisch gefundenen Ports


def test_f7_scanned_and_closed_ports_do_not_count() -> None:
    mac = "a4:c3:61:aa:bb:01"
    job = pipeline.ScanJob(request=ScanRequest(adapter="x"), adapter=ETH, services=None, scan_id=2)  # type: ignore[arg-type]
    job.previous[mac] = Device(mac=mac, ip="192.168.178.5", vendor="Apple, Inc.", ports=[PortResult(port=22)])
    job.scanned_ports[mac] = list(ports.COMMON_PORTS)  # 22 geprüft und jetzt zu
    d = Device(mac=mac, ip="192.168.178.5", vendor="Apple, Inc.")
    pipeline.ClassifyEnricher().run(None, job, [d])  # type: ignore[arg-type]
    assert d.category == "phone"
