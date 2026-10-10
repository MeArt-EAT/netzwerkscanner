"""Gesamtablauf gegen ein simuliertes Heimnetz auf 127.0.0.0/28 (nur Loopback).

Ersetzt werden nur die Stellen, die sonst ins echte Netz senden würden: ARP-Sender, DNS-Resolver,
mDNS-Browser, SSDP-Ziel (Unicast an den Sim-Router) und die Portnummern (Sim-Ports).
"""

from __future__ import annotations

import time

import pytest

from netscan.core.models import PingResult
from netscan.net import adapters, arp, names, ports, ssdp
from netscan.platform.base import AdapterDetail, InterfaceAddr, WifiEntry, WifiStatus
from tests.fakes import HOTSPOT_SSID, FakeArpSender, FakePlatform, make_adapter
from tests.sim import SimLab, UdpService, free_port

LAB_ADAPTER = make_adapter("Ethernet", ipv4="127.0.0.1", network="127.0.0.0/28", mac="00:1b:21:00:00:01")
ROUTER_IP, ROUTER_MAC = "127.0.0.2", "3c:a6:2f:11:22:02"


def lab_platform(lab: SimLab) -> FakePlatform:
    p = FakePlatform(
        ifaces=[InterfaceAddr("Ethernet", "127.0.0.1", "255.255.255.240", "00:1b:21:00:00:01", True)],
        details={"Ethernet": AdapterDetail("Ethernet", "Intel(R) Ethernet (Test)", False, False, "00:1b:21:00:00:01")},
        wifi=WifiStatus([WifiEntry("WLAN", False, None)], readable=True),
        gateways={None: ROUTER_IP, "Ethernet": ROUTER_IP},
        neighbors={ROUTER_IP: ROUTER_MAC},
    )
    p.alive = lab.ping_results()
    return p


@pytest.fixture
def lab_env(data_dir, monkeypatch):  # type: ignore[no-untyped-def]
    from netscan.core.services import build_services
    from tests.fakes import FakeOui

    with SimLab() as lab:
        platform = lab_platform(lab)
        services = build_services(data_dir=data_dir, platform=platform, oui=FakeOui())  # type: ignore[arg-type]
        services.settings.update(
            rate_pps=1000, names_timeout_s=0.3, mdns_timeout_s=0.5, ssdp_timeout_s=0.5,
            port_timeout_ms=300, ping_timeout_ms=100, home_gateway_macs=[ROUTER_MAC],
        )
        arp_sender = FakeArpSender(lab.arp_answers())

        # SSDP: der Sim-Router antwortet per Unicast mit LOCATION auf seine UPnP-Beschreibung
        igd_url = lab.http_url(ROUTER_IP, 80, "/igd.xml")
        udp_port = free_port(ROUTER_IP, kind=2)
        responder = UdpService(
            ROUTER_IP, udp_port,
            lambda data, addr: (f"HTTP/1.1 200 OK\r\nLOCATION: {igd_url}\r\nSERVER: Sim/1.0 UPnP/1.0\r\n"
                                f"ST: upnp:rootdevice\r\nUSN: uuid:sim::upnp:rootdevice\r\n\r\n").encode()
            if data.startswith(b"M-SEARCH") else None,
        )

        real_arp_scan, real_resolve, real_ssdp, real_probe = arp.arp_scan, names.resolve_names, ssdp.ssdp_discover, ports.probe_port
        monkeypatch.setattr(adapters, "find_adapter", lambda platform, name: LAB_ADAPTER if name == "Ethernet" else None)
        monkeypatch.setattr(arp, "scapy_status", lambda: (True, "Test"))
        monkeypatch.setattr(arp, "arp_scan", lambda ctx, adapter, hosts, sender=None: real_arp_scan(ctx, adapter, hosts, sender=arp_sender))
        monkeypatch.setattr(
            names, "resolve_names",
            lambda ctx, ips, adapter, **kw: real_resolve(
                ctx, ips, adapter,
                resolver={ROUTER_IP: "fritz.box"}.get,
                netbios_port=free_port("127.0.0.1", kind=2),
                mdns_browser=lambda a, t: {"127.0.0.3": ("diskstation.local", ["_smb._tcp", "_http._tcp"]),
                                           "127.0.0.4": ("brother.local", ["_ipp._tcp"])},
            ),
        )
        monkeypatch.setattr(ssdp, "ssdp_discover", lambda ctx, adapter, **kw: real_ssdp(ctx, adapter, target=(ROUTER_IP, udp_port), allowed_ips=kw.get("allowed_ips")))
        monkeypatch.setattr(ports, "probe_port", lab.translating_probe(real_probe))
        try:
            yield services, lab, platform, arp_sender
        finally:
            responder.close()
            services.close()


def _run(services, **req):  # type: ignore[no-untyped-def]
    from netscan.core.models import ScanRequest
    from netscan.scan import pipeline

    request = ScanRequest(adapter="Ethernet", **req)
    services.jobs.start("scan", "Test-Scan", lambda ctx: pipeline.run_scan(ctx, request, services))
    assert services.jobs.wait(60), "Scan hängt"
    return services.jobs.last_result


def test_full_scan_finds_and_classifies_lab(lab_env) -> None:  # type: ignore[no-untyped-def]
    services, lab, platform, _ = lab_env
    t0 = time.monotonic()
    res = _run(services)
    assert res["result"] == "completed", res
    assert time.monotonic() - t0 < 30
    devs = {d.ip: d for d in services.inventory.list_devices()}
    assert set(devs) == {"127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5", "127.0.0.6", "127.0.0.7"}
    assert res["summary"]["devices"] == 7 and res["summary"]["new"] == 7

    router, nas, printer, pc, telnet, phone, me = (devs[f"127.0.0.{i}"] for i in (2, 3, 4, 5, 6, 7, 1))
    assert router.is_gateway and router.category == "router"
    assert router.hostname == "fritz.box"
    assert router.ssdp and router.ssdp.friendly_name == "FRITZ!Box 7590 (Sim)"
    assert nas.vendor == "Synology Incorporated" and nas.category == "server"
    assert {p.port for p in nas.ports} == {22, 445, 5000}
    assert next(p for p in nas.ports if p.port == 445).risk == "high"
    assert printer.category == "printer"
    assert pc.category == "pc"
    tel = next(p for p in telnet.ports if p.port == 23)
    assert tel.risk == "high" and tel.banner and "BusyBox" in tel.banner
    assert phone.mac_random and phone.vendor is None and phone.category == "phone"
    assert me.is_self and me.category == "pc"
    assert all(d.is_new and d.online for d in devs.values())


def test_rescan_keeps_names_and_flags_only_new_device(lab_env) -> None:  # type: ignore[no-untyped-def]
    services, lab, platform, arp_sender = lab_env
    assert _run(services)["result"] == "completed"
    services.inventory.update_user_fields("00:11:32:aa:bb:03", custom_name="NAS Keller", known=True)
    arp_sender.answers["127.0.0.8"] = "b8:27:eb:00:00:08"
    platform.alive["127.0.0.8"] = PingResult(True, 2.0, 64)
    res = _run(services)
    assert res["result"] == "completed"
    assert res["summary"]["new"] == 1
    devs = {d.ip: d for d in services.inventory.list_devices()}
    assert devs["127.0.0.3"].display_name == "NAS Keller"
    assert devs["127.0.0.8"].is_new
    assert not devs["127.0.0.2"].is_new


def test_cancel_during_scan_stops_quickly(lab_env) -> None:  # type: ignore[no-untyped-def]
    services, lab, platform, arp_sender = lab_env
    arp_sender.delay_s = 1.0  # jeder ARP-Block dauert 1 s
    from netscan.core.models import ScanRequest
    from netscan.scan import pipeline

    services.jobs.start("scan", "x", lambda ctx: pipeline.run_scan(ctx, ScanRequest(adapter="Ethernet"), services))
    time.sleep(0.5)
    t0 = time.monotonic()
    services.jobs.cancel()
    assert services.jobs.wait(6)
    assert time.monotonic() - t0 < 5
    assert services.jobs.last_result["result"] == "cancelled"
    assert services.inventory.list_devices() == []


def test_hotspot_blocks_scan_and_registered_mode(lab_env) -> None:  # type: ignore[no-untyped-def]
    services, lab, platform, _ = lab_env
    assert _run(services)["result"] == "completed"
    platform.connect_wifi(HOTSPOT_SSID)
    for mode in ("full", "registered"):
        res = _run(services, mode=mode, confirm_foreign=True)
        assert res["result"] == "blocked", res


def test_registered_mode_does_not_sweep(lab_env) -> None:  # type: ignore[no-untyped-def]
    services, lab, platform, arp_sender = lab_env
    assert _run(services)["result"] == "completed"
    platform.ping_calls.clear()
    arp_sender.calls.clear()
    res = _run(services, mode="registered")
    assert res["result"] == "completed"
    asked = set(platform.ping_calls) | {ip for call in arp_sender.calls for ip in call}
    assert asked <= {"127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5", "127.0.0.6", "127.0.0.7"}
    assert "127.0.0.9" not in asked


def test_port_scan_exclusion_and_deep_scan(lab_env) -> None:  # type: ignore[no-untyped-def]
    services, lab, platform, _ = lab_env
    from netscan.scan import pipeline

    assert _run(services)["result"] == "completed"
    services.inventory.update_user_fields("24:0a:c4:aa:bb:06", port_scan_excluded=True)
    services.settings.update(port_scan_excluded_categories=["printer"])
    assert _run(services)["result"] == "completed"
    devs = {d.ip: d for d in services.inventory.list_devices()}
    assert {p.port for p in devs["127.0.0.6"].ports} == {23}  # nicht neu gescannt, alter Stand bleibt
    assert {p.port for p in devs["127.0.0.4"].ports} == {80, 631, 9100}

    services.jobs.start("deep_scan", "Tiefenscan", lambda ctx: pipeline.run_deep_scan(ctx, "00:11:32:aa:bb:03", services, "Ethernet"))
    assert services.jobs.wait(60)
    res = services.jobs.last_result
    assert res["result"] == "completed", res
    assert set(res["summary"]["open_ports"]) == {22, 445, 5000}
    assert services.inventory.get("00:11:32:aa:bb:03").online  # Tiefenscan verschiebt „online“ nicht
