"""Fund über den ARP-Cache: Geräte, die ARP beantworten, aber Ping verwerfen (iPhone, iPad, Mac im Ruhezustand).

Befund aus dem ersten Heimnetz-Test (10.10.2026): Der ARP-Scan bekam 0 Antworten. Die Ersatzsuche nahm aus dem
ARP-Cache nur Geräte, die auch auf Ping antworteten. Deshalb fehlten alle Apple-Geräte.
"""

from __future__ import annotations

import pytest

from netscan.core.models import PingResult, ScanRequest
from netscan.net import adapters, arp, names, ports, ssdp
from tests.fakes import FakeArpSender, FakeOui, FakePlatform, make_adapter

ETH = make_adapter("Ethernet", ipv4="192.168.178.20", network="192.168.178.0/24")
IPHONE_IP, IPHONE_MAC = "192.168.178.50", "aa:ec:58:00:00:50"  # private MAC, kein Ping
PRINTER_IP, PRINTER_MAC = "192.168.178.55", "00:80:92:00:00:55"


@pytest.fixture
def env(data_dir, monkeypatch):  # type: ignore[no-untyped-def]
    from netscan.core.services import build_services

    platform = FakePlatform()
    platform.alive = {"192.168.178.1": PingResult(True, 1.0, 64), PRINTER_IP: PingResult(True, 2.0, 64)}
    platform.neighbors.update({PRINTER_IP: PRINTER_MAC, IPHONE_IP: IPHONE_MAC, "10.9.9.9": "00:00:00:09:09:09"})
    services = build_services(data_dir=data_dir, platform=platform, oui=FakeOui())  # type: ignore[arg-type]
    services.settings.update(rate_pps=1000, names_timeout_s=0.2, mdns_timeout_s=0.5, ssdp_timeout_s=0.5)
    sender = FakeArpSender({})  # ARP-Scan liefert nichts (wie im Heimnetz-Test)
    real_arp = arp.arp_scan
    monkeypatch.setattr(adapters, "find_adapter", lambda platform, name: ETH)
    monkeypatch.setattr(arp, "scapy_status", lambda **kw: (True, "Test"))
    monkeypatch.setattr(arp, "arp_scan", lambda ctx, adapter, hosts, sender_=None, **kw: real_arp(ctx, adapter, hosts, sender=sender))
    monkeypatch.setattr(names, "resolve_names", lambda ctx, ips, adapter, **kw: {})
    monkeypatch.setattr(ssdp, "ssdp_discover", lambda ctx, adapter, **kw: {})
    monkeypatch.setattr(ports, "probe_port", lambda ip, port, timeout_s, read_banner=False, **kw: (False, None))
    yield services
    services.close()


def _scan(services, **req):  # type: ignore[no-untyped-def]
    from netscan.scan import pipeline

    services.jobs.start("scan", "Test", lambda ctx: pipeline.run_scan(ctx, ScanRequest(adapter="Ethernet", **req), services))
    assert services.jobs.wait(60)
    return services.jobs.last_result


def test_device_answering_arp_but_not_ping_is_found(env) -> None:  # type: ignore[no-untyped-def]
    res = _scan(env)
    assert res["result"] == "completed", res
    devs = {d.ip: d for d in env.inventory.list_devices()}
    assert IPHONE_IP in devs, "Gerät ohne Ping-Antwort aus dem ARP-Cache fehlt"
    assert devs[IPHONE_IP].discovered_by == ["cache"]
    assert devs[IPHONE_IP].mac_random and devs[IPHONE_IP].category == "phone"
    assert devs[PRINTER_IP].discovered_by == ["ping", "cache"]
    assert "10.9.9.9" not in devs  # Cache-Einträge außerhalb des gescannten Netzes bleiben draußen


def test_zero_arp_answers_are_reported(env) -> None:  # type: ignore[no-untyped-def]
    _scan(env)
    messages = [e["message"] for e in env.inventory.get_log(limit=200)]
    assert any("keine einzige Antwort" in m for m in messages), messages
    assert any("nur über den ARP-Cache" in m for m in messages), messages


def test_registered_mode_takes_cache_only_for_registered_devices(env) -> None:  # type: ignore[no-untyped-def]
    assert _scan(env)["result"] == "completed"
    # fremdes Gerät taucht nachher im Cache an einer neuen IP auf – im Modus registered nicht übernehmen
    env.platform.neighbors["192.168.178.77"] = "00:11:22:33:44:77"
    res = _scan(env, mode="registered")
    assert res["result"] == "completed", res
    assert "192.168.178.77" not in {d.ip for d in env.inventory.list_devices()}
