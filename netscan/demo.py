"""Demo-Modus: simuliertes Heimnetz auf 127.0.0.0/28. Sendet NICHTS ins echte Netz.

Gedacht zum Ausprobieren der Oberfläche und für Tests im Browser. Nutzt die Sim-Bausteine aus
tests/ (läuft deshalb nur aus dem Projektordner) und ersetzt in diesem Prozess genau die Stellen,
die sonst Pakete ins Netz senden würden.
"""

from __future__ import annotations

import atexit
import logging
import shutil
import socket
from pathlib import Path
from typing import Any

from netscan import config
from netscan.core.models import Adapter
from netscan.core.services import Services, build_services

log = logging.getLogger(__name__)

DEMO_ADAPTER = Adapter(
    name="Ethernet (Demo)",
    description="Simuliertes Heimnetz auf 127.0.0.0/28",
    mac="00:1b:21:00:00:01",
    ipv4="127.0.0.1",
    netmask="255.255.255.240",
    network="127.0.0.0/28",
    prefix=28,
    is_virtual=False,
    is_wireless=False,
    is_up=True,
)
ROUTER_IP, ROUTER_MAC = "127.0.0.2", "3c:a6:2f:11:22:02"


def _extra_devices() -> list[Any]:
    from tests.sim import SimDevice

    return [
        SimDevice("127.0.0.8", "28:ee:52:aa:bb:08", "Switch", tcp={22: b"SSH-2.0-dropbear\r\n"},
                  http={80: {"/": ("text/html", b"<title>TP-Link TL-SG108E</title>")}}),
        SimDevice("127.0.0.9", "b8:27:eb:aa:bb:09", "Raspberry Pi", tcp={22: b"SSH-2.0-OpenSSH_9.2p1 Debian\r\n"},
                  http={80: {"/": ("text/html", b"<title>AdGuard Home</title>")}}),
        SimDevice("127.0.0.10", "a4:c3:61:aa:bb:0a", "iPhone"),
    ]


def build_demo_services() -> Services:
    """Services mit Demo-Plattform, eigenem Datenordner und laufendem Sim-Netz."""
    from netscan.net import adapters, arp, names, ports, ssdp
    from netscan.platform.base import AdapterDetail, InterfaceAddr, WifiEntry, WifiStatus
    from tests.fakes import FakeArpSender, FakePlatform
    from tests.sim import SimLab, UdpService, free_port, standard_devices

    base = config.app_home() / "demo-data"
    shutil.rmtree(base, ignore_errors=True)  # jedes Mal frisch
    base.mkdir(parents=True, exist_ok=True)

    lab = SimLab(standard_devices() + _extra_devices()).__enter__()
    atexit.register(lab.__exit__, None, None, None)

    platform = FakePlatform(
        name="demo",
        ifaces=[InterfaceAddr(DEMO_ADAPTER.name, "127.0.0.1", "255.255.255.240", DEMO_ADAPTER.mac, True)],
        details={DEMO_ADAPTER.name: AdapterDetail(DEMO_ADAPTER.name, DEMO_ADAPTER.description, False, False, DEMO_ADAPTER.mac)},
        wifi=WifiStatus([WifiEntry("WLAN", True, "Heimnetz (Demo)")], readable=True),
        gateways={None: ROUTER_IP, DEMO_ADAPTER.name: ROUTER_IP, "WLAN": ROUTER_IP},
        neighbors={ROUTER_IP: ROUTER_MAC},
    )
    platform.alive = lab.ping_results()

    services = build_services(data_dir=base, platform=platform)  # type: ignore[arg-type]
    services.settings.update(names_timeout_s=0.5, mdns_timeout_s=1.0, ssdp_timeout_s=1.0)

    sender = FakeArpSender(lab.arp_answers())
    igd_url = lab.http_url(ROUTER_IP, 80, "/igd.xml")
    udp_port = free_port(ROUTER_IP, kind=socket.SOCK_DGRAM)
    responder = UdpService(
        ROUTER_IP,
        udp_port,
        lambda data, addr: (
            f"HTTP/1.1 200 OK\r\nLOCATION: {igd_url}\r\nSERVER: Demo/1.0 UPnP/1.0\r\nST: upnp:rootdevice\r\n"
            f"USN: uuid:demo::upnp:rootdevice\r\n\r\n"
        ).encode()
        if data.startswith(b"M-SEARCH")
        else None,
    )
    atexit.register(responder.close)

    real_arp_scan, real_resolve, real_ssdp, real_probe = arp.arp_scan, names.resolve_names, ssdp.ssdp_discover, ports.probe_port
    adapters.list_adapters = lambda platform, include_virtual=False: [DEMO_ADAPTER]  # type: ignore[assignment]
    adapters.find_adapter = lambda platform, name: DEMO_ADAPTER if name == DEMO_ADAPTER.name else None  # type: ignore[assignment]
    arp.scapy_status = lambda **kw: (True, "Demo-Modus (simuliert)")  # type: ignore[assignment]
    arp.arp_scan = lambda ctx, adapter, hosts, sender_=None, **kw: real_arp_scan(ctx, adapter, hosts, sender=sender)  # type: ignore[assignment]
    names.resolve_names = lambda ctx, ips, adapter, **kw: real_resolve(  # type: ignore[assignment]
        ctx,
        ips,
        adapter,
        resolver={ROUTER_IP: "fritz.box", "127.0.0.9": "raspberrypi.fritz.box"}.get,
        netbios_port=free_port("127.0.0.1", kind=socket.SOCK_DGRAM),
        mdns_browser=lambda a, t: {
            "127.0.0.3": ("diskstation.local", ["_smb._tcp", "_http._tcp"]),
            "127.0.0.4": ("brother-hl.local", ["_ipp._tcp", "_printer._tcp"]),
            "127.0.0.10": ("iPhone.local", ["_companion-link._tcp"]),
        },
    )
    ssdp.ssdp_discover = lambda ctx, adapter, **kw: real_ssdp(ctx, adapter, target=(ROUTER_IP, udp_port), allowed_ips=kw.get("allowed_ips"))  # type: ignore[assignment]
    ports.probe_port = lab.translating_probe(real_probe)  # type: ignore[assignment]

    log.info("Demo-Netz läuft: %d simulierte Geräte auf 127.0.0.0/28, Daten in %s", len(lab.devices), base)
    return services


def demo_data_dir() -> Path:
    return config.app_home() / "demo-data"
