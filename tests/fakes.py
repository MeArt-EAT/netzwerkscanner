"""Attrappen für Tests: Plattform, Herstellerliste, ARP-Sender. Senden nie etwas."""

from __future__ import annotations

from dataclasses import dataclass, field

from netscan.core.models import Adapter, PingResult, normalize_mac
from netscan.platform.base import AdapterDetail, InterfaceAddr, WifiEntry, WifiStatus

HOME_GW_IP = "192.168.178.1"
HOME_GW_MAC = "3c:a6:2f:00:00:01"  # AVM
HOTSPOT_SSID = "DE22LA000256314 8159"


def make_adapter(
    name: str = "Ethernet",
    ipv4: str = "192.168.178.20",
    network: str = "192.168.178.0/24",
    *,
    wireless: bool = False,
    virtual: bool = False,
    mac: str | None = "00:1b:21:00:00:20",
) -> Adapter:
    prefix = int(network.split("/")[1])
    import ipaddress

    netmask = str(ipaddress.ip_network(network).netmask)
    return Adapter(
        name=name,
        description=f"{name} (Test)",
        mac=mac,
        ipv4=ipv4,
        netmask=netmask,
        network=network,
        prefix=prefix,
        is_virtual=virtual,
        is_wireless=wireless,
        is_up=True,
    )


@dataclass
class FakePlatform:
    """Frei einstellbare Plattform. Standard: Heimnetz über Ethernet, WLAN „Heimnetz“ verbunden."""

    name: str = "fake"
    ifaces: list[InterfaceAddr] = field(
        default_factory=lambda: [
            InterfaceAddr("Ethernet", "192.168.178.20", "255.255.255.0", "00:1b:21:00:00:20", True),
            InterfaceAddr("WLAN", "192.168.178.21", "255.255.255.0", "a4:c3:61:00:00:21", True),
            InterfaceAddr("vEthernet (WSL)", "172.20.0.1", "255.255.240.0", "00:15:5d:00:00:01", True),
            InterfaceAddr("Loopback Pseudo-Interface 1", "127.0.0.1", "255.0.0.0", None, True),
        ]
    )
    details: dict[str, AdapterDetail] = field(
        default_factory=lambda: {
            "Ethernet": AdapterDetail("Ethernet", "Intel(R) Ethernet Connection I219-V", False, False, "00:1b:21:00:00:20"),
            "WLAN": AdapterDetail("WLAN", "Intel(R) Wi-Fi 6 AX201 160MHz", False, True, "a4:c3:61:00:00:21"),
            "vEthernet (WSL)": AdapterDetail("vEthernet (WSL)", "Hyper-V Virtual Ethernet Adapter", True, False, "00:15:5d:00:00:01"),
        }
    )
    wifi: WifiStatus = field(default_factory=lambda: WifiStatus([WifiEntry("WLAN", True, "Heimnetz")], readable=True))
    gateways: dict[str | None, str | None] = field(default_factory=lambda: {None: HOME_GW_IP, "Ethernet": HOME_GW_IP, "WLAN": HOME_GW_IP})
    neighbors: dict[str, str] = field(default_factory=lambda: {HOME_GW_IP: HOME_GW_MAC})
    alive: dict[str, PingResult] = field(default_factory=dict)  # ip -> Ergebnis; fehlt = keine Antwort
    admin: bool = True
    ping_calls: list[str] = field(default_factory=list)

    # --- Einstellhilfen für Tests --------------------------------------------
    def connect_wifi(self, ssid: str | None, interface: str = "WLAN", readable: bool = True) -> None:
        self.wifi = WifiStatus([WifiEntry(interface, True, ssid)], readable=readable)

    def wifi_unreadable(self, error: str = "Standortberechtigung fehlt") -> None:
        self.wifi = WifiStatus([], readable=False, error=error)

    def set_gateway(self, ip: str | None, mac: str | None, adapter: str | None = None) -> None:
        for key in ([adapter] if adapter else [None, "Ethernet", "WLAN"]):
            self.gateways[key] = ip
        if ip and mac:
            self.neighbors[ip] = normalize_mac(mac)

    # --- Platform-Protokoll --------------------------------------------------
    def interfaces(self) -> list[InterfaceAddr]:
        return list(self.ifaces)

    def adapter_details(self) -> dict[str, AdapterDetail]:
        return dict(self.details)

    def wifi_status(self) -> WifiStatus:
        return self.wifi

    def default_gateway(self, adapter_name: str | None = None) -> str | None:
        if adapter_name in self.gateways:
            return self.gateways[adapter_name]
        return self.gateways.get(None)

    def neighbor_table(self) -> dict[str, str]:
        return dict(self.neighbors)

    def neighbor_mac(self, ip: str) -> str | None:
        return self.neighbors.get(ip)

    def ping(self, ip: str, timeout_ms: int) -> PingResult:
        self.ping_calls.append(ip)
        return self.alive.get(ip, PingResult(alive=False))

    def is_admin(self) -> bool:
        return self.admin


class FakeOui:
    """Kleine Herstellerliste für Tests (gleiche Schnittstelle wie OuiDb)."""

    TABLE = {
        "3CA62F": "AVM Audiovisuelles Marketing und Computersysteme GmbH",
        "001132": "Synology Incorporated",
        "30055C": "Brother industries, LTD.",
        "001B21": "Intel Corporate",
        "240AC4": "Espressif Inc.",
        "A4C361": "Apple, Inc.",
        "28EE52": "TP-LINK TECHNOLOGIES CO.,LTD.",
        "B827EB": "Raspberry Pi Foundation",
    }

    def __init__(self) -> None:
        self.entries = len(self.TABLE)
        self.source = "Testliste"

    def lookup(self, mac: str) -> str | None:
        return self.TABLE.get(normalize_mac(mac).replace(":", "")[:6].upper())


class FakeArpSender:
    """ARP-Attrappe: antwortet für die eingetragenen IPs, merkt sich die Anfragen."""

    def __init__(self, answers: dict[str, str], delay_s: float = 0.0) -> None:
        self.answers = {ip: normalize_mac(mac) for ip, mac in answers.items()}
        self.delay_s = delay_s
        self.calls: list[list[str]] = []

    def __call__(self, adapter: Adapter, ips: list[str], timeout_s: float) -> dict[str, str]:
        import time

        self.calls.append(list(ips))
        if self.delay_s:
            time.sleep(self.delay_s)
        return {ip: self.answers[ip] for ip in ips if ip in self.answers}
