"""Plattform-Schicht: alles, was je Betriebssystem anders ist. Der Rest bleibt plattformneutral."""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from netscan.core.models import PingResult


@dataclass
class AdapterDetail:
    name: str  # Anzeigename wie bei psutil (z. B. "WLAN", "Ethernet", "vEthernet (WSL)")
    description: str = ""  # z. B. "Intel(R) Ethernet Connection I219-V"
    is_virtual: bool = False
    is_wireless: bool = False
    mac: str | None = None


@dataclass
class InterfaceAddr:
    name: str  # Anzeigename (psutil)
    ipv4: str
    netmask: str
    mac: str | None  # normalisiert
    is_up: bool


def psutil_interfaces() -> list[InterfaceAddr]:
    """IPv4-Adressen aller Schnittstellen über psutil (Windows und Linux gleich)."""
    import psutil

    from netscan.core.models import normalize_mac

    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    out: list[InterfaceAddr] = []
    for name, entries in addrs.items():
        mac: str | None = None
        for e in entries:
            if e.family == psutil.AF_LINK and e.address:
                try:
                    mac = normalize_mac(e.address)
                except ValueError:
                    mac = None
        for e in entries:
            if e.family == socket.AF_INET and e.address and e.netmask:
                st = stats.get(name)
                out.append(InterfaceAddr(name=name, ipv4=e.address, netmask=e.netmask, mac=mac, is_up=bool(st and st.isup)))
    return out


@dataclass
class WifiEntry:
    interface: str  # Anzeigename, z. B. "WLAN"
    connected: bool
    ssid: str | None  # None = verbunden, aber Name nicht lesbar


@dataclass
class WifiStatus:
    entries: list[WifiEntry] = field(default_factory=list)
    readable: bool = True  # False = Abfrage ganz gescheitert (z. B. Standortberechtigung fehlt)
    error: str | None = None

    @property
    def connected(self) -> list[WifiEntry]:
        return [e for e in self.entries if e.connected]


@runtime_checkable
class Platform(Protocol):
    name: str

    def interfaces(self) -> list[InterfaceAddr]:
        """IPv4-Adressen aller Schnittstellen. Windows/Linux: psutil_interfaces()."""
        ...

    def adapter_details(self) -> dict[str, AdapterDetail]:
        """Anzeigename -> Details. Fehlt ein Adapter hier, gilt er als physisch."""
        ...

    def wifi_status(self) -> WifiStatus:
        """Verbundene WLANs und ihre Namen. Sendet keine Pakete."""
        ...

    def default_gateway(self, adapter_name: str | None = None) -> str | None:
        """IPv4-Standard-Gateway (für den Adapter, sonst das bevorzugte)."""
        ...

    def neighbor_table(self) -> dict[str, str]:
        """IP -> MAC (normalisiert) aus dem ARP-Cache des Systems. Sendet keine Pakete."""
        ...

    def neighbor_mac(self, ip: str) -> str | None:
        ...

    def ping(self, ip: str, timeout_ms: int) -> PingResult:
        """Ein einzelner Ping. Blockiert höchstens timeout_ms + kleine Reserve."""
        ...

    def is_admin(self) -> bool:
        ...
