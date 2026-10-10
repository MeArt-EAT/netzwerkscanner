"""Netzwerkadapter auflisten (psutil + Plattformdetails), virtuelle ausblenden. (Agent guard)"""

from __future__ import annotations

from netscan.core.models import Adapter
from netscan.platform.base import Platform

# Muster im Namen oder in der Beschreibung, die einen virtuellen Adapter kennzeichnen
VIRTUAL_PATTERNS: tuple[str, ...] = (
    "hyper-v", "vethernet", "wsl", "virtualbox", "vmware", "loopback", "tap-", "tap adapter",
    "vpn", "wireguard", "tailscale", "zerotier", "openvpn", "npcap loopback", "bluetooth",
    "teredo", "isatap", "docker", "wan miniport",
)


def list_adapters(platform: Platform, include_virtual: bool = False) -> list[Adapter]:
    """Adapter mit IPv4-Adresse (ohne 127.x/169.254.x). Physische zuerst, dann nach Name."""
    raise NotImplementedError


def find_adapter(platform: Platform, name: str) -> Adapter | None:
    """Sucht auch unter den virtuellen Adaptern."""
    raise NotImplementedError


def hosts_of(adapter: Adapter) -> list[str]:
    """Alle Host-Adressen des Netzes (ohne Netz- und Broadcastadresse, ohne die eigene)."""
    raise NotImplementedError
