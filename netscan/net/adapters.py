"""Netzwerkadapter auflisten (psutil + Plattformdetails), virtuelle ausblenden. (Agent guard)"""

from __future__ import annotations

import ipaddress
import logging

from netscan.config import PREFIX_MIN
from netscan.core.models import Adapter, normalize_mac
from netscan.platform.base import AdapterDetail, InterfaceAddr, Platform

log = logging.getLogger(__name__)

# Muster im Namen oder in der Beschreibung, die einen virtuellen Adapter kennzeichnen
VIRTUAL_PATTERNS: tuple[str, ...] = (
    "hyper-v", "vethernet", "wsl", "virtualbox", "vmware", "loopback", "tap-", "tap adapter",
    "vpn", "wireguard", "tailscale", "zerotier", "openvpn", "npcap loopback", "bluetooth",
    "teredo", "isatap", "docker", "wan miniport",
)


def _looks_virtual(*texts: str) -> bool:
    low = " ".join(t.lower() for t in texts if t)
    return any(pattern in low for pattern in VIRTUAL_PATTERNS)


def _mac(*candidates: str | None) -> str | None:
    for value in candidates:
        if not value:
            continue
        try:
            return normalize_mac(value)
        except ValueError:
            continue
    return None


def _build(iface: InterfaceAddr, detail: AdapterDetail | None) -> Adapter | None:
    """Adapter aus psutil-Adresse und Plattformdetail; None für Loopback, 169.254.x und Unsinn."""
    try:
        net_if = ipaddress.IPv4Interface(f"{iface.ipv4}/{iface.netmask}")
    except ValueError:
        log.debug("Adresse unbrauchbar: %s %s/%s", iface.name, iface.ipv4, iface.netmask)
        return None
    ip = net_if.ip
    if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
        return None
    description = detail.description if detail else ""
    return Adapter(
        name=iface.name,
        description=description,
        mac=_mac(iface.mac, detail.mac if detail else None),
        ipv4=str(ip),
        netmask=str(net_if.netmask),
        network=str(net_if.network),
        prefix=net_if.network.prefixlen,
        is_virtual=bool(detail and detail.is_virtual) or _looks_virtual(iface.name, description),
        is_wireless=bool(detail and detail.is_wireless),
        is_up=bool(iface.is_up),
    )


def _all_adapters(platform: Platform) -> list[Adapter]:
    """Alle brauchbaren Adapter, je Name nur die erste IPv4-Adresse (Name ist der Schlüssel)."""
    try:
        ifaces = platform.interfaces()
    except Exception:  # noqa: BLE001 – Adapterliste darf den Server nie mitreißen
        log.warning("Netzwerkadapter nicht lesbar", exc_info=True)
        return []
    try:
        details = platform.adapter_details() or {}
    except Exception:  # noqa: BLE001 – ohne Details gilt ein Adapter als physisch
        log.warning("Adapterdetails nicht lesbar", exc_info=True)
        details = {}
    out: list[Adapter] = []
    seen: set[str] = set()
    for iface in ifaces:
        if iface.name in seen:
            continue
        adapter = _build(iface, details.get(iface.name))
        if adapter is not None:
            seen.add(iface.name)
            out.append(adapter)
    return out


def _sort_key(adapter: Adapter) -> tuple[bool, bool, str, str]:
    """Physisch vor virtuell, kabelgebunden vor WLAN, dann Name."""
    return (adapter.is_virtual, adapter.is_wireless, adapter.name.lower(), adapter.name)


def list_adapters(platform: Platform, include_virtual: bool = False) -> list[Adapter]:
    """Adapter mit IPv4-Adresse (ohne 127.x/169.254.x). Physische zuerst, dann nach Name."""
    adapters = _all_adapters(platform)
    if not include_virtual:
        adapters = [a for a in adapters if not a.is_virtual]
    return sorted(adapters, key=_sort_key)


def find_adapter(platform: Platform, name: str) -> Adapter | None:
    """Sucht auch unter den virtuellen Adaptern."""
    for adapter in _all_adapters(platform):
        if adapter.name == name:
            return adapter
    return None


def hosts_of(adapter: Adapter) -> list[str]:
    """Alle Host-Adressen des Netzes (ohne Netz- und Broadcastadresse, ohne die eigene).

    Größer als /22 (Präfix < 22) ⇒ ValueError – so ein Netz wird nicht abgesucht.
    """
    network = ipaddress.IPv4Network(adapter.network, strict=False)
    if network.prefixlen < PREFIX_MIN:
        raise ValueError(
            f"Netz {network} ist zu groß (/{network.prefixlen}) – abgesucht werden höchstens /{PREFIX_MIN}-Netze."
        )
    try:
        own: ipaddress.IPv4Address | None = ipaddress.IPv4Address(adapter.ipv4)
    except ValueError:
        own = None
    return [str(host) for host in network.hosts() if host != own]
