"""SSDP/UPnP: M-SEARCH und Gerätebeschreibung (XML). (Agent identify)"""

from __future__ import annotations

from collections.abc import Callable

from netscan.core.context import ScanContext
from netscan.core.models import Adapter, SsdpInfo

# fetch(url, timeout_s) -> bytes
Fetcher = Callable[[str, float], bytes]


def ssdp_discover(
    ctx: ScanContext,
    adapter: Adapter,
    *,
    target: tuple[str, int] = ("239.255.255.250", 1900),
    allowed_ips: set[str] | None = None,
    fetch: Fetcher | None = None,
) -> dict[str, SsdpInfo]:
    """Sendet M-SEARCH (ssdp:all) von adapter.ipv4 aus, sammelt settings.ssdp_timeout_s lang Antworten,
    lädt je Gerät die Beschreibung (nur von IPs aus allowed_ips bzw. aus dem Netz des Adapters)."""
    raise NotImplementedError
