"""Hostnamen: DNS-Rückwärtsauflösung, NetBIOS (NBSTAT, UDP 137) und mDNS (zeroconf). (Agent identify)"""

from __future__ import annotations

from collections.abc import Callable

from netscan.core.context import ScanContext
from netscan.core.models import Adapter, NameInfo

# resolver(ip) -> Name oder None; Standard: socket.gethostbyaddr mit Zeitgrenze
Resolver = Callable[[str], str | None]
# mdns_browser(adapter, timeout_s) -> {ip: (hostname | None, [diensttypen])}; Standard: zeroconf
MdnsBrowser = Callable[[Adapter, float], dict[str, tuple[str | None, list[str]]]]


def resolve_names(
    ctx: ScanContext,
    ips: list[str],
    adapter: Adapter,
    *,
    resolver: Resolver | None = None,
    netbios_port: int = 137,
    mdns_browser: MdnsBrowser | None = None,
) -> dict[str, NameInfo]:
    """Liefert für jede ip ein NameInfo (auch leer). Teilschritte laufen parallel und gedrosselt,
    jeder mit Zeitgrenze (settings.names_timeout_s, settings.mdns_timeout_s)."""
    raise NotImplementedError
