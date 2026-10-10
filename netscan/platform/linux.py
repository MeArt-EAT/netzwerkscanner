"""Linux-Implementierung (Raspberry Pi später): iw/nmcli, ping, ip route, ip neigh. (Agent guard)"""

from __future__ import annotations

from netscan.core.models import PingResult
from netscan.platform.base import AdapterDetail, InterfaceAddr, WifiStatus, psutil_interfaces


class LinuxPlatform:
    name = "linux"

    def interfaces(self) -> list[InterfaceAddr]:
        return psutil_interfaces()

    def adapter_details(self) -> dict[str, AdapterDetail]:
        raise NotImplementedError

    def wifi_status(self) -> WifiStatus:
        raise NotImplementedError

    def default_gateway(self, adapter_name: str | None = None) -> str | None:
        raise NotImplementedError

    def neighbor_table(self) -> dict[str, str]:
        raise NotImplementedError

    def neighbor_mac(self, ip: str) -> str | None:
        raise NotImplementedError

    def ping(self, ip: str, timeout_ms: int) -> PingResult:
        raise NotImplementedError

    def is_admin(self) -> bool:
        raise NotImplementedError
