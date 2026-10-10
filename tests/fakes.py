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
    # ARP-Cache je Schnittstelle (für neighbor_mac(ip, interface)); fehlt die Schnittstelle, gilt neighbors
    iface_neighbors: dict[str, dict[str, str]] = field(default_factory=dict)
    alive: dict[str, PingResult] = field(default_factory=dict)  # ip -> Ergebnis; fehlt = keine Antwort
    admin: bool = True
    ping_calls: list[str] = field(default_factory=list)

    # --- Einstellhilfen für Tests --------------------------------------------
    def connect_wifi(self, ssid: str | None, interface: str = "WLAN", readable: bool = True) -> None:
        self.wifi = WifiStatus([WifiEntry(interface, True, ssid)], readable=readable)

    def wifi_unreadable(self, error: str = "Standortberechtigung fehlt", profiles: dict[str, str] | None = None) -> None:
        """WLAN-Name nicht lesbar; profiles = Netzwerkprofilnamen je Adapter (Windows: Get-NetConnectionProfile)."""
        self.wifi = WifiStatus([], readable=False, error=error, profile_names=dict(profiles or {}))

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

    def neighbor_mac(self, ip: str, interface: str | None = None) -> str | None:
        if interface is not None and interface in self.iface_neighbors:
            return self.iface_neighbors[interface].get(ip)
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


# =====================================================================================
# Stufe 2 – Attrappen für die Überwachung (BAUPLAN §22–25)
# =====================================================================================


def seed_device(services, mac: str, ip: str, **fields):  # type: ignore[no-untyped-def]
    """Legt ein Gerät im Inventar an (wie nach einem Scan) und gibt es zurück. fields: Device-Felder."""
    from netscan.core.models import Device

    inv = services.inventory
    scan_id = inv.begin_scan("scan", "Ethernet", "192.168.178.0/24")
    device = Device(mac=normalize_mac(mac), ip=ip, discovered_by=["ping"], **fields)
    inv.record_seen(device, scan_id)
    if device.ports:
        inv.set_ports(device.mac, [p.port for p in device.ports], device.ports)
    inv.finish_scan(scan_id, "completed", 1)
    stored = inv.get(device.mac)
    assert stored is not None
    return stored


class FakeChecks:
    """Ersetzt netscan.net.checks im Monitor-Test: Ergebnisse je IP bzw. (IP, Art, Port) frei einstellbar.

    install(monkeypatch) hängt die Funktionen an das Modul. Sendet nichts.
    """

    def __init__(self) -> None:
        from netscan.core.models import CheckResult

        self._CheckResult = CheckResult
        self.reach: dict[str, CheckResult] = {}  # IP -> Ergebnis; fehlt = keine Antwort
        self.service: dict[tuple[str, str, int], CheckResult] = {}  # (IP, Art, Port) -> Ergebnis; fehlt = down
        self.reach_calls: list[tuple[str, str, list[int], str | None]] = []
        self.service_calls: list[tuple[str, str, int, str | None]] = []
        self.raise_gone: set[str] = set()  # IPs, bei denen die Absenderadresse fehlt

    def online(self, ip: str, rtt_ms: float = 2.0) -> None:
        self.reach[ip] = self._CheckResult(ok=True, rtt_ms=rtt_ms, detail="Ping-Antwort", method="ping")

    def offline(self, ip: str) -> None:
        self.reach.pop(ip, None)

    def service_up(self, ip: str, kind: str, port: int, rtt_ms: float = 3.0) -> None:
        self.service[(ip, kind, port)] = self._CheckResult(ok=True, rtt_ms=rtt_ms, detail=f"{kind} ok", method=f"{kind}:{port}")

    def service_down(self, ip: str, kind: str, port: int) -> None:
        self.service.pop((ip, kind, port), None)

    # --- Ersatzfunktionen ------------------------------------------------------------------
    def check_reachability(self, ip, *, method, ping, timeout_ms, tcp_ports, source_ip=None):  # type: ignore[no-untyped-def]
        from netscan.net.ports import SourceAddressGone

        self.reach_calls.append((ip, method, list(tcp_ports), source_ip))
        if ip in self.raise_gone:
            raise SourceAddressGone(f"{source_ip} fehlt")
        return self.reach.get(ip) or self._CheckResult(ok=False, detail="keine Antwort", method="ping")

    def run_check(self, kind, ip, port, timeout_s, *, path="/", source_ip=None):  # type: ignore[no-untyped-def]
        self.service_calls.append((ip, kind, port, source_ip))
        return self.service.get((ip, kind, port)) or self._CheckResult(ok=False, detail="Port geschlossen", method=f"{kind}:{port}")

    @staticmethod
    def fallback_tcp_ports(device):  # type: ignore[no-untyped-def]
        return [p.port for p in device.ports][:3]

    @staticmethod
    def suggest_checks(device):  # type: ignore[no-untyped-def]
        return [{"kind": "tcp", "port": p.port, "path": "/", "label": f"TCP {p.port}", "reason": "offen"} for p in device.ports]

    def install(self, monkeypatch) -> FakeChecks:  # type: ignore[no-untyped-def]
        from netscan.net import checks

        for name in ("check_reachability", "run_check", "fallback_tcp_ports", "suggest_checks"):
            monkeypatch.setattr(checks, name, getattr(self, name))
        return self


class RecordingMetrics:
    """MetricsStore-Attrappe: merkt sich Messwerte und Aufrufe."""

    def __init__(self) -> None:
        self.samples: list = []
        self.deleted: list[tuple[int, int | None]] = []
        self.compacted: list[int] = []
        self.pruned: list[set] = []

    def record(self, samples) -> None:  # type: ignore[no-untyped-def]
        self.samples.extend(samples)

    def delete_series(self, target_id: int, check_id: int | None = None) -> int:
        self.deleted.append((target_id, check_id))
        return 0

    def compact(self, now: int, keep_days: int = 30) -> int:
        self.compacted.append(now)
        return 0

    def prune_orphans(self, valid) -> int:  # type: ignore[no-untyped-def]
        self.pruned.append(set(valid))
        return 0

    def size_bytes(self) -> int:
        return 0


class RecordingAlertEngine:
    """AlertEngine-Attrappe: merkt sich, was der Monitor auswerten lässt (Zustände als Kopie)."""

    def __init__(self) -> None:
        self.targets: list[tuple[str, str, str | None, float]] = []  # (mac, status, down_since, now)
        self.checks: list[tuple[int, str, str | None]] = []  # (check_id, status, down_since)
        self.removed_targets: list[str] = []
        self.removed_checks: list[int] = []
        self.scans: list = []

    def evaluate_target(self, target, device, now) -> None:  # type: ignore[no-untyped-def]
        self.targets.append((target.mac, target.status, target.down_since, now))

    def evaluate_check(self, target, check, device, now) -> None:  # type: ignore[no-untyped-def]
        self.checks.append((check.id, check.status, check.down_since))

    def on_target_removed(self, target) -> None:  # type: ignore[no-untyped-def]
        self.removed_targets.append(target.mac)

    def on_check_removed(self, target, check) -> None:  # type: ignore[no-untyped-def]
        self.removed_checks.append(check.id)

    def on_scan(self, outcome) -> None:  # type: ignore[no-untyped-def]
        self.scans.append(outcome)


class RecordingAlertStore:
    def __init__(self) -> None:
        self.pruned: list[float] = []

    def prune(self, now, keep_days=365, keep_max=5000) -> int:  # type: ignore[no-untyped-def]
        self.pruned.append(now)
        return 0
