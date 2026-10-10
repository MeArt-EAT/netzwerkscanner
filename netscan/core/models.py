"""Gemeinsame Datentypen. Verbindlich laut docs/BAUPLAN.md – Feldnamen nicht ändern."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from typing import Any, Literal

Category = Literal["router", "switch", "server", "pc", "printer", "iot", "phone", "unknown"]
CATEGORIES: tuple[str, ...] = ("router", "switch", "server", "pc", "printer", "iot", "phone", "unknown")
CATEGORY_LABELS: dict[str, str] = {
    "router": "Router",
    "switch": "Switch",
    "server": "Server/NAS",
    "pc": "PC",
    "printer": "Drucker",
    "iot": "IoT-Gerät",
    "phone": "Handy",
    "unknown": "Unbekannt",
}

Risk = Literal["low", "medium", "high", "critical"]
RISKS: tuple[str, ...] = ("low", "medium", "high", "critical")
RISK_LABELS: dict[str, str] = {"low": "niedrig", "medium": "mittel", "high": "hoch", "critical": "kritisch"}
RISK_ORDER: dict[str, int] = {r: i for i, r in enumerate(RISKS)}

ScanMode = Literal["full", "registered"]
JobKind = Literal["scan", "deep_scan", "oui_update"]
JobState = Literal["idle", "running", "cancelling"]
JobResult = Literal["completed", "cancelled", "failed", "blocked"]
GuardDecision = Literal["allow", "confirm", "block"]
GuardCode = Literal["ok_home", "blocked_ssid", "blocked_gateway", "foreign_network", "unknown_network", "no_gateway"]

_MAC_HEX = re.compile(r"[0-9a-fA-F]")


def utc_now_iso() -> str:
    """Aktuelle Zeit als ISO 8601 in UTC, sekundengenau."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_mac(mac: str) -> str:
    """Bringt eine MAC-Adresse in die Form aa:bb:cc:dd:ee:ff. Wirft ValueError bei Unsinn."""
    if not isinstance(mac, str):
        raise ValueError(f"MAC-Adresse ungültig: {mac!r}")
    digits = "".join(_MAC_HEX.findall(mac))
    stripped = re.sub(r"[\s:\-\.]", "", mac)
    if len(digits) != 12 or len(stripped) != 12:
        raise ValueError(f"MAC-Adresse ungültig: {mac!r}")
    digits = digits.lower()
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def _from_dict(cls: type, data: dict[str, Any]) -> Any:
    """Baut eine Dataclass aus einem Dict und ignoriert unbekannte Schlüssel."""
    names = {f.name for f in fields(cls)}
    return cls(**{k: v for k, v in data.items() if k in names})


@dataclass
class Adapter:
    name: str  # Anzeigename, z. B. "WLAN" oder "Ethernet"
    description: str  # z. B. "Intel(R) Wi-Fi 6 AX201 160MHz"
    mac: str | None
    ipv4: str  # Adresse dieses PCs auf dem Adapter
    netmask: str
    network: str  # z. B. "192.168.178.0/24"
    prefix: int
    is_virtual: bool = False
    is_wireless: bool = False
    is_up: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PortResult:
    port: int
    proto: str = "tcp"
    service: str = ""
    risk: Risk = "low"
    reason: str = ""  # deutsche Begründung, warum diese Risikostufe
    banner: str | None = None  # erste Zeile des Dienstes, höchstens 200 Zeichen

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["risk_label"] = RISK_LABELS.get(self.risk, self.risk)
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PortResult:
        return _from_dict(cls, data)


@dataclass
class NameInfo:
    dns: str | None = None
    netbios: str | None = None
    mdns: str | None = None
    mdns_services: list[str] = field(default_factory=list)  # z. B. ["_ipp._tcp", "_http._tcp"]

    def best(self) -> str | None:
        """Bester Hostname: DNS, dann mDNS, dann NetBIOS."""
        return self.dns or self.mdns or self.netbios

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> NameInfo:
        return _from_dict(cls, data or {})


@dataclass
class SsdpInfo:
    location: str | None = None
    server: str | None = None
    friendly_name: str | None = None
    manufacturer: str | None = None
    model_name: str | None = None
    model_number: str | None = None
    device_type: str | None = None  # z. B. "urn:schemas-upnp-org:device:InternetGatewayDevice:1"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> SsdpInfo | None:
        return _from_dict(cls, data) if data else None


@dataclass
class PingResult:
    alive: bool
    rtt_ms: float | None = None
    ttl: int | None = None


@dataclass
class Device:
    mac: str
    ip: str
    vendor: str | None = None
    mac_random: bool = False
    hostname: str | None = None
    names: NameInfo = field(default_factory=NameInfo)
    ssdp: SsdpInfo | None = None
    ports: list[PortResult] = field(default_factory=list)
    category: Category = "unknown"
    category_source: Literal["auto", "user"] = "auto"
    category_reason: str = ""
    custom_name: str | None = None
    note: str = ""
    known: bool = False
    is_gateway: bool = False
    is_self: bool = False
    port_scan_excluded: bool = False
    online: bool = True
    rtt_ms: float | None = None
    ttl: int | None = None
    discovered_by: list[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    first_seen_scan: int | None = None
    last_seen_scan: int | None = None
    is_new: bool = False  # wird vom Inventory berechnet

    @property
    def display_name(self) -> str:
        if self.custom_name:
            return self.custom_name
        if self.hostname:
            return self.hostname
        if self.ssdp and self.ssdp.friendly_name:
            return self.ssdp.friendly_name
        if self.vendor:
            return self.vendor
        return self.ip

    @property
    def max_risk(self) -> Risk | None:
        if not self.ports:
            return None
        return max((p.risk for p in self.ports), key=lambda r: RISK_ORDER.get(r, 0))  # type: ignore[return-value]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["names"] = self.names.to_dict()
        d["ssdp"] = self.ssdp.to_dict() if self.ssdp else None
        d["ports"] = [p.to_dict() for p in sorted(self.ports, key=lambda p: (p.proto, p.port))]
        d["display_name"] = self.display_name
        d["category_label"] = CATEGORY_LABELS.get(self.category, self.category)
        d["max_risk"] = self.max_risk
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Device:
        d = dict(data)
        d["names"] = NameInfo.from_dict(d.get("names"))
        d["ssdp"] = SsdpInfo.from_dict(d.get("ssdp"))
        d["ports"] = [PortResult.from_dict(p) for p in d.get("ports") or []]
        return _from_dict(cls, d)


@dataclass
class ScanRequest:
    adapter: str  # Adapter.name
    mode: ScanMode = "full"
    port_scan: bool = True
    confirm_foreign: bool = False
    remember_home: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class GuardResult:
    decision: GuardDecision
    code: GuardCode
    reason: str  # deutscher Text für die Oberfläche
    ssid: str | None = None
    ssid_readable: bool = True
    gateway_ip: str | None = None
    gateway_mac: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class JobStatus:
    job_id: str | None = None
    kind: JobKind | None = None
    label: str = ""
    state: JobState = "idle"
    phase: str | None = None
    done: int = 0
    total: int = 0
    message: str = ""
    started: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
