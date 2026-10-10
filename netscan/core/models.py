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
GuardCode = Literal["ok_home", "ok_network", "blocked_ssid", "blocked_gateway", "foreign_network", "unknown_network", "no_gateway"]

# Stufe 2 – Überwachung (BAUPLAN §19)
TargetStatus = Literal["unknown", "online", "degraded", "offline", "paused"]
TARGET_STATUS_LABELS: dict[str, str] = {
    "unknown": "unbekannt",
    "online": "online",
    "degraded": "gestört",
    "offline": "offline",
    "paused": "pausiert",
}
PauseCode = Literal["blocked", "confirm", "no_adapter", "other_network", "disabled"]
ReachMethod = Literal["auto", "ping", "tcp"]
REACH_METHODS: tuple[str, ...] = ("auto", "ping", "tcp")
CheckKind = Literal["tcp", "http", "https", "smb", "ssh"]
CHECK_KINDS: tuple[str, ...] = ("tcp", "http", "https", "smb", "ssh")
CheckStatus = Literal["unknown", "up", "down"]
MonitorState = Literal["stopped", "off", "idle", "running", "paused"]
AlertRule = Literal["device_offline", "service_down", "rtt_high", "new_device", "new_port"]
ALERT_RULES: tuple[str, ...] = ("device_offline", "service_down", "rtt_high", "new_device", "new_port")
ALERT_RULE_LABELS: dict[str, str] = {
    "device_offline": "Gerät offline",
    "service_down": "Dienst ausgefallen",
    "rtt_high": "Antwortzeit hoch",
    "new_device": "Neues Gerät",
    "new_port": "Neuer offener Port",
}
AlertSeverity = Literal["info", "warning", "critical"]
SEVERITY_LABELS: dict[str, str] = {"info": "Hinweis", "warning": "Warnung", "critical": "kritisch"}

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
    profile_name: str | None = None  # Windows-Netzwerkprofil des Adapters (wenn die SSID nicht lesbar ist)
    home_allowed: bool = False  # darf dieser Router jetzt als Heimnetz gemerkt werden? (nur bei confirm)

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


# =====================================================================================
# Stufe 2 – Überwachung (BAUPLAN §21)
# =====================================================================================


def iso_from_ts(ts: float | None) -> str | None:
    """Unix-Sekunden -> ISO 8601 in UTC (sekundengenau); None bleibt None."""
    if ts is None:
        return None
    return datetime.fromtimestamp(int(ts), timezone.utc).isoformat(timespec="seconds")


def ts_from_iso(text: str | None) -> float | None:
    """ISO 8601 -> Unix-Sekunden; None oder Unsinn ergibt None."""
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(str(text))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


@dataclass
class CheckResult:
    """Ergebnis einer einzelnen Prüfung (Erreichbarkeit oder Dienst)."""

    ok: bool
    rtt_ms: float | None = None
    detail: str = ""  # deutscher Kurztext, z. B. „HTTP 200“, „keine Antwort“, „Port geschlossen“
    code: int | None = None  # HTTP-Statuscode
    method: str = ""  # „ping“, „tcp:445“, „http:80“ …

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ServiceCheck:
    id: int
    target_id: int
    kind: CheckKind
    port: int
    path: str = "/"
    enabled: bool = True
    status: CheckStatus = "unknown"
    status_since: str | None = None
    last_check: str | None = None
    last_rtt_ms: float | None = None
    last_detail: str = ""
    down_since: str | None = None  # Beginn der laufenden Störung (für die Alert-Schwelle)

    @property
    def label(self) -> str:
        names = {"tcp": "TCP", "http": "HTTP", "https": "HTTPS", "smb": "SMB-Freigabe", "ssh": "SSH"}
        return f"{names.get(self.kind, self.kind)} {self.port}"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["label"] = self.label
        return d


@dataclass
class MonitorTarget:
    id: int
    mac: str
    enabled: bool = True
    method: ReachMethod = "auto"
    tcp_port: int | None = None  # fester Port für den TCP-Test; None = aus den offenen Ports
    offline_after_min: int | None = None  # None = Einstellung alert_offline_minutes
    rtt_threshold_ms: float | None = None  # None = keine Regel „Antwortzeit hoch“
    gateway_mac: str | None = None  # Router des Netzes, in dem das Ziel überwacht wird
    network: str | None = None
    created: str = ""
    status: TargetStatus = "unknown"
    status_since: str | None = None
    pause_code: PauseCode | None = None
    pause_reason: str = ""  # deutscher Text zur Pause
    last_check: str | None = None
    last_rtt_ms: float | None = None
    last_detail: str = ""
    last_method: str = ""
    down_since: str | None = None
    rtt_high_since: str | None = None
    checks: list[ServiceCheck] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status_label"] = TARGET_STATUS_LABELS.get(self.status, self.status)
        d["checks"] = [c.to_dict() for c in self.checks]
        return d


@dataclass
class Sample:
    """Ein Messwert. check_id 0 = Erreichbarkeit des Geräts. ts in Unix-Sekunden (UTC)."""

    target_id: int
    check_id: int
    ts: int
    ok: bool
    rtt_ms: float | None = None


@dataclass
class Alert:
    id: int
    rule: AlertRule
    key: str
    severity: AlertSeverity
    title: str
    message: str = ""
    mac: str | None = None
    target_id: int | None = None
    check_id: int | None = None
    opened: str = ""
    closed: str | None = None
    acknowledged: str | None = None

    @property
    def active(self) -> bool:
        return self.closed is None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["active"] = self.active
        d["rule_label"] = ALERT_RULE_LABELS.get(self.rule, self.rule)
        d["severity_label"] = SEVERITY_LABELS.get(self.severity, self.severity)
        return d


@dataclass
class MonitorStatus:
    state: MonitorState = "stopped"
    reason: str = ""  # deutscher Text, z. B. warum pausiert
    interval_s: int = 60
    last_cycle: str | None = None
    next_cycle: str | None = None
    cycle_ms: float | None = None
    targets: int = 0  # aktive Ziele
    online: int = 0
    degraded: int = 0
    offline: int = 0
    paused: int = 0
    unknown: int = 0
    db_size_bytes: int | None = None
    raw_keep_days: int = 30  # Tage Rohwerte; weniger als 30 nur, wenn das Plattenbudget sonst nicht reicht

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanOutcome:
    """Rückmeldung eines abgeschlossenen Scans an die Überwachung (BAUPLAN §26)."""

    scan_id: int
    kind: str  # "scan" | "deep_scan"
    adapter: Adapter
    gateway_mac: str | None = None
    seen_macs: list[str] = field(default_factory=list)
    new_devices: list[Device] = field(default_factory=list)
    new_ports: dict[str, list[PortResult]] = field(default_factory=dict)  # MAC -> neu offene, vorher geprüfte Ports
    baseline: bool = False  # erster abgeschlossener Scan überhaupt: Grundbestand, keine „Neues Gerät“-Alerts
