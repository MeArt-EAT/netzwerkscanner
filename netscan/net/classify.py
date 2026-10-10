"""Geräteart aus Hersteller, Diensten und Kennungen. (Agent ports)

Datengetrieben: Oben stehen die Tabellen (Hersteller-Stichwörter, Ports, mDNS-Dienste,
SSDP-Gerätetypen, Hostnamen-Muster), unten die Regeln. RULES läuft der Reihe nach, die erste
passende Regel gewinnt (Reihenfolge laut Auftrag):
router → printer → server (NAS) → switch → pc → server (Linux) → iot → phone → unknown.
"""

from __future__ import annotations

import functools
import logging
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from netscan.core.models import Device, NameInfo

log = logging.getLogger(__name__)

# ============================================================================
# Tabellen
# ============================================================================

# Hersteller-Stichwörter: (regulärer Ausdruck auf den kleingeschriebenen Herstellertext, Anzeigename).
# Herstellertext = OUI-Hersteller, SSDP-Hersteller und SSDP-Modell, je eine Zeile (^ = Zeilenanfang).
VendorTable = tuple[tuple[str, str], ...]

PRINTER_VENDORS: VendorTable = (
    (r"\bbrother\b", "Brother"),
    (r"\bcanon\b", "Canon"),
    (r"\bepson\b", "Epson"),
    (r"\bkyocera\b", "Kyocera"),
    (r"\blexmark\b", "Lexmark"),
    (r"\bxerox\b", "Xerox"),
    (r"\bricoh\b", "Ricoh"),
    (r"\boki\b", "OKI"),
    (r"\bkonica\b", "Konica Minolta"),
)

NAS_VENDORS: VendorTable = (
    (r"\bsynology\b", "Synology"),
    (r"\bqnap\b", "QNAP"),
    (r"\basustor\b", "Asustor"),
    (r"\bterra ?master\b", "TerraMaster"),
    (r"\bbuffalo\b", "Buffalo"),
    (r"western digital|^wd\b", "Western Digital"),
)

NETWORK_VENDORS: VendorTable = (
    (r"\btp-?link\b", "TP-Link"),
    (r"\bmercusys\b", "Mercusys"),
    (r"\bnetgear\b", "Netgear"),
    (r"\bcisco\b", "Cisco"),
    (r"\bzyxel\b", "Zyxel"),
    (r"\bd-link\b", "D-Link"),
    (r"\bubiquiti\b", "Ubiquiti"),
    (r"\bmikrotik\b|\brouterboard\b", "MikroTik"),
    (r"hewlett packard enterprise|\baruba\b|\bprocurve\b", "HPE/Aruba"),
    (r"juniper networks", "Juniper"),
    (r"\blinksys\b", "Linksys"),
    (r"lancom systems|^lancom\b", "Lancom"),
    (r"\bdevolo\b", "devolo"),
    (r"\bavm\b|fritz!", "AVM"),
    (r"\ballnet\b", "Allnet"),
    (r"\bedimax\b", "Edimax"),
    (r"\bdraytek\b", "DrayTek"),
    (r"asus network technologies", "ASUS"),
)

PC_VENDORS: VendorTable = (
    (r"\bintel\b", "Intel"),
    (r"^dell\b", "Dell"),
    (r"^(?!.*(?:motorola|mobile)).*\blenovo\b|\blcfc\b", "Lenovo"),  # ohne Lenovo-Handys (Motorola)
    (r"\basustek\b", "ASUS"),
    (r"micro-star|^msi\b", "MSI"),
    (r"^giga-?byte\b", "Gigabyte"),
    (r"\basrock\b", "ASRock"),
    (r"\bfujitsu\b", "Fujitsu"),
    (r"^hp inc\b|^hewlett[- ]packard\b(?! enterprise)", "HP"),
    (r"^apple\b", "Apple"),  # Mac: Apple mit offenen Ports (Apple ohne Dienste ⇒ Handy, Regel 8)
)

IOT_VENDORS: VendorTable = (
    (r"\bespressif\b", "Espressif"),
    (r"\btuya\b", "Tuya"),
    (r"\bshelly\b|\ballterco\b", "Shelly"),
    (r"\bsonos\b", "Sonos"),
    (r"\bamazon\b", "Amazon"),
    (r"\bsignify\b|philips lighting", "Signify/Philips Hue"),
    (r"\bbosch\b|^bsh\b", "Bosch"),
    (r"\btado\b", "tado"),
    (r"\bnetatmo\b", "Netatmo"),
    (r"^ring\b", "Ring"),
    (r"\beufy\b|\banker\b", "Eufy/Anker"),
    (r"\broku\b", "Roku"),
    (r"nest labs", "Google Nest"),
    (r"\bhikvision\b|\bezviz\b", "Hikvision"),
    (r"\bdahua\b", "Dahua"),
    (r"\breolink\b", "Reolink"),
    (r"^arlo\b", "Arlo"),
    (r"\birobot\b", "iRobot"),
    (r"\broborock\b", "Roborock"),
    (r"\bmiele\b", "Miele"),
    (r"\beq-3\b", "eQ-3 (Homematic)"),
    (r"\bnuki\b", "Nuki"),
    (r"\bnanoleaf\b", "Nanoleaf"),
    (r"\bmeross\b", "Meross"),
    (r"\bwithings\b", "Withings"),
    (r"\becobee\b", "ecobee"),
    (r"\bwyze\b", "Wyze"),
)

# Nur IoT, wenn das Gerät Dienste zeigt (offene Ports, mDNS, SSDP) – sonst eher Handy (Regel 8).
IOT_VENDORS_WITH_SERVICES: VendorTable = (
    (r"\bxiaomi\b", "Xiaomi"),
    (r"^google\b", "Google"),
)

# Nur IoT mit SSDP MediaRenderer (Fernseher, Lautsprecher) – sonst eher Handy.
MEDIA_VENDORS: VendorTable = (
    (r"\bsamsung\b", "Samsung"),
    (r"^lg\b", "LG"),
    (r"^sony\b", "Sony"),
)

PHONE_VENDORS: VendorTable = (
    (r"^apple\b", "Apple"),
    (r"\bsamsung\b", "Samsung"),
    (r"\bxiaomi\b", "Xiaomi"),
    (r"\bhuawei\b|^honor device\b", "Huawei/Honor"),
    (r"\boneplus\b", "OnePlus"),
    (r"\boppo\b|^realme\b", "OPPO"),
    (r"^vivo mobile\b", "vivo"),
    (r"^google\b", "Google"),
    (r"\bmotorola\b", "Motorola"),
    (r"^nothing technology\b", "Nothing"),
    (r"^fairphone\b", "Fairphone"),
    (r"^hmd global\b", "HMD/Nokia"),
)

RASPBERRY_VENDORS: VendorTable = ((r"raspberry pi", "Raspberry Pi"),)

# Ports
PRINTER_PORTS: frozenset[int] = frozenset({515, 631, 9100})
WEB_PORTS: frozenset[int] = frozenset({80, 443})
WINDOWS_PORTS: frozenset[int] = frozenset({135, 139, 445, 3389})
WINDOWS_MARKER_PORTS: frozenset[int] = frozenset({135, 3389})  # nur Windows, nicht Samba
MGMT_PORTS: frozenset[int] = frozenset({22, 23, 80, 443, 8080, 8443})
DSM_PORTS: frozenset[int] = frozenset({5000, 5001})  # Synology DSM (beide zusammen)
FILE_SERVICE_PORTS: frozenset[int] = frozenset({445, 548, 2049})
# Regel 6: SSH plus einer dieser Dienste (Auftrag: 80/443/2049/3306/5432/8080/873; ergänzt um weitere Serverdienste)
SERVER_COMPANION_PORTS: frozenset[int] = frozenset(
    {80, 443, 2049, 3306, 5432, 8080, 873} | {21, 25, 53, 111, 1883, 2375, 6379, 8443, 27017}
)
DATABASE_PORTS: frozenset[int] = frozenset({2375, 3306, 5432, 6379, 27017})

# mDNS-Diensttypen (erster Namensteil, z. B. "_ipp" aus "_ipp._tcp.local")
PRINTER_MDNS: frozenset[str] = frozenset({"_ipp", "_ipps", "_printer", "_pdl-datastream", "_uscan", "_uscans", "_scanner"})
WORKSTATION_MDNS: frozenset[str] = frozenset({"_workstation"})
IOT_MDNS: frozenset[str] = frozenset({
    "_hap", "_homekit", "_googlecast", "_spotify-connect", "_matter", "_matterc", "_sonos", "_amzn-wplay",
    "_airplay", "_raop", "_hue", "_esphomelib", "_shelly", "_miio", "_googlezone", "_meshcop", "_nanoleafapi",
})
# Reine Kennungen ohne eigentlichen Dienst (Handys/Tablets melden sie) – zählen nicht als „Dienst“.
PASSIVE_MDNS: frozenset[str] = frozenset({
    "_apple-mobdev2", "_companion-link", "_rdlink", "_device-info", "_adb-tls-connect", "_adb-tls-pairing",
})

# SSDP-Gerätetypen (urn:…:device:<Typ>:<Version>, Typ kleingeschrieben)
SSDP_ROUTER_PREFIXES: tuple[str, ...] = ("urn:schemas-upnp-org:device:internetgatewaydevice",)
SSDP_PRINTER_KINDS: frozenset[str] = frozenset({"printer"})
SSDP_IOT_KINDS: dict[str, str] = {
    "mediarenderer": "Medienwiedergabe (MediaRenderer)",
    "basic": "einfaches UPnP-Gerät (Basic)",
    "zoneplayer": "Lautsprecher (ZonePlayer)",
    "dial": "Streaming-Empfänger (DIAL)",
    "remotecontrolreceiver": "Fernseher (RemoteControlReceiver)",
}
# Netzwerkgerät ohne gefundene Verwaltungsports, aber mit UPnP-Kennung (z. B. TR-064 eines Repeaters)
SSDP_NETWORK_KINDS: frozenset[str] = frozenset({"wlanaccesspointdevice", "internetgatewaydevice"})

# Hostname-Muster: gelten für ganze Namensteile (erster DNS-/mDNS-/NetBIOS-Label, an - und _ getrennt).
HOSTNAME_HINTS: dict[str, tuple[str, ...]] = {
    "printer": (
        r"printer\w*", r"drucker\w*", r"br[nw][0-9a-f]{12}", r"npi[0-9a-f]{6}", r"hp[0-9a-f]{6}",
        r"(?:laser|office|desk)jet\w*", r"pixma\w*", r"epson\w*", r"mfc",
    ),
    "nas": (
        r"nas\d*", r"diskstation\w*", r"rackstation\w*", r"ds\d{3,4}[a-z]*", r"readynas\w*",
        r"terastation\w*", r"linkstation\w*", r"mycloud\w*", r"qnap\w*", r"synology\w*",
    ),
    "pc": (
        r"desktop", r"laptop", r"notebook", r"macbook\w*", r"imac\w*", r"thinkpad\w*", r"pc\d*", r"workstation",
    ),
    "iot": (
        r"esp(?:32|8266)?(?:[0-9a-f]{6})?", r"espressif", r"esphome\w*", r"shelly\w*", r"tasmota\w*",
        r"sonoff\w*", r"wled\w*", r"chromecast\w*", r"sonos\w*", r"roku\w*", r"homepod\w*", r"appletv\w*",
    ),
    "phone": (
        r"iphone\w*", r"ipad\w*", r"android\w*", r"galaxy\w*", r"pixel\w*", r"redmi\w*", r"oneplus\w*",
        r"smartphone", r"handy",
    ),
}

UNKNOWN_REASON = "keine eindeutigen Merkmale"
PHONE_RANDOM_REASON = "private MAC-Adresse, keine Dienste – vermutlich Handy"
SWITCH_REASON = "Netzwerkgerät mit Verwaltungsoberfläche (Switch/Access Point/Repeater)"


# ============================================================================
# Merkmale eines Geräts
# ============================================================================

_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")


@functools.lru_cache(maxsize=64)
def _compile_vendors(table: VendorTable) -> tuple[tuple[re.Pattern[str], str], ...]:
    return tuple((re.compile(rx, re.MULTILINE), label) for rx, label in table)


@functools.lru_cache(maxsize=64)
def _compile_hints(patterns: tuple[str, ...]) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(rx) for rx in patterns)


@dataclass(frozen=True)
class _Signals:
    ports: frozenset[int]
    mdns: frozenset[str]
    ssdp_type: str  # kleingeschrieben, "" wenn keiner
    ssdp_kind: str  # z. B. "mediarenderer"
    has_ssdp: bool
    vendor_text: str  # kleingeschrieben, je Quelle eine Zeile
    host_tokens: tuple[str, ...]
    model_tokens: tuple[str, ...]
    is_gateway: bool
    is_self: bool
    mac_random: bool

    @property
    def active_mdns(self) -> frozenset[str]:
        return self.mdns - PASSIVE_MDNS

    @property
    def has_services(self) -> bool:
        return bool(self.ports or self.active_mdns or self.has_ssdp)


def _open_ports(device: Device) -> frozenset[int]:
    out: set[int] = set()
    for p in device.ports or ():
        port = getattr(p, "port", None)
        proto = getattr(p, "proto", "tcp") or "tcp"
        if isinstance(port, int) and not isinstance(port, bool) and proto == "tcp":
            out.add(port)
    return frozenset(out)


def _mdns_labels(services: Iterable[object]) -> frozenset[str]:
    """Diensttypen: „_ipp._tcp.local.“ → {"_ipp"}; Untertypen „_universal._sub._ipp._tcp“ → {"_universal", "_ipp"}."""
    out: set[str] = set()
    for service in services or ():
        if not isinstance(service, str):
            continue
        for label in service.strip().lower().rstrip(".").split("."):
            if label.startswith("_") and label not in ("_tcp", "_udp", "_sub"):
                out.add(label)
    return frozenset(out)


def _ssdp_kind(device_type: str) -> str:
    parts = device_type.split(":")
    if len(parts) >= 4 and parts[0] == "urn" and parts[2] == "device":
        return parts[3]
    return ""


def _tokens(names: Iterable[object], first_label_only: bool) -> tuple[str, ...]:
    out: list[str] = []
    for name in names:
        if not isinstance(name, str) or not name.strip():
            continue
        text = name.strip().lower()
        if first_label_only:  # „nas.fritz.box“ → „nas“ (Domain des Routers zählt nicht)
            text = text.split(".", 1)[0]
        for token in _TOKEN_SPLIT.split(text):
            if token and token not in out:
                out.append(token)
    return tuple(out)


def _signals(device: Device) -> _Signals:
    names = device.names if isinstance(device.names, NameInfo) else NameInfo()
    ssdp = device.ssdp
    ssdp_type = (ssdp.device_type or "").strip().lower() if ssdp else ""
    ssdp_values = [ssdp.location, ssdp.server, ssdp.friendly_name, ssdp.manufacturer, ssdp.model_name,
                   ssdp.model_number, ssdp.device_type] if ssdp else []
    vendor_parts = [device.vendor, ssdp.manufacturer if ssdp else None, ssdp.model_name if ssdp else None]
    return _Signals(
        ports=_open_ports(device),
        mdns=_mdns_labels(names.mdns_services or ()),
        ssdp_type=ssdp_type,
        ssdp_kind=_ssdp_kind(ssdp_type),
        has_ssdp=any(isinstance(v, str) and v.strip() for v in ssdp_values),
        vendor_text="\n".join(v.strip().lower() for v in vendor_parts if isinstance(v, str) and v.strip()),
        host_tokens=_tokens((device.hostname, names.dns, names.mdns, names.netbios), first_label_only=True),
        model_tokens=_tokens((ssdp.model_name if ssdp else None,), first_label_only=False),
        is_gateway=bool(device.is_gateway),
        is_self=bool(device.is_self),
        mac_random=bool(device.mac_random),
    )


def _vendor(s: _Signals, table: VendorTable) -> str | None:
    """Anzeigename des ersten passenden Herstellers. Beim eigenen PC zählt der Hersteller nicht
    (das ist oft nur der Hersteller des WLAN-Sticks, z. B. TP-Link)."""
    if s.is_self or not s.vendor_text:
        return None
    for rx, label in _compile_vendors(table):
        if rx.search(s.vendor_text):
            return label
    return None


def _hint(s: _Signals, key: str) -> str | None:
    """Passender Hostname- oder Modell-Teil, z. B. „Hostname „diskstation““."""
    patterns = _compile_hints(HOSTNAME_HINTS.get(key, ()))
    for source, tokens in (("Hostname", s.host_tokens), ("UPnP-Modell", s.model_tokens)):
        for token in tokens:
            if any(rx.fullmatch(token) for rx in patterns):
                return f"{source} „{token}“"
    return None


def _ports_text(ports: Iterable[int], limit: int = 6) -> str:
    items = sorted(set(ports))
    if not items:
        return "keine offenen Ports"
    shown = "/".join(str(p) for p in items[:limit]) + ("/…" if len(items) > limit else "")
    return f"Port {shown}" if len(items) == 1 else f"Ports {shown}"


def _with_ports(text: str, ports: Iterable[int]) -> str:
    ports = frozenset(ports)
    return f"{text}, {_ports_text(ports)}" if ports else text


# ============================================================================
# Regeln (Reihenfolge = RULES unten; erste passende gewinnt)
# ============================================================================

Hit = tuple[str, str]


def _rule_router(s: _Signals) -> Hit | None:
    """1: Standard-Gateway oder UPnP-Internet-Gateway ⇒ router."""
    if s.is_gateway:
        return "router", "Standard-Gateway des Netzes"
    if s.ssdp_type.startswith(SSDP_ROUTER_PREFIXES):
        return "router", "meldet sich per UPnP als Internet-Gateway (InternetGatewayDevice)"
    return None


def _rule_printer(s: _Signals) -> Hit | None:
    """2: Druckerports, Druck-mDNS, SSDP Printer oder Druckerhersteller mit Weboberfläche ⇒ printer."""
    hit = s.ports & PRINTER_PORTS
    if hit:
        return "printer", f"Druckdienste offen ({_ports_text(hit)})"
    services = s.mdns & PRINTER_MDNS
    if services:
        return "printer", f"bietet Druckdienst per mDNS an ({', '.join(sorted(services))})"
    if s.ssdp_kind in SSDP_PRINTER_KINDS:
        return "printer", "meldet sich per UPnP als Drucker"
    vendor = _vendor(s, PRINTER_VENDORS)
    web = s.ports & WEB_PORTS
    if vendor and web:
        return "printer", f"Druckerhersteller {vendor} mit Weboberfläche ({_ports_text(web)})"
    hint = _hint(s, "printer")
    if hint:
        return "printer", f"{hint} deutet auf einen Drucker"
    return None


def _rule_nas(s: _Signals) -> Hit | None:
    """3: NAS-Hersteller, NAS-Hostname oder NAS-Portmuster ⇒ server."""
    vendor = _vendor(s, NAS_VENDORS)
    if vendor:
        return "server", _with_ports(f"NAS-Hersteller {vendor}", s.ports)
    hint = _hint(s, "nas")
    if hint:
        return "server", f"{hint} deutet auf ein NAS"
    if DSM_PORTS <= s.ports:
        return "server", "Synology-DSM-Ports 5000/5001 – vermutlich NAS"
    files = s.ports & FILE_SERVICE_PORTS
    if (
        files
        and 22 in s.ports
        and not s.ports & WINDOWS_MARKER_PORTS
        and not s.is_self
        and not _vendor(s, PC_VENDORS)
        and not _vendor(s, PHONE_VENDORS)
    ):
        return "server", f"Dateifreigabe mit SSH ({_ports_text(files | {22})}) ohne Windows-Kennung – vermutlich NAS/Linux-Server"
    return None


def _rule_network(s: _Signals) -> Hit | None:
    """4: Netzwerkhersteller mit Verwaltungsoberfläche, nicht Gateway ⇒ switch."""
    if s.is_gateway:
        return None
    vendor = _vendor(s, NETWORK_VENDORS)
    if not vendor:
        return None
    mgmt = s.ports & MGMT_PORTS
    if mgmt:
        return "switch", f"{SWITCH_REASON}: Hersteller {vendor}, {_ports_text(mgmt)}"
    if s.ssdp_kind in SSDP_NETWORK_KINDS:
        return "switch", f"{SWITCH_REASON}: Hersteller {vendor}, UPnP-Kennung"
    return None


def _rule_pc(s: _Signals) -> Hit | None:
    """5: eigener PC, Windows-Ports, mDNS _workstation, PC-Hersteller mit offenen Ports ⇒ pc."""
    if s.is_self:
        return "pc", "eigener PC (dieser Rechner)"
    windows = s.ports & WINDOWS_PORTS
    if windows:  # NAS-Merkmale hat Regel 3 schon abgefangen
        return "pc", f"Windows-Dienste offen ({_ports_text(windows)})"
    if s.mdns & WORKSTATION_MDNS:
        return "pc", "meldet sich per mDNS als Arbeitsplatzrechner (_workstation)"
    return None


def _rule_pc_vendor(s: _Signals) -> Hit | None:
    """6b: PC-Hersteller mit offenen Ports oder PC-Hostname ⇒ pc (nach der Server-Regel, damit
    Mini-PCs/Eigenbau-Server mit Intel-Netzwerkkarte und SSH + Webdienst als Server gelten)."""
    vendor = _vendor(s, PC_VENDORS)
    if vendor and s.ports:
        return "pc", f"PC-Hersteller {vendor} mit offenen Ports ({_ports_text(s.ports)})"
    hint = _hint(s, "pc")
    if hint:
        return "pc", f"{hint} deutet auf einen PC"
    return None


def _rule_server(s: _Signals) -> Hit | None:
    """6: SSH plus Serverdienst ohne Windows-Ports, Raspberry Pi mit SSH, Datenbankdienste ⇒ server."""
    if s.ports & WINDOWS_PORTS:
        return None
    if 22 in s.ports:
        companions = s.ports & SERVER_COMPANION_PORTS
        if companions:
            return "server", f"SSH mit Serverdiensten ({_ports_text(companions | {22})}) ohne Windows-Dienste – Linux-/Allzweck-Server"
        if _vendor(s, RASPBERRY_VENDORS):
            return "server", "Raspberry Pi mit SSH (Port 22)"
    databases = s.ports & DATABASE_PORTS
    if databases:
        return "server", f"Datenbank-/Container-Dienste offen ({_ports_text(databases)})"
    return None


def _rule_iot(s: _Signals) -> Hit | None:
    """7: IoT-Hersteller, Smart-Home-mDNS, SSDP MediaRenderer/Basic, Raspberry Pi ohne SSH ⇒ iot."""
    vendor = _vendor(s, IOT_VENDORS)
    if vendor:
        return "iot", _with_ports(f"Smart-Home-/IoT-Hersteller {vendor}", s.ports)
    services = s.mdns & IOT_MDNS
    if services and not s.mdns & WORKSTATION_MDNS:
        return "iot", f"Smart-Home-/Mediendienst per mDNS ({', '.join(sorted(services))})"
    media = _vendor(s, MEDIA_VENDORS)
    if media and s.ssdp_kind == "mediarenderer":
        return "iot", f"Mediengerät von {media} (UPnP MediaRenderer)"
    if s.ssdp_kind in SSDP_IOT_KINDS:
        return "iot", f"meldet sich per UPnP als {SSDP_IOT_KINDS[s.ssdp_kind]}"
    vendor = _vendor(s, IOT_VENDORS_WITH_SERVICES)
    if vendor and s.has_services:
        return "iot", _with_ports(f"Hersteller {vendor} mit Diensten – vermutlich Smart-Home-/Mediengerät", s.ports)
    if _vendor(s, RASPBERRY_VENDORS) and 22 not in s.ports:
        return "iot", _with_ports("Raspberry Pi ohne SSH – vermutlich Steuer- oder Bastelgerät", s.ports)
    hint = _hint(s, "iot")
    if hint:
        return "iot", f"{hint} deutet auf ein Smart-Home-/IoT-Gerät"
    return None


def _rule_phone(s: _Signals) -> Hit | None:
    """8: private MAC ohne Ports/SSDP oder Handy-Hersteller ohne Dienste ⇒ phone."""
    if s.ports:
        return None
    if s.mac_random and not s.has_ssdp:
        return "phone", PHONE_RANDOM_REASON
    if not s.has_services:
        vendor = _vendor(s, PHONE_VENDORS)
        if vendor:
            return "phone", f"Hersteller {vendor}, keine Dienste – vermutlich Handy"
    hint = _hint(s, "phone")
    if hint:
        return "phone", f"{hint}, keine offenen Ports – vermutlich Handy oder Tablet"
    return None


RULES: tuple[Callable[[_Signals], Hit | None], ...] = (
    _rule_router,   # 1
    _rule_printer,  # 2
    _rule_nas,      # 3
    _rule_network,  # 4
    _rule_pc,       # 5  eigener PC, Windows-Dienste, _workstation
    _rule_server,   # 6
    _rule_pc_vendor,  # 6b PC-Hersteller mit Ports, PC-Hostname
    _rule_iot,      # 7
    _rule_phone,    # 8
)


# ============================================================================
# Schnittstelle
# ============================================================================


def classify(device: Device) -> tuple[str, str]:
    """(category, reason) – reason ist ein kurzer deutscher Satz, z. B. „Hersteller Synology, Ports 5000/5001“."""
    signals = _signals(device)
    for rule in RULES:
        hit = rule(signals)
        if hit is not None:
            return hit
    return "unknown", UNKNOWN_REASON


def apply_classification(devices: list[Device]) -> None:
    """Setzt category/category_reason für alle Geräte mit category_source == "auto"."""
    for device in devices:
        if device.category_source != "auto":
            continue
        try:
            category, reason = classify(device)
        except Exception:  # Einordnung darf den Scan nie stoppen
            log.warning("Einordnung für %s fehlgeschlagen", device.mac, exc_info=True)
            category, reason = "unknown", UNKNOWN_REASON
        device.category = category  # type: ignore[assignment]
        device.category_reason = reason
