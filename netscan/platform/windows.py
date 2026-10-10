"""Windows-Implementierung der Plattform-Schicht (netsh, ping, Get-NetAdapter, Get-NetRoute, arp). (Agent guard)

Alle Befehle lesen nur den Zustand des eigenen Systems – einzig ping sendet ein Echo an eine
vorher geprüfte IPv4-Adresse. Fehler (Befehl fehlt, Zeitüberschreitung, unbekanntes Format)
ergeben leere Ergebnisse, nie einen Absturz. Die Parser sind reine Funktionen und laufen auf
jedem System (Tests unter Linux).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from netscan.core.models import PingResult, normalize_mac
from netscan.platform.base import AdapterDetail, InterfaceAddr, WifiEntry, WifiStatus, psutil_interfaces

log = logging.getLogger(__name__)

CREATE_NO_WINDOW = 0x08000000  # subprocess.CREATE_NO_WINDOW, gibt es nur unter Windows

CMD_TIMEOUT_S = 5.0  # netsh, arp, route: lokal, normalerweise < 0,5 s
PS_ROUTE_TIMEOUT_S = 5.0  # Get-NetRoute; bei Zeitüberschreitung hilft route print
PS_ADAPTER_TIMEOUT_S = 10.0  # Get-NetAdapter braucht mit PowerShell-Start 2–4 s
PS_PROFILE_TIMEOUT_S = 5.0  # Get-NetConnectionProfile, nur wenn netsh den WLAN-Namen nicht liefert
ROUTE_CACHE_S = 5.0
ADAPTER_CACHE_S = 30.0  # Beschreibung, virtuell, WLAN ändern sich praktisch nie
PING_MIN_MS = 50
PING_MAX_MS = 2000  # Bauplan: jede Netzoperation höchstens 2 s
PING_RESERVE_S = 1.5  # Reserve für den Prozessstart

# PowerShell schreibt in eine Pipe sonst in der OEM-Codepage (cp850) – UTF-8 erzwingen.
_PS_PREFIX = "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); $ProgressPreference='SilentlyContinue'; "
# -IncludeHidden: versteckte virtuelle Adapter (Wi-Fi Direct/mobiler Hotspot, VPN-Miniports) tragen nur
# dann Virtual=True; ohne den Schalter fehlen sie hier und gälten als physisch.
_PS_ADAPTERS = (
    "Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | "
    "Select-Object Name,InterfaceDescription,Virtual,MacAddress,PhysicalMediaType,NdisPhysicalMedium,Status | "
    "ConvertTo-Json -Compress"
)
# Netzwerkprofil je Adapter. Braucht weder Standortberechtigung noch Adminrechte; bei WLAN heißt das
# Profil beim Anlegen wie die SSID. Nur ein Hinweis in Sperr-Richtung (siehe WifiStatus.profile_names).
_PS_PROFILES = (
    "Get-NetConnectionProfile -ErrorAction SilentlyContinue | "
    "Select-Object Name,InterfaceAlias | "
    "ConvertTo-Json -Compress"
)
_PS_ROUTES = (
    "Get-NetRoute -DestinationPrefix 0.0.0.0/0 -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | "
    "Select-Object InterfaceAlias,InterfaceIndex,NextHop,RouteMetric,InterfaceMetric | "
    "ConvertTo-Json -Compress"
)

PERMISSION_ERROR = "Standortberechtigung fehlt – Windows-Einstellungen › Datenschutz und Sicherheit › Standort"


# --- Befehle ausführen ------------------------------------------------------------------


@dataclass(frozen=True)
class _Result:
    rc: int
    out: str
    err: str


def _decode(data: bytes | None) -> str:
    """Bytes zu Text: UTF-8, wenn gültig, sonst OEM-Codepage (Fallback cp850), errors="replace".

    netsh liefert unter Windows 11 (24H2) UTF-8, ping/route/arp dagegen die OEM-Codepage.
    Text in cp850 mit Umlauten ist praktisch nie gültiges UTF-8, daher ist die Reihenfolge sicher.
    """
    if not data:
        return ""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = data.decode("oem", errors="replace")
        except LookupError:  # Codec "oem" gibt es nur unter Windows
            text = data.decode("cp850", errors="replace")
    return text.lstrip("\ufeff")


def _system_exe(*parts: str) -> str:
    """Voller Pfad unter %SystemRoot%\\System32 (kein Suchpfad-Trick möglich), sonst nur der Name."""
    root = os.environ.get("SystemRoot") or os.environ.get("windir") or r"C:\Windows"
    path = os.path.join(root, "System32", *parts)
    return path if os.path.isfile(path) else parts[-1]


def _run(args: list[str], timeout: float) -> _Result | None:
    """Startet einen Befehl ohne Konsolenfenster. None, wenn er fehlt, hängt oder nicht startet."""
    kwargs: dict[str, Any] = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", CREATE_NO_WINDOW)
    try:
        proc = subprocess.run(
            args, capture_output=True, stdin=subprocess.DEVNULL, timeout=timeout, check=False, **kwargs
        )
    except subprocess.TimeoutExpired:
        log.warning("Befehl %s: Zeitüberschreitung nach %.1f s", os.path.basename(args[0]), timeout)
        return None
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        log.warning("Befehl %s nicht ausführbar: %s", os.path.basename(args[0]), exc)
        return None
    return _Result(proc.returncode, _decode(proc.stdout), _decode(proc.stderr))


def _run_ps(script: str, timeout: float) -> _Result | None:
    exe = _system_exe("WindowsPowerShell", "v1.0", "powershell.exe")
    return _run([exe, "-NoProfile", "-NonInteractive", "-Command", _PS_PREFIX + script], timeout)


# --- kleine Helfer ---------------------------------------------------------------------


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _to_bool(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes", "ja")
    return bool(value)


def _norm_mac(value: Any) -> str | None:
    if not value or not isinstance(value, str):
        return None
    try:
        mac = normalize_mac(value)
    except ValueError:
        return None
    return None if mac == "00:00:00:00:00:00" else mac


def _usable_neighbor(ip: str, mac: str) -> str | None:
    """Normalisierte MAC, wenn ip/mac ein echter Nachbar ist (kein Broadcast, Multicast, leer)."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return None
    if addr.is_multicast or addr.is_unspecified or addr == ipaddress.IPv4Address("255.255.255.255"):
        return None
    norm = _norm_mac(mac)
    if norm is None or int(norm[:2], 16) & 1:  # Gruppenbit: ff-ff-…, 01-00-5e-…, 33-33-…
        return None
    return norm


def _json_items(text: str) -> list[dict[str, Any]]:
    """ConvertTo-Json liefert bei einem Treffer ein Objekt, sonst eine Liste – beides annehmen."""
    text = (text or "").strip().lstrip("\ufeff")
    if not text:
        return []
    try:
        data = json.loads(text)
    except ValueError:
        log.debug("Kein gültiges JSON von PowerShell: %.80r", text)
        return []
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    return []


# --- Parser (reine Funktionen) ----------------------------------------------------------

_KV = re.compile(r"^\s*([^:\r\n]+?)\s*:\s?(.*?)\s*$")
_STATE_KEYS = ("status", "state")
_CONNECTED = {"verbunden", "connected"}
_DISCONNECTED = {"getrennt", "disconnected", "nicht verbunden", "not connected"}
_PERMISSION_MARKERS = (
    "standortberechtigung",  # „… benötigen Standortberechtigungen …“, „… ist eine Standortberechtigung erforderlich …“
    "location permission",  # „Network shell commands need location permission …“
    "privacy-location",  # ms-settings:privacy-location
    "wlanqueryinterface",  # „Die Funktion WlanQueryInterface gibt den Fehler 5 zurück“
    "erhöhte rechte",
    "requires elevation",
)
_NO_WIFI_MARKERS = (
    "keine drahtlosschnittstelle",  # „Es ist keine Drahtlosschnittstelle auf dem System vorhanden.“
    "no wireless interface",  # „There is no wireless interface on the system.“
    "wlansvc",  # WLAN-Dienst „Automatische WLAN-Konfiguration“ (wlansvc) läuft nicht
)
_ZERO_IFACES = re.compile(r"\b0\s+(schnittstellen|interfaces)\b")


def _parse_netsh_interfaces(text: str) -> WifiStatus:
    """Ausgabe von „netsh wlan show interfaces“ (deutsch oder englisch) auswerten.

    Je Schnittstelle zählen nur die Felder Name, Status/State und SSID (nicht BSSID / AP BSSID).
    Fehlermeldung zur Standortberechtigung ⇒ readable=False. Keine WLAN-Karte oder WLAN-Dienst aus
    ⇒ readable=True ohne Einträge. Unbekannte Ausgabe ⇒ readable=False (im Zweifel „nicht lesbar“).
    """
    text = text or ""
    blocks: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for line in text.splitlines():
        m = _KV.match(line)
        if not m:
            continue
        key, value = m.group(1).strip().lower(), m.group(2).strip()
        if key == "name":
            current = {"name": value}
            blocks.append(current)
        elif current is not None and key not in current:
            current[key] = value

    entries: list[WifiEntry] = []
    for block in blocks:
        name = block.get("name", "")
        if not name:
            continue
        state = next((block[k] for k in _STATE_KEYS if k in block), "").strip().lower()
        ssid = block.get("ssid") or None  # leer = Name nicht lesbar
        # Unbekannte Zustandswörter: eine SSID-Zeile gibt es nur bei bestehender Verbindung
        connected = state in _CONNECTED or (ssid is not None and state not in _DISCONNECTED)
        entries.append(WifiEntry(interface=name, connected=connected, ssid=ssid if connected else None))

    low = text.lower()
    if any(marker in low for marker in _PERMISSION_MARKERS):
        return WifiStatus(entries, readable=False, error=PERMISSION_ERROR)
    if entries:
        return WifiStatus(entries, readable=True)
    if any(marker in low for marker in _NO_WIFI_MARKERS) or _ZERO_IFACES.search(low):
        return WifiStatus([], readable=True)
    first = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
    error = f"Unbekannte Antwort von netsh: {first[:120]}" if first else "Keine Antwort von netsh"
    return WifiStatus([], readable=False, error=error)


def _parse_profiles(text: str) -> dict[str, str]:
    """JSON von Get-NetConnectionProfile (Objekt oder Liste) -> Adaptername -> Profilname.

    Leerzeichen am Rand werden entfernt (sichere Richtung, wie bei netsh). Leere Namen zählen nicht;
    steht ein Adapter mehrfach da, gewinnt der erste Eintrag.
    """
    out: dict[str, str] = {}
    for item in _json_items(text):
        alias = str(item.get("InterfaceAlias") or "").strip()
        name = item.get("Name")
        if not alias or not isinstance(name, str):
            continue
        name = name.strip()
        if name and alias not in out:
            out[alias] = name
    return out


_PING_TTL = re.compile(r"TTL=(\d+)", re.IGNORECASE)
_PING_RTT = re.compile(r"([=<])\s*(\d+(?:[.,]\d+)?)\s*ms", re.IGNORECASE)


def _parse_ping(text: str) -> PingResult:
    """Ausgabe von „ping -n 1“: erreichbar nur mit „TTL=“ (Rückgabecode 0 auch bei „Zielhost nicht erreichbar“)."""
    for line in (text or "").splitlines():
        ttl_m = _PING_TTL.search(line)
        if not ttl_m:
            continue
        rtt: float | None = None
        rtt_m = _PING_RTT.search(line)
        if rtt_m:
            value = float(rtt_m.group(2).replace(",", "."))
            rtt = 0.5 if rtt_m.group(1) == "<" and value <= 1 else value
        return PingResult(alive=True, rtt_ms=rtt, ttl=int(ttl_m.group(1)))
    return PingResult(alive=False)


_ARP_LINE = re.compile(
    r"^[ \t]*(\d{1,3}(?:\.\d{1,3}){3})[ \t]+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})(?:[ \t]+(\S+))?"
)


# Kopfzeile je Schnittstelle: „Schnittstelle: 192.168.178.20 --- 0xb“ bzw. „Interface: … --- 0x4“
_ARP_SECTION = re.compile(r"^\s*\S[^:\r\n]*:\s*(\d{1,3}(?:\.\d{1,3}){3})\s+-{3}\s+0x[0-9a-fA-F]+")


def _arp_entries(text: str) -> list[tuple[str | None, str, str, bool]]:
    """Einträge von „arp -a“ als (Schnittstellen-IP, IP, MAC, dynamisch), ohne Broadcast/Multicast."""
    out: list[tuple[str | None, str, str, bool]] = []
    section: str | None = None
    for line in (text or "").splitlines():
        header = _ARP_SECTION.match(line)
        if header:
            section = header.group(1)
            continue
        m = _ARP_LINE.match(line)
        if not m:
            continue
        ip, raw_mac, kind = m.group(1), m.group(2), (m.group(3) or "").lower()
        mac = _usable_neighbor(ip, raw_mac)
        if mac is None:
            continue
        out.append((section, ip, mac, kind.startswith("dyn")))  # „dynamisch“ / „dynamic“
    return out


def _pick(entries: list[tuple[str, str, bool]]) -> dict[str, str]:
    """IP -> MAC; steht eine IP mehrfach da, gewinnt der erste dynamische Eintrag."""
    out: dict[str, str] = {}
    dynamic: dict[str, bool] = {}
    for ip, mac, is_dynamic in entries:
        if ip not in out or (is_dynamic and not dynamic[ip]):
            out[ip] = mac
            dynamic[ip] = is_dynamic
    return out


def _parse_arp(text: str) -> dict[str, str]:
    """Ausgabe von „arp -a“: IP -> MAC (normalisiert), ohne Broadcast/Multicast.

    Sprachunabhängig per Regex. Steht eine IP mehrfach da (mehrere Adapter), gewinnt der erste
    dynamische Eintrag.
    """
    return _pick([(ip, mac, dyn) for _section, ip, mac, dyn in _arp_entries(text)])


def _parse_arp_sections(text: str) -> dict[str | None, dict[str, str]]:
    """Ausgabe von „arp -a“ je Schnittstelle: Schnittstellen-IP -> (IP -> MAC)."""
    grouped: dict[str | None, list[tuple[str, str, bool]]] = {}
    for section, ip, mac, dyn in _arp_entries(text):
        grouped.setdefault(section, []).append((ip, mac, dyn))
    return {section: _pick(items) for section, items in grouped.items()}


@dataclass(frozen=True)
class _Route:
    interface: str | None  # Anzeigename des Adapters (None = unbekannt)
    gateway: str
    metric: int


def _gateway_ip(value: Any) -> str | None:
    try:
        addr = ipaddress.IPv4Address(str(value or "").strip())
    except ValueError:
        return None
    return None if addr.is_unspecified else str(addr)


def _parse_routes(text: str) -> list[_Route]:
    """JSON von Get-NetRoute (Objekt oder Liste) -> Standardrouten, kleinste Metrik zuerst.

    NextHop 0.0.0.0 (z. B. VPN „auf Verbindung“) ist kein Router und wird übergangen.
    Metrik = RouteMetric + InterfaceMetric (so wählt Windows selbst).
    """
    routes: list[_Route] = []
    for item in _json_items(text):
        gateway = _gateway_ip(item.get("NextHop"))
        if gateway is None:
            continue
        alias = item.get("InterfaceAlias")
        metric = _to_int(item.get("RouteMetric")) + _to_int(item.get("InterfaceMetric"))
        routes.append(_Route(str(alias) if alias else None, gateway, metric))
    return sorted(routes, key=lambda r: r.metric)


_ROUTE_PRINT = re.compile(
    r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s*$"
)


def _parse_route_print(text: str) -> list[tuple[str, str, int]]:
    """„route print -4“: aktive Standardrouten als (Schnittstellen-IP, Gateway, Metrik), kleinste Metrik zuerst.

    „Auf Verbindung“/„On-link“ ist kein Gateway; ständige Routen haben nur vier Spalten und passen nicht.
    """
    out: list[tuple[str, str, int]] = []
    for line in (text or "").splitlines():
        m = _ROUTE_PRINT.match(line)
        if not m:
            continue
        gateway = _gateway_ip(m.group(1))
        if gateway is None:
            continue
        out.append((m.group(2), gateway, int(m.group(3))))
    return sorted(out, key=lambda r: r[2])


_WIRELESS_NDIS = (1, 9)  # NdisPhysicalMediumWirelessLan, NdisPhysicalMediumNative802_11


def _parse_adapters(text: str) -> dict[str, AdapterDetail]:
    """JSON von Get-NetAdapter (Objekt oder Liste) -> Anzeigename -> AdapterDetail.

    WLAN: PhysicalMediaType „Native 802.11“/„Wireless LAN“ oder NdisPhysicalMedium 1/9
    (nicht „Wireless WAN“ = Mobilfunk). Virtuell: Feld Virtual.
    """
    out: dict[str, AdapterDetail] = {}
    for item in _json_items(text):
        name = str(item.get("Name") or "").strip()
        if not name:
            continue
        media = str(item.get("PhysicalMediaType") or "").lower()
        ndis = _to_int(item.get("NdisPhysicalMedium"), -1)
        wireless = ndis in _WIRELESS_NDIS or "802.11" in media or "wireless lan" in media
        out[name] = AdapterDetail(
            name=name,
            description=str(item.get("InterfaceDescription") or ""),
            is_virtual=_to_bool(item.get("Virtual")),
            is_wireless=wireless,
            mac=_norm_mac(item.get("MacAddress")),
        )
    return out


# --- Plattform ------------------------------------------------------------------------


class WindowsPlatform:
    name = "windows"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._routes_cache: tuple[float, list[_Route]] | None = None
        self._routes_signature: tuple[Any, ...] | None = None  # Adressen beim Füllen des Routen-Caches
        self._details_cache: tuple[float, dict[str, AdapterDetail]] | None = None
        self._wifi_signature: tuple[Any, ...] | None = None

    def interfaces(self) -> list[InterfaceAddr]:
        return psutil_interfaces()

    # --- Adapter -----------------------------------------------------------------
    def adapter_details(self) -> dict[str, AdapterDetail]:
        now = time.monotonic()
        with self._lock:
            if self._details_cache and now - self._details_cache[0] < ADAPTER_CACHE_S:
                return dict(self._details_cache[1])
        res = _run_ps(_PS_ADAPTERS, PS_ADAPTER_TIMEOUT_S)
        details = _parse_adapters(res.out) if res is not None and res.rc == 0 else {}
        if not details:
            log.info("Adapterdetails nicht verfügbar (Get-NetAdapter)")
        with self._lock:
            # Fehlschlag nur kurz merken, damit ein langsamer Start nicht jede Abfrage bremst
            stamp = time.monotonic() if details else time.monotonic() - ADAPTER_CACHE_S + ROUTE_CACHE_S
            self._details_cache = (stamp, details)
        return dict(details)

    # --- WLAN --------------------------------------------------------------------
    def wifi_status(self) -> WifiStatus:
        res = _run([_system_exe("netsh.exe"), "wlan", "show", "interfaces"], CMD_TIMEOUT_S)
        if res is None:
            status = WifiStatus([], readable=False, error="netsh ließ sich nicht ausführen")
        else:
            status = _parse_netsh_interfaces(res.out + "\n" + res.err)
        if not status.readable or any(e.connected and e.ssid is None for e in status.entries):
            # Ohne Standortberechtigung liefert netsh keinen Namen – der Profilname kommt ohne sie aus.
            status = replace(status, profile_names=self.connection_profiles())
        signature = (
            tuple((e.interface, e.connected, e.ssid) for e in status.entries),
            status.readable,
            tuple(sorted(status.profile_names.items())),
        )
        with self._lock:
            if signature != self._wifi_signature:
                # WLAN gewechselt: Routen sofort neu lesen, nicht die des alten Netzes verwenden
                self._wifi_signature = signature
                self._routes_cache = None
        return status

    def connection_profiles(self) -> dict[str, str]:
        """Adaptername -> Netzwerkprofilname (Get-NetConnectionProfile). Fehler ⇒ leer."""
        res = _run_ps(_PS_PROFILES, PS_PROFILE_TIMEOUT_S)
        return _parse_profiles(res.out) if res is not None and res.rc == 0 else {}

    # --- Routen ------------------------------------------------------------------
    def _address_signature(self) -> tuple[Any, ...]:
        """IPv4-Adressen aller Schnittstellen (psutil, schnell). Ändern sie sich, gilt der Routen-Cache nicht
        mehr – auch dann, wenn der WLAN-Name nicht lesbar ist und die WLAN-Signatur deshalb gleich bleibt."""
        try:
            return tuple(sorted((i.name, i.ipv4, i.netmask, i.is_up) for i in self.interfaces()))
        except Exception:  # noqa: BLE001 – ohne Signatur lieber neu lesen
            return (time.monotonic(),)

    def _default_routes(self) -> list[_Route]:
        now = time.monotonic()
        signature = self._address_signature()
        with self._lock:
            if signature != self._routes_signature:
                self._routes_signature = signature
                self._routes_cache = None
            if self._routes_cache and now - self._routes_cache[0] < ROUTE_CACHE_S:
                return list(self._routes_cache[1])
        routes = self._query_routes()
        with self._lock:
            self._routes_cache = (time.monotonic(), routes)
        return list(routes)

    def _query_routes(self) -> list[_Route]:
        res = _run_ps(_PS_ROUTES, PS_ROUTE_TIMEOUT_S)
        routes = _parse_routes(res.out) if res is not None and res.rc == 0 else []
        if routes:
            return routes
        res = _run([_system_exe("route.exe"), "print", "-4"], CMD_TIMEOUT_S)
        if res is None:
            return []
        by_ip: dict[str, str] = {}
        try:
            for iface in self.interfaces():
                by_ip.setdefault(iface.ipv4, iface.name)
        except Exception:  # noqa: BLE001 – ohne Zuordnung bleibt der Adaptername unbekannt
            log.debug("Schnittstellen für route print nicht lesbar", exc_info=True)
        return [_Route(by_ip.get(if_ip), gw, metric) for if_ip, gw, metric in _parse_route_print(res.out)]

    def default_gateway(self, adapter_name: str | None = None) -> str | None:
        """Gateway des Adapters; ohne Adapter das mit der kleinsten Metrik.

        Hat der genannte Adapter keine Standardroute, gibt es None – nie das Gateway eines
        anderen Adapters (sonst prüft der Wächter das falsche Netz).
        """
        routes = self._default_routes()
        if adapter_name is not None:
            routes = [r for r in routes if r.interface == adapter_name]
        if not routes:
            return None
        return min(routes, key=lambda r: r.metric).gateway

    # --- ARP-Cache ---------------------------------------------------------------
    def neighbor_table(self) -> dict[str, str]:
        res = _run([_system_exe("ARP.EXE"), "-a"], CMD_TIMEOUT_S)
        return _parse_arp(res.out) if res is not None else {}

    def neighbor_mac(self, ip: str, interface: str | None = None) -> str | None:
        """MAC aus dem ARP-Cache. Mit interface nur aus dem Abschnitt dieser Schnittstelle – sonst könnte bei
        gleicher Gateway-IP an zwei Adaptern (Ethernet und Hotspot-WLAN) die MAC des anderen Netzes gelten."""
        try:
            key = str(ipaddress.IPv4Address(str(ip)))
        except ValueError:
            return None
        res = _run([_system_exe("ARP.EXE"), "-a"], CMD_TIMEOUT_S)
        if res is None:
            return None
        if interface is None:
            return _parse_arp(res.out).get(key)
        try:
            own_ips = [i.ipv4 for i in self.interfaces() if i.name == interface]
        except Exception:  # noqa: BLE001 – Zuordnung unklar ⇒ lieber „unbekannt“ als die MAC eines anderen Netzes
            log.debug("Schnittstellen für arp -a nicht lesbar", exc_info=True)
            return None
        sections = _parse_arp_sections(res.out)
        for if_ip in own_ips:
            mac = sections.get(if_ip, {}).get(key)
            if mac:
                return mac
        return None

    # --- Ping --------------------------------------------------------------------
    def ping(self, ip: str, timeout_ms: int) -> PingResult:
        try:
            addr = ipaddress.IPv4Address(str(ip))  # nur IPv4-Literale – keine Befehlsinjektion
        except ValueError:
            log.warning("Ping abgelehnt, keine IPv4-Adresse: %.60r", ip)
            return PingResult(alive=False)
        if addr.is_multicast or addr.is_unspecified or addr == ipaddress.IPv4Address("255.255.255.255"):
            return PingResult(alive=False)
        wait_ms = max(PING_MIN_MS, min(PING_MAX_MS, _to_int(timeout_ms, PING_MAX_MS)))
        res = _run([_system_exe("PING.EXE"), "-n", "1", "-w", str(wait_ms), str(addr)], wait_ms / 1000 + PING_RESERVE_S)
        return _parse_ping(res.out) if res is not None else PingResult(alive=False)

    # --- Rechte ------------------------------------------------------------------
    def is_admin(self) -> bool:
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001 – kein Windows oder Aufruf gescheitert
            return False


# --- Konsolenfenster des Servers ----------------------------------------------------------

ENABLE_QUICK_EDIT_MODE = 0x0040
ENABLE_EXTENDED_FLAGS = 0x0080


def _mode_without_quick_edit(mode: int) -> int:
    """Konsolenmodus ohne QuickEdit (ENABLE_EXTENDED_FLAGS muss dafür gesetzt sein)."""
    return (int(mode) | ENABLE_EXTENDED_FLAGS) & ~ENABLE_QUICK_EDIT_MODE


def disable_quick_edit() -> Callable[[], None] | None:
    """Schaltet QuickEdit für das eigene Konsolenfenster ab und gibt eine Funktion zurück, die den alten
    Zustand wiederherstellt (None, wenn nichts zu tun war oder es nicht ging).

    Mit QuickEdit startet schon ein Klick ins Server-Fenster den Markiermodus; dann blockiert jede
    Ausgabe auf die Konsole – Oberfläche und Scan stehen still, bis Esc gedrückt wird. Geändert wird
    nur der Modus dieser Konsole, keine Einstellung von Windows.
    """
    if sys.platform != "win32":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
        kernel32.GetStdHandle.restype = wintypes.HANDLE
        kernel32.GetStdHandle.argtypes = [wintypes.DWORD]
        kernel32.GetConsoleMode.restype = wintypes.BOOL
        kernel32.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel32.SetConsoleMode.restype = wintypes.BOOL
        kernel32.SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        handle = kernel32.GetStdHandle(0xFFFFFFF6)  # STD_INPUT_HANDLE (-10)
        if not handle or handle == ctypes.c_void_p(-1).value:
            return None
        mode = wintypes.DWORD()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):  # keine Konsole (Eingabe umgeleitet)
            return None
        old = int(mode.value)
        new = _mode_without_quick_edit(old)
        if new == old or not kernel32.SetConsoleMode(handle, new):
            return None
    except Exception:  # noqa: BLE001 – ohne diese Hilfe läuft der Server genauso
        log.debug("QuickEdit ließ sich nicht abschalten", exc_info=True)
        return None

    def restore() -> None:
        try:
            kernel32.SetConsoleMode(handle, old)
        except Exception:  # noqa: BLE001
            log.debug("Konsolenmodus nicht wiederhergestellt", exc_info=True)

    return restore
