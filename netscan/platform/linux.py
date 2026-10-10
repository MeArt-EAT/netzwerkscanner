"""Linux-Implementierung (Raspberry Pi später): nmcli/iwgetid, ping, ip route, ip neigh, /sys. (Agent guard)

Alle Abfragen lesen nur den Zustand des eigenen Systems – einzig ping sendet ein Echo an eine
vorher geprüfte IPv4-Adresse (mit -n, also ohne Namensauflösung). Befehle laufen mit LC_ALL=C,
damit die Ausgaben nicht übersetzt sind. Fehler ergeben leere Ergebnisse, nie einen Absturz.
"""

from __future__ import annotations

import ipaddress
import logging
import math
import os
import re
import socket
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from netscan.core.models import PingResult, normalize_mac
from netscan.platform.base import AdapterDetail, InterfaceAddr, WifiEntry, WifiStatus, psutil_interfaces

log = logging.getLogger(__name__)

CMD_TIMEOUT_S = 5.0
SSID_TIMEOUT_S = 3.0
PING_MIN_MS = 50
PING_MAX_MS = 2000  # Bauplan: jede Netzoperation höchstens 2 s
PING_RESERVE_S = 1.5

_ENV_C = {"LC_ALL": "C", "LANG": "C", "LANGUAGE": "C"}


# --- Befehle ausführen ------------------------------------------------------------------


@dataclass(frozen=True)
class _Result:
    rc: int
    out: str
    err: str


def _run(args: list[str], timeout: float) -> _Result | None:
    """Startet einen Befehl mit LC_ALL=C. None, wenn er fehlt, hängt oder nicht startet."""
    env = dict(os.environ)
    env.update(_ENV_C)
    try:
        proc = subprocess.run(
            args, capture_output=True, stdin=subprocess.DEVNULL, timeout=timeout, check=False, env=env
        )
    except subprocess.TimeoutExpired:
        log.warning("Befehl %s: Zeitüberschreitung nach %.1f s", args[0], timeout)
        return None
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        log.debug("Befehl %s nicht ausführbar: %s", args[0], exc)
        return None
    return _Result(
        proc.returncode,
        (proc.stdout or b"").decode("utf-8", errors="replace"),
        (proc.stderr or b"").decode("utf-8", errors="replace"),
    )


# --- kleine Helfer ---------------------------------------------------------------------


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
    if norm is None or int(norm[:2], 16) & 1:  # Gruppenbit gesetzt
        return None
    return norm


def _gateway_ip(value: Any) -> str | None:
    try:
        addr = ipaddress.IPv4Address(str(value or "").strip())
    except ValueError:
        return None
    return None if addr.is_unspecified else str(addr)


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None


# --- Parser (reine Funktionen) ----------------------------------------------------------


def _split_terse(line: str) -> list[str]:
    """Eine Zeile von „nmcli -t“ zerlegen: ':' trennt, '\\:' und '\\\\' sind maskiert."""
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for ch in line:
        if escaped:
            current.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(ch)
    fields.append("".join(current))
    return fields


@dataclass(frozen=True)
class _NmDevice:
    device: str
    type: str
    state: str
    connection: str | None


def _parse_nmcli_devices(text: str) -> list[_NmDevice]:
    """„nmcli -t -f DEVICE,TYPE,STATE,CONNECTION device“ -> Geräteliste.

    Achtung: CONNECTION ist der Profilname, nicht zwingend die SSID – er wird nie als SSID verwendet.
    """
    out: list[_NmDevice] = []
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        parts = _split_terse(line)
        if len(parts) < 3:
            continue
        connection = parts[3] if len(parts) > 3 and parts[3] not in ("", "--") else None
        out.append(_NmDevice(parts[0], parts[1].strip().lower(), parts[2].strip().lower(), connection))
    return out


def _nm_connected(state: str) -> bool:
    """„connected“, „connected (externally)“, „connected (site only)“ zählen als verbunden."""
    return state.startswith("connected")


@dataclass(frozen=True)
class _Route:
    interface: str | None
    gateway: str
    metric: int


def _parse_ip_route(text: str) -> list[_Route]:
    """„ip -4 route show default“ -> Standardrouten, kleinste Metrik zuerst (auch Mehrweg-Routen)."""
    routes: list[_Route] = []
    parent_metric = 0
    for line in (text or "").splitlines():
        tokens = line.split()
        if not tokens:
            continue
        if tokens[0] == "default":
            parent_metric = _token_int(tokens, "metric")
        elif tokens[0] != "nexthop":
            continue
        gateway = _gateway_ip(_token_after(tokens, "via"))
        if gateway is None:
            continue
        metric = _token_int(tokens, "metric") if tokens[0] == "default" else parent_metric
        routes.append(_Route(_token_after(tokens, "dev"), gateway, metric))
    return sorted(routes, key=lambda r: r.metric)


def _token_after(tokens: list[str], key: str) -> str | None:
    try:
        return tokens[tokens.index(key) + 1]
    except (ValueError, IndexError):
        return None


def _token_int(tokens: list[str], key: str) -> int:
    try:
        return int(_token_after(tokens, key) or 0)
    except ValueError:
        return 0


_RTF_GATEWAY = 0x2


def _parse_proc_route(text: str) -> list[_Route]:
    """/proc/net/route (Hex, little endian) -> Standardrouten, kleinste Metrik zuerst."""
    routes: list[_Route] = []
    for line in (text or "").splitlines()[1:]:
        cols = line.split()
        if len(cols) < 8:
            continue
        try:
            dest, gw_hex, flags, metric, mask = int(cols[1], 16), int(cols[2], 16), int(cols[3], 16), int(cols[6]), int(cols[7], 16)
        except ValueError:
            continue
        if dest != 0 or mask != 0 or not flags & _RTF_GATEWAY:
            continue
        gateway = _gateway_ip(socket.inet_ntoa(struct.pack("<L", gw_hex)))
        if gateway is not None:
            routes.append(_Route(cols[0], gateway, metric))
    return sorted(routes, key=lambda r: r.metric)


def _parse_ip_neigh(text: str) -> dict[str, str]:
    """„ip -4 neigh show“ -> IP -> MAC. Einträge ohne lladdr (FAILED, INCOMPLETE) fehlen."""
    out: dict[str, str] = {}
    for line in (text or "").splitlines():
        tokens = line.split()
        if len(tokens) < 3 or "lladdr" not in tokens:
            continue
        if tokens[-1].upper() in ("FAILED", "INCOMPLETE"):
            continue
        mac = _usable_neighbor(tokens[0], _token_after(tokens, "lladdr") or "")
        if mac is not None:
            out.setdefault(tokens[0], mac)
    return out


def _parse_proc_arp(text: str) -> dict[str, str]:
    """/proc/net/arp -> IP -> MAC. Flags 0x0 = unvollständig."""
    out: dict[str, str] = {}
    for line in (text or "").splitlines()[1:]:
        cols = line.split()
        if len(cols) < 4:
            continue
        try:
            flags = int(cols[2], 16)
        except ValueError:
            continue
        if not flags & 0x2:  # ATF_COM: Eintrag vollständig
            continue
        mac = _usable_neighbor(cols[0], cols[3])
        if mac is not None:
            out.setdefault(cols[0], mac)
    return out


def _parse_ping(text: str) -> PingResult:
    """Ausgabe von „ping -c 1“ (iputils/BusyBox): erreichbar nur mit „ttl=“ in einer Antwortzeile."""
    for line in (text or "").splitlines():
        ttl_m = re.search(r"\bttl=(\d+)", line, re.IGNORECASE)
        if not ttl_m:
            continue
        rtt_m = re.search(r"time[=<]\s*(\d+(?:\.\d+)?)\s*ms", line, re.IGNORECASE)
        return PingResult(alive=True, rtt_ms=float(rtt_m.group(1)) if rtt_m else None, ttl=int(ttl_m.group(1)))
    return PingResult(alive=False)


def _read_sysfs_details(root: Path) -> dict[str, AdapterDetail]:
    """/sys/class/net/<if>: WLAN = Unterordner wireless oder phy80211; ohne device = virtuell."""
    out: dict[str, AdapterDetail] = {}
    try:
        entries = sorted(root.iterdir(), key=lambda p: p.name)
    except OSError:
        return out
    for entry in entries:
        name = entry.name
        wireless = (entry / "wireless").exists() or (entry / "phy80211").exists()
        virtual = not (entry / "device").exists()
        driver = ""
        uevent = _read_text(entry / "device" / "uevent") if not virtual else None
        for line in (uevent or "").splitlines():
            if line.startswith("DRIVER="):
                driver = line.split("=", 1)[1].strip()
                break
        description = driver or ("virtuelle Schnittstelle" if virtual else "")
        out[name] = AdapterDetail(
            name=name,
            description=description,
            is_virtual=virtual,
            is_wireless=wireless,
            mac=_norm_mac(_read_text(entry / "address")),
        )
    return out


# --- Plattform ------------------------------------------------------------------------


class LinuxPlatform:
    name = "linux"

    def __init__(self, *, sys_net: str | Path = "/sys/class/net", proc_net: str | Path = "/proc/net") -> None:
        self._sys_net = Path(sys_net)
        self._proc_net = Path(proc_net)

    def interfaces(self) -> list[InterfaceAddr]:
        return psutil_interfaces()

    def adapter_details(self) -> dict[str, AdapterDetail]:
        return _read_sysfs_details(self._sys_net)

    # --- WLAN --------------------------------------------------------------------
    def _iwgetid(self, device: str) -> tuple[bool, str | None]:
        """(Werkzeug vorhanden, SSID oder None)."""
        res = _run(["iwgetid", "-r", device], SSID_TIMEOUT_S)
        if res is None:
            return False, None
        ssid = res.out.strip()
        return True, ssid if res.rc == 0 and ssid else None

    def _ssid_of(self, device: str, connection: str | None) -> str | None:
        _, ssid = self._iwgetid(device)
        if ssid:
            return ssid
        if connection:
            res = _run(
                ["nmcli", "-t", "-e", "no", "-g", "802-11-wireless.ssid", "connection", "show", "id", connection],
                SSID_TIMEOUT_S,
            )
            if res is not None and res.rc == 0 and res.out.strip():
                return res.out.strip()
        return None

    def _iw_entry(self, device: str) -> tuple[bool, WifiEntry]:
        """WLAN-Karte ohne NetworkManager: SSID per iwgetid, sonst operstate. (Werkzeug vorhanden, Eintrag)."""
        available, ssid = self._iwgetid(device)
        if ssid:
            return available, WifiEntry(interface=device, connected=True, ssid=ssid)
        operstate = (_read_text(self._sys_net / device / "operstate") or "").lower()
        return available, WifiEntry(interface=device, connected=operstate == "up", ssid=None)

    def wifi_status(self) -> WifiStatus:
        res = _run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device"], CMD_TIMEOUT_S)
        if res is not None and res.rc == 0:
            entries: list[WifiEntry] = []
            seen: set[str] = set()
            for dev in _parse_nmcli_devices(res.out):
                if dev.type != "wifi":
                    continue
                seen.add(dev.device)
                if _nm_connected(dev.state):
                    entries.append(WifiEntry(dev.device, True, self._ssid_of(dev.device, dev.connection)))
                elif dev.state.startswith("unmanaged"):
                    # z. B. wpa_supplicant ohne NetworkManager: selbst nachsehen
                    entries.append(self._iw_entry(dev.device)[1])
                else:
                    entries.append(WifiEntry(dev.device, False, None))
            for name, detail in self.adapter_details().items():  # WLAN-Karten, die nmcli nicht kennt
                if detail.is_wireless and name not in seen:
                    entries.append(self._iw_entry(name)[1])
            return WifiStatus(entries, readable=True)

        # ohne NetworkManager: WLAN-Karten aus /sys, SSID per iwgetid
        wireless = [name for name, d in self.adapter_details().items() if d.is_wireless]
        if not wireless:
            return WifiStatus([], readable=True)
        entries = []
        for device in wireless:
            available, entry = self._iw_entry(device)
            if not available:
                return WifiStatus([], readable=False, error="weder nmcli noch iwgetid vorhanden")
            entries.append(entry)
        return WifiStatus(entries, readable=True)

    # --- Routen ------------------------------------------------------------------
    def _default_routes(self) -> list[_Route]:
        res = _run(["ip", "-4", "route", "show", "default"], CMD_TIMEOUT_S)
        if res is not None and res.rc == 0:
            return _parse_ip_route(res.out)
        return _parse_proc_route(_read_text(self._proc_net / "route") or "")

    def default_gateway(self, adapter_name: str | None = None) -> str | None:
        """Gateway des Adapters; ohne Adapter das mit der kleinsten Metrik. Fremde Adapter nie."""
        routes = self._default_routes()
        if adapter_name is not None:
            routes = [r for r in routes if r.interface == adapter_name]
        if not routes:
            return None
        return min(routes, key=lambda r: r.metric).gateway

    # --- ARP-Cache ---------------------------------------------------------------
    def neighbor_table(self) -> dict[str, str]:
        res = _run(["ip", "-4", "neigh", "show"], CMD_TIMEOUT_S)
        if res is not None and res.rc == 0:
            return _parse_ip_neigh(res.out)
        return _parse_proc_arp(_read_text(self._proc_net / "arp") or "")

    def neighbor_mac(self, ip: str) -> str | None:
        try:
            key = str(ipaddress.IPv4Address(str(ip)))
        except ValueError:
            return None
        return self.neighbor_table().get(key)

    # --- Ping --------------------------------------------------------------------
    def ping(self, ip: str, timeout_ms: int) -> PingResult:
        try:
            addr = ipaddress.IPv4Address(str(ip))  # nur IPv4-Literale – keine Befehlsinjektion
        except ValueError:
            log.warning("Ping abgelehnt, keine IPv4-Adresse: %.60r", ip)
            return PingResult(alive=False)
        if addr.is_multicast or addr.is_unspecified or addr == ipaddress.IPv4Address("255.255.255.255"):
            return PingResult(alive=False)
        try:
            wait_ms = max(PING_MIN_MS, min(PING_MAX_MS, int(timeout_ms)))
        except (TypeError, ValueError):
            wait_ms = PING_MAX_MS
        wait_s = max(1, math.ceil(wait_ms / 1000))  # -W nimmt bei BusyBox nur ganze Sekunden
        res = _run(["ping", "-n", "-c", "1", "-W", str(wait_s), str(addr)], wait_s + PING_RESERVE_S)
        return _parse_ping(res.out) if res is not None else PingResult(alive=False)

    # --- Rechte ------------------------------------------------------------------
    def is_admin(self) -> bool:
        geteuid = getattr(os, "geteuid", None)
        try:
            return bool(geteuid is not None and geteuid() == 0)
        except OSError:
            return False
