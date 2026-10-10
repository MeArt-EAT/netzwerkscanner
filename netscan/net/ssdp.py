"""SSDP/UPnP: M-SEARCH und Gerätebeschreibung (XML). (Agent identify)"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from netscan.core.context import ScanCancelled, ScanContext, parallel_map
from netscan.core.models import Adapter, SsdpInfo

log = logging.getLogger(__name__)

# fetch(url, timeout_s) -> bytes
Fetcher = Callable[[str, float], bytes]

_PHASE = "SSDP/UPnP"
_SEARCH_COUNT = 2  # M-SEARCH wird zweimal gesendet (UDP kann verloren gehen)
_SECOND_SEARCH_MAX_DELAY_S = 0.5
_RECV_TIMEOUT_S = 0.25
_RECV_SIZE = 65535
_MULTICAST_TTL = 2
_MAX_DESCRIPTION_BYTES = 256 * 1024
_FETCH_TIMEOUT_S = 2.0
_FETCH_WORKERS = 8
_TEXT_LIMIT = 200  # längste übernommene Textangabe (Name, Hersteller, Server …)
_MAX_HEADER_LINES = 100

# HOST steht laut UPnP immer auf der Multicast-Adresse, auch wenn das Ziel in Tests ein anderes ist.
_M_SEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
).encode("ascii")


@dataclass
class _Responder:
    """Was ein Gerät auf den M-SEARCH geantwortet hat (erste brauchbare Angaben)."""

    server: str | None = None
    location: str | None = None  # nur eine ladbare LOCATION (http, Host == antwortende IP)


# --- reine Hilfsfunktionen ---------------------------------------------------------------------


def _clip(text: str | None) -> str | None:
    """Leerraum vereinheitlichen und auf _TEXT_LIMIT kürzen; leer ⇒ None."""
    if not text:
        return None
    cleaned = " ".join(text.split())
    return cleaned[:_TEXT_LIMIT] or None


def _parse_ssdp_response(data: bytes) -> dict[str, str]:
    """Kopfzeilen einer SSDP-Antwort (HTTP/1.1 200 OK bzw. NOTIFY) ohne Beachtung der Groß-/Kleinschreibung.

    Schlüssel sind klein geschrieben (location, server, st, usn …), der erste Wert gewinnt.
    Alles andere (Anfragen, Müll) ergibt ein leeres Wörterbuch.
    """
    lines = data.decode("utf-8", errors="replace").splitlines()
    if not lines:
        return {}
    start = lines[0].strip().upper()
    if not (start.startswith("HTTP/") or start.startswith("NOTIFY")):
        return {}
    headers: dict[str, str] = {}
    for line in lines[1 : 1 + _MAX_HEADER_LINES]:
        if not line.strip():
            break
        key, sep, value = line.partition(":")
        key = key.strip().lower()
        if sep and key and key not in headers:
            headers[key] = value.strip()
    return headers


def _loadable_location(ip: str, location: str) -> str | None:
    """Gibt die LOCATION zurück, wenn sie geladen werden darf: Schema http, Host == antwortende IP.

    Keine Namen (das wäre eine Namensauflösung), keine Zugangsdaten in der Adresse, kein Port 0.
    """
    url = location.strip()
    if not url or not url.isascii() or any(ch.isspace() or ord(ch) < 0x20 or ch in "\\\x7f" for ch in url):
        return None
    try:
        parts = urlsplit(url)
        host = parts.hostname
        port = parts.port
    except ValueError:
        return None
    if parts.scheme != "http" or not host or "@" in parts.netloc or port == 0:
        return None
    try:
        if ipaddress.ip_address(host) != ipaddress.ip_address(ip):
            return None
    except ValueError:
        return None
    return url


def _local_name(tag: str) -> str:
    """Tag ohne Namensraum: "{urn:…}device" ⇒ "device"."""
    return tag.rsplit("}", 1)[-1]


def _child_text(element: ET.Element, name: str) -> str | None:
    for child in element:
        if _local_name(child.tag) == name:
            return _clip(child.text)
    return None


def _parse_description(data: bytes) -> dict[str, str | None]:
    """Liest root/device einer UPnP-Beschreibung (namensraum-unabhängig). Kaputtes XML ⇒ {}."""
    if len(data) > _MAX_DESCRIPTION_BYTES:
        return {}
    lowered = data.lower()
    # Keine DOCTYPE/ENTITY (Entity-Bomben) und keine NUL-Bytes (UTF-16): UPnP braucht beides nicht.
    if b"\x00" in data or b"<!doctype" in lowered or b"<!entity" in lowered:
        return {}
    try:
        root = ET.fromstring(data)
    except Exception:  # noqa: BLE001 – ParseError, ValueError u. a.: Beschreibung unbrauchbar
        return {}
    device = next((child for child in root if _local_name(child.tag) == "device"), None)
    if device is None:
        return {}
    return {
        "friendly_name": _child_text(device, "friendlyName"),
        "manufacturer": _child_text(device, "manufacturer"),
        "model_name": _child_text(device, "modelName"),
        "model_number": _child_text(device, "modelNumber"),
        "device_type": _child_text(device, "deviceType"),
    }


def _is_multicast(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_multicast
    except ValueError:
        return False


# --- Beschreibung laden ------------------------------------------------------------------------


_MAX_HEAD_BYTES = 16 * 1024  # Kopfzeilen einer Antwort
_STATUS_LINE = re.compile(rb"^HTTP/1\.[01][ \t]+(\d{3})\b")


def _remaining(deadline: float) -> float:
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError("Beschreibung kommt zu langsam")
    return left


def _head_end(data: bytes | bytearray) -> int | None:
    """Position hinter der Leerzeile nach den Kopfzeilen; None, solange sie noch fehlt."""
    for sep in (b"\r\n\r\n", b"\n\n"):
        index = data.find(sep)
        if index >= 0:
            return index + len(sep)
    return None


def _parse_head(head: bytes) -> tuple[int, dict[str, str]]:
    """(Status, Kopfzeilen klein geschrieben; der erste Wert gewinnt). Keine HTTP-Antwort ⇒ ValueError."""
    lines = head.replace(b"\r\n", b"\n").split(b"\n")
    match = _STATUS_LINE.match(lines[0])
    if not match:
        raise ValueError("Keine HTTP-Antwort")
    headers: dict[str, str] = {}
    for line in lines[1 : 1 + _MAX_HEADER_LINES]:
        key, sep, value = line.decode("latin-1").partition(":")
        key = key.strip().lower()
        if sep and key and key not in headers:
            headers[key] = value.strip()
    return int(match.group(1)), headers


def _dechunk(data: bytes) -> bytes:
    """Transfer-Encoding: chunked auflösen (manche Geräte senden das trotz HTTP/1.0). Unvollständig ⇒ ValueError."""
    out = bytearray()
    pos = 0
    while True:
        end = data.find(b"\r\n", pos)
        if end < 0:
            raise ValueError("Unvollständige Antwort")
        try:
            size = int(data[pos:end].split(b";", 1)[0].strip(), 16)
        except ValueError as exc:
            raise ValueError("Ungültige Blocklänge") from exc
        if size == 0:
            return bytes(out)
        start = end + 2
        if start + size > len(data):
            raise ValueError("Unvollständige Antwort")
        out += data[start : start + size]
        if len(out) > _MAX_DESCRIPTION_BYTES:
            raise ValueError("Beschreibung zu groß")
        pos = start + size + 2


def _fetch_http(url: str, timeout_s: float) -> bytes:
    """Standard-fetch: einfaches HTTP/1.0-GET über einen eigenen Socket – ohne Proxy, ohne Weiterleitung,
    höchstens 256 KB. Die Zeitgrenze timeout_s gilt für Verbindung, Kopfzeilen und Inhalt zusammen: jedes
    recv wartet höchstens bis zur Frist. Ein Gerät, das Byte für Byte tröpfelt, hält den Scan nicht auf."""
    parts = urlsplit(url)
    if parts.scheme != "http" or not parts.hostname:
        raise ValueError("Nur http-Adressen")
    address = str(ipaddress.IPv4Address(parts.hostname))  # nur IP-Literale, keine Namensauflösung
    port = parts.port or 80
    target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    request = (
        f"GET {target} HTTP/1.0\r\nHost: {address}:{port}\r\nUser-Agent: Netzwerkscanner\r\n"
        "Accept: text/xml, */*;q=0.5\r\nConnection: close\r\n\r\n"
    ).encode("ascii")
    deadline = time.monotonic() + max(0.05, float(timeout_s))
    data = bytearray()
    body_start: int | None = None
    length: int | None = None
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(_remaining(deadline))
        sock.connect((address, port))
        sock.settimeout(_remaining(deadline))
        sock.sendall(request)
        while True:
            sock.settimeout(max(0.01, _remaining(deadline)))
            chunk = sock.recv(8192)
            if not chunk:
                break
            data += chunk
            if body_start is None:
                body_start = _head_end(data)
                if body_start is None:
                    if len(data) > _MAX_HEAD_BYTES:
                        raise ValueError("Kopfzeilen zu lang")
                    continue
                status, headers = _parse_head(bytes(data[:body_start]))
                if status != 200:
                    raise ValueError(f"HTTP-Status {status}")  # auch 3xx: keiner Weiterleitung folgen
                raw_length = headers.get("content-length", "")
                if raw_length.isdigit() and "chunked" not in headers.get("transfer-encoding", "").lower():
                    length = int(raw_length)
                    if length > _MAX_DESCRIPTION_BYTES:
                        raise ValueError("Beschreibung zu groß")
            body_size = len(data) - body_start
            if body_size > _MAX_DESCRIPTION_BYTES + _MAX_HEAD_BYTES:  # Reserve für chunked-Blockköpfe
                raise ValueError("Beschreibung zu groß")
            if length is not None and body_size >= length:
                break  # alles da – nicht auf das Schließen der Verbindung warten
    finally:
        try:
            sock.close()
        except OSError:
            pass
    if body_start is None:
        raise ValueError("Antwort ohne Kopfzeilen")
    status, headers = _parse_head(bytes(data[:body_start]))
    body = bytes(data[body_start:])
    if "chunked" in headers.get("transfer-encoding", "").lower():
        body = _dechunk(body)
    elif length is not None:
        if len(body) < length:
            raise ValueError("Unvollständige Antwort")
        body = body[:length]
    if len(body) > _MAX_DESCRIPTION_BYTES:
        raise ValueError("Beschreibung zu groß")
    return body


# --- Suche -------------------------------------------------------------------------------------


def _source_filter(adapter: Adapter, allowed_ips: set[str] | None) -> Callable[[str], bool]:
    """Welche Absender zulässig sind: allowed_ips, sonst das Netz des Adapters."""
    if allowed_ips is not None:
        allowed = set(allowed_ips)
        return lambda ip: ip in allowed
    try:
        network = ipaddress.ip_network(adapter.network, strict=False)
    except ValueError:
        return lambda ip: False

    def in_network(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip) in network
        except ValueError:
            return False

    return in_network


def _note_response(responders: dict[str, _Responder], data: bytes, addr: tuple[Any, ...], is_allowed: Callable[[str], bool]) -> None:
    ip = addr[0]
    if not isinstance(ip, str) or not is_allowed(ip):
        return
    headers = _parse_ssdp_response(data)
    if not any(key in headers for key in ("location", "server", "st", "usn")):
        return
    entry = responders.setdefault(ip, _Responder())
    if entry.server is None:
        entry.server = _clip(headers.get("server"))
    if entry.location is None and headers.get("location"):
        entry.location = _loadable_location(ip, headers["location"])


def _search(
    ctx: ScanContext, adapter: Adapter, target: tuple[str, int], is_allowed: Callable[[str], bool]
) -> dict[str, _Responder]:
    """Sendet zweimal M-SEARCH und sammelt settings.ssdp_timeout_s lang die Antworten."""
    responders: dict[str, _Responder] = {}
    timeout = max(0.0, float(ctx.settings.ssdp_timeout_s))
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError as exc:
        ctx.log(f"SSDP/UPnP: Suche nicht möglich ({exc}).", "warning")
        return responders
    try:
        sock.bind((adapter.ipv4, 0))
        if _is_multicast(target[0]):
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(adapter.ipv4))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, _MULTICAST_TTL)
        start = time.monotonic()
        deadline = start + timeout
        send_at = [0.0, min(_SECOND_SEARCH_MAX_DELAY_S, timeout / 2)]
        sent = 0
        while True:
            ctx.check_cancel()
            now = time.monotonic()
            if sent < _SEARCH_COUNT and now - start >= send_at[sent]:
                if ctx.rate is not None:
                    ctx.rate.acquire()
                sock.sendto(_M_SEARCH, target)
                sent += 1
                continue
            if now >= deadline:
                break
            wait = min(_RECV_TIMEOUT_S, deadline - now)
            if sent < _SEARCH_COUNT:
                wait = min(wait, max(0.001, send_at[sent] - (now - start)))
            sock.settimeout(max(wait, 0.001))
            try:
                data, addr = sock.recvfrom(_RECV_SIZE)
            except (TimeoutError, BlockingIOError, InterruptedError):
                continue
            except ConnectionResetError:  # Windows: ICMP „Port nicht erreichbar“ einer früheren Sendung
                continue
            _note_response(responders, data, addr, is_allowed)
    except OSError as exc:
        log.debug("SSDP-Suche abgebrochen", exc_info=True)
        ctx.log(f"SSDP/UPnP: Suche nicht möglich oder gestört ({exc}).", "warning")
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return responders


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
    ctx.check_cancel()
    if allowed_ips is not None and not allowed_ips:
        return {}
    fetcher = fetch if fetch is not None else _fetch_http
    is_allowed = _source_filter(adapter, allowed_ips)

    ctx.progress(_PHASE, 0, 1, "Suche nach UPnP-Geräten …")
    responders = _search(ctx, adapter, target, is_allowed)
    ctx.check_cancel()

    result = {ip: SsdpInfo(location=entry.location, server=entry.server) for ip, entry in responders.items()}
    todo = [(ip, entry.location) for ip, entry in responders.items() if entry.location]
    total = 1 + len(todo)
    ctx.progress(_PHASE, 1, total, f"{len(responders)} Geräte antworten")

    def describe(item: tuple[str, str | None]) -> dict[str, str | None] | None:
        _ip, url = item
        ctx.check_cancel()
        try:
            data = fetcher(url or "", _FETCH_TIMEOUT_S)
        except ScanCancelled:
            raise
        except Exception:  # noqa: BLE001 – ein Gerät ohne brauchbare Beschreibung bleibt mit server/location
            log.debug("UPnP-Beschreibung von %s nicht ladbar", url, exc_info=True)
            return None
        if not isinstance(data, (bytes, bytearray)):
            return None
        return _parse_description(bytes(data))

    def on_result(_item: tuple[str, str | None], _fields: dict[str, str | None] | None, done: int, count: int) -> None:
        ctx.progress(_PHASE, 1 + done, total, f"Beschreibung {done} von {count}")

    loaded = 0
    if todo:
        pairs = parallel_map(ctx, describe, todo, min(_FETCH_WORKERS, len(todo)), on_result=on_result)
        for (ip, _url), fields in pairs:
            if not fields:
                continue
            loaded += 1
            info = result[ip]
            info.friendly_name = fields.get("friendly_name")
            info.manufacturer = fields.get("manufacturer")
            info.model_name = fields.get("model_name")
            info.model_number = fields.get("model_number")
            info.device_type = fields.get("device_type")

    ctx.progress(_PHASE, total, total, f"{len(result)} Geräte, {loaded} Beschreibungen")
    ctx.log(f"SSDP/UPnP: {len(result)} Geräte antworteten, {loaded} Beschreibungen geladen.")
    return result
