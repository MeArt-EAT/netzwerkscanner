"""Dienst- und Erreichbarkeitsprüfungen für den Monitor (BAUPLAN §23). (Agent checks)

Jede Verbindung läuft über `connect` – Aufruf über den Modulnamen (globale Suche zur Laufzeit), damit Tests und
Demo ihn ersetzen können. Nur IPv4-Literale (keine Namensauflösung), jede Netzoperation höchstens 2 s.
Keine Anmeldung, keine Passwörter; von den Antworten bleibt nur das Ergebnis (Statuscode, Kennung), nichts wird
gespeichert.
"""

from __future__ import annotations

import errno
import ipaddress
import logging
import math
import re
import socket
import ssl
import struct
import time
import uuid
from collections.abc import Callable

from netscan.core.models import REACH_METHODS, CheckResult, Device, PingResult
from netscan.net.ports import UNKNOWN_SERVICE, SourceAddressGone, describe_port

log = logging.getLogger(__name__)

CHECK_KINDS = ("tcp", "http", "https", "smb", "ssh")
DEFAULT_PORTS = {"http": 80, "https": 443, "smb": 445, "ssh": 22}

MIN_TIMEOUT_S = 0.05
MAX_TIMEOUT_S = 2.0  # BAUPLAN §6/§18: jede Netzoperation ≤ 2 s
HTTP_READ_LIMIT = 4096  # höchstens so viele Byte bis zur Statuszeile
HTTP_PATH_MAX = 200
USER_AGENT = "Netzwerkscanner-Monitor"
SSH_LINE_MAX = 255  # RFC 4253: Kennung höchstens 255 Zeichen
SSH_DETAIL_MAX = 60
SMB_READ_LIMIT = 4096
REACH_MAX_PORTS = 3
# Reihenfolge der Ersatzports für den TCP-Erreichbarkeitstest (verbreitete, meist offene Dienste zuerst)
PREFERRED_TCP_PORTS: tuple[int, ...] = (80, 443, 22, 445, 8080, 5000, 5001, 8443, 139, 3389, 53, 631, 9100)
HTTP_PORTS: tuple[int, ...] = (80, 8080, 5000)
HTTPS_PORTS: tuple[int, ...] = (443, 8443, 5001)

SMB2_MAGIC = b"\xfeSMB"
SMB1_MAGIC = b"\xffSMB"
SMB_DIALECTS: tuple[int, ...] = (0x0202, 0x0210, 0x0300)
_SMB_DIALECT_NAMES = {0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0", 0x0302: "3.0.2", 0x0311: "3.1.1"}
_SMB_WANT = 4 + 64 + 6  # NetBIOS-Kopf + SMB2-Kopf + Anfang der NEGOTIATE-Antwort (bis DialectRevision)

_BROADCAST = ipaddress.IPv4Address("255.255.255.255")
_STATUS_LINE = re.compile(rb"HTTP/\d(?:\.\d)? ([1-5]\d\d)(?:[ \t][^\r\n]*)?")

# Uhr für Fristen (Tests ersetzen sie, statt zu warten); Antwortzeiten misst perf_counter.
_monotonic: Callable[[], float] = time.monotonic


def _errno_texts() -> dict[int, str]:
    """Deutsche Kurztexte für typische Verbindungsfehler (POSIX- und Windows-Nummern)."""
    names = {
        "ENETUNREACH": "Netz nicht erreichbar",
        "EHOSTUNREACH": "keine Route zum Gerät",
        "EHOSTDOWN": "Gerät nicht erreichbar",
        "ENETDOWN": "Netz ausgefallen",
        "ECONNRESET": "Verbindung zurückgesetzt",
        "ECONNABORTED": "Verbindung abgebrochen",
        "EADDRNOTAVAIL": "Adresse nicht verfügbar",
        "EACCES": "vom System blockiert",
        "EPERM": "vom System blockiert",
    }
    out: dict[int, str] = {}
    for name, text in names.items():
        for variant in (name, "WSA" + name):
            value = getattr(errno, variant, None)
            if isinstance(value, int):
                out.setdefault(value, text)
    return out


_ERRNO_TEXT = _errno_texts()


# --- Eingaben prüfen ---------------------------------------------------------------------------


def _ipv4(ip: object) -> str:
    """Unicast-IPv4-Literal oder ValueError. Keine Namensauflösung."""
    if not isinstance(ip, str):
        raise ValueError(f"Keine IPv4-Adresse: {ip!r}")
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        raise ValueError(f"Keine IPv4-Adresse (Namen werden nicht aufgelöst): {ip[:60]!r}") from None
    if addr.is_multicast or addr.is_unspecified or addr == _BROADCAST:
        raise ValueError(f"Keine Unicast-IPv4-Adresse: {ip!r}")
    return str(addr)


def _valid_port(port: object) -> bool:
    return isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535


def _port(port: object) -> int:
    if not _valid_port(port):
        raise ValueError(f"Port muss eine ganze Zahl zwischen 1 und 65535 sein: {port!r}")
    return int(port)  # type: ignore[call-overload]


def _clamp_timeout(timeout_s: object) -> float:
    """Zeitgrenze auf 0,05–2 s begrenzen; Unsinn ergibt 2 s."""
    try:
        value = float(timeout_s)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return MAX_TIMEOUT_S
    if math.isnan(value):
        return MAX_TIMEOUT_S
    return min(MAX_TIMEOUT_S, max(MIN_TIMEOUT_S, value))


def _http_path(path: object) -> str:
    """Pfad für die Anfragezeile. ValueError bei ungültigem Pfad; Nicht-ASCII wird %-kodiert (UTF-8)."""
    if path is None:
        path = "/"
    if not isinstance(path, str) or not path.startswith("/") or len(path) > HTTP_PATH_MAX:
        raise ValueError(f"path muss mit „/“ beginnen und höchstens {HTTP_PATH_MAX} Zeichen lang sein.")
    if any(ord(ch) < 33 or ord(ch) == 127 for ch in path):
        raise ValueError("path darf keine Leer- oder Steuerzeichen enthalten.")
    # Gleiche Regeln wie targets.validate_check; Nicht-ASCII nur kodiert senden (Anfragezeile bleibt reines ASCII).
    return "".join(ch if ord(ch) < 128 else "".join(f"%{b:02X}" for b in ch.encode("utf-8")) for ch in path)


# --- Verbindung --------------------------------------------------------------------------------


def connect(ip: str, port: int, timeout_s: float, source_ip: str | None = None) -> socket.socket:
    """Baut eine TCP-Verbindung auf – der EINZIGE Weg ins Netz für die Prüfungen (Tests/Demo ersetzen ihn).

    Nur IPv4-Literale (Hostname ⇒ ValueError, keine DNS-Anfrage), Port 1–65535 (sonst ValueError), Zeitgrenze
    0,05–2 s. Mit source_ip wird vorher an diese Adresse gebunden; scheitert das (Adresse nach Netzwechsel weg)
    oder ist sie kein IPv4-Literal ⇒ SourceAddressGone, und es wurde nichts gesendet.
    Fehler beim Verbindungsaufbau (abgelehnt, Zeitüberschreitung, …) werden als OSError weitergereicht.
    """
    target = _ipv4(ip)
    port = _port(port)
    timeout = _clamp_timeout(timeout_s)
    source: str | None = None
    if source_ip is not None:
        try:
            source = _ipv4(source_ip)  # kein Name (DNS), nicht 0.0.0.0 (das wäre „irgendein Adapter“)
        except ValueError as exc:
            raise SourceAddressGone(f"Absenderadresse ungültig: {str(source_ip)[:60]!r}") from exc
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        if source is not None:
            try:
                sock.bind((source, 0))
            except OSError as exc:
                raise SourceAddressGone(f"Absenderadresse {source} nicht verfügbar: {exc}") from exc
        sock.connect((target, port))
    except BaseException:
        sock.close()
        raise
    return sock


def _close(sock: socket.socket | None) -> None:
    if sock is None:
        return
    try:
        sock.close()
    except OSError:
        pass


def _ms_since(t0: float) -> float:
    return round((time.perf_counter() - t0) * 1000, 1)


def _error_text(exc: OSError) -> str:
    """„nicht erreichbar (…)“ mit deutschem Grund statt Systemmeldung."""
    code = exc.errno if isinstance(exc.errno, int) else getattr(exc, "winerror", None)
    reason = _ERRNO_TEXT.get(code) if isinstance(code, int) else None
    if reason is None:
        reason = f"Fehler {code}" if isinstance(code, int) else type(exc).__name__
    return f"nicht erreichbar ({reason})"


def _open(
    ip: str, port: int, timeout: float, source_ip: str | None, method: str
) -> tuple[socket.socket | None, CheckResult | None]:
    """Verbindung über checks.connect. (Socket, None) oder (None, Ergebnis für den Fehlschlag).

    ValueError (ungültige Eingabe) und SourceAddressGone werden weitergereicht.
    """
    try:
        # Bewusst über den Modulnamen: globale Suche zur Laufzeit, damit ein ersetztes connect greift.
        return connect(ip, port, timeout, source_ip), None
    except ConnectionRefusedError:
        return None, CheckResult(ok=False, detail="Port geschlossen", method=method)
    except TimeoutError:
        return None, CheckResult(ok=False, detail="keine Antwort", method=method)
    except OSError as exc:
        log.debug("Verbindung zu %s:%s gescheitert: %r", ip, port, exc)
        return None, CheckResult(ok=False, detail=_error_text(exc), method=method)


def _recv_until(sock: socket.socket, deadline: float, enough: Callable[[bytes], bool], limit: int) -> tuple[bytes, str]:
    """Liest, bis enough(daten) gilt. Rückgabe (Daten, Grund): ok, limit, eof, timeout oder error."""
    data = b""
    while True:
        if enough(data):
            return data, "ok"
        if len(data) >= limit:
            return data, "limit"
        remaining = deadline - _monotonic()
        if remaining <= 0:
            return data, "timeout"
        try:
            sock.settimeout(remaining)
            chunk = sock.recv(min(1024, limit - len(data)))
        except TimeoutError:
            return data, "timeout"
        except OSError:  # Reset, TLS-Fehler nach der Aushandlung …
            return data, "error"
        if not chunk:
            return data, "eof"
        data += chunk


def _line_or_mismatch(prefix: bytes) -> Callable[[bytes], bool]:
    """Genug gelesen: Zeilenende da – oder der Anfang passt schon nicht mehr zum erwarteten Präfix."""

    def enough(data: bytes) -> bool:
        return b"\n" in data or not prefix.startswith(data[: len(prefix)])

    return enough


def _send(sock: socket.socket, payload: bytes, deadline: float) -> str:
    """Sendet innerhalb der Frist. Rückgabe ok, timeout oder error."""
    remaining = deadline - _monotonic()
    if remaining <= 0:
        return "timeout"
    try:
        sock.settimeout(remaining)
        sock.sendall(payload)
    except TimeoutError:
        return "timeout"
    except OSError:
        return "error"
    return "ok"


# --- Dienstprüfungen ---------------------------------------------------------------------------


def check_tcp(ip: str, port: int, timeout_s: float, *, source_ip: str | None = None) -> CheckResult:
    """TCP-Verbindungsaufbau. ok = offen; rtt = Dauer des Verbindungsaufbaus."""
    target, port = _ipv4(ip), _port(port)
    method = f"tcp:{port}"
    t0 = time.perf_counter()
    sock, failed = _open(target, port, _clamp_timeout(timeout_s), source_ip, method)
    if failed is not None:
        return failed
    rtt = _ms_since(t0)
    _close(sock)
    return CheckResult(ok=True, rtt_ms=rtt, detail="Port offen", method=method)


def _tls_handshake(sock: socket.socket, deadline: float) -> ssl.SSLSocket:
    """TLS ohne Zertifikatsprüfung (NAS mit eigenem Zertifikat; Bewertung erst in Stufe 3)."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False  # vor verify_mode setzen, sonst ValueError
    context.verify_mode = ssl.CERT_NONE
    tls = context.wrap_socket(sock, server_hostname=None, do_handshake_on_connect=False)
    try:
        remaining = deadline - _monotonic()
        if remaining <= 0:
            raise TimeoutError("Frist abgelaufen")
        tls.settimeout(remaining)
        tls.do_handshake()
    except BaseException:
        _close(tls)
        raise
    return tls


def _status_code(data: bytes, why: str) -> int | None:
    """Statuscode aus der ersten Zeile oder None. Die Zeile muss vollständig sein (Zeilenende oder Verbindungsende)."""
    if b"\n" in data:
        line = data.split(b"\n", 1)[0]
    elif why in ("eof", "error") and data:
        line = data
    else:
        return None
    match = _STATUS_LINE.fullmatch(line.rstrip(b"\r"))
    return int(match.group(1)) if match else None


def check_http(
    ip: str, port: int, timeout_s: float, *, tls: bool = False, path: str = "/", source_ip: str | None = None
) -> CheckResult:
    """Eigene minimale HTTP/1.1-Anfrage (GET), liest nur bis zur Statuszeile (≤ 4 KB), folgt keiner Weiterleitung.

    ok bei 100–499 (401/403 = Dienst läuft, Anmeldung nötig), down bei 5xx oder ohne gültige Antwort.
    """
    request_path = _http_path(path)
    target, port = _ipv4(ip), _port(port)
    scheme = "https" if tls else "http"
    method = f"{scheme}:{port}"
    timeout = _clamp_timeout(timeout_s)
    t0 = time.perf_counter()
    sock, failed = _open(target, port, timeout, source_ip, method)
    if failed is not None:
        return failed
    assert sock is not None
    stream: socket.socket = sock
    deadline = _monotonic() + timeout  # Frist für Aushandlung, Anfrage und Statuszeile
    try:
        if tls:
            try:
                stream = _tls_handshake(sock, deadline)
            except (OSError, ValueError) as exc:  # SSLError, Zeitüberschreitung, Reset
                log.debug("TLS-Aushandlung mit %s:%s gescheitert: %r", target, port, exc)
                return CheckResult(ok=False, detail="TLS-Aushandlung fehlgeschlagen", method=method)
        request = (
            f"GET {request_path} HTTP/1.1\r\nHost: {target}\r\nUser-Agent: {USER_AGENT}\r\nConnection: close\r\n\r\n"
        ).encode("ascii")
        sent = _send(stream, request, deadline)
        if sent != "ok":
            text = "keine Antwort" if sent == "timeout" else "keine gültige HTTP-Antwort"
            return CheckResult(ok=False, detail=text, method=method)
        data, why = _recv_until(stream, deadline, _line_or_mismatch(b"HTTP/"), HTTP_READ_LIMIT)
        code = _status_code(data, why)
        if code is None:
            text = "keine Antwort" if not data and why == "timeout" else "keine gültige HTTP-Antwort"
            return CheckResult(ok=False, detail=text, method=method)
        return CheckResult(
            ok=100 <= code <= 499, rtt_ms=_ms_since(t0), detail=f"{scheme.upper()} {code}", code=code, method=method
        )
    finally:
        _close(stream)
        _close(sock)


def _clean_ident(line: bytes) -> str:
    """SSH-Kennung: nur druckbares ASCII, höchstens 60 Zeichen."""
    text = "".join(chr(b) for b in line if 32 <= b < 127)
    return " ".join(text.split())[:SSH_DETAIL_MAX]


def check_ssh(ip: str, port: int, timeout_s: float, *, source_ip: str | None = None) -> CheckResult:
    """Liest passiv die erste Zeile (≤ 255 Byte); ok, wenn sie mit „SSH-“ beginnt. Sendet nichts."""
    target, port = _ipv4(ip), _port(port)
    method = f"ssh:{port}"
    timeout = _clamp_timeout(timeout_s)
    t0 = time.perf_counter()
    sock, failed = _open(target, port, timeout, source_ip, method)
    if failed is not None:
        return failed
    assert sock is not None
    try:
        data, why = _recv_until(sock, _monotonic() + timeout, _line_or_mismatch(b"SSH-"), SSH_LINE_MAX)
    finally:
        _close(sock)
    line = data.split(b"\n", 1)[0].rstrip(b"\r")[:SSH_LINE_MAX]
    if line.startswith(b"SSH-"):
        return CheckResult(ok=True, rtt_ms=_ms_since(t0), detail=_clean_ident(line), method=method)
    if not data and why == "timeout":
        return CheckResult(ok=False, detail="keine Antwort", method=method)
    return CheckResult(ok=False, detail="keine SSH-Kennung", method=method)


def _smb2_negotiate_request() -> bytes:
    """SMB2-NEGOTIATE mit NetBIOS-Sitzungskopf (Dialekte 2.0.2, 2.1, 3.0) – ohne Anmeldung."""
    header = struct.pack(
        "<4sHHIHHIIQIIQ16s",
        SMB2_MAGIC,  # ProtocolId
        64,  # StructureSize
        0,  # CreditCharge
        0,  # Status
        0,  # Command: NEGOTIATE
        1,  # CreditRequest
        0,  # Flags
        0,  # NextCommand
        0,  # MessageId
        0,  # Reserved (ProcessId)
        0,  # TreeId
        0,  # SessionId
        bytes(16),  # Signature
    )
    body = struct.pack(
        "<HHHHI16sQ",
        36,  # StructureSize
        len(SMB_DIALECTS),  # DialectCount
        1,  # SecurityMode: Signieren möglich
        0,  # Reserved
        0,  # Capabilities
        uuid.uuid4().bytes,  # ClientGuid (Pflicht, sobald mehr als 2.0.2 angeboten wird)
        0,  # ClientStartTime
    ) + struct.pack(f"<{len(SMB_DIALECTS)}H", *SMB_DIALECTS)
    message = header + body
    return b"\x00" + len(message).to_bytes(3, "big") + message


def _smb_enough(data: bytes) -> bool:
    if len(data) < 8:
        return False
    if data[4:8] not in (SMB2_MAGIC, SMB1_MAGIC):
        return True  # keine SMB-Antwort – nicht weiter warten
    expected = 4 + int.from_bytes(data[1:4], "big")
    return len(data) >= min(expected, _SMB_WANT)


def _smb_detail(data: bytes) -> str:
    if data[4:8] == SMB1_MAGIC:
        return "SMB1-Antwort"
    if len(data) >= _SMB_WANT:
        command = int.from_bytes(data[16:18], "little")
        status = int.from_bytes(data[12:16], "little")
        size = int.from_bytes(data[68:70], "little")
        dialect = int.from_bytes(data[72:74], "little")
        if command == 0 and status == 0 and size == 65 and dialect in _SMB_DIALECT_NAMES:
            return f"SMB {_SMB_DIALECT_NAMES[dialect]}"
    return "SMB2-Antwort"


def check_smb(ip: str, port: int, timeout_s: float, *, source_ip: str | None = None) -> CheckResult:
    """SMB2-Aushandlung ohne Anmeldung. ok, wenn die Antwort mit NetBIOS-Kopf und FE/FF 'SMB' beginnt."""
    target, port = _ipv4(ip), _port(port)
    method = f"smb:{port}"
    timeout = _clamp_timeout(timeout_s)
    t0 = time.perf_counter()
    sock, failed = _open(target, port, timeout, source_ip, method)
    if failed is not None:
        return failed
    assert sock is not None
    try:
        deadline = _monotonic() + timeout
        data = b""
        if _send(sock, _smb2_negotiate_request(), deadline) == "ok":
            data, _why = _recv_until(sock, deadline, _smb_enough, SMB_READ_LIMIT)
    finally:
        _close(sock)
    if len(data) >= 8 and data[0] == 0 and data[4:8] in (SMB2_MAGIC, SMB1_MAGIC):
        return CheckResult(ok=True, rtt_ms=_ms_since(t0), detail=_smb_detail(data), method=method)
    return CheckResult(ok=False, detail="Port offen, aber keine SMB-Antwort", method=method)


def run_check(
    kind: str, ip: str, port: int, timeout_s: float, *, path: str = "/", source_ip: str | None = None
) -> CheckResult:
    """Verteiler nach ServiceCheck.kind. Unbekannte Art ⇒ ValueError."""
    if kind == "tcp":
        return check_tcp(ip, port, timeout_s, source_ip=source_ip)
    if kind == "http":
        return check_http(ip, port, timeout_s, tls=False, path=path, source_ip=source_ip)
    if kind == "https":
        return check_http(ip, port, timeout_s, tls=True, path=path, source_ip=source_ip)
    if kind == "smb":
        return check_smb(ip, port, timeout_s, source_ip=source_ip)
    if kind == "ssh":
        return check_ssh(ip, port, timeout_s, source_ip=source_ip)
    raise ValueError(f"Unbekannte Dienstprüfung: {str(kind)[:30]!r} (erlaubt: {', '.join(CHECK_KINDS)}).")


# --- Erreichbarkeit ----------------------------------------------------------------------------


def _ping_result(ping: Callable[[str, int], PingResult], ip: str, timeout_ms: int) -> CheckResult:
    try:
        res = ping(ip, timeout_ms)
    except (OSError, ValueError) as exc:  # die Plattform fängt das selbst ab; doppelt hält besser
        log.debug("Ping %s gescheitert: %r", ip, exc)
        res = None
    if res is None or not bool(getattr(res, "alive", False)):
        return CheckResult(ok=False, detail="keine Ping-Antwort", method="ping")
    rtt = getattr(res, "rtt_ms", None)
    rtt_ms = round(float(rtt), 1) if isinstance(rtt, (int, float)) and not isinstance(rtt, bool) else None
    if rtt_ms is not None and (math.isnan(rtt_ms) or math.isinf(rtt_ms) or rtt_ms < 0):
        rtt_ms = None
    return CheckResult(ok=True, rtt_ms=rtt_ms, detail="Ping-Antwort", method="ping")


def _reach_ports(tcp_ports: object) -> list[int]:
    """Gültige Ports in gegebener Reihenfolge, ohne Doppelte, höchstens 3."""
    out: list[int] = []
    if tcp_ports is None or isinstance(tcp_ports, (str, bytes)):
        return out
    try:
        items = list(tcp_ports)  # type: ignore[call-overload]
    except TypeError:
        return out
    for p in items:
        if _valid_port(p) and p not in out:
            out.append(int(p))
        if len(out) >= REACH_MAX_PORTS:
            break
    return out


def _tcp_reach(ip: str, tcp_ports: list[int], timeout: float, source_ip: str | None) -> CheckResult:
    """TCP-Erreichbarkeit: offen oder abgelehnt heißt „das Gerät hat geantwortet“."""
    reasons: list[str] = []
    for port in tcp_ports:
        t0 = time.perf_counter()
        try:
            sock = connect(ip, port, timeout, source_ip)
        except ConnectionRefusedError:
            # Antwortzeit hier nicht verwertbar: Windows wiederholt den Aufbau nach einem RST (~2 s).
            return CheckResult(ok=True, detail=f"erreichbar (Port {port} geschlossen)", method=f"tcp:{port}")
        except TimeoutError:
            continue
        except OSError as exc:
            log.debug("TCP-Erreichbarkeit %s:%s: %r", ip, port, exc)
            reasons.append(_error_text(exc))
            continue
        rtt = _ms_since(t0)
        _close(sock)
        return CheckResult(ok=True, rtt_ms=rtt, detail=f"erreichbar (Port {port} offen)", method=f"tcp:{port}")
    detail = reasons[0] if reasons else "keine Antwort auf TCP " + ", ".join(str(p) for p in tcp_ports)
    return CheckResult(ok=False, detail=detail, method=f"tcp:{tcp_ports[0]}")


def check_reachability(
    ip: str,
    *,
    method: str,
    ping: Callable[[str, int], PingResult],
    timeout_ms: int,
    tcp_ports: list[int],
    source_ip: str | None = None,
) -> CheckResult:
    """Erreichbarkeit: „ping“ nur Ping, „tcp“ nur TCP (höchstens 3 Ports), „auto“ erst Ping, ohne Antwort TCP.

    ValueError bei unbekannter Methode oder ungültiger IP; SourceAddressGone wird weitergereicht.
    """
    if method not in REACH_METHODS:
        allowed = ", ".join(REACH_METHODS)
        raise ValueError(f"Unbekannter Erreichbarkeitstest: {str(method)[:30]!r} (erlaubt: {allowed}).")
    target = _ipv4(ip)  # vor dem Ping: der Systembefehl darf nie einen Namen auflösen
    timeout_s = _clamp_timeout(timeout_ms / 1000 if isinstance(timeout_ms, (int, float)) else None)
    ping_res: CheckResult | None = None
    if method in ("ping", "auto"):
        ping_res = _ping_result(ping, target, int(round(timeout_s * 1000)))
        if ping_res.ok or method == "ping":
            return ping_res
    candidates = _reach_ports(tcp_ports)
    if not candidates:
        if ping_res is not None:
            return ping_res  # auto ohne bekannten Port: das Ping-Ergebnis zählt
        return CheckResult(ok=False, detail="kein TCP-Port für den Test bekannt", method="tcp")
    result = _tcp_reach(target, candidates, timeout_s, source_ip)
    if ping_res is not None and not result.ok:
        result.detail = f"keine Ping-Antwort, {result.detail}"
    return result


# --- Ports aus dem Inventar --------------------------------------------------------------------


def _open_tcp_ports(device: Device) -> list[int]:
    """Offen gespeicherte TCP-Ports, aufsteigend, ohne Doppelte (Datenbank = nicht vertrauenswürdig)."""
    found: set[int] = set()
    for p in getattr(device, "ports", None) or ():
        port = getattr(p, "port", None)
        proto = getattr(p, "proto", "tcp")
        if _valid_port(port) and isinstance(proto, str) and proto.lower() == "tcp":
            found.add(int(port))  # type: ignore[arg-type]
    return sorted(found)


def fallback_tcp_ports(device: Device) -> list[int]:
    """Höchstens 3 offene TCP-Ports für den Erreichbarkeitstest, bevorzugte Dienste zuerst."""
    open_ports = _open_tcp_ports(device)
    ordered = [p for p in PREFERRED_TCP_PORTS if p in open_ports]
    ordered += [p for p in open_ports if p not in PREFERRED_TCP_PORTS]
    return ordered[:REACH_MAX_PORTS]


def suggest_checks(device: Device) -> list[dict]:
    """Dienstprüfungen aus den offen gespeicherten Ports: [{kind, port, path, label, reason}], nach Port sortiert."""
    out: list[dict] = []
    for port in _open_tcp_ports(device):
        if port == 445:
            kind, label = "smb", f"Dateifreigabe (SMB) {port}"
            reason = f"Port {port} ist offen. Prüft, ob die Dateifreigabe antwortet (SMB-Aushandlung ohne Anmeldung)."
        elif port == 22:
            kind, label = "ssh", f"Fernwartung (SSH) {port}"
            reason = f"Port {port} ist offen. Prüft, ob der SSH-Dienst seine Kennung sendet (ohne Anmeldung)."
        elif port in HTTP_PORTS:
            kind, label = "http", f"Weboberfläche (HTTP) {port}"
            reason = (
                f"Port {port} ist offen. Prüft den Antwortcode der Weboberfläche; 401/403 zählen als erreichbar, "
                "5xx als Ausfall."
            )
        elif port in HTTPS_PORTS:
            kind, label = "https", f"Weboberfläche (HTTPS) {port}"
            reason = (
                f"Port {port} ist offen. Prüft den Antwortcode der verschlüsselten Weboberfläche "
                "(ohne Zertifikatsprüfung)."
            )
        else:
            service = describe_port(port).service
            if service == UNKNOWN_SERVICE:
                continue  # nur bekannte Dienste vorschlagen
            kind, label = "tcp", f"Dienst {service} (TCP) {port}"
            reason = f"Port {port} ist offen ({service}). Prüft, ob der Dienst Verbindungen annimmt."
        out.append({"kind": kind, "port": port, "path": "/", "label": label, "reason": reason})
    return out
