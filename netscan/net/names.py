"""Hostnamen: DNS-Rückwärtsauflösung, NetBIOS (NBSTAT, UDP 137) und mDNS (zeroconf). (Agent identify)"""

from __future__ import annotations

import functools
import ipaddress
import logging
import secrets
import socket
import struct
import threading
import time
from collections.abc import Callable, Iterable
from typing import Any

from netscan.core.context import ScanCancelled, ScanContext, parallel_map
from netscan.core.models import Adapter, NameInfo

log = logging.getLogger(__name__)

# resolver(ip) -> Name oder None; Standard: socket.gethostbyaddr mit Zeitgrenze
Resolver = Callable[[str], str | None]
# mdns_browser(adapter, timeout_s) -> {ip: (hostname | None, [diensttypen])}; Standard: zeroconf
MdnsBrowser = Callable[[Adapter, float], dict[str, tuple[str | None, list[str]]]]

_PHASE = "Namen"
_DNS_MAX_WORKERS = 128
_NAME_MAX_LEN = 253  # längster gültiger DNS-Name

# NetBIOS (RFC 1001/1002)
_NB_QTYPE_NBSTAT = 0x0021
_NB_QCLASS_IN = 0x0001
_NB_SUFFIX_WORKSTATION = 0x00
_NB_FLAG_GROUP = 0x8000
_NB_ENTRY_LEN = 18  # 15 Byte Name + 1 Byte Suffix + 2 Byte Flags
_NB_RECV_BUFFER = 256 * 1024
_NB_MAX_LATE_READS = 4096  # Obergrenze beim Leerlesen nach Ablauf der Zeit
_POLL_S = 0.1

# mDNS
_MDNS_SERVICE_NAMES = (
    "_http", "_https", "_ipp", "_ipps", "_printer", "_pdl-datastream", "_scanner", "_smb",
    "_afpovertcp", "_ssh", "_sftp-ssh", "_workstation", "_device-info", "_airplay", "_raop",
    "_googlecast", "_spotify-connect", "_hap", "_homekit", "_sonos", "_amzn-wplay", "_matter",
    "_companion-link",
)  # fmt: skip
_MDNS_SERVICE_TYPES = tuple(f"{name}._tcp.local." for name in _MDNS_SERVICE_NAMES)
_MDNS_RESOLVE_BUDGET_S = 1.0  # Gesamtzeit für das Auflösen der gefundenen Dienste
_MDNS_RESOLVE_TIMEOUT_MS = 300  # je Dienst
_MDNS_STEP_S = 0.1  # Schrittweite beim abbrechbaren Warten

MdnsRecord = tuple[str, str | None, Iterable[str]]  # (Diensttyp, Server, IPv4-Adressen)


# --- kleine Helfer -----------------------------------------------------------------------------


def _is_ipv4(text: str) -> bool:
    try:
        ipaddress.IPv4Address(text)
    except ValueError:
        return False
    return True


def _clean_hostname(name: object, ip: str) -> str | None:
    """Bereinigt einen Rechnernamen: Leerraum und Schlusspunkt weg; leer oder gleich der IP ⇒ None."""
    if not isinstance(name, str):
        return None
    cleaned = name.strip().rstrip(".").strip()
    if not cleaned or cleaned.lower() == ip.lower():
        return None
    return cleaned[:_NAME_MAX_LEN]


# --- DNS rückwärts -----------------------------------------------------------------------------


def _system_resolver(ip: str) -> str | None:
    """Standard-Resolver: socket.gethostbyaddr (hat selbst keine Zeitgrenze – die setzt der Aufrufer)."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):  # herror und gaierror sind OSError
        return None


def _lookup_within(ctx: ScanContext, resolver: Resolver, ip: str, deadline: float) -> str | None:
    """Ruft den Resolver in einem Daemon-Thread auf und wartet höchstens bis deadline.

    gethostbyaddr lässt sich nicht unterbrechen; bei Zeitüberschreitung oder Abbruch bleibt der Thread
    als Daemon zurück und wird verworfen.
    """
    if time.monotonic() >= deadline or ctx.cancel.cancelled:
        return None
    box: list[object] = []
    done = threading.Event()

    def work() -> None:
        try:
            box.append(resolver(ip))
        except Exception:  # noqa: BLE001 – ein kaputter Resolver darf den Scan nicht stoppen
            log.debug("Rückwärtsauflösung für %s fehlgeschlagen", ip, exc_info=True)
        finally:
            done.set()

    threading.Thread(target=work, name=f"names-dns-{ip}", daemon=True).start()
    while not done.is_set():
        remaining = deadline - time.monotonic()
        if remaining <= 0 or ctx.cancel.cancelled:
            return None
        done.wait(min(remaining, _POLL_S))
    return _clean_hostname(box[0], ip) if box else None


def _reverse_lookups(
    ctx: ScanContext, ips: list[str], resolver: Resolver, deadline: float, progress_total: int
) -> dict[str, str | None]:
    """Rückwärtsauflösung für alle ips, parallel und gedrosselt; was bis deadline fehlt, bleibt None."""
    count = len(ips)
    step = max(1, count // 10)

    def on_result(_ip: str, _name: str | None, done: int, total: int) -> None:
        if done == total or done % step == 0:
            ctx.progress(_PHASE, done, progress_total, f"DNS rückwärts: {done} von {total}")

    pairs = parallel_map(
        ctx,
        lambda ip: _lookup_within(ctx, resolver, ip, deadline),
        ips,
        min(count, _DNS_MAX_WORKERS),
        on_result=on_result,
    )
    return {ip: name for ip, name in pairs}


# --- NetBIOS (NBSTAT) --------------------------------------------------------------------------


def _encode_netbios_name(raw: bytes) -> bytes:
    """First-Level-Encoding (RFC 1001): jedes Byte als zwei Buchstaben 'A'..'P'."""
    out = bytearray()
    for byte in raw:
        out.append(0x41 + (byte >> 4))
        out.append(0x41 + (byte & 0x0F))
    return bytes(out)


def _build_nbstat_query(transaction_id: int) -> bytes:
    """NBSTAT-Abfrage nach dem Platzhalternamen "*" (16 Byte, mit 0x00 aufgefüllt)."""
    header = struct.pack(">HHHHHH", transaction_id & 0xFFFF, 0, 1, 0, 0, 0)
    wildcard = b"*" + b"\x00" * 15
    question = b"\x20" + _encode_netbios_name(wildcard) + b"\x00" + struct.pack(">HH", _NB_QTYPE_NBSTAT, _NB_QCLASS_IN)
    return header + question


def _skip_dns_name(data: bytes, pos: int) -> int | None:
    """Springt über einen Namen (Labels oder Zeiger) und gibt die Position danach zurück; None bei Unsinn."""
    for _ in range(128):
        if pos >= len(data):
            return None
        length = data[pos]
        if length == 0:
            return pos + 1
        if length & 0xC0 == 0xC0:  # Kompressionszeiger (2 Byte)
            return pos + 2 if pos + 2 <= len(data) else None
        if length & 0xC0:  # reservierte Label-Typen
            return None
        pos += 1 + length
    return None


def _decode_netbios_name(raw: bytes) -> str | None:
    """15 Byte Name (mit Leerzeichen oder 0x00 aufgefüllt) ⇒ Text ohne Auffüllung; Unsinn ⇒ None."""
    text = raw.decode("cp850", errors="replace").strip(" \x00")
    if not text or any(ord(ch) < 0x20 or ch == "�" for ch in text):
        return None
    return text


def _parse_nbstat_response(data: bytes, transaction_id: int | None = None) -> str | None:
    """Liest eine NBSTAT-Antwort und gibt den ersten Einzelnamen mit Suffix 0x00 zurück (sonst None).

    Prüft alle Längen; kaputte oder abgeschnittene Antworten ergeben None, nie eine Ausnahme.
    """
    if len(data) < 12:
        return None
    tid, flags, qdcount, ancount, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    if transaction_id is not None and tid != transaction_id:
        return None
    if not flags & 0x8000 or flags & 0x000F:  # keine Antwort oder Fehlercode
        return None
    if ancount < 1 or qdcount > 4:
        return None
    pos = 12
    for _ in range(qdcount):  # manche Geräte schicken die Frage mit zurück
        nxt = _skip_dns_name(data, pos)
        if nxt is None or nxt + 4 > len(data):
            return None
        pos = nxt + 4
    nxt = _skip_dns_name(data, pos)  # Name im Antwortsatz: voll oder komprimiert
    if nxt is None or nxt + 10 > len(data):
        return None
    rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", data[nxt : nxt + 10])
    if rtype != _NB_QTYPE_NBSTAT:
        return None
    rdata = data[nxt + 10 : nxt + 10 + rdlength]
    if not rdata:
        return None
    for index in range(rdata[0]):
        entry = rdata[1 + index * _NB_ENTRY_LEN : 1 + (index + 1) * _NB_ENTRY_LEN]
        if len(entry) < _NB_ENTRY_LEN:
            break
        suffix = entry[15]
        (name_flags,) = struct.unpack(">H", entry[16:18])
        if suffix != _NB_SUFFIX_WORKSTATION or name_flags & _NB_FLAG_GROUP:
            continue
        name = _decode_netbios_name(entry[:15])
        if name:
            return name
    return None


class _NetbiosProbe:
    """Ein UDP-Socket für alle NBSTAT-Abfragen (Unicast, gedrosselt); sammelt die Antworten.

    Zuerst send_queries(), danach beliebig lange etwas anderes tun (Antworten stauen sich im
    Socket-Puffer) und am Ende collect(). Ein Fehler beim Socket ergibt nur ein leeres Ergebnis.
    """

    def __init__(self, ctx: ScanContext, adapter: Adapter, ips: Iterable[str], port: int) -> None:
        self._ctx = ctx
        self._adapter = adapter
        self._port = port
        self._order = [ip for ip in ips if _is_ipv4(ip)]
        self._targets = set(self._order)
        self._tid = secrets.randbits(16)
        self._sock: socket.socket | None = None
        self.names: dict[str, str] = {}
        self.answered: set[str] = set()

    def __enter__(self) -> _NetbiosProbe:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        sock, self._sock = self._sock, None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    # --- Senden ---
    def send_queries(self) -> None:
        if not self._order:
            return
        ctx = self._ctx
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except OSError as exc:
            ctx.log(f"NetBIOS-Abfrage nicht möglich ({exc}).", "warning")
            return
        self._sock = sock
        try:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _NB_RECV_BUFFER)
            except OSError:
                pass  # kleinerer Puffer genügt meist
            sock.bind((self._adapter.ipv4, 0))
        except OSError as exc:
            ctx.log(f"NetBIOS-Abfrage nicht möglich ({exc}).", "warning")
            self.close()
            return
        query = _build_nbstat_query(self._tid)
        for ip in self._order:
            ctx.check_cancel()
            if ctx.rate is not None:
                ctx.rate.acquire()
            for _attempt in range(2):
                try:
                    sock.sendto(query, (ip, self._port))
                    break
                except ConnectionResetError:  # Windows meldet hier eine frühere ICMP-Antwort; nochmal
                    continue
                except OSError:
                    log.debug("NetBIOS: Senden an %s fehlgeschlagen", ip, exc_info=True)
                    break
            for _ in range(64):  # zwischendurch leeren, damit der Puffer nicht überläuft
                if not self._receive_once(0.0):
                    break

    # --- Empfangen ---
    def _receive_once(self, timeout: float) -> bool:
        """Liest höchstens ein Datagramm. True, wenn etwas (auch ein Fehlerzeichen) verarbeitet wurde."""
        sock = self._sock
        if sock is None:
            return False
        try:
            sock.settimeout(timeout)
            data, addr = sock.recvfrom(2048)
        except (TimeoutError, BlockingIOError, InterruptedError):
            return False
        except ConnectionResetError:  # Windows: ICMP „Port nicht erreichbar“ einer früheren Sendung
            return True
        except OSError:
            log.debug("NetBIOS: Empfang beendet", exc_info=True)
            self.close()
            return False
        self._handle(data, addr)
        return True

    def _handle(self, data: bytes, addr: tuple[Any, ...]) -> None:
        ip = addr[0]
        if ip not in self._targets:  # nur Antworten von angefragten Adressen werten
            return
        if len(data) < 2 or struct.unpack(">H", data[:2])[0] != self._tid:
            return
        self.answered.add(ip)
        if ip in self.names:
            return
        name = _parse_nbstat_response(data, self._tid)
        if name:
            self.names[ip] = name

    def collect(self, deadline: float) -> None:
        """Sammelt Antworten bis deadline oder bis alle Angefragten geantwortet haben.

        Nach Ablauf der Zeit wird der Socket-Puffer noch leer gelesen (dort liegt, was während der
        DNS-Phase eingetroffen ist), aber nicht mehr gewartet.
        """
        late_reads = 0
        while self._sock is not None and not self.answered >= self._targets:
            self._ctx.check_cancel()
            remaining = deadline - time.monotonic()
            if remaining > 0:
                self._receive_once(min(_POLL_S, remaining))
                continue
            late_reads += 1
            if late_reads > _NB_MAX_LATE_READS or not self._receive_once(0.0):
                break


# --- mDNS --------------------------------------------------------------------------------------


def _short_service_type(service_type: str) -> str:
    """"_ipp._tcp.local." ⇒ "_ipp._tcp"."""
    text = service_type.strip().rstrip(".")
    return text.removesuffix(".local")


def _mdns_records_to_result(records: Iterable[MdnsRecord]) -> dict[str, tuple[str | None, list[str]]]:
    """Reine Umwandlung: (Diensttyp, Server, IPv4-Adressen)-Einträge ⇒ {ip: (Hostname, [Dienste])}.

    Der Hostname verliert den Schlusspunkt ("nas.local." ⇒ "nas.local"); der erste Server einer IP gilt.
    Die Dienste erscheinen in Kurzform ("_ipp._tcp"), ohne Doppelte und sortiert.
    """
    hostnames: dict[str, str | None] = {}
    services: dict[str, set[str]] = {}
    for service_type, server, addresses in records:
        short = _short_service_type(service_type) if isinstance(service_type, str) else ""
        host = server.strip().rstrip(".") if isinstance(server, str) else ""
        for address in addresses:
            if not isinstance(address, str) or not _is_ipv4(address):
                continue
            services.setdefault(address, set())
            hostnames.setdefault(address, None)
            if short:
                services[address].add(short)
            if host and hostnames[address] is None:
                hostnames[address] = _clean_hostname(host, address)
    return {ip: (hostnames[ip], sorted(services[ip])) for ip in services}


def _zeroconf_browse(ctx: ScanContext, adapter: Adapter, timeout_s: float) -> dict[str, tuple[str | None, list[str]]]:
    """Standard-mDNS-Suche mit zeroconf auf dem Adapter: sammelt timeout_s lang, löst die Dienste auf."""
    import zeroconf as zc_mod  # verzögert: der Import ist teuer und für andere Teile unnötig

    found: dict[tuple[str, str], None] = {}  # geordnete Menge (Diensttyp, Dienstname)
    lock = threading.Lock()

    def on_change(zeroconf: Any, service_type: str, name: str, state_change: Any) -> None:
        # zeroconf ruft die Handler mit Schlüsselwortargumenten auf – Namen nicht ändern
        if state_change == zc_mod.ServiceStateChange.Removed:
            return
        with lock:
            found[(service_type, name)] = None

    zc = zc_mod.Zeroconf(interfaces=[adapter.ipv4], ip_version=zc_mod.IPVersion.V4Only)
    try:
        browser = zc_mod.ServiceBrowser(zc, list(_MDNS_SERVICE_TYPES), handlers=[on_change])
        try:
            deadline = time.monotonic() + max(0.0, timeout_s)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                ctx.sleep(min(_MDNS_STEP_S, remaining))
            with lock:
                snapshot = list(found)
            records = _resolve_services(ctx, zc_mod, zc, snapshot)
        finally:
            browser.cancel()
    finally:
        zc.close()
    return _mdns_records_to_result(records)


def _resolve_services(ctx: ScanContext, zc_mod: Any, zc: Any, services: list[tuple[str, str]]) -> list[MdnsRecord]:
    """Holt Server und IPv4-Adressen der gefundenen Dienste (erst aus dem Zwischenspeicher, sonst kurz anfragen)."""
    records: list[MdnsRecord] = []
    deadline = time.monotonic() + _MDNS_RESOLVE_BUDGET_S
    for service_type, name in services:
        ctx.check_cancel()
        if time.monotonic() >= deadline:
            break
        try:
            info = zc_mod.ServiceInfo(service_type, name)
            if not info.load_from_cache(zc) and not info.request(zc, _MDNS_RESOLVE_TIMEOUT_MS):
                continue
            addresses = info.parsed_addresses(zc_mod.IPVersion.V4Only)
            records.append((service_type, info.server, addresses))
        except ScanCancelled:
            raise
        except Exception:  # noqa: BLE001 – ein Dienst, der sich nicht auflösen lässt, wird übersprungen
            log.debug("mDNS: %s nicht auflösbar", name, exc_info=True)
    return records


def _browse_mdns(
    ctx: ScanContext, adapter: Adapter, browser: MdnsBrowser | None, timeout_s: float
) -> dict[str, tuple[str | None, list[str]]]:
    """Führt den mDNS-Browser aus; jeder Fehler ⇒ leeres Ergebnis und eine Warnung im Protokoll."""
    ctx.check_cancel()
    run = browser if browser is not None else functools.partial(_zeroconf_browse, ctx)
    try:
        raw = run(adapter, timeout_s)
        if not isinstance(raw, dict):
            raise TypeError(f"Ergebnis ist kein Wörterbuch, sondern {type(raw).__name__}")
        cleaned: dict[str, tuple[str | None, list[str]]] = {}
        for ip, value in raw.items():
            host, services = value
            cleaned[str(ip)] = (
                _clean_hostname(host, str(ip)) if host else None,
                list(dict.fromkeys(str(s) for s in services if s)),
            )
    except ScanCancelled:
        raise
    except Exception as exc:  # noqa: BLE001 – mDNS ist ein Zusatz und darf den Scan nie stoppen
        log.debug("mDNS-Suche fehlgeschlagen", exc_info=True)
        ctx.log(f"mDNS-Suche fehlgeschlagen ({type(exc).__name__}: {exc}) – weiter ohne mDNS-Namen.", "warning")
        return {}
    ctx.check_cancel()
    return cleaned


# --- Hauptfunktion -----------------------------------------------------------------------------


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
    jeder mit Zeitgrenze (settings.names_timeout_s, settings.mdns_timeout_s).

    DNS rückwärts und NetBIOS teilen sich names_timeout_s: die NetBIOS-Abfragen gehen zuerst hinaus, die
    Antworten laufen während der DNS-Phase ein und werden danach bis zur Zeitgrenze eingesammelt. Danach
    folgt mDNS (mdns_timeout_s, dazu höchstens ~1 s zum Auflösen der Dienste).
    """
    unique = list(dict.fromkeys(ips))
    result = {ip: NameInfo() for ip in unique}
    if not unique:
        return result
    settings = ctx.settings
    count = len(unique)
    total = count + 2  # eine Einheit je IP (DNS), dazu NetBIOS und mDNS
    ctx.check_cancel()
    ctx.progress(_PHASE, 0, total, "Namen werden abgefragt …")
    names_deadline = time.monotonic() + max(0.0, float(settings.names_timeout_s))

    with _NetbiosProbe(ctx, adapter, unique, netbios_port) as netbios:
        netbios.send_queries()
        dns = _reverse_lookups(ctx, unique, resolver if resolver is not None else _system_resolver, names_deadline, total)
        ctx.progress(_PHASE, count, total, "NetBIOS-Antworten werden gesammelt …")
        netbios.collect(names_deadline)
        netbios_names = dict(netbios.names)

    ctx.progress(_PHASE, count + 1, total, "mDNS-Suche …")
    mdns = _browse_mdns(ctx, adapter, mdns_browser, float(settings.mdns_timeout_s))

    for ip, info in result.items():
        info.dns = dns.get(ip)
        info.netbios = netbios_names.get(ip)
        if ip in mdns:
            info.mdns, info.mdns_services = mdns[ip][0], list(mdns[ip][1])

    named = sum(1 for info in result.values() if info.best())
    ctx.progress(_PHASE, total, total, f"{named} von {count} Geräten mit Namen")
    ctx.log(
        f"Namen: {named} von {count} Geräten benannt "
        f"(DNS {sum(1 for i in result.values() if i.dns)}, "
        f"NetBIOS {sum(1 for i in result.values() if i.netbios)}, "
        f"mDNS {sum(1 for i in result.values() if i.mdns)})."
    )
    return result
