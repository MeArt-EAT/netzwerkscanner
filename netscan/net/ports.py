"""TCP-Port-Scan und feste Regeltabelle für Dienst und Risiko. (Agent ports)

Nur TCP-Connect (keine rohen Pakete), nur IPv4-Literale, kurze Zeitgrenzen (≤ 2 s).
Banner werden nur passiv gelesen: Nach dem Verbindungsaufbau sendet der Scanner nichts.
"""

from __future__ import annotations

import ipaddress
import logging
import math
import re
import socket
import time
from dataclasses import dataclass

from netscan.core.context import ScanContext, parallel_map
from netscan.core.models import PortResult, Risk

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class PortSpec:
    port: int
    service: str
    risk: Risk
    reason: str  # deutsche Begründung / Abhilfe


# Feste Regeltabelle: Dienst, Risikostufe und Begründung (warum diese Stufe + Abhilfe).
# Keine Industrie-Ports (102, 502, 4840) – die gehören in den optionalen Baustein laut Pflichtenheft.
# Pflichtenheft Stufe 3: offenes Telnet oder SMB ⇒ Stufe „hoch“.
PORT_TABLE: dict[int, PortSpec] = {
    spec.port: spec
    for spec in (
        PortSpec(21, "ftp", "high",
                 "FTP überträgt Anmeldung und Dateien unverschlüsselt, Passwörter lassen sich mitlesen. "
                 "Abschalten oder durch SFTP bzw. FTPS ersetzen."),
        PortSpec(22, "ssh", "low",
                 "SSH ist verschlüsselt und für die Fernwartung üblich. "
                 "Nur mit starkem Passwort oder Schlüssel nutzen und Updates einspielen."),
        PortSpec(23, "telnet", "high",
                 "Telnet überträgt Anmeldung und Daten unverschlüsselt. Abschalten und SSH verwenden."),
        PortSpec(25, "smtp", "medium",
                 "Ein Mailserver ist im Heimnetz ungewöhnlich und kann als Spam-Schleuder missbraucht werden. "
                 "Prüfen, ob er gebraucht wird, sonst abschalten."),
        PortSpec(53, "dns", "low",
                 "Namensdienst (DNS), typisch für Router oder Werbeblocker. "
                 "Nur im Heimnetz anbieten, nicht ins Internet freigeben."),
        PortSpec(80, "http", "medium",
                 "Weboberfläche ohne Verschlüsselung – Anmeldedaten gehen im Klartext durchs Netz. "
                 "Wenn möglich HTTPS verwenden und ein starkes Passwort setzen."),
        PortSpec(110, "pop3", "medium",
                 "POP3 überträgt die Anmeldung oft unverschlüsselt. Nur mit TLS (Port 995) nutzen oder abschalten."),
        PortSpec(111, "rpcbind", "medium",
                 "Rpcbind verrät, welche RPC-Dienste wie NFS laufen, und ist ein bekanntes Angriffsziel. "
                 "Abschalten, wenn kein NFS gebraucht wird."),
        PortSpec(135, "msrpc", "medium",
                 "Der Windows-Fernaufruf (RPC) ist auf Windows-PCs üblich, aber ein häufiges Angriffsziel. "
                 "Windows-Firewall eingeschaltet lassen und Updates einspielen."),
        PortSpec(139, "netbios-ssn", "high",
                 "Alte Windows-Dateifreigabe über NetBIOS, oft mit veraltetem SMBv1 und ein häufiges Angriffsziel. "
                 "NetBIOS über TCP/IP abschalten und nur aktuelles SMB nutzen."),
        PortSpec(143, "imap", "medium",
                 "IMAP überträgt die Anmeldung oft unverschlüsselt. Nur mit TLS (Port 993) nutzen oder abschalten."),
        PortSpec(443, "https", "low",
                 "Verschlüsselte Weboberfläche (HTTPS). Firmware aktuell halten und ein starkes Passwort setzen."),
        PortSpec(445, "smb", "high",
                 "Datei- und Druckerfreigabe (SMB) ist ein häufiges Ziel von Würmern und Erpressungstrojanern. "
                 "Nur nötige Freigaben mit Passwort anbieten, SMBv1 abschalten und nie ins Internet freigeben."),
        PortSpec(515, "lpd", "low",
                 "Älterer Druckdienst (LPD), typisch für Drucker und im Heimnetz unbedenklich. "
                 "Abschalten, wenn er nicht gebraucht wird."),
        PortSpec(548, "afp", "medium",
                 "Die Apple-Dateifreigabe (AFP) ist veraltet und wird nicht mehr gepflegt. "
                 "Durch SMB ersetzen und abschalten."),
        PortSpec(554, "rtsp", "medium",
                 "Videostream (RTSP), typisch für Kameras, oft ohne oder mit schwachem Passwort. "
                 "Passwort setzen und nie ins Internet freigeben."),
        PortSpec(631, "ipp", "low",
                 "Druckdienst (IPP), typisch für Drucker und im Heimnetz unbedenklich. "
                 "Firmware des Druckers aktuell halten."),
        PortSpec(873, "rsync", "medium",
                 "Rsync-Dienst für Datensicherungen, manchmal ohne Anmeldung lesbar. "
                 "Zugang mit Passwort schützen und auf bekannte Geräte beschränken."),
        PortSpec(1080, "socks", "high",
                 "Ein offener SOCKS-Proxy leitet fremden Datenverkehr weiter und wird oft von Schadsoftware geöffnet. "
                 "Herkunft prüfen und abschalten."),
        PortSpec(1883, "mqtt", "medium",
                 "MQTT ohne Verschlüsselung, oft ohne Anmeldung – Smart-Home-Nachrichten lassen sich mitlesen "
                 "und fälschen. Anmeldung einschalten und MQTT über TLS (Port 8883) nutzen."),
        PortSpec(2049, "nfs", "medium",
                 "NFS-Freigaben prüfen meist nur die IP-Adresse des zugreifenden Geräts. "
                 "Freigaben auf bestimmte Geräte beschränken."),
        PortSpec(2375, "docker", "critical",
                 "Docker-Steuerung ohne Verschlüsselung und ohne Anmeldung – wer sie erreicht, übernimmt den Rechner "
                 "vollständig. Sofort abschalten oder nur mit TLS (Port 2376) betreiben."),
        PortSpec(3306, "mysql", "medium",
                 "Datenbank (MySQL/MariaDB) direkt im Netz erreichbar. "
                 "Nur an localhost binden oder per Firewall auf nötige Geräte beschränken."),
        PortSpec(3389, "rdp", "medium",
                 "Der Windows-Remotedesktop ist ein beliebtes Ziel für Passwort-Rateangriffe. "
                 "Nur bei Bedarf einschalten, mit Netzwerkebenen-Authentifizierung (NLA) und starkem Passwort."),
        PortSpec(5000, "http", "medium",
                 "Unverschlüsselte Weboberfläche, z. B. Synology DSM – Anmeldedaten gehen im Klartext durchs Netz. "
                 "HTTPS (Port 5001) nutzen und HTTP abschalten oder umleiten."),
        PortSpec(5001, "https", "low",
                 "Verschlüsselte Weboberfläche, z. B. Synology DSM. "
                 "Updates einspielen und die Zwei-Faktor-Anmeldung einschalten."),
        PortSpec(5432, "postgresql", "medium",
                 "Datenbank (PostgreSQL) direkt im Netz erreichbar. "
                 "Nur an localhost binden oder in pg_hba.conf auf nötige Geräte beschränken."),
        PortSpec(5555, "adb", "critical",
                 "Die Android-Debug-Schnittstelle (ADB) über das Netz erlaubt ohne Anmeldung die volle Kontrolle "
                 "über das Gerät. ADB-Debugging über das Netzwerk sofort abschalten."),
        PortSpec(5900, "vnc", "high",
                 "Bildschirmfreigabe (VNC) ist oft unverschlüsselt und nur schwach oder gar nicht geschützt. "
                 "Abschalten oder nur mit starkem Passwort über einen verschlüsselten Tunnel nutzen."),
        PortSpec(6379, "redis", "high",
                 "Redis hat im Standard keine Anmeldung und lässt sich zur Übernahme des Rechners missbrauchen. "
                 "Nur an localhost binden und ein Passwort setzen."),
        PortSpec(8080, "http-alt", "medium",
                 "Zusätzliche unverschlüsselte Weboberfläche oder Proxy. "
                 "Prüfen, welcher Dienst das ist, und wenn möglich HTTPS verwenden."),
        PortSpec(8443, "https-alt", "low",
                 "Zusätzliche verschlüsselte Weboberfläche (HTTPS). "
                 "Firmware aktuell halten und ein starkes Passwort setzen."),
        PortSpec(8883, "mqtt-tls", "low",
                 "Üblicher Port für MQTT über TLS. Eingeordnet nur nach der Portnummer: Manche Broker lauschen "
                 "hier auch im Klartext – ob wirklich verschlüsselt wird, zeigt erst die TLS-Prüfung (Stufe 3). "
                 "Anmeldung mit eigenem Passwort verwenden."),
        PortSpec(9100, "jetdirect", "medium",
                 "Rohdruckdienst (JetDirect) ohne Anmeldung – jedes Gerät im Netz kann drucken und Druckerbefehle "
                 "senden. Wenn möglich abschalten und IPP (Port 631) verwenden."),
        PortSpec(27017, "mongodb", "high",
                 "MongoDB war in vielen Installationen ohne Anmeldung erreichbar, Daten lassen sich auslesen und "
                 "löschen. Anmeldung einschalten und nur an localhost binden."),
    )
}
COMMON_PORTS: list[int] = sorted(PORT_TABLE)  # Standard-Scan, sortiert
DEEP_PORTS: range = range(1, 1025)  # Tiefenscan auf Knopfdruck

UNKNOWN_SERVICE = "unbekannt"
UNKNOWN_REASON = "Dienst unbekannt – prüfen, ob der offene Port gewollt ist."


def describe_port(port: int) -> PortSpec:
    """Eintrag aus PORT_TABLE oder ein Eintrag „unbekannt“ (risk low)."""
    spec = PORT_TABLE.get(port)
    if spec is not None:
        return spec
    return PortSpec(port, UNKNOWN_SERVICE, "low", UNKNOWN_REASON)


BANNER_PORTS: frozenset[int] = frozenset({21, 22, 23, 25})

# Zeitgrenzen und Grenzwerte
MAX_TIMEOUT_S = 2.0  # BAUPLAN §6: jede Netzoperation ≤ 2 s
MIN_TIMEOUT_S = 0.05
BANNER_TIMEOUT_S = 0.8
BANNER_MAX_CHARS = 200
_BANNER_MAX_BYTES = 1024
PROGRESS_PHASE = "Ports"
PROGRESS_STEP = 25  # Fortschritt höchstens alle 25 Ergebnisse (und am Ende)

_BROADCAST = ipaddress.IPv4Address("255.255.255.255")
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_LINE_BREAK = re.compile(r"[\r\n]+")


def _ipv4_target(ip: object) -> str | None:
    """Gibt die Adresse zurück, wenn sie ein gültiges Unicast-IPv4-Literal ist, sonst None."""
    if not isinstance(ip, str):
        return None
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return None
    if addr.is_multicast or addr.is_unspecified or addr == _BROADCAST:
        return None
    return str(addr)


def _valid_port(port: object) -> bool:
    return isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535


def _clamp_timeout(timeout_s: object) -> float:
    try:
        value = float(timeout_s)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return MAX_TIMEOUT_S
    if math.isnan(value):
        return MAX_TIMEOUT_S
    return min(MAX_TIMEOUT_S, max(MIN_TIMEOUT_S, value))


def _strip_telnet_iac(data: bytes) -> bytes:
    """Entfernt Telnet-Steuerfolgen (IAC …), damit nur der lesbare Text bleibt."""
    out = bytearray()
    i, n = 0, len(data)
    while i < n:
        b = data[i]
        if b != 0xFF:
            out.append(b)
            i += 1
            continue
        cmd = data[i + 1] if i + 1 < n else None
        if cmd == 0xFF:  # maskiertes Byte 255
            out.append(0xFF)
            i += 2
        elif cmd in (0xFB, 0xFC, 0xFD, 0xFE):  # WILL/WONT/DO/DONT + Option
            i += 3
        elif cmd == 0xFA:  # Unterverhandlung bis IAC SE
            end = data.find(b"\xff\xf0", i + 2)
            i = n if end < 0 else end + 2
        else:
            i += 2
    return bytes(out)


def _clean_banner(data: bytes) -> str | None:
    """Erste nicht leere Zeile, nur druckbare Zeichen, höchstens BANNER_MAX_CHARS Zeichen."""
    if not data:
        return None
    text = _strip_telnet_iac(data).decode("utf-8", errors="replace")
    text = _ANSI_ESCAPE.sub("", text)
    for line in _LINE_BREAK.split(text):
        printable = "".join(ch if ch.isprintable() and ch != "�" else " " for ch in line)
        cleaned = " ".join(printable.split())
        if cleaned:
            return cleaned[:BANNER_MAX_CHARS]
    return None


def _has_complete_line(data: bytes) -> bool:
    lines = _LINE_BREAK.split(_strip_telnet_iac(data).decode("utf-8", errors="replace"))
    return len(lines) > 1 and any(line.strip() for line in lines[:-1])


def _read_banner(sock: socket.socket, timeout_s: float) -> str | None:
    """Liest passiv, was der Dienst von sich aus schickt (nichts senden). Fehler zählen nicht."""
    deadline = time.monotonic() + timeout_s
    data = b""
    try:
        while len(data) < _BANNER_MAX_BYTES:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            chunk = sock.recv(_BANNER_MAX_BYTES - len(data))
            if not chunk:
                break
            data += chunk
            if _has_complete_line(data):
                break
    except OSError:  # Zeitgrenze oder Reset: was bis dahin kam, zählt
        pass
    return _clean_banner(data)


class SourceAddressGone(RuntimeError):
    """Die Absenderadresse (IPv4 des Adapters) gibt es nicht mehr – z. B. nach einem Netzwechsel.
    Dann wird nichts gesendet; scan_ports bricht ab, statt alle Ports als „geschlossen“ zu melden."""


def probe_port(
    ip: str, port: int, timeout_s: float, read_banner: bool = False, source_ip: str | None = None
) -> tuple[bool, str | None]:
    """Ein TCP-Connect-Versuch. (offen, Banner). Banner nur passiv lesen (nichts senden), höchstens
    200 Zeichen, kurze Zeitgrenze. Tests ersetzen diese Funktion (Portübersetzung auf Sim-Ports) –
    scan_ports muss sie daher über den Modulnamen aufrufen, nicht über eine lokale Kopie.

    source_ip: an diese Adresse (IPv4 des Scan-Adapters) binden. Dann geht die Verbindung nur über diesen
    Adapter hinaus; ist die Adresse nach einem Netzwechsel weg, scheitert das Binden (SourceAddressGone),
    statt über die Standardroute in ein anderes Netz zu senden."""
    target = _ipv4_target(ip)
    if target is None or not _valid_port(port):
        return (False, None)
    timeout = _clamp_timeout(timeout_s)
    sock: socket.socket | None = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if source_ip is not None:
            try:
                sock.bind((source_ip, 0))
            except OSError as exc:
                raise SourceAddressGone(f"Absenderadresse {source_ip} nicht verfügbar: {exc}") from exc
        if sock.connect_ex((target, port)) != 0:
            return (False, None)
        banner = _read_banner(sock, min(BANNER_TIMEOUT_S, timeout)) if read_banner else None
        return (True, banner)
    except (OSError, ValueError, OverflowError, TypeError):
        # Absichtlich nicht „except Exception“: LanTrafficError der Test-Netzsperre soll durchschlagen.
        return (False, None)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _plan_pairs(ctx: ScanContext, targets: dict[str, list[int]]) -> list[tuple[str, int]]:
    """Alle (ip, port)-Paare, reihum über die Geräte verteilt (schont das einzelne Gerät)."""
    queues: list[tuple[str, list[int]]] = []
    for ip, ports in targets.items():
        if _ipv4_target(ip) is None:
            ctx.log(f"Port-Scan: {ip!r} ist keine gültige IPv4-Adresse und wird übersprungen.", "warning")
            continue
        valid = sorted({p for p in (ports or ()) if _valid_port(p)})
        if valid:
            queues.append((ip, valid))
    longest = max((len(ports) for _, ports in queues), default=0)
    pairs: list[tuple[str, int]] = []
    for i in range(longest):
        for ip, ports in queues:
            if i < len(ports):
                pairs.append((ip, ports[i]))
    return pairs


def scan_ports(
    ctx: ScanContext, targets: dict[str, list[int]], *, source_ip: str | None = None
) -> dict[str, list[PortResult]]:
    """TCP-Connect-Scan aller (ip, port)-Paare in einem gemeinsamen Pool (parallel_map,
    settings.port_workers, settings.port_timeout_ms, gedrosselt) über probe_port(). Banner nur für
    BANNER_PORTS. Rückgabe {ip: [offene Ports, sortiert]} für jede ip aus targets.

    source_ip: Absenderadresse (IPv4 des Scan-Adapters), siehe probe_port. Verschwindet sie während des
    Scans, endet scan_ports mit SourceAddressGone – nie mit lauter „geschlossenen“ Ports."""
    ctx.check_cancel()
    results: dict[str, list[PortResult]] = {ip: [] for ip in targets}
    pairs = _plan_pairs(ctx, targets)
    if not pairs:
        return results

    timeout_s = _clamp_timeout(ctx.settings.port_timeout_ms / 1000)
    workers = max(1, int(ctx.settings.port_workers))
    reported = 0
    gone: list[SourceAddressGone] = []

    def work(pair: tuple[str, int]) -> tuple[bool, str | None] | None:
        if gone:
            return None  # Absenderadresse weg: nichts mehr versuchen
        ip, port = pair
        try:
            # Aufruf über den Modulnamen (globale Suche zur Laufzeit), damit Tests probe_port ersetzen können.
            if source_ip is None:
                return probe_port(ip, port, timeout_s, port in BANNER_PORTS)
            return probe_port(ip, port, timeout_s, port in BANNER_PORTS, source_ip=source_ip)
        except SourceAddressGone as exc:
            gone.append(exc)
            return None

    def on_result(_pair: tuple[str, int], _res: object, done: int, total: int) -> None:
        nonlocal reported
        if done - reported >= PROGRESS_STEP or done == total:
            reported = done
            ctx.progress(PROGRESS_PHASE, done, total, f"{done} von {total} Port-Prüfungen")

    outcome = parallel_map(ctx, work, pairs, workers, rate=True, on_result=on_result)
    if gone:
        raise gone[0]
    for (ip, port), res in outcome:
        if not res:
            continue
        is_open, banner = res
        if not is_open:
            continue
        spec = describe_port(port)
        results[ip].append(
            PortResult(port=port, proto="tcp", service=spec.service, risk=spec.risk, reason=spec.reason, banner=banner)
        )
    for found in results.values():
        found.sort(key=lambda p: p.port)
    log.debug("Port-Scan: %d Prüfungen, %d offen", len(pairs), sum(len(v) for v in results.values()))
    return results
