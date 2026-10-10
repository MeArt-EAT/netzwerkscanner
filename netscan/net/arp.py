"""ARP-Scan über Scapy/Npcap. Scapy NUR hier und NUR verzögert importieren. (Agent discovery)"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from netscan.core.context import ScanContext
from netscan.core.models import Adapter, normalize_mac

log = logging.getLogger(__name__)

# sender(adapter, ips, timeout_s) -> {ip: mac}; Standard: Scapy srp() über Npcap
ArpSender = Callable[[Adapter, list[str], float], dict[str, str]]

# Blockgröße: so viele Adressen, wie bei settings.rate_pps in BLOCK_SEND_S gesendet werden (höchstens
# MAX_BLOCK_SIZE). Scapy sendet den Block mit dem Paketabstand 1/rate_pps (srp inter) – also nie mehr als
# rate_pps Anfragen je Sekunde und kein Stoß. Jeder srp-Aufruf wartet nach dem letzten Paket das volle Timeout;
# wenige große Blöcke statt vieler 32er-Blöcke sparen im /24 rund zehn Sekunden.
MAX_BLOCK_SIZE = 256
BLOCK_SEND_S = 1.0  # Sendedauer je Block; mit Timeout ≤ 2 s bleibt der Abbruch unter 5 s
RETRY_TIMEOUT_FACTOR = 0.5  # Wiederholungen warten kürzer: wer da ist, antwortet in Millisekunden
MIN_RETRY_TIMEOUT_S = 0.3
PHASE = "Gerätesuche (ARP)"
_BROADCAST = "ff:ff:ff:ff:ff:ff"
_MAX_TIMEOUT_S = 2.0  # harte Obergrenze je Netzoperation (Bauplan: ≤ 2 s)


def block_size(rate_pps: float) -> int:
    """Adressen je srp-Aufruf bei rate_pps Paketen pro Sekunde (mindestens 1, höchstens MAX_BLOCK_SIZE)."""
    try:
        rate = float(rate_pps)
    except (TypeError, ValueError):
        rate = 1.0
    return max(1, min(MAX_BLOCK_SIZE, int(max(1.0, rate) * BLOCK_SEND_S)))


class ArpUnavailable(RuntimeError):
    """Scapy, Npcap oder die nötigen Rechte fehlen – die Pipeline fällt auf Ping + ARP-Cache zurück."""


# --- Status ------------------------------------------------------------------

_status_lock = threading.Lock()
_status_cache: tuple[bool, str] | None = None


def _is_windows() -> bool:
    return sys.platform == "win32"


def _npcap_dll() -> Path:
    """Ort der Npcap-Bibliothek (C:\\Windows\\System32\\Npcap\\wpcap.dll)."""
    root = os.environ.get("SystemRoot") or os.environ.get("windir") or r"C:\Windows"
    return Path(root) / "System32" / "Npcap" / "wpcap.dll"


def _check_scapy() -> tuple[bool, str]:
    """Prüft Npcap (nur Windows) und den Import von Scapy. Sendet nichts."""
    if _is_windows() and not _npcap_dll().is_file():
        return False, "Npcap ist nicht installiert (wpcap.dll fehlt). Ohne Npcap gibt es nur Ping und den ARP-Cache des Systems."
    try:
        import scapy
        from scapy.all import conf  # noqa: F401 – vollständiger Import, hier dauert er einige Sekunden
    except Exception as exc:  # noqa: BLE001 – ImportError, OSError (DLL), Scapy-Fehler
        return False, f"Scapy lässt sich nicht laden: {_short(exc)}"
    version = getattr(scapy, "__version__", "")
    label = f"Scapy {version}".strip()
    if _is_windows():
        return True, f"{label} und Npcap sind bereit."
    return True, f"{label} ist bereit."


def scapy_status(*, refresh: bool = False) -> tuple[bool, str]:
    """(verfügbar, Begründung) – prüft Import von Scapy und unter Windows Npcap, ohne Pakete zu senden.
    Das Ergebnis wird zwischengespeichert (der Import von Scapy ist langsam); refresh=True prüft neu."""
    global _status_cache
    with _status_lock:
        if _status_cache is None or refresh:
            _status_cache = _check_scapy()
        return _status_cache


def _short(exc: BaseException, limit: int = 160) -> str:
    text = " ".join(str(exc).split()) or type(exc).__name__
    return text if len(text) <= limit else text[: limit - 1] + "…"


# --- Standard-Sender (Scapy) -------------------------------------------------


def _iface_has_ip(iface: Any, ip: str) -> bool:
    if getattr(iface, "ip", None) == ip:
        return True
    ips = getattr(iface, "ips", None)
    if hasattr(ips, "get"):
        return ip in (ips.get(4) or [])
    return False


def _find_iface(conf: Any, adapter: Adapter) -> Any | None:
    """Sucht die Scapy-Schnittstelle zum Adapter: erst über die IPv4-Adresse, dann über die MAC."""
    ifaces = getattr(conf, "ifaces", None)
    if ifaces is None:
        return None
    candidates = list(ifaces.values()) if hasattr(ifaces, "values") else list(ifaces)
    if adapter.ipv4:
        for iface in candidates:
            if _iface_has_ip(iface, adapter.ipv4):
                return iface
    if adapter.mac:
        try:
            wanted = normalize_mac(adapter.mac)
        except ValueError:
            return None
        for iface in candidates:
            try:
                if normalize_mac(getattr(iface, "mac", None) or "") == wanted:
                    return iface
            except ValueError:
                continue
    return None


def _refresh_scapy() -> None:
    """Schnittstellen und Routen von Scapy neu einlesen (nur lesend, sendet nichts).

    Scapy liest beides sonst nur beim ersten Import: Ein später eingesteckter USB-LAN-Adapter fehlte dann,
    und nach einem Netzwechsel stimmten die gemerkten Adressen nicht mehr.
    """
    try:
        from scapy.all import conf
    except Exception:  # noqa: BLE001 – ohne Scapy meldet der Sender ArpUnavailable
        return
    for what, refresh in (("Schnittstellen", "ifaces"), ("Routen", "route")):
        try:
            target = getattr(conf, refresh, None)
            method = getattr(target, "reload" if refresh == "ifaces" else "resync", None)
            if callable(method):
                method()
        except AssertionError:
            raise
        except Exception:  # noqa: BLE001 – dann eben mit dem alten Stand
            log.debug("Scapy: %s nicht neu lesbar", what, exc_info=True)


def _scapy_sender(adapter: Adapter, ips: list[str], timeout_s: float, inter: float = 0.0) -> dict[str, str]:
    """Standard-Sender: ARP-Anfragen per Broadcast über Scapy/Npcap. Wirft ArpUnavailable bei jedem Mangel.

    inter: Abstand zwischen zwei Paketen in Sekunden (1/rate_pps), damit der Block gleichmäßig verteilt
    hinausgeht. Absender-IP und -MAC stehen ausdrücklich im Paket (Adapter des Scans) und kommen nicht aus
    Scapys zwischengespeicherter Routentabelle.
    """
    # Verzögerter Import: ohne Npcap muss das restliche Programm trotzdem starten.
    try:
        from scapy.all import ARP, Ether, conf, srp
    except Exception as exc:  # noqa: BLE001
        raise ArpUnavailable(f"Scapy oder Npcap konnte nicht geladen werden: {_short(exc)}") from exc
    if not ips:
        return {}
    try:
        iface = _find_iface(conf, adapter)
    except AssertionError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise ArpUnavailable(f"Die Schnittstellenliste von Scapy ist nicht lesbar: {_short(exc)}") from exc
    if iface is None:
        raise ArpUnavailable(f"Die Netzwerkschnittstelle „{adapter.name}“ ({adapter.ipv4}) wurde von Scapy/Npcap nicht gefunden.")
    timeout = min(max(float(timeout_s), 0.1), _MAX_TIMEOUT_S)
    gap = min(max(float(inter or 0.0), 0.0), 1.0)
    hwsrc: str | None = None
    for candidate in (getattr(iface, "mac", None), adapter.mac):
        try:
            hwsrc = normalize_mac(candidate or "")
            break
        except ValueError:
            continue
    ether_fields: dict[str, str] = {"dst": _BROADCAST}
    arp_fields: dict[str, Any] = {"pdst": list(ips)}
    if adapter.ipv4:
        arp_fields["psrc"] = adapter.ipv4
    if hwsrc:
        ether_fields["src"] = hwsrc
        arp_fields["hwsrc"] = hwsrc
    try:
        # promisc=False: Viele Windows-WLAN-Treiber (z. B. Intel) nehmen im Promiscuous Mode keine an den eigenen
        # Rechner gerichteten Antworten mehr an – dann kämen 0 Antworten zurück. Wir brauchen nur Antworten an uns.
        answered, _unanswered = srp(
            Ether(**ether_fields) / ARP(**arp_fields),
            iface=iface,
            timeout=timeout,
            inter=gap,
            promisc=False,
            verbose=0,
        )
    except AssertionError:  # Programmierfehler bzw. Testsperre nicht als „nicht verfügbar“ tarnen
        raise
    except Exception as exc:  # noqa: BLE001 – Npcap fehlt, keine Rechte, Schnittstelle weg …
        raise ArpUnavailable(
            f"ARP-Anfrage nicht möglich: {_short(exc)}. Läuft das Programm als Administrator und ist Npcap installiert?"
        ) from exc
    replies: dict[str, str] = {}
    for _sent, received in answered:
        layer = received.getlayer(ARP)
        if layer is None:
            continue
        replies[str(layer.psrc)] = str(layer.hwsrc)
    return replies


# --- ARP-Scan ----------------------------------------------------------------


def _valid_replies(block: list[str], replies: dict[str, str] | None) -> dict[str, str]:
    """Nur Antworten auf gefragte Adressen mit gültiger, normalisierter MAC."""
    asked = set(block)
    out: dict[str, str] = {}
    for ip, mac in (replies or {}).items():
        if ip not in asked:
            continue
        try:
            out[ip] = normalize_mac(mac)
        except ValueError:
            log.debug("Ungültige MAC %r für %s verworfen", mac, ip)
    return out


def arp_scan(ctx: ScanContext, adapter: Adapter, hosts: list[str], sender: ArpSender | None = None) -> dict[str, str]:
    """Fragt alle hosts per ARP ab, in Blöcken (block_size(rate_pps)), abbrechbar zwischen Blöcken.
    Wiederholt nicht antwortende Adressen settings.arp_retries mal (mit kürzerem Timeout).
    Rückgabe {ip: mac normalisiert}.

    Drosselung: Der Standard-Sender schickt jeden Block mit dem Paketabstand 1/rate_pps (srp inter) – so
    gehen nie mehr als rate_pps Anfragen je Sekunde hinaus, auch nicht stoßweise. Zusätzlich dauert jeder
    Block mindestens len(block)/rate_pps Sekunden (gilt auch für eingesetzte Sender). Der Token-Bucket
    ctx.rate würde den gleichmäßig verteilten Block ein zweites Mal ausbremsen und bleibt Ping und TCP vorbehalten.
    """
    settings = ctx.settings
    rate = max(1.0, float(settings.rate_pps))
    size = block_size(rate)
    if sender is not None:
        send = sender
    else:
        _refresh_scapy()
        inter = 1.0 / rate

        def send(a: Adapter, ips: list[str], timeout_s: float) -> dict[str, str]:
            # über den Modulnamen, damit Tests _scapy_sender ersetzen können
            return _scapy_sender(a, ips, timeout_s, inter=inter)

    retries = max(0, int(settings.arp_retries))
    base_timeout = float(settings.arp_timeout_s)
    total = len(hosts)
    found: dict[str, str] = {}
    pending = list(hosts)
    done = 0
    for attempt in range(retries + 1):
        if not pending:
            break
        timeout = base_timeout if attempt == 0 else min(base_timeout, max(MIN_RETRY_TIMEOUT_S, base_timeout * RETRY_TIMEOUT_FACTOR))
        for start in range(0, len(pending), size):
            block = pending[start : start + size]
            ctx.check_cancel()
            started = time.monotonic()
            replies = send(adapter, block, timeout)
            found.update(_valid_replies(block, replies))
            rest = len(block) / rate - (time.monotonic() - started)
            if rest > 0:
                ctx.sleep(rest)  # Mindestdauer je Block (abbrechbar)
            if attempt == 0:
                done += len(block)
                ctx.progress(PHASE, done, total)
            else:
                ctx.progress(PHASE, total, total, f"Wiederholung {attempt} von {retries}")
        pending = [ip for ip in pending if ip not in found]
    ctx.log(f"ARP-Scan: {len(found)} von {total} Adressen haben geantwortet.")
    return found
