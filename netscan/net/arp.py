"""ARP-Scan über Scapy/Npcap. Scapy NUR hier und NUR verzögert importieren. (Agent discovery)"""

from __future__ import annotations

import logging
import os
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from netscan.core.context import ScanContext
from netscan.core.models import Adapter, normalize_mac

log = logging.getLogger(__name__)

# sender(adapter, ips, timeout_s) -> {ip: mac}; Standard: Scapy srp() über Npcap
ArpSender = Callable[[Adapter, list[str], float], dict[str, str]]

BLOCK_SIZE = 32  # Adressen je ARP-Block
PHASE = "Gerätesuche (ARP)"
_BROADCAST = "ff:ff:ff:ff:ff:ff"
_MAX_TIMEOUT_S = 2.0  # harte Obergrenze je Netzoperation (Bauplan: ≤ 2 s)


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


def _scapy_sender(adapter: Adapter, ips: list[str], timeout_s: float) -> dict[str, str]:
    """Standard-Sender: ARP-Anfragen per Broadcast über Scapy/Npcap. Wirft ArpUnavailable bei jedem Mangel."""
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
    try:
        answered, _unanswered = srp(
            Ether(dst=_BROADCAST) / ARP(pdst=list(ips)),
            iface=iface,
            timeout=timeout,
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
    """Fragt alle hosts per ARP ab, in Blöcken, gedrosselt (ctx.rate), abbrechbar zwischen Blöcken.
    Wiederholt nicht antwortende Adressen settings.arp_retries mal. Rückgabe {ip: mac normalisiert}."""
    send = sender if sender is not None else _scapy_sender
    settings = ctx.settings
    retries = max(0, int(settings.arp_retries))
    total = len(hosts)
    found: dict[str, str] = {}
    pending = list(hosts)
    done = 0
    for attempt in range(retries + 1):
        if not pending:
            break
        for start in range(0, len(pending), BLOCK_SIZE):
            block = pending[start : start + BLOCK_SIZE]
            ctx.check_cancel()
            if ctx.rate is not None:
                ctx.rate.acquire(len(block))
            replies = send(adapter, block, settings.arp_timeout_s)
            found.update(_valid_replies(block, replies))
            if attempt == 0:
                done += len(block)
                ctx.progress(PHASE, done, total)
            else:
                ctx.progress(PHASE, total, total, f"Wiederholung {attempt} von {retries}")
        pending = [ip for ip in pending if ip not in found]
    ctx.log(f"ARP-Scan: {len(found)} von {total} Adressen haben geantwortet.")
    return found
