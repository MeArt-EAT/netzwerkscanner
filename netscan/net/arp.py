"""ARP-Scan über Scapy/Npcap. Scapy NUR hier und NUR verzögert importieren. (Agent discovery)"""

from __future__ import annotations

from collections.abc import Callable

from netscan.core.context import ScanContext
from netscan.core.models import Adapter

# sender(adapter, ips, timeout_s) -> {ip: mac}; Standard: Scapy srp() über Npcap
ArpSender = Callable[[Adapter, list[str], float], dict[str, str]]


def scapy_status() -> tuple[bool, str]:
    """(verfügbar, Begründung) – prüft Import von Scapy und unter Windows Npcap, ohne Pakete zu senden."""
    raise NotImplementedError


def arp_scan(ctx: ScanContext, adapter: Adapter, hosts: list[str], sender: ArpSender | None = None) -> dict[str, str]:
    """Fragt alle hosts per ARP ab, in Blöcken, gedrosselt (ctx.rate), abbrechbar zwischen Blöcken.
    Wiederholt nicht antwortende Adressen settings.arp_retries mal. Rückgabe {ip: mac normalisiert}."""
    raise NotImplementedError
