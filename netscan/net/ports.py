"""TCP-Port-Scan und feste Regeltabelle für Dienst und Risiko. (Agent ports)"""

from __future__ import annotations

from dataclasses import dataclass

from netscan.core.context import ScanContext
from netscan.core.models import PortResult, Risk


@dataclass(frozen=True)
class PortSpec:
    port: int
    service: str
    risk: Risk
    reason: str  # deutsche Begründung / Abhilfe


PORT_TABLE: dict[int, PortSpec] = {}  # rund 30 häufige Ports, siehe Auftrag
COMMON_PORTS: list[int] = []  # Standard-Scan, sortiert
DEEP_PORTS: range = range(1, 1025)  # Tiefenscan auf Knopfdruck


def describe_port(port: int) -> PortSpec:
    """Eintrag aus PORT_TABLE oder ein Eintrag „unbekannt“ (risk low)."""
    raise NotImplementedError


BANNER_PORTS: frozenset[int] = frozenset({21, 22, 23, 25})


def probe_port(ip: str, port: int, timeout_s: float, read_banner: bool = False) -> tuple[bool, str | None]:
    """Ein TCP-Connect-Versuch. (offen, Banner). Banner nur passiv lesen (nichts senden), höchstens
    200 Zeichen, kurze Zeitgrenze. Tests ersetzen diese Funktion (Portübersetzung auf Sim-Ports) –
    scan_ports muss sie daher über den Modulnamen aufrufen, nicht über eine lokale Kopie."""
    raise NotImplementedError


def scan_ports(ctx: ScanContext, targets: dict[str, list[int]]) -> dict[str, list[PortResult]]:
    """TCP-Connect-Scan aller (ip, port)-Paare in einem gemeinsamen Pool (parallel_map,
    settings.port_workers, settings.port_timeout_ms, gedrosselt) über probe_port(). Banner nur für
    BANNER_PORTS. Rückgabe {ip: [offene Ports, sortiert]} für jede ip aus targets."""
    raise NotImplementedError
