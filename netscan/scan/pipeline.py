"""Scan-Ablauf: Gerätesuche → Enricher → Speichern. Siehe BAUPLAN §9. (Integration)

Erweiterung in späteren Stufen: neue Enricher an ENRICHERS anhängen, bestehende nicht umbauen.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

from netscan.core.context import ScanContext
from netscan.core.models import Device, ScanRequest

if TYPE_CHECKING:
    from netscan.core.services import Services


class Enricher(Protocol):
    name: str  # z. B. "names"
    label: str  # Fortschrittstext, z. B. "Namen"

    def run(self, ctx: ScanContext, devices: list[Device], services: Services, request: ScanRequest) -> None:
        ...


ENRICHERS: list[Enricher] = []


def run_scan(ctx: ScanContext, request: ScanRequest, services: Services) -> dict[str, Any]:
    """Kompletter Scan. Summary: {devices, new, duration_s, network, scan_id}."""
    raise NotImplementedError


def run_deep_scan(ctx: ScanContext, mac: str, services: Services, adapter_name: str | None = None) -> dict[str, Any]:
    """Tiefenscan Ports 1–1024 eines Geräts. Summary: {mac, open_ports, new_ports, duration_s}."""
    raise NotImplementedError
