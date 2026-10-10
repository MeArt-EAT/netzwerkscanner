"""Geräteart aus Hersteller, Diensten und Kennungen. (Agent ports)"""

from __future__ import annotations

from netscan.core.models import Device


def classify(device: Device) -> tuple[str, str]:
    """(category, reason) – reason ist ein kurzer deutscher Satz, z. B. „Hersteller Synology, Ports 5000/5001“."""
    raise NotImplementedError


def apply_classification(devices: list[Device]) -> None:
    """Setzt category/category_reason für alle Geräte mit category_source == "auto"."""
    raise NotImplementedError
