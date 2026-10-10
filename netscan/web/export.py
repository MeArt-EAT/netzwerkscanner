"""Export als JSON, CSV und HTML-Bericht. Siehe BAUPLAN §14. (Agent api)"""

from __future__ import annotations

from typing import Any

from netscan.core.models import Device


def to_json(devices: list[Device], meta: dict[str, Any]) -> str:
    """{"meta": {...}, "devices": [Device.to_dict()]}, eingerückt, ensure_ascii=False."""
    raise NotImplementedError


def to_csv(devices: list[Device]) -> str:
    """Semikolon-getrennt, beginnt mit BOM (\\ufeff) für Excel. Eine Zeile je Gerät, Ports als „22/ssh, 80/http“."""
    raise NotImplementedError


def to_html(devices: list[Device], meta: dict[str, Any]) -> str:
    """Eigenständiger Bericht: CSS inline, keine Skripte, alle Texte HTML-maskiert."""
    raise NotImplementedError
