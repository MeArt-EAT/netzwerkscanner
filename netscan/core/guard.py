"""Netz-Wächter: erkennt Heimnetz und gesperrte Netze. Sicherheitskritisch – siehe BAUPLAN §10. (Agent guard)"""

from __future__ import annotations

from netscan.config import PERMANENT_BLOCKED_SSIDS, SettingsStore
from netscan.core.models import Adapter, GuardResult
from netscan.platform.base import Platform

__all__ = ["NetworkGuard", "PERMANENT_BLOCKED_SSIDS"]


class NetworkGuard:
    def __init__(self, platform: Platform, settings_store: SettingsStore) -> None:
        self.platform = platform
        self.settings_store = settings_store

    def check(self, adapter: Adapter | None) -> GuardResult:
        """Entscheidung allow / confirm / block für einen Scan über adapter. Sendet keine Pakete."""
        raise NotImplementedError

    def remember_home(self, gateway_mac: str) -> None:
        """Gateway-MAC als Heimnetz merken (nach ausdrücklicher Bestätigung in der Oberfläche)."""
        raise NotImplementedError
