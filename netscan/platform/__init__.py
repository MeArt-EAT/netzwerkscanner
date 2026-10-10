"""Wählt die passende Plattform-Implementierung."""

from __future__ import annotations

import sys

from netscan.platform.base import AdapterDetail, InterfaceAddr, Platform, WifiEntry, WifiStatus

__all__ = ["AdapterDetail", "InterfaceAddr", "Platform", "WifiEntry", "WifiStatus", "get_platform"]


def get_platform() -> Platform:
    if sys.platform == "win32":
        from netscan.platform.windows import WindowsPlatform

        return WindowsPlatform()
    from netscan.platform.linux import LinuxPlatform

    return LinuxPlatform()
