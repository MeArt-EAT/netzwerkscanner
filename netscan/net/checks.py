"""Dienst- und Erreichbarkeitsprüfungen für den Monitor (BAUPLAN §23). (Agent checks)

Platzhalter der Leitung: Signaturen sind verbindlich, die Umsetzung folgt durch Agent checks.
Jede Verbindung läuft über `connect` (Modulname), damit Tests und Demo sie ersetzen können.
"""

from __future__ import annotations

import socket
from collections.abc import Callable

from netscan.core.models import CheckResult, Device, PingResult

CHECK_KINDS = ("tcp", "http", "https", "smb", "ssh")
DEFAULT_PORTS = {"http": 80, "https": 443, "smb": 445, "ssh": 22}


def connect(ip: str, port: int, timeout_s: float, source_ip: str | None = None) -> socket.socket:
    raise NotImplementedError


def check_tcp(ip: str, port: int, timeout_s: float, *, source_ip: str | None = None) -> CheckResult:
    raise NotImplementedError


def check_http(
    ip: str, port: int, timeout_s: float, *, tls: bool = False, path: str = "/", source_ip: str | None = None
) -> CheckResult:
    raise NotImplementedError


def check_ssh(ip: str, port: int, timeout_s: float, *, source_ip: str | None = None) -> CheckResult:
    raise NotImplementedError


def check_smb(ip: str, port: int, timeout_s: float, *, source_ip: str | None = None) -> CheckResult:
    raise NotImplementedError


def run_check(
    kind: str, ip: str, port: int, timeout_s: float, *, path: str = "/", source_ip: str | None = None
) -> CheckResult:
    raise NotImplementedError


def check_reachability(
    ip: str,
    *,
    method: str,
    ping: Callable[[str, int], PingResult],
    timeout_ms: int,
    tcp_ports: list[int],
    source_ip: str | None = None,
) -> CheckResult:
    raise NotImplementedError


def fallback_tcp_ports(device: Device) -> list[int]:
    raise NotImplementedError


def suggest_checks(device: Device) -> list[dict]:
    raise NotImplementedError
