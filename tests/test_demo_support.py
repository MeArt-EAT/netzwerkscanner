"""Gemeinsame Hilfen für die Tests der Demo (BAUPLAN §32): Fixtures, Konstanten, kleine Attrappen.

Enthält selbst keine Tests. Die Demo ersetzt Funktionen prozessweit (checks.connect, ports.probe_port …);
`demo_env` baut sie deshalb im Testprozess auf, lenkt den Datenordner auf tmp_path um (nie der echte
%LOCALAPPDATA%-Ordner) und setzt mit demo.shutdown_demo() am Ende alles zurück. Das Sim-Netz liegt auf
127.0.0.0/28 – nichts verlässt den Rechner (die Netzsperre aus conftest.py gilt auch hier).
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from netscan import demo
from netscan.core.models import PingResult

NOW = 1_760_000_000  # feste Uhr für die Verlaufs-Tests
END = NOW - NOW % demo.HISTORY_STEP_S  # Ende des Verlaufs: auf den Takt gerundet
WEEK_S = demo.HISTORY_DAYS * 86400
DB_LIMIT_BYTES = 5 * 1024 * 1024  # Vorgabe: Demo-Datenbank klein halten

FIVE_MACS = {demo.ROUTER_MAC, demo.NAS_MAC, demo.PC_MAC, demo.PHONE_MAC, demo.TELNET_MAC}


def wait_for(predicate: Callable[[], Any], timeout: float = 5.0, step: float = 0.01) -> bool:
    """Wartet kurz auf einen Zustand (Threads); gibt False zurück, wenn er nicht eintritt."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(step)
    return bool(predicate())


def flapper_threads() -> list[threading.Thread]:
    return [t for t in threading.enumerate() if t.name == "demo-flapper" and t.is_alive()]


class FakeLab:
    """Sim-Netz-Attrappe für das Wechselspiel: merkt sich Anhalten und Starten, öffnet keinen Port."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, int]] = []
        self.fail: Exception | None = None

    def stop_service(self, ip: str, port: int) -> None:
        if self.fail is not None:
            raise self.fail
        self.calls.append(("stop", ip, port))

    def start_service(self, ip: str, port: int) -> None:
        if self.fail is not None:
            raise self.fail
        self.calls.append(("start", ip, port))


def fake_platform() -> SimpleNamespace:
    """Nur das, was das Wechselspiel anfasst: platform.alive."""
    return SimpleNamespace(alive={demo.TELNET_IP: PingResult(alive=True, rtt_ms=11.0, ttl=64)})


@pytest.fixture
def demo_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Lenkt den Demo-Datenordner (%LOCALAPPDATA% bzw. XDG_DATA_HOME) auf tmp_path um."""
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.delenv("NETSCAN_DATA_DIR", raising=False)
    target = demo.demo_data_dir().resolve()
    assert tmp_path.resolve() in target.parents, f"Demo-Datenordner liegt nicht im Testordner: {target}"
    return tmp_path


@pytest.fixture
def demo_env(demo_home: Path):  # type: ignore[no-untyped-def]
    """Die fertig gebaute Demo: services, runtime, lab, platform. Räumt Services, Sim-Netz und Ersatzfunktionen auf."""
    services = None
    try:
        services = demo.build_demo_services()
        runtime = demo.demo_runtime()
        assert runtime is not None
        yield SimpleNamespace(
            svc=services, runtime=runtime, lab=runtime.lab, platform=runtime.platform, home=demo_home,
        )  # fmt: skip
    finally:
        try:
            if services is not None:
                services.close()
        finally:
            demo.shutdown_demo()


@pytest.fixture
def seeded(services):  # type: ignore[no-untyped-def]
    """Inventar, Ziele und Verlauf der Demo in den Standard-Services (FakePlatform, FakeOui) – ohne Sim-Netz."""
    inventory = demo.seed_inventory(services)
    targets = demo.seed_monitoring(services)
    counts = demo.seed_history(services, NOW)
    return SimpleNamespace(svc=services, inventory=inventory, targets=targets, counts=counts, end=END)
