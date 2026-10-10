"""Gemeinsame Hilfen für die Web-API-Tests (Fixtures env/client, Wächter-Attrappe, Pipeline-Attrappe).

Enthält selbst keine Tests. Alles läuft über TestClient (kein echter Port) und Attrappen – nichts geht
ins Netz. adapters, arp, oui und pipeline werden per monkeypatch ersetzt (die echten Module bauen
andere Agenten).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

import pytest
from fastapi.testclient import TestClient

from netscan.core.context import ScanContext
from netscan.core.models import Adapter, Device, GuardResult, PortResult, ScanRequest
from netscan.net import adapters, arp, oui
from netscan.scan import pipeline
from netscan.web import server
from tests.fakes import FakeOui, make_adapter

BASE = "http://127.0.0.1:8765"
PORT = 8765
GATEWAY_MAC = "3c:a6:2f:00:00:01"


def guard_result(decision: str, code: str, reason: str = "Testgrund.", **kw: Any) -> GuardResult:
    return GuardResult(decision=decision, code=code, reason=reason, **kw)  # type: ignore[arg-type]


ALLOW = guard_result("allow", "ok_home", "Heimnetz erkannt.", gateway_ip="192.168.178.1", gateway_mac=GATEWAY_MAC)
BLOCK = guard_result("block", "blocked_ssid", "Gesperrtes WLAN.", ssid="Gesperrt", gateway_mac=GATEWAY_MAC)
CONFIRM = guard_result("confirm", "foreign_network", "Fremdes Netz.", gateway_ip="10.9.9.1", gateway_mac="aa:bb:cc:00:00:99")


class StubGuard:
    """Ersatz für NetworkGuard: liefert ein festes Ergebnis und merkt sich alle Aufrufe."""

    def __init__(self, result: GuardResult = ALLOW) -> None:
        self.result = result
        self.checked: list[Adapter | None] = []
        self.remembered: list[str] = []
        self.remembered_adapters: list[Adapter | None] = []
        self.error: Exception | None = None
        self.remember_error: Exception | None = None

    def check(self, adapter: Adapter | None) -> GuardResult:
        self.checked.append(adapter)
        if self.error is not None:
            raise self.error
        return self.result

    def remember_home(self, mac: str, adapter: Adapter | None = None) -> None:
        if self.remember_error is not None:
            raise self.remember_error
        self.remembered.append(mac)
        self.remembered_adapters.append(adapter)


@dataclass
class ApiEnv:
    svc: Any
    guard: StubGuard
    app: Any
    adapters: dict[str, Adapter] = field(default_factory=dict)
    scan_calls: list[tuple[ScanRequest, Any]] = field(default_factory=list)
    deep_calls: list[tuple[str, str | None]] = field(default_factory=list)
    oui_calls: list[Any] = field(default_factory=list)
    hold: bool = False  # True: die Pipeline-Attrappe läuft, bis release gesetzt oder abgebrochen wird
    release: threading.Event = field(default_factory=threading.Event)
    started: threading.Event = field(default_factory=threading.Event)

    def add_adapter(self, adapter: Adapter) -> Adapter:
        self.adapters[adapter.name] = adapter
        return adapter

    def wait_job(self, timeout: float = 5.0) -> None:
        assert self.svc.jobs.wait(timeout), "Auftrag ist nicht rechtzeitig fertig geworden"

    def events(self, prefix: str) -> list[Any]:
        return self.svc.bus.history(type_prefix=prefix)

    def hold_pipeline(self, ctx: ScanContext) -> None:
        self.started.set()
        while not self.release.is_set():
            ctx.check_cancel()
            self.release.wait(0.02)


def make_env(services: Any, monkeypatch: pytest.MonkeyPatch, **app_kwargs: Any) -> ApiEnv:
    guard = StubGuard()
    services.guard = guard
    env = ApiEnv(svc=services, guard=guard, app=None)
    env.adapters = {
        "Ethernet": make_adapter("Ethernet"),
        "WLAN": make_adapter("WLAN", "192.168.178.21", wireless=True, mac="a4:c3:61:00:00:21"),
        "vEthernet (WSL)": make_adapter("vEthernet (WSL)", "172.20.0.1", "172.20.0.0/20", virtual=True),
    }

    def find_adapter(platform: Any, name: str) -> Adapter | None:
        return env.adapters.get(name)

    def list_adapters(platform: Any, include_virtual: bool = False) -> list[Adapter]:
        return [a for a in env.adapters.values() if include_virtual or not a.is_virtual]

    def run_scan(ctx: ScanContext, request: ScanRequest, services_arg: Any) -> dict[str, Any]:
        env.scan_calls.append((request, services_arg))
        if env.hold:
            env.hold_pipeline(ctx)
        return {"devices": 0, "new": 0}

    def run_deep_scan(ctx: ScanContext, mac: str, services_arg: Any, adapter_name: str | None = None) -> dict[str, Any]:
        env.deep_calls.append((mac, adapter_name))
        if env.hold:
            env.hold_pipeline(ctx)
        return {"mac": mac, "open_ports": 0}

    def update_from_ieee(data_dir: Any, fetch: Any = None, **kwargs: Any) -> int:
        env.oui_calls.append(data_dir)
        if env.hold:
            env.started.set()
            env.release.wait(5)
        return 123

    monkeypatch.setattr(adapters, "find_adapter", find_adapter)
    monkeypatch.setattr(adapters, "list_adapters", list_adapters)
    monkeypatch.setattr(arp, "scapy_status", lambda: (True, "Npcap erkannt (Test)"))
    monkeypatch.setattr(pipeline, "run_scan", run_scan)
    monkeypatch.setattr(pipeline, "run_deep_scan", run_deep_scan)
    monkeypatch.setattr(oui, "update_from_ieee", update_from_ieee)
    monkeypatch.setattr(oui.OuiDb, "load", classmethod(lambda cls, data_dir=None: FakeOui()))

    env.app = server.create_app(services, **app_kwargs)
    return env


def add_devices(svc: Any, *devices: Device) -> list[Device]:
    """Speichert Geräte in einem abgeschlossenen Scan (Ports werden mit set_ports übernommen)."""
    scan_id = svc.inventory.begin_scan("scan", "Ethernet", "192.168.178.0/24")
    for dev in devices:
        saved = svc.inventory.record_seen(dev, scan_id)
        if dev.ports:
            svc.inventory.set_ports(saved.mac, [p.port for p in dev.ports], list(dev.ports))
    svc.inventory.finish_scan(scan_id, "completed", len(devices))
    return [svc.inventory.get(d.mac) for d in devices]


def sample_device(mac: str = "aa:bb:cc:dd:ee:01", ip: str = "192.168.178.50", **kw: Any) -> Device:
    return Device(mac=mac, ip=ip, vendor=kw.pop("vendor", "Testhersteller"), **kw)


def sample_port(port: int = 22, service: str = "ssh", risk: str = "medium", reason: str = "Fernzugriff") -> PortResult:
    return PortResult(port=port, service=service, risk=risk, reason=reason)  # type: ignore[arg-type]


@pytest.fixture
def env(services: Any, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    e = make_env(services, monkeypatch)
    yield e
    e.release.set()
    services.jobs.cancel()
    services.jobs.wait(5)


@pytest.fixture
def client(env: ApiEnv):  # type: ignore[no-untyped-def]
    with TestClient(env.app, base_url=BASE) as c:
        yield c
