"""Gemeinsame Hilfen für die Tests der Überwachungs-API (BAUPLAN §27): Fixtures und Attrappen.

Enthält selbst keine Tests. Die echten metrics/alerts-Bausteine bauen andere Agenten; hier stehen kleine
Attrappen mit den Signaturen aus §24/§25. Alles läuft über TestClient (kein echter Port), FakeChecks und
FakePlatform – nichts geht ins Netz, schtasks wird nie aufgerufen.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

import pytest
from fastapi.testclient import TestClient

from netscan.core.models import Alert, Device, PortResult, iso_from_ts
from netscan.net import arp
from netscan.platform import autostart
from netscan.platform.autostart import AutostartStatus
from netscan.web import monitor_api, server
from tests.fakes import (
    FakeChecks,
    RecordingAlertEngine,
    RecordingAlertStore,
    RecordingMetrics,
    seed_device,
)

BASE = "http://127.0.0.1:8765"
WS_URL = "ws://127.0.0.1:8765/ws"
EVIL = "http://evil.example"
NOW = 1_760_000_000  # feste Uhr der API (monitor_api._now)

NAS_MAC, NAS_IP = "00:11:32:aa:bb:03", "192.168.178.3"
PC_MAC, PC_IP = "00:1b:21:aa:bb:05", "192.168.178.5"
PHONE_MAC, PHONE_IP = "a6:c3:61:aa:bb:07", "192.168.178.7"  # zweites Hex-Zeichen 6: privat (locally administered)
UNKNOWN_MAC = "de:ad:be:ef:00:01"  # kein Gerät im Inventar


class ApiMetrics(RecordingMetrics):
    """MetricsStore-Attrappe mit den Lesemethoden aus §24; merkt sich Aufrufe, Ergebnisse sind einstellbar."""

    def __init__(self) -> None:
        super().__init__()
        self.avail: dict[tuple[int, int], dict[str, dict[str, Any]]] = {}
        self.avail_calls: list[int] = []
        self.series_calls: list[dict[str, Any]] = []
        self.trend_calls: list[dict[str, Any]] = []
        self.series_result: dict[str, Any] = {"bucket_s": 300, "points": []}
        self.trend_result: list[dict[str, Any]] = []
        self.count_result: dict[str, Any] = {"raw": 0, "hourly": 0}
        self.error: Exception | None = None  # alle Lesemethoden werfen

    def _check(self) -> None:
        if self.error is not None:
            raise self.error

    def availability_map(self, now: int) -> dict[tuple[int, int], dict[str, dict[str, Any]]]:
        self.avail_calls.append(now)
        self._check()
        return dict(self.avail)

    def series(self, target_id: int, check_id: int = 0, *, since: int, until: int, max_points: int = 400) -> dict[str, Any]:
        self.series_calls.append(
            {"target_id": target_id, "check_id": check_id, "since": since, "until": until, "max_points": max_points}
        )
        self._check()
        return dict(self.series_result)

    def trend(self, target_id: int, check_id: int = 0, *, days: int = 30, now: int) -> list[dict[str, Any]]:
        self.trend_calls.append({"target_id": target_id, "check_id": check_id, "days": days, "now": now})
        self._check()
        return list(self.trend_result)

    def counts(self) -> dict[str, Any]:
        self._check()
        return dict(self.count_result)


class ApiAlertStore(RecordingAlertStore):
    """AlertStore-Attrappe mit den Methoden aus §25: Alerts im Speicher, Aufrufe werden aufgezeichnet."""

    def __init__(self) -> None:
        super().__init__()
        self.items: list[Alert] = []
        self.list_calls: list[dict[str, Any]] = []
        self.ack_calls: list[int] = []
        self.ack_all_calls = 0
        self.frequency_calls: list[dict[str, Any]] = []
        self.frequency_result: list[dict[str, Any]] = []
        self.error: Exception | None = None

    def add(self, rule: str = "device_offline", mac: str | None = None, *, severity: str = "warning",
            closed: str | None = None, acknowledged: str | None = None) -> Alert:  # noqa: PLR0913
        alert = Alert(
            id=len(self.items) + 1,
            rule=rule,  # type: ignore[arg-type]
            key=f"{rule}:{mac or len(self.items) + 1}",
            severity=severity,  # type: ignore[arg-type]
            title=f"Testalert {len(self.items) + 1}",
            message="Meldung",
            mac=mac,
            opened=iso_from_ts(NOW) or "",
            closed=closed,
            acknowledged=acknowledged,
        )
        self.items.append(alert)
        return alert

    def _check(self) -> None:
        if self.error is not None:
            raise self.error

    def list(self, *, state: str = "active", limit: int = 200, mac: str | None = None) -> list[Alert]:
        self.list_calls.append({"state": state, "limit": limit, "mac": mac})
        self._check()
        rows = list(reversed(self.items))
        if state == "active":
            rows = [a for a in rows if a.closed is None]
        elif state == "unacked":
            rows = [a for a in rows if a.closed is None and a.acknowledged is None]
        if mac is not None:
            rows = [a for a in rows if a.mac == mac]
        return rows[:limit]

    def acknowledge(self, alert_id: int, now: float | None = None) -> Alert:
        self.ack_calls.append(alert_id)
        self._check()
        for i, alert in enumerate(self.items):
            if alert.id == alert_id:
                self.items[i] = replace(alert, acknowledged=iso_from_ts(NOW) or "")
                return self.items[i]
        raise LookupError(alert_id)

    def acknowledge_all(self, now: float | None = None) -> int:
        self.ack_all_calls += 1
        self._check()
        open_ones = [i for i, a in enumerate(self.items) if a.acknowledged is None]
        for i in open_ones:
            self.items[i] = replace(self.items[i], acknowledged=iso_from_ts(NOW) or "")
        return len(open_ones)

    def counts(self) -> dict[str, Any]:
        self._check()
        active = [a for a in self.items if a.closed is None]
        return {
            "active": len(active),
            "unacked": len([a for a in active if a.acknowledged is None]),
            "by_rule": {},
        }

    def frequency(self, *, days: int = 30, now: float) -> list[dict[str, Any]]:
        self.frequency_calls.append({"days": days, "now": now})
        self._check()
        return list(self.frequency_result)


class FakeAutostart:
    """Ersetzt autostart_status/set_autostart. Ruft nie schtasks auf."""

    def __init__(self) -> None:
        self.status = AutostartStatus(supported=True, enabled=False, detail="Nicht eingerichtet.")
        self.set_calls: list[bool] = []
        self.status_calls = 0
        self.status_error: Exception | None = None
        self.set_error: Exception | None = None
        self.set_result: AutostartStatus | None = None  # None: Zustand wie gesetzt

    def autostart_status(self, *, run: Any = None) -> AutostartStatus:
        self.status_calls += 1
        if self.status_error is not None:
            raise self.status_error
        return self.status

    def set_autostart(self, enabled: bool, *, run: Any = None) -> AutostartStatus:
        self.set_calls.append(enabled)
        if self.set_error is not None:
            raise self.set_error
        if self.set_result is not None:
            return self.set_result
        self.status = AutostartStatus(supported=True, enabled=enabled, detail="Eingerichtet." if enabled else "Entfernt.")
        return self.status

    def install(self, monkeypatch: pytest.MonkeyPatch) -> FakeAutostart:
        monkeypatch.setattr(autostart, "autostart_status", self.autostart_status)
        monkeypatch.setattr(autostart, "set_autostart", self.set_autostart)
        return self


@dataclass
class MonEnv:
    svc: Any
    app: Any
    client: TestClient
    checks: FakeChecks
    metrics: ApiMetrics
    alerts: ApiAlertStore
    engine: RecordingAlertEngine
    autostart: FakeAutostart
    nas: Device
    pc: Device
    phone: Device

    def events(self, prefix: str) -> list[Any]:
        return self.svc.bus.history(type_prefix=prefix)

    def quiet_client(self) -> TestClient:
        """Client, der Serverfehler als 500-Antwort liefert statt sie im Test auszulösen."""
        return TestClient(self.app, base_url=BASE, raise_server_exceptions=False)

    def add_target(self, mac: str = NAS_MAC, **kw: Any) -> dict[str, Any]:
        r = self.client.post("/api/monitor/targets", json={"mac": mac, **kw})
        assert r.status_code == 201, r.text
        return r.json()


@pytest.fixture
def env(services: Any, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    checks = FakeChecks().install(monkeypatch)
    fake_autostart = FakeAutostart().install(monkeypatch)
    monkeypatch.setattr(monitor_api, "_now", lambda: float(NOW))
    monkeypatch.setattr(arp, "scapy_status", lambda: (True, "Npcap erkannt (Test)"))
    services.metrics = ApiMetrics()
    services.alerts = ApiAlertStore()
    services.alert_engine = RecordingAlertEngine()
    nas = seed_device(
        services, NAS_MAC, NAS_IP, category="server", custom_name="NAS",
        ports=[PortResult(445, service="smb"), PortResult(5000, service="http")],
    )  # fmt: skip
    pc = seed_device(services, PC_MAC, PC_IP, category="pc", is_self=True)
    phone = seed_device(services, PHONE_MAC, PHONE_IP, category="phone", mac_random=True)
    app = server.create_app(services)
    with TestClient(app, base_url=BASE) as client:
        yield MonEnv(
            svc=services, app=app, client=client, checks=checks, metrics=services.metrics, alerts=services.alerts,
            engine=services.alert_engine, autostart=fake_autostart, nas=nas, pc=pc, phone=phone,
        )  # fmt: skip


@pytest.fixture
def client(env: MonEnv) -> TestClient:
    return env.client
