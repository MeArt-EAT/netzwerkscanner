"""Leitungsentscheidungen beim Zusammenbau von Stufe 2 (BAUPLAN §34)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from netscan.core.alerts import AlertEngine, AlertStore
from netscan.core.db import JOURNAL_SIZE_LIMIT, Database
from netscan.core.models import Device, ScanOutcome
from netscan.platform import autostart
from tests.fakes import make_adapter
from tests.test_demo_support import demo_env, demo_home  # noqa: F401 – Fixtures


def test_wal_is_limited(tmp_path: Path) -> None:
    db = Database(tmp_path / "w.sqlite3")
    try:
        assert db.query_one("PRAGMA journal_size_limit")[0] == JOURNAL_SIZE_LIMIT == 8 * 1024 * 1024
    finally:
        db.close()


def _engine(services) -> AlertEngine:  # type: ignore[no-untyped-def]
    return AlertEngine(AlertStore(services.db, services.bus), services.settings)


def test_first_scan_is_baseline_without_new_device_alerts(services) -> None:  # type: ignore[no-untyped-def]
    engine = _engine(services)
    phone = Device(mac="da:a1:19:aa:bb:07", ip="192.168.178.7")
    engine.on_scan(ScanOutcome(scan_id=1, kind="scan", adapter=make_adapter(), new_devices=[phone], baseline=True))
    assert engine.store.list(state="all") == []
    engine.on_scan(ScanOutcome(scan_id=2, kind="scan", adapter=make_adapter(), new_devices=[phone], baseline=False))
    assert [a.rule for a in engine.store.list(state="all")] == ["new_device"]


def test_demo_never_creates_a_real_scheduled_task(demo_env) -> None:  # type: ignore[no-untyped-def]  # noqa: F811
    status = autostart.autostart_status()
    assert status.supported is False and "Demo" in status.detail
    with pytest.raises(autostart.AutostartError):
        autostart.set_autostart(True)


def test_cycle_event_carries_status_since(services, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from tests.fakes import FakeChecks, RecordingAlertEngine, RecordingAlertStore, RecordingMetrics, seed_device

    fc = FakeChecks().install(monkeypatch)
    services.metrics, services.alert_engine, services.alerts = RecordingMetrics(), RecordingAlertEngine(), RecordingAlertStore()
    seed_device(services, "00:11:32:aa:bb:03", "192.168.178.3")
    services.monitor.add_target("00:11:32:aa:bb:03")
    fc.online("192.168.178.3")
    services.monitor.run_cycle()
    cycle = [e.data for e in services.bus.history() if e.type == "monitor.cycle"][-1]
    assert cycle["targets"][0]["status_since"] is not None


def test_settings_change_wakes_a_running_monitor(services, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from fastapi.testclient import TestClient

    from netscan.web.server import create_app

    woke = []
    monkeypatch.setattr(type(services.monitor), "running", property(lambda self: True))
    monkeypatch.setattr(services.monitor, "trigger", lambda: woke.append(True))
    with TestClient(create_app(services), base_url="http://127.0.0.1:8765") as client:
        assert client.put("/api/settings", json={"rate_pps": 300}).status_code == 200
        assert woke == []  # Scan-Einstellung: Monitor bleibt im Takt
        assert client.put("/api/settings", json={"monitor_enabled": False}).status_code == 200
        assert woke == [True]


def test_sqlite_has_partial_index_support() -> None:
    # Teilindex für „ein aktiver Alert je Schlüssel“ braucht SQLite ≥ 3.8 (Python bringt längst neuere mit)
    assert tuple(int(x) for x in sqlite3.sqlite_version.split(".")[:2]) >= (3, 8)


def test_own_pc_never_raises_new_device(services) -> None:  # type: ignore[no-untyped-def]
    engine = _engine(services)
    me = Device(mac="00:1b:21:00:00:20", ip="192.168.178.20", is_self=True)
    other = Device(mac="da:a1:19:aa:bb:07", ip="192.168.178.7")
    engine.on_scan(ScanOutcome(scan_id=2, kind="scan", adapter=make_adapter(), new_devices=[me, other]))
    assert [a.mac for a in engine.store.list(state="all")] == ["da:a1:19:aa:bb:07"]
