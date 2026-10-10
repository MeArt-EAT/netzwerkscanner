"""Review 2, B1: Abschalten/Löschen von Ziel oder Prüfung während eines Durchlaufs (BAUPLAN §22, §25, §27).

Der Durchlauf wird in der Erreichbarkeitsprüfung angehalten (FakeChecks.gate); währenddessen ändert die
„Web-API“ (die Monitor-Methoden, die sie aufruft) Ziele und Prüfungen. Danach darf der Durchlauf weder den Zustand
überschreiben noch geschlossene Zustands-Alerts wieder öffnen noch Messwerte gelöschter Reihen schreiben.
Echte Stores (TargetStore, MetricsStore, AlertStore, AlertEngine); Netz gibt es nicht.
"""

from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest

from netscan.core.monitor import Monitor
from tests.fakes import FakeChecks, seed_device

NAS_MAC, NAS_IP = "00:11:32:aa:bb:03", "192.168.178.3"
T0 = 1_760_000_000.0


@pytest.fixture
def env(services, monkeypatch):  # type: ignore[no-untyped-def]
    fc = FakeChecks().install(monkeypatch)
    clock = {"now": T0}
    monitor = Monitor(services, clock=lambda: clock["now"])
    services.monitor = monitor
    seed_device(services, NAS_MAC, NAS_IP, category="server")
    services.platform.neighbors[NAS_IP] = NAS_MAC
    yield SimpleNamespace(svc=services, checks=fc, monitor=monitor, clock=clock)
    if fc.gate is not None:
        fc.gate.set()
    monitor.stop()


def _cycle(env, advance: float = 60.0):  # type: ignore[no-untyped-def]
    env.clock["now"] += advance
    return env.monitor.run_cycle()


def _blocked_cycle(env, during, advance: float = 60.0):  # type: ignore[no-untyped-def]
    """Durchlauf in eigenem Thread, angehalten in der Erreichbarkeitsprüfung; währenddessen during()."""
    env.clock["now"] += advance
    env.checks.started.clear()
    env.checks.gate = threading.Event()
    out: dict = {}

    def run() -> None:
        try:
            out["status"] = env.monitor.run_cycle()
        except BaseException as exc:  # noqa: BLE001 – im Test auswerten
            out["error"] = exc

    worker = threading.Thread(target=run, name="test-cycle", daemon=True)
    worker.start()
    assert env.checks.started.wait(5), "Durchlauf hat nicht begonnen"
    t0 = time.monotonic()
    during()
    # Die Verwaltung wartet nie auf die Netzprüfungen eines Durchlaufs (nur kurze Sperre beim Speichern)
    assert time.monotonic() - t0 < 2.0
    env.checks.gate.set()
    worker.join(10)
    env.checks.gate = None
    assert not worker.is_alive()
    assert "error" not in out, out.get("error")
    return out["status"]


def _active(env, rule: str | None = None) -> list:  # type: ignore[no-untyped-def]
    return [a for a in env.svc.alerts.list() if rule is None or a.rule == rule]


def _raw(env, target_id: int, check_id: int | None = None) -> int:  # type: ignore[no-untyped-def]
    sql, params = "SELECT COUNT(*) AS n FROM samples WHERE target_id = ?", [target_id]
    if check_id is not None:
        sql += " AND check_id = ?"
        params.append(check_id)
    return int(env.svc.db.query_one(sql, params)["n"])


def _offline_with_alert(env):  # type: ignore[no-untyped-def]
    """NAS ist seit 6 Minuten offline, device_offline ist offen."""
    target = env.monitor.add_target(NAS_MAC)
    env.monitor.run_cycle()  # T0: keine Antwort
    _cycle(env, 360)
    assert [a.rule for a in _active(env)] == ["device_offline"]
    return target


# --- Fall A: Abschalten während des Durchlaufs ----------------------------------------------------


def test_disable_during_cycle_keeps_pause_and_alert_stays_closed(env) -> None:  # type: ignore[no-untyped-def]
    target = _offline_with_alert(env)
    raw_before = _raw(env, target.id)
    _blocked_cycle(env, lambda: env.monitor.update_target(NAS_MAC, enabled=False))
    stored = env.svc.targets.get(NAS_MAC)
    assert stored.enabled is False
    assert stored.status == "paused" and stored.pause_code == "disabled"
    assert _active(env) == []  # nicht wieder geöffnet
    assert _raw(env, target.id) == raw_before  # kein Messwert eines abgeschalteten Ziels
    for _ in range(3):
        _cycle(env)
    stored = env.svc.targets.get(NAS_MAC)
    assert stored.status == "paused" and stored.pause_code == "disabled"
    assert _active(env) == []
    # Übersicht (/api/metrics/overview zählt die gespeicherten Zustände): nicht als offline gezählt
    assert [t.status for t in env.svc.targets.list()] == ["paused"]


def test_disable_right_after_add_does_not_show_online(env) -> None:  # type: ignore[no-untyped-def]
    # Fall D: „Überwachen“ startet sofort einen Durchlauf, gleich danach „Prüfung aktiv“ abgewählt
    env.checks.online(NAS_IP)
    env.monitor.add_target(NAS_MAC)
    status = _blocked_cycle(env, lambda: env.monitor.update_target(NAS_MAC, enabled=False), advance=0)
    stored = env.svc.targets.get(NAS_MAC)
    assert stored.status == "paused" and stored.pause_code == "disabled" and stored.last_check is None
    assert status.state == "idle" and status.targets == 0
    assert env.svc.metrics.counts()["raw"] == 0


def test_disable_and_enable_during_cycle_starts_fresh(env) -> None:  # type: ignore[no-untyped-def]
    _offline_with_alert(env)

    def toggle() -> None:
        env.monitor.update_target(NAS_MAC, enabled=False)
        env.monitor.update_target(NAS_MAC, enabled=True)

    _blocked_cycle(env, toggle)
    stored = env.svc.targets.get(NAS_MAC)
    # Wieder eingeschaltet: der Ausfall zählt neu ab diesem Durchlauf, der alte Alert kommt nicht sofort zurück
    assert stored.status == "offline" and stored.down_since is not None
    assert _active(env) == []


# --- Fall B: Ziel löschen während des Durchlaufs ---------------------------------------------------


def test_remove_target_during_cycle_leaves_no_alert_and_no_sample(env) -> None:  # type: ignore[no-untyped-def]
    target = _offline_with_alert(env)
    status = _blocked_cycle(env, lambda: env.monitor.remove_target(NAS_MAC))
    assert env.svc.targets.get(NAS_MAC) is None
    assert _active(env) == []
    assert _raw(env, target.id) == 0  # Messwerte gelöscht und nicht neu geschrieben
    assert status.state == "idle"
    for _ in range(3):
        _cycle(env)
    assert _active(env) == []
    assert _raw(env, target.id) == 0


# --- Fall C: Prüfung löschen oder abschalten während des Durchlaufs ------------------------------


def _service_down_with_alert(env):  # type: ignore[no-untyped-def]
    target = env.monitor.add_target(NAS_MAC, checks=[{"kind": "http", "port": 5000}])
    [check] = target.checks
    env.checks.online(NAS_IP)  # Gerät erreichbar, HTTP 5000 antwortet nicht
    env.monitor.run_cycle()
    _cycle(env, 180)
    assert [a.key for a in _active(env)] == [f"service_down:{check.id}"]
    assert env.svc.targets.get(NAS_MAC).status == "degraded"
    return target, check


def test_remove_check_during_cycle_keeps_service_alert_closed(env) -> None:  # type: ignore[no-untyped-def]
    target, check = _service_down_with_alert(env)
    _blocked_cycle(env, lambda: env.monitor.remove_check(check.id))
    assert env.svc.targets.get_check(check.id) is None
    assert _active(env) == []
    assert _raw(env, target.id, check.id) == 0
    stored = env.svc.targets.get(NAS_MAC)
    assert stored.checks == [] and stored.status == "online"  # die gelöschte Prüfung stört das Gerät nicht mehr
    for _ in range(3):
        _cycle(env)
    assert _active(env) == []
    assert _raw(env, target.id, check.id) == 0


def test_disable_check_during_cycle_keeps_service_alert_closed(env) -> None:  # type: ignore[no-untyped-def]
    target, check = _service_down_with_alert(env)
    raw_before = _raw(env, target.id, check.id)
    _blocked_cycle(env, lambda: env.monitor.update_check(check.id, False))
    stored = env.svc.targets.get(NAS_MAC)
    [c] = stored.checks
    assert c.enabled is False and c.status == "unknown" and c.last_detail == "abgeschaltet"
    assert stored.status == "online"
    assert _active(env) == []
    assert _raw(env, target.id, check.id) == raw_before
    _cycle(env)
    assert _active(env) == []


def test_threshold_change_during_cycle_applies_immediately(env) -> None:  # type: ignore[no-untyped-def]
    # Neu gelesen wird das ganze Ziel: auch geänderte Schwellen gelten schon in diesem Durchlauf
    env.monitor.add_target(NAS_MAC)
    env.checks.online(NAS_IP, rtt_ms=80)
    env.monitor.run_cycle()
    assert env.svc.targets.get(NAS_MAC).status == "online"
    _blocked_cycle(env, lambda: env.monitor.update_target(NAS_MAC, rtt_threshold_ms=50))
    stored = env.svc.targets.get(NAS_MAC)
    assert stored.status == "degraded" and stored.rtt_high_since is not None
