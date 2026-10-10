"""Review 2, B2: stop() beendet auch die laufenden Prüfungen, und das Programmende wartet nicht auf sie (§18).

BAUPLAN §18: „Monitor.stop() hält innerhalb von 5 s an (Programmende, Tests)“. Gemessen wird hier nicht nur die
Rückkehr von stop(), sondern das Ende der Arbeiter-Threads bzw. des ganzen Prozesses. Netz gibt es nicht.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from netscan.core.monitor import Monitor
from tests.fakes import FakeChecks, RecordingAlertEngine, RecordingAlertStore, RecordingMetrics, seed_device

ROOT = Path(__file__).resolve().parent.parent
NAS_MAC, NAS_IP = "00:11:32:aa:bb:03", "192.168.178.3"


@pytest.fixture
def env(services, monkeypatch):  # type: ignore[no-untyped-def]
    fc = FakeChecks().install(monkeypatch)
    services.metrics = RecordingMetrics()
    services.alert_engine = RecordingAlertEngine()
    services.alerts = RecordingAlertStore()
    monitor = Monitor(services)
    services.monitor = monitor
    seed_device(services, NAS_MAC, NAS_IP)
    yield SimpleNamespace(svc=services, checks=fc, monitor=monitor)
    monitor.stop()


def _new_probes(before: set[threading.Thread]) -> list[threading.Thread]:
    return [t for t in threading.enumerate() if t.name.startswith("monitor-probe") and t not in before]


def test_stop_ends_running_service_checks(env) -> None:  # type: ignore[no-untyped-def]
    # Ein Ziel mit 8 HTTP-Prüfungen à 1 s: nach stop() beginnt keine weitere Prüfung
    env.monitor.add_target(NAS_MAC, checks=[{"kind": "http", "port": 8001 + i} for i in range(8)])
    env.checks.online(NAS_IP)
    env.checks.service_delay_s = 1.0
    before = set(threading.enumerate())
    env.monitor.start()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not env.checks.service_calls:
        time.sleep(0.02)
    assert env.checks.service_calls, "Dienstprüfungen haben nicht begonnen"
    time.sleep(0.3)
    probes = _new_probes(before)
    assert probes
    t0 = time.monotonic()
    env.monitor.stop()
    assert time.monotonic() - t0 < 1.0
    for t in probes:
        t.join(max(0.0, t0 + 2.0 - time.monotonic()))
    assert not any(t.is_alive() for t in probes), "Arbeiter prüfen nach stop() weiter"
    assert len(env.checks.service_calls) <= 2  # die laufende und höchstens eine gerade begonnene
    assert all(t.daemon for t in probes)


_EXIT_SCRIPT = r"""
import sys, threading, time
from types import SimpleNamespace
sys.path.insert(0, sys.argv[1])
from netscan.core.context import ScanCancelled
from netscan.core.monitor import Monitor

monitor = Monitor(services=None)

def slow(item):
    time.sleep(6)  # wie eine Prüfung, die gerade läuft (nichts geht ins Netz)

def run():
    try:
        monitor._parallel(slow, [SimpleNamespace(device=SimpleNamespace(ip="127.0.0.1"), reach=None) for _ in range(4)])
    except ScanCancelled:
        pass

worker = threading.Thread(target=run, daemon=True)
worker.start()
time.sleep(0.5)
monitor._cancel.cancel()  # wie stop()
worker.join(2)
print("gestoppt", flush=True)
"""


def test_running_probes_do_not_delay_program_exit(tmp_path) -> None:  # type: ignore[no-untyped-def]
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "NETSCAN_DATA_DIR": str(tmp_path / "data")}
    proc = subprocess.Popen(
        [sys.executable, "-B", "-c", _EXIT_SCRIPT, str(ROOT)],
        cwd=str(tmp_path), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )  # fmt: skip
    try:
        line = proc.stdout.readline() if proc.stdout else ""
        t0 = time.monotonic()
        proc.wait(timeout=30)
        waited = time.monotonic() - t0
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    err = proc.stderr.read() if proc.stderr else ""
    assert line.strip() == "gestoppt", err
    assert proc.returncode == 0, err
    # Vorher wartete der Interpreter auf die Arbeiter des ThreadPoolExecutor (hier ≈ 5 s)
    assert waited < 2.5, f"Programmende wartete {waited:.1f} s auf laufende Prüfungen"
