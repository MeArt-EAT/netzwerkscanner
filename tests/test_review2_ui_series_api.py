"""Regressionstest Review 2, Befund B7: Der Antwortzeit-Verlauf zeigt keine falschen Lücken.

Die Eimergröße von GET /api/metrics/series muss größer sein als das Prüfintervall (monitor_interval_s). Sonst bleibt
bei einem Intervall über der Eimergröße jeder zweite Eimer leer, und die Oberfläche meldet Lücken, obwohl der
Monitor lückenlos lief.

Hier läuft der echte MetricsStore (Datenbank im Testordner) hinter der Web-API (TestClient, kein echter Port).
Es geht kein Paket ins Netz.
"""

from __future__ import annotations

from typing import Any

import pytest

from netscan.core.metrics import MetricsStore
from netscan.core.models import Sample
from netscan.web import monitor_api
from tests.test_api_monitor_support import NAS_MAC, NOW, client, env  # noqa: F401  (Fixtures env und client)

RANGES = monitor_api.RANGE_SECONDS


def _seed(env: Any, interval_s: int, seconds: int, step_s: float) -> int:
    """Messwerte wie der Monitor: Abstand step_s (≥ Intervall), ts ganzzahlig abgeschnitten, bis kurz vor NOW."""
    env.svc.settings.update(monitor_interval_s=interval_s)
    env.svc.metrics = MetricsStore(env.svc.db)
    target = env.add_target(NAS_MAC)
    first = NOW - seconds - 2 * interval_s  # schon vor dem Zeitraum gemessen
    samples: list[Sample] = []
    k = 0
    while True:
        ts = int(first + k * step_s)
        if ts >= NOW:
            break
        samples.append(Sample(target["id"], 0, ts, True, 2.0))
        k += 1
    env.svc.metrics.record(samples)
    return int(target["id"])


def _inner_gaps(body: dict[str, Any]) -> list[int]:
    """Eimer ganz im Zeitraum [since, until) ohne Messwerte (die Ränder sind angefangen bzw. laufend)."""
    since_ms, until_ms, bucket_ms = body["since"] * 1000, body["until"] * 1000, body["bucket_s"] * 1000
    return [p["t"] for p in body["points"] if p["t"] >= since_ms and p["t"] + bucket_ms <= until_ms and p["n"] == 0]


@pytest.mark.parametrize(
    "interval_s, range_",
    [
        (600, "24h"),  # Fall 1 des Befunds: vorher Eimer 300 s ⇒ jeder zweite leer
        (3600, "24h"),
        (1801, "7d"),  # vorher Eimer 1800 s
        (3600, "7d"),
        (3600, "30d"),
        (60, "24h"),  # Standard: unverändert
        (10, "24h"),
    ],
)
def test_b7_eimer_sind_laenger_als_das_pruefintervall(env, interval_s: int, range_: str) -> None:
    _seed(env, interval_s, RANGES[range_], step_s=interval_s + 0.013)  # Weckverzug von einigen Millisekunden
    r = env.client.get("/api/metrics/series", params={"mac": NAS_MAC, "range": range_})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["bucket_s"] > interval_s
    assert _inner_gaps(body) == [], "lückenlos gemessen ⇒ keine leeren Eimer im Zeitraum"
    assert len(body["points"]) <= monitor_api.SERIES_MAX_POINTS + 1


@pytest.mark.parametrize("interval_s", [300, 900, 1800])
def test_b7_messabstaende_knapp_ueber_dem_intervall_ergeben_keine_luecke(env, interval_s: int) -> None:
    """Intervall gleich einer runden Eimergröße: Die Abstände liegen knapp darüber (Weckverzug, ganze Sekunden).

    Bei Eimer = Intervall rutscht eine Messung irgendwann über die Eimergrenze, und ein Eimer bleibt leer.
    Hier wandert die Phase um 1 s je Durchlauf, damit das im Testzeitraum sicher passiert.
    """
    _seed(env, interval_s, RANGES["24h"], step_s=interval_s + 1)
    r = env.client.get("/api/metrics/series", params={"mac": NAS_MAC, "range": "24h"})
    body = r.json()
    assert body["bucket_s"] > interval_s
    assert _inner_gaps(body) == []


def test_b7_standardintervall_behaelt_400_punkte(env) -> None:
    env.add_target(NAS_MAC)
    for range_ in RANGES:
        env.client.get("/api/metrics/series", params={"mac": NAS_MAC, "range": range_})
    assert [c["max_points"] for c in env.metrics.series_calls] == [400] * len(RANGES)


def test_b7_unlesbare_einstellungen_nehmen_den_standard(env, monkeypatch: pytest.MonkeyPatch) -> None:
    env.add_target(NAS_MAC)

    def broken() -> Any:
        raise OSError("Datenbank gesperrt")

    monkeypatch.setattr(env.svc.settings, "load", broken)
    r = env.client.get("/api/metrics/series", params={"mac": NAS_MAC, "range": "24h"})
    assert r.status_code == 200, r.text
    assert env.metrics.series_calls[-1]["max_points"] == 400  # wie mit 60 s


@pytest.mark.parametrize(
    "raw, expected",
    [(600, 600), (5, 10), (99999, 3600), (90.5, 91), (float("nan"), 60), ("x", 60), (None, 60), (True, 60)],
)
def test_b7_intervall_wird_in_die_grenzen_geklemmt(env, monkeypatch: pytest.MonkeyPatch, raw: Any, expected: int) -> None:
    class Loaded:
        monitor_interval_s = raw

    monkeypatch.setattr(env.svc.settings, "load", lambda: Loaded())
    assert monitor_api._monitor_interval_s(env.svc) == expected
