"""Messwerte (BAUPLAN §24): speichern, Verfügbarkeit, Karte, Verlauf, Tages-Trend – mit echter Datenbank im tmp_path."""

from __future__ import annotations

import logging
import math
from datetime import date, timedelta

import pytest

from netscan.core.db import Database
from netscan.core.metrics import MetricsStore
from netscan.core.models import Sample

DAY = 86400
HOUR = 3600
DAY0 = 20370 * DAY  # 2025-10-09 00:00:00 UTC
NOW = DAY0 + 10 * DAY + 12 * HOUR  # 2025-10-19 12:00:00 UTC


@pytest.fixture
def db(tmp_path):  # type: ignore[no-untyped-def]
    d = Database(tmp_path / "metrics.sqlite3")
    yield d
    d.close()


@pytest.fixture
def store(db) -> MetricsStore:  # type: ignore[no-untyped-def]
    return MetricsStore(db)


def put_hourly(db: Database, t: int, c: int, hour: object, n: object, up: object,
               avg: object = None, mn: object = None, mx: object = None) -> None:
    db.execute("INSERT INTO samples_hourly VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (t, c, hour, n, up, avg, mn, mx))


def raw_rows(db: Database) -> list[tuple]:
    return [tuple(r) for r in db.query("SELECT target_id, check_id, ts, ok, rtt_ms FROM samples ORDER BY 1, 2, 3")]


# --- record ---------------------------------------------------------------------------------------


def test_record_writes_and_same_key_replaces(store, db) -> None:  # type: ignore[no-untyped-def]
    store.record([Sample(1, 0, NOW, True, 4.5), Sample(1, 3, NOW, False), Sample(2, 0, NOW + 60, True, 0)])
    assert raw_rows(db) == [(1, 0, NOW, 1, 4.5), (1, 3, NOW, 0, None), (2, 0, NOW + 60, 1, 0.0)]
    store.record([Sample(1, 0, NOW, False, None)])
    assert raw_rows(db)[0] == (1, 0, NOW, 0, None)
    assert store.counts() == {"raw": 3, "hourly": 0}


def test_record_skips_invalid_values_and_warns_once(store, db, caplog) -> None:  # type: ignore[no-untyped-def]
    bad = [
        Sample(0, 0, NOW, True),            # target_id < 1
        Sample(-4, 0, NOW, True),
        Sample(1, -1, NOW, True),           # check_id < 0
        Sample(1, 0, float(NOW), True),     # ts kein int
        Sample(1, 0, "1760000000", True),   # type: ignore[arg-type]
        Sample(1, 0, True, True),           # type: ignore[arg-type]  bool ist kein Zeitstempel
        Sample(1, 0, -5, True),             # vor 1970
        Sample(1, 0, NOW, True, math.nan),  # rtt nicht endlich
        Sample(1, 0, NOW, True, math.inf),
        Sample(1, 0, NOW, True, -0.5),      # rtt < 0
        Sample(1, 0, NOW, True, "5"),       # type: ignore[arg-type]
        Sample(1, 0, NOW, "ja"),            # type: ignore[arg-type]  ok weder bool noch 0/1
        Sample(True, 0, NOW, True),         # type: ignore[arg-type]
        Sample(1, 0, NOW, True, 10**400),   # rtt zu groß für float
        None,
        object(),
    ]
    good = [Sample(1, 0, NOW + 1, True, 1.0), Sample(1, 0, NOW + 2, 0), Sample(1, 0, NOW + 3, 1, 3)]
    with caplog.at_level(logging.WARNING, logger="netscan.core.metrics"):
        store.record(bad[:8] + good + bad[8:])  # type: ignore[list-item]
    assert [r[2] for r in raw_rows(db)] == [NOW + 1, NOW + 2, NOW + 3]
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert f"{len(bad)} ungültige" in warnings[0].getMessage()


def test_record_accepts_generator_and_empty_input(store, db, caplog) -> None:  # type: ignore[no-untyped-def]
    with caplog.at_level(logging.WARNING, logger="netscan.core.metrics"):
        store.record([])
        store.record(iter(()))
    assert caplog.records == []
    store.record(Sample(5, 0, NOW + i, True, float(i)) for i in range(50))
    assert store.counts()["raw"] == 50


def test_record_uses_one_transaction(store, db) -> None:  # type: ignore[no-untyped-def]
    statements: list[str] = []
    db.conn.set_trace_callback(statements.append)
    try:
        store.record([Sample(1, 0, NOW + i, True, 1.0) for i in range(200)])
    finally:
        db.conn.set_trace_callback(None)
    assert sum(s.startswith("BEGIN") for s in statements) == 1
    assert sum(s.startswith("COMMIT") for s in statements) == 1


# --- availability ---------------------------------------------------------------------------------


def test_availability_counts_only_present_samples_and_respects_window(store) -> None:  # type: ignore[no-untyped-def]
    # 10 Messwerte, 2 davon schlecht, dazwischen eine Pause von 2 Stunden (Lücke = kein Ausfall)
    times = [NOW + i * 60 for i in range(5)] + [NOW + 2 * HOUR + i * 60 for i in range(5)]
    store.record(Sample(1, 0, ts, i not in (3, 7), 2.0) for i, ts in enumerate(times))
    store.record([Sample(1, 9, NOW, False), Sample(2, 0, NOW, False)])  # andere Reihen zählen nicht mit
    assert store.availability(1, since=NOW, until=NOW + DAY) == {"up_pct": 80.0, "samples": 10, "up": 8}
    # since einschließlich, until ausschließlich
    assert store.availability(1, 0, since=NOW + 60, until=NOW + 2 * HOUR)["samples"] == 4
    assert store.availability(1, 0, since=NOW, until=NOW + 60)["samples"] == 1
    assert store.availability(1, 0, since=NOW + 1, until=NOW + 60)["samples"] == 0


def test_availability_without_values_and_empty_window(store) -> None:  # type: ignore[no-untyped-def]
    empty = {"up_pct": None, "samples": 0, "up": 0}
    assert store.availability(1, since=NOW - DAY, until=NOW) == empty
    store.record([Sample(1, 0, NOW, True)])
    assert store.availability(1, since=NOW + 10, until=NOW) == empty
    assert store.availability(1, since=NOW, until=NOW) == empty


def test_availability_rounds_to_two_decimals(store) -> None:  # type: ignore[no-untyped-def]
    store.record([Sample(1, 0, NOW, True), Sample(1, 0, NOW + 60, True), Sample(1, 0, NOW + 120, False)])
    assert store.availability(1, since=NOW, until=NOW + HOUR)["up_pct"] == 66.67


def test_availability_mixes_raw_and_hourly_values(store, db) -> None:  # type: ignore[no-untyped-def]
    h = DAY0 + 5 * HOUR
    put_hourly(db, 1, 0, h - HOUR, 60, 0)      # vor since: zählt nicht
    put_hourly(db, 1, 0, h, 60, 30, 12.0, 5.0, 20.0)
    put_hourly(db, 1, 0, h + HOUR, 60, 60, 10.0, 9.0, 11.0)
    put_hourly(db, 1, 0, h + 3 * HOUR, 60, 0)  # hour == until: zählt nicht
    store.record(Sample(1, 0, h + 2 * HOUR + i * 60, i < 8, 1.0) for i in range(10))
    result = store.availability(1, since=h, until=h + 3 * HOUR)
    assert result == {"up_pct": round(100 * 98 / 130, 2), "samples": 130, "up": 98}


def test_availability_clamps_untrusted_hourly_rows(store, db) -> None:  # type: ignore[no-untyped-def]
    h = DAY0
    put_hourly(db, 1, 0, h, -5, 3)            # n negativ -> 0
    put_hourly(db, 1, 0, h + HOUR, 10, 50)    # up > n -> n
    put_hourly(db, 1, 0, h + 2 * HOUR, "viel", "x")  # fremde Typen -> 0
    put_hourly(db, 1, 0, h + 3 * HOUR, 4, -2)  # up negativ -> 0
    assert store.availability(1, since=h, until=h + DAY) == {"up_pct": round(100 * 10 / 14, 2), "samples": 14, "up": 10}


def test_availability_rejects_nonsense_times(store) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ValueError):
        store.availability(1, since=math.nan, until=NOW)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        store.availability(1, since="gestern", until=NOW)  # type: ignore[arg-type]
    # float wird abgerundet
    store.record([Sample(1, 0, NOW, True)])
    assert store.availability(1, since=NOW - 0.5, until=NOW + 0.9)["samples"] == 1  # type: ignore[arg-type]


# --- availability_map -----------------------------------------------------------------------------


def test_availability_map_windows_and_series(store, db) -> None:  # type: ignore[no-untyped-def]
    # (1, 0): 24h: 2 Werte (einer genau bei now, einer genau bei now-24h), 7d: dazu 2 ältere
    store.record([
        Sample(1, 0, NOW, True), Sample(1, 0, NOW - DAY, False),
        Sample(1, 0, NOW - DAY - 1, True), Sample(1, 0, NOW - 7 * DAY, True),
        Sample(1, 0, NOW - 7 * DAY - 1, False),  # außerhalb 7d
        Sample(1, 0, NOW + 1, False),            # Zukunft: außerhalb
    ])
    store.record([Sample(1, 4, NOW - 3600, False)])
    store.record([Sample(3, 0, NOW - 30 * DAY, True)])  # nur alte Werte
    put_hourly(db, 7, 2, NOW - 3 * DAY, 60, 45)          # nur Stundenwerte
    put_hourly(db, 1, 0, NOW - 2 * DAY, 60, 30)          # gemischt
    result = store.availability_map(NOW)
    assert set(result) == {(1, 0), (1, 4), (3, 0), (7, 2)}
    assert result[(1, 0)]["24h"] == {"up_pct": 50.0, "samples": 2, "up": 1}
    assert result[(1, 0)]["7d"] == {"up_pct": round(100 * 33 / 64, 2), "samples": 64, "up": 33}
    assert result[(1, 4)] == {"24h": {"up_pct": 0.0, "samples": 1, "up": 0}, "7d": {"up_pct": 0.0, "samples": 1, "up": 0}}
    none = {"up_pct": None, "samples": 0, "up": 0}
    assert result[(3, 0)] == {"24h": none, "7d": none}
    assert result[(7, 2)] == {"24h": none, "7d": {"up_pct": 75.0, "samples": 60, "up": 45}}


def test_availability_map_matches_single_availability(store) -> None:  # type: ignore[no-untyped-def]
    store.record(
        Sample(t, c, NOW - i * 997, (i * t + c) % 5 != 0, 1.0)
        for t in range(1, 6) for c in (0, 10 + t) for i in range(800)
    )
    result = store.availability_map(NOW)
    assert len(result) == 10
    for (t, c), windows in result.items():
        assert windows["24h"] == store.availability(t, c, since=NOW - DAY, until=NOW + 1)
        assert windows["7d"] == store.availability(t, c, since=NOW - 7 * DAY, until=NOW + 1)


def test_availability_map_uses_few_queries(store, db) -> None:  # type: ignore[no-untyped-def]
    store.record(Sample(t, c, NOW - i * 60, True, 1.0) for t in range(1, 21) for c in (0, t) for i in range(5))
    for t in range(1, 21):
        put_hourly(db, t, 0, NOW - 2 * DAY, 60, 60)
    statements: list[str] = []
    db.conn.set_trace_callback(statements.append)
    try:
        result = store.availability_map(NOW)
    finally:
        db.conn.set_trace_callback(None)
    assert len(result) == 40
    assert len(statements) <= 3


def test_availability_map_empty_and_junk_keys(store, db) -> None:  # type: ignore[no-untyped-def]
    assert store.availability_map(NOW) == {}
    db.execute("INSERT INTO samples VALUES ('kaputt', 0, ?, 1, NULL)", (NOW,))
    db.execute("INSERT INTO samples VALUES (2, 'x', ?, 1, NULL)", (NOW,))
    store.record([Sample(1, 0, NOW, True)])
    assert set(store.availability_map(NOW)) == {(1, 0)}


# --- series ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("span", [1, 59, 60, 61, 3600, DAY, 7 * DAY, 30 * DAY, 365 * DAY, 3650 * DAY])
@pytest.mark.parametrize("max_points", [1, 7, 400, 2000])
@pytest.mark.parametrize("offset", [0, 17, 3599])
def test_series_bucket_rules(store, span: int, max_points: int, offset: int) -> None:  # type: ignore[no-untyped-def]
    since = DAY0 + offset
    until = since + span
    result = store.series(1, since=since, until=until, max_points=max_points)
    bucket = result["bucket_s"]
    points = result["points"]
    assert bucket >= 60 and bucket % 60 == 0
    assert 1 <= len(points) <= max_points + 1
    assert points[0]["t"] == (since // bucket) * bucket * 1000
    assert all(b["t"] - a["t"] == bucket * 1000 for a, b in zip(points, points[1:]))
    assert points[-1]["t"] < until * 1000 <= points[-1]["t"] + bucket * 1000  # deckt [since, until) genau ab
    assert all(p["n"] == 0 and p["up_pct"] is None and p["rtt_avg"] is None for p in points)


@pytest.mark.parametrize(("span", "bucket"), [(DAY, 300), (7 * DAY, 1800), (30 * DAY, 7200), (365 * DAY, DAY)])
def test_series_default_buckets_for_ui_ranges(store, span: int, bucket: int) -> None:  # type: ignore[no-untyped-def]
    assert store.series(1, since=NOW - span, until=NOW)["bucket_s"] == bucket


def test_series_aggregates_buckets_and_marks_gaps(store) -> None:  # type: ignore[no-untyped-def]
    since = DAY0 + 10 * HOUR
    until = since + 1800  # max_points 6 -> Eimer 300 s, 6 Eimer
    store.record([
        Sample(1, 0, since + 10, True, 10.0),
        Sample(1, 0, since + 70, True, 30.0),
        Sample(1, 0, since + 130, False, 999.0),  # schlecht: zählt nicht in die Antwortzeit
        Sample(1, 0, since + 190, True, None),    # gut, ohne Antwortzeit
        Sample(1, 0, since + 600, False),         # Eimer 2: nur Ausfall
        Sample(1, 0, since + 1500, True, 2.5),    # Eimer 5
        Sample(1, 0, since - 1, True, 1.0),       # vor since
        Sample(1, 0, until, True, 1.0),           # until ausschließlich
        Sample(1, 5, since + 10, False, 1.0),     # andere Reihe
    ])
    result = store.series(1, 0, since=since, until=until, max_points=6)
    assert result["bucket_s"] == 300
    pts = result["points"]
    assert [p["t"] for p in pts] == [(since + i * 300) * 1000 for i in range(6)]
    assert pts[0] == {"t": since * 1000, "rtt_avg": 20.0, "rtt_min": 10.0, "rtt_max": 30.0, "up_pct": 75.0, "n": 4}
    assert pts[1] == {"t": (since + 300) * 1000, "rtt_avg": None, "rtt_min": None, "rtt_max": None, "up_pct": None, "n": 0}
    assert pts[2] == {"t": (since + 600) * 1000, "rtt_avg": None, "rtt_min": None, "rtt_max": None, "up_pct": 0.0, "n": 1}
    assert pts[3]["n"] == 0 and pts[4]["n"] == 0
    assert pts[5] == {"t": (since + 1500) * 1000, "rtt_avg": 2.5, "rtt_min": 2.5, "rtt_max": 2.5, "up_pct": 100.0, "n": 1}


def test_series_weights_hourly_values(store, db) -> None:  # type: ignore[no-untyped-def]
    since = DAY0
    until = since + 30 * DAY  # Eimer 7200 s
    h = DAY0 + 4 * HOUR
    put_hourly(db, 1, 0, h, 60, 30, 40.0, 5.0, 90.0)
    put_hourly(db, 1, 0, h + HOUR, 60, 0, None, None, None)  # nur Ausfälle in dieser Stunde
    store.record([Sample(1, 0, h + HOUR + 10, True, 10.0), Sample(1, 0, h + HOUR + 70, True, 20.0)])
    result = store.series(1, since=since, until=until)
    assert result["bucket_s"] == 7200
    p = result["points"][2]  # [4 h, 6 h)
    assert p["t"] == h * 1000
    assert p["n"] == 122
    assert p["up_pct"] == round(100 * 32 / 122, 2)
    assert p["rtt_avg"] == round((40.0 * 30 + 10.0 + 20.0) / 32, 2)
    assert (p["rtt_min"], p["rtt_max"]) == (5.0, 90.0)
    assert sum(q["n"] for q in result["points"]) == 122


def test_series_ignores_untrusted_rtt_values(store, db) -> None:  # type: ignore[no-untyped-def]
    since = DAY0
    for i, rtt in enumerate(["schnell", -3.0, 1e300, 7.0]):
        db.execute("INSERT INTO samples VALUES (1, 0, ?, 1, ?)", (since + i, rtt))
    put_hourly(db, 1, 0, since, 10, 10, "x", -1.0, "y")
    pts = store.series(1, since=since, until=since + 600, max_points=10)["points"]
    assert pts[0]["n"] == 14 and pts[0]["up_pct"] == 100.0
    assert (pts[0]["rtt_avg"], pts[0]["rtt_min"], pts[0]["rtt_max"]) == (7.0, 7.0, 7.0)
    for p in pts:
        for key in ("rtt_avg", "rtt_min", "rtt_max", "up_pct"):
            assert p[key] is None or (math.isfinite(p[key]) and p[key] >= 0)


def test_series_empty_range_and_odd_max_points(store) -> None:  # type: ignore[no-untyped-def]
    assert store.series(1, since=NOW, until=NOW)["points"] == []
    assert store.series(1, since=NOW, until=NOW - 5)["points"] == []
    assert len(store.series(1, since=NOW, until=NOW + DAY, max_points=0)["points"]) <= 2
    with pytest.raises(ValueError):
        store.series(1, since=NOW, until=NOW + DAY, max_points="viele")  # type: ignore[arg-type]


# --- trend ----------------------------------------------------------------------------------------


def _label(day_index: int) -> str:
    return (date(1970, 1, 1) + timedelta(days=day_index)).isoformat()


def test_trend_utc_days_including_today(store, db) -> None:  # type: ignore[no-untyped-def]
    now = DAY0 + 2 * DAY + 5000  # dritter Tag, 01:23:20 UTC
    store.record([
        Sample(1, 0, DAY0 + DAY - 1, False),      # 23:59:59 am ersten Tag
        Sample(1, 0, DAY0 + DAY, True),           # 00:00:00 am zweiten Tag
        Sample(1, 0, DAY0 + DAY + 60, True),
        Sample(1, 0, DAY0 - 1, True),             # vor dem Zeitraum
        Sample(1, 0, DAY0 + 3 * DAY, False),      # nach heute
        Sample(1, 0, now, True),
    ])
    put_hourly(db, 1, 0, DAY0 + 2 * DAY, 60, 15)  # heute 00:00 als Stundenwert
    result = store.trend(1, days=3, now=now)
    first = DAY0 // DAY
    assert result == [
        {"day": _label(first), "up_pct": 0.0, "n": 1},
        {"day": _label(first + 1), "up_pct": 100.0, "n": 2},
        {"day": _label(first + 2), "up_pct": round(100 * 16 / 61, 2), "n": 61},
    ]
    assert result[0]["day"] == "2025-10-09"


def test_trend_days_without_values_and_limits(store) -> None:  # type: ignore[no-untyped-def]
    store.record([Sample(1, 0, NOW - 5 * DAY, True)])
    result = store.trend(1, 0, days=30, now=NOW)
    assert len(result) == 30
    assert result[-1]["day"] == _label(NOW // DAY)
    assert [r["n"] for r in result].count(1) == 1
    assert all(r["up_pct"] is None for r in result if r["n"] == 0)
    assert result[-6] == {"day": _label(NOW // DAY - 5), "up_pct": 100.0, "n": 1}
    assert len(store.trend(1, days=0, now=NOW)) == 1
    assert len(store.trend(1, days=100_000, now=NOW)) == 3660
    with pytest.raises(ValueError):
        store.trend(1, now=-1)


# --- counts / size --------------------------------------------------------------------------------


def test_counts_and_size(store, db) -> None:  # type: ignore[no-untyped-def]
    assert store.counts() == {"raw": 0, "hourly": 0}
    store.record(Sample(1, 0, NOW + i, True) for i in range(5))
    put_hourly(db, 1, 0, DAY0, 60, 60)
    assert store.counts() == {"raw": 5, "hourly": 1}
    assert store.size_bytes() > 0
