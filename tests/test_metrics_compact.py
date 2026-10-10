"""Messwerte (BAUPLAN §24): Verdichtung, Aufbewahrung, Löschen, Waisen, Leistung, Gleichzeitigkeit."""

from __future__ import annotations

import sqlite3
import threading
import time

import pytest

from netscan.core.db import Database
from netscan.core.metrics import HOURLY_KEEP_DAYS, RAW_KEEP_DAYS, MetricsStore
from netscan.core.models import Sample

DAY = 86400
HOUR = 3600
H0 = 20370 * DAY + 6 * HOUR  # 2025-10-09 06:00:00 UTC, volle Stunde


@pytest.fixture
def db(tmp_path):  # type: ignore[no-untyped-def]
    d = Database(tmp_path / "metrics.sqlite3")
    yield d
    d.close()


@pytest.fixture
def store(db) -> MetricsStore:  # type: ignore[no-untyped-def]
    return MetricsStore(db)


def hourly_rows(db: Database) -> list[tuple]:
    return [tuple(r) for r in db.query("SELECT * FROM samples_hourly ORDER BY target_id, check_id, hour")]


def put_hourly(db: Database, t: int, c: int, hour: object, n: object, up: object,
               avg: object = None, mn: object = None, mx: object = None) -> None:
    db.execute("INSERT INTO samples_hourly VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (t, c, hour, n, up, avg, mn, mx))


def _pattern(hours: int, t: int = 1, c: int = 0) -> list[Sample]:
    """Je Stunde 60 Messwerte; jeder 4. schlecht, jeder 7. gute ohne Antwortzeit."""
    out = []
    for i in range(hours * 60):
        ok = i % 4 != 0
        rtt = None if (not ok or i % 7 == 0) else float(i % 10) + 0.5
        out.append(Sample(t, c, H0 + i * 60, ok, rtt))
    return out


def _expected_hour(samples: list[Sample], hour: int) -> tuple:
    rows = [s for s in samples if hour <= s.ts < hour + HOUR]
    rtts = [s.rtt_ms for s in rows if s.ok and s.rtt_ms is not None]
    return (len(rows), sum(1 for s in rows if s.ok), sum(rtts) / len(rtts), min(rtts), max(rtts))


# --- Verdichtung ----------------------------------------------------------------------------------


def test_compact_exact_hourly_values_and_boundary(store, db) -> None:  # type: ignore[no-untyped-def]
    samples = _pattern(5)
    store.record(samples)
    # Grenze = volle Stunde von now - 30 Tage (abgerundet) = H0 + 3 h
    now = H0 + 3 * HOUR + 30 * DAY + 1799
    removed = store.compact(now)
    assert removed == 180
    rows = hourly_rows(db)
    assert [r[2] for r in rows] == [H0, H0 + HOUR, H0 + 2 * HOUR]
    for row in rows:
        n, up, avg, mn, mx = _expected_hour(samples, row[2])
        assert row[:5] == (1, 0, row[2], n, up)
        assert row[5] == pytest.approx(avg) and (row[6], row[7]) == (mn, mx)
    remaining = [r["ts"] for r in db.query("SELECT ts FROM samples ORDER BY ts")]
    assert remaining[0] == H0 + 3 * HOUR and len(remaining) == 120
    assert store.counts() == {"raw": 120, "hourly": 3}


def test_compact_keeps_last_sample_before_boundary_hour_exactly(store, db) -> None:  # type: ignore[no-untyped-def]
    boundary = H0 + 10 * HOUR
    store.record([Sample(1, 0, boundary - 1, True, 1.0), Sample(1, 0, boundary, False)])
    assert store.compact(boundary + RAW_KEEP_DAYS * DAY) == 1
    assert [r["ts"] for r in db.query("SELECT ts FROM samples")] == [boundary]
    assert hourly_rows(db) == [(1, 0, boundary - HOUR, 1, 1, 1.0, 1.0, 1.0)]


def test_compact_is_idempotent(store, db) -> None:  # type: ignore[no-untyped-def]
    store.record(_pattern(6) + _pattern(6, t=2, c=7))
    now = H0 + 4 * HOUR + 30 * DAY
    assert store.compact(now) == 480
    snapshot = (hourly_rows(db), store.counts())
    assert store.compact(now) == 0
    assert store.compact(now + 1800) == 0  # dieselbe Grenzstunde
    assert (hourly_rows(db), store.counts()) == snapshot


def test_compact_keeps_availability_series_and_trend(store) -> None:  # type: ignore[no-untyped-def]
    samples = _pattern(30) + _pattern(30, t=3, c=0)
    store.record(samples)
    since, until = H0, H0 + 30 * HOUR
    now = H0 + 20 * HOUR + 30 * DAY
    before = {
        "avail": [store.availability(t, since=since + k * HOUR, until=until) for t in (1, 3) for k in (0, 5, 19)],
        "series": [[(p["t"], p["n"], p["up_pct"]) for p in store.series(t, since=H0 - 4 * DAY, until=until + 25 * DAY)["points"]]
                   for t in (1, 3)],
        "trend": [store.trend(t, days=5, now=until) for t in (1, 3)],
        "map": store.availability_map(H0 + 7 * DAY),
    }
    assert store.compact(now) == 2 * 20 * 60
    after = {
        "avail": [store.availability(t, since=since + k * HOUR, until=until) for t in (1, 3) for k in (0, 5, 19)],
        "series": [[(p["t"], p["n"], p["up_pct"]) for p in store.series(t, since=H0 - 4 * DAY, until=until + 25 * DAY)["points"]]
                   for t in (1, 3)],
        "trend": [store.trend(t, days=5, now=until) for t in (1, 3)],
        "map": store.availability_map(H0 + 7 * DAY),
    }
    assert after == before
    assert before["avail"][0]["samples"] == 1800


def test_compact_merges_into_existing_hour(store, db) -> None:  # type: ignore[no-untyped-def]
    put_hourly(db, 1, 0, H0, 10, 8, 5.0, 2.0, 9.0)
    store.record([Sample(1, 0, H0 + 100, True, 20.0), Sample(1, 0, H0 + 200, True, 40.0),
                  Sample(1, 0, H0 + 300, False)])
    assert store.compact(H0 + HOUR + 30 * DAY) == 3
    # rtt_avg mit Gewicht up: (5·8 + 30·2) / 10
    assert hourly_rows(db) == [(1, 0, H0, 13, 10, 10.0, 2.0, 40.0)]


def test_compact_merges_into_untrusted_hour(store, db) -> None:  # type: ignore[no-untyped-def]
    put_hourly(db, 1, 0, H0, -3, "x", "abc", "min", None)
    store.record([Sample(1, 0, H0 + 100, True, 20.0), Sample(1, 0, H0 + 200, False)])
    store.compact(H0 + HOUR + 30 * DAY)
    assert hourly_rows(db) == [(1, 0, H0, 2, 1, 20.0, 20.0, 20.0)]


def test_compact_hour_without_rtt(store, db) -> None:  # type: ignore[no-untyped-def]
    store.record([Sample(1, 0, H0 + 1, False), Sample(1, 0, H0 + 2, True, None)])
    store.compact(H0 + HOUR + 30 * DAY)
    assert hourly_rows(db) == [(1, 0, H0, 2, 1, None, None, None)]
    put_hourly(db, 1, 0, H0 + HOUR, 5, 5, 3.0, 1.0, 6.0)
    store.record([Sample(1, 0, H0 + HOUR + 1, False)])  # Ausfall ohne Antwortzeit: rtt bleibt erhalten
    store.compact(H0 + 2 * HOUR + 30 * DAY)
    assert hourly_rows(db)[1] == (1, 0, H0 + HOUR, 6, 5, 3.0, 1.0, 6.0)


def test_compact_removes_old_hourly_values(store, db) -> None:  # type: ignore[no-untyped-def]
    now = H0 + 1000 * DAY + 1234
    limit = (now - HOURLY_KEEP_DAYS * DAY) // HOUR * HOUR
    put_hourly(db, 1, 0, limit - HOUR, 60, 60)
    put_hourly(db, 1, 0, limit, 60, 60)
    put_hourly(db, 2, 4, limit - 400 * DAY, 60, 60)
    put_hourly(db, 2, 4, now - DAY, 60, 60)
    store.compact(now)
    assert [(r[0], r[1], r[2]) for r in hourly_rows(db)] == [(1, 0, limit), (2, 4, (now - DAY))]


def test_compact_with_keep_days_zero_and_invalid_arguments(store) -> None:  # type: ignore[no-untyped-def]
    store.record(_pattern(2))
    assert store.compact(H0 + 2 * HOUR + 59, keep_days=0) == 120
    with pytest.raises(ValueError):
        store.compact(H0, keep_days=-1)
    with pytest.raises(ValueError):
        store.compact(float("nan"))  # type: ignore[arg-type]


def test_compact_is_one_transaction(store, db) -> None:  # type: ignore[no-untyped-def]
    store.record(_pattern(3))
    put_hourly(db, 9, 0, H0 - 1000 * DAY, 1, 1)
    db.execute("CREATE TRIGGER no_delete BEFORE DELETE ON samples_hourly BEGIN SELECT RAISE(ABORT, 'gesperrt'); END")
    with pytest.raises(sqlite3.DatabaseError):
        store.compact(H0 + 3 * HOUR + 30 * DAY)
    assert store.counts() == {"raw": 180, "hourly": 1}  # alles zurückgerollt
    db.execute("DROP TRIGGER no_delete")
    assert store.compact(H0 + 3 * HOUR + 30 * DAY) == 180


def test_compact_performance_200k(store) -> None:  # type: ignore[no-untyped-def]
    series = [(t, c) for t in range(1, 11) for c in (0, 100 + t)]
    per_series = 10_000
    store.record(Sample(t, c, H0 + i * 60, i % 13 != 0, float(i % 50)) for t, c in series for i in range(per_series))
    assert store.counts()["raw"] == len(series) * per_series
    start = time.perf_counter()
    removed = store.compact(H0 + per_series * 60 + DAY, keep_days=0)
    elapsed = time.perf_counter() - start
    assert removed == 200_000
    assert store.counts()["raw"] == 0
    assert elapsed < 5.0, f"Verdichtung dauerte {elapsed:.2f} s"
    start = time.perf_counter()
    result = store.availability_map(H0 + per_series * 60)
    assert time.perf_counter() - start < 2.0
    assert set(result) == set(series)
    assert result[(1, 0)]["7d"]["samples"] == per_series  # alle Stundenwerte liegen im Fenster [now - 7 d, now]


# --- Löschen und Waisen -----------------------------------------------------------------------------


def test_delete_series_single_check_and_whole_target(store, db) -> None:  # type: ignore[no-untyped-def]
    store.record([Sample(1, 0, H0, True), Sample(1, 5, H0, True), Sample(1, 5, H0 + 60, True), Sample(2, 0, H0, True)])
    put_hourly(db, 1, 5, H0 - DAY, 60, 60)
    put_hourly(db, 1, 0, H0 - DAY, 60, 60)
    assert store.delete_series(1, 5) == 3
    assert store.delete_series(1, 5) == 0
    assert store.delete_series(1) == 2
    assert store.counts() == {"raw": 1, "hourly": 0}
    assert store.delete_series(99) == 0
    with pytest.raises(ValueError):
        store.delete_series("1")  # type: ignore[arg-type]


def test_prune_orphans_removes_series_not_in_valid(store, db) -> None:  # type: ignore[no-untyped-def]
    store.record([Sample(1, 0, H0 + i, True) for i in range(3)])
    store.record([Sample(1, 4, H0, True), Sample(2, 0, H0, True), Sample(3, 9, H0, False)])
    put_hourly(db, 1, 0, H0 - DAY, 60, 60)
    put_hourly(db, 5, 0, H0 - DAY, 60, 60)   # nur Stundenwerte, verwaist
    db.execute("INSERT INTO samples VALUES ('kaputt', 0, ?, 1, NULL)", (H0,))
    valid = {(1, 0), (2, 0), (7, 0), ("x", 1), None, (1,)}  # unsinnige Einträge werden übergangen
    assert store.prune_orphans(valid) == 4  # type: ignore[arg-type]
    left = {(r[0], r[1]) for r in db.query("SELECT target_id, check_id FROM samples")}
    assert left == {(1, 0), (2, 0)}
    assert [(r[0], r[1]) for r in hourly_rows(db)] == [(1, 0)]
    assert store.prune_orphans(valid) == 0  # type: ignore[arg-type]
    assert store.prune_orphans(set()) == 5
    assert store.counts() == {"raw": 0, "hourly": 0}


def test_prune_orphans_uses_no_full_scan(store, db) -> None:  # type: ignore[no-untyped-def]
    store.record(Sample(t, 0, H0 + i * 60, True) for t in range(1, 6) for i in range(2000))
    statements: list[str] = []
    db.conn.set_trace_callback(statements.append)
    try:
        assert store.prune_orphans({(t, 0) for t in range(1, 5)}) == 2000
    finally:
        db.conn.set_trace_callback(None)
    plans = [tuple(r) for r in db.query("EXPLAIN QUERY PLAN DELETE FROM samples WHERE target_id = ? AND check_id = ?", (5, 0))]
    assert any("PRIMARY KEY" in str(p) for p in plans)
    assert len(statements) <= 10


# --- Gleichzeitigkeit -------------------------------------------------------------------------------


def test_record_from_two_threads_while_reading(store) -> None:  # type: ignore[no-untyped-def]
    errors: list[BaseException] = []
    stop = threading.Event()

    def writer(target_id: int) -> None:
        try:
            for batch in range(100):
                store.record(Sample(target_id, 0, H0 + batch * 500 + i, i % 3 != 0, 1.0) for i in range(50))
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    def reader() -> None:
        try:
            while not stop.is_set():
                store.availability_map(H0 + DAY)
                store.series(1, since=H0, until=H0 + DAY)
                store.counts()
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(t,)) for t in (1, 2)]
    read_thread = threading.Thread(target=reader)
    read_thread.start()
    for th in threads:
        th.start()
    for th in threads:
        th.join(30)
    stop.set()
    read_thread.join(30)
    assert errors == []
    assert store.counts()["raw"] == 2 * 100 * 50
    for t in (1, 2):
        a = store.availability(t, since=H0, until=H0 + DAY)
        assert a["samples"] == 5000 and a["up"] == 100 * 33


def test_compact_while_recording(store) -> None:  # type: ignore[no-untyped-def]
    store.record(_pattern(10))
    errors: list[BaseException] = []

    def writer() -> None:
        try:
            for i in range(200):
                store.record([Sample(2, 0, H0 + 40 * DAY + i, True, 1.0)])
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    th = threading.Thread(target=writer)
    th.start()
    removed = store.compact(H0 + 10 * HOUR + 30 * DAY)
    th.join(30)
    assert errors == [] and removed == 600
    assert store.counts() == {"raw": 200, "hourly": 10}
