"""Messwerte der Überwachung: speichern, Verfügbarkeit, Verläufe, Verdichtung (BAUPLAN §20, §24). (Agent metrics)

Rohwerte (`samples`, ts in Unix-Sekunden UTC) bleiben RAW_KEEP_DAYS Tage. `compact()` fasst ältere Rohwerte je
Messreihe und voller Stunde zu Stundenwerten (`samples_hourly`) zusammen. Alle Auswertungen lesen beide Tabellen;
Stundenwerte zählen mit ihren `n` und `up`, ihre Antwortzeit mit dem Gewicht `up`.

Verfügbarkeit = gute Messwerte (ok = 1) / alle Messwerte im Zeitraum. Pausen sind Lücken, keine Ausfälle.

Die Datenbank gilt als nicht vertrauenswürdige Eingabe: Die Abfragen klemmen `n`/`up` auf 0 ≤ up ≤ n, werten nur
Antwortzeiten aus, die Zahlen zwischen 0 und 1e9 ms sind, und vertragen fremde Typen in allen Spalten.

Messreihen findet ein rekursiver Sprung durch den Primärschlüssel (`_series_cte`): O(Reihen · log n) statt eines
Vollscans. Damit bleiben Karte, Verdichtung und Aufräumen auch bei 1,3 Mio. Rohwerten schnell.
"""

from __future__ import annotations

import logging
import math
from collections.abc import Iterable
from datetime import date, timedelta
from typing import Any

from netscan.core.db import Database
from netscan.core.models import Sample

log = logging.getLogger(__name__)

RAW_KEEP_DAYS = 30
HOURLY_KEEP_DAYS = 730

HOUR_S = 3600
DAY_S = 86400

_MAX_ID = 2**63 - 1  # SQLite INTEGER
_MAX_TS = 2**37  # ≈ Jahr 6325 – größere Zeitstempel sind Unsinn und würden Datumsrechnungen sprengen
_MAX_POINTS_LIMIT = 10_000
_MAX_TREND_DAYS = 3660
_SERIES_LIMIT = 100_000  # Sicherheitsnetz für den rekursiven Reihen-Sprung

# Eimergrößen für Diagramme: Vielfache von 60 s; ab einer Stunde Teiler von 86400, ab einem Tag ganze Tage.
# Damit liegen Eimergrenzen auf vollen Minuten/Stunden/UTC-Tagen und Stundenwerte fallen in genau einen Eimer.
_NICE_BUCKETS = (60, 120, 180, 300, 600, 900, 1200, 1800, 3600, 7200, 10800, 14400, 21600, 43200, 86400)

# --- SQL-Bausteine (nur Konstanten, nie Eingaben) ---------------------------------------------------

_RTT_MAX_SQL = "1e9"


def _num_ok(col: str) -> str:
    """Spalte ist eine Zahl zwischen 0 und 1e9 (schließt Text, NULL, negative und unendliche Werte aus)."""
    return f"(typeof({col}) IN ('integer', 'real') AND {col} >= 0 AND {col} <= {_RTT_MAX_SQL})"


# Rohwert gut und mit brauchbarer Antwortzeit
_RAW_GOOD_RTT = f"(ok = 1 AND {_num_ok('rtt_ms')})"
_X_GOOD_RTT = f"(x.ok = 1 AND {_num_ok('x.rtt_ms')})"
# Stundenwert: n und up geklemmt (0 ≤ up ≤ n), fremde Typen zählen als 0
_H_N = "(CASE WHEN typeof(n) IN ('integer', 'real') AND n > 0 THEN CAST(n AS INTEGER) ELSE 0 END)"
_H_UP = f"(CASE WHEN typeof(up) IN ('integer', 'real') AND up > 0 THEN MIN(CAST(up AS INTEGER), {_H_N}) ELSE 0 END)"


def _floor_hour(col: str) -> str:
    """Volle Stunde (abgerundet, auch für negative Werte) eines Zeitstempels in SQL."""
    v = f"CAST({col} AS INTEGER)"
    return f"({v} - (({v} % {HOUR_S}) + {HOUR_S}) % {HOUR_S})"


def _series_cte(table: str) -> str:
    """CTE s(t, c): alle Messreihen einer Tabelle, gefunden per Sprung durch den Primärschlüssel.

    Jeder Schritt sucht die nächste Prüfung desselben Ziels, sonst das nächste Ziel mit seiner kleinsten Prüfung –
    jeweils eine Indexsuche. Die letzte Zeile ist (NULL, NULL); Nutzer filtern mit `WHERE t IS NOT NULL`.
    """
    if table not in ("samples", "samples_hourly"):
        raise ValueError(table)
    next_check = f"(SELECT MIN(check_id) FROM {table} WHERE target_id = s.t AND check_id > s.c)"
    next_target = f"(SELECT MIN(target_id) FROM {table} WHERE target_id > s.t)"
    return f"""s(t, c) AS (
        SELECT m, (SELECT MIN(check_id) FROM {table} WHERE target_id = m)
        FROM (SELECT MIN(target_id) AS m FROM {table})
        UNION ALL
        SELECT CASE WHEN {next_check} IS NULL THEN {next_target} ELSE s.t END,
               COALESCE({next_check}, (SELECT MIN(check_id) FROM {table} WHERE target_id = {next_target}))
        FROM s WHERE s.t IS NOT NULL
        LIMIT {_SERIES_LIMIT}
    )"""


_SERIES_RAW = _series_cte("samples")
_SERIES_HOURLY = _series_cte("samples_hourly")


def _raw_range(start: str, end: str) -> str:
    return f"FROM samples WHERE target_id = s.t AND check_id = s.c AND ts >= {start} AND ts < {end}"


def _hourly_range(start: str, end: str) -> str:
    return f"FROM samples_hourly WHERE target_id = s.t AND check_id = s.c AND hour >= {start} AND hour < {end}"


# Karte: je Reihe zwei getrennte Fenster [s7, s24) und [s24, until) – korrelierte Teilabfragen nutzen den
# Primärschlüssel und lesen nur die Werte der letzten 7 Tage (schneller als ein Vollscan mit GROUP BY).
_MAP_RAW_SQL = f"""WITH RECURSIVE {_SERIES_RAW}
SELECT t, c,
    (SELECT COUNT(*) {_raw_range(':s7', ':s24')}),
    (SELECT TOTAL(ok = 1) {_raw_range(':s7', ':s24')}),
    (SELECT COUNT(*) {_raw_range(':s24', ':until')}),
    (SELECT TOTAL(ok = 1) {_raw_range(':s24', ':until')})
FROM s WHERE t IS NOT NULL"""

_MAP_HOURLY_SQL = f"""WITH RECURSIVE {_SERIES_HOURLY}
SELECT t, c,
    (SELECT TOTAL({_H_N}) {_hourly_range(':s7', ':s24')}),
    (SELECT TOTAL({_H_UP}) {_hourly_range(':s7', ':s24')}),
    (SELECT TOTAL({_H_N}) {_hourly_range(':s24', ':until')}),
    (SELECT TOTAL({_H_UP}) {_hourly_range(':s24', ':until')})
FROM s WHERE t IS NOT NULL"""

_SERIES_RAW_SQL = f"""
SELECT CAST((ts - :start) / :bucket AS INTEGER) AS i,
       COUNT(*), TOTAL(ok = 1),
       TOTAL(CASE WHEN {_RAW_GOOD_RTT} THEN 1 END),
       TOTAL(CASE WHEN {_RAW_GOOD_RTT} THEN rtt_ms END),
       MIN(CASE WHEN {_RAW_GOOD_RTT} THEN rtt_ms END),
       MAX(CASE WHEN {_RAW_GOOD_RTT} THEN rtt_ms END)
FROM samples
WHERE target_id = :t AND check_id = :c AND ts >= :since AND ts < :until
GROUP BY i"""

_SERIES_HOURLY_SQL = f"""
SELECT CAST((hour - :start) / :bucket AS INTEGER) AS i,
       TOTAL({_H_N}), TOTAL({_H_UP}),
       TOTAL(CASE WHEN {_num_ok('rtt_avg')} THEN {_H_UP} END),
       TOTAL(CASE WHEN {_num_ok('rtt_avg')} THEN rtt_avg * {_H_UP} END),
       MIN(CASE WHEN {_num_ok('rtt_min')} AND {_H_UP} > 0 THEN rtt_min END),
       MAX(CASE WHEN {_num_ok('rtt_max')} AND {_H_UP} > 0 THEN rtt_max END)
FROM samples_hourly
WHERE target_id = :t AND check_id = :c AND hour >= :since AND hour < :until
GROUP BY i"""

# Verdichtung: Rohwerte vor der Grenze je (Ziel, Prüfung, Stunde) zusammenfassen und mit vorhandenen
# Stundenwerten zusammenführen. Näherung: Das Gewicht einer Stunden-Antwortzeit ist `up` (Zahl guter Messwerte),
# weil die Zahl guter Messwerte MIT Antwortzeit nicht gespeichert wird. Exakt, solange gute Messwerte immer eine
# Antwortzeit haben; zusammengeführt wird ohnehin nur, wenn Rohwerte nachträglich in eine schon verdichtete Stunde
# fallen (Uhr zurückgestellt, nachgereichte Werte).
_COMPACT_INSERT_SQL = f"""WITH RECURSIVE {_SERIES_RAW}
INSERT INTO samples_hourly (target_id, check_id, hour, n, up, rtt_avg, rtt_min, rtt_max)
SELECT x.target_id, x.check_id, {_floor_hour('x.ts')} AS h,
       COUNT(*), SUM(x.ok = 1),
       AVG(CASE WHEN {_X_GOOD_RTT} THEN x.rtt_ms END),
       MIN(CASE WHEN {_X_GOOD_RTT} THEN x.rtt_ms END),
       MAX(CASE WHEN {_X_GOOD_RTT} THEN x.rtt_ms END)
FROM s CROSS JOIN samples AS x ON x.target_id = s.t AND x.check_id = s.c AND x.ts < :boundary
WHERE s.t IS NOT NULL
GROUP BY x.target_id, x.check_id, h
ON CONFLICT (target_id, check_id, hour) DO UPDATE SET
    n = {_H_N} + excluded.n,
    up = {_H_UP} + excluded.up,
    rtt_avg = CASE
        WHEN excluded.rtt_avg IS NULL THEN CASE WHEN {_num_ok('rtt_avg')} THEN rtt_avg END
        WHEN NOT {_num_ok('rtt_avg')} OR {_H_UP} = 0 THEN excluded.rtt_avg
        ELSE (rtt_avg * {_H_UP} + excluded.rtt_avg * MAX(excluded.up, 1)) / ({_H_UP} + MAX(excluded.up, 1))
    END,
    rtt_min = CASE
        WHEN excluded.rtt_min IS NULL THEN CASE WHEN {_num_ok('rtt_min')} THEN rtt_min END
        WHEN NOT {_num_ok('rtt_min')} THEN excluded.rtt_min
        ELSE MIN(rtt_min, excluded.rtt_min)
    END,
    rtt_max = CASE
        WHEN excluded.rtt_max IS NULL THEN CASE WHEN {_num_ok('rtt_max')} THEN rtt_max END
        WHEN NOT {_num_ok('rtt_max')} THEN excluded.rtt_max
        ELSE MAX(rtt_max, excluded.rtt_max)
    END"""

_COMPACT_DELETE_SQL = f"""WITH RECURSIVE {_SERIES_RAW}
DELETE FROM samples
WHERE (target_id, check_id) IN (SELECT t, c FROM s WHERE t IS NOT NULL) AND ts < :boundary"""

_HOURLY_RETENTION_SQL = f"""WITH RECURSIVE {_SERIES_HOURLY}
DELETE FROM samples_hourly
WHERE (target_id, check_id) IN (SELECT t, c FROM s WHERE t IS NOT NULL) AND hour < :boundary"""


# --- Hilfsfunktionen ---------------------------------------------------------------------------------


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _time(value: object, name: str, *, bound: bool = False) -> int:
    """Zeitpunkt in Unix-Sekunden als int. ValueError bei Unsinn.

    float wird abgerundet; als Grenze eines Bereichs [since, until) aufgerundet (bound=True), denn für ganzzahlige
    ts gilt ts ≥ x ⇔ ts ≥ ceil(x) und ts < x ⇔ ts < ceil(x).
    """
    if _is_int(value):
        result = int(value)  # type: ignore[call-overload]
    elif isinstance(value, float) and math.isfinite(value):
        result = math.ceil(value) if bound else math.floor(value)
    else:
        raise ValueError(f"{name}: kein gültiger Zeitpunkt ({value!r})")
    if not -_MAX_TS <= result <= _MAX_TS:
        raise ValueError(f"{name}: Zeitpunkt außerhalb des gültigen Bereichs ({value!r})")
    return result


def _require_id(value: object, name: str) -> int:
    if not _is_int(value) or not -_MAX_ID <= value <= _MAX_ID:  # type: ignore[operator]
        raise ValueError(f"{name}: keine gültige Kennung ({value!r})")
    return int(value)  # type: ignore[call-overload]


def _key(t: object, c: object) -> tuple[int, int] | None:
    """Reihenschlüssel aus der Datenbank – fremde Typen und unmögliche Werte werden übergangen."""
    if _is_int(t) and _is_int(c) and t >= 1 and c >= 0:  # type: ignore[operator]
        return int(t), int(c)  # type: ignore[call-overload]
    return None


def _avail(n: float, up: float) -> dict[str, Any]:
    n_i = max(int(n), 0)
    up_i = min(max(int(up), 0), n_i)
    return {"up_pct": round(100.0 * up_i / n_i, 2) if n_i else None, "samples": n_i, "up": up_i}


def _sample_row(sample: object) -> tuple[int, int, int, int, float | None] | None:
    """Prüft einen Messwert; None = ungültig (wird übersprungen)."""
    try:
        target_id = sample.target_id  # type: ignore[attr-defined]
        check_id = sample.check_id  # type: ignore[attr-defined]
        ts = sample.ts  # type: ignore[attr-defined]
        ok = sample.ok  # type: ignore[attr-defined]
        rtt = sample.rtt_ms  # type: ignore[attr-defined]
    except AttributeError:
        return None
    if not _is_int(target_id) or not 1 <= target_id <= _MAX_ID:
        return None
    if not _is_int(check_id) or not 0 <= check_id <= _MAX_ID:
        return None
    if not _is_int(ts) or not 0 <= ts <= _MAX_TS:
        return None
    if isinstance(ok, bool):
        ok_i = int(ok)
    elif _is_int(ok) and ok in (0, 1):
        ok_i = int(ok)
    else:
        return None
    rtt_f: float | None = None
    if rtt is not None:
        if isinstance(rtt, bool) or not isinstance(rtt, (int, float)):
            return None
        try:
            rtt_f = float(rtt)
        except OverflowError:
            return None
        if not math.isfinite(rtt_f) or rtt_f < 0:
            return None
    return int(target_id), int(check_id), int(ts), ok_i, rtt_f


def _bucket_seconds(span: int, max_points: int) -> int:
    """Kleinste „runde“ Eimergröße (Vielfaches von 60 s) mit ceil(span / bucket) ≤ max_points."""
    need = max(1, -(-span // max_points))
    for bucket in _NICE_BUCKETS:
        if bucket >= need:
            return bucket
    return -(-need // DAY_S) * DAY_S


def _round(value: float | None) -> float | None:
    if value is None or not math.isfinite(value):
        return None
    return round(value, 2)


def _day_label(day_index: int) -> str:
    """UTC-Tag als „YYYY-MM-DD“ aus der Tageszahl seit 1970-01-01 (auch vor 1970, ohne gmtime)."""
    return (date(1970, 1, 1) + timedelta(days=day_index)).isoformat()


class MetricsStore:
    """Messwerte in `samples` (Rohwerte) und `samples_hourly` (Stundenwerte). Thread-sicher über die Datenbank-Sperre."""

    def __init__(self, db: Database) -> None:
        self.db = db

    # --- Schreiben ------------------------------------------------------------------------------------
    def record(self, samples: Iterable[Sample]) -> None:
        """Speichert Messwerte in einer Transaktion; gleicher Schlüssel (Ziel, Prüfung, ts) ersetzt.

        Ungültige Werte (target_id < 1, check_id < 0, ts kein int bzw. außerhalb 0…2^37, ok kein bool/0/1,
        rtt_ms nicht endlich oder < 0) werden übersprungen und gesammelt auf WARNING gemeldet.
        """
        rows: list[tuple[int, int, int, int, float | None]] = []
        skipped = 0
        for sample in samples:
            row = _sample_row(sample)
            if row is None:
                skipped += 1
            else:
                rows.append(row)
        if skipped:
            log.warning("Messwerte: %d ungültige Werte übersprungen", skipped)
        if not rows:
            return
        with self.db.transaction() as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO samples (target_id, check_id, ts, ok, rtt_ms) VALUES (?, ?, ?, ?, ?)", rows
            )

    # --- Auswertung -----------------------------------------------------------------------------------
    def availability(self, target_id: int, check_id: int = 0, *, since: int, until: int) -> dict[str, Any]:
        """Verfügbarkeit im Zeitraum [since, until): {up_pct (None ohne Werte), samples, up}.

        Rohwerte mit since ≤ ts < until plus Stundenwerte mit since ≤ hour < until (ganze Stunde zählt).
        """
        t = _require_id(target_id, "target_id")
        c = _require_id(check_id, "check_id")
        lo = max(_time(since, "since", bound=True), 0)
        hi = _time(until, "until", bound=True)
        if hi <= lo:
            return _avail(0, 0)
        params = (t, c, lo, hi)
        with self.db.lock:  # beide Abfragen sehen denselben Stand (keine Verdichtung dazwischen)
            raw = self.db.query_one(
                "SELECT COUNT(*), TOTAL(ok = 1) FROM samples "
                "WHERE target_id = ? AND check_id = ? AND ts >= ? AND ts < ?",
                params,
            )
            hourly = self.db.query_one(
                f"SELECT TOTAL({_H_N}), TOTAL({_H_UP}) FROM samples_hourly "
                "WHERE target_id = ? AND check_id = ? AND hour >= ? AND hour < ?",
                params,
            )
        n = (raw[0] if raw else 0) + (hourly[0] if hourly else 0)
        up = (raw[1] if raw else 0) + (hourly[1] if hourly else 0)
        return _avail(n, up)

    def availability_map(self, now: int) -> dict[tuple[int, int], dict[str, dict[str, Any]]]:
        """Verfügbarkeit aller vorhandenen Messreihen: {(target_id, check_id): {"24h": …, "7d": …}}.

        Fenster: [now − 24 h, now] bzw. [now − 7 d, now] (der Messwert genau zu `now` zählt mit). Eine Reihe mit
        Werten nur außerhalb der Fenster erscheint mit up_pct None. Zwei Abfragen insgesamt, nicht eine je Reihe.
        """
        now_i = _time(now, "now")
        params = {"s7": now_i - 7 * DAY_S, "s24": now_i - DAY_S, "until": now_i + 1}
        acc: dict[tuple[int, int], list[float]] = {}
        with self.db.lock:
            for sql in (_MAP_RAW_SQL, _MAP_HOURLY_SQL):
                for row in self.db.query(sql, params):
                    key = _key(row[0], row[1])
                    if key is None:
                        continue
                    a = acc.setdefault(key, [0.0, 0.0, 0.0, 0.0])
                    for i in range(4):
                        a[i] += row[2 + i] or 0
        out: dict[tuple[int, int], dict[str, dict[str, Any]]] = {}
        for key, (n_old, up_old, n24, up24) in acc.items():
            out[key] = {"24h": _avail(n24, up24), "7d": _avail(n_old + n24, up_old + up24)}
        return out

    def series(
        self, target_id: int, check_id: int = 0, *, since: int, until: int, max_points: int = 400
    ) -> dict[str, Any]:
        """Verlauf für Diagramme: {"bucket_s", "points": [{t (ms), rtt_avg, rtt_min, rtt_max, up_pct, n}]}.

        bucket_s ist eine runde Eimergröße (Vielfaches von 60, mindestens 60), sodass höchstens max_points + 1
        Eimer entstehen. Eimer beginnen bei floor(since / bucket_s) · bucket_s; gelesen wird [since, until).
        Antwortzeiten nur aus guten Messwerten mit Antwortzeit; Stundenwerte zählen mit n/up, ihre Antwortzeit mit
        Gewicht up und liegen im Eimer ihres Stundenbeginns. Eimer ohne Werte: n = 0, alles andere None (Lücke).
        """
        t = _require_id(target_id, "target_id")
        c = _require_id(check_id, "check_id")
        lo = max(_time(since, "since", bound=True), 0)
        hi = _time(until, "until", bound=True)
        try:
            points_max = int(max_points)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError(f"max_points: ungültig ({max_points!r})") from exc
        points_max = min(max(points_max, 1), _MAX_POINTS_LIMIT)
        if hi <= lo:
            return {"bucket_s": _NICE_BUCKETS[0], "points": []}
        bucket = _bucket_seconds(hi - lo, points_max)
        start = lo // bucket * bucket
        count = -(-(hi - start) // bucket)
        # je Eimer: n, up, Gewicht der Antwortzeit, Summe der Antwortzeiten, min, max
        n = [0.0] * count
        up = [0.0] * count
        weight = [0.0] * count
        rtt_sum = [0.0] * count
        rtt_min: list[float | None] = [None] * count
        rtt_max: list[float | None] = [None] * count
        params = {"t": t, "c": c, "since": lo, "until": hi, "start": start, "bucket": bucket}
        with self.db.lock:
            rows = self.db.query(_SERIES_RAW_SQL, params) + self.db.query(_SERIES_HOURLY_SQL, params)
        for row in rows:
            i = row[0]
            if not _is_int(i) or not 0 <= i < count:
                continue
            n[i] += row[1] or 0
            up[i] += row[2] or 0
            weight[i] += row[3] or 0
            rtt_sum[i] += row[4] or 0
            lo_v, hi_v = row[5], row[6]
            if isinstance(lo_v, (int, float)):
                rtt_min[i] = lo_v if rtt_min[i] is None else min(rtt_min[i], lo_v)  # type: ignore[type-var]
            if isinstance(hi_v, (int, float)):
                rtt_max[i] = hi_v if rtt_max[i] is None else max(rtt_max[i], hi_v)  # type: ignore[type-var]
        points: list[dict[str, Any]] = []
        for i in range(count):
            n_i = int(n[i])
            point: dict[str, Any] = {
                "t": (start + i * bucket) * 1000,
                "rtt_avg": None,
                "rtt_min": None,
                "rtt_max": None,
                "up_pct": None,
                "n": n_i,
            }
            if n_i > 0:
                up_i = min(int(up[i]), n_i)
                point["up_pct"] = round(100.0 * up_i / n_i, 2)
                if weight[i] > 0:
                    point["rtt_avg"] = _round(rtt_sum[i] / weight[i])
                    point["rtt_min"] = _round(rtt_min[i])
                    point["rtt_max"] = _round(rtt_max[i])
            points.append(point)
        return {"bucket_s": bucket, "points": points}

    def trend(self, target_id: int, check_id: int = 0, *, days: int = 30, now: int) -> list[dict[str, Any]]:
        """Verfügbarkeit je UTC-Tag der letzten `days` Tage einschließlich heute, älteste zuerst.

        [{day "YYYY-MM-DD", up_pct, n}]; Tage ohne Werte: n = 0, up_pct None. days wird auf 1…3660 begrenzt.
        """
        t = _require_id(target_id, "target_id")
        c = _require_id(check_id, "check_id")
        now_i = _time(now, "now")
        if now_i < 0:
            raise ValueError(f"now: Zeitpunkt vor 1970 ({now!r})")
        try:
            day_count = int(days)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError(f"days: ungültig ({days!r})") from exc
        day_count = min(max(day_count, 1), _MAX_TREND_DAYS)
        today = now_i // DAY_S
        first = (today - day_count + 1) * DAY_S
        params = {"t": t, "c": c, "first": first, "end": (today + 1) * DAY_S}
        with self.db.lock:
            rows = self.db.query(
                "SELECT CAST((ts - :first) / 86400 AS INTEGER) AS d, COUNT(*), TOTAL(ok = 1) FROM samples "
                "WHERE target_id = :t AND check_id = :c AND ts >= :first AND ts < :end GROUP BY d",
                params,
            ) + self.db.query(
                f"SELECT CAST((hour - :first) / 86400 AS INTEGER) AS d, TOTAL({_H_N}), TOTAL({_H_UP}) "
                "FROM samples_hourly WHERE target_id = :t AND check_id = :c AND hour >= :first AND hour < :end "
                "GROUP BY d",
                params,
            )
        n = [0.0] * day_count
        up = [0.0] * day_count
        for row in rows:
            d = row[0]
            if not _is_int(d) or not 0 <= d < day_count:
                continue
            n[d] += row[1] or 0
            up[d] += row[2] or 0
        out: list[dict[str, Any]] = []
        for d in range(day_count):
            a = _avail(n[d], up[d])
            out.append({"day": _day_label(first // DAY_S + d), "up_pct": a["up_pct"], "n": a["samples"]})
        return out

    # --- Pflege ---------------------------------------------------------------------------------------
    def compact(self, now: int, keep_days: int = RAW_KEEP_DAYS) -> int:
        """Verdichtet Rohwerte vor der Grenze zu Stundenwerten und löscht sie; entfernt alte Stundenwerte.

        Grenze = volle Stunde von now − keep_days · 86400 (abgerundet) – davor liegen nur vollständige Stunden.
        n und up bleiben erhalten (Verfügbarkeit über ganze Stunden unverändert). Eine Transaktion, idempotent.
        Rückgabe: Zahl der verdichteten (gelöschten) Rohwerte.
        """
        now_i = _time(now, "now")
        if not _is_int(keep_days) or keep_days < 0:  # type: ignore[operator]
            raise ValueError(f"keep_days: ungültig ({keep_days!r})")
        boundary = (now_i - int(keep_days) * DAY_S) // HOUR_S * HOUR_S
        hourly_boundary = (now_i - HOURLY_KEEP_DAYS * DAY_S) // HOUR_S * HOUR_S
        with self.db.transaction() as conn:
            conn.execute(_COMPACT_INSERT_SQL, {"boundary": boundary})
            before = conn.total_changes
            conn.execute(_COMPACT_DELETE_SQL, {"boundary": boundary})
            removed = conn.total_changes - before
            before = conn.total_changes
            conn.execute(_HOURLY_RETENTION_SQL, {"boundary": hourly_boundary})
            expired = conn.total_changes - before
        if removed or expired:
            log.debug("Messwerte verdichtet: %d Rohwerte, %d alte Stundenwerte entfernt", removed, expired)
        return removed

    def delete_series(self, target_id: int, check_id: int | None = None) -> int:
        """Löscht Roh- und Stundenwerte einer Reihe bzw. (check_id None) aller Reihen des Ziels. Rückgabe: Zeilen."""
        t = _require_id(target_id, "target_id")
        with self.db.transaction() as conn:
            if check_id is None:
                a = conn.execute("DELETE FROM samples WHERE target_id = ?", (t,)).rowcount
                b = conn.execute("DELETE FROM samples_hourly WHERE target_id = ?", (t,)).rowcount
            else:
                c = _require_id(check_id, "check_id")
                a = conn.execute("DELETE FROM samples WHERE target_id = ? AND check_id = ?", (t, c)).rowcount
                b = conn.execute("DELETE FROM samples_hourly WHERE target_id = ? AND check_id = ?", (t, c)).rowcount
        return max(a, 0) + max(b, 0)

    def prune_orphans(self, valid: set[tuple[int, int]]) -> int:
        """Löscht alle Messreihen, die nicht in `valid` stehen (Ziel oder Prüfung gibt es nicht mehr).

        Vorhandene Reihen findet der Sprung durch den Primärschlüssel; gelöscht wird je verwaister Reihe über den
        Primärschlüssel – kein Vollscan, keine Schleife je Zeile. Auch Reihen mit unsinnigen Schlüsseln (fremde
        Typen) gelten als verwaist. Rückgabe: Zahl gelöschter Zeilen (Roh- und Stundenwerte).
        """
        keep: set[tuple[int, int]] = set()
        for item in valid:
            try:
                t, c = item
            except (TypeError, ValueError):
                continue
            if _is_int(t) and _is_int(c):
                keep.add((int(t), int(c)))
        with self.db.transaction() as conn:
            present: set[tuple[Any, Any]] = set()
            for cte in (_SERIES_RAW, _SERIES_HOURLY):
                present.update(
                    (r[0], r[1]) for r in conn.execute(f"WITH RECURSIVE {cte} SELECT t, c FROM s WHERE t IS NOT NULL")
                )
            orphans = [p for p in present if not (_is_int(p[0]) and _is_int(p[1]) and p in keep)]
            if not orphans:
                return 0
            before = conn.total_changes
            conn.executemany("DELETE FROM samples WHERE target_id = ? AND check_id = ?", orphans)
            conn.executemany("DELETE FROM samples_hourly WHERE target_id = ? AND check_id = ?", orphans)
            removed = conn.total_changes - before
        if removed:
            log.info("Messwerte: %d Werte aus %d verwaisten Messreihen entfernt", removed, len(orphans))
        return removed

    def size_bytes(self) -> int:
        return self.db.size_bytes()

    def counts(self) -> dict[str, int]:
        """{"raw": Zahl der Rohwerte, "hourly": Zahl der Stundenwerte}."""
        with self.db.lock:
            raw = self.db.query_one("SELECT COUNT(*) FROM samples")
            hourly = self.db.query_one("SELECT COUNT(*) FROM samples_hourly")
        return {"raw": int(raw[0]) if raw else 0, "hourly": int(hourly[0]) if hourly else 0}
