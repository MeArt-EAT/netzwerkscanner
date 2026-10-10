"""AlertStore (BAUPLAN §25): Öffnen, Schließen, Quittieren, Filter, Häufigkeit, Aufräumen, Gleichzeitigkeit.

Nur Datenbank im tmp_path und EventBus – kein Netz.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone

import pytest

from netscan.core.alerts import ALERT_KEEP_DAYS, LIST_LIMIT_MAX, AlertStore
from netscan.core.db import Database
from netscan.core.events import EventBus
from netscan.core.models import ALERT_RULES, iso_from_ts, ts_from_iso

T0 = 1_760_000_000.0  # 2025-10-09T08:53:20Z
DAY = 86400
MAC = "00:11:32:aa:bb:03"


@pytest.fixture
def db(tmp_path):  # type: ignore[no-untyped-def]
    database = Database(tmp_path / "alerts.sqlite3")
    yield database
    database.close()


@pytest.fixture
def bus() -> EventBus:
    return EventBus()


@pytest.fixture
def store(db, bus) -> AlertStore:  # type: ignore[no-untyped-def]
    return AlertStore(db, bus)


def _events(bus: EventBus, type_: str) -> list[dict]:
    return [e.data for e in bus.history() if e.type == type_]


def _open(  # type: ignore[no-untyped-def]
    store: AlertStore, key: str, *, rule: str = "device_offline", now: float = T0, mac: str | None = MAC, **kw
):
    return store.open(rule=rule, key=key, severity=kw.pop("severity", "warning"), title=kw.pop("title", f"Titel {key}"),
                      message=kw.pop("message", "Meldung"), mac=mac, now=now, **kw)  # fmt: skip


def _ts(day: str, hms: str = "12:00:00") -> float:
    return datetime.fromisoformat(f"{day}T{hms}+00:00").timestamp()


# --- Öffnen ---------------------------------------------------------------------------------------


def test_open_stores_alert_and_publishes(store, bus) -> None:  # type: ignore[no-untyped-def]
    alert = _open(store, f"device_offline:{MAC}", target_id=7, severity="critical", title="NAS ist offline")
    assert alert is not None and alert.id > 0
    assert alert.rule == "device_offline" and alert.key == f"device_offline:{MAC}" and alert.severity == "critical"
    assert alert.title == "NAS ist offline" and alert.mac == MAC and alert.target_id == 7 and alert.check_id is None
    assert alert.opened == iso_from_ts(T0) and alert.closed is None and alert.acknowledged is None and alert.active
    events = _events(bus, "alert.opened")
    assert len(events) == 1 and events[0]["alert"] == alert.to_dict()
    assert events[0]["alert"]["rule_label"] == "Gerät offline" and events[0]["alert"]["severity_label"] == "kritisch"
    assert store.get(alert.id) == alert


def test_open_is_idempotent_per_key(store, bus) -> None:  # type: ignore[no-untyped-def]
    first = _open(store, "device_offline:a")
    assert _open(store, "device_offline:a", now=T0 + 60) is None
    assert _open(store, "device_offline:b") is not None
    assert len(_events(bus, "alert.opened")) == 2
    assert [a.id for a in store.list(state="all") if a.key == "device_offline:a"] == [first.id]


def test_open_again_after_close_creates_new_alert(store) -> None:  # type: ignore[no-untyped-def]
    first = _open(store, "k")
    store.close("k", now=T0 + 60)
    second = _open(store, "k", now=T0 + 120)
    assert second is not None and second.id != first.id
    assert [a.id for a in store.list(state="all")] == [second.id, first.id]


def test_open_normalizes_mac_and_validates(store) -> None:  # type: ignore[no-untyped-def]
    alert = _open(store, "k1", mac="00-11-32-AA-BB-03")
    assert alert.mac == MAC
    with pytest.raises(ValueError):
        _open(store, "k2", rule="telnet_open")
    with pytest.raises(ValueError):
        _open(store, "k3", severity="hoch")
    with pytest.raises(ValueError):
        _open(store, "   ")
    with pytest.raises(ValueError):
        _open(store, "k4", mac="kein-mac")
    with pytest.raises(ValueError):
        _open(store, "k5", target_id="abc")
    assert [a.key for a in store.list(state="all")] == ["k1"]


def test_open_without_now_uses_current_time(store) -> None:  # type: ignore[no-untyped-def]
    import time

    before = time.time()
    alert = store.open(rule="new_device", key="new_device:x", severity="warning", title="Neu", message="")
    assert before - 1 <= ts_from_iso(alert.opened) <= time.time() + 1


def test_open_cleans_texts(store) -> None:  # type: ignore[no-untyped-def]
    alert = _open(store, "k", title="Zeile\neins\x00" + "x" * 500, message="a\tb")
    assert "\n" not in alert.title and "\x00" not in alert.title and len(alert.title) <= 200
    assert alert.message == "a b"
    empty = _open(store, "k2", title="", rule="rtt_high")
    assert empty.title == "Antwortzeit hoch"  # Regelname statt leerem Titel


def test_bus_error_does_not_lose_alert(db) -> None:  # type: ignore[no-untyped-def]
    class BrokenBus:
        def publish(self, *a, **k):  # type: ignore[no-untyped-def]
            raise RuntimeError("Bus kaputt")

    store = AlertStore(db, BrokenBus())  # type: ignore[arg-type]
    alert = _open(store, "k")
    assert alert is not None and store.get(alert.id) is not None
    assert store.close("k") is not None


# --- Schließen ------------------------------------------------------------------------------------


def test_close_sets_time_and_publishes(store, bus) -> None:  # type: ignore[no-untyped-def]
    opened = _open(store, "k")
    closed = store.close("k", now=T0 + 300)
    assert closed is not None and closed.id == opened.id
    assert closed.closed == iso_from_ts(T0 + 300) and not closed.active
    assert _events(bus, "alert.closed") == [{"alert": closed.to_dict()}]
    assert store.close("k", now=T0 + 360) is None
    assert store.close("gibt-es-nicht") is None
    assert store.close("") is None
    assert len(_events(bus, "alert.closed")) == 1


# --- Quittieren -----------------------------------------------------------------------------------


def test_acknowledge_state_alert_keeps_it_active(store, bus) -> None:  # type: ignore[no-untyped-def]
    alert = _open(store, "device_offline:x")
    acked = store.acknowledge(alert.id, now=T0 + 10)
    assert acked.acknowledged == iso_from_ts(T0 + 10) and acked.active  # Zustands-Alert endet von selbst
    assert _events(bus, "alert.acknowledged") == [{"ids": [alert.id]}]
    again = store.acknowledge(alert.id, now=T0 + 99)
    assert again.acknowledged == iso_from_ts(T0 + 10)  # erste Quittung bleibt
    assert len(_events(bus, "alert.acknowledged")) == 1
    # Solange aktiv: kein zweiter Alert für denselben Schlüssel
    assert _open(store, "device_offline:x", now=T0 + 120) is None


def test_acknowledge_event_alert_closes_it(store) -> None:  # type: ignore[no-untyped-def]
    alert = _open(store, f"new_port:{MAC}:80", rule="new_port", severity="info")
    acked = store.acknowledge(alert.id, now=T0 + 10)
    assert acked.acknowledged == iso_from_ts(T0 + 10) and acked.closed == iso_from_ts(T0 + 10)
    assert not acked.active
    # Nach dem Quittieren darf derselbe Port wieder gemeldet werden
    assert _open(store, f"new_port:{MAC}:80", rule="new_port", now=T0 + 20) is not None


@pytest.mark.parametrize("bad", [999, -1, "abc", None, 2**70, 1.5, True])
def test_acknowledge_unknown_raises_lookup(store, bad) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(LookupError):
        store.acknowledge(bad)
    assert store.get(bad) is None


def test_acknowledge_all(store, bus) -> None:  # type: ignore[no-untyped-def]
    a = _open(store, "device_offline:a")
    b = _open(store, "service_down:1", rule="service_down")
    c = _open(store, "new_device:c", rule="new_device")
    d = _open(store, "rtt_high:d", rule="rtt_high", severity="info")
    store.acknowledge(d.id, now=T0 + 5)
    store.close("device_offline:a", now=T0 + 6)  # geschlossen, aber unquittiert
    assert store.acknowledge_all(now=T0 + 30) == 3
    assert _events(bus, "alert.acknowledged")[-1] == {"ids": sorted([a.id, b.id, c.id])}
    assert store.get(c.id).closed == iso_from_ts(T0 + 30)  # Ereignis-Alert beendet
    assert store.get(b.id).active and store.get(b.id).acknowledged == iso_from_ts(T0 + 30)
    assert store.get(d.id).acknowledged == iso_from_ts(T0 + 5)
    n_events = len(_events(bus, "alert.acknowledged"))
    assert store.acknowledge_all(now=T0 + 60) == 0
    assert len(_events(bus, "alert.acknowledged")) == n_events  # nichts zu tun, kein Ereignis
    assert store.counts()["unacked"] == 0


def test_acknowledge_all_repairs_acked_but_open_event_alert(store, db) -> None:  # type: ignore[no-untyped-def]
    alert = _open(store, "new_port:x:22", rule="new_port")
    db.execute("UPDATE alerts SET acknowledged = ? WHERE id = ?", (iso_from_ts(T0), alert.id))  # inkonsistent
    assert store.acknowledge_all(now=T0 + 10) == 0
    assert not store.get(alert.id).active
    assert _open(store, "new_port:x:22", rule="new_port", now=T0 + 20) is not None


# --- Lesen und Filter -----------------------------------------------------------------------------


def test_list_filters_and_order(store) -> None:  # type: ignore[no-untyped-def]
    old = _open(store, "device_offline:old", now=T0 - 3600)
    new = _open(store, "service_down:1", rule="service_down", now=T0)
    middle = _open(store, "new_device:m", rule="new_device", now=T0 - 60, mac="a4:c3:61:00:00:21")
    store.close("device_offline:old", now=T0 - 1800)
    store.acknowledge(middle.id, now=T0)  # Ereignis-Alert: quittiert und beendet
    assert [a.id for a in store.list(state="all")] == [new.id, middle.id, old.id]  # neueste zuerst
    assert [a.id for a in store.list()] == [new.id]
    assert [a.id for a in store.list(state="unacked")] == [new.id, old.id]
    assert [a.id for a in store.list(state="all", mac="A4-C3-61-00-00-21")] == [middle.id]
    assert store.list(state="all", mac="Unsinn") == []
    assert [a.id for a in store.list(state="all", mac="")] == [new.id, middle.id, old.id]
    assert len(store.list(state="all", limit=1)) == 1
    assert len(store.list(state="all", limit=0)) == 1  # auf 1 begrenzt
    with pytest.raises(ValueError):
        store.list(state="offen")
    with pytest.raises(ValueError):
        store.list(state="all", limit="viele")  # type: ignore[arg-type]


def test_list_limit_capped(store, db) -> None:  # type: ignore[no-untyped-def]
    rows = [("device_offline", f"k{i}", "warning", "t", "", iso_from_ts(T0 + i), iso_from_ts(T0 + i + 1)) for i in range(1005)]
    db.executemany("INSERT INTO alerts(rule, key, severity, title, message, opened, closed) VALUES(?,?,?,?,?,?,?)", rows)
    assert len(store.list(state="all", limit=5000)) == LIST_LIMIT_MAX
    assert store.list(state="all", limit=5000)[0].key == "k1004"


def test_counts(store) -> None:  # type: ignore[no-untyped-def]
    assert store.counts() == {"active": 0, "unacked": 0, "by_rule": {r: 0 for r in ALERT_RULES}}
    _open(store, "device_offline:a")
    _open(store, "device_offline:b")
    _open(store, "service_down:1", rule="service_down")
    store.close("device_offline:b")
    port = _open(store, "new_port:x:80", rule="new_port")
    store.acknowledge(port.id)
    counts = store.counts()
    assert counts["active"] == 2 and counts["unacked"] == 3
    assert counts["by_rule"] == {"device_offline": 1, "service_down": 1, "rtt_high": 0, "new_device": 0, "new_port": 0}


def test_untrusted_rows_are_skipped_or_cleaned(store, db) -> None:  # type: ignore[no-untyped-def]
    db.execute(
        "INSERT INTO alerts(rule, key, severity, title, message, mac, opened) VALUES(?,?,?,?,?,?,?)",
        ("delete_all", "x", "warning", "böse", "", None, iso_from_ts(T0)),
    )
    bad_id = int(db.query_one("SELECT id FROM alerts WHERE rule = 'delete_all'")["id"])
    db.execute(
        "INSERT INTO alerts(rule, key, severity, title, message, mac, target_id, opened) VALUES(?,?,?,?,?,?,?,?)",
        ("rtt_high", "rtt_high:y", "extrem", "Zeile\r\nzwei", 42, "keine-mac", "abc", iso_from_ts(T0)),
    )
    assert store.get(bad_id) is None
    with pytest.raises(LookupError):
        store.acknowledge(bad_id)
    alerts = store.list(state="all")
    assert len(alerts) == 1
    a = alerts[0]
    assert a.severity == "warning" and a.title == "Zeile zwei" and a.message == "42"
    assert a.mac is None and a.target_id is None
    assert store.counts()["active"] == 1
    assert store.active_keys() == ["rtt_high:y"]


def test_active_keys_by_target(store) -> None:  # type: ignore[no-untyped-def]
    _open(store, "service_down:1", rule="service_down", target_id=5)
    _open(store, "service_down:2", rule="service_down", target_id=6)
    _open(store, "new_port:x:1", rule="new_port", target_id=5)
    assert store.active_keys(target_id=5) == ["service_down:1", "new_port:x:1"]
    assert store.active_keys(target_id=5, rules={"service_down", "rtt_high"}) == ["service_down:1"]
    assert store.active_keys(target_id=5, rules={"gibt_es_nicht"}) == []
    assert store.active_keys(target_id="kaputt") == []


# --- Häufigkeit -----------------------------------------------------------------------------------


def test_frequency_per_utc_day(store, db) -> None:  # type: ignore[no-untyped-def]
    now = _ts("2026-10-10", "15:00:00")
    _open(store, "a", now=_ts("2026-10-10", "00:00:00"))
    _open(store, "b", now=_ts("2026-10-09", "23:59:59"))
    _open(store, "c", rule="new_port", now=_ts("2026-10-09", "08:00:00"))
    _open(store, "d", rule="service_down", now=_ts("2026-10-07", "08:00:00"))  # außerhalb von 3 Tagen
    # fremde Zeitzonen-Angabe (manipuliert/importiert): 01:30 +02:00 ist 23:30 UTC am Vortag
    db.execute(
        "INSERT INTO alerts(rule, key, severity, title, opened) VALUES('rtt_high', 'e', 'info', 't', '2026-10-10T01:30:00+02:00')"
    )
    db.execute("INSERT INTO alerts(rule, key, severity, title, opened) VALUES('rtt_high', 'f', 'info', 't', 'Unsinn')")
    freq = store.frequency(days=3, now=now)
    assert [d["day"] for d in freq] == ["2026-10-08", "2026-10-09", "2026-10-10"]
    assert freq[0] == {"day": "2026-10-08", **{r: 0 for r in ALERT_RULES}}
    assert freq[1] == {"day": "2026-10-09", "device_offline": 1, "service_down": 0, "rtt_high": 1, "new_device": 0, "new_port": 1}
    assert freq[2] == {"day": "2026-10-10", "device_offline": 1, "service_down": 0, "rtt_high": 0, "new_device": 0, "new_port": 0}
    week = store.frequency(days=7, now=now)
    assert len(week) == 7 and week[3]["service_down"] == 1


def test_frequency_days_are_limited(store) -> None:  # type: ignore[no-untyped-def]
    assert len(store.frequency(days=0, now=T0)) == 1
    assert len(store.frequency(days=10_000, now=T0)) == 365
    assert store.frequency(days=1, now=T0)[0]["day"] == "2025-10-09"
    with pytest.raises(ValueError):
        store.frequency(days="viele", now=T0)  # type: ignore[arg-type]


# --- Aufräumen ------------------------------------------------------------------------------------


def test_prune_by_age_only_closed(store) -> None:  # type: ignore[no-untyped-def]
    now = T0 + 400 * DAY
    old_closed = _open(store, "old", now=T0)
    store.close("old", now=T0 + DAY)
    old_active = _open(store, "still", now=T0)  # seit 400 Tagen aktiv – bleibt
    recent = _open(store, "recent", now=now - 10 * DAY)
    store.close("recent", now=now - 9 * DAY)
    assert store.prune(now) == 1
    remaining = {a.id for a in store.list(state="all")}
    assert remaining == {old_active.id, recent.id} and old_closed.id not in remaining
    assert store.prune(now) == 0  # idempotent
    assert store.prune(now, keep_days=ALERT_KEEP_DAYS, keep_max=5000) == 0


def test_prune_by_count_keeps_active(store) -> None:  # type: ignore[no-untyped-def]
    ids = []
    for i in range(5):
        ids.append(_open(store, f"c{i}", now=T0 + i).id)
        store.close(f"c{i}", now=T0 + 10 + i)
    active = [_open(store, f"a{i}", now=T0 + i).id for i in range(2)]
    # 7 Einträge, höchstens 3: die ältesten geschlossenen gehen, aktive nie
    assert store.prune(T0 + 100, keep_max=3) == 4
    assert {a.id for a in store.list(state="all")} == {ids[4], *active}
    assert store.prune(T0 + 100, keep_max=0) == 1
    assert {a.id for a in store.list(state="all")} == set(active)  # aktive auch über der Obergrenze


# --- Gleichzeitigkeit -----------------------------------------------------------------------------


def test_concurrent_open_same_key_yields_one_alert(store) -> None:  # type: ignore[no-untyped-def]
    n = 12
    barrier = threading.Barrier(n)
    results: list = []
    lock = threading.Lock()

    def worker() -> None:
        barrier.wait()
        a = _open(store, "device_offline:race")
        with lock:
            results.append(a)

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert len(results) == n
    assert len([a for a in results if a is not None]) == 1
    assert len(store.list(state="all")) == 1


def test_concurrent_open_from_two_connections(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "shared.sqlite3"
    db1, db2 = Database(path), Database(path)
    try:
        s1, s2 = AlertStore(db1, EventBus()), AlertStore(db2, EventBus())
        barrier = threading.Barrier(2)
        out: dict[str, object] = {}

        def run(name: str, s: AlertStore) -> None:
            barrier.wait()
            out[name] = _open(s, "device_offline:two")

        threads = [threading.Thread(target=run, args=("a", s1)), threading.Thread(target=run, args=("b", s2))]
        for t in threads:
            t.start()
        for t in threads:
            t.join(15)
        assert sum(1 for v in out.values() if v is not None) == 1
        assert len(s1.list(state="all")) == 1
    finally:
        db1.close()
        db2.close()


def test_integrity_error_from_race_returns_none(store, monkeypatch, bus) -> None:  # type: ignore[no-untyped-def]
    _open(store, "device_offline:r")
    # Wettlauf nachstellen: die Prüfung sieht den aktiven Alert nicht, der Teilindex verhindert den zweiten
    monkeypatch.setattr(AlertStore, "_find_active", staticmethod(lambda conn, key: None))
    assert _open(store, "device_offline:r", now=T0 + 1) is None
    monkeypatch.undo()
    assert len(store.list(state="all")) == 1
    assert len(_events(bus, "alert.opened")) == 1
