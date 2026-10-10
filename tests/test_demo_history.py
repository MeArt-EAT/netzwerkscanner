"""Demo: Inventar, Ziele, künstlicher Verlauf und alte Alerts (BAUPLAN §32).

Läuft ohne Sim-Netz gegen die Standard-Services (FakePlatform, Test-Datenordner): geprüft wird, was
seed_inventory(), seed_monitoring() und seed_history() in die Datenbank schreiben.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from netscan import demo
from netscan.core.models import ALERT_RULES, iso_from_ts, ts_from_iso
from netscan.core.services import build_services
from netscan.net import ports as net_ports
from tests.fakes import FakeOui, FakePlatform
from tests.test_demo_support import DB_LIMIT_BYTES, END, FIVE_MACS, NOW, WEEK_S, seeded  # noqa: F401  (Fixture seeded)

# --- Inventar und Ziele -----------------------------------------------------------------------


def test_inventory_holds_the_five_monitored_devices(seeded) -> None:  # type: ignore[no-untyped-def]
    devices = {d.mac: d for d in seeded.svc.inventory.list_devices()}
    assert set(devices) == FIVE_MACS
    router, nas, pc = devices[demo.ROUTER_MAC], devices[demo.NAS_MAC], devices[demo.PC_MAC]
    phone, telnet = devices[demo.PHONE_MAC], devices[demo.TELNET_MAC]
    assert (router.category, nas.category, pc.category, phone.category, telnet.category) == (
        "router", "server", "pc", "phone", "iot",
    )  # fmt: skip
    assert router.is_gateway and router.ip == demo.ROUTER_IP
    assert [d.display_name for d in (router, nas, pc, phone, telnet)] == ["Router", "NAS", "PC", "iPhone", "Telnet-Gerät"]
    assert {p.port for p in nas.ports} == {22, 445, 5000, 5001}
    assert {p.port for p in pc.ports} == {135, 445, 3389}
    assert {p.port for p in telnet.ports} == {23} and telnet.ports[0].risk == "high"
    assert phone.ports == [] and not phone.mac_random
    assert router.known and nas.known and pc.known and phone.known and not telnet.known


def test_inventory_marks_all_common_ports_as_checked(seeded) -> None:  # type: ignore[no-untyped-def]
    # Grundlage für „neuer offener Port“ (BAUPLAN §20): nur geprüfte, damals geschlossene Ports lösen aus
    assert set(net_ports.COMMON_PORTS) <= seeded.svc.inventory.checked_ports(demo.NAS_MAC)


def test_inventory_records_a_completed_demo_scan(seeded) -> None:  # type: ignore[no-untyped-def]
    inv = seeded.svc.inventory
    scan_id = inv.latest_scan_id()
    assert scan_id is not None
    assert inv.list_scans(1)[0]["device_count"] == 5
    assert all(d.online for d in inv.list_devices())
    assert "Demo-Vorlauf" in inv.get_log(scan_id)[0]["message"]


def test_targets_and_checks(seeded) -> None:  # type: ignore[no-untyped-def]
    targets = {t.mac: t for t in seeded.svc.targets.list()}
    assert set(targets) == FIVE_MACS
    nas = targets[demo.NAS_MAC]
    assert {(c.kind, c.port) for c in nas.checks} == {("smb", 445), ("http", 5000), ("ssh", 22)}
    assert nas.rtt_threshold_ms == 20 and nas.method == "auto"
    telnet = targets[demo.TELNET_MAC]
    assert telnet.method == "ping" and telnet.offline_after_min == 2
    for mac in (demo.ROUTER_MAC, demo.PC_MAC, demo.PHONE_MAC, demo.TELNET_MAC):
        assert targets[mac].checks == []
    assert all(t.enabled and t.status == "unknown" for t in targets.values())  # den ersten Durchlauf macht der Monitor
    assert all(t.gateway_mac == demo.ROUTER_MAC and t.network == demo.DEMO_ADAPTER.network for t in targets.values())


def test_seed_functions_return_what_they_stored(seeded) -> None:  # type: ignore[no-untyped-def]
    assert set(seeded.inventory) == set(seeded.targets) == {"router", "nas", "pc", "iphone", "telnet"}
    assert seeded.targets["nas"].mac == demo.NAS_MAC and len(seeded.targets["nas"].checks) == 3


# --- Messwerte ---------------------------------------------------------------------------------


def test_history_covers_seven_days_in_five_minute_steps(seeded) -> None:  # type: ignore[no-untyped-def]
    svc = seeded.svc
    assert seeded.counts["samples"] == svc.metrics.counts()["raw"]
    assert 14_000 < seeded.counts["samples"] < 18_000  # 5 Geräte + 3 Dienste, ~2000 Takte
    first, last = svc.db.query_one("SELECT MIN(ts) AS lo, MAX(ts) AS hi FROM samples")  # type: ignore[misc]
    assert first >= END - WEEK_S and last <= END  # nichts aus der Zukunft
    assert last == END and first - (END - WEEK_S) < 3600  # der Verlauf reicht bis jetzt und eine Woche zurück
    steps = {r[0] for r in svc.db.query("SELECT DISTINCT ts % ? FROM samples", (demo.HISTORY_STEP_S,))}
    assert steps == {0}  # alle Werte liegen im 5-Minuten-Raster


def test_every_series_has_availability(seeded) -> None:  # type: ignore[no-untyped-def]
    metrics = seeded.svc.metrics
    for key, target in seeded.targets.items():
        week = metrics.availability(target.id, 0, since=END - WEEK_S, until=END + 1)
        assert week["samples"] > 1900, key
        assert week["up_pct"] is not None and 60 < week["up_pct"] <= 100, key
        for check in target.checks:
            avail = metrics.availability(target.id, check.id, since=END - WEEK_S, until=END + 1)
            assert avail["samples"] > 1800 and 90 < avail["up_pct"] < 100, check.kind  # Dienste fielen zeitweise aus
    router = metrics.availability(seeded.targets["router"].id, 0, since=END - WEEK_S, until=END + 1)
    telnet = metrics.availability(seeded.targets["telnet"].id, 0, since=END - WEEK_S, until=END + 1)
    assert router["up_pct"] > telnet["up_pct"]  # der Router ist zuverlässiger als das Telnet-Gerät


def test_availability_map_has_values_for_24h_and_7d(seeded) -> None:  # type: ignore[no-untyped-def]
    amap = seeded.svc.metrics.availability_map(END)
    assert len(amap) == 8  # 5 Geräte + 3 Dienste der NAS
    for (_target_id, _check_id), windows in amap.items():
        assert windows["24h"]["up_pct"] is not None and windows["7d"]["up_pct"] is not None


def test_series_and_trend_are_filled(seeded) -> None:  # type: ignore[no-untyped-def]
    metrics = seeded.svc.metrics
    for key, target in seeded.targets.items():
        for span in (86400, WEEK_S):
            series = metrics.series(target.id, 0, since=END - span, until=END)
            filled = [p for p in series["points"] if p["n"]]
            assert len(filled) > 100, (key, span)
            rtts = [p["rtt_avg"] for p in filled if p["rtt_avg"] is not None]
            assert rtts and all(0.2 <= r <= 400 for r in rtts), key
        trend = metrics.trend(target.id, 0, days=7, now=END)
        assert len(trend) == 7 and sum(1 for d in trend if d["up_pct"] is not None) >= 6, key


def test_response_times_are_plausible_per_device(seeded) -> None:  # type: ignore[no-untyped-def]
    db = seeded.svc.db

    def mean_rtt(key: str, check_id: int = 0) -> float:
        row = db.query_one(
            "SELECT AVG(rtt_ms) AS m FROM samples WHERE target_id = ? AND check_id = ? AND ok = 1",
            (seeded.targets[key].id, check_id),
        )
        return float(row["m"])  # type: ignore[index]

    router, nas, phone = mean_rtt("router"), mean_rtt("nas"), mean_rtt("iphone")
    assert 0.5 < router < 1.5 and 1.5 < nas < 6 and 15 < phone < 60  # Kabel schnell, Handy im WLAN langsamer
    assert db.query_one("SELECT MIN(rtt_ms) AS lo FROM samples WHERE ok = 1")["lo"] >= 0.2  # type: ignore[index]
    assert db.query_one("SELECT COUNT(*) AS n FROM samples WHERE ok = 0 AND rtt_ms IS NOT NULL")["n"] == 0  # type: ignore[index]


def test_gap_has_no_values_at_all(seeded) -> None:  # type: ignore[no-untyped-def]
    start = END - round(demo.GAP_HOURS_AGO * 3600)
    stop = start + demo.GAP_MINUTES * 60
    db = seeded.svc.db
    assert db.query_one("SELECT COUNT(*) AS n FROM samples WHERE ts >= ? AND ts < ?", (start, stop))["n"] == 0  # type: ignore[index]
    around = db.query_one("SELECT COUNT(*) AS n FROM samples WHERE ts >= ? AND ts < ?", (start - 1800, start))["n"]  # type: ignore[index]
    assert around > 0  # davor und danach wurde gemessen: die Lücke ist wirklich eine Lücke
    series = seeded.svc.metrics.series(seeded.targets["router"].id, 0, since=start - 7200, until=stop + 7200, max_points=400)
    assert any(p["n"] == 0 for p in series["points"])  # im Diagramm sichtbar


def test_nas_restart_makes_services_unknown_not_down(seeded) -> None:  # type: ignore[no-untyped-def]
    # Neustart der NAS (61 h zurück, 26 min): Gerät ausgefallen, Dienste ohne Messwert (BAUPLAN §22: „unknown“)
    db, nas = seeded.svc.db, seeded.targets["nas"]
    start = END - 61 * 3600
    stop = start + 26 * 60
    device = db.query("SELECT ok FROM samples WHERE target_id = ? AND check_id = 0 AND ts >= ? AND ts < ?", (nas.id, start, stop))
    assert device and all(r["ok"] == 0 for r in device)
    for check in nas.checks:
        n = db.query_one(
            "SELECT COUNT(*) AS n FROM samples WHERE target_id = ? AND check_id = ? AND ts >= ? AND ts < ?",
            (nas.id, check.id, start, stop),
        )["n"]  # type: ignore[index]
        assert n == 0, check.kind


def test_http_outage_leaves_the_device_reachable(seeded) -> None:  # type: ignore[no-untyped-def]
    db, nas = seeded.svc.db, seeded.targets["nas"]
    http = next(c for c in nas.checks if c.kind == "http")
    start = END - 29 * 3600
    stop = start + 38 * 60
    service = db.query("SELECT ok FROM samples WHERE target_id = ? AND check_id = ? AND ts >= ? AND ts < ?", (nas.id, http.id, start, stop))
    device = db.query("SELECT ok FROM samples WHERE target_id = ? AND check_id = 0 AND ts >= ? AND ts < ?", (nas.id, start, stop))
    assert service and all(r["ok"] == 0 for r in service)
    assert device and all(r["ok"] == 1 for r in device)


def test_database_stays_small(seeded) -> None:  # type: ignore[no-untyped-def]
    assert seeded.svc.db.size_bytes() < DB_LIMIT_BYTES
    assert seeded.svc.db.size_bytes() < 2 * 1024 * 1024  # real etwa 0,5 MB


# --- Alerts ------------------------------------------------------------------------------------


def test_old_alerts_are_closed_and_cover_every_rule(seeded) -> None:  # type: ignore[no-untyped-def]
    store = seeded.svc.alerts
    alerts = store.list(state="all", limit=1000)
    assert len(alerts) == seeded.counts["alerts"] >= 20
    assert {a.rule for a in alerts} == set(ALERT_RULES)
    assert store.list(state="active") == [] and store.counts()["active"] == 0
    for a in alerts:
        assert a.closed is not None and a.opened <= a.closed <= iso_from_ts(END), a.title
        assert ts_from_iso(a.opened) >= END - 30 * 86400, a.title  # alles innerhalb der 30-Tage-Ansicht  # type: ignore[operator]


def test_alert_texts_come_from_the_real_rules(seeded) -> None:  # type: ignore[no-untyped-def]
    alerts = seeded.svc.alerts.list(state="all", limit=1000)
    by_title = {}
    for a in alerts:
        by_title.setdefault(a.title, a)
    router = by_title["Router ist offline"]
    assert router.severity == "critical" and router.rule == "device_offline" and router.mac == demo.ROUTER_MAC
    assert demo.ROUTER_IP in router.message and "Schwelle: 5 Minuten" in router.message
    assert by_title["NAS ist offline"].severity == "critical"  # Server/NAS
    assert by_title["Telnet-Gerät ist offline"].severity == "warning"
    assert "Schwelle: 2 Minuten" in by_title["Telnet-Gerät ist offline"].message  # Schwelle des Ziels
    http = by_title["HTTP 5000 auf NAS ausgefallen"]
    assert http.rule == "service_down" and http.check_id is not None and "Das Gerät selbst ist erreichbar" in http.message
    assert by_title["Antwortzeit von NAS hoch"].severity == "info"
    new_port = by_title["Neuer offener Port 3389 auf PC"]
    assert new_port.rule == "new_port" and new_port.severity == "warning" and "Risiko: mittel" in new_port.message
    assert by_title["Neuer offener Port 5001 auf NAS"].severity == "info"
    assert by_title["Neues Gerät: Telnet-Gerät"].rule == "new_device"
    assert not any(a.title.startswith("Neues Gerät: Router") for a in alerts)


def test_only_the_two_newest_state_alerts_stay_unacknowledged(seeded) -> None:  # type: ignore[no-untyped-def]
    store = seeded.svc.alerts
    assert store.counts()["unacked"] == 2
    titles = [a.title for a in store.list(state="unacked")]
    assert titles == ["HTTP 5000 auf NAS ausgefallen", "Telnet-Gerät ist offline"]
    for a in store.list(state="all", limit=1000):
        if a.acknowledged:
            assert a.closed <= a.acknowledged <= iso_from_ts(END), a.title  # type: ignore[operator]


def test_alert_frequency_chart_is_filled(seeded) -> None:  # type: ignore[no-untyped-def]
    days = seeded.svc.alerts.frequency(days=30, now=END)
    assert len(days) == 30
    assert sum(1 for d in days if any(d[r] for r in ALERT_RULES)) >= 8  # an vielen Tagen etwas los
    for rule in ALERT_RULES:
        assert sum(d[rule] for d in days) > 0, rule
    assert sum(d["device_offline"] for d in days) > sum(d["rtt_high"] for d in days)


def test_alerts_match_the_outages_in_the_samples(seeded) -> None:  # type: ignore[no-untyped-def]
    # Ein Alert „Telnet-Gerät ist offline“ gehört zu einer Lücke im Verlauf (ok = 0), nicht zu Zufall
    db, telnet = seeded.svc.db, seeded.targets["telnet"]
    alerts = [a for a in seeded.svc.alerts.list(state="all", limit=1000) if a.rule == "device_offline" and a.mac == telnet.mac]
    inside = 0
    for a in alerts:
        opened = ts_from_iso(a.opened)
        if opened < END - WEEK_S:  # ältere Alerts haben keine Messwerte mehr
            continue
        row = db.query_one("SELECT ok FROM samples WHERE target_id = ? AND check_id = 0 AND ts <= ? ORDER BY ts DESC LIMIT 1", (telnet.id, opened))  # type: ignore[arg-type]
        inside += row is not None and row["ok"] == 0
    assert inside >= 5


# --- Gleich bleiben, leer bleiben ----------------------------------------------------------------


def test_history_is_deterministic(seeded, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    def digest(svc) -> str:  # type: ignore[no-untyped-def]
        h = hashlib.sha256()
        for r in svc.db.query("SELECT target_id, check_id, ts, ok, rtt_ms FROM samples ORDER BY target_id, check_id, ts"):
            h.update(repr(tuple(r)).encode())
        for a in svc.alerts.list(state="all", limit=1000):
            h.update(f"{a.rule}|{a.title}|{a.opened}|{a.closed}|{a.acknowledged}".encode())
        return h.hexdigest()

    other = build_services(data_dir=tmp_path / "zweite", platform=FakePlatform(), oui=FakeOui())  # type: ignore[arg-type]
    try:
        demo.seed_inventory(other)
        demo.seed_monitoring(other)
        demo.seed_history(other, seeded.end)
        assert digest(other) == digest(seeded.svc)
    finally:
        other.close()


def test_history_without_targets_does_nothing(services) -> None:  # type: ignore[no-untyped-def]
    assert demo.seed_history(services, NOW) == {"samples": 0, "alerts": 0}
    assert services.metrics.counts() == {"raw": 0, "hourly": 0}
    assert services.alerts.list(state="all") == []


def test_history_defaults_to_the_current_time(services) -> None:  # type: ignore[no-untyped-def]
    import time

    demo.seed_inventory(services)
    demo.seed_monitoring(services)
    before = int(time.time())
    counts = demo.seed_history(services)  # ohne now: Ende = jetzt
    row = services.db.query_one("SELECT MAX(ts) AS hi FROM samples")
    assert counts["samples"] > 10_000 and before - 600 <= row["hi"] <= int(time.time())  # type: ignore[index]

