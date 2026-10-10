"""Überwachungs-API: Messwerte, Übersicht, Alerts und Autostart (BAUPLAN §27).

metrics, alerts und autostart sind Attrappen (siehe test_api_monitor_support) – kein Paket verlässt den
Rechner, schtasks wird nie aufgerufen.
"""

from __future__ import annotations

import pytest

from netscan import config
from netscan.platform.autostart import AutostartError, AutostartStatus
from tests.fakes import seed_device
from tests.test_api_monitor_support import (  # noqa: F401  (Fixtures env und client)
    NAS_MAC,
    NOW,
    PC_MAC,
    PHONE_MAC,
    UNKNOWN_MAC,
    client,
    env,
)

RANGES = {"24h": 86400, "7d": 604800, "30d": 2592000, "1y": 31536000}
POINTS = [
    {"t": (NOW - 600) * 1000, "rtt_avg": 2.5, "rtt_min": 1.0, "rtt_max": 4.0, "up_pct": 100.0, "n": 10},
    {"t": NOW * 1000, "rtt_avg": None, "rtt_min": None, "rtt_max": None, "up_pct": None, "n": 0},
]


# --- Antwortzeit-Verlauf ---------------------------------------------------------------------


@pytest.mark.parametrize("name, seconds", list(RANGES.items()))
def test_verlauf_zeitraeume(env, name, seconds):
    t = env.add_target(NAS_MAC)
    env.metrics.series_result = {"bucket_s": 600, "points": POINTS}
    r = env.client.get("/api/metrics/series", params={"mac": NAS_MAC, "range": name})
    assert r.status_code == 200, r.text
    assert r.json() == {"range": name, "since": NOW - seconds, "until": NOW, "bucket_s": 600, "points": POINTS}
    assert env.metrics.series_calls == [
        {"target_id": t["id"], "check_id": 0, "since": NOW - seconds, "until": NOW, "max_points": 400}
    ]


def test_verlauf_standardwerte(env):
    t = env.add_target(NAS_MAC)
    r = env.client.get("/api/metrics/series", params={"mac": NAS_MAC})
    assert r.status_code == 200
    assert r.json() == {"range": "24h", "since": NOW - 86400, "until": NOW, "bucket_s": 300, "points": []}
    assert env.metrics.series_calls[0]["check_id"] == 0 and env.metrics.series_calls[0]["target_id"] == t["id"]


def test_verlauf_einer_dienstpruefung(env):
    t = env.add_target(NAS_MAC, checks=[{"kind": "smb", "port": 445}])
    cid = t["checks"][0]["id"]
    r = env.client.get("/api/metrics/series", params={"mac": NAS_MAC, "check_id": cid, "range": "7d"})
    assert r.status_code == 200
    assert env.metrics.series_calls[0] == {
        "target_id": t["id"], "check_id": cid, "since": NOW - 604800, "until": NOW, "max_points": 400,
    }  # fmt: skip


def test_verlauf_mac_wird_normalisiert(env):
    env.add_target(NAS_MAC)
    r = env.client.get("/api/metrics/series", params={"mac": "00-11-32-AA-BB-03"})
    assert r.status_code == 200 and len(env.metrics.series_calls) == 1


def test_verlauf_fremde_pruefung_ergibt_404(env):
    nas = env.add_target(NAS_MAC, checks=[{"kind": "smb", "port": 445}])
    env.add_target(PC_MAC)
    foreign = nas["checks"][0]["id"]
    for params in (
        {"mac": PC_MAC, "check_id": foreign},  # die Prüfung gehört zum NAS, nicht zum PC
        {"mac": NAS_MAC, "check_id": foreign + 100},
        {"mac": NAS_MAC, "check_id": -1},
    ):
        r = env.client.get("/api/metrics/series", params=params)
        assert r.status_code == 404, params
        assert "Prüfung" in r.json()["detail"]
    assert env.metrics.series_calls == []  # der Speicher wurde nie gefragt


@pytest.mark.parametrize("mac", [PHONE_MAC, UNKNOWN_MAC, "kein-mac", ""])
def test_verlauf_unbekanntes_geraet_ergibt_404(env, mac):
    env.add_target(NAS_MAC)
    r = env.client.get("/api/metrics/series", params={"mac": mac})
    assert r.status_code == 404, mac
    assert env.metrics.series_calls == []


@pytest.mark.parametrize(
    "params, stichwort",
    [
        ({"mac": NAS_MAC, "range": "5d"}, "Zeitraum"),
        ({"mac": NAS_MAC, "range": "24H"}, "Zeitraum"),
        ({"mac": NAS_MAC, "range": ""}, "Zeitraum"),
        ({"mac": NAS_MAC, "range": "1w"}, "Zeitraum"),
        ({}, "mac"),
        ({"mac": NAS_MAC, "check_id": "abc"}, "check_id"),
        ({"mac": NAS_MAC, "check_id": "1.5"}, "check_id"),
    ],
)
def test_verlauf_ungueltige_angaben_ergeben_400(env, params, stichwort):
    env.add_target(NAS_MAC)
    r = env.client.get("/api/metrics/series", params=params)
    assert r.status_code == 400, r.text
    assert stichwort in r.json()["detail"]
    assert env.metrics.series_calls == []


def test_verlauf_lesefehler_ergibt_500_mit_text(env):
    env.add_target(NAS_MAC)
    env.metrics.error = RuntimeError("Datenbank kaputt")
    with env.quiet_client() as c:
        r = c.get("/api/metrics/series", params={"mac": NAS_MAC})
    assert r.status_code == 500
    assert "Logfile" in r.json()["detail"]


# --- Verfügbarkeits-Trend --------------------------------------------------------------------


def test_trend_standard(env):
    t = env.add_target(NAS_MAC)
    rows = [{"day": "2026-10-08", "up_pct": 100.0, "n": 1440}, {"day": "2026-10-09", "up_pct": None, "n": 0}]
    env.metrics.trend_result = rows
    r = env.client.get("/api/metrics/trend", params={"mac": NAS_MAC})
    assert r.status_code == 200 and r.json() == rows
    assert env.metrics.trend_calls == [{"target_id": t["id"], "check_id": 0, "days": 30, "now": NOW}]
    assert isinstance(env.metrics.trend_calls[0]["now"], int)


def test_trend_einer_dienstpruefung_und_tage(env):
    t = env.add_target(NAS_MAC, checks=[{"kind": "tcp", "port": 22}])
    cid = t["checks"][0]["id"]
    r = env.client.get("/api/metrics/trend", params={"mac": "00-11-32-AA-BB-03", "check_id": cid, "days": 7})
    assert r.status_code == 200
    assert env.metrics.trend_calls == [{"target_id": t["id"], "check_id": cid, "days": 7, "now": NOW}]


@pytest.mark.parametrize("days", [1, 365])
def test_trend_grenzen_sind_erlaubt(env, days):
    env.add_target(NAS_MAC)
    assert env.client.get("/api/metrics/trend", params={"mac": NAS_MAC, "days": days}).status_code == 200
    assert env.metrics.trend_calls[-1]["days"] == days


@pytest.mark.parametrize("days", [0, 366, -1, 100000, "abc", "1.5", ""])
def test_trend_tage_ausserhalb_ergeben_400(env, days):
    env.add_target(NAS_MAC)
    r = env.client.get("/api/metrics/trend", params={"mac": NAS_MAC, "days": days})
    assert r.status_code == 400, r.text
    assert "days" in r.json()["detail"]
    assert env.metrics.trend_calls == []


def test_trend_404_und_400(env):
    nas = env.add_target(NAS_MAC, checks=[{"kind": "tcp", "port": 22}])
    env.add_target(PC_MAC)
    assert env.client.get("/api/metrics/trend", params={"mac": UNKNOWN_MAC}).status_code == 404
    assert env.client.get("/api/metrics/trend", params={"mac": "kein-mac"}).status_code == 404
    assert env.client.get("/api/metrics/trend", params={"mac": PHONE_MAC}).status_code == 404  # nicht überwacht
    assert env.client.get("/api/metrics/trend", params={"mac": PC_MAC, "check_id": nas["checks"][0]["id"]}).status_code == 404
    assert env.client.get("/api/metrics/trend").status_code == 400  # mac fehlt
    assert env.metrics.trend_calls == []


# --- Übersicht -------------------------------------------------------------------------------


def _set_status(env, mac: str, status: str) -> None:  # type: ignore[no-untyped-def]
    target = env.svc.targets.get(mac)
    target.status = status
    env.svc.targets.save_state(target)


def test_uebersicht_zaehlt_die_zustaende(env):
    extra1 = seed_device(env.svc, "00:1b:21:aa:bb:09", "192.168.178.9")
    extra2 = seed_device(env.svc, "00:1b:21:aa:bb:0a", "192.168.178.10")
    for mac in (NAS_MAC, PC_MAC, PHONE_MAC, extra1.mac, extra2.mac):
        env.add_target(mac)
    for mac, status in ((NAS_MAC, "online"), (PC_MAC, "offline"), (PHONE_MAC, "degraded"), (extra1.mac, "paused")):
        _set_status(env, mac, status)  # extra2 bleibt „unknown“
    env.metrics.count_result = {"raw": 1234, "hourly": 56}
    r = env.client.get("/api/metrics/overview")
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["counts"] == {"online": 1, "degraded": 1, "offline": 1, "paused": 1, "unknown": 1}
    assert data["samples"] == {"raw": 1234, "hourly": 56}
    assert data["db_size_bytes"] == env.svc.db.size_bytes() and data["db_size_bytes"] > 0
    assert data["db_warn"] is False


def test_uebersicht_ohne_ziele(env):
    data = env.client.get("/api/metrics/overview").json()
    assert data["counts"] == {"online": 0, "degraded": 0, "offline": 0, "paused": 0, "unknown": 0}


def test_uebersicht_zaehlt_abgeschaltete_ziele_als_pausiert(env):
    env.add_target(NAS_MAC)
    env.client.patch(f"/api/monitor/targets/{NAS_MAC}", json={"enabled": False})
    assert env.client.get("/api/metrics/overview").json()["counts"]["paused"] == 1


@pytest.mark.parametrize(
    "size, warn",
    [(0, False), (config.DB_WARN_BYTES - 1, False), (config.DB_WARN_BYTES, True), (config.DB_WARN_BYTES + 1, True)],
)
def test_uebersicht_warnschwelle(env, monkeypatch, size, warn):
    monkeypatch.setattr(env.svc.db, "size_bytes", lambda: size)
    data = env.client.get("/api/metrics/overview").json()
    assert data["db_size_bytes"] == size and data["db_warn"] is warn


def test_uebersicht_warnschwelle_ist_100_mb():
    assert config.DB_WARN_BYTES == 100 * 1024 * 1024


def test_uebersicht_toleriert_lesefehler(env, monkeypatch):
    def boom() -> int:
        raise OSError("Datei gesperrt")

    monkeypatch.setattr(env.svc.db, "size_bytes", boom)
    env.metrics.error = RuntimeError("kaputt")
    r = env.client.get("/api/metrics/overview")
    assert r.status_code == 200
    data = r.json()
    assert data["db_size_bytes"] is None and data["db_warn"] is False
    assert data["samples"] == {"raw": 0, "hourly": 0}


# --- Alerts ----------------------------------------------------------------------------------


def test_alerts_standardabfrage(env):
    env.alerts.add("device_offline", NAS_MAC)
    env.alerts.add("new_device", PC_MAC, acknowledged="2026-10-10T10:00:00+00:00")
    env.alerts.add("service_down", NAS_MAC, closed="2026-10-10T11:00:00+00:00")
    r = env.client.get("/api/alerts")
    assert r.status_code == 200, r.text
    assert env.alerts.list_calls == [{"state": "active", "limit": 200, "mac": None}]
    data = r.json()
    assert [a["rule"] for a in data] == ["new_device", "device_offline"]  # neueste zuerst, geschlossener fehlt
    first = data[1]
    assert first["active"] is True and first["rule_label"] == "Gerät offline" and first["severity_label"] == "Warnung"
    assert first["mac"] == NAS_MAC and first["acknowledged"] is None


@pytest.mark.parametrize("state, rules", [("active", 2), ("unacked", 1), ("all", 3)])
def test_alerts_zustand(env, state, rules):
    env.alerts.add("device_offline", NAS_MAC)
    env.alerts.add("new_device", PC_MAC, acknowledged="2026-10-10T10:00:00+00:00")
    env.alerts.add("service_down", NAS_MAC, closed="2026-10-10T11:00:00+00:00")
    r = env.client.get("/api/alerts", params={"state": state})
    assert r.status_code == 200 and len(r.json()) == rules
    assert env.alerts.list_calls[-1]["state"] == state


def test_alerts_limit_und_filter(env):
    for _ in range(5):
        env.alerts.add("device_offline", NAS_MAC)
    env.alerts.add("device_offline", PC_MAC)
    assert len(env.client.get("/api/alerts", params={"limit": 2}).json()) == 2
    assert env.alerts.list_calls[-1]["limit"] == 2
    assert env.client.get("/api/alerts", params={"limit": 1000}).status_code == 200
    assert env.client.get("/api/alerts", params={"limit": 1}).status_code == 200
    data = env.client.get("/api/alerts", params={"mac": "00-11-32-AA-BB-03"}).json()
    assert env.alerts.list_calls[-1]["mac"] == NAS_MAC  # normalisiert weitergereicht
    assert len(data) == 5 and {a["mac"] for a in data} == {NAS_MAC}


def test_alerts_leerer_macfilter_gilt_nicht(env):
    env.alerts.add("device_offline", NAS_MAC)
    r = env.client.get("/api/alerts", params={"mac": ""})
    assert r.status_code == 200 and len(r.json()) == 1
    assert env.alerts.list_calls[-1]["mac"] is None


@pytest.mark.parametrize(
    "params, stichwort",
    [
        ({"state": "offen"}, "Zustand"),
        ({"state": ""}, "Zustand"),
        ({"state": "ALL"}, "Zustand"),
        ({"limit": 0}, "limit"),
        ({"limit": 1001}, "limit"),
        ({"limit": -5}, "limit"),
        ({"limit": "abc"}, "limit"),
        ({"limit": "1.5"}, "limit"),
        ({"mac": "kein-mac"}, "MAC"),
    ],
)
def test_alerts_ungueltige_angaben_ergeben_400(env, params, stichwort):
    r = env.client.get("/api/alerts", params=params)
    assert r.status_code == 400, r.text
    assert stichwort in r.json()["detail"]
    assert env.alerts.list_calls == []


def test_alert_quittieren(env):
    env.alerts.add("device_offline", NAS_MAC)
    env.alerts.add("new_port", NAS_MAC)
    r = env.client.post("/api/alerts/2/ack")
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["id"] == 2 and data["rule"] == "new_port" and data["acknowledged"]
    assert env.alerts.ack_calls == [2]
    assert env.alerts.items[0].acknowledged is None  # der andere Alert bleibt offen


@pytest.mark.parametrize("alert_id", ["99", "0", "abc", "-1", "1.5", "99999999999999999999999999"])
def test_alert_quittieren_unbekannt_ergibt_404(env, alert_id):
    env.alerts.add("device_offline", NAS_MAC)
    r = env.client.post(f"/api/alerts/{alert_id}/ack")
    assert r.status_code == 404
    assert r.json()["detail"]
    assert env.alerts.items[0].acknowledged is None


def test_alle_quittieren(env):
    env.alerts.add("device_offline", NAS_MAC)
    env.alerts.add("new_device", PC_MAC)
    env.alerts.add("new_port", PC_MAC, acknowledged="2026-10-10T10:00:00+00:00")
    r = env.client.post("/api/alerts/ack-all")
    assert r.status_code == 200 and r.json() == {"acknowledged": 2}
    assert env.alerts.ack_all_calls == 1 and env.alerts.ack_calls == []  # nicht als Kennung „ack-all“ missverstanden
    assert env.client.post("/api/alerts/ack-all").json() == {"acknowledged": 0}


def test_alert_haeufigkeit(env):
    rows = [{"day": "2026-10-09", "device_offline": 2, "service_down": 0, "rtt_high": 1, "new_device": 0, "new_port": 0}]
    env.alerts.frequency_result = rows
    env.alerts.add("device_offline", NAS_MAC)
    r = env.client.get("/api/alerts/stats")
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["days"] == rows
    assert data["counts"] == {"active": 1, "unacked": 1, "by_rule": {}}
    assert env.alerts.frequency_calls == [{"days": 30, "now": float(NOW)}]
    env.client.get("/api/alerts/stats", params={"days": 7})
    assert env.alerts.frequency_calls[-1]["days"] == 7


@pytest.mark.parametrize("days", [0, 366, -1, "abc", "1.5"])
def test_alert_haeufigkeit_tage_ausserhalb_ergeben_400(env, days):
    r = env.client.get("/api/alerts/stats", params={"days": days})
    assert r.status_code == 400 and "days" in r.json()["detail"]
    assert env.alerts.frequency_calls == []


def test_alert_lesefehler_ergibt_500_mit_text(env):
    env.alerts.error = RuntimeError("kaputt")
    with env.quiet_client() as c:
        assert c.get("/api/alerts").status_code == 500
        assert c.get("/api/alerts/stats").status_code == 500


# --- Autostart -------------------------------------------------------------------------------


def test_autostart_lesen(env):
    r = env.client.get("/api/autostart")
    assert r.status_code == 200
    assert r.json() == {"supported": True, "enabled": False, "detail": "Nicht eingerichtet."}
    assert env.autostart.set_calls == []


def test_autostart_lesen_ohne_unterstuetzung(env):
    env.autostart.status = AutostartStatus(supported=False, detail="Unter Linux über systemd einrichten.")
    r = env.client.get("/api/autostart")
    assert r.status_code == 200
    assert r.json() == {"supported": False, "enabled": False, "detail": "Unter Linux über systemd einrichten."}


def test_autostart_lesen_fehler(env):
    env.autostart.status_error = AutostartError("Die Aufgabenplanung ist nicht erreichbar.")
    r = env.client.get("/api/autostart")
    assert r.status_code == 500 and r.json()["detail"] == "Die Aufgabenplanung ist nicht erreichbar."
    env.autostart.status_error = NotImplementedError()
    assert env.client.get("/api/autostart").status_code == 501
    env.autostart.status_error = FileNotFoundError("schtasks")
    with env.quiet_client() as c:
        r = c.get("/api/autostart")
    assert r.status_code == 500 and "Autostart" in r.json()["detail"] and "schtasks" not in r.json()["detail"]


def test_autostart_ein_und_ausschalten(env):
    on = env.client.put("/api/autostart", json={"enabled": True})
    assert on.status_code == 200, on.text
    assert on.json() == {"supported": True, "enabled": True, "detail": "Eingerichtet."}
    assert env.client.get("/api/autostart").json()["enabled"] is True
    off = env.client.put("/api/autostart", json={"enabled": False})
    assert off.status_code == 200 and off.json()["enabled"] is False
    assert env.autostart.set_calls == [True, False]


def test_autostart_ohne_unterstuetzung_ergibt_501_ohne_aenderung(env):
    env.autostart.status = AutostartStatus(supported=False, detail="Unter Linux über systemd einrichten.")
    r = env.client.put("/api/autostart", json={"enabled": True})
    assert r.status_code == 501
    assert r.json()["detail"] == "Unter Linux über systemd einrichten."
    assert env.autostart.set_calls == []  # es wird gar nicht erst versucht


def test_autostart_ohne_unterstuetzung_ohne_text(env):
    env.autostart.status = AutostartStatus(supported=False)
    r = env.client.put("/api/autostart", json={"enabled": True})
    assert r.status_code == 501 and "nicht unterstützt" in r.json()["detail"]


def test_autostart_ergebnis_ohne_unterstuetzung_ergibt_501(env):
    env.autostart.set_result = AutostartStatus(supported=False, detail="Nicht möglich.")
    r = env.client.put("/api/autostart", json={"enabled": True})
    assert r.status_code == 501 and r.json()["detail"] == "Nicht möglich."


def test_autostart_fehler_beim_aendern(env):
    env.autostart.set_error = AutostartError("Die Aufgabe konnte nicht angelegt werden (Zugriff verweigert).")
    r = env.client.put("/api/autostart", json={"enabled": True})
    assert r.status_code == 500
    assert r.json()["detail"] == "Die Aufgabe konnte nicht angelegt werden (Zugriff verweigert)."
    env.autostart.set_error = NotImplementedError()
    assert env.client.put("/api/autostart", json={"enabled": True}).status_code == 501
    env.autostart.set_error = None
    env.autostart.status_error = AutostartError("Aufgabenplanung nicht lesbar.")
    r = env.client.put("/api/autostart", json={"enabled": True})
    assert r.status_code == 500 and "nicht lesbar" in r.json()["detail"]
    assert env.autostart.set_calls == [True, True]  # beim letzten Versuch scheiterte schon das Lesen


@pytest.mark.parametrize("body", [{}, {"enabled": "true"}, {"enabled": "false"}, {"enabled": 1}, {"enabled": 0}, {"enabled": None}, {"on": True}, []])
def test_autostart_falsche_eingabe_ergibt_400(env, body):
    r = env.client.put("/api/autostart", json=body)
    assert r.status_code == 400, r.text
    assert env.autostart.set_calls == []


def test_autostart_unbekanntes_feld_ergibt_400(env):
    r = env.client.put("/api/autostart", json={"enabled": True, "admin": True})
    assert r.status_code == 400 and "admin" in r.json()["detail"]
    assert env.autostart.set_calls == []
