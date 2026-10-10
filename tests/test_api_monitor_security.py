"""Überwachungs-API: Status, Einstellungen und Sicherheitsregeln der neuen schreibenden Endpunkte (BAUPLAN §27).

Origin 403, Content-Type 415 und Host-Schutz kommen aus der Middleware in server.py und müssen für jeden
neuen Endpunkt greifen; dazu unbekannte Felder und falsche Typen (400), Grenzen der Einstellungen.
"""

from __future__ import annotations

import pytest

from netscan import config
from netscan.core.models import MonitorStatus
from tests.test_api_monitor_support import (  # noqa: F401  (Fixtures env und client)
    BASE,
    EVIL,
    NAS_MAC,
    PC_MAC,
    WS_URL,
    client,
    env,
)

NEW_SETTINGS = {
    "monitor_enabled": True,
    "monitor_interval_s": 60,
    "monitor_timeout_ms": 1000,
    "alert_offline_minutes": 5,
    "alert_service_minutes": 2,
    "alert_rtt_minutes": 5,
    "alert_new_device": True,
    "alert_new_port": True,
}
INT_SETTINGS = {
    # Name: (kleinster, größter erlaubter Wert) – config.SETTING_LIMITS
    "monitor_interval_s": (10, 3600),
    "monitor_timeout_ms": (200, 2000),
    "alert_offline_minutes": (1, 1440),
    "alert_service_minutes": (1, 1440),
    "alert_rtt_minutes": (1, 1440),
}
BOOL_SETTINGS = ("monitor_enabled", "alert_new_device", "alert_new_port")

# (Methode, Pfad mit {mac} und {check}, Body) – alle neuen schreibenden Endpunkte
WRITES = [
    ("post", "/api/monitor/targets", {"mac": PC_MAC}),
    ("patch", "/api/monitor/targets/{mac}", {"enabled": False}),
    ("delete", "/api/monitor/targets/{mac}", None),
    ("post", "/api/monitor/targets/{mac}/checks", {"kind": "tcp", "port": 22}),
    ("patch", "/api/monitor/checks/{check}", {"enabled": False}),
    ("delete", "/api/monitor/checks/{check}", None),
    ("post", "/api/monitor/run", None),
    ("post", "/api/alerts/1/ack", None),
    ("post", "/api/alerts/ack-all", None),
    ("put", "/api/autostart", {"enabled": True}),
    ("put", "/api/settings", {"monitor_interval_s": 30, "monitor_enabled": False}),
]
WRITE_IDS = [f"{m.upper()} {p}" for m, p, _ in WRITES]


@pytest.fixture
def seeded(env):  # type: ignore[no-untyped-def]
    """NAS überwacht (mit einer Prüfung), ein Alert vorhanden; gibt (env, check_id) zurück."""
    target = env.add_target(NAS_MAC, checks=[{"kind": "smb", "port": 445}])
    env.alerts.add("device_offline", NAS_MAC)
    return env, target["checks"][0]["id"]


def _call(env, method: str, template: str, body, check_id: int, **kwargs):  # type: ignore[no-untyped-def]
    path = template.format(mac=NAS_MAC, check=check_id)
    return env.client.request(method.upper(), path, json=body, **kwargs)


def _state(env):  # type: ignore[no-untyped-def]
    """Alles, was die neuen Endpunkte verändern könnten."""
    return {
        "targets": [t.to_dict() for t in env.svc.targets.list()],
        "settings": env.svc.settings.load().to_dict(),
        "acked": list(env.alerts.ack_calls),
        "ack_all": env.alerts.ack_all_calls,
        "autostart": list(env.autostart.set_calls),
        "metrics_deleted": list(env.metrics.deleted),
        "removed": (list(env.engine.removed_targets), list(env.engine.removed_checks)),
    }


# --- Status ----------------------------------------------------------------------------------


def test_status_enthaelt_monitor_und_alerts(env):
    env.alerts.add("device_offline", NAS_MAC)
    env.alerts.add("new_device", PC_MAC, acknowledged="2026-10-10T10:00:00+00:00")
    env.alerts.add("service_down", NAS_MAC, closed="2026-10-10T11:00:00+00:00")
    data = env.client.get("/api/status").json()
    assert data["monitor"] == env.svc.monitor.status().to_dict()
    assert data["monitor"]["state"] == "stopped"
    assert data["alerts"] == {"active": 2, "unacked": 1}  # nur diese beiden Zähler, keine Aufschlüsselung
    for key in ("version", "platform", "admin", "scapy", "oui", "job", "guard"):
        assert key in data  # die Felder aus Stufe 1 bleiben


def test_status_zeigt_laufenden_monitor(env, monkeypatch):
    running = MonitorStatus(state="running", interval_s=15, targets=3, online=2, offline=1, db_size_bytes=4096)
    monkeypatch.setattr(env.svc.monitor, "status", lambda: running)
    data = env.client.get("/api/status").json()["monitor"]
    assert data["state"] == "running" and data["targets"] == 3 and data["offline"] == 1 and data["db_size_bytes"] == 4096


def test_status_alerts_null_bei_fehler(env):
    env.alerts.error = RuntimeError("kaputt")
    r = env.client.get("/api/status")
    assert r.status_code == 200
    assert r.json()["alerts"] is None and r.json()["monitor"]["state"] == "stopped"


@pytest.mark.parametrize("counts", [{}, {"active": 1}, {"active": "viele", "unacked": 0}, None, [1, 2]])
def test_status_alerts_null_bei_unlesbaren_zaehlern(env, monkeypatch, counts):
    monkeypatch.setattr(env.alerts, "counts", lambda: counts)
    r = env.client.get("/api/status")
    assert r.status_code == 200 and r.json()["alerts"] is None


def test_status_monitor_null_bei_fehler(env, monkeypatch):
    def boom() -> MonitorStatus:
        raise RuntimeError("kaputt")

    monkeypatch.setattr(env.svc.monitor, "status", boom)
    r = env.client.get("/api/status")
    assert r.status_code == 200 and r.json()["monitor"] is None and r.json()["alerts"] == {"active": 0, "unacked": 0}


def test_hello_enthaelt_monitor_und_alerts(env):
    env.alerts.add("device_offline", NAS_MAC)
    with env.client.websocket_connect(WS_URL, headers={"origin": BASE}) as ws:
        hello = ws.receive_json()
    assert hello["type"] == "hello"
    status = hello["data"]["status"]
    assert status["monitor"]["state"] == "stopped" and status["alerts"] == {"active": 1, "unacked": 1}


# --- Einstellungen ---------------------------------------------------------------------------


def test_einstellungen_lesen_enthaelt_standardwerte(env):
    data = env.client.get("/api/settings").json()
    for key, value in NEW_SETTINGS.items():
        assert data[key] == value, key


def test_einstellungen_schreiben(env):
    body = {
        "monitor_enabled": False,
        "monitor_interval_s": 120,
        "monitor_timeout_ms": 500,
        "alert_offline_minutes": 15,
        "alert_service_minutes": 3,
        "alert_rtt_minutes": 20,
        "alert_new_device": False,
        "alert_new_port": False,
    }
    r = env.client.put("/api/settings", json=body)
    assert r.status_code == 200, r.text
    data = r.json()
    for key, value in body.items():
        assert data[key] == value, key
    stored = env.svc.settings.load()
    for key, value in body.items():
        assert getattr(stored, key) == value, key
    assert env.client.get("/api/settings").json() == data
    assert data["rate_pps"] == 200  # die übrigen Einstellungen blieben


@pytest.mark.parametrize("name", list(INT_SETTINGS))
def test_einstellungen_grenzen_sind_erlaubt(env, name):
    lo, hi = INT_SETTINGS[name]
    assert config.SETTING_LIMITS[name] == (lo, hi)  # die Tabelle hier folgt config
    for value in (lo, hi):
        r = env.client.put("/api/settings", json={name: value})
        assert r.status_code == 200, (name, value, r.text)
        assert r.json()[name] == value


@pytest.mark.parametrize("name, value", [(n, v) for n, (lo, hi) in INT_SETTINGS.items() for v in (lo - 1, hi + 1)])
def test_einstellungen_ausserhalb_der_grenzen(env, name, value):
    before = env.client.get("/api/settings").json()
    r = env.client.put("/api/settings", json={name: value})
    assert r.status_code == 400, r.text
    assert name in r.json()["detail"]
    assert env.client.get("/api/settings").json() == before


@pytest.mark.parametrize("name", list(INT_SETTINGS))
@pytest.mark.parametrize("value", ["60", 60.5, True, False, None, [60], {"wert": 60}, ""])
def test_einstellungen_ganzzahlen_lehnen_falsche_typen_ab(env, name, value):
    before = env.client.get("/api/settings").json()
    r = env.client.put("/api/settings", json={name: value})
    assert r.status_code == 400, r.text
    assert name in r.json()["detail"]
    assert env.client.get("/api/settings").json() == before


@pytest.mark.parametrize("name", BOOL_SETTINGS)
@pytest.mark.parametrize("value", ["true", "false", "ja", 1, 0, None, [], {}, ""])
def test_einstellungen_wahrheitswerte_lehnen_falsche_typen_ab(env, name, value):
    before = env.client.get("/api/settings").json()
    r = env.client.put("/api/settings", json={name: value})
    assert r.status_code == 400, r.text
    assert name in r.json()["detail"]
    assert env.client.get("/api/settings").json() == before


@pytest.mark.parametrize("name", BOOL_SETTINGS)
def test_einstellungen_wahrheitswerte_umschalten(env, name):
    assert env.client.put("/api/settings", json={name: False}).json()[name] is False
    assert env.client.put("/api/settings", json={name: True}).json()[name] is True


@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity"])
def test_einstellungen_nan_und_unendlich(env, literal):
    r = env.client.put("/api/settings", content=f'{{"monitor_interval_s": {literal}}}'.encode(), headers={"content-type": "application/json"})
    assert r.status_code == 400
    assert env.client.get("/api/settings").json()["monitor_interval_s"] == 60


def test_einstellungen_alles_oder_nichts(env):
    before = env.client.get("/api/settings").json()
    r = env.client.put("/api/settings", json={"monitor_interval_s": 30, "alert_rtt_minutes": 0})
    assert r.status_code == 400
    r = env.client.put("/api/settings", json={"monitor_interval_s": 30, "alert_new_port": "nein"})
    assert r.status_code == 400
    r = env.client.put("/api/settings", json={"monitor_interval_s": 30, "monitor_gibt_es_nicht": 1})
    assert r.status_code == 400
    assert env.client.get("/api/settings").json() == before


# --- Origin und Content-Type -----------------------------------------------------------------


@pytest.mark.parametrize("origin", [EVIL, "null", "http://127.0.0.1:9999", "https://127.0.0.1:8765", "http://localhost"])
def test_fremder_origin_wird_bei_allen_schreibenden_endpunkten_abgewiesen(seeded, origin):
    env, check_id = seeded
    before = _state(env)
    for method, template, body in WRITES:
        r = _call(env, method, template, body, check_id, headers={"origin": origin})
        assert r.status_code == 403, (method, template, r.text)
        assert "Origin" in r.json()["detail"]
    assert _state(env) == before  # nichts wurde verändert


@pytest.mark.parametrize("origin", [BASE, "http://localhost:8765", "HTTP://LOCALHOST:8765"])
def test_eigener_origin_ist_erlaubt(seeded, origin):
    env, check_id = seeded
    r = env.client.post("/api/monitor/targets", json={"mac": PC_MAC}, headers={"origin": origin})
    assert r.status_code == 201, r.text
    assert env.client.put("/api/settings", json={"monitor_interval_s": 45}, headers={"origin": origin}).status_code == 200
    assert env.client.put("/api/autostart", json={"enabled": True}, headers={"origin": origin}).status_code == 200
    assert env.client.post("/api/alerts/ack-all", headers={"origin": origin}).status_code == 200


def test_ohne_origin_ist_erlaubt(seeded):
    env, check_id = seeded
    assert env.client.post("/api/alerts/ack-all").status_code == 200  # curl und Skripte senden keinen Origin


def test_lesende_anfragen_pruefen_den_origin_nicht(seeded):
    env, check_id = seeded
    for path in (
        "/api/monitor", f"/api/monitor/targets/{NAS_MAC}", f"/api/monitor/targets/{NAS_MAC}/suggestions",
        f"/api/metrics/series?mac={NAS_MAC}", f"/api/metrics/trend?mac={NAS_MAC}", "/api/metrics/overview",
        "/api/alerts", "/api/alerts/stats", "/api/autostart",
    ):  # fmt: skip
        assert env.client.get(path, headers={"origin": EVIL}).status_code == 200, path


@pytest.mark.parametrize("content_type", ["text/plain", "application/x-www-form-urlencoded", "multipart/form-data", "text/json", "application/xml"])
@pytest.mark.parametrize("method, template, body", [w for w in WRITES if w[2] is not None], ids=[i for i, w in zip(WRITE_IDS, WRITES) if w[2] is not None])
def test_falscher_content_type_ergibt_415(seeded, method, template, body, content_type):
    env, check_id = seeded
    before = _state(env)
    path = template.format(mac=NAS_MAC, check=check_id)
    r = env.client.request(method.upper(), path, content=b'{"enabled": false}', headers={"content-type": content_type})
    assert r.status_code == 415, r.text
    assert _state(env) == before


@pytest.mark.parametrize("method, template, body", [w for w in WRITES if w[2] is not None], ids=[i for i, w in zip(WRITE_IDS, WRITES) if w[2] is not None])
def test_body_ohne_content_type_ergibt_415(seeded, method, template, body):
    env, check_id = seeded
    path = template.format(mac=NAS_MAC, check=check_id)
    r = env.client.request(method.upper(), path, content=b'{"enabled": false}')
    assert r.status_code == 415


def test_content_type_mit_charset_ist_erlaubt(seeded):
    env, check_id = seeded
    r = env.client.patch(
        f"/api/monitor/checks/{check_id}", content=b'{"enabled": false}',
        headers={"content-type": "application/json; charset=utf-8"},
    )  # fmt: skip
    assert r.status_code == 200 and r.json()["enabled"] is False


def test_fremder_host_ergibt_400(seeded):
    env, _ = seeded
    for host in ("evil.example", "192.168.178.20:8765", "127.0.0.1.evil.example"):
        for path in ("/api/monitor", "/api/alerts", "/api/autostart", "/api/metrics/overview"):
            assert env.client.get(path, headers={"host": host}).status_code == 400, (host, path)
        assert env.client.post("/api/monitor/run", headers={"host": host}).status_code == 400


def test_schutz_kopfzeilen_auch_bei_fehlern(seeded):
    env, _ = seeded
    for r in (env.client.get("/api/monitor"), env.client.get("/api/monitor/targets/kein-mac"), env.client.post("/api/monitor/targets", json={})):
        assert r.headers["x-content-type-options"] == "nosniff"
        assert "script-src 'self'" in r.headers["content-security-policy"]


# --- Unbekannte Felder und falsche Typen -----------------------------------------------------

# (Methode, Pfad, Body, erwarteter Text in der Meldung)
UNKNOWN_FIELDS = [
    ("post", "/api/monitor/targets", {"mac": PC_MAC, "admin": True}, "Unbekannte Felder: admin"),
    ("post", "/api/monitor/targets", {"mac": PC_MAC, "MAC": PC_MAC}, "Unbekannte Felder: MAC"),
    ("post", "/api/monitor/targets", {"mac": PC_MAC, "checks": [{"kind": "tcp", "port": 22, "admin": True}]}, "Unbekannte Felder: admin"),
    ("patch", "/api/monitor/targets/{mac}", {"enabled": False, "id": 7}, "Unbekannte Felder: id"),
    ("patch", "/api/monitor/targets/{mac}", {"gateway_mac": "aa:bb:cc:dd:ee:ff"}, "Unbekannte Felder: gateway_mac"),
    ("patch", "/api/monitor/targets/{mac}", {"status": "online"}, "Unbekannte Felder: status"),
    ("post", "/api/monitor/targets/{mac}/checks", {"kind": "tcp", "port": 22, "enabled": False}, "Unbekannte Felder: enabled"),
    ("patch", "/api/monitor/checks/{check}", {"enabled": False, "port": 1}, "Unbekannte Felder: port"),
    ("patch", "/api/monitor/checks/{check}", {"enabled": False, "status": "up"}, "Unbekannte Felder: status"),
    ("put", "/api/autostart", {"enabled": True, "pfad": "x.exe"}, "Unbekannte Felder: pfad"),
    ("put", "/api/settings", {"monitor_interval_s": 30, "monitor_wert": 1}, "monitor_wert"),  # Stufe-1-Regel
]


@pytest.mark.parametrize("method, template, body, text", UNKNOWN_FIELDS)
def test_unbekannte_felder_ergeben_400(seeded, method, template, body, text):
    env, check_id = seeded
    before = _state(env)
    r = _call(env, method, template, body, check_id)
    assert r.status_code == 400, r.text
    assert text in r.json()["detail"]
    assert _state(env) == before  # auch die gültigen Felder daneben wurden nicht übernommen


def test_viele_unbekannte_felder_werden_gekuerzt(seeded):
    env, check_id = seeded
    body = {"mac": PC_MAC, **{f"feld{i}": i for i in range(50)}}
    r = env.client.post("/api/monitor/targets", json=body)
    assert r.status_code == 400
    assert len(r.json()["detail"]) < 200


# (Methode, Pfad, Body): richtiger Aufbau, falscher Typ in einem Feld
WRONG_TYPES = [
    ("post", "/api/monitor/targets", {"mac": ["a"]}),
    ("post", "/api/monitor/targets", {"mac": PC_MAC, "method": ["auto"]}),
    ("post", "/api/monitor/targets", {"mac": PC_MAC, "tcp_port": "445"}),
    ("post", "/api/monitor/targets", {"mac": PC_MAC, "offline_after_min": "5"}),
    ("post", "/api/monitor/targets", {"mac": PC_MAC, "rtt_threshold_ms": "50"}),
    ("post", "/api/monitor/targets", {"mac": PC_MAC, "checks": {"kind": "tcp", "port": 22}}),
    ("post", "/api/monitor/targets", {"mac": PC_MAC, "checks": [{"kind": "tcp", "port": "22"}]}),
    ("patch", "/api/monitor/targets/{mac}", {"enabled": "true"}),
    ("patch", "/api/monitor/targets/{mac}", {"enabled": "false"}),
    ("patch", "/api/monitor/targets/{mac}", {"enabled": 1}),
    ("patch", "/api/monitor/targets/{mac}", {"tcp_port": "445"}),
    ("patch", "/api/monitor/targets/{mac}", {"offline_after_min": 2.5}),
    ("patch", "/api/monitor/targets/{mac}", {"rtt_threshold_ms": False}),
    ("post", "/api/monitor/targets/{mac}/checks", {"kind": "tcp", "port": "22"}),
    ("post", "/api/monitor/targets/{mac}/checks", {"kind": ["tcp"], "port": 22}),
    ("post", "/api/monitor/targets/{mac}/checks", {"kind": "http", "port": 80, "path": ["/"]}),
    ("patch", "/api/monitor/checks/{check}", {"enabled": "true"}),
    ("patch", "/api/monitor/checks/{check}", {"enabled": "false"}),
    ("patch", "/api/monitor/checks/{check}", {"enabled": 0}),
    ("put", "/api/autostart", {"enabled": "true"}),
    ("put", "/api/autostart", {"enabled": 1}),
]


@pytest.mark.parametrize("method, template, body", WRONG_TYPES)
def test_falsche_typen_ergeben_400(seeded, method, template, body):
    env, check_id = seeded
    before = _state(env)
    r = _call(env, method, template, body, check_id)
    assert r.status_code == 400, r.text
    assert isinstance(r.json()["detail"], str) and r.json()["detail"]  # Text, keine Fehlerliste
    assert _state(env) == before


@pytest.mark.parametrize("method, template", [(m, p) for m, p, b in WRITES if b is not None and p not in ("/api/settings",)])
@pytest.mark.parametrize("content", [b"{", b"[]", b"null", b'"text"', b"5", b""])
def test_kaputter_body_ergibt_400(seeded, method, template, content):
    env, check_id = seeded
    before = _state(env)
    path = template.format(mac=NAS_MAC, check=check_id)
    r = env.client.request(method.upper(), path, content=content, headers={"content-type": "application/json"})
    assert r.status_code == 400, (r.status_code, r.text)
    assert isinstance(r.json()["detail"], str)
    assert _state(env) == before
