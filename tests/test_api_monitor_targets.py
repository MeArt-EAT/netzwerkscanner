"""Überwachungs-API: Ziele, Dienstprüfungen, Dienstvorschläge, „Jetzt prüfen“ (BAUPLAN §27).

Alles gegen TestClient und Attrappen (siehe test_api_monitor_support) – kein Paket verlässt den Rechner.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from netscan import config
from netscan.core.monitor import Monitor
from netscan.net import checks as checks_module
from tests.test_api_monitor_support import (  # noqa: F401  (Fixtures env und client)
    NAS_IP,
    NAS_MAC,
    NOW,
    PC_IP,
    PC_MAC,
    PHONE_IP,
    PHONE_MAC,
    UNKNOWN_MAC,
    client,
    env,
)

DEVICE_KEYS = {"mac", "ip", "display_name", "category", "category_label", "is_self", "online", "mac_random"}
EMPTY_AVAIL = {"up_pct": None, "samples": 0, "up": 0}


def _targets(env) -> list[dict]:  # type: ignore[no-untyped-def]
    return env.client.get("/api/monitor").json()["targets"]


# --- Übersicht und Ansicht -------------------------------------------------------------------


def test_monitor_ohne_ziele(client):
    data = client.get("/api/monitor").json()
    assert data["targets"] == []
    assert data["status"]["state"] == "stopped"  # der Thread läuft in Tests nie
    assert {"reason", "interval_s", "last_cycle", "next_cycle", "targets", "online", "offline", "db_size_bytes"} <= set(data["status"])


def test_ziel_anlegen_minimal(env):
    r = env.client.post("/api/monitor/targets", json={"mac": NAS_MAC})
    assert r.status_code == 201, r.text
    data = r.json()
    assert data["mac"] == NAS_MAC and isinstance(data["id"], int)
    assert data["enabled"] is True and data["method"] == "auto" and data["status"] == "unknown"
    assert data["tcp_port"] is None and data["offline_after_min"] is None and data["rtt_threshold_ms"] is None
    assert data["checks"] == [] and data["status_label"] == "unbekannt"
    assert env.svc.targets.get(NAS_MAC).id == data["id"]
    assert len(env.events("monitor.targets")) == 1


def test_ziel_anlegen_mit_allen_angaben(env):
    body = {
        "mac": "00-11-32-AA-BB-03",
        "method": "tcp",
        "tcp_port": 445,
        "offline_after_min": 10,
        "rtt_threshold_ms": 80,
        "checks": [
            {"kind": "smb", "port": 445},
            {"kind": "http", "port": 5000, "path": "/status"},
            {"kind": "tcp", "port": 22, "path": None},
        ],
    }
    r = env.client.post("/api/monitor/targets", json=body)
    assert r.status_code == 201, r.text
    data = r.json()
    assert data["mac"] == NAS_MAC
    assert (data["method"], data["tcp_port"], data["offline_after_min"], data["rtt_threshold_ms"]) == ("tcp", 445, 10, 80.0)
    by_port = {c["port"]: c for c in data["checks"]}
    assert {p: (c["kind"], c["path"]) for p, c in by_port.items()} == {
        22: ("tcp", "/"),
        445: ("smb", "/"),
        5000: ("http", "/status"),
    }
    stored = env.svc.targets.get(NAS_MAC)
    assert stored.rtt_threshold_ms == 80.0 and len(stored.checks) == 3


def test_ziel_ansicht_enthaelt_geraet(env):
    env.add_target(NAS_MAC)
    env.add_target(PC_MAC)
    env.add_target(PHONE_MAC)
    views = {t["mac"]: t for t in _targets(env)}
    nas, pc, phone = views[NAS_MAC], views[PC_MAC], views[PHONE_MAC]
    for view in views.values():
        assert set(view["device"]) == DEVICE_KEYS
    assert nas["device"] == {
        "mac": NAS_MAC, "ip": NAS_IP, "display_name": "NAS", "category": "server", "category_label": "Server/NAS",
        "is_self": False, "online": False, "mac_random": False,
    }  # fmt: skip
    assert pc["device"]["is_self"] is True and pc["device"]["ip"] == PC_IP and pc["device"]["category"] == "pc"
    assert pc["device"]["display_name"] == PC_IP  # kein Name bekannt: die IP
    assert phone["device"]["mac_random"] is True and phone["device"]["category_label"] == "Handy"
    assert phone["device"]["online"] is True and phone["device"]["ip"] == PHONE_IP  # im letzten Scan gesehen


def test_ziel_ansicht_verfuegbarkeit_standard_und_gemessen(env):
    t = env.add_target(NAS_MAC, checks=[{"kind": "smb", "port": 445}, {"kind": "tcp", "port": 22}])
    smb, ssh = sorted(t["checks"], key=lambda c: c["port"], reverse=True)
    assert t["availability"] == {"24h": EMPTY_AVAIL, "7d": EMPTY_AVAIL}
    assert all(c["availability"] == {"24h": EMPTY_AVAIL, "7d": EMPTY_AVAIL} for c in t["checks"])

    env.metrics.avail = {
        (t["id"], 0): {"24h": {"up_pct": 99.5, "samples": 1440, "up": 1433}, "7d": {"up_pct": 98.0, "samples": 10080, "up": 9878}},
        (t["id"], smb["id"]): {"24h": {"up_pct": 50.0, "samples": 10, "up": 5}, "7d": {"up_pct": 60.0, "samples": 20, "up": 12}},
    }
    got = env.client.get(f"/api/monitor/targets/{NAS_MAC}").json()
    assert got["availability"]["24h"] == {"up_pct": 99.5, "samples": 1440, "up": 1433}
    assert got["availability"]["7d"]["up_pct"] == 98.0
    checks = {c["port"]: c for c in got["checks"]}
    assert checks[445]["availability"]["24h"]["up_pct"] == 50.0 and checks[445]["availability"]["7d"]["samples"] == 20
    assert checks[22]["availability"] == {"24h": EMPTY_AVAIL, "7d": EMPTY_AVAIL}  # ohne Messwerte: leer, nicht fremd
    assert checks[445]["label"] == "SMB-Freigabe 445"


def test_ziel_ansicht_verfuegbarkeit_unvollstaendig_und_kaputt(env):
    t = env.add_target(NAS_MAC)
    env.metrics.avail = {(t["id"], 0): {"24h": {"up_pct": 100.0, "samples": 3, "up": 3}, "7d": "kaputt"}}
    got = env.client.get(f"/api/monitor/targets/{NAS_MAC}").json()
    assert got["availability"]["24h"]["up_pct"] == 100.0
    assert got["availability"]["7d"] == EMPTY_AVAIL


def test_liste_liest_verfuegbarkeit_einmal(env):
    env.add_target(NAS_MAC, checks=[{"kind": "smb", "port": 445}, {"kind": "http", "port": 5000}])
    env.add_target(PC_MAC)
    env.metrics.avail_calls.clear()
    data = env.client.get("/api/monitor").json()
    assert [t["mac"] for t in data["targets"]] == [NAS_MAC, PC_MAC]  # in der Reihenfolge des Anlegens
    assert env.metrics.avail_calls == [NOW]  # einmal je Anfrage, nicht je Ziel oder Prüfung
    env.client.get(f"/api/monitor/targets/{NAS_MAC}")
    assert env.metrics.avail_calls == [NOW, NOW]


def test_liste_ohne_ziele_fragt_keine_metrik(env):
    env.client.get("/api/monitor")
    assert env.metrics.avail_calls == []


def test_liste_ueberlebt_defekte_metrik(env):
    env.add_target(NAS_MAC)
    env.metrics.error = RuntimeError("kaputt")
    r = env.client.get("/api/monitor")
    assert r.status_code == 200
    assert r.json()["targets"][0]["availability"] == {"24h": EMPTY_AVAIL, "7d": EMPTY_AVAIL}


def test_liste_zeigt_zustand_des_monitors(env):
    env.add_target(NAS_MAC)
    status = env.client.get("/api/monitor").json()["status"]
    assert status == env.svc.monitor.status().to_dict()


# --- Einzelnes Ziel, MAC im Pfad -------------------------------------------------------------


def test_einzelnes_ziel_und_404(env):
    assert env.client.get(f"/api/monitor/targets/{NAS_MAC}").status_code == 404  # noch nicht überwacht
    env.add_target(NAS_MAC)
    r = env.client.get(f"/api/monitor/targets/{NAS_MAC}")
    assert r.status_code == 200 and r.json()["mac"] == NAS_MAC
    for mac in (PC_MAC, UNKNOWN_MAC, "kein-mac", "00:11:32"):  # Gerät ohne Überwachung, unbekannt, ungültig
        r = env.client.get(f"/api/monitor/targets/{mac}")
        assert r.status_code == 404, mac
        assert r.json()["detail"]


@pytest.mark.parametrize("form", ["00:11:32:AA:BB:03", "00-11-32-aa-bb-03", "001132AABB03", "0011.32aa.bb03"])
def test_mac_im_pfad_wird_normalisiert(env, form):
    env.add_target(NAS_MAC)
    r = env.client.get(f"/api/monitor/targets/{form}")
    assert r.status_code == 200 and r.json()["mac"] == NAS_MAC
    assert env.client.patch(f"/api/monitor/targets/{form}", json={"method": "ping"}).json()["method"] == "ping"
    assert env.client.get(f"/api/monitor/targets/{form}/suggestions").status_code == 200


# --- Anlegen: Fehler -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body, code, stichwort",
    [
        ({"mac": UNKNOWN_MAC}, 404, "Gerät"),
        ({"mac": "kein-mac"}, 400, "MAC"),
        ({"mac": ""}, 400, "MAC"),
        ({"mac": 5}, 400, "mac"),
        ({"mac": None}, 400, "mac"),
        ({}, 400, "mac"),
        ({"mac": NAS_MAC, "method": "icmp"}, 400, "Erreichbarkeitstest"),
        ({"mac": NAS_MAC, "method": 5}, 400, "method"),
        ({"mac": NAS_MAC, "tcp_port": 0}, 400, "tcp_port"),
        ({"mac": NAS_MAC, "tcp_port": 65536}, 400, "tcp_port"),
        ({"mac": NAS_MAC, "tcp_port": "80"}, 400, "tcp_port"),
        ({"mac": NAS_MAC, "tcp_port": 80.5}, 400, "tcp_port"),
        ({"mac": NAS_MAC, "tcp_port": True}, 400, "tcp_port"),
        ({"mac": NAS_MAC, "offline_after_min": 0}, 400, "offline_after_min"),
        ({"mac": NAS_MAC, "offline_after_min": 1441}, 400, "offline_after_min"),
        ({"mac": NAS_MAC, "offline_after_min": 5.5}, 400, "offline_after_min"),
        ({"mac": NAS_MAC, "offline_after_min": "5"}, 400, "offline_after_min"),
        ({"mac": NAS_MAC, "rtt_threshold_ms": 0}, 400, "rtt_threshold_ms"),
        ({"mac": NAS_MAC, "rtt_threshold_ms": 10001}, 400, "rtt_threshold_ms"),
        ({"mac": NAS_MAC, "rtt_threshold_ms": "schnell"}, 400, "rtt_threshold_ms"),
        ({"mac": NAS_MAC, "rtt_threshold_ms": True}, 400, "rtt_threshold_ms"),
        ({"mac": NAS_MAC, "checks": "smb"}, 400, "checks"),
        ({"mac": NAS_MAC, "checks": [5]}, 400, "checks[0]"),
        ({"mac": NAS_MAC, "checks": [{"kind": "smb"}]}, 400, "port"),
        ({"mac": NAS_MAC, "checks": [{"port": 445}]}, 400, "kind"),
        ({"mac": NAS_MAC, "checks": [{"kind": "ftp", "port": 21}]}, 400, "Dienstprüfung"),
        ({"mac": NAS_MAC, "checks": [{"kind": 5, "port": 21}]}, 400, "kind"),
        ({"mac": NAS_MAC, "checks": [{"kind": "tcp", "port": 0}]}, 400, "port"),
        ({"mac": NAS_MAC, "checks": [{"kind": "tcp", "port": 65536}]}, 400, "port"),
        ({"mac": NAS_MAC, "checks": [{"kind": "tcp", "port": "22"}]}, 400, "port"),
        ({"mac": NAS_MAC, "checks": [{"kind": "tcp", "port": True}]}, 400, "port"),
        ({"mac": NAS_MAC, "checks": [{"kind": "http", "port": 80, "path": "status"}]}, 400, "path"),
        ({"mac": NAS_MAC, "checks": [{"kind": "http", "port": 80, "path": 5}]}, 400, "path"),
        ({"mac": NAS_MAC, "checks": [{"kind": "http", "port": 80, "path": "/a b"}]}, 400, "path"),
        ({"mac": NAS_MAC, "checks": [{"kind": "smb", "port": 445}, {"kind": "smb", "port": 445}]}, 400, "doppelt"),
        ({"mac": NAS_MAC, "checks": [{"kind": "tcp", "port": 1000 + i} for i in range(config.MAX_CHECKS_PER_TARGET + 1)]}, 400, "checks"),
    ],
)
def test_anlegen_fehler(env, body, code, stichwort):
    r = env.client.post("/api/monitor/targets", json=body)
    assert r.status_code == code, r.text
    assert stichwort in r.json()["detail"]
    assert _targets(env) == []  # alles oder nichts: auch bei einer kaputten Prüfung entsteht kein Ziel
    assert env.events("monitor.targets") == []


def test_anlegen_doppelt_ergibt_409(env):
    env.add_target(NAS_MAC)
    r = env.client.post("/api/monitor/targets", json={"mac": "00-11-32-AA-BB-03", "method": "tcp"})
    assert r.status_code == 409
    assert "überwacht" in r.json()["detail"]
    targets = _targets(env)
    assert len(targets) == 1 and targets[0]["method"] == "auto"  # das bestehende Ziel blieb unberührt


def test_anlegen_obergrenze_der_ziele(env, monkeypatch):
    monkeypatch.setattr(config, "MAX_TARGETS", 1)
    env.add_target(NAS_MAC)
    r = env.client.post("/api/monitor/targets", json={"mac": PC_MAC})
    assert r.status_code == 400 and "Höchstens 1" in r.json()["detail"]
    assert [t["mac"] for t in _targets(env)] == [NAS_MAC]


def test_anlegen_ungueltiger_body(env):
    headers = {"content-type": "application/json"}
    for content, stichwort in ((b"{", "JSON"), (b"[]", "Objekt"), (b"5", "Objekt"), (b"", "Body")):
        r = env.client.post("/api/monitor/targets", content=content, headers=headers)
        assert r.status_code == 400, content
        assert stichwort in r.json()["detail"], content
    r = env.client.post("/api/monitor/targets")  # ganz ohne Body
    assert r.status_code == 400 and "Body" in r.json()["detail"]
    assert _targets(env) == []


# --- Ändern ----------------------------------------------------------------------------------


def test_aendern_setzt_felder(env):
    env.add_target(NAS_MAC)
    before = len(env.events("monitor.targets"))
    r = env.client.patch(
        f"/api/monitor/targets/{NAS_MAC}",
        json={"method": "tcp", "tcp_port": 445, "offline_after_min": 15, "rtt_threshold_ms": 120.5},
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert (data["method"], data["tcp_port"], data["offline_after_min"], data["rtt_threshold_ms"]) == ("tcp", 445, 15, 120.5)
    assert set(data["device"]) == DEVICE_KEYS and "availability" in data
    stored = env.svc.targets.get(NAS_MAC)
    assert (stored.method, stored.tcp_port, stored.offline_after_min, stored.rtt_threshold_ms) == ("tcp", 445, 15, 120.5)
    assert len(env.events("monitor.targets")) == before + 1


def test_aendern_null_setzt_zurueck(env):
    env.add_target(NAS_MAC, tcp_port=445, offline_after_min=9, rtt_threshold_ms=50)
    r = env.client.patch(f"/api/monitor/targets/{NAS_MAC}", json={"tcp_port": None, "offline_after_min": None, "rtt_threshold_ms": None})
    assert r.status_code == 200, r.text
    data = r.json()
    assert (data["tcp_port"], data["offline_after_min"], data["rtt_threshold_ms"]) == (None, None, None)


def test_aendern_betrifft_nur_gesendete_felder(env):
    env.add_target(NAS_MAC, tcp_port=445, offline_after_min=9)
    data = env.client.patch(f"/api/monitor/targets/{NAS_MAC}", json={"offline_after_min": None}).json()
    assert data["tcp_port"] == 445 and data["offline_after_min"] is None


def test_aendern_leerer_body_aendert_nichts(env):
    before = env.add_target(NAS_MAC, tcp_port=445)
    r = env.client.patch(f"/api/monitor/targets/{NAS_MAC}", json={})
    assert r.status_code == 200
    assert r.json()["tcp_port"] == 445 and r.json()["id"] == before["id"]


def test_abschalten_pausiert_und_einschalten_setzt_zurueck(env):
    env.add_target(NAS_MAC, checks=[{"kind": "smb", "port": 445}])
    off = env.client.patch(f"/api/monitor/targets/{NAS_MAC}", json={"enabled": False}).json()
    assert off["enabled"] is False and off["status"] == "paused" and off["pause_code"] == "disabled"
    assert off["status_label"] == "pausiert" and off["pause_reason"]
    assert env.engine.removed_targets == [NAS_MAC]  # Zustands-Alerts werden geschlossen
    assert env.svc.targets.get(NAS_MAC).enabled is False

    on = env.client.patch(f"/api/monitor/targets/{NAS_MAC}", json={"enabled": True}).json()
    assert on["enabled"] is True and on["status"] == "unknown" and on["pause_code"] is None


def test_aendern_404(env):
    env.add_target(NAS_MAC)
    for mac in (PC_MAC, UNKNOWN_MAC, "kein-mac"):
        r = env.client.patch(f"/api/monitor/targets/{mac}", json={"method": "ping"})
        assert r.status_code == 404, mac


@pytest.mark.parametrize(
    "body, stichwort",
    [
        ({"enabled": None}, "enabled"),
        ({"enabled": "true"}, "enabled"),
        ({"enabled": 1}, "enabled"),
        ({"method": None}, "method"),
        ({"method": "icmp"}, "Erreichbarkeitstest"),
        ({"method": 5}, "method"),
        ({"tcp_port": 0}, "tcp_port"),
        ({"tcp_port": 65536}, "tcp_port"),
        ({"tcp_port": "80"}, "tcp_port"),
        ({"tcp_port": 1.5}, "tcp_port"),
        ({"tcp_port": False}, "tcp_port"),
        ({"offline_after_min": 0}, "offline_after_min"),
        ({"offline_after_min": 1441}, "offline_after_min"),
        ({"offline_after_min": "5"}, "offline_after_min"),
        ({"rtt_threshold_ms": 0}, "rtt_threshold_ms"),
        ({"rtt_threshold_ms": 10001}, "rtt_threshold_ms"),
        ({"rtt_threshold_ms": "x"}, "rtt_threshold_ms"),
        ({"rtt_threshold_ms": True}, "rtt_threshold_ms"),
        ({"method": "tcp", "tcp_port": 0}, "tcp_port"),  # nichts wird halb übernommen
    ],
)
def test_aendern_fehler(env, body, stichwort):
    env.add_target(NAS_MAC, tcp_port=445)
    before = env.svc.targets.get(NAS_MAC)
    r = env.client.patch(f"/api/monitor/targets/{NAS_MAC}", json=body)
    assert r.status_code == 400, r.text
    assert stichwort in r.json()["detail"]
    assert env.svc.targets.get(NAS_MAC) == before


# --- Löschen ---------------------------------------------------------------------------------


def test_loeschen_entfernt_ziel_messwerte_und_alerts(env):
    t = env.add_target(NAS_MAC, checks=[{"kind": "smb", "port": 445}])
    other = env.add_target(PC_MAC)
    check_id = t["checks"][0]["id"]
    r = env.client.delete(f"/api/monitor/targets/{NAS_MAC}")
    assert r.status_code == 204 and r.content == b""
    assert env.client.get(f"/api/monitor/targets/{NAS_MAC}").status_code == 404
    assert env.svc.targets.get_check(check_id) is None  # Prüfungen gehen mit
    assert (t["id"], None) in env.metrics.deleted  # alle Reihen des Ziels
    assert env.engine.removed_targets == [NAS_MAC]
    assert [x["mac"] for x in _targets(env)] == [PC_MAC] and _targets(env)[0]["id"] == other["id"]
    assert len(env.events("monitor.targets")) == 3  # zweimal angelegt, einmal gelöscht


def test_loeschen_404(env):
    env.add_target(NAS_MAC)
    for mac in (PC_MAC, UNKNOWN_MAC, "kein-mac"):
        assert env.client.delete(f"/api/monitor/targets/{mac}").status_code == 404, mac
    assert env.client.delete(f"/api/monitor/targets/{NAS_MAC}").status_code == 204
    assert env.client.delete(f"/api/monitor/targets/{NAS_MAC}").status_code == 404  # zweites Mal


def test_loeschen_und_neu_anlegen(env):
    env.add_target(NAS_MAC, tcp_port=445, checks=[{"kind": "smb", "port": 445}])
    env.client.delete(f"/api/monitor/targets/{NAS_MAC}")
    second = env.add_target(NAS_MAC)
    assert second["checks"] == [] and second["tcp_port"] is None  # keine Reste des alten Ziels
    assert second["status"] == "unknown"


@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity", "1e999"])
def test_zahlen_ohne_grenze_werden_abgelehnt(env, literal):
    env.add_target(NAS_MAC)
    headers = {"content-type": "application/json"}
    r = env.client.patch(f"/api/monitor/targets/{NAS_MAC}", content=f'{{"rtt_threshold_ms": {literal}}}'.encode(), headers=headers)
    assert r.status_code == 400, r.text
    r = env.client.post("/api/monitor/targets", content=f'{{"mac": "{PC_MAC}", "rtt_threshold_ms": {literal}}}'.encode(), headers=headers)
    assert r.status_code == 400, r.text
    assert env.svc.targets.get(NAS_MAC).rtt_threshold_ms is None


# --- Dienstvorschläge ------------------------------------------------------------------------


SUGGESTIONS = [
    {"kind": "smb", "port": 445, "path": "/", "label": "SMB-Freigabe 445", "reason": "Port 445 ist offen"},
    {"kind": "http", "port": 5000, "path": "/", "label": "HTTP 5000", "reason": "Port 5000 ist offen"},
]


def test_vorschlaege_fuer_nicht_ueberwachtes_geraet(env, monkeypatch):
    monkeypatch.setattr(checks_module, "suggest_checks", lambda device: [dict(s) for s in SUGGESTIONS])
    r = env.client.get(f"/api/monitor/targets/{NAS_MAC}/suggestions")
    assert r.status_code == 200, r.text
    data = r.json()
    assert [(s["kind"], s["port"]) for s in data] == [("smb", 445), ("http", 5000)]
    assert all(set(s) == {"kind", "port", "path", "label", "reason", "active"} for s in data)
    assert all(s["active"] is False for s in data)


def test_vorschlaege_kennzeichnen_aktive_pruefungen(env, monkeypatch):
    monkeypatch.setattr(checks_module, "suggest_checks", lambda device: [dict(s) for s in SUGGESTIONS])
    env.add_target(NAS_MAC, checks=[{"kind": "smb", "port": 445}, {"kind": "tcp", "port": 5000}])
    data = {s["port"]: s for s in env.client.get(f"/api/monitor/targets/{NAS_MAC}/suggestions").json()}
    assert data[445]["active"] is True
    assert data[5000]["active"] is False  # tcp 5000 ist nicht http 5000


def test_vorschlaege_nutzen_die_offenen_ports_des_geraets(env):
    data = env.client.get(f"/api/monitor/targets/{NAS_MAC}/suggestions").json()  # Standard-Attrappe: je offener Port
    assert sorted(s["port"] for s in data) == [445, 5000]
    assert env.client.get(f"/api/monitor/targets/{PC_MAC}/suggestions").json() == []  # keine offenen Ports


def test_vorschlaege_404(env):
    for mac in (UNKNOWN_MAC, "kein-mac"):
        assert env.client.get(f"/api/monitor/targets/{mac}/suggestions").status_code == 404, mac


# --- Dienstprüfungen -------------------------------------------------------------------------


def test_pruefung_anlegen(env):
    target = env.add_target(NAS_MAC)
    r = env.client.post(f"/api/monitor/targets/{NAS_MAC}/checks", json={"kind": "http", "port": 8080, "path": "/health"})
    assert r.status_code == 201, r.text
    check = r.json()
    assert check["target_id"] == target["id"] and isinstance(check["id"], int)
    assert (check["kind"], check["port"], check["path"]) == ("http", 8080, "/health")
    assert check["enabled"] is True and check["status"] == "unknown" and check["label"] == "HTTP 8080"
    assert "availability" not in check  # es ist die ServiceCheck-Ansicht, nicht die Ziel-Ansicht
    shown = env.client.get(f"/api/monitor/targets/{NAS_MAC}").json()["checks"]
    assert [c["id"] for c in shown] == [check["id"]]
    assert len(env.events("monitor.targets")) == 2


@pytest.mark.parametrize("body", [{"kind": "tcp", "port": 22}, {"kind": "tcp", "port": 22, "path": None}])
def test_pruefung_standardpfad(env, body):
    env.add_target(NAS_MAC)
    r = env.client.post(f"/api/monitor/targets/{NAS_MAC}/checks", json=body)
    assert r.status_code == 201 and r.json()["path"] == "/"


def test_pruefung_doppelt_ergibt_409(env):
    env.add_target(NAS_MAC)
    url = f"/api/monitor/targets/{NAS_MAC}/checks"
    assert env.client.post(url, json={"kind": "tcp", "port": 80}).status_code == 201
    r = env.client.post(url, json={"kind": "tcp", "port": 80, "path": "/anders"})
    assert r.status_code == 409 and "gibt es schon" in r.json()["detail"]
    assert env.client.post(url, json={"kind": "http", "port": 80}).status_code == 201  # andere Art, gleicher Port
    assert len(env.svc.targets.get(NAS_MAC).checks) == 2


@pytest.mark.parametrize("mac", [PC_MAC, UNKNOWN_MAC, "kein-mac"])
def test_pruefung_anlegen_404(env, mac):
    env.add_target(NAS_MAC)
    r = env.client.post(f"/api/monitor/targets/{mac}/checks", json={"kind": "tcp", "port": 22})
    assert r.status_code == 404


@pytest.mark.parametrize(
    "body, stichwort",
    [
        ({}, "kind"),
        ({"port": 22}, "kind"),
        ({"kind": "tcp"}, "port"),
        ({"kind": "ftp", "port": 21}, "Dienstprüfung"),
        ({"kind": 5, "port": 21}, "kind"),
        ({"kind": None, "port": 21}, "kind"),
        ({"kind": "tcp", "port": 0}, "port"),
        ({"kind": "tcp", "port": 65536}, "port"),
        ({"kind": "tcp", "port": "22"}, "port"),
        ({"kind": "tcp", "port": 22.0}, "port"),
        ({"kind": "tcp", "port": True}, "port"),
        ({"kind": "http", "port": 80, "path": "status"}, "path"),
        ({"kind": "http", "port": 80, "path": ""}, "path"),
        ({"kind": "http", "port": 80, "path": 5}, "path"),
        ({"kind": "http", "port": 80, "path": "/a\tb"}, "path"),
        ({"kind": "http", "port": 80, "path": "/" + "x" * 200}, "path"),
    ],
)
def test_pruefung_anlegen_fehler(env, body, stichwort):
    env.add_target(NAS_MAC)
    r = env.client.post(f"/api/monitor/targets/{NAS_MAC}/checks", json=body)
    assert r.status_code == 400, r.text
    assert stichwort in r.json()["detail"]
    assert env.svc.targets.get(NAS_MAC).checks == []


def test_pruefung_obergrenze(env, monkeypatch):
    monkeypatch.setattr(config, "MAX_CHECKS_PER_TARGET", 2)
    env.add_target(NAS_MAC)
    url = f"/api/monitor/targets/{NAS_MAC}/checks"
    assert env.client.post(url, json={"kind": "tcp", "port": 21}).status_code == 201
    assert env.client.post(url, json={"kind": "tcp", "port": 22}).status_code == 201
    r = env.client.post(url, json={"kind": "tcp", "port": 23})
    assert r.status_code == 400 and "Höchstens 2" in r.json()["detail"]


def test_pruefung_umschalten(env):
    t = env.add_target(NAS_MAC, checks=[{"kind": "smb", "port": 445}])
    cid = t["checks"][0]["id"]
    off = env.client.patch(f"/api/monitor/checks/{cid}", json={"enabled": False})
    assert off.status_code == 200, off.text
    assert off.json()["id"] == cid and off.json()["enabled"] is False
    assert env.svc.targets.get_check(cid).enabled is False
    assert env.engine.removed_checks == [cid]  # Dienst-Alert wird geschlossen
    on = env.client.patch(f"/api/monitor/checks/{cid}", json={"enabled": True})
    assert on.status_code == 200 and on.json()["enabled"] is True
    assert env.engine.removed_checks == [cid]  # Einschalten schließt nichts


@pytest.mark.parametrize("check_id", ["999", "0", "abc", "-1", "1.5", "1e3", " 1", "99999999999999999999999999"])
def test_pruefung_unbekannte_kennung_ergibt_404(env, check_id):
    env.add_target(NAS_MAC, checks=[{"kind": "smb", "port": 445}])
    assert env.client.patch(f"/api/monitor/checks/{check_id}", json={"enabled": False}).status_code == 404
    assert env.client.delete(f"/api/monitor/checks/{check_id}").status_code == 404
    assert len(env.svc.targets.get(NAS_MAC).checks) == 1


@pytest.mark.parametrize("body", [{}, {"enabled": None}, {"enabled": "false"}, {"enabled": 0}, {"enabled": "true"}, []])
def test_pruefung_umschalten_fehler(env, body):
    t = env.add_target(NAS_MAC, checks=[{"kind": "smb", "port": 445}])
    cid = t["checks"][0]["id"]
    r = env.client.patch(f"/api/monitor/checks/{cid}", json=body)
    assert r.status_code == 400, r.text
    assert env.svc.targets.get_check(cid).enabled is True


def test_pruefung_loeschen(env):
    t = env.add_target(NAS_MAC, checks=[{"kind": "smb", "port": 445}, {"kind": "tcp", "port": 22}])
    smb = next(c for c in t["checks"] if c["kind"] == "smb")
    r = env.client.delete(f"/api/monitor/checks/{smb['id']}")
    assert r.status_code == 204 and r.content == b""
    left = env.client.get(f"/api/monitor/targets/{NAS_MAC}").json()["checks"]
    assert [c["kind"] for c in left] == ["tcp"]
    assert (t["id"], smb["id"]) in env.metrics.deleted  # nur die Reihe dieser Prüfung
    assert env.engine.removed_checks == [smb["id"]]
    assert env.client.delete(f"/api/monitor/checks/{smb['id']}").status_code == 404


# --- Jetzt prüfen ----------------------------------------------------------------------------


def test_jetzt_pruefen_ohne_laufenden_monitor(env, monkeypatch):
    calls: list[int] = []
    monkeypatch.setattr(env.svc.monitor, "trigger", lambda: calls.append(1))
    r = env.client.post("/api/monitor/run")
    assert r.status_code == 409
    assert r.json()["detail"] == "Die Überwachung läuft nicht."
    assert calls == []


def test_jetzt_pruefen_stoesst_den_durchlauf_an(env, monkeypatch):
    calls: list[int] = []
    monkeypatch.setattr(Monitor, "running", property(lambda self: True))
    monkeypatch.setattr(env.svc.monitor, "trigger", lambda: calls.append(1))
    r = env.client.post("/api/monitor/run")
    assert r.status_code == 202
    assert r.json() == {"started": True}
    assert calls == [1]


def test_jetzt_pruefen_mit_echtem_thread(env):
    """Der echte Thread läuft ohne Ziele nur im Leerlauf (kein Netz); trigger() weckt ihn."""
    monitor = env.svc.monitor
    monitor.start()
    try:
        assert monitor.running
        r = env.client.post("/api/monitor/run")
        assert r.status_code == 202 and r.json() == {"started": True}
    finally:
        monitor.stop()
    assert env.client.post("/api/monitor/run").status_code == 409  # nach dem Anhalten wieder abgewiesen


# --- Dienst nicht bereit ---------------------------------------------------------------------


def test_ohne_services_antwortet_503():
    """Ohne Lebenszyklus (kein `with`) gibt es keine Services und build_services() läuft nie."""
    from netscan.web import server

    c = TestClient(server.create_app(None), base_url="http://127.0.0.1:8765")
    for path in ("/api/monitor", "/api/alerts", "/api/metrics/overview"):
        r = c.get(path)
        assert r.status_code == 503, path
        assert "startet" in r.json()["detail"]
