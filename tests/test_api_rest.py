"""REST-Schnittstelle des Webservers: Statuscodes, Wächter-Schranke, Geräte, Einstellungen, Export.

Alles gegen TestClient und Attrappen (siehe test_api_support) – kein Paket verlässt den Rechner.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import replace

import pytest

from netscan.core.models import Device, NameInfo
from tests.fakes import make_adapter
from tests.test_api_support import (  # noqa: F401  (Fixtures env und client)
    ALLOW,
    BLOCK,
    CONFIRM,
    add_devices,
    client,
    env,
    sample_device,
    sample_port,
)

SCAN = {"adapter": "Ethernet"}


# --- Status, Adapter, Wächter ----------------------------------------------------------------


def test_status_enthaelt_alle_felder(client, env):
    r = client.get("/api/status")
    assert r.status_code == 200
    data = r.json()
    assert data["version"]
    assert data["platform"] == "fake"
    assert data["admin"] is True
    assert data["scapy"] == {"available": True, "reason": "Npcap erkannt (Test)"}
    assert data["oui"] == {"entries": env.svc.oui.entries, "source": env.svc.oui.source}
    assert data["job"]["state"] == "idle"
    assert data["guard"] is None  # weder adapter noch last_adapter


def test_status_guard_mit_adapter_und_last_adapter(client, env):
    data = client.get("/api/status", params={"adapter": "Ethernet"}).json()
    assert data["guard"]["decision"] == "allow"
    assert env.guard.checked[-1].name == "Ethernet"

    env.svc.settings.update(last_adapter="WLAN")
    data = client.get("/api/status").json()
    assert data["guard"]["code"] == "ok_home"
    assert env.guard.checked[-1].name == "WLAN"


def test_status_guard_fehler_oder_unbekannter_adapter_ergibt_null(client, env):
    assert client.get("/api/status", params={"adapter": "gibt-es-nicht"}).json()["guard"] is None
    env.guard.error = RuntimeError("kaputt")
    r = client.get("/api/status", params={"adapter": "Ethernet"})
    assert r.status_code == 200
    assert r.json()["guard"] is None


def test_status_scapy_fehler_bricht_nicht_ab(client, monkeypatch):
    from netscan.net import arp

    def boom():
        raise RuntimeError("kein Npcap")

    monkeypatch.setattr(arp, "scapy_status", boom)
    data = client.get("/api/status").json()
    assert data["scapy"]["available"] is False


def test_adapter_liste_und_virtuelle(client):
    names = [a["name"] for a in client.get("/api/adapters").json()]
    assert names == ["Ethernet", "WLAN"]
    names = [a["name"] for a in client.get("/api/adapters", params={"include_virtual": "true"}).json()]
    assert "vEthernet (WSL)" in names
    first = client.get("/api/adapters").json()[0]
    assert first["network"] == "192.168.178.0/24" and first["prefix"] == 24


def test_guard_endpunkt(client, env):
    r = client.get("/api/guard", params={"adapter": "Ethernet"})
    assert r.status_code == 200 and r.json()["decision"] == "allow"
    assert client.get("/api/guard", params={"adapter": "gibt-es-nicht"}).status_code == 404
    assert client.get("/api/guard").status_code == 422  # adapter ist Pflicht
    env.guard.error = RuntimeError("kaputt")
    assert client.get("/api/guard", params={"adapter": "Ethernet"}).status_code == 500


def test_job_ohne_auftrag(client):
    data = client.get("/api/job").json()
    assert data["state"] == "idle" and data["job_id"] is None


# --- POST /api/scan: Statuscodes -------------------------------------------------------------


def test_scan_202_startet_pipeline(client, env):
    r = client.post("/api/scan", json={"adapter": "Ethernet", "mode": "registered", "port_scan": False})
    assert r.status_code == 202
    body = r.json()
    assert re.fullmatch(r"[0-9a-f]{12}", body["job_id"])
    assert "warning" not in body
    env.wait_job()
    request, services = env.scan_calls[0]
    assert (request.adapter, request.mode, request.port_scan) == ("Ethernet", "registered", False)
    assert services is env.svc
    assert env.svc.settings.load().last_adapter == "Ethernet"
    kinds = [e.type for e in env.svc.bus.history()]
    assert "job.started" in kinds and "job.finished" in kinds
    guard_events = env.events("guard.result")
    assert guard_events and guard_events[-1].data["guard"]["decision"] == "allow"


def test_scan_standardwerte(client, env):
    assert client.post("/api/scan", json=SCAN).status_code == 202
    env.wait_job()
    request, _ = env.scan_calls[0]
    assert (request.mode, request.port_scan, request.confirm_foreign, request.remember_home) == ("full", True, False, False)


def test_scan_404_adapter_fehlt(client, env):
    r = client.post("/api/scan", json={"adapter": "gibt-es-nicht"})
    assert r.status_code == 404
    assert "gibt-es-nicht" in r.json()["detail"]
    assert env.guard.checked == []  # ohne Adapter wird auch der Wächter nicht gefragt
    assert env.scan_calls == []


def test_scan_422_ungueltiger_body(client, env):
    assert client.post("/api/scan", json={}).status_code == 422
    assert client.post("/api/scan", json={"adapter": "Ethernet", "mode": "alles"}).status_code == 422
    assert client.post("/api/scan", json={"adapter": "Ethernet", "confirm_foreign": "true"}).status_code == 422
    assert env.scan_calls == []


def test_scan_422_netz_zu_gross(client, env):
    env.add_adapter(make_adapter("Gross", "10.0.0.5", "10.0.0.0/20"))
    r = client.post("/api/scan", json={"adapter": "Gross"})
    assert r.status_code == 422
    assert "Netz zu groß" in r.json()["detail"]
    assert env.scan_calls == []
    assert env.svc.jobs.status().state == "idle"


def test_scan_warnung_bei_mittlerem_netz(client, env):
    env.add_adapter(make_adapter("Mittel", "10.0.0.5", "10.0.0.0/23"))
    r = client.post("/api/scan", json={"adapter": "Mittel"})
    assert r.status_code == 202
    assert "warning" in r.json() and "/23" in r.json()["warning"]
    env.wait_job()

    env.add_adapter(make_adapter("Grenze", "10.0.0.5", "10.0.0.0/22"))
    r = client.post("/api/scan", json={"adapter": "Grenze"})
    assert r.status_code == 202 and "warning" in r.json()
    env.wait_job()


def test_scan_409_wenn_auftrag_laeuft_und_abbruch(client, env):
    env.hold = True
    assert client.post("/api/scan", json=SCAN).status_code == 202
    assert env.started.wait(5)
    assert client.get("/api/job").json()["state"] == "running"
    r = client.post("/api/scan", json=SCAN)
    assert r.status_code == 409
    assert "Auftrag" in r.json()["detail"]
    assert len(env.scan_calls) == 1

    assert client.post("/api/scan/cancel").json() == {"cancelled": True}
    env.wait_job()
    assert client.post("/api/scan/cancel").json() == {"cancelled": False}
    finished = env.events("job.finished")[-1].data
    assert finished["result"] == "cancelled"


# --- Wächter-Schranke ------------------------------------------------------------------------


def test_scan_423_gesperrt(client, env):
    env.guard.result = BLOCK
    r = client.post("/api/scan", json=SCAN)
    assert r.status_code == 423
    body = r.json()
    assert "Gesperrtes WLAN." in body["detail"]
    assert body["guard"]["decision"] == "block" and body["guard"]["code"] == "blocked_ssid"
    assert env.scan_calls == []
    assert env.svc.jobs.status().state == "idle"
    assert env.events("guard.result")[-1].data["guard"]["decision"] == "block"
    assert env.svc.settings.load().last_adapter is None


@pytest.mark.parametrize("mode", ["full", "registered"])
def test_scan_423_kein_feld_kopfzeile_oder_parameter_umgeht_die_sperre(client, env, mode):
    env.guard.result = BLOCK
    umgehungen = [
        {"adapter": "Ethernet", "mode": mode, "confirm_foreign": True, "remember_home": True, "force": True},
        {"adapter": "Ethernet", "mode": mode, "confirm_foreign": True, "ignore_guard": True, "override": True,
         "decision": "allow", "guard": {"decision": "allow"}},
    ]
    for body in umgehungen:
        r = client.post("/api/scan", json=body)
        assert r.status_code == 423, body
    r = client.post(
        "/api/scan?force=true&confirm=1&confirm_foreign=true&override=1",
        json={"adapter": "Ethernet", "mode": mode, "confirm_foreign": True},
        headers={"X-Force": "1", "X-Confirm-Foreign": "true", "X-Override-Guard": "1", "Authorization": "Bearer admin"},
    )
    assert r.status_code == 423
    assert env.scan_calls == []
    assert env.guard.remembered == []
    assert env.svc.jobs.status().state == "idle"


def test_tiefenscan_423_auch_mit_bestaetigung(client, env):
    (dev,) = add_devices(env.svc, sample_device())
    env.guard.result = BLOCK
    r = client.post(f"/api/devices/{dev.mac}/deep-scan", json={"confirm_foreign": True, "force": True})
    assert r.status_code == 423
    assert r.json()["guard"]["decision"] == "block"
    assert env.deep_calls == []


def test_unbekannte_entscheidung_gilt_als_gesperrt(client, env):
    env.guard.result = replace(ALLOW, decision="vielleicht")
    r = client.post("/api/scan", json={"adapter": "Ethernet", "confirm_foreign": True})
    assert r.status_code == 423
    assert env.scan_calls == []


def test_waechter_fehler_startet_nichts(client, env):
    env.guard.error = RuntimeError("netsh kaputt")
    r = client.post("/api/scan", json={"adapter": "Ethernet", "confirm_foreign": True})
    assert r.status_code == 500
    assert env.scan_calls == []
    assert env.svc.jobs.status().state == "idle"


def test_scan_428_bestaetigung_noetig(client, env):
    env.guard.result = CONFIRM
    r = client.post("/api/scan", json=SCAN)
    assert r.status_code == 428
    body = r.json()
    assert "Fremdes Netz." in body["detail"]
    assert body["guard"]["decision"] == "confirm" and body["guard"]["code"] == "foreign_network"
    assert env.scan_calls == []
    # remember_home allein ersetzt die Bestätigung nicht
    assert client.post("/api/scan", json={"adapter": "Ethernet", "remember_home": True}).status_code == 428
    assert env.guard.remembered == []


def test_scan_mit_bestaetigung_nur_diesmal(client, env):
    env.guard.result = CONFIRM
    r = client.post("/api/scan", json={"adapter": "Ethernet", "confirm_foreign": True})
    assert r.status_code == 202
    env.wait_job()
    assert env.guard.remembered == []  # „nur diesmal“ merkt sich nichts
    assert len(env.scan_calls) == 1
    assert env.scan_calls[0][0].confirm_foreign is True


def test_scan_remember_home_ruft_guard(client, env):
    env.guard.result = CONFIRM
    r = client.post("/api/scan", json={"adapter": "Ethernet", "confirm_foreign": True, "remember_home": True})
    assert r.status_code == 202
    env.wait_job()
    assert env.guard.remembered == ["aa:bb:cc:00:00:99"]


def test_scan_remember_home_ohne_gateway_mac_merkt_nichts(client, env):
    env.guard.result = replace(CONFIRM, code="no_gateway", gateway_mac=None)
    r = client.post("/api/scan", json={"adapter": "Ethernet", "confirm_foreign": True, "remember_home": True})
    assert r.status_code == 202
    env.wait_job()
    assert env.guard.remembered == []


def test_scan_remember_home_abgelehnt_ergibt_423_und_keinen_scan(client, env):
    """Der echte Wächter lehnt den Router eines gesperrten Netzes als Heimnetz ab (ValueError)."""
    env.guard.result = CONFIRM
    env.guard.remember_error = ValueError("Dieser Router gehört zu einem gesperrten Netz.")
    r = client.post("/api/scan", json={"adapter": "Ethernet", "confirm_foreign": True, "remember_home": True})
    assert r.status_code == 423
    assert "gesperrten Netz" in r.json()["detail"] and r.json()["guard"]["decision"] == "confirm"
    assert env.scan_calls == [] and env.svc.jobs.status().state == "idle"


def test_scan_erlaubt_merkt_kein_heimnetz_neu(client, env):
    r = client.post("/api/scan", json={"adapter": "Ethernet", "remember_home": True})
    assert r.status_code == 202
    env.wait_job()
    assert env.guard.remembered == []


# --- Tiefenscan ------------------------------------------------------------------------------


def test_tiefenscan_202(client, env):
    (dev,) = add_devices(env.svc, sample_device(custom_name="Drucker oben"))
    r = client.post(f"/api/devices/{dev.mac}/deep-scan", json={"confirm_foreign": False})
    assert r.status_code == 202
    env.wait_job()
    assert env.deep_calls == [(dev.mac, "Ethernet")]
    started = env.events("job.started")[-1].data
    assert started["kind"] == "deep_scan" and "Drucker oben" in started["label"]
    assert env.events("guard.result")


def test_tiefenscan_ohne_body_gueltig(client, env):
    (dev,) = add_devices(env.svc, sample_device())
    assert client.post(f"/api/devices/{dev.mac}/deep-scan").status_code == 202
    env.wait_job()


def test_tiefenscan_404_unbekanntes_geraet(client, env):
    assert client.post("/api/devices/aa:bb:cc:00:00:77/deep-scan", json={}).status_code == 404
    assert client.post("/api/devices/kaputt/deep-scan", json={}).status_code == 404
    assert env.deep_calls == []


def test_tiefenscan_428_und_bestaetigung(client, env):
    (dev,) = add_devices(env.svc, sample_device())
    env.guard.result = CONFIRM
    r = client.post(f"/api/devices/{dev.mac}/deep-scan", json={})
    assert r.status_code == 428 and r.json()["guard"]["decision"] == "confirm"
    assert env.deep_calls == []
    r = client.post(f"/api/devices/{dev.mac}/deep-scan", json={"confirm_foreign": True})
    assert r.status_code == 202
    env.wait_job()
    assert env.guard.remembered == []  # der Tiefenscan merkt nie ein Heimnetz


def test_tiefenscan_409(client, env):
    (dev,) = add_devices(env.svc, sample_device())
    env.hold = True
    assert client.post(f"/api/devices/{dev.mac}/deep-scan", json={}).status_code == 202
    assert env.started.wait(5)
    assert client.post(f"/api/devices/{dev.mac}/deep-scan", json={}).status_code == 409


def test_tiefenscan_adapter_last_adapter_hat_vorrang_wenn_ip_passt(client, env):
    (dev,) = add_devices(env.svc, sample_device())
    env.svc.settings.update(last_adapter="WLAN")
    assert client.post(f"/api/devices/{dev.mac}/deep-scan", json={}).status_code == 202
    env.wait_job()
    assert env.deep_calls[-1][1] == "WLAN"
    assert env.guard.checked[-1].name == "WLAN"


def test_tiefenscan_adapter_nach_netz_der_geraete_ip(client, env):
    (dev,) = add_devices(env.svc, sample_device(ip="172.20.0.9"))
    assert client.post(f"/api/devices/{dev.mac}/deep-scan", json={}).status_code == 202
    env.wait_job()
    assert env.deep_calls[-1][1] == "vEthernet (WSL)"


def test_tiefenscan_ip_im_netz_eines_anderen_adapters_prueft_dessen_netz(client, env):
    """last_adapter gehört zu einem anderen Netz als die Geräte-IP: der Wächter prüft das Netz der IP."""
    (dev,) = add_devices(env.svc, sample_device(ip="172.20.0.9"))
    env.svc.settings.update(last_adapter="Ethernet")
    assert client.post(f"/api/devices/{dev.mac}/deep-scan", json={}).status_code == 202
    env.wait_job()
    assert env.guard.checked[-1].name == "vEthernet (WSL)"
    assert env.deep_calls[-1][1] == "vEthernet (WSL)"


def test_tiefenscan_ip_in_keinem_netz_nimmt_last_adapter(client, env):
    (dev,) = add_devices(env.svc, sample_device(ip="10.77.0.9"))
    env.svc.settings.update(last_adapter="Ethernet")
    assert client.post(f"/api/devices/{dev.mac}/deep-scan", json={}).status_code == 202
    env.wait_job()
    assert env.deep_calls[-1][1] == "Ethernet"


def test_tiefenscan_404_ohne_passenden_adapter(client, env):
    (dev,) = add_devices(env.svc, sample_device(ip="10.77.0.9"))
    r = client.post(f"/api/devices/{dev.mac}/deep-scan", json={})
    assert r.status_code == 404
    assert env.deep_calls == []


# --- Geräte ----------------------------------------------------------------------------------


def test_geraeteliste_und_einzelabruf(client, env):
    a, b = add_devices(
        env.svc,
        sample_device("aa:bb:cc:dd:ee:02", "192.168.178.60", ports=[sample_port(22), sample_port(23, "telnet", "critical", "unverschlüsselt")]),
        sample_device("aa:bb:cc:dd:ee:01", "192.168.178.50", is_gateway=True),
    )
    data = client.get("/api/devices").json()
    assert [d["mac"] for d in data] == [b.mac, a.mac]  # Router zuerst
    one = client.get(f"/api/devices/{a.mac}").json()
    assert one["max_risk"] == "critical" and len(one["ports"]) == 2
    assert one["display_name"] == "Testhersteller"
    # MAC in anderer Schreibweise
    assert client.get("/api/devices/AA-BB-CC-DD-EE-02").json()["mac"] == a.mac


def test_geraet_404(client):
    assert client.get("/api/devices/aa:bb:cc:00:00:77").status_code == 404
    assert client.get("/api/devices/unsinn").status_code == 404


def test_inventar_scans_und_protokoll(client, env):
    add_devices(env.svc, sample_device(custom_name="Mein Gerät"))
    inv = client.get("/api/inventory").json()
    assert inv == [{"mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.178.50", "name": "Mein Gerät"}]

    scans = client.get("/api/scans").json()
    assert len(scans) == 1 and scans[0]["result"] == "completed"
    assert client.get("/api/scans", params={"limit": 0}).status_code == 422

    scan_id = scans[0]["id"]
    env.svc.inventory.add_log(scan_id, "info", "Erster Eintrag")
    env.svc.inventory.add_log(scan_id, "warning", "Zweiter Eintrag")
    env.svc.inventory.add_log(None, "info", "Ohne Scan")
    log = client.get("/api/log", params={"scan_id": scan_id}).json()
    assert [e["message"] for e in log] == ["Erster Eintrag", "Zweiter Eintrag"]
    assert len(client.get("/api/log").json()) == 3
    assert len(client.get("/api/log", params={"limit": 1}).json()) == 1
    assert client.get("/api/log", params={"limit": 0}).status_code == 422


# --- PATCH -----------------------------------------------------------------------------------


def test_patch_aendert_felder_und_meldet_ereignisse(client, env):
    (dev,) = add_devices(env.svc, sample_device())
    r = client.patch(
        f"/api/devices/{dev.mac}",
        json={"custom_name": "  Küchen-Drucker ", "category": "printer", "note": "neben dem Herd", "known": True, "port_scan_excluded": True},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["custom_name"] == "Küchen-Drucker"
    assert data["category"] == "printer" and data["category_source"] == "user"
    assert data["known"] is True and data["port_scan_excluded"] is True
    assert data["note"] == "neben dem Herd"
    stored = env.svc.inventory.get(dev.mac)
    assert stored.custom_name == "Küchen-Drucker"

    updated = env.events("device.updated")
    assert updated and updated[-1].data["device"]["mac"] == dev.mac
    assert updated[-1].data["device"]["custom_name"] == "Küchen-Drucker"
    assert env.events("devices.changed")


def test_patch_nur_gesendete_felder_und_zuruecksetzen(client, env):
    (dev,) = add_devices(env.svc, sample_device())
    client.patch(f"/api/devices/{dev.mac}", json={"custom_name": "Name", "category": "iot", "note": "N"})
    r = client.patch(f"/api/devices/{dev.mac}", json={"known": True})
    assert r.json()["custom_name"] == "Name" and r.json()["note"] == "N" and r.json()["known"] is True
    r = client.patch(f"/api/devices/{dev.mac}", json={"category": "auto", "custom_name": None})
    assert r.json()["category_source"] == "auto"
    assert r.json()["custom_name"] is None


def test_patch_fehlerfaelle(client, env):
    (dev,) = add_devices(env.svc, sample_device())
    url = f"/api/devices/{dev.mac}"
    r = client.patch(url, json={"category": "kühlschrank"})
    assert r.status_code == 400 and "Kategorie" in r.json()["detail"]
    r = client.patch(url, json={"ip": "1.2.3.4"})  # nicht änderbar ⇒ KeyError im Inventar
    assert r.status_code == 400 and "ip" in r.json()["detail"]
    assert client.patch(url, json={"known": None}).status_code == 400
    assert client.patch("/api/devices/aa:bb:cc:00:00:77", json={"note": "x"}).status_code == 404
    assert client.patch("/api/devices/unsinn", json={"note": "x"}).status_code == 400
    assert client.patch(url, json={"known": "ja"}).status_code == 422
    assert client.patch(url, json={"custom_name": 5}).status_code == 422
    assert client.patch(url, content=b"{kaputt", headers={"content-type": "application/json"}).status_code == 422
    # nach allen Fehlern blieb das Gerät unverändert und es gab keine Änderungsereignisse
    assert env.svc.inventory.get(dev.mac).category == "unknown"
    assert env.events("device.updated") == []


# --- Einstellungen ---------------------------------------------------------------------------


def test_settings_lesen(client):
    data = client.get("/api/settings").json()
    assert data["rate_pps"] == 200
    assert data["permanent_blocked_ssids"] == ["DE22LA000256314 8159"]
    assert "blocked_gateway_macs" in data


def test_settings_schreiben(client, env):
    r = client.put(
        "/api/settings",
        json={
            "rate_pps": 150,
            "ping_timeout_ms": 500,
            "ping_workers": 16,
            "port_timeout_ms": 600,
            "port_workers": 32,
            "names_timeout_s": 1.5,
            "mdns_timeout_s": 4,
            "ssdp_timeout_s": 2.5,
            "blocked_ssids_extra": ["  Schule-Gast ", "Büro", "Büro"],
            "home_gateway_macs": ["3C-A6-2F-00-00-01", "3ca6.2f00.0001"],
            "port_scan_excluded_categories": ["printer", "iot", "printer"],
        },
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["rate_pps"] == 150 and data["port_workers"] == 32
    assert data["mdns_timeout_s"] == 4.0 and isinstance(data["mdns_timeout_s"], float)
    assert data["blocked_ssids_extra"] == ["Schule-Gast", "Büro"]
    assert data["home_gateway_macs"] == ["3c:a6:2f:00:00:01"]
    assert data["port_scan_excluded_categories"] == ["printer", "iot"]
    stored = env.svc.settings.load()
    assert stored.rate_pps == 150 and stored.blocked_ssids_extra == ["Schule-Gast", "Büro"]
    assert client.get("/api/settings").json() == data


def test_settings_leerer_body_aendert_nichts(client):
    before = client.get("/api/settings").json()
    r = client.put("/api/settings", json={})
    assert r.status_code == 200 and r.json() == before


@pytest.mark.parametrize(
    "body, stichwort",
    [
        ({"blocked_gateway_macs": []}, "nur lesbar"),
        ({"blocked_gateway_macs": ["aa:bb:cc:dd:ee:ff"]}, "nur lesbar"),
        ({"permanent_blocked_ssids": []}, "nur lesbar"),
        ({"last_adapter": "Ethernet"}, "nur lesbar"),
        ({"arp_retries": 1}, "nur lesbar"),
        ({"gibt_es_nicht": 1}, "unbekannt"),
        ({"rate_pps": 5}, "rate_pps"),
        ({"rate_pps": 5000}, "rate_pps"),
        ({"rate_pps": "viel"}, "rate_pps"),
        ({"rate_pps": True}, "rate_pps"),
        ({"rate_pps": 100.5}, "rate_pps"),
        ({"ping_timeout_ms": 50}, "ping_timeout_ms"),
        ({"names_timeout_s": 5}, "names_timeout_s"),
        ({"mdns_timeout_s": 0.1}, "mdns_timeout_s"),
        ({"ssdp_timeout_s": None}, "ssdp_timeout_s"),
        ({"blocked_ssids_extra": "Büro"}, "Liste"),
        ({"blocked_ssids_extra": [""]}, "leer"),
        ({"blocked_ssids_extra": ["   "]}, "leer"),
        ({"blocked_ssids_extra": [5]}, "Text"),
        ({"blocked_ssids_extra": ["x" * 65]}, "64"),
        ({"blocked_ssids_extra": [f"WLAN {i}" for i in range(51)]}, "50"),
        ({"home_gateway_macs": ["kein-mac"]}, "MAC"),
        ({"home_gateway_macs": [5]}, "MAC"),
        ({"port_scan_excluded_categories": ["kühlschrank"]}, "Geräteart"),
        ({"port_scan_excluded_categories": "printer"}, "Liste"),
    ],
)
def test_settings_ablehnung(client, env, body, stichwort):
    before = client.get("/api/settings").json()
    r = client.put("/api/settings", json=body)
    assert r.status_code == 400, r.text
    assert stichwort in r.json()["detail"]
    assert client.get("/api/settings").json() == before


def test_settings_grenzwerte_sind_erlaubt(client):
    r = client.put("/api/settings", json={"rate_pps": 10, "ping_workers": 128, "blocked_ssids_extra": ["x" * 64] * 1})
    assert r.status_code == 200
    r = client.put("/api/settings", json={"blocked_ssids_extra": [f"WLAN {i}" for i in range(50)]})
    assert r.status_code == 200 and len(r.json()["blocked_ssids_extra"]) == 50


def test_settings_alles_oder_nichts(client):
    before = client.get("/api/settings").json()
    r = client.put("/api/settings", json={"rate_pps": 300, "ping_workers": 9999})
    assert r.status_code == 400
    assert client.get("/api/settings").json() == before
    r = client.put("/api/settings", json={"rate_pps": 300, "blocked_gateway_macs": []})
    assert r.status_code == 400
    assert client.get("/api/settings").json()["rate_pps"] == before["rate_pps"]


@pytest.mark.parametrize("zahl", ["NaN", "Infinity", "-Infinity"])
def test_settings_nan_und_unendlich_werden_abgelehnt(client, zahl):
    for key in ("rate_pps", "names_timeout_s"):
        r = client.put("/api/settings", content=f'{{"{key}": {zahl}}}'.encode(), headers={"content-type": "application/json"})
        assert r.status_code == 400, (key, zahl, r.text)
    assert client.get("/api/settings").json()["rate_pps"] == 200


def test_settings_kein_objekt(client):
    assert client.put("/api/settings", json=[1, 2]).status_code == 422


def test_gesperrte_ssids_bleiben_bei_put_erhalten(client):
    client.put("/api/settings", json={"blocked_ssids_extra": ["Zusatz"]})
    data = client.get("/api/settings").json()
    assert data["permanent_blocked_ssids"] == ["DE22LA000256314 8159"]
    client.put("/api/settings", json={"blocked_ssids_extra": []})
    assert client.get("/api/settings").json()["permanent_blocked_ssids"] == ["DE22LA000256314 8159"]


# --- Herstellerliste -------------------------------------------------------------------------


def test_oui_update(client, env):
    r = client.post("/api/oui/update")
    assert r.status_code == 202
    assert re.fullmatch(r"[0-9a-f]{12}", r.json()["job_id"])
    env.wait_job()
    assert env.oui_calls == [env.svc.data_dir]
    updated = env.events("oui.updated")
    assert len(updated) == 1
    assert updated[0].data == {"entries": 8, "source": "Testliste"}
    started = env.events("job.started")[-1].data
    assert started["kind"] == "oui_update" and started["label"] == "Herstellerliste aktualisieren"
    assert env.events("job.finished")[-1].data["result"] == "completed"
    assert env.svc.oui.source == "Testliste"  # neu geladen


def test_oui_update_409_wenn_belegt(client, env):
    env.hold = True
    assert client.post("/api/oui/update").status_code == 202
    assert env.started.wait(5)
    assert client.post("/api/oui/update").status_code == 409
    assert client.post("/api/scan", json=SCAN).status_code == 409
    env.release.set()
    env.wait_job()


def test_oui_update_fehler_wird_gemeldet(client, env, monkeypatch):
    from netscan.net import oui

    def boom(data_dir, fetch=None):
        raise OSError("keine Verbindung")

    monkeypatch.setattr(oui, "update_from_ieee", boom)
    assert client.post("/api/oui/update").status_code == 202
    env.wait_job()
    finished = env.events("job.finished")[-1].data
    assert finished["result"] == "failed" and "keine Verbindung" in finished["error"]
    assert env.events("oui.updated") == []


# --- Export ----------------------------------------------------------------------------------


@pytest.fixture
def bestand(env):
    return add_devices(
        env.svc,
        sample_device(
            "aa:bb:cc:dd:ee:01",
            "192.168.178.50",
            custom_name="Drucker <Büro> & \"Co\"",
            category="printer",
            ports=[sample_port(80, "http", "medium", "Unverschlüsselt"), sample_port(23, "telnet", "critical", "Klartext")],
            note="Notiz mit ; Semikolon",
        ),
        sample_device("aa:bb:cc:dd:ee:02", "192.168.178.60", vendor="Zweiter", names=NameInfo(dns="nas.fritz.box"), category="server"),
        sample_device("aa:bb:cc:dd:ee:03", "192.168.178.70", is_gateway=True, mac_random=True, vendor=None),
    )


FILENAME = r'attachment; filename="netzwerkscanner-geraete-\d{8}-\d{4}\.%s"'


def test_export_json(client, bestand):
    r = client.get("/api/export/json")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/json"
    assert re.fullmatch(FILENAME % "json", r.headers["content-disposition"])
    data = json.loads(r.content.decode("utf-8"))
    assert data["meta"]["device_count"] == 3
    assert data["meta"]["exported_at"] and data["meta"]["last_scan"]["result"] == "completed"
    assert {d["mac"] for d in data["devices"]} == {d.mac for d in bestand}
    first = next(d for d in data["devices"] if d["mac"] == "aa:bb:cc:dd:ee:01")
    assert [p["port"] for p in first["ports"]] == [23, 80]


def test_export_csv(client, bestand):
    r = client.get("/api/export/csv")
    assert r.status_code == 200
    assert r.headers["content-type"] == "text/csv; charset=utf-8"
    assert re.fullmatch(FILENAME % "csv", r.headers["content-disposition"])
    assert r.content.startswith(b"\xef\xbb\xbf")  # BOM für Excel
    text = r.content.decode("utf-8-sig")
    lines = text.strip().split("\r\n")
    assert lines[0].startswith("Name;IP;MAC;Private MAC;Hersteller;Kategorie;")
    assert len(lines) == 1 + 3
    for d in bestand:
        assert d.mac in text and d.ip in text


def test_export_html(client, bestand):
    r = client.get("/api/export/html")
    assert r.status_code == 200
    assert r.headers["content-type"] == "text/html; charset=utf-8"
    assert re.fullmatch(FILENAME % "html", r.headers["content-disposition"])
    html = r.content.decode("utf-8")
    assert "<script" not in html.lower()
    assert "Netzwerkscanner – Gerätebericht" in html
    assert "Drucker &lt;Büro&gt; &amp; &quot;Co&quot;" in html
    assert "Drucker <Büro>" not in html
    for d in bestand:
        assert d.mac in html


def test_export_unbekanntes_format(client, bestand):
    assert client.get("/api/export/pdf").status_code == 404
    assert client.get("/api/export/").status_code in (404, 405)


def test_export_leeres_inventar(client):
    assert json.loads(client.get("/api/export/json").content)["devices"] == []
    assert client.get("/api/export/csv").content.decode("utf-8-sig").strip().count("\n") == 0
    assert "Keine Geräte" in client.get("/api/export/html").content.decode("utf-8")


def test_export_schreibt_keine_datei(client, env, bestand, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    before_data = sorted(p.name for p in env.svc.data_dir.iterdir())
    before_cwd = sorted(os.listdir(tmp_path))
    for fmt in ("json", "csv", "html"):
        assert client.get(f"/api/export/{fmt}").status_code == 200
    assert sorted(p.name for p in env.svc.data_dir.iterdir()) == before_data
    assert sorted(os.listdir(tmp_path)) == before_cwd


def test_geraet_dataclass_roundtrip_im_export(client, bestand):
    data = json.loads(client.get("/api/export/json").content)
    for entry, original in zip(sorted(data["devices"], key=lambda d: d["mac"]), sorted(bestand, key=lambda d: d.mac)):
        assert Device.from_dict(entry).to_dict() == original.to_dict()
