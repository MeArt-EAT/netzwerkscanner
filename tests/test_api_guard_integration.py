"""Server + echter NetworkGuard + echte Adapterliste auf der FakePlatform (nur die Pipeline ist Attrappe).

Prüft das Zusammenspiel: Sperre des Schul-Hotspots, Heimnetz merken, Einstellungen als Umgehungsversuch.
Kein Paket geht ins Netz: Platform und Pipeline sind Attrappen.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from netscan.net import arp, oui
from netscan.platform.base import InterfaceAddr
from netscan.scan import pipeline
from netscan.web import server
from tests.fakes import HOME_GW_MAC, HOTSPOT_SSID, FakeOui
from tests.test_api_support import BASE, add_devices, sample_device

HOTSPOT_GW_IP = "192.168.43.1"
HOTSPOT_GW_MAC = "02:11:22:33:44:55"


def join_hotspot(platform, ssid: str = HOTSPOT_SSID) -> None:
    """Der PC hängt per WLAN im Hotspot-Netz 192.168.43.0/24; sein Router ist der Hotspot."""
    platform.ifaces = [
        InterfaceAddr("WLAN", "192.168.43.20", "255.255.255.0", "a4:c3:61:00:00:21", True) if i.name == "WLAN" else i
        for i in platform.ifaces
    ]
    platform.connect_wifi(ssid)
    platform.set_gateway(HOTSPOT_GW_IP, HOTSPOT_GW_MAC, adapter="WLAN")


class Calls:
    def __init__(self) -> None:
        self.scans: list[str] = []
        self.deep: list[str] = []


@pytest.fixture
def calls(monkeypatch):
    c = Calls()

    def run_scan(ctx, request, services):
        c.scans.append(request.adapter)
        return {"devices": 0}

    def run_deep_scan(ctx, mac, services, adapter_name=None):
        c.deep.append(mac)
        return {"mac": mac}

    monkeypatch.setattr(pipeline, "run_scan", run_scan)
    monkeypatch.setattr(pipeline, "run_deep_scan", run_deep_scan)
    monkeypatch.setattr(arp, "scapy_status", lambda: (True, "Test"))
    monkeypatch.setattr(oui.OuiDb, "load", classmethod(lambda cls, data_dir=None: FakeOui()))
    return c


@pytest.fixture
def api(services, calls):
    """TestClient mit den echten Bausteinen aus services (Guard, Adapterliste) auf der FakePlatform."""
    with TestClient(server.create_app(services), base_url=BASE) as client:
        yield client
    services.jobs.wait(5)


def scan(api, services, adapter="Ethernet", **extra):
    r = api.post("/api/scan", json={"adapter": adapter, **extra})
    if r.status_code == 202:
        assert services.jobs.wait(5)
    return r


def test_adapterliste_blendet_virtuelle_aus(api):
    names = [a["name"] for a in api.get("/api/adapters").json()]
    assert names == ["Ethernet", "WLAN"]
    names = [a["name"] for a in api.get("/api/adapters", params={"include_virtual": "true"}).json()]
    assert "vEthernet (WSL)" in names and "Loopback Pseudo-Interface 1" not in names


def test_unbekannter_adapter_404(api):
    assert api.post("/api/scan", json={"adapter": "gibt-es-nicht"}).status_code == 404


def test_heimnetz_erst_bestaetigen_dann_merken_dann_frei(api, services, calls):
    r = scan(api, services)
    assert r.status_code == 428
    assert r.json()["guard"]["code"] == "foreign_network" and r.json()["guard"]["gateway_mac"] == HOME_GW_MAC
    assert calls.scans == []

    # nur diesmal: scannt, merkt aber nichts
    assert scan(api, services, confirm_foreign=True).status_code == 202
    assert services.settings.load().home_gateway_macs == []
    assert scan(api, services).status_code == 428

    # „Das ist mein Heimnetz“
    assert scan(api, services, confirm_foreign=True, remember_home=True).status_code == 202
    assert services.settings.load().home_gateway_macs == [HOME_GW_MAC]
    assert scan(api, services).status_code == 202  # ab jetzt ohne Nachfrage
    assert api.get("/api/guard", params={"adapter": "Ethernet"}).json()["code"] == "ok_home"
    assert calls.scans == ["Ethernet", "Ethernet", "Ethernet"]


@pytest.mark.parametrize("mode", ["full", "registered"])
def test_hotspot_sperrt_jeden_scan_auch_mit_allen_umgehungsversuchen(api, services, fake_platform, calls, mode):
    join_hotspot(fake_platform)
    body = {"adapter": "WLAN", "mode": mode, "confirm_foreign": True, "remember_home": True, "force": True}
    r = api.post("/api/scan", json=body, headers={"X-Force": "1"})
    assert r.status_code == 423
    guard = r.json()["guard"]
    assert guard["decision"] == "block" and guard["code"] == "blocked_ssid" and guard["ssid"] == HOTSPOT_SSID
    assert calls.scans == []
    assert services.settings.load().home_gateway_macs == []
    # das Gateway des Hotspots wurde gemerkt (Wächter-Regel 2)
    assert services.settings.load().blocked_gateway_macs == [HOTSPOT_GW_MAC]
    # auch über den Ethernet-Adapter: irgendein verbundenes WLAN mit gesperrtem Namen sperrt
    assert api.post("/api/scan", json={**body, "adapter": "Ethernet"}).status_code == 423


def test_hotspot_sperrt_den_tiefenscan(api, services, fake_platform, calls):
    (dev,) = add_devices(services, sample_device())
    fake_platform.connect_wifi(HOTSPOT_SSID)
    r = api.post(f"/api/devices/{dev.mac}/deep-scan", json={"confirm_foreign": True})
    assert r.status_code == 423
    assert calls.deep == []


def test_gemerktes_hotspot_gateway_sperrt_auch_bei_unlesbarem_namen(api, services, fake_platform, calls):
    join_hotspot(fake_platform)
    assert api.post("/api/scan", json={"adapter": "WLAN"}).status_code == 423  # lernt die Gateway-MAC

    fake_platform.wifi_unreadable()
    r = api.post("/api/scan", json={"adapter": "WLAN", "confirm_foreign": True, "remember_home": True})
    assert r.status_code == 423
    assert r.json()["guard"]["code"] == "blocked_gateway"
    assert calls.scans == []
    assert services.settings.load().home_gateway_macs == []


def test_aehnlicher_name_ist_nicht_gesperrt(api, services, fake_platform):
    for ssid in (HOTSPOT_SSID.lower(), HOTSPOT_SSID + " ", HOTSPOT_SSID.replace(" ", "")):
        fake_platform.connect_wifi(ssid)
        r = api.post("/api/scan", json={"adapter": "WLAN"})
        assert r.status_code == 428, ssid  # fremdes Netz: Bestätigung, aber keine Sperre


def test_nicht_lesbarer_name_im_fremden_netz_fragt_nach(api, services, fake_platform, calls):
    fake_platform.wifi_unreadable()
    r = api.post("/api/scan", json={"adapter": "WLAN"})
    assert r.status_code == 428
    assert r.json()["guard"]["ssid_readable"] is False
    assert api.post("/api/scan", json={"adapter": "WLAN", "confirm_foreign": True}).status_code == 202
    services.jobs.wait(5)
    assert calls.scans == ["WLAN"]


def test_zusaetzlich_gesperrter_name_ueber_die_einstellungen(api, services, fake_platform, calls):
    fake_platform.connect_wifi("Schule-Gast")
    assert api.post("/api/scan", json={"adapter": "WLAN"}).status_code == 428
    assert api.put("/api/settings", json={"blocked_ssids_extra": ["Schule-Gast"]}).status_code == 200
    r = api.post("/api/scan", json={"adapter": "WLAN", "confirm_foreign": True})
    assert r.status_code == 423 and r.json()["guard"]["code"] == "blocked_ssid"
    # wieder entfernen geht, der feste Hotspot-Name bleibt aber gesperrt
    assert api.put("/api/settings", json={"blocked_ssids_extra": []}).status_code == 200
    fake_platform.connect_wifi(HOTSPOT_SSID)
    assert api.post("/api/scan", json={"adapter": "WLAN", "confirm_foreign": True}).status_code == 423


def test_einstellungen_koennen_die_sperre_nicht_aufheben(api, services, fake_platform, calls):
    join_hotspot(fake_platform)
    assert api.post("/api/scan", json={"adapter": "WLAN"}).status_code == 423
    for body in (
        {"blocked_gateway_macs": []},
        {"permanent_blocked_ssids": []},
        {"blocked_ssids_extra": [], "permanent_blocked_ssids": []},
        {"home_gateway_macs": [HOTSPOT_GW_MAC], "blocked_gateway_macs": []},
    ):
        assert api.put("/api/settings", json=body).status_code == 400
    assert services.settings.load().blocked_gateway_macs == [HOTSPOT_GW_MAC]
    # Hotspot-Router als „Heimnetz“ eintragen geht nicht (BAUPLAN §10: gesperrte MAC nie Heimnetz) …
    r = api.put("/api/settings", json={"home_gateway_macs": [HOTSPOT_GW_MAC]})
    assert r.status_code == 400 and "gesperrt" in r.json()["detail"]
    assert HOTSPOT_GW_MAC not in services.settings.load().home_gateway_macs
    # … und selbst ein so eingetragener Router hebt die Sperre nicht auf (Namens-Sperre kommt zuerst)
    services.settings.update(home_gateway_macs=[HOTSPOT_GW_MAC])
    assert api.post("/api/scan", json={"adapter": "WLAN", "confirm_foreign": True}).status_code == 423
    fake_platform.wifi_unreadable()
    assert api.post("/api/scan", json={"adapter": "WLAN", "confirm_foreign": True}).status_code == 423
    assert calls.scans == []


def test_status_zeigt_den_waechter_fuer_den_gewaehlten_adapter(api, fake_platform):
    fake_platform.connect_wifi(HOTSPOT_SSID)
    data = api.get("/api/status", params={"adapter": "WLAN"}).json()
    assert data["guard"]["decision"] == "block"
    assert data["admin"] is True and data["platform"] == "fake"
    assert api.get("/api/status").json()["guard"] is None  # noch kein last_adapter


def test_status_nutzt_last_adapter_nach_einem_scan(api, services, fake_platform):
    assert scan(api, services, confirm_foreign=True).status_code == 202
    assert api.get("/api/status").json()["guard"]["code"] == "foreign_network"


def test_tiefenscan_adapter_aus_dem_netz_der_geraete_ip(api, services, calls):
    (dev,) = add_devices(services, sample_device(ip="192.168.178.77"))
    assert api.post(f"/api/devices/{dev.mac}/deep-scan", json={}).status_code == 428
    r = api.post(f"/api/devices/{dev.mac}/deep-scan", json={"confirm_foreign": True})
    assert r.status_code == 202
    services.jobs.wait(5)
    assert calls.deep == [dev.mac]
    # Gerät in einem Netz, das kein Adapter hat und ohne last_adapter ⇒ kein passender Adapter
    (fremd,) = add_devices(services, sample_device("aa:bb:cc:dd:ee:09", "10.50.0.9"))
    services.settings.update(last_adapter=None)
    assert api.post(f"/api/devices/{fremd.mac}/deep-scan", json={"confirm_foreign": True}).status_code == 404
