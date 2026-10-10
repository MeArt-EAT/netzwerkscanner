"""Standardregel seit 10.10.2026 (Entscheidung des Nutzers): Der Scanner ist frei nutzbar – außer in der Schule.

- Nicht gesperrte Netze ⇒ allow ohne Rückfrage (kein Heimnetz nötig).
- Schul-Hotspot (Name über netsh oder Windows-Netzwerkprofil, gelernte Router-MAC, weitere gesperrte Namen) ⇒ block,
  ohne jede Möglichkeit zum Übergehen.
- Nur wenn sich die Sperre nicht sicher prüfen lässt ⇒ confirm („Nur diesmal scannen“).
Die strenge Regel des Pflichtenhefts (Heimnetz/Bestätigung) prüfen test_guard_rules.py & Co. mit
ask_before_foreign_scan=True.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from netscan.config import SettingsStore
from netscan.core.db import Database
from netscan.core.guard import NetworkGuard
from netscan.core.models import Adapter
from tests.fakes import HOME_GW_IP, HOME_GW_MAC, HOTSPOT_SSID, FakePlatform, make_adapter

FOREIGN_GW_IP, FOREIGN_GW_MAC = "192.168.1.1", "00:11:22:33:44:01"


@pytest.fixture
def store(tmp_path: Path):  # type: ignore[no-untyped-def]
    db = Database(tmp_path / "guard.sqlite3")
    yield SettingsStore(db)
    db.close()


@pytest.fixture
def fake() -> FakePlatform:
    return FakePlatform()


@pytest.fixture
def guard(fake: FakePlatform, store: SettingsStore) -> NetworkGuard:
    return NetworkGuard(fake, store)


def wlan() -> Adapter:
    return make_adapter("WLAN", ipv4="192.168.178.21", wireless=True, mac="a4:c3:61:00:00:21")


def test_default_setting_is_free_use(store: SettingsStore) -> None:
    assert store.load().ask_before_foreign_scan is False


def test_foreign_network_is_allowed_without_question(guard: NetworkGuard, fake: FakePlatform) -> None:
    fake.connect_wifi("Café am Markt")
    fake.set_gateway(FOREIGN_GW_IP, FOREIGN_GW_MAC)
    g = guard.check(wlan())
    assert g.decision == "allow" and g.code == "ok_network"
    assert "Netz frei" in g.reason and g.gateway_mac == FOREIGN_GW_MAC


def test_home_network_still_reported_as_home(guard: NetworkGuard) -> None:
    guard.remember_home(HOME_GW_MAC)
    assert guard.check(make_adapter()).code == "ok_home"


def test_network_without_router_is_allowed(guard: NetworkGuard, fake: FakePlatform) -> None:
    fake.set_gateway(None, None)
    fake.connect_wifi("Labor")
    assert guard.check(make_adapter()).decision == "allow"


@pytest.mark.parametrize("name", [HOTSPOT_SSID, "Schule-Extra"])
def test_school_names_still_block(guard: NetworkGuard, fake: FakePlatform, store: SettingsStore, name: str) -> None:
    store.update(blocked_ssids_extra=["Schule-Extra"])
    fake.connect_wifi(name)
    for adapter in (wlan(), make_adapter()):  # auch ein Kabel-Scan ist gesperrt
        g = guard.check(adapter)
        assert g.decision == "block" and g.code == "blocked_ssid"
        assert not g.home_allowed


def test_similar_name_is_free(guard: NetworkGuard, fake: FakePlatform) -> None:
    fake.connect_wifi("DE22LA000256314 8158")
    fake.set_gateway(FOREIGN_GW_IP, FOREIGN_GW_MAC)
    assert guard.check(wlan()).decision == "allow"


def test_hotspot_profile_name_blocks_without_location_permission(guard: NetworkGuard, fake: FakePlatform, store: SettingsStore) -> None:
    fake.set_gateway("192.168.178.254", "da:a1:19:00:43:01", adapter="WLAN")  # im Teilnetz des WLAN-Adapters
    fake.wifi_unreadable(profiles={"WLAN": HOTSPOT_SSID})
    g = guard.check(wlan())
    assert g.decision == "block" and g.code == "blocked_ssid"
    assert "da:a1:19:00:43:01" in store.load().blocked_gateway_macs  # Router gelernt


def test_learned_hotspot_router_blocks_when_nothing_is_readable(guard: NetworkGuard, fake: FakePlatform) -> None:
    fake.set_gateway("192.168.178.254", "da:a1:19:00:43:01", adapter="WLAN")  # im Teilnetz des WLAN-Adapters
    fake.wifi_unreadable(profiles={"WLAN": HOTSPOT_SSID})
    assert guard.check(wlan()).decision == "block"
    fake.wifi_unreadable()  # jetzt nennt Windows gar nichts mehr
    g = guard.check(wlan())
    assert g.decision == "block" and g.code == "blocked_gateway"


def test_profile_name_of_other_network_is_free(guard: NetworkGuard, fake: FakePlatform) -> None:
    fake.wifi_unreadable(profiles={"WLAN": "Welt"})
    g = guard.check(wlan())
    assert g.decision == "allow" and g.profile_name == "Welt"


def test_unidentifiable_wifi_asks(guard: NetworkGuard, fake: FakePlatform) -> None:
    """Weder WLAN-Name noch Profil: Es könnte der (noch nicht gelernte) Hotspot sein ⇒ nachfragen."""
    fake.wifi_unreadable()
    g = guard.check(wlan())
    assert g.decision == "confirm" and g.code == "unknown_network"
    assert "Schule" in g.reason
    # auch ein Kabel-Scan, solange ein WLAN mit Router unbekannt ist
    assert guard.check(make_adapter()).decision == "confirm"


def test_platform_failure_never_allows(fake: FakePlatform, store: SettingsStore) -> None:
    class Broken(FakePlatform):
        def wifi_status(self):  # type: ignore[no-untyped-def]
            raise OSError("netsh fehlt")

    g = NetworkGuard(Broken(), store).check(make_adapter())
    assert g.decision == "confirm"


def test_strict_mode_can_be_switched_back_on(guard: NetworkGuard, fake: FakePlatform, store: SettingsStore) -> None:
    store.update(ask_before_foreign_scan=True)
    fake.set_gateway(FOREIGN_GW_IP, FOREIGN_GW_MAC)
    assert guard.check(make_adapter()).decision == "confirm"


# --- API --------------------------------------------------------------------------------


@pytest.fixture
def api(services, monkeypatch):  # type: ignore[no-untyped-def]
    from netscan.scan import pipeline
    from netscan.web import server

    started: list[str] = []
    monkeypatch.setattr(pipeline, "run_scan", lambda ctx, req, svc: started.append(req.adapter) or {"devices": 0})
    with TestClient(server.create_app(services), base_url="http://127.0.0.1:8765") as client:
        client.started = started  # type: ignore[attr-defined]
        yield client
    services.jobs.wait(5)


def test_api_scans_foreign_network_without_confirmation(api, services, fake_platform) -> None:  # type: ignore[no-untyped-def]
    fake_platform.set_gateway(FOREIGN_GW_IP, FOREIGN_GW_MAC)
    r = api.post("/api/scan", json={"adapter": "Ethernet"})
    assert r.status_code == 202, r.text
    services.jobs.wait(5)
    assert api.started == ["Ethernet"]


def test_api_hotspot_still_423_with_every_flag(api, services, fake_platform) -> None:  # type: ignore[no-untyped-def]
    fake_platform.connect_wifi(HOTSPOT_SSID)
    r = api.post("/api/scan", json={"adapter": "Ethernet", "confirm_foreign": True, "remember_home": True, "force": True})
    assert r.status_code == 423
    assert api.started == []


def test_api_setting_is_editable_and_typed(api) -> None:  # type: ignore[no-untyped-def]
    assert api.get("/api/settings").json()["ask_before_foreign_scan"] is False
    assert api.put("/api/settings", json={"ask_before_foreign_scan": "ja"}).status_code == 400
    r = api.put("/api/settings", json={"ask_before_foreign_scan": True})
    assert r.status_code == 200 and r.json()["ask_before_foreign_scan"] is True


def test_home_constants_unchanged() -> None:
    assert HOME_GW_IP == "192.168.178.1"
