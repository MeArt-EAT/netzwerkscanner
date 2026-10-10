"""Regressionstests zu Prüfbefunden an der Web-API: S1 (Heimnetz über WLAN ohne lesbaren Namen), S6 (PUT
home_gateway_macs), F3 (Tiefenscan für offline-Geräte), F4 (Kategorie „Automatisch“), F8 (Gerät außerhalb jedes
Adapter-Netzes), F2 (Herstellerliste abbrechen). TestClient und Attrappen – kein Paket ins Netz."""

from __future__ import annotations

import gzip
import io
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from netscan.core.context import ScanCancelled
from netscan.net import arp, oui
from netscan.scan import pipeline
from netscan.web import server
from tests.fakes import HOME_GW_MAC, FakeOui
from tests.test_api_support import BASE, add_devices, sample_device, sample_port


class Calls:
    def __init__(self) -> None:
        self.scans: list[str] = []
        self.deep: list[str] = []


@pytest.fixture
def calls(monkeypatch: pytest.MonkeyPatch) -> Calls:
    c = Calls()

    def run_scan(ctx, request, services):  # type: ignore[no-untyped-def]
        c.scans.append(request.adapter)
        return {"devices": 0}

    def run_deep_scan(ctx, mac, services, adapter_name=None):  # type: ignore[no-untyped-def]
        c.deep.append(mac)
        return {"mac": mac}

    monkeypatch.setattr(pipeline, "run_scan", run_scan)
    monkeypatch.setattr(pipeline, "run_deep_scan", run_deep_scan)
    monkeypatch.setattr(arp, "scapy_status", lambda **kw: (True, "Test"))
    monkeypatch.setattr(oui.OuiDb, "load", classmethod(lambda cls, data_dir=None: FakeOui()))
    return c


@pytest.fixture
def api(services, calls):  # type: ignore[no-untyped-def]
    """Echter NetworkGuard und echte Adapterliste auf der FakePlatform; nur die Pipeline ist Attrappe."""
    services.settings.update(ask_before_foreign_scan=True)  # strenge Regel; Standard: tests/test_guard_free.py
    with TestClient(server.create_app(services), base_url=BASE) as client:
        yield client
    services.jobs.wait(5)


# --- S1: „Das ist mein Heimnetz“ über WLAN nur mit lesbarem WLAN-Namen -------------------------------


def test_s1_remember_home_over_unreadable_wlan_is_422_and_starts_nothing(api, services, fake_platform, calls) -> None:  # type: ignore[no-untyped-def]
    fake_platform.wifi_unreadable()  # weder WLAN-Name noch Netzwerkprofil (Profilname genügt sonst, Leitung 10.10.2026)
    r = api.post("/api/scan", json={"adapter": "WLAN", "confirm_foreign": True, "remember_home": True})
    assert r.status_code == 422, r.text
    assert "WLAN-Namen" in r.json()["detail"] and r.json()["guard"]["ssid_readable"] is False
    assert services.settings.load().home_gateway_macs == []
    assert calls.scans == []
    # „Nur diesmal scannen“ geht weiterhin (Pflichtenheft: Warnung, dann Scan nach Bestätigung)
    assert api.post("/api/scan", json={"adapter": "WLAN", "confirm_foreign": True}).status_code == 202
    services.jobs.wait(5)
    assert calls.scans == ["WLAN"]


def test_s1_remember_home_over_ethernet_still_works_without_wlan_name(api, services, fake_platform, calls) -> None:  # type: ignore[no-untyped-def]
    fake_platform.wifi_unreadable()
    r = api.post("/api/scan", json={"adapter": "Ethernet", "confirm_foreign": True, "remember_home": True})
    assert r.status_code == 202
    services.jobs.wait(5)
    assert services.settings.load().home_gateway_macs == [HOME_GW_MAC]


def test_s1_hotspot_profile_name_gives_423_in_api(api, fake_platform, calls) -> None:  # type: ignore[no-untyped-def]
    fake_platform.wifi_unreadable(profiles={"WLAN": "DE22LA000256314 8159"})
    for body in ({"adapter": "WLAN"}, {"adapter": "WLAN", "confirm_foreign": True, "remember_home": True, "mode": "registered"}):
        r = api.post("/api/scan", json=body)
        assert r.status_code == 423 and r.json()["guard"]["code"] == "blocked_ssid"
    assert calls.scans == []


# --- S6: PUT /api/settings ---------------------------------------------------------------------------


@pytest.mark.parametrize("mac", ["ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01", "33:33:00:00:00:01", "00:00:00:00:00:00"])
def test_s6_put_rejects_non_unicast_home_macs(api, services, mac) -> None:  # type: ignore[no-untyped-def]
    r = api.put("/api/settings", json={"home_gateway_macs": [HOME_GW_MAC, mac]})
    assert r.status_code == 400 and "keine Router-Adresse" in r.json()["detail"]
    assert services.settings.load().home_gateway_macs == []


def test_s6_put_rejects_learned_blocked_mac(api, services) -> None:  # type: ignore[no-untyped-def]
    services.settings.update(blocked_gateway_macs=["02:11:22:33:44:55"])
    r = api.put("/api/settings", json={"home_gateway_macs": ["02-11-22-33-44-55"]})
    assert r.status_code == 400 and "gesperrten Netz" in r.json()["detail"]
    assert api.put("/api/settings", json={"home_gateway_macs": [HOME_GW_MAC]}).status_code == 200


# --- F3/F8: Tiefenscan ---------------------------------------------------------------------------------


def test_f3_deep_scan_of_offline_device_is_rejected(api, services, calls) -> None:  # type: ignore[no-untyped-def]
    (old,) = add_devices(services, sample_device("aa:bb:cc:dd:ee:40", "192.168.178.40"))
    add_devices(services, sample_device("aa:bb:cc:dd:ee:41", "192.168.178.41"))  # neuer Scan ohne .40
    assert services.inventory.get(old.mac).online is False
    r = api.post(f"/api/devices/{old.mac}/deep-scan", json={"confirm_foreign": True})
    assert r.status_code == 422 and "nicht erreichbar" in r.json()["detail"]
    assert calls.deep == []


def test_f8_deep_scan_outside_every_adapter_network_does_not_ask_for_confirmation(api, services, calls) -> None:  # type: ignore[no-untyped-def]
    (dev,) = add_devices(services, sample_device("aa:bb:cc:dd:ee:09", "10.50.0.9"))
    services.settings.update(last_adapter="Ethernet")
    r = api.post(f"/api/devices/{dev.mac}/deep-scan", json={})
    assert r.status_code == 422  # früher 428 „Bestätigung erforderlich“ und danach ein Fehlschlag
    assert "guard" not in r.json()
    assert calls.deep == []


# --- F4: Kategorie zurück auf „Automatisch“ ordnet sofort neu ein ------------------------------------------


def test_f4_patch_category_auto_reclassifies_immediately(api, services) -> None:  # type: ignore[no-untyped-def]
    nas = sample_device("00:11:32:aa:bb:03", "192.168.178.30", vendor="Synology Incorporated",
                        ports=[sample_port(5000, "http", "medium", "x"), sample_port(5001, "https", "low", "y")])  # fmt: skip
    (dev,) = add_devices(services, nas)
    assert api.patch(f"/api/devices/{dev.mac}", json={"category": "pc"}).json()["category"] == "pc"
    data = api.patch(f"/api/devices/{dev.mac}", json={"category": "auto"}).json()
    assert data["category_source"] == "auto"
    assert data["category"] == "server" and data["category_reason"] != "vom Nutzer festgelegt"
    stored = services.inventory.get(dev.mac)
    assert (stored.category, stored.category_source) == ("server", "auto")


# --- F2: Herstellerliste – Abbruch wirkt und wird richtig gemeldet ----------------------------------------


class SlowResponse(io.BytesIO):
    """Liefert die Liste in kleinen Stücken, jedes nach einer Pause (wie ein langsamer Server)."""

    def __init__(self, data: bytes, delay_s: float) -> None:
        super().__init__(data)
        self.delay_s = delay_s
        self.reads = 0

    def read1(self, n: int = -1) -> bytes:  # type: ignore[override]
        time.sleep(self.delay_s)
        self.reads += 1
        return super().read1(min(n, 256) if n and n > 0 else 256)

    def __enter__(self):  # type: ignore[no-untyped-def]
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _ieee_csv(rows: int = 40) -> bytes:
    lines = ["Registry,Assignment,Organization Name,Organization Address"]
    lines += [f'MA-L,{i:06X},"Firma {i}",Adresse' for i in range(rows)]
    return ("\n".join(lines) + "\n").encode()


def test_f2_oui_update_cancel_stops_download_and_keeps_list(make_ctx, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / oui.OUI_FILE
    with gzip.open(target, "wt", encoding="utf-8") as fh:
        fh.write("# alt\nAABBCC\tAlt\n")
    before = target.read_bytes()
    response = SlowResponse(_ieee_csv(400), 0.05)
    monkeypatch.setattr(oui.urllib.request, "urlopen", lambda request, timeout=None: response)
    ctx = make_ctx()
    threading.Timer(0.3, ctx.cancel.cancel).start()
    t0 = time.monotonic()
    with pytest.raises(ScanCancelled):
        oui.update_from_ieee(tmp_path, min_entries=1, ctx=ctx)
    assert time.monotonic() - t0 < 2.0
    assert target.read_bytes() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == [oui.OUI_FILE]


def test_f2_oui_update_cancel_right_before_replace_changes_nothing(make_ctx, tmp_path: Path) -> None:
    ctx = make_ctx()
    original = ctx.check_cancel
    calls = {"n": 0}

    def check() -> None:  # Abbruch genau bei der letzten Prüfung vor os.replace
        calls["n"] += 1
        if calls["n"] == 2:
            ctx.cancel.cancel()
        original()

    ctx.check_cancel = check  # type: ignore[method-assign]
    with pytest.raises(ScanCancelled):
        oui.update_from_ieee(tmp_path, lambda url: _ieee_csv(20), min_entries=1, ctx=ctx)
    assert list(tmp_path.iterdir()) == []


def test_f2_job_that_finished_despite_cancel_is_completed(services) -> None:  # type: ignore[no-untyped-def]
    gate = threading.Event()

    def work(ctx):  # type: ignore[no-untyped-def]
        gate.wait(5)  # prüft den Abbruch nicht – wie die Speicherschleife eines Scans
        return {"saved": True}

    services.jobs.start("oui_update", "x", work)
    assert services.jobs.cancel()
    gate.set()
    assert services.jobs.wait(5)
    res = services.jobs.last_result
    assert res["result"] == "completed" and res["summary"] == {"saved": True}
    logs = [e.data["message"] for e in services.bus.history(type_prefix="job.log")]
    assert any("zu spät" in m for m in logs)


def test_f1_cancel_event_comes_before_job_finished(services) -> None:  # type: ignore[no-untyped-def]
    """jobs.cancel veröffentlicht „Abbruch“ unter der Sperre – nie nach job.finished desselben Auftrags."""
    for _ in range(20):
        job_id = services.jobs.start("scan", "x", lambda ctx: ctx.sleep(5))
        services.jobs.cancel()
        assert services.jobs.wait(5)
        types = [e.type for e in services.bus.history() if e.job_id == job_id]
        assert types[-1] == "job.finished"
        assert types.index("job.progress") < types.index("job.finished")


def test_remember_home_over_wlan_with_profile_name_works(api, services, fake_platform, calls) -> None:  # type: ignore[no-untyped-def]
    """Leitung: Standortfreigabe aus, aber Windows nennt das Netzwerkprofil – Heimnetz merken geht."""
    fake_platform.wifi_unreadable(profiles={"WLAN": "Welt"})
    r = api.post("/api/scan", json={"adapter": "WLAN", "confirm_foreign": True, "remember_home": True})
    assert r.status_code == 202, r.text
    services.jobs.wait(5)
    assert services.settings.load().home_gateway_macs == [HOME_GW_MAC]
    assert api.get("/api/guard", params={"adapter": "WLAN"}).json()["decision"] == "allow"
