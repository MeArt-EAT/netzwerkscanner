"""Regressionstests zu den Prüfbefunden am Netz-Wächter und an der Windows-Plattform.

S1/WIN-01 (Hotspot ohne Standortberechtigung), S6 (gesperrte MAC nie Heimnetz), S7 (Routen-Cache, ARP je
Schnittstelle), WIN-02 (versteckte Adapter), WIN-07 (QuickEdit). Alles mit Attrappen – kein Paket ins Netz.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from netscan.config import SettingsStore
from netscan.core.db import Database
from netscan.core.guard import HomeRefused, NetworkGuard
from netscan.net import adapters
from netscan.platform import windows
from netscan.platform.base import AdapterDetail, InterfaceAddr, WifiStatus
from netscan.platform.windows import WindowsPlatform, _parse_arp_sections, _parse_profiles, _Result
from tests.fakes import HOME_GW_IP, HOME_GW_MAC, HOTSPOT_SSID, FakePlatform, make_adapter

HOTSPOT_GW_IP = "172.20.10.1"
HOTSPOT_GW_MAC = "02:1a:2b:00:00:01"


@pytest.fixture
def store(tmp_path: Path):  # type: ignore[no-untyped-def]
    db = Database(tmp_path / "guard.sqlite3")
    st = SettingsStore(db)
    # Diese Datei prüft die strenge Regel des Pflichtenhefts (Heimnetz/Bestätigung). Seit 10.10.2026 ist sie
    # nur noch per Einstellung aktiv; die Standardregel „frei außer Schule“ prüft tests/test_guard_free.py.
    st.update(ask_before_foreign_scan=True)
    yield st
    db.close()


@pytest.fixture
def fake() -> FakePlatform:
    return FakePlatform()


@pytest.fixture
def guard(fake: FakePlatform, store: SettingsStore) -> NetworkGuard:
    return NetworkGuard(fake, store)


def wlan_hotspot():  # type: ignore[no-untyped-def]
    return make_adapter("WLAN", "172.20.10.2", "172.20.10.0/28", wireless=True, mac="a4:c3:61:00:00:21")


def wlan_home():  # type: ignore[no-untyped-def]
    return make_adapter("WLAN", "192.168.178.21", wireless=True, mac="a4:c3:61:00:00:21")


def join_hotspot_without_location(fake: FakePlatform, profile: str | None = HOTSPOT_SSID) -> None:
    """Zustand des Ziel-PCs: netsh liefert keinen Namen (Standortberechtigung fehlt), nur das Netzwerkprofil."""
    fake.ifaces = [i for i in fake.ifaces if i.name != "WLAN"] + [
        InterfaceAddr("WLAN", "172.20.10.2", "255.255.255.240", "a4:c3:61:00:00:21", True)
    ]
    fake.gateways["WLAN"] = HOTSPOT_GW_IP
    fake.neighbors[HOTSPOT_GW_IP] = HOTSPOT_GW_MAC
    fake.wifi_unreadable(profiles={"WLAN": profile} if profile else {})


# --- S1/WIN-01: Hotspot-Sperre ohne Standortberechtigung --------------------------------------------


def test_s1_profile_name_of_hotspot_blocks_and_learns_gateway(guard: NetworkGuard, fake: FakePlatform, store: SettingsStore) -> None:
    join_hotspot_without_location(fake)
    r = guard.check(wlan_hotspot())
    assert (r.decision, r.code) == ("block", "blocked_ssid")
    assert r.ssid == HOTSPOT_SSID and r.ssid_readable is False
    assert "Netzwerkprofil" in r.reason
    # gelernt, damit Regel 3 auch ohne Profilnamen greift
    assert store.load().blocked_gateway_macs == [HOTSPOT_GW_MAC]
    fake.wifi_unreadable(profiles={})
    assert guard.check(wlan_hotspot()).code == "blocked_gateway"


def test_s1_profile_name_blocks_every_adapter_and_cannot_become_home(guard: NetworkGuard, fake: FakePlatform) -> None:
    join_hotspot_without_location(fake)
    for adapter in (make_adapter(), wlan_hotspot()):  # auch ein Scan über Ethernet ist gesperrt
        assert guard.check(adapter).decision == "block"
    with pytest.raises(ValueError):
        guard.remember_home(HOTSPOT_GW_MAC)


def test_s1_profile_name_only_blocks_never_allows(guard: NetworkGuard, fake: FakePlatform) -> None:
    # Ähnlicher Name sperrt nicht (Pflichtenheft), und ein harmloser Profilname gibt nichts frei.
    join_hotspot_without_location(fake, profile=HOTSPOT_SSID[:-1] + "0")
    r = guard.check(wlan_hotspot())
    assert (r.decision, r.code) == ("confirm", "foreign_network")
    assert r.ssid_readable is False and r.ssid is None
    join_hotspot_without_location(fake, profile="  " + HOTSPOT_SSID + " ")  # Rand-Leerzeichen: sichere Richtung
    assert guard.check(wlan_hotspot()).decision == "block"


def test_s1_extra_blocked_names_also_match_profiles(guard: NetworkGuard, fake: FakePlatform, store: SettingsStore) -> None:
    store.update(blocked_ssids_extra=["Schule-Gast"])
    join_hotspot_without_location(fake, profile="Schule-Gast")
    assert guard.check(wlan_hotspot()).code == "blocked_ssid"


def test_s1_remember_home_over_wlan_needs_readable_name(guard: NetworkGuard, fake: FakePlatform, store: SettingsStore) -> None:
    # Leitungsentscheidung 10.10.2026: Ohne WLAN-Namen UND ohne Netzwerkprofilnamen wird abgelehnt;
    # ein (nicht gesperrter) Profilname genügt – siehe test_profile_name_allows_home_over_wlan_without_location.
    fake.wifi_unreadable()
    with pytest.raises(HomeRefused, match="WLAN-Namen"):
        guard.remember_home(HOME_GW_MAC, adapter=wlan_home())
    assert store.load().home_gateway_macs == []
    # über Ethernet bleibt es möglich (dort spielt der WLAN-Name keine Rolle)
    guard.remember_home(HOME_GW_MAC, adapter=make_adapter())
    assert store.load().home_gateway_macs == [HOME_GW_MAC]


def test_s1_remember_home_over_wlan_with_readable_name_works(guard: NetworkGuard, store: SettingsStore) -> None:
    guard.remember_home(HOME_GW_MAC, adapter=wlan_home())  # FakePlatform: WLAN „Heimnetz“ lesbar
    assert store.load().home_gateway_macs == [HOME_GW_MAC]


def test_s1_unknown_adapter_kind_counts_as_wlan_when_details_fail(fake: FakePlatform, store: SettingsStore) -> None:
    class NoDetails(FakePlatform):
        def adapter_details(self):  # type: ignore[no-untyped-def]
            raise OSError("Get-NetAdapter fehlt")

    platform = NoDetails()
    platform.wifi_unreadable()
    guard = NetworkGuard(platform, store)
    plain = make_adapter("WLAN", "192.168.178.21", wireless=False)  # Art unbekannt
    with pytest.raises(HomeRefused):
        guard.remember_home(HOME_GW_MAC, adapter=plain)


def test_s1_windows_reads_profiles_only_when_netsh_has_no_name(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    outputs = {
        "netsh": "Netzwerkshellbefehle benötigen Standortberechtigungen für den Zugriff auf WLAN-Informationen.",
        "profile": '[{"Name":"DE22LA000256314 8159","InterfaceAlias":"WLAN"},{"Name":"Netzwerk 3","InterfaceAlias":"Ethernet"}]',
    }

    def run(args: list[str], timeout: float) -> _Result | None:
        key = "profile" if "Get-NetConnectionProfile" in args[-1] else args[0].lower().rsplit("\\", 1)[-1].removesuffix(".exe")
        calls.append(key)
        return _Result(1 if key == "netsh" else 0, outputs.get(key, ""), "")

    monkeypatch.setattr(windows, "_run", run)
    plat = WindowsPlatform()
    st = plat.wifi_status()
    assert st.readable is False
    assert st.profile_names == {"WLAN": HOTSPOT_SSID, "Ethernet": "Netzwerk 3"}
    assert calls.count("profile") == 1
    # mit lesbarem Namen wird nichts zusätzlich abgefragt
    outputs["netsh"] = "    Name                   : WLAN\n    Status                 : Verbunden\n    SSID                   : Welt\n"
    calls.clear()
    st = plat.wifi_status()
    assert st.readable is True and st.profile_names == {} and "profile" not in calls


def test_s1_parse_profiles() -> None:
    assert _parse_profiles('{"Name":" Welt ","InterfaceAlias":"WLAN"}') == {"WLAN": "Welt"}
    assert _parse_profiles('[{"Name":"","InterfaceAlias":"WLAN"},{"Name":"X","InterfaceAlias":""},{"Name":5}]') == {}
    assert _parse_profiles("kaputt") == {} and _parse_profiles("") == {}


def test_s1_guard_survives_odd_profile_data(guard: NetworkGuard, fake: FakePlatform) -> None:
    fake.wifi = WifiStatus([], readable=False, error="x", profile_names={"WLAN": None, 5: HOTSPOT_SSID})  # type: ignore[dict-item]
    assert guard.check(wlan_home()).decision == "confirm"


# --- S6: gesperrte MAC nie Heimnetz -----------------------------------------------------------------


def test_s6_blocked_mac_in_home_list_never_allows(guard: NetworkGuard, fake: FakePlatform, store: SettingsStore) -> None:
    # Router gleich, WLAN-Name lesbar, aber anders (umbenannter Hotspot): früher allow, jetzt confirm
    store.update(blocked_gateway_macs=[HOME_GW_MAC], home_gateway_macs=[HOME_GW_MAC])
    fake.connect_wifi("Ganz anderer Name")
    r = guard.check(wlan_home())
    assert r.decision == "confirm" and r.code == "foreign_network"


def test_s6_learning_a_blocked_mac_removes_it_from_home(guard: NetworkGuard, fake: FakePlatform, store: SettingsStore) -> None:
    store.update(home_gateway_macs=[HOTSPOT_GW_MAC, HOME_GW_MAC])
    join_hotspot_without_location(fake)
    assert guard.check(wlan_hotspot()).decision == "block"
    settings = store.load()
    assert settings.blocked_gateway_macs == [HOTSPOT_GW_MAC]
    assert settings.home_gateway_macs == [HOME_GW_MAC]


# --- S7: Routen-Cache und ARP je Schnittstelle --------------------------------------------------------

ROUTES_HOME = '{"InterfaceAlias":"WLAN","NextHop":"192.168.178.1","RouteMetric":0,"InterfaceMetric":35}'
ROUTES_HOTSPOT = '{"InterfaceAlias":"WLAN","NextHop":"172.20.10.1","RouteMetric":0,"InterfaceMetric":35}'
ARP_TWO = """
Schnittstelle: 192.168.1.20 --- 0x8
  Internetadresse       Physische Adresse     Typ
  192.168.1.1           3c-a6-2f-00-00-01     dynamisch

Schnittstelle: 192.168.1.30 --- 0x12
  Internetadresse       Physische Adresse     Typ
  192.168.1.1           02-1a-2b-00-00-01     dynamisch
"""


def test_s7_route_cache_follows_address_change_even_without_wifi_name(monkeypatch: pytest.MonkeyPatch) -> None:
    out = {"routes": ROUTES_HOME}

    def run(args: list[str], timeout: float) -> _Result | None:
        if "Get-NetRoute" in args[-1]:
            return _Result(0, out["routes"], "")
        return _Result(1, "Netzwerkshellbefehle benötigen Standortberechtigungen", "")

    monkeypatch.setattr(windows, "_run", run)
    plat = WindowsPlatform()
    ifaces = [InterfaceAddr("WLAN", "192.168.178.21", "255.255.255.0", None, True)]
    monkeypatch.setattr(plat, "interfaces", lambda: list(ifaces))
    plat.wifi_status()
    assert plat.default_gateway("WLAN") == "192.168.178.1"
    # Wechsel in den Hotspot innerhalb von 5 s: WLAN-Signatur gleich (Name nicht lesbar), Adresse neu
    out["routes"] = ROUTES_HOTSPOT
    ifaces[0] = InterfaceAddr("WLAN", "172.20.10.2", "255.255.255.240", None, True)
    plat.wifi_status()
    assert plat.default_gateway("WLAN") == "172.20.10.1"


def test_s7_arp_sections_and_interface_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    sections = _parse_arp_sections(ARP_TWO)
    assert sections["192.168.1.20"] == {"192.168.1.1": "3c:a6:2f:00:00:01"}
    assert sections["192.168.1.30"] == {"192.168.1.1": "02:1a:2b:00:00:01"}
    monkeypatch.setattr(windows, "_run", lambda args, timeout: _Result(0, ARP_TWO, ""))
    plat = WindowsPlatform()
    monkeypatch.setattr(
        plat, "interfaces",
        lambda: [InterfaceAddr("Ethernet", "192.168.1.20", "255.255.255.0", None, True),
                 InterfaceAddr("WLAN", "192.168.1.30", "255.255.255.0", None, True)],
    )  # fmt: skip
    assert plat.neighbor_mac("192.168.1.1", "Ethernet") == "3c:a6:2f:00:00:01"
    assert plat.neighbor_mac("192.168.1.1", "WLAN") == "02:1a:2b:00:00:01"
    assert plat.neighbor_mac("192.168.1.1", "gibt-es-nicht") is None
    assert plat.neighbor_mac("192.168.1.1") == "3c:a6:2f:00:00:01"  # ohne Schnittstelle wie bisher


def test_s7_guard_asks_per_interface_and_sees_blocked_hotspot_router(guard: NetworkGuard, fake: FakePlatform, store: SettingsStore) -> None:
    # Ethernet (Heimrouter) und WLAN im Hotspot mit derselben Gateway-IP; WLAN-Name nicht lesbar
    store.update(blocked_gateway_macs=[HOTSPOT_GW_MAC], home_gateway_macs=[HOME_GW_MAC])
    fake.gateways.update({"Ethernet": HOME_GW_IP, "WLAN": HOME_GW_IP})
    fake.neighbors = {HOME_GW_IP: HOME_GW_MAC}  # globale Tabelle kennt nur den Heimrouter
    fake.iface_neighbors = {"Ethernet": {HOME_GW_IP: HOME_GW_MAC}, "WLAN": {HOME_GW_IP: HOTSPOT_GW_MAC}}
    fake.wifi_unreadable()
    r = guard.check(make_adapter())
    assert (r.decision, r.code) == ("block", "blocked_gateway")
    assert r.gateway_mac == HOTSPOT_GW_MAC


# --- WIN-02: versteckte virtuelle Adapter ---------------------------------------------------------------


def test_win02_get_netadapter_includes_hidden_adapters() -> None:
    assert "Get-NetAdapter -IncludeHidden" in windows._PS_ADAPTERS


def test_win02_hidden_wifi_direct_and_vpn_without_details_are_virtual() -> None:
    p = FakePlatform(
        ifaces=[
            InterfaceAddr("LAN-Verbindung* 10", "192.168.137.1", "255.255.255.0", "a6:c3:61:00:00:22", True),
            InterfaceAddr("Local Area Connection* 13", "10.8.0.5", "255.255.255.0", "02:00:4c:4f:4f:50", True),
            InterfaceAddr("Ethernet", "192.168.178.20", "255.255.255.0", "00:1b:21:00:00:20", True),
            InterfaceAddr("WLAN", "192.168.178.21", "255.255.255.0", "a4:c3:61:00:00:21", True),
        ],
        details={
            "Ethernet": AdapterDetail("Ethernet", "Intel(R) Ethernet", False, False, "00:1b:21:00:00:20"),
            "WLAN": AdapterDetail("WLAN", "Intel(R) Wi-Fi 6", False, True, "a4:c3:61:00:00:21"),
        },
    )
    names = [a.name for a in adapters.list_adapters(p)]
    assert names == ["Ethernet", "WLAN"]  # die versteckten stehen nicht mehr vor dem WLAN
    assert adapters._looks_virtual("", "Microsoft Wi-Fi Direct Virtual Adapter #2")
    assert adapters._looks_virtual("", "Shrew Soft Virtual Adapter")
    assert not adapters._looks_virtual("Ethernet 2", "Realtek PCIe GbE Family Controller")


# --- WIN-07: QuickEdit im Server-Fenster ----------------------------------------------------------------


def test_win07_quick_edit_bit_is_cleared_and_extended_flags_set() -> None:
    mode = 0x01F7  # typischer Eingabemodus mit QuickEdit
    new = windows._mode_without_quick_edit(mode)
    assert new & windows.ENABLE_QUICK_EDIT_MODE == 0
    assert new & windows.ENABLE_EXTENDED_FLAGS
    assert new & 0x0007 == mode & 0x0007  # übrige Bits bleiben


def test_win07_disable_quick_edit_is_harmless_without_console(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(windows.sys, "platform", "linux")
    assert windows.disable_quick_edit() is None


def test_win07_server_has_no_access_log() -> None:
    import inspect

    from netscan.web import server

    assert "access_log=False" in inspect.getsource(server.run)


def test_unreadable_wifi_reason_does_not_offer_home_button(services, fake_platform) -> None:  # type: ignore[no-untyped-def]
    """Leitung: Über WLAN ohne lesbaren Namen wird remember_home abgelehnt – der Text darf es nicht anbieten."""
    services.settings.update(ask_before_foreign_scan=True)  # strenge Regel
    from tests.fakes import make_adapter

    fake_platform.wifi_unreadable()
    wlan = make_adapter("WLAN", ipv4="192.168.178.21", wireless=True, mac="a4:c3:61:00:00:21")
    g = services.guard.check(wlan)
    assert g.decision == "confirm"
    assert "„Das ist mein Heimnetz“" not in g.reason
    assert "Standortberechtigung" in g.reason
    eth = make_adapter("Ethernet")
    assert "„Das ist mein Heimnetz“" in services.guard.check(eth).reason


def test_profile_name_allows_home_over_wlan_without_location(services, fake_platform) -> None:  # type: ignore[no-untyped-def]
    """Leitung: Ohne Standortfreigabe genügt der (nicht gesperrte) Netzwerkprofilname, um das Heimnetz zu merken."""
    services.settings.update(ask_before_foreign_scan=True)  # strenge Regel
    from tests.fakes import HOME_GW_MAC, HOTSPOT_SSID, make_adapter

    wlan = make_adapter("WLAN", ipv4="192.168.178.21", wireless=True, mac="a4:c3:61:00:00:21")
    fake_platform.wifi_unreadable(profiles={"WLAN": "Welt"})
    g = services.guard.check(wlan)
    assert g.decision == "confirm" and g.home_allowed and g.profile_name == "Welt"
    assert "„Das ist mein Heimnetz“" in g.reason
    services.guard.remember_home(HOME_GW_MAC, wlan)
    assert services.guard.check(wlan).decision == "allow"

    # Hotspot-Profil: gesperrt, kein Heimnetz möglich
    fake_platform.wifi_unreadable(profiles={"WLAN": HOTSPOT_SSID})
    blocked = services.guard.check(wlan)
    assert blocked.decision == "block" and not blocked.home_allowed


def test_no_profile_no_ssid_still_refuses_home(services, fake_platform) -> None:  # type: ignore[no-untyped-def]
    import pytest
    services.settings.update(ask_before_foreign_scan=True)  # strenge Regel

    from netscan.core.guard import HomeRefused
    from tests.fakes import HOME_GW_MAC, make_adapter

    wlan = make_adapter("WLAN", ipv4="192.168.178.21", wireless=True, mac="a4:c3:61:00:00:21")
    fake_platform.wifi_unreadable()
    assert not services.guard.check(wlan).home_allowed
    with pytest.raises(HomeRefused):
        services.guard.remember_home(HOME_GW_MAC, wlan)
