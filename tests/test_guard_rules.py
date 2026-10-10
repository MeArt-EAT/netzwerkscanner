"""Netz-Wächter (BAUPLAN §10) mit FakePlatform – inkl. Abnahmekriterien Pflichtenheft Stufe 1."""

from __future__ import annotations

import inspect
import json
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from netscan.config import PERMANENT_BLOCKED_SSIDS, SettingsStore
from netscan.core.db import Database
from netscan.core.guard import NetworkGuard
from netscan.core.models import PingResult
from netscan.platform.base import AdapterDetail, InterfaceAddr, WifiEntry, WifiStatus
from tests.fakes import HOME_GW_IP, HOME_GW_MAC, HOTSPOT_SSID, FakePlatform, make_adapter

HOTSPOT_GW_IP = "172.20.10.1"
HOTSPOT_GW_MAC = "02:1a:2b:00:00:01"  # Handy-Hotspot, lokal verwaltete MAC
FOREIGN_GW_IP = "10.0.0.1"
FOREIGN_GW_MAC = "00:11:32:00:00:99"


@dataclass
class FlakyPlatform(FakePlatform):
    """FakePlatform, deren Methoden auf Wunsch eine Ausnahme werfen (Befehl fehlt o. Ä.)."""

    fail: set[str] = field(default_factory=set)

    def _maybe_fail(self, method: str) -> None:
        if method in self.fail:
            raise FileNotFoundError(f"{method}: Befehl fehlt")

    def interfaces(self) -> list[InterfaceAddr]:
        self._maybe_fail("interfaces")
        return super().interfaces()

    def adapter_details(self) -> dict[str, AdapterDetail]:
        self._maybe_fail("adapter_details")
        return super().adapter_details()

    def wifi_status(self) -> WifiStatus:
        self._maybe_fail("wifi_status")
        return super().wifi_status()

    def default_gateway(self, adapter_name: str | None = None) -> str | None:
        self._maybe_fail("default_gateway")
        return super().default_gateway(adapter_name)

    def neighbor_mac(self, ip: str) -> str | None:
        self._maybe_fail("neighbor_mac")
        return super().neighbor_mac(ip)

    def ping(self, ip: str, timeout_ms: int) -> PingResult:
        raise AssertionError("Der Wächter darf nicht pingen")


@pytest.fixture
def fake() -> FlakyPlatform:
    return FlakyPlatform()


@pytest.fixture
def store(tmp_path: Path):  # type: ignore[no-untyped-def]
    db = Database(tmp_path / "guard.sqlite3")
    yield SettingsStore(db)
    db.close()


@pytest.fixture
def guard(fake: FlakyPlatform, store: SettingsStore) -> NetworkGuard:
    return NetworkGuard(fake, store)


def join_hotspot(fake: FakePlatform, ssid: str = HOTSPOT_SSID, readable: bool = True) -> None:
    """WLAN-Adapter verbindet sich mit einem Handy-Hotspot (eigenes Netz 172.20.10.0/28)."""
    fake.ifaces = [i for i in fake.ifaces if i.name != "WLAN"] + [
        InterfaceAddr("WLAN", "172.20.10.2", "255.255.255.240", "a4:c3:61:00:00:21", True)
    ]
    fake.gateways["WLAN"] = HOTSPOT_GW_IP
    fake.neighbors[HOTSPOT_GW_IP] = HOTSPOT_GW_MAC
    fake.connect_wifi(ssid, readable=readable)


def wlan_home():  # type: ignore[no-untyped-def]
    return make_adapter("WLAN", "192.168.178.21", wireless=True, mac="a4:c3:61:00:00:21")


def wlan_hotspot():  # type: ignore[no-untyped-def]
    return make_adapter("WLAN", "172.20.10.2", "172.20.10.0/28", wireless=True, mac="a4:c3:61:00:00:21")


# --- Heimnetz, erster Start ---------------------------------------------------------------


def test_home_network_is_allowed(guard: NetworkGuard) -> None:
    guard.remember_home(HOME_GW_MAC)
    r = guard.check(make_adapter())
    assert (r.decision, r.code) == ("allow", "ok_home")
    assert r.gateway_ip == HOME_GW_IP and r.gateway_mac == HOME_GW_MAC
    assert r.ssid == "Heimnetz" and r.ssid_readable is True
    assert "Heimnetz erkannt" in r.reason


def test_first_start_asks_for_confirmation(guard: NetworkGuard) -> None:
    r = guard.check(make_adapter())
    assert (r.decision, r.code) == ("confirm", "foreign_network")
    assert r.reason.startswith("Noch kein Heimnetz festgelegt")
    assert HOME_GW_MAC in r.reason and "Das ist mein Heimnetz" in r.reason


def test_first_start_without_gateway_mac(guard: NetworkGuard, fake: FlakyPlatform) -> None:
    fake.neighbors.clear()
    r = guard.check(make_adapter())
    assert (r.decision, r.code) == ("confirm", "unknown_network")
    assert r.reason.startswith("Noch kein Heimnetz festgelegt")


def test_foreign_network_asks(guard: NetworkGuard, fake: FlakyPlatform) -> None:
    guard.remember_home(HOME_GW_MAC)
    fake.set_gateway(FOREIGN_GW_IP, FOREIGN_GW_MAC)
    r = guard.check(make_adapter())
    assert (r.decision, r.code) == ("confirm", "foreign_network")
    assert r.gateway_ip == FOREIGN_GW_IP and r.gateway_mac == FOREIGN_GW_MAC
    assert r.reason.startswith("Fremdes Netz") and "Bestätigung" in r.reason


def test_unknown_gateway_mac_asks(guard: NetworkGuard, fake: FlakyPlatform) -> None:
    guard.remember_home(HOME_GW_MAC)
    fake.neighbors.clear()
    r = guard.check(make_adapter())
    assert (r.decision, r.code) == ("confirm", "unknown_network")
    assert r.gateway_ip == HOME_GW_IP and r.gateway_mac is None
    assert "nicht bekannt" in r.reason


def test_no_gateway_asks(guard: NetworkGuard, fake: FlakyPlatform) -> None:
    guard.remember_home(HOME_GW_MAC)
    fake.set_gateway(None, None)
    r = guard.check(make_adapter())
    assert (r.decision, r.code) == ("confirm", "no_gateway")
    assert r.gateway_ip is None and "„Ethernet“" in r.reason


def test_adapter_without_route_does_not_borrow_other_gateway(guard: NetworkGuard, fake: FlakyPlatform) -> None:
    guard.remember_home(HOME_GW_MAC)
    fake.gateways["Ethernet"] = None  # Kabel an einem fremden Switch ohne Router
    r = guard.check(make_adapter())
    assert (r.decision, r.code) == ("confirm", "no_gateway")


def test_check_without_adapter_uses_preferred_gateway(guard: NetworkGuard) -> None:
    guard.remember_home(HOME_GW_MAC)
    r = guard.check(None)
    assert (r.decision, r.code) == ("allow", "ok_home")


# --- Schul-Hotspot (Pflichtenheft, Grundsatz 6 und Abnahme) -----------------------------------


@pytest.mark.parametrize("scan_adapter", ["wlan", "ethernet", "none"])
def test_hotspot_with_exact_name_blocks_every_scan(
    guard: NetworkGuard, fake: FlakyPlatform, store: SettingsStore, scan_adapter: str
) -> None:
    guard.remember_home(HOME_GW_MAC)  # Ethernet hängt sogar im Heimnetz
    join_hotspot(fake)
    adapter = {"wlan": wlan_hotspot(), "ethernet": make_adapter(), "none": None}[scan_adapter]
    r = guard.check(adapter)
    assert (r.decision, r.code) == ("block", "blocked_ssid")
    assert r.ssid == HOTSPOT_SSID and r.ssid_readable is True
    assert r.gateway_ip == HOTSPOT_GW_IP and r.gateway_mac == HOTSPOT_GW_MAC
    assert "nicht übergehen" in r.reason and "nur eingetragene Geräte" in r.reason
    # Router-MAC des Hotspots gemerkt – und nur diese (nicht der Heimnetz-Router am Ethernet)
    assert store.load().blocked_gateway_macs == [HOTSPOT_GW_MAC]


def test_hotspot_on_second_wlan_adapter_blocks(guard: NetworkGuard, fake: FlakyPlatform) -> None:
    guard.remember_home(HOME_GW_MAC)
    fake.wifi = WifiStatus([WifiEntry("WLAN", True, "Heimnetz"), WifiEntry("WLAN 2", True, HOTSPOT_SSID)])
    r = guard.check(wlan_home())
    assert (r.decision, r.code) == ("block", "blocked_ssid")
    assert r.ssid == HOTSPOT_SSID


@pytest.mark.parametrize(
    "ssid",
    [
        "DE22LA000256314 8158",
        "de22la000256314 8159",
        "DE22LA000256314  8159",
        "DE22LA0002563148159",
        "DE22LA000256314 81590",
        "XDE22LA000256314 8159",
    ],
)
def test_similar_name_is_not_blocked(guard: NetworkGuard, fake: FlakyPlatform, ssid: str) -> None:
    guard.remember_home(HOME_GW_MAC)
    fake.connect_wifi(ssid)
    r = guard.check(wlan_home())
    assert (r.decision, r.code) == ("allow", "ok_home")
    assert r.ssid == ssid


def test_similar_hotspot_name_in_foreign_network_only_asks(guard: NetworkGuard, fake: FlakyPlatform) -> None:
    guard.remember_home(HOME_GW_MAC)
    join_hotspot(fake, ssid="DE22LA000256314 8158")
    r = guard.check(wlan_hotspot())
    assert (r.decision, r.code) == ("confirm", "foreign_network")


def test_mac_rule_does_not_apply_to_readable_other_name(
    guard: NetworkGuard, fake: FlakyPlatform, store: SettingsStore
) -> None:
    join_hotspot(fake)
    assert guard.check(wlan_hotspot()).decision == "block"
    assert store.load().blocked_gateway_macs == [HOTSPOT_GW_MAC]
    fake.connect_wifi("DE22LA000256314 8158")  # gleiches Handy, Hotspot umbenannt
    r = guard.check(wlan_hotspot())
    assert (r.decision, r.code) == ("confirm", "foreign_network")


@pytest.mark.parametrize("how", ["readable_false", "ssid_none", "wifi_exception", "no_entry"])
def test_block_after_first_detection_even_if_name_unreadable(
    guard: NetworkGuard, fake: FlakyPlatform, how: str
) -> None:
    guard.remember_home(HOME_GW_MAC)
    join_hotspot(fake)
    assert guard.check(wlan_hotspot()).code == "blocked_ssid"  # erstes Erkennen
    if how == "readable_false":
        fake.wifi_unreadable("Standortberechtigung fehlt")
    elif how == "ssid_none":
        fake.connect_wifi(None)
    elif how == "wifi_exception":
        fake.fail.add("wifi_status")
    else:  # Plattform meldet „lesbar, kein WLAN“, der WLAN-Adapter hat aber einen Router
        fake.wifi = WifiStatus([], readable=True)
    for adapter in (wlan_hotspot(), make_adapter(), None):
        r = guard.check(adapter)
        assert (r.decision, r.code) == ("block", "blocked_gateway"), (how, adapter)
        assert r.gateway_mac == HOTSPOT_GW_MAC and r.ssid_readable is False
        assert "nicht übergehen" in r.reason


def test_unreadable_name_blocks_ethernet_scan_via_wlan_gateway(guard: NetworkGuard, fake: FlakyPlatform) -> None:
    guard.remember_home(HOME_GW_MAC)
    join_hotspot(fake)
    guard.check(make_adapter())
    fake.wifi_unreadable()
    r = guard.check(make_adapter())  # Ethernet im Heimnetz, WLAN im (unlesbaren) Hotspot
    assert (r.decision, r.code) == ("block", "blocked_gateway")
    assert r.gateway_ip == HOTSPOT_GW_IP


def test_unknown_hotspot_with_unreadable_name_only_asks(guard: NetworkGuard, fake: FlakyPlatform) -> None:
    guard.remember_home(HOME_GW_MAC)
    join_hotspot(fake)
    fake.wifi_unreadable("Standortberechtigung fehlt")  # noch nie erkannt ⇒ MAC unbekannt
    r = guard.check(wlan_hotspot())
    assert (r.decision, r.code) == ("confirm", "foreign_network")
    assert r.ssid_readable is False
    assert "nicht lesbar" in r.reason and "Standortberechtigung fehlt" in r.reason


def test_switching_into_hotspot_blocks_next_check(guard: NetworkGuard, fake: FlakyPlatform) -> None:
    guard.remember_home(HOME_GW_MAC)
    assert guard.check(wlan_home()).decision == "allow"
    join_hotspot(fake)  # Wechsel bei laufendem Programm
    assert guard.check(wlan_hotspot()).decision == "block"
    assert guard.check(make_adapter()).decision == "block"


def test_leaving_hotspot_unblocks_home_network(guard: NetworkGuard, fake: FlakyPlatform, store: SettingsStore) -> None:
    guard.remember_home(HOME_GW_MAC)
    join_hotspot(fake)
    assert guard.check(make_adapter()).decision == "block"
    fake.wifi = WifiStatus([WifiEntry("WLAN", False, None)], readable=True)
    fake.gateways["WLAN"] = None
    assert guard.check(make_adapter()).decision == "allow"
    fake.wifi_unreadable()  # auch bei unlesbarem Namen bleibt das Heimnetz frei
    assert guard.check(make_adapter()).decision == "allow"
    assert HOME_GW_MAC not in store.load().blocked_gateway_macs


# --- unlesbarer WLAN-Name sonst ------------------------------------------------------------


def test_unreadable_name_in_home_network_is_allowed(guard: NetworkGuard, fake: FlakyPlatform) -> None:
    guard.remember_home(HOME_GW_MAC)
    fake.wifi_unreadable()
    r = guard.check(wlan_home())
    assert (r.decision, r.code) == ("allow", "ok_home")
    assert r.ssid_readable is False and "nicht lesbar" in r.reason


def test_unreadable_name_in_foreign_network_asks(guard: NetworkGuard, fake: FlakyPlatform) -> None:
    guard.remember_home(HOME_GW_MAC)
    fake.set_gateway(FOREIGN_GW_IP, FOREIGN_GW_MAC)
    fake.wifi_unreadable("Standortberechtigung fehlt")
    r = guard.check(make_adapter())
    assert (r.decision, r.code) == ("confirm", "foreign_network")
    assert r.ssid_readable is False and "WLAN-Name ist nicht lesbar" in r.reason


def test_connected_entry_without_name_counts_as_unreadable(guard: NetworkGuard, fake: FlakyPlatform) -> None:
    fake.connect_wifi(None)
    r = guard.check(wlan_home())
    assert r.decision == "confirm" and r.ssid_readable is False and "nicht lesbar" in r.reason


def test_empty_ssid_counts_as_unreadable(guard: NetworkGuard, fake: FlakyPlatform) -> None:
    guard.remember_home(HOME_GW_MAC)
    fake.connect_wifi("")
    r = guard.check(wlan_home())
    assert r.ssid_readable is False and r.ssid is None


def test_wireless_adapter_without_wifi_entry_counts_as_unreadable(guard: NetworkGuard, fake: FlakyPlatform) -> None:
    guard.remember_home(HOME_GW_MAC)
    fake.wifi = WifiStatus([], readable=True)
    r = guard.check(wlan_home())
    assert (r.decision, r.code) == ("allow", "ok_home")
    assert r.ssid_readable is False and "kein WLAN-Status" in r.reason


def test_wlan_with_router_but_no_reported_connection_counts_as_unreadable(
    guard: NetworkGuard, fake: FlakyPlatform
) -> None:
    guard.remember_home(HOME_GW_MAC)
    fake.wifi = WifiStatus([WifiEntry("WLAN", False, None)], readable=True)  # Widerspruch: Route über WLAN
    r = guard.check(make_adapter())
    assert (r.decision, r.code) == ("allow", "ok_home")
    assert r.ssid_readable is False and "meldet aber keine WLAN-Verbindung" in r.reason


def test_ethernet_only_without_wlan_is_readable(guard: NetworkGuard, fake: FlakyPlatform) -> None:
    guard.remember_home(HOME_GW_MAC)
    fake.wifi = WifiStatus([], readable=True)  # z. B. „keine Drahtlosschnittstelle“
    fake.details.pop("WLAN")
    fake.ifaces = [i for i in fake.ifaces if i.name != "WLAN"]
    fake.gateways.pop("WLAN")
    r = guard.check(make_adapter())
    assert (r.decision, r.code, r.ssid_readable, r.ssid) == ("allow", "ok_home", True, None)


# --- Einstellungen -------------------------------------------------------------------------


def test_extra_blocked_names_from_settings(guard: NetworkGuard, fake: FlakyPlatform, store: SettingsStore) -> None:
    store.update(blocked_ssids_extra=["Schule Gast"])
    guard.remember_home(HOME_GW_MAC)
    join_hotspot(fake, ssid="Schule Gast")
    r = guard.check(make_adapter())
    assert (r.decision, r.code) == ("block", "blocked_ssid") and r.ssid == "Schule Gast"
    join_hotspot(fake, ssid="schule gast")
    assert guard.check(make_adapter()).decision != "block"


def test_permanent_name_cannot_be_removed_or_overridden(
    guard: NetworkGuard, fake: FlakyPlatform, store: SettingsStore
) -> None:
    assert HOTSPOT_SSID in PERMANENT_BLOCKED_SSIDS
    store.update(blocked_ssids_extra=[], home_gateway_macs=[HOTSPOT_GW_MAC, HOME_GW_MAC])
    join_hotspot(fake)
    assert guard.check(wlan_hotspot()).code == "blocked_ssid"
    fake.wifi_unreadable()
    assert guard.check(wlan_hotspot()).code == "blocked_gateway"  # gesperrt schlägt Heimnetz


def test_check_has_no_override_parameter() -> None:
    assert list(inspect.signature(NetworkGuard.check).parameters) == ["self", "adapter"]


def test_learned_mac_is_stored_once(guard: NetworkGuard, fake: FlakyPlatform, store: SettingsStore) -> None:
    join_hotspot(fake)
    for _ in range(3):
        guard.check(make_adapter())
    assert store.load().blocked_gateway_macs == [HOTSPOT_GW_MAC]


def test_stale_gateway_outside_wlan_subnet_is_not_learned(
    guard: NetworkGuard, fake: FlakyPlatform, store: SettingsStore
) -> None:
    fake.connect_wifi(HOTSPOT_SSID)  # WLAN-Adresse noch 192.168.178.21/24 …
    fake.gateways["WLAN"] = "10.9.9.1"  # … aber Route eines anderen Netzes
    fake.neighbors["10.9.9.1"] = "02:00:00:00:09:01"
    assert guard.check(make_adapter()).code == "blocked_ssid"
    assert store.load().blocked_gateway_macs == []


def test_hotspot_without_gateway_mac_still_blocks(guard: NetworkGuard, fake: FlakyPlatform, store: SettingsStore) -> None:
    join_hotspot(fake)
    del fake.neighbors[HOTSPOT_GW_IP]
    r = guard.check(make_adapter())
    assert r.code == "blocked_ssid" and r.gateway_mac is None
    assert store.load().blocked_gateway_macs == []


# --- Plattformfehler: nie allow --------------------------------------------------------------


@pytest.mark.parametrize(
    "failing, unreadable",
    [
        ({"wifi_status"}, False),
        ({"default_gateway"}, False),
        ({"neighbor_mac"}, False),
        ({"adapter_details"}, False),
        ({"adapter_details"}, True),
        ({"adapter_details", "interfaces"}, True),
        ({"wifi_status", "default_gateway", "neighbor_mac", "adapter_details", "interfaces"}, False),
    ],
)
def test_platform_errors_never_allow(
    guard: NetworkGuard, fake: FlakyPlatform, failing: set[str], unreadable: bool
) -> None:
    guard.remember_home(HOME_GW_MAC)
    if unreadable:
        fake.wifi_unreadable()  # nur dann werden die Adapterdetails gebraucht
    fake.fail |= failing
    for adapter in (wlan_home(), make_adapter(), None):
        r = guard.check(adapter)
        assert r.decision == "confirm", (failing, adapter, r)


def test_platform_errors_do_not_lift_block(guard: NetworkGuard, fake: FlakyPlatform) -> None:
    join_hotspot(fake)
    fake.fail |= {"default_gateway", "neighbor_mac", "adapter_details", "interfaces"}
    r = guard.check(make_adapter())
    assert (r.decision, r.code) == ("block", "blocked_ssid")


def test_wlan_gateway_mac_unknown_while_unreadable_is_a_doubt(guard: NetworkGuard, fake: FlakyPlatform) -> None:
    guard.remember_home(HOME_GW_MAC)
    join_hotspot(fake)
    del fake.neighbors[HOTSPOT_GW_IP]
    fake.wifi_unreadable()
    r = guard.check(make_adapter())  # Ethernet ist Heimnetz, WLAN-Router unbekannt
    assert r.decision == "confirm" and "unvollständig" in r.reason


class BrokenStore:
    def load(self):  # type: ignore[no-untyped-def]
        raise RuntimeError("Datenbank kaputt")

    def add_to_list(self, key, value):  # type: ignore[no-untyped-def]
        raise RuntimeError("Datenbank kaputt")


def test_broken_settings_still_block_hotspot_and_never_allow(fake: FlakyPlatform) -> None:
    guard = NetworkGuard(fake, BrokenStore())  # type: ignore[arg-type]
    assert guard.check(make_adapter()).decision == "confirm"
    join_hotspot(fake)
    assert guard.check(make_adapter()).code == "blocked_ssid"


def test_internal_error_falls_back_to_block_or_confirm(
    guard: NetworkGuard, fake: FlakyPlatform, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard.remember_home(HOME_GW_MAC)

    def boom(adapter):  # type: ignore[no-untyped-def]
        raise ZeroDivisionError

    monkeypatch.setattr(guard, "_evaluate", boom)
    assert guard.check(make_adapter()).decision == "confirm"
    join_hotspot(fake)
    assert guard.check(make_adapter()).decision == "block"


# --- remember_home ----------------------------------------------------------------------------


def test_remember_home_normalizes_and_deduplicates(guard: NetworkGuard, store: SettingsStore) -> None:
    guard.remember_home("3C-A6-2F-00-00-01")
    guard.remember_home("3ca6.2f00.0001")
    guard.remember_home(HOME_GW_MAC)
    assert store.load().home_gateway_macs == [HOME_GW_MAC]


@pytest.mark.parametrize("bad", ["", "kein-mac", "3c:a6:2f:00:00", "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01", "00:00:00:00:00:00"])
def test_remember_home_rejects_invalid(guard: NetworkGuard, store: SettingsStore, bad: str) -> None:
    with pytest.raises(ValueError):
        guard.remember_home(bad)
    assert store.load().home_gateway_macs == []


def test_remember_home_rejects_blocked_router(guard: NetworkGuard, fake: FlakyPlatform, store: SettingsStore) -> None:
    join_hotspot(fake)
    guard.check(make_adapter())
    with pytest.raises(ValueError, match="gesperrten Netz"):
        guard.remember_home(HOTSPOT_GW_MAC.upper())
    assert store.load().home_gateway_macs == []


# --- sonstiges --------------------------------------------------------------------------------


def test_guard_result_is_json_serializable(guard: NetworkGuard, fake: FlakyPlatform) -> None:
    join_hotspot(fake)
    data = guard.check(make_adapter()).to_dict()
    assert json.loads(json.dumps(data, ensure_ascii=False))["code"] == "blocked_ssid"
    assert set(data) == {"decision", "code", "reason", "ssid", "ssid_readable", "gateway_ip", "gateway_mac"}


def test_guard_sends_nothing(guard: NetworkGuard, fake: FlakyPlatform) -> None:
    # FlakyPlatform.ping wirft – und der Netz-Riegel aus conftest sperrt Sockets ohnehin
    guard.remember_home(HOME_GW_MAC)
    for setup in (lambda: None, fake.wifi_unreadable, lambda: join_hotspot(fake)):
        setup()
        guard.check(make_adapter())
        guard.check(wlan_home())
    assert fake.ping_calls == []
