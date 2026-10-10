"""Adapterliste: physisch/virtuell, Sortierung, Suche, Hostliste (FakePlatform)."""

from __future__ import annotations

import pytest

from netscan.net.adapters import find_adapter, hosts_of, list_adapters
from netscan.platform.base import AdapterDetail, InterfaceAddr
from tests.fakes import FakePlatform, make_adapter


def test_default_list_shows_only_physical_adapters(fake_platform: FakePlatform) -> None:
    names = [a.name for a in list_adapters(fake_platform)]
    assert names == ["Ethernet", "WLAN"]  # kabelgebunden vor WLAN, ohne vEthernet und Loopback


def test_include_virtual_shows_virtual_last(fake_platform: FakePlatform) -> None:
    names = [a.name for a in list_adapters(fake_platform, include_virtual=True)]
    assert names == ["Ethernet", "WLAN", "vEthernet (WSL)"]


def test_adapter_fields(fake_platform: FakePlatform) -> None:
    eth, wlan = list_adapters(fake_platform)
    assert (eth.ipv4, eth.netmask, eth.network, eth.prefix) == ("192.168.178.20", "255.255.255.0", "192.168.178.0/24", 24)
    assert eth.description == "Intel(R) Ethernet Connection I219-V" and eth.mac == "00:1b:21:00:00:20"
    assert (eth.is_virtual, eth.is_wireless, eth.is_up) == (False, False, True)
    assert wlan.is_wireless is True and wlan.description.startswith("Intel(R) Wi-Fi")
    wsl = find_adapter(fake_platform, "vEthernet (WSL)")
    assert wsl is not None and wsl.is_virtual and wsl.network == "172.20.0.0/20" and wsl.prefix == 20


def test_loopback_and_link_local_are_never_listed(fake_platform: FakePlatform) -> None:
    fake_platform.ifaces.append(InterfaceAddr("Ethernet 2", "169.254.10.20", "255.255.0.0", "00:1b:21:00:00:22", False))
    fake_platform.ifaces.append(InterfaceAddr("Kaputt", "999.1.1.1", "255.255.255.0", None, True))
    fake_platform.ifaces.append(InterfaceAddr("Maske kaputt", "10.1.1.1", "255.0.255.0", None, True))
    names = [a.name for a in list_adapters(fake_platform, include_virtual=True)]
    assert "Loopback Pseudo-Interface 1" not in names and "Ethernet 2" not in names
    assert "Kaputt" not in names and "Maske kaputt" not in names
    assert find_adapter(fake_platform, "Loopback Pseudo-Interface 1") is None


def test_virtual_by_pattern_in_description_or_name(fake_platform: FakePlatform) -> None:
    fake_platform.ifaces += [
        InterfaceAddr("Ethernet 4", "192.168.56.1", "255.255.255.0", "0a:00:27:00:00:24", True),
        InterfaceAddr("Tailscale", "100.101.102.103", "255.192.0.0", None, True),
        InterfaceAddr("LAN 3", "10.20.30.40", "255.255.255.0", None, True),
    ]
    # Detail sagt „nicht virtuell“, die Beschreibung verrät es aber
    fake_platform.details["Ethernet 4"] = AdapterDetail("Ethernet 4", "VirtualBox Host-Only Ethernet Adapter", False, False, None)
    names = [a.name for a in list_adapters(fake_platform)]
    assert "Ethernet 4" not in names and "Tailscale" not in names
    assert "LAN 3" in names  # ohne Details und ohne Muster: physisch
    lan3 = find_adapter(fake_platform, "LAN 3")
    assert lan3 is not None and lan3.description == "" and lan3.is_virtual is False


def test_sorting_physical_wired_wireless_then_name(fake_platform: FakePlatform) -> None:
    fake_platform.ifaces += [
        InterfaceAddr("ethernet 3", "10.0.3.2", "255.255.255.0", None, True),
        InterfaceAddr("Aaa-WLAN", "10.0.4.2", "255.255.255.0", None, True),
        InterfaceAddr("Aaa VPN", "10.0.5.2", "255.255.255.0", None, True),
    ]
    fake_platform.details["Aaa-WLAN"] = AdapterDetail("Aaa-WLAN", "USB-Stick", False, True, None)
    names = [a.name for a in list_adapters(fake_platform, include_virtual=True)]
    assert names == ["Ethernet", "ethernet 3", "Aaa-WLAN", "WLAN", "Aaa VPN", "vEthernet (WSL)"]


def test_first_ipv4_per_adapter_name_wins(fake_platform: FakePlatform) -> None:
    fake_platform.ifaces.insert(1, InterfaceAddr("Ethernet", "10.99.0.5", "255.255.255.0", None, True))
    adapters = [a for a in list_adapters(fake_platform) if a.name == "Ethernet"]
    assert [a.ipv4 for a in adapters] == ["192.168.178.20"]


def test_missing_details_or_broken_platform(fake_platform: FakePlatform, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom() -> dict[str, AdapterDetail]:
        raise RuntimeError("Get-NetAdapter kaputt")

    monkeypatch.setattr(fake_platform, "adapter_details", boom)
    adapters = list_adapters(fake_platform)
    assert [a.name for a in adapters] == ["Ethernet", "WLAN"]  # „vethernet“ im Namen genügt fürs Ausblenden
    assert all(a.description == "" and a.is_wireless is False for a in adapters)

    def broken() -> list[InterfaceAddr]:
        raise OSError("psutil kaputt")

    monkeypatch.setattr(fake_platform, "interfaces", broken)
    assert list_adapters(fake_platform) == [] and find_adapter(fake_platform, "Ethernet") is None


def test_find_adapter(fake_platform: FakePlatform) -> None:
    assert find_adapter(fake_platform, "WLAN") is not None
    assert find_adapter(fake_platform, "wlan") is None  # exakter Name
    assert find_adapter(fake_platform, "Gibt es nicht") is None


def test_mac_from_details_when_psutil_has_none(fake_platform: FakePlatform) -> None:
    fake_platform.ifaces[0] = InterfaceAddr("Ethernet", "192.168.178.20", "255.255.255.0", None, True)
    eth = find_adapter(fake_platform, "Ethernet")
    assert eth is not None and eth.mac == "00:1b:21:00:00:20"


# --- hosts_of -----------------------------------------------------------------------------


def test_hosts_of_24_without_own_address() -> None:
    hosts = hosts_of(make_adapter())
    assert len(hosts) == 253
    assert hosts[0] == "192.168.178.1" and hosts[-1] == "192.168.178.254"
    assert "192.168.178.20" not in hosts and "192.168.178.0" not in hosts and "192.168.178.255" not in hosts


@pytest.mark.parametrize("network, count", [("10.0.0.0/22", 1021), ("10.0.0.0/23", 509), ("10.0.0.0/30", 1), ("10.0.0.0/32", 0)])
def test_hosts_of_sizes(network: str, count: int) -> None:
    own = "10.0.0.2" if not network.endswith("/32") else "10.0.0.0"
    assert len(hosts_of(make_adapter(ipv4=own, network=network))) == count


@pytest.mark.parametrize("network", ["10.0.0.0/21", "10.0.0.0/16", "10.0.0.0/8"])
def test_hosts_of_rejects_too_large_networks(network: str) -> None:
    with pytest.raises(ValueError, match="zu groß"):
        hosts_of(make_adapter(ipv4="10.0.0.2", network=network))
