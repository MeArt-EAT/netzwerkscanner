"""LinuxPlatform (Raspberry Pi später): Parser mit Beispieltexten und Befehlsaufrufe mit Attrappe.
Läuft auf jedem System; der echte Ping auf 127.0.0.1 nur unter Linux."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

from netscan.core.models import PingResult
from netscan.platform import linux
from netscan.platform.linux import (
    LinuxPlatform,
    _NmDevice,
    _parse_ip_neigh,
    _parse_ip_route,
    _parse_nmcli_devices,
    _parse_ping,
    _parse_proc_arp,
    _parse_proc_route,
    _read_sysfs_details,
    _Result,
    _Route,
    _split_terse,
)

NMCLI_DEVICES = "\n".join(
    [
        "eth0:ethernet:connected:Wired connection 1",
        r"wlan0:wifi:connected:Mein\:Profil",
        "p2p-dev-wlan0:wifi-p2p:disconnected:",
        "wlan1:wifi:unavailable:--",
        "lo:loopback:unmanaged:",
        "",
    ]
)

IP_ROUTE = """default via 192.168.178.1 dev wlan0 proto dhcp src 192.168.178.30 metric 600
default via 192.168.178.1 dev eth0 proto dhcp src 192.168.178.31 metric 100
default dev tun0 scope link
"""
IP_ROUTE_MULTIPATH = """default proto static metric 50
	nexthop via 10.0.0.1 dev eth1 weight 1
	nexthop via 10.0.1.1 dev eth2 weight 1
"""
PROC_ROUTE = """Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
wlan0	00000000	01B2A8C0	0003	0	0	600	00000000	0	0	0
wlan0	00B2A8C0	00000000	0001	0	0	600	00FFFFFF	0	0	0
eth0	00000000	010A14AC	0003	0	0	100	00000000	0	0	0
"""
IP_NEIGH = """192.168.178.1 dev wlan0 lladdr 3c:a6:2f:00:00:01 REACHABLE
192.168.178.40 dev wlan0 lladdr 02:00:00:00:00:40 STALE
192.168.178.41 dev wlan0  FAILED
192.168.178.42 dev wlan0 INCOMPLETE
192.168.178.255 dev wlan0 lladdr ff:ff:ff:ff:ff:ff PERMANENT
"""
PROC_ARP = """IP address       HW type     Flags       HW address            Mask     Device
192.168.178.1    0x1         0x2         3c:a6:2f:00:00:01     *        wlan0
192.168.178.41   0x1         0x0         00:00:00:00:00:00     *        wlan0
192.168.178.40   0x1         0x6         02:00:00:00:00:40     *        wlan0
"""
PING_IPUTILS_OK = """PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.045 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.045/0.045/0.045/0.000 ms
"""
PING_BUSYBOX_OK = "PING 127.0.0.1 (127.0.0.1): 56 data bytes\n64 bytes from 127.0.0.1: seq=0 ttl=64 time=0.081 ms\n"
PING_LOSS = """PING 192.168.178.99 (192.168.178.99) 56(84) bytes of data.

--- 192.168.178.99 ping statistics ---
1 packets transmitted, 0 received, 100% packet loss, time 0ms
"""
PING_UNREACHABLE = "From 192.168.178.30 icmp_seq=1 Destination Host Unreachable\n"


# --- Parser -----------------------------------------------------------------------------------


def test_split_terse_handles_escapes() -> None:
    assert _split_terse(r"wlan0:wifi:connected:Mein\:Netz\\x") == ["wlan0", "wifi", "connected", "Mein:Netz\\x"]
    assert _split_terse("a::b") == ["a", "", "b"]


def test_parse_nmcli_devices() -> None:
    devices = _parse_nmcli_devices(NMCLI_DEVICES)
    assert devices[1] == _NmDevice("wlan0", "wifi", "connected", "Mein:Profil")
    assert devices[2].connection is None and devices[3].connection is None
    assert [d.device for d in devices] == ["eth0", "wlan0", "p2p-dev-wlan0", "wlan1", "lo"]


def test_parse_ip_route() -> None:
    assert _parse_ip_route(IP_ROUTE) == [_Route("eth0", "192.168.178.1", 100), _Route("wlan0", "192.168.178.1", 600)]
    assert _parse_ip_route(IP_ROUTE_MULTIPATH) == [_Route("eth1", "10.0.0.1", 50), _Route("eth2", "10.0.1.1", 50)]
    assert _parse_ip_route("") == []


def test_parse_proc_route() -> None:
    assert _parse_proc_route(PROC_ROUTE) == [_Route("eth0", "172.20.10.1", 100), _Route("wlan0", "192.168.178.1", 600)]
    assert _parse_proc_route("Iface\tDestination\n") == []


def test_parse_ip_neigh_and_proc_arp() -> None:
    expected = {"192.168.178.1": "3c:a6:2f:00:00:01", "192.168.178.40": "02:00:00:00:00:40"}
    assert _parse_ip_neigh(IP_NEIGH) == expected
    assert _parse_proc_arp(PROC_ARP) == expected


@pytest.mark.parametrize(
    "text, expected",
    [
        (PING_IPUTILS_OK, PingResult(True, 0.045, 64)),
        (PING_BUSYBOX_OK, PingResult(True, 0.081, 64)),
        (PING_LOSS, PingResult(False)),
        (PING_UNREACHABLE, PingResult(False)),
        ("", PingResult(False)),
    ],
)
def test_parse_ping(text: str, expected: PingResult) -> None:
    assert _parse_ping(text) == expected


def make_sysfs(root: Path) -> Path:
    """Nachbau von /sys/class/net: eth0, wlan0 (physisch), docker0 und lo (virtuell)."""
    net = root / "net"
    for name, mac, driver, wireless in (
        ("eth0", "b8:27:eb:00:00:01", "bcmgenet", False),
        ("wlan0", "b8:27:eb:00:00:02", "brcmfmac", True),
        ("docker0", "02:42:00:00:00:01", None, False),
        ("lo", "00:00:00:00:00:00", None, False),
    ):
        d = net / name
        d.mkdir(parents=True)
        (d / "address").write_text(mac + "\n", encoding="utf-8")
        (d / "operstate").write_text("up\n", encoding="utf-8")
        if driver:
            (d / "device").mkdir()
            (d / "device" / "uevent").write_text(f"DRIVER={driver}\nPCI_ID=1\n", encoding="utf-8")
        if wireless:
            (d / "wireless").mkdir()
    return net


def test_read_sysfs_details(tmp_path: Path) -> None:
    d = _read_sysfs_details(make_sysfs(tmp_path))
    assert (d["eth0"].is_virtual, d["eth0"].is_wireless, d["eth0"].description) == (False, False, "bcmgenet")
    assert (d["wlan0"].is_virtual, d["wlan0"].is_wireless, d["wlan0"].mac) == (False, True, "b8:27:eb:00:00:02")
    assert d["docker0"].is_virtual is True and d["lo"].is_virtual is True and d["lo"].mac is None
    assert _read_sysfs_details(tmp_path / "fehlt") == {}


# --- LinuxPlatform mit Befehls-Attrappe -------------------------------------------------------


class Runner:
    """Ersetzt linux._run. Schlüssel: Befehlsname bzw. „iwgetid <dev>“; None = Befehl fehlt."""

    def __init__(self, outputs: dict[str, str | tuple[int, str] | None]) -> None:
        self.outputs = outputs
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str], timeout: float) -> _Result | None:
        self.calls.append(list(args))
        key = f"iwgetid {args[-1]}" if args[0] == "iwgetid" else " ".join(args[:2]) if args[0] == "ip" else args[0]
        if args[0] == "nmcli" and "connection" in args:
            key = "nmcli connection"
        if key not in self.outputs and args[0] == "iwgetid" and "iwgetid" in self.outputs:
            key = "iwgetid"
        value = self.outputs.get(key)
        if value is None:
            return None
        rc, out = value if isinstance(value, tuple) else (0, value)
        return _Result(rc, out, "")


@pytest.fixture
def sysfs(tmp_path: Path) -> Path:
    return make_sysfs(tmp_path)


def platform_with(monkeypatch: pytest.MonkeyPatch, sysfs: Path, outputs: dict, proc: Path | None = None) -> tuple[LinuxPlatform, Runner]:  # type: ignore[type-arg]
    runner = Runner(outputs)
    monkeypatch.setattr(linux, "_run", runner)
    return LinuxPlatform(sys_net=sysfs, proc_net=proc or sysfs.parent / "proc"), runner


def test_wifi_status_via_nmcli_and_iwgetid(monkeypatch: pytest.MonkeyPatch, sysfs: Path) -> None:
    plat, _ = platform_with(monkeypatch, sysfs, {"nmcli": NMCLI_DEVICES, "iwgetid wlan0": "DE22LA000256314 8159\n"})
    st = plat.wifi_status()
    assert st.readable is True
    assert [(e.interface, e.connected, e.ssid) for e in st.connected] == [("wlan0", True, "DE22LA000256314 8159")]
    assert ("wlan1", False, None) in [(e.interface, e.connected, e.ssid) for e in st.entries]


def test_wifi_ssid_falls_back_to_profile_ssid_not_profile_name(monkeypatch: pytest.MonkeyPatch, sysfs: Path) -> None:
    plat, runner = platform_with(
        monkeypatch, sysfs, {"nmcli": NMCLI_DEVICES, "iwgetid": None, "nmcli connection": "Heimnetz\n"}
    )
    assert plat.wifi_status().connected[0].ssid == "Heimnetz"
    assert ["nmcli", "-t", "-e", "no", "-g", "802-11-wireless.ssid", "connection", "show", "id", "Mein:Profil"] in runner.calls


def test_wifi_ssid_unknown_when_no_source(monkeypatch: pytest.MonkeyPatch, sysfs: Path) -> None:
    plat, _ = platform_with(monkeypatch, sysfs, {"nmcli": NMCLI_DEVICES, "iwgetid": None, "nmcli connection": None})
    st = plat.wifi_status()
    assert st.readable is True and st.connected[0].ssid is None  # Profilname ist keine SSID


def test_wifi_unmanaged_device_is_checked_with_iwgetid(monkeypatch: pytest.MonkeyPatch, sysfs: Path) -> None:
    nm = "eth0:ethernet:connected:Wired\nwlan0:wifi:unmanaged:\n"
    plat, _ = platform_with(monkeypatch, sysfs, {"nmcli": nm, "iwgetid wlan0": "DE22LA000256314 8159\n"})
    assert [(e.interface, e.ssid) for e in plat.wifi_status().connected] == [("wlan0", "DE22LA000256314 8159")]
    plat, _ = platform_with(monkeypatch, sysfs, {"nmcli": nm, "iwgetid": None})  # operstate up, Name unbekannt
    assert [(e.interface, e.connected, e.ssid) for e in plat.wifi_status().entries] == [("wlan0", True, None)]


def test_wifi_card_unknown_to_nmcli_is_checked(monkeypatch: pytest.MonkeyPatch, sysfs: Path) -> None:
    plat, _ = platform_with(monkeypatch, sysfs, {"nmcli": "eth0:ethernet:connected:Wired\n", "iwgetid wlan0": "Heimnetz\n"})
    assert [(e.interface, e.ssid) for e in plat.wifi_status().connected] == [("wlan0", "Heimnetz")]


def test_wifi_without_nmcli_uses_iwgetid(monkeypatch: pytest.MonkeyPatch, sysfs: Path) -> None:
    plat, _ = platform_with(monkeypatch, sysfs, {"nmcli": None, "iwgetid wlan0": "Heimnetz\n"})
    st = plat.wifi_status()
    assert st.readable is True and [(e.interface, e.ssid) for e in st.connected] == [("wlan0", "Heimnetz")]


def test_wifi_without_tools_is_unreadable(monkeypatch: pytest.MonkeyPatch, sysfs: Path) -> None:
    plat, _ = platform_with(monkeypatch, sysfs, {"nmcli": (8, "Error: NetworkManager is not running."), "iwgetid": None})
    st = plat.wifi_status()
    assert st.readable is False and st.error


def test_wifi_without_wireless_card_is_readable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    net = tmp_path / "net"
    (net / "eth0" / "device").mkdir(parents=True)
    plat, _ = platform_with(monkeypatch, net, {"nmcli": None, "iwgetid": None})
    st = plat.wifi_status()
    assert st.readable is True and st.entries == []


def test_default_gateway(monkeypatch: pytest.MonkeyPatch, sysfs: Path) -> None:
    plat, _ = platform_with(monkeypatch, sysfs, {"ip -4": IP_ROUTE})
    assert plat.default_gateway("wlan0") == "192.168.178.1"
    assert plat.default_gateway() == "192.168.178.1"
    assert plat.default_gateway("docker0") is None  # nie das Gateway eines anderen Adapters


def test_default_gateway_falls_back_to_proc(monkeypatch: pytest.MonkeyPatch, sysfs: Path, tmp_path: Path) -> None:
    proc = tmp_path / "proc"
    proc.mkdir()
    (proc / "route").write_text(PROC_ROUTE, encoding="utf-8")
    (proc / "arp").write_text(PROC_ARP, encoding="utf-8")
    plat, _ = platform_with(monkeypatch, sysfs, {}, proc=proc)
    assert plat.default_gateway() == "172.20.10.1"
    assert plat.default_gateway("wlan0") == "192.168.178.1"
    assert plat.neighbor_mac("192.168.178.1") == "3c:a6:2f:00:00:01"


def test_neighbor_table(monkeypatch: pytest.MonkeyPatch, sysfs: Path) -> None:
    plat, runner = platform_with(monkeypatch, sysfs, {"ip -4": IP_NEIGH})
    assert plat.neighbor_mac("192.168.178.40") == "02:00:00:00:00:40"
    assert plat.neighbor_mac("192.168.178.41") is None
    before = len(runner.calls)
    assert plat.neighbor_mac("$(reboot)") is None and len(runner.calls) == before


def test_ping_command(monkeypatch: pytest.MonkeyPatch, sysfs: Path) -> None:
    plat, runner = platform_with(monkeypatch, sysfs, {"ping": PING_IPUTILS_OK})
    assert plat.ping("127.0.0.1", 800) == PingResult(True, 0.045, 64)
    assert runner.calls[-1] == ["ping", "-n", "-c", "1", "-W", "1", "127.0.0.1"]  # -n: keine Namensauflösung
    plat.ping("127.0.0.1", 60_000)
    assert runner.calls[-1][5] == "2"
    for bad in ("127.0.0.1; reboot", "-f", "localhost", "::1", "224.0.0.1"):
        assert plat.ping(bad, 500) == PingResult(False)
    assert sum(1 for c in runner.calls if c[0] == "ping") == 2
    runner.outputs["ping"] = None
    assert plat.ping("127.0.0.1", 500).alive is False


def test_adapter_details_and_admin(sysfs: Path) -> None:
    plat = LinuxPlatform(sys_net=sysfs)
    assert plat.adapter_details()["wlan0"].is_wireless is True
    assert isinstance(plat.is_admin(), bool)


@pytest.mark.skipif(sys.platform != "linux" or shutil.which("ping") is None, reason="nur unter Linux mit ping")
def test_real_ping_loopback_linux() -> None:
    r = LinuxPlatform().ping("127.0.0.1", 1000)
    assert r.alive is True and r.ttl is not None
