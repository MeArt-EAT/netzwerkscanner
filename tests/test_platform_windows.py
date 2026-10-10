"""WindowsPlatform: Parser mit Beispielausgaben (deutsch und englisch, anonymisiert) und Befehlsaufrufe
mit Attrappe. Läuft auf jedem System; echte Befehle nur unter Windows (ping nur 127.0.0.1)."""

from __future__ import annotations

import re
import sys

import pytest

from netscan.core.models import PingResult
from netscan.platform import windows
from netscan.platform.base import InterfaceAddr, WifiStatus
from netscan.platform.windows import (
    PERMISSION_ERROR,
    WindowsPlatform,
    _decode,
    _parse_adapters,
    _parse_arp,
    _parse_netsh_interfaces,
    _parse_ping,
    _parse_route_print,
    _parse_routes,
    _Result,
    _Route,
)

# --- netsh wlan show interfaces ------------------------------------------------------------

NETSH_DE_CONNECTED = """
Es ist 1 Schnittstelle auf dem System vorhanden:

    Name                   : WLAN
    Beschreibung           : Intel(R) Wi-Fi 6 AX201 160MHz
    GUID                   : 00000000-0000-0000-0000-000000000001
    Physische Adresse      : 02:00:00:00:00:01
    Schnittstellentyp      : Primär
    Status                 : Verbunden
    SSID                   : DE22LA000256314 8159
    AP BSSID               : 02:00:00:00:00:02
    Band                   : 5 GHz
    Kanal                  : 36
    Netzwerktyp            : Infrastruktur
    Funktyp                : 802.11ax
    Authentifizierung      : WPA2-Personal
    Verschlüsselung        : CCMP
    Verbindungsmodus       : Automat. Verbindung
    Empfangsrate (MBit/s)  : 1201
    Übertragungsrate (MBit/s) : 1201
    Signal                 : 92%
    Profil                 : DE22LA000256314 8159
    QoS MSCS konfiguriert         : 0

    Gehosteter Netzwerkstatus  : Nicht verfügbar
"""

NETSH_EN_CONNECTED = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    GUID                   : 00000000-0000-0000-0000-000000000001
    Physical address       : 02:00:00:00:00:01
    State                  : connected
    SSID                   : Heimnetz: 5 GHz
    BSSID                  : 02:00:00:00:00:02
    Network type           : Infrastructure
    Radio type             : 802.11ac
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Connection mode        : Auto Connect
    Channel                : 36
    Receive rate (Mbps)    : 866.7
    Transmit rate (Mbps)   : 866.7
    Signal                 : 99%
    Profile                : Heimnetz: 5 GHz

    Hosted network status  : Not available
"""

NETSH_DE_TWO = """
Es sind 2 Schnittstellen auf dem System vorhanden:

    Name                   : WLAN
    Beschreibung           : Intel(R) Wi-Fi 6 AX201 160MHz
    Status                 : Verbunden
    SSID                   : Café Müller
    AP BSSID               : 02:00:00:00:00:02
    Profil                 : Café Müller

    Name                   : WLAN 2
    Beschreibung           : USB-WLAN-Stick
    Status                 : Getrennt
    Funkstatus             : Hardware Ein
                             Software Ein

    Gehosteter Netzwerkstatus  : Nicht verfügbar
"""

NETSH_EN_DISCONNECTED = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    State                  : disconnected
    Radio status           : Hardware On
                             Software On

    Hosted network status  : Not available
"""

# Windows 11 24H2 ohne Standortberechtigung (echte Ausgabe dieses PCs, gekürzt)
NETSH_DE_PERMISSION_24H2 = """
Es ist 1 Schnittstelle auf dem System vorhanden:
Netzwerkshellbefehle benötigen Standortberechtigungen für den Zugriff auf WLAN-Informationen. Aktivieren Sie „Positionsdienste“ auf der Seite „Standort“ in den Datenschutz- und Sicherheitseinstellungen.
Hier ist der URI für die Seite „Standort“ in der App „Einstellungen“: ms-settings:privacy-location

Die Funktion WlanQueryInterface gibt den Fehler 5 zurück:
Für den angeforderten Vorgang sind erhöhte Rechte erforderlich (Als Administrator ausführen).
"""
NETSH_DE_PERMISSION_OTHER = (
    "Für Netzwerkshell-Befehle ist eine Standortberechtigung erforderlich, um auf WLAN-Informationen zuzugreifen."
)
NETSH_EN_PERMISSION = """
Network shell commands need location permission to access WLAN information. Turn on Location services on the Location page in Privacy & security settings.

Here is the URI for the Location page in the Settings app: ms-settings:privacy-location
"""
NETSH_DE_NO_WIFI = "Es ist keine Drahtlosschnittstelle auf dem System vorhanden.\n"
NETSH_EN_NO_WIFI = "There is no wireless interface on the system.\n"
NETSH_DE_SERVICE = 'Der Dienst "Automatische WLAN-Konfiguration" (wlansvc) wird nicht ausgeführt.\n'
NETSH_EN_SERVICE = "The Wireless AutoConfig Service (wlansvc) is not running.\n"


def test_netsh_german_connected() -> None:
    st = _parse_netsh_interfaces(NETSH_DE_CONNECTED)
    assert st.readable is True and st.error is None
    assert [(e.interface, e.connected, e.ssid) for e in st.entries] == [("WLAN", True, "DE22LA000256314 8159")]


def test_netsh_english_connected_ssid_with_colon_not_bssid() -> None:
    st = _parse_netsh_interfaces(NETSH_EN_CONNECTED)
    assert [(e.interface, e.connected, e.ssid) for e in st.entries] == [("Wi-Fi", True, "Heimnetz: 5 GHz")]


def test_netsh_two_interfaces_umlauts_and_hosted_status_ignored() -> None:
    st = _parse_netsh_interfaces(NETSH_DE_TWO)
    assert st.readable is True
    assert [(e.interface, e.connected, e.ssid) for e in st.entries] == [
        ("WLAN", True, "Café Müller"),
        ("WLAN 2", False, None),
    ]
    assert [e.interface for e in st.connected] == ["WLAN"]


def test_netsh_disconnected() -> None:
    st = _parse_netsh_interfaces(NETSH_EN_DISCONNECTED)
    assert st.readable is True
    assert [(e.interface, e.connected, e.ssid) for e in st.entries] == [("Wi-Fi", False, None)]


@pytest.mark.parametrize("text", [NETSH_DE_PERMISSION_24H2, NETSH_DE_PERMISSION_OTHER, NETSH_EN_PERMISSION])
def test_netsh_location_permission_missing_is_unreadable(text: str) -> None:
    st = _parse_netsh_interfaces(text)
    assert st.readable is False and st.entries == [] and st.error == PERMISSION_ERROR


@pytest.mark.parametrize("text", [NETSH_DE_NO_WIFI, NETSH_EN_NO_WIFI, NETSH_DE_SERVICE, NETSH_EN_SERVICE])
def test_netsh_no_wireless_or_service_stopped_is_readable_without_entries(text: str) -> None:
    st = _parse_netsh_interfaces(text)
    assert st.readable is True and st.entries == []


@pytest.mark.parametrize("text", ["", "\n\n", "Irgendwas Unerwartetes ist passiert.", "Es ist 1 Schnittstelle auf dem System vorhanden:\n"])
def test_netsh_unknown_output_is_unreadable(text: str) -> None:
    st = _parse_netsh_interfaces(text)
    assert st.readable is False and st.entries == [] and st.error


def test_netsh_connected_without_ssid_line_or_empty_ssid() -> None:
    only_bssid = "    Name : WLAN\n    Status : Verbunden\n    AP BSSID : 02:00:00:00:00:02\n"
    empty_ssid = "    Name : WLAN\n    Status : Verbunden\n    SSID :\n"
    for text in (only_bssid, empty_ssid):
        st = _parse_netsh_interfaces(text)
        assert [(e.interface, e.connected, e.ssid) for e in st.entries] == [("WLAN", True, None)]


def test_netsh_unknown_state_word_with_ssid_counts_as_connected() -> None:
    text = "    Nom : x\n    Name : Wi-Fi\n    State : connecté\n    SSID : DE22LA000256314 8159\n"
    st = _parse_netsh_interfaces(text)
    assert [(e.connected, e.ssid) for e in st.entries] == [(True, "DE22LA000256314 8159")]


def test_netsh_trailing_whitespace_is_stripped() -> None:
    st = _parse_netsh_interfaces("    Name : WLAN\r\n    Status : Verbunden\r\n    SSID : DE22LA000256314 8159   \r\n")
    assert st.entries[0].ssid == "DE22LA000256314 8159"


def test_decode_utf8_oem_and_bom() -> None:
    assert _decode("Übertragungsrate".encode("utf-8")) == "Übertragungsrate"  # netsh unter 24H2
    assert _decode("Zeitüberschreitung der Anforderung.".encode("cp850")) == "Zeitüberschreitung der Anforderung."
    assert _decode(b"\xef\xbb\xbf[1]") == "[1]"
    assert _decode(b"") == "" and _decode(None) == ""


# --- ping -----------------------------------------------------------------------------------

PING_DE_OK = """
Ping wird ausgeführt für 127.0.0.1 mit 32 Bytes Daten:
Antwort von 127.0.0.1: Bytes=32 Zeit<1ms TTL=128

Ping-Statistik für 127.0.0.1:
    Pakete: Gesendet = 1, Empfangen = 1, Verloren = 0
    (0% Verlust),
Ca. Zeitangaben in Millisek.:
    Minimum = 0ms, Maximum = 0ms, Mittelwert = 0ms
"""
PING_DE_SLOW = "Antwort von 192.168.178.1: Bytes=32 Zeit=12ms TTL=64\n"
PING_EN_OK = """
Pinging 192.168.178.1 with 32 bytes of data:
Reply from 192.168.178.1: bytes=32 time=3ms TTL=64

Ping statistics for 192.168.178.1:
    Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),
"""
PING_DE_UNREACHABLE = """
Ping wird ausgeführt für 192.168.178.99 mit 32 Bytes Daten:
Antwort von 192.168.178.20: Zielhost nicht erreichbar.

Ping-Statistik für 192.168.178.99:
    Pakete: Gesendet = 1, Empfangen = 1, Verloren = 0
"""
PING_DE_TIMEOUT = "Ping wird ausgeführt für 192.168.178.98 mit 32 Bytes Daten:\nZeitüberschreitung der Anforderung.\n"
PING_EN_TTL_EXPIRED = "Reply from 10.0.0.1: TTL expired in transit.\n"


@pytest.mark.parametrize(
    "text, expected",
    [
        (PING_DE_OK, PingResult(True, 0.5, 128)),
        (PING_DE_SLOW, PingResult(True, 12.0, 64)),
        (PING_EN_OK, PingResult(True, 3.0, 64)),
        (PING_DE_UNREACHABLE, PingResult(False)),
        (PING_DE_TIMEOUT, PingResult(False)),
        (PING_EN_TTL_EXPIRED, PingResult(False)),
        ("", PingResult(False)),
    ],
)
def test_parse_ping(text: str, expected: PingResult) -> None:
    assert _parse_ping(text) == expected


# --- arp -a ---------------------------------------------------------------------------------

ARP_DE = """
Schnittstelle: 192.168.178.20 --- 0x28
  Internetadresse       Physische Adresse     Typ
  192.168.178.1         3c-a6-2f-00-00-01     dynamisch
  192.168.178.33        02-00-00-00-00-33     dynamisch
  192.168.178.255       ff-ff-ff-ff-ff-ff     statisch
  224.0.0.22            01-00-5e-00-00-16     statisch
  239.255.255.250       01-00-5e-7f-ff-fa     statisch
  255.255.255.255       ff-ff-ff-ff-ff-ff     statisch

Schnittstelle: 172.20.0.1 --- 0xd
  Internetadresse       Physische Adresse     Typ
  172.20.0.5            00-00-00-00-00-00     ungültig
  192.168.178.33        02-00-00-00-00-99     statisch
"""
ARP_EN = """
Interface: 192.168.178.21 --- 0x10
  Internet Address      Physical Address      Type
  192.168.178.1         3c-a6-2f-00-00-01     dynamic
  192.168.178.40        02-00-00-00-00-40     static
"""


def test_parse_arp_german_filters_broadcast_and_multicast() -> None:
    assert _parse_arp(ARP_DE) == {"192.168.178.1": "3c:a6:2f:00:00:01", "192.168.178.33": "02:00:00:00:00:33"}


def test_parse_arp_english_and_dynamic_preferred() -> None:
    assert _parse_arp(ARP_EN) == {"192.168.178.1": "3c:a6:2f:00:00:01", "192.168.178.40": "02:00:00:00:00:40"}
    text = "  10.0.0.1   02-00-00-00-00-01   statisch\n  10.0.0.1   02-00-00-00-00-02   dynamisch\n"
    assert _parse_arp(text) == {"10.0.0.1": "02:00:00:00:00:02"}


def test_parse_arp_garbage() -> None:
    assert _parse_arp("") == {} and _parse_arp("Keine ARP-Einträge gefunden.") == {}


# --- Routen ---------------------------------------------------------------------------------

ROUTES_JSON_LIST = (
    '[{"InterfaceAlias":"WLAN","InterfaceIndex":40,"NextHop":"192.168.178.1","RouteMetric":0,"InterfaceMetric":35},'
    '{"InterfaceAlias":"Ethernet","InterfaceIndex":12,"NextHop":"192.168.178.1","RouteMetric":0,"InterfaceMetric":25},'
    '{"InterfaceAlias":"VPN","InterfaceIndex":50,"NextHop":"0.0.0.0","RouteMetric":0,"InterfaceMetric":1}]'
)
ROUTES_JSON_SINGLE = '{"InterfaceAlias":"WLAN","InterfaceIndex":40,"NextHop":"172.20.10.1","RouteMetric":0,"InterfaceMetric":35}'

ROUTE_PRINT_DE = """
===========================================================================
IPv4-Routentabelle
===========================================================================
Aktive Routen:
     Netzwerkziel    Netzwerkmaske          Gateway    Schnittstelle Metrik
          0.0.0.0          0.0.0.0    192.168.178.1   192.168.178.21     35
          0.0.0.0          0.0.0.0    192.168.178.1   192.168.178.20     25
        127.0.0.0        255.0.0.0   Auf Verbindung         127.0.0.1    331
    192.168.178.0    255.255.255.0   Auf Verbindung    192.168.178.20    281
===========================================================================
Ständige Routen:
  Netzwerkadresse          Netzmaske  Gatewayadresse  Metrik
          0.0.0.0          0.0.0.0        10.0.0.1  Standard
"""
ROUTE_PRINT_EN = """
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0     172.20.10.1      172.20.10.2     50
          0.0.0.0          0.0.0.0          On-link       10.8.0.2       5
Persistent Routes:
  None
"""


def test_parse_routes_list_ignores_onlink_and_sorts_by_metric() -> None:
    assert _parse_routes(ROUTES_JSON_LIST) == [
        _Route("Ethernet", "192.168.178.1", 25),
        _Route("WLAN", "192.168.178.1", 35),
    ]


def test_parse_routes_single_object_and_garbage() -> None:
    assert _parse_routes(ROUTES_JSON_SINGLE) == [_Route("WLAN", "172.20.10.1", 35)]
    assert _parse_routes("") == [] and _parse_routes("Fehler: kein JSON") == [] and _parse_routes("null") == []


def test_parse_route_print() -> None:
    assert _parse_route_print(ROUTE_PRINT_DE) == [
        ("192.168.178.20", "192.168.178.1", 25),
        ("192.168.178.21", "192.168.178.1", 35),
    ]
    assert _parse_route_print(ROUTE_PRINT_EN) == [("172.20.10.2", "172.20.10.1", 50)]


# --- Get-NetAdapter -------------------------------------------------------------------------

ADAPTERS_JSON = (
    '[{"Name":"WLAN","InterfaceDescription":"Intel(R) Wi-Fi 6 AX201 160MHz","Virtual":false,'
    '"MacAddress":"A4-C3-61-00-00-21","PhysicalMediaType":"Native 802.11","NdisPhysicalMedium":9,"Status":"Up"},'
    '{"Name":"Ethernet","InterfaceDescription":"Intel(R) Ethernet Connection I219-V","Virtual":false,'
    '"MacAddress":"00-1B-21-00-00-20","PhysicalMediaType":"802.3","NdisPhysicalMedium":14,"Status":"Up"},'
    '{"Name":"Ethernet 4","InterfaceDescription":"VirtualBox Host-Only Ethernet Adapter","Virtual":true,'
    '"MacAddress":"0A-00-27-00-00-24","PhysicalMediaType":"802.3","NdisPhysicalMedium":14,"Status":"Up"},'
    '{"Name":"Mobilfunk","InterfaceDescription":"Qualcomm Snapdragon X55 5G","Virtual":false,'
    '"MacAddress":"","PhysicalMediaType":"Wireless WAN","NdisPhysicalMedium":8,"Status":"Disconnected"},'
    '{"Name":"WLAN 2","InterfaceDescription":"USB-WLAN-Stick","Virtual":false,'
    '"MacAddress":"02-00-00-00-00-02","PhysicalMediaType":"Wireless LAN","NdisPhysicalMedium":1,"Status":"Up"},'
    '{"Name":"Ethernet-Verbindung über USB","InterfaceDescription":"USB 2.0","Virtual":"True",'
    '"MacAddress":null,"PhysicalMediaType":null,"NdisPhysicalMedium":null,"Status":"Up"}]'
)


def test_parse_adapters_list() -> None:
    d = _parse_adapters(ADAPTERS_JSON)
    assert list(d) == ["WLAN", "Ethernet", "Ethernet 4", "Mobilfunk", "WLAN 2", "Ethernet-Verbindung über USB"]
    assert (d["WLAN"].is_wireless, d["WLAN"].is_virtual, d["WLAN"].mac) == (True, False, "a4:c3:61:00:00:21")
    assert (d["Ethernet"].is_wireless, d["Ethernet"].is_virtual) == (False, False)
    assert d["Ethernet 4"].is_virtual is True and d["Ethernet 4"].description.startswith("VirtualBox")
    assert d["Mobilfunk"].is_wireless is False and d["Mobilfunk"].mac is None  # Mobilfunk ist kein WLAN
    assert d["WLAN 2"].is_wireless is True
    assert d["Ethernet-Verbindung über USB"].is_virtual is True and d["Ethernet-Verbindung über USB"].mac is None


def test_parse_adapters_single_object_and_garbage() -> None:
    single = '{"Name":"Ethernet","InterfaceDescription":"Realtek","Virtual":false,"MacAddress":"00-1B-21-00-00-20","PhysicalMediaType":"802.3","NdisPhysicalMedium":14}'
    assert list(_parse_adapters(single)) == ["Ethernet"]
    assert _parse_adapters("") == {} and _parse_adapters("<html>") == {} and _parse_adapters('[{"Name":""}]') == {}


# --- WindowsPlatform mit Befehls-Attrappe ---------------------------------------------------


class Runner:
    """Ersetzt windows._run: antwortet je Befehl mit vorgegebener Ausgabe (None = Befehl fehlt)."""

    def __init__(self, outputs: dict[str, str | tuple[int, str] | None]) -> None:
        self.outputs = outputs
        self.calls: list[tuple[list[str], float]] = []

    @staticmethod
    def key(args: list[str]) -> str:
        exe = re.split(r"[\\/]", args[0])[-1].lower().removesuffix(".exe")
        if exe == "powershell":
            return "Get-NetRoute" if "Get-NetRoute" in args[-1] else "Get-NetAdapter"
        return exe

    def count(self, key: str) -> int:
        return sum(1 for args, _ in self.calls if self.key(args) == key)

    def __call__(self, args: list[str], timeout: float) -> _Result | None:
        self.calls.append((list(args), timeout))
        value = self.outputs.get(self.key(args))
        if value is None:
            return None
        rc, out = value if isinstance(value, tuple) else (0, value)
        return _Result(rc, out, "")


@pytest.fixture
def runner(monkeypatch: pytest.MonkeyPatch) -> Runner:
    r = Runner(
        {
            "netsh": NETSH_DE_TWO,
            "Get-NetRoute": ROUTES_JSON_LIST,
            "Get-NetAdapter": ADAPTERS_JSON,
            "route": ROUTE_PRINT_DE,
            "arp": ARP_DE,
            "ping": PING_DE_OK,
        }
    )
    monkeypatch.setattr(windows, "_run", r)
    return r


@pytest.fixture
def plat(monkeypatch: pytest.MonkeyPatch) -> WindowsPlatform:
    p = WindowsPlatform()
    ifaces = [
        InterfaceAddr("Ethernet", "192.168.178.20", "255.255.255.0", "00:1b:21:00:00:20", True),
        InterfaceAddr("WLAN", "192.168.178.21", "255.255.255.0", "a4:c3:61:00:00:21", True),
    ]
    monkeypatch.setattr(p, "interfaces", lambda: list(ifaces))
    return p


def test_default_gateway_per_adapter_and_smallest_metric(runner: Runner, plat: WindowsPlatform) -> None:
    assert plat.default_gateway("WLAN") == "192.168.178.1"
    assert plat.default_gateway(None) == "192.168.178.1"
    assert plat.default_gateway("vEthernet (WSL)") is None  # nie das Gateway eines anderen Adapters
    assert plat.default_gateway("VPN") is None  # NextHop 0.0.0.0
    assert runner.count("Get-NetRoute") == 1 and runner.count("route") == 0  # zwischengespeichert


def test_default_gateway_falls_back_to_route_print(runner: Runner, plat: WindowsPlatform) -> None:
    runner.outputs["Get-NetRoute"] = None  # PowerShell fehlt oder hängt
    assert plat.default_gateway("Ethernet") == "192.168.178.1"
    assert plat.default_gateway(None) == "192.168.178.1"
    assert runner.count("route") == 1


def test_default_gateway_empty_powershell_result_uses_route_print(runner: Runner, plat: WindowsPlatform) -> None:
    runner.outputs["Get-NetRoute"] = ""
    runner.outputs["route"] = ROUTE_PRINT_EN
    plat.interfaces = lambda: [InterfaceAddr("WLAN", "172.20.10.2", "255.255.255.240", None, True)]  # type: ignore[method-assign]
    assert plat.default_gateway("WLAN") == "172.20.10.1"


def test_default_gateway_nothing_available(runner: Runner, plat: WindowsPlatform) -> None:
    runner.outputs["Get-NetRoute"] = None
    runner.outputs["route"] = None
    assert plat.default_gateway("WLAN") is None and plat.default_gateway() is None


def test_route_cache_expires_and_is_cleared_on_wifi_change(runner: Runner, plat: WindowsPlatform) -> None:
    plat.wifi_status()
    plat.default_gateway("WLAN")
    plat.default_gateway("WLAN")
    assert runner.count("Get-NetRoute") == 1
    plat.wifi_status()  # gleicher WLAN-Zustand: Zwischenspeicher bleibt
    plat.default_gateway("WLAN")
    assert runner.count("Get-NetRoute") == 1
    runner.outputs["netsh"] = NETSH_DE_CONNECTED  # Wechsel in ein anderes WLAN
    plat.wifi_status()
    plat.default_gateway("WLAN")
    assert runner.count("Get-NetRoute") == 2
    assert plat._routes_cache is not None
    plat._routes_cache = (plat._routes_cache[0] - 60, plat._routes_cache[1])  # abgelaufen
    plat.default_gateway("WLAN")
    assert runner.count("Get-NetRoute") == 3


def test_wifi_status_uses_netsh_and_handles_missing_command(runner: Runner, plat: WindowsPlatform) -> None:
    st = plat.wifi_status()
    assert [(e.interface, e.ssid) for e in st.connected] == [("WLAN", "Café Müller")]
    runner.outputs["netsh"] = (1, NETSH_DE_PERMISSION_24H2)
    assert plat.wifi_status().readable is False
    runner.outputs["netsh"] = None
    st = plat.wifi_status()
    assert isinstance(st, WifiStatus) and st.readable is False and st.error


def test_adapter_details_cached_and_failure_is_empty(runner: Runner, plat: WindowsPlatform) -> None:
    d = plat.adapter_details()
    assert d["WLAN"].is_wireless and plat.adapter_details() == d
    assert runner.count("Get-NetAdapter") == 1
    runner.outputs["Get-NetAdapter"] = None
    other = WindowsPlatform()
    assert other.adapter_details() == {}


def test_neighbor_table_and_mac(runner: Runner, plat: WindowsPlatform) -> None:
    assert plat.neighbor_table()["192.168.178.1"] == "3c:a6:2f:00:00:01"
    assert plat.neighbor_mac("192.168.178.1") == "3c:a6:2f:00:00:01"
    assert plat.neighbor_mac("192.168.178.250") is None
    before = len(runner.calls)
    assert plat.neighbor_mac("192.168.178.1 & del x") is None
    assert len(runner.calls) == before
    runner.outputs["arp"] = None
    assert plat.neighbor_table() == {}


def test_ping_builds_safe_command(runner: Runner, plat: WindowsPlatform) -> None:
    assert plat.ping("127.0.0.1", 800) == PingResult(True, 0.5, 128)
    args, timeout = runner.calls[-1]
    assert args[1:] == ["-n", "1", "-w", "800", "127.0.0.1"]
    assert timeout <= 0.8 + 2.0
    plat.ping("127.0.0.1", 60_000)  # höchstens 2 s je Netzoperation
    args, timeout = runner.calls[-1]
    assert args[4] == "2000" and timeout <= 2.0 + 2.0


@pytest.mark.parametrize(
    "bad", ["127.0.0.1 & calc", "127.0.0.1; rm -rf /", "-t 127.0.0.1", "localhost", "::1", "", "127.000.0.1", "224.0.0.1", "255.255.255.255"]
)
def test_ping_rejects_non_ipv4_literals(runner: Runner, plat: WindowsPlatform, bad: str) -> None:
    assert plat.ping(bad, 500) == PingResult(False)
    assert runner.count("ping") == 0


def test_ping_failure_and_missing_command(runner: Runner, plat: WindowsPlatform) -> None:
    runner.outputs["ping"] = PING_DE_UNREACHABLE
    assert plat.ping("127.0.0.2", 500).alive is False
    runner.outputs["ping"] = None
    assert plat.ping("127.0.0.2", 500).alive is False


def test_is_admin_returns_bool() -> None:
    assert isinstance(WindowsPlatform().is_admin(), bool)


# --- echte Befehle (nur Windows, nur lesend bzw. Ping auf 127.0.0.1) -----------------------

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="nur unter Windows")


@windows_only
def test_real_ping_loopback() -> None:
    r = WindowsPlatform().ping("127.0.0.1", 1000)
    assert r.alive is True and r.ttl is not None and r.rtt_ms is not None


@windows_only
def test_real_queries_do_not_crash() -> None:
    p = WindowsPlatform()
    assert isinstance(p.wifi_status(), WifiStatus)
    details = p.adapter_details()
    assert isinstance(details, dict)
    gw = p.default_gateway()
    assert gw is None or isinstance(gw, str)
    assert all(isinstance(k, str) and isinstance(v, str) for k, v in p.neighbor_table().items())
    assert isinstance(p.is_admin(), bool)
