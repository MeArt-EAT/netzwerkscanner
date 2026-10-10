"""Einordnung der Geräteart (classify) – reine Logik, kein Netzverkehr (außer SimLab auf 127.0.0.x)."""

from __future__ import annotations

import re
from typing import Any

import pytest

from netscan.core.models import CATEGORIES, Device, NameInfo, PortResult, SsdpInfo
from netscan.net import classify as classify_mod
from netscan.net import ports
from netscan.net.classify import apply_classification, classify
from netscan.net.ports import COMMON_PORTS, describe_port, scan_ports
from tests.fakes import FakeOui
from tests.sim import SimLab, standard_devices

# Herstellernamen so, wie sie in der IEEE-Liste stehen
AVM = "AVM Audiovisuelles Marketing und Computersysteme GmbH"
NETGEAR = "NETGEAR"
TPLINK = "TP-LINK TECHNOLOGIES CO.,LTD."
SYNOLOGY = "Synology Incorporated"
BROTHER = "Brother Industries, LTD."
INTEL = "Intel Corporate"
APPLE = "Apple, Inc."
ESPRESSIF = "Espressif Inc."
RASPI = "Raspberry Pi Trading Ltd"
XIAOMI = "Xiaomi Communications Co Ltd"
GOOGLE = "Google, Inc."
SAMSUNG = "Samsung Electronics Co.,Ltd"

IGD = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
TR064 = "urn:dslforum-org:device:InternetGatewayDevice:1"
RENDERER = "urn:schemas-upnp-org:device:MediaRenderer:1"


def is_random(mac: str) -> bool:
    """Bit „locally administered“ (eigene Hilfe – oui.is_random_mac gehört einem anderen Agenten)."""
    return bool(int(mac.split(":")[0], 16) & 0x02)


def port_result(port: int) -> PortResult:
    spec = describe_port(port)
    return PortResult(port=port, service=spec.service, risk=spec.risk, reason=spec.reason)


def make(
    *,
    ports: tuple[int, ...] | list[int] = (),
    vendor: str | None = None,
    mdns: tuple[str, ...] = (),
    ssdp: SsdpInfo | None = None,
    hostname: str | None = None,
    netbios: str | None = None,
    mac_random: bool = False,
    gateway: bool = False,
    self_: bool = False,
    mac: str = "00:00:5e:00:53:01",
    ip: str = "127.0.0.50",
    **extra: Any,
) -> Device:
    return Device(
        mac=mac,
        ip=ip,
        vendor=vendor,
        mac_random=mac_random,
        hostname=hostname,
        names=NameInfo(netbios=netbios, mdns_services=list(mdns)),
        ssdp=ssdp,
        ports=[port_result(p) for p in ports],
        is_gateway=gateway,
        is_self=self_,
        **extra,
    )


def assert_reason_ok(reason: str) -> None:
    assert reason and reason == reason.strip()
    assert len(reason) <= 160
    assert not re.search(r"\b(fuer|ueber|koennen|moeglich|oeffentlich)\b", reason.lower())


# --- Standardgeräte aus tests.sim ----------------------------------------------

EXPECTED_STANDARD = {
    "Router": "router",
    "NAS": "server",
    "Drucker": "printer",
    "PC": "pc",
    "Telnet-Gerät": "iot",
    "Handy (private MAC)": "phone",
}


def sim_to_device(sim: Any, oui: FakeOui, open_ports: list[PortResult] | None = None) -> Device:
    found = open_ports if open_ports is not None else [port_result(p) for p in sorted({*sim.tcp, *sim.http})]
    random_mac = is_random(sim.mac)
    return Device(
        mac=sim.mac,
        ip=sim.ip,
        vendor=None if random_mac else oui.lookup(sim.mac),
        mac_random=random_mac,
        ports=found,
        is_gateway=sim.label == "Router",
    )


def test_standard_devices() -> None:
    oui = FakeOui()
    for sim in standard_devices():
        device = sim_to_device(sim, oui)
        category, reason = classify(device)
        assert category == EXPECTED_STANDARD[sim.label], (sim.label, category, reason)
        assert_reason_ok(reason)


def test_standard_reasons_name_the_decisive_features() -> None:
    oui = FakeOui()
    by_label = {sim.label: classify(sim_to_device(sim, oui))[1] for sim in standard_devices()}
    assert by_label["Router"] == "Standard-Gateway des Netzes"
    assert "Synology" in by_label["NAS"]
    assert "631" in by_label["Drucker"] and "9100" in by_label["Drucker"]
    assert "Windows" in by_label["PC"] and "3389" in by_label["PC"]
    assert "Espressif" in by_label["Telnet-Gerät"]
    assert by_label["Handy (private MAC)"] == "private MAC-Adresse, keine Dienste – vermutlich Handy"


def test_simlab_scan_then_classify(make_ctx, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    """Ende-zu-Ende über 127.0.0.x: Port-Scan der simulierten Geräte, dann Einordnung."""
    # HTTPServer.server_bind ruft getfqdn → gethostbyaddr (im Test gesperrt); lokale Abhilfe, siehe Vertragsfragen
    monkeypatch.setattr(ports.socket, "getfqdn", lambda name="": name or "localhost")
    oui = FakeOui()
    with SimLab() as lab:
        monkeypatch.setattr(ports, "probe_port", lab.translating_probe(ports.probe_port))
        scanned = scan_ports(make_ctx(), {d.ip: list(COMMON_PORTS) for d in lab.devices})
    devices = [sim_to_device(sim, oui, scanned[sim.ip]) for sim in standard_devices()]
    apply_classification(devices)
    got = {sim.label: dev.category for sim, dev in zip(standard_devices(), devices)}
    assert got == EXPECTED_STANDARD
    assert all(dev.category_reason for dev in devices)


def test_router_by_upnp_igd_without_gateway_flag() -> None:
    assert classify(make(vendor=AVM, ports=(53, 80), ssdp=SsdpInfo(device_type=IGD)))[0] == "router"


# --- Randfälle -------------------------------------------------------------------

SWITCH = "Netzwerkgerät mit Verwaltungsoberfläche (Switch/Access Point/Repeater)"

CASES: list[tuple[str, dict[str, Any], str, str | None]] = [
    # Router
    ("avm_gateway", dict(vendor=AVM, ports=(53, 80), gateway=True), "router", "Standard-Gateway"),
    ("igd_ssdp", dict(ssdp=SsdpInfo(device_type=IGD)), "router", "Internet-Gateway"),
    # Switch / Netzwerkgerät
    ("netgear_switch_80", dict(vendor=NETGEAR, ports=(80,)), "switch", SWITCH),
    ("avm_repeater", dict(vendor=AVM, ports=(80, 443)), "switch", "Hersteller AVM"),
    ("avm_repeater_tr064", dict(vendor=AVM, ssdp=SsdpInfo(device_type=TR064)), "switch", SWITCH),
    ("tplink_ssh", dict(vendor=TPLINK, ports=(22,)), "switch", "TP-Link"),
    ("tplink_no_ports", dict(vendor=TPLINK), "unknown", None),
    ("hpe_switch", dict(vendor="Hewlett Packard Enterprise", ports=(22, 443)), "switch", "HPE/Aruba"),
    ("procurve", dict(vendor="ProCurve Networking by HP", ports=(23, 80)), "switch", SWITCH),
    # Drucker
    ("ipp_mdns", dict(mdns=("_ipp._tcp",)), "printer", "_ipp"),
    ("ipp_subtype", dict(mdns=("_universal._sub._ipp._tcp.local.",)), "printer", "_ipp"),
    ("ssdp_printer", dict(ssdp=SsdpInfo(device_type="urn:schemas-upnp-org:device:Printer:1")), "printer", "Drucker"),
    ("brother_web", dict(vendor=BROTHER, ports=(80,)), "printer", "Brother"),
    ("brother_no_ports", dict(vendor=BROTHER), "unknown", None),
    ("printer_hostname", dict(hostname="BRN001BA9AABBCC"), "printer", "Hostname"),
    ("jetdirect_only", dict(ports=(9100,)), "printer", "9100"),
    # NAS / Server
    ("synology_smb", dict(vendor=SYNOLOGY, ports=(445, 5000, 5001)), "server", "Synology"),
    ("synology_ssdp", dict(ssdp=SsdpInfo(manufacturer="Synology", model_name="DS920+",
                                         device_type="urn:schemas-upnp-org:device:Basic:1")), "server", "Synology"),
    ("dsm_ports", dict(ports=(5000, 5001)), "server", "DSM"),
    ("nas_hostname", dict(hostname="diskstation.fritz.box"), "server", "„diskstation“"),
    ("nas_hostname_ds", dict(hostname="DS220j"), "server", "„ds220j“"),
    ("nas_netbios", dict(netbios="NAS01"), "server", "„nas01“"),
    ("readynas", dict(vendor=NETGEAR, ports=(80, 443), hostname="ReadyNAS-214"), "server", "readynas"),
    ("samba_linux", dict(ports=(22, 445)), "server", "Dateifreigabe"),
    ("raspberry_samba", dict(vendor=RASPI, ports=(22, 139, 445)), "server", None),
    ("linux_server", dict(vendor="Super Micro Computer, Inc.", ports=(22, 80, 443)), "server", "Linux-/Allzweck-Server"),
    ("linux_server_db", dict(ports=(22, 5432)), "server", "5432"),
    ("database_only", dict(ports=(3306,)), "server", "Datenbank"),
    ("raspberry_ssh", dict(vendor=RASPI, ports=(22,)), "server", "Raspberry Pi mit SSH"),
    # PC
    ("self", dict(self_=True), "pc", "eigener PC"),
    ("self_tplink_stick", dict(vendor=TPLINK, ports=(80, 445), self_=True), "pc", "eigener PC"),
    ("windows_ports", dict(ports=(135, 445)), "pc", "Windows-Dienste"),
    ("windows_with_ssh", dict(ports=(22, 135, 445)), "pc", "Windows-Dienste"),
    ("workstation_mdns", dict(mdns=("_workstation._tcp", "_hap._tcp")), "pc", "_workstation"),
    ("intel_ssh", dict(vendor=INTEL, ports=(22,)), "pc", "PC-Hersteller Intel"),
    ("lenovo_odm", dict(vendor="LCFC(Hefei) Electronics Technology co., ltd", ports=(22,)), "pc", "Lenovo"),
    ("mac_airplay_port", dict(vendor=APPLE, ports=(5000,), mdns=("_airplay._tcp",)), "pc", "Apple"),
    ("windows_hostname_random_mac", dict(hostname="DESKTOP-AB12CD3", mac_random=True), "pc", "„desktop“"),
    # IoT
    ("espressif_telnet", dict(vendor=ESPRESSIF, ports=(23,)), "iot", "Espressif, Port 23"),
    ("camera", dict(vendor="Hangzhou Hikvision Digital Technology Co.,Ltd.", ports=(80, 554)), "iot", "Hikvision"),
    ("homekit_mdns", dict(mdns=("_hap._tcp",)), "iot", "_hap"),
    ("apple_tv", dict(vendor=APPLE, mdns=("_airplay._tcp", "_raop._tcp")), "iot", "_airplay"),
    ("xiaomi_with_service", dict(vendor=XIAOMI, ports=(80,)), "iot", "Xiaomi mit Diensten"),
    ("google_cast", dict(vendor=GOOGLE, ports=(8443,)), "iot", "Google"),
    ("samsung_tv", dict(vendor=SAMSUNG, ssdp=SsdpInfo(device_type=RENDERER)), "iot", "Samsung"),
    ("renderer_only", dict(ssdp=SsdpInfo(device_type=RENDERER)), "iot", "MediaRenderer"),
    ("raspberry_no_ssh", dict(vendor="Raspberry Pi Foundation"), "iot", "Raspberry Pi ohne SSH"),
    ("tasmota_hostname", dict(hostname="tasmota-3A2B1C-1234"), "iot", "„tasmota“"),
    # Handy
    ("random_mac", dict(mac_random=True), "phone", "private MAC-Adresse, keine Dienste – vermutlich Handy"),
    ("random_mac_passive_mdns", dict(mac_random=True, mdns=("_companion-link._tcp",)), "phone", "private MAC"),
    ("apple_no_services", dict(vendor=APPLE), "phone", "Hersteller Apple, keine Dienste"),
    ("apple_passive_mdns", dict(vendor=APPLE, mdns=("_companion-link._tcp", "_apple-mobdev2._tcp")), "phone", "Apple"),
    ("xiaomi_no_services", dict(vendor=XIAOMI), "phone", "Xiaomi"),
    ("google_pixel", dict(vendor=GOOGLE), "phone", "Google"),
    ("samsung_phone", dict(vendor=SAMSUNG), "phone", "Samsung"),
    ("motorola_lenovo", dict(vendor="Motorola Mobility LLC, a Lenovo Company"), "phone", "Motorola"),
    ("iphone_hostname", dict(hostname="Annas-iPhone.local"), "phone", "„iphone“"),
    # Unbekannt
    ("nothing", dict(), "unknown", "keine eindeutigen Merkmale"),
    ("random_mac_with_port", dict(mac_random=True, ports=(80,)), "unknown", None),
    ("random_mac_with_ssdp", dict(mac_random=True, ssdp=SsdpInfo(device_type="urn:schemas-upnp-org:device:MediaServer:1")),
     "unknown", None),
    ("fritz_domain_only", dict(hostname="box-wohnzimmer.fritz.box"), "unknown", None),
    ("apple_with_active_mdns", dict(vendor=APPLE, mdns=("_smb._tcp",)), "unknown", None),
]


@pytest.mark.parametrize(("kwargs", "expected", "fragment"), [c[1:] for c in CASES], ids=[c[0] for c in CASES])
def test_edge_cases(kwargs: dict[str, Any], expected: str, fragment: str | None) -> None:
    category, reason = classify(make(**kwargs))
    assert category == expected, reason
    assert category in CATEGORIES
    assert_reason_ok(reason)
    if fragment is not None:
        assert fragment in reason, reason


def test_unknown_reason_exact() -> None:
    assert classify(make()) == ("unknown", "keine eindeutigen Merkmale")


def test_switch_reason_names_management_ui() -> None:
    category, reason = classify(make(vendor=NETGEAR, ports=(80,)))
    assert category == "switch"
    assert reason.startswith("Netzwerkgerät mit Verwaltungsoberfläche (Switch/Access Point/Repeater)")
    assert "Netgear" in reason and "Port 80" in reason


def test_udp_ports_are_ignored() -> None:
    device = make()
    device.ports.append(PortResult(port=9100, proto="udp"))
    assert classify(device)[0] == "unknown"


def test_odd_input_does_not_crash() -> None:
    device = make(
        hostname="",
        mdns=("", "nonsense", "._tcp", "_IPP._TCP.LOCAL."),
        ssdp=SsdpInfo(device_type="kaputt:::", manufacturer="   ", model_name=None),
    )
    device.names.mdns_services.append(None)  # type: ignore[arg-type]
    category, reason = classify(device)
    assert category == "printer"  # _IPP (groß geschrieben) zählt trotzdem
    assert reason


# --- apply_classification -------------------------------------------------------


def test_apply_keeps_user_category() -> None:
    user = make(vendor=APPLE, category="server", category_source="user", category_reason="vom Nutzer gesetzt")
    auto = make(vendor=SYNOLOGY, ports=(5000,), category="pc", category_reason="alt")
    apply_classification([user, auto])
    assert (user.category, user.category_source, user.category_reason) == ("server", "user", "vom Nutzer gesetzt")
    assert (auto.category, auto.category_source) == ("server", "auto")
    assert "Synology" in auto.category_reason


def test_apply_replaces_stale_auto_category() -> None:
    stale = make(category="router", category_reason="früher Gateway")
    apply_classification([stale])
    assert (stale.category, stale.category_reason) == ("unknown", "keine eindeutigen Merkmale")


def test_apply_survives_classifier_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(device: Device) -> tuple[str, str]:
        raise RuntimeError("Fehler in der Regel")

    monkeypatch.setattr(classify_mod, "classify", broken)
    device = make(category="pc")
    apply_classification([device])
    assert device.category == "unknown"


def test_apply_empty_list() -> None:
    apply_classification([])


# --- Tabellen ----------------------------------------------------------------------


def test_vendor_tables_compile_and_hint_tables_cover_categories() -> None:
    tables = [
        classify_mod.PRINTER_VENDORS, classify_mod.NAS_VENDORS, classify_mod.NETWORK_VENDORS,
        classify_mod.PC_VENDORS, classify_mod.IOT_VENDORS, classify_mod.IOT_VENDORS_WITH_SERVICES,
        classify_mod.MEDIA_VENDORS, classify_mod.PHONE_VENDORS, classify_mod.RASPBERRY_VENDORS,
    ]
    for table in tables:
        for pattern, label in table:
            re.compile(pattern)
            assert label
    assert set(classify_mod.HOSTNAME_HINTS) == {"printer", "nas", "pc", "iot", "phone"}
    assert len(classify_mod.RULES) == 9  # 1–8 plus 6b (PC-Hersteller nach der Server-Regel)


@pytest.mark.parametrize(
    ("vendor", "table"),
    [
        ("Qingdao Intelligent&Precise Electronics Co.,Ltd.", "PC_VENDORS"),  # „intel“ nur als ganzes Wort
        ("Murata Manufacturing Co., Ltd.", "IOT_VENDORS"),  # „ring“ nicht mitten im Wort
        ("Digitron da Amazonia S/A", "IOT_VENDORS"),
        ("CARLO GAVAZZI CONTROLS SPA-Controls Division", "IOT_VENDORS"),
        ("Motorola Mobility LLC, a Lenovo Company", "PC_VENDORS"),  # Lenovo-Handys sind keine PCs
        ("Hewlett Packard Enterprise", "PC_VENDORS"),  # HPE ist Netzwerk, nicht PC
    ],
)
def test_vendor_keywords_do_not_overmatch(vendor: str, table: str) -> None:
    signals = classify_mod._signals(make(vendor=vendor))
    assert classify_mod._vendor(signals, getattr(classify_mod, table)) is None


def test_intel_mini_pc_with_ssh_and_web_is_server_not_pc() -> None:
    """Leitungsentscheidung: PC-Hersteller-Regel steht hinter der Server-Regel."""
    from netscan.core.models import Device, PortResult

    d = Device(mac="00:1b:21:aa:bb:01", ip="192.168.178.40", vendor="Intel Corporate",
               ports=[PortResult(22, service="ssh"), PortResult(80, service="http")])
    category, reason = classify_mod.classify(d)
    assert category == "server", reason
    d2 = Device(mac="00:1b:21:aa:bb:02", ip="192.168.178.41", vendor="Intel Corporate",
                ports=[PortResult(80, service="http")])
    assert classify_mod.classify(d2)[0] == "pc"
