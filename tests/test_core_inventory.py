"""Inventar und Einstellungen: Wiedererkennung über MAC, Nutzerfelder bleiben, „neu“-Logik."""

from __future__ import annotations

import pytest

from netscan.config import PERMANENT_BLOCKED_SSIDS
from netscan.core.models import Device, NameInfo, PortResult


def _scan(inv, devices):  # type: ignore[no-untyped-def]
    sid = inv.begin_scan("scan", "Ethernet", "192.168.178.0/24")
    for d in devices:
        inv.record_seen(d, sid)
    inv.finish_scan(sid, "completed", len(devices))
    return sid


def test_custom_name_survives_rescan(services) -> None:  # type: ignore[no-untyped-def]
    inv = services.inventory
    _scan(inv, [Device(mac="00:11:32:AA:BB:03", ip="192.168.178.30", vendor="Synology")])
    inv.update_user_fields("00:11:32:aa:bb:03", custom_name="NAS Keller", known=True, category="server", note="RAID 1")
    _scan(inv, [Device(mac="00-11-32-aa-bb-03", ip="192.168.178.31", vendor="Synology", category="pc", names=NameInfo(dns="ds"))])
    d = inv.get("00:11:32:aa:bb:03")
    assert d is not None
    assert d.custom_name == "NAS Keller" and d.known and d.note == "RAID 1"
    assert d.category == "server" and d.category_source == "user"
    assert d.ip == "192.168.178.31"  # automatische Felder werden aktualisiert
    assert d.names.dns == "ds"


def test_new_device_flag(services) -> None:  # type: ignore[no-untyped-def]
    inv = services.inventory
    _scan(inv, [Device(mac="00:00:00:00:00:01", ip="10.0.0.1")])
    assert inv.list_devices()[0].is_new  # erster Scan: alles neu (unbekannt)
    _scan(inv, [Device(mac="00:00:00:00:00:01", ip="10.0.0.1"), Device(mac="00:00:00:00:00:02", ip="10.0.0.2")])
    by_mac = {d.mac: d for d in inv.list_devices()}
    assert not by_mac["00:00:00:00:00:01"].is_new
    assert by_mac["00:00:00:00:00:02"].is_new
    inv.update_user_fields("00:00:00:00:00:02", known=True)
    assert not inv.get("00:00:00:00:00:02").is_new


def test_online_flag_and_reset_category(services) -> None:  # type: ignore[no-untyped-def]
    inv = services.inventory
    _scan(inv, [Device(mac="00:00:00:00:00:01", ip="10.0.0.1"), Device(mac="00:00:00:00:00:02", ip="10.0.0.2")])
    _scan(inv, [Device(mac="00:00:00:00:00:01", ip="10.0.0.1", category="router", category_reason="Gateway")])
    by_mac = {d.mac: d for d in inv.list_devices()}
    assert by_mac["00:00:00:00:00:01"].online and not by_mac["00:00:00:00:00:02"].online
    inv.update_user_fields("00:00:00:00:00:01", category="iot")
    inv.update_user_fields("00:00:00:00:00:01", category="auto")
    _scan(inv, [Device(mac="00:00:00:00:00:01", ip="10.0.0.1", category="router", category_reason="Gateway")])
    assert inv.get("00:00:00:00:00:01").category == "router"


def test_set_ports_only_deletes_scanned(services) -> None:  # type: ignore[no-untyped-def]
    inv = services.inventory
    _scan(inv, [Device(mac="00:00:00:00:00:01", ip="10.0.0.1")])
    mac = "00:00:00:00:00:01"
    new = inv.set_ports(mac, range(1, 1025), [PortResult(22, service="ssh"), PortResult(8080, service="http-alt")])
    assert {p.port for p in new} == {22, 8080}
    new = inv.set_ports(mac, [22, 80, 443], [PortResult(80, service="http")])  # 22 zu, 8080 nicht geprüft
    assert [p.port for p in new] == [80]
    assert sorted(p.port for p in inv.get(mac).ports) == [80, 8080]


def test_user_field_validation(services) -> None:  # type: ignore[no-untyped-def]
    inv = services.inventory
    _scan(inv, [Device(mac="00:00:00:00:00:01", ip="10.0.0.1")])
    with pytest.raises(KeyError):
        inv.update_user_fields("00:00:00:00:00:01", ip="1.2.3.4")
    with pytest.raises(ValueError):
        inv.update_user_fields("00:00:00:00:00:01", category="toaster")
    with pytest.raises(LookupError):
        inv.update_user_fields("00:00:00:00:00:99", known=True)


def test_log_retention_and_inventory_view(services) -> None:  # type: ignore[no-untyped-def]
    inv = services.inventory
    for i in range(55):
        sid = inv.begin_scan("scan", None, None)
        inv.add_log(sid, "info", f"scan {i}")
        inv.finish_scan(sid, "completed", 0)
    logs = inv.get_log(limit=1000)
    assert len(logs) == 50 and logs[-1]["message"] == "scan 54"
    _scan(inv, [Device(mac="00:00:00:00:00:01", ip="10.0.0.1", hostname="drucker")])
    assert inv.inventory_view() == [{"mac": "00:00:00:00:00:01", "ip": "10.0.0.1", "name": "drucker"}]


def test_settings_store(services) -> None:  # type: ignore[no-untyped-def]
    st = services.settings
    assert st.load().rate_pps == 200
    st.update(rate_pps=150, blocked_ssids_extra=["Gast"])
    st.add_to_list("home_gateway_macs", "3c:a6:2f:00:00:01")
    st.add_to_list("home_gateway_macs", "3c:a6:2f:00:00:01")
    s = st.load()
    assert s.rate_pps == 150 and s.home_gateway_macs == ["3c:a6:2f:00:00:01"]
    assert s.blocked_ssids() == set(PERMANENT_BLOCKED_SSIDS) | {"Gast"}
    with pytest.raises(ValueError):
        st.update(rate_pps=5000)
    with pytest.raises(KeyError):
        st.update(unbekannt=1)
