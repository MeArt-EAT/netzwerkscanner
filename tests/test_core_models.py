from __future__ import annotations

import pytest

from netscan.core.models import Device, NameInfo, PortResult, SsdpInfo, normalize_mac


@pytest.mark.parametrize(
    "raw",
    ["AA-BB-CC-DD-EE-FF", "aa:bb:cc:dd:ee:ff", "aabb.ccdd.eeff", "AABBCCDDEEFF", " aa:bb:cc:dd:ee:ff "],
)
def test_normalize_mac(raw: str) -> None:
    assert normalize_mac(raw) == "aa:bb:cc:dd:ee:ff"


@pytest.mark.parametrize("raw", ["", "aa:bb:cc", "zz:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff:00"])
def test_normalize_mac_rejects(raw: str) -> None:
    with pytest.raises(ValueError):
        normalize_mac(raw)


def test_device_roundtrip_and_display_name() -> None:
    d = Device(
        mac="00:11:32:aa:bb:03",
        ip="192.168.178.30",
        vendor="Synology Incorporated",
        names=NameInfo(netbios="DISKSTATION"),
        ssdp=SsdpInfo(friendly_name="DS920+"),
        ports=[PortResult(445, service="smb", risk="high"), PortResult(22, service="ssh", risk="low")],
    )
    assert d.display_name == "DISKSTATION" or d.hostname is None
    d.hostname = d.names.best()
    assert d.display_name == "DISKSTATION"
    d.custom_name = "NAS Keller"
    assert d.display_name == "NAS Keller"
    data = d.to_dict()
    assert data["max_risk"] == "high"
    assert data["category_label"] == "Unbekannt"
    assert [p["port"] for p in data["ports"]] == [22, 445]
    back = Device.from_dict(data)
    assert back.names.netbios == "DISKSTATION"
    assert back.ssdp and back.ssdp.friendly_name == "DS920+"
    assert back.ports[0].port == 22
