"""Regeltabelle der Ports: Dienst, Risiko, Begründung."""

from __future__ import annotations

import re

import pytest

from netscan.core.models import RISKS
from netscan.net import ports
from netscan.net.ports import BANNER_PORTS, COMMON_PORTS, DEEP_PORTS, PORT_TABLE, PortSpec, describe_port

EXPECTED: dict[int, tuple[str, str]] = {
    21: ("ftp", "high"), 22: ("ssh", "low"), 23: ("telnet", "high"), 25: ("smtp", "medium"),
    53: ("dns", "low"), 80: ("http", "medium"), 110: ("pop3", "medium"), 111: ("rpcbind", "medium"),
    135: ("msrpc", "medium"), 139: ("netbios-ssn", "high"), 143: ("imap", "medium"), 443: ("https", "low"),
    445: ("smb", "high"), 515: ("lpd", "low"), 548: ("afp", "medium"), 554: ("rtsp", "medium"),
    631: ("ipp", "low"), 873: ("rsync", "medium"), 1080: ("socks", "high"), 1883: ("mqtt", "medium"),
    2049: ("nfs", "medium"), 2375: ("docker", "critical"), 3306: ("mysql", "medium"), 3389: ("rdp", "medium"),
    5000: ("http", "medium"), 5001: ("https", "low"), 5432: ("postgresql", "medium"), 5555: ("adb", "critical"),
    5900: ("vnc", "high"), 6379: ("redis", "high"), 8080: ("http-alt", "medium"), 8443: ("https-alt", "low"),
    8883: ("mqtt-tls", "low"), 9100: ("jetdirect", "medium"), 27017: ("mongodb", "high"),
}

GERMAN_WORDS = re.compile(r"\b(und|oder|nicht|nur|ist|ohne|mit|über|für|im|wenn|sonst|auf)\b")
# typische Umschreibungen statt echter Umlaute (ä ö ü ß) – dürfen nicht vorkommen
TRANSLITERATIONS = re.compile(r"\b(fuer|ueber|koenn|muess|aender|oeffn|schuetz|unverschluess|haeufig|moeglich)")


def test_table_has_exactly_the_standard_ports() -> None:
    assert set(PORT_TABLE) == set(EXPECTED)
    assert len(PORT_TABLE) == 35
    assert COMMON_PORTS == sorted(PORT_TABLE)


def test_services_and_risks_follow_the_rule_table() -> None:
    for port, (service, risk) in EXPECTED.items():
        spec = PORT_TABLE[port]
        assert spec.port == port
        assert (spec.service, spec.risk) == (service, risk), port
        assert spec.risk in RISKS


def test_telnet_and_smb_are_high_with_remedy() -> None:
    # Pflichtenheft Stufe 3: offenes Telnet oder SMB ⇒ „hoch“ mit Abhilfehinweis
    assert PORT_TABLE[23].risk == "high"
    assert PORT_TABLE[445].risk == "high"
    assert PORT_TABLE[23].reason == "Telnet überträgt Anmeldung und Daten unverschlüsselt. Abschalten und SSH verwenden."
    assert "abschalten" in PORT_TABLE[445].reason.lower()


def test_no_industrial_ports() -> None:
    for port in (102, 502, 4840):
        assert port not in PORT_TABLE
        assert port not in COMMON_PORTS


@pytest.mark.parametrize("port", sorted(EXPECTED))
def test_reasons_are_german_with_why_and_remedy(port: int) -> None:
    reason = PORT_TABLE[port].reason
    assert reason and reason == reason.strip()
    assert reason.endswith(".")
    assert len(re.split(r"(?<=\.)\s+", reason)) >= 2, "Begründung und Abhilfe erwartet"
    assert GERMAN_WORDS.search(reason), reason
    assert not TRANSLITERATIONS.search(reason.lower()), reason


def test_describe_port_known_and_unknown() -> None:
    assert describe_port(22) is PORT_TABLE[22]
    assert describe_port(12345) == PortSpec(12345, "unbekannt", "low", "Dienst unbekannt – prüfen, ob der offene Port gewollt ist.")


def test_deep_and_banner_ports() -> None:
    assert DEEP_PORTS == range(1, 1025)
    assert BANNER_PORTS == frozenset({21, 22, 23, 25})
    assert BANNER_PORTS <= set(PORT_TABLE)
    assert ports.BANNER_TIMEOUT_S <= 0.8
    assert ports.MAX_TIMEOUT_S <= 2.0
