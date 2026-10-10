"""Die Netz-Sperre der Tests selbst prüfen: Nicht-Loopback muss scheitern, Loopback klappen."""

from __future__ import annotations

import socket
import subprocess

import pytest

from tests.conftest import LanTrafficError
from tests.sim import TcpService, free_port


def test_connect_to_lan_is_blocked() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s, pytest.raises(LanTrafficError):
        s.connect(("192.168.178.1", 80))


def test_connect_ex_to_lan_is_blocked() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s, pytest.raises(LanTrafficError):
        s.connect_ex(("10.0.0.1", 80))


def test_udp_multicast_is_blocked() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s, pytest.raises(LanTrafficError):
        s.sendto(b"M-SEARCH", ("239.255.255.250", 1900))


def test_name_resolution_is_blocked() -> None:
    with pytest.raises(LanTrafficError):
        socket.getaddrinfo("fritz.box", 80)
    with pytest.raises(LanTrafficError):
        socket.gethostbyaddr("192.168.178.1")


def test_ping_to_lan_is_blocked() -> None:
    with pytest.raises(LanTrafficError):
        subprocess.run(["ping", "192.168.178.1"], capture_output=True, timeout=5)


def test_scapy_send_is_blocked() -> None:
    scapy_all = pytest.importorskip("scapy.all")
    with pytest.raises(LanTrafficError):
        scapy_all.srp(None)


def test_loopback_works() -> None:
    port = free_port("127.0.0.2")
    svc = TcpService("127.0.0.2", port, b"hallo")
    try:
        with socket.create_connection(("127.0.0.2", port), timeout=2) as s:
            assert s.recv(5) == b"hallo"
    finally:
        svc.close()
