"""Sim-Labor für Stufe 2: HTTPS mit Test-Zertifikat, SMB-Attrappe, Dienste stoppen/starten (nur Loopback)."""

from __future__ import annotations

import socket
import ssl

import pytest

from tests.sim import SMB2_MAGIC, SimDevice, SimLab


def _lab() -> SimLab:
    return SimLab([
        SimDevice("127.0.0.3", "00:11:32:aa:bb:03", "NAS", tcp={22: b"SSH-2.0-OpenSSH_9.6\r\n"}, smb=(445,),
                  http={5000: {"/": ("text/html", b"<title>DSM</title>"), "/kaputt": ("text/plain", b"x", 503)}},
                  https={5001: {"/": ("text/html", b"<title>DSM</title>")}}),
    ])  # fmt: skip


def _raw_connect(ip: str, port: int, timeout_s: float, source_ip: str | None = None) -> socket.socket:
    return socket.create_connection((ip, port), timeout=timeout_s)


def _http_get(sock: socket.socket, path: str) -> bytes:
    sock.sendall(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.3\r\nConnection: close\r\n\r\n".encode())
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            return data
        data += chunk


def test_https_with_self_signed_cert() -> None:
    with _lab() as lab:
        connect = lab.translating_connect(_raw_connect)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with connect("127.0.0.3", 5001, 2.0) as raw, ctx.wrap_socket(raw, server_hostname="127.0.0.3") as tls:
            assert _http_get(tls, "/").startswith(b"HTTP/1.0 200")


def test_http_status_per_route() -> None:
    with _lab() as lab:
        connect = lab.translating_connect(_raw_connect)
        with connect("127.0.0.3", 5000, 2.0) as s:
            assert _http_get(s, "/kaputt").startswith(b"HTTP/1.0 503")


def test_smb_negotiate_answer() -> None:
    with _lab() as lab:
        connect = lab.translating_connect(_raw_connect)
        with connect("127.0.0.3", 445, 2.0) as s:
            payload = SMB2_MAGIC + bytes(60)
            s.sendall(len(payload).to_bytes(4, "big") + payload)
            reply = s.recv(4096)
        assert reply[4:8] == SMB2_MAGIC


def test_stop_and_start_service_on_same_port() -> None:
    with _lab() as lab:
        connect = lab.translating_connect(_raw_connect)
        sim_port = lab.port_map["127.0.0.3"][22]
        lab.stop_service("127.0.0.3", 22)
        assert not lab.service_running("127.0.0.3", 22)
        with pytest.raises(OSError):
            connect("127.0.0.3", 22, 1.0).close()
        lab.start_service("127.0.0.3", 22)
        assert lab.port_map["127.0.0.3"][22] == sim_port
        with connect("127.0.0.3", 22, 2.0) as s:
            assert s.recv(64).startswith(b"SSH-2.0")


def test_unknown_port_is_refused() -> None:
    with _lab() as lab:
        connect = lab.translating_connect(_raw_connect)
        with pytest.raises(ConnectionRefusedError):
            connect("127.0.0.3", 3389, 1.0)
