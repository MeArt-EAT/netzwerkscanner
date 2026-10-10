"""Simulierte Geräte auf 127.0.0.x – nur Loopback, nie das echte Netz.

Echte Portnummern (22, 80, 445 …) lassen sich unter Linux ohne root nicht belegen. Deshalb läuft
jeder Dienst auf einem freien hohen Port; SimLab.port_map übersetzt „echter Port → Sim-Port“.
Tests ersetzen netscan.net.ports.probe_port durch lab.translating_probe(original).
"""

from __future__ import annotations

import socket
import socketserver
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from netscan.core.models import PingResult


def free_port(host: str = "127.0.0.1", kind: int = socket.SOCK_STREAM) -> int:
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind((host, 0))
        return int(s.getsockname()[1])


class _TcpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        banner: bytes = self.server.banner  # type: ignore[attr-defined]
        try:
            if banner:
                self.request.sendall(banner)
            self.request.settimeout(0.5)
            try:
                self.request.recv(64)
            except OSError:
                pass
        except OSError:
            pass


class _ThreadingTcp(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class TcpService:
    """TCP-Dienst, der optional sofort ein Banner schickt (SSH, Telnet, FTP …) oder nur annimmt."""

    def __init__(self, host: str, port: int, banner: bytes = b"") -> None:
        self.server = _ThreadingTcp((host, port), _TcpHandler)
        self.server.banner = banner  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class _LoopbackHTTPServer(ThreadingHTTPServer):
    """Ohne socket.getfqdn() im server_bind – das wäre eine Namensauflösung (im Test gesperrt)."""

    daemon_threads = True

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = str(host)
        self.server_port = int(port)


class HttpService:
    """HTTP-Dienst mit festen Antworten: routes = {pfad: (content_type, body)}."""

    def __init__(self, host: str, port: int, routes: dict[str, tuple[str, bytes]], server_header: str = "SimHTTP/1.0") -> None:
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                ctype, body = routes.get(self.path, ("text/plain", b"not found"))
                code = 200 if self.path in routes else 404
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Server", server_header)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: Any) -> None:
                pass

        self.server = _LoopbackHTTPServer((host, port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class UdpService:
    """UDP-Antworter: handler(daten, absender) -> Antwort oder None."""

    def __init__(self, host: str, port: int, handler: Callable[[bytes, tuple[str, int]], bytes | None]) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        self.sock.settimeout(0.1)
        self.handler = handler
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                return
            reply = self.handler(data, addr)
            if reply:
                try:
                    self.sock.sendto(reply, addr)
                except OSError:
                    pass

    def close(self) -> None:
        self._stop.set()
        self.thread.join(1)
        self.sock.close()


UPNP_IGD_XML = b"""<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>FRITZ!Box 7590 (Sim)</friendlyName>
    <manufacturer>AVM Berlin</manufacturer>
    <modelName>FRITZ!Box 7590</modelName>
    <modelNumber>avm</modelNumber>
  </device>
</root>"""


@dataclass
class SimDevice:
    ip: str
    mac: str
    label: str
    tcp: dict[int, bytes] = field(default_factory=dict)  # echter Port -> Banner (b"" = nur annehmen)
    http: dict[int, dict[str, tuple[str, bytes]]] = field(default_factory=dict)  # echter Port -> Routen
    ping: bool = True


def standard_devices() -> list[SimDevice]:
    """Kleines Heimnetz zum Testen (127.0.0.0/28, eigener PC = 127.0.0.1)."""
    return [
        SimDevice("127.0.0.2", "3c:a6:2f:11:22:02", "Router", tcp={53: b""},
                  http={80: {"/": ("text/html", b"<title>FRITZ!Box</title>"), "/igd.xml": ("text/xml", UPNP_IGD_XML)}}),
        SimDevice("127.0.0.3", "00:11:32:aa:bb:03", "NAS",
                  tcp={22: b"SSH-2.0-OpenSSH_8.2p1\r\n", 445: b""},
                  http={5000: {"/": ("text/html", b"<title>Synology DiskStation</title>")}}),
        SimDevice("127.0.0.4", "30:05:5c:aa:bb:04", "Drucker", tcp={631: b"", 9100: b""},
                  http={80: {"/": ("text/html", b"<title>Brother HL-L2350DW</title>")}}),
        SimDevice("127.0.0.5", "00:1b:21:aa:bb:05", "PC", tcp={135: b"", 445: b"", 3389: b""}),
        SimDevice("127.0.0.6", "24:0a:c4:aa:bb:06", "Telnet-Gerät", tcp={23: b"BusyBox v1.31 login: "}),
        SimDevice("127.0.0.7", "da:a1:19:aa:bb:07", "Handy (private MAC)"),
    ]


class SimLab:
    """Startet simulierte Geräte. with SimLab() as lab: ..."""

    def __init__(self, devices: list[SimDevice] | None = None) -> None:
        self.devices = devices if devices is not None else standard_devices()
        self.port_map: dict[str, dict[int, int]] = {}
        self._services: list[Any] = []

    def __enter__(self) -> SimLab:
        for dev in self.devices:
            mapping: dict[int, int] = {}
            for real, banner in dev.tcp.items():
                p = free_port(dev.ip)
                self._services.append(TcpService(dev.ip, p, banner))
                mapping[real] = p
            for real, routes in dev.http.items():
                p = free_port(dev.ip)
                self._services.append(HttpService(dev.ip, p, routes))
                mapping[real] = p
            self.port_map[dev.ip] = mapping
        return self

    def __exit__(self, *exc: object) -> None:
        for s in self._services:
            try:
                s.close()
            except Exception:
                pass
        self._services.clear()

    # --- Hilfen für Tests ------------------------------------------------------
    def arp_answers(self) -> dict[str, str]:
        return {d.ip: d.mac for d in self.devices}

    def ping_results(self) -> dict[str, PingResult]:
        return {d.ip: PingResult(alive=True, rtt_ms=1.0, ttl=64) for d in self.devices if d.ping}

    def http_url(self, ip: str, real_port: int, path: str = "/") -> str:
        return f"http://{ip}:{self.port_map[ip][real_port]}{path}"

    def translating_probe(self, original: Callable[..., Any]) -> Callable[..., Any]:
        """Wrapper für netscan.net.ports.probe_port: echter Port -> Sim-Port; unbekannt = geschlossen."""

        def probe(ip: str, port: int, timeout_s: float, read_banner: bool = False, **kw: Any):  # type: ignore[no-untyped-def]
            sim_port = self.port_map.get(ip, {}).get(port)
            if sim_port is None:
                return (False, None)
            return original(ip, sim_port, timeout_s, read_banner, **kw)  # source_ip wird durchgereicht

        return probe
