"""Tests für netscan.net.ssdp: M-SEARCH, Antworten, UPnP-Beschreibung. Nur Loopback und Attrappen."""

from __future__ import annotations

import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from netscan.core.context import RateLimiter, ScanCancelled
from netscan.core.models import SsdpInfo
from netscan.net import ssdp
from tests.fakes import make_adapter
from tests.sim import UPNP_IGD_XML, HttpService, TcpService, UdpService, free_port

ADAPTER = make_adapter("Ethernet", ipv4="127.0.0.1", network="127.0.0.0/28")  # 127.0.0.0 … 127.0.0.15
IGD_TYPE = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
EXPECTED_M_SEARCH = (
    b"M-SEARCH * HTTP/1.1\r\n"
    b"HOST: 239.255.255.250:1900\r\n"
    b'MAN: "ssdp:discover"\r\n'
    b"MX: 2\r\n"
    b"ST: ssdp:all\r\n"
    b"\r\n"
)


def ssdp_reply(location: str | None = None, server: str | None = "Linux/5.4 UPnP/1.0 SimUPnP/1.0", *, case: str = "upper") -> bytes:
    """Antwort eines UPnP-Geräts auf M-SEARCH; case: upper | lower | mixed (Kopfzeilen-Schreibweise)."""
    names = {"upper": ("LOCATION", "SERVER", "ST", "USN"), "lower": ("location", "server", "st", "usn"), "mixed": ("Location", "Server", "St", "Usn")}[case]
    lines = ["HTTP/1.1 200 OK", "CACHE-CONTROL: max-age=1800", "EXT:"]
    if location:
        lines.append(f"{names[0]}: {location}")
    if server:
        lines.append(f"{names[1]}: {server}")
    lines += [f"{names[2]}: upnp:rootdevice", f"{names[3]}: uuid:1234-sim::upnp:rootdevice", "", ""]
    return "\r\n".join(lines).encode()


class SsdpSim:
    """UDP-Antworter wie ein UPnP-Gerät: antwortet auf jeden M-SEARCH, reihum mit einer der locations."""

    def __init__(self, host: str, locations: list[str | None], *, server: str | None = "Linux/5.4 UPnP/1.0 SimUPnP/1.0", case: str = "upper") -> None:
        self.locations = locations
        self.server = server
        self.case = case
        self.requests: list[bytes] = []
        self.senders: list[tuple[str, int]] = []
        self.port = free_port(host, socket.SOCK_DGRAM)
        self.service = UdpService(host, self.port, self._handle)

    def _handle(self, data: bytes, addr: tuple[str, int]) -> bytes | None:
        self.senders.append(addr)
        self.requests.append(data)
        if not data.startswith(b"M-SEARCH"):
            return None
        location = self.locations[(len(self.requests) - 1) % len(self.locations)]
        return ssdp_reply(location, self.server, case=self.case)

    @property
    def target(self) -> tuple[str, int]:
        return (self.service.sock.getsockname()[0], self.port)

    def close(self) -> None:
        self.service.close()


class FetchSpy:
    """fetch-Attrappe: merkt sich die Aufrufe; bodies = {url: bytes | Ausnahme}, sonst default."""

    def __init__(self, default: bytes | Exception = UPNP_IGD_XML, bodies: dict[str, bytes | Exception] | None = None) -> None:
        self.default = default
        self.bodies = bodies or {}
        self.calls: list[tuple[str, float]] = []
        self._lock = threading.Lock()

    def __call__(self, url: str, timeout_s: float) -> bytes:
        with self._lock:
            self.calls.append((url, timeout_s))
        body = self.bodies.get(url, self.default)
        if isinstance(body, Exception):
            raise body
        return body

    @property
    def urls(self) -> list[str]:
        return [url for url, _ in self.calls]


class CountingServer:
    """HTTP-Server, der nur zählt (Stolperdraht für Anfragen an Dritte)."""

    def __init__(self, host: str, body: bytes = b"<root/>") -> None:
        self.hits: list[str] = []
        hits = self.hits

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                hits.append(self.path)
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                pass

        self.server = ThreadingHTTPServer((host, 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class RedirectServer:
    """HTTP-Server, der auf eine andere Adresse umleitet."""

    def __init__(self, host: str, target_url: str) -> None:
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                self.send_response(302)
                self.send_header("Location", target_url)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args: object) -> None:
                pass

        self.server = ThreadingHTTPServer((host, 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture(autouse=True)
def _no_fqdn_lookup(monkeypatch):  # noqa: ANN001, ANN202
    """HTTPServer.server_bind ruft socket.getfqdn -> gethostbyaddr, das conftest sperrt (LanTrafficError).

    Lokale Abhilfe für tests.sim.HttpService und die Server in dieser Datei; kein Paket verlässt den PC.
    """
    monkeypatch.setattr(socket, "getfqdn", lambda name="": name or "localhost")


@pytest.fixture
def ctx(make_ctx):  # noqa: ANN001, ANN201
    return make_ctx(ssdp_timeout_s=0.5)


@pytest.fixture
def fake_udp(monkeypatch):  # noqa: ANN001, ANN201
    """Ersetzt den UDP-Socket in ssdp durch eine Attrappe, die nie sendet. Rückgabe: (Fabrik, Klasse)."""

    def install(script: list[tuple[bytes, tuple[str, int]]]):  # noqa: ANN202
        class FakeSock:
            instances: list[FakeSock] = []

            def __init__(self, *args: object, **kwargs: object) -> None:
                FakeSock.instances.append(self)
                self.calls: list[tuple] = []
                self._timeout: float | None = None

            def bind(self, addr: tuple[str, int]) -> None:
                self.calls.append(("bind", addr))

            def setsockopt(self, *args: object) -> None:
                self.calls.append(("setsockopt", args))

            def settimeout(self, value: float | None) -> None:
                self._timeout = value

            def sendto(self, data: bytes, addr: tuple[str, int]) -> int:
                self.calls.append(("sendto", data, addr))
                return len(data)

            def recvfrom(self, size: int) -> tuple[bytes, tuple[str, int]]:
                if script:
                    return script.pop(0)
                time.sleep(min(self._timeout or 0.01, 0.02))
                raise TimeoutError()

            def close(self) -> None:
                self.calls.append(("close",))

        class FakeSocketModule:
            socket = FakeSock

            def __getattr__(self, name: str) -> object:
                return getattr(socket, name)

        monkeypatch.setattr(ssdp, "socket", FakeSocketModule())
        return FakeSock

    return install


# --- reine Helfer --------------------------------------------------------------------------------


def test_parse_headers_case_insensitive():
    for case in ("upper", "lower", "mixed"):
        headers = ssdp._parse_ssdp_response(ssdp_reply("http://127.0.0.2:5000/d.xml", "Srv/1.0 UPnP/1.0", case=case))
        assert headers["location"] == "http://127.0.0.2:5000/d.xml"  # Doppelpunkte im Wert bleiben erhalten
        assert headers["server"] == "Srv/1.0 UPnP/1.0"
        assert headers["st"] == "upnp:rootdevice"
        assert headers["usn"] == "uuid:1234-sim::upnp:rootdevice"


def test_parse_headers_tolerates_odd_formatting():
    raw = b"HTTP/1.1 200 OK\nlocation:http://127.0.0.2/x.xml\n  Server :   Foo/1   \nNoColonHere\nST:upnp:rootdevice\n\nLOCATION: spaeter-ignoriert\n"
    headers = ssdp._parse_ssdp_response(raw)
    assert headers["location"] == "http://127.0.0.2/x.xml"  # nach der Leerzeile zählt nichts mehr
    assert headers["server"] == "Foo/1"
    assert headers["st"] == "upnp:rootdevice"
    first_wins = ssdp._parse_ssdp_response(b"HTTP/1.1 200 OK\r\nLOCATION: a\r\nlocation: b\r\n\r\n")
    assert first_wins["location"] == "a"


@pytest.mark.parametrize(
    "raw",
    [b"", b"\xff\xfe\x00\x01", b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nST: ssdp:all\r\n\r\n", b"GET / HTTP/1.1\r\nLocation: x\r\n\r\n", b"nur text"],
)
def test_parse_headers_ignores_requests_and_junk(raw):  # noqa: ANN001
    assert ssdp._parse_ssdp_response(raw) == {}


def test_parse_headers_accepts_notify():
    headers = ssdp._parse_ssdp_response(b"NOTIFY * HTTP/1.1\r\nNT: upnp:rootdevice\r\nLOCATION: http://127.0.0.2/d.xml\r\n\r\n")
    assert headers["location"] == "http://127.0.0.2/d.xml"


@pytest.mark.parametrize(
    "location",
    [
        "http://127.0.0.2:5000/desc.xml",
        "http://127.0.0.2/desc.xml",
        "HTTP://127.0.0.2:49152/a/b.xml?x=1",
        "  http://127.0.0.2:80/d.xml  ",
    ],
)
def test_loadable_location_accepts_same_host_http(location):  # noqa: ANN001
    assert ssdp._loadable_location("127.0.0.2", location) == location.strip()


@pytest.mark.parametrize(
    "location",
    [
        "http://127.0.0.3:5000/desc.xml",  # anderer Host
        "http://localhost:5000/desc.xml",  # Name statt IP
        "http://fritz.box:49000/igddesc.xml",
        "https://127.0.0.2:5000/desc.xml",  # nicht http
        "ftp://127.0.0.2/desc.xml",
        "file:///etc/passwd",
        "http://user:pw@127.0.0.2:5000/d.xml",  # Zugangsdaten in der Adresse
        "http://127.0.0.2@127.0.0.3/d.xml",
        "http://127.0.0.3\\@127.0.0.2/d.xml",
        "http://127.0.0.2:0/d.xml",
        "http://127.0.0.2:99999/d.xml",
        "http://127.0.0.2:abc/d.xml",
        "http://[::1]:5000/d.xml",
        "http://127.000.000.002/d.xml",
        "http://127.0.0.2 :5000/d.xml",
        "http://127.0.0.2:5000/d\n.xml",
        "http://127.0.0.2:5000/dä.xml",
        "//127.0.0.2/d.xml",
        "/d.xml",
        "",
        "   ",
    ],
)
def test_loadable_location_rejects_everything_else(location):  # noqa: ANN001
    assert ssdp._loadable_location("127.0.0.2", location) is None


XML_PREFIXED = """<?xml version="1.0" encoding="utf-8"?>
<u:root xmlns:u="urn:schemas-upnp-org:device-1-0">
  <u:device>
    <u:deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</u:deviceType>
    <u:friendlyName>  Wohnzimmer
        Büro &amp; Co </u:friendlyName>
    <u:manufacturer>Sony</u:manufacturer>
    <u:modelName>KD-55</u:modelName>
    <u:modelNumber>1.0</u:modelNumber>
  </u:device>
</u:root>""".encode()


def test_parse_description_igd_sample():
    fields = ssdp._parse_description(UPNP_IGD_XML)
    assert fields == {
        "friendly_name": "FRITZ!Box 7590 (Sim)",
        "manufacturer": "AVM Berlin",
        "model_name": "FRITZ!Box 7590",
        "model_number": "avm",
        "device_type": IGD_TYPE,
    }


def test_parse_description_other_namespace_prefix_and_whitespace():
    fields = ssdp._parse_description(XML_PREFIXED)
    assert fields["friendly_name"] == "Wohnzimmer Büro & Co"
    assert fields["manufacturer"] == "Sony"
    assert fields["device_type"] == "urn:schemas-upnp-org:device:MediaRenderer:1"


def test_parse_description_without_namespace_and_missing_fields():
    fields = ssdp._parse_description(b"<root><device><friendlyName>Nur Name</friendlyName></device></root>")
    assert fields["friendly_name"] == "Nur Name"
    assert fields["manufacturer"] is None
    assert fields["model_name"] is None
    assert fields["device_type"] is None
    empty = ssdp._parse_description(b"<root><device><friendlyName>   </friendlyName></device></root>")
    assert empty["friendly_name"] is None


def test_parse_description_uses_root_device_not_embedded_devices():
    xml = b"""<root xmlns="urn:schemas-upnp-org:device-1-0"><device>
      <friendlyName>Haupt</friendlyName>
      <deviceList><device><friendlyName>Eingebettet</friendlyName><manufacturer>Fremd</manufacturer></device></deviceList>
    </device></root>"""
    fields = ssdp._parse_description(xml)
    assert fields["friendly_name"] == "Haupt"
    assert fields["manufacturer"] is None  # steht nur im eingebetteten Gerät


def test_parse_description_clips_very_long_values():
    xml = b"<root><device><friendlyName>" + b"x" * 5000 + b"</friendlyName></device></root>"
    assert len(ssdp._parse_description(xml)["friendly_name"] or "") == 200


@pytest.mark.parametrize(
    "xml",
    [
        b"",
        b"<root><device><friendlyName>offen",
        b"kein xml",
        b"<root></root>",  # kein device
        b"<html><body>404</body></html>",
        b"\xff\xfe<\x00r\x00o\x00o\x00t\x00/\x00>\x00",  # UTF-16
        b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]><root><device><friendlyName>&lol2;</friendlyName></device></root>',
        b'<!doctype x><root><device><friendlyName>x</friendlyName></device></root>',
        b'<!DOCTYPE root><root><device><friendlyName>harmlos, aber mit DOCTYPE</friendlyName></device></root>',
        b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///c:/windows/win.ini">]><root><device><friendlyName>&x;</friendlyName></device></root>',
    ],
)
def test_parse_description_broken_or_dangerous_xml_gives_empty(xml):  # noqa: ANN001
    assert ssdp._parse_description(xml) == {}


def test_parse_description_size_limit_is_256_kb():
    head = b"<root><device><friendlyName>Gross</friendlyName></device></root>"
    limit = 256 * 1024
    assert ssdp._parse_description(head + b" " * (limit - len(head)))["friendly_name"] == "Gross"
    assert ssdp._parse_description(head + b" " * (limit - len(head) + 1)) == {}


def test_is_multicast():
    assert ssdp._is_multicast("239.255.255.250")
    assert not ssdp._is_multicast("127.0.0.2")
    assert not ssdp._is_multicast("fritz.box")


# --- Suche gegen simulierte Geräte auf Loopback ---------------------------------------------------


def test_discovers_igd_and_reads_description(ctx):  # noqa: ANN001
    http = HttpService("127.0.0.2", free_port("127.0.0.2"), {"/igd.xml": ("text/xml", UPNP_IGD_XML)})
    sim = SsdpSim("127.0.0.2", [f"http://127.0.0.2:{http.server.server_address[1]}/igd.xml"], server="Linux/5.4 UPnP/1.0 AVM-Sim/7.57")
    try:
        result = ssdp.ssdp_discover(ctx, ADAPTER, target=sim.target)
    finally:
        sim.close()
        http.close()
    assert set(result) == {"127.0.0.2"}
    info = result["127.0.0.2"]
    assert isinstance(info, SsdpInfo)
    assert info.friendly_name == "FRITZ!Box 7590 (Sim)"
    assert info.device_type == IGD_TYPE
    assert info.manufacturer == "AVM Berlin"
    assert info.model_name == "FRITZ!Box 7590"
    assert info.model_number == "avm"
    assert info.server == "Linux/5.4 UPnP/1.0 AVM-Sim/7.57"
    assert info.location == f"http://127.0.0.2:{http.server.server_address[1]}/igd.xml"


def test_msearch_is_sent_twice_from_the_adapter_address(ctx):  # noqa: ANN001
    sim = SsdpSim("127.0.0.2", [None])
    try:
        ssdp.ssdp_discover(ctx, ADAPTER, target=sim.target, fetch=FetchSpy())
    finally:
        sim.close()
    assert sim.requests == [EXPECTED_M_SEARCH, EXPECTED_M_SEARCH]
    assert {addr[0] for addr in sim.senders} == {ADAPTER.ipv4}  # Absender ist die Adresse des gewählten Adapters


def test_collects_for_ssdp_timeout_seconds(make_ctx):  # noqa: ANN001
    ctx = make_ctx(ssdp_timeout_s=0.8)
    sim = SsdpSim("127.0.0.2", [None])
    try:
        started = time.monotonic()
        ssdp.ssdp_discover(ctx, ADAPTER, target=sim.target, fetch=FetchSpy())
        elapsed = time.monotonic() - started
    finally:
        sim.close()
    assert 0.75 <= elapsed < 1.6


def test_response_without_location_still_reports_the_device(ctx):  # noqa: ANN001
    sim = SsdpSim("127.0.0.2", [None], server="Nur-Server/1.0")
    spy = FetchSpy()
    try:
        result = ssdp.ssdp_discover(ctx, ADAPTER, target=sim.target, fetch=spy)
    finally:
        sim.close()
    assert result == {"127.0.0.2": SsdpInfo(location=None, server="Nur-Server/1.0")}
    assert spy.calls == []


def test_header_case_does_not_matter_end_to_end(ctx):  # noqa: ANN001
    for case in ("lower", "mixed"):
        sim = SsdpSim("127.0.0.2", ["http://127.0.0.2:5000/d.xml"], case=case)
        spy = FetchSpy()
        try:
            result = ssdp.ssdp_discover(ctx, ADAPTER, target=sim.target, fetch=spy)
        finally:
            sim.close()
        assert spy.urls == ["http://127.0.0.2:5000/d.xml"], case
        assert result["127.0.0.2"].friendly_name == "FRITZ!Box 7590 (Sim)"


def test_foreign_location_is_not_loaded_and_not_requested(ctx):  # noqa: ANN001
    stranger = CountingServer("127.0.0.9")  # „Dritter“
    sim = SsdpSim("127.0.0.2", [f"http://127.0.0.9:{stranger.port}/desc.xml"], server="Boese/1.0")
    try:
        result = ssdp.ssdp_discover(ctx, ADAPTER, target=sim.target)  # mit dem echten Standard-fetch
    finally:
        sim.close()
        stranger.close()
    assert stranger.hits == []  # keine Anfrage an den Dritten
    info = result["127.0.0.2"]
    assert info.server == "Boese/1.0"
    assert info.location is None
    assert info.friendly_name is None and info.device_type is None


@pytest.mark.parametrize(
    "location",
    [
        "http://127.0.0.9:5000/desc.xml",
        "http://fritz.box:49000/igddesc.xml",
        "https://127.0.0.2:5000/desc.xml",
        "http://user:pw@127.0.0.2:5000/desc.xml",
        "http://127.0.0.2:0/desc.xml",
        "ftp://127.0.0.2/desc.xml",
    ],
)
def test_unloadable_locations_never_reach_fetch(ctx, location):  # noqa: ANN001
    sim = SsdpSim("127.0.0.2", [location])
    spy = FetchSpy()
    try:
        result = ssdp.ssdp_discover(ctx, ADAPTER, target=sim.target, fetch=spy)
    finally:
        sim.close()
    assert spy.calls == []
    assert result["127.0.0.2"].location is None


def test_disallowed_ip_is_ignored(ctx):  # noqa: ANN001
    sim = SsdpSim("127.0.0.2", ["http://127.0.0.2:5000/d.xml"])
    spy = FetchSpy()
    try:
        result = ssdp.ssdp_discover(ctx, ADAPTER, target=sim.target, allowed_ips={"127.0.0.9"}, fetch=spy)
    finally:
        sim.close()
    assert result == {}
    assert spy.calls == []
    assert len(sim.requests) == 2  # gesucht wurde, nur die Antwort zählt nicht


def test_empty_allowed_set_sends_nothing(ctx):  # noqa: ANN001
    sim = SsdpSim("127.0.0.2", ["http://127.0.0.2:5000/d.xml"])
    try:
        result = ssdp.ssdp_discover(ctx, ADAPTER, target=sim.target, allowed_ips=set(), fetch=FetchSpy())
    finally:
        sim.close()
    assert result == {}
    assert sim.requests == []


def test_default_allowed_sources_are_the_adapter_network(ctx):  # noqa: ANN001
    # 127.0.0.20 liegt außerhalb von 127.0.0.0/28
    sim = SsdpSim("127.0.0.20", ["http://127.0.0.20:5000/d.xml"])
    spy = FetchSpy()
    try:
        outside = ssdp.ssdp_discover(ctx, ADAPTER, target=sim.target, fetch=spy)
        widened = ssdp.ssdp_discover(ctx, ADAPTER, target=sim.target, allowed_ips={"127.0.0.20"}, fetch=spy)
    finally:
        sim.close()
    assert outside == {}
    assert set(widened) == {"127.0.0.20"}
    assert spy.urls == ["http://127.0.0.20:5000/d.xml"]


def test_broken_xml_keeps_server_and_location(ctx):  # noqa: ANN001
    url = "http://127.0.0.2:5000/d.xml"
    sim = SsdpSim("127.0.0.2", [url], server="Kaputt/1.0")
    try:
        result = ssdp.ssdp_discover(ctx, ADAPTER, target=sim.target, fetch=FetchSpy(b"<root><device><friendlyName>abgeschnitt"))
    finally:
        sim.close()
    assert result == {"127.0.0.2": SsdpInfo(location=url, server="Kaputt/1.0")}


def test_fetch_errors_do_not_stop_discovery(ctx):  # noqa: ANN001
    url = "http://127.0.0.2:5000/d.xml"
    for error in (TimeoutError("zu langsam"), OSError("Verbindung abgelehnt"), ValueError("zu groß")):
        sim = SsdpSim("127.0.0.2", [url], server="Stumm/1.0")
        try:
            result = ssdp.ssdp_discover(ctx, ADAPTER, target=sim.target, fetch=FetchSpy(error))
        finally:
            sim.close()
        assert result == {"127.0.0.2": SsdpInfo(location=url, server="Stumm/1.0")}, type(error).__name__


def test_fetch_result_over_256_kb_is_discarded(ctx):  # noqa: ANN001
    url = "http://127.0.0.2:5000/d.xml"
    big = b"<root><device><friendlyName>Riesig</friendlyName></device></root>" + b" " * (256 * 1024)
    sim = SsdpSim("127.0.0.2", [url])
    try:
        result = ssdp.ssdp_discover(ctx, ADAPTER, target=sim.target, fetch=FetchSpy(big))
    finally:
        sim.close()
    assert result["127.0.0.2"].friendly_name is None
    assert result["127.0.0.2"].location == url


def test_only_one_description_per_ip_first_matching_location(ctx, fake_udp):  # noqa: ANN001
    first, second = "http://127.0.0.2:5000/a.xml", "http://127.0.0.2:5001/b.xml"
    fake_udp(
        [
            (ssdp_reply("http://127.0.0.9:1/fremd.xml"), ("127.0.0.2", 1900)),  # unpassend: anderer Host
            (ssdp_reply("https://127.0.0.2:5443/s.xml"), ("127.0.0.2", 1900)),  # unpassend: nicht http
            (ssdp_reply(first), ("127.0.0.2", 1900)),
            (ssdp_reply(second), ("127.0.0.2", 1900)),
        ]
    )
    spy = FetchSpy()
    result = ssdp.ssdp_discover(ctx, ADAPTER, target=("127.0.0.2", 1900), fetch=spy)
    assert spy.urls == [first]  # genau eine Beschreibung, die erste passende
    assert result["127.0.0.2"].location == first


def test_fetch_gets_the_two_second_timeout(ctx):  # noqa: ANN001
    sim = SsdpSim("127.0.0.2", ["http://127.0.0.2:5000/d.xml"])
    spy = FetchSpy()
    try:
        ssdp.ssdp_discover(ctx, ADAPTER, target=sim.target, fetch=spy)
    finally:
        sim.close()
    assert [t for _, t in spy.calls] == [2.0]


def test_closed_target_port_is_harmless(ctx):  # noqa: ANN001
    """Unter Windows meldet recvfrom nach einer Sendung an einen geschlossenen Port einen Fehler."""
    target = ("127.0.0.2", free_port("127.0.0.2", socket.SOCK_DGRAM))
    started = time.monotonic()
    result = ssdp.ssdp_discover(ctx, ADAPTER, target=target, fetch=FetchSpy())
    assert result == {}
    assert 0.45 <= time.monotonic() - started < 1.5


def test_unbindable_adapter_address_is_logged_not_raised(ctx):  # noqa: ANN001
    bad = make_adapter("Ethernet", ipv4="203.0.113.77", network="203.0.113.0/24")
    assert ssdp.ssdp_discover(ctx, bad, target=("127.0.0.2", 9), fetch=FetchSpy()) == {}
    warnings = [e.data["message"] for e in ctx.bus.history(type_prefix="job.log") if e.data["level"] == "warning"]
    assert any("SSDP" in m for m in warnings)


# --- Abbruch, Drosselung, Fortschritt --------------------------------------------------------------


def test_cancel_before_start(ctx):  # noqa: ANN001
    ctx.cancel.cancel()
    with pytest.raises(ScanCancelled):
        ssdp.ssdp_discover(ctx, ADAPTER, target=("127.0.0.2", 9), fetch=FetchSpy())


def test_cancel_during_collection_acts_quickly(make_ctx):  # noqa: ANN001
    ctx = make_ctx(ssdp_timeout_s=8.0)
    sim = SsdpSim("127.0.0.2", [None])
    timer = threading.Timer(0.3, ctx.cancel.cancel)
    timer.start()
    started = time.monotonic()
    try:
        with pytest.raises(ScanCancelled):
            ssdp.ssdp_discover(ctx, ADAPTER, target=sim.target, fetch=FetchSpy())
    finally:
        timer.cancel()
        sim.close()
    assert time.monotonic() - started < 1.5


def test_cancel_during_description_download(ctx):  # noqa: ANN001
    sim = SsdpSim("127.0.0.2", ["http://127.0.0.2:5000/d.xml"])
    release = threading.Event()

    def slow_fetch(url: str, timeout_s: float) -> bytes:
        ctx.cancel.cancel()  # Abbruch kommt, während die Beschreibung geladen wird
        release.wait(0.3)
        return UPNP_IGD_XML

    try:
        with pytest.raises(ScanCancelled):
            ssdp.ssdp_discover(ctx, ADAPTER, target=sim.target, fetch=slow_fetch)
    finally:
        release.set()
        sim.close()


def test_throttle_is_used_for_searches_and_downloads(ctx):  # noqa: ANN001
    class CountingRate(RateLimiter):
        def __init__(self) -> None:
            super().__init__(1000, burst=1000)
            self.calls = 0

        def acquire(self, n: float = 1.0) -> None:
            self.calls += 1

    ctx.rate = CountingRate()
    sim = SsdpSim("127.0.0.2", ["http://127.0.0.2:5000/d.xml"])
    try:
        ssdp.ssdp_discover(ctx, ADAPTER, target=sim.target, fetch=FetchSpy())
    finally:
        sim.close()
    assert ctx.rate.calls == 2 + 1  # zwei M-SEARCH, eine Beschreibung


def test_progress_phase_and_log_summary(ctx):  # noqa: ANN001
    sim = SsdpSim("127.0.0.2", ["http://127.0.0.2:5000/d.xml"])
    try:
        ssdp.ssdp_discover(ctx, ADAPTER, target=sim.target, fetch=FetchSpy())
    finally:
        sim.close()
    events = [e.data for e in ctx.bus.history(type_prefix="job.progress")]
    assert events and {e["phase"] for e in events} == {"SSDP/UPnP"}
    assert all(0 <= e["done"] <= e["total"] for e in events)
    assert events[-1]["done"] == events[-1]["total"]
    messages = [e.data["message"] for e in ctx.bus.history(type_prefix="job.log")]
    assert any(m.startswith("SSDP/UPnP: 1 Geräte") and "1 Beschreibungen" in m for m in messages)


# --- Mehrere Geräte und Multicast-Einstellungen mit Socket-Attrappe (es wird nichts gesendet) ----


def test_multicast_target_sets_interface_and_ttl_and_sends_twice(ctx, fake_udp):  # noqa: ANN001
    script = [(ssdp_reply("http://127.0.0.2:5000/d.xml", "Fritz/1.0"), ("127.0.0.2", 1900))]
    fake = fake_udp(script)
    spy = FetchSpy()
    result = ssdp.ssdp_discover(ctx, ADAPTER, fetch=spy)  # Standardziel: 239.255.255.250:1900
    (sock,) = fake.instances
    calls = sock.calls
    assert ("bind", ("127.0.0.1", 0)) in calls
    options = [c[1] for c in calls if c[0] == "setsockopt"]
    assert (socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton("127.0.0.1")) in options
    assert (socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2) in options
    sends = [c for c in calls if c[0] == "sendto"]
    assert [(s[1], s[2]) for s in sends] == [(EXPECTED_M_SEARCH, ("239.255.255.250", 1900))] * 2
    assert calls[-1] == ("close",)
    assert result["127.0.0.2"].friendly_name == "FRITZ!Box 7590 (Sim)"


def test_unicast_target_sets_no_multicast_options(ctx, fake_udp):  # noqa: ANN001
    fake = fake_udp([])
    ssdp.ssdp_discover(ctx, ADAPTER, target=("127.0.0.2", 1900), fetch=FetchSpy())
    (sock,) = fake.instances
    assert not [c for c in sock.calls if c[0] == "setsockopt"]


def test_many_devices_mixed_with_junk(ctx, fake_udp):  # noqa: ANN001
    urls = {ip: f"http://{ip}:5000/d.xml" for ip in ("127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5")}
    script = [
        (ssdp_reply(urls["127.0.0.2"], "A/1"), ("127.0.0.2", 1900)),
        (ssdp_reply(urls["127.0.0.3"], "B/1"), ("127.0.0.3", 1900)),
        (ssdp_reply("http://127.0.0.20:5000/d.xml", "Draussen/1"), ("127.0.0.20", 1900)),  # außerhalb des Netzes
        (b"\x00\x01\x02 Muell", ("127.0.0.6", 1900)),  # kein SSDP
        (EXPECTED_M_SEARCH, ("127.0.0.7", 1900)),  # eine fremde Anfrage, keine Antwort
        (ssdp_reply(urls["127.0.0.4"], "C/1"), ("127.0.0.4", 1900)),
        (ssdp_reply(urls["127.0.0.2"], "A-zweitens/1"), ("127.0.0.2", 1900)),  # doppelte Antwort
        (ssdp_reply(urls["127.0.0.5"], "D/1"), ("127.0.0.5", 1900)),
    ]
    fake_udp(script)
    spy = FetchSpy(
        bodies={
            urls["127.0.0.3"]: TimeoutError("langsam"),
            urls["127.0.0.4"]: b"<kaputt",
            urls["127.0.0.5"]: XML_PREFIXED,
        }
    )
    result = ssdp.ssdp_discover(ctx, ADAPTER, fetch=spy)
    assert set(result) == set(urls)  # .20 und .6 und .7 fehlen
    assert sorted(spy.urls) == sorted(urls.values())  # je IP genau eine Beschreibung
    assert result["127.0.0.2"].server == "A/1"  # erste Antwort gewinnt
    assert result["127.0.0.2"].friendly_name == "FRITZ!Box 7590 (Sim)"
    assert result["127.0.0.3"] == SsdpInfo(location=urls["127.0.0.3"], server="B/1")
    assert result["127.0.0.4"] == SsdpInfo(location=urls["127.0.0.4"], server="C/1")
    assert result["127.0.0.5"].manufacturer == "Sony"
    assert result["127.0.0.5"].device_type == "urn:schemas-upnp-org:device:MediaRenderer:1"


# --- Standard-fetch (urllib) gegen Loopback-Server ------------------------------------------------


def test_default_fetch_reads_description():
    http = HttpService("127.0.0.2", free_port("127.0.0.2"), {"/d.xml": ("text/xml", UPNP_IGD_XML)})
    try:
        port = http.server.server_address[1]
        assert ssdp._fetch_http(f"http://127.0.0.2:{port}/d.xml", 2.0) == UPNP_IGD_XML
        with pytest.raises(Exception):  # noqa: B017 – 404 ist ein Fehler
            ssdp._fetch_http(f"http://127.0.0.2:{port}/gibt-es-nicht.xml", 2.0)
    finally:
        http.close()


def test_default_fetch_enforces_256_kb_limit():
    limit = 256 * 1024
    http = HttpService(
        "127.0.0.2", free_port("127.0.0.2"),
        {"/genau": ("text/xml", b"x" * limit), "/zu-gross": ("text/xml", b"x" * (limit + 1))},
    )  # fmt: skip
    try:
        port = http.server.server_address[1]
        assert len(ssdp._fetch_http(f"http://127.0.0.2:{port}/genau", 2.0)) == limit
        with pytest.raises(ValueError):
            ssdp._fetch_http(f"http://127.0.0.2:{port}/zu-gross", 2.0)
    finally:
        http.close()


def test_default_fetch_does_not_follow_redirects():
    third = CountingServer("127.0.0.9")
    redirect = RedirectServer("127.0.0.2", f"http://127.0.0.9:{third.port}/geheim.xml")
    try:
        with pytest.raises(Exception):  # noqa: B017
            ssdp._fetch_http(f"http://127.0.0.2:{redirect.port}/d.xml", 2.0)
        time.sleep(0.1)
        assert third.hits == []  # die Weiterleitung wurde nicht befolgt
    finally:
        redirect.close()
        third.close()


def test_default_fetch_ignores_proxy_settings(monkeypatch):  # noqa: ANN001
    for name in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(name, "http://127.0.0.9:9")  # würde bei einem Proxy-Versuch ins Leere laufen
    monkeypatch.setenv("NO_PROXY", "")
    monkeypatch.setenv("no_proxy", "")
    server = CountingServer("127.0.0.2", UPNP_IGD_XML)
    try:
        assert ssdp._fetch_http(f"http://127.0.0.2:{server.port}/d.xml", 2.0) == UPNP_IGD_XML
        assert server.hits == ["/d.xml"]
    finally:
        server.close()


def test_default_fetch_fails_when_the_server_hangs_up_without_answer():
    port = free_port("127.0.0.2")
    silent = TcpService("127.0.0.2", port, b"")  # nimmt an, liest die Anfrage, antwortet nie
    try:
        with pytest.raises(Exception):  # noqa: B017
            ssdp._fetch_http(f"http://127.0.0.2:{port}/d.xml", 0.5)
    finally:
        silent.close()


def test_default_fetch_times_out_on_a_server_that_never_answers():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.2", 0))
    listener.listen(1)
    held: list[socket.socket] = []
    stop = threading.Event()

    def accept_and_hold() -> None:
        listener.settimeout(0.1)
        while not stop.is_set():
            try:
                held.append(listener.accept()[0])  # Verbindung offen halten, nichts lesen, nichts senden
            except OSError:
                continue

    thread = threading.Thread(target=accept_and_hold, daemon=True)
    thread.start()
    started = time.monotonic()
    try:
        with pytest.raises(Exception):  # noqa: B017
            ssdp._fetch_http(f"http://127.0.0.2:{listener.getsockname()[1]}/d.xml", 0.4)
        assert time.monotonic() - started < 2.0
    finally:
        stop.set()
        thread.join(1)
        for conn in held:
            conn.close()
        listener.close()
