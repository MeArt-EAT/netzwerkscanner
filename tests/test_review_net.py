"""Regressionstests zu Prüfbefunden in netscan/net und im Export: S4 (SSDP-Beschreibung mit Gesamtfrist),
S8/WIN-03/WIN-06 (ARP: Paketabstand, Blockgröße, Laufzeit, Scapy neu einlesen), S9 (CSV-Formel-Injection).

Nur Loopback (127.0.0.x) und Attrappen; ein falsches scapy.all sendet nichts.
"""

from __future__ import annotations

import csv
import io
import socket
import sys
import threading
import time
import types
from types import SimpleNamespace

import pytest

from netscan.core.models import Device
from netscan.net import arp, ssdp
from netscan.web import export
from tests.fakes import FakeArpSender, make_adapter
from tests.sim import UPNP_IGD_XML

NET = "192.168.178"


def hosts(n: int = 253) -> list[str]:
    return [f"{NET}.{i}" for i in range(1, n + 1)]


# --- S4: SSDP-Beschreibung mit Gesamtfrist ------------------------------------------------------------


class DripServer:
    """HTTP-Server auf 127.0.0.5: Kopfzeilen sofort, danach je delay_s ein Byte (oder alles und offen halten)."""

    def __init__(self, head: bytes, body: bytes, delay_s: float, keep_open: bool = False) -> None:
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.5", 0))
        self.listener.listen(4)
        self.port = self.listener.getsockname()[1]
        self.head, self.body, self.delay_s, self.keep_open = head, body, delay_s, keep_open
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        self.listener.settimeout(0.1)
        while not self.stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except OSError:
                continue
            try:
                conn.settimeout(1.0)
                conn.recv(4096)
                conn.sendall(self.head)
                if self.delay_s:
                    for i in range(len(self.body)):
                        if self.stop.wait(self.delay_s):
                            break
                        conn.sendall(self.body[i : i + 1])
                else:
                    conn.sendall(self.body)
                if self.keep_open:
                    self.stop.wait(5)
            except OSError:
                pass
            finally:
                conn.close()

    def close(self) -> None:
        self.stop.set()
        self.thread.join(2)
        self.listener.close()


def test_s4_dripping_server_cannot_hold_the_fetch_beyond_the_deadline() -> None:
    server = DripServer(b"HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n", b"x" * 5000, delay_s=0.1)
    t0 = time.monotonic()
    try:
        with pytest.raises(TimeoutError):
            ssdp._fetch_http(f"http://127.0.0.5:{server.port}/d.xml", 0.8)
        assert time.monotonic() - t0 < 1.5  # früher: bis die 5000 Bytes da waren (über 8 Minuten)
    finally:
        server.close()


def test_s4_dripping_headers_also_count_against_the_deadline() -> None:
    server = DripServer(b"", b"HTTP/1.1 200 OK\r\nX-Langsam: " + b"a" * 200, delay_s=0.05)
    t0 = time.monotonic()
    try:
        with pytest.raises(TimeoutError):
            ssdp._fetch_http(f"http://127.0.0.5:{server.port}/d.xml", 0.6)
        assert time.monotonic() - t0 < 1.2
    finally:
        server.close()


def test_s4_keep_alive_server_returns_as_soon_as_content_length_is_complete() -> None:
    head = b"HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: %d\r\n\r\n" % len(UPNP_IGD_XML)
    server = DripServer(head, UPNP_IGD_XML, delay_s=0, keep_open=True)
    t0 = time.monotonic()
    try:
        assert ssdp._fetch_http(f"http://127.0.0.5:{server.port}/d.xml", 2.0) == UPNP_IGD_XML
        assert time.monotonic() - t0 < 1.0  # nicht bis zur Frist auf das Schließen gewartet
    finally:
        server.close()


def test_s4_chunked_answer_is_decoded() -> None:
    body = b"5\r\n<root\r\n1\r\n>\r\n7\r\n</root>\r\n0\r\n\r\n"
    server = DripServer(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", body, delay_s=0)
    try:
        assert ssdp._fetch_http(f"http://127.0.0.5:{server.port}/d.xml", 2.0) == b"<root></root>"
    finally:
        server.close()


def test_s4_only_ip_literals_no_name_resolution() -> None:
    with pytest.raises(ValueError):
        ssdp._fetch_http("http://router.local:80/d.xml", 1.0)


# --- S8/WIN-03/WIN-06: ARP ------------------------------------------------------------------------------


def test_win03_block_size_follows_rate() -> None:
    assert arp.block_size(200) == 200  # Standard: ein Block ≈ 1 s Senden
    assert arp.block_size(1000) == arp.MAX_BLOCK_SIZE == 256
    assert arp.block_size(10) == 10  # Minimum der Einstellung: nie mehr als 10 je Sekunde
    assert arp.block_size(0) == 1 and arp.block_size("x") == 1  # type: ignore[arg-type]


def test_win03_slash24_needs_four_waits_instead_of_fifteen(make_ctx) -> None:  # type: ignore[no-untyped-def]
    ctx = make_ctx()  # Standard: 200 Pakete/s, Timeout 1 s, 1 Wiederholung
    slept: list[float] = []
    ctx.sleep = lambda s: slept.append(s)  # type: ignore[method-assign]
    seen: list[tuple[int, float]] = []

    def sender(adapter, ips, timeout_s):  # type: ignore[no-untyped-def]
        seen.append((len(ips), timeout_s))
        return {}

    arp.arp_scan(ctx, make_adapter(), hosts(), sender)
    assert seen == [(200, 1.0), (53, 1.0), (200, 0.5), (53, 0.5)]
    waiting = sum(t for _, t in seen)
    sending = sum(n for n, _ in seen) / 200
    assert waiting == 3.0 and waiting + sending < 6.0  # früher 8 + 7 Blöcke à 1 s ≈ 15 s
    assert sum(slept) == pytest.approx(sending, abs=0.05)  # Mindestdauer je Block: Rate bleibt eingehalten


def test_win03_retry_timeout_never_exceeds_the_setting(make_ctx) -> None:  # type: ignore[no-untyped-def]
    ctx = make_ctx(arp_timeout_s=0.2, rate_pps=1000)
    sender = FakeArpSender({})
    timeouts: list[float] = []
    arp.arp_scan(ctx, make_adapter(), hosts(5), lambda a, ips, t: timeouts.append(t) or sender(a, ips, t))
    assert timeouts == [0.2, 0.2]


def install_fake_scapy(monkeypatch: pytest.MonkeyPatch, iface: SimpleNamespace) -> types.ModuleType:
    module = types.ModuleType("scapy.all")
    module.sendp_calls = []  # type: ignore[attr-defined]
    module.refreshes = []  # type: ignore[attr-defined]

    class Layer:
        def __init__(self, **fields: object) -> None:
            self.fields = fields
            self.payload = None

        def __truediv__(self, other):  # type: ignore[no-untyped-def]
            self.payload = other
            return self

    def sendp(packet, **kwargs):  # type: ignore[no-untyped-def]
        module.sendp_calls.append({"packet": packet, **kwargs})  # type: ignore[attr-defined]

    class AsyncSniffer:  # liest nichts mit: startet sofort, liefert keine Antworten
        def __init__(self, **kwargs: object) -> None:
            self.kwargs = kwargs
            self.running = False
            self.results: list[object] | None = None

        def start(self) -> None:
            self.running = True
            self.kwargs["started_callback"]()  # type: ignore[operator]

        def join(self, timeout: float | None = None) -> None:
            pass

        def stop(self, join: bool = True) -> None:
            self.running = False
            self.results = []

    class Ifaces(dict):  # type: ignore[type-arg]
        def reload(self) -> None:
            module.refreshes.append("ifaces")  # type: ignore[attr-defined]

    route = SimpleNamespace(resync=lambda: module.refreshes.append("route"))  # type: ignore[attr-defined]
    module.ARP = type("ARP", (Layer,), {})  # type: ignore[attr-defined]
    module.Ether = type("Ether", (Layer,), {})  # type: ignore[attr-defined]
    module.conf = SimpleNamespace(ifaces=Ifaces(x=iface), route=route)  # type: ignore[attr-defined]
    module.sendp = sendp  # type: ignore[attr-defined]
    module.AsyncSniffer = AsyncSniffer  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "scapy.all", module)
    return module


def test_s8_scapy_blocks_are_paced_at_the_configured_rate(make_ctx, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    iface = SimpleNamespace(name="eth", ip="192.168.178.20", ips={4: ["192.168.178.20"]}, mac="00:1b:21:00:00:20")
    fake = install_fake_scapy(monkeypatch, iface)
    ctx = make_ctx(rate_pps=10, arp_retries=0)
    ctx.sleep = lambda s: None  # type: ignore[method-assign]
    arp.arp_scan(ctx, make_adapter(), hosts(25))
    sizes = [len(c["packet"].payload.fields["pdst"]) for c in fake.sendp_calls]
    assert sizes == [10, 10, 5]  # früher 25 Anfragen auf einmal, obwohl nur 10 je Sekunde erlaubt sind
    assert all(c["inter"] == pytest.approx(0.1) for c in fake.sendp_calls)  # 1/rate_pps zwischen zwei Paketen
    for call in fake.sendp_calls:  # jeder Block: n Pakete im Abstand 1/rate ⇒ höchstens rate je Sekunde
        n = len(call["packet"].payload.fields["pdst"])
        assert n <= 10 and (n - 1) * call["inter"] <= 1.0


def test_win06_scapy_is_reloaded_once_per_scan_and_sender_addresses_are_explicit(make_ctx, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    iface = SimpleNamespace(name="eth", ip="192.168.178.20", ips={4: ["192.168.178.20"]}, mac="00:1B:21:00:00:20")
    fake = install_fake_scapy(monkeypatch, iface)
    ctx = make_ctx(rate_pps=1000, arp_retries=1)
    arp.arp_scan(ctx, make_adapter(), hosts(10))
    assert fake.refreshes == ["ifaces", "route"]  # einmal je Scan, nicht je Block
    assert len(fake.sendp_calls) == 2
    packet = fake.sendp_calls[0]["packet"]
    assert packet.fields["src"] == "00:1b:21:00:00:20"
    assert packet.payload.fields["psrc"] == "192.168.178.20" and packet.payload.fields["hwsrc"] == "00:1b:21:00:00:20"


def test_win06_refresh_errors_do_not_stop_the_scan(make_ctx, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    iface = SimpleNamespace(name="eth", ip="192.168.178.20", ips={4: ["192.168.178.20"]}, mac="00:1b:21:00:00:20")
    fake = install_fake_scapy(monkeypatch, iface)

    def broken() -> None:
        raise OSError("Npcap gerade beschäftigt")

    fake.conf.route = SimpleNamespace(resync=broken)  # type: ignore[attr-defined]
    ctx = make_ctx(rate_pps=1000, arp_retries=0)
    assert arp.arp_scan(ctx, make_adapter(), hosts(3)) == {}
    assert len(fake.sendp_calls) == 1


# --- S9: CSV-Export -------------------------------------------------------------------------------------


def _csv_device(name: str) -> Device:
    return Device(mac="aa:bb:cc:00:00:01", ip="192.168.178.10", custom_name=name, note="x,=1+1")


def test_s9_comma_separated_reading_never_yields_a_formula_cell() -> None:
    text = export.to_csv([_csv_device("TV,=cmd|' /C calc'!A0"), _csv_device('TV,=HYPERLINK("http://x")')])
    body = text[1:]  # ohne BOM
    for delimiter in (",", ";"):
        for row in list(csv.reader(io.StringIO(body, newline=""), delimiter=delimiter))[1:]:
            for cell in row:
                assert not cell.lstrip('"').startswith(("=", "+", "-", "@")), (delimiter, cell)


def test_s9_data_fields_are_quoted_and_formula_after_comma_is_neutralised() -> None:
    text = export.to_csv([_csv_device("TV,=cmd")])
    lines = text[1:].split("\r\n")
    assert lines[0].startswith("Name;IP;MAC;")  # feste Kopfzeile unverändert
    assert lines[1].startswith('"TV,\'=cmd";"192.168.178.10";"aa:bb:cc:00:00:01";')  # jedes Feld in Anführungszeichen
    rows = list(csv.reader(io.StringIO(text[1:], newline=""), delimiter=";"))
    assert rows[1][0] == "TV,'=cmd" and rows[1][13] == "x,'=1+1"


def test_s9_ordinary_text_with_commas_stays_as_it_is() -> None:
    d = Device(mac="aa:bb:cc:00:00:01", ip="192.168.178.10", custom_name="Drucker, Büro 2", note="a-b, c=d; Zeile\nzwei")
    row = list(csv.reader(io.StringIO(export.to_csv([d])[1:], newline=""), delimiter=";"))[1]
    assert row[0] == "Drucker, Büro 2" and row[13] == "a-b, c=d; Zeile\nzwei"
    note = Device(mac="aa:bb:cc:00:00:02", ip="192.168.178.11", note="Zeile 1\n=HYPERLINK(1)")
    row = list(csv.reader(io.StringIO(export.to_csv([note])[1:], newline=""), delimiter=";"))[1]
    assert row[13] == "Zeile 1\n'=HYPERLINK(1)"  # auch nach einem Zeilenumbruch
