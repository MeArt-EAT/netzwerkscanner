"""Tests für netscan.net.names: DNS rückwärts, NetBIOS (NBSTAT), mDNS. Nur Loopback und Attrappen."""

from __future__ import annotations

import enum
import random
import socket
import struct
import sys
import threading
import time
import types
from collections.abc import Iterator
from contextlib import contextmanager

import pytest

from netscan.core.context import RateLimiter, ScanCancelled
from netscan.core.models import NameInfo
from netscan.net import names
from tests.fakes import make_adapter
from tests.sim import UdpService, free_port

ADAPTER = make_adapter("Ethernet", ipv4="127.0.0.1", network="127.0.0.0/28")
WILDCARD = b"*" + b"\x00" * 15


# --- NBSTAT-Attrappe (unabhängig von names.py geschrieben) --------------------------------------


def _enc(raw: bytes) -> bytes:
    """First-Level-Encoding, eigene Umsetzung für die Tests."""
    return b"".join(bytes([0x41 + (b >> 4), 0x41 + (b & 15)]) for b in raw)


def nbstat_response(
    tid: bytes,
    entries: list[tuple[str, int, int]],
    *,
    compressed: bool = False,
    echo_question: bool = False,
    declared_count: int | None = None,
) -> bytes:
    """Baut eine NBSTAT-Antwort. entries = [(Name, Suffix, Flags)]."""
    rdata = bytes([len(entries) if declared_count is None else declared_count])
    for name, suffix, flags in entries:
        rdata += name.encode("cp850").ljust(15, b" ")[:15] + bytes([suffix]) + struct.pack(">H", flags)
    rdata += bytes(46)  # Statistik (MAC-Adresse usw.), hier nur Nullen
    question = b"\x20" + _enc(WILDCARD) + b"\x00" + struct.pack(">HH", 0x21, 1)
    header = tid + struct.pack(">HHHHH", 0x8400, 1 if echo_question else 0, 1, 0, 0)
    owner = b"\xc0\x0c" if compressed else b"\x20" + _enc(WILDCARD) + b"\x00"
    record = owner + struct.pack(">HHIH", 0x21, 1, 0, len(rdata)) + rdata
    return header + (question if echo_question else b"") + record


GOOD_ENTRIES = [("WORKGROUP", 0x00, 0x8400), ("DISKSTATION", 0x00, 0x0400), ("DISKSTATION", 0x20, 0x0400)]


class NbstatResponder:
    """UDP-Antworter auf NBSTAT-Abfragen; merkt sich Abfragen und Absender."""

    def __init__(self, host: str, port: int, entries: list[tuple[str, int, int]] | None = None, **options) -> None:
        self.entries = entries
        self.options = options
        self.queries: list[bytes] = []
        self.senders: list[str] = []
        self.service = UdpService(host, port, self._handle)

    def _handle(self, data: bytes, addr: tuple[str, int]) -> bytes | None:
        self.queries.append(data)
        self.senders.append(addr[0])
        if self.entries is None:
            return None
        return nbstat_response(data[:2], self.entries, **self.options)

    def close(self) -> None:
        self.service.close()


@contextmanager
def responders(*specs: tuple[str, list[tuple[str, int, int]] | None], **options) -> Iterator[tuple[int, list[NbstatResponder]]]:
    """Startet je Eintrag (Host, Namenszeilen) einen Antworter, alle am selben freien UDP-Port."""
    port = free_port(specs[0][0], socket.SOCK_DGRAM)
    started = [NbstatResponder(host, port, entries, **options) for host, entries in specs]
    try:
        yield port, started
    finally:
        for r in started:
            r.close()


def closed_udp_port() -> int:
    return free_port("127.0.0.1", socket.SOCK_DGRAM)


def quiet_mdns(adapter, timeout_s):  # noqa: ANN001, ANN201
    return {}


def no_names(ip: str) -> str | None:
    return None


def run(ctx, ips, **kw):  # noqa: ANN001, ANN201
    kw.setdefault("resolver", no_names)
    kw.setdefault("mdns_browser", quiet_mdns)
    kw.setdefault("netbios_port", closed_udp_port())
    return names.resolve_names(ctx, ips, ADAPTER, **kw)


@pytest.fixture
def ctx(make_ctx):  # noqa: ANN001, ANN201
    """Kurze Zeitgrenzen, damit die Tests schnell laufen."""
    return make_ctx(names_timeout_s=0.4, mdns_timeout_s=0.3)


# --- reine Helfer --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("nas.fritz.box.", "nas.fritz.box"),
        ("  drucker  ", "drucker"),
        ("127.0.0.7", None),  # gleich der IP
        ("127.0.0.7.", None),
        ("", None),
        (".", None),
        (None, None),
        (b"bytes", None),
    ],
)
def test_clean_hostname(raw, expected):  # noqa: ANN001
    assert names._clean_hostname(raw, "127.0.0.7") == expected


def test_nbstat_query_layout():
    query = names._build_nbstat_query(0xABCD)
    assert len(query) == 50
    assert query[:2] == b"\xab\xcd"
    assert query[2:12] == bytes.fromhex("0000 0001 0000 0000 0000".replace(" ", ""))  # Flags 0, QDCOUNT 1
    assert query[12:] == b"\x20" + b"CK" + b"A" * 30 + b"\x00" + b"\x00\x21\x00\x01"  # "*" + 15 Byte Auffüllung, NBSTAT, IN


def test_encode_netbios_name():
    assert names._encode_netbios_name(WILDCARD) == b"CK" + b"A" * 30
    assert names._encode_netbios_name(b"FRED") == b"EGFCEFEE"  # F=0x46 -> "EG", R=0x52 -> "FC", E -> "EF", D -> "EE"
    assert names._encode_netbios_name(bytes([0xFF, 0x00])) == b"PPAA"


def test_parse_nbstat_first_unique_workstation_name():
    data = nbstat_response(b"\x12\x34", GOOD_ENTRIES)
    assert names._parse_nbstat_response(data) == "DISKSTATION"
    assert names._parse_nbstat_response(data, 0x1234) == "DISKSTATION"
    assert names._parse_nbstat_response(data, 0x1235) is None  # falsche Transaktions-ID


def test_parse_nbstat_skips_group_and_other_suffixes():
    only_group = nbstat_response(b"\0\1", [("WORKGROUP", 0x00, 0x8400), ("WORKGROUP", 0x1E, 0x8400), ("SRV", 0x20, 0x0400)])
    assert names._parse_nbstat_response(only_group) is None


def test_parse_nbstat_strips_padding_and_decodes_oem():
    data = nbstat_response(b"\0\1", [("BÜRO-PC", 0x00, 0x0400)])
    assert names._parse_nbstat_response(data) == "BÜRO-PC"
    nul_padded = bytearray(nbstat_response(b"\0\1", [("PC1", 0x00, 0x0400)]))
    start = bytes(nul_padded).index(b"PC1")
    nul_padded[start + 3 : start + 15] = b"\x00" * 12
    assert names._parse_nbstat_response(bytes(nul_padded)) == "PC1"


def test_parse_nbstat_compressed_owner_and_echoed_question():
    entries = [("NAS", 0x00, 0x0400)]
    assert names._parse_nbstat_response(nbstat_response(b"\0\1", entries, compressed=True)) == "NAS"
    assert names._parse_nbstat_response(nbstat_response(b"\0\1", entries, echo_question=True)) == "NAS"
    assert names._parse_nbstat_response(nbstat_response(b"\0\1", entries, compressed=True, echo_question=True)) == "NAS"


def test_parse_nbstat_too_many_declared_names_is_safe():
    data = nbstat_response(b"\0\1", [("A", 0x20, 0x0400), ("PC", 0x00, 0x0400)], declared_count=200)
    assert names._parse_nbstat_response(data) == "PC"
    data = nbstat_response(b"\0\1", [("A", 0x20, 0x0400)], declared_count=200)
    assert names._parse_nbstat_response(data) is None


def test_parse_nbstat_rejects_wrong_type_error_code_and_requests():
    good = bytearray(nbstat_response(b"\0\1", [("PC", 0x00, 0x0400)]))
    assert names._parse_nbstat_response(bytes(good)) == "PC"
    request = bytearray(good)
    request[2:4] = b"\x00\x00"  # keine Antwort
    assert names._parse_nbstat_response(bytes(request)) is None
    error = bytearray(good)
    error[2:4] = b"\x84\x03"  # Fehlercode 3
    assert names._parse_nbstat_response(bytes(error)) is None
    wrong_type = bytearray(good)
    offset = 12 + 34  # hinter dem Namen im Antwortsatz
    wrong_type[offset : offset + 2] = b"\x00\x20"  # NB statt NBSTAT
    assert names._parse_nbstat_response(bytes(wrong_type)) is None


def test_parse_nbstat_never_raises_on_broken_data():
    good = nbstat_response(b"\x12\x34", GOOD_ENTRIES, echo_question=True)
    for cut in range(len(good)):  # jede Abschneidung
        assert names._parse_nbstat_response(good[:cut]) in (None, "DISKSTATION")
    rng = random.Random(20261010)
    for _ in range(400):  # Zufallsdaten und zufällig veränderte gute Antworten
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 160)))
        found = names._parse_nbstat_response(blob)
        assert found is None or isinstance(found, str)
        mutated = bytearray(good)
        for _ in range(rng.randrange(1, 6)):
            mutated[rng.randrange(len(mutated))] = rng.randrange(256)
        result = names._parse_nbstat_response(bytes(mutated))
        assert result is None or isinstance(result, str)


def test_mdns_records_to_result():
    records = [
        ("_ipp._tcp.local.", "drucker.local.", ["127.0.0.4"]),
        ("_http._tcp.local.", "drucker.local.", ["127.0.0.4", "::1"]),
        ("_ipp._tcp.local.", "drucker.local.", ["127.0.0.4"]),  # doppelt
        ("_smb._tcp.local.", "nas.local.", ["127.0.0.3", "127.0.0.31"]),
        ("_ssh._tcp.local.", None, ["127.0.0.9"]),  # ohne Server
        ("_hap._tcp.local.", "zweiter.local.", ["127.0.0.4"]),  # erster Server gilt
        ("_x._tcp.local.", "ohne-adresse.local.", []),
        ("_y._tcp.local.", "falsch.local.", ["keine-ip", "999.1.1.1"]),
    ]
    result = names._mdns_records_to_result(records)
    assert result == {
        "127.0.0.4": ("drucker.local", ["_hap._tcp", "_http._tcp", "_ipp._tcp"]),
        "127.0.0.3": ("nas.local", ["_smb._tcp"]),
        "127.0.0.31": ("nas.local", ["_smb._tcp"]),
        "127.0.0.9": (None, ["_ssh._tcp"]),
    }
    assert names._mdns_records_to_result([]) == {}


def test_mdns_service_types_are_all_tcp_local():
    types_ = names._MDNS_SERVICE_TYPES
    assert len(types_) == 23
    assert all(t.startswith("_") and t.endswith("._tcp.local.") for t in types_)
    for wanted in ("_http", "_ipp", "_pdl-datastream", "_googlecast", "_companion-link", "_matter", "_workstation"):
        assert f"{wanted}._tcp.local." in types_


# --- DNS rückwärts -----------------------------------------------------------------------------


def test_every_ip_gets_a_nameinfo_even_empty(ctx):  # noqa: ANN001
    table = {"127.0.0.2": "fritz.box.", "127.0.0.3": "diskstation", "127.0.0.4": "127.0.0.4"}
    result = run(ctx, ["127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5"], resolver=table.get)
    assert list(result) == ["127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5"]
    assert all(isinstance(v, NameInfo) for v in result.values())
    assert result["127.0.0.2"].dns == "fritz.box"  # Schlusspunkt entfernt
    assert result["127.0.0.3"].dns == "diskstation"
    assert result["127.0.0.4"].dns is None  # Name gleich IP
    assert result["127.0.0.5"] == NameInfo()  # nichts gefunden: leer, aber vorhanden


def test_empty_ip_list_returns_empty_dict_without_work(ctx):  # noqa: ANN001
    called = []
    result = run(ctx, [], resolver=lambda ip: called.append(ip))
    assert result == {}
    assert called == []


def test_duplicate_ips_are_resolved_once(ctx):  # noqa: ANN001
    calls: list[str] = []

    def resolver(ip: str) -> str | None:
        calls.append(ip)
        return "gleich"

    result = run(ctx, ["127.0.0.2", "127.0.0.2", "127.0.0.3"], resolver=resolver)
    assert sorted(calls) == ["127.0.0.2", "127.0.0.3"]
    assert list(result) == ["127.0.0.2", "127.0.0.3"]


def test_resolver_exception_gives_none_for_that_ip_only(ctx):  # noqa: ANN001
    def resolver(ip: str) -> str | None:
        if ip.endswith(".3"):
            raise RuntimeError("kaputt")
        return "ok-" + ip.rsplit(".", 1)[1]

    result = run(ctx, ["127.0.0.2", "127.0.0.3", "127.0.0.4"], resolver=resolver)
    assert [result[ip].dns for ip in result] == ["ok-2", None, "ok-4"]


def test_resolver_returning_junk_gives_none(ctx):  # noqa: ANN001
    result = run(ctx, ["127.0.0.2", "127.0.0.3"], resolver=lambda ip: ("tuple", "statt", "text") if ip.endswith("2") else 42)  # type: ignore[arg-type,return-value]
    assert result["127.0.0.2"].dns is None
    assert result["127.0.0.3"].dns is None


def test_slow_resolver_gives_none_after_time_limit(make_ctx):  # noqa: ANN001
    ctx = make_ctx(names_timeout_s=0.3, mdns_timeout_s=0.2)
    release = threading.Event()

    def resolver(ip: str) -> str | None:
        if ip == "127.0.0.3":
            release.wait(10)  # hängt wie ein gethostbyaddr ohne Antwort
            return "kommt-zu-spaet"
        return "schnell"

    started = time.monotonic()
    try:
        result = run(ctx, ["127.0.0.2", "127.0.0.3", "127.0.0.4"], resolver=resolver)
    finally:
        elapsed = time.monotonic() - started
        release.set()
    assert result["127.0.0.2"].dns == "schnell"
    assert result["127.0.0.3"].dns is None
    assert result["127.0.0.4"].dns == "schnell"
    assert elapsed < 0.3 + 0.2 + 1.0  # names_timeout_s + mdns_timeout_s + Spielraum


def test_total_duration_is_bounded_with_hanging_resolver_and_many_ips(make_ctx):  # noqa: ANN001
    ctx = make_ctx(names_timeout_s=0.3, mdns_timeout_s=0.2)
    release = threading.Event()
    ips = [f"127.0.0.{n}" for n in range(2, 15)]
    started = time.monotonic()
    try:
        result = run(ctx, ips, resolver=lambda ip: release.wait(10) and "nie")
    finally:
        elapsed = time.monotonic() - started
        release.set()
    assert all(result[ip].dns is None for ip in ips)
    assert elapsed < 1.5


def test_dns_and_netbios_share_the_names_deadline(make_ctx):  # noqa: ANN001
    """Ein hängender Resolver darf NetBIOS nicht die Zeit nehmen, und beides zusammen dauert names_timeout_s."""
    ctx = make_ctx(names_timeout_s=0.5, mdns_timeout_s=0.2)
    release = threading.Event()
    entries = [("BUERO-PC", 0x00, 0x0400)]
    started = time.monotonic()
    try:
        with responders(("127.0.0.3", entries)) as (port, _):
            result = run(ctx, ["127.0.0.3"], resolver=lambda ip: release.wait(10) and "nie", netbios_port=port)
    finally:
        elapsed = time.monotonic() - started
        release.set()
    assert result["127.0.0.3"].dns is None
    assert result["127.0.0.3"].netbios == "BUERO-PC"
    assert elapsed < 0.5 + 0.2 + 1.0


def test_throttle_is_used_for_dns_and_netbios(ctx):  # noqa: ANN001
    class CountingRate(RateLimiter):
        def __init__(self) -> None:
            super().__init__(1000, burst=1000)
            self.calls = 0

        def acquire(self, n: float = 1.0) -> None:
            self.calls += 1

    ctx.rate = CountingRate()
    ips = [f"127.0.0.{n}" for n in range(2, 8)]
    run(ctx, ips, resolver=lambda ip: "x")
    assert ctx.rate.calls == 2 * len(ips)  # je IP ein Token für DNS und eines für die NetBIOS-Abfrage


def test_default_resolver_maps_errors_to_none(monkeypatch):  # noqa: ANN001
    monkeypatch.setattr(names.socket, "gethostbyaddr", lambda ip: ("host.lan.", [], [ip]))
    assert names._system_resolver("127.0.0.2") == "host.lan."

    def failing(ip: str):  # noqa: ANN202
        raise socket.herror(1, "Host not found")

    monkeypatch.setattr(names.socket, "gethostbyaddr", failing)
    assert names._system_resolver("127.0.0.2") is None


def test_default_resolver_is_used_when_none_is_injected(ctx, monkeypatch):  # noqa: ANN001
    seen: list[str] = []

    def fake_gethostbyaddr(ip: str):  # noqa: ANN202
        seen.append(ip)
        return ("pc-" + ip.rsplit(".", 1)[1] + ".fritz.box.", [], [ip])

    monkeypatch.setattr(names.socket, "gethostbyaddr", fake_gethostbyaddr)
    result = names.resolve_names(ctx, ["127.0.0.2", "127.0.0.3"], ADAPTER, mdns_browser=quiet_mdns, netbios_port=closed_udp_port())
    assert sorted(seen) == ["127.0.0.2", "127.0.0.3"]
    assert result["127.0.0.2"].dns == "pc-2.fritz.box"


# --- NetBIOS -----------------------------------------------------------------------------------


def test_netbios_names_from_two_hosts(ctx):  # noqa: ANN001
    with responders(("127.0.0.3", GOOD_ENTRIES), ("127.0.0.5", [("BUERO-PC", 0x00, 0x0400), ("WORKGROUP", 0x00, 0x8400)])) as (
        port,
        (nas, pc),
    ):
        result = run(ctx, ["127.0.0.3", "127.0.0.5", "127.0.0.9"], netbios_port=port)
    assert result["127.0.0.3"].netbios == "DISKSTATION"
    assert result["127.0.0.5"].netbios == "BUERO-PC"
    assert result["127.0.0.9"].netbios is None  # dort lauscht niemand
    # genau eine Abfrage je Gerät, Unicast, vom Adapter aus, im RFC-1002-Format
    for responder in (nas, pc):
        assert len(responder.queries) == 1
        query = responder.queries[0]
        assert len(query) == 50
        assert query[2:12] == bytes.fromhex("00000001000000000000")
        assert query[12:] == b"\x20" + b"CK" + b"A" * 30 + b"\x00" + b"\x00\x21\x00\x01"
        assert responder.senders == [ADAPTER.ipv4]


def test_netbios_group_only_answer_gives_none(ctx):  # noqa: ANN001
    with responders(("127.0.0.3", [("WORKGROUP", 0x00, 0x8400), ("WORKGROUP", 0x1E, 0x8400)])) as (port, _):
        result = run(ctx, ["127.0.0.3"], netbios_port=port)
    assert result["127.0.0.3"].netbios is None


@pytest.mark.parametrize("options", [{"compressed": True}, {"echo_question": True}, {"compressed": True, "echo_question": True}])
def test_netbios_answer_variants(ctx, options):  # noqa: ANN001
    with responders(("127.0.0.3", [("NAS-1", 0x00, 0x0400)]), **options) as (port, _):
        result = run(ctx, ["127.0.0.3"], netbios_port=port)
    assert result["127.0.0.3"].netbios == "NAS-1"


def test_netbios_broken_answer_gives_none(make_ctx):  # noqa: ANN001
    ctx = make_ctx(names_timeout_s=0.4, mdns_timeout_s=0.2)
    port = free_port("127.0.0.3", socket.SOCK_DGRAM)

    def broken(data: bytes, addr: tuple[str, int]) -> bytes | None:
        good = nbstat_response(data[:2], GOOD_ENTRIES)
        return {"127.0.0.3": good[:30], "127.0.0.5": data[:2] + b"\xff" * 20, "127.0.0.6": b"\x00"}[addr[0]] if False else good[:30]

    service = UdpService("127.0.0.3", port, broken)
    garbage = UdpService("127.0.0.5", port, lambda data, addr: data[:2] + b"\xff" * 20)
    try:
        started = time.monotonic()
        result = run(ctx, ["127.0.0.3", "127.0.0.5"], netbios_port=port)
        elapsed = time.monotonic() - started
    finally:
        service.close()
        garbage.close()
    assert result["127.0.0.3"].netbios is None  # abgeschnitten
    assert result["127.0.0.5"].netbios is None  # Müll
    assert elapsed < 0.4 + 0.2 + 1.0


def test_netbios_ignores_foreign_sender_and_wrong_transaction_id(make_ctx):  # noqa: ANN001
    ctx = make_ctx(names_timeout_s=0.4, mdns_timeout_s=0.2)
    port = free_port("127.0.0.3", socket.SOCK_DGRAM)
    spoof = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    spoof.bind(("127.0.0.6", 0))  # nicht angefragt

    def from_stranger(data: bytes, addr: tuple[str, int]) -> bytes | None:
        spoof.sendto(nbstat_response(data[:2], [("EVIL", 0x00, 0x0400)]), addr)
        return None

    def wrong_tid(data: bytes, addr: tuple[str, int]) -> bytes | None:
        return nbstat_response(bytes([data[0] ^ 0xFF, data[1]]), [("EVIL", 0x00, 0x0400)])

    one = UdpService("127.0.0.3", port, from_stranger)
    two = UdpService("127.0.0.5", port, wrong_tid)
    try:
        result = run(ctx, ["127.0.0.3", "127.0.0.5"], netbios_port=port)
    finally:
        one.close()
        two.close()
        spoof.close()
    assert result["127.0.0.3"].netbios is None
    assert result["127.0.0.5"].netbios is None


def test_netbios_wrong_transaction_id_packet_does_not_end_the_wait(ctx):  # noqa: ANN001
    """Ein Paket mit falscher Transaktions-ID zählt nicht als Antwort – die echte Antwort danach wird noch gelesen."""
    port = free_port("127.0.0.3", socket.SOCK_DGRAM)
    noise = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    noise.bind(("127.0.0.3", 0))

    def noise_then_answer(data: bytes, addr: tuple[str, int]) -> bytes | None:
        noise.sendto(nbstat_response(bytes([data[0] ^ 0xFF, data[1]]), [("FALSCH", 0x00, 0x0400)]), addr)
        return nbstat_response(data[:2], [("RICHTIG", 0x00, 0x0400)])

    service = UdpService("127.0.0.3", port, noise_then_answer)
    try:
        result = run(ctx, ["127.0.0.3"], netbios_port=port)
    finally:
        service.close()
        noise.close()
    assert result["127.0.0.3"].netbios == "RICHTIG"


def test_no_dns_lookup_is_started_after_the_time_limit(make_ctx):  # noqa: ANN001
    ctx = make_ctx(names_timeout_s=0.0, mdns_timeout_s=0.2)
    called: list[str] = []
    result = run(ctx, ["127.0.0.2", "127.0.0.3"], resolver=lambda ip: called.append(ip) or "x")
    assert called == []
    assert all(info.dns is None for info in result.values())


def test_netbios_closed_ports_do_not_hide_real_answers(ctx):  # noqa: ANN001
    """Unter Windows meldet recvfrom nach einer Sendung an einen geschlossenen Port einen Fehler (WSAECONNRESET)."""
    ips = [f"127.0.0.{n}" for n in (2, 4, 6, 7, 8)] + ["127.0.0.5"]
    with responders(("127.0.0.5", [("NACH-FEHLERN", 0x00, 0x0400)])) as (port, _):
        result = run(ctx, ips, netbios_port=port)
    assert result["127.0.0.5"].netbios == "NACH-FEHLERN"
    assert all(result[ip].netbios is None for ip in ips if ip != "127.0.0.5")


def test_netbios_waits_no_longer_than_needed_when_all_answered(make_ctx):  # noqa: ANN001
    ctx = make_ctx(names_timeout_s=2.0, mdns_timeout_s=0.2)
    started = time.monotonic()
    with responders(("127.0.0.3", [("A", 0x00, 0x0400)]), ("127.0.0.5", [("B", 0x00, 0x0400)])) as (port, _):
        result = run(ctx, ["127.0.0.3", "127.0.0.5"], netbios_port=port)
    assert time.monotonic() - started < 1.5  # nicht die vollen 2 s
    assert (result["127.0.0.3"].netbios, result["127.0.0.5"].netbios) == ("A", "B")


def test_netbios_skips_non_ipv4_entries(ctx):  # noqa: ANN001
    result = run(ctx, ["::1", "kein-ip"], resolver=lambda ip: None)
    assert set(result) == {"::1", "kein-ip"}
    assert all(info == NameInfo() for info in result.values())


def test_netbios_bind_failure_is_logged_not_raised(ctx):  # noqa: ANN001
    bad = make_adapter("Ethernet", ipv4="203.0.113.77", network="203.0.113.0/24")  # keine lokale Adresse: bind scheitert
    result = names.resolve_names(ctx, ["127.0.0.2"], bad, resolver=lambda ip: "dns-name", mdns_browser=quiet_mdns)
    assert result["127.0.0.2"].dns == "dns-name"
    assert result["127.0.0.2"].netbios is None
    warnings = [e for e in ctx.bus.history(type_prefix="job.log") if e.data["level"] == "warning"]
    assert any("NetBIOS" in e.data["message"] for e in warnings)


# --- mDNS mit eingespeistem Browser --------------------------------------------------------------


def test_injected_mdns_browser_fills_names_and_services(ctx):  # noqa: ANN001
    calls: list[tuple[object, float]] = []

    def browser(adapter, timeout_s):  # noqa: ANN001, ANN202
        calls.append((adapter, timeout_s))
        return {
            "127.0.0.4": ("drucker.local.", ["_ipp._tcp", "_http._tcp", "_ipp._tcp"]),
            "127.0.0.3": (None, ["_smb._tcp"]),
            "127.0.0.99": ("fremd.local", ["_ssh._tcp"]),  # nicht angefragt
        }

    result = run(ctx, ["127.0.0.3", "127.0.0.4", "127.0.0.5"], mdns_browser=browser)
    assert calls == [(ADAPTER, 0.3)]  # Adapter und settings.mdns_timeout_s
    assert result["127.0.0.4"].mdns == "drucker.local"
    assert result["127.0.0.4"].mdns_services == ["_ipp._tcp", "_http._tcp"]
    assert result["127.0.0.3"].mdns is None
    assert result["127.0.0.3"].mdns_services == ["_smb._tcp"]
    assert result["127.0.0.5"] == NameInfo()
    assert "127.0.0.99" not in result


def test_mdns_error_gives_empty_result_and_warning(ctx):  # noqa: ANN001
    def browser(adapter, timeout_s):  # noqa: ANN001, ANN202
        raise OSError("Port 5353 belegt")

    result = run(ctx, ["127.0.0.2"], mdns_browser=browser, resolver=lambda ip: "dns-name")
    assert result["127.0.0.2"].dns == "dns-name"  # die anderen Wege laufen weiter
    assert result["127.0.0.2"].mdns is None
    assert result["127.0.0.2"].mdns_services == []
    warnings = [e.data["message"] for e in ctx.bus.history(type_prefix="job.log") if e.data["level"] == "warning"]
    assert any("mDNS" in m and "5353" in m for m in warnings)


@pytest.mark.parametrize("junk", [None, ["liste"], {"127.0.0.2": "kein-tupel"}, {"127.0.0.2": ("a",)}])
def test_mdns_junk_result_is_handled(ctx, junk):  # noqa: ANN001
    result = run(ctx, ["127.0.0.2"], mdns_browser=lambda adapter, timeout_s: junk)
    assert result["127.0.0.2"].mdns is None


def test_best_name_order_with_all_sources(ctx):  # noqa: ANN001
    with responders(("127.0.0.3", [("NAS-NB", 0x00, 0x0400)])) as (port, _):
        result = run(
            ctx,
            ["127.0.0.3"],
            resolver=lambda ip: "nas.fritz.box.",
            netbios_port=port,
            mdns_browser=lambda adapter, timeout_s: {"127.0.0.3": ("nas.local.", ["_smb._tcp"])},
        )
    info = result["127.0.0.3"]
    assert (info.dns, info.netbios, info.mdns) == ("nas.fritz.box", "NAS-NB", "nas.local")
    assert info.best() == "nas.fritz.box"


# --- mDNS mit Attrappe des zeroconf-Moduls (kein Paket, kein Multicast) -------------------------


class FakeZeroconfWorld:
    """Ersetzt das Modul zeroconf: merkt sich Aufrufe und liefert vorgegebene Dienste."""

    def __init__(self, services: list[dict], fail_constructor: Exception | None = None) -> None:
        self.services = services
        self.created: list[object] = []
        self.browsers: list[object] = []
        self.requests: list[str] = []
        world = self

        class IPVersion(enum.Enum):
            V4Only = 1
            V6Only = 2
            All = 3

        class ServiceStateChange(enum.Enum):
            Added = 1
            Removed = 2
            Updated = 3

        class Zeroconf:
            def __init__(self, interfaces=None, ip_version=None, **kwargs) -> None:  # noqa: ANN001, ANN003
                if fail_constructor is not None:
                    raise fail_constructor
                self.interfaces = interfaces
                self.ip_version = ip_version
                self.closed = False
                world.created.append(self)

            def close(self) -> None:
                self.closed = True

        class ServiceBrowser:
            def __init__(self, zc, type_, handlers=None, **kwargs) -> None:  # noqa: ANN001, ANN003
                self.zc = zc
                self.types = type_
                self.cancelled = False
                world.browsers.append(self)
                for svc in world.services:
                    if svc["type"] in type_:
                        for handler in handlers or []:
                            # wie zeroconf: nur Schlüsselwortargumente
                            handler(zeroconf=zc, service_type=svc["type"], name=svc["name"], state_change=svc.get("change", ServiceStateChange.Added))

            def cancel(self) -> None:
                self.cancelled = True

        class ServiceInfo:
            def __init__(self, type_: str, name: str) -> None:
                self.type = type_
                self.name = name
                self._svc = next(s for s in world.services if s["name"] == name)
                self.server = None

            def _fill(self) -> None:
                if self._svc.get("explode"):
                    raise RuntimeError("kaputt")
                self.server = self._svc["server"]

            def load_from_cache(self, zc) -> bool:  # noqa: ANN001
                if self._svc.get("cached", True):
                    self._fill()
                    return True
                return False

            def request(self, zc, timeout) -> bool:  # noqa: ANN001
                world.requests.append(self.name)
                if self._svc.get("answers", False):
                    self._fill()
                    return True
                return False

            def parsed_addresses(self, version=None) -> list[str]:  # noqa: ANN001
                return list(self._svc["addresses"])

        self.module = types.ModuleType("zeroconf")
        self.module.IPVersion = IPVersion  # type: ignore[attr-defined]
        self.module.ServiceStateChange = ServiceStateChange  # type: ignore[attr-defined]
        self.module.Zeroconf = Zeroconf  # type: ignore[attr-defined]
        self.module.ServiceBrowser = ServiceBrowser  # type: ignore[attr-defined]
        self.module.ServiceInfo = ServiceInfo  # type: ignore[attr-defined]


SERVICES = [
    {"type": "_smb._tcp.local.", "name": "NAS._smb._tcp.local.", "server": "nas.local.", "addresses": ["127.0.0.3"]},
    {"type": "_http._tcp.local.", "name": "NAS-Web._http._tcp.local.", "server": "nas.local.", "addresses": ["127.0.0.3", "fe80::1"]},
    {"type": "_ipp._tcp.local.", "name": "Drucker._ipp._tcp.local.", "server": "drucker.local.", "addresses": ["127.0.0.4"], "cached": False, "answers": True},
    {"type": "_ssh._tcp.local.", "name": "Stumm._ssh._tcp.local.", "server": "stumm.local.", "addresses": ["127.0.0.6"], "cached": False, "answers": False},
    {"type": "_hap._tcp.local.", "name": "Defekt._hap._tcp.local.", "server": "x.local.", "addresses": ["127.0.0.7"], "explode": True},
    {"type": "_airplay._tcp.local.", "name": "Weg._airplay._tcp.local.", "server": "weg.local.", "addresses": ["127.0.0.8"], "change": "removed"},
]


def install_fake_zeroconf(monkeypatch, services=SERVICES, **kw):  # noqa: ANN001, ANN201
    world = FakeZeroconfWorld([dict(s) for s in services], **kw)
    for svc in world.services:
        if svc.get("change") == "removed":
            svc["change"] = world.module.ServiceStateChange.Removed
    monkeypatch.setitem(sys.modules, "zeroconf", world.module)
    return world


def test_default_mdns_browser_with_fake_zeroconf(make_ctx, monkeypatch):  # noqa: ANN001
    ctx = make_ctx(names_timeout_s=0.3, mdns_timeout_s=0.25)
    world = install_fake_zeroconf(monkeypatch)
    result = names.resolve_names(
        ctx, ["127.0.0.3", "127.0.0.4", "127.0.0.5", "127.0.0.6", "127.0.0.7", "127.0.0.8"], ADAPTER,
        resolver=no_names, netbios_port=closed_udp_port(),
    )  # fmt: skip
    assert result["127.0.0.3"].mdns == "nas.local"
    assert result["127.0.0.3"].mdns_services == ["_http._tcp", "_smb._tcp"]
    assert result["127.0.0.4"].mdns == "drucker.local"  # nicht im Zwischenspeicher: kurz angefragt
    assert result["127.0.0.4"].mdns_services == ["_ipp._tcp"]
    assert result["127.0.0.5"] == NameInfo()
    assert result["127.0.0.6"].mdns is None  # keine Antwort auf die Anfrage: übersprungen
    assert result["127.0.0.7"].mdns is None  # Auflösung warf eine Ausnahme: übersprungen
    assert result["127.0.0.8"].mdns is None  # „Removed“-Ereignis zählt nicht
    assert "Drucker._ipp._tcp.local." in world.requests
    # Aufbau: ein Zeroconf nur auf dem Adapter, nur IPv4, alle gängigen Diensttypen, am Ende alles geschlossen
    (zc,) = world.created
    assert zc.interfaces == [ADAPTER.ipv4]  # type: ignore[attr-defined]
    assert zc.ip_version == world.module.IPVersion.V4Only  # type: ignore[attr-defined]
    assert zc.closed is True  # type: ignore[attr-defined]
    (browser,) = world.browsers
    assert list(browser.types) == list(names._MDNS_SERVICE_TYPES)  # type: ignore[attr-defined]
    assert browser.cancelled is True  # type: ignore[attr-defined]


def test_default_mdns_browser_collects_for_the_timeout(make_ctx, monkeypatch):  # noqa: ANN001
    ctx = make_ctx(names_timeout_s=0.2, mdns_timeout_s=0.5)
    install_fake_zeroconf(monkeypatch, services=[])
    started = time.monotonic()
    result = run(ctx, ["127.0.0.2"], mdns_browser=None)
    assert time.monotonic() - started >= 0.5
    assert result["127.0.0.2"] == NameInfo()


def test_default_mdns_browser_closes_zeroconf_on_cancel(make_ctx, monkeypatch):  # noqa: ANN001
    ctx = make_ctx(names_timeout_s=0.2, mdns_timeout_s=5.0)
    world = install_fake_zeroconf(monkeypatch)
    timer = threading.Timer(0.4, ctx.cancel.cancel)
    timer.start()
    started = time.monotonic()
    try:
        with pytest.raises(ScanCancelled):
            run(ctx, ["127.0.0.3"], mdns_browser=None)
    finally:
        timer.cancel()
    assert time.monotonic() - started < 2.0  # weit unter den 5 s Sammelzeit
    assert world.created[0].closed is True  # type: ignore[attr-defined]
    assert world.browsers[0].cancelled is True  # type: ignore[attr-defined]


def test_default_mdns_browser_error_gives_empty_result_and_warning(ctx, monkeypatch):  # noqa: ANN001
    install_fake_zeroconf(monkeypatch, fail_constructor=OSError("keine Schnittstelle"))
    result = run(ctx, ["127.0.0.3"], mdns_browser=None, resolver=lambda ip: "dns-name")
    assert result["127.0.0.3"].dns == "dns-name"
    assert result["127.0.0.3"].mdns is None
    warnings = [e.data["message"] for e in ctx.bus.history(type_prefix="job.log") if e.data["level"] == "warning"]
    assert any("mDNS" in m and "keine Schnittstelle" in m for m in warnings)


# --- Abbruch, Fortschritt, Protokoll -------------------------------------------------------------


def test_already_cancelled_context_raises_immediately(ctx):  # noqa: ANN001
    ctx.cancel.cancel()
    called = []
    with pytest.raises(ScanCancelled):
        run(ctx, ["127.0.0.2"], resolver=lambda ip: called.append(ip))
    assert called == []


def test_cancel_during_dns_wait_acts_within_five_seconds(make_ctx):  # noqa: ANN001
    ctx = make_ctx(names_timeout_s=2.0, mdns_timeout_s=3.0)
    release = threading.Event()
    timer = threading.Timer(0.2, ctx.cancel.cancel)
    timer.start()
    started = time.monotonic()
    try:
        with pytest.raises(ScanCancelled):
            run(ctx, ["127.0.0.2", "127.0.0.3"], resolver=lambda ip: release.wait(10) and "nie")
    finally:
        timer.cancel()
        release.set()
    assert time.monotonic() - started < 1.5


def test_cancel_during_netbios_collection(make_ctx):  # noqa: ANN001
    ctx = make_ctx(names_timeout_s=2.0, mdns_timeout_s=3.0)
    timer = threading.Timer(0.2, ctx.cancel.cancel)
    timer.start()
    started = time.monotonic()
    try:
        with pytest.raises(ScanCancelled):
            run(ctx, ["127.0.0.2", "127.0.0.3"])  # niemand antwortet, NetBIOS würde 2 s warten
    finally:
        timer.cancel()
    assert time.monotonic() - started < 1.5


def test_cancel_during_injected_mdns_browser(make_ctx):  # noqa: ANN001
    ctx = make_ctx(names_timeout_s=0.2, mdns_timeout_s=0.2)

    def browser(adapter, timeout_s):  # noqa: ANN001, ANN202
        ctx.cancel.cancel()  # Abbruch während der Suche, der Browser selbst merkt nichts
        return {"127.0.0.2": ("nie.local", [])}

    with pytest.raises(ScanCancelled):
        run(ctx, ["127.0.0.2"], mdns_browser=browser)


def test_progress_events_use_the_names_phase_and_finish_complete(ctx):  # noqa: ANN001
    run(ctx, ["127.0.0.2", "127.0.0.3", "127.0.0.4"], resolver=lambda ip: "x")
    events = [e.data for e in ctx.bus.history(type_prefix="job.progress")]
    assert events, "kein Fortschritt gemeldet"
    assert {e["phase"] for e in events} == {"Namen"}
    assert all(0 <= e["done"] <= e["total"] for e in events)
    assert events[-1]["done"] == events[-1]["total"]
    assert "3 von 3" in events[-1]["message"]


def test_summary_line_goes_to_the_log(ctx):  # noqa: ANN001
    run(ctx, ["127.0.0.2", "127.0.0.3"], resolver=lambda ip: "x" if ip.endswith("2") else None)
    messages = [e.data["message"] for e in ctx.bus.history(type_prefix="job.log")]
    assert any(m.startswith("Namen: 1 von 2") and "DNS 1" in m for m in messages)


def test_lan_lock_stops_netbios_to_a_non_loopback_address(ctx):  # noqa: ANN001
    """Absicherung: ein Versuch, ins LAN zu senden, fällt auf (conftest sperrt es) und wird nicht verschluckt."""
    from tests.conftest import LanTrafficError

    with pytest.raises(LanTrafficError):
        run(ctx, ["192.168.178.50"])  # NetBIOS-Abfrage an eine Nicht-Loopback-Adresse
