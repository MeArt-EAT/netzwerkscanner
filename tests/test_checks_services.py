"""Dienstprüfungen tcp, http, https, ssh, smb (BAUPLAN §23) gegen simulierte Dienste auf 127.0.0.x.

checks.connect wird per lab.translating_connect auf die Sim-Ports umgeleitet (echter Port -> Sim-Port,
unbekannter Port = abgelehnt). Für „nimmt an und schweigt“ dient ein lauschender Socket ohne accept().
"""

from __future__ import annotations

import errno
import socket
import struct
import sys
import time

import pytest

from netscan.net import checks, ports
from tests.sim import SimDevice, SimLab

ORIGINAL_CONNECT = checks.connect
NAS, PC = "127.0.0.3", "127.0.0.4"
FAST = 0.5  # Zeitgrenze der Tests in Sekunden (kurz, damit kein Test lange wartet)


def _devices() -> list[SimDevice]:
    return [
        SimDevice(NAS, "00:11:32:aa:bb:03", "NAS",
                  tcp={22: b"SSH-2.0-OpenSSH_9.6\r\n", 23: b"BusyBox v1.31 login: ", 8081: b"Hallo, kein HTTP\r\n",
                       2200: b"SSH-2.0-" + b"X" * 80 + b"\x1b[0m\x07\r\n", 9000: b""},
                  smb=(445,),
                  http={5000: {"/": ("text/html", b"<title>DSM</title>"), "/login": ("text/plain", b"x", 401),
                               "/kaputt": ("text/plain", b"x", 503), "/umzug": ("text/plain", b"", 301)}},
                  https={5001: {"/": ("text/html", b"<title>DSM</title>"), "/kaputt": ("text/plain", b"x", 500)}}),
        SimDevice(PC, "00:1b:21:aa:bb:04", "PC", tcp={445: b""}),  # Port 445 offen, aber kein SMB
    ]  # fmt: skip


@pytest.fixture(scope="module")
def lab():  # type: ignore[no-untyped-def]
    with SimLab(_devices()) as lab:
        yield lab


@pytest.fixture
def sim(lab, monkeypatch):  # type: ignore[no-untyped-def]
    calls: list[tuple[str, int]] = []
    translate = lab.translating_connect(ORIGINAL_CONNECT)

    def counting(ip, port, timeout_s, source_ip=None):  # type: ignore[no-untyped-def]
        calls.append((ip, port))
        return translate(ip, port, timeout_s, source_ip)

    monkeypatch.setattr(checks, "connect", counting)
    lab.connect_calls = calls
    return lab


@pytest.fixture
def silent():  # type: ignore[no-untyped-def]
    """Dienst, der annimmt und schweigt: lauschender Socket ohne accept() (Kernel schließt den Aufbau ab)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    yield srv.getsockname()[1]
    srv.close()


class FakeSock:
    """Socket-Attrappe für Protokolldetails: liefert vorgegebene Antworten, merkt sich Gesendetes."""

    def __init__(self, chunks: list[bytes | BaseException] | None = None) -> None:
        self.chunks = list(chunks or [])
        self.sent = b""
        self.read = 0
        self.recv_calls = 0
        self.closed = False

    def settimeout(self, _t: float | None) -> None:
        pass

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def recv(self, n: int) -> bytes:
        self.recv_calls += 1
        if not self.chunks:
            return b""
        item = self.chunks.pop(0)
        if isinstance(item, BaseException):
            raise item
        if len(item) > n:
            self.chunks.insert(0, item[n:])
            item = item[:n]
        self.read += len(item)
        return item

    def close(self) -> None:
        self.closed = True


def _use(monkeypatch, sock: FakeSock) -> FakeSock:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(checks, "connect", lambda ip, port, timeout_s, source_ip=None: sock)
    return sock


def _raising(exc: BaseException):  # type: ignore[no-untyped-def]
    def connect(ip, port, timeout_s, source_ip=None):  # type: ignore[no-untyped-def]
        raise exc

    return connect


# --- tcp ----------------------------------------------------------------------------------------


def test_tcp_open(sim) -> None:  # type: ignore[no-untyped-def]
    res = checks.check_tcp(NAS, 22, FAST)
    assert res.ok and res.detail == "Port offen" and res.method == "tcp:22" and res.code is None
    assert isinstance(res.rtt_ms, float) and res.rtt_ms >= 0 and round(res.rtt_ms, 1) == res.rtt_ms


def test_tcp_refused(sim) -> None:  # type: ignore[no-untyped-def]
    res = checks.check_tcp(NAS, 3389, FAST)
    assert not res.ok and res.detail == "Port geschlossen" and res.method == "tcp:3389" and res.rtt_ms is None


def test_tcp_timeout(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(checks, "connect", _raising(TimeoutError("timed out")))
    res = checks.check_tcp(NAS, 80, FAST)
    assert not res.ok and res.detail == "keine Antwort" and res.method == "tcp:80"


@pytest.mark.parametrize(
    ("exc", "detail"),
    [
        (OSError(errno.EHOSTUNREACH, "x"), "nicht erreichbar (keine Route zum Gerät)"),
        (OSError(errno.ENETUNREACH, "x"), "nicht erreichbar (Netz nicht erreichbar)"),
        (ConnectionResetError(errno.ECONNRESET, "x"), "nicht erreichbar (Verbindung zurückgesetzt)"),
        (OSError(9999, "x"), "nicht erreichbar (Fehler 9999)"),
        (OSError("ohne Nummer"), "nicht erreichbar (OSError)"),
    ],
)
def test_tcp_other_errors(monkeypatch, exc, detail) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(checks, "connect", _raising(exc))
    assert checks.check_tcp(NAS, 80, FAST).detail == detail


def test_tcp_silent_service_counts_as_open(silent) -> None:  # type: ignore[no-untyped-def]
    assert checks.check_tcp("127.0.0.1", silent, FAST).ok


def test_stopped_service_is_down_and_back_up(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    with SimLab([SimDevice("127.0.0.5", "00:1b:21:aa:bb:05", "PC", tcp={8080: b""})]) as lab:
        monkeypatch.setattr(checks, "connect", lab.translating_connect(ORIGINAL_CONNECT))
        assert checks.check_tcp("127.0.0.5", 8080, 0.3).ok
        lab.stop_service("127.0.0.5", 8080)
        res = checks.check_tcp("127.0.0.5", 8080, 0.3)
        # Windows meldet „abgelehnt“ auf Loopback erst nach ~2 s Wiederholungen ⇒ dort Zeitüberschreitung
        assert not res.ok and res.detail in ("Port geschlossen", "keine Antwort")
        lab.start_service("127.0.0.5", 8080)
        assert checks.check_tcp("127.0.0.5", 8080, 0.3).ok


@pytest.mark.skipif(sys.platform == "win32", reason="Windows wiederholt den Aufbau nach RST ~2 s (Zeitüberschreitung)")
def test_tcp_real_refusal_is_port_closed() -> None:
    free = socket.socket()
    free.bind(("127.0.0.1", 0))
    port = free.getsockname()[1]
    free.close()
    assert checks.check_tcp("127.0.0.1", port, FAST).detail == "Port geschlossen"


# --- http ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "ok", "code"),
    [("/", True, 200), ("/login", True, 401), ("/gibtsnicht", True, 404), ("/umzug", True, 301),
     ("/kaputt", False, 503)],
)  # fmt: skip
def test_http_status_codes(sim, path, ok, code) -> None:  # type: ignore[no-untyped-def]
    res = checks.check_http(NAS, 5000, FAST, path=path)
    assert (res.ok, res.code, res.detail, res.method) == (ok, code, f"HTTP {code}", "http:5000")
    assert res.rtt_ms is not None
    assert sim.connect_calls == [(NAS, 5000)]  # genau eine Verbindung, keine Weiterleitung verfolgt


def test_http_garbage_is_invalid(sim) -> None:  # type: ignore[no-untyped-def]
    res = checks.check_http(NAS, 8081, FAST)
    assert not res.ok and res.detail == "keine gültige HTTP-Antwort" and res.code is None


def test_http_against_ssh_banner_is_invalid(sim) -> None:  # type: ignore[no-untyped-def]
    assert checks.check_http(NAS, 22, FAST).detail == "keine gültige HTTP-Antwort"


def test_http_service_closing_without_answer_is_invalid(sim) -> None:  # type: ignore[no-untyped-def]
    # Dienst nimmt an, liest die Anfrage und schließt ohne Antwort
    assert checks.check_http(NAS, 9000, FAST).detail == "keine gültige HTTP-Antwort"


def test_http_silent_service_times_out(silent) -> None:  # type: ignore[no-untyped-def]
    t0 = time.monotonic()
    res = checks.check_http("127.0.0.1", silent, 0.3)
    assert not res.ok and res.detail == "keine Antwort" and res.method == f"http:{silent}"
    assert time.monotonic() - t0 < 1.5


def test_http_refused(sim) -> None:  # type: ignore[no-untyped-def]
    assert checks.check_http(NAS, 80, FAST).detail == "Port geschlossen"


def test_http_against_https_port_is_invalid(sim) -> None:  # type: ignore[no-untyped-def]
    res = checks.check_http(NAS, 5001, FAST)
    assert not res.ok and res.detail == "keine gültige HTTP-Antwort"


def test_http_request_is_minimal(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    sock = _use(monkeypatch, FakeSock([b"HTTP/1.1 204 No Content\r\nServer: x\r\n\r\n"]))
    res = checks.check_http("127.0.0.3", 8080, FAST, path="/status?x=1")
    assert res.ok and res.code == 204 and res.detail == "HTTP 204"
    assert sock.sent == (
        b"GET /status?x=1 HTTP/1.1\r\nHost: 127.0.0.3\r\nUser-Agent: Netzwerkscanner-Monitor\r\n"
        b"Connection: close\r\n\r\n"
    )
    assert sock.closed


def test_http_non_ascii_path_is_percent_encoded(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    sock = _use(monkeypatch, FakeSock([b"HTTP/1.0 200 OK\r\n"]))
    assert checks.check_http("127.0.0.3", 80, FAST, path="/über").ok
    assert sock.sent.startswith(b"GET /%C3%BCber HTTP/1.1\r\n")


@pytest.mark.parametrize("path", ["status", "", "/a b", "/a\r\nX-Evil: 1", "/a\tb", "/\x7f", "/" + "a" * 200, 5, b"/"])
def test_http_rejects_bad_path_before_connecting(monkeypatch, path) -> None:  # type: ignore[no-untyped-def]
    called: list[object] = []
    monkeypatch.setattr(checks, "connect", lambda *a, **k: called.append(a))
    with pytest.raises(ValueError):
        checks.check_http("127.0.0.3", 80, FAST, path=path)
    assert called == []


def test_http_path_limit_is_inclusive(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    _use(monkeypatch, FakeSock([b"HTTP/1.1 200 OK\r\n"]))
    assert checks.check_http("127.0.0.3", 80, FAST, path="/" + "a" * 199).ok


def test_http_reads_at_most_4096_bytes(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    sock = _use(monkeypatch, FakeSock([b"A" * 1024] * 10))
    res = checks.check_http("127.0.0.3", 80, FAST)
    assert res.detail == "keine gültige HTTP-Antwort"
    assert sock.read <= 4096


def test_http_overall_deadline_with_drip_feed(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # Ein Dienst, der Byte für Byte tröpfelt, darf die Frist nicht verlängern (Uhr injiziert, kein Warten)
    clock = {"now": 1000.0}

    def tick() -> float:
        clock["now"] += 0.1
        return clock["now"]

    monkeypatch.setattr(checks, "_monotonic", tick)
    sock = _use(monkeypatch, FakeSock([b"H"] * 1000))
    res = checks.check_http("127.0.0.3", 80, 1.0)
    assert not res.ok and res.detail == "keine gültige HTTP-Antwort"
    assert sock.recv_calls <= 12


def test_http_connection_reset_while_reading(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    _use(monkeypatch, FakeSock([ConnectionResetError(errno.ECONNRESET, "reset")]))
    assert checks.check_http("127.0.0.3", 80, FAST).detail == "keine gültige HTTP-Antwort"


@pytest.mark.parametrize(
    ("data", "why", "code"),
    [
        (b"HTTP/1.1 200 OK\r\n", "ok", 200),
        (b"HTTP/1.0 404\r\nX: y", "ok", 404),
        (b"HTTP/1.1 503 Service Unavailable\n", "ok", 503),
        (b"HTTP/2 200\r\n", "ok", 200),
        (b"HTTP/1.1 200 OK", "eof", 200),
        (b"HTTP/1.1 200 OK", "timeout", None),
        (b"HTTP/1.1 200 OK", "limit", None),
        (b"HTTP/1.1 600 Unsinn\r\n", "ok", None),
        (b"HTTP/1.1 099 Unsinn\r\n", "ok", None),
        (b"HTTP/1.1 20 OK\r\n", "ok", None),
        (b"http/1.1 200 OK\r\n", "ok", None),
        (b" HTTP/1.1 200 OK\r\n", "ok", None),
        (b"SSH-2.0-OpenSSH\r\n", "ok", None),
        (b"", "eof", None),
    ],
)
def test_status_line_parsing(data, why, code) -> None:  # type: ignore[no-untyped-def]
    assert checks._status_code(data, why) == code


# --- https --------------------------------------------------------------------------------------


def test_https_with_self_signed_test_certificate(sim) -> None:  # type: ignore[no-untyped-def]
    res = checks.check_http(NAS, 5001, FAST, tls=True)
    assert (res.ok, res.code, res.detail, res.method) == (True, 200, "HTTPS 200", "https:5001")
    assert res.rtt_ms is not None


def test_https_server_error_is_down(sim) -> None:  # type: ignore[no-untyped-def]
    res = checks.run_check("https", NAS, 5001, FAST, path="/kaputt")
    assert not res.ok and res.code == 500 and res.detail == "HTTPS 500"


def test_tls_against_plaintext_port_fails_cleanly(sim) -> None:  # type: ignore[no-untyped-def]
    t0 = time.monotonic()
    res = checks.check_http(NAS, 5000, FAST, tls=True)
    assert not res.ok and res.detail == "TLS-Aushandlung fehlgeschlagen" and res.method == "https:5000"
    assert time.monotonic() - t0 < 2.5


def test_tls_against_banner_port_fails(sim) -> None:  # type: ignore[no-untyped-def]
    assert checks.check_http(NAS, 22, FAST, tls=True).detail == "TLS-Aushandlung fehlgeschlagen"


def test_tls_against_silent_service_times_out(silent) -> None:  # type: ignore[no-untyped-def]
    t0 = time.monotonic()
    res = checks.check_http("127.0.0.1", silent, 0.3, tls=True)
    assert res.detail == "TLS-Aushandlung fehlgeschlagen"
    assert time.monotonic() - t0 < 1.5


# --- ssh ----------------------------------------------------------------------------------------


def test_ssh_banner_ok(sim) -> None:  # type: ignore[no-untyped-def]
    res = checks.check_ssh(NAS, 22, FAST)
    assert res.ok and res.detail == "SSH-2.0-OpenSSH_9.6" and res.method == "ssh:22" and res.rtt_ms is not None


def test_ssh_wrong_banner(sim) -> None:  # type: ignore[no-untyped-def]
    res = checks.check_ssh(NAS, 23, FAST)
    assert not res.ok and res.detail == "keine SSH-Kennung" and res.method == "ssh:23"


def test_ssh_banner_is_cleaned_and_shortened(sim) -> None:  # type: ignore[no-untyped-def]
    res = checks.run_check("ssh", NAS, 2200, FAST)
    assert res.ok and res.detail.startswith("SSH-2.0-XXX")
    assert len(res.detail) <= 60 and res.detail.isprintable() and "\x1b" not in res.detail


def test_foreign_banner_ends_reading_early(sim, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # Telnet-Banner ohne Zeilenende: Der Anfang passt nicht zu „SSH-“, also nicht bis zur Zeitgrenze warten
    t0 = time.monotonic()
    assert checks.check_ssh(NAS, 23, 2.0).detail == "keine SSH-Kennung"
    assert time.monotonic() - t0 < 1.0
    sock = _use(monkeypatch, FakeSock([b"Hallo"] + [b"x"] * 50))
    assert checks.check_http("127.0.0.3", 80, 2.0).detail == "keine gültige HTTP-Antwort"
    assert sock.recv_calls == 1


def test_ssh_silent_service(silent) -> None:  # type: ignore[no-untyped-def]
    res = checks.check_ssh("127.0.0.1", silent, 0.3)
    assert not res.ok and res.detail == "keine Antwort"


def test_ssh_closed_and_empty(sim, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    assert checks.check_ssh(NAS, 2222, FAST).detail == "Port geschlossen"
    _use(monkeypatch, FakeSock([]))  # schließt sofort ohne Kennung
    assert checks.check_ssh(NAS, 22, FAST).detail == "keine SSH-Kennung"


def test_ssh_reads_at_most_255_bytes_and_sends_nothing(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    sock = _use(monkeypatch, FakeSock([b"SSH-2.0-" + b"Y" * 1000]))
    res = checks.check_ssh("127.0.0.3", 22, FAST)
    assert res.ok and len(res.detail) == 60
    assert sock.read <= 255 and sock.sent == b""


# --- smb ----------------------------------------------------------------------------------------


def test_smb_negotiate_answer_ok(sim) -> None:  # type: ignore[no-untyped-def]
    res = checks.check_smb(NAS, 445, FAST)
    assert res.ok and res.method == "smb:445" and res.detail == "SMB2-Antwort" and res.rtt_ms is not None


def test_smb_plain_tcp_on_445_is_down(sim) -> None:  # type: ignore[no-untyped-def]
    res = checks.check_smb(PC, 445, FAST)
    assert not res.ok and res.detail == "Port offen, aber keine SMB-Antwort"


def test_smb_silent_service_is_down(silent) -> None:  # type: ignore[no-untyped-def]
    res = checks.check_smb("127.0.0.1", silent, 0.3)
    assert res.detail == "Port offen, aber keine SMB-Antwort"


def test_smb_closed(sim) -> None:  # type: ignore[no-untyped-def]
    assert checks.check_smb(PC, 139, FAST).detail == "Port geschlossen"


def test_smb2_negotiate_request_structure() -> None:
    req = checks._smb2_negotiate_request()
    assert req[0] == 0 and int.from_bytes(req[1:4], "big") == len(req) - 4
    msg = req[4:]
    assert msg[:4] == b"\xfeSMB" and len(msg) == 64 + 36 + 6
    structure_size, credit_charge, status, command = struct.unpack_from("<HHIH", msg, 4)
    assert (structure_size, credit_charge, status, command) == (64, 0, 0, 0)
    assert msg[48:64] == bytes(16)  # keine Signatur, keine Sitzung
    assert struct.unpack_from("<Q", msg, 40)[0] == 0  # SessionId 0 = keine Anmeldung
    body_size, dialect_count = struct.unpack_from("<HH", msg, 64)
    assert (body_size, dialect_count) == (36, 3)
    assert struct.unpack_from("<3H", msg, 64 + 36) == (0x0202, 0x0210, 0x0300)


def test_smb_sends_negotiate_and_reads_dialect(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    header = b"\xfeSMB" + struct.pack("<HHIHH", 64, 0, 0, 0, 1) + bytes(48)
    body = struct.pack("<HHH", 65, 1, 0x0300) + bytes(58)
    reply = len(header + body).to_bytes(4, "big") + header + body
    sock = _use(monkeypatch, FakeSock([reply[:10], reply[10:]]))
    res = checks.check_smb("127.0.0.3", 445, FAST)
    assert res.ok and res.detail == "SMB 3.0"
    assert len(sock.sent) == 4 + 64 + 36 + 6 and sock.sent[4:8] == b"\xfeSMB" and sock.closed


@pytest.mark.parametrize(
    ("reply", "ok", "detail"),
    [
        (b"\x00\x00\x00\x23\xffSMBr" + bytes(30), True, "SMB1-Antwort"),
        (b"\x00\x00\x00\x40\xfeSMB" + bytes(60), True, "SMB2-Antwort"),
        (b"\x85\x00\x00\x00\xfeSMB" + bytes(60), False, "Port offen, aber keine SMB-Antwort"),  # kein Sitzungskopf
        (b"\x00\x00\x00\x40SMB2" + bytes(60), False, "Port offen, aber keine SMB-Antwort"),
        (b"\x00\x00\x00", False, "Port offen, aber keine SMB-Antwort"),
    ],
)
def test_smb_reply_variants(monkeypatch, reply, ok, detail) -> None:  # type: ignore[no-untyped-def]
    _use(monkeypatch, FakeSock([reply]))
    res = checks.check_smb("127.0.0.3", 445, FAST)
    assert (res.ok, res.detail) == (ok, detail)


# --- Absenderadresse und Verteiler --------------------------------------------------------------


@pytest.mark.parametrize("kind", ["tcp", "http", "https", "ssh", "smb"])
def test_source_ip_loopback_ok_and_missing_address_raises(sim, kind) -> None:  # type: ignore[no-untyped-def]
    port = {"tcp": 22, "http": 5000, "https": 5001, "ssh": 22, "smb": 445}[kind]
    assert checks.run_check(kind, NAS, port, FAST, source_ip="127.0.0.1").ok
    with pytest.raises(ports.SourceAddressGone):
        checks.run_check(kind, NAS, port, FAST, source_ip="192.0.2.1")


def test_run_check_dispatches(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    seen: list[tuple] = []

    def fake(name):  # type: ignore[no-untyped-def]
        def fn(ip, port, timeout_s, **kw):  # type: ignore[no-untyped-def]
            seen.append((name, ip, port, timeout_s, kw))
            return checks.CheckResult(ok=True)

        return fn

    for name in ("check_tcp", "check_http", "check_ssh", "check_smb"):
        monkeypatch.setattr(checks, name, fake(name))
    for kind in checks.CHECK_KINDS:
        checks.run_check(kind, NAS, 1, 1.0, path="/x", source_ip="127.0.0.1")
    assert seen == [
        ("check_tcp", NAS, 1, 1.0, {"source_ip": "127.0.0.1"}),
        ("check_http", NAS, 1, 1.0, {"tls": False, "path": "/x", "source_ip": "127.0.0.1"}),
        ("check_http", NAS, 1, 1.0, {"tls": True, "path": "/x", "source_ip": "127.0.0.1"}),
        ("check_smb", NAS, 1, 1.0, {"source_ip": "127.0.0.1"}),
        ("check_ssh", NAS, 1, 1.0, {"source_ip": "127.0.0.1"}),
    ]


@pytest.mark.parametrize("kind", ["telnet", "", None, "TCP", "ping"])
def test_run_check_unknown_kind(kind) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ValueError):
        checks.run_check(kind, NAS, 80, FAST)


def test_default_ports_match_kinds() -> None:
    assert checks.CHECK_KINDS == ("tcp", "http", "https", "smb", "ssh")
    assert checks.DEFAULT_PORTS == {"http": 80, "https": 443, "smb": 445, "ssh": 22}
