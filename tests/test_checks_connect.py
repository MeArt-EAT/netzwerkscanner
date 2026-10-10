"""checks.connect (BAUPLAN §23): nur IPv4-Literale, Zeitgrenzen, Absenderadresse, einziger Weg ins Netz.

Nur Loopback (127.0.0.x); 192.0.2.1 (TEST-NET-1) dient nur als Absenderadresse, die es am System nicht gibt –
das Binden scheitert, bevor etwas gesendet wird.
"""

from __future__ import annotations

import socket

import pytest

from netscan.net import checks, ports


@pytest.fixture
def listener():  # type: ignore[no-untyped-def]
    """Lauschender Socket auf 127.0.0.1 (nimmt Verbindungen im Kernel an, antwortet nie)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    yield srv.getsockname()[1]
    srv.close()


@pytest.fixture
def no_dns(monkeypatch):  # type: ignore[no-untyped-def]
    """Jede Namensauflösung schlägt den Test fehl."""

    def forbidden(*_a, **_k):  # type: ignore[no-untyped-def]
        raise AssertionError("Namensauflösung darf nicht stattfinden")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "gethostbyname", forbidden)


@pytest.fixture
def connect_calls(monkeypatch):  # type: ignore[no-untyped-def]
    """Zeichnet echte socket.connect-Aufrufe auf (die Netzsperre aus conftest bleibt aktiv)."""
    calls: list[object] = []
    real = socket.socket.connect

    def recording(self, address):  # type: ignore[no-untyped-def]
        calls.append(address)
        return real(self, address)

    monkeypatch.setattr(socket.socket, "connect", recording)
    return calls


# --- Eingaben -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ip",
    ["localhost", "router.fritz.box", "nas", "::1", "", " 127.0.0.1", "127.0.0.01", "0.0.0.0", "224.0.0.251",
     "255.255.255.255", 2130706433, None, b"127.0.0.1"],
)  # fmt: skip
def test_connect_rejects_non_ipv4_literals_without_dns(ip, no_dns, connect_calls) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ValueError):
        checks.connect(ip, 80, 1.0)
    assert connect_calls == []


@pytest.mark.parametrize("port", [0, 65536, -1, True, "80", 80.0, None])
def test_connect_rejects_bad_ports(port, connect_calls) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ValueError):
        checks.connect("127.0.0.1", port, 1.0)
    assert connect_calls == []


@pytest.mark.parametrize(
    ("given", "expected"),
    [(99, 2.0), (2.5, 2.0), (1.0, 1.0), (0.0001, 0.05), (-3, 0.05), (float("nan"), 2.0), ("x", 2.0), (None, 2.0)],
)
def test_connect_clamps_timeout(listener, given, expected) -> None:  # type: ignore[no-untyped-def]
    sock = checks.connect("127.0.0.1", listener, given)
    try:
        assert sock.gettimeout() == pytest.approx(expected)
        assert sock.family == socket.AF_INET and sock.type == socket.SOCK_STREAM
    finally:
        sock.close()


def test_connect_returns_connected_socket(listener) -> None:  # type: ignore[no-untyped-def]
    with checks.connect("127.0.0.1", listener, 1.0) as sock:
        assert sock.getpeername() == ("127.0.0.1", listener)


def test_connect_closed_port_raises_oserror() -> None:
    free = socket.socket()
    free.bind(("127.0.0.1", 0))
    port = free.getsockname()[1]
    free.close()
    # Linux: sofort abgelehnt; Windows wiederholt den Aufbau nach dem RST ~2 s ⇒ hier Zeitüberschreitung
    with pytest.raises((ConnectionRefusedError, TimeoutError)):
        checks.connect("127.0.0.1", port, 0.3)


# --- Absenderadresse ----------------------------------------------------------------------------


def test_connect_binds_to_source_ip(listener) -> None:  # type: ignore[no-untyped-def]
    with checks.connect("127.0.0.1", listener, 1.0, "127.0.0.1") as sock:
        assert sock.getsockname()[0] == "127.0.0.1"


def test_missing_source_ip_raises_without_sending(listener, connect_calls) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ports.SourceAddressGone):
        checks.connect("127.0.0.1", listener, 1.0, "192.0.2.1")
    assert connect_calls == []  # Binden scheitert vor dem Verbindungsaufbau


@pytest.mark.parametrize("source", ["", "localhost", "nas.local", "0.0.0.0", "224.0.0.1", "::1", 2130706433])
def test_invalid_source_ip_counts_as_gone_without_dns(listener, source, no_dns, connect_calls) -> None:  # type: ignore[no-untyped-def]
    # "" oder 0.0.0.0 hieße „irgendein Adapter“ – genau das soll die Bindung verhindern
    with pytest.raises(ports.SourceAddressGone):
        checks.connect("127.0.0.1", listener, 1.0, source)
    assert connect_calls == []


def test_source_address_gone_is_the_stage1_class() -> None:
    assert checks.SourceAddressGone is ports.SourceAddressGone


# --- connect ist der einzige Weg ins Netz -------------------------------------------------------


class _Recorder:
    """Ersatz für checks.connect: merkt sich Aufrufe und lehnt jede Verbindung ab."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, int, float, str | None]] = []

    def __call__(self, ip, port, timeout_s, source_ip=None):  # type: ignore[no-untyped-def]
        self.calls.append((ip, port, timeout_s, source_ip))
        raise ConnectionRefusedError("Attrappe")


@pytest.mark.parametrize("kind", checks.CHECK_KINDS)
def test_every_check_goes_through_module_connect(kind, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    rec = _Recorder()
    monkeypatch.setattr(checks, "connect", rec)
    res = checks.run_check(kind, "127.0.0.9", 4711, 0.7, source_ip="127.0.0.1")
    assert rec.calls == [("127.0.0.9", 4711, 0.7, "127.0.0.1")]
    assert res.ok is False and res.detail == "Port geschlossen" and res.method == f"{kind}:4711"


def test_reachability_goes_through_module_connect(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    rec = _Recorder()
    monkeypatch.setattr(checks, "connect", rec)
    res = checks.check_reachability("127.0.0.9", method="tcp", ping=lambda ip, t: None, timeout_ms=800,
                                    tcp_ports=[80], source_ip="127.0.0.1")  # fmt: skip
    assert rec.calls == [("127.0.0.9", 80, 0.8, "127.0.0.1")]
    assert res.ok is True  # abgelehnt = Gerät hat geantwortet


@pytest.mark.parametrize("kind", checks.CHECK_KINDS)
def test_hostnames_rejected_even_with_replaced_connect(kind, monkeypatch, no_dns) -> None:  # type: ignore[no-untyped-def]
    rec = _Recorder()
    monkeypatch.setattr(checks, "connect", rec)
    with pytest.raises(ValueError):
        checks.run_check(kind, "nas.fritz.box", 445, 1.0)
    with pytest.raises(ValueError):
        checks.run_check(kind, "127.0.0.9", 0, 1.0)
    assert rec.calls == []
