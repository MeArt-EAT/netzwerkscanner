"""Erreichbarkeit (ping/tcp/auto), Ersatzports und Dienstvorschläge (BAUPLAN §23).

Ping kommt aus einer Attrappe (bzw. FakePlatform), TCP aus simulierten Diensten auf 127.0.0.x.
"""

from __future__ import annotations

import errno

import pytest

from netscan.core.models import Device, PingResult, PortResult
from netscan.core.targets import validate_check
from netscan.net import checks, ports
from tests.fakes import FakePlatform
from tests.sim import SimDevice, SimLab

ORIGINAL_CONNECT = checks.connect
NAS = "127.0.0.3"


class FakePing:
    """Ping-Attrappe: Ergebnis je IP, merkt sich Aufrufe (ip, timeout_ms)."""

    def __init__(self, results: dict[str, PingResult] | None = None, error: Exception | None = None) -> None:
        self.results = results or {}
        self.error = error
        self.calls: list[tuple[str, int]] = []

    def __call__(self, ip: str, timeout_ms: int) -> PingResult:
        self.calls.append((ip, timeout_ms))
        if self.error is not None:
            raise self.error
        return self.results.get(ip, PingResult(alive=False))


class ConnectLog:
    """Ersatz für checks.connect: Ergebnis je Port (Ausnahme oder Weiterleitung an die Sim)."""

    def __init__(self, behaviour: dict[int, BaseException] | None = None, fallback=None) -> None:  # type: ignore[no-untyped-def]
        self.behaviour = behaviour or {}
        self.fallback = fallback
        self.calls: list[tuple[str, int, float, str | None]] = []

    def __call__(self, ip, port, timeout_s, source_ip=None):  # type: ignore[no-untyped-def]
        self.calls.append((ip, port, timeout_s, source_ip))
        if port in self.behaviour:
            raise self.behaviour[port]
        if self.fallback is None:
            raise AssertionError("Unerwarteter Verbindungsaufbau")
        return self.fallback(ip, port, timeout_s, source_ip)


@pytest.fixture(scope="module")
def lab():  # type: ignore[no-untyped-def]
    with SimLab([SimDevice(NAS, "00:11:32:aa:bb:03", "NAS", tcp={22: b"SSH-2.0-OpenSSH_9.6\r\n", 5000: b""})]) as lab:
        yield lab


@pytest.fixture
def sim_connect(lab, monkeypatch):  # type: ignore[no-untyped-def]
    log = ConnectLog(fallback=lab.translating_connect(ORIGINAL_CONNECT))
    monkeypatch.setattr(checks, "connect", log)
    return log


@pytest.fixture
def no_connect(monkeypatch):  # type: ignore[no-untyped-def]
    log = ConnectLog()
    monkeypatch.setattr(checks, "connect", log)
    return log


def _reach(ip: str = NAS, **kw):  # type: ignore[no-untyped-def]
    kw.setdefault("timeout_ms", 500)
    kw.setdefault("tcp_ports", [])
    kw.setdefault("ping", FakePing())
    return checks.check_reachability(ip, **kw)


# --- ping ---------------------------------------------------------------------------------------


def test_ping_answer(no_connect) -> None:  # type: ignore[no-untyped-def]
    ping = FakePing({NAS: PingResult(alive=True, rtt_ms=1.234, ttl=64)})
    res = _reach(method="ping", ping=ping, tcp_ports=[22])
    assert (res.ok, res.rtt_ms, res.detail, res.method, res.code) == (True, 1.2, "Ping-Antwort", "ping", None)
    assert ping.calls == [(NAS, 500)] and no_connect.calls == []


def test_ping_without_answer_never_tries_tcp(no_connect) -> None:  # type: ignore[no-untyped-def]
    res = _reach(method="ping", tcp_ports=[22, 80])
    assert (res.ok, res.detail, res.method, res.rtt_ms) == (False, "keine Ping-Antwort", "ping", None)
    assert no_connect.calls == []


@pytest.mark.parametrize("rtt", [None, float("nan"), -1.0, True, "3"])
def test_ping_answer_with_unusable_rtt(no_connect, rtt) -> None:  # type: ignore[no-untyped-def]
    res = _reach(method="ping", ping=FakePing({NAS: PingResult(alive=True, rtt_ms=rtt)}))
    assert res.ok and res.rtt_ms is None


def test_ping_error_counts_as_no_answer(no_connect) -> None:  # type: ignore[no-untyped-def]
    res = _reach(method="ping", ping=FakePing(error=OSError("kein ping")))
    assert not res.ok and res.detail == "keine Ping-Antwort"


@pytest.mark.parametrize(("given", "expected"), [(5000, 2000), (10, 50), (1000, 1000), (None, 2000)])
def test_ping_timeout_is_clamped(no_connect, given, expected) -> None:  # type: ignore[no-untyped-def]
    ping = FakePing()
    _reach(method="ping", ping=ping, timeout_ms=given)
    assert ping.calls == [(NAS, expected)]


def test_works_with_platform_ping(no_connect) -> None:  # type: ignore[no-untyped-def]
    platform = FakePlatform()
    platform.alive[NAS] = PingResult(alive=True, rtt_ms=0.5, ttl=64)
    assert _reach(method="ping", ping=platform.ping).ok
    assert platform.ping_calls == [NAS]


# --- tcp ----------------------------------------------------------------------------------------


def test_tcp_open_port(sim_connect) -> None:  # type: ignore[no-untyped-def]
    ping = FakePing({NAS: PingResult(alive=True, rtt_ms=1.0)})
    res = _reach(method="tcp", ping=ping, tcp_ports=[22])
    assert (res.ok, res.detail, res.method) == (True, "erreichbar (Port 22 offen)", "tcp:22")
    assert res.rtt_ms is not None and ping.calls == []


def test_tcp_refused_counts_as_reachable(sim_connect) -> None:  # type: ignore[no-untyped-def]
    res = _reach(method="tcp", tcp_ports=[80])  # in der Sim nicht belegt ⇒ abgelehnt
    assert (res.ok, res.detail, res.method, res.rtt_ms) == (True, "erreichbar (Port 80 geschlossen)", "tcp:80", None)


def test_tcp_without_ports(no_connect) -> None:  # type: ignore[no-untyped-def]
    res = _reach(method="tcp", tcp_ports=[])
    assert (res.ok, res.detail, res.method) == (False, "kein TCP-Port für den Test bekannt", "tcp")
    assert no_connect.calls == []


def test_tcp_uses_at_most_three_valid_ports(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    log = ConnectLog({p: TimeoutError("timed out") for p in (80, 443, 22, 8080, 5000)})
    monkeypatch.setattr(checks, "connect", log)
    res = _reach(method="tcp", tcp_ports=[0, 80, 80, "22", True, 443, 70000, 22, 8080, 5000], timeout_ms=700,
                 source_ip="127.0.0.1")  # fmt: skip
    assert [c[1] for c in log.calls] == [80, 443, 22]
    assert all(c[2] == pytest.approx(0.7) and c[3] == "127.0.0.1" for c in log.calls)
    assert (res.ok, res.detail, res.method) == (False, "keine Antwort auf TCP 80, 443, 22", "tcp:80")


@pytest.mark.parametrize("tcp_ports", [None, "80", 80, (443,), iter([443])])
def test_tcp_ports_tolerates_odd_containers(monkeypatch, tcp_ports) -> None:  # type: ignore[no-untyped-def]
    log = ConnectLog({443: TimeoutError()})
    monkeypatch.setattr(checks, "connect", log)
    res = _reach(method="tcp", tcp_ports=tcp_ports)
    assert not res.ok
    assert [c[1] for c in log.calls] in ([], [443])


def test_tcp_tries_next_port_after_timeout(lab, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    log = ConnectLog({443: TimeoutError("timed out")}, fallback=lab.translating_connect(ORIGINAL_CONNECT))
    monkeypatch.setattr(checks, "connect", log)
    res = _reach(method="tcp", tcp_ports=[443, 22])
    assert res.ok and res.method == "tcp:22" and [c[1] for c in log.calls] == [443, 22]


def test_tcp_error_reason_is_reported(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    log = ConnectLog({80: TimeoutError(), 443: OSError(errno.ENETUNREACH, "x")})
    monkeypatch.setattr(checks, "connect", log)
    res = _reach(method="tcp", tcp_ports=[80, 443])
    assert not res.ok and res.detail == "nicht erreichbar (Netz nicht erreichbar)" and res.method == "tcp:80"


# --- auto ---------------------------------------------------------------------------------------


def test_auto_ping_answer_skips_tcp(no_connect) -> None:  # type: ignore[no-untyped-def]
    res = _reach(method="auto", ping=FakePing({NAS: PingResult(alive=True, rtt_ms=2.0)}), tcp_ports=[22])
    assert res.ok and res.method == "ping" and no_connect.calls == []


def test_auto_falls_back_to_tcp(sim_connect) -> None:  # type: ignore[no-untyped-def]
    ping = FakePing()
    res = _reach(method="auto", ping=ping, tcp_ports=[22], timeout_ms=800)
    assert ping.calls == [(NAS, 800)]
    assert (res.ok, res.method, res.detail) == (True, "tcp:22", "erreichbar (Port 22 offen)")


def test_auto_without_ports_reports_ping(no_connect) -> None:  # type: ignore[no-untyped-def]
    res = _reach(method="auto", tcp_ports=[])
    assert (res.ok, res.detail, res.method) == (False, "keine Ping-Antwort", "ping")


def test_auto_ping_and_tcp_fail(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(checks, "connect", ConnectLog({80: TimeoutError()}))
    res = _reach(method="auto", tcp_ports=[80])
    assert (res.ok, res.detail, res.method) == (False, "keine Ping-Antwort, keine Antwort auf TCP 80", "tcp:80")


# --- Fehler und Absenderadresse ----------------------------------------------------------------


@pytest.mark.parametrize("method", ["icmp", "", None, "PING"])
def test_unknown_method(no_connect, method) -> None:  # type: ignore[no-untyped-def]
    ping = FakePing()
    with pytest.raises(ValueError):
        _reach(method=method, ping=ping, tcp_ports=[22])
    assert ping.calls == [] and no_connect.calls == []


@pytest.mark.parametrize("ip", ["nas.local", "localhost", "", "0.0.0.0", "::1"])
def test_hostname_rejected_before_ping(no_connect, ip) -> None:  # type: ignore[no-untyped-def]
    ping = FakePing()
    with pytest.raises(ValueError):
        _reach(ip, method="auto", ping=ping, tcp_ports=[22])
    assert ping.calls == []


@pytest.mark.parametrize("method", ["tcp", "auto"])
def test_source_address_gone_is_passed_on(sim_connect, method) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ports.SourceAddressGone):
        _reach(method=method, tcp_ports=[22], source_ip="192.0.2.1")


def test_source_ip_loopback_works(sim_connect) -> None:  # type: ignore[no-untyped-def]
    res = _reach(method="tcp", tcp_ports=[22], source_ip="127.0.0.1")
    assert res.ok and sim_connect.calls[0][3] == "127.0.0.1"


# --- Ersatzports --------------------------------------------------------------------------------


def _device(*port_numbers: object, proto: str = "tcp") -> Device:
    return Device(mac="00:11:32:aa:bb:03", ip=NAS, ports=[PortResult(port=p, proto=proto) for p in port_numbers])  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("open_ports", "expected"),
    [
        ((9100, 22, 631, 12345, 80), [80, 22, 631]),
        ((5001, 445, 139), [445, 5001, 139]),
        ((443,), [443]),
        ((40000, 1234, 50000, 60000), [1234, 40000, 50000]),
        ((8443, 53, 3389, 7000), [8443, 3389, 53]),
        ((80, 80, 443), [80, 443]),
        ((), []),
    ],
)
def test_fallback_tcp_ports(open_ports, expected) -> None:  # type: ignore[no-untyped-def]
    assert checks.fallback_tcp_ports(_device(*open_ports)) == expected


def test_fallback_ignores_garbage_and_udp() -> None:
    device = _device("80", 0, True, 70000, None, 22)
    device.ports.append(PortResult(port=53, proto="udp"))
    assert checks.fallback_tcp_ports(device) == [22]
    assert checks.fallback_tcp_ports(Device(mac="00:11:32:aa:bb:03", ip=NAS, ports=None)) == []  # type: ignore[arg-type]


# --- Vorschläge ---------------------------------------------------------------------------------


def test_suggestions_for_nas() -> None:
    device = _device(5001, 445, 22, 5000, 139, 548, 873, 12345, 3389, 445)
    out = checks.suggest_checks(device)
    assert [(s["kind"], s["port"]) for s in out] == [
        ("ssh", 22), ("tcp", 139), ("smb", 445), ("tcp", 548), ("tcp", 873), ("tcp", 3389), ("http", 5000),
        ("https", 5001),
    ]  # fmt: skip
    labels = {s["port"]: s["label"] for s in out}
    assert labels[445] == "Dateifreigabe (SMB) 445"
    assert labels[5001] == "Weboberfläche (HTTPS) 5001"
    assert labels[5000] == "Weboberfläche (HTTP) 5000"
    assert labels[22] == "Fernwartung (SSH) 22"
    assert labels[139] == "Dienst netbios-ssn (TCP) 139"
    for s in out:
        assert set(s) == {"kind", "port", "path", "label", "reason"}
        assert s["path"] == "/" and str(s["port"]) in s["reason"] and s["reason"].endswith(".")
        assert validate_check(s["kind"], s["port"], s["path"]) == (s["kind"], s["port"], "/")  # passt zum Monitor


def test_suggestion_kinds_per_port() -> None:
    device = _device(80, 8080, 443, 8443, 21, 631, 1883, 8883, 9100)
    kinds = {s["port"]: s["kind"] for s in checks.suggest_checks(device)}
    assert kinds == {21: "tcp", 80: "http", 443: "https", 631: "tcp", 1883: "tcp", 8080: "http", 8443: "https",
                     8883: "tcp", 9100: "tcp"}  # fmt: skip


def test_suggestions_only_open_tcp_ports_and_known_services() -> None:
    device = _device(40000, "445", 0)
    device.ports.append(PortResult(port=22, proto="udp"))
    assert checks.suggest_checks(device) == []
    assert checks.suggest_checks(Device(mac="00:11:32:aa:bb:03", ip=NAS)) == []


def test_suggestions_from_untrusted_stored_device() -> None:
    device = Device.from_dict({"mac": "00:11:32:aa:bb:03", "ip": NAS,
                               "ports": [{"port": 445}, {"port": "x"}, {"port": 22, "proto": "TCP"}, {"port": -5}]})  # fmt: skip
    assert [(s["kind"], s["port"]) for s in checks.suggest_checks(device)] == [("ssh", 22), ("smb", 445)]
