"""probe_port und scan_ports – nur gegen 127.0.0.x (tests.sim) oder Attrappen."""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator

import pytest

from netscan.core.context import RateLimiter, ScanCancelled
from netscan.net import ports
from netscan.net.ports import BANNER_PORTS, COMMON_PORTS, PORT_TABLE, probe_port, scan_ports
from tests.sim import SimLab, TcpService, free_port

SIM_IP = "127.0.0.2"


# --- Hilfen -------------------------------------------------------------------


@pytest.fixture
def sim_http_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    """tests.sim.HttpService: HTTPServer.server_bind ruft socket.getfqdn() → gethostbyaddr, das conftest
    sperrt (LanTrafficError). Lokale Abhilfe (als Vertragsfrage gemeldet): getfqdn gibt den Namen
    unverändert zurück. Es verlässt kein Paket den PC."""
    monkeypatch.setattr(ports.socket, "getfqdn", lambda name="": name or "localhost")


@pytest.fixture
def tcp_service() -> Iterator:  # type: ignore[type-arg]
    """Fabrik für TcpService auf 127.0.0.2; schließt alle am Ende."""
    started: list[TcpService] = []

    def _start(banner: bytes) -> int:
        port = free_port(SIM_IP)
        started.append(TcpService(SIM_IP, port, banner))
        return port

    yield _start
    for svc in started:
        svc.close()


class FakeSocket:
    """Socket-Attrappe: zeichnet Zeitgrenzen auf und verbietet jedes Senden."""

    instances: list[FakeSocket] = []
    connect_result: int | BaseException = 0
    payload: bytes = b"220 FTP bereit\r\nzweite Zeile\r\n"

    def __init__(self, family: int, kind: int) -> None:
        self.family = family
        self.kind = kind
        self.timeouts: list[float] = []
        self.closed = False
        self.address: object = None
        FakeSocket.instances.append(self)

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)

    def connect_ex(self, address: object) -> int:
        self.address = address
        if isinstance(FakeSocket.connect_result, BaseException):
            raise FakeSocket.connect_result
        return FakeSocket.connect_result

    def recv(self, size: int) -> bytes:
        return FakeSocket.payload[:size]

    def send(self, *_a: object) -> int:
        raise AssertionError("probe_port darf nichts senden")

    sendall = send
    sendto = send

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def fake_socket(monkeypatch: pytest.MonkeyPatch) -> type[FakeSocket]:
    FakeSocket.instances = []
    FakeSocket.connect_result = 0
    FakeSocket.payload = b"220 FTP bereit\r\nzweite Zeile\r\n"
    monkeypatch.setattr(ports.socket, "socket", FakeSocket)
    return FakeSocket


class CountingLimiter:
    """Hüllt den echten RateLimiter ein und zählt die angeforderten Tokens."""

    def __init__(self, inner: RateLimiter) -> None:
        self.inner = inner
        self.count = 0
        self._lock = threading.Lock()

    def acquire(self, n: float = 1.0) -> None:
        with self._lock:
            self.count += 1
        self.inner.acquire(n)


def progress_events(ctx) -> list[dict]:  # type: ignore[no-untyped-def]
    return [e.data for e in ctx.bus.history(type_prefix="job.progress") if e.data.get("phase") == "Ports"]


# --- probe_port gegen simulierte Dienste --------------------------------------


def test_probe_open_port_reads_ssh_banner(tcp_service) -> None:  # type: ignore[no-untyped-def]
    port = tcp_service(b"SSH-2.0-OpenSSH_9.6 Sim\r\nweitere Daten")
    assert probe_port(SIM_IP, port, 1.0, read_banner=True) == (True, "SSH-2.0-OpenSSH_9.6 Sim")


def test_probe_open_port_without_banner_read(tcp_service) -> None:  # type: ignore[no-untyped-def]
    port = tcp_service(b"SSH-2.0-OpenSSH_9.6 Sim\r\n")
    assert probe_port(SIM_IP, port, 1.0) == (True, None)


def test_probe_silent_service_gives_no_banner_quickly(tcp_service) -> None:  # type: ignore[no-untyped-def]
    port = tcp_service(b"")
    t0 = time.monotonic()
    assert probe_port(SIM_IP, port, 2.0, read_banner=True) == (True, None)
    assert time.monotonic() - t0 < 1.5  # Banner-Zeitgrenze höchstens 0,8 s


def test_probe_closed_port(tcp_service) -> None:  # type: ignore[no-untyped-def]
    port = free_port(SIM_IP)  # war kurz belegt, jetzt frei ⇒ geschlossen
    t0 = time.monotonic()
    assert probe_port(SIM_IP, port, 0.3) == (False, None)
    assert time.monotonic() - t0 < 1.5


def test_probe_cleans_telnet_banner(tcp_service) -> None:  # type: ignore[no-untyped-def]
    # Telnet-Aushandlung (IAC …), Steuerzeichen und ANSI-Farben werden entfernt
    port = tcp_service(b"\xff\xfd\x18\xff\xfb\x01\x1b[1mBusyBox\x1b[0m v1.31\x07 login: ")
    assert probe_port(SIM_IP, port, 1.0, read_banner=True) == (True, "BusyBox v1.31 login:")


def test_probe_banner_is_first_nonempty_line_and_capped(tcp_service) -> None:  # type: ignore[no-untyped-def]
    port = tcp_service(b"\r\n\r\n" + b"A" * 500 + b"\r\nzweite Zeile\r\n")
    is_open, banner = probe_port(SIM_IP, port, 1.0, read_banner=True)
    assert is_open and banner == "A" * 200


def test_probe_utf8_banner(tcp_service) -> None:  # type: ignore[no-untyped-def]
    port = tcp_service("220 Willkommen auf dem Dateiserver – grüß Gott\r\n".encode())
    assert probe_port(SIM_IP, port, 1.0, read_banner=True) == (True, "220 Willkommen auf dem Dateiserver – grüß Gott")


# --- probe_port mit Socket-Attrappe -------------------------------------------


@pytest.mark.parametrize(
    "ip",
    ["localhost", "::1", "999.1.1.1", "", "127.1", "224.0.0.251", "255.255.255.255", "0.0.0.0", "nas.local", None],
)
def test_probe_accepts_only_ipv4_unicast_literals(fake_socket, ip) -> None:  # type: ignore[no-untyped-def]
    assert probe_port(ip, 80, 0.5) == (False, None)
    assert fake_socket.instances == []  # gar kein Socket angelegt


@pytest.mark.parametrize("port", [0, -1, 65536, True])
def test_probe_rejects_invalid_ports(fake_socket, port) -> None:  # type: ignore[no-untyped-def]
    assert probe_port("127.0.0.2", port, 0.5) == (False, None)
    assert fake_socket.instances == []


def test_probe_caps_timeouts_and_never_sends(fake_socket) -> None:  # type: ignore[no-untyped-def]
    assert probe_port("127.0.0.2", 21, 10.0, read_banner=True) == (True, "220 FTP bereit")
    sock = fake_socket.instances[0]
    assert sock.family == ports.socket.AF_INET
    assert sock.address == ("127.0.0.2", 21)
    assert sock.timeouts[0] == 2.0  # Netzoperation höchstens 2 s
    assert all(t <= 0.8 for t in sock.timeouts[1:])  # Banner höchstens 0,8 s
    assert sock.closed


def test_probe_errors_mean_closed_and_socket_is_closed(fake_socket) -> None:  # type: ignore[no-untyped-def]
    fake_socket.connect_result = OSError("Netz nicht erreichbar")
    assert probe_port("127.0.0.2", 80, 0.5) == (False, None)
    assert fake_socket.instances[-1].closed
    fake_socket.connect_result = 10061  # Verbindung abgelehnt
    assert probe_port("127.0.0.2", 80, 0.5) == (False, None)
    assert fake_socket.instances[-1].closed


def test_probe_does_not_swallow_lan_lock(fake_socket) -> None:  # type: ignore[no-untyped-def]
    # Die Netzsperre der Tests (LanTrafficError ⊂ AssertionError) darf nicht verschluckt werden.
    fake_socket.connect_result = AssertionError("Netzsperre")
    with pytest.raises(AssertionError, match="Netzsperre"):
        probe_port("127.0.0.2", 80, 0.5)
    assert fake_socket.instances[-1].closed


# --- scan_ports gegen das simulierte Heimnetz ---------------------------------


def test_scan_simlab_finds_services(make_ctx, monkeypatch: pytest.MonkeyPatch, sim_http_ok) -> None:  # type: ignore[no-untyped-def]
    with SimLab() as lab:
        monkeypatch.setattr(ports, "probe_port", lab.translating_probe(ports.probe_port))
        ctx = make_ctx()
        targets = {d.ip: list(COMMON_PORTS) for d in lab.devices}
        result = scan_ports(ctx, targets)

    assert set(result) == set(targets)
    open_ports = {ip: [p.port for p in found] for ip, found in result.items()}
    assert open_ports["127.0.0.2"] == [53, 80]  # Router
    assert open_ports["127.0.0.3"] == [22, 445, 5000]  # NAS
    assert open_ports["127.0.0.4"] == [80, 631, 9100]  # Drucker
    assert open_ports["127.0.0.5"] == [135, 445, 3389]  # PC
    assert open_ports["127.0.0.6"] == [23]  # Telnet-Gerät
    assert open_ports["127.0.0.7"] == []  # Handy

    nas = {p.port: p for p in result["127.0.0.3"]}
    assert nas[22].banner is not None and nas[22].banner.startswith("SSH-2.0-")
    assert nas[445].banner is None  # kein Banner-Port
    assert (nas[445].service, nas[445].risk) == ("smb", "high")
    assert (nas[5000].service, nas[5000].risk) == ("http", "medium")

    telnet = result["127.0.0.6"][0]
    assert (telnet.service, telnet.risk, telnet.proto) == ("telnet", "high", "tcp")
    assert telnet.banner == "BusyBox v1.31 login:"
    assert telnet.reason == PORT_TABLE[23].reason

    for found in result.values():
        for p in found:
            spec = PORT_TABLE[p.port]
            assert (p.service, p.risk, p.reason) == (spec.service, spec.risk, spec.reason)


def test_scan_one_parallel_map_with_settings(make_ctx, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    calls: list[tuple[int, bool, int]] = []
    planned: list[tuple[str, int]] = []
    real_parallel_map = ports.parallel_map

    def spy(ctx, fn, items, workers, *, rate=True, on_result=None):  # type: ignore[no-untyped-def]
        items = list(items)
        calls.append((workers, rate, len(items)))
        planned.extend(items)
        return real_parallel_map(ctx, fn, items, workers, rate=rate, on_result=on_result)

    seen: list[tuple[str, int, float, bool]] = []

    def fake_probe(ip: str, port: int, timeout_s: float, read_banner: bool = False):  # type: ignore[no-untyped-def]
        seen.append((ip, port, timeout_s, read_banner))
        return (port == 22, "SSH-2.0-Attrappe" if read_banner and port == 22 else None)

    monkeypatch.setattr(ports, "parallel_map", spy)
    monkeypatch.setattr(ports, "probe_port", fake_probe)
    ctx = make_ctx(port_workers=17, port_timeout_ms=450)
    targets = {f"127.0.0.{i}": list(COMMON_PORTS) for i in range(10, 14)}
    result = scan_ports(ctx, targets)

    assert calls == [(17, True, 4 * len(COMMON_PORTS))]  # EIN gemeinsamer Pool, gedrosselt
    assert len(seen) == 4 * len(COMMON_PORTS)
    assert {t for *_, t, _ in seen} == {0.45}
    assert all(rb == (port in BANNER_PORTS) for _, port, _, rb in seen)
    for ip in targets:
        assert [(p.port, p.banner) for p in result[ip]] == [(22, "SSH-2.0-Attrappe")]
    # reihum über die Geräte geplant: je vier aufeinanderfolgende Prüfungen gehen an vier verschiedene Geräte
    assert all(len({ip for ip, _ in planned[i : i + 4]}) == 4 for i in range(0, len(planned), 4))
    assert sorted(planned) == sorted((ip, port) for ip in targets for port in COMMON_PORTS)


def test_scan_returns_every_target_even_empty(make_ctx, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(ports, "probe_port", lambda ip, port, timeout_s, read_banner=False: (False, None))
    ctx = make_ctx()
    targets = {"127.0.0.20": [80, 443], "127.0.0.21": [], "kein-ip": [80], "127.0.0.22": [0, 70000]}
    assert scan_ports(ctx, targets) == {ip: [] for ip in targets}
    assert any("kein-ip" in e.data["message"] for e in ctx.bus.history(type_prefix="job.log"))


def test_scan_sorts_dedups_and_describes_unknown(make_ctx, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    calls: list[int] = []

    def fake_probe(ip: str, port: int, timeout_s: float, read_banner: bool = False):  # type: ignore[no-untyped-def]
        calls.append(port)
        return (True, None)

    monkeypatch.setattr(ports, "probe_port", fake_probe)
    result = scan_ports(make_ctx(), {"127.0.0.30": [443, 22, 22, 12345, 80, 0, 70000]})
    assert [p.port for p in result["127.0.0.30"]] == [22, 80, 443, 12345]
    assert sorted(calls) == [22, 80, 443, 12345]
    unknown = result["127.0.0.30"][-1]
    assert (unknown.service, unknown.risk) == ("unbekannt", "low")
    assert unknown.reason == "Dienst unbekannt – prüfen, ob der offene Port gewollt ist."


def test_scan_empty_targets(make_ctx) -> None:  # type: ignore[no-untyped-def]
    ctx = make_ctx()
    assert scan_ports(ctx, {}) == {}
    assert progress_events(ctx) == []


def test_scan_progress_is_throttled_and_ends_complete(make_ctx, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(ports, "probe_port", lambda ip, port, timeout_s, read_banner=False: (False, None))
    ctx = make_ctx(rate_pps=1000)
    targets = {f"127.0.0.{i}": list(COMMON_PORTS) for i in range(40, 46)}  # 6 × 35 = 210
    scan_ports(ctx, targets)
    events = progress_events(ctx)
    total = 6 * len(COMMON_PORTS)
    assert events, "Fortschritt erwartet"
    assert len(events) <= total // 25 + 1
    assert events[-1]["done"] == events[-1]["total"] == total
    dones = [e["done"] for e in events]
    steps = [b - a for a, b in zip([0] + dones[:-1], dones)]
    assert all(step >= 25 for step in steps[:-1])  # höchstens alle 25 Ergebnisse
    assert all(step > 0 for step in steps)


def test_scan_respects_rate_limit(make_ctx, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(ports, "probe_port", lambda ip, port, timeout_s, read_banner=False: (False, None))
    ctx = make_ctx(rate_pps=20, port_workers=64)
    limiter = CountingLimiter(RateLimiter(20, cancel=ctx.cancel))
    ctx.rate = limiter
    targets = {"127.0.0.50": list(range(1, 16)), "127.0.0.51": list(range(1, 16))}  # 30 Prüfungen
    t0 = time.monotonic()
    scan_ports(ctx, targets)
    elapsed = time.monotonic() - t0
    assert limiter.count == 30  # ein Token je Verbindungsversuch
    # 20/s, Startguthaben 2 Tokens ⇒ mindestens (30 - 2) / 20 = 1,4 s
    assert elapsed >= 1.2


def test_scan_cancel_stops_within_5_seconds(services, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    release = threading.Event()
    started = threading.Event()

    def slow_probe(ip: str, port: int, timeout_s: float, read_banner: bool = False):  # type: ignore[no-untyped-def]
        started.set()
        release.wait(2.0)  # wie ein Ziel, das nicht antwortet (Zeitgrenze 2 s)
        return (False, None)

    monkeypatch.setattr(ports, "probe_port", slow_probe)
    targets = {f"127.0.1.{i}": list(COMMON_PORTS) for i in range(1, 31)}
    try:
        services.jobs.start("scan", "Port-Scan", lambda ctx: {"ports": len(scan_ports(ctx, targets))})
        assert started.wait(3)
        time.sleep(0.3)
        t0 = time.monotonic()
        assert services.jobs.cancel()
        assert services.jobs.wait(5)
        assert time.monotonic() - t0 < 5
        assert services.jobs.last_result["result"] == "cancelled"
    finally:
        release.set()


def test_scan_raises_when_already_cancelled(make_ctx, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(ports, "probe_port", lambda *a, **k: pytest.fail("darf nicht prüfen"))
    ctx = make_ctx()
    ctx.cancel.cancel()
    with pytest.raises(ScanCancelled):
        scan_ports(ctx, {"127.0.0.60": [22]})


@pytest.mark.slow
def test_runtime_target_30_devices_35_ports(make_ctx, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    """Laufzeitziel: 30 Geräte × 35 Ports bei 200/s Drosselung < 30 s (jedes 10. Ziel antwortet nie)."""
    counter = iter(range(10**6))
    lock = threading.Lock()

    def probe(ip: str, port: int, timeout_s: float, read_banner: bool = False):  # type: ignore[no-untyped-def]
        with lock:
            n = next(counter)
        time.sleep(timeout_s if n % 10 == 0 else 0.002)
        return (False, None)

    monkeypatch.setattr(ports, "probe_port", probe)
    ctx = make_ctx()  # Standard: 200/s, 64 Threads, 700 ms
    targets = {f"127.0.2.{i}": list(COMMON_PORTS) for i in range(1, 31)}
    t0 = time.monotonic()
    result = scan_ports(ctx, targets)
    elapsed = time.monotonic() - t0
    assert len(result) == 30
    assert elapsed < 30
    assert elapsed >= (30 * 35 - 20) / 200 * 0.9  # Drosselung greift
