"""ARP-Scan: Blöcke, Wiederholungen, MAC-Prüfung, Abbruch, Drosselung, Scapy-Sender (nur mit Attrappen)."""

from __future__ import annotations

import sys
import threading
import time
import types
from types import SimpleNamespace

import pytest

from netscan.core.context import ScanCancelled
from netscan.net import arp
from netscan.net.arp import ArpUnavailable, arp_scan, scapy_status
from tests.fakes import FakeArpSender, make_adapter

NET = "192.168.178"


@pytest.fixture(autouse=True)
def blocks_of_32(monkeypatch: pytest.MonkeyPatch) -> None:
    """Die Tests dieser Datei rechnen mit Blöcken zu höchstens 32 Adressen. Die echte Blockgröße richtet sich
    nach rate_pps (arp.block_size, siehe tests/test_review_arp.py) – hier bleibt sie klein und übersichtlich."""
    monkeypatch.setattr(arp, "MAX_BLOCK_SIZE", 32)


def make_hosts(first: int = 1, last: int = 254) -> list[str]:
    return [f"{NET}.{i}" for i in range(first, last + 1)]


def progress_events(ctx):  # type: ignore[no-untyped-def]
    return [e.data for e in ctx.bus.history(type_prefix="job.progress")]


class CountingRate:
    """Ersatz für ctx.rate: merkt sich nur, wie viel angefordert wurde."""

    def __init__(self) -> None:
        self.calls: list[float] = []

    def acquire(self, n: float = 1.0) -> None:
        self.calls.append(n)


# --- arp_scan: Blöcke und Ergebnis -------------------------------------------------


def test_scan_asks_in_blocks_of_32(make_ctx) -> None:  # type: ignore[no-untyped-def]
    ctx = make_ctx(arp_retries=0, rate_pps=1000)
    sender = FakeArpSender({f"{NET}.1": "3c:a6:2f:00:00:01", f"{NET}.20": "AA:BB:CC:00:00:20", f"{NET}.200": "aa-bb-cc-00-02-00"})
    result = arp_scan(ctx, make_adapter(), make_hosts(), sender)
    assert [len(c) for c in sender.calls] == [32] * 7 + [30]
    assert [ip for call in sender.calls for ip in call] == make_hosts()
    assert result == {
        f"{NET}.1": "3c:a6:2f:00:00:01",
        f"{NET}.20": "aa:bb:cc:00:00:20",
        f"{NET}.200": "aa:bb:cc:00:02:00",
    }


def test_scan_normalizes_macs_and_drops_invalid_ones(make_ctx) -> None:  # type: ignore[no-untyped-def]
    ctx = make_ctx(arp_retries=0, rate_pps=1000)

    def sender(adapter, ips, timeout_s):  # type: ignore[no-untyped-def]
        return {
            f"{NET}.1": "AA-BB-CC-DD-EE-01",
            f"{NET}.2": "aabb.ccdd.ee02",
            f"{NET}.3": "kein-mac",
            f"{NET}.4": "aa:bb:cc",
            f"{NET}.5": "",
            f"{NET}.6": None,  # type: ignore[dict-item]
            f"{NET}.7": 12345,  # type: ignore[dict-item]
        }

    result = arp_scan(ctx, make_adapter(), make_hosts(1, 7), sender)
    assert result == {f"{NET}.1": "aa:bb:cc:dd:ee:01", f"{NET}.2": "aa:bb:cc:dd:ee:02"}


def test_scan_ignores_answers_for_addresses_not_asked(make_ctx) -> None:  # type: ignore[no-untyped-def]
    ctx = make_ctx(arp_retries=0, rate_pps=1000)

    def sender(adapter, ips, timeout_s):  # type: ignore[no-untyped-def]
        return {f"{NET}.1": "aa:bb:cc:00:00:01", "10.0.0.99": "aa:bb:cc:00:00:99"}

    assert arp_scan(ctx, make_adapter(), [f"{NET}.1", f"{NET}.2"], sender) == {f"{NET}.1": "aa:bb:cc:00:00:01"}


def test_scan_passes_adapter_and_timeout_to_sender(make_ctx) -> None:  # type: ignore[no-untyped-def]
    ctx = make_ctx(arp_retries=0, arp_timeout_s=0.7, rate_pps=1000)
    adapter = make_adapter()
    seen: list[tuple[object, list[str], float]] = []

    def sender(a, ips, timeout_s):  # type: ignore[no-untyped-def]
        seen.append((a, list(ips), timeout_s))
        return {}

    arp_scan(ctx, adapter, [f"{NET}.1"], sender)
    assert seen == [(adapter, [f"{NET}.1"], 0.7)]


def test_scan_with_no_hosts_sends_nothing(make_ctx) -> None:  # type: ignore[no-untyped-def]
    ctx = make_ctx()
    sender = FakeArpSender({})
    assert arp_scan(ctx, make_adapter(), [], sender) == {}
    assert sender.calls == []


def test_scan_uses_scapy_sender_by_default(make_ctx, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    calls: list[list[str]] = []

    inters: list[float] = []

    def fake_default(adapter, ips, timeout_s, inter=0.0):  # type: ignore[no-untyped-def]
        calls.append(list(ips))
        inters.append(inter)
        return {ips[0]: "aa:bb:cc:00:00:01"}

    monkeypatch.setattr(arp, "_scapy_sender", fake_default)
    ctx = make_ctx(arp_retries=0, rate_pps=1000)
    assert arp_scan(ctx, make_adapter(), make_hosts(1, 3)) == {f"{NET}.1": "aa:bb:cc:00:00:01"}
    assert calls == [make_hosts(1, 3)]
    assert inters == [pytest.approx(1 / 1000)]  # Paketabstand aus rate_pps


def test_scan_passes_arp_unavailable_through(make_ctx) -> None:  # type: ignore[no-untyped-def]
    ctx = make_ctx(rate_pps=1000)

    def sender(adapter, ips, timeout_s):  # type: ignore[no-untyped-def]
        raise ArpUnavailable("Npcap fehlt")

    with pytest.raises(ArpUnavailable, match="Npcap fehlt"):
        arp_scan(ctx, make_adapter(), make_hosts(1, 5), sender)


def test_arp_unavailable_is_a_runtime_error() -> None:
    assert issubclass(ArpUnavailable, RuntimeError)


# --- Wiederholungen ------------------------------------------------------------------


class AnswersOnSecondAsk:
    """Antwortet je Adresse erst, wenn sie zum n-ten Mal gefragt wird."""

    def __init__(self, needs: dict[str, int]) -> None:
        self.needs = needs
        self.asked: dict[str, int] = {}
        self.calls: list[list[str]] = []

    def __call__(self, adapter, ips, timeout_s):  # type: ignore[no-untyped-def]
        self.calls.append(list(ips))
        out = {}
        for ip in ips:
            self.asked[ip] = self.asked.get(ip, 0) + 1
            if ip in self.needs and self.asked[ip] >= self.needs[ip]:
                out[ip] = "aa:bb:cc:00:00:" + ip.rsplit(".", 1)[1].zfill(2)
        return out


def test_retry_asks_only_unanswered_addresses(make_ctx) -> None:  # type: ignore[no-untyped-def]
    ctx = make_ctx(arp_retries=1, rate_pps=1000)
    h1, h2, h3 = make_hosts(1, 3)
    sender = AnswersOnSecondAsk({h1: 1, h2: 2})
    result = arp_scan(ctx, make_adapter(), [h1, h2, h3], sender)
    assert sender.calls == [[h1, h2, h3], [h2, h3]]
    assert set(result) == {h1, h2}


def test_retry_count_follows_setting(make_ctx) -> None:  # type: ignore[no-untyped-def]
    for retries in (0, 1, 3):
        ctx = make_ctx(arp_retries=retries, rate_pps=1000)
        sender = FakeArpSender({})
        assert arp_scan(ctx, make_adapter(), make_hosts(1, 10), sender) == {}
        assert len(sender.calls) == 1 + retries, retries


def test_retries_are_blocked_again(make_ctx) -> None:  # type: ignore[no-untyped-def]
    ctx = make_ctx(arp_retries=1, rate_pps=1000)
    sender = FakeArpSender({})
    arp_scan(ctx, make_adapter(), make_hosts(1, 70), sender)
    assert [len(c) for c in sender.calls] == [32, 32, 6, 32, 32, 6]


def test_no_retry_when_everyone_answered(make_ctx) -> None:  # type: ignore[no-untyped-def]
    ctx = make_ctx(arp_retries=3, rate_pps=1000)
    hosts = make_hosts(1, 10)
    sender = FakeArpSender({ip: "aa:bb:cc:00:00:01" for ip in hosts})
    assert len(arp_scan(ctx, make_adapter(), hosts, sender)) == 10
    assert len(sender.calls) == 1


def test_invalid_answer_counts_as_unanswered(make_ctx) -> None:  # type: ignore[no-untyped-def]
    ctx = make_ctx(arp_retries=1, rate_pps=1000)
    calls: list[list[str]] = []

    def sender(adapter, ips, timeout_s):  # type: ignore[no-untyped-def]
        calls.append(list(ips))
        return {f"{NET}.1": "unsinn"} if len(calls) == 1 else {f"{NET}.1": "AA:BB:CC:00:00:01"}

    assert arp_scan(ctx, make_adapter(), [f"{NET}.1"], sender) == {f"{NET}.1": "aa:bb:cc:00:00:01"}
    assert calls == [[f"{NET}.1"], [f"{NET}.1"]]


# --- Fortschritt und Protokoll -------------------------------------------------------


def test_progress_after_each_block(make_ctx) -> None:  # type: ignore[no-untyped-def]
    ctx = make_ctx(arp_retries=0, rate_pps=1000)
    arp_scan(ctx, make_adapter(), make_hosts(), FakeArpSender({}))
    events = progress_events(ctx)
    assert [e["done"] for e in events] == [32, 64, 96, 128, 160, 192, 224, 254]
    assert {e["total"] for e in events} == {254}
    assert {e["phase"] for e in events} == {"Gerätesuche (ARP)"}


def test_progress_never_exceeds_total_during_retries(make_ctx) -> None:  # type: ignore[no-untyped-def]
    ctx = make_ctx(arp_retries=2, rate_pps=1000)
    arp_scan(ctx, make_adapter(), make_hosts(1, 40), FakeArpSender({}))
    events = progress_events(ctx)
    assert all(e["done"] <= e["total"] == 40 for e in events)
    assert events[-1]["done"] == 40
    assert any("Wiederholung" in e["message"] for e in events)


def test_final_log_names_the_count(make_ctx) -> None:  # type: ignore[no-untyped-def]
    ctx = make_ctx(arp_retries=0, rate_pps=1000)
    answers = {f"{NET}.{i}": f"aa:bb:cc:00:00:{i:02x}" for i in (1, 2, 3)}
    arp_scan(ctx, make_adapter(), make_hosts(), FakeArpSender(answers))
    logs = [e.data for e in ctx.bus.history(type_prefix="job.log")]
    assert len(logs) == 1
    assert logs[0]["level"] == "info"
    assert "3 von 254" in logs[0]["message"]


# --- Drosselung und Abbruch ----------------------------------------------------------


def test_rate_limiter_is_not_charged_twice(make_ctx) -> None:  # type: ignore[no-untyped-def]
    # Gedrosselt wird über den Paketabstand im Block (srp inter = 1/rate_pps) und eine Mindestdauer je Block.
    # Den Token-Bucket zusätzlich zu belasten, würde jeden Block ein zweites Mal ausbremsen.
    ctx = make_ctx(arp_retries=0)
    ctx.rate = CountingRate()  # type: ignore[assignment]
    sender = FakeArpSender({})
    arp_scan(ctx, make_adapter(), make_hosts(), sender)
    assert ctx.rate.calls == []  # type: ignore[union-attr]
    assert [len(c) for c in sender.calls] == [32] * 7 + [30]


def test_rate_limiter_slows_the_scan_down(make_ctx) -> None:  # type: ignore[no-untyped-def]
    # 64 Adressen bei 100 Paketen/s und Eimergröße 10: mindestens ~0,5 s
    ctx = make_ctx(arp_retries=0, rate_pps=100)
    t0 = time.monotonic()
    arp_scan(ctx, make_adapter(), make_hosts(1, 64), FakeArpSender({}))
    assert time.monotonic() - t0 >= 0.4


def test_cancel_before_start_sends_nothing(make_ctx) -> None:  # type: ignore[no-untyped-def]
    ctx = make_ctx(rate_pps=1000)
    ctx.cancel.cancel()
    sender = FakeArpSender({})
    with pytest.raises(ScanCancelled):
        arp_scan(ctx, make_adapter(), make_hosts(), sender)
    assert sender.calls == []


def test_cancel_during_slow_sender_stops_within_5_seconds(make_ctx) -> None:  # type: ignore[no-untyped-def]
    ctx = make_ctx(arp_retries=1, rate_pps=1000)
    sender = FakeArpSender({}, delay_s=0.4)  # ungebremst: 16 Blöcke · 0,4 s ≈ 6,4 s
    timer = threading.Timer(0.3, ctx.cancel.cancel)
    timer.start()
    t0 = time.monotonic()
    try:
        with pytest.raises(ScanCancelled):
            arp_scan(ctx, make_adapter(), make_hosts(), sender)
    finally:
        timer.cancel()
    assert time.monotonic() - t0 < 5
    assert len(sender.calls) <= 2


def test_cancel_stops_before_next_retry_block(make_ctx) -> None:  # type: ignore[no-untyped-def]
    ctx = make_ctx(arp_retries=1, rate_pps=1000)
    calls: list[list[str]] = []

    def sender(adapter, ips, timeout_s):  # type: ignore[no-untyped-def]
        calls.append(list(ips))
        if len(calls) == 3:  # erster Block der Wiederholung (Durchgang 1: 32 + 8 Adressen)
            ctx.cancel.cancel()
        return {}

    with pytest.raises(ScanCancelled):
        arp_scan(ctx, make_adapter(), make_hosts(1, 40), sender)
    assert [len(c) for c in calls] == [32, 8, 32]  # der zweite Block der Wiederholung wird nicht mehr gesendet


# --- Standard-Sender mit Scapy-Attrappe -----------------------------------------------


class _Layer:
    def __init__(self, **fields: object) -> None:
        self.fields = fields
        self.payload: _Layer | None = None

    def __truediv__(self, other: _Layer) -> _Layer:
        self.payload = other
        return self


class _Ether(_Layer):
    pass


class _Arp(_Layer):
    pass


class _Reply:
    def __init__(self, psrc: str, hwsrc: str, with_arp: bool = True) -> None:
        self._layer = SimpleNamespace(psrc=psrc, hwsrc=hwsrc) if with_arp else None

    def getlayer(self, cls: type) -> object | None:
        return self._layer if cls is _Arp else None


def make_iface(ip: str = "", mac: str = "", ips4: list[str] | None = None, name: str = "eth") -> SimpleNamespace:
    return SimpleNamespace(name=name, ip=ip, ips={4: ips4 if ips4 is not None else ([ip] if ip else []), 6: []}, mac=mac)


def install_fake_scapy(monkeypatch, ifaces, answers=None, error=None):  # type: ignore[no-untyped-def]
    """Setzt ein falsches scapy.all ein. Es sendet nichts und merkt sich die srp-Aufrufe."""
    module = types.ModuleType("scapy.all")
    module.srp_calls = []  # type: ignore[attr-defined]

    def srp(packet, **kwargs):  # type: ignore[no-untyped-def]
        module.srp_calls.append({"packet": packet, **kwargs})  # type: ignore[attr-defined]
        if error is not None:
            raise error
        replies = [(packet, _Reply(ip, mac)) for ip, mac in (answers or {}).items()]
        return replies, []

    module.ARP = _Arp  # type: ignore[attr-defined]
    module.Ether = _Ether  # type: ignore[attr-defined]
    module.conf = SimpleNamespace(ifaces=ifaces)  # type: ignore[attr-defined]
    module.srp = srp  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "scapy.all", module)
    return module


def test_scapy_sender_sends_broadcast_arp_through_found_interface(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    other = make_iface("10.0.0.5", "00:00:00:00:00:05", name="andere")
    mine = make_iface("192.168.178.20", "00:1b:21:00:00:20", name="meine")
    fake = install_fake_scapy(monkeypatch, {"a": other, "b": mine}, answers={f"{NET}.5": "AA:BB:CC:00:00:05"})
    asked = [f"{NET}.5", f"{NET}.6"]
    result = arp._scapy_sender(make_adapter(), asked, 1.5)
    assert result == {f"{NET}.5": "AA:BB:CC:00:00:05"}
    (call,) = fake.srp_calls
    assert call["iface"] is mine
    assert call["timeout"] == 1.5
    assert call["verbose"] == 0
    assert call["inter"] == 0.0
    ether = call["packet"]
    # Absender ausdrücklich aus dem Adapter, nicht aus Scapys zwischengespeicherter Routentabelle (Befund WIN-06)
    assert isinstance(ether, _Ether) and ether.fields == {"dst": "ff:ff:ff:ff:ff:ff", "src": "00:1b:21:00:00:20"}
    assert isinstance(ether.payload, _Arp)
    assert ether.payload.fields == {"pdst": asked, "psrc": "192.168.178.20", "hwsrc": "00:1b:21:00:00:20"}


def test_scapy_sender_finds_interface_by_secondary_address(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mine = make_iface("169.254.1.2", "", ips4=["169.254.1.2", "192.168.178.20"])
    fake = install_fake_scapy(monkeypatch, {"x": mine})
    arp._scapy_sender(make_adapter(), [f"{NET}.5"], 1.0)
    assert fake.srp_calls[0]["iface"] is mine


def test_scapy_sender_falls_back_to_mac(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mine = make_iface("", "00:1B:21:00:00:20")
    fake = install_fake_scapy(monkeypatch, {"x": make_iface("1.2.3.4", "11:22:33:44:55:66"), "y": mine})
    arp._scapy_sender(make_adapter(), [f"{NET}.5"], 1.0)
    assert fake.srp_calls[0]["iface"] is mine


def test_scapy_sender_clamps_timeout_to_2_seconds(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    fake = install_fake_scapy(monkeypatch, {"x": make_iface("192.168.178.20")})
    arp._scapy_sender(make_adapter(), [f"{NET}.5"], 30.0)
    assert fake.srp_calls[0]["timeout"] == 2.0


def test_scapy_sender_skips_replies_without_arp_layer(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    fake = install_fake_scapy(monkeypatch, {"x": make_iface("192.168.178.20")})
    original = fake.srp

    def srp(packet, **kwargs):  # type: ignore[no-untyped-def]
        answered, unanswered = original(packet, **kwargs)
        return answered + [(packet, _Reply("x", "y", with_arp=False))], unanswered

    fake.srp = srp
    assert arp._scapy_sender(make_adapter(), [f"{NET}.5"], 1.0) == {}


def test_scapy_sender_without_matching_interface_is_unavailable(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    install_fake_scapy(monkeypatch, {"x": make_iface("10.0.0.5", "00:00:00:00:00:05")})
    with pytest.raises(ArpUnavailable, match="nicht gefunden") as info:
        arp._scapy_sender(make_adapter(name="Ethernet"), [f"{NET}.5"], 1.0)
    assert "Ethernet" in str(info.value)


def test_scapy_sender_import_failure_is_unavailable(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setitem(sys.modules, "scapy.all", None)  # erzwingt ImportError
    with pytest.raises(ArpUnavailable, match="Scapy"):
        arp._scapy_sender(make_adapter(), [f"{NET}.5"], 1.0)


@pytest.mark.parametrize("error", [OSError("winpcap is not installed"), PermissionError("Operation not permitted"), RuntimeError("kaputt")])
def test_scapy_sender_send_errors_are_unavailable(monkeypatch, error) -> None:  # type: ignore[no-untyped-def]
    install_fake_scapy(monkeypatch, {"x": make_iface("192.168.178.20")}, error=error)
    with pytest.raises(ArpUnavailable, match="Administrator") as info:
        arp._scapy_sender(make_adapter(), [f"{NET}.5"], 1.0)
    assert info.value.__cause__ is error


def test_scapy_sender_does_not_hide_assertion_errors(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    install_fake_scapy(monkeypatch, {"x": make_iface("192.168.178.20")}, error=AssertionError("Testsperre"))
    with pytest.raises(AssertionError, match="Testsperre"):
        arp._scapy_sender(make_adapter(), [f"{NET}.5"], 1.0)


def test_scapy_sender_without_addresses_sends_nothing(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    fake = install_fake_scapy(monkeypatch, {"x": make_iface("192.168.178.20")})
    assert arp._scapy_sender(make_adapter(), [], 1.0) == {}
    assert fake.srp_calls == []


def test_arp_scan_with_scapy_attrappe_end_to_end(make_ctx, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    install_fake_scapy(monkeypatch, {"x": make_iface("192.168.178.20")}, answers={f"{NET}.1": "3C-A6-2F-00-00-01"})
    ctx = make_ctx(arp_retries=0, rate_pps=1000)
    assert arp_scan(ctx, make_adapter(), make_hosts(1, 5)) == {f"{NET}.1": "3c:a6:2f:00:00:01"}


# --- scapy_status ---------------------------------------------------------------------


def test_scapy_status_returns_flag_and_reason(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(arp, "_status_cache", None)
    ok, reason = scapy_status()
    assert isinstance(ok, bool)
    assert isinstance(reason, str) and reason


def test_scapy_status_is_cached(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(arp, "_status_cache", None)
    calls: list[int] = []

    def fake_check() -> tuple[bool, str]:
        calls.append(1)
        return True, "alles bereit"

    monkeypatch.setattr(arp, "_check_scapy", fake_check)
    assert scapy_status() == (True, "alles bereit")
    assert scapy_status() == (True, "alles bereit")
    assert len(calls) == 1
    assert scapy_status(refresh=True) == (True, "alles bereit")
    assert len(calls) == 2


def test_status_reports_missing_npcap_on_windows(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(arp, "_is_windows", lambda: True)
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    ok, reason = arp._check_scapy()
    assert ok is False
    assert "Npcap" in reason


def test_status_accepts_installed_npcap_on_windows(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    dll = tmp_path / "System32" / "Npcap" / "wpcap.dll"
    dll.parent.mkdir(parents=True)
    dll.write_bytes(b"")
    monkeypatch.setattr(arp, "_is_windows", lambda: True)
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    module = types.ModuleType("scapy.all")
    module.conf = object()  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "scapy.all", module)
    ok, reason = arp._check_scapy()
    assert ok is True
    assert "Npcap" in reason


def test_status_reports_scapy_import_failure(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(arp, "_is_windows", lambda: False)
    monkeypatch.setitem(sys.modules, "scapy.all", None)
    ok, reason = arp._check_scapy()
    assert ok is False
    assert "Scapy" in reason


@pytest.mark.skipif(sys.platform != "win32", reason="Npcap-Pfad gibt es nur unter Windows")
def test_npcap_dll_path_on_windows() -> None:
    path = arp._npcap_dll()
    assert path.name.lower() == "wpcap.dll"
    assert path.parent.name == "Npcap"
