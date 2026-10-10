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
    # Gedrosselt wird über den Paketabstand im Block (sendp inter = 1/rate_pps) und eine Mindestdauer je Block.
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


OWN_IP = "192.168.178.20"  # Adresse von make_adapter()
REPLY_FILTER = "arp and arp[6:2] = 2"


class _Reply:
    """Mitgelesenes Paket: op=2 ist eine ARP-Antwort (is-at), op=1 eine Anfrage."""

    def __init__(self, psrc: str, hwsrc: str, *, op: int = 2, pdst: str = OWN_IP, with_arp: bool = True) -> None:
        self._layer = SimpleNamespace(op=op, psrc=psrc, hwsrc=hwsrc, pdst=pdst) if with_arp else None

    def getlayer(self, cls: type) -> object | None:
        return self._layer if cls is _Arp else None


class _FakeSniffer:
    """Attrappe für Scapys AsyncSniffer: liest nichts mit und liefert beim Anhalten module.packets.

    start_mode „sofort“: meldet den Start sofort, join() kehrt sofort zurück, stop() beendet.
    „thread“: echter Thread wie bei Scapy – meldet den Start nach start_delay_s und läuft ohne timeout bis stop();
    stop() wirkt erst nach dem Start (vorher hat Scapy noch nichts zum Anhalten).
    „nie“: meldet sich nie. „fehler“: Öffnen scheitert (exception gesetzt wie bei Scapy). „hängt“: stop() wirkt nicht.
    """

    def __init__(self, module: types.ModuleType, **kwargs: object) -> None:
        if "timeout" in kwargs:  # wie Scapy 2.8
            raise ValueError("'timeout' isn't supported with AsyncSniffer. Use join(timeout=1)")
        self.module = module
        self.kwargs = kwargs
        self.running = False
        self.results: list[object] | None = None
        self.exception: BaseException | None = None
        self.thread: threading.Thread | None = None
        self.join_timeouts: list[float | None] = []
        self.stop_calls = 0
        self._armed = False
        self._halt = threading.Event()
        module.sniffers.append(self)  # type: ignore[attr-defined]

    def _announce(self) -> None:
        self._armed = True
        self.module.events.append("gestartet")  # type: ignore[attr-defined]
        self.kwargs["started_callback"]()  # type: ignore[operator]

    def _finish(self) -> None:
        self.results = list(self.module.packets)  # type: ignore[attr-defined]
        self.running = False
        self.module.events.append("beendet")  # type: ignore[attr-defined]

    def _run(self) -> None:
        time.sleep(self.module.start_delay_s)  # type: ignore[attr-defined]  # langsames Öffnen
        self._announce()
        self._halt.wait(10)  # ohne timeout: läuft bis stop()
        self._finish()

    def start(self) -> None:
        mode = self.module.start_mode  # type: ignore[attr-defined]
        self.module.events.append("start")  # type: ignore[attr-defined]
        self.running = True
        if mode in ("sofort", "hängt"):
            self._announce()
        elif mode == "fehler":
            self.exception = OSError("Adapter lässt sich nicht öffnen")
        elif mode == "thread":
            self.thread = threading.Thread(target=self._run, daemon=True)
            self.thread.start()

    def join(self, timeout: float | None = None) -> None:
        self.join_timeouts.append(timeout)
        if self.thread is not None:
            self.thread.join(timeout)
        if self.exception is not None:
            raise self.exception

    def stop(self, join: bool = True) -> None:
        self.stop_calls += 1
        self.module.events.append("stop")  # type: ignore[attr-defined]
        if not self.running:
            raise RuntimeError("Not running ! (check .running attr)")
        if not self._armed:
            if self.exception is not None:
                raise self.exception
            return  # wie Scapy: vor dem Start wirkt stop() nicht
        if self.module.start_mode == "hängt":  # type: ignore[attr-defined]
            return
        if self.thread is not None:
            self._halt.set()
            if join:
                self.thread.join()
        else:
            self._finish()


def make_iface(ip: str = "", mac: str = "", ips4: list[str] | None = None, name: str = "eth") -> SimpleNamespace:
    return SimpleNamespace(name=name, ip=ip, ips={4: ips4 if ips4 is not None else ([ip] if ip else []), 6: []}, mac=mac)


def install_fake_scapy(  # type: ignore[no-untyped-def]
    monkeypatch, ifaces, answers=None, error=None, *, packets=None, start_mode="sofort", start_delay_s=0.0
):
    """Setzt ein falsches scapy.all ein (umgeht die Sperre aus conftest nur durch Ersetzen des Moduls).
    Es sendet nichts und liest nichts mit; es merkt sich Mitlese-Attrappen, sendp-Aufrufe und die Reihenfolge."""
    module = types.ModuleType("scapy.all")
    module.sendp_calls = []  # type: ignore[attr-defined]
    module.sniffers = []  # type: ignore[attr-defined]
    module.events = []  # type: ignore[attr-defined]
    module.start_mode = start_mode  # type: ignore[attr-defined]
    module.start_delay_s = start_delay_s  # type: ignore[attr-defined]
    module.simulate_send_time = True  # type: ignore[attr-defined]
    module.packets = list(packets or []) + [_Reply(ip, mac) for ip, mac in (answers or {}).items()]  # type: ignore[attr-defined]

    def sendp(packet, **kwargs):  # type: ignore[no-untyped-def]
        module.events.append("sendp")  # type: ignore[attr-defined]
        module.sendp_calls.append({"packet": packet, **kwargs})  # type: ignore[attr-defined]
        if error is not None:
            raise error
        if module.simulate_send_time:  # type: ignore[attr-defined]  # Sendedauer wie Scapy: inter je Paket
            time.sleep(float(kwargs.get("inter") or 0.0) * len(packet.payload.fields["pdst"]))

    module.ARP = _Arp  # type: ignore[attr-defined]
    module.Ether = _Ether  # type: ignore[attr-defined]
    module.AsyncSniffer = lambda **kwargs: _FakeSniffer(module, **kwargs)  # type: ignore[attr-defined]
    module.conf = SimpleNamespace(ifaces=ifaces)  # type: ignore[attr-defined]
    module.sendp = sendp  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "scapy.all", module)
    return module


def test_scapy_sender_sends_broadcast_arp_through_found_interface(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    other = make_iface("10.0.0.5", "00:00:00:00:00:05", name="andere")
    mine = make_iface("192.168.178.20", "00:1b:21:00:00:20", name="meine")
    fake = install_fake_scapy(monkeypatch, {"a": other, "b": mine}, answers={f"{NET}.5": "AA:BB:CC:00:00:05"})
    asked = [f"{NET}.5", f"{NET}.6"]
    result = arp._scapy_sender(make_adapter(), asked, 1.5)
    assert result == {f"{NET}.5": "AA:BB:CC:00:00:05"}
    (call,) = fake.sendp_calls
    assert call["iface"] is mine
    assert call["verbose"] == 0
    assert call["inter"] == 0.0
    # Promiscuous Mode aus, auch beim Senden: Windows-WLAN-Treiber nehmen dort sonst keine Antworten an
    assert call["promisc"] is False
    ether = call["packet"]
    # Absender ausdrücklich aus dem Adapter, nicht aus Scapys zwischengespeicherter Routentabelle (Befund WIN-06)
    assert isinstance(ether, _Ether) and ether.fields == {"dst": "ff:ff:ff:ff:ff:ff", "src": "00:1b:21:00:00:20"}
    assert isinstance(ether.payload, _Arp)
    assert ether.payload.fields == {"pdst": asked, "psrc": "192.168.178.20", "hwsrc": "00:1b:21:00:00:20"}
    (sniffer,) = fake.sniffers
    assert sniffer.kwargs["iface"] is mine


def test_scapy_sender_listens_for_replies_only_without_promiscuous_mode(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    fake = install_fake_scapy(monkeypatch, {"x": make_iface("192.168.178.20")})
    monkeypatch.setattr(arp, "_is_windows", lambda: True)  # BPF-Filter nur unter Windows (Npcap)
    arp._scapy_sender(make_adapter(), [f"{NET}.5"], 1.0)
    (sniffer,) = fake.sniffers
    assert sniffer.kwargs["filter"] == REPLY_FILTER  # nur ARP-Antworten (Opcode 2), nicht die eigenen Anfragen
    assert sniffer.kwargs["promisc"] is False
    assert sniffer.kwargs["store"] is True
    assert callable(sniffer.kwargs["started_callback"])
    assert "timeout" not in sniffer.kwargs  # Scapy 2.8 lehnt timeout an AsyncSniffer ab


def test_scapy_sender_starts_listening_before_sending(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # Der Start des Mitlesens kommt erst nach 0,1 s – gesendet wird erst danach (Befund: Antwort kommt in Millisekunden)
    fake = install_fake_scapy(monkeypatch, {"x": make_iface("192.168.178.20")}, start_mode="thread", start_delay_s=0.1)
    arp._scapy_sender(make_adapter(), [f"{NET}.5"], 0.1)
    assert fake.events[:3] == ["start", "gestartet", "sendp"]
    assert fake.events.index("stop") > fake.events.index("sendp")
    (sniffer,) = fake.sniffers
    assert sniffer.thread is not None and not sniffer.thread.is_alive()


def test_scapy_sender_finds_interface_by_secondary_address(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mine = make_iface("169.254.1.2", "", ips4=["169.254.1.2", "192.168.178.20"])
    fake = install_fake_scapy(monkeypatch, {"x": mine})
    arp._scapy_sender(make_adapter(), [f"{NET}.5"], 1.0)
    assert fake.sendp_calls[0]["iface"] is mine
    assert fake.sniffers[0].kwargs["iface"] is mine


def test_scapy_sender_falls_back_to_mac(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mine = make_iface("", "00:1B:21:00:00:20")
    fake = install_fake_scapy(monkeypatch, {"x": make_iface("1.2.3.4", "11:22:33:44:55:66"), "y": mine})
    arp._scapy_sender(make_adapter(), [f"{NET}.5"], 1.0)
    assert fake.sendp_calls[0]["iface"] is mine
    assert fake.sniffers[0].kwargs["iface"] is mine


def test_scapy_sender_clamps_timeout_to_2_seconds(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    fake = install_fake_scapy(monkeypatch, {"x": make_iface("192.168.178.20")})
    arp._scapy_sender(make_adapter(), [f"{NET}.5"], 30.0)
    # nach dem letzten Paket höchstens 2 s Timeout plus kleine Reserve für den Npcap-Puffer
    assert fake.sniffers[0].join_timeouts[0] == pytest.approx(2.0)  # Lauschen höchstens 2 s (Abbruch < 5 s)
    assert arp._LISTEN_GRACE_S <= 0.5


def test_scapy_sender_clamps_packet_gap_to_1_second(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    fake = install_fake_scapy(monkeypatch, {"x": make_iface("192.168.178.20")})
    fake.simulate_send_time = False  # die Attrappe „sendet“ sonst 1 s lang
    arp._scapy_sender(make_adapter(), [f"{NET}.5"], 1.0, inter=5.0)
    assert fake.sendp_calls[0]["inter"] == 1.0


def test_scapy_sender_call_duration_is_bounded(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # Echter Mitlese-Thread ohne timeout (wie Scapy): Der Sender hält ihn nach Sendedauer + Timeout + Reserve an.
    fake = install_fake_scapy(
        monkeypatch, {"x": make_iface("192.168.178.20")}, answers={f"{NET}.3": "aa:bb:cc:00:00:03"}, start_mode="thread"
    )
    ips = make_hosts(1, 10)
    inter, timeout = 0.02, 0.2
    t0 = time.monotonic()
    result = arp._scapy_sender(make_adapter(), ips, timeout, inter=inter)
    elapsed = time.monotonic() - t0
    sending = len(ips) * inter
    assert result == {f"{NET}.3": "aa:bb:cc:00:00:03"}
    assert sending + timeout <= elapsed < sending + timeout + 0.5 + 0.2  # 0,2 s Spielraum für den Testrechner
    (sniffer,) = fake.sniffers
    assert sniffer.thread is not None and not sniffer.thread.is_alive()  # kein hängender Mitlese-Thread
    assert sniffer.running is False


def test_scapy_sender_matches_only_replies_to_us_for_asked_addresses(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    packets = [
        _Reply(f"{NET}.5", "aa:bb:cc:00:00:05", op=1),  # Anfrage, keine Antwort
        _Reply(f"{NET}.6", "aa:bb:cc:00:00:06", pdst=f"{NET}.99"),  # Antwort an einen anderen Rechner
        _Reply(f"{NET}.7", "aa:bb:cc:00:00:07"),  # nicht gefragt
        _Reply(f"{NET}.8", "aa:bb:cc:00:00:08"),  # gültig
    ]
    install_fake_scapy(monkeypatch, {"x": make_iface("192.168.178.20")}, packets=packets)
    result = arp._scapy_sender(make_adapter(), [f"{NET}.5", f"{NET}.6", f"{NET}.8"], 1.0)
    assert result == {f"{NET}.8": "aa:bb:cc:00:00:08"}


def test_scapy_sender_first_reply_wins(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    packets = [_Reply(f"{NET}.5", "aa:bb:cc:00:00:01"), _Reply(f"{NET}.5", "aa:bb:cc:00:00:02")]
    install_fake_scapy(monkeypatch, {"x": make_iface("192.168.178.20")}, packets=packets)
    assert arp._scapy_sender(make_adapter(), [f"{NET}.5"], 1.0) == {f"{NET}.5": "aa:bb:cc:00:00:01"}


def test_scapy_sender_without_own_ipv4_skips_target_check(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    packets = [_Reply(f"{NET}.5", "aa:bb:cc:00:00:05", pdst="0.0.0.0")]
    fake = install_fake_scapy(monkeypatch, {"x": make_iface("", "00:1b:21:00:00:20")}, packets=packets)
    assert arp._scapy_sender(make_adapter(ipv4=""), [f"{NET}.5"], 1.0) == {f"{NET}.5": "aa:bb:cc:00:00:05"}
    assert "psrc" not in fake.sendp_calls[0]["packet"].payload.fields


def test_scapy_sender_skips_replies_without_arp_layer(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    packets = [_Reply(f"{NET}.5", "aa:bb:cc:00:00:05", with_arp=False)]
    install_fake_scapy(monkeypatch, {"x": make_iface("192.168.178.20")}, packets=packets)
    assert arp._scapy_sender(make_adapter(), [f"{NET}.5"], 1.0) == {}


def test_scapy_sender_without_matching_interface_is_unavailable(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    fake = install_fake_scapy(monkeypatch, {"x": make_iface("10.0.0.5", "00:00:00:00:00:05")})
    with pytest.raises(ArpUnavailable, match="nicht gefunden") as info:
        arp._scapy_sender(make_adapter(name="Ethernet"), [f"{NET}.5"], 1.0)
    assert "Ethernet" in str(info.value)
    assert fake.sniffers == [] and fake.sendp_calls == []


def test_scapy_sender_import_failure_is_unavailable(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setitem(sys.modules, "scapy.all", None)  # erzwingt ImportError
    with pytest.raises(ArpUnavailable, match="Scapy"):
        arp._scapy_sender(make_adapter(), [f"{NET}.5"], 1.0)


def test_scapy_sender_sniffer_that_never_starts_is_unavailable(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(arp, "_SNIFF_START_S", 0.05)
    fake = install_fake_scapy(monkeypatch, {"x": make_iface("192.168.178.20")}, start_mode="nie")
    with pytest.raises(ArpUnavailable, match="startet nicht") as info:
        arp._scapy_sender(make_adapter(name="WLAN"), [f"{NET}.5"], 1.0)
    assert "WLAN" in str(info.value)
    assert fake.sendp_calls == []  # ohne Mitlesen wird nichts gesendet


def test_scapy_sender_sniffer_open_error_is_reported_at_once(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    fake = install_fake_scapy(monkeypatch, {"x": make_iface("192.168.178.20")}, start_mode="fehler")
    t0 = time.monotonic()
    with pytest.raises(ArpUnavailable, match="startet nicht: Adapter lässt sich nicht öffnen") as info:
        arp._scapy_sender(make_adapter(), [f"{NET}.5"], 1.0)
    assert time.monotonic() - t0 < 1.0  # nicht erst die vollen 2 s abwarten
    assert isinstance(info.value.__cause__, OSError)
    assert fake.sendp_calls == []


def test_scapy_sender_late_sniffer_stops_itself(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # Meldet sich das Mitlesen erst nach Ablauf der Wartezeit, wirkte stop() davor noch nicht – es muss sich selbst anhalten.
    monkeypatch.setattr(arp, "_SNIFF_START_S", 0.05)
    fake = install_fake_scapy(monkeypatch, {"x": make_iface("192.168.178.20")}, start_mode="thread", start_delay_s=0.2)
    with pytest.raises(ArpUnavailable, match="startet nicht"):
        arp._scapy_sender(make_adapter(), [f"{NET}.5"], 1.0)
    (sniffer,) = fake.sniffers
    assert sniffer.thread is not None
    sniffer.thread.join(2)
    assert not sniffer.thread.is_alive()
    assert fake.sendp_calls == []


def test_scapy_sender_sniffer_that_does_not_stop_is_unavailable(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    install_fake_scapy(monkeypatch, {"x": make_iface("192.168.178.20")}, start_mode="hängt")
    with pytest.raises(ArpUnavailable, match="nicht rechtzeitig beenden"):
        arp._scapy_sender(make_adapter(), [f"{NET}.5"], 1.0)


@pytest.mark.parametrize("error", [OSError("winpcap is not installed"), PermissionError("Operation not permitted"), RuntimeError("kaputt")])
def test_scapy_sender_send_errors_are_unavailable(monkeypatch, error) -> None:  # type: ignore[no-untyped-def]
    fake = install_fake_scapy(monkeypatch, {"x": make_iface("192.168.178.20")}, error=error)
    with pytest.raises(ArpUnavailable, match="Administrator") as info:
        arp._scapy_sender(make_adapter(), [f"{NET}.5"], 1.0)
    assert info.value.__cause__ is error


@pytest.mark.parametrize("start_mode", ["sofort", "thread"])
def test_scapy_sender_stops_sniffer_when_sendp_fails(monkeypatch, start_mode) -> None:  # type: ignore[no-untyped-def]
    fake = install_fake_scapy(monkeypatch, {"x": make_iface("192.168.178.20")}, error=OSError("Adapter weg"), start_mode=start_mode)
    with pytest.raises(ArpUnavailable):
        arp._scapy_sender(make_adapter(), [f"{NET}.5"], 1.0)
    (sniffer,) = fake.sniffers
    assert sniffer.stop_calls >= 1 and sniffer.running is False
    assert sniffer.thread is None or not sniffer.thread.is_alive()


def test_scapy_sender_does_not_hide_assertion_errors(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    fake = install_fake_scapy(monkeypatch, {"x": make_iface("192.168.178.20")}, error=AssertionError("Testsperre"))
    with pytest.raises(AssertionError, match="Testsperre"):
        arp._scapy_sender(make_adapter(), [f"{NET}.5"], 1.0)
    assert fake.sniffers[0].running is False  # auch dann angehalten


def test_scapy_sender_without_addresses_sends_nothing(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    fake = install_fake_scapy(monkeypatch, {"x": make_iface("192.168.178.20")})
    assert arp._scapy_sender(make_adapter(), [], 1.0) == {}
    assert fake.sendp_calls == [] and fake.sniffers == []


def test_lan_lock_blocks_real_scapy_sniffer_and_sender(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # Ohne Attrappe greift die Sperre aus conftest; der Sender tarnt sie nicht als ArpUnavailable.
    scapy_all = pytest.importorskip("scapy.all")
    import scapy.sendrecv as scapy_sendrecv

    from tests.conftest import LanTrafficError

    for mod in (scapy_all, scapy_sendrecv):
        for name in ("AsyncSniffer", "sendp", "sniff", "srp"):
            assert getattr(mod, name).__name__ == "_scapy_forbidden", f"{mod.__name__}.{name} ist nicht gesperrt"
    monkeypatch.setattr(arp, "_find_iface", lambda conf, adapter: SimpleNamespace(name="attrappe", mac="00:1b:21:00:00:20"))
    with pytest.raises(LanTrafficError):
        arp._scapy_sender(make_adapter(), [f"{NET}.5"], 0.1)


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


def test_scapy_sender_on_linux_filters_in_python_without_libpcap(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # Ohne libpcap ließe sich der BPF-Filter unter Linux nicht übersetzen – dann filtert lfilter in Python.
    fake = install_fake_scapy(monkeypatch, {"x": make_iface("192.168.178.20")})
    monkeypatch.setattr(arp, "_is_windows", lambda: False)
    arp._scapy_sender(make_adapter(), [f"{NET}.5"], 1.0)
    (sniffer,) = fake.sniffers
    assert "filter" not in sniffer.kwargs and callable(sniffer.kwargs["lfilter"])


def test_scapy_sender_stops_the_sniffer_only_once(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # Kein zweites join im finally: sonst könnte der Abbruch zwischen zwei Blöcken über 5 s dauern.
    fake = install_fake_scapy(monkeypatch, {"x": make_iface("192.168.178.20")})
    arp._scapy_sender(make_adapter(), [f"{NET}.5"], 2.0)
    (sniffer,) = fake.sniffers
    assert len(sniffer.join_timeouts) == 2  # Lauschen (≤ 2 s) und ein Nachlauf nach stop()
    assert sniffer.join_timeouts[0] <= 2.0 and sum(sniffer.join_timeouts) <= 2.0 + arp._STOP_JOIN_S
