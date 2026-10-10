"""Monitor: prüft ausgewählte Geräte zyklisch und meldet Ausfälle (BAUPLAN §18, §22).

Läuft als eigener Thread neben dem JobRunner. Vor jedem Durchlauf fragt er je Adapter den Netz-Wächter;
gesendet wird nur bei „allow“. Ein Fehler in einem Durchlauf beendet nie den Thread.
Meldungen nach außen nur über den EventBus (wie in Stufe 1).
"""

from __future__ import annotations

import ipaddress
import logging
import queue
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

from netscan import config
from netscan.core.context import CancelToken, RateLimiter, ScanCancelled
from netscan.core.models import (
    Adapter,
    CheckResult,
    Device,
    GuardResult,
    MonitorStatus,
    MonitorTarget,
    Sample,
    ScanOutcome,
    ServiceCheck,
    iso_from_ts,
    normalize_mac,
)
from netscan.core.metrics import RAW_KEEP_DAYS
from netscan.core.targets import validate_check
from netscan.net import adapters, checks, ports

if TYPE_CHECKING:
    from netscan.core.services import Services

log = logging.getLogger(__name__)

MAX_PARALLEL = 16  # höchstens so viele Ziele gleichzeitig
MONITOR_RATE = 50.0  # höchstens so viele Vorgänge pro Sekunde (eigener Token-Bucket)
MAINTENANCE_S = 3600  # Verdichtung und Aufräumen einmal je Stunde
# Uhrsprung nach vorn: die Wartung rechnet höchstens so weit über die monoton gemessene Laufzeit hinaus
MAINTENANCE_SLACK_S = 86400
STOP_WAIT_S = 0.25  # Takt, in dem Warten und Parallelarbeit auf stop() achten
_PAUSE_TEXT = {
    "blocked": "Netz gesperrt",
    "confirm": "Bestätigung nötig",
    "no_adapter": "kein passendes Netz",
    "other_network": "anderes Netz",
    "disabled": "abgeschaltet",
}


@dataclass
class _Active:
    """Ein Ziel, das in diesem Durchlauf geprüft wird."""

    target: MonitorTarget
    device: Device
    adapter: Adapter
    gateway_mac: str | None = None  # Router-MAC laut Wächter (wird gelernt, sobald das Gerät bestätigt ist)
    reach: CheckResult | None = None
    services: dict[int, CheckResult] | None = None
    gone: bool = False  # Absenderadresse verschwunden (Netzwechsel)
    confirmed: bool = False  # im Durchlauf wiedererkannt (ARP-Cache zeigt die MAC des Ziels bzw. eigene Adresse)


class Monitor:
    def __init__(self, services: Services, *, clock: Callable[[], float] = time.time) -> None:
        self.services = services
        self._clock = clock
        self._lock = threading.RLock()  # schützt _status und _guard_seen
        self._cycle_lock = threading.Lock()  # genau ein Durchlauf zur Zeit
        # Kurze Sperre: Ergebnisse eines Durchlaufs speichern vs. Ziele/Prüfungen ändern oder löschen (nie während
        # der Netzprüfungen gehalten – die Web-API wartet höchstens Millisekunden)
        self._state_lock = threading.RLock()
        self._wake = threading.Event()
        self._cancel = CancelToken()
        self._thread: threading.Thread | None = None
        self._status = MonitorStatus(state="stopped")
        self._last_maintenance: float | None = None  # Zeitpunkt (Wanduhr) der letzten Wartung, ggf. begrenzt
        self._last_maintenance_mono: float | None = None  # derselbe Zeitpunkt auf der monotonen Uhr
        self._monotonic: Callable[[], float] = time.monotonic  # Takt der Wartung; Tests ersetzen ihn
        self._guard_seen: dict[str, tuple[str, str]] = {}  # Adapter -> (decision, code) für guard.result bei Wechsel

    # --- Thread ----------------------------------------------------------------
    def start(self) -> None:
        """Startet den Monitor-Thread (idempotent). Nur server.run() ruft das auf, Tests nicht."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._cancel = CancelToken()
            self._wake.clear()
            thread = threading.Thread(target=self._loop, name="monitor", daemon=True)
            self._thread = thread
            self._status = replace(self._status, state="idle", reason="")
        thread.start()
        log.info("Überwachung gestartet.")

    def stop(self, timeout: float = 6.0) -> None:
        """Hält den Monitor an (kehrt nach etwa STOP_WAIT_S zurück).

        Laufende Prüfungen enden nach ihrer aktuellen Netzoperation; ihre Threads sind Daemon-Threads und halten das
        Programmende nicht auf.
        """
        with self._lock:
            thread = self._thread
            self._cancel.cancel()
            self._wake.set()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout)
        with self._lock:
            self._thread = None
            self._status = replace(self._status, state="stopped", reason="", next_cycle=None)

    def trigger(self) -> None:
        """Nächsten Durchlauf sofort starten (z. B. „Jetzt prüfen“, neues Ziel)."""
        self._wake.set()

    @property
    def running(self) -> bool:
        thread = self._thread
        return thread is not None and thread.is_alive()

    def status(self) -> MonitorStatus:
        with self._lock:
            return replace(self._status)

    def _loop(self) -> None:
        cancel = self._cancel
        last_start: float | None = None
        while not cancel.cancelled:
            interval = self._interval()
            due = 0.0 if last_start is None else last_start + interval
            with self._lock:
                if last_start is not None:
                    self._status.next_cycle = iso_from_ts(self._clock() + max(0.0, due - time.monotonic()))
            woke = self._wake.wait(min(1.0, max(0.0, due - time.monotonic())))
            if cancel.cancelled:
                break
            if not woke and time.monotonic() < due:
                continue  # weiter warten; das Intervall wird jede Sekunde neu gelesen
            self._wake.clear()
            last_start = time.monotonic()
            try:
                self.run_cycle()
            except ScanCancelled:
                break
            except Exception:  # noqa: BLE001 – der Monitor-Thread darf nie sterben
                log.exception("Überwachung: Durchlauf fehlgeschlagen")
        log.info("Überwachung beendet.")

    def _interval(self) -> float:
        try:
            return float(self.services.settings.load().monitor_interval_s)
        except Exception:  # noqa: BLE001
            return 60.0

    # --- Durchlauf -------------------------------------------------------------
    def run_cycle(self, now: float | None = None) -> MonitorStatus:
        """Ein vollständiger Durchlauf. Gibt den neuen Zustand zurück."""
        with self._cycle_lock:
            t0 = time.monotonic()
            now = float(now) if now is not None else float(self._clock())
            svc = self.services
            settings = svc.settings.load()
            if not settings.monitor_enabled:
                return self._finish_empty("off", "Die Überwachung ist in den Einstellungen ausgeschaltet.", now, t0)
            targets = svc.targets.list(enabled_only=True)
            if not targets:
                return self._finish_empty("idle", "Keine Geräte zur Überwachung ausgewählt.", now, t0)

            devices = {d.mac: d for d in svc.inventory.list_devices()}
            adapter_list = adapters.list_adapters(svc.platform, include_virtual=True)
            own_ips = {a.ipv4 for a in adapter_list if a.is_up and a.ipv4}
            groups: dict[str, tuple[Adapter, list[MonitorTarget]]] = {}
            pauses: list[tuple[MonitorTarget, str, str]] = []  # (Ziel, Grund, Text) – übernommen erst beim Speichern
            for t in targets:
                device = devices.get(t.mac)
                adapter = _adapter_for_ip(adapter_list, device.ip) if device is not None else None
                if device is None or adapter is None:
                    where = device.ip if device is not None else t.mac
                    pauses.append((t, "no_adapter", f"{where} liegt in keinem Netz eines verbundenen Adapters."))
                    continue
                if device.is_self and device.ip not in own_ips:
                    # Eigener PC ohne ARP-Wiedererkennung: nur unter einer eigenen Adresse prüfen, sonst antwortet
                    # unter der alten IP ein anderes Gerät (Pause wie bei fehlender Absenderadresse, §18)
                    pauses.append((
                        t, "no_adapter",
                        f"Die gespeicherte Adresse {device.ip} gehört nicht mehr zu diesem PC. Ein Scan aktualisiert sie.",
                    ))  # fmt: skip
                    continue
                groups.setdefault(adapter.name, (adapter, []))[1].append(t)

            active: list[_Active] = []
            for adapter, group in groups.values():
                guard = self._guard(adapter)
                if guard.decision != "allow":
                    code = "blocked" if guard.decision == "block" else "confirm"
                    text = (
                        f"Gesperrt: {guard.reason}" if code == "blocked" else f"Der Wächter verlangt eine Bestätigung: {guard.reason}"
                    )
                    pauses.extend((t, code, text) for t in group)
                    continue
                for t in group:
                    if t.gateway_mac and guard.gateway_mac and t.gateway_mac != guard.gateway_mac:
                        pauses.append((
                            t, "other_network",
                            f"Anderes Netz: Router {guard.gateway_mac} statt {t.gateway_mac}. Findet ein Scan das Gerät "
                            "in diesem Netz, wird es dort weiter überwacht.",
                        ))  # fmt: skip
                        continue
                    active.append(_Active(t, devices[t.mac], adapter, gateway_mac=guard.gateway_mac))

            if active:
                self._measure(active, settings)
            with self._state_lock:
                kept, all_targets = self._store(active, pauses, devices, settings, now)

            status = self._summarize(all_targets, bool(kept), now, t0)
            self._publish_cycle(all_targets, now)
            self._maybe_maintenance(now)
            return status

    def _store(
        self,
        active: list[_Active],
        pauses: list[tuple[MonitorTarget, str, str]],
        devices: dict[str, Device],
        settings: Any,
        now: float,
    ) -> tuple[list[_Active], list[MonitorTarget]]:
        """Ergebnisse übernehmen und speichern; nur unter _state_lock aufrufen.

        Jedes Ziel wird vorher neu gelesen: Während der Netzprüfungen gelöschte oder abgeschaltete Ziele bzw. Prüfungen
        bekommen weder Messwert noch Alert-Auswertung noch Zustand – sonst überschriebe der Durchlauf das Abschalten
        bzw. Löschen und öffnete gerade geschlossene Zustands-Alerts wieder. Gibt (geprüfte Ziele, alle Ziele) zurück.
        """
        svc = self.services
        current = {t.id: t for t in svc.targets.list()}
        paused: list[MonitorTarget] = []
        for t, code, reason in pauses:
            fresh = current.get(t.id)
            if fresh is None or not fresh.enabled:
                continue
            self._pause(fresh, code, reason, now)
            paused.append(fresh)
        kept: list[_Active] = []
        for item in active:
            fresh = current.get(item.target.id)
            if fresh is None or not fresh.enabled:
                continue
            item.target = fresh  # aktuelle Prüfungen und Schwellen; Messergebnisse hängen an der Prüfungs-ID
            self._learn_network(item)
            kept.append(item)

        samples = self._apply(kept, settings, now)
        if samples:
            try:
                svc.metrics.record(samples)
            except Exception:  # noqa: BLE001 – Messwerte fehlen dann, der Monitor läuft weiter
                log.exception("Überwachung: Messwerte nicht gespeichert")

        all_targets = [a.target for a in kept] + paused
        for t in all_targets:
            self._evaluate_alerts(t, devices.get(t.mac), now)
            try:
                svc.targets.save_state(t)
            except Exception:  # noqa: BLE001
                log.exception("Überwachung: Zustand von %s nicht gespeichert", t.mac)
        return kept, all_targets

    def _learn_network(self, item: _Active) -> None:
        """Router-MAC eines Ziels ohne Netz erst übernehmen, wenn das Gerät in diesem Netz wiedererkannt wurde.

        Sonst lernte ein Ziel, das in einem fremden Netz mit gleichem Adressbereich angelegt wird, dessen Router und
        stünde daheim bis zum nächsten Scan auf „anderes Netz“.
        """
        t = item.target
        if t.gateway_mac or not item.gateway_mac or not item.confirmed or item.gone:
            return
        try:
            self.services.targets.set_network(t.id, item.gateway_mac, item.adapter.network)
        except Exception:  # noqa: BLE001 – dann im nächsten Durchlauf
            log.warning("Überwachung: Netz von %s nicht gespeichert", t.mac, exc_info=True)
            return
        t.gateway_mac, t.network = item.gateway_mac, item.adapter.network

    def _guard(self, adapter: Adapter) -> GuardResult:
        """Wächter je Adapter. Ein Fehler gilt als Sperre (sichere Richtung)."""
        try:
            guard = self.services.guard.check(adapter, quiet=True)
        except Exception:  # noqa: BLE001
            log.exception("Überwachung: Netz-Wächter fehlgeschlagen – Ziele pausiert")
            guard = GuardResult(decision="block", code="unknown_network", reason="Der Netz-Wächter konnte nicht prüfen.")
        seen = (guard.decision, guard.code)
        with self._lock:
            changed = self._guard_seen.get(adapter.name) != seen
            self._guard_seen[adapter.name] = seen
        if changed:
            self.services.bus.publish("guard.result", {"guard": guard.to_dict()})
        return guard

    def _measure(self, active: list[_Active], settings: Any) -> None:
        """Erreichbarkeit aller Ziele, dann ARP-Cache (Wiedererkennung), dann Dienstprüfungen."""
        timeout_ms = int(settings.monitor_timeout_ms)
        cancel = self._cancel
        rate = RateLimiter(MONITOR_RATE, cancel=cancel)
        platform = self.services.platform

        def reach(item: _Active) -> None:
            t, d = item.target, item.device
            if cancel.cancelled:
                raise ScanCancelled()
            rate.acquire()
            tcp_ports = [t.tcp_port] if t.tcp_port else _safe_fallback_ports(d)
            try:
                item.reach = checks.check_reachability(
                    d.ip, method=t.method, ping=platform.ping, timeout_ms=timeout_ms, tcp_ports=tcp_ports,
                    source_ip=item.adapter.ipv4,
                )  # fmt: skip
            except ports.SourceAddressGone:
                item.gone = True

        self._parallel(reach, active)

        reached = [a for a in active if a.reach is not None and a.reach.ok]
        foreign = [a for a in reached if not a.device.is_self]
        if foreign:
            try:
                neighbors = platform.neighbor_table()
            except Exception:  # noqa: BLE001 – ohne ARP-Cache keine Wiedererkennung, aber kein Ausfall
                log.debug("ARP-Cache nicht lesbar", exc_info=True)
                neighbors = {}
            for item in foreign:
                seen = neighbors.get(item.device.ip)
                try:
                    seen_mac = normalize_mac(seen) if seen else None
                except ValueError:
                    seen_mac = None
                if seen_mac and seen_mac != item.target.mac:
                    item.reach = CheckResult(
                        ok=False,
                        detail=f"Unter {item.device.ip} antwortet ein anderes Gerät ({seen_mac}).",
                        method=item.reach.method if item.reach else "",
                    )
                elif seen_mac == item.target.mac:
                    item.confirmed = True
        for item in reached:
            if item.device.is_self:
                item.confirmed = True  # Adresse gehört zu diesem PC (vor dem Durchlauf geprüft)

        def services(item: _Active) -> None:
            if item.gone or item.reach is None or not item.reach.ok:
                return
            results: dict[int, CheckResult] = {}
            for c in item.target.checks:
                if not c.enabled:
                    continue
                if cancel.cancelled:  # stop(): keine weitere Prüfung beginnen
                    raise ScanCancelled()
                rate.acquire()
                try:
                    results[c.id] = checks.run_check(
                        c.kind, item.device.ip, c.port, timeout_ms / 1000, path=c.path, source_ip=item.adapter.ipv4
                    )
                except ports.SourceAddressGone:
                    item.gone = True
                    return
                except ScanCancelled:
                    raise
                except Exception as exc:  # noqa: BLE001 – eine kaputte Prüfung zählt als Ausfall dieses Dienstes
                    log.debug("Prüfung %s fehlgeschlagen", c.id, exc_info=True)
                    results[c.id] = CheckResult(ok=False, detail=f"Prüfung fehlgeschlagen: {type(exc).__name__}", method=c.kind)
            item.services = results

        if any(a.target.checks for a in active):
            self._parallel(services, active)

    def _parallel(self, fn: Callable[[_Active], None], items: list[_Active]) -> None:
        """fn für alle Ziele parallel; abbrechbar über stop(). Fehler einzelner Ziele werden geloggt.

        Eigene Daemon-Threads statt ThreadPoolExecutor: dessen Arbeiter wartet der Interpreter beim Beenden ab (auch
        nach shutdown(wait=False)), eine laufende Prüfung hielte sonst das Programmende auf. Nach stop() nimmt kein
        Arbeiter ein weiteres Ziel an.
        """
        if not items:
            return
        cancel = self._cancel
        todo: queue.SimpleQueue[_Active] = queue.SimpleQueue()
        for item in items:
            todo.put(item)
        done: queue.SimpleQueue[tuple[_Active, BaseException | None]] = queue.SimpleQueue()

        def worker() -> None:
            while not cancel.cancelled:
                try:
                    item = todo.get_nowait()
                except queue.Empty:
                    return
                try:
                    fn(item)
                except BaseException as exc:  # noqa: BLE001 – ausgewertet im Durchlauf
                    done.put((item, exc))
                else:
                    done.put((item, None))

        for n in range(max(1, min(MAX_PARALLEL, len(items)))):
            threading.Thread(target=worker, name=f"monitor-probe-{n}", daemon=True).start()
        pending = len(items)
        while pending:
            if cancel.cancelled:
                raise ScanCancelled()
            try:
                item, exc = done.get(timeout=STOP_WAIT_S)
            except queue.Empty:
                continue
            pending -= 1
            if isinstance(exc, ScanCancelled):
                raise exc
            if exc is not None:
                log.warning("Überwachung: Prüfung von %s fehlgeschlagen: %r", item.device.ip, exc)
                if item.reach is None:
                    item.reach = CheckResult(ok=False, detail=f"Prüfung fehlgeschlagen: {type(exc).__name__}")

    def _apply(self, active: list[_Active], settings: Any, now: float) -> list[Sample]:
        """Ergebnisse in die Zustände der Ziele übernehmen. Gibt die Messwerte zurück."""
        iso = iso_from_ts(now)
        ts = int(now)
        samples: list[Sample] = []
        for item in active:
            t = item.target
            if item.gone or item.reach is None:
                self._pause(t, "no_adapter", f"Die Adresse von „{item.adapter.name}“ ist verschwunden (Netzwechsel?).", now)
                continue
            reach = item.reach
            t.pause_code, t.pause_reason = None, ""
            t.last_check = iso
            t.last_detail = reach.detail
            t.last_method = reach.method
            t.last_rtt_ms = reach.rtt_ms if reach.ok else None
            samples.append(Sample(t.id, 0, ts, reach.ok, reach.rtt_ms if reach.ok else None))
            if reach.ok:
                t.down_since = None
                threshold = t.rtt_threshold_ms
                if threshold and reach.rtt_ms is not None and reach.rtt_ms > threshold:
                    t.rtt_high_since = t.rtt_high_since or iso
                else:
                    t.rtt_high_since = None
                results = item.services or {}
                any_down = False
                for c in t.checks:
                    res = results.get(c.id) if c.enabled else None
                    if res is None:
                        _set_check(c, "unknown", iso, detail="abgeschaltet" if not c.enabled else "nicht geprüft")
                        continue
                    samples.append(Sample(t.id, c.id, ts, res.ok, res.rtt_ms if res.ok else None))
                    c.last_check = iso
                    c.last_rtt_ms = res.rtt_ms if res.ok else None
                    if res.ok:
                        _set_check(c, "up", iso, detail=res.detail)
                    else:
                        _set_check(c, "down", iso, detail=res.detail)
                        any_down = True
                _set_status(t, "degraded" if any_down or t.rtt_high_since else "online", iso)
            else:
                t.down_since = t.down_since or iso
                t.rtt_high_since = None
                for c in t.checks:
                    _set_check(c, "unknown", iso, detail="Gerät nicht erreichbar")
                _set_status(t, "offline", iso)
        return samples

    def _pause(self, t: MonitorTarget, code: str, reason: str, now: float) -> None:
        """Ziel pausieren: keine Messung, keine Ausfallzählung (Pausen sind Lücken, keine Ausfälle)."""
        iso = iso_from_ts(now)
        t.pause_code = code  # type: ignore[assignment]
        t.pause_reason = reason
        t.down_since = None
        t.rtt_high_since = None
        for c in t.checks:
            _set_check(c, "unknown", iso, detail=f"pausiert ({_PAUSE_TEXT.get(code, code)})")
        _set_status(t, "paused", iso)

    def _evaluate_alerts(self, t: MonitorTarget, device: Device | None, now: float) -> None:
        engine = self.services.alert_engine
        try:
            engine.evaluate_target(t, device, now)
            for c in t.checks:
                engine.evaluate_check(t, c, device, now)
        except Exception:  # noqa: BLE001 – Alerts dürfen den Monitor nie stoppen
            log.exception("Überwachung: Alert-Auswertung für %s fehlgeschlagen", t.mac)

    def _finish_empty(self, state: str, reason: str, now: float, t0: float) -> MonitorStatus:
        status = self._set_status_counts(state, reason, [], now, t0)
        self._maybe_maintenance(now)
        return status

    def _summarize(self, targets: list[MonitorTarget], any_active: bool, now: float, t0: float) -> MonitorStatus:
        if not targets:  # alle Ziele während des Durchlaufs abgeschaltet oder gelöscht
            return self._set_status_counts("idle", "Keine Geräte zur Überwachung ausgewählt.", [], now, t0)
        if any_active:
            return self._set_status_counts("running", "", targets, now, t0)
        reasons = {t.pause_reason for t in targets if t.pause_reason}
        reason = reasons.pop() if len(reasons) == 1 else "Alle überwachten Geräte sind pausiert."
        return self._set_status_counts("paused", reason, targets, now, t0)

    def _set_status_counts(
        self, state: str, reason: str, targets: list[MonitorTarget], now: float, t0: float
    ) -> MonitorStatus:
        counts = {"online": 0, "degraded": 0, "offline": 0, "paused": 0, "unknown": 0}
        for t in targets:
            counts[t.status if t.status in counts else "unknown"] += 1
        with self._lock:
            thread_alive = self._thread is not None and self._thread.is_alive()
            self._status = replace(
                self._status,
                state=state,  # type: ignore[arg-type]
                reason=reason,
                interval_s=self._interval_int(),
                last_cycle=iso_from_ts(now),
                cycle_ms=round((time.monotonic() - t0) * 1000, 1),
                targets=len(targets),
                **counts,
            )
            if not thread_alive:
                self._status.next_cycle = None
            status = replace(self._status)
        self.services.bus.publish("monitor.status", {"status": status.to_dict()})
        return status

    def _interval_int(self) -> int:
        return int(self._interval())

    def _publish_cycle(self, targets: list[MonitorTarget], now: float) -> None:
        self.services.bus.publish(
            "monitor.cycle",
            {
                "ts": iso_from_ts(now),
                "targets": [
                    {
                        "mac": t.mac,
                        "status": t.status,
                        "status_since": t.status_since,
                        "rtt_ms": t.last_rtt_ms,
                        "detail": t.pause_reason if t.status == "paused" else t.last_detail,
                        "checks": [
                            {"id": c.id, "status": c.status, "rtt_ms": c.last_rtt_ms, "detail": c.last_detail} for c in t.checks
                        ],
                    }
                    for t in targets
                ],
            },
        )

    def _maybe_maintenance(self, now: float) -> None:
        """Einmal je Stunde verdichten und aufräumen – robust gegen Sprünge der Wanduhr.

        Fällig nach einer Stunde Wanduhr ODER einer Stunde monotoner Zeit (ein Rücksprung der Uhr sperrt die Wartung
        so nicht). Die Grenzen von compact/prune rechnen höchstens mit der monoton fortgeschriebenen Zeit der letzten
        Wartung plus MAINTENANCE_SLACK_S: ein kurzer Sprung nach vorn löscht so keinen Verlauf; eine dauerhaft
        vorgestellte Uhr holt die Wartung um höchstens diesen Betrag je Wartung ein.
        """
        mono = self._monotonic()
        when = now
        if self._last_maintenance is not None and self._last_maintenance_mono is not None:
            elapsed = max(0.0, mono - self._last_maintenance_mono)
            if now - self._last_maintenance < MAINTENANCE_S and elapsed < MAINTENANCE_S:
                return
            when = min(now, self._last_maintenance + elapsed + MAINTENANCE_SLACK_S)
            if when < now:
                log.warning("Überwachung: Uhr springt nach vorn – Wartung rechnet mit %s statt %s", iso_from_ts(when),
                            iso_from_ts(now))  # fmt: skip
        self._last_maintenance, self._last_maintenance_mono = when, mono
        svc = self.services
        keep_days = self._raw_keep_days(when)
        for what, fn in (
            ("Verdichtung", lambda: svc.metrics.compact(int(when), keep_days=keep_days)),
            ("Aufräumen der Messreihen", lambda: svc.metrics.prune_orphans(svc.targets.valid_series())),
            ("Aufräumen der Alerts", lambda: svc.alerts.prune(when)),
        ):
            try:
                fn()
            except Exception:  # noqa: BLE001
                log.warning("Überwachung: %s fehlgeschlagen", what, exc_info=True)
        try:
            size = svc.db.size_bytes()
        except Exception:  # noqa: BLE001
            size = None
        with self._lock:
            self._status.db_size_bytes = size
            self._status.raw_keep_days = keep_days

    def _raw_keep_days(self, when: float) -> int:
        """Tage Rohwerte nach dem Plattenbudget: 30 (Pflichtenheft), weniger nur, wenn die Rohwerte der letzten 24 h
        hochgerechnet mehr als config.RAW_BUDGET_BYTES belegen würden (extreme Einstellungen). Mindestens 1 Tag."""
        keep = int(RAW_KEEP_DAYS)
        try:
            per_day = int(self.services.metrics.raw_rows_since(int(when) - 86400))
        except Exception:  # noqa: BLE001 – ohne Zählung bleibt es bei 30 Tagen
            log.debug("Rohwerte nicht zählbar", exc_info=True)
            return keep
        if per_day > 0:
            fits = int(config.RAW_BUDGET_BYTES // (per_day * config.RAW_BYTES_PER_SAMPLE))
            keep = max(1, min(keep, fits))
        if keep < RAW_KEEP_DAYS and keep != self._status.raw_keep_days:
            log.warning(
                "Überwachung: Plattenbudget – Rohwerte werden nur %d Tag(e) aufbewahrt statt %d (%d Messwerte/Tag). "
                "Weniger Geräte/Dienste oder ein längeres Intervall halten 30 Tage.", keep, RAW_KEEP_DAYS, per_day,
            )
        return keep

    # --- Zielverwaltung (für die Web-API) --------------------------------------
    def add_target(
        self,
        mac: str,
        *,
        method: str = "auto",
        tcp_port: int | None = None,
        offline_after_min: int | None = None,
        rtt_threshold_ms: float | None = None,
        checks: list[dict[str, Any]] | None = None,
    ) -> MonitorTarget:
        """Legt ein Ziel samt Dienstprüfungen an. LookupError (Gerät), ValueError, TargetExists."""
        svc = self.services
        device = svc.inventory.get(mac)
        if device is None:
            raise LookupError(mac)
        specs: list[tuple[str, int, str]] = []
        for spec in checks or []:
            if not isinstance(spec, dict):
                raise ValueError("Jede Dienstprüfung braucht kind und port.")
            item = validate_check(spec.get("kind"), spec.get("port"), spec.get("path", "/"))
            if any(s[:2] == item[:2] for s in specs):
                raise ValueError(f"Die Prüfung {item[0]} {item[1]} ist doppelt angegeben.")
            specs.append(item)
        if len(specs) > config.MAX_CHECKS_PER_TARGET:
            raise ValueError(f"Höchstens {config.MAX_CHECKS_PER_TARGET} Dienstprüfungen je Gerät.")
        target = svc.targets.add(
            device.mac, method=method, tcp_port=tcp_port, offline_after_min=offline_after_min,
            rtt_threshold_ms=rtt_threshold_ms,
        )  # fmt: skip
        try:
            for kind, port, path in specs:
                svc.targets.add_check(target.id, kind, port, path)
        except Exception:
            svc.targets.remove(device.mac)  # alles oder nichts
            raise
        self._targets_changed()
        result = svc.targets.get(device.mac)
        assert result is not None
        return result

    def update_target(self, mac: str, **fields: Any) -> MonitorTarget:
        """Ändert Nutzerfelder. Abschalten pausiert das Ziel und schließt seine Zustands-Alerts."""
        svc = self.services
        with self._state_lock:  # ein laufender Durchlauf liest das Ziel vor dem Speichern neu
            before = svc.targets.get(mac)
            if before is None:
                raise LookupError(mac)
            target = svc.targets.update(mac, **fields)
            if before.enabled and not target.enabled:
                self._pause(target, "disabled", "Überwachung für dieses Gerät abgeschaltet.", self._clock())
                svc.targets.save_state(target)
                self._safe_engine("on_target_removed", target)
            elif not before.enabled and target.enabled:
                _set_status(target, "unknown", iso_from_ts(self._clock()))
                target.pause_code, target.pause_reason = None, ""
                svc.targets.save_state(target)
        self._targets_changed()
        result = svc.targets.get(mac)
        if result is None:  # gleichzeitig gelöscht
            raise LookupError(mac)
        return result

    def remove_target(self, mac: str) -> None:
        """Entfernt ein Ziel mit allen Messwerten; schließt seine Zustands-Alerts. LookupError."""
        svc = self.services
        with self._state_lock:
            target = svc.targets.remove(mac)
            if target is None:
                raise LookupError(mac)
            try:
                svc.metrics.delete_series(target.id)
            except Exception:  # noqa: BLE001 – Reste räumt die stündliche Wartung (prune_orphans) weg
                log.warning("Messwerte von %s nicht gelöscht", target.mac, exc_info=True)
            self._safe_engine("on_target_removed", target)
        self._targets_changed(trigger=False)

    def add_check(self, mac: str, kind: str, port: int, path: str = "/") -> ServiceCheck:
        target = self.services.targets.get(mac)
        if target is None:
            raise LookupError(mac)
        check = self.services.targets.add_check(target.id, kind, port, path)
        self._targets_changed()
        return check

    def update_check(self, check_id: int, enabled: bool) -> ServiceCheck:
        svc = self.services
        with self._state_lock:  # ein laufender Durchlauf liest die Prüfung vor dem Speichern neu
            before = svc.targets.get_check(check_id)
            if before is None:
                raise LookupError(check_id)
            check = svc.targets.update_check(check_id, enabled)
            if before.enabled and not check.enabled:
                target = svc.targets.get_by_id(check.target_id)
                if target is not None:
                    for c in target.checks:
                        if c.id == check.id:
                            _set_check(c, "unknown", iso_from_ts(self._clock()), detail="abgeschaltet")
                    svc.targets.save_state(target)
                    self._safe_engine("on_check_removed", target, check)
        self._targets_changed()
        result = svc.targets.get_check(check_id)
        if result is None:  # gleichzeitig gelöscht
            raise LookupError(check_id)
        return result

    def remove_check(self, check_id: int) -> None:
        svc = self.services
        with self._state_lock:
            check = svc.targets.remove_check(check_id)
            if check is None:
                raise LookupError(check_id)
            target = svc.targets.get_by_id(check.target_id)
            try:
                svc.metrics.delete_series(check.target_id, check.id)
            except Exception:  # noqa: BLE001
                log.warning("Messwerte der Prüfung %s nicht gelöscht", check.id, exc_info=True)
            if target is not None:
                self._safe_engine("on_check_removed", target, check)
        self._targets_changed(trigger=False)

    def suggestions(self, mac: str) -> list[dict[str, Any]]:
        """Dienstvorschläge aus dem Port-Scan, mit Kennzeichnung bereits aktiver Prüfungen. LookupError."""
        device = self.services.inventory.get(mac)
        if device is None:
            raise LookupError(mac)
        target = self.services.targets.get(device.mac)
        existing = {(c.kind, c.port) for c in target.checks} if target is not None else set()
        out = []
        for s in checks.suggest_checks(device):
            out.append({**s, "active": (s.get("kind"), s.get("port")) in existing})
        return out

    def on_scan(self, outcome: ScanOutcome) -> None:
        """Ein Scan hat Geräte im aktuellen Netz gefunden: deren Ziele überwachen in diesem Netz weiter."""
        if outcome.kind != "scan" or not outcome.gateway_mac:
            return
        seen = set(outcome.seen_macs)
        changed = False
        with self._state_lock:  # nicht zwischen Neulesen und Lernen eines Durchlaufs (_store)
            for t in self.services.targets.list():
                if t.mac in seen and (t.gateway_mac != outcome.gateway_mac or t.network != outcome.adapter.network):
                    self.services.targets.set_network(t.id, outcome.gateway_mac, outcome.adapter.network)
                    changed = True
        if changed:
            self._targets_changed()

    # --- intern ----------------------------------------------------------------
    def _targets_changed(self, trigger: bool = True) -> None:
        self.services.bus.publish("monitor.targets", {})
        if trigger and self.running:
            self.trigger()

    def _safe_engine(self, name: str, *args: Any) -> None:
        try:
            getattr(self.services.alert_engine, name)(*args)
        except Exception:  # noqa: BLE001
            log.warning("Alert-Auswertung %s fehlgeschlagen", name, exc_info=True)


# --- Hilfen ------------------------------------------------------------------------------------


def _set_status(t: MonitorTarget, status: str, iso: str | None) -> None:
    if t.status != status or t.status_since is None:
        t.status = status  # type: ignore[assignment]
        t.status_since = iso


def _set_check(c: ServiceCheck, status: str, iso: str | None, *, detail: str = "") -> None:
    if c.status != status or c.status_since is None:
        c.status = status  # type: ignore[assignment]
        c.status_since = iso
    c.last_detail = detail
    if status == "down":
        c.down_since = c.down_since or iso
    else:
        c.down_since = None
    if status == "unknown":
        c.last_rtt_ms = None


def _adapter_for_ip(adapter_list: list[Adapter], ip: str) -> Adapter | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for a in adapter_list:
        if not a.is_up or not a.ipv4:
            continue
        try:
            if addr in ipaddress.ip_network(a.network, strict=False):
                return a
        except ValueError:
            continue
    return None


def _safe_fallback_ports(device: Device) -> list[int]:
    try:
        return list(checks.fallback_tcp_ports(device))[:3]
    except Exception:  # noqa: BLE001
        log.debug("Ersatzports für %s nicht ermittelbar", device.ip, exc_info=True)
        return []
