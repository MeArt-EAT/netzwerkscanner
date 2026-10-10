"""Werkzeugkasten für jeden Scan-Auftrag: Abbruch, Drosselung, Meldungen, Parallelarbeit."""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable, Iterable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, TypeVar

if TYPE_CHECKING:
    from netscan.config import Settings
    from netscan.core.events import EventBus
    from netscan.platform.base import Platform

log = logging.getLogger(__name__)

T = TypeVar("T")
R = TypeVar("R")


class ScanCancelled(Exception):
    """Der Auftrag wurde abgebrochen."""


class GuardBlocked(Exception):
    """Der Netz-Wächter verbietet den Scan."""

    def __init__(self, guard: Any) -> None:
        super().__init__(getattr(guard, "reason", "Scan gesperrt"))
        self.guard = guard


class CancelToken:
    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def wait(self, timeout: float) -> bool:
        """Wartet höchstens timeout Sekunden; True, wenn inzwischen abgebrochen wurde."""
        return self._event.wait(timeout)


class RateLimiter:
    """Token-Bucket: höchstens rate Vorgänge pro Sekunde (thread-sicher, abbrechbar)."""

    def __init__(self, rate: float, burst: float | None = None, cancel: CancelToken | None = None) -> None:
        self.rate = max(1.0, float(rate))
        self.capacity = burst if burst is not None else max(1.0, self.rate / 10)
        self._tokens = self.capacity
        self._last = time.monotonic()
        self._lock = threading.Lock()
        self._cancel = cancel

    def acquire(self, n: float = 1.0) -> None:
        """Wartet, bis n Vorgänge erlaubt sind. Größere n als die Bucket-Größe werden gestückelt."""
        while n > self.capacity:
            self._acquire(self.capacity)
            n -= self.capacity
        if n > 0:
            self._acquire(n)

    def _acquire(self, n: float) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                self._tokens = min(self.capacity, self._tokens + (now - self._last) * self.rate)
                self._last = now
                if self._tokens >= n:
                    self._tokens -= n
                    return
                wait_s = (n - self._tokens) / self.rate
            if self._cancel is not None:
                if self._cancel.wait(min(wait_s, 0.2)):
                    raise ScanCancelled()
            else:
                time.sleep(min(wait_s, 0.2))


@dataclass
class ScanContext:
    job_id: str
    bus: EventBus
    settings: Settings
    platform: Platform
    cancel: CancelToken = field(default_factory=CancelToken)
    rate: RateLimiter | None = None
    scan_id: int | None = None  # vom Pipeline-Code gesetzt (Inventory.begin_scan)
    log_sink: Callable[[int | None, str, str], None] | None = None  # (scan_id, level, message) -> speichern
    _status_cb: Callable[[str | None, int, int, str], None] | None = None

    def __post_init__(self) -> None:
        if self.rate is None:
            self.rate = RateLimiter(self.settings.rate_pps, cancel=self.cancel)

    # --- Abbruch -------------------------------------------------------------
    def check_cancel(self) -> None:
        if self.cancel.cancelled:
            raise ScanCancelled()

    def sleep(self, seconds: float) -> None:
        """Abbrechbares Warten."""
        if self.cancel.wait(seconds):
            raise ScanCancelled()

    # --- Meldungen -----------------------------------------------------------
    def emit(self, type: str, data: dict[str, Any] | None = None) -> None:
        self.bus.publish(type, data or {}, job_id=self.job_id)

    def log(self, message: str, level: str = "info") -> None:
        getattr(log, "warning" if level == "warning" else ("error" if level == "error" else "info"))(message)
        self.bus.publish("job.log", {"job_id": self.job_id, "level": level, "message": message}, job_id=self.job_id)
        if self.log_sink is not None:
            try:
                self.log_sink(self.scan_id, level, message)
            except Exception:  # Protokoll darf den Scan nie stoppen
                log.debug("Protokolleintrag nicht gespeichert", exc_info=True)

    def progress(self, phase: str, done: int, total: int, message: str = "") -> None:
        if self._status_cb is not None:
            self._status_cb(phase, done, total, message)
        self.bus.publish(
            "job.progress",
            {"job_id": self.job_id, "phase": phase, "done": done, "total": total, "message": message},
            job_id=self.job_id,
        )


def parallel_map(
    ctx: ScanContext,
    fn: Callable[[T], R],
    items: Iterable[T],
    workers: int,
    *,
    rate: bool = True,
    on_result: Callable[[T, R | None, int, int], None] | None = None,
) -> list[tuple[T, R | None]]:
    """Führt fn für alle items parallel aus.

    - gedrosselt über ctx.rate (ein Token pro Element), wenn rate=True
    - abbrechbar: bei Abbruch werden offene Aufgaben verworfen und ScanCancelled geworfen
    - Fehler einzelner Elemente ergeben None (DEBUG-Log), der Rest läuft weiter
    - on_result(item, result, done, total) wird im aufrufenden Thread aufgerufen (für Fortschritt)
    Rückgabe in Eingabereihenfolge.
    """
    items = list(items)
    total = len(items)
    results: list[R | None] = [None] * total
    if total == 0:
        return []
    ctx.check_cancel()

    def run(i: int) -> R | None:
        if ctx.cancel.cancelled:
            return None
        if rate and ctx.rate is not None:
            ctx.rate.acquire()
        if ctx.cancel.cancelled:
            return None
        return fn(items[i])

    pool = ThreadPoolExecutor(max_workers=max(1, min(workers, total)), thread_name_prefix=f"job-{ctx.job_id}")
    futures: dict[Future[R | None], int] = {}
    done_count = 0
    try:
        for i in range(total):
            futures[pool.submit(run, i)] = i
        pending = set(futures)
        while pending:
            finished, pending = wait(pending, timeout=0.25, return_when=FIRST_COMPLETED)
            if ctx.cancel.cancelled:
                raise ScanCancelled()
            for fut in finished:
                i = futures[fut]
                try:
                    results[i] = fut.result()
                except ScanCancelled:
                    raise
                except Exception:
                    log.debug("Fehler bei %r", items[i], exc_info=True)
                    results[i] = None
                done_count += 1
                if on_result is not None:
                    on_result(items[i], results[i], done_count, total)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return list(zip(items, results))
