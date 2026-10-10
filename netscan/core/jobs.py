"""Auftragssteuerung: genau ein Scan-Auftrag zur Zeit, jederzeit abbrechbar."""

from __future__ import annotations

import logging
import threading
import uuid
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from netscan.core.context import CancelToken, GuardBlocked, ScanCancelled, ScanContext
from netscan.core.models import JobStatus, utc_now_iso

if TYPE_CHECKING:
    from netscan.config import SettingsStore
    from netscan.core.events import EventBus
    from netscan.platform.base import Platform

log = logging.getLogger(__name__)

JobFn = Callable[[ScanContext], dict[str, Any]]


class JobBusyError(RuntimeError):
    """Es läuft bereits ein Auftrag."""


class JobRunner:
    def __init__(
        self,
        bus: EventBus,
        settings_store: SettingsStore,
        platform: Platform,
        log_sink: Callable[[int | None, str, str], None] | None = None,
    ) -> None:
        self._bus = bus
        self._settings_store = settings_store
        self._platform = platform
        self._log_sink = log_sink
        self._lock = threading.Lock()
        self._status = JobStatus()
        self._cancel: CancelToken | None = None
        self._thread: threading.Thread | None = None
        self._finished = threading.Event()
        self._finished.set()
        self.last_result: dict[str, Any] | None = None

    # --- Abfrage -------------------------------------------------------------
    def status(self) -> JobStatus:
        with self._lock:
            return JobStatus(**self._status.to_dict())

    @property
    def busy(self) -> bool:
        with self._lock:
            return self._status.state != "idle"

    # --- Steuerung -----------------------------------------------------------
    def start(self, kind: str, label: str, fn: JobFn) -> str:
        with self._lock:
            if self._status.state != "idle":
                raise JobBusyError("Es läuft bereits ein Auftrag.")
            job_id = uuid.uuid4().hex[:12]
            cancel = CancelToken()
            self._cancel = cancel
            self._status = JobStatus(job_id=job_id, kind=kind, label=label, state="running", started=utc_now_iso())  # type: ignore[arg-type]
            self._finished.clear()
        ctx = ScanContext(
            job_id=job_id,
            bus=self._bus,
            settings=self._settings_store.load(),
            platform=self._platform,
            cancel=cancel,
            log_sink=self._log_sink,
            _status_cb=self._on_progress,
        )
        self._bus.publish("job.started", {"job_id": job_id, "kind": kind, "label": label}, job_id=job_id)
        thread = threading.Thread(target=self._run, args=(ctx, kind, fn), name=f"job-{job_id}", daemon=True)
        self._thread = thread
        thread.start()
        return job_id

    def cancel(self) -> bool:
        with self._lock:
            if self._status.state != "running" or self._cancel is None:
                return False
            self._status.state = "cancelling"
            self._cancel.cancel()
            job_id = self._status.job_id
        self._bus.publish("job.progress", {"job_id": job_id, "phase": "Abbruch", "done": 0, "total": 0, "message": "Wird abgebrochen …"}, job_id=job_id)
        return True

    def wait(self, timeout: float | None = None) -> bool:
        """Wartet, bis kein Auftrag mehr läuft (für Tests und Programmende)."""
        return self._finished.wait(timeout)

    # --- intern --------------------------------------------------------------
    def _on_progress(self, phase: str | None, done: int, total: int, message: str) -> None:
        with self._lock:
            if self._status.state == "idle":
                return
            self._status.phase = phase
            self._status.done = done
            self._status.total = total
            self._status.message = message

    def _run(self, ctx: ScanContext, kind: str, fn: JobFn) -> None:
        result = "completed"
        summary: dict[str, Any] = {}
        error: str | None = None
        try:
            summary = fn(ctx) or {}
            if ctx.cancel.cancelled:
                result = "cancelled"
        except ScanCancelled:
            result = "cancelled"
            ctx.log("Auftrag abgebrochen.", "warning")
        except GuardBlocked as exc:
            result = "blocked"
            error = str(exc)
            ctx.log(f"Gesperrt: {exc}", "error")
        except Exception as exc:  # noqa: BLE001 – Auftrag darf den Server nie mitreißen
            result = "failed"
            error = f"{type(exc).__name__}: {exc}"
            log.exception("Auftrag %s fehlgeschlagen", ctx.job_id)
            ctx.log(f"Fehler: {error}", "error")
        finally:
            with self._lock:
                self._status = JobStatus()
                self._cancel = None
            self.last_result = {"job_id": ctx.job_id, "kind": kind, "result": result, "summary": summary, "error": error}
            self._bus.publish("job.finished", dict(self.last_result), job_id=ctx.job_id)
            self._finished.set()
