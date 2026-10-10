"""Ereignis-Warteschlange zwischen Scan-Threads und Webserver.

Scan-Threads rufen nur publish(). Der Webserver hängt seine asyncio-Schleife an
(attach_loop) und holt Ereignisse über subscribe(). Kein Scan-Thread berührt die
Oberfläche – das war die Absturzursache von 2025.
"""

from __future__ import annotations

import asyncio
import itertools
import logging
import threading
from collections import deque
from dataclasses import asdict, dataclass, field
from typing import Any

from netscan.core.models import utc_now_iso

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Event:
    seq: int
    type: str
    ts: str
    job_id: str | None = None
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class Subscription:
    """Ein Abonnent (z. B. eine WebSocket-Verbindung)."""

    def __init__(self, bus: EventBus, maxsize: int) -> None:
        self._bus = bus
        self.queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=maxsize)
        self.dropped = 0

    def _offer(self, event: Event) -> None:
        # läuft in der asyncio-Schleife
        if self.queue.full():
            try:
                self.queue.get_nowait()  # ältestes verwerfen, Oberfläche lädt bei Bedarf neu
                self.dropped += 1
            except asyncio.QueueEmpty:
                pass
        self.queue.put_nowait(event)

    async def get(self) -> Event:
        return await self.queue.get()

    def close(self) -> None:
        self._bus._unsubscribe(self)


class EventBus:
    def __init__(self, history: int = 500, queue_size: int = 1000) -> None:
        self._lock = threading.Lock()
        self._seq = itertools.count(1)
        self._history: deque[Event] = deque(maxlen=history)
        self._subs: list[Subscription] = []
        self._loop: asyncio.AbstractEventLoop | None = None
        self._queue_size = queue_size

    def attach_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Vom Webserver beim Start aufrufen."""
        self._loop = loop

    def detach_loop(self) -> None:
        self._loop = None

    def publish(self, type: str, data: dict[str, Any] | None = None, job_id: str | None = None) -> Event:
        """Thread-sicher. Darf aus jedem Thread aufgerufen werden."""
        with self._lock:
            event = Event(seq=next(self._seq), type=type, ts=utc_now_iso(), job_id=job_id, data=dict(data or {}))
            self._history.append(event)
            subs = list(self._subs)
            loop = self._loop
        if loop is not None and subs and not loop.is_closed():
            for sub in subs:
                try:
                    loop.call_soon_threadsafe(sub._offer, event)
                except RuntimeError:  # Schleife wurde gerade beendet
                    log.debug("Ereignis nach Ende der Schleife verworfen: %s", type)
        return event

    def subscribe(self) -> Subscription:
        """Im asyncio-Kontext aufrufen."""
        sub = Subscription(self, self._queue_size)
        with self._lock:
            self._subs.append(sub)
        return sub

    def _unsubscribe(self, sub: Subscription) -> None:
        with self._lock:
            if sub in self._subs:
                self._subs.remove(sub)

    def history(self, limit: int | None = None, type_prefix: str | None = None) -> list[Event]:
        with self._lock:
            items = list(self._history)
        if type_prefix:
            items = [e for e in items if e.type.startswith(type_prefix)]
        return items[-limit:] if limit else items
