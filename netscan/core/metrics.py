"""Messwerte der Überwachung: speichern, Verfügbarkeit, Verläufe, Verdichtung (BAUPLAN §24). (Agent metrics)

Platzhalter der Leitung: Signaturen sind verbindlich, die Umsetzung folgt durch Agent metrics.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from netscan.core.db import Database
from netscan.core.models import Sample

RAW_KEEP_DAYS = 30
HOURLY_KEEP_DAYS = 730


class MetricsStore:
    def __init__(self, db: Database) -> None:
        self.db = db

    def record(self, samples: Iterable[Sample]) -> None:
        raise NotImplementedError

    def availability(self, target_id: int, check_id: int = 0, *, since: int, until: int) -> dict[str, Any]:
        raise NotImplementedError

    def availability_map(self, now: int) -> dict[tuple[int, int], dict[str, dict[str, Any]]]:
        raise NotImplementedError

    def series(self, target_id: int, check_id: int = 0, *, since: int, until: int, max_points: int = 400) -> dict[str, Any]:
        raise NotImplementedError

    def trend(self, target_id: int, check_id: int = 0, *, days: int = 30, now: int) -> list[dict[str, Any]]:
        raise NotImplementedError

    def compact(self, now: int, keep_days: int = RAW_KEEP_DAYS) -> int:
        raise NotImplementedError

    def delete_series(self, target_id: int, check_id: int | None = None) -> int:
        raise NotImplementedError

    def prune_orphans(self, valid: set[tuple[int, int]]) -> int:
        raise NotImplementedError

    def size_bytes(self) -> int:
        return self.db.size_bytes()

    def counts(self) -> dict[str, int]:
        raise NotImplementedError
