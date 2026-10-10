"""Autostart über die Windows-Aufgabenplanung, ohne Adminrechte (BAUPLAN §31). (Agent platform)

Platzhalter der Leitung: Signaturen sind verbindlich, die Umsetzung folgt durch Agent platform.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any

TASK_NAME = "Netzwerkscanner"


class AutostartError(RuntimeError):
    """Autostart ließ sich nicht ändern (deutsche Meldung für die Oberfläche)."""


@dataclass
class AutostartStatus:
    supported: bool
    enabled: bool = False
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def autostart_status(*, run: Callable[..., Any] | None = None) -> AutostartStatus:
    raise NotImplementedError


def set_autostart(enabled: bool, *, run: Callable[..., Any] | None = None) -> AutostartStatus:
    raise NotImplementedError
