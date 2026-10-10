"""FastAPI-Server: REST, WebSocket, Sicherheitsregeln. Siehe BAUPLAN §12. (Agent api)"""

from __future__ import annotations

from typing import TYPE_CHECKING

from netscan.config import DEFAULT_PORT

if TYPE_CHECKING:
    from fastapi import FastAPI

    from netscan.core.services import Services

BIND_HOST = "127.0.0.1"  # nie ändern, keine Option dafür (Pflichtenheft, Grundsatz 1)


def create_app(services: Services | None = None, port: int = DEFAULT_PORT) -> FastAPI:
    """Baut die App. Ohne services wird build_services() beim Start aufgerufen."""
    raise NotImplementedError


def run(port: int = DEFAULT_PORT, open_browser: bool = False, services: Services | None = None) -> None:
    """Startet uvicorn auf BIND_HOST:port. Belegter Port → verständliche Meldung und Exit-Code 2."""
    raise NotImplementedError
