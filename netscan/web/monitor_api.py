"""Web-API der Überwachung: Ziele, Dienstprüfungen, Messwerte, Alerts, Autostart (BAUPLAN §27). (Agent api)

Platzhalter der Leitung: Der Router ist in create_app eingebunden; die Endpunkte folgen durch Agent api.
"""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/api")
