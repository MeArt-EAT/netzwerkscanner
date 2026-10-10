"""FastAPI-Server: REST, WebSocket, Sicherheitsregeln. Siehe BAUPLAN §12. (Agent api)

Der Server lauscht nur auf BIND_HOST (127.0.0.1). Aufrufe in andere Module laufen immer über den
Modulnamen (adapters.find_adapter, pipeline.run_scan, arp.scapy_status, oui.update_from_ieee), damit
Tests sie ersetzen können.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import logging
import math
import mimetypes
import socket
import sys
import threading
import time
import webbrowser
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Annotated, Any, Literal

import uvicorn
from fastapi import APIRouter, Body, Depends, FastAPI, HTTPException, Query, Request, WebSocket
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, StrictBool
from starlette.datastructures import Headers, MutableHeaders
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send
from starlette.websockets import WebSocketDisconnect

from netscan import __version__, config
from netscan.config import DEFAULT_PORT
from netscan.core.guard import HomeRefused
from netscan.core.jobs import JobBusyError
from netscan.core.models import CATEGORIES, Adapter, Device, GuardResult, ScanRequest, normalize_mac, utc_now_iso
from netscan.core.services import Services, build_services
from netscan.net import adapters, arp, classify, oui
from netscan.scan import pipeline
from netscan.web import export, monitor_api

log = logging.getLogger(__name__)

BIND_HOST = "127.0.0.1"  # nie ändern, keine Option dafür (Pflichtenheft, Grundsatz 1)

ALLOWED_HOSTS: tuple[str, ...] = ("127.0.0.1", "localhost")
_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Einstellungen, die per PUT /api/settings änderbar sind
_INT_SETTINGS = ("rate_pps", "ping_timeout_ms", "ping_workers", "port_timeout_ms", "port_workers")
_FLOAT_SETTINGS = ("names_timeout_s", "mdns_timeout_s", "ssdp_timeout_s")
_LIST_SETTINGS = ("blocked_ssids_extra", "home_gateway_macs", "port_scan_excluded_categories")
_BOOL_SETTINGS = ("ask_before_foreign_scan",)
EDITABLE_SETTINGS: frozenset[str] = frozenset(_INT_SETTINGS + _FLOAT_SETTINGS + _LIST_SETTINGS + _BOOL_SETTINGS)
SSID_MAX_LEN = 64
SSID_MAX_COUNT = 50

_EXPORT_FORMATS: dict[str, tuple[str, str]] = {
    # Kennung -> (Medientyp, Dateiendung)
    "json": ("application/json", "json"),
    "csv": ("text/csv; charset=utf-8", "csv"),
    "html": ("text/html; charset=utf-8", "html"),
}

_FALLBACK_PAGE = (
    '<!DOCTYPE html><html lang="de"><head><meta charset="utf-8"><title>Netzwerkscanner</title></head>'
    "<body><h1>Netzwerkscanner</h1>"
    "<p>Die Oberfläche (static/index.html) wurde nicht gefunden. Die Schnittstelle läuft trotzdem: "
    '<a href="/api/status">/api/status</a>.</p></body></html>'
)


# --- Anfrage-Modelle -------------------------------------------------------------------------


class ScanBody(BaseModel):
    """Body von POST /api/scan. Unbekannte Felder werden ignoriert – keines kann den Wächter übergehen."""

    adapter: str
    mode: Literal["full", "registered"] = "full"
    port_scan: StrictBool = True
    confirm_foreign: StrictBool = False
    remember_home: StrictBool = False


class DeepScanBody(BaseModel):
    confirm_foreign: StrictBool = False


class DevicePatch(BaseModel):
    """Nutzerfelder eines Geräts. Unbekannte Felder bleiben erhalten, damit das Inventar sie ablehnt (400)."""

    model_config = ConfigDict(extra="allow")

    custom_name: str | None = None
    category: str | None = None
    note: str | None = None
    known: StrictBool | None = None
    port_scan_excluded: StrictBool | None = None


# --- Sicherheit ------------------------------------------------------------------------------


def allowed_origins(port: int) -> frozenset[str]:
    return frozenset({f"http://127.0.0.1:{port}", f"http://localhost:{port}"})


def content_security_policy(port: int) -> str:
    return (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        f"connect-src 'self' ws://127.0.0.1:{port} ws://localhost:{port}; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    )


def _is_json_type(content_type: str | None) -> bool:
    if not content_type:
        return False
    return content_type.split(";", 1)[0].strip().lower() == "application/json"


def _has_body(headers: Headers) -> bool:
    """Body vorhanden: Content-Length > 0 (oder unlesbar) bzw. Transfer-Encoding gesetzt."""
    if headers.get("transfer-encoding"):
        return True
    raw = headers.get("content-length")
    if raw is None:
        return False
    try:
        return int(raw) > 0
    except ValueError:
        return True


class SecurityMiddleware:
    """Fremder Origin bei schreibenden Anfragen ⇒ 403, Body ohne JSON-Content-Type ⇒ 415, Schutz-Kopfzeilen."""

    def __init__(self, app: ASGIApp, port: int = DEFAULT_PORT) -> None:
        self.app = app
        self.origins = allowed_origins(port)
        self.csp = content_security_policy(port)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["X-Content-Type-Options"] = "nosniff"
                headers["X-Frame-Options"] = "DENY"
                headers["Referrer-Policy"] = "no-referrer"
                headers["Content-Security-Policy"] = self.csp
            await send(message)

        if scope["method"] in _UNSAFE_METHODS:
            headers = Headers(scope=scope)
            origin = headers.get("origin")
            if origin is not None and origin.lower() not in self.origins:
                log.warning("Anfrage mit fremdem Origin abgewiesen: %s %s", scope["method"], origin)
                response = JSONResponse({"detail": "Fremder Origin – Anfrage abgewiesen."}, status_code=403)
                await response(scope, receive, send_with_headers)
                return
            if _has_body(headers) and not _is_json_type(headers.get("content-type")):
                response = JSONResponse(
                    {"detail": "Content-Type muss application/json sein."}, status_code=415
                )
                await response(scope, receive, send_with_headers)
                return
        await self.app(scope, receive, send_with_headers)


# --- Hilfsfunktionen -------------------------------------------------------------------------


async def _services_dependency(request: Request) -> Services:
    svc = getattr(request.app.state, "services", None)
    if svc is None:
        raise HTTPException(503, "Der Scanner startet noch.")
    return svc


Svc = Annotated[Services, Depends(_services_dependency)]


def _error(status: int, detail: str, **extra: Any) -> JSONResponse:
    return JSONResponse({"detail": detail, **extra}, status_code=status)


def _dumps(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, default=str)


def _status_dict(svc: Services, adapter_name: str | None) -> dict[str, Any]:
    """Inhalt von GET /api/status (und der hello-Nachricht). Wirft nie."""
    try:
        available, reason = arp.scapy_status()
    except Exception:  # noqa: BLE001 – Statusabfrage darf nie scheitern
        log.debug("scapy_status fehlgeschlagen", exc_info=True)
        available, reason = False, "Prüfung nicht möglich."
    try:
        admin = bool(svc.platform.is_admin())
    except Exception:  # noqa: BLE001
        log.debug("is_admin fehlgeschlagen", exc_info=True)
        admin = False

    guard: dict[str, Any] | None = None
    try:
        name = adapter_name or svc.settings.load().last_adapter
        if name:
            adapter = adapters.find_adapter(svc.platform, name)
            if adapter is not None:
                guard = svc.guard.check(adapter).to_dict()
    except Exception:  # noqa: BLE001 – Fehler im Wächter ⇒ null, der Scan-Weg bleibt davon unberührt
        log.debug("Wächter-Abfrage für den Status fehlgeschlagen", exc_info=True)
        guard = None

    return {
        "version": __version__,
        "platform": getattr(svc.platform, "name", ""),
        "admin": admin,
        "scapy": {"available": bool(available), "reason": reason},
        "oui": {"entries": getattr(svc.oui, "entries", 0), "source": getattr(svc.oui, "source", "")},
        "job": svc.jobs.status().to_dict(),
        "guard": guard,
    }


def _check_guard(svc: Services, adapter: Adapter) -> GuardResult:
    """Fragt den Wächter und meldet das Ergebnis als Ereignis. Fehler im Wächter ⇒ kein Scan (500)."""
    try:
        guard = svc.guard.check(adapter)
    except Exception as exc:  # noqa: BLE001
        log.exception("Netz-Wächter ist fehlgeschlagen")
        raise HTTPException(500, "Der Netz-Wächter konnte nicht prüfen – es wurde nichts gestartet.") from exc
    svc.bus.publish("guard.result", {"guard": guard.to_dict()})
    return guard


def _guard_gate(svc: Services, adapter: Adapter, confirm_foreign: bool, remember_home: bool) -> JSONResponse | None:
    """Wächter-Schranke für Scan und Tiefenscan. None = durchgelassen, sonst die Abweisung (423 oder 428).

    Es gibt keinen Weg an `block` vorbei: weder ein Feld im Body noch eine Kopfzeile noch ein Parameter
    werden hier ausgewertet. Unbekannte Entscheidungen gelten als gesperrt.
    """
    guard = _check_guard(svc, adapter)
    if guard.decision == "allow":
        return None
    if guard.decision == "confirm":
        if not confirm_foreign:
            return _error(428, f"Bestätigung erforderlich: {guard.reason}", guard=guard.to_dict())
        if remember_home and guard.gateway_mac:
            try:
                svc.guard.remember_home(guard.gateway_mac, adapter=adapter)
            except HomeRefused as exc:  # z. B. WLAN-Name nicht lesbar: nicht merken, nichts starten
                return _error(422, str(exc), guard=guard.to_dict())
            except ValueError as exc:  # z. B. Router eines gesperrten Netzes: nie als Heimnetz merken, kein Scan
                return _error(423, f"Scan gesperrt: {exc}", guard=guard.to_dict())
        return None
    return _error(423, f"Scan gesperrt: {guard.reason}", guard=guard.to_dict())


def _remember_last_adapter(svc: Services, name: str) -> None:
    try:
        svc.settings.update(last_adapter=name)
    except Exception:  # noqa: BLE001 – der gestartete Scan hängt nicht davon ab
        log.warning("Letzter Adapter konnte nicht gespeichert werden", exc_info=True)


def _network_contains(adapter: Adapter, ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(adapter.network, strict=False)
    except ValueError:
        return False


def _adapter_for_device(svc: Services, device: Device) -> Adapter | None:
    """Adapter für einen Tiefenscan: settings.last_adapter, sonst der Adapter, in dessen Netz die IP liegt.

    Liegt die IP nicht im Netz von last_adapter, aber im Netz eines anderen Adapters, gilt dieser – der
    Wächter muss das Netz prüfen, über das der Verkehr wirklich läuft.
    """
    last = svc.settings.load().last_adapter
    candidate = adapters.find_adapter(svc.platform, last) if last else None
    if candidate is not None and _network_contains(candidate, device.ip):
        return candidate
    for adapter in adapters.list_adapters(svc.platform, include_virtual=True):
        if _network_contains(adapter, device.ip):
            return adapter
    return candidate


def _start_job(svc: Services, kind: str, label: str, fn: Any) -> str | JSONResponse:
    try:
        return svc.jobs.start(kind, label, fn)
    except JobBusyError as exc:
        return _error(409, str(exc))


def _export_meta(svc: Services, devices: list[Device]) -> dict[str, Any]:
    last_scan: dict[str, Any] | None = None
    latest = svc.inventory.latest_scan_id()
    if latest is not None:
        for row in svc.inventory.list_scans(limit=200):
            if row.get("id") == latest:
                last_scan = row
                break
    return {
        "program": "Netzwerkscanner",
        "version": __version__,
        "exported_at": utc_now_iso(),
        "device_count": len(devices),
        "last_scan": last_scan,
    }


def _validate_settings(body: dict[str, Any], blocked_macs: Any = ()) -> dict[str, Any]:
    """Prüft einen PUT-Body vollständig (alles oder nichts). Fehler ⇒ HTTPException 400.

    blocked_macs: gelernte Router-MACs gesperrter Netze – die dürfen nie Heimnetz werden (BAUPLAN §10).
    """
    known = set(config.Settings().to_dict())
    changes: dict[str, Any] = {}
    for key, value in body.items():
        if key not in known:
            raise HTTPException(400, f"Einstellung „{key}“ ist unbekannt.")
        if key not in EDITABLE_SETTINGS:
            raise HTTPException(400, f"Einstellung „{key}“ ist nur lesbar.")
        if key in _INT_SETTINGS:
            if not _is_number(value) or int(value) != value:
                raise HTTPException(400, f"{key} muss eine ganze Zahl sein.")
            changes[key] = int(value)
        elif key in _FLOAT_SETTINGS:
            if not _is_number(value):
                raise HTTPException(400, f"{key} muss eine Zahl sein.")
            changes[key] = float(value)
        elif key in _BOOL_SETTINGS:
            if not isinstance(value, bool):
                raise HTTPException(400, f"{key} muss true oder false sein.")
            changes[key] = value
        elif key == "blocked_ssids_extra":
            changes[key] = _clean_ssids(value)
        elif key == "home_gateway_macs":
            changes[key] = _clean_macs(value, blocked_macs)
        else:
            changes[key] = _clean_categories(value)
    return changes


def _is_number(value: Any) -> bool:
    """Endliche Zahl (kein bool, kein NaN/Infinity, das Pythons JSON-Leser durchlässt)."""
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _as_list(key: str, value: Any) -> list[Any]:
    if not isinstance(value, list):
        raise HTTPException(400, f"{key} muss eine Liste sein.")
    return value


def _clean_ssids(value: Any) -> list[str]:
    items = _as_list("blocked_ssids_extra", value)
    if len(items) > SSID_MAX_COUNT:
        raise HTTPException(400, f"Höchstens {SSID_MAX_COUNT} zusätzliche WLAN-Namen erlaubt.")
    out: list[str] = []
    for item in items:
        if not isinstance(item, str):
            raise HTTPException(400, "WLAN-Namen müssen Text sein.")
        name = item.strip()
        if not name:
            raise HTTPException(400, "WLAN-Namen dürfen nicht leer sein.")
        if len(name) > SSID_MAX_LEN:
            raise HTTPException(400, f"WLAN-Namen dürfen höchstens {SSID_MAX_LEN} Zeichen lang sein.")
        if name not in out:
            out.append(name)
    return out


def _clean_macs(value: Any, blocked_macs: Any = ()) -> list[str]:
    """Heimnetz-Router: nur Unicast-MACs, nie eine gesperrte (gleiche Regel wie remember_home)."""
    items = _as_list("home_gateway_macs", value)
    blocked: set[str] = set()
    for raw in blocked_macs or ():
        try:
            blocked.add(normalize_mac(raw))
        except (ValueError, TypeError, AttributeError):
            continue
    out: list[str] = []
    for item in items:
        try:
            mac = normalize_mac(item)
        except (ValueError, TypeError, AttributeError) as exc:
            raise HTTPException(400, f"Keine gültige MAC-Adresse: {item!r}") from exc
        if mac == "00:00:00:00:00:00" or int(mac[:2], 16) & 1:
            raise HTTPException(400, f"{mac} ist keine Router-Adresse (Null-, Broadcast- oder Multicast-MAC).")
        if mac in blocked:
            raise HTTPException(400, f"{mac} gehört zu einem gesperrten Netz und kann nie Heimnetz werden.")
        if mac not in out:
            out.append(mac)
    return out


def _clean_categories(value: Any) -> list[str]:
    items = _as_list("port_scan_excluded_categories", value)
    out: list[str] = []
    for item in items:
        if not isinstance(item, str) or item not in CATEGORIES:
            raise HTTPException(400, f"Unbekannte Geräteart: {item!r}")
        if item not in out:
            out.append(item)
    return out


# --- REST-Schnittstelle ----------------------------------------------------------------------

router = APIRouter(prefix="/api")


@router.get("/status")
def get_status(svc: Svc, adapter: str | None = None) -> dict[str, Any]:
    return _status_dict(svc, adapter)


@router.get("/adapters")
def get_adapters(svc: Svc, include_virtual: bool = False) -> list[dict[str, Any]]:
    return [a.to_dict() for a in adapters.list_adapters(svc.platform, include_virtual=include_virtual)]


@router.get("/guard")
def get_guard(svc: Svc, adapter: str) -> dict[str, Any]:
    found = adapters.find_adapter(svc.platform, adapter)
    if found is None:
        raise HTTPException(404, f"Adapter „{adapter}“ nicht gefunden.")
    try:
        return svc.guard.check(found).to_dict()
    except Exception as exc:  # noqa: BLE001
        log.exception("Netz-Wächter ist fehlgeschlagen")
        raise HTTPException(500, "Der Netz-Wächter konnte nicht prüfen.") from exc


@router.post("/scan", status_code=202)
def start_scan(body: ScanBody, svc: Svc) -> JSONResponse:
    adapter = adapters.find_adapter(svc.platform, body.adapter)
    if adapter is None:
        raise HTTPException(404, f"Adapter „{body.adapter}“ nicht gefunden.")

    denied = _guard_gate(svc, adapter, body.confirm_foreign, body.remember_home)
    if denied is not None:
        return denied

    warning: str | None = None
    if adapter.prefix < config.PREFIX_MIN:
        return _error(
            422,
            f"Netz zu groß (/{adapter.prefix}): Gescannt werden nur Netze mit höchstens "
            f"{2 ** (32 - config.PREFIX_MIN) - 2} Adressen (/{config.PREFIX_MIN} oder kleiner).",
        )
    if adapter.prefix < config.PREFIX_WARN:
        warning = f"Großes Netz (/{adapter.prefix}): Der Scan dauert deutlich länger als in einem /{config.PREFIX_WARN}."

    request = ScanRequest(
        adapter=adapter.name,
        mode=body.mode,
        port_scan=body.port_scan,
        confirm_foreign=body.confirm_foreign,
        remember_home=body.remember_home,
    )
    label = "Nur eingetragene Geräte prüfen" if body.mode == "registered" else f"Netz {adapter.network} absuchen"
    job = _start_job(svc, "scan", label, lambda ctx: pipeline.run_scan(ctx, request, svc))
    if isinstance(job, JSONResponse):
        return job
    _remember_last_adapter(svc, adapter.name)
    content: dict[str, Any] = {"job_id": job}
    if warning:
        content["warning"] = warning
    return JSONResponse(content, status_code=202)


@router.post("/scan/cancel")
def cancel_scan(svc: Svc) -> dict[str, bool]:
    return {"cancelled": svc.jobs.cancel()}


@router.get("/job")
def get_job(svc: Svc) -> dict[str, Any]:
    return svc.jobs.status().to_dict()


@router.get("/devices")
def get_devices(svc: Svc) -> list[dict[str, Any]]:
    return [d.to_dict() for d in svc.inventory.list_devices()]


@router.get("/devices/{mac}")
def get_device(mac: str, svc: Svc) -> dict[str, Any]:
    device = svc.inventory.get(mac)
    if device is None:
        raise HTTPException(404, "Gerät nicht gefunden.")
    return device.to_dict()


@router.patch("/devices/{mac}")
def patch_device(mac: str, body: DevicePatch, svc: Svc) -> dict[str, Any]:
    fields = body.model_dump(exclude_unset=True)
    for key in ("known", "port_scan_excluded"):
        if key in fields and fields[key] is None:
            raise HTTPException(400, f"{key} muss true oder false sein.")
    try:
        device = svc.inventory.update_user_fields(mac, **fields)
    except KeyError as exc:
        raise HTTPException(400, f"Unbekanntes Feld: {exc.args[0] if exc.args else exc}") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(404, "Gerät nicht gefunden.") from exc
    if "category" in fields and fields["category"] in ("auto", None) and device.category_source == "auto":
        # Zurück auf „Automatisch“: sofort neu einordnen, damit kein alter Nutzerwert („vom Nutzer festgelegt“)
        # stehen bleibt – sonst richtete sich z. B. die Ausnahme vom Port-Scan bis zum nächsten Scan danach.
        try:
            category, reason = classify.classify(device)
            svc.inventory.set_auto_category(device.mac, category, reason)
            device = svc.inventory.get(device.mac) or device
        except Exception:  # noqa: BLE001 – die Änderung selbst ist gespeichert
            log.warning("Neue Einordnung für %s fehlgeschlagen", device.mac, exc_info=True)
    svc.bus.publish("device.updated", {"device": device.to_dict()})
    svc.bus.publish("devices.changed", {})
    return device.to_dict()


@router.post("/devices/{mac}/deep-scan", status_code=202)
def deep_scan(mac: str, svc: Svc, body: DeepScanBody | None = None) -> JSONResponse:
    device = svc.inventory.get(mac)
    if device is None:
        raise HTTPException(404, "Gerät nicht gefunden.")
    adapter = _adapter_for_device(svc, device)
    if adapter is None:
        raise HTTPException(404, "Kein Netzwerkadapter für dieses Gerät gefunden.")
    if not _network_contains(adapter, device.ip):
        # last_adapter (BAUPLAN §12), aber die Geräte-IP liegt nicht in dessen Netz: Die Pipeline würde den
        # Auftrag ohnehin ablehnen – also nicht erst eine Freigabe für ein fremdes Netz erfragen.
        return _error(
            422,
            f"Das Gerät ({device.ip}) liegt in keinem Netz eines verbundenen Adapters "
            f"(„{adapter.name}“: {adapter.network}) – Tiefenscan nicht möglich.",
        )
    if not device.online:
        # Unter der alten Adresse kann inzwischen ein anderes Gerät antworten (DHCP).
        return _error(
            422,
            f"{device.display_name} war im letzten Scan nicht erreichbar – bitte zuerst neu scannen, dann Tiefenscan.",
        )

    denied = _guard_gate(svc, adapter, bool(body and body.confirm_foreign), False)
    if denied is not None:
        return denied

    device_mac = device.mac
    adapter_name = adapter.name
    job = _start_job(
        svc,
        "deep_scan",
        f"Tiefenscan {device.display_name}",
        lambda ctx: pipeline.run_deep_scan(ctx, device_mac, svc, adapter_name),
    )
    if isinstance(job, JSONResponse):
        return job
    return JSONResponse({"job_id": job}, status_code=202)


@router.get("/inventory")
def get_inventory(svc: Svc) -> list[dict[str, Any]]:
    return svc.inventory.inventory_view()


@router.get("/scans")
def get_scans(svc: Svc, limit: Annotated[int, Query(ge=1, le=200)] = 20) -> list[dict[str, Any]]:
    return svc.inventory.list_scans(limit=limit)


@router.get("/log")
def get_log(
    svc: Svc,
    scan_id: int | None = None,
    limit: Annotated[int, Query(ge=1, le=5000)] = 500,
) -> list[dict[str, Any]]:
    return svc.inventory.get_log(scan_id, limit)


@router.get("/export/{fmt}")
def get_export(fmt: str, svc: Svc) -> Response:
    spec = _EXPORT_FORMATS.get(fmt)
    if spec is None:
        raise HTTPException(404, "Unbekanntes Exportformat (json, csv oder html).")
    media_type, extension = spec
    devices = svc.inventory.list_devices()
    if fmt == "json":
        text = export.to_json(devices, _export_meta(svc, devices))
    elif fmt == "csv":
        text = export.to_csv(devices)
    else:
        text = export.to_html(devices, _export_meta(svc, devices))
    filename = f"netzwerkscanner-geraete-{datetime.now().strftime('%Y%m%d-%H%M')}.{extension}"
    return Response(
        content=text.encode("utf-8"),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/settings")
def get_settings(svc: Svc) -> dict[str, Any]:
    return svc.settings.load().to_dict()


@router.put("/settings")
def put_settings(svc: Svc, body: Annotated[dict[str, Any], Body()]) -> dict[str, Any]:
    changes = _validate_settings(body, svc.settings.load().blocked_gateway_macs)
    try:
        return svc.settings.update(**changes).to_dict()
    except KeyError as exc:
        raise HTTPException(400, f"Einstellung „{exc.args[0] if exc.args else exc}“ ist unbekannt.") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/oui/update", status_code=202)
def update_oui(svc: Svc) -> JSONResponse:
    def work(ctx: Any) -> dict[str, Any]:
        ctx.log("Herstellerliste wird von der IEEE geladen …")
        # Mit ctx abbrechbar – auch direkt vor dem Ersetzen der Datei; ein Abbruch ändert die Liste nie.
        count = oui.update_from_ieee(svc.data_dir, ctx=ctx)
        svc.oui = oui.OuiDb.load(svc.data_dir)
        info = {"entries": svc.oui.entries, "source": svc.oui.source}
        ctx.log(f"Herstellerliste aktualisiert: {info['entries']} Einträge.")
        ctx.emit("oui.updated", info)
        return {**info, "downloaded": count}

    job = _start_job(svc, "oui_update", "Herstellerliste aktualisieren", work)
    if isinstance(job, JSONResponse):
        return job
    return JSONResponse({"job_id": job}, status_code=202)


# --- WebSocket -------------------------------------------------------------------------------


async def _ws_send_events(websocket: WebSocket, sub: Any) -> None:
    while True:
        event = await sub.get()
        await websocket.send_text(_dumps(event.to_dict()))


async def _ws_drain(websocket: WebSocket) -> None:
    """Liest eingehende Nachrichten (werden ignoriert), damit das Trennen bemerkt wird."""
    while True:
        message = await websocket.receive()
        if message["type"] == "websocket.disconnect":
            return


async def websocket_endpoint(websocket: WebSocket) -> None:
    origins: frozenset[str] = websocket.app.state.allowed_origins
    origin = websocket.headers.get("origin")
    if origin is not None and origin.lower() not in origins:
        log.warning("WebSocket mit fremdem Origin abgewiesen: %s", origin)
        await websocket.close(code=1008)
        return
    svc: Services | None = getattr(websocket.app.state, "services", None)
    if svc is None:
        await websocket.close(code=1013)
        return

    await websocket.accept()
    sub = svc.bus.subscribe()  # vor dem hello abonnieren, damit kein Ereignis verloren geht
    try:
        status = await asyncio.to_thread(_status_dict, svc, None)
        await websocket.send_text(_dumps({"type": "hello", "data": {"status": status}}))
        sender = asyncio.create_task(_ws_send_events(websocket, sub))
        receiver = asyncio.create_task(_ws_drain(websocket))
        done, pending = await asyncio.wait({sender, receiver}, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        for task in pending:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        for task in done:
            if not task.cancelled() and task.exception() is not None:
                log.debug("WebSocket beendet: %r", task.exception())
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001 – eine kaputte Verbindung darf den Server nie stören
        log.debug("WebSocket-Fehler", exc_info=True)
    finally:
        sub.close()
        with contextlib.suppress(Exception):
            await websocket.close()


# --- App -------------------------------------------------------------------------------------


class _TolerantStaticFiles(StaticFiles):
    """Wie StaticFiles, aber ein fehlender Ordner ergibt 404 statt eines Serverfehlers."""

    async def check_config(self) -> None:
        return None


def _register_mime_types() -> None:
    """Windows liest Medientypen aus der Registry; ein falscher Eintrag für .js würde mit nosniff die Seite lahmlegen."""
    for mime, ext in (
        ("text/javascript", ".js"),
        ("text/javascript", ".mjs"),
        ("text/css", ".css"),
        ("image/svg+xml", ".svg"),
        ("application/json", ".json"),
        ("text/html", ".html"),
    ):
        mimetypes.add_type(mime, ext)


def create_app(services: Services | None = None, port: int = DEFAULT_PORT, *, start_monitor: bool = False) -> FastAPI:
    """Baut die App. Ohne services wird build_services() beim Start aufgerufen.

    start_monitor: Überwachung mit dem Server starten (nur server.run(), nie in Tests – BAUPLAN §18).
    """
    _register_mime_types()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        owned = False
        svc = getattr(app.state, "services", None)
        if svc is None:
            svc = await asyncio.to_thread(build_services)
            app.state.services = svc
            owned = True
        svc.bus.attach_loop(asyncio.get_running_loop())
        if start_monitor:
            svc.monitor.start()
        try:
            yield
        finally:
            if start_monitor:
                await asyncio.to_thread(svc.monitor.stop)
            svc.bus.detach_loop()
            if owned:
                app.state.services = None
                await asyncio.to_thread(svc.close)

    # Die automatische Dokumentation lädt Skripte von fremden Adressen – hier abgeschaltet.
    app = FastAPI(
        title="Netzwerkscanner",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.services = services
    app.state.allowed_origins = allowed_origins(port)

    app.include_router(router)
    app.include_router(monitor_api.router)
    app.add_api_websocket_route("/ws", websocket_endpoint)

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception) -> JSONResponse:
        log.error("Unbehandelter Fehler bei %s %s", request.method, request.url.path, exc_info=exc)
        return JSONResponse({"detail": "Interner Fehler – Details stehen im Logfile."}, status_code=500)

    static_dir = config.STATIC_DIR

    @app.get("/", include_in_schema=False)
    def index() -> Response:
        page = static_dir / "index.html"
        if page.is_file():
            return FileResponse(page, media_type="text/html; charset=utf-8")
        return HTMLResponse(_FALLBACK_PAGE)

    app.mount("/static", _TolerantStaticFiles(directory=static_dir, check_dir=False), name="static")

    # Reihenfolge: zuletzt hinzugefügt = ganz außen. Der Host wird zuerst geprüft (DNS-Rebinding).
    app.add_middleware(SecurityMiddleware, port=port)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(ALLOWED_HOSTS))
    return app


# --- Start -----------------------------------------------------------------------------------


def _port_is_free(port: int) -> bool:
    """Bind-Versuch auf BIND_HOST:port. Unter Windows ohne SO_REUSEADDR (sonst wäre jeder Port „frei“)."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if sys.platform != "win32":
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind((BIND_HOST, port))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def _open_browser_when_started(server: Any, url: str, stop: threading.Event) -> None:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if getattr(server, "started", False):
            try:
                webbrowser.open(url)
            except Exception:  # noqa: BLE001 – ohne Browser läuft der Server trotzdem
                log.warning("Browser konnte nicht geöffnet werden: %s", url, exc_info=True)
            return
        if stop.is_set():
            return
        time.sleep(0.1)


def run(port: int = DEFAULT_PORT, open_browser: bool = False, services: Services | None = None) -> None:
    """Startet uvicorn auf BIND_HOST:port. Belegter Port → verständliche Meldung und Exit-Code 2."""
    if not _port_is_free(port):
        log.error("Port %d ist belegt – läuft der Scanner schon?", port)
        sys.exit(2)

    app = create_app(services, port=port, start_monitor=True)
    # access_log=False: keine Zeile je Anfrage aus der Ereignisschleife auf die Konsole. Im klassischen
    # Konsolenfenster blockiert jede Ausgabe, solange dort Text markiert ist – dann stünde die Oberfläche still.
    server = uvicorn.Server(uvicorn.Config(app, host=BIND_HOST, port=port, log_level="info", access_log=False))

    stop = threading.Event()
    opener: threading.Thread | None = None
    if open_browser:
        opener = threading.Thread(
            target=_open_browser_when_started,
            args=(server, f"http://127.0.0.1:{port}/", stop),
            name="open-browser",
            daemon=True,
        )
        opener.start()
    try:
        server.run()
    finally:
        stop.set()
        if opener is not None:
            opener.join(timeout=2)
