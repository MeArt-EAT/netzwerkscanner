"""Web-API der Überwachung: Ziele, Dienstprüfungen, Messwerte, Alerts, Autostart (BAUPLAN §27). (Agent api)

Zielverwaltung läuft nur über svc.monitor (Anlegen, Ändern, Löschen); gelesen wird über svc.targets,
svc.inventory, svc.metrics und svc.alerts. Aufrufe in andere Module gehen über den Modulnamen
(autostart.autostart_status, autostart.set_autostart), damit Tests sie ersetzen können.

Fehler kommen wie in Stufe 1 als {detail} mit deutschem Text:
LookupError -> 404, TargetExists/CheckExists -> 409, ValueError/KeyError -> 400. Auch Pydantic-Fehler
(falscher Typ, fehlendes oder unbekanntes Feld, kaputtes JSON) werden in diesem Router zu 400 mit Text
statt 422 mit Fehlerliste. Die Sicherheitsregeln (Origin 403, Content-Type 415) gelten über die
Middleware in server.py für alle schreibenden Endpunkte.
"""

from __future__ import annotations

import logging
import math
import time
from collections.abc import Callable
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictFloat, StrictInt

from netscan import config
from netscan.core.models import CATEGORY_LABELS, Device, MonitorTarget, normalize_mac
from netscan.core.services import Services
from netscan.core.targets import CheckExists, TargetExists
from netscan.platform import autostart

log = logging.getLogger(__name__)

RANGE_SECONDS: dict[str, int] = {"24h": 86400, "7d": 604800, "30d": 2592000, "1y": 31536000}
SERIES_MAX_POINTS = 400
# Ein Eimer des Verlaufs muss länger sein als das Prüfintervall: Die Abstände der Messungen liegen knapp darüber
# (Weckverzug, auf ganze Sekunden abgeschnitten). Bei Eimer = Intervall rutscht sonst ab und zu eine Messung in den
# übernächsten Eimer, und einer bleibt leer (falsche Lücke).
SERIES_INTERVAL_SLACK = 1.1
ALERT_STATES: tuple[str, ...] = ("active", "unacked", "all")
ALERT_LIMIT = (1, 1000)
TREND_DAYS = (1, 365)
STATS_DAYS = (1, 365)
_AVAILABILITY_KEYS = ("24h", "7d")
_STATUS_KEYS = ("online", "degraded", "offline", "paused", "unknown")
_MAX_ID_DIGITS = 18  # passt sicher in einen 64-Bit-Integer der Datenbank


def _now() -> float:
    """Aktuelle Zeit in Unix-Sekunden (Tests ersetzen das)."""
    return time.time()


# --- Router und Fehlerabbildung --------------------------------------------------------------


def _loc_name(loc: list[Any]) -> str:
    if loc and loc[0] in ("body", "query", "path"):
        loc = loc[1:]
    name = ""
    for part in loc:
        if isinstance(part, int):
            name += f"[{part}]"
        else:
            name += ("." if name else "") + str(part)
    return name


def _describe_errors(errors: list[dict[str, Any]]) -> str:
    """Deutscher Text zum ersten Eingabefehler (Pydantic liefert Englisch und Listen)."""
    if not errors:
        return "Ungültige Eingabe."
    err = errors[0]
    kind = str(err.get("type", ""))
    if kind == "json_invalid":
        return "Der Body ist kein gültiges JSON."
    name = _loc_name(list(err.get("loc", ())))
    if kind in ("model_attributes_type", "dict_type", "model_type"):
        return f"„{name}“ muss ein Objekt sein." if name else "Der Body muss ein JSON-Objekt sein."
    if kind == "missing":
        return f"„{name}“ fehlt." if name else "Der Body fehlt."
    if not name:
        return "Ungültige Eingabe."
    if kind in ("bool_type", "bool_parsing"):
        return f"„{name}“ muss true oder false sein."
    if kind in ("int_type", "int_parsing", "int_from_float"):
        return f"„{name}“ muss eine ganze Zahl sein."
    if kind in ("float_type", "float_parsing"):
        return f"„{name}“ muss eine Zahl sein."
    if kind == "string_type":
        return f"„{name}“ muss Text sein."
    if kind == "list_type":
        return f"„{name}“ muss eine Liste sein."
    if kind == "too_long":
        limit = (err.get("ctx") or {}).get("max_length")
        return f"„{name}“ hat zu viele Einträge" + (f" (höchstens {limit})." if limit is not None else ".")
    return f"„{name}“ ist ungültig."


class _ApiRoute(APIRoute):
    """Pydantic-Eingabefehler als 400 mit deutschem Text (statt 422 mit Fehlerliste)."""

    def get_route_handler(self) -> Callable[[Request], Any]:
        original = super().get_route_handler()

        async def handler(request: Request) -> Response:
            try:
                return await original(request)
            except RequestValidationError as exc:
                return JSONResponse({"detail": _describe_errors(exc.errors())}, status_code=400)

        return handler


router = APIRouter(prefix="/api", route_class=_ApiRoute)


async def _services_dependency(request: Request) -> Services:
    svc = getattr(request.app.state, "services", None)
    if svc is None:
        raise HTTPException(503, "Der Scanner startet noch.")
    return svc


Svc = Annotated[Services, Depends(_services_dependency)]


def _guarded(fn: Callable[..., Any], *args: Any, missing: str, **kwargs: Any) -> Any:
    """Ruft die Zielverwaltung auf und bildet deren Ausnahmen auf Statuscodes ab.

    TargetExists/CheckExists sind ValueError, KeyError ist LookupError – die Reihenfolge der except-Zweige
    ist deshalb Teil des Vertrags: erst 409, dann 400, zuletzt 404.
    """
    try:
        return fn(*args, **kwargs)
    except (TargetExists, CheckExists) as exc:
        raise HTTPException(409, str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(400, f"Unbekanntes Feld: {exc.args[0] if exc.args else exc}") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(404, missing) from exc


# --- Eingabemodelle --------------------------------------------------------------------------


class _Body(BaseModel):
    """Unbekannte Felder bleiben erhalten (extra=allow), damit reject_unknown sie mit 400 ablehnt."""

    model_config = ConfigDict(extra="allow")

    def reject_unknown(self) -> None:
        extra = self.model_extra or {}
        if extra:
            names = ", ".join(str(k)[:40] for k in sorted(extra, key=str)[:5])
            raise HTTPException(400, f"Unbekannte Felder: {names}")


class CheckSpec(_Body):
    kind: str
    port: StrictInt
    path: str | None = "/"


class TargetCreate(_Body):
    mac: str
    method: str = "auto"
    tcp_port: StrictInt | None = None
    offline_after_min: StrictInt | None = None
    rtt_threshold_ms: StrictFloat | None = None
    checks: list[CheckSpec] | None = Field(default=None, max_length=config.MAX_CHECKS_PER_TARGET)


class TargetPatch(_Body):
    enabled: StrictBool | None = None
    method: str | None = None
    tcp_port: StrictInt | None = None
    offline_after_min: StrictInt | None = None
    rtt_threshold_ms: StrictFloat | None = None


class CheckPatch(_Body):
    enabled: StrictBool


class AutostartBody(_Body):
    enabled: StrictBool


# --- Hilfen ----------------------------------------------------------------------------------


def _path_mac(mac: str) -> str:
    """MAC aus dem Pfad normalisieren; ungültig ⇒ 404 (wie unbekannt)."""
    try:
        return normalize_mac(mac)
    except ValueError:
        raise HTTPException(404, "Gerät nicht gefunden.") from None


def _path_id(raw: str, what: str) -> int:
    """Numerische Kennung aus dem Pfad; alles andere ⇒ 404."""
    if not (raw.isascii() and raw.isdecimal()) or len(raw) > _MAX_ID_DIGITS:
        raise HTTPException(404, f"{what} nicht gefunden.")
    return int(raw)


def _int_in_range(name: str, value: int, bounds: tuple[int, int]) -> int:
    lo, hi = bounds
    if not lo <= value <= hi:
        raise HTTPException(400, f"{name} muss zwischen {lo} und {hi} liegen.")
    return value


def _target_or_404(svc: Services, mac: str) -> MonitorTarget:
    target = svc.targets.get(_path_mac(mac))
    if target is None:
        raise HTTPException(404, "Dieses Gerät wird nicht überwacht.")
    return target


def _series_target(svc: Services, mac: str, check_id: int) -> MonitorTarget:
    """Ziel für Messreihen; check_id 0 = Erreichbarkeit, sonst muss die Prüfung zum Ziel gehören."""
    target = _target_or_404(svc, mac)
    if check_id != 0 and not any(c.id == check_id for c in target.checks):
        raise HTTPException(404, "Diese Prüfung gehört nicht zu diesem Gerät.")
    return target


def _monitor_interval_s(svc: Services) -> int:
    """Prüfintervall aus den Einstellungen, in den Grenzen aus config. Lesefehler oder Unsinn ⇒ Standard."""
    default = config.Settings().monitor_interval_s
    try:
        raw = svc.settings.load().monitor_interval_s
    except Exception:  # noqa: BLE001 – der Verlauf lebt auch ohne Einstellungen
        log.warning("Prüfintervall nicht lesbar, nehme %d s", default, exc_info=True)
        return default
    if isinstance(raw, bool) or not isinstance(raw, (int, float)) or not math.isfinite(raw):
        return default
    lo, hi = config.SETTING_LIMITS["monitor_interval_s"]
    return math.ceil(min(max(raw, lo), hi))


def _series_max_points(seconds: int, interval_s: int) -> int:
    """Höchstzahl der Eimer, sodass jeder Eimer länger ist als das Prüfintervall (höchstens SERIES_MAX_POINTS).

    metrics.series wählt die kleinste runde Eimergröße ≥ ceil(seconds / max_points); mit
    max_points ≤ seconds / min_bucket ist das mindestens min_bucket. Sonst bleibt bei einem Intervall über der
    Eimergröße jeder zweite Eimer leer, und die Oberfläche meldet Lücken, obwohl lückenlos gemessen wurde.
    """
    min_bucket = math.ceil(interval_s * SERIES_INTERVAL_SLACK)
    return max(1, min(SERIES_MAX_POINTS, seconds // min_bucket))


def _empty_availability() -> dict[str, Any]:
    return {"up_pct": None, "samples": 0, "up": 0}


def _load_availability(svc: Services, now: int) -> dict[Any, Any]:
    """Verfügbarkeit aller Reihen, einmal je Anfrage. Ein Lesefehler lässt die Werte leer, nicht die Seite sterben."""
    try:
        result = svc.metrics.availability_map(now)
    except Exception:  # noqa: BLE001
        log.warning("Verfügbarkeit nicht lesbar", exc_info=True)
        return {}
    return result if isinstance(result, dict) else {}


def _availability(amap: dict[Any, Any], target_id: int, check_id: int) -> dict[str, Any]:
    entry = amap.get((target_id, check_id))
    entry = entry if isinstance(entry, dict) else {}
    out: dict[str, Any] = {}
    for key in _AVAILABILITY_KEYS:
        value = entry.get(key)
        out[key] = dict(value) if isinstance(value, dict) else _empty_availability()
    return out


def _device_view(mac: str, device: Device | None) -> dict[str, Any]:
    if device is None:  # kann es durch ON DELETE CASCADE nicht geben; die Form bleibt trotzdem stabil
        return {
            "mac": mac,
            "ip": None,
            "display_name": mac,
            "category": "unknown",
            "category_label": CATEGORY_LABELS["unknown"],
            "is_self": False,
            "online": False,
            "mac_random": False,
        }
    return {
        "mac": device.mac,
        "ip": device.ip,
        "display_name": device.display_name,
        "category": device.category,
        "category_label": CATEGORY_LABELS.get(device.category, device.category),
        "is_self": device.is_self,
        "online": device.online,
        "mac_random": device.mac_random,
    }


def _target_view(target: MonitorTarget, device: Device | None, amap: dict[Any, Any]) -> dict[str, Any]:
    data = target.to_dict()
    data["device"] = _device_view(target.mac, device)
    data["availability"] = _availability(amap, target.id, 0)
    data["checks"] = [{**c, "availability": _availability(amap, target.id, c["id"])} for c in data["checks"]]
    return data


def _single_view(svc: Services, target: MonitorTarget) -> dict[str, Any]:
    return _target_view(target, svc.inventory.get(target.mac), _load_availability(svc, int(_now())))


# --- Ziele -----------------------------------------------------------------------------------


@router.get("/monitor")
def get_monitor(svc: Svc) -> dict[str, Any]:
    targets = svc.targets.list()
    devices = {d.mac: d for d in svc.inventory.list_devices()} if targets else {}
    amap = _load_availability(svc, int(_now())) if targets else {}
    return {
        "status": svc.monitor.status().to_dict(),
        "targets": [_target_view(t, devices.get(t.mac), amap) for t in targets],
    }


@router.post("/monitor/targets", status_code=201)
def create_target(body: TargetCreate, svc: Svc) -> dict[str, Any]:
    body.reject_unknown()
    for spec in body.checks or []:
        spec.reject_unknown()
    try:
        mac = normalize_mac(body.mac)
    except ValueError:
        raise HTTPException(400, "Die MAC-Adresse ist ungültig.") from None
    checks = (
        [{"kind": s.kind, "port": s.port, "path": s.path} for s in body.checks] if body.checks is not None else None
    )
    target = _guarded(
        svc.monitor.add_target,
        mac,
        missing="Gerät nicht gefunden.",
        method=body.method,
        tcp_port=body.tcp_port,
        offline_after_min=body.offline_after_min,
        rtt_threshold_ms=body.rtt_threshold_ms,
        checks=checks,
    )
    return _single_view(svc, target)


@router.get("/monitor/targets/{mac}")
def get_target(mac: str, svc: Svc) -> dict[str, Any]:
    return _single_view(svc, _target_or_404(svc, mac))


@router.patch("/monitor/targets/{mac}")
def patch_target(mac: str, body: TargetPatch, svc: Svc) -> dict[str, Any]:
    mac = _path_mac(mac)
    body.reject_unknown()
    fields = body.model_dump(exclude_unset=True)
    for key in ("enabled", "method"):
        if key in fields and fields[key] is None:
            raise HTTPException(400, f"{key} darf nicht null sein.")
    target = _guarded(svc.monitor.update_target, mac, missing="Dieses Gerät wird nicht überwacht.", **fields)
    return _single_view(svc, target)


@router.delete("/monitor/targets/{mac}", status_code=204)
def delete_target(mac: str, svc: Svc) -> Response:
    _guarded(svc.monitor.remove_target, _path_mac(mac), missing="Dieses Gerät wird nicht überwacht.")
    return Response(status_code=204)


@router.get("/monitor/targets/{mac}/suggestions")
def get_suggestions(mac: str, svc: Svc) -> list[dict[str, Any]]:
    return _guarded(svc.monitor.suggestions, _path_mac(mac), missing="Gerät nicht gefunden.")


# --- Dienstprüfungen -------------------------------------------------------------------------


@router.post("/monitor/targets/{mac}/checks", status_code=201)
def create_check(mac: str, body: CheckSpec, svc: Svc) -> dict[str, Any]:
    mac = _path_mac(mac)
    body.reject_unknown()
    path = "/" if body.path is None else body.path
    check = _guarded(
        svc.monitor.add_check, mac, body.kind, body.port, path, missing="Dieses Gerät wird nicht überwacht."
    )
    return check.to_dict()


@router.patch("/monitor/checks/{check_id}")
def patch_check(check_id: str, body: CheckPatch, svc: Svc) -> dict[str, Any]:
    cid = _path_id(check_id, "Prüfung")
    body.reject_unknown()
    check = _guarded(svc.monitor.update_check, cid, body.enabled, missing="Prüfung nicht gefunden.")
    return check.to_dict()


@router.delete("/monitor/checks/{check_id}", status_code=204)
def delete_check(check_id: str, svc: Svc) -> Response:
    _guarded(svc.monitor.remove_check, _path_id(check_id, "Prüfung"), missing="Prüfung nicht gefunden.")
    return Response(status_code=204)


@router.post("/monitor/run", status_code=202)
def run_monitor(svc: Svc) -> dict[str, bool]:
    """Nächsten Durchlauf sofort starten. Der Wächter gilt dabei wie immer (er sitzt im Durchlauf)."""
    if not svc.monitor.running:
        raise HTTPException(409, "Die Überwachung läuft nicht.")
    svc.monitor.trigger()
    return {"started": True}


# --- Messwerte -------------------------------------------------------------------------------


@router.get("/metrics/series")
def get_series(
    svc: Svc,
    mac: str,
    check_id: int = 0,
    range_: Annotated[str, Query(alias="range")] = "24h",
) -> dict[str, Any]:
    """Antwortzeit-Verlauf; ein Eimer ist immer länger als das Prüfintervall (keine falschen Lücken)."""
    seconds = RANGE_SECONDS.get(range_)
    if seconds is None:
        raise HTTPException(400, f"Unbekannter Zeitraum „{range_[:20]}“ (erlaubt: {', '.join(RANGE_SECONDS)}).")
    target = _series_target(svc, mac, check_id)
    until = int(_now())
    since = until - seconds
    max_points = _series_max_points(seconds, _monitor_interval_s(svc))
    result = svc.metrics.series(target.id, check_id, since=since, until=until, max_points=max_points)
    return {
        "range": range_,
        "since": since,
        "until": until,
        "bucket_s": result.get("bucket_s"),
        "points": list(result.get("points") or []),
    }


@router.get("/metrics/trend")
def get_trend(svc: Svc, mac: str, check_id: int = 0, days: int = 30) -> list[dict[str, Any]]:
    _int_in_range("days", days, TREND_DAYS)
    target = _series_target(svc, mac, check_id)
    return list(svc.metrics.trend(target.id, check_id, days=days, now=int(_now())))


@router.get("/metrics/overview")
def get_overview(svc: Svc) -> dict[str, Any]:
    counts = dict.fromkeys(_STATUS_KEYS, 0)
    for target in svc.targets.list():
        counts[target.status if target.status in counts else "unknown"] += 1
    try:
        size: int | None = int(svc.db.size_bytes())
    except Exception:  # noqa: BLE001 – die Übersicht lebt auch ohne Dateigröße
        log.warning("Dateigröße der Datenbank nicht lesbar", exc_info=True)
        size = None
    try:
        raw = svc.metrics.counts()
        samples = {"raw": int(raw["raw"]), "hourly": int(raw["hourly"])}
    except Exception:  # noqa: BLE001
        log.warning("Anzahl der Messwerte nicht lesbar", exc_info=True)
        samples = {"raw": 0, "hourly": 0}
    return {
        "counts": counts,
        "db_size_bytes": size,
        "db_warn": size is not None and size >= config.DB_WARN_BYTES,
        "samples": samples,
    }


# --- Alerts ----------------------------------------------------------------------------------


@router.get("/alerts")
def list_alerts(svc: Svc, state: str = "active", limit: int = 200, mac: str | None = None) -> list[dict[str, Any]]:
    if state not in ALERT_STATES:
        raise HTTPException(400, f"Unbekannter Zustand „{state[:20]}“ (erlaubt: {', '.join(ALERT_STATES)}).")
    _int_in_range("limit", limit, ALERT_LIMIT)
    wanted: str | None = None
    if mac is not None and mac.strip():
        try:
            wanted = normalize_mac(mac)
        except ValueError:
            raise HTTPException(400, "Die MAC-Adresse ist ungültig.") from None
    return [a.to_dict() for a in svc.alerts.list(state=state, limit=limit, mac=wanted)]


# Feste Pfade vor dem Pfad mit Kennung: ack-all und stats kollidieren nicht mit /alerts/{id}/ack.
@router.post("/alerts/ack-all")
def acknowledge_all(svc: Svc) -> dict[str, int]:
    return {"acknowledged": int(svc.alerts.acknowledge_all())}


@router.get("/alerts/stats")
def alert_stats(svc: Svc, days: int = 30) -> dict[str, Any]:
    _int_in_range("days", days, STATS_DAYS)
    return {
        "days": list(svc.alerts.frequency(days=days, now=_now())),
        "counts": svc.alerts.counts(),
    }


@router.post("/alerts/{alert_id}/ack")
def acknowledge_alert(alert_id: str, svc: Svc) -> dict[str, Any]:
    aid = _path_id(alert_id, "Alert")
    alert = _guarded(svc.alerts.acknowledge, aid, missing="Alert nicht gefunden.")
    return alert.to_dict()


# --- Autostart -------------------------------------------------------------------------------

_NOT_SUPPORTED = "Autostart wird auf diesem System nicht unterstützt."


def _autostart(fn: Callable[..., Any], *args: Any, what: str) -> Any:
    """Autostart-Aufruf mit Abbildung der Fehler: NotImplementedError ⇒ 501, AutostartError ⇒ 500 mit Meldung."""
    try:
        return fn(*args)
    except NotImplementedError as exc:
        raise HTTPException(501, _NOT_SUPPORTED) from exc
    except autostart.AutostartError as exc:
        raise HTTPException(500, str(exc) or f"Autostart konnte nicht {what} werden.") from exc
    except Exception as exc:  # noqa: BLE001 – z. B. schtasks fehlt: verständliche Meldung statt Rohtext
        log.exception("Autostart: Aufruf fehlgeschlagen")
        raise HTTPException(500, f"Autostart konnte nicht {what} werden – Details stehen im Logfile.") from exc


@router.get("/autostart")
def get_autostart() -> dict[str, Any]:
    return _autostart(autostart.autostart_status, what="gelesen").to_dict()


@router.put("/autostart")
def put_autostart(body: AutostartBody) -> dict[str, Any]:
    body.reject_unknown()
    current = _autostart(autostart.autostart_status, what="gelesen")
    if not current.supported:
        raise HTTPException(501, current.detail or _NOT_SUPPORTED)
    result = _autostart(autostart.set_autostart, body.enabled, what="geändert")
    if not result.supported:
        raise HTTPException(501, result.detail or _NOT_SUPPORTED)
    return result.to_dict()
