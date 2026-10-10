"""Vertrag Oberfläche <-> Kern/Server: Feldnamen, Kategorien, Routen. Nur Lesen, kein Netz, kein Start des Servers.

Der Server (netscan.web.server) wird nur importiert und seine Routentabelle gelesen. Lässt er sich nicht
importieren (z. B. weil ein anderer Baustein noch fehlt), werden die Server-Prüfungen übersprungen.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from netscan.core import models

ROOT = Path(__file__).resolve().parent.parent
APP_JS = ROOT / "netscan" / "web" / "static" / "app.js"

NODE_SCRIPT = r"""
const ui = require(process.argv[2]);
const dev = { custom_name: null, category: "pc", category_source: "auto", note: "", known: false, port_scan_excluded: false };
const out = {
  categoryList: ui.CATEGORY_LIST,
  riskLabels: ui.RISK_LABELS,
  riskOrder: ui.RISK_ORDER,
  settingsEditable: ui.SETTINGS_EDITABLE,
  scanRequestKeys: Object.keys(ui.buildScanRequest("WLAN", "full", true)).sort(),
  patchKeys: Object.keys(ui.buildDevicePatch(dev, { custom_name: "x", category: "iot", note: "y", known: true, port_scan_excluded: true })).sort(),
};
process.stdout.write(JSON.stringify(out));
"""


@pytest.fixture(scope="module")
def ui(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node nicht im PATH")
    script = tmp_path_factory.mktemp("frontend_contract") / "check.js"
    script.write_text(NODE_SCRIPT, encoding="utf-8")
    result = subprocess.run([node, str(script), str(APP_JS)], capture_output=True, text=True, encoding="utf-8", timeout=60, env=dict(os.environ, NODE_OPTIONS=""))
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@pytest.fixture(scope="module")
def server():  # type: ignore[no-untyped-def]
    try:
        from netscan.web import server as server_module
    except Exception as exc:  # noqa: BLE001 – fremder Baustein unfertig: nicht unser Fehler
        pytest.skip(f"netscan.web.server nicht importierbar: {exc!r}")
    return server_module


# --- Kern: Namen und Beschriftungen müssen mit models.py übereinstimmen -------------------------------


def test_categories_match_models(ui: dict[str, Any]) -> None:
    assert [c[0] for c in ui["categoryList"]] == list(models.CATEGORIES)
    assert {c[0]: c[1] for c in ui["categoryList"]} == models.CATEGORY_LABELS


def test_risk_labels_match_models(ui: dict[str, Any]) -> None:
    assert ui["riskLabels"] == models.RISK_LABELS
    assert ui["riskOrder"] == models.RISK_ORDER


def test_scan_request_fields_match_model(ui: dict[str, Any]) -> None:
    assert ui["scanRequestKeys"] == sorted(models.ScanRequest("x").to_dict())


def test_fields_used_by_ui_exist_in_device_dict() -> None:
    """Jedes Feld aus models.Device.to_dict, das die Oberfläche liest, gibt es wirklich."""
    keys = set(models.Device(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.1").to_dict())
    js = APP_JS.read_text(encoding="utf-8")
    used = set(re.findall(r"\b(?:d|device|dev|plan\.hub|d\.names|d\.ssdp)\.([a-z_]+)\b", js)) & {
        "mac", "ip", "vendor", "mac_random", "hostname", "names", "ssdp", "ports", "category", "category_label",
        "category_source", "category_reason", "custom_name", "note", "known", "is_gateway", "is_self",
        "port_scan_excluded", "online", "rtt_ms", "ttl", "discovered_by", "first_seen", "last_seen", "is_new",
        "display_name", "max_risk",
    }
    assert used, "keine Gerätefelder gefunden"
    assert used <= keys, sorted(used - keys)
    for field in ("mac", "ip", "display_name", "category", "online", "is_new", "known", "is_gateway", "is_self", "max_risk", "ports", "last_seen"):
        assert field in used, f"{field} wird in der Oberfläche nicht gelesen"


def test_guard_and_job_fields_used_by_ui_exist() -> None:
    guard = set(models.GuardResult("allow", "ok_home", "x").to_dict())
    job = set(models.JobStatus().to_dict())
    js = APP_JS.read_text(encoding="utf-8")
    for field in re.findall(r"\bguard\.([a-z_]+)\b", js):
        if field in {"decision", "code", "reason", "ssid", "ssid_readable", "gateway_ip", "gateway_mac"}:
            assert field in guard
    for field in re.findall(r"\bjob\.([a-z_]+)\b", js):
        if field in {"job_id", "kind", "label", "state", "phase", "done", "total", "message", "started"}:
            assert field in job


# --- Server: Routen und Einstellungen -------------------------------------------------------------------


# Pfad -> Methoden, mit denen die Oberfläche ihn aufruft
UI_CALLS = {
    "/api/status": {"get"},
    "/api/adapters": {"get"},
    "/api/guard": {"get"},
    "/api/scan": {"post"},
    "/api/scan/cancel": {"post"},
    "/api/job": {"get"},
    "/api/devices": {"get"},
    "/api/devices/{mac}": {"patch"},
    "/api/devices/{mac}/deep-scan": {"post"},
    "/api/scans": {"get"},
    "/api/log": {"get"},
    "/api/settings": {"get", "put"},
    "/api/oui/update": {"post"},
}


def test_every_ui_path_is_a_server_route(server) -> None:  # type: ignore[no-untyped-def]
    app = server.create_app(services=object())  # type: ignore[arg-type]  # nur die Routentabelle wird gelesen
    paths = app.openapi()["paths"]  # {pfad: {methode: ...}}
    ws_routes = {getattr(r, "path", "") for r in app.routes}
    js = APP_JS.read_text(encoding="utf-8")
    used = {re.sub(r"\$\{[^}]*\}", "{mac}", m) for m in re.findall(r"[`\"'](/(?:api/[^`\"'\s]*|ws))[`\"']", js)}
    assert used
    assert "/ws" in used and "/ws" in ws_routes
    missing = {u for u in used if u != "/ws"} - set(paths)
    assert not missing, f"keine Server-Route für: {sorted(missing)}"
    assert set(UI_CALLS) <= used, "UI_CALLS passt nicht mehr zu app.js"
    for path, methods in UI_CALLS.items():
        assert methods <= set(paths[path]), f"{path}: Server kennt {sorted(paths[path])}, die Oberfläche ruft {sorted(methods)}"
    assert "get" in paths["/api/export/{fmt}"]  # Export-Links in index.html


def test_editable_settings_are_accepted_by_server(server, ui: dict[str, Any]) -> None:  # type: ignore[no-untyped-def]
    editable = set(server.EDITABLE_SETTINGS)
    assert set(ui["settingsEditable"]) <= editable
    assert "blocked_gateway_macs" not in editable and "permanent_blocked_ssids" not in editable
    assert "blocked_gateway_macs" not in ui["settingsEditable"]


def test_scan_body_accepts_ui_request(server, ui: dict[str, Any]) -> None:  # type: ignore[no-untyped-def]
    assert set(server.ScanBody.model_fields) == set(ui["scanRequestKeys"])
    body = server.ScanBody(adapter="WLAN", mode="registered", port_scan=False, confirm_foreign=True, remember_home=True)
    assert body.mode == "registered" and body.remember_home is True


def test_device_patch_accepts_ui_fields(server, ui: dict[str, Any]) -> None:  # type: ignore[no-untyped-def]
    allowed = set(server.DevicePatch.model_fields)
    assert set(ui["patchKeys"]) <= allowed, sorted(set(ui["patchKeys"]) - allowed)


def test_server_csp_allows_what_the_ui_needs(server) -> None:  # type: ignore[no-untyped-def]
    csp = server.content_security_policy(8765)
    assert "script-src 'self'" in csp and "'unsafe-inline'" not in csp.split("script-src")[1].split(";")[0]
    assert "img-src 'self' data:" in csp, "Knotenbilder der Karte sind Data-URIs"
    assert "style-src 'self' 'unsafe-inline'" in csp, "vis-network fügt ein <style>-Element ein"
    assert "ws://127.0.0.1:8765" in csp or "connect-src 'self'" in csp
