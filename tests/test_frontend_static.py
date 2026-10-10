"""Statische Prüfungen der Oberfläche (netscan/web/static): offline, CSP-tauglich, Vertrag zur Web-API.

Kein Browser nötig. Die Sicherheitsregeln hier spiegeln die CSP des Servers (script-src 'self') und
die Regel „Daten aus dem Netz nie als HTML einsetzen“. Stufe 2 (monitor.js, BAUPLAN §27–§30) wird mitgeprüft.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "netscan" / "web" / "static"
INDEX = STATIC / "index.html"
APP_JS = STATIC / "app.js"
MONITOR_JS = STATIC / "monitor.js"
STYLE = STATIC / "style.css"
VIS = STATIC / "vendor" / "vis-network.min.js"
CHART = STATIC / "vendor" / "chart.umd.min.js"
BAUPLAN = ROOT / "docs" / "BAUPLAN.md"
JS_FILES = {"app.js": APP_JS, "monitor.js": MONITOR_JS}

# Pfade der Web-API laut BAUPLAN §12 (Export: je Format ein Pfad)
CONTRACT_PATHS = {
    "/api/status",
    "/api/adapters",
    "/api/guard",
    "/api/scan",
    "/api/scan/cancel",
    "/api/job",
    "/api/devices",
    "/api/devices/{mac}",
    "/api/devices/{mac}/deep-scan",
    "/api/inventory",
    "/api/scans",
    "/api/log",
    "/api/export/json",
    "/api/export/csv",
    "/api/export/html",
    "/api/settings",
    "/api/oui/update",
    "/ws",
}
# Stufe 2 (BAUPLAN §27); {mac} = Geräte-MAC, {id} = Kennung einer Prüfung bzw. eines Alerts
CONTRACT_PATHS_STAGE2 = {
    "/api/monitor",
    "/api/monitor/targets",
    "/api/monitor/targets/{mac}",
    "/api/monitor/targets/{mac}/suggestions",
    "/api/monitor/targets/{mac}/checks",
    "/api/monitor/checks/{id}",
    "/api/monitor/run",
    "/api/metrics/series",
    "/api/metrics/trend",
    "/api/metrics/overview",
    "/api/alerts",
    "/api/alerts/{id}/ack",
    "/api/alerts/ack-all",
    "/api/alerts/stats",
    "/api/autostart",
}
CONTRACT_PATHS |= CONTRACT_PATHS_STAGE2

# Diese Pfade muss die Oberfläche laut Auftrag tatsächlich benutzen (Export steht als Link in index.html).
REQUIRED_JS_PATHS = {
    "/api/status",
    "/api/adapters",
    "/api/guard",
    "/api/scan",
    "/api/scan/cancel",
    "/api/job",
    "/api/devices",
    "/api/devices/{mac}",
    "/api/devices/{mac}/deep-scan",
    "/api/scans",
    "/api/log",
    "/api/settings",
    "/api/oui/update",
    "/ws",
} | CONTRACT_PATHS_STAGE2

EVENT_TYPES = [
    "hello",
    "job.started",
    "job.progress",
    "job.log",
    "job.finished",
    "device.updated",
    "devices.changed",
    "guard.result",
    "oui.updated",
]
# Stufe 2 (BAUPLAN §29): behandelt monitor.js, app.js reicht sie über emit() weiter
EVENT_TYPES_STAGE2 = ["monitor.status", "monitor.cycle", "monitor.targets", "alert.opened", "alert.closed", "alert.acknowledged"]
TAB_NAMES = ("devices", "map", "monitor", "alerts", "log")


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def html() -> str:
    return read(INDEX)


@pytest.fixture(scope="module")
def js() -> str:
    return read(APP_JS)


@pytest.fixture(scope="module")
def mjs() -> str:
    return read(MONITOR_JS)


@pytest.fixture(scope="module")
def css() -> str:
    return read(STYLE)


class _Tags(HTMLParser):
    """Sammelt Tags mit Attributen und den Text in <script>/<style>."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[tuple[str, dict[str, str | None]]] = []
        self.script_text: list[str] = []
        self._in_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))
        if tag == "script":
            self._in_script = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self._in_script = False

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self.script_text.append(data)


@pytest.fixture(scope="module")
def tags(html: str) -> _Tags:
    parser = _Tags()
    parser.feed(html)
    return parser


# --- Dateien ----------------------------------------------------------------------------------


def test_files_exist() -> None:
    for path in (INDEX, APP_JS, MONITOR_JS, STYLE, VIS, CHART):
        assert path.is_file(), f"fehlt: {path}"
        assert path.stat().st_size > 0


def test_vis_network_version() -> None:
    head = VIS.read_bytes()[:400].decode("utf-8", errors="replace")
    assert "@version 10.1.2" in head


def test_chart_js_version() -> None:
    head = CHART.read_bytes()[:300].decode("utf-8", errors="replace")
    assert "Chart.js v4.5.1" in head
    assert (STATIC / "vendor" / "chart.js-LICENSE.md").is_file()


def test_html_basics(html: str) -> None:
    assert html.lstrip().lower().startswith("<!doctype html>")
    assert '<html lang="de">' in html
    assert '<meta charset="utf-8">' in html
    for label in ("Geräte", "Netzwerkkarte", "Überwachung", "Alerts", "Scan-Protokoll", "Scan starten", "Abbrechen", "Port-Scan",
                  "virtuelle Adapter zeigen", "Jetzt prüfen", "Alle quittieren", "Autostart"):
        assert label in html, label
    assert "Netz absuchen" in html and "Nur eingetragene Geräte" in html
    assert 'value="full"' in html and 'value="registered"' in html


def test_html_ids_unique(html: str) -> None:
    ids = re.findall(r'\sid="([^"]+)"', html)
    assert len(ids) == len(set(ids)), [i for i in ids if ids.count(i) > 1]


def test_export_links(html: str) -> None:
    for fmt in ("json", "csv", "html"):
        match = re.search(rf'<a\b[^>]*href="/api/export/{fmt}"[^>]*>', html)
        assert match, fmt
        assert re.search(r"\sdownload\b", match.group(0)), f"download-Attribut fehlt bei {fmt}"


def test_settings_and_detail_containers(html: str, tags: _Tags) -> None:
    names = [t for t, _ in tags.tags]
    assert "dialog" in names, "Einstellungen brauchen ein <dialog>"
    assert "aside" in names or "dialog" in names
    assert 'id="detail"' in html and 'id="settings-dialog"' in html


# --- Offline und CSP --------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["index.html", "app.js", "monitor.js", "style.css"])
def test_no_external_addresses(name: str) -> None:
    text = read(STATIC / name)
    for url in re.findall(r"https?://[^\s\"'<>)`]*", text):
        assert url.startswith("http://www.w3.org/"), f"externe Adresse in {name}: {url}"
    # ws:// und wss:// nur als nackter Präfix, der mit location.host zusammengesetzt wird
    for match in re.finditer(r"wss?://[^\"'`]*", text):
        assert match.group(0) in ("ws://", "wss://"), f"ws-Adresse in {name}: {match.group(0)}"


def test_css_has_no_urls(css: str) -> None:
    assert "url(" not in css
    assert "@import" not in css


def test_index_has_no_inline_script_or_handlers(tags: _Tags) -> None:
    assert "".join(tags.script_text).strip() == "", "Inline-Skript in index.html"
    for tag, attrs in tags.tags:
        for name, value in attrs.items():
            assert not name.startswith("on"), f"<{tag}> hat Ereignis-Attribut {name}"
            assert name != "style", f"<{tag}> hat style-Attribut"
            assert name != "srcdoc"
            if name in ("href", "src", "action"):
                assert not (value or "").strip().lower().startswith("javascript:"), f"javascript:-Adresse in <{tag}>"
        assert tag not in ("style", "iframe", "object", "embed"), f"<{tag}> ist nicht erlaubt"


def test_index_scripts_and_styles(tags: _Tags) -> None:
    scripts = [a for t, a in tags.tags if t == "script"]
    srcs = [a.get("src") for a in scripts]
    # Bibliotheken zuerst, dann app.js (stellt window.NetscanApp bereit), dann monitor.js
    assert srcs == ["/static/vendor/vis-network.min.js", "/static/vendor/chart.umd.min.js", "/static/app.js", "/static/monitor.js"], srcs
    assert all("defer" in a for a in scripts), "alle Skripte mit defer laden (die Reihenfolge bleibt dabei erhalten)"
    links = [a for t, a in tags.tags if t == "link"]
    assert any(a.get("href") == "/static/style.css" for a in links)
    for a in links:
        assert (a.get("href") or "").startswith("/static/")


@pytest.mark.parametrize("name", sorted(JS_FILES))
@pytest.mark.parametrize(
    "pattern, what",
    [
        (r"\beval\s*\(", "eval"),
        (r"new\s+Function\b", "new Function"),
        (r"\bFunction\s*\(", "Function()"),
        (r"\b(?:setTimeout|setInterval)\s*\(\s*[\"'`]", "Zeichenkette in setTimeout/setInterval"),
        (r"setAttribute\(\s*[\"']on", "setAttribute on…"),
        (r"setAttribute\(\s*[\"']style", "setAttribute style"),
        (r"javascript:", "javascript:-Adresse"),
        (r"\.srcdoc\b", "srcdoc"),
        (r"document\.write", "document.write"),
        (r"insertAdjacentHTML", "insertAdjacentHTML"),
        (r"createContextualFragment", "createContextualFragment"),
        (r"\bDOMParser\b", "DOMParser"),
        (r"\bimportScripts\b", "importScripts"),
    ],
)
def test_js_has_no_unsafe_constructs(name: str, pattern: str, what: str) -> None:
    assert not re.search(pattern, read(JS_FILES[name])), f"verboten in {name}: {what}"


@pytest.mark.parametrize("name", sorted(JS_FILES))
def test_innerhtml_only_with_fixed_strings(name: str) -> None:
    for match in re.finditer(r"\.(innerHTML|outerHTML)\s*(\+?=)\s*([^;\n]+)", read(JS_FILES[name])):
        rhs = match.group(3).strip().rstrip(",")
        fixed = re.fullmatch(r"(['\"])[^'\"\\$`{}]*\1", rhs)
        assert fixed, f"{match.group(1)} mit Variable oder Ausdruck: {match.group(0)}"


def test_monitor_js_never_writes_html(mjs: str) -> None:
    # Daten aus Netz und Datenbank (Alert-Texte, Gerätenamen, Dienstdetails) nur über textContent/createElement
    for bad in ("innerHTML", "outerHTML", "insertAdjacent", "document.write", ".srcdoc", "fetch(", "XMLHttpRequest", "localStorage"):
        assert bad not in mjs, bad
    assert "textContent" in mjs and "App.h" in mjs


@pytest.mark.parametrize("name", sorted(JS_FILES))
def test_js_node_syntax_check(name: str) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node nicht im PATH")
    result = subprocess.run([node, "--check", str(JS_FILES[name])], capture_output=True, text=True, encoding="utf-8", timeout=30)
    assert result.returncode == 0, result.stderr


def test_only_one_new_global(js: str, mjs: str) -> None:
    """app.js legt genau window.NetscanApp an; monitor.js legt nichts Globales an und nutzt nur bekannte Globale."""
    assert re.findall(r"window\.([A-Za-z_$][\w$]*)\s*=(?!=)", js) == ["NetscanApp"]
    assert "Object.freeze" in js[js.index("window.NetscanApp =") :][:80]
    assert not re.findall(r"window\.([A-Za-z_$][\w$]*)\s*=(?!=)", mjs)
    assert set(re.findall(r"window\.([A-Za-z_$][\w$]*)", mjs)) <= {"NetscanApp", "Chart", "confirm", "matchMedia"}
    assert re.match(r'/\*[\s\S]*?\*/\s*"use strict";\s*\(function \(\) \{', mjs), "monitor.js ist ein eigenes IIFE"
    assert mjs.rstrip().endswith("})();")


def test_chart_js_usage(mjs: str) -> None:
    """Kein Zeit-Adapter, x-Achse linear in ms, Animation aus, Lücken sichtbar, alte Diagramme zerstören, Hinweis ohne Chart.js."""
    assert 'type: "linear"' in mjs and 'type: "time"' not in mjs and "adapter" not in mjs.lower()
    assert "animation: false" in mjs
    assert mjs.count("spanGaps: false") >= 3 and "spanGaps: true" not in mjs
    assert ".destroy()" in mjs and "getChart" in mjs
    assert 'typeof window.Chart === "function"' in mjs and "Chart.js" in mjs and "konnte nicht geladen werden" in mjs
    assert "--chart-1" in mjs and "getComputedStyle" in mjs, "Farben aus CSS-Variablen (hell/dunkel)"
    assert "prefers-color-scheme: dark" in mjs, "bei Wechsel Hell/Dunkel neu zeichnen"


# --- Vertrag zur Web-API ----------------------------------------------------------------------


def _placeholder(match: re.Match[str]) -> str:
    return "{mac}" if "mac" in match.group(1).lower() else "{id}"


def _js_paths(js: str) -> set[str]:
    found: set[str] = set()
    for match in re.finditer(r"[`\"'](/(?:api/[^`\"'\s]*|ws))[`\"']", js):
        found.add(re.sub(r"\$\{([^}]*)\}", _placeholder, match.group(1)))
    return found


@pytest.mark.parametrize("name", sorted(JS_FILES))
def test_js_paths_are_in_contract(name: str) -> None:
    used = _js_paths(read(JS_FILES[name]))
    assert used, "keine API-Pfade gefunden"
    unknown = used - CONTRACT_PATHS
    assert not unknown, f"Pfade in {name} nicht im Bauplan §12/§27: {sorted(unknown)}"


def test_js_uses_required_paths(js: str, mjs: str) -> None:
    missing = REQUIRED_JS_PATHS - _js_paths(js) - _js_paths(mjs)
    assert not missing, f"nicht benutzt: {sorted(missing)}"


def test_stage2_paths_live_in_monitor_js(js: str, mjs: str) -> None:
    assert CONTRACT_PATHS_STAGE2 <= _js_paths(mjs)
    assert not (_js_paths(js) & CONTRACT_PATHS_STAGE2), "Stufe-2-Pfade gehören nach monitor.js"


def test_html_api_paths_are_in_contract(html: str) -> None:
    for path in re.findall(r'(?:href|src|action)="(/api/[^"]*)"', html):
        assert path in CONTRACT_PATHS, path


@pytest.mark.skipif(not BAUPLAN.exists(), reason="docs/BAUPLAN.md fehlt")
def test_contract_paths_appear_in_bauplan() -> None:
    text = read(BAUPLAN)
    for path in CONTRACT_PATHS:
        if path.startswith("/api/export/"):
            assert "/api/export/" in text
        else:
            assert path in text, f"{path} steht nicht im Bauplan"


def test_every_event_type_is_handled(js: str, mjs: str) -> None:
    for event in EVENT_TYPES:
        assert f'"{event}"' in js, f"Ereignis {event} wird nicht behandelt"
    for event in EVENT_TYPES_STAGE2:
        assert f'App.on("{event}"' in mjs, f"Ereignis {event} wird in monitor.js nicht behandelt"
    body = js[js.index("function handleEvent(msg)") : js.index("function onHello(data)")]
    assert "emit(msg.type, data, msg)" in body, "app.js muss alle Ereignisse an monitor.js weiterreichen"


def test_single_fetch_with_json_header(js: str) -> None:
    assert len(re.findall(r"\bfetch\s*\(", js)) == 1, "alle Aufrufe über api()"
    assert '"Content-Type"' in js and '"application/json"' in js
    # Bodies nur bei Methoden mit Body, und dann immer mit Content-Type
    start = js.index("async function api(")
    body = js[start : js.index("// ---------- Status", start)]
    assert body.index('"Content-Type"') < body.index("init.body")


def test_settings_only_send_editable_fields(js: str) -> None:
    match = re.search(r"const SETTINGS_EDITABLE = \[([^\]]*)\]", js)
    assert match
    fields = set(re.findall(r'"([a-z_]+)"', match.group(1)))
    assert fields == {
        "blocked_ssids_extra", "home_gateway_macs", "rate_pps", "port_timeout_ms", "port_scan_excluded_categories", "ask_before_foreign_scan",
        # Stufe 2 (BAUPLAN §28)
        "monitor_enabled", "monitor_interval_s", "monitor_timeout_ms", "alert_offline_minutes", "alert_service_minutes", "alert_rtt_minutes",
        "alert_new_device", "alert_new_port",
    }
    assert "blocked_gateway_macs" not in fields and "permanent_blocked_ssids" not in fields


def test_ids_used_by_js_exist_in_html(html: str, js: str, mjs: str) -> None:
    html_ids = set(re.findall(r'\sid="([^"]+)"', html))
    used = set(re.findall(r"\$\(\s*\"([A-Za-z0-9_-]+)\"\s*\)", js + mjs))
    used |= {f"tab-{t}" for t in TAB_NAMES} | {f"panel-{t}" for t in TAB_NAMES}
    # Eingabefelder der Überwachung stehen als Liste in app.js (MONITOR_NUMBER_SETTINGS / MONITOR_BOOL_SETTINGS)
    used |= set(re.findall(r'"(set-(?:mon|alert)-[a-z-]+)"', js))
    assert {"set-mon-interval", "set-mon-enabled", "set-alert-new-port"} <= used
    missing = used - html_ids
    assert not missing, f"IDs fehlen in index.html: {sorted(missing)}"


def test_js_has_no_getelementbyid_with_unknown_literal(html: str, js: str, mjs: str) -> None:
    html_ids = set(re.findall(r'\sid="([^"]+)"', html))
    for literal in re.findall(r"getElementById\(\s*\"([^\"]+)\"\s*\)", js + mjs):
        assert literal in html_ids, literal


def test_tabs_order_and_panels(html: str, js: str) -> None:
    tabs = re.findall(r'role="tab" id="tab-([a-z]+)" aria-controls="panel-([a-z]+)"', html)
    assert [t for t, _ in tabs] == list(TAB_NAMES), "Reiter: Geräte | Netzwerkkarte | Überwachung | Alerts | Scan-Protokoll"
    assert all(t == p for t, p in tabs)
    assert 'const TABS = ["devices", "map", "monitor", "alerts", "log"]' in js, "Tastaturbedienung läuft über TABS"
    assert re.search(r'id="tab-alerts"[^>]*>Alerts<span class="tab-count" id="alert-count" hidden>', html), "Zähler am Reiter Alerts"
    for name in ("monitor", "alerts"):
        assert re.search(rf'<section[^>]*id="panel-{name}"[^>]*role="tabpanel"[^>]*hidden', html)


def test_status_line_has_monitor_part(html: str, js: str, mjs: str) -> None:
    assert 'id="status-core"' in html and 'id="status-monitor"' in html
    assert '$("status-core")' in js and '$("status-monitor")' in mjs
    assert "DB_WARN_BYTES = 100 * 1024 * 1024" in mjs


def test_detail_and_settings_containers(html: str) -> None:
    assert html.index('id="detail-ports"') < html.index('id="detail-firewall"') < html.index('id="detail-monitor"'), "Firewall-Hinweis unter den Ports"
    assert re.search(r'id="set-autostart-block" hidden', html), "Autostart nur zeigen, wenn unterstützt"
    assert "startet mit der Anmeldung, ohne Adminrechte – ARP-Scan dann nicht möglich" in html


def test_hint_texts_verbatim(mjs: str) -> None:
    flat = re.sub(r'"\s*\+?\s*\n\s*"', "", mjs)  # über zwei Zeilen verteilte Zeichenketten zusammenfügen
    assert "Die Überwachung macht sichtbar, wann diese Person zu Hause ist. Alle im Haushalt sollten davon wissen." in flat
    assert (
        "Eigener PC: lokal geprüft – die Windows-Firewall wird dabei nicht berücksichtigt; von anderen Geräten aus kann der Port gesperrt sein."
        in flat
    )


def test_run_button_handles_busy_monitor(mjs: str) -> None:
    body = mjs[mjs.index("async function runNow()") : mjs.index("// ---------- Reiter Alerts")]
    assert "res.status === 409" in body and "MAPI.run" in body


# --- Wächter-Band: bei „block“ keine Schaltfläche ------------------------------------------------


def test_block_band_has_no_buttons_in_source(js: str) -> None:
    start = js.index("function renderGuard()")
    end = js.index("function renderGuardButtons()", start)
    body = js[start:end]
    first_button = body.find('h("button"')
    assert first_button > 0, "Wächter-Band erzeugt gar keine Knöpfe mehr"
    confirm_branch = body.index('if (tone === "confirm")')
    assert first_button > confirm_branch, "Knopf außerhalb des confirm-Zweigs"
    assert body.count('h("button"') == 2
    # Nur diese beiden Texte, kein „Trotzdem“, „Ignorieren“ o. Ä.
    labels = re.findall(r'text: "([^"]+)", on:', body)
    assert labels == ["Nur diesmal scannen", "Das ist mein Heimnetz"], labels


def test_start_button_disabled_on_block(js: str) -> None:
    start = js.index("function updateControls()")
    body = js[start : js.index("let renderJobQueued", start)]
    assert 'state.guard.decision === "block"' in body
    assert "start.disabled = busy || blocked" in body


def test_monitor_ui_has_no_guard_override(mjs: str) -> None:
    """Der Wächter gilt auch für den Monitor (BAUPLAN §18): die Oberfläche bietet nichts, was ihn übergeht."""
    for bad in ("confirm_foreign", "remember_home", "Trotzdem", "Ignorieren", "Wächter übergehen"):
        assert bad not in mjs, bad


# --- Darstellung --------------------------------------------------------------------------------


def test_css_light_and_dark(css: str) -> None:
    assert "prefers-color-scheme: dark" in css
    assert re.search(r"color-scheme:\s*light dark", css)
    root_blocks = re.findall(r":root\s*\{", css)
    assert len(root_blocks) >= 2, "Farben für Hell und Dunkel fehlen"


def test_css_covers_main_classes(css: str, js: str) -> None:
    for cls in ("badge-new", "badge-unknown", "badge-known", "badge-private", "risk-low", "risk-medium", "risk-high", "risk-critical",
                "guard-block", "guard-confirm", "guard-allow", "row-new", "row-offline", "dot-on", "dot-off", "log-line", "level-warning", "level-error",
                # Stufe 2
                "status-part", "tab-count", "seg-btn", "tile-online", "tile-degraded", "tile-offline", "tile-paused", "chart-box", "chart-msg",
                "st-online", "st-degraded", "st-offline", "st-paused", "st-unknown", "svc-up", "svc-down", "svc-unknown", "svc-off",
                "sev-info", "sev-warning", "sev-critical", "privacy-hint", "firewall-hint", "check-list", "mstate-running", "mstate-paused"):
        assert f".{cls}" in css, cls


def test_css_chart_colors_light_and_dark(css: str) -> None:
    light, dark = css.split("@media (prefers-color-scheme: dark)", 1)
    for var in ("--chart-1", "--chart-2", "--chart-3", "--chart-4", "--chart-5", "--chart-band", "--chart-grid", "--status-paused", "--status-unknown"):
        assert f"{var}:" in light and f"{var}:" in dark, var
    for var in ("--status-good", "--status-warning", "--status-critical"):
        assert f"{var}:" in light, var


def test_german_text_uses_real_umlauts(html: str, js: str, mjs: str) -> None:
    for text in (html, js, mjs):
        for bad in ("Geraet", "Waechter", "fuer ", "ueber", "moeglich", "loeschen", "waehlen", "pruef", "Aenderung", "oeffnen", "Groesse"):
            assert bad.lower() not in text.lower(), f"Umschrift statt Umlaut: {bad}"
    assert "Geräte" in html and "Geräte" in js and "Geräte" in mjs
    assert "Einträge" in js
    assert "Überwachung" in mjs and "gestört" in mjs and "Lücke" in mjs


def test_no_leftover_markers(html: str, js: str, mjs: str, css: str) -> None:
    for name, text in (("index.html", html), ("app.js", js), ("monitor.js", mjs), ("style.css", css)):
        assert not re.search(r"\b(TODO|FIXME|XXX)\b", text), name
        assert "console.log" not in text, name
