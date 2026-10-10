"""Statische Prüfungen der Oberfläche (netscan/web/static): offline, CSP-tauglich, Vertrag zur Web-API.

Kein Browser nötig. Die Sicherheitsregeln hier spiegeln die CSP des Servers (script-src 'self') und
die Regel „Daten aus dem Netz nie als HTML einsetzen“.
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
STYLE = STATIC / "style.css"
VIS = STATIC / "vendor" / "vis-network.min.js"
BAUPLAN = ROOT / "docs" / "BAUPLAN.md"

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
}

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


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def html() -> str:
    return read(INDEX)


@pytest.fixture(scope="module")
def js() -> str:
    return read(APP_JS)


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
    for path in (INDEX, APP_JS, STYLE, VIS):
        assert path.is_file(), f"fehlt: {path}"
        assert path.stat().st_size > 0


def test_vis_network_version() -> None:
    head = VIS.read_bytes()[:400].decode("utf-8", errors="replace")
    assert "@version 10.1.2" in head


def test_html_basics(html: str) -> None:
    assert html.lstrip().lower().startswith("<!doctype html>")
    assert '<html lang="de">' in html
    assert '<meta charset="utf-8">' in html
    for label in ("Geräte", "Netzwerkkarte", "Scan-Protokoll", "Scan starten", "Abbrechen", "Port-Scan", "virtuelle Adapter zeigen"):
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


@pytest.mark.parametrize("name", ["index.html", "app.js", "style.css"])
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
    assert srcs == ["/static/vendor/vis-network.min.js", "/static/app.js"], srcs
    assert all("defer" in a for a in scripts), "beide Skripte mit defer laden"
    links = [a for t, a in tags.tags if t == "link"]
    assert any(a.get("href") == "/static/style.css" for a in links)
    for a in links:
        assert (a.get("href") or "").startswith("/static/")


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
def test_js_has_no_unsafe_constructs(js: str, pattern: str, what: str) -> None:
    assert not re.search(pattern, js), f"verboten in app.js: {what}"


def test_innerhtml_only_with_fixed_strings(js: str) -> None:
    for match in re.finditer(r"\.(innerHTML|outerHTML)\s*(\+?=)\s*([^;\n]+)", js):
        rhs = match.group(3).strip().rstrip(",")
        fixed = re.fullmatch(r"(['\"])[^'\"\\$`{}]*\1", rhs)
        assert fixed, f"{match.group(1)} mit Variable oder Ausdruck: {match.group(0)}"


def test_js_node_syntax_check() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node nicht im PATH")
    result = subprocess.run([node, "--check", str(APP_JS)], capture_output=True, text=True, encoding="utf-8", timeout=30)
    assert result.returncode == 0, result.stderr


# --- Vertrag zur Web-API ----------------------------------------------------------------------


def _js_paths(js: str) -> set[str]:
    found: set[str] = set()
    for match in re.finditer(r"[`\"'](/(?:api/[^`\"'\s]*|ws))[`\"']", js):
        found.add(re.sub(r"\$\{[^}]*\}", "{mac}", match.group(1)))
    return found


def test_js_paths_are_in_contract(js: str) -> None:
    used = _js_paths(js)
    assert used, "keine API-Pfade gefunden"
    unknown = used - CONTRACT_PATHS
    assert not unknown, f"Pfade nicht im Bauplan §12: {sorted(unknown)}"


def test_js_uses_required_paths(js: str) -> None:
    missing = REQUIRED_JS_PATHS - _js_paths(js)
    assert not missing, f"nicht benutzt: {sorted(missing)}"


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


def test_every_event_type_is_handled(js: str) -> None:
    for event in EVENT_TYPES:
        assert f'"{event}"' in js, f"Ereignis {event} wird nicht behandelt"


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
    assert fields == {"blocked_ssids_extra", "home_gateway_macs", "rate_pps", "port_timeout_ms", "port_scan_excluded_categories", "ask_before_foreign_scan"}
    assert "blocked_gateway_macs" not in fields and "permanent_blocked_ssids" not in fields


def test_ids_used_by_js_exist_in_html(html: str, js: str) -> None:
    html_ids = set(re.findall(r'\sid="([^"]+)"', html))
    used = set(re.findall(r"\$\(\s*\"([A-Za-z0-9_-]+)\"\s*\)", js))
    used |= {f"tab-{t}" for t in ("devices", "map", "log")} | {f"panel-{t}" for t in ("devices", "map", "log")}
    missing = used - html_ids
    assert not missing, f"IDs fehlen in index.html: {sorted(missing)}"


def test_js_has_no_getelementbyid_with_unknown_literal(html: str, js: str) -> None:
    html_ids = set(re.findall(r'\sid="([^"]+)"', html))
    for literal in re.findall(r"getElementById\(\s*\"([^\"]+)\"\s*\)", js):
        assert literal in html_ids, literal


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


# --- Darstellung --------------------------------------------------------------------------------


def test_css_light_and_dark(css: str) -> None:
    assert "prefers-color-scheme: dark" in css
    assert re.search(r"color-scheme:\s*light dark", css)
    root_blocks = re.findall(r":root\s*\{", css)
    assert len(root_blocks) >= 2, "Farben für Hell und Dunkel fehlen"


def test_css_covers_main_classes(css: str, js: str) -> None:
    for cls in ("badge-new", "badge-unknown", "badge-known", "badge-private", "risk-low", "risk-medium", "risk-high", "risk-critical",
                "guard-block", "guard-confirm", "guard-allow", "row-new", "row-offline", "dot-on", "dot-off", "log-line", "level-warning", "level-error"):
        assert f".{cls}" in css, cls


def test_german_text_uses_real_umlauts(html: str, js: str) -> None:
    for text in (html, js):
        for bad in ("Geraet", "Waechter", "fuer ", "ueber", "moeglich", "loeschen", "waehlen", "pruef", "Aenderung", "oeffnen", "Groesse"):
            assert bad.lower() not in text.lower(), f"Umschrift statt Umlaut: {bad}"
    assert "Geräte" in html and "Geräte" in js
    assert "Einträge" in js


def test_no_leftover_markers(html: str, js: str, css: str) -> None:
    for name, text in (("index.html", html), ("app.js", js), ("style.css", css)):
        assert not re.search(r"\b(TODO|FIXME|XXX)\b", text), name
        assert "console.log" not in text, name
