"""Logik der Oberfläche: die reinen Funktionen aus app.js laufen in Node (ohne Browser, ohne DOM).

app.js stellt sie über module.exports bereit, wenn es kein document gibt. Ohne node im PATH werden
die Tests übersprungen. Es geht kein Paket ins Netz; Node bekommt nur Beispieldaten.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
APP_JS = ROOT / "netscan" / "web" / "static" / "app.js"

# Node-Skript (nur ASCII, damit keine Kodierung der Kommandozeile stört). Gibt ein JSON-Objekt aus.
NODE_SCRIPT = r"""
const ui = require(process.argv[2]);
const out = {};
const colors = { bg: "#fff", surface: "#fff", text: "#111", muted: "#666", border: "#bbb", accent: "#24d", fresh: "#e50", edge: "#999", offline: "#aaa" };
const dev = (o) => Object.assign({ mac: "aa:bb:cc:00:00:01", ip: "192.168.178.10", display_name: "Test", category: "pc", category_label: "PC",
  category_source: "auto", ports: [], max_risk: null, known: false, is_new: false, online: true, is_gateway: false, is_self: false,
  mac_random: false, custom_name: null, note: "", port_scan_excluded: false }, o || {});

out.exports = Object.keys(ui).sort();

// IP-Sortierung numerisch
const ips = ["192.168.178.10", "192.168.178.9", "10.0.0.2", "foo", "192.168.178.100", "192.168.178.1"];
out.ipSorted = [...ips].sort((a, b) => ui.ipKey(a) - ui.ipKey(b));

// Gerätevergleich
const a = dev({ mac: "aa:bb:cc:00:00:0a", ip: "192.168.178.9", display_name: "Zebra", category_label: "Drucker", category: "printer", max_risk: "low", ports: [{ port: 631 }] });
const b = dev({ mac: "aa:bb:cc:00:00:0b", ip: "192.168.178.10", display_name: "alpha", category_label: "PC", max_risk: "critical", ports: [{ port: 23 }] });
const c = dev({ mac: "aa:bb:cc:00:00:0c", ip: "192.168.178.11", display_name: "Mitte", category_label: "Router", category: "router", max_risk: null });
const list = [a, b, c];
const sorted = (key, dir) => [...list].sort((x, y) => ui.compareDevices(x, y, key, dir)).map((d) => d.display_name);
out.byIp = sorted("ip", 1);
out.byIpDesc = sorted("ip", -1);
out.byName = sorted("name", 1);
out.byCategory = sorted("category", 1);
out.byRiskDesc = sorted("risk", -1);
out.byRiskAsc = sorted("risk", 1);
out.defaultDirRisk = ui.defaultSortDir("risk");
out.defaultDirIp = ui.defaultSortDir("ip");

// Suche
const nas = dev({ display_name: "NAS Keller", vendor: "Synology Incorporated", ip: "192.168.178.30", ports: [{ port: 445, service: "smb" }], is_new: true });
out.filter = {
  empty: ui.matchesFilter(nas, ""),
  name: ui.matchesFilter(nas, "keller"),
  vendor: ui.matchesFilter(nas, "synology"),
  ip: ui.matchesFilter(nas, "178.30"),
  port: ui.matchesFilter(nas, "445"),
  service: ui.matchesFilter(nas, "smb"),
  neu: ui.matchesFilter(nas, "neu"),
  miss: ui.matchesFilter(nas, "drucker"),
  offline: ui.matchesFilter(dev({ online: false }), "offline"),
};

// Zeit und Dauer
out.duration = [ui.formatDuration(0.4), ui.formatDuration(14.6), ui.formatDuration(60), ui.formatDuration(125), ui.formatDuration("x")];
out.time = { ok: ui.formatTime("2026-10-10T12:07:03+00:00"), noYear: ui.formatTime("2026-10-10T12:07:03+00:00", false), bad: ui.formatTime("kein Datum"), empty: ui.formatTime(null) };
out.number = ui.formatNumber(40316);

// Auftragsergebnis
out.results = {
  scan: ui.describeResult({ kind: "scan", result: "completed", summary: { devices: 26, new: 3, duration_s: 14.6, network: "192.168.178.0/24" } }),
  one: ui.describeResult({ kind: "scan", result: "completed", summary: { devices: 1, new: 0 } }),
  deep: ui.describeResult({ kind: "deep_scan", result: "completed", summary: { open_ports: [22], new_ports: [], duration_s: 70 } }),  // echtes Format: Listen
  oui: ui.describeResult({ kind: "oui_update", result: "completed", summary: { entries: 41000 } }),
  cancelled: ui.describeResult({ kind: "scan", result: "cancelled", summary: {} }),
  blocked: ui.describeResult({ kind: "scan", result: "blocked", error: "WLAN gesperrt" }),
  failed: ui.describeResult({ kind: "scan", result: "failed", error: "OSError: boom" }),
  failedNoText: ui.describeResult({ kind: "deep_scan", result: "failed" }),
  nothing: ui.describeResult({ kind: "scan", result: "completed" }),
};

// Fehlertexte der API
out.api = {
  text: ui.apiMessage({ detail: "Netz zu gross" }, "x"),
  list: ui.apiMessage({ detail: [{ msg: "Feld fehlt" }, { msg: "Wert falsch" }] }, "x"),
  fallback: ui.apiMessage(null, "Standardtext"),
  objectDetail: ui.apiMessage({ detail: { message: "Meldung" } }, "x"),
  emptyDetail: ui.apiMessage({ detail: "" }, "leer"),
};

// Request-Bodies
out.scanRequest = {
  plain: ui.buildScanRequest("WLAN", "full", true),
  once: ui.buildScanRequest("WLAN", "registered", false, { confirm_foreign: true }),
  home: ui.buildScanRequest("WLAN", "full", true, { confirm_foreign: true, remember_home: true }),
  badMode: ui.buildScanRequest("WLAN", "unsinn", true),
};
const form = (d, o) => Object.assign({ custom_name: d.custom_name || "", category: d.category_source === "user" ? d.category : "auto", note: d.note || "", known: d.known, port_scan_excluded: d.port_scan_excluded }, o || {});
const autoDev = dev({ category_source: "auto", category: "pc" });
const userDev = dev({ category_source: "user", category: "server", custom_name: "NAS Keller", note: "RAID", known: true });
out.patch = {
  unchanged: ui.buildDevicePatch(autoDev, form(autoDev)),
  unchangedUser: ui.buildDevicePatch(userDev, form(userDev)),
  name: ui.buildDevicePatch(autoDev, form(autoDev, { custom_name: "  Drucker Flur  " })),
  clearName: ui.buildDevicePatch(userDev, form(userDev, { custom_name: "   " })),
  setCategory: ui.buildDevicePatch(autoDev, form(autoDev, { category: "printer" })),
  resetCategory: ui.buildDevicePatch(userDev, form(userDev, { category: "auto" })),
  flags: ui.buildDevicePatch(autoDev, form(autoDev, { known: true, port_scan_excluded: true, note: "n" })),
};

// Einstellungen: nur geaenderte, erlaubte Felder
const orig = { rate_pps: 200, port_timeout_ms: 700, blocked_ssids_extra: ["A"], home_gateway_macs: ["aa:aa"], blocked_gateway_macs: ["zz"], permanent_blocked_ssids: ["P"], port_scan_excluded_categories: ["printer", "iot"] };
out.settings = {
  none: ui.diffSettings(orig, { rate_pps: 200, port_timeout_ms: 700, blocked_ssids_extra: ["A"], home_gateway_macs: ["aa:aa"], port_scan_excluded_categories: ["iot", "printer"] }),
  rate: ui.diffSettings(orig, { rate_pps: 100, port_timeout_ms: 700, blocked_ssids_extra: ["A"], home_gateway_macs: ["aa:aa"], port_scan_excluded_categories: ["printer", "iot"] }),
  ssid: ui.diffSettings(orig, { rate_pps: 200, port_timeout_ms: 700, blocked_ssids_extra: ["A", " B "], home_gateway_macs: ["aa:aa"], port_scan_excluded_categories: ["printer", "iot"] }),
  readonly: ui.diffSettings(orig, { rate_pps: 200, blocked_gateway_macs: [], permanent_blocked_ssids: [], port_timeout_ms: 700 }),
  home: ui.diffSettings(orig, { home_gateway_macs: [] }),
  cats: ui.diffSettings(orig, { port_scan_excluded_categories: ["router"] }),
};

// Karte
const ring = (n) => ui.ringLayout(n);
const minDist = (pts) => { let m = Infinity; for (let i = 0; i < pts.length; i++) for (let j = i + 1; j < pts.length; j++) m = Math.min(m, Math.hypot(pts[i].x - pts[j].x, pts[i].y - pts[j].y)); return m; };
const r30 = ring(30);
out.ring = { zero: ring(0).length, one: ring(1).length, n30: r30.length, minDist30: Math.round(minDist(r30)), minRadius: Math.round(Math.min(...r30.map((p) => Math.hypot(p.x, p.y)))), n100: ring(100).length, minDist100: Math.round(minDist(ring(100))) };

// freier Platz fuer neue Geraete: nie auf einem belegten Punkt und nie auf dem Router
const taken = ring(12);
const slotA = ui.freeSlot(taken);
const slotB = ui.freeSlot(taken.concat([slotA]));
out.slot = {
  emptyIsOnFirstRing: Math.round(Math.hypot(ui.freeSlot([]).x, ui.freeSlot([]).y)),
  minDistA: Math.round(Math.min(...taken.map((p) => Math.hypot(p.x - slotA.x, p.y - slotA.y)))),
  minDistB: Math.round(Math.min(...taken.concat([slotA]).map((p) => Math.hypot(p.x - slotB.x, p.y - slotB.y)))),
  distinct: slotA.x !== slotB.x || slotA.y !== slotB.y,
  full: (() => { let pts = []; for (let i = 0; i < 150; i++) pts.push(ui.freeSlot(pts)); return Math.round(minDist(pts)); })(),
  allOffCenter: (() => { let pts = []; for (let i = 0; i < 40; i++) pts.push(ui.freeSlot(pts)); return Math.min(...pts.map((p) => Math.hypot(p.x, p.y))) >= 125; })(),
};

const gw = dev({ mac: "aa:bb:cc:00:00:01", ip: "192.168.178.1", is_gateway: true, category: "router", display_name: "fritz.box" });
const d2 = dev({ mac: "aa:bb:cc:00:00:02", ip: "192.168.178.30", online: false });
const d3 = dev({ mac: "aa:bb:cc:00:00:03", ip: "192.168.178.9" });
const planA = ui.planMap([d2, gw, d3]);
const planB = ui.planMap([d2, d3]);
const gw2 = dev({ mac: "aa:bb:cc:00:00:04", ip: "192.168.178.2", is_gateway: true });
const planC = ui.planMap([gw2, gw, d3]);
out.plan = {
  hubA: planA.hubId, othersA: planA.others.map((d) => d.mac), edgesA: planA.edges.map((e) => [e.from, e.to, e.offline]),
  hubB: planB.hubId, hubIsNullB: planB.hub === null, edgesB: planB.edges.map((e) => e.from),
  hubC: planC.hubId, othersC: planC.others.map((d) => d.mac),
  empty: ui.planMap([]).edges.length,
};
const colorsFresh = ui.nodeSpec(dev({ is_new: true, display_name: "<img src=x onerror=alert(1)>" }), false, colors);
const colorsOff = ui.nodeSpec(dev({ online: false }), false, colors);
const colorsHub = ui.nodeSpec(gw, true, colors);
const colorsNormal = ui.nodeSpec(dev(), false, colors);
out.nodes = {
  freshBorder: colorsFresh.color.border, freshWidth: colorsFresh.borderWidth, freshLabel: colorsFresh.label,
  offOpacity: colorsOff.opacity, offBorder: colorsOff.color.border, offFont: colorsOff.font.color,
  hubFixed: colorsHub.fixed, hubSize: colorsHub.size, normalFixed: colorsNormal.fixed, normalSize: colorsNormal.size,
  normalBorder: colorsNormal.color.border, normalOpacity: colorsNormal.opacity, shape: colorsNormal.shape,
  imageIsDataUri: colorsNormal.image.startsWith("data:image/svg+xml"),
  longLabel: ui.nodeLabel(dev({ display_name: "x".repeat(60) })).split("\n")[0].length,
  idIsMac: colorsNormal.id,
};

// Symbole
const cats = ui.CATEGORY_LIST.map((c) => c[0]);
out.icons = { categories: cats, svgs: Object.fromEntries(cats.map((c) => [c, ui.iconSvg(c)])), fallback: ui.iconSvg("gibt-es-nicht") === ui.iconSvg("unknown"), uri: ui.iconUri("router").slice(0, 40) };

// Wächter-Texte
out.guard = {
  home: ui.guardTitle({ decision: "allow", code: "ok_home" }),
  ssid: ui.guardTitle({ decision: "block", code: "blocked_ssid" }),
  gw: ui.guardTitle({ decision: "block", code: "blocked_gateway" }),
  foreign: ui.guardTitle({ decision: "confirm", code: "foreign_network" }),
  unknown: ui.guardTitle({ decision: "confirm", code: "unknown_network" }),
  nogw: ui.guardTitle({ decision: "confirm", code: "no_gateway" }),
  fallbackBlock: ui.guardTitle({ decision: "block", code: null }),
  details: ui.guardDetails({ ssid: "Cafe Netz", gateway_ip: "10.0.0.1", gateway_mac: "00:00:5e:00:53:01" }),
  unreadable: ui.guardDetails({ ssid: null, ssid_readable: false, gateway_ip: "10.0.0.1", gateway_mac: null }),
  ssidKeepsSpaces: ui.guardDetails({ ssid: " A  B ", gateway_ip: null }),
};

// Pfade
out.paths = { device: ui.API.device("aa:bb:cc:00:00:01"), deep: ui.API.deepScan("aa:bb:cc:00:00:01"), weird: ui.macPath("a/b c") };
out.misc = { truncate: ui.truncate("abcdefghij", 5), truncateShort: ui.truncate("abc", 5), plural: [ui.plural(1, "Geraet", "Geraete"), ui.plural(2, "Geraet", "Geraete")], label: ui.categoryLabel("iot"), labelUnknown: ui.categoryLabel("zzz") };

process.stdout.write(JSON.stringify(out));
"""


@pytest.fixture(scope="module")
def ui(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node nicht im PATH")
    script = tmp_path_factory.mktemp("frontend") / "check.js"
    script.write_text(NODE_SCRIPT, encoding="utf-8")
    env = dict(os.environ, TZ="UTC", NODE_OPTIONS="")
    result = subprocess.run([node, str(script), str(APP_JS)], capture_output=True, text=True, encoding="utf-8", timeout=60, env=env)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_module_loads_without_dom(ui: dict[str, Any]) -> None:
    for name in ("ipKey", "compareDevices", "matchesFilter", "describeResult", "buildScanRequest", "buildDevicePatch", "diffSettings", "planMap", "nodeSpec", "ringLayout"):
        assert name in ui["exports"], name


def test_ip_sort_is_numeric(ui: dict[str, Any]) -> None:
    assert ui["ipSorted"] == ["10.0.0.2", "192.168.178.1", "192.168.178.9", "192.168.178.10", "192.168.178.100", "foo"]


def test_device_sorting(ui: dict[str, Any]) -> None:
    assert ui["byIp"] == ["Zebra", "alpha", "Mitte"]
    assert ui["byIpDesc"] == ["Mitte", "alpha", "Zebra"]
    assert ui["byName"] == ["alpha", "Mitte", "Zebra"]  # ohne Beachtung der Groß-/Kleinschreibung
    assert ui["byCategory"] == ["Zebra", "alpha", "Mitte"]  # Drucker, PC, Router
    assert ui["byRiskDesc"] == ["alpha", "Zebra", "Mitte"]  # kritisch, niedrig, ohne Ports
    assert ui["byRiskAsc"] == ["Mitte", "Zebra", "alpha"]
    assert ui["defaultDirRisk"] == -1 and ui["defaultDirIp"] == 1


def test_filter(ui: dict[str, Any]) -> None:
    f = ui["filter"]
    assert f["empty"] and f["name"] and f["vendor"] and f["ip"] and f["port"] and f["service"] and f["neu"] and f["offline"]
    assert not f["miss"]


def test_time_and_duration(ui: dict[str, Any]) -> None:
    assert ui["duration"] == ["unter 1 s", "15 s", "1 min", "2 min 5 s", ""]
    assert "10.10.2026" in ui["time"]["ok"] and "12:07:03" in ui["time"]["ok"]
    assert "2026" not in ui["time"]["noYear"] and "12:07:03" in ui["time"]["noYear"]
    assert ui["time"]["bad"] == "" and ui["time"]["empty"] == ""
    assert ui["number"] == "40.316"


def test_job_results(ui: dict[str, Any]) -> None:
    r = ui["results"]
    assert r["scan"] == {"tone": "ok", "text": "Scan abgeschlossen: 26 Geräte, 3 neu, Dauer 15 s, 192.168.178.0/24"}
    assert r["one"]["text"] == "Scan abgeschlossen: 1 Gerät, 0 neu"
    assert r["deep"]["text"] == "Tiefenscan abgeschlossen: 1 offener Port, 0 neu, Dauer 1 min 10 s"
    assert r["oui"]["text"] == "Aktualisierung der Herstellerliste abgeschlossen: 41.000 Einträge"
    assert r["cancelled"] == {"tone": "warn", "text": "Scan abgebrochen."}
    assert r["blocked"] == {"tone": "error", "text": "Scan gesperrt: WLAN gesperrt"}
    assert r["failed"] == {"tone": "error", "text": "Scan fehlgeschlagen: OSError: boom"}
    assert r["failedNoText"] == {"tone": "error", "text": "Tiefenscan fehlgeschlagen."}
    assert r["nothing"] == {"tone": "ok", "text": "Scan abgeschlossen."}


def test_api_messages(ui: dict[str, Any]) -> None:
    a = ui["api"]
    assert a["text"] == "Netz zu gross"
    assert a["list"] == "Feld fehlt; Wert falsch"
    assert a["fallback"] == "Standardtext"
    assert a["objectDetail"] == "Meldung"
    assert a["emptyDetail"] == "leer"


def test_scan_request_body(ui: dict[str, Any]) -> None:
    r = ui["scanRequest"]
    assert r["plain"] == {"adapter": "WLAN", "mode": "full", "port_scan": True, "confirm_foreign": False, "remember_home": False}
    assert r["once"] == {"adapter": "WLAN", "mode": "registered", "port_scan": False, "confirm_foreign": True, "remember_home": False}
    assert r["home"]["confirm_foreign"] is True and r["home"]["remember_home"] is True
    assert r["badMode"]["mode"] == "full"


def test_device_patch_sends_only_changes(ui: dict[str, Any]) -> None:
    p = ui["patch"]
    assert p["unchanged"] == {}
    assert p["unchangedUser"] == {}
    assert p["name"] == {"custom_name": "Drucker Flur"}
    assert p["clearName"] == {"custom_name": ""}
    assert p["setCategory"] == {"category": "printer"}
    assert p["resetCategory"] == {"category": "auto"}
    assert p["flags"] == {"note": "n", "known": True, "port_scan_excluded": True}


def test_settings_diff_only_editable_changes(ui: dict[str, Any]) -> None:
    s = ui["settings"]
    assert s["none"] == {}
    assert s["rate"] == {"rate_pps": 100}
    assert s["ssid"] == {"blocked_ssids_extra": ["A", " B "]}  # Namen unverändert, Leerzeichen bleiben
    assert s["readonly"] == {}, "blocked_gateway_macs und permanent_blocked_ssids dürfen nie gesendet werden"
    assert s["home"] == {"home_gateway_macs": []}
    assert s["cats"] == {"port_scan_excluded_categories": ["router"]}


def test_ring_layout_spreads_nodes(ui: dict[str, Any]) -> None:
    r = ui["ring"]
    assert (r["zero"], r["one"], r["n30"], r["n100"]) == (0, 1, 30, 100)
    assert r["minRadius"] >= 200, "Knoten dürfen nicht auf dem Router liegen"
    assert r["minDist30"] >= 80
    assert r["minDist100"] >= 60


def test_free_slot_never_collides(ui: dict[str, Any]) -> None:
    s = ui["slot"]
    assert s["emptyIsOnFirstRing"] == 240
    assert s["minDistA"] >= 125 and s["minDistB"] >= 125
    assert s["distinct"]
    assert s["full"] >= 125, "auch bei 150 Geräten dürfen sich keine zwei Knoten berühren"
    assert s["allOffCenter"]


def test_map_plan_is_a_star(ui: dict[str, Any]) -> None:
    p = ui["plan"]
    assert p["hubA"] == "aa:bb:cc:00:00:01"
    assert p["othersA"] == ["aa:bb:cc:00:00:03", "aa:bb:cc:00:00:02"]  # nach IP
    assert p["edgesA"] == [["aa:bb:cc:00:00:01", "aa:bb:cc:00:00:03", False], ["aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02", True]]
    assert p["hubB"] == "__hub__" and p["hubIsNullB"] is True
    assert p["edgesB"] == ["__hub__", "__hub__"]
    assert p["hubC"] == "aa:bb:cc:00:00:01"  # bei zwei Routern gewinnt die kleinere IP
    assert "aa:bb:cc:00:00:04" in p["othersC"]
    assert p["empty"] == 0


def test_node_appearance(ui: dict[str, Any]) -> None:
    n = ui["nodes"]
    assert n["freshBorder"] == "#e50"  # neu: auffällige Umrandung in eigener Farbe
    assert n["freshWidth"] >= 4 and n["normalBorder"] == "#bbb"
    assert "\nneu" in n["freshLabel"]
    assert n["offOpacity"] < 1 and n["normalOpacity"] == 1
    assert n["offBorder"] == "#aaa" and n["offFont"] == "#666"
    assert n["hubFixed"] == {"x": True, "y": True} and n["normalFixed"] is False
    assert n["hubSize"] > n["normalSize"]
    assert n["shape"] == "circularImage" and n["imageIsDataUri"]
    assert n["longLabel"] <= 26
    assert n["idIsMac"] == "aa:bb:cc:00:00:01"


def test_node_label_is_plain_text(ui: dict[str, Any]) -> None:
    # Gerätenamen aus dem Netz bleiben Text: vis-network zeichnet label auf ein Canvas, nie als HTML
    label = ui["nodes"]["freshLabel"]
    assert label.startswith("<img src=x onerror=alert(") and label.endswith("…\n192.168.178.10\nneu")  # gekürzt, aber unverändert als Text


def test_icons_are_valid_svg_per_category(ui: dict[str, Any]) -> None:
    icons = ui["icons"]
    assert icons["categories"] == ["router", "switch", "server", "pc", "printer", "iot", "phone", "unknown"]
    fills = set()
    for category, svg in icons["svgs"].items():
        root = ET.fromstring(svg)  # muss wohlgeformtes XML sein
        assert root.tag == "{http://www.w3.org/2000/svg}svg", category
        assert root.attrib["viewBox"] == "0 0 64 64"
        assert "@COLOR@" not in svg
        assert "<script" not in svg and "http://www.w3.org/2000/svg" in svg
        fills.add(root.find("{http://www.w3.org/2000/svg}rect").attrib["fill"])
    assert len(fills) == 8, "jede Kategorie braucht eine eigene Farbe"
    assert icons["fallback"] is True
    assert icons["uri"].startswith("data:image/svg+xml;charset=utf-8,%3Csvg")


def test_guard_texts(ui: dict[str, Any]) -> None:
    g = ui["guard"]
    assert g["home"] == "Heimnetz erkannt"
    assert g["ssid"] == "Gesperrtes WLAN" and g["gw"] == "Gesperrtes Netz (Router erkannt)"
    assert g["foreign"] == "Fremdes Netz" and g["unknown"] == "Unbekanntes Netz" and g["nogw"] == "Kein Router erkannt"
    assert g["fallbackBlock"] == "Scan gesperrt"
    assert g["details"] == "WLAN: „Cafe Netz“ · Router: 10.0.0.1 (00:00:5e:00:53:01)"
    assert g["unreadable"] == "WLAN-Name nicht lesbar · Router: 10.0.0.1"
    assert g["ssidKeepsSpaces"] == "WLAN: „ A  B “"


def test_paths_and_helpers(ui: dict[str, Any]) -> None:
    assert ui["paths"]["device"] == "/api/devices/aa:bb:cc:00:00:01"
    assert ui["paths"]["deep"] == "/api/devices/aa:bb:cc:00:00:01/deep-scan"
    assert ui["paths"]["weird"] == "a%2Fb%20c"
    m = ui["misc"]
    assert m["truncate"] == "abcd…" and m["truncateShort"] == "abc"
    assert m["plural"] == ["Geraet", "Geraete"]
    assert m["label"] == "IoT-Gerät" and m["labelUnknown"] == "zzz"
