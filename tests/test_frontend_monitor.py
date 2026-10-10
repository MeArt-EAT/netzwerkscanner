"""Logik der Oberfläche Stufe 2: die reinen Funktionen aus monitor.js (und die Einstellungen aus app.js) in Node.

monitor.js stellt sie über module.exports bereit, wenn es kein document gibt (wie app.js). Ohne node im PATH werden
die Tests übersprungen. Es geht kein Paket ins Netz; Node bekommt nur Beispieldaten. TZ=UTC macht die Zeitachsen
reproduzierbar.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from netscan import config
from netscan.core import models

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "netscan" / "web" / "static"
MONITOR_JS = STATIC / "monitor.js"
APP_JS = STATIC / "app.js"

# Node-Skript (nur ASCII, damit keine Kodierung der Kommandozeile stört). Gibt ein JSON-Objekt aus.
NODE_SCRIPT = r"""
const mon = require(process.argv[2]);
const app = require(process.argv[3]);
const out = {};
const T = (iso) => Date.parse(iso);
out.exports = Object.keys(mon).sort();
out.consts = {
  statusLabels: mon.TARGET_STATUS_LABELS, statusOrder: mon.STATUS_ORDER, checkKinds: mon.CHECK_KINDS, ruleLabels: mon.ALERT_RULE_LABELS,
  rules: mon.ALERT_RULES, severity: mon.SEVERITY_LABELS, monitorStates: Object.keys(mon.MONITOR_STATE_LABELS),
  reach: mon.REACH_METHODS.map((m) => m[0]), ranges: mon.RANGES.map((r) => r[0]), alertStates: mon.ALERT_STATES.map((s) => s[0]),
  dbWarn: mon.DB_WARN_BYTES, maxChecks: mon.MAX_CHECKS_PER_TARGET, targetLimits: mon.TARGET_LIMITS,
  privacy: mon.PRIVACY_HINT, firewall: mon.FIREWALL_HINT,
};

// Pfade
out.paths = {
  target: mon.MAPI.target("aa:bb:cc:00:00:01"), sugg: mon.MAPI.suggestions("aa:bb:cc:00:00:01"), checks: mon.MAPI.targetChecks("aa:bb:cc:00:00:01"),
  check: mon.MAPI.check(5), checkBad: mon.MAPI.check("5; DROP"), checkNeg: mon.MAPI.check(-1), ack: mon.MAPI.ack(12), weird: mon.MAPI.target("a/b c"),
};

// Formatierung
out.pct = [mon.formatPercent(99.96), mon.formatPercent(100), mon.formatPercent(99.97), mon.formatPercent(57.25), mon.formatPercent(0),
  mon.formatPercent(null), mon.formatPercent(-5), mon.formatPercent(150), mon.formatPercent(NaN), mon.formatPercent("99")];
out.avail = {
  obj: mon.formatAvailability({ up_pct: 99.5, samples: 100, up: 99 }), none: mon.formatAvailability({ up_pct: null, samples: 0, up: 0 }),
  missing: mon.formatAvailability(undefined), titleEmpty: mon.availabilityTitle({ up_pct: null, samples: 0, up: 0 }),
  title: mon.availabilityTitle({ up_pct: 50, samples: 1440, up: 720 }), titleBad: mon.availabilityTitle("x"),
};
const now = T("2026-10-10T12:00:00Z");
const ago = (s) => new Date(now - s * 1000).toISOString();
out.since = [mon.formatSince(ago(5), now), mon.formatSince(ago(45), now), mon.formatSince(ago(12 * 60 + 30), now), mon.formatSince(ago(3 * 3600), now),
  mon.formatSince(ago(3 * 3600 + 5 * 60), now), mon.formatSince(ago(86400), now), mon.formatSince(ago(2 * 86400 + 4 * 3600 + 59), now),
  mon.formatSince(ago(-600), now), mon.formatSince("kein Datum", now), mon.formatSince(null, now), mon.formatSince("2026-10-10T11:00:00+00:00", now)];
out.bytes = [mon.formatBytes(0), mon.formatBytes(1023), mon.formatBytes(1536), mon.formatBytes(12.3 * 1024 * 1024), mon.formatBytes(100 * 1024 * 1024),
  mon.formatBytes(1.5 * 1024 * 1024 * 1024), mon.formatBytes(-1), mon.formatBytes("x"), mon.formatBytes(null)];
out.rtt = [mon.formatRtt(0.5), mon.formatRtt(2.34), mon.formatRtt(12.6), mon.formatRtt(1234), mon.formatRtt(null), mon.formatRtt(-1)];
out.misc = {
  interval: [mon.formatInterval(60), mon.formatInterval(90), mon.formatInterval(300), mon.formatInterval(null)],
  cycle: [mon.formatCycleMs(350.4), mon.formatCycleMs(2500), mon.formatCycleMs(null)],
  bucket: [mon.formatBucket(30), mon.formatBucket(216), mon.formatBucket(3600), mon.formatBucket(86400), mon.formatBucket(0)],
  method: [mon.methodLabel("ping"), mon.methodLabel("tcp:445"), mon.methodLabel("http:80"), mon.methodLabel(""), mon.methodLabel("<b>")],
  toMs: [mon.toMs(1760000000), mon.toMs(1760000000000), mon.toMs(null), mon.toMs("1")],
  day: [mon.dayLabel("2026-10-09"), mon.dayTitle("2026-10-10"), mon.dayLabel("kaputt"), mon.dayLabel(null)],
  clock: mon.formatClock("2026-10-10T14:05:09+00:00"), clockBad: mon.formatClock("x"), dateTime: mon.formatDateTime(T("2026-10-10T14:05:00Z")),
  count: [mon.alertCountText(0), mon.alertCountText(5), mon.alertCountText(150), mon.alertCountText(null)],
};

// Zeitachse
const hi = T("2026-10-11T10:20:00Z");
out.ticks = {
  h24: mon.timeTicks(T("2026-10-10T10:20:00Z"), hi, "24h").map((x) => mon.tickLabel(x, "24h")),
  d7: mon.timeTicks(T("2026-10-04T10:20:00Z"), hi, "7d").map((x) => mon.tickLabel(x, "7d")),
  d30: mon.timeTicks(T("2026-09-11T10:20:00Z"), hi, "30d").map((x) => mon.tickLabel(x, "30d")),
  y1: mon.timeTicks(T("2025-10-11T10:20:00Z"), hi, "1y").map((x) => mon.tickLabel(x, "1y")),
  empty: mon.timeTicks(hi, hi, "24h").length, bad: mon.timeTicks(null, hi, "24h").length,
  capped: mon.timeTicks(0, T("2026-10-11T00:00:00Z"), "24h").length,
};

// Zustaende
out.states = Object.fromEntries(["stopped", "off", "idle", "running", "paused"].map((s) => [s, mon.monitorStateInfo({ state: s, reason: "" })]));
out.stateReason = mon.monitorStateInfo({ state: "paused", reason: "Gesperrt: Schule" });
out.stateNull = mon.monitorStateInfo(null);
out.stateBogus = mon.monitorStateInfo({ state: "kaputt" });
out.run = {
  none: mon.runButtonState(null, 3), stopped: mon.runButtonState({ state: "stopped" }, 3), off: mon.runButtonState({ state: "off" }, 3),
  idle: mon.runButtonState({ state: "idle" }, 0), running: mon.runButtonState({ state: "running" }, 2), paused: mon.runButtonState({ state: "paused" }, 1),
};
out.db = {
  small: mon.dbInfo(50 * 1024 * 1024), edge: mon.dbInfo(100 * 1024 * 1024), flag: mon.dbInfo(1024, true), flagFalseBig: mon.dbInfo(200 * 1024 * 1024, false),
  none: mon.dbInfo(null), bad: mon.dbInfo("x"),
};
out.labels = [mon.targetStatusLabel("degraded"), mon.targetStatusLabel("paused"), mon.targetStatusLabel("zzz"), mon.checkLabel("smb", 445), mon.checkLabel("https", 5001)];
const tl = [{ mac: "a", status: "online" }, { mac: "b", status: "online" }, { mac: "c", status: "degraded" }, { mac: "d", status: "paused" },
  { mac: "e", status: "kaputt" }, null, "x", { mac: "f", status: "offline" }];
out.counts = mon.countStatuses(tl);
out.segments = mon.statusSegments({ online: 2, degraded: 1, offline: -3, paused: "x" });

// Antwortzeit-Verlauf mit Luecken
const pts = [
  { t: 3000, rtt_avg: 3, rtt_min: 2, rtt_max: 4, up_pct: 100, n: 60 },
  { t: 1000, rtt_avg: 2, rtt_min: 1, rtt_max: 5, up_pct: 100, n: 60 },
  { t: 2000, rtt_avg: null, rtt_min: null, rtt_max: null, up_pct: null, n: 0 },
  { t: 4000, rtt_avg: 9, rtt_min: 9, rtt_max: 9, up_pct: null, n: 0 },
  { t: 5000, rtt_avg: null, rtt_min: null, rtt_max: null, up_pct: 0, n: 30 },
  { t: 6000, rtt_avg: 4, rtt_min: 6, rtt_max: 3, up_pct: 90, n: 10 },
  { t: 7000, rtt_avg: 5, rtt_min: null, rtt_max: null, up_pct: 100, n: 10 },
  { t: "x", rtt_avg: 1, n: 5 }, null, "kaputt", { t: 8000, rtt_avg: -1, n: 2, up_pct: 100 },
];
const sd = mon.seriesData(pts);
out.series = {
  x: sd.avg.map((p) => p.x), avg: sd.avg.map((p) => p.y), min: sd.min.map((p) => p.y), max: sd.max.map((p) => p.y), down: sd.down.map((p) => p.y),
  radius: sd.radius, gaps: sd.gaps, downs: sd.downs, samples: sd.samples, empty: mon.seriesData(null).samples, emptyLen: mon.seriesData("x").avg.length,
  tipGap: mon.seriesTooltip(sd.info[1]), tipOk: mon.seriesTooltip(sd.info[0]), tipDown: mon.seriesTooltip(sd.info[4]), tipNull: mon.seriesTooltip(null),
  note: mon.seriesNote(300, sd), noteEmpty: mon.seriesNote(null, null),
};

// Trend und Haeufigkeit
out.trend = mon.trendData([{ day: "2026-10-10", up_pct: 99.5, n: 1440 }, { day: "2026-10-09", up_pct: 80, n: 0 }, { day: 5 }, null,
  { day: "2026-10-08", up_pct: 120, n: 10 }, { day: "2026-10-07", up_pct: "x", n: 5 }]);
out.trendBad = mon.trendData("kaputt");
out.freq = mon.frequencyData([{ day: "2026-10-10", device_offline: 2, service_down: 1, rtt_high: -4, new_device: "3", new_port: 1.6, extra: 9 },
  { day: "2026-10-09" }, { nope: 1 }]);

// Hinweise
out.hints = {
  phone: mon.privacyHint({ category: "phone", mac_random: false }), random: mon.privacyHint({ category: "pc", mac_random: true }),
  pc: mon.privacyHint({ category: "pc", mac_random: false }), none: mon.privacyHint(null), randomString: mon.privacyHint({ mac_random: "true" }),
  selfPorts: mon.firewallHint({ is_self: true, ports: [{ port: 445 }] }), selfNoPorts: mon.firewallHint({ is_self: true, ports: [] }),
  otherPorts: mon.firewallHint({ is_self: false, ports: [{ port: 445 }] }), selfBad: mon.firewallHint({ is_self: true, ports: "x" }),
};

// Dienstvorschlaege
const sugg = [
  { kind: "smb", port: 445, path: "/", label: "SMB-Freigabe 445", reason: "Port 445 offen", active: false },
  { kind: "http", port: 5000, path: "/", label: "HTTP 5000", reason: "Weboberflaeche", active: true },
  { kind: "tcp", port: 139, path: "/", label: "TCP 139", reason: "NetBIOS", active: false },
  { kind: "ssh", port: 22, label: "SSH 22", reason: "SSH" },
  { kind: "gopher", port: 70 }, { kind: "http", port: 0 }, null, { kind: "http", port: "80" },
];
const checks = [{ id: 7, target_id: 1, kind: "http", port: 5000, path: "/", enabled: false, status: "unknown", label: "HTTP 5000" },
  { id: 8, target_id: 1, kind: "https", port: 443, path: "/", enabled: true, status: "up", label: "HTTPS 443" }];
const opts = mon.mergeCheckOptions(sugg, checks);
out.options = opts.map((o) => [o.key, o.check ? o.check.id : null, o.suggested, o.reason, o.label, o.path]);
out.selection = mon.defaultSelection(opts);
out.selectionNew = mon.defaultSelection(mon.mergeCheckOptions(sugg, []));
const many = []; for (let p = 1; p <= 12; p++) many.push({ kind: "http", port: 8000 + p });
out.selectionCap = mon.defaultSelection(mon.mergeCheckOptions(many, [])).length;
out.chips = {
  up: mon.checkChip({ kind: "smb", port: 445, label: "SMB-Freigabe 445", enabled: true, status: "up", last_detail: "Antwort", last_rtt_ms: 3.2, availability: { "24h": { up_pct: 99.5, samples: 10, up: 9 } } }),
  down: mon.checkChip({ kind: "http", port: 80, enabled: true, status: "down", last_detail: "HTTP 503" }),
  off: mon.checkChip({ kind: "ssh", port: 22, enabled: false, status: "up" }),
  odd: mon.checkChip({ kind: "ssh", port: 22, status: "kaputt" }), none: mon.checkChip(null),
};

// Ziel-Einstellungen
const target = { mac: "a", method: "auto", tcp_port: null, offline_after_min: 10, rtt_threshold_ms: 50 };
const form = (o) => Object.assign({ method: "auto", tcp_port: "", offline_after_min: "10", rtt_threshold_ms: "50" }, o || {});
out.patch = {
  same: mon.buildTargetPatch(target, form()),
  method: mon.buildTargetPatch(target, form({ method: "tcp", tcp_port: " 8080 " })),
  reset: mon.buildTargetPatch(target, form({ offline_after_min: "", rtt_threshold_ms: "  " })),
  comma: mon.buildTargetPatch(target, form({ rtt_threshold_ms: "12,5" })),
  badPort: mon.buildTargetPatch(target, form({ tcp_port: "0" })),
  badOffline: mon.buildTargetPatch(target, form({ offline_after_min: "1,5" })),
  badText: mon.buildTargetPatch(target, form({ rtt_threshold_ms: "schnell", offline_after_min: "99999" })),
  badMethod: mon.buildTargetPatch(target, form({ method: "icmp" })),
  nullTarget: mon.buildTargetPatch(null, form({ offline_after_min: "", rtt_threshold_ms: "" })),
};
out.parse = [mon.parseOptionalNumber("", 1, 10, true), mon.parseOptionalNumber("5", 1, 10, true), mon.parseOptionalNumber("-5", 1, 10, true),
  mon.parseOptionalNumber("1e3", 1, 10000, false), mon.parseOptionalNumber("2.5", 1, 10, false)];

// Live-Aktualisierung (monitor.cycle)
const before = [
  { mac: "a", status: "online", status_since: "2026-10-10T08:00:00+00:00", last_rtt_ms: 2, last_detail: "", pause_reason: "",
    checks: [{ id: 1, status: "up", status_since: "2026-10-10T08:00:00+00:00", last_rtt_ms: 3, last_detail: "HTTP 200" }, { id: 2, status: "up" }] },
  { mac: "b", status: "online", status_since: "2026-10-10T09:00:00+00:00", last_rtt_ms: 4, last_detail: "", checks: [] },
  { mac: "c", status: "online", status_since: "2026-10-10T09:00:00+00:00", last_rtt_ms: 1, checks: [] },
];
const cycle = { ts: "2026-10-10T12:00:00+00:00", targets: [
  { mac: "a", status: "degraded", rtt_ms: 5.5, detail: "", checks: [{ id: 1, status: "down", rtt_ms: null, detail: "HTTP 503" }, { id: 99, status: "up" }] },
  { mac: "b", status: "online", rtt_ms: 6, detail: "ok" },
  { mac: "c", status: "paused", rtt_ms: null, detail: "Gesperrt: Schule" },
  { mac: "zz", status: "offline" }, null, { mac: "b", status: "kaputt" },
] };
const after = mon.applyCycle(before, cycle);
out.cycle = after;
out.cycleBefore = before[0].status;
out.cycleJunk = mon.applyCycle(before, null).map((t) => t.status);
out.cycleNotArray = mon.applyCycle("x", cycle);

// Alerts
const al = (id, opened, extra) => Object.assign({ id: id, rule: "device_offline", severity: "warning", title: "T" + id, opened: opened, closed: null, acknowledged: null }, extra || {});
const list = [al(3, "2026-10-10T10:00:00+00:00"), al(1, "2026-10-09T10:00:00+00:00")];
out.alerts = {
  insert: mon.mergeAlert(list, al(5, "2026-10-10T11:00:00+00:00"), "active").map((a) => a.id),
  middle: mon.mergeAlert(list, al(2, "2026-10-09T12:00:00+00:00"), "all").map((a) => a.id),
  closeActive: mon.mergeAlert(list, al(3, "2026-10-10T10:00:00+00:00", { closed: "2026-10-10T11:00:00+00:00" }), "active").map((a) => a.id),
  closeAll: mon.mergeAlert(list, al(3, "2026-10-10T10:00:00+00:00", { closed: "2026-10-10T11:00:00+00:00" }), "all").map((a) => [a.id, a.closed]),
  ackedUnacked: mon.mergeAlert(list, al(1, "2026-10-09T10:00:00+00:00", { acknowledged: "2026-10-10T11:00:00+00:00" }), "unacked").map((a) => a.id),
  junk: mon.mergeAlert(list, { id: "x" }, "all").map((a) => a.id),
  limit: mon.mergeAlert(list, al(9, "2026-10-11T00:00:00+00:00"), "all", 2).map((a) => a.id),
  matches: [mon.alertMatches(al(1, "x"), "active"), mon.alertMatches(al(1, "x", { closed: "y" }), "active"), mon.alertMatches(al(1, "x", { acknowledged: "y" }), "unacked"), mon.alertMatches(null, "all")],
};
out.toast = {
  one: mon.alertToast([al(1, "x", { severity: "critical", title: "Router offline" })]),
  info: mon.alertToast([al(1, "x", { severity: "info", title: "" , rule: "rtt_high" })]),
  many: mon.alertToast([al(1, "x", { severity: "info" }), al(2, "x", { severity: "warning" }), null]),
  none: mon.alertToast([]),
};
out.sorted = mon.sortTargets([{ mac: "x2", device: { ip: "192.168.178.10", display_name: "B" } }, { mac: "x1", device: { ip: "192.168.178.9", display_name: "A" } },
  { mac: "x3", device: null }, null, { nomac: 1 }]).map((t) => t.mac);

// Einstellungen (app.js): neue Felder im Diff
const orig = { rate_pps: 200, port_timeout_ms: 700, blocked_ssids_extra: [], home_gateway_macs: [], port_scan_excluded_categories: [], ask_before_foreign_scan: false,
  monitor_enabled: true, monitor_interval_s: 60, monitor_timeout_ms: 1000, alert_offline_minutes: 5, alert_service_minutes: 2, alert_rtt_minutes: 5,
  alert_new_device: true, alert_new_port: true, blocked_gateway_macs: ["zz"] };
const work = (o) => Object.assign(JSON.parse(JSON.stringify(orig)), o || {});
out.settings = {
  none: app.diffSettings(orig, work()),
  changed: app.diffSettings(orig, work({ monitor_interval_s: 120, alert_new_port: false, monitor_enabled: false })),
  alerts: app.diffSettings(orig, work({ alert_offline_minutes: 10, alert_service_minutes: 3, alert_rtt_minutes: 15, alert_new_device: false, monitor_timeout_ms: 1500 })),
  readonly: app.diffSettings(orig, work({ blocked_gateway_macs: [] })),
  editable: app.SETTINGS_EDITABLE, numbers: app.MONITOR_NUMBER_SETTINGS, bools: app.MONITOR_BOOL_SETTINGS, tabs: app.TABS,
  parse: [app.parseSettingInt("60", 10, 3600), app.parseSettingInt(" 10 ", 10, 3600), app.parseSettingInt("9", 10, 3600), app.parseSettingInt("3601", 10, 3600),
    app.parseSettingInt("1.5", 1, 10), app.parseSettingInt("", 1, 10), app.parseSettingInt("abc", 1, 10), app.parseSettingInt("-1", -5, 10)],
};

process.stdout.write(JSON.stringify(out));
"""


@pytest.fixture(scope="module")
def ui(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node nicht im PATH")
    script = tmp_path_factory.mktemp("frontend_monitor") / "check.js"
    script.write_text(NODE_SCRIPT, encoding="utf-8")
    env = dict(os.environ, TZ="UTC", NODE_OPTIONS="")
    result = subprocess.run(
        [node, str(script), str(MONITOR_JS), str(APP_JS)], capture_output=True, text=True, encoding="utf-8", timeout=60, env=env
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


# --- Modul und Vertrag ------------------------------------------------------------------------------


def test_module_loads_without_dom(ui: dict[str, Any]) -> None:
    for name in ("formatAvailability", "formatSince", "formatBytes", "seriesData", "frequencyData", "trendData", "privacyHint",
                 "firewallHint", "buildTargetPatch", "applyCycle", "mergeAlert", "monitorStateInfo", "dbInfo", "timeTicks"):
        assert name in ui["exports"], name


def test_labels_match_models(ui: dict[str, Any]) -> None:
    c = ui["consts"]
    assert c["statusLabels"] == models.TARGET_STATUS_LABELS
    assert set(c["statusOrder"]) == set(models.TARGET_STATUS_LABELS)
    assert c["checkKinds"] == list(models.CHECK_KINDS)
    assert c["ruleLabels"] == models.ALERT_RULE_LABELS
    assert c["rules"] == list(models.ALERT_RULES)
    assert c["severity"] == models.SEVERITY_LABELS
    assert c["reach"] == list(models.REACH_METHODS)
    assert set(c["monitorStates"]) == {"stopped", "off", "idle", "running", "paused"}  # BAUPLAN §19
    assert c["ranges"] == ["24h", "7d", "30d", "1y"]
    assert c["alertStates"] == ["active", "unacked", "all"]


def test_limits_match_config(ui: dict[str, Any]) -> None:
    c = ui["consts"]
    assert c["dbWarn"] == config.DB_WARN_BYTES
    assert c["maxChecks"] == config.MAX_CHECKS_PER_TARGET
    assert {k: tuple(v) for k, v in c["targetLimits"].items()} == config.TARGET_LIMITS


def test_hint_texts_are_verbatim(ui: dict[str, Any]) -> None:
    c = ui["consts"]
    assert c["privacy"] == "Die Überwachung macht sichtbar, wann diese Person zu Hause ist. Alle im Haushalt sollten davon wissen."
    assert c["firewall"] == (
        "Eigener PC: lokal geprüft – die Windows-Firewall wird dabei nicht berücksichtigt; "
        "von anderen Geräten aus kann der Port gesperrt sein."
    )


def test_paths(ui: dict[str, Any]) -> None:
    p = ui["paths"]
    assert p["target"] == "/api/monitor/targets/aa:bb:cc:00:00:01"
    assert p["sugg"] == "/api/monitor/targets/aa:bb:cc:00:00:01/suggestions"
    assert p["checks"] == "/api/monitor/targets/aa:bb:cc:00:00:01/checks"
    assert p["check"] == "/api/monitor/checks/5"
    assert p["checkBad"] == "/api/monitor/checks/0" and p["checkNeg"] == "/api/monitor/checks/0"  # Unsinn nie in den Pfad
    assert p["ack"] == "/api/alerts/12/ack"
    assert p["weird"] == "/api/monitor/targets/a%2Fb%20c"


# --- Formatierung -----------------------------------------------------------------------------------


def test_availability_format(ui: dict[str, Any]) -> None:
    assert ui["pct"] == ["99,9 %", "100 %", "99,9 %", "57,2 %", "0 %", "–", "0 %", "100 %", "–", "–"]
    a = ui["avail"]
    assert a["obj"] == "99,5 %" and a["none"] == "–" and a["missing"] == "–"
    assert a["titleEmpty"] == "Noch keine Messwerte in diesem Zeitraum."
    assert a["title"] == "720 von 1.440 Messungen erfolgreich"
    assert a["titleBad"] == ""


def test_since_format(ui: dict[str, Any]) -> None:
    assert ui["since"] == [
        "seit wenigen Sekunden", "seit 45 s", "seit 12 min", "seit 3 h", "seit 3 h 5 min", "seit 1 Tag", "seit 2 Tagen 4 h",
        "seit wenigen Sekunden",  # Uhr des Servers etwas voraus: nie negativ
        "", "", "seit 1 h",
    ]


def test_bytes_and_rtt_format(ui: dict[str, Any]) -> None:
    assert ui["bytes"] == ["0 B", "1023 B", "1,5 KB", "12,3 MB", "100 MB", "1,5 GB", "–", "–", "–"]
    assert ui["rtt"] == ["0,5 ms", "2,3 ms", "13 ms", "1.234 ms", "–", "–"]


def test_small_formats(ui: dict[str, Any]) -> None:
    m = ui["misc"]
    assert m["interval"] == ["1 min", "90 s", "5 min", ""]
    assert m["cycle"] == ["350 ms", "2,5 s", ""]
    assert m["bucket"] == ["30 s", "3,6 min", "1 h", "1 Tag", ""]
    assert m["method"] == ["Ping", "TCP 445", "HTTP 80", "", ""]
    assert m["toMs"] == [1760000000000, 1760000000000, None, None]
    assert m["day"] == ["09.10.", "Sa 10.10.2026", "kaputt", ""]
    assert m["clock"] == "14:05:09" and m["clockBad"] == "" and m["dateTime"] == "10.10.2026 14:05"
    assert m["count"] == ["", "5", "99+", ""]


def test_time_axis_ticks_and_labels(ui: dict[str, Any]) -> None:
    t = ui["ticks"]
    assert t["h24"] == ["12:00", "15:00", "18:00", "21:00", "11.10.", "03:00", "06:00", "09:00"]  # Mitternacht zeigt das Datum
    assert t["d7"] == ["Mo 05.10.", "Di 06.10.", "Mi 07.10.", "Do 08.10.", "Fr 09.10.", "Sa 10.10.", "So 11.10."]
    assert t["d30"] == ["12.09.", "17.09.", "22.09.", "27.09.", "02.10.", "07.10."]
    assert t["y1"][0] == "Nov 2025" and t["y1"][-1] == "Okt 2026" and "Mär 2026" in t["y1"] and len(t["y1"]) == 12
    assert t["empty"] == 0 and t["bad"] == 0
    assert t["capped"] == 60, "nie mehr als 60 Ticks, auch bei Unsinn"


# --- Zustände und Beschriftungen --------------------------------------------------------------------------


def test_monitor_state_texts(ui: dict[str, Any]) -> None:
    s = ui["states"]
    assert {k: v["label"] for k, v in s.items()} == {
        "stopped": "angehalten", "off": "ausgeschaltet", "idle": "bereit", "running": "läuft", "paused": "pausiert"
    }
    assert s["running"]["tone"] == "ok" and s["paused"]["tone"] == "warn" and s["off"]["tone"] == "muted"
    assert s["off"]["reason"] == "Die Überwachung ist in den Einstellungen ausgeschaltet."
    assert s["idle"]["reason"] == "Keine Geräte zur Überwachung ausgewählt."
    assert s["running"]["reason"] == ""
    assert ui["stateReason"]["reason"] == "Gesperrt: Schule"  # Grund vom Server hat Vorrang
    assert ui["stateNull"]["label"] == "unbekannt" and ui["stateBogus"]["state"] == ""


def test_run_button_state(ui: dict[str, Any]) -> None:
    r = ui["run"]
    assert r["none"]["disabled"] and r["stopped"]["disabled"] and r["off"]["disabled"] and r["idle"]["disabled"]
    assert "Einstellungen" in r["off"]["title"]
    assert r["running"]["disabled"] is False and r["paused"]["disabled"] is False  # pausiert: Wächter prüft beim Durchlauf neu


def test_db_size_warning(ui: dict[str, Any]) -> None:
    d = ui["db"]
    assert d["small"] == {"text": "Datenbank: 50 MB", "warn": False, "title": d["small"]["title"]}
    assert d["edge"]["warn"] is True and d["edge"]["text"] == "Datenbank: 100 MB – größer als 100 MB"
    assert d["flag"]["warn"] is True, "db_warn vom Server zählt"
    assert d["flagFalseBig"]["warn"] is True, "ab 100 MB warnt die Oberfläche in jedem Fall"
    assert d["none"] is None and d["bad"] is None


def test_status_labels_and_counts(ui: dict[str, Any]) -> None:
    assert ui["labels"] == ["gestört", "pausiert", "unbekannt", "SMB-Freigabe 445", "HTTPS 5001"]
    assert ui["counts"] == {"online": 2, "degraded": 1, "offline": 1, "paused": 1, "unknown": 1}
    assert ui["segments"] == [
        {"key": "online", "label": "online", "value": 2},
        {"key": "degraded", "label": "gestört", "value": 1},
        {"key": "offline", "label": "offline", "value": 0},
        {"key": "paused", "label": "pausiert", "value": 0},
        {"key": "unknown", "label": "unbekannt", "value": 0},
    ]


# --- Diagramm-Daten -----------------------------------------------------------------------------------


def test_series_keeps_gaps_visible(ui: dict[str, Any]) -> None:
    s = ui["series"]
    assert s["x"] == [1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000]  # sortiert, Unsinn verworfen
    # n = 0 ⇒ null (auch wenn dort Werte stehen), nicht erreichbar ⇒ null, negative Antwortzeit ⇒ null
    assert s["avg"] == [2, None, 3, None, None, 4, 5, None]
    assert s["min"] == [1, None, 2, None, None, 3, 5, None]  # min/max vertauscht ⇒ geordnet; fehlend ⇒ Mittelwert
    assert s["max"] == [5, None, 4, None, None, 6, 5, None]
    assert s["down"] == [None, None, None, None, 0, 0, None, None]  # Ausfälle als Marke auf der Nulllinie
    assert s["radius"] == [2.5, 0, 2.5, 0, 0, 0, 0, 0]  # einzelne Werte zwischen Lücken als Punkt
    assert s["gaps"] == 2 and s["downs"] == 2 and s["samples"] == 60 + 60 + 30 + 10 + 10 + 2
    assert s["empty"] == 0 and s["emptyLen"] == 0
    assert s["tipGap"] == ["Keine Messwerte (Lücke)"]
    assert s["tipOk"] == ["Antwortzeit Ø 2 ms (min 1 ms, max 5 ms)", "Erreichbar: 100 % von 60 Messungen"]
    assert s["tipDown"] == ["Keine Antwortzeit (nicht erreichbar)", "Erreichbar: 0 % von 30 Messungen"]
    assert s["tipNull"] == []
    assert s["note"].startswith("Ein Punkt fasst 5 min zusammen") and "2 Abschnitte ohne Messwerte" in s["note"]
    assert s["noteEmpty"] == ""


def test_trend_bars(ui: dict[str, Any]) -> None:
    t = ui["trend"]
    assert t["labels"] == ["07.10.", "08.10.", "09.10.", "10.10."]
    assert t["titles"][-1] == "Sa 10.10.2026"
    assert t["values"] == [None, 100, None, 99.5]  # Text ⇒ leer, über 100 ⇒ 100, n = 0 ⇒ leer
    assert t["n"] == [5, 10, 0, 1440]
    assert ui["trendBad"] == {"labels": [], "titles": [], "values": [], "n": []}


def test_frequency_datasets(ui: dict[str, Any]) -> None:
    f = ui["freq"]
    assert f["labels"] == ["09.10.", "10.10."]
    assert [d["rule"] for d in f["datasets"]] == list(models.ALERT_RULES)
    assert [d["label"] for d in f["datasets"]] == [models.ALERT_RULE_LABELS[r] for r in models.ALERT_RULES]
    data = {d["rule"]: d["data"] for d in f["datasets"]}
    assert data == {"device_offline": [0, 2], "service_down": [0, 1], "rtt_high": [0, 0], "new_device": [0, 0], "new_port": [0, 2]}
    assert f["total"] == [0, 5]


# --- Hinweise, Dienste, Ziel-Einstellungen ----------------------------------------------------------------


def test_privacy_and_firewall_hint_decision(ui: dict[str, Any]) -> None:
    h = ui["hints"]
    privacy = ui["consts"]["privacy"]
    assert h["phone"] == privacy and h["random"] == privacy
    assert h["pc"] == "" and h["none"] == "" and h["randomString"] == ""
    assert h["selfPorts"] == ui["consts"]["firewall"]
    assert h["selfNoPorts"] == "" and h["otherPorts"] == "" and h["selfBad"] == ""


def test_check_options_merge_suggestions_and_checks(ui: dict[str, Any]) -> None:
    assert ui["options"] == [
        ["ssh:22", None, True, "SSH", "SSH 22", "/"],
        ["tcp:139", None, True, "NetBIOS", "TCP 139", "/"],
        ["https:443", 8, False, "", "HTTPS 443", "/"],
        ["smb:445", None, True, "Port 445 offen", "SMB-Freigabe 445", "/"],
        ["http:5000", 7, True, "Weboberflaeche", "HTTP 5000", "/"],
    ]
    # Vorauswahl nur für neue Ziele sinnvoll: wichtige Dienste, keine reinen TCP-Ports, keine schon vorhandenen
    assert ui["selection"] == ["ssh:22", "smb:445"]
    assert ui["selectionNew"] == ["ssh:22", "smb:445", "http:5000"]
    assert ui["selectionCap"] == 8


def test_check_chips(ui: dict[str, Any]) -> None:
    c = ui["chips"]
    assert c["up"]["tone"] == "up" and c["up"]["symbol"] == "✓" and c["up"]["text"] == "SMB-Freigabe 445"
    assert c["up"]["title"] == "SMB-Freigabe 445: läuft · Antwort · 3,2 ms · 24 h: 99,5 %"
    assert c["down"] == {"text": "HTTP 80", "tone": "down", "symbol": "✗", "title": "HTTP 80: ausgefallen · HTTP 503"}
    assert c["off"]["tone"] == "off" and c["off"]["title"] == "SSH 22: abgeschaltet"
    assert c["odd"]["tone"] == "unknown" and c["none"] is None


def test_target_patch(ui: dict[str, Any]) -> None:
    p = ui["patch"]
    assert p["same"] == {"patch": {}, "errors": []}
    assert p["method"] == {"patch": {"method": "tcp", "tcp_port": 8080}, "errors": []}
    assert p["reset"] == {"patch": {"offline_after_min": None, "rtt_threshold_ms": None}, "errors": []}  # leer = null
    assert p["comma"] == {"patch": {"rtt_threshold_ms": 12.5}, "errors": []}
    assert p["badPort"]["patch"] == {} and "TCP-Port" in p["badPort"]["errors"][0] and "65.535" in p["badPort"]["errors"][0]
    assert p["badOffline"]["errors"] and "ganze Zahl" in p["badOffline"]["errors"][0]
    assert len(p["badText"]["errors"]) == 2
    assert p["badMethod"]["patch"] == {}  # Unsinn ⇒ auto, wie bisher
    assert p["nullTarget"] == {"patch": {}, "errors": []}
    assert ui["parse"] == [{"value": None}, {"value": 5}, {"error": True}, {"error": True}, {"value": 2.5}]


def test_cycle_event_updates_targets(ui: dict[str, Any]) -> None:
    a, b, c = ui["cycle"]
    assert a["status"] == "degraded" and a["status_label"] == "gestört" and a["status_since"] == "2026-10-10T12:00:00+00:00"
    assert a["last_rtt_ms"] == 5.5 and a["last_check"] == "2026-10-10T12:00:00+00:00"
    assert a["checks"][0] == {"id": 1, "status": "down", "status_since": "2026-10-10T12:00:00+00:00", "last_rtt_ms": None, "last_detail": "HTTP 503"}
    assert a["checks"][1] == {"id": 2, "status": "up"}  # nicht im Ereignis ⇒ unverändert
    assert b["status"] == "online" and b["status_since"] == "2026-10-10T09:00:00+00:00", "gleicher Zustand behält „seit“"
    assert b["last_detail"] == "ok" and b["last_rtt_ms"] == 6
    assert c["status"] == "paused" and c["pause_reason"] == "Gesperrt: Schule" and c["last_rtt_ms"] is None
    assert ui["cycleBefore"] == "online", "die alten Objekte bleiben unverändert"
    assert ui["cycleJunk"] == ["online", "online", "online"]
    assert ui["cycleNotArray"] == []


def test_alert_list_merge(ui: dict[str, Any]) -> None:
    a = ui["alerts"]
    assert a["insert"] == [5, 3, 1]  # neueste zuerst
    assert a["middle"] == [3, 2, 1]
    assert a["closeActive"] == [1], "beendete Alerts verschwinden aus „aktiv“"
    assert a["closeAll"] == [[3, "2026-10-10T11:00:00+00:00"], [1, None]]
    assert a["ackedUnacked"] == [3]
    assert a["junk"] == [3, 1]
    assert a["limit"] == [9, 3]
    assert a["matches"] == [True, False, False, False]


def test_alert_toast(ui: dict[str, Any]) -> None:
    t = ui["toast"]
    assert t["one"] == {"tone": "error", "text": "Alert (kritisch): Router offline"}
    assert t["info"] == {"tone": "info", "text": "Alert (Hinweis): Antwortzeit hoch"}
    assert t["many"] == {"tone": "warn", "text": "2 neue Alerts – siehe Reiter „Alerts“."}
    assert t["none"] is None


def test_targets_sorted_by_ip(ui: dict[str, Any]) -> None:
    assert ui["sorted"] == ["x1", "x2", "x3"]


# --- Einstellungen (app.js) ------------------------------------------------------------------------------


def test_settings_diff_with_monitor_fields(ui: dict[str, Any]) -> None:
    s = ui["settings"]
    assert s["none"] == {}
    assert s["changed"] == {"monitor_enabled": False, "monitor_interval_s": 120, "alert_new_port": False}
    assert s["alerts"] == {
        "monitor_timeout_ms": 1500, "alert_offline_minutes": 10, "alert_service_minutes": 3, "alert_rtt_minutes": 15, "alert_new_device": False
    }
    assert s["readonly"] == {}


def test_settings_fields_match_config(ui: dict[str, Any]) -> None:
    s = ui["settings"]
    stage2 = {"monitor_enabled", "monitor_interval_s", "monitor_timeout_ms", "alert_offline_minutes", "alert_service_minutes",
              "alert_rtt_minutes", "alert_new_device", "alert_new_port"}
    assert stage2 <= set(s["editable"])
    assert set(s["editable"]) <= set(config.Settings().to_dict())
    numbers = {row[0]: (row[3], row[4]) for row in s["numbers"]}
    assert set(numbers) | {row[0] for row in s["bools"]} == stage2
    for key, (lo, hi) in numbers.items():
        assert config.SETTING_LIMITS[key] == (lo, hi), key
    assert s["tabs"] == ["devices", "map", "monitor", "alerts", "log"]
    assert s["parse"] == [60, 10, None, None, None, None, None, None]
