"""Regressionstests zu Prüfbefunden an der Oberfläche: F1 (Hängen in „Wird abgebrochen …“), F6 (Portzahlen
des Tiefenscans), S1 (Hinweis und „Das ist mein Heimnetz“ ohne lesbaren WLAN-Namen), F3 (Tiefenscan-Knopf für
offline-Geräte). Die reinen Funktionen laufen in Node (ohne Browser); fehlt node, werden sie übersprungen."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
APP_JS = ROOT / "netscan" / "web" / "static" / "app.js"

NODE_SCRIPT = r"""
const ui = require(process.argv[2]);
const out = {};
const running = (id) => ({ job_id: id, state: "running" });
const idle = { job_id: null, state: "idle" };
out.cancel = {
  stillRunning: ui.shouldMarkCancelling(running("a1"), "a1"),
  finishedBeforeAnswer: ui.shouldMarkCancelling(idle, "a1"),
  otherJob: ui.shouldMarkCancelling(running("b2"), "a1"),
  placeholder: ui.shouldMarkCancelling({ job_id: null, state: "running" }, null),
  alreadyCancelling: ui.shouldMarkCancelling({ job_id: "a1", state: "cancelling" }, "a1"),
};
out.progress = {
  lateAfterFinish: ui.acceptProgress(idle, { job_id: "a1", phase: "Abbruch" }, ["a1"]),
  otherJob: ui.acceptProgress(running("b2"), { job_id: "a1", phase: "Ports" }, []),
  sameJob: ui.acceptProgress(running("a1"), { job_id: "a1", phase: "Ports" }, []),
  pageOpenedMidJob: ui.acceptProgress(idle, { job_id: "c3", phase: "Ping" }, ["a1"]),
};
out.deep = {
  lists: ui.describeResult({ kind: "deep_scan", result: "completed", summary: { open_ports: [80, 631, 9100], new_ports: [631], duration_s: 5 } }),
  empty: ui.describeResult({ kind: "deep_scan", result: "completed", summary: { open_ports: [], new_ports: [], duration_s: 5 } }),
  numbers: ui.describeResult({ kind: "deep_scan", result: "completed", summary: { open_ports: 1, new_ports: 0 } }),
};
const confirmUnreadable = { decision: "confirm", code: "foreign_network", ssid_readable: false, gateway_mac: "3c:a6:2f:00:00:01" };
const confirmReadable = { decision: "confirm", code: "foreign_network", ssid_readable: true, ssid: "Welt", gateway_mac: "3c:a6:2f:00:00:01" };
out.guard = {
  warnUnreadable: ui.guardWarning(confirmUnreadable),
  warnAllowUnreadable: ui.guardWarning({ decision: "allow", code: "ok_home", ssid_readable: false }),
  warnReadable: ui.guardWarning(confirmReadable),
  warnBlock: ui.guardWarning({ decision: "block", code: "blocked_gateway", ssid_readable: false }),
  homeWlanUnreadable: ui.homeButtonAllowed(confirmUnreadable, { name: "WLAN", is_wireless: true }),
  homeUnknownAdapter: ui.homeButtonAllowed(confirmUnreadable, null),
  homeEthernetUnreadable: ui.homeButtonAllowed(confirmUnreadable, { name: "Ethernet", is_wireless: false }),
  homeWlanReadable: ui.homeButtonAllowed(confirmReadable, { name: "WLAN", is_wireless: true }),
  homeNoMac: ui.homeButtonAllowed(Object.assign({}, confirmReadable, { gateway_mac: null }), { is_wireless: false }),
  homeBlock: ui.homeButtonAllowed({ decision: "block", gateway_mac: "x" }, { is_wireless: false }),
  // Ohne Standortfreigabe, aber mit Netzwerkprofilnamen: Server entscheidet über home_allowed
  warnProfile: ui.guardWarning(Object.assign({}, confirmUnreadable, { profile_name: "Welt" })),
  homeServerYes: ui.homeButtonAllowed(Object.assign({}, confirmUnreadable, { profile_name: "Welt", home_allowed: true }), { name: "WLAN", is_wireless: true }),
  homeServerNo: ui.homeButtonAllowed(Object.assign({}, confirmReadable, { home_allowed: false }), { name: "Ethernet", is_wireless: false }),
};
process.stdout.write(JSON.stringify(out));
"""


@pytest.fixture(scope="module")
def ui(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node nicht im PATH")
    script = tmp_path_factory.mktemp("frontend-review") / "check.js"
    script.write_text(NODE_SCRIPT, encoding="utf-8")
    env = dict(os.environ, TZ="UTC", NODE_OPTIONS="")
    result = subprocess.run([node, str(script), str(APP_JS)], capture_output=True, text=True, encoding="utf-8", timeout=60, env=env)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_f1_cancel_answer_after_job_finished_does_not_stick(ui: dict[str, Any]) -> None:
    c = ui["cancel"]
    assert c["stillRunning"] is True and c["placeholder"] is True
    assert c["finishedBeforeAnswer"] is False  # job.finished kam vor der HTTP-Antwort: nicht „wird abgebrochen“
    assert c["otherJob"] is False and c["alreadyCancelling"] is False


def test_f1_late_progress_of_finished_job_is_ignored(ui: dict[str, Any]) -> None:
    p = ui["progress"]
    assert p["lateAfterFinish"] is False  # „Abbruch“ nach job.finished macht keinen Geister-Auftrag
    assert p["otherJob"] is False
    assert p["sameJob"] is True and p["pageOpenedMidJob"] is True


def test_f1_cancel_scan_uses_the_check_and_a_watchdog_heals_the_state() -> None:
    js = APP_JS.read_text(encoding="utf-8")
    cancel = js[js.index("async function cancelScan()") : js.index("// ---------- Adapter ----------")]
    assert "shouldMarkCancelling(state.job, jobId)" in cancel and "refreshJob()" in cancel
    progress = js[js.index("function onJobProgress(data)") : js.index("function onJobFinished(data)")]
    assert "acceptProgress(state.job, data, state.finishedJobIds)" in progress
    assert "finishedJobIds.push(data.job_id)" in js
    watch = js[js.index("function watchJob(busy)") : js.index("let renderJobQueued")]
    assert "setInterval" in watch and 'res.data.state === "idle"' in watch and "clearInterval" in watch


def test_f6_deep_scan_summary_lists_are_counted(ui: dict[str, Any]) -> None:
    d = ui["deep"]
    assert d["lists"]["text"] == "Tiefenscan abgeschlossen: 3 offene Ports, 1 neu, Dauer 5 s"
    assert d["empty"]["text"] == "Tiefenscan abgeschlossen: 0 offene Ports, 0 neu, Dauer 5 s"
    assert d["numbers"]["text"] == "Tiefenscan abgeschlossen: 1 offener Port, 0 neu"


def test_s1_red_hint_and_no_home_button_over_wlan_without_name(ui: dict[str, Any]) -> None:
    g = ui["guard"]
    assert "Hotspot-Sperre eingeschränkt" in g["warnUnreadable"] and "Netzwerkprofil" in g["warnUnreadable"]
    assert g["warnAllowUnreadable"]  # auch im Heimnetz sichtbar: die Sperre ist eingeschränkt
    assert g["warnReadable"] == "" and g["warnBlock"] == ""
    assert g["homeWlanUnreadable"] is False and g["homeUnknownAdapter"] is False
    assert g["homeEthernetUnreadable"] is True and g["homeWlanReadable"] is True
    assert g["homeNoMac"] is False and g["homeBlock"] is False


def test_profile_name_replaces_location_permission(ui: dict[str, Any]) -> None:
    """Leitung: Standortfreigabe bleibt beim Nutzer aus. Mit Netzwerkprofilnamen keine rote Warnung,
    und der Heimnetz-Knopf folgt der Entscheidung des Servers (home_allowed)."""
    g = ui["guard"]
    assert g["warnProfile"] == ""
    assert g["homeServerYes"] is True and g["homeServerNo"] is False


def test_s1_guard_band_uses_the_helpers_and_the_warning_style() -> None:
    js = APP_JS.read_text(encoding="utf-8")
    band = js[js.index("function renderGuard()") : js.index("function currentAdapter()")]
    assert 'class: "guard-warning"' in band and "guardWarning(guard)" in band
    assert "homeButtonAllowed(guard, currentAdapter())" in band
    css = (ROOT / "netscan" / "web" / "static" / "style.css").read_text(encoding="utf-8")
    assert re.search(r"\.guard-warning\s*\{[^}]*var\(--danger\)", css)


def test_f3_deep_button_is_disabled_for_offline_devices() -> None:
    js = APP_JS.read_text(encoding="utf-8")
    body = js[js.index("function updateDeepButton()") : js.index("async function saveDevice()")]
    assert "d.online === false" in body and "offline" in body
    assert re.search(r"btn\.disabled = !d \|\| offline", body)
