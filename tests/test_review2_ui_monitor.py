"""Regressionstests Review 2, Oberfläche der Überwachung (monitor.js): Befunde B7 und B8.

B7: Der angefangene erste Eimer (beginnt vor `since`) und der laufende letzte Eimer (reicht über `until`) sind keine
    Lücke. Ohne Messwerte dort darf der Hinweis nicht „Abschnitt ohne Messwerte (Lücke …)“ melden.
B8: „Jetzt prüfen“ ist gesperrt, wenn alle Ziele abgeschaltet sind (Monitor-Zustand idle).

Die reinen Funktionen laufen in Node (wie tests/test_frontend_monitor.py); ohne node im PATH werden die Tests
übersprungen. Es geht kein Paket ins Netz.
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

ROOT = Path(__file__).resolve().parent.parent
MONITOR_JS = ROOT / "netscan" / "web" / "static" / "monitor.js"

# Node-Skript (nur ASCII). Zeiten wie die API: since/until in Sekunden, t in Millisekunden.
NODE_SCRIPT = r"""
const mon = require(process.argv[2]);
const out = {};
const B = 300;                        // Eimer 5 min
const until = 1760000000;             // liegt nicht auf einer Eimergrenze (1760000000 % 300 = 200)
const since = until - 86400;
const start = Math.floor(since / B) * B;
const count = Math.ceil((until - start) / B);
const pt = (i, n) => n > 0
  ? { t: (start + i * B) * 1000, rtt_avg: 2, rtt_min: 1, rtt_max: 3, up_pct: 100, n: n }
  : { t: (start + i * B) * 1000, rtt_avg: null, rtt_min: null, rtt_max: null, up_pct: null, n: 0 };
const frame = { since: since, until: until, bucket_s: B };

// Erster und letzter Eimer leer (angefangen bzw. laufend), alle vollen Eimer mit Messwerten
const edges = []; for (let i = 0; i < count; i++) edges.push(pt(i, i === 0 || i === count - 1 ? 0 : 5));
const sdEdges = mon.seriesData(edges, frame);
out.edges = { count: count, gaps: sdEdges.gaps, samples: sdEdges.samples, note: mon.seriesNote(B, sdEdges),
  first: sdEdges.avg[0].y, last: sdEdges.avg[count - 1].y,
  tipFirst: mon.seriesTooltip(sdEdges.info[0]), tipLast: mon.seriesTooltip(sdEdges.info[count - 1]),
  tipInner: mon.seriesTooltip(sdEdges.info[1]) };
// Ohne Rahmen (alter Aufruf mit einem Argument) bleibt alles wie bisher
out.edgesLegacy = mon.seriesData(edges).gaps;

// Echte Luecke mitten im Zeitraum zaehlt weiter, die Raender nicht
const inner = edges.map((p, i) => (i === 100 || i === 101 ? pt(i, 0) : p));
const sdInner = mon.seriesData(inner, frame);
out.inner = { gaps: sdInner.gaps, note: mon.seriesNote(B, sdInner), tip: mon.seriesTooltip(sdInner.info[100]) };

// Zeitraum genau auf Eimergrenzen: erster und letzter Eimer sind voll; leer = echte Luecke
const u2 = 1760000100;                 // 1760000100 % 300 = 0
const s2 = u2 - 3000;
const full = []; for (let i = 0; i < 10; i++) full.push({ t: (s2 + i * B) * 1000, rtt_avg: null, rtt_min: null, rtt_max: null, up_pct: null, n: i === 0 || i === 9 ? 0 : 4 });
for (let i = 1; i < 9; i++) Object.assign(full[i], { rtt_avg: 2, rtt_min: 1, rtt_max: 3, up_pct: 100 });
const sdFull = mon.seriesData(full, { since: s2, until: u2, bucket_s: B });
out.full = { gaps: sdFull.gaps, tipFirst: mon.seriesTooltip(sdFull.info[0]), tipLast: mon.seriesTooltip(sdFull.info[9]) };

// Rahmen in Millisekunden oder mit Unsinn: nie ein Absturz, Unsinn = alter Ablauf
out.msFrame = mon.seriesData(edges, { since: since * 1000, until: until * 1000, bucket_s: B }).gaps;
out.badFrame = [mon.seriesData(edges, null).gaps, mon.seriesData(edges, "x").gaps, mon.seriesData(edges, { since: "a", until: null, bucket_s: -5 }).gaps];
// Ohne bucket_s gilt nur die Regel fuer den ersten Eimer
out.noBucket = mon.seriesData(edges, { since: since, until: until }).gaps;

// B8: Jetzt pruefen
const off = { mac: "a", enabled: false }, on = { mac: "b", enabled: true }, legacy = { mac: "c" };
out.run = {
  idleAllOff: mon.runButtonState({ state: "idle" }, [off]),
  idleCount: mon.runButtonState({ state: "idle" }, 1),
  runningAllOff: mon.runButtonState({ state: "running" }, [off, off]),
  runningMixed: mon.runButtonState({ state: "running" }, [off, on]),
  runningLegacy: mon.runButtonState({ state: "running" }, [legacy]),
  idleFreshOn: mon.runButtonState({ state: "idle" }, [on]),
  pausedOn: mon.runButtonState({ state: "paused" }, [on]),
  empty: mon.runButtonState({ state: "running" }, []),
  junk: mon.runButtonState({ state: "running" }, [null, "x", off]),
  idleZero: mon.runButtonState({ state: "idle" }, 0),
  runningCount: mon.runButtonState({ state: "running" }, 2),
  offList: mon.runButtonState({ state: "off" }, [on]),
  stoppedList: mon.runButtonState({ state: "stopped" }, [on]),
};
process.stdout.write(JSON.stringify(out));
"""


@pytest.fixture(scope="module")
def ui(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node nicht im PATH")
    script = tmp_path_factory.mktemp("review2_ui_monitor") / "check.js"
    script.write_text(NODE_SCRIPT, encoding="utf-8")
    env = dict(os.environ, TZ="UTC", NODE_OPTIONS="")
    result = subprocess.run(
        [node, str(script), str(MONITOR_JS)], capture_output=True, text=True, encoding="utf-8", timeout=60, env=env
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _source() -> str:
    return MONITOR_JS.read_text(encoding="utf-8")


# --- B7: Randeimer sind keine Lücke -----------------------------------------------------------------


def test_b7_angefangener_und_laufender_randeimer_sind_keine_luecke(ui: dict[str, Any]) -> None:
    e = ui["edges"]
    assert e["count"] == 289  # 288 volle Eimer in 24 h plus der angefangene am Anfang
    assert e["gaps"] == 0, "erster (vor since) und laufender letzter Eimer zählen nicht als Lücke"
    assert "ohne Messwerte" not in e["note"] and e["note"] == "Ein Punkt fasst 5 min zusammen"
    assert e["first"] is None and e["last"] is None  # leer bleibt leer (nichts wird erfunden)
    assert e["samples"] == 5 * 287


def test_b7_randeimer_haben_eigene_tooltips(ui: dict[str, Any]) -> None:
    e = ui["edges"]
    assert e["tipFirst"] == ["Keine Messwerte (Abschnitt liegt nur teilweise im Zeitraum)"]
    assert e["tipLast"] == ["Noch keine Messwerte (Abschnitt läuft noch)"]
    assert e["tipInner"][0].startswith("Antwortzeit Ø")


def test_b7_echte_luecke_im_zeitraum_zaehlt_weiter(ui: dict[str, Any]) -> None:
    i = ui["inner"]
    assert i["gaps"] == 2
    assert "2 Abschnitte ohne Messwerte (Lücke, z. B. Pause oder Programm aus)" in i["note"]
    assert i["tip"] == ["Keine Messwerte (Lücke)"]


def test_b7_volle_randeimer_auf_eimergrenzen_sind_echte_luecken(ui: dict[str, Any]) -> None:
    f = ui["full"]
    assert f["gaps"] == 2, "beginnt der Zeitraum auf einer Eimergrenze, ist der erste Eimer voll; endet er dort, auch der letzte"
    assert f["tipFirst"] == ["Keine Messwerte (Lücke)"] and f["tipLast"] == ["Keine Messwerte (Lücke)"]


def test_b7_alter_aufruf_und_unsinniger_rahmen_bleiben_wie_bisher(ui: dict[str, Any]) -> None:
    assert ui["edgesLegacy"] == 2  # ohne Rahmen weiß seriesData nichts über die Ränder
    assert ui["msFrame"] == 0  # since/until in Millisekunden werden erkannt
    assert ui["badFrame"] == [2, 2, 2]
    assert ui["noBucket"] == 1  # ohne Eimergröße bleibt nur die Regel für den ersten Eimer


def test_b7_diagramm_uebergibt_den_zeitrahmen() -> None:
    src = _source()
    assert re.search(r"seriesData\(\s*M\.series\.points\s*,\s*M\.series\s*\)", src), "drawRttChart muss since/until/bucket_s mitgeben"


# --- B8: Jetzt prüfen bei abgeschalteten Zielen -------------------------------------------------------


def test_b8_alle_ziele_abgeschaltet_sperrt_jetzt_pruefen(ui: dict[str, Any]) -> None:
    r = ui["run"]
    for key in ("idleAllOff", "runningAllOff", "junk"):
        assert r[key]["disabled"] is True, key
        assert r[key]["title"] == "Alle überwachten Geräte sind abgeschaltet.", key
    assert r["idleCount"]["disabled"] is True, "idle heißt: keine aktiven Ziele (auch bei Aufruf nur mit Anzahl)"
    assert r["idleCount"]["title"] == "Alle überwachten Geräte sind abgeschaltet."


def test_b8_aktive_ziele_erlauben_jetzt_pruefen(ui: dict[str, Any]) -> None:
    r = ui["run"]
    for key in ("runningMixed", "runningLegacy", "pausedOn", "runningCount"):
        assert r[key]["disabled"] is False, key
    # idle ist veraltet, sobald die frisch geladene Liste ein eingeschaltetes Ziel hat (z. B. gerade wieder
    # eingeschaltet, Durchlauf läuft schon): dann darf geprüft werden.
    assert r["idleFreshOn"]["disabled"] is False


def test_b8_bisherige_sperren_bleiben(ui: dict[str, Any]) -> None:
    r = ui["run"]
    assert r["empty"] == {"disabled": True, "title": "Noch kein Gerät zur Überwachung ausgewählt."}
    assert r["idleZero"] == {"disabled": True, "title": "Noch kein Gerät zur Überwachung ausgewählt."}
    assert r["offList"]["disabled"] is True and "Einstellungen" in r["offList"]["title"]
    assert r["stoppedList"] == {"disabled": True, "title": "Der Monitor läuft nicht."}


def test_b8_oberflaeche_uebergibt_die_zielliste() -> None:
    src = _source()
    assert "runButtonState(M.status, M.targets.size)" not in src, "die Anzahl aller Ziele zählt auch abgeschaltete"
    assert re.search(r"runButtonState\(\s*M\.status\s*,\s*Array\.from\(\s*M\.targets\.values\(\)\s*\)\s*\)", src)
