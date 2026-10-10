"""Regressionstest zu S10/F9: Im Demo-Modus lädt „Herstellerliste aktualisieren“ nichts aus dem Internet.

Der Demo-Modus ersetzt Funktionen prozessweit – deshalb läuft er hier in einem eigenen Python-Prozess. Dort
gilt dieselbe Netzsperre wie in den Tests (tests/conftest.py wird zuerst geladen), und alle Daten landen im
Testordner.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SCRIPT = r"""
import sys
sys.path.insert(0, sys.argv[1])
import tests.conftest  # noqa: F401  Netzsperre: nur 127.0.0.0/8
from fastapi.testclient import TestClient
from netscan import demo
from netscan.net import oui
from netscan.web import server

svc = demo.build_demo_services()
before = sorted(p.name for p in svc.data_dir.iterdir())
for call in (lambda: oui.update_from_ieee(svc.data_dir), lambda: oui._default_fetch(oui.OUI_URL)):
    try:
        call()
        print("KEIN FEHLER")
    except OSError as exc:
        print("OSError:", exc)
with TestClient(server.create_app(svc), base_url="http://127.0.0.1:8765") as client:
    r = client.post("/api/oui/update", json={})
    print("STATUS", r.status_code)
    assert svc.jobs.wait(10)
    res = svc.jobs.last_result
    print("RESULT", res["result"], res["error"])
print("UNVERAENDERT", sorted(p.name for p in svc.data_dir.iterdir()) == before)
svc.close()
"""


def test_s10_demo_oui_update_stays_offline(tmp_path: Path) -> None:
    env = dict(os.environ, LOCALAPPDATA=str(tmp_path), XDG_DATA_HOME=str(tmp_path), PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8")
    env.pop("NETSCAN_DATA_DIR", None)
    result = subprocess.run(
        [sys.executable, "-c", SCRIPT, str(ROOT)], cwd=str(tmp_path), env=env,
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120,
    )  # fmt: skip
    out = result.stdout
    assert result.returncode == 0, (out, result.stderr[-2000:])
    assert "KEIN FEHLER" not in out
    lines = out.splitlines()
    assert sum(line.startswith("OSError: Im Demo-Modus wird nichts aus dem Internet geladen") for line in lines) == 2
    assert "STATUS 202" in lines
    assert any(line.startswith("RESULT failed OSError: Im Demo-Modus") for line in lines)
    assert "UNVERAENDERT True" in out
    # Ein Versuch, ieee.org aufzulösen, schlüge an der Netzsperre fehl (LanTrafficError statt OSError) –
    # die Meldungen oben beweisen, dass der Ersatz gegriffen hat. (Scapys eigener Import meldet beim Laden
    # von scapy.layers.dhcp ebenfalls einen LanTrafficError; der betrifft kein Senden und bleibt hier außen vor.)
    assert "ieee.org" not in result.stderr
