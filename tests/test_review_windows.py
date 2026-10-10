"""Regressionstests zu Prüfbefunden an start.bat und am Server-Fenster: S1/WIN-01 (Hinweistext), WIN-04 (Python-
Suche), WIN-05 (Sonderzeichen in Pfaden), WIN-07 (QuickEdit). Unter Windows laufen die Zeilen aus start.bat
in einer Kopie – Start-Process ist dort durch eine Ausgabe ersetzt, es startet nichts und es geht nichts ins Netz."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
START_BAT = ROOT / "start.bat"


def bat_lines() -> list[str]:
    return START_BAT.read_bytes().decode("utf-8").split("\r\n")


def test_start_bat_keeps_crlf() -> None:
    data = START_BAT.read_bytes()
    assert data.count(b"\r\n") == data.count(b"\n") > 50  # keine einzelnen LF


def test_s1_start_bat_no_longer_promises_protection_that_never_comes() -> None:
    text = "\n".join(bat_lines())
    assert "erst, nachdem der Hotspot einmal erkannt wurde" not in text
    assert "Windows-Netzwerkprofils" in text and "sperrt den Schul-Hotspot auch so" in text


def test_win04_python_search_includes_314_and_caps_python_on_path() -> None:
    text = "\n".join(bat_lines())
    assert re.search(r"for %%v in \(3\.13 3\.14 3\.12\) do if not defined BASEPY py -%%v ", text)
    assert "(3, 12) <= sys.version_info[:2] <= (3, 14)" in text
    assert "py -0p" in text
    assert not re.search(r"py -3 ", text)  # nie pauschal „py -3“ (könnte 3.13t sein)


def _blocks(lines: list[str]) -> list[str]:
    """Zeilen innerhalb von ( … )-Blöcken (einfacher Zähler, reicht für start.bat)."""
    inside: list[str] = []
    depth = 0
    for line in lines:
        code = re.sub(r'"[^"]*"', '""', line)  # Klammern in Anführungszeichen zählen nicht
        if depth > 0:
            inside.append(line)
        depth += code.count("(") - code.count(")")
        depth = max(depth, 0)
    return inside


def test_win05_no_unquoted_paths_inside_blocks_and_no_path_in_powershell_code() -> None:
    lines = bat_lines()
    for line in _blocks(lines):
        stripped = re.sub(r'"[^"]*"', "", line)
        assert not re.search(r"%(APPHOME|VENV|VPY|~dp0)", stripped), line
    ps = [line for line in lines if "Start-Process" in line]
    assert len(ps) == 1
    assert "$env:NS_PY" in ps[0] and "$env:NS_SCRIPT" in ps[0]
    assert "%VPY%" not in ps[0] and "%~dp0" not in ps[0]
    assert 'set "NS_PY=%VPY%"' in lines and 'set "NS_SCRIPT=%~dp0run_server.py"' in lines


@pytest.mark.skipif(sys.platform != "win32", reason="cmd.exe gibt es nur unter Windows")
def test_win05_real_lines_work_in_a_folder_with_ampersand_apostrophe_and_brackets(tmp_path: Path) -> None:
    lines = bat_lines()
    folder = tmp_path / "Schule & Co's (x)"
    folder.mkdir()
    ps_line = next(line for line in lines if "Start-Process" in line)
    # Start-Process durch eine Funktion ersetzen (Funktionen haben in PowerShell Vorrang vor Cmdlets)
    fake = (
        "function Start-Process { param($FilePath, $ArgumentList, $Verb, $ErrorAction) "
        "Write-Output ('EXE=' + $FilePath); Write-Output ('ARGS=' + ($ArgumentList -join ' ')); Write-Output ('VERB=' + $Verb) }; "
    )
    ps_line = ps_line.replace('-Command "', '-Command "' + fake, 1)
    noserver = lines.index(":noserver")
    body = [
        "@echo off",
        "setlocal EnableExtensions",
        "chcp 65001 >nul",
        'set "APPHOME=%~dp0Max (Admin)"',
        "set \"VPY=%~dp0venv & 'x'\\python.exe\"",
        'set "BASEPY="',
        next(line for line in lines if line.startswith("for %%v in (3.13")),
        "echo BASEPY=[%BASEPY%]",
        'set "NS_PY=%VPY%"',
        'set "NS_SCRIPT=%~dp0run_server.py"',
        ps_line,
        "echo PS-RC=%errorlevel%",
        *[line for line in lines[noserver + 1 :] if line.startswith("echo ")][:2],
    ]
    bat = folder / "probe.bat"
    bat.write_bytes(("\r\n".join(body) + "\r\n").encode("utf-8"))
    result = subprocess.run(f'cmd.exe /d /c ""{bat}""', capture_output=True, timeout=60)
    out = result.stdout.decode("utf-8", errors="replace")
    assert result.returncode == 0, (out, result.stderr.decode("cp850", errors="replace"))
    assert f"EXE={folder}\\venv & 'x'\\python.exe" in out
    assert f'ARGS="{folder}\\run_server.py" --no-browser' in out
    assert "VERB=RunAs" in out and "PS-RC=0" in out
    assert f'"{folder}\\Max (Admin)\\data\\logs\\netscan.log"' in out
    assert "BASEPY=[" in out


def test_win07_run_server_turns_quick_edit_off_and_restores_it() -> None:
    text = (ROOT / "run_server.py").read_text(encoding="utf-8")
    assert "disable_quick_edit" in text
    assert re.search(r"finally:\s+if callable\(restore\):\s+restore\(\)", text)
