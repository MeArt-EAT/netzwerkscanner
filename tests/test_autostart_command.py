"""Autostart (BAUPLAN §31): Befehl der Aufgabe, Pfadprüfungen, Längengrenze von schtasks /TR.

Reine Logik – schtasks wird hier nie gestartet. Pfade liegen in tmp_path; die Längengrenze wird mit
frei gewählten Zeichenketten geprüft, damit lange Temp-Pfade (CI) die Tests nicht verfälschen.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from netscan import config
from netscan.platform import autostart
from netscan.platform.autostart import AutostartError

PY = r"C:\Python\pythonw.exe"
SCRIPT = r"C:\Netzwerkscanner\run_server.py"


# --- _build_task_command ----------------------------------------------------------------


def test_command_quotes_both_paths_and_adds_no_browser() -> None:
    command = autostart._build_task_command(PY, SCRIPT)
    assert command == f'"{PY}" "{SCRIPT}" --no-browser'
    assert command.count('"') == 4


def test_command_accepts_spaces_and_umlauts() -> None:
    script = r"C:\Users\Jörg Müller\Netz Scanner\run_server.py"
    command = autostart._build_task_command(PY, script)
    assert f'"{script}"' in command


@pytest.mark.parametrize("which", ["python", "script"])
def test_command_rejects_quote_in_path(which: str) -> None:
    py, script = PY, SCRIPT
    if which == "python":
        py = r'C:\Py"thon\pythonw.exe'
    else:
        script = r'C:\Netz"werk\run_server.py'
    with pytest.raises(AutostartError, match="Anführungszeichen"):
        autostart._build_task_command(py, script)


@pytest.mark.parametrize("char", ["\n", "\r", "\t", "\x00", "\x1b", "\x7f", "\x85"])
@pytest.mark.parametrize("which", ["python", "script"])
def test_command_rejects_control_characters(which: str, char: str) -> None:
    py, script = PY, SCRIPT
    if which == "python":
        py = f"C:\\Py{char}thon\\pythonw.exe"
    else:
        script = f"C:\\Netz{char}werk\\run_server.py"
    with pytest.raises(AutostartError, match="Steuerzeichen") as info:
        autostart._build_task_command(py, script)
    # die Meldung selbst enthält keine Steuerzeichen
    assert char not in str(info.value)


def _script_with_total_length(total: int) -> str:
    base = len(f'"{PY}" "C:\\\\run_server.py" --no-browser')
    return "C:\\" + "a" * (total - base) + "\\run_server.py"


def test_command_of_exactly_261_characters_is_allowed() -> None:
    script = _script_with_total_length(261)
    command = autostart._build_task_command(PY, script)
    assert len(command) == 261 == autostart.MAX_COMMAND_LEN


def test_command_of_262_characters_is_refused_with_explanation() -> None:
    script = _script_with_total_length(262)
    with pytest.raises(AutostartError) as info:
        autostart._build_task_command(PY, script)
    message = str(info.value)
    assert "262" in message and "261" in message
    assert "schtasks" in message and "kürzeren Pfad" in message


# --- Python-Programm und Projektordner --------------------------------------------------


@pytest.fixture
def layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Projekt <tmp>/app mit run_server.py und Python-Ordner <tmp>/py; Längengrenze aufgehoben."""
    app = tmp_path / "app"
    (app / "netscan").mkdir(parents=True)
    (app / "run_server.py").write_text("", encoding="utf-8")
    (tmp_path / "py").mkdir()
    (tmp_path / "py" / "python.exe").write_text("", encoding="utf-8")
    monkeypatch.setattr(config, "PACKAGE_DIR", app / "netscan")
    monkeypatch.setattr(sys, "executable", str(tmp_path / "py" / "python.exe"))
    monkeypatch.setattr(autostart, "MAX_COMMAND_LEN", 10_000)
    return tmp_path


def test_prefers_pythonw_next_to_python(layout: Path) -> None:
    (layout / "py" / "pythonw.exe").write_text("", encoding="utf-8")
    command = autostart._task_command()
    assert command == f'"{layout / "py" / "pythonw.exe"}" "{layout / "app" / "run_server.py"}" --no-browser'


def test_falls_back_to_python_itself_without_pythonw(layout: Path) -> None:
    command = autostart._task_command()
    assert command.startswith(f'"{layout / "py" / "python.exe"}" ')
    assert "pythonw" not in command


def test_project_folder_is_parent_of_package_dir(layout: Path) -> None:
    script = str(layout / "app" / "run_server.py")
    assert f'"{script}"' in autostart._task_command()


def test_missing_run_server_is_an_error(layout: Path) -> None:
    (layout / "app" / "run_server.py").unlink()
    with pytest.raises(AutostartError, match="run_server.py"):
        autostart._task_command()


def test_unknown_python_executable_is_an_error(layout: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "executable", "")
    with pytest.raises(AutostartError, match="Python"):
        autostart._task_command()


def test_task_command_checks_the_real_paths(layout: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "executable", str(layout / "py" / 'py"thon.exe'))
    with pytest.raises(AutostartError, match="Anführungszeichen"):
        autostart._task_command()


def test_task_command_applies_the_length_limit(layout: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(autostart, "MAX_COMMAND_LEN", 20)
    with pytest.raises(AutostartError, match="Zeichen lang"):
        autostart._task_command()


# --- schtasks.exe ------------------------------------------------------------------------


def test_schtasks_path_is_absolute_under_system32(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SystemRoot", "C:\\Windows\\")
    assert autostart._schtasks_exe() == r"C:\Windows\System32\schtasks.exe"
    monkeypatch.setenv("SystemRoot", r"D:\Win")
    assert autostart._schtasks_exe() == r"D:\Win\System32\schtasks.exe"


def test_schtasks_path_has_a_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SystemRoot", raising=False)
    monkeypatch.delenv("windir", raising=False)
    assert autostart._schtasks_exe() == r"C:\Windows\System32\schtasks.exe"
