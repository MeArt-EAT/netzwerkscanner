"""Autostart (BAUPLAN §31): Abfrage, Einrichten, Entfernen, Fehlerpfade.

`schtasks` wird nie gestartet: jeder Test übergibt eine Attrappe als `run`; tests/conftest.py bricht
echte schtasks-Aufrufe zusätzlich ab. Windows-Verhalten wird auf jedem System über sys.platform geprüft.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from netscan import config
from netscan.platform import autostart
from netscan.platform.autostart import AutostartError, AutostartStatus, autostart_status, set_autostart

SCHTASKS = r"C:\Windows\System32\schtasks.exe"
OK = (0, "", "")


class FakeRun:
    """Zeichnet Aufrufe auf und liefert der Reihe nach vorbereitete Ergebnisse (oder wirft sie)."""

    def __init__(self, *results: Any, default: Any = OK) -> None:
        self.calls: list[tuple[list[str], float]] = []
        self._results = list(results)
        self._default = default

    def __call__(self, args: list[str], timeout: float) -> Any:
        self.calls.append((list(args), timeout))
        item = self._results.pop(0) if self._results else self._default
        if isinstance(item, BaseException):
            raise item
        return item

    @property
    def argv(self) -> list[list[str]]:
        return [args for args, _ in self.calls]


@pytest.fixture
def install(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """Windows-Umgebung auf jedem System: Projekt, pythonw.exe und %SystemRoot% in tmp_path/Attrappen."""
    app = tmp_path / "app"
    (app / "netscan").mkdir(parents=True)
    (app / "run_server.py").write_text("", encoding="utf-8")
    py = tmp_path / "py"
    py.mkdir()
    for name in ("python.exe", "pythonw.exe"):
        (py / name).write_text("", encoding="utf-8")
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("USERDOMAIN", "TESTPC")
    monkeypatch.setenv("USERNAME", "anna")
    monkeypatch.setattr(config, "PACKAGE_DIR", app / "netscan")
    monkeypatch.setattr(sys, "executable", str(py / "python.exe"))
    monkeypatch.setattr(autostart, "MAX_COMMAND_LEN", 10_000)  # Längengrenze: test_autostart_command.py
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    return SimpleNamespace(command=f'"{py / "pythonw.exe"}" "{app / "run_server.py"}" --no-browser')


@pytest.fixture
def linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")


# --- Abfrage ---------------------------------------------------------------------------------


def test_status_enabled_when_query_succeeds(install: SimpleNamespace) -> None:
    run = FakeRun((0, "Ordner: \\\nNetzwerkscanner  Bereit", ""))
    status = autostart_status(run=run)
    assert status == AutostartStatus(supported=True, enabled=True, detail=autostart.ENABLED_DETAIL)
    assert run.calls == [([SCHTASKS, "/Query", "/TN", "Netzwerkscanner"], 10.0)]


def test_status_disabled_when_query_fails(install: SimpleNamespace) -> None:
    run = FakeRun((1, "", "FEHLER: Das System kann die angegebene Datei nicht finden."))
    status = autostart_status(run=run)
    assert status == AutostartStatus(supported=True, enabled=False, detail=autostart.DISABLED_DETAIL)
    assert len(run.calls) == 1


@pytest.mark.parametrize(
    ("problem", "fragment"),
    [
        (OSError("Datei kaputt"), "Datei kaputt"),
        (FileNotFoundError(2, "Das System kann die angegebene Datei nicht finden"), "nicht starten"),
        (subprocess.TimeoutExpired("schtasks", 10), "nicht innerhalb von 10 s"),
    ],
)
def test_status_never_raises_when_schtasks_is_unusable(
    install: SimpleNamespace, problem: Exception, fragment: str
) -> None:
    status = autostart_status(run=FakeRun(problem))
    assert status.supported is True and status.enabled is False
    assert fragment in status.detail


def test_status_to_dict_has_exactly_the_api_keys(install: SimpleNamespace) -> None:
    assert autostart_status(run=FakeRun(OK)).to_dict() == {
        "supported": True,
        "enabled": True,
        "detail": autostart.ENABLED_DETAIL,
    }


# --- Einrichten ------------------------------------------------------------------------------


def test_enable_calls_schtasks_create_with_exact_arguments(install: SimpleNamespace) -> None:
    run = FakeRun(OK)
    status = set_autostart(True, run=run)
    assert run.argv == [
        [
            SCHTASKS, "/Create", "/TN", "Netzwerkscanner", "/SC", "ONLOGON", "/RL", "LIMITED",
            "/RU", r"TESTPC\anna", "/IT", "/F", "/TR", install.command,
        ]
    ]
    assert run.calls[0][1] == 10.0
    assert status == AutostartStatus(supported=True, enabled=True, detail=autostart.ENABLED_DETAIL)


def test_enable_never_asks_for_highest_rights(install: SimpleNamespace) -> None:
    run = FakeRun(OK)
    set_autostart(True, run=run)
    args = run.argv[0]
    assert "HIGHEST" not in " ".join(args).upper()
    assert args[args.index("/RL") + 1] == "LIMITED"
    # Konto = angemeldeter Benutzer, nur interaktiv (/IT), nie ein Kennwort (/RP)
    assert args[args.index("/RU") + 1] == r"TESTPC\anna" and "/IT" in args and "/RP" not in args


def test_enable_command_is_quoted_and_runs_without_browser(install: SimpleNamespace) -> None:
    run = FakeRun(OK)
    set_autostart(True, run=run)
    command = run.argv[0][-1]
    assert run.argv[0][-2] == "/TR"
    assert command.count('"') == 4
    assert command.startswith('"') and command.endswith('run_server.py" --no-browser')
    assert "pythonw.exe" in command


def test_enable_with_task_already_there_overwrites_with_f(install: SimpleNamespace) -> None:
    run = FakeRun((0, "ERFOLGREICH: Die geplante Aufgabe \"Netzwerkscanner\" wurde erfolgreich erstellt.", ""))
    assert set_autostart(True, run=run).enabled is True
    assert "/F" in run.argv[0]


@pytest.mark.parametrize(
    "message",
    ["FEHLER: Zugriff verweigert.", "ERROR: Access is denied.", "FEHLER: Der Zugriff wurde verweigert."],
)
def test_enable_access_denied_points_to_admin_rights(install: SimpleNamespace, message: str) -> None:
    with pytest.raises(AutostartError) as info:
        set_autostart(True, run=FakeRun((1, "", message)))
    text = str(info.value)
    assert message.split(": ", 1)[1].rstrip(".") in text
    assert "Adminrechte" in text and "start.bat" in text
    assert "nicht eingerichtet" in text


def test_enable_other_error_has_no_admin_hint(install: SimpleNamespace) -> None:
    with pytest.raises(AutostartError) as info:
        set_autostart(True, run=FakeRun((1, "", "FEHLER: Ungültiger Wert für /SC.")))
    text = str(info.value)
    assert "Ungültiger Wert für /SC." in text and "Code 1" in text
    assert "start.bat" not in text


def test_enable_error_falls_back_to_stdout_when_stderr_is_empty(install: SimpleNamespace) -> None:
    with pytest.raises(AutostartError, match="Nur Standardausgabe"):
        set_autostart(True, run=FakeRun((2, "Nur Standardausgabe", "  \n")))


def test_enable_error_output_is_cleaned_and_limited_to_200_characters(install: SimpleNamespace) -> None:
    noisy = "FEHLER:\r\n\tSchlimm\x00 \x1b[31mrot\x07 " + "lang " * 400
    with pytest.raises(AutostartError) as info:
        set_autostart(True, run=FakeRun((1, "", noisy)))
    text = str(info.value)
    assert all(ch.isprintable() for ch in text)
    detail = text.split("): ", 1)[1]
    assert len(detail) <= autostart.ERROR_DETAIL_MAX == 200
    assert detail.endswith("…")
    assert detail.startswith("FEHLER: Schlimm")


def test_access_denied_hint_survives_long_output(install: SimpleNamespace) -> None:
    long_text = "Hinweis " * 100 + "Zugriff verweigert"  # der Fund steht hinter der Kürzung
    with pytest.raises(AutostartError, match="start.bat"):
        set_autostart(True, run=FakeRun((1, "", long_text)))


def test_enable_without_message_still_reports_the_code(install: SimpleNamespace) -> None:
    with pytest.raises(AutostartError, match=r"Code 5\)$"):
        set_autostart(True, run=FakeRun((5, "", "")))


def test_enable_refuses_unusable_paths_before_calling_schtasks(
    install: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "executable", 'C:\\Py"thon\\python.exe')
    run = FakeRun(OK)
    with pytest.raises(AutostartError, match="Anführungszeichen"):
        set_autostart(True, run=run)
    assert run.calls == []


def test_enable_refuses_too_long_command_before_calling_schtasks(
    install: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    length = len(install.command)
    monkeypatch.setattr(autostart, "MAX_COMMAND_LEN", length)  # genau an der Grenze: erlaubt
    assert set_autostart(True, run=FakeRun(OK)).enabled is True
    monkeypatch.setattr(autostart, "MAX_COMMAND_LEN", length - 1)  # ein Zeichen zu lang: abgelehnt
    run = FakeRun(OK)
    with pytest.raises(AutostartError, match=f"{length} Zeichen"):
        set_autostart(True, run=run)
    assert run.calls == []


# --- Entfernen -------------------------------------------------------------------------------


def test_disable_calls_schtasks_delete_with_exact_arguments(install: SimpleNamespace) -> None:
    run = FakeRun(OK)
    status = set_autostart(False, run=run)
    assert run.argv == [[SCHTASKS, "/Delete", "/TN", "Netzwerkscanner", "/F"]]
    assert status == AutostartStatus(supported=True, enabled=False, detail=autostart.DISABLED_DETAIL)


def test_disable_when_task_does_not_exist_is_no_error(install: SimpleNamespace) -> None:
    run = FakeRun(
        (1, "", "FEHLER: Das System kann die angegebene Datei nicht finden."),  # Delete
        (1, "", "FEHLER: Das System kann die angegebene Datei nicht finden."),  # Query: gibt es nicht
    )
    status = set_autostart(False, run=run)
    assert status.supported is True and status.enabled is False
    assert [a[1] for a in run.argv] == ["/Delete", "/Query"]


def test_disable_works_with_english_error_text_too(install: SimpleNamespace) -> None:
    run = FakeRun((1, "", "ERROR: The system cannot find the file specified."), (1, "", "ERROR: ..."))
    assert set_autostart(False, run=run).enabled is False


def test_disable_failure_with_task_still_there_is_an_error(install: SimpleNamespace) -> None:
    run = FakeRun((1, "", "FEHLER: Zugriff verweigert."), OK)  # Delete scheitert, Query findet die Aufgabe
    with pytest.raises(AutostartError) as info:
        set_autostart(False, run=run)
    text = str(info.value)
    assert "nicht entfernt" in text and "Adminrechte" in text and "start.bat" in text
    assert [a[1] for a in run.argv] == ["/Delete", "/Query"]


def test_disable_failure_with_unclear_state_reports_the_delete_error(install: SimpleNamespace) -> None:
    run = FakeRun((1, "", "FEHLER: Etwas Unerwartetes."), OSError("Abfrage nicht möglich"))
    with pytest.raises(AutostartError, match="Etwas Unerwartetes"):
        set_autostart(False, run=run)


# --- Unerwartete Antworten von run -----------------------------------------------------------


def test_run_exceptions_become_autostart_errors(install: SimpleNamespace) -> None:
    with pytest.raises(AutostartError, match="nicht innerhalb von 10 s"):
        set_autostart(True, run=FakeRun(subprocess.TimeoutExpired("schtasks", 10)))
    with pytest.raises(AutostartError, match="nicht starten.*Zugriff"):
        set_autostart(False, run=FakeRun(PermissionError("Zugriff")))


@pytest.mark.parametrize("garbage", [None, "ok", 5, (0, "nur zwei"), ("null", "", "")])
def test_unusable_run_results_become_autostart_errors(install: SimpleNamespace, garbage: Any) -> None:
    with pytest.raises(AutostartError, match="auswertbare Antwort"):
        set_autostart(True, run=FakeRun(garbage))


def test_run_may_return_bytes_which_are_decoded(install: SimpleNamespace) -> None:
    with pytest.raises(AutostartError, match="Größe überschritten"):
        set_autostart(True, run=FakeRun((1, b"", "FEHLER: Größe überschritten.".encode("utf-8"))))


def test_enabled_must_be_a_real_bool(install: SimpleNamespace) -> None:
    run = FakeRun(OK)
    for bad in ("yes", None, 1, "false"):
        with pytest.raises(AutostartError):
            set_autostart(bad, run=run)  # type: ignore[arg-type]
    assert run.calls == []


# --- Nicht Windows ---------------------------------------------------------------------------


def test_status_not_supported_outside_windows(linux: None) -> None:
    run = FakeRun()
    status = autostart_status(run=run)
    assert status == AutostartStatus(
        supported=False, enabled=False, detail="Unter Linux als systemd-Dienst einrichten (siehe README)."
    )
    assert run.calls == []


@pytest.mark.parametrize("enabled", [True, False])
def test_set_autostart_outside_windows_is_an_error(linux: None, enabled: bool) -> None:
    run = FakeRun()
    with pytest.raises(AutostartError, match="systemd"):
        set_autostart(enabled, run=run)
    assert run.calls == []


@pytest.mark.parametrize("platform", ["linux", "darwin", "cygwin"])
def test_only_win32_counts_as_windows(monkeypatch: pytest.MonkeyPatch, platform: str) -> None:
    monkeypatch.setattr(sys, "platform", platform)
    assert autostart_status(run=FakeRun()).supported is False


def test_enable_refuses_without_known_user(install: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("USERNAME", raising=False)
    run = FakeRun(OK)
    with pytest.raises(AutostartError):
        set_autostart(True, run=run)
    assert run.argv == []  # schtasks gar nicht erst gestartet


def test_enable_refuses_user_with_quote(install: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("USERNAME", 'an"na')
    run = FakeRun(OK)
    with pytest.raises(AutostartError):
        set_autostart(True, run=run)
    assert run.argv == []
