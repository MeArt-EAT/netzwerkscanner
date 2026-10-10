"""Autostart (BAUPLAN §31): Standard-Ausführer (subprocess), Dekodierung der schtasks-Ausgabe.

`subprocess.run` wird ersetzt – schtasks läuft auch hier nie. Die Dekodierung folgt platform/windows.py:
erst UTF-8 strikt, dann OEM-Codepage, dann cp850 mit errors="replace".
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from netscan import config
from netscan.platform import autostart
from netscan.platform.autostart import AutostartError, autostart_status, set_autostart

SCHTASKS = r"C:\Windows\System32\schtasks.exe"
UMLAUTS = "ÄÖÜäöüß"


def _oem_is_dos_latin() -> bool:
    """cp437 und cp850 kodieren die deutschen Umlaute gleich; andere OEM-Seiten nicht."""
    if sys.platform != "win32":
        return True
    import ctypes

    return int(ctypes.windll.kernel32.GetOEMCP()) in (437, 850)  # type: ignore[attr-defined]


# Einmal beim Import auswerten: In den Tests ist sys.platform teils ersetzt.
needs_dos_latin = pytest.mark.skipif(not _oem_is_dos_latin(), reason="OEM-Codepage ist nicht cp437/cp850")


class FakeSubprocess:
    """Ersetzt subprocess.run: merkt sich Aufruf und liefert vorbereitete Bytes (oder wirft)."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, *, rc: int = 0, out: bytes = b"", err: bytes = b"",
                 raises: BaseException | None = None) -> None:
        self.calls: list[tuple[list[str], dict[str, Any]]] = []
        self._rc, self._out, self._err, self._raises = rc, out, err, raises
        monkeypatch.setattr(subprocess, "run", self)

    def __call__(self, args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        self.calls.append((list(args), kwargs))
        if self._raises is not None:
            raise self._raises
        return subprocess.CompletedProcess(args, self._rc, self._out, self._err)


@pytest.fixture
def windows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app = tmp_path / "app"
    (app / "netscan").mkdir(parents=True)
    (app / "run_server.py").write_text("", encoding="utf-8")
    (tmp_path / "py").mkdir()
    (tmp_path / "py" / "python.exe").write_text("", encoding="utf-8")
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(config, "PACKAGE_DIR", app / "netscan")
    monkeypatch.setattr(sys, "executable", str(tmp_path / "py" / "python.exe"))
    monkeypatch.setattr(autostart, "MAX_COMMAND_LEN", 10_000)
    monkeypatch.setenv("SystemRoot", r"C:\Windows")


# --- Dekodierung -----------------------------------------------------------------------------


def test_decode_handles_empty_and_text() -> None:
    assert autostart._decode(None) == ""
    assert autostart._decode(b"") == ""
    assert autostart._decode("schon Text") == "schon Text"
    assert autostart._decode(bytearray(b"abc")) == "abc"


def test_decode_prefers_utf8_and_strips_bom() -> None:
    assert autostart._decode(("FEHLER: " + UMLAUTS).encode("utf-8")) == "FEHLER: " + UMLAUTS
    assert autostart._decode(("\ufeff" + UMLAUTS).encode("utf-8")) == UMLAUTS


@needs_dos_latin
def test_decode_reads_cp850_umlauts() -> None:
    assert autostart._decode(("FEHLER: Ungültiger Wert für /SC, Größe " + UMLAUTS).encode("cp850")) == (
        "FEHLER: Ungültiger Wert für /SC, Größe " + UMLAUTS
    )


def test_decode_never_raises_on_garbage() -> None:
    text = autostart._decode(b"\xff\xfe\x81\x00\xc3")
    assert isinstance(text, str) and text


# --- Standard-Ausführer ----------------------------------------------------------------------


def test_default_run_on_windows_hides_the_console_window(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    fake = FakeSubprocess(monkeypatch, rc=3, out="Fertig".encode("utf-8"), err=b"")
    assert autostart._default_run([SCHTASKS, "/Query"], 10.0) == (3, "Fertig", "")
    (args, kwargs), = fake.calls
    assert args == [SCHTASKS, "/Query"]
    assert kwargs["creationflags"] == 0x08000000
    assert kwargs["capture_output"] is True and kwargs["check"] is False
    assert kwargs["timeout"] == 10.0
    assert kwargs["stdin"] == subprocess.DEVNULL
    assert not kwargs.get("shell")  # niemals über eine Shell


def test_default_run_outside_windows_sets_no_creationflags(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    fake = FakeSubprocess(monkeypatch)
    autostart._default_run(["x"], 1.0)
    assert "creationflags" not in fake.calls[0][1]


@needs_dos_latin
def test_default_run_decodes_cp850_output(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeSubprocess(monkeypatch, rc=1, out="Größe".encode("cp850"), err=("FEHLER: Für " + UMLAUTS).encode("cp850"))
    assert autostart._default_run(["x"], 1.0) == (1, "Größe", "FEHLER: Für " + UMLAUTS)


def test_public_functions_use_the_default_run_with_full_schtasks_path(
    windows: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeSubprocess(monkeypatch, rc=0)
    assert autostart_status().enabled is True
    (args, kwargs), = fake.calls
    assert args == [SCHTASKS, "/Query", "/TN", "Netzwerkscanner"]
    assert kwargs["timeout"] == 10.0 and kwargs["creationflags"] == 0x08000000


@needs_dos_latin
def test_set_autostart_default_run_reports_cp850_error_text(windows: None, monkeypatch: pytest.MonkeyPatch) -> None:
    FakeSubprocess(monkeypatch, rc=1, err="FEHLER: Ungültiger Wert für /SC. Größe überschritten.".encode("cp850"))
    with pytest.raises(AutostartError, match="Ungültiger Wert für /SC. Größe überschritten."):
        set_autostart(True)


def test_default_run_timeout_becomes_autostart_error(windows: None, monkeypatch: pytest.MonkeyPatch) -> None:
    FakeSubprocess(monkeypatch, raises=subprocess.TimeoutExpired("schtasks", 10.0))
    with pytest.raises(AutostartError, match="nicht innerhalb von 10 s"):
        set_autostart(True)
    assert autostart_status().enabled is False  # die Abfrage wirft nie


def test_default_run_missing_schtasks_becomes_autostart_error(windows: None, monkeypatch: pytest.MonkeyPatch) -> None:
    FakeSubprocess(monkeypatch, raises=FileNotFoundError(2, "Das System kann die angegebene Datei nicht finden"))
    with pytest.raises(AutostartError, match="nicht starten"):
        set_autostart(False)
    status = autostart_status()
    assert status.supported is True and status.enabled is False and "nicht starten" in status.detail
