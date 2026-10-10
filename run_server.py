"""Startskript für start.bat: findet das Paket unabhängig vom Arbeitsordner (Adminfenster startet in System32)
und lässt das Fenster bei einem Fehler offen, damit die Meldung lesbar bleibt."""

from __future__ import annotations

import os
import sys
import traceback

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
os.chdir(HERE)


def _pause() -> None:
    try:
        input("\nEnter drücken zum Schließen …")
    except (EOFError, KeyboardInterrupt):
        pass


def _quiet_console() -> object:
    """QuickEdit im Server-Fenster abschalten: Ein Klick ins Fenster würde sonst den Markiermodus starten,
    und dann blockiert jede Konsolenausgabe Oberfläche und Scan. Gibt die Funktion zum Zurückstellen zurück."""
    try:
        from netscan.platform.windows import disable_quick_edit

        return disable_quick_edit()
    except Exception:  # noqa: BLE001 – ohne diese Hilfe läuft der Server genauso
        return None


if __name__ == "__main__":
    restore = _quiet_console()
    try:
        from netscan.__main__ import main

        code = main(sys.argv[1:])
    except KeyboardInterrupt:
        code = 0
    except SystemExit as exc:
        code = int(exc.code or 0) if not isinstance(exc.code, str) else 1
        if code:
            _pause()
    except Exception:
        traceback.print_exc()
        print("\nDer Scanner wurde wegen eines Fehlers beendet. Bitte diese Ausgabe und die Logdatei melden:")
        print(os.path.join(os.environ.get("LOCALAPPDATA", "~"), "Netzwerkscanner", "data", "logs", "netscan.log"))
        _pause()
        code = 1
    finally:
        if callable(restore):
            restore()
    sys.exit(code)
