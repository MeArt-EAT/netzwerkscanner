"""Start: python -m netscan [--port 8765] [--no-browser] [--data-dir PFAD] [--demo]

Die Oberfläche lauscht immer nur auf 127.0.0.1 – eine Option für andere Adressen gibt es nicht.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

from netscan import __version__, config


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m netscan",
        description="Netzwerkscanner – Oberfläche im Browser unter http://127.0.0.1:8765 (nur dieser PC).",
    )
    parser.add_argument("--port", type=int, default=config.DEFAULT_PORT, help="Port der Oberfläche (Standard 8765)")
    parser.add_argument("--no-browser", action="store_true", help="Browser nicht automatisch öffnen")
    parser.add_argument("--data-dir", help="anderer Datenordner (Standard: %%LOCALAPPDATA%%\\Netzwerkscanner\\data)")
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Demo mit simulierten Geräten auf 127.0.0.x – sendet nichts ins echte Netz",
    )
    parser.add_argument("--version", action="version", version=f"Netzwerkscanner {__version__}")
    args = parser.parse_args(argv)

    if not 1024 <= args.port <= 65535:
        print("Port muss zwischen 1024 und 65535 liegen.", file=sys.stderr)
        return 2
    if args.data_dir:
        os.environ["NETSCAN_DATA_DIR"] = args.data_dir

    if args.demo:
        from netscan import demo

        services = demo.build_demo_services()
        base = services.data_dir
        log_path = config.setup_logging(base)
    else:
        base = config.data_dir()
        log_path = config.setup_logging(base)
        from netscan.core.services import build_services

        services = build_services(base)

    log = logging.getLogger("netscan")
    log.info("Netzwerkscanner %s – Daten in %s, Logdatei %s", __version__, base, log_path)
    if args.demo:
        log.info("DEMO-MODUS: simulierte Geräte auf 127.0.0.x, kein Verkehr ins echte Netz.")
    elif not services.platform.is_admin():
        log.warning("Ohne Adminrechte: ARP-Scan nicht möglich, nur Ping-Suche. Besser über start.bat starten.")

    from netscan.web import server

    try:
        server.run(port=args.port, open_browser=not args.no_browser, services=services)
    finally:
        services.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
