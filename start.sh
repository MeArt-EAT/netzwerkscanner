#!/usr/bin/env bash
# Netzwerkscanner unter Linux (z. B. Raspberry Pi) – vorbereitet, in Stufe 1 nicht abgenommen.
# Startet mit sudo, weil der ARP-Scan rohe Pakete braucht. Oberfläche: http://127.0.0.1:8765
set -euo pipefail
cd "$(dirname "$0")"
APPHOME="${XDG_DATA_HOME:-$HOME/.local/share}/netzwerkscanner"
VENV="$APPHOME/venv"
export PYTHONDONTWRITEBYTECODE=1
if [ ! -x "$VENV/bin/python" ]; then
  mkdir -p "$APPHOME"
  python3 -m venv "$VENV"
fi
"$VENV/bin/python" -m pip install --disable-pip-version-check --no-cache-dir -q -r requirements.txt
if [ "${1:-}" = "--demo" ]; then
  exec "$VENV/bin/python" run_server.py --demo "$@"
fi
exec sudo --preserve-env=PYTHONDONTWRITEBYTECODE,NETSCAN_DATA_DIR "$VENV/bin/python" run_server.py "$@"
