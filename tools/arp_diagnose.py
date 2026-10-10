"""ARP-Diagnose für die WLAN-Karte (Npcap) – startet NUR der Nutzer selbst.

Was gesendet wird (nur an den eigenen Router im WLAN): 3 Pings des Betriebssystems und höchstens 5 ARP-Anfragen.
Im Schul-Hotspot bricht das Skript sofort ab, ohne etwas zu senden. Es ändert nichts am System.
Ergebnis: Konsole und eine kleine Textdatei %LOCALAPPDATA%\\Netzwerkscanner\\data\\logs\\arp_diagnose.txt.

Start (aus dem Projektordner, Python-Umgebung des Scanners, isoliert):
  "%LOCALAPPDATA%\\Netzwerkscanner\\venv\\Scripts\\python.exe" -I tools\\arp_diagnose.py
"""

from __future__ import annotations

import ipaddress
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

ADAPTER = "WLAN"
BLOCKED = ("DE22LA000256314 8159",)  # Schul-Hotspot: hier nie senden
CREATE_NO_WINDOW = 0x08000000
LINES: list[str] = []


def say(text: str = "") -> None:
    LINES.append(text)
    try:
        print(text, flush=True)
    except UnicodeEncodeError:
        print(text.encode("ascii", "replace").decode(), flush=True)


def ps(command: str) -> str:
    res = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, timeout=20, creationflags=CREATE_NO_WINDOW,
    )  # fmt: skip
    for enc in ("utf-8", "cp850"):
        try:
            return res.stdout.decode(enc).strip()
        except UnicodeDecodeError:
            continue
    return res.stdout.decode("utf-8", "replace").strip()


def main() -> int:
    say("ARP-Diagnose Netzwerkscanner – " + time.strftime("%d.%m.%Y %H:%M:%S"))
    say("=" * 60)

    # --- 0. Sicherheit: Netz prüfen, bevor irgendetwas gesendet wird -----------------------------
    profile = ps(f"(Get-NetConnectionProfile -InterfaceAlias '{ADAPTER}' -ErrorAction SilentlyContinue).Name")
    ssid_out = ps("netsh wlan show interfaces")
    if any(b in profile or b in ssid_out for b in BLOCKED):
        say("ABBRUCH: Verbunden mit dem Schul-Hotspot – hier wird nichts gesendet.")
        return 2
    gateway = ps(f"(Get-NetRoute -InterfaceAlias '{ADAPTER}' -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue "
                 "| Sort-Object RouteMetric | Select-Object -First 1).NextHop")  # fmt: skip
    say(f"Netzwerkprofil: {profile or '(unbekannt)'}")
    say(f"Router (Standard-Gateway über {ADAPTER}): {gateway or '(keiner)'}")
    if not gateway:
        say("ABBRUCH: Kein Router über die WLAN-Karte gefunden.")
        return 2

    say()
    say("Treiber an der WLAN-Karte (aktiv):")
    say(ps(f"Get-NetAdapterBinding -Name '{ADAPTER}' | Where-Object Enabled | ForEach-Object {{ '  ' + $_.DisplayName + ' (' + $_.ComponentID + ')' }}"))

    # --- Scapy / Npcap ---------------------------------------------------------------------------
    try:
        import scapy
        from scapy.all import ARP, Ether, conf, sendp, sniff, srp
    except Exception as exc:  # noqa: BLE001
        say(f"ABBRUCH: Scapy/Npcap nicht ladbar: {exc}")
        return 2
    iface = next((i for i in conf.ifaces.values() if i.name == ADAPTER), None)
    if iface is None:
        say(f"ABBRUCH: Scapy kennt die Schnittstelle „{ADAPTER}“ nicht.")
        return 2
    my_ip = (iface.ips.get(4) or [None])[0]
    my_mac = iface.mac
    say()
    say(f"Scapy {scapy.__version__}, Schnittstelle {iface.network_name}")
    say(f"Eigene Adresse {my_ip}, MAC {my_mac}")
    try:
        net = ipaddress.ip_network(f"{my_ip}/24", strict=False)
        if ipaddress.ip_address(gateway) not in net:
            say("ABBRUCH: Router liegt nicht im Netz der WLAN-Karte.")
            return 2
    except ValueError:
        say("ABBRUCH: Adressen nicht lesbar.")
        return 2

    results: dict[str, object] = {}

    # --- A: Empfängt Npcap überhaupt etwas? (3 Pings des Betriebssystems) ------------------------
    say()
    say("Test A: Mitlesen (5 s), während Windows den Router 3-mal anpingt …")
    captured: list = []

    def run_sniff() -> None:
        captured.extend(sniff(iface=iface, filter=f"host {gateway} and (icmp or arp)", timeout=5, promisc=False))

    t = threading.Thread(target=run_sniff, daemon=True)
    t.start()
    time.sleep(1.0)
    subprocess.run(["ping", "-n", "3", "-w", "500", gateway], capture_output=True, timeout=10, creationflags=CREATE_NO_WINDOW)
    t.join(8)
    icmp_in = sum(1 for p in captured if p.haslayer("ICMP") and p["IP"].src == gateway)
    icmp_out = sum(1 for p in captured if p.haslayer("ICMP") and p["IP"].dst == gateway)
    say(f"  mitgelesen: {len(captured)} Pakete – Ping-Anfragen raus {icmp_out}, Ping-Antworten rein {icmp_in}")
    results["A_rein"] = icmp_in
    results["A_raus"] = icmp_out

    # --- B/C: ARP-Anfrage wie der Scanner (srp), ohne und mit Promiscuous Mode --------------------
    request = Ether(dst="ff:ff:ff:ff:ff:ff", src=my_mac) / ARP(pdst=gateway, psrc=my_ip, hwsrc=my_mac)
    for key, promisc in (("B", False), ("C", True)):
        say()
        say(f"Test {key}: ARP-Anfrage an den Router wie im Scanner (promisc={promisc}) …")
        try:
            answered, _ = srp(request, iface=iface, timeout=2, retry=1, promisc=promisc, verbose=0)
            say(f"  Antworten: {len(answered)}" + (f" – Router-MAC {answered[0][1].hwsrc}" if answered else ""))
            results[key] = len(answered)
        except Exception as exc:  # noqa: BLE001
            say(f"  Fehler: {type(exc).__name__}: {exc}")
            results[key] = f"Fehler {type(exc).__name__}"

    # --- D: eigene ARP-Anfrage senden und dabei mitlesen (geht sie raus? kommt die Antwort an?) ---
    say()
    say("Test D: eigene ARP-Anfrage senden und 3 s mitlesen …")
    seen: list = []

    def run_sniff_arp() -> None:
        seen.extend(sniff(iface=iface, filter="arp", timeout=3, promisc=False))

    t = threading.Thread(target=run_sniff_arp, daemon=True)
    t.start()
    time.sleep(1.0)
    sendp(request, iface=iface, verbose=0)
    t.join(6)
    own_req = sum(1 for p in seen if p.haslayer(ARP) and p[ARP].op == 1 and p[ARP].hwsrc.lower() == my_mac.lower())
    replies = sum(1 for p in seen if p.haslayer(ARP) and p[ARP].op == 2 and p[ARP].psrc == gateway)
    say(f"  eigene Anfrage mitgelesen: {own_req} · Antworten des Routers: {replies} · ARP gesamt: {len(seen)}")
    results["D_anfrage"] = own_req
    results["D_antwort"] = replies

    # --- Auswertung --------------------------------------------------------------------------------
    say()
    say("Auswertung:")
    if not icmp_in and not icmp_out:
        say("  Npcap liest auf der WLAN-Karte GAR NICHTS mit (nicht einmal die Pings von Windows).")
        say("  -> Ursache liegt zwischen Npcap und Karte: Filtertreiber (Shrew Soft, VirtualBox, AVM VPN) oder Npcap.")
    elif results.get("B") or results.get("C"):
        say("  ARP funktioniert hier. Im Scanner dann die Blockgröße/Paketabstand prüfen.")
    elif replies:
        say("  Die Antwort des Routers kommt bei Npcap an, nur srp() ordnet sie nicht zu.")
        say("  -> Lässt sich im Scanner beheben (Senden und Mitlesen getrennt). Kein Eingriff am System nötig.")
    elif own_req:
        say("  Die Anfrage verlässt Npcap, aber keine Antwort kommt zurück: Die WLAN-Karte/ein Filter sendet")
        say("  eingeschleuste Rahmen nicht wirklich aus, oder Antworten an uns werden vorher verworfen.")
        say("  -> Nächster Schritt: Filtertreiber an der WLAN-Karte testweise abschalten (Shrew Soft zuerst).")
    else:
        say("  Mitlesen geht, aber die eigene Anfrage taucht nicht einmal im Mitschnitt auf: Senden über Npcap scheitert.")
        say("  -> Nächster Schritt: Filtertreiber testweise abschalten (Shrew Soft zuerst), sonst Npcap neu installieren.")
    say()
    say("Rohwerte: " + ", ".join(f"{k}={v}" for k, v in results.items()))

    out = Path(os.environ.get("LOCALAPPDATA", ".")) / "Netzwerkscanner" / "data" / "logs" / "arp_diagnose.txt"
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("\n".join(LINES) + "\n", encoding="utf-8")
        say(f"Gespeichert: {out}")
    except OSError as exc:
        say(f"(Datei nicht gespeichert: {exc})")
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        pass
    sys.exit(main())
