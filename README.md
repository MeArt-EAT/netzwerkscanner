# Netzwerkscanner – Stufe 1

Zeigt alle Geräte im eigenen Heimnetz als Inventar und Netzwerkkarte im Browser. Ein neues,
unbekanntes Gerät fällt sofort auf. Grundlage: [Pflichtenheft](Pflichtenheft%20Netzwerkscanner.md),
technischer Vertrag: [docs/BAUPLAN.md](docs/BAUPLAN.md).

**Stufe 1 kann:** Adapterwahl, Gerätesuche (ARP über Npcap plus paralleler Ping), Hersteller
(IEEE-Liste), private MAC-Adressen, Namen (DNS, NetBIOS, mDNS), UPnP-Beschreibung, Port-Scan
auf 35 häufige Ports mit Risikostufe, Tiefenscan 1–1024 je Gerät, Einordnung (Router, Switch,
Server/NAS, PC, Drucker, IoT, Handy), Inventar mit eigenem Namen, Notiz und „bekannt“,
Netzwerkkarte, Scan-Protokoll und Export als JSON, CSV und HTML.

## Voraussetzungen (einmalig)

1. **Windows 10 oder 11**, **Python 3.12 oder neuer** von python.org.
2. **Npcap** von npcap.com, Option **„WinPcap API-compatible Mode“ aus**. WinPcap 4.1.3 vorher
   deinstallieren. Ohne Npcap gibt es nur die Ping-Suche.
3. **Standortberechtigung einschalten.** Seit Windows 11 24H2 gibt Windows den WLAN-Namen nur
   damit heraus. Einstellungen → Datenschutz und Sicherheit → Standort: „Standortdienste“ an und
   „Desktop-Apps den Zugriff auf Ihren Standort erlauben“ an. Ohne diese Berechtigung erkennt die
   Hotspot-Sperre den Schul-Hotspot nur am Namen des Windows-Netzwerkprofils (beim ersten Verbinden
   gleich dem WLAN-Namen) oder an einer früher gemerkten Router-Adresse. „Das ist mein Heimnetz“ geht
   über WLAN dann nicht; die Oberfläche zeigt einen roten Hinweis. `start.bat` weist ebenfalls darauf hin.

## Starten

| Aufruf | Wirkung |
|---|---|
| `start.bat` (Doppelklick) | legt beim ersten Mal die Python-Umgebung an (`%LOCALAPPDATA%\Netzwerkscanner\venv`, braucht einmal Internet), startet den Server **mit Adminrechten** in einem eigenen Fenster und öffnet den Browser **ohne Adminrechte** unter <http://127.0.0.1:8765> |
| `start.bat /noadmin` | ohne Adminrechte, nur Ping-Suche |
| `start.bat /demo` | **Demo** mit simuliertem Heimnetz auf 127.0.0.x – sendet nichts ins echte Netz |

Beendet wird der Scanner im Server-Fenster mit Strg+C.

**Erster Scan:** Das gelbe Band fragt, ob dies dein Heimnetz ist. „Das ist mein Heimnetz“ merkt sich
die MAC-Adresse des Routers. Danach scannt der Scanner dort ohne Rückfrage.

## Sicherheit

- Die Oberfläche lauscht **nur auf 127.0.0.1**. Andere Geräte im WLAN erreichen sie nicht.
  Fremde Webseiten können sie nicht fernsteuern: Host-, Origin- und Content-Type-Prüfung sowie
  eine CSP ohne Inline-Skripte.
- **Schul-Hotspot „DE22LA000256314 8159“:** Jeder Scan ist gesperrt, auch im Modus „nur eingetragene
  Geräte“ und beim Tiefenscan. Es gibt keine Schaltfläche, keinen Parameter und keine Einstellung zum
  Übergehen. Gesperrt wird nur der exakte Name, ein ähnlicher nicht. Die Router-MAC des Hotspots wird
  gemerkt, damit die Sperre auch bei nicht lesbarem WLAN-Namen greift; zusätzlich zählt dann der Name
  des Windows-Netzwerkprofils (nur zum Sperren, nie zum Freigeben). Weitere Namen lassen sich in
  den Einstellungen ergänzen.
- **Modus „nur eingetragene Geräte“:** fragt nur die gespeicherten Adressen ab, ohne Multicast-Suche
  (mDNS, SSDP). Antwortet dort ein nicht eingetragenes Gerät (auch ein fremder Router), wird es weder
  gespeichert noch weiter geprüft.
- **Fremde oder unklare Netze:** erst Warnung, Scan nur nach Bestätigung. Fremde Netze, auch das
  Schulnetz, nur mit Freigabe des Netzbetreibers scannen.
- **Schonend:** höchstens 200 Pakete bzw. Verbindungsversuche pro Sekunde, kurze Wartezeiten,
  Standard-Port-Scan nur auf häufige Ports. Empfindliche Geräte oder ganze Kategorien lassen sich
  vom Port-Scan ausnehmen. Keine Passwort-Rateversuche, keine Exploits.
- **Daten bleiben lokal:** eine SQLite-Datei in `%LOCALAPPDATA%\Netzwerkscanner\data`. Exporte entstehen
  nur auf Knopfdruck als Download. Ins Internet geht nur „Herstellerliste aktualisieren“ (ieee.org, ca. 4 MB).

## Dateien und Logs

| Was | Wo |
|---|---|
| Datenbank | `%LOCALAPPDATA%\Netzwerkscanner\data\netscan.sqlite3` |
| Logdatei (1 MB × 3, rotierend) | `%LOCALAPPDATA%\Netzwerkscanner\data\logs\netscan.log` |
| Python-Umgebung | `%LOCALAPPDATA%\Netzwerkscanner\venv` (nicht in Dropbox) |
| Demo-Daten (bei jedem Demo-Start neu) | `%LOCALAPPDATA%\Netzwerkscanner\demo-data` |

Fehler bitte mit der Ausgabe des Server-Fensters und der Logdatei melden.

## Abnahme

Checkliste: [docs/ABNAHME_STUFE1.md](docs/ABNAHME_STUFE1.md).

## Entwicklung

```bash
PYTHONDONTWRITEBYTECODE=1 "$LOCALAPPDATA/Netzwerkscanner/venv/Scripts/python.exe" -m pytest
```

- Die Tests laufen nur gegen 127.0.0.0/8 und Attrappen. `tests/conftest.py` sperrt jeden Verkehr ins
  echte Netz (TCP, UDP, Namensauflösung, Scapy, ping).
- GitHub führt die Tests bei jedem Hochladen auf Windows und Linux aus (`.github/workflows/tests.yml`).
- Aufbau: `netscan/core` (Datentypen, Ereignis-Warteschlange, Aufträge, Datenbank, Wächter),
  `netscan/platform` (Windows/Linux), `netscan/net` (Scan-Module), `netscan/scan/pipeline.py`
  (Ablauf), `netscan/web` (Server, Export, Oberfläche).
- Linux/Raspberry Pi: `start.sh` ist vorbereitet, in Stufe 1 aber nicht abgenommen.

## Bekannte Grenzen

- Topologie: Ohne verwaltete Switches zeigt die Karte einen Stern um den Router. Echte
  Verbindungen kommen in Stufe 3 (SNMP/LLDP).
- Repeater mit MAC-Umsetzung antworten für mehrere Geräte mit derselben MAC. Dann erscheint nur
  ein Eintrag, das Protokoll vermerkt es.
- Die Einordnung ist eine Schätzung und lässt sich im Gerät jederzeit korrigieren.
