# Netzwerkscanner – Stufe 1 und 2

Zeigt alle Geräte im eigenen Heimnetz als Inventar und Netzwerkkarte im Browser. Ein neues,
unbekanntes Gerät fällt sofort auf. Grundlage: [Pflichtenheft](Pflichtenheft%20Netzwerkscanner.md),
technischer Vertrag: [docs/BAUPLAN.md](docs/BAUPLAN.md).

**Stufe 1 kann:** Adapterwahl, Gerätesuche (ARP über Npcap plus paralleler Ping), Hersteller
(IEEE-Liste), private MAC-Adressen, Namen (DNS, NetBIOS, mDNS), UPnP-Beschreibung, Port-Scan
auf 35 häufige Ports mit Risikostufe, Tiefenscan 1–1024 je Gerät, Einordnung (Router, Switch,
Server/NAS, PC, Drucker, IoT, Handy), Inventar mit eigenem Namen, Notiz und „bekannt“,
Netzwerkkarte, Scan-Protokoll und Export als JSON, CSV und HTML.

**Stufe 2 kann (Überwachung):** ausgewählte Geräte zyklisch prüfen (Standard alle 60 s; Ping, ohne Antwort ein
TCP-Port), Dienste einzeln prüfen (SMB-Freigabe, Weboberfläche HTTP/HTTPS mit Antwortcode, SSH, TCP), Vorschläge
aus dem Port-Scan, Antwortzeit und Verfügbarkeit über 24 Stunden und 7 Tage, Alerts für „Gerät offline“,
„Dienst ausgefallen“, „Antwortzeit hoch“, „neues unbekanntes Gerät“ und „neuer offener Port“ (quittierbar),
Diagramme (Antwortzeit-Verlauf, Status-Übersicht, Verfügbarkeits-Trend, Alert-Häufigkeit) und optional Start mit
der Windows-Anmeldung.

## Voraussetzungen (einmalig)

1. **Windows 10 oder 11**, **Python 3.12 oder neuer** von python.org.
2. **Npcap** von npcap.com, Option **„WinPcap API-compatible Mode“ aus**. WinPcap 4.1.3 vorher
   deinstallieren. Ohne Npcap gibt es nur die Ping-Suche.
3. **Standortberechtigung (optional).** Seit Windows 11 24H2 gibt Windows den WLAN-Namen nur mit
   Standortberechtigung heraus. Ohne sie erkennt der Scanner das WLAN am Namen des
   Windows-Netzwerkprofils (`Get-NetConnectionProfile`). Das reicht für das Heimnetz und für die
   Hotspot-Sperre, solange das Profil so heißt wie das WLAN, was beim ersten Verbinden der Fall ist.

## Starten

| Aufruf | Wirkung |
|---|---|
| `start.bat` (Doppelklick) | legt beim ersten Mal die Python-Umgebung an (`%LOCALAPPDATA%\Netzwerkscanner\venv`, braucht einmal Internet), startet den Server **mit Adminrechten** in einem eigenen Fenster und öffnet den Browser **ohne Adminrechte** unter <http://127.0.0.1:8765> |
| `start.bat /noadmin` | ohne Adminrechte, nur Ping-Suche |
| `start.bat /demo` | **Demo** mit simuliertem Heimnetz auf 127.0.0.x – sendet nichts ins echte Netz |

Beendet wird der Scanner im Server-Fenster mit Strg+C.

**Erster Scan:** Ein grünes Band zeigt „Netz frei“. Der Scan startet ohne Rückfrage. Im Schul-Hotspot zeigt ein
rotes Band „Scan gesperrt“, dann ist der Start-Knopf aus.

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
- **Frei nutzbar außer in der Schule:** Jedes nicht gesperrte Netz wird ohne Rückfrage gescannt. Nachgefragt
  wird nur, wenn sich nicht prüfen lässt, ob es die Schule ist, weil Windows weder WLAN-Namen noch Netzwerkprofil
  nennt. Die frühere Rückfrage in fremden Netzen gibt es weiter als Einstellung „Vor fremden Netzen nachfragen“.
  In fremden Netzen gilt: nur mit Erlaubnis des Netzbetreibers scannen.
- **Schonend:** höchstens 200 Pakete bzw. Verbindungsversuche pro Sekunde, kurze Wartezeiten,
  Standard-Port-Scan nur auf häufige Ports. Empfindliche Geräte oder ganze Kategorien lassen sich
  vom Port-Scan ausnehmen. Keine Passwort-Rateversuche, keine Exploits.
- **Daten bleiben lokal:** eine SQLite-Datei in `%LOCALAPPDATA%\Netzwerkscanner\data`. Exporte entstehen
  nur auf Knopfdruck als Download. Ins Internet geht nur „Herstellerliste aktualisieren“ (ieee.org, ca. 4 MB).

## Überwachung (Stufe 2)

- **Gerät überwachen:** Gerät anklicken → Abschnitt „Überwachung“ → einschalten, gewünschte Dienste anhaken.
  Bei Handys erscheint ein Hinweis: Die Überwachung macht sichtbar, wann eine Person zu Hause ist.
- **Reiter Überwachung:** Zustand aller überwachten Geräte, „Jetzt prüfen“, Diagramme je Gerät (24 h, 7 d, 30 d,
  1 Jahr). **Reiter Alerts:** aktive und frühere Alerts, einzeln oder alle quittieren.
- **Einstellungen → Überwachung:** an/aus, Intervall (10–3600 s), Zeitschwellen für die Alerts, Alerts für neue
  Geräte und Ports.
- **Schulsperre gilt auch hier:** Vor jedem Durchlauf fragt der Monitor den Netz-Wächter. Im Schul-Hotspot (oder
  einem anderen gesperrten Netz) pausiert er und sendet nichts. In einem anderen Netz mit gleichem Adressbereich
  (anderer Router) pausiert er ebenfalls.
- **Erster Scan = Grundbestand:** Der allererste Scan löst keine „Neues Gerät“-Alerts aus. „Neuer offener Port“
  meldet nur Ports, die vorher schon geprüft und geschlossen waren.
- **Eigener PC:** Seine Ports prüft der Scanner von sich selbst aus; die Windows-Firewall wirkt dabei nicht. Von
  anderen Geräten aus können diese Ports gesperrt sein (Firewall-Auswertung folgt in Stufe 3).
- **Platz auf der Platte:** Rohwerte 30 Tage, danach Stundenmittel. 10 Geräte mit je 2 Diensten ≈ 30–60 MB nach
  30 Tagen, danach etwa 1 MB pro Monat. Die Statuszeile zeigt die Größe, ab 100 MB als Warnung. Bei extremen
  Einstellungen (sehr viele Dienste, sehr kurzes Intervall) verdichtet der Scanner früher, damit die Rohwerte
  höchstens etwa 250 MB belegen.
- **Autostart (Einstellungen → Autostart):** legt in der Aufgabenplanung die Aufgabe „Netzwerkscanner“ an, die
  den Server bei deiner Anmeldung **ohne Adminrechte** und ohne Fenster startet. Der Monitor braucht keine
  Adminrechte; ein ARP-Scan ist in diesem Betrieb nicht möglich (`start.bat` meldet dann „läuft bereits“).
  Bewusst ohne höchste Rechte, weil Projekt- und Python-Ordner ohne Adminrechte beschreibbar sind. In der Demo ist
  der Autostart gesperrt.

## Dateien und Logs

| Was | Wo |
|---|---|
| Datenbank | `%LOCALAPPDATA%\Netzwerkscanner\data\netscan.sqlite3` |
| Logdatei (1 MB × 3, rotierend) | `%LOCALAPPDATA%\Netzwerkscanner\data\logs\netscan.log` |
| Python-Umgebung | `%LOCALAPPDATA%\Netzwerkscanner\venv` (nicht in Dropbox) |
| Demo-Daten (bei jedem Demo-Start neu) | `%LOCALAPPDATA%\Netzwerkscanner\demo-data` |

Fehler bitte mit der Ausgabe des Server-Fensters und der Logdatei melden.

## Abnahme

Checklisten: [Stufe 1](docs/ABNAHME_STUFE1.md), [Stufe 2](docs/ABNAHME_STUFE2.md).

## Entwicklung

```bash
PYTHONDONTWRITEBYTECODE=1 "$LOCALAPPDATA/Netzwerkscanner/venv/Scripts/python.exe" -m pytest
```

- Die Tests laufen nur gegen 127.0.0.0/8 und Attrappen. `tests/conftest.py` sperrt jeden Verkehr ins
  echte Netz (TCP, UDP, Namensauflösung, Scapy, ping).
- GitHub führt die Tests bei jedem Hochladen auf Windows und Linux aus (`.github/workflows/tests.yml`).
- Aufbau: `netscan/core` (Datentypen, Ereignis-Warteschlange, Aufträge, Datenbank, Wächter),
  `netscan/platform` (Windows/Linux), `netscan/net` (Scan-Module), `netscan/scan/pipeline.py`
  (Ablauf), `netscan/web` (Server, Export, Oberfläche). Stufe 2: `core/monitor.py`, `core/targets.py`,
  `core/metrics.py`, `core/alerts.py`, `net/checks.py`, `web/monitor_api.py`, `web/static/monitor.js`,
  `platform/autostart.py`. Diagramme mit Chart.js 4.5.1 (lokal, MIT).
- Linux/Raspberry Pi: `start.sh` ist vorbereitet, in Stufe 1 aber nicht abgenommen.

## Bekannte Grenzen

- Topologie: Ohne verwaltete Switches zeigt die Karte einen Stern um den Router. Echte
  Verbindungen kommen in Stufe 3 (SNMP/LLDP).
- Repeater mit MAC-Umsetzung antworten für mehrere Geräte mit derselben MAC. Dann erscheint nur
  ein Eintrag, das Protokoll vermerkt es.
- Die Einordnung ist eine Schätzung und lässt sich im Gerät jederzeit korrigieren.
- Überwachung unter Windows: Ein geschlossener Port meldet sich dort erst nach etwa 2 s und erscheint deshalb als
  „keine Antwort“ statt „Port geschlossen“.
- Port 8883 wird nur nach der Nummer als „MQTT über TLS“ eingeordnet; ob wirklich verschlüsselt wird, prüft erst
  Stufe 3.
