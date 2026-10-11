# Übergabe an den nächsten Chat – Stand 11.10.2026, 08:05 Uhr

Einstieg: diese Datei, dann das [Pflichtenheft](../Pflichtenheft%20Netzwerkscanner.md), dann der [Bauplan](BAUPLAN.md)
(Teil 1 §1–17, Teil 2 §18–34). Den alten Chatverlauf braucht es nicht.

## 0. Kurzstand

| Stufe | Stand | Wo |
|---|---|---|
| 1 Kern und Oberfläche | **fertig**, Tag `v1.0-stufe1` (11.10.2026) | `main`, Projektordner |
| 2 Überwachung | **gebaut**, Tag `v2.0-stufe2-rc2`, Abnahme läuft (24-Stunden-Test) | Zweig `stufe-2`, Arbeitsordner `.claude\worktrees\stufe-2` |
| 3 Sicherheit und SNMP | nicht begonnen – erst nach der Abnahme von Stufe 2 | – |

Alles ist gepusht (`main`, `stufe-2`, alle Tags). GitHub Actions testet bei jedem Push auf `main` und bei Tags.

## 1. Stufe 1 – fertig

- 1013 Tests grün, 1 übersprungen. Testversionen: rc1 Prüfrunde (26 Befunde), rc2 frei nutzbar außer Schule,
  rc3 Geräte ohne Ping-Antwort über den ARP-Cache, rc4 ARP über WLAN.
- **ARP über WLAN gelöst (rc4):** Scapys `srp()` ordnete auf der Intel-WLAN-Karte die Antworten nicht zu, obwohl
  Npcap sie empfing (Diagnose `tools/arp_diagnose.py`, startet nur der Nutzer). Jetzt: Mitlesen (AsyncSniffer, nur
  ARP-Antworten) vor `sendp`, eigene Zuordnung. Bestätigt: „ARP-Scan: 21 bzw. 26 von 253“, 20–25 Geräte, 32–37 s mit
  Port-Scan.
- Noch offen aus [ABNAHME_STUFE1.md](ABNAHME_STUFE1.md): Hotspot-Tests und Export-Test. Befunde daraus als 1.0.x.

## 2. Stufe 2 – Abnahme läuft

- **Läuft beim Nutzer im Heimnetz** aus `.claude\worktrees\stufe-2\start.bat`, zuletzt neu gestartet am
  11.10.2026 um 07:53 Uhr. Für den Punkt „24 Stunden lückenlos“ nicht neu starten (frühestens 12.10., 07:53 Uhr).
- Stand 11.10., 08:00 Uhr (nur lesend geprüft): 8 überwachte Geräte, 10 Dienstprüfungen, keine Fehler im Log,
  größte Lücke 70 s (nur bei Neustarts), Datenbank 328 KB.
- Checkliste: `docs/ABNAHME_STUFE2.md` auf dem Zweig `stufe-2`. Inhalt und Entscheidungen: BAUPLAN §18–34,
  README-Abschnitt „Überwachung“, Istwerte in [PROGNOSE.md](PROGNOSE.md).
- 2202 Tests grün, 2 übersprungen. Prüfrunde: 25 Befunde, 12 bestätigt, zu 8 zusammengeführt, alle behoben.
- **Beobachtungen, die der Nutzer am 11.10. ausdrücklich „vorerst genau so lassen“ will** (nicht ungefragt umsetzen;
  als Vorschlag für 2.0.1 bereit, Schätzung 45–60 min mit Prüfrunde):
  1. iPhone-Offline-Alerts flattern (13 in 8 h, Verfügbarkeit 11 %): Handys im Standby antworten selten auf Ping.
     Ideen: Erreichbarkeit per ARP (Methode „arp“, nutzt den neuen ARP-Sender; Handys antworten auf ARP auch im
     Standby) und Offline-Alert erst nach stabiler Rückkehr schließen.
  2. Fritz!Box-Prüfungen HTTP 80 / HTTPS 443 schlugen am 10.10. um 23:21 Uhr fehl, der Nutzer hat sie abgeschaltet.
     Ursache unbekannt (Verdacht: Weboberfläche langsamer als `monitor_timeout_ms` = 1 s). Wieder einschalten zeigt
     den Grund im Detailbereich unter „Hinweis“.
  3. Eigener PC heißt „host.docker.internal“ (Eintrag von Docker Desktop); besser wäre der Windows-Rechnername.
- **Bewusst offen (BAUPLAN §34):** geschlossener Port unter Windows erst nach ~2 s („keine Antwort“), Ping des
  Monitors ohne Bindung an die Absenderadresse, Autostart nie echt aufgerufen (prüft der Nutzer bei der Abnahme).
- **Nach der Abnahme:** `stufe-2` in `main` zusammenführen (Rezept Abschnitt 5), Tag `v2.0-stufe2`, Übergabe
  und Prognose-Istwerte nachtragen, Memory aktualisieren.

## 3. Stufe 3 – Sicherheit und SNMP (nächster Bau)

Inhalt laut Pflichtenheft (rund 35 % des Gesamtaufwands):
- Betriebssystem-Schätzung, SSL/TLS-Prüfung (Aussteller, Ablauf, Selbstsignatur, TLS-Version, Warnung 30 Tage
  vorher), Risiko-Dashboard mit Abhilfe, **Warnung vor Klartext-Anmeldung** (nur passiv, kein Mitschnitt, nie
  Passwörter anzeigen), Reiter „Sicherheit“.
- SNMP: Erkennung ohne Zugangsdaten (SNMPv3-Discovery), SNMPv3-Leseprofil über `keyring`, v2c nur gezielt je
  Gerät, Switches (MAC-Tabelle, Interfaces, VLANs, LLDP → echte Verbindungen in der Karte), Synology DS720+
  (System, Temperatur, Lüfter, Platten, RAID, Volumes, DSM-Update), Alerts für Platten/RAID/Temperatur/Volume,
  Einrichtungshinweis beim Mouseover, Berichte (Sicherheit, Zustand, Topologie).

Zusätzlich vorgemerkt:
- Firewall-Auswertung beim eigenen PC (`Get-NetFirewallRule` je Port und Profil): „lokal offen, von außen gesperrt“.
- Echte TLS-Prüfung klärt Port 8883 (Mosquitto des Nutzers lauscht dort im Klartext).
- Optional: SIO_TCP_INITIAL_RTO gegen die 2-s-Verzögerung bei abgelehnten Verbindungen (in `platform/`);
  `Platform.ping` mit Absenderadresse.
- Neuer Reiter über die Schnittstelle `window.NetscanApp` (BAUPLAN §34).

Vorbereitung durch den Nutzer: SNMP auf der Synology einschalten und das Leseprofil anlegen (der Scanner zeigt den
Weg). Ob verwaltete Switches vorhanden sind, ist im Pflichtenheft noch offen.

Prognose (vor dem Bau neu bestätigen): 3–4 h, 25–35 % eines 5-Stunden-Fensters, Woche +6–8 %, 18.000–23.000
Zeilen. **Vor dem Start nach Freigabe und Plattenbudget fragen** (globale Regel; Stufe 2: 79 MB von 400 MB).

Bauort: nach dem Zusammenführen von Stufe 2 einen neuen Arbeitsordner anlegen
(`git worktree add .claude/worktrees/stufe-3 -b stufe-3 main` – das erstmalige Anlegen funktioniert, nur spätere
`checkout`/`merge` darin scheitern an Dropbox) und im Projektordner auf `main` bleiben.

## 4. Feste Entscheidungen des Nutzers (nicht wieder aufrollen)

- **Frei nutzbar außer in der Schule.** Nicht gesperrte Netze ohne Rückfrage; die alte Rückfrage nur als
  Einstellung `ask_before_foreign_scan` (Standard aus).
- **Die Standortberechtigung bleibt aus.** Nicht wieder vorschlagen. WLAN-Erkennung über den Windows-Netzwerkprofil-
  namen (`Get-NetConnectionProfile`); Profile „Welt“ (Heimnetz) und „DE22LA000256314 8159“ (Schul-Hotspot).
- **Schulsperre:** Hotspot-Name, gelernte Router-MAC, eigene gesperrte Namen. Kein Weg zum Übergehen. Gilt auch für
  den Monitor (pausiert) und für `tools/arp_diagnose.py`.
- **Claude sendet selbst keine Pakete ins Heimnetz** (Grundsatz 8). Diagnose nur lesend (Datenbank mit `?mode=ro`,
  Logdatei, netsh, arp -a, Get-NetAdapter) oder über ein Skript, das der Nutzer selbst startet. Tests nur gegen
  127.0.0.0/8 (`tests/conftest.py` sperrt alles andere, auch `schtasks` und Scapy einschließlich `AsyncSniffer`).
- **Autostart** nur ohne Adminrechte (`/RL LIMITED`, `/RU <Benutzer>`, `/IT`), nie `HIGHEST`.
- **Prognose** vor jedem Bau (Dauer, Kontingent, Tokens, Umfang, Plattenbudget), Istwerte in PROGNOSE.md.
- **Beobachtungen aus Abschnitt 2 vorerst nicht umsetzen.**

## 5. Git im Dropbox-Ordner – wichtig

Dropbox markiert Ordner und Dateien als Cloud-Platzhalter (Reparse-Point). Git-Befehle, die Dateien auschecken
(`checkout`, `merge` im Arbeitsordner), brechen dann ab („cannot create directory at 'netscan'“, „Invalid
argument“). `status`, `diff`, `commit`, `push` funktionieren.
- **Nie `git checkout` im Projektordner** (auch nicht vom Nutzer). Stufe 2 startet aus dem Arbeitsordner.
- **Zusammenführen ohne Checkout:** `git merge-tree --write-tree <ziel> <quelle>` (Baum-ID, Konflikte prüfen) →
  `git commit-tree <baum> -p <ziel> -p <quelle> -m "…"` → `git update-ref refs/heads/<ziel> <commit> <alter-stand>`
  → geänderte Dateien selbst aus `HEAD` schreiben (Python `write_bytes`, gelöschte entfernen) → `git add -- <dateien>`
  zum Auffrischen des Index. So wurde der ARP-Fix nach `stufe-2` übernommen (Commit a7a8a06).
- Meldet Git bei einer Datei „Invalid argument“: Datei mit gleichem Inhalt neu schreiben (über eine Temp-Datei).
- **Zeilenenden:** `.gitattributes` verlangt LF. Python `write_text` erzeugt unter Windows CRLF – Dateien mit
  `write_bytes` schreiben. In Bash-Heredocs keine Backslash-Folgen; Skripte mit dem Write-Werkzeug anlegen.

## 6. Umgebung

| Was | Wo |
|---|---|
| Projekt (`main`) | `C:\Users\meyer\Dropbox\_6.Block\X-Claude-LF11EA\Claude_Code\Network` |
| Stufe 2 (`stufe-2`) | `…\Network\.claude\worktrees\stufe-2` (von Git ignoriert, Dropbox sichert mit) |
| Repository | <https://github.com/MeArt-EAT/netzwerkscanner> (privat). Kein `gh`; Push über den Git Credential Manager |
| Python | `%LOCALAPPDATA%\Netzwerkscanner\venv\Scripts\python.exe` (3.13, außerhalb von Dropbox), `pythonw.exe` daneben |
| Daten / Log | `%LOCALAPPDATA%\Netzwerkscanner\data\netscan.sqlite3` (Schema 2), `…\data\logs\netscan.log` |
| Demo | `start.bat /demo`; Browser-Bereich: `.claude/launch.json` im Projektordner mit `netscan-demo` (8798, Stufe 1) und `netscan-demo-stufe2` (8799, Arbeitsordner) |
| Npcap | 1.89 ohne WinPcap-Modus, `AdminOnly = 0` (Mitlesen auch ohne Adminrechte) |
| WLAN-Karte | Intel AX201, Treiber 24.20.0.4; Filtertreiber Shrew Soft, VirtualBox Bridged, AVM VPN (unschädlich) |

Testbefehl (Git Bash, im jeweiligen Ordner):

```bash
PYTHONDONTWRITEBYTECODE=1 /c/Users/meyer/AppData/Local/Netzwerkscanner/venv/Scripts/python.exe -m pytest -p no:cacheprovider -o addopts="" -q
```

Heimnetz grob: /24 über WLAN, Fritz!Box mit zwei Repeatern (MAC-Umsetzung: .202/.204 antworten mit der Router-MAC),
Synology DS720+ (zwei Netzwerkkarten), Brother-Drucker, ESP-/Shelly-/Solar-Geräte (u. a. APsystems, Marstek),
Haushaltsgeräte, iPhone, Android (A55), Mosquitto auf dem PC (1883/8883).

## 7. Arbeitsweise (bewährt in Stufe 1 und 2)

1. **Prognose** und Freigabe mit Plattenbudget, dann Bau im Arbeitsordner.
2. **Leitung (Hauptchat, Opus):** Bauplan-Teil und Kern selbst, inklusive Attrappen (`tests/fakes.py`) und
   Sim-Labor (`tests/sim.py`).
3. **Bau (Workflow):** 6–7 Agenten mit getrennten Schreibbereichen; Anspruchsvolles `ingenieur` (Opus), Routine
   `zeichner` (Sonnet); abhängige Teile (z. B. Demo) starten, wenn ihre Grundlagen fertig sind.
4. **Zusammenbau:** Vertragsfragen der Agenten entscheiden und im Bauplan festhalten, ganze Suite, Demo im
   Browser-Bereich prüfen.
5. **Prüfung (Workflow, Ultracode):** 4 Prüfer mit Schwerpunkten, je Befund 2 Gegenprüfer (bei Uneinigkeit ein
   dritter), Bündeln nach Schreibbereichen, Nachbesserung mit Regressionstests.
6. **Abschluss:** README, Checkliste, Prognose-Istwerte, Übergabe, Tag, nach Rückfrage pushen.

Nach jeder Phase `get_usage` und Plattenverbrauch messen. Kalibrierung Stufe 2: 2 h 55 min, ~21 % des Fensters,
Woche +5 %, 9,9 Mio. Agenten-Tokens (Prüfrunde 7,8 Mio.), 16.650 Zeilen, 79 MB Agent-Protokolle.

## 8. Bekannte Grenzen und Beobachtungen

- **Einordnung „unbekannt“** bei mehreren Smart-Home- und Solar-Geräten (FN-LINK „MSA-…“, Smart Innovation
  „S380HB“, Quectel „marstek“, Viessmann); die IoT-Herstellertabelle in `netscan/net/classify.py` ließe sich ergänzen.
- **Fritz-Repeater** melden eine private MAC und werden als Switch eingeordnet; vertretbar.
- **Lücke beim Profilnamen:** Heißt das Windows-Profil des Hotspots anders als die SSID, greift nur die gelernte
  Router-MAC.
- **Start mit Adminrechten aus beschreibbaren Ordnern (Aufgabe):** `start.bat` startet Code aus dem Dropbox-Ordner
  mit Adminrechten; Projektordner und Python-Umgebung sind ohne Adminrechte änderbar. Lösung (noch offen): ein
  Installationsschritt nach `C:\Program Files\Netzwerkscanner`, Start dort mit `python -I` und festen Argumenten.
  Bis dahin prüft der Nutzer vor jedem Start mit Adminrechten `git status` (Projekt- bzw. Arbeitsordner).
