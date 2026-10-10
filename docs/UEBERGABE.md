# Übergabe an den nächsten Chat – Stand 10.10.2026, 22:15 Uhr

Diese Datei, das [Pflichtenheft](../Pflichtenheft%20Netzwerkscanner.md) und der [Bauplan](BAUPLAN.md) reichen
als Einstieg. Den alten Chatverlauf braucht es nicht.

## 0. Stufe 2 (Überwachung) – gebaut, Abnahme offen

- **Zweig `stufe-2`, Tag `v2.0-stufe2-rc1`.** Gebaut im Git-Arbeitsordner `.claude/worktrees/stufe-2`, damit der
  Projektordner für die Abnahme von Stufe 1 auf `main` bleibt. Nach der Abnahme von Stufe 1 und 2: `stufe-2` in
  `main` zusammenführen.
- Vertrag: [BAUPLAN.md](BAUPLAN.md) Teil 2 (§18–34, inkl. Entscheidungen der Prüfrunde). Checkliste:
  [ABNAHME_STUFE2.md](ABNAHME_STUFE2.md). Prognose und Istwerte: [PROGNOSE.md](PROGNOSE.md).
- Prüfrunde: 25 Befunde, 12 bestätigt (je 2 Gegenprüfer), zu 8 zusammengeführt, alle behoben (B6 Plattenbudget
  durch die Leitung).
- Bewusst offen (BAUPLAN §34): geschlossener Port unter Windows erst nach ~2 s (erscheint als „keine Antwort“),
  Ping des Monitors ohne Bindung an die Absenderadresse, Autostart nie echt aufgerufen (Abnahme durch den Nutzer).
- Für Stufe 3 vorgemerkt: Firewall-Auswertung beim eigenen PC, echte TLS-Prüfung (Port 8883), Warnung vor
  Klartext-Anmeldung, `window.NetscanApp` als Schnittstelle für neue Reiter, ggf. SIO_TCP_INITIAL_RTO.

## 1. Stand Stufe 1

- **Stufe 1 ist fertig** als Tag `v1.0-stufe1-rc3`, Branch `main`.
  - 997 Tests grün, 1 übersprungen.
  - GitHub Actions testet bei jedem Push auf Windows und Linux.
- **Abnahme im Heimnetz läuft.** Die Scans waren erfolgreich: 16–20 Geräte, etwa 31 s inklusive Port-Scan.
- **Verlauf der Testversionen:**
  - rc1: Prüfrunde mit 26 behobenen Befunden
  - rc2: frei nutzbar außer Schule
  - rc3: ARP über WLAN korrigiert

## 2. Offen, bevor der Tag `v1.0-stufe1` gesetzt wird

1. **ARP-Korrektur aus rc3 im Heimnetz bestätigen.**
   - Bisher lief der Server noch mit dem alten Stand (Start 17:21 Uhr, Korrektur 17:57 Uhr). Alle Scans meldeten „ARP-Scan: 0 von 253“.
   - Ablauf: Server-Fenster mit Strg+C schließen, `start.bat` neu starten, scannen.
   - Gutes Ergebnis: Im Scan-Protokoll steht „ARP-Scan: X von 253“ mit X > 0, und bei den Geräten taucht der Fundweg „arp“ auf.
   - Kommt wieder 0, greift die Ersatzsuche: Meldung „nur über den ARP-Cache gefunden“ plus eine Warnung. Dann weiter untersuchen (Ursache vermutlich der WLAN-Treiber, Abschnitt 6).
2. **Export-Test:** zurückgestellt. Der Nutzer testet ihn, wenn er gebraucht wird.
3. **Übrige Punkte** der [Abnahme-Checkliste](ABNAHME_STUFE1.md), z. B. die Tests mit dem Hotspot.
4. **Danach** `git tag -a v1.0-stufe1` setzen und pushen.

## 3. Feste Entscheidungen des Nutzers (nicht wieder aufrollen)

- **Frei nutzbar außer in der Schule.** Grundsatz 6 im Pflichtenheft ist geändert und datiert.
  - Nicht gesperrte Netze werden ohne Rückfrage gescannt (`allow`/`ok_network`).
  - Die alte Rückfrage gibt es nur noch als Einstellung `ask_before_foreign_scan`, Standard aus.
- **Die Standortberechtigung bleibt aus.** Nicht wieder vorschlagen.
  - Der Wächter erkennt WLANs über den Windows-Netzwerkprofilnamen (`Get-NetConnectionProfile`).
  - Auf dem PC heißen die Profile „Welt“ (Heimnetz) und „DE22LA000256314 8159“ (Schul-Hotspot).
- **Schulsperre:** Hotspot-Name, gelernte Router-MAC und eigene gesperrte Namen. Es gibt keinen Weg zum Übergehen.
- **Claude sendet selbst keine Pakete ins Heimnetz** (Grundsatz 8).
  - Diagnose nur lesend: Datenbank im Modus `?mode=ro`, Logdatei, lesende Befehle wie netsh, arp -a, Get-NetAdapter.
  - Tests nur gegen 127.0.0.0/8; `tests/conftest.py` sperrt alles andere.
- **Warnung vor Klartext-Anmeldung:** kommt in Stufe 3 (Pflichtenheft, Risiko-Dashboard). Nur passive Prüfung, kein Mitschnitt, keine Anzeige echter Passwörter.
- **Prognose:** Vor jedem Bau Tokens bzw. Kontingent und Dauer prognostizieren, die Istwerte in [PROGNOSE.md](PROGNOSE.md) nachtragen.

## 4. Umgebung

| Was | Wo |
|---|---|
| Projekt | `C:\Users\meyer\Dropbox\_6.Block\X-Claude-LF11EA\Claude_Code\Network` |
| Repository | <https://github.com/MeArt-EAT/netzwerkscanner> (privat). `gh` ist nicht installiert; Push läuft über den Git Credential Manager |
| Python | `%LOCALAPPDATA%\Netzwerkscanner\venv\Scripts\python.exe` (3.13, außerhalb von Dropbox) |
| Daten / Log | `%LOCALAPPDATA%\Netzwerkscanner\data\netscan.sqlite3`, `…\data\logs\netscan.log` |
| Demo | `start.bat /demo`. Für den Browser-Bereich gibt es `.claude/launch.json` mit `netscan-demo` auf Port 8798 (nicht im Git) |
| Npcap | 1.89 ohne WinPcap-Modus, geprüft am 10.10.2026 |

Testbefehl (Git Bash):

```bash
PYTHONDONTWRITEBYTECODE=1 /c/Users/meyer/AppData/Local/Netzwerkscanner/venv/Scripts/python.exe -m pytest -p no:cacheprovider -o addopts="" -q
```

Heimnetz grob:
- /24 über WLAN (Intel AX201)
- Fritz!Box mit zwei Fritz-Repeatern
- Synology DS720+, die mit zwei Netzwerkkarten zweimal erscheint
- Brother-Drucker
- mehrere ESP-, Shelly- und Solar-Geräte
- Haushaltsgeräte (Miele, Siemens)

## 5. Arbeitsweise, die sich bewährt hat (Muster für Stufe 2 und 3)

1. **Leitung (Hauptchat):** Bauplan-Ergänzung und Kern selbst schreiben, inklusive Fakes und Testgerüst.
2. **Bau:** bis zu 6 Agenten parallel mit getrennten Schreibbereichen. Anspruchsvolles bekommt der Agent `ingenieur`, Routine der Agent `zeichner`.
3. **Zusammenbau:** Ende-zu-Ende-Test gegen das Sim-Labor (`tests/sim.py`), dazu die Demo im Browser-Bereich prüfen.
4. **Prüfung:** 3 Prüfer mit verschiedenen Schwerpunkten, je ein Gegenprüfer, danach eine Nachbesserung mit Regressionstests.
5. **Abschluss:** README, Checkliste, Prognose-Istwerte, Testversion taggen.

Kalibrierung aus Stufe 1:
- Dauer gesamt etwa 3 h, davon die Prüfrunde 94 min. Für die Prüfung 60–100 min ansetzen.
- 15 % des 5-Stunden-Fensters, 4–5 % der Woche (Max-Abo).
- Umfang etwa fünfmal so groß wie geschätzt, die Hälfte davon Tests.

Prognose Stufe 2: 2–2½ h, etwa 10 % des Fensters.

## 6. Bekannte Grenzen und Beobachtungen

- **ARP über WLAN:** Bis rc2 kam keine einzige Antwort. rc3 setzt `promisc=False`, das ist noch unbestätigt. Hilft das nicht, sind die nächsten Kandidaten:
  - der Absender im Paket (`iface.mac` gegenüber der aktuellen WLAN-MAC)
  - der Npcap-Treiber auf der Intel-Karte
  - Prüfen nur lesend bzw. über einen Diagnoselauf, den der Nutzer selbst startet.
- **Einordnung „unbekannt“** bei mehreren Smart-Home- und Solar-Geräten: FN-LINK „MSA-…“, Smart Innovation „S380HB“, Quectel „marstek“, Viessmann. Die IoT-Herstellertabelle in `netscan/net/classify.py` ließe sich ergänzen.
- **Fritz-Repeater** melden eine private MAC und werden als Switch eingeordnet. Das ist vertretbar.
- **Eigen-Scan ignoriert die Firewall:** Den eigenen PC (`is_self`) scannt der Scanner von sich selbst aus. Lokale
  Verbindungen prüft die Windows-Firewall nicht, deshalb erscheinen gesperrte Ports trotzdem als offen. Im
  Heimnetz-Test waren das 139/445 („hoch“), obwohl die Freigaberegeln aus sind. Vorschlag für Stufe 3: Beim eigenen PC
  die Firewall-Regeln mit auswerten (`Get-NetFirewallRule` je Port und Profil) und „lokal offen, von außen
  gesperrt“ getrennt anzeigen. Bis dahin in der Oberfläche einen Hinweis anzeigen.
- **MQTT 8883** stuft der Scanner nach der Portnummer als „verschlüsselt“ ein. Beim Mosquitto des Nutzers läuft dort
  aber Klartext (`listener 8883` ohne TLS). Die echte TLS-Prüfung kommt in Stufe 3.
- **Lücke beim Profilnamen:** Heißt das Windows-Profil des Hotspots anders als die SSID (umbenannt oder „… 2“), greift die Namensregel nicht. Dann wirkt nur die gelernte Router-MAC.
- **Start mit Adminrechten aus beschreibbaren Ordnern (Aufgabe, festgestellt am 10.10.2026):**
  - `start.bat` startet `%LOCALAPPDATA%\Netzwerkscanner\venv\Scripts\python.exe` mit `run_server.py` aus dem
    Dropbox-Ordner per `Start-Process -Verb RunAs`. Projektordner, Python-Umgebung und `start.bat` selbst lassen
    sich ohne Adminrechte ändern. Wer dort Code ablegt (ein Programm unter dem Benutzerkonto, auch Claude Code, oder
    jemand mit Zugriff auf das Dropbox-Konto), bekommt beim nächsten „Ja“ in der Benutzerkontensteuerung
    Adminrechte.
  - Die Server-Schnittstelle selbst ist keine solche Brücke: keine Dateipfade, keine Befehle von außen, Export nur als
    Download, die Herstellerliste nur von der festen IEEE-Adresse.
  - Lösung:
    - Ein Installationsschritt, den der Nutzer selbst mit Adminrechten startet, kopiert `netscan/`, `run_server.py`
      und eine eigene Python-Umgebung nach `C:\Program Files\Netzwerkscanner`. Nur Administratoren dürfen dort
      schreiben.
    - Der Start mit Adminrechten läuft nur noch von dort, mit festen Argumenten ohne Umgebungsvariablen aus dem
      Benutzerkontext und mit `python -I` (ignoriert `PYTHONPATH` und die Benutzer-Pakete).
    - Aktualisieren nur über diesen Installationsschritt, nachdem `git status` bzw. der Diff geprüft ist.
    - Die Daten (`%LOCALAPPDATA%\Netzwerkscanner\data`) bleiben beschreibbar. Einstellungen, Datenbank und
      Herstellerliste deshalb weiter als nicht vertrauenswürdige Eingabe prüfen.
    - Auf dem Raspberry Pi entsprechend: Dateien unter `/opt/netzwerkscanner`, Besitzer `root`, Dienst über systemd.
  - Bis dahin gilt für den Nutzer: vor jedem Start mit Adminrechten im Projektordner `git status` aufrufen. Bei
    Änderungen, die nicht von ihm selbst stammen, in der Benutzerkontensteuerung nicht „Ja“ klicken.

## 7. Für Stufe 2 (Überwachung) schon vorbereitet bzw. zu beachten

- **Der Monitor muss vor jedem Durchlauf `NetworkGuard.check()` aufrufen.** Bei einer Sperre pausiert er (Abnahmepunkt aus Stufe 1).
- **Neue offene Ports** liefert `Inventory.set_ports()` schon zurück, als Grundlage für den Alert „neuer offener Port“.
- **Neue Geräte** erkennt `is_new` bzw. `first_seen_scan`.
- **Datenbank:** `netscan/core/db.py` hat `SCHEMA_VERSION = 1` und eine Migrationsstelle. Für Messwerte auf 2 erhöhen, Messwerte älter als 30 Tage zu Stundenmitteln verdichten.
- **Erweiterung des Scans:** neue Module als Enricher an `ENRICHERS` in `netscan/scan/pipeline.py` hängen, ohne bestehende umzubauen.
- **Chart.js** wie vis-network lokal unter `netscan/web/static/vendor/` ablegen. Version mindestens zwei Wochen alt, CSP ohne Inline-Skripte.
