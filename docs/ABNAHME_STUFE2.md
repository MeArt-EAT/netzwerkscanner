# Abnahme Stufe 2 – Checkliste für den Windows-PC

Abhaken auf dem eigenen PC, am besten im **Heimnetz**. Voraussetzung: Stufe 1 ist abgenommen. Fehler bitte mit
der Ausgabe des Server-Fensters und der Logdatei `%LOCALAPPDATA%\Netzwerkscanner\data\logs\netscan.log`
zurückmelden.

**Vorher:** Stufe 2 liegt auf dem Zweig `stufe-2` im Arbeitsordner `.claude\worktrees\stufe-2` des Projekts.
**Nicht** im Projektordner `git checkout stufe-2` ausführen: Dropbox markiert die Ordner als Cloud-Platzhalter,
dann bricht Git beim Umschalten ab („cannot create directory at 'netscan'“). Stattdessen:
1. Server von Stufe 1 schließen (Strg+C im Server-Fenster).
2. Im Arbeitsordner `git status` aufrufen (keine fremden Änderungen).
3. `.claude\worktrees\stufe-2\start.bat` per Doppelklick starten. Datenbank und Einstellungen sind dieselben;
   Stufe 2 erweitert die Datenbank, Stufe 1 kommt mit der erweiterten Datenbank weiter zurecht.
Zurück zu Stufe 1: Server schließen, `start.bat` im Projektordner starten.

**Ausprobieren ohne Netz:** `start.bat /demo` – fünf Geräte werden überwacht, das Telnet-Gerät fällt regelmäßig
aus, der Webdienst der NAS stoppt zeitweise. Es geht nichts ins echte Netz.

| ✓ | Kriterium (Pflichtenheft) | So prüfen |
|---|---|---|
| ☐ | Ein überwachtes Gerät, das ausgeschaltet wird, löst nach der eingestellten Zeit einen Alert aus. Nach dem Einschalten endet der Alert. | Gerät (z. B. Drucker oder Shelly) anklicken → „Überwachung“ einschalten. Gerät ausschalten. Nach 5 min (Einstellung „Offline-Alert nach“) erscheint im Reiter Alerts „… ist offline“. Gerät einschalten → beim nächsten Durchlauf ist der Alert nicht mehr aktiv. |
| ☐ | Wird ein überwachter Dienst gestoppt, meldet der Monitor einen Dienst-Alert, obwohl das Gerät per Ping erreichbar bleibt. | Auf einem PC einen Test-Webserver starten (`python -m http.server 8080` in einem leeren Ordner), Scan mit Port-Scan, PC überwachen, Dienst „Weboberfläche (HTTP) 8080“ anhaken. Webserver beenden → nach 2 min „HTTP 8080 auf … ausgefallen“, Gerät „gestört“. Webserver wieder starten → Alert endet. |
| ☐ | Nach 24 Stunden Betrieb zeigen die Diagramme lückenlose Verläufe. | Scanner 24 h laufen lassen (PC nicht in den Ruhezustand). Reiter Überwachung → Gerät wählen → 24 h: durchgehende Linie. Lücken zeigt die Oberfläche als „Abschnitt ohne Messwerte“ an (z. B. Ruhezustand, Programm aus). |
| ☐ | Ein neu geöffneter Port löst einen Alert aus. | Wie oben einen Webserver auf Port 8080 starten, **nachdem** ein Scan mit Port-Scan gelaufen ist (Port war geprüft und geschlossen). Neuer Scan mit Port-Scan → Alert „Neuer offener Port 8080 auf …“. Beim eigenen PC steht der Firewall-Hinweis dabei. |
| ☐ | Nach einem Neustart des Programms sind alle Messwerte noch da. | Server-Fenster mit Strg+C schließen, `start.bat` → Diagramme und Verfügbarkeit wie vorher, offene Alerts noch da. |
| ☐ | *(aus Stufe 1)* Wechselt der Rechner bei laufendem Programm in den Schul-Hotspot, pausiert der Monitor beim nächsten Durchlauf. | Bei laufender Überwachung in den Hotspot „DE22LA000256314 8159“ wechseln → Reiter Überwachung: „pausiert – Gesperrt …“, rotes Band, im Log kein Durchlauf mit Prüfungen. Zurück ins Heimnetz → Überwachung läuft weiter. |

**Zusätzlich prüfen (Stufe 2):**

| ✓ | Punkt | So prüfen |
|---|---|---|
| ☐ | Datenschutz-Hinweis bei Handys | Ein Handy überwachen → Hinweis „Die Überwachung macht sichtbar, wann diese Person zu Hause ist …“ |
| ☐ | Einstellungen wirken sofort | Einstellungen → Überwachung ausschalten → Reiter Überwachung „ausgeschaltet“ ohne Wartezeit |
| ☐ | Autostart (optional) | Einstellungen → Autostart einschalten → Windows-Aufgabenplanung zeigt „Netzwerkscanner“: Bei Anmeldung, „Nur ausführen, wenn der Benutzer angemeldet ist“, **ohne** „Mit höchsten Privilegien ausführen“. Abmelden/anmelden → `http://127.0.0.1:8765` erreichbar (ohne Fenster). Ausschalten → Aufgabe weg. *Ungeprüft beim Bau: schtasks wurde aus Sicherheitsgründen nie wirklich aufgerufen.* |
| ☐ | Datenbankgröße | Statuszeile zeigt „Datenbank: … MB“; unter 100 MB ohne Warnung |
| ☐ | Anderes Netz mit gleichem Adressbereich | (falls möglich) In einem fremden WLAN mit gleichem Adressbereich: überwachte Geräte „pausiert – anderes Netz“, keine Offline-Alerts |
