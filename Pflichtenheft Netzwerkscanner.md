# Pflichtenheft Netzwerkscanner

Oct 10, 2026 · @Kommuniziere in deutsch

## Ziel und Abgrenzung

Der Scanner zeigt alle Geräte im eigenen Heimnetz als Inventar und Netzwerkkarte im Browser und überwacht sie. Gebaut wird er in drei Stufen, jede einzeln getestet und lauffähig.

- **Zweck:** wissen, welche Geräte im Netz sind, was sie anbieten und ob sie erreichbar sind. Ein neues, unbekanntes Gerät fällt sofort auf.
- **Grenze Topologie:** Der Scanner sieht, welche Geräte da sind, aber nicht, woran sie hängen. Ohne verwaltete Switches zeigt die Karte einen Stern mit dem Router in der Mitte. Echte Verbindungen liefern nur verwaltete Switches per SNMP oder LLDP (Stufe 3).
- **Grenze Datenverkehr:** Wohin Geräte Daten senden, sieht ein Scanner nicht. Diese Auswertung kommt als Stufe 4 auf einen eigenen Raspberry Pi.

Der Scanner von 2025 lief aus vier Gründen nie zuverlässig. Jede Ursache hat hier eine feste Gegenmaßnahme:

| Ursache 2025 | Gegenmaßnahme |
| --- | --- |
| Code in Bruchstücken über viele „Weiter“-Runden, Teile in verschiedenen Artefakten, widersprüchliche Namen (`scanning_active` / `scan_running`) | Jede Stufe als vollständige Dateien, vor der Übergabe getestet |
| Gerätesuche prüfte nur die ersten 20 Adressen, nacheinander | ARP-Scan über das ganze Netz, Ping parallel |
| Scan-Threads schrieben direkt in tkinter und matplotlib | Browser-Oberfläche; Scans melden nur über eine Ereignis-Warteschlange |
| WinPcap 4.1.3, seit Jahren nicht gepflegt | Npcap |

## Rahmenbedingungen

Der Scanner läuft auf einem Windows-PC mit Python und Npcap, startet mit Administratorrechten und wird im Browser auf demselben PC bedient.

| Punkt | Festlegung |
| --- | --- |
| Zielsystem | Windows 10 oder 11, 64 Bit |
| Python | 3.12 oder neuer; Scapy 2.8 und pysnmp 7.1 unterstützen bis 3.14 |
| Paket-Treiber | Npcap in aktueller Version, Option „WinPcap compatibility mode“ aus. Scapy setzt unter Windows Npcap voraus, WinPcap wird nicht mehr unterstützt ([Scapy-Doku](https://scapy.readthedocs.io/en/latest/installation.html)) |
| Vorarbeit | WinPcap 4.1.3 deinstallieren, Reste `wpcap.dll` und `Packet.dll` in `System32` und `SysWOW64` löschen, dann Npcap installieren |
| Rechte | Start als Administrator, nötig für ARP-Scan und rohe Pakete |
| Bedienung | Browser auf demselben PC unter `http://127.0.0.1:8765` |
| Start | `start.bat` per Doppelklick: fordert Adminrechte an, startet den Server, öffnet den Browser |
| Netz | Heimnetz IPv4, typisch ein /24; größere Netze bis /22 mit Warnhinweis |
| Offline | Oberfläche läuft ohne Internet, alle Bibliotheken liegen lokal bei; Herstellerliste (IEEE OUI) lokal, Aktualisierung per Knopf |

## Sicherheits- und Datenschutzgrundsätze

Der Scanner ist nur vom eigenen PC aus bedienbar, greift im Standard nicht auf den Router zu, und Claude bekommt nie Zugangsdaten.

1. **Nur lokal:** Die Oberfläche lauscht ausschließlich auf `127.0.0.1`. Andere Geräte im WLAN erreichen sie nicht.
2. **Zugangsdaten beim Programm, nicht bei Claude:** SNMP-, MQTT- und optionale Router-Zugangsdaten fragt der Scanner selbst ab. Er speichert sie in der Windows-Anmeldeinformationsverwaltung (Python-Paket `keyring`), nie in Projektdateien. Weder dieser Chat noch Claude Code erhalten sie.
3. **Router-Anbindung optional und aus:** Die Fritz!Box-Anbindung per TR-064 ist standardmäßig abgeschaltet. TR-064 braucht in der Regel das Recht „FRITZ!Box Einstellungen“, also volle Rechte. Wer sie einschaltet, legt einen eigenen Fritz!Box-Benutzer ohne Internetzugang an.
4. **Schonend scannen:** Pakete pro Sekunde begrenzt, kurze Timeouts, im Standard nur eine Liste häufiger Ports. Tiefenscan nur auf Knopfdruck. Empfindliche Geräte wie Drucker, IoT oder SPS lassen sich vom Port-Scan ausnehmen.
5. **Keine Angriffe:** keine Passwort-Rateversuche, auch keine SNMP-Community-Liste durchprobieren, keine Exploits. SNMP nutzt nur eingetragene Zugangsdaten. Das eigene SNMPv3-Leseprofil darf automatisch an Geräte gehen, die SNMPv3 melden; SNMPv2c nur gezielt pro Gerät, weil es den Zugangsnamen im Klartext sendet.
6. **Nur eigenes Netz:** Fremde Netze, auch das Schulnetz, nur mit Freigabe des Netzbetreibers. Der Scanner erkennt das Heimnetz am Router (MAC-Adresse des Gateways), warnt bei einem anderen Netz und scannt erst nach ausdrücklicher Bestätigung. Dazu gibt es einen Modus „nur eingetragene Geräte“, der das Netz gar nicht absucht. Sperre für den Schul-Hotspot: Heißt das verbundene WLAN exakt „DE22LA000256314 8159“, ist jeder Scan gesperrt, auch im Modus „nur eingetragene Geräte“, und der Monitor pausiert. Geprüft wird vor jedem Scan und vor jedem Monitor-Durchlauf; eine Schaltfläche zum Übergehen gibt es nicht. Der Scanner merkt sich zusätzlich die MAC-Adresse des Hotspot-Gateways, damit die Sperre auch greift, wenn Windows den WLAN-Namen nicht herausgibt. Weitere gesperrte WLAN-Namen lassen sich in den Einstellungen ergänzen. In allen anderen fremden oder unklaren Netzen, auch bei nicht lesbarem WLAN-Namen, entscheidest du: Warnung, dann Scan nur nach Bestätigung. **Änderung 10.10.2026 (Entscheidung des Auftraggebers):** Der Scanner ist **frei nutzbar, außer in der Schule**. Nicht gesperrte Netze werden ohne Rückfrage gescannt, ein Heimnetz muss nicht festgelegt werden. Gesperrt bleibt alles, was als Schule erkannt wird: der Hotspot-Name (auch über den Namen des Windows-Netzwerkprofils, wenn Windows den WLAN-Namen ohne Standortberechtigung nicht herausgibt), die gemerkte Router-MAC des Hotspots und weitere gesperrte Namen. Nachgefragt wird nur, wenn sich nicht prüfen lässt, ob es die Schule ist. Die frühere Regel (Warnung und Bestätigung in fremden Netzen) bleibt als Einstellung „Vor fremden Netzen nachfragen“ erhalten, Standard aus. Die Standortberechtigung bleibt auf dem PC aus. Hinweis zum Schulnetz: Auch über einen Hotspot läuft ein Scan Richtung Schulnetz über den anmeldenden Rechner und ist im verwalteten Netz als dessen Scan nachvollziehbar; ein Scan im Arbeitgebernetz ohne schriftliche Freigabe kann dienstrechtlich als unbefugter Zugriff gelten. Im Schulnetz kommen Datenschutz und Mitbestimmung dazu, weil der Live-Monitor Anwesenheit erkennbar machen kann.
7. **Daten bleiben lokal:** alles in einer SQLite-Datei auf dem PC. Exporte entstehen nur auf Knopfdruck. Hinweis: Überwacht der Monitor auch Geräte von Personen, wird deren An- und Abwesenheit sichtbar; im Haushalt sollten alle davon wissen.
8. **Getrennte Entwicklung:** Claude baut und testet in der Cloud ohne Verbindung zum Heimnetz. Claude Code bekommt keinen Zugriff auf Router, NAS-Adminkonto oder den Raspberry Pi von Stufe 4.

## Architektur

Ein lokaler Server trennt Oberfläche und Scan-Arbeit. Die Module melden ihre Ergebnisse über eine Ereignis-Warteschlange, nie direkt an die Oberfläche.

&#91;embedded content: Architektur · 4 Schichten, 6 Scan-Module\]

Die Warteschlange beseitigt die Ursache der Abstürze von 2025: Kein Scan-Thread berührt die Oberfläche.

- **Ein Auftrag zur Zeit:** Scans laufen nacheinander und sind abbrechbar. Der Monitor aus Stufe 2 läuft daneben mit eigenem Takt.
- **Feste Modul-Schnittstelle:** Jede Stufe fügt Module hinzu, ohne bestehende umzubauen. Stufe 4 dockt über die Inventar-Schnittstelle an.
- **Plattformneutraler Kern:** reines Python, damit derselbe Code später auch unter Linux auf dem Raspberry Pi läuft.

| Paket | Zweck | ab Stufe |
| --- | --- | --- |
| fastapi, uvicorn | Webserver, REST und WebSocket | 1 |
| scapy | ARP-Scan und Pakete über Npcap | 1 |
| psutil | Netzwerkadapter auflisten; ersetzt netifaces, dessen Repository seit 2021 archiviert ist | 1 |
| zeroconf | mDNS-Namen | 1 |
| keyring | Zugangsdaten in der Windows-Anmeldeinformationsverwaltung | 1 |
| vis-network (lokal) | Netzwerkkarte im Browser | 1 |
| pytest | automatische Tests | 1 |
| Chart.js (lokal) | Diagramme | 2 |
| pysnmp 7.1 | SNMP v2c und v3 mit asyncio, gepflegt von LeXtudio | 3 |

Dazu kommen Bordmittel von Python: `sqlite3`, `ssl`, `asyncio` und `socket`.

## Stufe 1 – Kern und Oberfläche

Stufe 1 findet alle Geräte im Netz, erkennt sie wieder und zeigt sie als Liste und Karte. Sie trägt rund 40 % des Gesamtaufwands, weil sie das Fundament für alle weiteren Stufen legt.

### Funktionen

1. **Adapterwahl:** Liste der physischen Netzwerkadapter mit ihrem IPv4-Netz. Virtuelle Adapter von Hyper-V, WSL, VirtualBox und VPN sind ausgeblendet und lassen sich einblenden.
2. **Gerätesuche:** ARP-Scan über Npcap für das ganze Netz, dazu paralleler Ping als Ergänzung.
3. **Identifikation:**
   - Hersteller per MAC-Adresse aus der lokalen IEEE-Liste
   - zufällige MAC-Adressen (Handys) erkennen und als „private Adresse“ kennzeichnen
   - Hostname per DNS-Rückwärtsauflösung, NetBIOS und mDNS
   - Gerätebeschreibung per SSDP/UPnP
4. **Geräteart:** Einordnung als Router, Switch, Server/NAS, PC, Drucker, IoT-Gerät oder Handy aus Hersteller, Diensten und Kennungen, im Inventar korrigierbar. Ein verwalteter Switch fällt durch eigene IP-Adresse, Netzwerk-Hersteller und Verwaltungsoberfläche auf und erscheint in Liste und Karte als Switch.
5. **Ports:** TCP-Scan auf rund 30 häufige Ports, parallel mit Timeout. Dienstname und Risikostufe (niedrig, mittel, hoch, kritisch) nach fester Regeltabelle. Tiefenscan der Ports 1–1024 auf Knopfdruck je Gerät.
6. **Inventar:** Jedes Gerät wird über seine MAC-Adresse wiedererkannt. Eigener Name, Kategorie und Notiz sind vergebbar, dazu die Markierung „bekannt“. Gespeichert werden erstmals und zuletzt gesehen. Ein unbekanntes neues Gerät wird hervorgehoben.
7. **Netzwerkkarte:** interaktive Karte mit dem Router in der Mitte, Geräte nach Kategorie mit Symbol. Ein Klick zeigt die Details.
8. **Oberfläche:** Reiter Geräte, Netzwerkkarte und Scan-Protokoll. Fortschritt live, Scan jederzeit abbrechbar.
9. **Export:** JSON, CSV und HTML-Bericht.

### Abnahme

- [ ] `start.bat` öffnet nach Doppelklick die Oberfläche im Browser, ohne Fehlermeldung in der Konsole.
- [ ] Die Adapterliste zeigt die echte Netzwerkkarte, virtuelle Adapter sind ausgeblendet.
- [ ] Die Gerätesuche im /24 dauert unter 30 Sekunden, mit Standard-Port-Scan unter 3 Minuten.
- [ ] Router, NAS und eigener PC werden gefunden. Die Gerätezahl stimmt mit der Geräteliste des Routers überein, Abweichungen sind erklärbar (z. B. Gerät im Standby).
- [ ] Router und NAS sind richtig eingeordnet. Ein vorhandener verwalteter Switch erscheint in Liste und Karte als Switch.
- [ ] Ein Gerät behält seinen eigenen Namen nach einem neuen Scan.
- [ ] Ein neu eingeschaltetes, unbekanntes Gerät erscheint beim nächsten Scan als „neu“.
- [ ] Ein abgebrochener Scan hält innerhalb von 5 Sekunden an, die Oberfläche bleibt bedienbar.
- [ ] Von einem anderen Gerät im WLAN ist die Oberfläche nicht erreichbar.
- [ ] Die Exporte als JSON, CSV und HTML lassen sich öffnen und enthalten alle Geräte.
- [ ] Über einen Test-Hotspot mit exakt dem Namen „DE22LA000256314 8159“ startet weder ein Scan noch der Monitor, auch nicht im Modus „nur eingetragene Geräte“. Es gibt keine Schaltfläche zum Übergehen. Nach dem ersten Erkennen greift die Sperre auch bei nicht lesbarem WLAN-Namen. Ein Hotspot mit ähnlichem, aber anderem Namen wird nicht gesperrt.
- [ ] Wechselt der Rechner bei laufendem Programm in diesen Hotspot, pausiert der Monitor beim nächsten Durchlauf.
- [ ] ~~Ist der WLAN-Name nicht lesbar und das Netz nicht das Heimnetz, warnt der Scanner und scannt erst nach deiner Bestätigung.~~ Geändert am 10.10.2026: Ein nicht gesperrtes Netz wird ohne Rückfrage gescannt. Nur wenn Windows weder den WLAN-Namen noch ein Netzwerkprofil nennt, warnt der Scanner und scannt erst nach deiner Bestätigung.

## Stufe 2 – Überwachung

Stufe 2 prüft ausgewählte Geräte laufend, speichert Antwortzeiten und meldet Ausfälle und Veränderungen. Sie trägt rund 25 % des Gesamtaufwands.

### Funktionen

1. **Live-Monitor:** ausgewählte Geräte zyklisch prüfen, Intervall einstellbar, Standard 60 Sekunden. Ping, bei Geräten ohne Ping-Antwort ein TCP-Port.
2. **Dienst-Prüfung für Server und NAS:** Der Monitor prüft wichtige Dienste einzeln, etwa Dateifreigabe (SMB), Weboberfläche (HTTP/HTTPS mit Antwortcode) und SSH. Welche Dienste geprüft werden, schlägt der Scanner aus dem Port-Scan vor; du wählst sie an oder ab. So wird „Gerät erreichbar, aber Freigabe ausgefallen“ sichtbar.
3. **Messwerte:** Antwortzeit, Status (online, offline, gestört) und Verfügbarkeit in Prozent über 24 Stunden und 7 Tage. Alles in der SQLite-Datei; Messwerte älter als 30 Tage werden zu Stundenmitteln verdichtet.
4. **Alerts:** Regeln für Gerät länger als X Minuten offline, Dienst ausgefallen, Antwortzeit über Schwellwert, neues unbekanntes Gerät und neuer offener Port an einem bekannten Gerät. Anzeige im Reiter Alerts, quittierbar.
5. **Diagramme:** Antwortzeit-Verlauf je Gerät, Status-Übersicht, Verfügbarkeits-Trend und Alert-Häufigkeit.
6. **Hintergrundbetrieb:** Der Monitor läuft, solange der Server läuft. Optional startet der Scanner über die Windows-Aufgabenplanung mit dem System.

### Abnahme

- [ ] Ein überwachtes Gerät, das ausgeschaltet wird, löst nach der eingestellten Zeit einen Alert aus. Nach dem Einschalten endet der Alert.
- [ ] Wird ein überwachter Dienst gestoppt, etwa ein Test-Webserver auf einem PC, meldet der Monitor einen Dienst-Alert, obwohl das Gerät per Ping erreichbar bleibt.
- [ ] Nach 24 Stunden Betrieb zeigen die Diagramme lückenlose Verläufe.
- [ ] Ein neu geöffneter Port, etwa ein testweise gestarteter Webserver auf einem PC, löst einen Alert aus.
- [ ] Nach einem Neustart des Programms sind alle Messwerte noch da.

## Stufe 3 – Sicherheit und SNMP

Stufe 3 bewertet das Risiko jedes Geräts und liest verwaltete Netzwerkgeräte per SNMP aus. Sie trägt rund 35 % des Gesamtaufwands.

### Funktionen

1. **Betriebssystem-Schätzung:** aus TTL, offenen Ports und Dienst-Kennungen. Ergebnis als Schätzung gekennzeichnet: Windows, Linux, Netzwerkgerät, Drucker oder IoT.
2. **SSL/TLS-Prüfung:** Zertifikat mit Aussteller, Ablaufdatum und Selbstsignatur, dazu die TLS-Version. Warnung 30 Tage vor Ablauf.
3. **Risiko-Dashboard:** Bewertung je Gerät aus offenen Ports, Diensten wie Telnet, SMB oder Anmeldung über unverschlüsseltes HTTP, und Zertifikaten. Übersicht nach Risikostufe mit Abhilfehinweis.
   - **Warnung vor Klartext-Anmeldung** (ergänzt 10.10.2026): Der Scanner markiert jeden Dienst, bei dem Zugangsdaten unverschlüsselt übertragen würden, und warnt davor, dort ein Passwort einzugeben. Ziel: In einem freien oder fremden Netz kein eigenes Passwort im Klartext preisgeben. Erkannt werden Anmeldeseiten über HTTP (Seite mit Passwortfeld, HTTP-Basic-Auth), FTP (21), Telnet (23) und Mail-Dienste ohne Verschlüsselung (POP3 110, IMAP 143, SMTP 25/587 ohne STARTTLS). Die Warnung nennt Gerät, Dienst und Adresse und schlägt die verschlüsselte Alternative vor (HTTPS, SFTP/SSH, Mail mit TLS). In einem nicht als Heimnetz bekannten Netz zeigt die Oberfläche zusätzlich einen Hinweis, dass in offenen WLANs Mitlesen möglich ist. Die Grundlage aus Stufe 1 (Risikotabelle der Ports) bleibt; hier kommt die gezielte Prüfung der Anmeldeseiten und eine eigene Übersicht dazu.
   - **Grenze:** Der Scanner liest dafür nur öffentlich erreichbare Dienste passiv aus (Banner, Anmeldeseite, angebotene Verschlüsselung). Er fängt keinen fremden Datenverkehr ab, schneidet nichts mit und zeigt keine tatsächlich übertragenen Passwörter an. Das entspricht Grundsatz 5 (keine Angriffe); Verkehrsauswertung gibt es nur in Stufe 4 und dort nur als DNS-Treffer.
4. **Sicherheits-Reiter:** jeder Befund mit Details und Begründung.
5. **SNMP-Erkennung:** Bei Switches, Servern und NAS prüft der Scanner ohne Zugangsdaten über die SNMPv3-Erkennungsanfrage, ob SNMP antwortet. Zugangsdaten rät er nie.
6. **SNMP-Zugang:** Ein SNMPv3-Leseprofil wird einmal im Scanner eingetragen und auf den Geräten als gleicher Benutzer angelegt. Der Scanner probiert es automatisch bei jedem Gerät, das SNMPv3 meldet. SNMPv2c gibt es nur gezielt pro Gerät, weil es den Zugangsnamen im Klartext sendet. Abweichende Zugänge pro Gerät sind möglich.
7. **Netzwerkgeräte per SNMP:**
   - Systeminfo und Interfaces mit Status und Datenverkehr
   - MAC-Adresstabelle: welches Gerät an welchem Switch-Port hängt
   - ARP- und Routing-Tabelle
   - VLANs, sofern das Gerät sie meldet
   - LLDP-Nachbarn: Verbindungen zwischen Switches
8. **Server und NAS per SNMP:**
   - über Standard-MIBs: CPU- und RAM-Auslastung, Belegung der Volumes, Netzwerkverkehr
   - bei Synology zusätzlich: Systemstatus, Temperatur, Netzteil und Lüfter, Modell, DSM-Version und ob ein Update bereitsteht
   - je Platte: Modell, Status, Temperatur, Gesundheit, Restlebensdauer und defekte Sektoren
   - je Speicherpool: RAID-Zustand, freie und gesamte Kapazität
   - Alerts bei Plattenfehler, RAID nicht „normal“, Temperatur über Schwellwert und fast vollem Volume
   - DSM verschickt keine SNMP-Traps, der Monitor fragt deshalb regelmäßig ab.
   - Synology empfiehlt SNMPv2c, um alle Synology-eigenen Werte zu erhalten. Fehlen sie unter v3, wird für die NAS gezielt v2c freigegeben.
9. **Einrichtungshinweis:** Fährt die Maus über einen Switch, Server oder eine NAS mit unvollständigen Daten, nennt ein Hinweis die fehlende Einstellung und was sie bringt. Liefert das Gerät alles, erscheint kein Hinweis.
   - SNMP antwortet nicht: SNMP mit Lesezugang einschalten und den Benutzer des Scanner-Profils anlegen. Bei Synology im DSM unter Systemsteuerung → Terminal & SNMP, bei Linux den SNMP-Dienst installieren.
   - Synology-Werte fehlen: für die NAS SNMPv2c gezielt freigeben
   - MAC-Adresstabelle fehlt (Switch): Lesezugriff auf die Bridge-Daten freigeben
   - LLDP fehlt: LLDP einschalten, nur bei mehreren Switches nötig
   - Windows-Rechner bekommen keinen SNMP-Hinweis. Microsoft stuft den SNMP-Dienst als veraltet ein, hier bleibt es bei der Außensicht.
10. **Berichte:** Sicherheitsbericht, Zustandsbericht und SNMP-Topologie als HTML, JSON und CSV.

### Abnahme

- [ ] Ein Gerät mit offenem Telnet- oder SMB-Port erscheint im Risiko-Dashboard mit Stufe „hoch“ und einem Abhilfehinweis.
- [ ] Ein Test-Dienst mit Anmeldeseite über HTTP (Passwortfeld) und ein FTP- oder Telnet-Dienst erscheinen als „Klartext-Anmeldung“ mit Warnung und verschlüsselter Alternative. Eine Anmeldeseite über HTTPS wird nicht gewarnt.
- [ ] Der Scanner zeigt dabei nie ein tatsächlich übertragenes Passwort an und schneidet keinen Datenverkehr mit.
- [ ] Ein selbstsigniertes, abgelaufenes oder in weniger als 30 Tagen ablaufendes Zertifikat wird erkannt.
- [ ] Die NAS mit eingeschaltetem SNMP liefert über das Leseprofil oder die gezielte v2c-Freigabe Systemstatus, Temperatur, Platten- und RAID-Zustand.
- [ ] Ein simulierter Plattenfehler oder ein RAID-Zustand ungleich „normal“ löst einen Alert aus.
- [ ] Bei einem verwalteten Switch mit SNMP zeigt die Karte, welches Gerät an welchem Port hängt.
- [ ] Ein Switch, Server oder eine NAS ohne SNMP zeigt beim Mouseover den passenden Einrichtungshinweis. Nach dem Einschalten ist er beim nächsten Scan weg.
- [ ] Ein Gerät, das alle Daten liefert, zeigt keinen Hinweis.
- [ ] Liefern mehrere Switches LLDP-Daten, zeigt die Karte die Verbindungen zwischen ihnen.
- [ ] SNMPv2c-Zugangsdaten gehen nie automatisch an andere Geräte.
- [ ] Ohne SNMP-Geräte läuft Stufe 3 fehlerfrei und meldet „keine SNMP-Geräte gefunden“.

## Optionale Bausteine

Diese Bausteine sind vorgesehen, aber nicht Teil der drei Stufen. Die Architektur lässt Platz dafür, gebaut werden sie nur auf Wunsch.

| Baustein | Nutzen | Frühestens nach | Hinweis |
| --- | --- | --- | --- |
| MQTT-Ausgabe | Alerts und Status an Node-RED weitergeben | Stufe 2 | Zugangsdaten über `keyring` |
| IPv6-Erkennung | Geräte finden, die auch oder nur IPv6 nutzen | Stufe 1 | Erkennung über Neighbor Discovery |
| Fritz!Box TR-064 | Geräteliste und Namen direkt aus dem Router | Stufe 1 | standardmäßig aus, braucht volle Router-Rechte |
| Industrieprotokolle | S7 (Port 102), Modbus TCP (502), OPC UA (4840), PROFINET-DCP erkennen | Stufe 3 | eigener, besonders vorsichtiger Scanmodus; Laborbetrieb nur mit Freigabe; nicht in eine weitergegebene .exe einpacken (Npcap-Lizenz) |
| Windows-Programmdatei (.exe) | Start ohne Python-Installation, nur für den eigenen Rechner | Stufe 3 | gebaut mit PyInstaller; Npcap darf nicht mitgeliefert werden, muss separat installiert sein |

## Ausblick: Stufe 4 auf dem Raspberry Pi

Stufe 4 wertet aus, welche Ziele die Geräte im Netz ansprechen. Sie läuft getrennt vom Scanner auf einem eigenen Raspberry Pi mit AdGuard Home und wird erst nach Stufe 3 gebaut.

- **DNS-Server:** AdGuard Home auf dem Pi wird DNS-Server des Heimnetzes. Der Router verteilt dafür per DHCP die Pi-Adresse als DNS. Diese Umstellung machst du einmal selbst.
- **Auswertung:** Das DNS-Protokoll jedes Geräts wird gegen Bedrohungslisten geprüft, etwa abuse.ch (URLhaus, ThreatFox, Feodo Tracker) und Spamhaus DROP. Treffer erscheinen als Alert im Scanner. Welches Gerät hinter einer IP steckt, kommt aus dem Inventar von Stufe 1.
- **Stichproben:** Mitschnitte der Fritz!Box (pcap) lassen sich zusätzlich per Hand importieren und gegen dieselben Listen prüfen.
- **Datenschutz:** AdGuard bewahrt das Protokoll nur kurz auf, etwa 24 Stunden. Der Scanner speichert nur Treffer, nicht den Verlauf. Alle im Haushalt wissen davon.
- **Trennung:** Auf dem Pi läuft kein Claude Code. Der Scanner liest AdGuard nur, mit eigenem Zugang. Entwicklung und Test laufen ohne Zugriff auf den Pi.
- **Grenze:** Geräte mit fest eingebautem DNS oder DNS-over-HTTPS umgehen die Auswertung. Eine Router-Sperre für DNS nach außen (Ports 53 und 853) dämmt das teilweise ein.

Vorbereitung schon in Stufe 1: Das Inventar ist über eine Schnittstelle abrufbar (Gerät, MAC, IP), damit Stufe 4 ohne Umbau andocken kann.

## Test, Abnahme und Arbeitsweise

Jede Stufe wird erst in der Cloud getestet, dann von dir auf dem PC abgenommen, und erst danach beginnt die nächste.

1. **Test durch Claude:** Jede Stufe läuft vor der Übergabe gegen simulierte Geräte, etwa Testdienste mit Webserver, SSH, Telnet und einem SNMP-Agenten. Automatische Tests (pytest) gehören zum Lieferumfang.
2. **Lieferung:** jede Stufe als vollständiges Paket mit README und `start.bat`. Kein Weiterschreiben in Bruchstücken über mehrere „Weiter“-Runden.
3. **Abnahme durch dich:** Abnahme-Checkliste der Stufe auf dem Windows-PC abhaken. Fehler mit Konsolenausgabe oder Logdatei zurückmelden.
4. **Ein Chat pro Stufe:** Claude Code bearbeitet das Projekt und richtet mit dir ein privates GitHub-Repository ein (ein GitHub-Zugang ist vorhanden). Pro Stufe eine markierte Version (Tag), damit ein defekter Stand zurückdrehbar ist. Startnachricht eines neuen Chats ist dieses Pflichtenheft plus das Repository, nicht der ganze Verlauf. Das spart Tokens.
5. **Kontingent:** Die Vollversion ist groß, rund 4.000 bis 6.000 Zeilen. Mit Pro-Abo und Opus braucht sie voraussichtlich mehrere Nutzungsfenster. Bricht ein Fenster mitten in einer Stufe ab, geht nichts verloren. Für Stufe 2 und 3 lässt sich auf Sonnet umschalten, das schont das Kontingent.

## Offene Punkte

Sechs Fragen sind vor oder während Stufe 1 zu klären. Die ersten beiden beeinflussen den Bau direkt.

- [ ] **Router:** Fritz!Box ja oder nein, welches Modell? Wichtig für den Abgleich der Geräteliste und die optionale TR-064-Anbindung.
- [ ] **Vorarbeit am PC:** WinPcap 4.1.3 deinstallieren, Npcap installieren.
- [ ] **Verwaltete Geräte:** vermutlich vorhanden, aber unbestätigt. Stufe 1 erkennt verwaltete Switches selbst, der Einrichtungshinweis aus Stufe 3 nennt dann die nötigen Einstellungen.
- [ ] **Netze:** Reicht ein /24, oder gibt es weitere Netze wie Gast-WLAN oder ein eigenes IoT-Netz?
- [ ] **Raspberry Pi:** Modell und Speicher für Stufe 4.
- [ ] **Automatisierungslabor:** Soll der Scanner auch dort laufen? Dann Industrieprotokolle und Freigabe klären.

## Quellen

- [Scapy-Dokumentation: Installation unter Windows](https://scapy.readthedocs.io/en/latest/installation.html)
- [pysnmp 7.1 auf PyPI (gepflegt von LeXtudio, Python 3.10–3.14)](https://pypi.org/project/pysnmp/)
- [netifaces: Repository seit Juni 2021 archiviert](https://github.com/al45tair/netifaces)
- [ioBroker-Forum: Fritz!Box-Benutzerrechte für TR-064](https://forum.iobroker.net/post/336756)
- [Synology SNMP MIB Guide, Stand August 2026](https://global.download.synology.com/download/Document/Software/DeveloperGuide/Firmware/DSM/All/enu/Synology_DiskStation_MIB_Guide.pdf)
