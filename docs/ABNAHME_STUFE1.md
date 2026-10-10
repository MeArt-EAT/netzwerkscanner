# Abnahme Stufe 1 – Checkliste für den Windows-PC

Abhaken auf dem eigenen PC, am besten im **Heimnetz**. Fehler bitte mit Konsolenausgabe des Server-Fensters
und der Logdatei `%LOCALAPPDATA%\Netzwerkscanner\data\logs\netscan.log` zurückmelden.

**Vorarbeiten:**
- ☑ Npcap 1.89 ohne „WinPcap API-compatible Mode“ installiert (10.10.2026). Geprüft: `WinPcapCompatible = 0`,
  keine `wpcap.dll`/`Packet.dll` mehr in `System32`/`SysWOW64`, Scapy findet die WLAN-Karte.
- Standortberechtigung bleibt bewusst aus (Entscheidung 10.10.2026). Der Scanner erkennt das WLAN dann am
  Windows-Netzwerkprofil, auf diesem PC „Welt“ für das Heimnetz und „DE22LA000256314 8159“ für den Hotspot.

**Ausprobieren ohne Netz:** `start.bat /demo` startet ein simuliertes Heimnetz auf 127.0.0.x.
Dabei geht nichts ins echte Netz.

| ✓ | Kriterium (Pflichtenheft) | So prüfen |
|---|---|---|
| ☐ | `start.bat` öffnet nach Doppelklick die Oberfläche, ohne Fehlermeldung in der Konsole | Doppelklick → Windows fragt nach Adminrechten → „Ja“ → Server-Fenster zeigt `Uvicorn running on http://127.0.0.1:8765`, Browser öffnet sich |
| ☐ | Adapterliste zeigt die echte Netzwerkkarte, virtuelle sind ausgeblendet | Auswahl oben links: Ethernet/WLAN da, `vEthernet (WSL)`, Hyper-V, VPN nicht; Kästchen „virtuelle Adapter zeigen“ blendet sie ein |
| ☐ | Gerätesuche im /24 unter 30 s, mit Standard-Port-Scan unter 3 min | Scan einmal ohne, einmal mit „Port-Scan“ starten; Dauer steht im Scan-Protokoll („Scan fertig: … s“) |
| ☐ | Router, NAS und eigener PC werden gefunden; Gerätezahl stimmt mit der Router-Liste überein (Abweichungen erklärbar) | Fritz!Box → Heimnetz → Netzwerk vergleichen; Geräte im Standby fehlen ggf. |
| ☐ | Router und NAS sind richtig eingeordnet; ein verwalteter Switch erscheint als Switch | Spalte „Kategorie“ und Symbol in der Netzwerkkarte |
| ☐ | Ein Gerät behält seinen eigenen Namen nach einem neuen Scan | Gerät anklicken → eigener Name → Speichern → neuer Scan |
| ☐ | Ein neu eingeschaltetes, unbekanntes Gerät erscheint beim nächsten Scan als „neu“ | Alle bekannten Geräte als „bekannt“ markieren, ein Gerät einschalten (z. B. Handy ins WLAN), Scan → Abzeichen „neu“ |
| ☐ | Ein abgebrochener Scan hält innerhalb von 5 s an, die Oberfläche bleibt bedienbar | Während der Port-Phase „Abbrechen“ → Protokoll „Auftrag abgebrochen“ in ≤ 5 s |
| ☐ | Von einem anderen Gerät im WLAN ist die Oberfläche nicht erreichbar | Handy im WLAN: `http://<IP-des-PCs>:8765` aufrufen → keine Verbindung |
| ☐ | Exporte JSON, CSV und HTML lassen sich öffnen und enthalten alle Geräte | Export-Knöpfe; CSV in Excel öffnen (Umlaute korrekt, Spalten getrennt) |
| ☐ | Hotspot exakt „DE22LA000256314 8159“: weder Scan noch Monitor starten, auch nicht im Modus „nur eingetragene Geräte“; keine Schaltfläche zum Übergehen | Handy-Hotspot mit genau diesem Namen, PC verbinden → rotes Band, Start-Knopf gesperrt, auch bei Modus „nur eingetragene Geräte“ |
| ☐ | Nach dem ersten Erkennen greift die Sperre auch bei nicht lesbarem WLAN-Namen | Windows: Standortdienste aus → im selben Hotspot bleibt das rote Band („Gesperrtes WLAN“ über den Windows-Netzwerkprofilnamen bzw. „Gesperrtes Netz (Router erkannt)“), dazu kein „Das ist mein Heimnetz“ |
| ☐ | Ein Hotspot mit ähnlichem, aber anderem Namen wird nicht gesperrt | Hotspot umbenennen (z. B. Endziffer ändern), PC neu verbinden → grünes Band „Netz frei“, kein rotes |
| ☐ | Wechselt der Rechner bei laufendem Programm in diesen Hotspot, pausiert der Monitor beim nächsten Durchlauf | Monitor kommt in Stufe 2; in Stufe 1: Wechsel in den Hotspot → nächster Scan-Versuch gesperrt |
| ☐ | *Geändert 10.10.2026:* Fremdes, nicht gesperrtes Netz wird ohne Rückfrage gescannt; nur wenn Windows weder WLAN-Namen noch Netzwerkprofil nennt, kommt die Warnung | Im Heimnetz und in einem anderen erlaubten Netz → grünes Band „Netz frei“, Scan startet sofort. Die alte Regel lässt sich in den Einstellungen mit „Vor fremden Netzen nachfragen“ wieder einschalten (dann gelbes Band in fremden Netzen) |

**Beim ersten Scan:** Ein grünes Band zeigt „Netz frei“. Ein Heimnetz muss nicht festgelegt werden.
Ist „Vor fremden Netzen nachfragen“ eingeschaltet, fragt das gelbe Band wie früher nach dem Heimnetz.
