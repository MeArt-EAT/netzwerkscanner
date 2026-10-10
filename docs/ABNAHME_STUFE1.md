# Abnahme Stufe 1 – Checkliste für den Windows-PC

Abhaken auf dem eigenen PC im **Heimnetz**. Fehler bitte mit Konsolenausgabe des Server-Fensters
und der Logdatei `%LOCALAPPDATA%\Netzwerkscanner\data\logs\netscan.log` zurückmelden.

**Vorher einmal:** Npcap ohne „WinPcap API-compatible Mode“ neu installieren. Derzeit ist der
Modus an: `WinPcapCompatible = 1`, außerdem liegen `wpcap.dll` und `Packet.dll` in `System32`.
`start.bat` weist darauf hin, solange das so ist.

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
| ☐ | Nach dem ersten Erkennen greift die Sperre auch bei nicht lesbarem WLAN-Namen | Windows: Standortdienste aus → im selben Hotspot bleibt das rote Band („Gateway gesperrt“) |
| ☐ | Ein Hotspot mit ähnlichem, aber anderem Namen wird nicht gesperrt | Hotspot umbenennen (z. B. Endziffer ändern) → gelbes Band „fremdes Netz“, kein rotes |
| ☐ | Wechselt der Rechner bei laufendem Programm in diesen Hotspot, pausiert der Monitor beim nächsten Durchlauf | Monitor kommt in Stufe 2; in Stufe 1: Wechsel in den Hotspot → nächster Scan-Versuch gesperrt |
| ☐ | Nicht lesbarer WLAN-Name und nicht das Heimnetz: Warnung, Scan erst nach Bestätigung | Standortdienste aus, fremdes WLAN → gelbes Band mit Hinweis „WLAN-Name nicht lesbar“, Scan erst nach „Nur diesmal scannen“ |

**Beim ersten Scan im Heimnetz:** Das gelbe Band fragt „Ist das dein Heimnetz?“. Klick auf
„Das ist mein Heimnetz“ speichert die MAC-Adresse der Fritz!Box. Danach scannt der Scanner dort
ohne Rückfrage.
