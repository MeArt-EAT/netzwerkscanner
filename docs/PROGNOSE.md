# Prognose und Istwerte – Stufe 1

Prognose vom 10.10.2026, Abo Max, Leitung: Opus 5.5. Uhrzeiten Ortszeit.

| Phase | Prognose Dauer | Ist Dauer | Ist Kontingent (5-h-Fenster) |
|---|---|---|---|
| 1 Bauplan, Gerüst, Umgebung | 25–40 min | 20 min (13:50–14:10) | 0 % → 1 % |
| 2 Module bauen (6 Agenten parallel) | 45–75 min | 35 min (14:12–14:47) | 1 % → 6 % |
| 3 Zusammenbau, Gesamttest, Demo im Browser | 30–60 min | 18 min | 6 % → 7 % |
| 4 Prüfung (3 Prüfer, 3 Gegenprüfer, 1 Nachbesserung) | 30–45 min | **94 min** | 7 % → 15 % |
| 5 Endabnahme, README, Versionsmarke | 10–20 min | 15 min | 15 % |
| **Summe** | **2½–4 h** | **≈ 3 h** | **15 %** (Woche: 2 % → 6 %) |

Tokens: Die Agenten haben zusammen rund 4,0 M Tokens umgesetzt (Phase 2: 1,73 M, Phase 4: 2,25 M).
Das sind überwiegend gelesene Tokens, meist aus dem Zwischenspeicher. Wie viele davon Output waren, zeigt das
Werkzeug nicht getrennt an. Deshalb ist die Output-Prognose (0,33–0,55 M) nicht direkt nachprüfbar.

## Umfang – Prognose deutlich verfehlt

| | Prognose | Ist |
|---|---|---|
| Programm (Python) | ~2.000 | 7.639 |
| Oberfläche (HTML/JS/CSS) | ~900 | 3.020 |
| Tests | ~900 | 10.279 (973 Tests) |
| Start/CI | – | 185 |
| **Gesamt** | **3.000–4.000** | **21.123** |

Ursache: Die Agenten haben deutlich mehr Fehlerfälle abgefangen und getestet als angenommen, etwa
Plattformausfälle, Sprachvarianten von netsh/ping, Sicherheitsprüfungen der API und Abbruch in jedem Modul. Dazu
kamen gut 1.100 Zeilen aus der Prüfrunde (26 bestätigte Befunde, jeder mit Regressionstest). Die Zeit hat
trotzdem gereicht, weil die Arbeit parallel lief.

## Lehre für die Prognose von Stufe 2 und 3

- Zeit: Bau und Zusammenbau lagen unter der Prognose, die Prüfrunde dauerte etwa doppelt so lang wie geplant.
  Künftig für die Prüfung 60–100 min ansetzen.
- Kontingent: Eine Stufe dieser Größe braucht im Max-Abo etwa 15 % des 5-Stunden-Fensters und 4–5 % der Woche.
- Umfang: Faktor ~5 auf die bisherige Zeilenschätzung; Tests machen etwa die Hälfte aus.

| Stufe | Dauer (neu geschätzt) | 5-h-Fenster | Woche |
|---|---|---|---|
| 2 Überwachung | 2–2½ h | ~10 % | ~3 % |
| 3 Sicherheit und SNMP | 3–4 h | ~15–20 % | ~5 % |

# Prognose und Istwerte – Stufe 2 (Überwachung)

Prognose vom 10.10.2026, 19:20 Uhr. Abo Max, Leitung Opus 5.5, Ultracode an (jeder Prüfbefund wird von zwei
unabhängigen Gegenprüfern bewertet). Gebaut wird auf dem Zweig `stufe-2` in einem eigenen Arbeitsordner
(`.claude/worktrees/stufe-2`), damit der Projektordner für die Abnahme von Stufe 1 auf `main` bleibt.
Stand beim Start: 5-h-Fenster 1 %, Woche 7 %.

| Phase | Wer | Prognose Dauer | Ist Dauer | Ist Kontingent (5-h-Fenster / Woche) |
|---|---|---|---|---|
| 1 Bauplan Stufe 2, Kern (Datenbank v2, Monitor, Ereignisse, Attrappen, Sim-Labor) | Leitung (Opus) | 30–45 min | | |
| 2 Module bauen, 6 Agenten parallel | 4 Ingenieure (Opus), 2 Zeichner (Sonnet) | 40–60 min | | |
| 3 Zusammenbau, Ende-zu-Ende-Test, Demo im Browser | Leitung | 25–40 min | | |
| 4 Prüfung (4 Schwerpunkte, je Befund 2 Gegenprüfer, Nachbesserung) | Ingenieure | 70–110 min | | |
| 5 README, Checkliste, Istwerte, Tag `v2.0-stufe2-rc1` | Zeichner und Leitung | 15–20 min | | |
| **Summe** | | **3–4½ h** | | |

- Umfang: 11.000–14.000 Zeilen, etwa die Hälfte Tests (Stufe 1: 21.000; Stufe 2 laut Pflichtenheft ~60 % davon).
- Tokens: 5–7 Mio. verarbeitet (überwiegend Zwischenspeicher), davon 0,4–0,7 Mio. Output (Stufe 1: 4,0 Mio.).
- Kontingent: 20–30 % eines 5-h-Fensters (verteilt über ein bis zwei Fenster), Woche +6–9 %.
- Plattenbudget beim Bau: Agent-Protokolle dieses Projekts höchstens 400 MB (Start: 27 MB), Prüfung nach jeder Phase.
- Plattenbudget im Betrieb: 10 überwachte Geräte mit je 2 Diensten ≈ 30–60 MB Messwerte nach 30 Tagen, danach
  etwa 1 MB pro Monat (Stundenmittel). Anzeige der Dateigröße, Warnung ab 100 MB.
