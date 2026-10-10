# Bauplan Netzwerkscanner – Stufe 1 (verbindlich)

Dieser Bauplan ist der Vertrag zwischen allen Teilen des Codes. Grundlage ist
`Pflichtenheft Netzwerkscanner.md`. Wer etwas braucht, das hier nicht steht,
**ändert den Vertrag nicht selbst**, sondern meldet es (siehe Abschnitt 16).

## 1. Konventionen

- Python ≥ 3.12, entwickelt mit 3.13. Typ-Hinweise überall, `from __future__ import annotations`.
- **Bezeichner Englisch, Kommentare/Docstrings Deutsch (kurz), Texte für die Oberfläche und Log-Meldungen Deutsch** mit echten Umlauten (ä ö ü ß).
- Keine neuen Abhängigkeiten außer `requirements.txt`. Standardbibliothek bevorzugen.
- Logging über `logging.getLogger(__name__)`; nie `print` im Paket (außer `__main__`).
- Zeitstempel: ISO 8601 in UTC, Sekundengenauigkeit → `netscan.core.models.utc_now_iso()`.
- MAC-Adressen immer normalisiert: `aa:bb:cc:dd:ee:ff` (klein, Doppelpunkt) → `normalize_mac()`.
- Kein Modul in `netscan/net/` importiert `netscan.web` oder ruft die Oberfläche auf. Meldungen nach außen **nur** über `ScanContext` (→ Ereignis-Warteschlange).
- Plattformabhängiges (netsh, ping, route, arp) **nur** in `netscan/platform/`. Alles andere ist plattformneutral (später Raspberry Pi).
- Scapy wird nur in `netscan/net/arp.py` importiert, und zwar **verzögert** (innerhalb von Funktionen), damit alles ohne Npcap importierbar bleibt.

## 2. Verzeichnisse und Zuständigkeit

```
start.bat / start.sh            Start (Windows / Linux)
requirements*.txt, pyproject.toml
.github/workflows/tests.yml     Tests bei GitHub auf Windows + Linux
docs/BAUPLAN.md                 dieser Vertrag
netscan/
  __init__.py                   __version__
  __main__.py                   python -m netscan [--port] [--no-browser] [--data-dir] [--demo]
  config.py                     Pfade, Settings, SettingsStore, Logging          (Leitung)
  core/models.py                Datentypen                                       (Leitung)
  core/events.py                EventBus (Ereignis-Warteschlange)                (Leitung)
  core/context.py               ScanContext, CancelToken, RateLimiter, parallel_map (Leitung)
  core/jobs.py                  JobRunner (ein Auftrag zur Zeit)                 (Leitung)
  core/db.py                    Database: Verbindung, Schema, Settings-Tabelle   (Leitung)
  core/services.py              Services-Container, build_services()             (Leitung)
  core/inventory.py             Inventory: Geräte, Ports, Scans, Protokoll       (Leitung)
  core/guard.py                 NetworkGuard: Heimnetz, Hotspot-Sperre           (Agent guard)
  platform/base.py              Platform-Protokoll + Datentypen                  (Leitung)
  platform/windows.py           netsh, ping, route, arp, Get-NetAdapter          (Agent guard)
  platform/linux.py             iw/nmcli, ping, ip route, ip neigh               (Agent guard)
  net/adapters.py               Adapterliste, virtuelle ausblenden               (Agent guard)
  net/arp.py                    ARP-Scan (Scapy/Npcap)                           (Agent discovery)
  net/ping.py                   paralleler Ping                                  (Agent discovery)
  net/oui.py                    Herstellerliste, zufällige MAC                   (Agent discovery)
  net/names.py                  DNS rückwärts, NetBIOS, mDNS                     (Agent identify)
  net/ssdp.py                   SSDP/UPnP                                        (Agent identify)
  net/ports.py                  TCP-Port-Scan, Regeltabelle Risiko               (Agent ports)
  net/classify.py               Geräteart                                        (Agent ports)
  scan/pipeline.py              Scan-Ablauf, Enricher-Liste                      (Integration)
  web/server.py                 FastAPI: REST, WebSocket, Sicherheit             (Agent api)
  web/export.py                 JSON, CSV, HTML-Bericht                          (Agent api)
  web/static/                   index.html, app.js, style.css, vendor/           (Agent frontend)
  demo.py                       Demo-Modus mit simulierten Geräten               (Integration)
  data/oui.tsv.gz               IEEE-Liste, mitgeliefert (40.316 Einträge)
tests/
  conftest.py                   Netz-Sperre für Tests, Fixtures                  (Leitung)
  fakes.py                      FakePlatform, FakeArpSender                      (Leitung)
  sim.py                        simulierte Dienste auf 127.0.0.x                 (Leitung)
  test_<bereich>_*.py           je Agent eigene Dateien
```

Jeder Agent schreibt **nur** in seine Dateien und seine Testdateien `tests/test_<bereich>_*.py`.

## 3. Namensliste (verbindlich – keine Synonyme)

| Begriff | Bezeichner | Werte |
|---|---|---|
| Geräteart | `category` | `router`, `switch`, `server`, `pc`, `printer`, `iot`, `phone`, `unknown` |
| Herkunft der Geräteart | `category_source` | `auto`, `user` |
| Risikostufe | `risk` | `low`, `medium`, `high`, `critical` (UI: niedrig, mittel, hoch, kritisch) |
| Scan-Modus | `mode` | `full` (Netz absuchen), `registered` (nur eingetragene Geräte) |
| Auftragsart | `kind` | `scan`, `deep_scan`, `oui_update` |
| Auftragszustand | `state` | `idle`, `running`, `cancelling` |
| Auftragsergebnis | `result` | `completed`, `cancelled`, `failed`, `blocked` |
| Wächter-Entscheidung | `decision` | `allow`, `confirm`, `block` |
| Wächter-Grund | `code` | `ok_home`, `ok_network`, `blocked_ssid`, `blocked_gateway`, `foreign_network`, `unknown_network`, `no_gateway` |
| Gerät neu | `is_new` | zuerst im letzten abgeschlossenen Scan gesehen und nicht `known` |
| Gerät bekannt | `known` | vom Nutzer markiert |
| Private (zufällige) MAC | `mac_random` | Bit „locally administered“ gesetzt |
| Fundweg | `discovered_by` | Liste aus `arp`, `ping`, `cache`, `self` |

Es gibt **keinen** zweiten Namen für dieselbe Sache (nicht `scan_running`, nicht `scanning_active` –
Zustand steht nur in `JobStatus.state`).

## 4. Datentypen (`netscan/core/models.py`, fertig)

`Adapter`, `PortResult`, `NameInfo`, `SsdpInfo`, `Device`, `ScanRequest`, `GuardResult`,
`JobStatus`, `PingResult` – Feldnamen siehe Datei. Alle haben `to_dict()` (JSON-tauglich);
`Device.from_dict()` liest das wieder ein. `Device.to_dict()` enthält zusätzlich
`display_name`, `category_label`, `max_risk`.

## 5. Ereignisse (`netscan/core/events.py`, fertig)

`Event(seq, type, ts, job_id, data)`. Scan-Threads rufen nur `bus.publish(...)` (über `ScanContext`).
Der Webserver abonniert mit `bus.subscribe()` und leitet an den WebSocket weiter.

| `type` | `data` |
|---|---|
| `hello` | `{status}` – vom Server beim Verbinden (nicht über den Bus) |
| `job.started` | `{job_id, kind, label}` |
| `job.progress` | `{job_id, phase, done, total, message}` |
| `job.log` | `{job_id, level, message}` – level `info`/`warning`/`error` |
| `job.finished` | `{job_id, kind, result, summary, error}` |
| `device.updated` | `{device}` – nach dem Speichern eines Geräts |
| `devices.changed` | `{}` – Liste neu laden (nach Scan-Ende, nach Bearbeiten) |
| `guard.result` | `{guard}` |
| `oui.updated` | `{entries, source}` |

## 6. Auftragssteuerung (`core/jobs.py`, `core/context.py`, fertig)

- `JobRunner.start(kind, label, fn)` startet `fn(ctx)` in einem eigenen Thread. Läuft schon ein
  Auftrag → `JobBusyError`. Genau **ein** Auftrag zur Zeit.
- `fn` gibt ein `summary`-Dict zurück. Nur `ScanCancelled` → `result=cancelled`, `GuardBlocked` →
  `blocked`, jede andere Ausnahme → `failed` (Traceback ins Logfile, kurze Meldung ins Protokoll).
- `JobRunner.cancel()` setzt das `CancelToken`. **Abbruch muss innerhalb von 5 s greifen:**
  jede Schleife ruft `ctx.check_cancel()`, jede Netzoperation hat ein Timeout ≤ 2 s,
  Warten nur über `ctx.sleep()`.
- `parallel_map(ctx, fn, items, workers)` ist der einzige Weg für Parallelarbeit in `net/`:
  Thread-Pool, Abbruch, Drosselung (`ctx.rate.acquire()` pro Element, wenn `rate=True`),
  Fehler einzelner Elemente → `None` (geloggt auf DEBUG).
- `ctx.rate`: Token-Bucket mit `settings.rate_pps` (Standard 200 Pakete/Verbindungen pro Sekunde).
- `ctx.progress(phase, done, total, message)`, `ctx.log(message, level)`, `ctx.emit(type, data)`.

## 7. Plattform-Schicht (`platform/base.py` fertig, Implementierungen: Agent guard)

```python
class Platform(Protocol):
    name: str                                     # "windows" | "linux" | "fake"
    def interfaces(self) -> list[InterfaceAddr]   # IPv4 je Schnittstelle (psutil_interfaces(), fertig)
    def adapter_details(self) -> dict[str, AdapterDetail]   # Anzeigename -> Beschreibung, virtuell, WLAN, MAC
    def wifi_status(self) -> WifiStatus           # verbundene WLANs und ihre Namen (SSID)
    def default_gateway(self, adapter_name: str | None = None) -> str | None
    def neighbor_table(self) -> dict[str, str]    # IP -> MAC aus dem ARP-Cache des Systems, sendet NICHTS
    def neighbor_mac(self, ip: str, interface: str | None = None) -> str | None   # mit interface nur dessen ARP-Abschnitt
    def ping(self, ip: str, timeout_ms: int) -> PingResult
    def is_admin(self) -> bool
```

`WifiStatus.profile_names` (Adapter → Name des Netzwerkprofils, Windows: `Get-NetConnectionProfile`, braucht
keine Standortberechtigung) wird nur abgefragt, wenn netsh keinen Namen liefert, und dient **nur zum Sperren**.

Windows-Hinweise (für Agent guard):
- `netsh wlan show interfaces` ist **sprachabhängig** (deutsch: „Status : Verbunden“) und braucht seit
  Windows 11 24H2 die Standortberechtigung, sonst kommt eine Fehlermeldung statt SSID → dann
  `WifiStatus(readable=False, …)`. Ausgabe als Bytes lesen; **netsh liefert UTF-8**, ping/route/arp
  liefern OEM (cp850) → Dekodierung: erst UTF-8 strikt, dann `oem`, dann `cp850` (`errors="replace"`).
  Zeile `SSID` ≠ `BSSID` beachten.
- `ping -n 1 -w <ms> <ip>`: Erfolg nur, wenn `TTL=` in der Ausgabe steht (Rückgabecode 0 auch
  bei „Zielhost nicht erreichbar“). RTT aus `[=<](\d+)\s*ms`, `Zeit<1ms` → 0.5.
- Adapterdetails per `powershell -NoProfile -Command "Get-NetAdapter | Select Name,InterfaceDescription,Virtual,MacAddress,PhysicalMediaType,Status | ConvertTo-Json"`.
- Standard-Gateway per `Get-NetRoute -DestinationPrefix 0.0.0.0/0` (mit InterfaceAlias) oder `route print -4`.
- ARP-Cache per `arp -a` (MAC mit `-`), Regex statt Spaltenüberschriften (sprachabhängig).
- Alle Aufrufe mit `subprocess.run(..., timeout=…, creationflags=CREATE_NO_WINDOW)`.

## 8. Modul-Schnittstellen (`netscan/net/`)

Signaturen stehen als Platzhalter in den Dateien und sind verbindlich.

| Modul | Funktion |
|---|---|
| adapters | `list_adapters(platform, include_virtual=False) -> list[Adapter]`, `find_adapter(platform, name) -> Adapter \| None`, `hosts_of(adapter) -> list[str]` |
| arp | `arp_scan(ctx, adapter, hosts, sender=None) -> dict[ip, mac]` (Blöcke ≤ rate_pps, Paketabstand 1/rate_pps), `scapy_status() -> tuple[bool, str]`, `ArpUnavailable` (Scapy/Npcap/Rechte fehlen → Pipeline fällt auf Ping + ARP-Cache zurück) |
| ping | `ping_sweep(ctx, hosts) -> dict[ip, PingResult]` (nur erreichbare) |
| oui | `OuiDb.load(data_dir)` (None ⇒ nur mitgelieferte Liste), `.lookup(mac)`, `.entries`, `.source`; `is_random_mac(mac)`; `update_from_ieee(data_dir, fetch=None, *, min_entries=10000, ctx=None) -> int` (abbrechbar) (danach lädt der Server `OuiDb.load` neu) |
| names | `resolve_names(ctx, ips, adapter, *, resolver=None, netbios_port=137, mdns_browser=None) -> dict[ip, NameInfo]` |
| ssdp | `ssdp_discover(ctx, adapter, *, target=("239.255.255.250", 1900), allowed_ips=None, fetch=None) -> dict[ip, SsdpInfo]` |
| ports | `COMMON_PORTS`, `PORT_TABLE`, `DEEP_PORTS`, `describe_port(port) -> PortSpec`, `probe_port(ip, port, timeout_s, read_banner, source_ip=None) -> (offen, banner)`, `SourceAddressGone`, `scan_ports(ctx, targets: dict[ip, list[int]]) -> dict[ip, list[PortResult]]` (ruft `probe_port` über den Modulnamen auf) |
| classify | `classify(device) -> tuple[category, reason]`, `apply_classification(devices) -> None` (lässt `category_source == "user"` unangetastet) |

Testbarkeit: Jede Funktion, die Pakete sendet, hat einen injizierbaren Parameter
(`sender`, `resolver`, `mdns_browser`, `fetch`, `target`, Ports), damit Tests nur gegen
`127.0.0.x` oder Attrappen laufen.

## 9. Scan-Ablauf (`scan/pipeline.py`, Integration)

`run_scan(ctx, request, services) -> summary`:
1. Wächter erneut prüfen (doppelt hält besser) → `block` ⇒ `GuardBlocked`.
2. Adapter und Netz bestimmen. Präfix ≥ /24 normal; /22–/23 Warnung im Protokoll; kleiner als /22 ⇒ Abbruch mit Meldung.
3. Gerätesuche: `full` ⇒ ARP über alle Hosts + Ping-Ergänzung für den Rest; MAC für Ping-Treffer aus `neighbor_table()`.
   `registered` ⇒ nur letzte IPs eingetragener Geräte anpingen (+ ARP, falls verfügbar); **kein** Absuchen.
   Im Modus `registered` zählen nur Antworten mit **eingetragener MAC** (auch beim Router); kein SSDP-/mDNS-Multicast;
   Port-Scan nur für bestätigte Geräte.
   Null-, Broadcast- und Multicast-MACs werden verworfen; antwortet eine MAC für mehrere IPs, zählt die erste.
   Vor Ping, Namen, SSDP und Ports wird geprüft, ob Adapter und Netz noch dieselben sind (Wächter erneut;
   Wechsel ⇒ `NetworkChanged`, Ergebnis failed; gesperrt ⇒ `GuardBlocked`).
   Ohne Npcap/Adminrechte: nur Ping + ARP-Cache, mit Warnung.
4. Eigenen PC (`is_self`) und Router (`is_gateway`) ergänzen.
5. Gespeicherte Nutzerangaben übernehmen (`inventory.merge_user_fields`).
6. Enricher (`run(ctx, job: ScanJob, devices)`) der Reihe nach: `oui` → `names` → `ssdp` → `ports` (nur wenn `request.port_scan`, nicht für
   `port_scan_excluded` oder ausgenommene Kategorien) → `classify`. Weitere Stufen hängen Enricher an,
   ohne bestehende umzubauen.
7. Speichern: `inventory.record_seen()`, `inventory.set_ports()`, je Gerät `device.updated`.
8. Ende: `devices.changed`, Summary `{devices, new, duration_s, network}`.

`run_deep_scan(ctx, mac, services)`: erst prüfen, ob die IP noch zur MAC gehört (sonst Abbruch mit Meldung),
dann Ports 1–1024 eines Geräts, neu einordnen, speichern. Ausnahmen vom Port-Scan nach Kategorie gelten auch für
neue Geräte (vorläufige Einordnung).
Fortschrittsphasen (UI-Text): „Gerätesuche (ARP)“, „Ping“, „Namen“, „SSDP/UPnP“, „Ports“, „Einordnung“, „Speichern“.

## 10. Netz-Wächter (`core/guard.py`, Agent guard) – sicherheitskritisch

`NetworkGuard(platform, settings_store).check(adapter) -> GuardResult`, `remember_home(mac)`.

Regeln in dieser Reihenfolge:
1. Gesperrte Namen = `PERMANENT_BLOCKED_SSIDS` (`"DE22LA000256314 8159"`, nicht entfernbar) ∪ `settings.blocked_ssids_extra`.
   Vergleich **exakt** (Groß/Klein, Leerzeichen innen). Leerzeichen am Rand entfernen Plattform und API
   (sichere Richtung). Ein ähnlicher Name ist **nicht** gesperrt.
2. Ist **irgendein** verbundenes WLAN gesperrt ⇒ `block`/`blocked_ssid`. Dabei Gateway-MAC dieses WLANs
   (aus dem ARP-Cache, ohne Pakete) in `settings.blocked_gateway_macs` merken – nur, wenn das Gateway im
   Teilnetz dieses WLAN-Adapters liegt. Eine gesperrte MAC kann nie Heimnetz werden (`remember_home` ⇒ ValueError ⇒ API 422).
3. Ist der WLAN-Name nicht lesbar (`readable=False` oder `ssid=None` bei verbundenem WLAN) und die
   Gateway-MAC des betroffenen Adapters steht in `blocked_gateway_macs` ⇒ `block`/`blocked_gateway`.
   (Bei lesbarem, anderem Namen greift die MAC-Regel nicht – Pflichtenheft: ähnlicher Name nicht gesperrt.)
**Standard seit 10.10.2026 – frei außer Schule** (`settings.ask_before_foreign_scan = False`): Nach den Sperrregeln 1–3
gilt jedes Netz als frei ⇒ `allow`/`ok_network` (bzw. `ok_home` für ein gemerktes Heimnetz), auch ohne Router.
Nur wenn die Sperre nicht sicher prüfbar ist ⇒ `confirm`/`unknown_network`: Plattformzweifel, oder ein verbundener
WLAN-Adapter nennt weder SSID noch Netzwerkprofil. Die Regeln 4–6 gelten nur mit `ask_before_foreign_scan = True`:

4. Kein Gateway ermittelbar ⇒ `confirm`/`no_gateway`.
5. Gateway-MAC in `settings.home_gateway_macs` ⇒ `allow`/`ok_home`.
6. Sonst ⇒ `confirm`/`foreign_network` (MAC bekannt) bzw. `unknown_network` (MAC unbekannt).
   Ist der WLAN-Name nicht lesbar, sagt `reason` das dazu.

Ohne Standortberechtigung (Windows 11 24H2) liefert netsh keinen WLAN-Namen. Dann gilt zusätzlich:
- Heißt ein verbundenes Netzwerkprofil (`profile_names`) exakt wie ein gesperrter Name ⇒ block/blocked_ssid
  (und MAC lernen). Der Profilname wird nie für allow verwendet.
- `remember_home(mac, adapter)` lehnt über einen WLAN-Adapter ab, wenn weder SSID noch Profilname bekannt sind oder
  der Name gesperrt ist (`HomeRefused` ⇒ API 422). Ein bekannter, nicht gesperrter Profilname genügt
  (Leitungsentscheidung 10.10.2026: Standortberechtigung bleibt beim Nutzer aus).
- `GuardResult.profile_name` und `GuardResult.home_allowed` sagen der Oberfläche, ob „Das ist mein Heimnetz“
  angeboten wird.
- Gesperrte MACs werden aus `home_gateway_macs` entfernt; Regel 5 rechnet mit Heimnetz minus gesperrt.
`start.bat` nennt den Grund sachlich; eine rote Warnung zeigt die Oberfläche nur, wenn auch der Profilname fehlt.

Es gibt **keinen** Parameter, keine Einstellung und keine Schaltfläche, die `block` übergeht.
`blocked_gateway_macs` ist über die API nur lesbar. Geprüft wird vor jedem Scan, jedem Tiefenscan
und (Stufe 2) vor jedem Monitor-Durchlauf. Der Wächter selbst sendet keine Pakete.

## 11. Datenbank (`core/db.py` und `core/inventory.py` fertig)

Eine SQLite-Datei `<data_dir>/netscan.sqlite3`, WAL, `foreign_keys=ON`. Schema in `core/db.py`
(Tabellen `meta`, `settings`, `devices`, `ports`, `scans`, `scan_log`).

```python
class Inventory:
    def __init__(self, db: Database)
    def begin_scan(self, kind, adapter, network) -> int
    def finish_scan(self, scan_id, result, device_count) -> None      # räumt Protokolle alter Scans auf (nur letzte 50 behalten)
    def latest_scan_id(self, kind="scan", result="completed") -> int | None
    def list_scans(self, limit=20) -> list[dict]
    def add_log(self, scan_id, level, message) -> None
    def get_log(self, scan_id=None, limit=500) -> list[dict]          # {id, scan_id, ts, level, message}
    def merge_user_fields(self, device) -> Device                     # füllt custom_name, note, known, category (wenn user), port_scan_excluded, first_seen*
    def record_seen(self, device, scan_id) -> Device                  # Upsert; Nutzerfelder bleiben; gibt gespeicherten Stand zurück
    def set_ports(self, mac, scanned_ports, open_ports) -> list[PortResult]   # löscht nur geprüfte, nicht mehr offene; gibt NEU offene zurück
    def get(self, mac) -> Device | None
    def list_devices(self) -> list[Device]                            # mit ports, is_new, online (= im letzten Scan gesehen)
    def update_user_fields(self, mac, **fields) -> Device             # custom_name, category ("auto" = zurücksetzen), note, known, port_scan_excluded
    def inventory_view(self) -> list[dict]                            # [{mac, ip, name}] – Schnittstelle für Stufe 4
    def registered_devices(self) -> list[Device]
```

## 12. Web-API (`web/server.py`, Agent api)

Lauscht **nur** auf `127.0.0.1` (Konstante `BIND_HOST`, keine Option dafür), Port 8765.

| Methode | Pfad | Ergebnis |
|---|---|---|
| GET | `/` | `static/index.html` |
| GET | `/api/status?adapter=` | `{version, platform, admin, scapy:{available,reason}, oui:{entries,source}, job, guard}` |
| GET | `/api/adapters?include_virtual=false` | `[Adapter]` |
| GET | `/api/guard?adapter=` | `GuardResult` |
| POST | `/api/scan` | Body `ScanRequest` → 202 `{job_id, warning?}`; 404 Adapter fehlt; 409 Auftrag läuft; **423** gesperrt `{detail, guard}`; **428** Bestätigung nötig `{detail, guard}`; 422 Netz zu groß |
| POST | `/api/scan/cancel` | `{cancelled: bool}` |
| GET | `/api/job` | `JobStatus` |
| GET | `/api/devices` | `[Device]` |
| GET/PATCH | `/api/devices/{mac}` | Gerät / Nutzerfelder ändern |
| POST | `/api/devices/{mac}/deep-scan` | Body `{confirm_foreign}` – gleiche Codes wie `/api/scan`; Adapter = der, in dessen Netz die Geräte-IP liegt; liegt sie in keinem ⇒ 422; Gerät antwortet nicht mehr unter der IP ⇒ Auftrag endet mit Meldung |
| GET | `/api/inventory` | `[{mac, ip, name}]` |
| GET | `/api/scans`, `/api/log?scan_id=&limit=500` | Verlauf, Protokoll |
| GET | `/api/export/{json\|csv\|html}` | Datei-Download (`Content-Disposition`) |
| GET/PUT | `/api/settings` | Einstellungen (`blocked_gateway_macs` nur lesen; `permanent_blocked_ssids` nur lesen) |
| POST | `/api/oui/update` | Auftrag `oui_update` (holt IEEE-Liste, nur auf Knopfdruck) |
| WS | `/ws` | Ereignisse als JSON, zuerst `hello` |

Sicherheit: `TrustedHostMiddleware(["127.0.0.1", "localhost"])` gegen DNS-Rebinding; bei
POST/PUT/PATCH/DELETE wird ein fremder `Origin` mit 403 abgewiesen und `Content-Type: application/json`
verlangt (415); WebSocket prüft `Origin`. Kopfzeilen `X-Content-Type-Options: nosniff` und eine
CSP ohne Inline-Skripte (`script-src 'self'`). Keine CORS-Freigaben. Exporte entstehen nur als
Download, der Server schreibt keine Exportdateien.

## 13. Oberfläche (`web/static/`, Agent frontend)

Reines HTML/CSS/JavaScript ohne Build-Schritt, keine Inline-Skripte, keine externen Adressen
(vis-network liegt in `static/vendor/vis-network.min.js`, Version 10.1.2). Deutsch.
- Kopfzeile: Adapterwahl (virtuelle einblendbar), Modus, „Port-Scan“, Start, Abbrechen, Fortschrittsbalken (live über `/ws`).
- Wächter-Hinweis: `block` = rotes Band **ohne** Schaltfläche; `confirm` = gelbes Band mit „Nur diesmal scannen“ und „Das ist mein Heimnetz“.
- Reiter **Geräte** (Tabelle, „neu“ hervorgehoben, unbekannt markiert, Details mit Bearbeiten, Tiefenscan),
  **Netzwerkkarte** (Router in der Mitte, Stern, Symbol je Kategorie als Inline-SVG, Klick → Details),
  **Scan-Protokoll**. Export-Knöpfe, Einstellungen (gesperrte WLAN-Namen ergänzen, Drosselung, Ausnahmen, Herstellerliste aktualisieren).

## 14. Export (`web/export.py`, Agent api)

`to_json(devices, meta) -> str`, `to_csv(devices) -> str` (Semikolon, UTF-8 mit BOM für Excel),
`to_html(devices, meta) -> str` (eigenständige Datei, CSS inline, keine Skripte). Alle Geräte, alle Ports.

## 15. Tests – nur Loopback (harte Regel)

- **Kein Test und kein Entwicklungsschritt sendet ein Paket ins echte Netz.** Erlaubt ist nur `127.0.0.0/8`.
  `tests/conftest.py` erzwingt das: `connect`, `connect_ex`, `sendto`, `getaddrinfo` für Nicht-Loopback,
  `gethostbyaddr`, `getnameinfo` und Scapy-Senden lösen im Test einen Fehler aus.
- Kein echter Scan auf diesem PC, auch nicht „nur kurz“. `ping` nur auf `127.0.0.1`.
  Den echten Server darf man starten (lauscht nur lokal) und `GET`-Endpunkte abfragen; `POST /api/scan`
  gegen den echten Server nur im `--demo`-Modus.
- Simulierte Geräte: `tests/sim.py` startet Dienste auf `127.0.0.2`, `127.0.0.3`, … (HTTP mit
  UPnP-Beschreibung, SSH-, Telnet-, FTP-Banner, NetBIOS-Antworter auf hohem UDP-Port).
- Testbefehl (Git Bash):
  `PYTHONDONTWRITEBYTECODE=1 /c/Users/meyer/AppData/Local/Netzwerkscanner/venv/Scripts/python.exe -m pytest tests/test_<bereich>_*.py`
- Tests müssen auch unter Linux laufen (GitHub-Tests); Windows-Eigenes mit `@pytest.mark.skipif`.

## 16. Pfade, Logs, Plattenhygiene

- Daten: `NETSCAN_DATA_DIR` oder `%LOCALAPPDATA%\Netzwerkscanner\data` bzw. `~/.local/share/netzwerkscanner`.
- Python-Umgebung: `%LOCALAPPDATA%\Netzwerkscanner\venv` (nicht in Dropbox).
- Logdatei rotierend, 1 MB × 3. Keine Dumps von Paketen oder Antworten in Dateien.
- Keine Dateien außerhalb von Projekt, Datenordner und Testordner (`tmp_path`) anlegen.

## 17. Rückmeldung an die Leitung

Jeder Agent liefert am Ende: geänderte Dateien, Testergebnis (Anzahl bestanden/fehlgeschlagen),
**Vertragsfragen** (was am Bauplan fehlt oder nicht passt) und bekannte Grenzen.
