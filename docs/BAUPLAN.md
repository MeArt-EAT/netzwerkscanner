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

---

# Teil 2: Stufe 2 – Überwachung (verbindlich ab 10.10.2026)

Grundlage: Pflichtenheft, Abschnitt „Stufe 2 – Überwachung“. Alles aus Teil 1 gilt weiter (Konventionen §1,
Namensliste §3, Tests nur über Loopback §15, Plattenhygiene §16, Rückmeldung §17). Wer etwas braucht, das hier
nicht steht, ändert den Vertrag nicht selbst, sondern meldet es.

## 18. Grundsätze der Überwachung

- **Eigener Thread, kein Auftrag.** Der Monitor (`core/monitor.py`) läuft im Serverprozess neben dem
  `JobRunner`. Scans und Monitor laufen gleichzeitig; der Monitor belegt nie den JobRunner. Gestartet wird er nur
  von `server.run()` (echter Betrieb und Demo), nicht in Tests mit `create_app()`.
- **Wächter vor jedem Durchlauf** (Abnahmepunkt aus Stufe 1): je Adapter `NetworkGuard.check(adapter, quiet=True)`.
  Nur `allow` sendet. `block` ⇒ Ziele dieses Adapters pausieren (Grund `blocked`), `confirm` ⇒ pausieren
  (Grund `confirm`). Es gibt keinen Weg, das zu übergehen. Der Monitor meldet das Ergebnis als `guard.result`,
  wenn sich die Entscheidung ändert.
- **Nur verbundene Netze.** Ein Ziel wird nur geprüft, wenn seine IP im Netz eines verbundenen Adapters liegt;
  sonst Pause (Grund `no_adapter`). Jede Verbindung bindet an die IPv4 dieses Adapters (`source_ip`). Fehlt sie,
  wird das Ziel pausiert (`no_adapter`), nicht als offline gewertet.
- **Anderes Netz mit gleichem Adressbereich.** Ein Ziel merkt sich die Router-MAC seines Netzes (`gateway_mac`).
  Meldet der Wächter eine andere Router-MAC, pausiert das Ziel (Grund `other_network`) – es wird nichts an fremde
  Geräte mit zufällig gleicher IP gesendet und kein falscher Offline-Alert ausgelöst. Findet ein abgeschlossener
  Scan das Gerät im aktuellen Netz, übernimmt das Ziel dessen Router-MAC (Scan-Rückmeldung §26).
- **Wiedererkennung:** Nach den Erreichbarkeitstests liest der Monitor einmal den ARP-Cache
  (`platform.neighbor_table()`, sendet nichts). Steht unter der IP eine andere MAC als die des Ziels, gilt das Ziel
  als offline mit Hinweis „Unter <ip> antwortet ein anderes Gerät (<mac>)“. Nicht für den eigenen PC.
- **Schonend:** ein Erreichbarkeitstest und die gewählten Dienstprüfungen je Ziel und Durchlauf, jede Netzoperation
  ≤ 2 s, gedrosselt über einen eigenen `RateLimiter` (höchstens 50 Vorgänge/s), höchstens 16 Ziele gleichzeitig.
  Keine Anmeldung, keine Passwörter, keine Inhalte speichern.
- **Abbruch:** `Monitor.stop()` hält innerhalb von 5 s an (Programmende, Tests).
- **Plattenhygiene:** Messwerte kompakt (§20), Rohwerte 30 Tage, danach Stundenmittel; Alerts mit Obergrenze;
  der Monitor schreibt nichts ins Scan-Protokoll und loggt einen normalen Durchlauf höchstens auf DEBUG.

## 19. Namensliste Stufe 2 (verbindlich – keine Synonyme)

| Begriff | Bezeichner | Werte |
|---|---|---|
| Zielzustand | `MonitorTarget.status` | `unknown`, `online`, `degraded` (UI: gestört), `offline`, `paused` |
| Pausengrund | `MonitorTarget.pause_code` | `blocked`, `confirm`, `no_adapter`, `other_network`, `disabled` |
| Erreichbarkeitstest | `method` | `auto` (Ping, ohne Antwort TCP), `ping`, `tcp` |
| Dienstprüfung | `ServiceCheck.kind` | `tcp`, `http`, `https`, `smb`, `ssh` |
| Dienstzustand | `ServiceCheck.status` | `unknown`, `up`, `down` |
| Monitor-Zustand | `MonitorStatus.state` | `stopped` (Thread aus), `off` (Einstellung aus), `idle` (keine aktiven Ziele), `running`, `paused` (alle aktiven Ziele pausiert) |
| Alert-Regel | `Alert.rule` | `device_offline`, `service_down`, `rtt_high` (Zustands-Alerts, enden von selbst), `new_device`, `new_port` (Ereignis-Alerts, enden mit Quittieren) |
| Alert-Schwere | `Alert.severity` | `info`, `warning`, `critical` (UI: Hinweis, Warnung, kritisch) |
| Zeitraum | `range` | `24h`, `7d`, `30d`, `1y` |
| Messreihe | `(target_id, check_id)` | `check_id = 0` ist die Erreichbarkeit des Geräts |

„gestört“ (`degraded`) heißt: Gerät erreichbar, aber mindestens ein gewählter Dienst ist `down` oder die
Antwortzeit liegt über dem Schwellwert des Ziels.

## 20. Datenbank Schema 2 (`core/db.py`, Leitung, fertig)

`SCHEMA_VERSION = 2`. Neue Datenbanken bekommen alles über `SCHEMA`; eine Datenbank aus Stufe 1 wird beim Öffnen
erweitert (Spalte per `ALTER TABLE`, neue Tabellen per `CREATE TABLE IF NOT EXISTS`).

- `devices.checked_ports TEXT NOT NULL DEFAULT ''` – kommagetrennt alle Ports, die je für dieses Gerät geprüft
  wurden (Vereinigung über alle Scans). Grundlage für „neuer offener Port“: Alarm nur für Ports, die schon einmal
  geprüft und damals nicht offen waren.
- `monitor_targets` – ein Ziel je Gerät (`mac` UNIQUE, `ON DELETE CASCADE`), Einstellungen und letzter Zustand.
- `service_checks` – Dienstprüfungen je Ziel (`UNIQUE(target_id, kind, port)`), Einstellungen und letzter Zustand.
- `samples(target_id, check_id, ts, ok, rtt_ms)` – Rohwerte, `ts` = **Unix-Sekunden UTC** (Ausnahme von §1:
  Zeitreihen kompakt), `ok` 0/1, `WITHOUT ROWID`, Primärschlüssel `(target_id, check_id, ts)`.
- `samples_hourly(target_id, check_id, hour, n, up, rtt_avg, rtt_min, rtt_max)` – Stundenmittel, `hour` =
  Unix-Sekunden der vollen Stunde.
- `alerts` – Verlauf; höchstens ein aktiver Alert je `key` (Teilindex `WHERE closed IS NULL`).

Abschätzung: 30 Messreihen im 60-s-Takt ≈ 1,3 Mio. Rohwerte in 30 Tagen ≈ 30–60 MB, danach ~1 MB pro Monat.

## 21. Datentypen (`core/models.py`, Leitung, fertig)

`CheckResult(ok, rtt_ms, detail, code, method)`, `ServiceCheck`, `MonitorTarget`, `Sample`, `Alert`,
`MonitorStatus`, `ScanOutcome` – Feldnamen siehe Datei. Alle mit `to_dict()`; Zeitfelder als ISO-Text wie in
Stufe 1, nur `Sample.ts`, `now`-Parameter (Unix-Sekunden) und die Zeitachsen der Diagramme (Millisekunden) sind
Zahlen.

## 22. Monitor (`core/monitor.py`) und Ziele (`core/targets.py`) – Leitung, fertig

```python
class TargetStore:                      # nur Datenbank, keine Netzlogik
    def list(self, enabled_only=False) -> list[MonitorTarget]      # mit checks
    def get(self, mac) / get_by_id(target_id) -> MonitorTarget | None
    def add(self, mac, *, method, tcp_port, offline_after_min, rtt_threshold_ms, gateway_mac, network) -> MonitorTarget
    def update(self, mac, **fields) -> MonitorTarget                # enabled, method, tcp_port, offline_after_min, rtt_threshold_ms
    def remove(self, mac) -> MonitorTarget | None
    def add_check(self, target_id, kind, port, path="/") -> ServiceCheck
    def get_check(self, check_id) / update_check(check_id, enabled) / remove_check(check_id)
    def save_state(self, target: MonitorTarget) -> None             # Zustandsfelder von Ziel und Checks
    def set_network(self, target_id, gateway_mac, network) -> None

class Monitor:
    def __init__(self, services, *, clock=time.time)
    def start() / stop(timeout=6.0) / trigger()                     # Thread „monitor“
    def status() -> MonitorStatus
    def run_cycle(now: float | None = None) -> MonitorStatus       # synchron (Tests); „Jetzt prüfen“ nutzt trigger()
    def add_target(mac, *, method="auto", tcp_port=None, offline_after_min=None, rtt_threshold_ms=None,
                   checks: list[dict] | None = None) -> MonitorTarget   # LookupError (Gerät), ValueError, TargetExists
    def update_target(mac, **fields) -> MonitorTarget              # LookupError, ValueError
    def remove_target(mac) -> None                                 # LookupError; löscht Messwerte, schließt Alerts
    def add_check(mac, kind, port, path="/") -> ServiceCheck       # LookupError, ValueError, CheckExists
    def update_check(check_id, enabled: bool) -> ServiceCheck      # LookupError
    def remove_check(check_id) -> None                             # LookupError
    def suggestions(mac) -> list[dict]                             # checks.suggest_checks + {active}
    def on_scan(outcome: ScanOutcome) -> None                      # Router-MAC/Netz gesehener Ziele übernehmen
```

Ablauf `run_cycle`: Einstellungen laden → aktive Ziele → je Adapter Wächter → Erreichbarkeit (parallel) → ARP-Cache
lesen (Wiedererkennung) → Dienstprüfungen nur bei erreichbarem Gerät (sonst Checks `unknown`, Detail „Gerät nicht
erreichbar“) → Zustände berechnen (`down_since`, `rtt_high_since`, `status_since`) → `metrics.record()` →
`alert_engine.evaluate_target/evaluate_check` → `targets.save_state` → Ereignisse. Einmal je Stunde Wartung:
`metrics.compact(now)`, `alerts.prune(now)`, Dateigröße merken. Fehler in einem Durchlauf beenden nie den Thread.

## 23. Prüfungen (`net/checks.py`, Agent checks)

```python
CHECK_KINDS = ("tcp", "http", "https", "smb", "ssh")
DEFAULT_PORTS = {"http": 80, "https": 443, "smb": 445, "ssh": 22}
def connect(ip, port, timeout_s, source_ip=None) -> socket.socket   # EINZIGER Weg ins Netz; Tests/Demo ersetzen ihn
def check_tcp(ip, port, timeout_s, *, source_ip=None) -> CheckResult
def check_http(ip, port, timeout_s, *, tls=False, path="/", source_ip=None) -> CheckResult
def check_ssh(ip, port, timeout_s, *, source_ip=None) -> CheckResult
def check_smb(ip, port, timeout_s, *, source_ip=None) -> CheckResult
def run_check(kind, ip, port, timeout_s, *, path="/", source_ip=None) -> CheckResult      # Verteiler
def check_reachability(ip, *, method, ping, timeout_ms, tcp_ports, source_ip=None) -> CheckResult
def fallback_tcp_ports(device: Device) -> list[int]                 # höchstens 3, aus device.ports
def suggest_checks(device: Device) -> list[dict]                     # [{kind, port, path, label, reason}]
```

- Alle Funktionen rufen `connect` über den Modulnamen (`checks.connect`), damit Tests und Demo ihn ersetzen.
  Timeout auf 0,05–2 s begrenzt. Ist `source_ip` am System nicht vorhanden ⇒ `ports.SourceAddressGone` (wie Stufe 1).
- `tcp`: offen = ok; abgelehnt ⇒ „Port geschlossen“, Zeitüberschreitung ⇒ „keine Antwort“.
- `http`/`https`: `GET path` mit `Host: <ip>`, ohne Weiterleitungen zu folgen, höchstens 4 KB lesen, nichts speichern.
  ok bei Statuscode 100–499 (401/403 = Dienst läuft, Anmeldung nötig), down bei 5xx oder ohne gültige Antwort.
  `detail` z. B. „HTTP 200“, `code` = Statuscode. HTTPS ohne Zertifikatsprüfung (NAS mit eigenem Zertifikat);
  die Bewertung von Zertifikaten kommt in Stufe 3.
- `ssh`: ok, wenn die erste Zeile mit `SSH-` beginnt. `smb`: SMB2-NEGOTIATE ohne Anmeldung, ok bei einer Antwort, die
  mit dem NetBIOS-Kopf und `\xfeSMB` oder `\xffSMB` beginnt; Port offen ohne SMB-Antwort ⇒ down
  „Port offen, aber keine SMB-Antwort“.
- `check_reachability`: `ping` ⇒ nur `ping(ip, timeout_ms)`; `tcp` ⇒ nur TCP auf `tcp_ports`; `auto` ⇒ erst Ping,
  ohne Antwort TCP. Bei TCP gilt auch „Verbindung abgelehnt“ als erreichbar (das Gerät hat geantwortet).
  `method` im Ergebnis: `ping` bzw. `tcp:<port>`.
- `suggest_checks`: aus offenen Ports: 445→smb, 22→ssh, 80/8080/5000→http, 443/8443/5001→https, sonst bekannte
  Dienste als `tcp` (z. B. 21, 139, 548, 631, 873, 1883, 3389, 8883, 9100). Nur Ports, die offen gespeichert sind.

## 24. Messwerte (`core/metrics.py`, Agent metrics)

```python
RAW_KEEP_DAYS = 30
HOURLY_KEEP_DAYS = 730
class MetricsStore:
    def __init__(self, db)
    def record(self, samples: Iterable[Sample]) -> None              # eine Transaktion; gleicher Schlüssel ersetzt
    def availability(self, target_id, check_id=0, *, since: int, until: int) -> dict
        # {up_pct (None ohne Werte), samples, up} aus Roh- und Stundenwerten
    def availability_map(self, now: int) -> dict[tuple[int, int], dict[str, dict]]   # {(t, c): {"24h": …, "7d": …}}
    def series(self, target_id, check_id=0, *, since: int, until: int, max_points=400) -> dict
        # {"bucket_s", "points": [{t (ms), rtt_avg, rtt_min, rtt_max, up_pct, n}]} – Eimer ohne Werte: n=0, Rest None
    def trend(self, target_id, check_id=0, *, days=30, now: int) -> list[dict]   # [{day "YYYY-MM-DD" (UTC), up_pct, n}]
    def compact(self, now: int, keep_days=RAW_KEEP_DAYS) -> int      # nur volle Stunden vor der Grenze; idempotent
    def delete_series(self, target_id, check_id=None) -> int         # None = alle Reihen des Ziels
    def prune_orphans(self, valid: set[tuple[int, int]]) -> int
    def size_bytes(self) -> int                                     # page_count × page_size
    def counts(self) -> dict                                       # {"raw": n, "hourly": n}
```

Verfügbarkeit = gute Messwerte / alle Messwerte im Zeitraum. Pausen sind Lücken, keine Ausfälle. Stundenwerte
zählen mit ihren `n` und `up`. `24h`, `7d`, `30d` aus Rohwerten (plus Stundenwerte, falls schon verdichtet),
`1y` überwiegend aus Stundenwerten. Stundenwerte älter als `HOURLY_KEEP_DAYS` entfernt `compact`.

## 25. Alerts (`core/alerts.py`, Agent alerts)

```python
EVENT_RULES = frozenset({"new_device", "new_port"})
ALERT_KEEP_DAYS = 365; ALERT_KEEP_MAX = 5000
class AlertStore:
    def __init__(self, db, bus)
    def open(self, *, rule, key, severity, title, message, mac=None, target_id=None, check_id=None, now=None) -> Alert | None
        # None, wenn für key schon ein aktiver Alert besteht (idempotent)
    def close(self, key, now=None) -> Alert | None
    def acknowledge(self, alert_id, now=None) -> Alert              # LookupError; Ereignis-Alerts werden dabei geschlossen
    def acknowledge_all(self, now=None) -> int
    def get(self, alert_id) -> Alert | None
    def list(self, *, state="active", limit=200, mac=None) -> list[Alert]   # active | unacked | all; neueste zuerst
    def counts(self) -> dict                                       # {"active", "unacked", "by_rule": {...}}
    def frequency(self, *, days=30, now) -> list[dict]             # [{day, device_offline, service_down, rtt_high, new_device, new_port}]
    def prune(self, now, keep_days=ALERT_KEEP_DAYS, keep_max=ALERT_KEEP_MAX) -> int   # nur geschlossene
class AlertEngine:
    def __init__(self, store, settings_store)
    def evaluate_target(self, target, device, now: float) -> None   # device_offline, rtt_high
    def evaluate_check(self, target, check, device, now: float) -> None   # service_down
    def on_target_removed(self, target) -> None                     # schließt Zustands-Alerts des Ziels
    def on_check_removed(self, target, check) -> None
    def on_scan(self, outcome: ScanOutcome) -> None                 # new_device, new_port
```

`now` ist hier Unix-Sekunden (`float`); gespeichert wird ISO-Text (`opened`, `closed`, `acknowledged`).
Regeln (Schwellen aus §28):
- `device_offline` (Schlüssel `device_offline:<mac>`): Status `offline` seit `down_since` und mindestens
  `target.offline_after_min` bzw. `alert_offline_minutes` Minuten ⇒ öffnen; Status `online`/`degraded` ⇒ schließen;
  `paused`/`unknown` ⇒ nichts ändern. Schwere `critical` bei Router und Server/NAS, sonst `warning`.
- `service_down` (`service_down:<check_id>`): Check `down` seit `down_since` ≥ `alert_service_minutes` ⇒ öffnen;
  Check `up` oder `unknown` ⇒ schließen. Schwere `warning`.
- `rtt_high` (`rtt_high:<mac>`): Schwellwert gesetzt, Antwortzeit darüber seit `rtt_high_since` ≥
  `alert_rtt_minutes` ⇒ öffnen; `rtt_high_since` wieder leer (Antwortzeit darunter oder Gerät offline) ⇒ schließen.
  Schwere `info`.
- `new_device` (`new_device:<mac>`): abgeschlossener Scan, Gerät zum ersten Mal gesehen und nicht „bekannt“,
  Einstellung `alert_new_device`. Schwere `warning`.
- `new_port` (`new_port:<mac>:<port>`): Port war schon einmal geprüft und nicht offen, jetzt offen; Gerät nicht neu;
  Einstellung `alert_new_port`. Schwere aus dem Port-Risiko: low→info, medium→warning, high/critical→critical.
  Beim eigenen PC zusätzlich der Hinweis: „Eigener PC: lokal geprüft – die Windows-Firewall wird dabei nicht
  berücksichtigt; von anderen Geräten aus kann der Port gesperrt sein.“
- Titel und Meldung deutsch mit Gerätenamen (`display_name`), IP und – wo passend – Dienst und Port.
- Ereignisse über den Bus: `alert.opened {alert}`, `alert.closed {alert}`, `alert.acknowledged {ids}`.

## 26. Scan-Rückmeldung (`scan/pipeline.py`, `core/inventory.py`, Leitung, fertig)

- `Inventory.set_ports` merkt sich zusätzlich die geprüften Ports (`checked_ports`); `Inventory.checked_ports(mac)`.
- Nach einem abgeschlossenen Scan bzw. Tiefenscan ruft die Pipeline jeden Eintrag aus `services.scan_listeners`
  mit einem `ScanOutcome(scan_id, kind, adapter, gateway_mac, seen_macs, new_devices, new_ports)` auf.
  `new_ports` enthält nur Ports, die vorher schon geprüft und nicht offen waren. Fehler eines Empfängers werden
  geloggt und stoppen den Scan nie. Standard-Empfänger: `alert_engine.on_scan`, `monitor.on_scan`.

## 27. Web-API Stufe 2 (`web/monitor_api.py` und Ergänzungen in `web/server.py`, Agent api)

`monitor_api.router = APIRouter(prefix="/api")`, in `create_app` eingebunden. Fehler wie in Stufe 1 als
`{detail}`. MACs im Pfad werden normalisiert; ungültig oder unbekannt ⇒ 404.

| Methode | Pfad | Ergebnis |
|---|---|---|
| GET | `/api/monitor` | `{status: MonitorStatus, targets: [TargetView]}` |
| POST | `/api/monitor/targets` | Body `{mac, method?, tcp_port?, offline_after_min?, rtt_threshold_ms?, checks?: [{kind, port, path?}]}` → 201 `TargetView`; 404 Gerät unbekannt; 409 schon überwacht; 400 ungültig |
| GET | `/api/monitor/targets/{mac}` | `TargetView`; 404 |
| PATCH | `/api/monitor/targets/{mac}` | `{enabled?, method?, tcp_port?, offline_after_min?, rtt_threshold_ms?}` (null = zurücksetzen) → `TargetView` |
| DELETE | `/api/monitor/targets/{mac}` | 204 – Messwerte gelöscht, Zustands-Alerts geschlossen |
| GET | `/api/monitor/targets/{mac}/suggestions` | `[{kind, port, path, label, reason, active}]` – auch für noch nicht überwachte Geräte |
| POST | `/api/monitor/targets/{mac}/checks` | `{kind, port, path?}` → 201 `ServiceCheck`; 409 doppelt |
| PATCH | `/api/monitor/checks/{id}` | `{enabled}` → `ServiceCheck` |
| DELETE | `/api/monitor/checks/{id}` | 204 |
| POST | `/api/monitor/run` | 202 `{started: true}` – nächster Durchlauf sofort (`trigger()`, Wächter gilt) |
| GET | `/api/metrics/series?mac=&check_id=0&range=24h` | `{range, since, until, bucket_s, points}` (t in ms) |
| GET | `/api/metrics/trend?mac=&check_id=0&days=30` | `[{day, up_pct, n}]` (days 1–365) |
| GET | `/api/metrics/overview` | `{counts: {online, degraded, offline, paused, unknown}, db_size_bytes, db_warn, samples: {raw, hourly}}` |
| GET | `/api/alerts?state=active&limit=200&mac=` | `[Alert]` (state `active`, `unacked`, `all`; limit 1–1000) |
| POST | `/api/alerts/{id}/ack` | `Alert`; 404 |
| POST | `/api/alerts/ack-all` | `{acknowledged: n}` |
| GET | `/api/alerts/stats?days=30` | `{days: [...frequency], counts}` |
| GET | `/api/autostart` | `{supported, enabled, detail}` |
| PUT | `/api/autostart` | `{enabled}` → wie GET; 501 ohne Unterstützung; 500 mit verständlicher Meldung bei Fehlschlag |

- `TargetView` = `MonitorTarget.to_dict()` + `device {mac, ip, display_name, category, category_label, is_self,
  online, mac_random}` + `availability {"24h": …, "7d": …}`; jede Prüfung in `checks` zusätzlich mit `availability`.
- `/api/status` bekommt `monitor` (MonitorStatus) und `alerts` (`{active, unacked}`).
- `PUT /api/settings`: die neuen Einstellungen aus §28 sind änderbar (Grenzen aus `config.SETTING_LIMITS`).
- `DB_WARN_BYTES = 100 * 1024 * 1024` (in `config.py`) – `db_warn` ab dieser Größe.

## 28. Einstellungen Stufe 2 (`config.py`, Leitung, fertig)

| Feld | Standard | Grenzen |
|---|---|---|
| `monitor_enabled` | `True` | bool |
| `monitor_interval_s` | 60 | 10–3600 |
| `monitor_timeout_ms` | 1000 | 200–2000 |
| `alert_offline_minutes` | 5 | 1–1440 |
| `alert_service_minutes` | 2 | 1–1440 |
| `alert_rtt_minutes` | 5 | 1–1440 |
| `alert_new_device` | `True` | bool |
| `alert_new_port` | `True` | bool |

Ziel-Einstellungen (`config.TARGET_LIMITS`): `offline_after_min` 1–1440 oder null, `rtt_threshold_ms` 1–10000
oder null, `tcp_port` 1–65535 oder null. `MAX_TARGETS = 64`, `MAX_CHECKS_PER_TARGET = 8`.

## 29. Ereignisse Stufe 2 (`core/events.py` unverändert)

| `type` | `data` |
|---|---|
| `monitor.status` | `{status}` – bei Zustandswechsel und nach jedem Durchlauf |
| `monitor.cycle` | `{ts, targets: [{mac, status, rtt_ms, detail, checks: [{id, status, rtt_ms, detail}]}]}` |
| `monitor.targets` | `{}` – Zielliste neu laden (Anlegen, Ändern, Löschen) |
| `alert.opened` / `alert.closed` | `{alert}` |
| `alert.acknowledged` | `{ids}` |

## 30. Oberfläche Stufe 2 (`web/static/`, Agent frontend)

- Neue Datei `static/monitor.js` (eigenes IIFE, reine Hilfsfunktionen mit `module.exports` für Node-Tests), dazu
  die nötigen Ergänzungen in `index.html`, `app.js` und `style.css`. Chart.js 4.5.1 liegt fertig unter
  `static/vendor/chart.umd.min.js` (MIT, Lizenz daneben). Kein Zeit-Adapter: x-Achse `linear` mit Millisekunden
  und eigener Beschriftung. Keine Inline-Skripte, Netzdaten nur über `textContent`.
- Reiter: Geräte | Netzwerkkarte | **Überwachung** | **Alerts** (mit Zähler offener Alerts) | Scan-Protokoll.
- **Überwachung:** Monitor-Zustand mit Grund, „Jetzt prüfen“; Status-Übersicht (Kacheln und Diagramm); Tabelle der
  Ziele (Name, IP, Status seit, Antwortzeit, Verfügbarkeit 24 h / 7 d, Dienste als Chips); Ziel wählen ⇒
  Antwortzeit-Verlauf (Linie mit min/max-Band, Lücken sichtbar, Zeitraum 24 h / 7 d / 30 d / 1 Jahr) und
  Verfügbarkeits-Trend (Balken je Tag).
- **Alerts:** Liste (aktiv / unquittiert / alle), quittieren einzeln und alle, Alert-Häufigkeit (gestapelte Balken
  je Tag und Regel, 30 Tage).
- **Detailbereich Geräte:** Abschnitt „Überwachung“: an/aus, Dienstvorschläge zum An- und Abwählen, Schwellen.
  Bei Handys (`phone`) und Geräten mit privater MAC der Datenschutz-Hinweis (Grundsatz 7): „Die Überwachung macht
  sichtbar, wann diese Person zu Hause ist. Alle im Haushalt sollten davon wissen.“ Beim eigenen PC unter den Ports
  der Firewall-Hinweis aus §25.
- **Einstellungen:** Abschnitt Überwachung (an/aus, Intervall, Zeitschwellen, Alerts für neue Geräte/Ports) und
  Autostart (nur Windows, mit Erklärung „startet mit der Anmeldung, ohne Adminrechte – ARP-Scan dann nicht möglich“).
- **Statuszeile:** Monitor-Zustand, Dateigröße der Datenbank, ab 100 MB als Warnung.
- Diagramme folgen Hell/Dunkel, Animation aus, alte Diagramme vor dem Neuzeichnen zerstören.

## 31. Autostart (`platform/autostart.py`, Agent platform)

`AutostartStatus(supported, enabled, detail)`, `autostart_status(*, run=None) -> AutostartStatus`,
`set_autostart(enabled: bool, *, run=None) -> AutostartStatus` (`AutostartError` mit deutscher Meldung).
Windows: Aufgabenplanung über `schtasks.exe`, Aufgabe „Netzwerkscanner“, Auslöser bei Anmeldung des aktuellen
Benutzers, **`/RL LIMITED` (ohne Adminrechte)**, Aktion `"<venv>\Scripts\pythonw.exe" "<Projekt>\run_server.py"
--no-browser`. Begründung: Projektordner und Python-Umgebung sind ohne Adminrechte beschreibbar (Übergabe §6); eine
Aufgabe mit höchsten Rechten wäre eine dauerhafte Rechteausweitung ohne Rückfrage. Der Monitor braucht keine
Adminrechte; für einen ARP-Scan weiter `start.bat` (meldet dann „läuft bereits“ – der Scan läuft ohne ARP).
Linux: `supported=False` mit Hinweis auf systemd. Tests rufen `schtasks` nie wirklich auf (conftest sperrt es).

## 32. Demo Stufe 2 (`demo.py`, Agent platform)

Demo-Monitor mit Intervall 15 s; überwacht Router, NAS (SMB, HTTP 5000, SSH), PC und iPhone; künstlicher Verlauf der
letzten 7 Tage; das Telnet-Gerät fällt regelmäßig aus (Offline-Alert), der HTTP-Dienst der NAS stoppt zeitweise
(Dienst-Alert). `checks.connect` wird im Demo-Prozess auf die Sim-Ports umgeleitet (wie `ports.probe_port`).
Sendet weiterhin nichts ins echte Netz.

## 33. Zuständigkeit Stufe 2

| Bereich | Dateien | Wer |
|---|---|---|
| Kern | `config.py`, `core/models.py`, `core/db.py`, `core/inventory.py`, `core/targets.py`, `core/monitor.py`, `core/services.py`, `core/guard.py` (nur `quiet`), `scan/pipeline.py`, `net/ports.py` (nur Text 8883), `tests/conftest.py`, `tests/fakes.py`, `tests/sim.py`, `tests/test_core_*`, `tests/test_monitor_*` | Leitung |
| checks | `net/checks.py`, `tests/test_checks_*.py` | Agent checks (Ingenieur) |
| metrics | `core/metrics.py`, `tests/test_metrics_*.py` | Agent metrics (Ingenieur) |
| alerts | `core/alerts.py`, `tests/test_alerts_*.py` | Agent alerts (Ingenieur) |
| api | `web/monitor_api.py`, `web/server.py`, `tests/test_api_monitor_*.py` | Agent api (Zeichner) |
| frontend | `web/static/*` (außer `vendor/`), `tests/test_frontend_*.py` | Agent frontend (Ingenieur) |
| platform | `platform/autostart.py`, `demo.py`, `tests/test_autostart_*.py`, `tests/test_demo_*.py` | Agent platform (Zeichner) |
