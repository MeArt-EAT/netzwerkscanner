"""Demo-Modus: simuliertes Heimnetz auf 127.0.0.0/28. Sendet NICHTS ins echte Netz.

Gedacht zum Ausprobieren der Oberfläche und für Tests im Browser. Nutzt die Sim-Bausteine aus
tests/ (läuft deshalb nur aus dem Projektordner) und ersetzt in diesem Prozess genau die Stellen,
die sonst Pakete ins Netz senden würden.

Stufe 2 (BAUPLAN §32): Fünf Geräte stehen schon im Inventar und werden überwacht (Router, NAS mit SMB, HTTP und
SSH, PC, iPhone, Telnet-Gerät). Dazu kommen ein künstlicher Verlauf der letzten 7 Tage und einige alte, geschlossene
Alerts, damit Diagramme und Häufigkeit gefüllt sind. Im laufenden Prozess fallen das Telnet-Gerät und der HTTP-Dienst
der NAS zeitweise aus („Wechselspiel“). Den Monitor selbst startet – wie im echten Betrieb – server.run().
"""

from __future__ import annotations

import atexit
import logging
import math
import random
import shutil
import socket
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from netscan import config
from netscan.core.models import (
    RISK_LABELS,
    Adapter,
    Device,
    MonitorTarget,
    NameInfo,
    PingResult,
    PortResult,
    Sample,
    SsdpInfo,
    iso_from_ts,
    normalize_mac,
    ts_from_iso,
)
from netscan.core.services import Services, build_services

log = logging.getLogger(__name__)

DEMO_ADAPTER = Adapter(
    name="Ethernet (Demo)",
    description="Simuliertes Heimnetz auf 127.0.0.0/28",
    mac="00:1b:21:00:00:01",
    ipv4="127.0.0.1",
    netmask="255.255.255.240",
    network="127.0.0.0/28",
    prefix=28,
    is_virtual=False,
    is_wireless=False,
    is_up=True,
)
ROUTER_IP, ROUTER_MAC = "127.0.0.2", "3c:a6:2f:11:22:02"
NAS_IP, NAS_MAC = "127.0.0.3", "00:11:32:aa:bb:03"
PC_IP, PC_MAC = "127.0.0.5", "00:1b:21:aa:bb:05"
TELNET_IP, TELNET_MAC = "127.0.0.6", "24:0a:c4:aa:bb:06"
PHONE_IP, PHONE_MAC = "127.0.0.10", "a4:c3:61:aa:bb:0a"
NAS_HTTP_PORT = 5000  # echter Port; der Sim-Port steht in lab.port_map

# Überwachung in der Demo (BAUPLAN §32)
DEMO_MONITOR_INTERVAL_S = 15
DEMO_MONITOR_TIMEOUT_MS = 500

# Wechselspiel im laufenden Demo-Prozess, in Sekunden: so lange läuft alles, dann so lange der Ausfall.
# Das Telnet-Gerät fällt erst nach TELNET_UP_S aus und bleibt TELNET_DOWN_S weg (länger als die Alert-Schwelle),
# der HTTP-Dienst der NAS ebenso. Tests setzen diese Werte kleiner (monkeypatch), bevor sie die Demo bauen.
TELNET_UP_S = 3 * 60.0
TELNET_DOWN_S = 6 * 60.0
NAS_HTTP_UP_S = 10 * 60.0
NAS_HTTP_DOWN_S = 4 * 60.0
RETRY_S = 5.0  # scheitert ein Wechsel (z. B. Port belegt), wird nach so vielen Sekunden erneut versucht

# Künstlicher Verlauf (klein halten: 5-Minuten-Takt ≈ 16 000 Messwerte ≈ 1 MB)
HISTORY_DAYS = 7
HISTORY_STEP_S = 300
HISTORY_SEED = 20261010  # fester Startwert: jede Demo zeigt denselben Verlauf
GAP_HOURS_AGO = 76.0  # Lücke im Verlauf (Programm war nicht aktiv): Beginn, gemessen vom Ende des Verlaufs
GAP_MINUTES = 45


def _extra_devices() -> list[Any]:
    from tests.sim import SimDevice

    return [
        SimDevice("127.0.0.8", "28:ee:52:aa:bb:08", "Switch", tcp={22: b"SSH-2.0-dropbear\r\n"},
                  http={80: {"/": ("text/html", b"<title>TP-Link TL-SG108E</title>")}}),
        SimDevice("127.0.0.9", "b8:27:eb:aa:bb:09", "Raspberry Pi", tcp={22: b"SSH-2.0-OpenSSH_9.2p1 Debian\r\n"},
                  http={80: {"/": ("text/html", b"<title>AdGuard Home</title>")}}),
        SimDevice("127.0.0.10", "a4:c3:61:aa:bb:0a", "iPhone"),
    ]  # fmt: skip


def _demo_devices() -> list[Any]:
    """Sim-Geräte: das Standardnetz, nur die NAS bekommt SMB-Attrappe, HTTP 5000, SSH 22 und HTTPS 5001."""
    from tests.sim import SimDevice, standard_devices

    devices: list[Any] = []
    for dev in standard_devices():
        if dev.ip == NAS_IP:
            dev = SimDevice(
                NAS_IP, NAS_MAC, "NAS",
                tcp={22: b"SSH-2.0-OpenSSH_8.2p1\r\n"},
                smb=(445,),
                http={NAS_HTTP_PORT: {"/": ("text/html", b"<title>Synology DiskStation</title>")}},
                https={5001: {"/": ("text/html", b"<title>Synology DiskStation</title>")}},
            )  # fmt: skip
        devices.append(dev)
    return devices + _extra_devices()


DEMO_OUI_MESSAGE = (
    "Im Demo-Modus wird nichts aus dem Internet geladen – die Herstellerliste lässt sich nur im normalen "
    "Betrieb aktualisieren. Die mitgelieferte Liste bleibt in Gebrauch."
)


def demo_oui_update(data_dir: Any = None, fetch: Any = None, **_kw: Any) -> int:
    """Ersatz für oui.update_from_ieee im Demo-Modus: lädt nichts, ändert nichts, meldet es verständlich."""
    raise OSError(DEMO_OUI_MESSAGE)


def _demo_fetch(url: str, *_args: Any, **_kw: Any) -> bytes:
    """Ersatz für oui._default_fetch (doppelt hält besser): keine Verbindung ins Internet."""
    raise OSError(DEMO_OUI_MESSAGE)


# =====================================================================================
# Inventar und überwachte Ziele
# =====================================================================================

# Anzeigename und „bekannt“ je Gerät. Das Telnet-Gerät bleibt unbekannt (offener Telnet-Port, Risiko hoch).
_DEVICE_NAMES: dict[str, tuple[str, bool]] = {
    "router": ("Router", True),
    "nas": ("NAS", True),
    "pc": ("PC", True),
    "iphone": ("iPhone", True),
    "telnet": ("Telnet-Gerät", False),
}
_KEY_MAC: dict[str, str] = {
    "router": ROUTER_MAC,
    "nas": NAS_MAC,
    "pc": PC_MAC,
    "iphone": PHONE_MAC,
    "telnet": TELNET_MAC,
}
# Typische Antwortzeiten in ms (Kabel, WLAN, schwaches IoT-Gerät) – für den Verlauf und das Live-Ping
_BASE_RTT: dict[str, float] = {"router": 0.9, "nas": 2.2, "pc": 0.7, "iphone": 22.0, "telnet": 11.0}
_RTT_BY_IP: dict[str, float] = {
    ROUTER_IP: _BASE_RTT["router"], NAS_IP: _BASE_RTT["nas"], PC_IP: _BASE_RTT["pc"],
    PHONE_IP: _BASE_RTT["iphone"], TELNET_IP: _BASE_RTT["telnet"],
}  # fmt: skip
# Typische Antwortzeiten der Dienste in ms
_CHECK_RTT: dict[str, float] = {"ssh": 4.5, "smb": 3.2, "http": 9.0}

# Ziele: (Schlüssel, MAC, Optionen für Monitor.add_target). Das Telnet-Gerät antwortet nur auf Ping; so lässt es sich
# im Wechselspiel (FakePlatform.alive) wirklich abschalten – ein TCP-Test gälte auch bei „abgelehnt“ als erreichbar.
# Seine Offline-Schwelle von 2 Minuten liegt unter dem Ausfall des Wechselspiels, damit der Alert sichtbar wird.
_TARGET_SPECS: tuple[tuple[str, str, dict[str, Any]], ...] = (
    ("router", ROUTER_MAC, {}),
    ("nas", NAS_MAC, {
        "rtt_threshold_ms": 20,
        "checks": [
            {"kind": "smb", "port": 445},
            {"kind": "http", "port": NAS_HTTP_PORT},
            {"kind": "ssh", "port": 22},
        ],
    }),
    ("pc", PC_MAC, {}),
    ("iphone", PHONE_MAC, {}),
    ("telnet", TELNET_MAC, {"method": "ping", "offline_after_min": 2}),
)  # fmt: skip


def _inventory_devices(oui: Any) -> dict[str, Device]:
    """Die fünf Geräte so, wie ein Scan sie gefunden hätte (Hersteller aus der Herstellerliste)."""
    from netscan.net import ports as net_ports
    from netscan.net.oui import is_random_mac

    def port(number: int, banner: str | None = None) -> PortResult:
        spec = net_ports.describe_port(number)
        return PortResult(number, "tcp", spec.service, spec.risk, spec.reason, banner)

    def make(mac: str, ip: str, rtt: float, ttl: int, **fields: Any) -> Device:
        mac = normalize_mac(mac)
        return Device(
            mac=mac, ip=ip, vendor=oui.lookup(mac), mac_random=is_random_mac(mac), rtt_ms=rtt, ttl=ttl,
            discovered_by=["arp", "ping"], **fields,
        )  # fmt: skip

    return {
        "router": make(
            ROUTER_MAC, ROUTER_IP, _BASE_RTT["router"], 64,
            hostname="fritz.box", names=NameInfo(dns="fritz.box"), is_gateway=True, ports=[port(53), port(80)],
            ssdp=SsdpInfo(
                friendly_name="FRITZ!Box 7590 (Sim)", manufacturer="AVM Berlin", model_name="FRITZ!Box 7590",
                model_number="avm", device_type="urn:schemas-upnp-org:device:InternetGatewayDevice:1",
            ),
        ),  # fmt: skip
        "nas": make(
            NAS_MAC, NAS_IP, _BASE_RTT["nas"], 64,
            hostname="diskstation.local", names=NameInfo(mdns="diskstation.local", mdns_services=["_smb._tcp", "_http._tcp"]),
            ports=[port(22, "SSH-2.0-OpenSSH_8.2p1"), port(445), port(NAS_HTTP_PORT), port(5001)],
        ),  # fmt: skip
        "pc": make(PC_MAC, PC_IP, _BASE_RTT["pc"], 128, ports=[port(135), port(445), port(3389)]),
        "iphone": make(
            PHONE_MAC, PHONE_IP, _BASE_RTT["iphone"], 64,
            hostname="iPhone.local", names=NameInfo(mdns="iPhone.local", mdns_services=["_companion-link._tcp"]),
        ),  # fmt: skip
        "telnet": make(TELNET_MAC, TELNET_IP, _BASE_RTT["telnet"], 64, ports=[port(23, "BusyBox v1.31 login:")]),
    }


def seed_inventory(services: Services) -> dict[str, Device]:
    """Bringt Router, NAS, PC, iPhone und Telnet-Gerät ins Inventar (ein abgeschlossener Demo-Scan, ohne zu senden).

    Die übrigen Sim-Geräte (Drucker, Switch, Raspberry Pi, eigener PC) findet erst der Scan in der Oberfläche –
    dann erscheinen sie als neu und lösen „Neues Gerät“-Alerts aus. Gibt die gespeicherten Geräte je Schlüssel zurück.
    """
    from netscan.net import classify
    from netscan.net import ports as net_ports

    inv = services.inventory
    devices = _inventory_devices(services.oui)
    classify.apply_classification(list(devices.values()))
    scan_id = inv.begin_scan("scan", DEMO_ADAPTER.name, DEMO_ADAPTER.network)
    inv.add_log(scan_id, "info", f"Demo-Vorlauf: {len(devices)} Geräte aus einem früheren Scan übernommen (nichts gesendet).")
    for dev in devices.values():
        inv.record_seen(dev, scan_id)
        inv.set_ports(dev.mac, net_ports.COMMON_PORTS, dev.ports)  # alle gängigen Ports gelten als geprüft
    inv.finish_scan(scan_id, "completed", len(devices))
    stored: dict[str, Device] = {}
    for key, dev in devices.items():
        name, known = _DEVICE_NAMES[key]
        stored[key] = inv.update_user_fields(dev.mac, custom_name=name, known=known)
    return stored


def seed_monitoring(services: Services) -> dict[str, MonitorTarget]:
    """Legt die fünf Ziele samt Dienstprüfungen an (über den Monitor, wie die Oberfläche es tut)."""
    out: dict[str, MonitorTarget] = {}
    for key, mac, options in _TARGET_SPECS:
        target = services.monitor.add_target(mac, **options)
        # Der Router dieses Netzes ist bekannt; der Monitor müsste ihn sonst im ersten Durchlauf erst lernen.
        services.targets.set_network(target.id, ROUTER_MAC, DEMO_ADAPTER.network)
        stored = services.targets.get(mac)
        assert stored is not None
        out[key] = stored
    return out


# =====================================================================================
# Künstlicher Verlauf
# =====================================================================================


@dataclass(frozen=True)
class _Outage:
    """Ein Ausfall im Verlauf. Beginn und Dauer; hours_ago zählt vom Ende des Verlaufs zurück."""

    who: str  # router | nas | pc | iphone | telnet
    hours_ago: float
    minutes: float
    check: str | None = None  # None: das Gerät antwortet nicht; sonst fällt dieser Dienst (smb, http, ssh) aus
    slow: bool = False  # Gerät antwortet, aber sehr langsam (Alert „Antwortzeit hoch“)


# Ausfälle über zehn Tage verteilt: die letzten 7 Tage füllen die Messreihen, die älteren nur die Alert-Häufigkeit.
# Ausfälle ab der Alert-Schwelle (Gerät 5 Minuten, Telnet-Gerät 2, Dienst 2, Antwortzeit 5) enden in einem Alert.
_OUTAGES: tuple[_Outage, ...] = (
    _Outage("router", 250.0, 9), _Outage("router", 99.0, 7), _Outage("router", 31.0, 2),
    _Outage("nas", 61.0, 26),  # Neustart nach einem Update
    _Outage("nas", 71.0, 22, slow=True),  # Datensicherung läuft: Antworten dauern lange
    _Outage("pc", 140.0, 14), _Outage("pc", 36.5, 6),
    _Outage("iphone", 150.0, 4), _Outage("iphone", 121.0, 9), _Outage("iphone", 98.0, 6), _Outage("iphone", 74.5, 3),
    _Outage("iphone", 52.0, 12), _Outage("iphone", 26.0, 6), _Outage("iphone", 9.5, 4),
    _Outage("telnet", 420.0, 6), _Outage("telnet", 300.0, 6),
    _Outage("telnet", 160.0, 6), _Outage("telnet", 133.0, 6), _Outage("telnet", 109.0, 8), _Outage("telnet", 84.0, 6),
    _Outage("telnet", 60.0, 6), _Outage("telnet", 37.0, 10), _Outage("telnet", 13.0, 6),
    _Outage("nas", 330.0, 15, check="http"), _Outage("nas", 118.0, 22, check="http"),
    _Outage("nas", 29.0, 38, check="http"), _Outage("nas", 12.0, 6, check="http"),
    _Outage("nas", 88.0, 9, check="ssh"), _Outage("nas", 20.5, 4, check="smb"),
)  # fmt: skip

# Ereignis-Alerts (new_device, new_port): (Regel, Gerät, Port, Stunden zurück). Alle sind längst quittiert.
_EVENT_ALERTS: tuple[tuple[str, str, int | None, float], ...] = (
    ("new_port", "nas", 5001, 340.0),
    ("new_port", "pc", 3389, 118.0),
    ("new_device", "telnet", None, 167.5),
)


def _span(outage: _Outage, end: int) -> tuple[int, int]:
    start = end - round(outage.hours_ago * 3600)
    return start, start + round(outage.minutes * 60)


def _inside(spans: list[tuple[int, int]] | None, ts: int) -> bool:
    return any(s <= ts < e for s, e in spans or ())


def _draw_rtt(rng: random.Random, who: str, wave: float, slow: bool) -> float:
    """Eine plausible Antwortzeit: Grundwert mit Schwankung, selten ein Ausreißer; das Handy im WLAN streut stärker."""
    if slow:
        return round(rng.uniform(32.0, 68.0), 1)
    base = _BASE_RTT[who]
    if who == "iphone":
        value = base * rng.lognormvariate(0.0, 0.5)
    else:
        value = base * (0.85 + 0.3 * rng.random())
        if rng.random() < 0.015:
            value *= rng.uniform(2.5, 6.0)
    return round(min(max(value * wave, 0.2), 400.0), 1)


def _history_samples(
    targets: dict[str, MonitorTarget], end: int, rng: random.Random, step_s: int = HISTORY_STEP_S
) -> list[Sample]:
    """Messwerte von end − HISTORY_DAYS bis end im Takt step_s. Dienstwerte nur, solange das Gerät antwortet."""
    device_down: dict[str, list[tuple[int, int]]] = {}
    service_down: dict[tuple[str, str], list[tuple[int, int]]] = {}
    slow: dict[str, list[tuple[int, int]]] = {}
    for outage in _OUTAGES:
        span = _span(outage, end)
        if outage.slow:
            slow.setdefault(outage.who, []).append(span)
        elif outage.check:
            service_down.setdefault((outage.who, outage.check), []).append(span)
        else:
            device_down.setdefault(outage.who, []).append(span)
    gap_start = end - round(GAP_HOURS_AGO * 3600)
    gap_end = gap_start + GAP_MINUTES * 60

    samples: list[Sample] = []
    for ts in range(end - HISTORY_DAYS * 86400, end + 1, step_s):
        if gap_start <= ts < gap_end:
            continue  # Lücke: gar nichts gemessen (keine Ausfälle)
        wave = 1.0 + 0.12 * math.sin(2 * math.pi * ((ts % 86400) - 14 * 3600) / 86400)  # abends etwas langsamer
        for who, target in targets.items():
            if _inside(device_down.get(who), ts):
                samples.append(Sample(target.id, 0, ts, False, None))
                continue  # Dienste sind „unbekannt“, nicht ausgefallen: keine Dienstwerte
            samples.append(Sample(target.id, 0, ts, True, _draw_rtt(rng, who, wave, _inside(slow.get(who), ts))))
            for check in target.checks:
                if _inside(service_down.get((who, check.kind)), ts):
                    samples.append(Sample(target.id, check.id, ts, False, None))
                else:
                    value = _CHECK_RTT.get(check.kind, 5.0) * (0.85 + 0.3 * rng.random()) * wave
                    samples.append(Sample(target.id, check.id, ts, True, round(max(value, 0.2), 1)))
    return samples


def _replay_state_alerts(
    services: Services, targets: dict[str, MonitorTarget], devices: dict[str, Device | None], end: int
) -> int:
    """Spielt die Ausfälle durch die echte Alert-Regel (Texte und Schwere wie im Betrieb) und gibt die Zahl zurück."""
    engine, store = services.alert_engine, services.alerts
    settings = services.settings.load()
    before = len(store.list(state="all", limit=1000))
    for outage in sorted(_OUTAGES, key=lambda o: -o.hours_ago):  # ältester zuerst
        base = targets.get(outage.who)
        if base is None:
            continue
        device = devices.get(outage.who)
        start, stop = _span(outage, end)
        if outage.slow:
            minutes = settings.alert_rtt_minutes
            if outage.minutes < minutes:
                continue
            t = replace(base, checks=[], status="degraded", status_since=iso_from_ts(start),
                        rtt_high_since=iso_from_ts(start), last_rtt_ms=52.0)  # fmt: skip
            engine.evaluate_target(t, device, start + minutes * 60)
            t.status, t.rtt_high_since = "online", None
            engine.evaluate_target(t, device, stop)
        elif outage.check:
            minutes = settings.alert_service_minutes
            check = next((c for c in base.checks if c.kind == outage.check), None)
            if check is None or outage.minutes < minutes:
                continue
            t = replace(base, status="online", status_since=iso_from_ts(start))  # das Gerät selbst antwortet
            c = replace(check, status="down", status_since=iso_from_ts(start), down_since=iso_from_ts(start),
                        last_check=iso_from_ts(start), last_detail="Port geschlossen")  # fmt: skip
            engine.evaluate_check(t, c, device, start + minutes * 60)
            c.status, c.status_since, c.down_since = "up", iso_from_ts(stop), None
            engine.evaluate_check(t, c, device, stop)
        else:
            minutes = base.offline_after_min or settings.alert_offline_minutes
            if outage.minutes < minutes:
                continue
            t = replace(base, checks=[], status="offline", status_since=iso_from_ts(start),
                        down_since=iso_from_ts(start), last_detail="keine Antwort", last_rtt_ms=None)  # fmt: skip
            engine.evaluate_target(t, device, start + minutes * 60)
            t.status, t.status_since, t.down_since = "online", iso_from_ts(stop), None
            engine.evaluate_target(t, device, stop)
    return len(store.list(state="all", limit=1000)) - before


def _event_alerts(services: Services, targets: dict[str, MonitorTarget], devices: dict[str, Device | None], end: int) -> int:
    """Ereignis-Alerts aus der Vergangenheit (Texte wie in alerts.py). Zählt die neu angelegten."""
    from netscan.net import ports as net_ports

    created = 0
    for rule, who, port, hours_ago in _EVENT_ALERTS:
        target, device = targets.get(who), devices.get(who)
        if target is None or device is None:
            continue
        ts = end - round(hours_ago * 3600)
        name, label = device.display_name, f"{device.display_name} ({device.ip})"
        if rule == "new_device":
            vendor = f", Hersteller {device.vendor}" if device.vendor else ""
            alert = services.alerts.open(
                rule=rule, key=f"new_device:{device.mac}", severity="warning", title=f"Neues Gerät: {name}",
                message=(f"{label} ist zum ersten Mal aufgetaucht (Netz {DEMO_ADAPTER.network}). MAC {device.mac}{vendor}. "
                         "Gehört es dazu, im Inventar als „bekannt“ markieren."),
                mac=device.mac, now=ts,
            )  # fmt: skip
        else:
            assert port is not None
            spec = net_ports.describe_port(port)
            severity = {"low": "info", "medium": "warning"}.get(spec.risk, "critical")
            alert = services.alerts.open(
                rule=rule, key=f"new_port:{device.mac}:{port}", severity=severity, title=f"Neuer offener Port {port} auf {name}",
                message=(f"Auf {label} ist Port {port} ({spec.service}) jetzt offen; bei früheren Scans war er geschlossen. "
                         f"Risiko: {RISK_LABELS.get(spec.risk, spec.risk)}. {spec.reason}"),
                mac=device.mac, now=ts,
            )  # fmt: skip
        created += alert is not None
    return created


def _acknowledge_old(services: Services, end: int) -> None:
    """Alles quittieren, außer den beiden jüngsten Zustands-Alerts – die zeigen das Quittieren in der Oberfläche."""
    store = services.alerts
    alerts = store.list(state="all", limit=1000)  # neueste zuerst
    state_alerts = [a for a in alerts if a.rule in ("device_offline", "service_down", "rtt_high")]
    keep = {a.id for a in state_alerts[:2]}
    for alert in alerts:
        if alert.id in keep:
            continue
        done = ts_from_iso(alert.closed) or ts_from_iso(alert.opened) or end
        store.acknowledge(alert.id, now=min(done + 45 * 60, end))


def _history_alerts(services: Services, targets: dict[str, MonitorTarget], end: int) -> int:
    devices: dict[str, Device | None] = {who: services.inventory.get(t.mac) for who, t in targets.items()}
    created = _replay_state_alerts(services, targets, devices, end) + _event_alerts(services, targets, devices, end)
    _acknowledge_old(services, end)
    return created


def seed_history(services: Services, now: float | None = None, *, seed: int = HISTORY_SEED) -> dict[str, int]:
    """Künstlicher Verlauf der letzten HISTORY_DAYS Tage: Messwerte im 5-Minuten-Takt und alte, geschlossene Alerts.

    Setzt seed_inventory() und seed_monitoring() voraus; fehlende Ziele werden übergangen. Gibt die Zahl der Messwerte
    und der angelegten Alerts zurück: {"samples": n, "alerts": n}.
    """
    end = int(time.time() if now is None else now)
    end -= end % HISTORY_STEP_S
    targets: dict[str, MonitorTarget] = {}
    for who, mac in _KEY_MAC.items():
        target = services.targets.get(mac)
        if target is not None:
            targets[who] = target
    if not targets:
        return {"samples": 0, "alerts": 0}
    samples = _history_samples(targets, end, random.Random(seed))
    services.metrics.record(samples)
    alerts = _history_alerts(services, targets, end)
    return {"samples": len(samples), "alerts": alerts}


# =====================================================================================
# Wechselspiel im laufenden Prozess
# =====================================================================================


def _or(value: float | None, default: float) -> float:
    return default if value is None else value


@dataclass
class _Actor:
    """Ein Ausfall-Spieler: wechselt zwischen „läuft“ (up_s) und „ausgefallen“ (down_s)."""

    name: str
    up_s: float
    down_s: float
    go_down: Callable[[], None]
    go_up: Callable[[], None]
    down: bool = False
    next_at: float = 0.0


class Flapper:
    """Lässt das Telnet-Gerät und den HTTP-Dienst der NAS zeitweise ausfallen, damit Alerts entstehen.

    Das Telnet-Gerät verschwindet aus platform.alive (kein Ping mehr), den HTTP-Dienst hält lab.stop_service an
    (Verbindung abgelehnt). Ein Daemon-Thread führt die Wechsel aus; stop() beendet ihn und stellt alles wieder her.
    Die Zeiten kommen aus den Konstanten TELNET_UP_S usw. (zur Laufzeit gelesen) oder aus den Parametern.
    """

    def __init__(
        self,
        lab: Any,
        platform: Any,
        *,
        telnet_up_s: float | None = None,
        telnet_down_s: float | None = None,
        http_up_s: float | None = None,
        http_down_s: float | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._lab = lab
        self._platform = platform
        self._clock = clock
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._saved_ping: PingResult | None = platform.alive.get(TELNET_IP)
        durations = {
            "telnet": (_or(telnet_up_s, TELNET_UP_S), _or(telnet_down_s, TELNET_DOWN_S)),
            "nas-http": (_or(http_up_s, NAS_HTTP_UP_S), _or(http_down_s, NAS_HTTP_DOWN_S)),
        }
        for name, (up, down) in durations.items():
            if not (up > 0 and down > 0):
                raise ValueError(f"Wechselspiel {name}: die Zeiten müssen größer als 0 sein.")
        self._actors = [
            _Actor("telnet", *durations["telnet"], self._telnet_down, self._telnet_up),
            _Actor("nas-http", *durations["nas-http"], self._http_down, self._http_up),
        ]

    # --- Ausfälle --------------------------------------------------------------------------
    def _telnet_down(self) -> None:
        self._platform.alive.pop(TELNET_IP, None)

    def _telnet_up(self) -> None:
        self._platform.alive[TELNET_IP] = self._saved_ping or PingResult(alive=True, rtt_ms=_BASE_RTT["telnet"], ttl=64)

    def _http_down(self) -> None:
        self._lab.stop_service(NAS_IP, NAS_HTTP_PORT)

    def _http_up(self) -> None:
        self._lab.start_service(NAS_IP, NAS_HTTP_PORT)

    # --- Ablauf ----------------------------------------------------------------------------
    def begin(self, now: float) -> None:
        """Nullpunkt setzen: der erste Ausfall kommt nach der jeweiligen Laufzeit (up_s)."""
        with self._lock:
            for actor in self._actors:
                actor.down = False
                actor.next_at = now + actor.up_s

    def tick(self, now: float) -> float:
        """Führt fällige Wechsel aus und gibt die Sekunden bis zum nächsten Wechsel zurück (Uhr von außen: testbar)."""
        with self._lock:
            wait = math.inf
            for actor in self._actors:
                if now >= actor.next_at:
                    going_down = not actor.down
                    try:
                        (actor.go_down if going_down else actor.go_up)()
                    except Exception:  # noqa: BLE001 – das Wechselspiel darf die Demo nie stören
                        log.warning("Demo-Wechselspiel „%s“: Wechsel fehlgeschlagen", actor.name, exc_info=True)
                        # Zustand unverändert lassen und bald erneut versuchen (kein dauerhaft hängender Dienst)
                        actor.next_at = now + min(RETRY_S, actor.down_s if going_down else actor.up_s)
                    else:
                        actor.down = going_down
                        actor.next_at = now + (actor.down_s if going_down else actor.up_s)
                        log.debug("Demo-Wechselspiel „%s“: %s", actor.name, "fällt aus" if going_down else "läuft wieder")
                wait = min(wait, actor.next_at - now)
            return max(0.0, wait)

    def state(self) -> dict[str, bool]:
        """Welche Spieler sind gerade ausgefallen? {"telnet": …, "nas-http": …}"""
        with self._lock:
            return {actor.name: actor.down for actor in self._actors}

    @property
    def running(self) -> bool:
        thread = self._thread
        return thread is not None and thread.is_alive()

    def start(self) -> None:
        """Startet den Daemon-Thread (idempotent)."""
        with self._lock:
            if self.running:
                return
            self._stop_event.clear()
            self.begin(self._clock())
            thread = threading.Thread(target=self._run, name="demo-flapper", daemon=True)
            self._thread = thread
        thread.start()

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                delay = self.tick(self._clock())
            except Exception:  # noqa: BLE001
                log.exception("Demo-Wechselspiel: Fehler")
                delay = 5.0
            if self._stop_event.wait(max(delay, 0.01)):
                break

    def restore(self) -> None:
        """Alles wieder einschalten (Telnet-Gerät antwortet, HTTP-Dienst läuft)."""
        with self._lock:
            for actor in self._actors:
                if actor.down:
                    try:
                        actor.go_up()
                    except Exception:  # noqa: BLE001
                        log.warning("Demo-Wechselspiel „%s“: Wiederherstellen fehlgeschlagen", actor.name, exc_info=True)
                    actor.down = False

    def stop(self, timeout: float = 5.0) -> None:
        """Beendet den Thread und stellt den Normalzustand wieder her."""
        self._stop_event.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout)
        self._thread = None
        self.restore()


# =====================================================================================
# Aufbau
# =====================================================================================


def _demo_platform(lab: Any) -> Any:
    """FakePlatform für das Sim-Netz. Ping antwortet mit schwankender Zeit je Gerät (statt überall 1,0 ms)."""
    from netscan.platform.base import AdapterDetail, InterfaceAddr, WifiEntry, WifiStatus
    from tests.fakes import FakePlatform

    class DemoPlatform(FakePlatform):
        def ping(self, ip: str, timeout_ms: int) -> PingResult:
            result = self.alive.get(ip)  # kein Protokoll der Aufrufe: die Demo läuft lange
            if result is None or not result.alive:
                return PingResult(alive=False)
            rtt = round(max(0.2, _RTT_BY_IP.get(ip, 1.0) * (0.85 + 0.3 * random.random())), 1)
            return PingResult(alive=True, rtt_ms=rtt, ttl=result.ttl)

    platform = DemoPlatform(
        name="demo",
        ifaces=[InterfaceAddr(DEMO_ADAPTER.name, "127.0.0.1", "255.255.255.240", DEMO_ADAPTER.mac, True)],
        details={DEMO_ADAPTER.name: AdapterDetail(DEMO_ADAPTER.name, DEMO_ADAPTER.description, False, False, DEMO_ADAPTER.mac)},
        wifi=WifiStatus([WifiEntry("WLAN", True, "Heimnetz (Demo)")], readable=True),
        gateways={None: ROUTER_IP, DEMO_ADAPTER.name: ROUTER_IP, "WLAN": ROUTER_IP},
        neighbors={ROUTER_IP: ROUTER_MAC},
    )  # fmt: skip
    platform.alive = lab.ping_results()
    return platform


def _close_quietly(service: Any) -> None:
    try:
        service.close()
    except Exception:  # noqa: BLE001
        log.debug("Sim-Dienst ließ sich nicht schließen", exc_info=True)


def _close_lab(lab: Any) -> None:
    """Schließt das Sim-Netz. Jeder Dienst braucht beim Anhalten bis zu 0,1 s; parallel dauert das Beenden nicht Sekunden."""
    running = list(getattr(lab, "_services", None) or [])
    workers = [threading.Thread(target=_close_quietly, args=(service,), daemon=True) for service in running]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(3.0)
    lab.__exit__(None, None, None)  # räumt die Listen auf (ein zweites close() eines Dienstes ist harmlos)


class DemoRuntime:
    """Alles, was zur laufenden Demo gehört und wieder abgebaut werden muss: Sim-Netz, Antworter, Wechselspiel und
    die ersetzten Funktionen. close() ist wiederholbar und läuft auch beim Programmende (atexit)."""

    def __init__(self, lab: Any) -> None:
        self.lab = lab
        self.platform: Any = None
        self.responder: Any = None
        self.flapper: Flapper | None = None
        self.services: Services | None = None
        self._patches: list[tuple[Any, str, Any]] = []
        self._closed = False
        self._lock = threading.Lock()

    def patch(self, module: Any, name: str, value: Any) -> None:
        """Ersetzt module.name und merkt sich das Original für close()."""
        self._patches.append((module, name, getattr(module, name)))
        setattr(module, name, value)

    def close(self) -> None:
        global _ACTIVE
        with self._lock:
            if self._closed:
                return
            self._closed = True
        if self.flapper is not None:
            self.flapper.stop()  # stellt den HTTP-Dienst wieder her, bevor das Sim-Netz schließt
        for what, fn in (("Antworter", getattr(self.responder, "close", None)), ("Sim-Netz", lambda: _close_lab(self.lab))):
            if fn is None:
                continue
            try:
                fn()
            except Exception:  # noqa: BLE001
                log.warning("Demo: %s ließ sich nicht schließen", what, exc_info=True)
        for module, name, original in reversed(self._patches):
            setattr(module, name, original)
        self._patches.clear()
        try:
            atexit.unregister(self.close)
        except Exception:  # noqa: BLE001
            pass
        if _ACTIVE is self:
            _ACTIVE = None


_ACTIVE: DemoRuntime | None = None


def demo_runtime() -> DemoRuntime | None:
    """Die laufende Demo dieses Prozesses (Sim-Netz, Wechselspiel …) oder None."""
    return _ACTIVE


def shutdown_demo() -> None:
    """Baut die Demo dieses Prozesses ab: Wechselspiel anhalten, Sim-Netz schließen, ersetzte Funktionen zurücksetzen."""
    runtime = _ACTIVE
    if runtime is not None:
        runtime.close()


def build_demo_services() -> Services:
    """Services mit Demo-Plattform, eigenem Datenordner und laufendem Sim-Netz."""
    from netscan.net import adapters, arp, checks, names, oui, ports, ssdp
    from netscan.platform import autostart
    from tests.fakes import FakeArpSender
    from tests.sim import SimLab, UdpService, free_port

    global _ACTIVE
    shutdown_demo()  # eine frühere Demo desselben Prozesses zuerst abbauen (nie doppelt ersetzen)

    base = demo_data_dir()
    shutil.rmtree(base, ignore_errors=True)  # jedes Mal frisch
    base.mkdir(parents=True, exist_ok=True)

    lab = SimLab(_demo_devices()).__enter__()
    runtime = DemoRuntime(lab)
    atexit.register(runtime.close)
    _ACTIVE = runtime
    try:
        platform = _demo_platform(lab)
        runtime.platform = platform

        services = build_services(data_dir=base, platform=platform)  # type: ignore[arg-type]
        runtime.services = services
        services.settings.update(
            names_timeout_s=0.5, mdns_timeout_s=1.0, ssdp_timeout_s=1.0,
            monitor_interval_s=DEMO_MONITOR_INTERVAL_S, monitor_timeout_ms=DEMO_MONITOR_TIMEOUT_MS,
        )  # fmt: skip

        sender = FakeArpSender(lab.arp_answers())
        igd_url = lab.http_url(ROUTER_IP, 80, "/igd.xml")
        udp_port = free_port(ROUTER_IP, kind=socket.SOCK_DGRAM)
        runtime.responder = UdpService(
            ROUTER_IP,
            udp_port,
            lambda data, addr: (
                f"HTTP/1.1 200 OK\r\nLOCATION: {igd_url}\r\nSERVER: Demo/1.0 UPnP/1.0\r\nST: upnp:rootdevice\r\n"
                f"USN: uuid:demo::upnp:rootdevice\r\n\r\n"
            ).encode()
            if data.startswith(b"M-SEARCH")
            else None,
        )

        real_arp_scan, real_resolve, real_ssdp = arp.arp_scan, names.resolve_names, ssdp.ssdp_discover
        real_probe, real_connect = ports.probe_port, checks.connect
        runtime.patch(adapters, "list_adapters", lambda platform, include_virtual=False: [DEMO_ADAPTER])
        runtime.patch(adapters, "find_adapter", lambda platform, name: DEMO_ADAPTER if name == DEMO_ADAPTER.name else None)
        runtime.patch(arp, "scapy_status", lambda **kw: (True, "Demo-Modus (simuliert)"))
        runtime.patch(
            arp, "arp_scan",
            lambda ctx, adapter, hosts, sender_=None, **kw: real_arp_scan(ctx, adapter, hosts, sender=sender),
        )  # fmt: skip
        runtime.patch(
            names, "resolve_names",
            lambda ctx, ips, adapter, **kw: real_resolve(
                ctx,
                ips,
                adapter,
                resolver={ROUTER_IP: "fritz.box", "127.0.0.9": "raspberrypi.fritz.box"}.get,
                netbios_port=free_port("127.0.0.1", kind=socket.SOCK_DGRAM),
                mdns_browser=lambda a, t: {
                    "127.0.0.3": ("diskstation.local", ["_smb._tcp", "_http._tcp"]),
                    "127.0.0.4": ("brother-hl.local", ["_ipp._tcp", "_printer._tcp"]),
                    "127.0.0.10": ("iPhone.local", ["_companion-link._tcp"]),
                },
            ),
        )  # fmt: skip
        runtime.patch(
            ssdp, "ssdp_discover",
            lambda ctx, adapter, **kw: real_ssdp(ctx, adapter, target=(ROUTER_IP, udp_port), allowed_ips=kw.get("allowed_ips")),
        )  # fmt: skip
        runtime.patch(ports, "probe_port", lab.translating_probe(real_probe))
        # Stufe 2: Die Dienstprüfungen des Monitors gehen ebenfalls nur an die Sim-Ports (echter Port → Sim-Port).
        runtime.patch(checks, "connect", lab.translating_connect(real_connect))
        # „Herstellerliste aktualisieren“ ginge sonst per HTTPS an ieee.org – die Demo sendet nichts ins echte Netz.
        runtime.patch(oui, "update_from_ieee", demo_oui_update)
        runtime.patch(oui, "_default_fetch", _demo_fetch)
        # Autostart würde eine echte Aufgabe in der Windows-Aufgabenplanung anlegen – in der Demo nie.
        runtime.patch(autostart, "autostart_status", demo_autostart_status)
        runtime.patch(autostart, "set_autostart", demo_set_autostart)

        seed_inventory(services)
        seed_monitoring(services)
        try:
            counts = seed_history(services)
            log.info("Demo-Verlauf: %d Messwerte, %d Alerts (%d Tage).", counts["samples"], counts["alerts"], HISTORY_DAYS)
        except Exception:  # noqa: BLE001 – ohne Verlauf bleibt die Demo brauchbar
            log.warning("Demo-Verlauf konnte nicht angelegt werden", exc_info=True)
        try:
            services.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")  # Journal klein halten
        except Exception:  # noqa: BLE001
            log.debug("Journal nicht zurückgeschrieben", exc_info=True)

        runtime.flapper = Flapper(lab, platform)
        runtime.flapper.start()
    except BaseException:
        if runtime.services is not None:
            try:
                runtime.services.close()  # Datenbank freigeben
            except Exception:  # noqa: BLE001
                log.debug("Services ließen sich nicht schließen", exc_info=True)
        runtime.close()
        raise

    log.info("Demo-Netz läuft: %d simulierte Geräte auf 127.0.0.0/28, Daten in %s", len(lab.devices), base)
    return services


DEMO_AUTOSTART_DETAIL = "Im Demo-Modus nicht verfügbar – der Autostart lässt sich nur im normalen Betrieb einrichten."


def demo_autostart_status(**_kw: Any) -> Any:
    """Ersatz für autostart.autostart_status in der Demo: nicht unterstützt, ändert nichts am System."""
    from netscan.platform.autostart import AutostartStatus

    return AutostartStatus(supported=False, enabled=False, detail=DEMO_AUTOSTART_DETAIL)


def demo_set_autostart(enabled: bool, **_kw: Any) -> Any:
    """Ersatz für autostart.set_autostart in der Demo: legt nie eine echte Aufgabe an."""
    from netscan.platform.autostart import AutostartError

    raise AutostartError(DEMO_AUTOSTART_DETAIL)


def demo_data_dir() -> Path:
    return config.app_home() / "demo-data"
