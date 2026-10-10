"""Scan-Ablauf: Gerätesuche → Enricher → Speichern. Siehe BAUPLAN §9.

Erweiterung in späteren Stufen: neue Enricher an ENRICHERS anhängen, bestehende nicht umbauen.
Alle Aufrufe in die Module laufen über den Modulnamen (adapters.find_adapter …), damit Tests und
der Demo-Modus sie ersetzen können.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any, Protocol

from netscan import config
from netscan.core.context import GuardBlocked, ScanCancelled, ScanContext
from netscan.core.models import (
    Adapter,
    Device,
    GuardResult,
    NameInfo,
    PingResult,
    PortResult,
    ScanOutcome,
    ScanRequest,
    normalize_mac,
)
from netscan.net import adapters, arp, classify, names, oui, ping, ports, ssdp

if TYPE_CHECKING:
    from netscan.core.services import Services

log = logging.getLogger(__name__)

_BAD_MACS = {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}


@dataclass
class ScanJob:
    """Alles, was die Enricher über den laufenden Scan wissen müssen."""

    request: ScanRequest
    adapter: Adapter
    services: Services
    scan_id: int
    deep: bool = False
    previous: dict[str, Device] = field(default_factory=dict)  # gespeicherter Stand je MAC
    scanned_ports: dict[str, list[int]] = field(default_factory=dict)  # MAC -> geprüfte Ports
    gateway_ip: str | None = None  # Router laut Wächter beim Start (für die Prüfung auf Netzwechsel)
    gateway_mac: str | None = None


class Enricher(Protocol):
    name: str  # z. B. "names"
    label: str  # Fortschrittstext, z. B. "Namen"

    def run(self, ctx: ScanContext, job: ScanJob, devices: list[Device]) -> None:
        ...


class OuiEnricher:
    name = "oui"
    label = "Hersteller"
    sends_packets = False  # nur die Herstellerliste auf der Platte

    def run(self, ctx: ScanContext, job: ScanJob, devices: list[Device]) -> None:
        for d in devices:
            d.mac_random = oui.is_random_mac(d.mac)
            d.vendor = None if d.mac_random else job.services.oui.lookup(d.mac)


def _no_mdns(_adapter: Adapter, _timeout_s: float) -> dict[str, tuple[str | None, list[str]]]:
    """mDNS-Browser für den Modus „nur eingetragene Geräte“: keine Multicast-Suche ins ganze Segment."""
    return {}


class NamesEnricher:
    name = "names"
    label = "Namen"

    def run(self, ctx: ScanContext, job: ScanJob, devices: list[Device]) -> None:
        if not devices:
            return
        registered = job.request.mode == "registered"
        kwargs: dict[str, Any] = {}
        if registered:
            # Die mDNS-Suche fordert jedes Gerät im Segment zur Antwort auf – das wäre ein Absuchen des Netzes.
            kwargs["mdns_browser"] = _no_mdns
            ctx.log("Modus „nur eingetragene Geräte“: keine mDNS-Suche (Multicast), gespeicherte mDNS-Namen bleiben.")
        infos = names.resolve_names(ctx, [d.ip for d in devices], job.adapter, **kwargs)
        for d in devices:
            info = infos.get(d.ip) or NameInfo()
            prev = job.previous.get(d.mac)
            if registered and prev is not None and not info.mdns and not info.mdns_services:
                info.mdns, info.mdns_services = prev.names.mdns, list(prev.names.mdns_services)
            d.names = info
            d.hostname = d.names.best()


class SsdpEnricher:
    name = "ssdp"
    label = "SSDP/UPnP"

    def run(self, ctx: ScanContext, job: ScanJob, devices: list[Device]) -> None:
        if job.request.mode == "registered":
            # M-SEARCH an 239.255.255.250 fordert jedes UPnP-Gerät im Segment zur Antwort auf – hier nicht.
            ctx.log("Modus „nur eingetragene Geräte“: keine SSDP-Suche (Multicast), gespeicherte UPnP-Angaben bleiben.")
            for d in devices:
                prev = job.previous.get(d.mac)
                d.ssdp = prev.ssdp if prev is not None else None
            return
        found = ssdp.ssdp_discover(ctx, job.adapter, allowed_ips={d.ip for d in devices})
        for d in devices:
            d.ssdp = found.get(d.ip)


class PortsEnricher:
    name = "ports"
    label = "Ports"

    def run(self, ctx: ScanContext, job: ScanJob, devices: list[Device]) -> None:
        if not (job.request.port_scan or job.deep):
            ctx.log("Port-Scan ausgeschaltet – gespeicherte Ports bleiben unverändert.")
            return
        excluded_cats = set(ctx.settings.port_scan_excluded_categories)
        port_list = deep_port_list() if job.deep else list(ports.COMMON_PORTS)
        targets: dict[str, list[int]] = {}
        by_ip: dict[str, Device] = {}
        skipped = 0
        for d in devices:
            if d.port_scan_excluded or (excluded_cats and _port_scan_categories(job, d) & excluded_cats):
                skipped += 1
                continue
            targets[d.ip] = port_list
            by_ip[d.ip] = d
        if skipped:
            ctx.log(f"{skipped} Gerät(e) vom Port-Scan ausgenommen.")
        if not targets:
            return
        try:
            results = ports.scan_ports(ctx, targets, source_ip=job.adapter.ipv4)
        except ports.SourceAddressGone as exc:
            raise NetworkChanged(
                f"Die Adresse {job.adapter.ipv4} von „{job.adapter.name}“ ist während des Port-Scans verschwunden – "
                "vermutlich ein Netzwechsel. Scan abgebrochen, nichts gespeichert."
            ) from exc
        for ip, d in by_ip.items():
            d.ports = results.get(ip, [])
            job.scanned_ports[d.mac] = port_list
        open_total = sum(len(v) for v in results.values())
        ctx.log(f"Port-Scan: {len(targets)} Gerät(e), {open_total} offene Port(s).")


class ClassifyEnricher:
    name = "classify"
    label = "Einordnung"
    sends_packets = False  # wertet nur Gesammeltes aus

    def run(self, ctx: ScanContext, job: ScanJob, devices: list[Device]) -> None:
        views: list[Device] = []
        for d in devices:
            prev = job.previous.get(d.mac)
            if not d.ports and prev is not None and d.mac not in job.scanned_ports:
                d.ports = list(prev.ports)  # ohne Port-Scan: gespeicherte Ports für die Einordnung nutzen
            # Eingeordnet wird nach dem Bestand, den set_ports danach speichert: frisch gefundene Ports plus
            # gespeicherte, die dieser Scan gar nicht geprüft hat (z. B. Port 88 aus einem Tiefenscan).
            views.append(replace(d, ports=_ports_after_save(job, d)))
        classify.apply_classification(views)
        for d, view in zip(devices, views):
            d.category, d.category_reason = view.category, view.category_reason


ENRICHERS: list[Enricher] = [OuiEnricher(), NamesEnricher(), SsdpEnricher(), PortsEnricher(), ClassifyEnricher()]


def deep_port_list() -> list[int]:
    return sorted(set(ports.DEEP_PORTS) | set(ports.COMMON_PORTS))


def _port_scan_categories(job: ScanJob, d: Device) -> set[str]:
    """Gerätearten, nach denen ein Gerät vom Port-Scan ausgenommen sein kann (Pflichtenheft Grundsatz 4).

    Vom Nutzer festgelegt ⇒ nur diese. Sonst die gespeicherte automatische Art UND eine vorläufige Einordnung
    aus Hersteller, Namen, UPnP und gespeicherten Ports – die liegen vor dem Port-Scan schon vor. So bleibt
    auch ein neuer Drucker beim ersten Kontakt verschont.
    """
    if d.category_source == "user":
        return {d.category}
    prev = job.previous.get(d.mac)
    found: set[str] = set()
    if prev is not None and prev.category_source == "auto":
        found.add(prev.category)
    try:
        category, _reason = classify.classify(replace(d, ports=list(prev.ports) if prev is not None else []))
        found.add(category)
    except Exception:  # noqa: BLE001 – Einordnung darf den Scan nie stoppen
        log.warning("Vorläufige Einordnung für %s fehlgeschlagen", d.mac, exc_info=True)
    return found


def _ports_after_save(job: ScanJob, d: Device) -> list[PortResult]:
    """Offene Ports nach dem Speichern: geprüfte laut Scan, ungeprüfte aus dem gespeicherten Stand."""
    scanned = job.scanned_ports.get(d.mac)
    prev = job.previous.get(d.mac)
    if scanned is None or prev is None:
        return list(d.ports)
    checked = set(scanned)
    fresh = {(p.port, p.proto) for p in d.ports}
    kept = [p for p in prev.ports if (p.proto != "tcp" or p.port not in checked) and (p.port, p.proto) not in fresh]
    return sorted([*d.ports, *kept], key=lambda p: (p.proto, p.port))


# --- Ablauf ---------------------------------------------------------------------


class NetworkChanged(RuntimeError):
    """Das Netz des Adapters hat sich während des Auftrags geändert – weiterzumachen hieße, in ein anderes Netz
    zu senden. Der Auftrag endet als „fehlgeschlagen“, gespeichert wird nichts."""


def _check_guard(ctx: ScanContext, services: Services, adapter: Adapter, confirmed: bool | None) -> GuardResult:
    """Zweite Prüfung im Auftrag selbst. confirmed=None: Bestätigung nicht prüfen (Tiefenscan)."""
    guard = services.guard.check(adapter)
    ctx.emit("guard.result", {"guard": guard.to_dict()})
    if guard.decision == "block":
        raise GuardBlocked(guard)
    if guard.decision == "confirm" and confirmed is False:
        raise GuardBlocked(replace(guard, reason=f"Bestätigung fehlt: {guard.reason}"))
    return guard


def _ensure_same_network(ctx: ScanContext, job: ScanJob, before: str, *, full: bool = True) -> None:
    """Vor einem Schritt, der Pakete sendet: ist es noch dasselbe Netz?

    Der Wächter prüft beim Start (BAUPLAN §10). Wechselt Windows während des Scans das WLAN – etwa in den
    gespeicherten Schul-Hotspot –, gingen die restlichen Phasen sonst über die neue Verbindung hinaus.
    Immer geprüft wird Adresse und Netz des Adapters (psutil, schnell). Mit full zusätzlich der Wächter
    (gesperrt ⇒ GuardBlocked) sowie Router-Adresse und Router-MAC gegenüber dem Start (Abweichung ⇒
    NetworkChanged). Der Wächter kostet unter Windows rund eine Sekunde, deshalb nur vor den langen Phasen
    Ping und Ports; NetBIOS, SSDP und die Port-Prüfung binden ihre Sockets ohnehin an die Adapter-Adresse.
    """
    ctx.check_cancel()
    services, adapter = job.services, job.adapter
    current = adapters.find_adapter(services.platform, adapter.name)
    if current is None or current.ipv4 != adapter.ipv4 or current.network != adapter.network:
        now = f"{current.ipv4} ({current.network})" if current is not None else "keine Adresse mehr"
        raise NetworkChanged(
            f"Netzwechsel vor „{before}“: „{adapter.name}“ hatte {adapter.ipv4} ({adapter.network}), jetzt {now}. "
            "Scan abgebrochen, nichts gespeichert."
        )
    if not full:
        return
    guard = services.guard.check(adapter)
    if guard.decision == "block":
        ctx.emit("guard.result", {"guard": guard.to_dict()})
        raise GuardBlocked(guard)
    for what, old, new in (
        ("Router-Adresse", job.gateway_ip, guard.gateway_ip),
        ("Router-MAC", job.gateway_mac, guard.gateway_mac),
    ):
        if old and new and old != new:
            raise NetworkChanged(
                f"Netzwechsel vor „{before}“: {what} war {old}, jetzt {new}. Scan abgebrochen, nichts gespeichert."
            )


# Kurze Schritte, die ihre Sockets an die Adapter-Adresse binden (NetBIOS, SSDP, mDNS) bzw. nur die
# Rückwärtsauflösung fragen: vor ihnen reicht die schnelle Adressprüfung. Vor allem anderen fragt der Wächter.
_BOUND_ENRICHERS = frozenset({"names", "ssdp"})


def _sends_packets(enricher: Enricher, job: ScanJob) -> bool:
    """Schickt dieser Schritt Pakete ins Netz? Unbekannte (spätere) Enricher gelten vorsichtshalber als sendend."""
    if enricher.name == "ports":
        return bool(job.request.port_scan or job.deep)
    return bool(getattr(enricher, "sends_packets", True))


def _neighbor_mac(platform: Any, ip: str, interface: str | None) -> str | None:
    """ARP-Cache des Systems, wenn möglich nur für den Adapter (Plattformen ohne Parameter wie bisher)."""
    try:
        return platform.neighbor_mac(ip, interface)
    except TypeError:
        return platform.neighbor_mac(ip)


def _discover(ctx: ScanContext, job: ScanJob) -> list[Device]:
    services, adapter, request = job.services, job.adapter, job.request
    macs: dict[str, str] = {}
    via: dict[str, list[str]] = {}
    registered_macs: set[str] | None = None  # nur im Modus „nur eingetragene Geräte“

    if request.mode == "full":
        targets = adapters.hosts_of(adapter)
        ctx.log(f"Suche im Netz {adapter.network} ({len(targets)} Adressen).")
    else:
        known = services.inventory.registered_devices()
        registered_macs = {d.mac for d in known}
        targets = sorted({d.ip for d in known if _in_network(d.ip, adapter.network) and d.ip != adapter.ipv4})
        ctx.log(f"Modus „nur eingetragene Geräte“: {len(targets)} Adresse(n), das Netz wird nicht abgesucht.")

    available, reason = arp.scapy_status()
    if available and targets:
        try:
            for ip, mac in arp.arp_scan(ctx, adapter, targets).items():
                macs[ip] = mac
                via.setdefault(ip, []).append("arp")
        except arp.ArpUnavailable as exc:
            ctx.log(f"ARP-Scan nicht möglich: {exc} Weiter mit Ping und ARP-Cache.", "warning")
    elif targets:
        ctx.log(f"ARP-Scan nicht verfügbar ({reason}). Weiter mit Ping und ARP-Cache.", "warning")

    pings: dict[str, PingResult] = {}
    if targets:
        _ensure_same_network(ctx, job, "Ping")
        pings = ping.ping_sweep(ctx, targets)
    for ip in pings:
        via.setdefault(ip, []).append("ping")

    arp_found = len(macs)
    neighbors = services.platform.neighbor_table()
    # Beim Ping-Durchlauf fragt das Betriebssystem selbst per ARP nach jeder Adresse. Geräte, die ARP beantworten,
    # aber Ping verwerfen (z. B. iPhone, iPad, Mac im Ruhezustand), stehen danach im ARP-Cache – also alle Ziele
    # übernehmen, nicht nur die Ping-Antworten. Gelesen wird nur der Cache, es wird nichts zusätzlich gesendet.
    target_set = set(targets)
    cache_only = 0
    for ip in sorted(neighbors, key=_ip_key):
        if ip in macs or ip not in target_set:
            continue
        macs[ip] = neighbors[ip]
        entry = via.setdefault(ip, [])
        entry.append("cache")
        if "ping" not in entry:
            cache_only += 1
    if cache_only:
        ctx.log(f"{cache_only} Gerät(e) nur über den ARP-Cache gefunden (antworten nicht auf Ping, z. B. Handys im Ruhezustand).")
    if available and targets and arp_found == 0 and len(macs) >= 2:
        ctx.log(
            "Der ARP-Scan bekam keine einzige Antwort, Ping und ARP-Cache fanden aber Geräte. Vermutlich nimmt der "
            "Netzwerktreiber die Antworten nicht an. Ergebnis stammt aus Ping und ARP-Cache.",
            "warning",
        )

    gateway_ip = services.platform.default_gateway(adapter.name)
    if gateway_ip and gateway_ip not in macs and gateway_ip in neighbors and _in_network(gateway_ip, adapter.network):
        macs[gateway_ip] = neighbors[gateway_ip]  # aus dem ARP-Cache, ohne zu senden
        via.setdefault(gateway_ip, []).append("cache")

    devices: dict[str, Device] = {}
    foreign: list[str] = []
    for ip in sorted(macs, key=_ip_key):
        try:
            mac = normalize_mac(macs[ip])
        except ValueError:
            continue
        if mac in _BAD_MACS or int(mac[:2], 16) & 0x01:  # Null-, Broadcast-, Multicast-MAC
            continue
        if registered_macs is not None and mac not in registered_macs:
            # Modus „nur eingetragene Geräte“: ein anderes Gerät an einer eingetragenen IP oder ein fremder Router
            # wird weder gespeichert noch weiter geprüft (keine Namen, kein UPnP, kein Port-Scan).
            foreign.append(f"{ip} ({mac})")
            continue
        if mac in devices:
            ctx.log(f"MAC {mac} antwortet für mehrere Adressen ({devices[mac].ip}, {ip}) – z. B. Repeater. "
                    f"Gespeichert wird {devices[mac].ip}.", "warning")
            continue
        p = pings.get(ip)
        devices[mac] = Device(
            mac=mac,
            ip=ip,
            rtt_ms=p.rtt_ms if p else None,
            ttl=p.ttl if p else None,
            discovered_by=via.get(ip, []),
            is_gateway=(ip == gateway_ip),
        )
    if foreign:
        ctx.log(
            f"Modus „nur eingetragene Geräte“: {len(foreign)} nicht eingetragene(s) Gerät(e) übergangen, "
            f"nicht gespeichert und nicht weiter geprüft: {', '.join(foreign)}.",
            "warning",
        )

    if adapter.mac:
        own = normalize_mac(adapter.mac)
        if own not in devices:
            devices[own] = Device(mac=own, ip=adapter.ipv4, is_self=True, discovered_by=["self"])
        else:
            devices[own].is_self = True

    ctx.log(f"{len(devices)} Gerät(e) gefunden.")
    return list(devices.values())


def run_scan(ctx: ScanContext, request: ScanRequest, services: Services) -> dict[str, Any]:
    """Kompletter Scan. Summary: {devices, new, duration_s, network, scan_id}."""
    t0 = time.monotonic()
    adapter = adapters.find_adapter(services.platform, request.adapter)
    if adapter is None:
        raise ValueError(f"Adapter „{request.adapter}“ nicht gefunden.")
    if adapter.prefix < config.PREFIX_MIN:
        raise ValueError(f"Netz zu groß (/{adapter.prefix}). Erlaubt ist höchstens /{config.PREFIX_MIN}.")
    guard = _check_guard(ctx, services, adapter, confirmed=request.confirm_foreign)
    if adapter.prefix < config.PREFIX_WARN:
        ctx.log(f"Großes Netz (/{adapter.prefix}) – der Scan dauert länger.", "warning")

    inventory = services.inventory
    scan_id = inventory.begin_scan("scan", adapter.name, adapter.network)
    ctx.scan_id = scan_id
    job = ScanJob(
        request=request, adapter=adapter, services=services, scan_id=scan_id,
        gateway_ip=guard.gateway_ip, gateway_mac=guard.gateway_mac,
    )  # fmt: skip
    mode_text = "Netz absuchen" if request.mode == "full" else "nur eingetragene Geräte"
    ctx.log(f"Scan gestartet über „{adapter.name}“ ({adapter.ipv4}, {adapter.network}), Modus: {mode_text}.")
    result = "failed"
    count = 0
    finished = False
    try:
        devices = _discover(ctx, job)
        for d in devices:
            prev = inventory.get(d.mac)
            if prev is not None:
                job.previous[d.mac] = prev
            inventory.merge_user_fields(d)

        for i, enricher in enumerate(ENRICHERS):
            ctx.check_cancel()
            ctx.progress(enricher.label, i, len(ENRICHERS))
            if devices and _sends_packets(enricher, job):
                _ensure_same_network(ctx, job, enricher.label, full=enricher.name not in _BOUND_ENRICHERS)
            enricher.run(ctx, job, devices)

        ctx.check_cancel()
        new_ports: dict[str, list[PortResult]] = {}
        for i, d in enumerate(devices, 1):
            # Vor dem Speichern: welche Ports waren für dieses Gerät schon einmal geprüft? (Stufe 2, BAUPLAN §26)
            checked_before = inventory.checked_ports(d.mac) if d.mac in job.previous else set()
            inventory.record_seen(d, scan_id)
            if d.mac in job.scanned_ports:
                opened = inventory.set_ports(d.mac, job.scanned_ports[d.mac], d.ports)
                reopened = [p for p in opened if p.proto == "tcp" and p.port in checked_before]
                if reopened:
                    new_ports[d.mac] = reopened
            ctx.progress("Speichern", i, len(devices))
        count = len(devices)
        result = "completed"
        inventory.finish_scan(scan_id, result, count)
        finished = True
        # device.updated erst nach dem Abschluss: online und is_new gelten dann gegen diesen Scan (BAUPLAN §5).
        new_devices: list[Device] = []
        for d in devices:
            stored = inventory.get(d.mac)
            if stored is None:
                continue
            if stored.first_seen_scan == scan_id and not stored.known:
                new_devices.append(stored)
            ctx.emit("device.updated", {"device": stored.to_dict()})
        new_count = len(new_devices)
        duration = round(time.monotonic() - t0, 1)
        ctx.log(f"Scan fertig: {count} Gerät(e), davon {new_count} neu, {duration} s.")
        if new_ports:
            by_mac = {d.mac: d for d in devices}
            listed = "; ".join(
                f"{by_mac[m].display_name if m in by_mac else m}: {', '.join(str(p.port) for p in ps)}"
                for m, ps in new_ports.items()
            )
            ctx.log(f"Neu geöffnete Ports (vorher geprüft und geschlossen): {listed}.", "warning")
        services.notify_scan(
            ScanOutcome(
                scan_id=scan_id, kind="scan", adapter=adapter, gateway_mac=guard.gateway_mac,
                seen_macs=[d.mac for d in devices], new_devices=new_devices, new_ports=new_ports,
            )
        )  # fmt: skip
        return {"devices": count, "new": new_count, "duration_s": duration, "network": adapter.network, "scan_id": scan_id}
    except ScanCancelled:
        result = "cancelled"
        raise
    except GuardBlocked:
        result = "blocked"
        raise
    finally:
        if not finished:
            inventory.finish_scan(scan_id, result, count)
        ctx.emit("devices.changed", {})


def _verify_identity(ctx: ScanContext, services: Services, adapter: Adapter, device: Device) -> None:
    """Gehört die gespeicherte IP noch zu diesem Gerät? Sonst kein Tiefenscan (ValueError).

    Ohne diese Prüfung bekäme ein anderes Gerät mit der neu vergebenen Adresse – etwa ein vom Port-Scan
    ausgenommener Drucker – über tausend Verbindungsversuche, und seine Ports landeten unter der falschen MAC.
    Gefragt wird nur diese eine IP: per ARP (Scapy) oder per Ping und ARP-Cache des Systems.
    """
    if device.is_self and device.ip == adapter.ipv4:
        return
    seen: str | None = None
    available, _reason = arp.scapy_status()
    if available:
        try:
            seen = arp.arp_scan(ctx, adapter, [device.ip]).get(device.ip)
        except arp.ArpUnavailable as exc:
            ctx.log(f"ARP-Prüfung nicht möglich: {exc} Weiter mit Ping und ARP-Cache.", "warning")
    if seen is None:
        ctx.check_cancel()
        services.platform.ping(device.ip, ctx.settings.ping_timeout_ms)  # füllt den ARP-Cache des Systems
        seen = _neighbor_mac(services.platform, device.ip, adapter.name)
    ctx.check_cancel()
    if seen is None:
        raise ValueError(
            f"{device.display_name} ({device.ip}) antwortet nicht – Tiefenscan nicht gestartet. "
            "Bitte zuerst neu scannen."
        )
    try:
        seen_mac = normalize_mac(seen)
    except ValueError as exc:
        raise ValueError(f"Unter {device.ip} meldet sich keine gültige MAC-Adresse – Tiefenscan nicht gestartet.") from exc
    if seen_mac != device.mac:
        raise ValueError(
            f"Unter {device.ip} antwortet ein anderes Gerät ({seen_mac}) als {device.display_name} ({device.mac}) – "
            "Tiefenscan nicht gestartet, damit kein fremdes Gerät gescannt und nichts falsch gespeichert wird. "
            "Bitte zuerst neu scannen."
        )
    ctx.log(f"Geprüft: {device.ip} gehört weiterhin zu {device.mac}.")


def run_deep_scan(ctx: ScanContext, mac: str, services: Services, adapter_name: str | None = None) -> dict[str, Any]:
    """Tiefenscan Ports 1–1024 eines Geräts. Summary: {mac, open_ports, new_ports, duration_s}."""
    t0 = time.monotonic()
    device = services.inventory.get(mac)
    if device is None:
        raise LookupError(f"Gerät {mac} unbekannt.")
    adapter = _adapter_for(services, device, adapter_name)
    if adapter is None:
        raise ValueError(f"Kein Adapter im Netz von {device.ip} gefunden.")
    _check_guard(ctx, services, adapter, confirmed=None)

    inventory = services.inventory
    scan_id = inventory.begin_scan("deep_scan", adapter.name, device.ip)
    ctx.scan_id = scan_id
    result = "failed"
    port_list = deep_port_list()
    ctx.log(f"Tiefenscan {device.display_name} ({device.ip}): {len(port_list)} Ports.")
    try:
        _verify_identity(ctx, services, adapter, device)
        try:
            found = ports.scan_ports(ctx, {device.ip: port_list}, source_ip=adapter.ipv4).get(device.ip, [])
        except ports.SourceAddressGone as exc:
            raise NetworkChanged(
                f"Die Adresse {adapter.ipv4} von „{adapter.name}“ ist während des Tiefenscans verschwunden – "
                "vermutlich ein Netzwechsel. Tiefenscan abgebrochen, nichts gespeichert."
            ) from exc
        checked_before = inventory.checked_ports(device.mac)
        new_ports = inventory.set_ports(device.mac, port_list, found)
        current = inventory.get(device.mac)
        assert current is not None
        if current.category_source == "auto":
            category, reason = classify.classify(current)
            inventory.set_auto_category(current.mac, category, reason)
            current = inventory.get(device.mac) or current
        ctx.emit("device.updated", {"device": current.to_dict()})
        result = "completed"
        duration = round(time.monotonic() - t0, 1)
        if new_ports:
            ctx.log(f"Neu offen: {', '.join(f'{p.port}/{p.service}' for p in new_ports)}.", "warning")
        ctx.log(f"Tiefenscan fertig: {len(found)} offene Port(s), {duration} s.")
        reopened = [p for p in new_ports if p.proto == "tcp" and p.port in checked_before]
        services.notify_scan(
            ScanOutcome(
                scan_id=scan_id, kind="deep_scan", adapter=adapter, gateway_mac=None, seen_macs=[device.mac],
                new_devices=[], new_ports={device.mac: reopened} if reopened else {},
            )
        )  # fmt: skip
        return {
            "mac": device.mac,
            "open_ports": [p.port for p in found],
            "new_ports": [p.port for p in new_ports],
            "duration_s": duration,
        }
    except ScanCancelled:
        result = "cancelled"
        raise
    except GuardBlocked:
        result = "blocked"
        raise
    finally:
        inventory.finish_scan(scan_id, result, 1 if result == "completed" else 0)
        ctx.emit("devices.changed", {})


# --- Hilfen ---------------------------------------------------------------------


def _adapter_for(services: Services, device: Device, adapter_name: str | None) -> Adapter | None:
    for name in (adapter_name, services.settings.load().last_adapter):
        if name:
            a = adapters.find_adapter(services.platform, name)
            if a is not None and _in_network(device.ip, a.network):
                return a
    for a in adapters.list_adapters(services.platform, include_virtual=True):
        if _in_network(device.ip, a.network):
            return a
    return None


def _in_network(ip: str, network: str) -> bool:
    import ipaddress

    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(network, strict=False)
    except ValueError:
        return False


def _ip_key(ip: str) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in ip.split("."))
    except ValueError:
        return (999,)
