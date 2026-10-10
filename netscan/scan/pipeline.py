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
from netscan.core.models import Adapter, Device, NameInfo, PingResult, ScanRequest, normalize_mac
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


class Enricher(Protocol):
    name: str  # z. B. "names"
    label: str  # Fortschrittstext, z. B. "Namen"

    def run(self, ctx: ScanContext, job: ScanJob, devices: list[Device]) -> None:
        ...


class OuiEnricher:
    name = "oui"
    label = "Hersteller"

    def run(self, ctx: ScanContext, job: ScanJob, devices: list[Device]) -> None:
        for d in devices:
            d.mac_random = oui.is_random_mac(d.mac)
            d.vendor = None if d.mac_random else job.services.oui.lookup(d.mac)


class NamesEnricher:
    name = "names"
    label = "Namen"

    def run(self, ctx: ScanContext, job: ScanJob, devices: list[Device]) -> None:
        infos = names.resolve_names(ctx, [d.ip for d in devices], job.adapter)
        for d in devices:
            d.names = infos.get(d.ip) or NameInfo()
            d.hostname = d.names.best()


class SsdpEnricher:
    name = "ssdp"
    label = "SSDP/UPnP"

    def run(self, ctx: ScanContext, job: ScanJob, devices: list[Device]) -> None:
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
            prev = job.previous.get(d.mac)
            category = d.category if d.category_source == "user" or prev is None else prev.category
            if d.port_scan_excluded or category in excluded_cats:
                skipped += 1
                continue
            targets[d.ip] = port_list
            by_ip[d.ip] = d
        if skipped:
            ctx.log(f"{skipped} Gerät(e) vom Port-Scan ausgenommen.")
        if not targets:
            return
        results = ports.scan_ports(ctx, targets)
        for ip, d in by_ip.items():
            d.ports = results.get(ip, [])
            job.scanned_ports[d.mac] = port_list
        open_total = sum(len(v) for v in results.values())
        ctx.log(f"Port-Scan: {len(targets)} Gerät(e), {open_total} offene Port(s).")


class ClassifyEnricher:
    name = "classify"
    label = "Einordnung"

    def run(self, ctx: ScanContext, job: ScanJob, devices: list[Device]) -> None:
        for d in devices:
            prev = job.previous.get(d.mac)
            if not d.ports and prev is not None and d.mac not in job.scanned_ports:
                d.ports = list(prev.ports)  # ohne Port-Scan: gespeicherte Ports für die Einordnung nutzen
        classify.apply_classification(devices)


ENRICHERS: list[Enricher] = [OuiEnricher(), NamesEnricher(), SsdpEnricher(), PortsEnricher(), ClassifyEnricher()]


def deep_port_list() -> list[int]:
    return sorted(set(ports.DEEP_PORTS) | set(ports.COMMON_PORTS))


# --- Ablauf ---------------------------------------------------------------------


def _check_guard(ctx: ScanContext, services: Services, adapter: Adapter, confirmed: bool | None) -> None:
    """Zweite Prüfung im Auftrag selbst. confirmed=None: Bestätigung nicht prüfen (Tiefenscan)."""
    guard = services.guard.check(adapter)
    ctx.emit("guard.result", {"guard": guard.to_dict()})
    if guard.decision == "block":
        raise GuardBlocked(guard)
    if guard.decision == "confirm" and confirmed is False:
        raise GuardBlocked(replace(guard, reason=f"Bestätigung fehlt: {guard.reason}"))


def _discover(ctx: ScanContext, job: ScanJob) -> list[Device]:
    services, adapter, request = job.services, job.adapter, job.request
    macs: dict[str, str] = {}
    via: dict[str, list[str]] = {}

    if request.mode == "full":
        targets = adapters.hosts_of(adapter)
        ctx.log(f"Suche im Netz {adapter.network} ({len(targets)} Adressen).")
    else:
        known = services.inventory.registered_devices()
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

    ctx.check_cancel()
    pings: dict[str, PingResult] = ping.ping_sweep(ctx, targets) if targets else {}
    for ip in pings:
        via.setdefault(ip, []).append("ping")

    neighbors = services.platform.neighbor_table()
    for ip in pings:
        if ip not in macs and ip in neighbors:
            macs[ip] = neighbors[ip]
            via[ip].append("cache")

    gateway_ip = services.platform.default_gateway(adapter.name)
    if gateway_ip and gateway_ip not in macs and gateway_ip in neighbors and _in_network(gateway_ip, adapter.network):
        macs[gateway_ip] = neighbors[gateway_ip]
        via.setdefault(gateway_ip, []).append("cache")

    devices: dict[str, Device] = {}
    for ip in sorted(macs, key=_ip_key):
        try:
            mac = normalize_mac(macs[ip])
        except ValueError:
            continue
        if mac in _BAD_MACS or int(mac[:2], 16) & 0x01:  # Null-, Broadcast-, Multicast-MAC
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
    _check_guard(ctx, services, adapter, confirmed=request.confirm_foreign)
    if adapter.prefix < config.PREFIX_WARN:
        ctx.log(f"Großes Netz (/{adapter.prefix}) – der Scan dauert länger.", "warning")

    inventory = services.inventory
    scan_id = inventory.begin_scan("scan", adapter.name, adapter.network)
    ctx.scan_id = scan_id
    job = ScanJob(request=request, adapter=adapter, services=services, scan_id=scan_id)
    mode_text = "Netz absuchen" if request.mode == "full" else "nur eingetragene Geräte"
    ctx.log(f"Scan gestartet über „{adapter.name}“ ({adapter.ipv4}, {adapter.network}), Modus: {mode_text}.")
    result = "failed"
    count = 0
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
            enricher.run(ctx, job, devices)

        ctx.check_cancel()
        new_count = 0
        for i, d in enumerate(devices, 1):
            inventory.record_seen(d, scan_id)
            if d.mac in job.scanned_ports:
                inventory.set_ports(d.mac, job.scanned_ports[d.mac], d.ports)
            stored = inventory.get(d.mac)
            if stored is not None:
                if stored.first_seen_scan == scan_id and not stored.known:
                    new_count += 1
                ctx.emit("device.updated", {"device": stored.to_dict()})
            ctx.progress("Speichern", i, len(devices))
        count = len(devices)
        result = "completed"
        duration = round(time.monotonic() - t0, 1)
        ctx.log(f"Scan fertig: {count} Gerät(e), davon {new_count} neu, {duration} s.")
        return {"devices": count, "new": new_count, "duration_s": duration, "network": adapter.network, "scan_id": scan_id}
    except ScanCancelled:
        result = "cancelled"
        raise
    except GuardBlocked:
        result = "blocked"
        raise
    finally:
        inventory.finish_scan(scan_id, result, count)
        ctx.emit("devices.changed", {})


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
        found = ports.scan_ports(ctx, {device.ip: port_list}).get(device.ip, [])
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
