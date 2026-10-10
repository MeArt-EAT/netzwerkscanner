"""Netz-Wächter: erkennt Heimnetz und gesperrte Netze. Sicherheitskritisch – siehe BAUPLAN §10. (Agent guard)

Grundsätze:
- Eine Sperre (block) lässt sich durch nichts übergehen – es gibt keinen Parameter und keine
  Einstellung dafür. Die Namen aus PERMANENT_BLOCKED_SSIDS gelten immer.
- Im Zweifel nie allow: jede Ausnahme der Plattform führt höchstens zu confirm. Ist der
  WLAN-Status gar nicht abfragbar, gilt der WLAN-Name als „nicht lesbar“.
- Der Wächter sendet keine Pakete; er fragt nur den Systemzustand ab (WLAN, Routen, ARP-Cache).
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field

from netscan.config import PERMANENT_BLOCKED_SSIDS, Settings, SettingsStore
from netscan.core.models import Adapter, GuardResult, normalize_mac
from netscan.platform.base import Platform, WifiEntry

__all__ = ["NetworkGuard", "PERMANENT_BLOCKED_SSIDS"]

log = logging.getLogger(__name__)

_CONFIRM_HINT = "Scanne nur Netze, für die du die Erlaubnis hast – Scan erst nach Bestätigung."
_NO_HOME = "Noch kein Heimnetz festgelegt."


def _normalize(value: object) -> str | None:
    """Normalisierte Unicast-MAC oder None (ungültig, leer, Broadcast/Multicast)."""
    if not isinstance(value, str) or not value:
        return None
    try:
        mac = normalize_mac(value)
    except ValueError:
        return None
    if mac == "00:00:00:00:00:00" or int(mac[:2], 16) & 1:
        return None
    return mac


def _mac_set(values: object) -> set[str]:
    if not isinstance(values, (list, tuple, set, frozenset)):
        return set()
    return {mac for mac in (_normalize(v) for v in values) if mac}


@dataclass
class _Gateway:
    interface: str | None
    ip: str | None = None
    mac: str | None = None
    error: str | None = None  # Abfrage ist mit einer Ausnahme gescheitert


@dataclass
class _Wifi:
    entries: list[WifiEntry] = field(default_factory=list)  # alle gemeldeten Einträge
    readable: bool = False
    error: str | None = None
    failed: bool = False  # wifi_status() hat eine Ausnahme geworfen

    @property
    def connected(self) -> list[WifiEntry]:
        return [e for e in self.entries if e.connected]


class _Probe:
    """Plattformabfragen eines check()-Durchlaufs: jede höchstens einmal, Ausnahmen werden zu Zweifeln."""

    def __init__(self, platform: Platform) -> None:
        self.platform = platform
        self.doubts: list[str] = []
        self._gateways: dict[str | None, _Gateway] = {}
        self._wireless: set[str] | None = None

    def doubt(self, text: str) -> None:
        if text not in self.doubts:
            self.doubts.append(text)

    def gateway(self, interface: str | None) -> _Gateway:
        if interface not in self._gateways:
            gw = self._query_gateway(interface)
            if gw.error:
                self.doubt(gw.error)
            self._gateways[interface] = gw
        return self._gateways[interface]

    def _query_gateway(self, interface: str | None) -> _Gateway:
        label = f"„{interface}“" if interface else "den Standardweg"
        try:
            raw_ip = self.platform.default_gateway(interface)
        except Exception as exc:  # noqa: BLE001
            log.warning("Gateway für %s nicht abfragbar: %s", interface, exc)
            return _Gateway(interface, error=f"das Gateway für {label} ließ sich nicht abfragen")
        if not raw_ip:
            return _Gateway(interface)
        try:
            ip = str(ipaddress.IPv4Address(str(raw_ip)))
        except ValueError:
            return _Gateway(interface, error=f"die Gateway-Adresse für {label} ist ungültig")
        try:
            mac = _normalize(self.platform.neighbor_mac(ip))
        except Exception as exc:  # noqa: BLE001
            log.warning("ARP-Cache nicht abfragbar: %s", exc)
            return _Gateway(interface, ip=ip, error="der ARP-Cache ließ sich nicht abfragen")
        return _Gateway(interface, ip=ip, mac=mac)

    def wireless_names(self, wifi: _Wifi) -> set[str]:
        """Namen aller WLAN-Adapter. Adapterliste nicht abfragbar ⇒ vorsichtshalber alle Adapter."""
        if self._wireless is None:
            names = {e.interface for e in wifi.entries if e.interface}
            try:
                details = self.platform.adapter_details() or {}
                names |= {name for name, d in details.items() if getattr(d, "is_wireless", False)}
            except Exception as exc:  # noqa: BLE001
                log.warning("Adapterdetails nicht abfragbar: %s", exc)
                self.doubt("die Netzwerkadapter ließen sich nicht abfragen")
                try:
                    names |= {i.name for i in self.platform.interfaces()}
                except Exception:  # noqa: BLE001
                    log.warning("Schnittstellen nicht abfragbar", exc_info=True)
            self._wireless = names
        return set(self._wireless)


class NetworkGuard:
    def __init__(self, platform: Platform, settings_store: SettingsStore) -> None:
        self.platform = platform
        self.settings_store = settings_store

    # --- öffentlich ----------------------------------------------------------------
    def check(self, adapter: Adapter | None) -> GuardResult:
        """Entscheidung allow / confirm / block für einen Scan über adapter. Sendet keine Pakete."""
        try:
            result = self._evaluate(adapter)
        except Exception:  # noqa: BLE001 – ein Fehler im Wächter darf nie zu allow führen
            log.exception("Netz-Wächter: unerwarteter Fehler – Ergebnis höchstens „confirm“")
            result = self._emergency_result()
        level = logging.WARNING if result.decision == "block" else logging.INFO
        log.log(level, "Netz-Wächter: %s/%s für %s", result.decision, result.code, adapter.name if adapter else "-")
        return result

    def remember_home(self, gateway_mac: str) -> None:
        """Gateway-MAC als Heimnetz merken (nach ausdrücklicher Bestätigung in der Oberfläche).

        ValueError bei ungültiger MAC oder wenn der Router zu einem gesperrten Netz gehört.
        """
        mac = normalize_mac(gateway_mac)  # ValueError bei Unsinn
        if _normalize(mac) is None:
            raise ValueError(f"Keine gültige Router-MAC-Adresse: {gateway_mac!r}")
        settings = self.settings_store.load()
        if mac in _mac_set(settings.blocked_gateway_macs):
            raise ValueError("Dieser Router gehört zu einem gesperrten Netz und kann nicht als Heimnetz gelten.")
        if mac in _mac_set(settings.home_gateway_macs):
            return
        self.settings_store.add_to_list("home_gateway_macs", mac)
        log.info("Heimnetz-Router gemerkt: %s", mac)

    # --- Regeln (BAUPLAN §10, in dieser Reihenfolge) ----------------------------------
    def _evaluate(self, adapter: Adapter | None) -> GuardResult:
        probe = _Probe(self.platform)
        settings = self._load_settings(probe)
        blocked_names = self._blocked_ssids(settings)
        wifi = self._wifi()

        # Regel 1 + 2: irgendein verbundenes WLAN mit gesperrtem Namen (exakter Vergleich) ⇒ block
        hits = [e for e in wifi.connected if e.ssid is not None and e.ssid in blocked_names]
        if hits:
            return self._block_ssid(hits, adapter, probe)

        adapter_name = adapter.name if adapter else None
        if wifi.failed:
            probe.doubt("der WLAN-Status ließ sich nicht abfragen")
        own = probe.gateway(adapter_name)
        unreadable = self._unreadable_detail(wifi, adapter, probe)
        ssid = self._display_ssid(wifi, adapter_name)

        # Regel 3: Name nicht lesbar ⇒ Gateway-MACs von Scan-Adapter und allen WLAN-Adaptern prüfen
        if unreadable is not None:
            candidates = [own]
            for name in sorted(probe.wireless_names(wifi) - {adapter_name}):  # type: ignore[operator]
                gw = probe.gateway(name)
                if gw.ip is not None and gw.mac is None and gw.error is None:
                    probe.doubt(f"die MAC-Adresse des Routers {gw.ip} hinter „{name}“ ist unbekannt")
                candidates.append(gw)
            blocked_macs = _mac_set(settings.blocked_gateway_macs)
            for gw in candidates:
                if gw.mac is not None and gw.mac in blocked_macs:
                    reason = (
                        f"Scan gesperrt: Der WLAN-Name ist nicht lesbar, aber der Router {gw.ip} ({gw.mac}) "
                        "gehört zu einem gesperrten WLAN, das der Scanner früher erkannt hat. In diesem Netz ist "
                        "jeder Scan verboten – auch im Modus „nur eingetragene Geräte“. "
                        "Die Sperre lässt sich nicht übergehen."
                    )
                    return GuardResult(
                        "block", "blocked_gateway", reason, ssid=ssid, ssid_readable=False,
                        gateway_ip=gw.ip, gateway_mac=gw.mac,
                    )

        home = _mac_set(settings.home_gateway_macs)
        prefix = f"{_NO_HOME} " if not home else ""
        suffix = self._unreadable_text(unreadable) + self._doubt_text(probe.doubts)
        result_fields = {"ssid": ssid, "ssid_readable": unreadable is None, "gateway_ip": own.ip, "gateway_mac": own.mac}

        # Regel 4: kein Gateway ⇒ confirm
        if own.ip is None:
            where = f"Für den Adapter „{adapter_name}“ ist" if adapter_name else "Es ist"
            reason = (
                f"{prefix}{where} kein Router (Standard-Gateway) ermittelbar – ob das dein Heimnetz ist, "
                f"lässt sich nicht prüfen. {_CONFIRM_HINT}{suffix}"
            )
            return GuardResult("confirm", "no_gateway", reason, **result_fields)

        # Regel 5: Heimnetz-Router ⇒ allow (aber nie bei Zweifeln aus Plattformfehlern)
        if own.mac is not None and own.mac in home:
            if probe.doubts:
                reason = (
                    f"Heimnetz-Router erkannt ({own.mac}), aber die Sperrprüfung war unvollständig. "
                    f"Scan erst nach Bestätigung.{suffix}"
                )
                return GuardResult("confirm", "unknown_network", reason, **result_fields)
            reason = f"Heimnetz erkannt: Router {own.ip} ({own.mac})."
            if unreadable is not None:
                reason += self._unreadable_text(unreadable) + " Geprüft wurde der Router."
            return GuardResult("allow", "ok_home", reason, **result_fields)

        # Regel 6: fremdes oder unklares Netz ⇒ confirm
        if own.mac is not None:
            if home:
                reason = f"Fremdes Netz: Der Router {own.ip} ({own.mac}) ist nicht als Heimnetz eingetragen. {_CONFIRM_HINT}"
            else:
                reason = (
                    f"{_NO_HOME} Router dieses Netzes: {own.ip} ({own.mac}). Ist das dein Heimnetz, bestätige mit "
                    "„Das ist mein Heimnetz“; ein fremdes Netz scanne nur mit Erlaubnis des Netzbetreibers. "
                    "Scan erst nach Bestätigung."
                )
            return GuardResult("confirm", "foreign_network", reason + suffix, **result_fields)
        reason = (
            f"{prefix}{'Unklares Netz: ' if home else ''}Die MAC-Adresse des Routers {own.ip} ist nicht bekannt, "
            f"das Heimnetz lässt sich nicht erkennen. {_CONFIRM_HINT}"
        )
        return GuardResult("confirm", "unknown_network", reason + suffix, **result_fields)

    # --- Sperre über den WLAN-Namen -----------------------------------------------------
    def _block_ssid(self, hits: list[WifiEntry], adapter: Adapter | None, probe: _Probe) -> GuardResult:
        """block/blocked_ssid; Router-MAC jedes gesperrten WLANs merken (Fehler dabei ändern nichts)."""
        gateways = [self._learn_blocked_gateway(entry, probe) for entry in hits]
        index = next((i for i, e in enumerate(hits) if adapter is not None and e.interface == adapter.name), 0)
        entry, gw = hits[index], gateways[index]
        reason = (
            f"Scan gesperrt: Der Rechner ist über „{entry.interface}“ mit dem WLAN „{entry.ssid}“ verbunden. "
            "In diesem Netz ist jeder Scan verboten – auch im Modus „nur eingetragene Geräte“. "
            "Die Sperre lässt sich nicht übergehen; trenne zuerst die Verbindung zu diesem WLAN."
        )
        return GuardResult(
            "block", "blocked_ssid", reason, ssid=entry.ssid, ssid_readable=True, gateway_ip=gw.ip, gateway_mac=gw.mac
        )

    def _learn_blocked_gateway(self, entry: WifiEntry, probe: _Probe) -> _Gateway:
        gw = probe.gateway(entry.interface)
        if gw.mac is None or gw.ip is None:
            log.warning("Gesperrtes WLAN über %s: Router-MAC nicht ermittelbar, wird nicht gemerkt", entry.interface)
            return gw
        if not self._gateway_in_subnet(entry.interface, gw.ip):
            # z. B. veraltete Route: lieber nicht merken als den falschen Router dauerhaft sperren
            log.warning("Gesperrtes WLAN über %s: Router %s liegt nicht im Netz des Adapters, nicht gemerkt", entry.interface, gw.ip)
            return gw
        try:
            if gw.mac not in _mac_set(self.settings_store.load().blocked_gateway_macs):
                self.settings_store.add_to_list("blocked_gateway_macs", gw.mac)
                log.warning("Router-MAC des gesperrten WLANs gemerkt: %s", gw.mac)
        except Exception:  # noqa: BLE001 – die Sperre gilt trotzdem
            log.exception("Router-MAC des gesperrten WLANs nicht gespeichert")
        return gw

    def _gateway_in_subnet(self, interface: str, gateway_ip: str) -> bool:
        """Liegt das Gateway im IPv4-Netz des Adapters? Adapter unbekannt ⇒ True (nicht verhindern)."""
        try:
            addrs = [i for i in self.platform.interfaces() if i.name == interface]
            gateway = ipaddress.IPv4Address(gateway_ip)
        except Exception:  # noqa: BLE001
            return True
        if not addrs:
            return True
        for addr in addrs:
            try:
                net = ipaddress.IPv4Interface(f"{addr.ipv4}/{addr.netmask}").network
            except ValueError:
                return True
            if gateway in net:
                return True
        return False

    # --- Abfragen (jede Ausnahme abgefangen) ----------------------------------------------
    def _load_settings(self, probe: _Probe) -> Settings:
        try:
            return self.settings_store.load()
        except Exception:  # noqa: BLE001 – Standard: nur feste Sperrliste, kein Heimnetz ⇒ nie allow
            log.exception("Einstellungen für den Netz-Wächter nicht lesbar")
            probe.doubt("die Einstellungen ließen sich nicht lesen")
            return Settings()

    @staticmethod
    def _blocked_ssids(settings: Settings) -> set[str]:
        names = set(PERMANENT_BLOCKED_SSIDS)  # gilt immer, auch wenn die Einstellungen kaputt sind
        try:
            names |= {s for s in settings.blocked_ssids() if isinstance(s, str) and s}
        except Exception:  # noqa: BLE001
            log.exception("Gesperrte WLAN-Namen aus den Einstellungen nicht lesbar")
        return names

    def _wifi(self) -> _Wifi:
        try:
            status = self.platform.wifi_status()
            entries: list[WifiEntry] = []
            for e in list(getattr(status, "entries", None) or []):
                ssid = getattr(e, "ssid", None)
                entries.append(
                    WifiEntry(
                        interface=str(getattr(e, "interface", "") or ""),
                        connected=bool(getattr(e, "connected", False)),
                        ssid=ssid if isinstance(ssid, str) and ssid != "" else None,  # leer = nicht lesbar
                    )
                )
            error = getattr(status, "error", None)
            return _Wifi(entries, bool(getattr(status, "readable", False)), str(error) if error else None)
        except Exception as exc:  # noqa: BLE001 – gilt als „nicht lesbar“, nie als „kein WLAN“
            log.warning("WLAN-Status nicht abfragbar: %s", exc)
            return _Wifi([], readable=False, error="WLAN-Status nicht abfragbar", failed=True)

    # --- Lesbarkeit und Texte ------------------------------------------------------------
    @staticmethod
    def _unreadable_detail(wifi: _Wifi, adapter: Adapter | None, probe: _Probe) -> str | None:
        """None = WLAN-Name lesbar, sonst kurze Begründung (für reason)."""
        if not wifi.readable:
            return wifi.error or ""
        connected = {e.interface for e in wifi.connected}
        for entry in wifi.connected:
            if entry.ssid is None:
                return f"„{entry.interface}“ meldet keinen Namen"
        if adapter is not None and adapter.is_wireless and adapter.name not in connected:
            return f"für „{adapter.name}“ liegt kein WLAN-Status vor"
        # Widerspruch: ein WLAN-Adapter hat einen Router, aber keine gemeldete WLAN-Verbindung
        for name in sorted(probe.wireless_names(wifi) - connected):
            if probe.gateway(name).ip is not None:
                return f"„{name}“ hat einen Router, meldet aber keine WLAN-Verbindung"
        return None

    @staticmethod
    def _display_ssid(wifi: _Wifi, adapter_name: str | None) -> str | None:
        named = [e for e in wifi.connected if e.ssid]
        for entry in named:
            if entry.interface == adapter_name:
                return entry.ssid
        return named[0].ssid if named else None

    @staticmethod
    def _unreadable_text(detail: str | None) -> str:
        if detail is None:
            return ""
        return f" Der WLAN-Name ist nicht lesbar ({detail})." if detail else " Der WLAN-Name ist nicht lesbar."

    @staticmethod
    def _doubt_text(doubts: list[str]) -> str:
        return " Die Prüfung war unvollständig: " + "; ".join(doubts) + "." if doubts else ""

    def _emergency_result(self) -> GuardResult:
        """Notfall nach internem Fehler: gesperrter Name ⇒ block, sonst confirm. Nie allow."""
        try:
            names = set(PERMANENT_BLOCKED_SSIDS)
            try:
                names |= self._blocked_ssids(self.settings_store.load())
            except Exception:  # noqa: BLE001
                pass
            for entry in self.platform.wifi_status().entries:
                if entry.connected and entry.ssid in names:
                    reason = (
                        f"Scan gesperrt: Der Rechner ist mit dem WLAN „{entry.ssid}“ verbunden. "
                        "In diesem Netz ist jeder Scan verboten. Die Sperre lässt sich nicht übergehen."
                    )
                    return GuardResult("block", "blocked_ssid", reason, ssid=entry.ssid, ssid_readable=True)
        except Exception:  # noqa: BLE001
            log.debug("Notfallprüfung gescheitert", exc_info=True)
        reason = f"Die Netzprüfung ist an einem internen Fehler gescheitert – das Netz lässt sich nicht erkennen. {_CONFIRM_HINT}"
        return GuardResult("confirm", "unknown_network", reason, ssid_readable=False)
