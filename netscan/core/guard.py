"""Netz-Wächter: erkennt Heimnetz und gesperrte Netze. Sicherheitskritisch – siehe BAUPLAN §10. (Agent guard)

Grundsätze:
- Eine Sperre (block) lässt sich durch nichts übergehen – es gibt keinen Parameter und keine
  Einstellung dafür. Die Namen aus PERMANENT_BLOCKED_SSIDS gelten immer.
- Im Zweifel nie allow: jede Ausnahme der Plattform führt höchstens zu confirm. Ist der
  WLAN-Status gar nicht abfragbar, gilt der WLAN-Name als „nicht lesbar“.
- Der Wächter sendet keine Pakete; er fragt nur den Systemzustand ab (WLAN, Routen, ARP-Cache).
- Ist der WLAN-Name nicht lesbar (Windows ohne Standortberechtigung), zählt zusätzlich der Name des
  Netzwerkprofils (WifiStatus.profile_names) – aber nur in Sperr-Richtung: Heißt ein Profil exakt wie
  ein gesperrtes WLAN, gilt das wie ein verbundenes gesperrtes WLAN (block, Router-MAC wird gelernt).
  Für allow zählt der Profilname nie, und ein Heimnetz über WLAN lässt sich ohne lesbaren Namen nicht
  merken (remember_home ⇒ HomeRefused).
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Any

from netscan.config import PERMANENT_BLOCKED_SSIDS, Settings, SettingsStore
from netscan.core.models import Adapter, GuardResult, normalize_mac
from netscan.platform.base import Platform, WifiEntry

__all__ = ["HomeRefused", "NetworkGuard", "PERMANENT_BLOCKED_SSIDS"]

log = logging.getLogger(__name__)


class HomeRefused(ValueError):
    """Der Router darf (noch) nicht als Heimnetz gemerkt werden – kein Sperrgrund, die API meldet 422."""

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
    profiles: dict[str, str] = field(default_factory=dict)  # Adapter -> Netzwerkprofilname (nur zum Sperren)

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
            mac = _normalize(self._neighbor_mac(ip, interface))
        except Exception as exc:  # noqa: BLE001
            log.warning("ARP-Cache nicht abfragbar: %s", exc)
            return _Gateway(interface, ip=ip, error="der ARP-Cache ließ sich nicht abfragen")
        return _Gateway(interface, ip=ip, mac=mac)

    def _neighbor_mac(self, ip: str, interface: str | None) -> str | None:
        """MAC des Gateways aus dem ARP-Cache – mit Adapter nur aus dessen Einträgen (gleiche Gateway-IP an zwei
        Adaptern). Plattformen ohne den Parameter interface werden wie bisher gefragt."""
        if interface is None:
            return self.platform.neighbor_mac(ip)
        try:
            return self.platform.neighbor_mac(ip, interface)  # type: ignore[call-arg]
        except TypeError:
            return self.platform.neighbor_mac(ip)

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

    def remember_home(self, gateway_mac: str, adapter: Adapter | None = None) -> None:
        """Gateway-MAC als Heimnetz merken (nach ausdrücklicher Bestätigung in der Oberfläche).

        ValueError bei ungültiger MAC oder wenn der Router zu einem gesperrten Netz gehört.
        HomeRefused (Unterklasse von ValueError), wenn adapter ein WLAN-Adapter ist und dessen WLAN-Name
        gerade nicht lesbar ist: Dann ließe sich der Schul-Hotspot nicht ausschließen, und ein einmal
        gemerkter Hotspot-Router ergäbe später allow ohne jede Rückfrage.
        """
        mac = normalize_mac(gateway_mac)  # ValueError bei Unsinn
        if _normalize(mac) is None:
            raise ValueError(f"Keine gültige Router-MAC-Adresse: {gateway_mac!r}")
        settings = self.settings_store.load()
        if mac in _mac_set(settings.blocked_gateway_macs):
            raise ValueError("Dieser Router gehört zu einem gesperrten Netz und kann nicht als Heimnetz gelten.")
        if adapter is not None:
            refusal = self._home_refusal(adapter)
            if refusal:
                raise HomeRefused(refusal)
        if mac in _mac_set(settings.home_gateway_macs):
            return
        self.settings_store.add_to_list("home_gateway_macs", mac)
        log.info("Heimnetz-Router gemerkt: %s", mac)

    def _home_refusal(self, adapter: Adapter) -> str | None:
        """Begründung, warum der Router hinter adapter jetzt nicht Heimnetz werden darf (None = darf)."""
        probe = _Probe(self.platform)
        wifi = self._wifi()
        blocked_names = self._blocked_ssids(self._load_settings(probe))
        return self._home_refusal_for(adapter, wifi, probe, blocked_names)

    @staticmethod
    def _unidentified_wifi(wifi: _Wifi, adapter: Adapter | None, probe: _Probe) -> list[str]:
        """WLAN-Adapter mit Verbindung (Router oder Scan-Adapter), die weder SSID noch Profilnamen nennen.
        Über sie ließe sich der Schul-Hotspot nicht ausschließen."""
        names = set(probe.wireless_names(wifi))
        if adapter is not None and adapter.is_wireless:
            names.add(adapter.name)
        out: list[str] = []
        for name in sorted(names):
            is_scan = adapter is not None and name == adapter.name
            if not is_scan and probe.gateway(name).ip is None:
                continue  # nicht verbunden
            named = any(e.interface == name and e.connected and e.ssid is not None for e in wifi.entries)
            if (wifi.readable and named) or wifi.profiles.get(name):
                continue
            out.append(name)
        return out

    @staticmethod
    def _home_refusal_for(adapter: Adapter, wifi: _Wifi, probe: _Probe, blocked_names: set[str]) -> str | None:
        """Kabel: immer erlaubt. WLAN: erlaubt, wenn der WLAN-Name (netsh) oder – ohne Standortberechtigung –
        der Name des Windows-Netzwerkprofils bekannt ist und nicht gesperrt ist. Ohne beides ließe sich der
        Schul-Hotspot nicht ausschließen."""
        wireless = bool(adapter.is_wireless) or adapter.name in probe.wireless_names(wifi)
        if not wireless:
            return None
        named = [e for e in wifi.entries if e.interface == adapter.name and e.connected and e.ssid is not None]
        if wifi.readable and named:
            return None if named[0].ssid not in blocked_names else "Dieses WLAN ist gesperrt."
        profile = wifi.profiles.get(adapter.name)
        if profile:
            return None if profile not in blocked_names else "Dieses WLAN ist gesperrt."
        return (
            f"Das Heimnetz lässt sich über „{adapter.name}“ nicht merken: Windows nennt weder den WLAN-Namen noch "
            "den Namen des Netzwerkprofils, so ließe sich der Schul-Hotspot nicht sicher ausschließen. "
            "Bis dahin „Nur diesmal scannen“ verwenden."
        )

    # --- Regeln (BAUPLAN §10, in dieser Reihenfolge) ----------------------------------
    def _evaluate(self, adapter: Adapter | None) -> GuardResult:
        probe = _Probe(self.platform)
        settings = self._load_settings(probe)
        blocked_names = self._blocked_ssids(settings)
        wifi = self._wifi()

        # Regel 1 + 2: irgendein verbundenes WLAN mit gesperrtem Namen (exakter Vergleich) ⇒ block.
        # Dazu zählt ein Netzwerkprofil, das exakt wie ein gesperrtes WLAN heißt (Name per netsh nicht lesbar).
        hits = [e for e in wifi.connected if e.ssid is not None and e.ssid in blocked_names]
        named = {e.interface for e in hits}
        profile_hits = [
            WifiEntry(interface=name, connected=True, ssid=profile)
            for name, profile in sorted(wifi.profiles.items())
            if profile in blocked_names and name not in named
        ]
        if hits or profile_hits:
            return self._block_ssid(hits + profile_hits, adapter, probe, {e.interface for e in profile_hits})

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

        # Eine gesperrte MAC kann nie Heimnetz sein – auch nicht, wenn sie (z. B. per PUT /api/settings oder vor
        # dem Lernen) in home_gateway_macs steht.
        home = _mac_set(settings.home_gateway_macs) - _mac_set(settings.blocked_gateway_macs)
        prefix = f"{_NO_HOME} " if not home else ""
        suffix = self._unreadable_text(unreadable) + self._doubt_text(probe.doubts)
        profile_name = wifi.profiles.get(adapter_name) if adapter_name and unreadable is not None else None
        result_fields: dict[str, Any] = {
            "ssid": ssid, "ssid_readable": unreadable is None, "gateway_ip": own.ip, "gateway_mac": own.mac,
            "profile_name": profile_name,
        }
        # „Das ist mein Heimnetz“ nur anbieten, wenn remember_home es auch annimmt
        home_refusal = (
            self._home_refusal_for(adapter, wifi, probe, blocked_names) if adapter is not None else "kein Adapter"
        )
        home_allowed = bool(own.mac) and not probe.doubts and home_refusal is None
        if profile_name:
            suffix += f" Netzwerkprofil laut Windows: „{profile_name}“ (nicht gesperrt)."

        # Freie Nutzung (Entscheidung des Nutzers, 10.10.2026): Jedes Netz, das sicher NICHT gesperrt ist, darf
        # ohne Rückfrage gescannt werden. Nachgefragt wird nur, wenn sich die Sperre nicht sicher prüfen lässt.
        # Die frühere Heimnetz-Rückfrage gibt es weiter über settings.ask_before_foreign_scan.
        if not getattr(settings, "ask_before_foreign_scan", False):
            unidentified = self._unidentified_wifi(wifi, adapter, probe)
            if probe.doubts or unidentified:
                gaps = list(probe.doubts) + [f"„{n}“ nennt weder WLAN-Namen noch Netzwerkprofil" for n in unidentified]
                reason = (
                    "Ob das ein gesperrtes Netz (Schule) ist, lässt sich nicht sicher prüfen: " + "; ".join(gaps)
                    + f". {_CONFIRM_HINT}"
                )
                return GuardResult("confirm", "unknown_network", reason, **result_fields)
            router = (f"Router {own.ip}" + (f", MAC {own.mac}" if own.mac else "")) if own.ip else "kein Router"
            reason = f"Netz frei: kein gesperrtes Netz erkannt – {router}."
            if profile_name:
                reason += " Erkannt über das Windows-Netzwerkprofil (WLAN-Name nicht lesbar)."
            code = "ok_home" if own.mac is not None and own.mac in home else "ok_network"
            return GuardResult("allow", code, reason, **result_fields)  # type: ignore[arg-type]

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
                if home_allowed:
                    home_hint = "Ist das dein Heimnetz, bestätige mit „Das ist mein Heimnetz“"
                else:
                    # remember_home lehnt das hier ab (HomeRefused) – also auch nicht anbieten
                    home_hint = (
                        "Als Heimnetz merken lässt es sich über WLAN erst, wenn Windows den WLAN-Namen oder den "
                        "Namen des Netzwerkprofils nennt"
                    )
                reason = (
                    f"{_NO_HOME} Router dieses Netzes: {own.ip} ({own.mac}). {home_hint}; ein fremdes Netz scanne "
                    "nur mit Erlaubnis des Netzbetreibers. Scan erst nach Bestätigung."
                )
            return GuardResult("confirm", "foreign_network", reason + suffix, home_allowed=home_allowed, **result_fields)
        reason = (
            f"{prefix}{'Unklares Netz: ' if home else ''}Die MAC-Adresse des Routers {own.ip} ist nicht bekannt, "
            f"das Heimnetz lässt sich nicht erkennen. {_CONFIRM_HINT}"
        )
        return GuardResult("confirm", "unknown_network", reason + suffix, **result_fields)

    # --- Sperre über den WLAN-Namen -----------------------------------------------------
    def _block_ssid(
        self, hits: list[WifiEntry], adapter: Adapter | None, probe: _Probe, from_profile: set[str] | None = None
    ) -> GuardResult:
        """block/blocked_ssid; Router-MAC jedes gesperrten WLANs merken (Fehler dabei ändern nichts).

        from_profile: Adapter, deren Treffer nur aus dem Netzwerkprofilnamen stammt (WLAN-Name nicht lesbar).
        """
        from_profile = from_profile or set()
        gateways = [self._learn_blocked_gateway(entry, probe) for entry in hits]
        index = next((i for i, e in enumerate(hits) if adapter is not None and e.interface == adapter.name), 0)
        entry, gw = hits[index], gateways[index]
        if entry.interface in from_profile:
            where = (
                f"Der WLAN-Name ist nicht lesbar, aber Windows führt die Verbindung über „{entry.interface}“ "
                f"unter dem Netzwerkprofil „{entry.ssid}“ – das ist ein gesperrtes WLAN. "
            )
        else:
            where = f"Der Rechner ist über „{entry.interface}“ mit dem WLAN „{entry.ssid}“ verbunden. "
        reason = (
            f"Scan gesperrt: {where}"
            "In diesem Netz ist jeder Scan verboten – auch im Modus „nur eingetragene Geräte“. "
            "Die Sperre lässt sich nicht übergehen; trenne zuerst die Verbindung zu diesem WLAN."
        )
        return GuardResult(
            "block", "blocked_ssid", reason, ssid=entry.ssid, ssid_readable=entry.interface not in from_profile,
            gateway_ip=gw.ip, gateway_mac=gw.mac,
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
            settings = self.settings_store.load()
            if gw.mac not in _mac_set(settings.blocked_gateway_macs):
                self.settings_store.add_to_list("blocked_gateway_macs", gw.mac)
                log.warning("Router-MAC des gesperrten WLANs gemerkt: %s", gw.mac)
            if gw.mac in _mac_set(settings.home_gateway_macs):
                # Ein gesperrter Router kann nie Heimnetz sein – auch einen früheren Eintrag entfernen.
                kept = [m for m in settings.home_gateway_macs if _normalize(m) != gw.mac]
                self.settings_store.update(home_gateway_macs=kept)
                log.warning("Router-MAC %s aus den Heimnetz-Routern entfernt (gehört zu einem gesperrten WLAN)", gw.mac)
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
            profiles: dict[str, str] = {}
            raw_profiles = getattr(status, "profile_names", None)
            if isinstance(raw_profiles, dict):
                for name, profile in raw_profiles.items():
                    if isinstance(name, str) and name and isinstance(profile, str) and profile.strip():
                        profiles[name] = profile.strip()  # Rand-Leerzeichen weg: sichere Richtung
            return _Wifi(entries, bool(getattr(status, "readable", False)), str(error) if error else None, profiles=profiles)
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
            status = self.platform.wifi_status()
            for entry in status.entries:
                if entry.connected and entry.ssid in names:
                    reason = (
                        f"Scan gesperrt: Der Rechner ist mit dem WLAN „{entry.ssid}“ verbunden. "
                        "In diesem Netz ist jeder Scan verboten. Die Sperre lässt sich nicht übergehen."
                    )
                    return GuardResult("block", "blocked_ssid", reason, ssid=entry.ssid, ssid_readable=True)
            for profile in (getattr(status, "profile_names", None) or {}).values():
                if isinstance(profile, str) and profile.strip() in names:
                    reason = (
                        f"Scan gesperrt: Windows führt eine Verbindung unter dem Netzwerkprofil „{profile.strip()}“ – "
                        "das ist ein gesperrtes WLAN. Die Sperre lässt sich nicht übergehen."
                    )
                    return GuardResult("block", "blocked_ssid", reason, ssid=profile.strip(), ssid_readable=False)
        except Exception:  # noqa: BLE001
            log.debug("Notfallprüfung gescheitert", exc_info=True)
        reason = f"Die Netzprüfung ist an einem internen Fehler gescheitert – das Netz lässt sich nicht erkennen. {_CONFIRM_HINT}"
        return GuardResult("confirm", "unknown_network", reason, ssid_readable=False)
