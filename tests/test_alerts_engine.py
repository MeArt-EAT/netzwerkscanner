"""AlertEngine (BAUPLAN §25): Regeln mit Schwellen, Schwere, Texten, Schließen, Scan-Rückmeldung.

Datenbank im tmp_path, echter AlertStore, EventBus und SettingsStore; Ziele, Prüfungen und Geräte direkt gebaut.
"""

from __future__ import annotations

import pytest

from netscan.config import SettingsStore
from netscan.core.alerts import SELF_FIREWALL_HINT, AlertEngine, AlertStore
from netscan.core.db import Database
from netscan.core.events import EventBus
from netscan.core.inventory import Inventory
from netscan.core.models import Device, MonitorTarget, PortResult, ScanOutcome, ServiceCheck, iso_from_ts
from tests.fakes import make_adapter

T0 = 1_760_000_000.0
NAS_MAC, NAS_IP = "00:11:32:aa:bb:03", "192.168.178.3"
PC_MAC, PC_IP = "00:1b:21:aa:bb:05", "192.168.178.5"
SELF_MAC, SELF_IP = "00:1b:21:00:00:20", "192.168.178.20"


@pytest.fixture
def env(tmp_path):  # type: ignore[no-untyped-def]
    db = Database(tmp_path / "engine.sqlite3")
    bus = EventBus()
    store = AlertStore(db, bus)
    settings = SettingsStore(db)
    engine = AlertEngine(store, settings)

    class Env:
        pass

    e = Env()
    e.db, e.bus, e.store, e.settings, e.engine = db, bus, store, settings, engine  # type: ignore[attr-defined]
    yield e
    db.close()


def _events(env, type_: str) -> list[dict]:  # type: ignore[no-untyped-def]
    return [e.data for e in env.bus.history() if e.type == type_]


def _nas(**kw) -> Device:  # type: ignore[no-untyped-def]
    return Device(mac=NAS_MAC, ip=NAS_IP, hostname="nas", category=kw.pop("category", "server"), **kw)


def _pc(**kw) -> Device:  # type: ignore[no-untyped-def]
    return Device(mac=PC_MAC, ip=PC_IP, hostname="buero-pc", category=kw.pop("category", "pc"), **kw)


def _target(mac: str = PC_MAC, **kw) -> MonitorTarget:  # type: ignore[no-untyped-def]
    return MonitorTarget(id=kw.pop("id", 1), mac=mac, **kw)


def _offline(mac: str = PC_MAC, since: float = T0, **kw) -> MonitorTarget:  # type: ignore[no-untyped-def]
    return _target(mac, status="offline", status_since=iso_from_ts(since), down_since=iso_from_ts(since), **kw)


def _check(**kw) -> ServiceCheck:  # type: ignore[no-untyped-def]
    base = {"id": 11, "target_id": 1, "kind": "smb", "port": 445}
    base.update(kw)
    return ServiceCheck(**base)


def _down(since: float = T0, **kw) -> ServiceCheck:  # type: ignore[no-untyped-def]
    return _check(status="down", status_since=iso_from_ts(since), down_since=iso_from_ts(since),
                  last_detail=kw.pop("last_detail", "Port geschlossen"), **kw)  # fmt: skip


def _active(env, rule: str | None = None) -> list:  # type: ignore[no-untyped-def]
    return [a for a in env.store.list() if rule is None or a.rule == rule]


def _seed(env, device: Device) -> Device:  # type: ignore[no-untyped-def]
    inv = Inventory(env.db)
    scan_id = inv.begin_scan("scan", "Ethernet", "192.168.178.0/24")
    inv.record_seen(device, scan_id)
    inv.finish_scan(scan_id, "completed", 1)
    stored = inv.get(device.mac)
    assert stored is not None
    return stored


# --- device_offline -------------------------------------------------------------------------------


def test_offline_opens_exactly_at_threshold(env) -> None:  # type: ignore[no-untyped-def]
    target = _offline(last_detail="keine Antwort")
    env.engine.evaluate_target(target, _pc(), T0 + 299)  # Standard 5 Minuten: knapp darunter
    assert _active(env) == []
    env.engine.evaluate_target(target, _pc(), T0 + 300)
    [alert] = _active(env)
    assert alert.rule == "device_offline" and alert.key == f"device_offline:{PC_MAC}"
    assert alert.severity == "warning" and alert.mac == PC_MAC and alert.target_id == 1
    assert alert.opened == iso_from_ts(T0 + 300)
    assert alert.title == "buero-pc ist offline"
    assert PC_IP in alert.message and "5 Minuten" in alert.message and "keine Antwort" in alert.message
    assert _events(env, "alert.opened")[0]["alert"]["id"] == alert.id


def test_offline_is_idempotent(env) -> None:  # type: ignore[no-untyped-def]
    target = _offline()
    for i in range(5):
        env.engine.evaluate_target(target, _pc(), T0 + 300 + 60 * i)
    assert len(_active(env)) == 1 and len(_events(env, "alert.opened")) == 1


def test_offline_threshold_from_target_and_settings(env) -> None:  # type: ignore[no-untyped-def]
    env.engine.evaluate_target(_offline(offline_after_min=10), _pc(), T0 + 599)
    assert _active(env) == []
    env.engine.evaluate_target(_offline(offline_after_min=10), _pc(), T0 + 600)
    assert len(_active(env)) == 1
    env.settings.update(alert_offline_minutes=2)
    nas = _offline(NAS_MAC, id=2)
    env.engine.evaluate_target(nas, _nas(), T0 + 119)
    assert len(_active(env)) == 1
    env.engine.evaluate_target(nas, _nas(), T0 + 120)
    assert len(_active(env)) == 2


@pytest.mark.parametrize(
    ("device", "severity"),
    [
        (Device(mac=PC_MAC, ip="192.168.178.1", is_gateway=True), "critical"),
        (Device(mac=PC_MAC, ip=PC_IP, category="router"), "critical"),
        (Device(mac=PC_MAC, ip=PC_IP, category="server"), "critical"),
        (Device(mac=PC_MAC, ip=PC_IP, category="printer"), "warning"),
        (None, "warning"),
    ],
)
def test_offline_severity(env, device, severity) -> None:  # type: ignore[no-untyped-def]
    env.engine.evaluate_target(_offline(), device, T0 + 300)
    assert _active(env)[0].severity == severity


def test_offline_without_device_uses_mac(env) -> None:  # type: ignore[no-untyped-def]
    env.engine.evaluate_target(_offline(), None, T0 + 300)
    alert = _active(env)[0]
    assert alert.title == f"{PC_MAC} ist offline" and PC_MAC in alert.message


def test_offline_closes_when_online_or_degraded(env) -> None:  # type: ignore[no-untyped-def]
    for status in ("online", "degraded"):
        env.engine.evaluate_target(_offline(), _pc(), T0 + 300)
        assert len(_active(env)) == 1
        env.engine.evaluate_target(_target(status=status), _pc(), T0 + 360)
        assert _active(env) == []
    closed = _events(env, "alert.closed")
    assert len(closed) == 2 and closed[0]["alert"]["closed"] == iso_from_ts(T0 + 360)


@pytest.mark.parametrize("status", ["paused", "unknown"])
def test_offline_unchanged_while_paused_or_unknown(env, status) -> None:  # type: ignore[no-untyped-def]
    env.engine.evaluate_target(_offline(), _pc(), T0 + 300)
    env.engine.evaluate_target(_target(status=status, pause_code="blocked" if status == "paused" else None), _pc(), T0 + 360)
    assert len(_active(env, "device_offline")) == 1
    # Pause ohne bestehenden Alert öffnet auch keinen
    env.engine.evaluate_target(_target(NAS_MAC, id=2, status=status, down_since=iso_from_ts(T0)), _nas(), T0 + 9999)
    assert len(_active(env, "device_offline")) == 1


def test_offline_falls_back_to_status_since_and_ignores_garbage(env) -> None:  # type: ignore[no-untyped-def]
    t = _target(status="offline", status_since=iso_from_ts(T0), down_since=None)
    env.engine.evaluate_target(t, _pc(), T0 + 300)
    assert len(_active(env)) == 1
    t2 = _target(NAS_MAC, id=2, status="offline", status_since="kaputt", down_since="auch kaputt")
    env.engine.evaluate_target(t2, _nas(), T0 + 99999)
    assert len(_active(env)) == 1


def test_disabled_target_closes_its_alerts(env) -> None:  # type: ignore[no-untyped-def]
    env.engine.evaluate_target(_offline(), _pc(), T0 + 300)
    env.engine.evaluate_target(_offline(enabled=False), _pc(), T0 + 9999)
    assert _active(env) == []


# --- rtt_high -------------------------------------------------------------------------------------


def _slow(since: float = T0, **kw) -> MonitorTarget:  # type: ignore[no-untyped-def]
    return _target(status="degraded", rtt_threshold_ms=kw.pop("rtt_threshold_ms", 50.0),
                   rtt_high_since=iso_from_ts(since), last_rtt_ms=kw.pop("last_rtt_ms", 80.5), **kw)  # fmt: skip


def test_rtt_high_threshold_and_text(env) -> None:  # type: ignore[no-untyped-def]
    env.engine.evaluate_target(_slow(), _pc(), T0 + 299)
    assert _active(env) == []
    env.engine.evaluate_target(_slow(), _pc(), T0 + 300)
    [alert] = _active(env)
    assert alert.rule == "rtt_high" and alert.key == f"rtt_high:{PC_MAC}" and alert.severity == "info"
    assert "buero-pc" in alert.title and PC_IP in alert.message
    assert "50 ms" in alert.message and "80,5 ms" in alert.message
    assert _active(env, "device_offline") == []  # degraded ist kein Ausfall


def test_rtt_high_minutes_from_settings(env) -> None:  # type: ignore[no-untyped-def]
    env.settings.update(alert_rtt_minutes=1)
    env.engine.evaluate_target(_slow(), _pc(), T0 + 59)
    assert _active(env) == []
    env.engine.evaluate_target(_slow(), _pc(), T0 + 60)
    assert len(_active(env, "rtt_high")) == 1


def test_rtt_high_closes_when_below_or_rule_off(env) -> None:  # type: ignore[no-untyped-def]
    env.engine.evaluate_target(_slow(), _pc(), T0 + 300)
    env.engine.evaluate_target(_target(status="online", rtt_threshold_ms=50.0, rtt_high_since=None), _pc(), T0 + 360)
    assert _active(env) == []
    env.engine.evaluate_target(_slow(), _pc(), T0 + 400)
    assert len(_active(env)) == 1
    # Schwellwert entfernt (Regel aus) ⇒ Alert endet, auch wenn rtt_high_since noch gesetzt wäre
    env.engine.evaluate_target(_slow(rtt_threshold_ms=None), _pc(), T0 + 460)
    assert _active(env) == []
    # Gerät offline ⇒ rtt_high_since leer ⇒ Alert endet
    env.engine.evaluate_target(_slow(), _pc(), T0 + 500)
    env.engine.evaluate_target(_offline(since=T0 + 520), _pc(), T0 + 540)
    assert _active(env, "rtt_high") == []


# --- service_down ---------------------------------------------------------------------------------


def test_service_down_threshold_and_text(env) -> None:  # type: ignore[no-untyped-def]
    target = _target(NAS_MAC, status="degraded")
    check = _down()
    env.engine.evaluate_check(target, check, _nas(), T0 + 119)  # Standard 2 Minuten
    assert _active(env) == []
    env.engine.evaluate_check(target, check, _nas(), T0 + 120)
    [alert] = _active(env)
    assert alert.rule == "service_down" and alert.key == "service_down:11" and alert.severity == "warning"
    assert alert.check_id == 11 and alert.target_id == 1 and alert.mac == NAS_MAC
    assert alert.title == "SMB-Freigabe 445 auf nas ausgefallen"
    assert NAS_IP in alert.message and "Port geschlossen" in alert.message
    assert "Das Gerät selbst ist erreichbar." in alert.message
    env.engine.evaluate_check(target, check, _nas(), T0 + 180)
    assert len(_events(env, "alert.opened")) == 1  # idempotent


def test_service_down_minutes_from_settings(env) -> None:  # type: ignore[no-untyped-def]
    env.settings.update(alert_service_minutes=5)
    target = _target(NAS_MAC, status="degraded")
    env.engine.evaluate_check(target, _down(), _nas(), T0 + 299)
    assert _active(env) == []
    env.engine.evaluate_check(target, _down(), _nas(), T0 + 300)
    assert len(_active(env)) == 1


@pytest.mark.parametrize("change", ["up", "unknown", "check_off", "target_off"])
def test_service_down_closes(env, change) -> None:  # type: ignore[no-untyped-def]
    target = _target(NAS_MAC, status="degraded")
    env.engine.evaluate_check(target, _down(), _nas(), T0 + 120)
    assert len(_active(env)) == 1
    if change in ("up", "unknown"):
        env.engine.evaluate_check(target, _check(status=change), _nas(), T0 + 180)
    elif change == "check_off":
        env.engine.evaluate_check(target, _down(enabled=False), _nas(), T0 + 180)
    else:
        env.engine.evaluate_check(_target(NAS_MAC, status="degraded", enabled=False), _down(), _nas(), T0 + 180)
    assert _active(env) == []


def test_service_down_http_label_with_path_and_without_device(env) -> None:  # type: ignore[no-untyped-def]
    check = _down(id=12, kind="http", port=5000, path="/status", last_detail="HTTP 503")
    env.engine.evaluate_check(_target(NAS_MAC, status="offline"), check, None, T0 + 120)
    [alert] = _active(env)
    assert alert.title == f"HTTP 5000 /status auf {NAS_MAC} ausgefallen"
    assert "HTTP 503" in alert.message and "erreichbar" not in alert.message


# --- Ziel/Prüfung entfernt ------------------------------------------------------------------------


def test_on_target_removed_closes_state_alerts_only(env) -> None:  # type: ignore[no-untyped-def]
    target = _target(NAS_MAC, status="offline", down_since=iso_from_ts(T0), rtt_threshold_ms=10.0,
                     checks=[_check(id=11)])  # fmt: skip
    env.engine.evaluate_target(target, _nas(), T0 + 300)
    env.engine.evaluate_check(target, _down(id=11), _nas(), T0 + 300)
    # Dienst-Alert einer Prüfung, die im Ziel-Objekt schon fehlt (nur über target_id auffindbar)
    env.store.open(rule="service_down", key="service_down:12", severity="warning", title="x", message="",
                   mac=NAS_MAC, target_id=1, check_id=12)  # fmt: skip
    env.store.open(rule="rtt_high", key=f"rtt_high:{NAS_MAC}", severity="info", title="x", message="", mac=NAS_MAC, target_id=1)
    env.store.open(rule="new_port", key=f"new_port:{NAS_MAC}:22", severity="info", title="x", message="", mac=NAS_MAC)
    other = env.store.open(rule="device_offline", key=f"device_offline:{PC_MAC}", severity="warning", title="y",
                           message="", mac=PC_MAC, target_id=2)  # fmt: skip
    assert len(_active(env)) == 6
    env.engine.on_target_removed(target)
    remaining = {a.key for a in _active(env)}
    assert remaining == {f"new_port:{NAS_MAC}:22", other.key}  # Ereignis-Alerts enden nur mit Quittieren


def test_on_check_removed(env) -> None:  # type: ignore[no-untyped-def]
    target = _target(NAS_MAC, status="degraded")
    env.engine.evaluate_check(target, _down(id=11), _nas(), T0 + 120)
    env.engine.evaluate_check(target, _down(id=12, port=139), _nas(), T0 + 120)
    env.engine.on_check_removed(target, _check(id=11))
    assert [a.key for a in _active(env)] == ["service_down:12"]


# --- new_device -----------------------------------------------------------------------------------


def _outcome(kind: str = "scan", **kw) -> ScanOutcome:  # type: ignore[no-untyped-def]
    return ScanOutcome(scan_id=kw.pop("scan_id", 3), kind=kind, adapter=make_adapter(), **kw)


def test_new_device_alert(env) -> None:  # type: ignore[no-untyped-def]
    phone = Device(mac="7a:11:22:33:44:55", ip="192.168.178.40", vendor=None, mac_random=True, category="phone")
    known = Device(mac="00:1b:21:aa:bb:99", ip="192.168.178.41", known=True)
    plug = Device(mac="24:0a:c4:00:00:07", ip="192.168.178.42", vendor="Espressif Inc.")
    env.engine.on_scan(_outcome(new_devices=[phone, known, plug]))
    alerts = {a.mac: a for a in _active(env)}
    assert set(alerts) == {phone.mac, plug.mac}
    a = alerts[plug.mac]
    assert a.rule == "new_device" and a.key == f"new_device:{plug.mac}" and a.severity == "warning"
    assert a.title == "Neues Gerät: Espressif Inc." and "192.168.178.42" in a.message
    assert "192.168.178.0/24" in a.message and plug.mac in a.message and "Hersteller Espressif Inc." in a.message
    assert "private (zufällige) Adresse" in alerts[phone.mac].message
    env.engine.on_scan(_outcome(new_devices=[phone, plug]))  # gleicher Stand noch einmal
    assert len(_events(env, "alert.opened")) == 2


def test_new_device_only_after_normal_scan_and_when_enabled(env) -> None:  # type: ignore[no-untyped-def]
    dev = Device(mac="24:0a:c4:00:00:07", ip="192.168.178.42")
    env.engine.on_scan(_outcome("deep_scan", new_devices=[dev]))
    assert _active(env) == []
    env.settings.update(alert_new_device=False)
    env.engine.on_scan(_outcome(new_devices=[dev]))
    assert _active(env) == []
    env.settings.update(alert_new_device=True)
    env.engine.on_scan(_outcome(new_devices=[dev]))
    assert len(_active(env)) == 1


# --- new_port -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("risk", "severity", "label"),
    [("low", "info", "niedrig"), ("medium", "warning", "mittel"), ("high", "critical", "hoch"), ("critical", "critical", "kritisch")],
)
def test_new_port_severity_from_risk(env, risk, severity, label) -> None:  # type: ignore[no-untyped-def]
    _seed(env, _nas())
    port = PortResult(8080, service="http-alt", risk=risk, reason="Weboberfläche ohne TLS")
    env.engine.on_scan(_outcome(new_ports={NAS_MAC: [port]}))
    [alert] = _active(env)
    assert alert.rule == "new_port" and alert.key == f"new_port:{NAS_MAC}:8080" and alert.severity == severity
    assert alert.title == "Neuer offener Port 8080 auf nas"
    assert NAS_IP in alert.message and "http-alt" in alert.message and f"Risiko: {label}." in alert.message
    assert "Weboberfläche ohne TLS" in alert.message and SELF_FIREWALL_HINT not in alert.message


def test_new_port_on_own_pc_has_firewall_hint(env) -> None:  # type: ignore[no-untyped-def]
    _seed(env, Device(mac=SELF_MAC, ip=SELF_IP, hostname="mein-pc", is_self=True, category="pc"))
    env.engine.on_scan(_outcome(new_ports={SELF_MAC.upper(): [PortResult(5000, service="http", risk="medium")]}))
    [alert] = _active(env)
    assert alert.message.endswith(
        "Eigener PC: lokal geprüft – die Windows-Firewall wird dabei nicht berücksichtigt; "
        "von anderen Geräten aus kann der Port gesperrt sein."
    )
    assert alert.mac == SELF_MAC and "mein-pc" in alert.title


def test_new_port_skips_new_devices_and_respects_setting(env) -> None:  # type: ignore[no-untyped-def]
    _seed(env, _nas())
    fresh = Device(mac=PC_MAC, ip=PC_IP)
    outcome = _outcome(new_devices=[fresh], new_ports={PC_MAC: [PortResult(22, service="ssh", risk="medium")],
                                                       NAS_MAC: [PortResult(22, service="ssh", risk="medium")]})  # fmt: skip
    env.settings.update(alert_new_port=False, alert_new_device=False)
    env.engine.on_scan(outcome)
    assert _active(env) == []
    env.settings.update(alert_new_port=True)
    env.engine.on_scan(outcome)
    assert [a.key for a in _active(env)] == [f"new_port:{NAS_MAC}:22"]  # nicht für das neue Gerät


def test_new_port_after_deep_scan_and_robust_input(env) -> None:  # type: ignore[no-untyped-def]
    ports = [PortResult(21, service="ftp", risk="high"), PortResult(21, service="ftp", risk="high"),
             PortResult(0, service="kaputt"), PortResult(23, service="telnet", risk="sonderbar")]  # fmt: skip
    env.engine.on_scan(_outcome("deep_scan", new_ports={"kein-mac": ports, PC_MAC: ports}))
    alerts = {a.key: a for a in _active(env)}
    assert set(alerts) == {f"new_port:{PC_MAC}:21", f"new_port:{PC_MAC}:23"}
    assert alerts[f"new_port:{PC_MAC}:21"].title == f"Neuer offener Port 21 auf {PC_MAC}"  # Gerät nicht im Inventar
    assert alerts[f"new_port:{PC_MAC}:23"].severity == "warning"  # unbekanntes Risiko ⇒ mittel
    env.engine.on_scan(_outcome("deep_scan", new_ports={PC_MAC: ports}))
    assert len(_events(env, "alert.opened")) == 2  # bis zum Quittieren kein zweiter Alert


# --- Einstellungen aus der Datenbank --------------------------------------------------------------


def test_broken_settings_fall_back_to_defaults(env) -> None:  # type: ignore[no-untyped-def]
    env.db.set_setting("alert_offline_minutes", "fünf")
    env.db.set_setting("alert_service_minutes", 99999)
    env.db.set_setting("alert_new_device", "nein")
    env.engine.evaluate_target(_offline(), _pc(), T0 + 299)
    assert _active(env) == []
    env.engine.evaluate_target(_offline(), _pc(), T0 + 300)  # Standard 5 Minuten
    env.engine.evaluate_check(_target(NAS_MAC, id=2, status="degraded"), _down(), _nas(), T0 + 120)  # Standard 2
    env.engine.on_scan(_outcome(new_devices=[Device(mac="24:0a:c4:00:00:07", ip="192.168.178.42")]))  # Standard an
    assert {a.rule for a in _active(env)} == {"device_offline", "service_down", "new_device"}


def test_unreadable_settings_store_uses_defaults(env) -> None:  # type: ignore[no-untyped-def]
    class Broken:
        def load(self):  # type: ignore[no-untyped-def]
            raise RuntimeError("kaputt")

    engine = AlertEngine(env.store, Broken())  # type: ignore[arg-type]
    engine.evaluate_target(_offline(), _pc(), T0 + 300)
    assert len(_active(env)) == 1
