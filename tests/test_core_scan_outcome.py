"""Scan-Rückmeldung an die Überwachung (BAUPLAN §26): neue Geräte, neu geöffnete Ports, Router des Netzes."""

from __future__ import annotations

from netscan.core.context import ScanContext
from netscan.core.models import ScanRequest
from netscan.scan import pipeline
from tests.test_pipeline_e2e import ROUTER_MAC, lab_env  # noqa: F401 – Fixture

NAS_IP, NAS_MAC = "127.0.0.3", "00:11:32:aa:bb:03"


def _ctx(services) -> ScanContext:  # type: ignore[no-untyped-def]
    return ScanContext(job_id="t", bus=services.bus, settings=services.settings.load(), platform=services.platform)


def _scan(services):  # type: ignore[no-untyped-def]
    return pipeline.run_scan(_ctx(services), ScanRequest(adapter="Ethernet", port_scan=True), services)


def test_first_scan_reports_new_devices_but_no_new_ports(lab_env) -> None:  # noqa: F811
    services, lab, _platform, _arp = lab_env
    seen = []
    services.scan_listeners = [seen.append]
    summary = _scan(services)
    assert len(seen) == 1
    outcome = seen[0]
    assert outcome.kind == "scan" and outcome.scan_id == summary["scan_id"]
    assert outcome.gateway_mac == ROUTER_MAC
    assert outcome.adapter.name == "Ethernet"
    assert NAS_MAC in outcome.seen_macs
    assert {d.mac for d in outcome.new_devices} >= {NAS_MAC}
    assert len(outcome.new_devices) == summary["new"]
    assert outcome.new_ports == {}  # nichts war vorher geprüft


def test_reopened_port_is_reported_once(lab_env) -> None:  # noqa: F811
    services, lab, _platform, _arp = lab_env
    lab.stop_service(NAS_IP, 22)
    _scan(services)  # Port 22 geprüft und geschlossen
    assert 22 in services.inventory.checked_ports(NAS_MAC)
    for d in services.inventory.list_devices():
        services.inventory.update_user_fields(d.mac, known=True)
    lab.start_service(NAS_IP, 22)
    seen = []
    services.scan_listeners = [seen.append]
    _scan(services)
    outcome = seen[-1]
    assert outcome.new_devices == []
    assert [p.port for p in outcome.new_ports.get(NAS_MAC, [])] == [22]
    _scan(services)  # bleibt offen ⇒ nicht noch einmal
    assert seen[-1].new_ports == {}


def test_deep_scan_reports_kind_and_ports(lab_env) -> None:  # noqa: F811
    services, lab, _platform, _arp = lab_env
    lab.stop_service(NAS_IP, 445)
    _scan(services)
    lab.start_service(NAS_IP, 445)
    seen = []
    services.scan_listeners = [seen.append]
    result = pipeline.run_deep_scan(_ctx(services), NAS_MAC, services, "Ethernet")
    assert 445 in result["open_ports"]
    assert seen and seen[-1].kind == "deep_scan" and seen[-1].seen_macs == [NAS_MAC]
    assert [p.port for p in seen[-1].new_ports.get(NAS_MAC, [])] == [445]


def test_listener_error_never_breaks_the_scan(lab_env) -> None:  # noqa: F811
    services, _lab, _platform, _arp = lab_env

    def boom(outcome):  # type: ignore[no-untyped-def]
        raise RuntimeError("kaputt")

    services.scan_listeners = [boom]
    summary = _scan(services)
    assert summary["devices"] >= 6
