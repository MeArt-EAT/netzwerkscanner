"""Export: JSON, CSV und HTML-Bericht (netscan.web.export)."""

from __future__ import annotations

import csv
import io
import json
import re
from html.parser import HTMLParser

import pytest

from netscan.core.models import Device, NameInfo, PortResult, SsdpInfo
from netscan.web import export

META = {
    "program": "Netzwerkscanner",
    "version": "1.0.0-test",
    "exported_at": "2026-10-10T12:30:00+00:00",
    "device_count": 3,
    "last_scan": {"id": 7, "kind": "scan", "adapter": "Ethernet", "network": "192.168.178.0/24",
                  "started": "2026-10-10T12:00:00+00:00", "finished": "2026-10-10T12:02:00+00:00",
                  "result": "completed", "device_count": 3},
}


def make_devices() -> list[Device]:
    router = Device(
        mac="3c:a6:2f:00:00:01", ip="192.168.178.1", vendor="AVM GmbH", hostname="fritz.box",
        names=NameInfo(dns="fritz.box", mdns_services=["_http._tcp"]),
        ssdp=SsdpInfo(friendly_name="FRITZ!Box 7590", manufacturer="AVM", model_name="FRITZ!Box", model_number="7590",
                      device_type="urn:schemas-upnp-org:device:InternetGatewayDevice:1", server="UPnP/1.0",
                      location="http://192.168.178.1:49000/igddesc.xml"),
        category="router", category_reason="Gateway und UPnP-Gateway", is_gateway=True, known=True,
        discovered_by=["arp", "ping"], first_seen="2026-10-01T08:00:00+00:00", last_seen="2026-10-10T12:01:00+00:00",
        ports=[PortResult(80, "tcp", "http", "medium", "Weboberfläche ohne Verschlüsselung", "Server: FRITZ!Box"),
               PortResult(443, "tcp", "https", "low", "Verschlüsselte Weboberfläche")],
    )
    phone = Device(
        mac="ae:11:22:33:44:55", ip="192.168.178.31", vendor=None, mac_random=True, category="phone",
        is_new=True, online=True, first_seen="2026-10-10T12:01:00+00:00", last_seen="2026-10-10T12:01:00+00:00",
    )
    nas = Device(
        mac="00:11:32:aa:bb:cc", ip="192.168.178.40", vendor="Synology Incorporated", custom_name="NAS Keller",
        note="Zeile 1\nZeile 2; mit Semikolon", category="server", category_source="user", online=False,
        first_seen="2026-09-01T08:00:00+00:00", last_seen="2026-10-09T20:00:00+00:00",
        ports=[PortResult(23, "tcp", "telnet", "critical", "Klartext-Anmeldung"),
               PortResult(22, "tcp", "ssh", "medium", "Fernzugriff", "SSH-2.0-OpenSSH_9.6"),
               PortResult(5000, "tcp", "", "high", "Verwaltung")],
    )
    return [router, phone, nas]


# --- JSON ------------------------------------------------------------------------------------


def test_json_aufbau_und_roundtrip():
    devices = make_devices()
    text = export.to_json(devices, META)
    assert text.startswith('{\n  "meta": {')  # eingerückt
    data = json.loads(text)
    assert list(data) == ["meta", "devices"]
    assert data["meta"] == META
    assert len(data["devices"]) == 3
    for entry, original in zip(data["devices"], devices):
        assert entry == original.to_dict()
        assert Device.from_dict(entry).to_dict() == original.to_dict()
    assert data["devices"][0]["display_name"] == "fritz.box"
    assert data["devices"][2]["max_risk"] == "critical"


def test_json_behaelt_umlaute():
    d = Device(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.2", custom_name="Küche – Größe ß")
    text = export.to_json([d], {"titel": "Gerätebericht"})
    assert "Küche – Größe ß" in text and "\\u" not in text


def test_json_leer():
    data = json.loads(export.to_json([], {"device_count": 0}))
    assert data == {"meta": {"device_count": 0}, "devices": []}


# --- CSV -------------------------------------------------------------------------------------


def parse_csv(text: str) -> list[list[str]]:
    assert text.startswith("﻿")
    return list(csv.reader(io.StringIO(text[1:], newline=""), delimiter=";"))


def test_csv_kopf_bom_und_zeilen():
    text = export.to_csv(make_devices())
    assert text.startswith("﻿Name;IP;MAC;Private MAC;Hersteller;Kategorie;Bekannt;Neu;Online;Ports;Höchstes Risiko;Zuerst gesehen;Zuletzt gesehen;Notiz\r\n")
    assert text.encode("utf-8").startswith(b"\xef\xbb\xbf")
    rows = parse_csv(text)
    assert len(rows) == 1 + 3
    assert rows[0] == list(export.CSV_COLUMNS) and len(export.CSV_COLUMNS) == 14
    assert all(len(r) == 14 for r in rows)


def test_csv_inhalt():
    rows = parse_csv(export.to_csv(make_devices()))
    router, phone, nas = rows[1:]
    assert router[:10] == ["fritz.box", "192.168.178.1", "3c:a6:2f:00:00:01", "Nein", "AVM GmbH", "Router", "Ja", "Nein", "Ja", "80/http, 443/https"]
    assert router[10] == "mittel"
    assert router[11:13] == ["2026-10-01T08:00:00+00:00", "2026-10-10T12:01:00+00:00"]
    assert phone[0] == "192.168.178.31"  # kein Name, kein Hersteller ⇒ IP
    assert phone[3] == "Ja" and phone[4] == "" and phone[5] == "Handy" and phone[7] == "Ja"
    assert phone[9] == "" and phone[10] == ""  # keine Ports, kein Risiko
    assert nas[0] == "NAS Keller" and nas[5] == "Server/NAS" and nas[8] == "Nein"
    assert nas[9] == "22/ssh, 23/telnet, 5000/tcp"  # nach Port sortiert, ohne Dienstnamen „Port/tcp“
    assert nas[10] == "kritisch"
    assert nas[13] == "Zeile 1\nZeile 2; mit Semikolon"


def test_csv_alle_risikostufen_und_kategorien_deutsch():
    devices = [Device(mac=f"aa:bb:cc:00:00:{i:02x}", ip=f"10.0.0.{i}", category=cat, ports=[PortResult(80, risk=risk)])
               for i, (cat, risk) in enumerate([("router", "low"), ("switch", "medium"), ("printer", "high"), ("iot", "critical")], start=1)]
    rows = parse_csv(export.to_csv(devices))[1:]
    assert [r[5] for r in rows] == ["Router", "Switch", "Drucker", "IoT-Gerät"]
    assert [r[10] for r in rows] == ["niedrig", "mittel", "hoch", "kritisch"]


def test_csv_leer_hat_nur_kopf():
    rows = parse_csv(export.to_csv([]))
    assert rows == [list(export.CSV_COLUMNS)]


@pytest.mark.parametrize("gefaehrlich", ["=1+1", "+49 123", "-2+3", "@SUMME(A1)", "\t=cmd", "=HYPERLINK(\"http://evil\",\"x\")"])
def test_csv_formeln_werden_entschaerft(gefaehrlich):
    d = Device(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.2", custom_name=gefaehrlich, vendor=gefaehrlich, note=gefaehrlich)
    row = parse_csv(export.to_csv([d]))[1]
    for idx in (0, 4, 13):
        assert row[idx] == "'" + gefaehrlich
    assert not row[0].startswith(("=", "+", "-", "@"))


def test_csv_normale_texte_bleiben_unveraendert():
    d = Device(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.2", custom_name="Drucker-1 (oben)", note="a-b, c=d")
    row = parse_csv(export.to_csv([d]))[1]
    assert row[0] == "Drucker-1 (oben)" and row[13] == "a-b, c=d"


# --- HTML ------------------------------------------------------------------------------------


class Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[str] = []
        self.text: list[str] = []
        self.attrs: list[tuple[str, str, str | None]] = []

    def handle_starttag(self, tag, attrs):  # type: ignore[no-untyped-def]
        self.tags.append(tag)
        for k, v in attrs:
            self.attrs.append((tag, k, v))

    def handle_data(self, data):  # type: ignore[no-untyped-def]
        self.text.append(data)


def parse_html(text: str) -> Collector:
    c = Collector()
    c.feed(text)
    return c


def test_html_grundgeruest():
    html = export.to_html(make_devices(), META)
    assert html.startswith("<!DOCTYPE html>")
    assert '<html lang="de">' in html and '<meta charset="utf-8">' in html
    assert "<title>Netzwerkscanner – Gerätebericht</title>" in html
    assert "<h1>Netzwerkscanner – Gerätebericht</h1>" in html
    assert "Anzahl Geräte: 3" in html
    assert "Erstellt:" in html and "10.10.2026" in html
    assert "Letzter Scan:" in html and "192.168.178.0/24" in html
    assert "<style>" in html


def test_html_ohne_skripte_ohne_externe_adressen():
    html = export.to_html(make_devices(), META)
    parsed = parse_html(html)
    assert "script" not in parsed.tags
    assert "link" not in parsed.tags and "img" not in parsed.tags and "iframe" not in parsed.tags
    assert not any(k.startswith("on") for _, k, _ in parsed.attrs)  # keine Ereignis-Attribute
    for tag, key, value in parsed.attrs:
        if key in ("href", "src"):
            assert (value or "").startswith("#"), (tag, key, value)  # nur Sprungmarken im Dokument
    assert "http://" not in re.sub(r"http://192\.168\.178\.1:49000/igddesc\.xml", "", html)  # UPnP-Adresse nur als Text
    assert "<script" not in html.lower() and "javascript:" not in html.lower()
    assert "Content-Security-Policy" in html


def test_html_alle_geraete_und_ports():
    devices = make_devices()
    html = export.to_html(devices, META)
    for d in devices:
        assert d.mac in html and d.ip in html
    for needle in ("80/tcp", "443/tcp", "23/tcp", "22/tcp", "5000/tcp", "http", "telnet", "ssh",
                   "Weboberfläche ohne Verschlüsselung", "Klartext-Anmeldung", "Fernzugriff", "SSH-2.0-OpenSSH_9.6"):
        assert needle in html, needle
    # Risikostufen als Text und als Farbklasse
    for label, css in (("niedrig", "risk-low"), ("mittel", "risk-medium"), ("hoch", "risk-high"), ("kritisch", "risk-critical")):
        assert f'<span class="risk {css}">{label}</span>' in html, label
    assert ".risk-critical" in html  # Farbe steht im eingebetteten CSS
    assert html.count('<section class="device"') == 3


def test_html_geraetedetails():
    html = export.to_html(make_devices(), META)
    assert "FRITZ!Box 7590" in html and "UPnP-Hersteller" in html
    assert "private, zufällige Adresse" in html
    assert "vom Nutzer festgelegt" in html
    assert "NAS Keller" in html and "Zeile 1\nZeile 2; mit Semikolon" in html
    assert "Router (Standard-Gateway)" in html
    assert '<span class="badge new">neu</span>' in html and '<span class="badge offline">offline</span>' in html
    assert "Keine offenen Ports bekannt." in html  # Handy ohne Ports
    # Sprungmarken aus der Übersicht treffen vorhandene IDs
    parsed = parse_html(html)
    ids = {v for _, k, v in parsed.attrs if k == "id"}
    links = {v[1:] for t, k, v in parsed.attrs if t == "a" and k == "href"}
    assert links and links <= ids


def test_html_port_scan_ausgenommen():
    d = Device(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.2", port_scan_excluded=True)
    assert "Vom Port-Scan ausgenommen." in export.to_html([d], META)


def test_html_maskiert_sonderzeichen():
    boese = '<script>alert(1)</script>'
    d = Device(
        mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.2", vendor='Fa. "Müller" & <Söhne>', custom_name="<img src=x onerror=alert(1)>",
        hostname=boese, note=f"Notiz {boese}", category_reason="<b>fett</b>",
        names=NameInfo(dns=boese, netbios="'><svg onload=alert(1)>", mdns_services=["<i>"]),
        ssdp=SsdpInfo(friendly_name=boese, location="javascript:alert(1)", server="</style><script>x</script>"),
        discovered_by=["<arp>"],
        ports=[PortResult(8080, "tcp", "<http>", "high", 'Grund "A" & <B>', banner=boese)],
    )
    html = export.to_html([d], {"exported_at": "<kaputt>", "device_count": "<1>", "version": "<v>",
                                "last_scan": {"network": "<n>", "adapter": "\"a\"", "device_count": 1, "started": "<t>"}})
    assert "<script" not in html.lower()
    assert "<img" not in html and "<svg" not in html and "<b>" not in html and "<i>" not in html
    assert "onerror=alert(1)>" not in html  # nur in maskierter Form (&lt;img … onerror=…&gt;)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
    assert "Fa. &quot;Müller&quot; &amp; &lt;Söhne&gt;" in html
    assert "Grund &quot;A&quot; &amp; &lt;B&gt;" in html
    assert "&lt;kaputt&gt;" in html and "&lt;1&gt;" in html and "&lt;v&gt;" in html and "&lt;n&gt;" in html
    parsed = parse_html(html)
    assert "script" not in parsed.tags and "img" not in parsed.tags and "svg" not in parsed.tags
    assert not any(k.startswith("on") for _, k, _ in parsed.attrs)


def test_html_id_aus_unsinniger_mac_bleibt_gueltig():
    d = Device(mac='aa:"><x', ip="10.0.0.2")
    html = export.to_html([d], META)
    ids = [v for _, k, v in parse_html(html).attrs if k == "id"]
    assert ids and all(re.fullmatch(r"dev-[0-9a-z-]+", i) for i in ids)


def test_html_ohne_geraete_und_ohne_meta():
    html = export.to_html([], {})
    assert "Keine Geräte im Inventar." in html
    assert "Anzahl Geräte: 0" in html
    assert "Letzter Scan: noch keiner abgeschlossen" in html
    assert "Erstellt: –" in html


def test_html_unlesbarer_zeitstempel_bleibt_text():
    d = Device(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.2", first_seen="gestern", last_seen="")
    html = export.to_html([d], META)
    assert "gestern" in html
