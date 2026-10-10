"""Export als JSON, CSV und HTML-Bericht. Siehe BAUPLAN §14. (Agent api)

Alle drei Formate enthalten alle Geräte mit allen Ports. Die Funktionen liefern nur Text –
geschrieben wird nichts (der Server reicht den Text als Download weiter).
"""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime
from html import escape
from typing import Any

from netscan.core.models import CATEGORY_LABELS, RISK_LABELS, Device, PortResult

CSV_COLUMNS: tuple[str, ...] = (
    "Name",
    "IP",
    "MAC",
    "Private MAC",
    "Hersteller",
    "Kategorie",
    "Bekannt",
    "Neu",
    "Online",
    "Ports",
    "Höchstes Risiko",
    "Zuerst gesehen",
    "Zuletzt gesehen",
    "Notiz",
)

# Zeichen, mit denen Excel einen Zellinhalt als Formel liest (CSV-Injection)
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")
# Formelzeichen hinter Komma, Semikolon oder Zeilenumbruch im Freitext: Liest jemand die Datei mit Komma als
# Trennzeichen (englisches Excel, Importdialog), beginnt dort eine neue Zelle – auch trotz Anführungszeichen,
# denn nach dem ersten Feld einer Zeile laufen die Felder im Leser ineinander. Dann ein ' davor setzen.
_FORMULA_AFTER_SEPARATOR = re.compile(r"""([,;\r\n][ \t"']*)(?=[=+\-@])""")


# --- JSON -----------------------------------------------------------------------------------


def to_json(devices: list[Device], meta: dict[str, Any]) -> str:
    """{"meta": {...}, "devices": [Device.to_dict()]}, eingerückt, ensure_ascii=False."""
    payload = {"meta": meta, "devices": [d.to_dict() for d in devices]}
    return json.dumps(payload, indent=2, ensure_ascii=False, default=str)


# --- CSV ------------------------------------------------------------------------------------


def _yes_no(value: bool) -> str:
    return "Ja" if value else "Nein"


def _csv_text(value: str | None) -> str:
    """Freitext für Excel entschärfen: ein führendes = + - @ würde als Formel ausgeführt – ebenso eines direkt
    hinter einem Komma, Semikolon oder Zeilenumbruch, wenn die Datei mit anderem Trennzeichen geöffnet wird."""
    text = value or ""
    if not text:
        return text
    text = _FORMULA_AFTER_SEPARATOR.sub(lambda m: m.group(1) + "'", text)
    if text[0] in _FORMULA_START:
        return "'" + text
    return text


def _port_text(port: PortResult) -> str:
    return f"{port.port}/{port.service or port.proto}"


def to_csv(devices: list[Device]) -> str:
    """Semikolon-getrennt, beginnt mit BOM (\\ufeff) für Excel. Eine Zeile je Gerät, Ports als „22/ssh, 80/http“.

    Jedes Datenfeld steht in Anführungszeichen (QUOTE_ALL): Öffnet jemand die Datei mit Komma als Trennzeichen
    (englisches Excel, Importdialog), bleibt „TV,=HYPERLINK(…)“ trotzdem eine Zelle und wird keine Formel.
    Die feste Kopfzeile enthält keine Fremddaten und bleibt ohne Anführungszeichen.
    """
    buf = io.StringIO(newline="")
    buf.write("﻿")
    csv.writer(buf, delimiter=";", quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n").writerow(CSV_COLUMNS)
    writer = csv.writer(buf, delimiter=";", quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    for d in devices:
        ports = sorted(d.ports, key=lambda p: (p.proto, p.port))
        risk = d.max_risk
        writer.writerow(
            [
                _csv_text(d.display_name),
                d.ip,
                d.mac,
                _yes_no(d.mac_random),
                _csv_text(d.vendor),
                CATEGORY_LABELS.get(d.category, d.category),
                _yes_no(d.known),
                _yes_no(d.is_new),
                _yes_no(d.online),
                _csv_text(", ".join(_port_text(p) for p in ports)),
                RISK_LABELS.get(risk, risk) if risk else "",
                d.first_seen,
                d.last_seen,
                _csv_text(d.note),
            ]
        )
    return buf.getvalue()


# --- HTML -----------------------------------------------------------------------------------

_CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { margin: 0; padding: 24px; font: 14px/1.45 "Segoe UI", system-ui, -apple-system, Arial, sans-serif; color: #1b2330; background: #f4f6f9; }
main, header, footer { max-width: 1100px; margin: 0 auto; }
h1 { font-size: 24px; margin: 0 0 4px; }
h2 { font-size: 18px; margin: 28px 0 10px; border-bottom: 2px solid #c9d1dc; padding-bottom: 4px; }
h3 { font-size: 16px; margin: 0 0 6px; }
.meta { color: #4a5668; margin: 2px 0; }
table { width: 100%; border-collapse: collapse; background: #fff; }
th, td { text-align: left; padding: 6px 8px; border: 1px solid #c9d1dc; vertical-align: top; }
th { background: #e6ebf2; font-weight: 600; }
td.num, th.num { text-align: right; }
code, .mono { font-family: Consolas, "Courier New", monospace; font-size: 13px; }
a { color: #14508c; }
section.device { background: #fff; border: 1px solid #c9d1dc; border-radius: 6px; padding: 12px 14px; margin: 14px 0; break-inside: avoid; }
dl { display: grid; grid-template-columns: max-content 1fr; gap: 2px 14px; margin: 8px 0; }
dt { color: #4a5668; }
dd { margin: 0; overflow-wrap: anywhere; }
.badge { display: inline-block; padding: 1px 7px; border-radius: 10px; border: 1px solid #7b8798; font-size: 12px; font-weight: 600; background: #fff; white-space: nowrap; }
.badge.new { border-color: #b26a00; background: #fff2d6; }
.badge.offline { color: #5a6577; }
.risk { display: inline-block; padding: 1px 8px; border-radius: 4px; border: 1px solid; font-weight: 700; font-size: 12px; white-space: nowrap; }
.risk-low { background: #dff3e4; border-color: #2e7d46; color: #14532d; }
.risk-medium { background: #fff1c2; border-color: #a77b00; color: #5c4400; }
.risk-high { background: #ffd9b8; border-color: #c25400; color: #6b2e00; }
.risk-critical { background: #ffc9c9; border-color: #b00020; color: #6e0014; }
.risk-unknown { background: #eceff3; border-color: #7b8798; color: #2b3442; }
.note { white-space: pre-wrap; background: #f4f6f9; border-left: 3px solid #c9d1dc; padding: 4px 8px; margin: 8px 0; }
.empty { color: #5a6577; font-style: italic; }
footer { margin-top: 28px; color: #5a6577; font-size: 12px; }
@media print {
  body { background: #fff; padding: 0; }
  section.device { border-color: #888; }
  .risk, .badge { border-width: 2px; }
}
""".strip()

_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:"


def _e(value: Any) -> str:
    """HTML-maskieren (auch Anführungszeichen). None wird zu leerem Text."""
    return escape("" if value is None else str(value), quote=True)


def _fmt_time(value: Any) -> str:
    """ISO-Zeitstempel als „10.10.2026 14:30 Uhr“ (Ortszeit); unlesbare Werte bleiben unverändert."""
    if not value:
        return "–"
    text = str(value)
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return text
    if moment.tzinfo is not None:
        moment = moment.astimezone()
    return moment.strftime("%d.%m.%Y %H:%M") + " Uhr"


def _anchor_id(mac: str) -> str:
    return "dev-" + re.sub(r"[^0-9a-z]+", "-", str(mac).lower())


def _risk_badge(risk: str | None) -> str:
    if not risk:
        return "–"
    css = f"risk-{risk}" if risk in RISK_LABELS else "risk-unknown"
    return f'<span class="risk {css}">{_e(RISK_LABELS.get(risk, risk))}</span>'


def _status_badges(d: Device) -> str:
    parts = ['<span class="badge">online</span>' if d.online else '<span class="badge offline">offline</span>']
    if d.is_new:
        parts.append('<span class="badge new">neu</span>')
    if d.known:
        parts.append('<span class="badge">bekannt</span>')
    return " ".join(parts)


def _dl_row(label: str, value_html: str) -> str:
    return f"<dt>{_e(label)}</dt><dd>{value_html}</dd>"


def _device_details(d: Device) -> str:
    rows: list[str] = [
        _dl_row("IP-Adresse", f'<span class="mono">{_e(d.ip)}</span>'),
        _dl_row(
            "MAC-Adresse",
            f'<span class="mono">{_e(d.mac)}</span>' + (" (private, zufällige Adresse)" if d.mac_random else ""),
        ),
        _dl_row("Hersteller", _e(d.vendor) if d.vendor else "unbekannt"),
        _dl_row(
            "Kategorie",
            _e(CATEGORY_LABELS.get(d.category, d.category))
            + (" (vom Nutzer festgelegt)" if d.category_source == "user" else "")
            + (f" – {_e(d.category_reason)}" if d.category_reason else ""),
        ),
    ]
    if d.custom_name:
        rows.append(_dl_row("Eigener Name", _e(d.custom_name)))
    if d.names.dns:
        rows.append(_dl_row("DNS-Name", _e(d.names.dns)))
    if d.names.mdns:
        rows.append(_dl_row("mDNS-Name", _e(d.names.mdns)))
    if d.names.netbios:
        rows.append(_dl_row("NetBIOS-Name", _e(d.names.netbios)))
    if d.names.mdns_services:
        rows.append(_dl_row("mDNS-Dienste", _e(", ".join(d.names.mdns_services))))
    if d.hostname and d.hostname not in (d.names.dns, d.names.mdns, d.names.netbios):
        rows.append(_dl_row("Hostname", _e(d.hostname)))
    if d.ssdp:
        for label, value in (
            ("UPnP-Name", d.ssdp.friendly_name),
            ("UPnP-Hersteller", d.ssdp.manufacturer),
            ("UPnP-Modell", " ".join(x for x in (d.ssdp.model_name, d.ssdp.model_number) if x)),
            ("UPnP-Typ", d.ssdp.device_type),
            ("UPnP-Server", d.ssdp.server),
            ("UPnP-Beschreibung", d.ssdp.location),
        ):
            if value:
                rows.append(_dl_row(label, _e(value)))
    rows.append(_dl_row("Status", _status_badges(d)))
    if d.is_gateway:
        rows.append(_dl_row("Rolle", "Router (Standard-Gateway)"))
    if d.is_self:
        rows.append(_dl_row("Rolle", "dieser PC"))
    if d.discovered_by:
        rows.append(_dl_row("Gefunden per", _e(", ".join(d.discovered_by))))
    rows.append(_dl_row("Zuerst gesehen", _e(_fmt_time(d.first_seen))))
    rows.append(_dl_row("Zuletzt gesehen", _e(_fmt_time(d.last_seen))))
    return "<dl>" + "".join(rows) + "</dl>"


def _ports_table(d: Device) -> str:
    if not d.ports:
        if d.port_scan_excluded:
            return '<p class="empty">Vom Port-Scan ausgenommen.</p>'
        return '<p class="empty">Keine offenen Ports bekannt.</p>'
    body: list[str] = []
    for p in sorted(d.ports, key=lambda x: (x.proto, x.port)):
        banner = f'<span class="mono">{_e(p.banner)}</span>' if p.banner else "–"
        body.append(
            "<tr>"
            f'<td class="num"><span class="mono">{_e(p.port)}/{_e(p.proto)}</span></td>'
            f"<td>{_e(p.service) or '–'}</td>"
            f"<td>{_risk_badge(p.risk)}</td>"
            f"<td>{_e(p.reason) or '–'}</td>"
            f"<td>{banner}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>Port</th><th>Dienst</th><th>Risiko</th><th>Begründung</th><th>Kennung</th></tr></thead>"
        f"<tbody>{''.join(body)}</tbody></table>"
    )


def _device_section(d: Device) -> str:
    note = f'<div class="note">{_e(d.note)}</div>' if d.note else ""
    return (
        f'<section class="device" id="{_e(_anchor_id(d.mac))}">'
        f"<h3>{_e(d.display_name)}</h3>"
        f"{_device_details(d)}{note}"
        f"<h4>Offene Ports</h4>{_ports_table(d)}"
        "</section>"
    )


def _overview_row(d: Device) -> str:
    risk = d.max_risk
    return (
        "<tr>"
        f'<td><a href="#{_e(_anchor_id(d.mac))}">{_e(d.display_name)}</a></td>'
        f'<td><span class="mono">{_e(d.ip)}</span></td>'
        f'<td><span class="mono">{_e(d.mac)}</span>{" (privat)" if d.mac_random else ""}</td>'
        f"<td>{_e(d.vendor) or '–'}</td>"
        f"<td>{_e(CATEGORY_LABELS.get(d.category, d.category))}</td>"
        f"<td>{_status_badges(d)}</td>"
        f'<td class="num">{len(d.ports)}</td>'
        f"<td>{_risk_badge(risk)}</td>"
        f"<td>{_e(_fmt_time(d.last_seen))}</td>"
        "</tr>"
    )


def _last_scan_text(last_scan: Any) -> str:
    if not isinstance(last_scan, dict) or not last_scan:
        return "Letzter Scan: noch keiner abgeschlossen"
    when = _fmt_time(last_scan.get("finished") or last_scan.get("started"))
    extras = []
    if last_scan.get("network"):
        extras.append(f"Netz {last_scan['network']}")
    if last_scan.get("adapter"):
        extras.append(f"Adapter {last_scan['adapter']}")
    if last_scan.get("device_count") is not None:
        extras.append(f"{last_scan['device_count']} Geräte")
    return f"Letzter Scan: {when}" + (" (" + ", ".join(extras) + ")" if extras else "")


def to_html(devices: list[Device], meta: dict[str, Any]) -> str:
    """Eigenständiger Bericht: CSS inline, keine Skripte, alle Texte HTML-maskiert."""
    count = meta.get("device_count", len(devices))
    online = sum(1 for d in devices if d.online)
    new = sum(1 for d in devices if d.is_new)
    risky = sum(1 for d in devices if d.max_risk in ("high", "critical"))
    created = _fmt_time(meta.get("exported_at"))
    version = meta.get("version")

    if devices:
        overview = (
            "<table><thead><tr><th>Name</th><th>IP-Adresse</th><th>MAC-Adresse</th><th>Hersteller</th>"
            '<th>Kategorie</th><th>Status</th><th class="num">Ports</th><th>Höchstes Risiko</th>'
            "<th>Zuletzt gesehen</th></tr></thead><tbody>"
            + "".join(_overview_row(d) for d in devices)
            + "</tbody></table>"
        )
        details = "".join(_device_section(d) for d in devices)
    else:
        overview = '<p class="empty">Keine Geräte im Inventar.</p>'
        details = ""

    footer = "Erstellt mit dem Netzwerkscanner" + (f" {_e(version)}" if version else "")
    footer += ". Der Bericht enthält nur Daten aus dem lokalen Inventar."
    return (
        "<!DOCTYPE html>\n"
        '<html lang="de">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f'<meta http-equiv="Content-Security-Policy" content="{_e(_CSP)}">\n'
        "<title>Netzwerkscanner – Gerätebericht</title>\n"
        f"<style>\n{_CSS}\n</style>\n"
        "</head>\n<body>\n"
        "<header>\n"
        "<h1>Netzwerkscanner – Gerätebericht</h1>\n"
        f'<p class="meta">Erstellt: {_e(created)} · Anzahl Geräte: {_e(count)}</p>\n'
        f'<p class="meta">{_e(_last_scan_text(meta.get("last_scan")))}</p>\n'
        f'<p class="meta">{online} online · {new} neu · {risky} mit hohem oder kritischem Risiko</p>\n'
        "</header>\n<main>\n"
        f"<h2>Übersicht</h2>\n{overview}\n"
        f"<h2>Geräte im Detail</h2>\n{details}\n"
        "</main>\n"
        f"<footer>{footer}</footer>\n"
        "</body>\n</html>\n"
    )
