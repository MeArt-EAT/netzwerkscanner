/* Netzwerkscanner – Überwachung und Alerts im Browser (BAUPLAN §30).
 *
 * Eigenes Modul neben app.js: Reiter „Überwachung“ und „Alerts“, Abschnitt „Überwachung“ im Detailbereich,
 * Autostart in den Einstellungen und Monitor-Zustand/Datenbankgröße in der Statuszeile. Die Seite wird nur über
 * window.NetscanApp (aus app.js) bedient. Daten aus dem Netz und aus der Datenbank kommen nur über textContent bzw.
 * createElement in die Seite, nie als HTML. Diagramme zeichnet Chart.js (static/vendor) auf ein Canvas.
 *
 * Aufbau:
 *   1. Konstanten (Pfade aus §27, Namen aus §19)
 *   2. reine Hilfsfunktionen ohne DOM (in Node testbar, siehe module.exports unten)
 *   3. Oberfläche
 */
"use strict";

(function () {
  // =====================================================================================
  // 1. Konstanten
  // =====================================================================================

  // Pfade der Web-API Stufe 2 (BAUPLAN §27). tests/test_frontend_static.py prüft sie gegen den Vertrag.
  const MAPI = {
    monitor: "/api/monitor",
    targets: "/api/monitor/targets",
    target: (mac) => `/api/monitor/targets/${macPath(mac)}`,
    suggestions: (mac) => `/api/monitor/targets/${macPath(mac)}/suggestions`,
    targetChecks: (mac) => `/api/monitor/targets/${macPath(mac)}/checks`,
    check: (id) => `/api/monitor/checks/${idPath(id)}`,
    run: "/api/monitor/run",
    series: "/api/metrics/series",
    trend: "/api/metrics/trend",
    overview: "/api/metrics/overview",
    alerts: "/api/alerts",
    ack: (id) => `/api/alerts/${idPath(id)}/ack`,
    ackAll: "/api/alerts/ack-all",
    alertStats: "/api/alerts/stats",
    autostart: "/api/autostart",
  };

  // Namen wie in netscan/core/models.py (BAUPLAN §19)
  const TARGET_STATUS_LABELS = { unknown: "unbekannt", online: "online", degraded: "gestört", offline: "offline", paused: "pausiert" };
  const STATUS_ORDER = ["online", "degraded", "offline", "paused", "unknown"];
  const CHECK_KINDS = ["tcp", "http", "https", "smb", "ssh"];
  const CHECK_KIND_NAMES = { tcp: "TCP", http: "HTTP", https: "HTTPS", smb: "SMB-Freigabe", ssh: "SSH" };
  const CHECK_STATUS_LABELS = { unknown: "unbekannt", up: "läuft", down: "ausgefallen" };
  const REACH_METHODS = [
    ["auto", "Automatisch (Ping, ohne Antwort ein TCP-Port)"],
    ["ping", "Nur Ping"],
    ["tcp", "Nur TCP-Port"],
  ];
  const REACH_METHOD_KEYS = REACH_METHODS.map((m) => m[0]);
  const MONITOR_STATE_LABELS = { stopped: "angehalten", off: "ausgeschaltet", idle: "bereit", running: "läuft", paused: "pausiert" };
  const MONITOR_STATE_REASONS = {
    stopped: "Der Monitor läuft nicht (der Server wurde ohne Überwachung gestartet).",
    off: "Die Überwachung ist in den Einstellungen ausgeschaltet.",
    idle: "Keine Geräte zur Überwachung ausgewählt.",
    running: "",
    paused: "Alle überwachten Geräte sind pausiert.",
  };
  const ALERT_RULES = ["device_offline", "service_down", "rtt_high", "new_device", "new_port"];
  const ALERT_RULE_LABELS = {
    device_offline: "Gerät offline",
    service_down: "Dienst ausgefallen",
    rtt_high: "Antwortzeit hoch",
    new_device: "Neues Gerät",
    new_port: "Neuer offener Port",
  };
  const SEVERITY_LABELS = { info: "Hinweis", warning: "Warnung", critical: "kritisch" };
  const SEVERITY_RANK = { info: 0, warning: 1, critical: 2 };
  const ALERT_STATES = [
    ["active", "Aktiv"],
    ["unacked", "Unquittiert"],
    ["all", "Alle"],
  ];
  const RANGES = [
    ["24h", "24 h"],
    ["7d", "7 d"],
    ["30d", "30 d"],
    ["1y", "1 Jahr"],
  ];
  const DB_WARN_BYTES = 100 * 1024 * 1024; // wie config.DB_WARN_BYTES
  const MAX_CHECKS_PER_TARGET = 8; // wie config.MAX_CHECKS_PER_TARGET
  const TARGET_LIMITS = { offline_after_min: [1, 1440], rtt_threshold_ms: [1, 10000], tcp_port: [1, 65535] };
  const WEEKDAYS = ["So", "Mo", "Di", "Mi", "Do", "Fr", "Sa"];
  const MONTHS = ["Jan", "Feb", "Mär", "Apr", "Mai", "Jun", "Jul", "Aug", "Sep", "Okt", "Nov", "Dez"];

  // Wörtlich aus BAUPLAN §30 (Grundsatz 7) und §25
  const PRIVACY_HINT = "Die Überwachung macht sichtbar, wann diese Person zu Hause ist. Alle im Haushalt sollten davon wissen.";
  const FIREWALL_HINT =
    "Eigener PC: lokal geprüft – die Windows-Firewall wird dabei nicht berücksichtigt; von anderen Geräten aus kann der Port gesperrt sein.";

  // =====================================================================================
  // 2. Reine Hilfsfunktionen (kein DOM)
  // =====================================================================================

  /** Endliche Zahl oder null (Werte aus der Datenbank sind nicht vertrauenswürdig). */
  function num(value) {
    return typeof value === "number" && Number.isFinite(value) ? value : null;
  }

  function pad2(n) {
    return String(n).padStart(2, "0");
  }

  function fmt(n, digits) {
    return n.toLocaleString("de-DE", { maximumFractionDigits: digits, minimumFractionDigits: 0 });
  }

  function truncate(text, max) {
    const s = String(text == null ? "" : text);
    return s.length > max ? s.slice(0, Math.max(1, max - 1)) + "…" : s;
  }

  function macPath(mac) {
    return encodeURIComponent(String(mac)).replace(/%3A/gi, ":");
  }

  /** Ganzzahlige Kennung für einen Pfad; Unsinn wird 0 (der Server antwortet dann 404). */
  function idPath(id) {
    const n = Number(id);
    return Number.isSafeInteger(n) && n >= 0 ? String(n) : "0";
  }

  /** IPv4 als Zahl für die Sortierung; Ungültiges ans Ende. */
  function ipKey(ip) {
    const parts = String(ip || "").split(".");
    if (parts.length !== 4) return Number.MAX_SAFE_INTEGER;
    let n = 0;
    for (const part of parts) {
      if (!/^\d{1,3}$/.test(part)) return Number.MAX_SAFE_INTEGER;
      n = n * 256 + Number(part);
    }
    return n;
  }

  /** Zeitwert der API in Millisekunden. Kleine Zahlen gelten als Unix-Sekunden (since/until). */
  function toMs(value) {
    const n = num(value);
    if (n === null) return null;
    return Math.abs(n) < 1e11 ? n * 1000 : n;
  }

  /** Prozent mit höchstens einer Nachkommastelle, abgerundet (99,96 % ist noch nicht 100 %). */
  function formatPercent(value) {
    const n = num(value);
    if (n === null) return "–";
    const clamped = Math.min(100, Math.max(0, n));
    const shown = clamped >= 100 ? 100 : Math.floor(clamped * 10 + 1e-9) / 10;
    return fmt(shown, 1) + " %";
  }

  /** Verfügbarkeit aus {up_pct, samples, up} (oder einer Zahl). */
  function formatAvailability(av) {
    return formatPercent(av && typeof av === "object" ? av.up_pct : av);
  }

  function availabilityTitle(av) {
    if (!av || typeof av !== "object") return "";
    const samples = num(av.samples);
    if (samples === null) return "";
    if (samples <= 0) return "Noch keine Messwerte in diesem Zeitraum.";
    const up = num(av.up);
    return `${fmt(up === null ? 0 : up, 0)} von ${fmt(samples, 0)} Messungen erfolgreich`;
  }

  function formatRtt(ms) {
    const n = num(ms);
    if (n === null || n < 0) return "–";
    return fmt(n, n < 10 ? 1 : 0) + " ms";
  }

  /** Dateigröße mit Basis 1024 (wie DB_WARN_BYTES = 100 MB). */
  function formatBytes(bytes) {
    const n = num(bytes);
    if (n === null || n < 0) return "–";
    if (n < 1024) return `${Math.round(n)} B`;
    const units = ["KB", "MB", "GB", "TB"];
    let v = n / 1024;
    let i = 0;
    while (v >= 1024 && i < units.length - 1) {
      v /= 1024;
      i += 1;
    }
    return `${fmt(v, 1)} ${units[i]}`;
  }

  /** „seit …“ relativ zu nowMs; "" bei ungültiger Zeit. */
  function formatSince(iso, nowMs) {
    if (!iso) return "";
    const t = Date.parse(String(iso));
    const now = num(nowMs);
    if (!Number.isFinite(t) || now === null) return "";
    const s = Math.max(0, Math.floor((now - t) / 1000));
    if (s < 10) return "seit wenigen Sekunden";
    if (s < 60) return `seit ${s} s`;
    const min = Math.floor(s / 60);
    if (min < 60) return `seit ${min} min`;
    const hours = Math.floor(min / 60);
    if (hours < 24) {
      const rest = min % 60;
      return rest ? `seit ${hours} h ${rest} min` : `seit ${hours} h`;
    }
    const days = Math.floor(hours / 24);
    const restH = hours % 24;
    const dayText = days === 1 ? "1 Tag" : `${days} Tagen`;
    return restH ? `seit ${dayText} ${restH} h` : `seit ${dayText}`;
  }

  /** Uhrzeit (lokal) aus ISO-Text, z. B. „14:05:09“. */
  function formatClock(iso) {
    if (!iso) return "";
    const d = new Date(String(iso));
    if (Number.isNaN(d.getTime())) return "";
    return `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
  }

  /** Datum und Uhrzeit (lokal) aus Millisekunden, z. B. „10.10.2026 14:05“. */
  function formatDateTime(ms) {
    const n = num(ms);
    if (n === null) return "";
    const d = new Date(n);
    return `${pad2(d.getDate())}.${pad2(d.getMonth() + 1)}.${d.getFullYear()} ${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
  }

  function formatInterval(seconds) {
    const s = num(seconds);
    if (s === null || s <= 0) return "";
    if (s >= 60 && s % 60 === 0) return `${s / 60} min`;
    return `${fmt(s, 0)} s`;
  }

  function formatCycleMs(ms) {
    const n = num(ms);
    if (n === null || n < 0) return "";
    return n < 1000 ? `${Math.round(n)} ms` : `${fmt(n / 1000, 1)} s`;
  }

  /** Länge eines Diagramm-Eimers (bucket_s) als Text. */
  function formatBucket(seconds) {
    const s = num(seconds);
    if (s === null || s <= 0) return "";
    if (s < 60) return `${fmt(s, 0)} s`;
    if (s < 3600) return `${fmt(s / 60, 1)} min`;
    if (s < 86400) return `${fmt(s / 3600, 1)} h`;
    const days = s / 86400;
    return `${fmt(days, 1)} ${days === 1 ? "Tag" : "Tage"}`;
  }

  function parseDay(day) {
    const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(day == null ? "" : day));
    return m ? { y: Number(m[1]), m: Number(m[2]), d: Number(m[3]) } : null;
  }

  /** „2026-10-10“ (UTC-Tag) ⇒ „10.10.“ */
  function dayLabel(day) {
    const p = parseDay(day);
    return p ? `${pad2(p.d)}.${pad2(p.m)}.` : truncate(day, 12);
  }

  /** „2026-10-10“ ⇒ „Sa 10.10.2026“ */
  function dayTitle(day) {
    const p = parseDay(day);
    if (!p) return truncate(day, 24);
    const wd = WEEKDAYS[new Date(Date.UTC(p.y, p.m - 1, p.d)).getUTCDay()];
    return `${wd} ${pad2(p.d)}.${pad2(p.m)}.${p.y}`;
  }

  /** Beschriftung der Zeitachse (x in ms, Ortszeit), passend zum Zeitraum. */
  function tickLabel(ms, range) {
    const n = num(ms);
    if (n === null) return "";
    const d = new Date(n);
    const dm = `${pad2(d.getDate())}.${pad2(d.getMonth() + 1)}.`;
    if (range === "24h") return d.getHours() === 0 && d.getMinutes() === 0 ? dm : `${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
    if (range === "7d") return `${WEEKDAYS[d.getDay()]} ${dm}`;
    if (range === "1y") return `${MONTHS[d.getMonth()]} ${d.getFullYear()}`;
    return dm;
  }

  /** Ticks auf runden Zeitpunkten (Ortszeit): 24 h alle 3 h, 7 d täglich, 30 d alle 5 Tage, 1 Jahr monatlich. */
  function timeTicks(minMs, maxMs, range) {
    const lo = num(minMs);
    const hi = num(maxMs);
    if (lo === null || hi === null || hi <= lo) return [];
    const unit = { "24h": ["h", 3], "7d": ["d", 1], "30d": ["d", 5], "1y": ["m", 1] }[range] || ["d", 1];
    const d = new Date(lo);
    if (unit[0] === "h") {
      d.setMinutes(0, 0, 0);
      if (d.getTime() < lo) d.setHours(d.getHours() + 1);
      for (let i = 0; i < 4 && d.getHours() % unit[1]; i += 1) d.setHours(d.getHours() + 1);
    } else if (unit[0] === "d") {
      d.setHours(0, 0, 0, 0);
      if (d.getTime() < lo) d.setDate(d.getDate() + 1);
    } else {
      d.setDate(1);
      d.setHours(0, 0, 0, 0);
      if (d.getTime() < lo) d.setMonth(d.getMonth() + 1);
    }
    const out = [];
    while (d.getTime() <= hi && out.length < 60) {
      out.push(d.getTime());
      if (unit[0] === "h") d.setHours(d.getHours() + unit[1]);
      else if (unit[0] === "d") d.setDate(d.getDate() + unit[1]);
      else d.setMonth(d.getMonth() + 1);
    }
    return out;
  }

  function targetStatusLabel(status) {
    return TARGET_STATUS_LABELS[status] || "unbekannt";
  }

  function checkLabel(kind, port) {
    return `${CHECK_KIND_NAMES[kind] || String(kind || "?")} ${port}`;
  }

  /** „ping“ ⇒ „Ping“, „tcp:445“ ⇒ „TCP 445“ (CheckResult.method). */
  function methodLabel(method) {
    const m = /^([a-z]+)(?::(\d+))?$/.exec(String(method || ""));
    if (!m) return "";
    if (m[1] === "ping") return "Ping";
    return m[2] ? checkLabel(m[1], m[2]) : CHECK_KIND_NAMES[m[1]] || m[1];
  }

  /** Monitor-Zustand für Kopf und Statuszeile: {state, label, tone, reason}. */
  function monitorStateInfo(status) {
    if (!status || typeof status !== "object") return { state: "", label: "unbekannt", tone: "muted", reason: "" };
    const state = Object.prototype.hasOwnProperty.call(MONITOR_STATE_LABELS, status.state) ? status.state : "";
    const tone = state === "running" ? "ok" : state === "paused" ? "warn" : "muted";
    const reason = typeof status.reason === "string" && status.reason ? status.reason : MONITOR_STATE_REASONS[state] || "";
    return { state: state, label: MONITOR_STATE_LABELS[state] || "unbekannt", tone: tone, reason: reason };
  }

  /** „Jetzt prüfen“: nur, wenn der Monitor läuft, eingeschaltet ist und eingeschaltete Ziele hat.
   *  targets: Liste der Ziele (TargetView; enabled false zählt nicht) oder nur deren Anzahl. Mit einer Anzahl
   *  entscheidet der Zustand idle (= keine eingeschalteten Ziele beim letzten Durchlauf). Mit einer Liste gilt die
   *  Liste: Sie wird bei jeder Änderung der Ziele neu geladen, der Zustand erst nach dem nächsten Durchlauf. */
  function runButtonState(status, targets) {
    const info = monitorStateInfo(status);
    if (!info.state) return { disabled: true, title: "Der Zustand der Überwachung ist noch nicht bekannt." };
    if (info.state === "stopped") return { disabled: true, title: "Der Monitor läuft nicht." };
    if (info.state === "off") return { disabled: true, title: "Die Überwachung ist in den Einstellungen ausgeschaltet." };
    const list = Array.isArray(targets) ? targets.filter((t) => t && typeof t === "object") : null;
    const total = list ? list.length : num(targets);
    if (!(total > 0)) return { disabled: true, title: "Noch kein Gerät zur Überwachung ausgewählt." };
    const active = list ? list.filter((t) => t.enabled !== false).length : info.state === "idle" ? 0 : total;
    if (!(active > 0)) return { disabled: true, title: "Alle überwachten Geräte sind abgeschaltet." };
    return { disabled: false, title: "Alle überwachten Geräte sofort prüfen (der Netz-Wächter gilt auch hier)." };
  }

  /** Chip der Statuszeile für die Datenbank: {text, warn, title} oder null ohne Größe. */
  function dbInfo(bytes, warnFlag) {
    const n = num(bytes);
    if (n === null || n < 0) return null;
    const warn = warnFlag === true || n >= DB_WARN_BYTES;
    return {
      text: `Datenbank: ${formatBytes(n)}${warn ? " – größer als 100 MB" : ""}`,
      warn: warn,
      title: warn
        ? "Die Datenbankdatei ist größer als 100 MB. Weniger Geräte oder Dienste überwachen oder das Intervall vergrößern."
        : "Größe der Datenbankdatei (Messwerte, Alerts, Inventar)",
    };
  }

  function countStatuses(targets) {
    const counts = { online: 0, degraded: 0, offline: 0, paused: 0, unknown: 0 };
    for (const t of Array.isArray(targets) ? targets : []) {
      if (!t || typeof t !== "object") continue;
      const key = Object.prototype.hasOwnProperty.call(counts, t.status) ? t.status : "unknown";
      counts[key] += 1;
    }
    return counts;
  }

  /** Segmente der Status-Übersicht in fester Reihenfolge (Farbe folgt dem Zustand, nicht dem Rang). */
  function statusSegments(counts) {
    const c = counts && typeof counts === "object" ? counts : {};
    return STATUS_ORDER.map((key) => {
      const v = num(c[key]);
      return { key: key, label: TARGET_STATUS_LABELS[key], value: v !== null && v > 0 ? Math.round(v) : 0 };
    });
  }

  /** Datensätze für den Antwortzeit-Verlauf. Eimer mit n = 0 (oder ohne Antwortzeit) werden null ⇒ sichtbare Lücke.
   *  frame (optional, die Antwort der API): {since, until, bucket_s}. Damit zählen der angefangene erste Eimer
   *  (beginnt vor since) und der laufende letzte Eimer (reicht über until) ohne Messwerte nicht als Lücke. */
  function seriesData(points, frame) {
    const out = { avg: [], min: [], max: [], down: [], radius: [], info: [], samples: 0, gaps: 0, downs: 0 };
    if (!Array.isArray(points)) return out;
    const f = frame && typeof frame === "object" ? frame : {};
    const sinceMs = toMs(f.since);
    const untilMs = toMs(f.until);
    const bucketS = num(f.bucket_s);
    const bucketMs = bucketS !== null && bucketS > 0 ? bucketS * 1000 : null;
    const rows = [];
    for (const p of points) {
      if (!p || typeof p !== "object") continue;
      const t = num(p.t);
      if (t === null) continue;
      const rawN = num(p.n);
      const n = rawN !== null && rawN > 0 ? Math.round(rawN) : 0;
      const pick = (v) => {
        const x = num(v);
        return n > 0 && x !== null && x >= 0 ? x : null;
      };
      const up = n > 0 ? num(p.up_pct) : null;
      rows.push({ t: t, n: n, avg: pick(p.rtt_avg), min: pick(p.rtt_min), max: pick(p.rtt_max), up: up === null ? null : Math.min(100, Math.max(0, up)) });
    }
    rows.sort((a, b) => a.t - b.t);
    for (const r of rows) {
      let lo = null;
      let hi = null;
      if (r.avg !== null) {
        lo = r.min === null ? r.avg : r.min;
        hi = r.max === null ? r.avg : r.max;
        if (lo > hi) [lo, hi] = [hi, lo];
      }
      const isDown = r.n > 0 && r.up !== null && r.up < 100;
      // Randeimer nur teilweise im Zeitraum: "start" beginnt vor since, "end" läuft noch (reicht über until)
      const startsEarly = sinceMs !== null && r.t < sinceMs;
      const stillRunning = untilMs !== null && bucketMs !== null && r.t + bucketMs > untilMs;
      const edge = startsEarly ? "start" : stillRunning ? "end" : "";
      out.avg.push({ x: r.t, y: r.avg });
      out.min.push({ x: r.t, y: lo });
      out.max.push({ x: r.t, y: hi });
      out.down.push({ x: r.t, y: isDown ? 0 : null });
      out.info.push({ t: r.t, n: r.n, up_pct: r.up, rtt_avg: r.avg, rtt_min: lo, rtt_max: hi, edge: edge });
      out.samples += r.n;
      if (r.n === 0 && !edge) out.gaps += 1;
      if (isDown) out.downs += 1;
    }
    // Einzelne Werte zwischen zwei Lücken als Punkt zeigen (eine Linie braucht zwei Punkte)
    out.radius = out.avg.map((p, i) => {
      if (p.y === null) return 0;
      const before = i === 0 || out.avg[i - 1].y === null;
      const after = i === out.avg.length - 1 || out.avg[i + 1].y === null;
      return before && after ? 2.5 : 0;
    });
    return out;
  }

  /** Zeilen des Tooltips für einen Eimer des Antwortzeit-Verlaufs. */
  function seriesTooltip(info) {
    if (!info || typeof info !== "object") return [];
    if (!info.n && info.edge === "end") return ["Noch keine Messwerte (Abschnitt läuft noch)"];
    if (!info.n && info.edge === "start") return ["Keine Messwerte (Abschnitt liegt nur teilweise im Zeitraum)"];
    if (!info.n) return ["Keine Messwerte (Lücke)"];
    const lines = [];
    if (info.rtt_avg === null || info.rtt_avg === undefined) lines.push("Keine Antwortzeit (nicht erreichbar)");
    else lines.push(`Antwortzeit Ø ${formatRtt(info.rtt_avg)} (min ${formatRtt(info.rtt_min)}, max ${formatRtt(info.rtt_max)})`);
    lines.push(`Erreichbar: ${formatPercent(info.up_pct)} von ${fmt(info.n, 0)} ${info.n === 1 ? "Messung" : "Messungen"}`);
    return lines;
  }

  function seriesNote(bucketS, sd) {
    const parts = [];
    const bucket = formatBucket(bucketS);
    if (bucket) parts.push(`Ein Punkt fasst ${bucket} zusammen`);
    if (sd && sd.gaps) parts.push(`${sd.gaps} ${sd.gaps === 1 ? "Abschnitt" : "Abschnitte"} ohne Messwerte (Lücke, z. B. Pause oder Programm aus)`);
    if (sd && sd.downs) parts.push(`${sd.downs} mit Ausfällen (rote Marken)`);
    return parts.join(" · ");
  }

  function sortedDays(list) {
    return (Array.isArray(list) ? list : [])
      .filter((r) => r && typeof r === "object" && typeof r.day === "string")
      .slice()
      .sort((a, b) => (a.day < b.day ? -1 : a.day > b.day ? 1 : 0));
  }

  /** Verfügbarkeits-Trend: Balken je Tag; Tage ohne Messwerte bleiben leer (null). */
  function trendData(list) {
    const out = { labels: [], titles: [], values: [], n: [] };
    for (const r of sortedDays(list)) {
      const rawN = num(r.n);
      const n = rawN !== null && rawN > 0 ? Math.round(rawN) : 0;
      const up = n > 0 ? num(r.up_pct) : null;
      out.labels.push(dayLabel(r.day));
      out.titles.push(dayTitle(r.day));
      out.values.push(up === null ? null : Math.min(100, Math.max(0, up)));
      out.n.push(n);
    }
    return out;
  }

  /** Alert-Häufigkeit: je Regel ein Datensatz (feste Reihenfolge), fehlende oder unsinnige Werte = 0. */
  function frequencyData(days) {
    const rows = sortedDays(days);
    const datasets = ALERT_RULES.map((rule) => ({
      rule: rule,
      label: ALERT_RULE_LABELS[rule],
      data: rows.map((r) => {
        const v = num(r[rule]);
        return v !== null && v > 0 ? Math.round(v) : 0;
      }),
    }));
    const total = rows.map((_, i) => datasets.reduce((sum, ds) => sum + ds.data[i], 0));
    return { labels: rows.map((r) => dayLabel(r.day)), titles: rows.map((r) => dayTitle(r.day)), datasets: datasets, total: total };
  }

  /** Datenschutz-Hinweis bei Handys und Geräten mit privater (zufälliger) MAC. */
  function privacyHint(device) {
    return device && (device.category === "phone" || device.mac_random === true) ? PRIVACY_HINT : "";
  }

  /** Firewall-Hinweis unter den Ports des eigenen PCs (nur, wenn dort offene Ports stehen). */
  function firewallHint(device) {
    return device && device.is_self === true && Array.isArray(device.ports) && device.ports.length > 0 ? FIREWALL_HINT : "";
  }

  function validPort(port) {
    return Number.isInteger(port) && port >= 1 && port <= 65535;
  }

  /** Vorschläge und vorhandene Prüfungen zu einer Liste: [{key, kind, port, path, label, reason, check, suggested}]. */
  function mergeCheckOptions(suggestions, checks) {
    const index = new Map();
    for (const c of Array.isArray(checks) ? checks : []) {
      if (!c || typeof c !== "object" || !CHECK_KINDS.includes(c.kind) || !validPort(c.port)) continue;
      const key = `${c.kind}:${c.port}`;
      if (index.has(key)) continue;
      index.set(key, {
        key: key, kind: c.kind, port: c.port, path: typeof c.path === "string" && c.path ? c.path : "/",
        label: typeof c.label === "string" && c.label ? c.label : checkLabel(c.kind, c.port), reason: "", check: c, suggested: false,
      });
    }
    for (const s of Array.isArray(suggestions) ? suggestions : []) {
      if (!s || typeof s !== "object" || !CHECK_KINDS.includes(s.kind) || !validPort(s.port)) continue;
      const key = `${s.kind}:${s.port}`;
      const reason = typeof s.reason === "string" ? s.reason : "";
      const existing = index.get(key);
      if (existing) {
        existing.suggested = true;
        if (!existing.reason) existing.reason = reason;
        continue;
      }
      index.set(key, {
        key: key, kind: s.kind, port: s.port, path: typeof s.path === "string" && s.path ? s.path : "/",
        label: typeof s.label === "string" && s.label ? s.label : checkLabel(s.kind, s.port), reason: reason, check: null, suggested: true,
      });
    }
    return Array.from(index.values()).sort((a, b) => a.port - b.port || CHECK_KINDS.indexOf(a.kind) - CHECK_KINDS.indexOf(b.kind));
  }

  /** Vorauswahl für ein neues Ziel: die wichtigen Dienste (SMB, HTTP/HTTPS, SSH), keine reinen TCP-Ports; höchstens 8. */
  function defaultSelection(options) {
    return (Array.isArray(options) ? options : [])
      .filter((o) => o && !o.check && o.kind !== "tcp")
      .slice(0, MAX_CHECKS_PER_TARGET)
      .map((o) => o.key);
  }

  /** Leer ⇒ {value: null}; Zahl im Bereich ⇒ {value}; sonst {error: true}. Komma als Dezimalzeichen erlaubt. */
  function parseOptionalNumber(text, lo, hi, integer) {
    const s = String(text == null ? "" : text).trim().replace(",", ".");
    if (!s) return { value: null };
    if (!/^\d+(\.\d+)?$/.test(s)) return { error: true };
    const n = Number(s);
    if (!Number.isFinite(n) || n < lo || n > hi || (integer && !Number.isInteger(n))) return { error: true };
    return { value: n };
  }

  /** Nur geänderte Felder für PATCH /api/monitor/targets/{mac}; leere Felder = null (zurücksetzen). */
  function buildTargetPatch(target, form) {
    const t = target && typeof target === "object" ? target : {};
    const f = form && typeof form === "object" ? form : {};
    const patch = {};
    const errors = [];
    const method = REACH_METHOD_KEYS.includes(f.method) ? f.method : "auto";
    if (method !== (REACH_METHOD_KEYS.includes(t.method) ? t.method : "auto")) patch.method = method;
    const fields = [
      ["tcp_port", "TCP-Port", true],
      ["offline_after_min", "Offline-Alert", true],
      ["rtt_threshold_ms", "Antwortzeit-Schwelle", false],
    ];
    for (const [key, label, integer] of fields) {
      const [lo, hi] = TARGET_LIMITS[key];
      const parsed = parseOptionalNumber(f[key], lo, hi, integer);
      if (parsed.error) {
        errors.push(`${label}: bitte ${integer ? "eine ganze Zahl" : "eine Zahl"} von ${fmt(lo, 0)} bis ${fmt(hi, 0)} eintragen oder leer lassen.`);
        continue;
      }
      if (parsed.value !== num(t[key])) patch[key] = parsed.value;
    }
    return { patch: patch, errors: errors };
  }

  /** Ereignis monitor.cycle in die geladenen Ziele einarbeiten (gibt neue Objekte zurück). */
  function applyCycle(targets, data) {
    if (!Array.isArray(targets)) return [];
    const rows = data && typeof data === "object" && Array.isArray(data.targets) ? data.targets : [];
    const ts = data && typeof data.ts === "string" ? data.ts : null;
    const byMac = new Map();
    for (const r of rows) if (r && typeof r === "object" && typeof r.mac === "string" && !byMac.has(r.mac)) byMac.set(r.mac, r); // erster zählt
    return targets.map((t) => {
      const r = t && byMac.get(t.mac);
      if (!r) return t;
      const next = Object.assign({}, t);
      if (Object.prototype.hasOwnProperty.call(TARGET_STATUS_LABELS, r.status) && r.status !== t.status) {
        next.status = r.status;
        next.status_label = TARGET_STATUS_LABELS[r.status];
        if (ts) next.status_since = ts;
      }
      next.last_rtt_ms = num(r.rtt_ms);
      const detail = typeof r.detail === "string" ? r.detail : "";
      if (next.status === "paused") next.pause_reason = detail;
      else next.last_detail = detail;
      if (ts) next.last_check = ts;
      if (Array.isArray(r.checks) && Array.isArray(t.checks)) {
        const updates = new Map();
        for (const c of r.checks) if (c && typeof c === "object" && num(c.id) !== null) updates.set(c.id, c);
        next.checks = t.checks.map((c) => {
          const u = c && updates.get(c.id);
          if (!u) return c;
          const nc = Object.assign({}, c);
          if (Object.prototype.hasOwnProperty.call(CHECK_STATUS_LABELS, u.status) && u.status !== c.status) {
            nc.status = u.status;
            if (ts) nc.status_since = ts;
          }
          nc.last_rtt_ms = num(u.rtt_ms);
          nc.last_detail = typeof u.detail === "string" ? u.detail : "";
          return nc;
        });
      }
      return next;
    });
  }

  /** Ziele nach IP, dann Name, dann MAC. */
  function sortTargets(list) {
    const name = (t) => (t && t.device && typeof t.device.display_name === "string" ? t.device.display_name : "");
    const ip = (t) => (t && t.device ? t.device.ip : "");
    return (Array.isArray(list) ? list : [])
      .filter((t) => t && typeof t === "object" && typeof t.mac === "string")
      .slice()
      .sort((a, b) => ipKey(ip(a)) - ipKey(ip(b)) || name(a).localeCompare(name(b), "de") || (a.mac < b.mac ? -1 : a.mac > b.mac ? 1 : 0));
  }

  /** Chip einer Dienstprüfung: {text, tone (up|down|unknown|off), symbol, title}. */
  function checkChip(check) {
    if (!check || typeof check !== "object") return null;
    const label = typeof check.label === "string" && check.label ? check.label : checkLabel(check.kind, check.port);
    if (check.enabled === false) return { text: label, tone: "off", symbol: "–", title: `${label}: abgeschaltet` };
    const status = Object.prototype.hasOwnProperty.call(CHECK_STATUS_LABELS, check.status) ? check.status : "unknown";
    const parts = [`${label}: ${CHECK_STATUS_LABELS[status]}`];
    if (typeof check.last_detail === "string" && check.last_detail) parts.push(check.last_detail);
    if (num(check.last_rtt_ms) !== null) parts.push(formatRtt(check.last_rtt_ms));
    const av = check.availability && typeof check.availability === "object" ? check.availability["24h"] : null;
    if (av && num(av.up_pct) !== null) parts.push(`24 h: ${formatAvailability(av)}`);
    return { text: label, tone: status, symbol: status === "up" ? "✓" : status === "down" ? "✗" : "?", title: parts.join(" · ") };
  }

  function alertMatches(alert, filter) {
    if (!alert || typeof alert !== "object") return false;
    if (filter === "active") return !alert.closed;
    if (filter === "unacked") return !alert.acknowledged;
    return true;
  }

  function compareAlerts(a, b) {
    const ta = Date.parse(a.opened) || 0;
    const tb = Date.parse(b.opened) || 0;
    return tb - ta || (num(b.id) || 0) - (num(a.id) || 0);
  }

  /** Alert (neu oder geändert) in die angezeigte Liste übernehmen: neueste zuerst, Filter beachten. */
  function mergeAlert(list, alert, filter, limit) {
    const base = (Array.isArray(list) ? list : []).filter((a) => a && typeof a === "object");
    if (!alert || typeof alert !== "object" || num(alert.id) === null) return base;
    const rest = base.filter((a) => a.id !== alert.id);
    if (alertMatches(alert, filter)) rest.push(alert);
    rest.sort(compareAlerts);
    return rest.slice(0, limit || 200);
  }

  /** Zähler am Reiter „Alerts“. */
  function alertCountText(n) {
    const v = num(n);
    if (v === null || v <= 0) return "";
    return v > 99 ? "99+" : String(Math.round(v));
  }

  /** Eine Meldung für mehrere kurz nacheinander geöffnete Alerts: {text, tone} oder null. */
  function alertToast(alerts) {
    const list = (Array.isArray(alerts) ? alerts : []).filter((a) => a && typeof a === "object");
    if (!list.length) return null;
    const worst = list.reduce((w, a) => Math.max(w, SEVERITY_RANK[a.severity] || 0), 0);
    const tone = worst === 2 ? "error" : worst === 1 ? "warn" : "info";
    if (list.length === 1) {
      const a = list[0];
      const title = typeof a.title === "string" && a.title ? a.title : ALERT_RULE_LABELS[a.rule] || "Neuer Alert";
      return { tone: tone, text: `Alert (${SEVERITY_LABELS[a.severity] || "Hinweis"}): ${title}` };
    }
    return { tone: tone, text: `${list.length} neue Alerts – siehe Reiter „Alerts“.` };
  }

  // Für Tests in Node: dort gibt es kein document, wir stellen nur die reinen Funktionen bereit.
  if (typeof document === "undefined") {
    if (typeof module !== "undefined" && module.exports) {
      module.exports = {
        MAPI, TARGET_STATUS_LABELS, STATUS_ORDER, CHECK_KINDS, CHECK_KIND_NAMES, CHECK_STATUS_LABELS, REACH_METHODS,
        MONITOR_STATE_LABELS, ALERT_RULES, ALERT_RULE_LABELS, SEVERITY_LABELS, ALERT_STATES, RANGES, DB_WARN_BYTES,
        MAX_CHECKS_PER_TARGET, TARGET_LIMITS, PRIVACY_HINT, FIREWALL_HINT,
        num, toMs, idPath, macPath, ipKey, formatPercent, formatAvailability, availabilityTitle, formatRtt, formatBytes,
        formatSince, formatClock, formatDateTime, formatInterval, formatCycleMs, formatBucket, dayLabel, dayTitle,
        tickLabel, timeTicks, targetStatusLabel, checkLabel, methodLabel, monitorStateInfo, runButtonState, dbInfo,
        countStatuses, statusSegments, seriesData, seriesTooltip, seriesNote, trendData, frequencyData, privacyHint,
        firewallHint, mergeCheckOptions, defaultSelection, parseOptionalNumber, buildTargetPatch, applyCycle,
        sortTargets, checkChip, alertMatches, mergeAlert, alertCountText, alertToast,
      };
    }
    return;
  }

  // =====================================================================================
  // 3. Oberfläche
  // =====================================================================================

  const App = window.NetscanApp;
  if (!App) return; // app.js fehlt: dann gibt es auch nichts zu erweitern

  const h = App.h;
  const clear = App.clear;
  const api = App.api;
  const apiMessage = App.apiMessage;
  const toast = App.toast;
  const $ = (id) => document.getElementById(id);

  const ALERT_LIMIT = 200;
  const SERIES_REFRESH_MS = 30000;
  const OVERVIEW_REFRESH_MS = 60000;
  const CHART_MISSING = "Die Diagrammbibliothek (Chart.js) konnte nicht geladen werden. Werte und Tabellen funktionieren weiterhin.";

  const M = {
    tab: App.tab(),
    status: null, // MonitorStatus
    targets: new Map(), // mac -> TargetView
    loaded: false,
    loadError: "",
    overview: null,
    overviewAt: 0,
    selectedMac: null,
    checkId: 0,
    range: "24h",
    series: null,
    seriesError: "",
    seriesAt: 0,
    trend: null,
    trendError: "",
    running: false, // POST /api/monitor/run läuft
    alerts: [],
    alertFilter: "active",
    alertsLoaded: false,
    alertsError: "",
    alertCounts: null, // {active, unacked}
    stats: null,
    statsError: "",
    ackBusy: false,
    autostart: null,
    autostartBusy: false,
    charts: { status: null, rtt: null, trend: null, freq: null },
    statusChartSig: "",
    toastQueue: [],
    toastTimer: null,
  };

  // Detailbereich: Zustand des Abschnitts „Überwachung“ für das gerade geöffnete Gerät
  const D = { mac: null, parts: null, sigs: {}, suggestions: null, sugError: "", selection: null, formDirty: false, busy: false };
  const seqs = { monitor: 0, rtt: 0, trend: 0, alerts: 0, stats: 0, overview: 0, sug: 0, autostart: 0 };
  const timers = { monitor: null, stats: null, alerts: null, sug: null };

  // ---------- kleine DOM-Hilfen ----------

  /** Schlüssel (data-focus-key) des fokussierten Elements, wenn es in container liegt. */
  function focusKeyIn(container) {
    const active = document.activeElement;
    if (!container || !active || active === document.body || !container.contains(active) || !active.dataset) return null;
    return active.dataset.focusKey || null;
  }

  function refocus(container, key) {
    if (!container || !key) return;
    for (const el of container.querySelectorAll("[data-focus-key]")) {
      if (el.dataset.focusKey === key) {
        el.focus();
        break;
      }
    }
  }

  /** Inhalt neu bauen und den Fokus (data-focus-key) danach wiederherstellen. */
  function withFocus(container, fn) {
    const key = focusKeyIn(container);
    fn();
    refocus(container, key);
  }

  function statusBadge(status) {
    const key = Object.prototype.hasOwnProperty.call(TARGET_STATUS_LABELS, status) ? status : "unknown";
    return h("span", { class: "badge st-" + key, text: TARGET_STATUS_LABELS[key] });
  }

  /** Chip einer Dienstprüfung; statusText: Zustand statt Name zeigen (wenn der Name schon daneben steht). */
  function chipNode(check, statusText) {
    const c = checkChip(check);
    if (!c) return null;
    const text = statusText ? (c.tone === "off" ? "aus" : CHECK_STATUS_LABELS[c.tone] || "unbekannt") : c.text;
    return h("span", { class: "svc svc-" + c.tone, title: c.title }, h("span", { "aria-hidden": "true", text: c.symbol }), text);
  }

  function targetDevice(t) {
    const live = t ? App.device(t.mac) : null;
    if (live) return live;
    return t && t.device && typeof t.device === "object" ? t.device : null;
  }

  function targetName(t) {
    const d = targetDevice(t);
    return (d && typeof d.display_name === "string" && d.display_name) || (t && t.mac) || "";
  }

  function schedule(name, fn, delay) {
    clearTimeout(timers[name]);
    timers[name] = setTimeout(() => {
      timers[name] = null;
      fn();
    }, delay);
  }

  // ---------- Laden ----------

  async function loadMonitor() {
    const seq = ++seqs.monitor;
    const res = await api("GET", MAPI.monitor);
    if (seq !== seqs.monitor) return;
    if (!res.ok || !res.data || typeof res.data !== "object") {
      M.loadError =
        res.status === 404 ? "Die Überwachung ist auf diesem Server nicht verfügbar." : "Überwachung nicht lesbar: " + apiMessage(res.data, "keine Antwort");
      if (M.tab === "monitor") renderMonitorView();
      if (D.mac) renderDetailMonitor(App.device(D.mac));
      return;
    }
    M.loadError = "";
    if (res.data.status && typeof res.data.status === "object") M.status = res.data.status;
    const list = Array.isArray(res.data.targets) ? res.data.targets.filter((t) => t && typeof t === "object" && typeof t.mac === "string") : [];
    M.targets = new Map(list.map((t) => [t.mac, t]));
    M.loaded = true;
    afterTargetsChanged();
  }

  function scheduleMonitorReload(delay) {
    schedule("monitor", loadMonitor, delay);
  }

  async function loadOverview() {
    const seq = ++seqs.overview;
    M.overviewAt = Date.now();
    const res = await api("GET", MAPI.overview);
    if (seq !== seqs.overview) return;
    if (res.ok && res.data && typeof res.data === "object") {
      M.overview = res.data;
      renderStatusLine();
    }
  }

  async function loadSeries() {
    await Promise.all([loadRtt(), loadTrend()]);
  }

  async function loadRtt() {
    const mac = M.selectedMac;
    if (!mac || M.tab !== "monitor") return;
    const seq = ++seqs.rtt;
    M.seriesAt = Date.now();
    const res = await api("GET", MAPI.series, undefined, { mac: mac, check_id: M.checkId, range: M.range });
    if (seq !== seqs.rtt) return;
    if (res.ok && res.data && typeof res.data === "object") {
      M.series = res.data;
      M.seriesError = "";
    } else {
      M.series = null;
      M.seriesError = "Verlauf nicht lesbar: " + apiMessage(res.data, "keine Antwort");
    }
    drawRttChart();
  }

  async function loadTrend() {
    const mac = M.selectedMac;
    if (!mac || M.tab !== "monitor") return;
    const seq = ++seqs.trend;
    const res = await api("GET", MAPI.trend, undefined, { mac: mac, check_id: M.checkId, days: 30 });
    if (seq !== seqs.trend) return;
    if (res.ok && Array.isArray(res.data)) {
      M.trend = res.data;
      M.trendError = "";
    } else {
      M.trend = null;
      M.trendError = "Trend nicht lesbar: " + apiMessage(res.data, "keine Antwort");
    }
    drawTrendChart();
  }

  async function loadAlerts() {
    const seq = ++seqs.alerts;
    const filter = M.alertFilter;
    const res = await api("GET", MAPI.alerts, undefined, { state: filter, limit: ALERT_LIMIT });
    if (seq !== seqs.alerts) return;
    if (!res.ok || !Array.isArray(res.data)) {
      M.alertsError = "Alerts nicht lesbar: " + apiMessage(res.data, "keine Antwort");
      renderAlerts();
      return;
    }
    M.alerts = res.data.filter((a) => a && typeof a === "object" && num(a.id) !== null);
    M.alertsLoaded = true;
    M.alertsError = "";
    renderAlerts();
  }

  function scheduleAlertsReload() {
    schedule("alerts", loadAlerts, 400);
  }

  async function loadAlertStats() {
    const seq = ++seqs.stats;
    const res = await api("GET", MAPI.alertStats, undefined, { days: 30 });
    if (seq !== seqs.stats) return;
    if (!res.ok || !res.data || typeof res.data !== "object") {
      M.statsError = "Alert-Häufigkeit nicht lesbar: " + apiMessage(res.data, "keine Antwort");
      drawFreqChart();
      return;
    }
    M.stats = res.data;
    M.statsError = "";
    if (res.data.counts && typeof res.data.counts === "object") updateAlertCounts(res.data.counts);
    drawFreqChart();
  }

  function scheduleStatsReload() {
    schedule("stats", loadAlertStats, 800);
  }

  // ---------- Ereignisse und Zustand ----------

  function afterTargetsChanged() {
    renderStatusLine();
    if (M.tab === "monitor") renderMonitorView();
    if (D.mac) renderDetailMonitor(App.device(D.mac));
  }

  function onMonitorStatus(data) {
    if (!data.status || typeof data.status !== "object") return;
    M.status = data.status;
    renderStatusLine();
    if (M.tab === "monitor") renderMonitorState();
    if (Date.now() - M.overviewAt > OVERVIEW_REFRESH_MS) loadOverview();
  }

  function onCycle(data) {
    if (!M.loaded) return;
    const list = applyCycle(Array.from(M.targets.values()), data);
    M.targets = new Map(list.map((t) => [t.mac, t]));
    afterTargetsChanged();
    if (M.tab === "monitor") {
      scheduleMonitorReload(1500); // Verfügbarkeit und genaue Zeiten vom Server
      if (M.selectedMac && Date.now() - M.seriesAt > SERIES_REFRESH_MS) loadSeries();
    }
  }

  function onAppStatus(status) {
    if (status && typeof status === "object") {
      if (status.monitor && typeof status.monitor === "object") M.status = status.monitor;
      if (status.alerts && typeof status.alerts === "object") updateAlertCounts(status.alerts);
    }
    renderStatusLine();
    if (M.tab === "monitor") renderMonitorState();
  }

  function updateAlertCounts(counts) {
    M.alertCounts = { active: num(counts.active) || 0, unacked: num(counts.unacked) || 0 };
    renderAlertBadge();
    if (M.tab === "alerts") renderAlertSummary();
  }

  function onAlertEvent(kind, data) {
    const alert = data.alert && typeof data.alert === "object" ? data.alert : null;
    if ((kind === "opened" || kind === "closed") && alert) {
      if (M.alertsLoaded) {
        M.alerts = mergeAlert(M.alerts, alert, M.alertFilter, ALERT_LIMIT);
        if (M.tab === "alerts") renderAlerts();
      }
      if (kind === "opened") queueAlertToast(alert);
    } else if (kind === "acknowledged") {
      if (M.tab === "alerts") scheduleAlertsReload();
      else M.alertsLoaded = false;
    }
    scheduleStatsReload();
  }

  function queueAlertToast(alert) {
    M.toastQueue.push(alert);
    if (M.toastTimer) return;
    M.toastTimer = setTimeout(() => {
      const message = alertToast(M.toastQueue);
      M.toastQueue = [];
      M.toastTimer = null;
      if (message) toast(message.text, message.tone, message.tone === "error" ? 12000 : 8000);
    }, 700);
  }

  function onTab(tab) {
    const before = M.tab;
    M.tab = tab;
    if (before === "monitor" && tab !== "monitor") {
      for (const name of ["status", "rtt", "trend"]) destroyChart(name);
      M.statusChartSig = "";
    }
    if (before === "alerts" && tab !== "alerts") destroyChart("freq");
    if (tab === "monitor") {
      renderMonitorView();
      drawRttChart(); // vorhandene Daten sofort, dann frisch laden
      drawTrendChart();
      loadMonitor();
      loadOverview();
      loadSeries();
    } else if (tab === "alerts") {
      renderAlerts();
      drawFreqChart();
      loadAlerts();
      loadAlertStats();
    }
  }

  function resync() {
    loadMonitor();
    loadOverview();
    loadAlertStats();
    if (M.tab === "alerts") loadAlerts();
    else M.alertsLoaded = false;
    if (M.tab === "monitor") loadSeries();
    if (D.mac) loadSuggestions(D.mac);
  }

  // ---------- Statuszeile und Reiter-Zähler ----------

  function renderStatusLine() {
    const box = $("status-monitor");
    if (!box) return;
    clear(box);
    if (!M.status && !M.loaded) return;
    const info = monitorStateInfo(M.status);
    let text = "Überwachung: " + info.label;
    const count = M.status ? num(M.status.targets) : null;
    if ((info.state === "running" || info.state === "paused") && count !== null) text += ` · ${count} ${count === 1 ? "Gerät" : "Geräte"}`;
    box.append(h("span", { class: "chip chip-" + info.tone, text: text, title: info.reason }));
    const bytes = M.overview && num(M.overview.db_size_bytes) !== null ? M.overview.db_size_bytes : M.status ? M.status.db_size_bytes : null;
    const db = dbInfo(bytes, M.overview ? M.overview.db_warn : undefined);
    if (db) {
      box.append(db.warn ? h("strong", { class: "status-warning", text: db.text, title: db.title }) : h("span", { class: "chip chip-info", text: db.text, title: db.title }));
    }
  }

  function renderAlertBadge() {
    const el = $("alert-count");
    const tab = $("tab-alerts");
    const counts = M.alertCounts || { active: 0, unacked: 0 };
    const text = alertCountText(counts.unacked);
    el.textContent = text;
    el.hidden = !text;
    if (M.alertCounts) tab.title = `${counts.unacked} unquittiert, ${counts.active} aktiv`;
    else tab.removeAttribute("title");
    if (text) tab.setAttribute("aria-label", `Alerts (${counts.unacked} unquittiert)`);
    else tab.removeAttribute("aria-label");
  }

  // ---------- Diagramme (Chart.js) ----------

  function chartReady() {
    return typeof window.Chart === "function";
  }

  function chartTheme() {
    const style = getComputedStyle(document.documentElement);
    const v = (name, fallback) => (style.getPropertyValue(name) || "").trim() || fallback;
    return {
      text: v("--text", "#1b1f27"),
      muted: v("--muted", "#566070"),
      grid: v("--chart-grid", "#e6e9ef"),
      surface: v("--surface", "#ffffff"),
      font: v("--font", "system-ui, sans-serif"),
      series: [v("--chart-1", "#2a78d6"), v("--chart-2", "#eb6834"), v("--chart-3", "#1baf7a"), v("--chart-4", "#eda100"), v("--chart-5", "#e87ba4")],
      band: v("--chart-band", "rgba(42, 120, 214, 0.18)"),
      status: {
        online: v("--status-good", "#0ca30c"),
        degraded: v("--status-warning", "#fab219"),
        offline: v("--status-critical", "#d03b3b"),
        paused: v("--status-paused", "#9aa3b2"),
        unknown: v("--status-unknown", "#c9ced8"),
      },
    };
  }

  function destroyChart(name) {
    const chart = M.charts[name];
    M.charts[name] = null;
    if (chart) {
      try {
        chart.destroy();
      } catch (err) {
        /* schon weg */
      }
    }
  }

  function chartMessage(canvasId, text) {
    const canvas = $(canvasId);
    if (!canvas) return;
    const box = canvas.parentElement;
    let msg = box.querySelector(".chart-msg");
    if (!msg) {
      msg = h("p", { class: "chart-msg" });
      box.append(msg);
    }
    msg.textContent = text || "";
    msg.hidden = !text;
    canvas.hidden = !!text;
  }

  /** Altes Diagramm zerstören, dann neu zeichnen – oder eine Meldung statt des Diagramms zeigen. */
  function drawChart(name, canvasId, makeConfig, message) {
    destroyChart(name);
    if (!chartReady()) {
      chartMessage(canvasId, CHART_MISSING);
      return;
    }
    if (message) {
      chartMessage(canvasId, message);
      return;
    }
    chartMessage(canvasId, "");
    const canvas = $(canvasId);
    try {
      const old = typeof window.Chart.getChart === "function" ? window.Chart.getChart(canvas) : null;
      if (old) old.destroy();
      const theme = chartTheme();
      window.Chart.defaults.color = theme.muted;
      window.Chart.defaults.borderColor = theme.grid;
      window.Chart.defaults.font.family = theme.font;
      M.charts[name] = new window.Chart(canvas, makeConfig(theme));
    } catch (err) {
      chartMessage(canvasId, "Das Diagramm konnte nicht gezeichnet werden.");
    }
  }

  function baseOptions() {
    return { animation: false, responsive: true, maintainAspectRatio: false, resizeDelay: 60 };
  }

  function drawStatusChart(force) {
    if (M.tab !== "monitor") return;
    const counts = countStatuses(Array.from(M.targets.values()));
    const segments = statusSegments(counts);
    const total = segments.reduce((sum, s) => sum + s.value, 0);
    const sig = JSON.stringify(segments) + "|" + M.loaded;
    if (!force && sig === M.statusChartSig && (M.charts.status || !chartReady() || !total)) return;
    M.statusChartSig = sig;
    const message = !M.loaded ? "Wird geladen …" : !total ? "Noch keine überwachten Geräte." : "";
    drawChart("status", "chart-status", (theme) => ({
      type: "bar",
      data: {
        labels: ["Geräte"],
        datasets: segments.map((s) => ({
          label: s.label, data: [s.value], backgroundColor: theme.status[s.key], borderColor: theme.surface, borderWidth: 2,
          borderSkipped: false, barThickness: 26,
        })),
      },
      options: Object.assign(baseOptions(), {
        indexAxis: "y",
        scales: {
          x: { stacked: true, beginAtZero: true, max: total, ticks: { precision: 0, color: theme.muted }, grid: { color: theme.grid } },
          y: { stacked: true, display: false },
        },
        plugins: {
          legend: { position: "bottom", labels: { color: theme.text, boxWidth: 12, filter: (item, data) => (data.datasets[item.datasetIndex].data[0] || 0) > 0 } },
          tooltip: { callbacks: { title: () => "Status-Übersicht", label: (item) => `${item.dataset.label}: ${item.raw}` } },
        },
      }),
    }), message);
  }

  function drawRttChart() {
    if (M.tab !== "monitor" || !M.targets.has(M.selectedMac)) return;
    const note = $("chart-rtt-note");
    note.textContent = "";
    if (M.seriesError) return drawChart("rtt", "chart-rtt", null, M.seriesError);
    if (!M.series) return drawChart("rtt", "chart-rtt", null, "Verlauf wird geladen …");
    const sd = seriesData(M.series.points, M.series);
    if (!sd.samples) return drawChart("rtt", "chart-rtt", null, "Noch keine Messwerte in diesem Zeitraum.");
    note.textContent = seriesNote(M.series.bucket_s, sd);
    const range = typeof M.series.range === "string" ? M.series.range : M.range;
    const first = sd.info.length ? sd.info[0].t : null;
    const last = sd.info.length ? sd.info[sd.info.length - 1].t : null;
    const minX = toMs(M.series.since) !== null ? toMs(M.series.since) : first;
    const maxX = toMs(M.series.until) !== null ? toMs(M.series.until) : last;
    const bucket = formatBucket(M.series.bucket_s);
    drawChart("rtt", "chart-rtt", (theme) => ({
      type: "line",
      data: {
        datasets: [
          { label: "min", data: sd.min, borderWidth: 0, borderColor: "transparent", pointRadius: 0, pointHitRadius: 0, fill: false, spanGaps: false },
          {
            label: "Bereich min–max", data: sd.max, borderWidth: 0, borderColor: "transparent", backgroundColor: theme.band,
            pointRadius: 0, pointHitRadius: 0, fill: "-1", spanGaps: false,
          },
          {
            label: "Mittelwert", data: sd.avg, borderColor: theme.series[0], backgroundColor: theme.series[0], borderWidth: 2,
            pointRadius: sd.radius, pointHoverRadius: 4, fill: false, spanGaps: false, tension: 0,
          },
          {
            label: "Ausfälle", data: sd.down, showLine: false, borderColor: theme.status.offline, backgroundColor: theme.status.offline,
            pointStyle: "rectRot", pointRadius: 4, pointHoverRadius: 5, fill: false, spanGaps: false,
          },
        ],
      },
      options: Object.assign(baseOptions(), {
        normalized: true,
        interaction: { mode: "index", intersect: false },
        scales: {
          x: {
            type: "linear", min: minX, max: maxX,
            afterBuildTicks: (axis) => {
              axis.ticks = timeTicks(axis.min, axis.max, range).map((value) => ({ value: value }));
            },
            ticks: { callback: (value) => tickLabel(value, range), maxRotation: 0, autoSkip: true, color: theme.muted },
            grid: { color: theme.grid },
          },
          y: {
            beginAtZero: true,
            title: { display: true, text: "Antwortzeit in ms", color: theme.muted },
            ticks: { color: theme.muted, callback: (value) => fmt(Number(value), 1) },
            grid: { color: theme.grid },
          },
        },
        plugins: {
          legend: { labels: { color: theme.text, boxWidth: 14, filter: (item) => item.text !== "min" } },
          tooltip: {
            filter: (item, index) => index === 0,
            displayColors: false,
            callbacks: {
              title: (items) => (items.length ? formatDateTime(sd.info[items[0].dataIndex].t) + (bucket ? ` (${bucket})` : "") : ""),
              label: (item) => seriesTooltip(sd.info[item.dataIndex]),
            },
          },
        },
      }),
    }), "");
  }

  function drawTrendChart() {
    if (M.tab !== "monitor" || !M.targets.has(M.selectedMac)) return;
    if (M.trendError) return drawChart("trend", "chart-trend", null, M.trendError);
    if (!M.trend) return drawChart("trend", "chart-trend", null, "Trend wird geladen …");
    const td = trendData(M.trend);
    if (!td.n.some((n) => n > 0)) return drawChart("trend", "chart-trend", null, "Noch keine Messwerte in den letzten 30 Tagen.");
    drawChart("trend", "chart-trend", (theme) => ({
      type: "bar",
      data: {
        labels: td.labels,
        datasets: [{ label: "Verfügbarkeit", data: td.values, backgroundColor: theme.series[0], borderRadius: 4, maxBarThickness: 22, categoryPercentage: 0.9, barPercentage: 0.9 }],
      },
      options: Object.assign(baseOptions(), {
        scales: {
          x: { ticks: { color: theme.muted, maxRotation: 0, autoSkip: true }, grid: { display: false } },
          y: { min: 0, max: 100, ticks: { color: theme.muted, callback: (value) => `${value} %` }, grid: { color: theme.grid } },
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              title: (items) => (items.length ? td.titles[items[0].dataIndex] : ""),
              label: (item) => {
                const i = item.dataIndex;
                return td.n[i] ? `Verfügbarkeit ${formatPercent(td.values[i])} (${fmt(td.n[i], 0)} Messungen)` : "Keine Messwerte";
              },
            },
          },
        },
      }),
    }), "");
  }

  function drawFreqChart() {
    if (M.tab !== "alerts") return;
    if (M.statsError) return drawChart("freq", "chart-freq", null, M.statsError);
    if (!M.stats) return drawChart("freq", "chart-freq", null, "Wird geladen …");
    const fd = frequencyData(M.stats.days);
    if (!fd.labels.length || !fd.total.some((n) => n > 0)) return drawChart("freq", "chart-freq", null, "In den letzten 30 Tagen gab es keine Alerts.");
    drawChart("freq", "chart-freq", (theme) => ({
      type: "bar",
      data: {
        labels: fd.labels,
        datasets: fd.datasets.map((ds, i) => ({
          label: ds.label, data: ds.data, backgroundColor: theme.series[i % theme.series.length], borderColor: theme.surface, borderWidth: 1,
          maxBarThickness: 22, categoryPercentage: 0.9, barPercentage: 0.9,
        })),
      },
      options: Object.assign(baseOptions(), {
        interaction: { mode: "index", intersect: false },
        scales: {
          x: { stacked: true, ticks: { color: theme.muted, maxRotation: 0, autoSkip: true }, grid: { display: false } },
          y: { stacked: true, beginAtZero: true, ticks: { precision: 0, color: theme.muted }, grid: { color: theme.grid } },
        },
        plugins: {
          legend: { position: "bottom", labels: { color: theme.text, boxWidth: 12 } },
          tooltip: {
            filter: (item) => item.raw > 0,
            callbacks: {
              title: (items) => (items.length ? fd.titles[items[0].dataIndex] : ""),
              footer: (items) => (items.length ? `Zusammen: ${fd.total[items[0].dataIndex]}` : ""),
            },
          },
        },
      }),
    }), "");
  }

  function redrawCharts() {
    if (M.tab === "monitor") {
      drawStatusChart(true);
      drawRttChart();
      drawTrendChart();
    } else if (M.tab === "alerts") {
      drawFreqChart();
    }
  }

  // ---------- Reiter Überwachung ----------

  function ensureSelection() {
    const before = M.selectedMac;
    if (M.selectedMac && !M.targets.has(M.selectedMac)) M.selectedMac = null;
    if (!M.selectedMac && M.targets.size) M.selectedMac = sortTargets(Array.from(M.targets.values()))[0].mac;
    let changed = M.selectedMac !== before;
    const target = M.targets.get(M.selectedMac);
    if (target && M.checkId !== 0 && !(Array.isArray(target.checks) && target.checks.some((c) => c && c.id === M.checkId))) {
      M.checkId = 0;
      changed = true;
    }
    if (changed) {
      M.series = null;
      M.trend = null;
      M.seriesError = "";
      M.trendError = "";
    }
    return changed;
  }

  function renderMonitorView() {
    renderMonitorState();
    renderTiles();
    drawStatusChart(false);
    renderTargets();
    const changed = ensureSelection();
    renderSelection();
    if (changed && M.selectedMac) {
      drawRttChart();
      drawTrendChart();
      loadSeries();
    }
  }

  function renderMonitorState() {
    const box = $("mon-state");
    clear(box);
    const info = monitorStateInfo(M.status);
    box.append(h("span", { class: "badge mstate mstate-" + (info.state || "unknown"), text: "Überwachung " + info.label }));
    if (M.loadError) box.append(h("span", { class: "mon-reason error-text", text: M.loadError }));
    else if (info.reason) box.append(h("span", { class: "mon-reason", text: info.reason }));
    const s = M.status || {};
    const times = [];
    if (s.last_cycle) {
      const ms = formatCycleMs(s.cycle_ms);
      times.push(`Letzter Durchlauf ${formatClock(s.last_cycle)}${ms ? ` (${ms})` : ""}`);
    }
    if (s.next_cycle) times.push(`nächster ${formatClock(s.next_cycle)}`);
    const every = formatInterval(s.interval_s);
    if (every && info.state !== "off" && info.state !== "stopped") times.push(`alle ${every}`);
    if (times.length) box.append(h("span", { class: "muted mon-times", text: times.join(" · "), title: s.last_cycle ? App.formatTime(s.last_cycle) : "" }));
    const btn = $("btn-mon-run");
    const run = runButtonState(M.status, Array.from(M.targets.values()));
    btn.disabled = run.disabled || M.running;
    btn.title = M.running ? "Wird gestartet …" : run.title;
  }

  function renderTiles() {
    const box = $("mon-tiles");
    clear(box);
    const counts = countStatuses(Array.from(M.targets.values()));
    for (const key of ["online", "degraded", "offline", "paused"]) {
      box.append(
        h("div", { class: "tile tile-" + key }, h("span", { class: "tile-num", text: String(counts[key]) }), h("span", { class: "tile-label", text: TARGET_STATUS_LABELS[key] }))
      );
    }
    if (counts.unknown) {
      box.append(
        h("div", { class: "tile tile-unknown" }, h("span", { class: "tile-num", text: String(counts.unknown) }), h("span", { class: "tile-label", text: "noch unbekannt" }))
      );
    }
  }

  function targetRow(t, now) {
    const d = targetDevice(t);
    const name = targetName(t);
    const selected = t.mac === M.selectedMac;
    const cls = ["target-row"];
    if (selected) cls.push("row-selected");
    if (t.status === "offline") cls.push("row-down");
    const tr = h("tr", { class: cls.join(" "), tabindex: "0", dataset: { mac: t.mac, focusKey: "t:" + t.mac }, "aria-current": selected ? "true" : false });

    const nameCell = h("td", { class: "col-name" }, h("span", { class: "name", text: name }));
    if (t.enabled === false) nameCell.append(" ", h("span", { class: "badge badge-unknown", text: "aus", title: "Überwachung für dieses Gerät abgeschaltet" }));
    if (App.device(t.mac)) {
      nameCell.append(
        " ",
        h("button", { type: "button", class: "link-btn", text: "Details", dataset: { open: t.mac, focusKey: "o:" + t.mac }, "aria-label": `Details zu ${name}` })
      );
    }
    tr.append(nameCell);
    tr.append(h("td", { class: "col-ip mono", text: (d && d.ip) || "" }));

    const status = h("td", { class: "col-mstatus" }, statusBadge(t.status));
    const since = formatSince(t.status_since, now);
    if (since) status.append(h("span", { class: "since", text: since, title: App.formatTime(t.status_since) }));
    const detail = t.status === "paused" ? t.pause_reason : t.status === "offline" || t.status === "degraded" ? t.last_detail : "";
    if (detail) status.append(h("span", { class: "cell-detail", text: String(detail) }));
    tr.append(status);

    tr.append(h("td", { class: "col-num", text: formatRtt(t.last_rtt_ms), title: methodLabel(t.last_method) ? "Geprüft mit " + methodLabel(t.last_method) : "" }));
    const av = t.availability && typeof t.availability === "object" ? t.availability : {};
    tr.append(h("td", { class: "col-num", text: formatAvailability(av["24h"]), title: availabilityTitle(av["24h"]) }));
    tr.append(h("td", { class: "col-num", text: formatAvailability(av["7d"]), title: availabilityTitle(av["7d"]) }));

    const services = h("td", { class: "col-services" });
    const checks = Array.isArray(t.checks) ? t.checks : [];
    if (checks.length) for (const c of checks) services.append(chipNode(c));
    else services.append(h("span", { class: "muted", text: "–", title: "Nur Erreichbarkeit" }));
    tr.append(services);
    return tr;
  }

  function renderTargets() {
    const body = $("mon-body");
    const list = sortTargets(Array.from(M.targets.values()));
    const now = Date.now();
    withFocus(body, () => {
      clear(body);
      const frag = document.createDocumentFragment();
      for (const t of list) frag.append(targetRow(t, now));
      body.append(frag);
    });
    const empty = $("mon-empty");
    empty.hidden = list.length > 0;
    if (!list.length) {
      empty.textContent = M.loadError
        ? M.loadError
        : M.loaded
          ? "Noch keine Geräte überwacht. Öffne im Reiter „Geräte“ ein Gerät und schalte im Abschnitt „Überwachung“ die Überwachung ein."
          : "Überwachung wird geladen …";
    }
    $("mon-table").hidden = !list.length;
  }

  function selectTarget(mac) {
    if (!M.targets.has(mac)) return;
    if (mac !== M.selectedMac) {
      M.selectedMac = mac;
      M.checkId = 0;
      M.series = null;
      M.trend = null;
      M.seriesError = "";
      M.trendError = "";
    }
    for (const tr of document.querySelectorAll("#mon-body tr[data-mac]")) {
      const sel = tr.dataset.mac === mac;
      tr.classList.toggle("row-selected", sel);
      if (sel) tr.setAttribute("aria-current", "true");
      else tr.removeAttribute("aria-current");
    }
    renderSelection();
    drawRttChart();
    drawTrendChart();
    loadSeries();
  }

  function renderSelection() {
    const target = M.targets.get(M.selectedMac);
    $("mon-charts").hidden = !target;
    if (!target) return;
    $("mon-chart-title").textContent = "Verlauf: " + targetName(target);
    const select = $("mon-series");
    const options = [["0", "Erreichbarkeit des Geräts"]];
    for (const c of Array.isArray(target.checks) ? target.checks : []) {
      if (!c || num(c.id) === null) continue;
      options.push([String(c.id), "Dienst: " + (c.label || checkLabel(c.kind, c.port))]);
    }
    const sig = JSON.stringify(options);
    if (select.dataset.sig !== sig) {
      // nur bei geänderter Liste neu bauen (sonst schließt jeder Durchlauf eine offene Auswahl)
      clear(select);
      for (const [value, text] of options) select.append(h("option", { value: value, text: text }));
      select.dataset.sig = sig;
    }
    if (select.value !== String(M.checkId)) select.value = String(M.checkId);
    for (const btn of document.querySelectorAll("#mon-range button[data-range]")) {
      btn.setAttribute("aria-pressed", btn.dataset.range === M.range ? "true" : "false");
    }
    $("btn-mon-detail").disabled = !App.device(target.mac);
  }

  function setRange(range) {
    if (!RANGES.some((r) => r[0] === range) || range === M.range) return;
    M.range = range;
    M.series = null;
    M.seriesError = "";
    renderSelection();
    drawRttChart();
    loadRtt();
  }

  async function runNow() {
    if (M.running) return;
    M.running = true;
    renderMonitorState();
    const res = await api("POST", MAPI.run, {});
    M.running = false;
    renderMonitorState();
    if (res.ok) {
      toast("Prüfung gestartet – die Ergebnisse erscheinen in wenigen Sekunden.", "ok", 3500);
    } else if (res.status === 409) {
      // 409: Der Monitor läuft gerade nicht (z. B. Server ohne Überwachung) – sachlich melden, Zustand neu holen
      toast(apiMessage(res.data, "Die Überwachung läuft gerade nicht."), "warn");
      scheduleMonitorReload(0);
    } else {
      toast(apiMessage(res.data, `„Jetzt prüfen“ war nicht möglich (Fehler ${res.status || "Verbindung"}).`), "error");
    }
  }

  // ---------- Reiter Alerts ----------

  function alertRow(a) {
    const sev = Object.prototype.hasOwnProperty.call(SEVERITY_LABELS, a.severity) ? a.severity : "info";
    const cls = [a.closed ? "alert-closed" : "alert-active"];
    if (a.acknowledged) cls.push("alert-acked");
    const tr = h("tr", { class: cls.join(" "), dataset: { id: String(a.id) } });
    tr.append(h("td", {}, h("span", { class: "badge sev-" + sev, text: SEVERITY_LABELS[sev] })));
    const what = h("td", { class: "col-alert" });
    what.append(h("span", { class: "alert-title", text: typeof a.title === "string" && a.title ? a.title : ALERT_RULE_LABELS[a.rule] || "Alert" }));
    if (typeof a.message === "string" && a.message) what.append(h("span", { class: "alert-msg", text: a.message }));
    what.append(h("span", { class: "alert-rule", text: ALERT_RULE_LABELS[a.rule] || String(a.rule || "") }));
    tr.append(what);

    const devCell = h("td", { class: "col-dev" });
    const dev = a.mac ? App.device(a.mac) : null;
    if (dev) {
      devCell.append(h("button", { type: "button", class: "link-btn", text: dev.display_name || a.mac, dataset: { open: a.mac, focusKey: "d:" + a.id } }));
      devCell.append(h("span", { class: "cell-detail mono", text: dev.ip || "" }));
    } else {
      devCell.append(h("span", { class: a.mac ? "mono" : "muted", text: a.mac || "–" }));
    }
    tr.append(devCell);
    tr.append(h("td", { class: "col-seen", text: App.formatTime(a.opened) }));
    tr.append(
      h("td", { class: "col-seen" }, a.closed ? h("span", { text: "beendet " + App.formatTime(a.closed) }) : h("span", { class: "badge sev-active", text: "aktiv" }))
    );
    const ackCell = h("td", { class: "col-seen" });
    if (a.acknowledged) ackCell.append(h("span", { class: "muted", text: App.formatTime(a.acknowledged) }));
    else {
      ackCell.append(
        h("button", { type: "button", class: "btn btn-small", text: "Quittieren", disabled: M.ackBusy, dataset: { ack: String(a.id), focusKey: "a:" + a.id } })
      );
    }
    tr.append(ackCell);
    return tr;
  }

  function renderAlertSummary() {
    const counts = M.alertCounts;
    const n = M.alerts.length;
    const parts = [];
    if (M.alertsLoaded) parts.push(`${n} ${n === 1 ? "Alert" : "Alerts"}${n >= ALERT_LIMIT ? ` (die neuesten ${ALERT_LIMIT})` : ""}`);
    if (counts) parts.push(`aktiv: ${counts.active}`, `unquittiert: ${counts.unacked}`);
    $("alert-summary").textContent = parts.join(" · ");
    const unacked = counts ? counts.unacked : M.alerts.filter((a) => !a.acknowledged).length;
    $("btn-ack-all").disabled = M.ackBusy || !(unacked > 0);
  }

  function renderAlerts() {
    for (const btn of document.querySelectorAll("#alert-filter button[data-state]")) {
      btn.setAttribute("aria-pressed", btn.dataset.state === M.alertFilter ? "true" : "false");
    }
    const body = $("alert-body");
    withFocus(body, () => {
      clear(body);
      const frag = document.createDocumentFragment();
      for (const a of M.alerts) frag.append(alertRow(a));
      body.append(frag);
    });
    const n = M.alerts.length;
    const empty = $("alert-empty");
    const emptyTexts = { active: "Keine aktiven Alerts – alles in Ordnung.", unacked: "Keine unquittierten Alerts.", all: "Noch keine Alerts." };
    empty.hidden = n > 0 && !M.alertsError;
    empty.textContent = M.alertsError || (M.alertsLoaded ? emptyTexts[M.alertFilter] || "" : "Alerts werden geladen …");
    $("alert-table").hidden = n === 0;
    renderAlertSummary();
  }

  async function ackAlert(id) {
    if (M.ackBusy) return;
    M.ackBusy = true;
    renderAlerts();
    const res = await api("POST", MAPI.ack(id), {});
    M.ackBusy = false;
    if (res.ok && res.data && typeof res.data === "object") {
      M.alerts = mergeAlert(M.alerts, res.data, M.alertFilter, ALERT_LIMIT);
      toast("Alert quittiert.", "ok", 2500);
    } else if (res.status === 404) {
      toast("Diesen Alert gibt es nicht mehr.", "warn");
      loadAlerts();
    } else {
      toast(apiMessage(res.data, "Quittieren war nicht möglich."), "error");
    }
    renderAlerts();
    loadAlertStats();
  }

  async function ackAll() {
    const unacked = M.alertCounts ? M.alertCounts.unacked : M.alerts.filter((a) => !a.acknowledged).length;
    if (M.ackBusy || !(unacked > 0)) return;
    if (unacked > 1 && !window.confirm(`Alle ${unacked} unquittierten Alerts quittieren?`)) return;
    M.ackBusy = true;
    renderAlerts();
    const res = await api("POST", MAPI.ackAll, {});
    M.ackBusy = false;
    if (res.ok) {
      const n = res.data && num(res.data.acknowledged) !== null ? res.data.acknowledged : 0;
      toast(`${n} ${n === 1 ? "Alert" : "Alerts"} quittiert.`, "ok", 3000);
    } else {
      toast(apiMessage(res.data, "Quittieren war nicht möglich."), "error");
    }
    renderAlerts();
    loadAlerts();
    loadAlertStats();
  }

  // ---------- Detailbereich: Abschnitt „Überwachung“ ----------

  function onDetail(device, changed) {
    if (!device) {
      D.mac = null;
      D.parts = null;
      return;
    }
    if (changed || D.mac !== device.mac) {
      D.mac = device.mac;
      D.parts = null;
      D.sigs = {};
      D.suggestions = null;
      D.sugError = "";
      D.selection = null;
      D.formDirty = false;
      D.busy = false;
      loadSuggestions(device.mac);
    }
    const hint = firewallHint(device);
    const fw = $("detail-firewall");
    fw.textContent = hint;
    fw.hidden = !hint;
    renderDetailMonitor(device);
  }

  async function loadSuggestions(mac) {
    const seq = ++seqs.sug;
    const res = await api("GET", MAPI.suggestions(mac));
    if (seq !== seqs.sug || D.mac !== mac) return;
    if (res.ok && Array.isArray(res.data)) {
      D.suggestions = res.data;
      D.sugError = "";
    } else {
      D.suggestions = [];
      D.sugError = "Dienstvorschläge nicht lesbar: " + apiMessage(res.data, "keine Antwort");
    }
    renderDetailMonitor(App.device(mac));
  }

  function setDetailMsg(text, kind) {
    if (!D.parts) return;
    D.parts.msg.className = "form-msg" + (kind ? " " + kind : "");
    D.parts.msg.textContent = text || "";
  }

  function renderPart(name, sig, fn) {
    if (D.sigs[name] === sig) return;
    D.sigs[name] = sig;
    const box = D.parts[name];
    withFocus(box, () => {
      clear(box);
      fn(box);
    });
  }

  function renderDetailMonitor(device) {
    if (!device || device.mac !== D.mac) return;
    const sec = $("detail-monitor");
    if (!D.parts) {
      clear(sec);
      D.parts = {
        privacy: h("p", { class: "privacy-hint", role: "note", hidden: true }),
        head: h("div", { class: "dm-head" }),
        checks: h("div", { class: "dm-checks" }),
        form: h("div", { class: "dm-form-wrap" }),
        msg: h("p", { class: "form-msg", role: "status" }),
      };
      D.sigs = {};
      sec.append(h("h3", { text: "Überwachung" }), D.parts.privacy, D.parts.head, D.parts.checks, D.parts.form, D.parts.msg);
    }
    const privacy = privacyHint(device);
    D.parts.privacy.textContent = privacy;
    D.parts.privacy.hidden = !privacy;

    if (!M.loaded) {
      renderPart("head", "loading:" + M.loadError, (box) => box.append(h("p", { class: "muted", text: M.loadError || "Überwachung wird geladen …" })));
      renderPart("checks", "loading", () => {});
      renderPart("form", "loading", () => {});
      return;
    }
    const target = M.targets.get(device.mac) || null;
    if (!target && D.selection === null && D.suggestions !== null) {
      D.selection = new Set(defaultSelection(mergeCheckOptions(D.suggestions, [])));
    }
    const options = mergeCheckOptions(D.suggestions || [], target ? target.checks : []);

    // Kopf: Zustand, an/aus (immer neu, der Fokus bleibt erhalten)
    D.sigs.head = null;
    renderPart("head", "x", (box) => renderDetailHead(box, device, target));

    const checkSig = JSON.stringify([
      !!target, D.busy, D.suggestions === null, D.sugError,
      options.map((o) => [o.key, o.label, o.reason, o.check ? [o.check.id, o.check.enabled, o.check.status] : null]),
      D.selection ? Array.from(D.selection).sort() : null,
    ]);
    renderPart("checks", checkSig, (box) => renderDetailChecks(box, target, options));

    const settings = App.settings() || {};
    const formSig = JSON.stringify([
      target ? [target.method, target.tcp_port, target.offline_after_min, target.rtt_threshold_ms] : null,
      settings.alert_offline_minutes, target ? null : [D.busy, D.selection ? D.selection.size : 0],
    ]);
    if (!(target && D.formDirty)) renderPart("form", formSig, (box) => (target ? renderThresholdForm(box, target) : renderStartForm(box)));
  }

  function renderDetailHead(box, device, target) {
    if (!target) {
      box.append(h("p", { class: "muted", text: "Dieses Gerät wird nicht überwacht." }));
      return;
    }
    const now = Date.now();
    const line = h("div", { class: "dm-status" }, statusBadge(target.status));
    const since = formatSince(target.status_since, now);
    if (since) line.append(h("span", { class: "since", text: since, title: App.formatTime(target.status_since) }));
    box.append(line);
    const av = target.availability && typeof target.availability === "object" ? target.availability : {};
    const rows = [
      ["Antwortzeit", formatRtt(target.last_rtt_ms) + (methodLabel(target.last_method) ? ` (${methodLabel(target.last_method)})` : "")],
      ["Verfügbarkeit", `24 h: ${formatAvailability(av["24h"])} · 7 d: ${formatAvailability(av["7d"])}`],
    ];
    const detail = target.status === "paused" ? target.pause_reason : target.last_detail;
    if (detail) rows.push(["Hinweis", String(detail)]);
    if (target.last_check) rows.push(["Zuletzt geprüft", App.formatTime(target.last_check)]);
    const dl = h("dl", { class: "kv" });
    for (const [label, value] of rows) dl.append(h("dt", { text: label }), h("dd", { text: value }));
    box.append(dl);

    const active = h("input", {
      type: "checkbox", checked: target.enabled !== false, disabled: D.busy, dataset: { focusKey: "h:active" },
      on: { change: (ev) => setTargetEnabled(ev.target.checked) },
    });
    box.append(h("label", { class: "check" }, active, h("span", { text: "Prüfung aktiv (aus = pausiert, Messwerte bleiben)" })));
    box.append(
      h(
        "div",
        { class: "dm-actions" },
        h("button", { type: "button", class: "btn btn-small", text: "Verlauf anzeigen", dataset: { focusKey: "h:history" }, on: { click: () => showHistory(device.mac) } }),
        h("button", {
          type: "button", class: "btn btn-small btn-danger-quiet", text: "Überwachung beenden", disabled: D.busy, dataset: { focusKey: "h:stop" },
          on: { click: () => stopMonitoring(device) },
        })
      )
    );
  }

  function renderDetailChecks(box, target, options) {
    box.append(h("h4", { text: "Dienstprüfungen" }));
    if (D.suggestions === null && !target) {
      box.append(h("p", { class: "muted", text: "Vorschläge werden geladen …" }));
      return;
    }
    if (D.sugError) box.append(h("p", { class: "form-msg error", text: D.sugError }));
    if (!options.length) {
      box.append(
        h("p", {
          class: "muted",
          text: "Keine Dienstvorschläge: Der Port-Scan hat keine passenden offenen Ports gefunden. Überwacht wird dann nur die Erreichbarkeit.",
        })
      );
      return;
    }
    const used = target ? (Array.isArray(target.checks) ? target.checks.length : 0) : D.selection ? D.selection.size : 0;
    const full = used >= MAX_CHECKS_PER_TARGET;
    const list = h("ul", { class: "check-list" });
    for (const o of options) {
      const checked = target ? !!(o.check && o.check.enabled !== false) : !!(D.selection && D.selection.has(o.key));
      const blocked = !checked && !o.check && full;
      const input = h("input", {
        type: "checkbox", checked: checked, disabled: D.busy || blocked, dataset: { focusKey: "c:" + o.key },
        on: { change: (ev) => toggleCheck(o, ev.target.checked) },
      });
      const li = h("li", {}, h("label", { class: "check" }, input, h("span", { text: o.label })));
      if (o.check) li.append(chipNode(o.check, true));
      if (o.check && target) {
        li.append(
          h("button", {
            type: "button", class: "btn btn-small btn-danger-quiet", text: "Entfernen", disabled: D.busy, dataset: { focusKey: "r:" + o.key },
            "aria-label": `${o.label} entfernen`, on: { click: () => removeCheck(o) },
          })
        );
      }
      if (o.reason) li.append(h("span", { class: "check-reason", text: o.reason }));
      list.append(li);
    }
    box.append(list);
    if (full) box.append(h("p", { class: "muted small", text: `Höchstens ${MAX_CHECKS_PER_TARGET} Dienstprüfungen je Gerät.` }));
  }

  function renderStartForm(box) {
    const n = D.selection ? D.selection.size : 0;
    box.append(
      h("p", { class: "muted small", text: "Die Erreichbarkeit prüft der Monitor immer: zuerst Ping, ohne Antwort ein offener TCP-Port." }),
      h(
        "div",
        { class: "dm-actions" },
        h("button", {
          type: "button", class: "btn btn-primary", disabled: D.busy, dataset: { focusKey: "f:start" },
          text: n ? `Überwachen (mit ${n} ${n === 1 ? "Dienstprüfung" : "Dienstprüfungen"})` : "Überwachen",
          on: { click: startMonitoring },
        })
      )
    );
  }

  function renderThresholdForm(box, target) {
    const settings = App.settings() || {};
    const defaultOffline = num(settings.alert_offline_minutes) !== null ? settings.alert_offline_minutes : 5;
    const method = h("select", {});
    for (const [value, label] of REACH_METHODS) method.append(h("option", { value: value, text: label }));
    method.value = REACH_METHOD_KEYS.includes(target.method) ? target.method : "auto";
    const field = (value, placeholder) =>
      h("input", { type: "text", inputmode: "numeric", autocomplete: "off", value: num(value) !== null ? String(value).replace(".", ",") : "", placeholder: placeholder });
    const port = field(target.tcp_port, "aus den offenen Ports");
    const offline = field(target.offline_after_min, `Standard: ${defaultOffline} min`);
    const rtt = field(target.rtt_threshold_ms, "keine Regel");
    const form = h(
      "form",
      { class: "dm-form", novalidate: true, autocomplete: "off" },
      h("h4", { text: "Erreichbarkeit und Schwellen" }),
      h("label", { class: "stack" }, "Erreichbarkeitstest", method),
      h("label", { class: "stack" }, "TCP-Port für den Test (leer = aus den offenen Ports)", port),
      h("label", { class: "stack" }, `Offline-Alert nach Minuten (leer = Standard, ${defaultOffline} min)`, offline),
      h("label", { class: "stack" }, "Antwortzeit-Schwelle in ms (leer = keine Regel)", rtt),
      h("div", { class: "form-actions" }, h("button", { type: "submit", class: "btn", text: "Schwellen speichern", dataset: { focusKey: "f:save" } }))
    );
    form.addEventListener("input", () => {
      D.formDirty = true;
      setDetailMsg("");
    });
    form.addEventListener("submit", (ev) => {
      ev.preventDefault();
      saveThresholds({ method: method.value, tcp_port: port.value, offline_after_min: offline.value, rtt_threshold_ms: rtt.value });
    });
    box.append(form);
  }

  /** Eine Änderung an der Überwachung ausführen; währenddessen sind die Knöpfe gesperrt. */
  async function mutate(request) {
    const section = $("detail-monitor");
    const key = focusKeyIn(section); // gesperrte Knöpfe verlieren den Fokus – danach zurückgeben
    D.busy = true;
    renderDetailMonitor(App.device(D.mac));
    try {
      return await request();
    } finally {
      D.busy = false;
      renderDetailMonitor(App.device(D.mac));
      if (key && !focusKeyIn(section)) refocus(section, key);
    }
  }

  function acceptTarget(data) {
    if (data && typeof data === "object" && typeof data.mac === "string") {
      M.targets.set(data.mac, data);
      M.loaded = true;
      afterTargetsChanged();
    }
    scheduleMonitorReload(300);
  }

  async function startMonitoring() {
    const mac = D.mac;
    if (!mac || D.busy) return;
    const options = mergeCheckOptions(D.suggestions || [], []);
    const chosen = options.filter((o) => D.selection && D.selection.has(o.key)).map((o) => ({ kind: o.kind, port: o.port, path: o.path }));
    const res = await mutate(() => api("POST", MAPI.targets, { mac: mac, checks: chosen }));
    if (D.mac !== mac) return;
    if (res.ok) {
      setDetailMsg("Überwachung eingeschaltet.", "ok");
      toast("Überwachung eingeschaltet.", "ok", 2500);
      acceptTarget(res.data);
    } else if (res.status === 409) {
      setDetailMsg("Dieses Gerät wird bereits überwacht.");
      scheduleMonitorReload(0);
    } else if (res.status === 404) {
      setDetailMsg(apiMessage(res.data, "Das Gerät ist unbekannt. Bitte neu scannen."), "error");
    } else {
      setDetailMsg(apiMessage(res.data, "Die Überwachung konnte nicht eingeschaltet werden."), "error");
    }
  }

  async function stopMonitoring(device) {
    const mac = D.mac;
    if (!mac || D.busy) return;
    const name = device && device.display_name ? device.display_name : mac;
    if (!window.confirm(`Überwachung für „${name}“ beenden? Alle Messwerte dieses Geräts werden gelöscht.`)) return;
    const res = await mutate(() => api("DELETE", MAPI.target(mac)));
    if (D.mac !== mac) return;
    if (res.ok || res.status === 404) {
      M.targets.delete(mac);
      D.selection = null;
      D.formDirty = false;
      setDetailMsg("Überwachung beendet.", "ok");
      afterTargetsChanged();
      scheduleMonitorReload(300);
    } else {
      setDetailMsg(apiMessage(res.data, "Die Überwachung konnte nicht beendet werden."), "error");
    }
  }

  async function setTargetEnabled(enabled) {
    const mac = D.mac;
    if (!mac || D.busy) return;
    const res = await mutate(() => api("PATCH", MAPI.target(mac), { enabled: !!enabled }));
    if (D.mac !== mac) return;
    if (res.ok) {
      setDetailMsg(enabled ? "Prüfung wieder aktiv." : "Prüfung pausiert.", "ok");
      acceptTarget(res.data);
    } else {
      setDetailMsg(apiMessage(res.data, "Ändern war nicht möglich."), "error");
      renderDetailMonitor(App.device(mac)); // Häkchen auf den gespeicherten Stand zurück
    }
  }

  async function toggleCheck(option, checked) {
    const mac = D.mac;
    if (!mac || D.busy) return;
    const target = M.targets.get(mac);
    if (!target) {
      // noch nicht überwacht: nur die Auswahl ändern
      if (!D.selection) D.selection = new Set();
      if (checked && D.selection.size < MAX_CHECKS_PER_TARGET) D.selection.add(option.key);
      else D.selection.delete(option.key);
      renderDetailMonitor(App.device(mac));
      return;
    }
    let res;
    if (option.check) res = await mutate(() => api("PATCH", MAPI.check(option.check.id), { enabled: !!checked }));
    else if (checked) res = await mutate(() => api("POST", MAPI.targetChecks(mac), { kind: option.kind, port: option.port, path: option.path }));
    else return;
    if (D.mac !== mac) return;
    if (res.ok) {
      setDetailMsg(checked ? `${option.label}: wird geprüft.` : `${option.label}: abgeschaltet.`, "ok");
    } else if (res.status === 409) {
      setDetailMsg("Diese Dienstprüfung gibt es schon.");
    } else {
      setDetailMsg(apiMessage(res.data, "Ändern war nicht möglich."), "error");
    }
    D.sigs.checks = null; // Häkchen auf den gespeicherten Stand
    scheduleMonitorReload(0);
  }

  async function removeCheck(option) {
    const mac = D.mac;
    if (!mac || D.busy || !option.check) return;
    if (!window.confirm(`Dienstprüfung „${option.label}“ entfernen? Ihre Messwerte werden gelöscht.`)) return;
    const res = await mutate(() => api("DELETE", MAPI.check(option.check.id)));
    if (D.mac !== mac) return;
    if (res.ok || res.status === 404) setDetailMsg(`${option.label}: entfernt.`, "ok");
    else setDetailMsg(apiMessage(res.data, "Entfernen war nicht möglich."), "error");
    scheduleMonitorReload(0);
  }

  async function saveThresholds(form) {
    const mac = D.mac;
    const target = M.targets.get(mac);
    if (!target || D.busy) return;
    const built = buildTargetPatch(target, form);
    if (built.errors.length) {
      setDetailMsg(built.errors.join(" "), "error");
      return;
    }
    if (!Object.keys(built.patch).length) {
      D.formDirty = false;
      setDetailMsg("Keine Änderungen.");
      return;
    }
    const res = await mutate(() => api("PATCH", MAPI.target(mac), built.patch));
    if (D.mac !== mac) return;
    if (!res.ok) {
      setDetailMsg(apiMessage(res.data, "Speichern war nicht möglich."), "error");
      return;
    }
    D.formDirty = false;
    D.sigs.form = null;
    setDetailMsg("Gespeichert.", "ok");
    acceptTarget(res.data);
  }

  function showHistory(mac) {
    if (M.targets.has(mac) && mac !== M.selectedMac) {
      M.selectedMac = mac;
      M.checkId = 0;
      M.series = null;
      M.trend = null;
    }
    if (M.tab === "monitor") selectTarget(mac);
    else App.setTab("monitor");
  }

  // ---------- Einstellungen: Autostart ----------

  async function loadAutostart() {
    const block = $("set-autostart-block");
    const seq = ++seqs.autostart;
    autostartMessage("");
    const res = await api("GET", MAPI.autostart);
    if (seq !== seqs.autostart) return;
    if (!res.ok || !res.data || typeof res.data !== "object" || res.data.supported !== true) {
      block.hidden = true;
      return;
    }
    M.autostart = res.data;
    block.hidden = false;
    renderAutostart();
  }

  function autostartMessage(text, kind) {
    const msg = $("set-autostart-msg");
    msg.className = "form-msg" + (kind ? " " + kind : "");
    msg.textContent = text || "";
  }

  function renderAutostart() {
    const a = M.autostart || {};
    $("set-autostart-state").textContent = a.enabled ? "Autostart ist eingeschaltet." : "Autostart ist ausgeschaltet.";
    $("set-autostart-detail").textContent = typeof a.detail === "string" ? a.detail : "";
    const btn = $("btn-autostart");
    btn.textContent = a.enabled ? "Autostart ausschalten" : "Autostart einschalten";
    btn.disabled = M.autostartBusy;
  }

  async function toggleAutostart() {
    if (!M.autostart || M.autostartBusy) return;
    const wanted = !M.autostart.enabled;
    M.autostartBusy = true;
    renderAutostart();
    autostartMessage("Wird geändert …");
    const res = await api("PUT", MAPI.autostart, { enabled: wanted });
    M.autostartBusy = false;
    if (res.ok && res.data && typeof res.data === "object") {
      M.autostart = res.data;
      autostartMessage(res.data.enabled ? "Autostart eingeschaltet." : "Autostart ausgeschaltet.", "ok");
    } else if (res.status === 501) {
      autostartMessage("Autostart wird auf diesem System nicht unterstützt.", "error");
    } else {
      autostartMessage(apiMessage(res.data, "Autostart konnte nicht geändert werden."), "error");
    }
    renderAutostart();
  }

  // ---------- Start ----------

  function bindUi() {
    $("btn-mon-run").addEventListener("click", runNow);
    const monBody = $("mon-body");
    monBody.addEventListener("click", (ev) => {
      const open = ev.target.closest("button[data-open]");
      if (open) {
        App.openDetail(open.dataset.open);
        return;
      }
      const row = ev.target.closest("tr[data-mac]");
      if (row) selectTarget(row.dataset.mac);
    });
    monBody.addEventListener("keydown", (ev) => {
      if (ev.key !== "Enter" && ev.key !== " ") return;
      if (ev.target.closest("button")) return;
      const row = ev.target.closest("tr[data-mac]");
      if (row) {
        ev.preventDefault();
        selectTarget(row.dataset.mac);
      }
    });
    $("mon-range").addEventListener("click", (ev) => {
      const btn = ev.target.closest("button[data-range]");
      if (btn) setRange(btn.dataset.range);
    });
    $("mon-series").addEventListener("change", () => {
      const value = Number($("mon-series").value);
      M.checkId = Number.isSafeInteger(value) && value >= 0 ? value : 0;
      M.series = null;
      M.trend = null;
      drawRttChart();
      drawTrendChart();
      loadSeries();
    });
    $("btn-mon-detail").addEventListener("click", () => {
      if (M.selectedMac) App.openDetail(M.selectedMac);
    });
    $("alert-filter").addEventListener("click", (ev) => {
      const btn = ev.target.closest("button[data-state]");
      if (!btn || !ALERT_STATES.some((s) => s[0] === btn.dataset.state)) return;
      M.alertFilter = btn.dataset.state;
      M.alerts = [];
      M.alertsLoaded = false;
      renderAlerts();
      loadAlerts();
    });
    $("alert-body").addEventListener("click", (ev) => {
      const ack = ev.target.closest("button[data-ack]");
      if (ack) {
        ackAlert(Number(ack.dataset.ack));
        return;
      }
      const open = ev.target.closest("button[data-open]");
      if (open) App.openDetail(open.dataset.open);
    });
    $("btn-ack-all").addEventListener("click", ackAll);
    $("btn-autostart").addEventListener("click", toggleAutostart);

    if (typeof window.matchMedia === "function") {
      const media = window.matchMedia("(prefers-color-scheme: dark)");
      if (media.addEventListener) media.addEventListener("change", redrawCharts);
    }
    // „seit …“ aktuell halten
    setInterval(() => {
      if (document.visibilityState !== "visible") return;
      if (M.tab === "monitor") renderTargets();
      if (D.mac) renderDetailMonitor(App.device(D.mac));
    }, 30000);
  }

  function init() {
    App.on("monitor.status", onMonitorStatus);
    App.on("monitor.cycle", onCycle);
    App.on("monitor.targets", () => scheduleMonitorReload(200));
    App.on("alert.opened", (data) => onAlertEvent("opened", data));
    App.on("alert.closed", (data) => onAlertEvent("closed", data));
    App.on("alert.acknowledged", (data) => onAlertEvent("acknowledged", data));
    App.on("devices.changed", () => {
      if (D.mac) schedule("sug", () => D.mac && loadSuggestions(D.mac), 500);
    });
    App.on("app.tab", (data) => onTab(data.tab));
    App.on("app.detail", (data) => onDetail(data.device, !!data.changed));
    App.on("app.status", (data) => onAppStatus(data.status));
    App.on("app.devices", () => {
      if (M.tab === "monitor") renderTargets();
      if (M.tab === "alerts") renderAlerts();
    });
    App.on("app.settings", loadAutostart);
    App.on("app.settings.saved", () => scheduleMonitorReload(400));
    App.on("app.resync", resync);
    bindUi();

    // app.js kann schon Daten haben, bevor dieses Skript lief
    onAppStatus(App.status());
    renderAlertBadge();
    const selected = App.selectedMac();
    if (selected && App.device(selected)) onDetail(App.device(selected), true);
    if (M.tab === "monitor" || M.tab === "alerts") onTab(M.tab);
    loadMonitor();
    loadOverview();
    loadAlertStats();
  }

  init();
})();
