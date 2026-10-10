/* Netzwerkscanner – Browser-Oberfläche (BAUPLAN §13).
 *
 * Reines JavaScript (ES2020), kein Build, keine externen Adressen, keine Inline-Skripte.
 * Geräte-, WLAN- und Netzwerkdaten kommen aus dem Netz und werden NIE als HTML eingesetzt,
 * sondern nur über textContent / createElement.
 *
 * Aufbau:
 *   1. Konstanten und Symbole (Kategorien, Risiko, Symbole der Karte)
 *   2. reine Hilfsfunktionen ohne DOM (in Node testbar, siehe module.exports unten)
 *   3. Oberfläche: Zustand, API, WebSocket, Kopfzeile, Wächter, Geräte, Details, Karte, Protokoll, Einstellungen
 */
"use strict";

(function () {
  // =====================================================================================
  // 1. Konstanten
  // =====================================================================================

  // Pfade der Web-API (BAUPLAN §12). Der Test tests/test_frontend_static.py prüft sie gegen den Vertrag.
  const API = {
    status: "/api/status",
    adapters: "/api/adapters",
    guard: "/api/guard",
    scan: "/api/scan",
    cancel: "/api/scan/cancel",
    job: "/api/job",
    devices: "/api/devices",
    device: (mac) => `/api/devices/${macPath(mac)}`,
    deepScan: (mac) => `/api/devices/${macPath(mac)}/deep-scan`,
    scans: "/api/scans",
    log: "/api/log",
    settings: "/api/settings",
    ouiUpdate: "/api/oui/update",
  };
  const WS_PATH = "/ws";

  // Reihenfolge und Namen wie in netscan/core/models.py
  const CATEGORY_LIST = [
    ["router", "Router"],
    ["switch", "Switch"],
    ["server", "Server/NAS"],
    ["pc", "PC"],
    ["printer", "Drucker"],
    ["iot", "IoT-Gerät"],
    ["phone", "Handy"],
    ["unknown", "Unbekannt"],
  ];
  const CATEGORY_LABELS = Object.fromEntries(CATEGORY_LIST);
  const RISK_LABELS = { low: "niedrig", medium: "mittel", high: "hoch", critical: "kritisch" };
  const RISK_ORDER = { low: 0, medium: 1, high: 2, critical: 3 };
  const JOB_KIND_LABELS = { scan: "Scan", deep_scan: "Tiefenscan", oui_update: "Herstellerliste aktualisieren" };
  const JOB_NOUNS = { scan: "Scan", deep_scan: "Tiefenscan", oui_update: "Aktualisierung der Herstellerliste" };
  const SCAN_RESULT_LABELS = { completed: "abgeschlossen", cancelled: "abgebrochen", failed: "fehlgeschlagen", blocked: "gesperrt" };
  const DISCOVERY_LABELS = { arp: "ARP", ping: "Ping", cache: "ARP-Cache des Systems", self: "eigener PC" };
  const LOG_LEVEL_LABELS = { info: "Info", warning: "Warnung", error: "Fehler" };
  const SETTINGS_EDITABLE = ["blocked_ssids_extra", "home_gateway_macs", "rate_pps", "port_timeout_ms", "port_scan_excluded_categories"];
  const HUB_ID = "__hub__";
  const MAX_LOG_LINES = 1000;

  // Farbe und Zeichnung je Kategorie (Symbole auf einer Scheibe, in Hell und Dunkel gut erkennbar)
  const ICON_COLORS = {
    router: "#2563eb",
    switch: "#0f766e",
    server: "#7c3aed",
    pc: "#475569",
    printer: "#c2410c",
    iot: "#15803d",
    phone: "#be185d",
    unknown: "#6b7280",
  };
  const ICON_GLYPHS = {
    router:
      '<rect x="16" y="35" width="32" height="12" rx="3"/><path d="M23 35L20 21M41 35L44 21"/>' +
      '<circle cx="24" cy="41" r="1.4" fill="#fff" stroke="none"/><circle cx="30" cy="41" r="1.4" fill="#fff" stroke="none"/>' +
      '<circle cx="36" cy="41" r="1.4" fill="#fff" stroke="none"/>',
    switch:
      '<rect x="13" y="24" width="38" height="15" rx="2"/>' +
      '<rect x="18" y="29" width="5" height="5" fill="#fff" stroke="none"/><rect x="26" y="29" width="5" height="5" fill="#fff" stroke="none"/>' +
      '<rect x="34" y="29" width="5" height="5" fill="#fff" stroke="none"/><rect x="42" y="29" width="5" height="5" fill="#fff" stroke="none"/>' +
      '<path d="M18 46h28M22 43l-4 3 4 3M42 43l4 3-4 3"/>',
    server:
      '<rect x="17" y="15" width="30" height="14" rx="2"/><rect x="17" y="34" width="30" height="14" rx="2"/>' +
      '<circle cx="24" cy="22" r="1.7" fill="#fff" stroke="none"/><circle cx="24" cy="41" r="1.7" fill="#fff" stroke="none"/>' +
      '<path d="M31 22h10M31 41h10"/>',
    pc: '<rect x="14" y="17" width="36" height="23" rx="2.5"/><path d="M32 40v7M23 47h18"/>',
    printer:
      '<rect x="22" y="14" width="20" height="11" rx="1"/><rect x="13" y="25" width="38" height="16" rx="3"/>' +
      '<rect x="21" y="35" width="22" height="14" rx="1" fill="@COLOR@"/><path d="M26 41h12M26 45h8"/>' +
      '<circle cx="45" cy="30" r="1.3" fill="#fff" stroke="none"/>',
    iot:
      '<rect x="22" y="22" width="20" height="20" rx="2.5"/><circle cx="32" cy="32" r="3" fill="#fff" stroke="none"/>' +
      '<path d="M28 22v-6M36 22v-6M28 42v6M36 42v6M22 28h-6M22 36h-6M42 28h6M42 36h6"/>',
    phone: '<rect x="22" y="13" width="20" height="38" rx="4.5"/><path d="M29 18.5h6"/><circle cx="32" cy="45" r="1.5" fill="#fff" stroke="none"/>',
    unknown:
      '<path d="M24.5 26a8 8 0 1 1 11.5 7.2c-2.6 1.4-4 2.7-4 5.6"/><circle cx="32" cy="46" r="2" fill="#fff" stroke="none"/>',
  };

  // =====================================================================================
  // 2. Reine Hilfsfunktionen (kein DOM)
  // =====================================================================================

  function macPath(mac) {
    return encodeURIComponent(String(mac)).replace(/%3A/gi, ":");
  }

  function categoryLabel(category) {
    return CATEGORY_LABELS[category] || category || "Unbekannt";
  }

  function plural(n, one, many) {
    return n === 1 ? one : many;
  }

  function isNumber(value) {
    return typeof value === "number" && Number.isFinite(value);
  }

  /** IPv4 als Zahl, damit 192.168.178.9 vor 192.168.178.10 sortiert. Ungültiges ans Ende. */
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

  function compareText(a, b) {
    return String(a || "").localeCompare(String(b || ""), "de", { sensitivity: "base", numeric: true });
  }

  function riskRank(risk) {
    return Object.prototype.hasOwnProperty.call(RISK_ORDER, risk) ? RISK_ORDER[risk] : -1;
  }

  /** Vergleich für die Gerätetabelle: key = ip | name | category | risk, dir = 1 oder -1. */
  function compareDevices(a, b, key, dir) {
    let result = 0;
    if (key === "name") {
      result = compareText(a.display_name, b.display_name);
    } else if (key === "category") {
      result = compareText(a.category_label || categoryLabel(a.category), b.category_label || categoryLabel(b.category));
    } else if (key === "risk") {
      result = riskRank(a.max_risk) - riskRank(b.max_risk);
      if (result === 0) result = (a.ports || []).length - (b.ports || []).length;
    } else {
      result = ipKey(a.ip) - ipKey(b.ip);
    }
    if (result !== 0) return result * dir;
    const tie = ipKey(a.ip) - ipKey(b.ip);
    if (tie !== 0) return tie;
    return compareText(a.mac, b.mac);
  }

  function defaultSortDir(key) {
    return key === "risk" ? -1 : 1; // riskanteste Geräte zuerst
  }

  /** Sucht in allen sichtbaren Feldern; needle muss klein geschrieben sein. */
  function matchesFilter(device, needle) {
    if (!needle) return true;
    const names = device.names || {};
    const ssdp = device.ssdp || {};
    const parts = [
      device.display_name, device.custom_name, device.hostname, device.ip, device.mac, device.vendor,
      device.category_label, device.note, names.dns, names.netbios, names.mdns,
      ssdp.friendly_name, ssdp.model_name, ssdp.manufacturer,
      device.is_new ? "neu" : "", device.online ? "online" : "offline",
      device.is_gateway ? "router gateway" : "", device.is_self ? "dieser pc" : "", device.mac_random ? "privat" : "",
    ];
    for (const p of device.ports || []) parts.push(`${p.port}`, p.service);
    return parts.filter(Boolean).join("\n").toLowerCase().includes(needle);
  }

  function formatDuration(seconds) {
    if (!isNumber(seconds)) return "";
    if (seconds < 1) return "unter 1 s";
    const total = Math.round(seconds);
    if (total < 60) return `${total} s`;
    const min = Math.floor(total / 60);
    const sec = total % 60;
    return sec ? `${min} min ${sec} s` : `${min} min`;
  }

  /** ISO-Zeit (UTC) lokal formatiert; "" bei ungültiger Eingabe. */
  function formatTime(iso, withYear) {
    if (!iso) return "";
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return "";
    const opts = { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" };
    if (withYear !== false) opts.year = "numeric";
    return date.toLocaleString("de-DE", opts);
  }

  function formatNumber(n) {
    return isNumber(n) ? n.toLocaleString("de-DE") : "–";
  }

  /** Text und Tonart für das Ende eines Auftrags (Ereignis job.finished). */
  function describeResult(res) {
    const kind = res && res.kind;
    const what = JOB_NOUNS[kind] || "Auftrag";
    const sum = (res && res.summary) || {};
    const error = res && res.error ? String(res.error) : "";
    const dur = isNumber(sum.duration_s) ? formatDuration(sum.duration_s) : "";
    switch (res && res.result) {
      case "completed": {
        const detail = [];
        if (kind === "scan") {
          if (isNumber(sum.devices)) detail.push(`${sum.devices} ${plural(sum.devices, "Gerät", "Geräte")}`);
          if (isNumber(sum.new)) detail.push(`${sum.new} neu`);
        } else if (kind === "deep_scan") {
          if (isNumber(sum.open_ports)) detail.push(`${sum.open_ports} ${plural(sum.open_ports, "offener Port", "offene Ports")}`);
          if (isNumber(sum.new_ports)) detail.push(`${sum.new_ports} neu`);
        } else if (kind === "oui_update") {
          if (isNumber(sum.entries)) detail.push(`${formatNumber(sum.entries)} Einträge`);
        }
        if (dur) detail.push(`Dauer ${dur}`);
        if (kind === "scan" && sum.network) detail.push(String(sum.network));
        return { tone: "ok", text: `${what} abgeschlossen${detail.length ? ": " + detail.join(", ") : "."}` };
      }
      case "cancelled":
        return { tone: "warn", text: `${what} abgebrochen.` };
      case "blocked":
        return { tone: "error", text: `${what} gesperrt${error ? ": " + error : "."}` };
      case "failed":
        return { tone: "error", text: `${what} fehlgeschlagen${error ? ": " + error : "."}` };
      default:
        return { tone: "warn", text: `${what} beendet.` };
    }
  }

  /** Fehlertext aus einer API-Antwort: FastAPI liefert detail als Text oder als Liste. */
  function apiMessage(data, fallback) {
    if (data && typeof data === "object") {
      const detail = data.detail;
      if (typeof detail === "string" && detail) return detail;
      if (Array.isArray(detail)) {
        const parts = detail
          .map((item) => (typeof item === "string" ? item : item && typeof item.msg === "string" ? item.msg : ""))
          .filter(Boolean);
        if (parts.length) return parts.join("; ");
      }
      if (detail && typeof detail === "object" && typeof detail.message === "string") return detail.message;
      if (typeof data.message === "string" && data.message) return data.message;
    }
    return fallback;
  }

  function truncate(text, max) {
    const s = String(text == null ? "" : text);
    return s.length > max ? s.slice(0, Math.max(1, max - 1)) + "…" : s;
  }

  function sameJson(a, b) {
    try {
      return JSON.stringify(a) === JSON.stringify(b);
    } catch (err) {
      return false;
    }
  }

  function guardTitle(guard) {
    switch (guard && guard.code) {
      case "ok_home": return "Heimnetz erkannt";
      case "blocked_ssid": return "Gesperrtes WLAN";
      case "blocked_gateway": return "Gesperrtes Netz (Router erkannt)";
      case "foreign_network": return "Fremdes Netz";
      case "unknown_network": return "Unbekanntes Netz";
      case "no_gateway": return "Kein Router erkannt";
      default: break;
    }
    if (guard && guard.decision === "block") return "Scan gesperrt";
    if (guard && guard.decision === "confirm") return "Bitte bestätigen";
    return "Heimnetz erkannt";
  }

  /** Zeile mit WLAN-Name und Gateway unter dem Wächter-Text. */
  function guardDetails(guard) {
    const parts = [];
    if (guard && guard.ssid) parts.push(`WLAN: „${guard.ssid}“`);
    else if (guard && guard.ssid_readable === false) parts.push("WLAN-Name nicht lesbar");
    if (guard && guard.gateway_ip) {
      parts.push(`Router: ${guard.gateway_ip}${guard.gateway_mac ? " (" + guard.gateway_mac + ")" : ""}`);
    }
    return parts.join(" · ");
  }

  /** Request-Body für POST /api/scan. */
  function buildScanRequest(adapter, mode, portScan, extra) {
    return Object.assign(
      { adapter: adapter, mode: mode === "registered" ? "registered" : "full", port_scan: !!portScan, confirm_foreign: false, remember_home: false },
      extra || {}
    );
  }

  /** Nur die geänderten Felder für PATCH /api/devices/{mac}. Kategorie "auto" nur, wenn sie wirklich geändert wurde. */
  function buildDevicePatch(device, form) {
    const patch = {};
    const name = String(form.custom_name || "").trim();
    if (name !== (device.custom_name || "")) patch.custom_name = name;
    const initialCategory = device.category_source === "user" ? device.category : "auto";
    if (form.category !== initialCategory) patch.category = form.category;
    const note = String(form.note || "");
    if (note !== (device.note || "")) patch.note = note;
    if (!!form.known !== !!device.known) patch.known = !!form.known;
    if (!!form.port_scan_excluded !== !!device.port_scan_excluded) patch.port_scan_excluded = !!form.port_scan_excluded;
    return patch;
  }

  /** Nur geänderte, erlaubte Einstellungen für PUT /api/settings. */
  function diffSettings(original, working) {
    const changes = {};
    for (const key of SETTINGS_EDITABLE) {
      if (!working || !(key in working)) continue;
      const before = original ? original[key] : undefined;
      const after = working[key];
      if (Array.isArray(after)) {
        const a = key === "port_scan_excluded_categories" ? [...(before || [])].sort() : [...(before || [])];
        const b = key === "port_scan_excluded_categories" ? [...after].sort() : [...after];
        if (!sameJson(a, b)) changes[key] = [...after];
      } else if (before !== after) {
        changes[key] = after;
      }
    }
    return changes;
  }

  /** Positionen auf Ringen um die Mitte (0, 0): Startanordnung der Karte (ohne Physik, gleichmäßig verteilt). */
  function ringLayout(count) {
    const out = [];
    let ring = 0;
    let placed = 0;
    while (placed < count) {
      const radius = 240 + ring * 175;
      const capacity = Math.max(6, Math.floor((2 * Math.PI * radius) / 150));
      const n = Math.min(capacity, count - placed);
      const offset = -Math.PI / 2 + (ring % 2) * (Math.PI / Math.max(n, 2));
      for (let i = 0; i < n; i += 1) {
        const angle = offset + (2 * Math.PI * i) / n;
        out.push({ x: Math.round(Math.cos(angle) * radius), y: Math.round(Math.sin(angle) * radius) });
      }
      placed += n;
      ring += 1;
    }
    return out;
  }

  /** Nächster freier Platz auf den Ringen (kein belegter Punkt näher als gap). occupied: [{x, y}]. */
  function freeSlot(occupied, gap) {
    const minGap = gap || 125;
    for (let ring = 0; ring < 60; ring += 1) {
      const radius = 240 + ring * 175;
      const capacity = Math.max(6, Math.floor((2 * Math.PI * radius) / 150));
      const offset = -Math.PI / 2 + (ring % 2) * (Math.PI / capacity);
      for (let i = 0; i < capacity; i += 1) {
        const angle = offset + (2 * Math.PI * i) / capacity;
        const x = Math.round(Math.cos(angle) * radius);
        const y = Math.round(Math.sin(angle) * radius);
        if (Math.hypot(x, y) >= minGap && occupied.every((p) => Math.hypot(p.x - x, p.y - y) >= minGap)) return { x: x, y: y };
      }
    }
    return { x: 20000, y: 0 };
  }

  /** Plan der Karte: Router (is_gateway) in der Mitte, alle anderen per Kante daran (Stern). */
  function planMap(devices) {
    const sorted = [...devices].sort((a, b) => ipKey(a.ip) - ipKey(b.ip) || compareText(a.mac, b.mac));
    const hub = sorted.find((d) => d.is_gateway) || null;
    const hubId = hub ? hub.mac : HUB_ID;
    const others = sorted.filter((d) => d !== hub);
    return {
      hub: hub,
      hubId: hubId,
      others: others,
      edges: others.map((d) => ({ id: "e:" + d.mac, from: hubId, to: d.mac, offline: d.online === false })),
    };
  }

  function nodeLabel(device) {
    return truncate(device.display_name || device.ip, 26) + "\n" + device.ip + (device.is_new ? "\nneu" : "");
  }

  function iconSvg(category) {
    const key = Object.prototype.hasOwnProperty.call(ICON_COLORS, category) ? category : "unknown";
    const color = ICON_COLORS[key];
    const glyph = ICON_GLYPHS[key].replace(/@COLOR@/g, color);
    return (
      '<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">' +
      `<rect width="64" height="64" fill="${color}"/>` +
      `<g fill="none" stroke="#fff" stroke-width="3" stroke-linecap="round" stroke-linejoin="round">${glyph}</g></svg>`
    );
  }

  function iconUri(category) {
    return "data:image/svg+xml;charset=utf-8," + encodeURIComponent(iconSvg(category));
  }

  /** Knotenbeschreibung für vis-network. colors kommt aus den CSS-Variablen (Hell/Dunkel). */
  function nodeSpec(device, isHub, colors) {
    const online = device.online !== false;
    const fresh = !!device.is_new;
    const border = fresh ? colors.fresh : online ? colors.border : colors.offline;
    return {
      id: device.mac,
      label: nodeLabel(device),
      shape: "circularImage",
      image: iconUri(device.category),
      size: isHub ? 32 : 22,
      borderWidth: fresh ? 5 : 2,
      borderWidthSelected: 5,
      opacity: online ? 1 : 0.4,
      color: {
        border: border,
        background: colors.surface,
        highlight: { border: colors.accent, background: colors.surface },
        hover: { border: colors.accent, background: colors.surface },
      },
      font: { color: online ? colors.text : colors.muted, size: 12, strokeWidth: 3, strokeColor: colors.bg },
      fixed: isHub ? { x: true, y: true } : false,
    };
  }

  // Für Tests in Node: dort gibt es kein document, wir stellen nur die reinen Funktionen bereit.
  if (typeof document === "undefined") {
    if (typeof module !== "undefined" && module.exports) {
      module.exports = {
        API, ipKey, compareDevices, defaultSortDir, matchesFilter, formatDuration, formatTime, formatNumber,
        describeResult, apiMessage, truncate, guardTitle, guardDetails, buildScanRequest, buildDevicePatch,
        diffSettings, ringLayout, freeSlot, planMap, nodeLabel, nodeSpec, iconSvg, iconUri, macPath, plural, categoryLabel,
        CATEGORY_LIST, CATEGORY_LABELS, RISK_LABELS, RISK_ORDER, JOB_KIND_LABELS, SETTINGS_EDITABLE, HUB_ID,
      };
    }
    return;
  }

  // =====================================================================================
  // 3. Oberfläche
  // =====================================================================================

  const $ = (id) => document.getElementById(id);

  const state = {
    adapters: [],
    adapterName: "",
    showVirtual: false,
    status: null,
    settings: null,
    settingsWork: null,
    job: idleJob(),
    lastResult: null,
    starting: false,
    guard: null,
    guardPending: false,
    guardContext: { type: "scan" },
    devices: new Map(),
    sortKey: "ip",
    sortDir: 1,
    filter: "",
    selectedMac: null,
    formDirty: false,
    savingDevice: false,
    tab: "devices",
    // Karte
    network: null,
    mapNodes: null,
    mapEdges: null,
    mapDirty: true,
    mapFitted: false,
    mapHubId: null,
    // Protokoll
    log: [],
    logScanId: null,
    logLoaded: false,
    scans: [],
    // WebSocket
    ws: null,
    wsAttempt: 0,
    wsTimer: null,
    wsSeen: false,
  };

  function idleJob() {
    return { job_id: null, kind: null, label: "", state: "idle", phase: null, done: 0, total: 0, message: "", started: null };
  }

  // ---------- DOM-Hilfen ----------

  /** Baut ein Element. props: class, text, dataset, on:{ereignis: funktion}, value/checked/disabled/hidden, sonst Attribute. */
  function h(tag, props, ...children) {
    const node = document.createElement(tag);
    if (props) {
      for (const key of Object.keys(props)) {
        const value = props[key];
        if (value === undefined || value === null || value === false) continue;
        if (key === "class") node.className = value;
        else if (key === "text") node.textContent = value;
        else if (key === "dataset") Object.assign(node.dataset, value);
        else if (key === "on") {
          for (const type of Object.keys(value)) node.addEventListener(type, value[type]);
        } else if (key === "value" || key === "checked" || key === "disabled" || key === "hidden" || key === "selected") node[key] = value;
        else node.setAttribute(key, value === true ? "" : String(value));
      }
    }
    for (const child of children.flat(Infinity)) {
      if (child === undefined || child === null || child === false) continue;
      node.append(child);
    }
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function badge(text, cls, title) {
    return h("span", { class: "badge " + cls, text: text, title: title });
  }

  function riskBadge(risk, title) {
    if (!risk) return null;
    return h("span", { class: "badge risk-" + risk, text: RISK_LABELS[risk] || risk, title: title });
  }

  const prefs = {
    get(key, fallback) {
      try {
        const v = window.localStorage.getItem("netscan." + key);
        return v === null ? fallback : v;
      } catch (err) {
        return fallback;
      }
    },
    set(key, value) {
      try {
        window.localStorage.setItem("netscan." + key, String(value));
      } catch (err) {
        /* privater Modus o. Ä.: nicht schlimm */
      }
    },
  };

  function toast(message, kind, ms) {
    const box = $("toasts");
    const tone = kind || "info";
    const item = h("div", { class: "toast toast-" + tone, role: tone === "error" ? "alert" : "status", text: message });
    box.append(item);
    while (box.children.length > 5) box.firstChild.remove();
    item.addEventListener("click", () => item.remove());
    setTimeout(() => item.remove(), ms || (tone === "error" ? 9000 : tone === "warn" ? 7000 : 4500));
  }

  // ---------- API ----------

  /** Ruft die API auf und wirft nie: Rückgabe {ok, status, data}. Bodies immer als application/json. */
  async function api(method, path, body, query) {
    let url = path;
    if (query) {
      const params = new URLSearchParams();
      for (const key of Object.keys(query)) {
        const value = query[key];
        if (value !== undefined && value !== null && value !== "") params.set(key, String(value));
      }
      const qs = params.toString();
      if (qs) url += "?" + qs;
    }
    const init = { method: method, headers: { Accept: "application/json" }, cache: "no-store" };
    if (method !== "GET" && method !== "HEAD") {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body === undefined ? {} : body);
    }
    let response;
    try {
      response = await fetch(url, init);
    } catch (err) {
      return { ok: false, status: 0, data: { detail: "Der Scanner-Server ist nicht erreichbar." } };
    }
    let data = null;
    try {
      data = await response.json();
    } catch (err) {
      data = null;
    }
    return { ok: response.ok, status: response.status, data: data };
  }

  // ---------- Status ----------

  async function refreshStatus() {
    const res = await api("GET", API.status);
    if (res.ok && res.data && typeof res.data === "object") {
      state.status = res.data;
      renderStatus();
      renderOuiInfo();
    } else if (!state.status) {
      clear($("status-line"));
      $("status-line").append(h("span", { class: "chip chip-warn", text: "Status nicht lesbar: " + apiMessage(res.data, "keine Antwort") }));
    }
  }

  function chip(text, tone, title) {
    return h("span", { class: "chip chip-" + tone, text: text, title: title });
  }

  function renderStatus() {
    const box = $("status-line");
    clear(box);
    const s = state.status;
    if (!s) {
      box.append(h("span", { text: "Status wird geladen …" }));
      return;
    }
    const scapy = s.scapy || {};
    const oui = s.oui || {};
    box.append(chip("Adminrechte: " + (s.admin ? "ja" : "nein"), s.admin ? "ok" : "warn"));
    box.append(chip("Scapy/Npcap: " + (scapy.available ? "bereit" : "nicht verfügbar"), scapy.available ? "ok" : "warn", scapy.reason || ""));
    box.append(
      chip(
        "Herstellerliste: " + formatNumber(oui.entries) + " Einträge" + (oui.source ? " · " + oui.source : ""),
        isNumber(oui.entries) && oui.entries > 0 ? "ok" : "warn"
      )
    );
    if (!s.admin || !scapy.available) {
      const why = [];
      if (!s.admin) why.push("Adminrechte fehlen");
      if (!scapy.available) why.push("Scapy/Npcap nicht verfügbar" + (scapy.reason ? " (" + scapy.reason + ")" : ""));
      box.append(h("strong", { class: "status-warning", text: "Ohne Npcap/Adminrechte nur Ping-Suche – " + why.join("; ") + "." }));
    }
    box.append(h("span", { text: "Version " + (s.version || "?") + (s.platform ? " · " + s.platform : "") }));
  }

  // ---------- Auftrag, Fortschritt, Knöpfe ----------

  async function refreshJob() {
    const res = await api("GET", API.job);
    if (res.ok && res.data && typeof res.data === "object") applyJobStatus(res.data);
  }

  function applyJobStatus(job) {
    state.job = Object.assign(idleJob(), job || {});
    updateControls();
    renderJob();
  }

  function jobBusy() {
    return state.job.state !== "idle";
  }

  function updateControls() {
    const busy = jobBusy();
    const blocked = !!(state.guard && state.guard.decision === "block");
    const start = $("btn-start");
    start.disabled = busy || blocked || state.guardPending || state.starting || !state.adapterName;
    start.title = blocked ? "Dieses Netz ist gesperrt." : busy ? "Es läuft bereits ein Auftrag." : "";
    const cancel = $("btn-cancel");
    cancel.disabled = state.job.state !== "running";
    cancel.textContent = state.job.state === "cancelling" ? "Wird abgebrochen …" : "Abbrechen";
    for (const id of ["adapter", "mode", "port-scan", "show-virtual"]) $(id).disabled = busy;
    $("btn-oui-update").disabled = busy;
    updateDeepButton();
    renderGuardButtons();
  }

  let renderJobQueued = false;
  function renderJobSoon() {
    if (renderJobQueued) return;
    renderJobQueued = true;
    requestAnimationFrame(() => {
      renderJobQueued = false;
      renderJob();
    });
  }

  function renderJob() {
    const job = state.job;
    const progress = $("job-progress");
    const text = $("job-text");
    const result = $("job-result");
    clear(text);
    if (job.state === "idle") {
      progress.hidden = true;
      if (state.lastResult) {
        result.hidden = false;
        result.className = "job-result tone-" + state.lastResult.tone;
        result.textContent = state.lastResult.text;
      } else {
        text.textContent = "Bereit.";
        result.hidden = true;
      }
      return;
    }
    result.hidden = true;
    progress.hidden = false;
    if (job.total > 0) {
      progress.max = job.total;
      progress.value = Math.min(job.done, job.total);
    } else {
      progress.removeAttribute("value"); // unbestimmt
    }
    text.append(h("strong", { text: job.label || JOB_KIND_LABELS[job.kind] || "Auftrag" }));
    if (job.phase) text.append(" · " + job.phase);
    if (job.total > 0) text.append(` · ${job.done}/${job.total}`);
    if (job.message) text.append(" · " + job.message);
    if (job.state === "cancelling") text.append(" (wird abgebrochen)");
  }

  // ---------- Scan starten, abbrechen ----------

  async function startScan(extra) {
    if (!state.adapterName) {
      toast("Bitte zuerst einen Netzwerkadapter wählen.", "warn");
      return;
    }
    const body = buildScanRequest(state.adapterName, $("mode").value, $("port-scan").checked, extra);
    state.starting = true;
    updateControls();
    const res = await api("POST", API.scan, body);
    state.starting = false;
    handleStartResponse(res, { type: "scan" }, "Scan");
    updateControls();
  }

  async function startDeepScan(mac, confirmForeign) {
    state.starting = true;
    updateControls();
    const res = await api("POST", API.deepScan(mac), { confirm_foreign: !!confirmForeign });
    state.starting = false;
    handleStartResponse(res, { type: "deep", mac: mac }, "Tiefenscan");
    updateControls();
  }

  /** Gemeinsame Antwortbehandlung für POST /api/scan, /api/devices/{mac}/deep-scan und /api/oui/update. */
  function handleStartResponse(res, context, what) {
    const data = res.data && typeof res.data === "object" ? res.data : {};
    if (res.ok) {
      state.lastResult = null;
      if (state.job.state === "idle" && context.type !== "oui") {
        state.job = Object.assign(idleJob(), { state: "running", label: "Wird gestartet …" }); // bis job.started eintrifft
        renderJob();
      }
      toast(`${what} gestartet.`, "ok");
      const warnings = Array.isArray(data.warning) ? data.warning : data.warning ? [data.warning] : [];
      for (const w of warnings) toast(String(w), "warn", 10000);
      refreshJob();
      return true;
    }
    if (res.status === 423 || res.status === 428) {
      const blocked = res.status === 423;
      const guard =
        data.guard && typeof data.guard === "object"
          ? data.guard
          : { decision: blocked ? "block" : "confirm", code: null, reason: apiMessage(data, blocked ? "Scan gesperrt." : "Bitte bestätigen.") };
      state.guard = guard;
      state.guardContext = context;
      renderGuard();
      updateControls();
      if (!blocked) pulseGuard();
      toast(apiMessage(data, guard.reason || "Nicht möglich."), blocked ? "error" : "warn");
      return false;
    }
    if (res.status === 409) {
      toast(context.type === "oui" ? "Es läuft bereits ein Auftrag." : "Es läuft bereits ein Scan.", "warn");
      refreshJob();
      return false;
    }
    toast(apiMessage(res.data, `${what} konnte nicht gestartet werden (Fehler ${res.status || "Verbindung"}).`), "error");
    return false;
  }

  async function cancelScan() {
    if (state.job.state !== "running") return;
    const res = await api("POST", API.cancel, {});
    if (!res.ok) {
      toast(apiMessage(res.data, "Abbrechen nicht möglich."), "error");
    } else if (res.data && res.data.cancelled === false) {
      toast("Es läuft gerade nichts, das man abbrechen könnte.", "info");
      refreshJob();
    } else {
      state.job.state = "cancelling";
      updateControls();
      renderJob();
    }
  }

  // ---------- Adapter ----------

  async function loadAdapters() {
    const res = await api("GET", API.adapters, undefined, { include_virtual: state.showVirtual ? "true" : "false" });
    const select = $("adapter");
    if (!res.ok || !Array.isArray(res.data)) {
      toast("Netzwerkadapter konnten nicht gelesen werden: " + apiMessage(res.data, "keine Antwort"), "error");
      return;
    }
    state.adapters = res.data;
    clear(select);
    if (!state.adapters.length) {
      select.append(h("option", { value: "", text: "Kein Netzwerkadapter gefunden", disabled: true, selected: true }));
      state.adapterName = "";
      updateControls();
      return;
    }
    const wanted = [state.adapterName, prefs.get("adapter", ""), state.settings && state.settings.last_adapter];
    let chosen = null;
    for (const name of wanted) {
      if (name && state.adapters.some((a) => a.name === name)) {
        chosen = name;
        break;
      }
    }
    if (!chosen) {
      const preferred = state.adapters.find((a) => a.is_up && !a.is_virtual && a.ipv4) || state.adapters[0];
      chosen = preferred.name;
    }
    for (const a of state.adapters) {
      const label = `${a.name} · ${a.ipv4} · ${a.network}${a.is_up ? "" : " (nicht verbunden)"}${a.is_virtual ? " (virtuell)" : ""}`;
      const detail = [a.description, a.mac, a.is_wireless ? "WLAN" : "kabelgebunden"].filter(Boolean).join(" · ");
      select.append(h("option", { value: a.name, text: label, title: detail }));
    }
    select.value = chosen;
    state.adapterName = chosen;
    updateControls();
  }

  async function onAdapterChanged() {
    state.adapterName = $("adapter").value;
    prefs.set("adapter", state.adapterName);
    await refreshGuard(true);
  }

  // ---------- Wächter ----------

  let guardSeq = 0;
  async function refreshGuard(resetContext) {
    if (resetContext) state.guardContext = { type: "scan" };
    if (!state.adapterName) {
      state.guard = null;
      state.guardPending = false;
      renderGuard();
      updateControls();
      return;
    }
    const seq = ++guardSeq;
    state.guardPending = true;
    updateControls();
    const res = await api("GET", API.guard, undefined, { adapter: state.adapterName });
    if (seq !== guardSeq) return; // eine neuere Abfrage läuft
    state.guardPending = false;
    if (res.ok && res.data && res.data.decision) {
      state.guard = res.data;
    } else {
      state.guard = null;
      toast("Netzprüfung fehlgeschlagen: " + apiMessage(res.data, "keine Antwort"), "warn");
    }
    renderGuard();
    updateControls();
  }

  function onGuardEvent(data) {
    const guard = data && data.guard;
    if (guard && guard.decision && sameJson(guard, state.guard)) return; // nichts Neues (vermeidet Schleifen)
    if (guard && guard.decision) {
      state.guard = guard;
      renderGuard();
      updateControls();
    }
    refreshGuard(false);
  }

  function renderGuard() {
    const band = $("guard-band");
    clear(band);
    const guard = state.guard;
    if (!guard) {
      band.hidden = true;
      return;
    }
    const tone = guard.decision === "block" ? "block" : guard.decision === "confirm" ? "confirm" : "allow";
    band.hidden = false;
    band.className = "guard guard-" + tone;
    band.setAttribute("role", tone === "block" ? "alert" : "status");
    const body = h("div", { class: "guard-body" }, h("strong", { class: "guard-title", text: guardTitle(guard) }));
    if (guard.reason) body.append(h("span", { class: "guard-reason", text: guard.reason }));
    const details = guardDetails(guard);
    if (details) body.append(h("span", { class: "guard-details", text: details }));
    if (tone === "confirm" && state.guardContext.type === "deep") {
      const dev = state.devices.get(state.guardContext.mac);
      body.append(h("span", { class: "guard-details", text: "Betrifft: Tiefenscan von " + (dev ? dev.display_name : state.guardContext.mac) }));
    }
    band.append(body);
    if (tone === "confirm") {
      // Nur bei "confirm" gibt es Knöpfe. Bei "block" bewusst keinen einzigen.
      const actions = h("div", { class: "guard-actions" });
      actions.append(
        h("button", { type: "button", class: "btn", dataset: { role: "once" }, text: "Nur diesmal scannen", on: { click: confirmOnce } })
      );
      // „Heimnetz merken“ geht nur mit bekannter Router-MAC (sonst gäbe es nichts zu merken)
      if (state.guardContext.type !== "deep" && guard.gateway_mac) {
        actions.append(
          h("button", { type: "button", class: "btn", dataset: { role: "home" }, text: "Das ist mein Heimnetz", on: { click: confirmHome } })
        );
      }
      band.append(actions);
    }
    renderGuardButtons();
  }

  function renderGuardButtons() {
    const disabled = jobBusy() || state.starting;
    for (const btn of document.querySelectorAll("#guard-band .guard-actions button")) btn.disabled = disabled;
  }

  function pulseGuard() {
    const band = $("guard-band");
    band.classList.remove("pulse");
    void band.offsetWidth; // Animation neu starten
    band.classList.add("pulse");
    band.scrollIntoView({ block: "nearest" });
  }

  function confirmOnce() {
    if (state.guardContext.type === "deep") return startDeepScan(state.guardContext.mac, true);
    return startScan({ confirm_foreign: true });
  }

  function confirmHome() {
    return startScan({ confirm_foreign: true, remember_home: true });
  }

  // ---------- Geräte laden ----------

  let devicesSeq = 0;
  async function loadDevices() {
    const seq = ++devicesSeq;
    const res = await api("GET", API.devices);
    if (seq !== devicesSeq) return;
    if (!res.ok || !Array.isArray(res.data)) {
      toast("Geräteliste konnte nicht geladen werden: " + apiMessage(res.data, "keine Antwort"), "error");
      return;
    }
    const map = new Map();
    for (const d of res.data) if (d && d.mac) map.set(d.mac, d);
    state.devices = map;
    afterDevicesChanged();
  }

  let devicesReloadTimer = null;
  function scheduleDevicesReload() {
    clearTimeout(devicesReloadTimer);
    devicesReloadTimer = setTimeout(loadDevices, 150);
  }

  let renderTimer = null;
  function scheduleRender() {
    if (renderTimer) return;
    renderTimer = setTimeout(() => {
      renderTimer = null;
      afterDevicesChanged();
    }, 200);
  }

  function afterDevicesChanged() {
    renderDevices();
    if (state.tab === "map") renderMap();
    else state.mapDirty = true;
    if (state.selectedMac) {
      if (state.devices.has(state.selectedMac)) renderDetail(false);
      else closeDetail();
    }
  }

  // ---------- Reiter Geräte ----------

  function visibleDevices() {
    const needle = state.filter.trim().toLowerCase();
    const list = [];
    for (const d of state.devices.values()) if (matchesFilter(d, needle)) list.push(d);
    list.sort((a, b) => compareDevices(a, b, state.sortKey, state.sortDir));
    return list;
  }

  function statusCell(d) {
    const cell = h("td", { class: "col-status" });
    cell.append(h("span", { class: "dot " + (d.online ? "dot-on" : "dot-off"), title: d.online ? "online" : "offline" }));
    cell.append(h("span", { class: "sr-only", text: d.online ? "online" : "offline" }));
    cell.append(statusBadge(d));
    return cell;
  }

  function statusBadge(d) {
    if (d.is_new) return badge("neu", "badge-new", "Neues, noch nicht als bekannt markiertes Gerät");
    if (d.known) return badge("bekannt", "badge-known", "Von dir als bekannt markiert");
    return badge("unbekannt", "badge-unknown", "Noch nicht als bekannt markiert");
  }

  function portsCell(d) {
    const cell = h("td", { class: "col-ports" });
    const ports = d.ports || [];
    if (ports.length) {
      cell.append(h("span", { text: String(ports.length) + " " }));
      cell.append(riskBadge(d.max_risk, "Höchstes Risiko: " + (RISK_LABELS[d.max_risk] || d.max_risk)));
    } else if (d.port_scan_excluded) {
      cell.append(h("span", { class: "muted", text: "ausgenommen", title: "Vom Port-Scan ausgenommen" }));
    } else {
      cell.append(h("span", { class: "muted", text: "–" }));
    }
    return cell;
  }

  function deviceRow(d) {
    const cls = [];
    if (d.is_new) cls.push("row-new");
    if (!d.online) cls.push("row-offline");
    if (d.mac === state.selectedMac) cls.push("row-selected");
    const tr = h("tr", { class: cls.join(" "), tabindex: "0", dataset: { mac: d.mac }, "aria-current": d.mac === state.selectedMac ? "true" : false });
    tr.append(statusCell(d));

    const name = h("td", { class: "col-name" }, h("span", { class: "name", text: d.display_name }));
    if (d.is_gateway) name.append(" ", badge("Router", "badge-role", "Standard-Gateway dieses Netzes"));
    if (d.is_self) name.append(" ", badge("Dieser PC", "badge-role", "Der PC, auf dem der Scanner läuft"));
    tr.append(name);

    tr.append(h("td", { class: "col-ip mono", text: d.ip }));

    const mac = h("td", { class: "col-mac" }, h("span", { class: "mono", text: d.mac }));
    if (d.mac_random) mac.append(" ", badge("privat", "badge-private", "Zufällige (private) MAC-Adresse, z. B. bei Handys"));
    tr.append(mac);

    tr.append(h("td", { class: "col-vendor" + (d.vendor ? "" : " muted"), text: d.vendor || "–", title: d.vendor || false }));

    const cat = h("td", {}, d.category_label || categoryLabel(d.category));
    if (d.category_source === "user") cat.append(h("span", { class: "manual", text: "✎", title: "Von dir festgelegt", "aria-label": "von dir festgelegt" }));
    tr.append(cat);

    tr.append(portsCell(d));
    tr.append(h("td", { class: "col-seen", text: formatTime(d.last_seen), title: d.first_seen ? "Erstmals gesehen: " + formatTime(d.first_seen) : "" }));
    return tr;
  }

  function renderDevices() {
    const body = $("devices-body");
    const list = visibleDevices();
    clear(body);
    const frag = document.createDocumentFragment();
    for (const d of list) frag.append(deviceRow(d));
    body.append(frag);

    for (const th of document.querySelectorAll("#devices-table th[data-th]")) {
      const key = th.getAttribute("data-th");
      const active = key === state.sortKey;
      th.setAttribute("aria-sort", active ? (state.sortDir === 1 ? "ascending" : "descending") : "none");
      const arrow = th.querySelector(".arrow");
      if (arrow) arrow.textContent = active && state.sortDir === -1 ? "▼" : "▲";
    }

    const total = state.devices.size;
    let online = 0;
    let fresh = 0;
    for (const d of state.devices.values()) {
      if (d.online) online += 1;
      if (d.is_new) fresh += 1;
    }
    const countText = list.length === total ? `${total} ${plural(total, "Gerät", "Geräte")}` : `${list.length} von ${total} Geräten`;
    $("device-count").textContent = total ? `${countText} · ${online} online${fresh ? ` · ${fresh} neu` : ""}` : "";

    const empty = $("devices-empty");
    empty.hidden = list.length > 0;
    if (!list.length) {
      empty.textContent = total ? "Kein Gerät passt zur Suche." : "Noch keine Geräte. Wähle einen Adapter und starte einen Scan.";
    }
    $("devices-table").hidden = !list.length && !total;
  }

  function setSort(key) {
    if (state.sortKey === key) state.sortDir = -state.sortDir;
    else {
      state.sortKey = key;
      state.sortDir = defaultSortDir(key);
    }
    renderDevices();
  }

  // ---------- Detailbereich ----------

  function openDetail(mac) {
    if (!state.devices.has(mac)) return;
    const changed = state.selectedMac !== mac;
    state.selectedMac = mac;
    if (changed) state.formDirty = false;
    $("detail").hidden = false;
    document.body.classList.add("detail-open");
    renderDetail(changed);
    markSelectedRow();
    scheduleMapResize();
  }

  function closeDetail() {
    state.selectedMac = null;
    state.formDirty = false;
    $("detail").hidden = true;
    document.body.classList.remove("detail-open");
    markSelectedRow();
    if (state.network) state.network.unselectAll();
    scheduleMapResize();
  }

  function markSelectedRow() {
    for (const tr of document.querySelectorAll("#devices-body tr")) {
      const selected = tr.dataset.mac === state.selectedMac;
      tr.classList.toggle("row-selected", selected);
      if (selected) tr.setAttribute("aria-current", "true");
      else tr.removeAttribute("aria-current");
    }
  }

  function categoryOptions(device) {
    const select = $("d-category");
    clear(select);
    const autoLabel = device && device.category_source !== "user" ? `Automatisch (erkannt: ${device.category_label || categoryLabel(device.category)})` : "Automatisch";
    select.append(h("option", { value: "auto", text: autoLabel }));
    for (const [value, label] of CATEGORY_LIST) select.append(h("option", { value: value, text: label }));
  }

  function fillForm(d) {
    categoryOptions(d);
    $("d-name").value = d.custom_name || "";
    $("d-name").placeholder = d.display_name || "";
    $("d-category").value = d.category_source === "user" ? d.category : "auto";
    $("d-note").value = d.note || "";
    $("d-known").checked = !!d.known;
    $("d-excluded").checked = !!d.port_scan_excluded;
    state.formDirty = false;
  }

  function readForm() {
    return {
      custom_name: $("d-name").value,
      category: $("d-category").value,
      note: $("d-note").value,
      known: $("d-known").checked,
      port_scan_excluded: $("d-excluded").checked,
    };
  }

  function kv(label, value) {
    if (value === undefined || value === null || value === "" || (Array.isArray(value) && !value.length)) return [];
    return [h("dt", { text: label }), h("dd", {}, Array.isArray(value) ? value.join(", ") : value)];
  }

  function infoSection(title, rows) {
    const flat = rows.flat();
    const section = h("div", { class: "info-block" }, h("h3", { text: title }));
    if (flat.length) section.append(h("dl", { class: "kv" }, flat));
    else section.append(h("p", { class: "muted", text: "Keine Angaben." }));
    return section;
  }

  function renderDetail(forceForm) {
    const d = state.devices.get(state.selectedMac);
    if (!d) {
      closeDetail();
      return;
    }
    $("detail-title").textContent = d.display_name;
    $("detail-sub").textContent = `${d.ip} · ${d.mac}`;

    const badges = $("detail-badges");
    clear(badges);
    badges.append(h("span", { class: "dot " + (d.online ? "dot-on" : "dot-off") }), h("span", { text: d.online ? "online" : "offline" }));
    badges.append(statusBadge(d));
    if (d.is_gateway) badges.append(badge("Router", "badge-role", "Standard-Gateway dieses Netzes"));
    if (d.is_self) badges.append(badge("Dieser PC", "badge-role"));
    if (d.mac_random) badges.append(badge("privat", "badge-private", "Zufällige (private) MAC-Adresse"));
    if (d.max_risk) badges.append(riskBadge(d.max_risk, "Höchstes Risiko"));

    if (forceForm || !state.formDirty) fillForm(d);
    renderDetailInfo(d);
    renderDetailPorts(d);
    updateDeepButton();
  }

  function renderDetailInfo(d) {
    const box = $("detail-info");
    clear(box);
    const names = d.names || {};
    const ssdp = d.ssdp || null;
    const source = d.category_source === "user" ? "von dir festgelegt" : "automatisch erkannt";
    box.append(
      infoSection("Gerät", [
        kv("Status", d.online ? "online (im letzten Scan gesehen)" : "offline (im letzten Scan nicht gesehen)"),
        kv("Kategorie", `${d.category_label || categoryLabel(d.category)} (${source})`),
        kv("Begründung", d.category_reason),
        kv("Hersteller", d.vendor),
        kv("MAC-Adresse", d.mac_random ? `${d.mac} – private (zufällige) Adresse` : d.mac),
        kv("Antwortzeit", isNumber(d.rtt_ms) ? `${d.rtt_ms.toLocaleString("de-DE", { maximumFractionDigits: 1 })} ms` : ""),
        kv("TTL", isNumber(d.ttl) ? String(d.ttl) : ""),
        kv("Gefunden über", (d.discovered_by || []).map((x) => DISCOVERY_LABELS[x] || x)),
        kv("Erstmals gesehen", formatTime(d.first_seen)),
        kv("Zuletzt gesehen", formatTime(d.last_seen)),
      ])
    );
    box.append(
      infoSection("Namen", [
        kv("Hostname", d.hostname),
        kv("DNS", names.dns),
        kv("NetBIOS", names.netbios),
        kv("mDNS", names.mdns),
        kv("mDNS-Dienste", names.mdns_services),
      ])
    );
    box.append(
      infoSection(
        "SSDP/UPnP",
        ssdp
          ? [
              kv("Name", ssdp.friendly_name),
              kv("Hersteller", ssdp.manufacturer),
              kv("Modell", [ssdp.model_name, ssdp.model_number].filter(Boolean).join(" ")),
              kv("Gerätetyp", ssdp.device_type),
              kv("Server", ssdp.server),
              kv("Beschreibung", ssdp.location),
            ]
          : []
      )
    );
  }

  function renderDetailPorts(d) {
    const box = $("detail-ports");
    clear(box);
    box.append(h("h3", { text: "Offene Ports" }));
    const ports = d.ports || [];
    if (!ports.length) {
      box.append(
        h("p", {
          class: "muted",
          text: d.port_scan_excluded ? "Dieses Gerät ist vom Port-Scan ausgenommen." : "Keine offenen Ports gefunden (oder noch nicht geprüft).",
        })
      );
      return;
    }
    const table = h("table", { class: "ports-table" });
    table.append(
      h("thead", {}, h("tr", {}, h("th", { scope: "col", text: "Port" }), h("th", { scope: "col", text: "Dienst" }), h("th", { scope: "col", text: "Risiko" }), h("th", { scope: "col", text: "Begründung" }), h("th", { scope: "col", text: "Banner" })))
    );
    const body = h("tbody");
    for (const p of ports) {
      body.append(
        h(
          "tr",
          {},
          h("td", { class: "mono", text: `${p.port}/${p.proto || "tcp"}` }),
          h("td", { text: p.service || "–" }),
          h("td", {}, riskBadge(p.risk, p.risk_label) || "–"),
          h("td", { text: p.reason || "" }),
          h("td", { class: "banner", text: p.banner || "" })
        )
      );
    }
    table.append(body);
    box.append(table);
  }

  function updateDeepButton() {
    const btn = $("d-deep");
    if (!btn) return;
    const d = state.devices.get(state.selectedMac);
    const blocked = !!(state.guard && state.guard.decision === "block");
    btn.disabled = !d || jobBusy() || state.starting || blocked;
    const hint = $("d-deep-hint");
    if (blocked) hint.textContent = "Dieses Netz ist gesperrt, kein Tiefenscan möglich.";
    else if (jobBusy()) hint.textContent = "Es läuft gerade ein anderer Auftrag.";
    else if (d && d.port_scan_excluded) hint.textContent = "Dieses Gerät ist vom Port-Scan ausgenommen. Ein Tiefenscan sendet trotzdem viele Verbindungsanfragen an das Gerät.";
    else hint.textContent = "Prüft alle Ports 1–1024 dieses einen Geräts. Das sind viele Verbindungsanfragen; empfindliche Geräte können darauf reagieren.";
  }

  async function saveDevice() {
    const d = state.devices.get(state.selectedMac);
    const msg = $("d-msg");
    if (!d || state.savingDevice) return;
    const patch = buildDevicePatch(d, readForm());
    if (!Object.keys(patch).length) {
      msg.className = "form-msg";
      msg.textContent = "Keine Änderungen.";
      return;
    }
    state.savingDevice = true;
    $("d-save").disabled = true;
    msg.className = "form-msg";
    msg.textContent = "Speichere …";
    const res = await api("PATCH", API.device(d.mac), patch);
    state.savingDevice = false;
    $("d-save").disabled = false;
    if (!res.ok) {
      msg.className = "form-msg error";
      msg.textContent = apiMessage(res.data, "Speichern fehlgeschlagen.");
      return;
    }
    if (res.data && res.data.mac) state.devices.set(res.data.mac, res.data);
    state.formDirty = false;
    msg.className = "form-msg ok";
    msg.textContent = "Gespeichert.";
    toast("Gerät gespeichert.", "ok", 2500);
    if (!(res.data && res.data.mac)) scheduleDevicesReload();
    afterDevicesChanged();
  }

  // ---------- Netzwerkkarte (vis-network) ----------

  function themeColors() {
    const style = getComputedStyle(document.documentElement);
    const get = (name, fallback) => (style.getPropertyValue(name) || "").trim() || fallback;
    return {
      bg: get("--surface", "#ffffff"),
      surface: get("--surface", "#ffffff"),
      text: get("--text", "#1b1f27"),
      muted: get("--muted", "#566070"),
      border: get("--border", "#9aa3b2"),
      accent: get("--accent", "#2457d6"),
      fresh: get("--new-border", "#e8590c"),
      edge: get("--edge", "#8b95a6"),
      offline: get("--offline", "#9aa3b2"),
    };
  }

  function ensureNetwork() {
    if (state.network) return true;
    if (typeof vis === "undefined" || !vis.Network || !vis.DataSet) {
      $("map-error").hidden = false;
      return false;
    }
    $("map-error").hidden = true;
    state.mapNodes = new vis.DataSet([]);
    state.mapEdges = new vis.DataSet([]);
    const options = {
      autoResize: true,
      layout: { improvedLayout: false },
      interaction: { hover: true, dragNodes: true, dragView: true, zoomView: true, selectConnectedEdges: false },
      physics: false, // feste Ringanordnung: kein Zittern, keine Verschiebung der Ansicht
      nodes: { shape: "circularImage", font: { face: "Segoe UI, system-ui, sans-serif", size: 12 } },
      edges: { smooth: false, width: 1.5, selectionWidth: 2 },
    };
    state.network = new vis.Network($("map-canvas"), { nodes: state.mapNodes, edges: state.mapEdges }, options);
    state.network.on("click", (params) => {
      hideMapTip();
      if (params.nodes && params.nodes.length) {
        const id = params.nodes[0];
        if (id !== HUB_ID && state.devices.has(id)) openDetail(id);
      }
    });
    state.network.on("hoverNode", (params) => showMapTip(params.node, params.pointer && params.pointer.DOM));
    state.network.on("blurNode", hideMapTip);
    state.network.on("dragStart", hideMapTip);
    state.network.on("zoom", hideMapTip);
    return true;
  }

  function renderMap() {
    state.mapDirty = false;
    const devices = Array.from(state.devices.values());
    $("map-empty").hidden = devices.length > 0;
    if (!ensureNetwork()) return;
    syncMap();
  }

  function syncMap() {
    const colors = themeColors();
    const plan = planMap(Array.from(state.devices.values()));
    const net = state.network;
    const nodes = state.mapNodes;
    const edges = state.mapEdges;
    const existing = new Set(nodes.getIds());
    const wanted = new Set();
    const nodeSpecs = [];

    const oldHubId = state.mapHubId;
    const hubChanged = oldHubId !== null && oldHubId !== plan.hubId;
    state.mapHubId = plan.hubId;

    // Bereits belegte Plätze: neue Geräte bekommen einen freien Platz, vorhandene bleiben, wo sie sind.
    const positions = existing.size ? net.getPositions() : {};
    const occupied = Object.keys(positions).map((id) => positions[id]);
    const initial = existing.size === 0 ? ringLayout(plan.others.length) : null;
    const placed = [];

    if (!plan.hub && plan.others.length) {
      wanted.add(HUB_ID);
      nodeSpecs.push({
        id: HUB_ID, label: "Netz", shape: "dot", size: 14, x: 0, y: 0, fixed: { x: true, y: true }, borderWidth: 2,
        color: { background: colors.edge, border: colors.edge }, font: { color: colors.muted, size: 13, strokeWidth: 3, strokeColor: colors.bg },
      });
    }
    if (plan.hub) {
      wanted.add(plan.hub.mac);
      nodeSpecs.push(Object.assign(nodeSpec(plan.hub, true, colors), { x: 0, y: 0 }));
    }
    plan.others.forEach((d, i) => {
      wanted.add(d.mac);
      const spec = nodeSpec(d, false, colors);
      if (!existing.has(d.mac)) {
        const slot = initial ? initial[i] : freeSlot(occupied);
        occupied.push(slot);
        placed.push(slot);
        spec.x = slot.x;
        spec.y = slot.y;
      }
      nodeSpecs.push(spec);
    });

    const removeNodes = [...existing].filter((id) => !wanted.has(id));
    const wantedEdges = new Set(plan.edges.map((e) => e.id));
    const removeEdges = edges.getIds().filter((id) => !wantedEdges.has(id));
    const edgeSpecs = plan.edges.map((e) => ({
      id: e.id, from: e.from, to: e.to, dashes: e.offline ? [5, 5] : false, width: 1.5,
      color: { color: colors.edge, highlight: colors.accent, hover: colors.accent },
    }));

    if (removeEdges.length) edges.remove(removeEdges);
    if (removeNodes.length) nodes.remove(removeNodes);
    nodes.update(nodeSpecs);
    edges.update(edgeSpecs);

    // Der bisherige Router steht noch in der Mitte: an einen freien Platz rücken.
    if (hubChanged && oldHubId !== HUB_ID && wanted.has(oldHubId)) {
      const slot = freeSlot(occupied.filter((p) => p.x !== 0 || p.y !== 0));
      net.moveNode(oldHubId, slot.x, slot.y);
      placed.push(slot);
    }
    if (!state.mapFitted && nodeSpecs.length) {
      state.mapFitted = true; // beim ersten Zeichnen einpassen, sonst bleibt die Ansicht, wie der Nutzer sie hat
      net.fit({ animation: false });
    } else if (placed.length && placed.some((p) => !insideView(p))) {
      net.fit({ animation: { duration: 300 } }); // nur wenn ein neuer Knoten sonst außerhalb läge
    }
    if (state.selectedMac && wanted.has(state.selectedMac)) net.selectNodes([state.selectedMac]);
  }

  /** Liegt ein Punkt der Karte (Canvas-Koordinaten) im sichtbaren Ausschnitt? */
  function insideView(point) {
    const box = $("map-canvas");
    const dom = state.network.canvasToDOM(point);
    return dom.x > 40 && dom.y > 40 && dom.x < box.clientWidth - 40 && dom.y < box.clientHeight - 60;
  }

  /** „Neu anordnen“: alles zurück auf die Ringe und die Ansicht einpassen. */
  function arrangeAll() {
    if (!state.network) return;
    const plan = planMap(Array.from(state.devices.values()));
    const slots = ringLayout(plan.others.length);
    plan.others.forEach((d, i) => state.network.moveNode(d.mac, slots[i].x, slots[i].y));
    if (plan.hub) state.network.moveNode(plan.hub.mac, 0, 0);
    else if (plan.others.length) state.network.moveNode(HUB_ID, 0, 0);
    state.network.fit({ animation: { duration: 300 } });
  }

  let mapResizeTimer = null;
  function scheduleMapResize() {
    if (!state.network) return;
    clearTimeout(mapResizeTimer);
    mapResizeTimer = setTimeout(() => {
      if (state.tab !== "map" || !state.network) return;
      state.network.setSize("100%", "100%");
      state.network.redraw();
    }, 60);
  }

  function showMapTip(id, point) {
    const tip = $("map-tip");
    const d = state.devices.get(id);
    clear(tip);
    if (!d) {
      if (id !== HUB_ID) return;
      tip.append(h("strong", { text: "Netz" }), "Mittelpunkt: Es wurde kein Router erkannt.");
    } else {
      tip.append(h("strong", { text: d.display_name }));
      tip.append(`${d.ip} · ${d.mac}`);
      const lines = [
        d.vendor,
        (d.category_label || categoryLabel(d.category)) + (d.is_gateway ? " (Router)" : "") + (d.is_self ? " (dieser PC)" : ""),
        (d.ports || []).length ? `${d.ports.length} offene Ports, höchstes Risiko ${RISK_LABELS[d.max_risk] || "–"}` : "",
        d.is_new ? "neu" : d.known ? "bekannt" : "unbekannt",
        d.online ? "" : "offline",
      ].filter(Boolean);
      for (const line of lines) tip.append(h("br"), line);
    }
    tip.hidden = false;
    const wrap = tip.parentElement.getBoundingClientRect();
    const x = point ? point.x : 20;
    const y = point ? point.y : 20;
    tip.style.left = Math.max(4, Math.min(x + 16, wrap.width - tip.offsetWidth - 4)) + "px";
    tip.style.top = Math.max(4, Math.min(y + 16, wrap.height - tip.offsetHeight - 4)) + "px";
  }

  function hideMapTip() {
    $("map-tip").hidden = true;
  }

  function renderLegend() {
    const box = $("map-legend");
    clear(box);
    for (const [value, label] of CATEGORY_LIST) {
      box.append(h("span", { class: "legend-item" }, h("img", { src: iconUri(value), alt: "", width: 22, height: 22 }), label));
    }
    box.append(h("span", { class: "legend-item" }, h("span", { class: "legend-new", "aria-hidden": "true" }), "neues Gerät"));
    box.append(h("span", { class: "legend-item" }, h("span", { class: "legend-off", "aria-hidden": "true" }), "offline"));
  }

  // ---------- Reiter wechseln ----------

  const TABS = ["devices", "map", "log"];

  function setTab(name, focus) {
    if (!TABS.includes(name)) return;
    state.tab = name;
    for (const t of TABS) {
      const selected = t === name;
      const button = $("tab-" + t);
      button.setAttribute("aria-selected", selected ? "true" : "false");
      button.tabIndex = selected ? 0 : -1;
      $("panel-" + t).hidden = !selected;
      if (selected && focus) button.focus();
    }
    if (name === "map") {
      renderMap();
      scheduleMapResize();
    } else if (name === "log") {
      loadLog(state.logScanId);
      loadScans();
    }
  }

  // ---------- Protokoll ----------

  function logLine(entry) {
    const level = LOG_LEVEL_LABELS[entry.level] ? entry.level : "info";
    return h(
      "div",
      { class: "log-line level-" + level },
      h("span", { class: "log-time", text: formatTime(entry.ts, false), title: formatTime(entry.ts) }),
      h("span", { class: "log-level", text: LOG_LEVEL_LABELS[level] }),
      h("span", { class: "log-msg", text: entry.message || "" })
    );
  }

  function scrollLogToEnd() {
    const view = $("log-view");
    if ($("log-autoscroll").checked) view.scrollTop = view.scrollHeight;
  }

  function renderLog() {
    const view = $("log-view");
    clear(view);
    if (!state.log.length) {
      view.append(h("div", { class: "empty", text: "Noch keine Protokolleinträge." }));
    } else {
      const frag = document.createDocumentFragment();
      for (const entry of state.log) frag.append(logLine(entry));
      view.append(frag);
    }
    $("log-title").textContent = state.logScanId ? `Protokoll von Scan Nr. ${state.logScanId}` : "Protokoll (neueste Einträge)";
    $("btn-log-all").hidden = !state.logScanId;
    scrollLogToEnd();
  }

  let logSeq = 0;
  let pendingLive = null;
  async function loadLog(scanId) {
    state.logScanId = scanId || null;
    const seq = ++logSeq;
    pendingLive = [];
    const res = await api("GET", API.log, undefined, { limit: 500, scan_id: state.logScanId });
    if (seq !== logSeq) return;
    const live = pendingLive || [];
    pendingLive = null;
    if (!res.ok || !Array.isArray(res.data)) {
      toast("Protokoll konnte nicht geladen werden: " + apiMessage(res.data, "keine Antwort"), "error");
      return;
    }
    state.log = res.data.map((e) => ({ ts: e.ts, level: e.level, message: e.message }));
    // Live-Zeilen, die während des Ladens kamen und noch nicht in der Antwort stehen, anhängen
    if (!state.logScanId) {
      const recent = state.log.slice(-40).map((e) => e.level + "|" + e.message);
      for (const e of live) {
        const key = e.level + "|" + e.message;
        const at = recent.indexOf(key);
        if (at >= 0) recent.splice(at, 1);
        else state.log.push(e);
      }
    }
    state.logLoaded = true;
    renderLog();
    markScanRows();
  }

  function onJobLog(data, ts) {
    const entry = { ts: ts || new Date().toISOString(), level: data.level || "info", message: String(data.message || "") };
    if (pendingLive) pendingLive.push(entry);
    if (state.logScanId) return; // ein älterer Scan wird angezeigt
    state.log.push(entry);
    if (state.log.length > MAX_LOG_LINES) state.log.splice(0, state.log.length - MAX_LOG_LINES);
    if (state.tab === "log" && !pendingLive) {
      const view = $("log-view");
      const first = view.firstElementChild;
      if (first && first.classList.contains("empty")) clear(view);
      view.append(logLine(entry));
      while (view.children.length > MAX_LOG_LINES) view.firstChild.remove();
      scrollLogToEnd();
    }
  }

  async function loadScans() {
    const res = await api("GET", API.scans);
    if (!res.ok || !Array.isArray(res.data)) return;
    state.scans = res.data;
    renderScans();
  }

  function scanDuration(scan) {
    if (!scan.started || !scan.finished) return "";
    const s = (new Date(scan.finished).getTime() - new Date(scan.started).getTime()) / 1000;
    return Number.isFinite(s) && s >= 0 ? formatDuration(s) : "";
  }

  function renderScans() {
    const body = $("scan-body");
    clear(body);
    $("scan-empty").hidden = state.scans.length > 0;
    for (const scan of state.scans) {
      const result = scan.result ? SCAN_RESULT_LABELS[scan.result] || scan.result : scan.finished ? "–" : "läuft";
      body.append(
        h(
          "tr",
          { dataset: { id: scan.id }, tabindex: "0", title: "Protokoll dieses Scans anzeigen" },
          h("td", { text: String(scan.id) }),
          h("td", { text: JOB_KIND_LABELS[scan.kind] || scan.kind || "" }),
          h("td", { text: formatTime(scan.started), class: "col-seen" }),
          h("td", { text: scanDuration(scan) }),
          h("td", { text: [scan.network, scan.adapter].filter(Boolean).join(" · ") }),
          h("td", { text: result }),
          h("td", { text: scan.kind === "scan" || isNumber(scan.device_count) ? String(scan.device_count) : "" })
        )
      );
    }
    markScanRows();
  }

  function markScanRows() {
    for (const tr of document.querySelectorAll("#scan-body tr")) {
      tr.classList.toggle("row-selected", state.logScanId !== null && Number(tr.dataset.id) === Number(state.logScanId));
    }
  }

  // ---------- Einstellungen ----------

  async function loadSettings() {
    const res = await api("GET", API.settings);
    if (res.ok && res.data && typeof res.data === "object") {
      state.settings = res.data;
      return true;
    }
    return false;
  }

  const SETTINGS_DEFAULTS = { blocked_ssids_extra: [], home_gateway_macs: [], rate_pps: 200, port_timeout_ms: 700, port_scan_excluded_categories: [] };

  function cloneEditable(settings) {
    const work = {};
    for (const key of SETTINGS_EDITABLE) {
      const value = settings[key] === undefined || settings[key] === null ? SETTINGS_DEFAULTS[key] : settings[key];
      work[key] = Array.isArray(value) ? [...value] : value;
    }
    return work;
  }

  function renderOuiInfo() {
    const oui = (state.status && state.status.oui) || {};
    $("set-oui-info").textContent = `Aktuell: ${formatNumber(oui.entries)} Einträge${oui.source ? " · " + oui.source : ""}.`;
  }

  function pillList(container, items, options) {
    clear(container);
    if (!items.length) {
      container.append(h("li", { class: "pill-empty" }, h("span", { class: "pill-text", text: options.empty })));
      return;
    }
    items.forEach((item, index) => {
      const li = h("li", {}, h("span", { class: "pill-text" + (options.mono ? " mono" : ""), text: options.quote ? `„${item}“` : item }));
      if (options.note) li.append(h("span", { class: "pill-note", text: options.note }));
      if (options.onRemove) {
        li.append(
          h("button", {
            type: "button", class: "btn btn-small", text: "Entfernen", "aria-label": `${item} entfernen`,
            on: { click: () => options.onRemove(index) },
          })
        );
      }
      container.append(li);
    });
  }

  function renderSettings() {
    const s = state.settings;
    const work = state.settingsWork;
    pillList($("set-ssid-fixed"), s.permanent_blocked_ssids || [], { quote: true, note: "nicht entfernbar", empty: "–" });
    pillList($("set-ssid-extra"), work.blocked_ssids_extra, {
      quote: true, empty: "Keine eigenen gesperrten WLAN-Namen.",
      onRemove: (i) => {
        work.blocked_ssids_extra.splice(i, 1);
        renderSettings();
      },
    });
    pillList($("set-gw-blocked"), s.blocked_gateway_macs || [], { mono: true, note: "gelernt", empty: "Noch keine gelernt." });
    pillList($("set-gw-home"), work.home_gateway_macs, {
      mono: true, empty: "Noch kein Heimnetz gemerkt.",
      onRemove: (i) => {
        work.home_gateway_macs.splice(i, 1);
        renderSettings();
      },
    });
    $("set-rate").value = work.rate_pps;
    $("set-port-timeout").value = work.port_timeout_ms;
    const cats = $("set-categories");
    clear(cats);
    for (const [value, label] of CATEGORY_LIST) {
      const input = h("input", {
        type: "checkbox", checked: work.port_scan_excluded_categories.includes(value),
        on: {
          change: (ev) => {
            const list = work.port_scan_excluded_categories.filter((c) => c !== value);
            if (ev.target.checked) list.push(value);
            work.port_scan_excluded_categories = list;
          },
        },
      });
      cats.append(h("label", { class: "check" }, input, h("span", { text: label })));
    }
    renderOuiInfo();
  }

  function settingsMessage(text, kind) {
    const msg = $("set-msg");
    msg.className = "form-msg" + (kind ? " " + kind : "");
    msg.textContent = text || "";
  }

  async function openSettings() {
    settingsMessage("");
    const ok = await loadSettings();
    if (!ok && !state.settings) {
      toast("Einstellungen konnten nicht geladen werden.", "error");
      return;
    }
    state.settingsWork = cloneEditable(state.settings);
    renderSettings();
    const dlg = $("settings-dialog");
    if (!dlg.open) {
      if (typeof dlg.showModal === "function") dlg.showModal();
      else dlg.setAttribute("open", "");
    }
  }

  function closeSettings() {
    const dlg = $("settings-dialog");
    if (typeof dlg.close === "function") dlg.close();
    else dlg.removeAttribute("open");
  }

  function addBlockedSsid() {
    const input = $("set-ssid-new");
    const name = input.value; // bewusst unverändert: der Vergleich ist exakt
    if (!name.trim()) {
      settingsMessage("Bitte einen WLAN-Namen eintragen.", "error");
      return;
    }
    const known = new Set([...(state.settings.permanent_blocked_ssids || []), ...state.settingsWork.blocked_ssids_extra]);
    if (known.has(name)) {
      settingsMessage("Dieser Name ist bereits gesperrt.", "error");
      return;
    }
    state.settingsWork.blocked_ssids_extra.push(name);
    input.value = "";
    settingsMessage("");
    renderSettings();
  }

  async function saveSettings() {
    const work = state.settingsWork;
    const rateText = $("set-rate").value.trim();
    const timeoutText = $("set-port-timeout").value.trim();
    const rate = Number(rateText);
    const timeout = Number(timeoutText);
    if (!rateText || !Number.isFinite(rate) || !timeoutText || !Number.isFinite(timeout)) {
      settingsMessage("Bitte gültige Zahlen für Drosselung und Timeout eintragen.", "error");
      return;
    }
    work.rate_pps = Math.round(rate);
    work.port_timeout_ms = Math.round(timeout);
    const changes = diffSettings(state.settings, work);
    if (!Object.keys(changes).length) {
      closeSettings();
      toast("Keine Änderungen an den Einstellungen.", "info", 2500);
      return;
    }
    $("btn-settings-save").disabled = true;
    settingsMessage("Speichere …");
    const res = await api("PUT", API.settings, changes);
    $("btn-settings-save").disabled = false;
    if (!res.ok) {
      settingsMessage(apiMessage(res.data, "Einstellungen konnten nicht gespeichert werden."), "error");
      return;
    }
    if (res.data && typeof res.data === "object" && "rate_pps" in res.data) state.settings = res.data;
    else await loadSettings();
    closeSettings();
    toast("Einstellungen gespeichert.", "ok");
    refreshGuard(false); // gesperrte Namen können die Entscheidung ändern
  }

  async function updateOui() {
    const res = await api("POST", API.ouiUpdate, {});
    handleStartResponse(res, { type: "oui" }, "Aktualisierung der Herstellerliste");
    updateControls();
  }

  // ---------- WebSocket ----------

  function wsUrl() {
    return (location.protocol === "https:" ? "wss://" : "ws://") + location.host + WS_PATH;
  }

  function setLive(kind, delayMs) {
    const box = $("live-indicator");
    box.dataset.state = kind;
    const texts = {
      open: "Live verbunden",
      connecting: "Verbinde …",
      waiting: `Getrennt – neuer Versuch in ${Math.max(1, Math.round((delayMs || 0) / 1000))} s`,
    };
    $("live-text").textContent = texts[kind] || "";
  }

  function connectWs() {
    clearTimeout(state.wsTimer);
    let ws;
    try {
      ws = new WebSocket(wsUrl());
    } catch (err) {
      scheduleReconnect();
      return;
    }
    state.ws = ws;
    setLive("connecting");
    ws.addEventListener("open", () => {
      state.wsAttempt = 0;
      setLive("open");
    });
    ws.addEventListener("message", (ev) => {
      let msg = null;
      try {
        msg = JSON.parse(ev.data);
      } catch (err) {
        return;
      }
      handleEvent(msg);
    });
    ws.addEventListener("close", () => {
      if (state.ws !== ws) return;
      state.ws = null;
      scheduleReconnect();
    });
    ws.addEventListener("error", () => {
      /* close folgt automatisch */
    });
  }

  function scheduleReconnect() {
    const delay = Math.min(15000, 1000 * Math.pow(2, state.wsAttempt));
    state.wsAttempt += 1;
    setLive("waiting", delay);
    clearTimeout(state.wsTimer);
    state.wsTimer = setTimeout(connectWs, delay);
  }

  /** Nach einer Unterbrechung alles neu holen, was in der Zwischenzeit passiert sein kann. */
  function resync() {
    refreshStatus();
    refreshJob();
    loadDevices();
    refreshGuard(false);
    if (state.tab === "log") {
      loadLog(state.logScanId);
      loadScans();
    }
  }

  function handleEvent(msg) {
    if (!msg || typeof msg !== "object") return;
    const data = msg.data && typeof msg.data === "object" ? msg.data : {};
    switch (msg.type) {
      case "hello":
        onHello(data);
        break;
      case "job.started":
        onJobStarted(data, msg.ts);
        break;
      case "job.progress":
        onJobProgress(data);
        break;
      case "job.log":
        onJobLog(data, msg.ts);
        break;
      case "job.finished":
        onJobFinished(data);
        break;
      case "device.updated":
        onDeviceUpdated(data);
        break;
      case "devices.changed":
        scheduleDevicesReload();
        break;
      case "guard.result":
        onGuardEvent(data);
        break;
      case "oui.updated":
        onOuiUpdated(data);
        break;
      default:
        break;
    }
  }

  function onHello(data) {
    const reconnect = state.wsSeen;
    state.wsSeen = true;
    if (data.status && typeof data.status === "object") {
      state.status = data.status;
      renderStatus();
      renderOuiInfo();
      if (data.status.job && typeof data.status.job === "object") applyJobStatus(data.status.job);
    }
    if (reconnect) resync();
  }

  function onJobStarted(data, ts) {
    state.lastResult = null;
    state.job = Object.assign(idleJob(), { job_id: data.job_id || null, kind: data.kind || null, label: data.label || "", state: "running", started: ts || null });
    updateControls();
    renderJob();
  }

  function onJobProgress(data) {
    if (state.job.state === "idle") {
      state.job = Object.assign(idleJob(), { job_id: data.job_id || null, state: "running" });
    }
    state.job.phase = data.phase || null;
    state.job.done = isNumber(data.done) ? data.done : 0;
    state.job.total = isNumber(data.total) ? data.total : 0;
    state.job.message = data.message || "";
    if (data.phase === "Abbruch" && state.job.state === "running") state.job.state = "cancelling";
    updateControls();
    renderJobSoon();
  }

  function onJobFinished(data) {
    state.job = idleJob();
    state.lastResult = describeResult(data);
    const tone = state.lastResult.tone;
    toast(state.lastResult.text, tone === "ok" ? "ok" : tone, tone === "error" ? 12000 : 6000);
    updateControls();
    renderJob();
    loadDevices();
    refreshStatus();
    if (data.kind === "scan") refreshGuard(false);
    if (state.tab === "log") {
      loadLog(state.logScanId);
      loadScans();
    }
  }

  function onDeviceUpdated(data) {
    const d = data.device;
    if (!d || !d.mac) return;
    state.devices.set(d.mac, d);
    scheduleRender();
  }

  function onOuiUpdated(data) {
    refreshStatus();
    toast(isNumber(data.entries) ? `Herstellerliste aktualisiert: ${formatNumber(data.entries)} Einträge.` : "Herstellerliste aktualisiert.", "ok");
  }

  // ---------- Start ----------

  function bindEvents() {
    $("adapter").addEventListener("change", onAdapterChanged);
    $("show-virtual").addEventListener("change", async () => {
      state.showVirtual = $("show-virtual").checked;
      prefs.set("virtual", state.showVirtual ? "1" : "0");
      await loadAdapters();
      await refreshGuard(true);
    });
    $("mode").addEventListener("change", () => prefs.set("mode", $("mode").value));
    $("port-scan").addEventListener("change", () => prefs.set("portscan", $("port-scan").checked ? "1" : "0"));
    $("btn-start").addEventListener("click", () => startScan({}));
    $("btn-cancel").addEventListener("click", cancelScan);
    $("btn-settings").addEventListener("click", openSettings);

    // Reiter
    for (const t of TABS) {
      $("tab-" + t).addEventListener("click", () => setTab(t, false));
      $("tab-" + t).addEventListener("keydown", (ev) => {
        const at = TABS.indexOf(t);
        let next = -1;
        if (ev.key === "ArrowRight") next = (at + 1) % TABS.length;
        else if (ev.key === "ArrowLeft") next = (at + TABS.length - 1) % TABS.length;
        else if (ev.key === "Home") next = 0;
        else if (ev.key === "End") next = TABS.length - 1;
        if (next >= 0) {
          ev.preventDefault();
          setTab(TABS[next], true);
        }
      });
    }

    // Gerätetabelle
    $("device-filter").addEventListener("input", () => {
      state.filter = $("device-filter").value;
      renderDevices();
    });
    for (const btn of document.querySelectorAll("#devices-table .th-sort")) {
      btn.addEventListener("click", () => setSort(btn.dataset.sort));
    }
    const body = $("devices-body");
    body.addEventListener("click", (ev) => {
      const row = ev.target.closest("tr[data-mac]");
      if (row) openDetail(row.dataset.mac);
    });
    body.addEventListener("keydown", (ev) => {
      if (ev.key !== "Enter" && ev.key !== " ") return;
      const row = ev.target.closest("tr[data-mac]");
      if (row) {
        ev.preventDefault();
        openDetail(row.dataset.mac);
      }
    });

    // Detailbereich
    $("detail-close").addEventListener("click", closeDetail);
    $("detail-form").addEventListener("submit", (ev) => {
      ev.preventDefault();
      saveDevice();
    });
    $("detail-form").addEventListener("input", () => {
      state.formDirty = true;
      $("d-msg").textContent = "";
    });
    $("d-deep").addEventListener("click", () => {
      if (state.selectedMac) startDeepScan(state.selectedMac, false);
    });
    document.addEventListener("keydown", (ev) => {
      if (ev.key === "Escape" && !$("settings-dialog").open && state.selectedMac) closeDetail();
    });

    // Karte
    $("btn-map-fit").addEventListener("click", () => {
      if (state.network) state.network.fit({ animation: { duration: 300 } });
    });
    $("btn-map-arrange").addEventListener("click", arrangeAll);
    if (typeof window.matchMedia === "function") {
      const media = window.matchMedia("(prefers-color-scheme: dark)");
      const onTheme = () => {
        if (state.network) syncMap();
      };
      if (media.addEventListener) media.addEventListener("change", onTheme);
    }
    if (typeof ResizeObserver === "function") {
      new ResizeObserver(() => scheduleMapResize()).observe($("map-canvas"));
    }

    // Protokoll
    $("btn-log-all").addEventListener("click", () => loadLog(null));
    $("scan-body").addEventListener("click", (ev) => {
      const row = ev.target.closest("tr[data-id]");
      if (row) loadLog(Number(row.dataset.id));
    });
    $("scan-body").addEventListener("keydown", (ev) => {
      if (ev.key !== "Enter" && ev.key !== " ") return;
      const row = ev.target.closest("tr[data-id]");
      if (row) {
        ev.preventDefault();
        loadLog(Number(row.dataset.id));
      }
    });

    // Einstellungen
    $("btn-settings-x").addEventListener("click", closeSettings);
    $("btn-settings-cancel").addEventListener("click", closeSettings);
    $("btn-settings-save").addEventListener("click", saveSettings);
    $("btn-ssid-add").addEventListener("click", addBlockedSsid);
    $("set-ssid-new").addEventListener("keydown", (ev) => {
      if (ev.key === "Enter") {
        ev.preventDefault();
        addBlockedSsid();
      }
    });
    $("btn-oui-update").addEventListener("click", updateOui);

    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState === "visible" && !state.ws) connectWs();
    });
  }

  async function init() {
    state.showVirtual = prefs.get("virtual", "0") === "1";
    $("show-virtual").checked = state.showVirtual;
    $("mode").value = prefs.get("mode", "full") === "registered" ? "registered" : "full";
    $("port-scan").checked = prefs.get("portscan", "1") !== "0";
    categoryOptions(null);
    renderLegend();
    renderStatus();
    renderDevices();
    renderJob();
    bindEvents();
    connectWs();

    await Promise.all([loadSettings(), refreshStatus(), loadDevices(), refreshJob()]);
    await loadAdapters();
    await refreshGuard(true);
  }

  init();
})();
