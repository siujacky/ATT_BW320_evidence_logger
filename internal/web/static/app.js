/*
 * att-monitor dashboard (docs/DESIGN.md §12).
 *
 * Plain JavaScript, no libraries, no external URLs: the page must keep working while the
 * internet connection is down. Everything that originates outside this program (gateway
 * pages, SSIDs, DNS answers, TSA names, notes, error texts, ledger records) is inserted as
 * text nodes only, never parsed as markup. Elements are built with h() and s(); attributes
 * from variables go through setAttr(), which refuses event-handler and style attributes and
 * any URL that would leave this origin (escaping_test.go enforces both).
 *
 * Charts are hand-written SVG and follow one set of rules: one y-axis per chart, categorical
 * series colours assigned in fixed order and following the entity (not its rank), status
 * colours reserved for states and always paired with an icon and a label, 2px lines, a
 * legend for two or more series, crosshair + tooltip on hover and keyboard, and a table
 * view for every chart.
 */
'use strict';

(() => {
  // ------------------------------------------------------------------ constants

  const SVGNS = 'http://www.w3.org/2000/svg';
  const STATUS_REFRESH_MS = 10000;
  const SERIES_REFRESH_MS = 60000;
  const HEX64 = /^[0-9a-f]{64}$/;
  // Classifier rules versions (docs/DESIGN.md §9-§10) from which incidents carry measured
  // time accounting (downtime_s, degraded_s), and gateway-restart windows (restart_s).
  const RULES_TIME_ACCOUNTING = '2026.10-2';
  const RULES_RESTART_WINDOWS = '2026.10-3';
  const RULES_VERDICT_INPUTS = '2026.10-3'; // verdicts name the records they used
  // From rules 2026.10-4 an incident with a gateway restart is AT&T's only with at least as many
  // provider-attributed bad cycles outside the restart windows as it takes to open an incident.
  const RULES_RESTART_MIN_CYCLES = '2026.10-4';
  const RANGES = [['1h', '1 h'], ['6h', '6 h'], ['24h', '24 h'], ['7d', '7 d']];
  const RANGE_MS = dict({ '1h': 3600e3, '6h': 6 * 3600e3, '24h': 86400e3, '7d': 7 * 86400e3 });
  const RECORD_TYPES = [
    'genesis', 'segment_open', 'bootstrap_import', 'monitor_start', 'monitor_stop', 'heartbeat',
    'sample', 'state_change', 'gateway_snapshot', 'gateway_event', 'service_check', 'local_link',
    'traceroute', 'clock_check', 'clock_jump', 'incident_open', 'incident_update', 'incident_close',
    'anchor', 'config_change', 'power_event', 'custody_export', 'operator_note', 'recovery',
    'integrity_alert', 'config_state', 'syslog',
  ];

  /** dict makes a lookup table without a prototype, so that a value from the data such as
   *  "constructor" never resolves to an Object.prototype member. */
  function dict(o) {
    return Object.freeze(Object.assign(Object.create(null), o));
  }

  const STATES = dict({
    ONLINE: { label: 'Online', tone: 'good' },
    DEGRADED: { label: 'Degraded', tone: 'warning' },
    LOCAL_FAULT: { label: 'Local fault', tone: 'serious' },
    ISP_OUTAGE: { label: 'AT&T outage', tone: 'critical' },
    UNKNOWN: { label: 'Unknown', tone: 'none' },
    '': { label: 'No data', tone: 'none' },
  });
  // Fixed legend order for state strips.
  const STATE_ORDER = ['ONLINE', 'DEGRADED', 'LOCAL_FAULT', 'ISP_OUTAGE', ''];

  const CAUSES = dict({
    FIBER_LINK_DOWN: { text: 'fiber link down', src: 'reported by the AT&T gateway' },
    WAN_DOWN: { text: 'broadband connection down', src: 'reported by the AT&T gateway' },
    ISP_EDGE_UNREACHABLE: { text: 'AT&T network edge not answering', src: 'gateway reachable, AT&T next hop silent' },
    UPSTREAM_UNREACHABLE: { text: 'internet unreachable beyond the AT&T gateway', src: 'gateway reachable, every internet probe failed' },
    PACKET_LOSS: { text: 'packet loss' },
    HIGH_LATENCY: { text: 'high latency' },
    ISP_DNS_FAILURE: { text: 'AT&T DNS servers not answering' },
    GATEWAY_DNS_FAILURE: { text: 'gateway DNS not answering' },
    GATEWAY_UNREACHABLE: { text: 'this PC cannot reach the AT&T gateway' },
    LOCAL_LINK_DOWN: { text: 'this PC’s network link is down' },
    GATEWAY_REBOOT: { text: 'AT&T gateway restarted', src: 'detected from the gateway’s own uptime' },
    // Rules 2026.10-4: the gateway answered, but the route check shows this computer's traffic
    // leaving through another adapter (VPN tunnel, second network, hotspot). Recorded under
    // LOCAL_FAULT; the headline says what was observed rather than "local fault".
    LOCAL_ROUTE: {
      text: 'this computer’s traffic does not go through the AT&T gateway (VPN or another network)',
      headline: 'This computer’s traffic does not go through the AT&T gateway (VPN or another network); nothing is attributed to AT&T',
    },
  });
  const ATTR_LONG = dict({
    provider: 'Attributed to AT&T (provider side)',
    local: 'Local problem (this PC or the home network)',
    undetermined: 'Attribution undetermined — the evidence does not support a call',
  });
  const ATTR_SHORT = dict({ provider: 'AT&T (provider)', local: 'Local', undetermined: 'Undetermined', none: '—' });

  // Condition codes that are the AT&T gateway's own DMI alarm/warning flags (fiberstat page),
  // as produced by the gateway package: <MEASURE>_<LOW|HIGH>_<ALARM|WARNING>.
  const GATEWAY_FLAG_RE = /^(OPTICAL_RX|OPTICAL_TX|TX_BIAS|TEMPERATURE|VCC)_/;

  const COND_TITLES = dict({
    OPTICAL_RX_LOW_ALARM: 'Fiber receive power LOW ALARM',
    OPTICAL_RX_LOW_WARNING: 'Fiber receive power low warning',
    OPTICAL_RX_HIGH_ALARM: 'Fiber receive power HIGH ALARM',
    OPTICAL_RX_HIGH_WARNING: 'Fiber receive power high warning',
    OPTICAL_TX_LOW_ALARM: 'Fiber transmit power LOW ALARM',
    OPTICAL_TX_LOW_WARNING: 'Fiber transmit power low warning',
    OPTICAL_TX_HIGH_ALARM: 'Fiber transmit power HIGH ALARM',
    OPTICAL_TX_HIGH_WARNING: 'Fiber transmit power high warning',
    TEMPERATURE_LOW_ALARM: 'Optical module temperature LOW ALARM',
    TEMPERATURE_LOW_WARNING: 'Optical module temperature low warning',
    TEMPERATURE_HIGH_ALARM: 'Optical module temperature HIGH ALARM',
    TEMPERATURE_HIGH_WARNING: 'Optical module temperature high warning',
    TX_BIAS_LOW_ALARM: 'Laser bias current LOW ALARM',
    TX_BIAS_LOW_WARNING: 'Laser bias current low warning',
    TX_BIAS_HIGH_ALARM: 'Laser bias current HIGH ALARM',
    TX_BIAS_HIGH_WARNING: 'Laser bias current high warning',
    VCC_LOW_ALARM: 'Optical module supply voltage LOW ALARM',
    VCC_LOW_WARNING: 'Optical module supply voltage low warning',
    VCC_HIGH_ALARM: 'Optical module supply voltage HIGH ALARM',
    VCC_HIGH_WARNING: 'Optical module supply voltage high warning',
    NOTIFICATION_REDIRECT_ON: 'Outage redirect is ON',
    GATEWAY_CERT_CHANGED: 'Gateway TLS certificate changed — authenticated actions paused',
    NO_ACCESS_CODE: 'No usable gateway access code',
    ANCHOR_UNTRUSTED: 'Recent time-stamps could not be verified',
    EGRESS_NOT_VIA_GATEWAY: 'Traffic does not go through the AT&T gateway (VPN or another network)',
    LEDGER_WRITE_FAILING: 'Evidence is not being recorded — the ledger refuses new records',
    DISK_SPACE_LOW: 'Low disk space on the evidence volume',
    CLOCK_OFFSET: 'This computer’s clock is off',
  });
  // Conditions also shown on the Gateway page (they pause or block its authenticated actions).
  const GATEWAY_ALERTS = ['GATEWAY_CERT_CHANGED', 'NO_ACCESS_CODE'];
  // Conditions also shown on the Evidence page (they affect what is recorded, and when).
  const EVIDENCE_ALERTS = ['LEDGER_WRITE_FAILING', 'DISK_SPACE_LOW', 'CLOCK_OFFSET', 'ANCHOR_UNTRUSTED'];

  // Verification problems (model.VerifyFailure.problem) in words.
  const VERIFY_PROBLEMS = dict({
    hash_mismatch: 'hash mismatch (h ≠ SHA-256 of b)',
    bad_signature: 'signature does not verify',
    seq_gap: 'record missing or out of sequence',
    prev_mismatch: 'chain broken (prev ≠ h of the record before)',
    segment_hash: 'segment hash mismatch',
    blob_missing: 'raw data missing',
    blob_corrupt: 'raw data corrupt',
    anchor_invalid: 'time-stamp invalid',
    parse_error: 'line cannot be read',
    ts_contradiction: 'record time contradicts a trusted time-stamp',
  });

  const ICMP_STATUS = dict({
    IP_SUCCESS: 'reply',
    IP_REQ_TIMED_OUT: 'timed out',
    IP_DEST_NET_UNREACHABLE: 'network unreachable',
    IP_DEST_HOST_UNREACHABLE: 'host unreachable',
    IP_DEST_PROT_UNREACHABLE: 'protocol unreachable',
    IP_DEST_PORT_UNREACHABLE: 'port unreachable',
    IP_TTL_EXPIRED_TRANSIT: 'TTL expired',
    IP_GENERAL_FAILURE: 'general failure',
    IP_BAD_DESTINATION: 'bad destination',
  });
  const HTTP_CHECK_NAMES = dict({ msft_connecttest: 'Microsoft connectivity test', google_204: 'Google generate_204' });
  const DNS_ROLES = dict({ gateway: 'Gateway DNS', isp: 'AT&T DNS', public: 'Public DNS' });
  const HIJACK_TEST_HELP = 'Every check also asks this resolver for a random name under .invalid, which never exists (RFC 6761). ' +
    'NXDOMAIN is the correct answer. An address in the answer would mean the resolver is redirecting (hijacking) DNS.';

  // Syslog severities (RFC 5424 §6.2.1) by number: the keyword GET /api/syslog accepts, the word
  // shown and the tone of its chip. Notice, info and debug are routine.
  const SYSLOG_SEVERITIES = [
    { name: 'emerg', label: 'Emergency', tone: 'critical' },
    { name: 'alert', label: 'Alert', tone: 'critical' },
    { name: 'crit', label: 'Critical', tone: 'critical' },
    { name: 'err', label: 'Error', tone: 'serious' },
    { name: 'warning', label: 'Warning', tone: 'warning' },
    { name: 'notice', label: 'Notice', tone: 'info' },
    { name: 'info', label: 'Info', tone: 'none' },
    { name: 'debug', label: 'Debug', tone: 'none' },
  ];
  // Syslog facilities by number (RFC 5424 §6.2.1).
  const SYSLOG_FACILITIES = ['kern', 'user', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news', 'uucp', 'cron', 'authpriv', 'ftp',
    'ntp', 'audit', 'alert', 'clock', 'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7'];
  const SYSLOG_FORMATS = dict({ rfc5424: 'RFC 5424', rfc3164: 'RFC 3164 (BSD syslog)', unknown: 'not recognised: kept as received' });
  const SYSLOG_PAGE = 200; // messages asked for at first; "Load more" doubles it
  const SYSLOG_MAX = 5000; // the most GET /api/syslog returns
  const SYSLOG_MAX_SPAN_MS = 31 * 86400e3; // the longest period GET /api/syslog reads

  // ------------------------------------------------------------------ app state

  const app = {
    status: null,
    statusError: null,
    statusAt: null,
    range: loadPref('range', '24h'),
    hidden: new Set(), // series hidden via legend toggles (shared by linked charts)
    tableViews: new Set(), // chart ids currently shown as tables
    view: null,
  };
  if (!RANGES.some(([v]) => v === app.range)) app.range = '24h';

  // ------------------------------------------------------------------ DOM helpers

  // Attributes whose value a browser fetches or navigates to.
  const URL_ATTRS = new Set(['href', 'src', 'action', 'formaction', 'xlink:href', 'srcset', 'poster', 'ping', 'background', 'cite', 'data', 'codebase', 'manifest']);

  /** sameOriginUrl returns v when it stays on this origin — a fragment (#...) or an absolute
   *  path (/..., but not //host or /\host) — and null otherwise, so that no value from the
   *  data can turn a link into a script or data URL or one to another site. Control characters
   *  are refused because browsers drop tabs and newlines from URLs ("/<tab>/x" is "//x"). */
  function sameOriginUrl(v) {
    const u = String(v);
    if (/[\u0000-\u001f\u007f]/.test(u)) return null;
    return /^#/.test(u) || /^\/(?![\/\\])/.test(u) ? u : null;
  }

  /** setAttr is the only place where app.js sets an attribute named by a variable. It refuses
   *  event-handler attributes (handlers are functions passed to h() as on<event>), inline
   *  styles and srcdoc, and URL attributes that would leave this origin. Values are set as
   *  attribute text, which the browser never parses as markup. Returns whether it was set. */
  function setAttr(el, name, value) {
    const n = String(name).toLowerCase();
    if (n.startsWith('on') || n === 'style' || n === 'srcdoc') return false;
    let v = value === true ? '' : String(value);
    if (URL_ATTRS.has(n)) {
      v = sameOriginUrl(v);
      if (v == null) return false;
    }
    el.setAttribute(name, v);
    return true;
  }

  /** h creates an HTML element; props: class, text, on<event> (a function), dataset, attributes. */
  function h(tag, props, ...kids) {
    const el = document.createElement(tag);
    if (props) {
      for (const [k, v] of Object.entries(props)) {
        if (v == null || v === false) continue;
        if (k === 'class') el.className = v;
        else if (k === 'text') el.textContent = v;
        else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
        else if (k === 'dataset') Object.assign(el.dataset, v);
        else setAttr(el, k, v);
      }
    }
    return add(el, kids);
  }

  /** s creates an SVG element. */
  function s(tag, attrs, ...kids) {
    const el = document.createElementNS(SVGNS, tag);
    if (attrs) for (const [k, v] of Object.entries(attrs)) if (v != null) setAttr(el, k, v);
    return add(el, kids);
  }

  /** add appends children, flattening arrays and skipping null/false/''. */
  function add(el, kids) {
    for (const k of kids.flat(Infinity)) {
      if (k == null || k === false || k === '') continue;
      el.append(k instanceof Node ? k : document.createTextNode(String(k)));
    }
    return el;
  }

  /** replace swaps all children of el (null-safe, unlike Element.replaceChildren). */
  function replace(el, ...kids) {
    el.textContent = '';
    return add(el, kids);
  }

  function loadPref(key, def) {
    try {
      const v = window.localStorage.getItem('attmon.' + key);
      return v == null ? def : v;
    } catch (_) {
      return def;
    }
  }

  function savePref(key, value) {
    try { window.localStorage.setItem('attmon.' + key, value); } catch (_) { /* private mode */ }
  }

  function announce(msg) {
    const live = document.getElementById('live');
    live.textContent = '';
    window.setTimeout(() => { live.textContent = msg; }, 60);
  }

  // ------------------------------------------------------------------ formatting

  const F = {
    full: new Intl.DateTimeFormat(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', second: '2-digit' }),
    short: new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }),
    time: new Intl.DateTimeFormat(undefined, { hour: 'numeric', minute: '2-digit', second: '2-digit' }),
    hm: new Intl.DateTimeFormat(undefined, { hour: 'numeric', minute: '2-digit' }),
    day: new Intl.DateTimeFormat(undefined, { weekday: 'short', month: 'short', day: 'numeric' }),
    sec: new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', second: '2-digit' }),
  };

  /** toDate parses RFC 3339 (any fraction length), numbers (ms) and Dates. */
  function toDate(v) {
    if (v == null || v === '') return null;
    if (v instanceof Date) return isNaN(v) ? null : v;
    if (typeof v === 'number') return new Date(v);
    const d = new Date(String(v).replace(/(\.\d{3})\d+/, '$1'));
    return isNaN(d) ? null : d;
  }

  function toMs(v) {
    const d = toDate(v);
    return d ? d.getTime() : null;
  }

  /** utcText shows the recorded UTC string exactly when we have one. */
  function utcText(v, d) {
    if (typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$/.test(v)) {
      return v.replace('T', ' ').replace('Z', ' UTC');
    }
    return d.toISOString().replace('T', ' ').replace('.000Z', 'Z').replace('Z', ' UTC');
  }

  /** timeEl renders a time in local time with the UTC value on hover. */
  function timeEl(v, fmt) {
    const d = toDate(v);
    if (!d) return h('span', { class: 'muted' }, v ? String(v) : '—');
    return h('time', { datetime: d.toISOString(), title: 'UTC: ' + utcText(v, d) }, (fmt || F.full).format(d));
  }

  function fmtDur(sec) {
    if (sec == null || !isFinite(sec)) return '—';
    sec = Math.max(0, Math.round(sec));
    if (sec < 60) return sec + ' s';
    const m = Math.floor(sec / 60);
    const rs = sec % 60;
    if (m < 60) return m < 10 && rs ? `${m} min ${rs} s` : `${m} min`;
    const hh = Math.floor(m / 60);
    const mm = m % 60;
    if (hh < 48) return mm ? `${hh} h ${mm} min` : `${hh} h`;
    const dd = Math.floor(hh / 24);
    const rh = hh % 24;
    return rh ? `${dd} d ${rh} h` : `${dd} d`;
  }

  function sinceText(v, now) {
    const d = toDate(v);
    if (!d) return '';
    const n = toDate(now) || new Date();
    return fmtDur((n - d) / 1000);
  }

  /** ageSeconds returns how long before now (the monitor's clock when given) v was, or null. */
  function ageSeconds(v, now) {
    const d = toDate(v);
    if (!d) return null;
    const n = toDate(now) || new Date();
    return (n - d) / 1000;
  }

  function fmtMs(ms) {
    if (ms == null || !isFinite(ms)) return '—';
    return ms < 100 ? ms.toFixed(1) + ' ms' : Math.round(ms).toLocaleString() + ' ms';
  }

  function fmtRTT(us) {
    return us == null || !isFinite(us) || us <= 0 ? '—' : fmtMs(us / 1000);
  }

  function fmtInt(n) {
    return n == null || !isFinite(n) ? '—' : Number(n).toLocaleString();
  }

  /** fmtPct truncates instead of rounding so that 99.996 % never shows as 100 %; a share too
   *  small for the digits shows as "< 0.01 %", never as 0 (a short outage is not no outage). */
  function fmtPct(p, digits = 2) {
    if (p == null || !isFinite(p)) return '—';
    if (p >= 100) return '100 %';
    const f = Math.pow(10, digits);
    if (p > 0 && p * f < 1) return '< ' + (1 / f).toFixed(digits) + ' %';
    return (Math.floor(p * f) / f).toFixed(digits) + ' %';
  }

  function fmtBytes(n) {
    if (n == null || !isFinite(n)) return '—';
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KiB';
    return (n / 1024 / 1024).toFixed(1) + ' MiB';
  }

  function fmtMeasure(v, unit) {
    if (v == null || !isFinite(v)) return '—';
    switch (unit) {
      case '0.1dBm': return (v / 10).toFixed(1) + ' dBm';
      case 'C': return v + ' °C';
      case 'V': return v + ' V';
      case 'mA': return v + ' mA';
      default: return unit ? v + ' ' + unit : String(v);
    }
  }

  /** orQ shows a missing field as "?" instead of "undefined" (damaged or unusual records). */
  function orQ(v) {
    return v == null || v === '' ? '?' : String(v);
  }

  function humanize(code) {
    return String(code == null ? '' : code).toLowerCase().replace(/_/g, ' ');
  }

  /** hiddenChar reports whether the UTF-16 code unit c would act on the display instead of
   *  showing: C0 and C1 controls, DEL, the bidirectional marks, embeddings, overrides and
   *  isolates, zero-width characters and joiners, the line and paragraph separators, the byte
   *  order mark. */
  function hiddenChar(c) {
    return c < 0x20 || (c >= 0x7f && c <= 0x9f) || c === 0x61c || (c >= 0x200b && c <= 0x200f) ||
      (c >= 0x2028 && c <= 0x202e) || (c >= 0x2060 && c <= 0x2069) || c === 0xfeff;
  }

  /** charEscape writes a hidden character as an escape: \t, \n, \r, \xHH or \uHHHH. */
  function charEscape(c) {
    switch (c) {
      case 0x09: return '\\t';
      case 0x0a: return '\\n';
      case 0x0d: return '\\r';
      default: return c < 0x100 ? '\\x' + c.toString(16).padStart(2, '0') : '\\u' + c.toString(16).padStart(4, '0');
    }
  }

  /** visibleText shows untrusted text (a syslog message) as received, with its hidden
   *  characters (hiddenChar) written as escapes (charEscape: an ESC as \x1b, a right-to-left
   *  override as a \u escape of 202e) and set apart (class ctl), so that they can be neither
   *  mistaken for the text nor reorder, hide or break what is shown around it. keepNewlines
   *  leaves line breaks as they are (pretty-printed JSON). Returns the parts for h(). */
  function visibleText(text, keepNewlines) {
    const t = String(text == null ? '' : text);
    const out = [];
    let start = 0;
    for (let i = 0; i < t.length; i++) {
      const c = t.charCodeAt(i);
      if (!hiddenChar(c) || (keepNewlines && c === 0x0a)) continue;
      if (i > start) out.push(t.slice(start, i));
      out.push(h('span', { class: 'ctl', title: 'U+' + c.toString(16).toUpperCase().padStart(4, '0') }, charEscape(c)));
      start = i + 1;
    }
    if (start < t.length) out.push(t.slice(start));
    return out;
  }

  /** escapedText is visibleText as one string, for text that cannot hold markup (a summary
   *  line, a title). */
  function escapedText(text) {
    const t = String(text == null ? '' : text);
    let out = '';
    for (let i = 0; i < t.length; i++) {
      const c = t.charCodeAt(i);
      out += hiddenChar(c) ? charEscape(c) : t[i];
    }
    return out;
  }

  function groupFingerprint(fp) {
    return String(fp || '').replace(/(.{4})(?=.)/g, '$1 ');
  }

  function shortHash(x, n) {
    return x ? String(x).slice(0, n || 12) + '…' : '—';
  }

  function tsaName(u) {
    try { return new URL(u).hostname || String(u); } catch (_) { return u || '—'; }
  }

  /** rulesAtLeast compares classifier rules versions ("2026.10-3"); an unknown or malformed
   *  version is never "at least" anything, so nothing is claimed for it. */
  function rulesAtLeast(rules, want) {
    const parse = (v) => {
      const m = /^(\d{4})\.(\d{2})-(\d+)$/.exec(String(v == null ? '' : v));
      return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
    };
    const a = parse(rules);
    const b = parse(want);
    if (!a || !b) return false;
    for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] > b[i];
    return true;
  }

  /** normFp lower-cases a SHA-256 fingerprint; anything else becomes ''. */
  function normFp(v) {
    const fp = String(v == null ? '' : v).trim().toLowerCase();
    return HEX64.test(fp) ? fp : '';
  }

  /** hex64sIn lists the distinct SHA-256 fingerprints a text names. */
  function hex64sIn(text) {
    const out = [];
    for (const m of String(text || '').toLowerCase().match(/\b[0-9a-f]{64}\b/g) || []) if (!out.includes(m)) out.push(m);
    return out;
  }

  function findCondition(st, code) {
    return ((st && st.conditions) || []).find((c) => c && c.code === code) || null;
  }

  function stateInfo(state) {
    return STATES[state == null ? '' : state] || { label: humanize(state), tone: 'none' };
  }

  function causeText(cause) {
    return CAUSES[cause] ? CAUSES[cause].text : humanize(cause);
  }

  /** headline: "AT&T outage — fiber link down (reported by the AT&T gateway)". An UNKNOWN
   *  verdict is a cycle that could not be judged (e.g. interrupted by system sleep, rules
   *  2026.10-4); its reasons say why. */
  function headline(v) {
    if (!v || !v.state) return 'Waiting for the first measurements';
    if (v.state === 'UNKNOWN') return 'Unknown — this measurement could not be judged (see the reason)';
    const c = v.cause ? CAUSES[v.cause] : null;
    // A gateway restart is recorded under LOCAL_FAULT (the gateway was unreachable), but
    // "local fault" would suggest this PC or the owner caused it: name the event instead.
    if (v.cause === 'GATEWAY_REBOOT') return c.text + ' (' + c.src + ')';
    if (c && c.headline) return c.headline;
    let t = stateInfo(v.state).label;
    if (v.cause) t += ' — ' + (c ? c.text : humanize(v.cause));
    if (c && c.src) t += ' (' + c.src + ')';
    return t;
  }

  /** statusStale reports a status that describes no current measurement: no cycle has been
   *  recorded for longer than a monitoring gap (the ledger refuses records, the cycle worker is
   *  stuck, the computer just resumed), so the monitor replaced its last verdict with an UNKNOWN
   *  one that says why and left "since" empty (internal/monitor staleVerdict). Its last sample
   *  is then old. A status whose verdict is the latest sample's own UNKNOWN verdict (a cycle
   *  that could not be judged, e.g. the first one after startup) is not stale: samples are
   *  being produced. */
  function statusStale(st) {
    const v = (st && st.verdict) || {};
    const ls = st && st.last_sample;
    if (v.state !== 'UNKNOWN' || !ls || st.since) return false;
    const lv = (ls && ls.verdict) || {};
    return !(lv.state === 'UNKNOWN' && JSON.stringify(lv.reasons || []) === JSON.stringify(v.reasons || []));
  }

  /** statusHeadline words the monitor's current state (Status). UNKNOWN is never shown as the
   *  state last recorded: before the first cycle the monitor is waiting for it; while no cycle
   *  is recorded the monitor is not producing samples, and its reasons say why. */
  function statusHeadline(st) {
    const v = (st && st.verdict) || {};
    if (!v.state || v.state === 'UNKNOWN') {
      if (!st || !st.last_sample) return 'Waiting for the first measurements';
      if (statusStale(st)) return 'Monitoring is not producing samples — see the reason';
    }
    return headline(v);
  }

  function probeStatusText(p) {
    if (p.ok) return 'OK';
    if (p.status && ICMP_STATUS[p.status]) return ICMP_STATUS[p.status];
    if (p.status) return humanize(p.status);
    return p.err ? 'failed' : 'failed';
  }

  // ------------------------------------------------------------------ icons & small widgets

  /** icon draws a status icon; the shape differs per tone so colour never carries meaning alone. */
  function icon(tone, extraClass) {
    const svg = s('svg', { viewBox: '0 0 16 16', class: 'ico tone-' + tone + (extraClass ? ' ' + extraClass : ''), 'aria-hidden': 'true', focusable: 'false' });
    switch (tone) {
      case 'good':
        svg.append(s('circle', { class: 'bg', cx: 8, cy: 8, r: 7.5 }), s('path', { class: 'fg', d: 'M4.6 8.3l2.3 2.3 4.6-4.8' }));
        break;
      case 'warning':
        svg.append(s('path', { class: 'bg', d: 'M8 .9l7.4 13.4H.6z' }), s('path', { class: 'fg', d: 'M8 5.6v3.9M8 12v.1' }));
        break;
      case 'serious':
        svg.append(s('path', { class: 'bg', d: 'M8 .4l7.6 7.6L8 15.6.4 8z' }), s('path', { class: 'fg', d: 'M8 4.4v4.4M8 11.3v.1' }));
        break;
      case 'critical':
        svg.append(s('path', { class: 'bg', d: 'M5.1.6h5.8l4.5 4.5v5.8l-4.5 4.5H5.1L.6 10.9V5.1z' }), s('path', { class: 'fg', d: 'M5.5 5.5l5 5M10.5 5.5l-5 5' }));
        break;
      case 'info':
        svg.append(s('circle', { class: 'bg', cx: 8, cy: 8, r: 7.5 }), s('path', { class: 'fg', d: 'M8 7.2v4.6M8 4.5v.1' }));
        break;
      default:
        svg.append(s('circle', { class: 'bg', cx: 8, cy: 8, r: 6.8 }), s('path', { class: 'fg', d: 'M5 8h6' }));
    }
    return svg;
  }

  function chip(tone, label, title) {
    return h('span', { class: 'chip tone-' + tone, title: title || null }, icon(tone), label);
  }

  /** alteredChip marks a ledger line whose h is not the SHA-256 of its b. */
  function alteredChip() {
    return chip('critical', 'h ≠ SHA-256(b)', 'This ledger line was changed after it was written. Run Verify on the Evidence page.');
  }

  function stateBadge(state) {
    const si = stateInfo(state);
    return h('span', { class: 'badge' }, icon(si.tone), si.label);
  }

  function lineKey(slot) {
    return s('svg', { class: 'key', viewBox: '0 0 18 10', 'aria-hidden': 'true', focusable: 'false' },
      s('line', { class: 'c' + slot, x1: 1.5, y1: 5, x2: 16.5, y2: 5 }));
  }

  /** tickKey keys a series drawn as tick marks (slot 0: in ink, for the legend's explanation). */
  function tickKey(slot) {
    return s('svg', { class: 'key', viewBox: '0 0 18 10', 'aria-hidden': 'true', focusable: 'false' },
      s('line', { class: 'pk ' + (slot ? 'c' + slot : 'ink'), x1: 5.5, y1: 5, x2: 12.5, y2: 5 }));
  }

  /** chevronKey keys the "at least" mark of lineChart. */
  function chevronKey() {
    return s('svg', { class: 'key', viewBox: '0 0 18 10', 'aria-hidden': 'true', focusable: 'false' },
      s('path', { class: 'atleast', d: 'M5 8L9 3L13 8' }));
  }

  function chevron() {
    return s('svg', { class: 'chev', viewBox: '0 0 12 12', 'aria-hidden': 'true', focusable: 'false' }, s('path', { d: 'M4 2l4 4-4 4' }));
  }

  function spinner() {
    return h('span', { class: 'spinner', 'aria-hidden': 'true' });
  }

  function emptyNote(text) {
    return h('p', { class: 'empty' }, text);
  }

  function notice(tone, ...content) {
    return h('div', { class: 'notice tone-' + tone, role: tone === 'critical' ? 'alert' : 'status' }, ...content);
  }

  /** callout looks like a notice but is part of a card's content, not news: the cards are
   *  rebuilt with every status refresh, and a live region would be announced again each time. */
  function callout(tone, ...content) {
    return h('div', { class: 'notice tone-' + tone }, ...content);
  }

  function errorNotice(err) {
    return notice('critical', (err && err.message) || String(err));
  }

  /** kv renders a definition list, skipping empty values. */
  function kv(rows) {
    const dl = h('dl', { class: 'kv' });
    for (const [k, v] of rows) {
      if (v == null || v === '' || (Array.isArray(v) && v.every((x) => x == null || x === ''))) continue;
      dl.append(h('dt', null, k), h('dd', null, v));
    }
    return dl;
  }

  function card(title, ...body) {
    return h('section', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', null, title)), ...body);
  }

  function cardWithLink(title, href, linkText, ...body) {
    return h('section', { class: 'card' },
      h('div', { class: 'card-head' }, h('h2', null, title), h('a', { href, class: 'small' }, linkText)), ...body);
  }

  /** table builds a simple table; cols: [{label, num, cls}], rows: arrays of cell content.
   *  opts.stack: on narrow screens each row becomes a stacked label/value block. */
  function table(cols, rows, opts) {
    const o = opts || {};
    const t = h('table', { class: 'tbl' + (o.compact ? ' compact' : '') + (o.stack ? ' stack-narrow' : '') });
    if (o.caption) t.append(h('caption', null, o.caption));
    t.append(h('thead', null, h('tr', null, cols.map((c) => h('th', { scope: 'col', class: [c.num ? 'num' : '', c.cls || ''].join(' ').trim() || null }, c.label)))));
    const tb = h('tbody');
    for (const r of rows) tb.append(tableRow(cols, r, o));
    t.append(tb);
    return h('div', { class: 'table-scroll' }, t);
  }

  /** tableRow builds a body row of table() (with the same cols and opts). */
  function tableRow(cols, r, o) {
    return h('tr', null, r.map((cell, i) => h('td', {
      class: [cols[i] && cols[i].num ? 'num' : '', cols[i] && cols[i].cls ? cols[i].cls : ''].join(' ').trim() || null,
      'data-label': o && o.stack && cols[i] ? cols[i].label : null,
    }, cell)));
  }

  function field(labelText, control, hint) {
    const id = control.id || ('f-' + Math.random().toString(36).slice(2, 9));
    control.id = id;
    const hintEl = hint ? h('p', { class: 'hint', id: id + '-hint' }, hint) : null;
    if (hintEl) control.setAttribute('aria-describedby', hintEl.id);
    return h('div', { class: 'field' }, h('label', { for: id }, labelText), control, hintEl);
  }

  function recordsLink(seq) {
    return '#/records?from_seq=' + encodeURIComponent(seq) + '&focus=' + encodeURIComponent(seq);
  }

  /** verdictInputs names the ledger records a verdict was computed from (docs/DESIGN.md §10,
   *  Verdict.inputs) as links, so that every classification can be traced and recomputed. */
  function verdictInputs(inp) {
    if (!inp || typeof inp !== 'object') return null;
    const seqLink = (seq, label) => h('a', { href: recordsLink(seq) }, (label ? label + ' ' : '') + '#' + seq);
    const part = (seq, label, none) => (Number(seq) > 0
      ? seqLink(seq, label)
      : h('span', { class: 'muted', title: 'none, or older than the classifier accepts' }, none));
    const n = Number(inp.window_cycles);
    const out = [
      part(inp.snapshot_seq, 'gateway snapshot', 'no fresh gateway snapshot'), ' · ',
      part(inp.service_check_seq, 'DNS & web check', 'no fresh DNS & web check'),
    ];
    // Rules 2026.10-4: a resolver failure counts only when the check before showed it too.
    if (Number(inp.prev_service_check_seq) > 0) {
      out.push(h('span', { title: 'A DNS resolver counts as failing only when two consecutive checks show the same failure.' },
        ' (compared with the previous ', seqLink(inp.prev_service_check_seq, 'DNS & web check'), ')'));
    }
    out.push(' · ', part(inp.local_link_seq, 'local link', 'no fresh local-link reading'));
    // Rules 2026.10-4: DEGRADED is AT&T's only when the household's own WAN traffic, from the
    // gateway's counters in two snapshots, stayed below 80 Mb/s.
    const from = Number(inp.traffic_from_seq);
    const to = Number(inp.traffic_to_seq);
    if (from > 0 || to > 0) {
      out.push(' · ', h('span', { title: 'The household’s own WAN traffic, from the gateway’s counters in these two snapshots.' },
        'WAN traffic: gateway snapshots ', from > 0 ? seqLink(from) : '?', ' → ', to > 0 ? seqLink(to) : '?'));
    }
    out.push(' · ', 'window of ' + fmtInt(n) + ' cycle' + (n === 1 ? '' : 's'));
    return out;
  }

  function blobLinks(id, opts) {
    if (!HEX64.test(id || '')) return null;
    const o = opts || {};
    const out = [];
    if (o.view) out.push(h('a', { href: '/api/blobs/' + id + '/view', target: '_blank', rel: 'noopener noreferrer' }, o.viewText || 'View page (sandboxed)'));
    out.push(h('a', { href: '/api/blobs/' + id, download: id + '.bin' }, o.downloadText || 'Download raw bytes'));
    return out;
  }

  // ------------------------------------------------------------------ API

  class ApiError extends Error {
    constructor(status, message, data) {
      super(message);
      this.status = status;
      this.data = data;
    }
  }

  /** api performs a same-origin request; non-GET requests carry the CSRF header. opts.signal
   *  (an AbortSignal) cancels it: the server then stops the work for it. */
  async function api(path, opts) {
    const o = opts || {};
    const init = { method: o.method || 'GET', headers: { Accept: 'application/json' }, cache: 'no-store', credentials: 'same-origin' };
    if (o.signal) init.signal = o.signal;
    if (init.method !== 'GET' && init.method !== 'HEAD') {
      init.headers['X-ATT-Monitor'] = '1';
      if (o.body !== undefined) {
        init.headers['Content-Type'] = 'application/json';
        init.body = JSON.stringify(o.body);
      }
    }
    let res;
    try {
      res = await fetch(path, init);
    } catch (_) {
      throw new ApiError(0, 'Cannot reach the att-monitor service. Is it running?');
    }
    const text = await res.text();
    let data = null;
    if (text) {
      try { data = JSON.parse(text); } catch (_) { data = null; }
    }
    if (!res.ok) {
      const msg = data && typeof data.error === 'string' ? data.error : 'HTTP ' + res.status;
      throw new ApiError(res.status, msg, data);
    }
    return o.withHeaders ? { data, headers: res.headers } : data;
  }

  // ------------------------------------------------------------------ page chrome & status loop

  let statusInFlight = false;

  async function refreshStatus() {
    if (statusInFlight) return;
    statusInFlight = true;
    try {
      const st = await api('/api/status');
      const prev = app.status;
      app.status = st;
      app.statusError = null;
      app.statusAt = new Date();
      if (prev && prev.verdict && st.verdict && (prev.verdict.state !== st.verdict.state || prev.verdict.cause !== st.verdict.cause)) {
        announce('Status changed: ' + statusHeadline(st));
      }
      updateChrome();
      if (app.view && app.view.onStatus) app.view.onStatus(st);
    } catch (e) {
      app.statusError = e;
      updateChrome();
    } finally {
      statusInFlight = false;
    }
  }

  function updateChrome() {
    const conn = document.getElementById('conn');
    if (app.statusError) {
      conn.hidden = false;
      conn.textContent = app.statusError.status === 0
        ? 'Cannot reach the att-monitor service. Retrying every 10 seconds — the data shown may be out of date.'
        : 'The monitor returned an error: ' + app.statusError.message;
    } else {
      conn.hidden = true;
    }
    const st = app.status;
    const pill = document.getElementById('pill');
    if (st) {
      const v = st.verdict || {};
      const si = stateInfo(v.state);
      replace(pill, icon(si.tone), h('span', { class: 'pill-text' }, si.label),
        st.since && v.state && v.state !== 'UNKNOWN' ? h('span', { class: 'pill-sub' }, 'for ' + sinceText(st.since, st.now)) : null,
        statusStale(st) ? h('span', { class: 'pill-sub' }, 'not measuring') : null);
      pill.title = statusHeadline(st);
      pill.setAttribute('aria-label', 'Current status: ' + statusHeadline(st));
      document.title = si.label + ' · AT&T Internet Monitor';
    }
    const upd = document.getElementById('foot-updated');
    if (app.statusAt) {
      replace(upd, 'Status updated ', timeEl(app.statusAt, F.time), app.statusError ? ' (stale)' : '');
    }
  }

  // ------------------------------------------------------------------ router

  const ROUTES = [
    [/^\/$/, 'overview', (c, m, q, ctx) => renderOverview(c, ctx)],
    [/^\/incidents$/, 'incidents', (c, m, q, ctx) => renderIncidents(c, q, ctx)],
    [/^\/incidents\/([^/]+)$/, 'incidents', (c, m, q, ctx) => renderIncident(c, safeDecode(m[1]), ctx)],
    [/^\/gateway$/, 'gateway', (c, m, q, ctx) => renderGateway(c, ctx)],
    [/^\/syslog$/, 'syslog', (c, m, q, ctx) => renderSyslog(c, q, ctx)],
    [/^\/evidence$/, 'evidence', (c, m, q, ctx) => renderEvidence(c, ctx)],
    [/^\/records$/, 'records', (c, m, q, ctx) => renderRecords(c, q, ctx)],
  ];

  function safeDecode(v) {
    try { return decodeURIComponent(v); } catch (_) { return v; }
  }

  function parseHash() {
    const raw = window.location.hash.replace(/^#/, '');
    const qi = raw.indexOf('?');
    let path = qi >= 0 ? raw.slice(0, qi) : raw;
    path = '/' + path.replace(/^\/+/, '').replace(/\/+$/, '');
    return { path, query: new URLSearchParams(qi >= 0 ? raw.slice(qi + 1) : '') };
  }

  function newViewCtx() {
    const cleanups = [];
    const ctx = {
      alive: true,
      onStatus: null,
      cleanup(fn) { cleanups.push(fn); },
      interval(fn, ms) {
        const id = window.setInterval(fn, ms);
        cleanups.push(() => window.clearInterval(id));
      },
      dispose() {
        ctx.alive = false;
        ctx.onStatus = null;
        for (const fn of cleanups.splice(0)) {
          try { fn(); } catch (_) { /* ignore */ }
        }
      },
    };
    return ctx;
  }

  let firstRoute = true;

  function route() {
    const { path, query } = parseHash();
    if (app.view) app.view.dispose();
    const ctx = newViewCtx();
    app.view = ctx;
    const container = h('div', { class: 'stack' });
    document.getElementById('view').replaceChildren(container);
    let name = '';
    for (const [re, routeName, fn] of ROUTES) {
      const m = path.match(re);
      if (!m) continue;
      name = routeName;
      Promise.resolve()
        .then(() => fn(container, m, query, ctx))
        .catch((err) => { if (ctx.alive) container.append(errorNotice(err)); });
      break;
    }
    if (!name) {
      container.append(h('h1', null, 'Page not found'), h('p', null, h('a', { href: '#/' }, 'Go to the overview')));
    }
    for (const a of document.querySelectorAll('.nav a')) {
      if (a.dataset.route === name) a.setAttribute('aria-current', 'page');
      else a.removeAttribute('aria-current');
    }
    if (!firstRoute) {
      const title = container.querySelector('h1');
      if (title) {
        title.setAttribute('tabindex', '-1');
        title.focus();
      }
      window.scrollTo(0, 0);
    }
    firstRoute = false;
  }

  // ------------------------------------------------------------------ overview

  function renderOverview(c, ctx) {
    const hero = h('section', { class: 'card hero tone-none', 'aria-label': 'Current status' },
      icon('none', 'hero-icon'), h('div', null, h('p', { class: 'loading' }, 'Loading status…')));
    const conditions = h('div', { class: 'conditions' });
    const tiles = h('section', { 'aria-label': 'Availability statistics' });
    const cards = h('div', { class: 'grid' });
    const charts = h('section', { 'aria-labelledby': 'history-h' });
    const recent = h('section', { class: 'card', 'aria-labelledby': 'recent-h' });
    c.append(h('h1', { class: 'sr-only' }, 'Overview'), hero, conditions, tiles, cards, charts, recent);

    const update = (st) => {
      fillHero(hero, st);
      fillAlerts(conditions, st, null);
      fillTiles(tiles, st);
      fillCards(cards, st);
    };
    ctx.onStatus = update;
    if (app.status) update(app.status);
    setupCharts(charts, ctx);
    loadRecentIncidents(recent, ctx);
    ctx.interval(() => { if (!document.hidden) loadRecentIncidents(recent, ctx); }, SERIES_REFRESH_MS);
  }

  function fillHero(el, st) {
    const v = st.verdict || {};
    const si = stateInfo(v.state);
    const unknown = !v.state || v.state === 'UNKNOWN';
    const ls = st.last_sample;
    el.className = 'card hero tone-' + si.tone;
    const body = h('div', { class: 'hero-body' },
      h('p', { class: 'eyebrow' }, 'Internet status now'),
      h('h2', { class: 'hero-title' }, statusHeadline(st)));
    // An UNKNOWN verdict attributes nothing to anyone.
    if (!unknown && ATTR_LONG[v.attribution]) body.append(h('p', { class: 'hero-attr' }, ATTR_LONG[v.attribution]));
    if (st.since && !unknown) {
      body.append(h('p', { class: 'hero-since' }, 'In this state since ', timeEl(st.since), ' (' + sinceText(st.since, st.now) + ')'));
    }
    if (statusStale(st)) {
      body.append(h('p', { class: 'hero-since' }, 'The last measurement recorded was taken ', timeEl(ls.started),
        ' (' + sinceText(ls.started, st.now) + ' ago). What this page shows from it is not the current state.'));
    }
    if (v.reasons && v.reasons.length) {
      body.append(h('ul', { class: 'reasons', 'aria-label': 'Why' }, v.reasons.map((r) => h('li', null, r))));
    }
    if (v.inputs) body.append(h('p', { class: 'hero-meta' }, 'Classified from: ', verdictInputs(v.inputs)));
    if (st.active_incident) body.append(activeIncidentBanner(st.active_incident, st.now));
    const mon = st.monitor || {};
    const age = ls && !statusStale(st) ? ageSeconds(ls.started, st.now) : null; // a stale status says it above
    body.append(h('p', { class: 'hero-meta' },
      'Classifier rules ', h('code', null, v.rules || '—'),
      ls ? [' · last measurement ', timeEl(ls.started, F.time), age != null && age > 120 ? ' (' + fmtDur(age) + ' ago)' : null] : null,
      mon.mode ? [' · monitor running as ', mon.mode, ' for ', fmtDur(mon.uptime_s)] : null));
    replace(el, icon(si.tone, 'hero-icon'), body);
  }

  function activeIncidentBanner(inc, now) {
    const si = stateInfo(inc.state);
    return h('div', { class: 'banner tone-' + si.tone },
      icon(si.tone),
      h('div', { class: 'banner-body' },
        h('p', { class: 'banner-title' }, 'Incident in progress: ', inc.id),
        h('p', null, headline(inc), ' — open for ', sinceText(inc.opened, now), ' (since ', timeEl(inc.opened), ').'),
        h('p', null, h('a', { href: '#/incidents/' + encodeURIComponent(inc.id) }, 'Open the incident and its evidence'))));
  }

  function severityRank(sev) {
    return sev === 'critical' ? 3 : sev === 'warning' ? 2 : sev === 'info' ? 1 : 0;
  }

  function toneOf(severity) {
    return severity === 'critical' ? 'critical' : severity === 'warning' ? 'warning' : 'info';
  }

  /** conditionGroups merges the gateway's flags for one measurement (e.g. Rx low alarm and
   *  Rx low warning) into one group, most severe first; groups are ordered by severity. */
  function conditionGroups(conds) {
    const groups = new Map();
    for (const cnd of conds || []) {
      const m = GATEWAY_FLAG_RE.exec(cnd.code || '');
      const key = m ? m[1] : cnd.code;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(cnd);
    }
    const out = [...groups.values()].map((g) => g.sort((a, b) => severityRank(b.severity) - severityRank(a.severity)));
    return out.sort((a, b) => severityRank(b[0].severity) - severityRank(a[0].severity));
  }

  // The answer to an operator action taken from a banner (e.g. a confirmed gateway
  // certificate) is shown above the conditions for a while: the status refresh that removes
  // the banner itself must not take the answer with it.
  const flash = { node: null, until: 0 };

  function setFlash(node, ms) {
    flash.node = node;
    flash.until = Date.now() + (ms || 120000);
  }

  const alertKeys = new WeakMap();

  /** fillAlerts shows the flash and the conditions (all of them, or those with the given
   *  codes). It re-renders only when something changed, so a banner stays put while read. */
  function fillAlerts(el, st, codes) {
    const conds = alertConditions(st, codes);
    const fl = flash.node && Date.now() < flash.until ? flash.node : null;
    const d = st.gateway && st.gateway.derived;
    const key = JSON.stringify([conds, certState(st), d ? [d.rx_power_x10, d.rx_low_alarm_x10, d.rx_low_warn_x10] : null, fl ? flash.until : 0, certBusy]);
    if (alertKeys.get(el) === key) return;
    alertKeys.set(el, key);
    replace(el, fl, ...conditionGroups(conds).map((g) => conditionBanner(g, st)));
  }

  /** alertConditions lists the conditions to show (all, or those with the given codes). A
   *  changed gateway certificate that the monitor's certificate state reports as pending is
   *  shown even when the condition reporting it is missing. */
  function alertConditions(st, codes) {
    const conds = (st.conditions || []).filter((c) => c && (!codes || codes.includes(c.code)));
    const gc = certState(st);
    if (gc && gc.pending && (!codes || codes.includes('GATEWAY_CERT_CHANGED')) && !conds.some((c) => c.code === 'GATEWAY_CERT_CHANGED')) {
      conds.push({ code: 'GATEWAY_CERT_CHANGED', severity: 'critical', since: gc.since, seq: gc.seq });
    }
    return conds;
  }

  /** evidenceLink links the Evidence page, except on the Evidence page itself. */
  function evidenceLink(text) {
    return parseHash().path === '/evidence' ? null : h('a', { href: '#/evidence' }, text);
  }

  function conditionBanner(group, st) {
    const cnd = group[0];
    // A condition that the certificate state contradicts (nothing pending) is shown as reported,
    // without a confirmation.
    if (cnd.code === 'GATEWAY_CERT_CHANGED' && certPending(st)) return certBanner(cnd, st);
    const tone = toneOf(cnd.severity);
    const fromGateway = GATEWAY_FLAG_RE.test(cnd.code || '');
    const body = h('div', { class: 'banner-body' },
      h('p', { class: 'banner-title' }, COND_TITLES[cnd.code] || humanize(cnd.code), fromGateway ? ' — flagged by the AT&T gateway itself' : ''));
    if (group.length > 1) {
      body.append(h('p', { class: 'chips' }, 'Gateway flags: ',
        group.map((c) => chip(toneOf(c.severity), String(c.code).replace(GATEWAY_FLAG_RE, '').replace(/_/g, ' ')))));
    }
    if (cnd.message) body.append(h('p', null, cnd.message));
    const d = st.gateway && st.gateway.derived;
    if (/^OPTICAL_RX_LOW/.test(cnd.code || '') && d && d.rx_power_x10 != null) {
      const parts = ['Received light ' + (d.rx_power_x10 / 10).toFixed(1) + ' dBm'];
      if (d.rx_low_alarm_x10 != null) parts.push('gateway alarm threshold ' + (d.rx_low_alarm_x10 / 10).toFixed(1) + ' dBm');
      if (d.rx_low_warn_x10 != null) parts.push('warning threshold ' + (d.rx_low_warn_x10 / 10).toFixed(1) + ' dBm');
      if (d.rx_low_alarm_x10 != null && d.rx_power_x10 < d.rx_low_alarm_x10) {
        parts.push(((d.rx_low_alarm_x10 - d.rx_power_x10) / 10).toFixed(1) + ' dB below the alarm threshold');
      }
      body.append(h('p', { class: 'figure' }, parts.join(' · ')));
    }
    if (fromGateway) {
      // Say exactly what the flag shows — no more.
      let why = '';
      if (/^OPTICAL_RX_/.test(cnd.code)) {
        why = 'The received optical level is measured by the gateway’s fiber module and depends on AT&T’s fiber path into the home (network, drop, wall jack, patch cord, connectors) — not on this PC or the home Wi-Fi. This is provider-side evidence.';
      } else if (/^OPTICAL_TX_/.test(cnd.code)) {
        why = 'The transmit level is produced by the optical module inside the AT&T-supplied gateway.';
      } else if (/^TX_BIAS_/.test(cnd.code)) {
        why = 'The laser bias current is that of the optical module inside the AT&T-supplied gateway.';
      } else if (/^VCC_/.test(cnd.code)) {
        why = 'The supply voltage is that of the optical module inside the AT&T-supplied gateway (the gateway reports whole volts).';
      } else {
        why = 'This is the temperature of the gateway’s optical module; it can also be affected by where the gateway is placed (ventilation).';
      }
      body.append(h('p', { class: 'src' },
        'Source: the gateway’s own fiber diagnostics (fiberstat page, alarm/warning flags), captured byte-exact in the evidence ledger. ' + why));
    }
    if (cnd.code === 'NOTIFICATION_REDIRECT_ON') {
      body.append(h('p', { class: 'src' }, 'While the internet is down the gateway redirects web browsing to AT&T pages. ',
        h('a', { href: '#/gateway' }, 'Turn it off on the Gateway page')));
    }
    if (cnd.code === 'NO_ACCESS_CODE') {
      body.append(h('p', { class: 'src' }, 'Monitoring needs no access code — only checking or changing the gateway’s outage-redirect setting does. To store it, run ',
        h('code', null, 'att-monitor set-access-code --file PATH'), ' as administrator (the device access code is printed on the gateway’s label).'));
    }
    if (cnd.code === 'ANCHOR_UNTRUSTED') {
      body.append(h('p', { class: 'src' }, 'An RFC 3161 time-stamp proves when records existed only if its signature verifies and the time-stamp authority’s certificate chains to a trusted root. Records after the last trusted time-stamp therefore count as not yet time-stamped; they remain hash-chained and signed. ',
        evidenceLink('Check the time-stamps on the Evidence page')));
    }
    if (cnd.code === 'EGRESS_NOT_VIA_GATEWAY') {
      body.append(h('p', { class: 'src' }, 'att-monitor checks the route Windows uses to reach the AT&T gateway and each internet destination. While a destination is routed past the gateway — through a VPN tunnel, a second network adapter or a phone hotspot — what this computer measures on the Internet may be that other network’s doing, so nothing is attributed to AT&T: an outage is recorded as this computer’s routing, not as an AT&T outage (unless the gateway itself reports its fiber or broadband connection down), and a slowdown stays undetermined. Disconnect the VPN or the other network to resume attribution. Per-application VPNs and IPv6 destinations are not detected. The routes are listed under “Route to the Internet” in the Local link card on the Overview.'));
    }
    if (cnd.code === 'LEDGER_WRITE_FAILING') {
      body.append(h('p', { class: 'src' }, 'Nothing that happens now becomes evidence, so this period will be missing from the ledger. Free disk space on the data volume; otherwise att-monitor stops so that Windows restarts the service, which reopens the ledger with its crash recovery. ',
        evidenceLink('Ledger and data directory on the Evidence page')));
    }
    if (cnd.code === 'DISK_SPACE_LOW') {
      body.append(h('p', { class: 'src' }, 'Once the volume is full no record can be written and the monitor stops producing evidence. Free space on the volume that holds the data directory. ',
        evidenceLink('Data directory on the Evidence page')));
    }
    if (cnd.code === 'CLOCK_OFFSET') {
      body.append(h('p', { class: 'src' }, 'Every record carries this computer’s time, so a wrong clock shifts the recorded times by that much; the RFC 3161 time-stamps still prove when records existed. Correct the clock in Windows Settings › Time & language › Date & time (Sync now), or run ',
        h('code', null, 'w32tm /resync'), ' as administrator.'));
    }
    const since = group.map((c) => c.since).filter((v) => toDate(v)).sort((a, b) => toMs(a) - toMs(b))[0];
    const seqs = [...new Set(group.map((c) => c.seq).filter((n) => n))];
    if (since || seqs.length) {
      body.append(h('p', { class: 'src' },
        since ? ['Since ', timeEl(since)] : null,
        since && seqs.length ? ' · ' : null,
        seqs.map((n, i) => [i ? ', ' : '', h('a', { href: recordsLink(n) }, 'evidence record #' + n)])));
    }
    return h('div', { class: 'banner tone-' + tone }, icon(tone), body);
  }

  // ------------------------------------------------------------------ gateway certificate

  let certBusy = false; // a confirmation is being sent
  const certInfoCache = new Map();

  /** certState returns the gateway certificate pin as the monitor applies it
   *  (Status.gateway_cert: pinned, pending, since, seq), or null when the status does not
   *  carry it (an older monitor). */
  function certState(st) {
    const gc = st && st.gateway_cert;
    return gc && typeof gc === 'object' && !Array.isArray(gc) ? gc : null;
  }

  /** certPending reports whether a changed gateway certificate waits for the operator's
   *  confirmation: as the certificate state says, or else as the GATEWAY_CERT_CHANGED
   *  condition says. */
  function certPending(st) {
    const gc = certState(st);
    return gc ? !!gc.pending : !!findCondition(st, 'GATEWAY_CERT_CHANGED');
  }

  /** certInfoFromState is what the banner shows from the certificate state: the pinned
   *  (before) and pending (after) fingerprints, when the pending one was first presented and
   *  the evidence record that reported it, as {before, after, since, seq, problem}. A problem
   *  says why the certificate cannot be confirmed from here (its button stays disabled). */
  function certInfoFromState(gc, cnd) {
    const info = { before: normFp(gc.pinned), after: normFp(gc.pending), since: gc.since || '', seq: Number(gc.seq) || 0, problem: '' };
    const named = hex64sIn(cnd && cnd.message);
    if (!info.after) {
      info.problem = 'The monitor reports a changed certificate without a valid SHA-256 fingerprint (' + String(gc.pending) + '), so it cannot be confirmed here.';
    } else if (named.length && !named.includes(info.after)) {
      // The message is shown next to the button: it must not name another certificate than
      // the one a confirmation pins.
      info.problem = 'The monitor’s message names another certificate (' + named.map((x) => shortHash(x, 16)).join(', ') +
        ') than its certificate state (' + shortHash(info.after, 16) + '). Reload the page; if this persists, restart att-monitor.';
    }
    return info;
  }

  /** certInfo resolves to what can be shown about a GATEWAY_CERT_CHANGED condition when the
   *  status carries no certificate state: the pinned (before) and presented (after)
   *  fingerprints from the cert_changed gateway_event record it cites, cross-checked with the
   *  fingerprint its message names, as {before, after, since, seq, problem}. A problem says
   *  why the certificate cannot be confirmed from here (its button stays disabled). */
  function certInfo(cnd) {
    const key = (cnd.seq || 0) + '|' + (cnd.message || '');
    if (!certInfoCache.has(key)) {
      const p = loadCertInfo(cnd);
      certInfoCache.set(key, p);
      p.then((info) => { if (info.retry) certInfoCache.delete(key); });
    }
    return certInfoCache.get(key);
  }

  async function loadCertInfo(cnd) {
    const named = hex64sIn(cnd.message);
    const info = { before: '', after: '', since: cnd.since || '', seq: 0, problem: '', retry: false };
    if (Number(cnd.seq) > 0) {
      try {
        const recs = await api('/api/records?from_seq=' + encodeURIComponent(cnd.seq) + '&limit=1');
        const rec = Array.isArray(recs) ? recs[0] : null;
        const d = rec && rec.body && rec.body.data;
        if (rec && rec.seq === cnd.seq && rec.type === 'gateway_event' && d && d.kind === 'cert_changed') {
          info.seq = rec.seq;
          info.before = normFp(d.before);
          info.after = normFp(d.after);
          if (rec.hash_ok === false) {
            info.problem = 'Evidence record #' + rec.seq + ' fails its hash check (h ≠ SHA-256(b)), so its fingerprints cannot be relied on. Run Verify on the Evidence page.';
          }
        }
      } catch (_) {
        info.retry = true; // the message still names the certificate; read the record next time
      }
    }
    if (!info.problem) {
      if (info.after && named.length && !named.includes(info.after)) {
        info.problem = 'The monitor now names another certificate (' + named.map((x) => shortHash(x, 16)).join(', ') +
          ') than evidence record #' + info.seq + '. Reload the page; if this persists, run Verify on the Evidence page.';
      } else if (!info.after && named.length === 1) {
        info.after = named[0];
      } else if (!info.after) {
        info.problem = 'The new certificate’s fingerprint is not known, so it cannot be confirmed here.';
      }
    }
    return info;
  }

  function fpLine(label, fp) {
    return h('p', { class: 'cert-fp' }, h('span', { class: 'cert-fp-label' }, label), ' ',
      fp ? h('span', { class: 'fp' }, groupFingerprint(fp)) : h('span', { class: 'muted' }, 'not recorded'));
  }

  function capitalize(text) {
    const t = String(text || '');
    return t.charAt(0).toUpperCase() + t.slice(1);
  }

  /** certBanner explains a changed gateway TLS certificate (GATEWAY_CERT_CHANGED), shows the
   *  pinned and the presented fingerprints and lets the operator trust the new one. Everything
   *  comes from the monitor's certificate state (Status.gateway_cert); only a status without it
   *  falls back to the condition's evidence record and message. */
  function certBanner(cnd, st) {
    const gc = certState(st);
    const since = gc ? gc.since : cnd.since;
    const seq = Number(gc ? gc.seq : cnd.seq) || 0;
    const fps = h('div', { class: 'cert-fps' }, gc ? null : h('p', { class: 'loading' }, 'Reading the evidence record…'));
    const btn = h('button', { type: 'button', class: 'btn btn-primary', disabled: true }, 'Trust the new certificate');
    const body = h('div', { class: 'banner-body' },
      h('p', { class: 'banner-title' }, COND_TITLES.GATEWAY_CERT_CHANGED),
      h('p', null, 'The AT&T gateway presented a different TLS certificate from the one att-monitor pinned. Status pages are still read and recorded (they need no login), but authenticated actions — checking or changing the outage-redirect setting — are paused, so the gateway’s access code is never sent to a device that may not be your gateway.'),
      fps,
      cnd.message ? h('p', { class: 'src' }, 'Monitor: ', cnd.message) : null,
      since || seq ? h('p', { class: 'src' }, since ? ['Since ', timeEl(since)] : null, since && seq ? ' · ' : null,
        seq ? h('a', { href: recordsLink(seq) }, 'evidence record #' + seq) : null) : null,
      h('div', { class: 'btn-row' }, btn, certBusy ? h('span', { class: 'small' }, spinner(), ' Confirming…') : null));
    const show = (info) => {
      replace(fps, fpLine('Pinned until now:', info.before), fpLine('Presented now:', info.after),
        info.problem ? notice('critical', info.problem) : null);
      if (!info.problem && info.after && !certBusy) {
        btn.disabled = false;
        btn.addEventListener('click', () => trustCertificate(info, btn));
      }
    };
    if (gc) show(certInfoFromState(gc, cnd));
    else certInfo(cnd).then(show);
    return h('div', { class: 'banner tone-critical' }, icon('critical'), body);
  }

  async function trustCertificate(info, btn) {
    const ok = await dialog({
      title: 'Trust the new gateway certificate?',
      body: [
        h('p', null, h('strong', null, 'Only confirm if AT&T updated your gateway (e.g. a firmware update) or you replaced it. Otherwise another device may be impersonating your gateway.')),
        fpLine('New certificate (SHA-256):', info.after),
        info.before ? fpLine('Pinned until now:', info.before) : null,
        info.since || info.seq ? h('p', { class: 'small muted' }, info.since ? ['Presented since ', timeEl(info.since)] : null,
          info.since && info.seq ? ' · ' : null, info.seq ? 'reported in evidence record #' + info.seq : null) : null,
        h('p', null, 'Confirming pins the new certificate, records your decision in the evidence ledger (a config_change record) and resumes the authenticated gateway actions. You can compare the fingerprint with the one your browser shows for the gateway’s own web page.'),
      ],
      confirm: 'Trust the new certificate',
    });
    if (!ok) return;
    certBusy = true;
    btn.disabled = true;
    try {
      // sha256: the monitor pins nothing but this certificate (it compares it with the pending
      // one under its own lock), so nothing the reader was not shown can be pinned.
      const cc = await api('/api/gateway/trust-cert', { method: 'POST', body: { sha256: info.after } });
      setFlash(notice('good', h('strong', null, 'New gateway certificate trusted. '),
        'SHA-256 ', h('span', { class: 'fp' }, groupFingerprint(normFp(cc && cc.after) || info.after)),
        ' is now pinned and authenticated gateway actions resume. Recorded in the evidence ledger: “',
        (cc && cc.what) || 'configuration change', '”, ', (cc && cc.result) || 'applied', '.'));
      announce('Gateway certificate trusted.');
    } catch (e) {
      if (e.status === 404) {
        setFlash(notice('info', 'No changed certificate is waiting for confirmation any more: it was confirmed already, or the gateway presents its pinned certificate again.'));
      } else {
        // The server's message says what happened: which certificate waits now when it is not
        // the one shown (409), and what did change when something after the pinning failed.
        setFlash(notice('critical', capitalize(e.message)), 600000);
      }
    } finally {
      certBusy = false;
      refreshStatus();
    }
  }

  function fillTiles(el, st) {
    const by = {};
    for (const w of st.stats || []) by[w.window] = w;
    const d = by['24h'];
    const wk = by['7d'];
    if (!d && !wk) {
      replace(el);
      return;
    }
    const tile = (label, get, fmt, hint) => h('div', { class: 'tile', title: hint || null },
      h('p', { class: 'tile-label' }, label),
      h('p', { class: 'tile-value' }, d ? fmt(get(d)) : '—'),
      wk ? h('p', { class: 'tile-sub' }, 'Last 7 days: ' + fmt(get(wk))) : null);
    const restarts = rulesAtLeast((st.monitor || {}).rules, RULES_RESTART_WINDOWS)
      ? ' Cycles while the AT&T gateway was restarting are not counted.' : '';
    replace(el,
      h('h2', { class: 'sr-only' }, 'Last 24 hours'),
      h('div', { class: 'tiles' },
        tile('Availability, last 24 h', (x) => x.availability_pct, (p) => fmtPct(p, 2), 'Share of measurement cycles classified ONLINE'),
        tile('AT&T-attributed time without Internet', (x) => x.provider_outage_s, fmtDur,
          'Time of measurement cycles classified as an AT&T outage (the AT&T gateway answered, no internet target did, and this computer’s traffic was not routed past the gateway); each cycle counts until the next one started.' + restarts),
        tile('Degraded', (x) => x.degraded_s, fmtDur, 'Time of measurement cycles classified DEGRADED (packet loss, high latency or DNS failures), whoever caused them'),
        tile('Incidents', (x) => x.incidents, fmtInt),
        tile('Blips (short drops)', (x) => x.blips, fmtInt, 'Bad streaks too short to open an incident'),
        tile('Monitoring coverage', (x) => x.coverage_pct, (p) => fmtPct(p, 1), 'Share of the window during which the monitor was measuring')));
  }

  function fillCards(el, st) {
    replace(el, cardInternet(st), cardGatewayWAN(st), cardFiber(st), cardLocalLink(st), syslogCard(st, true), cardEvidence(st), cardMonitor(st));
  }

  /** probeLabel names a probe as configured (Status.probes, else the chart series' list). */
  function probeLabel(p) {
    for (const list of [app.status && app.status.probes, app.series && app.series.probes]) {
      if (!Array.isArray(list)) continue;
      const spec = list.find((x) => x && x.name === p.name);
      if (spec && spec.label) return spec.label;
    }
    if (!p.target && !p.kind) return p.name;
    return (p.target || p.name) + ' (' + String(p.kind || '').toUpperCase() + ')';
  }

  /** isHijackTestName tells the DNS hijack test from the resolution checks. Every service check
   *  also asks the gateway's resolver for a random "<hex>.invalid" name (docs/DESIGN.md §8).
   *  Names under .invalid never exist (RFC 6761). The rule is the monitor's isInvalidName. */
  function isHijackTestName(name) {
    const n = String(name == null ? '' : name).trim().toLowerCase().replace(/\.$/, '');
    return n === 'invalid' || n.endsWith('.invalid');
  }

  /** rcodeOK accepts the spellings a DNS client may use for "no error", as the classifier does. */
  function rcodeOK(rc) {
    return ['', 'NOERROR', 'RCODESUCCESS', 'SUCCESS', '0'].includes(String(rc == null ? '' : rc).trim().toUpperCase());
  }

  /** dnsVerdict judges one DNS query of a service check by the monitor's rules (docs/DESIGN.md
   *  §8-§9) and returns { test, tone, label, title, note, text }.
   *  - A resolution check passes when it gets a well-formed, successful answer that carries a
   *    record (the classifier's dnsAnswered).
   *  - The hijack test (test: true) passes when the resolver does not resolve the name, so
   *    NXDOMAIN is the correct answer there, not a failure. Any answer to it is a hijack, which
   *    the monitor records as hijacked, and only a hijack is critical. The monitor classifies
   *    nothing else from this query, so a query that got no usable answer leaves the test
   *    incomplete (a warning), not failed.
   *  tone and label make the chip and title is its tooltip. note is a short explanation shown
   *  under the chip, and text is the wording used in the timeline and the records. */
  function dnsVerdict(r) {
    const test = isHijackTestName(r.name);
    const rc = String(r.rcode == null ? '' : r.rcode).trim();
    const answers = Array.isArray(r.answers) ? r.answers : [];
    const v = (tone, label, text, note, title) => ({ test, tone, label, text, note: note || null, title: title || null });
    if (r.hijacked) return v('critical', 'HIJACKED', 'HIJACKED' + (r.hijack_why ? ' (' + r.hijack_why + ')' : ''), null, r.hijack_why);
    if (!r.ok) {
      // A response that arrived but could not be read still carries its rcode.
      const label = rc ? 'malformed answer' : 'no answer';
      return test ? v('warning', label, label + ' (hijack test not completed)', 'hijack test not completed', r.err) : v('critical', label, label, null, r.err);
    }
    if (test) {
      if (answers.length) {
        return v('warning', 'unexpected answer', 'answered a name that never exists', 'a name that never exists was answered',
          'The resolver answered a name that never exists, but this record does not flag the answer as a hijack.');
      }
      const why = rc.toUpperCase() === 'NXDOMAIN' ? 'NXDOMAIN, the correct answer' : 'answered ' + (rc || 'NOERROR') + ', no address';
      return v('good', 'not hijacked', 'not hijacked (' + why + ')', why,
        'The resolver gave no address for a name that never exists, so it is not redirecting (hijacking) DNS.');
    }
    if (!rcodeOK(rc)) return v('critical', rc, 'answered ' + rc, null, r.err);
    if (!answers.length) return v('critical', 'no address', 'answered ' + (rc || 'NOERROR') + ', no address', null, 'The resolver answered without any record for the name.');
    return v('good', 'answered', 'answered');
  }

  /** dnsCheckName names the resolver a DNS query went to ("Gateway DNS") and marks the hijack test. */
  function dnsCheckName(r) {
    const role = DNS_ROLES[r.server_role] || r.server_role || 'DNS';
    return isHijackTestName(r.name) ? role + ' hijack test' : role;
  }

  /** dnsRetryable mirrors the monitor's dnsRetryable: a query that got no valid response or
   *  SERVFAIL is asked once more within its service check (rules 2026.10-4). */
  function dnsRetryable(r) {
    return !!r.err || !r.ok || String(r.rcode == null ? '' : r.rcode).trim().toUpperCase() === 'SERVFAIL';
  }

  /** dnsQueries groups the DNS results of a service check by query. The monitor records a
   *  retry right after the query it repeats (same resolver, name and type); such a pair is one
   *  query of the check, judged by both results. The hijack test is never retried. */
  function dnsQueries(list) {
    const out = [];
    for (const r of Array.isArray(list) ? list : []) {
      if (!r || typeof r !== 'object') continue;
      const q = out[out.length - 1];
      const a = q && q.length === 1 ? q[0] : null;
      if (a && a.server === r.server && a.server_role === r.server_role && a.name === r.name &&
        (a.qtype || 'A') === (r.qtype || 'A') && !isHijackTestName(r.name) && dnsRetryable(a)) {
        q.push(r);
      } else {
        out.push([r]);
      }
    }
    return out;
  }

  /** dnsQueryVerdict judges one query of a service check (dnsQueries) by all its results: a
   *  hijacked answer is shown whichever result carries it; otherwise the query passed if any
   *  result passed (a lost datagram that the retry made up for is not a failing resolver, as
   *  for the classifier); otherwise the retry's outcome is shown. It returns dnsVerdict's
   *  fields for the result shown (r); for a retried query, retry is the note
   *  "first query: … · retry: …", retryTitle the details, and text names both results. */
  function dnsQueryVerdict(q) {
    const vs = q.map(dnsVerdict);
    let i = vs.findIndex((x) => x.label === 'HIJACKED');
    if (i < 0) i = vs.findIndex((x) => x.tone === 'good');
    if (i < 0) i = vs.length - 1;
    const v = Object.assign({}, vs[i], { r: q[i], retry: null, retryTitle: null });
    if (q.length > 1) {
      const first = vs[0];
      const last = vs[vs.length - 1];
      v.retry = 'first query: ' + first.label + ' · retry: ' + last.label;
      v.retryTitle = q.map((r, k) => (k ? 'retry: ' : 'first query: ') + (r.err || vs[k].text)).join('\n');
      v.text = i > 0 && (v.tone === 'good' || v.label === 'HIJACKED')
        ? vs[i].text + ' on the retry (first query: ' + first.text + ')'
        : first.text + '; retried: ' + last.text;
    }
    return v;
  }

  function cardInternet(st) {
    const smp = st.last_sample;
    if (!smp) return card('Internet', emptyNote('No measurements yet.'));
    const stale = statusStale(st);
    const probes = smp.probes || [];
    const inet = probes.filter((p) => p.role === 'internet');
    const ok = inet.filter((p) => p.ok).length;
    const tone = !inet.length || stale ? 'none' : ok === inet.length ? 'good' : ok === 0 ? 'critical' : 'warning';
    const tbl = h('table', { class: 'tbl compact' },
      h('thead', null, h('tr', null, h('th', { scope: 'col' }, 'Probe'), h('th', { scope: 'col' }, 'Result'), h('th', { scope: 'col', class: 'num' }, 'Round trip'))));
    for (const [role, label] of [['gateway', 'AT&T gateway (home network)'], ['isp_hop', 'AT&T next hop'], ['internet', 'Internet']]) {
      const group = probes.filter((p) => p.role === role);
      if (!group.length) continue;
      const tb = h('tbody', null, h('tr', null, h('th', { scope: 'rowgroup', colspan: 3, class: 'small muted' }, label)));
      for (const p of group) {
        tb.append(h('tr', null,
          h('td', null, probeLabel(p)),
          h('td', null, p.ok ? chip('good', 'OK') : chip('critical', probeStatusText(p), [p.status, p.err].filter(Boolean).join(' — '))),
          h('td', { class: 'num' }, p.ok ? fmtRTT(p.rtt_us) : '—')));
      }
      tbl.append(tb);
    }
    const body = [
      // Never let the last recorded measurement read as the present one.
      stale ? callout('warning', h('strong', null, 'Not current. '), 'This is the last measurement recorded, ',
        sinceText(smp.started, st.now), ' ago: the monitor is not producing samples (see the status above).') : null,
      h('p', { class: 'big-line' }, icon(tone), (stale ? 'Last recorded: ' : '') + `${ok} of ${inet.length} internet probes answered`),
      h('div', { class: 'table-scroll' }, tbl),
    ];
    const sc = st.last_service_check;
    if (sc) {
      // A query and its retry (rules 2026.10-4) are one row, judged by both results.
      const dnsRows = dnsQueries(sc.dns).map((q) => {
        const v = dnsQueryVerdict(q);
        const r = v.r;
        return [
          h('span', { title: v.test ? HIJACK_TEST_HELP : null }, dnsCheckName(r), h('span', { class: 'small muted' }, ' ' + String(r.server || '').replace(/:53$/, '')),
            r.name ? h('span', { class: 'sub small muted wrap-any' }, v.test ? r.name + ' (a reserved name that never exists)' : r.name) : null),
          h('span', null,
            h('span', { class: 'chips' },
              chip(v.tone, v.label, v.title),
              r.truncated ? chip('warning', 'truncated', 'The answer had its TC (truncated) bit set: it may be incomplete.') : null),
            Array.isArray(r.answers) && r.answers.length ? h('span', { class: 'sub small muted wrap-any' }, r.answers.join(', ')) : null,
            r.hijacked && r.hijack_why ? h('span', { class: 'sub small wrap-any' }, r.hijack_why) : null,
            v.note ? h('span', { class: 'sub small muted' }, v.note) : null,
            v.retry ? h('span', { class: 'sub small muted', title: v.retryTitle }, v.retry) : null),
          r.ok ? fmtRTT(r.rtt_us) : '—',
        ];
      });
      const httpRows = (sc.http || []).map((r) => [
        h('span', null, HTTP_CHECK_NAMES[r.name] || r.name,
          r.tls_cert_sha256 ? h('span', { class: 'sub small muted', title: 'SHA-256 of the TLS certificate the server presented: ' + r.tls_cert_sha256 },
            'TLS certificate ' + shortHash(r.tls_cert_sha256, 12)) : null),
        h('span', null,
          r.hijacked ? chip('critical', 'HIJACKED', r.hijack_why) : r.ok ? chip('good', 'OK ' + (r.status || '')) : chip('critical', r.status ? 'HTTP ' + r.status : 'failed', r.err),
          r.hijacked ? httpHijackDetail(r) : null),
        r.ok ? fmtRTT(r.rtt_us) : '—',
      ]);
      body.push(h('h3', { class: 'subhead' }, 'Name resolution & web checks'),
        table([{ label: 'Check' }, { label: 'Result' }, { label: 'Time', num: true }], dnsRows.concat(httpRows), { compact: true }));
    }
    body.push(h('p', { class: 'card-foot' }, 'Cycle #', fmtInt(smp.cycle), ' at ', timeEl(smp.started, F.time), smp.dur_ms != null ? ` · took ${smp.dur_ms} ms` : ''));
    return card('Internet', ...body);
  }

  /** httpHijackDetail shows what answered a hijacked web check: the evidence itself. */
  function httpHijackDetail(r) {
    const parts = [];
    if (r.hijack_why) parts.push(String(r.hijack_why));
    if (r.remote_addr) parts.push('answered by ' + r.remote_addr);
    if (r.location) parts.push('redirect to ' + r.location);
    if (r.body_prefix) parts.push('body starts “' + String(r.body_prefix).slice(0, 160) + '”');
    return parts.length ? h('span', { class: 'sub small' }, parts.join(' · ')) : null;
  }

  function upDownChip(v, upWords, downWords) {
    if (v == null) return null;
    return v ? chip('good', upWords) : chip('critical', downWords);
  }

  function cardGatewayWAN(st) {
    const g = st.gateway;
    if (!g) return card('AT&T gateway WAN', emptyNote('No gateway snapshot yet.'));
    const d = g.derived || {};
    const bb = g.broadband || {};
    const fb = g.fiber || {};
    const n = st.notification;
    const clock = d.gateway_clock_blank
      ? h('span', null, chip('warning', 'blank'), ' the gateway shows no time — it does this while its WAN is down')
      : d.gateway_clock_offset_ms != null ? 'offset ' + (d.gateway_clock_offset_ms / 1000).toFixed(1) + ' s vs this PC' : null;
    return cardWithLink('AT&T gateway WAN', '#/gateway', 'All gateway fields',
      kv([
        ['Broadband', bb.connection ? [upDownChip(/^up$/i.test(bb.connection), 'Up', bb.connection), ' as reported by the gateway'] : upDownChip(d.broadband_up, 'Up', 'Down')],
        ['Fiber (PON)', bb.pon_link_status ? [upDownChip(d.pon_operational !== false && /O5/.test(bb.pon_link_status), 'operational', 'not operational'), ' ', bb.pon_link_status] : null],
        ['Optical WAN', fb.optical_status || (d.optical_up == null ? null : d.optical_up ? 'Up' : 'Down')],
        ['WAN IPv4', d.wan_ipv4 || bb.ipv4],
        ['AT&T next hop', d.isp_next_hop || bb.gateway_ipv4],
        ['AT&T DNS', [bb.primary_dns, bb.secondary_dns].filter(Boolean).join(', ')],
        ['Gateway uptime', d.uptime_s >= 0 && d.uptime_s != null ? [fmtDur(d.uptime_s), d.boot_time_estimate ? [' (booted ', timeEl(d.boot_time_estimate, F.short), ')'] : null] : null],
        ['Gateway clock', clock],
        ['Firmware', d.firmware],
        ['Model / serial', [d.model, d.serial].filter(Boolean).join(' / ')],
        ['Outage redirect', n ? (n.enabled ? chip('warning', 'ON') : chip('good', 'OFF')) : 'not checked yet'],
      ]),
      h('p', { class: 'card-foot' }, 'Polled ', timeEl(st.gateway_at, F.time), gatewayAge(st), d.reachable === false ? [' · ', chip('critical', 'status pages unreachable')] : ''));
  }

  /** gatewayAge says how old the gateway reading shown is when it is older than a few polls
   *  (the status keeps the last reading in which the gateway answered). */
  function gatewayAge(st) {
    const age = ageSeconds(st.gateway_at, st.now);
    return age != null && age > 300 ? ' (' + fmtDur(age) + ' ago — no newer reading)' : null;
  }

  function findMeasure(fb, name) {
    if (!fb || !fb.measures) return null;
    return fb.measures.find((m) => String(m.name || '').toLowerCase() === name) || null;
  }

  function measureValue(m) {
    return m.current == null ? (m.current_raw || 'no reading') : fmtMeasure(m.current, m.unit);
  }

  function flagChips(m) {
    const out = [];
    if (m.low_alarm && m.low_alarm.active) out.push(chip('critical', 'LOW ALARM', m.low_alarm.raw));
    if (m.high_alarm && m.high_alarm.active) out.push(chip('critical', 'HIGH ALARM', m.high_alarm.raw));
    if (m.low_warning && m.low_warning.active) out.push(chip('warning', 'LOW WARNING', m.low_warning.raw));
    if (m.high_warning && m.high_warning.active) out.push(chip('warning', 'HIGH WARNING', m.high_warning.raw));
    if (!out.length) out.push(chip('good', 'no gateway flag'));
    return h('span', { class: 'chips' }, out);
  }

  /** bullet draws a value against the gateway's own low/high alarm and warning thresholds. */
  function bullet(m) {
    const thr = (x) => (x && x.threshold != null ? x.threshold : null);
    const la = thr(m.low_alarm);
    const lw = thr(m.low_warning);
    const hw = thr(m.high_warning);
    const ha = thr(m.high_alarm);
    const cur = m.current;
    const pts = [la, lw, hw, ha, cur].filter((v) => v != null);
    if (cur == null || pts.length < 2) return null;
    let lo = Math.min(...pts);
    let hi = Math.max(...pts);
    const pad = Math.max((hi - lo) * 0.08, 5);
    lo -= pad;
    hi += pad;
    const X = (v) => ((v - lo) / (hi - lo)) * 100;
    const svg = s('svg', {
      class: 'bullet', viewBox: '0 0 100 16', preserveAspectRatio: 'none', role: 'img',
      'aria-label': `${m.name} ${fmtMeasure(cur, m.unit)}; gateway low alarm ${fmtMeasure(la, m.unit)}, low warning ${fmtMeasure(lw, m.unit)}`,
    });
    const region = (a, b, cls) => {
      if (a == null || b == null || b <= a) return;
      svg.append(s('rect', { class: cls, x: X(a), y: 3, width: X(b) - X(a), height: 10 }));
    };
    const loA = la != null ? la : lo;
    const loW = lw != null ? lw : loA;
    const hiA = ha != null ? ha : hi;
    const hiW = hw != null ? hw : hiA;
    region(lo, loA, 'r-critical');
    region(loA, loW, 'r-warning');
    region(loW, hiW, 'r-ok');
    region(hiW, hiA, 'r-warning');
    region(hiA, hi, 'r-critical');
    for (const v of [la, lw, hw, ha]) {
      if (v != null) svg.append(s('line', { class: 't', x1: X(v), x2: X(v), y1: 1, y2: 15, 'vector-effect': 'non-scaling-stroke' }));
    }
    svg.append(s('line', { class: 'm', x1: X(cur), x2: X(cur), y1: 0, y2: 16, 'vector-effect': 'non-scaling-stroke' }));
    return h('div', null, svg,
      h('p', { class: 'bullet-legend' },
        `Black marker: current reading. Gateway thresholds — low alarm ${fmtMeasure(la, m.unit)}, low warning ${fmtMeasure(lw, m.unit)}, high warning ${fmtMeasure(hw, m.unit)}, high alarm ${fmtMeasure(ha, m.unit)}.`));
  }

  function lastChangeText(fb) {
    if (!fb.last_change_unix) return fb.last_change_raw || null;
    return [timeEl(fb.last_change_unix * 1000), h('span', { class: 'small muted' }, ' (raw ' + (fb.last_change_raw || fb.last_change_unix) + '; epoch semantics unverified)')];
  }

  function cardFiber(st) {
    const fb = st.gateway && st.gateway.fiber;
    if (!fb) return card('Fiber optics', emptyNote('No fiber status from the gateway yet.'));
    const rx = findMeasure(fb, 'rx power');
    const tx = findMeasure(fb, 'tx power');
    const temp = findMeasure(fb, 'temperature');
    const bias = findMeasure(fb, 'tx bias');
    const vcc = findMeasure(fb, 'vcc');
    const body = [];
    for (const [m, label] of [[rx, 'Received light (Rx)'], [tx, 'Transmit power (Tx)']]) {
      if (!m) continue;
      body.push(h('div', { class: 'measure' },
        h('p', { class: 'eyebrow' }, label),
        h('p', { class: 'measure-line' }, h('span', { class: 'measure-value' }, measureValue(m)), flagChips(m)),
        bullet(m)));
    }
    body.push(kv([
      ['Temperature', temp ? [measureValue(temp), ' ', flagChips(temp)] : null],
      ['Laser bias', bias ? measureValue(bias) : null],
      ['Supply voltage', vcc ? [measureValue(vcc), h('span', { class: 'small muted' }, ' (gateway shows whole volts)')] : null],
      ['Optical WAN', fb.optical_status],
      ['Link state', fb.link_state],
      ['Last change', lastChangeText(fb)],
      ['Module', [fb.vendor_name, fb.vendor_pn, fb.wave_length].filter(Boolean).join(' · ')],
    ]));
    body.push(h('p', { class: 'card-foot' }, 'Alarm and warning flags are the AT&T gateway’s own diagnostic (DMI) bits from its fiber status page.'));
    return cardWithLink('Fiber optics', '#/gateway', 'DMI table', ...body);
  }

  function cardLocalLink(st) {
    const l = st.local_link;
    if (!l) return card('Local link (this PC)', emptyNote('Not measured yet.'));
    const connected = /^connected$/i.test(l.state || '');
    const signal = l.signal_pct || l.rssi_dbm
      ? [l.signal_pct ? l.signal_pct + ' %' : '', l.rssi_dbm ? (l.signal_pct ? ' · ' : '') + l.rssi_dbm + ' dBm' : '', l.signal_pct ? meter(l.signal_pct) : null]
      : null;
    return card('Local link (this PC)',
      kv([
        ['Adapter', [l.interface, l.type ? ' (' + (l.type === 'wifi' ? 'Wi-Fi' : l.type) + ')' : ''].join('')],
        ['State', l.state ? (connected ? chip('good', l.state) : chip('critical', l.state)) : null],
        ['Network', l.ssid],
        ['Access point', l.bssid],
        ['Signal', signal],
        ['Channel', l.channel ? [l.channel, l.band ? ' · ' + l.band : ''].join('') : null],
        ['Radio', l.radio_type],
        ['Link rate', l.rx_mbps || l.tx_mbps ? `receive ${l.rx_mbps || '—'} / transmit ${l.tx_mbps || '—'} Mbps` : l.link_mbps ? l.link_mbps + ' Mbps' : null],
        ['This PC', l.local_ip],
        ['Default gateway', l.gateway_ip],
        ['Error', l.err],
      ]),
      egressBlock(l.egress),
      HEX64.test(l.raw_sha256 || '') ? h('p', { class: 'card-foot' }, 'Raw adapter report: ', blobLinks(l.raw_sha256, { downloadText: 'download' })) : null);
  }

  /** ifText names a network interface: its alias and Windows interface index. */
  function ifText(name, index) {
    const n = Number(index) > 0 ? 'interface ' + index : '';
    if (name) return n ? name + ' (' + n + ')' : String(name);
    return n || 'unknown interface';
  }

  /** egressRoutes returns the well-formed per-destination routes of a route check. */
  function egressRoutes(e) {
    return Array.isArray(e && e.routes) ? e.routes.filter((r) => r && typeof r === 'object') : [];
  }

  /** egressBlock shows the route check recorded with the local-link reading (LocalLink.egress,
   *  rules 2026.10-4): the route to the AT&T gateway and whether the route to each internet
   *  destination leaves through it. While one does not (VPN tunnel, second adapter, hotspot),
   *  nothing measured on the Internet is attributed to AT&T. A check that could not be made
   *  concludes nothing. */
  function egressBlock(e) {
    if (!e || typeof e !== 'object') return null;
    const head = h('h3', { class: 'subhead' }, 'Route to the Internet');
    if (e.err) {
      return h('div', null, head, h('p', { class: 'small' }, chip('none', 'not checked'), ' The route check could not be made: ', String(e.err),
        '. Nothing is concluded from it.'));
    }
    const routes = egressRoutes(e);
    const off = routes.filter((r) => !r.err && !r.via_gateway);
    const gw = h('p', { class: 'small muted' }, 'This computer reaches the AT&T gateway ', orQ(e.gateway), ' through ',
      ifEl(e.gateway_if_name, e.gateway_if), e.gateway_next_hop ? ' via ' + e.gateway_next_hop : ' (on-link)', '.');
    const rows = routes.map((r) => [
      h('span', { class: 'wrap-any' }, orQ(r.target)),
      r.err ? chip('none', 'unknown', String(r.err)) : r.via_gateway ? chip('good', 'yes') : chip('warning', 'no'),
      r.err ? h('span', { class: 'small muted wrap-any' }, 'route not found: ' + r.err)
        : h('span', { class: 'wrap-any' }, ifEl(r.if_name, r.if), r.next_hop ? ' via ' + r.next_hop : ' (on-link)'),
    ]);
    const tbl = rows.length ? table([{ label: 'Destination' }, { label: 'Via gateway' }, { label: 'Leaves through' }], rows, { compact: true })
      : emptyNote('No destination was checked.');
    if (!e.bypass && rows.length && routes.every((r) => !r.err && r.via_gateway)) {
      // Nothing to look into: one line, the routes on request.
      return h('div', null, head, h('details', { class: 'egress' },
        h('summary', null, `All ${routes.length} destinations leave through the AT&T gateway`), gw, tbl));
    }
    return h('div', null, head,
      e.bypass ? callout('warning', h('strong', null, 'Not through the AT&T gateway. '),
        off.length ? `The route to ${off.length} of ${routes.length} destinations leaves through another adapter` : 'The route check found traffic leaving through another adapter',
        ' (a VPN tunnel, a second network or a hotspot). While this lasts, nothing measured on the Internet is attributed to AT&T.') : null,
      gw, tbl);
  }

  /** ifEl shows a network interface by its alias, with its Windows interface index on hover
   *  (as `route print` lists it). */
  function ifEl(name, index) {
    const title = Number(index) > 0 ? 'Windows interface index ' + index : null;
    return h('span', { title }, name ? String(name) : ifText('', index));
  }

  /** egressSummary words a route check for the timeline and the records. */
  function egressSummary(e) {
    if (!e || typeof e !== 'object') return '';
    if (e.err) return 'route check could not be made: ' + e.err;
    const routes = egressRoutes(e);
    const off = routes.filter((r) => !r.err && !r.via_gateway);
    if (off.length) {
      return 'route check: ' + off.map((r) => orQ(r.target) + ' leaves through ' + ifText(r.if_name, r.if) + (r.next_hop ? ' via ' + r.next_hop : '')).join(', ') +
        ', not through the AT&T gateway';
    }
    if (e.bypass) return 'route check: traffic does not go through the AT&T gateway';
    if (!routes.length) return 'route check: no destination checked';
    const via = routes.filter((r) => r.via_gateway).length;
    return 'route check: ' + (via === routes.length ? 'all ' + via : via + ' of ' + routes.length) + ' destinations through the AT&T gateway';
  }

  function meter(pct) {
    const fill = h('span');
    fill.style.width = Math.max(0, Math.min(100, Number(pct) || 0)) + '%'; // CSSOM: allowed by the CSP
    return h('span', { class: 'meter', 'aria-hidden': 'true' }, fill);
  }

  function cardEvidence(st) {
    const L = st.ledger || {};
    const lv = L.last_verify;
    return cardWithLink('Evidence integrity', '#/evidence', 'Verify & export',
      kv([
        ['Ledger head', ['record #' + fmtInt(L.head_seq), L.head_ts ? [' · ', timeEl(L.head_ts, F.short)] : null]],
        ['Head hash', L.head_hash ? h('span', { class: 'hash', title: L.head_hash }, shortHash(L.head_hash, 20)) : null],
        ['Signing key', L.fingerprint ? h('span', { class: 'fp', title: 'SHA-256 fingerprint of the Ed25519 public key' }, groupFingerprint(L.fingerprint)) : null],
        ['Ledger started', L.genesis_ts ? timeEl(L.genesis_ts) : null],
        ['Last time-stamp', L.last_anchor_time ? [timeEl(L.last_anchor_time, F.short), ' by ', tsaName(L.last_anchor_tsa), ' (covers #' + fmtInt(L.last_anchor_seq) + ')'] : 'none yet'],
        ['Not yet time-stamped', fmtInt(L.unanchored_records) + ' records'],
        ['Last verification', lv ? [lv.ok ? chip('good', 'passed') : chip('critical', 'FAILED'), ' ', timeEl(lv.at, F.short), ` · ${fmtInt(lv.records)} records, ${fmtInt(lv.failures)} problems`] : 'not run yet'],
        ['MongoDB copy', st.mongo ? mongoCell(st.mongo) : null],
      ]));
  }

  /** mongoCell describes the MongoDB copy of the ledger (Status.mongo): a synchronized copy of
   *  every record with its exact signed bytes; the signed ledger stays the source of truth. */
  function mongoCell(m) {
    const upTo = m.has_data ? ` · copied up to #${fmtInt(m.last_seq)}` : '';
    if (!m.connected && !m.has_data) {
      // Not reached since the service started: most PCs have no MongoDB server, and the copy is optional.
      return [chip('none', 'no server', m.last_error || 'No MongoDB server answered'), ' no MongoDB server answered at ',
        m.uri || 'this PC', ' (the copy is optional; evidence recording is not affected)'];
    }
    if (!m.connected) {
      return [chip('warning', 'not connected', m.last_error || 'MongoDB is not reachable'), ' ', m.uri || '', upTo,
        ' · evidence recording is not affected'];
    }
    let state = chip('good', 'in sync');
    if (m.last_error) state = chip('warning', 'problem', m.last_error);
    else if (!m.has_data || m.lag > 0) state = chip('warning', m.has_data ? fmtInt(m.lag) + ' records behind' : 'copying');
    return [state, ` · ${fmtInt(m.records || 0)} records, ${fmtInt(m.blobs || 0)} blobs in “${m.database}”`, upTo];
  }

  function cardMonitor(st) {
    const m = st.monitor || {};
    const ck = st.clock;
    const rows = [
      ['Version', m.version],
      ['Running as', m.mode],
      ['Started', m.started ? [timeEl(m.started), ' (up ', fmtDur(m.uptime_s), ')'] : null],
      ['Cycles', fmtInt(m.cycles)],
      ['Rules', m.rules],
    ];
    if (ck && ck.results) {
      for (const r of ck.results) {
        rows.push(['Clock vs ' + r.server, r.ok ? `${r.offset_ms >= 0 ? '+' : ''}${fmtInt(r.offset_ms)} ms (stratum ${r.stratum || '?'})` : chip('warning', 'no answer', r.err)]);
      }
    }
    return card('Monitor & clock', kv(rows));
  }

  // ------------------------------------------------------------------ gateway syslog

  /** syslogCard shows the receiver of the gateway's syslog messages and the gateway's Syslog
   *  setting (Status.syslog, docs/syslog-snmp-traffic.md §3.2), or nothing when the monitor
   *  reports neither. link: on the Overview, linking the Syslog page (which has its own card
   *  title). */
  function syslogCard(st, link) {
    const sl = st && st.syslog;
    if (!sl || typeof sl !== 'object' || Array.isArray(sl)) return null;
    const seq = Number(sl.gateway_seq) || 0;
    const body = [
      kv([
        ['Receiver', syslogReceiver(sl)],
        ['Messages', [syslogCounts(sl), h('span', { class: 'sub small muted' }, 'since the service started')]],
        ['Last message', sl.last_at || sl.last
          ? [timeEl(sl.last_at, F.sec), sl.last ? h('span', { class: 'sub syslog-text small' }, visibleText(sl.last)) : null]
          : 'none since the service started'],
        ['Gateway setting', syslogSetting(sl)],
        ['Setting read', sl.gateway_at || seq
          ? [sl.gateway_at ? timeEl(sl.gateway_at, F.short) : null, sl.gateway_at && seq ? ' · ' : null, seq ? h('a', { href: recordsLink(seq) }, 'record #' + seq) : null]
          : null],
      ]),
      h('p', { class: 'card-foot' }, syslogEnforcement(sl, st)),
    ];
    return link ? cardWithLink('Gateway syslog', '#/syslog', 'Messages', ...body) : card('Receiver and gateway setting', ...body);
  }

  /** syslogReceiver says whether this computer listens for the gateway's messages. */
  function syslogReceiver(sl) {
    if (!sl.enabled) return [chip('none', 'off'), ' turned off in the configuration (syslog.enabled)'];
    if (sl.listening) return [chip('good', 'listening'), ' on UDP ', h('code', null, String(sl.listen || '?'))];
    if (sl.listen_error) return [chip('critical', 'not listening'), ' ', h('span', { class: 'wrap-any' }, String(sl.listen_error))];
    return [chip('none', 'not listening yet'), sl.listen ? [' (UDP ', h('code', null, String(sl.listen)), ')'] : null];
  }

  /** syslogCounts words the receiver's counters (since the service started). */
  function syslogCounts(sl) {
    const n = (v) => fmtInt(Number(v) || 0);
    return [
      h('span', { title: 'Messages accepted from the gateway' }, n(sl.received) + ' received'), ' · ',
      h('span', { title: 'Written to the evidence ledger' }, n(sl.recorded) + ' recorded'), ' · ',
      Number(sl.dropped) > 0
        ? chip('warning', n(sl.dropped) + ' dropped', 'Accepted but over the per-minute cap: counted, not recorded')
        : h('span', { title: 'Accepted but over the per-minute cap: counted, not recorded' }, '0 dropped'), ' · ',
      h('span', { title: 'Datagrams from senders other than the gateway: counted, not recorded' }, n(sl.rejected) + ' from other senders'),
    ];
  }

  /** syslogTarget writes a Syslog destination as server:port. */
  function syslogTarget(x) {
    return x && x.server ? String(x.server) + (x.port ? ':' + x.port : '') : '';
  }

  /** syslogSetting words the gateway's Syslog setting as the monitor last read it
   *  (Status.syslog.state: ok, off, elsewhere, unknown, error). */
  function syslogSetting(sl) {
    const g = sl.gateway && typeof sl.gateway === 'object' ? sl.gateway : null;
    const level = g && g.level ? [' · level ', String(g.level)] : null;
    const problem = sl.problem ? h('span', { class: 'sub small muted wrap-any' }, String(sl.problem)) : null;
    const state = sl.state || (!g ? 'unknown' : g.enabled ? '' : 'off');
    switch (state) {
      case 'ok': return [chip('good', 'on'), ' sends to ', syslogTarget(g) || '?', ' (this PC)', level, problem];
      case 'off': return [chip('warning', 'off'), ' the gateway sends no syslog messages', problem];
      case 'elsewhere': return [chip('warning', 'sends elsewhere'), ' to ', syslogTarget(g) || 'another address', level, ', not to this PC', problem];
      case 'error':
        return [chip('warning', 'could not be read'), ' ', String(sl.problem || 'the last check failed'),
          g ? h('span', { class: 'sub small muted' }, 'Last read: ', g.enabled ? 'on, sends to ' + (syslogTarget(g) || '?') : 'off', level) : null];
      case 'unknown':
        return g ? [chip('none', 'not understood'), ' ', String(sl.problem || 'the gateway’s Syslog page was not understood')]
          : [chip('none', 'not read yet'), problem];
    }
    return [chip('none', humanize(state) || 'on'), g && g.enabled ? [' sends to ', syslogTarget(g) || '?', level] : null, problem];
  }

  /** syslogEnforcement says what att-monitor does with the gateway's Syslog setting. */
  function syslogEnforcement(sl, st) {
    if (sl.enforce) {
      return 'att-monitor keeps the gateway sending its log to ' + (syslogTarget(sl.target) || 'this PC') + ' and records every check and change of the setting.';
    }
    const ip = st && st.local_link && st.local_link.local_ip;
    const port = (sl.target && sl.target.port) || (/:(\d+)$/.exec(String(sl.listen || '')) || [])[1] || 514;
    return ['att-monitor only reads this setting; it does not change it yet. To receive the gateway’s log, turn Syslog on in the gateway’s Diagnostics › Syslog page with server ',
      ip ? h('code', null, String(ip)) : 'this PC’s address', ' and port ', String(port), '.'];
  }

  async function loadRecentIncidents(el, ctx) {
    const from = new Date(Date.now() - 7 * 86400e3).toISOString();
    try {
      const list = await api('/api/incidents?limit=8&from=' + encodeURIComponent(from));
      if (!ctx.alive) return;
      replace(el, 
        h('div', { class: 'card-head' }, h('h2', { id: 'recent-h' }, 'Recent incidents (7 days)'), h('a', { href: '#/incidents', class: 'small' }, 'All incidents')),
        incidentsTable(list.slice(0, 8), app.status && app.status.now));
    } catch (e) {
      if (!ctx.alive) return;
      replace(el, h('h2', { id: 'recent-h' }, 'Recent incidents'), errorNotice(e));
    }
  }

  function incidentDuration(inc, now) {
    if (inc.open) return 'ongoing · ' + sinceText(inc.opened, now);
    if (inc.duration_s) return fmtDur(inc.duration_s);
    const a = toMs(inc.opened);
    const b = toMs(inc.closed);
    return a != null && b != null ? fmtDur((b - a) / 1000) : '—';
  }

  /** downtimeText is an incident's time without Internet: its ISP_OUTAGE cycles (docs/DESIGN.md
   *  §10; restart windows excluded). Zero is not always "none": inside a gateway restart the
   *  time is counted as restart time, and in a LOCAL_FAULT incident this PC could not reach the
   *  gateway, so whether the Internet was up was not observed. */
  function downtimeText(inc) {
    const st = inc.stats || {};
    if (st.downtime_s > 0) return fmtDur(st.downtime_s);
    if (st.restart_s > 0) return 'none outside gateway restarts';
    if (inc.state === 'LOCAL_FAULT') {
      const why = inc.cause === 'LOCAL_ROUTE'
        ? 'This computer’s traffic did not go through the AT&T gateway, so whether AT&T’s Internet service was up was not observed.'
        : 'This PC could not reach the AT&T gateway, so whether the Internet was up is unknown.';
      return h('span', { title: why }, 'not observed');
    }
    return 'none';
  }

  /** timeAccountingCell: time without Internet, with degraded and gateway-restart time below. */
  function timeAccountingCell(inc) {
    if (!rulesAtLeast(inc.rules, RULES_TIME_ACCOUNTING)) {
      return h('span', { class: 'muted', title: 'Not measured: classified with rules ' + orQ(inc.rules) + ', before time accounting (rules ' + RULES_TIME_ACCOUNTING + ')' }, '—');
    }
    const st = inc.stats || {};
    return h('span', null, downtimeText(inc),
      st.degraded_s > 0 ? h('span', { class: 'sub small muted' }, 'degraded ' + fmtDur(st.degraded_s)) : null,
      st.restart_s > 0 ? h('span', { class: 'sub small muted' }, 'gateway restart ' + fmtDur(st.restart_s)) : null);
  }

  function incidentsTable(list, now) {
    if (!list || !list.length) return emptyNote('No incidents in this period.');
    return table(
      [{ label: 'Opened' }, { label: 'Duration', num: true }, { label: 'Without Internet', num: true }, { label: 'State' }, { label: 'Cause' }, { label: 'Attributed to' }, { label: 'Summary' }],
      list.map((inc) => [
        h('a', { href: '#/incidents/' + encodeURIComponent(inc.id), title: inc.id, class: 'nowrap' }, timeEl(inc.opened, F.short)),
        incidentDuration(inc, now),
        timeAccountingCell(inc),
        stateBadge(inc.state),
        inc.cause ? causeText(inc.cause) : '—',
        ATTR_SHORT[inc.attribution] || inc.attribution || '—',
        inc.summary || '',
      ]), { stack: true });
  }

  // ------------------------------------------------------------------ charts

  function setupCharts(section, ctx) {
    const body = h('div', { class: 'charts-body' }, h('p', { class: 'loading' }, 'Loading chart data…'));
    section.append(
      h('div', { class: 'section-head' }, h('h2', { id: 'history-h' }, 'History'),
        rangeControl(app.range, (r) => { app.range = r; savePref('range', r); load(); })),
      body);
    let token = 0;
    async function load() {
      const mine = ++token;
      body.classList.add('is-loading');
      body.setAttribute('aria-busy', 'true');
      try {
        const ser = await api('/api/series?range=' + encodeURIComponent(app.range));
        if (!ctx.alive || mine !== token) return;
        const firstLabels = !app.series;
        app.series = ser;
        renderCharts(body, ser, ctx);
        if (firstLabels && app.status && ctx.onStatus) ctx.onStatus(app.status); // probe labels come with the series
      } catch (e) {
        if (!ctx.alive || mine !== token) return;
        replace(body, errorNotice(e));
      } finally {
        if (mine === token) {
          body.classList.remove('is-loading');
          body.removeAttribute('aria-busy');
        }
      }
    }
    load();
    ctx.interval(() => { if (!document.hidden) load(); }, SERIES_REFRESH_MS);
  }

  /** rangeControl offers the RANGES as a segmented radio group; groupLabel names the group. */
  function rangeControl(current, onChange, groupLabel) {
    const name = 'range-' + Math.random().toString(36).slice(2, 8);
    const group = h('div', { class: 'seg', role: 'radiogroup', 'aria-label': groupLabel || 'Chart time range' });
    for (const [value, label] of RANGES) {
      const id = name + '-' + value;
      const input = h('input', { type: 'radio', name, id, value });
      input.checked = value === current;
      input.addEventListener('change', () => { if (input.checked) onChange(value); });
      group.append(input, h('label', { for: id }, label));
    }
    return h('div', { class: 'chart-filters' }, h('span', { class: 'small muted', 'aria-hidden': 'true' }, 'Range'), group);
  }

  /** chartProbes picks the latency/loss series: the gateway ICMP probe, then every internet
   *  probe, in configuration order. Slots follow that order, so colours follow the probe. */
  function chartProbes(ser) {
    let specs = (ser.probes || []).slice();
    if (!specs.length) {
      const keys = new Set();
      for (const p of ser.points || []) {
        for (const k of Object.keys(p.rtt_ms || {})) keys.add(k);
        for (const k of Object.keys(p.loss || {})) keys.add(k);
      }
      specs = [...keys].sort().map((k) => ({
        name: k, label: k, role: /^inet/.test(k) ? 'internet' : /^gateway/.test(k) ? 'gateway' : 'other', kind: /tcp/.test(k) ? 'tcp' : 'icmp',
      }));
    }
    const gw = specs.find((p) => p.role === 'gateway' && p.kind === 'icmp') || specs.find((p) => p.role === 'gateway');
    const chosen = (gw ? [gw] : []).concat(specs.filter((p) => p.role === 'internet')).slice(0, 8);
    return chosen.map((p, i) => ({ key: p.name, label: p.label || p.name, slot: i + 1 }));
  }

  function renderCharts(body, ser, ctx) {
    const from = toMs(ser.from);
    const to = toMs(ser.to);
    if (from == null || to == null || to <= from) {
      replace(body, errorNotice(new Error('The monitor returned an invalid chart range.')));
      return;
    }
    const stepMs = Math.max(1, ser.step_s || 60) * 1000;
    const pts = (ser.points || []).filter((p) => toMs(p.t) != null);
    const starts = pts.map((p) => toMs(p.t));
    const times = starts.map((t) => t + stepMs / 2); // plot each bucket at its centre
    const bucketLabel = (i) => F.short.format(new Date(starts[i])) + ' – ' + F.hm.format(new Date(starts[i] + stepMs));
    const bucketUTC = (i) => new Date(starts[i]).toISOString().slice(0, 16).replace('T', ' ') + ' – ' +
      new Date(starts[i] + stepMs).toISOString().slice(11, 16) + ' UTC';
    const specs = chartProbes(ser);
    const num = (v) => (v == null || !isFinite(v) ? null : Number(v));
    const linked = [];

    const strip = stateStrip({ id: 'availability', points: pts, from, to, stepMs, ctx });
    const latency = lineChart({
      id: 'latency', ctx, linked,
      title: 'Round-trip time',
      subtitle: 'Mean of the successful replies in each ' + fmtDur(stepMs / 1000) + ' bucket. Gaps: no successful reply, or no data.',
      series: specs.map((sp) => ({ ...sp, vals: pts.map((p) => num(p.rtt_ms && p.rtt_ms[sp.key])) })),
      times, from, to, gapMs: stepMs * 1.5, legend: true,
      yMin: 0, minMax: 5, robustMax: true,
      yFmt: (v) => fmtInt(v) + ' ms', tipFmt: fmtMs, tipTime: bucketLabel, tipUTC: bucketUTC, unit: 'ms',
    });
    const loss = lineChart({
      id: 'loss', ctx, linked,
      title: 'Packet loss',
      subtitle: 'Share of probe attempts without a reply in each bucket.',
      series: specs.map((sp) => ({ ...sp, vals: pts.map((p) => (p.loss && p.loss[sp.key] != null ? num(p.loss[sp.key] * 100) : null)) })),
      times, from, to, gapMs: stepMs * 1.5, legend: true,
      yMin: 0, yMax: 100,
      yFmt: (v) => v + ' %', tipFmt: (v) => (v == null ? '—' : Math.round(v * 10) / 10 + ' %'), tipTime: bucketLabel, tipUTC: bucketUTC, unit: '%',
    });
    replace(body, strip, latency, loss, trafficChart(ser, from, to, stepMs, ctx), trafficDaysTable(ser), opticalChart(ser, from, to, ctx));
  }

  /** fmtNum writes a number with at most two decimals (axis ticks, thresholds). */
  function fmtNum(v) {
    return v == null || !isFinite(v) ? '—' : Number(Number(v).toFixed(2)).toLocaleString();
  }

  /** fmtMbps writes a rate in Mb/s with the precision it deserves. */
  function fmtMbps(v) {
    if (v == null || !isFinite(v)) return '—';
    const a = Math.abs(v);
    return (a === 0 ? '0' : a < 10 ? v.toFixed(2) : a < 100 ? v.toFixed(1) : Math.round(v).toLocaleString()) + ' Mb/s';
  }

  /** fmtGB writes a byte count in GB (10^9 bytes). */
  function fmtGB(n) {
    if (n == null || !isFinite(n)) return '—';
    const gb = n / 1e9;
    return (gb < 10 ? gb.toFixed(2) : gb < 100 ? gb.toFixed(1) : Math.round(gb).toLocaleString()) + ' GB';
  }

  /** dayLabel writes a YYYY-MM-DD local date as "Mon, Oct 5" (anything else as given). */
  function dayLabel(v) {
    const m = /^(\d{4})-(\d\d)-(\d\d)$/.exec(String(v == null ? '' : v));
    return m ? F.day.format(new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]))) : String(v);
  }

  /** trafficChart draws the household's traffic (Series.traffic, docs/syslog-snmp-traffic.md
   *  §3.3): the WAN download and upload from the gateway's own counters (mean lines, peak
   *  marks) and this computer's, against the classifier's heavy-traffic level; null when the
   *  monitor reports no traffic at all. */
  function trafficChart(ser, from, to, stepMs, ctx) {
    const title = 'Traffic';
    const heavy = Number(ser.heavy_traffic_mbps) > 0 ? Number(ser.heavy_traffic_mbps) : null;
    const pts = (Array.isArray(ser.traffic) ? ser.traffic : []).filter((p) => p && typeof p === 'object' && toMs(p.t) != null);
    if (!pts.length) {
      if (heavy == null) return null;
      return h('figure', { class: 'chart' }, h('figcaption', { class: 'chart-head' }, h('div', null, h('span', { class: 'chart-title' }, title))),
        emptyNote('No traffic readings in this range.'));
    }
    const starts = pts.map((p) => toMs(p.t));
    const num = (v) => (v == null || !isFinite(v) ? null : Number(v));
    const col = (k) => pts.map((p) => num(p[k]));
    const atLeast = pts.map((p) => p.at_least === true);
    const anyAtLeast = atLeast.some(Boolean);
    const legendExtra = [[tickKey(0), 'peak: the highest rate between two readings in the bucket']];
    if (anyAtLeast) legendExtra.push([chevronKey(), 'at least: the true rate may have been higher']);
    return lineChart({
      id: 'traffic', ctx, linked: null,
      title,
      subtitle: 'Mean rate in each ' + fmtDur(stepMs / 1000) + ' bucket, in Mb/s. WAN: the AT&T gateway’s own IPv4 byte counters, with short marks at the highest rate between two of its readings. This PC: its own network adapter.' +
        (heavy != null ? ' Dashed line: ' + fmtNum(heavy) + ' Mb/s, from which the household’s own traffic may slow the connection by itself, so a slowdown is not attributed to AT&T.' : '') +
        ' Gaps: no reading.' +
        (anyAtLeast ? ' Chevron: the gateway’s 32-bit byte counter may have wrapped more often than can be told, so the rate was at least the one shown.' : ''),
      series: [
        { key: 'wan_rx', label: 'WAN download', slot: 1, vals: col('wan_rx_mbps'), atLeast },
        { key: 'wan_rx_peak', of: 'wan_rx', mark: 'tick', label: 'WAN download peak', slot: 1, vals: col('wan_rx_peak_mbps'), atLeast },
        { key: 'wan_tx', label: 'WAN upload', slot: 2, vals: col('wan_tx_mbps'), atLeast },
        { key: 'wan_tx_peak', of: 'wan_tx', mark: 'tick', label: 'WAN upload peak', slot: 2, vals: col('wan_tx_peak_mbps'), atLeast },
        { key: 'pc_rx', label: 'This PC download', slot: 3, vals: col('pc_rx_mbps') },
        { key: 'pc_tx', label: 'This PC upload', slot: 4, vals: col('pc_tx_mbps') },
      ],
      times: starts.map((t) => t + stepMs / 2), from, to, gapMs: stepMs * 1.5, legend: true, legendExtra,
      yMin: 0, minMax: 1,
      thresholds: heavy != null ? [{ v: heavy, tone: 'ref', place: 'above', label: 'Heavy household traffic ' + fmtNum(heavy) + ' Mb/s' }] : [],
      atLeast: anyAtLeast ? { at: atLeast, keys: ['wan_rx', 'wan_tx'] } : null,
      yFmt: fmtNum,
      tipFmt: (v, se, i) => (v == null ? '—' : (se && se.atLeast && se.atLeast[i] ? 'at least ' : '') + fmtMbps(v)),
      tipTime: (i) => F.short.format(new Date(starts[i])) + ' – ' + F.hm.format(new Date(starts[i] + stepMs)),
      tipUTC: (i) => new Date(starts[i]).toISOString().slice(0, 16).replace('T', ' ') + ' – ' + new Date(starts[i] + stepMs).toISOString().slice(11, 16) + ' UTC',
      unit: 'Mb/s',
    });
  }

  /** trafficDaysTable lists the WAN volume per day of this computer's time zone
   *  (Series.traffic_days), newest first; null when the monitor reports none. */
  function trafficDaysTable(ser) {
    const days = (Array.isArray(ser.traffic_days) ? ser.traffic_days : []).filter((d) => d && typeof d === 'object');
    if (!days.length) return null;
    const today = localDateValue(new Date());
    const rows = days.slice().reverse().map((d) => [
      h('span', { class: 'nowrap', title: String(d.day) }, dayLabel(d.day), d.day === today ? h('span', { class: 'small muted' }, ' (today, so far)') : null),
      fmtGB(d.rx_bytes), fmtGB(d.tx_bytes),
      Number(d.covered_s) > 0 ? fmtDur(d.covered_s) : '—',
      d.complete ? h('span', { class: 'muted' }, 'complete')
        : chip('warning', 'partial', 'Part of this day has no known counter delta, so its traffic was more than these totals.'),
    ]);
    return h('figure', { class: 'chart' },
      h('figcaption', { class: 'chart-head' }, h('div', null, h('span', { class: 'chart-title' }, 'WAN volume per day'),
        h('p', { class: 'chart-sub' }, 'Downloaded and uploaded through the AT&T gateway, from its own byte counters, per day of this computer’s time zone (1 GB = 1,000,000,000 bytes). Only exactly known counter deltas are added up. Partial: part of the day has none (the monitor was not running, the gateway could not be read, or its counters were reset or may have wrapped more often than can be told), so the day’s traffic was more than shown.'))),
      table([{ label: 'Day' }, { label: 'Downloaded', num: true }, { label: 'Uploaded', num: true }, { label: 'Time counted', num: true }, { label: 'Totals' }], rows, { compact: true }));
  }

  function median(arr) {
    if (!arr.length) return 0;
    const a = arr.slice().sort((x, y) => x - y);
    return a[Math.floor(a.length / 2)];
  }

  function opticalChart(ser, from, to, ctx) {
    const pts = (ser.optical || [])
      .map((p) => ({ t: toMs(p.t), rx: p.rx_x10 != null ? p.rx_x10 / 10 : null, alarm: !!p.rx_low_alarm, warn: !!p.rx_low_warn }))
      .filter((p) => p.t != null && p.t >= from && p.t <= to)
      .sort((a, b) => a.t - b.t);
    const title = 'Fiber receive power vs the gateway’s own thresholds';
    if (!pts.length) {
      return h('figure', { class: 'chart' }, h('figcaption', { class: 'chart-head' }, h('div', null, h('span', { class: 'chart-title' }, title))),
        emptyNote('No optical readings from the gateway in this range.'));
    }
    const diffs = [];
    for (let i = 1; i < pts.length; i++) diffs.push(pts[i].t - pts[i - 1].t);
    const typical = median(diffs) || 60000;
    const gapMs = Math.max(3 * typical, 5 * 60000);
    const la = ser.rx_low_alarm_x10 != null ? ser.rx_low_alarm_x10 / 10 : null;
    const lw = ser.rx_low_warn_x10 != null ? ser.rx_low_warn_x10 / 10 : null;
    const thresholds = [];
    if (lw != null) thresholds.push({ v: lw, tone: 'warning', place: la != null && lw >= la ? 'above' : 'below', label: 'Low-warning threshold ' + lw.toFixed(1) + ' dBm' });
    if (la != null) thresholds.push({ v: la, tone: 'critical', place: lw != null && la > lw ? 'above' : 'below', label: 'Low-alarm threshold ' + la.toFixed(1) + ' dBm' });

    // The gateway's own Rx-low flag over time, as runs.
    const flagOf = (p) => (p.alarm ? 'critical' : p.warn ? 'warning' : 'good');
    const flagText = { critical: 'Rx low ALARM flag on', warning: 'Rx low warning flag on', good: 'no Rx flag' };
    const runs = [];
    for (let i = 0; i < pts.length; i++) {
      const p = pts[i];
      const next = pts[i + 1];
      const end = next && next.t - p.t <= gapMs ? next.t : Math.min(p.t + typical, to);
      const tone = flagOf(p);
      const last = runs[runs.length - 1];
      if (last && last.tone === tone && Math.abs(last.end - p.t) < 1000) last.end = end;
      else runs.push({ start: p.t, end, tone, label: flagText[tone] });
    }
    return lineChart({
      id: 'optical', ctx, linked: null,
      title,
      subtitle: 'Optical level reported by the AT&T gateway, in dBm. Dashed lines: the gateway’s alarm and warning thresholds. Strip: the gateway’s own Rx-low flag.',
      series: [{ key: 'rx', label: 'Rx power', slot: 1, vals: pts.map((p) => p.rx) }],
      times: pts.map((p) => p.t), from, to, gapMs, legend: false,
      pad: 0.6, thresholds,
      band: { label: 'Flag', runs, legend: [['critical', 'Low alarm on'], ['warning', 'Low warning on'], ['good', 'No flag']] },
      yFmt: (v) => v.toFixed(1), tipFmt: (v) => (v == null ? 'no reading' : v.toFixed(1) + ' dBm'),
      tipTime: (i) => F.full.format(new Date(pts[i].t)),
      tipExtra: (i) => h('div', { class: 'tip-row' }, icon(flagOf(pts[i])), h('span', { class: 'val' }, flagText[flagOf(pts[i])]), h('span')),
      unit: 'dBm',
    });
  }

  function niceTicks(lo, hi, count) {
    if (!(hi > lo)) hi = lo + 1;
    const raw = (hi - lo) / Math.max(1, count);
    const mag = Math.pow(10, Math.floor(Math.log10(raw)));
    const norm = raw / mag;
    const step = (norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 2.5 ? 2.5 : norm <= 5 ? 5 : 10) * mag;
    const start = Math.floor(lo / step) * step;
    const end = Math.ceil(hi / step) * step;
    const ticks = [];
    for (let v = start; v <= end + step / 2; v += step) ticks.push(Number(v.toFixed(10)));
    return { lo: start, hi: end, ticks };
  }

  /** timeTicks returns local-time ticks (at most one per ~72 px). */
  function timeTicks(from, to, widthPx) {
    const H1 = 3600e3;
    const D1 = 24 * H1;
    const span = to - from;
    const maxTicks = Math.max(2, Math.floor(widthPx / 72));
    const steps = [5 * 60e3, 10 * 60e3, 15 * 60e3, 30 * 60e3, H1, 2 * H1, 3 * H1, 6 * H1, 12 * H1, D1, 2 * D1, 7 * D1];
    const step = steps.find((st) => span / st <= maxTicks) || 7 * D1;
    let d = new Date(from);
    if (step >= D1) {
      d.setHours(0, 0, 0, 0);
    } else if (step >= H1) {
      d.setMinutes(0, 0, 0);
      const hrs = step / H1;
      d.setHours(Math.floor(d.getHours() / hrs) * hrs);
    } else {
      const mins = step / 60e3;
      d.setSeconds(0, 0);
      d.setMinutes(Math.floor(d.getMinutes() / mins) * mins);
    }
    const out = [];
    for (let guard = 0; guard < 500 && d.getTime() <= to; guard++) {
      const t = d.getTime();
      if (t >= from) {
        const midnight = d.getHours() === 0 && d.getMinutes() === 0;
        out.push({ ms: t, label: step >= D1 || midnight ? F.day.format(d) : F.hm.format(d) });
      }
      d = step >= D1 ? new Date(d.getFullYear(), d.getMonth(), d.getDate() + step / D1) : new Date(t + step);
    }
    return out;
  }

  /** nearestIndex finds the index of the time closest to t (times ascending). */
  function nearestIndex(times, t) {
    let lo = 0;
    let hi = times.length - 1;
    if (hi < 0) return -1;
    while (hi - lo > 1) {
      const mid = (lo + hi) >> 1;
      if (times[mid] < t) lo = mid; else hi = mid;
    }
    return Math.abs(times[lo] - t) <= Math.abs(times[hi] - t) ? lo : hi;
  }

  function chartTableView(o, cols, rows) {
    const wrap = h('div', { class: 'chart-table', tabindex: '0', role: 'region', 'aria-label': o.title + ' — table view' });
    wrap.append(table(cols, rows, { compact: true }).firstChild);
    return wrap;
  }

  /** chartFrame builds the figure, caption, table toggle and the focusable plot area. */
  function chartFrame(o) {
    const fig = h('figure', { class: 'chart' });
    const tableBtn = h('button', { type: 'button', class: 'btn btn-small', 'aria-pressed': String(app.tableViews.has(o.id)), title: 'Show the data as a table (T)' }, 'Table');
    fig.append(h('figcaption', { class: 'chart-head' },
      h('div', null, h('span', { class: 'chart-title' }, o.title), o.subtitle ? h('p', { class: 'chart-sub' }, o.subtitle) : null),
      tableBtn));
    const plot = h('div', {
      class: 'plot', tabindex: '0', role: 'group', 'aria-roledescription': 'chart',
      'aria-label': o.title + '. Use the left and right arrow keys to read values, T for the table view.',
    });
    const tip = h('div', { class: 'tip', hidden: true, 'aria-hidden': 'true' });
    plot.append(tip);
    const live = h('div', { class: 'sr-only', 'aria-live': 'polite' });
    return { fig, tableBtn, plot, tip, live };
  }

  function placeTip(tip, x, width) {
    tip.hidden = false;
    const tw = tip.offsetWidth;
    let left = x + 14;
    if (left + tw > width) left = x - 14 - tw;
    if (left < 0) left = Math.max(0, Math.min(width - tw, x - tw / 2));
    tip.style.left = Math.round(left) + 'px'; // CSSOM (not a style attribute): allowed by the CSP
  }

  /**
   * lineChart draws one or more series against one y-axis.
   * o: {id, title, subtitle, series:[{key,label,slot,vals,mark,of}], times, from, to, gapMs,
   *     legend, legendExtra, linked, yMin, yMax, minMax, robustMax, pad, thresholds, band,
   *     atLeast, yFmt, tipFmt(v, series, i), tipTime, tipExtra, unit, ctx}
   * A series with mark 'tick' is drawn as a short mark per value (e.g. the peak of a bucket);
   * one with "of" has no legend button and shows and hides with the series it names. legendExtra
   * lists further legend entries ([key, label]). atLeast {at: [bool], keys} marks the values at
   * those indexes, of those series, as lower bounds: a chevron above them.
   */
  function lineChart(o) {
    const { fig, tableBtn, plot, tip, live } = chartFrame(o);
    const H = o.band ? 252 : 224;
    let legendEl = null;
    const primary = o.series.filter((se) => !se.of);
    if (o.legend && primary.length > 1) {
      legendEl = h('ul', { class: 'legend', 'aria-label': 'Series — select to show or hide' });
      for (const se of primary) {
        const btn = h('button', { type: 'button', 'aria-pressed': String(!app.hidden.has(se.key)), dataset: { key: se.key } }, lineKey(se.slot), se.label);
        btn.addEventListener('click', () => {
          if (app.hidden.has(se.key)) app.hidden.delete(se.key); else app.hidden.add(se.key);
          for (const c of o.linked || [api_]) c.refresh();
        });
        legendEl.append(h('li', null, btn));
      }
      for (const [key, label] of o.legendExtra || []) legendEl.append(h('li', null, h('span', { class: 'static' }, key, label)));
      fig.append(legendEl);
    }
    if (o.band && o.band.legend) {
      fig.append(h('ul', { class: 'legend', 'aria-label': 'Flag strip legend' },
        o.band.legend.map(([tone, label]) => h('li', null, h('span', { class: 'static' }, icon(tone), label)))));
    }
    const note = h('p', { class: 'chart-note', hidden: true });
    const tableWrap = h('div', { hidden: true });
    fig.append(plot, note, live, tableWrap);

    let W = 0;
    let g = null;
    let idx = -1;

    function visible() {
      return o.series.filter((se) => !app.hidden.has(se.of || se.key));
    }

    function layout() {
      const M = { top: 12, right: 14, bottom: o.band ? 50 : 26, left: 54 };
      const x0 = M.left;
      const x1 = W - M.right;
      const y0 = H - M.bottom;
      const y1 = M.top;
      const vis = visible();
      let mn = Infinity;
      let mx = -Infinity;
      const all = [];
      for (const se of vis) {
        for (const v of se.vals) {
          if (v == null || !isFinite(v)) continue;
          all.push(v);
          if (v < mn) mn = v;
          if (v > mx) mx = v;
        }
      }
      for (const t of o.thresholds || []) {
        if (t.v == null) continue;
        if (t.v < mn) mn = t.v;
        if (t.v > mx) mx = t.v;
      }
      if (!isFinite(mn)) { mn = 0; mx = 1; }
      let lo = o.yMin != null ? o.yMin : mn - (o.pad || 0);
      let hi = o.yMax != null ? o.yMax : mx + (o.pad || 0);
      if (o.yMax == null && o.robustMax && all.length > 20) {
        const sorted = all.slice().sort((a, b) => a - b);
        const p99 = sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.99))];
        if (mx > p99 * 1.5) hi = p99 * 1.25;
      }
      if (o.minMax != null) hi = Math.max(hi, o.minMax);
      const nt = niceTicks(lo, hi, 4);
      lo = o.yMin != null ? o.yMin : nt.lo;
      hi = o.yMax != null ? o.yMax : nt.hi;
      const ticks = nt.ticks.filter((t) => t >= lo - 1e-9 && t <= hi + 1e-9);
      const xs = (t) => x0 + ((t - o.from) / (o.to - o.from)) * (x1 - x0);
      const ys = (v) => y0 - ((v - lo) / (hi - lo)) * (y0 - y1);
      return { x0, x1, y0, y1, lo, hi, ticks, xs, ys, vis };
    }

    function draw() {
      W = Math.max(260, Math.round(plot.clientWidth));
      g = layout();
      const svg = s('svg', { width: W, height: H, viewBox: `0 0 ${W} ${H}`, 'aria-hidden': 'true', focusable: 'false' });
      for (const t of g.ticks) {
        const y = Math.round(g.ys(t)) + 0.5;
        svg.append(s('line', { class: 'gl', x1: g.x0, x2: g.x1, y1: y, y2: y }),
          s('text', { class: 'tk', x: g.x0 - 8, y: y + 3.5, 'text-anchor': 'end' }, o.yFmt(t)));
      }
      svg.append(s('line', { class: 'al', x1: g.x0, x2: g.x1, y1: g.y0 + 0.5, y2: g.y0 + 0.5 }));
      for (const t of timeTicks(o.from, o.to, g.x1 - g.x0)) {
        const x = Math.round(g.xs(t.ms)) + 0.5;
        svg.append(s('line', { class: 'al', x1: x, x2: x, y1: g.y0, y2: g.y0 + 4 }),
          s('text', { class: 'tk', x, y: g.y0 + 17, 'text-anchor': 'middle' }, t.label));
      }
      for (const th of o.thresholds || []) {
        if (th.v == null || th.v < g.lo || th.v > g.hi) continue;
        const y = g.ys(th.v);
        svg.append(s('line', { class: 'thr thr-' + th.tone, x1: g.x0, x2: g.x1, y1: y, y2: y }),
          s('text', { class: 'thr-label', x: g.x1 - 4, y: th.place === 'below' ? y + 13 : y - 5, 'text-anchor': 'end' }, th.label));
      }
      let clamped = 0;
      // Tick marks span half a bucket (the times' typical spacing), 2 to 8 px, so that marks of
      // neighbouring buckets stay apart.
      const n = o.times.length;
      const spacing = n > 1 ? (o.times[n - 1] - o.times[0]) / (n - 1) : o.to - o.from;
      const half = Math.max(1, Math.min(4, (spacing / (o.to - o.from)) * (g.x1 - g.x0) / 4));
      for (const se of g.vis) {
        if (se.mark === 'tick') {
          for (let i = 0; i < se.vals.length; i++) {
            const v = se.vals[i];
            const t = o.times[i];
            if (v == null || !isFinite(v) || t < o.from || t > o.to) continue;
            if (v > g.hi) clamped++;
            const x = g.xs(t);
            const y = g.ys(Math.min(Math.max(v, g.lo), g.hi)).toFixed(1);
            svg.append(s('line', { class: 'pk c' + se.slot, x1: (x - half).toFixed(1), x2: (x + half).toFixed(1), y1: y, y2: y }));
          }
          continue;
        }
        const segs = [];
        let cur = null;
        let prevT = null;
        for (let i = 0; i < se.vals.length; i++) {
          const v = se.vals[i];
          const t = o.times[i];
          if (v == null || !isFinite(v) || t < o.from || t > o.to) { cur = null; continue; }
          let vv = v;
          if (vv > g.hi) { vv = g.hi; clamped++; }
          if (vv < g.lo) vv = g.lo;
          const pt = [g.xs(t), g.ys(vv)];
          if (cur && prevT != null && t - prevT <= o.gapMs) cur.push(pt);
          else { cur = [pt]; segs.push(cur); }
          prevT = t;
        }
        let d = '';
        for (const seg of segs) {
          if (seg.length === 1) {
            svg.append(s('circle', { class: 'dot f' + se.slot, cx: seg[0][0].toFixed(1), cy: seg[0][1].toFixed(1), r: 4 }));
            continue;
          }
          d += 'M' + seg.map((p) => p[0].toFixed(1) + ' ' + p[1].toFixed(1)).join('L');
        }
        if (d) svg.append(s('path', { class: 'ln c' + se.slot, d }));
      }
      if (o.atLeast) {
        // A chevron above the highest value of the series concerned: "at least this much".
        const marked = g.vis.filter((se) => o.atLeast.keys.includes(se.of || se.key));
        for (let i = 0; i < n; i++) {
          if (!o.atLeast.at[i] || o.times[i] < o.from || o.times[i] > o.to) continue;
          const top = Math.max(...marked.map((se) => se.vals[i]).filter((v) => v != null && isFinite(v)));
          if (!isFinite(top)) continue;
          const x = g.xs(o.times[i]);
          const y = g.ys(Math.min(Math.max(top, g.lo), g.hi)) - 5;
          svg.append(s('path', { class: 'atleast', d: `M${(x - 4).toFixed(1)} ${y.toFixed(1)}L${x.toFixed(1)} ${(y - 5).toFixed(1)}L${(x + 4).toFixed(1)} ${y.toFixed(1)}` }));
        }
      }
      if (o.band) {
        const by = H - 14;
        svg.append(s('text', { class: 'tk', x: g.x0 - 8, y: by + 7, 'text-anchor': 'end' }, o.band.label));
        const rr = o.band.runs;
        for (let i = 0; i < rr.length; i++) {
          const a = Math.max(g.x0, g.xs(rr[i].start));
          const b = Math.min(g.x1, g.xs(rr[i].end));
          let w = b - a;
          if (i < rr.length - 1 && w > 6) w -= 2; // 2px surface gap between touching runs
          if (w <= 0) continue;
          svg.append(s('rect', { class: 'sf-' + rr[i].tone, x: a.toFixed(1), y: by, width: Math.max(1.5, w).toFixed(1), height: 8, rx: 1 }));
        }
      }
      note.hidden = clamped === 0;
      if (clamped) note.textContent = `${clamped} value${clamped > 1 ? 's' : ''} above ${o.yFmt(g.hi)} ${clamped > 1 ? 'are' : 'is'} drawn at the top edge; the table view has the exact numbers.`;
      g.xh = s('line', { class: 'xh', x1: 0, x2: 0, y1: g.y1, y2: g.y0, visibility: 'hidden' });
      g.dots = s('g', { visibility: 'hidden' });
      svg.append(g.xh, g.dots);
      const old = plot.querySelector('svg');
      if (old) old.replaceWith(svg); else plot.insertBefore(svg, tip);
      if (idx >= 0 && !tip.hidden) showAt(idx, false);
    }

    function bandAt(t) {
      if (!o.band) return null;
      return o.band.runs.find((r) => t >= r.start && t <= r.end) || null;
    }

    function showAt(i, pointer) {
      if (!g || i < 0 || i >= o.times.length) { hide(); return; }
      idx = i;
      const x = g.xs(o.times[i]);
      g.xh.setAttribute('x1', x);
      g.xh.setAttribute('x2', x);
      g.xh.setAttribute('visibility', 'visible');
      replace(g.dots);
      const rows = [];
      for (const se of g.vis) {
        const v = se.vals[i];
        if (v != null && isFinite(v)) {
          g.dots.append(s('circle', { class: 'dot f' + se.slot, cx: x, cy: g.ys(Math.min(Math.max(v, g.lo), g.hi)), r: 4 }));
        }
        rows.push(h('div', { class: 'tip-row' }, se.mark === 'tick' ? tickKey(se.slot) : lineKey(se.slot),
          h('span', { class: 'val' }, o.tipFmt(v, se, i)), h('span', { class: 'lab' }, se.label)));
      }
      g.dots.setAttribute('visibility', 'visible');
      const when = new Date(o.times[i]);
      replace(tip, 
        h('div', { class: 'tip-time' }, o.tipTime ? o.tipTime(i) : F.full.format(when)),
        h('div', { class: 'tip-utc' }, o.tipUTC ? o.tipUTC(i) : utcText(null, when)),
        rows, o.tipExtra ? o.tipExtra(i) : null);
      placeTip(tip, x, W);
      if (!pointer) {
        const b = bandAt(o.times[i]);
        live.textContent = (o.tipTime ? o.tipTime(i) : F.full.format(when)) + ': ' +
          g.vis.map((se) => se.label + ' ' + o.tipFmt(se.vals[i], se, i)).join(', ') + (b ? '; ' + b.label : '');
      }
    }

    function hide() {
      tip.hidden = true;
      if (g) {
        g.xh.setAttribute('visibility', 'hidden');
        g.dots.setAttribute('visibility', 'hidden');
      }
    }

    function lastIndexWithData() {
      for (let i = o.times.length - 1; i >= 0; i--) {
        if (g && g.vis.some((se) => se.vals[i] != null)) return i;
      }
      return o.times.length - 1;
    }

    plot.addEventListener('pointermove', (e) => {
      if (!g || !o.times.length) return;
      const x = e.clientX - plot.getBoundingClientRect().left;
      if (x < g.x0 - 10 || x > g.x1 + 10) { hide(); return; }
      const t = o.from + ((x - g.x0) / (g.x1 - g.x0)) * (o.to - o.from);
      showAt(nearestIndex(o.times, t), true);
    });
    plot.addEventListener('pointerleave', hide);
    plot.addEventListener('focus', () => { if (o.times.length) showAt(idx >= 0 ? idx : lastIndexWithData(), false); });
    plot.addEventListener('blur', hide);
    plot.addEventListener('keydown', (e) => {
      const n = o.times.length;
      if (!n) return;
      let i = idx >= 0 ? idx : lastIndexWithData();
      switch (e.key) {
        case 'ArrowLeft': i = Math.max(0, i - (e.shiftKey ? 10 : 1)); break;
        case 'ArrowRight': i = Math.min(n - 1, i + (e.shiftKey ? 10 : 1)); break;
        case 'Home': i = 0; break;
        case 'End': i = n - 1; break;
        case 'Escape': hide(); return;
        case 't': case 'T': tableBtn.click(); return;
        default: return;
      }
      e.preventDefault();
      showAt(i, false);
    });

    function buildTable() {
      const cols = [{ label: 'Time (local)' }].concat(o.series.map((se) => ({ label: se.label + (o.unit ? ' (' + o.unit + ')' : ''), num: true })));
      if (o.band) cols.push({ label: 'Gateway flag' });
      const rows = [];
      for (let i = o.times.length - 1; i >= 0; i--) {
        const r = [timeEl(o.times[i], F.full)];
        if (o.tipTime) r[0] = h('span', { title: 'UTC: ' + utcText(null, new Date(o.times[i])) }, o.tipTime(i));
        for (const se of o.series) r.push(o.tipFmt(se.vals[i], se, i));
        if (o.band) {
          const b = bandAt(o.times[i]);
          r.push(b ? h('span', { class: 'badge' }, icon(b.tone), b.label) : '—');
        }
        rows.push(r);
      }
      return chartTableView(o, cols, rows);
    }

    function applyView() {
      const on = app.tableViews.has(o.id);
      tableBtn.setAttribute('aria-pressed', String(on));
      plot.hidden = on;
      tableWrap.hidden = !on;
      if (on && !tableWrap.firstChild) tableWrap.append(buildTable());
      if (!on && plot.clientWidth && Math.round(plot.clientWidth) !== W) draw();
    }
    tableBtn.addEventListener('click', () => {
      if (app.tableViews.has(o.id)) app.tableViews.delete(o.id); else app.tableViews.add(o.id);
      applyView();
    });

    const api_ = {
      refresh() {
        if (legendEl) {
          for (const btn of legendEl.querySelectorAll('button')) {
            btn.setAttribute('aria-pressed', String(!app.hidden.has(btn.dataset.key)));
          }
        }
        if (W) draw();
      },
    };
    if (o.linked) o.linked.push(api_);

    const ro = new ResizeObserver(() => {
      const w = Math.round(plot.clientWidth);
      if (w && w !== W) draw();
    });
    ro.observe(plot);
    if (o.ctx) o.ctx.cleanup(() => ro.disconnect());
    applyView();
    return fig;
  }

  /** stateRuns merges buckets into runs of equal state; missing buckets become "no data". */
  function stateRuns(points, from, to, stepMs) {
    const runs = [];
    const push = (state, start, end) => {
      if (end <= start) return;
      const last = runs[runs.length - 1];
      if (last && last.state === state && Math.abs(last.end - start) < 1000) last.end = end;
      else runs.push({ state, start, end });
    };
    let cursor = from;
    for (const p of points) {
      const t = toMs(p.t);
      if (t == null) continue;
      if (t > cursor + 1000) push('', cursor, t);
      const start = Math.max(t, from);
      const end = Math.min(t + stepMs, to);
      push(p.state || '', start, end);
      cursor = Math.max(cursor, end);
    }
    if (to - cursor > 2 * stepMs) push('', cursor, to);
    return runs;
  }

  /** stripOrder lists the states of the availability legend and shares: the fixed order, plus
   *  UNKNOWN when a bucket's every cycle could not be judged (e.g. interrupted by system sleep,
   *  rules 2026.10-4), so that the shares add up. */
  function stripOrder(runs) {
    const order = STATE_ORDER.slice();
    if (runs.some((r) => r.state === 'UNKNOWN')) order.splice(order.indexOf(''), 0, 'UNKNOWN');
    return order;
  }

  function stateStrip(o) {
    const runs = stateRuns(o.points, o.from, o.to, o.stepMs);
    const order = stripOrder(runs);
    const unknown = order.includes('UNKNOWN');
    const { fig, tableBtn, plot, tip, live } = chartFrame({
      id: o.id, title: 'Availability',
      subtitle: 'Worst classifier state in each ' + fmtDur(o.stepMs / 1000) + ' bucket. Grey: the monitor was not measuring' +
        (unknown ? ', or its measurements could not be judged (Unknown).' : '.'),
    });
    const H = 64;
    fig.append(h('ul', { class: 'legend', 'aria-label': 'States' },
      order.map((st) => h('li', null, h('span', { class: 'static' }, icon(stateInfo(st).tone), stateInfo(st).label)))));
    const summary = h('p', { class: 'chart-summary' });
    const tableWrap = h('div', { hidden: true });
    fig.append(plot, summary, live, tableWrap);

    const total = {};
    let all = 0;
    for (const r of runs) {
      total[r.state] = (total[r.state] || 0) + (r.end - r.start);
      all += r.end - r.start;
    }
    if (all > 0) {
      add(summary, ['Share of this range: ', order.filter((st) => total[st]).map((st) =>
        h('span', { class: 'badge' }, icon(stateInfo(st).tone), stateInfo(st).label + ' ' + fmtPct((100 * total[st]) / all, 2)))]);
    }

    let W = 0;
    let g = null;
    let idx = -1;

    function draw() {
      W = Math.max(260, Math.round(plot.clientWidth));
      const x0 = 54;
      const x1 = W - 14;
      const xs = (t) => x0 + ((t - o.from) / (o.to - o.from)) * (x1 - x0);
      const svg = s('svg', { width: W, height: H, viewBox: `0 0 ${W} ${H}`, 'aria-hidden': 'true', focusable: 'false' });
      const rects = [];
      for (let i = 0; i < runs.length; i++) {
        const r = runs[i];
        const a = xs(r.start);
        let w = xs(r.end) - a;
        if (i < runs.length - 1 && w > 6) w -= 2; // 2px surface gap between touching runs
        if (r.state !== 'ONLINE' && r.state !== '') w = Math.max(w, 2); // a blip stays visible
        const rect = s('rect', { class: 'sf-' + stateInfo(r.state).tone, x: a.toFixed(1), y: 6, width: Math.max(1, w).toFixed(1), height: 28, rx: 2 });
        rects.push(rect);
        svg.append(rect);
      }
      for (const t of timeTicks(o.from, o.to, x1 - x0)) {
        const x = Math.round(xs(t.ms)) + 0.5;
        svg.append(s('line', { class: 'al', x1: x, x2: x, y1: 38, y2: 42 }),
          s('text', { class: 'tk', x, y: 55, 'text-anchor': 'middle' }, t.label));
      }
      const outline = s('rect', { class: 'run-hover', visibility: 'hidden', x: 0, y: 5, width: 0, height: 30, rx: 3 });
      svg.append(outline);
      g = { x0, x1, xs, outline };
      const old = plot.querySelector('svg');
      if (old) old.replaceWith(svg); else plot.insertBefore(svg, tip);
      if (idx >= 0 && !tip.hidden) showAt(idx, false);
    }

    function showAt(i, pointer) {
      if (!g || i < 0 || i >= runs.length) { hide(); return; }
      idx = i;
      const r = runs[i];
      const si = stateInfo(r.state);
      const a = g.xs(r.start);
      const b = g.xs(r.end);
      g.outline.setAttribute('x', a.toFixed(1));
      g.outline.setAttribute('width', Math.max(2, b - a).toFixed(1));
      g.outline.setAttribute('visibility', 'visible');
      const range = F.short.format(new Date(r.start)) + ' – ' + F.short.format(new Date(r.end));
      replace(tip, 
        h('div', { class: 'tip-row' }, icon(si.tone), h('span', { class: 'val' }, si.label), h('span')),
        h('div', { class: 'tip-time' }, range),
        h('div', { class: 'tip-utc' }, utcText(null, new Date(r.start)) + ' – ' + utcText(null, new Date(r.end))),
        h('div', null, 'Duration ' + fmtDur((r.end - r.start) / 1000)));
      placeTip(tip, (a + b) / 2, W);
      if (!pointer) live.textContent = `${si.label}, ${range}, ${fmtDur((r.end - r.start) / 1000)}`;
    }

    function hide() {
      tip.hidden = true;
      if (g) g.outline.setAttribute('visibility', 'hidden');
    }

    plot.addEventListener('pointermove', (e) => {
      if (!g || !runs.length) return;
      const x = e.clientX - plot.getBoundingClientRect().left;
      if (x < g.x0 - 4 || x > g.x1 + 4) { hide(); return; }
      const t = o.from + ((x - g.x0) / (g.x1 - g.x0)) * (o.to - o.from);
      let i = runs.findIndex((r) => t >= r.start && t < r.end);
      if (i < 0) i = nearestIndex(runs.map((r) => (r.start + r.end) / 2), t);
      showAt(i, true);
    });
    plot.addEventListener('pointerleave', hide);
    plot.addEventListener('focus', () => { if (runs.length) showAt(idx >= 0 ? idx : runs.length - 1, false); });
    plot.addEventListener('blur', hide);
    plot.addEventListener('keydown', (e) => {
      if (!runs.length) return;
      let i = idx >= 0 ? idx : runs.length - 1;
      switch (e.key) {
        case 'ArrowLeft': i = Math.max(0, i - 1); break;
        case 'ArrowRight': i = Math.min(runs.length - 1, i + 1); break;
        case 'Home': i = 0; break;
        case 'End': i = runs.length - 1; break;
        case 'Escape': hide(); return;
        case 't': case 'T': tableBtn.click(); return;
        default: return;
      }
      e.preventDefault();
      showAt(i, false);
    });

    function applyView() {
      const on = app.tableViews.has(o.id);
      tableBtn.setAttribute('aria-pressed', String(on));
      plot.hidden = on;
      tableWrap.hidden = !on;
      if (on && !tableWrap.firstChild) {
        const rows = runs.slice().reverse().map((r) => [h('span', { class: 'badge' }, icon(stateInfo(r.state).tone), stateInfo(r.state).label), timeEl(r.start, F.full), timeEl(r.end, F.full), fmtDur((r.end - r.start) / 1000)]);
        tableWrap.append(chartTableView({ title: 'Availability' }, [{ label: 'State' }, { label: 'From' }, { label: 'To' }, { label: 'Duration', num: true }], rows));
      }
      if (!on && plot.clientWidth && Math.round(plot.clientWidth) !== W) draw();
    }
    tableBtn.addEventListener('click', () => {
      if (app.tableViews.has(o.id)) app.tableViews.delete(o.id); else app.tableViews.add(o.id);
      applyView();
    });
    const ro = new ResizeObserver(() => {
      const w = Math.round(plot.clientWidth);
      if (w && w !== W) draw();
    });
    ro.observe(plot);
    if (o.ctx) o.ctx.cleanup(() => ro.disconnect());
    applyView();
    return fig;
  }

  // ------------------------------------------------------------------ incidents

  function localDateValue(d) {
    const pad = (n) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  }

  function localDateToISO(value, addDays) {
    const m = /^(\d{4})-(\d\d)-(\d\d)$/.exec(value || '');
    if (!m) return '';
    return new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]) + (addDays || 0)).toISOString();
  }

  function renderIncidents(c, q, ctx) {
    c.append(h('div', { class: 'view-head' }, h('h1', null, 'Incidents'),
      h('p', { class: 'muted' }, 'With the default settings an incident opens when at least 3 of the last 6 ten-second measurement cycles are bad — a continuous outage or flapping connectivity — and closes after 3 consecutive good cycles; bad cycles that never open an incident count as blips. “Without Internet” counts only the cycles classified as an AT&T outage: the AT&T gateway answered, no internet target did, and this computer’s traffic was not routed past the gateway (a VPN, for example). Cycles while the AT&T gateway was restarting are shown separately and are not counted as AT&T downtime.')));
    const fromIn = h('input', { type: 'date' });
    const toIn = h('input', { type: 'date' });
    fromIn.value = q.get('from') || localDateValue(new Date(Date.now() - 30 * 86400e3));
    toIn.value = q.get('to') || '';
    const out = h('section', { class: 'card', 'aria-live': 'polite' }, h('p', { class: 'loading' }, 'Loading…'));
    const form = h('form', { class: 'card filters' },
      field('From (local date)', fromIn),
      field('To (local date, inclusive)', toIn),
      h('button', { type: 'submit', class: 'btn btn-primary' }, 'Show incidents'));
    form.addEventListener('submit', (e) => { e.preventDefault(); load(); });
    c.append(form, out);

    async function load() {
      const params = new URLSearchParams();
      if (fromIn.value) params.set('from', localDateToISO(fromIn.value, 0));
      if (toIn.value) params.set('to', localDateToISO(toIn.value, 1));
      replace(out, h('p', { class: 'loading' }, 'Loading…'));
      try {
        const list = await api('/api/incidents?' + params.toString());
        if (!ctx.alive) return;
        const provider = list.filter((i) => i.attribution === 'provider');
        const measured = provider.filter((i) => rulesAtLeast(i.rules, RULES_TIME_ACCOUNTING));
        const downSec = measured.reduce((acc, i) => acc + ((i.stats && i.stats.downtime_s) || 0), 0);
        const spanSec = provider.reduce((acc, i) => acc + (i.duration_s || 0), 0);
        let summary = `${provider.length} attributed to AT&T`;
        if (provider.length) {
          summary += `: ${fmtDur(downSec)} without Internet` + (measured.length < provider.length
            ? ` (${provider.length - measured.length} recorded before time accounting not included)` : '') +
            `, ${fmtDur(spanSec)} from their first bad cycle to their close (or to now)`;
        }
        replace(out,
          h('h2', null, `${list.length} incident${list.length === 1 ? '' : 's'}`),
          h('p', { class: 'muted' }, summary + '.'),
          incidentsTable(list, app.status && app.status.now));
      } catch (e) {
        if (ctx.alive) replace(out, errorNotice(e));
      }
    }
    load();
  }

  async function renderIncident(c, id, ctx) {
    c.append(h('p', null, h('a', { href: '#/incidents' }, '← All incidents')), h('h1', null, 'Incident ', id));
    const box = h('div', { class: 'stack' }, h('p', { class: 'loading' }, 'Loading incident…'));
    // The gateway's syslog around the incident: kept outside box so that the 30 s refresh of an
    // open incident does not rebuild it (and close what the reader opened) until new data arrive.
    const sys = h('section', { class: 'card', 'aria-labelledby': 'incident-syslog-h', hidden: true });
    const sysIntro = h('p', { class: 'small muted' });
    c.append(box, sys);
    let open = false;
    let sysBrowser = null;
    let sysPeriod = null;
    const load = async () => {
      if (box.querySelector('button[disabled]')) return; // an export is running; keep its result area
      try {
        const data = await api('/api/incidents/' + encodeURIComponent(id));
        if (!ctx.alive) return;
        open = !!data.incident.open;
        replace(box, ...incidentDetail(data));
        const p = incidentSyslogPeriod(data.incident);
        const key = JSON.stringify(p);
        if (open || key !== sysPeriod) {
          sysPeriod = key;
          replace(sysIntro, 'The gateway’s own log messages recorded from 5 minutes before the incident opened to ',
            open ? 'now (the incident is still open)' : '5 minutes after it closed', ', newest first; their times are when this PC received them.',
            p.clipped ? ' The incident is longer than 31 days: only its last 31 days are searched.' : '');
          if (!sysBrowser) {
            sys.hidden = false;
            sysBrowser = syslogBrowser(sys, ctx, {
              heading: 'Gateway syslog around this incident', headingId: 'incident-syslog-h', intro: sysIntro,
              empty: () => 'No syslog messages were received in this period.',
            });
          }
          sysBrowser.load({ from: p.from, to: p.to });
        }
      } catch (e) {
        if (ctx.alive) replace(box, errorNotice(e));
      }
    };
    await load();
    ctx.interval(() => { if (open && !document.hidden) load(); }, 30000);
  }

  /** incidentSyslogPeriod is the period of an incident's syslog messages: from 5 minutes before
   *  it opened to 5 minutes after it closed, or (while it is open) until now, which the server
   *  fills in (to is left out). A period longer than GET /api/syslog reads keeps its end
   *  (clipped). */
  function incidentSyslogPeriod(inc) {
    const opened = toMs(inc.opened);
    const closed = inc.open ? null : toMs(inc.closed);
    const end = closed != null ? closed + 5 * 60e3 : Date.now();
    let from = opened != null ? opened - 5 * 60e3 : end - 3600e3;
    const clipped = end - from > SYSLOG_MAX_SPAN_MS;
    if (clipped) from = end - SYSLOG_MAX_SPAN_MS;
    return { from: new Date(from).toISOString(), to: closed != null ? new Date(end).toISOString() : '', clipped };
  }

  function incidentDetail(data) {
    const inc = data.incident;
    const si = stateInfo(inc.state);
    const now = app.status && app.status.now;
    const st = inc.stats || {};
    const exportResult = h('div');
    const exportBtn = h('button', { type: 'button', class: 'btn btn-primary' }, 'Export this incident as an evidence bundle');
    exportBtn.addEventListener('click', () => exportIncident(inc.id, exportBtn, exportResult));

    const head = h('section', { class: 'card hero tone-' + si.tone },
      icon(si.tone, 'hero-icon'),
      h('div', null,
        h('p', { class: 'eyebrow' }, inc.open ? 'Incident in progress' : 'Closed incident'),
        h('h2', { class: 'hero-title' }, headline(inc)),
        ATTR_LONG[inc.attribution] ? h('p', { class: 'hero-attr' }, ATTR_LONG[inc.attribution]) : null,
        h('p', { class: 'hero-since' }, 'Opened ', timeEl(inc.opened), inc.closed ? [' · closed ', timeEl(inc.closed)] : null, ' · duration ', incidentDuration(inc, now)),
        inc.summary ? h('p', null, inc.summary) : null,
        inc.reasons && inc.reasons.length ? h('ul', { class: 'reasons' }, inc.reasons.map((r) => h('li', null, r))) : null,
        h('p', { class: 'hero-meta' }, 'Classified with rules ', h('code', null, inc.rules || '—'),
          inc.causes && inc.causes.length ? ' · causes seen: ' + inc.causes.map(causeText).join(', ') : ''),
        h('div', { class: 'btn-row' }, exportBtn),
        exportResult));

    // Time accounting (docs/DESIGN.md §10): cycles, not the wall-clock span.
    const restartRules = rulesAtLeast(inc.rules, RULES_RESTART_WINDOWS);
    const sub = (text) => h('span', { class: 'sub small muted' }, text);
    const restarts = (inc.gateway_restarts || []).filter((t) => toDate(t));
    const timeRows = [
      ['Duration', [incidentDuration(inc, now), sub(inc.open ? 'from the first bad cycle until now' : 'from the first bad cycle to the first of the good cycles that closed it')]],
    ];
    if (rulesAtLeast(inc.rules, RULES_TIME_ACCOUNTING)) {
      timeRows.push(
        ['Without Internet', [downtimeText(inc), sub('cycles classified as an AT&T outage: the AT&T gateway answered but no internet target did' + (restartRules ? ', outside gateway-restart windows' : ''))]],
        ['Degraded', [st.degraded_s > 0 ? fmtDur(st.degraded_s) : 'none', sub('cycles with packet loss, high latency or DNS failures')]]);
      if (restartRules || st.restart_s > 0) {
        timeRows.push(['During gateway restarts', [st.restart_s > 0 ? fmtDur(st.restart_s) : 'none', sub('bad cycles inside a gateway-restart window — not counted as AT&T downtime')]]);
      }
    } else {
      timeRows.push(['Without Internet', h('span', { class: 'muted' }, 'not measured: classified with rules ' + orQ(inc.rules) + ', before time accounting (rules ' + RULES_TIME_ACCOUNTING + ')')]);
    }
    timeRows.push(
      ['Internet back', inc.recovered_at ? [timeEl(inc.recovered_at), sub('the first cycle after the last outage cycle in which every probe succeeded')] : null],
      ['Gateway restarts', restarts.length ? [restarts.map((t, i) => [i ? ', ' : '', timeEl(t)]), sub('boot times estimated from the gateway’s own uptime')] : null]);
    const timeCard = card('Time accounting', kv(timeRows),
      restarts.length || st.restart_s > 0 ? h('p', { class: 'small muted' }, 'A gateway-restart window runs from the gateway’s boot (including the time it was unreachable just before) until the Internet is reachable again, at most 10 minutes. Bad cycles inside it are not counted as AT&T downtime, because a restart can be caused by the owner (for example by power-cycling the gateway) as well as by AT&T. ' + (rulesAtLeast(inc.rules, RULES_RESTART_MIN_CYCLES)
        ? 'The incident is attributed to AT&T only if the outage was also observed outside restart windows on at least as many measurement cycles as it takes to open an incident (fewer are stray cycles of the restart’s own shutdown and bring-up), or if the gateway’s firmware changed across the restart (an AT&T-pushed update).'
        : 'The incident is attributed to AT&T only if the outage was also observed outside restart windows, or if the gateway’s firmware changed across the restart (an AT&T-pushed update).')) : null,
      h('p', { class: 'small muted' }, 'Times count measurement cycles: each cycle covers the time until the next one started, at most 1.5 cycle intervals; longer pauses are monitoring gaps, not outage time.'));

    const flag = (v, label) => [label, v ? chip('critical', 'yes') : chip('good', 'no')];
    const probeRows = Object.keys(st.probe_total || {}).sort().map((name) => {
      const tot = st.probe_total[name] || 0;
      const ok = (st.probe_ok || {})[name] || 0;
      return [h('span', { title: name }, probeLabel({ name })), fmtInt(ok) + ' / ' + fmtInt(tot), tot ? fmtPct((100 * ok) / tot, 1) : '—'];
    });
    const stats = card('What was observed',
      kv([
        ['Measurement cycles', `${fmtInt(st.bad_cycles)} bad of ${fmtInt(st.cycles)}`],
        ['Gateway status fetches', fmtInt(st.gateway_fetches)],
        flag(st.gateway_reported_down, 'Gateway reported broadband Down'),
        flag(st.pon_down_seen, 'Fiber (PON) down seen'),
        flag(st.optical_alarm_seen, 'Optical alarm seen'),
        flag(st.dns_hijack_seen, 'DNS hijack seen'),
        flag(st.http_hijack_seen, 'Web (HTTP) hijack seen'),
        flag(st.local_link_down_seen, 'This PC’s link down seen'),
      ]),
      probeRows.length ? h('h3', { class: 'subhead' }, 'Probe success during the incident') : null,
      probeRows.length ? table([{ label: 'Probe' }, { label: 'Answered', num: true }, { label: 'Success', num: true }], probeRows, { compact: true }) : null);

    const records = (data.records || []).slice().sort((a, b) => a.seq - b.seq);
    const timeline = h('ol', { class: 'timeline' });
    for (const rec of records) {
      const d = describeRecord(rec);
      timeline.append(h('li', null,
        icon(d.tone, 'tl-dot'),
        h('div', { class: 'tl-time' }, timeEl(rec.ts), ' · ', h('a', { href: recordsLink(rec.seq) }, 'record #' + rec.seq), ' ', h('span', { class: 'type-tag' }, rec.type),
          rec.hash_ok === false ? [' ', alteredChip()] : null),
        h('div', { class: 'tl-title' }, d.title),
        d.detail ? h('p', { class: 'tl-detail' }, d.detail) : null,
        d.inputs ? h('p', { class: 'tl-detail' }, 'Classified from: ', d.inputs) : null,
        d.links && d.links.length ? h('p', { class: 'tl-links' }, d.links) : null));
    }
    const tl = card('Timeline (from the evidence records)',
      records.length ? timeline : emptyNote('No evidence records could be read.'),
      data.truncated ? notice('warning', `${fmtInt(records.length)} of the ${fmtInt(data.referenced)} records this incident references are shown: its first and last record and the earliest and latest evidence.`) : null,
      data.missing && data.missing.length ? notice('warning', 'Referenced records that could not be read: ' + data.missing.map((n) => '#' + n).join(', ')) : null);

    const evRows = (inc.evidence || []).map((e) => [
      h('a', { href: recordsLink(e.seq) }, '#' + e.seq),
      h('span', { class: 'type-tag' }, e.type || ''),
      e.note || '',
      HEX64.test(e.blob || '') ? h('span', { class: 'tl-links' }, blobLinks(e.blob, { view: e.type === 'gateway_snapshot', viewText: 'view page', downloadText: 'download' })) : '—',
    ]);
    const ev = card('Evidence references',
      h('p', { class: 'muted small' }, 'Each reference is a signed, hash-chained ledger record; raw gateway pages open in a sandbox with scripts disabled.'),
      evRows.length ? table([{ label: 'Record' }, { label: 'Type' }, { label: 'Note' }, { label: 'Raw data' }], evRows, { compact: true }) : emptyNote('No evidence references.'));
    return [head, h('div', { class: 'grid-2' }, timeCard, stats), ev, tl];
  }

  async function exportIncident(id, btn, out) {
    const prepared = h('input', { type: 'text', autocomplete: 'name', maxlength: '200' });
    prepared.value = loadPref('preparedBy', '');
    const notes = h('textarea', { maxlength: '4000' });
    const res = await dialog({
      title: 'Export incident ' + id,
      body: [h('p', null, 'Builds a verifiable evidence bundle (ledger segments, raw gateway pages, report, verifier) covering the incident ± 15 minutes. The export itself is recorded in the ledger and time-stamped.')],
      fields: [field('Prepared by (optional)', prepared), field('Notes (optional)', notes, 'For example the AT&T ticket number.')],
      confirm: 'Build bundle',
    });
    if (!res) return;
    savePref('preparedBy', prepared.value.trim());
    btn.disabled = true;
    replace(out, notice('info', spinner(), ' Building the bundle — this can take a minute…'));
    try {
      const info = await api('/api/exports', { method: 'POST', body: { incident_id: id, prepared_by: prepared.value.trim(), notes: notes.value.trim() } });
      replace(out, exportResultNotice(info));
      announce('Evidence bundle created.');
    } catch (e) {
      replace(out, errorNotice(e));
    } finally {
      btn.disabled = false;
    }
  }

  function exportResultNotice(info) {
    return notice('good',
      h('strong', null, 'Bundle ready: '),
      h('a', { href: '/api/exports/' + encodeURIComponent(info.file_name), download: info.file_name }, info.file_name),
      ` (${fmtBytes(info.size)}, ${fmtInt(info.records)} records, ${fmtInt(info.blobs)} blobs)`,
      h('div', { class: 'small' }, 'SHA-256 ', h('span', { class: 'hash' }, info.sha256 || '—'),
        info.custody_seq ? [' · custody record ', h('a', { href: recordsLink(info.custody_seq) }, '#' + info.custody_seq)] : null));
  }

  /** configSummary words the thresholds in force from a recorded configuration (secrets
   *  removed): monitor_start and config_state records. */
  function configSummary(config) {
    const cfg = config && typeof config === 'object' ? config : {};
    const ic = cfg.incident || {};
    const parts = [];
    if (ic.open_after_cycles && ic.window_cycles) {
      parts.push(`incidents open on ${ic.open_after_cycles} bad of the last ${ic.window_cycles} cycles and close after ${orQ(ic.close_after_cycles)} good ones`);
    }
    if (cfg.probes && cfg.probes.fast_interval) parts.push('measurement cycle every ' + cfg.probes.fast_interval);
    return parts;
  }

  /** describeRecord turns a ledger record into a timeline entry. A record whose content does
   *  not have the expected shape (a damaged or altered line) is listed without a summary
   *  rather than taking the whole timeline down. */
  function describeRecord(rec) {
    try {
      return describeRecordData(rec);
    } catch (_) {
      return { tone: 'warning', title: humanize(rec.type) + ' (content not in the expected form — see the raw record)' };
    }
  }

  function describeRecordData(rec) {
    const b = rec.body || {};
    const d = b.data || {};
    switch (rec.type) {
      case 'incident_open':
        return { tone: stateInfo(d.state).tone, title: 'Incident opened — ' + headline(d), detail: d.summary };
      case 'incident_update':
        return { tone: 'info', title: 'Incident updated — ' + headline(d), detail: d.summary };
      case 'incident_close':
        return { tone: 'good', title: 'Incident closed after ' + fmtDur(d.duration_s), detail: d.summary };
      case 'state_change':
        return {
          tone: stateInfo(d.to_state).tone,
          title: `State ${stateInfo(d.from_state).label} → ${stateInfo(d.to_state).label}` + (d.to_cause ? ' (' + causeText(d.to_cause) + ')' : ''),
          detail: (d.reasons || []).join(' · '),
        };
      case 'sample': {
        const pr = d.probes || [];
        const inet = pr.filter((p) => p.role === 'internet');
        const gw = pr.filter((p) => p.role === 'gateway');
        return {
          tone: stateInfo(d.verdict && d.verdict.state).tone,
          title: `Measurement cycle #${orQ(d.cycle)}: ${stateInfo(d.verdict && d.verdict.state).label}`,
          detail: `${inet.filter((p) => p.ok).length} of ${inet.length} internet probes answered; gateway ${gw.some((p) => p.ok) ? 'reachable' : 'not reachable'}.`,
          inputs: d.verdict && d.verdict.inputs ? verdictInputs(d.verdict.inputs) : null,
        };
      }
      case 'gateway_snapshot': {
        const dv = d.derived || {};
        const bb = d.broadband || {};
        const pages = Array.isArray(d.pages) ? d.pages : [];
        const parts = [];
        if (bb.connection) parts.push('Broadband ' + bb.connection);
        if (bb.pon_link_status) parts.push('PON ' + bb.pon_link_status);
        if (dv.rx_power_x10 != null) parts.push('Rx ' + (dv.rx_power_x10 / 10).toFixed(1) + ' dBm');
        if (dv.alarms && dv.alarms.length) parts.push('gateway alarms: ' + dv.alarms.join(', '));
        if (dv.gateway_clock_blank) parts.push('gateway clock blank');
        for (const p of pages) if (p && p.err && !p.not_attempted) parts.push(orQ(p.page) + ': ' + p.err);
        const skipped = pages.filter((p) => p && p.not_attempted).length;
        if (skipped) parts.push(`${skipped} page${skipped === 1 ? '' : 's'} not attempted (the gateway could not be reached)`);
        const links = [];
        for (const p of d.pages || []) {
          if (p.stored && HEX64.test(p.sha256 || '')) {
            links.push(h('a', { href: '/api/blobs/' + p.sha256 + '/view', target: '_blank', rel: 'noopener noreferrer' }, 'view ' + p.page + ' page'));
          }
        }
        return { tone: dv.reachable === false ? 'warning' : 'info', title: 'Gateway status captured (' + (d.trigger || 'periodic') + ')', detail: parts.join(' · '), links };
      }
      case 'gateway_event':
        return {
          tone: d.kind === 'optical_alarm' ? 'critical' : 'info',
          title: 'Gateway event: ' + humanize(d.kind),
          detail: [d.before || d.after ? `${d.before || '—'} → ${d.after || '—'}` : '', d.detail].filter(Boolean).join(' · '),
        };
      case 'service_check': {
        // A query and its retry (rules 2026.10-4) are worded together.
        const dns = dnsQueries(d.dns).map((q) => {
          const v = dnsQueryVerdict(q);
          const r = v.r;
          return dnsCheckName(r) + (v.test ? ' (' + r.name + ')' : '') + ': ' + v.text + (r.truncated ? ' (truncated)' : '') +
            (Array.isArray(r.answers) && r.answers.length ? ' ' + r.answers.join(', ') : '');
        });
        const web = (d.http || []).map((r) => `${HTTP_CHECK_NAMES[r.name] || r.name}: ${r.hijacked ? 'HIJACKED' : r.ok ? 'OK' : r.status ? 'HTTP ' + r.status : 'failed'}` +
          (r.hijacked && r.hijack_why ? ' (' + r.hijack_why + ')' : '') + (r.err ? ' — ' + r.err : '') +
          (r.tls_cert_sha256 ? ' · TLS certificate ' + shortHash(r.tls_cert_sha256, 12) : ''));
        const bad = (d.dns || []).concat(d.http || []).some((r) => r.hijacked);
        return { tone: bad ? 'critical' : 'info', title: 'DNS and web checks', detail: dns.concat(web).join(' · ') };
      }
      case 'traceroute': {
        const hops = (d.hops || []).map((hp) => `${hp.ttl}: ${hp.addr || '*'}${hp.rtt_us ? ' ' + fmtRTT(hp.rtt_us) : ''}` +
          (hp.status && hp.status !== 'IP_SUCCESS' && hp.status !== 'IP_TTL_EXPIRED_TRANSIT' ? ' (' + (ICMP_STATUS[hp.status] || humanize(hp.status)) + ')' : ''));
        if (d.err) {
          return { tone: 'warning', title: `Traceroute to ${orQ(d.target)} could not run`, detail: [d.err].concat(hops).join(' · ') };
        }
        return { tone: d.reached ? 'good' : 'warning', title: `Traceroute to ${orQ(d.target)}: ${d.reached ? 'reached' : 'not reached'} (${(d.hops || []).length} hops)`, detail: hops.join(' · ') };
      }
      case 'local_link': {
        const bypass = !!(d.egress && typeof d.egress === 'object' && d.egress.bypass && !d.egress.err);
        return {
          tone: !/^connected$/i.test(d.state || '') ? 'serious' : bypass ? 'warning' : 'info',
          title: 'This PC’s link: ' + (d.state || '?') + (bypass ? ' — traffic not through the AT&T gateway' : ''),
          detail: [d.interface, d.ssid, d.signal_pct ? d.signal_pct + ' % signal' : '', d.rssi_dbm ? d.rssi_dbm + ' dBm' : '', d.err, egressSummary(d.egress)].filter(Boolean).join(' · '),
        };
      }
      case 'anchor':
        // Only a token whose authority chains to a trusted root counts as proof of time.
        return {
          tone: d.verified && d.chain_ok !== false ? 'good' : 'warning',
          title: 'Time-stamped by ' + tsaName(d.tsa_url) + ' (' + (d.reason || 'anchor') + ')',
          detail: `TSA time ${orQ(d.gen_time)} · covers records up to #${orQ(d.head_seq)}` +
            (d.chain_ok === false ? ' · the authority’s certificate did not chain to a trusted root' + (d.chain_note ? ': ' + d.chain_note : '') : ''),
          links: blobLinks(d.token_sha256, { downloadText: 'download time-stamp token' }),
        };
      case 'operator_note':
        return { tone: 'info', title: 'Operator note' + (d.author ? ' by ' + d.author : ''), detail: d.text };
      case 'config_change':
        return { tone: 'info', title: 'Configuration change: ' + orQ(d.what || d.target), detail: `${orQ(d.before)} → ${orQ(d.after)} · ${orQ(d.actor)} · ${orQ(d.result)}` };
      case 'power_event':
        return { tone: 'warning', title: 'Power event: ' + humanize(d.kind) };
      case 'monitor_start': {
        // The effective configuration (secrets removed) is recorded with every start, so the
        // thresholds in force can be quoted from the evidence.
        const parts = [];
        // A negative gap: this computer's clock was behind the previous record's time.
        if (d.gap_seconds > 0) parts.push('Gap since the previous record: ' + fmtDur(d.gap_seconds));
        else if (d.gap_seconds < 0) parts.push('This computer’s clock was ' + fmtDur(-d.gap_seconds) + ' behind the previous record’s time');
        if (d.software && d.software.rules) parts.push('rules ' + d.software.rules);
        return { tone: 'info', title: 'Monitor started' + (d.mode ? ' (' + d.mode + ')' : ''), detail: parts.concat(configSummary(d.config)).join(' · ') };
      }
      case 'config_state': {
        // Recorded right after each segment_open, so every daily segment (and every bundle)
        // states the thresholds in force.
        const parts = d.rules ? ['rules ' + d.rules] : [];
        if (d.config_sha256) parts.push('configuration SHA-256 ' + shortHash(d.config_sha256, 16));
        return {
          tone: 'info',
          title: 'Configuration in force' + (d.reason === 'new_segment' ? ' (recorded at the start of the day’s segment)' : d.reason ? ' (' + d.reason + ')' : ''),
          detail: parts.concat(configSummary(d.config)).join(' · '),
        };
      }
      case 'monitor_stop':
        return { tone: 'warning', title: 'Monitor stopped (' + (d.reason || '?') + ')' };
      case 'syslog': {
        // A batch of the gateway's syslog messages; a message's text is the sender's, so its
        // hidden characters are written as escapes.
        const msgs = Array.isArray(d.messages) ? d.messages.filter((m) => m && typeof m === 'object') : [];
        const parts = msgs.slice(0, 3).map((m) => escapedText(String(m.msg || m.raw || (m.raw_b64 ? '(not valid UTF-8)' : '')).slice(0, 160)));
        if (msgs.length > 3) parts.push(`and ${fmtInt(msgs.length - 3)} more`);
        if (d.dropped > 0) parts.push(`${fmtInt(d.dropped)} more over the per-minute cap (counted, not recorded)`);
        if (d.rejected > 0) parts.push(`${fmtInt(d.rejected)} datagram${d.rejected === 1 ? '' : 's'} from other senders (counted, not recorded)`);
        return { tone: 'info', title: `Gateway syslog: ${fmtInt(msgs.length)} message${msgs.length === 1 ? '' : 's'} received`, detail: parts.join(' · ') };
      }
      default:
        return { tone: 'info', title: humanize(rec.type) };
    }
  }

  // ------------------------------------------------------------------ gateway view

  function renderGateway(c, ctx) {
    c.append(h('div', { class: 'view-head' }, h('h1', null, 'AT&T gateway'),
      h('p', { class: 'muted' }, 'Everything parsed from the gateway’s own status pages (read without logging in). Raw pages are kept byte-exact as evidence.')));
    const stateArea = h('div');
    const result = h('div', { 'aria-live': 'polite' });
    const notif = h('section', { class: 'card', 'aria-labelledby': 'notif-h' },
      h('div', { class: 'card-head' }, h('h2', { id: 'notif-h' }, 'Outage redirect (Broadband Status Notification)')),
      h('p', { class: 'muted' }, 'When this gateway setting is on, the gateway redirects web browsing to AT&T instructional pages while the internet connection is down. att-monitor keeps it off so outages are observed as they are.'),
      stateArea, result);
    const details = h('div', { class: 'stack' });
    const alerts = h('div', { class: 'conditions' });
    const cert = h('section', { class: 'card', 'aria-labelledby': 'cert-h' });
    c.append(alerts, notif, cert, details);
    let lastKey = null;
    let certKey = null;
    const update = (st) => {
      fillAlerts(alerts, st, GATEWAY_ALERTS);
      const ck = JSON.stringify([certState(st), certPending(st)]);
      if (ck !== certKey) {
        certKey = ck;
        fillCertCard(cert, st);
      }
      const key = (st.gateway_at || '') + '|' + JSON.stringify(st.notification || null) + '|' + gatewayAuthBlock(st) + '|' + ck;
      if (key === lastKey) return;
      lastKey = key;
      fillNotification(stateArea, result, st);
      // Re-rendering must not collapse sections the reader opened.
      const open = new Set([...details.querySelectorAll('details[open] > summary')].map((x) => x.closest('section').querySelector('h2').textContent + '|' + x.textContent.replace(/\(\d+.*$/, '')));
      fillGatewayDetails(details, st);
      for (const sm of details.querySelectorAll('details > summary')) {
        if (open.has(sm.closest('section').querySelector('h2').textContent + '|' + sm.textContent.replace(/\(\d+.*$/, ''))) sm.parentElement.open = true;
      }
    };
    ctx.onStatus = update;
    if (app.status) update(app.status);
    else details.append(h('p', { class: 'loading' }, 'Loading…'));
  }

  /** gatewayAuthBlock says why authenticated gateway actions cannot run now ('' = they can). */
  function gatewayAuthBlock(st) {
    if (certPending(st)) return 'cert';
    if (findCondition(st, 'NO_ACCESS_CODE')) return 'code';
    return '';
  }

  /** fpText shows a fingerprint grouped in fours, or, if it is not a SHA-256, as given. */
  function fpText(v) {
    const fp = normFp(v);
    return fp ? h('span', { class: 'fp' }, groupFingerprint(fp)) : h('span', { class: 'hash' }, String(v));
  }

  /** fillCertCard shows the gateway TLS certificate pin as the monitor applies it
   *  (Status.gateway_cert): always the pinned fingerprint and, while a changed certificate
   *  waits for confirmation, that one too. The monitor leaves gateway_cert out while nothing
   *  is pinned or pending. */
  function fillCertCard(el, st) {
    const gc = certState(st);
    const head = h('div', { class: 'card-head' }, h('h2', { id: 'cert-h' }, 'Gateway TLS certificate'));
    const intro = h('p', { class: 'muted' }, 'att-monitor reads the gateway’s pages over HTTPS and pins the certificate the gateway presents (trust on first use). It logs in only to the pinned certificate, so the access code never reaches another device.');
    if (!gc) {
      replace(el, head, intro, certPending(st)
        ? h('p', null, h('span', { class: 'muted' }, 'This monitor does not report its certificate pin.'), ' A changed certificate waits for confirmation (see above).')
        : kv([['Pinned (trusted)', h('span', { class: 'muted' }, 'none reported — the first certificate the gateway presents is pinned')]]));
      return;
    }
    const seq = Number(gc.seq) || 0;
    const rows = [['Pinned (trusted)', gc.pinned ? fpText(gc.pinned)
      : h('span', { class: 'muted' }, 'none yet — the first certificate the gateway presents is pinned')]];
    if (gc.pending) {
      rows.push(
        ['Presented now', [chip('critical', 'waiting for confirmation'), ' ', fpText(gc.pending)]],
        ['First presented', gc.since ? timeEl(gc.since) : null],
        ['Evidence', seq ? h('a', { href: recordsLink(seq) }, 'record #' + seq) : null]);
    } else {
      rows.push(['Changed certificate', chip('good', 'none waiting for confirmation')]);
    }
    replace(el, head, intro, kv(rows),
      gc.pending ? h('p', { class: 'small' }, 'Authenticated actions are paused. Review the new fingerprint in the banner above and trust it only if AT&T updated or replaced your gateway.') : null);
  }

  /** pinNote says whether a certificate a page was fetched with is the pinned one. */
  function pinNote(fp, st) {
    const gc = certState(st);
    const pinned = gc ? normFp(gc.pinned) : '';
    if (!pinned || !normFp(fp)) return null;
    return normFp(fp) === pinned ? ' (the pinned certificate)' : h('span', null, ' ', chip('warning', 'not the pinned certificate'));
  }

  function fillNotification(area, result, st) {
    const n = st.notification;
    const enabled = n ? !!n.enabled : null;
    const block = gatewayAuthBlock(st);
    const stateLine = enabled == null
      ? h('p', null, chip('none', 'unknown'), ' Not checked yet (reading it requires a gateway login, which att-monitor does rarely).')
      : enabled
        ? h('p', null, chip('warning', 'ON'), ' The gateway will hijack web browsing during an outage.')
        : h('p', null, chip('good', 'OFF'), ' Browsers are not redirected during outages.');
    const meta = n ? h('p', { class: 'small muted' }, 'Checked ', timeEl(n.checked_at), n.seq ? [' · ', h('a', { href: recordsLink(n.seq) }, 'record #' + n.seq)] : null, n.err ? ' · last error: ' + n.err : '') : null;
    const blockLine = block === 'cert'
      ? h('p', null, chip('critical', 'paused'), ' The gateway presented an unconfirmed TLS certificate, so att-monitor will not log in to it until the certificate is confirmed (see above).')
      : block === 'code'
        ? h('p', null, chip('none', 'no access code'), ' No usable gateway access code is stored, so this setting can be neither read nor changed (att-monitor set-access-code).')
        : null;
    const btns = h('div', { class: 'btn-row' });
    if (enabled !== false) {
      const off = h('button', { type: 'button', class: 'btn btn-primary', disabled: !!block }, 'Turn redirect off');
      off.addEventListener('click', () => setNotification(false, off, result));
      btns.append(off);
    }
    if (enabled !== true) {
      const on = h('button', { type: 'button', class: 'btn', disabled: !!block }, 'Turn redirect on');
      on.addEventListener('click', () => setNotification(true, on, result));
      btns.append(on);
    }
    replace(area, stateLine, meta, blockLine, btns);
  }

  async function setNotification(enabled, btn, out) {
    const ok = await dialog({
      title: enabled ? 'Turn the outage redirect ON?' : 'Turn the outage redirect OFF?',
      body: [
        h('p', null, 'att-monitor will log in to the AT&T gateway with the stored access code and ' + (enabled ? 'tick' : 'untick') + ' “Broadband Status Notification” (Diagnostics › Event Notifications).'),
        h('p', null, 'The page before and after the change is stored as evidence and the change is written to the ledger as a config_change record.'),
        enabled ? h('p', null, h('strong', null, 'When ON, the gateway redirects web browsing to AT&T pages while the internet is down.')) : null,
      ],
      confirm: enabled ? 'Turn redirect on' : 'Turn redirect off',
    });
    if (!ok) return;
    btn.disabled = true;
    replace(out, notice('info', spinner(), ' Talking to the gateway…'));
    try {
      const cc = await api('/api/gateway/notification', { method: 'POST', body: { enabled } });
      replace(out, notice('good', `Done — ${cc.what || 'setting'}: ${cc.before || '?'} → ${cc.after || '?'} (${cc.result || 'applied'}).`));
      announce('Gateway setting changed.');
      refreshStatus();
    } catch (e) {
      // Do not claim "not changed": a failure can come after the gateway took the change
      // (e.g. reading its page afterwards timed out, or recording the change failed).
      const ch = e.data && e.data.change;
      const result = ch && ch.result ? String(ch.result) : '';
      if (result && !/^\s*failed/i.test(result)) {
        replace(out, notice('warning', e.message.charAt(0).toUpperCase() + e.message.slice(1)));
      } else {
        replace(out, notice('critical', 'The change could not be completed or confirmed: ' + e.message, result ? ' (recorded result: ' + result + ')' : ''));
      }
      refreshStatus();
    } finally {
      btn.disabled = false;
    }
  }

  function valuesTable(values, caption) {
    const keys = Object.keys(values || {});
    if (!keys.length) return null;
    const rows = keys.map((k) => {
      const i = k.indexOf('/');
      return i > 0 ? [k.slice(0, i), k.slice(i + 1), values[k]] : ['', k, values[k]];
    });
    return h('details', null, h('summary', null, caption + ` (${keys.length} values)`),
      table([{ label: 'Section' }, { label: 'Field' }, { label: 'Value', cls: 'wrap' }], rows, { compact: true }));
  }

  function thresholdCell(t, unit, tone) {
    if (!t) return '—';
    const val = t.threshold != null ? fmtMeasure(t.threshold, unit) : (t.raw || '—');
    return h('span', { title: 'Gateway cell: ' + (t.raw || '') }, val, ' ', t.active ? chip(tone, 'ACTIVE') : h('span', { class: 'small muted' }, 'off'));
  }

  function fillGatewayDetails(el, st) {
    const g = st.gateway;
    if (!g) {
      replace(el, card('Status pages', emptyNote('No gateway snapshot yet.')));
      return;
    }
    const d = g.derived || {};
    const sys = g.system || {};
    const bb = g.broadband || {};
    const fb = g.fiber;
    const yesNo = (v) => (v == null ? null : v ? 'yes' : 'no');

    const derived = card('Summary (derived from the pages)',
      kv([
        ['Status pages reachable', d.reachable ? chip('good', 'yes') : chip('critical', 'no')],
        ['Broadband up', yesNo(d.broadband_up)],
        ['Fiber (PON) operational', yesNo(d.pon_operational)],
        ['Optical WAN up', yesNo(d.optical_up)],
        ['WAN IPv4', d.wan_ipv4],
        ['AT&T next hop', d.isp_next_hop],
        ['AT&T DNS', d.isp_dns],
        ['Rx / Tx power', d.rx_power_x10 != null || d.tx_power_x10 != null ? `${d.rx_power_x10 != null ? (d.rx_power_x10 / 10).toFixed(1) : '—'} / ${d.tx_power_x10 != null ? (d.tx_power_x10 / 10).toFixed(1) : '—'} dBm` : null],
        ['Gateway alarm flags', d.alarms && d.alarms.length ? h('span', { class: 'chips' }, d.alarms.map((a) => chip(/ALARM/.test(a) ? 'critical' : 'warning', a))) : 'none'],
        ['Uptime', d.uptime_s >= 0 ? fmtDur(d.uptime_s) : 'unknown'],
        ['Boot time (estimated)', d.boot_time_estimate ? timeEl(d.boot_time_estimate) : null],
        ['Gateway clock', d.gateway_clock_blank ? 'blank (WAN down indicator)' : d.gateway_clock_offset_ms != null ? `offset ${(d.gateway_clock_offset_ms / 1000).toFixed(1)} s vs this PC` : null],
        ['Model / firmware / serial', [d.model, d.firmware, d.serial].filter(Boolean).join(' / ')],
      ]),
      h('p', { class: 'card-foot' }, 'Snapshot ', timeEl(st.gateway_at), ' · trigger ', g.trigger || '—'));

    const system = card('System information (sysinfo)',
      kv([
        ['Manufacturer', sys.manufacturer], ['Model', sys.model], ['Serial number', sys.serial],
        ['Software version', sys.software_version], ['Hardware version', sys.hardware_version],
        ['MAC address', sys.wan_mac], ['First use', sys.first_use_date],
        ['Time since reboot', sys.uptime_raw ? [sys.uptime_raw, sys.uptime_s >= 0 ? ' (' + fmtDur(sys.uptime_s) + ')' : ''] : null],
        ['Gateway date/time', sys.gateway_time_raw ? sys.gateway_time_raw + ' (gateway local time, no zone)'
          : sys.gateway_time_present || d.gateway_clock_blank ? 'blank — the gateway shows no time while its WAN is down'
            : g.system ? 'no “Current Date/Time” row on the page' : null],
      ]));

    const broadband = card('Broadband (broadbandstatistics)',
      kv([
        ['Connection source', bb.connection_source], ['Connection', bb.connection], ['Network type', bb.network_type],
        ['IPv4 address', bb.ipv4], ['Gateway (next hop)', bb.gateway_ipv4],
        ['DNS', [bb.primary_dns, bb.secondary_dns].filter(Boolean).join(', ')], ['MTU', bb.mtu],
        ['Ethernet line', [bb.line_state, bb.speed_mbps ? bb.speed_mbps + ' Mbps' : '', bb.duplex].filter(Boolean).join(' · ')],
        ['IPv6', [bb.ipv6_status, bb.ipv6_global].filter(Boolean).join(' · ')], ['IPv6 gateway', bb.ipv6_gateway],
        ['PON link status', bb.pon_link_status], ['UNI status', bb.uni_status],
      ]),
      bb.counters && Object.keys(bb.counters).length
        ? h('details', null, h('summary', null, `Traffic counters (${Object.keys(bb.counters).length})`),
          table([{ label: 'Counter' }, { label: 'Value', num: true }], Object.keys(bb.counters).map((k) => [k, fmtInt(bb.counters[k])]), { compact: true }))
        : null,
      valuesTable(bb.values, 'All fields as shown by the gateway'));

    let fiber = null;
    if (fb) {
      const ms = fb.measures || [];
      fiber = card('Fiber (fiberstat)',
        kv([
          ['Optical WAN status', fb.optical_status], ['Fiber module', fb.fiber_module], ['Link state', fb.link_state],
          ['Last change', lastChangeText(fb)], ['Rx LOS state', fb.rx_los_state], ['OPT LOS', fb.opt_los], ['Tx fault', fb.tx_fault_state],
          ['Vendor', [fb.vendor_name, fb.vendor_pn, fb.vendor_sn].filter(Boolean).join(' · ')], ['Wavelength', fb.wave_length],
        ]),
        ms.length ? h('h3', { class: 'subhead' }, 'Diagnostics (DMI) with the gateway’s own thresholds and flags') : null,
        ms.length ? table(
          [{ label: 'Measure' }, { label: 'Current', num: true }, { label: 'Low alarm' }, { label: 'Low warning' }, { label: 'High warning' }, { label: 'High alarm' }],
          ms.map((m) => [m.name, measureValue(m),
            thresholdCell(m.low_alarm, m.unit, 'critical'), thresholdCell(m.low_warning, m.unit, 'warning'),
            thresholdCell(m.high_warning, m.unit, 'warning'), thresholdCell(m.high_alarm, m.unit, 'critical')]),
          { compact: true, caption: 'Power in dBm (the gateway reports 0.1 dBm units); “ACTIVE” = the gateway’s flag bit is 1.' }) : null,
        valuesTable(fb.values, 'All fields as shown by the gateway'));
    }

    const lan = g.lan && g.lan.values && Object.keys(g.lan.values).length ? card('LAN statistics (lanstatistics)', valuesTable(g.lan.values, 'All fields')) : null;

    const pageRows = (g.pages || []).map((p) => [
      p.page,
      p.not_attempted ? chip('none', 'not attempted', p.err || 'Skipped: the gateway could not be reached at all.')
        : p.err ? chip('critical', 'error', p.err) : p.login_page ? chip('warning', 'login page') : String(p.status || '—'),
      timeEl(p.fetched_at, F.time),
      fmtInt(p.dur_ms) + ' ms',
      fmtBytes(p.bytes),
      p.sha256 ? h('span', { class: 'hash', title: p.sha256 }, shortHash(p.sha256, 16)) : '—',
      p.stored && HEX64.test(p.sha256 || '') ? h('span', { class: 'tl-links' }, blobLinks(p.sha256, { view: true, viewText: 'view (sandboxed)', downloadText: 'download' })) : h('span', { class: 'small muted' }, 'hash recorded, page not stored this time'),
    ]);
    const tls = (g.pages || []).find((p) => p && p.tls_cert_sha256);
    const pages = card('Page captures in this snapshot',
      h('p', { class: 'small muted' }, 'Every fetched page is hashed; the raw bytes are stored when something material changed, during incidents and at least every 5 minutes. TLS certificate: ',
        tls ? [h('span', { class: 'hash', title: tls.tls_cert_sha256 }, shortHash(tls.tls_cert_sha256, 16)), pinNote(tls.tls_cert_sha256, st)] : 'n/a'),
      pageRows.length ? table([{ label: 'Page' }, { label: 'HTTP' }, { label: 'Fetched' }, { label: 'Took', num: true }, { label: 'Size', num: true }, { label: 'SHA-256' }, { label: 'Raw page' }], pageRows, { compact: true }) : emptyNote('No pages.'));

    replace(el, h('div', { class: 'grid-2' }, derived, system), fiber, broadband, lan, pages);
  }

  // ------------------------------------------------------------------ syslog view

  function renderSyslog(c, q, ctx) {
    c.append(h('div', { class: 'view-head' }, h('h1', null, 'Gateway syslog'),
      h('p', { class: 'muted' }, 'The AT&T gateway’s own log messages as this PC received them, recorded in the evidence ledger in signed batches. Every message keeps the exact datagram; its time is when this PC received it.')));
    const statusArea = h('div');
    let statusKey = null;
    const update = (st) => {
      const key = JSON.stringify([st.syslog || null, st.local_link ? st.local_link.local_ip : null]);
      if (key === statusKey) return;
      statusKey = key;
      replace(statusArea, syslogCard(st, false) ||
        callout('info', 'This monitor reports no syslog receiver: the messages below are the ones recorded in the evidence ledger.'));
    };
    ctx.onStatus = update;
    if (app.status) update(app.status);

    let range = RANGE_MS[q.get('range')] ? q.get('range') : '24h';
    const sev = h('select', null, h('option', { value: '' }, 'All messages'),
      SYSLOG_SEVERITIES.map((sv, i) => h('option', { value: sv.name }, `${sv.label} (${i})${i ? ' and more severe' : ' only'}`)));
    sev.value = SYSLOG_SEVERITIES.some((sv) => sv.name === q.get('severity')) ? q.get('severity') : '';
    const text = h('input', { type: 'search', maxlength: '200', autocomplete: 'off', spellcheck: 'false', placeholder: 'message, host or app' });
    text.value = (q.get('q') || '').slice(0, 200);
    const period = rangeControl(range, (r) => { range = r; load(); }, 'Period').querySelector('.seg');
    const search = field('Search', text);
    search.classList.add('grow');
    const form = h('form', { class: 'card filters', role: 'search', 'aria-label': 'Syslog filters' },
      h('div', { class: 'field' }, h('span', { class: 'label', 'aria-hidden': 'true' }, 'Period'), period),
      field('Severity', sev), search,
      h('button', { type: 'submit', class: 'btn' }, 'Refresh'));
    const out = h('section', { class: 'card', 'aria-labelledby': 'syslog-list-h' });
    c.append(statusArea, form, out);
    const browser = syslogBrowser(out, ctx, {
      heading: 'Messages', headingId: 'syslog-list-h',
      empty: () => (sev.value || text.value.trim() ? 'No syslog message received in this period matches the filters.' : 'No syslog messages were received in this period.'),
    });

    function load() {
      const params = new URLSearchParams();
      if (range !== '24h') params.set('range', range);
      if (sev.value) params.set('severity', sev.value);
      if (text.value.trim()) params.set('q', text.value.trim());
      // keep the URL shareable without re-triggering the router
      const hash = '#/syslog' + (params.toString() ? '?' + params.toString() : '');
      if (window.location.hash !== hash) window.history.replaceState(null, '', hash);
      const to = Date.now();
      browser.load({ from: new Date(to - RANGE_MS[range]).toISOString(), to: new Date(to).toISOString(), q: text.value.trim(), severity: sev.value });
    }
    let timer = 0;
    text.addEventListener('input', () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(load, 350);
    });
    ctx.cleanup(() => window.clearTimeout(timer));
    sev.addEventListener('change', load);
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      window.clearTimeout(timer);
      load();
    });
    load();
  }

  /** syslogBrowser shows in el the messages GET /api/syslog returns for a period and filters,
   *  newest first, with "Load more" while more matched: that asks again for the same period with
   *  a larger limit and appends what is new. o: heading, headingId, intro (optional), empty()
   *  (the text when nothing matched). Returns { load(query) }, query: {from, to, q, severity}
   *  (to may be left out: until now). */
  function syslogBrowser(el, ctx, o) {
    const status = h('p', { class: 'small muted', 'aria-live': 'polite', tabindex: '-1' });
    const warn = h('div');
    const list = h('div', { class: 'syslog-list' }, h('p', { class: 'loading' }, 'Loading…'));
    const more = h('button', { type: 'button', class: 'btn', hidden: true }, 'Load more');
    replace(el, h('div', { class: 'card-head' }, h('h2', { id: o.headingId }, o.heading)), o.intro || null, status, warn, list,
      h('div', { class: 'btn-row' }, more));
    const cols = [{ label: 'Received' }, { label: 'Severity' }, { label: 'Host · app', cls: 'syslog-host' }, { label: 'Message', cls: 'syslog-msg' }];
    let token = 0;
    let busy = false; // a request is out ("Load more" stays enabled, so that it keeps the focus)
    let abort = null; // cancels the request out: a newer one replaces it
    let cur = null; // the query shown, with the period the server read
    let tbody = null;
    let shown = [];
    ctx.cleanup(() => { if (abort) abort.abort(); });

    async function fetchList(query, append) {
      const mine = ++token;
      if (abort) abort.abort();
      abort = typeof AbortController === 'function' ? new AbortController() : null;
      const params = new URLSearchParams({ from: query.from, limit: String(query.limit) });
      if (query.to) params.set('to', query.to);
      if (query.q) params.set('q', query.q);
      if (query.severity) params.set('severity', query.severity);
      busy = true;
      list.classList.add('is-loading');
      list.setAttribute('aria-busy', 'true');
      more.setAttribute('aria-disabled', 'true');
      try {
        const { data, headers } = await api('/api/syslog?' + params.toString(), { withHeaders: true, signal: abort ? abort.signal : null });
        if (!ctx.alive || mine !== token) return;
        const msgs = Array.isArray(data && data.messages) ? data.messages.filter((m) => m && typeof m === 'object') : [];
        cur = Object.assign({}, query, { from: (data && data.from) || query.from, to: (data && data.to) || query.to });
        const w = headers.get('X-ATT-Monitor-Warning');
        replace(warn, w ? notice('critical', h('strong', null, 'Integrity problem in the syslog records read. '), w, ' ', h('a', { href: '#/evidence' }, 'Run Verify')) : null);
        // A larger page of the same period starts with the messages shown already.
        const keyOf = (m) => m.seq + '|' + m.rx + '|' + (m.raw || m.raw_b64 || m.msg || '');
        const grows = append && tbody && shown.length <= msgs.length && shown.every((k, i) => k === keyOf(msgs[i]));
        if (grows) {
          for (const m of msgs.slice(shown.length)) tbody.append(tableRow(cols, syslogRow(m), { stack: true }));
        } else if (msgs.length) {
          const tbl = table(cols, msgs.map(syslogRow), { compact: true, stack: true });
          tbody = tbl.querySelector('tbody');
          replace(list, tbl);
        } else {
          tbody = null;
          replace(list, emptyNote(o.empty()));
        }
        shown = msgs.map(keyOf);
        const period = [timeEl(cur.from, F.short), ' to ', timeEl(cur.to, F.short)];
        const n = fmtInt(msgs.length) + ' message' + (msgs.length === 1 ? '' : 's');
        replace(status, !msgs.length ? null
          : !data.truncated ? [n + ' recorded from ', period, ', newest first.']
            : query.limit < SYSLOG_MAX ? ['The newest ' + n + ' recorded from ', period, '; more were recorded in this period.']
              : ['The newest ' + n + ' recorded from ', period, '. Narrow the period or the filters to see older ones.']);
        more.hidden = !data.truncated || query.limit >= SYSLOG_MAX;
        if (append && more.hidden) status.focus(); // the button the keyboard was on is gone
      } catch (e) {
        if (ctx.alive && mine === token) {
          if (append && tbody) {
            replace(warn, errorNotice(e)); // keep what is shown: Load more can be tried again
          } else {
            tbody = null;
            shown = [];
            more.hidden = true;
            replace(status);
            replace(list, errorNotice(e));
          }
        }
      } finally {
        if (mine === token) {
          busy = false;
          list.classList.remove('is-loading');
          list.removeAttribute('aria-busy');
          more.removeAttribute('aria-disabled');
        }
      }
    }
    more.addEventListener('click', () => {
      if (cur && !busy) fetchList(Object.assign({}, cur, { limit: Math.min(SYSLOG_MAX, cur.limit * 2) }), true);
    });
    return { load(query) { fetchList(Object.assign({ limit: SYSLOG_PAGE }, query), false); } };
  }

  /** syslogSeverity describes a severity number (SYSLOG_SEVERITIES), or null. */
  function syslogSeverity(n) {
    return Number.isInteger(n) && n >= 0 && n < SYSLOG_SEVERITIES.length ? SYSLOG_SEVERITIES[n] : null;
  }

  /** syslogRow is the table row of a message (GET /api/syslog): when, how severe, from which
   *  host and program, and what it says, with the exact datagram on request. Every cell holds
   *  one element (the stacked rows of a narrow screen lay out a cell's children as a grid). */
  function syslogRow(m) {
    const sv = syslogSeverity(m.severity);
    const text = m.msg || m.raw || '';
    return [
      h('span', { class: 'nowrap' }, timeEl(m.rx, F.sec)),
      h('span', null, sv ? chip(sv.tone, sv.label, 'Severity ' + m.severity + ' (' + sv.name + ')')
        : h('span', { class: 'muted', title: 'The message carries no severity' }, '—')),
      h('div', null, m.host ? h('span', { class: 'wrap-any' }, visibleText(m.host)) : h('span', { class: 'muted' }, '—'),
        m.app ? h('span', { class: 'sub small muted wrap-any' }, visibleText(m.app)) : null),
      h('div', null, text ? h('span', { class: 'syslog-text' }, visibleText(text))
        : h('span', { class: 'muted' }, m.raw_b64 ? 'not valid UTF-8: see the exact bytes' : '(empty)'),
      syslogDetails(m)),
    ];
  }

  /** syslogDetails offers a message's exact datagram, its parsed header and its ledger record. */
  function syslogDetails(m) {
    const det = h('details', { class: 'syslog-raw' }, h('summary', null, 'Exact datagram · record #' + orQ(m.seq)));
    let filled = false;
    det.addEventListener('toggle', () => {
      if (!det.open || filled) return;
      filled = true;
      det.append(syslogFacts(m));
    });
    return det;
  }

  function syslogFacts(m) {
    const sv = syslogSeverity(m.severity);
    const fac = Number.isInteger(m.facility) ? m.facility : null;
    const raw = typeof m.raw === 'string' && m.raw !== '' ? m.raw : null;
    const escaped = raw != null && escapedText(raw) !== raw;
    return h('div', { class: 'syslog-facts' }, kv([
      ['Datagram', raw != null ? [h('pre', { class: 'json wrap syslog-text' }, visibleText(raw)),
        escaped ? h('span', { class: 'sub small muted' }, 'Characters that would not show as themselves are written as escapes (\\x1b, \\n, …).') : null] : null],
      ['Bytes (base64)', m.raw_b64 ? [h('pre', { class: 'json wrap' }, String(m.raw_b64)),
        h('span', { class: 'sub small muted' }, 'Not valid UTF-8: the exact bytes received, base64-encoded.')] : null],
      ['Received', [timeEl(m.rx), m.src ? [' from ', h('code', null, String(m.src))] : null]],
      ['Format', m.format ? SYSLOG_FORMATS[m.format] || String(m.format) : null],
      ['Priority', Number.isInteger(m.pri)
        ? `${m.pri}: facility ${fac == null ? '?' : fac + ' (' + (SYSLOG_FACILITIES[fac] || '?') + ')'}, severity ${sv ? m.severity + ' (' + sv.name + ')' : '?'}`
        : 'none in the datagram'],
      ['Header time', m.ts ? [h('code', null, visibleText(m.ts)), h('span', { class: 'small muted' }, ' as the gateway wrote it')] : null],
      ['Evidence', m.seq != null ? h('a', { href: recordsLink(m.seq) }, 'ledger record #' + m.seq) : null],
    ]));
  }

  // ------------------------------------------------------------------ evidence view

  function renderEvidence(c, ctx) {
    c.append(h('div', { class: 'view-head' }, h('h1', null, 'Evidence & chain of custody'),
      h('p', { class: 'muted' }, 'Every record is SHA-256 hash-chained to the previous one and Ed25519-signed; the chain head is time-stamped by independent RFC 3161 authorities. Verification re-checks all of it.')));
    const alerts = h('div', { class: 'conditions' });
    const integrity = h('section', { class: 'card', 'aria-labelledby': 'integrity-h' });
    const update = (st) => {
      fillAlerts(alerts, st, EVIDENCE_ALERTS);
      fillIntegrity(integrity, st);
    };
    ctx.onStatus = update;
    if (app.status) update(app.status);
    else integrity.append(h('p', { class: 'loading' }, 'Loading…'));
    c.append(alerts, integrity, verifyCard(), h('div', { class: 'grid-2' }, anchorCard(), noteCard()), exportsCard(ctx));
  }

  function fillIntegrity(el, st) {
    const L = st.ledger || {};
    replace(el, 
      h('div', { class: 'card-head' }, h('h2', { id: 'integrity-h' }, 'Ledger')),
      kv([
        ['Head record', ['#' + fmtInt(L.head_seq), L.head_ts ? [' · ', timeEl(L.head_ts)] : null]],
        ['Head hash', L.head_hash ? h('span', { class: 'hash' }, L.head_hash) : null],
        ['Public key fingerprint', L.fingerprint ? h('span', { class: 'fp' }, groupFingerprint(L.fingerprint)) : null],
        ['Ledger created', L.genesis_ts ? timeEl(L.genesis_ts) : null],
        ['Last time-stamp', L.last_anchor_time ? [timeEl(L.last_anchor_time), ' · ', tsaName(L.last_anchor_tsa), ' · covers #' + fmtInt(L.last_anchor_seq)] : 'none yet'],
        ['Records after the last time-stamp', fmtInt(L.unanchored_records)],
        ['Data directory', L.data_dir ? h('code', null, L.data_dir) : null],
        ['Last verification', L.last_verify ? [L.last_verify.ok ? chip('good', 'passed') : chip('critical', 'FAILED'), ' ', timeEl(L.last_verify.at), ` · ${fmtInt(L.last_verify.records)} records · ${fmtInt(L.last_verify.failures)} problems`] : 'not run yet'],
      ]));
  }

  function verifyCard() {
    const out = h('div', { 'aria-live': 'polite' });
    const btn = h('button', { type: 'button', class: 'btn btn-primary' }, 'Verify the whole ledger now');
    btn.addEventListener('click', async () => {
      btn.disabled = true;
      replace(out, notice('info', spinner(), ' Verifying every record, signature, segment, blob and time-stamp… this can take a while.'));
      try {
        const rep = await api('/api/verify', { method: 'POST' });
        replace(out, verifyReportView(rep));
        announce(rep.ok ? 'Verification passed.' : 'Verification found problems.');
        refreshStatus();
      } catch (e) {
        replace(out, errorNotice(e));
      } finally {
        btn.disabled = false;
      }
    });
    return card('Verify', h('p', { class: 'muted' }, 'Recomputes every hash, checks every signature and the chain linkage, segment hashes, blobs and RFC 3161 time-stamp tokens, and lists monitoring gaps.'), btn, out);
  }

  /** scrollBox bounds a long table so that a big report cannot stretch the page. */
  function scrollBox(label, content) {
    return h('div', { class: 'chart-table', tabindex: '0', role: 'region', 'aria-label': label }, content);
  }

  function verifyReportView(rep) {
    const failures = rep.failures || [];
    const parts = [
      rep.ok
        ? notice('good', h('strong', null, 'Verification passed. '), `${fmtInt(rep.records)} records, no integrity problems.`)
        : notice('critical', h('strong', null, 'Verification FAILED. '), `${fmtInt(rep.failures_total || failures.length)} problem(s) found.`),
      kv([
        ['Checked at', timeEl(rep.at)],
        ['Records', fmtInt(rep.records)],
        ['Segments', (rep.segments || []).length ? `${rep.segments.length}: ${rep.segments.join(', ')}` : null],
        ['First / last record', [timeEl(rep.first_ts), ' → ', timeEl(rep.last_ts)]],
        ['Head hash', rep.head_hash ? h('span', { class: 'hash' }, rep.head_hash) : null],
        ['Key fingerprint', rep.fingerprint ? h('span', { class: 'fp' }, groupFingerprint(rep.fingerprint)) : null],
        ['Blobs checked', fmtInt(rep.blobs_checked)],
        ['Time-stamped up to', (rep.anchors || []).some((a) => a.ok) || rep.last_anchored_seq > 0
          ? '#' + fmtInt(rep.last_anchored_seq) + ` (${fmtInt(rep.unanchored_tail)} newer records not yet time-stamped)`
          : `nothing yet — none of the ${fmtInt(rep.records)} records is covered by a valid time-stamp`],
        ['Clock jumps', fmtInt(rep.clock_jumps)],
      ]),
    ];
    if (failures.length) {
      parts.push(h('h3', { class: 'subhead' }, 'Problems'),
        scrollBox('Verification problems', table([{ label: 'Record', num: true }, { label: 'Segment' }, { label: 'Line', num: true }, { label: 'Problem' }, { label: 'Detail', cls: 'wrap' }],
          failures.map((f) => [h('a', { href: recordsLink(f.seq) }, '#' + f.seq), f.segment, fmtInt(f.line),
            h('span', { title: f.problem }, VERIFY_PROBLEMS[f.problem] || humanize(f.problem)), f.detail]), { compact: true })));
      if (rep.failures_total > failures.length) parts.push(h('p', { class: 'small muted' }, `Showing the first ${failures.length} of ${fmtInt(rep.failures_total)} problems.`));
    }
    const anchors = rep.anchors || [];
    parts.push(h('h3', { class: 'subhead' }, `Time-stamps (${anchors.length})`));
    const badAnchors = anchors.filter((a) => !a.ok).length;
    const checked = !!rep.tokens_checked; // the tokens themselves were verified (VerifyReport.tokens_checked)
    if (anchors.length) {
      parts.push(h('p', { class: 'small muted' }, `${fmtInt(anchors.length - badAnchors)} passed, ${fmtInt(badAnchors)} failed; newest first. ` +
        (checked ? 'Each token’s signature and imprint were verified.'
          : 'The tokens themselves were not cryptographically checked in this verification; the chain column shows the trust recorded when each was obtained.')));
    }
    parts.push(anchors.length
      ? scrollBox('Time-stamps', table([{ label: 'Record', num: true }, { label: 'Authority' }, { label: 'TSA time' }, { label: 'Covers', num: true }, { label: 'Token' }, { label: 'Chain' }],
        anchors.slice().reverse().map((a) => [h('a', { href: recordsLink(a.seq) }, '#' + a.seq), tsaName(a.tsa), timeEl(a.gen_time, F.short), '#' + fmtInt(a.head_seq),
          !a.ok ? chip('critical', 'invalid', a.detail) : checked ? chip('good', 'verified') : chip('none', 'not checked', 'Only the anchor record was checked in this verification, not the token’s signature.'),
          a.chain_ok ? chip('good', checked ? 'trusted root' : 'trusted root (as recorded)') : chip('warning', 'not chained', a.detail)]), { compact: true }))
      : emptyNote('No time-stamps yet.'));
    const gaps = rep.gaps || [];
    parts.push(h('h3', { class: 'subhead' }, `Monitoring gaps (${gaps.length})`));
    parts.push(gaps.length
      ? scrollBox('Monitoring gaps', table([{ label: 'From' }, { label: 'To' }, { label: 'Length', num: true }, { label: 'Explanation' }], gaps.map((x) => [timeEl(x.from), timeEl(x.to), fmtDur(x.seconds), x.explanation]), { compact: true }))
      : emptyNote('No gaps: the monitor measured continuously.'));
    const counts = Object.entries(rep.type_counts || {}).sort((a, b) => b[1] - a[1]);
    if (counts.length) {
      parts.push(h('details', null, h('summary', null, 'Records by type'),
        table([{ label: 'Type' }, { label: 'Records', num: true }], counts.map(([k, v]) => [h('span', { class: 'type-tag' }, k), fmtInt(v)]), { compact: true })));
    }
    if (rep.notes && rep.notes.length) parts.push(h('ul', { class: 'small muted' }, rep.notes.map((n) => h('li', null, n))));
    return h('div', { class: 'stack' }, parts);
  }

  function anchorCard() {
    const out = h('div', { 'aria-live': 'polite' });
    const btn = h('button', { type: 'button', class: 'btn' }, 'Time-stamp the ledger head now');
    btn.addEventListener('click', async () => {
      btn.disabled = true;
      replace(out, notice('info', spinner(), ' Asking the time-stamp authorities…'));
      try {
        const { data, headers } = await api('/api/anchor', { method: 'POST', withHeaders: true });
        replace(out, anchorResult(data || [], headers.get('X-ATT-Monitor-Warning')));
        announce('Time-stamp request finished.');
        refreshStatus();
      } catch (e) {
        replace(out, errorNotice(e));
      } finally {
        btn.disabled = false;
      }
    });
    return card('Time-stamp (anchor)',
      h('p', { class: 'muted' }, 'Sends only the SHA-256 of the newest record to independent RFC 3161 time-stamp authorities; their signed answer proves every record up to it existed at that time. Happens automatically every 30 minutes and after incidents.'),
      btn, out);
  }

  /** anchorResult shows the time-stamps obtained and, if some authorities failed, why. */
  function anchorResult(list, warning) {
    return h('div', null,
      list.length ? notice('good', `${list.length} time-stamp${list.length === 1 ? '' : 's'} obtained.`) : null,
      warning ? notice('warning', 'Not every authority answered: ' + warning) : null,
      list.length ? table([{ label: 'Authority' }, { label: 'TSA time' }, { label: 'Covers', num: true }, { label: 'Verified' }],
        list.map((a) => [tsaName(a.tsa_url), timeEl(a.gen_time), '#' + fmtInt(a.head_seq),
          !a.verified ? chip('warning', 'no')
            : a.chain_ok ? chip('good', 'yes, trusted root')
              : [chip('warning', 'yes, root not trusted', a.chain_note || null), a.chain_note ? h('span', { class: 'sub small muted' }, a.chain_note) : null]]), { compact: true }) : null);
  }

  function noteCard() {
    const text = h('textarea', { required: true, maxlength: '4000', placeholder: 'e.g. Called AT&T support, ticket 0123456789; technician visit scheduled for Tuesday.' });
    const author = h('input', { type: 'text', autocomplete: 'name', maxlength: '200' });
    author.value = loadPref('author', '');
    const out = h('div', { 'aria-live': 'polite' });
    const btn = h('button', { type: 'submit', class: 'btn btn-primary' }, 'Add note to the ledger');
    const form = h('form', { class: 'form' },
      field('Note', text, 'Notes are signed and time-stamped like every other record and cannot be edited afterwards.'),
      field('Your name (optional)', author), h('div', { class: 'btn-row' }, btn), out);
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!text.value.trim()) { text.focus(); return; }
      btn.disabled = true;
      try {
        const ref = await api('/api/notes', { method: 'POST', body: { text: text.value.trim(), author: author.value.trim() } });
        savePref('author', author.value.trim());
        text.value = '';
        replace(out, notice('good', 'Recorded as ', h('a', { href: recordsLink(ref.seq) }, 'record #' + ref.seq), ' at ', timeEl(ref.ts), ' (hash ', h('span', { class: 'hash' }, shortHash(ref.hash, 16)), ').'));
        announce('Note recorded.');
      } catch (err) {
        replace(out, errorNotice(err));
      } finally {
        btn.disabled = false;
      }
    });
    return card('Operator note', form);
  }

  function datetimeLocalValue(d) {
    const pad = (n) => String(n).padStart(2, '0');
    return `${localDateValue(d)}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  function exportsCard(ctx) {
    const list = h('div', null, h('p', { class: 'loading' }, 'Loading exports…'));
    const from = h('input', { type: 'datetime-local' });
    const to = h('input', { type: 'datetime-local' });
    from.value = datetimeLocalValue(new Date(Date.now() - 7 * 86400e3));
    to.value = datetimeLocalValue(new Date());
    const incident = h('input', { type: 'text', list: 'incident-ids', placeholder: 'INC-…', autocomplete: 'off', maxlength: '64' });
    const datalist = h('datalist', { id: 'incident-ids' });
    const prepared = h('input', { type: 'text', autocomplete: 'name', maxlength: '200' });
    prepared.value = loadPref('preparedBy', '');
    const notes = h('textarea', { maxlength: '4000' });
    const out = h('div', { 'aria-live': 'polite' });
    const btn = h('button', { type: 'submit', class: 'btn btn-primary' }, 'Build evidence bundle');
    const form = h('form', { class: 'form' },
      h('div', { class: 'form-grid' },
        field('From (local time)', from),
        field('To (local time)', to),
        field('Incident (optional)', incident, 'If set, the bundle covers that incident ± 15 minutes instead.')),
      datalist,
      h('div', { class: 'form-grid' }, field('Prepared by (optional)', prepared), field('Notes (optional)', notes)),
      h('div', { class: 'btn-row' }, btn), out);
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const body = { prepared_by: prepared.value.trim(), notes: notes.value.trim() };
      if (incident.value.trim()) body.incident_id = incident.value.trim();
      else {
        const f = toDate(from.value);
        const t = toDate(to.value);
        if (!f || !t) { replace(out, notice('critical', 'Choose a start and an end time, or an incident.')); return; }
        if (f >= t) { replace(out, notice('critical', 'The start must be before the end.')); return; }
        body.from = f.toISOString();
        body.to = t.toISOString();
      }
      savePref('preparedBy', prepared.value.trim());
      btn.disabled = true;
      replace(out, notice('info', spinner(), ' Building the bundle — this can take a minute…'));
      try {
        const info = await api('/api/exports', { method: 'POST', body });
        replace(out, exportResultNotice(info));
        announce('Evidence bundle created.');
        loadList();
      } catch (err) {
        replace(out, errorNotice(err));
      } finally {
        btn.disabled = false;
      }
    });

    async function loadList() {
      try {
        const items = await api('/api/exports');
        if (!ctx.alive) return;
        replace(list, items.length
          ? table([{ label: 'Bundle' }, { label: 'Created' }, { label: 'Size', num: true }, { label: 'Records', num: true }, { label: 'SHA-256' }, { label: 'Custody record' }],
            items.map((x) => [
              h('a', { href: '/api/exports/' + encodeURIComponent(x.file_name), download: x.file_name }, x.file_name),
              timeEl(x.created, F.short), fmtBytes(x.size), fmtInt(x.records),
              h('span', { class: 'hash', title: x.sha256 }, shortHash(x.sha256, 16)),
              x.custody_seq ? h('a', { href: recordsLink(x.custody_seq) }, '#' + x.custody_seq) : '—',
            ]), { compact: true })
          : emptyNote('No bundles yet.'));
      } catch (err) {
        if (ctx.alive) replace(list, errorNotice(err));
      }
    }
    async function loadIncidentIds() {
      try {
        const incs = await api('/api/incidents?limit=50&from=' + encodeURIComponent(new Date(Date.now() - 90 * 86400e3).toISOString()));
        if (!ctx.alive) return;
        replace(datalist, ...incs.slice(0, 50).map((i) => h('option', { value: i.id }, `${stateInfo(i.state).label} — ${i.cause ? causeText(i.cause) : ''}`)));
      } catch (_) { /* optional */ }
    }
    loadList();
    loadIncidentIds();
    return card('Evidence bundles',
      h('p', { class: 'muted' }, 'A bundle is a zip with the complete ledger segments for the period, every referenced raw page, a human-readable report, the public key, the time-stamp authorities’ root certificates and a stand-alone verifier, so anyone (for example AT&T) can check it independently.'),
      list, h('h3', { class: 'subhead' }, 'Create a bundle'), form);
  }

  // ------------------------------------------------------------------ records view

  function renderRecords(c, q, ctx) {
    c.append(h('div', { class: 'view-head' }, h('h1', null, 'Ledger records'),
      h('p', { class: 'muted' }, 'The raw evidence ledger. Each record’s body is the exact signed JSON; h = SHA-256 of b, s = Ed25519 signature over b.')));
    const fromIn = h('input', { type: 'number', min: '0', step: '1', inputmode: 'numeric' });
    const typeSel = h('select', null,
      h('option', { value: '' }, 'All types'),
      h('option', { value: '!sample' }, 'All except measurement samples'),
      RECORD_TYPES.map((t) => h('option', { value: t }, t)));
    const limitSel = h('select', null, ['25', '50', '100', '200', '500'].map((n) => h('option', { value: n }, n)));
    const typeParam = q.get('type') || (q.get('exclude') === 'sample' ? '!sample' : '');
    typeSel.value = RECORD_TYPES.includes(typeParam) || typeParam === '!sample' ? typeParam : '';
    limitSel.value = ['25', '50', '100', '200', '500'].includes(q.get('limit')) ? q.get('limit') : '100';
    const focusSeq = q.get('focus');
    const status = h('p', { class: 'small muted', 'aria-live': 'polite' });
    const listEl = h('div');
    const btnFirst = h('button', { type: 'button', class: 'btn btn-small' }, 'First');
    const btnPrev = h('button', { type: 'button', class: 'btn btn-small' }, '← Previous');
    const btnNext = h('button', { type: 'button', class: 'btn btn-small' }, 'Next →');
    const btnLatest = h('button', { type: 'button', class: 'btn btn-small' }, 'Latest');
    const form = h('form', { class: 'card filters' },
      field('From record #', fromIn), field('Type', typeSel), field('Per page', limitSel),
      h('button', { type: 'submit', class: 'btn btn-primary' }, 'Show'));
    c.append(form, h('div', { class: 'btn-row' }, btnFirst, btnPrev, btnNext, btnLatest, status), listEl);

    let nextSeq = null;
    const limit = () => Number(limitSel.value) || 100;
    const filterParams = () => {
      const v = typeSel.value;
      if (v === '!sample') return { exclude: 'sample' };
      return v ? { type: v } : {};
    };

    async function load(from, focus) {
      fromIn.value = String(from);
      const params = new URLSearchParams({ from_seq: String(from), limit: String(limit()), ...filterParams() });
      // keep the URL shareable without re-triggering the router
      const hash = '#/records?' + params.toString();
      if (window.location.hash !== hash) window.history.replaceState(null, '', hash);
      status.textContent = 'Loading…';
      listEl.classList.add('is-loading');
      try {
        const { data, headers } = await api('/api/records?' + params.toString(), { withHeaders: true });
        if (!ctx.alive) return;
        const hdr = headers.get('X-Next-Seq');
        nextSeq = hdr != null ? Number(hdr) : null;
        const warning = headers.get('X-ATT-Monitor-Warning');
        replace(listEl,
          warning ? notice('critical', h('strong', null, 'Integrity problem in the records examined. '), warning, ' ',
            h('a', { href: '#/evidence' }, 'Run Verify')) : null,
          ...(data.length ? data.map((rec) => recordItem(rec, focus != null && String(rec.seq) === String(focus))) : [emptyNote('No records match.')]));
        const head = app.status && app.status.ledger ? app.status.ledger.head_seq : null;
        status.textContent = data.length
          ? `Showing ${data.length} record${data.length === 1 ? '' : 's'}, #${data[0].seq}–#${data[data.length - 1].seq}` + (head != null ? ` of ${fmtInt(head + 1)} in the ledger` : '') + '.'
          : nextSeq != null ? `No matching records between #${from} and #${nextSeq - 1}; use Next to keep searching.` : 'No records.';
        btnNext.disabled = nextSeq == null;
        btnPrev.disabled = from <= 0 || !!typeSel.value;
        btnPrev.title = typeSel.value ? 'Previous is only available without a type filter' : '';
        btnLatest.disabled = !!typeSel.value || head == null;
      } catch (e) {
        if (ctx.alive) {
          replace(listEl, errorNotice(e));
          status.textContent = '';
        }
      } finally {
        listEl.classList.remove('is-loading');
      }
    }

    function latestFrom() {
      const head = app.status && app.status.ledger ? app.status.ledger.head_seq : 0;
      return Math.max(0, head - limit() + 1);
    }

    form.addEventListener('submit', (e) => { e.preventDefault(); load(Math.max(0, Math.floor(Number(fromIn.value) || 0))); });
    btnFirst.addEventListener('click', () => load(0));
    btnPrev.addEventListener('click', () => load(Math.max(0, (Number(fromIn.value) || 0) - limit())));
    btnNext.addEventListener('click', () => { if (nextSeq != null) load(nextSeq); });
    btnLatest.addEventListener('click', () => load(latestFrom()));
    typeSel.addEventListener('change', () => load(typeSel.value ? 0 : Number(fromIn.value) || 0));
    limitSel.addEventListener('change', () => load(Number(fromIn.value) || 0));

    if (q.has('from_seq')) {
      load(Math.max(0, Math.floor(Number(q.get('from_seq')) || 0)), focusSeq);
    } else if (typeSel.value) {
      load(0);
    } else if (app.status) {
      load(latestFrom());
    } else {
      api('/api/status').then((st) => { app.status = st; if (ctx.alive) load(latestFrom()); }).catch(() => load(0));
    }
  }

  function recordBrief(rec) {
    try {
      return recordBriefData(rec);
    } catch (_) {
      return '(content not in the expected form)';
    }
  }

  function recordBriefData(rec) {
    const d = (rec.body && rec.body.data) || {};
    switch (rec.type) {
      case 'sample': return d.verdict ? stateInfo(d.verdict.state).label + (d.verdict.cause ? ' · ' + causeText(d.verdict.cause) : '') : '';
      case 'state_change': return `${stateInfo(d.from_state).label} → ${stateInfo(d.to_state).label}`;
      case 'gateway_snapshot':
        return (d.derived && d.derived.reachable === false ? 'gateway unreachable' : d.broadband && d.broadband.connection ? 'Broadband ' + d.broadband.connection : '') +
          (d.trigger ? ' · ' + d.trigger : '');
      case 'traceroute': return orQ(d.target) + (d.err ? ' · could not run' : d.reached ? ' · reached' : ' · not reached');
      case 'local_link': {
        const e = d.egress && typeof d.egress === 'object' ? d.egress : null;
        return (d.state || '') + (e && e.bypass && !e.err ? ' · traffic not through the AT&T gateway' : '');
      }
      case 'gateway_event': return humanize(d.kind) + (d.after ? ' → ' + d.after : '');
      case 'anchor': return tsaName(d.tsa_url) + ' · covers #' + orQ(d.head_seq);
      case 'operator_note': return d.text || '';
      case 'incident_open': case 'incident_update': case 'incident_close': return (d.id || '') + ' · ' + stateInfo(d.state).label;
      case 'config_change': return (d.what || '') + ': ' + (d.before || '') + ' → ' + (d.after || '');
      case 'config_state': return [d.rules ? 'rules ' + d.rules : '', d.config_sha256 ? 'config ' + shortHash(d.config_sha256, 12) : ''].filter(Boolean).join(' · ');
      case 'custody_export': return d.file_name || '';
      case 'syslog': {
        const msgs = Array.isArray(d.messages) ? d.messages : [];
        const first = msgs.find((m) => m && typeof m === 'object');
        return `${fmtInt(msgs.length)} message${msgs.length === 1 ? '' : 's'}` +
          (first ? ' · ' + escapedText(String(first.msg || first.raw || '').slice(0, 120)) : '');
      }
      default: return '';
    }
  }

  function recordItem(rec, open) {
    const det = h('details', { class: 'rec' });
    det.append(h('summary', null,
      chevron(),
      h('span', { class: 'seq' }, '#' + rec.seq),
      timeEl(rec.ts, F.full),
      h('span', { class: 'rec-sum' }, h('span', { class: 'type-tag' }, rec.type), ' ', recordBrief(rec)),
      rec.hash_ok === false ? alteredChip() : null,
      h('span', { class: 'hash rec-hash', title: 'h = SHA-256 of b: ' + rec.hash }, shortHash(rec.hash, 10))));
    let filled = false;
    const fill = () => {
      if (filled) return;
      filled = true;
      det.append(recordBody(rec));
    };
    det.addEventListener('toggle', () => { if (det.open) fill(); });
    if (open) {
      det.open = true;
      fill();
      window.setTimeout(() => det.scrollIntoView({ block: 'start' }), 0);
    }
    return det;
  }

  /** verdictBlock summarises a sample's verdict and links the records it was computed from. */
  function verdictBlock(rec) {
    const v = rec.type === 'sample' && rec.body && rec.body.data && rec.body.data.verdict;
    if (!v || typeof v !== 'object') return null;
    return h('div', null,
      h('h4', null, 'Verdict of this cycle'),
      h('p', null, headline(v),
        v.attribution && v.attribution !== 'none' ? [' · ', ATTR_LONG[v.attribution] || 'attribution ' + v.attribution] : null,
        ' · rules ', h('code', null, orQ(v.rules))),
      Array.isArray(v.reasons) && v.reasons.length ? h('ul', { class: 'reasons' }, v.reasons.map((r) => h('li', null, r))) : null,
      v.inputs
        ? h('p', null, 'Classified from: ', verdictInputs(v.inputs))
        : h('p', { class: 'small muted' }, 'This verdict does not name the records it used (classified with rules ' + orQ(v.rules) + '; verdicts name them from rules ' + RULES_VERDICT_INPUTS + ').'));
  }

  function recordBody(rec) {
    const blobs = (Array.isArray(rec.body && rec.body.blobs) ? rec.body.blobs : []).filter((b) => HEX64.test(b));
    const env = rec.envelope || {};
    let verdict = null;
    try { verdict = verdictBlock(rec); } catch (_) { verdict = null; }
    // What the record says, as the incident timeline words it (samples: the verdict block).
    const d = verdict ? null : describeRecord(rec);
    return h('div', { class: 'rec-body' },
      verdict,
      d ? h('div', null, h('h4', null, d.title), d.detail ? h('p', { class: 'tl-detail' }, d.detail) : null) : null,
      h('h4', null, 'Body (pretty-printed; the signed bytes are in b below)'),
      // Text from outside (syslog messages, gateway pages) may hold characters that would reorder
      // or hide what is shown: they are written as escapes.
      h('pre', { class: 'json', tabindex: '0' }, visibleText(JSON.stringify(rec.body, null, 2), true)),
      blobs.length ? h('div', null, h('h4', null, 'Raw data referenced by this record'),
        h('ul', null, blobs.map((b) => h('li', null, h('span', { class: 'hash' }, b), ' — ', blobLinks(b, { view: rec.type === 'gateway_snapshot', viewText: 'view (sandboxed)', downloadText: 'download' }).reduce((acc, x, i) => (i ? acc.concat([' · ', x]) : [x]), []))))) : null,
      h('h4', null, 'Ledger line exactly as stored'),
      rec.hash_ok === false ? notice('critical', 'This line’s h is not the SHA-256 of its b: the line was changed after it was written. Run Verify on the Evidence page.') : null,
      kv([
        ['h (SHA-256 of b)', [h('span', { class: 'hash' }, env.h || ''), rec.hash_ok === false ? [' ', alteredChip()] : null]],
        ['s (Ed25519 signature)', h('span', { class: 'hash' }, env.s || '')],
        ['b (signed bytes)', h('pre', { class: 'json wrap', tabindex: '0' }, visibleText(env.b || ''))],
      ]));
  }

  // ------------------------------------------------------------------ dialog

  /** dialog shows a modal and resolves true (confirmed) or false. */
  function dialog(o) {
    return new Promise((resolve) => {
      const dlg = h('dialog', { class: 'dlg', 'aria-labelledby': 'dlg-title' });
      const cancel = h('button', { type: 'submit', class: 'btn', value: 'cancel', formnovalidate: true }, o.cancel || 'Cancel');
      const ok = h('button', { type: 'submit', class: 'btn btn-primary', value: 'ok' }, o.confirm || 'OK');
      const form = h('form', { method: 'dialog' },
        h('div', { class: 'dlg-body' }, h('h2', { id: 'dlg-title' }, o.title), o.body || null, o.fields || null),
        h('div', { class: 'dlg-actions' }, cancel, ok));
      dlg.append(form);
      document.body.append(dlg);
      dlg.addEventListener('close', () => {
        const confirmed = dlg.returnValue === 'ok';
        dlg.remove();
        resolve(confirmed);
      });
      dlg.showModal();
      const first = dlg.querySelector('input, textarea');
      (first || cancel).focus();
    });
  }

  // ------------------------------------------------------------------ init

  function init() {
    const meta = document.querySelector('meta[name="att-monitor-version"]');
    document.getElementById('foot-version').textContent = 'att-monitor ' + (meta ? meta.content : '');
    document.getElementById('skip-link').addEventListener('click', (e) => {
      e.preventDefault();
      document.getElementById('main').focus();
    });
    window.addEventListener('hashchange', route);
    route();
    refreshStatus();
    window.setInterval(refreshStatus, STATUS_REFRESH_MS);
    document.addEventListener('visibilitychange', () => { if (!document.hidden) refreshStatus(); });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
