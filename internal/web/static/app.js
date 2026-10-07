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
    'integrity_alert', 'config_state', 'syslog_chunk', 'syslog_prune',
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
    SYSLOG_RECEIVER_DOWN: 'The syslog receiver is not listening',
    SYSLOG_STORE_FAILING: 'The syslog store fails',
    SYSLOG_SETTING_FAILED: 'The gateway’s Syslog page could not be set',
    SYSLOG_NOT_ARRIVING: 'No syslog message from the gateway for a day',
  });
  // Conditions also shown on the Gateway page (they pause or block its authenticated actions).
  const GATEWAY_ALERTS = ['GATEWAY_CERT_CHANGED', 'NO_ACCESS_CODE'];
  // Conditions also shown on the Evidence page (they affect what is recorded, and when).
  const EVIDENCE_ALERTS = ['LEDGER_WRITE_FAILING', 'DISK_SPACE_LOW', 'CLOCK_OFFSET', 'ANCHOR_UNTRUSTED'];
  // Conditions also shown on the Syslog page (the receiver, the store and the gateway's Syslog
  // setting), with those that pause the change of that setting.
  const SYSLOG_ALERTS = ['SYSLOG_RECEIVER_DOWN', 'SYSLOG_STORE_FAILING', 'SYSLOG_SETTING_FAILED', 'SYSLOG_NOT_ARRIVING', 'GATEWAY_CERT_CHANGED', 'NO_ACCESS_CODE'];

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
  // Why the syslog store sealed a chunk (model.SyslogChunk.reason).
  const SEAL_REASONS = dict({ size: 'full', age: 'age limit', stop: 'service stopping', recovered: 'left open by a crash, sealed at the next start' });
  const SYSLOG_PAGE = 200; // messages asked for at first; "Load more" doubles it
  const SYSLOG_MAX = 5000; // the most GET /api/syslog returns
  // A row of the syslog list shows at most this much of a message's text and of its host and app
  // (characters as shown: an escape counts its length), each with at most SYSLOG_ROW_RUNS runs of
  // hidden characters (an element each): a sender controls the text, and 5000 rows of whole
  // datagrams would be millions of elements. "Exact datagram" under the row shows all of it.
  const SYSLOG_ROW_TEXT = 500;
  const SYSLOG_ROW_NAME = 100;
  const SYSLOG_ROW_RUNS = 16;
  const SYSLOG_MAX_SPAN_MS = 31 * 86400e3; // the longest period GET /api/syslog reads
  // How much syslog may be kept (internal/config MinSyslogKeepMB, MaxSyslogKeepMB, MaxSyslogKeepDays).
  const SYSLOG_KEEP_MB_MIN = 1;
  const SYSLOG_KEEP_MB_MAX = 1048576;
  const SYSLOG_KEEP_DAYS_MAX = 3650;
  const MIB = 1048576;
  // The flow meter asks for a reading this often while the Overview's Traffic card or its details
  // are on screen (GET /api/traffic/live).
  const LIVE_REFRESH_MS = 5000;
  // The Overview's Network card reads its figures (the last 24 hours of the gateway's firewall and
  // of the connections) this often: they change slowly, and the Network page shows them minute by
  // minute.
  const NET_SUMMARY_MS = 5 * 60000;
  // The Network page (docs/syslog-map-graphic.md): its periods (range= of /api/network/*, each
  // ending now), how often it reads its data again while shown, the longest period the server
  // reads, the table rows asked for (the most an answer holds), the longest device key the
  // server accepts, and how many connections the table shows before "Show all".
  const NET_RANGES = [['1h', '1 h'], ['24h', '24 h'], ['7d', '7 d'], ['30d', '30 d']];
  const NET_RANGE_MS = dict({ '1h': 3600e3, '24h': 86400e3, '7d': 7 * 86400e3, '30d': 30 * 86400e3 });
  const NET_REFRESH_MS = 60000;
  const NET_MAX_SPAN_MS = 31 * 86400e3;
  const NET_LIMIT = 1000;
  const NET_DEVICE_MAX = 128;
  const NET_TABLE_PAGE = 25;
  // The flow diagram is drawn at least this wide (room for its three columns of labels);
  // narrower, its box scrolls sideways.
  const NET_SANKEY_MIN_W = 760;
  // The flow diagram's spacing (sankeyLayout, spreadLabels): nodes at least minH px tall and pad
  // px apart; label centres (13 px type) at least gap px apart and edge px inside the node area.
  const NET_SANKEY = { pad: 10, minH: 3, gap: 16, edge: 6 };

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

  // seriesCache holds the newest series read of each range (GET /api/series), {ser, at}: the
  // Overview's strip and sparklines and a details modal's charts of the same range share one read,
  // rather than each downloading it every minute.
  const seriesCache = Object.create(null);

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

  /** placeChildren makes kids (as add() takes them) the children of el, in order, leaving where
   *  it is every node of el that stays: replace() would take a part a view keeps (the flow meter,
   *  the gateway syslog card, the incident link of the status card, a chart) out of the page and
   *  put it back, which loses the keyboard focus in it and can make a screen reader announce its
   *  live region again. The nodes that go are removed first and the new ones are put around those
   *  that stay, so that a node that stays is never moved for another's sake (as when a line
   *  before it appears or goes): only kept nodes whose order changed move. */
  function placeChildren(el, ...kids) {
    const want = [];
    for (const k of kids.flat(Infinity)) {
      if (k == null || k === false || k === '') continue;
      want.push(k instanceof Node ? k : document.createTextNode(String(k)));
    }
    const stays = new Set(want);
    for (const c of Array.from(el.childNodes)) if (!stays.has(c)) el.removeChild(c);
    want.forEach((k, i) => {
      const cur = el.childNodes[i];
      if (cur !== k) el.insertBefore(k, cur || null);
    });
    return el;
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

  /** announce says msg to a screen reader: in the live region of the topmost modal dialog open
   *  (the Overview's details, a confirmation), else in the page's (#live). A modal dialog makes the
   *  rest of the page inert, and an inert live region is never read. */
  function announce(msg) {
    const open = document.querySelectorAll('dialog[open]');
    const top = open.length ? open[open.length - 1] : null;
    const live = (top && top.querySelector('[data-announce]')) || document.getElementById('live');
    live.textContent = '';
    window.setTimeout(() => { live.textContent = msg; }, 60);
  }

  /** announcer is a modal dialog's own polite live region for announce(). */
  function announcer() {
    return h('p', { class: 'sr-only', 'aria-live': 'polite', 'aria-atomic': 'true', 'data-announce': '' });
  }

  // ------------------------------------------------------------------ formatting

  const F = {
    full: new Intl.DateTimeFormat(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', second: '2-digit' }),
    short: new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }),
    time: new Intl.DateTimeFormat(undefined, { hour: 'numeric', minute: '2-digit', second: '2-digit' }),
    hm: new Intl.DateTimeFormat(undefined, { hour: 'numeric', minute: '2-digit' }),
    day: new Intl.DateTimeFormat(undefined, { weekday: 'short', month: 'short', day: 'numeric' }),
    sec: new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', second: '2-digit' }),
    date: new Intl.DateTimeFormat(undefined, { year: 'numeric', month: 'short', day: 'numeric' }),
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

  /** whenText writes a time as text, in local time with seconds ("?" when it is missing). */
  function whenText(v) {
    const d = toDate(v);
    return d ? F.sec.format(d) : orQ(v);
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

  /** lossText writes a packet loss in percent rounded to a tenth, as the loss chart's tooltip
   *  does: fmtPct truncates (so as never to overstate availability), which would understate a
   *  loss; one too small for a tenth is "< 0.1 %", never 0. */
  function lossText(p) {
    if (p == null || !isFinite(p)) return '—';
    if (p <= 0) return '0 %';
    if (p < 0.1) return '< 0.1 %';
    return (Math.round(p * 10) / 10).toFixed(1) + ' %';
  }

  function fmtBytes(n) {
    if (n == null || !isFinite(n)) return '—';
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KiB';
    if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + ' MiB';
    return (n / 1024 / 1024 / 1024).toFixed(1) + ' GiB';
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
   *  mistaken for the text nor reorder, hide or break what is shown around it. A run of hidden
   *  characters is one element, however long (titled ctlTitle): a datagram of 8 KiB of control
   *  characters is one element, not 8,192. keepNewlines leaves line breaks as they are
   *  (pretty-printed JSON). Returns the parts for h(). */
  function visibleText(text, keepNewlines) {
    const t = String(text == null ? '' : text);
    const hidden = (i) => {
      const c = t.charCodeAt(i);
      return hiddenChar(c) && !(keepNewlines && c === 0x0a);
    };
    const out = [];
    let start = 0;
    for (let i = 0; i < t.length; i++) {
      if (!hidden(i)) continue;
      let end = i + 1;
      while (end < t.length && hidden(end)) end++;
      if (i > start) out.push(t.slice(start, i));
      let esc = '';
      for (let j = i; j < end; j++) esc += charEscape(t.charCodeAt(j));
      out.push(h('span', { class: 'ctl', title: ctlTitle(t.slice(i, end)) }, esc));
      start = end;
      i = end - 1;
    }
    if (start < t.length) out.push(t.slice(start));
    return out;
  }

  /** ctlTitle names the characters of a run of hidden characters for its tooltip: their code
   *  points ("U+001B", "U+0000 U+007F"), a repeated one once with its count ("U+0001 ×8192"),
   *  at most eight of them. */
  function ctlTitle(run) {
    const parts = [];
    for (let i = 0; i < run.length;) {
      if (parts.length === 8) {
        parts.push('…');
        break;
      }
      const c = run.charCodeAt(i);
      let n = 1;
      while (i + n < run.length && run.charCodeAt(i + n) === c) n++;
      parts.push('U+' + c.toString(16).toUpperCase().padStart(4, '0') + (n > 1 ? ' ×' + n : ''));
      i += n;
    }
    return parts.join(' ');
  }

  /** clipText returns the start of untrusted text that a list shows - at most maxChars
   *  characters as visibleText shows them (a hidden character counts the length of its escape,
   *  a UTF-16 code unit the others; never half of a surrogate pair), holding at most maxRuns
   *  runs of hidden characters, each an element of its own - and how many characters it leaves
   *  out. */
  function clipText(text, maxChars, maxRuns) {
    const t = String(text == null ? '' : text);
    let end = 0;
    let shown = 0;
    let runs = 0;
    for (; end < t.length; end++) {
      const c = t.charCodeAt(end);
      const hidden = hiddenChar(c);
      if (hidden && (end === 0 || !hiddenChar(t.charCodeAt(end - 1))) && ++runs > maxRuns) break;
      shown += hidden ? charEscape(c).length : 1;
      if (shown > maxChars) break;
    }
    if (end > 0 && end < t.length && (t.charCodeAt(end) & 0xfc00) === 0xdc00 && (t.charCodeAt(end - 1) & 0xfc00) === 0xd800) end--;
    let more = 0;
    for (let i = end; i < t.length; i++) if ((t.charCodeAt(i) & 0xfc00) !== 0xdc00) more++;
    return { text: t.slice(0, end), more };
  }

  /** clippedText is visibleText of what clipText keeps of text, then how much it leaves out
   *  (shown in full under "Exact datagram"). */
  function clippedText(text, maxChars) {
    const c = clipText(text, maxChars, SYSLOG_ROW_RUNS);
    return [visibleText(c.text), c.more ? h('span', { class: 'muted small nowrap' }, ' … ' + fmtInt(c.more) + ' more character' + (c.more === 1 ? '' : 's')) : null];
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

  /** areaKey keys a series drawn as a filled area: the wash with its edge on top. */
  function areaKey(slot) {
    return s('svg', { class: 'key', viewBox: '0 0 18 10', 'aria-hidden': 'true', focusable: 'false' },
      s('rect', { class: 'area f' + slot, x: 1, y: 2, width: 16, height: 8 }),
      s('line', { class: 'c' + slot, x1: 1, y1: 2, x2: 17, y2: 2 }));
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
    // Each link is keyed by what it names (data-fk), not by its record: when a newer record takes
    // its place, keepFocus gives the keyboard focus to the link that names the newer one.
    const seqLink = (seq, label, key) => h('a', { href: recordsLink(seq), 'data-fk': 'inputs:' + key }, (label ? label + ' ' : '') + '#' + seq);
    const part = (seq, label, none, key) => (Number(seq) > 0
      ? seqLink(seq, label, key)
      : h('span', { class: 'muted', title: 'none, or older than the classifier accepts' }, none));
    const n = Number(inp.window_cycles);
    const out = [
      part(inp.snapshot_seq, 'gateway snapshot', 'no fresh gateway snapshot', 'snapshot'), ' · ',
      part(inp.service_check_seq, 'DNS & web check', 'no fresh DNS & web check', 'service'),
    ];
    // Rules 2026.10-4: a resolver failure counts only when the check before showed it too.
    if (Number(inp.prev_service_check_seq) > 0) {
      out.push(h('span', { title: 'A DNS resolver counts as failing only when two consecutive checks show the same failure.' },
        ' (compared with the previous ', seqLink(inp.prev_service_check_seq, 'DNS & web check', 'prev-service'), ')'));
    }
    out.push(' · ', part(inp.local_link_seq, 'local link', 'no fresh local-link reading', 'link'));
    // Rules 2026.10-4: DEGRADED is AT&T's only when the household's own WAN traffic, from the
    // gateway's counters in two snapshots, stayed below 80 Mb/s.
    const from = Number(inp.traffic_from_seq);
    const to = Number(inp.traffic_to_seq);
    if (from > 0 || to > 0) {
      out.push(' · ', h('span', { title: 'The household’s own WAN traffic, from the gateway’s counters in these two snapshots.' },
        'WAN traffic: gateway snapshots ', from > 0 ? seqLink(from, '', 'traffic-from') : '?', ' → ', to > 0 ? seqLink(to, '', 'traffic-to') : '?'));
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
      // The banner that says so (#conn) is hidden behind a modal and inert under it: the view
      // says it where the reader is (the Overview's details).
      if (app.view && app.view.alive && app.view.onStatusError) app.view.onStatusError(e);
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
    [/^\/$/, 'overview', (c, m, q, ctx) => renderOverview(c, ctx, q)],
    [/^\/incidents$/, 'incidents', (c, m, q, ctx) => renderIncidents(c, q, ctx)],
    [/^\/incidents\/([^/]+)$/, 'incidents', (c, m, q, ctx) => renderIncident(c, safeDecode(m[1]), ctx)],
    [/^\/gateway$/, 'gateway', (c, m, q, ctx) => renderGateway(c, ctx)],
    [/^\/syslog$/, 'syslog', (c, m, q, ctx) => renderSyslog(c, q, ctx)],
    [/^\/network$/, 'network', (c, m, q, ctx) => renderNetwork(c, q, ctx, 'connections')],
    [/^\/network\/firewall$/, 'network', (c, m, q, ctx) => renderNetwork(c, q, ctx, 'firewall')],
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

  /** newViewCtx makes the context of a view (or of the Overview's details modal): what it does
   *  on a status update (onStatus) and when the status could not be read (onStatusError), on a
   *  change of only the address's query (onQuery: it handles the change in place and returns
   *  true, or returns false to have the view rendered again), the path and address it shows, and
   *  what ends with it (cleanup, interval; dispose runs them). */
  function newViewCtx() {
    const cleanups = [];
    const ctx = {
      alive: true,
      onStatus: null,
      onStatusError: null,
      onQuery: null,
      path: '',
      hash: '',
      cleanup(fn) { cleanups.push(fn); },
      interval(fn, ms) {
        const id = window.setInterval(fn, ms);
        cleanups.push(() => window.clearInterval(id));
      },
      dispose() {
        ctx.alive = false;
        ctx.onStatus = null;
        ctx.onStatusError = null;
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
    // A view may handle a change of only its address's query in place: the Overview opens and
    // closes a card's details (#/?detail=<key>), which must neither render the page again nor
    // take the reader's place on it. An address the view already shows is its own doing (it
    // went back in the history, or replaced the address): nothing changes.
    const cur = app.view;
    if (cur && cur.alive && cur.onQuery && cur.path === path) {
      if (cur.hash === window.location.hash) return;
      if (cur.onQuery(query)) {
        cur.hash = window.location.hash;
        return;
      }
    }
    if (app.view) app.view.dispose();
    const ctx = newViewCtx();
    ctx.path = path;
    ctx.hash = window.location.hash;
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

  // The Overview's summary cards, in their order (docs/overview-redesign.md §2); the status card
  // above them opens "status".
  const CARD_KEYS = ['internet', 'gateway', 'fiber', 'traffic', 'link', 'network', 'syslog', 'evidence', 'monitor'];

  /** DETAILS says what each card of the Overview shows and opens (docs/overview-redesign.md
   *  §2-§3): title is the card's title and its details' heading; summary(ov, st) returns {tone,
   *  chip, body, context}: the card's status chip ([tone, label]: no tooltip, which could not
   *  show under the card's button - a reason the chip stands for is a line of the card) and
   *  content, and the icon and the line of context of its details; mount(ov, m) builds the
   *  details in m.body and returns {update(st)}, which follows every status update while they are
   *  open. An address that names a card not listed here (#/?detail=<unknown>) opens nothing. */
  const DETAILS = dict({
    status: { title: 'Status & availability', summary: summaryStatus, mount: detailsStatus },
    internet: { title: 'Internet', summary: summaryInternet, mount: detailsInternet },
    gateway: { title: 'AT&T gateway', summary: summaryGateway, mount: detailsGateway },
    fiber: { title: 'Fiber optics', summary: summaryFiber, mount: detailsFiber },
    traffic: { title: 'Traffic', summary: summaryTraffic, mount: detailsTraffic },
    link: { title: 'This PC’s link', summary: summaryLink, mount: detailsLink },
    network: { title: 'Network', summary: summaryNetwork, mount: detailsNetwork },
    syslog: { title: 'Gateway syslog', summary: summarySyslog, mount: detailsSyslog },
    evidence: { title: 'Evidence', summary: summaryEvidence, mount: detailsEvidence },
    monitor: { title: 'Monitor & clock', summary: summaryMonitor, mount: detailsMonitor },
  });

  /** renderOverview shows the Overview as a summary dashboard (docs/overview-redesign.md): the
   *  conditions, the status card, the six key numbers, the nine summary cards and the recent
   *  incidents. Each card opens its details in a modal (detailModal), which the address names
   *  (#/?detail=<key>, query: a link or a reload opens it). The summary reads the status (every
   *  10 s), the last 24 hours of the series (every minute while the page is visible: the strip
   *  and the sparklines), the flow meter (every 5 s, only while the Traffic card or its details
   *  are on screen) and the Network card's figures (every 5 minutes); the details read what they
   *  show besides the status themselves, while they are open. A hidden page is not drawn; shown
   *  again, it reads at once what it missed meanwhile. */
  function renderOverview(c, ctx, query) {
    const ov = {
      ctx,
      series: null, // GET /api/series?range=24h: the strip and the sparklines (seriesErr: why not)
      seriesErr: null,
      seriesAt: 0, // when the series was read (Date.now()); 0: not yet
      seriesBusy: false,
      live: null, // the flow meter's newest reading, {lt, failure}, or {unavailable} without one
      net: null, // the Network card's figures (loadNetSummary)
      netAt: 0, // when they were read
      netBusy: false,
      recent: null, // the lines of the recent incidents shown (loadRecentIncidents)
      recentToken: 0,
      incId: null, // the incident in progress the status names ('' none; null: no status yet)
      cards: Object.create(null), // key -> {el, btn, paint(st)}, the status card's key "status"
      onScreen: typeof IntersectionObserver !== 'function', // the Traffic card is on screen
      detail: null,
      flow: null,
    };
    const conditions = h('div', { class: 'conditions' });
    const tiles = h('section', { 'aria-label': 'Availability statistics' });
    const open = (key) => ov.detail.open(key, 'click');
    ov.cards.status = statusCard(ov, open);
    for (const key of CARD_KEYS) ov.cards[key] = summaryCard(ov, key, open);
    const recent = h('section', { class: 'card recent', 'aria-labelledby': 'recent-h' },
      h('div', { class: 'card-head' }, h('h2', { id: 'recent-h' }, 'Recent incidents')), h('p', { class: 'loading' }, 'Loading…'));
    c.append(h('h1', { class: 'sr-only' }, 'Overview'), conditions, ov.cards.status.el, tiles,
      h('div', { class: 'sum-grid' }, CARD_KEYS.map((k) => ov.cards[k].el)), recent);
    ov.detail = detailModal(c, ov);
    ov.flow = flowMeter(ctx, {
      wanted: () => (ov.detail.key ? ov.detail.key === 'traffic' : ov.onScreen),
      onReading(live) {
        ov.live = live;
        paintCard(ov, 'traffic');
      },
    });
    watchTrafficCard(ov);

    const paint = (st) => {
      fillAlerts(conditions, st, null);
      fillTiles(tiles, st);
      paintCards(ov);
      ov.detail.update(st);
      followIncident(ov, recent, st);
    };
    // A hidden page is not drawn: it is drawn with the status read as soon as it is shown again
    // (init's visibilitychange), not every 10 s for nobody.
    ctx.onStatus = (st) => { if (!document.hidden) paint(st); };
    ctx.onStatusError = (err) => ov.detail.stale(err);
    ctx.onQuery = (q) => ov.detail.sync(q);
    if (app.status) paint(app.status);
    else paintCards(ov);
    loadSeries24(ov);
    loadNetSummary(ov);
    loadRecentIncidents(recent, ov);
    ctx.interval(() => {
      if (document.hidden) return;
      loadSeries24(ov);
      loadRecentIncidents(recent, ov);
    }, SERIES_REFRESH_MS);
    ctx.interval(() => { if (!document.hidden && !(ov.net && ov.net.none)) loadNetSummary(ov); }, NET_SUMMARY_MS);
    // Back from a hidden tab, what the minute's reads skipped meanwhile is read at once: the
    // strip, the sparklines and the recent incidents must not show an older day than the status
    // beside them.
    const onVisible = () => {
      if (document.hidden) return;
      if (Date.now() - ov.seriesAt >= SERIES_REFRESH_MS) {
        loadSeries24(ov);
        loadRecentIncidents(recent, ov);
      }
      if (!(ov.net && ov.net.none) && Date.now() - ov.netAt >= NET_SUMMARY_MS) loadNetSummary(ov);
    };
    document.addEventListener('visibilitychange', onVisible);
    ctx.cleanup(() => document.removeEventListener('visibilitychange', onVisible));
    ov.detail.sync(query); // the details the address names
  }

  /** followIncident follows the incident in progress the status names: when one opens or closes,
   *  the recent incidents are read again at once (not at the next minute), so that they never
   *  contradict the status card; meanwhile an open one's duration follows the status. */
  function followIncident(ov, el, st) {
    const id = st.active_incident && st.active_incident.id ? String(st.active_incident.id) : '';
    // At the first status the page reads them already.
    if (ov.incId !== null && id !== ov.incId) loadRecentIncidents(el, ov);
    ov.incId = id;
    for (const line of ov.recent || []) {
      if (line.inc.open) replace(line.dur, keepUnits(incidentDuration(line.inc, st.now)));
    }
  }

  /** watchTrafficCard tells the flow meter whether the Traffic card is on screen: it asks for
   *  readings only while the card or its details are (IntersectionObserver). A browser without the
   *  observer is taken to show the card. */
  function watchTrafficCard(ov) {
    if (typeof IntersectionObserver !== 'function') return;
    const io = new IntersectionObserver((entries) => {
      for (const en of entries) ov.onScreen = en.isIntersecting;
      ov.flow.wake();
    });
    io.observe(ov.cards.traffic.el);
    ov.ctx.cleanup(() => io.disconnect());
  }

  /** paintCards draws the status card and every summary card from the newest status. */
  function paintCards(ov) {
    ov.cards.status.paint(app.status);
    for (const key of CARD_KEYS) paintCard(ov, key);
  }

  /** paintCard draws one summary card again (new data of its own: a reading, a series). */
  function paintCard(ov, key) {
    if (ov.ctx.alive && ov.cards[key]) ov.cards[key].paint(app.status);
  }

  /** loadSeries24 reads the last 24 hours of the series for the status card's strip and the
   *  cards' sparklines (one read at a time). Its probe labels name the probes everywhere
   *  (app.series); a details modal's charts of the same range take it from seriesCache. */
  async function loadSeries24(ov) {
    if (ov.seriesBusy) return;
    ov.seriesBusy = true;
    try {
      const ser = await api('/api/series?range=24h');
      if (!ov.ctx.alive) return;
      const firstLabels = !app.series;
      ov.series = ser && typeof ser === 'object' ? ser : null;
      ov.seriesErr = null;
      ov.seriesAt = Date.now();
      if (ov.series) {
        app.series = ov.series;
        seriesCache['24h'] = { ser: ov.series, at: ov.seriesAt };
      }
      if (firstLabels && app.status && ov.ctx.onStatus) ov.ctx.onStatus(app.status); // probe labels come with the series
      else paintCards(ov);
    } catch (e) {
      if (!ov.ctx.alive) return;
      ov.seriesErr = e;
      paintCards(ov);
    } finally {
      ov.seriesBusy = false;
    }
  }

  /** loadNetSummary reads the Network card's figures: the last 24 hours of the gateway's
   *  firewall (its five heaviest outbound rows only: the card shows totals) and of the connections
   *  (one row: the card names the most used organisations), which the server keeps for the
   *  period. A monitor without the Network page answers 404 to both: the card says so (none), and
   *  is not asked again. The details of the Network card, when open, show them too. */
  async function loadNetSummary(ov) {
    if (ov.netBusy) return;
    ov.netBusy = true;
    const read = (path) => api(path).then((d) => ({ d: d && typeof d === 'object' ? d : {} }), (err) => ({ err }));
    try {
      const [fw, conn] = await Promise.all([read('/api/network/firewall?range=24h&limit=5'), read('/api/network/connections?range=24h&limit=1')]);
      if (!ov.ctx.alive) return;
      const gone = (x) => !!(x.err && x.err.status === 404);
      ov.net = { fw: fw.d || null, fwErr: fw.err || null, conn: conn.d || null, connErr: conn.err || null, none: gone(fw) && gone(conn) };
      ov.netAt = Date.now();
      paintCard(ov, 'network');
      if (ov.detail.key === 'network') ov.detail.update(app.status);
    } finally {
      ov.netBusy = false;
    }
  }

  /** statusHero is the status as the classifier words it, in the details "Status & availability":
   *  the state, its attribution and since when, the reasons, the records it was classified from,
   *  the incident in progress and the monitor. update(st) draws it again for every status but
   *  keeps its links (the records, the incident's) while they are the same, so that a status
   *  update neither moves the keyboard focus from one to a copy of it (a screen reader would
   *  announce it again every 10 s) nor takes a text selection in them away. Returns
   *  {el, update(st)}. */
  function statusHero() {
    const el = h('section', { class: 'card hero tone-none', 'aria-label': 'Current status' }, h('p', { class: 'loading' }, 'Loading status…'));
    const body = h('div', { class: 'hero-body' });
    let inputsKey = null;
    let inputs = null;
    let incId = null;
    let banner = null;
    return {
      el,
      update(st) {
        const v = st.verdict || {};
        const si = stateInfo(v.state);
        const unknown = !v.state || v.state === 'UNKNOWN';
        const ls = st.last_sample;
        const ik = JSON.stringify(v.inputs || null);
        if (ik !== inputsKey) {
          inputsKey = ik;
          inputs = v.inputs ? h('p', { class: 'hero-meta' }, 'Classified from: ', verdictInputs(v.inputs)) : null;
        }
        const inc = st.active_incident && st.active_incident.id ? st.active_incident : null;
        if ((inc ? String(inc.id) : '') !== incId) {
          incId = inc ? String(inc.id) : '';
          banner = inc ? incidentBanner(inc.id) : null;
        }
        if (banner) banner.update(inc, st.now);
        const mon = st.monitor || {};
        const age = ls && !statusStale(st) ? ageSeconds(ls.started, st.now) : null; // a stale status says it above
        placeChildren(body,
          h('p', { class: 'eyebrow' }, 'Internet status now'),
          h('h2', { class: 'hero-title' }, statusHeadline(st)),
          // An UNKNOWN verdict attributes nothing to anyone.
          !unknown && ATTR_LONG[v.attribution] ? h('p', { class: 'hero-attr' }, ATTR_LONG[v.attribution]) : null,
          st.since && !unknown ? h('p', { class: 'hero-since' }, 'In this state since ', timeEl(st.since), ' (' + sinceText(st.since, st.now) + ')') : null,
          statusStale(st) ? h('p', { class: 'hero-since' }, 'The last measurement recorded was taken ', timeEl(ls.started),
            ' (' + sinceText(ls.started, st.now) + ' ago). What this page shows from it is not the current state.') : null,
          v.reasons && v.reasons.length ? h('ul', { class: 'reasons', 'aria-label': 'Why' }, v.reasons.map((r) => h('li', null, r))) : null,
          inputs,
          banner ? banner.el : null,
          h('p', { class: 'hero-meta' },
            'Classifier rules ', h('code', null, v.rules || '—'),
            ls ? [' · last measurement ', timeEl(ls.started, F.time), age != null && age > 120 ? ' (' + fmtDur(age) + ' ago)' : null] : null,
            mon.mode ? [' · monitor running as ', mon.mode, ' for ', fmtDur(mon.uptime_s)] : null));
        el.className = 'card hero tone-' + si.tone;
        placeChildren(el, icon(si.tone, 'hero-icon'), body);
      },
    };
  }

  /** incidentBanner is the banner of the incident in progress (id) in the details "Status &
   *  availability": update(inc, now) words its state and how long it has been open, and leaves
   *  its link where it is. Returns {el, update(inc, now)}. */
  function incidentBanner(id) {
    const title = h('p', { class: 'banner-title' });
    const what = h('p');
    const body = h('div', { class: 'banner-body' }, title, what,
      h('p', null, h('a', { href: '#/incidents/' + encodeURIComponent(id), 'data-fk': 'status:incident' }, 'Open the incident and its evidence')));
    const el = h('div', { class: 'banner' }, body);
    return {
      el,
      update(inc, now) {
        const si = stateInfo(inc.state);
        el.className = 'banner tone-' + si.tone;
        placeChildren(el, icon(si.tone), body);
        replace(title, 'Incident in progress: ', inc.id);
        replace(what, headline(inc), ' — open for ', sinceText(inc.opened, now), ' (since ', timeEl(inc.opened), ').');
      },
    };
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
      body.append(h('p', { class: 'src' }, 'Monitoring needs no access code — only checking or changing the gateway’s settings (the outage redirect and the Syslog page) and reading its NAT table (the connections on the Network page) do. To store it, run ',
        h('code', null, 'att-monitor set-access-code --file PATH'), ' as administrator (the device access code is printed on the gateway’s label).'));
    }
    if (cnd.code === 'ANCHOR_UNTRUSTED') {
      body.append(h('p', { class: 'src' }, 'An RFC 3161 time-stamp proves when records existed only if its signature verifies and the time-stamp authority’s certificate chains to a trusted root. Records after the last trusted time-stamp therefore count as not yet time-stamped; they remain hash-chained and signed. ',
        evidenceLink('Check the time-stamps on the Evidence page')));
    }
    if (cnd.code === 'EGRESS_NOT_VIA_GATEWAY') {
      body.append(h('p', { class: 'src' }, 'att-monitor checks the route Windows uses to reach the AT&T gateway and each internet destination. While a destination is routed past the gateway — through a VPN tunnel, a second network adapter or a phone hotspot — what this computer measures on the Internet may be that other network’s doing, so nothing is attributed to AT&T: an outage is recorded as this computer’s routing, not as an AT&T outage (unless the gateway itself reports its fiber or broadband connection down), and a slowdown stays undetermined. Disconnect the VPN or the other network to resume attribution. Per-application VPNs and IPv6 destinations are not detected. The routes are listed under “Route to the Internet” in the details of the Overview’s “This PC’s link” card.'));
    }
    if (cnd.code === 'LEDGER_WRITE_FAILING') {
      body.append(h('p', { class: 'src' }, 'Nothing that happens now becomes evidence, so this period will be missing from the ledger. Free disk space on the data volume; otherwise att-monitor stops so that Windows restarts the service, which reopens the ledger with its crash recovery. ',
        evidenceLink('Ledger and data directory on the Evidence page')));
    }
    if (cnd.code === 'DISK_SPACE_LOW') {
      body.append(h('p', { class: 'src' }, 'Once the volume is full no record can be written and the monitor stops producing evidence. Free space on the volume that holds the data directory. ',
        evidenceLink('Data directory on the Evidence page')));
    }
    if (cnd.code === 'SYSLOG_SETTING_FAILED') {
      body.append(h('p', { class: 'src' }, 'While att-monitor keeps the gateway sending its log here (gateway.enforce_syslog), it tries again at its next settings check; the control of the gateway’s Syslog setting on the Syslog page tries now. ',
        parseHash().path === '/syslog' ? null : h('a', { href: '#/syslog' }, 'Open the Syslog page')));
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

  /** sentence ends text with a full stop unless it ends with one already (or ? or !). */
  function sentence(text) {
    const t = String(text || '');
    return /[.!?]$/.test(t) ? t : t + '.';
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
      h('p', null, 'The AT&T gateway presented a different TLS certificate from the one att-monitor pinned. Status pages are still read and recorded (they need no login), but authenticated actions — checking or changing the gateway’s outage-redirect and Syslog settings, and reading its NAT table for the connections on the Network page — are paused, so the gateway’s access code is never sent to a device that may not be your gateway.'),
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

  // ------------------------------------------------------------------ overview: the cards

  /** expandIcon is the arrows that mark what opens in a larger view (a card's details). */
  function expandIcon() {
    return s('svg', { class: 'expand', viewBox: '0 0 24 24', 'aria-hidden': 'true', focusable: 'false' }, s('path', { d: 'M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7' }));
  }

  /** closeIcon is the cross of a close button. */
  function closeIcon() {
    return s('svg', { class: 'xmark', viewBox: '0 0 24 24', 'aria-hidden': 'true', focusable: 'false' }, s('path', { d: 'M6 6l12 12M18 6L6 18' }));
  }

  /** summaryCard builds a card of the Overview (docs/overview-redesign.md §4): an article whose
   *  title is a button that opens the card's details, stretched over the whole card (CSS), so
   *  that the card is one click target and one Tab stop and the focus ring outlines it; a screen
   *  reader announces the title as a button that opens a dialog, then reads the card. It holds no
   *  other control. paint(st) draws its status chip and content (DETAILS[key].summary); the
   *  button stays, so that the keyboard focus on it survives every update. */
  function summaryCard(ov, key, open) {
    const d = DETAILS[key];
    // The chip describes the button: Tab says "Internet, button, opens dialog, No answer".
    const btn = h('button', { type: 'button', class: 'sum-open', 'aria-haspopup': 'dialog', 'aria-describedby': 'sum-chip-' + key, 'data-detail': key }, d.title);
    btn.addEventListener('click', () => open(key));
    const chipBox = h('span', { class: 'sum-chip', id: 'sum-chip-' + key });
    const body = h('div', { class: 'sum-body' });
    const el = h('article', { class: 'card sum-card tone-none' },
      h('div', { class: 'sum-head' }, h('h2', { class: 'sum-title' }, btn), ' ', chipBox, ' ',
        h('span', { class: 'sum-more', 'aria-hidden': 'true' }, 'Details', expandIcon())),
      body);
    return {
      el,
      btn,
      paint(st) {
        const v = st ? d.summary(ov, st) : { tone: 'none', chip: null, body: [h('p', { class: 'loading' }, 'Loading…')] };
        el.className = 'card sum-card tone-' + v.tone;
        // No tooltip (the chip's third part): it could not show under the card's button.
        replace(chipBox, v.chip ? chip(v.chip[0], v.chip[1]) : null);
        replace(body, untitled(v.body));
      },
    };
  }

  /** untitled takes the tooltips (title) out of a summary card's content (nodes as add() takes
   *  them) and returns it: the card's button is stretched over the whole card, so no tooltip in it
   *  could ever show. What one would say is on the card itself, or in its details (where times
   *  give their UTC value on hover). */
  function untitled(...kids) {
    for (const k of kids.flat(Infinity)) {
      if (!(k instanceof Node) || k.nodeType !== 1) continue;
      k.removeAttribute('title');
      for (const e of k.querySelectorAll('[title]')) e.removeAttribute('title');
    }
    return kids;
  }

  /** statusCard is the Overview's status card (docs/overview-redesign.md §2.2): the state now,
   *  its attribution, since when, the key facts of the newest measurement and the incident in
   *  progress; on the right the last 24 hours as a strip of the classifier's states. Its button
   *  "Status & availability" (described by the state shown) opens those details and, stretched
   *  over the card as the summary cards' titles are, makes the whole card open them; the
   *  incident's link stays a link of its own (above the button). paint(st) draws the card again
   *  for every status and every series, but keeps the incident's line while the incident is the
   *  same (placeChildren never moves it): the keyboard focus on its link survives every update. */
  function statusCard(ov, open) {
    const btn = h('button', { type: 'button', class: 'sum-open status-open', 'aria-haspopup': 'dialog', 'aria-describedby': 'status-state', 'data-detail': 'status' }, DETAILS.status.title);
    btn.addEventListener('click', () => open('status'));
    const ico = h('span', { class: 'status-ico' });
    const main = h('div', { class: 'status-main' });
    const cap = h('span', { class: 'status-strip-cap' });
    const strip = h('div', { class: 'status-strip' });
    const el = h('section', { class: 'card status-card tone-none', 'aria-label': 'Current status' },
      h('div', { class: 'status-left' }, ico, main),
      h('div', { class: 'status-right' },
        h('div', { class: 'status-strip-head' }, h('span', { class: 'status-strip-title' }, 'Last 24 hours', cap),
          h('span', { class: 'status-more' }, btn, expandIcon())),
        strip));
    let incId = '';
    let incLine = null;
    return {
      el,
      btn,
      paint(st) {
        const tone = st ? statusTone(st) : 'none';
        el.className = 'card status-card tone-' + tone;
        replace(ico, icon(tone, 'status-icon'));
        const id = st && st.active_incident && st.active_incident.id ? String(st.active_incident.id) : '';
        if (id !== incId) {
          incId = id;
          incLine = id ? statusIncident(id) : null;
        }
        placeChildren(main, untitled(statusMain(st)), incLine);
        const g = seriesGeom(ov.series);
        replace(cap, g ? ' · worst state in each ' + fmtDur(g.stepMs / 1000) : '');
        replace(strip, untitled(statusStrip(ov, st)));
      },
    };
  }

  /** statusIncident is the status card's line of the incident in progress (id): a link of its
   *  own, above the card's button (CSS). */
  function statusIncident(id) {
    return h('p', { class: 'status-incident' },
      h('a', { href: '#/incidents/' + encodeURIComponent(id), 'data-fk': 'status:incident' }, 'Incident in progress: ' + id + ' — open it and its evidence'));
  }

  /** statusTone is the tone of the state now; an UNKNOWN state (or none yet) has none. */
  function statusTone(st) {
    const v = (st && st.verdict) || {};
    return !v.state || v.state === 'UNKNOWN' ? 'none' : stateInfo(v.state).tone;
  }

  /** statusTitle words the state now in a word or two, for the status card's title: the
   *  state's label, except where that label would say more than was observed - a gateway restart
   *  and traffic routed past the gateway are recorded under LOCAL_FAULT, but neither is this PC's
   *  or the home network's fault. An UNKNOWN state is "Not measuring" while no cycle is recorded
   *  (statusStale), "Waiting for the first measurements" before the first one, "Unknown"
   *  otherwise: the card gives the reasons under it (statusMain). */
  function statusTitle(st) {
    const v = (st && st.verdict) || {};
    if (!v.state || v.state === 'UNKNOWN') {
      if (!st || !st.last_sample) return 'Waiting for the first measurements';
      return statusStale(st) ? 'Not measuring' : 'Unknown';
    }
    if (v.cause === 'GATEWAY_REBOOT') return 'AT&T gateway restarted';
    if (v.cause === 'LOCAL_ROUTE') return 'Not through the AT&T gateway';
    return stateInfo(v.state).label;
  }

  /** causeWords words a verdict's cause with its source, for the status card's facts: "fiber
   *  link down (reported by the AT&T gateway)"; traffic routed past the gateway in full, as it
   *  attributes nothing to AT&T. */
  function causeWords(v) {
    if (!v || !v.cause) return '';
    const c = CAUSES[v.cause];
    if (!c) return humanize(v.cause);
    if (c.headline) return c.headline;
    return c.text + (c.src ? ' (' + c.src + ')' : '');
  }

  /** gatewayAnswered mirrors the classifier (internal/monitor gatewayAnswered): the gateway's IP
   *  stack answered a probe when it succeeded, or when a TCP connection was refused (a reset is an
   *  answer). Every attribution to AT&T rests on it. */
  function gatewayAnswered(p) {
    return !!p && (!!p.ok || (String(p.kind).toLowerCase() === 'tcp' && String(p.status || '').trim().toLowerCase() === 'refused'));
  }

  /** isICMP reports whether a probe is an ICMP one. */
  function isICMP(p) {
    return String(p && p.kind).toLowerCase() === 'icmp';
  }

  /** probeFacts sums up a sample's probes: the internet probes and those that answered; whether
   *  the gateway answered any probe, as the classifier judges it (gwAnswered), and the gateway's
   *  probe to show - one that answered, the ICMP one first; else the ICMP one -; the AT&T next
   *  hop's probe (the ICMP one when there are several); the median round trip of the internet
   *  probes that answered (µs; null without one). */
  function probeFacts(smp) {
    const probes = (smp && Array.isArray(smp.probes) ? smp.probes : []).filter((p) => p && typeof p === 'object');
    const inet = probes.filter((p) => p.role === 'internet');
    const ok = inet.filter((p) => p.ok);
    const gws = probes.filter((p) => p.role === 'gateway');
    const answered = gws.filter(gatewayAnswered);
    const gw = answered.find((p) => p.ok && isICMP(p)) || answered.find((p) => p.ok) || answered[0] || gws.find(isICMP) || gws[0] || null;
    const hop = probes.find((p) => p.role === 'isp_hop' && isICMP(p)) || probes.find((p) => p.role === 'isp_hop') || null;
    const rtts = ok.map((p) => Number(p.rtt_us)).filter((v) => v > 0);
    return { inet, ok, gw, gwAnswered: answered.length > 0, hop, median: medianOf(rtts) };
  }

  /** gatewayRTTWords says how the gateway answered (probeFacts' gw, which answered): its round
   *  trip ("3.1 ms over TCP" when that is the probe), or that it refused a TCP connection. */
  function gatewayRTTWords(gw) {
    if (!gw.ok) return 'it refused a TCP connection';
    return fmtRTT(gw.rtt_us) + (isICMP(gw) ? '' : ' over TCP');
  }

  /** statusFacts is the status card's line of key facts from the newest measurement: the
   *  internet probes answered, whether and how the gateway answered, the internet's median round
   *  trip and the cause. A status that describes no current measurement (statusStale) has none. */
  function statusFacts(st) {
    const smp = st.last_sample;
    if (!smp || statusStale(st)) return '';
    const f = probeFacts(smp);
    const parts = [];
    if (f.inet.length) parts.push(`${f.ok.length} of ${f.inet.length} internet probes answered`);
    if (f.gw) {
      parts.push(!f.gwAnswered ? 'the AT&T gateway did not answer'
        : f.gw.ok ? 'AT&T gateway ' + gatewayRTTWords(f.gw) : 'the AT&T gateway answered (TCP connection refused)');
    }
    if (f.median != null) parts.push('median round trip ' + fmtRTT(f.median));
    const cause = causeWords(st.verdict);
    if (cause) parts.push(cause);
    return parts.join(' · ');
  }

  /** statusMain is the left of the status card: the state now and what goes with it (its
   *  incident's line is statusCard's). Never the last state recorded as the present one: a status
   *  that describes no current measurement says when the last one was taken. An UNKNOWN status
   *  gives its reasons (its details list them all): a stale one those after the first, which the
   *  line of the last measurement says already. */
  function statusMain(st) {
    const out = [h('p', { class: 'eyebrow' }, 'Internet status now')];
    if (!st) return out.concat(h('h2', { class: 'status-title', id: 'status-state' }, 'Loading status…'));
    const v = st.verdict || {};
    const unknown = !v.state || v.state === 'UNKNOWN';
    const stale = statusStale(st);
    out.push(h('h2', { class: 'status-title', id: 'status-state' }, statusTitle(st)));
    if (!unknown && ATTR_LONG[v.attribution]) out.push(h('p', { class: 'status-attr' }, ATTR_LONG[v.attribution]));
    if (st.since && !unknown) out.push(h('p', { class: 'status-since' }, 'For ' + sinceText(st.since, st.now) + ', since ', netTimeEl(st.since)));
    const ls = st.last_sample;
    if (stale && ls) {
      out.push(h('p', { class: 'status-since' }, 'The last measurement recorded was taken ', netTimeEl(ls.started),
        ' (' + sinceText(ls.started, st.now) + ' ago): what it showed is not the current state.'));
    }
    const first = stale && ls ? 1 : 0;
    const reasons = unknown && Array.isArray(v.reasons) ? v.reasons.slice(first, first + 2) : [];
    if (reasons.length) out.push(h('p', { class: 'status-facts' }, reasons.map((r) => sentence(capitalize(String(r)))).join(' ')));
    const facts = statusFacts(st);
    if (facts) out.push(h('p', { class: 'status-facts' }, keepUnits(facts)));
    return out;
  }

  /** statusStrip is the right of the status card: the last 24 hours as a strip of the
   *  classifier's worst state in each bucket (the series), with a legend that pairs its colours
   *  with the day's key numbers from the status - its availability, its degraded and its
   *  AT&T-attributed time, worded as the key numbers below word them: they count cycles (the
   *  conservative figures, gateway restarts left out), the strip buckets, and its own shares are
   *  in its details - and names every other state the strip shows. The strip ends "now" unless
   *  the series is minutes older than the status (then its times are given). */
  function statusStrip(ov, st) {
    const g = seriesGeom(ov.series);
    let runs = [];
    let bar;
    if (g) {
      runs = seriesRuns(ov.series);
      bar = stripSvg(runs, g.from, g.to);
    } else if (ov.seriesErr) {
      bar = h('p', { class: 'small muted' }, 'The last 24 hours could not be read: ' + sentence(ov.seriesErr.message));
    } else {
      bar = stripSvg([], 0, 1); // the empty track while the series loads
    }
    const day = ((st && Array.isArray(st.stats) ? st.stats : []).find((w) => w && w.window === '24h')) || null;
    const shown = new Set(runs.map((r) => r.state));
    const items = [
      ['ONLINE', day ? 'Availability ' + fmtPct(day.availability_pct, 2) : 'Online'],
      ['DEGRADED', day ? 'Degraded ' + fmtDur(day.degraded_s) : 'Degraded'],
      ['ISP_OUTAGE', day ? 'AT&T-attributed ' + fmtDur(day.provider_outage_s) : 'AT&T outage'],
    ];
    for (const state of ['LOCAL_FAULT', 'UNKNOWN', '']) {
      if (shown.has(state)) items.push([state, stateInfo(state).label]);
    }
    const now = st ? toMs(st.now) : null;
    const lags = !!g && now != null && now - g.to > 120e3;
    const axis = !g ? null : lags ? [g.from, (g.from + g.to) / 2, g.to].map((t) => F.hm.format(new Date(t))) : ['24 h ago', '12 h ago', 'now'];
    return [bar,
      axis ? h('p', { class: 'strip-axis', 'aria-hidden': 'true' }, axis.map((x) => h('span', null, x))) : null,
      h('ul', { class: 'strip-legend', 'aria-label': 'Last 24 hours' },
        items.map(([state, text]) => h('li', null, icon(stateInfo(state).tone), text)))];
  }

  /** stripSvg draws the runs of states (stateRuns) of [from, to] as a strip across the status
   *  card; a blip stays visible. Decoration: the legend beside it says what it shows. */
  function stripSvg(runs, from, to) {
    const W = 300;
    const svg = s('svg', { class: 'strip', viewBox: `0 0 ${W} 18`, preserveAspectRatio: 'none', 'aria-hidden': 'true', focusable: 'false' },
      s('rect', { class: 'strip-track', x: 0, y: 0, width: W, height: 18 }));
    const X = (t) => ((t - from) / (to - from)) * W;
    for (const r of runs) {
      const a = X(r.start);
      let w = X(r.end) - a;
      if (r.state !== 'ONLINE' && r.state !== '') w = Math.max(w, 1.5);
      if (w > 0) svg.append(s('rect', { class: 'sf-' + stateInfo(r.state).tone, x: a.toFixed(2), y: 0, width: w.toFixed(2), height: 18 }));
    }
    return svg;
  }

  // ------------------------------------------------------------------ overview: sparklines

  /** numOrNull reads a number of the data, or null for none (NaN, Infinity, a string). */
  function numOrNull(v) {
    return v == null || v === '' || !isFinite(v) ? null : Number(v);
  }

  // What is drawn from a series (its range, its runs of states, the sparklines' values) is worked
  // out once per series read, not at every status update (10 s) and flow meter reading (5 s): a
  // series changes once a minute. Each use builds its own elements from it.
  const seriesMemos = new WeakMap();

  /** seriesMemo returns what make() works out from the series ser, made once per series object
   *  and name (it must not be changed); null without a series. */
  function seriesMemo(ser, name, make) {
    if (!ser || typeof ser !== 'object') return null;
    let m = seriesMemos.get(ser);
    if (!m) seriesMemos.set(ser, m = Object.create(null));
    if (!(name in m)) m[name] = make();
    return m[name];
  }

  /** seriesGeom reads what every use of a series needs (GET /api/series): its range (from, to,
   *  in ms), its bucket length and its points with their start times; null when its range is not
   *  valid. */
  function seriesGeom(ser) {
    return seriesMemo(ser, 'geom', () => {
      const from = toMs(ser.from);
      const to = toMs(ser.to);
      if (from == null || to == null || to <= from) return null;
      const stepMs = Math.max(1, Number(ser.step_s) || 60) * 1000;
      const pts = [];
      const starts = [];
      for (const p of Array.isArray(ser.points) ? ser.points : []) {
        const t = p && typeof p === 'object' ? toMs(p.t) : null;
        if (t == null) continue;
        pts.push(p);
        starts.push(t);
      }
      return { from, to, stepMs, pts, starts };
    });
  }

  /** seriesRuns is a series' buckets merged into runs of equal state (stateRuns), for the status
   *  card's strip; none without a valid range. */
  function seriesRuns(ser) {
    return seriesMemo(ser, 'runs', () => {
      const g = seriesGeom(ser);
      return g ? stateRuns(g.pts, g.from, g.to, g.stepMs) : [];
    }) || [];
  }

  /** inetKeys names the internet probes of a series (their keys in rtt_ms and loss): from its
   *  list of probes, else the keys of its points that start with "inet". */
  function inetKeys(ser) {
    const specs = ser && Array.isArray(ser.probes) ? ser.probes.filter((p) => p && p.role === 'internet') : [];
    if (specs.length) return specs.map((p) => String(p.name));
    const keys = new Set();
    for (const p of ser && Array.isArray(ser.points) ? ser.points : []) {
      for (const k of Object.keys((p && p.rtt_ms) || {}).concat(Object.keys((p && p.loss) || {}))) if (/^inet/.test(k)) keys.add(k);
    }
    return [...keys];
  }

  /** sparkTop is the top of a sparkline's scale: the highest value, unless spikes stand far above
   *  the rest (more than three times the 90th percentile): then 1.5 times that percentile, and the
   *  spikes reach the top edge. */
  function sparkTop(vals) {
    const a = vals.slice().sort((x, y) => x - y);
    const max = a[a.length - 1];
    const p90 = a[Math.floor((a.length - 1) * 0.9)];
    return p90 > 0 && max > 3 * p90 ? 1.5 * p90 : max;
  }

  /** sparkSvg draws a summary card's sparkline across [from, to]: vals[i] at times[i] (null: no
   *  value) as a line, filled down to the axis with o.area, broken where a value is missing or the
   *  next one comes more than o.gapMs later, with the time spans of o.shade shaded. The scale
   *  starts at 0 with o.zero, else just below the lowest value (sparkTop sets its top); o.short
   *  makes it lower. Decoration: hidden from screen readers, as the card says in a sentence what
   *  it shows. null without a value. */
  function sparkSvg(times, vals, from, to, o) {
    const W = 300;
    const H = o.short ? 30 : 44;
    const have = vals.filter((v) => v != null);
    if (!have.length || !(to > from)) return null;
    let lo = o.zero ? 0 : Math.min(...have);
    let hi = sparkTop(have);
    if (!o.zero) {
      const pad = Math.max((hi - lo) * 0.15, 0.5);
      lo -= pad;
      hi += pad;
    }
    if (!(hi > lo)) hi = lo + 1;
    const f = (n) => n.toFixed(1);
    const X = (t) => ((t - from) / (to - from)) * W;
    const Y = (v) => H - 2 - ((Math.min(Math.max(v, lo), hi) - lo) / (hi - lo)) * (H - 6);
    const runs = [];
    let cur = null;
    let prev = null;
    vals.forEach((v, i) => {
      const t = times[i];
      if (v == null || t == null) {
        cur = null;
        return;
      }
      if (!cur || t - prev > o.gapMs) runs.push(cur = []);
      cur.push([X(t), Y(v)]);
      prev = t;
    });
    const svg = s('svg', { class: 'spark' + (o.short ? ' is-short' : ''), viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'none', 'aria-hidden': 'true', focusable: 'false' });
    for (const [a, b] of o.shade || []) {
      const x = Math.max(0, X(a));
      const w = Math.min(W, X(b)) - x;
      if (w > 0) svg.append(s('rect', { class: 'spark-shade', x: f(x), y: 0, width: f(Math.max(w, 1)), height: H }));
    }
    const pts = (r) => r.map(([x, y]) => f(x) + ' ' + f(y)).join('L');
    if (o.area) svg.append(s('path', { class: 'area f1', d: runs.map((r) => 'M' + f(r[0][0]) + ' ' + H + 'L' + pts(r) + 'L' + f(r[r.length - 1][0]) + ' ' + H + 'Z').join('') }));
    svg.append(s('path', { class: 'ln c1', d: runs.map((r) => 'M' + pts(r) + (r.length === 1 ? 'h2' : '')).join(''), 'vector-effect': 'non-scaling-stroke' }));
    return svg;
  }

  /** rttSpark is the Internet card's sparkline: the median round trip of the internet probes in
   *  each bucket of the last 24 hours, with the buckets in which none of them got a reply shaded.
   *  Returns {svg, shaded, sentence} (the sentence says what it shows), or null. */
  function rttSpark(ser) {
    const d = seriesMemo(ser, 'rtt', () => {
      const g = seriesGeom(ser);
      if (!g) return null;
      const keys = inetKeys(ser);
      const vals = [];
      const shade = [];
      g.pts.forEach((p, i) => {
        const rtts = keys.map((k) => numOrNull(p.rtt_ms && p.rtt_ms[k])).filter((v) => v != null && v > 0);
        vals.push(medianOf(rtts));
        const loss = keys.map((k) => numOrNull(p.loss && p.loss[k])).filter((v) => v != null);
        if (loss.length && loss.every((v) => v >= 0.999)) {
          const last = shade[shade.length - 1];
          if (last && Math.abs(last[1] - g.starts[i]) < 1000) last[1] = g.starts[i] + g.stepMs;
          else shade.push([g.starts[i], g.starts[i] + g.stepMs]);
        }
      });
      return { g, vals, shade, times: g.starts.map((t) => t + g.stepMs / 2) };
    });
    if (!d) return null;
    const { g, vals, shade } = d;
    const svg = sparkSvg(d.times, vals, g.from, g.to, { zero: true, gapMs: g.stepMs * 1.5, shade });
    if (!svg) return null;
    const have = vals.filter((v) => v != null);
    const silent = shade.reduce((a, [x, y]) => a + (y - x), 0) / 1000;
    return {
      svg,
      shaded: shade.length > 0,
      sentence: 'Median internet round trip from ' + fmtMs(Math.min(...have)) + ' to ' + fmtMs(Math.max(...have)) + ' over the last 24 hours' +
        (shade.length ? '; no internet probe got a reply for ' + fmtDur(silent) + ' in all.' : '.'),
    };
  }

  /** seriesLoss is the internet probes' packet loss over a series, in percent: the share of their
   *  attempts without a reply, averaged over the buckets with data (null without data). */
  function seriesLoss(ser) {
    return seriesMemo(ser, 'loss', () => {
      const g = seriesGeom(ser);
      if (!g) return null;
      const keys = inetKeys(ser);
      let sum = 0;
      let n = 0;
      for (const p of g.pts) {
        for (const k of keys) {
          const v = numOrNull(p.loss && p.loss[k]);
          if (v != null) {
            sum += v;
            n++;
          }
        }
      }
      return n ? (100 * sum) / n : null;
    });
  }

  /** rxSpark is the Fiber card's sparkline: the light the gateway received over the last 24
   *  hours (Series.optical, dBm), broken where it read none. */
  function rxSpark(ser) {
    const d = seriesMemo(ser, 'rx', () => {
      const g = seriesGeom(ser);
      if (!g) return null;
      // Each time is read once, before the sort (not twice per comparison).
      const pts = (Array.isArray(ser.optical) ? ser.optical : []).filter((p) => p && typeof p === 'object')
        .map((p) => ({ t: toMs(p.t), v: numOrNull(p.rx_x10) == null ? null : Number(p.rx_x10) / 10 }))
        .filter((p) => p.t != null).sort((a, b) => a.t - b.t);
      const times = pts.map((p) => p.t);
      const diffs = [];
      for (let i = 1; i < times.length; i++) diffs.push(times[i] - times[i - 1]);
      return { g, times, vals: pts.map((p) => p.v), gapMs: Math.max(3 * (median(diffs) || 60000), 5 * 60000) };
    });
    if (!d) return null;
    const svg = sparkSvg(d.times, d.vals, d.g.from, d.g.to, { gapMs: d.gapMs, short: true });
    if (!svg) return null;
    const have = d.vals.filter((v) => v != null);
    return { svg, sentence: 'Light received from ' + Math.min(...have).toFixed(1) + ' to ' + Math.max(...have).toFixed(1) + ' dBm over the last 24 hours.' };
  }

  /** trafficSpark is the Traffic card's sparkline: the WAN download in each bucket of the last
   *  24 hours (Series.traffic, Mb/s), filled. */
  function trafficSpark(ser) {
    const d = seriesMemo(ser, 'traffic', () => {
      const g = seriesGeom(ser);
      if (!g) return null;
      const pts = (Array.isArray(ser.traffic) ? ser.traffic : []).filter((p) => p && typeof p === 'object')
        .map((p) => ({ t: toMs(p.t), v: numOrNull(p.wan_rx_mbps) })).filter((p) => p.t != null);
      return { g, times: pts.map((p) => p.t + g.stepMs / 2), vals: pts.map((p) => p.v) };
    });
    if (!d) return null;
    const svg = sparkSvg(d.times, d.vals, d.g.from, d.g.to, { zero: true, area: true, gapMs: d.g.stepMs * 1.5 });
    if (!svg) return null;
    const have = d.vals.filter((v) => v != null);
    return { svg, sentence: 'WAN download from ' + fmtRate(Math.min(...have)) + ' to ' + fmtRate(Math.max(...have)) + ' over the last 24 hours.' };
  }

  /** seriesFoot is the start of a sparkline card's last line: what its sparkline sp covers
   *  (shown), that the series holds none (none) - or, while the last 24 hours are not known, that
   *  they are being read or could not be read: never that nothing was measured. */
  function seriesFoot(ov, sp, shown, none) {
    if (sp) return shown;
    if (ov.series) return none;
    return ov.seriesErr ? 'The last 24 h could not be read' : 'Reading the last 24 h…';
  }

  // ------------------------------------------------------------------ overview: what each card says

  /** sumFigure is a summary card's key figure: the number, then what it counts (the space
   *  between them is for the text read out: the layout spaces them). */
  function sumFigure(num, unit) {
    return h('p', { class: 'sum-fig' }, h('span', { class: 'sum-num' }, num), unit ? [' ', h('span', { class: 'sum-unit' }, unit)] : null);
  }

  /** keepUnits keeps a number and its unit on one line ("13.7 ms", "24 h"): a card's lines
   *  wrap in narrow columns. */
  function keepUnits(text) {
    return typeof text === 'string' ? text.replace(/(\d) (?=(ms|s|min|h|d|%|dBm|[kMG]?b\/s|GB|[KMG]iB|°C)(?![\w/]))/g, '$1 ') : text;
  }

  /** sumLine is a line of a summary card; strong ones (what matters most) are in the text colour.
   *  null for nothing to say. */
  function sumLine(content, strong) {
    if (content == null || content === '' || (Array.isArray(content) && !content.length)) return null;
    return h('p', { class: 'sum-line' + (strong ? ' is-strong' : '') }, keepUnits(content));
  }

  /** sumFoot is a summary card's last line: what its sparkline covers, when it was read (start),
   *  and on the right what else to know (end). */
  function sumFoot(start, end) {
    return h('p', { class: 'sum-foot' }, h('span', null, keepUnits(start)), end ? h('span', { class: 'sum-foot-end' }, keepUnits(end)) : null);
  }

  /** sumSpark adds a sparkline (rttSpark, rxSpark, trafficSpark) to a card: the graphic, hidden
   *  from screen readers, and the sentence that says what it shows, for them. */
  function sumSpark(sp) {
    return sp ? [sp.svg, h('p', { class: 'sr-only' }, sp.sentence)] : null;
  }

  /** clockText writes a time as its time of day ("6:51:20 PM"); "?" when it is missing. */
  function clockText(v) {
    const d = toDate(v);
    return d ? F.time.format(d) : '?';
  }

  /** noData is what a card says when the monitor reports nothing for it (yet). */
  function noData(text, label) {
    return { tone: 'none', chip: ['none', label || 'No data'], body: [sumLine(text)], context: text };
  }

  /** summaryStatus is what the details "Status & availability" say in their header (the status
   *  card itself is statusCard's). */
  function summaryStatus(ov, st) {
    const v = st.verdict || {};
    const unknown = !v.state || v.state === 'UNKNOWN';
    return { tone: statusTone(st), chip: null, body: null, context: statusHeadline(st) + (st.since && !unknown ? ' for ' + sinceText(st.since, st.now) : '') };
  }

  /** gatewayWords says what still answers when no internet probe does - the AT&T gateway, as the
   *  classifier judges it (gatewayAnswered: this PC and the home network work), and the AT&T next
   *  hop -; in the past tense for the last measurement recorded (stale). */
  function gatewayWords(f, stale) {
    if (!f.gw) return 'No probe of the AT&T gateway was made.';
    if (!f.gwAnswered) return 'The AT&T gateway did not answer either.';
    let t = 'The AT&T gateway ' + (stale ? 'answered' : 'answers') + ' (' + gatewayRTTWords(f.gw) + ')';
    if (f.hop) {
      t += f.hop.ok ? (stale ? ', and so did the AT&T next hop' : ', and so does the AT&T next hop')
        : (stale ? '; the AT&T next hop did not' : '; the AT&T next hop does not');
    }
    return t + '.';
  }

  /** serviceFacts sums up a service check (Status.last_service_check): its words (the resolution
   *  queries - dnsQueryVerdict, retries included -, the web checks and the gateway's DNS hijack
   *  test), and whether a resolution query (dnsBad) or a web check (webBad) failed. */
  function serviceFacts(sc) {
    const parts = [];
    const qs = dnsQueries(sc.dns).map(dnsQueryVerdict);
    const res = qs.filter((v) => !v.test);
    const bad = res.filter((v) => v.tone !== 'good');
    if (res.length) parts.push(bad.length ? bad.map((v) => dnsCheckName(v.r) + ' ' + v.label).join(', ') : 'DNS answered');
    const web = Array.isArray(sc.http) ? sc.http.filter((r) => r && typeof r === 'object') : [];
    const ok = web.filter((r) => r.ok && !r.hijacked).length;
    if (web.length) {
      parts.push(web.some((r) => r.hijacked) ? 'a web check HIJACKED' : ok === web.length ? 'web checks OK' : ok ? `${ok} of ${web.length} web checks OK` : 'web checks failed');
    }
    const test = qs.find((v) => v.test);
    if (test) parts.push(test.label === 'HIJACKED' ? 'DNS HIJACKED' : test.tone === 'good' ? 'no DNS hijack' : 'DNS hijack test not completed');
    return { text: parts.join(' · '), dnsBad: bad.length > 0, webBad: ok < web.length };
  }

  /** summaryInternet: whether the internet probes answer, the median round trip and the packet
   *  loss of the day, the DNS, web and hijack checks; the day's round trips as a sparkline. When
   *  nothing answers, what still does (gatewayWords). Every probe answering is not enough for
   *  "OK": a line the classifier finds degraded (latency, loss over its window, DNS) or a newest
   *  service check with failures is in the warning tone, as the status card is. */
  function summaryInternet(ov, st) {
    const smp = st.last_sample;
    if (!smp) return noData('No measurements yet.');
    const stale = statusStale(st);
    const v = st.verdict || {};
    const f = probeFacts(smp);
    const n = f.inet.length;
    const k = f.ok.length;
    const sc = st.last_service_check && typeof st.last_service_check === 'object' ? st.last_service_check : null;
    const svc = sc ? serviceFacts(sc) : null;
    const hijack = !!sc && [].concat(Array.isArray(sc.dns) ? sc.dns : [], Array.isArray(sc.http) ? sc.http : []).some((r) => r && r.hijacked);
    const chipV = stale ? ['none', 'Not current']
      : hijack ? ['critical', 'Hijacked']
        : !n ? ['none', 'No probes'] : !k ? ['critical', 'No answer'] : k < n ? ['warning', `${k} of ${n} answered`]
          : v.state === 'DEGRADED' ? ['warning', capitalize(v.cause ? causeText(v.cause) : 'degraded')]
            : svc && svc.dnsBad ? ['warning', 'DNS failing'] : svc && svc.webBad ? ['warning', 'Web checks failing'] : ['good', 'OK'];
    const answered = (stale ? 'Last recorded: ' : '') + `${k} of ${n} internet probes answered`;
    const body = [];
    if (stale) body.push(sumLine('Not current: the last measurement recorded, ' + sinceText(smp.started, st.now) + ' ago.', true));
    if (hijack && !stale) body.push(sumLine('A DNS or web check was answered by something other than the real server.', true));
    if (k) {
      // The day's loss only once the day is known: until then the footer says why there is none.
      const loss = seriesLoss(ov.series);
      // The loss phrase never breaks inside ("in" / "24 h" alone on a line): the line wraps at the dot.
      body.push(sumFigure(fmtRTT(f.median), 'median round trip'),
        sumLine(answered + (loss != null ? ' · ' + ('packet loss ' + lossText(loss) + ' in 24 h').replace(/ /g, ' ') : '')));
    } else {
      body.push(sumFigure(`0 of ${n}`, 'internet probes answered'), sumLine((stale ? 'Last recorded: ' : '') + gatewayWords(f, stale)));
    }
    const sp = rttSpark(ov.series);
    body.push(sumSpark(sp),
      sumFoot(seriesFoot(ov, sp, 'Last 24 h' + (sp && sp.shaded ? ' · shaded: no reply' : ''), 'No round trips in the last 24 h'), svc ? svc.text : null));
    return { tone: chipV[0], chip: chipV, body, context: answered + ' · cycle #' + fmtInt(smp.cycle) + ' at ' + clockText(smp.started) + (smp.dur_ms != null ? ', took ' + fmtInt(smp.dur_ms) + ' ms' : '') };
  }

  /** ponWords words the fiber (PON) link as the gateway reports it: "Fiber operational (O5)". */
  function ponWords(bb, d) {
    const pon = bb.pon_link_status ? String(bb.pon_link_status) : '';
    if (!pon && d.pon_operational == null) return '';
    const ok = pon ? d.pon_operational !== false && /O5/.test(pon) : !!d.pon_operational;
    const code = (/\((O\d)\)/.exec(pon) || [])[1];
    return (ok ? 'Fiber operational' : 'Fiber not operational') + (code ? ' (' + code + ')' : pon ? ' (' + pon + ')' : '');
  }

  // GATEWAY_FRESH_S is how old a reading of the gateway's status pages may be and still count as
  // the gateway now: the classifier's default freshness of gateway snapshots
  // (incident.snapshot_freshness, 150 s: two and a half polls).
  const GATEWAY_FRESH_S = 150;

  /** gatewayReading says whether the gateway reading the status carries is current. The status
   *  keeps the last reading in which the gateway answered (Status.gateway, read at gateway_at):
   *  while the gateway does not answer this PC's newest probes (silent: as the classifier judges
   *  it), or the reading is older than the classifier would use (GATEWAY_FRESH_S), it is the last
   *  reading, not the gateway now. Returns {age (s; null: unknown), silent, current}. */
  function gatewayReading(st) {
    const age = ageSeconds(st.gateway_at, st.now);
    const f = probeFacts(st.last_sample);
    const silent = !statusStale(st) && !!f.gw && !f.gwAnswered;
    return { age, silent, current: !silent && age != null && age <= GATEWAY_FRESH_S };
  }

  /** summaryGateway: the gateway's broadband connection and fiber link as it reports them, its
   *  uptime, its WAN address and the outage redirect, and when it was read. A reading that is not
   *  current (gatewayReading) is shown as the last reading, in no tone. */
  function summaryGateway(ov, st) {
    const g = st.gateway;
    if (!g || typeof g !== 'object') return noData('No gateway snapshot yet.');
    const d = g.derived || {};
    const bb = g.broadband || {};
    const r = gatewayReading(st);
    // The monitor's reading of the page first (derived); the page's own word otherwise.
    const up = d.broadband_up != null ? !!d.broadband_up : bb.connection ? /^up$/i.test(String(bb.connection).trim()) : null;
    const word = up === true ? 'Broadband up' : up === false ? 'Broadband down' : 'Broadband unknown';
    const chipV = !r.current ? ['none', r.silent ? 'Not answering' : 'Not current']
      : up === true ? ['good', 'Up'] : up === false ? ['critical', 'Down'] : ['none', 'Unknown'];
    const n = st.notification;
    const facts = [ponWords(bb, d), d.uptime_s != null && d.uptime_s >= 0 ? 'gateway up ' + fmtDur(d.uptime_s) : ''].filter(Boolean);
    const body = [
      sumFigure(r.current ? word : 'Last reading: ' + word),
      r.current ? null : sumLine(r.silent ? 'The gateway did not answer this PC’s latest probes.' : 'No newer reading of the gateway’s status pages.', true),
      sumLine(facts.join(' · ')),
      h('dl', { class: 'sum-kv' },
        h('dt', null, 'WAN IPv4'), h('dd', { class: 'mono' }, d.wan_ipv4 || bb.ipv4 || 'none'),
        h('dt', null, 'Outage redirect'), h('dd', null, n ? (n.enabled ? chip('warning', 'On') : 'Off') : 'not checked yet')),
      sumFoot(st.gateway_at ? [r.current ? 'Polled ' : 'Last reading ', agoEl(st.gateway_at, st.now)] : 'Not polled yet'),
    ];
    const when = (r.current ? 'Polled ' : 'Last reading ') + clockText(st.gateway_at) +
      (r.current ? '' : r.silent ? ' · the gateway does not answer now' : ' · no newer reading');
    return { tone: chipV[0], chip: chipV, body, context: when + (d.model ? ' · ' + d.model : '') + (d.firmware ? ' · firmware ' + d.firmware : '') };
  }

  /** measureTone is the gateway's own verdict on a measure: its alarm flag (critical), its
   *  warning flag (warning) or neither (good). */
  function measureTone(m) {
    const on = (x) => !!(x && x.active);
    if (on(m.low_alarm) || on(m.high_alarm)) return 'critical';
    if (on(m.low_warning) || on(m.high_warning)) return 'warning';
    return 'good';
  }

  // The gateway's fiber module measures (its fiberstat page), as a summary card names them.
  const MEASURE_WORDS = dict({ 'rx power': 'received light', 'tx power': 'transmit power', temperature: 'module temperature', 'tx bias': 'laser bias', vcc: 'supply voltage' });

  /** fiberFlags is what the gateway flags among its fiber module's measures, each of which has its
   *  own alarm and warning flags (DMI): the worst tone ("good" for none), and each measure flagged
   *  in words with its flag, the received light's (rx) apart from the others ("module
   *  temperature (high alarm)"). */
  function fiberFlags(fb) {
    const flagged = (Array.isArray(fb.measures) ? fb.measures : []).filter((m) => m && typeof m === 'object' && measureTone(m) !== 'good');
    const words = (m) => {
      const name = String(m.name == null ? '' : m.name);
      const flag = ['low_alarm', 'high_alarm', 'low_warning', 'high_warning'].find((k) => m[k] && m[k].active);
      return (MEASURE_WORDS[name.trim().toLowerCase()] || name || 'a measure') + ' (' + flag.replace('_', ' ') + ')';
    };
    const isRx = (m) => String(m.name || '').trim().toLowerCase() === 'rx power';
    return {
      tone: flagged.some((m) => measureTone(m) === 'critical') ? 'critical' : flagged.length ? 'warning' : 'good',
      rx: flagged.filter(isRx).map(words),
      others: flagged.filter((m) => !isRx(m)).map(words),
    };
  }

  /** summaryFiber: the light the gateway receives on a gauge with the gateway's own alarm and
   *  warning thresholds, the flags of every measure of its fiber module (named when they are not
   *  the received light's, which the gauge shows), the transmit power and the module's
   *  temperature; the day's received light as a sparkline. No level where the gateway reports
   *  loss of signal is no light, not a missing reading. A reading that is not current
   *  (gatewayReading) says so, in no tone. */
  function summaryFiber(ov, st) {
    const fb = st.gateway && st.gateway.fiber;
    if (!fb || typeof fb !== 'object') return noData('No fiber status from the gateway yet.');
    const r = gatewayReading(st);
    const rx = findMeasure(fb, 'rx power');
    const tx = findMeasure(fb, 'tx power');
    const temp = findMeasure(fb, 'temperature');
    const flags = fiberFlags(fb);
    const chipV = !r.current ? ['none', 'Not current']
      : flags.tone === 'critical' ? ['critical', 'Gateway alarm'] : flags.tone === 'warning' ? ['warning', 'Gateway warning']
        : !rx ? ['none', 'No reading'] : ['good', 'No gateway flag'];
    const has = !!rx && numOrNull(rx.current) != null;
    // The gateway's own loss-of-signal flag first; its optical link down otherwise.
    const d = (st.gateway && st.gateway.derived) || {};
    const los = !has && (String(fb.rx_los_state == null ? '' : fb.rx_los_state).trim() === '1' || d.optical_up === false);
    const last = r.current ? '' : ' at the last reading' + (st.gateway_at ? ', ' + sinceText(st.gateway_at, st.now) + ' ago' : '');
    const thr = (x) => (x && x.threshold != null ? fmtMeasure(x.threshold, rx.unit) : null);
    const limits = rx ? [thr(rx.low_alarm) ? 'alarm ' + thr(rx.low_alarm) : '', thr(rx.low_warning) ? 'warning ' + thr(rx.low_warning) : ''].filter(Boolean) : [];
    const sp = rxSpark(ov.series);
    const body = [
      has ? sumFigure(fmtMeasure(rx.current, rx.unit), 'light received' + last)
        : los ? sumFigure('No light', 'the gateway reports loss of signal on the fiber' + last)
          : sumFigure('No reading', 'the gateway reports no received light level' + last),
      has ? bullet(rx, true) : null,
      limits.length ? h('p', { class: 'sum-scale' }, 'The gateway’s low ' + limits.join(' · ')) : null,
      flags.others.length ? sumLine('Flagged by the gateway: ' + flags.rx.concat(flags.others).join(', '), true) : null,
      sumLine([tx ? 'Transmit ' + measureValue(tx) : '', temp ? 'module ' + measureValue(temp) : ''].filter(Boolean).join(' · ')),
      sumSpark(sp),
      sumFoot(seriesFoot(ov, sp, 'Last 24 h', 'No optical readings in the last 24 h')),
    ];
    const what = has ? 'Received light ' + fmtMeasure(rx.current, rx.unit) : los ? 'No light received (loss of signal)' : 'No received light level';
    return { tone: chipV[0], chip: chipV, body, context: what + ' · ' + chipV[1].toLowerCase() };
  }

  /** rateFigure is one direction of the live traffic as a key figure: its colour key, the rate
   *  and the direction. */
  function rateFigure(key, v, dir, atLeast) {
    const [num, unit] = rateParts(v);
    return h('span', { class: 'sum-rate' }, key, v != null && atLeast ? [h('span', { class: 'sum-unit' }, 'at least'), ' '] : null,
      h('span', { class: 'sum-num' }, num), ' ', h('span', { class: 'sum-unit' }, (unit ? unit + ' ' : '') + dir));
  }

  // A flow meter reading older than this is no longer shown as the traffic now (the meter reads
  // every LIVE_REFRESH_MS): the Traffic card gives its time and what it showed instead.
  const LIVE_OLD_MS = 60000;

  /** summaryTraffic: the flow meter's reading (download and upload through the gateway now), the
   *  day's WAN volume and the day's download as a sparkline. A read the monitor skipped while it
   *  used the gateway itself (its evidence snapshot, a settings check, a NAT read: "skipped: …",
   *  internal/monitor errLiveBusy) is a wait for the next one, not a failure (flowContent says so
   *  too). Only a reading of the last few reads is "Live": one that failed or is older (the meter
   *  reads only while the card or its details are on screen) names its time, and once it is a
   *  minute old its rates are not shown as the traffic now. A monitor without a flow meter says
   *  so. */
  function summaryTraffic(ov, st) {
    const live = ov.live;
    const lt = live && live.lt;
    const err = lt && lt.error ? String(lt.error) : '';
    const skipped = /^skipped\b/i.test(err);
    const failed = !!(live && (live.failure || (err && !skipped)));
    const age = lt && lt.at ? ageSeconds(lt.at) : null;
    const old = age != null && age * 1000 > 3 * LIVE_REFRESH_MS;
    const gone = age != null && age * 1000 > LIVE_OLD_MS;
    const chipV = live && live.unavailable ? ['none', 'No live reading'] : !live ? ['none', 'Reading…']
      : failed ? ['warning', 'No new reading'] : old ? ['none', 'Not current'] : ['info', 'Live'];
    const body = [];
    if (live && live.unavailable) {
      body.push(sumLine(live.unavailable));
    } else {
      const atLeast = !!(lt && lt.at_least);
      const rx = lt ? numOrNull(lt.wan_rx_mbps) : null;
      const tx = lt ? numOrNull(lt.wan_tx_mbps) : null;
      body.push(h('p', { class: 'sum-fig sum-rates' },
        rateFigure(areaKey(1), gone ? null : rx, 'down', atLeast), ' ', rateFigure(lineKey(2), gone ? null : tx, 'up', atLeast)));
      if (lt && lt.at && (failed || old)) {
        const was = gone && (rx != null || tx != null) ? ': ' + fmtRate(rx) + ' down · ' + fmtRate(tx) + ' up' : '';
        body.push(sumLine('Reading of ' + clockText(lt.at) + ' (' + sinceText(lt.at) + ' ago)' + was, true));
      }
      if (failed) body.push(sumLine('The newest read failed: ' + sentence(live.failure ? live.failure.message : err)));
    }
    const today = localDateValue(new Date());
    const day = (ov.series && Array.isArray(ov.series.traffic_days) ? ov.series.traffic_days : []).find((x) => x && x.day === today);
    if (day) body.push(sumLine('Today ' + fmtGB(day.rx_bytes) + ' down · ' + fmtGB(day.tx_bytes) + ' up' + (day.complete ? '' : ' (at least: part of the day is not counted)')));
    const sp = trafficSpark(ov.series);
    body.push(sumSpark(sp), sumFoot(seriesFoot(ov, sp, 'WAN download, last 24 h', 'No traffic readings in the last 24 h')));
    return { tone: chipV[0], chip: chipV, body, context: 'Through the AT&T gateway, from its own byte counters' + (lt && lt.at ? ' · reading of ' + clockText(lt.at) : '') };
  }

  /** summaryLink: this PC's network adapter, its signal and link rate, and whether its traffic
   *  goes through the AT&T gateway: traffic that leaves through another adapter (a VPN, another
   *  network) is a warning, as everywhere else. While the Internet is out but the gateway answers
   *  (as the classifier judges it), it says that the home network works: that is what attributes
   *  an outage to AT&T - except while the outage is this PC's routing (LOCAL_ROUTE), where it says
   *  that the traffic does not go through the gateway. */
  function summaryLink(ov, st) {
    const l = st.local_link;
    if (!l || typeof l !== 'object') return noData('Not measured yet.');
    const connected = /^connected$/i.test(String(l.state || ''));
    const e = l.egress && typeof l.egress === 'object' ? l.egress : null;
    const bypass = !!(e && !e.err && e.bypass);
    const chipV = !l.state ? ['none', 'Unknown'] : !connected ? ['critical', capitalize(String(l.state))]
      : bypass ? ['warning', 'Not through the gateway'] : ['good', 'Connected'];
    const fig = l.type === 'wifi' ? 'Wi-Fi' + (l.band ? ' ' + l.band : '') : l.type === 'ethernet' ? 'Ethernet' : String(l.interface || 'Network adapter');
    const facts = [];
    if (l.signal_pct) facts.push('Signal ' + l.signal_pct + ' %');
    if (l.rx_mbps || l.tx_mbps) facts.push('receive ' + (l.rx_mbps || '—') + ' / send ' + (l.tx_mbps || '—') + ' Mb/s');
    else if (l.link_mbps) facts.push('link ' + l.link_mbps + ' Mb/s');
    const route = !e ? null : e.err ? 'Route to the Internet: not checked'
      : bypass ? 'Route to the Internet: through another adapter (a VPN or another network)' : 'Route to the Internet: through the AT&T gateway';
    const f = probeFacts(st.last_sample);
    const homeWorks = connected && !statusStale(st) && f.gw && f.gwAnswered && f.inet.length && !f.ok.length;
    const routed = bypass && (st.verdict || {}).cause === 'LOCAL_ROUTE';
    const body = [
      sumFigure(fig),
      sumLine(facts.join(' · ')),
      l.signal_pct ? h('p', { class: 'sum-meter' }, meter(l.signal_pct), h('span', null, l.signal_pct + ' %')) : null,
      sumLine(route, true),
      !homeWorks ? null : routed ? sumLine('This PC reaches the AT&T gateway, but its internet traffic does not go through it.', true)
        : sumLine('The home network works: this PC reaches the AT&T gateway.', true),
    ];
    return { tone: chipV[0], chip: chipV, body, context: [l.interface, l.ssid, l.local_ip].filter(Boolean).map(String).join(' · ') || 'This PC’s network adapter' };
  }

  /** topOrgs is the organisations of the connections (the flow diagram's) without its groups -
   *  "other" (the rest), "local" (private addresses) and "unknown" (addresses the IP database
   *  does not know) -, ranked by the sites reached: the Network card names the first ones as the
   *  most used, and its details list them in the same order, so that the two never disagree. */
  function topOrgs(conn) {
    return netList(conn && conn.orgs).filter((o) => !['other', 'local', 'unknown'].includes(String(o.key)))
      .sort((a, b) => (Number(b.sites) || 0) - (Number(a.sites) || 0));
  }

  /** orgNames names the n most used organisations of the connections (topOrgs). */
  function orgNames(conn, n) {
    return topOrgs(conn).slice(0, n).map((o) => netText(o.name || o.key, 32));
  }

  /** summaryNetwork: the connections open at the last read of the NAT table, the devices the
   *  gateway lists, the most used organisations, and what the firewall blocked in 24 h. A monitor
   *  without the Network page, or a feature it does not have, is said so. */
  function summaryNetwork(ov, st) {
    const smp = st.connections && typeof st.connections === 'object' ? st.connections : null;
    const net = ov.net;
    if (!smp && net && net.none) return noData('This monitor offers no Network page.', 'Not offered');
    const age = smp && smp.nat_at ? ageSeconds(smp.nat_at, st.now) : null;
    // In whole minutes past the first: the chip neither changes every 10 s nor covers the title.
    const read = age != null ? fmtDur(age >= 60 ? Math.floor(age / 60) * 60 : age) : '';
    const chipV = !smp ? ['none', net ? 'No data' : 'Reading…']
      : !smp.enabled ? ['none', 'Off'] : smp.nat_problem ? ['warning', 'Not reading']
        : smp.nat_at ? ['info', 'Read ' + read + ' ago'] : ['none', 'Not read yet'];
    const body = [];
    if (smp && smp.nat_at) {
      const every = goDurMs(smp.interval);
      const fresh = age != null && age * 1000 <= Math.max(10 * 60e3, 2.5 * (every || 4 * 60e3));
      const listed = Number(smp.devices) > 0 ? ' · ' + fmtInt(smp.devices) + ' devices listed' : '';
      body.push(sumFigure(fmtInt(smp.sessions), (fresh ? 'connections open' : 'connections open at the last read, ' + fmtDur(age) + ' ago') + listed));
      if (smp.nat_problem) body.push(sumLine(sentence(capitalize(String(smp.nat_problem))), true));
    } else if (smp && !smp.enabled) {
      body.push(sumLine('Reading the gateway’s NAT table is turned off in the configuration.'));
    } else if (smp && smp.nat_problem) {
      body.push(sumLine(sentence(capitalize(String(smp.nat_problem))), true));
    } else if (smp) {
      body.push(sumLine('The NAT table has not been read yet.'));
    } else {
      body.push(sumLine('This monitor reports nothing about its reads of the NAT table.'));
    }
    const orgs = net && net.conn ? orgNames(net.conn, 3) : [];
    if (orgs.length) body.push(sumLine('Most used: ' + orgs.join(', ')));
    const fw = net && net.fw;
    const ff = firewallFacts(net, st);
    if (fw && !net.fwErr) {
      body.push(h('div', { class: 'sum-split' },
        sumFigure(fmtInt(fw.drops), 'packets blocked by the firewall ' + (ff.since ? 'since ' + shortWhen(ff.since) : 'in 24 h')),
        sumLine(fmtInt(fw.inbound) + ' inbound probes from ' + fmtInt(fw.sources) + ' addresses'),
        ff.unseen ? sumLine(ff.unseen, true) : null));
    } else if (net && net.fwErr && ff.noStore) {
      body.push(sumLine('Firewall: this monitor keeps no syslog store, so it shows no blocked packets.'));
    } else if (net && net.fwErr && net.fwErr.status !== 404) {
      body.push(sumLine('The firewall figures could not be read: ' + sentence(net.fwErr.message)));
    }
    return { tone: chipV[0], chip: chipV, body, context: smp && smp.nat_at ? 'NAT table read ' + sinceText(smp.nat_at, st.now) + ' ago' + (Number(smp.devices) > 0 ? ' · ' + fmtInt(smp.devices) + ' devices listed' : '') : 'Which device talks to which site, and what the firewall blocks' };
  }

  /** firewallFacts says what the firewall's figures (net.fw: counted from the syslog the store
   *  kept) can claim, as the Network page's notes say it (fwNotes, fwCoverage): unseen - why
   *  blocked packets are not seen now (the receiver is off, or the gateway does not send its log
   *  here), '' when they are -; since - when the syslog kept starts, when that is after the
   *  period's start (the count covers less than 24 hours); noStore - the figures are missing
   *  because the monitor keeps no syslog store (a 503 alone may also be a store that is closed or
   *  busy). */
  function firewallFacts(net, st) {
    const sl = syslogStatus(st);
    const fw = net && net.fw;
    const oldest = fw ? toMs(fw.oldest) : null;
    const from = fw ? toMs(fw.from) : null;
    return {
      unseen: !sl ? '' : !sl.enabled ? 'The syslog receiver is off: blocked packets are not seen.'
        : sl.state === 'off' || sl.state === 'elsewhere' ? 'The gateway does not send its log to this PC: blocked packets are not seen.' : '',
      since: oldest != null && from != null && oldest > from ? fw.oldest : null,
      noStore: !!(net && net.fwErr && net.fwErr.status === 503 && !syslogStore(sl)),
    };
  }

  /** shortWhen writes a time as netTimeEl shows it, as text: its time of day when it is today,
   *  else with its date. */
  function shortWhen(v) {
    const d = toDate(v);
    return d ? (localDateValue(d) === localDateValue(new Date()) ? F.hm : F.short).format(d) : '?';
  }

  /** syslogSettingWords says where the gateway sends its log, as last read (Status.syslog.state). */
  function syslogSettingWords(sl) {
    const g = sl.gateway && typeof sl.gateway === 'object' ? sl.gateway : null;
    const level = g && g.level ? ' (level ' + g.level + ')' : '';
    switch (sl.state || (!g ? 'unknown' : g.enabled ? '' : 'off')) {
      case 'ok': return 'The gateway sends its log to this PC' + level;
      case 'off': return 'The gateway sends no syslog messages';
      case 'elsewhere': return 'The gateway sends its log to ' + (syslogTarget(g) || 'another address') + ', not to this PC';
      case 'error': return 'The gateway’s Syslog setting could not be checked';
      case 'unknown':
        if (sl.problem) return sentence(capitalize(String(sl.problem)));
        return g ? 'The gateway’s Syslog page was not understood' : 'The gateway’s Syslog setting has not been read yet';
      default: return 'The gateway sends its log to ' + (syslogTarget(g) || '?') + level;
    }
  }

  // The Gateway syslog card's chip while this PC listens but the gateway's setting, as last read,
  // sends nothing here (Status.syslog.state; the details show it as a warning too).
  const SYSLOG_GATEWAY_CHIPS = dict({ off: ['warning', 'Gateway not sending'], elsewhere: ['warning', 'Sent elsewhere'], error: ['warning', 'Setting not checked'] });

  /** summarySyslog: whether this PC listens for the gateway's log, the messages received, where
   *  the gateway sends it, how much the syslog store keeps of its limit, the last message. A
   *  receiver that listens while the gateway sends its log elsewhere or not at all (or its setting
   *  could not be checked) collects nothing: the card is in the warning tone, as its details. */
  function summarySyslog(ov, st) {
    const sl = syslogStatus(st);
    if (!sl) return noData('This monitor reports no syslog receiver.', 'Not offered');
    const gw = sl.enabled && sl.listening ? SYSLOG_GATEWAY_CHIPS[sl.state] || null : null;
    const chipV = !sl.enabled ? ['none', 'Off'] : sl.listening ? gw || ['good', 'Listening']
      : sl.listen_error ? ['critical', 'Not listening'] : ['none', 'Not listening yet'];
    const u = syslogStore(sl);
    const limit = u && Number(u.keep_mb) > 0 ? Number(u.keep_mb) * MIB : 0;
    const body = [
      sumFigure(fmtInt(Number(sl.received) || 0), 'messages since the service started'),
      sl.enabled && !sl.listening && sl.listen_error ? sumLine(sentence(capitalize(String(sl.listen_error))), true) : null,
      sumLine(syslogSettingWords(sl), !!gw),
      u ? h('p', { class: 'sum-meter' }, limit ? meter((100 * (Number(u.bytes) || 0)) / limit) : null, h('span', null, syslogUsageText(u)))
        : sumLine('This monitor keeps no syslog store.'),
      sumFoot(sl.last_at ? ['Last message ', agoEl(sl.last_at, st.now)] : 'No message since the service started'),
    ];
    const rx = !sl.enabled ? 'Receiver off' : sl.listening ? 'Listening on UDP ' + (sl.listen || '?') : sl.listen_error ? 'Not listening' : 'Not listening yet';
    return { tone: chipV[0], chip: chipV, body, context: rx + ' · ' + syslogSettingWords(sl) };
  }

  /** mongoWords sums up the MongoDB copy of the ledger (Status.mongo; optional). */
  function mongoWords(m) {
    if (!m || typeof m !== 'object') return '';
    if (!m.connected && !m.has_data) return 'no MongoDB server (the copy is optional)';
    if (!m.connected) return 'MongoDB copy not connected';
    if (m.last_error) return 'MongoDB copy: a problem';
    if (!m.has_data) return 'MongoDB copy starting';
    return Number(m.lag) > 0 ? 'MongoDB copy ' + fmtInt(m.lag) + ' records behind' : 'MongoDB copy in sync';
  }

  /** summaryEvidence: the signed records, the last time-stamp, the MongoDB copy and the last
   *  verification; whether evidence is being recorded at all. */
  function summaryEvidence(ov, st) {
    const L = st.ledger || {};
    const lv = L.last_verify;
    const failing = !!findCondition(st, 'LEDGER_WRITE_FAILING');
    const head = numOrNull(L.head_seq);
    const chipV = failing ? ['critical', 'Not recording'] : lv && lv.ok === false ? ['critical', 'Verify failed']
      : head != null ? ['good', 'Recording'] : ['none', 'No data'];
    const mongo = mongoWords(st.mongo);
    const verify = lv ? [lv.ok ? 'verified ' : 'verification FAILED ', timeEl(lv.at, F.short)] : ['not verified yet'];
    if (!mongo) verify[0] = capitalize(verify[0]);
    const body = [
      sumFigure(head != null ? fmtInt(head + 1) : '—', 'signed records'),
      failing ? sumLine('The ledger refuses new records: nothing is being recorded.', true) : null,
      sumLine(L.last_anchor_time ? ['Last time-stamp ', agoEl(L.last_anchor_time, st.now), ' (' + tsaName(L.last_anchor_tsa) + ')'] : 'No time-stamp yet'),
      sumLine([mongo ? capitalize(mongo) + ' · ' : null, verify], true),
      sumFoot(fmtInt(L.unanchored_records) + ' records not yet time-stamped'),
    ];
    return { tone: chipV[0], chip: chipV, body, context: (head != null ? fmtInt(head + 1) + ' signed records' : 'No ledger head reported') + (L.last_anchor_time ? ' · last time-stamp ' + sinceText(L.last_anchor_time, st.now) + ' ago' : '') };
  }

  /** clockWords says how far this computer's clock is from internet time (the first time server
   *  that answered the latest clock check). */
  function clockWords(ck) {
    const results = ck && Array.isArray(ck.results) ? ck.results.filter((r) => r && typeof r === 'object') : [];
    if (!results.length) return 'Clock not checked yet';
    const r = results.find((x) => x.ok);
    if (!r) return 'No time server answered the latest clock check';
    const ms = Number(r.offset_ms) || 0;
    return 'Clock ' + (ms >= 0 ? '+' : '') + fmtInt(ms) + ' ms from ' + r.server;
  }

  /** summaryMonitor: how long the monitor has run and as what, its version and cycles, and this
   *  computer's clock. */
  function summaryMonitor(ov, st) {
    const m = st.monitor && typeof st.monitor === 'object' ? st.monitor : {};
    const stale = statusStale(st);
    const off = findCondition(st, 'CLOCK_OFFSET');
    const chipV = stale ? ['warning', 'Not measuring'] : off ? ['warning', 'Clock off']
      : m.started || m.uptime_s ? ['good', 'Running'] : ['none', 'No data'];
    const mode = m.mode ? (String(m.mode) === 'service' ? 'as a Windows service' : 'running as ' + m.mode) : 'running';
    const body = [
      sumFigure(m.uptime_s != null ? fmtDur(m.uptime_s) : '—', mode),
      stale ? sumLine('No measurement cycle is being recorded.', true) : null,
      sumLine([m.version ? 'Version ' + m.version : '', m.cycles != null ? fmtInt(m.cycles) + ' measurement cycles' : ''].filter(Boolean).join(' · ')),
      sumLine(clockWords(st.clock), true),
      m.rules ? sumFoot('Classifier rules ' + m.rules) : null,
    ];
    const running = m.mode ? 'running as ' + m.mode + (m.uptime_s != null ? ' for ' + fmtDur(m.uptime_s) : '') : '';
    return { tone: chipV[0], chip: chipV, body, context: [m.version ? 'Version ' + m.version : '', running].filter(Boolean).join(' · ') || 'The monitor and this computer’s clock' };
  }

  // ------------------------------------------------------------------ overview: the details modal

  /** onBackdrop reports whether a pointer event on a modal dialog fell on its backdrop: the
   *  backdrop belongs to the dialog element (it is the target), outside the dialog's box. */
  function onBackdrop(dlg, ev) {
    if (ev.target !== dlg) return false;
    const r = dlg.getBoundingClientRect();
    return ev.clientX < r.left || ev.clientX > r.right || ev.clientY < r.top || ev.clientY > r.bottom;
  }

  /** lockScroll keeps the page behind a modal from scrolling (the root element's overflow). The
   *  room of the scroll bar this takes away goes to the body as padding, so that nothing moves
   *  sideways - not to a gutter kept for it (scrollbar-gutter), which the modal's backdrop does
   *  not cover: a band of the page would stay bright beside the dimmed rest, and a modal as wide
   *  as the window would reach under it. */
  function lockScroll(on) {
    const root = document.documentElement;
    if (!on) {
      root.classList.remove('detail-open');
      document.body.style.paddingRight = '';
      return;
    }
    const bar = window.innerWidth - root.clientWidth; // measured while the scroll bar is there
    root.classList.add('detail-open');
    if (bar > 0) document.body.style.paddingRight = bar + 'px'; // CSSOM: allowed by the CSP
  }

  /** stampKeys gives every focusable element of root, and every <details>, a key (data-fk) by
   *  which keepFocus finds its successor after a rebuild: its tag, its link and its text, and how
   *  many before it share them. Keys set by the code (charts, ...) are kept. */
  function stampKeys(root) {
    const seen = new Map();
    for (const el of root.querySelectorAll('a, button, summary, details, input, select, textarea, [tabindex]')) {
      const own = el.getAttribute('data-fk');
      if (own && !own.startsWith('auto|')) continue;
      const sum = el.localName === 'details' ? el.querySelector('summary') : null;
      const base = el.localName + '|' + (el.getAttribute('href') || '') + '|' + (sum || el).textContent.trim().slice(0, 80);
      const n = seen.get(base) || 0;
      seen.set(base, n + 1);
      el.setAttribute('data-fk', 'auto|' + base + '|' + n);
    }
  }

  /** keepReading runs render, which rebuilds parts of a details modal's body (dlg, body) for a
   *  status update, so that the reader keeps their place: the scroll position, the <details>
   *  they opened and the keyboard focus (keepFocus, by stampKeys' keys). When the element with
   *  the focus is gone without a successor, the body takes it: the focus stays in the dialog.
   *  While the reader has text selected in the body (an address or a hash to copy), nothing is
   *  rebuilt: the first update after the selection is gone is. */
  function keepReading(dlg, body, render) {
    const sel = typeof window.getSelection === 'function' ? window.getSelection() : null;
    if (sel && !sel.isCollapsed && sel.anchorNode && body.contains(sel.anchorNode)) return;
    stampKeys(body);
    const opened = new Set(Array.from(body.querySelectorAll('details')).filter((d) => d.open).map((d) => d.getAttribute('data-fk')));
    const top = body.scrollTop;
    const inside = dlg.contains(document.activeElement);
    keepFocus(body, () => {
      render();
      stampKeys(body);
      for (const d of body.querySelectorAll('details')) if (!d.open && opened.has(d.getAttribute('data-fk'))) d.open = true;
    });
    body.scrollTop = top;
    if (inside && !dlg.contains(document.activeElement)) body.focus();
  }

  /** detailModal is the Overview's details modal (docs/overview-redesign.md §3): one card's
   *  details at a time on a native <dialog> opened with showModal() - the page behind is inert,
   *  and does not scroll (lockScroll) -, labelled by its heading, with a line of context and a
   *  close button. Esc, the close button and a click on the backdrop close it; the keyboard focus
   *  goes to the close button, and back to the card's button. The address names it: opened by a
   *  click it is added to the history (#/?detail=<key>: Back closes it, a reload opens it again)
   *  and closing it goes back; opened from the address (a link, a reload, Back or Forward), closing
   *  it replaces the address. While open its content follows every status update (update;
   *  keepReading keeps the reader's place) and its charts their series; while the status cannot
   *  be read, it says so (stale). Its body is a scroll region of its own (a Tab stop: the keyboard
   *  scrolls it), and it has its own live region for announce(), as the page's is inert behind
   *  it. Returns {open(key, how), sync(query) (the route's onQuery), update(st), stale(err),
   *  key}. */
  function detailModal(c, ov) {
    let cur = null; // {key, how, dlg, body, ico, titles, context, contextText, staleNote, ctx, from, why, done, part}
    let backPending = false; // our history.back() has not arrived yet: a click now would race it
    let backTimer = 0;
    const backDone = () => {
      backPending = false;
      window.clearTimeout(backTimer);
    };
    window.addEventListener('hashchange', backDone);
    ov.ctx.cleanup(() => {
      window.removeEventListener('hashchange', backDone);
      window.clearTimeout(backTimer);
      if (cur) close(cur, 'dispose');
    });

    function open(key, how) {
      const d = DETAILS[key];
      if (!d || backPending || !ov.ctx.alive) return;
      if (cur) {
        if (cur.key === key) return;
        close(cur, 'address');
      }
      const ico = h('span', { class: 'detail-ico-box' }, icon('none', 'detail-ico'));
      const context = h('p', { class: 'detail-context', id: 'detail-context' }, 'Loading…');
      const titles = h('div', { class: 'detail-titles' }, h('h2', { id: 'detail-title' }, d.title), context);
      const closeBtn = h('button', { type: 'button', class: 'btn detail-close', title: 'Close (Esc)' }, closeIcon(), h('span', { class: 'sr-only' }, 'Close'));
      // The body is the dialog's scroll region and a Tab stop of its own, so that PageDown and the
      // arrow keys scroll it where it holds no control (the focus starts on Close, in the header).
      const body = h('div', { class: 'detail-body', tabindex: '0', role: 'region', 'aria-labelledby': 'detail-title' });
      const dlg = h('dialog', { class: 'dlg dlg-detail', 'aria-labelledby': 'detail-title', 'aria-describedby': 'detail-context', 'data-detail': key },
        h('div', { class: 'detail-head' }, ico, titles, closeBtn), body, announcer());
      const e = { key, how, dlg, body, ico, titles, context, contextText: '', staleNote: null, ctx: newViewCtx(), from: window.location.hash, why: '', done: false, part: null };
      closeBtn.addEventListener('click', () => close(e, 'user'));
      dlg.addEventListener('close', () => finish(e)); // Esc, or close() below
      let fromBackdrop = false;
      // The rest of a double-click that opened these details lands on them, wherever they now lie
      // under the pointer (their backdrop, their close button, a link, a chart's legend), and must
      // do nothing - neither act, nor move the focus from Close, nor select a word: it is taken
      // before anything inside sees it.
      const openedAt = Date.now();
      const swallow = (ev) => {
        if (!(ev.detail > 1) || Date.now() - openedAt >= 1000) return;
        ev.preventDefault();
        ev.stopImmediatePropagation();
        fromBackdrop = false;
      };
      dlg.addEventListener('mousedown', swallow, true);
      dlg.addEventListener('click', swallow, true);
      // Only a click that also started on the backdrop closes: not one that selected text inside
      // and ended outside.
      dlg.addEventListener('pointerdown', (ev) => { fromBackdrop = onBackdrop(dlg, ev); });
      dlg.addEventListener('click', (ev) => {
        if (fromBackdrop && onBackdrop(dlg, ev)) close(e, 'user');
        fromBackdrop = false;
      });
      cur = e;
      e.part = d.mount(ov, e);
      c.append(dlg);
      lockScroll(true);
      dlg.showModal();
      closeBtn.focus();
      if (how === 'click') {
        window.history.pushState(null, '', '#/?detail=' + encodeURIComponent(key));
        ov.ctx.hash = window.location.hash;
      }
      update(app.status);
      if (app.statusError) stale(app.statusError); // opened while the status cannot be read
      ov.flow.wake();
    }

    /** close closes the details shown (e) for why: "user" (the reader: the close button, the
     *  backdrop; Esc closes the dialog itself), "address" (the address no longer names them) or
     *  "dispose" (the Overview is left). */
    function close(e, why) {
      if (e.done) return;
      e.why = why;
      if (e.dlg.open) e.dlg.close();
      finish(e);
    }

    function finish(e) {
      if (e.done) return;
      e.done = true;
      if (cur === e) cur = null;
      e.ctx.dispose();
      e.dlg.remove();
      lockScroll(false);
      if (e.why === 'dispose') return;
      if (e.why !== 'address') forget(e);
      const card = ov.cards[e.key];
      if (card && document.contains(card.btn)) card.btn.focus();
      ov.flow.wake();
    }

    /** forget takes closed details out of the address: details a click added to the history are
     *  gone back from (the history is as before they opened), details opened from the address
     *  replace it with the Overview's. */
    function forget(e) {
      if (e.how === 'click') {
        ov.ctx.hash = e.from;
        backPending = true;
        backTimer = window.setTimeout(backDone, 500);
        window.history.back();
      } else {
        window.history.replaceState(null, '', '#/');
        ov.ctx.hash = window.location.hash;
      }
    }

    /** sync follows the address (route's onQuery): it opens the details it names, closes those it
     *  no longer names, and ignores a card it does not know. false: nothing to do in place (the
     *  Overview is rendered again, as for any visit). */
    function sync(query) {
      backDone();
      const key = query.get('detail');
      if (key == null) {
        if (!cur) return false;
        close(cur, 'address');
        return true;
      }
      if (DETAILS[key]) open(key, 'address');
      else if (cur) close(cur, 'address');
      return true;
    }

    /** update follows a status update: the header's icon and line of context, and the content.
     *  While the status cannot be read (a part read the details' own figures meanwhile), the
     *  header keeps saying so (stale). */
    function update(st) {
      const e = cur;
      if (!e || !e.part || !st) return;
      const v = DETAILS[e.key].summary(ov, st);
      e.contextText = v.context || '';
      keepReading(e.dlg, e.body, () => e.part.update(st));
      if (app.statusError) {
        stale(app.statusError);
        return;
      }
      if (e.staleNote) {
        e.staleNote.remove();
        e.staleNote = null;
      }
      replace(e.ico, icon(v.tone, 'detail-ico'));
      replace(e.context, e.contextText, ' · updates while open');
    }

    /** stale says in the details open that the status could not be read (err): the page's banner
     *  (#conn) is behind the modal, and inert under it. The header loses its tone and says since
     *  when nothing was updated, and a note under it (visible at any scroll position) says why: made
     *  once, when the status stops being read, so that its alert is read once. The next status
     *  read takes both away (update). */
    function stale(err) {
      const e = cur;
      if (!e) return;
      const since = app.statusAt ? 'not updated since ' + F.time.format(app.statusAt) : 'no status read yet';
      replace(e.ico, icon('none', 'detail-ico'));
      replace(e.context, e.contextText ? e.contextText + ' · ' + since : capitalize(since));
      if (e.staleNote) return;
      const why = err && err.status === 0 ? 'the att-monitor service cannot be reached.' : 'the monitor returned an error: ' + sentence(err ? err.message : '');
      e.staleNote = notice('critical', h('strong', null, capitalize(since) + ': '), why + ' What these details show may be out of date.');
      e.staleNote.classList.add('detail-stale');
      e.titles.append(e.staleNote);
    }

    return { open, sync, update, stale, get key() { return cur ? cur.key : ''; } };
  }

  /** detailLinks is a details modal's pointer to the page that shows more. */
  function detailLinks(...kids) {
    return h('p', { class: 'detail-links' }, ...kids);
  }

  // The key of what a part of a details modal shows, by its element (keyed).
  const partKeys = new WeakMap();

  /** keyed draws a part of a details modal (el) again with build()'s content only when what it
   *  shows changed (key: its inputs, a relative time it words included). A status update every
   *  10 s must not replace a link, a <details> or a text the reader is on with a copy of it: the
   *  keyboard focus would move to the copy, a screen reader would announce it again, and a text
   *  selection would go. */
  function keyed(el, key, build) {
    if (partKeys.get(el) === key) return;
    partKeys.set(el, key);
    replace(el, build());
  }

  /** detailsStatus: the status as the classifier words it (statusHero: the reasons, the records it
   *  was classified from, the incident in progress) and the availability history. */
  function detailsStatus(ov, m) {
    const hero = statusHero();
    const charts = h('section', { class: 'detail-charts', 'aria-label': 'Availability history' });
    m.body.append(hero.el, charts);
    setupCharts(charts, m.ctx, ['availability']);
    return { update(st) { hero.update(st); } };
  }

  /** detailsInternet: the probes and the name resolution and web checks (cardInternet) side by
   *  side, the round-trip time and packet-loss charts, the cycle. The probes are drawn for every
   *  status (they hold no control); the checks only when there is a newer service check, so that
   *  an answer the reader opened keeps the focus. */
  function detailsInternet(ov, m) {
    const cols = h('div', { class: 'detail-cols' }, h('p', { class: 'loading' }, 'Loading…'));
    const foot = h('div');
    const charts = h('section', { class: 'detail-charts', 'aria-label': 'Round-trip time and packet loss' });
    m.body.append(cols, charts, foot, detailLinks('Every cycle’s measurements are on the ', h('a', { href: '#/records' }, 'Records'),
      ' page; the incidents and their evidence on the ', h('a', { href: '#/incidents' }, 'Incidents'), ' page.'));
    setupCharts(charts, m.ctx, ['latency', 'loss']);
    let checksKey = null;
    let checks = null;
    return {
      update(st) {
        const p = cardInternet(st);
        const k = JSON.stringify(st.last_service_check || null);
        if (k !== checksKey) {
          checksKey = k;
          checks = p.checks;
        }
        placeChildren(cols, p.probes, checks);
        replace(foot, p.foot);
      },
    };
  }

  /** detailsGateway: the gateway card of before (cardGatewayWAN), and a link to the Gateway page. */
  function detailsGateway(ov, m) {
    const box = h('div', null, h('p', { class: 'loading' }, 'Loading…'));
    m.body.append(box, detailLinks('Every field of the gateway’s status pages, its certificate and the outage-redirect setting are on the ',
      h('a', { href: '#/gateway' }, 'Gateway'), ' page.'));
    return { update(st) { keyed(box, JSON.stringify([st.gateway, st.notification, st.gateway_at, gatewayAge(st)]), () => cardGatewayWAN(st)); } };
  }

  /** detailsFiber: the fiber card of before (cardFiber) and the received light's history. */
  function detailsFiber(ov, m) {
    const box = h('div', null, h('p', { class: 'loading' }, 'Loading…'));
    const charts = h('section', { class: 'detail-charts', 'aria-label': 'Fiber receive power history' });
    m.body.append(box, charts, detailLinks('The gateway’s diagnostics with every threshold and flag are on the ', h('a', { href: '#/gateway' }, 'Gateway'), ' page.'));
    setupCharts(charts, m.ctx, ['optical']);
    return { update(st) { keyed(box, JSON.stringify(st.gateway ? st.gateway.fiber : null), () => cardFiber(st)); } };
  }

  /** detailsTraffic: the flow meter (which polls while these details are open), the MRTG-style
   *  traffic chart and the WAN volume per day; above them why there is no flow meter, when there is
   *  none (hidden otherwise: an empty part would double the gap above the first). */
  function detailsTraffic(ov, m) {
    const note = h('div', { hidden: true });
    const charts = h('section', { class: 'detail-charts', 'aria-label': 'Traffic history' });
    m.body.append(note, ov.flow.el, charts);
    setupCharts(charts, m.ctx, ['traffic']);
    return {
      update() {
        const why = ov.live && ov.live.unavailable ? String(ov.live.unavailable) : '';
        note.hidden = !why;
        keyed(note, why, () => (why ? callout('info', why) : null));
      },
    };
  }

  /** detailsLink: this PC's link card of before (cardLocalLink), with the route check. */
  function detailsLink(ov, m) {
    const box = h('div', null, h('p', { class: 'loading' }, 'Loading…'));
    m.body.append(box);
    return { update(st) { keyed(box, JSON.stringify(st.local_link || null), () => cardLocalLink(st)); } };
  }

  /** detailsNetwork: the reads of the NAT table and the Device List, the day's most active devices
   *  and organisations, the firewall's counts of the day, and links to the Network page's tabs.
   *  Its figures are read again when it opens and every minute while it is open. */
  function detailsNetwork(ov, m) {
    const samplers = h('section', { class: 'detail-part' }, h('p', { class: 'loading' }, 'Loading…'));
    const day = h('div', { class: 'detail-cols' });
    const fw = h('div', { class: 'detail-stack' });
    m.body.append(samplers, day, fw, detailLinks('Which device talks to which site, hour by hour, and what the firewall blocks are on the Network page: its ',
      h('a', { href: netHash('connections', { range: '24h' }, '') }, 'Connections'), ' and ', h('a', { href: netHash('firewall', { range: '24h' }, '') }, 'Firewall'), ' tabs.'));
    loadNetSummary(ov);
    m.ctx.interval(() => { if (!document.hidden) loadNetSummary(ov); }, NET_REFRESH_MS);
    const err = (e) => (e ? [e.status, e.message] : null);
    return {
      update(st) {
        const net = ov.net;
        const smp = st.connections && typeof st.connections === 'object' ? st.connections : null;
        keyed(samplers, JSON.stringify([smp, net && net.none, net && err(net.fwErr), smp && [sinceText(smp.nat_at, st.now), sinceText(smp.devices_at, st.now)]]),
          () => netSamplersPart(st, net));
        keyed(day, JSON.stringify(net && [net.conn, err(net.connErr)]), () => netDayParts(net));
        keyed(fw, JSON.stringify(net && [net.fw, err(net.fwErr), firewallFacts(net, st)]), () => netFirewallPart(net, st));
      },
    };
  }

  /** netSamplersPart tells how the monitor reads the gateway's NAT table and Device List
   *  (Status.connections). */
  function netSamplersPart(st, net) {
    const smp = st.connections && typeof st.connections === 'object' ? st.connections : null;
    const head = h('h3', { class: 'subhead' }, 'The gateway’s NAT table and Device List');
    if (!smp) {
      return [head, net && net.none ? callout('info', sentence(capitalize(net.fwErr.message)))
        : emptyNote('This monitor reports nothing about its reads of the NAT table.')];
    }
    const every = goDurMs(smp.interval);
    return [head, kv([
      ['NAT table', !smp.enabled ? [chip('none', 'off'), ' reading it is turned off in the configuration (connections.enabled)']
        : smp.nat_at ? ['read ', agoEl(smp.nat_at, st.now), every ? ' · every ' + fmtDur(every / 1000) : ''] : 'not read yet'],
      ['Open connections', smp.nat_at ? fmtInt(smp.sessions) + ' at the last read' : null],
      ['NAT sessions', Number(smp.in_use) > 0 || Number(smp.available) > 0 ? fmtInt(smp.in_use) + ' in use, ' + fmtInt(smp.available) + ' available' : null],
      ['Next read', smp.enabled && smp.nat_next ? timeEl(smp.nat_next, F.time) : null],
      ['Problem', smp.nat_problem ? [chip('warning', 'not read'), ' ', sentence(capitalize(String(smp.nat_problem)))]
        : smp.nat_note ? sentence(capitalize(String(smp.nat_note))) : null],
      ['Device List', smp.devices_at ? [fmtInt(smp.devices) + ' devices listed, read ', agoEl(smp.devices_at, st.now)] : 'not read yet'],
      ['Device List problem', smp.devices_problem ? sentence(capitalize(String(smp.devices_problem))) : null],
      ['Gateway logins, 24 h', Number(smp.nat_logins) > 0 ? fmtInt(smp.nat_logins) : null],
    ])];
  }

  /** netDayParts shows the day's most active devices and organisations (by the remote addresses
   *  they reached), as the Network page's connections of the last 24 hours count them: each list
   *  ranked by the value its bars show. The organisations are those of the flow diagram (the
   *  heaviest ones the server names, the rest grouped as "other"); without an IP address
   *  database none is named, which is not none reached. */
  function netDayParts(net) {
    if (!net) return h('p', { class: 'loading' }, 'Loading…');
    if (net.connErr) return net.connErr.status === 404 ? null : callout('warning', 'The connections could not be read: ', sentence(net.connErr.message));
    const c = net.conn || {};
    if (!(Number(c.samples) > 0)) return emptyNote('No read of the NAT table in the last 24 hours.');
    const sites = Number(c.totals && c.totals.sites) || 0;
    const bySites = (a, b) => (Number(b.sites) || 0) - (Number(a.sites) || 0);
    const part = (title, items, none) => h('section', { class: 'detail-part' }, h('h3', { class: 'subhead' }, title),
      items.length ? netBars(items, sites, title) : emptyNote(none || 'None in the last 24 hours.'));
    const devices = netList(c.devices).slice().sort(bySites).slice(0, 5)
      .map((dv) => ({ name: netText(dv.name || dv.ipv4 || dv.key, 40), note: '', value: Number(dv.sites) || 0 }));
    const orgs = topOrgs(c).slice(0, 5).map((o) => ({ name: netText(o.name || o.key, 40), note: '', value: Number(o.sites) || 0 }));
    return [part('Devices, last 24 hours (sites reached)', devices),
      part('Most used organisations, last 24 hours (sites)', orgs, !c.ipdb && sites > 0 ? 'Organisations are not named: no IP address database is loaded.' : '')];
  }

  /** netFirewallPart counts what the gateway's firewall blocked in the last 24 hours, from its
   *  syslog, with the most probed services - and says what the count cannot cover (firewallFacts):
   *  a period the syslog kept does not reach back to, a gateway that does not send its log here. A
   *  monitor without a syslog store says so; any other failure is an error. */
  function netFirewallPart(net, st) {
    if (!net || (!net.fw && !net.fwErr)) return null;
    const ff = firewallFacts(net, st);
    const head = h('h3', { class: 'subhead' }, 'The gateway’s firewall, ' + (ff.since ? 'since ' + shortWhen(ff.since) : 'last 24 hours'));
    if (net.fwErr) {
      if (net.fwErr.status === 404) return null;
      return [head, ff.noStore ? callout('info', 'This att-monitor keeps no syslog store, so there are no firewall messages to show.')
        : callout('warning', 'The firewall figures could not be read: ', sentence(net.fwErr.message))];
    }
    const fw = net.fw;
    const svcs = netList(fw.services).slice(0, 5).map((x) => ({
      name: x.name === 'Other' && !(Number(x.port) > 0) ? 'Other ports' : unnamedPort(x) ? portText(x.port, x.proto) : netText(x.name || portText(x.port, x.proto) || x.proto || '?', 40),
      note: unnamedPort(x) ? '' : portText(x.port, x.proto), value: Number(x.count) || 0,
    }));
    return [head,
      ff.unseen ? callout('warning', h('strong', null, ff.unseen), ' ', h('a', { href: '#/syslog' }, 'Open the Syslog page')) : null,
      ff.since ? callout('info', 'The syslog kept starts at ', timeEl(ff.since, F.short),
        ': what the gateway logged before was not received here or is no longer kept, so the counts cover less than 24 hours.') : null,
      h('div', { class: 'tiles net-tiles' },
        netTile('Blocked', fmtInt(fw.drops), 'packets in all'),
        netTile('Inbound', fmtInt(fw.inbound), 'probes from ' + fmtInt(fw.sources) + ' addresses'),
        netTile('Outbound', fmtInt(fw.outbound), 'packets from the home network'),
        netTile('Gateway itself', fmtInt(fw.local), 'to or from the gateway')),
      svcs.length ? h('section', { class: 'detail-part' }, h('h3', { class: 'subhead' }, 'Most probed services'), netBars(svcs, Number(fw.inbound) || 0, 'Most probed services')) : null];
  }

  /** detailsSyslog: the gateway syslog card of before (syslogPanel, its control of the gateway's
   *  Syslog setting included: built once, it keeps the focus and a change's outcome across the
   *  updates), and a link to the Syslog page. */
  function detailsSyslog(ov, m) {
    const panel = syslogPanel(m.ctx, true);
    const box = h('div', null, h('p', { class: 'loading' }, 'Loading…'));
    let none = null;
    m.body.append(box, detailLinks('The messages, their filters and how much of them is kept are on the ', h('a', { href: '#/syslog' }, 'Syslog'), ' page.'));
    return {
      update(st) {
        const el = panel.update(st);
        if (!el && !none) none = callout('info', 'This monitor reports no syslog receiver.');
        placeChildren(box, el || none);
      },
    };
  }

  /** detailsEvidence: the evidence card of before (cardEvidence), and links to verify and export. */
  function detailsEvidence(ov, m) {
    const box = h('div', null, h('p', { class: 'loading' }, 'Loading…'));
    m.body.append(box, detailLinks('Verify the whole ledger, time-stamp it now, add a note or build an evidence bundle on the ',
      h('a', { href: '#/evidence' }, 'Evidence'), ' page; every record is on the ', h('a', { href: '#/records' }, 'Records'), ' page.'));
    return { update(st) { keyed(box, JSON.stringify([st.ledger, st.mongo]), () => cardEvidence(st)); } };
  }

  /** detailsMonitor: the monitor and clock card of before (cardMonitor). */
  function detailsMonitor(ov, m) {
    const box = h('div', null, h('p', { class: 'loading' }, 'Loading…'));
    m.body.append(box);
    return { update(st) { keyed(box, JSON.stringify([st.monitor, st.clock]), () => cardMonitor(st)); } };
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

  /** cardInternet is the Internet card's details (docs/overview-redesign.md §2.4): the newest
   *  measurement's probes, the newest service check's name resolution and web checks (with the
   *  addresses of each query folded: dnsAnswers) and the cycle. Returns {probes, checks, foot}:
   *  the parts the details lay out side by side (checks null without a service check). */
  function cardInternet(st) {
    const smp = st.last_sample;
    if (!smp) return { probes: emptyNote('No measurements yet.'), checks: null, foot: null };
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
    const out = {
      probes: h('section', { class: 'detail-part', 'aria-label': 'Probes' },
        h('h3', { class: 'subhead' }, 'Probes'),
        // Never let the last recorded measurement read as the present one.
        stale ? callout('warning', h('strong', null, 'Not current. '), 'This is the last measurement recorded, ',
          sinceText(smp.started, st.now), ' ago: the monitor is not producing samples (see the status card).') : null,
        h('p', { class: 'big-line' }, icon(tone), (stale ? 'Last recorded: ' : '') + `${ok} of ${inet.length} internet probes answered`),
        h('div', { class: 'table-scroll' }, tbl)),
      checks: null,
      foot: h('p', { class: 'card-foot' }, 'Cycle #', fmtInt(smp.cycle), ' at ', timeEl(smp.started, F.time), smp.dur_ms != null ? ' · took ' + fmtInt(smp.dur_ms) + ' ms' : ''),
    };
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
            Array.isArray(r.answers) && r.answers.length ? dnsAnswers(r.answers) : null,
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
      out.checks = h('section', { class: 'detail-part', 'aria-label': 'Name resolution and web checks' },
        h('h3', { class: 'subhead' }, 'Name resolution & web checks'),
        table([{ label: 'Check' }, { label: 'Result' }, { label: 'Time', num: true }], dnsRows.concat(httpRows), { compact: true }));
    }
    return out;
  }

  /** dnsAnswers folds the records a DNS query got into a <details> ("1 address", "3 answers"
   *  when some are not addresses, e.g. a CNAME): every query of a check has them, and they matter
   *  only when looked into. Closed, they stay in the row's text. */
  function dnsAnswers(answers) {
    const list = answers.map(String);
    const typed = list.some((a) => /^[A-Za-z]+:/.test(a)); // "CNAME:www.l.google.com"
    const n = list.length;
    return h('details', { class: 'answers' },
      h('summary', null, n + ' ' + (typed ? (n === 1 ? 'answer' : 'answers') : n === 1 ? 'address' : 'addresses')),
      h('span', { class: 'sub small muted wrap-any' }, list.join(', ')));
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

  /** cardGatewayWAN is the AT&T gateway card's details: the gateway's WAN as its status pages
   *  report it, and when they were polled. Returns the content (the details give the heading). */
  function cardGatewayWAN(st) {
    const g = st.gateway;
    if (!g) return [emptyNote('No gateway snapshot yet.')];
    const d = g.derived || {};
    const bb = g.broadband || {};
    const fb = g.fiber || {};
    const n = st.notification;
    const clock = d.gateway_clock_blank
      ? h('span', null, chip('warning', 'blank'), ' the gateway shows no time — it does this while its WAN is down')
      : d.gateway_clock_offset_ms != null ? 'offset ' + (d.gateway_clock_offset_ms / 1000).toFixed(1) + ' s vs this PC' : null;
    return [
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
      h('p', { class: 'card-foot' }, 'Polled ', timeEl(st.gateway_at, F.time), gatewayAge(st)),
    ];
  }

  /** gatewayAge says how old the gateway reading shown is when it is not current
   *  (gatewayReading: the status keeps the last reading in which the gateway answered), and why. */
  function gatewayAge(st) {
    const r = gatewayReading(st);
    if (r.current || r.age == null) return null;
    return ' (' + fmtDur(r.age) + ' ago — ' + (r.silent ? 'the gateway does not answer now' : 'no newer reading') + ')';
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

  /** bullet draws a value against the gateway's own low/high alarm and warning thresholds. As a
   *  gauge (a summary card's), it is the graphic alone, hidden from screen readers: the card says
   *  the value and the thresholds in words. */
  function bullet(m, gauge) {
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
    const svg = s('svg', gauge ? { class: 'bullet gauge', viewBox: '0 0 100 16', preserveAspectRatio: 'none', 'aria-hidden': 'true', focusable: 'false' } : {
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
    if (gauge) return svg;
    return h('div', null, svg,
      h('p', { class: 'bullet-legend' },
        `Black marker: current reading. Gateway thresholds — low alarm ${fmtMeasure(la, m.unit)}, low warning ${fmtMeasure(lw, m.unit)}, high warning ${fmtMeasure(hw, m.unit)}, high alarm ${fmtMeasure(ha, m.unit)}.`));
  }

  function lastChangeText(fb) {
    if (!fb.last_change_unix) return fb.last_change_raw || null;
    return [timeEl(fb.last_change_unix * 1000), h('span', { class: 'small muted' }, ' (raw ' + (fb.last_change_raw || fb.last_change_unix) + '; epoch semantics unverified)')];
  }

  /** cardFiber is the Fiber optics card's details: the received and transmitted light against the
   *  gateway's own thresholds and flags, and the optical module. Returns the content. */
  function cardFiber(st) {
    const fb = st.gateway && st.gateway.fiber;
    if (!fb) return [emptyNote('No fiber status from the gateway yet.')];
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
    return body;
  }

  /** cardLocalLink is the This PC's link card's details: the network adapter, its signal and
   *  rate, its addresses and the route check (egressBlock). Returns the content. */
  function cardLocalLink(st) {
    const l = st.local_link;
    if (!l) return [emptyNote('Not measured yet.')];
    const connected = /^connected$/i.test(l.state || '');
    const signal = l.signal_pct || l.rssi_dbm
      ? [l.signal_pct ? l.signal_pct + ' %' : '', l.rssi_dbm ? (l.signal_pct ? ' · ' : '') + l.rssi_dbm + ' dBm' : '', l.signal_pct ? meter(l.signal_pct) : null]
      : null;
    return [
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
      HEX64.test(l.raw_sha256 || '') ? h('p', { class: 'card-foot' }, 'Raw adapter report: ', blobLinks(l.raw_sha256, { downloadText: 'download' })) : null,
    ];
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

  function meter(pct, cls) {
    const fill = h('span');
    fill.style.width = Math.max(0, Math.min(100, Number(pct) || 0)) + '%'; // CSSOM: allowed by the CSP
    return h('span', { class: 'meter' + (cls ? ' ' + cls : ''), 'aria-hidden': 'true' }, fill);
  }

  /** cardEvidence is the Evidence card's details: the ledger's head, signing key, time-stamps,
   *  last verification and MongoDB copy. Returns the content. */
  function cardEvidence(st) {
    const L = st.ledger || {};
    const lv = L.last_verify;
    return [
      kv([
        ['Ledger head', ['record #' + fmtInt(L.head_seq), L.head_ts ? [' · ', timeEl(L.head_ts, F.short)] : null]],
        ['Head hash', L.head_hash ? h('span', { class: 'hash', title: L.head_hash }, shortHash(L.head_hash, 20)) : null],
        ['Signing key', L.fingerprint ? h('span', { class: 'fp', title: 'SHA-256 fingerprint of the Ed25519 public key' }, groupFingerprint(L.fingerprint)) : null],
        ['Ledger started', L.genesis_ts ? timeEl(L.genesis_ts) : null],
        ['Last time-stamp', L.last_anchor_time ? [timeEl(L.last_anchor_time, F.short), ' by ', tsaName(L.last_anchor_tsa), ' (covers #' + fmtInt(L.last_anchor_seq) + ')'] : 'none yet'],
        ['Not yet time-stamped', fmtInt(L.unanchored_records) + ' records'],
        ['Last verification', lv ? [lv.ok ? chip('good', 'passed') : chip('critical', 'FAILED'), ' ', timeEl(lv.at, F.short), ` · ${fmtInt(lv.records)} records, ${fmtInt(lv.failures)} problems`] : 'not run yet'],
        ['MongoDB copy', st.mongo ? mongoCell(st.mongo) : null],
      ]),
    ];
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
    return [state, ` · ${fmtInt(m.records || 0)} records, ${fmtInt(m.blobs || 0)} blobs${m.syslog ? `, ${fmtInt(m.syslog)} syslog messages` : ''} in “${m.database}”`, upTo];
  }

  /** cardMonitor is the Monitor & clock card's details: the monitor's version, mode, start and
   *  cycles, and this computer's clock against each time server. Returns the content. */
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
        // A zero offset is left out of the JSON (omitempty).
        rows.push(['Clock vs ' + r.server, r.ok ? `${(r.offset_ms || 0) >= 0 ? '+' : ''}${fmtInt(r.offset_ms || 0)} ms (stratum ${r.stratum || '?'})` : chip('warning', 'no answer', r.err)]);
      }
    }
    return [kv(rows)];
  }

  // ------------------------------------------------------------------ flow meter

  /** flowMeter builds the live traffic card (GET /api/traffic/live, docs/
   *  syslog-snmp-traffic.md §3.3) that the Overview's Traffic card opens: the newest download and
   *  upload rates through the AT&T gateway, from its own counters, as large numbers and bars; the
   *  recent readings as a sparkline; this PC's rates; when the reading was taken. It asks for a
   *  reading every LIVE_REFRESH_MS while the page is visible and o.wanted() says so (the Traffic
   *  card or its details are on screen), and stops otherwise: the gateway gets no extra request
   *  while nobody watches. o.onReading(live) gets every reading ({lt, failure}) for the Traffic
   *  card, or {unavailable} from a monitor without a flow meter (404), whose card stays hidden.
   *  The numbers change every few seconds and are not announced (aria-live off). The card is
   *  built once and only updated, so that it can move into the details and out again. Returns
   *  {el, wake()}: wake asks again at once, or stops asking, when o.wanted() changed. */
  function flowMeter(ctx, o) {
    const opts = o || {};
    const body = h('div', { class: 'flow', 'aria-live': 'off' }, h('p', { class: 'loading' }, 'Reading the gateway’s counters…'));
    const el = h('section', { class: 'card', 'aria-labelledby': 'flow-h' },
      h('div', { class: 'card-head' }, h('h2', { id: 'flow-h' }, 'Live traffic'),
        h('span', { class: 'small muted' }, 'flow meter · every ' + fmtDur(LIVE_REFRESH_MS / 1000))),
      body);
    let timer = 0;
    let busy = false;
    let stopped = false;
    let abort = null;
    let last = null; // the newest reading received
    let failure = null; // why the newest request failed (null: it did not)
    const shown = () => document.visibilityState === 'visible' && (!opts.wanted || opts.wanted());
    const tell = (live) => { if (opts.onReading) opts.onReading(live); };

    async function poll() {
      window.clearTimeout(timer);
      timer = 0;
      if (busy || stopped || !shown()) return;
      busy = true;
      abort = typeof AbortController === 'function' ? new AbortController() : null;
      try {
        const lt = await api('/api/traffic/live', { signal: abort ? abort.signal : null });
        last = lt && typeof lt === 'object' && !Array.isArray(lt) ? lt : {};
        failure = null;
      } catch (e) {
        failure = e;
      } finally {
        busy = false;
        abort = null;
      }
      if (stopped) return;
      if (failure && failure.status === 404) { // this monitor offers no flow meter
        stopped = true;
        el.hidden = true;
        tell({ unavailable: sentence(capitalize(failure.message)) });
        return;
      }
      replace(body, flowContent(last, failure));
      tell({ lt: last, failure });
      if (shown()) timer = window.setTimeout(poll, LIVE_REFRESH_MS);
    }

    const onVisibility = () => {
      if (shown()) {
        poll();
      } else {
        window.clearTimeout(timer);
        timer = 0;
      }
    };
    const wake = () => {
      if (stopped) return;
      if (!shown()) {
        window.clearTimeout(timer);
        timer = 0;
      } else if (!timer && !busy) {
        poll();
      }
    };
    document.addEventListener('visibilitychange', onVisibility);
    ctx.cleanup(() => {
      stopped = true;
      window.clearTimeout(timer);
      document.removeEventListener('visibilitychange', onVisibility);
      if (abort) abort.abort();
    });
    poll();
    return { el, wake };
  }

  /** flowContent shows a flow meter reading (model.LiveTraffic), and why the newest request or
   *  read failed if one did: then the reading shown is the last one received, which says when it
   *  was taken. */
  function flowContent(lt, failure) {
    const out = [];
    if (failure) {
      out.push(callout('warning', h('strong', null, lt ? 'No new reading. ' : 'No reading. '), sentence(capitalize(failure.message)),
        lt && lt.at ? [' Shown: the reading of ', timeEl(lt.at, F.time), '.'] : null));
    }
    if (!lt) return out;
    if (lt.error) {
      // A read skipped because the monitor was taking its own evidence snapshot is not a failure.
      const skipped = /^skipped\b/i.test(String(lt.error));
      out.push(callout(skipped ? 'info' : 'warning',
        h('strong', null, skipped ? 'Waiting for the next read: ' : 'The newest read of the gateway’s counters failed: '), sentence(lt.error),
        lt.at ? [' Shown: the reading of ', timeEl(lt.at, F.time), '.'] : null));
    }
    const rate = (v) => (v == null || !isFinite(v) ? null : Number(v));
    const down = rate(lt.wan_rx_mbps);
    const up = rate(lt.wan_tx_mbps);
    const hist = (Array.isArray(lt.history) ? lt.history : []).filter((p) => p && typeof p === 'object' && toMs(p.t) != null);
    const heavy = app.series && Number(app.series.heavy_traffic_mbps) > 0 ? Number(app.series.heavy_traffic_mbps) : null;
    // The bars' scale: the larger of the recent maximum and the heavy-traffic level, rounded up.
    let recent = Math.max(down || 0, up || 0);
    for (const p of hist) recent = Math.max(recent, rate(p.wan_rx_mbps) || 0, rate(p.wan_tx_mbps) || 0);
    const scale = niceTicks(0, Math.max(recent, heavy || 0, 0.01), 1).hi;
    if (down == null && up == null && !lt.error) {
      out.push(h('p', { class: 'muted' }, 'Measuring: a rate needs two readings of the gateway’s counters, a few seconds apart.'));
    }
    out.push(flowRow('Download', areaKey(1), 1, down, !!lt.at_least, scale, heavy),
      flowRow('Upload', lineKey(2), 2, up, !!lt.at_least, scale, heavy),
      h('p', { class: 'flow-scale' }, 'Bars from 0 to ' + fmtLevel(scale), heavy != null ? ' · mark: heavy household traffic, ' + fmtLevel(heavy) : null));
    if (lt.at_least && (down != null || up != null)) {
      out.push(h('p', { class: 'small' }, chip('warning', 'at least'),
        ' The gateway’s 32-bit byte counter may have wrapped between the two readings, so the rates were at least these.'));
    }
    out.push(flowSpark(hist));
    const pcRx = rate(lt.pc_rx_mbps);
    const pcTx = rate(lt.pc_tx_mbps);
    if (pcRx != null || pcTx != null) {
      out.push(h('p', { class: 'flow-pc' }, h('span', { class: 'muted' }, 'This PC (its network adapter): '),
        'download ' + fmtRate(pcRx) + ' · upload ' + fmtRate(pcTx)));
    }
    const gap = Number(lt.interval_s) > 0 ? Number(lt.interval_s) : null;
    out.push(h('p', { class: 'card-foot' }, lt.at ? ['Reading of ', timeEl(lt.at, F.time)] : 'No reading yet',
      gap ? ', over the ' + gap.toFixed(1) + ' s between two readings' : '',
      '. Updated every ' + fmtDur(LIVE_REFRESH_MS / 1000) + ' while this page is open; shown, not recorded (the gateway snapshots every minute are the evidence).'));
    return out;
  }

  /** flowRow is one direction of the flow meter: its rate as a large number and as a bar against
   *  scale (Mb/s), heavy marked on it. */
  function flowRow(label, key, slot, v, atLeast, scale, heavy) {
    const [num, unit] = rateParts(v);
    const pct = (x) => Math.max(0, Math.min(100, (x / scale) * 100)).toFixed(2);
    const bar = s('svg', { class: 'flow-bar', viewBox: '0 0 100 10', preserveAspectRatio: 'none', 'aria-hidden': 'true', focusable: 'false' },
      s('rect', { class: 'track f' + slot, x: 0, y: 0, width: 100, height: 10 }),
      v != null ? s('rect', { class: 'f' + slot, x: 0, y: 0, width: pct(v), height: 10 }) : null,
      heavy != null && heavy <= scale
        ? s('line', { class: 'flow-heavy', x1: pct(heavy), x2: pct(heavy), y1: 0, y2: 10, 'vector-effect': 'non-scaling-stroke' }) : null);
    return h('div', { class: 'flow-row' },
      h('p', { class: 'flow-label' }, key, ' ', label, h('span', { class: 'muted' }, ' through the gateway')),
      h('p', { class: 'flow-value' }, v != null && atLeast ? h('span', { class: 'flow-pre' }, 'at least ') : null,
        h('span', { class: 'flow-num' }, num), unit ? h('span', { class: 'flow-unit' }, ' ' + unit) : null),
      bar);
  }

  /** flowSpark draws the flow meter's recent readings (LiveTraffic.history): download filled,
   *  upload as a line, on the scale of the largest; gaps where a reading had no rate or readings
   *  are missing. null with fewer than two readings. */
  function flowSpark(hist) {
    const rate = (v) => (v == null || !isFinite(v) ? null : Number(v));
    const pts = hist.map((p) => ({ t: toMs(p.t), rx: rate(p.wan_rx_mbps), tx: rate(p.wan_tx_mbps) }));
    if (pts.length < 2 || !(pts[pts.length - 1].t > pts[0].t)) return null;
    const t0 = pts[0].t;
    const t1 = pts[pts.length - 1].t;
    const diffs = [];
    for (let i = 1; i < pts.length; i++) diffs.push(pts[i].t - pts[i - 1].t);
    const gapMs = 3 * (median(diffs) || LIVE_REFRESH_MS);
    let top = 0;
    for (const p of pts) top = Math.max(top, p.rx || 0, p.tx || 0);
    const W = 300;
    const H = 40;
    const X = (t) => (((t - t0) / (t1 - t0)) * W).toFixed(1);
    const Y = (v) => (H - 1 - (top > 0 ? v / top : 0) * (H - 4)).toFixed(1);
    const runs = (k) => {
      const out = [];
      let cur = null;
      let prev = null;
      for (const p of pts) {
        if (p[k] == null) { cur = null; continue; }
        if (!cur || p.t - prev > gapMs) out.push(cur = []);
        cur.push(p);
        prev = p.t;
      }
      return out.filter((r) => r.length > 1);
    };
    const line = (r, k) => 'M' + r.map((p) => X(p.t) + ' ' + Y(p[k])).join('L');
    const rx = runs('rx');
    const tx = runs('tx');
    const svg = s('svg', { class: 'flow-spark', viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'none', 'aria-hidden': 'true', focusable: 'false' },
      s('line', { class: 'al', x1: 0, x2: W, y1: H - 0.5, y2: H - 0.5, 'vector-effect': 'non-scaling-stroke' }),
      rx.length ? s('path', { class: 'area f1', d: rx.map((r) => 'M' + X(r[0].t) + ' ' + H + 'L' + line(r, 'rx').slice(1) + 'L' + X(r[r.length - 1].t) + ' ' + H + 'Z').join('') }) : null,
      rx.length ? s('path', { class: 'ln c1', d: rx.map((r) => line(r, 'rx')).join(''), 'vector-effect': 'non-scaling-stroke' }) : null,
      tx.length ? s('path', { class: 'ln c2', d: tx.map((r) => line(r, 'tx')).join(''), 'vector-effect': 'non-scaling-stroke' }) : null);
    const most = (k) => pts.reduce((m, p) => (p[k] != null && p[k] > m ? p[k] : m), -Infinity);
    const span = (t1 - t0 + (median(diffs) || 0)) / 1000; // each reading covers the time since the one before
    return h('div', { class: 'flow-spark-wrap' }, svg,
      h('p', { class: 'flow-scale' }, 'Last ' + fmtDur(span) + ': highest download ' + fmtRate(isFinite(most('rx')) ? most('rx') : null) +
        ', upload ' + fmtRate(isFinite(most('tx')) ? most('tx') : null)));
  }

  // ------------------------------------------------------------------ gateway syslog

  /** syslogStatus returns Status.syslog (the receiver of the gateway's syslog messages and the
   *  gateway's Syslog setting, docs/syslog-snmp-traffic.md §3), or null when the monitor reports
   *  neither. */
  function syslogStatus(st) {
    const sl = st && st.syslog;
    return sl && typeof sl === 'object' && !Array.isArray(sl) ? sl : null;
  }

  /** syslogPanel is a view's part about the gateway's syslog: the receiver and what it received,
   *  the gateway's Syslog setting as last read, whether att-monitor keeps it sending here, and
   *  the control that changes that (syslogControl). details: the Overview's Gateway syslog
   *  details, which also say how much the store holds (the Syslog page shows the store in a
   *  card of its own), as their content; else the Syslog page's card. It is built once:
   *  update(st) redraws what it shows when that changes and leaves the control as it is, and the
   *  view puts it back with placeChildren, so a status refresh takes neither the keyboard focus
   *  nor a change's progress or outcome away. update returns the part, or null when the monitor
   *  reports no syslog status. */
  function syslogPanel(ctx, details) {
    const ctl = syslogControl(ctx);
    const body = h('div');
    const el = details ? h('div', { class: 'syslog-panel' }, body, ctl.el) : card('Receiver and gateway setting', body, ctl.el);
    let key = null;
    return {
      update(st) {
        const sl = syslogStatus(st);
        if (!sl) return null;
        const k = JSON.stringify([sl, st.local_link ? st.local_link.local_ip : null, gatewayAuthBlock(st)]);
        if (k !== key) {
          key = k;
          replace(body, syslogCardBody(sl, st, details));
        }
        ctl.update(st);
        return el;
      },
    };
  }

  /** syslogCardBody is what syslogPanel shows from Status.syslog (sl); withStore: also how much
   *  the syslog store holds. */
  function syslogCardBody(sl, st, withStore) {
    const seq = Number(sl.gateway_seq) || 0;
    const store = syslogStore(sl);
    return [
      kv([
        ['Receiver', syslogReceiver(sl)],
        ['Messages', [syslogCounts(sl), h('span', { class: 'sub small muted' }, 'since the service started')]],
        ['Stored', withStore && store ? [syslogUsageText(store), store.oldest ? h('span', { class: 'sub small muted' }, 'oldest message ', timeEl(store.oldest, F.short)) : null] : null],
        ['Last message', sl.last_at || sl.last
          ? [timeEl(sl.last_at, F.sec), sl.last ? h('span', { class: 'sub syslog-text small' }, visibleText(sl.last)) : null]
          : 'none since the service started'],
        ['Gateway setting', syslogSetting(sl)],
        ['Setting read', sl.gateway_at || seq
          ? [sl.gateway_at ? timeEl(sl.gateway_at, F.short) : null, sl.gateway_at && seq ? ' · ' : null, seq ? h('a', { href: recordsLink(seq) }, 'record #' + seq) : null]
          : null],
        ['Kept by att-monitor', syslogKept(sl)],
      ]),
      h('p', { class: 'card-foot' }, syslogEnforcement(sl, st)),
    ];
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
      h('span', { title: 'Kept in the syslog store; each chunk of messages is recorded in the evidence ledger with its SHA-256 when it is sealed' },
        n(sl.recorded) + ' stored'), ' · ',
      Number(sl.dropped) > 0
        ? chip('warning', n(sl.dropped) + ' dropped', 'Accepted but over the per-minute cap: counted, not stored')
        : h('span', { title: 'Accepted but over the per-minute cap: counted, not stored' }, '0 dropped'), ' · ',
      h('span', { title: 'Datagrams from senders other than the gateway: counted, not stored' }, n(sl.rejected) + ' from other senders'),
    ];
  }

  /** syslogStore returns the syslog store's volume and limits (Status.syslog.store), or null
   *  when the monitor reports no store. */
  function syslogStore(sl) {
    const u = sl && sl.store;
    return u && typeof u === 'object' && !Array.isArray(u) ? u : null;
  }

  /** syslogUsageText words how much the syslog store holds against its size limit. */
  function syslogUsageText(u) {
    const used = fmtBytes(Number(u.bytes) || 0);
    return Number(u.keep_mb) > 0 ? used + ' of ' + fmtInt(u.keep_mb) + ' MiB used' : used + ' used';
  }

  /** syslogTarget writes a Syslog destination as server:port. */
  function syslogTarget(x) {
    return x && x.server ? String(x.server) + (x.port ? ':' + x.port : '') : '';
  }

  /** syslogPort is the port the gateway is to send its log to: the target's (syslog.port), else
   *  the receiver's, else 514. */
  function syslogPort(sl) {
    const t = sl && sl.target && typeof sl.target === 'object' ? sl.target : null;
    return (t && Number(t.port)) || Number((/:(\d+)$/.exec(String((sl && sl.listen) || '')) || [])[1]) || 514;
  }

  /** syslogKept says whether att-monitor keeps the gateway's Syslog setting (Status.syslog.enforce,
   *  gateway.enforce_syslog) and at what (target: this PC's address toward the gateway,
   *  syslog.port and the level chosen; absent while this PC's address is not known). */
  function syslogKept(sl) {
    if (!sl.enforce) return [chip('none', 'no'), ' att-monitor only reads this setting'];
    const t = sl.target && typeof sl.target === 'object' ? sl.target : null;
    if (t && t.enabled === false) return [chip('good', 'yes'), ' off'];
    return [chip('good', 'yes'), ' on, sending to ', syslogTarget(t) || 'this PC (its address toward the gateway is not known yet)',
      t && t.level ? [' · level ', String(t.level)] : null];
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
        return [chip('warning', 'check failed'), ' ', String(sl.problem || 'the last check failed'),
          g ? h('span', { class: 'sub small muted' }, 'Last read: ', g.enabled ? 'on, sends to ' + (syslogTarget(g) || '?') : 'off', level) : null];
      case 'unknown':
        return g ? [chip('none', 'not understood'), ' ', String(sl.problem || 'the gateway’s Syslog page was not understood')]
          : [chip('none', 'not read yet'), problem];
    }
    return [chip('none', humanize(state) || 'on'), g && g.enabled ? [' sends to ', syslogTarget(g) || '?', level] : null, problem];
  }

  /** syslogEnforcement says what att-monitor does with the gateway's Syslog setting: it reads it
   *  in its daily settings check (and within 10 minutes after the service starts or this PC's
   *  address changed) and, while it keeps it (enforce), sets it again whenever it differs. A
   *  change made on the gateway itself therefore shows above only after the next read, while
   *  its messages show at once: once messages have arrived since a read that found the gateway
   *  sending elsewhere or not at all, the card says so. While the gateway does not send here and
   *  att-monitor cannot set it (syslogHandHint), and no message arrived since the setting was
   *  read, the card also says how to set it on the gateway itself. */
  function syslogEnforcement(sl, st) {
    const reads = 'in its daily settings check (also within 10 minutes after the service starts and after this PC’s address changes)';
    const out = [];
    const readAt = toMs(sl.gateway_at);
    const lastAt = toMs(sl.last_at);
    const receiving = lastAt != null && (readAt == null || lastAt > readAt); // messages since the latest read
    const contradicted = receiving && readAt != null && (sl.state === 'off' || sl.state === 'elsewhere');
    if (contradicted) out.push('Messages have arrived since this setting was read, so it may have been changed on the gateway since. ');
    if (sl.enforce) {
      out.push('att-monitor keeps the gateway sending its log to this PC: it reads the setting ' + reads +
        ', sets it again whenever it differs, and records every reading and change with the gateway’s page.');
    } else {
      out.push('att-monitor does not keep this setting (gateway.enforce_syslog is off): it only reads it ' + reads +
        ' and records every reading. “Send the gateway’s log to this PC” sets it and keeps it so.');
    }
    const hand = syslogHandHint(st) && !receiving;
    if (sl.enforce && !hand && !contradicted && (sl.state === 'off' || sl.state === 'elsewhere')) {
      out.push(' It is set again at the next check, or now with “Send the gateway’s log to this PC”.');
    }
    if (hand) out.push(' ', syslogByHand(sl, st));
    return out;
  }

  /** syslogHandHint reports whether to say how to set the gateway's Syslog page by hand: only
   *  while the gateway does not send its log here and att-monitor cannot set it - setting it
   *  failed or cannot be done: the latest check failed (state error), the latest attempt to set
   *  it failed (SYSLOG_SETTING_FAILED), the page was not understood, no access code is stored or
   *  a changed gateway certificate waits for confirmation (gatewayAuthBlock). While att-monitor
   *  merely does not keep the setting, its control (“Send the gateway’s log to this PC”) is the
   *  way. */
  function syslogHandHint(st) {
    const sl = syslogStatus(st);
    if (!sl || sl.state === 'ok') return false;
    const notUnderstood = (Number(sl.gateway_seq) || 0) > 0 && !(sl.gateway && typeof sl.gateway === 'object');
    return sl.state === 'error' || notUnderstood || !!findCondition(st, 'SYSLOG_SETTING_FAILED') || gatewayAuthBlock(st) !== '';
  }

  /** syslogByHand says how to set the gateway's Syslog page by hand: the real page enables its
   *  fields only once Syslog is set to On. */
  function syslogByHand(sl, st) {
    const t = sl.target && typeof sl.target === 'object' ? sl.target : null;
    const ip = (st && st.local_link && st.local_link.local_ip) || (t && t.server) || '';
    return ['To set it on the gateway itself: open its Diagnostics › Syslog page, set Syslog to On (the page then enables its other fields), enter Server IP Address ',
      ip ? h('code', null, String(ip)) : 'this PC’s address', ' and Server Port ', String(syslogPort(sl)), ', and save',
      sl.listening ? ': its messages then show here within a minute.' : '.'];
  }

  // ------------------------------------------------------------------ the gateway's Syslog setting

  /** gwSyslog is the operator's change of the gateway's Syslog setting (POST /api/gateway/syslog),
   *  which can take a minute or more: whether one runs (busy), its outcome (a function building
   *  the notice) until `until`, and why this monitor offers no such change (unavailable, after a
   *  404). It belongs to no view: the Overview's syslog card and the Syslog page both show it
   *  (views: their redraw functions), so a change in progress and its outcome survive going from
   *  one to the other, and neither offers a second change meanwhile. version counts its changes. */
  const gwSyslog = { busy: false, outcome: null, until: 0, unavailable: '', version: 0, views: new Set() };
  // How long the outcome of a change of the gateway's Syslog setting is shown.
  const GW_SYSLOG_OUTCOME_MS = 10 * 60 * 1000;

  function gwSyslogSet(changes) {
    Object.assign(gwSyslog, changes);
    gwSyslog.version++;
    for (const draw of gwSyslog.views) draw();
  }

  /** gwSyslogOffers says which changes the control offers (Status.syslog): sending the gateway's
   *  log to this PC unless att-monitor keeps it so and it does (enforce, state ok); stopping it
   *  while att-monitor keeps it or the gateway may send its log somewhere (not read as off). */
  function gwSyslogOffers(sl) {
    return { on: !(sl.enforce && sl.state === 'ok'), off: !!sl.enforce || sl.state !== 'off' };
  }

  /** syslogControl offers the operator's change of the gateway's Syslog setting in a view:
   *  “Send the gateway’s log to this PC” and “Stop sending” (gwSyslogOffers), each confirmed in a
   *  dialog that says what happens on the gateway, then the change's progress and outcome
   *  (gwSyslog). Like the outage-redirect control on the Gateway page, its buttons are disabled
   *  while authenticated gateway actions cannot run (gatewayAuthBlock), and it says why. Its
   *  elements are built once and only updated, so a status refresh never takes the focus or an
   *  outcome away (and a live region is not announced again). Nor does a change: while it runs
   *  the buttons only say that they do nothing (aria-disabled; changeGatewaySyslog ignores them),
   *  as a disabled button would drop the focus the dialog gave back to it to the start of the
   *  page; and once the button the keyboard is on is no longer offered (or is disabled), the focus
   *  goes to the outcome, else to why the control offers no change, else to the other button.
   *  Returns { el, update(st) }. */
  function syslogControl(ctx) {
    const why = h('div', { hidden: true, tabindex: '-1' });
    const on = h('button', { type: 'button', class: 'btn btn-primary' }, 'Send the gateway’s log to this PC');
    const off = h('button', { type: 'button', class: 'btn' }, 'Stop sending');
    const out = h('div', { 'aria-live': 'polite', tabindex: '-1' });
    const el = h('div', { class: 'syslog-control' }, why, h('div', { class: 'btn-row' }, on, off), out);
    let st = null;
    let whyKey = null;
    let shown = -1; // the gwSyslog.version out shows
    let shownUntil = 0; // until when the outcome out shows is current (0: none shown)
    on.addEventListener('click', () => changeGatewaySyslog(true, st, ctx));
    off.addEventListener('click', () => changeGatewaySyslog(false, st, ctx));
    const draw = () => {
      const had = [on, off].find((b) => b === document.activeElement) || null; // the button the keyboard is on
      const sl = syslogStatus(st);
      el.hidden = !sl;
      if (!sl) return;
      const block = gatewayAuthBlock(st);
      const offers = gwSyslogOffers(sl);
      on.hidden = !!gwSyslog.unavailable || !offers.on;
      off.hidden = !!gwSyslog.unavailable || !offers.off;
      on.disabled = off.disabled = !!block;
      for (const b of [on, off]) {
        if (gwSyslog.busy) b.setAttribute('aria-disabled', 'true');
        else b.removeAttribute('aria-disabled');
      }
      const k = block + '|' + gwSyslog.unavailable;
      if (k !== whyKey) {
        whyKey = k;
        replace(why, gwSyslog.unavailable ? callout('info', gwSyslog.unavailable)
          : block === 'cert' ? h('p', null, chip('critical', 'paused'), ' The gateway presented an unconfirmed TLS certificate, so att-monitor will not log in to it until the certificate is confirmed (see the certificate banner at the top of the page).')
            : block === 'code' ? h('p', null, chip('none', 'no access code'), ' No usable gateway access code is stored, so att-monitor can neither set nor read this setting (att-monitor set-access-code).')
              : null);
        why.hidden = !gwSyslog.unavailable && !block;
      }
      const current = !!gwSyslog.outcome && Date.now() < gwSyslog.until;
      if (gwSyslog.version !== shown || (shownUntil && !current)) {
        shown = gwSyslog.version;
        shownUntil = current ? gwSyslog.until : 0;
        replace(out, gwSyslog.busy ? gwSyslogProgress() : current ? gwSyslog.outcome() : null);
      }
      if (had && (had.hidden || had.disabled)) { // the focus stays in the control
        const next = out.firstChild ? out : !why.hidden ? why : [on, off].find((b) => !b.hidden && !b.disabled);
        if (next) next.focus();
      }
    };
    gwSyslog.views.add(draw);
    ctx.cleanup(() => gwSyslog.views.delete(draw));
    return { el, update(s) { st = s; draw(); } };
  }

  /** changeGatewaySyslog asks the monitor, once the operator confirmed what will happen on the
   *  gateway, to send the gateway's log to this PC and keep it so (enabled), or to stop it. The
   *  confirmation belongs to the view that asked (ctx): leaving it (Back closing the Overview's
   *  details) cancels it, so that it is never left open over a page that no longer shows the
   *  control. */
  async function changeGatewaySyslog(enabled, st, ctx) {
    if (gwSyslog.busy) return;
    if (!(await dialog(Object.assign(gwSyslogDialog(enabled, st), { ctx }))) || gwSyslog.busy) return;
    gwSyslogSet({ busy: true, outcome: null, until: 0 });
    let outcome = null;
    let unavailable = gwSyslog.unavailable;
    try {
      const cc = (await api('/api/gateway/syslog', { method: 'POST', body: { enabled } })) || {};
      outcome = () => gwSyslogDone(enabled, cc);
    } catch (e) {
      if (e.status === 404) unavailable = sentence(capitalize(e.message)); // this monitor offers no such change
      else outcome = () => gwSyslogFailed(e);
    } finally {
      gwSyslogSet({ busy: false, outcome, until: outcome ? Date.now() + GW_SYSLOG_OUTCOME_MS : 0, unavailable });
      refreshStatus();
    }
  }

  /** gwSyslogDialog is the confirmation before a change of the gateway's Syslog setting: what
   *  will happen on the gateway, and what att-monitor does about the setting from then on. */
  function gwSyslogDialog(enabled, st) {
    const sl = syslogStatus(st) || {};
    const g = sl.gateway && typeof sl.gateway === 'object' ? sl.gateway : null;
    const sends = g && g.enabled ? syslogTarget(g) : ''; // where the gateway sends its log as last read
    const evidence = 'att-monitor then reads the page back: the change counts only if the gateway shows it. The pages before and after the change are stored as evidence, and the change is recorded in the evidence ledger.';
    if (!enabled) {
      return {
        title: 'Stop the gateway sending its log?',
        body: [
          h('p', null, 'att-monitor will log in to the AT&T gateway with the stored access code and set Syslog to Off on its Diagnostics › Syslog page: the gateway then sends its log to no syslog server',
            sends ? ' (it sends it to ' + sends + ' now)' : '', '. ', evidence),
          h('p', null, 'att-monitor no longer sets this setting (gateway.enforce_syslog off) until you choose “Send the gateway’s log to this PC” again; it still reads it in its daily settings check. The messages received so far stay in the syslog store, within its limits.'),
        ],
        confirm: 'Stop sending',
      };
    }
    const t = sl.target && typeof sl.target === 'object' ? sl.target : null;
    const ip = (t && t.server) || (st && st.local_link && st.local_link.local_ip) || '';
    return {
      title: 'Send the gateway’s log to this PC?',
      body: [
        h('p', null, 'att-monitor will log in to the AT&T gateway with the stored access code and set its Diagnostics › Syslog page: Syslog On, Server IP Address ',
          ip ? h('code', null, String(ip)) : 'this PC’s address toward the gateway', ', Server Port ', h('code', null, String(syslogPort(sl))), ', Log Level ',
          t && t.level ? h('code', null, String(t.level)) : 'as gateway.syslog_level says, else as already set while Syslog is on, else the most detailed level the page offers (not Debug)', '.'),
        sl.state === 'elsewhere' && sends ? h('p', null, h('strong', null, 'The gateway sends its log to ' + sends + ' now: it will send it to this PC instead.')) : null,
        h('p', null, g && g.enabled ? null : 'The page enables those fields only once Syslog is On, so att-monitor first switches it on (the page’s Update), then fills them in and saves. ',
          evidence),
        h('p', null, 'From then on att-monitor keeps the setting: it reads it in its daily settings check (also after this PC’s address changes) and sets it again whenever it differs.'),
        sl.enabled === false ? h('p', null, h('strong', null, 'This PC’s syslog receiver is off (syslog.enabled is false in config.json): the gateway’s messages are not received until it is turned on.')) : null,
      ],
      confirm: 'Send the log to this PC',
    };
  }

  function gwSyslogProgress() {
    return notice('info', spinner(), ' Talking to the gateway… Logging in, changing its Syslog page and reading it back can take a minute or two.');
  }

  /** gwSyslogDone words a change of the gateway's Syslog setting that the monitor made (its
   *  config_change), or did not need to make: the page already showed what was asked
   *  ("unchanged: ...", not recorded as a change of the page). */
  function gwSyslogDone(enabled, cc) {
    const result = String(cc.result || 'applied');
    const then = enabled ? 'att-monitor keeps the gateway sending its log to this PC; new messages show on the Syslog page as they arrive.'
      : 'The gateway sends its log to no syslog server now, and att-monitor no longer sets it.';
    if (/^\s*unchanged/i.test(result)) {
      return notice('good', h('strong', null, 'Already so. '), 'The gateway’s Syslog page already showed this, so it was not changed (', result, '). ', then);
    }
    return notice('good', h('strong', null, 'Done. '), 'Recorded in the evidence ledger as a configuration change: ',
      String(cc.what || 'the gateway’s Syslog setting'), ', ', String(cc.before || '?'), ' → ', String(cc.after || '?'), ' (', result, '). ', then);
  }

  /** gwSyslogFailed words a change of the gateway's Syslog setting that failed. It never claims
   *  that nothing changed when the monitor reports that the gateway took the change (the answer's
   *  change says "verified" or "applied"): then what failed came after, e.g. recording it. */
  function gwSyslogFailed(e) {
    const ch = e.data && e.data.change;
    const result = ch && ch.result ? String(ch.result) : '';
    if (result && !/^\s*failed/i.test(result)) return notice('warning', sentence(capitalize(e.message)));
    return notice('critical', 'The change could not be completed or confirmed: ', sentence(e.message),
      result ? ' (Recorded result: ' + sentence(result) + ')' : '');
  }

  /** loadRecentIncidents shows the Overview's recent incidents (docs/overview-redesign.md §2.5):
   *  the three newest, one line each, an open one first; every line links its incident. Read
   *  again every minute and whenever an incident opens or closes (followIncident), it draws the
   *  lines again only when they changed (an open one's duration follows the status meanwhile), so
   *  that a link the keyboard is on stays; when they changed, it keeps the focus on the link that
   *  had it. Of reads that overlap, the last one asked for is shown. */
  async function loadRecentIncidents(el, ov) {
    const mine = ++ov.recentToken;
    const head = h('div', { class: 'card-head' }, h('h2', { id: 'recent-h' }, 'Recent incidents'),
      h('a', { href: '#/incidents', class: 'small', 'data-fk': 'recent:all' }, 'All incidents'));
    try {
      const list = await api('/api/incidents?limit=3');
      if (!ov.ctx.alive || mine !== ov.recentToken) return;
      const now = app.status && app.status.now;
      const items = (Array.isArray(list) ? list : []).filter((x) => x && typeof x === 'object').slice(0, 3)
        .sort((a, b) => (b.open ? 1 : 0) - (a.open ? 1 : 0));
      // What a line shows, but an open incident's duration (followIncident updates it in place).
      const key = JSON.stringify(items.map((x) => [x.id, x.open, x.opened, x.closed, x.open ? 0 : x.duration_s, x.state, x.cause, x.attribution, x.summary]));
      if (partKeys.get(el) === key && ov.recent) {
        ov.recent.forEach((line, i) => { line.inc = items[i]; });
      } else {
        partKeys.set(el, key);
        ov.recent = items.map((inc) => recentIncident(inc, now));
        keepFocus(el, () => replace(el, head,
          items.length ? h('ul', { class: 'recent-list' }, ov.recent.map((line) => line.el)) : emptyNote('No incidents recorded.')));
      }
      for (const line of ov.recent) if (line.inc.open) replace(line.dur, keepUnits(incidentDuration(line.inc, now)));
    } catch (e) {
      if (!ov.ctx.alive || mine !== ov.recentToken) return;
      partKeys.delete(el);
      ov.recent = null;
      keepFocus(el, () => replace(el, head, errorNotice(e)));
    }
  }

  /** recentIncident is one line of the recent incidents: when it opened (its link), how long it
   *  lasted, what it was, and to whom it is attributed - or that it is still in progress. Returns
   *  {el, dur (its duration's element), inc}. */
  function recentIncident(inc, now) {
    const d = toDate(inc.opened);
    const today = d && localDateValue(d) === localDateValue(new Date());
    const when = d ? h('time', { datetime: d.toISOString(), title: 'UTC: ' + utcText(inc.opened, d) }, today ? 'Today, ' + F.hm.format(d) : F.short.format(d)) : '?';
    const tag = inc.open ? chip(stateInfo(inc.state).tone, 'In progress')
      : inc.attribution === 'provider' ? chip('critical', ATTR_SHORT.provider) : chip('none', ATTR_SHORT[inc.attribution] || humanize(inc.attribution) || '—');
    const dur = h('span', { class: 'recent-dur' }, keepUnits(incidentDuration(inc, now)));
    const el = h('li', { class: inc.open ? 'is-open' : null },
      h('a', { class: 'recent-when', href: '#/incidents/' + encodeURIComponent(inc.id), title: inc.id, 'data-fk': 'recent:' + inc.id }, when),
      dur,
      h('span', { class: 'recent-sum', title: inc.summary ? String(inc.summary) : null }, headline(inc)),
      h('span', { class: 'recent-tag' }, tag));
    return { el, dur, inc };
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

  /** setupCharts shows charts of the history in section (which names them: HISTORY_CHARTS) under
   *  a range control: the series of the range chosen (remembered: app.range) is read at once, again
   *  every minute while the page is visible and at once when the page is shown again a minute or
   *  more later, until ctx ends. A series of that range read less than a minute ago by another part
   *  of the page (seriesCache: the Overview's 24 hours) is used rather than read again. The charts
   *  stay in the page from one series to the next (showCharts, renderCharts: updated in place). */
  function setupCharts(section, ctx, which) {
    const body = h('div', { class: 'charts-body' }, h('p', { class: 'loading' }, 'Loading chart data…'));
    section.append(
      h('div', { class: 'section-head' }, h('h3', { class: 'subhead' }, 'History'),
        rangeControl(app.range, (r) => { app.range = r; savePref('range', r); load(); })),
      body);
    let token = 0;
    let shownSer = null; // the series the charts show
    let loadedAt = 0;
    const charts = new Map(); // the charts shown (renderCharts)
    ctx.cleanup(() => disposeCharts(charts));
    async function load() {
      const mine = ++token;
      const range = app.range;
      body.classList.add('is-loading');
      body.setAttribute('aria-busy', 'true');
      try {
        const cached = seriesCache[range];
        let ser = cached && Date.now() - cached.at < SERIES_REFRESH_MS ? cached.ser : null;
        if (!ser) {
          ser = await api('/api/series?range=' + encodeURIComponent(range));
          if (ser && typeof ser === 'object') seriesCache[range] = { ser, at: Date.now() };
        }
        if (!ctx.alive || mine !== token) return;
        loadedAt = Date.now();
        if (ser && ser === shownSer) return; // nothing newer than the charts show
        shownSer = ser;
        const firstLabels = !app.series;
        app.series = ser;
        showCharts(body, ser, charts, which);
        if (firstLabels && app.status && app.view && app.view.onStatus) app.view.onStatus(app.status); // probe labels come with the series
      } catch (e) {
        if (!ctx.alive || mine !== token) return;
        disposeCharts(charts);
        shownSer = null;
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
    // Back from a hidden tab, the minutes the interval skipped are read at once.
    const onVisible = () => { if (!document.hidden && Date.now() - loadedAt >= SERIES_REFRESH_MS) load(); };
    document.addEventListener('visibilitychange', onVisible);
    ctx.cleanup(() => document.removeEventListener('visibilitychange', onVisible));
  }

  /** showCharts shows the charts of a series in body (renderCharts) so that the reader keeps their
   *  place. The charts shown are updated in place: a plot keeps the keyboard focus and the time it
   *  shows, a table view its focus and scroll position, nothing is announced again. For a chart
   *  drawn anew, body keeps its height until it has been drawn (a plot draws on its first layout,
   *  two frames later: the section must not shrink and throw the scroll position to the top), a
   *  table view gets its scroll position back, and the keyboard focus goes to the element that took
   *  the place of the one that had it (keepFocus) - else to the scroll region around (the details'
   *  body): never out of the dialog. */
  function showCharts(body, ser, charts, which) {
    const scrolls = new Map();
    for (const t of body.querySelectorAll('.chart-table[data-fk]')) scrolls.set(t.getAttribute('data-fk'), t.scrollTop);
    const had = body.contains(document.activeElement);
    body.style.minHeight = body.offsetHeight + 'px'; // CSSOM: allowed by the CSP
    keepFocus(body, () => renderCharts(body, ser, charts, which));
    for (const t of body.querySelectorAll('.chart-table[data-fk]')) {
      const top = scrolls.get(t.getAttribute('data-fk'));
      if (top && t.scrollTop !== top) t.scrollTop = top;
    }
    if (had && !body.contains(document.activeElement)) {
      const region = body.closest('.detail-body');
      if (region) region.focus({ preventScroll: true });
    }
    window.requestAnimationFrame(() => window.requestAnimationFrame(() => { body.style.minHeight = ''; }));
  }

  /** rangeControl offers the RANGES (or the given ranges, [value, label] pairs) as a segmented
   *  radio group; groupLabel names the group. */
  function rangeControl(current, onChange, groupLabel, ranges) {
    const name = 'range-' + Math.random().toString(36).slice(2, 8);
    const group = h('div', { class: 'seg', role: 'radiogroup', 'aria-label': groupLabel || 'Chart time range' });
    for (const [value, label] of ranges || RANGES) {
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

  // The charts of the history by name, in their order (renderCharts; the Overview's details
  // mount the ones they show): each gets the series, its range and buckets (seriesGeom) and the
  // charts whose legends show and hide the same probes (linked), and returns what to show, in
  // order: a chart ({key, kind: 'line' | 'strip', o}: drawn by lineChart or stateStrip, and updated
  // in place by the next series), or a part drawn anew every time ({el}); null for nothing.
  const HISTORY_CHARTS = dict({
    availability: (ser, g) => [{ key: 'availability', kind: 'strip', o: availabilityOpts(g) }],
    latency: (ser, g, linked) => [{ key: 'latency', kind: 'line', o: latencyOpts(ser, g, linked) }],
    loss: (ser, g, linked) => [{ key: 'loss', kind: 'line', o: lossOpts(ser, g, linked) }],
    traffic: (ser, g) => [trafficPart(ser, g.from, g.to, g.stepMs), { el: trafficDaysTable(ser) }],
    optical: (ser, g) => [opticalPart(ser, g.from, g.to)],
  });

  /** renderCharts shows in body the charts of a series (GET /api/series) that which names
   *  (HISTORY_CHARTS: "availability", "latency", "loss", "traffic", "optical"; every one when which
   *  is not given). A chart already shown (charts: key -> {kind, chart, ctx}) is updated in place
   *  with the new series when it can be; the others are drawn anew, and those no longer shown end
   *  with their context. The figures are put in place around those that stay (placeChildren),
   *  which never moves them: the keyboard focus in one stays. */
  function renderCharts(body, ser, charts, which) {
    const g = seriesGeom(ser);
    if (!g) {
      disposeCharts(charts);
      replace(body, errorNotice(new Error('The monitor returned an invalid chart range.')));
      return;
    }
    const linked = [];
    const parts = (which || Object.keys(HISTORY_CHARTS)).flatMap((name) => (HISTORY_CHARTS[name] ? HISTORY_CHARTS[name](ser, g, linked) : []));
    const next = new Map();
    const els = [];
    for (const p of parts) {
      if (!p) continue;
      if (!p.kind) {
        if (p.el) els.push(p.el);
        continue;
      }
      let c = charts.get(p.key);
      if (c && c.kind === p.kind && c.chart.update(p.o)) {
        charts.delete(p.key);
      } else {
        const ctx = newViewCtx();
        p.o.ctx = ctx;
        c = { kind: p.kind, chart: p.kind === 'strip' ? stateStrip(p.o) : lineChart(p.o), ctx };
      }
      next.set(p.key, c);
      els.push(c.chart.el);
    }
    disposeCharts(charts); // those not shown any more
    for (const [k, c] of next) charts.set(k, c);
    placeChildren(body, els.length ? els : emptyNote('This monitor reports nothing for these charts in this range.'));
  }

  /** disposeCharts ends the charts renderCharts shows (their contexts) and forgets them. */
  function disposeCharts(charts) {
    for (const c of charts.values()) c.ctx.dispose();
    charts.clear();
  }

  /** bucketWords words the buckets of a series' range (seriesGeom) for the tooltips and the
   *  table views: when each starts and ends, in local time and in UTC; times are their centres,
   *  where each bucket is plotted. */
  function bucketWords(g) {
    const { starts, stepMs } = g;
    return {
      times: starts.map((t) => t + stepMs / 2),
      label: (i) => F.short.format(new Date(starts[i])) + ' – ' + F.hm.format(new Date(starts[i] + stepMs)),
      utc: (i) => new Date(starts[i]).toISOString().slice(0, 16).replace('T', ' ') + ' – ' + new Date(starts[i] + stepMs).toISOString().slice(11, 16) + ' UTC',
    };
  }

  /** availabilityOpts is the availability chart: the classifier's worst state in each bucket
   *  (stateStrip). */
  function availabilityOpts(g) {
    return { id: 'availability', points: g.pts, from: g.from, to: g.to, stepMs: g.stepMs };
  }

  /** latencyOpts is the round-trip time chart (lineChart): the gateway's ICMP probe and every
   *  internet probe (chartProbes), the mean of the successful replies in each bucket. */
  function latencyOpts(ser, g, linked) {
    const b = bucketWords(g);
    return {
      id: 'latency', linked,
      title: 'Round-trip time',
      subtitle: 'Mean of the successful replies in each ' + fmtDur(g.stepMs / 1000) + ' bucket. Gaps: no successful reply, or no data.',
      series: chartProbes(ser).map((sp) => ({ ...sp, vals: g.pts.map((p) => numOrNull(p.rtt_ms && p.rtt_ms[sp.key])) })),
      times: b.times, from: g.from, to: g.to, gapMs: g.stepMs * 1.5, legend: true,
      yMin: 0, minMax: 5, robustMax: true,
      yFmt: (v) => fmtInt(v) + ' ms', tipFmt: fmtMs, tipTime: b.label, tipUTC: b.utc, unit: 'ms',
    };
  }

  /** lossOpts is the packet loss chart (lineChart) of the same probes: the share of attempts
   *  without a reply in each bucket. */
  function lossOpts(ser, g, linked) {
    const b = bucketWords(g);
    return {
      id: 'loss', linked,
      title: 'Packet loss',
      subtitle: 'Share of probe attempts without a reply in each bucket.',
      series: chartProbes(ser).map((sp) => ({ ...sp, vals: g.pts.map((p) => (p.loss && p.loss[sp.key] != null ? numOrNull(p.loss[sp.key] * 100) : null)) })),
      times: b.times, from: g.from, to: g.to, gapMs: g.stepMs * 1.5, legend: true,
      yMin: 0, yMax: 100,
      yFmt: (v) => v + ' %', tipFmt: (v) => (v == null ? '—' : Math.round(v * 10) / 10 + ' %'), tipTime: b.label, tipUTC: b.utc, unit: '%',
    };
  }

  /** fmtNum writes a number with at most two decimals (axis ticks, thresholds). */
  function fmtNum(v) {
    return v == null || !isFinite(v) ? '—' : Number(Number(v).toFixed(2)).toLocaleString();
  }

  // Units of rates, given in Mb/s: bits per second with SI prefixes (1 kb/s = 1,000 bit/s).
  const RATE_UNITS = [[1e-3, 'kb/s'], [1, 'Mb/s'], [1e3, 'Gb/s']];

  /** rateParts writes a rate given in Mb/s in the unit that suits it (kb/s, Mb/s or Gb/s), with
   *  the precision it deserves, as [number, unit]. */
  function rateParts(mbps) {
    if (mbps == null || !isFinite(mbps)) return ['—', ''];
    if (mbps === 0) return ['0', 'b/s'];
    const a = Math.abs(mbps);
    let i = a >= 1e3 ? 2 : a >= 1 ? 1 : 0;
    if (i < 2 && a / RATE_UNITS[i][0] >= 999.5) i++; // 999.96 Mb/s is 1.00 Gb/s, not "1,000 Mb/s"
    const v = mbps / RATE_UNITS[i][0];
    const r = Math.abs(v);
    return [r < 10 ? v.toFixed(2) : r < 100 ? v.toFixed(1) : Math.round(v).toLocaleString(), RATE_UNITS[i][1]];
  }

  /** fmtRate writes a rate given in Mb/s as rateParts does, in one string. */
  function fmtRate(mbps) {
    const [n, unit] = rateParts(mbps);
    return unit ? n + ' ' + unit : n;
  }

  /** rateAxis returns the tick labels of a rate axis that ends at hi Mb/s: every tick in the unit
   *  of the top one. */
  function rateAxis(hi) {
    const [div, unit] = RATE_UNITS[hi >= 1e3 ? 2 : hi >= 1 ? 1 : 0];
    return (v) => fmtNum(v / div) + ' ' + unit;
  }

  /** fmtLevel writes a set rate level in Mb/s (a threshold, a scale's end) as an axis does:
   *  "80 Mb/s", "1 Gb/s". */
  function fmtLevel(mbps) {
    return rateAxis(mbps)(mbps);
  }

  /** rateStats is what MRTG's legend says of a traffic series over the range: its maximum (from
   *  peaks when given: the highest rate between two readings; else the highest bucket), its
   *  average over the buckets with a reading, and its current value (the newest bucket with a
   *  reading). vals and peaks are Mb/s per bucket (null: no reading); atLeast flags the buckets
   *  whose rates are lower bounds, and a figure drawn from such a bucket is one too. Each figure
   *  is {v, i (its bucket; none for the average), atLeast}; null when nothing was read. */
  function rateStats(vals, peaks, atLeast) {
    let sum = 0;
    let n = 0;
    let anyAtLeast = false;
    let cur = -1;
    let top = -1;
    let topV = -Infinity;
    const lower = (i) => !!(atLeast && atLeast[i]);
    for (let i = 0; i < vals.length; i++) {
      const v = vals[i];
      if (v == null || !isFinite(v)) continue;
      sum += v;
      n++;
      cur = i;
      anyAtLeast = anyAtLeast || lower(i);
      const p = peaks && peaks[i] != null && isFinite(peaks[i]) ? Math.max(peaks[i], v) : v;
      if (p > topV) {
        topV = p;
        top = i;
      }
    }
    if (!n) return null;
    return {
      max: { v: topV, i: top, atLeast: lower(top) },
      avg: { v: sum / n, atLeast: anyAtLeast },
      cur: { v: vals[cur], i: cur, atLeast: lower(cur) },
    };
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

  /** trafficPart is the household's traffic in the manner of an MRTG graph — the "SNMP flow
   *  chart" without SNMP (Series.traffic, docs/syslog-snmp-traffic.md §3.3): from the AT&T
   *  gateway's own byte counters, the WAN download as a filled area and the upload as a line, in
   *  bits per second, each bucket's mean drawn across the bucket, with the highest rate between
   *  two readings marked and the classifier's heavy-traffic level; under it MRTG's legend: the
   *  maximum, average and current rate of each direction over the range, and this computer's. A
   *  part of renderCharts: the chart (lineChart), a figure that says there is no reading in the
   *  range, or null when the monitor reports no traffic at all. */
  function trafficPart(ser, from, to, stepMs) {
    const title = 'Traffic';
    const heavy = Number(ser.heavy_traffic_mbps) > 0 ? Number(ser.heavy_traffic_mbps) : null;
    const pts = (Array.isArray(ser.traffic) ? ser.traffic : []).filter((p) => p && typeof p === 'object' && toMs(p.t) != null);
    if (!pts.length) {
      if (heavy == null) return null;
      return {
        el: h('figure', { class: 'chart' }, h('figcaption', { class: 'chart-head' }, h('div', null, h('span', { class: 'chart-title' }, title))),
          emptyNote('No traffic readings in this range.')),
      };
    }
    const starts = pts.map((p) => toMs(p.t));
    const num = (v) => (v == null || !isFinite(v) ? null : Number(v));
    const col = (k) => pts.map((p) => num(p[k]));
    const atLeast = pts.map((p) => p.at_least === true);
    const anyAtLeast = atLeast.some(Boolean);
    const rx = col('wan_rx_mbps');
    const tx = col('wan_tx_mbps');
    const rxPeak = col('wan_rx_peak_mbps');
    const txPeak = col('wan_tx_peak_mbps');
    const pcRx = col('pc_rx_mbps');
    const pcTx = col('pc_tx_mbps');
    const bucket = (i) => F.short.format(new Date(starts[i])) + ' – ' + F.hm.format(new Date(starts[i] + stepMs));
    const legendExtra = [[tickKey(0), 'peak: the highest rate between two readings in the bucket']];
    if (anyAtLeast) legendExtra.push([chevronKey(), 'at least: the true rate may have been higher']);
    const summary = trafficSummary([
      { key: areaKey(1), label: 'WAN download', vals: rx, peaks: rxPeak, atLeast },
      { key: lineKey(2), label: 'WAN upload', vals: tx, peaks: txPeak, atLeast },
      { label: 'This PC download', vals: pcRx },
      { label: 'This PC upload', vals: pcTx },
    ], bucket);
    return { key: 'traffic', kind: 'line', o: {
      id: 'traffic', linked: null,
      title,
      subtitle: 'Bits per second through the AT&T gateway, from its own IPv4 byte counters (it offers no SNMP), as MRTG draws it: download filled, upload as a line, the mean of each ' +
        fmtDur(stepMs / 1000) + ' bucket across the bucket, and short marks at the highest rate between two of the gateway’s readings.' +
        (heavy != null ? ' Dashed line: ' + fmtLevel(heavy) + ', from which the household’s own traffic may slow the connection by itself, so a slowdown is not attributed to AT&T.' : '') +
        ' Gaps: no reading.' +
        (anyAtLeast ? ' Chevron: the gateway’s 32-bit byte counter may have wrapped more often than can be told, so the rate was at least the one shown.' : ''),
      series: [
        { key: 'wan_rx', label: 'WAN download', slot: 1, vals: rx, atLeast, area: true, step: true },
        { key: 'wan_rx_peak', of: 'wan_rx', mark: 'tick', label: 'WAN download peak', slot: 1, vals: rxPeak, atLeast },
        { key: 'wan_tx', label: 'WAN upload', slot: 2, vals: tx, atLeast, step: true },
        { key: 'wan_tx_peak', of: 'wan_tx', mark: 'tick', label: 'WAN upload peak', slot: 2, vals: txPeak, atLeast },
        { key: 'pc_rx', label: 'This PC download', vals: pcRx, plot: false },
        { key: 'pc_tx', label: 'This PC upload', vals: pcTx, plot: false },
      ],
      times: starts.map((t) => t + stepMs / 2), from, to, gapMs: stepMs * 1.5, stepMs, legend: true, legendExtra,
      yMin: 0, minMax: 1,
      thresholds: heavy != null ? [{ v: heavy, tone: 'ref', place: 'above', label: 'Heavy household traffic ' + fmtLevel(heavy) }] : [],
      atLeast: anyAtLeast ? { at: atLeast, keys: ['wan_rx', 'wan_tx'] } : null,
      yFmt: fmtNum, yFmtFor: rateAxis,
      tipFmt: (v, se, i) => (v == null ? '—' : (se && se.atLeast && se.atLeast[i] ? 'at least ' : '') + fmtRate(v)),
      tipTime: bucket,
      tipUTC: (i) => new Date(starts[i]).toISOString().slice(0, 16).replace('T', ' ') + ' – ' + new Date(starts[i] + stepMs).toISOString().slice(11, 16) + ' UTC',
      after: summary,
    } };
  }

  /** trafficSummary is MRTG's legend under the traffic chart: for each row (key, label, vals,
   *  peaks, atLeast) the maximum, average and current rate over the range (rateStats), with the
   *  bucket of a maximum or current value on hover (bucket(i) words it). */
  function trafficSummary(rows, bucket) {
    const cell = (x) => {
      if (!x) return '—';
      const text = (x.atLeast ? 'at least ' : '') + fmtRate(x.v);
      return x.i != null ? h('span', { title: bucket(x.i) }, text) : text;
    };
    const body = rows.map((r) => {
      const st = rateStats(r.vals, r.peaks, r.atLeast);
      return [h('span', { class: 'nowrap' }, r.key || null, r.key ? ' ' : null, r.label), cell(st && st.max), cell(st && st.avg), cell(st && st.cur)];
    });
    return h('div', { class: 'mrtg' },
      table([{ label: 'In this range' }, { label: 'Maximum', num: true }, { label: 'Average', num: true }, { label: 'Current', num: true }], body,
        { compact: true, stack: true }),
      h('p', { class: 'chart-note' }, 'Maximum: the highest rate between two readings of the gateway’s counters (this PC: the highest bucket). ' +
        'Average: over the buckets with a reading. Current: the newest bucket with a reading. Hover a figure for its time.'));
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

  /** median is the upper middle value of arr (0 without one), for the gap heuristics of the
   *  charts; a median that is shown is medianOf's. */
  function median(arr) {
    if (!arr.length) return 0;
    const a = arr.slice().sort((x, y) => x - y);
    return a[Math.floor(a.length / 2)];
  }

  /** medianOf is the median of arr as the classifier computes it (internal/monitor medianMs):
   *  the mean of the two middle values for an even count; null without a value. */
  function medianOf(arr) {
    if (!arr.length) return null;
    const a = arr.slice().sort((x, y) => x - y);
    const n = a.length;
    return n % 2 ? a[(n - 1) / 2] : (a[n / 2 - 1] + a[n / 2]) / 2;
  }

  /** opticalPart is the light the gateway received against its own alarm and warning thresholds,
   *  with its own Rx-low flag as a strip under it. A part of renderCharts: the chart (lineChart),
   *  or a figure that says there is no reading in the range. */
  function opticalPart(ser, from, to) {
    const pts = (ser.optical || [])
      .map((p) => ({ t: toMs(p.t), rx: p.rx_x10 != null ? p.rx_x10 / 10 : null, alarm: !!p.rx_low_alarm, warn: !!p.rx_low_warn }))
      .filter((p) => p.t != null && p.t >= from && p.t <= to)
      .sort((a, b) => a.t - b.t);
    const title = 'Fiber receive power vs the gateway’s own thresholds';
    if (!pts.length) {
      return {
        el: h('figure', { class: 'chart' }, h('figcaption', { class: 'chart-head' }, h('div', null, h('span', { class: 'chart-title' }, title))),
          emptyNote('No optical readings from the gateway in this range.')),
      };
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
    return { key: 'optical', kind: 'line', o: {
      id: 'optical', linked: null,
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
    } };
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
    const steps = [5 * 60e3, 10 * 60e3, 15 * 60e3, 30 * 60e3, H1, 2 * H1, 3 * H1, 6 * H1, 12 * H1, D1, 2 * D1, 3 * D1, 7 * D1, 14 * D1];
    const step = steps.find((st) => span / st <= maxTicks) || 14 * D1;
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

  /** chartTableView is a chart's table view: a focusable scroll region (keyed, data-fk, so that
   *  keepFocus finds it again in a chart drawn anew) holding the table of cols and rows. */
  function chartTableView(o, cols, rows) {
    const wrap = h('div', { class: 'chart-table', tabindex: '0', role: 'region', 'aria-label': o.title + ' — table view', 'data-fk': 'chart:' + o.id + ':tableview' });
    wrap.append(table(cols, rows, { compact: true }).firstChild);
    return wrap;
  }

  /** fillTableView shows cols and rows in the table view of wrap: in the region already there (it
   *  keeps the keyboard focus and its scroll position: new data every minute must not send the
   *  reader back to the first row), else in a new one (chartTableView). */
  function fillTableView(wrap, o, cols, rows) {
    const region = wrap.firstChild;
    if (region) replace(region, table(cols, rows, { compact: true }).firstChild);
    else wrap.append(chartTableView(o, cols, rows));
  }

  /** chartFrame builds the figure, caption (cap; its title and subtitle in head, chartCaption),
   *  table toggle and the focusable plot area. The plot and the toggle carry keys (data-fk) by
   *  which keepFocus finds them in a chart drawn anew. */
  function chartFrame(o) {
    const fig = h('figure', { class: 'chart' });
    const tableBtn = h('button', { type: 'button', class: 'btn btn-small', 'aria-pressed': String(app.tableViews.has(o.id)), title: 'Show the data as a table (T)', 'data-fk': 'chart:' + o.id + ':table' }, 'Table');
    const head = chartCaption(h('div'), o.title, o.subtitle);
    const cap = h('figcaption', { class: 'chart-head' }, head, tableBtn);
    fig.append(cap);
    const plot = h('div', {
      class: 'plot', tabindex: '0', role: 'group', 'aria-roledescription': 'chart', 'data-fk': 'chart:' + o.id + ':plot',
      'aria-label': o.title + '. Use the left and right arrow keys to read values, T for the table view.',
    });
    const tip = h('div', { class: 'tip', hidden: true, 'aria-hidden': 'true' });
    plot.append(tip);
    const live = h('div', { class: 'sr-only', 'aria-live': 'polite' });
    return { fig, cap, head, tableBtn, plot, tip, live };
  }

  /** chartCaption writes a chart's title and subtitle in head (chartFrame's) and returns it. */
  function chartCaption(head, title, subtitle) {
    return replace(head, h('span', { class: 'chart-title' }, title), subtitle ? h('p', { class: 'chart-sub' }, subtitle) : null);
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
   * o: {id, title, subtitle, series:[{key,label,slot,vals,mark,of,step,area,plot}], times, from,
   *     to, gapMs, stepMs, legend, legendExtra, linked, yMin, yMax, minMax, robustMax, pad,
   *     thresholds, band, atLeast, yFmt, yFmtFor, tipFmt(v, series, i), tipTime, tipExtra, unit,
   *     after, ctx}
   * A series with mark 'tick' is drawn as a short mark per value (e.g. the peak of a bucket);
   * one with "of" has no legend button and shows and hides with the series it names. A series
   * with step is drawn level across each bucket (stepMs wide, centred on its time), one with
   * area is filled down to the axis, and one with plot false is not drawn: the tooltip and the
   * table view show it. legendExtra lists further legend entries ([key, label]). atLeast {at:
   * [bool], keys} marks the values at those indexes, of those series, as lower bounds: a chevron
   * above them. yFmtFor(hi), when given, returns the tick labels for an axis that ends at hi
   * (units that follow the scale). after is shown under the plot.
   * Returns {el, update(o)}: update shows the same chart for new data (a newer series, another
   * range) in place - the plot keeps the keyboard focus and the time it shows (quietly: nothing is
   * announced again), the table view its focus and scroll position - and returns false, changing
   * nothing, when it cannot (a chart with a flag strip and one without differ in height).
   */
  function lineChart(o0) {
    let o = o0;
    const { fig, cap, head, tableBtn, plot, tip, live } = chartFrame(o);
    const H = o.band ? 252 : 224;
    // Its height before its first draw (CSSOM: allowed by the CSP): a chart drawn anew must not
    // make the page shorter for a moment, which would throw the reader's scroll position.
    plot.style.minHeight = H + 'px';
    const bandLegend = o.band && o.band.legend ? h('ul', { class: 'legend', 'aria-label': 'Flag strip legend' },
      o.band.legend.map(([tone, label]) => h('li', null, h('span', { class: 'static' }, icon(tone), label)))) : null;
    const note = h('p', { class: 'chart-note', hidden: true });
    const tableWrap = h('div', { hidden: true });
    let legendEl = null;
    let legendKey = null;

    let W = 0;
    let g = null;
    let idx = -1; // the value shown last (keyboard or pointer): the arrow keys go on from it
    let want = false; // its tooltip is shown, or is to be once the plot is drawn

    /** legend builds the legend (legendEl): its buttons (each series shown or hidden, for every
     *  linked chart) and its further entries, anew only when they change (legendKey), so that a
     *  button the keyboard is on stays; none with fewer than two series. */
    function legend() {
      const primary = o.series.filter((se) => !se.of && se.plot !== false);
      const show = o.legend && primary.length > 1;
      const k = JSON.stringify(show ? [primary.map((se) => [se.key, se.label, se.slot, !!se.area]), (o.legendExtra || []).map((x) => x[1])] : null);
      if (k === legendKey) return;
      legendKey = k;
      legendEl = null;
      if (!show) return;
      legendEl = h('ul', { class: 'legend', 'aria-label': 'Series — select to show or hide' });
      for (const se of primary) {
        const btn = h('button', { type: 'button', 'aria-pressed': String(!app.hidden.has(se.key)), dataset: { key: se.key }, 'data-fk': 'chart:' + o.id + ':legend:' + se.key },
          se.area ? areaKey(se.slot) : lineKey(se.slot), se.label);
        btn.addEventListener('click', () => {
          if (app.hidden.has(se.key)) app.hidden.delete(se.key); else app.hidden.add(se.key);
          for (const c of o.linked || [api_]) c.refresh();
        });
        legendEl.append(h('li', null, btn));
      }
      for (const [key, label] of o.legendExtra || []) legendEl.append(h('li', null, h('span', { class: 'static' }, key, label)));
    }

    /** place puts the chart's parts in its figure (placeChildren: the plot, and whatever has the
     *  keyboard focus, stays where it is). */
    function place() {
      placeChildren(fig, cap, legendEl, bandLegend, plot, note, o.after, live, tableWrap);
    }
    legend();
    place();

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
        if (se.plot === false) continue;
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
      g.yFmt = o.yFmtFor ? o.yFmtFor(g.hi) : o.yFmt;
      const svg = s('svg', { width: W, height: H, viewBox: `0 0 ${W} ${H}`, 'aria-hidden': 'true', focusable: 'false' });
      for (const t of g.ticks) {
        const y = Math.round(g.ys(t)) + 0.5;
        svg.append(s('line', { class: 'gl', x1: g.x0, x2: g.x1, y1: y, y2: y }),
          s('text', { class: 'tk', x: g.x0 - 8, y: y + 3.5, 'text-anchor': 'end' }, g.yFmt(t)));
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
      const base = g.ys(g.lo).toFixed(1); // the axis, where areas end
      for (const se of g.vis) {
        if (se.plot === false) continue;
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
        const segs = []; // runs of readings without a gap: [{t, y}]
        let cur = null;
        let prevT = null;
        for (let i = 0; i < se.vals.length; i++) {
          const v = se.vals[i];
          const t = o.times[i];
          if (v == null || !isFinite(v) || t < o.from || t > o.to) { cur = null; continue; }
          let vv = v;
          if (vv > g.hi) { vv = g.hi; clamped++; }
          if (vv < g.lo) vv = g.lo;
          const pt = { t, y: g.ys(vv) };
          if (cur && prevT != null && t - prevT <= o.gapMs) cur.push(pt);
          else { cur = [pt]; segs.push(cur); }
          prevT = t;
        }
        let d = '';
        let fill = '';
        if (se.step) {
          // Each bucket's value level across the bucket, verticals where it changes.
          const hw = (o.stepMs || spacing) / 2;
          const X = (t) => Math.min(g.x1, Math.max(g.x0, g.xs(t))).toFixed(1);
          for (const seg of segs) {
            let sd = '';
            for (let k = 0; k < seg.length; k++) {
              const y = seg[k].y.toFixed(1);
              sd += (k ? 'H' + X(seg[k].t - hw) + 'V' + y : 'M' + X(seg[k].t - hw) + ' ' + y) + 'H' + X(seg[k].t + hw);
            }
            d += sd;
            if (se.area) fill += 'M' + X(seg[0].t - hw) + ' ' + base + 'L' + sd.slice(1) + 'V' + base + 'Z';
          }
        } else {
          for (const seg of segs) {
            if (seg.length === 1) {
              svg.append(s('circle', { class: 'dot f' + se.slot, cx: g.xs(seg[0].t).toFixed(1), cy: seg[0].y.toFixed(1), r: 4 }));
              continue;
            }
            const line = seg.map((p) => g.xs(p.t).toFixed(1) + ' ' + p.y.toFixed(1)).join('L');
            d += 'M' + line;
            if (se.area) fill += 'M' + g.xs(seg[0].t).toFixed(1) + ' ' + base + 'L' + line + 'L' + g.xs(seg[seg.length - 1].t).toFixed(1) + ' ' + base + 'Z';
          }
        }
        if (fill) svg.append(s('path', { class: 'area f' + se.slot, d: fill }));
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
      if (clamped) note.textContent = `${clamped} value${clamped > 1 ? 's' : ''} above ${g.yFmt(g.hi)} ${clamped > 1 ? 'are' : 'is'} drawn at the top edge; the table view has the exact numbers.`;
      g.xh = s('line', { class: 'xh', x1: 0, x2: 0, y1: g.y1, y2: g.y0, visibility: 'hidden' });
      g.dots = s('g', { visibility: 'hidden' });
      svg.append(g.xh, g.dots);
      const old = plot.querySelector('svg');
      if (old) old.replaceWith(svg); else plot.insertBefore(svg, tip);
      if (want && idx >= 0) showAt(idx, true); // shown again where it was, quietly (a resize, new data)
    }

    function bandAt(t) {
      if (!o.band) return null;
      return o.band.runs.find((r) => t >= r.start && t <= r.end) || null;
    }

    /** showAt shows value i: its crosshair and tooltip, and its figures in the live region unless
     *  shown from the pointer or again after a redraw (pointer true). Before the plot is drawn it
     *  only notes it: draw shows it. */
    function showAt(i, pointer) {
      if (i < 0 || i >= o.times.length) { hide(); return; }
      idx = i;
      want = true;
      if (!g) return;
      const x = g.xs(o.times[i]);
      g.xh.setAttribute('x1', x);
      g.xh.setAttribute('x2', x);
      g.xh.setAttribute('visibility', 'visible');
      replace(g.dots);
      const rows = [];
      for (const se of g.vis) {
        const v = se.vals[i];
        const drawn = se.plot !== false;
        if (drawn && v != null && isFinite(v)) {
          g.dots.append(s('circle', { class: 'dot f' + se.slot, cx: x, cy: g.ys(Math.min(Math.max(v, g.lo), g.hi)), r: 4 }));
        }
        rows.push(h('div', { class: 'tip-row' }, !drawn ? h('span') : se.mark === 'tick' ? tickKey(se.slot) : lineKey(se.slot),
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
      want = false;
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
        case 'Escape': hideByKey(e); return;
        case 't': case 'T': tableBtn.click(); return;
        default: return;
      }
      e.preventDefault();
      showAt(i, false);
    });

    /** hideByKey hides the tooltip on Esc; the key does nothing else then, so that inside a
     *  modal (the Overview's details) only a second Esc closes it. */
    function hideByKey(e) {
      if (tip.hidden) return;
      e.preventDefault();
      hide();
    }

    /** fillTable shows the values in the table view (fillTableView), newest first. */
    function fillTable() {
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
      fillTableView(tableWrap, o, cols, rows);
    }

    function applyView() {
      const on = app.tableViews.has(o.id);
      tableBtn.setAttribute('aria-pressed', String(on));
      plot.hidden = on;
      tableWrap.hidden = !on;
      if (on && !tableWrap.firstChild) fillTable();
      if (!on && plot.clientWidth && Math.round(plot.clientWidth) !== W) draw();
    }
    tableBtn.addEventListener('click', () => {
      if (app.tableViews.has(o.id)) app.tableViews.delete(o.id); else app.tableViews.add(o.id);
      applyView();
    });

    /** refreshLegend shows on the legend's buttons which series are shown (app.hidden). */
    function refreshLegend() {
      if (!legendEl) return;
      for (const btn of legendEl.querySelectorAll('button')) btn.setAttribute('aria-pressed', String(!app.hidden.has(btn.dataset.key)));
    }

    const api_ = {
      refresh() {
        refreshLegend();
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

    /** update shows the same chart for new data (o2) in place: see lineChart. */
    function update(o2) {
      if (!!o2.band !== !!o.band) return false;
      const at = idx >= 0 ? o.times[idx] : null;
      o = Object.assign(o2, { ctx: o.ctx });
      chartCaption(head, o.title, o.subtitle);
      legend();
      refreshLegend();
      place(); // the flag strip's legend (bandLegend) is the same for every series of the chart
      if (o.linked) o.linked.push(api_);
      // The value shown last, by its time: still shown, quietly, when it is in the new data.
      idx = at != null && at >= o.from && at <= o.to && o.times.length ? nearestIndex(o.times, at) : -1;
      if (idx < 0 && want) hide();
      if (app.tableViews.has(o.id)) fillTable(); else replace(tableWrap); // made again when shown
      if (!plot.hidden && plot.clientWidth) draw(); else W = 0; // drawn again once shown (applyView, the resize observer)
      return true;
    }
    return { el: fig, update };
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

  /** stateStrip draws the classifier's worst state in each bucket of a series' range (o: {id,
   *  points, from, to, stepMs, ctx}) as runs of states, with their legend, their shares of the
   *  range, a tooltip on hover and from the keyboard, and a table view. Returns {el, update(o)}:
   *  update shows new data in place, as lineChart's does (the run shown last stays shown, by its
   *  time, quietly). */
  function stateStrip(o0) {
    let o = o0;
    const { fig, cap, head, tableBtn, plot, tip, live } = chartFrame({ id: o.id, title: 'Availability' });
    const H = 64;
    plot.style.minHeight = H + 'px'; // its height before its first draw (see lineChart)
    const summary = h('p', { class: 'chart-summary' });
    const tableWrap = h('div', { hidden: true });
    let runs = [];
    let legendEl = null;
    let legendKey = null;
    let W = 0;
    let g = null;
    let idx = -1; // the run shown last
    let want = false; // its tooltip is shown, or is to be once the plot is drawn

    /** compute works out the runs of o and what is said of them: the caption, the legend (anew
     *  only when its states change) and the shares of the range; place puts them in the figure. */
    function compute() {
      runs = stateRuns(o.points, o.from, o.to, o.stepMs);
      const order = stripOrder(runs);
      const unknown = order.includes('UNKNOWN');
      chartCaption(head, 'Availability', 'Worst classifier state in each ' + fmtDur(o.stepMs / 1000) + ' bucket. Grey: the monitor was not measuring' +
        (unknown ? ', or its measurements could not be judged (Unknown).' : '.'));
      const k = order.join('|');
      if (k !== legendKey) {
        legendKey = k;
        legendEl = h('ul', { class: 'legend', 'aria-label': 'States' },
          order.map((st) => h('li', null, h('span', { class: 'static' }, icon(stateInfo(st).tone), stateInfo(st).label))));
      }
      const total = {};
      let all = 0;
      for (const r of runs) {
        total[r.state] = (total[r.state] || 0) + (r.end - r.start);
        all += r.end - r.start;
      }
      replace(summary, all > 0 ? ['Share of this range: ', order.filter((st) => total[st]).map((st) =>
        h('span', { class: 'badge' }, icon(stateInfo(st).tone), stateInfo(st).label + ' ' + fmtPct((100 * total[st]) / all, 2)))] : null);
      placeChildren(fig, cap, legendEl, plot, summary, live, tableWrap);
    }
    compute();

    function draw() {
      W = Math.max(260, Math.round(plot.clientWidth));
      const x0 = 54;
      const x1 = W - 14;
      const xs = (t) => x0 + ((t - o.from) / (o.to - o.from)) * (x1 - x0);
      const svg = s('svg', { width: W, height: H, viewBox: `0 0 ${W} ${H}`, 'aria-hidden': 'true', focusable: 'false' });
      for (let i = 0; i < runs.length; i++) {
        const r = runs[i];
        const a = xs(r.start);
        let w = xs(r.end) - a;
        if (i < runs.length - 1 && w > 6) w -= 2; // 2px surface gap between touching runs
        if (r.state !== 'ONLINE' && r.state !== '') w = Math.max(w, 2); // a blip stays visible
        svg.append(s('rect', { class: 'sf-' + stateInfo(r.state).tone, x: a.toFixed(1), y: 6, width: Math.max(1, w).toFixed(1), height: 28, rx: 2 }));
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
      if (want && idx >= 0) showAt(idx, true); // shown again where it was, quietly (a resize, new data)
    }

    /** showAt shows run i: its outline and tooltip, and its words in the live region unless shown
     *  from the pointer or again after a redraw (pointer true). Before the plot is drawn it only
     *  notes it: draw shows it. */
    function showAt(i, pointer) {
      if (i < 0 || i >= runs.length) { hide(); return; }
      idx = i;
      want = true;
      if (!g) return;
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
      want = false;
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
        case 'Escape':
          // As in lineChart: Esc hides the tooltip first, and only then closes a modal around it.
          if (!tip.hidden) {
            e.preventDefault();
            hide();
          }
          return;
        case 't': case 'T': tableBtn.click(); return;
        default: return;
      }
      e.preventDefault();
      showAt(i, false);
    });

    /** fillTable shows the runs in the table view (fillTableView), newest first. */
    function fillTable() {
      const rows = runs.slice().reverse().map((r) => [h('span', { class: 'badge' }, icon(stateInfo(r.state).tone), stateInfo(r.state).label), timeEl(r.start, F.full), timeEl(r.end, F.full), fmtDur((r.end - r.start) / 1000)]);
      fillTableView(tableWrap, { id: o.id, title: 'Availability' }, [{ label: 'State' }, { label: 'From' }, { label: 'To' }, { label: 'Duration', num: true }], rows);
    }

    function applyView() {
      const on = app.tableViews.has(o.id);
      tableBtn.setAttribute('aria-pressed', String(on));
      plot.hidden = on;
      tableWrap.hidden = !on;
      if (on && !tableWrap.firstChild) fillTable();
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

    /** update shows the same chart for new data (o2) in place: see stateStrip. */
    function update(o2) {
      const at = idx >= 0 && runs[idx] ? runs[idx].start : null;
      o = Object.assign(o2, { ctx: o.ctx });
      compute();
      // The run shown last, by its start: the run that holds it now.
      idx = at == null ? -1 : runs.findIndex((r) => at >= r.start && at < r.end);
      if (idx < 0 && want) hide();
      if (app.tableViews.has(o.id)) fillTable(); else replace(tableWrap); // made again when shown
      if (!plot.hidden && plot.clientWidth) draw(); else W = 0; // drawn again once shown (applyView, the resize observer)
      return true;
    }
    return { el: fig, update };
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
      case 'syslog_chunk': {
        // A sealed chunk of the gateway's syslog messages: the store keeps the file within its
        // limit, this record its SHA-256 for good.
        const n = Number(d.messages) || 0;
        const parts = ['received ' + whenText(d.from) + ' to ' + whenText(d.to),
          'SHA-256 ' + shortHash(d.sha256, 16) + ' of ' + fmtBytes(d.bytes) + ' (' + fmtBytes(d.gz_bytes) + ' compressed)', 'chunk ' + orQ(d.name)];
        if (d.dropped > 0) parts.push(`${fmtInt(d.dropped)} more over the per-minute cap (counted, not stored)`);
        if (d.rejected > 0) parts.push(`${fmtInt(d.rejected)} datagram${d.rejected === 1 ? '' : 's'} from other senders (counted, not stored)`);
        return { tone: 'info', title: `Gateway syslog: ${fmtInt(n)} message${n === 1 ? '' : 's'} sealed in a chunk (${SEAL_REASONS[d.reason] || orQ(d.reason)})`, detail: parts.join(' · ') };
      }
      case 'syslog_prune': {
        // Chunks deleted to stay within the limits; their SHA-256 stay in their syslog_chunk records.
        const del = Array.isArray(d.deleted) ? d.deleted.filter((x) => x && typeof x === 'object') : [];
        const msgs = del.reduce((acc, x) => acc + (Number(x.messages) || 0), 0);
        const parts = ['limit ' + orQ(d.reason), `${fmtInt(d.kept_chunks)} chunks (${fmtBytes(d.kept_bytes)}) kept`];
        if (del.length) parts.push('deleted ' + del.slice(0, 3).map((x) => orQ(x.name)).join(', ') + (del.length > 3 ? ` and ${fmtInt(del.length - 3)} more` : ''));
        return {
          tone: 'info',
          title: `Gateway syslog: ${fmtInt(del.length)} chunk${del.length === 1 ? '' : 's'} (${fmtInt(msgs)} message${msgs === 1 ? '' : 's'}) deleted to stay within the limit`,
          detail: parts.join(' · '),
        };
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
      h('p', { class: 'muted' }, 'The AT&T gateway’s own log messages as this PC received them, kept in the syslog store within the limit you choose, the oldest deleted first. Every sealed chunk of messages is recorded in the evidence ledger with its SHA-256, and so is every deletion. Each message keeps the exact datagram; its time is when this PC received it.')));
    const alerts = h('div', { class: 'conditions' });
    const statusArea = h('div');
    const store = syslogStorePanel();
    const panel = syslogPanel(ctx, false);
    let none = null; // what the page says without a syslog status
    const update = (st) => {
      fillAlerts(alerts, st, SYSLOG_ALERTS);
      store.update(st);
      const card = panel.update(st);
      if (!card && !none) none = callout('info', 'This monitor reports no syslog receiver: the messages below are the ones the syslog store holds.');
      placeChildren(statusArea, card || none);
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
    c.append(alerts, statusArea, store.el, form, out);
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

  /** syslogStorePanel shows how much the syslog store holds against its limits
   *  (Status.syslog.store) and lets the operator choose how much to keep (POST
   *  /api/syslog/retention). The form is built once: a status refresh updates the figures and,
   *  until the operator types, the form's values, never what is being typed. A change that
   *  deletes messages now is confirmed first; saving the limits in force is said to change,
   *  record and delete nothing (the monitor's answer "unchanged"). Returns { el, update(st) }. */
  function syslogStorePanel() {
    const usage = h('div');
    const mib = h('input', { type: 'number', name: 'keep_mb', min: String(SYSLOG_KEEP_MB_MIN), max: String(SYSLOG_KEEP_MB_MAX), step: '1', inputmode: 'numeric', required: true });
    const days = h('input', { type: 'number', name: 'keep_days', min: '0', max: String(SYSLOG_KEEP_DAYS_MAX), step: '1', inputmode: 'numeric', placeholder: 'no age limit' });
    const btn = h('button', { type: 'submit', class: 'btn btn-primary' }, 'Save');
    const out = h('div', { 'aria-live': 'polite' });
    const form = h('form', { class: 'form retention', 'aria-label': 'How much syslog to keep' },
      h('div', { class: 'form-grid' },
        field('Keep at most (MiB)', mib, `The oldest messages are deleted first once the stored messages take more. ${fmtInt(SYSLOG_KEEP_MB_MIN)} to ${fmtInt(SYSLOG_KEEP_MB_MAX)} MiB (1 TiB); 100 by default.`),
        field('Also delete messages older than (days)', days, `Optional: empty or 0 keeps messages of any age that fit. At most ${fmtInt(SYSLOG_KEEP_DAYS_MAX)}.`)),
      h('div', { class: 'btn-row' }, btn));
    const el = h('section', { class: 'card', 'aria-labelledby': 'syslog-store-h', hidden: true },
      h('div', { class: 'card-head' }, h('h2', { id: 'syslog-store-h' }, 'Stored messages')), usage, form, out);
    let store = null; // the store as last shown (Status.syslog.store)
    let usageKey = null;
    let edited = false; // the operator changed the form since it was filled in
    let unavailable = false; // the monitor offers no control of the store (404)
    for (const inp of [mib, days]) inp.addEventListener('input', () => { edited = true; });

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const mb = wholeNumber(mib.value);
      const d = days.value.trim() === '' ? 0 : wholeNumber(days.value);
      if (mb == null || mb < SYSLOG_KEEP_MB_MIN || mb > SYSLOG_KEEP_MB_MAX) {
        replace(out, notice('critical', `Enter a whole number of MiB from ${fmtInt(SYSLOG_KEEP_MB_MIN)} to ${fmtInt(SYSLOG_KEEP_MB_MAX)}.`));
        mib.focus();
        return;
      }
      if (d == null || d > SYSLOG_KEEP_DAYS_MAX) {
        replace(out, notice('critical', `Enter a whole number of days from 0 (no age limit) to ${fmtInt(SYSLOG_KEEP_DAYS_MAX)}, or leave it empty.`));
        days.focus();
        return;
      }
      const loss = retentionLoss(store, mb, d);
      if (loss && !(await dialog({
        title: 'Delete the oldest syslog messages now?',
        body: [h('p', null, loss),
          h('p', null, 'The SHA-256 of every deleted chunk stays in the evidence ledger (its syslog_chunk record) and the deletion is recorded (a syslog_prune record), but the messages themselves cannot be brought back.')],
        confirm: 'Save and delete',
      }))) return;
      btn.disabled = true;
      replace(out, notice('info', spinner(), ' Saving…'));
      try {
        const cc = (await api('/api/syslog/retention', { method: 'POST', body: { keep_mb: mb, keep_days: d } })) || {};
        edited = false;
        const result = String(cc.result || 'applied');
        const limits = 'at most ' + fmtInt(mb) + ' MiB' +
          (d > 0 ? ', and nothing older than ' + fmtInt(d) + ' day' + (d === 1 ? '' : 's') : ' of messages of any age');
        if (/^\s*unchanged/i.test(result)) {
          // The limits in force: the monitor neither recorded nor deleted anything.
          replace(out, notice('good', h('strong', null, 'Already in force. '), 'The syslog store keeps ' + limits +
            ' already: nothing was changed, so nothing was recorded in the evidence ledger and nothing was deleted.'));
          announce('Syslog retention unchanged: already in force.');
        } else {
          replace(out, notice('good', h('strong', null, 'Saved. '), 'The syslog store keeps ' + limits +
            '. Recorded in the evidence ledger as a configuration change: ', String(cc.what || 'syslog retention'), ', ',
            String(cc.before || '?'), ' → ', String(cc.after || '?'), ' (', result, ').'));
          announce('Syslog retention saved.');
        }
      } catch (err) {
        if (err.status === 404) {
          unavailable = true;
          form.hidden = true;
          replace(out, callout('info', sentence(capitalize(err.message))));
        } else {
          // Do not claim "not changed": the limits may be in effect although something after
          // that failed (the answer's change says so).
          const ch = err.data && err.data.change;
          const result = ch && ch.result ? String(ch.result) : '';
          replace(out, result && !/^\s*failed/i.test(result)
            ? notice('warning', sentence(capitalize(err.message)))
            : notice('critical', 'The setting could not be saved: ', sentence(err.message)));
        }
      } finally {
        btn.disabled = false;
        refreshStatus();
      }
    });

    return {
      el,
      update(st) {
        const sl = st && st.syslog && typeof st.syslog === 'object' ? st.syslog : null;
        const u = syslogStore(sl);
        el.hidden = !sl; // without a receiver the page says so above
        const key = JSON.stringify(u);
        if (key !== usageKey) {
          usageKey = key;
          replace(usage, u ? syslogUsageBlock(u)
            : callout('info', 'This monitor reports no syslog store, so how much is kept cannot be shown or changed here.'));
        }
        store = u;
        form.hidden = !u || unavailable;
        if (u && !edited) {
          mib.value = Number(u.keep_mb) > 0 ? String(u.keep_mb) : '';
          days.value = Number(u.keep_days) > 0 ? String(u.keep_days) : '';
        }
      },
    };
  }

  /** wholeNumber parses a whole number typed in a form (null: not one). */
  function wholeNumber(v) {
    const t = String(v == null ? '' : v).trim();
    return /^\d{1,9}$/.test(t) ? Number(t) : null;
  }

  /** syslogUsageBlock shows the syslog store's volume against its limits: "<used> of <limit>
   *  used, oldest message <time>, <n> chunks", then what it holds. */
  function syslogUsageBlock(u) {
    const used = Number(u.bytes) || 0;
    const limit = Number(u.keep_mb) > 0 ? Number(u.keep_mb) * MIB : 0;
    const chunks = Number(u.chunks) || 0;
    const open = Number(u.open_messages) || 0;
    return h('div', { class: 'store-usage' },
      h('p', { class: 'store-line' }, h('strong', null, syslogUsageText(u)),
        u.oldest ? [', oldest message ', timeEl(u.oldest, F.short)] : ', no message kept yet',
        ', ' + fmtInt(chunks) + ' chunk' + (chunks === 1 ? '' : 's')),
      limit ? meter((100 * used) / limit, 'wide') : null,
      h('p', { class: 'small muted' }, fmtInt(Number(u.messages) || 0) + ' messages kept',
        open ? ', ' + fmtInt(open) + ' of them in the open chunk (sealed and recorded in the evidence ledger within minutes)' : '',
        '. ', Number(u.keep_days) > 0 ? 'Messages older than ' + fmtInt(u.keep_days) + ' days are deleted too.' : 'No age limit.'));
  }

  /** retentionLoss says what new limits would delete from the store now ('' = nothing). The
   *  limits in force delete nothing when saved again (the monitor answers "unchanged" and
   *  neither records nor prunes), although the store may hold a little more than its size
   *  limit between two seals: the open chunk counts uncompressed until it is sealed. */
  function retentionLoss(u, keepMB, keepDays) {
    if (!u) return '';
    if (keepMB === Number(u.keep_mb) && keepDays === (Number(u.keep_days) || 0)) return '';
    const parts = [];
    const used = Number(u.bytes) || 0;
    if (used > keepMB * MIB) parts.push('the store holds ' + fmtBytes(used) + ', more than ' + fmtInt(keepMB) + ' MiB');
    const oldest = toMs(u.oldest);
    if (keepDays > 0 && oldest != null && Date.now() - oldest > keepDays * 86400e3) {
      parts.push('its oldest message, received ' + F.full.format(new Date(oldest)) + ', is older than ' + fmtInt(keepDays) + ' day' + (keepDays === 1 ? '' : 's'));
    }
    return parts.length ? 'The oldest messages are deleted as soon as you save: ' + parts.join(', and ') + '.' : '';
  }

  /** syslogBrowser shows in el the messages GET /api/syslog returns for a period and filters,
   *  newest first, with "Load more" while more matched: that asks again for the same period with
   *  a larger limit and appends what is new (not offered when the answer ended at the size one
   *  answer may take: a larger limit gets the same). o: heading, headingId, intro (optional), empty()
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
        replace(warn, w ? notice('critical', h('strong', null, 'Integrity problem in the syslog_chunk records read. '), w, ' ', h('a', { href: '#/evidence' }, 'Run Verify')) : null);
        // A larger page of the same period starts with the messages shown already (a message's
        // chunk never changes; its record may have become known meanwhile).
        const keyOf = (m) => m.chunk + '|' + m.rx + '|' + (m.raw || m.raw_b64 || m.msg || '');
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
        // The server also ends a list at the size an answer may take: fewer messages than asked
        // for and more matched. A larger limit would not show more.
        const full = !!(data && data.truncated) && Array.isArray(data.messages) && data.messages.length < query.limit;
        replace(status, !msgs.length ? null
          : !data.truncated ? [n + ' received from ', period, ', newest first.']
            : full ? ['The newest ' + n + ' received from ', period, '; more were received, but these messages are long and one answer holds no more of them. Narrow the period or the filters to see older ones.']
              : query.limit < SYSLOG_MAX ? ['The newest ' + n + ' received from ', period, '; more were received in this period.']
                : ['The newest ' + n + ' received from ', period, '. Narrow the period or the filters to see older ones.'],
          prunedNote(cur.from));
        more.hidden = !data.truncated || full || query.limit >= SYSLOG_MAX;
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
            // A monitor without a syslog store (404) has no messages to show, which is no error.
            replace(list, e.status === 404 ? callout('info', sentence(capitalize(e.message))) : errorNotice(e));
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

  /** prunedNote says when a period starts before the oldest message the syslog store still
   *  keeps (Status.syslog.store.oldest): what was received before is not shown because it is not
   *  kept any more, not because nothing was received. */
  function prunedNote(from) {
    const u = syslogStore(app.status && app.status.syslog);
    const oldest = u ? toMs(u.oldest) : null;
    const start = toMs(from);
    if (oldest == null || start == null || oldest <= start) return null;
    return [' The store keeps no message received before ', timeEl(u.oldest, F.short),
      ': older ones, if there were any, were deleted by the retention limit.'];
  }

  /** syslogSeverity describes a severity number (SYSLOG_SEVERITIES), or null. */
  function syslogSeverity(n) {
    return Number.isInteger(n) && n >= 0 && n < SYSLOG_SEVERITIES.length ? SYSLOG_SEVERITIES[n] : null;
  }

  /** syslogRow is the table row of a message (GET /api/syslog): when, how severe, from which
   *  host and program, and what it says (as much as SYSLOG_ROW_TEXT and SYSLOG_ROW_NAME allow),
   *  with the exact datagram on request. Every cell holds one element (the stacked rows of a
   *  narrow screen lay out a cell's children as a grid). */
  function syslogRow(m) {
    const sv = syslogSeverity(m.severity);
    const text = m.msg || m.raw || '';
    return [
      h('span', { class: 'nowrap' }, timeEl(m.rx, F.sec), h('span', { class: 'sub small' }, chunkRecordLink(m, 'record #'))),
      h('span', null, sv ? chip(sv.tone, sv.label, 'Severity ' + m.severity + ' (' + sv.name + ')')
        : h('span', { class: 'muted', title: 'The message carries no severity' }, '—')),
      h('div', null, m.host ? h('span', { class: 'wrap-any' }, clippedText(m.host, SYSLOG_ROW_NAME)) : h('span', { class: 'muted' }, '—'),
        m.app ? h('span', { class: 'sub small muted wrap-any' }, clippedText(m.app, SYSLOG_ROW_NAME)) : null),
      h('div', null, text ? h('span', { class: 'syslog-text' }, clippedText(text, SYSLOG_ROW_TEXT))
        : h('span', { class: 'muted' }, m.raw_b64 ? 'not valid UTF-8: see the exact bytes' : '(empty)'),
      syslogDetails(m)),
    ];
  }

  // Why a message is not linked to a ledger record (yet).
  const CHUNK_UNRECORDED = 'Messages are recorded in the evidence ledger by chunk, when the chunk is sealed: a syslog_chunk record states its SHA-256. ' +
    'A chunk is sealed when it reaches its size limit, minutes after its first message, or when the service stops. ' +
    'This message’s chunk is still open, or its record was not found near it, or not yet: one request looks through a bounded part of the ledger, ' +
    'for the newest messages first, and the next request further back.';

  /** chunkRecordLink links the syslog_chunk record of a message's chunk (label + seq), or says
   *  that it is not known (yet). */
  function chunkRecordLink(m, label) {
    const seq = Number(m.seq) || 0;
    return seq > 0
      ? h('a', { href: recordsLink(seq), title: 'The syslog_chunk record of this message’s chunk, which states the chunk’s SHA-256' }, label + seq)
      : h('span', { class: 'muted', title: CHUNK_UNRECORDED }, 'no record yet');
  }

  /** syslogDetails offers a message's exact datagram, its parsed header and its chunk's ledger
   *  record. */
  function syslogDetails(m) {
    const det = h('details', { class: 'syslog-raw' }, h('summary', null, 'Exact datagram'));
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
      ['Stored in', m.chunk ? [h('code', { class: 'wrap-any' }, String(m.chunk)), h('span', { class: 'sub small' }, 'chunk of the syslog store; evidence: ',
        chunkRecordLink(m, 'ledger record #'))] : null],
    ]));
  }

  // ------------------------------------------------------------------ network view

  // Address kinds of the IP database (model.IPKind*) in words: what a remote address that is not
  // on the Internet is.
  const IP_KINDS = dict({
    public: 'Internet', private: 'Private network', shared: 'Carrier-grade NAT', loopback: 'Loopback',
    'link-local': 'Link-local', multicast: 'Multicast', reserved: 'Reserved range', invalid: 'Not an IP address',
  });

  // Country names: the browser's own (Intl.DisplayNames), else the world map's.
  const REGION_NAMES = (() => {
    try {
      return typeof Intl === 'object' && typeof Intl.DisplayNames === 'function' ? new Intl.DisplayNames(undefined, { type: 'region' }) : null;
    } catch (_) {
      return null;
    }
  })();
  const worldNames = new Map(); // ISO code -> the world map's name of the country

  // The device filter last chosen on the Connections tab, for its link on the Firewall tab.
  const netLast = { device: '' };

  // Colour slot (1-8) of each device while the page is open: the colour follows the device, never
  // its rank, so neither a filter nor a refresh repaints a device. From the ninth device on, the
  // devices are grey (slot 0) and told apart by their names: hues are never cycled.
  const deviceSlots = new Map();

  function deviceSlot(key) {
    const k = String(key == null ? '' : key);
    if (!deviceSlots.has(k)) deviceSlots.set(k, deviceSlots.size < 8 ? deviceSlots.size + 1 : 0);
    return deviceSlots.get(k);
  }

  function deviceDot(key) {
    return h('span', { class: 'dev-dot bg' + deviceSlot(key), 'aria-hidden': 'true' });
  }

  /** netList returns the objects of an answer's list (anything else in it, or no list, is left out). */
  function netList(v) {
    return Array.isArray(v) ? v.filter((x) => x && typeof x === 'object') : [];
  }

  /** countryName names an ISO 3166-1 alpha-2 code ("US" -> "United States"): the browser's name,
   *  else the world map's; "" is Unknown (an address the IP database does not place); anything
   *  that is not a code is shown as given. */
  function countryName(code) {
    const c = String(code == null ? '' : code);
    if (c === '') return 'Unknown';
    if (/^[A-Z]{2}$/.test(c)) {
      try {
        const n = REGION_NAMES ? REGION_NAMES.of(c) : '';
        if (n && n !== c) return n;
      } catch (_) { /* a code the browser does not know */ }
      if (worldNames.has(c)) return worldNames.get(c);
    }
    return netText(c, 40);
  }

  /** netText returns untrusted text (a device name from the gateway, an organisation from the IP
   *  database, a reverse DNS name) for a label, an option or a tooltip: at most max characters
   *  as shown, its hidden characters written as escapes (escapedText), "…" when cut. */
  function netText(text, max) {
    const c = clipText(text, max || 60, 8);
    return escapedText(c.text) + (c.more ? '…' : '');
  }

  /** netShown is netText for a table cell: the hidden characters set apart (visibleText). */
  function netShown(text, max) {
    const c = clipText(text, max || 80, 8);
    return [visibleText(c.text), c.more ? h('span', { class: 'muted', title: fmtInt(c.more) + ' more characters' }, '…') : null];
  }

  /** netShare writes v as a share of total ("36 %", "< 1 %"). */
  function netShare(v, total) {
    if (!(total > 0) || !(v >= 0)) return '—';
    const p = (100 * v) / total;
    return p > 0 && p < 1 ? '< 1 %' : Math.round(p) + ' %';
  }

  /** portText writes a port with its protocol ("443/tcp"); "" without a port. */
  function portText(port, proto) {
    return Number(port) > 0 ? port + (proto ? '/' + proto : '') : '';
  }

  /** unnamedPort reports whether a service's name is only its protocol and port, as the server
   *  names a port its port table does not know ("tcp 8071", "port 8071"): portText ("8071/tcp")
   *  says that alone, rather than beside it. */
  function unnamedPort(x) {
    return Number(x.port) > 0 && String(x.name == null ? '' : x.name) === (x.proto ? String(x.proto) : 'port') + ' ' + Number(x.port);
  }

  /** goDurMs reads a Go duration ("4m0s", "1h30m") as milliseconds; null when it is not one. */
  function goDurMs(v) {
    const t = String(v == null ? '' : v).trim();
    if (!/^(\d+(\.\d+)?(h|m|s|ms|us|µs|ns))+$/.test(t)) return null;
    const unit = { h: 3600e3, m: 60e3, s: 1e3, ms: 1, us: 1e-3, 'µs': 1e-3, ns: 1e-6 };
    let ms = 0;
    for (const m of t.matchAll(/(\d+(?:\.\d+)?)(h|ms|m|s|us|µs|ns)/g)) ms += Number(m[1]) * unit[m[2]];
    return ms;
  }

  /** agoEl says how long ago v was ("2 min ago"), with the time in UTC on hover. */
  function agoEl(v, now) {
    const d = toDate(v);
    if (!d) return h('span', { class: 'muted' }, '?');
    return h('time', { datetime: d.toISOString(), title: F.full.format(d) + ' · UTC: ' + utcText(v, d) }, sinceText(v, now) + ' ago');
  }

  /** netTimeEl shows a time of today as its time of day, any other with its date; UTC on hover. */
  function netTimeEl(v) {
    const d = toDate(v);
    return timeEl(v, d && localDateValue(d) === localDateValue(new Date()) ? F.hm : F.short);
  }

  function netTile(label, value, sub, title) {
    return h('div', { class: 'tile', title: title || null },
      h('p', { class: 'tile-label' }, label), h('p', { class: 'tile-value' }, value), sub ? h('p', { class: 'tile-sub' }, sub) : null);
  }

  /** netAbout is a page's explanation: what the figures are, where they come from. */
  function netAbout(title, ...text) {
    return h('div', { class: 'banner tone-info net-about' }, icon('info'),
      h('div', { class: 'banner-body' }, h('p', { class: 'banner-title' }, title), h('p', null, ...text)));
  }

  /** keepFocus runs render, which rebuilds parts of root, and gives the keyboard focus back to the
   *  element that had it - or to the one that took its place: the element of the new content with
   *  the same data-fk. A refresh every minute must not send a keyboard user back to the start of
   *  the page; nor may the focus scroll the page to it (the reader's scroll position is theirs). */
  function keepFocus(root, render) {
    const a = document.activeElement;
    const key = a && a !== document.body && root.contains(a) && a.getAttribute ? a.getAttribute('data-fk') : null;
    render();
    if (key && !root.contains(a)) {
      const b = Array.from(root.querySelectorAll('[data-fk]')).find((e) => e.getAttribute('data-fk') === key);
      if (b) b.focus({ preventScroll: true });
    }
  }

  // ------------------------------------------------------------------ network view: period & URL

  /** netPeriod reads the Network page's period from its URL (range=, or from= and to=), else the
   *  one chosen last (24 hours at first): {range} for a period ending now, {range: 'custom', from,
   *  to} (ms) for another. */
  function netPeriod(q) {
    const r = q.get('range');
    if (NET_RANGE_MS[r]) return { range: r };
    const from = toMs(q.get('from'));
    const to = toMs(q.get('to'));
    if (from != null && to != null && from < to && to - from <= NET_MAX_SPAN_MS) return { range: 'custom', from, to };
    const saved = loadPref('netRange', '24h');
    return { range: NET_RANGE_MS[saved] ? saved : '24h' };
  }

  /** netDeviceParam reads the device filter from the URL: a device key as the server accepts one
   *  (printable ASCII without spaces, at most NET_DEVICE_MAX characters), else none. */
  function netDeviceParam(q) {
    const d = q.get('device') || '';
    return d.length <= NET_DEVICE_MAX && /^[\x21-\x7e]+$/.test(d) ? d : '';
  }

  function netPeriodWords(p) {
    switch (p.range) {
      case '1h': return 'Last hour';
      case '24h': return 'Last 24 hours';
      case '7d': return 'Last 7 days';
      case '30d': return 'Last 30 days';
      default: return F.short.format(new Date(p.from)) + ' – ' + F.short.format(new Date(p.to));
    }
  }

  /** netPeriodParams writes a period as the network endpoints read it (range=, or from= and to=). */
  function netPeriodParams(p) {
    const out = new URLSearchParams();
    if (p.range === 'custom') {
      out.set('from', new Date(p.from).toISOString());
      out.set('to', new Date(p.to).toISOString());
    } else {
      out.set('range', p.range);
    }
    return out;
  }

  /** netHash is the URL of a tab of the Network page with a period and, on Connections, a device. */
  function netHash(tab, p, device) {
    const params = netPeriodParams(p);
    if (tab === 'connections' && device) params.set('device', device);
    return '#/network' + (tab === 'firewall' ? '/firewall' : '') + '?' + params.toString();
  }

  // ------------------------------------------------------------------ network view: the page

  /** renderNetwork shows the Network page (docs/syslog-map-graphic.md §2.3): which device on the
   *  home network talks to which remote address, organisation, country and service, from samples
   *  of the gateway's NAT table (tab "connections"), and what the gateway's firewall drops, from
   *  its syslog (tab "firewall"). One period for both tabs (1 h to 30 days ending now, or a
   *  custom one) and, on Connections, a device filter; both are kept in the URL. The data are read
   *  again every minute while the page is visible; the controls, the search box and the keyboard
   *  focus stay where they are. None of it is evidence. */
  function renderNetwork(c, q, ctx, tab) {
    let token = 0; // the newest load: an older answer is dropped
    let abort = null; // cancels the requests out: a newer load replaces them
    let period = netPeriod(q);
    let device = tab === 'connections' ? netDeviceParam(q) : '';
    if (tab === 'connections') netLast.device = device;
    const ipdbLine = h('p', { class: 'small muted' });
    c.append(h('div', { class: 'view-head' },
      h('div', { class: 'net-head-text' }, h('h1', null, 'Network'), h('p', { class: 'muted' }, 'Which device talks to which site, and what the gateway’s firewall blocks.')),
      ipdbLine));
    const tabConn = h('a', { href: netHash('connections', period, netLast.device), 'aria-current': tab === 'connections' ? 'page' : null }, 'Connections');
    const tabFw = h('a', { href: netHash('firewall', period, ''), 'aria-current': tab === 'firewall' ? 'page' : null }, 'Firewall');
    c.append(h('nav', { class: 'tabs', 'aria-label': 'Network views' }, tabConn, tabFw));

    const seg = rangeControl(period.range, setRange, 'Period', NET_RANGES.concat([['custom', 'Custom…']])).querySelector('.seg');
    const devSel = h('select', { name: 'device', 'data-fk': 'net-device' }, h('option', { value: '' }, 'All devices'));
    devSel.value = '';
    const readLine = h('p', { class: 'small muted net-read' });
    const fromIn = h('input', { type: 'datetime-local', required: true });
    const toIn = h('input', { type: 'datetime-local', required: true });
    const customOut = h('div', { 'aria-live': 'polite' });
    // Cancel closes the form of a custom period not applied yet (with a custom period in use, the
    // form shows it, and there is nothing to cancel).
    const cancel = h('button', { type: 'button', class: 'btn', hidden: period.range === 'custom' }, 'Cancel');
    const custom = h('form', { class: 'net-custom', 'aria-label': 'Custom period', hidden: period.range !== 'custom' },
      h('div', { class: 'form-grid' }, field('From (local time)', fromIn), field('To (local time)', toIn)),
      h('div', { class: 'btn-row' }, h('button', { type: 'submit', class: 'btn btn-primary' }, 'Apply'), cancel), customOut);
    c.append(h('div', { class: 'net-toolbar' }, seg,
      tab === 'connections' ? h('label', { class: 'net-device' }, 'Device', devSel) : null, readLine), custom);
    const notes = h('div', { class: 'conditions' });
    const content = h('div', { class: 'net-content' }, h('p', { class: 'loading' }, 'Loading…'));
    c.append(notes, content);

    const parts = tab === 'connections'
      ? { flow: netFlow(ctx, setDevice), map: netMap(ctx, NET_CONN_MAP), table: netConnTable(ctx) }
      : { timeline: fwTimeline(ctx), map: netMap(ctx, NET_FW_MAP) };
    let lastNs = null; // the network status shown
    let shown = false; // data shown at least once
    let devKey = null; // the devices listed in the select

    function fillCustom() {
      const to = period.range === 'custom' ? period.to : Date.now();
      const from = period.range === 'custom' ? period.from : to - NET_RANGE_MS[period.range];
      fromIn.value = datetimeLocalValue(new Date(from));
      toIn.value = datetimeLocalValue(new Date(to));
    }
    fillCustom();

    /** setRange applies a period chosen in the period control. "Custom…" only opens the form
     *  (filled with the period shown, unless it is open already): the period changes with Apply,
     *  so until then the period in use stays checked, as the data, the URL and the refresh are. */
    function setRange(r) {
      if (r === 'custom') {
        if (custom.hidden) {
          fillCustom();
          replace(customOut);
          custom.hidden = false;
        }
        markRange();
        return;
      }
      if (!NET_RANGE_MS[r]) return;
      custom.hidden = true;
      period = { range: r };
      savePref('netRange', r);
      markRange();
      load();
    }

    /** markRange checks the period in use in the period control ("Custom…" once a custom period
     *  is applied) and offers Cancel while a custom period waits for Apply. */
    function markRange() {
      for (const input of seg.querySelectorAll('input')) input.checked = input.getAttribute('value') === period.range;
      cancel.hidden = period.range === 'custom';
    }

    /** closeCustom closes the form of a custom period not applied: the period stays as it is.
     *  From Cancel (hidden with the form), the keyboard focus goes back to the period control. */
    function closeCustom(refocus) {
      if (period.range === 'custom' || custom.hidden) return;
      custom.hidden = true;
      replace(customOut);
      const on = Array.from(seg.querySelectorAll('input')).find((input) => input.checked);
      if (refocus && on) on.focus();
    }
    cancel.addEventListener('click', () => closeCustom(true));
    // The period in use stays checked while the form is open, so choosing it again changes
    // nothing (no change event): its click closes the form.
    seg.addEventListener('click', (e) => {
      const t = e.target;
      if (t && t.localName === 'input' && t.getAttribute('value') === period.range) closeCustom(false);
    });

    custom.addEventListener('submit', (e) => {
      e.preventDefault();
      const f = toMs(fromIn.value);
      const t = toMs(toIn.value);
      let why = '';
      if (f == null || t == null) why = 'Choose when the period starts and when it ends.';
      else if (f >= t) why = 'The start must be before the end.';
      else if (t - f > NET_MAX_SPAN_MS) why = 'The period may be at most 31 days long.';
      else if (t > Date.now() + 3600e3) why = 'The period may end at most an hour from now.';
      if (why) {
        replace(customOut, notice('critical', why));
        return;
      }
      replace(customOut);
      period = { range: 'custom', from: f, to: t };
      markRange();
      load();
    });

    /** setDevice applies a device filter ('' = every device). From the diagram's "Show every
     *  device" (src 'all'), which goes with the filter, the keyboard focus moves to the filter. */
    function setDevice(key, src) {
      device = String(key || '');
      netLast.device = device;
      devSel.value = device;
      if (src === 'all') devSel.focus();
      load();
    }
    devSel.addEventListener('change', () => setDevice(devSel.value));

    /** syncUrl keeps the period and the device in the URL, without routing again, and in the tabs' links. */
    function syncUrl() {
      const hash = netHash(tab, period, device);
      if (window.location.hash !== hash) window.history.replaceState(null, '', hash);
      setAttr(tabConn, 'href', netHash('connections', period, netLast.device));
      setAttr(tabFw, 'href', netHash('firewall', period, ''));
    }

    ctx.cleanup(() => { if (abort) abort.abort(); });

    async function load() {
      const mine = ++token;
      if (abort) abort.abort();
      abort = typeof AbortController === 'function' ? new AbortController() : null;
      const signal = abort ? abort.signal : null;
      syncUrl();
      content.classList.add('is-loading');
      content.setAttribute('aria-busy', 'true');
      const params = netPeriodParams(period);
      if (device) params.set('device', device);
      params.set('limit', String(NET_LIMIT));
      const statusReq = api('/api/network/status', { signal }).then((ns) => ({ ns }), (err) => ({ err }));
      try {
        const data = await api('/api/network/' + tab + '?' + params.toString(), { signal });
        const st = await statusReq;
        if (!ctx.alive || mine !== token) return;
        show(st.ns && typeof st.ns === 'object' ? st.ns : null, data && typeof data === 'object' ? data : {});
      } catch (e) {
        if (!ctx.alive || mine !== token) return;
        // Without a syslog store the firewall view is unavailable (503): the status says so, and
        // the tab explains it (fwNotes, fwAbout) rather than show the error alone.
        if (tab === 'firewall' && e.status === 503) {
          const st = await statusReq;
          if (ctx.alive && mine === token && st.ns && typeof st.ns === 'object' && !st.ns.syslog) {
            show(st.ns, {});
            return;
          }
        }
        if (ctx.alive && mine === token) failed(e);
      } finally {
        if (mine === token) {
          content.classList.remove('is-loading');
          content.removeAttribute('aria-busy');
        }
      }
    }

    function failed(e) {
      if (e.status === 404) {
        // A monitor without the Network page: nothing to show, which is no error.
        replace(notes);
        replace(content, callout('info', sentence(capitalize(e.message))));
        return;
      }
      replace(notes, errorNotice(e));
      if (!shown) replace(content);
    }

    function show(ns, d) {
      lastNs = ns;
      shown = true;
      keepFocus(c, () => {
        const updated = d.ipdb || (ns && ns.ipintel && ns.ipintel.loaded ? ns.ipintel.updated : '');
        replace(ipdbLine, updated ? ['Address data: IPtoASN, ', timeEl(updated, F.date)] : 'No IP address database loaded yet');
        readNote();
        if (tab === 'connections') showConnections(ns, d);
        else showFirewall(ns, d);
      });
    }

    /** readNote says when the data were last read: the NAT table, or the gateway's syslog. The
     *  monitor's status (every 10 s) is fresher than the network status (every minute). */
    function readNote() {
      const now = app.status && app.status.now;
      if (tab === 'connections') {
        const smp = (app.status && app.status.connections) || (lastNs && lastNs.samplers);
        if (!smp || typeof smp !== 'object') {
          replace(readLine);
          return;
        }
        const every = goDurMs(smp.interval);
        replace(readLine, smp.nat_at ? ['NAT table last read ', agoEl(smp.nat_at, now)] : 'NAT table not read yet',
          smp.enabled && every ? ' · every ' + fmtDur(every / 1000) : '');
        return;
      }
      const sl = syslogStatus(app.status);
      const last = (sl && sl.last_at) || (lastNs && lastNs.syslog && lastNs.syslog.newest);
      replace(readLine, 'From the gateway’s syslog', last ? [' · last message ', agoEl(last, now)] : '');
    }
    ctx.onStatus = readNote;

    // ---------------------------------------------------------------- Connections

    function showConnections(ns, d) {
      const devices = netList(d.devices);
      for (const dv of devices) deviceSlot(dv.key);
      fillDevices(devices);
      replace(notes, ...connNotes(ns));
      const endsNow = period.range !== 'custom';
      if (!(Number(d.samples) > 0)) {
        placeChildren(content, h('section', { class: 'card' }, emptyNote(connEmptyText(ns))), connAbout(ns));
        return;
      }
      parts.flow.update(d, { device, words: netPeriodWords(period) });
      parts.map.update(d.countries);
      parts.table.update(d, endsNow);
      placeChildren(content, connTiles(ns, d, endsNow), connLeftOut(d), parts.flow.el, parts.map.el, parts.table.el, connAbout(ns));
    }

    /** fillDevices lists the period's devices in the device filter, keeping the choice (a device
     *  not seen in the period stays listed as such). The select is rebuilt only when the list
     *  changed, so that a refresh does not close it under the pointer. */
    function fillDevices(devices) {
      const key = JSON.stringify([devices.map((dv) => [dv.key, dv.name, dv.ipv4]), device]);
      if (key === devKey) return;
      devKey = key;
      const opts = [h('option', { value: '' }, 'All devices')];
      let found = device === '';
      for (const dv of devices) {
        const k = String(dv.key == null ? '' : dv.key);
        if (!k) continue;
        found = found || k === device;
        const name = netText(dv.name || dv.ipv4 || k, 40);
        opts.push(h('option', { value: k }, dv.ipv4 && dv.ipv4 !== dv.name ? name + ' (' + netText(dv.ipv4, 40) + ')' : name));
      }
      if (!found) opts.push(h('option', { value: device }, device + ' (not seen in this period)'));
      replace(devSel, ...opts);
      devSel.value = device;
    }

    /** cfgWarnNotes says which of the Network page's settings in config.json the service could not
     *  use as written, and what it uses instead (NetworkStatus.config_warnings): a mistyped value
     *  then shows here, not only in the service log. */
    function cfgWarnNotes(ns) {
      const ws = ns && Array.isArray(ns.config_warnings) ? ns.config_warnings.filter((w) => typeof w === 'string' && w) : [];
      if (!ws.length) return [];
      return [callout('warning', h('strong', null, 'Some Network page settings in config.json are not used as written. '),
        ws.length === 1 ? sentence(capitalize(ws[0])) : h('ul', null, ...ws.map((w) => h('li', null, sentence(capitalize(w))))))];
    }

    function connNotes(ns) {
      const out = [];
      if (!ns) return out;
      out.push(...cfgWarnNotes(ns));
      const smp = ns.samplers && typeof ns.samplers === 'object' ? ns.samplers : null;
      if (!smp) {
        out.push(callout('info', 'This att-monitor reports nothing about its reads of the NAT table: the connections shown are those stored.'));
      } else if (!smp.enabled) {
        out.push(callout('info', h('strong', null, 'Connections are not being recorded. '),
          'Reading the gateway’s NAT table is turned off in the configuration (connections.enabled); what is shown was recorded before.'));
      } else if (smp.nat_problem) {
        out.push(callout('warning', h('strong', null, 'The NAT table is not being read. '), sentence(capitalize(String(smp.nat_problem))),
          smp.nat_at ? [' The newest read is from ', timeEl(smp.nat_at, F.short), '.'] : ''));
      } else if (smp.nat_note) {
        // The newest read worked - the line above says when - but did not keep all it showed: rows
        // not understood (a firmware the parser does not know yet), or the read itself when the
        // connection store refused it (its error makes it a warning).
        const refused = ns.store && typeof ns.store === 'object' && ns.store.error;
        out.push(callout(refused ? 'warning' : 'info', h('strong', null, 'The NAT table is read, but not all of it is kept. '),
          sentence(capitalize(String(smp.nat_note)))));
      }
      if (smp && smp.enabled && smp.devices_problem) {
        out.push(callout('info', h('strong', null, 'The Device List could not be read. '), sentence(capitalize(String(smp.devices_problem))),
          ' Devices it did not name are shown by their addresses.'));
      }
      const ip = ns.ipintel && typeof ns.ipintel === 'object' ? ns.ipintel : null;
      if (ip && !ip.enabled) {
        out.push(callout('info', 'Organisations and countries are not shown: the IP address database is turned off in the configuration (geo.enabled).'));
      } else if (ip && !ip.loaded) {
        out.push(callout('info', h('strong', null, 'The IP address database is not loaded yet, so organisations and countries are not shown. '),
          ip.download
            ? 'att-monitor downloads the public IPtoASN tables to this PC (only the files are fetched: no address is sent anywhere); they appear once loaded.'
            : 'Place the IPtoASN tables (ip2asn-v4.tsv.gz and ip2asn-v6.tsv.gz) in the geo folder of the data directory, or allow the download (geo.download).',
          ip.error ? [' Last attempt: ', sentence(String(ip.error))] : ''));
      }
      return out;
    }

    function connEmptyText(ns) {
      const smp = ns && ns.samplers;
      if (period.range === 'custom') return 'No read of the NAT table in this period.';
      if (smp && smp.enabled && !smp.nat_at) {
        // A first read is announced only when nothing stands in its way (the problem is said above).
        const next = smp.nat_problem ? null : toDate(smp.nat_next);
        return 'The NAT table has not been read yet' + (next ? ': the first read is due at ' + F.time.format(next) + '.' : '.');
      }
      return 'No read of the NAT table in this period.';
    }

    function connTiles(ns, d, endsNow) {
      const t = d.totals && typeof d.totals === 'object' ? d.totals : {};
      const smp = ns && ns.samplers;
      // "Now" only while the newest read in the period is recent (reads paused hours ago are not now).
      const every = smp ? goDurMs(smp.interval) : null;
      const age = ageSeconds(d.last, app.status && app.status.now);
      const fresh = endsNow && age != null && age * 1000 <= Math.max(10 * 60e3, 2.5 * (every || 4 * 60e3));
      const listed = smp && Number(smp.devices) > 0 && !device ? Number(smp.devices) : 0;
      // The gateway's own connections count as a device, but the Device List does not list it. The
      // devices of the period that the newest Device List lists (totals.listed) are at most all of
      // it; the others have left the network since.
      const gw = !device && netList(d.devices).some((dv) => dv.key === 'gateway');
      const inList = Math.min(listed, Math.max(0, Math.floor(Number(t.listed)) || 0));
      const nc = Number(t.countries) || 0;
      // Under a device filter the open connections are that device's (open_device): the NAT
      // table's own count, every device's, goes to the tooltip.
      const open = device ? Number(d.open_device) || 0 : d.open;
      const what = device ? 'connections of this device in the NAT table' : 'connections in the NAT table';
      const table = Number(d.in_use) >= 0 && Number(d.available) >= 0
        ? 'The gateway’s NAT table: ' + fmtInt(d.in_use) + ' sessions in use, ' + fmtInt(d.available) + ' available'
          + (device ? '; every device’s connections at that read: ' + fmtInt(d.open) : '') : null;
      return h('section', { 'aria-label': 'Summary' }, h('div', { class: 'tiles net-tiles' },
        netTile('Devices active', fmtInt(t.devices), device ? 'the device chosen'
          : listed ? fmtInt(inList) + ' of the ' + fmtInt(listed) + ' in the gateway’s Device List' + (gw ? ', and the gateway' : '')
            : 'in this period'),
        netTile('Sites', fmtInt(t.sites), 'remote addresses'),
        netTile('Organisations', fmtInt(t.orgs), 'in ' + fmtInt(nc) + ' countr' + (nc === 1 ? 'y' : 'ies')),
        netTile(fresh ? 'Open now' : 'Open at the last read', fmtInt(open),
          fresh || !toDate(d.last) ? what : [what + ' at ', timeEl(d.last, F.short)], table)));
    }

    /** connLeftOut says when the period holds more distinct connections than the store counts one
     *  by one: the lightest count only in their devices and as "Other". */
    function connLeftOut(d) {
      const n = Math.floor(Number(d.flows_left_out)) || 0;
      if (n <= 0) return null;
      return callout('info', h('strong', null, 'A very busy period. '),
        fmtInt(n) + ' connection' + (n === 1 ? ' was' : 's were') + ' too light to count one by one among so many (a device may be file sharing or scanning the Internet): they count in their devices and as “Other”, and the sites and organisations are at least the numbers shown. A shorter period, or one device, shows more of them.');
    }

    function connAbout(ns) {
      const smp = ns && ns.samplers;
      const every = smp ? goDurMs(smp.interval) : null;
      const keep = ns && ns.store && Number(ns.store.keep_days) > 0 ? Number(ns.store.keep_days) : null;
      const ptr = ns && ns.ipintel && ns.ipintel.reverse_dns;
      return netAbout('How this is measured',
        'The monitor reads the gateway’s NAT table ', every ? 'every ' + fmtDur(every / 1000) : 'regularly',
        ': every connection it translates, with the device and the remote address and port. A connection that opens and closes between two reads is not seen. IPv6 connections are listed too; each is named after the device whose address it uses. ',
        'Organisations and countries come from the IPtoASN database kept on this PC: no address is sent anywhere to name them.',
        ptr ? ' The names under some addresses are their reverse DNS names, looked up through this PC’s DNS resolver.' : '',
        ' This is not evidence: it is never written to the evidence ledger, and it is kept ', keep ? 'for ' + fmtInt(keep) + ' days' : 'for a limited time', '.');
    }

    // ---------------------------------------------------------------- Firewall

    function showFirewall(ns, d) {
      replace(notes, ...fwNotes(ns));
      if (ns && !ns.syslog) {
        placeChildren(content, fwAbout(ns));
        return;
      }
      const cover = fwCoverage(d);
      if (!(Number(d.drops) > 0)) {
        placeChildren(content, cover, h('section', { class: 'card' }, emptyNote('The gateway’s firewall dropped nothing in this period.')), fwAbout(ns));
        return;
      }
      parts.timeline.update(d);
      parts.map.update(d.countries);
      placeChildren(content, fwTiles(d), cover, parts.timeline.el, parts.map.el,
        h('div', { class: 'grid-2' }, fwServices(d), fwSources(d)), fwOutbound(d), fwAbout(ns));
    }

    function fwNotes(ns) {
      const out = cfgWarnNotes(ns);
      if (ns && !ns.syslog) {
        out.push(callout('info', 'This att-monitor keeps no syslog store, so there are no firewall messages to show.'));
        return out;
      }
      const sl = syslogStatus(app.status);
      if (sl && !sl.enabled) {
        out.push(callout('info', h('strong', null, 'The syslog receiver is off. '),
          'It is turned off in the configuration (syslog.enabled): no new firewall messages arrive; what is shown was received before.'));
      } else if (sl && (sl.state === 'off' || sl.state === 'elsewhere')) {
        out.push(callout('warning', h('strong', null, 'The gateway does not send its log to this PC. '),
          'Blocked packets are not seen until it does. ', h('a', { href: '#/syslog' }, 'Open the Syslog page')));
      }
      return out;
    }

    /** fwCoverage says when the syslog kept starts after the period does: the period's start shows
     *  nothing because no message of it is kept (none was received yet, or the retention limit
     *  deleted them), not because nothing was dropped. */
    function fwCoverage(d) {
      const oldest = toMs(d.oldest);
      const from = toMs(d.from);
      if (oldest == null || from == null || oldest <= from) return null;
      return callout('info', 'The syslog kept starts at ', timeEl(d.oldest, F.short),
        ': anything the gateway logged before was not received here or is no longer kept (the syslog’s retention limit deletes the oldest messages), so the first ',
        fmtDur((oldest - from) / 1000), ' of this period show nothing.');
    }

    function fwTiles(d) {
      const svc = netList(d.services).find((x) => Number(x.port) > 0);
      // Counted by the server over every outbound drop of the period, also beyond the rows listed.
      const devs = Math.max(0, Math.floor(Number(d.outbound_devices)) || 0);
      const countries = netList(d.countries).filter((x) => x.code).length;
      return h('section', { 'aria-label': 'Summary' }, h('div', { class: 'tiles net-tiles' },
        netTile('Inbound blocked', fmtInt(d.inbound), 'probes from the Internet'),
        netTile('Sources', fmtInt(d.sources), 'addresses in ' + fmtInt(countries) + ' countr' + (countries === 1 ? 'y' : 'ies')),
        netTile('Outbound blocked', fmtInt(d.outbound), devs ? 'packets from ' + fmtInt(devs) + ' device' + (devs === 1 ? '' : 's') : 'packets from the home network'),
        netTile('Most probed', svc ? (unnamedPort(svc) ? portText(svc.port, svc.proto) : netText(svc.name || portText(svc.port, svc.proto), 24)) : '—',
          svc ? (unnamedPort(svc) ? '' : portText(svc.port, svc.proto) + ' · ') + netShare(Number(svc.count), Number(d.inbound)) + ' of the probes'
            : 'no inbound probe')));
    }

    /** fwServices lists what the inbound probes tried to reach, as the server names it
     *  (model.FwService): a port with its protocol ("SSH", 22/tcp), a protocol without ports
     *  ("ICMP", "ICMPv6": port 0, with a protocol), and the rest grouped ("Other": no port, no
     *  protocol) - only that one is "Other ports". */
    function fwServices(d) {
      const list = netList(d.services);
      const fr = netFigure({ id: 'net-fw-services', title: 'Most probed services', sub: 'What the blocked inbound packets were trying to reach.' });
      const total = Number(d.inbound) || list.reduce((a, x) => a + (Number(x.count) || 0), 0);
      const items = list.map((x) => {
        const port = Number(x.port) > 0;
        const rest = !port && !x.proto && (x.name == null || x.name === '' || x.name === 'Other');
        // A port without a name is named by its port alone ("8071/tcp", not "tcp 8071 8071/tcp").
        const bare = unnamedPort(x);
        return {
          name: rest ? 'Other ports' : bare ? portText(x.port, x.proto) : netText(x.name || (port ? 'Port ' + x.port : x.proto || 'Unknown'), 40),
          note: bare ? '' : portText(x.port, x.proto), value: Number(x.count) || 0,
        };
      });
      add(fr.body, [items.length ? netBars(items, total, 'Most probed services') : emptyNote('No inbound probe in this period.')]);
      fr.setTable(() => netTableView('Most probed services', table(
        [{ label: 'Service' }, { label: 'Port' }, { label: 'Probes', num: true }, { label: 'Share', num: true }],
        items.map((x) => [x.name, x.note || '—', fmtInt(x.value), netShare(x.value, total)]), { compact: true }).firstChild));
      return fr.fig;
    }

    function fwSources(d) {
      const list = netList(d.top_sources);
      const top = list.slice(0, 6); // as many as the services beside them; the table view has all
      const fr = netFigure({ id: 'net-fw-sources', title: 'Top sources', sub: 'Addresses whose packets were blocked most often.' });
      const where = (x) => [x.org ? netText(x.org, 48) : x.asn ? 'AS' + x.asn : '', countryName(x.country)].filter(Boolean).join(' · ');
      const total = Math.max(Number(d.sources) || 0, list.length);
      add(fr.body, [top.length
        ? h('ol', { class: 'src-list', 'aria-label': 'Top sources' }, top.map((x) => h('li', null,
          h('span', { class: 'src-who' }, h('span', { class: 'mono src-addr' }, netShown(x.addr, 64)), h('span', { class: 'sub small muted wrap-any' }, where(x))),
          h('span', { class: 'src-n' }, fmtInt(x.count), h('span', { class: 'sub small muted' }, fmtInt(x.ports) + ' port' + (Number(x.ports) === 1 ? '' : 's'))))))
        : emptyNote('No source in this period.'),
      total > top.length ? h('p', { class: 'card-foot' }, 'The ', fmtInt(top.length), ' most active of ', fmtInt(total), ' source addresses',
        list.length > top.length ? '; the table view lists ' + fmtInt(list.length) + '.' : '.') : null]);
      fr.setTable(() => netTableView('Top sources', table(
        [{ label: 'Address' }, { label: 'Organisation' }, { label: 'Country' }, { label: 'Packets', num: true }, { label: 'Ports', num: true }, { label: 'Last' }],
        list.map((x) => [h('span', { class: 'mono' }, netShown(x.addr, 64)), [netShown(x.org || '—', 60), x.asn ? h('span', { class: 'sub small muted' }, 'AS' + x.asn) : null],
          countryName(x.country), fmtInt(x.count), fmtInt(x.ports), netTimeEl(x.last)]), { compact: true }).firstChild));
      return fr.fig;
    }

    function fwOutbound(d) {
      const rows = netList(d.outbound_rows);
      const total = Number(d.outbound_total) || rows.length;
      const body = rows.length
        ? h('div', { class: 'table-scroll' }, h('table', { class: 'tbl net-out' },
          h('thead', null, h('tr', null, ['Device', 'Destination', 'Organisation', 'Service', 'Reason'].map((l) => h('th', { scope: 'col' }, l)),
            h('th', { scope: 'col', class: 'num' }, 'Packets'), h('th', { scope: 'col', class: 'num' }, 'Last'))),
          h('tbody', null, rows.map((r) => h('tr', null,
            h('td', null, h('span', { class: 'dev' }, deviceDot(r.device), h('span', null, netShown(r.name || r.lan || r.device, 48))),
              r.lan && r.lan !== r.name ? h('span', { class: 'sub small muted' }, netShown(r.lan, 48)) : null),
            h('td', null, h('span', { class: 'mono' }, netShown(r.remote, 64))),
            h('td', null, netShown(r.org || (r.remote ? 'Unknown' : '—'), 60), r.asn ? h('span', { class: 'sub small muted' }, 'AS' + r.asn) : null),
            h('td', null, netShown(r.service || '—', 40), portText(r.port, r.proto) ? h('span', { class: 'sub small muted' }, portText(r.port, r.proto)) : null),
            h('td', null, h('span', { class: 'chip net-reason', title: r.reason ? 'The gateway’s reason: ' + escapedText(r.reason) : null }, netText(r.label || r.reason || '?', 72))),
            h('td', { class: 'num' }, fmtInt(r.count)),
            h('td', { class: 'num' }, netTimeEl(r.last)))))))
        : emptyNote('No packet from a device on the home network was blocked in this period.');
      return h('section', { class: 'card', 'aria-labelledby': 'net-out-h' },
        h('div', { class: 'card-head' }, h('div', null, h('h2', { id: 'net-out-h' }, 'Blocked on the way out'),
          h('p', { class: 'chart-sub' }, 'Packets a device on the home network sent that the gateway’s firewall did not forward.'))),
        body,
        total > rows.length ? h('p', { class: 'card-foot' }, 'The ', fmtInt(rows.length), ' destinations with the most packets of ', fmtInt(total), '.') : null);
    }

    function fwAbout(ns) {
      const keep = ns && ns.syslog && Number(ns.syslog.keep_mb) > 0 ? Number(ns.syslog.keep_mb) : null;
      return netAbout('What the syslog can show',
        'At its most detailed level the gateway logs only the packets its firewall drops, never the connections it allows; those are on the ',
        h('a', { href: netHash('connections', period, netLast.device) }, 'Connections tab'),
        '. Firewall lines are kept with the rest of the gateway’s syslog, within its size limit', keep ? ' (' + fmtInt(keep) + ' MiB)' : '', '. This is not evidence of an outage.');
    }

    load();
    ctx.interval(() => { if (!document.hidden) load(); }, NET_REFRESH_MS);
  }

  // The two world maps: the Connections tab's (remote addresses by country) and the Firewall
  // tab's (blocked inbound packets by source country).
  const NET_CONN_MAP = {
    id: 'net-map-conn', title: 'Where the sites are', legend: 'Sites per country',
    sub: 'Country each remote address is registered in. A CDN’s server is often nearer than its country.',
    value: (x) => Number(x.sites) || 0, valueLabel: 'Sites', unit: (n) => fmtInt(n) + ' site' + (n === 1 ? '' : 's'),
    extra: (x) => Number(x.weight) || 0, extraLabel: 'Times seen', extraUnit: (n) => 'seen ' + fmtInt(n) + ' time' + (n === 1 ? '' : 's'),
  };
  const NET_FW_MAP = {
    id: 'net-map-fw', title: 'Where the probes came from', legend: 'Probes per country',
    sub: 'Country each blocked source address is registered in.',
    value: (x) => Number(x.weight) || 0, valueLabel: 'Probes', unit: (n) => fmtInt(n) + ' probe' + (n === 1 ? '' : 's'),
    extra: (x) => Number(x.sites) || 0, extraLabel: 'Source addresses', extraUnit: (n) => fmtInt(n) + ' source address' + (n === 1 ? '' : 'es'),
  };

  // ------------------------------------------------------------------ network view: figures

  /** netFigure builds a card of the Network page with a Table toggle, as chartFrame does for the
   *  charts: o {id (remembered in app.tableViews), title, sub}. Returns {fig, body, sub,
   *  tableBtn, setTable(fn)}: body holds the graphic; fn() builds the table view of the data
   *  shown, when the table is shown and again with every update while it is. */
  function netFigure(o) {
    const sub = h('p', { class: 'chart-sub' }, o.sub || null);
    const tableBtn = h('button', { type: 'button', class: 'btn btn-small', 'aria-pressed': 'false', title: 'Show the data as a table', 'data-fk': o.id + ':table' }, 'Table');
    const body = h('div', { class: 'net-graphic' });
    const tableWrap = h('div', { hidden: true });
    const fig = h('figure', { class: 'chart' },
      h('figcaption', { class: 'chart-head' }, h('div', null, h('span', { class: 'chart-title' }, o.title), sub), tableBtn),
      body, tableWrap);
    let build = null;
    function apply() {
      const on = app.tableViews.has(o.id);
      tableBtn.setAttribute('aria-pressed', String(on));
      body.hidden = on;
      tableWrap.hidden = !on;
      if (on && build) replace(tableWrap, build());
      else replace(tableWrap);
    }
    tableBtn.addEventListener('click', () => {
      if (app.tableViews.has(o.id)) app.tableViews.delete(o.id); else app.tableViews.add(o.id);
      apply();
    });
    return { fig, body, sub, tableBtn, setTable(fn) { build = fn; apply(); } };
  }

  /** netTableView wraps the tables of a figure's table view (table() results) in one scrolling,
   *  focusable region. */
  function netTableView(label, ...tables) {
    return h('div', { class: 'chart-table', tabindex: '0', role: 'region', 'aria-label': label + ' — table view' },
      tables.map((t) => (t && t.classList && t.classList.contains('table-scroll') ? t.firstChild : t)));
  }

  /** netBars draws a ranked list as labelled bars: one series, so every bar is in the first
   *  slot's colour, as long as its share of the largest. items: [{name, note, value}]; shares are
   *  of total. */
  function netBars(items, total, label) {
    const top = items.reduce((a, x) => Math.max(a, x.value), 0) || 1;
    return h('ol', { class: 'bars', 'aria-label': label }, items.map((x) => {
      const fill = h('span', { class: 'bar-fill' });
      fill.style.width = Math.max(0.5, Math.min(100, (100 * x.value) / top)) + '%'; // CSSOM: allowed by the CSP
      return h('li', null,
        h('span', { class: 'bar-head' }, h('span', { class: 'bar-name' }, x.name, x.note ? h('span', { class: 'muted' }, ' ' + x.note) : null),
          h('span', { class: 'bar-val' }, fmtInt(x.value), h('span', { class: 'muted' }, ' · ' + netShare(x.value, total)))),
        h('span', { class: 'bar-track', 'aria-hidden': 'true' }, fill));
    }));
  }

  /** placeTipAt places a tooltip at (x, y) of its box (width × height), beside the point and
   *  inside the box. */
  function placeTipAt(tip, x, y, width, height) {
    tip.hidden = false;
    const tw = tip.offsetWidth;
    const th = tip.offsetHeight;
    let left = x + 14;
    if (left + tw > width) left = x - 14 - tw;
    if (left < 0) left = Math.max(0, Math.min(width - tw, x - tw / 2));
    let top = y + 14;
    if (height && top + th > height) top = Math.max(0, y - 14 - th);
    tip.style.left = Math.round(left) + 'px'; // CSSOM (not a style attribute): allowed by the CSP
    tip.style.top = Math.round(top) + 'px';
  }

  // ------------------------------------------------------------------ network view: flow diagram

  /** sankeyModel turns GET /api/network/connections into the flow diagram: three columns -
   *  devices, organisations, services - and the bands between them (links: device → organisation
   *  and organisation → service). A node is as tall as the larger of the weights of its bands in
   *  and out; nodes without a band (the devices a device filter leaves out) and bands that name no
   *  node are not drawn. */
  function sankeyModel(data) {
    const cols = [[], [], []];
    const index = [new Map(), new Map(), new Map()];
    const node = (col, key, x) => {
      const k = String(key == null ? '' : key);
      if (!k || index[col].has(k)) return;
      const n = Object.assign({ col, key: k, in: 0, out: 0, value: 0, links: [] }, x);
      index[col].set(k, n);
      cols[col].push(n);
    };
    for (const d of netList(data.devices)) {
      node(0, d.key, { name: String(d.name || d.ipv4 || d.key), sub: d.ipv4 && d.ipv4 !== d.name ? String(d.ipv4) : '', sites: Number(d.sites) || 0, slot: deviceSlot(d.key), device: true });
    }
    for (const o of netList(data.orgs)) {
      const name = String(o.name || (o.asn ? 'AS' + o.asn : o.key));
      // One company's ASes are one organisation: its tooltip lists them all.
      const asns = Array.isArray(o.asns) && o.asns.length > 1 ? o.asns.map((a) => 'AS' + Number(a)).join(', ') : o.asn ? 'AS' + o.asn : '';
      node(1, o.key, {
        name: o.key === 'other' && Number(o.members) > 0 ? name + ' (' + fmtInt(o.members) + ')' : name,
        sub: [asns, o.country ? countryName(o.country) : ''].filter(Boolean).join(', '), sites: Number(o.sites) || 0,
      });
    }
    for (const sv of netList(data.services)) {
      // A port without a name is named by its port alone ("8443/tcp").
      node(2, sv.key, unnamedPort(sv) ? { name: portText(sv.port, sv.proto), sub: '' } : { name: String(sv.name || sv.key), sub: portText(sv.port, sv.proto) });
    }
    const links = [];
    for (const l of netList(data.links)) {
      const w = Number(l.weight);
      if (!(w > 0)) continue;
      let a = index[0].get(String(l.from));
      let b = index[1].get(String(l.to));
      if (!a || !b) {
        a = index[1].get(String(l.from));
        b = index[2].get(String(l.to));
      }
      if (!a || !b) continue;
      const link = { a, b, w };
      links.push(link);
      a.out += w;
      b.in += w;
      a.links.push(link);
      b.links.push(link);
    }
    for (const col of cols) for (const n of col) n.value = Math.max(n.in, n.out);
    return { cols: cols.map((col) => col.filter((n) => n.value > 0)), links };
  }

  /** sankeyLayout places the nodes and bands of a sankeyModel: columns at xs (each nodeW wide),
   *  nodes between top and top + height. One scale for every column (k pixels per unit of
   *  weight), so that a band is as wide where it leaves as where it arrives; the nodes of a column
   *  stacked in their order, pad apart, centred, none shorter than minH. A node's bands leave in
   *  the order of the nodes they reach and arrive in the order of the nodes they come from, so
   *  that they do not cross at the nodes. Sets n.x, n.y, n.h, and l.width, l.y0, l.y1 (the band's
   *  centre at each end) and l.d (a cubic Bézier path, drawn with stroke-width l.width); returns k. */
  function sankeyLayout(m, o) {
    let k = Infinity;
    for (const col of m.cols) {
      if (!col.length) continue;
      const avail = Math.max(1, o.height - o.pad * (col.length - 1));
      let kc = avail / col.reduce((a, n) => a + n.value, 0);
      for (let i = 0; i < 8; i++) { // the nodes below minH take minH: share the rest among the others
        let small = 0;
        let rest = 0;
        for (const n of col) {
          if (n.value * kc < o.minH) small++;
          else rest += n.value;
        }
        const next = rest > 0 ? (avail - small * o.minH) / rest : kc;
        if (!(next > 0) || Math.abs(next - kc) < 1e-9) break;
        kc = next;
      }
      k = Math.min(k, kc);
    }
    if (!isFinite(k) || k < 0) k = 0;
    m.cols.forEach((col, ci) => {
      const hs = col.map((n) => Math.max(o.minH, n.value * k));
      const total = hs.reduce((a, b) => a + b, 0) + o.pad * Math.max(0, col.length - 1);
      let y = o.top + Math.max(0, (o.height - total) / 2);
      col.forEach((n, i) => {
        n.x = o.xs[ci];
        n.y = y;
        n.h = hs[i];
        y += hs[i] + o.pad;
      });
    });
    for (const col of m.cols) {
      for (const n of col) {
        let sy = n.y + (n.h - n.out * k) / 2;
        for (const l of n.links.filter((x) => x.a === n).sort((p, q) => p.b.y - q.b.y)) {
          l.width = l.w * k;
          l.y0 = sy + l.width / 2;
          sy += l.width;
        }
        let ty = n.y + (n.h - n.in * k) / 2;
        for (const l of n.links.filter((x) => x.b === n).sort((p, q) => p.a.y - q.a.y)) {
          l.y1 = ty + (l.w * k) / 2;
          ty += l.w * k;
        }
      }
    }
    const f = (v) => v.toFixed(1);
    for (const l of m.links) {
      const x0 = l.a.x + o.nodeW;
      const x1 = l.b.x;
      const xm = (x0 + x1) / 2;
      l.d = `M${f(x0)} ${f(l.y0)}C${f(xm)} ${f(l.y0)} ${f(xm)} ${f(l.y1)} ${f(x1)} ${f(l.y1)}`;
    }
    return k;
  }

  /** spreadLabels moves label centres ys (in the order of their nodes) at least gap apart, within
   *  [lo, hi], as little as it can: pushed down from the top, then back up from the bottom. */
  function spreadLabels(ys, gap, lo, hi) {
    const out = ys.slice();
    for (let i = 0; i < out.length; i++) out[i] = Math.max(out[i], i ? out[i - 1] + gap : lo);
    for (let i = out.length - 1; i >= 0; i--) out[i] = Math.min(out[i], i < out.length - 1 ? out[i + 1] - gap : hi);
    return out;
  }

  /** sankeyHeight is the height of the flow diagram's node area for a longest column of most
   *  nodes, o: NET_SANKEY: 30 px a node, at least 200 px and at most 640 px - a limit raised for
   *  a longer column (a household's devices over 30 days) to what it needs: its labels gap px
   *  apart, and its nodes at their minimum height, pad px apart, with 200 px left for their
   *  weights. Held at 640 px, a column of more than about 40 nodes would squeeze every node to
   *  the minimum height (and the other columns with it: they share one scale), push its first
   *  labels above the drawing and its last nodes below it. */
  function sankeyHeight(most, o) {
    const n = Math.max(1, Math.floor(Number(most)) || 1);
    const cap = Math.max(640, (n - 1) * o.gap + 2 * o.edge, (n - 1) * o.pad + n * o.minH + 200);
    return Math.min(cap, Math.max(200, n * 30));
  }

  /** sankeyColumns places the flow diagram's three columns in a drawing W px wide, nodes nodeW
   *  wide. The labels of the devices (left of their nodes) take c0 characters at most (the
   *  longest name and its share), within 28 % of the width; those of the services (on the right)
   *  c2 (name, port and share), within 32 %; 13 px type is about 7.2 px a character. Returns {xs:
   *  the x of each column, room: the characters of a label each column has room for}. The
   *  margins are rounded up, never down, so that the longest label gets all the room its margin
   *  was widened for and is not cut by a character. */
  function sankeyColumns(W, c0, c2, nodeW) {
    const fits = (px) => Math.max(4, Math.floor(px / 7.2));
    const left = Math.ceil(Math.max(110, Math.min(W * 0.28, 26 + 7.2 * c0)));
    const right = Math.ceil(Math.max(120, Math.min(W * 0.32, 30 + 7.2 * c2)));
    const xs = [left, 0, W - right - nodeW];
    xs[1] = Math.round(xs[0] + (xs[2] - xs[0]) * 0.52);
    const room = [Math.min(28, fits(left - 26) - 6), Math.min(28, fits(xs[2] - xs[1] - nodeW - 30) - 6), fits(right - 30)].map((r) => Math.max(4, r));
    return { xs, room };
  }

  /** netFlow is the flow diagram of the Connections tab: devices on the left (in their colours),
   *  the organisations they reached in the middle (the top ones, the rest as "Other"), the
   *  services on the right; a band's width is how often its connections were seen when the NAT
   *  table was read. Hovering a band or a node, or focusing a node, shows its figures and lifts
   *  its bands. The nodes take the keyboard focus, one tab stop for the diagram: the arrow keys
   *  move between them, Home and End to the ends of a column; clicking a device, or Enter on it,
   *  shows only that device (onDevice), and again every device. On a narrow screen the diagram
   *  scrolls in its box; a long column of devices makes it taller (sankeyHeight). The table view
   *  lists the bands. Returns {el, update(data, o)}, o:
   *  {device (the filter), words (the period)}. */
  function netFlow(ctx, onDevice) {
    const fr = netFigure({ id: 'net-flow', title: 'Devices and the sites they reach' });
    const only = h('p', { class: 'small net-only', hidden: true });
    const scroll = h('div', { class: 'sk-scroll' });
    const tip = h('div', { class: 'tip', hidden: true, 'aria-hidden': 'true' });
    const wrap = h('div', { class: 'sk-wrap' }, scroll, tip);
    // Shown on narrow screens only (style.css): the diagram keeps a legible size and scrolls.
    const hint = h('p', { class: 'sk-hint' }, 'The diagram is wider than the screen: scroll it sideways, or show it as a table.');
    add(fr.body, [only, wrap, hint]);
    let model = null;
    let filter = '';
    let W = 0;
    let svg = null;
    let nodeEls = new Map(); // node -> its <g>
    let active = ''; // "col:key" of the node with tabindex 0

    const nodeId = (n) => n.col + ':' + n.key;
    const total = (col) => model.cols[col].reduce((a, n) => a + n.value, 0);
    // A service's label also says its port and share ("HTTPS 443/tcp · 81 %"): its name gets the rest.
    const noteLen = (n) => (n.col === 2 && n.sub ? n.sub.length + 9 : 6);
    const labelOf = (n) => netText(n.name, n.col === 2 ? Math.max(4, room[2] - noteLen(n)) : room[n.col]);
    // The characters of a label each column has room for (sankeyColumns), set by draw(): the
    // labels are cut to it, never clipped by the drawing's edge.
    let room = [28, 28, 28];

    function draw() {
      if (!model || !model.links.length) return;
      // The box's width rounded down: an SVG a fraction of a pixel too wide would scroll.
      const avail = Math.floor(scroll.getBoundingClientRect().width);
      if (!avail) return; // hidden (the table view): drawn when shown again
      const prev = document.activeElement;
      const focusKey = prev && svg && svg.contains(prev) ? prev.getAttribute('data-fk') : null;
      W = Math.max(NET_SANKEY_MIN_W, avail);
      const most = Math.max(1, ...model.cols.map((col) => col.length));
      const height = sankeyHeight(most, NET_SANKEY);
      const top = 30;
      const H = top + height + 12;
      const nodeW = 10;
      // Room for the labels: devices on the left (name and share), services on the right (name,
      // port and share), as much as their texts take, within a share of the width.
      const chars = (col) => model.cols[col].reduce((a, n) => Math.max(a, netText(n.name, 28).length + noteLen(n)), 0);
      const place = sankeyColumns(W, chars(0), chars(2), nodeW);
      const xs = place.xs;
      room = place.room;
      sankeyLayout(model, { top, height, xs, nodeW, pad: NET_SANKEY.pad, minH: NET_SANKEY.minH });

      svg = s('svg', { class: 'sk-svg', width: W, height: H, viewBox: `0 0 ${W} ${H}`, role: 'group', 'aria-label': 'Flow diagram: devices on the left, the organisations they connected to in the middle, the services on the right' });
      svg.append(
        s('text', { class: 'sk-head', x: xs[0] + nodeW, y: 14, 'text-anchor': 'end', 'aria-hidden': 'true' }, 'DEVICE'),
        s('text', { class: 'sk-head', x: xs[1], y: 14, 'aria-hidden': 'true' }, 'ORGANISATION'),
        s('text', { class: 'sk-head', x: xs[2], y: 14, 'aria-hidden': 'true' }, 'SERVICE'));
      const bands = s('g', { class: 'sk-bands', 'aria-hidden': 'true' });
      for (const l of model.links) {
        const cls = l.a.col === 0 ? 'sk-band c' + l.a.slot : 'sk-band sk-neutral';
        l.el = s('path', { class: cls, d: l.d, 'stroke-width': Math.max(1, l.width).toFixed(1) });
        l.el.addEventListener('pointerenter', (e) => lift([l], bandTip(l), e));
        l.el.addEventListener('pointermove', (e) => moveTip(e));
        l.el.addEventListener('pointerleave', unlift);
        bands.append(l.el);
      }
      svg.append(bands);
      nodeEls = new Map();
      const nodes = s('g', { class: 'sk-nodes' });
      model.cols.forEach((col, ci) => {
        const ys = spreadLabels(col.map((n) => n.y + n.h / 2), NET_SANKEY.gap, top + NET_SANKEY.edge, top + height - NET_SANKEY.edge);
        const sum = total(ci);
        col.forEach((n, i) => nodes.append(nodeEl(n, ys[i], sum, ci, xs, nodeW)));
      });
      svg.append(nodes);
      const ids = [...nodeEls.keys()].map(nodeId);
      if (!ids.includes(active)) active = ids[0] || '';
      for (const [n, g] of nodeEls) g.setAttribute('tabindex', nodeId(n) === active ? '0' : '-1');
      replace(scroll, svg);
      tip.hidden = true;
      if (focusKey) {
        const g = [...nodeEls.values()].find((x) => x.getAttribute('data-fk') === focusKey);
        if (g) g.focus();
      }
    }

    /** nodeEl draws a node: its bar, its label (outside the bar: devices on the left, the others
     *  on the right) and an area that takes the pointer and the focus. */
    function nodeEl(n, ly, sum, ci, xs, nodeW) {
      const left = ci === 0;
      const lx = left ? n.x - 8 : n.x + nodeW + 8;
      const text = labelOf(n);
      const pct = netShare(n.value, sum);
      const note = ci === 2 && n.sub ? ' ' + n.sub + ' · ' + pct : ' ' + pct;
      const wEst = 7.2 * (text.length + note.length) + 12;
      const hx = left ? Math.max(2, lx - wEst) : n.x - 3;
      const hw = left ? n.x + nodeW + 3 - hx : nodeW + 3 + 8 + wEst;
      const y0 = Math.min(n.y, ly - 10) - 2;
      const y1 = Math.max(n.y + n.h, ly + 10) + 2;
      const isOnly = n.device && filter === n.key;
      const label = netText(n.name, 80) + (n.sub && ci !== 2 ? ' (' + n.sub + ')' : '') + ': seen ' + fmtInt(n.value) + ' time' + (n.value === 1 ? '' : 's') +
        ', ' + pct + (n.sites ? ', ' + fmtInt(n.sites) + ' remote address' + (n.sites === 1 ? '' : 'es') : '') + '.' +
        (n.device ? (isOnly ? ' Shown alone: press Enter to show every device.' : ' Press Enter to show only this device.') : '');
      const g = s('g', {
        class: 'sk-node' + (n.device ? ' is-device' : ''), tabindex: '-1', role: n.device ? 'button' : 'img',
        'aria-label': label, 'aria-pressed': n.device ? String(isOnly) : null, 'data-fk': 'sk:' + nodeId(n),
      },
      s('rect', { class: 'sk-hit', x: hx.toFixed(1), y: y0.toFixed(1), width: Math.max(1, hw).toFixed(1), height: (y1 - y0).toFixed(1) }),
      s('rect', { class: 'sk-ring', x: (hx - 2).toFixed(1), y: (y0 - 1).toFixed(1), width: (Math.max(1, hw) + 4).toFixed(1), height: (y1 - y0 + 2).toFixed(1), rx: 4 }),
      s('rect', { class: n.device ? 'sk-bar f' + n.slot : 'sk-bar sk-bar-n', x: n.x, y: n.y.toFixed(1), width: nodeW, height: n.h.toFixed(1), rx: 2 }),
      s('text', { class: 'sk-label', x: lx, y: ly.toFixed(1), dy: '0.35em', 'text-anchor': left ? 'end' : 'start' },
        text, s('tspan', { class: 'sk-pct' }, note)));
      g.addEventListener('pointerenter', (e) => lift(n.links, nodeTip(n, pct), e));
      g.addEventListener('pointermove', (e) => moveTip(e));
      g.addEventListener('pointerleave', unlift);
      g.addEventListener('focus', () => {
        active = nodeId(n);
        for (const [m2, g2] of nodeEls) g2.setAttribute('tabindex', m2 === n ? '0' : '-1');
        g.classList.add('is-focus');
        lift(n.links, nodeTip(n, pct), null, n);
      });
      g.addEventListener('blur', () => {
        g.classList.remove('is-focus');
        unlift();
      });
      g.addEventListener('keydown', (e) => onKey(e, n));
      if (n.device) g.addEventListener('click', () => onDevice(isOnly ? '' : n.key));
      nodeEls.set(n, g);
      return g;
    }

    function onKey(e, n) {
      const col = model.cols[n.col];
      const i = col.indexOf(n);
      let next = null;
      switch (e.key) {
        case 'ArrowDown': next = col[Math.min(col.length - 1, i + 1)]; break;
        case 'ArrowUp': next = col[Math.max(0, i - 1)]; break;
        case 'Home': next = col[0]; break;
        case 'End': next = col[col.length - 1]; break;
        case 'ArrowRight':
        case 'ArrowLeft': {
          const other = model.cols[n.col + (e.key === 'ArrowRight' ? 1 : -1)];
          const mid = n.y + n.h / 2;
          if (other && other.length) next = other.reduce((a, b) => (Math.abs(b.y + b.h / 2 - mid) < Math.abs(a.y + a.h / 2 - mid) ? b : a));
          break;
        }
        case 'Enter':
        case ' ':
          if (n.device) {
            e.preventDefault();
            onDevice(filter === n.key ? '' : n.key);
          }
          return;
        case 'Escape': unlift(); return;
        default: return;
      }
      e.preventDefault();
      const g = next && nodeEls.get(next);
      if (g && next !== n) g.focus();
    }

    function bandTip(l) {
      const a = netText(l.a.name, 40);
      const b = netText(l.b.name, 40);
      return [
        h('div', { class: 'tip-time' }, a, ' → ', b),
        h('div', { class: 'tip-row' }, l.a.col === 0 ? lineKey(l.a.slot) : h('span'), h('span', { class: 'val' }, fmtInt(l.w)), h('span', { class: 'lab' }, 'times seen')),
        h('div', { class: 'tip-utc' }, netShare(l.w, l.a.value) + ' of ' + a + ', ' + netShare(l.w, l.b.value) + ' of ' + b),
      ];
    }

    function nodeTip(n, pct) {
      return [
        h('div', { class: 'tip-time' }, netText(n.name, 48)),
        n.sub ? h('div', { class: 'tip-utc' }, n.sub) : null,
        h('div', { class: 'tip-row' }, n.device ? lineKey(n.slot) : h('span'), h('span', { class: 'val' }, fmtInt(n.value)), h('span', { class: 'lab' }, 'times seen · ' + pct)),
        n.sites ? h('div', { class: 'tip-row' }, h('span'), h('span', { class: 'val' }, fmtInt(n.sites)), h('span', { class: 'lab' }, 'remote addresses')) : null,
        n.device ? h('div', { class: 'tip-utc' }, filter === n.key ? 'Click or press Enter to show every device' : 'Click or press Enter to show only this device') : null,
      ];
    }

    /** lift highlights bands (the others recede) and shows the tooltip: at the pointer (e), or
     *  beside a node that has the focus. */
    function lift(links, content, e, n) {
      if (!svg) return;
      svg.classList.add('sk-dim');
      for (const l of model.links) if (l.el) l.el.classList.remove('is-hot');
      for (const l of links) if (l.el) l.el.classList.add('is-hot');
      replace(tip, content);
      if (e) moveTip(e);
      else if (n) {
        const x = (n.col === 0 ? n.x + 14 : n.x + 10) - scroll.scrollLeft;
        placeTipAt(tip, x, n.y + n.h / 2, wrap.clientWidth, wrap.clientHeight);
      }
    }

    function moveTip(e) {
      const r = wrap.getBoundingClientRect();
      placeTipAt(tip, e.clientX - r.left, e.clientY - r.top, wrap.clientWidth, wrap.clientHeight);
    }

    function unlift() {
      tip.hidden = true;
      if (!svg) return;
      svg.classList.remove('sk-dim');
      for (const l of model.links) if (l.el) l.el.classList.remove('is-hot');
    }

    function buildTable() {
      const byW = (p, q) => q.w - p.w;
      const dev = model.links.filter((l) => l.a.col === 0).sort(byW).map((l) => [
        h('span', { class: 'dev' }, deviceDot(l.a.key), h('span', null, netShown(l.a.name, 60))), netShown(l.b.name, 60), fmtInt(l.w), netShare(l.w, l.a.value)]);
      const org = model.links.filter((l) => l.a.col === 1).sort(byW).map((l) => [
        netShown(l.a.name, 60), [netShown(l.b.name, 40), l.b.sub ? h('span', { class: 'sub small muted' }, l.b.sub) : null], fmtInt(l.w), netShare(l.w, l.a.value)]);
      return netTableView('Devices and the sites they reach',
        table([{ label: 'Device' }, { label: 'Organisation' }, { label: 'Times seen', num: true }, { label: 'Share of the device', num: true }], dev,
          { compact: true, caption: 'Devices → organisations' }),
        table([{ label: 'Organisation' }, { label: 'Service' }, { label: 'Times seen', num: true }, { label: 'Share of the organisation', num: true }], org,
          { compact: true, caption: 'Organisations → services' }));
    }

    const ro = new ResizeObserver(() => {
      const w = Math.floor(scroll.getBoundingClientRect().width);
      if (w && Math.max(NET_SANKEY_MIN_W, w) !== W) draw();
    });
    ro.observe(scroll);
    ctx.cleanup(() => ro.disconnect());

    return {
      el: fr.fig,
      update(data, o) {
        filter = o.device || '';
        model = sankeyModel(data);
        replace(fr.sub, o.words + '. Band width: how often the connection was open when the NAT table was read.');
        const sel = filter ? model.cols[0].find((n) => n.key === filter) : null;
        only.hidden = !filter;
        replace(only, filter ? ['Only ', h('strong', null, sel ? netText(sel.name, 48) : filter), ' is shown. ',
          h('button', { type: 'button', class: 'link-btn', 'data-fk': 'net-flow:all' }, 'Show every device')] : null);
        const all = only.querySelector('button');
        if (all) all.addEventListener('click', () => onDevice('', 'all'));
        if (!model.links.length) {
          svg = null;
          replace(scroll, emptyNote(filter ? 'This device had no connection in this period.' : 'No connection was seen in this period.'));
        } else {
          W = 0;
          draw();
        }
        fr.setTable(() => (model.links.length ? buildTable() : emptyNote('No connection in this period.')));
      },
    };
  }

  // ------------------------------------------------------------------ network view: world map

  let worldReq = null;

  /** worldData reads the world map once (static/world.json: the Natural Earth 1:110m countries,
   *  pre-projected to SVG paths, keyed by ISO code) and keeps it; a failed read is tried again
   *  the next time. */
  function worldData() {
    if (!worldReq) {
      worldReq = api('/static/world.json').then((w) => {
        if (!w || !(Number(w.w) > 0) || !(Number(w.h) > 0) || !Array.isArray(w.countries)) throw new Error('The world map data are not valid.');
        const countries = w.countries.filter((x) => x && typeof x.id === 'string' && typeof x.d === 'string');
        for (const x of countries) if (typeof x.n === 'string' && x.n && !worldNames.has(x.id)) worldNames.set(x.id, x.n);
        return { w: Number(w.w), h: Number(w.h), countries };
      });
      worldReq.catch(() => { worldReq = null; });
    }
    return worldReq;
  }

  /** mapBreaks returns the lower bounds of the map's five colour steps for values up to max:
   *  1, then numbers of the 1-2-5 series spaced evenly on a log scale, the last one below max,
   *  e.g. [1, 2, 5, 20, 50] for 152 sites; 1 to 5 for small values. */
  function mapBreaks(max) {
    const m = Math.max(1, Number(max) || 1);
    if (m <= 5) return [1, 2, 3, 4, 5];
    const nice = (v) => {
      const p = Math.pow(10, Math.floor(Math.log10(v)));
      const f = v / p;
      return (f < 1.5 ? 1 : f < 3.5 ? 2 : f < 7.5 ? 5 : 10) * p;
    };
    const out = [1];
    for (let i = 1; i < 5; i++) out.push(Math.max(out[i - 1] + 1, Math.min(nice(Math.pow(m, i / 5)), Math.floor(m))));
    return out;
  }

  /** mapStep is the colour step (1-5) of a value, 0 for none. */
  function mapStep(v, breaks) {
    if (!(v > 0)) return 0;
    let step = 1;
    for (let i = 1; i < breaks.length; i++) if (v >= breaks[i]) step = i + 1;
    return step;
  }

  /** netMap is a world map card: the countries shaded in five steps of one hue (mapBreaks) by
   *  o.value, a legend, a tooltip on hover and from the keyboard (the map takes the focus; the
   *  arrow keys step through the countries with a value, largest first), and beside it the top
   *  countries as bars - Unknown ("") among them - and the others the map has no shape for
   *  (renderSide). o: NET_CONN_MAP or NET_FW_MAP. Returns {el, update(countries)}. */
  function netMap(ctx, o) {
    const fr = netFigure({ id: o.id, title: o.title, sub: o.sub });
    const plot = h('div', {
      class: 'map-plot', tabindex: '0', role: 'group', 'aria-roledescription': 'map', 'data-fk': o.id + ':map',
      'aria-label': o.title + '. Use the arrow keys to read the countries, T for the table view.',
    });
    const tip = h('div', { class: 'tip', hidden: true, 'aria-hidden': 'true' });
    plot.append(tip);
    const live = h('div', { class: 'sr-only', 'aria-live': 'polite' });
    const legend = h('div', { class: 'map-legend' });
    const side = h('div', { class: 'map-side' });
    add(fr.body, [h('div', { class: 'map-wrap' }, h('div', { class: 'map-main' }, plot, legend), side), live]);
    let world = null;
    let svg = null;
    const paths = new Map(); // ISO code -> its paths
    let rows = []; // [{code, value, extra}], largest first
    let total = 0;
    let breaks = [1, 2, 3, 4, 5];
    let hot = '';
    let idx = -1;

    worldData().then((wd) => {
      if (!ctx.alive) return;
      world = wd;
      build();
      paint();
      if (rows.length) renderSide(); // country names known now
    }).catch(() => {
      if (ctx.alive) plot.insertBefore(emptyNote('The world map could not be loaded; the list beside it and the table view show every country.'), tip);
    });

    function build() {
      svg = s('svg', { class: 'map-svg', viewBox: `0 0 ${world.w} ${world.h}`, 'aria-hidden': 'true', focusable: 'false' });
      for (const x of world.countries) {
        const p = s('path', { d: x.d, class: 'map-0', 'data-cc': x.id });
        if (!paths.has(x.id)) paths.set(x.id, []);
        paths.get(x.id).push(p);
        svg.append(p);
      }
      svg.addEventListener('pointermove', (e) => {
        const p = e.target && e.target.closest ? e.target.closest('path') : null;
        if (!p) {
          hide();
          return;
        }
        const r = plot.getBoundingClientRect();
        showCountry(p.getAttribute('data-cc') || '', e.clientX - r.left, e.clientY - r.top, true);
      });
      svg.addEventListener('pointerleave', hide);
      plot.insertBefore(svg, tip);
    }

    function paint() {
      if (!svg) return;
      const byCode = new Map(rows.map((r) => [r.code, r]));
      for (const [code, ps] of paths) {
        const r = byCode.get(code);
        const cls = 'map-' + (r ? mapStep(r.value, breaks) : 0) + (code === hot ? ' is-hot' : '');
        for (const p of ps) {
          p.setAttribute('class', cls);
          if (code === hot) svg.append(p); // on top, so that its outline shows
        }
      }
    }

    function rowOf(code) {
      return rows.find((r) => r.code === code) || null;
    }

    function tipLines(code) {
      const r = rowOf(code);
      return [
        h('div', { class: 'tip-time' }, countryName(code)),
        r ? h('div', { class: 'tip-row' }, h('span'), h('span', { class: 'val' }, o.unit(r.value)), h('span', { class: 'lab' }, netShare(r.value, total))) : h('div', { class: 'tip-utc' }, 'none'),
        r && r.extra ? h('div', { class: 'tip-utc' }, o.extraUnit(r.extra)) : null,
      ];
    }

    function showCountry(code, x, y, pointer) {
      if (hot !== code) {
        hot = code;
        paint();
      }
      replace(tip, tipLines(code));
      placeTipAt(tip, x, y, plot.clientWidth, plot.clientHeight);
      if (!pointer) {
        const r = rowOf(code);
        live.textContent = countryName(code) + ': ' + (r ? o.unit(r.value) + ', ' + netShare(r.value, total) : 'none');
      }
    }

    /** showRow shows a country chosen from the keyboard: beside its shape when the browser can
     *  measure it, else in the corner. */
    function showRow(r) {
      let x = 8;
      let y = 8;
      const p = paths.get(r.code);
      if (p && p[0] && typeof p[0].getBBox === 'function' && world) {
        try {
          const b = p[0].getBBox();
          const k = plot.clientWidth / world.w;
          x = (b.x + b.width / 2) * k;
          y = (b.y + b.height / 2) * k;
        } catch (_) { /* not rendered */ }
      }
      showCountry(r.code, x, y, false);
    }

    function hide() {
      tip.hidden = true;
      if (hot) {
        hot = '';
        paint();
      }
    }

    plot.addEventListener('keydown', (e) => {
      if (!rows.length) return;
      switch (e.key) {
        case 'ArrowRight': case 'ArrowDown': idx = Math.min(rows.length - 1, idx + 1); break;
        case 'ArrowLeft': case 'ArrowUp': idx = Math.max(0, idx - 1); break;
        case 'Home': idx = 0; break;
        case 'End': idx = rows.length - 1; break;
        case 'Escape': hide(); return;
        case 't': case 'T': fr.tableBtn.click(); return;
        default: return;
      }
      e.preventDefault();
      showRow(rows[idx]);
    });
    plot.addEventListener('focus', () => {
      if (rows.length) showRow(rows[Math.max(0, Math.min(idx, rows.length - 1))]);
    });
    plot.addEventListener('blur', hide);

    function renderLegend() {
      const keys = breaks.map((b, i) => {
        const hi = i < breaks.length - 1 ? breaks[i + 1] - 1 : null;
        const text = hi == null ? fmtInt(b) + '+' : hi === b ? fmtInt(b) : fmtInt(b) + '–' + fmtInt(hi);
        return h('span', { class: 'map-key' }, h('span', { class: 'map-swatch sw-' + (i + 1), 'aria-hidden': 'true' }), text);
      });
      replace(legend, h('span', { class: 'map-legend-title' }, o.legend), keys,
        h('span', { class: 'map-key' }, h('span', { class: 'map-swatch sw-0', 'aria-hidden': 'true' }), 'None'));
    }

    /** renderSide lists the top countries beside the map, the others together, and then, once
     *  the map is loaded, those of the others it has no shape for (Singapore, Hong Kong, Malta and
     *  other small states at this scale; Unknown): shaded nowhere, they would otherwise be seen
     *  only in the table view. */
    function renderSide() {
      const top = rows.slice(0, 5);
      const rest = rows.slice(5);
      const items = top.map((r) => ({ name: countryName(r.code), value: r.value }));
      if (rest.length) items.push({ name: fmtInt(rest.length) + ' other countr' + (rest.length === 1 ? 'y' : 'ies'), value: rest.reduce((a, r) => a + r.value, 0) });
      const off = world ? rest.filter((r) => !paths.has(r.code)) : [];
      const named = off.slice(0, 5);
      replace(side, h('h3', { class: 'side-head' }, 'Top countries'),
        items.length ? netBars(items, total, 'Top countries') : emptyNote('None in this period.'),
        named.length ? h('p', { class: 'small muted map-off' }, 'Not on the map: ',
          named.map((r, i) => [i ? ', ' : '', countryName(r.code), ' ', fmtInt(r.value)]),
          off.length > named.length ? ', and ' + fmtInt(off.length - named.length) + ' more in the table view.' : '.') : null);
    }

    function buildTable() {
      return netTableView(o.title, table(
        [{ label: 'Country' }, { label: 'Code' }, { label: o.valueLabel, num: true }, { label: o.extraLabel, num: true }, { label: 'Share', num: true }],
        rows.map((r) => [countryName(r.code), r.code ? netText(r.code, 8) : '—', fmtInt(r.value), fmtInt(r.extra), netShare(r.value, total)]), { compact: true }));
    }

    return {
      el: fr.fig,
      update(countries) {
        rows = netList(countries).map((x) => ({ code: typeof x.code === 'string' ? x.code : '', value: o.value(x), extra: o.extra(x) }))
          .filter((r) => r.value > 0).sort((a, b) => b.value - a.value);
        total = rows.reduce((a, r) => a + r.value, 0);
        breaks = mapBreaks(rows.length ? rows[0].value : 1);
        idx = Math.min(idx, rows.length - 1);
        renderLegend();
        renderSide();
        paint();
        fr.setTable(buildTable);
      },
    };
  }

  // ------------------------------------------------------------------ network view: connections table

  // The connections table's columns: what each sorts by, and in which direction at first.
  const NET_CONN_COLS = [
    { key: 'device', label: 'Device' },
    { key: 'remote', label: 'Remote address' },
    { key: 'org', label: 'Organisation' },
    { key: 'country', label: 'Country' },
    { key: 'service', label: 'Service' },
    { key: 'first', label: 'First seen', num: true, desc: true },
    { key: 'last', label: 'Last seen', num: true, desc: true },
    { key: 'samples', label: 'Times seen', num: true, desc: true },
  ];

  /** ipSortKey makes addresses sort by number (IPv4 before IPv6, each in order). */
  function ipSortKey(v) {
    const t = String(v == null ? '' : v);
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(t);
    return m ? '4' + m.slice(1).map((x) => x.padStart(3, '0')).join('.') : '6' + t.toLowerCase();
  }

  /** netConnTable is the Connections tab's table: each device's remote addresses with their
   *  reverse DNS name, organisation, country and service, when first and last seen and how many
   *  times. The search box keeps the rows that contain every word typed; a column heading sorts
   *  by that column (again: the other way round); the first NET_TABLE_PAGE rows are shown until
   *  "Show all". The search, the sort and "Show all" stay as they are when new data arrive.
   *  Returns {el, update(data, endsNow)}. */
  function netConnTable(ctx) {
    const search = h('input', { type: 'search', name: 'filter', placeholder: 'Filter by device, address, organisation', autocomplete: 'off', spellcheck: 'false', maxlength: '200', 'data-fk': 'net-conns:search' });
    const box = h('div', { class: 'net-conns-body' });
    const foot = h('div', { class: 'card-foot net-conns-foot' });
    const status = h('span');
    const more = h('button', { type: 'button', class: 'link-btn', hidden: true, 'data-fk': 'net-conns:more' }, 'Show all');
    add(foot, [status, ' ', more]);
    const el = h('section', { class: 'card', 'aria-labelledby': 'net-conns-h' },
      h('div', { class: 'card-head net-conns-head' },
        h('div', null, h('h2', { id: 'net-conns-h' }, 'Connections'),
          h('p', { class: 'chart-sub' }, 'Each device’s remote addresses, most seen first. The names under an address are its reverse DNS.')),
        h('label', { class: 'net-search' }, h('span', { class: 'sr-only' }, 'Filter the connections'), search)),
      box, foot);
    let rows = [];
    let totalRows = 0;
    let sort = { key: 'samples', dir: -1 };
    let all = false;
    let timer = 0;
    ctx.cleanup(() => window.clearTimeout(timer));
    search.addEventListener('input', () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(() => render(true), 150);
    });
    more.addEventListener('click', () => {
      all = !all;
      render(true);
    });

    /** render shows the rows that match the search, sorted; after the reader's own change
     *  (said), the new count is announced (a refresh changes it silently). */
    function render(said) {
      const terms = search.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
      const match = rows.filter((r) => terms.every((t) => r.hay.includes(t)));
      const col = NET_CONN_COLS.find((x) => x.key === sort.key) || NET_CONN_COLS[7];
      match.sort((p, q) => {
        const a = p.sort[col.key];
        const b = q.sort[col.key];
        const c = typeof a === 'number' && typeof b === 'number' ? a - b : String(a).localeCompare(String(b));
        return c * sort.dir || q.sort.samples - p.sort.samples;
      });
      const showN = all ? match.length : Math.min(match.length, NET_TABLE_PAGE);
      const head = h('tr', null, NET_CONN_COLS.map((x) => {
        const on = x.key === sort.key;
        const btn = h('button', { type: 'button', class: 'th-sort', 'data-fk': 'net-conns:sort:' + x.key }, x.label,
          h('span', { class: 'th-arrow', 'aria-hidden': 'true' }, on ? (sort.dir < 0 ? ' ▼' : ' ▲') : ''));
        btn.addEventListener('click', () => {
          sort = on ? { key: x.key, dir: -sort.dir } : { key: x.key, dir: x.desc ? -1 : 1 };
          render(true);
        });
        return h('th', { scope: 'col', class: x.num ? 'num' : null, 'aria-sort': on ? (sort.dir < 0 ? 'descending' : 'ascending') : null }, btn);
      }));
      keepFocus(el, () => {
        replace(box, match.length
          ? h('div', { class: 'table-scroll' }, h('table', { class: 'tbl net-conns' }, h('thead', null, head),
            h('tbody', null, match.slice(0, showN).map((r) => r.tr || (r.tr = r.make())))))
          : emptyNote(rows.length ? 'No connection matches the filter.' : 'No connection in this period.'));
      });
      const n = fmtInt(totalRows) + ' connection' + (totalRows === 1 ? '' : 's');
      const listed = totalRows > rows.length ? ' (the ' + fmtInt(rows.length) + ' most seen are listed)' : '';
      status.textContent = terms.length
        ? fmtInt(match.length) + ' of ' + n + ' match' + (match.length > showN ? ', ' + fmtInt(showN) + ' shown' : '') + listed + '.'
        : (showN < match.length ? 'Showing ' + fmtInt(showN) + ' of ' + n : 'Showing all ' + n) + listed + '.';
      more.hidden = match.length <= NET_TABLE_PAGE;
      more.textContent = all ? 'Show the first ' + NET_TABLE_PAGE : 'Show all';
      if (said) announce(status.textContent);
    }

    return {
      el,
      update(d, endsNow) {
        const names = new Map(netList(d.devices).map((dv) => [String(dv.key), String(dv.name || dv.ipv4 || dv.key)]));
        const lastRead = String(d.last || '');
        rows = netList(d.rows).map((r) => {
          const dev = names.get(String(r.device)) || String(r.lan || r.device || '?');
          const pub = !r.kind || r.kind === 'public';
          const org = r.org ? String(r.org) : pub ? 'Unknown' : IP_KINDS[r.kind] || String(r.kind);
          const cn = r.country ? countryName(r.country) : pub ? 'Unknown' : '—';
          const port = portText(r.port, r.proto);
          const now = endsNow && lastRead && r.last === lastRead;
          const lastD = toDate(r.last);
          // The row's elements are made when it is first shown (most of up to 1,000 rows never are).
          const make = () => h('tr', null,
            h('td', null, h('span', { class: 'dev', title: r.lan ? 'LAN address ' + escapedText(r.lan) : null }, deviceDot(r.device), h('span', null, netShown(dev, 40)))),
            h('td', { class: 'net-remote' }, h('span', { class: 'mono' }, netShown(r.remote, 64)), r.ptr ? h('span', { class: 'sub small muted wrap-any' }, netShown(r.ptr, 120)) : null),
            h('td', null, netShown(org, 60), r.asn ? h('span', { class: 'sub small muted' }, 'AS' + r.asn) : null),
            h('td', { title: r.country ? escapedText(r.country) : null }, cn),
            h('td', null, r.service ? netShown(r.service, 40) : h('span', { class: 'muted' }, '—'),
              port || r.inbound ? h('span', { class: 'sub small muted' }, port, r.inbound ? [port ? ' · ' : '', 'inbound'] : null) : null),
            h('td', { class: 'num' }, netTimeEl(r.first)),
            h('td', { class: 'num' }, now && lastD
              ? h('time', { datetime: lastD.toISOString(), title: 'Open at the newest read of the NAT table, ' + F.full.format(lastD) + ' · UTC: ' + utcText(r.last, lastD) }, 'now')
              : netTimeEl(r.last)),
            h('td', { class: 'num', title: Number(r.weight) > Number(r.samples) ? fmtInt(r.weight) + ' sessions over these reads' : null }, fmtInt(r.samples)));
          const hay = [dev, r.lan, r.remote, r.ptr, org, r.asn ? 'as' + r.asn : '', r.country, cn, r.service, port, r.proto]
            .filter((x) => x != null && x !== '').join(' ').toLowerCase();
          return {
            tr: null, make, hay,
            sort: {
              device: dev.toLowerCase(), remote: ipSortKey(r.remote), org: org.toLowerCase(), country: cn.toLowerCase(),
              service: String(r.service || port || '').toLowerCase(), first: toMs(r.first) || 0, last: toMs(r.last) || 0, samples: Number(r.samples) || 0,
            },
          };
        });
        totalRows = Math.max(rows.length, Number(d.rows_total) || 0);
        render(false);
      },
    };
  }

  // ------------------------------------------------------------------ network view: firewall timeline

  /** colPath is a column from y down to base, x..x+w wide, with its top corners rounded (r). */
  function colPath(x, y, w, base, r) {
    const rr = Math.max(0, Math.min(r, w / 2, base - y));
    const f = (v) => v.toFixed(1);
    return `M${f(x)} ${f(base)}V${f(y + rr)}Q${f(x)} ${f(y)} ${f(x + rr)} ${f(y)}H${f(x + w - rr)}Q${f(x + w)} ${f(y)} ${f(x + w)} ${f(y + rr)}V${f(base)}Z`;
  }

  /** fwTimeline draws the firewall's drops per hour over the period as stacked columns: inbound
   *  probes (slot 1), outbound packets from the home network (slot 2) and packets to or from the
   *  gateway itself (grey), each hour's column on its share of the period; a tooltip on hover and
   *  from the keyboard, the drops by reason under it, a table view. Built like lineChart. Like
   *  the page's other figures it stays in the page when new data arrive (update): the plot keeps
   *  the keyboard focus and the hour last shown (by its start), and shows that hour again without
   *  a word in its live region, so that the refresh every minute neither moves a keyboard user
   *  back to the last hour nor announces anything. Returns {el, update(data)}. */
  function fwTimeline(ctx) {
    const o = { id: 'net-fw-hours', title: 'Blocked per hour', subtitle: 'Packets the gateway’s firewall dropped, each hour of the period.' };
    const { fig, tableBtn, plot, tip, live } = chartFrame(o);
    plot.setAttribute('data-fk', 'net-fw-hours:plot');
    tableBtn.setAttribute('data-fk', 'net-fw-hours:table');
    const SER = [
      { key: 'in', label: 'Inbound probes', cls: 'f1', slot: 1 },
      { key: 'out', label: 'Outbound packets from the home network', cls: 'f2', slot: 2 },
      { key: 'local', label: 'To or from the gateway itself', cls: 'fw-local', slot: 0 },
    ];
    fig.append(h('ul', { class: 'legend', 'aria-label': 'Series' }, SER.map((x) => h('li', null, h('span', { class: 'static' },
      s('svg', { class: 'key', viewBox: '0 0 18 10', 'aria-hidden': 'true', focusable: 'false' }, s('rect', { class: x.cls, x: 3, y: 0, width: 12, height: 10, rx: 2 })), x.label)))));
    const summary = h('p', { class: 'chart-summary', hidden: true }); // the drops by reason
    const tableWrap = h('div', { hidden: true });
    add(fig, [plot, summary, live, tableWrap]);
    const H = 230;
    let from = null;
    let to = null;
    let hours = [];
    let W = 0;
    let chart = null; // the plot's <svg> (the tooltip's keys are <svg> too)
    let g = null;
    let idx = -1; // the hour shown last, from the keyboard or the pointer: the arrow keys go on from it
    const words = (x) => F.short.format(new Date(x.t)) + ' – ' + F.hm.format(new Date(x.t + 3600e3));

    function draw() {
      if (from == null || to == null || to <= from) {
        if (chart) chart.remove();
        chart = null;
        hide();
        g = null;
        return;
      }
      W = Math.max(260, Math.round(plot.clientWidth));
      const x0 = 54;
      const x1 = W - 14;
      const y0 = H - 26;
      const y1 = 12;
      const top = hours.reduce((a, x) => Math.max(a, x.in + x.out + x.local), 0);
      const nt = niceTicks(0, Math.max(1, top), 4);
      const hi = nt.hi;
      const xs = (t) => x0 + ((t - from) / (to - from)) * (x1 - x0);
      const ys = (v) => y0 - (v / hi) * (y0 - y1);
      const svg = s('svg', { width: W, height: H, viewBox: `0 0 ${W} ${H}`, 'aria-hidden': 'true', focusable: 'false' });
      for (const t of nt.ticks) {
        if (t > hi) continue;
        const y = Math.round(ys(t)) + 0.5;
        svg.append(s('line', { class: 'gl', x1: x0, x2: x1, y1: y, y2: y }), s('text', { class: 'tk', x: x0 - 8, y: y + 3.5, 'text-anchor': 'end' }, fmtInt(t)));
      }
      svg.append(s('line', { class: 'al', x1: x0, x2: x1, y1: y0 + 0.5, y2: y0 + 0.5 }));
      for (const t of timeTicks(from, to, x1 - x0)) {
        const x = Math.round(xs(t.ms)) + 0.5;
        svg.append(s('line', { class: 'al', x1: x, x2: x, y1: y0, y2: y0 + 4 }), s('text', { class: 'tk', x, y: y0 + 17, 'text-anchor': 'middle' }, t.label));
      }
      const cols = [];
      for (const x of hours) {
        const a = Math.max(from, x.t);
        const b = Math.min(to, x.t + 3600e3);
        if (b <= a) {
          cols.push(null);
          continue;
        }
        const slot = xs(b) - xs(a);
        const bw = slot >= 6 ? Math.min(24, slot - 2) : Math.max(0.6, slot * 0.8);
        const bx = xs(a) + (slot - bw) / 2;
        cols.push({ x: bx, w: bw, mid: bx + bw / 2 });
        let base = y0;
        const segs = SER.map((se) => ({ se, v: x[se.key] })).filter((p) => p.v > 0);
        segs.forEach((p, i) => {
          const hpx = (p.v / hi) * (y0 - y1);
          let yTop = base - hpx;
          const gap = i > 0 && hpx > 3 ? 2 : 0; // a 2px surface gap between stacked segments
          const bottom = base - gap;
          if (yTop > bottom - 0.5) yTop = bottom - 0.5;
          svg.append(i === segs.length - 1
            ? s('path', { class: p.se.cls, d: colPath(bx, yTop, bw, bottom, bw >= 6 ? 4 : 0) })
            : s('rect', { class: p.se.cls, x: bx.toFixed(1), y: yTop.toFixed(1), width: bw.toFixed(1), height: Math.max(0.5, bottom - yTop).toFixed(1) }));
          base = yTop;
        });
      }
      const outline = s('rect', { class: 'run-hover', visibility: 'hidden', x: 0, y: y1, width: 0, height: y0 - y1, rx: 3 });
      svg.append(outline);
      g = { x0, x1, xs, cols, outline, y1, y0 };
      if (chart) chart.replaceWith(svg); else plot.insertBefore(svg, tip);
      chart = svg;
      // The hour shown stays shown, quietly (a resize, new data), and so does the one the focus
      // chose before the plot could be drawn.
      if (idx >= 0 && (!tip.hidden || document.activeElement === plot)) showAt(idx, 'quiet');
    }

    /** showAt shows hour i: its outline and tooltip and, chosen from the keyboard (how 'key'),
     *  its figures in the live region. Shown from the pointer ('pointer') or again after a
     *  redraw ('quiet'), nothing is announced. */
    function showAt(i, how) {
      if (!g || i < 0 || i >= hours.length || !g.cols[i]) {
        hide();
        return;
      }
      idx = i;
      const x = hours[i];
      const col = g.cols[i];
      g.outline.setAttribute('x', (col.x - 2).toFixed(1));
      g.outline.setAttribute('width', (col.w + 4).toFixed(1));
      g.outline.setAttribute('visibility', 'visible');
      replace(tip,
        h('div', { class: 'tip-time' }, words(x)),
        h('div', { class: 'tip-utc' }, new Date(x.t).toISOString().slice(0, 16).replace('T', ' ') + ' UTC'),
        SER.map((se) => h('div', { class: 'tip-row' },
          s('svg', { class: 'key', viewBox: '0 0 18 10', 'aria-hidden': 'true', focusable: 'false' }, s('rect', { class: se.cls, x: 3, y: 0, width: 12, height: 10, rx: 2 })),
          h('span', { class: 'val' }, fmtInt(x[se.key])), h('span', { class: 'lab' }, se.label))));
      placeTip(tip, col.mid, W);
      if (how === 'key') live.textContent = words(x) + ': ' + SER.map((se) => se.label + ' ' + fmtInt(x[se.key])).join(', ');
    }

    function hide() {
      tip.hidden = true;
      if (g) g.outline.setAttribute('visibility', 'hidden');
    }

    function nearest(px) {
      let best = -1;
      let dist = Infinity;
      if (!g) return best;
      g.cols.forEach((col, i) => {
        if (!col) return;
        const dd = Math.abs(col.mid - px);
        if (dd < dist) {
          dist = dd;
          best = i;
        }
      });
      return best;
    }

    plot.addEventListener('pointermove', (e) => {
      if (!g || !hours.length) return;
      const x = e.clientX - plot.getBoundingClientRect().left;
      if (x < g.x0 - 10 || x > g.x1 + 10) {
        hide();
        return;
      }
      showAt(nearest(x), 'pointer');
    });
    plot.addEventListener('pointerleave', hide);
    plot.addEventListener('focus', () => {
      if (!hours.length) return;
      if (idx < 0) idx = hours.length - 1; // not drawn yet: draw shows it
      showAt(idx, 'key');
    });
    plot.addEventListener('blur', hide);
    plot.addEventListener('keydown', (e) => {
      const n = hours.length;
      if (!n) return;
      let i = idx >= 0 ? idx : n - 1;
      switch (e.key) {
        case 'ArrowLeft': i = Math.max(0, i - (e.shiftKey ? 24 : 1)); break;
        case 'ArrowRight': i = Math.min(n - 1, i + (e.shiftKey ? 24 : 1)); break;
        case 'Home': i = 0; break;
        case 'End': i = n - 1; break;
        case 'Escape': hide(); return;
        case 't': case 'T': tableBtn.click(); return;
        default: return;
      }
      e.preventDefault();
      showAt(i, 'key');
    });

    function applyView() {
      const on = app.tableViews.has(o.id);
      tableBtn.setAttribute('aria-pressed', String(on));
      plot.hidden = on;
      tableWrap.hidden = !on;
      if (on && !tableWrap.firstChild) {
        const rows = hours.slice().reverse().map((x) => [h('span', { title: 'UTC: ' + new Date(x.t).toISOString().slice(0, 16).replace('T', ' ') }, words(x)),
          fmtInt(x.in), fmtInt(x.out), fmtInt(x.local), fmtInt(x.in + x.out + x.local)]);
        tableWrap.append(chartTableView(o, [{ label: 'Hour (local)' }, { label: 'Inbound', num: true }, { label: 'Outbound', num: true },
          { label: 'Gateway itself', num: true }, { label: 'Total', num: true }], rows));
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
    ctx.cleanup(() => ro.disconnect());
    applyView();

    return {
      el: fig,
      update(d) {
        const shown = idx >= 0 && hours[idx] ? hours[idx].t : null;
        from = toMs(d.from);
        to = toMs(d.to);
        hours = netList(d.hours).map((x) => ({ t: toMs(x.t), in: Number(x.in) || 0, out: Number(x.out) || 0, local: Number(x.local) || 0 }))
          .filter((x) => x.t != null).sort((a, b) => a.t - b.t);
        idx = shown == null ? -1 : hours.findIndex((x) => x.t === shown); // -1: no longer in the period
        if (idx < 0) hide();
        const reasons = netList(d.reasons).filter((x) => Number(x.count) > 0);
        replace(summary, reasons.length ? ['By reason: ', reasons.map((x) => h('span', { class: 'badge', title: x.reason ? 'The gateway’s reason: ' + escapedText(x.reason) : null },
          netText(x.label || x.reason || '?', 72) + ' ' + fmtInt(x.count)))] : null);
        summary.hidden = !reasons.length;
        replace(tableWrap); // made again from these hours when it is shown (applyView)
        W = 0; // drawn again: now if it is shown, else once it is (applyView, the resize observer)
        applyView();
      },
    };
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
      case 'syslog_chunk': return `${fmtInt(d.messages)} message${d.messages === 1 ? '' : 's'} · ${SEAL_REASONS[d.reason] || orQ(d.reason)} · ${orQ(d.name)}`;
      case 'syslog_prune': {
        const n = Array.isArray(d.deleted) ? d.deleted.length : 0;
        return `${fmtInt(n)} chunk${n === 1 ? '' : 's'} deleted · ${orQ(d.reason)}`;
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

  /** dialog shows a modal and resolves true (confirmed) or false. It belongs to a view (o.ctx;
   *  else the view shown): when that view ends - a route change, Back closing the Overview's
   *  details it was opened from - it is cancelled, never left open over a page that no longer shows
   *  what it would change. It has its own live region for announce(): the page behind is inert. */
  function dialog(o) {
    return new Promise((resolve) => {
      const dlg = h('dialog', { class: 'dlg', 'aria-labelledby': 'dlg-title' });
      const cancel = h('button', { type: 'submit', class: 'btn', value: 'cancel', formnovalidate: true }, o.cancel || 'Cancel');
      const ok = h('button', { type: 'submit', class: 'btn btn-primary', value: 'ok' }, o.confirm || 'OK');
      const form = h('form', { method: 'dialog' },
        h('div', { class: 'dlg-body' }, h('h2', { id: 'dlg-title' }, o.title), o.body || null, o.fields || null),
        h('div', { class: 'dlg-actions' }, cancel, ok));
      dlg.append(form, announcer());
      document.body.append(dlg);
      dlg.addEventListener('close', () => {
        const confirmed = dlg.returnValue === 'ok';
        dlg.remove();
        resolve(confirmed);
      });
      const owner = o.ctx || app.view;
      if (owner && owner.alive) owner.cleanup(() => { if (dlg.open) dlg.close('cancel'); });
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
