'use strict';
/*
 * dashboard_harness.js runs the dashboard script (app.js, fetched from a running att-monitor
 * web server, i.e. exactly what is served) in a minimal fake DOM under Node.js, visits every
 * view, uses its buttons and forms, and reports what it rendered. escaping_test.go uses it to
 * check that remote-controlled text never becomes markup and that every view renders without
 * script errors.
 *
 *   node dashboard_harness.js <base URL> <scenario>        (marker in $HARNESS_MARKER)
 *
 * Scenarios: "hostile" (every remote string carries the marker) and "cert" (a changed gateway
 * certificate is waiting for confirmation; the harness looks at the Gateway page, then confirms
 * it through the dialog on the overview).
 *
 * The fake DOM has no HTML parser: assigning innerHTML/outerHTML, insertAdjacentHTML and
 * document.write are recorded as violations. After every step the whole document is checked:
 * only the element types app.js builds, no on* / style / srcdoc attributes, and URL
 * attributes that stay on this origin. Output: one JSON object on stdout.
 */

const vm = require('vm');

const [, , base, scenario] = process.argv;
const marker = process.env.HARNESS_MARKER || '<img src=x onerror=alert(1)>';
const origin = new URL(base).origin;
const violations = [];
const errors = [];
const requests = [];
const dialogs = [];
const views = {};

process.on('unhandledRejection', (e) => errors.push('unhandled rejection: ' + ((e && e.stack) || e)));
process.on('uncaughtException', (e) => errors.push('uncaught exception: ' + ((e && e.stack) || e)));

function guard(what, fn) {
  try {
    return fn();
  } catch (e) {
    errors.push(what + ': ' + ((e && e.stack) || e));
    return undefined;
  }
}

// ------------------------------------------------------------------ fake DOM

const HTMLNS = 'http://www.w3.org/1999/xhtml';
const SVGNS = 'http://www.w3.org/2000/svg';

class FakeEvent {
  constructor(type, init) {
    this.type = type;
    this.defaultPrevented = false;
    Object.assign(this, init || {});
  }
  preventDefault() { this.defaultPrevented = true; }
  stopPropagation() {}
}

class FakeNode {
  constructor(nodeType) {
    this.nodeType = nodeType;
    this.parentNode = null;
    this.childNodes = [];
    this.listeners = new Map();
  }
  get parentElement() { return this.parentNode && this.parentNode.nodeType === 1 ? this.parentNode : null; }
  get firstChild() { return this.childNodes[0] || null; }
  get lastChild() { return this.childNodes[this.childNodes.length - 1] || null; }
  get textContent() { return this.childNodes.map((n) => n.textContent).join(''); }
  set textContent(v) {
    for (const n of this.childNodes) n.parentNode = null;
    this.childNodes = [];
    const t = v == null ? '' : String(v);
    if (t !== '') this.appendChild(new FakeText(t));
  }
  appendChild(n) {
    if (!(n instanceof FakeNode)) throw new TypeError('appendChild: not a node (' + typeof n + ')');
    if (n.contains(this)) throw new Error('appendChild: would create a cycle');
    if (n.parentNode) n.parentNode.removeChild(n);
    n.parentNode = this;
    this.childNodes.push(n);
    return n;
  }
  removeChild(n) {
    const i = this.childNodes.indexOf(n);
    if (i < 0) throw new Error('removeChild: not a child');
    this.childNodes.splice(i, 1);
    n.parentNode = null;
    return n;
  }
  insertBefore(n, ref) {
    if (ref == null) return this.appendChild(n);
    if (!(n instanceof FakeNode)) throw new TypeError('insertBefore: not a node');
    if (n.parentNode) n.parentNode.removeChild(n);
    const i = this.childNodes.indexOf(ref);
    if (i < 0) throw new Error('insertBefore: the reference node is not a child');
    n.parentNode = this;
    this.childNodes.splice(i, 0, n);
    return n;
  }
  append(...nodes) { for (const n of nodes) this.appendChild(typeof n === 'string' ? new FakeText(n) : n); }
  replaceChildren(...nodes) {
    this.textContent = '';
    this.append(...nodes);
  }
  replaceWith(n) {
    const p = this.parentNode;
    if (!p) return;
    p.insertBefore(n, this);
    p.removeChild(this);
  }
  remove() { if (this.parentNode) this.parentNode.removeChild(this); }
  contains(n) {
    for (let x = n; x; x = x.parentNode) if (x === this) return true;
    return false;
  }
  addEventListener(type, fn) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(fn);
  }
  removeEventListener(type, fn) {
    const l = this.listeners.get(type);
    const i = l ? l.indexOf(fn) : -1;
    if (i >= 0) l.splice(i, 1);
  }
  dispatchEvent(ev) {
    if (!ev.target) ev.target = this;
    ev.currentTarget = this;
    for (const fn of (this.listeners.get(ev.type) || []).slice()) guard('listener for ' + ev.type, () => fn.call(this, ev));
    return !ev.defaultPrevented;
  }
}

class FakeText extends FakeNode {
  constructor(data) {
    super(3);
    this.data = String(data);
  }
  get textContent() { return this.data; }
  set textContent(v) { this.data = String(v); }
}

class FakeElement extends FakeNode {
  constructor(tag, ns) {
    super(1);
    this.namespaceURI = ns || HTMLNS;
    this.localName = this.namespaceURI === SVGNS ? String(tag) : String(tag).toLowerCase();
    this.tagName = this.namespaceURI === SVGNS ? String(tag) : String(tag).toUpperCase();
    this.attrs = new Map();
    this.dataset = {};
    this.style = {};
    this.value = '';
    this.checked = false;
    this.returnValue = '';
    const el = this;
    this.classList = {
      add(...c) { el.className = [...new Set(el.className.split(/\s+/).filter(Boolean).concat(c))].join(' '); },
      remove(...c) { el.className = el.className.split(/\s+/).filter((x) => x && !c.includes(x)).join(' '); },
      contains(c) { return el.className.split(/\s+/).includes(c); },
    };
  }
  setAttribute(name, value) { this.attrs.set(String(name).toLowerCase(), String(value)); }
  getAttribute(name) {
    const v = this.attrs.get(String(name).toLowerCase());
    return v === undefined ? null : v;
  }
  hasAttribute(name) { return this.attrs.has(String(name).toLowerCase()); }
  removeAttribute(name) { this.attrs.delete(String(name).toLowerCase()); }
  get id() { return this.getAttribute('id') || ''; }
  set id(v) { this.setAttribute('id', v); }
  get className() { return this.getAttribute('class') || ''; }
  set className(v) { this.setAttribute('class', v); }
  get title() { return this.getAttribute('title') || ''; }
  set title(v) { this.setAttribute('title', v); }
  get content() { return this.getAttribute('content') || ''; }
  get innerHTML() { return ''; }
  set innerHTML(v) { violations.push('innerHTML assigned on <' + this.localName + '>: ' + String(v).slice(0, 120)); }
  get outerHTML() { return ''; }
  set outerHTML(v) { violations.push('outerHTML assigned on <' + this.localName + '>: ' + String(v).slice(0, 120)); }
  insertAdjacentHTML(pos, v) { violations.push('insertAdjacentHTML on <' + this.localName + '>: ' + String(v).slice(0, 120)); }
  get clientWidth() { return 800; }
  get clientHeight() { return 240; }
  get offsetWidth() { return 160; }
  get offsetHeight() { return 40; }
  getBoundingClientRect() { return { left: 0, top: 0, right: 800, bottom: 240, width: 800, height: 240, x: 0, y: 0 }; }
  focus() { this.dispatchEvent(new FakeEvent('focus')); }
  blur() { this.dispatchEvent(new FakeEvent('blur')); }
  click() { this.dispatchEvent(new FakeEvent('click')); }
  scrollIntoView() {}
  showModal() { this.open = true; }
  close(rv) {
    if (rv !== undefined) this.returnValue = rv;
    this.open = false;
    this.dispatchEvent(new FakeEvent('close'));
  }
  matches(sel) { return matches(this, sel); }
  closest(sel) {
    for (let e = this; e; e = e.parentElement) if (matches(e, sel)) return e;
    return null;
  }
  querySelectorAll(sel) {
    const out = [];
    walkElements(this, (e) => { if (e !== this && matches(e, sel)) out.push(e); });
    return out;
  }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
}

// Boolean properties that reflect attributes, as in a browser (e.g. button.disabled).
for (const p of ['hidden', 'disabled', 'open', 'required']) {
  Object.defineProperty(FakeElement.prototype, p, {
    get() { return this.hasAttribute(p); },
    set(v) { if (v) this.setAttribute(p, ''); else this.removeAttribute(p); },
  });
}

class FakeDocument extends FakeNode {
  constructor() {
    super(9);
    this.title = '';
    this.hidden = false;
    this.readyState = 'complete';
    this.documentElement = new FakeElement('html');
    this.appendChild(this.documentElement);
    this.head = new FakeElement('head');
    this.body = new FakeElement('body');
    this.documentElement.append(this.head, this.body);
  }
  createElement(tag) { return new FakeElement(tag, HTMLNS); }
  createElementNS(ns, tag) { return new FakeElement(tag, ns); }
  createTextNode(t) { return new FakeText(t); }
  getElementById(id) {
    let found = null;
    walkElements(this, (e) => { if (!found && e.id === id) found = e; });
    return found;
  }
  querySelectorAll(sel) {
    const out = [];
    walkElements(this, (e) => { if (matches(e, sel)) out.push(e); });
    return out;
  }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
  write(v) { violations.push('document.write: ' + String(v).slice(0, 120)); }
  writeln(v) { violations.push('document.writeln: ' + String(v).slice(0, 120)); }
}

function walkElements(root, fn) {
  const stack = [root];
  while (stack.length) {
    const n = stack.pop();
    if (n.nodeType === 1) fn(n);
    for (let i = n.childNodes.length - 1; i >= 0; i--) stack.push(n.childNodes[i]);
  }
}

function walkText(root, fn) {
  const stack = [root];
  while (stack.length) {
    const n = stack.pop();
    if (n.nodeType === 3) fn(n);
    for (let i = n.childNodes.length - 1; i >= 0; i--) stack.push(n.childNodes[i]);
  }
}

// A small selector engine: tag, #id, .class, [attr], [attr="value"], descendant and child
// combinators, comma lists — what app.js and this harness use.
const selectorCache = new Map();

function parseCompound(t) {
  const c = { tag: null, id: null, classes: [], attrs: [] };
  const re = /([a-zA-Z][\w-]*)|#([\w-]+)|\.([\w-]+)|\[\s*([\w:-]+)\s*(?:=\s*(?:"([^"]*)"|'([^']*)'|([^\]\s]*)))?\s*\]/g;
  let pos = 0;
  let m;
  while ((m = re.exec(t))) {
    if (m.index !== pos) throw new Error('unsupported selector: ' + t);
    pos = re.lastIndex;
    if (m[1] !== undefined) c.tag = m[1].toLowerCase();
    else if (m[2] !== undefined) c.id = m[2];
    else if (m[3] !== undefined) c.classes.push(m[3]);
    else c.attrs.push([m[4].toLowerCase(), m[5] !== undefined ? m[5] : m[6] !== undefined ? m[6] : m[7]]);
  }
  if (pos !== t.length) throw new Error('unsupported selector: ' + t);
  return c;
}

function parseSelector(sel) {
  let groups = selectorCache.get(sel);
  if (groups) return groups;
  groups = String(sel).split(',').map((part) => {
    const steps = [];
    let comb = ' ';
    for (const tok of part.trim().replace(/\s*>\s*/g, ' > ').split(/\s+/).filter(Boolean)) {
      if (tok === '>') {
        comb = '>';
        continue;
      }
      steps.push({ comb, c: parseCompound(tok) });
      comb = ' ';
    }
    return steps;
  });
  selectorCache.set(sel, groups);
  return groups;
}

function matchCompound(el, c) {
  if (c.tag && el.localName.toLowerCase() !== c.tag) return false;
  if (c.id && el.id !== c.id) return false;
  if (c.classes.length) {
    const cls = el.className.split(/\s+/);
    if (!c.classes.every((x) => cls.includes(x))) return false;
  }
  for (const [name, value] of c.attrs) {
    if (!el.hasAttribute(name)) return false;
    if (value !== undefined && el.getAttribute(name) !== value) return false;
  }
  return true;
}

function matchSteps(el, steps, i) {
  if (!matchCompound(el, steps[i].c)) return false;
  if (i === 0) return true;
  if (steps[i].comb === '>') {
    const p = el.parentElement;
    return !!p && matchSteps(p, steps, i - 1);
  }
  for (let p = el.parentElement; p; p = p.parentElement) if (matchSteps(p, steps, i - 1)) return true;
  return false;
}

function matches(el, sel) {
  return parseSelector(sel).some((steps) => steps.length > 0 && matchSteps(el, steps, steps.length - 1));
}

// ------------------------------------------------------------------ the page around app.js

const document = new FakeDocument();

function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
  e.append(...kids);
  return e;
}

document.head.append(el('meta', { name: 'att-monitor-version', content: 'harness' }));
const navItems = ['overview', 'incidents', 'gateway', 'evidence', 'records'].map((r) => {
  const a = el('a', { href: r === 'overview' ? '#/' : '#/' + r }, r);
  a.dataset.route = r;
  return el('li', null, a);
});
document.body.append(
  el('a', { id: 'skip-link', class: 'skip-link', href: '#main' }, 'Skip to main content'),
  el('header', { class: 'topbar' }, el('div', { class: 'topbar-inner' },
    el('a', { id: 'pill', class: 'pill', href: '#/' }, el('span', { class: 'pill-text' }, 'Connecting…')),
    el('nav', { class: 'nav' }, el('ul', null, ...navItems)))),
  el('div', { id: 'conn', class: 'conn-banner', hidden: '' }),
  el('main', { id: 'main' }, el('div', { id: 'view' })),
  el('footer', { class: 'footer' }, el('p', null, el('span', { id: 'foot-version' }), el('span', { id: 'foot-updated' }))),
  el('div', { id: 'live', class: 'sr-only' }));

// ------------------------------------------------------------------ window

const windowEvents = new FakeNode(0);
const location = { hash: '' };
const intervals = [];
const storage = new Map();
let inflight = 0;

async function pageFetch(path, init) {
  inflight++;
  try {
    const url = new URL(String(path), base);
    if (url.origin !== origin) {
      violations.push('request to another origin: ' + url.href);
      throw new TypeError('blocked by the harness');
    }
    const o = init || {};
    const method = o.method || 'GET';
    const headers = Object.assign({}, o.headers || {});
    if (method !== 'GET' && method !== 'HEAD') headers.Origin = origin; // what a browser sends with a POST
    const res = await fetch(url, { method, headers, body: o.body });
    const text = await res.text();
    requests.push({ method, path: url.pathname + url.search, status: res.status });
    return { ok: res.ok, status: res.status, headers: res.headers, text: async () => text };
  } finally {
    inflight--;
  }
}

const context = {
  document,
  location,
  history: { replaceState(state, title, url) { if (typeof url === 'string' && url.startsWith('#')) location.hash = url; } },
  localStorage: {
    getItem: (k) => (storage.has(k) ? storage.get(k) : null),
    setItem: (k, v) => { storage.set(k, String(v)); },
    removeItem: (k) => { storage.delete(k); },
  },
  setTimeout: (fn, ms) => setTimeout(() => guard('timer', fn), ms),
  clearTimeout: (id) => clearTimeout(id),
  setInterval: (fn) => intervals.push(fn), // never fires by itself: the harness drives the page
  clearInterval: (id) => { if (id > 0) intervals[id - 1] = null; },
  scrollTo() {},
  addEventListener: (t, fn) => windowEvents.addEventListener(t, fn),
  removeEventListener: (t, fn) => windowEvents.removeEventListener(t, fn),
  fetch: pageFetch,
  ResizeObserver: class { observe() {} unobserve() {} disconnect() {} },
  Node: FakeNode,
  URL,
  URLSearchParams,
  console: {
    log() {}, info() {}, debug() {},
    warn: (...a) => errors.push('console.warn: ' + a.join(' ')),
    error: (...a) => errors.push('console.error: ' + a.join(' ')),
  },
};
context.window = context;
vm.createContext(context);

// ------------------------------------------------------------------ checks

const ALLOWED_TAGS = new Set([
  'html', 'head', 'body', 'meta', 'header', 'nav', 'main', 'footer',
  'a', 'button', 'caption', 'code', 'datalist', 'dd', 'details', 'dialog', 'div', 'dl', 'dt', 'figcaption',
  'figure', 'form', 'h1', 'h2', 'h3', 'h4', 'input', 'label', 'li', 'ol', 'option', 'p', 'pre', 'section',
  'select', 'span', 'strong', 'summary', 'table', 'tbody', 'td', 'textarea', 'th', 'thead', 'time', 'tr', 'ul',
  'svg', 'g', 'path', 'circle', 'line', 'rect', 'text',
]);
const URL_ATTRS = new Set(['href', 'src', 'action', 'formaction', 'xlink:href', 'srcset', 'poster', 'ping', 'background', 'cite', 'data', 'codebase', 'manifest']);
const JS_ERROR = /TypeError|ReferenceError|SyntaxError|RangeError|is not a function|is not defined|is not iterable|Cannot read prop|Cannot set prop|undefined is not|null is not/;

function checkDocument(where) {
  walkElements(document, (e) => {
    if (!ALLOWED_TAGS.has(e.localName.toLowerCase()) || (e.localName === 'meta' && e.parentElement !== document.head)) {
      violations.push(where + ': unexpected <' + e.localName + '> element');
    }
    for (const [name, value] of e.attrs) {
      if (name.startsWith('on')) violations.push(where + ': event-handler attribute ' + name + '="' + value.slice(0, 80) + '"');
      if (name === 'style' || name === 'srcdoc') violations.push(where + ': ' + name + ' attribute');
      if (URL_ATTRS.has(name) && (!/^(#|\/(?![/\\]))/.test(value) || /[\u0000-\u001f\u007f<>"'`]/.test(value) || /javascript:/i.test(value))) {
        violations.push(where + ': unsafe ' + name + '="' + value.slice(0, 120) + '" on <' + e.localName + '>');
      }
    }
    if (e.className.split(/\s+/).includes('notice') && JS_ERROR.test(e.textContent)) {
      errors.push(where + ': script error shown: ' + e.textContent.slice(0, 300));
    }
  });
}

function view() { return document.getElementById('view'); }

/** chipOf describes a status chip as "<tone>:<label>" (e.g. "critical:NXDOMAIN"). */
function chipOf(c) {
  const m = /(?:^|\s)tone-([\w-]+)/.exec(c.className);
  return (m ? m[1] : '') + ':' + c.textContent.trim();
}

function capture(name) {
  checkDocument(name);
  let markers = 0;
  walkText(view(), (t) => { if (t.data.includes(marker)) markers++; });
  const hero = view().querySelector('.hero');
  views[name] = {
    text: view().textContent,
    // The status as the page chrome shows it (the pill in the top bar, the window title) and
    // the status hero, so that a test can tell what is claimed about the present.
    pill: document.getElementById('pill').textContent,
    title: document.title,
    hero: hero ? hero.textContent : '',
    markers,
    buttons: view().querySelectorAll('button').map((b) => ({ text: b.textContent.trim(), disabled: b.disabled })),
    // Every table row with the status chips it shows, so that a test can tell a red chip
    // from a green one (the text alone cannot).
    rows: view().querySelectorAll('tr').map((tr) => ({ text: tr.textContent, chips: tr.querySelectorAll('.chip').map(chipOf) })),
  };
}

// ------------------------------------------------------------------ driving the page

const tick = (ms) => new Promise((r) => setTimeout(r, ms));

/** settle waits until no request has been in flight for a while (the demo world's slow
 *  operations take up to 1.5 s). */
async function settle() {
  let quiet = 0;
  for (let i = 0; i < 800 && quiet < 5; i++) {
    await tick(10);
    quiet = inflight === 0 ? quiet + 1 : 0;
  }
}

async function visit(hash) {
  location.hash = hash;
  windowEvents.dispatchEvent(new FakeEvent('hashchange'));
  await settle();
}

function button(text) { return document.querySelectorAll('button').find((b) => b.textContent.trim() === text) || null; }

async function press(text) {
  const b = button(text);
  if (!b) {
    errors.push('no button "' + text + '"');
    return false;
  }
  if (b.disabled) {
    errors.push('button "' + text + '" is disabled');
    return false;
  }
  b.click();
  await settle();
  return true;
}

/** answerDialog records the open dialog's text and closes it with OK or Cancel. */
async function answerDialog(ok, fill) {
  const dlg = document.querySelector('dialog');
  if (!dlg) {
    errors.push('no dialog is open');
    return;
  }
  if (fill) fill(dlg);
  dialogs.push(dlg.textContent);
  checkDocument('dialog');
  dlg.close(ok ? 'ok' : 'cancel');
  await settle();
}

async function openAllDetails() {
  for (const d of view().querySelectorAll('details')) {
    if (!d.open) {
      d.open = true;
      d.dispatchEvent(new FakeEvent('toggle'));
    }
  }
  await settle();
}

function exerciseCharts() {
  for (const p of view().querySelectorAll('.plot')) {
    p.focus();
    for (const key of ['ArrowLeft', 'Home', 'End']) p.dispatchEvent(new FakeEvent('keydown', { key, shiftKey: false }));
    p.blur();
  }
  for (const b of view().querySelectorAll('figure button')) if (b.textContent === 'Table') b.click();
}

async function submit(form) {
  form.dispatchEvent(new FakeEvent('submit'));
  await settle();
}

async function incidents() {
  const res = await fetch(new URL('/api/incidents', base));
  return res.json();
}

async function run() {
  const res = await fetch(new URL('/static/app.js', base));
  const code = await res.text();
  guard('app.js', () => vm.runInContext(code, context, { filename: 'app.js' }));
  await settle();

  await visit('#/');
  exerciseCharts();
  await settle();
  capture('overview');

  if (scenario === 'cert') {
    await visit('#/gateway');
    capture('gateway before trust');
    await visit('#/');
    if (await press('Trust the new certificate')) await answerDialog(true);
    await settle();
    capture('overview after trust');
  }

  await visit('#/incidents');
  capture('incidents');
  for (const inc of await incidents()) {
    await visit('#/incidents/' + encodeURIComponent(inc.id));
    capture('incident ' + inc.cause);
  }
  if (scenario === 'hostile') {
    const first = (await incidents())[0];
    await visit('#/incidents/' + encodeURIComponent(first.id));
    if (await press('Export this incident as an evidence bundle')) {
      await answerDialog(true, (dlg) => {
        for (const f of dlg.querySelectorAll('input, textarea')) f.value = 'prepared ' + marker;
      });
    }
    capture('incident export');
  }

  await visit('#/gateway');
  await openAllDetails();
  capture('gateway');

  await visit('#/evidence');
  await press('Verify the whole ledger now');
  await openAllDetails();
  await press('Time-stamp the ledger head now');
  const note = view().querySelector('textarea');
  if (note) {
    note.value = 'Note with ' + marker;
    await submit(note.closest('form'));
  }
  capture('evidence');

  await visit('#/records');
  await openAllDetails();
  capture('records');
  await visit('#/records?from_seq=0&limit=100');
  await openAllDetails();
  capture('records from genesis');
  await visit('#/records?type=config_state');
  await openAllDetails();
  capture('records config_state');
}

run()
  .catch((e) => errors.push('harness: ' + ((e && e.stack) || e)))
  .finally(() => {
    process.stdout.write(JSON.stringify({ views, dialogs, violations, errors, requests }) + '\n');
    process.exit(0);
  });
