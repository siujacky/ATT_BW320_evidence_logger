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
 * Scenarios: "hostile" (every remote string carries the marker), "cert" (a changed gateway
 * certificate is waiting for confirmation; the harness looks at the Gateway page, then confirms
 * it through the dialog on the overview), "overview" (the overview, every card's details, and
 * the Syslog page only), "syslog" (the flow meter's polling while the overview is shown, hidden
 * and left, then the Syslog page's retention form), "gwsyslog" (the control of the gateway's
 * Syslog setting on the Syslog page and in the overview's syslog details), "gwsyslogon" /
 * "gwsyslogoff" (one change of that setting on the Syslog page), "network" (the Network page
 * only, used as networkSteps does), "networktabs" (its two tabs as they first show), "details"
 * (each card's details opened and closed every way, a status update while they are open, an
 * AT&T outage: detailsScenario; the server must offer /demo/state), "deeplink" (the page
 * loaded with the address of a card's details, $HARNESS_HASH: deepLinkScenario), "deepfail" (the
 * same while the status cannot be read), "summary" (the summary and the details of the cards
 * $HARNESS_DETAILS names: summaryScenario), "keep" (a reader who stays on something while the page
 * updates: keepScenario; /demo/state), "statusfail" (the details while the status cannot be read:
 * statusFailScenario; /demo/statusfail) and "confirmback" (Back while a confirmation is open over
 * the details: confirmBackScenario); any other name visits every view, every card's details and
 * the Network page included.
 *
 * The page's clock can be moved on (skipTime: what the page does a minute later), and a text
 * selection made (selectText), as a reader does before copying it.
 *
 * Timers of a second or more (the flow meter's polling) do not run by themselves: the harness
 * fires them (fireLongTimers), so that a test sees exactly which requests a poll makes.
 *
 * The session history is kept as a browser keeps it (see "history" below): a visit adds an
 * entry, pushState adds one, replaceState replaces the current one, back() goes to the one
 * before, later, with popstate and hashchange events.
 *
 * The keyboard focus is kept as a browser keeps it (document.activeElement; see "focus" below):
 * the harness presses a button as a keyboard user does, with the focus on it, and every view
 * says where the focus is, so that a test can tell when a control sends it back to the start of
 * the page.
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
const facts = {}; // what a scenario's steps observed beyond the views (e.g. timelineSteps)

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

/** taken calls the onTaken hook of a node taken from its parent (removed, moved, or its
 *  parent's content replaced): a scenario sets it on a node that must stay where it is. */
function taken(n) {
  if (typeof n.onTaken === 'function') n.onTaken();
}

const HTMLNS = 'http://www.w3.org/1999/xhtml';
const SVGNS = 'http://www.w3.org/2000/svg';

// ------------------------------------------------------------------ focus

// focused is the element with the keyboard focus (null: the body, the start of the page).
let focused = null;

// modals are the dialogs open as modal dialogs (showModal), the topmost last.
const modals = [];

// The elements that take the focus without a tabindex, and those of them a disabled attribute
// takes it from.
const FOCUSABLE = new Set(['button', 'input', 'select', 'textarea', 'summary']);
const DISABLEABLE = new Set(['button', 'input', 'select', 'textarea']);

/** rendered reports whether e is shown: in the document, and neither inside a hidden element
 *  nor inside a closed dialog. */
function rendered(e) {
  if (!document.contains(e)) return false;
  for (let x = e; x; x = x.parentElement) {
    if (x.hasAttribute('hidden') || (x.localName === 'dialog' && !x.hasAttribute('open'))) return false;
  }
  return true;
}

/** canFocus reports whether e can have the keyboard focus, as a browser decides it. */
function canFocus(e) {
  if (!(e instanceof FakeElement) || !rendered(e)) return false;
  if (DISABLEABLE.has(e.localName) && e.hasAttribute('disabled')) return false;
  return FOCUSABLE.has(e.localName) || (e.localName === 'a' && e.hasAttribute('href')) || e.hasAttribute('tabindex');
}

/** fixFocus is a browser's focus fixup rule: the element with the focus loses it to the body when
 *  it is disabled, hidden or taken out of the document (moving a node takes it out). It runs
 *  after every change of an attribute or of the tree, which is stricter than a browser (that
 *  runs it at its next style or rendering update) only for a change undone within one task; a
 *  control that waits for an answer from the network meets that update first. */
function fixFocus() {
  if (focused && !canFocus(focused)) focused = null;
}

class FakeEvent {
  constructor(type, init) {
    this.type = type;
    this.defaultPrevented = false;
    this.propagationStopped = false;
    this.immediateStopped = false;
    Object.assign(this, init || {});
  }
  preventDefault() { this.defaultPrevented = true; }
  stopPropagation() { this.propagationStopped = true; }
  stopImmediatePropagation() {
    this.propagationStopped = true;
    this.immediateStopped = true;
  }
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
    for (const n of this.childNodes) {
      n.parentNode = null;
      taken(n);
    }
    this.childNodes = [];
    fixFocus();
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
    taken(n);
    fixFocus();
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
  // addEventListener keeps whether a listener captures (true, or {capture: true}).
  addEventListener(type, fn, opts) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push({ fn, capture: opts === true || !!(opts && opts.capture) });
  }
  removeEventListener(type, fn, opts) {
    const capture = opts === true || !!(opts && opts.capture);
    const l = this.listeners.get(type);
    const i = l ? l.findIndex((x) => x.fn === fn && x.capture === capture) : -1;
    if (i >= 0) l.splice(i, 1);
  }
  // dispatchEvent dispatches as a browser does: the capture listeners of the nodes around this
  // one (from the root in), then this node's (its capture listeners first), then, for an event
  // that bubbles (init {bubbles: true}), the others of the nodes around it (outwards).
  // stopPropagation ends it after the node it is at, stopImmediatePropagation at once.
  dispatchEvent(ev) {
    if (!ev.target) ev.target = this;
    const path = [];
    for (let x = this.parentNode; x; x = x.parentNode) path.unshift(x);
    const run = (node, capture) => {
      if (ev.propagationStopped && ev.currentTarget !== node) return;
      ev.currentTarget = node;
      for (const l of (node.listeners.get(ev.type) || []).slice()) {
        if (ev.immediateStopped) return;
        if (l.capture !== capture) continue;
        guard('listener for ' + ev.type, () => l.fn.call(node, ev));
      }
    };
    for (const n of path) run(n, true);
    run(this, true);
    run(this, false);
    if (ev.bubbles) for (const n of path.slice().reverse()) run(n, false);
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
  setAttribute(name, value) {
    this.attrs.set(String(name).toLowerCase(), String(value));
    fixFocus();
  }
  getAttribute(name) {
    const v = this.attrs.get(String(name).toLowerCase());
    return v === undefined ? null : v;
  }
  hasAttribute(name) { return this.attrs.has(String(name).toLowerCase()); }
  removeAttribute(name) {
    this.attrs.delete(String(name).toLowerCase());
    fixFocus();
  }
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
  // focus moves the keyboard focus here when this element can take it (canFocus); a browser
  // leaves it where it is otherwise. The focus and blur events are dispatched as before, either
  // way: the charts' keyboard handling is exercised through them.
  focus() {
    if (canFocus(this)) focused = this;
    this.dispatchEvent(new FakeEvent('focus'));
  }
  blur() {
    if (focused === this) focused = null;
    this.dispatchEvent(new FakeEvent('blur'));
  }
  click() { this.dispatchEvent(new FakeEvent('click')); }
  scrollIntoView() {}
  showModal() {
    if (!document.contains(this)) throw new Error('showModal: the dialog is not in the document (InvalidStateError)');
    if (this.open) throw new Error('showModal: the dialog is open already (InvalidStateError)');
    this.previouslyFocused = focused;
    this.open = true;
    modals.push(this);
  }
  // close closes a dialog as a browser does: the element that had the focus when the modal
  // dialog opened (the button that opened it) gets it back, then the close event. A closed
  // dialog does nothing.
  close(rv) {
    if (!this.open) return;
    if (rv !== undefined) this.returnValue = rv;
    this.open = false;
    const i = modals.indexOf(this);
    if (i >= 0) modals.splice(i, 1);
    const prev = this.previouslyFocused;
    this.previouslyFocused = null;
    if (prev && canFocus(prev)) prev.focus();
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

// checked: checking a radio button unchecks the other radio buttons of its group (the same name,
// in the same tree), as in a browser, so that a test sees which one a period control claims.
Object.defineProperty(FakeElement.prototype, 'checked', {
  get() { return !!this.isChecked; },
  set(v) {
    this.isChecked = !!v;
    if (!v || this.localName !== 'input' || this.getAttribute('type') !== 'radio' || !this.getAttribute('name')) return;
    const name = this.getAttribute('name');
    let root = this;
    while (root.parentNode) root = root.parentNode;
    walkElements(root, (e) => {
      if (e !== this && e.localName === 'input' && e.getAttribute('type') === 'radio' && e.getAttribute('name') === name) e.isChecked = false;
    });
  },
});

class FakeDocument extends FakeNode {
  constructor() {
    super(9);
    this.title = '';
    this.hidden = false;
    this.visibilityState = 'visible';
    this.readyState = 'complete';
    this.documentElement = new FakeElement('html');
    this.appendChild(this.documentElement);
    this.head = new FakeElement('head');
    this.body = new FakeElement('body');
    this.documentElement.append(this.head, this.body);
  }
  get activeElement() {
    fixFocus();
    return focused || this.body;
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
const navItems = ['overview', 'incidents', 'gateway', 'syslog', 'network', 'evidence', 'records'].map((r) => {
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
// The page opens at $HARNESS_HASH (a card's details, deepLinkScenario), else at no hash at all.
const location = { hash: process.env.HARNESS_HASH || '' };

// history is the session history as a browser keeps it: its entries (their hashes) and the
// current one. A visit (a link, the address bar) and pushState add an entry after the current
// one, dropping those after it; replaceState replaces the current one; neither fires an event.
// back() goes to the entry before, later (as a browser traverses the history), firing popstate
// and, as the hash changes, hashchange.
const hist = { entries: [location.hash], index: 0 };

function addEntry(hash) {
  hist.entries.splice(hist.index + 1);
  hist.entries.push(hash);
  hist.index = hist.entries.length - 1;
  location.hash = hash;
}

function traverse(delta) {
  setTimeout(() => {
    const i = hist.index + delta;
    if (!delta || i < 0 || i >= hist.entries.length) return;
    const old = location.hash;
    hist.index = i;
    location.hash = hist.entries[i];
    windowEvents.dispatchEvent(new FakeEvent('popstate'));
    if (location.hash !== old) windowEvents.dispatchEvent(new FakeEvent('hashchange'));
  }, 0);
}

const intervals = [];
const longTimers = new Map(); // id -> function, for timers of a second or more
let longTimerID = 0;
const storage = new Map();
let inflight = 0;

// The page's clock (its Date) is the real one moved on by clock.skew ms: a scenario sees what the
// page does a minute later (skipTime) without waiting a minute. The server's clock is not moved.
const clock = { skew: 0 };
const RealDate = Date;
class PageDate extends RealDate {
  constructor(...a) {
    if (a.length) super(...a);
    else super(RealDate.now() + clock.skew);
  }
  static now() { return RealDate.now() + clock.skew; }
}

function skipTime(ms) { clock.skew += ms; }

// selection is the page's text selection (window.getSelection): none, until a scenario selects
// text in a node (selectText) as a reader does before copying it.
const selection = { isCollapsed: true, anchorNode: null, focusNode: null, toString() { return this.anchorNode ? this.anchorNode.textContent : ''; } };

function selectText(node) {
  Object.assign(selection, { isCollapsed: !node, anchorNode: node || null, focusNode: node || null });
}

/** fireLongTimers runs the pending timers of a second or more (each once). */
function fireLongTimers() {
  const due = [...longTimers.values()];
  longTimers.clear();
  for (const fn of due) guard('timer', fn);
}

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
  history: {
    get length() { return hist.entries.length; },
    pushState(state, title, url) { if (typeof url === 'string' && url.startsWith('#')) addEntry(url); },
    replaceState(state, title, url) {
      if (typeof url !== 'string' || !url.startsWith('#')) return;
      hist.entries[hist.index] = url;
      location.hash = url;
    },
    back() { traverse(-1); },
    forward() { traverse(1); },
    go(n) { traverse(Number(n) || 0); },
  },
  localStorage: {
    getItem: (k) => (storage.has(k) ? storage.get(k) : null),
    setItem: (k, v) => { storage.set(k, String(v)); },
    removeItem: (k) => { storage.delete(k); },
  },
  setTimeout: (fn, ms) => {
    if (ms >= 1000) {
      longTimers.set(++longTimerID, fn);
      return 'long-' + longTimerID;
    }
    return setTimeout(() => guard('timer', fn), ms);
  },
  clearTimeout: (id) => {
    if (typeof id === 'string' && id.startsWith('long-')) longTimers.delete(Number(id.slice(5)));
    else clearTimeout(id);
  },
  setInterval: (fn) => intervals.push(fn), // never fires by itself: the harness drives the page
  clearInterval: (id) => { if (id > 0) intervals[id - 1] = null; },
  requestAnimationFrame: (fn) => setTimeout(() => guard('animation frame', () => fn(Date.now())), 16),
  getSelection: () => selection,
  scrollTo() {},
  addEventListener: (t, fn) => windowEvents.addEventListener(t, fn),
  removeEventListener: (t, fn) => windowEvents.removeEventListener(t, fn),
  fetch: pageFetch,
  ResizeObserver: class { observe() {} unobserve() {} disconnect() {} },
  Date: PageDate,
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
  'a', 'article', 'button', 'caption', 'code', 'datalist', 'dd', 'details', 'dialog', 'div', 'dl', 'dt', 'figcaption',
  'figure', 'form', 'h1', 'h2', 'h3', 'h4', 'input', 'label', 'li', 'ol', 'option', 'p', 'pre', 'section',
  'select', 'span', 'strong', 'summary', 'table', 'tbody', 'td', 'textarea', 'th', 'thead', 'time', 'tr', 'ul',
  'svg', 'g', 'path', 'circle', 'line', 'rect', 'text', 'tspan',
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

/** shownEl reports whether neither e nor an element around it is hidden. */
function shownEl(e) {
  for (let x = e; x; x = x.parentElement) if (x.hasAttribute('hidden')) return false;
  return true;
}

/** focusOf describes the element with the keyboard focus: "body" (the start of the page),
 *  "input:<type> <value>" for a radio button or a checkbox, or "<tag>:<its text>". */
function focusOf() {
  const e = document.activeElement;
  if (e === document.body) return 'body';
  const type = e.localName === 'input' ? e.getAttribute('type') || 'text' : '';
  if (type === 'radio' || type === 'checkbox') return 'input:' + type + ' ' + (e.getAttribute('value') || '');
  return e.localName + ':' + e.textContent.trim().slice(0, 300);
}

/** chipOf describes a status chip as "<tone>:<label>" (e.g. "critical:NXDOMAIN"). */
function chipOf(c) {
  const m = /(?:^|\s)tone-([\w-]+)/.exec(c.className);
  return (m ? m[1] : '') + ':' + c.textContent.trim();
}

/** markersIn counts the text nodes of root that show the hostile marker. */
function markersIn(root) {
  let n = 0;
  walkText(root, (t) => { if (t.data.includes(marker)) n++; });
  return n;
}

/** detailOf describes the Overview's details modal in the view, if there is one: which card's,
 *  whether it is open, its heading, its line of context, its text and the markers in it. */
function detailOf() {
  const dlg = view().querySelector('dialog.dlg-detail');
  if (!dlg) return null;
  const title = dlg.querySelector('h2');
  const context = dlg.querySelector('.detail-context');
  const body = dlg.querySelector('.detail-body');
  const stale = dlg.querySelector('.detail-stale');
  return {
    key: dlg.getAttribute('data-detail') || '', open: dlg.hasAttribute('open'), title: title ? title.textContent : '',
    context: context ? context.textContent : '', text: dlg.textContent, markers: markersIn(dlg),
    // The body as a keyboard user meets it (a Tab stop, a named region), and the parts it shows,
    // in their order ("<tag>.<class>" of each child not hidden).
    body: body ? { tabindex: body.getAttribute('tabindex'), role: body.getAttribute('role'), labelledby: body.getAttribute('aria-labelledby') } : null,
    parts: body ? body.childNodes.filter((n) => n.nodeType === 1 && !n.hasAttribute('hidden')).map((n) => n.localName + '.' + n.className) : [],
    // The note that the status cannot be read (its text and role), when there is one.
    stale: stale ? { text: stale.textContent, role: stale.getAttribute('role') || '' } : null,
  };
}

/** cardsOf describes the Overview's summary cards, in their order: the card whose details each
 *  opens, its title, its status chip ("<tone>:<label>"), its tone, its text, the markers in it
 *  and its sparklines (each hidden from screen readers, with a sentence that says what it shows). */
function cardsOf() {
  return view().querySelectorAll('article.sum-card').map((c) => {
    const btn = c.querySelector('button.sum-open');
    const ch = c.querySelector('.sum-chip .chip');
    const tone = /(?:^|\s)tone-([\w-]+)/.exec(c.className);
    const desc = btn && btn.getAttribute('aria-describedby') ? document.getElementById(btn.getAttribute('aria-describedby')) : null;
    return {
      key: btn ? btn.getAttribute('data-detail') || '' : '', title: btn ? btn.textContent : '', chip: ch ? chipOf(ch) : '',
      tone: tone ? tone[1] : '', text: c.textContent, markers: markersIn(c),
      // What a screen reader says after the button's name, on Tab (its aria-describedby).
      described: desc ? desc.textContent.trim() : '',
      // The tooltips in it (none can show under the card's button).
      titles: c.querySelectorAll('[title]').length,
      sparks: c.querySelectorAll('svg.spark').filter((sv) => sv.getAttribute('aria-hidden') === 'true').length,
      // Every control of the card: its title's button, and nothing else (docs/overview-redesign.md §4).
      controls: c.querySelectorAll('a, button, input, select, textarea, summary, [tabindex]').length,
    };
  });
}

function capture(name) {
  checkDocument(name);
  // The status card's left part: the state now (its right part is the last 24 hours).
  const hero = view().querySelector('.status-main');
  const strip = view().querySelector('.status-strip');
  const statusBtn = view().querySelector('button.status-open');
  const statusDesc = statusBtn && statusBtn.getAttribute('aria-describedby') ? document.getElementById(statusBtn.getAttribute('aria-describedby')) : null;
  const statusEl = view().querySelector('.status-card');
  views[name] = {
    text: view().textContent,
    // The status as the page chrome shows it (the pill in the top bar, the window title) and
    // the status card, so that a test can tell what is claimed about the present.
    pill: document.getElementById('pill').textContent,
    title: document.title,
    hero: hero ? hero.textContent : '',
    strip: strip ? strip.textContent : '',
    // What a screen reader says after the status card's button (its aria-describedby), and the
    // tooltips in the card (none can show under its button).
    statusDescribed: statusDesc ? statusDesc.textContent.trim() : '',
    statusTitles: statusEl ? statusEl.querySelectorAll('[title]').length : 0,
    markers: markersIn(view()),
    detail: detailOf(),
    cards: cardsOf(),
    // The session history (its length and the current entry) and whether the page behind a
    // modal is kept from scrolling.
    history: { length: hist.entries.length, index: hist.index },
    locked: document.documentElement.classList.contains('detail-open'),
    buttons: view().querySelectorAll('button').map((b) => ({
      text: b.textContent.trim(), disabled: b.disabled, ariaDisabled: b.getAttribute('aria-disabled') === 'true', shown: shownEl(b),
    })),
    // Where the keyboard focus is (focusOf).
    focus: focusOf(),
    // Every table row with the status chips it shows, so that a test can tell a red chip
    // from a green one (the text alone cannot).
    rows: view().querySelectorAll('tr').map((tr) => ({ text: tr.textContent, chips: tr.querySelectorAll('.chip').map(chipOf) })),
    // Chart marks that carry meaning without text: peak marks, "at least" chevrons, reference
    // lines, filled areas, the flow meter's bars and its heavy-traffic marks; and the elements
    // that set hidden characters of remote text apart (ctl).
    marks: {
      peak: view().querySelectorAll('line.pk').length,
      atleast: view().querySelectorAll('path.atleast').length,
      ref: view().querySelectorAll('line.thr-ref').length,
      area: view().querySelectorAll('path.area').length,
      flowbar: view().querySelectorAll('svg.flow-bar').length,
      heavy: view().querySelectorAll('line.flow-heavy').length,
      ctl: view().querySelectorAll('.ctl').length,
    },
    // The section headings shown (hidden ones still have text, so the text alone cannot tell).
    headings: view().querySelectorAll('h2').filter(shownEl).map((e) => e.textContent.trim()),
    // How many requests the page had made when the view was captured, and the timers waiting.
    requests: requests.length,
    timers: longTimers.size,
    // The live regions the view's text is in (none for the flow meter's numbers).
    live: view().querySelectorAll('[aria-live]').map((e) => e.getAttribute('aria-live') + ':' + (e.className || e.localName)),
    // The radio buttons checked (their values), the forms shown (their labels) and the URL's
    // hash: which period a period control claims, and which one the page is on.
    radios: view().querySelectorAll('input').filter((e) => e.getAttribute('type') === 'radio' && e.checked).map((e) => e.getAttribute('value') || ''),
    forms: view().querySelectorAll('form').filter(shownEl).map((f) => f.getAttribute('aria-label') || f.className),
    hash: location.hash,
    // The names of each list of ranked bars (by its aria-label), in their order: shown or not
    // (behind a table view), the labels a reader gets.
    bars: Object.fromEntries(view().querySelectorAll('ol.bars').map((ol) => [ol.getAttribute('aria-label') || '',
      ol.querySelectorAll('.bar-name').map((e) => e.textContent)])),
    // The values of those bars (the figure each shows), in the same order.
    barValues: Object.fromEntries(view().querySelectorAll('ol.bars').map((ol) => [ol.getAttribute('aria-label') || '',
      ol.querySelectorAll('.bar-val').map((e) => (e.firstChild ? e.firstChild.textContent : ''))])),
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

/** visit goes to hash as a link or the address bar does: a new history entry, and hashchange. */
async function visit(hash) {
  addEntry(hash);
  windowEvents.dispatchEvent(new FakeEvent('hashchange'));
  await settle();
}

/** back is the browser's Back button. */
async function back() {
  context.history.back();
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
  if (!shownEl(b)) {
    errors.push('button "' + text + '" is hidden');
    return false;
  }
  b.focus(); // as a keyboard user is on the button they press (and a browser focuses a button it clicks)
  b.click();
  await settle();
  return true;
}

/** topModal is the topmost modal dialog open, or null. */
function topModal() {
  for (let i = modals.length - 1; i >= 0; i--) if (document.contains(modals[i])) return modals[i];
  return null;
}

/** confirmation is the confirmation dialog open on top (dialog()), or null: not the Overview's
 *  details, which may be open under it. */
function confirmation() {
  const dlg = topModal();
  return dlg && !dlg.classList.contains('dlg-detail') ? dlg : null;
}

/** answerDialog records the open confirmation dialog's text and closes it with OK or Cancel.
 *  With running, what the answer starts is not waited for: the page is as it shows the action in
 *  progress. */
async function answerDialog(ok, fill, running) {
  const dlg = confirmation();
  if (!dlg) {
    errors.push('no dialog is open');
    return;
  }
  if (fill) fill(dlg);
  dialogs.push(dlg.textContent);
  checkDocument('dialog');
  dlg.close(ok ? 'ok' : 'cancel');
  if (running) await tick(30);
  else await settle();
}

/** refresh runs the page's periodic work once - the status refresh every 10 s and the view's
 *  own (the Overview's recent incidents): intervals never fire by themselves. */
async function refresh() {
  for (const fn of intervals.slice()) if (fn) guard('interval', fn);
  await settle();
}

/** refreshStatusOnly runs only the status refresh every 10 s (not a view's minute work), so that
 *  a test sees what follows from the status itself. */
async function refreshStatusOnly() {
  for (const fn of intervals.slice()) if (fn && fn.name === 'refreshStatus') guard('interval', fn);
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

function setVisibility(state) {
  document.visibilityState = state;
  document.hidden = state !== 'visible';
  document.dispatchEvent(new FakeEvent('visibilitychange'));
}

// ------------------------------------------------------------------ the Overview's details

/** cardButtons are the Overview's buttons that open a card's details (the status card's first). */
function cardButtons() { return view().querySelectorAll('button[data-detail]'); }

function cardButton(key) { return cardButtons().find((b) => b.getAttribute('data-detail') === key) || null; }

/** detailDialog is the Overview's details modal when one is open, else null. */
function detailDialog() {
  const dlg = view().querySelector('dialog.dlg-detail');
  return dlg && dlg.hasAttribute('open') ? dlg : null;
}

/** pressKeyOn presses a key on el as a keyboard user does, with the focus on it: a browser
 *  activates a focused button with Enter (on keydown) and Space (on keyup), unless the page
 *  prevents it. */
async function pressKeyOn(el, key) {
  el.focus();
  const down = new FakeEvent('keydown', { key });
  el.dispatchEvent(down);
  if (el.localName === 'button' && key === 'Enter' && !down.defaultPrevented) el.click();
  if (key === ' ') {
    const up = new FakeEvent('keyup', { key });
    el.dispatchEvent(up);
    if (el.localName === 'button' && !down.defaultPrevented && !up.defaultPrevented) el.click();
  }
  await settle();
}

/** openCard opens a card's details: with a click, or from the keyboard (Enter, Space). */
async function openCard(key, how) {
  const b = cardButton(key);
  if (!b) {
    errors.push('no card opens the details "' + key + '"');
    return;
  }
  if (how === 'enter') await pressKeyOn(b, 'Enter');
  else if (how === 'space') await pressKeyOn(b, ' ');
  else {
    b.focus(); // a browser focuses a button it clicks
    b.click();
    await settle();
  }
}

/** pressEscape is Esc on the topmost modal dialog: its cancel event, then, unless the page
 *  prevents it, the dialog closes. */
async function pressEscape() {
  const dlg = topModal();
  if (!dlg) {
    errors.push('Esc: no modal dialog is open');
    return;
  }
  const ev = new FakeEvent('cancel');
  dlg.dispatchEvent(ev);
  if (!ev.defaultPrevented) dlg.close();
  await settle();
}

/** clickBackdrop clicks the topmost modal dialog's backdrop: a browser gives the click to the
 *  dialog element, at a point outside its box (the fake box is 0..800 x 0..240). */
async function clickBackdrop() {
  const dlg = topModal();
  if (!dlg) {
    errors.push('backdrop: no modal dialog is open');
    return;
  }
  for (const type of ['pointerdown', 'click']) dlg.dispatchEvent(new FakeEvent(type, { target: dlg, clientX: 900, clientY: 300 }));
  await settle();
}

/** closeDetail closes the open details as a reader does: Esc, their close button, a click on the
 *  backdrop, or the browser's Back button. */
async function closeDetail(how) {
  const dlg = detailDialog();
  if (!dlg) {
    errors.push('no details open to close (' + how + ')');
    return;
  }
  switch (how) {
    case 'escape': await pressEscape(); break;
    case 'close': {
      const b = dlg.querySelector('button.detail-close');
      if (!b) {
        errors.push('the details have no close button');
        return;
      }
      b.focus();
      b.click();
      await settle();
      break;
    }
    case 'backdrop': await clickBackdrop(); break;
    case 'back': await back(); break;
    default: errors.push('closeDetail: ' + how);
  }
}

/** overviewDetails opens every card's details in turn with a click and captures them
 *  (prefix + key); the charts in them are used from the keyboard first and captured with their
 *  table views on (the plots drawn behind them), then put back to plots; the traffic's over 7
 *  days too (prefix + "traffic 7d", plots). Each is closed with Esc. */
async function overviewDetails(prefix) {
  for (const key of cardButtons().map((b) => b.getAttribute('data-detail'))) {
    await openCard(key, 'click');
    if (!detailDialog()) {
      errors.push('the ' + key + ' card opened no details');
      continue;
    }
    const charts = !!detailDialog().querySelector('.plot');
    if (charts) {
      exerciseCharts(); // read from the keyboard, then the table views on
      await settle();
    }
    capture(prefix + key);
    if (charts) {
      exerciseCharts(); // and the plots again
      await settle();
      if (key === 'traffic') {
        radio('7d');
        await settle();
        capture(prefix + 'traffic 7d');
        radio('24h');
        await settle();
      }
    }
    await pressEscape();
  }
}

/** detailsScenario uses each card's details as a reader does (facts.details): opened with a
 *  click, Enter or Space and closed with Esc, the close button, the backdrop or Back, in turn,
 *  noting the address, the history, the focus and the scroll lock before, while open and after.
 *  Then the This PC's link details across a status update, with their route check opened and the
 *  focus in it, scrolled (facts.live); then the Internet details while the line goes down
 *  (/demo/state?s=outage) and the summary in the outage (facts.outage); then a confirmation
 *  dialog over the syslog details (facts.confirm). */
async function detailsScenario() {
  const ways = ['click', 'enter', 'space'];
  const closes = ['escape', 'close', 'backdrop', 'back'];
  const keys = cardButtons().map((b) => b.getAttribute('data-detail'));
  const steps = [];
  const state = () => ({ hash: location.hash, length: hist.entries.length, index: hist.index, focus: focusOf(),
    open: !!detailDialog(), locked: document.documentElement.classList.contains('detail-open'), modals: modals.length });
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    const how = ways[i % ways.length];
    const close = closes[i % closes.length];
    const before = state();
    await openCard(key, how);
    const opened = state();
    capture('detail ' + key);
    await closeDetail(close);
    steps.push({ key, how, close, before, opened, after: state() });
  }
  facts.details = steps;

  // A status update while the details are open: their content is drawn anew, and the reader
  // keeps their place.
  await openCard('link', 'click');
  let dlg = detailDialog();
  const live = { opened: !!dlg };
  if (dlg) {
    const det = dlg.querySelector('details.egress');
    const body = dlg.querySelector('.detail-body');
    if (det && body) {
      det.open = true;
      det.dispatchEvent(new FakeEvent('toggle'));
      det.querySelector('summary').focus();
      body.scrollTop = 120;
      live.before = focusOf();
      await refresh();
      const now = detailDialog();
      const det2 = now ? now.querySelector('details.egress') : null;
      Object.assign(live, {
        sameDialog: now === dlg, kept: !!det2 && det2 === det, open: !!det2 && det2.open,
        focusKept: !!det2 && document.activeElement === det2.querySelector('summary'), focus: focusOf(),
        scrollTop: body.scrollTop, hash: location.hash,
      });
    } else {
      errors.push('the link details have no route check to open');
    }
    await closeDetail('escape');
  }
  facts.live = live;

  // The line goes down while the Internet details are open: they follow the status.
  await openCard('internet', 'click');
  dlg = detailDialog();
  capture('internet online');
  await fetch(new URL('/demo/state?s=outage', base));
  await refresh();
  capture('internet outage');
  facts.outage = { sameDialog: !!dlg && detailDialog() === dlg, hash: location.hash, focus: focusOf() };
  await closeDetail('escape');
  capture('summary outage');

  // A confirmation over the details: the syslog control's "Stop sending", then Cancel.
  await openCard('syslog', 'click');
  const confirm = { before: modals.length };
  if (await press('Stop sending')) {
    const c = confirmation();
    confirm.over = !!c && modals.length === 2 && !!detailDialog();
    await answerDialog(false);
    confirm.after = { modals: modals.length, detailOpen: !!detailDialog(), focus: focusOf() };
  }
  facts.confirm = confirm;
  await closeDetail('escape');
}

/** deepLinkScenario starts with the page loaded at a card's details ($HARNESS_HASH): they are
 *  open at once; closed, they replace the address (facts.deep). Then an address that names no
 *  card, details reached from another page, and Back from details opened from the address. */
async function deepLinkScenario() {
  capture('deep link');
  const opened = { hash: location.hash, length: hist.entries.length, index: hist.index, focus: focusOf() };
  await closeDetail('close');
  capture('deep link closed');
  const closed = { hash: location.hash, length: hist.entries.length, index: hist.index, focus: focusOf() };
  await visit('#/?detail=nosuchcard');
  capture('unknown card');
  await visit('#/incidents');
  await visit('#/?detail=fiber');
  capture('from another page');
  const fromPage = { hash: location.hash, focus: focusOf() };
  await back();
  capture('back to incidents');
  facts.deep = { opened, closed, fromPage, backHash: location.hash, backHasDialog: !!view().querySelector('dialog') };
}

/** syslogScenario (on the overview): the flow meter asks again when its timer fires, not while
 *  the page is hidden, at once when it is shown again, and never after the Overview was left.
 *  Then the Syslog page's retention form: keep 50 MiB and 30 days; then 3 days, which deletes
 *  the older messages (confirmed in the dialog); the same limits again, which changes nothing;
 *  then a value the page refuses itself. */
async function syslogScenario() {
  fireLongTimers();
  await settle();
  capture('overview poll');
  setVisibility('hidden');
  await settle();
  fireLongTimers();
  await settle();
  capture('overview hidden');
  setVisibility('visible');
  await settle();
  capture('overview visible');
  await visit('#/syslog');
  fireLongTimers();
  await settle();
  await openAllDetails();
  capture('syslog');

  const form = view().querySelector('form.retention');
  if (!form) {
    errors.push('the Syslog page has no retention form');
    return;
  }
  const [mib, days] = form.querySelectorAll('input');
  const type = (input, value) => {
    input.value = value;
    input.dispatchEvent(new FakeEvent('input'));
  };
  type(mib, '50');
  type(days, '30');
  await submit(form);
  capture('syslog retention');
  type(days, '3');
  await submit(form);
  await answerDialog(true);
  await settle();
  capture('syslog retention pruned');
  type(mib, '50');
  type(days, '3');
  await submit(form);
  if (confirmation()) await answerDialog(true); // recorded (dialogs), never expected
  await settle();
  capture('syslog retention unchanged');
  type(mib, '0');
  await submit(form);
  capture('syslog retention refused');
}

/** gwSyslogScenario: the control of the gateway's Syslog setting, on the Syslog page and in the
 *  Overview's Gateway syslog details, used from the keyboard. "Stop sending" is confirmed and
 *  runs (captured while it runs - pressed again meanwhile, it must do nothing -, then when it is
 *  done); "Send the gateway’s log to this PC" is cancelled in its dialog (nothing is sent), then
 *  confirmed. In the Overview's details the control stops the sending again (its confirmation
 *  over the details), and stays where it is, with its outcome, when the status refresh draws the
 *  details again around it. */
async function gwSyslogScenario() {
  await visit('#/syslog');
  capture('syslog');
  if (await press('Stop sending')) {
    await answerDialog(true, null, true);
    capture('syslog stopping');
    const again = button('Stop sending');
    if (again) again.click();
    if (confirmation()) {
      errors.push('"Stop sending", pressed while its change runs, opened a dialog');
      await answerDialog(false, null, true);
    }
    await settle();
  }
  capture('syslog stopped');
  if (await press('Send the gateway’s log to this PC')) await answerDialog(false);
  capture('syslog cancelled');
  if (await press('Send the gateway’s log to this PC')) await answerDialog(true);
  capture('syslog sending');
  await visit('#/');
  await openCard('syslog', 'click');
  capture('overview sending');
  const ctl = view().querySelector('.syslog-control');
  const panel = ctl && ctl.closest('.syslog-panel');
  let moved = 0;
  if (panel) panel.onTaken = () => { moved++; };
  else errors.push('the Overview’s syslog details have no syslog panel');
  if (await press('Stop sending')) await answerDialog(true);
  await refresh();
  if (!ctl || view().querySelector('.syslog-control') !== ctl) errors.push('the status refresh rebuilt the syslog control in the Overview’s details');
  if (moved) errors.push('the status refresh took the syslog panel out of the Overview’s details ' + moved + ' times (it loses the focus, and its live region is announced again)');
  capture('overview stopped');
}

function key(el, k, shiftKey) {
  if (el) el.dispatchEvent(new FakeEvent('keydown', { key: k, shiftKey: !!shiftKey }));
}

function radio(value) {
  const r = view().querySelector('input[value="' + value + '"]');
  if (!r) {
    errors.push('no radio button ' + value);
    return;
  }
  r.checked = true;
  r.dispatchEvent(new FakeEvent('change'));
}

/** timelineSteps reads the Firewall tab's "Blocked per hour" from the keyboard across the page's
 *  refresh every minute: focused (the last hour), five hours back, the refresh, one more hour
 *  back. At each step it notes (facts.timeline) the hour shown (the tooltip's UTC line), the
 *  text of the chart's live region and how many times it was written, and whether the chart
 *  has the keyboard focus; the plot and its live region are looked up again at each step. */
async function timelineSteps() {
  const plotOf = () => view().querySelector('[data-fk="net-fw-hours:plot"]');
  const liveOf = (p) => {
    const fig = p && p.closest('figure');
    return fig ? fig.querySelector('[aria-live]') : null;
  };
  const plot = plotOf();
  const live = liveOf(plot);
  if (!plot || !live) {
    errors.push('the firewall timeline has no plot or no live region');
    return;
  }
  let writes = 0;
  const text = Object.getOwnPropertyDescriptor(FakeNode.prototype, 'textContent');
  Object.defineProperty(live, 'textContent', {
    configurable: true,
    get() { return text.get.call(this); },
    set(v) {
      writes++;
      text.set.call(this, v);
    },
  });
  const steps = [];
  const note = (step) => {
    const p = plotOf();
    const tip = p && p.querySelector('.tip');
    const utc = tip && !tip.hidden ? tip.querySelector('.tip-utc') : null;
    const l = liveOf(p);
    steps.push({ step, utc: utc ? utc.textContent : '', live: l ? l.textContent : '', writes, focused: !!p && document.activeElement === p, same: p === plot });
  };
  plot.focus();
  note('focus');
  for (let i = 0; i < 5; i++) key(document.activeElement, 'ArrowLeft');
  note('back 5');
  await refresh();
  note('refresh');
  key(document.activeElement, 'ArrowLeft');
  note('back 1');
  key(document.activeElement, 'Escape');
  const p = plotOf();
  if (p) p.blur();
  facts.timeline = steps;
}

/** networkSteps visits the Network page as a keyboard user: the Connections tab (the flow
 *  diagram's nodes - moved through with the arrow keys, a device shown alone with Enter, then
 *  every device again -, the world map read from the keyboard, the table's search, sort and
 *  "Show all", every Table view, a custom period - its form opened, cancelled, opened again and
 *  applied, then refused), then the Firewall tab (its timeline across a refresh, timelineSteps). */
async function networkSteps() {
  await visit('#/network?range=24h');
  capture('network');
  const first = view().querySelector('g.sk-node');
  if (!first) {
    errors.push('the flow diagram has no node');
  } else {
    first.focus();
    for (const k of ['ArrowDown', 'ArrowDown', 'ArrowUp', 'End', 'Home', 'ArrowRight', 'ArrowDown', 'ArrowRight', 'ArrowLeft', 'ArrowLeft', 'Escape']) {
      key(document.activeElement, k);
    }
    capture('network keys');
    const dev = view().querySelectorAll('g.sk-node').find((g) => g.getAttribute('role') === 'button' && g.getAttribute('aria-pressed') === 'false');
    if (dev) {
      dev.focus();
      key(dev, 'Enter');
      await settle();
      capture('network device');
      const all = button('Show every device');
      if (all) {
        all.focus();
        all.click();
        await settle();
      } else {
        errors.push('no "Show every device" after a device was chosen');
      }
      capture('network every device');
    }
  }
  const map = view().querySelector('.map-plot');
  if (map) {
    map.focus();
    for (const k of ['ArrowRight', 'ArrowRight', 'End', 'ArrowLeft', 'Home']) key(map, k);
    map.blur();
  }
  const box = view().querySelector('input[type="search"]');
  if (box) {
    box.value = 'google';
    box.dispatchEvent(new FakeEvent('input'));
    await tick(300);
    capture('network search');
    box.value = '';
    box.dispatchEvent(new FakeEvent('input'));
    await tick(300);
  }
  for (const label of ['Remote address', 'Device', 'Last seen']) {
    const b = view().querySelectorAll('button.th-sort').find((x) => x.textContent.startsWith(label));
    if (!b) {
      errors.push('no sort button ' + label);
      continue;
    }
    b.focus();
    b.click();
    await tick(20);
  }
  capture('network sorted');
  if (button('Show all')) {
    await press('Show all');
    capture('network all rows');
  }
  for (const b of view().querySelectorAll('figure button')) if (b.textContent === 'Table') b.click();
  await settle();
  capture('network tables');
  for (const b of view().querySelectorAll('figure button')) if (b.textContent === 'Table') b.click();
  radio('custom');
  await settle();
  capture('network custom open');
  if (await press('Cancel')) capture('network custom cancelled');
  radio('custom');
  await settle();
  const form = view().querySelector('form.net-custom');
  if (form) {
    const [from, to] = form.querySelectorAll('input');
    const pad = (n) => String(n).padStart(2, '0');
    const local = (d) => d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + 'T' + pad(d.getHours()) + ':' + pad(d.getMinutes());
    from.value = local(new Date(Date.now() - 3 * 86400e3));
    to.value = local(new Date(Date.now() - 2 * 86400e3));
    await submit(form);
    capture('network custom');
    from.value = to.value;
    await submit(form);
    capture('network custom refused');
  } else {
    errors.push('no custom period form');
  }
  await visit('#/network/firewall?range=7d');
  await timelineSteps();
  exerciseCharts();
  await settle();
  capture('network firewall');
  radio('1h');
  await settle();
  capture('network firewall 1h');
}

/** summaryScenario captures the Overview's summary ("overview") and the details of each card
 *  $HARNESS_DETAILS names (comma-separated), each as "overview <key>", opened with a click and
 *  closed with Esc. */
async function summaryScenario() {
  for (const key of (process.env.HARNESS_DETAILS || '').split(',').filter(Boolean)) {
    await openCard(key, 'click');
    capture('overview ' + key);
    await pressEscape();
  }
}

/** countFocus counts the focus events on el from now on (a screen reader announces each). */
function countFocus(el) {
  const n = { focus: 0 };
  if (el) el.addEventListener('focus', () => { n.focus++; });
  return n;
}

/** requestsTo counts the requests made so far to path (with its query). */
function requestsTo(path) {
  return requests.filter((r) => r.path === path).length;
}

/** keepScenario uses the Overview as a reader who stays on something while it updates
 *  (facts.keep): the cards' buttons as Tab reads them; the Internet details opened right after the
 *  summary read the last 24 hours; their body as a keyboard user meets it; the round-trip chart
 *  read from the keyboard, and the packet-loss chart's table view scrolled, across the charts'
 *  refresh (the Overview's series read, then the details' minute); a double-click that opened them;
 *  a status change announced while they are open; the status card's incident link, the status
 *  details' record link and a text selected in the gateway details across status updates; the
 *  page shown again after a while. The server must offer /demo/state. */
async function keepScenario() {
  const keep = {};
  keep.cards = cardsOf().map((c) => ({ key: c.key, described: c.described, chip: c.chip, titles: c.titles }));
  const hero = view().querySelector('button.status-open');
  keep.status = { described: hero && hero.getAttribute('aria-describedby') ? (document.getElementById(hero.getAttribute('aria-describedby')) || { textContent: '' }).textContent : '' };

  // The Internet details opened right after the summary read the series: they draw from it.
  const reads = requestsTo('/api/series?range=24h');
  await openCard('internet', 'click');
  let dlg = detailDialog();
  keep.seriesReads = requestsTo('/api/series?range=24h') - reads;
  const d = detailOf();
  keep.body = d && d.body;

  // The round-trip chart read from the keyboard: three buckets back.
  const plot = dlg.querySelector('[data-fk="chart:latency:plot"]');
  const charts = { minHeight: plot ? plot.style.minHeight : '' };
  if (plot) {
    plot.focus();
    for (let i = 0; i < 3; i++) plot.dispatchEvent(new FakeEvent('keydown', { key: 'ArrowLeft' }));
    const fig = plot.closest('figure');
    const tipOf = () => { const t = plot.querySelector('.tip'); return t && !t.hidden ? t.querySelector('.tip-time').textContent : ''; };
    const liveOf = () => { const l = fig.querySelector('[aria-live]'); return l ? l.textContent : ''; };
    Object.assign(charts, { tip: tipOf(), live: liveOf() });
    const svg = plot.querySelector('svg');
    const focus = countFocus(plot);
    await refresh(); // the Overview reads the series again (the details still show theirs)
    await refresh(); // the details' minute: their charts follow the newer series
    const now = dlg.querySelector('[data-fk="chart:latency:plot"]');
    Object.assign(charts, {
      samePlot: now === plot, focused: document.activeElement === plot, redrawn: !!svg && plot.querySelector('svg') !== svg,
      tipAfter: tipOf(), liveAfter: liveOf(), focusEvents: focus.focus,
    });
    plot.blur();
  }
  // The packet-loss chart's table view, scrolled to older rows.
  const tableBtn = dlg.querySelector('[data-fk="chart:loss:table"]');
  if (tableBtn) {
    tableBtn.click();
    const region = dlg.querySelector('[data-fk="chart:loss:tableview"]');
    if (region) {
      region.focus();
      region.scrollTop = 500;
      const tbl = region.firstChild;
      const focus = countFocus(region);
      skipTime(61000); // the cached series is a minute old: the details read their own
      await refresh();
      const now = dlg.querySelector('[data-fk="chart:loss:tableview"]');
      charts.table = { same: now === region, focused: document.activeElement === region, scrollTop: now ? now.scrollTop : null, refilled: region.firstChild !== tbl, focusEvents: focus.focus };
    }
    const btn = dlg.querySelector('[data-fk="chart:loss:table"]');
    if (btn) btn.click();
  }
  keep.charts = charts;
  await closeDetail('escape');

  // A double-click on a card: its second click lands on the details that just opened.
  await openCard('internet', 'click');
  dlg = detailDialog();
  const dbl = {};
  if (dlg) {
    for (const type of ['pointerdown', 'click']) dlg.dispatchEvent(new FakeEvent(type, { target: dlg, clientX: 900, clientY: 300, detail: 2 }));
    await settle();
    dbl.afterBackdrop = { open: !!detailDialog(), hash: location.hash };
    const close = dlg.querySelector('button.detail-close');
    close.dispatchEvent(new FakeEvent('click', { detail: 2, bubbles: true }));
    await settle();
    dbl.afterClose = { open: !!detailDialog(), hash: location.hash };
    const link = dlg.querySelector('.detail-links a');
    const ev = new FakeEvent('click', { detail: 2, bubbles: true });
    if (link) link.dispatchEvent(ev);
    dbl.linkPrevented = ev.defaultPrevented;
    skipTime(1500); // a click well after the opening is a click
    for (const type of ['pointerdown', 'click']) dlg.dispatchEvent(new FakeEvent(type, { target: dlg, clientX: 900, clientY: 300, detail: 1 }));
    await settle();
    dbl.later = { open: !!detailDialog(), hash: location.hash };
  }
  keep.doubleClick = dbl;

  // An incident opens, then closes: the recent incidents follow the status at once, not at their
  // next minute.
  const recentText = () => { const r = view().querySelector('section.recent'); return r ? r.textContent : ''; };
  keep.recent = { before: recentText() };
  await fetch(new URL('/demo/state?s=outage', base));
  await refreshStatusOnly();
  keep.recent.opened = recentText();
  keep.recent.hero = (view().querySelector('.status-main') || { textContent: '' }).textContent;
  await fetch(new URL('/demo/state?s=online', base));
  await refreshStatusOnly();
  keep.recent.closed = recentText();

  // A status change while the details are open is announced in them: the page's own live region
  // is inert behind the modal.
  await openCard('internet', 'click');
  dlg = detailDialog();
  await fetch(new URL('/demo/state?s=outage', base));
  await refresh();
  await tick(150);
  const region = dlg && dlg.querySelector('[data-announce]');
  keep.announce = { modal: region ? region.textContent : '', page: document.getElementById('live').textContent, live: region ? region.getAttribute('aria-live') : '' };
  await closeDetail('escape');

  // The status card's incident link, focused across status updates (the outage goes on).
  await settle();
  const inc = view().querySelector('.status-incident a');
  if (inc) {
    inc.focus();
    const focus = countFocus(inc);
    await refresh();
    await refresh();
    keep.incident = { same: view().querySelector('.status-incident a') === inc, focused: document.activeElement === inc, focusEvents: focus.focus, text: inc.textContent };
  }

  // The status details' link to the gateway snapshot the verdict used, focused across a status
  // update that names the same records.
  await openCard('status', 'click');
  dlg = detailDialog();
  const snap = dlg && dlg.querySelector('[data-fk="inputs:snapshot"]');
  if (snap) {
    snap.focus();
    const focus = countFocus(snap);
    await refresh();
    keep.inputs = { same: dlg.querySelector('[data-fk="inputs:snapshot"]') === snap, focused: document.activeElement === snap, focusEvents: focus.focus };
  }
  await closeDetail('escape');

  // A text selected in the gateway details (the WAN address, to copy it) across a status update;
  // once it is no longer selected, the next update draws the details again.
  await openCard('gateway', 'click');
  dlg = detailDialog();
  const dd = dlg && dlg.querySelectorAll('dd').find((e) => e.textContent.includes(process.env.HARNESS_WAN || '203.0.113.45'));
  if (dd) {
    selectText(dd.firstChild || dd);
    await refresh();
    const kept = document.contains(dd);
    selectText(null);
    await refresh();
    keep.selection = { kept, redrawnAfter: !document.contains(dd) };
  }
  await closeDetail('escape');

  // The page hidden, then shown again a minute later: the series and the recent incidents are
  // read at once, not at the next minute - and so is the series of the details open (their
  // range set to 6 hours, which only they read).
  await openCard('internet', 'click');
  radio('6h');
  await settle();
  setVisibility('hidden');
  await settle();
  const before = { series: requestsTo('/api/series?range=24h'), incidents: requestsTo('/api/incidents?limit=3'), details: requestsTo('/api/series?range=6h') };
  skipTime(61000);
  setVisibility('visible');
  await settle();
  keep.visible = {
    series: requestsTo('/api/series?range=24h') - before.series, incidents: requestsTo('/api/incidents?limit=3') - before.incidents,
    details: requestsTo('/api/series?range=6h') - before.details,
  };
  radio('24h');
  await settle();
  await closeDetail('escape');
  facts.keep = keep;
}

/** statusFailScenario: the Internet details open while the status stops being read
 *  (/demo/statusfail?mode=down: the service does not answer; mode=500: it answers with an error),
 *  then is read again (facts.fail). */
async function statusFailScenario() {
  await openCard('internet', 'click');
  const fail = { before: detailOf() };
  await fetch(new URL('/demo/statusfail?mode=down', base));
  await refresh();
  fail.down = detailOf();
  const note = detailDialog() && detailDialog().querySelector('.detail-stale');
  await refresh();
  fail.sameNote = !!note && detailDialog().querySelector('.detail-stale') === note;
  // Details opened while the status cannot be read say so at once.
  await closeDetail('escape');
  await openCard('internet', 'click');
  fail.reopened = detailOf();
  await fetch(new URL('/demo/statusfail', base));
  await refresh();
  fail.back = detailOf();
  await fetch(new URL('/demo/statusfail?mode=500', base));
  await refresh();
  fail.error = detailOf();
  await fetch(new URL('/demo/statusfail', base));
  await refresh();
  facts.fail = fail;
}

/** confirmBackScenario: the syslog details' "Stop sending" asks for confirmation, and the browser's
 *  Back closes the details meanwhile (facts.confirmBack). */
async function confirmBackScenario() {
  await openCard('syslog', 'click');
  const out = { asked: false };
  if (await press('Stop sending')) {
    out.asked = !!confirmation();
    await back();
    out.after = { modals: modals.length, dialogs: document.querySelectorAll('dialog').length, detailOpen: !!detailDialog(), hash: location.hash, focus: focusOf() };
  }
  facts.confirmBack = out;
}

async function run() {
  const res = await fetch(new URL('/static/app.js', base));
  const code = await res.text();
  guard('app.js', () => vm.runInContext(code, context, { filename: 'app.js' }));
  await settle();

  if (scenario === 'deeplink') { // the page loaded at a card's details ($HARNESS_HASH)
    await deepLinkScenario();
    return;
  }
  if (scenario === 'deepfail') { // the page loaded at a card's details while the status cannot be read
    await refresh();
    capture('deep fail');
    return;
  }
  await visit('#/');
  capture('overview');
  if (scenario === 'summary') {
    await summaryScenario();
    return;
  }
  if (scenario === 'keep') {
    await keepScenario();
    return;
  }
  if (scenario === 'statusfail') {
    await statusFailScenario();
    return;
  }
  if (scenario === 'confirmback') {
    await confirmBackScenario();
    return;
  }
  if (scenario === 'overview') { // the summary and every card's details only (and the Syslog page)
    await overviewDetails('overview ');
    await visit('#/syslog');
    capture('syslog');
    return;
  }
  if (scenario === 'details') {
    await detailsScenario();
    return;
  }
  if (scenario === 'syslog') {
    await syslogScenario();
    return;
  }
  if (scenario === 'network') {
    await networkSteps();
    return;
  }
  if (scenario === 'networktabs') { // both tabs of the Network page as they first show
    await visit('#/network?range=24h');
    capture('network');
    await visit('#/network/firewall?range=24h');
    capture('network firewall');
    return;
  }
  if (scenario === 'gwsyslog') {
    await gwSyslogScenario();
    return;
  }
  // gwsyslogon / gwsyslogoff: one change of the gateway's Syslog setting on the Syslog page.
  if (scenario === 'gwsyslogon' || scenario === 'gwsyslogoff') {
    await visit('#/syslog');
    capture('syslog');
    if (await press(scenario === 'gwsyslogon' ? 'Send the gateway’s log to this PC' : 'Stop sending')) await answerDialog(true);
    capture('syslog changed');
    return;
  }
  // Every card's details, their charts used (the traffic's over 7 days too).
  await overviewDetails('overview ');

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

  // The gateway's syslog: the newest messages, more of them, then the filters (the search box
  // is debounced).
  await visit('#/syslog');
  await openAllDetails();
  capture('syslog');
  const more = button('Load more');
  if (more && !more.hidden) {
    more.click();
    await settle();
    await openAllDetails();
    capture('syslog more');
  }
  const sev = view().querySelector('select');
  if (sev) {
    sev.value = 'err';
    sev.dispatchEvent(new FakeEvent('change'));
    await settle();
    capture('syslog severity');
    sev.value = '';
    const box = view().querySelector('input[type="search"]');
    box.value = 'PON';
    box.dispatchEvent(new FakeEvent('input'));
    await tick(500);
    await settle();
    await openAllDetails();
    capture('syslog search');
  }

  // The Network page: used in full with hostile data, else its two tabs as they first show
  // (TestDashboardNetworkPage uses it in full with the demo's own data).
  if (scenario === 'hostile') {
    await networkSteps();
  } else {
    await visit('#/network?range=24h');
    capture('network');
    await visit('#/network/firewall?range=24h');
    capture('network firewall');
  }

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
    process.stdout.write(JSON.stringify({ views, dialogs, violations, errors, requests, facts }) + '\n');
    process.exit(0);
  });
