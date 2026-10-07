package web

// The dashboard shows text that other parties control: the gateway's pages, DNS answers,
// HTTP bodies, netsh output, TSA certificate names, operator notes and any ledger line. These
// tests make sure all of it reaches the page as text, never as markup or script:
//
//   - static checks of app.js: no markup or script sinks at all, and attributes named by a
//     variable are set only through setAttr (which refuses event handlers, styles and URLs
//     leaving this origin);
//   - a Node.js unit test of that guard;
//   - the real script, as served, rendering a demo world in which every remote-controlled
//     string carries "<img src=x onerror=alert(1)>", in a fake DOM that has no HTML parser
//     and records any attempt to use one (testdata/dashboard_harness.js).
//
// The Node.js tests are skipped when node is not installed, like TestAppJSSyntax.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/model"
)

func appJS(t *testing.T) string {
	t.Helper()
	b, err := staticFS.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func requireNode(t *testing.T) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; skipping the dashboard script test")
	}
	return node
}

// functionSource returns the source of the top-level-style declaration "function name(...) {...}"
// in src (brace matching; the functions checked here have no braces inside literals).
func functionSource(t *testing.T, src, name string) (string, int, int) {
	t.Helper()
	start := strings.Index(src, "function "+name+"(")
	if start < 0 {
		t.Fatalf("app.js has no function %s", name)
	}
	open := strings.Index(src[start:], "{")
	if open < 0 {
		t.Fatalf("function %s has no body", name)
	}
	depth := 0
	for i := start + open; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[start : i+1], start, i + 1
			}
		}
	}
	t.Fatalf("function %s: unbalanced braces", name)
	return "", 0, 0
}

// TestAppJSHasNoMarkupSinks: nothing in app.js may hand a string to the HTML parser or the
// script engine, or navigate to a computed URL. Remote text must become text nodes (h, s,
// textContent) or attribute values (setAttr).
func TestAppJSHasNoMarkupSinks(t *testing.T) {
	src := appJS(t)
	for _, re := range []*regexp.Regexp{
		regexp.MustCompile(`\.(innerHTML|outerHTML)\b`),
		regexp.MustCompile(`\binsertAdjacentHTML\b`),
		regexp.MustCompile(`\bdocument\s*\.\s*(write|writeln|open)\s*\(`),
		regexp.MustCompile(`\bcreateContextualFragment\b`),
		regexp.MustCompile(`\bDOMParser\b`),
		regexp.MustCompile(`\b(setHTMLUnsafe|parseHTMLUnsafe|setHTML)\b`),
		regexp.MustCompile(`\.srcdoc\b`),
		regexp.MustCompile(`\beval\s*\(`),
		regexp.MustCompile(`\bnew\s+Function\b`),
		regexp.MustCompile("\\bset(Timeout|Interval)\\s*\\(\\s*['\"`]"),
		regexp.MustCompile(`(?i)\bjavascript:`),
		regexp.MustCompile(`\bexecCommand\b`),
		regexp.MustCompile(`\.(href|src|action|formAction|srcset)\s*=[^=]`),
		regexp.MustCompile(`\blocation\s*\.\s*(href|assign|replace)\b`),
		regexp.MustCompile(`\blocation\s*=[^=]`),
		regexp.MustCompile(`\bwindow\s*\.\s*open\s*\(`),
		regexp.MustCompile(`\b(setAttributeNode|createAttribute)\b|\.attributes\s*\[`),
		regexp.MustCompile(`\.cssText\b`),
	} {
		if m := re.FindString(src); m != "" {
			t.Errorf("app.js uses %q: build elements with h()/s() and text nodes, and attributes with setAttr()", m)
		}
	}
}

// unsafeAttributes may never be set by name in app.js: they run script, load or navigate.
var unsafeAttributes = map[string]bool{
	"style": true, "srcdoc": true, "href": true, "src": true, "action": true, "formaction": true,
	"xlink:href": true, "srcset": true, "poster": true, "ping": true, "background": true, "cite": true,
	"data": true, "codebase": true, "manifest": true, "is": true,
}

// TestAppJSSetsAttributesOnlyThroughSetAttr: the only setAttribute call with a computed name
// is in setAttr (h() and s() use it for every property); every other call names a fixed,
// harmless attribute.
func TestAppJSSetsAttributesOnlyThroughSetAttr(t *testing.T) {
	src := appJS(t)
	_, start, end := functionSource(t, src, "setAttr")
	calls := regexp.MustCompile(`\.setAttribute(NS)?\s*\(\s*([^,)]*)`).FindAllStringSubmatchIndex(src, -1)
	if len(calls) < 5 {
		t.Fatalf("found only %d setAttribute calls; the pattern no longer matches app.js", len(calls))
	}
	inGuard := 0
	for _, m := range calls {
		arg := strings.TrimSpace(src[m[4]:m[5]])
		if len(arg) >= 2 && (arg[0] == '\'' || arg[0] == '"') && arg[len(arg)-1] == arg[0] {
			name := strings.ToLower(arg[1 : len(arg)-1])
			if strings.HasPrefix(name, "on") || unsafeAttributes[name] {
				t.Errorf("app.js sets the %q attribute directly; it must go through setAttr", name)
			}
			continue
		}
		if m[0] < start || m[0] >= end {
			t.Errorf("setAttribute(%s, ...) with a computed name outside setAttr (offset %d)", arg, m[0])
			continue
		}
		inGuard++
	}
	if inGuard != 1 {
		t.Errorf("setAttr calls setAttribute with a computed name %d times, want 1", inGuard)
	}
	for _, fn := range []string{"h", "s"} {
		body, _, _ := functionSource(t, src, fn)
		if !strings.Contains(body, "setAttr(el, k, v)") || strings.Contains(body, "setAttribute") {
			t.Errorf("function %s does not set its attributes through setAttr:\n%s", fn, body)
		}
	}
}

// TestAppJSURLAndAttributeGuards runs sameOriginUrl and setAttr, extracted from app.js, under
// Node.js.
func TestAppJSURLAndAttributeGuards(t *testing.T) {
	node := requireNode(t)
	src := appJS(t)
	decl := regexp.MustCompile(`(?m)^\s*const URL_ATTRS = new Set\(\[[^\]]*\]\);`).FindString(src)
	if decl == "" {
		t.Fatal("app.js: URL_ATTRS declaration not found")
	}
	sameOrigin, _, _ := functionSource(t, src, "sameOriginUrl")
	setAttr, _, _ := functionSource(t, src, "setAttr")

	hex := strings.Repeat("0f", 32)
	urls := []struct {
		in string
		ok bool
	}{
		{"#/records?from_seq=12&focus=12", true},
		{"#" + hostileMarker, true}, // a fragment cannot leave the page
		{"/api/blobs/" + hex + "/view", true},
		{"/api/exports/a%3Cimg%3E.zip", true},
		{"/%2F%2Fevil.example/x", true}, // an encoded slash is part of the path
		{"", false},
		{"javascript:alert(1)", false},
		{"JaVaScRiPt:alert(1)", false},
		{" javascript:alert(1)", false},
		{"\tjavascript:alert(1)", false},
		{"data:text/html,<script>alert(1)</script>", false},
		{"vbscript:msgbox(1)", false},
		{"http://evil.example/", false},
		{"https:evil.example", false},
		{"//evil.example/x", false},
		{`/\evil.example`, false},
		{`\\evil.example`, false},
		{"/\t/evil.example", false},
		{"/\n/evil.example", false},
		{"/\x00x", false},
		{"/x\x7f", false},
		{"\u2028/x", false},
		{"relative/path", false},
	}
	attrs := []struct {
		name  string
		value any
		set   []string // nil: refused
	}{
		{"onclick", "alert(1)", nil},
		{"ONERROR", "alert(1)", nil},
		{"onmouseover", true, nil},
		{"style", "background:url(x)", nil},
		{"srcdoc", hostileMarker, nil},
		{"href", "javascript:alert(1)", nil},
		{"HREF", "//evil.example", nil},
		{"xlink:href", "javascript:alert(1)", nil},
		{"formaction", "https://evil.example", nil},
		{"src", "http://evil.example/x.png", nil},
		{"href", "#/incidents", []string{"href", "#/incidents"}},
		{"href", "/api/blobs/" + hex, []string{"href", "/api/blobs/" + hex}},
		{"title", hostileMarker, []string{"title", hostileMarker}},
		{"aria-label", `"><img src=x>`, []string{"aria-label", `"><img src=x>`}},
		{"download", "a<b>.zip", []string{"download", "a<b>.zip"}},
		{"hidden", true, []string{"hidden", ""}},
		{"colspan", 3, []string{"colspan", "3"}},
	}
	inURLs := make([]string, len(urls))
	for i, u := range urls {
		inURLs[i] = u.in
	}
	inAttrs := make([][]any, len(attrs))
	for i, a := range attrs {
		inAttrs[i] = []any{a.name, a.value}
	}
	urlJSON, _ := json.Marshal(inURLs)
	attrJSON, _ := json.Marshal(inAttrs)
	prog := decl + "\n" + sameOrigin + "\n" + setAttr + "\n" +
		"const out = { urls: " + string(urlJSON) + ".map((u) => sameOriginUrl(u)), attrs: [] };\n" +
		"for (const [name, value] of " + string(attrJSON) + ") {\n" +
		"  const el = { set: null, setAttribute(n, v) { this.set = [n, v]; } };\n" +
		"  out.attrs.push({ ok: setAttr(el, name, value), set: el.set });\n" +
		"}\n" +
		"console.log(JSON.stringify(out));\n"
	p := filepath.Join(t.TempDir(), "guards.js")
	if err := os.WriteFile(p, []byte(prog), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, p).CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s\n--- program ---\n%s", err, out, prog)
	}
	var got struct {
		URLs  []*string `json:"urls"`
		Attrs []struct {
			OK  bool     `json:"ok"`
			Set []string `json:"set"`
		} `json:"attrs"`
	}
	if err := json.Unmarshal(out, &got); err != nil || len(got.URLs) != len(urls) || len(got.Attrs) != len(attrs) {
		t.Fatalf("unexpected output %s (%v)", out, err)
	}
	for i, u := range urls {
		switch r := got.URLs[i]; {
		case u.ok && (r == nil || *r != u.in):
			t.Errorf("sameOriginUrl(%q) refused a same-origin URL", u.in)
		case !u.ok && r != nil:
			t.Errorf("sameOriginUrl(%q) = %q, want refused", u.in, *r)
		}
	}
	for i, a := range attrs {
		g := got.Attrs[i]
		if g.OK != (a.set != nil) || !slices.Equal(g.Set, a.set) {
			t.Errorf("setAttr(%q, %v) = ok %v, set %q; want set %q", a.name, a.value, g.OK, g.Set, a.set)
		}
	}
}

// ----------------------------------------------------------------------------- the real script

type dashboardView struct {
	Text  string `json:"text"`
	Pill  string `json:"pill"`  // the status pill in the top bar
	Title string `json:"title"` // document.title
	// Hero is the Overview's status card as far as it speaks of the present (its left part: the
	// state, its attribution, since when, the key facts, the incident in progress); Strip its
	// right part, the last 24 hours.
	Hero    string `json:"hero"`
	Strip   string `json:"strip"`
	Markers int    `json:"markers"`
	// Detail is the Overview's details modal when one is in the view; Cards the Overview's summary
	// cards, in their order.
	Detail *dashboardDetail `json:"detail"`
	Cards  []dashboardCard  `json:"cards"`
	// History is the session history when the view was captured: its length and the index of the
	// current entry. Locked: the page behind a modal is kept from scrolling.
	History struct {
		Length int `json:"length"`
		Index  int `json:"index"`
	} `json:"history"`
	Locked  bool              `json:"locked"`
	Buttons []dashboardButton `json:"buttons"`
	Rows    []dashboardRow    `json:"rows"`
	// Marks counts chart marks by kind: "peak", "atleast", "ref", "area", and the flow meter's
	// "flowbar" and "heavy" marks; "ctl" counts the elements of hidden characters in remote text.
	Marks    map[string]int `json:"marks"`
	Headings []string       `json:"headings"` // the section headings (h2) shown: not inside a hidden element
	Requests int            `json:"requests"` // requests the page had made when the view was captured
	Timers   int            `json:"timers"`   // timers of a second or more waiting (the flow meter's next reading)
	Live     []string       `json:"live"`     // the view's live regions, "<aria-live>:<class>"
	// Focus is where the keyboard focus is: "body" (the start of the page, where a browser puts
	// it when the element that had it is disabled, hidden or removed), "input:<type> <value>"
	// for a radio button or a checkbox, or "<tag>:<its text>".
	Focus  string   `json:"focus"`
	Radios []string `json:"radios"` // the values of the radio buttons checked
	Forms  []string `json:"forms"`  // the forms shown, by their aria-label (else their class)
	Hash   string   `json:"hash"`   // the URL's hash when the view was captured
	// Bars holds the names of each list of ranked bars (by its aria-label), in their order,
	// also behind a table view; BarValues the figure each bar shows, in the same order.
	Bars      map[string][]string `json:"bars"`
	BarValues map[string][]string `json:"barValues"`
	// StatusDescribed is what a screen reader says after the status card's button (its
	// aria-describedby); StatusTitles the tooltips in the status card.
	StatusDescribed string `json:"statusDescribed"`
	StatusTitles    int    `json:"statusTitles"`
}

// dashboardDetail is the Overview's details modal of a rendered view: the card whose details
// they are, whether the dialog is open, its heading, its line of context, its text and the
// hostile markers in it; its body as a keyboard user meets it and the parts it shows ("<tag>.
// <class>", in order); the note that the status cannot be read, when there is one.
type dashboardDetail struct {
	Key     string `json:"key"`
	Open    bool   `json:"open"`
	Title   string `json:"title"`
	Context string `json:"context"`
	Text    string `json:"text"`
	Markers int    `json:"markers"`
	Body    *struct {
		Tabindex   string `json:"tabindex"`
		Role       string `json:"role"`
		Labelledby string `json:"labelledby"`
	} `json:"body"`
	Parts []string `json:"parts"`
	Stale *struct {
		Text string `json:"text"`
		Role string `json:"role"`
	} `json:"stale"`
}

// dashboardCard is one of the Overview's summary cards: the details it opens, its title, its
// status chip ("<tone>:<label>"), its tone, its text, the hostile markers in it, its sparklines
// (hidden from screen readers), its controls (its title's button only), what a screen reader
// says after its button (aria-describedby) and the tooltips in it.
type dashboardCard struct {
	Key       string `json:"key"`
	Title     string `json:"title"`
	Chip      string `json:"chip"`
	Tone      string `json:"tone"`
	Text      string `json:"text"`
	Markers   int    `json:"markers"`
	Sparks    int    `json:"sparks"`
	Controls  int    `json:"controls"`
	Described string `json:"described"`
	Titles    int    `json:"titles"`
}

// card returns the summary card of v that opens key, failing the test without one.
func (v dashboardView) card(t *testing.T, key string) dashboardCard {
	t.Helper()
	for _, c := range v.Cards {
		if c.Key == key {
			return c
		}
	}
	t.Fatalf("no summary card %q (cards: %+v)", key, v.Cards)
	return dashboardCard{}
}

// dashboardButton is one button of a rendered view.
type dashboardButton struct {
	Text     string `json:"text"`
	Disabled bool   `json:"disabled"`
	// AriaDisabled: aria-disabled="true", announced as unavailable while it keeps the focus.
	AriaDisabled bool `json:"ariaDisabled"`
	Shown        bool `json:"shown"` // not inside a hidden element
}

// dashboardRow is one table row of a rendered view.
type dashboardRow struct {
	Text  string   `json:"text"`
	Chips []string `json:"chips"` // "<tone>:<label>" of each status chip in the row, e.g. "good:answered"
}

type dashboardReport struct {
	Views      map[string]dashboardView `json:"views"`
	Dialogs    []string                 `json:"dialogs"`
	Violations []string                 `json:"violations"`
	Errors     []string                 `json:"errors"`
	Requests   []struct {
		Method string `json:"method"`
		Path   string `json:"path"`
		Status int    `json:"status"`
	} `json:"requests"`
	// Facts holds what a scenario's steps observed beyond the views, by name (e.g. "timeline",
	// the harness's timelineSteps).
	Facts map[string]json.RawMessage `json:"facts"`
}

// runHarness drives the dashboard served at base in testdata/dashboard_harness.js; env adds
// variables for it ("HARNESS_HASH=#/?detail=internet": the address the page opens at).
func runHarness(t *testing.T, base, scenario string, env ...string) dashboardReport {
	t.Helper()
	node := requireNode(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, filepath.Join("testdata", "dashboard_harness.js"), base, scenario)
	cmd.Env = append(append(os.Environ(), "HARNESS_MARKER="+hostileMarker), env...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("harness: %v\n%s", err, stderr.String())
	}
	var rep dashboardReport
	if err := json.Unmarshal(out, &rep); err != nil {
		t.Fatalf("harness output: %v\n%.2000s", err, out)
	}
	return rep
}

// runDashboard serves w on an ephemeral port and drives the dashboard against it in the
// harness; it fails the test on any markup-sink violation or script error.
func runDashboard(t *testing.T, w *demoWorld, scenario string) dashboardReport {
	t.Helper()
	requireNode(t)
	return runDashboardOn(t, newDemoServer(t, w, nil), scenario)
}

// runDashboardOn is runDashboard for a server the test built (e.g. one without some features).
func runDashboardOn(t *testing.T, srv *Server, scenario string) dashboardReport {
	t.Helper()
	requireNode(t)
	base, _ := startServer(t, srv)
	return checkedHarness(t, base, scenario)
}

// checkedHarness drives the dashboard at base in the harness (runHarness) and fails the test on
// any markup-sink violation or script error.
func checkedHarness(t *testing.T, base, scenario string, env ...string) dashboardReport {
	t.Helper()
	rep := runHarness(t, base, scenario, env...)
	for _, v := range rep.Violations {
		t.Errorf("markup/URL violation: %s", v)
	}
	for _, e := range rep.Errors {
		t.Errorf("script error: %s", e)
	}
	if len(rep.Views) == 0 {
		t.Fatal("the harness rendered no view")
	}
	return rep
}

// TestDashboardHarnessDetectsMarkupSinks: the harness must notice the mistakes it exists to
// catch (otherwise the tests above would pass vacuously).
func TestDashboardHarnessDetectsMarkupSinks(t *testing.T) {
	requireNode(t)
	unsafe := `'use strict';
const view = document.getElementById('view');
view.innerHTML = 'x <img src=x onerror=alert(1)>';
const a = document.createElement('a');
a.setAttribute('href', 'javascript:alert(1)');
a.setAttribute('onclick', 'alert(1)');
const b = document.createElement('a');
b.setAttribute('href', '//evil.example/');
view.append(a, b, document.createElement('img'));
view.insertAdjacentHTML('beforeend', '<b>x</b>');
document.write('<p>x</p>');
fetch('http://evil.example/x').catch(() => {});
`
	mux := http.NewServeMux()
	mux.HandleFunc("/static/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript")
		w.Write([]byte(unsafe))
	})
	mux.HandleFunc("/api/incidents", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("[]")) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	rep := runHarness(t, srv.URL, "hostile")
	for _, want := range []string{
		"innerHTML assigned", `unsafe href="javascript:alert(1)"`, `unsafe href="//evil.example/"`,
		"event-handler attribute onclick", "unexpected <img> element", "insertAdjacentHTML", "document.write",
		"request to another origin",
	} {
		if !slices.ContainsFunc(rep.Violations, func(v string) bool { return strings.Contains(v, want) }) {
			t.Errorf("the harness did not report %q; violations: %q", want, rep.Violations)
		}
	}
}

// TestDashboardHarnessModelsFocus: the harness keeps the keyboard focus as a browser does, so
// that a control which sends it back to the start of the page is noticed: an element takes it
// only when it can (a button, or an element with a tabindex; shown and not disabled), loses it
// to the body as soon as it is disabled, hidden or taken out of the page, keeps it while it is
// only aria-disabled, and gets it back when a modal dialog it opened closes.
func TestDashboardHarnessModelsFocus(t *testing.T) {
	requireNode(t)
	script := `'use strict';
const view = document.getElementById('view');
const say = (s) => view.append(document.createTextNode(s + ';'));
const on = () => { const e = document.activeElement; return e === document.body ? 'body' : e.textContent || e.localName; };
const b = document.createElement('button');
b.textContent = 'B';
const d = document.createElement('div');
view.append(b, d);
say('start ' + on());
b.focus(); say('focus ' + on());
b.disabled = true; say('disabled ' + on());
b.disabled = false; b.focus(); b.hidden = true; say('hidden ' + on());
b.hidden = false; b.focus(); view.hidden = true; say('inside hidden ' + on());
view.hidden = false; b.focus(); b.setAttribute('aria-disabled', 'true'); say('aria-disabled ' + on());
d.focus(); say('div ' + on());
d.setAttribute('tabindex', '-1'); d.focus(); say('div tabindex ' + on());
b.focus(); view.append(b); say('moved ' + on());
b.focus();
const dlg = document.createElement('dialog');
const ok = document.createElement('button');
ok.textContent = 'OK';
dlg.append(ok);
document.body.append(dlg);
dlg.showModal(); ok.focus(); say('dialog ' + on());
dlg.close('ok'); dlg.remove(); say('closed ' + on());
b.focus(); document.body.append(dlg); dlg.showModal(); ok.focus(); b.disabled = true; dlg.close('ok'); dlg.remove(); say('closed, opener disabled ' + on());
b.disabled = false; b.focus(); b.remove(); say('removed ' + on());
`
	mux := http.NewServeMux()
	mux.HandleFunc("/static/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript")
		w.Write([]byte(script))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	rep := runHarness(t, srv.URL, "overview")
	for _, e := range rep.Errors {
		t.Errorf("script error: %s", e)
	}
	want := "start body;focus B;disabled body;hidden body;inside hidden body;aria-disabled B;div B;div tabindex div;moved body;" +
		"dialog OK;closed B;closed, opener disabled body;removed body;"
	if got := rep.Views["overview"].Text; got != want {
		t.Errorf("focus as the harness keeps it:\n got %s\nwant %s", got, want)
	}
	if got := rep.Views["overview"].Focus; got != "body" {
		t.Errorf("the view reports the focus on %q, want body", got)
	}
}

// groupFP formats a fingerprint as the dashboard shows it ("49cd 292d ...").
func groupFP(fp string) string {
	var parts []string
	for i := 0; i < len(fp); i += 4 {
		parts = append(parts, fp[i:min(i+4, len(fp))])
	}
	return strings.Join(parts, " ")
}

// TestDashboardRendersHostileDataAsText renders every view from a world in which each
// remote-controlled string — gateway values and page names, DNS answers and rcodes, HTTP
// bodies and errors, Wi-Fi names, TSA names, traceroute statuses, notes, verification
// details, condition codes and messages, ledger records — ends in "<img src=x
// onerror=alert(1)>". The fake DOM records any use of an HTML or script sink; every view must
// show the marker as text (so the test would notice a view that silently dropped it).
func TestDashboardRendersHostileDataAsText(t *testing.T) {
	requireNode(t)
	w := newDemoWorldWith(time.Now(), hostileMarker)
	w.setPendingCert(demoNewCertSHA)
	w.mu.Lock()
	w.noAccessCode, w.anchorUntrusted = true, true
	w.mu.Unlock()
	rep := runDashboard(t, w, "hostile")

	// The Overview's summary and every card's details that show remote text (the traffic and the
	// evidence details show none: rates, counts, hashes and times only).
	want := []string{"overview", "overview status", "overview internet", "overview gateway", "overview fiber", "overview link",
		"overview network", "overview syslog", "overview monitor",
		"incidents", "incident export", "gateway", "syslog", "syslog more", "syslog severity", "syslog search",
		"network", "network device", "network search", "network tables", "network firewall",
		"evidence", "records", "records from genesis", "records config_state"}
	for name := range rep.Views {
		if strings.HasPrefix(name, "incident ") && name != "incident export" {
			want = append(want, name)
		}
	}
	if !slices.Contains(want, "incident "+model.CauseFiberLinkDown) {
		t.Errorf("no incident view rendered; views: %v", keys(rep.Views))
	}
	for _, name := range want {
		v, ok := rep.Views[name]
		if !ok {
			t.Errorf("view %q was not rendered", name)
			continue
		}
		if v.Markers == 0 {
			t.Errorf("view %q shows none of the hostile text, so this test would not notice it being parsed as markup", name)
		}
		// A card's details: the hostile text is in the details themselves.
		if key, ok := strings.CutPrefix(name, "overview "); ok && (v.Detail == nil || !v.Detail.Open || v.Detail.Key != key || v.Detail.Markers == 0) {
			t.Errorf("view %q: the %s details are not open or show none of the hostile text: %+v", name, key, v.Detail)
		}
	}
	// Every card's details were opened, the traffic and evidence ones too (their markup is
	// checked after every step all the same).
	for _, key := range []string{"traffic", "traffic 7d", "evidence"} {
		if v, ok := rep.Views["overview "+key]; !ok || v.Detail == nil || !v.Detail.Open {
			t.Errorf("the %s details were not opened", key)
		}
	}
	// The certificate banner and the Gateway page's certificate card are drawn from the
	// certificate state, next to the hostile condition message.
	for _, view := range []string{"overview", "gateway"} {
		for _, s := range []string{"Pinned until now: " + groupFP(demoCertSHA), "Presented now: " + groupFP(demoNewCertSHA)} {
			if !strings.Contains(rep.Views[view].Text, s) {
				t.Errorf("view %q does not show %q", view, s)
			}
		}
	}
	// Verification problems are worded (model.VerifyFailure.Problem), including the comparison of
	// record times with trusted time-stamps.
	for _, want := range []string{"line cannot be read", "record time contradicts a trusted time-stamp"} {
		if !strings.Contains(rep.Views["evidence"].Text, want) {
			t.Errorf("evidence view does not word a verification problem as %q", want)
		}
	}
	if v := rep.Views["gateway"].Text; !strings.Contains(v, "Pinned (trusted)"+groupFP(demoCertSHA)) ||
		!strings.Contains(v, "Presented nowwaiting for confirmation "+groupFP(demoNewCertSHA)) {
		t.Errorf("gateway certificate card not shown:\n%s", v)
	}
	// The hostile operator note and export were accepted and recorded as sent.
	for _, path := range []string{"/api/notes", "/api/exports", "/api/verify", "/api/anchor"} {
		if !slices.ContainsFunc(rep.Requests, func(r struct {
			Method string `json:"method"`
			Path   string `json:"path"`
			Status int    `json:"status"`
		}) bool {
			return r.Method == "POST" && r.Path == path && r.Status/100 == 2
		}) {
			t.Errorf("no successful POST %s", path)
		}
	}
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// viewChecker returns a function that fails the test unless the named view of rep shows every
// given text.
func viewChecker(t *testing.T, rep dashboardReport) func(view string, wants ...string) {
	return func(view string, wants ...string) {
		t.Helper()
		v, ok := rep.Views[view]
		if !ok {
			t.Errorf("view %q was not rendered (views: %v)", view, keys(rep.Views))
			return
		}
		for _, want := range wants {
			if !strings.Contains(v.Text, want) {
				t.Errorf("view %q does not show %q", view, want)
			}
		}
	}
}

// requested reports whether the dashboard made a request with the given method and path
// (including the query) that succeeded.
func requested(rep dashboardReport, method, path string) bool {
	for _, r := range rep.Requests {
		if r.Method == method && r.Path == path && r.Status/100 == 2 {
			return true
		}
	}
	return false
}

// pendingCertSeq returns the seq of the cert_changed record of the world's pending certificate.
func pendingCertSeq(w *demoWorld) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return strconv.FormatUint(w.certSeq, 10)
}

// TestDashboardCertificateAndAccountingViews renders the views changed for rules 2026.10-3
// and the gateway certificate policy, and confirms a changed certificate through the dialog.
func TestDashboardCertificateAndAccountingViews(t *testing.T) {
	requireNode(t)
	w := newDemoWorld(time.Now())
	w.setPendingCert(demoNewCertSHA)
	w.mu.Lock()
	w.noAccessCode, w.anchorUntrusted = true, true
	w.mu.Unlock()
	certSeq := pendingCertSeq(w)
	rep := runDashboard(t, w, "cert")
	contains := viewChecker(t, rep)

	// The certificate banner shows both fingerprints, since when and the evidence record from
	// the monitor's certificate state (Status.gateway_cert): the record is not read for it. It
	// and the access-code banner name every authenticated request the monitor makes, the NAT
	// table reads of the Network page included (they stop as well).
	contains("overview",
		"Gateway TLS certificate changed — authenticated actions paused",
		"Status pages are still read and recorded",
		"authenticated actions — checking or changing the gateway’s outage-redirect and Syslog settings, and reading its NAT table for the connections on the Network page — are paused",
		"Pinned until now: "+groupFP(demoCertSHA), "Presented now: "+groupFP(demoNewCertSHA),
		"Since ", "evidence record #"+certSeq,
		"Trust the new certificate",
		"No usable gateway access code", "att-monitor set-access-code",
		"only checking or changing the gateway’s settings (the outage redirect and the Syslog page) and reading its NAT table (the connections on the Network page) do",
		"Recent time-stamps could not be verified", "do not count as proof of time",
		"AT&T-attributed time without Internet", "Degraded")
	// What the status hero said is in the status card's details; the cards of before are the
	// details of the summary cards (the time accounting of the incidents is on the Incidents page,
	// below).
	contains("overview status", "Classified from: gateway snapshot #", "DNS & web check #", "local link #", "window of 6 cycles")
	contains("overview link", "86 % · -52 dBm")
	contains("overview internet", "TLS certificate "+demoGoogleCertSHA[:12])
	if len(rep.Dialogs) != 1 {
		t.Fatalf("dialogs: %q", rep.Dialogs)
	}
	for _, want := range []string{
		"Only confirm if AT&T updated your gateway (e.g. a firmware update) or you replaced it. Otherwise another device may be impersonating your gateway.",
		"New certificate (SHA-256): " + groupFP(demoNewCertSHA),
		"Pinned until now: " + groupFP(demoCertSHA),
		"Presented since ", "reported in evidence record #" + certSeq,
	} {
		if !strings.Contains(rep.Dialogs[0], want) {
			t.Errorf("confirmation dialog does not say %q:\n%s", want, rep.Dialogs[0])
		}
	}
	if requested(rep, "GET", "/api/records?from_seq="+certSeq+"&limit=1") {
		t.Error("the banner read the cert_changed record although the status carries the certificate state")
	}
	// The Gateway page always shows the pinned certificate; while another one waits, that one too.
	contains("gateway before trust", "Gateway TLS certificate", "Pinned (trusted)"+groupFP(demoCertSHA),
		"Presented nowwaiting for confirmation "+groupFP(demoNewCertSHA), "First presented", "Evidencerecord #"+certSeq,
		"Authenticated actions are paused", "not the pinned certificate",
		"The gateway presented an unconfirmed TLS certificate, so att-monitor will not log in to it")
	contains("gateway", "Pinned (trusted)"+groupFP(demoNewCertSHA), "Changed certificatenone waiting for confirmation",
		"(the pinned certificate)")
	if strings.Contains(rep.Views["gateway"].Text, "unconfirmed TLS certificate") {
		t.Error("the Gateway page still reports a certificate waiting for confirmation after it was trusted")
	}
	contains("overview after trust", "New gateway certificate trusted", groupFP(demoNewCertSHA), "authenticated gateway actions resume")
	if strings.Contains(rep.Views["overview after trust"].Text, "Gateway TLS certificate changed") {
		t.Error("certificate banner still shown after the confirmation")
	}
	w.mu.Lock()
	pinned, pending := w.pinnedCert, w.pendingCert
	w.mu.Unlock()
	if pinned != demoNewCertSHA || pending != "" {
		t.Errorf("after the confirmation: pinned %s pending %q", pinned, pending)
	}
	// The confirmation was sent with the fingerprint shown, by the web client.
	trusted := false
	for _, r := range rep.Requests {
		trusted = trusted || (r.Method == "POST" && r.Path == "/api/gateway/trust-cert" && r.Status == 200)
	}
	if !trusted {
		t.Error("no successful POST /api/gateway/trust-cert")
	}
	var cc model.ConfigChange
	found := false
	w.mu.Lock()
	for i := len(w.bodies) - 1; i >= 0 && !found; i-- {
		if w.bodies[i].Type == model.TypeConfigChange {
			found = json.Unmarshal(w.bodies[i].Data, &cc) == nil
		}
	}
	w.mu.Unlock()
	if !found || cc.After != demoNewCertSHA || cc.Actor != "operator via web" {
		t.Errorf("recorded config_change: %+v", cc)
	}

	contains("incidents", "3 of the last 6", "not counted as AT&T downtime", "Without Internet", "gateway restart 5 min 30 s", "degraded 16 min")
	contains("incident "+model.CauseGatewayReboot, "AT&T gateway restarted (detected from the gateway’s own uptime)",
		"Time accounting", "During gateway restarts", "5 min 30 s", "none outside gateway restarts",
		"Gateway restarts", "boot times estimated from the gateway’s own uptime", "Internet back",
		"not counted as AT&T downtime", "firmware changed across the restart", "gateway restart detected from its uptime")
	contains("incident "+model.CauseFiberLinkDown, "Without Internet", "27 min", "Internet back")
	contains("incident "+model.CauseLocalLinkDown, "not observed", "could not run", "IcmpSendEcho2",
		"pages not attempted (the gateway could not be reached)")
	contains("incident "+model.CausePacketLoss, "Degraded", "16 min", "(truncated)")
	contains("gateway", "No usable gateway access code", "no access code", "gateway local time")
	if v := rep.Views["gateway"]; !slices.ContainsFunc(v.Buttons, func(b dashboardButton) bool {
		return strings.HasPrefix(b.Text, "Turn redirect") && b.Disabled
	}) {
		t.Errorf("gateway setting buttons not disabled without a usable access code: %+v", v.Buttons)
	}
	contains("evidence", "Verification passed", "Each token’s signature and imprint were verified", "verified", "trusted root",
		// The time-stamp just obtained from an authority that does not chain to a trusted root.
		"yes, root not trusted", demoUntrustedChain)
	contains("records", "Verdict of this cycle", "Classified from: gateway snapshot #",
		"the authority’s certificate did not chain to a trusted root: "+demoUntrustedChain)
	contains("records from genesis", "Monitor started (service)", "incidents open on 3 bad of the last 6 cycles and close after 3 good ones",
		"measurement cycle every 10s")
	contains("records config_state", "config_state", "Configuration in force (recorded at the start of the day’s segment)",
		"rules "+demoRules, "configuration SHA-256 "+demoConfigSHA[:16], "incidents open on 3 bad of the last 6 cycles and close after 3 good ones")
}

// A status without the certificate state (an older monitor) still shows the changed
// certificate: the banner falls back to the condition's cert_changed record and message.
func TestDashboardCertificateFallsBackToConditionRecord(t *testing.T) {
	requireNode(t)
	w := newDemoWorld(time.Now())
	w.setPendingCert(demoNewCertSHA)
	w.mu.Lock()
	w.noGatewayCert = true
	w.mu.Unlock()
	certSeq := pendingCertSeq(w)
	rep := runDashboard(t, w, "cert")
	contains := viewChecker(t, rep)

	contains("overview", "Gateway TLS certificate changed — authenticated actions paused",
		"Pinned until now: "+groupFP(demoCertSHA), "Presented now: "+groupFP(demoNewCertSHA), "evidence record #"+certSeq)
	if !requested(rep, "GET", "/api/records?from_seq="+certSeq+"&limit=1") {
		t.Error("the banner did not read the cert_changed record")
	}
	contains("gateway before trust", "This monitor does not report its certificate pin.", "A changed certificate waits for confirmation",
		"The gateway presented an unconfirmed TLS certificate, so att-monitor will not log in to it")
	// Without a certificate state and with nothing pending, nothing is claimed about the pin
	// (the monitor leaves gateway_cert out while nothing is pinned).
	contains("gateway", "Pinned (trusted)none reported — the first certificate the gateway presents is pinned")
	if len(rep.Dialogs) != 1 || !strings.Contains(rep.Dialogs[0], "New certificate (SHA-256): "+groupFP(demoNewCertSHA)) {
		t.Fatalf("dialogs: %q", rep.Dialogs)
	}
	contains("overview after trust", "New gateway certificate trusted", groupFP(demoNewCertSHA))
	w.mu.Lock()
	pinned, pending := w.pinnedCert, w.pendingCert
	w.mu.Unlock()
	if pinned != demoNewCertSHA || pending != "" {
		t.Errorf("after the confirmation: pinned %s pending %q", pinned, pending)
	}
	if !requested(rep, "POST", "/api/gateway/trust-cert") {
		t.Error("no successful POST /api/gateway/trust-cert")
	}
}
