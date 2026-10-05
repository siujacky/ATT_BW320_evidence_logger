package ticket

import (
	"context"
	"fmt"
	"html/template"
	"regexp"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// Tests of the printed layout and wording that need no browser (pdf_test.go prints).

func renderText(t *testing.T, rep *Report) (string, string) {
	t.Helper()
	page, err := rep.HTML()
	if err != nil {
		t.Fatal(err)
	}
	return string(page), pageText(t, page)
}

// TestSegs: the values a line break must not split are kept whole; the text is unchanged.
func TestSegs(t *testing.T) {
	in := "From 2026-10-05 08:53:47 CDT (13:53:47 UTC) the outage INC-20261005-130457Z lasted 1 min 09 s; " +
		"Rx -31.5 dBm, 2.6 ms, the 24 h window, signal 82-84% on Wi-Fi (UTC-05:00 per its own clock), clock 2026-10-04T22:10:44, " +
		"the low-Rx ALARM, 5.15% and 34 °C; att-evidence_20261004T140000Z_20261005T140000Z_6961b23f.zip"
	var joined strings.Builder
	var kept []string
	for _, s := range segs(in) {
		joined.WriteString(s.T)
		if s.N {
			kept = append(kept, s.T)
		}
	}
	if joined.String() != in {
		t.Fatalf("segs changed the text:\n%s", joined.String())
	}
	want := []string{"2026-10-05 08:53:47 CDT", "13:53:47 UTC", "INC-20261005-130457Z", "1 min 09 s", "-31.5 dBm", "2.6 ms", "24 h",
		"82-84%", "Wi-Fi", "UTC-05:00", "2026-10-04T22:10:44", "low-Rx", "34 °C"}
	if strings.Join(kept, "|") != strings.Join(want, "|") {
		t.Errorf("kept whole:\n%q\nwant\n%q", kept, want)
	}
	// Longer values (the bundle name) stay breakable, so they can never widen a column; with a
	// hyphen, they wrap where the line is full, not after the hyphen (a PDF reader drops a
	// line-final hyphen from copied text).
	for _, s := range segs(in) {
		if s.N && len(s.T) > maxNoWrap {
			t.Errorf("%q kept whole", s.T)
		}
		if s.A != strings.HasPrefix(s.T, "att-evidence_") {
			t.Errorf("%q: break anywhere = %v", s.T, s.A)
		}
	}
	// In the page, a timestamp is one no-wrap span.
	s := realScenario(t)
	page, _ := renderText(t, mustBuild(t, s, s.options()))
	wantContains(t, "html", page, `<span class="nw">2026-10-05 07:45:47 CDT</span>`, `<span class="nw">UTC-05:00</span>`)
}

// TestCSSString: the page identity goes into the CSS margin boxes with only letters and digits
// unescaped, and html/template passes it through unchanged.
func TestCSSString(t *testing.T) {
	got := cssString(`AT&T "x" </style> url(a) @import \ é 1`)
	want := `"AT\000026T\000020\000022x\000022\000020\00003c\00002fstyle\00003e\000020url\000028a\000029\000020\000040import\000020\00005c\000020\0000e9\0000201"`
	if string(got) != want {
		t.Errorf("cssString = %s\nwant       %s", got, want)
	}
	tmpl := template.Must(template.New("x").Parse(`<style>@page { @bottom-left { content: {{.}}; } }</style>`))
	var b strings.Builder
	if err := tmpl.Execute(&b, got); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "content: "+want+";") {
		t.Errorf("html/template changed the value: %s", b.String())
	}
}

// TestPageOneBounded: on a bad day (16 provider outages with fiber flaps, two restarts) the summary
// sheet stays bounded - no list of every incident - and keeps to one page: the evidence brief moves
// to the details when the sheet would not fit with it.
func TestPageOneBounded(t *testing.T) {
	ss := stressScenario(t)
	o := ss.options()
	o.Customer = stressCustomer()
	o.Verification = cliVerification
	rep := mustBuild(t, ss, o)
	if n := len(rep.Incidents); n != 16 {
		t.Fatalf("%d incidents", n)
	}
	action := rep.Action.String()
	wantContains(t, "action", action, "including during 16 outages attributed to AT&T (see the summary)")
	if n := strings.Count(action, "INC-"); n != 0 {
		t.Errorf("the requested action names %d incidents:\n%s", n, action)
	}
	link := rep.Bullet("link").String()
	wantContains(t, "link", link, "fiber link state changes not at a gateway restart; the gateway also restarted twice.",
		"During monitoring the optical link changed state 16 times (gateway_event optical_link_change #",
		"and 13 more), 16 of them during 16 outages.",
		"The gateway events table lists each with its time.")
	wantNotContains(t, "link", link, "(s)")
	outages := rep.Bullet("outages").String()
	wantContains(t, "outages", outages, "16 incidents attributed to AT&T (INC-20261004-154000Z to INC-20261005-130000Z; see Incidents)")
	for _, b := range append(rep.Summary, rep.Action) {
		if n := strings.Count(b.String(), "INC-"); n > 3 {
			t.Errorf("%s names %d incidents", b.Key, n)
		}
	}
	v := rep.view()
	if v.BriefOnPage1 || v.pageOneHeight(false) > p1Usable || v.DetailsFlow {
		t.Errorf("page 1: brief %v, estimated %.0f pt without it (usable %.0f), details flow %v", v.BriefOnPage1, v.pageOneHeight(false), p1Usable, v.DetailsFlow)
	}
	html, text := renderText(t, rep)
	// No pointer line is left behind: it was what overflowed onto a page of its own.
	wantNotContains(t, "page 1", text, "are listed under Evidence and integrity")
	if strings.Contains(html, `<table class="brief">`) {
		t.Error("the evidence brief is still on page 1")
	}
	// The events table lists every link change: one row per observation, the events of the same
	// two snapshots together.
	if n := len(eventGroups(rep.Events)); n != 18 || n > maxEventRows {
		t.Errorf("%d event rows", n)
	}

	// The calm real situation keeps its brief on page 1.
	s := realScenario(t)
	if v := mustBuild(t, s, s.options()).view(); !v.BriefOnPage1 {
		t.Errorf("real situation: brief moved (estimate %.0f pt)", v.pageOneHeight(true))
	}
}

// TestPageOneEstimate checks the line estimate against what Edge prints.
func TestPageOneEstimate(t *testing.T) {
	// Measured in Edge's print layout: these paragraphs print on 5 and 6 lines.
	for _, tc := range []struct {
		lead, text string
		lines      float64
	}{
		{"The gateway's own low-Rx optical ALARM is active.", "AT&T's gateway reported an optical receive (Rx) power between -31.5 and -30.9 dBm in 76 readings from 2026-10-04 22:10 CDT (2026-10-05 03:10 UTC) to 2026-10-05 08:59 CDT (13:59 UTC) (latest -31.3 dBm, snapshot #536). The first is the setup-time capture, made before monitoring began. Its own low-Rx ALARM threshold is -29.5 dBm and its WARNING threshold is -29.2 dBm: the ALARM flag was set in 76 of 76 readings (100%) and the WARNING flag in 76 of 76 (100%). Every reading was below both thresholds.", 5},
		{"Please dispatch a technician to check the fiber connection.", "The gateway reports a received optical level below its own low-Rx threshold. Please measure the optical light level at the gateway's fiber port and at the fiber terminal / NID, and clean or repair the fiber connection, jumper or drop as needed until the gateway's low-Rx alarm clears. The fiber link also changed state without a gateway restart, including during the outage INC-20261005-130457Z attributed to AT&T (see the summary). Gateway: NOKIA BGW320-505, serial number N98XX0XX664683, firmware 6.34.7 (from snapshot #1057). AT&T should be able to confirm the low receive level and the link events in its own telemetry for this device.", 6},
	} {
		if got := wrapLines(tc.lead, tc.text, p1Width-17, p1Body); got < tc.lines || got > tc.lines+1 {
			t.Errorf("%q: estimated %v lines, printed %v", tc.lead, got, tc.lines)
		}
	}
	// A word longer than the line wraps anywhere.
	if got := wrapLines("", strings.Repeat("TICKET", 40), 200, 10); got < 7 {
		t.Errorf("unbreakable word: %v lines", got)
	}
	if wrapWords("from 2026-10-05 08:53:47 CDT to")[1] != "2026-10-05 08:53:47 CDT" {
		t.Errorf("wrapWords = %q", wrapWords("from 2026-10-05 08:53:47 CDT to"))
	}
}

// TestCustomerBox: blank fields are fill-in lines with room to write; long values get a row of
// their own across the box.
func TestCustomerBox(t *testing.T) {
	rows := customerRows(Customer{})
	if len(rows) != 3 || len(rows[0]) != 2 {
		t.Errorf("blank: %+v", rows)
	}
	rows = customerRows(stressCustomer())
	if len(rows) != 4 || len(rows[1]) != 1 || !rows[1][0].Wide || rows[1][0].Label != "Service address" || !rows[3][0].Wide || rows[3][0].Label != "Notes / ticket number" {
		t.Errorf("long values: %+v", rows)
	}
	s := realScenario(t)
	html, _ := renderText(t, mustBuild(t, s, s.options()))
	// 2 em at 9.5 pt plus the row padding: a writing line every 8.5 mm (college ruling is 7.1 mm).
	wantContains(t, "css", html, ".fill { display: inline-block; width: 100%; height: 2em;")
	o := s.options()
	o.Customer = stressCustomer()
	html, text := renderText(t, mustBuild(t, s, o))
	wantContains(t, "long values", html, `<td colspan="3">12345 North Example Boulevard`)
	wantContains(t, "long values", text, stressCustomer().Notes)
}

// TestChartCaption: the caption says what the table lists (it said "Every value is in the table
// below" while the table listed 30 of 76 readings).
func TestChartCaption(t *testing.T) {
	s := realScenario(t)
	rep := mustBuild(t, s, s.options())
	n := len(rep.Optical.Readings)
	_, text := renderText(t, rep)
	wantContains(t, "caption", text, fmt.Sprintf("The table below lists %d of the %d readings (the selection is explained under it); every reading is in the bundle.", MaxChartTableRows, n),
		fmt.Sprintf("%d of %d readings are listed: the first, the latest, the lowest, the highest and the setup capture", MaxChartTableRows, n),
		"The setup-time capture of 2026-10-04 22:10:46 CDT (2026-10-05 03:10:46 UTC), Rx -31.5 dBm with the gateway's low-Rx ALARM and WARNING flags set, is marked on the bar.")
	wantNotContains(t, "caption", text, "Every value is in the table below", "Every reading is listed in the table below")
	if len(rep.Optical.Rows) != MaxChartTableRows {
		t.Errorf("%d rows with a chart", len(rep.Optical.Rows))
	}
	// Few readings: all listed, and the caption says so.
	f := newFake(t)
	at := ts("2026-10-05T13:00:00Z")
	for i := 0; i < 5; i++ {
		f.add(at.Add(time.Duration(i)*time.Minute), model.TypeGatewaySnapshot, snapshot(at.Add(time.Duration(i)*time.Minute), -312, true, true, 400000, lastChange))
	}
	rep, err := Build(context.Background(), f, Options{From: at.Add(-time.Minute), To: at.Add(10 * time.Minute), Now: func() time.Time { return at.Add(10 * time.Minute) }, Location: cdt})
	if err != nil {
		t.Fatal(err)
	}
	_, text = renderText(t, rep)
	wantContains(t, "caption", text, "Every reading is listed in the table below.")
}

// TestIncidentRow: each figure once, from the incident record's fields; the monitor's free-text
// summary (which rounded 69 s to "1m10s") is not repeated.
func TestIncidentRow(t *testing.T) {
	fs := newFlapScenario(t)
	fs.inc.Summary = "ISP outage from 13:04:57 to 13:06:07 (1m9s), cause FIBER_LINK_DOWN. Measured time: 1m10s without Internet."
	fs.f.add(fs.now.Add(-time.Minute), model.TypeIncidentClose, fs.inc)
	rep, err := Build(context.Background(), fs.f, Options{From: fs.from, To: fs.to, Now: func() time.Time { return fs.now }, Location: cdt})
	if err != nil {
		t.Fatal(err)
	}
	_, text := renderText(t, rep)
	wantContains(t, "incidents", text, "INC-20261005-130457Z", "opened 2026-10-05 08:04:57 CDT (13:04:57 UTC)", "closed 2026-10-05 08:06:07 CDT (13:06:07 UTC)",
		"1 min 09 s in total", "1 min 09 s without Internet", "ISP_OUTAGE / FIBER_LINK_DOWN / attribution provider", "also seen: ISP_EDGE_UNREACHABLE")
	wantNotContains(t, "incidents", text, "1m10s", "1m9s", "Measured time")
}

// TestSetupCaptureRow: the capture's Last Change is shown with both of its readings (it was
// shown only "read as UTC").
func TestSetupCaptureRow(t *testing.T) {
	s := realScenario(t)
	_, text := renderText(t, mustBuild(t, s, s.options()))
	wantContains(t, "setup", text, "Fiber Last Change in the capture 1791151188: 2026-10-04 21:59:48 UTC if the gateway counts in UTC, or 2026-10-05 02:59:48 UTC if in its local time (UTC-05:00 per its own clock); the gateway does not say which")
	wantNotContains(t, "setup", text, "read as UTC:")
	// With a change that can only be read as UTC, the row says so.
	ss := stressScenario(t)
	rep := mustBuild(t, ss, ss.options())
	if rep.Link.Confirmed != "UTC" {
		t.Fatalf("confirmed %q", rep.Link.Confirmed)
	}
	_, text = renderText(t, rep)
	wantContains(t, "setup", text, "The change in "+rep.Link.ConfirmedBy+" can only be read as UTC, which supports that reading of this value too")
}

// TestVerifyCommands: commands wrap only between their arguments (they wrapped inside hashes and
// paths, so a copied command was broken).
func TestVerifyCommands(t *testing.T) {
	s := realScenario(t)
	rep := mustBuild(t, s, s.options())
	html, text := renderText(t, rep)
	a := rep.Evidence.Anchor
	wantContains(t, "verify", html, `<span class="arg">-digest `+a.HeadHash+`</span>`, `<span class="arg">-in blobs/`+a.Token+`</span>`,
		`<span class="arg">--expect-fingerprint `+rep.Evidence.Fingerprint+`</span>`, ".code .arg { display: inline-block;")
	wantContains(t, "verify", text, "Each command is one line; it is wrapped here only between its arguments. README.txt in the evidence bundle describes the same checks.")
	wantContains(t, "css", html, ".code .arg { display: inline-block; max-width: 100%; word-break: break-all; }")
	checkBreakAll(t, styleText(t, []byte(html)))
}

// TestWording: the printed wording errors of the review.
func TestWording(t *testing.T) {
	// "1 further incident are not listed", "#8 (snapshots #7)", "during the outage A, B and C".
	ss := stressScenario(t)
	rep := mustBuild(t, ss, ss.options())
	_, text := renderText(t, rep)
	wantContains(t, "stress", text, "1 further incident is not listed here (it is in the bundle).")
	wantNotContains(t, "stress", text, "further incident are", "during the outage INC")
	for _, b := range append(rep.Summary, rep.Action) {
		wantNotContains(t, b.Key, b.String(), "(s)")
	}
	s := realScenario(t)
	rep = mustBuild(t, s, s.options())
	_, text = renderText(t, rep)
	wantContains(t, "real", text, "snapshot #7", "1 gateway event about this monitor's own operation (certificate pinning, the gateway's notification setting) is not listed.",
		"cycle interval from the configuration record #2", "signal 82-84% (8 readings, latest local_link #506, its RSSI -58 dBm)")
	wantNotContains(t, "real", text, "snapshots #7)", "later readings after it", ") (", "interval from the default (")
	if regexp.MustCompile(`\(\w[^()]*\([^()]*\)\)`).FindString(rep.Coverage.Statement) != "" {
		t.Errorf("nested parentheses: %s", rep.Coverage.Statement)
	}
	// A window shown in UTC is not repeated in UTC.
	o := s.options()
	o.Location = time.UTC
	_, text = renderText(t, mustBuild(t, s, o))
	wantContains(t, "utc", text, "Window: 2026-10-04 14:00:00 UTC to 2026-10-05 14:00:00 UTC Generated")
	// Without a configuration record the interval basis has no nested parentheses.
	f := newFake(t)
	at := ts("2026-10-05T10:00:00Z")
	for i := 0; i < 5; i++ {
		f.add(at.Add(time.Duration(i)*10*time.Second), model.TypeSample, sample(uint64(i+1), at.Add(time.Duration(i)*10*time.Second), model.StateOnline, model.AttrNone, true, 2500, true, ""))
	}
	rep, err := Build(context.Background(), f, Options{From: at, To: at.Add(time.Hour), Now: func() time.Time { return at.Add(time.Hour) }, Location: cdt})
	if err != nil {
		t.Fatal(err)
	}
	_, text = renderText(t, rep)
	wantContains(t, "default", text, "cycle interval from the median spacing of the samples, as no configuration record is in the window")
}

// TestStatedInputs: the bundle's name, SHA-256 and verification result are stated by the
// program that generated the report; the report says so (it claimed every figure was computed
// from the records).
func TestStatedInputs(t *testing.T) {
	s := realScenario(t)
	_, text := renderText(t, mustBuild(t, s, s.options()))
	wantContains(t, "page", text, "Evidence bundle* att-evidence_", "Bundle SHA-256* ", "Verification* OK: 512 records",
		"* Stated by att-monitor test when it generated this report; every other figure is computed from the signed ledger records it names (in the evidence bundle).")
	wantNotContains(t, "page", text, "Ledger signing key*", "Every figure in this report is computed")
	// Without stated inputs, nothing is marked.
	o := s.options()
	o.BundleName, o.BundleSHA256, o.Verification = "", "", ""
	_, text = renderText(t, mustBuild(t, s, o))
	wantContains(t, "page", text, "Every figure in this report is computed from the signed ledger records it names")
	wantNotContains(t, "page", text, "*")
}

// TestSetupTables: the capture's tables are separated and captioned (they read as one broken
// table).
func TestSetupTables(t *testing.T) {
	s := realScenario(t)
	rep := mustBuild(t, s, s.options())
	html, text := renderText(t, rep)
	wantContains(t, "css", html, "table + table, table + p + table { margin-top: 6pt; }")
	wantContains(t, "setup", text, "Gateway pages in the capture Captured page File time SHA-256 In a time-stamped manifest",
		"initial-snapshot/fiberstat.anon.html 2026-10-05 03:10:46 UTC", "listed in BOOTSTRAP-MANIFEST.sha256",
		"RFC 3161 time-stamp tokens imported with the capture Token Authority genTime stated in the token Covers (by SHA-256)")
	for _, p := range rep.view().Setup.Pages {
		if p.Listed != "listed in BOOTSTRAP-MANIFEST.sha256" {
			t.Errorf("%s: %s", p.Path, p.Listed)
		}
	}
}

// TestChartStyle: ALARM and WARNING differ in grayscale too (dash pattern, and full blocks against
// a thin line in the strips), and chart text is at least 10 px (about 7.4 pt printed).
func TestChartStyle(t *testing.T) {
	s := realScenario(t)
	html, _ := renderText(t, mustBuild(t, s, s.options()))
	wantContains(t, "css", html, "svg.chart .ref.alarm { stroke: var(--critical); stroke-dasharray: 8 4; }",
		"svg.chart .ref.warning { stroke: var(--warning); stroke-dasharray: 0.1 4;", "svg.chart text { font-family: \"Segoe UI\", system-ui, Arial, sans-serif; font-size: 10px;",
		`height="2"><title>Gateway readings`)
	if regexp.MustCompile(`font-size: [1-9](\.\d+)?px`).FindString(html) != "" {
		t.Error("chart text below 10 px")
	}
}

// TestParentheses: no summary text has adjacent parentheses ("(13:59 UTC) (latest ...)") or a
// parenthesis inside another (the review found both).
func TestParentheses(t *testing.T) {
	fs := newFlapScenario(t)
	flap, err := Build(context.Background(), fs.f, Options{From: fs.from, To: fs.to, Now: func() time.Time { return fs.now }, Location: cdt})
	if err != nil {
		t.Fatal(err)
	}
	s, ss, ev, cs := realScenario(t), stressScenario(t), eveningScenario(t), clearedScenario(t)
	empty := s.options()
	empty.From, empty.To = ts("2026-10-03T00:00:00Z"), ts("2026-10-04T00:00:00Z")
	for name, rep := range map[string]*Report{"real": mustBuild(t, s, s.options()), "stress": mustBuild(t, ss, ss.options()),
		"evening": mustBuild(t, ev, ev.options()), "empty": mustBuild(t, s, empty), "flap": flap, "cleared": mustBuild(t, cs, cs.options())} {
		texts := []string{rep.Action.String(), rep.Coverage.Statement}
		for _, b := range rep.Summary {
			texts = append(texts, b.String())
		}
		for _, text := range texts {
			if strings.Contains(text, ") (") {
				t.Errorf("%s: adjacent parentheses in %q", name, text)
			}
			depth := 0
			for _, c := range text {
				switch c {
				case '(':
					if depth++; depth > 1 {
						t.Errorf("%s: nested parentheses in %q", name, text)
					}
				case ')':
					depth--
				}
			}
		}
	}
}

// TestTitle: the title names the window's length and end (it said "last 24 hours" whenever the
// report was read).
func TestTitle(t *testing.T) {
	for d, want := range map[time.Duration]string{24 * time.Hour: "24 hours", time.Hour: "1 hour", 330 * time.Minute: "5.5 hours",
		42*time.Minute + 30*time.Second: "42 minutes", 30 * time.Second: "less than a minute"} {
		if got := windowPhrase(d); got != want {
			t.Errorf("windowPhrase(%v) = %q, want %q", d, got, want)
		}
	}
	if got := fmtTitleTime(ts("2026-10-05T14:44:50Z"), cdt); got != "2026-10-05 09:44 CDT" {
		t.Errorf("fmtTitleTime = %q", got)
	}
}
