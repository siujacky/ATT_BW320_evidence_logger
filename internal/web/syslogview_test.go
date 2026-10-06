package web

// The dashboard's gateway syslog and traffic (docs/syslog-snmp-traffic.md §3.2-§3.3): the
// Overview card, the Syslog page and its filters, an incident's syslog, the Traffic chart and
// the WAN volume per day, rendered by the real script from the demo world; and the wording and
// escaping helpers of app.js under Node.js.

import (
	"encoding/json"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/model"
)

func TestDashboardShowsSyslogAndTraffic(t *testing.T) {
	requireNode(t)
	w := newDemoWorld(time.Now())
	rep := runDashboard(t, w, "plain")
	contains := viewChecker(t, rep)
	bs := string(rune(0x5c)) // a backslash: escapes are shown as typed

	// The Overview card: the receiver, its counters, the last message, the gateway's setting and
	// the record of its latest check; this version only reads the setting, and says so.
	w.mu.Lock()
	checkSeq := w.syslogCheck.Seq
	w.mu.Unlock()
	contains("overview", "Gateway syslog", "Receiverlistening on UDP 0.0.0.0:514", " received · ", " recorded · 0 dropped · 7 from other senders",
		"Gateway settingon sends to 192.168.1.71:514 (this PC) · level Informational", "record #"+strconv.FormatUint(checkSeq, 10),
		"att-monitor only reads this setting; it does not change it yet. To receive the gateway’s log, turn Syslog on in the gateway’s Diagnostics › Syslog page with server 192.168.1.71 and port 514.")

	// History: the Traffic chart (WAN download and upload with their peaks, this computer, the
	// heavy-traffic line) with its table view, and the WAN volume per day.
	contains("overview", "Traffic", "WAN download", "WAN upload", "This PC download", "This PC upload",
		"peak: the highest rate between two readings in the bucket", "Heavy household traffic 80 Mb/s",
		"WAN download peak (Mb/s)", "This PC upload (Mb/s)", "WAN volume per day", "(today, so far)", "Time counted")
	ov := rep.Views["overview"]
	if ov.Marks["peak"] == 0 || ov.Marks["ref"] != 1 || ov.Marks["atleast"] != 0 {
		t.Errorf("overview chart marks: %v", ov.Marks)
	}
	if rows := rowsWith(ov, regexp.MustCompile(`partial$`)); len(rows) == 0 || !slices.Equal(rows[0].Chips, []string{"warning:partial"}) {
		t.Errorf("no partial day in the WAN volume: %+v", rowsWith(ov, regexp.MustCompile(`GB`)))
	}
	// Over 7 days the big download's rates are "at least": marked, explained and in the table.
	wk := rep.Views["overview 7d"]
	contains("overview 7d", "at least: the true rate may have been higher", "Chevron: the gateway’s 32-bit byte counter may have wrapped more often than can be told")
	if wk.Marks["atleast"] == 0 || len(rowsWith(wk, regexp.MustCompile(`at least \d{3} Mb/s`))) == 0 {
		t.Errorf("7 days: %d chevrons, %d table rows with \"at least\"", wk.Marks["atleast"], len(rowsWith(wk, regexp.MustCompile(`at least \d`))))
	}

	// The Syslog page: the newest 200 messages, with what a sender controls shown as received:
	// escapes for the control and bidirectional characters, line breaks as \n, the bytes of a
	// datagram that is not UTF-8, a datagram without a PRI.
	contains("syslog", "Gateway syslog", "The newest 200 messages recorded from", "more were recorded in this period",
		bs+"x1b[1;31mWAN link flap"+bs+"x1b[0m detected on wan0",
		"DHCPACK on 192.168.1.80 to 02:00:00:00:00:80 ("+bs+"u202egpj.exe"+bs+"u202c) via br0",
		"Inform to the ACS failed:"+bs+"nHTTP 503 Service Unavailable"+bs+"nretry in 60 s",
		"Bytes (base64)", "Not valid UTF-8: the exact bytes received, base64-encoded.",
		"BGW320-505 watchdog: heartbeat ok", "Prioritynone in the datagram",
		"Exact datagram · record #", "RFC 3164 (BSD syslog)", "RFC 5424", "as the gateway wrote it", "ledger record #")
	sl := rep.Views["syslog"]
	if n := len(rowsWith(sl, regexp.MustCompile(`Exact datagram`))); n != DefaultSyslogLimit {
		t.Errorf("syslog page: %d message rows, want %d", n, DefaultSyslogLimit)
	}
	for _, chip := range []string{"none:Info", "info:Notice", "warning:Warning"} {
		if !slices.ContainsFunc(sl.Rows, func(r dashboardRow) bool { return slices.Contains(r.Chips, chip) }) {
			t.Errorf("syslog page: no %s severity chip", chip)
		}
	}
	if rows := rowsWith(sl, regexp.MustCompile(`watchdog: heartbeat ok`)); len(rows) != 1 || len(rows[0].Chips) != 0 || !strings.Contains(rows[0].Text, "—") {
		t.Errorf("message without a severity: %+v", rows)
	}
	contains("syslog more", "The newest 400 messages recorded from")
	if n := len(rowsWith(rep.Views["syslog more"], regexp.MustCompile(`Exact datagram`))); n != 2*DefaultSyslogLimit {
		t.Errorf("after Load more: %d message rows", n)
	}
	// Filters: error and more severe only; then the text.
	sev := rowsWith(rep.Views["syslog severity"], regexp.MustCompile(`Exact datagram`))
	if len(sev) == 0 {
		t.Error("severity filter: no messages")
	}
	for _, r := range sev {
		if len(r.Chips) != 1 || !(strings.HasPrefix(r.Chips[0], "critical:") || strings.HasPrefix(r.Chips[0], "serious:")) {
			t.Errorf("severity filter let through %q (%v)", r.Text, r.Chips)
		}
	}
	found := rowsWith(rep.Views["syslog search"], regexp.MustCompile(`Exact datagram`))
	if len(found) == 0 {
		t.Error("search: no messages")
	}
	for _, r := range found { // in the message, the host or the app ("ponlinkd"), ignoring case
		if !strings.Contains(strings.ToLower(r.Text), "pon") {
			t.Errorf("search for PON shows %q", r.Text)
		}
	}
	if !slices.ContainsFunc(rep.Requests, func(r struct {
		Method string `json:"method"`
		Path   string `json:"path"`
		Status int    `json:"status"`
	}) bool {
		return strings.HasPrefix(r.Path, "/api/syslog?") && strings.Contains(r.Path, "q=PON") && r.Status == 200
	}) {
		t.Error("the search did not ask the server")
	}

	// Incidents: the gateway's own account of the fiber outage; nothing during the high latency.
	contains("incident "+model.CauseFiberLinkDown, "Gateway syslog around this incident",
		"from 5 minutes before the incident opened to 5 minutes after it closed",
		"PON link state O5 -> O1 (loss of signal)", "PON link state O1 -> O5 (operation)", "Broadband connection down (PON link lost)")
	contains("incident "+model.CauseHighLatency, "Gateway syslog around this incident", "No syslog messages were received in this period.")

	// The ledger: the syslog batches, worded.
	contains("records", "Gateway syslog: ")
}

// The card's other states, as the monitor reports them (Status.syslog).
func TestDashboardSyslogCardStates(t *testing.T) {
	requireNode(t)
	for state, wants := range map[string][]string{
		"off":       {"Gateway settingoff the gateway sends no syslog messages"},
		"elsewhere": {"Gateway settingsends elsewhere to 192.168.1.20:1514 · level Debug, not to this PC"},
		"error":     {"could not be read gateway: login throttled", "Last read: on, sends to 192.168.1.71:514 · level Informational"},
		"unknown":   {"Gateway settingnot read yet", "the daily settings check has not read the gateway's Syslog page yet"},
		"enforce":   {"att-monitor keeps the gateway sending its log to 192.168.1.71:514"},
		"nolisten":  {"Receivernot listening listen udp 0.0.0.0:514: bind: Only one usage of each socket address"},
		"disabled":  {"Receiveroff turned off in the configuration (syslog.enabled)"},
	} {
		t.Run(state, func(t *testing.T) {
			w := newDemoWorld(time.Now())
			w.mu.Lock()
			w.syslogState = state
			w.mu.Unlock()
			rep := runDashboard(t, w, "overview")
			viewChecker(t, rep)("overview", wants...)
		})
	}
	// A monitor without a receiver: no card.
	w := newDemoWorld(time.Now())
	w.mu.Lock()
	w.syslogState = "none"
	w.mu.Unlock()
	rep := runDashboard(t, w, "overview")
	if strings.Contains(rep.Views["overview"].Text, "Gateway syslog") {
		t.Error("a card for a monitor that reports no syslog receiver")
	}
	viewChecker(t, rep)("syslog", "This monitor reports no syslog receiver")
}

// TestAppJSVisibleText runs hiddenChar, charEscape, visibleText and escapedText from app.js:
// every character that would act on the display instead of showing is written as an escape,
// in a span of its own; everything else is kept as received.
func TestAppJSVisibleText(t *testing.T) {
	prog := jsProgram(t, nil, []string{"hiddenChar", "charEscape", "visibleText", "escapedText"})
	// A stand-in for h(): a span as [class, title, text].
	prog += `function h(tag, props, text) { return [props.class, props.title, text]; }
const C = (n) => String.fromCharCode(n);
const cases = [
  'plain text, ' + C(0xe9) + ' and ' + C(0x65e5) + C(0x672c),
  C(0x1b) + '[31mred' + C(0x1b) + '[0m',
  'a' + C(0x202e) + 'gpj.exe' + C(0x202c) + 'b',
  'one' + C(0x0a) + 'two' + C(0x09) + 'three' + C(0x0d),
  C(0x00) + C(0x7f) + C(0x85) + C(0x9f) + C(0xa0) + C(0x200b) + C(0x2028) + C(0x2066) + C(0xfeff) + C(0xfffd),
];
console.log(JSON.stringify({
  visible: cases.map((t) => visibleText(t)),
  pretty: visibleText('{' + C(0x0a) + '  "a": 1' + C(0x0a) + '}', true),
  escaped: cases.map(escapedText),
}));
`
	var got struct {
		Visible [][]any  `json:"visible"`
		Pretty  []any    `json:"pretty"`
		Escaped []string `json:"escaped"`
	}
	if err := json.Unmarshal(runNode(t, prog), &got); err != nil {
		t.Fatal(err)
	}
	bs := string(rune(0x5c))
	span := func(text, code string) []any { return []any{"ctl", "U+" + code, text} }
	want := [][]any{
		{"plain text, " + string(rune(0xe9)) + " and " + string(rune(0x65e5)) + string(rune(0x672c))},
		{span(bs+"x1b", "001B"), "[31mred", span(bs+"x1b", "001B"), "[0m"},
		{"a", span(bs+"u202e", "202E"), "gpj.exe", span(bs+"u202c", "202C"), "b"},
		{"one", span(bs+"n", "000A"), "two", span(bs+"t", "0009"), "three", span(bs+"r", "000D")},
		{span(bs+"x00", "0000"), span(bs+"x7f", "007F"), span(bs+"x85", "0085"), span(bs+"x9f", "009F"), string(rune(0xa0)),
			span(bs+"u200b", "200B"), span(bs+"u2028", "2028"), span(bs+"u2066", "2066"), span(bs+"ufeff", "FEFF"), string(rune(0xfffd))},
	}
	for i := range want {
		if !jsonEqual(got.Visible[i], want[i]) {
			g, _ := json.Marshal(got.Visible[i])
			w, _ := json.Marshal(want[i])
			t.Errorf("visibleText case %d:\n got %s\nwant %s", i, g, w)
		}
	}
	if !jsonEqual(got.Pretty, []any{"{\n  \"a\": 1\n}"}) {
		t.Errorf("visibleText keeping line breaks: %v", got.Pretty)
	}
	for i, w := range []string{
		"plain text, " + string(rune(0xe9)) + " and " + string(rune(0x65e5)) + string(rune(0x672c)),
		bs + "x1b[31mred" + bs + "x1b[0m",
		"a" + bs + "u202egpj.exe" + bs + "u202cb",
		"one" + bs + "ntwo" + bs + "tthree" + bs + "r",
		bs + "x00" + bs + "x7f" + bs + "x85" + bs + "x9f" + string(rune(0xa0)) + bs + "u200b" + bs + "u2028" + bs + "u2066" + bs + "ufeff" + string(rune(0xfffd)),
	} {
		if got.Escaped[i] != w {
			t.Errorf("escapedText case %d = %q, want %q", i, got.Escaped[i], w)
		}
	}
}
