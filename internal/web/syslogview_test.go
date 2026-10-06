package web

// The dashboard's gateway syslog and traffic (docs/syslog-snmp-traffic.md §3.2-§3.3): the
// Overview card, the flow meter and the MRTG-style Traffic chart, the Syslog page with the
// syslog store's use, the choice of how much to keep, the messages and their filters, an
// incident's syslog, the WAN volume per day, rendered by the real script from the demo world;
// and the wording and escaping helpers of app.js under Node.js.

import (
	"encoding/json"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/model"
)

// liveRequests counts the flow meter's requests among the first n requests of a dashboard run.
func liveRequests(rep dashboardReport, n int) int {
	count := 0
	for _, r := range rep.Requests[:min(n, len(rep.Requests))] {
		if r.Path == "/api/traffic/live" {
			count++
		}
	}
	return count
}

func TestDashboardShowsSyslogAndTraffic(t *testing.T) {
	requireNode(t)
	w := newDemoWorld(time.Now())
	rep := runDashboard(t, w, "plain")
	contains := viewChecker(t, rep)
	bs := string(rune(0x5c)) // a backslash: escapes are shown as typed

	// The Overview card: the receiver, its counters, how much the store holds, the last
	// message, the gateway's setting and the record of its latest check; this version only
	// reads the setting, and says so.
	w.mu.Lock()
	checkSeq := w.syslogCheck.Seq
	w.mu.Unlock()
	contains("overview", "Gateway syslog", "Receiverlistening on UDP 0.0.0.0:514", " received · ", " stored · 0 dropped · 7 from other senders",
		"Gateway settingon sends to 192.168.1.71:514 (this PC) · level Informational", "record #"+strconv.FormatUint(checkSeq, 10),
		"att-monitor reads this setting in its daily settings check and within 10 minutes after the service starts (att-monitor stop, then start); it does not change it yet.")
	ov := rep.Views["overview"]
	if strings.Contains(ov.Text, "turn Syslog on") {
		t.Error("the card says how to turn on what the gateway already does")
	}
	if !regexp.MustCompile(`Stored\d+\.\d KiB of 100 MiB usedoldest message `).MatchString(ov.Text) {
		t.Error("the Overview's syslog card does not say how much the store holds")
	}

	// The flow meter: the rates through the gateway as numbers and bars against the larger of
	// the recent maximum and the heavy-traffic level, the last 15 minutes, this PC, the reading's
	// time; its numbers are in no live region.
	contains("overview", "Live trafficflow meter · every 5 s", "Download through the gateway", "Upload through the gateway",
		" · mark: heavy household traffic, 80 Mb/s", "Last 15 min: highest download ", "This PC (its network adapter): download ",
		"Reading of ", ", over the 5.0 s between two readings", "shown, not recorded (the gateway snapshots every minute are the evidence)")
	if !regexp.MustCompile(`Download through the gateway[\d.,]+ [kMG]?b/s`).MatchString(ov.Text) || !regexp.MustCompile(`Bars from 0 to \d+ [MG]b/s`).MatchString(ov.Text) {
		t.Error("the flow meter shows no rate or no scale")
	}
	if ov.Marks["flowbar"] != 2 || ov.Marks["heavy"] != 2 || !slices.Contains(ov.Headings, "Live traffic") {
		t.Errorf("flow meter: marks %v, headings %q", ov.Marks, ov.Headings)
	}
	if !slices.Contains(ov.Live, "off:flow") {
		t.Errorf("the flow meter's numbers are not marked aria-live off: %q", ov.Live)
	}

	// History: the Traffic chart in MRTG's manner (download filled, upload a line, the peaks,
	// the heavy-traffic line) with MRTG's legend under it, its table view, and the WAN volume
	// per day.
	contains("overview", "Traffic", "Bits per second through the AT&T gateway, from its own IPv4 byte counters (it offers no SNMP), as MRTG draws it",
		"WAN download", "WAN upload", "peak: the highest rate between two readings in the bucket", "Heavy household traffic 80 Mb/s",
		"In this rangeMaximumAverageCurrent", "Maximum: the highest rate between two readings of the gateway’s counters",
		"WAN download peak", "This PC upload", "WAN volume per day", "(today, so far)", "Time counted")
	if ov.Marks["peak"] == 0 || ov.Marks["ref"] != 1 || ov.Marks["atleast"] != 0 || ov.Marks["area"] < 2 {
		t.Errorf("overview chart marks: %v", ov.Marks) // areas: the chart's download and the flow meter's sparkline
	}
	rate := `(at least )?[\d.,]+ [kMG]?b/s`
	for _, row := range []string{"WAN download", "WAN upload", "This PC download", "This PC upload"} {
		if rows := rowsWith(ov, regexp.MustCompile(`^\s*`+row+rate+rate+rate+`$`)); len(rows) != 1 {
			t.Errorf("MRTG legend: %d rows for %s", len(rows), row)
		}
	}
	if rows := rowsWith(ov, regexp.MustCompile(`partial$`)); len(rows) == 0 || !slices.Equal(rows[0].Chips, []string{"warning:partial"}) {
		t.Errorf("no partial day in the WAN volume: %+v", rowsWith(ov, regexp.MustCompile(`GB`)))
	}
	// Over 7 days the big download's rates are "at least": marked, explained, in MRTG's legend
	// and in the table.
	wk := rep.Views["overview 7d"]
	contains("overview 7d", "at least: the true rate may have been higher", "Chevron: the gateway’s 32-bit byte counter may have wrapped more often than can be told")
	if wk.Marks["atleast"] == 0 || len(rowsWith(wk, regexp.MustCompile(`at least \d{3} Mb/s`))) == 0 {
		t.Errorf("7 days: %d chevrons, %d table rows with \"at least\"", wk.Marks["atleast"], len(rowsWith(wk, regexp.MustCompile(`at least \d`))))
	}
	if rows := rowsWith(wk, regexp.MustCompile(`^\s*WAN downloadat least \d{3} Mb/sat least [\d.]+ Mb/s`)); len(rows) != 1 {
		t.Errorf("7 days: MRTG legend does not give the download's maximum and average as lower bounds")
	}

	// The Syslog page: how much the store holds and the choice of how much to keep; the newest
	// 200 messages, with what a sender controls shown as received: escapes for the control and
	// bidirectional characters, line breaks as \n, the bytes of a datagram that is not UTF-8, a
	// datagram without a PRI; each linked to its chunk's record once the chunk is sealed.
	contains("syslog", "Gateway syslog", "Stored messages", "messages kept", "in the open chunk (sealed and recorded in the evidence ledger within minutes)",
		"No age limit.", "Keep at most (MiB)", "Also delete messages older than (days)",
		"The newest 200 messages received from", "more were received in this period",
		bs+"x1b[1;31mWAN link flap"+bs+"x1b[0m detected on wan0",
		"DHCPACK on 192.168.1.80 to 02:00:00:00:00:80 ("+bs+"u202egpj.exe"+bs+"u202c) via br0",
		"Inform to the ACS failed:"+bs+"nHTTP 503 Service Unavailable"+bs+"nretry in 60 s",
		"Bytes (base64)", "Not valid UTF-8: the exact bytes received, base64-encoded.",
		"BGW320-505 watchdog: heartbeat ok", "Prioritynone in the datagram",
		"Exact datagram", "RFC 3164 (BSD syslog)", "RFC 5424", "as the gateway wrote it",
		"Stored insyslog-", "chunk of the syslog store; evidence: ledger record #", "chunk of the syslog store; evidence: no record yet")
	sl := rep.Views["syslog"]
	if !regexp.MustCompile(`Stored messages\d+\.\d KiB of 100 MiB used, oldest message [^,]+, [^,]+, \d+ chunks`).MatchString(sl.Text) {
		t.Error("the Syslog page does not say how much the store holds")
	}
	msgRows := rowsWith(sl, regexp.MustCompile(`Exact datagram`))
	if len(msgRows) != DefaultSyslogLimit {
		t.Errorf("syslog page: %d message rows, want %d", len(msgRows), DefaultSyslogLimit)
	}
	// The newest messages are in the open chunk; all the others name their chunk's record.
	unsealed := 0
	for unsealed < len(msgRows) && strings.Contains(msgRows[unsealed].Text, "no record yet") {
		unsealed++
	}
	linked := regexp.MustCompile(`^[^·]*?record #\d+`)
	for _, r := range msgRows[unsealed:] {
		if !linked.MatchString(r.Text) {
			t.Fatalf("message without its chunk's record after the open chunk's: %q", r.Text)
		}
	}
	if unsealed == 0 || unsealed == len(msgRows) {
		t.Errorf("%d of %d messages without a record", unsealed, len(msgRows))
	}
	for _, chip := range []string{"none:Info", "info:Notice", "warning:Warning"} {
		if !slices.ContainsFunc(sl.Rows, func(r dashboardRow) bool { return slices.Contains(r.Chips, chip) }) {
			t.Errorf("syslog page: no %s severity chip", chip)
		}
	}
	if rows := rowsWith(sl, regexp.MustCompile(`watchdog: heartbeat ok`)); len(rows) != 1 || len(rows[0].Chips) != 0 || !strings.Contains(rows[0].Text, "—") {
		t.Errorf("message without a severity: %+v", rows)
	}
	contains("syslog more", "The newest 400 messages received from")
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

	// The ledger: the sealed chunks, worded.
	contains("records", "Gateway syslog: ", "message", "sealed in a chunk (age limit)", "syslog_chunk")
}

// A sender floods the gateway's address with datagrams of 8 KiB of control characters: the
// Syslog page shows the newest that fit in one answer (MaxSyslogAnswerBytes, fewer than the 200
// asked for), says that more were received and how to see them, and offers no "Load more",
// which would get the same answer; each row shows the start of its message, the control
// characters as one element. The page had an element for each character (1.6 million) and the
// service built answers of up to 0.5 GB.
func TestDashboardSyslogFloodIsBounded(t *testing.T) {
	requireNode(t)
	w := newDemoWorld(time.Now())
	w.floodSyslog(300)
	rep := runDashboard(t, w, "overview")
	viewChecker(t, rep)("syslog", "; more were received, but these messages are long and one answer holds no more of them. Narrow the period or the filters to see older ones.",
		strings.Repeat(string(rune(0x5c))+"x01", 125)+" … 8,067 more characters")
	sl := rep.Views["syslog"]
	rows := rowsWith(sl, regexp.MustCompile(`Exact datagram`))
	if len(rows) == 0 || len(rows) >= DefaultSyslogLimit {
		t.Fatalf("%d message rows; want the newest that fit in one answer, fewer than %d", len(rows), DefaultSyslogLimit)
	}
	if !regexp.MustCompile(`^The newest ` + strconv.Itoa(len(rows)) + ` messages received from `).MatchString(syslogStatusLine(sl.Text)) {
		t.Errorf("status line %q does not count the %d messages shown", syslogStatusLine(sl.Text), len(rows))
	}
	// One element for each row's control characters, and one for the card's last message.
	if n := sl.Marks["ctl"]; n > len(rows)+1 {
		t.Errorf("%d elements of control characters for %d rows", n, len(rows))
	}
	if !slices.ContainsFunc(sl.Buttons, func(b dashboardButton) bool { return b.Text == "Load more" }) {
		t.Error(`no "Load more" button on the page`)
	}
	for _, b := range sl.Buttons {
		if b.Text == "Load more" && b.Shown {
			t.Error(`"Load more" offered although a larger limit gets the same answer`)
		}
	}
}

// syslogStatusLine returns the Syslog page's line about the messages listed ("The newest …").
func syslogStatusLine(text string) string {
	i := strings.Index(text, "The newest ")
	if i < 0 {
		return ""
	}
	line, _, _ := strings.Cut(text[i:], "Narrow the period")
	return line
}

// The flow meter asks for a reading only while the Overview is shown and the page visible; the
// Syslog page's form changes how much is kept, asking first when the change deletes messages.
func TestDashboardFlowMeterAndRetention(t *testing.T) {
	requireNode(t)
	w := newDemoWorld(time.Now())
	rep := runDashboard(t, w, "syslog")
	contains := viewChecker(t, rep)
	v := func(name string) dashboardView {
		t.Helper()
		view, ok := rep.Views[name]
		if !ok {
			t.Fatalf("view %q was not rendered (views: %v)", name, keys(rep.Views))
		}
		return view
	}

	// The Overview is rendered twice (when the page loads and when the harness opens it): one
	// reading each, then one more whenever the next reading is due.
	ov, poll := v("overview"), v("overview poll")
	if n := liveRequests(rep, ov.Requests); n != 2 || ov.Timers != 1 {
		t.Errorf("overview: %d readings, %d timers", n, ov.Timers)
	}
	if n := liveRequests(rep, poll.Requests) - liveRequests(rep, ov.Requests); n != 1 || poll.Timers != 1 {
		t.Errorf("the reading due: %d requests, %d timers", n, poll.Timers)
	}
	// Hidden: nothing is due, nothing is asked.
	hidden := v("overview hidden")
	if n := liveRequests(rep, hidden.Requests) - liveRequests(rep, poll.Requests); n != 0 || hidden.Timers != 0 {
		t.Errorf("while hidden: %d readings, %d timers", n, hidden.Timers)
	}
	// Shown again: a reading at once, and the next one due.
	shown := v("overview visible")
	if n := liveRequests(rep, shown.Requests) - liveRequests(rep, hidden.Requests); n != 1 || shown.Timers != 1 {
		t.Errorf("visible again: %d readings, %d timers", n, shown.Timers)
	}
	// Left: no reading any more.
	if n := liveRequests(rep, len(rep.Requests)) - liveRequests(rep, shown.Requests); n != 0 || v("syslog").Timers != 0 {
		t.Errorf("%d readings after the Overview was left", n)
	}

	// Keep 50 MiB and 30 days: nothing to delete, so no question; the answer is the change
	// recorded in the ledger.
	contains("syslog retention", "Saved. The syslog store keeps at most 50 MiB, and nothing older than 30 days.",
		"Recorded in the evidence ledger as a configuration change: syslog.keep_mb, syslog.keep_days (how much gateway syslog is kept), 100 MiB, no age limit → 50 MiB, 30 days (applied).",
		"KiB of 50 MiB used", "Messages older than 30 days are deleted too.")
	// 3 days deletes the older messages: confirmed first.
	if len(rep.Dialogs) != 1 || !strings.Contains(rep.Dialogs[0], "Delete the oldest syslog messages now?") ||
		!regexp.MustCompile(`The oldest messages are deleted as soon as you save: its oldest message, received .+, is older than 3 days\.`).MatchString(rep.Dialogs[0]) ||
		!strings.Contains(rep.Dialogs[0], "The SHA-256 of every deleted chunk stays in the evidence ledger (its syslog_chunk record) and the deletion is recorded (a syslog_prune record)") {
		t.Errorf("dialogs: %q", rep.Dialogs)
	}
	contains("syslog retention pruned", "Saved. The syslog store keeps at most 50 MiB, and nothing older than 3 days.",
		"50 MiB, 30 days → 50 MiB, 3 days (applied)", "Messages older than 3 days are deleted too.")
	chunks := func(view string) int {
		m := regexp.MustCompile(`, (\d+) chunks`).FindStringSubmatch(v(view).Text)
		if m == nil {
			t.Fatalf("view %q does not say how many chunks are kept", view)
		}
		n, _ := strconv.Atoi(m[1])
		return n
	}
	if before, after := chunks("syslog"), chunks("syslog retention pruned"); after == 0 || after >= before {
		t.Errorf("chunks kept: %d before, %d after deleting the older ones", before, after)
	}
	// The same limits again: the monitor answers "unchanged" and records nothing, and the page
	// says so; it does not ask about deleting either (saving them deletes nothing).
	contains("syslog retention unchanged", "Already in force. The syslog store keeps at most 50 MiB, and nothing older than 3 days already: "+
		"nothing was changed, so nothing was recorded in the evidence ledger and nothing was deleted.")
	if text := v("syslog retention unchanged").Text; strings.Contains(text, "Recorded in the evidence ledger") || strings.Contains(text, "Saved.") {
		t.Error("saving the limits in force is reported as a change recorded in the evidence ledger")
	}
	if len(rep.Dialogs) != 1 {
		t.Errorf("%d dialogs, want only the one before deleting: %q", len(rep.Dialogs), rep.Dialogs)
	}
	// A value the page refuses is not sent.
	refused := v("syslog retention refused")
	contains("syslog retention refused", "Enter a whole number of MiB from 1 to 1,048,576.")
	if refused.Requests != v("syslog retention unchanged").Requests {
		t.Error("a refused value was sent")
	}
	posts := 0
	for _, r := range rep.Requests {
		if r.Method == "POST" && r.Path == "/api/syslog/retention" && r.Status == 200 {
			posts++
		}
	}
	w.mu.Lock()
	keepMB, keepDays := w.keepMB, w.keepDays
	changes := 0
	for _, b := range w.bodies {
		if b.Type == model.TypeConfigChange && strings.Contains(string(b.Data), "syslog.keep_mb") {
			changes++
		}
	}
	w.mu.Unlock()
	if posts != 3 || changes != 2 || keepMB != 50 || keepDays != 3 {
		t.Errorf("%d saves sent, %d recorded as a config_change; the store keeps %d MiB, %d days", posts, changes, keepMB, keepDays)
	}
}

// TestAppJSRetentionLoss: saving the limits in force deletes nothing, so the page does not ask
// about it, even while the open chunk takes the store a little over its size limit; a change
// that deletes is described.
func TestAppJSRetentionLoss(t *testing.T) {
	prog := jsProgram(t, []string{"MIB", "F"}, []string{"retentionLoss", "fmtBytes", "fmtInt", "toMs", "toDate"})
	prog += `const MiB = 1048576;
const old = new Date(Date.now() - 40 * 86400e3).toISOString();
const full = { bytes: 100.4 * MiB, keep_mb: 100, oldest: old };
console.log(JSON.stringify([
  retentionLoss(full, 100, 0),
  retentionLoss(Object.assign({}, full, { keep_days: 30 }), 100, 30),
  retentionLoss(full, 100, 30),
  retentionLoss(full, 50, 0),
  retentionLoss(full, 200, 0),
  retentionLoss(null, 1, 0),
]));
`
	var got []string
	if err := json.Unmarshal(runNode(t, prog), &got); err != nil {
		t.Fatal(err)
	}
	if got[0] != "" || got[1] != "" {
		t.Errorf("the limits in force saved again: %q, %q; want nothing deleted", got[0], got[1])
	}
	if !strings.Contains(got[2], "the store holds 100.4 MiB, more than 100 MiB") || !strings.Contains(got[2], "is older than 30 days") {
		t.Errorf("an age limit added: %q", got[2])
	}
	if !strings.Contains(got[3], "more than 50 MiB") || got[4] != "" || got[5] != "" {
		t.Errorf("50 MiB: %q; 200 MiB: %q; no store: %q", got[3], got[4], got[5])
	}
}

// The flow meter's other states, as the monitor reports them (LiveTraffic).
func TestDashboardFlowMeterStates(t *testing.T) {
	requireNode(t)
	for state, wants := range map[string][]string{
		"atleast": {"at least", "The gateway’s 32-bit byte counter may have wrapped between the two readings, so the rates were at least these."},
		"error": {"The newest read of the gateway’s counters failed: gateway 192.168.1.254: GET /cgi-bin/broadbandstatistics.ha: context deadline exceeded",
			"Shown: the reading of "},
		"first":       {"Measuring: a rate needs two readings of the gateway’s counters, a few seconds apart.", "Reading of "},
		"unavailable": {"No reading. Live traffic: the gateway's counters cannot be read: unavailable."},
	} {
		t.Run(state, func(t *testing.T) {
			w := newDemoWorld(time.Now())
			w.mu.Lock()
			w.liveState = state
			w.mu.Unlock()
			rep := runDashboard(t, w, "overview")
			viewChecker(t, rep)("overview", wants...)
			if ov := rep.Views["overview"]; !slices.Contains(ov.Headings, "Live traffic") {
				t.Errorf("headings: %q", ov.Headings)
			}
		})
	}
}

// A monitor without a syslog store, its control or a flow meter (404): the Overview has no flow
// meter, the Syslog page says that it has no messages to show, and the form says why it cannot
// change anything.
func TestDashboardWithoutSyslogStoreOrFlowMeter(t *testing.T) {
	requireNode(t)
	w := newDemoWorld(time.Now())
	srv := newDemoServer(t, w, nil)
	srv.syslog, srv.syslogCtl, srv.live = nil, nil, nil
	rep := runDashboardOn(t, srv, "syslog")
	contains := viewChecker(t, rep)
	if ov := rep.Views["overview"]; slices.Contains(ov.Headings, "Live traffic") || !slices.Contains(ov.Headings, "Gateway syslog") {
		t.Errorf("overview headings: %q", ov.Headings)
	}
	if n := liveRequests(rep, len(rep.Requests)); n != 2 { // one for each Overview, then nothing more
		t.Errorf("%d flow meter requests to a monitor without one", n)
	}
	contains("syslog", "The gateway's syslog messages are not available: this att-monitor keeps no syslog store.")
	contains("syslog retention", "How much syslog is kept cannot be changed here: this att-monitor offers no control of a syslog store.")
	if strings.Contains(rep.Views["syslog retention"].Text, "Saved.") {
		t.Error("a change reported as saved")
	}
}

// The card's other states, as the monitor reports them (Status.syslog).
func TestDashboardSyslogCardStates(t *testing.T) {
	requireNode(t)
	// The setting is read once a day: while it says off, the card tells how to set it by hand,
	// until messages arrive (they show at once that the gateway was set; the setting shown is
	// read again only later).
	reads := "att-monitor reads this setting in its daily settings check and within 10 minutes after the service starts (att-monitor stop, then start); it does not change it yet."
	for state, want := range map[string]struct {
		view  string
		texts []string
	}{
		"offquiet": {"overview", []string{"Gateway settingoff the gateway sends no syslog messages", "Last messagenone since the service started",
			"To receive the gateway’s log, turn Syslog on in the gateway’s Diagnostics › Syslog page with server 192.168.1.71 and port 514: its messages then show here within a minute. " + reads}},
		"off": {"overview", []string{"Gateway settingoff the gateway sends no syslog messages",
			"Messages have arrived since this setting was read, so it may have been changed on the gateway since. " + reads}},
		"elsewhere": {"overview", []string{"Gateway settingsends elsewhere to 192.168.1.20:1514 · level Debug, not to this PC"}},
		"error":     {"overview", []string{"could not be read gateway: login throttled", "Last read: on, sends to 192.168.1.71:514 · level Informational"}},
		"unknown":   {"overview", []string{"Gateway settingnot read yet", "the daily settings check has not read the gateway's Syslog page yet"}},
		"enforce":   {"overview", []string{"att-monitor keeps the gateway sending its log to 192.168.1.71:514"}},
		"nolisten":  {"overview", []string{"Receivernot listening listen udp 0.0.0.0:514: bind: Only one usage of each socket address"}},
		"disabled":  {"overview", []string{"Receiveroff turned off in the configuration (syslog.enabled)"}},
		"nostore":   {"syslog", []string{"This monitor reports no syslog store, so how much is kept cannot be shown or changed here."}},
	} {
		t.Run(state, func(t *testing.T) {
			w := newDemoWorld(time.Now())
			w.mu.Lock()
			w.syslogState = state
			w.mu.Unlock()
			rep := runDashboard(t, w, "overview")
			viewChecker(t, rep)(want.view, want.texts...)
			if state == "nostore" && strings.Contains(rep.Views["overview"].Text, "Stored") {
				t.Error("the Overview's card shows a store the monitor does not report")
			}
		})
	}
	// A monitor without a receiver: no card, no store panel.
	w := newDemoWorld(time.Now())
	w.mu.Lock()
	w.syslogState = "none"
	w.mu.Unlock()
	rep := runDashboard(t, w, "overview")
	if strings.Contains(rep.Views["overview"].Text, "Gateway syslog") {
		t.Error("a card for a monitor that reports no syslog receiver")
	}
	viewChecker(t, rep)("syslog", "This monitor reports no syslog receiver")
	if slices.Contains(rep.Views["syslog"].Headings, "Stored messages") {
		t.Error("a store panel for a monitor that reports no syslog receiver")
	}
}

// TestAppJSRates runs the traffic helpers of app.js: rates in the unit that suits them, axis
// labels in the unit of the axis's end, and MRTG's maximum, average and current.
func TestAppJSRates(t *testing.T) {
	prog := jsProgram(t, []string{"RATE_UNITS"}, []string{"fmtNum", "rateParts", "fmtRate", "rateAxis", "fmtLevel", "rateStats", "wholeNumber"})
	prog += `console.log(JSON.stringify({
  rates: [0, 0.0004, 0.25, 0.9996, 1, 9.5, 32.84, 612.5, 999.6, 1200, 18500, null, NaN].map(fmtRate),
  parts: rateParts(41.25),
  axes: [[0.5, 0.25], [80, 40], [800, 600], [1000, 250], [1500, 1250]].map(([hi, v]) => rateAxis(hi)(v)),
  levels: [80, 1000, 0.5].map(fmtLevel),
  stats: rateStats([null, 10, 20, null, 30], [null, 50, 25, null, 31], [false, false, true, false, false]),
  latest: rateStats([5, null], null, [true, false]),
  none: rateStats([null, null], null, null),
  whole: ['50', ' 7 ', '0', '1.5', '-1', '1e3', '', 'x', '1234567890'].map(wholeNumber),
}));
`
	var got struct {
		Rates  []string          `json:"rates"`
		Parts  []string          `json:"parts"`
		Axes   []string          `json:"axes"`
		Levels []string          `json:"levels"`
		Stats  json.RawMessage   `json:"stats"`
		Latest json.RawMessage   `json:"latest"`
		None   json.RawMessage   `json:"none"`
		Whole  []json.RawMessage `json:"whole"`
	}
	if err := json.Unmarshal(runNode(t, prog), &got); err != nil {
		t.Fatal(err)
	}
	if want := []string{"0 b/s", "0.40 kb/s", "250 kb/s", "1.00 Mb/s", "1.00 Mb/s", "9.50 Mb/s", "32.8 Mb/s", "613 Mb/s", "1.00 Gb/s", "1.20 Gb/s", "18.5 Gb/s", "—", "—"}; !slices.Equal(got.Rates, want) {
		t.Errorf("fmtRate = %q\n          want %q", got.Rates, want)
	}
	if !slices.Equal(got.Parts, []string{"41.3", "Mb/s"}) && !slices.Equal(got.Parts, []string{"41.2", "Mb/s"}) {
		t.Errorf("rateParts(41.25) = %q", got.Parts)
	}
	if want := []string{"250 kb/s", "40 Mb/s", "600 Mb/s", "0.25 Gb/s", "1.25 Gb/s"}; !slices.Equal(got.Axes, want) {
		t.Errorf("rateAxis = %q, want %q", got.Axes, want)
	}
	if want := []string{"80 Mb/s", "1 Gb/s", "500 kb/s"}; !slices.Equal(got.Levels, want) {
		t.Errorf("fmtLevel = %q, want %q", got.Levels, want)
	}
	// The maximum is the highest peak (bucket 1: 50), the average is over the three readings
	// (20, "at least" because bucket 2 is), the current is the newest reading (30, bucket 4).
	if want := `{"max":{"v":50,"i":1,"atLeast":false},"avg":{"v":20,"atLeast":true},"cur":{"v":30,"i":4,"atLeast":false}}`; string(got.Stats) != want {
		t.Errorf("rateStats = %s\n          want %s", got.Stats, want)
	}
	if want := `{"max":{"v":5,"i":0,"atLeast":true},"avg":{"v":5,"atLeast":true},"cur":{"v":5,"i":0,"atLeast":true}}`; string(got.Latest) != want {
		t.Errorf("rateStats without peaks = %s, want %s", got.Latest, want)
	}
	if string(got.None) != "null" {
		t.Errorf("rateStats without readings = %s", got.None)
	}
	var whole []string
	for _, w := range got.Whole {
		whole = append(whole, string(w))
	}
	if want := []string{"50", "7", "0", "null", "null", "null", "null", "null", "null"}; !slices.Equal(whole, want) {
		t.Errorf("wholeNumber = %q, want %q", whole, want)
	}
}

// TestAppJSSyslogRetentionLimits: the form's limits are the configuration's.
func TestAppJSSyslogRetentionLimits(t *testing.T) {
	src := appJS(t)
	for name, want := range map[string]int{
		"SYSLOG_KEEP_MB_MIN": config.MinSyslogKeepMB, "SYSLOG_KEEP_MB_MAX": config.MaxSyslogKeepMB, "SYSLOG_KEEP_DAYS_MAX": config.MaxSyslogKeepDays,
	} {
		decl := jsConst(t, src, name)
		if got := strings.TrimSuffix(strings.TrimPrefix(decl, "const "+name+" = "), ";"); got != strconv.Itoa(want) {
			t.Errorf("%s = %s, want %d (internal/config)", name, got, want)
		}
	}
}

// TestAppJSVisibleText runs hiddenChar, charEscape, visibleText and escapedText from app.js:
// every character that would act on the display instead of showing is written as an escape,
// set apart in a span, one span for each run of them however long; everything else is kept as
// received.
func TestAppJSVisibleText(t *testing.T) {
	prog := jsProgram(t, nil, []string{"hiddenChar", "charEscape", "visibleText", "ctlTitle", "escapedText"})
	// A stand-in for h(): a span as [class, title, text].
	prog += `function h(tag, props, text) { return [props.class, props.title, text]; }
const C = (n) => String.fromCharCode(n);
const cases = [
  'plain text, ' + C(0xe9) + ' and ' + C(0x65e5) + C(0x672c),
  C(0x1b) + '[31mred' + C(0x1b) + '[0m',
  'a' + C(0x202e) + 'gpj.exe' + C(0x202c) + 'b',
  'one' + C(0x0a) + 'two' + C(0x09) + 'three' + C(0x0d),
  C(0x00) + C(0x7f) + C(0x85) + C(0x9f) + C(0xa0) + C(0x200b) + C(0x2028) + C(0x2066) + C(0xfeff) + C(0xfffd),
  'x' + C(0x01).repeat(3) + C(0x02) + C(0x01) + 'y',
  C(0x01) + C(0x02) + C(0x03) + C(0x04) + C(0x05) + C(0x06) + C(0x07) + C(0x0e) + C(0x0f) + C(0x10),
];
const flood = visibleText(C(0x01).repeat(8192));
const alternating = visibleText(('a' + C(0x01)).repeat(4096));
console.log(JSON.stringify({
  visible: cases.map((t) => visibleText(t)),
  pretty: visibleText('{' + C(0x0a) + '  "a": 1' + C(0x0a) + '}', true),
  escaped: cases.map(escapedText),
  flood: { parts: flood.length, title: flood[0][1], text: flood[0][2] === '\\x01'.repeat(8192) },
  alternating: alternating.length,
}));
`
	var got struct {
		Visible [][]any  `json:"visible"`
		Pretty  []any    `json:"pretty"`
		Escaped []string `json:"escaped"`
		Flood   struct {
			Parts int    `json:"parts"`
			Title string `json:"title"`
			Text  bool   `json:"text"`
		} `json:"flood"`
		Alternating int `json:"alternating"`
	}
	if err := json.Unmarshal(runNode(t, prog), &got); err != nil {
		t.Fatal(err)
	}
	bs := string(rune(0x5c))
	span := func(text, title string) []any { return []any{"ctl", title, text} }
	want := [][]any{
		{"plain text, " + string(rune(0xe9)) + " and " + string(rune(0x65e5)) + string(rune(0x672c))},
		{span(bs+"x1b", "U+001B"), "[31mred", span(bs+"x1b", "U+001B"), "[0m"},
		{"a", span(bs+"u202e", "U+202E"), "gpj.exe", span(bs+"u202c", "U+202C"), "b"},
		{"one", span(bs+"n", "U+000A"), "two", span(bs+"t", "U+0009"), "three", span(bs+"r", "U+000D")},
		{span(bs+"x00"+bs+"x7f"+bs+"x85"+bs+"x9f", "U+0000 U+007F U+0085 U+009F"), string(rune(0xa0)),
			span(bs+"u200b"+bs+"u2028"+bs+"u2066"+bs+"ufeff", "U+200B U+2028 U+2066 U+FEFF"), string(rune(0xfffd))},
		{"x", span(strings.Repeat(bs+"x01", 3)+bs+"x02"+bs+"x01", "U+0001 ×3 U+0002 U+0001"), "y"},
		{span(bs+"x01"+bs+"x02"+bs+"x03"+bs+"x04"+bs+"x05"+bs+"x06"+bs+"x07"+bs+"x0e"+bs+"x0f"+bs+"x10",
			"U+0001 U+0002 U+0003 U+0004 U+0005 U+0006 U+0007 U+000E …")},
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
		"x" + strings.Repeat(bs+"x01", 3) + bs + "x02" + bs + "x01y",
		bs + "x01" + bs + "x02" + bs + "x03" + bs + "x04" + bs + "x05" + bs + "x06" + bs + "x07" + bs + "x0e" + bs + "x0f" + bs + "x10",
	} {
		if got.Escaped[i] != w {
			t.Errorf("escapedText case %d = %q, want %q", i, got.Escaped[i], w)
		}
	}
	// A datagram of 8 KiB of control characters is one element, every character written; one
	// that alternates letters and control characters has an element for each run.
	if got.Flood.Parts != 1 || got.Flood.Title != "U+0001 ×8192" || !got.Flood.Text {
		t.Errorf("8192 control characters: %+v, want one span of every escape", got.Flood)
	}
	if got.Alternating != 8192 {
		t.Errorf("4096 letters and control characters, alternating: %d parts", got.Alternating)
	}
}

// TestAppJSSyslogRowIsBounded renders rows of the syslog list (syslogRow) from datagrams a
// sender filled with control characters: a row holds a bounded number of elements, with the
// start of the text and how much it leaves out (the exact datagram shows all of it). A row
// had an element for every control character: 1.6 million for the first 200 rows of datagrams
// of 8 KiB.
func TestAppJSSyslogRowIsBounded(t *testing.T) {
	prog := jsProgram(t, []string{"SYSLOG_SEVERITIES", "SYSLOG_ROW_TEXT", "SYSLOG_ROW_NAME", "SYSLOG_ROW_RUNS"},
		[]string{"hiddenChar", "charEscape", "visibleText", "ctlTitle", "clipText", "clippedText", "fmtInt", "syslogSeverity", "syslogRow"})
	// Stand-ins for h() (an element as {tag, cls, kids}) and for the parts of a row that hold no
	// message text.
	prog += `let elements = 0;
function h(tag, props, ...kids) { elements++; return { tag, cls: (props && props.class) || '', kids: kids.flat(Infinity).filter((k) => k != null && k !== '') }; }
const F = { sec: null };
function timeEl() { return h('time', null, 'when'); }
function chip(tone, label) { return h('span', { class: 'chip' }, label); }
function chunkRecordLink() { return h('a', null, 'record'); }
function syslogDetails() { return h('details', { class: 'syslog-raw' }, h('summary', null, 'Exact datagram')); }
const text = (n) => typeof n === 'string' ? n : n.kids.map(text).join('');
const count = (n, cls) => typeof n === 'string' ? 0 : (n.cls === cls ? 1 : 0) + n.kids.reduce((s, k) => s + count(k, cls), 0);
const C = (n) => String.fromCharCode(n);
const row = (m) => {
  elements = 0;
  const cells = syslogRow(Object.assign({ rx: '2026-10-05T03:19:00Z', chunk: 'c', severity: 6 }, m));
  return { elements, ctl: cells.reduce((s, c) => s + count(c, 'ctl'), 0), host: text(cells[2]), msg: text(cells[3].kids[0]) };
};
const flood = C(0x01).repeat(8192);
console.log(JSON.stringify({
  flood: row({ raw: flood, msg: flood }),
  alternating: row({ msg: ('a' + C(0x02)).repeat(4096) }),
  host: row({ host: C(0x03).repeat(8000) + 'gw', app: ('b' + C(0x04)).repeat(100), msg: 'ok' }),
  long: row({ msg: 'x'.repeat(499) + '\u{1F600}' + 'y'.repeat(600) }),
  plain: row({ host: 'BGW320-505', app: 'dhcpd', msg: 'DHCPACK on 192.168.1.80 via br0' }),
}));
`
	type rowReport struct {
		Elements int    `json:"elements"`
		Ctl      int    `json:"ctl"`
		Host     string `json:"host"`
		Msg      string `json:"msg"`
	}
	var got map[string]rowReport
	if err := json.Unmarshal(runNode(t, prog), &got); err != nil {
		t.Fatal(err)
	}
	bs := string(rune(0x5c))
	plain := got["plain"]
	if plain.Host != "BGW320-505dhcpd" || plain.Msg != "DHCPACK on 192.168.1.80 via br0" || plain.Ctl != 0 {
		t.Errorf("an everyday message: %+v", plain)
	}
	for name, want := range map[string]rowReport{
		// 500 characters as shown (125 escapes of four), one element; the rest is counted.
		"flood": {Ctl: 1, Msg: strings.Repeat(bs+"x01", 125) + " … 8,067 more characters"},
		// 16 runs of control characters, then what is left out.
		"alternating": {Ctl: 16, Msg: strings.Repeat("a"+bs+"x02", 16) + "a … 8,159 more characters"},
		// The host and the app are cut too (100 characters as shown, 16 runs).
		"host": {Ctl: 1 + 16, Host: strings.Repeat(bs+"x03", 25) + " … 7,977 more characters" + strings.Repeat("b"+bs+"x04", 16) + "b … 167 more characters", Msg: "ok"},
		// Never half of a surrogate pair: the emoji goes with the rest.
		"long": {Ctl: 0, Msg: strings.Repeat("x", 499) + " … 601 more characters"},
	} {
		r := got[name]
		if r.Ctl != want.Ctl || r.Msg != want.Msg || (want.Host != "" && r.Host != want.Host) {
			t.Errorf("%s: %d hidden-character elements, host %q, message %q\nwant %d, %q, %q", name, r.Ctl, r.Host, r.Msg, want.Ctl, want.Host, want.Msg)
		}
		if r.Elements > plain.Elements+40 {
			t.Errorf("%s: a row of %d elements (an everyday message: %d)", name, r.Elements, plain.Elements)
		}
	}
}
