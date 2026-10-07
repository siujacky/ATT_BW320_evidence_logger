package web

// The Overview as a summary dashboard whose cards open their details in a modal
// (docs/overview-redesign.md), driven in testdata/dashboard_harness.js against the demo world:
// what the summary says on a healthy line, during an AT&T outage and for an older monitor; each
// card's details opened and closed every way a reader does it (a click, Enter, Space; Esc, the
// close button, the backdrop, Back), with the address, the history, the keyboard focus and the
// scroll lock checked at every step; a status update while the details are open; a link to a
// card's details and a reload. The wording helpers run under Node.js.

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// overviewCards are the Overview's summary cards in their order, with their titles.
var overviewCards = []struct{ key, title string }{
	{"internet", "Internet"}, {"gateway", "AT&T gateway"}, {"fiber", "Fiber optics"}, {"traffic", "Traffic"},
	{"link", "This PC’s link"}, {"network", "Network"}, {"syslog", "Gateway syslog"}, {"evidence", "Evidence"}, {"monitor", "Monitor & clock"},
}

// detailTitle is the heading of a card's details: the card's title, "Status & availability"
// for the status card.
func detailTitle(key string) string {
	if key == "status" {
		return "Status & availability"
	}
	for _, c := range overviewCards {
		if c.key == key {
			return c.title
		}
	}
	return ""
}

// wantCard fails the test unless the card of v that opens key has the chip and every text.
func wantCard(t *testing.T, v dashboardView, key, chip string, texts ...string) {
	t.Helper()
	c := v.card(t, key)
	if c.Chip != chip {
		t.Errorf("the %s card's chip is %q, want %q (card: %q)", key, c.Chip, chip, c.Text)
	}
	for _, s := range texts {
		if !strings.Contains(c.Text, s) {
			t.Errorf("the %s card does not say %q: %q", key, s, c.Text)
		}
	}
}

// nb writes a number's unit as the summary cards keep it on the number's line (a no-break space).
func nb(s string) string { return strings.ReplaceAll(s, " ", "\u00a0") }

// TestDashboardOverviewSummary renders the Overview of a healthy line: the status card with
// the last 24 hours, the key numbers, the nine cards - each one control (its title's button,
// which opens its details), the sparklines hidden from screen readers with a sentence for them
// - and the three recent incidents; the History section and the long tables are gone from the
// page. Then each card's details, opened with a click: the modal is open, labelled with the
// card's title and a line of context, the page behind locked, the address naming it, and it
// shows the card of before and its charts.
func TestDashboardOverviewSummary(t *testing.T) {
	requireNode(t)
	w := newDemoWorld(time.Now())
	rep := runDashboard(t, w, "overview")
	contains := viewChecker(t, rep)
	ov := rep.Views["overview"]

	// The status card: the state now, since when, the newest measurement's key facts; the last
	// 24 hours as a strip with its legend (the same figures as the key numbers below).
	for _, want := range []string{"Internet status now", "Online", "For ", ", since ", "5 of 5 internet probes answered · AT&T gateway ", " · median round trip "} {
		if !strings.Contains(ov.Hero, want) {
			t.Errorf("status card does not show %q: %q", want, ov.Hero)
		}
	}
	// The legend pairs the strip's colours with the key numbers below, worded as they are (they
	// count cycles, the strip buckets: its own shares are in its details).
	if !regexp.MustCompile(`^24 h ago12 h agonowAvailability \d+\.\d\d %Degraded .+AT&T-attributed .+`).MatchString(ov.Strip) {
		t.Errorf("status card's last 24 hours: %q", ov.Strip)
	}
	if !strings.Contains(ov.Text, "Last 24 hours · worst state in each 5 min") {
		t.Error("the status card does not say what its strip shows")
	}
	contains("overview", "Status & availability", "Availability, last 24 h", "AT&T-attributed time without Internet", "Monitoring coverage",
		"Recent incidents", "All incidents", "Degraded — AT&T DNS servers not answering")

	// The nine cards, in their order, each one Tab stop.
	if len(ov.Cards) != len(overviewCards) {
		t.Fatalf("%d summary cards: %+v", len(ov.Cards), ov.Cards)
	}
	for i, want := range overviewCards {
		c := ov.Cards[i]
		if c.Key != want.key || c.Title != want.title || c.Controls != 1 {
			t.Errorf("card %d: %s %q with %d controls, want %s %q with its title's button alone", i, c.Key, c.Title, c.Controls, want.key, want.title)
		}
		sparks := map[string]int{"internet": 1, "fiber": 1, "traffic": 1}[c.Key]
		if c.Sparks != sparks {
			t.Errorf("the %s card has %d sparklines hidden from screen readers, want %d", c.Key, c.Sparks, sparks)
		}
	}
	wantCard(t, ov, "internet", "good:OK", "median round trip", "5 of 5 internet probes answered · packet loss ", " in 24 h", "Median internet round trip from ",
		"over the last 24 hours", "DNS answered · web checks OK · no DNS hijack")
	wantCard(t, ov, "gateway", "good:Up", "Broadband up", "Fiber operational (O5) · gateway up ", "WAN IPv4"+demoWANIP, "Outage redirectOff", "Polled ")
	// The demo's line receives less light than the gateway's own alarm threshold.
	wantCard(t, ov, "fiber", "critical:Gateway alarm", "dBm light received", "The gateway’s low alarm -29.5 dBm · warning -29.2 dBm", "Transmit "+nb("3.7 dBm"),
		"Light received from ")
	wantCard(t, ov, "traffic", "info:Live", "b/s down", "b/s up", "Today ", "WAN download from ", "WAN download, last "+nb("24 h"))
	wantCard(t, ov, "link", "good:Connected", "Wi-Fi 5 GHz", "Signal "+nb("86 %")+" · receive 1201 / send "+nb("1201 Mb/s"), "Route to the Internet: through the AT&T gateway")
	wantCard(t, ov, "network", ov.card(t, "network").Chip, "connections open · 8 devices listed", "Most used: Google", "packets blocked by the firewall in 24 h",
		" inbound probes from ")
	if c := ov.card(t, "network"); !regexp.MustCompile(`^info:Read .+ ago$`).MatchString(c.Chip) {
		t.Errorf("the Network card's chip: %q", c.Chip)
	}
	wantCard(t, ov, "syslog", "good:Listening", "messages since the service started", "The gateway sends its log to this PC (level Notice)", " of 100 MiB used",
		"Last message ")
	wantCard(t, ov, "evidence", "good:Recording", "signed records", "Last time-stamp ", "records not yet time-stamped")
	wantCard(t, ov, "monitor", "good:Running", "as a Windows service", "Version demo · ", " measurement cycles", " from time.windows.com",
		"Classifier rules "+demoRules)
	// Nothing healthy is in a warning or critical tone but the fiber's own alarm.
	for _, c := range ov.Cards {
		if (c.Tone == "critical" || c.Tone == "warning") && c.Key != "fiber" {
			t.Errorf("the %s card is in tone %s on a healthy line: %q", c.Key, c.Tone, c.Text)
		}
	}
	// The History section and the long tables are in the details now.
	if slices.Contains(ov.Headings, "History") || len(ov.Rows) != 0 || ov.Marks["peak"] != 0 || ov.Marks["ref"] != 0 || ov.Detail != nil {
		t.Errorf("the summary shows charts or tables: headings %q, %d table rows, marks %v, details %+v", ov.Headings, len(ov.Rows), ov.Marks, ov.Detail)
	}
	if ov.Hash != "#/" || ov.Locked {
		t.Errorf("the summary: hash %q, scroll locked %v", ov.Hash, ov.Locked)
	}

	// Each card's details: open, labelled, the focus on Close, the page locked, the address.
	details := map[string][]string{
		"status": {"Internet status now", "In this state since", "Classified from: gateway snapshot #", "History", "Availability",
			"Worst classifier state in each"},
		"internet": {"Probes", "AT&T gateway (ICMP)", "Name resolution & web checks", "1 address142.250.72.100", "Gateway DNS hijack test",
			"Round-trip time", "Packet loss", "Every cycle’s measurements are on the Records page"},
		"gateway": {"Broadband", "Fiber (PON)", "Optical WAN", "AT&T next hop", "Gateway uptime", "Firmware", "Outage redirect", "Polled ",
			"are on the Gateway page."},
		"fiber": {"Received light (Rx)", "Transmit power (Tx)", "Black marker: current reading.", "Laser bias", "Module",
			"Fiber receive power vs the gateway’s own thresholds"},
		"traffic": {"Live traffic", "flow meter · every 5 s", "Bits per second through the AT&T gateway", "WAN volume per day"},
		"link":    {"Adapter", "Wi-Fi (Wi-Fi)", "Access point", "Route to the Internet", "All 5 destinations leave through the AT&T gateway"},
		"network": {"The gateway’s NAT table and Device List", "NAT tableread ", "Device List8 devices listed", "Devices, last 24 hours (sites reached)",
			"Office PC", "Most used organisations, last 24 hours (sites)", "The gateway’s firewall, last 24 hours", "Inbound", "Most probed services",
			"Connections and Firewall tabs."},
		"syslog":   {"Receiverlistening on UDP 0.0.0.0:514", "Gateway setting", "Kept by att-monitoryes", "Stop sending", "are on the Syslog page."},
		"evidence": {"Ledger head", "Signing key", "Last time-stamp", "Not yet time-stamped", "on the Evidence page"},
		"monitor":  {"Version", "Running as", "service", "Cycles", "Clock vs time.windows.com", "Clock vs time.google.com"},
	}
	for key, texts := range details {
		name := "overview " + key
		v, ok := rep.Views[name]
		if !ok {
			t.Errorf("view %q was not rendered", name)
			continue
		}
		d := v.Detail
		if d == nil || !d.Open || d.Key != key || d.Title != detailTitle(key) || !strings.HasSuffix(d.Context, " · updates while open") {
			t.Errorf("%s: details %+v", name, d)
			continue
		}
		// (Where the keyboard focus goes is TestDashboardOverviewDetails's: here the charts were
		// read from the keyboard before the capture.)
		if !v.Locked || v.Hash != "#/?detail="+key {
			t.Errorf("%s: scroll locked %v, hash %q", name, v.Locked, v.Hash)
		}
		for _, s := range texts {
			if !strings.Contains(d.Text, s) {
				t.Errorf("%s: the details do not show %q", name, s)
			}
		}
	}
	// The details' line of context says what matters, as the card does.
	if d := rep.Views["overview internet"].Detail; d == nil || !regexp.MustCompile(`^5 of 5 internet probes answered · cycle #[\d,]+ at .+, took [\d,]+ ms · updates while open$`).MatchString(d.Context) {
		t.Errorf("the Internet details' context: %+v", d)
	}
	// Closed, the page is as it was: the focus back on the card's button.
	if v := rep.Views["syslog"]; v.Locked {
		t.Error("the page stays locked after the details closed")
	}
}

// TestDashboardOverviewOutage renders the Overview during a live AT&T fiber outage: the status
// card in the critical tone says what failed and that it is AT&T's, with the incident in
// progress; the failing parts are critical, the parts that still work good - this PC's link
// connected, the home network working: what attributes the outage -; the incident in progress
// is the first of the recent incidents.
func TestDashboardOverviewOutage(t *testing.T) {
	requireNode(t)
	w := newDemoWorld(time.Now())
	w.setOutage(true)
	rep := runDashboard(t, w, "overview")
	ov := rep.Views["overview"]

	for _, want := range []string{"AT&T outage", "Attributed to AT&T (provider side)", "For ", "0 of 5 internet probes answered · AT&T gateway ",
		"fiber link down (reported by the AT&T gateway)", "Incident in progress: INC-", " — open it and its evidence"} {
		if !strings.Contains(ov.Hero, want) {
			t.Errorf("status card does not show %q: %q", want, ov.Hero)
		}
	}
	if strings.Contains(ov.Hero, "median round trip") {
		t.Errorf("status card gives a round trip although no internet probe answered: %q", ov.Hero)
	}
	wantCard(t, ov, "internet", "critical:No answer", "0 of 5 internet probes answered", "The AT&T gateway answers (", "the AT&T next hop does not.",
		"shaded: no reply", "Gateway DNS SERVFAIL, AT&T DNS no answer, Public DNS no answer · web checks failed")
	wantCard(t, ov, "gateway", "critical:Down", "Broadband down", "Fiber not operational (O1)")
	// No level, and the gateway reports loss of signal: no light reaches it (not a missing reading).
	wantCard(t, ov, "fiber", "critical:Gateway alarm", "No light", "the gateway reports loss of signal on the fiber")
	if d := rep.Views["overview fiber"].Detail; d == nil || !strings.HasPrefix(d.Context, "No light received (loss of signal) · gateway alarm") {
		t.Errorf("the Fiber details' context in the outage: %+v", d)
	}
	wantCard(t, ov, "link", "good:Connected", "Route to the Internet: through the AT&T gateway", "The home network works: this PC reaches the AT&T gateway.")
	wantCard(t, ov, "evidence", "good:Recording")
	wantCard(t, ov, "monitor", "good:Running")
	for _, key := range []string{"internet", "gateway", "fiber"} {
		if c := ov.card(t, key); c.Tone != "critical" {
			t.Errorf("the %s card is in tone %q during the outage", key, c.Tone)
		}
	}
	if c := ov.card(t, "link"); c.Tone != "good" {
		t.Errorf("the link card is in tone %q during the outage", c.Tone)
	}
	// The incident in progress first among the recent incidents: when it opened, ongoing, what it
	// is, in progress.
	const head = "Recent incidentsAll incidents"
	i := strings.Index(ov.Text, head)
	if i < 0 || !regexp.MustCompile(`^[^·]+ongoing · [^A]+AT&T outage — fiber link down \(reported by the AT&T gateway\)In progress`).MatchString(ov.Text[i+len(head):]) {
		t.Errorf("recent incidents during the outage: %.400q", ov.Text[max(i, 0):])
	}
	// The details say the same.
	viewChecker(t, rep)("overview internet", "0 of 5 internet probes answered", "timed out", "SERVFAIL")
	viewChecker(t, rep)("overview status", "AT&T outage — fiber link down (reported by the AT&T gateway)", "Attributed to AT&T (provider side)",
		"Incident in progress: INC-", "Open the incident and its evidence")
	viewChecker(t, rep)("overview gateway", "Broadband", "not operational")
}

// runDashboardLive serves w beside the demo's /demo/state switch (the line goes down with
// ?s=outage, comes back with ?s=online), so that a scenario can change the world while the page
// is open, and drives the dashboard in the harness, failing the test on any markup-sink
// violation or script error. env as for runHarness.
func runDashboardLive(t *testing.T, w *demoWorld, scenario string, env ...string) dashboardReport {
	t.Helper()
	return runDashboardFailing(t, w, "", scenario, env...)
}

// runDashboardFailing is runDashboardLive whose GET /api/status fails as mode says from the start
// (statusFailer), and as /demo/statusfail?mode=... says from then on.
func runDashboardFailing(t *testing.T, w *demoWorld, mode, scenario string, env ...string) dashboardReport {
	t.Helper()
	requireNode(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newDemoServerOn(t, w, ln.Addr().String(), nil)
	fail := &statusFailer{mode: mode, next: srv.Handler()}
	mux := http.NewServeMux()
	mux.HandleFunc("/demo/state", func(rw http.ResponseWriter, r *http.Request) {
		w.setOutage(r.URL.Query().Get("s") == "outage")
		fmt.Fprintln(rw, "ok")
	})
	mux.HandleFunc("/demo/statusfail", func(rw http.ResponseWriter, r *http.Request) {
		fail.set(r.URL.Query().Get("mode"))
		fmt.Fprintln(rw, "ok")
	})
	mux.Handle("/", fail)
	hs := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go hs.Serve(ln)
	t.Cleanup(func() { hs.Close() })
	return checkedHarness(t, "http://"+ln.Addr().String(), scenario, env...)
}

// statusFailer makes GET /api/status fail, as the service does when it stops or breaks: mode
// "down" closes the connection without an answer (the service is not running), "500" answers
// with an error; "" passes every request on (next).
type statusFailer struct {
	mu   sync.Mutex
	mode string
	next http.Handler
}

func (f *statusFailer) set(mode string) {
	f.mu.Lock()
	f.mode = mode
	f.mu.Unlock()
}

func (f *statusFailer) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	mode := f.mode
	f.mu.Unlock()
	if r.URL.Path != "/api/status" || mode == "" {
		f.next.ServeHTTP(rw, r)
		return
	}
	if mode == "500" {
		writeError(rw, http.StatusInternalServerError, "status: the monitor's state could not be read")
		return
	}
	if hj, ok := rw.(http.Hijacker); ok {
		if conn, _, err := hj.Hijack(); err == nil {
			conn.Close()
			return
		}
	}
	panic(http.ErrAbortHandler) // closes the connection without an answer
}

// detailState is where the page is at a step of the harness's detailsScenario: the address,
// the history, the keyboard focus, whether details are open, whether the page behind is locked
// and how many modal dialogs are open.
type detailState struct {
	Hash   string `json:"hash"`
	Length int    `json:"length"`
	Index  int    `json:"index"`
	Focus  string `json:"focus"`
	Open   bool   `json:"open"`
	Locked bool   `json:"locked"`
	Modals int    `json:"modals"`
}

// TestDashboardOverviewDetails uses each card's details as a reader does (the harness's
// detailsScenario): opened with a click, Enter or Space on the card's button, closed with Esc,
// the close button, a click on the backdrop or the browser's Back button - every way of each,
// in turn. Opened, the details are a modal labelled by their heading, the focus on its close
// button, the page behind locked and the address naming them, added to the history; closed,
// the history and the address are as before, and the focus is back on the card's button. Open,
// they follow every status update in place - a part whose data did not change is not drawn
// again, so the route check the reader opened stays open with the focus in it, and the scroll
// position stays -, and the line going down shows in them; a confirmation opens over them and
// gives the focus back to the button that asked for it.
func TestDashboardOverviewDetails(t *testing.T) {
	w := newDemoWorld(time.Now())
	rep := runDashboardLive(t, w, "details")
	var steps []struct {
		Key    string      `json:"key"`
		How    string      `json:"how"`
		Close  string      `json:"close"`
		Before detailState `json:"before"`
		Opened detailState `json:"opened"`
		After  detailState `json:"after"`
	}
	if err := json.Unmarshal(rep.Facts["details"], &steps); err != nil || len(steps) != 1+len(overviewCards) {
		t.Fatalf("details steps: %s (%v)", rep.Facts["details"], err)
	}
	hows, closes := map[string]bool{}, map[string]bool{}
	for _, s := range steps {
		hows[s.How], closes[s.Close] = true, true
		b, o, a := s.Before, s.Opened, s.After
		if o.Hash != "#/?detail="+s.Key || o.Index != b.Index+1 || o.Length != b.Index+2 || o.Focus != "button:Close" || !o.Open || !o.Locked || o.Modals != 1 {
			t.Errorf("%s opened with %s: %+v (before: %+v)", s.Key, s.How, o, b)
		}
		if a.Hash != b.Hash || a.Index != b.Index || a.Focus != "button:"+detailTitle(s.Key) || a.Open || a.Locked || a.Modals != 0 {
			t.Errorf("%s closed with %s: %+v (before it opened: %+v)", s.Key, s.Close, a, b)
		}
		if v := rep.Views["detail "+s.Key]; v.Detail == nil || v.Detail.Key != s.Key || !v.Detail.Open || v.Detail.Title != detailTitle(s.Key) {
			t.Errorf("%s: details %+v", s.Key, v.Detail)
		}
	}
	for _, how := range []string{"click", "enter", "space"} {
		if !hows[how] {
			t.Errorf("no details opened with %s", how)
		}
	}
	for _, c := range []string{"escape", "close", "backdrop", "back"} {
		if !closes[c] {
			t.Errorf("no details closed with %s", c)
		}
	}

	// A status update while the This PC's link details are open: the link is as it was, so its
	// part is not drawn again - the route check the reader opened is the same element, still open,
	// the focus on its summary (not moved to a copy, which a screen reader would announce again).
	var live struct {
		Opened     bool   `json:"opened"`
		Before     string `json:"before"`
		SameDialog bool   `json:"sameDialog"`
		Kept       bool   `json:"kept"`
		Open       bool   `json:"open"`
		FocusKept  bool   `json:"focusKept"`
		Focus      string `json:"focus"`
		ScrollTop  int    `json:"scrollTop"`
		Hash       string `json:"hash"`
	}
	if err := json.Unmarshal(rep.Facts["live"], &live); err != nil {
		t.Fatalf("live: %s (%v)", rep.Facts["live"], err)
	}
	if !live.Opened || !live.SameDialog || !live.Kept || !live.Open || !live.FocusKept || live.Focus != live.Before || live.ScrollTop != 120 || live.Hash != "#/?detail=link" {
		t.Errorf("the link details across a status update: %+v", live)
	}

	// The line goes down while the Internet details are open: they show it, in place.
	var outage struct {
		SameDialog bool   `json:"sameDialog"`
		Hash       string `json:"hash"`
		Focus      string `json:"focus"`
	}
	if err := json.Unmarshal(rep.Facts["outage"], &outage); err != nil || !outage.SameDialog || outage.Hash != "#/?detail=internet" || outage.Focus != "button:Close" {
		t.Errorf("the Internet details as the line goes down: %s (%v)", rep.Facts["outage"], err)
	}
	if d := rep.Views["internet online"].Detail; d == nil || !strings.Contains(d.Text, "5 of 5 internet probes answered") {
		t.Errorf("the Internet details before the outage: %+v", d)
	}
	if d := rep.Views["internet outage"].Detail; d == nil || !d.Open || !strings.Contains(d.Text, "0 of 5 internet probes answered") ||
		!strings.HasPrefix(d.Context, "0 of 5 internet probes answered") {
		t.Errorf("the Internet details in the outage: %+v", d)
	}
	sum := rep.Views["summary outage"]
	if !strings.Contains(sum.Hero, "AT&T outage") || sum.Detail != nil || sum.Hash != "#/" || sum.Focus != "button:Internet" {
		t.Errorf("the summary after the details closed in the outage: hero %q, details %+v, hash %q, focus %q", sum.Hero, sum.Detail, sum.Hash, sum.Focus)
	}
	wantCard(t, sum, "internet", "critical:No answer")

	// A confirmation over the syslog details: Cancel gives the focus back to the button.
	var confirm struct {
		Before int  `json:"before"`
		Over   bool `json:"over"`
		After  struct {
			Modals     int    `json:"modals"`
			DetailOpen bool   `json:"detailOpen"`
			Focus      string `json:"focus"`
		} `json:"after"`
	}
	if err := json.Unmarshal(rep.Facts["confirm"], &confirm); err != nil || !confirm.Over || confirm.After.Modals != 1 || !confirm.After.DetailOpen ||
		confirm.After.Focus != "button:"+stopButton {
		t.Errorf("a confirmation over the details: %s (%v)", rep.Facts["confirm"], err)
	}
	if len(rep.Dialogs) != 1 || !strings.Contains(rep.Dialogs[0], "Stop the gateway sending its log?") {
		t.Errorf("dialogs: %q", rep.Dialogs)
	}
	if posts := gwSyslogPosts(rep); len(posts) != 0 {
		t.Errorf("a cancelled change was sent: %v", posts)
	}
}

// TestDashboardOverviewDeepLink loads the page at a card's details (#/?detail=internet, as a
// link or a reload does): they open at once, the focus on their close button; closed, they
// replace the address (the history keeps no entry of them) and the focus goes to the card's
// button. An address naming no card opens nothing; a card's details reached from another page
// open over the Overview, and Back leaves them with the Overview.
func TestDashboardOverviewDeepLink(t *testing.T) {
	w := newDemoWorld(time.Now())
	rep := runDashboardLive(t, w, "deeplink", "HARNESS_HASH=#/?detail=internet")
	var deep struct {
		Opened, Closed struct {
			Hash   string `json:"hash"`
			Length int    `json:"length"`
			Index  int    `json:"index"`
			Focus  string `json:"focus"`
		}
		FromPage struct {
			Hash  string `json:"hash"`
			Focus string `json:"focus"`
		} `json:"fromPage"`
		BackHash      string `json:"backHash"`
		BackHasDialog bool   `json:"backHasDialog"`
	}
	if err := json.Unmarshal(rep.Facts["deep"], &deep); err != nil {
		t.Fatalf("deep: %s (%v)", rep.Facts["deep"], err)
	}
	if o := deep.Opened; o.Hash != "#/?detail=internet" || o.Length != 1 || o.Index != 0 || o.Focus != "button:Close" {
		t.Errorf("loaded at the Internet details: %+v", o)
	}
	if v := rep.Views["deep link"]; v.Detail == nil || v.Detail.Key != "internet" || !v.Detail.Open || !v.Locked || !strings.Contains(v.Detail.Text, "Probes") {
		t.Errorf("the details the address names: %+v", v.Detail)
	}
	if c := deep.Closed; c.Hash != "#/" || c.Length != 1 || c.Index != 0 || c.Focus != "button:Internet" {
		t.Errorf("closed, the details replace the address: %+v", c)
	}
	if v := rep.Views["deep link closed"]; v.Detail != nil || v.Locked {
		t.Errorf("closed: details %+v, scroll locked %v", v.Detail, v.Locked)
	}
	if v := rep.Views["unknown card"]; v.Detail != nil || v.Hash != "#/?detail=nosuchcard" || len(v.Cards) != len(overviewCards) {
		t.Errorf("an address naming no card: details %+v, hash %q, %d cards", v.Detail, v.Hash, len(v.Cards))
	}
	if v := rep.Views["from another page"]; v.Detail == nil || v.Detail.Key != "fiber" || !v.Detail.Open || deep.FromPage.Focus != "button:Close" {
		t.Errorf("the Fiber details reached from another page: %+v, focus %q", v.Detail, deep.FromPage.Focus)
	}
	if deep.BackHash != "#/incidents" || deep.BackHasDialog || !strings.Contains(rep.Views["back to incidents"].Text, "Incidents") {
		t.Errorf("Back from details opened from the address: hash %q, dialog left %v", deep.BackHash, deep.BackHasDialog)
	}
	if w := rep.Views["back to incidents"]; w.Locked {
		t.Error("the page stays locked after Back left the details")
	}
}

// oldMonitor is the status source of an older monitor: its status leaves out what later versions
// added (the syslog receiver, the NAT samplers, the MongoDB copy, the certificate pin, the
// probes' labels, the window statistics, the clock check, the local link, the service check).
type oldMonitor struct{ *demoWorld }

func (o oldMonitor) Status() model.Status {
	st := o.demoWorld.Status()
	st.Syslog, st.Connections, st.Mongo, st.GatewayCert, st.Probes, st.Stats = nil, nil, nil, nil, nil, nil
	st.Clock, st.LocalLink, st.LastService = nil, nil, nil
	return st
}

// TestDashboardOverviewOldMonitor renders the Overview of an older monitor: no syslog store or
// receiver, no flow meter, no Network page, and a status without the fields added since. Every
// card says something true - what the monitor does not have, or that nothing was reported -,
// and every card's details open without a script error.
func TestDashboardOverviewOldMonitor(t *testing.T) {
	requireNode(t)
	w := newDemoWorld(time.Now())
	srv := newDemoServer(t, w, nil)
	srv.status = oldMonitor{w}
	srv.syslog, srv.syslogCtl, srv.live, srv.network = nil, nil, nil, nil
	rep := runDashboardOn(t, srv, "overview")
	ov := rep.Views["overview"]
	if !strings.Contains(ov.Hero, "Online") || !regexp.MustCompile(`Online.*Degraded.*AT&T outage`).MatchString(ov.Strip) {
		t.Errorf("status card: %q, %q", ov.Hero, ov.Strip)
	}
	wantCard(t, ov, "internet", "good:OK", "5 of 5 internet probes answered")
	wantCard(t, ov, "link", "none:No data", "Not measured yet.")
	wantCard(t, ov, "network", "none:Not offered", "This monitor offers no Network page.")
	wantCard(t, ov, "syslog", "none:Not offered", "This monitor reports no syslog receiver.")
	wantCard(t, ov, "traffic", "none:No live reading", "The live traffic meter is not available")
	wantCard(t, ov, "monitor", "good:Running", "Clock not checked yet")
	wantCard(t, ov, "evidence", "good:Recording", "signed records")
	if strings.Contains(ov.Text, "Availability, last 24 h") {
		t.Error("key numbers shown for a monitor that reports no statistics")
	}
	for _, c := range overviewCards {
		if v, ok := rep.Views["overview "+c.key]; !ok || v.Detail == nil || !v.Detail.Open {
			t.Errorf("the %s details of an older monitor did not open", c.key)
		}
	}
	viewChecker(t, rep)("overview network", "The Network page is not available: this att-monitor offers no view of the connections and the firewall.")
	viewChecker(t, rep)("overview link", "Not measured yet.")
}

// TestAppJSOverviewWords runs the Overview's wording helpers under Node.js: the status card's
// title (never "Local fault" for a gateway restart or traffic routed past the gateway; an
// UNKNOWN status worded as statusHeadline does), the cause with its source, the numbers kept on
// one line with their units, the sparklines' scale, the fiber link, the clock and the MongoDB
// copy.
func TestAppJSOverviewWords(t *testing.T) {
	prog := jsProgram(t, []string{"STATES", "CAUSES"}, []string{"humanize", "stateInfo", "headline", "statusStale", "statusHeadline", "statusTitle",
		"causeWords", "keepUnits", "sparkTop", "ponWords", "clockWords", "fmtInt", "mongoWords", "syslogSettingWords", "syslogTarget", "sentence", "capitalize"})
	prog += `const v = (state, cause) => ({ verdict: { state, cause }, last_sample: { verdict: { state, cause } }, since: '2026-10-05T03:00:00Z' });
console.log(JSON.stringify({
  titles: [v('ONLINE'), v('ISP_OUTAGE', 'FIBER_LINK_DOWN'), v('DEGRADED', 'HIGH_LATENCY'), v('LOCAL_FAULT', 'LOCAL_LINK_DOWN'),
    v('LOCAL_FAULT', 'GATEWAY_REBOOT'), v('LOCAL_FAULT', 'LOCAL_ROUTE'), {}, { verdict: { state: 'UNKNOWN' }, since: '' }].map(statusTitle),
  causes: [{ cause: 'FIBER_LINK_DOWN' }, { cause: 'PACKET_LOSS' }, { cause: 'LOCAL_ROUTE' }, { cause: 'SOMETHING_NEW' }, {}].map(causeWords),
  units: ['median round trip 13.7 ms', 'packet loss 4.2 % in 24 h', 'up 5 d 2 h', '8 devices listed', '5 of 5 probes', '62.3 Mb/s down', 'Today 211 GB', '35 °C', '1 min 18 s'].map(keepUnits),
  tops: [[10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 200], [10, 12, 14], [-31.8, -31.2, -31.5]].map(sparkTop),
  pon: [[{ pon_link_status: 'OPERATION (O5)' }, {}], [{ pon_link_status: 'INITIAL (O1)' }, { pon_operational: false }], [{}, {}], [{}, { pon_operational: true }]].map(([bb, d]) => ponWords(bb, d)),
  clocks: [undefined, { results: [] }, { results: [{ server: 'a', ok: false }] }, { results: [{ server: 'b', ok: true, offset_ms: -23 }] }, { results: [{ server: 'c', ok: true }] }].map(clockWords),
  mongo: [null, { connected: false, has_data: false }, { connected: false, has_data: true }, { connected: true, has_data: true, lag: 0 }, { connected: true, has_data: true, lag: 12 }].map(mongoWords),
  syslog: [{ state: 'ok', gateway: { enabled: true, server: '192.168.1.71', port: 514, level: 'Notice' } }, { state: 'off', gateway: { enabled: false } },
    { state: 'unknown' }, { state: 'unknown', problem: 'the page was not understood: x' }].map(syslogSettingWords),
}));
`
	var got struct {
		Titles, Causes, Units, Pon, Clocks, Mongo, Syslog []string
		Tops                                              []float64
	}
	if err := json.Unmarshal(runNode(t, prog), &got); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name      string
		got, want []string
	}{
		{"statusTitle", got.Titles, []string{"Online", "AT&T outage", "Degraded", "Local fault", "AT&T gateway restarted", "Not through the AT&T gateway",
			"Waiting for the first measurements", "Waiting for the first measurements"}},
		{"causeWords", got.Causes, []string{"fiber link down (reported by the AT&T gateway)", "packet loss", localRouteHeadline, "something new", ""}},
		{"keepUnits", got.Units, []string{"median round trip 13.7\u00a0ms", "packet loss 4.2\u00a0% in 24\u00a0h", "up 5\u00a0d 2\u00a0h", "8 devices listed", "5 of 5 probes",
			"62.3\u00a0Mb/s down", "Today 211\u00a0GB", "35\u00a0°C", "1\u00a0min 18\u00a0s"}},
		{"ponWords", got.Pon, []string{"Fiber operational (O5)", "Fiber not operational (O1)", "", "Fiber operational"}},
		{"clockWords", got.Clocks, []string{"Clock not checked yet", "Clock not checked yet", "No time server answered the latest clock check", "Clock -23 ms from b", "Clock +0 ms from c"}},
		{"mongoWords", got.Mongo, []string{"", "no MongoDB server (the copy is optional)", "MongoDB copy not connected", "MongoDB copy in sync", "MongoDB copy 12 records behind"}},
		{"syslogSettingWords", got.Syslog, []string{"The gateway sends its log to this PC (level Notice)", "The gateway sends no syslog messages",
			"The gateway’s Syslog setting has not been read yet", "The page was not understood: x."}},
	} {
		if !slices.Equal(c.got, c.want) {
			t.Errorf("%s:\n got %q\nwant %q", c.name, c.got, c.want)
		}
	}
	// A spike far above the rest is cut (1.5 times the 90th percentile); otherwise the highest value.
	if want := []float64{28.5, 14, -31.2}; !slices.Equal(got.Tops, want) {
		t.Errorf("sparkTop = %v, want %v", got.Tops, want)
	}
}
