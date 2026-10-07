package web

// Every summary card says something true in every state (docs/overview-redesign.md §6), also in
// states the demo world does not model: the status, the series, the flow meter and the firewall
// view edited as a monitor may report them - the gateway answering only over TCP, a gateway
// reading that is no longer current, a degraded line, a flag of the fiber module's other measures,
// a flow meter reading that was skipped or is old, the last 24 hours that cannot be read, a
// gateway that sends its log elsewhere, a syslog kept for less than a day. The wording helpers run
// under Node.js; the style rules are read from style.css.

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// editedStatus is the demo world as a monitor whose status edit changes (a state the demo world
// does not model), and whose series fails with seriesErr when it is set.
type editedStatus struct {
	*demoWorld
	edit      func(*model.Status)
	seriesErr error
}

func (e editedStatus) Status() model.Status {
	st := e.demoWorld.Status()
	if e.edit != nil {
		e.edit(&st)
	}
	return st
}

func (e editedStatus) Series(rangeName string) (model.Series, error) {
	if e.seriesErr != nil {
		return model.Series{}, e.seriesErr
	}
	return e.demoWorld.Series(rangeName)
}

// liveSource is a flow meter (contracts.LiveTrafficSource) made of a function.
type liveSource func(context.Context) (model.LiveTraffic, error)

func (f liveSource) LiveTraffic(ctx context.Context) (model.LiveTraffic, error) { return f(ctx) }

// fwEdited is the demo world's Network page with the answers of its firewall view edited.
type fwEdited struct {
	*demoWorld
	edit func(*model.NetFirewall)
}

func (f fwEdited) Firewall(ctx context.Context, q contracts.NetQuery) (model.NetFirewall, error) {
	fw, err := f.demoWorld.Firewall(ctx, q)
	if err == nil && f.edit != nil {
		f.edit(&fw)
	}
	return fw, err
}

// runSummary serves srv and captures the Overview's summary ("overview") and the details of each
// card named ("overview <key>") in the harness (its summaryScenario).
func runSummary(t *testing.T, srv *Server, details ...string) dashboardReport {
	t.Helper()
	requireNode(t)
	base, _ := startServer(t, srv)
	return checkedHarness(t, base, "summary", "HARNESS_DETAILS="+strings.Join(details, ","))
}

// summaryOf serves w with its status edited (editedStatus) and captures its summary and the
// details of the cards named.
func summaryOf(t *testing.T, w *demoWorld, edit func(*model.Status), details ...string) dashboardReport {
	t.Helper()
	srv := newDemoServer(t, w, nil)
	srv.status = editedStatus{demoWorld: w, edit: edit}
	return runSummary(t, srv, details...)
}

// setProbe sets the outcome of the newest sample's probe named name: answered (with its round
// trip as measured), or not with the status given.
func setProbe(st *model.Status, name string, ok bool, status string) {
	for i := range st.LastSample.Probes {
		p := &st.LastSample.Probes[i]
		if p.Name != name {
			continue
		}
		p.OK, p.Status = ok, status
		if !ok {
			p.RTTus = 0
		}
	}
}

// notContains fails the test when the card of v that opens key says any of texts.
func notContains(t *testing.T, v dashboardView, key string, texts ...string) {
	t.Helper()
	c := v.card(t, key)
	for _, s := range texts {
		if strings.Contains(c.Text, s) {
			t.Errorf("the %s card says %q: %q", key, s, c.Text)
		}
	}
}

// TestDashboardOverviewGatewayAnswersOverTCP: the gateway answered when any of its probes did, or
// when a TCP connection to it was refused (a reset is an answer), as the classifier judges it -
// every attribution to AT&T rests on that. A lost ping while the TCP probe answers must not make
// the summary say that the gateway did not answer, nor take away "the home network works".
func TestDashboardOverviewGatewayAnswersOverTCP(t *testing.T) {
	requireNode(t)
	for _, tc := range []struct {
		name               string
		tcpOK              bool
		tcpStatus          string
		hero, internet     string
		homeWorks, silence bool
	}{
		{"ping lost, TCP answered", true, "connected", "AT&T gateway 3.1 ms over TCP", "The AT&T gateway answers (3.1 ms over TCP); the AT&T next hop does not.", true, false},
		{"ping lost, TCP refused", false, "refused", "the AT&T gateway answered (TCP connection refused)", "The AT&T gateway answers (it refused a TCP connection); the AT&T next hop does not.", true, false},
		{"neither answered", false, "timeout", "the AT&T gateway did not answer", "The AT&T gateway did not answer either.", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newDemoWorld(time.Now())
			w.setOutage(true)
			rep := summaryOf(t, w, func(st *model.Status) {
				setProbe(st, "gateway_icmp", false, "IP_REQ_TIMED_OUT")
				setProbe(st, "gateway_tcp", tc.tcpOK, tc.tcpStatus)
				for i := range st.LastSample.Probes {
					if p := &st.LastSample.Probes[i]; p.Name == "gateway_tcp" && p.OK {
						p.RTTus = 3100
					}
				}
			})
			ov := rep.Views["overview"]
			if !strings.Contains(ov.Hero, "0 of 5 internet probes answered · "+tc.hero+" · fiber link down") {
				t.Errorf("status card: %q, want %q", ov.Hero, tc.hero)
			}
			if !tc.silence && strings.Contains(ov.Hero, "did not answer") {
				t.Errorf("the status card says that the gateway did not answer: %q", ov.Hero)
			}
			wantCard(t, ov, "internet", "critical:No answer", tc.internet)
			const works = "The home network works: this PC reaches the AT&T gateway."
			if got := strings.Contains(ov.card(t, "link").Text, works); got != tc.homeWorks {
				t.Errorf("the link card says %q: %v, want %v", works, got, tc.homeWorks)
			}
			// A gateway that answers no probe is not shown as it was last read.
			if c := ov.card(t, "gateway"); (c.Chip == "none:Not answering") != tc.silence {
				t.Errorf("the gateway card: %+v (silent: %v)", c, tc.silence)
			}
		})
	}
}

// TestDashboardOverviewGatewayReadingNotCurrent: the status keeps the last gateway reading in
// which the gateway answered. While the gateway does not answer this PC, or that reading is older
// than the classifier would use (150 s), the gateway and fiber cards show it as the last reading,
// in no tone - never as the gateway now.
func TestDashboardOverviewGatewayReadingNotCurrent(t *testing.T) {
	requireNode(t)
	at := func(age time.Duration) string { return time.Now().Add(-age).UTC().Format(time.RFC3339Nano) }
	t.Run("silent", func(t *testing.T) {
		rep := summaryOf(t, newDemoWorld(time.Now()), func(st *model.Status) {
			for _, p := range st.LastSample.Probes {
				if p.Role == model.RoleGateway {
					setProbe(st, p.Name, false, "timeout")
				}
			}
			st.GatewayAt = at(100 * time.Second)
		}, "gateway")
		ov := rep.Views["overview"]
		wantCard(t, ov, "gateway", "none:Not answering", "Last reading: Broadband up", "The gateway did not answer this PC’s latest probes.", "Last reading ")
		notContains(t, ov, "gateway", "Polled ")
		wantCard(t, ov, "fiber", "none:Not current", "light received at the last reading, ")
		for _, key := range []string{"gateway", "fiber"} {
			if c := ov.card(t, key); c.Tone != "none" {
				t.Errorf("the %s card is in tone %q", key, c.Tone)
			}
		}
		if d := rep.Views["overview gateway"].Detail; d == nil || !strings.HasPrefix(d.Context, "Last reading ") ||
			!strings.Contains(d.Context, "the gateway does not answer now") || !strings.Contains(d.Text, "ago — the gateway does not answer now)") {
			t.Errorf("the gateway details: %+v", d)
		}
	})
	t.Run("old", func(t *testing.T) {
		rep := summaryOf(t, newDemoWorld(time.Now()), func(st *model.Status) { st.GatewayAt = at(200 * time.Second) })
		ov := rep.Views["overview"]
		wantCard(t, ov, "gateway", "none:Not current", "Last reading: Broadband up", "No newer reading of the gateway’s status pages.")
		wantCard(t, ov, "fiber", "none:Not current")
	})
	t.Run("current", func(t *testing.T) {
		rep := summaryOf(t, newDemoWorld(time.Now()), nil)
		wantCard(t, rep.Views["overview"], "gateway", "good:Up", "Broadband up", "Polled ")
		notContains(t, rep.Views["overview"], "gateway", "Last reading")
	})
}

// TestDashboardOverviewDegradedLine: every internet probe answering is not "OK" while the
// classifier finds the line degraded, or the newest service check fails: the Internet card is in
// the warning tone and names what, as the status card does.
func TestDashboardOverviewDegradedLine(t *testing.T) {
	requireNode(t)
	degraded := func(cause string) func(*model.Status) {
		return func(st *model.Status) {
			st.Verdict = model.Verdict{State: model.StateDegraded, Cause: cause, Attribution: model.AttrProvider, Rules: demoRules,
				Reasons: []string{"median internet RTT 212 ms over the last 6 cycles"}}
		}
	}
	for _, tc := range []struct {
		name string
		edit func(*model.Status)
		chip string
	}{
		{"high latency", degraded(model.CauseHighLatency), "warning:High latency"},
		{"AT&T DNS", degraded(model.CauseISPDNSFailure), "warning:AT&T DNS servers not answering"},
		{"a resolver fails, not counted yet", func(st *model.Status) {
			for i := range st.LastService.DNS {
				if r := &st.LastService.DNS[i]; r.ServerRole == "isp" {
					*r = lostQuery(*r)
				}
			}
		}, "warning:DNS failing"},
		{"web checks fail", func(st *model.Status) {
			for i := range st.LastService.HTTP {
				st.LastService.HTTP[i].OK, st.LastService.HTTP[i].Err = false, "dial tcp: i/o timeout"
			}
		}, "warning:Web checks failing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := summaryOf(t, newDemoWorld(time.Now()), tc.edit)
			c := rep.Views["overview"].card(t, "internet")
			if c.Chip != tc.chip || c.Tone != "warning" || !strings.Contains(c.Text, "5 of 5 internet probes answered") {
				t.Errorf("the Internet card: %+v, want the chip %s", c, tc.chip)
			}
		})
	}
}

// TestDashboardOverviewFiberModuleFlags: the gateway flags every measure of its fiber module, not
// only the light it receives. A temperature alarm while the light is fine is a gateway alarm on
// the Fiber card, which names it; the received light's own flag is shown by its gauge.
func TestDashboardOverviewFiberModuleFlags(t *testing.T) {
	requireNode(t)
	rep := summaryOf(t, newDemoWorld(time.Now()), func(st *model.Status) {
		for i := range st.Gateway.Fiber.Measures {
			m := &st.Gateway.Fiber.Measures[i]
			switch m.Name {
			case "Rx Power":
				m.Current, m.CurrentRaw, m.LowAlarm, m.LowWarn = i64(-200), "-200", thr(false, -295), thr(false, -292)
			case "Temperature":
				m.Current, m.CurrentRaw, m.HighAlarm, m.HighWarn = i64(92), "92", thr(true, 80), thr(true, 75)
			}
		}
	})
	wantCard(t, rep.Views["overview"], "fiber", "critical:Gateway alarm", "-20.0 dBm", "Flagged by the gateway: module temperature (high alarm)", "module 92\u00a0°C")
	// The demo's own line: only the received light is flagged, which the gauge shows.
	rep = summaryOf(t, newDemoWorld(time.Now()), nil)
	wantCard(t, rep.Views["overview"], "fiber", "critical:Gateway alarm")
	notContains(t, rep.Views["overview"], "fiber", "Flagged by the gateway")
}

// TestDashboardOverviewFlowMeterReadings: a read the monitor skipped while it used the gateway
// itself is a wait for the next one, not a failure; a reading that failed long ago names its time,
// and its rates are no longer shown as the traffic now; why the newest read failed is on the card.
func TestDashboardOverviewFlowMeterReadings(t *testing.T) {
	requireNode(t)
	w := newDemoWorld(time.Now())
	for _, tc := range []struct {
		name  string
		edit  func(*model.LiveTraffic)
		chip  string
		texts []string
		not   []string
	}{
		{"skipped", func(lt *model.LiveTraffic) {
			lt.Err = "skipped: the monitor was taking its evidence snapshot of the gateway; the next read follows"
		}, "info:Live", []string{" down", " up"}, []string{"No new reading", "The newest read failed", "Reading of "}},
		// Older than the last few reads (the meter reads only while the card is on screen): not
		// "Live", and its time is given; its rates are still shown for a minute.
		{"old", func(lt *model.LiveTraffic) {
			lt.At = time.Now().Add(-30 * time.Second).UTC().Format(time.RFC3339Nano)
		}, "none:Not current", []string{" down", " up", "Reading of ", "ago)"}, []string{"— down", "No new reading", "The newest read failed"}},
		{"old and failed", func(lt *model.LiveTraffic) {
			lt.At = time.Now().Add(-40 * time.Minute).UTC().Format(time.RFC3339Nano)
			rx, tx := 52.7, 6.56
			lt.WANRx, lt.WANTx, lt.Err = &rx, &tx, "not read: the gateway did not answer the monitor's latest poll"
		}, "warning:No new reading", []string{"— down", "— up", "Reading of ", "(40\u00a0min ago): 52.7\u00a0Mb/s down · 6.56\u00a0Mb/s up",
			"The newest read failed: not read: the gateway did not answer the monitor's latest poll."}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newDemoServer(t, w, nil)
			srv.live = liveSource(func(ctx context.Context) (model.LiveTraffic, error) {
				lt, err := w.LiveTraffic(ctx)
				if err == nil {
					tc.edit(&lt)
				}
				return lt, err
			})
			ov := runSummary(t, srv).Views["overview"]
			c := ov.card(t, "traffic")
			if c.Chip != tc.chip || c.Tone != strings.Split(tc.chip, ":")[0] {
				t.Errorf("the Traffic card: %+v, want the chip %s", c, tc.chip)
			}
			wantCard(t, ov, "traffic", tc.chip, tc.texts...)
			notContains(t, ov, "traffic", tc.not...)
		})
	}
}

// TestDashboardOverviewSeriesUnavailable: while the last 24 hours cannot be read, no card claims
// that nothing was measured in them; each says that they could not be read.
func TestDashboardOverviewSeriesUnavailable(t *testing.T) {
	requireNode(t)
	w := newDemoWorld(time.Now())
	srv := newDemoServer(t, w, nil)
	srv.status = editedStatus{demoWorld: w, seriesErr: fmt.Errorf("series store unavailable: %w", contracts.ErrUnavailable)}
	ov := runSummary(t, srv).Views["overview"]
	if !strings.Contains(ov.Strip, "The last 24 hours could not be read") {
		t.Errorf("the status card's strip: %q", ov.Strip)
	}
	for _, key := range []string{"internet", "fiber", "traffic"} {
		wantCard(t, ov, key, ov.card(t, key).Chip, "The last 24\u00a0h could not be read")
		notContains(t, ov, key, "No round trips", "No optical readings", "No traffic readings", "packet loss")
	}
}

// TestAppJSSeriesFoot: what a sparkline card's last line says of the last 24 hours: what the
// sparkline covers, that the series holds none, that it is being read or could not be read.
func TestAppJSSeriesFoot(t *testing.T) {
	prog := jsProgram(t, nil, []string{"seriesFoot"})
	prog += `console.log(JSON.stringify([
  seriesFoot({ series: {}, seriesErr: null }, { svg: 1 }, 'Last 24 h', 'none'),
  seriesFoot({ series: {}, seriesErr: null }, null, 'Last 24 h', 'none'),
  seriesFoot({ series: null, seriesErr: null }, null, 'Last 24 h', 'none'),
  seriesFoot({ series: null, seriesErr: new Error('x') }, null, 'Last 24 h', 'none'),
]));
`
	var got []string
	if err := json.Unmarshal(runNode(t, prog), &got); err != nil {
		t.Fatal(err)
	}
	if want := []string{"Last 24 h", "none", "Reading the last 24 h…", "The last 24 h could not be read"}; strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("seriesFoot = %q, want %q", got, want)
	}
}

// TestDashboardOverviewFirewallCoverage: the firewall's figures are counted from the syslog the
// store kept. While the gateway does not send its log here, the Network card and its details say
// that blocked packets are not seen; when the syslog kept starts after the period does, the count
// is "since" then, not "in 24 h"; a 503 is "no syslog store" only for a monitor that reports none.
func TestDashboardOverviewFirewallCoverage(t *testing.T) {
	requireNode(t)
	const unseen = "The gateway does not send its log to this PC: blocked packets are not seen."
	t.Run("not sent here", func(t *testing.T) {
		w := newDemoWorld(time.Now())
		w.mu.Lock()
		w.syslogState = "elsewhere"
		w.mu.Unlock()
		rep := runSummary(t, newDemoServer(t, w, nil), "network")
		wantCard(t, rep.Views["overview"], "network", rep.Views["overview"].card(t, "network").Chip, unseen)
		viewChecker(t, rep)("overview network", unseen, "Open the Syslog page")
	})
	t.Run("kept for less than a day", func(t *testing.T) {
		w := newDemoWorld(time.Now())
		srv := newDemoServer(t, w, nil)
		srv.network = fwEdited{demoWorld: w, edit: func(fw *model.NetFirewall) {
			if from, err := time.Parse(time.RFC3339Nano, fw.From); err == nil {
				fw.Oldest = from.Add(18 * time.Hour).UTC().Format(time.RFC3339Nano)
			}
		}}
		rep := runSummary(t, srv, "network")
		c := rep.Views["overview"].card(t, "network")
		if !regexp.MustCompile(`packets blocked by the firewall since \S`).MatchString(c.Text) || strings.Contains(c.Text, "blocked by the firewall in 24") {
			t.Errorf("the Network card: %q", c.Text)
		}
		viewChecker(t, rep)("overview network", "The gateway’s firewall, since ", "The syslog kept starts at ", "the counts cover less than 24 hours")
	})
	t.Run("store closed", func(t *testing.T) {
		w := newDemoWorld(time.Now())
		w.mu.Lock()
		w.netState = "unavailable"
		w.mu.Unlock()
		rep := runSummary(t, newDemoServer(t, w, nil), "network")
		wantCard(t, rep.Views["overview"], "network", rep.Views["overview"].card(t, "network").Chip,
			"The firewall figures could not be read: network firewall: netmap: the syslog store is closed: unavailable.")
		notContains(t, rep.Views["overview"], "network", "keeps no syslog store")
		viewChecker(t, rep)("overview network", "The firewall figures could not be read: ")
		if strings.Contains(rep.Views["overview network"].Text, "keeps no syslog store") {
			t.Error("the Network details say that the monitor keeps no syslog store, which it reports")
		}
	})
	t.Run("no store", func(t *testing.T) {
		w := newDemoWorld(time.Now())
		w.mu.Lock()
		w.netState, w.syslogState = "nosyslog", "nostore"
		w.mu.Unlock()
		rep := runSummary(t, newDemoServer(t, w, nil), "network")
		wantCard(t, rep.Views["overview"], "network", rep.Views["overview"].card(t, "network").Chip, "Firewall: this monitor keeps no syslog store")
		viewChecker(t, rep)("overview network", "This att-monitor keeps no syslog store, so there are no firewall messages to show.")
	})
}

// TestDashboardOverviewNetworkDetailsLists: the Network details rank each list by the value its
// bars show; without an IP address database no organisation is named, which they say (not that
// none was reached). The Network card's chip gives the read's age in whole minutes, and why the
// NAT table is not being read is on the card.
func TestDashboardOverviewNetworkDetailsLists(t *testing.T) {
	requireNode(t)
	rep := runSummary(t, newDemoServer(t, newDemoWorld(time.Now()), nil), "network")
	const orgs = "Most used organisations, last 24 hours (sites)"
	d := rep.Views["overview network"]
	for _, list := range []string{"Devices, last 24 hours (sites reached)", orgs} {
		vals := d.BarValues[list]
		if len(vals) < 3 {
			t.Errorf("%s: %q", list, vals)
			continue
		}
		for i := 1; i < len(vals); i++ {
			a, _ := strconv.Atoi(strings.ReplaceAll(vals[i-1], ",", ""))
			b, _ := strconv.Atoi(strings.ReplaceAll(vals[i], ",", ""))
			if b > a {
				t.Errorf("%s is not ranked by its values: %q (%q)", list, vals, d.Bars[list])
			}
		}
	}
	if c := rep.Views["overview"].card(t, "network"); !regexp.MustCompile(`^info:Read (\d+ s|\d+ min|\d+ h( \d+ min)?) ago$`).MatchString(c.Chip) {
		t.Errorf("the Network card's chip: %q", c.Chip)
	}

	w := newDemoWorld(time.Now())
	w.mu.Lock()
	w.netState = "noipdb"
	w.mu.Unlock()
	rep = runSummary(t, newDemoServer(t, w, nil), "network")
	viewChecker(t, rep)("overview network", orgs, "Organisations are not named: no IP address database is loaded.")
	if strings.Contains(rep.Views["overview network"].Text, "None in the last 24 hours.") {
		t.Error("the Network details say that no organisation was reached")
	}

	w = newDemoWorld(time.Now())
	w.mu.Lock()
	w.netState = "paused"
	w.mu.Unlock()
	rep = runSummary(t, newDemoServer(t, w, nil))
	wantCard(t, rep.Views["overview"], "network", "warning:Not reading", "connections open at the last read",
		"Gateway logins are paused after repeated rejected access codes")
}

// TestAppJSNetworkCardNamesTheDetailsFirst runs the Network card's "Most used" under Node.js:
// it names the organisations its details list first - ranked by the sites reached, the flow
// diagram's groups ("other", "local", "unknown") left out, ties in the server's order - so that
// the card and its details never disagree; the answer's list is not reordered.
func TestAppJSNetworkCardNamesTheDetailsFirst(t *testing.T) {
	prog := jsProgram(t, nil, []string{"netList", "topOrgs", "orgNames"})
	prog += `function netText(text) { return String(text); }
const conn = { orgs: [
  { key: 'other', name: 'Other', sites: 50 }, { key: 'netflix', name: 'Netflix', sites: 2 },
  { key: 'google', name: 'Google', sites: 18 }, { key: 'local', name: 'Local', sites: 30 },
  { key: 'amazon', name: 'Amazon', sites: 9 }, null, { key: 'unknown', name: 'Unknown', sites: 40 },
  { key: 'cloudflare', sites: 9 },
] };
console.log(JSON.stringify({ card: orgNames(conn, 3), details: topOrgs(conn).map((o) => o.name || o.key),
  answer: conn.orgs.map((o) => (o ? o.key : null)), none: orgNames(null, 3) }));
`
	var got struct{ Card, Details, Answer, None []any }
	if err := json.Unmarshal(runNode(t, prog), &got); err != nil {
		t.Fatal(err)
	}
	want := `{[Google Amazon cloudflare] [Google Amazon cloudflare Netflix] [other netflix google local amazon <nil> unknown cloudflare] []}`
	if s := fmt.Sprint(got); s != want {
		t.Errorf("the Network card's organisations:\n got %s\nwant %s", s, want)
	}
}

// TestDashboardOverviewLocalRoute: while this PC's internet traffic leaves through a VPN, the
// This PC's link card is a warning, as everywhere else, and does not say that the home network
// works (that would attribute the outage to AT&T, and it is this PC's routing).
func TestDashboardOverviewLocalRoute(t *testing.T) {
	requireNode(t)
	w := newDemoWorld(time.Now())
	w.setLive(liveVPN)
	rep := runSummary(t, newDemoServer(t, w, nil))
	ov := rep.Views["overview"]
	wantCard(t, ov, "link", "warning:Not through the gateway", "Route to the Internet: through another adapter (a VPN or another network)",
		"This PC reaches the AT&T gateway, but its internet traffic does not go through it.")
	notContains(t, ov, "link", "The home network works")
	if c := ov.card(t, "link"); c.Tone != "warning" {
		t.Errorf("the link card's tone: %q", c.Tone)
	}
}

// TestDashboardOverviewUnknownStatus: an UNKNOWN status that is not stale (a cycle that could not
// be judged) is "Unknown" on the status card, with its reasons there - not "see the reason". The
// last measurement recorded is in the past tense.
func TestDashboardOverviewUnknownStatus(t *testing.T) {
	requireNode(t)
	const why = "the cycle was interrupted by system sleep (the clocks jumped 41 s)"
	rep := summaryOf(t, newDemoWorld(time.Now()), func(st *model.Status) {
		v := model.Verdict{State: model.StateUnknown, Attribution: model.AttrUndetermined, Rules: demoRules, Reasons: []string{why}}
		st.Verdict, st.LastSample.Verdict, st.Since = v, v, ""
	})
	ov := rep.Views["overview"]
	if !strings.Contains(ov.Hero, "Internet status nowUnknown") || !strings.Contains(ov.Hero, "The cycle was interrupted by system sleep (the clocks jumped 41 s).") ||
		strings.Contains(ov.Hero, "see the reason") {
		t.Errorf("status card: %q", ov.Hero)
	}
	// Stale, with no internet probe answering then: what the gateway did is past.
	w := newDemoWorld(time.Now())
	w.mu.Lock()
	w.stale = true
	w.mu.Unlock()
	rep = summaryOf(t, w, func(st *model.Status) {
		for _, p := range st.LastSample.Probes {
			if p.Role == model.RoleInet || p.Role == model.RoleISPHop {
				setProbe(st, p.Name, false, "IP_REQ_TIMED_OUT")
			}
		}
	})
	wantCard(t, rep.Views["overview"], "internet", "none:Not current", "Last recorded: The AT&T gateway answered (", "; the AT&T next hop did not.")
	notContains(t, rep.Views["overview"], "internet", "answers (")
}

// TestDashboardOverviewStripBehindTheStatus: a series minutes older than the status (read before
// the page was hidden for a while) does not end "now" on the status card's strip: its times are
// given instead.
func TestDashboardOverviewStripBehindTheStatus(t *testing.T) {
	requireNode(t)
	rep := summaryOf(t, newDemoWorld(time.Now()), func(st *model.Status) {
		st.Now = time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339Nano)
	})
	if s := rep.Views["overview"].Strip; strings.Contains(s, " ago") || !regexp.MustCompile(`^\d{1,2}:\d\d`).MatchString(s) {
		t.Errorf("the strip of a series behind the status: %q", s)
	}
}

// TestDashboardOverviewNoTooltipsUnderTheButton: a summary card's button covers the whole card,
// so no tooltip in it could show: the cards hold none, and what one would say is on the card. The
// footer does not promise UTC on hover where no tooltip shows.
func TestDashboardOverviewNoTooltipsUnderTheButton(t *testing.T) {
	requireNode(t)
	w := newDemoWorld(time.Now())
	w.setOutage(true)
	ov := runSummary(t, newDemoServer(t, w, nil)).Views["overview"]
	for _, c := range ov.Cards {
		if c.Titles != 0 {
			t.Errorf("the %s card holds %d tooltips", c.Key, c.Titles)
		}
	}
	if ov.StatusTitles != 0 {
		t.Errorf("the status card holds %d tooltips", ov.StatusTitles)
	}
	index, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(index), "hover over a time in a list, a page or a card’s details to see UTC") {
		t.Error("index.html: the footer promises UTC on hover everywhere")
	}
}

// TestAppJSOverviewFigures runs the Overview's figures under Node.js: the median round trip as
// the classifier computes it (the mean of the two middle values for an even count), the gateway
// as the classifier judges it (a refused TCP connection is an answer) in the status card's facts
// and in the Internet card's words (in the past tense for the last measurement recorded), and the
// packet loss rounded rather than truncated.
func TestAppJSOverviewFigures(t *testing.T) {
	prog := jsProgram(t, []string{"CAUSES"}, []string{"humanize", "statusStale", "causeWords", "gatewayAnswered", "isICMP", "probeFacts", "medianOf",
		"gatewayRTTWords", "statusFacts", "gatewayWords", "fmtMs", "fmtRTT", "lossText"})
	prog += `const probe = (name, role, kind, ok, rtt, status) => ({ name, role, kind, ok, rtt_us: ok ? rtt : 0, status: status || '' });
const inet = (rtts) => rtts.map((r, i) => probe('inet' + i, 'internet', 'icmp', r > 0, r));
const st = (probes) => ({ verdict: { state: 'ONLINE' }, since: 'x', last_sample: { probes } });
const gw = (icmpOK, tcpOK, tcpStatus) => [probe('gateway_icmp', 'gateway', 'icmp', icmpOK, 1900), probe('gateway_tcp', 'gateway', 'tcp', tcpOK, 3100, tcpStatus)];
const hop = [probe('isp_hop_icmp', 'isp_hop', 'icmp', false, 0)];
console.log(JSON.stringify({
  facts: [
    st(gw(true, true).concat(inet([12200, 13400, 15300, 15500, 0]))),
    st(gw(true, true).concat(inet([12000, 90000]))),
    st(gw(false, true).concat(inet([0, 0]))),
    st(gw(false, false, 'refused').concat(inet([0, 0]))),
    st(gw(false, false, 'timeout').concat(inet([0, 0]))),
  ].map(statusFacts),
  words: [[gw(false, true), false], [gw(false, false, 'refused'), false], [gw(false, false, 'timeout'), false], [gw(true, true), true]]
    .map(([g, stale]) => gatewayWords(probeFacts({ probes: g.concat(hop, inet([0])) }), stale)),
  loss: [4.08, 0.19, 2.99, 0.05, 0, null].map(lossText),
}));
`
	var got struct{ Facts, Words, Loss []string }
	if err := json.Unmarshal(runNode(t, prog), &got); err != nil {
		t.Fatal(err)
	}
	want := struct{ Facts, Words, Loss []string }{
		Facts: []string{
			"4 of 5 internet probes answered · AT&T gateway 1.9 ms · median round trip 14.3 ms",
			"2 of 2 internet probes answered · AT&T gateway 1.9 ms · median round trip 51.0 ms",
			"0 of 2 internet probes answered · AT&T gateway 3.1 ms over TCP",
			"0 of 2 internet probes answered · the AT&T gateway answered (TCP connection refused)",
			"0 of 2 internet probes answered · the AT&T gateway did not answer",
		},
		Words: []string{
			"The AT&T gateway answers (3.1 ms over TCP); the AT&T next hop does not.",
			"The AT&T gateway answers (it refused a TCP connection); the AT&T next hop does not.",
			"The AT&T gateway did not answer either.",
			"The AT&T gateway answered (1.9 ms); the AT&T next hop did not.",
		},
		Loss: []string{"4.1 %", "0.2 %", "3.0 %", "< 0.1 %", "0 %", "—"},
	}
	for _, c := range []struct {
		name      string
		got, want []string
	}{{"statusFacts", got.Facts, want.Facts}, {"gatewayWords", got.Words, want.Words}, {"lossText", got.Loss, want.Loss}} {
		if strings.Join(c.got, "\n") != strings.Join(c.want, "\n") {
			t.Errorf("%s:\n got %q\nwant %q", c.name, c.got, c.want)
		}
	}
}

// TestAppJSSeriesWorkedOutOnce: what the summary draws from a series (its range and buckets, its
// runs of states, the day's packet loss) is worked out once per series read, not at every status
// update and flow meter reading: the second time, no time stamp is parsed again.
func TestAppJSSeriesWorkedOutOnce(t *testing.T) {
	prog := jsProgram(t, []string{"seriesMemos"}, []string{"toDate", "toMs", "numOrNull", "seriesMemo", "seriesGeom", "seriesRuns", "stateRuns",
		"inetKeys", "seriesLoss"})
	prog += `let parsed = 0;
const parse = toDate;
toDate = (v) => { parsed++; return parse(v); };
const from = Date.parse('2026-10-05T03:00:00Z');
const ser = { from: new Date(from).toISOString(), to: new Date(from + 600000).toISOString(), step_s: 60,
  probes: [{ name: 'inet_a', role: 'internet' }],
  points: Array.from({ length: 10 }, (_, i) => ({ t: new Date(from + i * 60000).toISOString(), state: 'ONLINE', loss: { inet_a: i === 3 ? 1 : 0 } })) };
const first = [seriesGeom(ser), seriesRuns(ser), seriesLoss(ser)];
const once = parsed;
const again = [seriesGeom(ser), seriesRuns(ser), seriesLoss(ser)];
console.log(JSON.stringify({ once, again: parsed - once, same: first.every((x, i) => x === again[i]), loss: again[2], runs: again[1].length }));
`
	var got struct {
		Once, Again int
		Same        bool
		Loss        float64
		Runs        int
	}
	if err := json.Unmarshal(runNode(t, prog), &got); err != nil {
		t.Fatal(err)
	}
	if got.Once == 0 || got.Again != 0 || !got.Same || got.Loss != 10 || got.Runs != 1 {
		t.Errorf("a series worked out again: %+v", got)
	}
}

// cssRule returns the declarations of the first rule of style.css whose selector is sel.
func cssRule(t *testing.T, css, sel string) string {
	t.Helper()
	i := strings.Index(css, "\n"+sel+" {")
	if i < 0 {
		t.Fatalf("style.css has no rule %s", sel)
	}
	body := css[i+len(sel)+3:]
	return body[:strings.Index(body, "}")]
}

// TestStyleOverviewRules: the Overview's style rules that a review found missing - the strip's
// axis readable on the outage card (4.5:1 needs text-2 on critical-bg), a chip that wraps under a
// one-word title, the details' body a visible Tab stop, the top bar kept in place while the page
// is locked, and a fixed header that leaves the body room on a short window - and the page locked
// without a gutter kept for its scroll bar, which the details' backdrop does not cover (a bright
// band beside the dimmed page, seen in the browser): the body gets the scroll bar's room instead.
func TestStyleOverviewRules(t *testing.T) {
	b, err := staticFS.ReadFile("static/style.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(b)
	for _, c := range []struct{ sel, want string }{
		{".strip-axis", "color: var(--text-2)"},
		{".sum-head", "flex-wrap: wrap"},
		{".sum-title", "min-width: auto"},
		{".detail-body:focus-visible", "outline: 2px solid var(--focus); outline-offset: -2px"},
		{"html.detail-open body", "overflow: visible"},
	} {
		if !strings.Contains(cssRule(t, css, c.sel), c.want) {
			t.Errorf("style.css: %s does not set %q", c.sel, c.want)
		}
	}
	if strings.Contains(css, ".detail-body:focus { outline: none; }") {
		t.Error("style.css hides the focus ring of the details' body")
	}
	short := css[strings.Index(css, "@media (max-height: 480px)"):]
	if !strings.Contains(short[:strings.Index(short, "\n}")], ".detail-context, .detail-ico-box { display: none; }") {
		t.Error("style.css: a short window keeps the details' whole header")
	}
	if strings.Contains(css, "scrollbar-gutter") {
		t.Error("style.css keeps a gutter for the scroll bar, which the details' backdrop does not cover")
	}
	if lock, _, _ := functionSource(t, appJS(t), "lockScroll"); !strings.Contains(lock, "document.body.style.paddingRight = bar + 'px'") {
		t.Errorf("lockScroll does not give the body the room of the scroll bar it takes away:\n%s", lock)
	}
}
