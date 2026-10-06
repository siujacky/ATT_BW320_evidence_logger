package web

// The Network page as the dashboard shows it (docs/syslog-map-graphic.md §2.3), driven in
// testdata/dashboard_harness.js against the demo world: what each tab shows, what it asks the
// server for, where the keyboard focus goes when the reader uses it, the states it explains, and
// the layout helpers of its charts run under Node.js.

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/contracts"
)

// TestDashboardNetworkPage uses the Network page as a keyboard user (the harness's networkSteps):
// the flow diagram's nodes, a device shown alone and every device again, the world map read from
// the keyboard, the table's search, sort and "Show all", the table views, a custom period, then
// the Firewall tab, its timeline read from the keyboard across a refresh.
func TestDashboardNetworkPage(t *testing.T) {
	requireNode(t)
	w := newDemoWorld(time.Now())
	rep := runDashboard(t, w, "network")
	contains := viewChecker(t, rep)

	contains("network", "Which device talks to which site, and what the gateway’s firewall blocks.", "Address data: IPtoASN, ",
		"NAT table last read ", " · every 4 min",
		"Devices active", "8 of the 8 in the gateway’s Device List, and the gateway", "remote addresses", "Organisations", "Open now", "connections in the NAT table",
		"Devices and the sites they reach", "Last 24 hours. Band width: how often the connection was open when the NAT table was read.",
		"DEVICE", "ORGANISATION", "SERVICE", "Office PC", "Google", "HTTPS", "Other (",
		"Where the sites are", "Sites per country", "Top countries", "United States", "other countries",
		"Each device’s remote addresses, most seen first.", "Showing 25 of ", "Show all",
		"How this is measured", "every 4 min", "an IPv6 connection appears only when the gateway lists it there too", "no address is sent anywhere to name them",
		"looked up through this PC’s DNS resolver", "This is not evidence", "kept for 30 days")
	// The first device of the diagram, chosen with Enter: only it is shown, and the keyboard focus
	// stays on its node, which now offers every device again.
	contains("network device", "Only Office PC is shown.", "Show every device", "the device chosen",
		"connections of this device in the NAT table")
	if f := rep.Views["network device"].Focus; f != "g:Office PC 100 %" {
		t.Errorf("focus after Enter on a device: %q", f)
	}
	// "Show every device" goes with the filter: the focus moves to the device filter.
	if f := rep.Views["network every device"].Focus; !strings.HasPrefix(f, "select:All devices") {
		t.Errorf("focus after Show every device: %q", f)
	}
	if strings.Contains(rep.Views["network every device"].Text, "Only Office PC is shown.") {
		t.Error("the device filter is still shown after Show every device")
	}
	// The search keeps the rows with every word typed.
	contains("network search", " connections match")
	for _, r := range rep.Views["network search"].Rows {
		if strings.Contains(r.Text, "AS8075") {
			t.Errorf("a Microsoft row matches the search for google: %s", r.Text)
		}
	}
	// A sort heading keeps the focus after the table is rebuilt; "Show all" turns into its opposite.
	if f := rep.Views["network sorted"].Focus; f != "button:Last seen ▼" {
		t.Errorf("focus after sorting: %q", f)
	}
	contains("network all rows", "Showing all ")
	if f := rep.Views["network all rows"].Focus; f != "button:Show the first 25" {
		t.Errorf("focus after Show all: %q", f)
	}
	contains("network tables", "Devices → organisations", "Organisations → services", "Share of the device", "Share of the organisation",
		"Code", "Times seen")
	contains("network custom", "Open at the last read", " – ")
	contains("network custom refused", "The start must be before the end.")
	// "Custom…" opens its form, but the period in use stays checked - as the data, the URL and
	// the refresh stay on it - until Apply changes the period; Cancel closes the form and gives
	// the keyboard focus back to the period in use.
	for _, c := range []struct {
		view, radio string
		form        bool
		hash        func(string) bool
	}{
		{"network custom open", "24h", true, func(h string) bool { return h == "#/network?range=24h" }},
		{"network custom cancelled", "24h", false, func(h string) bool { return h == "#/network?range=24h" }},
		{"network custom", "custom", true, func(h string) bool { return strings.HasPrefix(h, "#/network?from=") && strings.Contains(h, "&to=") }},
		{"network custom refused", "custom", true, func(h string) bool { return strings.HasPrefix(h, "#/network?from=") }},
		{"network firewall 1h", "1h", false, func(h string) bool { return h == "#/network/firewall?range=1h" }},
	} {
		v := rep.Views[c.view]
		if !slices.Equal(v.Radios, []string{c.radio}) || slices.Contains(v.Forms, "Custom period") != c.form || !c.hash(v.Hash) {
			t.Errorf("%s: checked %q, forms shown %q, hash %q; want %s checked, the custom period's form shown %v", c.view, v.Radios, v.Forms, v.Hash, c.radio, c.form)
		}
	}
	if f := rep.Views["network custom cancelled"].Focus; f != "input:radio 24h" {
		t.Errorf("focus after Cancel: %q", f)
	}
	contains("network firewall", "From the gateway’s syslog · last message ", "Inbound blocked", "probes from the Internet", "Sources",
		"Outbound blocked", "Most probed", "SSH", "Blocked per hour", "Inbound probes", "Outbound packets from the home network",
		"To or from the gateway itself", "By reason: ", "Unsolicited, to the gateway", "Where the probes came from", "Probes per country",
		"Most probed services", "Other ports", "Top sources", "Censys", "Blocked on the way out", "Invalid state (the connection was already closed)",
		"What the syslog can show", "never the connections it allows", "Connections tab")
	// The outbound tile counts every device whose packets were blocked, also those beyond the rows
	// listed (the demo's phone), as the server counted them.
	to := time.Now()
	fw, err := w.Firewall(context.Background(), contracts.NetQuery{From: to.Add(-7 * 24 * time.Hour), To: to})
	if err != nil || fw.OutboundDevices < 2 {
		t.Fatalf("the demo's firewall view: %d devices, %v", fw.OutboundDevices, err)
	}
	contains("network firewall", fmt.Sprintf("packets from %d devices", fw.OutboundDevices))
	if strings.Contains(rep.Views["network firewall"].Text, "packets from at least") {
		t.Error("the outbound tile still guesses the devices from the rows listed")
	}
	// Most probed services: ICMP and ICMPv6 (port 0, with a protocol) by their names, and "Other
	// ports" only for the rest grouped (no port, no protocol), in the bars and in their table view.
	bars := rep.Views["network firewall"].Bars["Most probed services"]
	if !slices.Contains(bars, "SSH 22/tcp") || !slices.Contains(bars, "ICMP") || !slices.Contains(bars, "ICMPv6") ||
		len(bars) == 0 || bars[len(bars)-1] != "Other ports" || slices.Index(bars, "Other ports") != len(bars)-1 {
		t.Errorf("most probed services: %q", bars)
	}
	// A port the port table does not name is named by its port alone, once.
	if !slices.Contains(bars, "8071/tcp") || strings.Contains(rep.Views["network firewall"].Text, "tcp 8071") {
		t.Errorf("the unnamed port: bars %q", bars)
	}
	svcRows := map[string]int{}
	for _, r := range rep.Views["network firewall"].Rows {
		for _, p := range []string{"Other ports—", "ICMP—", "ICMPv6—"} {
			if strings.HasPrefix(r.Text, p) {
				svcRows[p]++
			}
		}
	}
	if svcRows["Other ports—"] != 1 || svcRows["ICMP—"] != 1 || svcRows["ICMPv6—"] != 1 {
		t.Errorf("rows of the most probed services' table view: %v", svcRows)
	}
	// The countries the map has no shape for (Singapore, Hong Kong; Unknown), beyond the top five:
	// listed beside the map, which shades them nowhere.
	if text := rep.Views["network firewall"].Text; !strings.Contains(text, "Not on the map: ") {
		t.Error("the firewall map does not list the countries it has no shape for")
	} else {
		note, _, _ := strings.Cut(text[strings.Index(text, "Not on the map: "):], ".")
		if !strings.Contains(note, "Singapore ") || !strings.Contains(note, "Unknown ") || strings.Contains(note, "United States") {
			t.Errorf("countries not on the map: %q", note)
		}
	}
	// The timeline read from the keyboard across the refresh every minute: the hour reached
	// stays chosen (by its start) and shown, the chart keeps the focus, its live region (the one
	// written before: a new one, written, would be announced) says nothing new, and the next
	// arrow key goes on from that hour.
	var steps []struct {
		Step    string `json:"step"`
		UTC     string `json:"utc"`
		Live    string `json:"live"`
		Writes  int    `json:"writes"`
		Focused bool   `json:"focused"`
		Same    bool   `json:"same"`
	}
	if err := json.Unmarshal(rep.Facts["timeline"], &steps); err != nil || len(steps) != 4 {
		t.Fatalf("the timeline's steps: %s (%v)", rep.Facts["timeline"], err)
	}
	hour := func(i int) time.Time {
		at, err := time.Parse("2006-01-02 15:04 UTC", steps[i].UTC)
		if err != nil || steps[i].Live == "" || !steps[i].Focused {
			t.Fatalf("timeline, %s: %+v", steps[i].Step, steps[i])
		}
		return at
	}
	last, back5, refreshed, back6 := hour(0), hour(1), hour(2), hour(3)
	if back5 != last.Add(-5*time.Hour) {
		t.Errorf("timeline: five hours back from %s is %s", steps[0].UTC, steps[1].UTC)
	}
	if refreshed != back5 || steps[2].Live != steps[1].Live || steps[2].Writes != steps[1].Writes || !steps[2].Same {
		t.Errorf("timeline after the refresh: %+v; before it: %+v", steps[2], steps[1])
	}
	if back6 != back5.Add(-time.Hour) || steps[3].Live == steps[2].Live || steps[3].Writes != steps[2].Writes+1 {
		t.Errorf("timeline, one hour back after the refresh: %+v; before: %+v", steps[3], steps[2])
	}

	// What the page asked for: its period as range=, a device filter, a custom period, the
	// firewall; the world map once for both tabs; nothing with a device on the Firewall tab.
	for _, path := range []string{
		"/api/network/connections?range=24h&limit=1000",
		"/api/network/connections?range=24h&device=mac%3A00%3A00%3A5e%3A00%3A53%3A01&limit=1000",
		"/api/network/status",
		"/api/network/firewall?range=7d&limit=1000",
		"/api/network/firewall?range=1h&limit=1000",
	} {
		if !requested(rep, "GET", path) {
			t.Errorf("the page did not ask for %s", path)
		}
	}
	world, custom := 0, 0
	for _, r := range rep.Requests {
		switch {
		case r.Path == "/static/world.json":
			world++
		case strings.HasPrefix(r.Path, "/api/network/connections?from="):
			custom++
		case strings.HasPrefix(r.Path, "/api/network/firewall") && strings.Contains(r.Path, "device="):
			t.Errorf("the Firewall tab sent a device filter: %s", r.Path)
		}
		if strings.HasPrefix(r.Path, "/api/network/") && r.Status != 200 {
			t.Errorf("%s %s answered %d", r.Method, r.Path, r.Status)
		}
	}
	if world != 1 {
		t.Errorf("the world map was read %d times, want once", world)
	}
	if custom != 1 {
		t.Errorf("%d requests for the custom period, want 1 (the refused one is not sent)", custom)
	}
}

// TestDashboardNetworkStates: what the page says when the samplers are off, the NAT table is not
// read (logins paused, no access code), nothing was read yet, the IP database is not loaded, the
// monitor keeps no syslog store, the firewall dropped nothing, or the view fails.
func TestDashboardNetworkStates(t *testing.T) {
	requireNode(t)
	for _, tc := range []struct {
		state   string
		conn    []string
		fw      []string
		notConn []string
		notFw   []string
	}{
		{state: "nosamples", conn: []string{"The NAT table has not been read yet: the first read is due at", "NAT table not read yet"},
			notConn: []string{"Devices and the sites they reach"}},
		{state: "off", conn: []string{"Connections are not being recorded.", "turned off in the configuration (connections.enabled)"}},
		{state: "paused", conn: []string{"The NAT table is not being read.", "Gateway logins are paused", "The newest read is from ",
			"Open at the last read", "connections in the NAT table at "}, notConn: []string{"Open now"}},
		{state: "noaccess", conn: []string{"The NAT table is not being read.", "No gateway device access code is stored", "The NAT table has not been read yet."},
			notConn: []string{"first read is due"}},
		{state: "noipdb", conn: []string{"The IP address database is not loaded yet, so organisations and countries are not shown.",
			"only the files are fetched: no address is sent anywhere", "Last attempt: download ip2asn-v4.tsv.gz", "No IP address database loaded yet", "Unknown"}},
		{state: "natnote", conn: []string{"The NAT table is read, but not all of it is kept.", "3 rows of the NAT table page left out (not understood).",
			"NAT table last read "}, notConn: []string{"The NAT table is not being read."}},
		// More distinct connections than the connection store counts one by one: the page says that
		// the lightest count only in their devices and as "Other".
		{state: "busy", conn: []string{"A very busy period. 412 connections were too light to count one by one",
			"the sites and organisations are at least the numbers shown. A shorter period, or one device, shows more of them."}},
		// The firewall view is unavailable without a syslog store (503, as netmap's): the tab says why
		// and what the syslog would show, never the bare error.
		{state: "nosyslog", fw: []string{"This att-monitor keeps no syslog store, so there are no firewall messages to show.", "What the syslog can show"},
			notFw: []string{"network firewall:", "unavailable"}},
		{state: "nodrops", fw: []string{"The gateway’s firewall dropped nothing in this period.", "What the syslog can show"}},
		// Settings in config.json that the service replaced are said on both tabs, not only in the log.
		{state: "cfgwarn",
			conn: []string{"Some Network page settings in config.json are not used as written.",
				"Connections.interval is 10m0s, above the maximum: 4m0s is used.", "Geo.download is not true or false: it is turned off."},
			fw: []string{"Some Network page settings in config.json are not used as written.",
				"Connections.interval is 10m0s, above the maximum: 4m0s is used."}},
		{state: "unavailable", conn: []string{"network connections: connstore: the connection store is closed"},
			fw: []string{"network firewall: netmap: the syslog store is closed"}},
	} {
		t.Run(tc.state, func(t *testing.T) {
			t.Parallel()
			w := newDemoWorld(time.Now())
			w.mu.Lock()
			w.netState = tc.state
			w.mu.Unlock()
			rep := runDashboard(t, w, "networktabs")
			contains := viewChecker(t, rep)
			contains("network", tc.conn...)
			contains("network firewall", tc.fw...)
			for _, s := range tc.notConn {
				if strings.Contains(rep.Views["network"].Text, s) {
					t.Errorf("the Connections tab shows %q", s)
				}
			}
			for _, s := range tc.notFw {
				if strings.Contains(rep.Views["network firewall"].Text, s) {
					t.Errorf("the Firewall tab shows %q", s)
				}
			}
		})
	}
}

// TestAppJSNetworkLayout runs the Network page's layout helpers from app.js under Node.js: the
// map's colour steps, the flow diagram's layout (one scale for both ends of a band, nodes in
// their column, bands that do not cross at the nodes, a minimum height), label spreading, Go
// durations, shares and the address sort key.
func TestAppJSNetworkLayout(t *testing.T) {
	prog := jsProgram(t, nil, []string{"mapBreaks", "mapStep", "sankeyLayout", "spreadLabels", "goDurMs", "netShare", "ipSortKey"})
	prog += `
const breaks = {};
for (const m of [0, 1, 3, 5, 6, 12, 30, 152, 3664, 100000]) breaks[m] = mapBreaks(m);
let increasing = true;
for (let m = 1; m <= 200000; m = Math.ceil(m * 1.07)) {
  const b = mapBreaks(m);
  for (let i = 1; i < b.length; i++) if (!(b[i] > b[i - 1])) increasing = false;
  if (b[0] !== 1 || b.length !== 5 || (m > 5 && b[4] > m)) increasing = false;
}
const steps = [0, 1, 2, 4, 5, 19, 20, 49, 50, 1e6].map((v) => mapStep(v, [1, 2, 5, 20, 50]));

// devices A (60) and B (40) -> organisations X (70) and Y (30) -> service S (100); a tiny C (0.1).
const node = (col, key, extra) => Object.assign({ col, key, in: 0, out: 0, value: 0, links: [] }, extra);
const A = node(0, 'A'), B = node(0, 'B'), C = node(0, 'C'), X = node(1, 'X'), Y = node(1, 'Y'), S = node(2, 'S');
const links = [];
const link = (a, b, w) => { const l = { a, b, w }; links.push(l); a.out += w; b.in += w; a.links.push(l); b.links.push(l); };
link(A, Y, 20); link(A, X, 40); link(B, X, 30); link(B, Y, 10); link(C, Y, 0.1); link(X, S, 70); link(Y, S, 30.1);
for (const n of [A, B, C, X, Y, S]) n.value = Math.max(n.in, n.out);
const m = { cols: [[A, B, C], [X, Y], [S]], links };
const k = sankeyLayout(m, { top: 30, height: 300, xs: [100, 400, 700], nodeW: 10, pad: 10, minH: 3 });
const r1 = (v) => Math.round(v * 1000) / 1000;
const layout = {
  k: r1(k),
  nodes: [A, B, C, X, Y, S].map((n) => [n.key, r1(n.x), r1(n.y), r1(n.h)]),
  // A's bands leave in the order of the organisations they reach (X above Y), and arrive at Y in
  // the order of the devices they come from (A, B, C).
  aOut: A.links.filter((l) => l.a === A).sort((p, q) => p.y0 - q.y0).map((l) => l.b.key),
  yIn: Y.links.filter((l) => l.b === Y).sort((p, q) => p.y1 - q.y1).map((l) => l.a.key),
  widths: links.map((l) => r1(l.width / l.w)),
  paths: links.slice(0, 1).map((l) => l.d),
  inside: [A, B, C, X, Y, S].every((n) => n.y >= 30 - 1e-9 && n.y + n.h <= 330 + 1e-9),
  bandsInNodes: links.every((l) => l.y0 - l.width / 2 >= l.a.y - 1e-9 && l.y0 + l.width / 2 <= l.a.y + l.a.h + 1e-9 &&
    l.y1 - l.width / 2 >= l.b.y - 1e-9 && l.y1 + l.width / 2 <= l.b.y + l.b.h + 1e-9),
};
const empty = { cols: [[], [], []], links: [] };
console.log(JSON.stringify({
  breaks, increasing, steps, layout, emptyK: sankeyLayout(empty, { top: 0, height: 100, xs: [0, 1, 2], nodeW: 10, pad: 10, minH: 3 }),
  spread: [spreadLabels([10, 12, 13], 16, 0, 100), spreadLabels([90, 95], 16, 0, 100), spreadLabels([50], 16, 0, 100)],
  durs: ['4m0s', '15m0s', '1h30m', '2h0m0s', '250ms', '1.5s', '', 'bogus', '4 m', '-4m'].map(goDurMs),
  shares: [[36, 100], [1, 200], [0, 10], [5, 0], [100, 100]].map(([v, n]) => netShare(v, n)),
  sorted: ['2001:db8::1', '10.0.0.2', '9.0.0.1', '192.0.2.10', '192.0.2.9'].sort((a, b) => (ipSortKey(a) < ipSortKey(b) ? -1 : 1)),
}));
`
	var got struct {
		Breaks     map[string][]float64 `json:"breaks"`
		Increasing bool                 `json:"increasing"`
		Steps      []int                `json:"steps"`
		Layout     struct {
			K            float64   `json:"k"`
			Nodes        [][]any   `json:"nodes"`
			AOut         []string  `json:"aOut"`
			YIn          []string  `json:"yIn"`
			Widths       []float64 `json:"widths"`
			Paths        []string  `json:"paths"`
			Inside       bool      `json:"inside"`
			BandsInNodes bool      `json:"bandsInNodes"`
		} `json:"layout"`
		EmptyK float64     `json:"emptyK"`
		Spread [][]float64 `json:"spread"`
		Durs   []*float64  `json:"durs"`
		Shares []string    `json:"shares"`
		Sorted []string    `json:"sorted"`
	}
	out := runNode(t, prog)
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("output %s: %v", out, err)
	}
	for m, want := range map[string][]float64{
		"0": {1, 2, 3, 4, 5}, "1": {1, 2, 3, 4, 5}, "5": {1, 2, 3, 4, 5}, "6": {1, 2, 3, 4, 5}, "30": {1, 2, 5, 10, 20},
		"152": {1, 2, 5, 20, 50}, "3664": {1, 5, 20, 100, 500}, "100000": {1, 10, 100, 1000, 10000},
	} {
		if !slices.Equal(got.Breaks[m], want) {
			t.Errorf("mapBreaks(%s) = %v, want %v", m, got.Breaks[m], want)
		}
	}
	if !got.Increasing {
		t.Error("mapBreaks: some steps do not increase, do not start at 1 or end above the largest value")
	}
	if want := []int{0, 1, 2, 2, 3, 3, 4, 4, 5, 5}; !slices.Equal(got.Steps, want) {
		t.Errorf("mapStep = %v, want %v", got.Steps, want)
	}
	// One scale for every column: the devices' column binds - 300 px less 2 pads of 10, less the
	// 3 px minimum of the tiny node, shared by the other weights (100).
	if got.Layout.K != 2.77 {
		t.Errorf("k = %v", got.Layout.K)
	}
	for _, w := range got.Layout.Widths {
		if w != got.Layout.K {
			t.Errorf("a band's width is not its weight times k: %v (k %v)", got.Layout.Widths, got.Layout.K)
			break
		}
	}
	if !slices.Equal(got.Layout.AOut, []string{"X", "Y"}) || !slices.Equal(got.Layout.YIn, []string{"A", "B", "C"}) {
		t.Errorf("band order: A leaves to %v, Y receives from %v", got.Layout.AOut, got.Layout.YIn)
	}
	if !got.Layout.Inside || !got.Layout.BandsInNodes {
		t.Errorf("layout outside its box or bands outside their nodes: %+v", got.Layout)
	}
	nodes := map[string][]any{}
	for _, n := range got.Layout.Nodes {
		nodes[n[0].(string)] = n
	}
	if h := nodes["C"][3].(float64); h != 3 {
		t.Errorf("the tiny node is %v px tall, want the minimum 3", h)
	}
	if x := nodes["X"][1].(float64); x != 400 {
		t.Errorf("organisations at x %v", x)
	}
	if hA, hB := nodes["A"][3].(float64), nodes["B"][3].(float64); hA/hB < 1.49 || hA/hB > 1.51 {
		t.Errorf("node heights %v and %v are not in the ratio of their weights 60:40", hA, hB)
	}
	if p := got.Layout.Paths; len(p) != 1 || !strings.HasPrefix(p[0], "M110.0 ") || !strings.Contains(p[0], "C255.0 ") || !strings.Contains(p[0], " 400.0 ") {
		t.Errorf("band path %q: from the right edge of the device to the organisation, controls half-way", p)
	}
	if got.EmptyK != 0 {
		t.Errorf("an empty diagram has k %v", got.EmptyK)
	}
	for i, want := range [][]float64{{10, 26, 42}, {84, 100}, {50}} {
		if !slices.Equal(got.Spread[i], want) {
			t.Errorf("spreadLabels case %d = %v, want %v", i, got.Spread[i], want)
		}
	}
	wantDurs := []any{240000.0, 900000.0, 5400000.0, 7200000.0, 250.0, 1500.0, nil, nil, nil, nil}
	for i, w := range wantDurs {
		switch g := got.Durs[i]; {
		case w == nil && g != nil:
			t.Errorf("goDurMs case %d = %v, want null", i, *g)
		case w != nil && (g == nil || *g != w.(float64)):
			t.Errorf("goDurMs case %d = %v, want %v", i, g, w)
		}
	}
	if want := []string{"36 %", "< 1 %", "0 %", "—", "100 %"}; !slices.Equal(got.Shares, want) {
		t.Errorf("netShare = %q, want %q", got.Shares, want)
	}
	if want := []string{"9.0.0.1", "10.0.0.2", "192.0.2.9", "192.0.2.10", "2001:db8::1"}; !slices.Equal(got.Sorted, want) {
		t.Errorf("addresses sorted %q, want %q", got.Sorted, want)
	}
}

// TestAppJSFlowDiagramSizes runs the flow diagram's sizing from app.js under Node.js. A long column
// of devices (a household over 30 days) makes the diagram taller: every node stays inside the
// drawing, every label too and 16 px from the next, and a device with most of the weight stays
// tall, where a height held at 640 px squeezed every node to 3 px and pushed the first labels above
// the drawing; a column of up to 34 nodes keeps the height it had. The longest device or service
// label gets all the room its margin was widened for: rounded down, the margin cut it by a
// character.
func TestAppJSFlowDiagramSizes(t *testing.T) {
	prog := jsProgram(t, []string{"NET_SANKEY"}, []string{"sankeyHeight", "sankeyColumns", "sankeyLayout", "spreadLabels"})
	prog += `
const o = NET_SANKEY;
const node = (col, key) => ({ col, key, in: 0, out: 0, value: 0, links: [] });
// n devices -> one organisation -> one service; the first device has 99 % of the weight, or all
// have the same.
function diagram(n, heavy) {
  const devs = [];
  const links = [];
  const org = node(1, 'org');
  const svc = node(2, 'svc');
  const link = (a, b, w) => { const l = { a, b, w }; links.push(l); a.out += w; b.in += w; a.links.push(l); b.links.push(l); };
  for (let i = 0; i < n; i++) {
    const d = node(0, 'd' + i);
    devs.push(d);
    link(d, org, heavy && i === 0 ? 99 * Math.max(1, n - 1) : 1);
  }
  link(org, svc, org.in);
  for (const x of [...devs, org, svc]) x.value = Math.max(x.in, x.out);
  const top = 30;
  const height = sankeyHeight(n, o);
  sankeyLayout({ cols: [devs, [org], [svc]], links }, { top, height, xs: [100, 400, 700], nodeW: 10, pad: o.pad, minH: o.minH });
  const ys = spreadLabels(devs.map((x) => x.y + x.h / 2), o.gap, top + o.edge, top + height - o.edge);
  const eps = 1e-6;
  return {
    n, heavy, height,
    nodesInside: [...devs, org, svc].every((x) => x.y >= top - eps && x.y + x.h <= top + height + eps),
    labelsInside: ys.every((y) => y >= top + o.edge - eps && y <= top + height - o.edge + eps),
    labelsApart: ys.every((y, i) => i === 0 || y - ys[i - 1] >= o.gap - eps),
    firstH: devs[0].h,
  };
}
const cases = [];
for (const n of [1, 5, 9, 21, 22, 34, 35, 41, 45, 50, 64, 100, 250]) for (const heavy of [true, false]) cases.push(diagram(n, heavy));
// The characters of the longest label each margin was made for, and the room it gets: devices
// (a name of L characters and its share, 6), services (a name of L, its port "443/tcp" and share, 16).
const rooms = [];
for (const W of [760, 1000, 1400]) {
  for (let L = 1; L <= 28; L++) {
    const p = sankeyColumns(W, L + 6, L + 16, 10);
    rooms.push({ W, L, device: p.room[0], service: p.room[2] - 16, xs: p.xs });
  }
}
console.log(JSON.stringify({ cases, rooms }));
`
	var got struct {
		Cases []struct {
			N            int     `json:"n"`
			Heavy        bool    `json:"heavy"`
			Height       float64 `json:"height"`
			NodesInside  bool    `json:"nodesInside"`
			LabelsInside bool    `json:"labelsInside"`
			LabelsApart  bool    `json:"labelsApart"`
			FirstH       float64 `json:"firstH"`
		} `json:"cases"`
		Rooms []struct {
			W       int       `json:"W"`
			L       int       `json:"L"`
			Device  int       `json:"device"`
			Service int       `json:"service"`
			XS      []float64 `json:"xs"`
		} `json:"rooms"`
	}
	out := runNode(t, prog)
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("output %s: %v", out, err)
	}
	if len(got.Cases) != 26 || len(got.Rooms) != 3*28 {
		t.Fatalf("%d cases, %d rooms", len(got.Cases), len(got.Rooms))
	}
	for _, c := range got.Cases {
		if !c.NodesInside || !c.LabelsInside || !c.LabelsApart {
			t.Errorf("%d devices (one with 99 %% of the weight: %v), %v px: nodes inside %v, labels inside %v, labels 16 px apart %v",
				c.N, c.Heavy, c.Height, c.NodesInside, c.LabelsInside, c.LabelsApart)
		}
		if old := min(640, max(200, 30*float64(c.N))); c.N <= 34 && c.Height != old {
			t.Errorf("%d devices: %v px, want the height it had, %v", c.N, c.Height, old)
		}
		// Beyond 640 px, the 200 px left for the weights go to the device that has almost all of
		// them (held at 640 px, 50 such devices were all 3 px tall).
		if c.Heavy && c.N > 34 && c.FirstH < 200 {
			t.Errorf("%d devices: the one with 99 %% of the weight is %v px tall", c.N, c.FirstH)
		}
	}
	for _, r := range got.Rooms {
		// Within the share of the width a margin may take (28 % on the left, 32 % on the right,
		// 28 characters at most for a device's name), the longest label fits.
		if 26+7.2*float64(r.L+6) <= 0.28*float64(r.W) && r.Device < r.L {
			t.Errorf("W %d: the device column has room for %d characters, its longest name has %d", r.W, r.Device, r.L)
		}
		if 30+7.2*float64(r.L+16) <= 0.32*float64(r.W) && r.Service < r.L {
			t.Errorf("W %d: the service column has room for %d characters, its longest name has %d", r.W, r.Service, r.L)
		}
		if len(r.XS) != 3 || !(r.XS[0] < r.XS[1] && r.XS[1] < r.XS[2]) {
			t.Errorf("W %d, %d characters: columns at %v", r.W, r.L, r.XS)
		}
	}
}

// TestAppJSNetworkStatic: the Network page's code follows the dashboard's rules - it asks only
// its own endpoints and the world map, never sets an inline style other than through the CSSOM
// (positions and bar widths), and its map ramp and device colours are defined for both themes.
func TestAppJSNetworkStatic(t *testing.T) {
	src := appJS(t)
	for _, want := range []string{"'/api/network/' + tab + '?'", "'/api/network/status'", "'/static/world.json'",
		"[/^\\/network$/, 'network'", "[/^\\/network\\/firewall$/, 'network'"} {
		if !strings.Contains(src, want) {
			t.Errorf("app.js lacks %s", want)
		}
	}
	css, err := staticFS.ReadFile("static/style.css")
	if err != nil {
		t.Fatal(err)
	}
	style := string(css)
	dark := style[strings.Index(style, "@media (prefers-color-scheme: dark)"):]
	for _, token := range []string{"--map-1:", "--map-2:", "--map-3:", "--map-4:", "--map-5:", "--map-none:"} {
		if strings.Count(style, token) != 2 || !strings.Contains(dark, token) {
			t.Errorf("style.css does not define %s for both themes", token)
		}
	}
	index, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	nav := string(index)
	if s, n, e := strings.Index(nav, `data-route="syslog"`), strings.Index(nav, `data-route="network"`), strings.Index(nav, `data-route="evidence"`); !(s >= 0 && s < n && n < e) {
		t.Error("index.html: the Network item is not between Syslog and Evidence")
	}
}

// TestAppJSNetworkNames runs the flow diagram's model from app.js under Node.js: an organisation
// with several ASes is one node whose tooltip lists them all, and a port the port table does not
// name is named by its port alone ("8071/tcp"), without a note repeating it - as the firewall's
// bars and tile name it (unnamedPort).
func TestAppJSNetworkNames(t *testing.T) {
	prog := jsProgram(t, nil, []string{"netList", "portText", "unnamedPort", "sankeyModel"})
	prog += `
const deviceSlot = () => 1;
const fmtInt = (n) => String(n);
const countryName = (c) => (c === 'US' ? 'United States' : c);
const m = sankeyModel({
  devices: [{ key: 'd1', name: 'PC', ipv4: '192.168.1.10' }],
  orgs: [{ key: 'org:google', name: 'Google', asn: 15169, asns: [15169, 36040], country: 'US', weight: 4 },
    { key: 'as64500', name: 'Example', asn: 64500, country: 'US', weight: 1 }],
  services: [{ key: 'tcp/8071', name: 'tcp 8071', proto: 'tcp', port: 8071, weight: 3 },
    { key: 'tcp/443', name: 'HTTPS', proto: 'tcp', port: 443, weight: 2 }],
  links: [{ from: 'd1', to: 'org:google', weight: 4 }, { from: 'd1', to: 'as64500', weight: 1 },
    { from: 'org:google', to: 'tcp/8071', weight: 3 }, { from: 'org:google', to: 'tcp/443', weight: 1 }, { from: 'as64500', to: 'tcp/443', weight: 1 }],
});
console.log(JSON.stringify({
  orgs: m.cols[1].map((n) => [n.name, n.sub]),
  svcs: m.cols[2].map((n) => [n.name, n.sub]),
  unnamed: [unnamedPort({ name: 'tcp 8071', proto: 'tcp', port: 8071 }), unnamedPort({ name: 'port 8071', port: 8071 }),
    unnamedPort({ name: 'SSH', proto: 'tcp', port: 22 }), unnamedPort({ name: 'ICMP', proto: 'icmp', port: 0 }),
    unnamedPort({ name: 'tcp 8072', proto: 'tcp', port: 8071 })],
}));
`
	var got struct {
		Orgs    [][2]string `json:"orgs"`
		Svcs    [][2]string `json:"svcs"`
		Unnamed []bool      `json:"unnamed"`
	}
	if err := json.Unmarshal(runNode(t, prog), &got); err != nil {
		t.Fatal(err)
	}
	if want := [][2]string{{"Google", "AS15169, AS36040, United States"}, {"Example", "AS64500, United States"}}; !slices.Equal(got.Orgs, want) {
		t.Errorf("organisations %q, want %q", got.Orgs, want)
	}
	if want := [][2]string{{"8071/tcp", ""}, {"HTTPS", "443/tcp"}}; !slices.Equal(got.Svcs, want) {
		t.Errorf("services %q, want %q", got.Svcs, want)
	}
	if want := []bool{true, true, false, false, false}; !slices.Equal(got.Unnamed, want) {
		t.Errorf("unnamedPort %v, want %v", got.Unnamed, want)
	}
}
