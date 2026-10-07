package web

// The dashboard for rules 2026.10-4 (docs/DESIGN.md §9-§10) and the contract changes that came
// with them:
//
//   - LOCAL_ROUTE: the gateway answered but this computer's traffic left through another adapter
//     (VPN, second network, hotspot); the local-link reading carries the route check (egress)
//     and the monitor reports EGRESS_NOT_VIA_GATEWAY. Nothing is attributed to AT&T.
//   - A status the monitor reports as UNKNOWN because no cycle is being recorded (empty since,
//     an old last sample) must say so, never show the last recorded state as the present one.
//   - A DNS query without a valid answer is retried once within its check: a resolver is
//     judged by both results, and the retry is shown.
//   - Verdicts also name the previous service check (two-consecutive-checks DNS rule) and the
//     two gateway snapshots of the household's WAN traffic.
//   - Conditions LEDGER_WRITE_FAILING, DISK_SPACE_LOW and CLOCK_OFFSET; monitor_start gap_seconds
//     may be negative; verification problem ts_contradiction.

import (
	"encoding/json"
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

// jsConst returns the declaration "const name = ...;" from src, matching brackets outside of
// string literals and comments.
func jsConst(t *testing.T, src, name string) string {
	t.Helper()
	start := strings.Index(src, "const "+name+" = ")
	if start < 0 {
		t.Fatalf("app.js has no const %s", name)
	}
	depth := 0
	var quote byte
	for i := start; i < len(src); i++ {
		c := src[i]
		if quote != 0 {
			switch c {
			case '\\':
				i++
			case quote:
				quote = 0
			}
			continue
		}
		switch {
		case strings.HasPrefix(src[i:], "//"):
			if n := strings.IndexByte(src[i:], '\n'); n >= 0 {
				i += n
			}
			continue
		case strings.HasPrefix(src[i:], "/*"):
			if n := strings.Index(src[i:], "*/"); n >= 0 {
				i += n + 1
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			quote = c
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ';':
			if depth == 0 {
				return src[start : i+1]
			}
		}
	}
	t.Fatalf("const %s has no end", name)
	return ""
}

// jsProgram concatenates the named declarations of app.js (constants first, then functions);
// app.js resolves names when a function runs, so only what the exercised paths call is needed.
func jsProgram(t *testing.T, consts, funcs []string) string {
	t.Helper()
	src := appJS(t)
	var b strings.Builder
	dict, _, _ := functionSource(t, src, "dict")
	b.WriteString(dict + "\n")
	for _, c := range consts {
		b.WriteString(jsConst(t, src, c) + "\n")
	}
	for _, f := range funcs {
		body, _, _ := functionSource(t, src, f)
		b.WriteString(body + "\n")
	}
	return b.String()
}

// runNode runs a Node.js program and returns what it printed.
func runNode(t *testing.T, prog string) []byte {
	t.Helper()
	node := requireNode(t)
	p := filepath.Join(t.TempDir(), "prog.js")
	if err := os.WriteFile(p, []byte(prog), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, p).CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s\n--- program ---\n%s", err, out, prog)
	}
	return out
}

// ----------------------------------------------------------------------------- static

// TestAppJSKnowsEveryCauseConditionAndProblem: every cause of the model has dashboard words,
// every condition the monitor reports besides the gateway's own flags has a title (and the new
// ones an explanation), and every verification problem is worded.
func TestAppJSKnowsEveryCauseConditionAndProblem(t *testing.T) {
	src := appJS(t)
	causes := jsConst(t, src, "CAUSES")
	for _, c := range []string{model.CauseGatewayUnreachable, model.CauseLocalLinkDown, model.CauseGatewayReboot,
		model.CauseFiberLinkDown, model.CauseWANDown, model.CauseISPEdgeUnreachable, model.CauseUpstreamUnreachable,
		model.CausePacketLoss, model.CauseHighLatency, model.CauseISPDNSFailure, model.CauseGatewayDNSFailure, model.CauseLocalRoute} {
		if !regexp.MustCompile(`(?m)^\s*` + c + `: \{`).MatchString(causes) {
			t.Errorf("CAUSES has no words for cause %s", c)
		}
	}
	titles := jsConst(t, src, "COND_TITLES")
	for _, code := range []string{"NOTIFICATION_REDIRECT_ON", "GATEWAY_CERT_CHANGED", "NO_ACCESS_CODE", "ANCHOR_UNTRUSTED",
		"EGRESS_NOT_VIA_GATEWAY", "LEDGER_WRITE_FAILING", "DISK_SPACE_LOW", "CLOCK_OFFSET",
		"SYSLOG_RECEIVER_DOWN", "SYSLOG_STORE_FAILING", "SYSLOG_SETTING_FAILED", "SYSLOG_NOT_ARRIVING"} {
		if !strings.Contains(titles, "    "+code+": '") {
			t.Errorf("COND_TITLES has no title for %s", code)
		}
	}
	banner, _, _ := functionSource(t, src, "conditionBanner")
	for _, code := range []string{"EGRESS_NOT_VIA_GATEWAY", "LEDGER_WRITE_FAILING", "DISK_SPACE_LOW", "CLOCK_OFFSET", "SYSLOG_SETTING_FAILED"} {
		if !strings.Contains(banner, "cnd.code === '"+code+"'") {
			t.Errorf("conditionBanner does not explain %s", code)
		}
	}
	problems := jsConst(t, src, "VERIFY_PROBLEMS")
	for _, p := range []string{"hash_mismatch", "bad_signature", "seq_gap", "prev_mismatch", "segment_hash", "blob_missing",
		"blob_corrupt", "anchor_invalid", "parse_error", "ts_contradiction"} {
		if !strings.Contains(problems, "    "+p+": '") {
			t.Errorf("VERIFY_PROBLEMS has no words for %s", p)
		}
	}
}

// ----------------------------------------------------------------------------- unit (Node.js)

const localRouteHeadline = "This computer’s traffic does not go through the AT&T gateway (VPN or another network); nothing is attributed to AT&T"

// TestAppJSStatusHeadlines runs headline, statusStale and statusHeadline from app.js. An
// UNKNOWN status is never worded as a state: before the first cycle the dashboard waits; when
// no cycle is being recorded (the monitor's UNKNOWN verdict with its reason and no "since") it
// says that monitoring is not producing samples, whatever the last sample said; a cycle that
// could not be judged is unknown.
func TestAppJSStatusHeadlines(t *testing.T) {
	prog := jsProgram(t, []string{"STATES", "CAUSES"}, []string{"humanize", "stateInfo", "headline", "statusStale", "statusHeadline"})
	stale := []string{"no monitoring cycle has been recorded for 5m0s (the last one, at 2026-10-05 03:15:00 UTC, was ONLINE), so the current state is unknown"}
	interrupted := []string{"this cycle took 1m31s, longer than the 4s its probes may take: monitoring was interrupted while they were in flight (for example by system sleep), so their results say nothing about the network"}
	type st = map[string]any
	verdict := func(state, cause string, reasons []string) st {
		return st{"state": state, "cause": cause, "attribution": "undetermined", "reasons": reasons}
	}
	sample := func(v st) st { return st{"started": "2026-10-05T03:15:00Z", "verdict": v} }
	cases := []struct {
		what   string
		status st
		want   string
		stale  bool
	}{
		{"startup", st{"verdict": verdict("UNKNOWN", "", []string{"no monitoring cycle has completed yet"}), "since": ""},
			"Waiting for the first measurements", false},
		{"no verdict at all", st{}, "Waiting for the first measurements", false},
		{"no cycle recorded, the last one was online", st{"verdict": verdict("UNKNOWN", "", stale), "since": "",
			"last_sample": sample(verdict("ONLINE", "", []string{"5/5 internet probes succeeded"}))},
			"Monitoring is not producing samples — see the reason", true},
		{"no cycle recorded, the last one could not be judged", st{"verdict": verdict("UNKNOWN", "", stale), "since": "",
			"last_sample": sample(verdict("UNKNOWN", "", interrupted))},
			"Monitoring is not producing samples — see the reason", true},
		{"the first cycle could not be judged", st{"verdict": verdict("UNKNOWN", "", interrupted), "since": "",
			"last_sample": sample(verdict("UNKNOWN", "", interrupted))},
			"Unknown — this measurement could not be judged (see the reason)", false},
		{"a cycle could not be judged", st{"verdict": verdict("UNKNOWN", "", interrupted), "since": "2026-10-04T20:00:00Z",
			"last_sample": sample(verdict("UNKNOWN", "", interrupted))},
			"Unknown — this measurement could not be judged (see the reason)", false},
		{"traffic past the gateway", st{"verdict": verdict("LOCAL_FAULT", "LOCAL_ROUTE", nil), "since": "2026-10-05T03:00:00Z",
			"last_sample": sample(verdict("LOCAL_FAULT", "LOCAL_ROUTE", nil))}, localRouteHeadline, false},
		{"gateway restart", st{"verdict": verdict("LOCAL_FAULT", "GATEWAY_REBOOT", nil), "since": "2026-10-05T03:00:00Z",
			"last_sample": sample(verdict("LOCAL_FAULT", "GATEWAY_REBOOT", nil))}, "AT&T gateway restarted (detected from the gateway’s own uptime)", false},
		{"online", st{"verdict": verdict("ONLINE", "", nil), "since": "2026-10-05T03:00:00Z", "last_sample": sample(verdict("ONLINE", "", nil))}, "Online", false},
		{"AT&T outage", st{"verdict": verdict("ISP_OUTAGE", "FIBER_LINK_DOWN", nil), "since": "2026-10-05T03:00:00Z",
			"last_sample": sample(verdict("ISP_OUTAGE", "FIBER_LINK_DOWN", nil))}, "AT&T outage — fiber link down (reported by the AT&T gateway)", false},
	}
	in := make([]st, len(cases))
	for i, c := range cases {
		in[i] = c.status
	}
	inJSON, _ := json.Marshal(in)
	prog += "console.log(JSON.stringify(" + string(inJSON) + ".map((s) => [statusHeadline(s), statusStale(s)])));\n" +
		"console.log(JSON.stringify([headline({ state: 'LOCAL_FAULT', cause: 'LOCAL_ROUTE' }), headline({ state: 'UNKNOWN' })]));\n"
	lines := strings.Split(strings.TrimSpace(string(runNode(t, prog))), "\n")
	var got [][]any
	var direct []string
	if len(lines) != 2 || json.Unmarshal([]byte(lines[0]), &got) != nil || json.Unmarshal([]byte(lines[1]), &direct) != nil || len(got) != len(cases) {
		t.Fatalf("unexpected output %q", lines)
	}
	for i, c := range cases {
		if got[i][0] != c.want || got[i][1] != c.stale {
			t.Errorf("%s: headline %q, stale %v; want %q, %v", c.what, got[i][0], got[i][1], c.want, c.stale)
		}
		if v, _ := c.status["verdict"].(st); v != nil && v["state"] == "UNKNOWN" && strings.Contains(got[i][0].(string), "Online") {
			t.Errorf("%s: an UNKNOWN status is worded %q", c.what, got[i][0])
		}
	}
	if direct[0] != localRouteHeadline || !strings.HasPrefix(direct[1], "Unknown") {
		t.Errorf("headline: %q", direct)
	}
}

// dnsRes builds a DNS result as the probe records it.
func dnsRes(server, role, name string, extra map[string]any) map[string]any {
	r := map[string]any{"server": server, "server_role": role, "name": name, "qtype": "A", "hijacked": false}
	for k, v := range extra {
		r[k] = v
	}
	return r
}

// TestAppJSDNSQueries runs dnsQueries and dnsQueryVerdict from app.js. The monitor retries a
// query that got no valid answer once within its check and records the retry right after it
// (rules 2026.10-4): the pair is one query, judged by both results — passed if either
// passed, a hijack whichever carries it — and the retry is named.
func TestAppJSDNSQueries(t *testing.T) {
	prog := jsProgram(t, nil, []string{"isHijackTestName", "rcodeOK", "dnsVerdict", "dnsRetryable", "dnsQueries", "dnsQueryVerdict"})
	const gw, isp, pub = "192.168.1.254:53", "68.94.156.9:53", "1.1.1.1:53"
	const name, inv = "www.google.com", "bd5d25b1a90fdbe6.invalid"
	ok := func(server, role string, rtt int) map[string]any {
		return dnsRes(server, role, name, map[string]any{"ok": true, "rcode": "NOERROR", "answers": []string{"142.250.72.100"}, "rtt_us": rtt})
	}
	lost := func(server, role string) map[string]any {
		return dnsRes(server, role, name, map[string]any{"ok": false, "err": "read udp 192.168.1.71:53124->" + server + ": i/o timeout"})
	}
	servfail := dnsRes(gw, "gateway", name, map[string]any{"ok": true, "rcode": "SERVFAIL"})
	test := dnsRes(gw, "gateway", inv, map[string]any{"ok": true, "rcode": "NXDOMAIN"})
	hijacked := dnsRes(isp, "isp", name, map[string]any{"ok": true, "rcode": "NOERROR", "answers": []string{"192.168.1.254"}, "hijacked": true,
		"hijack_why": "answer 192.168.1.254 for www.google.com is the gateway's own address"})

	type want struct {
		size         int    // results in the query
		tone, label  string // the query's verdict
		retry, text  string // the retry note and the timeline wording ("" = no retry)
		rtt          int    // round trip of the result shown (0: none)
		resultIsLast bool   // the result shown is the retry
	}
	cases := []struct {
		what  string
		check []any
		want  []want
	}{
		{"healthy check", []any{ok(gw, "gateway", 2100), ok(isp, "isp", 11800), ok(pub, "public", 10900), test},
			[]want{{1, "good", "answered", "", "answered", 2100, false}, {1, "good", "answered", "", "answered", 11800, false},
				{1, "good", "answered", "", "answered", 10900, false}, {1, "good", "not hijacked", "", "not hijacked (NXDOMAIN, the correct answer)", 0, false}}},
		{"one lost datagram", []any{ok(gw, "gateway", 2100), lost(isp, "isp"), ok(isp, "isp", 11800), ok(pub, "public", 10900), test},
			[]want{{1, "good", "answered", "", "answered", 2100, false},
				{2, "good", "answered", "first query: no answer · retry: answered", "answered on the retry (first query: no answer)", 11800, true},
				{1, "good", "answered", "", "answered", 10900, false}, {1, "good", "not hijacked", "", "not hijacked (NXDOMAIN, the correct answer)", 0, false}}},
		{"query and retry lost", []any{lost(isp, "isp"), lost(isp, "isp"), ok(pub, "public", 10900)},
			[]want{{2, "critical", "no answer", "first query: no answer · retry: no answer", "no answer; retried: no answer", 0, true},
				{1, "good", "answered", "", "answered", 10900, false}}},
		{"SERVFAIL twice", []any{servfail, servfail, test},
			[]want{{2, "critical", "SERVFAIL", "first query: SERVFAIL · retry: SERVFAIL", "answered SERVFAIL; retried: answered SERVFAIL", 0, true},
				{1, "good", "not hijacked", "", "not hijacked (NXDOMAIN, the correct answer)", 0, false}}},
		{"SERVFAIL, then answered", []any{servfail, ok(gw, "gateway", 2300)},
			[]want{{2, "good", "answered", "first query: SERVFAIL · retry: answered", "answered on the retry (first query: answered SERVFAIL)", 2300, true}}},
		{"hijacked on the retry", []any{lost(isp, "isp"), hijacked},
			[]want{{2, "critical", "HIJACKED", "first query: no answer · retry: HIJACKED",
				"HIJACKED (answer 192.168.1.254 for www.google.com is the gateway's own address) on the retry (first query: no answer)", 0, true}}},
		// Not retries: a definite answer is never asked again, another resolver or name is
		// another query, and a query is retried at most once.
		{"the same resolver configured twice", []any{ok(pub, "public", 10900), ok(pub, "public", 11000)},
			[]want{{1, "good", "answered", "", "answered", 10900, false}, {1, "good", "answered", "", "answered", 11000, false}}},
		{"two resolvers lost", []any{lost(isp, "isp"), lost(pub, "public")},
			[]want{{1, "critical", "no answer", "", "no answer", 0, false}, {1, "critical", "no answer", "", "no answer", 0, false}}},
		{"the hijack test after a lost gateway query", []any{lost(gw, "gateway"), test},
			[]want{{1, "critical", "no answer", "", "no answer", 0, false}, {1, "good", "not hijacked", "", "not hijacked (NXDOMAIN, the correct answer)", 0, false}}},
		{"three lost results", []any{lost(isp, "isp"), lost(isp, "isp"), lost(isp, "isp")},
			[]want{{2, "critical", "no answer", "first query: no answer · retry: no answer", "no answer; retried: no answer", 0, true},
				{1, "critical", "no answer", "", "no answer", 0, false}}},
		{"damaged entries", []any{nil, "x", ok(gw, "gateway", 2100)}, []want{{1, "good", "answered", "", "answered", 2100, false}}},
	}
	in := make([][]any, len(cases))
	for i, c := range cases {
		in[i] = c.check
	}
	inJSON, _ := json.Marshal(in)
	prog += "console.log(JSON.stringify(" + string(inJSON) + ".map((check) => dnsQueries(check).map((q) => {\n" +
		"  const v = dnsQueryVerdict(q);\n" +
		"  return { size: q.length, tone: v.tone, label: v.label, retry: v.retry, text: v.text, rtt: v.r.rtt_us || 0, last: v.r === q[q.length - 1] && q.length > 1 };\n" +
		"}))));\n"
	var got [][]struct {
		Size  int     `json:"size"`
		Tone  string  `json:"tone"`
		Label string  `json:"label"`
		Retry *string `json:"retry"`
		Text  string  `json:"text"`
		RTT   int     `json:"rtt"`
		Last  bool    `json:"last"`
	}
	out := runNode(t, prog)
	if err := json.Unmarshal(out, &got); err != nil || len(got) != len(cases) {
		t.Fatalf("unexpected output %s (%v)", out, err)
	}
	for i, c := range cases {
		if len(got[i]) != len(c.want) {
			t.Errorf("%s: %d queries, want %d: %+v", c.what, len(got[i]), len(c.want), got[i])
			continue
		}
		for j, w := range c.want {
			g := got[i][j]
			retry := ""
			if g.Retry != nil {
				retry = *g.Retry
			}
			if g.Size != w.size || g.Tone != w.tone || g.Label != w.label || retry != w.retry || g.Text != w.text || g.RTT != w.rtt || g.Last != w.resultIsLast {
				t.Errorf("%s, query %d:\n got %+v (retry %q)\nwant %+v", c.what, j, g, retry, w)
			}
		}
	}
}

// TestAppJSRecordDescriptions runs describeRecordData from app.js on the record shapes that
// changed: a monitor_start whose gap is negative (this computer's clock was behind the previous
// record), local_link records with their route check, and a service check with a retry.
func TestAppJSRecordDescriptions(t *testing.T) {
	prog := jsProgram(t, []string{"DNS_ROLES", "HTTP_CHECK_NAMES"}, []string{"describeRecordData", "fmtDur", "orQ", "humanize", "configSummary",
		"isHijackTestName", "rcodeOK", "dnsVerdict", "dnsRetryable", "dnsQueries", "dnsQueryVerdict", "dnsCheckName", "shortHash",
		"ifText", "egressRoutes", "egressSummary"})
	link := func(egress any) map[string]any {
		d := map[string]any{"interface": "Wi-Fi", "type": "wifi", "state": "connected", "ssid": "HOME-5G"}
		if egress != nil {
			d["egress"] = egress
		}
		return map[string]any{"type": "local_link", "body": map[string]any{"data": d}}
	}
	route := func(target string, via bool, ifName string, ifIndex int, hop string) map[string]any {
		return map[string]any{"target": target, "via_gateway": via, "if_name": ifName, "if": ifIndex, "next_hop": hop}
	}
	recs := []any{
		map[string]any{"type": "monitor_start", "body": map[string]any{"data": map[string]any{"mode": "service", "gap_seconds": -42}}},
		map[string]any{"type": "monitor_start", "body": map[string]any{"data": map[string]any{"mode": "service", "gap_seconds": 95}}},
		map[string]any{"type": "monitor_start", "body": map[string]any{"data": map[string]any{"mode": "service", "gap_seconds": 0}}},
		link(map[string]any{"gateway": "192.168.1.254", "gateway_if": 12, "gateway_if_name": "Wi-Fi", "bypass": true, "routes": []any{
			route("1.1.1.1", false, "NordLynx", 23, "10.5.0.1"), route("203.0.113.1", true, "Wi-Fi", 12, "192.168.1.254")}}),
		link(map[string]any{"gateway": "192.168.1.254", "gateway_if": 12, "gateway_if_name": "Wi-Fi", "bypass": false, "routes": []any{
			route("1.1.1.1", true, "Wi-Fi", 12, "192.168.1.254"), route("8.8.8.8", true, "Wi-Fi", 12, "192.168.1.254")}}),
		link(map[string]any{"gateway": "192.168.1.254", "bypass": false, "err": "route to the gateway: element not found"}),
		link(nil),
		map[string]any{"type": "service_check", "body": map[string]any{"data": map[string]any{"dns": []any{
			dnsRes("68.94.156.9:53", "isp", "www.google.com", map[string]any{"ok": false, "err": "read udp: i/o timeout"}),
			dnsRes("68.94.156.9:53", "isp", "www.google.com", map[string]any{"ok": true, "rcode": "NOERROR", "answers": []string{"142.250.72.100"}}),
		}, "http": []any{}}}},
	}
	inJSON, _ := json.Marshal(recs)
	prog += "console.log(JSON.stringify(" + string(inJSON) + ".map((r) => describeRecordData(r))));\n"
	var got []struct {
		Tone   string `json:"tone"`
		Title  string `json:"title"`
		Detail string `json:"detail"`
	}
	out := runNode(t, prog)
	if err := json.Unmarshal(out, &got); err != nil || len(got) != len(recs) {
		t.Fatalf("unexpected output %s (%v)", out, err)
	}
	checks := []struct {
		what, title, detailHas, detailLacks, tone string
	}{
		{"negative gap", "Monitor started (service)", "This computer’s clock was 42 s behind the previous record’s time", "Gap since", "info"},
		{"gap", "Monitor started (service)", "Gap since the previous record: 1 min 35 s", "behind", "info"},
		{"no gap", "Monitor started (service)", "", "Gap since", "info"},
		{"route past the gateway", "This PC’s link: connected — traffic not through the AT&T gateway",
			"route check: 1.1.1.1 leaves through NordLynx (interface 23) via 10.5.0.1, not through the AT&T gateway", "", "warning"},
		{"routes through the gateway", "This PC’s link: connected", "route check: all 2 destinations through the AT&T gateway", "not through", "info"},
		{"route check failed", "This PC’s link: connected", "route check could not be made: route to the gateway: element not found", "", "info"},
		{"no route check (older record)", "This PC’s link: connected", "", "route check", "info"},
		{"service check with a retry", "DNS and web checks", "AT&T DNS: answered on the retry (first query: no answer) 142.250.72.100", "", "info"},
	}
	for i, c := range checks {
		g := got[i]
		if g.Title != c.title || g.Tone != c.tone || (c.detailHas != "" && !strings.Contains(g.Detail, c.detailHas)) ||
			(c.detailLacks != "" && strings.Contains(g.Detail, c.detailLacks)) {
			t.Errorf("%s: %+v", c.what, g)
		}
	}
}

// TestAppJSStripListsUnknownBuckets runs stateRuns and stripOrder from app.js: a bucket whose
// every cycle could not be judged is UNKNOWN (rules 2026.10-4 interrupted cycles); the
// availability legend and shares then list it, before "no data", so that the shares add up.
func TestAppJSStripListsUnknownBuckets(t *testing.T) {
	prog := jsProgram(t, []string{"STATE_ORDER"}, []string{"toDate", "toMs", "stateRuns", "stripOrder"})
	prog += `const from = Date.parse('2026-10-05T03:00:00Z');
const pts = (states) => states.map((s, i) => ({ t: new Date(from + i * 60000).toISOString(), state: s }));
const to = from + 5 * 60000;
console.log(JSON.stringify([
  stripOrder(stateRuns(pts(['ONLINE', 'UNKNOWN', 'ONLINE', 'DEGRADED', 'ONLINE']), from, to, 60000)),
  stripOrder(stateRuns(pts(['ONLINE', 'ONLINE', 'ISP_OUTAGE', 'ONLINE', 'ONLINE']), from, to, 60000)),
  stateRuns(pts(['ONLINE', 'UNKNOWN', 'ONLINE']), from, from + 3 * 60000, 60000).map((r) => r.state),
]));
`
	var got [][]string
	out := runNode(t, prog)
	if err := json.Unmarshal(out, &got); err != nil || len(got) != 3 {
		t.Fatalf("unexpected output %s (%v)", out, err)
	}
	if want := []string{"ONLINE", "DEGRADED", "LOCAL_FAULT", "ISP_OUTAGE", "UNKNOWN", ""}; !slices.Equal(got[0], want) {
		t.Errorf("legend with an UNKNOWN bucket: %q, want %q", got[0], want)
	}
	if want := []string{"ONLINE", "DEGRADED", "LOCAL_FAULT", "ISP_OUTAGE", ""}; !slices.Equal(got[1], want) {
		t.Errorf("legend without UNKNOWN buckets: %q, want %q", got[1], want)
	}
	if want := []string{"ONLINE", "UNKNOWN", "ONLINE"}; !slices.Equal(got[2], want) {
		t.Errorf("runs: %q, want %q", got[2], want)
	}
}

// ----------------------------------------------------------------------------- the real script

// TestDashboardShowsLocalRoute renders a live VPN period: the gateway answers, the internet
// probes fail, and the route check shows the internet destinations leaving through the VPN
// adapter. The dashboard must say that nothing is attributed to AT&T, show the routes with the
// interface and next hop of each, warn about the bypass, and word the history the same way.
func TestDashboardShowsLocalRoute(t *testing.T) {
	requireNode(t)
	w := newDemoWorld(time.Now())
	w.setLive(liveVPN)
	w.mu.Lock()
	w.extraConds = []model.Condition{demoClockCondition(time.Now())}
	w.mu.Unlock()
	rep := runDashboard(t, w, "plain")
	contains := viewChecker(t, rep)
	ov := rep.Views["overview"]

	// The status card says what was observed and attributes nothing; its details give the
	// classifier's reasons.
	for _, want := range []string{"Not through the AT&T gateway", localRouteHeadline, "Attribution undetermined", "Incident in progress"} {
		if !strings.Contains(ov.Hero, want) {
			t.Errorf("status card does not show %q:\n%s", want, ov.Hero)
		}
	}
	if strings.Contains(ov.Hero, "AT&T outage") || strings.Contains(ov.Hero, "Attributed to AT&T") || strings.Contains(ov.Hero, "Local fault") {
		t.Errorf("status card blames AT&T, or this PC:\n%s", ov.Hero)
	}
	contains("overview status", localRouteHeadline, "Attribution undetermined", `leaves through "NordLynx" (interface 23) via 10.5.0.1`,
		"their failure says nothing about AT&T's network", "Incident in progress")
	// The This PC's link card says that the route bypasses the gateway; its details show the
	// route check with every destination, and the warning.
	if c := ov.card(t, "link"); !strings.Contains(c.Text, "Route to the Internet: through another adapter (a VPN or another network)") {
		t.Errorf("the This PC's link card: %+v", c)
	}
	ov = rep.Views["overview link"]
	contains("overview link", "Route to the Internet", "Not through the AT&T gateway. The route to 3 of 5 destinations leaves through another adapter",
		"nothing measured on the Internet is attributed to AT&T", "This computer reaches the AT&T gateway 192.168.1.254 through Wi-Fi (on-link).")
	for _, r := range []struct{ dest, chip, via string }{
		{"1.1.1.1", "warning:no", "NordLynx via 10.5.0.1"},
		{"8.8.8.8", "warning:no", "NordLynx via 10.5.0.1"},
		{"9.9.9.9", "warning:no", "NordLynx via 10.5.0.1"},
		{demoNextHop, "good:yes", "Wi-Fi via 192.168.1.254"},
		{demoISPDNS, "good:yes", "Wi-Fi via 192.168.1.254"},
	} {
		rows := rowsWith(ov, regexp.MustCompile(`^`+regexp.QuoteMeta(r.dest)+`(yes|no)`))
		if len(rows) != 1 || !slices.Equal(rows[0].Chips, []string{r.chip}) || !strings.HasSuffix(rows[0].Text, r.via) {
			t.Errorf("route to %s: rows %+v, want one with %s leaving through %s", r.dest, rows, r.chip, r.via)
		}
	}
	// The conditions, with what they mean and what to do.
	contains("overview", "Traffic does not go through the AT&T gateway (VPN or another network)",
		"This computer's internet traffic does not go through the AT&T gateway: "+demoBypassText,
		"Disconnect the VPN or the other network to resume attribution",
		"This computer’s clock is off", "off by about 94 s compared with internet time servers", "w32tm /resync")
	if !strings.Contains(ov.Pill, "Local fault") || strings.Contains(ov.Pill, "Online") {
		t.Errorf("status pill: %q", ov.Pill)
	}
	// The clock is off: the Monitor & clock card says so.
	if c := rep.Views["overview"].card(t, "monitor"); c.Chip != "warning:Clock off" {
		t.Errorf("the Monitor & clock card with the clock off: %+v", c)
	}

	// The history: the incident list names the cause, the incident detail words it, and its
	// timeline shows the route check of the local-link reading.
	contains("incidents", "this computer’s traffic does not go through the AT&T gateway (VPN or another network)")
	contains("incident "+model.CauseLocalRoute, localRouteHeadline, "Attribution undetermined", "not observed",
		"This PC’s link: connected — traffic not through the AT&T gateway",
		"route check: 1.1.1.1 leaves through NordLynx (interface 23) via 10.5.0.1, 8.8.8.8 leaves through NordLynx (interface 23) via 10.5.0.1, 9.9.9.9 leaves through NordLynx (interface 23) via 10.5.0.1, not through the AT&T gateway")
	// Before the VPN the local-link readings show every route through the gateway; the reading
	// taken with it is marked in the records list.
	contains("records", "route check: all 5 destinations through the AT&T gateway", "local_link connected · traffic not through the AT&T gateway")
}

// TestDashboardShowsStaleStatus renders a monitor that records no cycle (its ledger refuses
// records on a full disk): the status is UNKNOWN with the monitor's reason and no "since",
// and the last sample is minutes old. Nothing may present that last sample as the present.
func TestDashboardShowsStaleStatus(t *testing.T) {
	requireNode(t)
	w := newDemoWorld(time.Now())
	w.mu.Lock()
	w.stale = true
	w.mu.Unlock()
	rep := runDashboard(t, w, "plain")
	contains := viewChecker(t, rep)
	ov := rep.Views["overview"]

	// The status card says it in a word or two, and gives the reasons the line of the last
	// measurement does not (the first one says what that line says); its details give them all.
	for _, want := range []string{"Internet status nowNot measuringThe last measurement recorded was taken", "not the current state.",
		"The evidence ledger is refusing records (see the LEDGER_WRITE_FAILING condition)."} {
		if !strings.Contains(ov.Hero, want) {
			t.Errorf("status card does not show %q:\n%s", want, ov.Hero)
		}
	}
	if strings.Contains(ov.Hero, "see the reason") || strings.Contains(ov.Hero, "No monitoring cycle has been recorded") {
		t.Errorf("status card points to a reason elsewhere, or says the line of the last measurement twice:\n%s", ov.Hero)
	}
	status := rep.Views["overview status"]
	for _, want := range []string{"Monitoring is not producing samples — see the reason",
		"the evidence ledger is refusing records (see the LEDGER_WRITE_FAILING condition)",
		"The last measurement recorded was taken", "not the current state"} {
		if status.Detail == nil || !strings.Contains(status.Detail.Text, want) {
			t.Errorf("the status details do not show %q", want)
		}
	}
	if status.Detail == nil || !regexp.MustCompile(`no monitoring cycle has been recorded for 7m\d+s \(the last one, at .* UTC, was ONLINE\), so the current state is unknown`).MatchString(status.Detail.Text) {
		t.Errorf("the status details do not give the monitor's reason: %+v", status.Detail)
	}
	for _, bad := range []string{"Online", "In this state since", "Attribut", "internet probes answered"} {
		if strings.Contains(ov.Hero, bad) {
			t.Errorf("status card shows %q although nothing is being measured:\n%s", bad, ov.Hero)
		}
	}
	// The cards say that the last measurement is not current, and why.
	for key, chip := range map[string]string{"internet": "none:Not current", "monitor": "warning:Not measuring", "evidence": "critical:Not recording"} {
		if c := ov.card(t, key); c.Chip != chip {
			t.Errorf("the %s card while nothing is measured: %+v, want the chip %s", key, c, chip)
		}
	}
	if !strings.Contains(ov.Pill, "Unknown") || !strings.Contains(ov.Pill, "not measuring") || strings.Contains(ov.Pill, "Online") {
		t.Errorf("status pill: %q", ov.Pill)
	}
	if ov.Title != "Unknown · AT&T Internet Monitor" {
		t.Errorf("window title: %q", ov.Title)
	}
	// The Internet details show the last measurement as what it is.
	contains("overview internet", "Not current. This is the last measurement recorded, 7 min", "ago: the monitor is not producing samples",
		"Last recorded: 5 of 5 internet probes answered")
	// The conditions, on the overview and on the Evidence page.
	for _, view := range []string{"overview", "evidence"} {
		contains(view, "Evidence is not being recorded — the ledger refuses new records", "There is not enough space on the disk",
			"Nothing that happens now becomes evidence", "Low disk space on the evidence volume", "has only 3 MB free of 237.1 GB")
	}
}

// TestDashboardShowsDNSRetriesAndVerdictInputs renders the AT&T resolver's lost queries: a
// query whose retry answered is a resolver that answered (with the retry shown), a query whose
// retry failed too is a failure, and the AT&T DNS incident's verdicts link the previous service
// check that the two-consecutive-checks rule compared with and the two gateway snapshots of the
// household's WAN traffic.
func TestDashboardShowsDNSRetriesAndVerdictInputs(t *testing.T) {
	requireNode(t)
	w := newDemoWorld(time.Now())
	w.mu.Lock()
	w.liveDNSRetry = "answered"
	w.mu.Unlock()
	rep := runDashboard(t, w, "plain")
	contains := viewChecker(t, rep)
	ov := rep.Views["overview internet"]

	rows := rowsWith(ov, regexp.MustCompile(`^AT&T DNS`))
	if len(rows) != 1 || !slices.Equal(rows[0].Chips, []string{"good:answered"}) ||
		!strings.Contains(rows[0].Text, "first query: no answer · retry: answered") || !strings.HasSuffix(rows[0].Text, "11.8 ms") {
		t.Errorf("AT&T DNS rows: %+v", rows)
	}
	// The ledger: the check with one lost datagram, as the records browser words it.
	contains("records", "AT&T DNS: answered on the retry (first query: no answer) 142.250.72.100")

	// The AT&T DNS incident: its first cycle's verdict, the records it names, and the checks.
	var inc model.Incident
	for _, i := range w.Incidents(time.Unix(0, 0), time.Now().Add(time.Hour)) {
		if i.Cause == model.CauseISPDNSFailure {
			inc = i
		}
	}
	_, body, err := w.Record(inc.FirstSeq)
	var smp model.Sample
	if err != nil || json.Unmarshal(body.Data, &smp) != nil || smp.Verdict.Inputs == nil {
		t.Fatalf("first record of the AT&T DNS incident: %v %+v", err, body)
	}
	in := smp.Verdict.Inputs
	seq := func(n uint64) string { return "#" + strconv.FormatUint(n, 10) }
	// The demo records a local-link reading every 10 minutes; depending on the minute of the
	// hour none is fresh for this cycle, and the verdict names none.
	link := "local link " + seq(in.LocalLinkSeq)
	if in.LocalLinkSeq == 0 {
		link = "no fresh local-link reading"
	}
	contains("incident "+model.CauseISPDNSFailure, "Degraded — AT&T DNS servers not answering", "Attributed to AT&T (provider side)",
		"Classified from: gateway snapshot "+seq(in.SnapshotSeq)+" · DNS & web check "+seq(in.ServiceCheckSeq)+
			" (compared with the previous DNS & web check "+seq(in.PrevServiceCheckSeq)+") · "+link+
			" · WAN traffic: gateway snapshots "+seq(in.TrafficFromSeq)+" → "+seq(in.TrafficToSeq)+" · window of 6 cycles",
		"AT&T DNS: no answer; retried: no answer", "Public DNS: answered")
	if in.PrevServiceCheckSeq == 0 || in.TrafficFromSeq == 0 || in.TrafficToSeq == 0 {
		t.Errorf("the incident's first verdict names no previous check or traffic snapshots: %+v", in)
	}
}
