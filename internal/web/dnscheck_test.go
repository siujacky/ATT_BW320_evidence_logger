package web

// The DNS rows of the dashboard (docs/DESIGN.md §8). Besides resolving www.google.com through
// each resolver, every service check asks the gateway's resolver for a random
// "<16 hex>.invalid" name. Names under .invalid never exist (RFC 6761), so NXDOMAIN is the
// healthy answer to that query and any answer at all is a hijack. The dashboard must show
// that row as the hijack test it is, naming the queried name. It must never show it as a red
// "NXDOMAIN" gateway DNS failure, which would make a healthy AT&T gateway look like it was
// failing every minute. It must still show a real hijack in red.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// hijackTestName matches the random name of the hijack test as the monitor builds it.
var hijackTestName = regexp.MustCompile(`[0-9a-f]{16}\.invalid`)

// rowsWith returns the table rows of v whose text matches re.
func rowsWith(v dashboardView, re *regexp.Regexp) []dashboardRow {
	var out []dashboardRow
	for _, r := range v.Rows {
		if re.MatchString(r.Text) {
			out = append(out, r)
		}
	}
	return out
}

// TestDashboardShowsDNSHijackTestAsPassed renders a healthy line. Every DNS row must be
// green, the .invalid query must be labelled as the gateway's hijack test with its name, and
// the timeline must word it the same way.
func TestDashboardShowsDNSHijackTestAsPassed(t *testing.T) {
	requireNode(t)
	rep := runDashboard(t, newDemoWorld(time.Now()), "plain")
	// The checks are in the Overview's Internet details.
	ov, ok := rep.Views["overview internet"]
	if !ok {
		t.Fatalf("no Internet details rendered (views: %v)", keys(rep.Views))
	}

	tests := rowsWith(ov, hijackTestName)
	if len(tests) != 1 {
		t.Fatalf("overview: %d rows name the .invalid hijack test query, want 1; rows:\n%s", len(tests), rowDump(ov.Rows))
	}
	row := tests[0]
	for _, want := range []string{"Gateway DNS hijack test", demoGateway, "NXDOMAIN, the correct answer"} {
		if !strings.Contains(row.Text, want) {
			t.Errorf("hijack test row %q does not show %q", row.Text, want)
		}
	}
	if !slices.Equal(row.Chips, []string{"good:not hijacked"}) {
		t.Errorf("hijack test row %q has chips %q, want a green \"not hijacked\"", row.Text, row.Chips)
	}

	// The real resolution checks name the name they resolved, and all of them passed.
	resolved := rowsWith(ov, regexp.MustCompile(`DNS.*www\.google\.com`))
	if len(resolved) != 3 {
		t.Errorf("overview: %d rows show the www.google.com checks, want 3 (gateway, AT&T, public); rows:\n%s", len(resolved), rowDump(ov.Rows))
	}
	for _, r := range resolved {
		if !slices.Equal(r.Chips, []string{"good:answered"}) {
			t.Errorf("resolution check row %q has chips %q, want a green \"answered\"", r.Text, r.Chips)
		}
	}
	// Nothing on a healthy line is a red DNS result, and the summary card says so.
	for _, r := range ov.Rows {
		if strings.Contains(r.Text, "DNS") && slices.ContainsFunc(r.Chips, func(c string) bool { return strings.HasPrefix(c, "critical:") }) {
			t.Errorf("healthy line: DNS row %q shows a critical chip %q", r.Text, r.Chips)
		}
	}
	if c := rep.Views["overview"].card(t, "internet"); c.Chip != "good:OK" || !strings.Contains(c.Text, "DNS answered · web checks OK · no DNS hijack") {
		t.Errorf("the Internet card on a healthy line: %+v", c)
	}

	// The timeline and the records say the same as the overview.
	passed := regexp.MustCompile(`Gateway DNS hijack test \([0-9a-f]{16}\.invalid\): not hijacked \(NXDOMAIN, the correct answer\)`)
	if v := rep.Views["records"].Text; !passed.MatchString(v) {
		t.Errorf("records view does not word the hijack test as passed (%s):\n%.3000s", passed, v)
	}
	for name, v := range rep.Views {
		if strings.Contains(v.Text, "Gateway DNS: answered NXDOMAIN") {
			t.Errorf("view %q words the hijack test as a gateway DNS answer: \"Gateway DNS: answered NXDOMAIN\"", name)
		}
	}
	// During the AT&T fiber outage the gateway's resolver failed (SERVFAIL) but still did not
	// hijack anything. From rules 2026.10-4 every resolution query without a valid answer is
	// retried once within its check, and the timeline words each query with its retry.
	outage := regexp.MustCompile(`Gateway DNS: answered SERVFAIL; retried: answered SERVFAIL · AT&T DNS: no answer; retried: no answer · ` +
		`Public DNS: no answer; retried: no answer · Gateway DNS hijack test \([0-9a-f]{16}\.invalid\): not hijacked \(answered SERVFAIL, no address\)`)
	if v := rep.Views["incident "+model.CauseFiberLinkDown].Text; !outage.MatchString(v) {
		i := max(0, strings.Index(v, "DNS and web checks"+"Gateway DNS"))
		t.Errorf("fiber outage incident does not word the DNS checks as %s:\n%.1500s", outage, v[i:])
	}
}

// TestDashboardShowsDNSHijack renders a gateway that answers the hijack test with its own
// address. That is a hijack, and the dashboard must show it in red with the evidence.
func TestDashboardShowsDNSHijack(t *testing.T) {
	requireNode(t)
	w := newDemoWorld(time.Now())
	w.mu.Lock()
	w.dnsHijack = true
	w.mu.Unlock()
	rep := runDashboard(t, w, "plain")
	ov := rep.Views["overview internet"]
	tests := rowsWith(ov, hijackTestName)
	if len(tests) != 1 {
		t.Fatalf("overview: %d rows name the .invalid hijack test query, want 1; rows:\n%s", len(tests), rowDump(ov.Rows))
	}
	row := tests[0]
	if !slices.Equal(row.Chips, []string{"critical:HIJACKED"}) {
		t.Errorf("hijacked test row %q has chips %q, want a red \"HIJACKED\"", row.Text, row.Chips)
	}
	for _, want := range []string{"Gateway DNS hijack test", "must not resolve (RFC 6761) but got: " + demoGateway} {
		if !strings.Contains(row.Text, want) {
			t.Errorf("hijacked test row %q does not show %q", row.Text, want)
		}
	}
	if strings.Contains(row.Text, "not hijacked") {
		t.Errorf("hijacked test row %q says \"not hijacked\"", row.Text)
	}
	// The summary card says it in red.
	if c := rep.Views["overview"].card(t, "internet"); c.Chip != "critical:Hijacked" || c.Tone != "critical" || !strings.Contains(c.Text, "DNS HIJACKED") {
		t.Errorf("the Internet card on a hijacked line: %+v", c)
	}
}

// rowDump lists the rows that show status chips (the probe and check tables), for failure
// messages.
func rowDump(rows []dashboardRow) string {
	var b strings.Builder
	for _, r := range rows {
		if len(r.Chips) > 0 {
			b.WriteString("  " + r.Text + "  [" + strings.Join(r.Chips, ", ") + "]\n")
		}
	}
	return b.String()
}

// TestAppJSDNSVerdict runs dnsVerdict, extracted from app.js, under Node.js on the DNS results
// the probe and the monitor record. The dashboard must judge them as the monitor does: the
// classifier counts a resolution check as answered only with a well-formed, successful answer
// that carries a record (internal/monitor dnsAnswered), and it never counts the .invalid
// hijack test as a resolution failure (it checks that one only for hijacking).
func TestAppJSDNSVerdict(t *testing.T) {
	node := requireNode(t)
	src := appJS(t)
	var prog strings.Builder
	for _, fn := range []string{"isHijackTestName", "rcodeOK", "dnsVerdict"} {
		body, _, _ := functionSource(t, src, fn)
		prog.WriteString(body + "\n")
	}
	const gw = "192.168.1.254:53"
	google := func(extra map[string]any) map[string]any {
		r := map[string]any{"server": gw, "server_role": "gateway", "name": "www.google.com", "qtype": "A", "hijacked": false}
		for k, v := range extra {
			r[k] = v
		}
		return r
	}
	test := func(name string, extra map[string]any) map[string]any {
		r := google(extra)
		r["name"] = name
		return r
	}
	const inv = "bd5d25b1a90fdbe6.invalid"
	cases := []struct {
		what      string
		in        map[string]any
		test      bool
		tone      string
		label     string
		textHas   string // a substring of the timeline wording
		textLacks string
	}{
		// The hijack test.
		{"hijack test NXDOMAIN", test(inv, map[string]any{"ok": true, "rcode": "NXDOMAIN"}), true, "good", "not hijacked", "not hijacked (NXDOMAIN, the correct answer)", "answered NXDOMAIN"},
		{"hijack test name spelled differently", test("BD5D25B1A90FDBE6.INVALID.", map[string]any{"ok": true, "rcode": "NXDOMAIN"}), true, "good", "not hijacked", "NXDOMAIN", ""},
		{"hijack test answered with the gateway address", test(inv, map[string]any{"ok": true, "rcode": "NOERROR", "answers": []string{"192.168.1.254"}, "hijacked": true,
			"hijack_why": "reserved name " + inv + " must not resolve (RFC 6761) but got: 192.168.1.254"}), true, "critical", "HIJACKED", "HIJACKED (reserved name", "not hijacked"},
		{"hijack test SERVFAIL during an outage", test(inv, map[string]any{"ok": true, "rcode": "SERVFAIL"}), true, "good", "not hijacked", "not hijacked (answered SERVFAIL, no address)", ""},
		{"hijack test empty NOERROR", test(inv, map[string]any{"ok": true, "rcode": "NOERROR"}), true, "good", "not hijacked", "answered NOERROR, no address", ""},
		// Without a usable response the test is incomplete: nothing was hijacked or proven.
		{"hijack test without a response", test(inv, map[string]any{"ok": false, "err": "read udp: i/o timeout"}), true, "warning", "no answer", "no answer (hijack test not completed)", "not hijacked"},
		{"hijack test with a malformed response", test(inv, map[string]any{"ok": false, "rcode": "NXDOMAIN", "err": "malformed answer section: x"}), true, "warning", "malformed answer", "hijack test not completed", "not hijacked"},
		{"hijack test answered but not flagged", test(inv, map[string]any{"ok": true, "rcode": "NOERROR", "answers": []string{"203.0.113.9"}}), true, "warning", "unexpected answer", "", "not hijacked"},
		{"a name that merely contains invalid", test("invalid.example.com", map[string]any{"ok": true, "rcode": "NXDOMAIN"}), false, "critical", "NXDOMAIN", "answered NXDOMAIN", ""},
		{"a name ending in invalid without the dot", test("notinvalid", map[string]any{"ok": true, "rcode": "NXDOMAIN"}), false, "critical", "NXDOMAIN", "", ""},
		// The resolution checks.
		{"resolved", google(map[string]any{"ok": true, "rcode": "NOERROR", "answers": []string{"142.250.72.100"}}), false, "good", "answered", "answered", ""},
		{"resolved, other spelling of no error", google(map[string]any{"ok": true, "rcode": "Success", "answers": []string{"142.250.72.100"}}), false, "good", "answered", "answered", ""},
		{"resolved, rcode not recorded", google(map[string]any{"ok": true, "answers": []string{"CNAME:www.l.google.com", "142.250.72.100"}}), false, "good", "answered", "answered", ""},
		{"NXDOMAIN for a public name", google(map[string]any{"ok": true, "rcode": "NXDOMAIN"}), false, "critical", "NXDOMAIN", "answered NXDOMAIN", ""},
		{"SERVFAIL", google(map[string]any{"ok": true, "rcode": "SERVFAIL"}), false, "critical", "SERVFAIL", "answered SERVFAIL", ""},
		{"NOERROR without a record", google(map[string]any{"ok": true, "rcode": "NOERROR"}), false, "critical", "no address", "answered NOERROR, no address", ""},
		{"timeout", google(map[string]any{"ok": false, "err": "read udp: i/o timeout"}), false, "critical", "no answer", "no answer", ""},
		{"malformed response", google(map[string]any{"ok": false, "rcode": "NOERROR", "err": "malformed answer section: x"}), false, "critical", "malformed answer", "malformed answer", ""},
		{"public name hijacked", google(map[string]any{"ok": true, "rcode": "NOERROR", "answers": []string{"192.168.1.254"}, "hijacked": true,
			"hijack_why": "answer 192.168.1.254 for www.google.com is the gateway's own address"}), false, "critical", "HIJACKED", "HIJACKED (answer 192.168.1.254", ""},
	}
	ins := make([]map[string]any, len(cases))
	for i, c := range cases {
		ins[i] = c.in
	}
	inJSON, err := json.Marshal(ins)
	if err != nil {
		t.Fatal(err)
	}
	prog.WriteString("console.log(JSON.stringify(" + string(inJSON) + ".map((r) => dnsVerdict(r))));\n")
	p := filepath.Join(t.TempDir(), "dnsverdict.js")
	if err := os.WriteFile(p, []byte(prog.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, p).CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s\n--- program ---\n%s", err, out, prog.String())
	}
	var got []struct {
		Test  bool    `json:"test"`
		Tone  string  `json:"tone"`
		Label string  `json:"label"`
		Text  string  `json:"text"`
		Note  *string `json:"note"`
		Title *string `json:"title"`
	}
	if err := json.Unmarshal(out, &got); err != nil || len(got) != len(cases) {
		t.Fatalf("unexpected output %s (%v)", out, err)
	}
	for i, c := range cases {
		g := got[i]
		if g.Test != c.test || g.Tone != c.tone || g.Label != c.label {
			t.Errorf("%s: test %v, %s %q; want test %v, %s %q", c.what, g.Test, g.Tone, g.Label, c.test, c.tone, c.label)
		}
		if c.textHas != "" && !strings.Contains(g.Text, c.textHas) {
			t.Errorf("%s: text %q does not contain %q", c.what, g.Text, c.textHas)
		}
		if c.textLacks != "" && strings.Contains(g.Text, c.textLacks) {
			t.Errorf("%s: text %q contains %q", c.what, g.Text, c.textLacks)
		}
	}
}
