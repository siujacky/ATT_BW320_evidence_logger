package export

// tools/verify_bundle.py checks record times against the trusted time-stamps of the chain like
// the att-monitor ledger verifier (internal/ledger timecheck.go, failure class ts_contradiction,
// tolerance 5 minutes), using only time-stamps it trusts: those openssl verified against a
// trusted root, or without openssl those whose records state verified and chain_ok. It also says
// plainly that it does not verify the report.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// pyTimeScenarios drives verify_bundle.TimeCheck directly with the scenarios of the Go ledger
// verifier's tests (internal/ledger timecheck_test.go) and prints the outcome as JSON.
const pyTimeScenarios = `
import json, sys
sys.path.insert(0, sys.argv[1])
import verify_bundle as v

S = v.NS
T0 = v.parse_ts_ns("2026-10-05T00:00:00Z")
YEAR = 365 * 24 * 3600 * S


class Ledger(object):
    """Records written by a computer whose clock reads real time + off; anchors stamped by a TSA
    with a correct clock (genTime = real time), each covering the records before it."""

    def __init__(self):
        self.recs, self.anchors, self.real, self.off = [], {}, T0, 0

    def rec(self, flags=0, advance=10):
        self.real += advance * S
        self.recs.append((len(self.recs), self.real + self.off, flags))
        return len(self.recs) - 1

    def anchor(self, trusted=True):
        seq = len(self.recs)
        if trusted:
            self.anchors[seq] = (seq - 1, self.real)
        self.recs.append((seq, self.real + self.off, 0))
        return seq

    def run(self, now=None):
        tc = v.TimeCheck(now if now is not None else T0 + YEAR)
        for seq, ts, flags in self.recs:
            a = self.anchors.get(seq)
            if a is not None:
                tc.anchor((seq, a[0], "CN=Clock TSA", a[1]))
            tc.record(seq, ts, 0, seq + 1, flags)
        tc.finish()
        fails = sorted(tc.low_fails + tc.high_fails, key=lambda f: (f[0][2], f[0][3]))
        return {"fails": [{"seq": f[0][0], "line": f[0][3], "detail": f[1]} for f in fails], "notes": tc.notes}


out = {}

# The custodian stops the monitor, sets the clock back 50 hours, runs it (a correct TSA anchors
# the run), restores the clock and restarts it.
L = Ledger()
L.rec(v.F_GENESIS, 0)
for _ in range(3): L.rec()
L.anchor()
for _ in range(3): L.rec()
L.rec()  # monitor_stop
L.off = -50 * 3600 * S
first_back = L.rec(v.F_CLOCK_ALERT)  # the writer's integrity_alert on open
L.rec()  # monitor_start
for _ in range(3): L.rec()
a2 = L.anchor()
for _ in range(2): L.rec()
stop2 = L.rec()
L.off = 0
L.rec()
for _ in range(3): L.rec()
L.anchor()
for _ in range(2): L.rec()
out["backdated"] = dict(L.run(), first_back=first_back, stop2=stop2, a2=a2)

# A clock running 3 hours ahead, corrected within the run (clock_jump).
L = Ledger()
L.off = 3 * 3600 * S
L.rec(v.F_GENESIS, 0)
for _ in range(4): L.rec()
a = L.anchor()
L.rec()
L.off = 0
jump = L.rec(v.F_CLOCK_JUMP)
for _ in range(3): L.rec()
L.anchor()
L.rec()
out["forward"] = dict(L.run(), a=a, jump=jump)

# An anchor record dated before the genTime of its own token (the clock is an hour behind).
L = Ledger()
L.off = -3600 * S
L.rec(v.F_GENESIS, 0)
for _ in range(3): L.rec()
a = L.anchor()
out["anchor_before_own"] = dict(L.run(), a=a)

# Ordinary clock error is tolerated; only a trusted time-stamp counts.
for name, off, trusted in (("accurate", 0, True), ("4m behind", -240, True), ("4m ahead", 240, True),
                           ("6m behind", -360, True), ("6m ahead", 360, True), ("untrusted", -50 * 3600, False)):
    L = Ledger()
    L.off = off * S
    L.rec(v.F_GENESIS, 0)
    for _ in range(3):
        for _ in range(3): L.rec()
        L.anchor(trusted)
    for _ in range(2): L.rec()
    out["tolerance " + name] = L.run()

# Without trusted time-stamps only the order is checked: a step back within a run (clock_jump),
# and one across a restart to before the genesis record (the writer's integrity_alert).
recs = []
def add(ts, flags=0):
    recs.append((len(recs), ts, flags))
    return len(recs) - 1
add(T0, v.F_GENESIS)
for i in range(3): add(T0 + 3 * 3600 * S + (10 + 10 * i) * S)
add(T0 + 2 * 3600 * S + 40 * S)
jump = add(T0 + 2 * 3600 * S + 41 * S, v.F_CLOCK_JUMP)
for i in range(2): add(T0 + 2 * 3600 * S + (50 + 10 * i) * S)
for i in range(2): add(T0 + 3 * 3600 * S + (70 + 10 * i) * S)
add(T0 + 3 * 3600 * S + 85 * S)
alert = add(T0 - 24 * 3600 * S, v.F_CLOCK_ALERT)
for i in range(2): add(T0 - 24 * 3600 * S + (10 + 10 * i) * S)
L = Ledger()
L.recs = recs
out["backward"] = dict(L.run(), jump=jump, alert=alert)

# Records dated after the verification.
L = Ledger()
L.rec(v.F_GENESIS, 0)
L.rec()
L.rec()
out["future"] = L.run(now=T0 - 3600 * S)

# More records than the pending list holds await a time-stamp: the older ones are folded.
v.MAX_PENDING_TS = 8
L = Ledger()
L.off = 3600 * S
L.rec(v.F_GENESIS, 0)
for _ in range(19): L.rec()
L.off = 0
L.anchor()
for _ in range(3): L.rec()
L.anchor()
out["fold"] = L.run()

out["format"] = {
    "dur": [v.fmt_dur(x) for x in (0, 300 * S, 3600 * S, 1500 * 10 ** 6, -90 * S, 499 * 10 ** 6, 588 * S + S // 2, 50 * 3600 * S)],
    "ts": [v.fmt_ts(v.parse_ts_ns(x)) for x in ("2026-10-05T03:20:00.123456789Z", "2026-10-05T03:20:00Z", "2026-10-05T03:20:00.5+02:00")],
    "bad": [v.parse_ts_ns(x) for x in ("garbage", "2026-13-01T00:00:00Z", "2026-10-05T24:00:00Z", "2026-10-05 03:20:00Z", "2026-10-05t03:20:00z", None)],
}
print(json.dumps(out))
`

type pyTimeResult struct {
	Fails []struct {
		Seq    uint64 `json:"seq"`
		Line   int    `json:"line"`
		Detail string `json:"detail"`
	} `json:"fails"`
	Notes     []string `json:"notes"`
	FirstBack uint64   `json:"first_back"`
	Stop2     uint64   `json:"stop2"`
	A2        uint64   `json:"a2"`
	A         uint64   `json:"a"`
	Jump      uint64   `json:"jump"`
	Alert     uint64   `json:"alert"`
}

func notesContaining(notes []string, sub string) []string {
	var out []string
	for _, n := range notes {
		if strings.Contains(n, sub) {
			out = append(out, n)
		}
	}
	return out
}

func TestPythonTimeCheckMatchesLedgerVerifier(t *testing.T) {
	py := findPython(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "verify_bundle.py"), verifyScript, 0o644); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "scenarios.py")
	if err := os.WriteFile(script, []byte(pyTimeScenarios), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := runPython(t, py, script, dir)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	var res map[string]json.RawMessage
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("%v:\n%s", err, out)
	}
	get := func(name string) pyTimeResult {
		var r pyTimeResult
		if err := json.Unmarshal(res[name], &r); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return r
	}

	t.Run("back-dated run", func(t *testing.T) {
		r := get("backdated")
		if len(r.Fails) != 1 || r.Fails[0].Seq != r.FirstBack || r.Fails[0].Line != int(r.FirstBack)+1 {
			t.Fatalf("want one failure at the first back-dated record %d: %+v", r.FirstBack, r.Fails)
		}
		for _, want := range []string{fmt.Sprintf("%d records from seq %d to seq %d are", r.Stop2-r.FirstBack+1, r.FirstBack, r.Stop2),
			"earlier than trusted time-stamps that precede them", fmt.Sprintf("anchor record %d (CN=Clock TSA)", r.A2), "50h0m0s",
			"back-dated, or the clock was behind (tolerance 5m0s)"} {
			if !strings.Contains(r.Fails[0].Detail, want) {
				t.Errorf("detail %q lacks %q", r.Fails[0].Detail, want)
			}
		}
		if n := notesContaining(r.Notes, "record ts go backwards"); len(n) != 1 || !strings.Contains(n[0], fmt.Sprintf("seq %d", r.FirstBack)) ||
			!strings.Contains(n[0], fmt.Sprintf("integrity_alert seq %d", r.FirstBack)) {
			t.Errorf("backward-step notes %q", r.Notes)
		}
	})

	t.Run("forward-dated records", func(t *testing.T) {
		r := get("forward")
		if len(r.Fails) != 1 || r.Fails[0].Seq != 0 || r.Fails[0].Line != 1 {
			t.Fatalf("want one failure at the genesis record: %+v", r.Fails)
		}
		for _, want := range []string{fmt.Sprintf("%d records from seq 0 to seq %d are", r.Jump, r.Jump-1), fmt.Sprintf("anchor record %d", r.A),
			"later than", "3h0m0s", "forward-dated, or the clock was ahead"} {
			if !strings.Contains(r.Fails[0].Detail, want) {
				t.Errorf("detail %q lacks %q", r.Fails[0].Detail, want)
			}
		}
		if n := notesContaining(r.Notes, "record ts go backwards"); len(n) != 1 || !strings.Contains(n[0], fmt.Sprintf("clock_jump record seq %d", r.Jump)) {
			t.Errorf("backward-step notes %q", r.Notes)
		}
	})

	t.Run("anchor record dated before its own time-stamp", func(t *testing.T) {
		r := get("anchor_before_own")
		if len(r.Fails) != 1 || r.Fails[0].Seq != r.A || !strings.Contains(r.Fails[0].Detail, fmt.Sprintf("seq %d is dated", r.A)) ||
			!strings.Contains(r.Fails[0].Detail, "earlier than") {
			t.Fatalf("want one failure at the anchor record %d: %+v", r.A, r.Fails)
		}
	})

	t.Run("tolerance and trust", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			fails bool
			agree string
		}{
			{"accurate", false, "no record is dated more than 0s before a time-stamp that precedes it, nor more than 0s after one that covers it"},
			{"4m behind", false, "more than 4m0s before a time-stamp"},
			{"4m ahead", false, "more than 4m0s after one that covers it"},
			{"6m behind", true, ""},
			{"6m ahead", true, ""},
			{"untrusted", false, ""},
		} {
			r := get("tolerance " + tc.name)
			if (len(r.Fails) > 0) != tc.fails {
				t.Errorf("%s: failures %+v", tc.name, r.Fails)
			}
			agree := notesContaining(r.Notes, "agree with the 3 trusted time-stamp(s)")
			if want := tc.agree != ""; (len(agree) == 1) != want || (want && !strings.Contains(agree[0], tc.agree)) {
				t.Errorf("%s: agreement note %q", tc.name, r.Notes)
			}
		}
	})

	t.Run("backward steps without time-stamps", func(t *testing.T) {
		r := get("backward")
		n := notesContaining(r.Notes, "record ts go backwards")
		if len(r.Fails) != 0 || len(n) != 2 {
			t.Fatalf("failures %+v notes %q", r.Fails, r.Notes)
		}
		if !strings.Contains(n[0], fmt.Sprintf("clock_jump record seq %d", r.Jump)) || strings.Contains(n[0], "genesis") {
			t.Errorf("in-run step note %q", n[0])
		}
		if !strings.Contains(n[1], "before the genesis record") || !strings.Contains(n[1], fmt.Sprintf("integrity_alert seq %d", r.Alert)) {
			t.Errorf("restart step note %q", n[1])
		}
	})

	t.Run("records dated after the verification", func(t *testing.T) {
		r := get("future")
		if n := notesContaining(r.Notes, "dated after the time of this verification"); len(n) != 1 || !strings.Contains(n[0], "1h0m20s later") {
			t.Fatalf("notes %q", r.Notes)
		}
	})

	t.Run("folded records", func(t *testing.T) {
		r := get("fold")
		if len(r.Fails) != 2 || r.Fails[0].Seq != 11 || r.Fails[1].Seq != 12 ||
			!strings.Contains(r.Fails[0].Detail, "of the 12 records seq 0-11 (more than 8 records awaited a trusted time-stamp") ||
			!strings.Contains(r.Fails[1].Detail, "8 records from seq 12 to seq 19 are dated up to 1h0m0s later") {
			t.Fatalf("failures %+v", r.Fails)
		}
	})

	t.Run("formatting", func(t *testing.T) {
		var f struct {
			Dur []string `json:"dur"`
			TS  []string `json:"ts"`
			Bad []*int64 `json:"bad"`
		}
		if err := json.Unmarshal(res["format"], &f); err != nil {
			t.Fatal(err)
		}
		// The way Go words them: time.Duration.Round(time.Second).String() (milliseconds below a second).
		var want []string
		for _, d := range []time.Duration{0, 5 * time.Minute, time.Hour, 1500 * time.Millisecond, -90 * time.Second, 499 * time.Millisecond,
			588*time.Second + 500*time.Millisecond, 50 * time.Hour} {
			if d >= time.Second || d <= -time.Second {
				want = append(want, d.Round(time.Second).String())
			} else {
				want = append(want, d.Round(time.Millisecond).String())
			}
		}
		if strings.Join(f.Dur, ",") != strings.Join(want, ",") {
			t.Errorf("durations %q, want %q", f.Dur, want)
		}
		if strings.Join(f.TS, ",") != "2026-10-05T03:20:00.123456789Z,2026-10-05T03:20:00Z,2026-10-05T01:20:00.5Z" {
			t.Errorf("times %q", f.TS)
		}
		for i, b := range f.Bad {
			if b != nil {
				t.Errorf("invalid time %d parsed as %d", i, *b)
			}
		}
	})
}

// timeLedger builds a bundle whose records contradict its time-stamps: after the first anchor,
// three samples are dated 10 minutes earlier than its genTime (back-dated), and later one sample
// is dated an hour ahead and then covered by an anchor (forward-dated). flags are the anchor
// records' issue-time flags (verified, chain_ok).
func timeLedger(t *testing.T, flags bool) (contracts.ExportInfo, *fakeLedger, []model.Ref) {
	t.Helper()
	d := func(m, s int) time.Time { return time.Date(2026, 10, 3, 12, m, s, 0, time.UTC) }
	f := rvLedger(t, d(0, 0))
	var anchors []model.Ref
	anchor := func(at time.Time) {
		ref, _ := rvAnchor(t, f, at, nil, "", true)
		anchors = append(anchors, ref)
	}
	if !flags {
		anchor = func(at time.Time) {
			token := f.tsa.stamp(t, mustHex(t, f.head.Hash), at)
			id := f.putBlob(token)
			anchors = append(anchors, f.append(at, model.TypeAnchor, model.Anchor{TSAURL: "https://tsa.example/tsr", HeadSeq: f.head.Seq,
				HeadHash: f.head.Hash, TokenSHA256: id, GenTime: at.UTC().Format(time.RFC3339), Verified: false, ChainOK: false,
				ChainNote: "x509: certificate signed by unknown authority", Reason: "periodic"}, id))
		}
	}
	rvSamples(f, d(1, 0), 3, 10*time.Second, model.StateOnline, "", model.AttrNone, "") // seq 2-4
	anchor(d(1, 30))                                                                    // seq 5
	rvSamples(f, d(1, 40).Add(-10*time.Minute), 3, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	rvSamples(f, d(2, 10), 3, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	anchor(d(2, 40))
	rvSamples(f, d(2, 50), 3, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	anchor(d(3, 30))
	rvSamples(f, d(3, 40).Add(time.Hour), 1, 10*time.Second, model.StateOnline, "", model.AttrNone, "") // seq 17
	anchor(d(3, 50))
	rvSamples(f, d(4, 0), 3, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	anchor(d(4, 40))
	rvSamples(f, d(4, 50), 3, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	info, _, _ := rvExport(t, f, d(30, 0), contracts.ExportRequest{From: d(0, 0), To: d(20, 0)},
		func(o *Options) { o.ExtraFiles = map[string][]byte{tsaRootsPath: f.tsa.rootPEM()} })
	return info, f, anchors
}

var tsFailureRE = regexp.MustCompile(`(?m)^  - ledger-2026-10-03 line (\d+) \(seq (\d+)\): record time contradicts a trusted time-stamp \(ts_contradiction\): (.*)$`)

func TestPythonVerifierRecordTimes(t *testing.T) {
	py := findPython(t)
	info, f, anchors := timeLedger(t, true)
	script := shippedScript(t, info.Path)
	if len(anchors) != 5 || anchors[0].Seq != 5 {
		t.Fatalf("test setup: anchors %+v", anchors)
	}
	check := func(t *testing.T, out string, code int, how string) {
		t.Helper()
		m := tsFailureRE.FindAllStringSubmatch(out, -1)
		if code != 1 || !strings.Contains(out, "RESULT: FAIL") || len(m) != 2 {
			t.Fatalf("exit %d, want 1 with two ts_contradiction failures:\n%s", code, out)
		}
		if m[0][1] != "7" || m[0][2] != "6" || !strings.Contains(m[0][3], "3 records from seq 6 to seq 8 are dated up to 9m49s earlier than trusted time-stamps") ||
			!strings.Contains(m[0][3], fmt.Sprintf("held by anchor record %d", anchors[0].Seq)) {
			t.Errorf("back-dated failure %q", m[0][0])
		}
		if m[1][2] != "17" || !strings.Contains(m[1][3], "seq 17 is dated up to 59m52s later than trusted time-stamps that cover it") ||
			!strings.Contains(m[1][3], fmt.Sprintf("anchor record %d", anchors[3].Seq)) {
			t.Errorf("forward-dated failure %q", m[1][0])
		}
		if !strings.Contains(out, pyLine("Record times", "FAILED (2 contradiction(s) with the 5 trusted time-stamp(s), "+how)) {
			t.Errorf("record-times line missing (%s):\n%s", how, out)
		}
		if !strings.Contains(out, "record ts go backwards: seq 18-") || !strings.Contains(out, "before seq 17") {
			t.Errorf("backward-step note missing:\n%s", out)
		}
	}

	t.Run("openssl, root trusted", func(t *testing.T) {
		findOpenSSL(t)
		out, code := runPython(t, py, script, "--trust-root", sha256Hex(f.tsa.cert.Raw), info.Path)
		check(t, out, code, "their TSA signatures and certificate chains verified by openssl against a trusted root")
	})

	t.Run("openssl, root not trusted", func(t *testing.T) {
		findOpenSSL(t)
		out, code := runPython(t, py, script, info.Path)
		if code != 0 || tsFailureRE.MatchString(out) || !strings.Contains(out, pyLine("Record times", "NOT CHECKED against time-stamps")) ||
			!strings.Contains(out, "record times were NOT checked against time-stamps") {
			t.Fatalf("exit %d: time-stamps that are not proof of time must not decide record times:\n%s", code, out)
		}
	})

	t.Run("openssl limit", func(t *testing.T) {
		findOpenSSL(t)
		out, code := runPython(t, py, script, "--trust-root", sha256Hex(f.tsa.cert.Raw), "--openssl-limit", "2", info.Path)
		if code != 1 || len(tsFailureRE.FindAllString(out, -1)) != 2 || !strings.Contains(out, "with the 2 trusted time-stamp(s)") ||
			!strings.Contains(out, "3 other time-stamp(s) were not verified with openssl (--openssl-limit) and were not used here") {
			t.Fatalf("exit %d:\n%s", code, out)
		}
	})

	t.Run("without openssl: issue-time flags", func(t *testing.T) {
		out, code := runPython(t, py, script, "--openssl-limit", "0", info.Path)
		check(t, out, code, "accepted per their anchor records' issue-time flags verified and chain_ok; their TSA signatures and chains were NOT verified here")
	})

	t.Run("without openssl: flags say not verified", func(t *testing.T) {
		info, _, _ := timeLedger(t, false)
		out, code := runPython(t, py, script, "--openssl-limit", "0", info.Path)
		if code != 0 || tsFailureRE.MatchString(out) || !strings.Contains(out, pyLine("Record times", "NOT CHECKED")) {
			t.Fatalf("exit %d: anchors recorded as not verified must not decide record times:\n%s", code, out)
		}
	})

	t.Run("a genuine bundle passes", func(t *testing.T) {
		_, plain := buildIncidentBundle(t)
		out, code := runPython(t, py, shippedScript(t, plain.Path), "--openssl-limit", "0", plain.Path)
		if code != 0 || !strings.Contains(out, pyLine("Record times", "OK (no record contradicts the 3 trusted time-stamp(s) by more than 5m0s")) ||
			!strings.Contains(out, "record ts agree with the 3 trusted time-stamp(s)") {
			t.Fatalf("exit %d:\n%s", code, out)
		}
		for _, want := range []string{pyLine("Report files", "NOT VERIFIED by this script: REPORT.html, report.json and README.txt"),
			"REPORT.html and report.json were NOT verified by this script", "Use 'att-monitor verify-bundle' to verify the report's figures."} {
			if !strings.Contains(out, want) {
				t.Errorf("output lacks %q:\n%s", want, out)
			}
		}
	})
}
