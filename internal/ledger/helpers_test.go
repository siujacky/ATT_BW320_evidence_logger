package ledger

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/model"
)

// fakeClock drives both the wall clock (Options.Now) and the monotonic clock (monoClock).
// Advance moves both (time passes); Step moves only the wall clock (a clock adjustment).
type fakeClock struct {
	mu   sync.Mutex
	t    time.Time
	mono time.Duration
}

func newClock(t time.Time) *fakeClock { return &fakeClock{t: t} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Mono() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mono
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
	c.mono += d
}

func (c *fakeClock) Step(to time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = to
}

func identity(b []byte) ([]byte, error) { return append([]byte(nil), b...), nil }

var t0 = time.Date(2026, 10, 5, 3, 20, 0, 0, time.UTC)

func testOptions(dir string, clk *fakeClock) Options {
	return Options{
		Paths:        config.PathsFor(dir),
		Host:         model.HostInfo{Hostname: "test-host", OS: "Windows 11 Pro for Workstations", OSVersion: "10.0.26200"},
		Software:     model.SoftwareInfo{Name: "att-monitor", Version: "test", GoVersion: runtime.Version(), Rules: "2026.10-1"},
		Now:          clk.Now,
		KeyProtect:   identity,
		KeyUnprotect: identity,
		monoClock:    clk.Mono,
	}
}

// openStore opens a store and closes it at the end of the test.
func openStore(t *testing.T, opts Options) *Store {
	t.Helper()
	s, err := Open(opts)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// newLedger creates a fresh writer in a temporary directory.
func newLedger(t *testing.T) (*Store, string, *fakeClock) {
	t.Helper()
	dir := t.TempDir()
	clk := newClock(t0)
	return openStore(t, testOptions(dir, clk)), dir, clk
}

func samplePayload(cycle uint64) model.Sample {
	return model.Sample{
		Cycle:   cycle,
		Started: "2026-10-05T03:20:00Z",
		DurMs:   12,
		Probes: []model.ProbeResult{
			{Name: "gateway_icmp", Kind: model.KindICMP, Role: model.RoleGateway, Target: "192.168.1.254", OK: true, RTTus: 1900, Status: "IP_SUCCESS"},
			{Name: "inet_icmp_google", Kind: model.KindICMP, Role: model.RoleInet, Target: "8.8.8.8", OK: cycle%7 != 0, RTTus: 14200, Status: "IP_SUCCESS"},
		},
		Verdict: model.Verdict{State: model.StateOnline, Attribution: model.AttrNone,
			Reasons: []string{"gateway 192.168.1.254 answered ICMP in 1.9 ms <fast> & \"quoted\"   é"}, Rules: "2026.10-1"},
	}
}

// appendSamples appends n sample records, advancing the clock by step before each.
func appendSamples(t *testing.T, s *Store, clk *fakeClock, n int, step time.Duration) []model.Ref {
	t.Helper()
	refs := make([]model.Ref, 0, n)
	for i := 0; i < n; i++ {
		clk.Advance(step)
		ref, err := s.Append(model.TypeSample, samplePayload(uint64(i)))
		if err != nil {
			t.Fatalf("Append sample %d: %v", i, err)
		}
		refs = append(refs, ref)
	}
	return refs
}

func mustAppend(t *testing.T, s *Store, typ string, data any, blobs ...string) model.Ref {
	t.Helper()
	ref, err := s.Append(typ, data, blobs...)
	if err != nil {
		t.Fatalf("Append %s: %v", typ, err)
	}
	return ref
}

func segPath(dir, name string) string { return filepath.Join(dir, "ledger", name+".jsonl") }

func segName(d time.Time) string { return "ledger-" + d.UTC().Format("2006-01-02") }

// readLines returns the lines of a file, each including its '\n' (a final fragment without
// one is returned as the last element).
func readLines(t *testing.T, path string) [][]byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			out = append(out, b)
			break
		}
		out = append(out, b[:i+1])
		b = b[i+1:]
	}
	return out
}

func writeLines(t *testing.T, path string, lines [][]byte) {
	t.Helper()
	if err := os.WriteFile(path, bytes.Join(lines, nil), 0o644); err != nil {
		t.Fatal(err)
	}
}

func parseLine(t *testing.T, line []byte) (model.Envelope, model.Body) {
	t.Helper()
	env, body, err := parseRecordLenient(line)
	if err != nil {
		t.Fatalf("parse %q: %v", line, err)
	}
	return env, body
}

// reencode builds a validly formatted line for body, signed with priv.
func reencode(t *testing.T, priv ed25519.PrivateKey, body model.Body) []byte {
	t.Helper()
	line, _, err := encodeRecord(priv, &body)
	if err != nil {
		t.Fatal(err)
	}
	return line
}

// verifyRO opens the ledger read-only and verifies it.
func verifyRO(t *testing.T, dir string, clk *fakeClock) model.VerifyReport {
	t.Helper()
	opts := testOptions(dir, clk)
	opts.ReadOnly = true
	ro := openStore(t, opts)
	rep, err := ro.Verify(context.Background())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return rep
}

func problems(rep model.VerifyReport) map[string]int {
	m := map[string]int{}
	for _, f := range rep.Failures {
		m[f.Problem]++
	}
	return m
}

func dumpReport(rep model.VerifyReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "ok=%v records=%d failures=%d\n", rep.OK, rep.Records, rep.FailuresTotal)
	for _, f := range rep.Failures {
		fmt.Fprintf(&b, "  %s line %d seq %d: %s: %s\n", f.Segment, f.Line, f.Seq, f.Problem, f.Detail)
	}
	for _, n := range rep.Notes {
		fmt.Fprintf(&b, "  note: %s\n", n)
	}
	return b.String()
}

func requireOK(t *testing.T, rep model.VerifyReport) {
	t.Helper()
	if !rep.OK || rep.FailuresTotal != 0 {
		t.Fatalf("verification failed:\n%s", dumpReport(rep))
	}
}

// scanAll returns every record via Scan(0).
func scanAll(t *testing.T, s *Store) []model.Body {
	t.Helper()
	var out []model.Body
	if err := s.Scan(0, func(_ model.Envelope, b model.Body) error {
		out = append(out, b)
		return nil
	}); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return out
}

func typesOf(bodies []model.Body) []string {
	out := make([]string, len(bodies))
	for i, b := range bodies {
		out[i] = b.Type
	}
	return out
}

func decodeData[T any](t *testing.T, b model.Body) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(b.Data, &v); err != nil {
		t.Fatalf("decode %s data: %v", b.Type, err)
	}
	return v
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
