package ipintel

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// t0 is the tests' base time.
var t0 = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

// row is one line of a synthetic table.
type row struct {
	start, end string
	asn        uint32
	cc, desc   string
}

func (r row) line() string {
	return fmt.Sprintf("%s\t%s\t%d\t%s\t%s", r.start, r.end, r.asn, r.cc, r.desc)
}

// rows4 is a small IPv4 table in the IPtoASN format: a few public rows (public facts) and the
// documentation ranges, which a table may hold but Lookup never looks up. The AS numbers of the
// synthetic rows are documentation ASNs (RFC 5398).
var rows4 = []row{
	{"1.0.0.0", "1.0.0.255", 13335, "US", "CLOUDFLARENET"},
	{"1.0.1.0", "1.0.3.255", 0, "None", "Not routed"},
	{"1.0.4.0", "1.0.7.255", 38803, "AU", "WPL-AS-AP Wirefreebroadband Pty Ltd"},
	{"1.1.1.0", "1.1.1.255", 13335, "US", "CLOUDFLARENET"},
	{"8.8.4.0", "8.8.4.255", 15169, "US", "GOOGLE"},
	{"8.8.5.0", "8.8.7.255", 0, "None", "Not routed"},
	{"8.8.8.0", "8.8.8.255", 15169, "US", "GOOGLE"},
	{"9.9.9.0", "9.9.9.255", 19281, "US", "QUAD9-AS-1"},
	{"192.0.2.0", "192.0.2.255", 64496, "US", "DOCUMENTATION-AS"},
	{"198.51.100.0", "198.51.100.255", 64497, "US", "DOCUMENTATION-AS"},
	{"203.0.113.0", "203.0.113.255", 64498, "ZZ", "DOCUMENTATION-AS"},
	{"223.255.255.0", "223.255.255.255", 64499, "jp", "EXAMPLE-NET-AP Example Networks Co., Ltd."},
}

// rows6 is a small IPv6 table, like rows4.
var rows6 = []row{
	{"2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", 64496, "US", "DOCUMENTATION-AS"},
	{"2001:4860::", "2001:4860:ffff:ffff:ffff:ffff:ffff:ffff", 15169, "US", "GOOGLE"},
	{"2001:4861::", "2001:4cff:ffff:ffff:ffff:ffff:ffff:ffff", 0, "None", "Not routed"},
	{"2606:4700::", "2606:4700:ffff:ffff:ffff:ffff:ffff:ffff", 13335, "US", "CLOUDFLARENET"},
	{"2a00:1450::", "2a00:1450:ffff:ffff:ffff:ffff:ffff:ffff", 15169, "US", "GOOGLE"},
}

// gzLines returns lines, each followed by a line feed, gzip-compressed.
func gzLines(lines ...string) []byte {
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	for _, l := range lines {
		zw.Write([]byte(l + "\n"))
	}
	zw.Close()
	return b.Bytes()
}

// gzRows returns a table of rows, gzip-compressed.
func gzRows(rows []row) []byte {
	lines := make([]string, len(rows))
	for i, r := range rows {
		lines[i] = r.line()
	}
	return gzLines(lines...)
}

// writeTables puts table files into dir (nil: none).
func writeTables(t testing.TB, dir string, v4, v6 []byte) {
	t.Helper()
	for name, b := range map[string][]byte{nameV4: v4, nameV6: v6} {
		if b == nil {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// mustAddr parses an address.
func mustAddr(t testing.TB, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// openTest opens an enabled DB in dir, logging to the test.
func openTest(t testing.TB, dir string, o Options) *DB {
	t.Helper()
	o.Enabled = true
	if o.Logger == nil {
		o.Logger = slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	d, err := Open(dir, o)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// testWriter sends log lines to t.Log.
type testWriter struct{ t testing.TB }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// loadedTables opens a DB in a new directory with rows4/rows6 (or the given tables) loaded.
func loadedTables(t testing.TB, v4, v6 []byte) *DB {
	t.Helper()
	dir := t.TempDir()
	writeTables(t, dir, v4, v6)
	d := openTest(t, dir, Options{})
	d.reload(context.Background())
	if p := d.Status().Error; p != "" {
		t.Fatalf("load: %s", p)
	}
	return d
}

// waitFor polls cond until it holds, failing the test after 10 seconds.
func waitFor(t testing.TB, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// startRun runs d.Run in a goroutine; the returned function stops it and waits for it to return.
func startRun(t testing.TB, d *DB) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		d.Run(ctx)
		close(done)
	}()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("Run did not return after its context ended")
			}
		})
	}
	t.Cleanup(stop)
	return stop
}

// ---------------------------------------------------------------- clock

// fakeClock is the DB's clock and timer in tests: Run's waits are handed to the test, which
// moves the time on and wakes Run up.
type fakeClock struct {
	mu    sync.Mutex
	now   time.Time
	waits chan fakeWait
}

// fakeWait is one of Run's waits.
type fakeWait struct {
	d  time.Duration
	ch chan time.Time
}

func newFakeClock(t time.Time) *fakeClock {
	return &fakeClock{now: t, waits: make(chan fakeWait, 64)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// After hands the wait to the test (a wait the test does not take never ends).
func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	w := fakeWait{d: d, ch: make(chan time.Time, 1)}
	select {
	case c.waits <- w:
	default:
	}
	return w.ch
}

// next returns Run's next wait.
func (c *fakeClock) next(t testing.TB) fakeWait {
	t.Helper()
	select {
	case w := <-c.waits:
		return w
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not wait")
		return fakeWait{}
	}
}

// fire moves the clock on by the wait and ends it.
func (c *fakeClock) fire(w fakeWait) {
	c.Advance(w.d)
	w.ch <- c.Now()
}

// ---------------------------------------------------------------- resolver

// fakeResolver answers reverse lookups from a map: a name list, an error, or "no such host".
type fakeResolver struct {
	mu    sync.Mutex
	names map[string][]string
	errs  map[string]error
	calls []string
	// block, when not nil, holds every lookup until it is closed; ignoreCtx makes a held lookup
	// ignore its context too (as Windows' reverse lookups do).
	block     chan struct{}
	ignoreCtx bool
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{names: map[string][]string{}, errs: map[string]error{}}
}

func (r *fakeResolver) set(addr string, names ...string) {
	r.mu.Lock()
	r.names[addr] = names
	r.mu.Unlock()
}

func (r *fakeResolver) fail(addr string, err error) {
	r.mu.Lock()
	r.errs[addr] = err
	r.mu.Unlock()
}

func (r *fakeResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	r.mu.Lock()
	r.calls = append(r.calls, addr)
	names, err, block, ignore := r.names[addr], r.errs[addr], r.block, r.ignoreCtx
	r.mu.Unlock()
	if block != nil {
		if ignore {
			<-block
		} else {
			select {
			case <-block:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
	if err != nil {
		return nil, err
	}
	if names == nil {
		return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
	}
	return names, nil
}

// count returns how many lookups were made (of addr, or of any address when addr is "").
func (r *fakeResolver) count(addr string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, c := range r.calls {
		if addr == "" || c == addr {
			n++
		}
	}
	return n
}

// bytesReader returns a reader of b.
func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

// containsAny says whether s contains one of subs.
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// captureHandler records the messages logged, for the tests that check what is logged.
type captureHandler struct {
	mu   sync.Mutex
	msgs []string
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	h.msgs = append(h.msgs, r.Message)
	h.mu.Unlock()
	return nil
}
func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

// count returns how many messages contain sub.
func (h *captureHandler) count(sub string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, m := range h.msgs {
		if strings.Contains(m, sub) {
			n++
		}
	}
	return n
}
