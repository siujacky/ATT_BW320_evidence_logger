package ipintel

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSanitizePTR(t *testing.T) {
	long := strings.Repeat("a.", 126) + "ab" // 254 characters
	for in, want := range map[string]string{
		"dns.google.":                     "dns.google",
		"dns.google":                      "dns.google",
		"One.One.One.One.":                "one.one.one.one",
		"ec2-198-51-100-1.compute-1.test": "ec2-198-51-100-1.compute-1.test",
		"_srv.example.test":               "_srv.example.test",
		"localhost":                       "localhost",
		long[2:]:                          long[2:], // 252: fits
		long:                              "",
		"":                                "",
		".":                               "",
		"..":                              "",
		".example.test":                   "",
		"a..example.test":                 "",
		"bad name.test":                   "",
		"bad\x00name.test":                "",
		"<script>.test":                   "",
		"bücher.test":                     "",
		"example.test..":                  "",
	} {
		if got := sanitizePTR(in); got != want {
			t.Errorf("sanitizePTR(%q) = %q, want %q", in, got, want)
		}
	}
}

// ptrDB opens a DB with reverse DNS through r and the clock clk.
func ptrDB(t *testing.T, dir string, r Resolver, clk *fakeClock) *DB {
	t.Helper()
	d := openTest(t, dir, Options{ReverseDNS: true, Resolver: r, Now: clk.Now})
	d.after = clk.After
	return d
}

// drain looks up the queued addresses as a worker would, in this goroutine.
func drain(d *DB) {
	for {
		select {
		case a := <-d.ptr.queue:
			d.resolve(context.Background(), a)
		default:
			return
		}
	}
}

func TestPTRInBackground(t *testing.T) {
	r := newFakeResolver()
	r.set("8.8.8.8", "dns.google.")
	r.set("2001:4860:4860::8888", "dns.google")
	clk := newFakeClock(t0)
	d := ptrDB(t, t.TempDir(), r, clk)
	startRun(t, d)
	g := mustAddr(t, "8.8.8.8")
	if got := d.PTR(g, true); got != "" {
		t.Fatalf("first PTR = %q", got)
	}
	waitFor(t, "8.8.8.8's name", func() bool { return d.PTR(g, false) == "dns.google" })
	// The same address, mapped: from the cache.
	if got := d.PTR(mustAddr(t, "::ffff:8.8.8.8"), true); got != "dns.google" || r.count("8.8.8.8") != 1 {
		t.Fatalf("mapped PTR = %q, %d lookups", got, r.count("8.8.8.8"))
	}
	g6 := mustAddr(t, "2001:4860:4860::8888")
	d.PTR(g6, true)
	waitFor(t, "the IPv6 name", func() bool { return d.PTR(g6, false) == "dns.google" })
	// No name (NXDOMAIN): remembered as such.
	one := mustAddr(t, "1.1.1.1")
	d.PTR(one, true)
	waitFor(t, "1.1.1.1's answer", func() bool { return d.ptr.size() == 3 })
	for range 3 {
		if got := d.PTR(one, true); got != "" {
			t.Fatalf("PTR(1.1.1.1) = %q", got)
		}
	}
	// Never looked up: without resolve, and every address that is not public.
	d.PTR(mustAddr(t, "9.9.9.9"), false)
	for _, s := range []string{"192.168.1.20", "10.0.0.1", "172.16.0.1", "100.64.0.1", "127.0.0.1", "169.254.1.1",
		"224.0.0.251", "192.0.2.1", "198.51.100.1", "203.0.113.1", "255.255.255.255", "0.0.0.0",
		"fe80::1", "fd00::1", "ff02::1", "::1", "2001:db8::1", "::ffff:192.168.1.20", "64:ff9b::a00:1"} {
		if got := d.PTR(mustAddr(t, s), true); got != "" {
			t.Fatalf("PTR(%s) = %q", s, got)
		}
	}
	if got := d.PTR(netip.Addr{}, true); got != "" {
		t.Fatalf("PTR(invalid) = %q", got)
	}
	// A last public lookup: once it is done, any lookup queued before it is done too.
	r.set("9.9.9.10", "dns10.quad9.net")
	d.PTR(mustAddr(t, "9.9.9.10"), true)
	waitFor(t, "9.9.9.10's name", func() bool { return d.PTR(mustAddr(t, "9.9.9.10"), false) != "" })
	if n := r.count(""); n != 4 {
		t.Fatalf("%d lookups, want 4: %v", n, r.calls)
	}
	if st := d.Status(); !st.ReverseDNS || st.PTRCached != 4 {
		t.Fatalf("status %+v", st)
	}
}

func TestPTRWithoutReverseDNS(t *testing.T) {
	r := newFakeResolver()
	clk := newFakeClock(t0)
	d := openTest(t, t.TempDir(), Options{Resolver: r, Now: clk.Now})
	g := mustAddr(t, "8.8.8.8")
	d.ptr.learned(g, "dns.google", true, t0)
	if got := d.PTR(g, true); got != "dns.google" {
		t.Fatalf("PTR = %q", got)
	}
	d.PTR(mustAddr(t, "1.1.1.1"), true)
	if len(d.ptr.queue) != 0 || d.Status().ReverseDNS {
		t.Fatal("queued without ReverseDNS")
	}
}

func TestPTRTimesToLive(t *testing.T) {
	r := newFakeResolver()
	r.set("8.8.8.8", "dns.google.")
	clk := newFakeClock(t0)
	d := ptrDB(t, t.TempDir(), r, clk)
	g, one, nine := mustAddr(t, "8.8.8.8"), mustAddr(t, "1.1.1.1"), mustAddr(t, "9.9.9.9")
	r.fail("9.9.9.9", &net.DNSError{Err: "i/o timeout", IsTimeout: true})
	for _, a := range []netip.Addr{g, one, nine} {
		d.PTR(a, true)
	}
	drain(d)
	if d.PTR(g, true) != "dns.google" || d.PTR(one, true) != "" || d.PTR(nine, true) != "" || len(d.ptr.queue) != 0 {
		t.Fatal("after the first lookups")
	}
	// The failed lookup is tried again after an hour; the other answers hold.
	clk.Advance(ptrRetry - time.Second)
	d.PTR(nine, true)
	if len(d.ptr.queue) != 0 {
		t.Fatal("retried within the hour")
	}
	clk.Advance(2 * time.Second)
	r.fail("9.9.9.9", nil)
	r.set("9.9.9.9", "dns9.quad9.net")
	d.PTR(nine, true)
	drain(d)
	if got := d.PTR(nine, false); got != "dns9.quad9.net" {
		t.Fatalf("after the retry: %q", got)
	}
	// "No name" holds a day.
	clk.Advance(ptrTTLNone - ptrRetry - 2*time.Second)
	d.PTR(one, true)
	if len(d.ptr.queue) != 0 {
		t.Fatal("no name renewed within a day")
	}
	clk.Advance(2 * time.Second)
	d.PTR(one, true)
	if len(d.ptr.queue) != 1 {
		t.Fatal("no name not renewed after a day")
	}
	drain(d)
	// A name holds a week; after it, the old name is still shown while the new one is looked up,
	// and kept when that lookup fails.
	clk.Advance(ptrTTLName - ptrTTLNone - 2*time.Second)
	d.PTR(g, true)
	if len(d.ptr.queue) != 0 {
		t.Fatal("name renewed within a week")
	}
	clk.Advance(2 * time.Second)
	r.fail("8.8.8.8", &net.DNSError{Err: "server misbehaving", IsTemporary: true})
	if got := d.PTR(g, true); got != "dns.google" || len(d.ptr.queue) != 1 {
		t.Fatalf("stale name %q, queue %d", got, len(d.ptr.queue))
	}
	drain(d)
	if got := d.PTR(g, true); got != "dns.google" || len(d.ptr.queue) != 0 {
		t.Fatalf("after a failed renewal: %q, queue %d", got, len(d.ptr.queue))
	}
	if n := r.count("8.8.8.8"); n != 2 {
		t.Fatalf("%d lookups of 8.8.8.8", n)
	}
}

func TestPTRNames(t *testing.T) {
	r := newFakeResolver()
	r.set("11.0.0.1", "bad name.", "ok.example.test.") // the first usable name
	r.set("11.0.0.2", "<b>.test", "also bad!")         // none usable: no name
	r.set("11.0.0.3", []string{}...)                   // an empty answer: no name
	d := ptrDB(t, t.TempDir(), r, newFakeClock(t0))
	want := map[string]string{"11.0.0.1": "ok.example.test", "11.0.0.2": "", "11.0.0.3": ""}
	for a := range want {
		d.PTR(mustAddr(t, a), true)
	}
	drain(d)
	for a, w := range want {
		if got := d.PTR(mustAddr(t, a), true); got != w {
			t.Errorf("PTR(%s) = %q, want %q", a, got, w)
		}
	}
	if len(d.ptr.queue) != 0 || d.ptr.size() != 3 {
		t.Fatalf("an answer without a usable name is asked again at once (queue %d)", len(d.ptr.queue))
	}
}

func TestPTRQueueBound(t *testing.T) {
	clk := newFakeClock(t0)
	d := ptrDB(t, t.TempDir(), newFakeResolver(), clk)
	addr := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{11, 0, byte(i >> 8), byte(i)}) }
	for i := range ptrQueueSize + 100 {
		d.PTR(addr(i), true)
	}
	if len(d.ptr.queue) != ptrQueueSize || len(d.ptr.inflight) != ptrQueueSize {
		t.Fatalf("queue %d, in flight %d", len(d.ptr.queue), len(d.ptr.inflight))
	}
	// Queued already: not twice. Dropped: not queued while the queue is full.
	d.PTR(addr(0), true)
	d.PTR(addr(ptrQueueSize+50), true)
	if len(d.ptr.queue) != ptrQueueSize || len(d.ptr.inflight) != ptrQueueSize {
		t.Fatalf("queue %d, in flight %d", len(d.ptr.queue), len(d.ptr.inflight))
	}
	// Once there is room, a dropped address is queued at its next PTR call.
	a0 := <-d.ptr.queue
	d.resolve(context.Background(), a0)
	d.PTR(addr(ptrQueueSize+50), true)
	if _, ok := d.ptr.inflight[addr(ptrQueueSize+50)]; !ok {
		t.Fatal("not queued once there was room")
	}
}

// TestPTRHungResolver checks that a resolver that ignores its context (as Windows' reverse
// lookups do) neither blocks the workers past the timeout nor makes the lookups pile up, nor
// keeps Run from returning.
func TestPTRHungResolver(t *testing.T) {
	r := newFakeResolver()
	r.block, r.ignoreCtx = make(chan struct{}), true
	defer close(r.block)
	clk := newFakeClock(t0)
	d := ptrDB(t, t.TempDir(), r, clk)
	d.ptrTimeout = 20 * time.Millisecond
	stop := startRun(t, d)
	for i := range 30 {
		d.PTR(netip.AddrFrom4([4]byte{11, 0, 0, byte(i)}), true)
	}
	waitFor(t, "every slot in use", func() bool { return r.count("") == ptrMaxInFlight })
	time.Sleep(100 * time.Millisecond)
	if n := r.count(""); n != ptrMaxInFlight {
		t.Fatalf("%d lookups running, at most %d expected", n, ptrMaxInFlight)
	}
	// The lookups given up are tried again in an hour.
	a := netip.AddrFrom4([4]byte{11, 0, 0, 0})
	if name, due := d.ptr.get(a, clk.Now()); name != "" || due {
		t.Fatalf("a lookup given up: %q, due %v", name, due)
	}
	begin := time.Now()
	stop()
	if took := time.Since(begin); took > 2*time.Second {
		t.Fatalf("Run took %v to return", took)
	}
}

func TestPTRCacheBound(t *testing.T) {
	c := newPTRCache(3, 10)
	a := func(i byte) netip.Addr { return netip.AddrFrom4([4]byte{11, 0, 0, i}) }
	for i := byte(1); i <= 3; i++ {
		c.learned(a(i), fmt.Sprintf("h%d.example.test", i), true, t0)
	}
	c.get(a(1), t0) // used: the least recently used is now a(2)
	c.learned(a(4), "h4.example.test", true, t0)
	if c.size() != 3 {
		t.Fatalf("size %d", c.size())
	}
	for i, want := range map[byte]bool{1: true, 2: false, 3: true, 4: true} {
		if _, ok := c.entries[a(i)]; ok != want {
			t.Errorf("entry %d present %v, want %v", i, ok, want)
		}
	}
	recs, ok := c.snapshot(t0)
	if !ok || len(recs) != 3 || recs[0].Addr != a(4).String() || recs[2].Addr != a(3).String() {
		t.Fatalf("snapshot %+v", recs)
	}
	if _, ok := c.snapshot(t0); ok {
		t.Fatal("a second snapshot without a change")
	}
}

func TestPTRPersistence(t *testing.T) {
	dir := t.TempDir()
	r := newFakeResolver()
	r.set("8.8.8.8", "dns.google")
	clk := newFakeClock(t0)
	d := ptrDB(t, dir, r, clk)
	stop := startRun(t, d)
	clk.next(t)
	d.PTR(mustAddr(t, "8.8.8.8"), true)
	d.PTR(mustAddr(t, "1.1.1.1"), true)
	waitFor(t, "the answers", func() bool { return d.ptr.size() == 2 })
	d.ptr.learned(mustAddr(t, "9.9.9.9"), "old.example.test", true, t0.Add(-8*24*time.Hour)) // expired
	stop()                                                                                   // saves

	clk2 := newFakeClock(t0.Add(time.Hour))
	r2 := newFakeResolver()
	d2 := ptrDB(t, dir, r2, clk2)
	d2.loadPTR(clk2.Now())
	if got := d2.PTR(mustAddr(t, "8.8.8.8"), true); got != "dns.google" {
		t.Fatalf("restored name %q", got)
	}
	d2.PTR(mustAddr(t, "1.1.1.1"), true)
	if len(d2.ptr.queue) != 0 || d2.ptr.size() != 2 {
		t.Fatalf("restored: queue %d, size %d", len(d2.ptr.queue), d2.ptr.size())
	}
	// After a day "no name" has expired, and is not restored.
	d3 := ptrDB(t, dir, r2, newFakeClock(t0.Add(25*time.Hour)))
	d3.loadPTR(t0.Add(25 * time.Hour))
	if d3.ptr.size() != 1 {
		t.Fatalf("restored a day later: %d entries", d3.ptr.size())
	}
}

func TestPTRRestoreRejects(t *testing.T) {
	dir := t.TempDir()
	at := t0.Add(-time.Hour)
	recs := []ptrRecord{
		{Addr: "8.8.8.8", Name: "dns.google", At: at},                  // kept
		{Addr: "192.168.1.20", Name: "printer.lan", At: at},            // not public
		{Addr: "::ffff:1.1.1.1", Name: "one.one", At: at},              // not in the cache's form
		{Addr: "fe80::1%eth0", Name: "x.test", At: at},                 // not public
		{Addr: "not an address", Name: "x.test", At: at},               // not an address
		{Addr: "9.9.9.9", Name: "Bad Name", At: at},                    // not a sanitized name
		{Addr: "9.9.9.10", Name: "x.test"},                             // never learned
		{Addr: "9.9.9.11", Name: "x.test", At: t0.Add(48 * time.Hour)}, // from the future
		{Addr: "8.8.8.8", Name: "dup.example.test", At: at},            // a second entry for an address
	}
	write := func(v any) {
		b, _ := json.Marshal(v)
		os.WriteFile(filepath.Join(dir, namePTR), b, 0o644)
	}
	write(ptrFile{Version: ptrVersion, Entries: recs})
	d := ptrDB(t, dir, newFakeResolver(), newFakeClock(t0))
	d.loadPTR(t0)
	if d.ptr.size() != 1 || d.PTR(mustAddr(t, "8.8.8.8"), false) != "dns.google" {
		t.Fatalf("restored %d entries", d.ptr.size())
	}
	for _, bad := range []any{ptrFile{Version: 99, Entries: recs}, "not an object"} {
		write(bad)
		d := ptrDB(t, dir, newFakeResolver(), newFakeClock(t0))
		d.loadPTR(t0)
		if d.ptr.size() != 0 {
			t.Fatalf("restored from %v", bad)
		}
	}
	os.WriteFile(filepath.Join(dir, namePTR), []byte("{"), 0o644)
	d = ptrDB(t, dir, newFakeResolver(), newFakeClock(t0))
	d.loadPTR(t0)
	if d.ptr.size() != 0 {
		t.Fatal("restored from broken JSON")
	}
}

// TestPTRSaveDebounced checks that Run saves the cache at most every ptrSaveEvery while it goes
// on, and at its end.
func TestPTRSaveDebounced(t *testing.T) {
	dir := t.TempDir()
	clk := newFakeClock(t0)
	d := ptrDB(t, dir, newFakeResolver(), clk)
	d.tick = time.Minute
	stop := startRun(t, d)
	w := clk.next(t)
	d.ptr.learned(mustAddr(t, "8.8.8.8"), "dns.google", true, clk.Now())
	path := filepath.Join(dir, namePTR)
	for i := 1; i < 5; i++ {
		clk.fire(w)
		w = clk.next(t)
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("saved after %d minutes", i)
		}
	}
	clk.fire(w)
	w = clk.next(t)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("not saved after 5 minutes: %v", err)
	}
	d.ptr.learned(mustAddr(t, "1.1.1.1"), "one.one.one.one", true, clk.Now())
	stop()
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "one.one.one.one") {
		t.Fatalf("not saved at the end of Run: %s", b)
	}
}

// TestPTRSaveFailure checks that a cache that cannot be saved is saved at a later attempt, and
// that the failure is logged once, not at every attempt.
func TestPTRSaveFailure(t *testing.T) {
	base := t.TempDir()
	blocker := filepath.Join(base, "blocker")
	os.WriteFile(blocker, []byte("a file where the directory should be"), 0o644)
	h := &captureHandler{}
	d := openTest(t, filepath.Join(blocker, "geo"), Options{ReverseDNS: true, Logger: slog.New(h)})
	d.ptr.learned(mustAddr(t, "8.8.8.8"), "dns.google", true, t0)
	d.savePTR()
	d.savePTR()
	if n := h.count("cannot save the reverse DNS cache"); n != 1 || !d.ptr.isDirty() {
		t.Fatalf("%d warnings, dirty %v", n, d.ptr.isDirty())
	}
	os.Remove(blocker)
	d.savePTR()
	if h.count("saved again") != 1 || d.ptr.isDirty() {
		t.Fatalf("not saved after the problem went away: %v", h.msgs)
	}
	if _, err := os.Stat(filepath.Join(blocker, "geo", namePTR)); err != nil {
		t.Fatal(err)
	}
}

// savedPTR returns the addresses in ptr-cache.json (nil when there is no file).
func savedPTR(t *testing.T, dir string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, namePTR))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var pf ptrFile
	if err := json.Unmarshal(b, &pf); err != nil {
		t.Fatal(err)
	}
	out := []string{}
	for _, r := range pf.Entries {
		out = append(out, r.Addr)
	}
	return out
}

// TestPTRCacheKeepsNoExpiredAnswer: an answer that has outlived its time to live is never saved:
// ptr-cache.json loses it at the next save - also when nothing new is learned, and when the file
// was written by an earlier run - and it is forgotten a day later.
func TestPTRCacheKeepsNoExpiredAnswer(t *testing.T) {
	dir := t.TempDir()
	clk := newFakeClock(t0)
	d := ptrDB(t, dir, newFakeResolver(), clk)
	a, b := mustAddr(t, "8.8.8.8"), mustAddr(t, "9.9.9.9")
	d.ptr.learned(a, "dns.google", true, clk.Now())
	d.savePTR()
	if got := savedPTR(t, dir); !reflect.DeepEqual(got, []string{"8.8.8.8"}) {
		t.Fatalf("saved %v", got)
	}
	// Seven and a half days later another name is learned: the file holds only it.
	clk.Advance(ptrTTLName + 12*time.Hour)
	d.ptr.learned(b, "dns9.quad9.net", true, clk.Now())
	d.savePTR()
	if got := savedPTR(t, dir); !reflect.DeepEqual(got, []string{"9.9.9.9"}) {
		t.Fatalf("saved %v seven and a half days later", got)
	}
	// The stale name is still shown while it is looked up again, for a day at most.
	if got := d.PTR(a, false); got != "dns.google" {
		t.Fatalf("stale name %q", got)
	}
	clk.Advance(12 * time.Hour)
	d.ptr.sweep(clk.Now())
	if got := d.PTR(a, false); got != "" || d.ptr.size() != 1 {
		t.Fatalf("a name stale for more than a day: %q, %d entries", got, d.ptr.size())
	}

	// Nothing learned: the expiry alone rewrites the file.
	clk.Advance(7 * 24 * time.Hour)
	d.savePTR()
	if got := savedPTR(t, dir); len(got) != 0 {
		t.Fatalf("saved %v after every answer expired", got)
	}
}

// TestPTRCacheFileFromAnEarlierRun: a file whose answers expired while the service was stopped is
// rewritten without them at the first save, even when nothing is learned.
func TestPTRCacheFileFromAnEarlierRun(t *testing.T) {
	dir := t.TempDir()
	write := func(recs ...ptrRecord) {
		b, _ := json.Marshal(ptrFile{Version: ptrVersion, Entries: recs})
		if err := os.WriteFile(filepath.Join(dir, namePTR), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(ptrRecord{Addr: "8.8.8.8", Name: "dns.google", At: t0.Add(-8 * 24 * time.Hour)},
		ptrRecord{Addr: "9.9.9.9", Name: "dns9.quad9.net", At: t0.Add(-time.Hour)})
	clk := newFakeClock(t0)
	d := ptrDB(t, dir, newFakeResolver(), clk)
	stop := startRun(t, d)
	clk.next(t)
	stop() // saves
	if got := savedPTR(t, dir); !reflect.DeepEqual(got, []string{"9.9.9.9"}) {
		t.Fatalf("saved %v", got)
	}
}

// TestPTRCacheWithoutReverseDNS: with reverse DNS off no name is kept: the cache saved by an earlier
// run is deleted, not loaded; so it is with the IP database off.
func TestPTRCacheWithoutReverseDNS(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		dir := t.TempDir()
		b, _ := json.Marshal(ptrFile{Version: ptrVersion, Entries: []ptrRecord{{Addr: "8.8.8.8", Name: "dns.google", At: t0}}})
		if err := os.WriteFile(filepath.Join(dir, namePTR), b, 0o644); err != nil {
			t.Fatal(err)
		}
		d := openTest(t, dir, Options{ReverseDNS: false, Now: newFakeClock(t0).Now})
		if !enabled {
			var err error
			if d, err = Open(dir, Options{Enabled: false}); err != nil {
				t.Fatal(err)
			}
		}
		stop := startRun(t, d)
		stop() // the file is deleted at the start, before Run waits
		if got := savedPTR(t, dir); got != nil {
			t.Fatalf("enabled %v: the cache file is still there: %v", enabled, got)
		}
		if d.PTR(mustAddr(t, "8.8.8.8"), false) != "" {
			t.Fatalf("enabled %v: a name of the deleted cache is shown", enabled)
		}
	}
}

// TestPTRCacheKeepDays: with connections.keep_days shorter than an answer's time to live, the
// answer is current - and saved - only that long.
func TestPTRCacheKeepDays(t *testing.T) {
	dir := t.TempDir()
	clk := newFakeClock(t0)
	d := openTest(t, dir, Options{ReverseDNS: true, Resolver: newFakeResolver(), Now: clk.Now, KeepDays: 1})
	a := mustAddr(t, "8.8.8.8")
	d.ptr.learned(a, "dns.google", true, clk.Now())
	clk.Advance(23 * time.Hour)
	if _, due := d.ptr.get(a, clk.Now()); due {
		t.Fatal("due within the day")
	}
	clk.Advance(time.Hour)
	if _, due := d.ptr.get(a, clk.Now()); !due {
		t.Fatal("not due after a day")
	}
	d.savePTR()
	if got := savedPTR(t, dir); len(got) != 0 {
		t.Fatalf("saved %v after keep_days", got)
	}
}
