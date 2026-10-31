package connstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// The LAN scans (docs/dhcp-table.md §6): a third kind of file, scan-YYYY-MM-DD.jsonl, kept with the
// NAT table and Device List reads and by the same rules.

// lanScan returns a sweep of 192.168.1.0/24 begun at t in which the LAN addresses hosts answered,
// each with the MAC address macOf of its number (this PC is 192.168.1.71).
func lanScan(t time.Time, hosts ...int) model.LANScan {
	s := model.LANScan{At: rfc(t), TookMs: 8200, Subnet: "192.168.1.0/24", Self: lanIP(71), Asked: 254, Hosts: []model.LANHost{}}
	for _, n := range hosts {
		s.Hosts = append(s.Hosts, model.LANHost{IP: lanIP(n), MAC: macOf(n)})
	}
	return s
}

// scan appends a LAN scan begun at t.
func (h *harness) scan(t time.Time, hosts ...int) {
	h.t.Helper()
	if err := h.s.AppendScan(t, lanScan(t, hosts...)); err != nil {
		h.t.Fatalf("AppendScan(%s): %v", t, err)
	}
}

// eachScan returns the scans EachScan passes on for [from, to), each as its time and its first
// host's number ("-" when none answered).
func eachScan(t *testing.T, s *Store, from, to time.Time) []string {
	t.Helper()
	var got []string
	err := s.EachScan(context.Background(), from, to, func(sc model.LANScan) error {
		first := "-"
		if len(sc.Hosts) > 0 {
			first = sc.Hosts[0].IP
		}
		got = append(got, sc.At+" "+first)
		return nil
	})
	if err != nil {
		t.Fatalf("EachScan(%s, %s): %v", rfc(from), rfc(to), err)
	}
	return got
}

// scanEntry is how eachScan lists the scan begun at tm whose first host is LAN address n.
func scanEntry(tm time.Time, n int) string { return rfc(tm) + " " + lanIP(n) }

func TestScanLineRoundTrip(t *testing.T) {
	tm := at(0, 8, 0).Add(123456789)
	in := lanScan(at(0, 7, 0), 10, 64) // its At is replaced by the line's time
	in.Problem = "the sweep was stopped after 2m0s"
	line, err := encodeScan(tm, in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(line), `{"t":"2026-10-05T08:00:00.123456789Z","at":"2026-10-05T08:00:00.123456789Z",`) || !strings.HasSuffix(string(line), "}\n") {
		t.Fatalf("line %s", line)
	}
	if pt, ok := peekTime(line[:len(line)-1]); !ok || !pt.Equal(tm) {
		t.Errorf("peekTime = %s, %v", pt, ok)
	}
	got, out, err := decodeScan(line[:len(line)-1])
	want := in
	want.At = rfc(tm)
	if err != nil || !got.Equal(tm) || !reflect.DeepEqual(out, want) {
		t.Errorf("decodeScan = %s, %+v, %v\nwant %+v", got, out, err, want)
	}
	// No host: an empty list, both ways.
	line, _ = encodeScan(tm, model.LANScan{Subnet: "192.168.1.0/24"})
	if !strings.Contains(string(line), `"hosts":[]`) {
		t.Errorf("line without hosts: %s", line)
	}
	if _, out, err := decodeScan([]byte(`{"t":"2026-10-05T08:00:00Z","subnet":"192.168.1.0/24"}`)); err != nil || out.Hosts == nil || out.At != "2026-10-05T08:00:00Z" {
		t.Errorf("a line without hosts decodes to %+v, %v", out, err)
	}
	for _, bad := range []string{``, `{`, `null`, `{"subnet":"192.168.1.0/24"}`, `{"t":"yesterday"}`, `{"t":"1999-12-31T00:00:00Z"}`, `{"t":"2026-10-05T08:00:00Z","hosts":{}}`} {
		if _, _, err := decodeScan([]byte(bad)); err == nil {
			t.Errorf("decodeScan(%q) accepted", bad)
		}
	}
}

func TestScanFileNames(t *testing.T) {
	d := dayOf(at(1, 13, 45))
	for _, gz := range []bool{false, true} {
		name := fileName(kindScan, d, gz)
		want := "scan-2026-10-06.jsonl"
		if gz {
			want += gzExt
		}
		if name != want {
			t.Errorf("fileName = %q, want %q", name, want)
		}
		if p, ok := parseFileName(name); !ok || p.kind != kindScan || p.day != d || p.gz != gz || p.tmp {
			t.Errorf("parseFileName(%q) = %+v, %v", name, p, ok)
		}
	}
	if p, ok := parseFileName("scan-2026-10-06.jsonl.gz.tmp"); !ok || p.kind != kindScan || !p.tmp {
		t.Errorf("the temporary copy: %+v, %v", p, ok)
	}
	for _, name := range []string{"scan-2026-10-06.json", "scans-2026-10-06.jsonl", "scan-2026-10-6.jsonl", "SCAN-2026-10-06.jsonl", "lanscan-2026-10-06.jsonl"} {
		if p, ok := parseFileName(name); ok {
			t.Errorf("parseFileName(%q) = %+v, want not one of the store's names", name, p)
		}
	}
	if kindScan.String() != "scan" || kindNAT.String() != "nat" || kindDevices.String() != "devices" {
		t.Errorf("kinds named %q, %q, %q", kindNAT, kindDevices, kindScan)
	}
}

// TestScansRoundTrip: the scans are appended to the file of their own UTC day, compressed with the
// other kinds once the day is over, and passed on by EachScan for [from, to) - oldest first, across
// plain and compressed days, after a restart too; LastScan is the newest, and Usage counts them.
func TestScansRoundTrip(t *testing.T) {
	h := newHarness(t, at(0, 10, 0), Options{})
	if sc, ok := h.s.LastScan(); ok || sc.Hosts != nil {
		t.Fatalf("LastScan of an empty store = %+v, %v", sc, ok)
	}
	if got := eachScan(t, h.s, time.Time{}, time.Time{}); len(got) != 0 {
		t.Fatalf("an empty store passed on %q", got)
	}
	times := []time.Time{at(0, 10, 0), at(0, 11, 0), at(1, 10, 0), at(2, 9, 0), at(2, 10, 0)}
	for i, tm := range times {
		h.clk.Set(tm)
		h.scan(tm, 10+i, 64)
	}
	h.nat(at(2, 10, 0), tcp(10, 1, "203.0.113.5", 443))
	for _, name := range []string{"scan-2026-10-05.jsonl.gz", "scan-2026-10-06.jsonl.gz", "scan-2026-10-07.jsonl"} {
		if !h.exists(name) {
			t.Errorf("%s does not exist", name)
		}
	}
	if h.exists("scan-2026-10-05.jsonl") || h.exists("scan-2026-10-06.jsonl") {
		t.Error("a past day's scans were not compressed")
	}
	all := []string{scanEntry(times[0], 10), scanEntry(times[1], 11), scanEntry(times[2], 12), scanEntry(times[3], 13), scanEntry(times[4], 14)}
	check := func(when string) {
		t.Helper()
		for _, c := range []struct {
			name     string
			from, to time.Time
			want     []string
		}{
			{"everything", time.Time{}, time.Time{}, all},
			{"from at a scan, to at a scan", times[1], times[3], all[1:3]},
			{"a day", at(1, 0, 0), at(2, 0, 0), all[2:3]},
			{"to before the first", at(-1, 0, 0), times[0], nil},
			{"from after the last", times[4].Add(time.Nanosecond), time.Time{}, nil},
			{"from the zero time", time.Time{}, at(0, 10, 30), all[:1]},
		} {
			if got := eachScan(t, h.s, c.from, c.to); !slices.Equal(got, c.want) {
				t.Errorf("%s, %s: %q, want %q", when, c.name, got, c.want)
			}
		}
		sc, ok := h.s.LastScan()
		if want := lanScan(times[4], 14, 64); !ok || !reflect.DeepEqual(sc, want) {
			t.Errorf("%s: LastScan = %+v, %v\nwant %+v", when, sc, ok, want)
		}
	}
	check("as written")
	u := h.s.Usage()
	var bytes int64
	files := 0
	for _, name := range dayNames(t, h.dir) {
		st, err := os.Stat(h.file(name))
		if err != nil {
			t.Fatal(err)
		}
		bytes += st.Size()
		files++
	}
	if u.Files != files || files != 4 || u.Bytes != bytes || u.Oldest != rfc(times[0]) || u.Newest != rfc(times[4]) || u.Error != "" {
		t.Errorf("Usage = %+v, want %d bytes in %d files", u, bytes, files)
	}
	h.reopen()
	check("after a restart")
	if u2 := h.s.Usage(); u2 != u {
		t.Errorf("Usage after a restart = %+v, want %+v", u2, u)
	}
	// The caller's scans are its own.
	sc, _ := h.s.LastScan()
	sc.Hosts[0].IP = "changed by the caller"
	if again, _ := h.s.LastScan(); again.Hosts[0].IP != lanIP(14) {
		t.Error("LastScan returned the store's own hosts")
	}
	if err := h.s.EachScan(context.Background(), time.Time{}, time.Time{}, func(sc model.LANScan) error {
		sc.Hosts[0].IP = "changed"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	check("after fn changed its scans")
}

// TestEachScanEnds: fn's ErrStop ends EachScan without an error, any other error of fn ends it
// with that error, and so does ctx's end.
func TestEachScanEnds(t *testing.T) {
	h := newHarness(t, at(1, 12, 0), Options{})
	for i := range 4 {
		h.scan(at(0, 10+i, 0), 10+i)
	}
	h.scan(at(1, 10, 0), 20)
	n := 0
	if err := h.s.EachScan(context.Background(), time.Time{}, time.Time{}, func(model.LANScan) error {
		if n++; n == 2 {
			return contracts.ErrStop
		}
		return nil
	}); err != nil || n != 2 {
		t.Errorf("ErrStop: %v after %d scans, want nil after 2", err, n)
	}
	stop := errors.New("stop")
	n = 0
	if err := h.s.EachScan(context.Background(), time.Time{}, time.Time{}, func(model.LANScan) error {
		if n++; n == 3 {
			return fmt.Errorf("fn: %w", stop)
		}
		return nil
	}); !errors.Is(err, stop) || n != 3 {
		t.Errorf("fn's error: %v after %d scans", err, n)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := h.s.EachScan(ctx, time.Time{}, time.Time{}, func(model.LANScan) error {
		t.Error("fn called after ctx ended")
		return nil
	}); !errors.Is(err, context.Canceled) {
		t.Errorf("ended ctx: %v", err)
	}
	// ctx ends during the scans: no scan after it.
	ctx, cancel = context.WithCancel(context.Background())
	n = 0
	err := h.s.EachScan(ctx, time.Time{}, time.Time{}, func(model.LANScan) error {
		if n++; n == 4 {
			cancel() // the fourth is the first day's last: the next day is not read
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) || n != 4 {
		t.Errorf("ctx ended during the scans: %v after %d", err, n)
	}
}

// TestLastScanKeepsTheNewest: of scans stored out of order the newest by its time stays the newest;
// one dated after the clock (made while it was ahead) gives way to the next one stored; Open loads
// the newest of the days up to today - a later day's only when no day up to today has one - and
// passes over a damaged line.
func TestLastScanKeepsTheNewest(t *testing.T) {
	h := newHarness(t, at(1, 12, 0), Options{})
	h.scan(at(1, 10, 0), 10)
	h.scan(at(1, 9, 0), 11) // stored later, made earlier
	if sc, _ := h.s.LastScan(); sc.At != rfc(at(1, 10, 0)) {
		t.Errorf("LastScan = %s, want the scan of 10:00", sc.At)
	}
	h.scan(at(3, 10, 0), 12) // the clock was ahead
	if sc, _ := h.s.LastScan(); sc.At != rfc(at(3, 10, 0)) {
		t.Errorf("LastScan = %s, want the scan dated day 3", sc.At)
	}
	h.scan(at(1, 11, 0), 13) // the clock corrected: the next scan stored wins
	if sc, _ := h.s.LastScan(); sc.At != rfc(at(1, 11, 0)) {
		t.Errorf("LastScan = %s, want the scan of 11:00 after the one dated after the clock", sc.At)
	}
	h.reopen()
	if sc, _ := h.s.LastScan(); sc.At != rfc(at(1, 11, 0)) || sc.Hosts[0].IP != lanIP(13) {
		t.Errorf("LastScan after reopening = %+v, want today's newest (the later day's is passed over)", sc)
	}

	// Today's newest line damaged: the one before it; all of today's: yesterday's newest.
	h2 := newHarness(t, at(1, 12, 0), Options{})
	h2.scan(at(0, 10, 0), 9)
	h2.scan(at(1, 10, 0), 10) // compresses yesterday
	h2.scan(at(1, 11, 0), 11)
	damage := func(n int) {
		t.Helper()
		if err := h2.s.Close(); err != nil {
			t.Fatal(err)
		}
		lines := h2.lines("scan-2026-10-06.jsonl")
		if len(lines) != 2 {
			t.Fatalf("today's file holds %d scans, want 2", len(lines))
		}
		for i := 2 - n; i < 2; i++ {
			lines[i] = `{"t":"` + strings.Split(lines[i], `"`)[3] + `","hosts":{}}` // its time, and hosts that are not a list
		}
		if err := os.WriteFile(h2.file("scan-2026-10-06.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		h2.open()
	}
	damage(1)
	if sc, _ := h2.s.LastScan(); sc.At != rfc(at(1, 10, 0)) {
		t.Errorf("LastScan with the newest line damaged = %s, want 10:00", sc.At)
	}
	if h2.log.count("lines that cannot be read were skipped") != 1 {
		t.Errorf("the damaged line was not logged once:\n%s", h2.log.all())
	}
	damage(2)
	if sc, _ := h2.s.LastScan(); sc.At != rfc(at(0, 10, 0)) {
		t.Errorf("LastScan with today's lines damaged = %s, want yesterday's", sc.At)
	}

	// Only a later day has a scan: that one.
	h3 := newHarness(t, at(1, 12, 0), Options{})
	h3.scan(at(3, 10, 0), 12)
	h3.reopen()
	if sc, ok := h3.s.LastScan(); !ok || sc.At != rfc(at(3, 10, 0)) {
		t.Errorf("LastScan with only a later day = %+v, %v", sc, ok)
	}
}

// TestScansFollowTheRetention: the scans' days are deleted with the other kinds' - by keep_days, and
// by keep_mb, which counts their files too - and LastScan forgets a scan whose day is gone.
func TestScansFollowTheRetention(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{KeepDays: 2})
	for d := range 6 {
		h.clk.Set(at(d, 12, 0))
		h.scan(at(d, 12, 0), 10+d)
		h.nat(at(d, 12, 0), tcp(10, 1, "203.0.113.5", 443))
	}
	want := []string{
		"nat-2026-10-08.jsonl.gz", "nat-2026-10-09.jsonl.gz", "nat-2026-10-10.jsonl",
		"scan-2026-10-08.jsonl.gz", "scan-2026-10-09.jsonl.gz", "scan-2026-10-10.jsonl",
	}
	if got := dayNames(t, h.dir); !slices.Equal(got, want) {
		t.Errorf("files = %v\nwant %v", got, want)
	}
	if got := eachScan(t, h.s, time.Time{}, time.Time{}); !slices.Equal(got, []string{scanEntry(at(3, 12, 0), 13), scanEntry(at(4, 12, 0), 14), scanEntry(at(5, 12, 0), 15)}) {
		t.Errorf("scans kept: %q", got)
	}
	// The size limit counts the scans' files: a limit that holds days 4 and 5 deletes day 3.
	var size int64
	for d := 4; d <= 5; d++ {
		for k := range numKinds {
			f, _ := h.s.entry(k, dayOf(at(d, 0, 0)))
			size += max(f.gz, 0) + max(f.plain, 0)
		}
	}
	h.s.mu.Lock()
	h.s.mib = 1 // KeepMB counts bytes from here on
	h.s.mu.Unlock()
	h.s.SetRetention(config.MaxConnKeepDays, int(size)+1)
	if err := h.s.Prune(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if h.exists("scan-2026-10-08.jsonl.gz") || !h.exists("scan-2026-10-09.jsonl.gz") {
		t.Errorf("after the size limit: %v", dayNames(t, h.dir))
	}
	if u := h.s.Usage(); u.Bytes != size || u.Oldest != rfc(at(4, 12, 0)) {
		t.Errorf("Usage = %+v, want %d bytes from day 4", u, size)
	}

	// Scans that stopped long ago: once their day is deleted, LastScan has none.
	h2 := newHarness(t, at(0, 12, 0), Options{KeepDays: 1})
	h2.scan(at(0, 12, 0), 10)
	h2.clk.Set(at(5, 12, 0))
	h2.nat(at(5, 12, 0), tcp(10, 1, "203.0.113.5", 443))
	if err := h2.s.Prune(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if h2.exists("scan-2026-10-05.jsonl.gz") || h2.exists("scan-2026-10-05.jsonl") {
		t.Fatalf("the old scan day was not deleted: %v", dayNames(t, h2.dir))
	}
	if sc, ok := h2.s.LastScan(); ok {
		t.Errorf("LastScan after its day was deleted = %+v", sc)
	}
	if got := eachScan(t, h2.s, time.Time{}, time.Time{}); len(got) != 0 {
		t.Errorf("scans after their day was deleted: %q", got)
	}
}

// TestScanDamageAndRepair: a scan line that cannot be decoded is skipped (logged once per file), so
// is a line of another day; Open cuts off a line a crash cut short and deletes an interrupted
// compressed copy, and the next append continues the file.
func TestScanDamageAndRepair(t *testing.T) {
	h := newHarness(t, at(0, 23, 0), Options{})
	h.scan(at(0, 10, 0), 10)
	h.scan(at(0, 11, 0), 11)
	if err := h.s.Close(); err != nil {
		t.Fatal(err)
	}
	name := "scan-2026-10-05.jsonl"
	other, err := encodeScan(at(2, 1, 0), lanScan(at(2, 1, 0), 30))
	if err != nil {
		t.Fatal(err)
	}
	appendFile(t, h.file(name), append([]byte("{not json\n"), other...))
	complete := h.content(name)
	half, _ := encodeScan(at(0, 12, 0), lanScan(at(0, 12, 0), 12))
	appendFile(t, h.file(name), half[:len(half)/2])
	if err := os.WriteFile(h.file("scan-2026-10-04.jsonl.gz.tmp"), []byte("half a gzip"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.open()
	if got := h.content(name); string(got) != string(complete) {
		t.Errorf("after Open the file holds %d bytes, want its %d of complete lines", len(got), len(complete))
	}
	if h.exists("scan-2026-10-04.jsonl.gz.tmp") {
		t.Error("the interrupted compressed copy is still there")
	}
	for range 2 {
		if got := eachScan(t, h.s, time.Time{}, time.Time{}); !slices.Equal(got, []string{scanEntry(at(0, 10, 0), 10), scanEntry(at(0, 11, 0), 11)}) {
			t.Errorf("around the damage: %q", got)
		}
	}
	for _, msg := range []string{"lines that cannot be read were skipped", "reads of another day were skipped", "cut off the incomplete last line"} {
		if n := h.log.count(msg); n != 1 {
			t.Errorf("%q logged %d times, want once:\n%s", msg, n, h.log.all())
		}
	}
	h.scan(at(0, 12, 0), 12)
	if got := eachScan(t, h.s, at(0, 11, 30), time.Time{}); !slices.Equal(got, []string{scanEntry(at(0, 12, 0), 12)}) {
		t.Errorf("after one more scan: %q", got)
	}
}

// TestScansLeaveTheOtherKindsAlone: the same NAT table and Device List reads give the same results -
// Aggregate, EachDevices, Devices - whether or not LAN scans are stored among them, across days.
func TestScansLeaveTheOtherKindsAlone(t *testing.T) {
	fill := func(withScans bool) *harness {
		h := newHarness(t, at(0, 9, 0), Options{})
		for d := range 3 {
			for hour := 9; hour < 18; hour += 2 {
				tm := at(d, hour, 0)
				h.clk.Set(tm)
				h.devices(tm, device(10+d, 1, "test-laptop", "Wi-Fi 5 GHz"), device(20, 2, "test-phone", "Wi-Fi 2.4 GHz"))
				if withScans {
					h.scan(tm.Add(time.Minute), 10+d, 20, 64)
				}
				h.nat(tm.Add(2*time.Minute), tcp(10+d, 40000+hour, remoteOf(hour), 443), udp(20, 50000, "192.0.2.53", 53))
			}
		}
		return h
	}
	plain, mixed := fill(false), fill(true)
	for _, q := range []contracts.ConnQuery{{}, {From: at(1, 0, 0), To: at(2, 0, 0)}, {From: at(0, 12, 0), To: at(2, 12, 0), Device: macKey(1)}} {
		a, err := plain.s.Aggregate(context.Background(), q)
		if err != nil {
			t.Fatal(err)
		}
		b, err := mixed.s.Aggregate(context.Background(), q)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(a, b) {
			t.Errorf("Aggregate(%+v) with scans:\n%+v\nwant\n%+v", q, b, a)
		}
	}
	if a, b := eachDevices(t, plain.s, at(0, 12, 0), at(2, 12, 0)), eachDevices(t, mixed.s, at(0, 12, 0), at(2, 12, 0)); !slices.Equal(a, b) {
		t.Errorf("EachDevices with scans %q, want %q", b, a)
	}
	da, ta := plain.s.Devices()
	db, tb := mixed.s.Devices()
	if !reflect.DeepEqual(da, db) || !ta.Equal(tb) {
		t.Errorf("Devices with scans %+v at %s, want %+v at %s", db, tb, da, ta)
	}
	if got := eachScan(t, mixed.s, time.Time{}, time.Time{}); len(got) != 15 {
		t.Errorf("%d scans, want 15", len(got))
	}
	// Each kind's files hold only its own lines.
	for _, name := range dayNames(t, mixed.dir) {
		for _, line := range mixed.lines(name) {
			isScan := strings.Contains(line, `"subnet":`)
			if strings.HasPrefix(name, "scan-") != isScan {
				t.Errorf("%s holds %s", name, line)
			}
		}
	}
}

// TestAppendScanRefusals: a time outside the store's years is refused, the zero time is now, and a
// closed store refuses scans (reading goes on).
func TestAppendScanRefusals(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{})
	for _, bad := range []time.Time{time.Date(1999, 12, 31, 23, 0, 0, 0, time.UTC), time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if err := h.s.AppendScan(bad, lanScan(bad, 10)); err == nil || !strings.Contains(err.Error(), "years 2000-2199") {
			t.Errorf("AppendScan(%s): %v", bad, err)
		}
	}
	if err := h.s.AppendScan(time.Time{}, model.LANScan{Subnet: "192.168.1.0/24"}); err != nil {
		t.Fatal(err)
	}
	if sc, ok := h.s.LastScan(); !ok || sc.At != rfc(at(0, 12, 0)) || sc.Hosts == nil || len(sc.Hosts) != 0 {
		t.Errorf("the scan at the zero time: %+v, %v", sc, ok)
	}
	if err := h.s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := h.s.AppendScan(at(0, 13, 0), lanScan(at(0, 13, 0), 10)); !errors.Is(err, ErrClosed) {
		t.Errorf("AppendScan after Close: %v", err)
	}
	if got := eachScan(t, h.s, time.Time{}, time.Time{}); len(got) != 1 {
		t.Errorf("EachScan after Close: %q", got)
	}
}

// TestConcurrentScanWriterAndReaders appends scans and NAT reads with the days rolling over (and
// being compressed and pruned) while readers ask EachScan and LastScan all the time. Run with -race:
// no reader may fail or see a scan out of order or outside its period.
func TestConcurrentScanWriterAndReaders(t *testing.T) {
	h := newHarness(t, at(0, 0, 0), Options{KeepDays: 2})
	const appends = 120 // every 2 hours: 10 days
	var (
		mu       sync.Mutex
		problems []string
		reads    int
	)
	problem := func(format string, args ...any) {
		mu.Lock()
		problems = append(problems, fmt.Sprintf(format, args...))
		mu.Unlock()
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range appends {
			tm := at(0, 0, 0).Add(time.Duration(i) * 2 * time.Hour)
			h.clk.Set(tm)
			if err := h.s.AppendScan(tm, lanScan(tm, 10+i%50, 100)); err != nil {
				problem("AppendScan: %v", err)
			}
			if err := h.s.AppendNAT(tm, model.NATTable{Sessions: []model.NATSession{tcp(10, 1, "203.0.113.5", 443)}}); err != nil {
				problem("AppendNAT: %v", err)
			}
			if i%12 == 11 {
				if err := h.s.Prune(time.Time{}); err != nil {
					problem("Prune: %v", err)
				}
			}
		}
	}()
	var wg sync.WaitGroup
	for r := range 4 {
		wg.Go(func() {
			for n := 0; ; n++ {
				select {
				case <-done:
					return
				default:
				}
				now := h.clk.Now()
				from, to := time.Time{}, time.Time{}
				if (n+r)%2 == 0 {
					from, to = now.Add(-30*time.Hour), now
				}
				var last time.Time
				err := h.s.EachScan(context.Background(), from, to, func(sc model.LANScan) error {
					at, err := time.Parse(time.RFC3339Nano, sc.At)
					if err != nil || at.Before(last) || at.Before(from) || (!to.IsZero() && !at.Before(to)) || len(sc.Hosts) != 2 || sc.Subnet != "192.168.1.0/24" {
						problem("scan %+v after %s in [%s, %s)", sc, last, from, to)
					}
					last = at
					return nil
				})
				if err != nil {
					problem("EachScan: %v", err)
				}
				if sc, ok := h.s.LastScan(); ok && len(sc.Hosts) != 2 {
					problem("LastScan = %+v", sc)
				}
				mu.Lock()
				reads++
				mu.Unlock()
			}
		})
	}
	<-done
	wg.Wait()
	for i, p := range problems {
		if i == 20 {
			t.Errorf("... %d more", len(problems)-20)
			break
		}
		t.Error(p)
	}
	if reads < 20 {
		t.Errorf("only %d reads ran while the writer did", reads)
	}
	for _, msg := range []string{"cannot be read", "could not", "failed"} {
		if n := h.log.count(msg); n > 0 {
			t.Errorf("%d log records %q:\n%s", n, msg, h.log.all())
		}
	}
	// The last append was at day 9, 22:00: with 2 days kept, days 7 to 9 are left, 12 scans each.
	got := eachScan(t, h.s, time.Time{}, time.Time{})
	h.reopen()
	if again := eachScan(t, h.s, time.Time{}, time.Time{}); len(got) != 36 || !slices.Equal(again, got) || !strings.HasPrefix(got[0], rfc(at(7, 0, 0))) {
		t.Errorf("kept %d scans from %q; after reopening %d", len(got), got[0], len(again))
	}
	if sc, ok := h.s.LastScan(); !ok || sc.At != rfc(at(9, 22, 0)) {
		t.Errorf("LastScan = %+v, %v", sc, ok)
	}
}

// FuzzDecodeScan: decoding never panics, and a scan line it accepts is kept as it decoded: encoded
// again, it decodes to the same scan and time, whose At is that time.
func FuzzDecodeScan(f *testing.F) {
	line, err := encodeScan(at(0, 9, 0), lanScan(at(0, 9, 0), 10, 64))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(line[:len(line)-1])
	f.Add([]byte(`{"t":"2026-10-05T09:00:00Z","at":"2020-01-01T00:00:00Z","hosts":null,"asked":-1}`))
	f.Add([]byte(`{"t":"2026-10-05T09:00:00Z","hosts":[{"ip":"x","mac":""},{}],"problem":"‮"}`))
	f.Fuzz(func(t *testing.T, line []byte) {
		tm, sc, err := decodeScan(line)
		if err != nil {
			return
		}
		if !validTime(tm) || sc.At != formatTime(tm) || sc.Hosts == nil {
			t.Fatalf("decoded %v: %+v", tm, sc)
		}
		again, err := encodeScan(tm, sc)
		if err != nil {
			if errors.Is(err, errLineTooLong) {
				return
			}
			t.Fatalf("encoding the decoded scan again: %v", err)
		}
		tm2, sc2, err := decodeScan(again[:len(again)-1])
		if err != nil || !tm2.Equal(tm) || !reflect.DeepEqual(sc2, sc) {
			t.Fatalf("round trip: %v %+v %v\nwant %v %+v", tm2, sc2, err, tm, sc)
		}
	})
}
