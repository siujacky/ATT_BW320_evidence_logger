package connstore

import (
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/model"
)

// fillDays appends one NAT read (n sessions) and one Device List read at noon of each day from
// first to last, moving the clock along (the appends compress the days that are over).
func fillDays(h *harness, first, last, n int) {
	h.t.Helper()
	for d := first; d <= last; d++ {
		h.clk.Set(at(d, 12, 0))
		h.devices(at(d, 12, 0), device(10, 1, "test-laptop", ""))
		var sessions []model.NATSession
		for i := range n {
			sessions = append(sessions, tcp(10, 40000+i, remoteOf(i), 443))
		}
		h.nat(at(d, 12, 0), sessions...)
	}
}

// remoteOf returns a documentation address for i.
func remoteOf(i int) string {
	nets := [...]string{"192.0.2.", "198.51.100.", "203.0.113."}
	return nets[i%3] + strconv.Itoa(i/3%254+1)
}

// dayNames returns the files of the store's days, as the directory lists them.
func dayNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if _, ok := parseFileName(e.Name()); ok {
			names = append(names, e.Name())
		}
	}
	return names
}

func TestPruneByDays(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{KeepDays: 2})
	fillDays(h, 0, 5, 3)
	// The appends pruned as they went: at day 5 noon, the days that ended at least two days
	// before (days 0 to 2) are gone.
	want := []string{
		"devices-2026-10-08.jsonl.gz", "devices-2026-10-09.jsonl.gz", "devices-2026-10-10.jsonl",
		"nat-2026-10-08.jsonl.gz", "nat-2026-10-09.jsonl.gz", "nat-2026-10-10.jsonl",
	}
	if got := dayNames(t, h.dir); !slices.Equal(got, want) {
		t.Errorf("files = %v\nwant %v", got, want)
	}
	if u := h.s.Usage(); u.Oldest != rfc(at(3, 12, 0)) || u.Newest != rfc(at(5, 12, 0)) || u.Files != 6 || u.Error != "" {
		t.Errorf("Usage = %+v", u)
	}
	if a := h.agg(day0, at(6, 0, 0)); a.Samples != 3 || a.First != rfc(at(3, 12, 0)) {
		t.Errorf("aggregate = %+v", a)
	}
	// Day 3 ended at day 4 00:00: kept until two days later.
	if err := h.s.Prune(at(5, 23, 59)); err != nil {
		t.Fatal(err)
	}
	if !h.exists("nat-2026-10-08.jsonl.gz") {
		t.Error("day 3 was deleted before it was two days old")
	}
	if err := h.s.Prune(at(6, 0, 0)); err != nil {
		t.Fatal(err)
	}
	if h.exists("nat-2026-10-08.jsonl.gz") || h.exists("devices-2026-10-08.jsonl.gz") {
		t.Error("day 3 was not deleted once two days old")
	}
	if h.log.count("deleted a day beyond the retention limits") != 4 || h.log.attr("deleted a day", "limit") != "keep_days 2" {
		t.Errorf("deletions logged:\n%s", h.log.all())
	}
}

func TestPruneBySize(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{KeepDays: config.MaxConnKeepDays})
	fillDays(h, 0, 4, 40)
	size := map[int]int64{}
	for d := range 5 {
		for _, k := range []kind{kindNAT, kindDevices} {
			f, _ := h.s.entry(k, dayOf(at(d, 0, 0)))
			size[d] += max(f.gz, 0) + max(f.plain, 0)
		}
	}
	h.s.mu.Lock()
	h.s.mib = 1 // KeepMB counts bytes from here on
	h.s.mu.Unlock()
	h.s.SetRetention(config.MaxConnKeepDays, int(size[2]+size[3]+size[4]))
	if err := h.s.Prune(time.Time{}); err != nil {
		t.Fatal(err)
	}
	for d, kept := range []bool{false, false, true, true, true} {
		if got := h.exists(fileName(kindNAT, dayOf(at(d, 0, 0)), d < 4)); got != kept {
			t.Errorf("day %d kept = %v, want %v", d, got, kept)
		}
	}
	if u := h.s.Usage(); u.Bytes != size[2]+size[3]+size[4] || u.Oldest != rfc(at(2, 12, 0)) {
		t.Errorf("Usage = %+v", u)
	}
	if h.log.attr("deleted a day", "limit") != "keep_mb "+strconv.Itoa(int(size[2]+size[3]+size[4])) {
		t.Errorf("deletions logged:\n%s", h.log.all())
	}
	// Today is never deleted, even when it alone exceeds the limit.
	h.s.SetRetention(config.MaxConnKeepDays, 1)
	if err := h.s.Prune(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if got, want := dayNames(t, h.dir), []string{"devices-2026-10-09.jsonl", "nat-2026-10-09.jsonl"}; !slices.Equal(got, want) {
		t.Errorf("files = %v, want %v", got, want)
	}
	if a := h.agg(time.Time{}, time.Time{}); a.Samples != 1 {
		t.Errorf("aggregate after pruning = %+v", a)
	}
}

func TestAppendsPruneAtMostHourly(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{KeepDays: 1})
	lastPrune := func() time.Time {
		h.s.mu.Lock()
		defer h.s.mu.Unlock()
		return h.s.lastPrune
	}
	if !lastPrune().Equal(at(0, 12, 0)) {
		t.Fatalf("Open did not prune: %s", lastPrune())
	}
	h.nat(at(0, 12, 0), tcp(10, 1, "203.0.113.5", 443))
	h.clk.Set(at(2, 12, 0))
	h.nat(at(2, 12, 0), tcp(10, 1, "203.0.113.5", 443))
	if !lastPrune().Equal(at(2, 12, 0)) || h.exists("nat-2026-10-05.jsonl.gz") {
		t.Errorf("an append two days later did not prune day 0 (last prune %s)", lastPrune())
	}
	h.clk.Set(at(2, 12, 59))
	h.nat(at(2, 12, 59), tcp(10, 1, "203.0.113.5", 443))
	if !lastPrune().Equal(at(2, 12, 0)) {
		t.Errorf("an append within the hour pruned again (%s)", lastPrune())
	}
	h.clk.Set(at(2, 13, 0))
	h.devices(at(2, 13, 0))
	if !lastPrune().Equal(at(2, 13, 0)) {
		t.Errorf("an append an hour later did not prune (%s)", lastPrune())
	}
	// New limits: the next append applies them.
	h.s.SetRetention(5, 100)
	h.clk.Set(at(2, 13, 1))
	h.nat(at(2, 13, 1), tcp(10, 1, "203.0.113.5", 443))
	if !lastPrune().Equal(at(2, 13, 1)) {
		t.Errorf("the append after SetRetention did not prune (%s)", lastPrune())
	}
	// A clock set back by more than an hour prunes too.
	h.clk.Set(at(2, 10, 0))
	h.nat(at(2, 10, 0), tcp(10, 1, "203.0.113.5", 443))
	if !lastPrune().Equal(at(2, 10, 0)) {
		t.Errorf("the append after the clock went back did not prune (%s)", lastPrune())
	}
}

func TestPruneDeletesTheDayBeingWrittenWhenItIsOld(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{KeepDays: 30})
	h.nat(at(0, 12, 0), tcp(10, 1, "203.0.113.5", 443))
	// 40 days later, without a read: the day the writer has open is old.
	h.clk.Set(at(40, 0, 0))
	if err := h.s.Prune(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if h.exists("nat-2026-10-05.jsonl") {
		t.Fatal("the old day was not deleted")
	}
	h.nat(at(0, 12, 5), tcp(10, 2, "203.0.113.5", 443))
	if lines := h.lines("nat-2026-10-05.jsonl"); len(lines) != 1 {
		t.Errorf("the day written again holds %d reads, want 1", len(lines))
	}
}

func TestRetentionLimits(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{})
	if u := h.s.Usage(); u.KeepDays != DefaultKeepDays || u.KeepMB != DefaultKeepMB {
		t.Errorf("defaults = %+v", u)
	}
	for _, c := range []struct{ days, mb, wantDays, wantMB int }{
		{0, 0, 1, 1},
		{-5, -5, 1, 1},
		{7, 50, 7, 50},
		{config.MaxConnKeepDays + 1, config.MaxConnKeepMB + 1, config.MaxConnKeepDays, config.MaxConnKeepMB},
	} {
		h.s.SetRetention(c.days, c.mb)
		if u := h.s.Usage(); u.KeepDays != c.wantDays || u.KeepMB != c.wantMB {
			t.Errorf("SetRetention(%d, %d): %d days, %d MB", c.days, c.mb, u.KeepDays, u.KeepMB)
		}
	}
	h2 := newHarness(t, at(0, 12, 0), Options{KeepDays: 9, KeepMB: 12})
	if u := h2.s.Usage(); u.KeepDays != 9 || u.KeepMB != 12 {
		t.Errorf("Options = %+v", u)
	}
}
