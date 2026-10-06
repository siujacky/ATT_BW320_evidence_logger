package connstore

import (
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"
)

// cacheStats returns the summaries found in the cache and computed, and the days read raw.
func cacheStats(h *harness) (hits, misses, raw int64) {
	return h.s.stats.sumHits.Load(), h.s.stats.sumMisses.Load(), h.s.stats.rawDays.Load()
}

func TestWholePastDaysComeFromTheCache(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{})
	fillDays(h, 0, 3, 20) // the clock ends at day 3, noon
	h.reopen()            // an empty cache

	a := h.agg(day0, at(3, 12, 0))
	if hits, misses, raw := cacheStats(h); hits != 0 || misses != 3 || raw != 1 {
		t.Errorf("first query: %d hits, %d misses, %d days raw; want 0, 3 (days 0-2), 1 (today)", hits, misses, raw)
	}
	b := h.agg(day0, at(3, 12, 0))
	if hits, misses, raw := cacheStats(h); hits != 3 || misses != 3 || raw != 2 {
		t.Errorf("second query: %d hits, %d misses, %d days raw", hits, misses, raw)
	}
	if !reflect.DeepEqual(a, b) {
		t.Errorf("the cached result differs:\n%+v\n%+v", a, b)
	}
	// A period that covers days in part reads them raw, and does not cache them.
	h.agg(at(0, 6, 0), at(2, 6, 0))
	if hits, misses, raw := cacheStats(h); hits != 4 || misses != 3 || raw != 4 {
		t.Errorf("partly covered days: %d hits, %d misses, %d days raw; want day 1 cached, days 0 and 2 raw", hits, misses, raw)
	}
	if n, _ := h.s.sums.size(); n != 3 {
		t.Errorf("the cache holds %d days, want 3", n)
	}
}

func TestCacheFollowsALateReadOfACachedDay(t *testing.T) {
	h := newHarness(t, at(2, 0, 30), Options{})
	h.devices(at(0, 9, 0), device(10, 1, "test-laptop", ""))
	h.nat(at(0, 10, 0), tcp(10, 1, "203.0.113.5", 443))
	h.nat(at(1, 10, 0), tcp(10, 1, "203.0.113.5", 443))
	h.nat(at(2, 0, 20), tcp(10, 1, "203.0.113.5", 443)) // day 1 is compressed
	before := h.agg(at(1, 0, 0), at(2, 0, 0))
	if before.Samples != 1 {
		t.Fatalf("day 1 = %+v", before)
	}
	// The clock goes back: a read of day 1, next to its compressed file.
	h.clk.Set(at(1, 23, 58))
	h.nat(at(1, 23, 58), tcp(10, 2, "198.51.100.7", 443))
	h.clk.Set(at(2, 0, 35)) // day 1 is a past day again: its summary is the cache's
	_, misses, _ := cacheStats(h)
	after := h.agg(at(1, 0, 0), at(2, 0, 0))
	if after.Samples != 2 || len(after.Flows) != 2 {
		t.Errorf("day 1 after a late read = %+v", after)
	}
	if _, m, _ := cacheStats(h); m != misses+1 {
		t.Errorf("day 1 was not summarized again (%d misses, %d before)", m, misses)
	}
	// Merged by the next read of day 2: the same, counted once.
	h.clk.Set(at(2, 0, 40))
	h.nat(at(2, 0, 40), tcp(10, 3, "203.0.113.5", 443))
	if merged := h.agg(at(1, 0, 0), at(2, 0, 0)); !reflect.DeepEqual(merged, after) {
		t.Errorf("day 1 after the merge = %+v\nwant %+v", merged, after)
	}
}

func TestCacheFollowsTheDeviceListReadsThatNameADay(t *testing.T) {
	h := newHarness(t, at(2, 12, 0), Options{})
	h.devices(at(0, 22, 0), device(10, 1, "test-laptop", ""))
	h.nat(at(1, 10, 0), tcp(10, 1, "203.0.113.5", 443))
	h.devices(at(2, 9, 0), device(10, 1, "test-laptop", "")) // compresses day 1
	if keys := deviceKeys(h.agg(at(1, 0, 0), at(2, 0, 0))); !reflect.DeepEqual(keys, []string{macKey(1)}) {
		t.Fatalf("day 1 devices = %v", keys)
	}
	// A Device List read of day 1 stored late (the clock went back): 192.168.1.10 was another
	// device by then.
	h.clk.Set(at(1, 9, 30))
	h.devices(at(1, 9, 30), device(10, 2, "test-tablet", ""))
	h.clk.Set(at(2, 12, 0)) // day 1 is a past day again: its summary is the cache's
	if keys := deviceKeys(h.agg(at(1, 0, 0), at(2, 0, 0))); !reflect.DeepEqual(keys, []string{macKey(2)}) {
		t.Errorf("day 1 devices after the late Device List read = %v, want the tablet", keys)
	}
}

func TestCacheFollowsTheFirstDeviceListRead(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{})
	h.nat(at(0, 10, 0), tcp(10, 1, "203.0.113.5", 443))
	h.clk.Set(at(1, 12, 0))
	h.nat(at(1, 10, 0), tcp(10, 1, "203.0.113.5", 443))
	if keys := deviceKeys(h.agg(day0, at(1, 0, 0))); !reflect.DeepEqual(keys, []string{"ip:" + lanIP(10)}) {
		t.Fatalf("before any Device List read: %v", keys)
	}
	// The first Device List read, a day later, names the reads before it.
	h.devices(at(1, 11, 0), device(10, 1, "test-laptop", ""))
	if keys := deviceKeys(h.agg(day0, at(1, 0, 0))); !reflect.DeepEqual(keys, []string{macKey(1)}) {
		t.Errorf("after the first Device List read: %v", keys)
	}
}

func TestCacheFollowsAPrunedDeviceListDay(t *testing.T) {
	h := newHarness(t, at(3, 12, 0), Options{KeepDays: 30})
	h.devices(at(0, 22, 0), device(10, 1, "test-laptop", ""))
	h.nat(at(0, 23, 0), tcp(10, 1, "203.0.113.5", 443))
	h.nat(at(1, 8, 0), tcp(10, 1, "203.0.113.5", 443))
	h.devices(at(1, 9, 0), device(10, 2, "test-tablet", ""))
	h.nat(at(3, 8, 0), tcp(10, 1, "203.0.113.5", 443))
	if a := h.agg(at(1, 0, 0), at(2, 0, 0)); findDevice(t, a, macKey(1)).Samples != 1 {
		t.Fatalf("day 1 = %+v", a.Devices)
	}
	// Day 0 goes: the read of day 1 at 08:00 is now named after the first read after it. (The
	// age limit applies once the store has been open for an hour.)
	h.s.SetRetention(2, DefaultKeepMB)
	h.clk.Set(at(3, 13, 0))
	if err := h.s.Prune(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if keys := deviceKeys(h.agg(at(1, 0, 0), at(2, 0, 0))); !reflect.DeepEqual(keys, []string{macKey(2)}) {
		t.Errorf("day 1 after day 0 was pruned: %v", keys)
	}
}

// testKey is a dayCache key for the tests: a day and a version of it.
type testKey struct {
	d day
	v int
}

func (k testKey) keyDay() day { return k.d }

func TestDayCache(t *testing.T) {
	c := newDayCache[testKey, string](3, 10)
	days := func() []int {
		var ds []int
		for k := range c.m {
			ds = append(ds, int(k.d))
		}
		slices.Sort(ds)
		return ds
	}
	put := func(d, v int, w int64) bool { return c.put(testKey{day(d), v}, fmt.Sprint(d, "/", v), w) }
	for _, d := range []int{5, 2, 7} {
		if !put(d, 0, 1) {
			t.Errorf("day %d was not stored in a cache with room for it", d)
		}
	}
	// Full (3 entries): a later day evicts the oldest, whatever the order they were used in.
	c.get(testKey{2, 0})
	if !put(9, 0, 1) || !reflect.DeepEqual(days(), []int{5, 7, 9}) {
		t.Errorf("after adding day 9: %v, want day 2 evicted", days())
	}
	if _, ok := c.get(testKey{2, 0}); ok {
		t.Error("an evicted entry was found")
	}
	// A day older than every entry is not stored, and nothing is evicted for it.
	if put(1, 0, 1) || !reflect.DeepEqual(days(), []int{5, 7, 9}) {
		t.Errorf("after offering day 1: %v, want it refused", days())
	}
	// A day between the others evicts the older ones only.
	if !put(6, 0, 1) || !reflect.DeepEqual(days(), []int{6, 7, 9}) {
		t.Errorf("after adding day 6: %v, want day 5 evicted", days())
	}
	// The weight bound: day 8 weighing 8 makes 11 of 10; evicting day 6, the oldest, is enough.
	if !put(8, 0, 8) || !reflect.DeepEqual(days(), []int{7, 8, 9}) {
		t.Errorf("after a heavy day 8: %v, want day 6 evicted", days())
	}
	if n, w := c.size(); n != 3 || w != 10 {
		t.Errorf("%d entries weighing %d, want 3 weighing 10", n, w)
	}
	// Another version of day 7, weighing 2, would need day 8 or 9 to go as well: refused, and
	// nothing is evicted for it.
	if put(7, 1, 2) || !reflect.DeepEqual(days(), []int{7, 8, 9}) {
		t.Errorf("after offering a heavy day 7: %v, want it refused", days())
	}
	if put(10, 0, 11) {
		t.Error("an entry heavier than the whole cache was stored")
	}
	if n, w := c.size(); n != 3 || w != 10 {
		t.Errorf("after the refusals: %d entries weighing %d, want 3 weighing 10", n, w)
	}
	// Another version of day 9 evicts the oldest day.
	if !put(9, 1, 1) || !reflect.DeepEqual(days(), []int{8, 9, 9}) {
		t.Errorf("after a second version of day 9: %v, want day 7 evicted", days())
	}
	// The same key replaces its value and weight.
	if !put(9, 1, 1) {
		t.Error("an entry replacing itself was refused")
	}
	if v, ok := c.get(testKey{9, 1}); !ok || v != "9/1" {
		t.Errorf("replaced entry = %q, %v", v, ok)
	}
	if n, w := c.size(); n != 3 || w != 10 {
		t.Errorf("after replacing: %d entries weighing %d, want 3 weighing 10", n, w)
	}
	c.removeIf(func(k testKey) bool { return k.d == 9 })
	if n, w := c.size(); n != 1 || w != 8 || !reflect.DeepEqual(days(), []int{8}) {
		t.Errorf("after removeIf: %v weighing %d (%d entries)", days(), w, n)
	}
}
