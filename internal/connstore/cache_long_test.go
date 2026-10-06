package connstore

import (
	"reflect"
	"testing"
)

// TestALongPeriodReusesTheCachedDays queries a period with more whole past days than the cache
// of day summaries holds, again and again: each query must reuse the days the cache holds - the
// newest - and read only the others. A cache that evicted the least recently used day would miss
// every day of every query: the days are read in the same order each time, and each day computed
// would evict the one the next query needs first.
func TestALongPeriodReusesTheCachedDays(t *testing.T) {
	const days, fit = 12, 8
	h := newHarness(t, at(0, 12, 0), Options{})
	fillDays(h, 0, days, 20) // whole past days 0 to 11; today (day 12) until noon
	period := func() (hits, misses int64) {
		t.Helper()
		h0, m0, _ := cacheStats(h)
		h.agg(day0, at(days, 12, 0))
		h1, m1, _ := cacheStats(h)
		return h1 - h0, m1 - m0
	}
	want := h.agg(day0, at(days, 12, 0)) // the cache holds every day
	n, w := h.s.sums.size()
	if n != days || w%days != 0 {
		t.Fatalf("the cache holds %d days weighing %d, want %d days of the same weight", n, w, days)
	}
	perDay := w / days

	// A cache with room for 8 of the 12 days.
	h.s.sums = newDayCache[sumKey, *sumEntry](summaryDays, fit*perDay)
	if hits, misses := period(); hits != 0 || misses != days {
		t.Errorf("first query: %d hits, %d misses; want 0, %d", hits, misses, days)
	}
	for i := range 3 {
		if hits, misses := period(); hits != fit || misses != days-fit {
			t.Errorf("query %d: %d hits, %d misses; want %d, %d", i+2, hits, misses, fit, days-fit)
		}
	}
	if got := h.agg(day0, at(days, 12, 0)); !reflect.DeepEqual(got, want) {
		t.Errorf("the result differs from the one with every day cached:\n%+v\nwant\n%+v", got, want)
	}
	// The days kept are the newest: a week's view finds all of its whole days.
	if hits, misses := func() (int64, int64) {
		h0, m0, _ := cacheStats(h)
		h.agg(at(days-7, 12, 0), at(days, 12, 0))
		h1, m1, _ := cacheStats(h)
		return h1 - h0, m1 - m0
	}(); hits != 6 || misses != 0 {
		t.Errorf("a week: %d hits, %d misses; want 6 (days 6 to 11), 0", hits, misses)
	}
	// A query of the oldest days does not evict the newest to make room for its own.
	h.agg(day0, at(4, 0, 0))
	if hits, misses := period(); hits != fit || misses != days-fit {
		t.Errorf("after a query of the oldest days: %d hits, %d misses; want %d, %d", hits, misses, fit, days-fit)
	}
}
