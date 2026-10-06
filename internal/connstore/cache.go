package connstore

import (
	"cmp"
	"slices"
	"sync"
)

// dayKey is the key of what a dayCache keeps about the files of one day.
type dayKey interface {
	comparable
	keyDay() day
}

// dayCache caches what is computed from the files of a day, bounded by its number of entries and
// by their total weight (each entry's weight is given when it is put). It is safe for concurrent
// use. The values must not be changed once put: concurrent readers share them.
//
// It keeps the newest days. When an entry does not fit, the entries of the oldest days are
// evicted to make room - never one of a later day than the new entry's: then the new entry is
// not stored, and nothing is evicted. The Network page's periods end now, so their newest days
// are the ones every view needs; and a period with more days than fit keeps reusing the days the
// cache holds, query after query. (A cache that evicted the least recently used entry would miss
// every day of such a period: each query reads the days in the same order, so each day it
// computes would evict the one the next query needs first. Nor does a query of old days evict
// the newest to make room for its own.)
type dayCache[K dayKey, V any] struct {
	mu        sync.Mutex
	maxLen    int
	maxWeight int64
	weight    int64
	m         map[K]cacheEntry[V]
}

// cacheEntry is a value of a dayCache with its weight.
type cacheEntry[V any] struct {
	v V
	w int64
}

// newDayCache returns a cache of at most maxLen entries weighing at most maxWeight together.
func newDayCache[K dayKey, V any](maxLen int, maxWeight int64) *dayCache[K, V] {
	return &dayCache[K, V]{maxLen: maxLen, maxWeight: maxWeight, m: map[K]cacheEntry[V]{}}
}

// get returns the value of k.
func (c *dayCache[K, V]) get(k K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[k]
	return e.v, ok
}

// put stores v under k with weight w, replacing what k held, and reports whether it did. When the
// bounds leave no room for it, the entries of the oldest days are evicted first, then those of
// later days up to k's own; when even evicting all of them would not make room, v is not stored
// and nothing is evicted. An entry heavier than the whole cache may hold is not stored either.
func (c *dayCache[K, V]) put(k K, v V, w int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.m[k]; ok {
		delete(c.m, k)
		c.weight -= e.w
	}
	if w > c.maxWeight || c.maxLen < 1 {
		return false
	}
	n, weight := len(c.m)+1, c.weight+w
	if n > c.maxLen || weight > c.maxWeight {
		// The entries that may go to make room: those of the days up to k's, the oldest first.
		d := k.keyDay()
		var older []K
		var freeable int64
		for key, e := range c.m {
			if key.keyDay() <= d {
				older = append(older, key)
				freeable += e.w
			}
		}
		if n-len(older) > c.maxLen || weight-freeable > c.maxWeight {
			return false
		}
		slices.SortFunc(older, func(a, b K) int { return cmp.Compare(a.keyDay(), b.keyDay()) })
		for _, key := range older {
			if n <= c.maxLen && weight <= c.maxWeight {
				break
			}
			e := c.m[key]
			delete(c.m, key)
			c.weight -= e.w
			n, weight = n-1, weight-e.w
		}
	}
	c.m[k] = cacheEntry[V]{v: v, w: w}
	c.weight += w
	return true
}

// removeIf removes every entry whose key matches.
func (c *dayCache[K, V]) removeIf(match func(K) bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.m {
		if match(k) {
			delete(c.m, k)
			c.weight -= e.w
		}
	}
}

// size returns the number of entries and their total weight.
func (c *dayCache[K, V]) size() (int, int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m), c.weight
}
