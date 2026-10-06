package netmap

import (
	"container/list"
	"sync"

	"attmonitor/internal/model"
)

// chunkCache keeps the summaries of whole sealed syslog chunks by name: a sealed chunk never
// changes, so it is read once. It holds at most maxEntries summaries taking at most maxBytes (by
// estimate), dropping the least recently used first - but never one that the running request
// needs: when only those are left, a new summary is not kept (the request reads that chunk
// again next time, instead of every chunk of a period longer than the cache holds). A summary
// is also dropped once the store no longer lists its chunk.
type chunkCache struct {
	maxBytes   int64 // < 1: nothing is kept
	maxEntries int

	mu     sync.Mutex
	lru    list.List // of *cacheEntry, the most recently used first
	byName map[string]*list.Element
	bytes  int64
	gen    uint64 // the running request; an entry it needs carries it
}

// cacheEntry is a kept summary: its chunk's name and SHA-256, its estimated size and the
// request that used it last.
type cacheEntry struct {
	name, sha string
	agg       *chunkAgg
	size      int64
	gen       uint64
}

func newChunkCache(maxBytes int64, maxEntries int) *chunkCache {
	if maxEntries < 1 {
		maxBytes = 0
	}
	return &chunkCache{maxBytes: maxBytes, maxEntries: maxEntries, byName: map[string]*list.Element{}}
}

// begin starts a request: it drops the summaries of chunks that are not listed (or listed with
// another SHA-256).
func (c *chunkCache) begin(listed []model.SyslogChunkRef) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gen++
	if c.lru.Len() == 0 {
		return
	}
	sha := make(map[string]string, len(listed))
	for _, r := range listed {
		sha[r.Name] = r.SHA256
	}
	for e := c.lru.Front(); e != nil; {
		next := e.Next()
		ce := e.Value.(*cacheEntry)
		if s, ok := sha[ce.name]; !ok || s != ce.sha {
			c.remove(e)
		}
		e = next
	}
}

// need marks the summaries the running request will use, so that no new one displaces them.
func (c *chunkCache) need(name, sha string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.byName[name]; e != nil && e.Value.(*cacheEntry).sha == sha {
		e.Value.(*cacheEntry).gen = c.gen
	}
}

// peek returns a summary without counting it as used (nil when not kept).
func (c *chunkCache) peek(name, sha string) *chunkAgg {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.byName[name]; e != nil && e.Value.(*cacheEntry).sha == sha {
		return e.Value.(*cacheEntry).agg
	}
	return nil
}

// get returns a summary, counting it as used by the running request (nil when not kept).
func (c *chunkCache) get(name, sha string) *chunkAgg {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.byName[name]
	if e == nil || e.Value.(*cacheEntry).sha != sha {
		return nil
	}
	ce := e.Value.(*cacheEntry)
	ce.gen = c.gen
	c.lru.MoveToFront(e)
	return ce.agg
}

// put keeps the summary of a chunk if it fits without displacing a summary the running request
// needs, and reports whether it was kept.
func (c *chunkCache) put(name, sha string, agg *chunkAgg) bool {
	size := agg.size()
	c.mu.Lock()
	defer c.mu.Unlock()
	if size > c.maxBytes {
		return false
	}
	if e := c.byName[name]; e != nil {
		c.remove(e)
	}
	for c.lru.Len() > 0 && (c.lru.Len() >= c.maxEntries || c.bytes+size > c.maxBytes) {
		back := c.lru.Back()
		if back.Value.(*cacheEntry).gen == c.gen {
			return false // the rest is needed by this request
		}
		c.remove(back)
	}
	c.byName[name] = c.lru.PushFront(&cacheEntry{name: name, sha: sha, agg: agg, size: size, gen: c.gen})
	c.bytes += size
	return true
}

// remove drops an entry (c.mu held).
func (c *chunkCache) remove(e *list.Element) {
	ce := c.lru.Remove(e).(*cacheEntry)
	delete(c.byName, ce.name)
	c.bytes -= ce.size
}

// stats reports the summaries kept and their estimated size.
func (c *chunkCache) stats() (entries int, bytes int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len(), c.bytes
}
