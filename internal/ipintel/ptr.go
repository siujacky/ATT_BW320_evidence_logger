package ipintel

import (
	"container/list"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"attmonitor/internal/model"
)

const (
	// ptrMaxEntries bounds the cache: far more addresses than a month of a household's
	// connections and scans show, in a few MB.
	ptrMaxEntries = 50_000
	// ptrQueueSize bounds the addresses waiting for a lookup; more are dropped (and asked for
	// again by a later PTR call).
	ptrQueueSize = 512
	// ptrWorkers look addresses up, one at a time each, within ptrLookupTimeout.
	ptrWorkers       = 3
	ptrLookupTimeout = 3 * time.Second
	// ptrMaxInFlight bounds the lookups running, those the workers gave up waiting for included.
	ptrMaxInFlight = 8
	// A name is kept for ptrTTLName, the answer that an address has none for ptrTTLNone; after a
	// lookup that failed (no answer in time), the address is tried again after ptrRetry.
	ptrTTLName = 7 * 24 * time.Hour
	ptrTTLNone = 24 * time.Hour
	ptrRetry   = time.Hour
	// ptrStale is how much longer an answer that has outlived its time to live (stale) is still
	// shown while it is looked up again - a lookup that fails keeps it - before it is forgotten. A
	// stale answer is never saved: ptr-cache.json holds only the current ones.
	ptrStale = 24 * time.Hour
	// ptrSaveEvery is the shortest time between two saves of the cache while Run goes on.
	ptrSaveEvery = 5 * time.Minute
	// maxPTRFileBytes bounds ptr-cache.json (a full cache takes about 4 MB).
	maxPTRFileBytes = 16 << 20
	// maxPTRName is the longest DNS name (RFC 1035).
	maxPTRName = 253
	ptrVersion = 1
)

// ptrCache is the reverse DNS cache - the names known, most recently used first, within a bound
// - and the queue of addresses to look up. Its addresses are public, without zone, IPv4 as IPv4.
type ptrCache struct {
	mu       sync.Mutex
	entries  map[netip.Addr]*list.Element // of *ptrEntry
	lru      *list.List                   // most recently used first
	max      int
	inflight map[netip.Addr]struct{} // queued or being looked up
	queue    chan netip.Addr
	slots    chan struct{} // one per lookup running (ptrMaxInFlight)
	dirty    bool          // the file as last saved differs from what would be saved now
	// keep is the longest an answer stays current (Options.KeepDays: the Network page's samples
	// are kept that long; zero: no limit but the time to live).
	keep time.Duration
}

// ptrEntry is what is known of an address.
type ptrEntry struct {
	addr  netip.Addr
	name  string    // its name; "" when it has none, or none is known yet
	at    time.Time // when name was learned (zero: never - only lookups that failed)
	due   time.Time // when to look it up again
	saved bool      // it is in the file as last saved
}

func newPTRCache(maxEntries, queueSize int) *ptrCache {
	return &ptrCache{
		entries:  make(map[netip.Addr]*list.Element),
		lru:      list.New(),
		max:      max(maxEntries, 1),
		inflight: make(map[netip.Addr]struct{}),
		queue:    make(chan netip.Addr, queueSize),
		slots:    make(chan struct{}, ptrMaxInFlight),
	}
}

// get returns a's name ("" when none is known) and whether a lookup is due: it is not cached, or
// its entry is older than its time to live.
func (c *ptrCache) get(a netip.Addr, now time.Time) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[a]
	if !ok {
		return "", true
	}
	c.lru.MoveToFront(el)
	e := el.Value.(*ptrEntry)
	return e.name, !now.Before(e.due)
}

// enqueue queues a for a lookup unless it is queued or being looked up already, or the queue is
// full.
func (c *ptrCache) enqueue(a netip.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.inflight[a]; ok {
		return
	}
	select {
	case c.queue <- a:
		c.inflight[a] = struct{}{}
	default: // full: a later PTR call asks again
	}
}

// learned notes the outcome of a's lookup: its name, or that it has none (answered), or that
// the lookup failed (what was known stays, and it is tried again after ptrRetry).
func (c *ptrCache) learned(a netip.Addr, name string, answered bool, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.inflight, a)
	e := c.entry(a)
	if !answered {
		e.due = now.Add(ptrRetry)
		return
	}
	e.name, e.at, e.due = name, now, now.Add(c.ttl(name))
	c.dirty = true
}

// forget drops a from the lookups in flight without learning anything (Run is stopping).
func (c *ptrCache) forget(a netip.Addr) {
	c.mu.Lock()
	delete(c.inflight, a)
	c.mu.Unlock()
}

// entry returns a's entry, made the most recently used; a new entry pushes the least recently
// used one out when the cache is full. Called with mu held.
func (c *ptrCache) entry(a netip.Addr) *ptrEntry {
	if el, ok := c.entries[a]; ok {
		c.lru.MoveToFront(el)
		return el.Value.(*ptrEntry)
	}
	e := &ptrEntry{addr: a}
	c.entries[a] = c.lru.PushFront(e)
	for len(c.entries) > c.max {
		old := c.lru.Remove(c.lru.Back()).(*ptrEntry)
		delete(c.entries, old.addr)
		if !old.at.IsZero() {
			c.dirty = true
		}
	}
	return e
}

func (c *ptrCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func (c *ptrCache) isDirty() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dirty
}

// ptrTTL is how long an answer holds.
func ptrTTL(name string) time.Duration {
	if name == "" {
		return ptrTTLNone
	}
	return ptrTTLName
}

// ttl is how long an answer is current: its time to live, at most keep. Called with mu held, or
// before the cache is shared.
func (c *ptrCache) ttl(name string) time.Duration {
	d := ptrTTL(name)
	if c.keep > 0 && c.keep < d {
		d = c.keep
	}
	return d
}

// current reports whether e holds an answer that is current at now (mu held).
func (c *ptrCache) current(e *ptrEntry, now time.Time) bool {
	return !e.at.IsZero() && now.Before(e.at.Add(c.ttl(e.name)))
}

// sweep forgets, at now, what is no longer to be kept: an answer stale for longer than ptrStale,
// and the retry time of a lookup that failed once it has passed (an address being looked up
// excepted). An answer in the file as last saved that is no longer current makes the cache dirty,
// so that the next save writes the file without it. It returns how many entries it forgot.
func (c *ptrCache) sweep(now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for el := c.lru.Back(); el != nil; {
		prev := el.Prev()
		e := el.Value.(*ptrEntry)
		if e.saved && !c.current(e, now) {
			c.dirty = true
		}
		end := e.due
		if !e.at.IsZero() {
			end = e.at.Add(c.ttl(e.name) + ptrStale)
		}
		if _, busy := c.inflight[e.addr]; !busy && !now.Before(end) {
			c.lru.Remove(el)
			delete(c.entries, e.addr)
			n++
		}
		el = prev
	}
	return n
}

// ptrFile is ptr-cache.json: the answers learned, most recently used first.
type ptrFile struct {
	Version int         `json:"version"`
	Entries []ptrRecord `json:"entries"`
}

type ptrRecord struct {
	Addr string    `json:"addr"`
	Name string    `json:"name,omitempty"` // "" when the address has no name
	At   time.Time `json:"at"`             // when it was learned
}

// snapshot returns the answers current at now, most recently used first, and clears dirty; false
// when nothing changed since the last snapshot. A stale answer - which may still be shown for a
// while, see sweep - is never saved.
func (c *ptrCache) snapshot(now time.Time) ([]ptrRecord, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.dirty {
		return nil, false
	}
	recs := make([]ptrRecord, 0, len(c.entries))
	for el := c.lru.Front(); el != nil; el = el.Next() {
		e := el.Value.(*ptrEntry)
		if e.saved = c.current(e, now); e.saved {
			recs = append(recs, ptrRecord{Addr: e.addr.String(), Name: e.name, At: e.at.UTC()})
		}
	}
	c.dirty = false
	return recs, true
}

// restore adds the saved answers that are still valid - for a public address, with a name that
// passes sanitizePTR, learned within its time to live (ttl) - behind the entries already there, up
// to the bound. It returns how many it added. When it left out a saved answer, the cache is dirty:
// the next save writes the file without it, even if nothing new is learned.
func (c *ptrCache) restore(recs []ptrRecord, now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, r := range recs {
		if len(c.entries) >= c.max {
			break
		}
		a, err := netip.ParseAddr(r.Addr)
		if err != nil {
			continue
		}
		if kind, la := classify(a); kind != model.IPKindPublic || la != a {
			continue
		}
		if r.Name != "" && sanitizePTR(r.Name) != r.Name {
			continue
		}
		due := r.At.Add(c.ttl(r.Name))
		if r.At.IsZero() || r.At.After(now.Add(ptrTTLNone)) || !now.Before(due) {
			continue // never learned, from the future, or expired
		}
		if _, ok := c.entries[a]; ok {
			continue
		}
		c.entries[a] = c.lru.PushBack(&ptrEntry{addr: a, name: r.Name, at: r.At, due: due, saved: true})
		n++
	}
	if n < len(recs) {
		c.dirty = true
	}
	return n
}

// loadPTR loads ptr-cache.json.
func (d *DB) loadPTR(now time.Time) {
	b, err := readSmall(filepath.Join(d.dir, namePTR), maxPTRFileBytes)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			d.log.Warn("ipintel: the reverse DNS cache is not readable; it starts empty", "err", err)
		}
		return
	}
	var pf ptrFile
	if err := json.Unmarshal(b, &pf); err != nil || pf.Version != ptrVersion {
		d.log.Warn("ipintel: the reverse DNS cache is not usable; it starts empty", "err", err, "version", pf.Version)
		return
	}
	n := d.ptr.restore(pf.Entries, now)
	d.log.Debug("ipintel: reverse DNS cache loaded", "entries", n, "saved", len(pf.Entries))
}

// savePTR writes ptr-cache.json when what it would hold changed since the last save: something
// learned, or an answer saved that is no longer current (sweep).
func (d *DB) savePTR() {
	now := d.now()
	d.ptr.sweep(now)
	recs, ok := d.ptr.snapshot(now)
	if !ok {
		return
	}
	b, err := json.Marshal(ptrFile{Version: ptrVersion, Entries: recs})
	if err == nil {
		err = writeFileAtomic(filepath.Join(d.dir, namePTR), b)
	}
	if err != nil {
		d.ptr.mu.Lock()
		d.ptr.dirty = true // try again at the next save
		d.ptr.mu.Unlock()
		if d.ptrSaveErr == nil {
			d.log.Warn("ipintel: cannot save the reverse DNS cache; trying again every few minutes", "err", err)
		}
		d.ptrSaveErr = err
		return
	}
	if d.ptrSaveErr != nil {
		d.log.Info("ipintel: the reverse DNS cache is saved again")
		d.ptrSaveErr = nil
	}
}

// removePTR deletes ptr-cache.json, when there is one, because no reverse DNS name is to be kept
// (why): reverse DNS is off (connections.reverse_dns), or the IP database is (geo.enabled). It
// reports whether the file is gone (false: it could not be deleted, which is logged).
func (d *DB) removePTR(why string) bool {
	if d.dir == "" {
		return true
	}
	path := filepath.Join(d.dir, namePTR)
	switch err := os.Remove(path); {
	case err == nil:
		d.log.Info("ipintel: deleted the reverse DNS cache", "file", path, "why", why)
	case !errors.Is(err, fs.ErrNotExist):
		d.log.Warn("ipintel: cannot delete the reverse DNS cache; trying again", "file", path, "err", err)
		return false
	}
	return true
}

// readSmall reads a file of at most limit bytes.
func readSmall(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("larger than expected")
	}
	return b, nil
}

// resolveLoop is a reverse DNS worker: it looks up the queued addresses until ctx ends.
func (d *DB) resolveLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case a := <-d.ptr.queue:
			if p := d.safely("reverse DNS", func() { d.resolve(ctx, a) }); p != "" {
				d.ptr.learned(a, "", false, d.now()) // tried again after ptrRetry, not at once
			}
		}
	}
}

// resolve looks a up and notes the answer: its first name that passes sanitizePTR, or that it
// has none (no name, or none usable), or that the lookup failed.
func (d *DB) resolve(ctx context.Context, a netip.Addr) {
	names, err := d.lookupAddr(ctx, a)
	if ctx.Err() != nil {
		d.ptr.forget(a)
		return
	}
	name := ""
	for _, n := range names {
		if s := sanitizePTR(n); s != "" {
			name = s
			break
		}
	}
	d.ptr.learned(a, name, name != "" || err == nil || isNotFound(err), d.now())
}

// lookupAddr runs one reverse lookup within d.ptrTimeout. The lookup runs in a goroutine of its
// own because a resolver may not honour the context - on Windows, net.DefaultResolver's reverse
// lookups wait for the system's DNS client - so the worker moves on at the deadline while
// ptrCache.slots bounds how many such lookups may still be running.
func (d *DB) lookupAddr(ctx context.Context, a netip.Addr) ([]string, error) {
	select {
	case d.ptr.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	lctx, cancel := context.WithTimeout(ctx, d.ptrTimeout)
	defer cancel()
	type result struct {
		names []string
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		defer func() { <-d.ptr.slots }()
		defer func() {
			// Outside every caller's recover: a panic here would stop the evidence logger.
			if p := recover(); p != nil {
				d.log.Error("ipintel: internal error in a reverse DNS lookup (recovered)", "panic", fmt.Sprint(p),
					"stack", string(debug.Stack()))
				ch <- result{err: fmt.Errorf("reverse DNS lookup: internal error: %v", p)}
			}
		}()
		names, err := d.resolver.LookupAddr(lctx, a.String())
		ch <- result{names, err}
	}()
	select {
	case r := <-ch:
		return r.names, r.err
	case <-lctx.Done():
		return nil, lctx.Err()
	}
}

// isNotFound says whether a lookup error means that the address has no name (NXDOMAIN).
func isNotFound(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}

// sanitizePTR returns a reverse DNS name fit to show, in lower case without the final dot, or ""
// when it is not one: empty, longer than 253 characters, with an empty label, or with anything
// but letters, digits, dots, hyphens and underscores. The names come from whoever controls the
// address's reverse zone, so they are untrusted.
func sanitizePTR(s string) string {
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > maxPTRName || s[0] == '.' || s[len(s)-1] == '.' || strings.Contains(s, "..") {
		return ""
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '-', c == '_':
		default:
			return ""
		}
	}
	return strings.ToLower(s)
}
