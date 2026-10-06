package syslogstore

import (
	"compress/gzip"
	"container/heap"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// ctxEvery is how many lines Query reads between two checks of its context.
const ctxEvery = 4096

// endOfTime is the end of a query without one: after any receive time RFC 3339 can state.
var endOfTime = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)

// Query returns the messages received in [from, to) for which match returns true (nil: all),
// newest first, at most limit (limit must be at least 1), and whether more matched. A zero to
// has no end. Newest first is by receive time; messages received at the same time come in
// reverse order of their storing. Entry.Chunk names the sealed chunk that holds a message ("" for
// the open chunk); Entry.Seq is left 0.
//
// It reads the open chunk and the sealed chunks whose messages' receive times overlap
// [from, to), newest first, and stops as soon as no chunk left can hold a message newer than
// the oldest of the limit+1 newest found: it holds at most that many messages and one line in
// memory. ctx is checked between chunks and every few thousand lines; match must not call the
// store.
//
// Reading is lenient, like the ledger's readers: lines that do not parse are skipped, and a
// chunk whose file is missing or damaged is read as far as it can be; both are logged once per
// chunk. A sealed chunk read to its end is checked against the SHA-256 it was sealed with; a
// mismatch is logged (its syslog_chunk record is the authority on what it held).
func (s *Store) Query(ctx context.Context, from, to time.Time, match func(*model.SyslogMessage) bool, limit int) ([]model.SyslogEntry, bool, error) {
	if limit < 1 {
		return nil, false, errors.New("syslogstore: the limit of a query must be at least 1")
	}
	if to.IsZero() {
		to = endOfTime
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if !from.Before(to) {
		return []model.SyslogEntry{}, false, nil
	}
	q := &query{from: from, to: to, match: match, top: &topN{n: limit}}
	if limit < math.MaxInt {
		q.top.n = limit + 1 // one more than returned tells whether more matched
	}

	// The open chunk and the sealed chunks to read, at one point in time: no writing method
	// runs while the open chunk is read, so it cannot be sealed meanwhile.
	s.wmu.RLock()
	s.mu.Lock()
	var open openView
	if oc := s.open; oc != nil {
		open = openView{name: oc.name, path: oc.path, f: oc.f, live: oc.live, size: oc.size,
			messages: oc.messages, rxMin: oc.rxMin, rxMax: oc.rxMax, pos: len(s.chunks)}
	}
	var cands []candidate
	for i, c := range s.chunks {
		if c.meta.Messages > 0 && !c.deleting && c.rxMin.Before(to) && !c.rxMax.Before(from) {
			cands = append(cands, candidate{c: c, pos: i, rxMax: c.rxMax, name: c.meta.Name,
				bytes: c.meta.Bytes, sha: c.meta.SHA256})
		}
	}
	s.mu.Unlock()
	err := s.readOpen(ctx, q, open)
	s.wmu.RUnlock()
	if err != nil {
		return nil, false, err
	}

	slices.SortFunc(cands, func(a, b candidate) int {
		if c := b.rxMax.Compare(a.rxMax); c != 0 {
			return c
		}
		return b.pos - a.pos
	})
	for _, cd := range cands {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		if q.top.full() && cd.rxMax.Before(q.top.oldest().rx) {
			break // this chunk and the ones after it hold only older messages
		}
		if err := s.readSealed(ctx, q, cd); err != nil {
			return nil, false, err
		}
	}
	entries, truncated := q.top.result(limit)
	return entries, truncated, nil
}

// openView is what Query needs of the open chunk.
type openView struct {
	name, path   string
	f            *os.File
	live         bool
	size         int64
	messages     int
	rxMin, rxMax time.Time
	pos          int
}

// candidate is a sealed chunk Query may read, with what Query needs of it as indexed.
type candidate struct {
	c     *chunk
	pos   int // its position in the index (oldest first)
	rxMax time.Time
	name  string
	bytes int64 // the size and SHA-256 of its content when it was sealed
	sha   string
}

// query is a running Query.
type query struct {
	from, to time.Time
	match    func(*model.SyslogMessage) bool
	top      *topN
	bad      int // lines of the current chunk that could not be read
}

// add takes one line of the chunk at position pos ("" names the open chunk).
func (q *query) add(chunkName string, pos, idx int, line []byte) {
	var m model.SyslogMessage
	if line == nil || json.Unmarshal(line, &m) != nil {
		q.bad++
		return
	}
	rx, ok := parseRX(m.RX)
	if !ok {
		q.bad++
		return
	}
	if rx.Before(q.from) || !rx.Before(q.to) || q.match != nil && !q.match(&m) {
		return
	}
	q.top.add(&hit{rx: rx, pos: pos, line: idx, entry: model.SyslogEntry{Chunk: chunkName, SyslogMessage: m}})
}

// lines returns the line callback of eachLine for the chunk at pos.
func (q *query) lines(ctx context.Context, chunkName string, pos int) func(int, []byte) error {
	q.bad = 0
	return func(i int, line []byte) error {
		if i%ctxEvery == ctxEvery-1 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		q.add(chunkName, pos, i, line)
		return nil
	}
}

// readOpen reads the open chunk (s.wmu held shared): the writer's lines through its handle;
// in a read-only or closed store, the file's complete lines as far as they go.
func (s *Store) readOpen(ctx context.Context, q *query, oc openView) error {
	if oc.name == "" {
		return nil
	}
	if oc.f != nil {
		if oc.messages == 0 || oc.rxMax.Before(q.from) || !oc.rxMin.Before(q.to) {
			return nil
		}
		err := eachLine(io.NewSectionReader(oc.f, 0, oc.size), false, q.lines(ctx, "", oc.pos))
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			s.warnOnce(oc.name, "syslog store: the open chunk cannot be read", "err", err)
		}
		s.noteBad(oc.name, q.bad)
		return nil
	}
	f, err := openShared(oc.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil // sealed meanwhile by the writer
	}
	if err != nil {
		s.warnOnce(oc.name, "syslog store: the open chunk cannot be read", "err", err)
		return nil
	}
	defer f.Close()
	err = eachLine(io.LimitReader(f, maxContent), false, q.lines(ctx, "", oc.pos))
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		s.warnOnce(oc.name, "syslog store: the open chunk cannot be read", "err", err)
	}
	s.noteBad(oc.name, q.bad)
	return nil
}

// readSealed reads a sealed chunk, unless Prune deleted it meanwhile. Only ctx's error is
// returned; a chunk that cannot be read is logged and skipped.
func (s *Store) readSealed(ctx context.Context, q *query, cd candidate) error {
	c, name := cd.c, cd.name
	if !s.acquire(c) {
		return nil
	}
	defer s.release(c)
	f, err := openShared(c.path)
	if err != nil {
		s.warnOnce(name, "syslog store: a chunk cannot be read", "err", err)
		return nil
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		s.warnOnce(name, "syslog store: a chunk cannot be read", "err", err)
		return nil
	}
	h := sha256.New()
	cnt := &countWriter{w: h}
	err = eachLine(io.TeeReader(io.LimitReader(zr, maxContent), cnt), true, q.lines(ctx, name, cd.pos))
	if ctx.Err() != nil {
		return ctx.Err()
	}
	s.noteBad(name, q.bad)
	if err != nil {
		s.warnOnce(name, "syslog store: a chunk cannot be read to its end; the messages before the damage were read", "err", err)
		return nil
	}
	if cnt.n != cd.bytes || hex.EncodeToString(h.Sum(nil)) != cd.sha {
		s.warnOnce(name, "syslog store: a chunk does not hold what it was sealed with (its SHA-256 differs); its syslog_chunk record is the authority",
			"bytes", cnt.n, "sealed_bytes", cd.bytes)
	}
	return nil
}

// countWriter counts what it passes on.
type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// noteBad logs, once per chunk, that lines of it could not be read.
func (s *Store) noteBad(name string, bad int) {
	if bad > 0 {
		s.warnOnce(name, "syslog store: lines of a chunk that cannot be read were skipped", "lines", bad)
	}
}

// warnOnce logs a problem with a chunk the first time it is found.
func (s *Store) warnOnce(name, msg string, args ...any) {
	s.mu.Lock()
	seen := s.warned[name][msg]
	if !seen {
		if s.warned[name] == nil {
			s.warned[name] = map[string]bool{}
		}
		s.warned[name][msg] = true
	}
	s.mu.Unlock()
	if !seen {
		s.log.Warn(msg, append([]any{"chunk", name}, args...)...)
	}
}

// acquire registers a reader of c, unless c is being deleted or gone.
func (s *Store) acquire(c *chunk) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.deleting || s.byName[c.meta.Name] != c {
		return false
	}
	c.readers++
	return true
}

// release ends a reader of c.
func (s *Store) release(c *chunk) {
	s.mu.Lock()
	c.readers--
	s.mu.Unlock()
}

// OpenChunk opens the exact stored bytes (gzip) of the sealed chunk name, which must be the
// name of an indexed chunk (contracts.ErrNotFound otherwise, also for any name with a path
// separator or ".."). Until the reader is closed, Prune does not delete the chunk.
func (s *Store) OpenChunk(name string) (io.ReadCloser, error) {
	notFound := fmt.Errorf("syslogstore: chunk %q: %w", name, contracts.ErrNotFound)
	if strings.ContainsAny(name, `/\:`) || strings.Contains(name, "..") {
		return nil, notFound
	}
	if _, _, _, ok := parseSealedName(name); !ok {
		return nil, notFound
	}
	s.mu.Lock()
	c := s.byName[name]
	s.mu.Unlock()
	if c == nil || !s.acquire(c) {
		return nil, notFound
	}
	f, err := openShared(c.path)
	if err != nil {
		s.release(c)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, notFound
		}
		return nil, fmt.Errorf("syslogstore: %w", err)
	}
	return &chunkReader{f: f, s: s, c: c}, nil
}

// chunkReader reads a sealed chunk's file for OpenChunk.
type chunkReader struct {
	f    *os.File
	s    *Store
	c    *chunk
	once sync.Once
}

func (r *chunkReader) Read(p []byte) (int, error) { return r.f.Read(p) }

// Close closes the file and lets Prune delete the chunk; later calls do nothing.
func (r *chunkReader) Close() error {
	var err error
	r.once.Do(func() {
		err = r.f.Close()
		r.s.release(r.c)
	})
	return err
}

// hit is a message that matched.
type hit struct {
	rx    time.Time
	pos   int // the position of its chunk, oldest first (the open chunk last)
	line  int
	entry model.SyslogEntry
}

// newer reports whether a was received after b: by receive time, then by place in the store.
func newer(a, b *hit) bool {
	if !a.rx.Equal(b.rx) {
		return a.rx.After(b.rx)
	}
	if a.pos != b.pos {
		return a.pos > b.pos
	}
	return a.line > b.line
}

// topN keeps the newest n hits: a heap with the oldest of them at its root.
type topN struct {
	n int
	h []*hit
}

func (t *topN) Len() int           { return len(t.h) }
func (t *topN) Less(i, j int) bool { return newer(t.h[j], t.h[i]) }
func (t *topN) Swap(i, j int)      { t.h[i], t.h[j] = t.h[j], t.h[i] }
func (t *topN) Push(x any)         { t.h = append(t.h, x.(*hit)) }
func (t *topN) Pop() any {
	x := t.h[len(t.h)-1]
	t.h[len(t.h)-1] = nil
	t.h = t.h[:len(t.h)-1]
	return x
}

// add keeps x if it is among the newest n.
func (t *topN) add(x *hit) {
	switch {
	case len(t.h) < t.n:
		heap.Push(t, x)
	case newer(x, t.h[0]):
		t.h[0] = x
		heap.Fix(t, 0)
	}
}

func (t *topN) full() bool   { return len(t.h) >= t.n }
func (t *topN) oldest() *hit { return t.h[0] }

// result returns the newest limit entries, newest first, and whether more were kept.
func (t *topN) result(limit int) ([]model.SyslogEntry, bool) {
	slices.SortFunc(t.h, func(a, b *hit) int {
		switch {
		case newer(a, b):
			return -1
		case newer(b, a):
			return 1
		}
		return 0
	})
	n := min(len(t.h), limit)
	out := make([]model.SyslogEntry, n)
	for i, x := range t.h[:n] {
		out[i] = x.entry
	}
	return out, len(t.h) > limit
}
