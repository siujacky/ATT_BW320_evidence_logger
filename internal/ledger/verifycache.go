package ledger

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
)

// Verification cache (Store.Verify only).
//
// Checking a record's Ed25519 signature is most of the cost of verifying it (about four fifths of
// the work per record; parsing and hashing are the rest). The outcome is a pure function of the
// public key and the line's bytes, so Store.Verify remembers, per segment, which lines' signatures
// did not verify, together with the identity of the exact bytes it read: the public key, and the
// length and SHA-256 of the segment's raw bytes (the uncompressed stream of a .jsonl file as read,
// the file bytes of a .jsonl.gz). A later Store.Verify reads each segment's raw bytes into memory
// and hashes them; only when they are identical does it take each line's signature outcome from
// the cache instead of computing it again — and the lines it then parses and checks are those very
// bytes in memory, so nothing can change between the comparison and the use. Neither the file's
// size and modification time nor the hash a later segment_open commits to decide anything: both
// can be kept while the bytes change.
//
// Everything else is done again by every verification, over the whole ledger: strict parsing,
// record hashes, seq and prev linkage, segment structure and segment_open hashes, genesis and key
// checks, blobs, anchors and their tokens, time checks and gaps. The report is therefore exactly
// the report of a verification without the cache (verifycache_test.go compares the two, also after
// tampering). A segment whose raw bytes exceed maxCachedSegmentBytes is streamed and verified in
// full every time. The cache lives in this process only: nothing on disk can make a verification
// skip a check.

// maxCachedSegmentBytes bounds the raw bytes of a segment held in memory to be identified (a
// variable so that tests can lower it). A day of records is far smaller.
var maxCachedSegmentBytes int64 = 64 << 20

// sigCache remembers the signature outcomes of the segments verified by one Store.
type sigCache struct {
	mu      sync.Mutex
	entries map[string]*sigEntry // by segment name

	// Statistics (tests): segments found / not found, signatures verified / outcomes reused.
	hits, misses     atomic.Int64
	verified, reused atomic.Int64
}

func newSigCache() *sigCache { return &sigCache{entries: map[string]*sigEntry{}} }

// sigEntry identifies the exact bytes one verification streamed for a segment and lists the lines
// whose signature did not verify. Entries are never modified once stored.
type sigEntry struct {
	pub   string            // the public key the signatures were checked with (raw bytes)
	gz    bool              // the raw bytes are a .jsonl.gz file (else the uncompressed stream)
	size  int64             // length of the raw bytes
	sum   [sha256.Size]byte // SHA-256 of the raw bytes
	lines int               // complete lines of the stream
	bad   []int             // line numbers (1-based) whose signature did not verify, ascending
}

func (e *sigEntry) sameBytes(o *sigEntry) bool {
	return e.pub == o.pub && e.gz == o.gz && e.size == o.size && e.sum == o.sum
}

func (e *sigEntry) badLine(n int) bool {
	_, found := slices.BinarySearch(e.bad, n)
	return found
}

// cacheRun is the cache's part of one verification.
type cacheRun struct {
	c     *sigCache
	pub   string
	names []string
	segs  []cacheSeg // by source index
}

type cacheSeg struct {
	id  *sigEntry // identity of the bytes streamed (lines and bad unset); nil: not identified
	hit *sigEntry // the outcomes recorded for exactly these bytes, if any
	bad []int     // lines whose signature did not verify in this run (collector)
}

// newCacheRun returns nil (no caching) without a cache or without a public key (signatures are
// then not checked at all).
func newCacheRun(c *sigCache, pub ed25519.PublicKey, srcs []lineSource) *cacheRun {
	if c == nil || pub == nil {
		return nil
	}
	r := &cacheRun{c: c, pub: string(pub), segs: make([]cacheSeg, len(srcs))}
	for _, s := range srcs {
		r.names = append(r.names, s.name)
	}
	return r
}

// openSource opens source si for streaming (producer goroutine). With the cache a source that fits
// in memory is read into memory, identified and streamed from those bytes; otherwise, and when it
// cannot be read, it is opened as without the cache, so that its errors are those of the file.
func (r *cacheRun) openSource(si int, src lineSource) (io.ReadCloser, error) {
	if r != nil && src.load != nil {
		raw, err := src.load()
		if err == nil && raw != nil {
			r.prepare(si, raw)
			return raw.stream()
		}
	}
	return src.open()
}

// prepare identifies the raw bytes of source si and looks them up. It runs before any line of the
// source is handed to a worker (the batches carry the happens-before edge).
func (r *cacheRun) prepare(si int, raw *rawSegment) {
	id := &sigEntry{pub: r.pub, gz: raw.gz, size: int64(len(raw.data)), sum: sha256.Sum256(raw.data)}
	r.c.mu.Lock()
	e := r.c.entries[r.names[si]]
	r.c.mu.Unlock()
	r.segs[si].id = id
	if e != nil && e.sameBytes(id) {
		r.segs[si].hit = e
		r.c.hits.Add(1)
	} else {
		r.c.misses.Add(1)
	}
}

// signatureValid reports whether sig is cfg.pub's Ed25519 signature of b, the content of line r.
// For a segment whose identical bytes were verified before, the outcome recorded then is used.
func (cfg *workerConfig) signatureValid(r *lineResult, b, sig []byte) bool {
	var valid bool
	if hit := cfg.cache.hitFor(r.seg); hit != nil && r.lineNo <= hit.lines {
		valid = !hit.badLine(r.lineNo)
		cfg.cache.c.reused.Add(1)
	} else {
		valid = ed25519.Verify(cfg.pub, b, sig)
		if cfg.cache != nil {
			cfg.cache.c.verified.Add(1)
		}
	}
	r.sigFailed = !valid
	return valid
}

func (r *cacheRun) hitFor(si int) *sigEntry {
	if r == nil {
		return nil
	}
	return r.segs[si].hit
}

// observe notes a line's signature outcome (collector goroutine, in file order).
func (r *cacheRun) observe(res *lineResult) {
	if res.sigFailed {
		s := &r.segs[res.seg]
		s.bad = append(s.bad, res.lineNo)
	}
}

// segmentDone records the outcomes of a source streamed completely (collector goroutine).
func (r *cacheRun) segmentDone(e *segEnd) {
	s := &r.segs[e.seg]
	if s.id == nil || e.openErr != nil || e.readErr != nil {
		return
	}
	name := r.names[e.seg]
	r.c.mu.Lock()
	defer r.c.mu.Unlock()
	if s.hit != nil {
		if s.hit.lines != e.lines {
			delete(r.c.entries, name) // identical bytes, other lines: cannot happen; trust nothing
		}
		return
	}
	entry := *s.id
	entry.lines, entry.bad = e.lines, slices.Clip(s.bad)
	r.c.entries[name] = &entry
}

// prune forgets segments the ledger no longer has (after a verification that listed them all).
func (r *cacheRun) prune() {
	r.c.mu.Lock()
	defer r.c.mu.Unlock()
	for name := range r.c.entries {
		if !slices.Contains(r.names, name) {
			delete(r.c.entries, name)
		}
	}
}

// ---------------------------------------------------------------- raw segment bytes

// rawSegment is a segment's raw bytes held in memory: the uncompressed stream of a .jsonl file
// (as read with its view's limit) or a whole .jsonl.gz file.
type rawSegment struct {
	data []byte
	gz   bool
	base string // file name, for error messages
}

// stream returns the uncompressed content of the bytes, as openSegmentFile delivers it from the
// file they were read from (same decompressor, same errors).
func (r *rawSegment) stream() (io.ReadCloser, error) {
	if !r.gz {
		return io.NopCloser(bytes.NewReader(r.data)), nil
	}
	return newGzStream(bytes.NewReader(r.data), nil, r.base)
}

// loadSegmentFile reads the raw bytes that openSegmentFile(f, limit) streams, from the same file
// and with the same fallback to the compressed form; nil when they exceed max.
func loadSegmentFile(f segFile, limit, max int64) (*rawSegment, error) {
	if f.Plain != "" {
		r, err := loadPlain(f.Plain, limit, max)
		if err == nil || !errors.Is(err, os.ErrNotExist) {
			return r, err
		}
		gz := f.Plain + gzExt
		if f.Gz != "" {
			gz = f.Gz
		}
		return loadGz(gz, max)
	}
	return loadGz(f.Gz, max)
}

// loadPlain reads an uncompressed segment with openPlain's limit: >= 0 the first limit bytes, -2
// complete lines only (as of now), -1 everything.
func loadPlain(path string, limit, max int64) (*rawSegment, error) {
	f, err := openShared(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	n, r := limit, io.Reader(io.LimitReader(f, limit))
	if limit < 0 {
		st, err := f.Stat()
		if err != nil {
			return nil, err
		}
		n, r = st.Size(), io.LimitReader(f, max+1)
	}
	if n > max {
		return nil, nil
	}
	data, err := readAllSized(r, n)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, nil // grew past the bound while being read
	}
	if limit == -2 {
		data = data[:bytes.LastIndexByte(data, '\n')+1]
	}
	return &rawSegment{data: data, base: filepath.Base(path)}, nil
}

// loadGz reads a whole compressed segment file.
func loadGz(path string, max int64) (*rawSegment, error) {
	f, err := openShared(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() > max {
		return nil, nil
	}
	data, err := readAllSized(io.LimitReader(f, max+1), st.Size())
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, nil
	}
	return &rawSegment{data: data, gz: true, base: filepath.Base(path)}, nil
}

// readAllSized reads r to its end into a buffer sized for n bytes.
func readAllSized(r io.Reader, n int64) ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0, n+bytes.MinRead))
	_, err := buf.ReadFrom(r)
	return buf.Bytes(), err
}
