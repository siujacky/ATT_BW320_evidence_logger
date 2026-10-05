package ledger

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"attmonitor/internal/model"
)

// Record lookups go through a line-offset index per segment file: built lazily by one pass over
// the segment, then searched in O(log n) (binary search over the seqs of its lines). The index is
// an accelerator only, never a source of truth:
//
//   - It is validated on every use: it must describe the same file (os.SameFile), and a sealed
//     or read-only segment must still have the size and modification time it was indexed at,
//     the writer's own active segment no more fsynced records than are indexed. A file that only
//     grew is indexed incrementally, after checking that the last indexed line is still in
//     place; any other change rebuilds the index.
//   - The line read at an indexed offset must be a record with the requested seq. If the bytes
//     there no longer match the index, the index is dropped; in every doubtful case Record falls
//     back to reading the segment from its start.
//
// The cache holds at most maxIndexedSegments segment indexes (least recently used first out).
// For a gzip-compressed segment the uncompressed bytes are also kept, within maxIndexDataBytes in
// total; a compressed segment beyond that is read by streaming decompression up to the record.

// maxIndexedSegments bounds the number of segment indexes kept by a Store.
const maxIndexedSegments = 4

// maxIndexDataBytes bounds the uncompressed bytes of compressed segments kept in memory by the
// index cache (a variable so that tests can lower it).
var maxIndexDataBytes int64 = 64 << 20

// lineIndex maps the seqs of the complete lines of one segment file to their byte ranges.
type lineIndex struct {
	path string
	gz   bool

	evicted atomic.Bool            // removed from the cache: must not acquire data any more
	data    atomic.Pointer[[]byte] // gz: the uncompressed bytes [0, end) when within the budget

	mu      sync.Mutex // guards the fields below; held while validating, extending or searching
	gen     uint64     // incremented by every reset, so that a stale report drops only what it saw
	valid   bool
	id      os.FileInfo // the file indexed (os.SameFile: a replaced file is never extended)
	statted bool        // size and mod describe the extent indexed (false while sized by the writer)
	size    int64       // file size when last validated
	mod     time.Time   // file modification time when last validated
	end     int64       // bytes covered (uncompressed): the end of the last complete line indexed

	// The last complete line covered, re-checked before the index is extended.
	lastStart int64
	lastLen   int
	lastSum   [sha256.Size]byte
	lastOK    bool // lastSum is set (false: no line yet, or the line is too long to keep)

	seqs   []uint64 // seq of each indexed line, in file order
	offs   []int64  // offset of each indexed line
	lens   []uint32 // length of each indexed line, '\n' included
	sorted bool     // seqs strictly increasing: binary search applies
}

// indexCache is a Store's bounded set of segment indexes.
type indexCache struct {
	mu        sync.Mutex
	entries   []*lineIndex // most recently used first
	dataBytes atomic.Int64 // uncompressed bytes held by entries

	builds, extends, stale atomic.Int64 // statistics (tests)
}

// get returns the index for path, creating it if needed, and marks it most recently used.
func (c *indexCache) get(path string, gz bool) *lineIndex {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, e := range c.entries {
		if e.path == path {
			copy(c.entries[1:i+1], c.entries[:i])
			c.entries[0] = e
			return e
		}
	}
	e := &lineIndex{path: path, gz: gz}
	c.entries = append([]*lineIndex{e}, c.entries...)
	for len(c.entries) > maxIndexedSegments {
		last := len(c.entries) - 1
		c.dropLocked(c.entries[last])
		c.entries[last] = nil
		c.entries = c.entries[:last]
	}
	return e
}

// remove forgets the index of path (its file was replaced, e.g. by compression).
func (c *indexCache) remove(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, e := range c.entries {
		if e.path == path {
			c.dropLocked(e)
			c.entries = slices.Delete(c.entries, i, i+1)
			return
		}
	}
}

// dropLocked releases what an entry leaving the cache holds. Lookups still using it finish
// normally. c.mu must be held.
func (c *indexCache) dropLocked(e *lineIndex) {
	e.evicted.Store(true)
	c.releaseData(e)
}

func (c *indexCache) releaseData(e *lineIndex) {
	if d := e.data.Swap(nil); d != nil {
		c.dataBytes.Add(-int64(len(*d)))
	}
}

// keepData keeps data as the uncompressed bytes of e if the budget allows, releasing the data of
// less recently used entries first.
func (c *indexCache) keepData(e *lineIndex, data []byte) {
	n := int64(len(data))
	if n == 0 || n > maxIndexDataBytes {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e.evicted.Load() {
		return
	}
	c.releaseData(e)
	for i := len(c.entries) - 1; i >= 0 && c.dataBytes.Load()+n > maxIndexDataBytes; i-- {
		if c.entries[i] != e {
			c.releaseData(c.entries[i])
		}
	}
	if c.dataBytes.Load()+n > maxIndexDataBytes {
		return
	}
	c.dataBytes.Add(n)
	e.data.Store(&data)
}

// ---------------------------------------------------------------- lookups

type lookupResult int8

const (
	lookupUnsure lookupResult = iota // the index cannot answer: read the segment
	lookupFound
	lookupAbsent // the (validated) index has no line with this seq
)

// lineLoc is where locate found a line.
type lineLoc struct {
	found bool
	off   int64
	n     int
	gen   uint64
	f     *os.File // plain segment, open for reading (the caller closes it)
	data  []byte   // compressed segment: its uncompressed bytes, if kept
}

// recordIndexed looks seq up in the segment v through its line index.
func (s *Store) recordIndexed(v segView, seq uint64) (model.Envelope, model.Body, lookupResult) {
	ix := s.idx.get(v.path(), v.compressed())
	loc, err := s.locate(ix, v, seq)
	if err != nil {
		s.log.Debug("segment index unavailable; reading the segment", "segment", v.Name, "err", err)
		return model.Envelope{}, model.Body{}, lookupUnsure
	}
	if loc.f != nil {
		defer loc.f.Close()
	}
	if !loc.found {
		return model.Envelope{}, model.Body{}, lookupAbsent
	}
	line, err := loc.read(ix.path)
	if err == nil {
		env, body, perr := parseRecordLenient(line)
		if perr == nil && body.Seq == seq {
			return env, body, lookupFound
		}
		if q, ok := lineSeq(line); ok && q == seq && line[len(line)-1] == '\n' {
			// The file matches the index; the line just is not a usable record for seq (the
			// scan skips it as well, and may find another line with this seq).
			return model.Envelope{}, model.Body{}, lookupUnsure
		}
	}
	// The file no longer matches the index (rewritten in place, truncated, unreadable).
	s.idx.stale.Add(1)
	s.log.Debug("segment index is stale; reading the segment", "segment", v.Name, "seq", seq, "err", err)
	ix.mu.Lock()
	if ix.gen == loc.gen {
		s.resetIndex(ix)
	}
	ix.mu.Unlock()
	return model.Envelope{}, model.Body{}, lookupUnsure
}

// locate brings the index of v up to date and finds the line of seq.
func (s *Store) locate(ix *lineIndex, v segView, seq uint64) (lineLoc, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	var loc lineLoc
	if ix.gz {
		if err := s.refreshGz(ix); err != nil {
			s.resetIndex(ix)
			return loc, err
		}
	} else {
		f, err := openShared(ix.path)
		if err != nil {
			s.resetIndex(ix)
			return loc, err
		}
		if err := s.refreshPlain(ix, v, f); err != nil {
			f.Close()
			s.resetIndex(ix)
			return loc, err
		}
		loc.f = f
	}
	loc.gen = ix.gen
	i := ix.find(seq)
	if i < 0 {
		return loc, nil
	}
	loc.found, loc.off, loc.n = true, ix.offs[i], int(ix.lens[i])
	if d := ix.data.Load(); d != nil {
		loc.data = *d
	}
	return loc, nil
}

// read returns the bytes of the located line.
func (l *lineLoc) read(path string) ([]byte, error) {
	switch {
	case l.n <= 0:
		return nil, errors.New("empty line")
	case l.f != nil:
		buf := make([]byte, l.n)
		n, err := l.f.ReadAt(buf, l.off)
		if n != l.n {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			return nil, err
		}
		return buf, nil
	case l.data != nil:
		if l.off < 0 || l.off+int64(l.n) > int64(len(l.data)) {
			return nil, io.ErrUnexpectedEOF
		}
		return l.data[l.off : l.off+int64(l.n)], nil // parsing copies what it keeps
	default:
		return readGzRange(path, l.off, l.n)
	}
}

// readGzRange decompresses a compressed segment up to off and returns the n bytes there.
func readGzRange(path string, off int64, n int) ([]byte, error) {
	rc, err := openGz(path)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	if _, err := io.CopyN(io.Discard, rc, off); err != nil {
		return nil, err
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(rc, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// ---------------------------------------------------------------- building

// resetIndex empties ix (ix.mu held).
func (s *Store) resetIndex(ix *lineIndex) {
	ix.gen++
	ix.valid, ix.id, ix.statted = false, nil, false
	ix.size, ix.mod, ix.end = 0, time.Time{}, 0
	ix.lastStart, ix.lastLen, ix.lastOK = 0, 0, false
	ix.seqs, ix.offs, ix.lens = nil, nil, nil
	ix.sorted = true
	s.idx.releaseData(ix)
}

// refreshPlain brings the index of an uncompressed segment up to date (ix.mu held); f is the
// segment, open for reading.
func (s *Store) refreshPlain(ix *lineIndex, v segView, f *os.File) error {
	st, err := f.Stat() // by handle: also identifies the file without another lookup
	if err != nil {
		return err
	}
	same := ix.valid && ix.id != nil && os.SameFile(st, ix.id)
	var end int64
	if v.writerActive {
		// Only this writer appends to its active segment, and it never removes what readers
		// can see (its fsynced records, v.limit): the index never needs more than extending.
		if same && v.limit <= ix.end {
			return nil
		}
		end = v.limit
	} else {
		if same && ix.statted && st.Size() == ix.size && st.ModTime().Equal(ix.mod) {
			return nil
		}
		// Readers never see a line that is still being written.
		if end, err = completeSize(f, st.Size()); err != nil {
			return err
		}
	}
	if same && end >= ix.end && ix.tailIntact(f) {
		if end > ix.end {
			if err := ix.scanPlain(f, ix.end, end); err != nil {
				return err
			}
			s.idx.extends.Add(1)
		}
	} else {
		s.resetIndex(ix)
		if err := ix.scanPlain(f, 0, end); err != nil {
			return err
		}
		s.idx.builds.Add(1)
	}
	ix.valid, ix.id = true, st
	// The writer's file may already be longer than the records it has fsynced (v.limit): its
	// size and time then do not describe what is indexed.
	ix.statted = !v.writerActive
	ix.size, ix.mod = st.Size(), st.ModTime()
	return nil
}

// refreshGz brings the index of a compressed segment up to date (ix.mu held). A compressed
// segment is sealed, so any change means another file: it is indexed again in one pass, keeping
// the uncompressed bytes when the budget allows.
func (s *Store) refreshGz(ix *lineIndex) error {
	f, err := openShared(ix.path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if ix.valid && ix.id != nil && os.SameFile(st, ix.id) && st.Size() == ix.size && st.ModTime().Equal(ix.mod) {
		return nil
	}
	s.resetIndex(ix)
	capture := &capBuffer{max: maxIndexDataBytes}
	if hint := gzipSizeHint(f, st.Size()); hint > 0 && hint <= capture.max {
		capture.buf = make([]byte, 0, hint)
	}
	zr, err := gzip.NewReader(bufio.NewReaderSize(io.NewSectionReader(f, 0, st.Size()), 64<<10))
	if err != nil {
		return fmt.Errorf("ledger: %s: %w", ix.path, err)
	}
	defer zr.Close()
	if err := ix.scanLines(newLineReader(io.TeeReader(zr, capture), readBufSize)); err != nil {
		return err
	}
	ix.valid, ix.id, ix.statted, ix.size, ix.mod = true, st, true, st.Size(), st.ModTime()
	if !capture.over && int64(len(capture.buf)) >= ix.end {
		data := capture.buf[:ix.end]
		if cap(data)-len(data) > len(data)/8+4096 {
			data = bytes.Clone(data) // do not keep a much larger buffer than accounted for
		}
		s.idx.keepData(ix, data[:len(data):len(data)])
	}
	s.idx.builds.Add(1)
	return nil
}

// scanPlain indexes the complete lines in [from, to) of an uncompressed segment (to ends a line).
func (ix *lineIndex) scanPlain(r io.ReaderAt, from, to int64) error {
	if to <= from {
		return nil
	}
	bufSize := readBufSize
	if to-from < int64(bufSize) {
		bufSize = max(int(to-from), 4096)
	}
	lr := newLineReader(io.NewSectionReader(r, from, to-from), bufSize)
	lr.off = from
	if err := ix.scanLines(lr); err != nil {
		return err
	}
	return ix.hashLast(r)
}

// scanLines indexes the complete lines of lr; an incomplete final line is never indexed.
func (ix *lineIndex) scanLines(lr *lineReader) error {
	for {
		rec, err := lr.next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if !rec.complete {
			return nil
		}
		ix.add(rec)
	}
}

// add records one complete line. Lines without a readable seq are covered but not indexed (the
// scan skips them too).
func (ix *lineIndex) add(rec lineRec) {
	ix.end = rec.start + int64(rec.n)
	ix.lastStart, ix.lastLen, ix.lastOK = rec.start, rec.n, false
	if rec.tooLong {
		return
	}
	seq, ok := lineSeq(rec.data)
	if !ok {
		return
	}
	if n := len(ix.seqs); n > 0 && ix.seqs[n-1] >= seq {
		ix.sorted = false
	}
	ix.seqs = append(ix.seqs, seq)
	ix.offs = append(ix.offs, rec.start)
	ix.lens = append(ix.lens, uint32(rec.n))
}

// hashLast remembers the hash of the last line covered, so that a later extension can check
// that the indexed part of the file is unchanged.
func (ix *lineIndex) hashLast(r io.ReaderAt) error {
	ix.lastOK = false
	if ix.end == 0 || ix.lastLen <= 0 || ix.lastLen > maxLineBytes {
		return nil
	}
	buf := make([]byte, ix.lastLen)
	n, err := r.ReadAt(buf, ix.lastStart)
	if n != len(buf) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return err
	}
	ix.lastSum, ix.lastOK = sha256.Sum256(buf), true
	return nil
}

// tailIntact reports whether the last line covered by the index is still in place.
func (ix *lineIndex) tailIntact(r io.ReaderAt) bool {
	if ix.end == 0 {
		return true
	}
	if !ix.lastOK {
		return false
	}
	buf := make([]byte, ix.lastLen)
	n, _ := r.ReadAt(buf, ix.lastStart)
	return n == len(buf) && sha256.Sum256(buf) == ix.lastSum
}

// find returns the position of the first line (in file order) with seq, or -1.
func (ix *lineIndex) find(seq uint64) int {
	if ix.sorted {
		if i, ok := slices.BinarySearch(ix.seqs, seq); ok {
			return i
		}
		return -1
	}
	return slices.Index(ix.seqs, seq)
}

// capBuffer keeps what is written to it, up to max bytes; beyond that it keeps nothing.
type capBuffer struct {
	buf  []byte
	max  int64
	over bool
}

func (c *capBuffer) Write(p []byte) (int, error) {
	if !c.over {
		if int64(len(c.buf))+int64(len(p)) > c.max {
			c.over, c.buf = true, nil
		} else {
			c.buf = append(c.buf, p...)
		}
	}
	return len(p), nil
}

// gzipSizeHint returns the uncompressed size a gzip file states in its trailer (ISIZE, modulo
// 2^32; 0 if unknown). It is only a capacity hint: nothing relies on it being true.
func gzipSizeHint(r io.ReaderAt, size int64) int64 {
	if size < 18 { // smallest possible gzip member
		return 0
	}
	var b [4]byte
	if n, _ := r.ReadAt(b[:], size-4); n != len(b) {
		return 0
	}
	return int64(binary.LittleEndian.Uint32(b[:]))
}
