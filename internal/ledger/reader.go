package ledger

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"
	"sync"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// errStopScan ends an internal scan early.
var errStopScan = errors.New("stop")

// segView is a segment as seen by a reader at one moment.
type segView struct {
	segFile
	last  bool
	limit int64 // plain file read limit: >= 0 bytes, -2 complete lines only, -1 everything

	// writerActive: the writer's own active segment (limit = its fsynced records), whose first
	// seq the writer knows.
	writerActive bool
	firstSeq     uint64
}

// activeView is the writer's active segment at one moment.
type activeView struct {
	name     string
	size     int64 // bytes of complete, fsynced lines
	firstSeq uint64
}

// activeSnapshot describes the writer's active segment. ok is false for a read-only store and
// after Close: the segment may then be changed by another writer.
func (s *Store) activeSnapshot() (activeView, bool) {
	if s.readOnly {
		return activeView{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil || s.closed {
		return activeView{}, false
	}
	return activeView{name: s.active.name, size: s.active.size, firstSeq: s.active.firstSeq}, true
}

// readerSegments lists the segments with read limits that never expose a partially written
// line: the writer's active segment is read up to its last fsynced record; for a read-only
// store the latest segment is read up to its last newline (completeOnly) or entirely.
func (s *Store) readerSegments(completeOnly bool) ([]segView, error) {
	files, err := listSegmentFiles(s.ledgerDir)
	if err != nil {
		return nil, fmt.Errorf("ledger: %w", err)
	}
	act, isWriter := s.activeSnapshot()
	views := make([]segView, len(files))
	for i, f := range files {
		v := segView{segFile: f, last: i == len(files)-1, limit: -1}
		switch {
		case isWriter && f.Name == act.name && f.Plain != "":
			v.limit, v.writerActive, v.firstSeq = act.size, true, act.firstSeq
		case v.last && completeOnly:
			v.limit = -2
		}
		views[i] = v
	}
	return views, nil
}

// verifySegments implements verifySegmentLister: the verifier sees an incomplete final line of
// a read-only store's latest segment (and notes it) instead of having it hidden.
func (s *Store) verifySegments() ([]lineSource, error) {
	views, err := s.readerSegments(false)
	if err != nil {
		return nil, err
	}
	srcs := make([]lineSource, len(views))
	for i, v := range views {
		srcs[i] = lineSource{name: v.Name, date: v.Date,
			open: func() (io.ReadCloser, error) { return openSegmentFile(v.segFile, v.limit) },
			load: func() (*rawSegment, error) { return loadSegmentFile(v.segFile, v.limit, maxCachedSegmentBytes) },
		}
	}
	return srcs, nil
}

// scanView calls fn for each complete line of a segment.
func scanView(v segView, fn func(line []byte) error) error {
	rc, err := openSegmentFile(v.segFile, v.limit)
	if err != nil {
		return fmt.Errorf("ledger: open segment %s: %w", v.Name, err)
	}
	defer rc.Close()
	lr := newLineReader(rc, readBufSize)
	for {
		rec, err := lr.next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("ledger: read segment %s: %w", v.Name, err)
		}
		if !rec.complete || rec.tooLong {
			continue
		}
		if err := fn(rec.data); err != nil {
			return err
		}
	}
}

// lineSeq returns the seq of a record line (fast path for this writer's layout).
func lineSeq(line []byte) (uint64, bool) {
	if seq, _, ok := quickSeqTS(line); ok {
		return seq, true
	}
	_, body, err := parseRecordLenient(line)
	if err != nil {
		return 0, false
	}
	return body.Seq, true
}

// Scan calls fn for each record with seq >= fromSeq in ascending (file) order. Returning
// contracts.ErrStop ends the scan with a nil error.
//
// Scan is lenient, like every reading method (ScanTime, Record, Segments, OpenSegment): it
// skips lines that cannot be parsed and checks neither hashes, signatures nor the chain, so it
// returns whatever the segment files hold, tampered or not. Verify (VerifyReader) is
// authoritative: it reads the same files strictly and reports every line Scan skips and every
// record that does not verify. Present Scan's records as evidence only together with a
// verification result.
func (s *Store) Scan(fromSeq uint64, fn func(env model.Envelope, body model.Body) error) error {
	views, err := s.readerSegments(true)
	if err != nil {
		return err
	}
	for _, v := range views[s.findStart(views, fromSeq):] {
		err := scanView(v, func(line []byte) error {
			if seq, _, ok := quickSeqTS(line); ok && seq < fromSeq {
				return nil
			}
			env, body, err := parseRecordLenient(line)
			if err != nil || body.Seq < fromSeq {
				return nil
			}
			return fn(env, body)
		})
		if err != nil {
			if errors.Is(err, contracts.ErrStop) {
				return nil
			}
			return err
		}
	}
	return nil
}

// ScanTime calls fn for records whose ts lies in [from, to), in ascending seq order. Like Scan it
// is lenient (unparseable lines and lines without a valid ts are skipped); Verify is
// authoritative.
//
// A segment holds records whose ts falls before the end of its UTC day (a later date starts a
// new segment), so segments ending at or before from are skipped exactly. A segment dated
// after to holds earlier records only if the wall clock was behind the segment's date while it
// was active (the writer never reopens an older segment): for example after a clock that
// jumped days ahead was corrected, every later record lands in the future-dated segment. Such
// a segment is skipped only when its earliest ts (cached per file) is not before to; the
// latest segment is always read.
func (s *Store) ScanTime(from, to time.Time, fn func(env model.Envelope, body model.Body) error) error {
	if !from.Before(to) {
		return nil
	}
	views, err := s.readerSegments(true)
	if err != nil {
		return err
	}
	inRange := func(t time.Time) bool { return !t.Before(from) && t.Before(to) }
	for _, v := range views {
		if !v.Date.Add(day).After(from) {
			continue
		}
		if !v.last && !v.Date.Add(-day).Before(to) {
			earliest, ok := s.segmentMinTS(v)
			if !ok {
				// Unreadable (Verify reports it); it normally holds nothing before to, so an
				// unrelated earlier range must not fail because of it.
				s.log.Warn("segment skipped by ScanTime: its earliest record time cannot be read", "segment", v.Name)
				continue
			}
			if !earliest.Before(to) {
				continue
			}
		}
		err := scanView(v, func(line []byte) error {
			if _, ts, ok := quickSeqTS(line); ok {
				if t, err := time.Parse(time.RFC3339Nano, string(ts)); err == nil && !inRange(t) {
					return nil
				}
			}
			env, body, err := parseRecordLenient(line)
			if err != nil {
				return nil
			}
			t, err := time.Parse(time.RFC3339Nano, body.TS)
			if err != nil || !inRange(t) {
				return nil
			}
			return fn(env, body)
		})
		if err != nil {
			if errors.Is(err, contracts.ErrStop) {
				return nil
			}
			return err
		}
	}
	return nil
}

// Record returns a single record by seq (contracts.ErrNotFound if absent): the first line, in
// file order, of the last segment whose first seq is <= seq, that parses with that seq. Like
// Scan it is lenient; Verify is authoritative.
//
// The segment is found through the cached first seq of each segment, the line through the
// segment's line-offset index (index.go), so that a lookup costs O(log n) once the index is
// built. The line read is re-checked; whenever the index cannot answer with certainty the
// segment is read from its start instead.
func (s *Store) Record(seq uint64) (model.Envelope, model.Body, error) {
	views, err := s.readerSegments(true)
	if err != nil {
		return model.Envelope{}, model.Body{}, err
	}
	if len(views) > 0 {
		v := views[s.findStart(views, seq)]
		env, body, res := s.recordIndexed(v, seq)
		switch res {
		case lookupFound:
			return env, body, nil
		case lookupUnsure:
			env, body, found, err := recordScan(v, seq)
			if err != nil {
				return model.Envelope{}, model.Body{}, err
			}
			if found {
				return env, body, nil
			}
		}
	}
	return model.Envelope{}, model.Body{}, fmt.Errorf("ledger: record %d: %w", seq, contracts.ErrNotFound)
}

// recordScan reads segment v from its start and returns the first line, in file order, that
// parses with seq. It is the reference that the line index accelerates (it does not stop at a
// larger seq: in a damaged or tampered segment the order of seqs proves nothing).
func recordScan(v segView, seq uint64) (env model.Envelope, body model.Body, found bool, err error) {
	err = scanView(v, func(line []byte) error {
		if q, _, ok := quickSeqTS(line); ok && q != seq {
			return nil
		}
		e, b, perr := parseRecordLenient(line)
		if perr != nil || b.Seq != seq {
			return nil
		}
		env, body, found = e, b, true
		return errStopScan
	})
	if errors.Is(err, errStopScan) {
		err = nil
	}
	return env, body, found, err
}

// findStart returns the index of the last segment whose first record has seq <= seq.
func (s *Store) findStart(views []segView, seq uint64) int {
	for i := len(views) - 1; i >= 0; i-- {
		v := views[i]
		if v.writerActive {
			// The writer knows its active segment's first record: no file access needed.
			if v.firstSeq <= seq {
				return i
			}
			continue
		}
		m, err := s.segmentMeta(v, false)
		if err == nil && m.haveFirst && m.firstSeq <= seq {
			return i
		}
	}
	return 0
}

// Segments describes every segment (Records counts lines). The writer knows its active segment;
// first/last seq and record count of every other segment come from the metadata cache
// (segmentMeta), so a sealed compressed segment is decompressed once per version of its file —
// and not at all when this store compressed it — rather than on every call. Segments whose
// metadata is not cached yet are read in parallel.
func (s *Store) Segments() ([]contracts.SegmentInfo, error) {
	views, err := s.readerSegments(true)
	if err != nil {
		return nil, err
	}
	var act activeSeg
	isWriter := false
	if !s.readOnly {
		s.mu.Lock()
		if s.active != nil {
			act, isWriter = *s.active, true
		}
		s.mu.Unlock()
	}
	own := func(v segView) bool { return isWriter && v.Name == act.name }
	metas, errs := s.segmentMetas(views, own)
	out := make([]contracts.SegmentInfo, 0, len(views))
	for i, v := range views {
		info := contracts.SegmentInfo{
			Name: v.Name, Path: v.path(), Date: v.Date, Compressed: v.compressed(), Active: v.last,
		}
		switch {
		case own(v):
			info.FirstSeq, info.LastSeq, info.Records = act.firstSeq, act.lastSeq, act.records
		case errs[i] == nil:
			m := metas[i]
			info.FirstSeq, info.LastSeq, info.Records = m.firstSeq, m.lastSeq, m.lines
		default:
			s.log.Warn("segment metadata", "segment", v.Name, "err", errs[i])
		}
		out = append(out, info)
	}
	return out, nil
}

// maxMetaWorkers bounds the segments whose metadata segmentMetas reads at the same time.
const maxMetaWorkers = 8

// segmentMetas returns the full metadata of every view not skipped, reading the segments that are
// not cached in parallel.
func (s *Store) segmentMetas(views []segView, skip func(segView) bool) ([]segMeta, []error) {
	metas := make([]segMeta, len(views))
	errs := make([]error, len(views))
	sem := make(chan struct{}, max(1, min(runtime.GOMAXPROCS(0), maxMetaWorkers)))
	var wg sync.WaitGroup
	for i, v := range views {
		if skip(v) {
			continue
		}
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() {
				<-sem
				wg.Done()
			}()
			metas[i], errs[i] = s.segmentMeta(v, true)
		}()
	}
	wg.Wait()
	return metas, errs
}

// OpenSegment returns the uncompressed bytes of a segment by name ("ledger-YYYY-MM-DD"; an
// extension is tolerated). For the latest segment only complete lines are returned.
func (s *Store) OpenSegment(name string) (io.ReadCloser, error) {
	n, _, ok := parseSegmentName(name)
	if !ok {
		return nil, fmt.Errorf("ledger: invalid segment name %q: %w", name, contracts.ErrNotFound)
	}
	views, err := s.readerSegments(true)
	if err != nil {
		return nil, err
	}
	for _, v := range views {
		if v.Name == n {
			return openSegmentFile(v.segFile, v.limit)
		}
	}
	return nil, fmt.Errorf("ledger: segment %s: %w", n, contracts.ErrNotFound)
}

// ---------------------------------------------------------------- metadata cache

// segMeta caches facts about a segment file, keyed by path and validated by size and mtime.
// For a growing plain file the line count is extended incrementally.
type segMeta struct {
	size      int64
	mod       time.Time
	scanned   int64 // plain: bytes whose lines are counted
	lines     int
	counted   bool // lines/lastSeq are valid
	firstSeq  uint64
	haveFirst bool
	lastSeq   uint64
	haveLast  bool
	// fullErr: a compressed segment's content could not be read completely (it is damaged). It is
	// returned for this version of the file instead of decompressing it again on every call; the
	// first seq stays usable when it was read.
	fullErr error
}

// segmentMeta returns cached metadata, computing what is missing. Without full only the first
// seq is guaranteed. An entry is valid while its file keeps the size and modification time it
// was computed for.
func (s *Store) segmentMeta(v segView, full bool) (segMeta, error) {
	path := v.path()
	st, err := os.Stat(path)
	if err != nil {
		return segMeta{}, err
	}
	s.cacheMu.Lock()
	m, ok := s.meta[path]
	s.cacheMu.Unlock()
	fresh := ok && m.size == st.Size() && m.mod.Equal(st.ModTime())
	switch {
	case fresh && full && m.fullErr != nil:
		return segMeta{}, m.fullErr
	case fresh && (m.counted || !full):
		return m, nil
	}
	if v.compressed() {
		if full {
			s.metaGzReads.Add(1)
		}
		m, err = metaCompressed(v.segFile, full)
	} else {
		m, err = metaPlain(path, m, ok, full)
	}
	if err != nil {
		// Only a fault of the content is a property of this version of the file; an operating
		// system error (sharing violation, I/O error) may pass.
		var pe *fs.PathError
		if !v.compressed() || !full || errors.As(err, &pe) {
			return segMeta{}, err
		}
		m.counted, m.fullErr = false, err
	}
	m.size, m.mod = st.Size(), st.ModTime()
	s.cacheMu.Lock()
	s.meta[path] = m
	s.cacheMu.Unlock()
	if err != nil {
		return segMeta{}, err
	}
	return m, nil
}

func metaPlain(path string, prev segMeta, havePrev, full bool) (segMeta, error) {
	f, err := openShared(path)
	if err != nil {
		return segMeta{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return segMeta{}, err
	}
	end, err := completeSize(f, st.Size())
	if err != nil {
		return segMeta{}, err
	}
	m := prev
	if !havePrev || m.scanned > end {
		m = segMeta{}
	}
	if !m.haveFirst && end > 0 {
		rec, err := newLineReader(io.NewSectionReader(f, 0, end), 16<<10).next()
		if err == nil && rec.complete && !rec.tooLong {
			m.firstSeq, m.haveFirst = lineSeq(rec.data)
		}
	}
	if !full {
		// lines/lastSeq describe an older size; keep them only as the base for counting on.
		m.counted = false
		return m, nil
	}
	buf := make([]byte, readBufSize)
	r := io.NewSectionReader(f, m.scanned, end-m.scanned)
	for {
		n, err := r.Read(buf)
		m.lines += bytes.Count(buf[:n], []byte{'\n'})
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return segMeta{}, err
		}
	}
	m.scanned = end
	if line, _, ok, err := lastCompleteLine(f, end); err == nil && ok {
		m.lastSeq, m.haveLast = lineSeq(line)
	}
	m.counted = true
	return m, nil
}

// metaCompressed reads the metadata of a compressed segment (without full: up to its first
// line). On a read error it also returns what it learned before (the first seq, if read).
func metaCompressed(f segFile, full bool) (segMeta, error) {
	rc, err := openSegmentFile(f, -1)
	if err != nil {
		return segMeta{}, err
	}
	defer rc.Close()
	lr := newLineReader(rc, readBufSize)
	var m segMeta
	var last []byte
	for {
		rec, err := lr.next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return m, err
		}
		if !rec.complete {
			continue
		}
		m.lines++
		if rec.tooLong {
			last = nil
			continue
		}
		if m.lines == 1 {
			m.firstSeq, m.haveFirst = lineSeq(rec.data)
			if !full {
				return m, nil
			}
		}
		last = append(last[:0], rec.data...)
	}
	if last != nil {
		m.lastSeq, m.haveLast = lineSeq(last)
	}
	m.counted = true
	return m, nil
}

// tsMeta caches the earliest record ts of a segment file, validated by size and mtime (sealed
// segments never change, so it is computed once per file).
type tsMeta struct {
	size     int64
	mod      time.Time
	earliest time.Time
}

// noTS sorts after every real record time: a segment without a readable ts holds nothing that
// ScanTime could return.
var noTS = time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)

// segmentMinTS returns the earliest ts of the complete records of a segment. ok=false means
// it could not be determined (the caller then reads the segment).
func (s *Store) segmentMinTS(v segView) (time.Time, bool) {
	path := v.path()
	st, err := os.Stat(path)
	if err != nil {
		return time.Time{}, false
	}
	s.cacheMu.Lock()
	m, ok := s.minTS[path]
	s.cacheMu.Unlock()
	if ok && m.size == st.Size() && m.mod.Equal(st.ModTime()) {
		return m.earliest, true
	}
	earliest := noTS
	err = scanView(v, func(line []byte) error {
		var t time.Time
		var perr error
		if _, ts, ok := quickSeqTS(line); ok {
			t, perr = time.Parse(time.RFC3339Nano, string(ts))
		}
		if t.IsZero() || perr != nil {
			_, body, err := parseRecordLenient(line)
			if err != nil {
				return nil
			}
			if t, perr = time.Parse(time.RFC3339Nano, body.TS); perr != nil {
				return nil
			}
		}
		if t.Before(earliest) {
			earliest = t
		}
		return nil
	})
	if err != nil {
		return time.Time{}, false
	}
	s.cacheMu.Lock()
	s.minTS[path] = tsMeta{size: st.Size(), mod: st.ModTime(), earliest: earliest}
	s.cacheMu.Unlock()
	return earliest, true
}

// refreshReadOnlyHead re-reads the last record of a read-only store when the latest segment
// changed since the previous call.
func (s *Store) refreshReadOnlyHead() {
	files, err := listSegmentFiles(s.ledgerDir)
	if err != nil || len(files) == 0 {
		return
	}
	last := files[len(files)-1]
	path := last.path()
	st, err := os.Stat(path)
	if err != nil {
		return
	}
	key := fmt.Sprintf("%s|%d|%d", path, st.Size(), st.ModTime().UnixNano())
	s.roMu.Lock()
	defer s.roMu.Unlock()
	if key == s.roHeadKey {
		return
	}
	var line []byte
	if last.Plain != "" {
		f, err := openShared(path)
		if err != nil {
			return
		}
		line, _, _, err = lastCompleteLine(f, st.Size())
		f.Close()
		if err != nil {
			return
		}
	} else {
		_ = scanView(segView{segFile: last, limit: -1}, func(l []byte) error {
			line = append(line[:0], l...)
			return nil
		})
	}
	if line == nil {
		return
	}
	env, body, err := parseRecordLenient(line)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.head = model.Ref{Seq: body.Seq, Hash: sha256Hex([]byte(env.B)), TS: body.TS}
	s.mu.Unlock()
	s.roHeadKey = key
}
