package ledger

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// validRecordType accepts lowercase identifiers such as "gateway_snapshot".
func validRecordType(t string) bool {
	if t == "" || len(t) > 64 {
		return false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// Append JSON-encodes data, chains, signs, writes and fsyncs one record. Every blob id in
// blobs must already be in the blob store. The genesis and segment_open types are reserved
// for the ledger itself.
func (s *Store) Append(recordType string, data any, blobs ...string) (model.Ref, error) {
	if s.readOnly {
		return model.Ref{}, ErrReadOnly
	}
	if !validRecordType(recordType) {
		return model.Ref{}, fmt.Errorf("ledger: invalid record type %q", recordType)
	}
	if recordType == model.TypeGenesis || recordType == model.TypeSegmentOpen {
		return model.Ref{}, fmt.Errorf("ledger: record type %q is reserved for the ledger itself", recordType)
	}
	raw, err := marshalJSON(data)
	if err != nil {
		return model.Ref{}, fmt.Errorf("ledger: encode %s data: %w", recordType, err)
	}
	ids, err := s.checkBlobRefs(blobs)
	if err != nil {
		return model.Ref{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return model.Ref{}, ErrClosed
	}
	return s.appendLocked(recordType, raw, ids)
}

// brokenErrLocked returns the error of every write refused because an earlier failed write could
// not be rolled back (nil while the store is usable). It wraps contracts.ErrLedgerBroken. s.mu
// must be held.
func (s *Store) brokenErrLocked() error {
	if s.broken == nil {
		return nil
	}
	return fmt.Errorf("ledger: refusing to write (reopen the ledger to recover): %w", s.broken)
}

// checkBlobRefs validates and de-duplicates blob ids and checks that each blob exists.
func (s *Store) checkBlobRefs(blobs []string) ([]string, error) {
	if len(blobs) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(blobs))
	seen := make(map[string]bool, len(blobs))
	for _, id := range blobs {
		if !isBlobID(id) {
			return nil, fmt.Errorf("ledger: invalid blob id %q", id)
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		if !s.HasBlob(id) {
			return nil, fmt.Errorf("ledger: referenced blob %s does not exist (PutBlob it first): %w", id, contracts.ErrNotFound)
		}
		out = append(out, id)
	}
	return out, nil
}

// appendLocked chains, signs, writes and fsyncs one record. s.mu must be held. Nothing is written
// once a failed write could not be rolled back (s.broken): not even a rotation, whose sealing hash
// would commit to the partial line.
func (s *Store) appendLocked(typ string, data []byte, blobs []string) (model.Ref, error) {
	if err := s.brokenErrLocked(); err != nil {
		return model.Ref{}, err
	}
	now := s.now().UTC()
	if err := s.prepareSegmentLocked(now); err != nil {
		return model.Ref{}, err
	}
	// The rotation appends its own integrity_alert, which may be the write that broke the store.
	if err := s.brokenErrLocked(); err != nil {
		return model.Ref{}, err
	}
	body := model.Body{
		V:     model.FormatVersion,
		Seq:   s.nextSeq,
		Prev:  s.head.Hash,
		TS:    now.Format(time.RFC3339Nano),
		Mono:  s.MonoNow(),
		Run:   s.runID,
		Type:  typ,
		Blobs: blobs,
		Data:  json.RawMessage(data),
	}
	line, hash, err := encodeRecord(s.priv, &body)
	if err != nil {
		return model.Ref{}, err
	}
	if err := s.writeLineLocked(line); err != nil {
		return model.Ref{}, err
	}
	ref := model.Ref{Seq: body.Seq, Hash: hash, TS: body.TS}
	s.head = ref
	s.nextSeq = body.Seq + 1
	s.active.records++
	s.active.lastSeq = body.Seq
	return ref, nil
}

// prepareSegmentLocked rotates when the record's UTC date is later than the active segment's.
// An older date (clock went backwards) keeps writing to the current segment: older segments are
// never reopened. The step itself is evidence: within a run the monitor records it (clock_jump),
// a clock found behind the newest record on open is recorded by Open (integrity_alert), and
// verification reports ts that go backwards or contradict trusted time-stamps (timecheck.go).
func (s *Store) prepareSegmentLocked(now time.Time) error {
	d := utcDate(now)
	switch {
	case d.After(s.active.date):
		return s.rotateLocked(now)
	case d.Before(s.active.date):
		if s.clockWarned.IsZero() || time.Since(s.clockWarned) > time.Hour {
			s.clockWarned = time.Now()
			s.log.Warn("wall clock is behind the active segment's date; continuing in the current segment",
				"now", now.Format(time.RFC3339Nano), "segment", s.active.name)
		}
	}
	return nil
}

// writeLineLocked writes one complete line at the end of the active segment and fsyncs it.
// On failure the segment is truncated back so that no partial line remains. When that rollback
// fails too, the store is broken (sticky, contracts.ErrLedgerBroken): the returned error and every
// later write's error wrap it, until the ledger is reopened and crash recovery quarantines the
// partial line.
func (s *Store) writeLineLocked(line []byte) error {
	a := s.active
	n, err := writeAt(a.f, line, a.size)
	if err == nil && n != len(line) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = a.f.Sync()
	}
	if err != nil {
		if terr := a.f.Truncate(a.size); terr != nil {
			s.broken = fmt.Errorf("%w: writing to %s failed (%w) and truncating the partial line failed (%v)", contracts.ErrLedgerBroken, a.name, err, terr)
		} else if serr := a.f.Sync(); serr != nil {
			s.broken = fmt.Errorf("%w: writing to %s failed (%w) and syncing the rollback failed (%v)", contracts.ErrLedgerBroken, a.name, err, serr)
		}
		if s.broken != nil {
			return fmt.Errorf("ledger: %w", s.broken)
		}
		return fmt.Errorf("ledger: write to %s: %w", a.name, err)
	}
	a.size += int64(len(line))
	return nil
}

// writeAt writes a line to the active segment (a variable so that tests can make it fail).
var writeAt = (*os.File).WriteAt

// rotateLocked seals the active segment and starts a new one whose first record is
// segment_open, committing to the SHA-256 of the sealed segment's complete bytes.
func (s *Store) rotateLocked(now time.Time) error {
	old := s.active
	name := segmentName(now)
	path := filepath.Join(s.ledgerDir, name+segExt)
	if _, err := os.Lstat(path); err == nil {
		// We hold the writer lock and never reopen older segments, so the file is either
		// foreign or left by our own earlier attempt whose new file could not be opened.
		// Preserve it in quarantine rather than failing every append today; the
		// integrity_alert follows the next successful rotation.
		origin, suffix := "existed before this ledger created it", ".foreign"
		if path == s.unopened {
			origin, suffix = "was created by an earlier rotation attempt of this writer, but could not be opened afterwards (its only record was never followed)", ".unopened"
		}
		q, err := s.quarantineMove(path, name+segExt+suffix)
		if err != nil {
			return fmt.Errorf("ledger: cannot rotate: %s exists and cannot be moved to quarantine: %w", path, err)
		}
		s.unopened = ""
		s.log.Error("a file already existed in place of a new segment; moved to quarantine", "segment", name, "quarantine", q)
		s.pendingAlerts = append(s.pendingAlerts, fmt.Sprintf("%s %s; it was moved to %s", name+segExt, origin, q))
	}
	sum, lines, size, err := hashLines(old.f)
	if err != nil {
		return fmt.Errorf("ledger: hash sealed segment %s: %w", old.name, err)
	}
	if size != old.size {
		s.log.Error("sealed segment size differs from the writer's record", "segment", old.name, "file_bytes", size, "written_bytes", old.size)
	}
	so := model.SegmentOpen{
		Segment:            name,
		PrevSegment:        old.name,
		PrevSegmentSHA256:  sum,
		PrevSegmentRecords: lines,
		PrevSegmentLastSeq: s.head.Seq,
	}
	data, err := marshalJSON(&so)
	if err != nil {
		return err
	}
	body := model.Body{
		V:    model.FormatVersion,
		Seq:  s.nextSeq,
		Prev: s.head.Hash,
		TS:   now.Format(time.RFC3339Nano),
		Mono: s.MonoNow(),
		Run:  s.runID,
		Type: model.TypeSegmentOpen,
		Data: json.RawMessage(data),
	}
	line, hash, err := encodeRecord(s.priv, &body)
	if err != nil {
		return err
	}
	f, err := createSegmentFile(path, line)
	if err != nil {
		var nerr *segmentNotOpenedError
		if errors.As(err, &nerr) {
			s.unopened = path // complete, but ours only on paper: described as such next time
		}
		return err
	}
	if err := old.f.Sync(); err != nil {
		s.log.Warn("sync sealed segment", "segment", old.name, "err", err)
	}
	if err := old.f.Close(); err != nil {
		s.log.Warn("close sealed segment", "segment", old.name, "err", err)
	}
	s.active = &activeSeg{
		name: name, date: utcDate(now), path: path, f: f,
		size: int64(len(line)), records: 1, firstSeq: body.Seq, lastSeq: body.Seq,
	}
	s.head = model.Ref{Seq: body.Seq, Hash: hash, TS: body.TS}
	s.nextSeq = body.Seq + 1
	s.log.Info("ledger segment sealed", "sealed", old.name, "sha256", sum, "records", lines, "next", name)
	if len(s.pendingAlerts) > 0 {
		alert := model.IntegrityAlert{Problem: "a file already existed where a new segment was to be created", Details: capDetails(s.pendingAlerts)}
		if data, err := marshalJSON(&alert); err == nil {
			if _, err := s.appendLocked(model.TypeIntegrityAlert, data, nil); err != nil {
				s.log.Error("append integrity_alert", "err", err)
			} else {
				s.pendingAlerts = nil
			}
		}
	}
	return nil
}

// hashLines returns the SHA-256 and number of '\n'-terminated lines of the complete file.
func hashLines(f *os.File) (sum string, lines int, size int64, err error) {
	st, err := f.Stat()
	if err != nil {
		return "", 0, 0, err
	}
	size = st.Size()
	h := sha256.New()
	buf := make([]byte, readBufSize)
	r := io.NewSectionReader(f, 0, size)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
			for _, c := range buf[:n] {
				if c == '\n' {
					lines++
				}
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", 0, 0, err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), lines, size, nil
}

// createSegmentFile creates path atomically with firstLine as its only content (temporary
// file, fsync, rename without replacing) and returns it opened for the writer. A segment file
// therefore never appears without a complete first record.
func createSegmentFile(path string, firstLine []byte) (*os.File, error) {
	tmp := path + tmpExt
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if errors.Is(err, os.ErrExist) {
		// Only our own failed attempt can leave it at run time (Open quarantines older ones).
		if err := os.Remove(tmp); err != nil {
			return nil, fmt.Errorf("ledger: remove stale %s: %w", tmp, err)
		}
		f, err = os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	}
	if err != nil {
		return nil, fmt.Errorf("ledger: create segment: %w", err)
	}
	_, err = f.Write(firstLine)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = renameNoReplace(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
		return nil, fmt.Errorf("ledger: create segment %s: %w", filepath.Base(path), err)
	}
	af, err := openAfterCreate(path)
	if err != nil {
		return nil, &segmentNotOpenedError{path: path, err: err}
	}
	return af, nil
}

// openAfterCreate opens a segment that was just renamed into place (a variable so that tests
// can make it fail).
var openAfterCreate = openExclusiveRW

// segmentNotOpenedError reports a new segment that is in place, complete with its first
// record, but could not be opened for appending.
type segmentNotOpenedError struct {
	path string
	err  error
}

func (e *segmentNotOpenedError) Error() string {
	return fmt.Sprintf("ledger: open new segment %s: %v", filepath.Base(e.path), e.err)
}

func (e *segmentNotOpenedError) Unwrap() error { return e.err }

// createGenesisLocked writes the genesis record (seq 0) into a new segment.
func (s *Store) createGenesisLocked() error {
	now := s.now().UTC()
	name := segmentName(now)
	path := filepath.Join(s.ledgerDir, name+segExt)
	g := model.Genesis{
		PublicKey:   base64.StdEncoding.EncodeToString(s.pub),
		Fingerprint: s.fp,
		Created:     now.Format(time.RFC3339Nano),
		Host:        s.opts.Host,
		Software:    s.opts.Software,
		Statement:   s.opts.Statement,
	}
	data, err := marshalJSON(&g)
	if err != nil {
		return err
	}
	body := model.Body{
		V:    model.FormatVersion,
		Seq:  0,
		Prev: model.ZeroHash,
		TS:   now.Format(time.RFC3339Nano),
		Mono: s.MonoNow(),
		Run:  s.runID,
		Type: model.TypeGenesis,
		Data: json.RawMessage(data),
	}
	line, hash, err := encodeRecord(s.priv, &body)
	if err != nil {
		return err
	}
	f, err := createSegmentFile(path, line)
	if err != nil {
		return err
	}
	s.active = &activeSeg{
		name: name, date: utcDate(now), path: path, f: f,
		size: int64(len(line)), records: 1, firstSeq: 0, lastSeq: 0,
	}
	s.head = model.Ref{Seq: 0, Hash: hash, TS: body.TS}
	s.nextSeq = 1
	s.genesisTS = body.TS
	s.created = true
	s.log.Info("ledger created", "segment", name, "fingerprint", s.fp)
	return nil
}
