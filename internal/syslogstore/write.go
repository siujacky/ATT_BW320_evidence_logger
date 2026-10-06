package syslogstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"attmonitor/internal/model"
)

// sealTmp is the temporary file a chunk is compressed into (its name needs the receive time of
// its last message, known only once it has been read).
const sealTmp = "seal" + sealedExt + tmpExt

// line is one message, encoded as stored.
type line struct {
	b  []byte // json.Marshal output and a line feed
	rx time.Time
}

// encodeLines encodes msgs as lines of a chunk. A message whose receive time does not parse is
// left out (bad counts them): Query could never find it.
func encodeLines(msgs []model.SyslogMessage) (lines []line, bad int) {
	lines = make([]line, 0, len(msgs))
	for i := range msgs {
		rx, ok := parseRX(msgs[i].RX)
		if !ok {
			bad++
			continue
		}
		b, err := json.Marshal(&msgs[i])
		if err != nil {
			bad++
			continue
		}
		lines = append(lines, line{b: append(b, '\n'), rx: rx})
	}
	return lines, bad
}

// Append adds msgs (oldest first) to the open chunk and dropped and rejected to its counts,
// and returns the chunks it sealed. A chunk is opened when needed, named after the receive
// time of its first message, or after now when it only carries counts (a chunk may hold no
// message). The lines are written and fsynced before Append returns; whenever the chunk's
// content reaches ChunkBytes it is sealed (reason "size") and a new one is opened, so a batch
// may be split across chunks.
//
// A message whose receive time (RX) does not parse is not stored: it is counted as dropped and
// logged. When writing fails, the messages not written are counted as dropped too (the next
// chunk that holds counts states them), and the error comes with the chunks sealed before it,
// which must be recorded like any other.
func (s *Store) Append(msgs []model.SyslogMessage, dropped, rejected int, now time.Time) ([]model.SyslogChunk, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if err := s.writable(); err != nil {
		return nil, err
	}
	now = s.when(now)
	s.retryPending()
	lines, bad := encodeLines(msgs)
	if bad > 0 {
		s.log.Error("syslog store: messages without a valid receive time were not stored; counted as dropped", "count", bad)
	}
	s.count(max(dropped, 0)+bad, max(rejected, 0))

	var sealed []model.SyslogChunk
	var errs []error
	// sealFailed: the chunk could not be sealed in this call; it takes the rest of the batch.
	sealFailed := false
	trySeal := func() {
		c, err := s.sealOpen(reasonSize)
		if err != nil {
			sealFailed = true
			errs = append(errs, err)
			return
		}
		sealed = append(sealed, *c)
	}
	if s.open != nil && s.open.f != nil && s.open.size >= s.o.ChunkBytes {
		trySeal() // full since an earlier call could not seal it
	}
	if len(lines) == 0 && s.open == nil && s.carried() {
		if err := s.openNew(now, now); err != nil {
			errs = append(errs, err)
		}
	}
	for len(lines) > 0 {
		if s.open == nil {
			if err := s.openNew(lines[0].rx, now); err != nil {
				s.count(len(lines), 0)
				errs = append(errs, err)
				break
			}
		}
		// The lines up to ChunkBytes (all of them when the chunk cannot be sealed now).
		n, size := 0, s.open.size
		for n < len(lines) {
			size += int64(len(lines[n].b))
			n++
			if size >= s.o.ChunkBytes && !sealFailed {
				break
			}
		}
		if err := s.write(lines[:n]); err != nil {
			s.count(len(lines), 0)
			errs = append(errs, err)
			break
		}
		lines = lines[n:]
		if !sealFailed && s.open.size >= s.o.ChunkBytes {
			trySeal()
		}
	}
	if err := s.saveCounts(); err != nil {
		s.log.Warn("syslog store: could not save the open chunk's counts; a crash would lose them", "err", err)
	}
	return sealed, errors.Join(errs...)
}

// count adds counts to the open chunk, or keeps them for the next one (s.wmu held).
func (s *Store) count(dropped, rejected int) {
	if dropped == 0 && rejected == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.open != nil && s.open.f != nil {
		s.open.dropped += dropped
		s.open.rejected += rejected
		return
	}
	s.carryDropped += dropped
	s.carryRejected += rejected
}

// carried reports whether counts wait for a chunk (s.wmu held).
func (s *Store) carried() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.carryDropped > 0 || s.carryRejected > 0
}

// openNew opens a new chunk named after from; ChunkAge counts from now. The chunk takes the
// counts carried so far (s.wmu held).
func (s *Store) openNew(from, now time.Time) error {
	for n := 1; n <= maxSuffix; n++ {
		name := openName(from, n)
		path := filepath.Join(s.dir, name)
		f, err := createExclusive(path)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("syslogstore: open a chunk: %w", err)
		}
		// The file is made durable at once: its state file may name it before any line does.
		if err := f.Sync(); err != nil {
			f.Close()
			os.Remove(path)
			return fmt.Errorf("syslogstore: open a chunk: %w", err)
		}
		oc := &openChunk{name: name, path: path, nameTime: from, opened: now, f: f}
		s.mu.Lock()
		oc.dropped, oc.rejected = s.carryDropped, s.carryRejected
		s.carryDropped, s.carryRejected = 0, 0
		s.open = oc
		s.mu.Unlock()
		return nil
	}
	return fmt.Errorf("syslogstore: open a chunk: every name for %s is taken", compact(from))
}

// write appends lines to the open chunk's file and fsyncs it. When that fails, the file is cut
// back to its last synced size (or, when even that fails, marked to be cut back before
// anything else is written) and the lines count as not written (s.wmu held).
func (s *Store) write(lines []line) error {
	oc := s.open
	if err := oc.cutBack(); err != nil {
		return fmt.Errorf("syslogstore: write %s: %w", oc.name, err)
	}
	total := 0
	for _, l := range lines {
		total += len(l.b)
	}
	buf := make([]byte, 0, total)
	for _, l := range lines {
		buf = append(buf, l.b...)
	}
	_, err := oc.f.WriteAt(buf, oc.size)
	if err == nil {
		err = oc.f.Sync()
	}
	if err != nil {
		oc.dirty = true
		if oc.cutBack() != nil {
			s.log.Error("syslog store: could not cut back the open chunk after a failed write; it is tried again before the next write",
				"chunk", oc.name)
		}
		return fmt.Errorf("syslogstore: write %s: %w", oc.name, err)
	}
	s.mu.Lock()
	oc.size += int64(total)
	oc.messages += len(lines)
	for _, l := range lines {
		if oc.rxMin.IsZero() || l.rx.Before(oc.rxMin) {
			oc.rxMin = l.rx
		}
		if l.rx.After(oc.rxMax) {
			oc.rxMax = l.rx
		}
	}
	s.mu.Unlock()
	return nil
}

// cutBack removes what a failed write may have left after the synced content.
func (oc *openChunk) cutBack() error {
	if !oc.dirty {
		return nil
	}
	err := oc.f.Truncate(oc.size)
	if err == nil {
		err = oc.f.Sync()
	}
	if err != nil {
		return err
	}
	oc.dirty = false
	return nil
}

// saveCounts writes the open chunk's counts to its state file when they changed (s.wmu held).
func (s *Store) saveCounts() error {
	oc := s.open
	if oc == nil || oc.f == nil {
		return nil
	}
	s.mu.Lock()
	dropped, rejected := oc.dropped, oc.rejected
	s.mu.Unlock()
	if dropped == oc.stateDropped && rejected == oc.stateRejected {
		return nil
	}
	if err := writeState(filepath.Join(s.dir, stateName(oc.name)), openState{Dropped: dropped, Rejected: rejected}); err != nil {
		return err
	}
	oc.stateDropped, oc.stateRejected = dropped, rejected
	return nil
}

// Seal seals the open chunk when it is ChunkAge old (counted from its opening) or, with force,
// whenever it holds anything (reason "stop" at shutdown); reason "" means "age", or "stop"
// with force. It returns the sealed chunk, or nil when nothing was sealed.
func (s *Store) Seal(now time.Time, reason string, force bool) (*model.SyslogChunk, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if err := s.writable(); err != nil {
		return nil, err
	}
	now = s.when(now)
	s.retryPending()
	oc := s.open
	if oc == nil || oc.f == nil {
		return nil, nil
	}
	s.mu.Lock()
	holds := oc.holds()
	s.mu.Unlock()
	if !holds || !force && now.Sub(oc.opened) < s.o.ChunkAge {
		return nil, nil
	}
	if reason == "" {
		reason = reasonAge
		if force {
			reason = reasonStop
		}
	}
	return s.sealOpen(reason)
}

// sealOpen seals the open chunk (s.wmu held). Once its compressed file is in place the chunk
// is sealed, whatever fails afterwards: a sidecar that could not be written is rebuilt at the
// next start, and a file that cannot be deleted now is deleted later.
func (s *Store) sealOpen(reason string) (*model.SyslogChunk, error) {
	oc := s.open
	if err := oc.cutBack(); err != nil {
		return nil, fmt.Errorf("syslogstore: seal %s: %w", oc.name, err)
	}
	s.mu.Lock()
	size, dropped, rejected := oc.size, oc.dropped, oc.rejected
	s.mu.Unlock()
	c, err := s.sealContent(io.NewSectionReader(oc.f, 0, size), size, oc.nameTime, dropped, rejected, reason)
	if err != nil {
		return nil, fmt.Errorf("syslogstore: seal %s: %w", oc.name, err)
	}
	if err := oc.f.Close(); err != nil {
		s.log.Warn("syslog store: closing a sealed chunk's open file failed", "chunk", oc.name, "err", err)
	}
	oc.f = nil
	s.mu.Lock()
	s.open = nil
	s.addChunk(c)
	s.mu.Unlock()
	s.removeOpen(oc.name, c.meta.Name)
	s.log.Debug("syslog store: chunk sealed", "chunk", c.meta.Name, "messages", c.meta.Messages,
		"bytes", c.meta.Bytes, "gz_bytes", c.meta.GzBytes, "reason", reason)
	meta := c.meta
	return &meta, nil
}

// sealContent stores the size bytes that src holds as a sealed chunk: compressed into a
// temporary file, checked, fsynced and renamed to syslog-<from>_<to>.jsonl.gz; then its
// sidecar is written. opened is From and To when no message has a receive time. It returns
// the chunk's index entry, not yet added (s.wmu held).
func (s *Store) sealContent(src io.Reader, size int64, opened time.Time, dropped, rejected int, reason string) (*chunk, error) {
	tmp := filepath.Join(s.dir, sealTmp)
	dg, gzBytes, err := writeGzip(tmp, src)
	if err != nil {
		return nil, err
	}
	if dg.bytes != size {
		os.Remove(tmp)
		return nil, fmt.Errorf("read %d bytes of the chunk's %d", dg.bytes, size)
	}
	from, to := dg.sum.span(opened)
	name, err := s.freeName(from, to)
	if err != nil {
		os.Remove(tmp)
		return nil, err
	}
	path := filepath.Join(s.dir, name)
	if err := renameNoReplace(tmp, path); err != nil {
		os.Remove(tmp)
		return nil, err
	}
	sc := dg.sidecar(name, from, to, gzBytes, dropped, rejected, reason)
	if err := writeSidecar(path, sc); err != nil {
		s.log.Warn("syslog store: could not write a sealed chunk's sidecar file; it is rebuilt from the chunk at the next start",
			"chunk", name, "err", err)
	}
	return newChunk(sc, path), nil
}

// freeName returns a sealed chunk name for From and To that is neither indexed nor on disk.
func (s *Store) freeName(from, to time.Time) (string, error) {
	for n := 1; n <= maxSuffix; n++ {
		name := sealedName(from, to, n)
		s.mu.Lock()
		_, taken := s.byName[name]
		s.mu.Unlock()
		if taken {
			continue
		}
		if _, err := os.Lstat(filepath.Join(s.dir, name)); errors.Is(err, fs.ErrNotExist) {
			return name, nil
		}
	}
	return "", fmt.Errorf("every chunk name for %s to %s is taken", compact(from), compact(to))
}

// addChunk adds c to the index (s.mu held).
func (s *Store) addChunk(c *chunk) {
	i, _ := slices.BinarySearchFunc(s.chunks, c, chunkCmp)
	s.chunks = slices.Insert(s.chunks, i, c)
	s.byName[c.meta.Name] = c
}

// removeChunk removes c from the index (s.mu held).
func (s *Store) removeChunk(c *chunk) {
	if i := slices.Index(s.chunks, c); i >= 0 {
		s.chunks = slices.Delete(s.chunks, i, i+1)
	}
	delete(s.byName, c.meta.Name)
	delete(s.warned, c.meta.Name)
}

// removeOpen deletes the files of the open chunk open, which is sealed into the chunk sealed
// ("" when it held nothing): its state file first, then the chunk file. A file that cannot be
// deleted now (another program holds it) is deleted later; until then the state file says what
// the chunk was sealed into, so that a crash meanwhile does not have it sealed again (s.wmu
// held).
func (s *Store) removeOpen(open, sealed string) {
	path := filepath.Join(s.dir, open)
	statePath := filepath.Join(s.dir, stateName(open))
	stateErr := removeFile(statePath)
	if err := removeFile(path); err != nil {
		s.log.Warn("syslog store: a sealed chunk's open file is in use and is deleted later", "file", open, "err", err)
		if sealed == "" {
			s.pending = append(s.pending, path, statePath)
			return
		}
		if err := writeState(statePath, openState{Sealed: sealed}); err != nil {
			s.log.Error("syslog store: could not note that a chunk left open was sealed; were the service to stop before the file is deleted, the chunk would be returned by Recover again",
				"file", open, "sealed", sealed, "err", err)
		}
		s.pending = append(s.pending, path, statePath)
		return
	}
	if stateErr != nil {
		s.log.Warn("syslog store: a sealed chunk's state file is in use and is deleted later", "file", stateName(open), "err", stateErr)
		s.pending = append(s.pending, statePath)
	}
}

// retryPending deletes the files that could not be deleted before. A state file stays as long
// as its open chunk's file does, and a sidecar as long as its sealed chunk's file (s.wmu held).
func (s *Store) retryPending() {
	if len(s.pending) == 0 {
		return
	}
	var keep []string
	blocked := map[string]bool{} // open and sealed chunk files still there
	for _, p := range s.pending {
		base := filepath.Base(p)
		if open, ok := openOfState(base); ok && blocked[open] {
			keep = append(keep, p)
			continue
		}
		if chunk, ok := strings.CutSuffix(base, sidecarExt); ok && blocked[chunk] {
			keep = append(keep, p)
			continue
		}
		if err := removeFile(p); err != nil {
			keep = append(keep, p)
			if _, ok := parseOpenName(base); ok {
				blocked[base] = true
			} else if _, _, _, ok := parseSealedName(base); ok {
				blocked[base] = true
			}
			continue
		}
		s.log.Info("syslog store: deleted a file that was in use before", "file", base)
	}
	s.pending = keep
}
