package syslogstore

import (
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

// Recover completes what a previous run left undone; call it once, before the first Append, and
// again, if it failed (a chunk left open that another program held), until it succeeds - it
// leaves the chunk this run opened alone. It returns the chunks to record, oldest first. For
// every crash point:
//
//   - temporary files (a chunk or sidecar being written) are deleted: the chunk they belonged
//     to is still open, or its sidecar is rebuilt;
//   - an open chunk left over is sealed (reason "recovered", with the counts its state file
//     kept), after a last line without a line feed - a write the crash cut short - is cut off
//     (logged with its size);
//   - an open chunk whose sealing was interrupted once its compressed file was in place (a
//     sealed chunk with the same From, To and SHA-256 exists) is not sealed again: its file is
//     deleted and the sealed chunk is returned, as its sealing never returned it (a sidecar
//     rebuilt meanwhile gets the counts of the state file);
//   - an open chunk that was sealed already but could not be deleted (its state file names the
//     chunk) is only deleted;
//   - an open chunk that holds nothing is deleted;
//   - a state file without its open chunk, and a sidecar without its chunk, are deleted.
//
// Sidecars that were missing or damaged were rebuilt by New. The time is not needed: a chunk
// left over is described by its own receive times.
func (s *Store) Recover(time.Time) ([]model.SyslogChunk, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if err := s.writable(); err != nil {
		return nil, err
	}
	s.retryPending()
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("syslogstore: %w", err)
	}
	current := ""
	if s.open != nil {
		current = s.open.name // opened by this run (Append before Recover)
	}
	var opens, states, sidecars []string
	for _, e := range entries {
		name := e.Name()
		if !e.Type().IsRegular() || current != "" && (name == current || name == stateName(current)) {
			continue
		}
		switch _, isOpen := parseOpenName(name); {
		case strings.HasSuffix(name, tmpExt):
			if err := removeFile(filepath.Join(s.dir, name)); err != nil {
				s.log.Warn("syslog store: could not delete a temporary file of an interrupted run", "file", name, "err", err)
			} else {
				s.log.Info("syslog store: deleted a temporary file of an interrupted run", "file", name)
			}
		case isOpen:
			opens = append(opens, name)
		case strings.HasSuffix(name, sealedExt+sidecarExt):
			sidecars = append(sidecars, name)
		default:
			if _, ok := openOfState(name); ok {
				states = append(states, name)
			}
		}
	}
	slices.Sort(opens)
	var out []model.SyslogChunk
	var errs []error
	for _, name := range opens {
		c, err := s.recoverOpen(name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if c != nil {
			out = append(out, *c)
		}
	}
	for _, name := range states {
		open, _ := openOfState(name)
		if _, err := os.Lstat(filepath.Join(s.dir, open)); !errors.Is(err, fs.ErrNotExist) {
			continue // its chunk is still there (it could not be recovered, or is in use)
		}
		s.removeLeftover(name, "the state file of a chunk no longer open")
	}
	for _, name := range sidecars {
		chunkName := strings.TrimSuffix(name, sidecarExt)
		if _, err := os.Lstat(filepath.Join(s.dir, chunkName)); !errors.Is(err, fs.ErrNotExist) {
			continue
		}
		s.removeLeftover(name, "the sidecar of a deleted chunk")
	}
	return out, errors.Join(errs...)
}

// removeLeftover deletes a file left over by an interrupted run (s.wmu held).
func (s *Store) removeLeftover(name, what string) {
	if err := removeFile(filepath.Join(s.dir, name)); err != nil {
		s.log.Warn("syslog store: could not delete "+what+"; trying again later", "file", name, "err", err)
		s.pending = append(s.pending, filepath.Join(s.dir, name))
		return
	}
	s.log.Info("syslog store: deleted "+what, "file", name)
}

// recoverOpen handles the open chunk file name that a previous run left (see Recover). It
// returns the chunk to record, if any (s.wmu held).
func (s *Store) recoverOpen(name string) (*model.SyslogChunk, error) {
	path := filepath.Join(s.dir, name)
	stateFile := stateName(name)
	st, err := readState(filepath.Join(s.dir, stateFile))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		s.log.Warn("syslog store: the state file of a chunk left open cannot be read; its counts are lost",
			"file", stateFile, "err", err)
		st = openState{}
	}
	f, err := openExclusive(path)
	if err != nil {
		return nil, fmt.Errorf("syslogstore: recover %s: %w", name, err)
	}
	defer func() {
		if f != nil {
			f.Close()
		}
	}()
	size, cut, err := completeLines(f)
	if err != nil {
		return nil, fmt.Errorf("syslogstore: recover %s: %w", name, err)
	}
	if cut > 0 {
		err := f.Truncate(size)
		if err == nil {
			err = f.Sync()
		}
		if err != nil {
			s.log.Warn("syslog store: could not cut off the incomplete last line of a chunk left open; it is left out of the chunk",
				"file", name, "bytes", cut, "err", err)
		} else {
			s.log.Warn("syslog store: cut off the incomplete last line of a chunk left open (a write the crash interrupted)",
				"file", name, "bytes", cut)
		}
	}
	d := newDigester()
	if _, err := io.Copy(d, io.NewSectionReader(f, 0, size)); err != nil {
		return nil, fmt.Errorf("syslogstore: recover %s: %w", name, err)
	}
	dg := d.finish()
	opened, _ := parseOpenName(name)
	from, to := dg.sum.span(opened)
	closeFile := func() {
		f.Close()
		f = nil
	}

	if st.Sealed != "" {
		s.mu.Lock()
		c := s.byName[st.Sealed]
		s.mu.Unlock()
		if c == nil || c.meta.SHA256 == dg.sha {
			closeFile()
			s.removeOpen(name, st.Sealed)
			s.log.Info("syslog store: deleted a chunk left open that was sealed already", "file", name, "sealed", st.Sealed)
			return nil, nil
		}
		s.log.Warn("syslog store: a chunk left open differs from the chunk it was sealed into; it is sealed again",
			"file", name, "sealed", st.Sealed)
	} else if twin := s.twin(from, to, dg.sha); twin != nil {
		s.mu.Lock()
		sc, rebuilt := twin.sidecar(), twin.rebuilt
		s.mu.Unlock()
		if rebuilt {
			// The sidecar was written from the chunk file alone; the state file has the counts.
			sc.Dropped, sc.Rejected = st.Dropped, st.Rejected
			if err := writeSidecar(twin.path, sc); err != nil {
				s.log.Warn("syslog store: could not write a sealed chunk's sidecar file", "chunk", twin.meta.Name, "err", err)
			}
			s.mu.Lock()
			twin.meta = sc.SyslogChunk
			twin.rebuilt = false
			s.mu.Unlock()
		}
		closeFile()
		s.removeOpen(name, sc.Name)
		if sc.Recorded > 0 {
			// Its sealing had returned and been recorded; only deleting the open file failed.
			s.log.Info("syslog store: deleted a chunk left open that was sealed and recorded already", "file", name, "chunk", sc.Name)
			return nil, nil
		}
		s.log.Warn("syslog store: completed the sealing of a chunk that a crash interrupted", "file", name, "chunk", sc.Name)
		meta := sc.SyslogChunk
		return &meta, nil
	}

	if dg.bytes == 0 && st.Dropped == 0 && st.Rejected == 0 {
		closeFile()
		s.removeOpen(name, "")
		s.log.Info("syslog store: deleted an empty chunk left open", "file", name)
		return nil, nil
	}
	c, err := s.sealContent(io.NewSectionReader(f, 0, size), size, opened, st.Dropped, st.Rejected, reasonRecovered)
	if err != nil {
		return nil, fmt.Errorf("syslogstore: recover %s: %w", name, err)
	}
	closeFile()
	s.mu.Lock()
	s.addChunk(c)
	s.mu.Unlock()
	s.removeOpen(name, c.meta.Name)
	s.log.Warn("syslog store: sealed a chunk left open by the previous run", "file", name, "chunk", c.meta.Name,
		"messages", c.meta.Messages)
	meta := c.meta
	return &meta, nil
}

// twin returns the sealed chunk with these From, To and SHA-256, if any.
func (s *Store) twin(from, to time.Time, sha string) *chunk {
	f, t := formatRX(from), formatRX(to)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.chunks {
		if c.meta.From == f && c.meta.To == t && c.meta.SHA256 == sha {
			return c
		}
	}
	return nil
}
