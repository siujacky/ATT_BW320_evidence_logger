package connstore

import (
	"fmt"
	"os"
	"slices"
	"time"

	"attmonitor/internal/model"
)

// writer is a plain file being appended to.
type writer struct {
	kind  kind
	day   day
	name  string
	path  string
	f     *os.File
	size  int64 // committed: complete, synced lines
	dirty bool  // a failed write may have left bytes after size
}

// AppendNAT adds one NAT table read, made at t (the zero time: now), to the file of t's UTC
// day; the line is written and fsynced before it returns. The first append of a new day
// compresses the days before it, and an append applies the retention limits at most once an
// hour (a failure of either is logged and shows in Usage, not here).
func (s *Store) AppendNAT(t time.Time, nat model.NATTable) error {
	t = s.when(t).UTC()
	if !validTime(t) {
		return fmt.Errorf("connstore: a NAT table read at %s: the time is outside the years 2000-2199", formatTime(t))
	}
	line, err := encodeNAT(t, nat)
	if err != nil {
		s.noteResult(opAppend(kindNAT), err)
		return err
	}
	return s.append(kindNAT, t, line, nil)
}

// AppendDevices adds one Device List read, made at t (the zero time: now), like AppendNAT. It
// becomes the read Devices returns unless that one is newer - and not dated after now: a read
// made while the clock was ahead gives way to the reads stored once it was corrected.
func (s *Store) AppendDevices(t time.Time, devices []model.LANDevice) error {
	t = s.when(t).UTC()
	if !validTime(t) {
		return fmt.Errorf("connstore: a Device List read at %s: the time is outside the years 2000-2199", formatTime(t))
	}
	line, err := encodeDevices(t, devices)
	if err != nil {
		s.noteResult(opAppend(kindDevices), err)
		return err
	}
	kept := cloneDevices(devices)
	if kept == nil {
		kept = []model.LANDevice{}
	}
	now := s.now()
	return s.append(kindDevices, t, line, func() {
		if s.devices == nil || !t.Before(s.devicesAt) || s.devicesAt.After(now) {
			s.devices, s.devicesAt = kept, t
		}
	})
}

// opAppend names the appends of a kind in Usage().Error.
func opAppend(k kind) string { return "append " + k.String() }

// append writes line, a read made at t, to the file of kind k for t's day; done runs (s.mu
// held) once it is written.
func (s *Store) append(k kind, t time.Time, line []byte, done func()) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.closed {
		return ErrClosed
	}
	s.retryPending()
	d := dayOf(t)
	err := s.writeLine(k, d, line)
	s.noteResult(opAppend(k), err)
	if err != nil {
		return err
	}
	now := s.now()
	s.mu.Lock()
	if s.oldest.IsZero() || t.Before(s.oldest) {
		s.oldest = t
	}
	if t.After(s.newest) {
		s.newest = t
	}
	if done != nil {
		done()
	}
	due := s.lastPrune.IsZero() || now.Sub(s.lastPrune) >= pruneEvery || now.Before(s.lastPrune)
	s.mu.Unlock()
	s.compressBefore(d, false)
	if due {
		s.noteResult(opPrune, s.prune(now))
	}
	return nil
}

// writeLine appends line to the plain file of kind k and day d. The file of the newest day is
// kept open between appends; a read of an earlier day goes to that day's file all the same - next
// to its compressed file if the day was compressed already, until the day is compressed again -
// so that every file only ever holds the reads of its own day (s.wmu held).
//
// When the file kept open is of a day after today, the clock was ahead when it was written and
// has been corrected since (or it has been set back over midnight UTC): the writer moves to the
// file of the read's day, once, with a warning. The day after today keeps its reads; it is
// compressed, and may be pruned, once it is over.
func (s *Store) writeLine(k kind, d day, line []byte) error {
	w := s.w[k]
	switch {
	case w != nil && w.day == d:
	case w == nil || d > w.day || w.day > dayOf(s.now()):
		if w != nil {
			if d < w.day {
				s.log.Warn("connection store: the file of a day after today was being written (the clock was ahead, or has been set back over midnight UTC); the reads go to the files of their own days again",
					"file", w.name, "day", d.String())
			}
			if err := w.close(); err != nil {
				s.log.Warn("connection store: closing the file of the previous day failed", "file", w.name, "err", err)
			}
			s.w[k] = nil
		}
		nw, err := s.openWriter(k, d)
		if err != nil {
			return err
		}
		s.w[k], w = nw, nw
	default:
		lw, err := s.openWriter(k, d)
		if err != nil {
			return err
		}
		defer lw.close()
		w = lw
		s.log.Info("connection store: a read of an earlier day than the newest was stored in that day's file",
			"file", lw.name)
	}
	return s.write(w, line)
}

// openWriter opens the plain file of kind k and day d for appending, creating it when needed.
// Bytes after the complete lines the index knows (a write that failed, a line a crash cut short)
// are cut off before the first write. A file the index does not know, or one shorter than the
// store wrote it (another program deleted or cut it), counts its complete lines: nothing is ever
// written beyond the end of a file (s.wmu held).
func (s *Store) openWriter(k kind, d day) (*writer, error) {
	name := fileName(k, d, false)
	path := s.path(k, d, false)
	if slices.Contains(s.pending, path) {
		return nil, fmt.Errorf("connstore: %s cannot be written before its older copy, compressed already, is deleted (another program holds it)", name)
	}
	f, err := openWriter(path)
	if err != nil {
		return nil, fmt.Errorf("connstore: open %s: %w", name, err)
	}
	fail := func(err error) (*writer, error) {
		f.Close()
		return nil, fmt.Errorf("connstore: open %s: %w", name, err)
	}
	st, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	s.mu.Lock()
	committed := s.indexed(k, d).plain
	s.mu.Unlock()
	if committed < 0 || st.Size() < committed {
		if committed >= 0 {
			s.log.Warn("connection store: a day's file is shorter than the store wrote it; its complete lines are kept",
				"file", name, "bytes", st.Size(), "written", committed)
		}
		if committed, _, err = completeLines(f); err != nil {
			return fail(err)
		}
	}
	s.mu.Lock()
	s.indexed(k, d).plain = committed
	s.mu.Unlock()
	return &writer{kind: k, day: d, name: name, path: path, f: f, size: committed, dirty: st.Size() != committed}, nil
}

// write appends line to w's file and fsyncs it. When that fails, the file is cut back to its
// committed size (or, when even that fails, marked to be cut back before anything else is
// written) and the line counts as not written (s.wmu held).
func (s *Store) write(w *writer, line []byte) error {
	if err := w.cutBack(); err != nil {
		return fmt.Errorf("connstore: write %s: %w", w.name, err)
	}
	_, err := w.f.WriteAt(line, w.size)
	if err == nil {
		err = w.f.Sync()
	}
	if err != nil {
		w.dirty = true
		if w.cutBack() != nil {
			s.log.Error("connection store: could not cut back a file after a failed write; it is tried again before the next write",
				"file", w.name)
		}
		return fmt.Errorf("connstore: write %s: %w", w.name, err)
	}
	w.size += int64(len(line))
	s.mu.Lock()
	s.indexed(w.kind, w.day).plain = w.size
	s.mu.Unlock()
	return nil
}

// cutBack removes what a failed write may have left after the committed content.
func (w *writer) cutBack() error {
	if !w.dirty {
		return nil
	}
	err := w.f.Truncate(w.size)
	if err == nil {
		err = w.f.Sync()
	}
	if err != nil {
		return err
	}
	w.dirty = false
	return nil
}

// close closes the file.
func (w *writer) close() error {
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}

// retryPending deletes the files that could not be deleted before (s.wmu held).
func (s *Store) retryPending() {
	if len(s.pending) == 0 {
		return
	}
	var keep []string
	for _, p := range s.pending {
		if err := removeFile(p); err != nil {
			keep = append(keep, p)
			continue
		}
		s.log.Info("connection store: deleted a file that was in use before", "file", p)
	}
	s.pending = keep
}

// deleteLater deletes path, or - when another program holds it - notes it to be deleted later.
// It reports whether the file is gone (s.wmu held).
func (s *Store) deleteLater(path string) bool {
	if err := removeFile(path); err != nil {
		s.log.Warn("connection store: a file is in use and is deleted later", "file", path, "err", err)
		if !slices.Contains(s.pending, path) {
			s.pending = append(s.pending, path)
		}
		return false
	}
	return true
}
