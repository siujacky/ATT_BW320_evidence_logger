package connstore

import (
	"fmt"
	"io"
	"os"
	"slices"
)

// opCompress names the compression of a day's file in Usage().Error.
func opCompress(k kind, d day) string { return "compress " + fileName(k, d, false) }

// compressBefore compresses the plain files of both kinds of the days before d: those days are
// over. A day whose compression failed is tried again after compressRetry, or with force (s.wmu
// held).
func (s *Store) compressBefore(d day, force bool) {
	now := s.now()
	for k := range numKinds {
		for _, pd := range s.plainDays(k, d) {
			key := fileKey{kind: k, day: pd}
			if at, ok := s.retryAt[key]; ok && !force && now.Before(at) {
				continue
			}
			err := s.compress(k, pd)
			s.noteResult(opCompress(k, pd), err)
			if err != nil {
				s.retryAt[key] = now.Add(compressRetry)
				s.log.Warn("connection store: a day could not be compressed; it is tried again later",
					"file", fileName(k, pd, false), "err", err)
				continue
			}
			delete(s.retryAt, key)
		}
	}
}

// plainDays returns the days before d that have a plain file of kind k, oldest first.
func (s *Store) plainDays(k kind, before day) []day {
	s.mu.Lock()
	var out []day
	for d, f := range s.files[k] {
		if d < before && f.plain >= 0 {
			out = append(out, d)
		}
	}
	s.mu.Unlock()
	slices.Sort(out)
	return out
}

// compress compresses the plain file of kind k and day d into <prefix><day>.jsonl.gz - after the
// lines of the day's compressed file when there is one already (reads stored after the day was
// compressed, the clock having been set back) - and deletes the plain file. The compressed copy
// is written to a temporary file, checked to decompress to exactly what was written, fsynced and
// renamed into place; the index then lists only the compressed file, so that a reader never
// reads both. A crash before the rename leaves the plain file (and a temporary file Open
// deletes); a crash after it, both files, which Open recognizes. A compressed file that is
// damaged keeps the reads before the damage. A plain file that cannot be deleted now (another
// program holds it) is deleted later (s.wmu held).
func (s *Store) compress(k kind, d day) error {
	f, ok := s.entry(k, d)
	if !ok || f.plain < 0 {
		return nil
	}
	if w := s.w[k]; w != nil && w.day == d {
		if err := w.close(); err != nil {
			s.log.Warn("connection store: closing a day's file failed", "file", w.name, "err", err)
		}
		s.w[k] = nil
	}
	name := fileName(k, d, false)
	plainPath, gzPath := s.path(k, d, false), s.path(k, d, true)
	tmp := gzPath + tmpExt
	var opened []*os.File
	defer func() {
		for _, f := range opened {
			f.Close()
		}
	}()
	open := func(path string) (*os.File, error) {
		f, err := openShared(path)
		if err == nil {
			opened = append(opened, f)
		}
		return f, err
	}
	var old *os.File
	if f.gz >= 0 {
		g, err := open(gzPath)
		if err != nil {
			return fmt.Errorf("connstore: compress %s: %w", name, err)
		}
		old = g
	}
	plain, err := open(plainPath)
	if err != nil {
		return fmt.Errorf("connstore: compress %s: %w", name, err)
	}
	var damage error
	n, gzSize, err := writeGzip(tmp, func(w io.Writer) error {
		if old != nil {
			if damage = copyLines(w, old); damage != nil && isWriteError(damage) {
				return damage
			}
		}
		_, err := io.Copy(w, io.NewSectionReader(plain, 0, f.plain))
		return err
	})
	if err != nil {
		return fmt.Errorf("connstore: compress %s: %w", name, err)
	}
	if damage != nil {
		s.log.Warn("connection store: the compressed file of a day was damaged; the reads before the damage were kept",
			"file", fileName(k, d, true), "err", damage)
	}
	for _, f := range opened {
		f.Close()
	}
	opened = nil
	// Readers wait while the compressed file is replaced and the index does not say so yet.
	s.mu.Lock()
	e := s.indexed(k, d)
	e.gen++
	s.mu.Unlock()
	if err := replaceFile(s.dir, fileName(k, d, true)+tmpExt, fileName(k, d, true)); err != nil {
		os.Remove(tmp)
		s.mu.Lock()
		e.gen++
		s.mu.Unlock()
		return fmt.Errorf("connstore: compress %s: %w", name, err)
	}
	s.mu.Lock()
	e.gz, e.plain = gzSize, -1
	e.gen++
	s.mu.Unlock()
	s.deleteLater(plainPath)
	s.dropCached(k, d)
	s.log.Info("connection store: compressed a day", "file", fileName(k, d, true), "bytes", n, "gz_bytes", gzSize)
	return nil
}

// writeError marks an error of the writer in copyLines (as opposed to damage of the source).
type writeError struct{ error }

func (e writeError) Unwrap() error { return e.error }

// isWriteError reports whether err is a writeError.
func isWriteError(err error) bool {
	_, ok := err.(writeError)
	return ok
}

// copyLines writes the complete lines of the compressed file src to w, each with its line feed.
// It returns a writeError when writing failed, and the source's damage otherwise (the lines
// before it were written).
func copyLines(w io.Writer, src io.Reader) error {
	content, err := gzipContent(src)
	if err != nil {
		return err
	}
	return eachLine(content, func(line []byte) error {
		if line == nil {
			return nil // longer than any line the store writes: damaged
		}
		if _, err := w.Write(line); err != nil {
			return writeError{err}
		}
		if _, err := w.Write([]byte{'\n'}); err != nil {
			return writeError{err}
		}
		return nil
	})
}

// dropCached forgets what the caches hold about the files of kind k and day d: their keys no
// longer match, and the memory is freed now rather than when the entries age out.
func (s *Store) dropCached(k kind, d day) {
	if k == kindNAT {
		s.sums.removeIf(func(key sumKey) bool { return key.day == d })
		return
	}
	s.devs.removeIf(func(key devKey) bool { return key.day == d })
}
