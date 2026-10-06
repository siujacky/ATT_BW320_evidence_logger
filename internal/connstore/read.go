package connstore

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"time"
)

// openAttempts bounds how often a reader looks again at a day that the writer was changing
// (compressing, merging or pruning it) while the reader opened its files; it waits a little
// longer each time (90 ms in all: a compression keeps a day marked for one rename).
const openAttempts = 10

// errChanged says that the writer changed a day's files while a reader opened them.
var errChanged = errors.New("the files kept changing while they were opened")

// dayReader reads the files of one kind and day as one index entry listed them: the
// compressed file, then the plain file up to its committed size (its complete, synced lines),
// so that a line being written is never read.
type dayReader struct {
	kind  kind
	day   day
	files dayFiles
	gz    *os.File
	plain *os.File
	// plainSize is how much of the plain file is read: its committed size, or less when another
	// program cut the file.
	plainSize int64
	// The stamps of the files read (zero for a file the day does not have): the key of what is
	// computed from them.
	gzStamp, plainStamp fileStamp
}

// openDay opens the files of kind k and day d. It returns nil when the store no longer has the
// day (pruned meanwhile). What it opens is always one state of the day the writer left it in,
// never one in between - such as a compressed file that holds a plain file's lines and that
// plain file: the writer marks the day's entry (an odd generation) while it replaces or deletes
// its files, and a day whose generation changed while its files were opened is opened again.
// Files changed by another program are read as they are (their complete lines).
func (s *Store) openDay(k kind, d day) (*dayReader, error) {
	for attempt := 1; ; attempt++ {
		f, ok := s.entry(k, d)
		if !ok {
			return nil, nil
		}
		var err error
		if f.gen%2 == 0 {
			r := &dayReader{kind: k, day: d, files: f}
			if err = r.open(s); err == nil {
				f2, ok := s.entry(k, d)
				switch {
				case !ok:
					r.close()
					return nil, nil
				case f2.gen == f.gen:
					return r, nil
				}
				err = errChanged
			}
			r.close()
			if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, errChanged) {
				return nil, fmt.Errorf("connstore: read %s: %w", fileName(k, d, f.gz >= 0), err)
			}
		}
		if attempt == openAttempts {
			if err == nil {
				err = errChanged
			}
			return nil, fmt.Errorf("connstore: read %s: %w", fileName(k, d, f.gz >= 0), err)
		}
		time.Sleep(time.Duration(2*attempt) * time.Millisecond)
	}
}

// open opens the files r.files lists.
func (r *dayReader) open(s *Store) error {
	if r.files.gz >= 0 {
		f, st, err := openStat(s.path(r.kind, r.day, true))
		if err != nil {
			return err
		}
		r.gz = f
		r.gzStamp = stampOf(st, st.Size())
	}
	if r.files.plain >= 0 {
		f, st, err := openStat(s.path(r.kind, r.day, false))
		if err != nil {
			return err
		}
		r.plain = f
		r.plainSize = min(st.Size(), r.files.plain)
		r.plainStamp = stampOf(st, r.plainSize)
	}
	return nil
}

// openStat opens path for reading and returns its file information.
func openStat(path string) (*os.File, os.FileInfo, error) {
	f, err := openShared(path)
	if err != nil {
		return nil, nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, st, nil
}

// close closes the files.
func (r *dayReader) close() {
	if r == nil {
		return
	}
	for _, f := range [...]*os.File{r.gz, r.plain} {
		if f != nil {
			f.Close()
		}
	}
	r.gz, r.plain = nil, nil
}

// each calls fn with every complete line of the day, the compressed file's first. When fn
// returns an error, reading ends and stop is that error. damage reports what could not be read
// (a damaged compressed file, an I/O error): the lines before it were passed, and the plain
// file is read after a damaged compressed one.
func (r *dayReader) each(fn func(line []byte) error) (damage, stop error) {
	call := func(line []byte) error {
		if err := fn(line); err != nil {
			stop = err
			return err
		}
		return nil
	}
	var errs []error
	if r.gz != nil {
		content, err := gzipContent(r.gz)
		if err == nil {
			err = eachLine(content, call)
		}
		if stop != nil {
			return nil, stop
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", fileName(r.kind, r.day, true), err))
		}
	}
	if r.plain != nil {
		err := eachLine(io.NewSectionReader(r.plain, 0, r.plainSize), call)
		if stop != nil {
			return nil, stop
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", fileName(r.kind, r.day, false), err))
		}
	}
	return errors.Join(errs...), nil
}

// dayStamps returns the stamps of the files of kind k and day d as they are now, without
// opening them: the key under which a summary of the day may be cached. ok is false when the
// store no longer has the day, or the writer kept changing it.
func (s *Store) dayStamps(k kind, d day) (gz, plain fileStamp, ok bool) {
	for range openAttempts {
		f, found := s.entry(k, d)
		if !found {
			return gz, plain, false
		}
		if f.gen%2 == 0 {
			if gz, plain, ok = s.statDay(k, d, f); ok {
				if f2, found := s.entry(k, d); found && f2.gen == f.gen {
					return gz, plain, true
				}
			}
		}
	}
	return fileStamp{}, fileStamp{}, false
}

// statDay returns the stamps of the files f lists (ok is false when one is missing).
func (s *Store) statDay(k kind, d day, f dayFiles) (gz, plain fileStamp, ok bool) {
	if f.gz >= 0 {
		st, err := os.Stat(s.path(k, d, true))
		if err != nil {
			return gz, plain, false
		}
		gz = stampOf(st, st.Size())
	}
	if f.plain >= 0 {
		st, err := os.Stat(s.path(k, d, false))
		if err != nil {
			return gz, plain, false
		}
		plain = stampOf(st, min(st.Size(), f.plain))
	}
	return gz, plain, true
}
