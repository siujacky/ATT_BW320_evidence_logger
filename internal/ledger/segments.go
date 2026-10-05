package ledger

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	segPrefix  = "ledger-"
	segExt     = ".jsonl"
	gzExt      = ".gz"
	tmpExt     = ".tmp"
	dateLayout = "2006-01-02"
	day        = 24 * time.Hour

	// maxLineBytes caps a line held in memory while reading; longer lines are reported as
	// parse errors and skipped (protects against corrupted files without newlines).
	maxLineBytes = 64 << 20
	readBufSize  = 256 << 10
)

// segmentName returns the segment name for the UTC date of t ("ledger-2026-10-05").
func segmentName(t time.Time) string { return segPrefix + t.UTC().Format(dateLayout) }

// utcDate truncates t to its UTC calendar day.
func utcDate(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// parseSegmentName accepts "ledger-YYYY-MM-DD", optionally followed by ".jsonl" or
// ".jsonl.gz", and returns the bare name and its date.
func parseSegmentName(s string) (name string, date time.Time, ok bool) {
	s = strings.TrimSuffix(s, gzExt)
	s = strings.TrimSuffix(s, segExt)
	if !strings.HasPrefix(s, segPrefix) {
		return "", time.Time{}, false
	}
	ds := strings.TrimPrefix(s, segPrefix)
	d, err := time.Parse(dateLayout, ds)
	if err != nil || d.Format(dateLayout) != ds {
		return "", time.Time{}, false
	}
	return s, d, true
}

// segFile is one segment as found on disk. During compression both forms may exist briefly;
// the uncompressed file is then preferred (it is the original).
type segFile struct {
	Name  string
	Date  time.Time
	Plain string // path of the .jsonl file, "" if absent
	Gz    string // path of the .jsonl.gz file, "" if absent
}

func (f segFile) path() string {
	if f.Plain != "" {
		return f.Plain
	}
	return f.Gz
}

func (f segFile) compressed() bool { return f.Plain == "" }

// listSegmentFiles returns the segments in dir ordered by date. Other files (the lock file,
// temporary files) are ignored.
func listSegmentFiles(dir string) ([]segFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	byName := map[string]*segFile{}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		fn := e.Name()
		var gz bool
		switch {
		case strings.HasSuffix(fn, segExt+gzExt):
			gz = true
		case strings.HasSuffix(fn, segExt):
		default:
			continue
		}
		name, date, ok := parseSegmentName(fn)
		if !ok {
			continue
		}
		f := byName[name]
		if f == nil {
			f = &segFile{Name: name, Date: date}
			byName[name] = f
		}
		p := filepath.Join(dir, fn)
		if gz {
			f.Gz = p
		} else {
			f.Plain = p
		}
	}
	out := make([]segFile, 0, len(byName))
	for _, f := range byName {
		out = append(out, *f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Date.Before(out[j].Date) })
	return out, nil
}

// ---------------------------------------------------------------- line reading

// lineRec is one line read from a segment.
type lineRec struct {
	data     []byte // line bytes including the trailing '\n' (aliases the reader's buffer)
	start    int64  // offset of the first byte in the uncompressed segment
	n        int    // total bytes of the line (also when tooLong)
	complete bool   // terminated by '\n'
	tooLong  bool   // longer than the reader's cap; data is empty
}

// lineReader splits a stream into '\n'-terminated lines, tracking offsets.
type lineReader struct {
	br  *bufio.Reader
	off int64
	buf []byte
	max int
}

func newLineReader(r io.Reader, bufSize int) *lineReader {
	return &lineReader{br: bufio.NewReaderSize(r, bufSize), max: maxLineBytes}
}

// next returns the next line. At EOF a final fragment without '\n' is returned with
// complete=false; after that next returns io.EOF. The returned data is only valid until the
// following call.
func (lr *lineReader) next() (lineRec, error) {
	lr.buf = lr.buf[:0]
	start := lr.off
	total := 0
	tooLong := false
	for {
		frag, err := lr.br.ReadSlice('\n')
		total += len(frag)
		if !tooLong {
			if len(lr.buf)+len(frag) > lr.max {
				tooLong = true
				lr.buf = lr.buf[:0]
			} else {
				lr.buf = append(lr.buf, frag...)
			}
		}
		switch {
		case err == nil:
			lr.off += int64(total)
			return lineRec{data: lr.buf, start: start, n: total, complete: true, tooLong: tooLong}, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			lr.off += int64(total)
			if total == 0 {
				return lineRec{}, io.EOF
			}
			return lineRec{data: lr.buf, start: start, n: total, complete: false, tooLong: tooLong}, nil
		default:
			return lineRec{}, err
		}
	}
}

// ---------------------------------------------------------------- segment streams

// gzReadCloser closes a gzip reader and its underlying file (if any).
type gzReadCloser struct {
	*gzip.Reader
	f io.Closer
}

func (g *gzReadCloser) Close() error {
	err := g.Reader.Close()
	if g.f != nil {
		err = errors.Join(err, g.f.Close())
	}
	return err
}

type limitedReadCloser struct {
	io.Reader
	c io.Closer
}

func (l *limitedReadCloser) Close() error { return l.c.Close() }

// openPlain opens an uncompressed segment. limit >= 0 restricts the stream to the first
// limit bytes; limit == -2 restricts it to complete lines (as of now); -1 = everything.
func openPlain(path string, limit int64) (io.ReadCloser, error) {
	f, err := openShared(path)
	if err != nil {
		return nil, err
	}
	if limit == -2 {
		st, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, err
		}
		limit, err = completeSize(f, st.Size())
		if err != nil {
			f.Close()
			return nil, err
		}
	}
	if limit < 0 {
		return f, nil
	}
	return &limitedReadCloser{Reader: io.LimitReader(f, limit), c: f}, nil
}

// openGz opens a compressed segment and returns its uncompressed content.
func openGz(path string) (io.ReadCloser, error) {
	f, err := openShared(path)
	if err != nil {
		return nil, err
	}
	rc, err := newGzStream(bufio.NewReaderSize(f, 64<<10), f, filepath.Base(path))
	if err != nil {
		f.Close()
	}
	return rc, err
}

// newGzStream returns the uncompressed content of the gzip data r, from the file named base;
// closing it closes c (if not nil). The file and in-memory paths (rawSegment) share it, so that
// both deliver the same bytes and the same errors for the same data.
func newGzStream(r io.Reader, c io.Closer, base string) (io.ReadCloser, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("ledger: %s: %w", base, err)
	}
	return &gzReadCloser{Reader: zr, f: c}, nil
}

// openSegmentFile opens the uncompressed content of f, falling back to the compressed form
// when the plain file disappeared (concurrent CompressSealed). limit as in openPlain.
func openSegmentFile(f segFile, limit int64) (io.ReadCloser, error) {
	if f.Plain != "" {
		rc, err := openPlain(f.Plain, limit)
		if err == nil || !errors.Is(err, os.ErrNotExist) {
			return rc, err
		}
		gz := f.Plain + gzExt
		if f.Gz != "" {
			gz = f.Gz
		}
		return openGz(gz)
	}
	return openGz(f.Gz)
}

// completeSize returns the length of the prefix of the first size bytes of r that ends with
// '\n' (0 if there is no newline): readers never deliver a line that is still being written.
func completeSize(r io.ReaderAt, size int64) (int64, error) {
	const chunk = 64 << 10
	buf := make([]byte, chunk)
	end := size
	for end > 0 {
		start := end - chunk
		if start < 0 {
			start = 0
		}
		n, err := r.ReadAt(buf[:end-start], start)
		if err != nil && !errors.Is(err, io.EOF) {
			return 0, err
		}
		if i := bytes.LastIndexByte(buf[:n], '\n'); i >= 0 {
			return start + int64(i) + 1, nil
		}
		end = start
	}
	return 0, nil
}

// lastCompleteLine returns the last '\n'-terminated line within the first size bytes of r and
// its start offset. ok=false if there is no complete line.
func lastCompleteLine(r io.ReaderAt, size int64) (line []byte, start int64, ok bool, err error) {
	end, err := completeSize(r, size)
	if err != nil || end == 0 {
		return nil, 0, false, err
	}
	// Find the newline that precedes the last line.
	prevEnd, err := completeSize(r, end-1)
	if err != nil {
		return nil, 0, false, err
	}
	n := end - prevEnd
	if n > maxLineBytes {
		return nil, prevEnd, false, fmt.Errorf("ledger: last line of %d bytes exceeds the %d byte limit", n, maxLineBytes)
	}
	line = make([]byte, n)
	if _, err := r.ReadAt(line, prevEnd); err != nil && !errors.Is(err, io.EOF) {
		return nil, 0, false, err
	}
	return line, prevEnd, true, nil
}

// readFirstLine returns the first complete line of a segment (nil if none).
func readFirstLine(f segFile) ([]byte, error) {
	rc, err := openSegmentFile(f, -1)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	lr := newLineReader(rc, 16<<10)
	rec, err := lr.next()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		return nil, err
	}
	if !rec.complete || rec.tooLong {
		return nil, nil
	}
	return bytes.Clone(rec.data), nil
}
