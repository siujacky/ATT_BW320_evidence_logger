package connstore

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"time"
)

const (
	// maxContent bounds what one compressed file is decompressed to: far beyond any day the
	// store writes, it keeps a damaged or hostile file from being decompressed for ever.
	maxContent = 2 << 30
	// gzipLevel is the compression of a day that is over. On a day of NAT table reads (3.5 MiB,
	// BenchmarkCompressDay) the default level takes about 45 ms for 0.59 MiB, the best one 16
	// times as long for 11 % less: the default keeps the append that compresses a day, and Open
	// after a restart, from stalling, and connections.keep_mb's default 200 MiB still holds
	// about a year of days.
	gzipLevel = gzip.DefaultCompression
)

// fileStamp identifies a file's content as long as it is not replaced: its size and its
// modification time. The cache of day summaries is keyed by the stamps of the files a summary
// was computed from, so a file that grew or was replaced is read again.
type fileStamp struct {
	size int64
	mod  int64 // Unix nanoseconds
}

// stampOf returns the stamp of a file whose content is its first size bytes.
func stampOf(fi os.FileInfo, size int64) fileStamp {
	return fileStamp{size: size, mod: fi.ModTime().UnixNano()}
}

// eachLine calls fn with every complete line of r (without its line feed), in order. A line
// longer than maxLine is passed as nil (it is damaged: the store never writes one). A last line
// without a line feed - a write in progress, or one a crash cut short - is not passed. It
// returns fn's error or the error of reading r.
func eachLine(r io.Reader, fn func(line []byte) error) error {
	br := bufio.NewReaderSize(r, 256<<10)
	var long []byte // a line longer than the reader's buffer, so far
	over := false   // the current line is longer than maxLine
	grow := func(frag []byte) {
		switch {
		case over:
		case len(long)+len(frag) > maxLine:
			long, over = long[:0], true
		default:
			long = append(long, frag...)
		}
	}
	for {
		frag, err := br.ReadSlice('\n')
		switch {
		case err == nil:
		case errors.Is(err, bufio.ErrBufferFull):
			grow(frag)
			continue
		case err == io.EOF:
			return nil // what follows the last line feed is not a complete line
		default:
			return err
		}
		line := frag[:len(frag)-1]
		if len(long) > 0 || over {
			grow(line)
			line = long
			if over {
				line = nil
			}
		}
		if err := fn(line); err != nil {
			return err
		}
		long, over = long[:0], false
	}
}

// gzipContent returns a reader of the decompressed content of a gzip stream, bounded by
// maxContent.
func gzipContent(r io.Reader) (io.Reader, error) {
	zr, err := gzip.NewReader(bufio.NewReaderSize(r, 64<<10))
	if err != nil {
		return nil, fmt.Errorf("not a gzip file: %w", err)
	}
	return io.LimitReader(zr, maxContent), nil
}

// writeGzip compresses what fill writes into a new file at path (replacing a leftover one),
// checks that the file decompresses to exactly those bytes, fsyncs it and closes it, and
// returns the size of the content and of the file. On failure the file is removed.
func writeGzip(path string, fill func(w io.Writer) error) (n, gzSize int64, err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o644)
	if err != nil {
		return 0, 0, err
	}
	done := false
	defer func() {
		if !done {
			f.Close()
			os.Remove(path)
		}
	}()
	h := sha256.New()
	// No name and no modification time in the header: the same content gives the same file.
	zw, err := gzip.NewWriterLevel(f, gzipLevel)
	if err != nil {
		return 0, 0, err
	}
	cw := &countWriter{w: io.MultiWriter(zw, h)}
	if err := fill(cw); err != nil {
		return 0, 0, err
	}
	if err := zw.Close(); err != nil {
		return 0, 0, err
	}
	if err := f.Sync(); err != nil {
		return 0, 0, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, 0, err
	}
	content, err := gzipContent(f)
	if err != nil {
		return 0, 0, fmt.Errorf("the compressed copy cannot be read back: %w", err)
	}
	check := sha256.New()
	m, err := io.Copy(check, content)
	if err != nil || m != cw.n || !bytes.Equal(check.Sum(nil), h.Sum(nil)) {
		return 0, 0, fmt.Errorf("the compressed copy does not decompress to the content (%d of %d bytes, %v)", m, cw.n, err)
	}
	st, err := f.Stat()
	if err != nil {
		return 0, 0, err
	}
	if err := f.Close(); err != nil {
		return 0, 0, err
	}
	done = true
	return cw.n, st.Size(), nil
}

// countWriter counts what it passes on.
type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// completeLines returns the size of f's content up to and including its last line feed, and
// the number of bytes after it (a last line that a crash cut short).
func completeLines(f *os.File) (size, cut int64, err error) {
	st, err := f.Stat()
	if err != nil {
		return 0, 0, err
	}
	end := st.Size()
	buf := make([]byte, 64<<10)
	for off := end; off > 0; {
		n := min(int64(len(buf)), off)
		off -= n
		if m, err := f.ReadAt(buf[:n], off); int64(m) < n {
			return 0, 0, err
		}
		if i := bytes.LastIndexByte(buf[:n], '\n'); i >= 0 {
			size = off + int64(i) + 1
			return size, end - size, nil
		}
	}
	return 0, end, nil
}

// gzipEndsWith reports whether the decompressed content of the gzip file gzPath ends with the
// first size bytes of the file plainPath: then the plain file was compressed into it already (a
// crash came between the compressed file's rename and the plain file's deletion), and deleting
// the plain file loses nothing.
func gzipEndsWith(gzPath, plainPath string, size int64) (bool, error) {
	total, err := gzipSize(gzPath)
	if err != nil {
		return false, err
	}
	if total < size {
		return false, nil
	}
	g, err := openShared(gzPath)
	if err != nil {
		return false, err
	}
	defer g.Close()
	content, err := gzipContent(g)
	if err != nil {
		return false, err
	}
	if _, err := io.CopyN(io.Discard, content, total-size); err != nil {
		return false, err
	}
	p, err := openShared(plainPath)
	if err != nil {
		return false, err
	}
	defer p.Close()
	plain := io.NewSectionReader(p, 0, size)
	a, b := make([]byte, 64<<10), make([]byte, 64<<10)
	for left := size; left > 0; {
		n := int(min(int64(len(a)), left))
		if _, err := io.ReadFull(content, a[:n]); err != nil {
			return false, err
		}
		if _, err := io.ReadFull(plain, b[:n]); err != nil {
			return false, err
		}
		if !bytes.Equal(a[:n], b[:n]) {
			return false, nil
		}
		left -= int64(n)
	}
	return true, nil
}

// gzipSize returns the size of the decompressed content of the gzip file path.
func gzipSize(path string) (int64, error) {
	f, err := openShared(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	content, err := gzipContent(f)
	if err != nil {
		return 0, err
	}
	return io.Copy(io.Discard, content)
}

// replaceFile atomically renames the file oldName of dir to newName, replacing newName when it
// exists. It renames through os.Root, which on Windows renames with POSIX semantics: a file that
// the store's readers have open (they open files with FILE_SHARE_DELETE) is replaced all the
// same, and they keep reading what they opened, where MoveFileEx would refuse ("Access is
// denied") while any query reads the day. The rename is not written through: Open recognizes
// every state a crash can leave (see compress).
func replaceFile(dir, oldName, newName string) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	return root.Rename(oldName, newName)
}

// removeFile deletes path; one that does not exist counts as deleted.
func removeFile(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// fromUnixNano converts Unix nanoseconds - how the summaries keep times, in 8 bytes instead of
// 24 - back to a UTC time.
func fromUnixNano(ns int64) time.Time { return time.Unix(0, ns).UTC() }
