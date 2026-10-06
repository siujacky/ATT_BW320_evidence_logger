package syslogstore

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"time"

	"attmonitor/internal/model"
)

// digester hashes, counts and describes the chunk content written to it (one message per
// line).
type digester struct {
	h    hash.Hash
	n    int64
	sum  summary
	line []byte // the current line so far
	cur  int64  // bytes of the current line
	long bool   // the current line is longer than maxLine: its bytes are not kept
}

func newDigester() *digester { return &digester{h: sha256.New()} }

func (d *digester) Write(p []byte) (int, error) {
	n := len(p)
	d.h.Write(p)
	d.n += int64(n)
	for len(p) > 0 {
		part := p
		i := bytes.IndexByte(p, '\n')
		if i >= 0 {
			part = p[:i]
		}
		d.cur += int64(len(part))
		switch {
		case d.long:
		case len(d.line)+len(part) > maxLine:
			d.long, d.line = true, d.line[:0]
		default:
			d.line = append(d.line, part...)
		}
		if i < 0 {
			break
		}
		d.endLine()
		p = p[i+1:]
	}
	return n, nil
}

// endLine counts the current line as a message.
func (d *digester) endLine() {
	if d.long {
		d.sum.messages++ // too long to be one of ours: a message without a receive time
	} else {
		d.sum.add(d.line)
	}
	d.line, d.cur, d.long = d.line[:0], 0, false
}

// digest is what a digester found.
type digest struct {
	bytes   int64
	sha     string // hex SHA-256
	sum     summary
	partial int64 // bytes of a last line without a line feed (counted as a message)
}

func (d *digester) finish() digest {
	partial := d.cur
	if partial > 0 || d.long {
		d.endLine()
	}
	return digest{bytes: d.n, sha: hex.EncodeToString(d.h.Sum(nil)), sum: d.sum, partial: partial}
}

// sidecar describes the content as the sealed chunk name with the given From and To.
func (dg digest) sidecar(name string, from, to time.Time, gzBytes int64, dropped, rejected int, reason string) sidecar {
	sc := sidecar{SyslogChunk: model.SyslogChunk{
		Name: name, From: formatRX(from), To: formatRX(to), Messages: dg.sum.messages,
		Dropped: dropped, Rejected: rejected, Bytes: dg.bytes, SHA256: dg.sha, GzBytes: gzBytes, Reason: reason,
	}}
	if dg.sum.timed {
		sc.RXMin, sc.RXMax = formatRX(dg.sum.min), formatRX(dg.sum.max)
	}
	return sc
}

// eachLine calls fn with every line of r (without its line feed) and its index; a line longer
// than maxLine is passed as nil. A last line without a line feed is passed only when partial
// is true. It returns fn's error, or the error of reading r.
func eachLine(r io.Reader, partial bool, fn func(i int, line []byte) error) error {
	br := bufio.NewReaderSize(r, 64<<10)
	var long []byte // a line longer than the reader's buffer, so far
	over := false   // the current line is longer than maxLine
	grow := func(frag []byte) {
		if over || len(long)+len(frag) > maxLine {
			long, over = long[:0], true
			return
		}
		long = append(long, frag...)
	}
	for i := 0; ; i++ {
		frag, err := br.ReadSlice('\n')
		for errors.Is(err, bufio.ErrBufferFull) {
			grow(frag)
			frag, err = br.ReadSlice('\n')
		}
		complete := err == nil
		switch {
		case complete:
			frag = frag[:len(frag)-1]
		case err != io.EOF:
			return err
		case len(frag) == 0 && len(long) == 0 && !over:
			return nil
		}
		line := frag
		if len(long) > 0 || over {
			grow(frag)
			line = long
		}
		if over {
			line = nil
		}
		if complete || partial {
			if err := fn(i, line); err != nil {
				return err
			}
		}
		if !complete {
			return nil
		}
		long, over = long[:0], false
	}
}

// writeGzip compresses what src holds into the file path (replacing an older one), checks
// that the file decompresses to exactly those bytes, fsyncs it and returns the digest of the
// content and the file's size. On failure the file is removed.
func writeGzip(path string, src io.Reader) (digest, int64, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o644)
	if err != nil {
		return digest{}, 0, err
	}
	done := false
	defer func() {
		if !done {
			f.Close()
			os.Remove(path)
		}
	}()
	d := newDigester()
	// No name and no modification time in the header: the same content gives the same file.
	zw, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		return digest{}, 0, err
	}
	if _, err := io.Copy(zw, io.TeeReader(src, d)); err != nil {
		return digest{}, 0, err
	}
	if err := zw.Close(); err != nil {
		return digest{}, 0, err
	}
	if err := f.Sync(); err != nil {
		return digest{}, 0, err
	}
	dg := d.finish()
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return digest{}, 0, err
	}
	zr, err := gzip.NewReader(f)
	if err != nil {
		return digest{}, 0, fmt.Errorf("the compressed copy cannot be read back: %w", err)
	}
	h := sha256.New()
	n, err := io.Copy(h, zr)
	if err != nil || n != dg.bytes || hex.EncodeToString(h.Sum(nil)) != dg.sha {
		return digest{}, 0, fmt.Errorf("the compressed copy does not decompress to the chunk's content (%v)", err)
	}
	st, err := f.Stat()
	if err != nil {
		return digest{}, 0, err
	}
	if err := f.Close(); err != nil {
		return digest{}, 0, err
	}
	done = true
	return dg, st.Size(), nil
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

// openState is the state file of an open chunk (open-<from>[-n].state.json): what a crash
// would lose otherwise.
type openState struct {
	// Dropped and Rejected are the chunk's counts (written when they change).
	Dropped  int `json:"dropped,omitempty"`
	Rejected int `json:"rejected,omitempty"`
	// Sealed names the chunk it was sealed into when its file could not be deleted then
	// (another program held it): such a file is only deleted, never sealed again.
	Sealed string `json:"sealed,omitempty"`
}

func readState(path string) (openState, error) {
	var st openState
	b, err := os.ReadFile(path)
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return openState{}, err
	}
	if st.Dropped < 0 || st.Rejected < 0 {
		return openState{}, errors.New("negative counts")
	}
	return st, nil
}

func writeState(path string, st openState) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(b, '\n'))
}

// removeFile deletes path; one that does not exist counts as deleted.
func removeFile(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
