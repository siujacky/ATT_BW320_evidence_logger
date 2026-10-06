package netmap

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
)

const (
	// maxChunkContent bounds the uncompressed content read from one chunk: far beyond a chunk the
	// store seals (1 MiB), it keeps a damaged file from being decompressed for ever.
	maxChunkContent = 256 << 20
	// maxLine is the longest line read; a stored message takes about 100 KiB at most. Longer
	// lines are skipped.
	maxLine = 1 << 20
	// ctxEvery is how many lines are read between two checks of the request's context.
	ctxEvery = 4096
)

// errDamaged wraps the problem of a chunk that could not be read to its end: the lines before
// it were read.
var errDamaged = errors.New("the chunk cannot be read to its end")

// errTooBig stops reading a chunk whose summary would hold more than any chunk the store seals
// (scan.over): the caller reads it again into the request's bounded sums.
var errTooBig = errors.New("the chunk holds more than a summary keeps")

// readChunk reads the sealed chunk name through the syslog store and passes its messages, in
// order, to sc. Its error is OpenChunk's (contracts.ErrNotFound for a chunk gone meanwhile),
// ctx's, errTooBig once sc.over is set (the lines before were passed), or errDamaged (wrapped)
// for a chunk that cannot be read to its end, whose lines before the damage were passed.
func (v *View) readChunk(ctx context.Context, name string, sc *scan) error {
	rc, err := v.syslog.OpenChunk(name)
	if err != nil {
		return err
	}
	defer rc.Close()
	zr, err := gzip.NewReader(bufio.NewReaderSize(rc, 64<<10))
	if err != nil {
		return fmt.Errorf("%w: not a gzip file: %w", errDamaged, err)
	}
	defer zr.Close()
	lr := &io.LimitedReader{R: zr, N: maxChunkContent + 1}
	err = eachLine(lr, func(i int, line []byte) error {
		if i%ctxEvery == ctxEvery-1 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		rx, text, ok := lineText(line)
		if !ok {
			sc.bad++
			return nil
		}
		sc.message(rx, text)
		if sc.over {
			return errTooBig
		}
		return nil
	})
	switch {
	case err != nil && ctx.Err() != nil:
		return ctx.Err()
	case errors.Is(err, errTooBig):
		return errTooBig
	case err != nil:
		return fmt.Errorf("%w: %w", errDamaged, err)
	case lr.N <= 0:
		return fmt.Errorf("%w: it decompresses to more than %d bytes", errDamaged, maxChunkContent)
	}
	return nil
}

// eachLine calls fn with every line of r (without its line feed; the last one also when no
// line feed ends it) and its index. A line longer than maxLine is passed as nil. The line is
// valid until fn returns. It returns fn's error, or the error of reading r.
func eachLine(r io.Reader, fn func(i int, line []byte) error) error {
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
		if err := fn(i, line); err != nil {
			return err
		}
		if !complete {
			return nil
		}
		long, over = long[:0], false
	}
}
