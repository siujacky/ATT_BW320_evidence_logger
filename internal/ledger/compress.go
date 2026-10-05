package ledger

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"attmonitor/internal/model"
)

// CompressSealed gzip-compresses every sealed (non-active) segment whose UTC day ended at least
// olderThan ago into ledger-YYYY-MM-DD.jsonl.gz and removes the uncompressed file. Hashes
// (segment_open, verification) keep referring to the uncompressed bytes; readers and the
// verifier handle both forms. The compressed copy is written to a temporary file, fsynced,
// decompressed and compared with the original before the original is removed. A segment whose
// bytes do not match the SHA-256 committed by the next segment is left untouched (error).
// It returns the number of segments compressed.
func (s *Store) CompressSealed(olderThan time.Duration) (int, error) {
	if s.readOnly {
		return 0, ErrReadOnly
	}
	s.compressMu.Lock()
	defer s.compressMu.Unlock()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, ErrClosed
	}
	activeName, activeDate := s.active.name, s.active.date
	now := s.now().UTC()
	s.mu.Unlock()
	if olderThan < 0 {
		olderThan = 0
	}

	files, err := listSegmentFiles(s.ledgerDir)
	if err != nil {
		return 0, fmt.Errorf("ledger: %w", err)
	}
	var errs []error
	n := 0
	for i, f := range files {
		if s.closing.Load() {
			break // Close is waiting; the rest is done by a later run
		}
		// Only segments older than the active one are sealed (a rotation racing with this
		// call only ever creates newer ones).
		if f.Name == activeName || f.Plain == "" || !f.Date.Before(activeDate) {
			continue
		}
		if now.Sub(f.Date.Add(day)) < olderThan {
			continue
		}
		var next *segFile
		if i+1 < len(files) {
			next = &files[i+1]
		}
		done, err := s.compressOne(f, next)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if done {
			n++
		}
	}
	return n, errors.Join(errs...)
}

func (s *Store) compressOne(f segFile, next *segFile) (bool, error) {
	before, err := os.Stat(f.Plain)
	if err != nil {
		return false, fmt.Errorf("ledger: %w", err)
	}
	// Readers' metadata of the uncompressed file (no decompression needed to get it) stays true
	// of its compressed copy: removeOriginal keeps it for the new file.
	var carry *segMeta
	if m, err := s.segmentMeta(segView{segFile: segFile{Name: f.Name, Date: f.Date, Plain: f.Plain}, limit: -1}, true); err == nil &&
		m.size == before.Size() && m.mod.Equal(before.ModTime()) {
		carry = &m
	}
	gzPath := f.Plain + gzExt
	if f.Gz != "" {
		// An earlier run stopped after creating the compressed copy.
		same, cerr := sameContent(f.Plain, f.Gz)
		if cerr == nil && same {
			return s.removeOriginal(f, before, f.Gz, carry)
		}
		q, err := s.quarantineMove(f.Gz, filepath.Base(f.Gz)+".stale")
		if err != nil {
			return false, fmt.Errorf("ledger: quarantine stale compressed copy of %s: %w", f.Name, err)
		}
		// This writer's .gz only appears through an atomic rename after a byte-for-byte check,
		// so a differing copy is not ours: record it, do not only log it.
		why := "it does not decompress to the segment's bytes"
		if cerr != nil {
			why = clipTo("it cannot be compared with the segment: "+cerr.Error(), maxAlertDetailBytes)
		}
		alert := model.IntegrityAlert{
			Problem: "a compressed copy of a sealed segment did not match the segment and was moved to quarantine",
			Details: []string{
				fmt.Sprintf("%s: %s", filepath.Base(f.Gz), why),
				"it was moved to " + q,
				"the uncompressed segment " + f.Name + segExt + " was kept and is compressed again from its own bytes",
			},
		}
		if _, err := s.Append(model.TypeIntegrityAlert, &alert); err != nil {
			s.log.Error("could not record a stale compressed segment in the ledger", "segment", f.Name, "quarantine", q, "err", err)
		}
		s.log.Warn("compressed copy differed from the segment; moved to quarantine", "segment", f.Name, "quarantine", q)
	}

	tmp := gzPath + tmpExt
	plainHash, err := gzipFile(f.Plain, tmp)
	if err != nil {
		os.Remove(tmp)
		return false, fmt.Errorf("ledger: compress %s: %w", f.Name, err)
	}
	if want, ok := committedHash(f, next); ok && want != plainHash {
		os.Remove(tmp)
		return false, fmt.Errorf("ledger: segment %s does not match the SHA-256 committed by %s (%s != %s); left uncompressed for inspection",
			f.Name, next.Name, plainHash, want)
	}
	gzHash, err := hashStream(func() (io.ReadCloser, error) { return openGz(tmp) })
	if err != nil || gzHash != plainHash {
		os.Remove(tmp)
		return false, fmt.Errorf("ledger: compressed copy of %s does not decompress to the original (%v)", f.Name, err)
	}
	if err := renameNoReplace(tmp, gzPath); err != nil {
		os.Remove(tmp)
		return false, fmt.Errorf("ledger: compress %s: %w", f.Name, err)
	}
	return s.removeOriginal(f, before, gzPath, carry)
}

// removeOriginal deletes the uncompressed file once its compressed copy gzPath (verified to hold
// the same bytes) is in place. If the file is still open elsewhere, both copies stay (identical)
// and a later run retries. Metadata cached for the uncompressed file as it was before compression
// (carry, and ScanTime's earliest ts) is kept for the compressed file, validated by that file's
// own size and modification time, so readers need not decompress it to learn it again.
func (s *Store) removeOriginal(f segFile, before os.FileInfo, gzPath string, carry *segMeta) (bool, error) {
	st, err := os.Stat(f.Plain)
	if err != nil {
		return false, fmt.Errorf("ledger: %w", err)
	}
	if st.Size() != before.Size() || !st.ModTime().Equal(before.ModTime()) {
		return false, fmt.Errorf("ledger: sealed segment %s changed while being compressed; both copies kept", f.Name)
	}
	if err := os.Remove(f.Plain); err != nil {
		s.log.Info("uncompressed segment still in use; compression will be completed later", "segment", f.Name, "err", err)
		return false, nil
	}
	gst, gerr := os.Stat(gzPath)
	s.cacheMu.Lock()
	ts, haveTS := s.minTS[f.Plain]
	delete(s.meta, f.Plain)
	delete(s.minTS, f.Plain)
	if gerr == nil {
		if carry != nil {
			m := *carry
			m.size, m.mod, m.scanned = gst.Size(), gst.ModTime(), 0
			s.meta[gzPath] = m
		}
		if haveTS && ts.size == before.Size() && ts.mod.Equal(before.ModTime()) {
			s.minTS[gzPath] = tsMeta{size: gst.Size(), mod: gst.ModTime(), earliest: ts.earliest}
		}
	}
	s.cacheMu.Unlock()
	s.idx.remove(f.Plain)
	s.log.Info("segment compressed", "segment", f.Name)
	return true, nil
}

// gzipFile writes a gzip copy of src to dst (fsynced) and returns the SHA-256 of src.
func gzipFile(src, dst string) (string, error) {
	in, err := openShared(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	zw, err := gzip.NewWriterLevel(out, gzip.BestCompression)
	if err != nil {
		out.Close()
		return "", err
	}
	_, err = io.Copy(zw, io.TeeReader(in, h))
	if cerr := zw.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// committedHash returns the SHA-256 that the next segment's segment_open records for f.
func committedHash(f segFile, next *segFile) (string, bool) {
	if next == nil {
		return "", false
	}
	line, err := readFirstLine(*next)
	if err != nil || line == nil {
		return "", false
	}
	_, body, err := parseRecordLenient(line)
	if err != nil || body.Type != model.TypeSegmentOpen {
		return "", false
	}
	var so model.SegmentOpen
	if json.Unmarshal(body.Data, &so) != nil || so.PrevSegment != f.Name {
		return "", false
	}
	return so.PrevSegmentSHA256, true
}
