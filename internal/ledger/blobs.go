package ledger

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// maxBlobBytes caps a blob's uncompressed size when reading (decompression-bomb guard).
const maxBlobBytes = 1 << 30

func (s *Store) blobPath(id string) string {
	return filepath.Join(s.blobDir, id[:2], id+gzExt)
}

// PutBlob stores the exact bytes of content gzip-compressed under blobs/<id[:2]>/<id>.gz and
// returns id, the lowercase hex SHA-256 of content. Storage is content-addressed and
// deduplicated; a new blob is written to a temporary file, fsynced and renamed into place, so a
// blob file is either complete or absent. An existing copy is re-verified on every put; one
// that no longer matches its id is moved to quarantine and replaced, and an integrity_alert
// record documents the replacement.
func (s *Store) PutBlob(content []byte) (string, error) {
	if s.readOnly {
		return "", ErrReadOnly
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return "", ErrClosed
	}
	id := sha256Hex(content)
	var dmg blobDamage
	err := s.putBlob(id, content, &dmg)
	if dmg.cause != nil {
		// Damage to the evidence store is itself evidence: record it (outside blobMu), also
		// when storing the good copy failed afterwards.
		outcome := "the same content was stored again; a blob id is the SHA-256 of its content, so the new copy holds exactly the bytes the id commits to"
		if err != nil {
			outcome = clipTo("storing the content again failed: "+err.Error(), maxAlertDetailBytes)
		}
		alert := model.IntegrityAlert{
			Problem: "a stored blob did not match its SHA-256 and was moved to quarantine",
			Details: []string{
				clipTo(fmt.Sprintf("blob %s: %v", id, dmg.cause), maxAlertDetailBytes),
				"the damaged file was moved to " + dmg.quarantined,
				outcome,
			},
		}
		if _, aerr := s.Append(model.TypeIntegrityAlert, &alert); aerr != nil {
			s.log.Error("could not record the replacement of a corrupt blob in the ledger", "id", id, "quarantine", dmg.quarantined, "err", aerr)
		}
	}
	if err != nil {
		return "", err
	}
	return id, nil
}

// blobDamage describes a corrupt stored copy that putBlob moved to quarantine.
type blobDamage struct {
	cause       error
	quarantined string // "quarantine/<file>"
}

// putBlob stores content (whose SHA-256 is id) under blobMu and fills dmg when it had to move
// a corrupt stored copy out of the way.
func (s *Store) putBlob(id string, content []byte, dmg *blobDamage) error {
	path := s.blobPath(id)
	s.blobMu.Lock()
	defer s.blobMu.Unlock()
	if _, err := os.Stat(path); err == nil {
		got, rerr := s.readBlobFile(id)
		switch {
		case rerr == nil && bytes.Equal(got, content):
			return nil
		case rerr == nil:
			rerr = fmt.Errorf("%w: %s does not hold the expected content", ErrBlobCorrupt, id) // only with a SHA-256 collision
		case errors.Is(rerr, contracts.ErrNotFound):
			rerr = nil // removed meanwhile: simply store it
		case !errors.Is(rerr, ErrBlobCorrupt):
			// Unreadable is not corrupt (e.g. a sharing violation): never move a copy that may be good.
			return fmt.Errorf("ledger: existing blob %s cannot be checked: %w", id, rerr)
		}
		if rerr != nil {
			// The stored copy is damaged: keep it for inspection, then store a good copy.
			q, qerr := s.quarantineMove(path, id+gzExt+".corrupt")
			if qerr != nil {
				return fmt.Errorf("ledger: blob %s is corrupt (%v) and cannot be moved to quarantine: %w", id, rerr, qerr)
			}
			s.log.Error("corrupt blob moved to quarantine", "id", id, "err", rerr, "quarantine", q)
			dmg.cause, dmg.quarantined = rerr, q
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("ledger: %w", err)
	}
	if err := os.MkdirAll(s.blobTmpDir, 0o755); err != nil {
		return fmt.Errorf("ledger: %w", err)
	}
	tmp, err := os.CreateTemp(s.blobTmpDir, id[:16]+".*"+tmpExt)
	if err != nil {
		return fmt.Errorf("ledger: %w", err)
	}
	tmpName := tmp.Name()
	zw := gzip.NewWriter(tmp) // header without name or mod time: identical bytes → identical file
	_, err = zw.Write(content)
	if err == nil {
		err = zw.Close()
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = renameDurable(tmpName, path)
	}
	if err != nil {
		os.Remove(tmpName)
		// A concurrent reader may hold an identical copy that appeared meanwhile.
		if got, gerr := s.readBlobFile(id); gerr == nil && bytes.Equal(got, content) {
			return nil
		}
		return fmt.Errorf("ledger: store blob %s: %w", id, err)
	}
	return nil
}

// GetBlob returns the exact bytes of a blob after re-checking their SHA-256. A missing blob
// yields an error wrapping contracts.ErrNotFound, a damaged one an error wrapping
// ErrBlobCorrupt.
func (s *Store) GetBlob(id string) ([]byte, error) {
	if !isBlobID(id) {
		return nil, fmt.Errorf("ledger: invalid blob id %q: %w", id, contracts.ErrNotFound)
	}
	return s.readBlobFile(id)
}

func (s *Store) readBlobFile(id string) ([]byte, error) {
	f, err := openShared(s.blobPath(id))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("ledger: blob %s: %w", id, contracts.ErrNotFound)
		}
		return nil, fmt.Errorf("ledger: blob %s: %w", id, err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, blobReadError(id, err)
	}
	content, err := io.ReadAll(io.LimitReader(zr, maxBlobBytes+1))
	if err != nil {
		return nil, blobReadError(id, err)
	}
	if len(content) > maxBlobBytes {
		return nil, fmt.Errorf("%w: %s exceeds %d bytes", ErrBlobCorrupt, id, maxBlobBytes)
	}
	if got := sha256Hex(content); got != id {
		return nil, fmt.Errorf("%w: %s content hashes to %s (corruption or tampering)", ErrBlobCorrupt, id, got)
	}
	return content, nil
}

// blobReadError classifies an error met while decompressing a blob: a failing read of the file
// (an *fs.PathError from the operating system) says nothing about its content, anything else
// (bad header, bad checksum, truncated or invalid deflate data) means the stored bytes are
// damaged.
func blobReadError(id string, err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return fmt.Errorf("ledger: blob %s cannot be read: %w", id, err)
	}
	return fmt.Errorf("%w: %s cannot be decompressed: %v", ErrBlobCorrupt, id, err)
}

// HasBlob reports whether a blob file exists for id (its content is not re-checked).
func (s *Store) HasBlob(id string) bool {
	if !isBlobID(id) {
		return false
	}
	st, err := os.Stat(s.blobPath(id))
	return err == nil && st.Mode().IsRegular()
}
