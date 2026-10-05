//go:build windows

package ledger

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"attmonitor/internal/contracts"
)

// An existing blob that cannot be read (here: another process holds it open without sharing)
// is not corrupt. PutBlob must neither move it to quarantine nor claim damage; it reports the
// error and leaves the good copy alone.
func TestPutBlobDoesNotQuarantineUnreadableBlob(t *testing.T) {
	s, dir, _ := newLedger(t)
	content := []byte("<html>fiberstat</html>")
	id, err := s.PutBlob(content)
	if err != nil {
		t.Fatal(err)
	}
	// Sharing only DELETE: readers fail with a sharing violation, but a rename (the move to
	// quarantine) would succeed, so a wrong "corrupt" verdict would really move a good copy.
	p, _ := windows.UTF16PtrFromString(s.blobPath(id))
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	head := s.Head()
	_, perr := s.PutBlob(content)
	_, gerr := s.GetBlob(id)
	windows.CloseHandle(h)

	if perr == nil {
		t.Fatal("PutBlob succeeded although the stored copy could not be checked")
	}
	if errors.Is(gerr, contracts.ErrNotFound) || errors.Is(gerr, ErrBlobCorrupt) || gerr == nil {
		t.Fatalf("GetBlob on an unreadable blob: %v", gerr)
	}
	if q, _ := filepath.Glob(filepath.Join(dir, "quarantine", "*")); len(q) != 0 {
		t.Fatalf("a readable-later blob was quarantined: %v", q)
	}
	if s.Head() != head {
		t.Fatal("an integrity_alert was written for a blob that is not damaged")
	}
	if got, err := s.GetBlob(id); err != nil || string(got) != string(content) {
		t.Fatalf("blob after the handle closed: %v", err)
	}
	if _, err := os.Stat(s.blobPath(id)); err != nil {
		t.Fatal(err)
	}
}
