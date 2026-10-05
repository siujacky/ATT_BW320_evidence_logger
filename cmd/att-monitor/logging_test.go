package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// A viewer holding service.log open without delete sharing must not cause the current log to be
// truncated by rotation.
func TestRotationNeverTruncatesWhenLogIsHeldOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "service.log")
	rf, err := openRotating(path)
	if err != nil {
		t.Fatal(err)
	}
	defer rf.Close()
	if _, err := rf.Write([]byte("first line that must survive\n")); err != nil {
		t.Fatal(err)
	}

	// Open the file the way a typical viewer does: read sharing only (no FILE_SHARE_DELETE).
	p16, _ := windows.UTF16PtrFromString(path)
	h, err := windows.CreateFile(p16, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)

	rf.size = logMaxBytes // force a rotation on the next write
	if _, err := rf.Write([]byte("second line\n")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "first line that must survive") || !strings.Contains(string(b), "second line") {
		t.Fatalf("log content lost during blocked rotation: %q", b)
	}
}

func TestHasLedger(t *testing.T) {
	dir := t.TempDir()
	if hasLedger(dir) {
		t.Fatal("empty dir reported as ledger")
	}
	if err := os.WriteFile(filepath.Join(dir, "ledger-2026-10-05.jsonl.gz"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !hasLedger(dir) {
		t.Fatal("compressed segment not recognised")
	}
}
