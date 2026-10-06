//go:build windows

package connstore

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"attmonitor/internal/model"
)

// hold opens path as another program might - reading, without letting anyone delete it - until
// the returned function is called.
func hold(t *testing.T, path string) (release func()) {
	t.Helper()
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatalf("hold %s: %v", path, err)
	}
	done := false
	release = func() {
		if !done {
			done = true
			windows.CloseHandle(h)
		}
	}
	t.Cleanup(release)
	return release
}

func TestPruneDeletesAFileInUseLater(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{KeepDays: 1})
	fillDays(h, 0, 1, 2)
	name := "nat-2026-10-05.jsonl.gz"
	release := hold(t, h.file(name))

	err := h.s.Prune(at(3, 0, 0))
	if err == nil || !strings.Contains(err.Error(), "in use") {
		t.Errorf("Prune with a file in use: %v", err)
	}
	if u := h.s.Usage(); !strings.Contains(u.Error, "in use") {
		t.Errorf("Usage().Error = %q", u.Error)
	}
	if !h.exists(name) {
		t.Fatal("the file in use is gone")
	}
	// The day left the store all the same.
	if a := h.agg(day0, at(1, 0, 0)); a.Samples != 0 {
		t.Errorf("the deleted day is still read: %+v", a)
	}
	for _, n := range dayNames(t, h.dir) {
		if n == name {
			continue
		}
		if strings.Contains(n, "2026-10-05") {
			t.Errorf("%s of the deleted day is still there", n)
		}
	}

	release()
	if err := h.s.Prune(at(3, 0, 0)); err != nil {
		t.Errorf("Prune once the file is free: %v", err)
	}
	if h.exists(name) {
		t.Error("the file was not deleted once free")
	}
	if u := h.s.Usage(); u.Error != "" {
		t.Errorf("Usage().Error = %q once the file was deleted", u.Error)
	}
}

func TestCompressionWithThePlainFileInUse(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{})
	h.nat(at(0, 10, 0), tcp(10, 1, "203.0.113.5", 443))
	h.nat(at(0, 11, 0), tcp(10, 2, "203.0.113.5", 443))
	plain := "nat-2026-10-05.jsonl"
	release := hold(t, h.file(plain))

	h.clk.Set(at(1, 0, 5))
	h.nat(at(1, 0, 5), tcp(10, 3, "203.0.113.5", 443)) // compresses day 0; its plain file stays
	if !h.exists(plain) || !h.exists(plain+gzExt) {
		t.Fatal("expected both files of day 0")
	}
	if a := h.agg(day0, at(1, 0, 0)); a.Samples != 2 {
		t.Errorf("day 0 = %d reads, want 2 (each once)", a.Samples)
	}
	// A late read of day 0 cannot go to a plain file that is still the old one.
	h.clk.Set(at(0, 23, 59))
	if err := h.s.AppendNAT(at(0, 23, 59), model.NATTable{}); err == nil || !strings.Contains(err.Error(), "cannot be written") {
		t.Errorf("a late read while the old plain file is in use: %v", err)
	}
	// A restart while the file is still held: Open recognizes it as compressed already.
	h.clk.Set(at(1, 0, 10))
	h.reopen()
	if a := h.agg(day0, at(1, 0, 0)); a.Samples != 2 {
		t.Errorf("day 0 after reopening = %d reads, want 2", a.Samples)
	}
	release()
	h.nat(at(1, 0, 10), tcp(10, 3, "203.0.113.5", 443))
	if h.exists(plain) {
		t.Error("the plain file was not deleted once free")
	}
	if a := h.agg(day0, at(1, 0, 0)); a.Samples != 2 {
		t.Errorf("day 0 at the end = %d reads, want 2", a.Samples)
	}
}
