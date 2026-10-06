package ipintel

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestRunHandPlacedFiles checks Run without Download: it loads the files found, reloads one that
// changes, keeps the loaded table when a file is broken or removed, and never downloads.
func TestRunHandPlacedFiles(t *testing.T) {
	dir := t.TempDir()
	writeTables(t, dir, gzRows(rows4), nil)
	clk := newFakeClock(t0)
	d := openTest(t, dir, Options{Now: clk.Now})
	d.after = clk.After
	stop := startRun(t, d)
	w := clk.next(t)
	st := d.Status()
	if w.d != tickEvery || st.V4Ranges != 10 || st.V6Ranges != 0 || st.Next != "" || st.Checked != "" ||
		st.Source != "IPtoASN (local files)" || !strings.Contains(st.Error, nameV6+" not found") {
		t.Fatalf("wait %v, status %+v", w.d, st)
	}

	// The IPv6 file appears and the IPv4 file is replaced.
	other := slices.Clone(rows4)
	other[6] = row{"8.8.8.0", "8.8.8.255", 64503, "US", "EXAMPLE-REPLACED"}
	writeTables(t, dir, gzRows(other), gzRows(rows6))
	touch(t, filepath.Join(dir, nameV4), time.Hour)
	clk.fire(w)
	w = clk.next(t)
	if got := d.Lookup(mustAddr(t, "8.8.8.8")); got.ASN != 64503 {
		t.Fatalf("the replaced file was not loaded: %+v", got)
	}
	if st := d.Status(); st.V6Ranges != 4 || st.Error != "" {
		t.Fatalf("status %+v", st)
	}

	// A broken file: reported, the loaded table stays.
	writeTables(t, dir, []byte("not gzip"), nil)
	touch(t, filepath.Join(dir, nameV4), 2*time.Hour)
	clk.fire(w)
	w = clk.next(t)
	if st := d.Status(); !strings.Contains(st.Error, nameV4+": not a gzip file") || st.V4Ranges != 10 {
		t.Fatalf("status %+v", st)
	}
	if got := d.Lookup(mustAddr(t, "8.8.8.8")); got.ASN != 64503 {
		t.Fatalf("the loaded table was dropped: %+v", got)
	}
	// The IPv6 file is removed: reported, the loaded table stays.
	os.Remove(filepath.Join(dir, nameV6))
	clk.fire(w)
	clk.next(t)
	if st := d.Status(); !strings.Contains(st.Error, nameV6+" not found") || st.V6Ranges != 4 {
		t.Fatalf("status %+v", st)
	}
	stop()
	if _, err := os.Stat(filepath.Join(dir, nameMeta)); !os.IsNotExist(err) {
		t.Fatalf("metadata written without Download: %v", err)
	}
}

// touch sets a file's write time to t0+d, so that a rewrite within the clock's resolution is
// still seen as a change.
func touch(t *testing.T, path string, d time.Duration) {
	t.Helper()
	if err := os.Chtimes(path, t0.Add(d), t0.Add(d)); err != nil {
		t.Fatal(err)
	}
}

func TestRunRemovesTemporaryFiles(t *testing.T) {
	dir := t.TempDir()
	left := []string{nameV4 + ".123.tmp", namePTR + ".456.tmp", nameMeta + ".7.tmp"}
	kept := []string{"other.tmp", nameV4 + ".tmp.keep"}
	for _, n := range append(slices.Clone(left), kept...) {
		os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o644)
	}
	clk := newFakeClock(t0)
	d := openTest(t, dir, Options{Now: clk.Now})
	d.after = clk.After
	startRun(t, d)
	clk.next(t)
	for _, n := range left {
		if _, err := os.Stat(filepath.Join(dir, n)); !os.IsNotExist(err) {
			t.Errorf("%s not removed", n)
		}
	}
	for _, n := range kept {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Errorf("%s removed", n)
		}
	}
}

func TestRunOnce(t *testing.T) {
	clk := newFakeClock(t0)
	d := openTest(t, t.TempDir(), Options{Now: clk.Now})
	d.after = clk.After
	startRun(t, d)
	clk.next(t)
	// A second Run does nothing and returns when its context ends.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	d.Run(ctx)
	select {
	case w := <-clk.waits:
		t.Fatalf("the second Run waited %v", w.d)
	default:
	}
}

// TestNextCheckClockSetBack checks that a clock set back does not postpone a check by more than
// Refresh.
func TestNextCheckClockSetBack(t *testing.T) {
	d := openTest(t, t.TempDir(), Options{Download: true, Refresh: 24 * time.Hour})
	d.disk = [2]fileState{{exists: true, mtime: t0}, {exists: true, mtime: t0}}
	d.st.checked = t0.Add(10 * 24 * time.Hour) // checked "in ten days"
	if got := d.nextCheck(t0); !got.Equal(t0.Add(24 * time.Hour)) {
		t.Fatalf("nextCheck = %v", got)
	}
	// Files placed by hand, never checked: Refresh after the older file was written.
	d.st.checked = time.Time{}
	d.disk[fam6].mtime = t0.Add(-20 * time.Hour)
	if got := d.nextCheck(t0); !got.Equal(t0.Add(4 * time.Hour)) {
		t.Fatalf("nextCheck for files placed by hand = %v", got)
	}
	// A file missing: at once.
	d.disk[fam6] = fileState{}
	if got := d.nextCheck(t0); !got.Equal(t0) {
		t.Fatalf("nextCheck with a file missing = %v", got)
	}
}

// TestNextCheckUnusableFile checks that a table file that is there but cannot be loaded makes the
// check due at once, as a missing one does - not at the next scheduled check, with its family
// unknown until then - but not before the backoff of a failed check.
func TestNextCheckUnusableFile(t *testing.T) {
	d := openTest(t, t.TempDir(), Options{Download: true, Refresh: 24 * time.Hour})
	d.disk = [2]fileState{{exists: true, mtime: t0}, {exists: true, mtime: t0}}
	d.st.checked = t0.Add(-time.Hour)
	if got := d.nextCheck(t0); !got.Equal(t0.Add(23 * time.Hour)) {
		t.Fatalf("nextCheck = %v", got)
	}
	for _, f := range families {
		d.st.loadErr = [2]string{}
		d.st.loadErr[f] = f.fileName() + ": line 5: unexpected EOF"
		if got := d.nextCheck(t0); !got.Equal(t0) {
			t.Fatalf("nextCheck with %s not usable = %v", f.fileName(), got)
		}
	}
	// After two failed checks, the second an hour ago: two hours after it.
	d.st.failures, d.st.attempt = 2, t0.Add(-time.Hour)
	if got := d.nextCheck(t0); !got.Equal(t0.Add(time.Hour)) {
		t.Fatalf("nextCheck after failed checks = %v", got)
	}
}
