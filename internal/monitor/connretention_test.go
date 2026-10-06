package monitor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"attmonitor/internal/config"
)

// The connection store's retention and the raw page copies' lifetime (docs/DESIGN.md §19): the
// retention limits are applied hourly whatever the samplers do, and the copies of the gateway's
// pages are deleted with the samples - never kept for longer than connections.keep_days, nor at all
// while the samplers are off - and keep no Wi-Fi network name.

// TestConnRetentionRunsWithoutTheSamplers: the retention limits are applied every pruneEvery also
// when nothing appends - the samplers switched off, or held while an incident is open - and the
// reads are left alone meanwhile.
func TestConnRetentionRunsWithoutTheSamplers(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, r *rig)
	}{
		{"connections.enabled off", nil},
		{"samplers held by an incident", func(t *testing.T, r *rig) { openIncident(t, r) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, store := connRig(t, func(c *config.Config) { c.Connections.Enabled = tc.setup != nil })
			r.m.conns.pruneEvery = 20 * time.Millisecond
			if tc.setup != nil {
				tc.setup(t, r)
				r.m.conns.natFirst, r.m.conns.devFirst = time.Hour, time.Hour
			}
			stop := r.start(t)
			waitFor(t, "three prunes", 10*time.Second, func() bool { return store.prunes.Load() >= 3 })
			if err := stop(); err != nil {
				t.Fatal(err)
			}
			if nat, dev := store.reads(); len(nat)+len(dev) != 0 {
				t.Fatalf("%d NAT and %d Device List reads appended", len(nat), len(dev))
			}
		})
	}
}

// rawCopyRig is a connRig with a data directory whose connections folder holds both raw copies,
// written age ago, and a temporary file a crash left; keep_days is 1.
func rawCopyRig(t *testing.T, enabled bool, age time.Duration) (*rig, string) {
	t.Helper()
	r, store := connRig(t, func(c *config.Config) { c.Connections.Enabled = enabled })
	store.usage.KeepDays = 1
	dir := t.TempDir()
	r.cfg.SetDataDir(dir)
	folder := config.PathsFor(dir).Connections
	if err := os.MkdirAll(folder, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{natRawFile, devicesRawFile, devicesRawFile + ".123456.tmp", "nat-2026-10-05.jsonl"} {
		p := filepath.Join(folder, name)
		if err := os.WriteFile(p, []byte("<html>page</html>"), 0o600); err != nil {
			t.Fatal(err)
		}
		at := time.Now().Add(-age)
		if err := os.Chtimes(p, at, at); err != nil {
			t.Fatal(err)
		}
	}
	return r, folder
}

// present reports which of names are in folder.
func present(t *testing.T, folder string, names ...string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, n := range names {
		_, err := os.Stat(filepath.Join(folder, n))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		out[n] = err == nil
	}
	return out
}

// TestRawCopiesAreDeleted: at the start the temporary files a crash left go, and - while the
// samplers are off - the copies too; with the samplers on, a copy goes once it is older than
// keep_days, and a younger one stays. The store's own files are never touched.
func TestRawCopiesAreDeleted(t *testing.T) {
	names := []string{natRawFile, devicesRawFile, devicesRawFile + ".123456.tmp", "nat-2026-10-05.jsonl"}

	r, folder := rawCopyRig(t, false, time.Minute)
	r.m.cleanRawCopies(time.Now(), true)
	if got := present(t, folder, names...); got[natRawFile] || got[devicesRawFile] || got[names[2]] || !got[names[3]] {
		t.Fatalf("samplers off, at the start: %v", got)
	}

	r, folder = rawCopyRig(t, true, time.Hour)
	r.m.cleanRawCopies(time.Now(), true)
	if got := present(t, folder, names...); !got[natRawFile] || !got[devicesRawFile] || got[names[2]] || !got[names[3]] {
		t.Fatalf("samplers on, copies an hour old: %v", got)
	}
	r.m.conns.locked(func() { r.m.conns.nat.raw.path = filepath.Join(folder, natRawFile) })
	r.m.cleanRawCopies(time.Now().Add(22*time.Hour+30*time.Minute), false) // the copies are 23.5 hours old
	if got := present(t, folder, names...); !got[natRawFile] || !got[devicesRawFile] {
		t.Fatalf("copies younger than keep_days were deleted: %v", got)
	}
	r.m.cleanRawCopies(time.Now().Add(23*time.Hour+time.Minute), false) // a day old
	if got := present(t, folder, names...); got[natRawFile] || got[devicesRawFile] || !got[names[3]] {
		t.Fatalf("copies older than keep_days: %v", got)
	}
	var path string
	r.m.conns.locked(func() { path = r.m.conns.nat.raw.path })
	if path != "" {
		t.Fatalf("the status still names the deleted copy %s", path)
	}
}

// TestRawCopiesExpireWhileRunning: the retention worker deletes a copy that has grown older than
// keep_days, with the samplers on.
func TestRawCopiesExpireWhileRunning(t *testing.T) {
	r, folder := rawCopyRig(t, true, 25*time.Hour)
	r.m.conns.pruneEvery = 20 * time.Millisecond
	r.m.conns.natFirst, r.m.conns.devFirst = time.Hour, time.Hour
	stop := r.start(t)
	waitFor(t, "the old copies to go", 10*time.Second, func() bool {
		got := present(t, folder, natRawFile, devicesRawFile)
		return !got[natRawFile] && !got[devicesRawFile]
	})
	if err := stop(); err != nil {
		t.Fatal(err)
	}
}

// TestDevicesCopyKeepsNoWiFiName: the copy of the Device List page - the sanitized real capture -
// keeps the page as read but for the Wi-Fi network's name, which the parser never keeps either.
func TestDevicesCopyKeepsNoWiFiName(t *testing.T) {
	page, err := os.ReadFile(filepath.Join("..", "..", "testdata", "gateway", "devices_real.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(page, []byte("Name: ATT-EXAMPLE")) {
		t.Fatal("the fixture no longer shows the Wi-Fi network's name")
	}
	r, _ := connRig(t, nil)
	dir := t.TempDir()
	r.cfg.SetDataDir(dir)
	answerDevices(r.gw, testDevices(), page, nil)
	r.m.sampleDevices(context.Background())
	got, err := os.ReadFile(filepath.Join(config.PathsFor(dir).Connections, devicesRawFile))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(got, []byte("ATT-EXAMPLE")) || !bytes.Contains(got, []byte("<br />Name: (removed)\n")) {
		t.Fatalf("the copy still holds the Wi-Fi network's name, or not where it was")
	}
	if want := redactWiFiName(page); !bytes.Equal(got, want) || len(got) < len(page)-200 {
		t.Fatal("the copy is not the page as read but for the Wi-Fi network's name")
	}
	// What the parser reads is the same either way.
	if !bytes.Contains(got, []byte("Connection Type")) || !bytes.Contains(got, []byte("5 GHz Radio-1<br />Type: Home<br />Name: (removed)")) {
		t.Fatal("the copy lost the Connection Type cells")
	}
}
