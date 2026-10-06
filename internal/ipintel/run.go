package ipintel

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"
	"time"
)

// Run loads the IP database and keeps it current until ctx ends: it deletes temporary files a
// crash left, loads the reverse DNS cache and the table files found in the directory, downloads
// missing tables and looks for newer ones every Refresh (with Download), reloads a table file
// placed or replaced by hand, runs the reverse DNS workers (with ReverseDNS) and saves their cache
// every few minutes - its answers that are still current only: what has outlived its time to
// live is forgotten (ptrCache.sweep). It returns when ctx ends, after saving the reverse DNS cache.
// Only the first call does this. Without ReverseDNS no reverse DNS name is kept: the cache saved
// before is deleted (not loaded); with the database disabled, Run deletes it too and only waits
// for ctx.
func (d *DB) Run(ctx context.Context) {
	if d == nil || !d.enabled {
		if d != nil {
			d.safely("start", func() { d.removePTR("the IP database is turned off (geo.enabled)") })
		}
		<-ctx.Done()
		return
	}
	if !d.running.CompareAndSwap(false, true) {
		d.log.Warn("ipintel: Run called again; the first call does the work")
		<-ctx.Done()
		return
	}
	start := d.now()
	removeWhy := "" // why ptr-cache.json is to be deleted ("" when it is not, or is gone)
	if !d.reverseDNS {
		removeWhy = "reverse DNS is turned off (connections.reverse_dns)"
	}
	d.safely("start", func() {
		removeTemp(d.dir)
		switch {
		case removeWhy == "":
			d.loadPTR(start)
		case d.removePTR(removeWhy):
			removeWhy = ""
		}
	})
	var wg sync.WaitGroup
	if d.reverseDNS {
		for range ptrWorkers {
			wg.Go(func() { d.resolveLoop(ctx) })
		}
	}
	defer func() {
		wg.Wait()
		d.safely("save", d.savePTR)
	}()
	d.safely("load", func() {
		if d.download {
			d.loadMeta()
		}
		d.reload(ctx)
	})

	lastSave := start
	for ctx.Err() == nil {
		now := d.now()
		if d.download && !now.Before(d.nextCheck(now)) {
			d.checkTables(ctx)
			now = d.now()
		}
		if removeWhy != "" && d.removePTR(removeWhy) { // the deletion at the start failed
			removeWhy = ""
		}
		d.ptr.sweep(now) // an answer that outlived its time to live leaves the file at the next save
		if d.ptr.isDirty() && (now.Sub(lastSave) >= ptrSaveEvery || now.Before(lastSave)) {
			d.safely("save", d.savePTR)
			lastSave = now
		}
		wait := d.tick
		if d.download {
			next := d.nextCheck(now)
			d.update(func(s *state) { s.next = next })
			wait = min(wait, max(next.Sub(now), time.Second))
		}
		select {
		case <-ctx.Done():
		case <-d.after(wait):
			d.safely("load", func() { d.reload(ctx) })
		}
	}
}

// safely runs a step of Run. This package runs inside the evidence logger, so a panic (a bug)
// is logged and reported by Status instead of stopping the service; the step leaves the tables
// whole, as they are only ever swapped in complete. It returns the panic's description ("" when
// there was none).
func (d *DB) safely(step string, fn func()) (panicked string) {
	defer func() {
		if p := recover(); p != nil {
			panicked = fmt.Sprintf("internal error (%s): %v", step, p)
			d.log.Error("ipintel: internal error (recovered)", "step", step, "panic", fmt.Sprint(p),
				"stack", string(debug.Stack()))
			d.update(func(s *state) { s.internal = panicked })
		}
	}()
	fn()
	return ""
}

// nextCheck is when the next look for newer tables is due: after the backoff of a failed check,
// at once when a table file is missing or cannot be loaded (damaged on disk, or a bad file put in
// its place: the check downloads it again, unconditionally, as the file is not the one
// downloaded), else Refresh after the last check that worked (or, for files placed by hand, after
// the older file was written) - never more than Refresh from now, so that a clock set back does
// not postpone it.
func (d *DB) nextCheck(now time.Time) time.Time {
	d.mu.Lock()
	checked, attempt, failures, loadErr := d.st.checked, d.st.attempt, d.st.failures, d.st.loadErr
	d.mu.Unlock()
	var next time.Time
	switch {
	case failures > 0:
		next = attempt.Add(backoff(failures, d.refresh))
	case !d.disk[fam4].exists || !d.disk[fam6].exists:
		return now
	case loadErr[fam4] != "" || loadErr[fam6] != "":
		// Else the family would keep no table (or an older one) until the next scheduled check, up
		// to Refresh (a week by default) away, although a good copy is one request away.
		return now
	case !checked.IsZero():
		next = checked.Add(d.refresh)
	default:
		next = d.disk[fam4].mtime
		if d.disk[fam6].mtime.Before(next) {
			next = d.disk[fam6].mtime
		}
		next = next.Add(d.refresh)
	}
	if limit := now.Add(d.refresh); next.After(limit) {
		next = limit
	}
	return next
}

// loadMeta reads ip2asn.json: the validators of the files downloaded and the schedule.
func (d *DB) loadMeta() {
	m, err := readMeta(filepath.Join(d.dir, nameMeta))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			d.log.Warn("ipintel: the IP database's metadata is not usable; the tables will be downloaded again", "err", err)
		}
		return
	}
	d.meta = metaFile{Version: metaVersion, V4: m.V4, V6: m.V6}
	d.update(func(s *state) { s.checked, s.attempt, s.failures, s.dlErr = m.Checked, m.Attempt, m.Failures, m.Error })
}

// reload loads each table file that changed on disk since it was last seen (at the start of
// Run: each file there). A file that cannot be used is reported and not read again until it
// changes; the table loaded before stays in use, and with Download a check is due at once
// (nextCheck), which downloads the file again.
func (d *DB) reload(ctx context.Context) {
	for _, f := range families {
		name := f.fileName()
		path := filepath.Join(d.dir, name)
		var st fileState
		fi, err := os.Stat(path)
		switch {
		case err == nil && fi.Mode().IsRegular():
			st = fileState{exists: true, size: fi.Size(), mtime: fi.ModTime()}
		case err == nil:
			err = errors.New("not a regular file")
		case errors.Is(err, fs.ErrNotExist):
			err = nil
		}
		if err != nil {
			d.disk[f] = fileState{}
			d.setLoadErr(f, fmt.Errorf("%s: %w", name, err))
			continue
		}
		if !st.exists {
			d.disk[f] = st
			if d.download {
				d.setLoadErr(f, nil) // the download fetches it
			} else {
				d.setLoadErr(f, fmt.Errorf("%s not found in %s", name, d.dir))
			}
			continue
		}
		if st.same(d.disk[f]) {
			continue
		}
		d.disk[f] = st // a file that cannot be used is not read again until it changes
		begin := time.Now()
		l, err := loadFile(ctx, path, f)
		if err != nil {
			if ctx.Err() != nil {
				d.disk[f] = fileState{} // stopping: read it at the next start
				return
			}
			d.setLoadErr(f, fmt.Errorf("%s: %w", name, err))
			d.log.Warn("ipintel: an IP database file is not usable", "file", name, "err", err)
			continue
		}
		d.disk[f].sum = l.sum
		if fm := d.meta.file(f); fm != nil && fm.SHA256 != l.sum {
			d.meta.setFile(f, nil) // not the file downloaded: its validators do not apply
		}
		d.install(l)
		d.setLoadErr(f, nil)
		d.log.Info("ipintel: IP database file loaded", "file", name, "rows", l.stats.rows, "ranges", l.ranges(),
			"skipped_lines", l.stats.bad, "written", rfc3339(l.at), "took", time.Since(begin).Round(time.Millisecond))
	}
}

// install swaps the table of a loaded file in: lookups see the old tables or the new ones,
// never a mix within one family.
func (d *DB) install(l *loaded) {
	for {
		old := d.tab.Load()
		n := new(tables)
		if old != nil {
			*n = *old
		}
		if l.fam == fam4 {
			n.v4 = l.t4
		} else {
			n.v6 = l.t6
		}
		n.at[l.fam] = l.at
		if d.tab.CompareAndSwap(old, n) {
			return
		}
	}
}

// setLoadErr notes why family f's table file cannot be loaded (nil: it can).
func (d *DB) setLoadErr(f family, err error) {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	d.update(func(s *state) { s.loadErr[f] = msg })
}
