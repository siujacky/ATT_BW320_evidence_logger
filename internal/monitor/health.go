package monitor

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// ---------------------------------------------------------------------------- log gates

// logGate keeps a failure that repeats every cycle or poll (the gateway unreachable for days,
// a full disk) from flooding the operational log, whose Warn and Error records also go to the
// Windows Application event log in service mode: the first failure is reported, then at most one
// summary per period while the failures go on, and the recovery once. The other failures are
// logged at Debug.
type logGate struct {
	mu       sync.Mutex
	failing  bool
	since    time.Time
	count    int
	lastLoud time.Time
}

// fail notes one failure at now and reports whether to log it at its full level, with the
// number of failures and the time of the first one in the current streak.
func (g *logGate) fail(now time.Time, every time.Duration) (loud bool, count int, since time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.count++
	if !g.failing {
		g.failing, g.since, g.count, g.lastLoud = true, now, 1, now
		return true, 1, now
	}
	if now.Sub(g.lastLoud) >= every || now.Before(g.lastLoud) {
		g.lastLoud = now
		return true, g.count, g.since
	}
	return false, g.count, g.since
}

// ok notes a success and reports whether it ends a streak of failures (and its size and start).
func (g *logGate) ok() (recovered bool, count int, since time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.failing {
		return false, 0, time.Time{}
	}
	recovered, count, since = true, g.count, g.since
	g.failing, g.count = false, 0
	return recovered, count, since
}

// How often a failure that goes on is reported again.
const (
	snapFailReport   = time.Hour
	appendFailReport = 10 * time.Minute
	anchorFailReport = time.Hour
	tsaProblemReport = 6 * time.Hour
	notifFailReport  = 6 * time.Hour
	blobFailReport   = 10 * time.Minute
	cacheFailReport  = 6 * time.Hour
)

// ---------------------------------------------------------------------------- ledger write health

// noteAppendFailure records that the ledger refused a record (status condition, Run's exit
// rules) and logs it through its gate. A ledger that reports itself unusable
// (contracts.ErrLedgerBroken: it refuses every record until it is reopened) ends Run at once.
// Caller may hold stMu.
func (m *Monitor) noteAppendFailure(typ string, err error) {
	now := m.now()
	broken := errors.Is(err, contracts.ErrLedgerBroken)
	m.locked(func() {
		if m.st.appendFails == 0 {
			m.st.appendFailSince = now
		}
		m.st.appendFails++
		m.st.appendFailErr = errText(err)
		m.st.appendBroken = m.st.appendBroken || broken
	})
	m.appendFailing.Store(true)
	if broken {
		m.ledgerBrokenOnce.Do(func() {
			m.brokenErr = fmt.Errorf("the evidence ledger is unusable: a failed write could not be undone, so it refuses every record until it is reopened (a %s record was refused: %w); stopping so that the service manager restarts the service, which reopens the ledger with its crash recovery",
				typ, err)
			close(m.ledgerBroken)
		})
	}
	if loud, n, since := m.appendFailLog.fail(now, appendFailReport); loud {
		m.log.Error("ledger append failed", "type", typ, "err", err, "failures", n, "since", since)
	} else {
		m.log.Debug("ledger append failed", "type", typ, "err", err, "failures", n)
	}
}

// noteAppendSuccess clears the failure state after a record was written. Caller may hold stMu.
func (m *Monitor) noteAppendSuccess() {
	if !m.appendFailing.Load() {
		return
	}
	m.appendFailing.Store(false)
	m.locked(func() {
		m.st.appendFails, m.st.appendFailSince, m.st.appendFailErr, m.st.appendBroken = 0, time.Time{}, "", false
	})
	if rec, n, since := m.appendFailLog.ok(); rec {
		m.log.Warn("ledger appends succeed again", "failed_records", n, "since", since)
	}
}

// ledgerFatal returns the error Run ends with when the ledger has refused every record for
// ledgerFailExit (at least three attempts) although the data volume has space: a store whose
// failed write could not be rolled back stays unusable until it is reopened, which a restart of
// the service does (with its crash recovery). With the volume (nearly) full a restart cannot
// help, so the monitor keeps running and keeps showing the condition. (A ledger that reports
// itself unusable, contracts.ErrLedgerBroken, does not wait for this: noteAppendFailure.)
func (m *Monitor) ledgerFatal() error {
	m.mu.Lock()
	since, n, last := m.st.appendFailSince, m.st.appendFails, m.st.appendFailErr
	m.mu.Unlock()
	if since.IsZero() || n < 3 || m.now().Sub(since) < m.ledgerFailExit {
		return nil
	}
	m.checkDisk()
	m.mu.Lock()
	d := m.st.disk
	m.mu.Unlock()
	if d.known && d.free < diskCriticalBytes {
		return nil
	}
	return fmt.Errorf("the evidence ledger has refused every record since %s (%d attempts, latest error: %s); stopping so that the ledger is reopened",
		fmtHuman(since), n, last)
}

// ledgerWatch ends Run (through fatal) once ledgerFatal says so.
func (m *Monitor) ledgerWatch(ctx context.Context, fatal chan<- error) {
	t := time.NewTicker(max(m.set.fast, 10*time.Millisecond))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := m.ledgerFatal(); err != nil {
			select {
			case fatal <- err:
			default:
			}
			return
		}
	}
}

// ledgerFailingCondition is shown while the ledger refuses records (critical: nothing that
// happens is being recorded). broken: the ledger reported itself unusable until it is reopened
// (contracts.ErrLedgerBroken), so the monitor is stopping.
func ledgerFailingCondition(since time.Time, n int, last string, broken bool) model.Condition {
	msg := fmt.Sprintf("The evidence ledger has refused every record since %s (%s; latest error: %s): nothing is being recorded, so this period will be missing from the evidence. Free disk space on the data volume or restart the service.",
		fmtHuman(since), plural(n, "attempt", "attempts"), last)
	if broken {
		msg = fmt.Sprintf("The evidence ledger is unusable since %s: a failed write could not be undone, so it refuses every record until it is reopened (%s; latest error: %s). The monitor stops so that Windows restarts the service, which reopens the ledger with its crash recovery; until then nothing is recorded.",
			fmtHuman(since), plural(n, "refused record", "refused records"), last)
	}
	return model.Condition{Code: condLedgerWriteFailing, Severity: "critical", Message: msg, Since: fmtTS(since)}
}

// ---------------------------------------------------------------------------- disk space

// Free space on the data volume below these shows DISK_SPACE_LOW (warning, then critical).
// The ledger grows by about 50 MB a day, 70 MB on days with incidents (raw pages every 15 s).
const (
	diskWarnBytes     = 2 << 30
	diskCriticalBytes = 512 << 20
)

// diskSpace is the last measurement of the data volume.
type diskSpace struct {
	known       bool
	free, total uint64
	at          time.Time
}

// checkDisk measures the free space of the data volume (best effort).
func (m *Monitor) checkDisk() {
	if m.diskFree == nil || m.opts.DataDir == "" {
		return
	}
	free, total, err := m.diskFree(m.opts.DataDir)
	if err != nil {
		m.log.Debug("cannot measure the free space of the data volume", "dir", m.opts.DataDir, "err", err)
		return
	}
	now := m.now()
	m.locked(func() { m.st.disk = diskSpace{known: true, free: free, total: total, at: now} })
}

// diskCondition is shown while the data volume is low on space.
func diskCondition(d diskSpace, dir string) (model.Condition, bool) {
	if !d.known || d.free >= diskWarnBytes {
		return model.Condition{}, false
	}
	sev := "warning"
	if d.free < diskCriticalBytes {
		sev = "critical"
	}
	return model.Condition{
		Code:     condDiskSpaceLow,
		Severity: sev,
		Message: fmt.Sprintf("The volume holding the evidence (%s) has only %s free of %s: the ledger grows by about 50-70 MB a day, and once the volume is full no record can be written. Free space on it.",
			dir, fmtBytes(d.free), fmtBytes(d.total)),
		Since: fmtTS(d.at),
	}, true
}

// fmtBytes renders a size in MB or GB.
func fmtBytes(b uint64) string {
	if b >= 1<<30 {
		return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
	}
	return fmt.Sprintf("%d MB", b>>20)
}

// ---------------------------------------------------------------------------- stale status

// staleVerdict is the status verdict once no cycle has been recorded for more than the gap
// limit: the last verdict no longer describes the present (DESIGN §6: a monitoring gap).
func staleVerdict(last model.Verdict, lastAt, now time.Time, ledgerFailing bool) model.Verdict {
	was := last.State
	if last.Cause != "" {
		was += "/" + last.Cause
	}
	reasons := []string{fmt.Sprintf("no monitoring cycle has been recorded for %s (the last one, at %s, was %s), so the current state is unknown",
		now.Sub(lastAt).Round(time.Second), fmtHuman(lastAt), was)}
	if ledgerFailing {
		reasons = append(reasons, "the evidence ledger is refusing records (see the LEDGER_WRITE_FAILING condition)")
	}
	return model.Verdict{State: model.StateUnknown, Attribution: model.AttrUndetermined, Reasons: reasons, Rules: RulesVersion}
}
