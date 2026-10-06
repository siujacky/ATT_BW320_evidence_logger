package monitor

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// The gateway's syslog (docs/syslog-snmp-traffic.md §3.1-§3.2).
//
// The receiver (contracts.SyslogReceiver) keeps the datagrams it accepts from the gateway (and
// syslog.allow) until the monitor drains them. Every syslog.flush_interval the monitor moves them
// into the syslog store (contracts.SyslogStore), which keeps them in chunk files within the
// retention limits syslog.keep_mb and syslog.keep_days. The ledger, which can never delete
// anything, holds their proof: a syslog_chunk record with the SHA-256 of every chunk the store
// seals and a syslog_prune record for every deletion. Without a store the receiver is not run.
//
// No sealed chunk is left without its record and no deletion goes unrecorded, whatever fails
// (syslogBook). The store notes which sealed chunks have their record, so a chunk sealed while
// the ledger refused records is recorded once it takes them again - by the next start, should
// this run end first - and the chunks found sealed but not noted at a start are looked up in the
// ledger before they are recorded (a crash may have come between a record and its note). A
// deletion is chosen, recorded, and only then made. While a chunk waits for its record nothing
// is deleted, so a chunk's record always precedes the record of its deletion.
//
// The gateway's own Syslog setting (Diagnostics > Syslog) is only read in phase 1 of the plan:
// in the daily settings check, right after the notification setting and in the same login
// session, and again within minutes after this computer's address toward the gateway changed.
// Each read is recorded as a gateway_event syslog_setting with the page.

// syslogCounts are the syslog messages of this run (Status.Syslog): handed over by the receiver,
// of those appended to the syslog store, and the datagrams the receiver did not keep - from the
// allowed senders beyond its limits (dropped) and from other senders (rejected).
type syslogCounts struct{ received, recorded, dropped, rejected int64 }

// syslogGwRead is the gateway's Syslog setting as last read and recorded: the gateway_event
// syslog_setting (seq, ts and its After) and the setting - nil when the page was not understood,
// Problem then says so. It is not modified once published (the state cache shares it).
type syslogGwRead struct {
	Seq     uint64               `json:"seq"`
	TS      string               `json:"ts"`
	After   string               `json:"after"`
	Setting *model.SyslogSetting `json:"setting,omitempty"`
	Problem string               `json:"problem,omitempty"`
}

const (
	// syslogAgePruneEvery: with an age limit (syslog.keep_days) the store is pruned at least this
	// often, also when nothing was sealed (no message arrived), so that old chunks go in time.
	syslogAgePruneEvery = time.Hour
	// syslogLookBack: the ledger is searched for the record of a chunk found unrecorded at a
	// start from this long before the chunk's first receive time on (a clock set back between
	// a message and the record of its chunk).
	syslogLookBack = 24 * time.Hour
	// maxSyslogLast bounds the newest message's text in the status.
	maxSyslogLast = 200
	// Why the monitor seals the open chunk (SyslogChunk.Reason; the store seals by "size" itself).
	sealAge  = "age"
	sealStop = "stop"
	// syslogUnknown is the After of a gateway_event syslog_setting whose page was not understood.
	syslogUnknown = "unknown"
	// kickAddressChange asks the notification loop for an early settings check: this computer's
	// address toward the gateway changed, so the gateway's Syslog setting may no longer reach it.
	kickAddressChange = "address_change"
	// syslogRetentionWhat names the retention settings in their config_change records.
	syslogRetentionWhat = "syslog.keep_mb, syslog.keep_days (how much of the gateway's syslog is kept)"
)

// Status.Syslog.State values.
const (
	syslogStateOK        = "ok"
	syslogStateOff       = "off"
	syslogStateElsewhere = "elsewhere"
	syslogStateUnknown   = "unknown"
	syslogStateError     = "error"
)

// ---------------------------------------------------------------------------- receiver → store

// startSyslog prepares the syslog pipeline when Run starts, after monitor_start: the receiver
// accepts the gateway and syslog.allow; the chunk a previous run left open is sealed
// ("recovered") and recorded; the other sealed chunks the store has not noted as recorded wait
// for syslogReconcile, which looks for their records in the ledger first; and the retention
// limits are applied (they may have changed while the monitor was stopped, and keep_days counts
// that time too) - once nothing waits.
func (m *Monitor) startSyslog() {
	senders := m.syslogSenders()
	m.opts.Syslog.SetAllowed(senders)
	m.syslogMu.Lock()
	defer m.syslogMu.Unlock()
	now := m.now()
	recovered, err := m.recoverSyslogLocked(now)
	for _, c := range m.syslog.Unrecorded() {
		if !slices.ContainsFunc(recovered, func(r model.SyslogChunk) bool { return r.Name == c.Name }) {
			m.syslogUnverified[c.Name] = true // sealed by an earlier run: maybe recorded already
		}
	}
	m.syslogChecked = true
	m.recordPendingChunksLocked()
	errs := []error{err}
	if m.syslogSettledLocked() {
		errs = append(errs, m.pruneSyslogLocked(now))
	}
	m.noteSyslogStore(errors.Join(errs...))
	m.log.Info("syslog receiver starting", "listen", m.set.syslogListen, "senders", senders, "recovered_chunks", len(recovered),
		"unrecorded_chunks", len(m.syslogUnverified))
}

// recoverSyslogLocked has the store seal the chunks a previous run left open and returns them
// (they are recorded as unrecorded chunks). One it could not seal (another program holds its
// file) is tried again at every flush, SYSLOG_STORE_FAILING meanwhile. Caller holds syslogMu.
func (m *Monitor) recoverSyslogLocked(now time.Time) ([]model.SyslogChunk, error) {
	chunks, err := m.syslog.Recover(now)
	m.syslogRecoverDue = err != nil
	if err != nil {
		err = fmt.Errorf("sealing the chunk a previous run left open: %w", err)
	}
	return chunks, err
}

// syslogReconcile looks in the ledger for the syslog_chunk records of the chunks startSyslog
// found sealed but not noted as recorded - chunks sealed while the ledger refused records in a
// run that ended before it could record them, one sealed just before a crash (its record may or
// may not have been written), chunks whose sidecar the store rebuilt - and notes the records it
// finds; the other chunks are recorded now (late: their records come after the time they were
// sealed). The search runs without syslogMu, as it may read days of the ledger; meanwhile those
// chunks wait and nothing is deleted. A search that fails records them all: a chunk recorded
// twice is reported by the verifiers, one never recorded would not be.
func (m *Monitor) syslogReconcile(ctx context.Context) {
	m.syslogMu.Lock()
	want := map[string]string{} // chunk name → SHA-256
	var earliest time.Time
	for _, c := range m.syslog.Unrecorded() {
		if !m.syslogUnverified[c.Name] {
			continue
		}
		want[c.Name] = c.SHA256
		for _, ts := range []string{c.From, c.To} {
			if t, ok := parseTS(ts); ok && (earliest.IsZero() || t.Before(earliest)) {
				earliest = t
			}
		}
	}
	if len(want) == 0 {
		clear(m.syslogUnverified)
		m.syslogMu.Unlock()
		return
	}
	m.syslogMu.Unlock()
	began := time.Now()
	found, err := m.findChunkRecords(ctx, want, earliest)
	if ctx.Err() != nil {
		return // stopping: the next start looks again
	}
	m.syslogMu.Lock()
	defer m.syslogMu.Unlock()
	for name, seq := range found {
		m.markRecordedLocked(name, seq)
	}
	clear(m.syslogUnverified)
	if err != nil {
		m.log.Error("the evidence ledger could not be searched for the records of syslog chunks sealed before this start; they are recorded now (one recorded already is then recorded twice)",
			"chunks", len(want), "found", len(found), "err", err)
	}
	if n := len(want) - len(found); n > 0 {
		m.log.Warn("syslog chunks sealed before this start had no syslog_chunk record (the evidence ledger refused records, or the service stopped first); they are recorded now",
			"chunks", n, "already_recorded", len(found), "searched", time.Since(began).Round(time.Millisecond))
	} else {
		m.log.Info("the syslog chunks sealed before this start have their records", "chunks", len(found),
			"searched", time.Since(began).Round(time.Millisecond))
	}
	m.recordPendingChunksLocked()
}

// syslogScanEnd ends the ledger search for chunk records: every record, also one whose ts lies
// in the future of a clock set back since.
var syslogScanEnd = time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)

// findChunkRecords searches the ledger for the syslog_chunk records of the chunks in want (name
// → SHA-256): a record that names the chunk and states its SHA-256, the first of them. A chunk's
// record was written after its last message was received, on the clock that dates the records,
// so the search runs from syslogLookBack before the chunks' earliest receive time to the end of
// the ledger (all of it without one).
func (m *Monitor) findChunkRecords(ctx context.Context, want map[string]string, earliest time.Time) (map[string]uint64, error) {
	found := map[string]uint64{}
	if m.reader == nil {
		return found, errors.New("the monitor has no ledger reader")
	}
	var from time.Time
	if !earliest.IsZero() {
		from = earliest.Add(-syslogLookBack)
	}
	err := m.reader.ScanTime(from, syslogScanEnd, func(_ model.Envelope, body model.Body) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if body.Type != model.TypeSyslogChunk {
			return nil
		}
		var c model.SyslogChunk
		if json.Unmarshal(body.Data, &c) != nil {
			return nil
		}
		if sha, ok := want[c.Name]; ok && strings.EqualFold(sha, c.SHA256) {
			if _, dup := found[c.Name]; !dup {
				found[c.Name] = body.Seq
			}
			if len(found) == len(want) {
				return contracts.ErrStop
			}
		}
		return nil
	})
	if errors.Is(err, contracts.ErrStop) {
		err = nil
	}
	return found, err
}

// syslogSenders lists the senders the receiver accepts: the gateway and syslog.allow (an entry
// that is not an IP address, which the configuration's validation refuses, is skipped).
func (m *Monitor) syslogSenders() []netip.Addr {
	var out []netip.Addr
	for _, s := range append([]string{m.set.gwHost}, m.set.syslogAllow...) {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			m.log.Warn("syslog sender is not an IP address; ignored", "sender", s)
			continue
		}
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}

// syslogReceiverLoop runs the syslog receiver until ctx is done. When it cannot listen (another
// program uses the port, no permission) or stops listening, it is started again after a pause
// that doubles from syslogRetryMin up to syslogRetryMax while that goes on; Status shows
// SYSLOG_RECEIVER_DOWN meanwhile. What it received before stays until it is drained.
func (m *Monitor) syslogReceiverLoop(ctx context.Context) {
	pause := m.syslogRetryMin
	for {
		began := time.Now()
		var err error
		m.safely("syslog-receiver", func() { err = m.opts.Syslog.Run(ctx) })
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			err = errors.New("the syslog receiver stopped")
		}
		if time.Since(began) >= m.syslogRetryMax {
			pause = m.syslogRetryMin // it listened for a while: a new failure, not the same one going on
		}
		now := m.now()
		m.locked(func() {
			if m.st.rxDown == "" {
				m.st.rxDownSince = now
			}
			m.st.rxDown = errText(err)
		})
		if loud, n, since := m.syslogRxLog.fail(now, syslogRxReport); loud {
			m.log.Warn("the syslog receiver is not listening; it is started again later", "listen", m.set.syslogListen,
				"err", err, "attempts", n, "since", since, "retry_in", pause)
		} else {
			m.log.Debug("the syslog receiver is not listening", "err", err, "attempts", n)
		}
		if !sleepCtx(ctx, pause) {
			return
		}
		pause = min(2*pause, m.syslogRetryMax)
	}
}

// syslogLoop first settles the chunks found unrecorded at the start (syslogReconcile), then moves
// what the receiver received into the syslog store every flush interval (flushSyslog); Run
// flushes a last time once the receiver has stopped.
func (m *Monitor) syslogLoop(ctx context.Context) {
	m.safely("syslog", func() { m.syslogReconcile(ctx) })
	next := time.Now().Add(m.set.syslogFlush)
	for {
		if !sleepUntil(ctx, next, nil) {
			return
		}
		m.safely("syslog", func() {
			m.noteReceiverListening()
			m.flushSyslog(false)
		})
		next = next.Add(m.set.syslogFlush)
		if now := time.Now(); next.Before(now) {
			next = now.Add(m.set.syslogFlush)
		}
	}
}

// noteReceiverListening ends a reported receiver failure once the receiver listens again.
func (m *Monitor) noteReceiverListening() {
	addr, _ := m.opts.Syslog.Listening()
	if addr == "" {
		return
	}
	m.locked(func() { m.st.rxDown, m.st.rxDownSince = "", time.Time{} })
	if rec, n, since := m.syslogRxLog.ok(); rec {
		m.log.Info("the syslog receiver listens again", "addr", addr, "failed_attempts", n, "since", since)
	}
}

// flushSyslog moves what the receiver received since the previous flush into the syslog store
// and records what the store did: a syslog_chunk record for every chunk it sealed - by size
// while appending, by age, and at shutdown (final) whatever it holds - and, when anything was
// sealed, a syslog_prune record for the chunks the retention limits then delete. Chunks sealed
// before whose records the ledger refused are recorded first, and a chunk left open by a previous
// run that the start could not seal is tried again. While the ledger refuses records nothing is
// sealed by age, nothing is deleted, and the chunks sealed by size wait in the store for their
// records: the open chunk keeps the messages meanwhile, and one left open at shutdown is sealed by
// the next start ("recovered").
func (m *Monitor) flushSyslog(final bool) {
	rx, book := m.opts.Syslog, m.syslog
	m.syslogMu.Lock()
	defer m.syslogMu.Unlock()
	now := m.now()
	var errs []error
	used, sealed := false, 0 // a store operation ran; chunks sealed
	if m.syslogRecoverDue {
		_, err := m.recoverSyslogLocked(now)
		used = true
		errs = append(errs, err)
	}
	m.recordPendingChunksLocked()
	if msgs, dropped, rejected := rx.Drain(); len(msgs) > 0 || dropped > 0 || rejected > 0 {
		chunks, err := book.Append(msgs, dropped, rejected, now)
		used = true
		m.noteSyslogReceived(msgs, dropped, rejected, err == nil)
		if err != nil {
			errs = append(errs, fmt.Errorf("storing %s: %w", plural(len(msgs), "message", "messages"), err))
		}
		sealed += len(chunks) // by size (also when a later message failed)
		m.recordPendingChunksLocked()
	}
	if !m.appendFailing.Load() {
		reason := sealAge
		if final {
			reason = sealStop
		}
		c, err := book.Seal(now, reason, final)
		used = true
		if err != nil {
			errs = append(errs, fmt.Errorf("sealing the open chunk: %w", err))
		}
		if c != nil {
			sealed++
			m.recordPendingChunksLocked()
		}
	}
	if (sealed > 0 || m.syslogPruneDue || m.agePruneDueLocked()) && m.syslogSettledLocked() {
		errs = append(errs, m.pruneSyslogLocked(now))
	}
	if used { // a round without store operations says nothing about the store
		m.noteSyslogStore(errors.Join(errs...))
	}
	if final {
		if n := m.pendingChunksLocked(); n > 0 {
			if _, inMemory := m.syslog.(*memBook); inMemory {
				m.log.Error("sealed syslog chunks have no syslog_chunk record: the evidence ledger refused them, and this syslog store keeps no note of them",
					"chunks", n)
			} else {
				m.log.Warn("sealed syslog chunks have no syslog_chunk record yet (the evidence ledger refused them); the syslog store keeps them and the next start records them",
					"chunks", n)
			}
		}
	}
}

// recordPendingChunksLocked appends a syslog_chunk record for every sealed chunk the store has
// not noted as recorded, oldest first, and notes each (markRecordedLocked) - except chunks whose
// record was written but not noted yet (noted now) and chunks still to be looked up in the
// ledger (syslogReconcile; before startSyslog has sorted them, none is recorded). When the ledger
// refuses one, the rest wait: the store keeps them. Caller holds syslogMu.
func (m *Monitor) recordPendingChunksLocked() {
	if !m.syslogChecked {
		return
	}
	for _, c := range m.syslog.Unrecorded() {
		if seq, written := m.syslogMarkLater[c.Name]; written {
			m.markRecordedLocked(c.Name, seq)
			continue
		}
		if m.syslogUnverified[c.Name] {
			continue
		}
		ref, err := m.appendApply(model.TypeSyslogChunk, c, nil, nil)
		if err != nil {
			return
		}
		m.markRecordedLocked(c.Name, ref.Seq)
	}
}

// markRecordedLocked notes in the store that chunk name has its syslog_chunk record, seq. When
// that fails the record is not written again: the note is tried again at the next flush and,
// should the service stop first, the next start finds the record in the ledger. Caller holds
// syslogMu.
func (m *Monitor) markRecordedLocked(name string, seq uint64) {
	err := m.syslog.MarkRecorded(name, seq)
	if err == nil || errors.Is(err, contracts.ErrNotFound) { // not found: deleted meanwhile
		delete(m.syslogMarkLater, name)
		return
	}
	if _, again := m.syslogMarkLater[name]; !again {
		m.log.Warn("the syslog store could not note that a chunk has its syslog_chunk record; tried again later",
			"chunk", name, "seq", seq, "err", err)
	}
	m.syslogMarkLater[name] = seq
}

// syslogSettledLocked reports whether every chunk the store sealed has its syslog_chunk record
// and the ledger takes records: only then is anything deleted, so that a chunk's record precedes
// the record of its deletion. Caller holds syslogMu.
func (m *Monitor) syslogSettledLocked() bool {
	return !m.appendFailing.Load() && m.pendingChunksLocked() == 0
}

// pendingChunksLocked counts the sealed chunks without a syslog_chunk record (written but not
// yet noted ones aside). Caller holds syslogMu.
func (m *Monitor) pendingChunksLocked() int {
	n := 0
	for _, c := range m.syslog.Unrecorded() {
		if _, written := m.syslogMarkLater[c.Name]; !written {
			n++
		}
	}
	return n
}

// agePruneDueLocked: with an age limit, the store was not pruned for syslogAgePruneEvery.
// Caller holds syslogMu.
func (m *Monitor) agePruneDueLocked() bool {
	_, keepDays := m.syslogRetention()
	return keepDays > 0 && time.Since(m.syslogPrunedAt) >= syslogAgePruneEvery
}

// syslogRetention returns the configured retention limits.
func (m *Monitor) syslogRetention() (keepMB, keepDays int) {
	m.cfgMu.Lock()
	defer m.cfgMu.Unlock()
	return m.cfg.Syslog.KeepMB, m.cfg.Syslog.KeepDays
}

// pruneSyslogLocked applies the retention limits: the store chooses the oldest sealed chunks
// beyond them (PlanPrune), the deletion is recorded (syslog_prune, with the limits in force and
// what the store keeps then) and only then made (CommitPrune). A deletion the ledger refuses is
// not made, and is tried again at a later flush. Caller holds syslogMu and has checked that every
// sealed chunk has its record (syslogSettledLocked).
func (m *Monitor) pruneSyslogLocked(now time.Time) error {
	book := m.syslog
	plan, err := book.PlanPrune(now)
	m.syslogPrunedAt, m.syslogPruneDue = time.Now(), false
	if len(plan) > 0 {
		u := book.Usage() // without the chosen chunks
		keepMB, keepDays := u.KeepMB, u.KeepDays
		if keepMB <= 0 { // a store that does not report its limits applies the configured ones
			keepMB, keepDays = m.syslogRetention()
		}
		rec := model.SyslogPrune{Reason: pruneReason(plan, keepMB, keepDays, now), KeepMB: keepMB, KeepDays: keepDays,
			Deleted: slices.Clone(plan), KeptBytes: u.Bytes, KeptChunks: u.Chunks}
		if _, aerr := m.appendApply(model.TypeSyslogPrune, rec, nil, nil); aerr != nil {
			book.CancelPrune()
			m.syslogPruneDue = true
			m.log.Warn("syslog chunks beyond the retention limits are kept until their deletion can be recorded",
				"chunks", len(plan), "err", aerr)
		} else {
			deleted, cerr := book.CommitPrune()
			m.log.Info("syslog chunks deleted by the retention limits", "chunks", len(deleted), "keep_mb", keepMB, "keep_days", keepDays)
			err = errors.Join(err, cerr)
		}
	}
	if err != nil {
		return fmt.Errorf("deleting chunks beyond the retention limits: %w", err)
	}
	return nil
}

// pruneReason names the retention limit that deleted the chunks: "keep_days N" when the newest
// message of every one of them was older than the age limit, "keep_mb N" when none was, both
// when some were.
func pruneReason(deleted []model.SyslogChunkRef, keepMB, keepDays int, now time.Time) string {
	byAge := 0
	if keepDays > 0 {
		cutoff := now.Add(-time.Duration(keepDays) * 24 * time.Hour)
		for _, c := range deleted {
			if t, ok := parseTS(c.To); ok && t.Before(cutoff) {
				byAge++
			}
		}
	}
	mb, days := fmt.Sprintf("keep_mb %d", keepMB), fmt.Sprintf("keep_days %d", keepDays)
	switch byAge {
	case 0:
		return mb
	case len(deleted):
		return days
	}
	return days + " and " + mb
}

// noteSyslogReceived counts what a drain handed over (Status.Syslog); stored: the store took
// the messages.
func (m *Monitor) noteSyslogReceived(msgs []model.SyslogMessage, dropped, rejected int, stored bool) {
	m.locked(func() {
		c := &m.st.syslogCounts
		c.received += int64(len(msgs))
		c.dropped += int64(dropped)
		c.rejected += int64(rejected)
		if stored {
			c.recorded += int64(len(msgs))
		}
		if n := len(msgs); n > 0 {
			m.st.syslogLastAt, m.st.syslogLast = msgs[n-1].RX, syslogText(msgs[n-1])
		}
	})
}

// syslogText is a message's text for the status: its message part (after its app), else the
// exact datagram, shortened. Control characters are left for the display to escape.
func syslogText(msg model.SyslogMessage) string {
	text := strings.TrimSpace(msg.Msg)
	switch {
	case text != "" && msg.App != "":
		text = msg.App + ": " + text
	case text == "":
		text = strings.TrimSpace(msg.Raw)
	}
	if text == "" && msg.RawB64 != "" {
		text = "(a datagram that is not UTF-8 text)"
	}
	return truncate(text, maxSyslogLast)
}

// noteSyslogStore notes the outcome of a round of syslog store operations (err: what failed,
// nil when everything succeeded) for SYSLOG_STORE_FAILING, and logs failures through their gate.
func (m *Monitor) noteSyslogStore(err error) {
	now := m.now()
	if err == nil {
		m.locked(func() { m.st.storeFails, m.st.storeFailSince, m.st.storeFailErr = 0, time.Time{}, "" })
		if rec, n, since := m.syslogStoreLog.ok(); rec {
			m.log.Warn("the syslog store works again", "failures", n, "since", since)
		}
		return
	}
	text := strings.ReplaceAll(errText(err), "\n", "; ") // errors.Join puts one error per line
	m.locked(func() {
		if m.st.storeFails == 0 {
			m.st.storeFailSince = now
		}
		m.st.storeFails++
		m.st.storeFailErr = text
	})
	if loud, n, since := m.syslogStoreLog.fail(now, syslogStoreReport); loud {
		m.log.Error("syslog store failed", "err", text, "failures", n, "since", since)
	} else {
		m.log.Debug("syslog store failed", "err", text, "failures", n)
	}
}

// ---------------------------------------------------------------------------- retention

// SetSyslogRetention implements contracts.SyslogControl: how much of the gateway's syslog the
// syslog store keeps - at most keepMB MiB and, with keepDays above 0, nothing older than that
// many days (docs/syslog-snmp-traffic.md §3.2). Values outside the configuration's limits are
// refused with an error that says so, and nothing changes. Otherwise the setting is saved
// (SaveConfig) and recorded as a config_change - nothing changes when that record cannot be
// written - and applied at once: the store deletes what no longer fits, recorded as syslog_prune
// (after the records of any chunks still without one; should the ledger refuse those, the next
// flush that can record them deletes). Setting the limits in force changes and records nothing.
// As with TrustCert, a configuration
// that could not be saved still applies until the monitor restarts: the change is returned with
// the save error.
func (m *Monitor) SetSyslogRetention(ctx context.Context, keepMB, keepDays int, actor string) (model.ConfigChange, error) {
	actor, err := label("actor", actor)
	if err != nil {
		return model.ConfigChange{}, err
	}
	if actor == "" {
		actor = "operator"
	}
	if keepMB < config.MinSyslogKeepMB || keepMB > config.MaxSyslogKeepMB {
		return model.ConfigChange{}, fmt.Errorf("the syslog size limit (keep_mb) must be %d to %d MB, not %d",
			config.MinSyslogKeepMB, config.MaxSyslogKeepMB, keepMB)
	}
	if keepDays < 0 || keepDays > config.MaxSyslogKeepDays {
		return model.ConfigChange{}, fmt.Errorf("the syslog age limit (keep_days) must be 0 (no age limit) to %d days, not %d",
			config.MaxSyslogKeepDays, keepDays)
	}
	if err := ctx.Err(); err != nil {
		return model.ConfigChange{}, err
	}
	m.syslogMu.Lock() // no flush prunes between the change and the store applying it
	defer m.syslogMu.Unlock()
	m.cfgMu.Lock()
	beforeMB, beforeDays := m.cfg.Syslog.KeepMB, m.cfg.Syslog.KeepDays
	cc := model.ConfigChange{Target: "monitor", What: syslogRetentionWhat, Before: retentionText(beforeMB, beforeDays),
		After: retentionText(keepMB, keepDays), Actor: actor, Result: "applied"}
	if beforeMB == keepMB && beforeDays == keepDays {
		m.cfgMu.Unlock()
		cc.Result = "unchanged: already in force"
		return cc, nil
	}
	m.cfg.Syslog.KeepMB, m.cfg.Syslog.KeepDays = keepMB, keepDays
	var saveErr error
	if m.opts.SaveConfig != nil {
		saveErr = m.opts.SaveConfig(m.cfg)
	}
	m.cfgMu.Unlock()
	book := m.syslog
	if saveErr != nil {
		cc.Result = "applied until the monitor restarts: the configuration could not be saved: " + errText(saveErr)
	}
	if book == nil {
		cc.Result += "; the syslog store is not running, so nothing is deleted now"
	}
	if _, err := m.appendApply(model.TypeConfigChange, cc, nil, func(ref model.Ref) {
		m.addEvidenceLocked(nil, model.TypeConfigChange, ref.Seq, model.EvidenceRef{Seq: ref.Seq, Type: model.TypeConfigChange, Note: "syslog retention " + cc.After})
	}); err != nil {
		// Not recorded: undone, so that the limits never change - and nothing is deleted by
		// them - without a ledger record.
		m.cfgMu.Lock()
		if m.cfg.Syslog.KeepMB == keepMB && m.cfg.Syslog.KeepDays == keepDays {
			m.cfg.Syslog.KeepMB, m.cfg.Syslog.KeepDays = beforeMB, beforeDays
			if m.opts.SaveConfig != nil {
				_ = m.opts.SaveConfig(m.cfg)
			}
		}
		m.cfgMu.Unlock()
		return model.ConfigChange{}, err
	}
	if book != nil {
		book.SetRetention(keepMB, keepDays)
		// The deletion waits for the records of chunks that have none yet (a flush makes it).
		m.recordPendingChunksLocked()
		if m.syslogSettledLocked() {
			m.noteSyslogStore(m.pruneSyslogLocked(m.now()))
		} else {
			m.syslogPruneDue = true
		}
	}
	m.log.Warn("syslog retention changed", "before", cc.Before, "after", cc.After, "actor", actor, "result", cc.Result)
	return cc, saveErr
}

// retentionText states retention limits as config_change records them: "keep_mb 100, keep_days 0".
func retentionText(keepMB, keepDays int) string {
	return fmt.Sprintf("keep_mb %d, keep_days %d", keepMB, keepDays)
}

// ---------------------------------------------------------------------------- the gateway's setting

// checkSyslogSetting reads the gateway's Syslog page (authenticated, and only read: phase 1 of
// the plan never calls SetSyslog) and records the read as a gateway_event syslog_setting with
// the page attached: Before is the setting as last recorded, After the setting read
// (syslogSummary) - or "unknown" when the page was not understood, whose exact bytes are what
// phase 2 needs. A read that fails is not recorded; Status.Syslog says why. why (may be "") says
// what asked for the check. Caller holds notifMu.
func (m *Monitor) checkSyslogSetting(ctx context.Context, why string) {
	var (
		set model.SyslogSetting
		raw []byte
		err error
	)
	m.withGatewayAuth(func() {
		sctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		set, raw, err = m.gw.Syslog(sctx)
	})
	if ctx.Err() != nil {
		return
	}
	now := m.now()
	if err != nil && len(raw) == 0 {
		problem := "the latest check could not read the gateway's Syslog page: " + errText(err)
		m.locked(func() { m.st.syslogErr = problem })
		if loud, n, since := m.syslogReadLog.fail(now, syslogReadReport); loud {
			m.log.Warn("cannot read the gateway's Syslog page; it is read again at the next settings check", "err", err, "failures", n, "since", since)
		} else {
			m.log.Debug("cannot read the gateway's Syslog page", "err", err, "failures", n)
		}
		return
	}
	if rec, n, since := m.syslogReadLog.ok(); rec {
		m.log.Info("the gateway's Syslog page can be read again", "failures", n, "since", since)
	}
	// The gateway client returns the page with an error only when it read the page but did not
	// understand it (gateway.ErrSyslogPage): that read is recorded too, with the problem.
	var blobs []string
	if len(raw) > 0 {
		if id, perr := m.putBlob(raw); perr == nil {
			blobs = append(blobs, id)
		}
	}
	m.mu.Lock()
	prev, localIP := m.st.syslogGw, m.st.localIP
	m.mu.Unlock()
	read := &syslogGwRead{}
	ev := model.GatewayEvent{Kind: model.GwEvSyslogSetting}
	if prev != nil {
		ev.Before = prev.After
	}
	if err == nil {
		cp := set
		cp.Levels = slices.Clone(set.Levels)
		read.Setting = &cp
		ev.After, ev.Detail = syslogSummary(set), syslogDetail(set, localIP, m.set.syslogPort, why)
	} else {
		read.Problem = "the gateway's Syslog page was not understood: " + errText(err)
		ev.After = syslogUnknown
		ev.Detail = fmt.Sprintf("Syslog page (Diagnostics > Syslog) read%s but not understood: %s; the page is kept with this record (read only: the monitor did not change the setting)",
			whyText(why), errText(err))
	}
	read.After = ev.After
	if _, aerr := m.appendApply(model.TypeGatewayEvent, ev, blobs, func(ref model.Ref) {
		read.Seq, read.TS = ref.Seq, ref.TS
		m.st.syslogGw, m.st.syslogErr = read, ""
	}); aerr != nil {
		m.locked(func() {
			m.st.syslogErr = "the gateway's Syslog setting was read but could not be recorded in the evidence ledger: " + errText(aerr)
		})
		return
	}
	if err != nil {
		m.log.Warn("the gateway's Syslog page was not understood; the page is recorded", "err", err)
		return
	}
	m.log.Info("gateway syslog setting read", "setting", ev.After, "before", ev.Before)
}

// whyText turns what asked for a settings check into words after "read" ("" for the regular
// check).
func whyText(why string) string {
	if why == "" {
		return ""
	}
	return " " + why
}

// syslogDest is where a Syslog setting sends the log: "server:port".
func syslogDest(s model.SyslogSetting) string {
	return net.JoinHostPort(truncate(strings.TrimSpace(s.Server), 128), strconv.Itoa(s.Port))
}

// syslogSummary renders a Syslog setting as a gateway_event syslog_setting records it: "off", or
// "on -> 192.168.1.71:514, level Informational" (parseSyslogSummary reads it back).
func syslogSummary(s model.SyslogSetting) string {
	if !s.Enabled {
		return "off"
	}
	out := "on -> " + syslogDest(s)
	if l := strings.TrimSpace(s.Level); l != "" {
		out += ", level " + truncate(l, 128)
	}
	return out
}

// parseSyslogSummary reads a setting back from syslogSummary's text (nil: not a setting, e.g.
// "unknown"). The options the page offered (Levels) are not part of it.
func parseSyslogSummary(after string) *model.SyslogSetting {
	if after == "off" {
		return &model.SyslogSetting{}
	}
	rest, ok := strings.CutPrefix(after, "on -> ")
	if !ok {
		return nil
	}
	dest, level, _ := strings.Cut(rest, ", level ")
	host, port, err := net.SplitHostPort(dest)
	if err != nil {
		return nil
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return nil
	}
	return &model.SyslogSetting{Enabled: true, Server: host, Port: p, Level: level}
}

// syslogReadFromEvent is the setting a recorded gateway_event syslog_setting states (the rebuild).
func syslogReadFromEvent(ev model.GatewayEvent, seq uint64, ts string) *syslogGwRead {
	r := &syslogGwRead{Seq: seq, TS: ts, After: ev.After, Setting: parseSyslogSummary(ev.After)}
	if r.Setting == nil {
		r.Problem = fmt.Sprintf("the gateway's Syslog page was not understood at the latest read (record #%d)", seq)
	}
	return r
}

// syslogDetail words a read of the gateway's Syslog page for its gateway_event.
func syslogDetail(s model.SyslogSetting, localIP string, port int, why string) string {
	var b strings.Builder
	b.WriteString("Syslog page (Diagnostics > Syslog) read" + whyText(why) + ": ")
	if !s.Enabled {
		b.WriteString("the gateway does not send its log to a syslog server")
	} else {
		b.WriteString("the gateway sends its log to " + syslogDest(s))
		if l := strings.TrimSpace(s.Level); l != "" {
			b.WriteString(" at level " + truncate(l, 128))
		}
		switch state, _ := syslogTargetState(s, localIP, port); state {
		case syslogStateOK:
			b.WriteString(", which is this computer and the port its syslog receiver is set up for")
		case syslogStateElsewhere:
			b.WriteString(", not to this computer (" + net.JoinHostPort(localIP, strconv.Itoa(port)) + ")")
		default:
			b.WriteString(" (this computer's address toward the gateway is not known yet)")
		}
	}
	if len(s.Levels) > 0 {
		b.WriteString("; log levels offered: " + truncate(strings.Join(s.Levels, ", "), 300))
	}
	b.WriteString("; read only: the monitor did not change the setting")
	return b.String()
}

// syslogTargetState compares a Syslog setting of the gateway with this computer: "ok" when the
// gateway sends to this computer's address toward it (localIP) on syslog.port (port), "off",
// "elsewhere", or "unknown" while this computer's address is not known. problem words the
// states other than ok.
func syslogTargetState(s model.SyslogSetting, localIP string, port int) (state, problem string) {
	switch {
	case !s.Enabled:
		return syslogStateOff, "the gateway does not send its log to a syslog server (its Syslog setting is off)"
	case localIP == "":
		return syslogStateUnknown, "the gateway sends its log to " + syslogDest(s) + "; this computer's address toward the gateway is not known yet"
	case !sameIP(s.Server, localIP) || s.Port != port:
		return syslogStateElsewhere, fmt.Sprintf("the gateway sends its log to %s, not to this computer (%s)",
			syslogDest(s), net.JoinHostPort(localIP, strconv.Itoa(port)))
	}
	return syslogStateOK, ""
}

// sameIP compares two addresses as IP addresses when both are, else as text (case aside).
func sameIP(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	x, errX := netip.ParseAddr(a)
	y, errY := netip.ParseAddr(b)
	if errX == nil && errY == nil {
		return x.Unmap() == y.Unmap()
	}
	return a != "" && strings.EqualFold(a, b)
}

// ---------------------------------------------------------------------------- status

// syslogStatusLocked returns Status.Syslog: nil when the monitor has neither a syslog receiver
// nor a store and knows nothing of the gateway's Syslog setting. addr and lerr are what the
// receiver's Listening reported and usage the store's volume (both read without mu); hasCode: a
// gateway access code is stored. Phase 1 only reads the gateway's setting: Enforce is false and
// Target nil. Caller holds mu.
func (m *Monitor) syslogStatusLocked(addr string, lerr error, usage *model.SyslogUsage, hasCode bool) *model.SyslogStatus {
	gw := m.st.syslogGw
	if m.opts.Syslog == nil && m.opts.SyslogStore == nil && gw == nil && m.st.syslogErr == "" {
		return nil
	}
	c := m.st.syslogCounts
	s := &model.SyslogStatus{
		Enabled:  m.syslogOn,
		Received: c.received,
		Recorded: c.recorded,
		Dropped:  c.dropped,
		Rejected: c.rejected,
		LastAt:   m.st.syslogLastAt,
		Last:     m.st.syslogLast,
		Store:    usage,
	}
	if m.syslogOn {
		s.Listening, s.Listen, s.ListenErr = addr != "", cmp.Or(addr, m.set.syslogListen), errText(lerr)
		if !s.Listening && s.ListenErr == "" {
			s.ListenErr = m.st.rxDown
		}
	}
	if gw != nil {
		if gw.Setting != nil {
			cp := *gw.Setting
			cp.Levels = slices.Clone(cp.Levels)
			s.Gateway = &cp
		}
		s.GatewayAt, s.GatewaySeq = gw.TS, gw.Seq
	}
	s.State, s.Problem = m.syslogStateLocked(hasCode)
	return s
}

// syslogStateLocked is Status.Syslog's State and Problem: "error" while the latest check of the
// gateway's Syslog setting failed; "unknown" before it was read, when its page was not understood
// and while this computer's address toward the gateway is not known; else what syslogTargetState
// finds. Caller holds mu.
func (m *Monitor) syslogStateLocked(hasCode bool) (state, problem string) {
	gw := m.st.syslogGw
	switch {
	case m.st.syslogErr != "":
		return syslogStateError, m.st.syslogErr
	case gw == nil && !hasCode:
		return syslogStateUnknown, "the gateway's Syslog setting has not been read: reading it needs the gateway access code (att-monitor set-access-code)"
	case gw == nil:
		return syslogStateUnknown, "the gateway's Syslog setting has not been read yet"
	case gw.Setting == nil:
		return syslogStateUnknown, cmp.Or(gw.Problem, "the gateway's Syslog page was not understood")
	}
	return syslogTargetState(*gw.Setting, m.st.localIP, m.set.syslogPort)
}

// syslogConditionsLocked returns SYSLOG_RECEIVER_DOWN while the syslog pipeline runs but the
// receiver does not listen (addr and lerr: what its Listening reported) and SYSLOG_STORE_FAILING
// while the syslog store fails. Caller holds mu.
func (m *Monitor) syslogConditionsLocked(addr string, lerr error) []model.Condition {
	var out []model.Condition
	if why := cmp.Or(errText(lerr), m.st.rxDown); m.syslogOn && addr == "" && why != "" {
		c := model.Condition{
			Code:     condSyslogReceiverDown,
			Severity: "warning",
			Message: fmt.Sprintf("The syslog receiver is not listening on %s (UDP): %s. The AT&T gateway's log messages are not received; the receiver is started again every few minutes (is another program using the port?).",
				m.set.syslogListen, strings.TrimRight(why, ". ")),
		}
		if !m.st.rxDownSince.IsZero() {
			c.Since = fmtTS(m.st.rxDownSince)
		}
		out = append(out, c)
	}
	if m.st.storeFails > 0 {
		out = append(out, model.Condition{
			Code:     condSyslogStoreFailing,
			Severity: "warning",
			Message: fmt.Sprintf("The syslog store has failed since %s (%s; latest error: %s): the AT&T gateway's log messages received meanwhile may not be kept. Check the free space and the permissions of the syslog folder in the data directory.",
				fmtHuman(m.st.storeFailSince), plural(m.st.storeFails, "failure", "failures"), m.st.storeFailErr),
			Since: fmtTS(m.st.storeFailSince),
		})
	}
	return out
}
