package monitor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// ---------------------------------------------------------------------------- fakes

// fakeSyslogRx is a contracts.SyslogReceiver: Run "listens" until its context ends, or fails at
// once with runErr (and Listening reports that error, as the real receiver does); tests push
// what Drain hands over.
type fakeSyslogRx struct {
	mu                sync.Mutex
	runErr            error
	runs              int
	addr              string
	listenErr         error
	allowed           []netip.Addr
	pending           []model.SyslogMessage
	dropped, rejected int
}

func (f *fakeSyslogRx) Run(ctx context.Context) error {
	f.mu.Lock()
	f.runs++
	if err := f.runErr; err != nil {
		f.addr, f.listenErr = "", err
		f.mu.Unlock()
		return err
	}
	f.addr, f.listenErr = "127.0.0.1:5514", nil
	f.mu.Unlock()
	<-ctx.Done()
	f.mu.Lock()
	f.addr = ""
	f.mu.Unlock()
	return nil
}

func (f *fakeSyslogRx) Drain() ([]model.SyslogMessage, int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	msgs, dropped, rejected := f.pending, f.dropped, f.rejected
	f.pending, f.dropped, f.rejected = nil, 0, 0
	return msgs, dropped, rejected
}

func (f *fakeSyslogRx) SetAllowed(addrs []netip.Addr) {
	f.mu.Lock()
	f.allowed = slices.Clone(addrs)
	f.mu.Unlock()
}

func (f *fakeSyslogRx) Listening() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.addr, f.listenErr
}

// push hands messages and discard counts to the next Drain.
func (f *fakeSyslogRx) push(dropped, rejected int, msgs ...model.SyslogMessage) {
	f.mu.Lock()
	f.pending = append(f.pending, msgs...)
	f.dropped += dropped
	f.rejected += rejected
	f.mu.Unlock()
}

func (f *fakeSyslogRx) setRunErr(err error) {
	f.mu.Lock()
	f.runErr = err
	f.mu.Unlock()
}

func (f *fakeSyslogRx) runCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.runs
}

var _ contracts.SyslogReceiver = (*fakeSyslogRx)(nil)

// fakeSyslogStore is a contracts.SyslogStore: it seals the open chunk at chunkMsgs messages
// ("size") and, by age, when its first message is chunkAge old (or always, with old: this
// computer's clock may not advance between two calls); every sealed chunk counts as 1 MiB of
// gzip, so it keeps at most keepMB of them, and with keepDays none whose newest message is older
// than that.
type fakeSyslogStore struct {
	mu                        sync.Mutex
	calls                     []string
	chunkMsgs                 int
	chunkAge                  time.Duration
	old                       bool
	keepMB, keepDays          int
	open                      []model.SyslogMessage
	openSince                 time.Time
	openDropped, openRejected int
	sealed                    []model.SyslogChunk
	recovered                 []model.SyslogChunk // what Recover seals
	n                         int
	appendErr, sealErr        error
	pruneErr, recoverErr      error
}

func newFakeSyslogStore() *fakeSyslogStore { return &fakeSyslogStore{chunkMsgs: 1000, keepMB: 100} }

func (s *fakeSyslogStore) call(c string) { s.calls = append(s.calls, c) }

func (s *fakeSyslogStore) callLog() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.calls)
}

func (s *fakeSyslogStore) set(f func(s *fakeSyslogStore)) {
	s.mu.Lock()
	f(s)
	s.mu.Unlock()
}

func (s *fakeSyslogStore) sealLocked(reason string) model.SyslogChunk {
	s.n++
	c := model.SyslogChunk{Name: fmt.Sprintf("syslog-%03d.jsonl.gz", s.n), From: s.open[0].RX, To: s.open[len(s.open)-1].RX,
		Messages: len(s.open), Dropped: s.openDropped, Rejected: s.openRejected, SHA256: fmt.Sprintf("%064x", s.n),
		GzBytes: 1 << 20, Reason: reason}
	for _, m := range s.open {
		c.Bytes += int64(len(m.Raw))
	}
	s.sealed = append(s.sealed, c)
	s.open, s.openDropped, s.openRejected = nil, 0, 0
	return c
}

func (s *fakeSyslogStore) Recover(now time.Time) ([]model.SyslogChunk, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.call("recover")
	if s.recoverErr != nil {
		return nil, s.recoverErr
	}
	s.sealed = append(s.sealed, s.recovered...)
	return slices.Clone(s.recovered), nil
}

func (s *fakeSyslogStore) Append(msgs []model.SyslogMessage, dropped, rejected int, now time.Time) ([]model.SyslogChunk, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.call("append")
	if s.appendErr != nil {
		return nil, s.appendErr
	}
	var out []model.SyslogChunk
	s.openDropped += dropped
	s.openRejected += rejected
	for _, m := range msgs {
		if len(s.open) == 0 {
			s.openSince = now
		}
		s.open = append(s.open, m)
		if len(s.open) >= s.chunkMsgs {
			out = append(out, s.sealLocked("size"))
		}
	}
	return out, nil
}

func (s *fakeSyslogStore) Seal(now time.Time, reason string, force bool) (*model.SyslogChunk, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.call("seal " + reason)
	if s.sealErr != nil {
		return nil, s.sealErr
	}
	if len(s.open) == 0 || (!force && !s.old && (s.chunkAge <= 0 || now.Sub(s.openSince) < s.chunkAge)) {
		return nil, nil
	}
	c := s.sealLocked(reason)
	return &c, nil
}

func (s *fakeSyslogStore) Prune(now time.Time) ([]model.SyslogChunkRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.call("prune")
	if s.pruneErr != nil {
		return nil, s.pruneErr
	}
	var out []model.SyslogChunkRef
	for len(s.sealed) > 0 {
		c := s.sealed[0]
		to, _ := parseTS(c.To)
		old := s.keepDays > 0 && to.Before(now.Add(-time.Duration(s.keepDays)*24*time.Hour))
		if len(s.sealed) <= s.keepMB && !old {
			break
		}
		out = append(out, model.SyslogChunkRef{Name: c.Name, SHA256: c.SHA256, From: c.From, To: c.To, Messages: c.Messages, GzBytes: c.GzBytes})
		s.sealed = s.sealed[1:]
	}
	return out, nil
}

func (s *fakeSyslogStore) SetRetention(keepMB, keepDays int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.call(fmt.Sprintf("retention %d %d", keepMB, keepDays))
	s.keepMB, s.keepDays = keepMB, keepDays
}

func (s *fakeSyslogStore) Usage() model.SyslogUsage {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := model.SyslogUsage{Chunks: len(s.sealed), OpenMessages: len(s.open), KeepMB: s.keepMB, KeepDays: s.keepDays}
	for _, c := range s.sealed {
		u.Bytes += c.GzBytes
		u.Messages += int64(c.Messages)
	}
	for _, m := range s.open {
		u.Bytes += int64(len(m.Raw))
	}
	u.Messages += int64(len(s.open))
	return u
}

func (s *fakeSyslogStore) Query(ctx context.Context, from, to time.Time, match func(*model.SyslogMessage) bool, limit int) ([]model.SyslogEntry, bool, error) {
	return nil, false, nil
}

func (s *fakeSyslogStore) OpenChunk(name string) (io.ReadCloser, error) {
	return nil, contracts.ErrNotFound
}

var _ contracts.SyslogStore = (*fakeSyslogStore)(nil)

// syslogRig is a rig whose monitor runs the syslog pipeline with a fake receiver and store
// (flushes every 20 ms; syslog.allow lists one more sender).
func syslogRig(t *testing.T) (*rig, *fakeSyslogRx, *fakeSyslogStore) {
	t.Helper()
	cfg := testConfig()
	cfg.Syslog.FlushInterval = config.D(20 * time.Millisecond)
	cfg.Syslog.Allow = []string{"192.168.1.10", "not-an-address"}
	rx, st := &fakeSyslogRx{}, newFakeSyslogStore()
	r := newRigWith(t, cfg, nil, func(o *Options) { o.Syslog, o.SyslogStore = rx, st })
	r.m.syslogRetryMin, r.m.syslogRetryMax = 20*time.Millisecond, 80*time.Millisecond
	return r, rx, st
}

// syslogMsg is a message received from the gateway at at.
func syslogMsg(at time.Time, text string) model.SyslogMessage {
	sev, fac := 6, 0
	return model.SyslogMessage{RX: fmtTS(at), Src: "192.168.1.254:514", Raw: "<6>" + text, Format: "rfc3164",
		Severity: &sev, Facility: &fac, App: "kernel", Msg: text}
}

// syslogRecs returns the syslog store records written, in ledger order.
func syslogRecs(r *rig) []model.Body {
	var out []model.Body
	for _, b := range r.led.records("") {
		if b.Type == model.TypeSyslogChunk || b.Type == model.TypeSyslogPrune {
			out = append(out, b)
		}
	}
	return out
}

func hasCondition(st model.Status, code string) (model.Condition, bool) {
	for _, c := range st.Conditions {
		if c.Code == code {
			return c, true
		}
	}
	return model.Condition{}, false
}

// ---------------------------------------------------------------------------- receiver → store → ledger

// Through Run: the chunk the previous run left open is recorded right after monitor_start, the
// receiver accepts the gateway and syslog.allow, every flush stores what it received and records
// the chunks sealed and the deletions they cause, and at shutdown the open chunk is sealed
// ("stop") and recorded - with the deletion it causes - just before monitor_stop.
func TestSyslogPipelineThroughRun(t *testing.T) {
	r, rx, st := syslogRig(t)
	t0 := time.Now().Add(-time.Hour)
	st.set(func(s *fakeSyslogStore) {
		s.chunkMsgs, s.keepMB = 2, 1
		s.recovered = []model.SyslogChunk{{Name: "syslog-000.jsonl.gz", From: fmtTS(t0), To: fmtTS(t0.Add(time.Minute)), Messages: 4,
			Bytes: 400, SHA256: strings.Repeat("ab", 32), GzBytes: 1 << 20, Reason: "recovered"}}
	})
	rx.push(1, 2, syslogMsg(t0.Add(2*time.Minute), "one"), syslogMsg(t0.Add(3*time.Minute), "two"), syslogMsg(t0.Add(4*time.Minute), "three"))

	stop := r.start(t)
	waitFor(t, "the first deletion", 10*time.Second, func() bool { return len(ofType(r.led.records(""), model.TypeSyslogPrune)) > 0 })
	st1 := r.m.Status()
	if s := st1.Syslog; s == nil || !s.Enabled || !s.Listening || s.Listen != "127.0.0.1:5514" || s.ListenErr != "" ||
		s.Received != 3 || s.Recorded != 3 || s.Dropped != 1 || s.Rejected != 2 || s.Enforce || s.Target != nil ||
		s.LastAt != fmtTS(t0.Add(4*time.Minute)) || s.Last != "kernel: three" || s.Store == nil || s.Store.KeepMB != 1 {
		t.Fatalf("syslog status %+v", st1.Syslog)
	}
	if _, down := hasCondition(st1, condSyslogReceiverDown); down {
		t.Fatal("the receiver listens: no SYSLOG_RECEIVER_DOWN")
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}

	if want := []netip.Addr{netip.MustParseAddr("192.168.1.254"), netip.MustParseAddr("192.168.1.10")}; !reflect.DeepEqual(rx.allowed, want) {
		t.Fatalf("allowed senders %v, want %v", rx.allowed, want)
	}
	recs := r.led.records("run-current")
	types := r.led.types("run-current")
	if types[1] != model.TypeMonitorStart || types[2] != model.TypeSyslogChunk {
		t.Fatalf("the recovered chunk is recorded right after monitor_start: %v", types[:3])
	}
	if c := decode[model.SyslogChunk](t, recs[2]); c.Name != "syslog-000.jsonl.gz" || c.Reason != "recovered" || c.SHA256 != strings.Repeat("ab", 32) {
		t.Fatalf("recovered chunk record %+v", c)
	}
	n := len(types)
	if types[n-1] != model.TypeMonitorStop || types[n-2] != model.TypeSyslogPrune || types[n-3] != model.TypeSyslogChunk {
		t.Fatalf("the final seal and its deletion come right before monitor_stop: %v", types[n-3:])
	}
	final := decode[model.SyslogChunk](t, recs[n-3])
	if final.Reason != "stop" || final.Messages != 1 || final.To != fmtTS(t0.Add(4*time.Minute)) {
		t.Fatalf("final chunk %+v", final)
	}

	// Every sealed chunk is recorded once, before the record of its deletion; every deletion
	// names the limit and what is kept.
	sys := syslogRecs(r)
	chunkAt := map[string]int{}
	var deleted []string
	for i, b := range sys {
		switch b.Type {
		case model.TypeSyslogChunk:
			c := decode[model.SyslogChunk](t, b)
			if _, dup := chunkAt[c.Name]; dup {
				t.Fatalf("chunk %s recorded twice", c.Name)
			}
			chunkAt[c.Name] = i
		case model.TypeSyslogPrune:
			p := decode[model.SyslogPrune](t, b)
			if p.Reason != "keep_mb 1" || p.KeepMB != 1 || p.KeepDays != 0 || p.KeptChunks != 1 || p.KeptBytes < 1<<20 || len(p.Deleted) == 0 {
				t.Fatalf("prune record %+v", p)
			}
			for _, d := range p.Deleted {
				at, ok := chunkAt[d.Name]
				if !ok || at > i {
					t.Fatalf("chunk %s deleted before its syslog_chunk record", d.Name)
				}
				deleted = append(deleted, d.Name)
			}
		}
	}
	if len(chunkAt) != 3 || !reflect.DeepEqual(deleted, []string{"syslog-000.jsonl.gz", "syslog-001.jsonl.gz"}) {
		t.Fatalf("chunks %v deleted %v", chunkAt, deleted)
	}
	if size := decode[model.SyslogChunk](t, sys[1]); size.Reason != "size" || size.Messages != 2 || size.Dropped != 1 || size.Rejected != 2 {
		t.Fatalf("size-sealed chunk %+v", size)
	}
	if calls := st.callLog(); calls[0] != "recover" || calls[len(calls)-2] != "seal stop" || calls[len(calls)-1] != "prune" {
		t.Fatalf("store calls %v", calls)
	}
}

// Store operations driven directly: the records follow the store's answers exactly.
func TestSyslogFlushRecords(t *testing.T) {
	r, rx, st := syslogRig(t)
	now := time.Now()
	st.set(func(s *fakeSyslogStore) { s.chunkMsgs, s.chunkAge, s.keepMB = 3, time.Hour, 2 })
	r.m.startSyslog()
	if recs := syslogRecs(r); len(recs) != 0 {
		t.Fatalf("nothing to recover: %d records", len(recs))
	}

	// Nothing received, nothing old: no record, and an idle flush calls nothing but Seal.
	r.m.flushSyslog(false)
	if recs := syslogRecs(r); len(recs) != 0 {
		t.Fatalf("idle flush wrote %d records", len(recs))
	}
	if calls := st.callLog(); !reflect.DeepEqual(calls, []string{"recover", "prune", "seal age"}) {
		t.Fatalf("calls %v", calls)
	}

	// Seven messages: two chunks sealed by size, one message stays open; three chunks would be
	// kept with the next seal, so the oldest goes then.
	for i := range 7 {
		rx.push(0, 0, syslogMsg(now.Add(time.Duration(i)*time.Second), fmt.Sprintf("m%d", i)))
	}
	r.m.flushSyslog(false)
	recs := syslogRecs(r)
	if len(recs) != 2 || recs[0].Type != model.TypeSyslogChunk || recs[1].Type != model.TypeSyslogChunk {
		t.Fatalf("records %v", r.led.types(""))
	}
	st.set(func(s *fakeSyslogStore) { s.old = true }) // the open chunk is old now
	r.m.flushSyslog(false)
	recs = syslogRecs(r)
	if len(recs) != 4 || recs[2].Type != model.TypeSyslogChunk || recs[3].Type != model.TypeSyslogPrune {
		t.Fatalf("records %v", r.led.types(""))
	}
	if c := decode[model.SyslogChunk](t, recs[2]); c.Reason != "age" || c.Messages != 1 {
		t.Fatalf("age chunk %+v", c)
	}
	p := decode[model.SyslogPrune](t, recs[3])
	if p.Reason != "keep_mb 2" || len(p.Deleted) != 1 || p.Deleted[0].Name != "syslog-001.jsonl.gz" || p.KeptChunks != 2 || p.KeptBytes != 2<<20 {
		t.Fatalf("prune %+v", p)
	}
	if s := r.m.Status().Syslog; s.Received != 7 || s.Recorded != 7 || s.Store.Chunks != 2 {
		t.Fatalf("status %+v", s)
	}
}

// A store that fails shows SYSLOG_STORE_FAILING naming the error (the messages count as received,
// not recorded) until a flush succeeds again.
func TestSyslogStoreFailureCondition(t *testing.T) {
	r, rx, st := syslogRig(t)
	r.m.startSyslog()
	st.set(func(s *fakeSyslogStore) {
		s.appendErr = errors.New("write syslog\\open.jsonl: There is not enough space on the disk.")
	})
	rx.push(0, 0, syslogMsg(time.Now(), "a"), syslogMsg(time.Now(), "b"))
	r.m.flushSyslog(false)
	rx.push(0, 0, syslogMsg(time.Now(), "c"))
	r.m.flushSyslog(false)
	st1 := r.m.Status()
	c, ok := hasCondition(st1, condSyslogStoreFailing)
	if !ok || c.Severity != "warning" || !strings.Contains(c.Message, "not enough space on the disk") || !strings.Contains(c.Message, "2 failures") || c.Since == "" {
		t.Fatalf("conditions %+v", st1.Conditions)
	}
	if s := st1.Syslog; s.Received != 3 || s.Recorded != 0 {
		t.Fatalf("counters %+v", s)
	}
	st.set(func(s *fakeSyslogStore) { s.appendErr = nil })
	rx.push(0, 0, syslogMsg(time.Now(), "d"))
	r.m.flushSyslog(false)
	st2 := r.m.Status()
	if _, ok := hasCondition(st2, condSyslogStoreFailing); ok {
		t.Fatal("the store works again: no SYSLOG_STORE_FAILING")
	}
	if s := st2.Syslog; s.Received != 4 || s.Recorded != 1 {
		t.Fatalf("counters %+v", s)
	}

	// A failing recovery or prune counts too.
	st.set(func(s *fakeSyslogStore) { s.pruneErr = errors.New("remove syslog\\x.jsonl.gz: Access is denied.") })
	if _, err := r.m.SetSyslogRetention(context.Background(), 5, 0, "test"); err != nil {
		t.Fatal(err)
	}
	if c, ok := hasCondition(r.m.Status(), condSyslogStoreFailing); !ok || !strings.Contains(c.Message, "Access is denied") {
		t.Fatalf("prune failure: %+v", r.m.Status().Conditions)
	}
}

// While the ledger refuses records nothing is sealed by age and nothing is deleted; a chunk the
// store sealed by size meanwhile is recorded once the ledger takes records again - before the
// record of its deletion - and at shutdown the open chunk is left for the next start to recover.
func TestSyslogWhileTheLedgerRefusesRecords(t *testing.T) {
	r, rx, st := syslogRig(t)
	st.set(func(s *fakeSyslogStore) { s.chunkMsgs, s.old, s.keepMB = 2, true, 1 })
	r.m.startSyslog()
	refuse := errors.New("ledger: write failed")
	r.led.setRejectRecord(func(string) error { return refuse })
	now := time.Now()
	rx.push(0, 0, syslogMsg(now, "a"), syslogMsg(now.Add(time.Second), "b"), syslogMsg(now.Add(2*time.Second), "c"))
	r.m.flushSyslog(false)
	if calls := st.callLog(); slices.Contains(calls[2:], "seal age") || slices.Contains(calls[2:], "prune") {
		t.Fatalf("sealed or pruned while the ledger refuses records: %v", calls)
	}
	if n := unrecordedChunks(r); n != 1 {
		t.Fatalf("%d chunks wait for their record", n)
	}
	r.m.flushSyslog(false) // still refused: still kept, once
	if n := unrecordedChunks(r); n != 1 || len(syslogRecs(r)) != 0 {
		t.Fatalf("kept %d, written %d", n, len(syslogRecs(r)))
	}

	r.led.setRejectRecord(nil)
	r.m.flushSyslog(false) // the kept record first, then the age seal and the deletion it causes
	recs := syslogRecs(r)
	if len(recs) != 3 || recs[0].Type != model.TypeSyslogChunk || recs[1].Type != model.TypeSyslogChunk || recs[2].Type != model.TypeSyslogPrune {
		t.Fatalf("records %v", r.led.types(""))
	}
	if c := decode[model.SyslogChunk](t, recs[0]); c.Reason != "size" || c.Name != "syslog-001.jsonl.gz" {
		t.Fatalf("retried chunk %+v", c)
	}
	if p := decode[model.SyslogPrune](t, recs[2]); len(p.Deleted) != 1 || p.Deleted[0].Name != "syslog-001.jsonl.gz" {
		t.Fatalf("prune %+v", p)
	}

	// At shutdown with the ledger refusing records the open chunk is not sealed.
	rx.push(0, 0, syslogMsg(now.Add(3*time.Second), "d"))
	r.led.setRejectRecord(func(string) error { return refuse })
	r.m.appendApply(model.TypeHeartbeat, model.Heartbeat{}, nil, nil) // refused: the ledger is failing
	before := len(st.callLog())
	r.m.flushSyslog(true)
	if calls := st.callLog()[before:]; !reflect.DeepEqual(calls, []string{"append"}) {
		t.Fatalf("final flush with a failing ledger: %v", calls)
	}
}

// unrecordedChunks returns how many sealed chunks wait for their syslog_chunk record.
func unrecordedChunks(r *rig) int {
	r.m.syslogMu.Lock()
	defer r.m.syslogMu.Unlock()
	return r.m.pendingChunksLocked()
}

// A store without bookkeeping of its own gets it in memory (memBook), bounded: beyond
// maxUnrecordedSyslog chunks without their record, and as many unrecorded deletions, the oldest
// is given up (logged).
func TestSyslogMemBookBound(t *testing.T) {
	r, _, st := syslogRig(t)
	book, ok := r.m.syslog.(*memBook)
	if !ok {
		t.Fatalf("the fake store got %T", r.m.syslog)
	}
	r.m.syslogMu.Lock()
	defer r.m.syslogMu.Unlock()
	for i := range maxUnrecordedSyslog + 5 {
		book.sealed(model.SyslogChunk{Name: fmt.Sprintf("c%d", i)})
	}
	if u := book.Unrecorded(); len(u) != maxUnrecordedSyslog || u[0].Name != "c5" {
		t.Fatalf("kept %d, oldest %s", len(u), u[0].Name)
	}
	// Deletions made by the store's own Prune wait (CancelPrune) until they can be recorded.
	st.set(func(s *fakeSyslogStore) {
		s.keepMB = 1
		for i := range 3 {
			s.sealed = append(s.sealed, model.SyslogChunk{Name: fmt.Sprintf("old-%d", i), To: fmtTS(time.Now()), GzBytes: 1 << 20})
		}
	})
	plan, err := book.PlanPrune(time.Now())
	if err != nil || len(plan) != 2 {
		t.Fatalf("PlanPrune: %+v %v", plan, err)
	}
	book.CancelPrune()
	again, err := book.PlanPrune(time.Now())
	if err != nil || !reflect.DeepEqual(again, plan) {
		t.Fatalf("PlanPrune after CancelPrune: %+v %v, want %+v", again, err, plan)
	}
	if done, err := book.CommitPrune(); err != nil || !reflect.DeepEqual(done, plan) {
		t.Fatalf("CommitPrune: %+v %v", done, err)
	}
	if next, err := book.PlanPrune(time.Now()); err != nil || len(next) != 0 {
		t.Fatalf("PlanPrune after CommitPrune: %+v %v", next, err)
	}
}

// A receiver that cannot listen (UDP 514 in use) is started again with a back-off and shows
// SYSLOG_RECEIVER_DOWN naming why, until it listens.
func TestSyslogReceiverDown(t *testing.T) {
	r, rx, _ := syslogRig(t)
	bind := errors.New("syslogrx: listen udp :514: bind: Only one usage of each socket address (protocol/network address/port) is normally permitted.")
	rx.setRunErr(bind)
	stop := r.start(t)
	waitFor(t, "a retry", 10*time.Second, func() bool { return rx.runCount() >= 3 })
	st := r.m.Status()
	c, ok := hasCondition(st, condSyslogReceiverDown)
	if !ok || c.Severity != "warning" || !strings.Contains(c.Message, "Only one usage of each socket address") || !strings.Contains(c.Message, ":514") || c.Since == "" {
		t.Fatalf("conditions %+v", st.Conditions)
	}
	if s := st.Syslog; s.Listening || s.Listen != ":514" || !strings.Contains(s.ListenErr, "bind") {
		t.Fatalf("syslog status %+v", s)
	}
	rx.setRunErr(nil)
	waitFor(t, "listening", 10*time.Second, func() bool { return r.m.Status().Syslog.Listening })
	waitFor(t, "the condition to clear", 10*time.Second, func() bool {
		_, down := hasCondition(r.m.Status(), condSyslogReceiverDown)
		return !down
	})
	if err := stop(); err != nil {
		t.Fatal(err)
	}
}

// Without a store (or with syslog disabled) the receiver is not run and nothing is recorded.
func TestSyslogNotRunWithoutStoreOrWhenDisabled(t *testing.T) {
	for _, tc := range []struct {
		name     string
		store    bool
		disabled bool
	}{{"no store", false, false}, {"disabled", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.Syslog.Enabled = !tc.disabled
			cfg.Syslog.FlushInterval = config.D(10 * time.Millisecond)
			rx, st := &fakeSyslogRx{}, newFakeSyslogStore()
			r := newRigWith(t, cfg, nil, func(o *Options) {
				o.Syslog = rx
				if tc.store {
					o.SyslogStore = st
				}
			})
			rx.push(0, 0, syslogMsg(time.Now(), "x"))
			stop := r.start(t)
			waitFor(t, "samples", 10*time.Second, func() bool { return len(ofType(r.led.records(""), model.TypeSample)) > 3 })
			s := r.m.Status().Syslog
			if err := stop(); err != nil {
				t.Fatal(err)
			}
			if rx.runCount() != 0 || len(st.callLog()) != 0 || len(syslogRecs(r)) != 0 {
				t.Fatalf("runs %d store calls %v records %d", rx.runCount(), st.callLog(), len(syslogRecs(r)))
			}
			if s == nil || s.Enabled || s.Listening {
				t.Fatalf("status %+v", s)
			}
		})
	}
}

// Every goroutine of the syslog pipeline has ended when Run returns, also one waiting to start
// the receiver again.
func TestSyslogNoGoroutineLeak(t *testing.T) {
	r, rx, _ := syslogRig(t)
	r.m.syslogRetryMin, r.m.syslogRetryMax = time.Hour, time.Hour
	rx.setRunErr(errors.New("bind: in use"))
	stop := r.start(t)
	waitFor(t, "a receiver attempt", 10*time.Second, func() bool { return rx.runCount() > 0 })
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the monitor's goroutines to end", 5*time.Second, func() bool {
		buf := make([]byte, 1<<20)
		return !strings.Contains(string(buf[:runtime.Stack(buf, true)]), "internal/monitor.(*Monitor)")
	})
}

// ---------------------------------------------------------------------------- retention

func TestSetSyslogRetention(t *testing.T) {
	ctx := context.Background()
	t.Run("applied: saved, recorded, pruned", func(t *testing.T) {
		r, _, st := syslogRig(t)
		now := time.Now()
		st.set(func(s *fakeSyslogStore) {
			for i := range 3 {
				s.sealed = append(s.sealed, model.SyslogChunk{Name: fmt.Sprintf("old-%d", i), From: fmtTS(now), To: fmtTS(now), GzBytes: 1 << 20})
			}
		})
		cc, err := r.m.SetSyslogRetention(ctx, 1, 0, "operator via web")
		if err != nil {
			t.Fatal(err)
		}
		want := model.ConfigChange{Target: "monitor", What: syslogRetentionWhat, Before: "keep_mb 100, keep_days 0",
			After: "keep_mb 1, keep_days 0", Actor: "operator via web", Result: "applied"}
		if cc != want {
			t.Fatalf("change %+v", cc)
		}
		if r.cfg.Syslog.KeepMB != 1 || r.cfg.Syslog.KeepDays != 0 || r.saved.Load() != 1 {
			t.Fatalf("config %+v saved %d", r.cfg.Syslog, r.saved.Load())
		}
		types := r.led.types("")
		if len(types) != 3 || types[1] != model.TypeConfigChange || types[2] != model.TypeSyslogPrune {
			t.Fatalf("records %v", types)
		}
		if got := decode[model.ConfigChange](t, r.led.records("")[1]); got != want {
			t.Fatalf("recorded change %+v", got)
		}
		p := decode[model.SyslogPrune](t, r.led.records("")[2])
		if p.Reason != "keep_mb 1" || len(p.Deleted) != 2 || p.KeptChunks != 1 {
			t.Fatalf("prune %+v", p)
		}
		if calls := st.callLog(); !reflect.DeepEqual(calls, []string{"retention 1 0", "prune"}) {
			t.Fatalf("store calls %v", calls)
		}
	})
	t.Run("age limit", func(t *testing.T) {
		r, _, st := syslogRig(t)
		old := time.Now().Add(-72 * time.Hour)
		st.set(func(s *fakeSyslogStore) {
			s.sealed = []model.SyslogChunk{{Name: "old", From: fmtTS(old), To: fmtTS(old), GzBytes: 1 << 20}}
		})
		if _, err := r.m.SetSyslogRetention(ctx, 100, 2, "cli"); err != nil {
			t.Fatal(err)
		}
		if p := decode[model.SyslogPrune](t, lastOfType(t, r, model.TypeSyslogPrune)); p.Reason != "keep_days 2" || p.KeepDays != 2 || p.KeepMB != 100 {
			t.Fatalf("prune %+v", p)
		}
	})
	t.Run("invalid values change nothing", func(t *testing.T) {
		r, _, st := syslogRig(t)
		for _, v := range [][2]int{{0, 0}, {-1, 0}, {config.MaxSyslogKeepMB + 1, 0}, {10, -1}, {10, config.MaxSyslogKeepDays + 1}} {
			_, err := r.m.SetSyslogRetention(ctx, v[0], v[1], "web")
			if err == nil || (!strings.Contains(err.Error(), "keep_mb") && !strings.Contains(err.Error(), "keep_days")) {
				t.Fatalf("%v: %v", v, err)
			}
		}
		if _, err := r.m.SetSyslogRetention(ctx, 10, 0, strings.Repeat("x", maxLabelBytes+1)); err == nil {
			t.Fatal("an oversized actor must be refused")
		}
		if len(r.led.records("")) != 1 || r.saved.Load() != 0 || len(st.callLog()) != 0 || r.cfg.Syslog.KeepMB != 100 {
			t.Fatalf("records %d saved %d store %v", len(r.led.records("")), r.saved.Load(), st.callLog())
		}
	})
	t.Run("unchanged", func(t *testing.T) {
		r, _, st := syslogRig(t)
		cc, err := r.m.SetSyslogRetention(ctx, 100, 0, "")
		if err != nil || cc.Result != "unchanged: already in force" || cc.Actor != "operator" {
			t.Fatalf("%+v %v", cc, err)
		}
		if len(r.led.records("")) != 1 || r.saved.Load() != 0 || len(st.callLog()) != 0 {
			t.Fatal("setting the limits in force must change nothing")
		}
	})
	t.Run("not recorded: undone", func(t *testing.T) {
		r, _, st := syslogRig(t)
		r.led.setRejectRecord(func(typ string) error {
			if typ == model.TypeConfigChange {
				return errors.New("disk full")
			}
			return nil
		})
		if _, err := r.m.SetSyslogRetention(ctx, 5, 3, "web"); err == nil {
			t.Fatal("error expected")
		}
		if r.cfg.Syslog.KeepMB != 100 || r.cfg.Syslog.KeepDays != 0 || len(st.callLog()) != 0 || len(r.led.records("")) != 1 {
			t.Fatalf("config %+v store %v", r.cfg.Syslog, st.callLog())
		}
	})
	t.Run("not saved: applied until restart", func(t *testing.T) {
		r, _, st := syslogRig(t)
		r.m.opts.SaveConfig = func(*config.Config) error { return errors.New("access denied") }
		cc, err := r.m.SetSyslogRetention(ctx, 5, 0, "web")
		if err == nil || !strings.HasPrefix(cc.Result, "applied until the monitor restarts: the configuration could not be saved: access denied") {
			t.Fatalf("%+v %v", cc, err)
		}
		if r.cfg.Syslog.KeepMB != 5 || !slices.Contains(st.callLog(), "retention 5 0") {
			t.Fatal("the change still applies")
		}
	})
	t.Run("no store", func(t *testing.T) {
		r := newRig(t, nil, nil)
		cc, err := r.m.SetSyslogRetention(ctx, 50, 0, "cli")
		if err != nil || !strings.Contains(cc.Result, "the syslog store is not running") || r.cfg.Syslog.KeepMB != 50 {
			t.Fatalf("%+v %v", cc, err)
		}
		if types := r.led.types(""); len(types) != 2 || types[1] != model.TypeConfigChange {
			t.Fatalf("records %v", types)
		}
	})
}

func TestPruneReason(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	old, recent := fmtTS(now.Add(-48*time.Hour)), fmtTS(now.Add(-time.Hour))
	refs := func(tos ...string) []model.SyslogChunkRef {
		var out []model.SyslogChunkRef
		for _, to := range tos {
			out = append(out, model.SyslogChunkRef{To: to})
		}
		return out
	}
	for _, tc := range []struct {
		deleted  []model.SyslogChunkRef
		keepDays int
		want     string
	}{
		{refs(old, recent), 0, "keep_mb 100"},
		{refs(old, old), 1, "keep_days 1"},
		{refs(recent), 1, "keep_mb 100"},
		{refs(old, recent), 1, "keep_days 1 and keep_mb 100"},
		{refs("not a time"), 1, "keep_mb 100"},
	} {
		if got := pruneReason(tc.deleted, 100, tc.keepDays, now); got != tc.want {
			t.Errorf("%v days %d: %q, want %q", tc.deleted, tc.keepDays, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------- the gateway's Syslog page

const syslogPageOn = `<html><form method="post" action="/cgi-bin/syslog.ha"><input name="nonce" value="n1"><label>Syslog</label><input type="checkbox" name="syslog" checked></form></html>`

// syslogOn192 is the gateway sending to 192.168.1.71:514.
func syslogOn192() model.SyslogSetting {
	return model.SyslogSetting{Enabled: true, Server: "192.168.1.71", Port: 514, Level: "Informational",
		Levels: []string{"Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Informational", "Debug"}}
}

// linkAt makes the fake prober report this computer at ip toward the gateway.
func linkAt(r *rig, ip *atomic.Value) {
	r.pr.link = func() (model.LocalLink, []byte, error) {
		return model.LocalLink{Interface: "Wi-Fi", Type: "wifi", State: "connected", SSID: "home", SignalPct: 90, LocalIP: ip.Load().(string)}, nil, nil
	}
}

// The Syslog page is read after a successful read of the notification setting, in the same check,
// and recorded as a gateway_event syslog_setting with the page; it is never changed.
func TestSyslogSettingReadInTheSettingsCheck(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, nil, nil)
	r.cfg.Gateway.AccessCodeProtected = "protected-blob"
	r.cfg.Gateway.EnforceNotificationOff = false
	var ip atomic.Value
	ip.Store("192.168.1.71")
	linkAt(r, &ip)
	r.m.checkLocalLink(ctx, false)
	setting := syslogOn192()
	r.gw.syslog = func() (model.SyslogSetting, []byte, error) { return setting, []byte(syslogPageOn), nil }

	if err := r.m.checkNotification(ctx); err != nil {
		t.Fatal(err)
	}
	evs := ofType(r.led.records(""), model.TypeGatewayEvent)
	if len(evs) != 2 {
		t.Fatalf("events %d", len(evs))
	}
	if k := decode[model.GatewayEvent](t, evs[0]).Kind; k != model.GwEvNotificationSetting {
		t.Fatalf("the notification setting is read first: %s", k)
	}
	ev := decode[model.GatewayEvent](t, evs[1])
	if ev.Kind != model.GwEvSyslogSetting || ev.Before != "" || ev.After != "on -> 192.168.1.71:514, level Informational" ||
		!strings.Contains(ev.Detail, "which is this computer") || !strings.Contains(ev.Detail, "read only") ||
		!strings.Contains(ev.Detail, "Informational, Debug") {
		t.Fatalf("event %+v", ev)
	}
	if len(evs[1].Blobs) != 1 || evs[1].Blobs[0] != sha256Hex([]byte(syslogPageOn)) || !r.led.HasBlob(evs[1].Blobs[0]) {
		t.Fatalf("page blob %v", evs[1].Blobs)
	}
	s := r.m.Status().Syslog
	if s == nil || s.State != syslogStateOK || s.Problem != "" || s.GatewaySeq != evs[1].Seq || s.GatewayAt != evs[1].TS ||
		s.Gateway == nil || !reflect.DeepEqual(*s.Gateway, setting) || s.Enabled || s.Enforce || s.Target != nil {
		t.Fatalf("status %+v", s)
	}

	// The next check records the read again, with the setting before; it moved elsewhere.
	setting.Server = "192.168.1.50"
	if err := r.m.checkNotification(ctx); err != nil {
		t.Fatal(err)
	}
	ev2 := decode[model.GatewayEvent](t, lastOfType(t, r, model.TypeGatewayEvent))
	if ev2.Before != ev.After || ev2.After != "on -> 192.168.1.50:514, level Informational" || !strings.Contains(ev2.Detail, "not to this computer (192.168.1.71:514)") {
		t.Fatalf("second event %+v", ev2)
	}
	if s := r.m.Status().Syslog; s.State != syslogStateElsewhere || !strings.Contains(s.Problem, "192.168.1.50:514") {
		t.Fatalf("status %+v", s)
	}
	if reads, sets := r.gw.syslogReads(); reads != 2 || sets != 0 {
		t.Fatalf("Syslog page read %d times, changed %d times", reads, sets)
	}
}

// No Syslog read without a successful read of the notification setting before it in the same
// check: a failed one, or a pending certificate (no authenticated request at all).
func TestSyslogSettingNeedsTheNotificationRead(t *testing.T) {
	ctx := context.Background()
	t.Run("notification read failed", func(t *testing.T) {
		r := newRig(t, nil, nil)
		r.gw.notifErr = contracts.ErrGatewayAuth
		r.gw.syslog = func() (model.SyslogSetting, []byte, error) { return syslogOn192(), []byte(syslogPageOn), nil }
		if err := r.m.checkNotification(ctx); !errors.Is(err, contracts.ErrGatewayAuth) {
			t.Fatalf("err %v", err)
		}
		if reads, _ := r.gw.syslogReads(); reads != 0 {
			t.Fatal("the Syslog page was read after a failed notification read")
		}
		if s := r.m.Status().Syslog; s == nil || s.State != syslogStateError || !strings.Contains(s.Problem, "notification setting") || !strings.Contains(s.Problem, "login failed") {
			t.Fatalf("status %+v", s)
		}
	})
	t.Run("pending certificate", func(t *testing.T) {
		r := certRig(t)
		r.gw.syslog = func() (model.SyslogSetting, []byte, error) { return syslogOn192(), []byte(syslogPageOn), nil }
		if err := r.m.checkNotification(ctx); !errors.Is(err, contracts.ErrGatewayCertRejected) {
			t.Fatalf("err %v", err)
		}
		if reads, _ := r.gw.syslogReads(); reads != 0 || r.gw.notifCalls != 0 {
			t.Fatal("authenticated request while a certificate is pending")
		}
		if s := r.m.Status().Syslog; s == nil || s.State != syslogStateError || !strings.Contains(s.Problem, "trust-cert") {
			t.Fatalf("status %+v", s)
		}
	})
}

// A page that is read but not understood (gateway.ErrSyslogPage: the client returns it with the
// error) is recorded with the problem and the page; a read that fails is not recorded.
func TestSyslogSettingNotUnderstoodOrFailed(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, nil, nil)
	r.gw.syslog = func() (model.SyslogSetting, []byte, error) { return syslogOn192(), []byte(syslogPageOn), nil }
	if err := r.m.checkNotification(ctx); err != nil {
		t.Fatal(err)
	}
	odd := []byte("<html><form><select name=x><option>On</select></form></html>")
	r.gw.syslog = func() (model.SyslogSetting, []byte, error) {
		return model.SyslogSetting{}, odd, errors.New(`gateway: Syslog page not understood: no control labelled "Syslog"`)
	}
	if err := r.m.checkNotification(ctx); err != nil {
		t.Fatalf("a page that is not understood does not fail the check: %v", err)
	}
	b := lastOfType(t, r, model.TypeGatewayEvent)
	ev := decode[model.GatewayEvent](t, b)
	if ev.Kind != model.GwEvSyslogSetting || ev.Before != "on -> 192.168.1.71:514, level Informational" || ev.After != syslogUnknown ||
		!strings.Contains(ev.Detail, `no control labelled "Syslog"`) || len(b.Blobs) != 1 || b.Blobs[0] != sha256Hex(odd) || !r.led.HasBlob(b.Blobs[0]) {
		t.Fatalf("event %+v blobs %v", ev, b.Blobs)
	}
	s := r.m.Status().Syslog
	if s.State != syslogStateUnknown || !strings.Contains(s.Problem, "not understood") || s.Gateway != nil || s.GatewaySeq != b.Seq {
		t.Fatalf("status %+v", s)
	}

	n := len(r.led.records(""))
	r.gw.syslog = func() (model.SyslogSetting, []byte, error) {
		return model.SyslogSetting{}, nil, fmt.Errorf("gateway: GET syslog: %w", contracts.ErrGatewaySessionsFull)
	}
	if err := r.m.checkNotification(ctx); err != nil {
		t.Fatalf("a failed Syslog read waits for the next check: %v", err)
	}
	if got := len(r.led.records("")); got != n {
		t.Fatalf("a failed read wrote %d records", got-n)
	}
	if s := r.m.Status().Syslog; s.State != syslogStateError || !strings.Contains(s.Problem, "sessions are in use") || s.GatewaySeq != b.Seq {
		t.Fatalf("status %+v", s)
	}
	// A successful read ends the error.
	r.gw.syslog = func() (model.SyslogSetting, []byte, error) {
		return model.SyslogSetting{}, []byte("<html>off</html>"), nil
	}
	if err := r.m.checkNotification(ctx); err != nil {
		t.Fatal(err)
	}
	if s := r.m.Status().Syslog; s.State != syslogStateOff || s.Gateway == nil || s.Gateway.Enabled {
		t.Fatalf("status %+v", s)
	}
}

// The status compares the gateway's setting with this computer's address toward it and the
// configured port.
func TestSyslogStatusStates(t *testing.T) {
	r := newRig(t, nil, nil)
	read := func(s *model.SyslogSetting) {
		r.m.locked(func() { r.m.st.syslogGw, r.m.st.syslogErr = &syslogGwRead{Seq: 7, TS: fmtTS(t0), Setting: s}, "" })
	}
	state := func() (string, string) {
		s := r.m.Status().Syslog
		if s == nil {
			t.Fatal("no syslog status")
		}
		return s.State, s.Problem
	}
	if r.m.Status().Syslog != nil {
		t.Fatal("nothing configured and nothing known: no syslog status")
	}
	r.m.locked(func() { r.m.st.syslogErr = "x" })
	if st, p := state(); st != syslogStateError || p != "x" {
		t.Fatalf("%s %s", st, p)
	}
	r.m.locked(func() { r.m.st.syslogErr = "" })
	r.m.locked(func() { r.m.st.syslogGw = &syslogGwRead{Seq: 3} })
	if st, p := state(); st != syslogStateUnknown || !strings.Contains(p, "not understood") {
		t.Fatalf("not understood: %s %s", st, p)
	}
	on := syslogOn192()
	read(&on)
	if st, p := state(); st != syslogStateUnknown || !strings.Contains(p, "address toward the gateway is not known") {
		t.Fatalf("no local address: %s %s", st, p)
	}
	r.m.locked(func() { r.m.st.localIP = "192.168.1.71" })
	if st, p := state(); st != syslogStateOK || p != "" {
		t.Fatalf("ok: %s %s", st, p)
	}
	other := on
	other.Port = 1514
	read(&other)
	if st, p := state(); st != syslogStateElsewhere || !strings.Contains(p, "192.168.1.71:1514, not to this computer (192.168.1.71:514)") {
		t.Fatalf("other port: %s %s", st, p)
	}
	read(&model.SyslogSetting{})
	if st, _ := state(); st != syslogStateOff {
		t.Fatalf("off: %s", st)
	}
	r.m.locked(func() { r.m.st.syslogGw = nil })
	r.m.opts.Syslog = &fakeSyslogRx{}
	if st, p := state(); st != syslogStateUnknown || !strings.Contains(p, "access code") {
		t.Fatalf("no access code: %s %s", st, p)
	}
	r.cfg.Gateway.AccessCodeProtected = "protected-blob"
	if st, p := state(); st != syslogStateUnknown || !strings.Contains(p, "not been read yet") {
		t.Fatalf("not read yet: %s %s", st, p)
	}
	if !sameIP("192.168.1.71", "::ffff:192.168.1.71") || sameIP("", "") || !sameIP("GW.local", "gw.LOCAL") {
		t.Fatal("sameIP")
	}
}

func TestSyslogSummaryRoundTrip(t *testing.T) {
	for _, s := range []model.SyslogSetting{
		{},
		{Enabled: true, Server: "192.168.1.71", Port: 514, Level: "Informational"},
		{Enabled: true, Server: "fd00::5", Port: 1514},
		{Enabled: true, Port: 514, Level: "Debug"},
	} {
		got := parseSyslogSummary(syslogSummary(s))
		if got == nil || !reflect.DeepEqual(*got, s) {
			t.Errorf("%+v -> %q -> %+v", s, syslogSummary(s), got)
		}
	}
	if syslogSummary(model.SyslogSetting{Enabled: true, Server: "192.168.1.71", Port: 514, Level: "Informational"}) != "on -> 192.168.1.71:514, level Informational" {
		t.Error("summary wording")
	}
	for _, bad := range []string{syslogUnknown, "", "on -> nonsense", "on -> 1.2.3.4:x"} {
		if parseSyslogSummary(bad) != nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

// When this computer's address toward the gateway changes, the settings check runs again -
// not sooner than the floor after the previous check, and once for a burst of changes.
func TestSyslogSettingReadAgainAfterAddressChange(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := newRig(t, nil, nil)
	r.cfg.Gateway.AccessCodeProtected = "protected-blob"
	const floor = 300 * time.Millisecond
	r.m.notifMinInterval = floor
	var ip atomic.Value
	ip.Store("192.168.1.71")
	linkAt(r, &ip)
	r.m.checkLocalLink(ctx, false)
	r.gw.syslog = func() (model.SyslogSetting, []byte, error) { return syslogOn192(), []byte(syslogPageOn), nil }
	times := func() []time.Time {
		r.gw.mu.Lock()
		defer r.gw.mu.Unlock()
		return slices.Clone(r.gw.syslogTimes)
	}
	done := make(chan struct{})
	go func() { r.m.notificationLoop(ctx); close(done) }()
	waitFor(t, "the startup check", 10*time.Second, func() bool { return len(times()) == 1 })

	ip.Store("192.168.1.80")
	r.m.checkLocalLink(ctx, false)
	waitFor(t, "the check after the address change", 10*time.Second, func() bool { return len(times()) == 2 })
	ts := times()
	if gap := ts[1].Sub(ts[0]); gap < floor {
		t.Fatalf("checked again after %v (floor %v)", gap, floor)
	}
	ev := decode[model.GatewayEvent](t, lastOfType(t, r, model.TypeGatewayEvent))
	if !strings.Contains(ev.Detail, "read again after this computer's address toward the gateway changed") || !strings.Contains(ev.Detail, "not to this computer (192.168.1.80:514)") {
		t.Fatalf("event %+v", ev)
	}

	// A burst of changes: one more check, after the floor.
	for _, a := range []string{"192.168.1.81", "192.168.1.82", "192.168.1.83"} {
		ip.Store(a)
		r.m.checkLocalLink(ctx, false)
	}
	waitFor(t, "one more check", 10*time.Second, func() bool { return len(times()) == 3 })
	time.Sleep(floor + 200*time.Millisecond)
	ts = times()
	if len(ts) != 3 || ts[2].Sub(ts[1]) < floor {
		t.Fatalf("%d checks; the last two %v apart", len(ts), ts[len(ts)-1].Sub(ts[len(ts)-2]))
	}
	cancel()
	<-done
}

// An address change during the back-off after a rejected login does not shorten it.
func TestSyslogAddressChangeKeepsTheLoginBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := newRig(t, nil, nil)
	r.cfg.Gateway.AccessCodeProtected = "protected-blob"
	r.m.notifMinInterval = 50 * time.Millisecond // the back-off after ErrGatewayAuth is an hour
	r.gw.notifErr = contracts.ErrGatewayAuth
	var ip atomic.Value
	ip.Store("192.168.1.71")
	linkAt(r, &ip)
	r.m.checkLocalLink(ctx, false)
	done := make(chan struct{})
	go func() { r.m.notificationLoop(ctx); close(done) }()
	calls := func() int {
		r.gw.mu.Lock()
		defer r.gw.mu.Unlock()
		return r.gw.notifCalls
	}
	waitFor(t, "the startup check", 10*time.Second, func() bool { return calls() == 1 })
	ip.Store("192.168.1.80")
	r.m.checkLocalLink(ctx, false)
	time.Sleep(300 * time.Millisecond)
	if n := calls(); n != 1 {
		t.Fatalf("%d notification reads: the login back-off was shortened", n)
	}
	cancel()
	<-done
}

// ---------------------------------------------------------------------------- rebuild

// The gateway's Syslog setting as last recorded survives a restart, from the ledger and from the
// state cache.
func TestRebuildSyslogSetting(t *testing.T) {
	r := newRig(t, nil, nil)
	prev, at := "run-old", time.Now().Add(-time.Hour)
	r.led.appendAs(prev, at, model.TypeMonitorStart, model.MonitorStart{})
	r.led.appendAs(prev, at.Add(time.Second), model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvSyslogSetting, After: "off"})
	ref := r.led.appendAs(prev, at.Add(2*time.Second), model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvSyslogSetting,
		Before: "off", After: "on -> 192.168.1.71:514, level Informational"})
	r.led.appendAs(prev, at.Add(3*time.Second), model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvNotificationSetting, After: "off"})
	r.m.rebuild(time.Now())
	want := model.SyslogSetting{Enabled: true, Server: "192.168.1.71", Port: 514, Level: "Informational"}
	s := r.m.Status().Syslog
	if s == nil || s.Gateway == nil || !reflect.DeepEqual(*s.Gateway, want) || s.GatewaySeq != ref.Seq || s.GatewayAt != ref.TS {
		t.Fatalf("rebuilt %+v", s)
	}

	// From the state cache, with a later read that was not understood after it.
	r.m.writeCache()
	ref2 := r.led.appendAs(prev, at.Add(4*time.Second), model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvSyslogSetting,
		Before: "on -> 192.168.1.71:514, level Informational", After: syslogUnknown, Detail: "not understood"})
	r2 := newRig(t, r.cfg, r.led)
	r2.m.opts.StateDir = r.m.opts.StateDir
	if _, ok := r2.m.loadCache(); !ok {
		t.Fatal("no state cache")
	}
	r2.m.rebuild(time.Now())
	if g := r2.m.st.syslogGw; g == nil || g.Seq != ref2.Seq || g.Setting != nil || !strings.Contains(g.Problem, "not understood") {
		t.Fatalf("rebuilt from the cache: %+v", g)
	}
	r3 := newRig(t, r.cfg, r.led)
	r3.m.opts.StateDir = r.m.opts.StateDir
	r3.led.appendAs(prev, at.Add(5*time.Second), model.TypeHeartbeat, model.Heartbeat{}) // the cache is still valid
	r3.m.rebuild(time.Now())
	r3.m.writeCache()
	r4 := newRig(t, r.cfg, r.led)
	r4.m.opts.StateDir = r.m.opts.StateDir
	r4.m.rebuild(time.Now())
	if g := r4.m.st.syslogGw; g == nil || g.Seq != ref2.Seq {
		t.Fatalf("the cache carries the setting: %+v", g)
	}
}

// ---------------------------------------------------------------------------- concurrency

// The syslog pipeline, the retention control, the flow meter and the status run concurrently
// without races.
func TestSyslogConcurrentUse(t *testing.T) {
	r, rx, st := syslogRig(t)
	st.set(func(s *fakeSyslogStore) { s.chunkMsgs, s.chunkAge, s.keepMB = 5, 50*time.Millisecond, 3 })
	r.m.liveEvery = 0
	stop := r.start(t)
	ctx := context.Background()
	deadline := time.Now().Add(500 * time.Millisecond)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for w := range 4 {
		wg.Go(func() {
			for i := 0; time.Now().Before(deadline); i++ {
				rx.push(i%2, i%3, syslogMsg(time.Now(), fmt.Sprintf("w%d m%d", w, i)))
				_ = r.m.Status()
				if _, err := r.m.LiveTraffic(ctx); err != nil {
					errs <- err
					return
				}
				if i%10 == 0 {
					if _, err := r.m.SetSyslogRetention(ctx, 2+i%3, i%2, "test"); err != nil {
						errs <- err
						return
					}
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
	wg.Wait()
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	s := r.m.Status().Syslog
	if s.Received == 0 || s.Received != s.Recorded {
		t.Fatalf("received %d recorded %d", s.Received, s.Recorded)
	}
	// Every message is in a recorded chunk: the final flush sealed the rest.
	var inChunks int64
	for _, b := range ofType(r.led.records(""), model.TypeSyslogChunk) {
		inChunks += int64(decode[model.SyslogChunk](t, b).Messages)
	}
	if inChunks != s.Recorded {
		t.Fatalf("%d messages in recorded chunks, %d recorded", inChunks, s.Recorded)
	}
}
