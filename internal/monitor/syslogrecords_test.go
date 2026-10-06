package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/model"
	"attmonitor/internal/syslogstore"
)

// Every sealed chunk gets exactly one syslog_chunk record, whatever ended a run (the syslog
// store's own bookkeeping, syslogBook): tested with the real store.

// openSyslogStore opens the real syslog store in dir (a restart opens it again).
func openSyslogStore(t *testing.T, dir string, o syslogstore.Options) *syslogstore.Store {
	t.Helper()
	o.Dir = dir
	st, err := syslogstore.New(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// chunkRecords returns the syslog_chunk records of the ledger by chunk name (every seq).
func chunkRecords(t *testing.T, led *fakeLedger) map[string][]uint64 {
	t.Helper()
	out := map[string][]uint64{}
	for _, b := range ofType(led.records(""), model.TypeSyslogChunk) {
		c := decode[model.SyslogChunk](t, b)
		out[c.Name] = append(out[c.Name], b.Seq)
	}
	return out
}

// Chunks the store sealed by size while the ledger refused their records, in a run that then
// ended, used to be lost with the run's memory. The store keeps them as unrecorded; the next
// start records each once - after looking for its record in the ledger, so that a chunk whose
// record was written just before a crash is not recorded twice.
func TestSyslogChunksWithoutRecordsAreRecordedAtTheNextStart(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig()
	led := newFakeLedger("run-current")
	base := time.Now().Add(-time.Hour)
	line, err := json.Marshal(syslogMsg(base, "message 0"))
	if err != nil {
		t.Fatal(err)
	}
	o := syslogstore.Options{ChunkBytes: int64(2 * (len(line) + 1))} // two messages a chunk
	st1 := openSyslogStore(t, dir, o)
	rx1 := &fakeSyslogRx{}
	r1 := newRigWith(t, cfg, led, func(o *Options) { o.Syslog, o.SyslogStore = rx1, st1 })
	if _, ok := r1.m.syslog.(*syslogstore.Store); !ok {
		t.Fatalf("the real store got %T", r1.m.syslog)
	}
	r1.m.startSyslog()
	r1.m.syslogReconcile(context.Background())
	push := func(rx *fakeSyslogRx, from, n int) {
		for i := range n {
			rx.push(0, 0, syslogMsg(base.Add(time.Duration(from+i)*time.Second), fmt.Sprintf("message %d", from+i)))
		}
	}
	push(rx1, 0, 4)
	r1.m.flushSyslog(false)
	recorded := chunkRecords(t, led)
	if len(recorded) == 0 || len(st1.Unrecorded()) != 0 {
		t.Fatalf("the first chunks: %v recorded, %d unrecorded", recorded, len(st1.Unrecorded()))
	}

	// The ledger refuses records: the chunks sealed by size now wait in the store.
	refuse := errors.New("ledger: the disk is full")
	led.setRejectRecord(func(typ string) error { return refuse })
	push(rx1, 4, 13)
	r1.m.flushSyslog(false)
	waiting := st1.Unrecorded()
	if len(waiting) < 3 || st1.Usage().OpenMessages == 0 {
		t.Fatalf("test setup: %d chunks wait, usage %+v", len(waiting), st1.Usage())
	}
	// One of them was recorded just before a crash, which came before the store could note it.
	led.setRejectRecord(nil)
	crash := waiting[1]
	led.appendAs("run-current", time.Now(), model.TypeSyslogChunk, crash)
	led.setRejectRecord(func(typ string) error { return refuse })
	r1.m.flushSyslog(true) // the run ends while the ledger refuses records
	if err := st1.Close(); err != nil {
		t.Fatal(err)
	}
	led.setRejectRecord(nil)

	// The next start.
	st2 := openSyslogStore(t, dir, o)
	rx2 := &fakeSyslogRx{}
	r2 := newRigWith(t, cfg, led, func(o *Options) { o.Syslog, o.SyslogStore = rx2, st2 })
	r2.m.startSyslog()
	for _, c := range waiting {
		if _, ok := chunkRecords(t, led)[c.Name]; ok && c.Name != crash.Name {
			t.Fatalf("chunk %s was recorded before the ledger was searched", c.Name)
		}
	}
	r2.m.syslogReconcile(context.Background())
	got := chunkRecords(t, led)
	for _, c := range st2.Chunks() {
		if seqs := got[c.Name]; len(seqs) != 1 {
			t.Errorf("chunk %s has %d syslog_chunk records", c.Name, len(seqs))
		}
	}
	if len(st2.Unrecorded()) != 0 {
		t.Fatalf("chunks still unrecorded: %+v", st2.Unrecorded())
	}
	for _, c := range waiting {
		if len(got[c.Name]) != 1 {
			t.Fatalf("waiting chunk %s: records %v", c.Name, got[c.Name])
		}
	}
	// The chunk the first run left open (sealed by the next start) is recorded too.
	var recoveredOne bool
	for _, b := range ofType(led.records(""), model.TypeSyslogChunk) {
		recoveredOne = recoveredOne || decode[model.SyslogChunk](t, b).Reason == "recovered"
	}
	if !recoveredOne {
		t.Fatalf("the chunk left open was not recorded: %v", got)
	}
	if _, failing := hasCondition(r2.m.Status(), condSyslogStoreFailing); failing {
		t.Fatalf("conditions %+v", r2.m.Status().Conditions)
	}
}

// A deletion is recorded before it is made: when the ledger refuses its syslog_prune record,
// nothing is deleted; once records are taken again the next flush deletes and records it.
func TestSyslogDeletionWaitsForItsRecord(t *testing.T) {
	dir := t.TempDir()
	st := openSyslogStore(t, dir, syslogstore.Options{KeepDays: 1})
	rx := &fakeSyslogRx{}
	r := newRigWith(t, testConfig(), nil, func(o *Options) { o.Syslog, o.SyslogStore = rx, st })
	r.m.startSyslog()
	old := time.Now().Add(-72 * time.Hour)
	rx.push(0, 0, syslogMsg(old, "three days old"), syslogMsg(old.Add(time.Second), "also old"))
	r.led.setRejectRecord(func(typ string) error {
		if typ == model.TypeSyslogPrune {
			return errors.New("ledger: write failed")
		}
		return nil
	})
	r.m.flushSyslog(true) // sealed ("stop") and recorded; its deletion (keep_days 1) is refused
	chunks := st.Chunks()
	if len(chunks) != 1 || len(chunkRecords(t, r.led)) != 1 || len(ofType(r.led.records(""), model.TypeSyslogPrune)) != 0 {
		t.Fatalf("chunks %+v, records %v", chunks, r.led.types(""))
	}
	if _, err := os.Stat(filepath.Join(dir, chunks[0].Name)); err != nil {
		t.Fatalf("the chunk was deleted without a record: %v", err)
	}
	if u := st.Usage(); u.Chunks != 1 {
		t.Fatalf("Usage %+v", u)
	}

	r.led.setRejectRecord(nil)
	r.m.appendApply(model.TypeHeartbeat, model.Heartbeat{}, nil, nil) // the ledger takes records again
	r.m.flushSyslog(false)
	prunes := ofType(r.led.records(""), model.TypeSyslogPrune)
	if len(prunes) != 1 {
		t.Fatalf("records %v", r.led.types(""))
	}
	if p := decode[model.SyslogPrune](t, prunes[0]); len(p.Deleted) != 1 || p.Deleted[0].Name != chunks[0].Name ||
		p.Reason != "keep_days 1" || p.KeptChunks != 0 {
		t.Fatalf("prune %+v", p)
	}
	if _, err := os.Stat(filepath.Join(dir, chunks[0].Name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the chunk is still there: %v", err)
	}
}

// A chunk a previous run left open that the start cannot seal (another program holds its file)
// is tried again at every flush, and SYSLOG_STORE_FAILING stays until it is sealed and recorded.
func TestSyslogRecoverIsTriedAgain(t *testing.T) {
	r, _, st := syslogRig(t)
	held := errors.New(`syslogstore: recover open-20261005T221500Z.jsonl: The process cannot access the file because it is being used by another process.`)
	t0 := time.Now().Add(-time.Hour)
	st.set(func(s *fakeSyslogStore) {
		s.recoverErr = held
		s.recovered = []model.SyslogChunk{{Name: "syslog-left-open.jsonl.gz", From: fmtTS(t0), To: fmtTS(t0), Messages: 1,
			Bytes: 10, SHA256: strings.Repeat("cd", 32), GzBytes: 40, Reason: "recovered"}}
	})
	r.m.startSyslog()
	for range 2 {
		r.m.flushSyslog(false) // nothing to store; the age seal succeeds
		if c, ok := hasCondition(r.m.Status(), condSyslogStoreFailing); !ok || !strings.Contains(c.Message, "being used by another process") {
			t.Fatalf("conditions %+v", r.m.Status().Conditions)
		}
	}
	if n := strings.Count(strings.Join(st.callLog(), ","), "recover"); n != 3 {
		t.Fatalf("Recover called %d times: %v", n, st.callLog())
	}
	st.set(func(s *fakeSyslogStore) { s.recoverErr = nil })
	r.m.flushSyslog(false)
	if _, ok := hasCondition(r.m.Status(), condSyslogStoreFailing); ok {
		t.Fatalf("still failing: %+v", r.m.Status().Conditions)
	}
	if got := chunkRecords(t, r.led); len(got["syslog-left-open.jsonl.gz"]) != 1 {
		t.Fatalf("records %v", got)
	}
	r.m.flushSyslog(false)
	if n := strings.Count(strings.Join(st.callLog(), ","), "recover"); n != 4 {
		t.Fatalf("Recover called %d times after it succeeded: %v", n, st.callLog())
	}
}

// A retention change that comes before the syslog pipeline starts (the dashboard may be first)
// records no chunk the start has not looked up in the ledger yet: a chunk an earlier run recorded
// just before a crash is not recorded twice.
func TestSyslogRetentionBeforeTheStart(t *testing.T) {
	led := newFakeLedger("run-current")
	st := openSyslogStore(t, t.TempDir(), syslogstore.Options{})
	if _, err := st.Append([]model.SyslogMessage{syslogMsg(time.Now().Add(-time.Hour), "earlier")}, 0, 0, time.Time{}); err != nil {
		t.Fatal(err)
	}
	c, err := st.Seal(time.Time{}, "stop", true)
	if err != nil || c == nil {
		t.Fatalf("Seal: %v %v", c, err)
	}
	led.appendAs("run-earlier", time.Now(), model.TypeSyslogChunk, *c) // recorded, never noted
	rx := &fakeSyslogRx{}
	r := newRigWith(t, testConfig(), led, func(o *Options) { o.Syslog, o.SyslogStore = rx, st })
	if _, err := r.m.SetSyslogRetention(context.Background(), 1, 0, "web"); err != nil {
		t.Fatal(err)
	}
	if n := len(chunkRecords(t, led)[c.Name]); n != 1 {
		t.Fatalf("the chunk has %d records before the start", n)
	}
	r.m.startSyslog()
	r.m.syslogReconcile(context.Background())
	if n := len(chunkRecords(t, led)[c.Name]); n != 1 || len(st.Unrecorded()) != 0 {
		t.Fatalf("the chunk has %d records after the start; unrecorded %+v", n, st.Unrecorded())
	}
}
