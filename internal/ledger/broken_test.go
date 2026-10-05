package ledger

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// A failed write whose partial line cannot be removed leaves the store unusable until it is
// reopened (crash recovery then quarantines the partial line). Every error the store returns
// because of it — the failing append included — wraps contracts.ErrLedgerBroken, so the monitor
// can stop at once and the restarted service reopens the ledger.
func TestBrokenStoreErrorsWrapErrLedgerBroken(t *testing.T) {
	dir := t.TempDir()
	clk := newClock(t0)
	s := openStore(t, testOptions(dir, clk))
	appendSamples(t, s, clk, 2, time.Second)
	head := s.Head()

	// Pull the file out from under the writer: the write and its rollback both fail.
	s.active.f.Close()
	_, err := s.Append(model.TypeSample, samplePayload(1))
	if !errors.Is(err, contracts.ErrLedgerBroken) {
		t.Fatalf("the append that broke the store: %v (want ErrLedgerBroken)", err)
	}
	if !errors.Is(err, os.ErrClosed) {
		t.Fatalf("the cause of the failed write is lost: %v", err)
	}

	// Every later append is refused with the sticky error, whatever its type.
	for _, typ := range []string{model.TypeSample, model.TypeOperatorNote, model.TypeIntegrityAlert} {
		_, err := s.Append(typ, map[string]string{"x": "y"})
		if !errors.Is(err, contracts.ErrLedgerBroken) || !strings.Contains(err.Error(), "reopen") {
			t.Fatalf("append %s on a broken store: %v", typ, err)
		}
	}

	// A record referencing a blob: the blob store still works, the record is refused.
	id, err := s.PutBlob([]byte("<html>page</html>"))
	if err != nil {
		t.Fatalf("PutBlob: %v", err)
	}
	if _, err := s.Append(model.TypeGatewaySnapshot, map[string]string{"page": id}, id); !errors.Is(err, contracts.ErrLedgerBroken) {
		t.Fatalf("append with blob on a broken store: %v", err)
	}

	// The next UTC day: a broken store must not rotate (sealing would commit to the partial line).
	clk.Advance(24 * time.Hour)
	if _, err := s.Append(model.TypeSample, samplePayload(3)); !errors.Is(err, contracts.ErrLedgerBroken) {
		t.Fatalf("append on the next day: %v", err)
	}
	if _, err := os.Stat(segPath(dir, segName(clk.Now()))); !os.IsNotExist(err) {
		t.Fatalf("a broken store rotated: %v", err)
	}
	if s.Head() != head {
		t.Fatalf("head moved on a broken store: %+v want %+v", s.Head(), head)
	}
	s.Close()

	// Reopening recovers and the chain verifies.
	s2 := openStore(t, testOptions(dir, clk))
	if s2.Head() != head {
		t.Fatalf("reopened head %+v want %+v", s2.Head(), head)
	}
	mustAppend(t, s2, model.TypeSample, samplePayload(4))
	rep, err := s2.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireOK(t, rep)
}

// The rotation's own integrity_alert (a foreign file occupied the new segment's name) is the write
// that fails and cannot be rolled back: the record that triggered the rotation must then not be
// written after it, and its append reports ErrLedgerBroken.
func TestStoreBrokenDuringRotationRefusesTheTriggeringRecord(t *testing.T) {
	dir := t.TempDir()
	clk := newClock(t0)
	s := openStore(t, testOptions(dir, clk))
	appendSamples(t, s, clk, 1, time.Second)
	next := segPath(dir, segName(t0.Add(24*time.Hour)))
	if err := os.WriteFile(next, []byte("not a ledger\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The new segment is created, but the writer's handle to it cannot write.
	openAfterCreate = func(path string) (*os.File, error) { return openShared(path) }
	t.Cleanup(func() { openAfterCreate = openExclusiveRW })
	clk.Advance(24 * time.Hour)
	_, err := s.Append(model.TypeSample, samplePayload(1))
	if !errors.Is(err, contracts.ErrLedgerBroken) {
		t.Fatalf("append that rotated into a broken store: %v (want ErrLedgerBroken)", err)
	}
	if _, err := s.Append(model.TypeSample, samplePayload(2)); !errors.Is(err, contracts.ErrLedgerBroken) {
		t.Fatalf("later append: %v", err)
	}
	lines := readLines(t, next)
	if len(lines) != 1 {
		t.Fatalf("new segment holds %d lines, want only its segment_open", len(lines))
	}
	if _, b := parseLine(t, lines[0]); b.Type != model.TypeSegmentOpen {
		t.Fatalf("new segment begins with %s", b.Type)
	}
	head := s.Head()
	s.Close()
	openAfterCreate = openExclusiveRW

	s2 := openStore(t, testOptions(dir, clk))
	if s2.Head() != head {
		t.Fatalf("reopened head %+v want %+v", s2.Head(), head)
	}
	mustAppend(t, s2, model.TypeSample, samplePayload(3))
	rep, err := s2.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireOK(t, rep)
}

// A write that fails but is rolled back leaves the store usable: its error is not
// ErrLedgerBroken, and the next append succeeds.
func TestRolledBackWriteDoesNotBreakTheStore(t *testing.T) {
	s, _, clk := newLedger(t)
	appendSamples(t, s, clk, 1, time.Second)
	head := s.Head()
	writeAt = func(f *os.File, b []byte, off int64) (int, error) {
		return 0, errors.New("simulated: the device is not ready")
	}
	t.Cleanup(func() { writeAt = (*os.File).WriteAt })
	_, err := s.Append(model.TypeSample, samplePayload(1))
	if err == nil || errors.Is(err, contracts.ErrLedgerBroken) {
		t.Fatalf("rolled-back write: %v (want an error that is not ErrLedgerBroken)", err)
	}
	if s.Head() != head {
		t.Fatalf("head moved on a failed write")
	}
	writeAt = (*os.File).WriteAt
	mustAppend(t, s, model.TypeSample, samplePayload(2))
	rep, err := s.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireOK(t, rep)
}
