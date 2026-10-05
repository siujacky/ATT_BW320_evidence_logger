package ledger

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// Crash-window tests for recovery documentation. Bytes moved to quarantine must always end up
// described by a recovery record, whichever step a crash interrupts:
//
//	marker written → bytes copied to quarantine → segment truncated → record appended → marker removed

// tornLedger builds a closed ledger whose only segment ends with a torn line and returns the
// segment path, its intact size and the torn bytes.
func tornLedger(t *testing.T) (dir string, clk *fakeClock, path string, good int64, torn []byte) {
	t.Helper()
	dir = t.TempDir()
	clk = newClock(t0)
	s := openStore(t, testOptions(dir, clk))
	appendSamples(t, s, clk, 3, time.Second)
	s.Close()
	path = segPath(dir, segName(t0))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	torn = []byte(`{"h":"0123","s":"torn by a crash`)
	if err := os.WriteFile(path, append(b, torn...), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, clk, path, int64(len(b)), torn
}

// crashAfterQuarantine performs the quarantine step of Open on the torn segment and "crashes"
// before the recovery record is written.
func crashAfterQuarantine(t *testing.T, dir, path string, good int64) (model.Recovery, string) {
	t.Helper()
	w := &Store{quarDir: filepath.Join(dir, "quarantine"), log: slog.New(slog.DiscardHandler)}
	os.MkdirAll(w.quarDir, 0o755)
	f, err := openExclusiveRW(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, _ := f.Stat()
	rec, marker, err := w.quarantineTail(f, segName(t0), good, st.Size(), "incomplete final line (test)")
	if err != nil {
		t.Fatal(err)
	}
	return rec, marker
}

func TestRecoveryRecordedAfterCrashBetweenTruncateAndAppend(t *testing.T) {
	dir, clk, path, good, torn := tornLedger(t)
	rec, marker := crashAfterQuarantine(t, dir, path, good)
	if st, _ := os.Stat(path); st.Size() != good {
		t.Fatalf("segment not truncated: %d", st.Size())
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("marker missing: %v", err)
	}

	s := openStore(t, testOptions(dir, clk))
	bodies := scanAll(t, s)
	last := bodies[len(bodies)-1]
	if last.Type != model.TypeRecovery {
		t.Fatalf("types %v", typesOf(bodies))
	}
	got := decodeData[model.Recovery](t, last)
	if got.QuarantineAs != rec.QuarantineAs || got.RemovedSHA256 != sha256Hex(torn) || got.Offset != good ||
		got.RemovedBytes != int64(len(torn)) || !strings.Contains(got.Reason, "recorded on a later start") {
		t.Fatalf("recovery %+v", got)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("marker not removed after the record was written")
	}
	rep, _ := s.Verify(context.Background())
	requireOK(t, rep)

	// A further restart records nothing new.
	head := s.Head()
	s.Close()
	s2 := openStore(t, testOptions(dir, clk))
	if s2.Head() != head {
		t.Fatalf("second restart appended records: %+v", s2.Head())
	}
}

func TestMarkerWhoseRecordIsWrittenIsOnlyRemoved(t *testing.T) {
	dir, clk, _, _, _ := tornLedger(t)
	s := openStore(t, testOptions(dir, clk)) // normal recovery: record + marker removal
	bodies := scanAll(t, s)
	rec := decodeData[model.Recovery](t, bodies[len(bodies)-1])
	head := s.Head()
	s.Close()
	// Crash after the append but before the marker was removed: put the marker back.
	marker := filepath.Join(dir, filepath.FromSlash(rec.QuarantineAs)) + pendingExt
	if _, err := writeRecoveryMarker(strings.TrimSuffix(marker, pendingExt), rec); err != nil {
		t.Fatal(err)
	}
	s2 := openStore(t, testOptions(dir, clk))
	if s2.Head() != head {
		t.Fatalf("a recovery already in the ledger was recorded twice: %v", typesOf(recordsAfter(t, s2, head.Seq)))
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("stale marker not removed")
	}
}

func TestCrashBetweenMarkerAndCopyRecordsOnce(t *testing.T) {
	dir, clk, path, good, torn := tornLedger(t)
	// The marker is written first; the crash happens before the copy is renamed into place.
	qpath := filepath.Join(dir, "quarantine", fmt.Sprintf("%s.%d.tail", segName(t0), good))
	os.MkdirAll(filepath.Dir(qpath), 0o755)
	if _, err := writeRecoveryMarker(qpath, model.Recovery{Segment: segName(t0), Offset: good, RemovedBytes: int64(len(torn)),
		RemovedSHA256: sha256Hex(torn), QuarantineAs: "quarantine/" + filepath.Base(qpath), Reason: "x"}); err != nil {
		t.Fatal(err)
	}
	s := openStore(t, testOptions(dir, clk))
	after := recordsAfter(t, s, 3)
	if fmt.Sprint(typesOf(after)) != "[recovery]" {
		t.Fatalf("records %v", typesOf(after))
	}
	if q, err := os.ReadFile(qpath); err != nil || !bytes.Equal(q, torn) {
		t.Fatalf("quarantine copy: %v", err)
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "quarantine"))
	if len(entries) != 1 {
		t.Fatalf("quarantine holds %d entries, want only the tail copy", len(entries))
	}
	rep, _ := s.Verify(context.Background())
	requireOK(t, rep)
	_ = path
}

func TestIncompleteSegmentMarkerSurvivesCrash(t *testing.T) {
	dir := t.TempDir()
	clk := newClock(t0)
	s := openStore(t, testOptions(dir, clk))
	head := s.Head()
	s.Close()
	// A rotation's temporary segment was moved to quarantine, then the writer stopped.
	next := segName(t0.Add(24 * time.Hour))
	content := []byte(`{"h":"x","s":"y","b":"{}"}` + "\n")
	qpath := filepath.Join(dir, "quarantine", next+".jsonl.incomplete")
	rec := model.Recovery{Segment: next, RemovedBytes: int64(len(content)), RemovedSHA256: sha256Hex(content),
		QuarantineAs: "quarantine/" + filepath.Base(qpath), Reason: "incomplete segment creation"}
	if _, err := writeRecoveryMarker(qpath, rec); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(qpath, content, 0o644)

	s2 := openStore(t, testOptions(dir, clk))
	after := recordsAfter(t, s2, head.Seq)
	if fmt.Sprint(typesOf(after)) != "[recovery]" {
		t.Fatalf("records %v", typesOf(after))
	}
	if got := decodeData[model.Recovery](t, after[0]); got.QuarantineAs != rec.QuarantineAs || got.RemovedSHA256 != rec.RemovedSHA256 {
		t.Fatalf("recovery %+v", got)
	}
}

func TestUnusableMarkersAreReportedOnce(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"not JSON", "{broken", "unreadable"},
		{"names another file", `{"quarantine_as":"quarantine/other.tail"}`, "unreadable"},
		{"fields not from this writer", `{"segment":"` + strings.Repeat("x", 1<<20) + `","removed_sha256":"x","quarantine_as":"quarantine/ledger-2026-10-05.99.tail"}`, "not those of a recovery record"},
		{"quarantine file missing", "", "cannot be read"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			clk := newClock(t0)
			s := openStore(t, testOptions(dir, clk))
			head := s.Head()
			s.Close()
			qname := "ledger-2026-10-05.99.tail"
			marker := filepath.Join(dir, "quarantine", qname+pendingExt)
			if tc.content == "" {
				if _, err := writeRecoveryMarker(strings.TrimSuffix(marker, pendingExt), model.Recovery{Segment: segName(t0), Offset: 99,
					RemovedSHA256: sha256Hex(nil), QuarantineAs: "quarantine/" + qname}); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(marker, []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}
			s2 := openStore(t, testOptions(dir, clk))
			after := recordsAfter(t, s2, head.Seq)
			if fmt.Sprint(typesOf(after)) != "[integrity_alert]" {
				t.Fatalf("records %v", typesOf(after))
			}
			a := decodeData[model.IntegrityAlert](t, after[0])
			if d := strings.Join(a.Details, "\n"); !strings.Contains(d, tc.want) || !strings.Contains(d, ".unusable") {
				t.Fatalf("alert %+v", a)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("marker still pending")
			}
			head = s2.Head()
			s2.Close()
			s3 := openStore(t, testOptions(dir, clk))
			if s3.Head() != head {
				t.Fatal("the same marker was reported again")
			}
		})
	}
}

// The quarantine copy no longer matching the marker's hash is reported, and the removal is
// still recorded.
func TestMarkerWithAlteredQuarantineCopy(t *testing.T) {
	dir, clk, path, good, _ := tornLedger(t)
	rec, _ := crashAfterQuarantine(t, dir, path, good)
	os.WriteFile(filepath.Join(dir, filepath.FromSlash(rec.QuarantineAs)), []byte("altered"), 0o644)
	s := openStore(t, testOptions(dir, clk))
	after := recordsAfter(t, s, 3)
	if fmt.Sprint(typesOf(after)) != "[recovery integrity_alert]" {
		t.Fatalf("records %v", typesOf(after))
	}
	a := decodeData[model.IntegrityAlert](t, after[1])
	if !strings.Contains(strings.Join(a.Details, "\n"), rec.RemovedSHA256) {
		t.Fatalf("alert %+v", a)
	}
}
