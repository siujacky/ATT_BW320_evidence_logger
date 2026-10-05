package ledger

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// fiveDayLedger builds a writer with one segment per day for five days.
func fiveDayLedger(t *testing.T) (*Store, string, *fakeClock, []string) {
	t.Helper()
	dir := t.TempDir()
	clk := newClock(t0)
	opts := testOptions(dir, clk)
	s := openStore(t, opts)
	var names []string
	for d := 0; d < 5; d++ {
		if d > 0 {
			clk.Advance(24 * time.Hour)
		}
		appendSamples(t, s, clk, 3, 10*time.Second)
		id, err := s.PutBlob([]byte("day page " + clk.Now().String()))
		if err != nil {
			t.Fatal(err)
		}
		mustAppend(t, s, model.TypeGatewaySnapshot, map[string]string{"page": id}, id)
		names = append(names, segName(clk.Now()))
	}
	return s, dir, clk, names
}

func TestCompressSealed(t *testing.T) {
	s, dir, clk, names := fiveDayLedger(t)
	orig := map[string][]byte{}
	for _, n := range names {
		orig[n], _ = os.ReadFile(segPath(dir, n))
	}
	segsBefore, _ := s.Segments()

	// Day 5 is active. Only segments whose day ended ≥ 48h ago qualify: days 1 and 2.
	n, err := s.CompressSealed(48 * time.Hour)
	if err != nil || n != 2 {
		t.Fatalf("CompressSealed = %d, %v", n, err)
	}
	for i, name := range names {
		_, plainErr := os.Stat(segPath(dir, name))
		_, gzErr := os.Stat(segPath(dir, name) + ".gz")
		compressed := i < 2
		if compressed != (plainErr != nil) || compressed != (gzErr == nil) {
			t.Fatalf("%s: plain err %v, gz err %v", name, plainErr, gzErr)
		}
	}
	// Idempotent.
	if n, err := s.CompressSealed(48 * time.Hour); err != nil || n != 0 {
		t.Fatalf("second run = %d, %v", n, err)
	}

	// Readers see the same bytes and records.
	segs, err := s.Segments()
	if err != nil {
		t.Fatal(err)
	}
	for i, si := range segs {
		b := segsBefore[i]
		if si.Name != b.Name || si.FirstSeq != b.FirstSeq || si.LastSeq != b.LastSeq || si.Records != b.Records ||
			si.Compressed != (i < 2) || (si.Compressed && !strings.HasSuffix(si.Path, ".jsonl.gz")) {
			t.Fatalf("segment %d: %+v (before %+v)", i, si, b)
		}
		rc, err := s.OpenSegment(si.Name)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(rc)
		rc.Close()
		if !bytes.Equal(got, orig[si.Name]) {
			t.Fatalf("OpenSegment(%s) differs from the original bytes", si.Name)
		}
	}
	for seq := uint64(0); seq <= s.Head().Seq; seq++ {
		if _, b, err := s.Record(seq); err != nil || b.Seq != seq {
			t.Fatalf("Record(%d): %v", seq, err)
		}
	}
	if got := len(scanAll(t, s)); uint64(got) != s.Head().Seq+1 {
		t.Fatalf("scan returned %d records", got)
	}
	var day2 int
	if err := s.ScanTime(utcDate(t0.Add(24*time.Hour)), utcDate(t0.Add(48*time.Hour)), func(model.Envelope, model.Body) error {
		day2++
		return nil
	}); err != nil || day2 != 5 {
		t.Fatalf("ScanTime over a compressed day: %d %v", day2, err)
	}
	rep, err := s.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireOK(t, rep)

	// Everything sealed, including the segment preceding the active one.
	if n, err := s.CompressSealed(0); err != nil || n != 2 {
		t.Fatalf("CompressSealed(0) = %d, %v", n, err)
	}
	// Reopen: the previous segment of the active one is compressed; no alerts.
	head := s.Head()
	s.Close()
	s2 := openStore(t, testOptions(dir, clk))
	if s2.Head() != head {
		t.Fatalf("reopen appended records: %+v", s2.Head())
	}
	clk.Advance(24 * time.Hour)
	appendSamples(t, s2, clk, 1, time.Second) // rotation after compression
	rep, _ = s2.Verify(context.Background())
	requireOK(t, rep)
	ro := verifyRO(t, dir, clk)
	requireOK(t, ro)
}

func TestCompressRefusesSegmentThatDoesNotMatchItsCommitment(t *testing.T) {
	s, dir, _, names := fiveDayLedger(t)
	path := segPath(dir, names[0])
	lines := readLines(t, path)
	lines[1] = append(bytes.TrimSuffix(lines[1], []byte("\n")), []byte(" \n")...)
	writeLines(t, path, lines)
	n, err := s.CompressSealed(0)
	if n != 3 || err == nil || !strings.Contains(err.Error(), "does not match the SHA-256 committed") {
		t.Fatalf("CompressSealed = %d, %v", n, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("tampered segment must stay uncompressed for inspection")
	}
	if _, err := os.Stat(path + ".gz"); !os.IsNotExist(err) {
		t.Fatal("no compressed copy expected")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "ledger", "*.tmp")); len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}
}

func TestCompressLeftoversAndOpenReaders(t *testing.T) {
	s, dir, _, names := fiveDayLedger(t)
	p0 := segPath(dir, names[0])
	p1 := segPath(dir, names[1])

	// An interrupted run left an identical compressed copy next to day 1; a stale (different)
	// one sits next to day 2.
	orig0, _ := os.ReadFile(p0)
	os.WriteFile(p0+".gz", gz(t, orig0), 0o644)
	os.WriteFile(p1+".gz", gz(t, []byte("stale")), 0o644)
	segs, _ := s.Segments()
	if segs[0].Compressed || segs[1].Compressed {
		t.Fatal("readers must prefer the uncompressed original while both exist")
	}

	// A reader without FILE_SHARE_DELETE keeps day 3 open: its compression completes later.
	p2 := segPath(dir, names[2])
	held, err := os.Open(p2)
	if err != nil {
		t.Fatal(err)
	}
	n, err := s.CompressSealed(0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 { // day 1 (finish), day 2 (recompress), day 4; day 3 is in use
		t.Fatalf("compressed %d", n)
	}
	if _, err := os.Stat(p2); err != nil {
		t.Fatal("in-use segment removed")
	}
	if _, err := os.Stat(p2 + ".gz"); err != nil {
		t.Fatal("compressed copy of the in-use segment missing")
	}
	q, _ := filepath.Glob(filepath.Join(dir, "quarantine", names[1]+".jsonl.gz.stale*"))
	if len(q) != 1 {
		t.Fatalf("stale copy not quarantined: %v", q)
	}
	rep, _ := s.Verify(context.Background())
	requireOK(t, rep)
	held.Close()
	if n, err := s.CompressSealed(0); err != nil || n != 1 {
		t.Fatalf("completion run = %d, %v", n, err)
	}
	rep, _ = s.Verify(context.Background())
	requireOK(t, rep)
	for _, name := range names[:4] {
		if _, err := os.Stat(segPath(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s still uncompressed", name)
		}
	}
}

func TestLatestSegmentOnlyCompressedIsRestored(t *testing.T) {
	// Construct the state left when a damaged newer segment was removed after its predecessor
	// had been compressed: the latest segment exists only as .jsonl.gz.
	s, dir, clk, names := fiveDayLedger(t)
	if _, err := s.CompressSealed(0); err != nil {
		t.Fatal(err)
	}
	head4, _ := s.Segments()
	s.Close()
	os.WriteFile(segPath(dir, names[4]), []byte("garbage\n"), 0o644)

	clk.Advance(time.Hour)
	s2 := openStore(t, testOptions(dir, clk))
	if _, err := os.Stat(segPath(dir, names[3])); err != nil {
		t.Fatalf("latest segment not restored uncompressed: %v", err)
	}
	if _, err := os.Stat(segPath(dir, names[3]) + ".gz"); !os.IsNotExist(err) {
		t.Fatal("compressed copy of the restored segment still present")
	}
	bodies := recordsAfter(t, s2, head4[3].LastSeq)
	if got := typesOf(bodies); len(got) != 3 || got[0] != model.TypeSegmentOpen || got[1] != model.TypeRecovery || got[2] != model.TypeIntegrityAlert {
		t.Fatalf("records %v", got)
	}
	rep, _ := s2.Verify(context.Background())
	requireOK(t, rep)
}
