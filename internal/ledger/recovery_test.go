package ledger

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// recordsAfter returns the records with a seq greater than seq.
func recordsAfter(t *testing.T, s *Store, seq uint64) []model.Body {
	t.Helper()
	var out []model.Body
	for _, b := range scanAll(t, s) {
		if b.Seq > seq {
			out = append(out, b)
		}
	}
	return out
}

func TestTornTailRecovery(t *testing.T) {
	cases := []struct {
		name       string
		tail       func(t *testing.T, next []byte) []byte
		reason     string
		wantAlert  bool
		tailLines  int
		tailPrefix string
	}{
		{
			name:   "half a line",
			tail:   func(t *testing.T, next []byte) []byte { return next[:len(next)/2] },
			reason: "incomplete final line",
		},
		{
			name:   "line without newline",
			tail:   func(t *testing.T, next []byte) []byte { return next[:len(next)-1] },
			reason: "incomplete final line",
		},
		{
			name: "complete line with a torn middle",
			tail: func(t *testing.T, next []byte) []byte {
				b := bytes.Clone(next)
				for i := 200; i < 600 && i < len(b)-1; i++ {
					b[i] = 0
				}
				return b
			},
			reason: "final line failed verification",
		},
		{
			name:   "zero bytes from a lost flush",
			tail:   func(t *testing.T, next []byte) []byte { return make([]byte, 4096) },
			reason: "incomplete final line",
		},
		{
			name: "several garbage lines",
			tail: func(t *testing.T, next []byte) []byte {
				return []byte("garbage one\n{\"h\":1}\n" + string(next[:10]))
			},
			reason:    "trailing lines failed verification",
			wantAlert: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			clk := newClock(t0)
			s := openStore(t, testOptions(dir, clk))
			refs := appendSamples(t, s, clk, 5, 10*time.Second)
			// Produce the line the writer would have written next, then "crash" mid-write.
			_, body := parseLine(t, readLines(t, segPath(dir, segName(t0)))[5])
			body.Seq, body.Prev = 6, refs[4].Hash
			next := reencode(t, s.priv, body)
			s.Close()

			path := segPath(dir, segName(t0))
			good, _ := os.ReadFile(path)
			tail := tc.tail(t, next)
			if err := os.WriteFile(path, append(bytes.Clone(good), tail...), 0o644); err != nil {
				t.Fatal(err)
			}

			clk.Advance(time.Minute)
			s2 := openStore(t, testOptions(dir, clk))
			after := recordsAfter(t, s2, refs[4].Seq)
			wantTypes := "[recovery]"
			if tc.wantAlert {
				wantTypes = "[recovery integrity_alert]"
			}
			if fmt.Sprint(typesOf(after)) != wantTypes {
				t.Fatalf("records after reopen %v, want %s", typesOf(after), wantTypes)
			}
			rec := decodeData[model.Recovery](t, after[0])
			sum := sha256.Sum256(tail)
			qname := fmt.Sprintf("%s.%d.tail", segName(t0), len(good))
			if rec.Segment != segName(t0) || rec.Offset != int64(len(good)) || rec.RemovedBytes != int64(len(tail)) ||
				rec.RemovedSHA256 != hex.EncodeToString(sum[:]) || rec.QuarantineAs != "quarantine/"+qname ||
				!strings.Contains(rec.Reason, tc.reason) {
				t.Fatalf("recovery %+v", rec)
			}
			q, err := os.ReadFile(filepath.Join(dir, "quarantine", qname))
			if err != nil || !bytes.Equal(q, tail) {
				t.Fatalf("quarantine content mismatch (%v)", err)
			}
			// The good prefix is byte-for-byte intact and the recovery record chains to it.
			now, _ := os.ReadFile(path)
			if !bytes.HasPrefix(now, good) {
				t.Fatal("good prefix altered")
			}
			if after[0].Seq != 6 || after[0].Prev != refs[4].Hash {
				t.Fatalf("recovery record seq %d prev %s", after[0].Seq, after[0].Prev)
			}
			rep, err := s2.Verify(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			requireOK(t, rep)
			if tc.wantAlert {
				a := decodeData[model.IntegrityAlert](t, after[1])
				if !strings.Contains(strings.Join(a.Details, "\n"), "more than a torn write") {
					t.Fatalf("alert %+v", a)
				}
			}
			// A second reopen finds nothing to recover.
			s2.Close()
			s3 := openStore(t, testOptions(dir, clk))
			if n := len(recordsAfter(t, s3, s3.Head().Seq)); n != 0 || s3.Head() != s2.Head() {
				t.Fatalf("second reopen appended records")
			}
		})
	}
}

func TestIntegrityAlertForTamperedActiveSegment(t *testing.T) {
	dir := t.TempDir()
	clk := newClock(t0)
	s := openStore(t, testOptions(dir, clk))
	refs := appendSamples(t, s, clk, 6, 10*time.Second)
	s.Close()

	// Flip one character inside b of seq 3 (h/s no longer match); later lines stay valid.
	path := segPath(dir, segName(t0))
	lines := readLines(t, path)
	i := bytes.Index(lines[3], []byte("IP_SUCCESS"))
	lines[3][i] = 'X'
	writeLines(t, path, lines)

	clk.Advance(time.Minute)
	s2 := openStore(t, testOptions(dir, clk))
	after := recordsAfter(t, s2, refs[5].Seq)
	if fmt.Sprint(typesOf(after)) != "[integrity_alert]" {
		t.Fatalf("records %v", typesOf(after))
	}
	alert := decodeData[model.IntegrityAlert](t, after[0])
	details := strings.Join(alert.Details, "\n")
	for _, want := range []string{"line 4 (seq 3): hash_mismatch", "bad_signature", "line 5 (seq 4): prev_mismatch"} {
		if !strings.Contains(details, want) {
			t.Fatalf("alert lacks %q:\n%s", want, details)
		}
	}
	// History is not rewritten: the tampered line is still there; chaining continues from
	// the last line as found.
	if !bytes.Equal(readLines(t, path)[3], lines[3]) {
		t.Fatal("tampered line was rewritten")
	}
	if after[0].Prev != refs[5].Hash || after[0].Seq != 7 {
		t.Fatalf("alert record seq %d prev %s", after[0].Seq, after[0].Prev)
	}
	more := appendSamples(t, s2, clk, 2, 10*time.Second)
	rep, err := s2.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("verification must fail")
	}
	for _, f := range rep.Failures {
		if f.Seq > 4 {
			t.Fatalf("failure after the tampered region: %+v", f)
		}
	}
	if rep.HeadHash != more[1].Hash {
		t.Fatal("new records must still chain")
	}
}

func TestIncompleteSegmentCreationIsQuarantined(t *testing.T) {
	dir := t.TempDir()
	clk := newClock(t0)
	s := openStore(t, testOptions(dir, clk))
	appendSamples(t, s, clk, 2, time.Second)
	head := s.Head()
	s.Close()

	ldir := filepath.Join(dir, "ledger")
	next := segName(t0.Add(24 * time.Hour))
	pending := []byte(`{"h":"abc","s":"def","b":"{\"v\":1,\"seq\":3}"}` + "\n")
	os.WriteFile(filepath.Join(ldir, next+".jsonl.tmp"), pending, 0o644)
	os.WriteFile(filepath.Join(ldir, segName(t0.Add(48*time.Hour))+".jsonl.tmp"), nil, 0o644)
	os.WriteFile(filepath.Join(ldir, segName(t0)+".jsonl.gz.tmp"), []byte("partial gzip"), 0o644)
	os.MkdirAll(filepath.Join(dir, "blobs", ".tmp"), 0o755)
	os.WriteFile(filepath.Join(dir, "blobs", ".tmp", "deadbeef.123.tmp"), []byte("half a blob"), 0o644)

	s2 := openStore(t, testOptions(dir, clk))
	after := recordsAfter(t, s2, head.Seq)
	if fmt.Sprint(typesOf(after)) != "[recovery]" {
		t.Fatalf("records %v", typesOf(after))
	}
	rec := decodeData[model.Recovery](t, after[0])
	if rec.Segment != next || rec.RemovedBytes != int64(len(pending)) || rec.QuarantineAs != "quarantine/"+next+".jsonl.incomplete" ||
		rec.RemovedSHA256 != sha256Hex(pending) || !strings.Contains(rec.Reason, "incomplete segment creation") {
		t.Fatalf("recovery %+v", rec)
	}
	if q, err := os.ReadFile(filepath.Join(dir, "quarantine", next+".jsonl.incomplete")); err != nil || !bytes.Equal(q, pending) {
		t.Fatalf("quarantine: %v", err)
	}
	for _, p := range []string{
		filepath.Join(ldir, next+".jsonl.tmp"),
		filepath.Join(ldir, segName(t0.Add(48*time.Hour))+".jsonl.tmp"),
		filepath.Join(ldir, segName(t0)+".jsonl.gz.tmp"),
		filepath.Join(dir, "blobs", ".tmp", "deadbeef.123.tmp"),
	} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s still exists", p)
		}
	}
	rep, _ := s2.Verify(context.Background())
	requireOK(t, rep)
}

func TestDamagedLatestSegmentIsRemovedAndDocumented(t *testing.T) {
	dir := t.TempDir()
	clk := newClock(t0)
	s := openStore(t, testOptions(dir, clk))
	appendSamples(t, s, clk, 3, time.Second)
	day1Head := s.Head()
	clk.Advance(24 * time.Hour)
	appendSamples(t, s, clk, 3, time.Second)
	s.Close()

	// Every line of the latest segment is destroyed.
	day2 := segPath(dir, segName(t0.Add(24*time.Hour)))
	garbage := []byte("xxxxxxxxxxxxxxxx\nyyyyyyyyyyyyyy\nzzzz")
	os.WriteFile(day2, garbage, 0o644)

	clk.Advance(time.Hour)
	s2 := openStore(t, testOptions(dir, clk))
	bodies := recordsAfter(t, s2, day1Head.Seq)
	if fmt.Sprint(typesOf(bodies)) != "[segment_open recovery integrity_alert]" {
		t.Fatalf("records %v", typesOf(bodies))
	}
	if bodies[0].Seq != day1Head.Seq+1 || bodies[0].Prev != day1Head.Hash {
		t.Fatal("new segment must chain to the last valid record")
	}
	rec := decodeData[model.Recovery](t, bodies[1])
	if rec.Offset != 0 || rec.RemovedBytes != int64(len(garbage)) {
		t.Fatalf("recovery %+v", rec)
	}
	q, _ := os.ReadFile(filepath.Join(dir, "quarantine", fmt.Sprintf("%s.0.tail", segName(t0.Add(24*time.Hour)))))
	if !bytes.Equal(q, garbage) {
		t.Fatal("garbage not preserved in quarantine")
	}
	alert := decodeData[model.IntegrityAlert](t, bodies[2])
	if !strings.Contains(strings.Join(alert.Details, "\n"), "contained no valid record") {
		t.Fatalf("alert %+v", alert)
	}
	rep, _ := s2.Verify(context.Background())
	requireOK(t, rep)
}

func TestWrongKeyNeverTruncates(t *testing.T) {
	dir := t.TempDir()
	clk := newClock(t0)
	s := openStore(t, testOptions(dir, clk))
	appendSamples(t, s, clk, 2, time.Second)
	clk.Advance(24 * time.Hour)
	appendSamples(t, s, clk, 2, time.Second)
	s.Close()

	// Genesis segment gone and a foreign key installed: the genesis check cannot run, but
	// the intact records of the active segment reveal the mismatch.
	os.Remove(segPath(dir, segName(t0)))
	other := t.TempDir()
	o := openStore(t, testOptions(other, clk))
	o.Close()
	kb, _ := os.ReadFile(filepath.Join(other, "keys", "ledger-signing.key"))
	os.WriteFile(filepath.Join(dir, "keys", "ledger-signing.key"), kb, 0o600)
	active := segPath(dir, segName(t0.Add(24*time.Hour)))
	before, _ := os.ReadFile(active)

	_, err := Open(testOptions(dir, clk))
	if err == nil || !strings.Contains(err.Error(), "does not belong to this ledger") {
		t.Fatalf("Open: %v", err)
	}
	after, _ := os.ReadFile(active)
	if !bytes.Equal(before, after) {
		t.Fatal("segment modified by a refused open")
	}
	if entries, _ := os.ReadDir(filepath.Join(dir, "quarantine")); len(entries) != 0 {
		t.Fatal("quarantine written by a refused open")
	}
}

func TestMissingGenesisSegmentIsReported(t *testing.T) {
	dir := t.TempDir()
	clk := newClock(t0)
	s := openStore(t, testOptions(dir, clk))
	appendSamples(t, s, clk, 2, time.Second)
	clk.Advance(24 * time.Hour)
	appendSamples(t, s, clk, 2, time.Second)
	head := s.Head()
	s.Close()
	os.Remove(segPath(dir, segName(t0)))

	s2 := openStore(t, testOptions(dir, clk))
	after := recordsAfter(t, s2, head.Seq)
	if fmt.Sprint(typesOf(after)) != "[integrity_alert]" {
		t.Fatalf("records %v", typesOf(after))
	}
	a := decodeData[model.IntegrityAlert](t, after[0])
	if !strings.Contains(strings.Join(a.Details, "\n"), "instead of the genesis record") {
		t.Fatalf("alert %+v", a)
	}
	rep, _ := s2.Verify(context.Background())
	if rep.OK || problems(rep)[probSignature] == 0 {
		t.Fatalf("verification must fail without genesis:\n%s", dumpReport(rep))
	}
}

func TestFailedWriteIsRolledBackOrFenced(t *testing.T) {
	dir := t.TempDir()
	clk := newClock(t0)
	s := openStore(t, testOptions(dir, clk))
	appendSamples(t, s, clk, 2, time.Second)
	head := s.Head()
	// Pull the file out from under the writer: the write and the rollback both fail.
	s.active.f.Close()
	if _, err := s.Append(model.TypeSample, samplePayload(1)); err == nil {
		t.Fatal("expected write error")
	}
	if _, err := s.Append(model.TypeSample, samplePayload(2)); err == nil || !strings.Contains(err.Error(), "unusable") {
		t.Fatalf("expected the store to be fenced: %v", err)
	}
	if s.Head() != head {
		t.Fatal("head advanced on a failed write")
	}
	s.Close()
	s2 := openStore(t, testOptions(dir, clk))
	if s2.Head() != head {
		t.Fatalf("head %+v want %+v", s2.Head(), head)
	}
	mustAppend(t, s2, model.TypeSample, samplePayload(3))
	rep, _ := s2.Verify(context.Background())
	requireOK(t, rep)
}

func TestOpenTimeValidationChecksLinkToPreviousSegment(t *testing.T) {
	dir := t.TempDir()
	clk := newClock(t0)
	s := openStore(t, testOptions(dir, clk))
	appendSamples(t, s, clk, 2, time.Second)
	clk.Advance(24 * time.Hour)
	appendSamples(t, s, clk, 2, time.Second)
	priv := append(ed25519.PrivateKey(nil), s.priv...)
	head := s.Head()
	s.Close()

	// Re-sign the active segment's segment_open with a wrong prev_segment_sha256: hashes and
	// signatures are valid, only the link to the sealed segment is wrong.
	path := segPath(dir, segName(t0.Add(24*time.Hour)))
	lines := readLines(t, path)
	_, so := parseLine(t, lines[0])
	d := decodeData[model.SegmentOpen](t, so)
	d.PrevSegmentSHA256 = strings.Repeat("0", 64)
	so.Data, _ = marshalJSON(d)
	lines[0] = reencode(t, priv, so)
	writeLines(t, path, lines)

	s2 := openStore(t, testOptions(dir, clk))
	after := recordsAfter(t, s2, head.Seq)
	if fmt.Sprint(typesOf(after)) != "[integrity_alert]" {
		t.Fatalf("records %v", typesOf(after))
	}
	a := decodeData[model.IntegrityAlert](t, after[0])
	if !strings.Contains(strings.Join(a.Details, "\n"), "segment_hash") {
		t.Fatalf("alert %+v", a)
	}
}
