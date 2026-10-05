package ledger

// Adversarial tests added during the independent review of this package. Each one pins down a
// behaviour that was wrong (or not covered) in the first implementation; the comment above each
// test says what used to happen.

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// The genesis record confirms the signing key, so an active segment whose only line is signed
// by another key is tampering, not "a key file that does not belong to this ledger". Open used
// to refuse to start (a denial of service with a misleading message); it must quarantine the
// forged bytes, document them and keep monitoring.
func TestForgedActiveSegmentWithConfirmedKeyIsQuarantined(t *testing.T) {
	dir := t.TempDir()
	clk := newClock(t0)
	s := openStore(t, testOptions(dir, clk))
	appendSamples(t, s, clk, 2, time.Second)
	day1Head := s.Head()
	clk.Advance(24 * time.Hour)
	appendSamples(t, s, clk, 2, time.Second)
	s.Close()

	day2Name := segName(t0.Add(24 * time.Hour))
	day2 := segPath(dir, day2Name)
	_, b := parseLine(t, readLines(t, day2)[0])
	_, other, _ := ed25519.GenerateKey(nil)
	forged := reencode(t, other, b) // intact hash, foreign signature
	writeLines(t, day2, [][]byte{forged})

	clk.Advance(time.Hour)
	s2, err := Open(testOptions(dir, clk))
	if err != nil {
		t.Fatalf("Open refused a ledger whose key is confirmed by its genesis record: %v", err)
	}
	defer s2.Close()
	bodies := recordsAfter(t, s2, day1Head.Seq)
	if got := fmt.Sprint(typesOf(bodies)); got != "[segment_open recovery integrity_alert]" {
		t.Fatalf("records after reopen %s", got)
	}
	if bodies[0].Seq != day1Head.Seq+1 || bodies[0].Prev != day1Head.Hash {
		t.Fatalf("new segment does not chain to the last valid record: %+v", bodies[0])
	}
	rec := decodeData[model.Recovery](t, bodies[1])
	if rec.Segment != day2Name || rec.Offset != 0 || rec.RemovedBytes != int64(len(forged)) || rec.RemovedSHA256 != sha256Hex(forged) {
		t.Fatalf("recovery %+v", rec)
	}
	q, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rec.QuarantineAs)))
	if err != nil || !bytes.Equal(q, forged) {
		t.Fatalf("forged bytes not preserved in quarantine (%v)", err)
	}
	alert := decodeData[model.IntegrityAlert](t, bodies[2])
	if !strings.Contains(strings.Join(alert.Details, "\n"), "bad_signature") {
		t.Fatalf("alert does not explain the foreign signature: %+v", alert)
	}
	rep, err := s2.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireOK(t, rep)
}

// A record that is intact and correctly signed was written by the key holder; a crash cannot
// produce it. Open used to treat such a line at the end of the active segment as a torn tail
// when its body had an unexpected format version or an unparsable ts, and moved it out of the
// ledger (history rewritten, e.g. after a downgrade). It must stay and be reported instead.
func TestSignedTailRecordIsNeverTruncated(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(b *model.Body)
		want   string
	}{
		{"future format version", func(b *model.Body) { b.V = 2 }, "unsupported body format version"},
		{"unparsable ts", func(b *model.Body) { b.TS = "yesterday" }, "is not an RFC 3339 time"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			clk := newClock(t0)
			s := openStore(t, testOptions(dir, clk))
			refs := appendSamples(t, s, clk, 3, time.Second)
			priv := append(ed25519.PrivateKey(nil), s.priv...)
			s.Close()

			path := segPath(dir, segName(t0))
			lines := readLines(t, path)
			_, b := parseLine(t, lines[len(lines)-1])
			b.Seq, b.Prev = refs[2].Seq+1, refs[2].Hash
			tc.mutate(&b)
			signed := reencode(t, priv, b)
			writeLines(t, path, append(lines, signed))

			clk.Advance(time.Minute)
			s2 := openStore(t, testOptions(dir, clk))
			now := readLines(t, path)
			if len(now) < len(lines)+1 || !bytes.Equal(now[len(lines)], signed) {
				t.Fatal("a correctly signed record was removed from the ledger")
			}
			after := recordsAfter(t, s2, refs[2].Seq)
			if got := fmt.Sprint(typesOf(after)); got != "[sample integrity_alert]" {
				t.Fatalf("records %s", got)
			}
			alert := decodeData[model.IntegrityAlert](t, after[1])
			if !strings.Contains(strings.Join(alert.Details, "\n"), tc.want) {
				t.Fatalf("alert %+v", alert)
			}
			if after[1].Prev != sha256Hex([]byte(mustEnv(t, signed).B)) || after[1].Seq != b.Seq+1 {
				t.Fatalf("chain does not continue from the signed record: %+v", after[1])
			}
			if entries, _ := os.ReadDir(filepath.Join(dir, "quarantine")); len(entries) != 0 {
				t.Fatalf("quarantine written: %v", entries)
			}
		})
	}
}

func mustEnv(t *testing.T, line []byte) model.Envelope {
	t.Helper()
	env, err := parseEnvelopeStrict(line)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// Values copied from a tampered record into failure details used to be unbounded: six records
// with a 3 MiB ts produced an 18 MiB integrity_alert, which exceeds the record size limit, so
// Open failed and the monitor could never start again. Reports must stay small, too.
func TestHugeTamperedValuesDoNotBreakOpenOrReports(t *testing.T) {
	dir := t.TempDir()
	clk := newClock(t0)
	s := openStore(t, testOptions(dir, clk))
	appendSamples(t, s, clk, 10, time.Second)
	head := s.Head()
	s.Close()

	path := segPath(dir, segName(t0))
	lines := readLines(t, path)
	huge := strings.Repeat("9", 3<<20)
	for i := 2; i <= 7; i++ {
		_, b := parseLine(t, lines[i])
		old := []byte(`\"ts\":\"` + b.TS + `\"`)
		if !bytes.Contains(lines[i], old) {
			t.Fatalf("line %d lacks %s", i, old)
		}
		lines[i] = bytes.Replace(lines[i], old, []byte(`\"ts\":\"`+huge+`\"`), 1)
	}
	writeLines(t, path, lines)

	clk.Advance(time.Minute)
	s2, err := Open(testOptions(dir, clk))
	if err != nil {
		t.Fatalf("Open failed on a tampered ledger: %v", err)
	}
	defer s2.Close()
	after := recordsAfter(t, s2, head.Seq)
	if fmt.Sprint(typesOf(after)) != "[integrity_alert]" {
		t.Fatalf("records %v", typesOf(after))
	}
	env, _, err := s2.Record(after[0].Seq)
	if err != nil || len(env.B) > 64<<10 {
		t.Fatalf("integrity_alert of %d bytes (%v)", len(env.B), err)
	}
	rep, err := s2.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("tampering not reported")
	}
	b, _ := json.Marshal(rep)
	if len(b) > 256<<10 {
		t.Fatalf("verification report of %d bytes", len(b))
	}
}

// A wall clock that jumps days ahead (rotation into a future-dated segment) and is then
// corrected leaves current records in the future-dated segment, because the writer never
// reopens an older segment. ScanTime skipped that segment and returned nothing for the
// corrected period (dashboard history and incident lookups went blind).
func TestScanTimeAfterForwardClockJumpIsCorrected(t *testing.T) {
	dir := t.TempDir()
	clk := newClock(t0)
	s := openStore(t, testOptions(dir, clk))
	appendSamples(t, s, clk, 1, time.Second)
	clk.Step(t0.Add(5 * 24 * time.Hour))
	mustAppend(t, s, model.TypeClockJump, model.ClockJump{WallDeltaMs: 5 * 86400000, JumpMs: 5 * 86400000})
	clk.Step(t0.Add(time.Hour))
	refs := appendSamples(t, s, clk, 3, 10*time.Second)
	if s.active.name != segName(t0.Add(5*24*time.Hour)) {
		t.Fatalf("active segment %s", s.active.name)
	}
	check := func(t *testing.T, r contracts.LedgerReader) {
		t.Helper()
		var got []uint64
		if err := r.ScanTime(t0.Add(30*time.Minute), t0.Add(2*time.Hour), func(_ model.Envelope, b model.Body) error {
			got = append(got, b.Seq)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		want := []uint64{refs[0].Seq, refs[1].Seq, refs[2].Seq}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("ScanTime = %v, want %v", got, want)
		}
	}
	t.Run("writer", func(t *testing.T) { check(t, s) })
	opts := testOptions(dir, clk)
	opts.ReadOnly = true
	ro := openStore(t, opts)
	t.Run("read-only", func(t *testing.T) { check(t, ro) })
	s.Close()
	t.Run("compressed", func(t *testing.T) {
		clk.Step(t0.Add(10 * 24 * time.Hour))
		w := openStore(t, testOptions(dir, clk))
		mustAppend(t, w, model.TypeSample, samplePayload(1)) // rotates
		if n, err := w.CompressSealed(0); err != nil || n != 2 {
			t.Fatalf("CompressSealed = %d, %v", n, err)
		}
		check(t, w)
	})
}

// Failures found by the deferred anchor lookup used to be dropped from the report once 200
// failures had been collected, although they lie earlier in the ledger than the ones listed.
func TestDeferredAnchorFailureIsListedInLedgerOrder(t *testing.T) {
	dir := t.TempDir()
	clk := newClock(t0)
	s := openStore(t, testOptions(dir, clk))
	refs := appendSamples(t, s, clk, 5, time.Second)
	tok, err := s.PutBlob([]byte("token"))
	if err != nil {
		t.Fatal(err)
	}
	anchor := mustAppend(t, s, model.TypeAnchor, model.Anchor{
		TSAURL: "http://tsa.example/", HeadSeq: refs[1].Seq, HeadHash: refs[0].Hash, TokenSHA256: tok,
	}, tok)
	appendSamples(t, s, clk, 250, time.Second)
	s.Close()

	path := segPath(dir, segName(t0))
	lines := readLines(t, path)
	zero := strings.Repeat("0", 64)
	for i := int(anchor.Seq) + 1; i < len(lines); i++ {
		env, _ := parseLine(t, lines[i])
		lines[i] = bytes.Replace(lines[i], []byte(env.H), []byte(zero), 1)
	}
	writeLines(t, path, lines)

	opts := testOptions(dir, clk)
	opts.ReadOnly = true
	ro := openStore(t, opts)
	rep, err := VerifyReader(context.Background(), ro, VerifyOptions{CheckBlobs: true, ringSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	if rep.FailuresTotal != 251 || len(rep.Failures) != maxReportedFailures {
		t.Fatalf("failures listed %d, total %d", len(rep.Failures), rep.FailuresTotal)
	}
	if f := rep.Failures[0]; f.Problem != probAnchor || f.Seq != anchor.Seq {
		t.Fatalf("first failure %+v, want the anchor at seq %d:\n%s", f, anchor.Seq, dumpReport(rep))
	}
	for i := 1; i < len(rep.Failures); i++ {
		if rep.Failures[i].Line < rep.Failures[i-1].Line {
			t.Fatalf("failures not in ledger order at %d", i)
		}
	}
	if last := rep.Failures[len(rep.Failures)-1]; last.Seq != anchor.Seq+199 {
		t.Fatalf("last listed failure %+v", last)
	}
}

// Verifying something that holds no ledger segment at all used to report OK=true.
func TestVerifyNothingIsNotOK(t *testing.T) {
	rep, err := VerifyReader(context.Background(), emptyReader{}, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK || rep.FailuresTotal == 0 {
		t.Fatalf("an empty ledger verified OK:\n%s", dumpReport(rep))
	}
}

// tailReader serves a store's segments and appends extra bytes to the last one, like a
// bundle whose final segment was damaged or extended. It deliberately does not embed *Store,
// so it is verified like any other LedgerReader (a bundle), not like the live ledger.
type tailReader struct {
	s     *Store
	extra []byte
}

func (r *tailReader) Scan(from uint64, fn func(model.Envelope, model.Body) error) error {
	return r.s.Scan(from, fn)
}
func (r *tailReader) ScanTime(from, to time.Time, fn func(model.Envelope, model.Body) error) error {
	return r.s.ScanTime(from, to, fn)
}
func (r *tailReader) Record(seq uint64) (model.Envelope, model.Body, error) { return r.s.Record(seq) }
func (r *tailReader) GetBlob(id string) ([]byte, error)                     { return r.s.GetBlob(id) }
func (r *tailReader) Segments() ([]contracts.SegmentInfo, error)            { return r.s.Segments() }

func (r *tailReader) OpenSegment(name string) (io.ReadCloser, error) {
	segs, err := r.s.Segments()
	if err != nil {
		return nil, err
	}
	rc, err := r.s.OpenSegment(name)
	if err != nil || len(segs) == 0 || segs[len(segs)-1].Name != name {
		return rc, err
	}
	b, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(append(b, r.extra...))), nil
}

var _ contracts.LedgerReader = (*tailReader)(nil)

// An exporter never copies the incomplete line of a segment that is being written, so an
// incomplete final line in a bundle is damage. It used to be only a note (OK=true). The live
// read-only store keeps the note: there the writer may be in the middle of a write.
func TestIncompleteFinalLineOutsideTheLiveLedgerFails(t *testing.T) {
	s, _, clk := newLedger(t)
	appendSamples(t, s, clk, 3, time.Second)
	r := &tailReader{s: s, extra: []byte(`{"h":"00`)}
	if _, ok := any(r).(verifySegmentLister); ok {
		t.Fatal("test reader must not look like the live store")
	}
	rep, err := VerifyReader(context.Background(), r, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK || problems(rep)[probParse] != 1 {
		t.Fatalf("incomplete final line accepted:\n%s", dumpReport(rep))
	}
}

// PutBlob replaced a corrupt stored copy and moved the damaged one to quarantine, but nothing
// in the ledger recorded that the evidence store had been damaged. It must append an
// integrity_alert naming the blob and where the damaged copy went.
func TestCorruptBlobReplacementIsRecordedInLedger(t *testing.T) {
	s, dir, _ := newLedger(t)
	content := []byte("<html>sysinfo</html>")
	id, err := s.PutBlob(content)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.blobPath(id), gz(t, []byte("<html>edited</html>")), 0o644); err != nil {
		t.Fatal(err)
	}
	head := s.Head()
	if _, err := s.PutBlob(content); err != nil {
		t.Fatal(err)
	}
	after := recordsAfter(t, s, head.Seq)
	if fmt.Sprint(typesOf(after)) != "[integrity_alert]" {
		t.Fatalf("records %v", typesOf(after))
	}
	alert := decodeData[model.IntegrityAlert](t, after[0])
	details := strings.Join(append([]string{alert.Problem}, alert.Details...), "\n")
	q, _ := filepath.Glob(filepath.Join(dir, "quarantine", id+".gz.corrupt*"))
	if len(q) != 1 || !strings.Contains(details, id) || !strings.Contains(details, "quarantine/"+filepath.Base(q[0])) {
		t.Fatalf("alert %+v, quarantine %v", alert, q)
	}
	// A healthy duplicate put appends nothing.
	head = s.Head()
	if _, err := s.PutBlob(content); err != nil || s.Head() != head {
		t.Fatalf("dedupe appended records or failed: %v", err)
	}
	rep, err := s.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireOK(t, rep)
}

// keys/ledger-signing.pub.txt is what humans compare with a bundle. Open used to rewrite it
// from a foreign key file before refusing that key, leaving a wrong fingerprint behind.
func TestRefusedForeignKeyDoesNotRewritePublicKeyText(t *testing.T) {
	dir := t.TempDir()
	clk := newClock(t0)
	s := openStore(t, testOptions(dir, clk))
	fp := s.Fingerprint()
	s.Close()
	pubTxt := filepath.Join(dir, "keys", "ledger-signing.pub.txt")
	before, err := os.ReadFile(pubTxt)
	if err != nil || !strings.Contains(string(before), fp) {
		t.Fatalf("pub.txt %q %v", before, err)
	}
	other := t.TempDir()
	o := openStore(t, testOptions(other, clk))
	o.Close()
	kb, _ := os.ReadFile(filepath.Join(other, "keys", "ledger-signing.key"))
	os.WriteFile(filepath.Join(dir, "keys", "ledger-signing.key"), kb, 0o600)
	if _, err := Open(testOptions(dir, clk)); err == nil {
		t.Fatal("foreign key accepted")
	}
	after, _ := os.ReadFile(pubTxt)
	if !bytes.Equal(before, after) {
		t.Fatalf("pub.txt rewritten from a refused key:\n%s", after)
	}
}

// A ledger that verifies but contains recovery or integrity_alert records must say so in the
// report: those records are part of the evidence a reader has to look at.
func TestVerifyNotesWriterAlertsAndRecoveries(t *testing.T) {
	dir := t.TempDir()
	clk := newClock(t0)
	s := openStore(t, testOptions(dir, clk))
	appendSamples(t, s, clk, 3, time.Second)
	s.Close()
	path := segPath(dir, segName(t0))
	b, _ := os.ReadFile(path)
	os.WriteFile(path, append(b, []byte(`{"h":"torn`)...), 0o644)
	s2 := openStore(t, testOptions(dir, clk))
	mustAppend(t, s2, model.TypeIntegrityAlert, model.IntegrityAlert{Problem: "test", Details: []string{"x"}})
	rep, err := s2.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireOK(t, rep)
	notes := strings.Join(rep.Notes, "\n")
	if !strings.Contains(notes, "1 recovery record") || !strings.Contains(notes, "1 integrity_alert record") {
		t.Fatalf("notes %q", rep.Notes)
	}
}

// A compressed copy that differs from its sealed segment is never produced by this writer (the
// .gz appears only through an atomic rename after a byte-for-byte check), so CompressSealed
// must record it, not just log it, when it moves the copy to quarantine.
func TestStaleCompressedCopyIsRecorded(t *testing.T) {
	s, dir, _, names := fiveDayLedger(t)
	p1 := segPath(dir, names[1])
	os.WriteFile(p1+".gz", gz(t, []byte("not the segment")), 0o644)
	head := s.Head()
	if _, err := s.CompressSealed(0); err != nil {
		t.Fatal(err)
	}
	after := recordsAfter(t, s, head.Seq)
	if fmt.Sprint(typesOf(after)) != "[integrity_alert]" {
		t.Fatalf("records %v", typesOf(after))
	}
	a := decodeData[model.IntegrityAlert](t, after[0])
	q, _ := filepath.Glob(filepath.Join(dir, "quarantine", names[1]+".jsonl.gz.stale*"))
	if len(q) != 1 || !strings.Contains(strings.Join(a.Details, "\n"), filepath.Base(q[0])) {
		t.Fatalf("alert %+v quarantine %v", a, q)
	}
	rep, err := s.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireOK(t, rep)
}

// Close must not release the writer lock while CompressSealed is still changing files in the
// ledger directory: once Close has returned, nothing in the directory may change any more (a
// CompressSealed that starts later returns ErrClosed without touching anything).
func TestCloseWaitsForCompressSealed(t *testing.T) {
	listing := func(dir string) string {
		entries, err := os.ReadDir(filepath.Join(dir, "ledger"))
		if err != nil {
			t.Fatal(err)
		}
		var b strings.Builder
		for _, e := range entries {
			fi, _ := e.Info()
			fmt.Fprintln(&b, e.Name(), fi.Size())
		}
		return b.String()
	}
	for i := 0; i < 8; i++ {
		s, dir, clk, _ := fiveDayLedger(t)
		started := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			close(started)
			_, err := s.CompressSealed(0)
			done <- err
		}()
		<-started
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		atClose := listing(dir)
		if err := <-done; err != nil && !errors.Is(err, ErrClosed) {
			t.Fatalf("CompressSealed: %v", err)
		}
		if after := listing(dir); after != atClose {
			t.Fatalf("ledger directory changed after Close returned:\n%s\nvs\n%s", atClose, after)
		}
		s2 := openStore(t, testOptions(dir, clk))
		rep, err := s2.Verify(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		requireOK(t, rep)
		s2.Close()
	}
}

func TestClipToRespectsUTF8(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"short", 80, "short"},
		{"abcdef", 3, "abc..."},
		{"ééé", 3, "é..."}, // 'é' is 2 bytes: cut before the split rune
		{"日本語", 4, "日..."},
		{"日本語", 6, "日本..."},
		{"", 0, ""},
	}
	for _, tc := range cases {
		got := clipTo(tc.in, tc.n)
		if got != tc.want || !utf8.ValidString(got) {
			t.Errorf("clipTo(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
		}
	}
}

// Notes are copied into the bootstrap_import record. A large CAPTURE-NOTES.txt used to make
// the record exceed the size limit, so the whole import failed (and the service only tries it
// once, when the ledger is created). The notes are now bounded with an explicit marker; the
// exact file is always kept as a blob.
func TestImportBootstrapLargeNotes(t *testing.T) {
	s, _, _ := newLedger(t)
	src := t.TempDir()
	notes := []byte(strings.Repeat("captured by the owner; ", 1<<20)) // ~23 MiB
	os.WriteFile(filepath.Join(src, "CAPTURE-NOTES.txt"), notes, 0o644)
	os.WriteFile(filepath.Join(src, "page.html"), []byte("<html></html>"), 0o644)
	ref, err := s.ImportBootstrap(src)
	if err != nil {
		t.Fatalf("ImportBootstrap: %v", err)
	}
	_, body, err := s.Record(ref.Seq)
	if err != nil {
		t.Fatal(err)
	}
	imp := decodeData[model.BootstrapImport](t, body)
	id := sha256Hex(notes)
	if len(imp.Notes) > maxBootstrapNotes+512 || !strings.HasPrefix(string(notes), strings.SplitN(imp.Notes, "\n[", 2)[0]) ||
		!strings.Contains(imp.Notes, id) {
		t.Fatalf("notes of %d bytes: %q", len(imp.Notes), imp.Notes[len(imp.Notes)-200:])
	}
	if got, err := s.GetBlob(id); err != nil || !bytes.Equal(got, notes) {
		t.Fatalf("notes blob: %v", err)
	}
}

// Only damaged content is "corrupt"; an operating-system read error is not (PutBlob would
// otherwise move a good copy to quarantine and record damage that does not exist).
func TestBlobReadErrorClassification(t *testing.T) {
	id := strings.Repeat("ab", 32)
	cases := []struct {
		name    string
		err     error
		corrupt bool
	}{
		{"bad gzip header", gzip.ErrHeader, true},
		{"bad checksum", gzip.ErrChecksum, true},
		{"truncated", io.ErrUnexpectedEOF, true},
		{"empty file", io.EOF, true},
		{"read failed", &fs.PathError{Op: "read", Path: "x", Err: errors.New("I/O device error")}, false},
	}
	for _, tc := range cases {
		err := blobReadError(id, tc.err)
		if errors.Is(err, ErrBlobCorrupt) != tc.corrupt || !strings.Contains(err.Error(), id) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

// A damaged sealed segment dated after the queried range must not make ScanTime fail for an
// unrelated earlier range (Verify reports the damage).
func TestScanTimeIgnoresUnreadableLaterSegment(t *testing.T) {
	s, dir, _, names := fiveDayLedger(t)
	if _, err := s.CompressSealed(0); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(segPath(dir, names[3])+".gz", []byte("not gzip"), 0o644)
	n := 0
	if err := s.ScanTime(t0, t0.Add(time.Hour), func(model.Envelope, model.Body) error { n++; return nil }); err != nil || n == 0 {
		t.Fatalf("ScanTime = %d records, %v", n, err)
	}
	rep, _ := s.Verify(context.Background())
	if rep.OK || problems(rep)[probParse] == 0 {
		t.Fatalf("damaged segment not reported:\n%s", dumpReport(rep))
	}
}
