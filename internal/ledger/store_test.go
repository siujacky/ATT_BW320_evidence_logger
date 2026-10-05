package ledger

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

func TestOpenCreatesLedger(t *testing.T) {
	s, dir, _ := newLedger(t)
	if !s.Created() {
		t.Fatal("Created() = false on first open")
	}
	head := s.Head()
	if head.Seq != 0 || len(head.Hash) != 64 || head.TS != t0.Format(time.RFC3339Nano) {
		t.Fatalf("head after genesis = %+v", head)
	}
	if s.GenesisTS() != head.TS {
		t.Fatalf("GenesisTS = %q, want %q", s.GenesisTS(), head.TS)
	}
	if len(s.RunID()) != 32 || !isLowerHex(s.RunID(), 32) {
		t.Fatalf("run id %q", s.RunID())
	}
	pub := s.PublicKey()
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("public key length %d", len(pub))
	}
	sum := sha256.Sum256(pub)
	if s.Fingerprint() != hex.EncodeToString(sum[:]) || s.Fingerprint() != Fingerprint(pub) {
		t.Fatalf("fingerprint %q", s.Fingerprint())
	}

	// Key file: JSON {alg, protected, public, created}; with identity protection the seed
	// is the protected blob.
	kb, err := os.ReadFile(filepath.Join(dir, "keys", "ledger-signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	var kf map[string]string
	if err := json.Unmarshal(kb, &kf); err != nil {
		t.Fatal(err)
	}
	if kf["alg"] != "ed25519" || kf["public"] != base64.StdEncoding.EncodeToString(pub) || kf["created"] == "" {
		t.Fatalf("key file %v", kf)
	}
	seed, _ := base64.StdEncoding.DecodeString(kf["protected"])
	if !bytes.Equal(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), pub) {
		t.Fatal("protected seed does not derive the public key")
	}
	txt, err := os.ReadFile(filepath.Join(dir, "keys", "ledger-signing.pub.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{base64.StdEncoding.EncodeToString(pub), s.Fingerprint(), FormatFingerprint(s.Fingerprint())} {
		if !strings.Contains(string(txt), want) {
			t.Fatalf("pub.txt lacks %q:\n%s", want, txt)
		}
	}

	// Genesis record content.
	bodies := scanAll(t, s)
	if len(bodies) != 1 || bodies[0].Type != model.TypeGenesis || bodies[0].Seq != 0 || bodies[0].Prev != model.ZeroHash {
		t.Fatalf("genesis bodies %+v", bodies)
	}
	g := decodeData[model.Genesis](t, bodies[0])
	if g.PublicKey != base64.StdEncoding.EncodeToString(pub) || g.Fingerprint != s.Fingerprint() ||
		g.Host.Hostname != "test-host" || g.Software.Name != "att-monitor" || g.Statement != DefaultStatement || g.Created != head.TS {
		t.Fatalf("genesis payload %+v", g)
	}
	if _, err := os.Stat(segPath(dir, segName(t0))); err != nil {
		t.Fatalf("segment file: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(dir, "ledger", ".lock")); err != nil || fi.Size() == 0 {
		t.Fatalf("lock file: %v", err)
	}
}

func TestCustomStatementAndKeyProtection(t *testing.T) {
	dir := t.TempDir()
	clk := newClock(t0)
	opts := testOptions(dir, clk)
	opts.Statement = "custom statement"
	xor := func(b []byte) ([]byte, error) {
		out := make([]byte, len(b))
		for i := range b {
			out[i] = b[i] ^ 0x5a
		}
		return out, nil
	}
	opts.KeyProtect, opts.KeyUnprotect = xor, xor
	s := openStore(t, opts)
	pub := s.PublicKey()
	g := decodeData[model.Genesis](t, scanAll(t, s)[0])
	if g.Statement != "custom statement" {
		t.Fatalf("statement %q", g.Statement)
	}
	s.Close()

	kb, _ := os.ReadFile(filepath.Join(dir, "keys", "ledger-signing.key"))
	var kf keyFile
	if err := json.Unmarshal(kb, &kf); err != nil {
		t.Fatal(err)
	}
	blob, _ := base64.StdEncoding.DecodeString(kf.Protected)
	seed, _ := xor(blob)
	if bytes.Equal(blob, seed) || !bytes.Equal(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), pub) {
		t.Fatal("KeyProtect was not applied to the stored seed")
	}

	// Reopening with the wrong unprotect function fails cleanly.
	opts.KeyUnprotect = identity
	if _, err := Open(opts); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("Open with wrong unprotect: %v", err)
	}
	opts.KeyUnprotect = func([]byte) ([]byte, error) { return nil, errors.New("dpapi says no") }
	if _, err := Open(opts); err == nil || !strings.Contains(err.Error(), "dpapi says no") {
		t.Fatalf("Open with failing unprotect: %v", err)
	}
	opts.KeyUnprotect = xor
	s2 := openStore(t, opts)
	if s2.Created() || s2.Fingerprint() != Fingerprint(pub) {
		t.Fatal("reopen with the right key failed")
	}
}

func TestReopenContinuesChain(t *testing.T) {
	s, dir, clk := newLedger(t)
	refs := appendSamples(t, s, clk, 5, 10*time.Second)
	runA := s.RunID()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := s.Append(model.TypeSample, samplePayload(1)); !errors.Is(err, ErrClosed) {
		t.Fatalf("Append after Close: %v", err)
	}
	if _, err := s.PutBlob([]byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("PutBlob after Close: %v", err)
	}
	if _, err := s.CompressSealed(0); !errors.Is(err, ErrClosed) {
		t.Fatalf("CompressSealed after Close: %v", err)
	}
	if got := len(scanAll(t, s)); got != 6 {
		t.Fatalf("reads after Close: %d records", got)
	}

	clk.Advance(time.Minute)
	s2 := openStore(t, testOptions(dir, clk))
	if s2.Created() {
		t.Fatal("Created() true on reopen")
	}
	if s2.Head() != refs[len(refs)-1] {
		t.Fatalf("head %+v, want %+v", s2.Head(), refs[len(refs)-1])
	}
	if s2.RunID() == runA {
		t.Fatal("run id reused")
	}
	if s2.GenesisTS() != t0.Format(time.RFC3339Nano) {
		t.Fatalf("GenesisTS %q", s2.GenesisTS())
	}
	ref := mustAppend(t, s2, model.TypeMonitorStart, model.MonitorStart{Mode: "console"})
	if ref.Seq != 6 {
		t.Fatalf("seq %d after reopen", ref.Seq)
	}
	_, b, err := s2.Record(6)
	if err != nil || b.Prev != refs[4].Hash || b.Run != s2.RunID() || b.Mono != 0 {
		t.Fatalf("record 6 = %+v, %v", b, err)
	}
	rep, err := s2.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireOK(t, rep)
	if rep.Records != 7 || rep.HeadHash != ref.Hash {
		t.Fatalf("report records=%d head=%s", rep.Records, rep.HeadHash)
	}
}

func TestEnvelopeFormat(t *testing.T) {
	s, dir, clk := newLedger(t)
	clk.Advance(1234567 * time.Nanosecond)
	id, err := s.PutBlob([]byte("raw page <html>"))
	if err != nil {
		t.Fatal(err)
	}
	ref := mustAppend(t, s, model.TypeSample, samplePayload(3), id)
	lines := readLines(t, segPath(dir, segName(t0)))
	if len(lines) != 2 {
		t.Fatalf("%d lines", len(lines))
	}
	line := lines[1]
	if !bytes.HasSuffix(line, []byte("\n")) || bytes.Count(line, []byte("\n")) != 1 {
		t.Fatal("line must end with exactly one newline")
	}
	// Exactly the keys h, s, b, in that order.
	if !bytes.HasPrefix(line, []byte(`{"h":"`)) {
		t.Fatalf("line prefix %q", line[:10])
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(line, &raw); err != nil || len(raw) != 3 {
		t.Fatalf("envelope keys %v %v", raw, err)
	}
	env, err := parseEnvelopeStrict(line)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(env.B))
	if env.H != hex.EncodeToString(sum[:]) || env.H != ref.Hash {
		t.Fatal("h is not the SHA-256 of b")
	}
	sig, err := base64.StdEncoding.DecodeString(env.S)
	if err != nil || !ed25519.Verify(s.PublicKey(), []byte(env.B), sig) {
		t.Fatal("s is not a valid signature over b")
	}
	// No HTML escaping anywhere; U+2028 is escaped by encoding/json as required by JSON-in-JS.
	if strings.Contains(env.B, `\u003c`) || !strings.Contains(env.B, "<fast> &") {
		t.Fatalf("body is HTML-escaped: %s", env.B)
	}
	// Body field order and content.
	if !strings.HasPrefix(env.B, `{"v":1,"seq":1,"prev":"`) {
		t.Fatalf("body prefix %s", env.B[:40])
	}
	var body model.Body
	if err := json.Unmarshal([]byte(env.B), &body); err != nil {
		t.Fatal(err)
	}
	first := parseLineBody(t, lines[0])
	ts, err := time.Parse(time.RFC3339Nano, body.TS)
	if err != nil || !ts.Equal(t0.Add(1234567)) || !strings.HasSuffix(body.TS, "Z") {
		t.Fatalf("ts %q", body.TS)
	}
	if body.V != 1 || body.Seq != 1 || body.Prev != first.hash || body.Type != model.TypeSample ||
		body.Run != s.RunID() || body.Mono != int64(1234567) || len(body.Blobs) != 1 || body.Blobs[0] != id {
		t.Fatalf("body %+v", body)
	}
	want, _ := marshalJSON(samplePayload(3))
	if !bytes.Equal(body.Data, want) {
		t.Fatalf("data %s\nwant %s", body.Data, want)
	}
	// The fast reader path agrees with the full parse.
	seq, qts, ok := quickSeqTS(line)
	if !ok || seq != 1 || string(qts) != body.TS {
		t.Fatalf("quickSeqTS = %d %q %v", seq, qts, ok)
	}
}

type lineInfo struct{ hash string }

func parseLineBody(t *testing.T, line []byte) lineInfo {
	env, _ := parseLine(t, line)
	return lineInfo{hash: sha256Hex([]byte(env.B))}
}

func TestAppendValidation(t *testing.T) {
	s, _, _ := newLedger(t)
	id, err := s.PutBlob([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	missing := strings.Repeat("ab", 32)
	cases := []struct {
		name  string
		typ   string
		data  any
		blobs []string
		want  string
		is    error
	}{
		{"empty type", "", 1, nil, "invalid record type", nil},
		{"upper case type", "Sample", 1, nil, "invalid record type", nil},
		{"type with space", "a b", 1, nil, "invalid record type", nil},
		{"reserved genesis", model.TypeGenesis, 1, nil, "reserved", nil},
		{"reserved segment_open", model.TypeSegmentOpen, 1, nil, "reserved", nil},
		{"unencodable data", model.TypeOperatorNote, func() {}, nil, "encode", nil},
		{"invalid blob id", model.TypeOperatorNote, 1, []string{"xyz"}, "invalid blob id", nil},
		{"upper-case blob id", model.TypeOperatorNote, 1, []string{strings.ToUpper(id)}, "invalid blob id", nil},
		{"missing blob", model.TypeOperatorNote, 1, []string{missing}, "does not exist", contracts.ErrNotFound},
		{"invalid utf-8 raw data", model.TypeOperatorNote, json.RawMessage("\"\xff\""), nil, "UTF-8", nil},
		{"oversized record", model.TypeOperatorNote, strings.Repeat("x", maxRecordBytes), nil, "exceeds", nil},
	}
	head := s.Head()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.Append(tc.typ, tc.data, tc.blobs...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Fatalf("err = %v, want errors.Is %v", err, tc.is)
			}
		})
	}
	if s.Head() != head {
		t.Fatal("failed appends changed the head")
	}
	// Valid: duplicate blob ids are de-duplicated; nil data is "null".
	ref := mustAppend(t, s, model.TypeOperatorNote, nil, id, id)
	_, b, err := s.Record(ref.Seq)
	if err != nil || len(b.Blobs) != 1 || string(b.Data) != "null" {
		t.Fatalf("record %+v %v", b, err)
	}
	rep, _ := s.Verify(context.Background())
	requireOK(t, rep)
}

func TestRoundTripScanVerify(t *testing.T) {
	s, _, clk := newLedger(t)
	page, err := s.PutBlob([]byte("<html>gateway page</html>"))
	if err != nil {
		t.Fatal(err)
	}
	payloads := []struct {
		typ   string
		data  any
		blobs []string
	}{
		{model.TypeMonitorStart, model.MonitorStart{Mode: "console", ConfigSHA256: strings.Repeat("0", 64)}, nil},
		{model.TypeSample, samplePayload(1), nil},
		{model.TypeGatewaySnapshot, map[string]any{"pages": []string{page}}, []string{page}},
		{model.TypeStateChange, model.StateChange{FromState: "ONLINE", ToState: "ISP_OUTAGE"}, nil},
		{model.TypeOperatorNote, model.OperatorNote{Text: "AT&T ticket #123 <urgent>", Source: "web"}, nil},
		{model.TypeClockJump, model.ClockJump{WallDeltaMs: 5000, MonoDeltaMs: 10, JumpMs: 4990}, nil},
		{model.TypeMonitorStop, model.MonitorStop{Reason: "console interrupt", UptimeSec: 60}, nil},
	}
	var refs []model.Ref
	for _, p := range payloads {
		clk.Advance(time.Second)
		refs = append(refs, mustAppend(t, s, p.typ, p.data, p.blobs...))
	}
	bodies := scanAll(t, s)
	if len(bodies) != len(payloads)+1 {
		t.Fatalf("scanned %d records", len(bodies))
	}
	for i, p := range payloads {
		b := bodies[i+1]
		want, _ := marshalJSON(p.data)
		if b.Type != p.typ || b.Seq != uint64(i+1) || b.TS != refs[i].TS || !bytes.Equal(b.Data, want) {
			t.Fatalf("record %d = %+v", i+1, b)
		}
	}
	// Scan from the middle; ErrStop ends early without error.
	var got []uint64
	err = s.Scan(3, func(_ model.Envelope, b model.Body) error {
		got = append(got, b.Seq)
		if b.Seq == 5 {
			return contracts.ErrStop
		}
		return nil
	})
	if err != nil || fmt.Sprint(got) != "[3 4 5]" {
		t.Fatalf("Scan(3) = %v, %v", got, err)
	}
	boom := errors.New("boom")
	if err := s.Scan(0, func(model.Envelope, model.Body) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("callback error not propagated: %v", err)
	}
	rep, err := s.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireOK(t, rep)
	if rep.Records != uint64(len(payloads)+1) || rep.TypeCounts[model.TypeSample] != 1 || rep.TypeCounts[model.TypeGenesis] != 1 ||
		rep.ClockJumps != 1 || rep.BlobsChecked != 1 || rep.Fingerprint != s.Fingerprint() ||
		rep.FirstTS != t0.Format(time.RFC3339Nano) || rep.LastTS != refs[len(refs)-1].TS ||
		rep.HeadHash != refs[len(refs)-1].Hash || len(rep.Segments) != 1 || rep.UnanchoredTail != rep.Records {
		t.Fatalf("report %+v", rep)
	}
	if rep.At == "" || rep.Failures == nil || rep.Gaps == nil || rep.Anchors == nil {
		t.Fatalf("report slices must be non-nil: %+v", rep)
	}
}

func TestRecordAndSegments(t *testing.T) {
	s, _, clk := newLedger(t)
	// Three days of records.
	appendSamples(t, s, clk, 3, 10*time.Second)
	clk.Advance(24 * time.Hour)
	appendSamples(t, s, clk, 3, 10*time.Second)
	clk.Advance(24 * time.Hour)
	appendSamples(t, s, clk, 3, 10*time.Second)
	head := s.Head()
	if head.Seq != 11 { // genesis + 3 + (segment_open + 3) + (segment_open + 3)
		t.Fatalf("head seq %d", head.Seq)
	}
	for seq := uint64(0); seq <= head.Seq; seq++ {
		env, b, err := s.Record(seq)
		if err != nil || b.Seq != seq || sha256Hex([]byte(env.B)) != env.H {
			t.Fatalf("Record(%d) = %+v, %v", seq, b, err)
		}
	}
	if _, _, err := s.Record(head.Seq + 1); !errors.Is(err, contracts.ErrNotFound) {
		t.Fatalf("Record beyond head: %v", err)
	}
	segs, err := s.Segments()
	if err != nil {
		t.Fatal(err)
	}
	want := []contracts.SegmentInfo{
		{Name: segName(t0), FirstSeq: 0, LastSeq: 3, Records: 4},
		{Name: segName(t0.Add(24 * time.Hour)), FirstSeq: 4, LastSeq: 7, Records: 4},
		{Name: segName(t0.Add(48 * time.Hour)), FirstSeq: 8, LastSeq: 11, Records: 4, Active: true},
	}
	if len(segs) != len(want) {
		t.Fatalf("segments %+v", segs)
	}
	for i, w := range want {
		g := segs[i]
		if g.Name != w.Name || g.FirstSeq != w.FirstSeq || g.LastSeq != w.LastSeq || g.Records != w.Records ||
			g.Active != w.Active || g.Compressed || !filepath.IsAbs(g.Path) || !g.Date.Equal(utcDate(t0.Add(time.Duration(i)*24*time.Hour))) {
			t.Fatalf("segment %d = %+v, want %+v", i, g, w)
		}
	}
	// OpenSegment returns the exact bytes; names may carry the extension; unknown → ErrNotFound.
	for _, name := range []string{segs[1].Name, segs[1].Name + ".jsonl"} {
		rc, err := s.OpenSegment(name)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		disk, _ := os.ReadFile(segs[1].Path)
		if !bytes.Equal(b, disk) {
			t.Fatalf("OpenSegment(%s) differs from disk", name)
		}
	}
	for _, name := range []string{"ledger-2020-01-01", "../etc/passwd", "ledger-2026-13-01", ""} {
		if _, err := s.OpenSegment(name); !errors.Is(err, contracts.ErrNotFound) {
			t.Fatalf("OpenSegment(%q) = %v", name, err)
		}
	}
}

func TestScanTime(t *testing.T) {
	s, _, clk := newLedger(t)
	start := clk.Now()
	// Hourly from 04:20 on 10-05 to 09:20 on 10-06: rotation at refs[20] (00:20).
	refs := appendSamples(t, s, clk, 30, time.Hour)
	at := func(i int) time.Time { tm, _ := time.Parse(time.RFC3339Nano, refs[i].TS); return tm }
	if segs, _ := s.Segments(); len(segs) != 2 {
		t.Fatalf("expected 2 segments, got %d", len(segs))
	}
	cases := []struct {
		name     string
		from, to time.Time
		want     int
	}{
		{"everything", start, at(29).Add(time.Nanosecond), 32}, // genesis + 30 + segment_open
		{"half-open end excluded", at(0), at(5), 5},
		{"single record", at(7), at(7).Add(time.Nanosecond), 1},
		{"across midnight", at(18), at(21), 4}, // 18, 19, segment_open, 20
		{"second day only", utcDate(at(29)), at(29).Add(time.Hour), 11},
		{"before the ledger", start.Add(-48 * time.Hour), start, 0},
		{"after the ledger", at(29).Add(time.Hour), at(29).Add(48 * time.Hour), 0},
		{"empty range", at(5), at(5), 0},
		{"inverted range", at(6), at(5), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var n int
			var prev uint64
			err := s.ScanTime(tc.from, tc.to, func(_ model.Envelope, b model.Body) error {
				ts, _ := time.Parse(time.RFC3339Nano, b.TS)
				if ts.Before(tc.from) || !ts.Before(tc.to) {
					t.Errorf("record %d ts %s outside range", b.Seq, b.TS)
				}
				if n > 0 && b.Seq <= prev {
					t.Errorf("not ascending: %d after %d", b.Seq, prev)
				}
				prev = b.Seq
				n++
				return nil
			})
			if err != nil || n != tc.want {
				t.Fatalf("ScanTime = %d records, %v; want %d", n, err, tc.want)
			}
		})
	}
	n := 0
	if err := s.ScanTime(start, at(29).Add(time.Second), func(model.Envelope, model.Body) error {
		n++
		return contracts.ErrStop
	}); err != nil || n != 1 {
		t.Fatalf("ErrStop: n=%d err=%v", n, err)
	}
}

func TestConcurrentAppends(t *testing.T) {
	s, _, clk := newLedger(t)
	const goroutines, each = 50, 20
	var wg sync.WaitGroup
	errs := make(chan error, goroutines*each)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				clk.Advance(time.Millisecond)
				if _, err := s.Append(model.TypeSample, samplePayload(uint64(g*1000+i))); err != nil {
					errs <- err
				}
				if i%5 == 0 {
					_ = s.Head()
					_ = s.HasBlob(strings.Repeat("0", 64))
				}
			}
		}(g)
	}
	// Readers run concurrently with the writers.
	var rwg sync.WaitGroup
	stop := make(chan struct{})
	rwg.Add(1)
	go func() {
		defer rwg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = s.Scan(0, func(model.Envelope, model.Body) error { return nil })
			_, _ = s.Segments()
		}
	}()
	wg.Wait()
	close(stop)
	rwg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if s.Head().Seq != goroutines*each {
		t.Fatalf("head seq %d", s.Head().Seq)
	}
	bodies := scanAll(t, s)
	for i, b := range bodies {
		if b.Seq != uint64(i) {
			t.Fatalf("record %d has seq %d", i, b.Seq)
		}
	}
	rep, err := s.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireOK(t, rep)
	if rep.Records != goroutines*each+1 {
		t.Fatalf("records %d", rep.Records)
	}
}

func TestReadOnlyWhileWriterActive(t *testing.T) {
	w, dir, clk := newLedger(t)
	appendSamples(t, w, clk, 5, 10*time.Second)
	opts := testOptions(dir, clk)
	opts.ReadOnly = true
	opts.KeyUnprotect = func([]byte) ([]byte, error) {
		t.Error("read-only store must not decrypt the key")
		return nil, errors.New("no")
	}
	ro := openStore(t, opts)
	if ro.Created() {
		t.Fatal("read-only Created")
	}
	if ro.Head() != w.Head() || ro.Fingerprint() != w.Fingerprint() || ro.GenesisTS() != w.GenesisTS() {
		t.Fatalf("ro head %+v fp %s; writer %+v %s", ro.Head(), ro.Fingerprint(), w.Head(), w.Fingerprint())
	}
	if !bytes.Equal(ro.PublicKey(), w.PublicKey()) {
		t.Fatal("public key differs")
	}
	if len(scanAll(t, ro)) != 6 {
		t.Fatal("read-only scan")
	}
	// Writes are refused.
	if _, err := ro.Append(model.TypeOperatorNote, "x"); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("Append: %v", err)
	}
	if _, err := ro.PutBlob([]byte("x")); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("PutBlob: %v", err)
	}
	if _, err := ro.CompressSealed(0); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("CompressSealed: %v", err)
	}
	if _, err := ro.ImportBootstrap(dir); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("ImportBootstrap: %v", err)
	}
	// The writer keeps appending; the reader follows.
	last := appendSamples(t, w, clk, 3, 10*time.Second)[2]
	if ro.Head() != last {
		t.Fatalf("ro head %+v, want %+v", ro.Head(), last)
	}
	rep, err := ro.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireOK(t, rep)
	if rep.Records != 9 {
		t.Fatalf("records %d", rep.Records)
	}
	// A record being written (no newline yet) is invisible to readers and noted by Verify.
	w.Close()
	f, err := os.OpenFile(segPath(dir, segName(t0)), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"h":"0000`)
	f.Close()
	if len(scanAll(t, ro)) != 9 || ro.Head() != last {
		t.Fatal("partial line visible to readers")
	}
	rc, _ := ro.OpenSegment(segName(t0))
	b, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.HasSuffix(b, []byte("\n")) {
		t.Fatal("OpenSegment exposes a partial line")
	}
	rep, _ = ro.Verify(context.Background())
	requireOK(t, rep)
	if len(rep.Notes) == 0 || !strings.Contains(strings.Join(rep.Notes, "\n"), "incomplete line") {
		t.Fatalf("notes %v", rep.Notes)
	}
}

func TestSecondWriterRefused(t *testing.T) {
	s, dir, clk := newLedger(t)
	_, err := Open(testOptions(dir, clk))
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("second writer: %v", err)
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("pid %d", os.Getpid())) {
		t.Fatalf("error does not describe the holder: %v", err)
	}
	// The failed attempt changed nothing; after Close a new writer may open.
	appendSamples(t, s, clk, 1, time.Second)
	s.Close()
	s2 := openStore(t, testOptions(dir, clk))
	if s2.Head().Seq != 1 {
		t.Fatalf("head %+v", s2.Head())
	}
}

func TestOpenErrors(t *testing.T) {
	clk := newClock(t0)
	t.Run("missing paths", func(t *testing.T) {
		if _, err := Open(Options{}); err == nil {
			t.Fatal("expected error")
		}
		opts := testOptions(t.TempDir(), clk)
		opts.Paths.Quarantine = ""
		if _, err := Open(opts); err == nil {
			t.Fatal("expected error for writer without quarantine dir")
		}
	})
	t.Run("read-only without ledger", func(t *testing.T) {
		opts := testOptions(t.TempDir(), clk)
		opts.ReadOnly = true
		if _, err := Open(opts); err == nil {
			t.Fatal("expected error")
		}
		os.MkdirAll(opts.Paths.Ledger, 0o755)
		if _, err := Open(opts); !errors.Is(err, contracts.ErrNotFound) {
			t.Fatalf("empty ledger dir: %v", err)
		}
	})
	t.Run("key missing but segments exist", func(t *testing.T) {
		dir := t.TempDir()
		s := openStore(t, testOptions(dir, clk))
		s.Close()
		os.Remove(filepath.Join(dir, "keys", "ledger-signing.key"))
		if _, err := Open(testOptions(dir, clk)); err == nil || !strings.Contains(err.Error(), "signing key") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("key does not match genesis", func(t *testing.T) {
		dir := t.TempDir()
		s := openStore(t, testOptions(dir, clk))
		s.Close()
		// Replace the key with another ledger's key.
		other := t.TempDir()
		o := openStore(t, testOptions(other, clk))
		o.Close()
		kb, _ := os.ReadFile(filepath.Join(other, "keys", "ledger-signing.key"))
		os.WriteFile(filepath.Join(dir, "keys", "ledger-signing.key"), kb, 0o600)
		before, _ := os.ReadFile(segPath(dir, segName(t0)))
		_, err := Open(testOptions(dir, clk))
		if err == nil || !strings.Contains(err.Error(), "does not match the ledger's genesis key") {
			t.Fatalf("err = %v", err)
		}
		after, _ := os.ReadFile(segPath(dir, segName(t0)))
		if !bytes.Equal(before, after) {
			t.Fatal("a refused open modified the ledger")
		}
	})
	t.Run("corrupt key file", func(t *testing.T) {
		dir := t.TempDir()
		s := openStore(t, testOptions(dir, clk))
		s.Close()
		os.WriteFile(filepath.Join(dir, "keys", "ledger-signing.key"), []byte("{not json"), 0o600)
		if _, err := Open(testOptions(dir, clk)); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestKeyRecreatedWithoutLedgerIsDisclosed(t *testing.T) {
	dir := t.TempDir()
	clk := newClock(t0)
	s := openStore(t, testOptions(dir, clk))
	fp := s.Fingerprint()
	s.Close()
	// The ledger directory disappears but the key survives.
	if err := os.RemoveAll(filepath.Join(dir, "ledger")); err != nil {
		t.Fatal(err)
	}
	clk.Advance(time.Hour)
	s2 := openStore(t, testOptions(dir, clk))
	if !s2.Created() || s2.Fingerprint() != fp {
		t.Fatal("expected a new genesis with the existing key")
	}
	bodies := scanAll(t, s2)
	if fmt.Sprint(typesOf(bodies)) != "[genesis integrity_alert]" {
		t.Fatalf("types %v", typesOf(bodies))
	}
	alert := decodeData[model.IntegrityAlert](t, bodies[1])
	if !strings.Contains(strings.Join(alert.Details, " "), "no ledger segment was found") {
		t.Fatalf("alert %+v", alert)
	}
}

func TestFingerprintHelpers(t *testing.T) {
	pub := make([]byte, 32)
	fp := Fingerprint(pub)
	sum := sha256.Sum256(pub)
	if fp != hex.EncodeToString(sum[:]) {
		t.Fatal(fp)
	}
	grouped := FormatFingerprint(fp)
	if len(strings.Fields(grouped)) != 16 || strings.ReplaceAll(grouped, " ", "") != fp {
		t.Fatalf("grouped %q", grouped)
	}
	for _, in := range []string{grouped, strings.ToUpper(fp), strings.ReplaceAll(grouped, " ", ":")} {
		if normalizeFingerprint(in) != fp {
			t.Fatalf("normalize(%q) = %q", in, normalizeFingerprint(in))
		}
	}
	if FormatFingerprint("xyz") != "xyz" {
		t.Fatal("non-fingerprint input must be returned unchanged")
	}
}
