package export

// Syslog chunks in bundles: the exporter copies the chunks of the period that the syslog store
// still keeps (syslog/<name>, exact bytes), VerifySyslogChunks and tools/verify_bundle.py check
// each against its syslog_chunk record and list the chunks of the period that are not in the
// bundle, and the report files stay what the records give.

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// fakeSyslog is a syslog store holding sealed chunk files (contracts.SyslogReader).
type fakeSyslog struct {
	mu     sync.Mutex
	chunks map[string][]byte // name -> the stored gzip bytes
	errs   map[string]error  // OpenChunk fails with these
	opened []string
}

var _ contracts.SyslogReader = (*fakeSyslog)(nil)

func (s *fakeSyslog) Query(context.Context, time.Time, time.Time, func(*model.SyslogMessage) bool, int) ([]model.SyslogEntry, bool, error) {
	return nil, false, errors.New("not used by the exporter")
}

func (s *fakeSyslog) Usage() model.SyslogUsage { return model.SyslogUsage{KeepMB: 100} }

func (s *fakeSyslog) OpenChunk(name string) (io.ReadCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.opened = append(s.opened, name)
	if err := s.errs[name]; err != nil {
		return nil, err
	}
	data, ok := s.chunks[name]
	if !ok {
		return nil, fmt.Errorf("syslog chunk %s: %w", name, contracts.ErrNotFound)
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func gzipBytes(t testing.TB, data []byte, level int) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, level)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// syslogLines renders n messages received every 10 s from `from` as the syslog store keeps
// them: one SyslogMessage JSON object per line.
func syslogLines(t testing.TB, from time.Time, n int, text string) []byte {
	t.Helper()
	var b bytes.Buffer
	for i := 0; i < n; i++ {
		at := from.Add(time.Duration(i) * 10 * time.Second).UTC()
		pri, fac, sev := 30, 3, 6
		raw := fmt.Sprintf("<30>%s bgw320 %s %d <&>", at.Format(time.Stamp), text, i)
		line, err := json.Marshal(model.SyslogMessage{RX: at.Format(time.RFC3339Nano), Src: "192.168.1.254:514", Raw: raw,
			Format: "rfc3164", PRI: &pri, Facility: &fac, Severity: &sev, TS: at.Format(time.Stamp), Host: "bgw320", Msg: text})
		if err != nil {
			t.Fatal(err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// syslogChunkFile returns a sealed chunk as the syslog store writes it (gzip of syslogLines) and
// its syslog_chunk record.
func syslogChunkFile(t testing.TB, name string, from time.Time, n int) (model.SyslogChunk, []byte) {
	t.Helper()
	content := syslogLines(t, from, n, "PON link state")
	gz := gzipBytes(t, content, gzip.DefaultCompression)
	sum := sha256.Sum256(content)
	last := from.Add(time.Duration(n-1) * 10 * time.Second)
	return model.SyslogChunk{Name: name, From: from.UTC().Format(time.RFC3339Nano), To: last.UTC().Format(time.RFC3339Nano),
		Messages: n, Bytes: int64(len(content)), SHA256: hex.EncodeToString(sum[:]), GzBytes: int64(len(gz)), Reason: "age"}, gz
}

const (
	chunkA = "syslog-20261005T080000Z.jsonl.gz"
	chunkB = "syslog-20261005T080500Z.jsonl.gz"
	chunkC = "syslog-20261005T081000Z.jsonl.gz"
	chunkE = "syslog-20261005T081500Z.jsonl.gz"
	chunkD = "syslog-20261005T084000Z.jsonl.gz"
)

// syslogScenario is a ledger of 2026-10-05 whose monitor sealed a syslog chunk every 5 minutes,
// with the syslog store holding what it still keeps:
//
//	A 08:00-08:05  deleted by the retention limit (syslog_prune at 08:20:30)
//	B 08:05-08:10  kept
//	C 08:10-08:15  kept
//	E 08:15-08:20  not kept, and no syslog_prune names it
//	D 08:40-08:45  kept, after the period
//
// The period exported is 08:02-08:30: A, B, C and E are its chunks.
type syslogScenario struct {
	f      *fakeLedger
	store  *fakeSyslog
	now    time.Time
	req    contracts.ExportRequest
	chunks map[string]model.SyslogChunk
	seq    map[string]uint64 // the syslog_chunk record of each chunk
}

func buildSyslogScenario(t *testing.T) *syslogScenario {
	t.Helper()
	at := func(h, m int) time.Time { return time.Date(2026, 10, 5, h, m, 0, 0, time.UTC) }
	s := &syslogScenario{f: rvLedger(t, at(8, 0)), store: &fakeSyslog{chunks: map[string][]byte{}}, now: at(9, 0),
		req: contracts.ExportRequest{From: at(8, 2), To: at(8, 30)}, chunks: map[string]model.SyslogChunk{}, seq: map[string]uint64{}}
	samples := func(from time.Time, n int) {
		rvSamples(s.f, from, n, time.Minute, model.StateOnline, "", model.AttrNone, "")
	}
	seal := func(name string, opened time.Time, keep bool) {
		c, gz := syslogChunkFile(t, name, opened.Add(10*time.Second), 29)
		if keep {
			s.store.chunks[name] = gz
		}
		s.chunks[name] = c
		s.seq[name] = s.f.append(opened.Add(5*time.Minute), model.TypeSyslogChunk, c).Seq
	}
	samples(at(8, 1), 4)
	seal(chunkA, at(8, 0), false)
	samples(at(8, 5), 5)
	seal(chunkB, at(8, 5), true)
	samples(at(8, 10), 5)
	seal(chunkC, at(8, 10), true)
	samples(at(8, 15), 5)
	seal(chunkE, at(8, 15), false)
	a := s.chunks[chunkA]
	s.f.append(at(8, 20).Add(30*time.Second), model.TypeSyslogPrune, model.SyslogPrune{Reason: "keep_mb 1", KeepMB: 1,
		Deleted:   []model.SyslogChunkRef{{Name: a.Name, SHA256: a.SHA256, From: a.From, To: a.To, Messages: a.Messages, GzBytes: a.GzBytes}},
		KeptBytes: 3000, KeptChunks: 3})
	samples(at(8, 21), 24)
	seal(chunkD, at(8, 40), true)
	samples(at(8, 45), 5)
	return s
}

// export builds a bundle of the scenario's period with the store (nil: without one).
func (s *syslogScenario) export(t *testing.T, store contracts.SyslogReader, mods ...func(*Options)) contracts.ExportInfo {
	t.Helper()
	e, _ := newTestExporter(t, &scenario{f: s.f, now: s.now}, t.TempDir(), append([]func(*Options){func(o *Options) {
		if store != nil {
			o.Syslog = store
		}
	}}, mods...)...)
	info, err := e.Build(context.Background(), s.req)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	mustVerifyReport(t, info.Path)
	return info
}

func syslogEntries(z zipContent) []string {
	var out []string
	for _, n := range z.names {
		if strings.HasPrefix(n, syslogDir) {
			out = append(out, n)
		}
	}
	return out
}

func TestSyslogChunksInBundle(t *testing.T) {
	s := buildSyslogScenario(t)
	info := s.export(t, s.store)
	z := readZip(t, info.Path)

	// The kept chunks of the period, exact bytes, in ledger order; not the pruned (A), the
	// unavailable (E) or the later one (D).
	if got, want := strings.Join(syslogEntries(z), " "), syslogDir+chunkB+" "+syslogDir+chunkC; got != want {
		t.Fatalf("syslog entries = %s, want %s", got, want)
	}
	for _, name := range []string{chunkB, chunkC} {
		if !bytes.Equal(z.files[syslogDir+name], s.store.chunks[name]) {
			t.Errorf("%s is not the stored chunk", name)
		}
		if !strings.Contains(string(z.files[manifestName]), sha256Hex(s.store.chunks[name])+"  "+syslogDir+name+"\n") {
			t.Errorf("MANIFEST.sha256 does not list %s", name)
		}
	}
	if got := strings.Join(s.store.opened, " "); got != chunkA+" "+chunkB+" "+chunkC+" "+chunkE {
		t.Errorf("chunks read from the store: %s", got)
	}
	if err := VerifyManifest(info.Path); err != nil {
		t.Errorf("VerifyManifest: %v", err)
	}
	// The chunks are not extra files: the report does not mention them.
	if r := readReportJSON(t, z); len(r.Bundle.ExtraFiles) != 0 {
		t.Errorf("extra files %+v", r.Bundle.ExtraFiles)
	}

	chk, err := VerifySyslogChunks(info.Path)
	if err != nil {
		t.Fatalf("VerifySyslogChunks: %v", err)
	}
	if chk.Records != 5 || chk.OfPeriod != 4 || chk.Files != 2 || chk.Verified != 2 || !chk.OK() ||
		fmt.Sprint(chk.Pruned) != "["+chunkA+"]" || fmt.Sprint(chk.Absent) != "["+chunkE+"]" || len(chk.Notes) != 0 {
		t.Errorf("check = %+v", chk)
	}
	want := "2 chunk files, each matching the SHA-256, size and message count its syslog_chunk record states; of the 4 chunks of the period, " +
		"1 deleted by the retention limit according to a syslog_prune record and 1 not in the bundle for another reason: deleted after the " +
		"records of this bundle, or unreadable at export"
	if got := chk.Summary(); got != want {
		t.Errorf("Summary = %q\nwant      %q", got, want)
	}

	t.Run("python", func(t *testing.T) {
		py := findPython(t)
		out, code := runPython(t, py, shippedScript(t, info.Path), "--openssl-limit", "0", info.Path)
		if code != 0 || !strings.Contains(out, "RESULT: PASS") {
			t.Fatalf("exit %d:\n%s", code, out)
		}
		for _, want := range []string{
			pyLine("Syslog chunks", "OK (2 chunk file(s), each matching its syslog_chunk record: SHA-256, size and message count); "+
				"of the 4 chunk(s) of the period, 1 deleted by the retention limit and 1 not in the bundle (see the notes)"),
			fmt.Sprintf("1 syslog chunk(s) of the period are not in this bundle because the syslog store's retention limit deleted them "+
				"(a syslog_prune record names them; their SHA-256 stays in their syslog_chunk records): %s (syslog_chunk seq %d)", chunkA, s.seq[chunkA]),
			fmt.Sprintf("records): %s (syslog_chunk seq %d)", chunkE, s.seq[chunkE]),
		} {
			if !strings.Contains(out, want) {
				t.Errorf("output lacks %q:\n%s", want, out)
			}
		}
		// An extracted bundle verifies the same way.
		if out, code := runPython(t, py, shippedScript(t, info.Path), "--openssl-limit", "0", extractZip(t, info.Path)); code != 0 ||
			!strings.Contains(out, pyLine("Syslog chunks", "OK (2 chunk file(s)")) {
			t.Errorf("extracted folder: exit %d:\n%s", code, out)
		}
	})
}

// The report files are a function of the records: the chunks must not change them.
func TestSyslogChunksLeaveReportUnchanged(t *testing.T) {
	s := buildSyslogScenario(t)
	without := readZip(t, s.export(t, nil).Path)
	with := readZip(t, s.export(t, s.store).Path)
	for _, name := range reportFiles {
		if !bytes.Equal(without.files[name], with.files[name]) {
			t.Errorf("%s differs when the bundle includes syslog chunks", name)
		}
	}
	if len(syslogEntries(without)) != 0 || len(syslogEntries(with)) != 2 {
		t.Fatalf("syslog entries %v / %v", syslogEntries(without), syslogEntries(with))
	}
	// Otherwise the bundles hold the same files.
	for _, n := range with.names {
		if _, ok := without.files[n]; !ok && !strings.HasPrefix(n, syslogDir) {
			t.Errorf("%s only in the bundle with chunks", n)
		}
		if n != manifestName && !strings.HasPrefix(n, syslogDir) && !bytes.Equal(with.files[n], without.files[n]) {
			t.Errorf("%s differs", n)
		}
	}
}

// Without a syslog store (or for a bundle of an earlier version) every chunk of the period is
// reported as not in the bundle - or as pruned - and nothing fails.
func TestSyslogChunksWithoutStore(t *testing.T) {
	s := buildSyslogScenario(t)
	info := s.export(t, nil)
	chk, err := VerifySyslogChunks(info.Path)
	if err != nil {
		t.Fatalf("VerifySyslogChunks: %v", err)
	}
	if chk.Files != 0 || chk.OfPeriod != 4 || fmt.Sprint(chk.Pruned) != "["+chunkA+"]" ||
		fmt.Sprint(chk.Absent) != fmt.Sprint([]string{chunkB, chunkC, chunkE}) {
		t.Errorf("check = %+v", chk)
	}
	if got := chk.Summary(); !strings.HasPrefix(got, "no chunk files in this bundle; of the 4 chunks of the period, 1 deleted by the "+
		"retention limit according to a syslog_prune record and 3 not in the bundle") {
		t.Errorf("Summary = %q", got)
	}

	// A bundle without syslog records at all.
	_, plain := buildIncidentBundle(t)
	chk, err = VerifySyslogChunks(plain.Path)
	if err != nil || chk.Records != 0 || chk.Files != 0 || chk.Summary() != "no syslog chunks in this bundle" {
		t.Errorf("bundle without syslog: %+v, %v", chk, err)
	}
	py := findPython(t)
	out, code := runPython(t, py, shippedScript(t, plain.Path), "--openssl-limit", "0", plain.Path)
	if code != 0 || !strings.Contains(out, pyLine("Syslog chunks", "none in this bundle")) {
		t.Errorf("python, bundle without syslog: exit %d:\n%s", code, out)
	}
	out, code = runPython(t, py, shippedScript(t, info.Path), "--openssl-limit", "0", info.Path)
	if code != 0 || !strings.Contains(out, pyLine("Syslog chunks", "OK (no chunk files in this bundle); of the 4 chunk(s) of the period, "+
		"1 deleted by the retention limit and 3 not in the bundle")) {
		t.Errorf("python, bundle without chunks: exit %d:\n%s", code, out)
	}
}

// A chunk file that is not what its record states, or that no record names, fails both
// verifiers - also when MANIFEST.sha256 was recomputed.
func TestSyslogChunkTampering(t *testing.T) {
	s := buildSyslogScenario(t)
	info := s.export(t, s.store)
	stored := s.store.chunks[chunkB]
	content := syslogLines(t, time.Date(2026, 10, 5, 8, 5, 10, 0, time.UTC), 29, "PON link state")
	// Other messages of the same size and number.
	otherContent := syslogLines(t, time.Date(2026, 10, 5, 8, 5, 10, 0, time.UTC), 29, "PON LINK DOWN!")
	other := gzipBytes(t, otherContent, gzip.DefaultCompression)
	flipped := append([]byte(nil), stored...)
	flipped[len(flipped)/2] ^= 0x55
	seqB := s.seq[chunkB]
	replace := func(name string, data []byte) zipEdit {
		return zipEdit{fixManifest: true, edit: func(n string, d []byte) ([]byte, bool) {
			if n == syslogDir+name {
				return data, true
			}
			return d, true
		}}
	}
	tests := []struct {
		name     string
		edit     zipEdit
		want     string // in the Go error ("" = the bundle verifies)
		wantPy   string // in the Python output
		problems int
	}{
		{"content replaced", replace(chunkB, other), fmt.Sprintf("syslog/%s: it is not what its syslog_chunk record (seq %d) states: its SHA-256 is %s, "+
			"the record states %s", chunkB, seqB, sha256Hex(otherContent), s.chunks[chunkB].SHA256),
			fmt.Sprintf("syslog/%s: it is not what its syslog_chunk record (seq %d) states: its SHA-256 is %s, the record states %s",
				chunkB, seqB, sha256Hex(otherContent), s.chunks[chunkB].SHA256), 1},
		{"bytes changed", replace(chunkB, flipped), "syslog/" + chunkB + ": it is not a valid gzip file", "syslog/" + chunkB + ": it is not a valid gzip file", 1},
		{"truncated", replace(chunkB, stored[:len(stored)-4]), "it is not a valid gzip file", "it ends inside a gzip member", 1},
		{"trailing data", replace(chunkB, append(append([]byte(nil), stored...), make([]byte, 16)...)), "it is not a valid gzip file",
			"syslog/" + chunkB + ": it is not a valid gzip file", 1},
		{"a message removed", replace(chunkB, gzipBytes(t, content[bytes.IndexByte(content, '\n')+1:], gzip.BestSpeed)),
			"it holds 28 messages (lines), the record states 29 messages", "it holds 28 messages (lines), the record states 29", 1},
		{"messages appended", replace(chunkB, gzipBytes(t, append(append([]byte(nil), content...), content...), gzip.BestSpeed)),
			"uncompressed it is larger than the", "uncompressed it is larger than the", 1},
		{"chunk without a record", zipEdit{fixManifest: true, extra: []zipEntry{{syslogDir + "syslog-20261005T082500Z.jsonl.gz", other}}},
			"syslog/syslog-20261005T082500Z.jsonl.gz: no syslog_chunk record in this bundle names it",
			"syslog/syslog-20261005T082500Z.jsonl.gz: no syslog_chunk record in this bundle names it", 1},
		{"file in a subfolder", zipEdit{fixManifest: true, extra: []zipEntry{{syslogDir + "x/" + chunkB, stored}}},
			"syslog/x/" + chunkB + ": no syslog_chunk record", "syslog/x/" + chunkB + ": no syslog_chunk record", 1},
		{"two chunks replaced", zipEdit{fixManifest: true, edit: func(n string, d []byte) ([]byte, bool) {
			if strings.HasPrefix(n, syslogDir) {
				return other, true
			}
			return d, true
		}}, "(and 1 more problem)", "FAILED (2 of 2 chunk file(s)", 2},
		// The content is the evidence: the same messages compressed differently still match.
		{"recompressed", replace(chunkB, gzipBytes(t, content, gzip.BestSpeed)), "", pyLine("Syslog chunks", "OK (2 chunk file(s)"), 0},
		{"two gzip members", replace(chunkB, append(gzipBytes(t, content[:100], gzip.BestSpeed), gzipBytes(t, content[100:], gzip.NoCompression)...)),
			"", pyLine("Syslog chunks", "OK (2 chunk file(s)"), 0},
	}
	py := findPython(t)
	script := shippedScript(t, info.Path)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := rewriteZip(t, info.Path, tc.edit)
			if err := VerifyManifest(path); err != nil {
				t.Errorf("VerifyManifest after recomputing the manifest: %v", err)
			}
			chk, err := VerifySyslogChunks(path)
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("VerifySyslogChunks: %v", err)
			case tc.want != "" && (!errors.Is(err, ErrSyslogMismatch) || !strings.Contains(err.Error(), tc.want)):
				t.Errorf("err = %v\nwant ErrSyslogMismatch with %q", err, tc.want)
			}
			if chk == nil || len(chk.Problems) != tc.problems || chk.OK() != (tc.problems == 0) {
				t.Errorf("check = %+v", chk)
			}
			out, code := runPython(t, py, script, "--openssl-limit", "0", path)
			wantCode := 1
			if tc.want == "" {
				wantCode = 0
			}
			if code != wantCode || !strings.Contains(out, tc.wantPy) {
				t.Errorf("python: exit %d, want %d with %q:\n%s", code, wantCode, tc.wantPy, out)
			}
		})
	}
}

// The store's failures do not stop an export: a chunk it cannot read is left out (and reported
// as not in the bundle), a chunk that no longer matches its record is exported as stored (and
// fails verification), and both are logged.
func TestSyslogChunkStoreProblems(t *testing.T) {
	s := buildSyslogScenario(t)
	damaged := gzipBytes(t, []byte("{\"rx\":\"2026-10-05T08:10:10Z\"}\n"), gzip.BestSpeed)
	store := &fakeSyslog{chunks: map[string][]byte{chunkB: s.store.chunks[chunkB], chunkC: damaged},
		errs: map[string]error{chunkB: errors.New("sharing violation")}}
	var logs syncBuffer
	info := s.export(t, store, func(o *Options) { o.Logger = slog.New(slog.NewTextHandler(&logs, nil)) })
	if got := syslogEntries(readZip(t, info.Path)); fmt.Sprint(got) != "["+syslogDir+chunkC+"]" {
		t.Fatalf("syslog entries = %v", got)
	}
	for _, want := range []string{"syslog chunk left out of the bundle: it cannot be read", "sharing violation",
		"syslog chunk does not match its syslog_chunk record", "syslog_chunks=1"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("log lacks %q:\n%s", want, logs.String())
		}
	}
	chk, err := VerifySyslogChunks(info.Path)
	if !errors.Is(err, ErrSyslogMismatch) || !strings.Contains(err.Error(), "syslog/"+chunkC+": it is not what its syslog_chunk record") ||
		fmt.Sprint(chk.Absent) != fmt.Sprint([]string{chunkB, chunkE}) {
		t.Errorf("check %+v, err %v", chk, err)
	}
}

// syncBuffer is a bytes.Buffer safe for concurrent writers (a log handler's output).
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// Records that name the same chunk put it into the bundle once; records that cannot be used
// (an unsafe name, no SHA-256) put nothing into it and are noted by the verifiers.
func TestSyslogChunkRecordsDuplicateAndUnusable(t *testing.T) {
	s := buildSyslogScenario(t)
	b := s.chunks[chunkB]
	s.f.append(s.now.Add(-5*time.Minute), model.TypeSyslogChunk, b) // recorded twice
	bad := b
	bad.Name = "../" + chunkB
	s.f.append(s.now.Add(-4*time.Minute), model.TypeSyslogChunk, bad)
	noSum := s.chunks[chunkC]
	noSum.Name, noSum.SHA256 = "syslog-nosum.jsonl.gz", ""
	s.f.append(s.now.Add(-3*time.Minute), model.TypeSyslogChunk, noSum)
	s.store.chunks["syslog-nosum.jsonl.gz"] = s.store.chunks[chunkC]
	// A syslog_prune record that cannot be read, and one naming chunk E with another SHA-256 (an
	// earlier chunk of that name): E is still not known to be deleted.
	s.f.append(s.now.Add(-2*time.Minute), model.TypeSyslogPrune, map[string]any{"reason": "keep_mb 1", "deleted": "everything"})
	s.f.append(s.now.Add(-time.Minute), model.TypeSyslogPrune, model.SyslogPrune{Reason: "keep_mb 1", KeepMB: 1,
		Deleted: []model.SyslogChunkRef{{Name: chunkE, SHA256: strings.Repeat("0", 64)}}})
	info := s.export(t, s.store)
	if got := syslogEntries(readZip(t, info.Path)); fmt.Sprint(got) != fmt.Sprint([]string{syslogDir + chunkB, syslogDir + chunkC}) {
		t.Fatalf("syslog entries = %v", got)
	}
	chk, err := VerifySyslogChunks(info.Path)
	notes := strings.Join(chk.Notes, "\n")
	if err != nil || chk.Files != 2 || chk.Verified != 2 || chk.Records != 6 || len(chk.Notes) != 3 ||
		!strings.Contains(notes, `its chunk name "../`+chunkB+`" is not a plain file name`) ||
		!strings.Contains(notes, `its sha256 "" is not a SHA-256`) || !strings.Contains(notes, "syslog_prune record seq") ||
		fmt.Sprint(chk.Pruned) != "["+chunkA+"]" || fmt.Sprint(chk.Absent) != "["+chunkE+"]" {
		t.Errorf("check %+v, err %v", chk, err)
	}
	py := findPython(t)
	out, code := runPython(t, py, shippedScript(t, info.Path), "--openssl-limit", "0", info.Path)
	if code != 0 || !strings.Contains(out, "the syslog_chunk record cannot be used: its chunk name '../"+chunkB+"' is not a plain file name") ||
		!strings.Contains(out, "the syslog_chunk record cannot be used: its sha256 '' is not a SHA-256") ||
		!strings.Contains(out, "the syslog_prune record cannot be used") ||
		!strings.Contains(out, "of the 5 chunk(s) of the period, 1 deleted by the retention limit and 1 not in the bundle") {
		t.Errorf("python: exit %d:\n%s", code, out)
	}
}

// Without a usable period in report.json every chunk record counts as one of the period.
func TestSyslogChunksPeriodNotStated(t *testing.T) {
	s := buildSyslogScenario(t)
	info := s.export(t, s.store)
	r := readReportJSON(t, readZip(t, info.Path))
	path := forgeZip(t, info.Path, map[string][2]string{"report.json": {`"from": "` + r.Period.From + `"`, `"from": "unknown"`}})
	chk, err := VerifySyslogChunks(path)
	if err != nil || chk.OfPeriod != 5 || fmt.Sprint(chk.Absent) != "["+chunkE+" "+chunkD+"]" || len(chk.Notes) != 1 ||
		!strings.Contains(chk.Notes[0], "report.json states no usable period") {
		t.Errorf("check %+v, err %v", chk, err)
	}
	py := findPython(t)
	out, _ := runPython(t, py, shippedScript(t, path), "--openssl-limit", "0", path)
	if !strings.Contains(out, "report.json states no usable period") ||
		!strings.Contains(out, "of the 5 chunk(s) of the period, 1 deleted by the retention limit and 2 not in the bundle") {
		t.Errorf("python:\n%s", out)
	}
}

func TestSyslogChunkOverlap(t *testing.T) {
	at := func(m int) string { return time.Date(2026, 10, 5, 8, m, 0, 0, time.UTC).Format(time.RFC3339Nano) }
	from, to := time.Date(2026, 10, 5, 8, 10, 0, 0, time.UTC), time.Date(2026, 10, 5, 8, 20, 0, 0, time.UTC)
	for _, tc := range []struct {
		from, to string
		want     bool
	}{
		{at(0), at(5), false}, {at(0), at(10), true}, {at(5), at(15), true}, {at(12), at(14), true}, {at(15), at(25), true},
		{at(19), at(19), true}, {at(20), at(25), false}, {at(0), at(30), true}, {"", at(15), false}, {at(12), "garbage", false},
	} {
		raw, _ := json.Marshal(model.SyslogChunk{Name: "c.jsonl.gz", From: tc.from, To: tc.to, SHA256: strings.Repeat("a", 64)})
		r, err := parseSyslogChunk(model.Body{Seq: 1, Type: model.TypeSyslogChunk, Data: raw})
		if err != nil {
			t.Fatal(err)
		}
		if got := r.overlaps(from, to); got != tc.want {
			t.Errorf("chunk %s .. %s overlaps 08:10-08:20: %v, want %v", tc.from, tc.to, got, tc.want)
		}
	}
}

func TestExtraFilesNotInSyslogFolder(t *testing.T) {
	for _, p := range []string{"syslog/x.jsonl.gz", "Syslog/x", "syslog"} {
		if _, err := checkExtraFiles(map[string][]byte{p: []byte("x")}); !errors.Is(err, ErrInvalidExtraFile) {
			t.Errorf("extra file %q accepted: %v", p, err)
		}
	}
}

// pyChunkChecks runs verify_bundle's chunk name, record and gzip checks on the cases in the
// JSON file argv[2] and prints the outcomes as JSON.
const pyChunkChecks = `
import json, sys
sys.path.insert(0, sys.argv[1])
import verify_bundle as v

with open(sys.argv[2], encoding="utf-8") as fh:
    cases = json.load(fh)
out = {"names": [v.chunk_name_ok(n) for n in cases["names"]], "records": [], "gzip": []}
for raw in cases["records"]:
    rec, why = v.chunk_record(json.loads(raw))
    out["records"].append(rec is not None)
for c in cases["gzip"]:
    with open(c["path"], "rb") as fh:
        try:
            sha, size, lines = v.gunzip_digest(fh, c["limit"])
            out["gzip"].append({"ok": True, "sha256": sha, "bytes": size, "lines": lines})
        except v.ChunkTooLarge:
            out["gzip"].append({"too_large": True})
        except ValueError as e:
            out["gzip"].append({"error": str(e)})
print(json.dumps(out))
`

// The Python verifier accepts exactly the chunk names, records and chunk files the Go verifier
// accepts, and digests them alike.
func TestPythonChunkChecksMatchGo(t *testing.T) {
	py := findPython(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "verify_bundle.py"), verifyScript, 0o644); err != nil {
		t.Fatal(err)
	}
	names := []string{"syslog-20261005T080000Z.jsonl.gz", "a", "a-", "a_b.c", "COM10", "AUX1", strings.Repeat("a", 200),
		"", ".hidden", "-a", "a/b", "a..b", "a.", "CON", "con.jsonl.gz", "COM1.gz", "lpt9.x", "nul", "a b", "ä", "a\n", "a\\b", "a:b",
		strings.Repeat("a", 201)}

	sum := strings.Repeat("ab", 32)
	records := []string{
		`{"name":"c.jsonl.gz","from":"2026-10-05T08:00:00Z","to":"2026-10-05T08:05:00Z","messages":2,"bytes":10,"sha256":"` + sum + `","gz_bytes":30,"reason":"age"}`,
		`{"name":"c.jsonl.gz","messages":2,"bytes":10,"sha256":"` + strings.ToUpper(sum) + `"}`,
		`{"name":"c.jsonl.gz","sha256":"` + sum + `","messages":null,"bytes":null,"from":null,"extra":[1,2]}`,
		`{"name":"c.jsonl.gz","sha256":"` + sum + `","from":"garbage"}`,
		`{"name":"c.jsonl.gz","bytes":10}`,
		`{"name":"c.jsonl.gz","sha256":"` + sum[:63] + `"}`,
		`{"name":"c.jsonl.gz","sha256":"` + sum + `","bytes":-1}`,
		`{"name":"c.jsonl.gz","sha256":"` + sum + `","messages":-1}`,
		`{"name":"c.jsonl.gz","sha256":"` + sum + `","bytes":"10"}`,
		`{"name":"c.jsonl.gz","sha256":"` + sum + `","bytes":10.5}`,
		`{"name":"c.jsonl.gz","sha256":"` + sum + `","bytes":10.0}`,
		`{"name":"c.jsonl.gz","sha256":"` + sum + `","bytes":1e3}`,
		`{"name":"c.jsonl.gz","sha256":"` + sum + `","bytes":100000000000000000000}`,
		`{"name":"c.jsonl.gz","sha256":"` + sum + `","bytes":true}`,
		`{"name":"c.jsonl.gz","sha256":"` + sum + `","dropped":1.5}`,
		`{"name":"c.jsonl.gz","sha256":"` + sum + `","from":5}`,
		`{"name":5,"sha256":"` + sum + `"}`,
		`{"name":"a/c.jsonl.gz","sha256":"` + sum + `"}`,
		`{"name":"","sha256":"` + sum + `"}`,
		`null`, `"text"`, `[]`, `{}`,
	}

	type gzCase struct {
		name  string
		data  []byte
		limit int64
	}
	content := syslogLines(t, time.Date(2026, 10, 5, 8, 0, 0, 0, time.UTC), 40, "PON link state")
	single := gzipBytes(t, content, gzip.DefaultCompression)
	rng := rand.New(rand.NewSource(1))
	noise := make([]byte, 300<<10)
	rng.Read(noise)
	same := bytes.Repeat([]byte("{\"rx\":\"2026-10-05T08:00:00Z\",\"raw\":\"the same line\"}\n"), 100000)
	var named bytes.Buffer
	zw := gzip.NewWriter(&named)
	zw.Name, zw.Comment, zw.Extra, zw.ModTime = "chunk.jsonl", "sealed", []byte("xx"), time.Date(2026, 10, 5, 8, 0, 0, 0, time.UTC)
	zw.Write(content)
	zw.Close()
	var zl bytes.Buffer
	zlw := zlib.NewWriter(&zl)
	zlw.Write(content)
	zlw.Close()
	badCRC := append([]byte(nil), single...)
	badCRC[len(badCRC)-8] ^= 1
	badSize := append([]byte(nil), single...)
	badSize[len(badSize)-1] ^= 1
	big := int64(maxChunkContentBytes)
	cases := []gzCase{
		{"single member", single, big},
		{"two members", append(gzipBytes(t, content[:500], gzip.BestSpeed), gzipBytes(t, content[500:], gzip.BestCompression)...), big},
		{"empty content", gzipBytes(t, nil, gzip.DefaultCompression), big},
		{"empty content, limit 0", gzipBytes(t, nil, gzip.DefaultCompression), 0},
		{"incompressible", gzipBytes(t, noise, gzip.DefaultCompression), big},
		{"stored blocks", gzipBytes(t, noise, gzip.NoCompression), big},
		{"highly compressible", gzipBytes(t, same, gzip.BestCompression), big},
		{"header fields", named.Bytes(), big},
		{"content at the limit", single, int64(len(content))},
		{"content over the limit", single, int64(len(content)) - 1},
		{"bomb", gzipBytes(t, make([]byte, 40<<20), gzip.BestCompression), 1 << 20},
		{"trailing zeros", append(append([]byte(nil), single...), make([]byte, 8)...), big},
		{"trailing garbage", append(append([]byte(nil), single...), []byte("garbage after the member")...), big},
		{"partial second header", append(append([]byte(nil), single...), 0x1f, 0x8b), big},
		{"truncated trailer", single[:len(single)-3], big},
		{"truncated deflate", single[:len(single)/2], big},
		{"bad CRC", badCRC, big},
		{"bad size", badSize, big},
		{"empty file", nil, big},
		{"not gzip", []byte("plain text\n"), big},
		{"zlib", zl.Bytes(), big},
	}
	var spec struct {
		Names   []string `json:"names"`
		Records []string `json:"records"`
		Gzip    []struct {
			Path  string `json:"path"`
			Limit int64  `json:"limit"`
		} `json:"gzip"`
	}
	spec.Names, spec.Records = names, records
	for i, c := range cases {
		p := filepath.Join(dir, fmt.Sprintf("case%d.gz", i))
		if err := os.WriteFile(p, c.data, 0o644); err != nil {
			t.Fatal(err)
		}
		spec.Gzip = append(spec.Gzip, struct {
			Path  string `json:"path"`
			Limit int64  `json:"limit"`
		}{p, c.limit})
	}
	specJSON, _ := json.Marshal(spec)
	specPath := filepath.Join(dir, "cases.json")
	if err := os.WriteFile(specPath, specJSON, 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := runPython(t, py, "-c", pyChunkChecks, dir, specPath)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	var res struct {
		Names   []bool `json:"names"`
		Records []bool `json:"records"`
		Gzip    []struct {
			OK       bool   `json:"ok"`
			SHA256   string `json:"sha256"`
			Bytes    int64  `json:"bytes"`
			Lines    int    `json:"lines"`
			TooLarge bool   `json:"too_large"`
			Error    string `json:"error"`
		} `json:"gzip"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("%v:\n%s", err, out)
	}

	for i, n := range names {
		if goOK := checkChunkName(n) == nil; goOK != res.Names[i] {
			t.Errorf("name %q: Go accepts %v, Python %v", n, goOK, res.Names[i])
		}
	}
	for i, raw := range records {
		_, err := parseSyslogChunk(model.Body{Seq: 7, Type: model.TypeSyslogChunk, Data: json.RawMessage(raw)})
		if goOK := err == nil; goOK != res.Records[i] {
			t.Errorf("record %s: Go usable %v (%v), Python %v", raw, goOK, err, res.Records[i])
		}
	}
	accepted := 0
	for i, c := range cases {
		d, err := digestChunk(bytes.NewReader(c.data), c.limit)
		p := res.Gzip[i]
		switch {
		case err == nil && !p.OK:
			t.Errorf("%s: Go accepts it, Python: %+v", c.name, p)
		case errors.Is(err, errChunkTooLarge) != p.TooLarge:
			t.Errorf("%s: Go %v, Python too large %v", c.name, err, p.TooLarge)
		case err != nil && p.OK:
			t.Errorf("%s: Go: %v, Python accepts it", c.name, err)
		case err == nil && (d.sha256 != p.SHA256 || d.bytes != p.Bytes || d.lines != p.Lines):
			t.Errorf("%s: Go %+v, Python %+v", c.name, d, p)
		case err == nil:
			accepted++
		}
	}
	if accepted != 9 {
		t.Errorf("%d gzip cases accepted, want 9", accepted)
	}
	if res.Gzip[0].Bytes != int64(len(content)) || res.Gzip[0].Lines != 40 || res.Gzip[0].SHA256 != sha256Hex(content) {
		t.Errorf("single member digested as %+v", res.Gzip[0])
	}
}
