package ledger

// The verification cache (verifycache.go) reuses Ed25519 outcomes of segments whose exact bytes were
// verified before. These tests prove that Store.Verify with the cache reports exactly what a full
// verification reports — the same function with the same options and clock, without the cache —
// on an intact ledger, after every kind of tampering (also of older and compressed segments, also
// when the files keep their size and modification time), across random damage, on the writer while
// it appends and rotates, and concurrently.

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// verifyUncached is Store.Verify without the verification cache: the oracle.
func verifyUncached(t *testing.T, s *Store) model.VerifyReport {
	t.Helper()
	rep, err := verifyReader(context.Background(), s, s.verifyOptions(), s.now)
	if err != nil {
		t.Fatalf("verification without the cache: %v", err)
	}
	return rep
}

func verifyCached(t *testing.T, s *Store) model.VerifyReport {
	t.Helper()
	rep, err := s.Verify(context.Background())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return rep
}

// cacheEntries returns a copy of the store's verification cache entries.
func cacheEntries(s *Store) map[string]*sigEntry {
	s.sigs.mu.Lock()
	defer s.sigs.mu.Unlock()
	return maps.Clone(s.sigs.entries)
}

// requireSameReport fails unless the cached report is identical to the full one.
func requireSameReport(t *testing.T, what string, cached, full model.VerifyReport) {
	t.Helper()
	if reflect.DeepEqual(cached, full) {
		return
	}
	cj, _ := json.MarshalIndent(cached, "", " ")
	fj, _ := json.MarshalIndent(full, "", " ")
	t.Fatalf("%s: the cached verification differs from a full verification\ncached:\n%s\nfull:\n%s", what, cj, fj)
}

// requireCachedEqualsFull verifies s with and without the cache and returns the report.
func requireCachedEqualsFull(t *testing.T, s *Store, what string) model.VerifyReport {
	t.Helper()
	cached := verifyCached(t, s)
	requireSameReport(t, what, cached, verifyUncached(t, s))
	return cached
}

// cacheFixture is a closed four-day ledger with trusted anchors (timeTSA) and a blob-referencing
// record every day, a stop and restart (a monitoring gap) on day 1 and a clock check at the end;
// days 0 and 1 are compressed, day 2 is sealed, day 3 the latest segment.
type cacheFixture struct {
	dir    string
	clk    *fakeClock
	priv   ed25519.PrivateKey
	other  ed25519.PrivateKey // not the ledger's key
	segs   []string
	pages  []string // page blob per day
	tokens []string // anchor token blob per day
}

func newCacheFixture(t *testing.T) *cacheFixture {
	t.Helper()
	dir := t.TempDir()
	clk := newClock(t0)
	opts := testOptions(dir, clk)
	opts.TokenVerifier = timeTSA{}
	s := openStore(t, opts)
	f := &cacheFixture{dir: dir, clk: clk}
	for d := 0; d < 4; d++ {
		if d > 0 {
			clk.Advance(day)
		}
		appendSamples(t, s, clk, 5, 10*time.Second)
		page, err := s.PutBlob([]byte(fmt.Sprintf("<html>broadbandstatistics of day %d</html>", d)))
		if err != nil {
			t.Fatal(err)
		}
		f.pages = append(f.pages, page)
		mustAppend(t, s, model.TypeGatewaySnapshot, map[string]string{"page": page}, page)
		head, gen := s.Head(), clk.Now()
		stampAt(t, s, head, gen, true)
		f.tokens = append(f.tokens, sha256Hex([]byte("TS|"+gen.UTC().Format(time.RFC3339Nano)+"|"+head.Hash)))
		appendSamples(t, s, clk, 4, 10*time.Second)
		if d == 1 {
			mustAppend(t, s, model.TypeMonitorStop, model.MonitorStop{Reason: "service stop"})
			clk.Advance(10 * time.Minute)
			mustAppend(t, s, model.TypeMonitorStart, model.MonitorStart{Mode: "service"})
			appendSamples(t, s, clk, 3, 10*time.Second)
		}
		f.segs = append(f.segs, segName(clk.Now()))
	}
	mustAppend(t, s, model.TypeClockCheck, model.ClockCheck{Results: []model.ClockResult{{Server: "time.windows.com", OK: true, OffsetMs: 12}}})
	if n, err := s.CompressSealed(24 * time.Hour); err != nil || n != 2 {
		t.Fatalf("CompressSealed = %d, %v", n, err)
	}
	f.priv = append(ed25519.PrivateKey(nil), s.priv...)
	_, f.other, _ = ed25519.GenerateKey(nil)
	s.Close()
	return f
}

// reader opens the fixture read-only with the fixture's token verifier.
func (f *cacheFixture) reader(t *testing.T) *Store {
	t.Helper()
	opts := testOptions(f.dir, f.clk)
	opts.ReadOnly = true
	opts.TokenVerifier = timeTSA{}
	return openStore(t, opts)
}

// file returns the path of segment i as it is on disk (.jsonl or .jsonl.gz).
func (f *cacheFixture) file(i int) string {
	p := segPath(f.dir, f.segs[i])
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return p + gzExt
}

func (f *cacheFixture) blobPath(id string) string {
	return filepath.Join(f.dir, "blobs", id[:2], id+gzExt)
}

// edit rewrites the uncompressed content of segment i (a compressed segment is compressed again).
// keepTime restores the file's modification time afterwards.
func (f *cacheFixture) edit(t *testing.T, i int, keepTime bool, change func([]byte) []byte) {
	t.Helper()
	path := f.file(i)
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	gzFile := strings.HasSuffix(path, gzExt)
	var content []byte
	if gzFile {
		content = gunzipFile(t, path)
	} else if content, err = os.ReadFile(path); err != nil {
		t.Fatal(err)
	}
	content = change(bytes.Clone(content))
	if gzFile {
		writeGz(t, path, content)
	} else if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if keepTime {
		if err := os.Chtimes(path, st.ModTime(), st.ModTime()); err != nil {
			t.Fatal(err)
		}
	}
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			return append(out, b)
		}
		out = append(out, b[:i+1])
		b = b[i+1:]
	}
	return out
}

// changeLine applies change to line n (0-based) of a segment's content.
func changeLine(n int, change func(line []byte) []byte) func([]byte) []byte {
	return func(b []byte) []byte {
		lines := splitLines(b)
		lines[n] = change(bytes.Clone(lines[n]))
		return bytes.Join(lines, nil)
	}
}

// otherSignature replaces the signature of a line with a different one of the same length.
func otherSignature(t *testing.T) func([]byte) []byte {
	return func(line []byte) []byte {
		env := mustEnv(t, line)
		sig := []byte(env.S)
		if sig[0] == 'A' {
			sig[0] = 'B'
		} else {
			sig[0] = 'A'
		}
		return bytes.Replace(line, []byte(env.S), sig, 1)
	}
}

// resign re-signs the line's record with key after change alters its body.
func resign(t *testing.T, key ed25519.PrivateKey, change func(*model.Body)) func([]byte) []byte {
	return func(line []byte) []byte {
		_, b := parseLine(t, line)
		change(&b)
		return reencode(t, key, b)
	}
}

func TestVerifyCacheMatchesFullVerificationAfterTampering(t *testing.T) {
	cases := []struct {
		name   string
		tamper func(t *testing.T, f *cacheFixture)
		want   []string // problems the (identical) reports must contain; nil: the ledger still verifies
	}{
		{
			name: "flip a byte inside b in a compressed segment",
			tamper: func(t *testing.T, f *cacheFixture) {
				f.edit(t, 0, false, changeLine(3, func(l []byte) []byte {
					i := bytes.Index(l, []byte("IP_SUCCESS"))
					l[i+1] = 'Q'
					return l
				}))
			},
			want: []string{probHash, probSignature, probPrev, probSegmentHash},
		},
		{
			name:   "edit s in the sealed plain segment, keeping size and modification time",
			tamper: func(t *testing.T, f *cacheFixture) { f.edit(t, 2, true, changeLine(2, otherSignature(t))) },
			want:   []string{probSignature},
		},
		{
			name:   "edit s in a compressed segment, keeping its modification time",
			tamper: func(t *testing.T, f *cacheFixture) { f.edit(t, 1, true, changeLine(4, otherSignature(t))) },
			want:   []string{probSignature},
		},
		{
			name:   "edit s in the latest segment",
			tamper: func(t *testing.T, f *cacheFixture) { f.edit(t, 3, true, changeLine(1, otherSignature(t))) },
			want:   []string{probSignature},
		},
		{
			name: "replace a record by one signed with another key, in a compressed segment",
			tamper: func(t *testing.T, f *cacheFixture) {
				f.edit(t, 1, true, changeLine(2, resign(t, f.other, func(b *model.Body) { b.Data = []byte(`{"cycle":999,"forged":true}`) })))
			},
			want: []string{probSignature, probPrev, probSegmentHash},
		},
		{
			name: "rewrite a record with the ledger key, breaking the chain",
			tamper: func(t *testing.T, f *cacheFixture) {
				f.edit(t, 2, false, changeLine(2, resign(t, f.priv, func(b *model.Body) { b.Data = []byte(`{"cycle":1,"rewritten":true}`) })))
			},
			want: []string{probPrev, probSegmentHash},
		},
		{
			name: "replace the genesis key (every later signature is then foreign)",
			tamper: func(t *testing.T, f *cacheFixture) {
				f.edit(t, 0, true, changeLine(0, resign(t, f.other, func(b *model.Body) {
					var g model.Genesis
					if err := json.Unmarshal(b.Data, &g); err != nil {
						t.Fatal(err)
					}
					pub := f.other.Public().(ed25519.PublicKey)
					g.PublicKey, g.Fingerprint = base64.StdEncoding.EncodeToString(pub), Fingerprint(pub)
					b.Data, _ = marshalJSON(&g)
				})))
			},
			want: []string{probSignature, probPrev},
		},
		{
			name: "delete a line from a compressed segment",
			tamper: func(t *testing.T, f *cacheFixture) {
				f.edit(t, 0, false, func(b []byte) []byte {
					l := splitLines(b)
					return bytes.Join(append(l[:2], l[3:]...), nil)
				})
			},
			want: []string{probSeqGap, probPrev, probSegmentHash},
		},
		{
			name: "swap two lines of the latest segment",
			tamper: func(t *testing.T, f *cacheFixture) {
				f.edit(t, 3, false, func(b []byte) []byte {
					l := splitLines(b)
					l[2], l[3] = l[3], l[2]
					return bytes.Join(l, nil)
				})
			},
			want: []string{probSeqGap, probPrev},
		},
		{
			name: "append a copy of a record to a compressed segment",
			tamper: func(t *testing.T, f *cacheFixture) {
				f.edit(t, 1, false, func(b []byte) []byte { return append(b, splitLines(b)[3]...) })
			},
			want: []string{probSeqGap, probSegmentHash},
		},
		{
			name: "truncate a compressed segment mid-line",
			tamper: func(t *testing.T, f *cacheFixture) {
				f.edit(t, 0, true, func(b []byte) []byte { return b[:len(b)-30] })
			},
			want: []string{probParse, probSegmentHash},
		},
		{
			name: "damage the compressed bytes of a segment",
			tamper: func(t *testing.T, f *cacheFixture) {
				path := f.file(1)
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				raw[len(raw)/2] ^= 0x55
				if err := os.WriteFile(path, raw, 0o644); err != nil {
					t.Fatal(err)
				}
			},
			want: []string{probParse},
		},
		{
			name:   "delete a whole compressed segment",
			tamper: func(t *testing.T, f *cacheFixture) { os.Remove(f.file(1)) },
			want:   []string{probSeqGap, probPrev, probSegmentHash},
		},
		{
			name:   "rename the sealed plain segment to a later day",
			tamper: func(t *testing.T, f *cacheFixture) { os.Rename(f.file(2), segPath(f.dir, "ledger-2026-10-30")) },
			want:   []string{probSegmentHash, probSeqGap},
		},
		{
			name: "decompress a sealed segment (same bytes, other form)",
			tamper: func(t *testing.T, f *cacheFixture) {
				path := f.file(0)
				if err := os.WriteFile(strings.TrimSuffix(path, gzExt), gunzipFile(t, path), 0o644); err != nil {
					t.Fatal(err)
				}
				os.Remove(path)
			},
		},
		{
			name: "remove the last line of the latest segment (undetectable without a later record)",
			tamper: func(t *testing.T, f *cacheFixture) {
				f.edit(t, 3, false, func(b []byte) []byte {
					l := splitLines(b)
					return bytes.Join(l[:len(l)-1], nil)
				})
			},
		},
		{
			name: "an incomplete line at the end of the latest segment",
			tamper: func(t *testing.T, f *cacheFixture) {
				f.edit(t, 3, false, func(b []byte) []byte { return append(b, `{"h":"0`...) })
			},
		},
		{
			name:   "delete a page blob",
			tamper: func(t *testing.T, f *cacheFixture) { os.Remove(f.blobPath(f.pages[1])) },
			want:   []string{probBlobMissing},
		},
		{
			name: "replace an anchor's time-stamp token",
			tamper: func(t *testing.T, f *cacheFixture) {
				if err := os.WriteFile(f.blobPath(f.tokens[0]), gz(t, []byte("TS|2026-10-05T03:21:00Z|00")), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			want: []string{probAnchor},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newCacheFixture(t)
			ro := f.reader(t)
			requireOK(t, requireCachedEqualsFull(t, ro, "intact ledger"))
			if n := len(cacheEntries(ro)); n != len(f.segs) {
				t.Fatalf("%d segments cached, want %d", n, len(f.segs))
			}
			// With every segment cached, verify again: everything is reused.
			verified := ro.sigs.verified.Load()
			requireOK(t, requireCachedEqualsFull(t, ro, "intact ledger, cached"))
			if ro.sigs.verified.Load() != verified {
				t.Fatalf("an unchanged ledger was verified again (%d signatures)", ro.sigs.verified.Load()-verified)
			}

			tc.tamper(t, f)
			reused := ro.sigs.reused.Load()
			rep := requireCachedEqualsFull(t, ro, "after tampering")
			got := problems(rep)
			if tc.want == nil && !rep.OK {
				t.Fatalf("unexpected failures:\n%s", dumpReport(rep))
			}
			if tc.want != nil && (rep.OK || rep.FailuresTotal == 0) {
				t.Fatalf("tampering not detected:\n%s", dumpReport(rep))
			}
			for _, p := range tc.want {
				if got[p] == 0 {
					t.Errorf("missing %s; got %v:\n%s", p, sortedKeys(got), dumpReport(rep))
				}
			}
			if !strings.Contains(tc.name, "genesis") && ro.sigs.reused.Load() == reused {
				t.Fatalf("no signature outcome was reused: the cache was not exercised")
			}
			// Cached again, now for the tampered bytes.
			requireSameReport(t, "after tampering, cached", verifyCached(t, ro), rep)
		})
	}
}

// A forged line stays a failure when its segment's outcomes come from the cache.
func TestVerifyCacheKeepsReportingBadSignatures(t *testing.T) {
	f := newCacheFixture(t)
	f.edit(t, 1, false, changeLine(3, otherSignature(t)))
	f.edit(t, 3, false, changeLine(2, otherSignature(t)))
	ro := f.reader(t)
	first := requireCachedEqualsFull(t, ro, "first")
	if problems(first)[probSignature] != 2 {
		t.Fatalf("want two bad signatures:\n%s", dumpReport(first))
	}
	reused := ro.sigs.reused.Load()
	again := requireCachedEqualsFull(t, ro, "cached")
	requireSameReport(t, "cached vs first", again, first)
	if ro.sigs.reused.Load()-reused != int64(first.Records) {
		t.Fatalf("reused %d outcomes, want %d", ro.sigs.reused.Load()-reused, first.Records)
	}
}

// The cache skips only signature checks, and only for segments whose bytes are unchanged.
func TestVerifyCacheReverifiesOnlyChangedSegments(t *testing.T) {
	f := newCacheFixture(t)
	ro := f.reader(t)
	rep := requireCachedEqualsFull(t, ro, "first")
	if v, r := ro.sigs.verified.Load(), ro.sigs.reused.Load(); v != int64(rep.Records) || r != 0 {
		t.Fatalf("first run: verified %d reused %d, want %d and 0", v, r, rep.Records)
	}
	// Rewriting a file with the same bytes (a new modification time) changes nothing.
	f.edit(t, 2, false, func(b []byte) []byte { return b })
	requireCachedEqualsFull(t, ro, "same bytes")
	if v := ro.sigs.verified.Load(); v != int64(rep.Records) {
		t.Fatalf("identical bytes were verified again (%d)", v-int64(rep.Records))
	}
	// Recompressing a segment (same content, other gzip bytes) changes its raw bytes: only its
	// lines are verified again.
	content := gunzipFile(t, f.file(1))
	lines1 := len(splitLines(content))
	var recompressed bytes.Buffer
	zw := gzip.NewWriter(&recompressed)
	zw.Name = "recompressed" // the header alone guarantees other bytes
	zw.Write(content)
	zw.Close()
	if err := os.WriteFile(f.file(1), recompressed.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	requireCachedEqualsFull(t, ro, "recompressed")
	if v := ro.sigs.verified.Load(); v != int64(rep.Records)+int64(lines1) {
		t.Fatalf("verified %d signatures after recompressing one segment of %d lines", v-int64(rep.Records), lines1)
	}
}

// Segments larger than maxCachedSegmentBytes are verified in full every time.
func TestVerifyCacheBoundsTheBytesHeldInMemory(t *testing.T) {
	old := maxCachedSegmentBytes
	maxCachedSegmentBytes = 1024
	t.Cleanup(func() { maxCachedSegmentBytes = old })
	f := newCacheFixture(t)
	ro := f.reader(t)
	first := requireCachedEqualsFull(t, ro, "first")
	requireSameReport(t, "second", requireCachedEqualsFull(t, ro, "second"), first)
	if r := ro.sigs.reused.Load(); r != 0 || len(cacheEntries(ro)) != 0 {
		t.Fatalf("segments over the bound were cached: reused %d, entries %d", r, len(cacheEntries(ro)))
	}
}

// Entries of segments that disappeared are dropped by the next complete verification.
func TestVerifyCacheForgetsRemovedSegments(t *testing.T) {
	f := newCacheFixture(t)
	ro := f.reader(t)
	requireCachedEqualsFull(t, ro, "first")
	os.Remove(f.file(1))
	requireCachedEqualsFull(t, ro, "segment removed")
	if _, ok := cacheEntries(ro)[f.segs[1]]; ok || len(cacheEntries(ro)) != len(f.segs)-1 {
		t.Fatalf("entries after removing %s: %d", f.segs[1], len(cacheEntries(ro)))
	}
}

// The writer verifies itself while it appends and rotates; an older segment tampered with in the
// meantime is detected exactly as by a full verification.
func TestVerifyCacheOnTheWriter(t *testing.T) {
	f := newCacheFixture(t)
	opts := testOptions(f.dir, f.clk)
	opts.TokenVerifier = timeTSA{}
	w := openStore(t, opts)
	requireOK(t, requireCachedEqualsFull(t, w, "writer"))
	appendSamples(t, w, f.clk, 3, 10*time.Second)
	requireOK(t, requireCachedEqualsFull(t, w, "after appends"))
	f.clk.Advance(day)
	appendSamples(t, w, f.clk, 3, 10*time.Second) // rotates
	stampAt(t, w, w.Head(), f.clk.Now(), true)
	rep := requireCachedEqualsFull(t, w, "after rotation")
	requireOK(t, rep)
	if len(rep.Segments) != 5 {
		t.Fatalf("segments %v", rep.Segments)
	}
	f.edit(t, 0, true, changeLine(4, otherSignature(t)))
	rep = requireCachedEqualsFull(t, w, "older segment tampered with")
	if rep.OK || problems(rep)[probSignature] != 1 {
		t.Fatalf("tampering not detected:\n%s", dumpReport(rep))
	}
}

// Concurrent verifications share the cache and all report what a full verification reports.
func TestVerifyCacheConcurrentVerifications(t *testing.T) {
	f := newCacheFixture(t)
	f.edit(t, 2, false, changeLine(3, otherSignature(t)))
	ro := f.reader(t)
	want := verifyUncached(t, ro)
	var wg sync.WaitGroup
	reps := make([]model.VerifyReport, 8)
	errs := make([]error, len(reps))
	for i := range reps {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reps[i], errs[i] = ro.Verify(context.Background())
		}()
	}
	wg.Wait()
	for i := range reps {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		requireSameReport(t, fmt.Sprintf("verification %d", i), reps[i], want)
	}
	requireSameReport(t, "afterwards", verifyCached(t, ro), want)
}

// Random damage to random segments, in either form, with and without keeping the modification
// time, sometimes undone: the cached report always equals the full one.
func TestVerifyCacheRandomDamage(t *testing.T) {
	seed := time.Now().UnixNano()
	t.Logf("seed %d", seed)
	rng := rand.New(rand.NewSource(seed))
	f := newCacheFixture(t)
	orig := map[string][]byte{}
	origTime := map[string]time.Time{}
	paths := func() []string {
		m, _ := filepath.Glob(filepath.Join(f.dir, "ledger", "ledger-*"))
		return m
	}
	for _, p := range paths() {
		orig[p], _ = os.ReadFile(p)
		st, _ := os.Stat(p)
		origTime[p] = st.ModTime()
	}
	ro := f.reader(t)
	requireCachedEqualsFull(t, ro, "intact")
	restore := func() {
		for p, b := range orig {
			os.WriteFile(p, b, 0o644)
			os.Chtimes(p, origTime[p], origTime[p])
		}
	}
	// mutate is f.edit, except that a compressed segment that no longer decompresses has its
	// raw bytes changed.
	mutate := func(i int, keep bool, change func([]byte) []byte) {
		path := f.file(i)
		if strings.HasSuffix(path, gzExt) {
			if _, err := tryGunzip(path); err != nil {
				st, _ := os.Stat(path)
				raw, _ := os.ReadFile(path)
				os.WriteFile(path, change(raw), 0o644)
				if keep {
					os.Chtimes(path, st.ModTime(), st.ModTime())
				}
				return
			}
		}
		f.edit(t, i, keep, change)
	}
	for it := 0; it < 60; it++ {
		if rng.Intn(4) == 0 {
			restore()
		}
		i := rng.Intn(len(f.segs))
		keep := rng.Intn(2) == 0
		what := ""
		switch op := rng.Intn(7); op {
		case 0:
			what = "flip a byte"
			mutate(i, keep, func(b []byte) []byte {
				if len(b) > 0 {
					b[rng.Intn(len(b))] ^= byte(1 << rng.Intn(8))
				}
				return b
			})
		case 1:
			what = "delete a line"
			mutate(i, keep, func(b []byte) []byte {
				l := splitLines(b)
				if len(l) == 0 {
					return b
				}
				k := rng.Intn(len(l))
				return bytes.Join(append(l[:k:k], l[k+1:]...), nil)
			})
		case 2:
			what = "duplicate a line"
			mutate(i, keep, func(b []byte) []byte {
				l := splitLines(b)
				if len(l) == 0 {
					return b
				}
				k := rng.Intn(len(l))
				return bytes.Join(append(l[:k+1:k+1], l[k:]...), nil)
			})
		case 3:
			what = "swap lines"
			mutate(i, keep, func(b []byte) []byte {
				l := splitLines(b)
				if len(l) < 2 {
					return b
				}
				x, y := rng.Intn(len(l)), rng.Intn(len(l))
				l[x], l[y] = l[y], l[x]
				return bytes.Join(l, nil)
			})
		case 4:
			what = "truncate"
			mutate(i, keep, func(b []byte) []byte { return b[:rng.Intn(len(b)+1)] })
		case 5:
			what = "replace a signature"
			mutate(i, keep, func(b []byte) []byte {
				l := splitLines(b)
				if len(l) == 0 || !bytes.HasSuffix(l[0], []byte("\n")) {
					return b
				}
				k := rng.Intn(len(l))
				if env, err := parseEnvelopeStrict(l[k]); err == nil && len(env.S) > 2 {
					s := []byte(env.S)
					s[1] = "ABCDEFGHIJ"[rng.Intn(10)]
					l[k] = bytes.Replace(l[k], []byte(env.S), s, 1)
				}
				return bytes.Join(l, nil)
			})
		default:
			what = "damage the file bytes"
			path := f.file(i)
			if raw, err := os.ReadFile(path); err == nil && len(raw) > 0 {
				raw[rng.Intn(len(raw))] ^= byte(1 << rng.Intn(8))
				os.WriteFile(path, raw, 0o644)
			}
		}
		requireCachedEqualsFull(t, ro, fmt.Sprintf("iteration %d: %s in segment %d (keep time %v)", it, what, i, keep))
	}
	restore()
	requireOK(t, requireCachedEqualsFull(t, ro, "restored"))
}

func tryGunzip(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	_, err = b.ReadFrom(zr)
	return b.Bytes(), err
}

// BenchmarkVerifyRepeated measures a full verification ("full", what every Verify cost before the
// cache) and a repeated Store.Verify of the unchanged ledger ("cached"), for 30 daily segments of
// 3000 records, uncompressed and compressed.
func BenchmarkVerifyRepeated(b *testing.B) {
	for _, gzip := range []bool{false, true} {
		form := "plain"
		if gzip {
			form = "gz"
		}
		dir, clk := buildMultiDayLedger(b, 30, 3000)
		if gzip {
			compressAllSealed(b, dir, clk, 29)
		}
		ro := openRO(b, dir, clk)
		run := func(b *testing.B, verify func() (model.VerifyReport, error)) {
			for i := 0; i < b.N; i++ {
				rep, err := verify()
				if err != nil || !rep.OK {
					b.Fatalf("verify: %v\n%s", err, dumpReport(rep))
				}
			}
		}
		b.Run(form+"/full", func(b *testing.B) {
			run(b, func() (model.VerifyReport, error) {
				return verifyReader(context.Background(), ro, ro.verifyOptions(), ro.now)
			})
		})
		b.Run(form+"/cached", func(b *testing.B) {
			if _, err := ro.Verify(context.Background()); err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			run(b, func() (model.VerifyReport, error) { return ro.Verify(context.Background()) })
		})
		ro.Close()
	}
}
