package ledger

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"testing"
	"time"

	"attmonitor/internal/contracts"
)

// gzReads returns how many compressed segments the store decompressed completely for metadata.
func gzReads(s *Store) int64 { return s.metaGzReads.Load() }

func segmentsOf(t *testing.T, s *Store) []contracts.SegmentInfo {
	t.Helper()
	segs, err := s.Segments()
	if err != nil {
		t.Fatalf("Segments: %v", err)
	}
	return segs
}

func describeSegments(segs []contracts.SegmentInfo) string {
	var b bytes.Buffer
	for _, s := range segs {
		fmt.Fprintf(&b, "%s gz=%v active=%v seq %d-%d records %d\n", s.Name, s.Compressed, s.Active, s.FirstSeq, s.LastSeq, s.Records)
	}
	return b.String()
}

// Segments decompresses a sealed .gz segment once per version of its file: repeated calls use the
// metadata cached for (path, size, modification time); a changed file is read again.
func TestSegmentsMetadataIsCachedPerFileVersion(t *testing.T) {
	const days, perDay = 5, 30
	dir, clk := buildMultiDayLedger(t, days, perDay)
	compressAllSealed(t, dir, clk, days-1)
	ro := readOnly(t, dir, clk)

	first := segmentsOf(t, ro)
	if n := gzReads(ro); n != days-1 {
		t.Fatalf("first call decompressed %d segments, want %d", n, days-1)
	}
	if first[1].FirstSeq != perDay+1 || first[1].LastSeq != 2*perDay+1 || first[1].Records != perDay+1 || !first[1].Compressed {
		t.Fatalf("segment metadata:\n%s", describeSegments(first))
	}
	for i := 0; i < 3; i++ {
		again := segmentsOf(t, ro)
		if describeSegments(again) != describeSegments(first) {
			t.Fatalf("metadata changed without a change of the files:\n%s\nwas\n%s", describeSegments(again), describeSegments(first))
		}
	}
	if n := gzReads(ro); n != days-1 {
		t.Fatalf("repeated calls decompressed again (%d decompressions)", n)
	}

	// Another version of one compressed segment (its last line removed) is read again, once.
	gzPath := segPath(dir, segName(t0.Add(day))) + gzExt
	plain := gunzipFile(t, gzPath)
	lines := bytes.SplitAfter(plain, []byte("\n"))
	writeGz(t, gzPath, bytes.Join(lines[:len(lines)-2], nil)) // SplitAfter leaves a final empty element
	changed := segmentsOf(t, ro)
	if n := gzReads(ro); n != days {
		t.Fatalf("a changed file was decompressed %d times in total, want %d", n, days)
	}
	if changed[1].Records != perDay || changed[1].LastSeq != 2*perDay {
		t.Fatalf("metadata of the changed segment:\n%s", describeSegments(changed))
	}
	segmentsOf(t, ro)
	if n := gzReads(ro); n != days {
		t.Fatalf("the new version was decompressed again (%d)", n)
	}

	// A new modification time alone is a new version too.
	later := time.Now().Add(time.Hour)
	if err := os.Chtimes(gzPath, later, later); err != nil {
		t.Fatal(err)
	}
	segmentsOf(t, ro)
	if n := gzReads(ro); n != days+1 {
		t.Fatalf("a touched file was not read again (%d)", n)
	}
}

// A compressed segment whose content cannot be decompressed is reported (and logged) on every
// call, but read only once per version of its file.
func TestSegmentsDamagedCompressedSegmentIsReadOncePerVersion(t *testing.T) {
	dir, clk := buildMultiDayLedger(t, 3, 20)
	compressAllSealed(t, dir, clk, 2)
	gzPath := segPath(dir, segName(t0)) + gzExt
	raw, err := os.ReadFile(gzPath)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0xff // corrupt deflate data (or the CRC)
	if err := os.WriteFile(gzPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	ro := readOnly(t, dir, clk)
	for i := 0; i < 3; i++ {
		segs := segmentsOf(t, ro)
		if segs[0].Records != 0 || segs[0].LastSeq != 0 || segs[1].Records != 21 {
			t.Fatalf("call %d:\n%s", i, describeSegments(segs))
		}
	}
	if n := gzReads(ro); n != 2 {
		t.Fatalf("decompressions: %d, want 2 (one per compressed segment)", n)
	}
	// Record still finds what the damaged segment's readable part holds (its first seq is cached).
	if _, b, err := ro.Record(0); err != nil || b.Seq != 0 {
		t.Fatalf("Record(0) in the damaged segment: %v", err)
	}
}

// CompressSealed keeps the metadata it knows: the writer's Segments needs no decompression for a
// segment it compressed itself, and reports exactly what it reported before.
func TestSegmentsAfterCompressSealedNeedNoDecompression(t *testing.T) {
	const days, perDay = 4, 25
	dir, clk := buildMultiDayLedger(t, days, perDay)
	w := openStore(t, testOptions(dir, clk))
	before := segmentsOf(t, w)
	// ScanTime's earliest-ts cache, known for every sealed segment.
	views, err := w.readerSegments(true)
	if err != nil {
		t.Fatal(err)
	}
	earliest := map[string]time.Time{}
	for _, v := range views[:days-1] {
		e, ok := w.segmentMinTS(v)
		if !ok {
			t.Fatalf("segmentMinTS(%s)", v.Name)
		}
		earliest[v.Name] = e
	}
	if n, err := w.CompressSealed(0); err != nil || n != days-1 {
		t.Fatalf("CompressSealed = %d, %v", n, err)
	}
	after := segmentsOf(t, w)
	if n := gzReads(w); n != 0 {
		t.Fatalf("Segments decompressed %d segments the writer had just compressed", n)
	}
	for i := range after {
		b, a := before[i], after[i]
		b.Path, b.Compressed = a.Path, true
		if i == days-1 {
			b.Compressed = false
		}
		if a != b {
			t.Fatalf("segment %d after compression %+v, before %+v", i, a, before[i])
		}
	}
	// A fresh reader computes the same metadata from the compressed files.
	ro := readOnly(t, dir, clk)
	if got := describeSegments(segmentsOf(t, ro)); got != describeSegments(after) {
		t.Fatalf("fresh reader:\n%s\nwriter:\n%s", got, describeSegments(after))
	}
	if n := gzReads(ro); n != days-1 {
		t.Fatalf("fresh reader decompressed %d", n)
	}
	// The earliest ts were kept for the compressed files (validated by their size and time).
	views, err = w.readerSegments(true)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range views[:days-1] {
		w.cacheMu.Lock()
		m, ok := w.minTS[v.path()]
		w.cacheMu.Unlock()
		st, err := os.Stat(v.path())
		if err != nil || !ok || !v.compressed() || !m.earliest.Equal(earliest[v.Name]) || m.size != st.Size() || !m.mod.Equal(st.ModTime()) {
			t.Fatalf("earliest ts of %s after compression: %+v (cached %v), want %s", v.Name, m, ok, earliest[v.Name])
		}
		if e, ok := ro.segmentMinTS(v); !ok || !e.Equal(earliest[v.Name]) {
			t.Fatalf("fresh reader's earliest ts of %s: %s", v.Name, e)
		}
	}
}

func gunzipFile(t *testing.T, path string) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if _, err := b.ReadFrom(zr); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func writeGz(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path+".new", gz(t, content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".new", path); err != nil {
		t.Fatal(err)
	}
}

// openRO opens dir read-only (no cleanup: benchmarks close it themselves).
func openRO(tb testing.TB, dir string, clk *fakeClock) *Store {
	tb.Helper()
	opts := testOptions(dir, clk)
	opts.ReadOnly = true
	ro, err := Open(opts)
	if err != nil {
		tb.Fatal(err)
	}
	return ro
}

// BenchmarkSegmentsCompressed lists the segments of a ledger whose 30 sealed daily segments are
// gzip-compressed. "warm" repeats Segments on one store: the cached metadata must make every call
// after the first cheap (no decompression). "cold" is the first call on a new store. "writer"
// repeats Segments on the writer itself.
func BenchmarkSegmentsCompressed(b *testing.B) {
	const days, perDay = 31, 2000
	dir, clk := buildMultiDayLedger(b, days, perDay)
	compressAllSealed(b, dir, clk, days-1)
	check := func(b *testing.B, s *Store) {
		segs, err := s.Segments()
		if err != nil || len(segs) != days || segs[1].Records != perDay+1 || !segs[1].Compressed {
			b.Fatalf("Segments: %d segments, %v", len(segs), err)
		}
	}
	b.Run("warm", func(b *testing.B) {
		ro := openRO(b, dir, clk)
		defer ro.Close()
		check(b, ro)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			check(b, ro)
		}
	})
	b.Run("writer", func(b *testing.B) {
		w, err := Open(testOptions(dir, clk))
		if err != nil {
			b.Fatal(err)
		}
		defer w.Close()
		check(b, w)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			check(b, w)
		}
	})
	b.Run("cold", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			ro := openRO(b, dir, clk)
			b.StartTimer()
			check(b, ro)
			b.StopTimer()
			ro.Close()
			b.StartTimer()
		}
	})
}
