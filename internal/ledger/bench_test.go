package ledger

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// buildSyntheticLedger writes n valid sample records after genesis directly into the active
// segment (bypassing the per-record fsync of Append) and returns the directory.
func buildSyntheticLedger(tb testing.TB, n int) (string, *fakeClock) {
	tb.Helper()
	dir := tb.TempDir()
	clk := newClock(t0)
	s, err := Open(testOptions(dir, clk))
	if err != nil {
		tb.Fatal(err)
	}
	priv := append(ed25519.PrivateKey(nil), s.priv...)
	head, run := s.Head(), s.RunID()
	path := s.active.path
	s.Close()

	data, _ := json.Marshal(samplePayload(1))
	bodies := make([]model.Body, n)
	prev := head.Hash
	for i := range bodies {
		ts := t0.Add(time.Duration(i+1) * 100 * time.Millisecond)
		bodies[i] = model.Body{V: 1, Seq: uint64(i + 1), Prev: prev, TS: ts.Format(time.RFC3339Nano),
			Mono: int64(ts.Sub(t0)), Run: run, Type: model.TypeSample, Data: data}
		b, _ := marshalJSON(&bodies[i])
		prev = sha256Hex(b)
	}
	lines := make([][]byte, n)
	var wg sync.WaitGroup
	workers := runtime.GOMAXPROCS(0)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := w; i < n; i += workers {
				line, _, err := encodeRecord(priv, &bodies[i])
				if err != nil {
					panic(err)
				}
				lines[i] = line
			}
		}(w)
	}
	wg.Wait()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		tb.Fatal(err)
	}
	bw := bufio.NewWriterSize(f, 1<<20)
	for _, l := range lines {
		bw.Write(l)
	}
	if err := bw.Flush(); err != nil {
		tb.Fatal(err)
	}
	f.Close()
	return dir, clk
}

func BenchmarkVerifyReader100k(b *testing.B) {
	const n = 100000
	dir, clk := buildSyntheticLedger(b, n)
	opts := testOptions(dir, clk)
	opts.ReadOnly = true
	ro, err := Open(opts)
	if err != nil {
		b.Fatal(err)
	}
	defer ro.Close()
	fi, _ := os.Stat(segPath(dir, segName(t0)))
	b.SetBytes(fi.Size())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rep, err := VerifyReader(context.Background(), ro, VerifyOptions{CheckBlobs: true})
		if err != nil || !rep.OK || rep.Records != n+1 {
			b.Fatalf("verify: %v ok=%v records=%d", err, rep.OK, rep.Records)
		}
	}
	b.ReportMetric(float64(n+1)*float64(b.N)/b.Elapsed().Seconds(), "records/s")
}

func BenchmarkScan100k(b *testing.B) {
	const n = 100000
	dir, clk := buildSyntheticLedger(b, n)
	opts := testOptions(dir, clk)
	opts.ReadOnly = true
	ro, err := Open(opts)
	if err != nil {
		b.Fatal(err)
	}
	defer ro.Close()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		count := 0
		if err := ro.Scan(0, func(model.Envelope, model.Body) error { count++; return nil }); err != nil || count != n+1 {
			b.Fatalf("scan %d %v", count, err)
		}
	}
	b.ReportMetric(float64(n+1)*float64(b.N)/b.Elapsed().Seconds(), "records/s")
}

func BenchmarkRecordLookup100k(b *testing.B) {
	const n = 100000
	dir, clk := buildSyntheticLedger(b, n)
	opts := testOptions(dir, clk)
	opts.ReadOnly = true
	ro, err := Open(opts)
	if err != nil {
		b.Fatal(err)
	}
	defer ro.Close()
	warmRecord(b, ro, n)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		seq := uint64(i*7919) % n
		if _, body, err := ro.Record(seq); err != nil || body.Seq != seq {
			b.Fatalf("Record(%d): %v", seq, err)
		}
	}
}

// warmRecord performs one lookup before timing, so that the benchmarks measure steady-state
// lookups (the first one builds the segment's line index).
func warmRecord(b *testing.B, s *Store, n int) {
	b.Helper()
	if _, _, err := s.Record(uint64(n / 2)); err != nil {
		b.Fatal(err)
	}
}

// BenchmarkRecordLookupWriterActive100k looks records up in the writer's own active segment
// (the common case: the dashboard showing recent incidents).
func BenchmarkRecordLookupWriterActive100k(b *testing.B) {
	const n = 100000
	dir, clk := buildSyntheticLedger(b, n)
	w, err := Open(testOptions(dir, clk))
	if err != nil {
		b.Fatal(err)
	}
	defer w.Close()
	warmRecord(b, w, n)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		seq := uint64(i*7919) % n
		if _, body, err := w.Record(seq); err != nil || body.Seq != seq {
			b.Fatalf("Record(%d): %v", seq, err)
		}
	}
}

// BenchmarkRecordLookupCompressed20k looks records up in a sealed, gzip-compressed segment of
// about one day's size.
func BenchmarkRecordLookupCompressed20k(b *testing.B) {
	const n = 20000
	dir, clk := buildSyntheticLedger(b, n)
	clk.Advance(72 * time.Hour)
	w, err := Open(testOptions(dir, clk))
	if err != nil {
		b.Fatal(err)
	}
	defer w.Close()
	if _, err := w.Append(model.TypeSample, samplePayload(1)); err != nil { // rotates
		b.Fatal(err)
	}
	if c, err := w.CompressSealed(0); err != nil || c != 1 {
		b.Fatalf("CompressSealed = %d, %v", c, err)
	}
	warmRecord(b, w, n)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		seq := uint64(i*7919) % n
		if _, body, err := w.Record(seq); err != nil || body.Seq != seq {
			b.Fatalf("Record(%d): %v", seq, err)
		}
	}
}

// BenchmarkRecordFirstLookup100k measures a lookup that must first build the segment's line
// index (one sequential pass over the segment).
func BenchmarkRecordFirstLookup100k(b *testing.B) {
	const n = 100000
	dir, clk := buildSyntheticLedger(b, n)
	opts := testOptions(dir, clk)
	opts.ReadOnly = true
	ro, err := Open(opts)
	if err != nil {
		b.Fatal(err)
	}
	defer ro.Close()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ro.idx.mu.Lock()
		for _, e := range ro.idx.entries {
			ro.idx.dropLocked(e)
		}
		ro.idx.entries = nil
		ro.idx.mu.Unlock()
		seq := uint64(i*7919) % n
		if _, body, err := ro.Record(seq); err != nil || body.Seq != seq {
			b.Fatalf("Record(%d): %v", seq, err)
		}
	}
}

func BenchmarkAppendWithFsync(b *testing.B) {
	dir := b.TempDir()
	clk := newClock(t0)
	s, err := Open(testOptions(dir, clk))
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	p := samplePayload(1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.Append(model.TypeSample, p); err != nil {
			b.Fatal(err)
		}
	}
}
