package ledger

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// buildMultiDayLedger writes a valid ledger of days daily segments directly to disk, bypassing
// the per-record fsync of Append: the genesis segment and every later one (which begins with a
// segment_open committing to its predecessor's bytes) hold perDay sample records each, one second
// apart. The clock is left one second after the last record, on the last day.
func buildMultiDayLedger(tb testing.TB, days, perDay int) (string, *fakeClock) {
	tb.Helper()
	dir := tb.TempDir()
	clk := newClock(t0)
	s, err := Open(testOptions(dir, clk))
	if err != nil {
		tb.Fatal(err)
	}
	priv := append(ed25519.PrivateKey(nil), s.priv...)
	head, run := s.Head(), s.RunID()
	s.Close()
	prevBytes, err := os.ReadFile(segPath(dir, segName(t0)))
	if err != nil {
		tb.Fatal(err)
	}
	data, _ := json.Marshal(samplePayload(1))
	seq, prev := head.Seq, head.Hash
	var last time.Time
	for d := 0; d < days; d++ {
		date := utcDate(t0).Add(time.Duration(d) * day)
		start := date.Add(time.Hour)
		if d == 0 {
			start = t0.Add(time.Second)
		}
		var bodies []model.Body
		add := func(ts time.Time, typ string, payload []byte) {
			seq++
			b := model.Body{V: model.FormatVersion, Seq: seq, Prev: prev, TS: ts.Format(time.RFC3339Nano),
				Mono: int64(ts.Sub(t0)), Run: run, Type: typ, Data: payload}
			enc, err := marshalJSON(&b)
			if err != nil {
				tb.Fatal(err)
			}
			prev = sha256Hex(enc)
			bodies = append(bodies, b)
			last = ts
		}
		if d > 0 {
			so, _ := marshalJSON(&model.SegmentOpen{
				Segment: segName(date), PrevSegment: segName(date.Add(-day)),
				PrevSegmentSHA256: sha256Hex(prevBytes), PrevSegmentRecords: bytes.Count(prevBytes, []byte{'\n'}),
				PrevSegmentLastSeq: seq,
			})
			add(start.Add(-time.Second), model.TypeSegmentOpen, so)
		}
		for i := 0; i < perDay; i++ {
			add(start.Add(time.Duration(i)*time.Second), model.TypeSample, data)
		}
		lines := signBodies(tb, priv, bodies)
		var seg []byte
		if d == 0 {
			seg = append(seg, prevBytes...) // the genesis record written by Open
		}
		for _, l := range lines {
			seg = append(seg, l...)
		}
		if err := os.WriteFile(segPath(dir, segName(date)), seg, 0o644); err != nil {
			tb.Fatal(err)
		}
		prevBytes = seg
	}
	clk.Advance(last.Sub(clk.Now()) + time.Second)
	return dir, clk
}

// signBodies encodes and signs bodies in parallel, in order.
func signBodies(tb testing.TB, priv ed25519.PrivateKey, bodies []model.Body) [][]byte {
	tb.Helper()
	lines := make([][]byte, len(bodies))
	var wg sync.WaitGroup
	workers := runtime.GOMAXPROCS(0)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := w; i < len(bodies); i += workers {
				line, _, err := encodeRecord(priv, &bodies[i])
				if err != nil {
					panic(err)
				}
				lines[i] = line
			}
		}(w)
	}
	wg.Wait()
	return lines
}

// compressAllSealed opens a writer on dir (its clock on the last day) and gzip-compresses every
// sealed segment, then closes it.
func compressAllSealed(tb testing.TB, dir string, clk *fakeClock, want int) {
	tb.Helper()
	w, err := Open(testOptions(dir, clk))
	if err != nil {
		tb.Fatal(err)
	}
	defer w.Close()
	if n, err := w.CompressSealed(0); err != nil || n != want {
		tb.Fatalf("CompressSealed = %d, %v (want %d)", n, err, want)
	}
}

func TestMultiDayLedgerVerifies(t *testing.T) {
	dir, clk := buildMultiDayLedger(t, 4, 50)
	rep := verifyRO(t, dir, clk)
	requireOK(t, rep)
	if len(rep.Segments) != 4 || rep.Records != 1+4*50+3 || rep.TypeCounts[model.TypeSegmentOpen] != 3 {
		t.Fatalf("report %+v", rep)
	}
	compressAllSealed(t, dir, clk, 3)
	requireOK(t, verifyRO(t, dir, clk))
}
