package ledger

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// tamperFixture is a closed three-segment ledger with a blob-referencing record.
type tamperFixture struct {
	dir   string
	clk   *fakeClock
	priv  ed25519.PrivateKey
	segs  []string // segment names, oldest first
	blob  string
	refs  []model.Ref
	other ed25519.PrivateKey // a key that is not the ledger's
}

func newTamperFixture(t *testing.T) *tamperFixture {
	t.Helper()
	dir := t.TempDir()
	clk := newClock(t0)
	s := openStore(t, testOptions(dir, clk))
	f := &tamperFixture{dir: dir, clk: clk}
	f.refs = append(f.refs, appendSamples(t, s, clk, 5, 10*time.Second)...)
	id, err := s.PutBlob([]byte("<html>broadbandstatistics</html>"))
	if err != nil {
		t.Fatal(err)
	}
	f.blob = id
	f.refs = append(f.refs, mustAppend(t, s, model.TypeGatewaySnapshot, map[string]string{"page": id}, id))
	clk.Advance(24 * time.Hour)
	f.refs = append(f.refs, appendSamples(t, s, clk, 5, 10*time.Second)...)
	clk.Advance(24 * time.Hour)
	f.refs = append(f.refs, appendSamples(t, s, clk, 5, 10*time.Second)...)
	for i := 0; i < 3; i++ {
		f.segs = append(f.segs, segName(t0.Add(time.Duration(i)*24*time.Hour)))
	}
	f.priv = append(ed25519.PrivateKey(nil), s.priv...)
	_, f.other, _ = ed25519.GenerateKey(nil)
	s.Close()
	return f
}

func (f *tamperFixture) path(i int) string { return segPath(f.dir, f.segs[i]) }

func TestTamperDetection(t *testing.T) {
	cases := []struct {
		name   string
		tamper func(t *testing.T, f *tamperFixture)
		want   []string // problems that must be reported
		seq    uint64   // seq the first failure must point at (0 = don't care)
	}{
		{
			name: "flip a byte inside b",
			tamper: func(t *testing.T, f *tamperFixture) {
				lines := readLines(t, f.path(0))
				i := bytes.Index(lines[3], []byte("IP_SUCCESS"))
				lines[3][i+1] = 'Q'
				writeLines(t, f.path(0), lines)
			},
			want: []string{probHash, probSignature, probPrev, probSegmentHash},
			seq:  3,
		},
		{
			name: "edit h",
			tamper: func(t *testing.T, f *tamperFixture) {
				lines := readLines(t, f.path(1))
				env, _ := parseLine(t, lines[2])
				h := []byte(env.H)
				if h[0] == '0' {
					h[0] = '1'
				} else {
					h[0] = '0'
				}
				lines[2] = bytes.Replace(lines[2], []byte(env.H), h, 1)
				writeLines(t, f.path(1), lines)
			},
			want: []string{probHash, probSegmentHash},
		},
		{
			name: "edit s",
			tamper: func(t *testing.T, f *tamperFixture) {
				lines := readLines(t, f.path(2))
				env, _ := parseLine(t, lines[2])
				sig := []byte(env.S)
				if sig[0] == 'A' {
					sig[0] = 'B'
				} else {
					sig[0] = 'A'
				}
				lines[2] = bytes.Replace(lines[2], []byte(env.S), sig, 1)
				writeLines(t, f.path(2), lines)
			},
			want: []string{probSignature},
		},
		{
			name: "signature not canonical base64",
			tamper: func(t *testing.T, f *tamperFixture) {
				lines := readLines(t, f.path(2))
				env, _ := parseLine(t, lines[1])
				lines[1] = bytes.Replace(lines[1], []byte(env.S), []byte(env.S[:10]+`\n`+env.S[10:]), 1)
				writeLines(t, f.path(2), lines)
			},
			want: []string{probSignature},
		},
		{
			name: "delete a line",
			tamper: func(t *testing.T, f *tamperFixture) {
				lines := readLines(t, f.path(0))
				writeLines(t, f.path(0), append(lines[:2], lines[3:]...))
			},
			want: []string{probSeqGap, probPrev, probSegmentHash},
			seq:  3,
		},
		{
			name: "delete the last line of the active segment",
			tamper: func(t *testing.T, f *tamperFixture) {
				lines := readLines(t, f.path(2))
				writeLines(t, f.path(2), lines[:len(lines)-1])
			},
			want: nil, // undetectable without an anchor or a later record — documented limitation
		},
		{
			name: "swap two lines",
			tamper: func(t *testing.T, f *tamperFixture) {
				lines := readLines(t, f.path(1))
				lines[2], lines[3] = lines[3], lines[2]
				writeLines(t, f.path(1), lines)
			},
			want: []string{probSeqGap, probPrev, probSegmentHash},
		},
		{
			name: "insert a forged line",
			tamper: func(t *testing.T, f *tamperFixture) {
				lines := readLines(t, f.path(2))
				_, b := parseLine(t, lines[2])
				b.Data = []byte(`{"cycle":999,"forged":true}`)
				forged := reencode(t, f.other, b)
				writeLines(t, f.path(2), append(lines[:3], append([][]byte{forged}, lines[3:]...)...))
			},
			want: []string{probSignature, probSeqGap, probPrev},
		},
		{
			name: "rewrite a record with the real key but break the chain",
			tamper: func(t *testing.T, f *tamperFixture) {
				lines := readLines(t, f.path(2))
				_, b := parseLine(t, lines[2])
				b.Data = []byte(`{"cycle":1,"rewritten":true}`)
				lines[2] = reencode(t, f.priv, b)
				writeLines(t, f.path(2), lines)
			},
			want: []string{probPrev},
		},
		{
			name: "edit an earlier segment file without touching any record",
			tamper: func(t *testing.T, f *tamperFixture) {
				lines := readLines(t, f.path(0))
				lines[2] = append(bytes.TrimSuffix(lines[2], []byte("\n")), []byte(" \n")...)
				writeLines(t, f.path(0), lines)
			},
			want: []string{probSegmentHash},
		},
		{
			name: "rename a segment to another day",
			tamper: func(t *testing.T, f *tamperFixture) {
				os.Rename(f.path(1), segPath(f.dir, "ledger-2026-10-30"))
			},
			want: []string{probSegmentHash, probSeqGap},
		},
		{
			name: "delete a whole sealed segment",
			tamper: func(t *testing.T, f *tamperFixture) {
				os.Remove(f.path(1))
			},
			want: []string{probSeqGap, probPrev, probSegmentHash},
		},
		{
			name: "truncate a sealed segment mid-line",
			tamper: func(t *testing.T, f *tamperFixture) {
				b, _ := os.ReadFile(f.path(0))
				os.WriteFile(f.path(0), b[:len(b)-20], 0o644)
			},
			want: []string{probParse, probSegmentHash},
		},
		{
			name: "extra key in an envelope",
			tamper: func(t *testing.T, f *tamperFixture) {
				lines := readLines(t, f.path(1))
				lines[1] = bytes.Replace(lines[1], []byte(`{"h":`), []byte(`{"x":"1","h":`), 1)
				writeLines(t, f.path(1), lines)
			},
			want: []string{probParse},
		},
		{
			name: "duplicate b key in an envelope",
			tamper: func(t *testing.T, f *tamperFixture) {
				lines := readLines(t, f.path(1))
				lines[1] = bytes.Replace(lines[1], []byte(`}`+"\n"), []byte(`,"b":"{}"}`+"\n"), 1)
				writeLines(t, f.path(1), lines)
			},
			want: []string{probParse},
		},
		{
			name: "case-variant key in an envelope",
			tamper: func(t *testing.T, f *tamperFixture) {
				lines := readLines(t, f.path(1))
				lines[1] = bytes.Replace(lines[1], []byte(`"b":`), []byte(`"B":`), 1)
				writeLines(t, f.path(1), lines)
			},
			want: []string{probParse},
		},
		{
			name: "corrupt a blob",
			tamper: func(t *testing.T, f *tamperFixture) {
				var buf bytes.Buffer
				zw := gzip.NewWriter(&buf)
				zw.Write([]byte("<html>edited</html>"))
				zw.Close()
				os.WriteFile(filepath.Join(f.dir, "blobs", f.blob[:2], f.blob+".gz"), buf.Bytes(), 0o644)
			},
			want: []string{probBlobCorrupt},
			seq:  6,
		},
		{
			name: "blob is not gzip",
			tamper: func(t *testing.T, f *tamperFixture) {
				os.WriteFile(filepath.Join(f.dir, "blobs", f.blob[:2], f.blob+".gz"), []byte("plain"), 0o644)
			},
			want: []string{probBlobCorrupt},
		},
		{
			name: "delete a blob",
			tamper: func(t *testing.T, f *tamperFixture) {
				os.Remove(filepath.Join(f.dir, "blobs", f.blob[:2], f.blob+".gz"))
			},
			want: []string{probBlobMissing},
			seq:  6,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTamperFixture(t)
			before := verifyRO(t, f.dir, f.clk)
			requireOK(t, before)
			tc.tamper(t, f)
			rep := verifyRO(t, f.dir, f.clk)
			got := problems(rep)
			if len(tc.want) == 0 {
				if !rep.OK {
					t.Fatalf("unexpected failures:\n%s", dumpReport(rep))
				}
				return
			}
			if rep.OK || rep.FailuresTotal == 0 {
				t.Fatalf("tampering not detected:\n%s", dumpReport(rep))
			}
			for _, p := range tc.want {
				if got[p] == 0 {
					t.Errorf("missing %s; got %v:\n%s", p, sortedKeys(got), dumpReport(rep))
				}
			}
			if tc.seq != 0 && rep.Failures[0].Seq != tc.seq {
				t.Errorf("first failure at seq %d, want %d:\n%s", rep.Failures[0].Seq, tc.seq, dumpReport(rep))
			}
			for _, fl := range rep.Failures {
				if fl.Segment == "" || fl.Line == 0 || fl.Detail == "" {
					t.Errorf("failure lacks location/detail: %+v", fl)
				}
			}
			if !strings.HasPrefix(rep.Segments[0], "ledger-") {
				t.Errorf("segments %v", rep.Segments)
			}
		})
	}
}
