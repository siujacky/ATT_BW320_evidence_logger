package export

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

func buildIncidentBundle(t *testing.T) (*scenario, contracts.ExportInfo) {
	t.Helper()
	s := buildScenario(t)
	e, _ := newTestExporter(t, s, t.TempDir())
	info, err := e.Build(context.Background(), contracts.ExportRequest{IncidentID: s.incidentID})
	if err != nil {
		t.Fatal(err)
	}
	mustVerifyReport(t, info.Path)
	return s, info
}

type zipEntry struct {
	name string
	data []byte
}

// zipEdit describes a modification of a bundle for tamper tests.
type zipEdit struct {
	edit        func(name string, data []byte) ([]byte, bool) // keep=false drops the entry
	extra       []zipEntry                                    // appended (names may repeat)
	fixManifest bool                                          // recompute MANIFEST.sha256 afterwards
}

func rewriteZip(t *testing.T, src string, ed zipEdit) string {
	t.Helper()
	z := readZip(t, src)
	var entries []zipEntry
	for _, n := range z.names {
		data := z.files[n]
		if ed.edit != nil {
			var keep bool
			if data, keep = ed.edit(n, data); !keep {
				continue
			}
		}
		entries = append(entries, zipEntry{n, data})
	}
	entries = append(entries, ed.extra...)
	if ed.fixManifest {
		var lines []string
		for _, e := range entries {
			if e.name != manifestName {
				lines = append(lines, sha256Hex(e.data)+"  "+e.name)
			}
		}
		sort.Slice(lines, func(i, j int) bool { return lines[i][66:] < lines[j][66:] })
		for i := range entries {
			if entries[i].name == manifestName {
				entries[i].data = []byte(strings.Join(lines, "\n") + "\n")
			}
		}
	}
	out := filepath.Join(t.TempDir(), filepath.Base(src))
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for _, e := range entries {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: e.name, Method: zip.Deflate})
		if err != nil {
			t.Fatal(err)
		}
		w.Write(e.data)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return out
}

// replaceRecord re-writes record line idx (0-based) of a segment with a modified body whose
// h is recomputed (so only the signature and the chain can detect the change).
func replaceRecord(t *testing.T, seg []byte, idx int, mutate func(*model.Body)) []byte {
	t.Helper()
	lines := bytes.Split(bytes.TrimSuffix(seg, []byte("\n")), []byte("\n"))
	if idx < 0 {
		idx += len(lines)
	}
	env, body, err := parseLine(lines[idx])
	if err != nil {
		t.Fatal(err)
	}
	mutate(&body)
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	env.B, env.H = string(b), sha256Hex(b)
	if lines[idx], err = json.Marshal(env); err != nil {
		t.Fatal(err)
	}
	return append(bytes.Join(lines, []byte("\n")), '\n')
}

func TestOpenBundleRoundTrip(t *testing.T) {
	s, info := buildIncidentBundle(t)
	b, err := OpenBundle(info.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if b.Path() != info.Path {
		t.Errorf("Path = %s", b.Path())
	}

	segs, err := b.Segments()
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 2 {
		t.Fatalf("segments = %+v", segs)
	}
	for i, fi := range []int{0, 2} {
		fs := s.f.segs[fi]
		g := segs[i]
		if g.Name != fs.name || g.Path != "ledger/"+fs.name+".jsonl" || !g.Date.Equal(fs.date) || g.FirstSeq != fs.first ||
			g.LastSeq != fs.last || g.Records != fs.records || g.Compressed || g.Active {
			t.Errorf("segment %d = %+v, want %s %d-%d (%d)", i, g, fs.name, fs.first, fs.last, fs.records)
		}
	}

	// Scan returns exactly the records of the included segments, unchanged and in order.
	var want []struct {
		env  model.Envelope
		body model.Body
	}
	for _, r := range s.f.records() {
		if r.body.Seq <= s.f.segs[0].last || (r.body.Seq >= s.f.segs[2].first && r.body.Seq <= s.f.segs[2].last) {
			want = append(want, r)
		}
	}
	var got []model.Envelope
	if err := b.Scan(0, func(env model.Envelope, body model.Body) error {
		got = append(got, env)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("Scan returned %d records, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i].env {
			t.Fatalf("record %d differs", i)
		}
	}

	// Scan from the middle, early stop and error propagation.
	mid := s.f.segs[2].first + 10
	n := 0
	first := uint64(0)
	if err := b.Scan(mid, func(_ model.Envelope, body model.Body) error {
		if n == 0 {
			first = body.Seq
		}
		n++
		return nil
	}); err != nil || first != mid || n != int(s.f.segs[2].last-mid+1) {
		t.Errorf("Scan(mid) first=%d n=%d err=%v", first, n, err)
	}
	n = 0
	if err := b.Scan(0, func(model.Envelope, model.Body) error {
		n++
		if n == 3 {
			return contracts.ErrStop
		}
		return nil
	}); err != nil || n != 3 {
		t.Errorf("ErrStop: n=%d err=%v", n, err)
	}
	boom := errors.New("boom")
	if err := b.Scan(0, func(model.Envelope, model.Body) error { return boom }); !errors.Is(err, boom) {
		t.Errorf("Scan error = %v", err)
	}

	// ScanTime agrees with the ledger for a window inside the bundle.
	from, to := s.opened.Add(-time.Minute), s.closed.Add(time.Minute)
	var a, c []uint64
	b.ScanTime(from, to, func(_ model.Envelope, body model.Body) error { a = append(a, body.Seq); return nil })
	s.f.ScanTime(from, to, func(_ model.Envelope, body model.Body) error { c = append(c, body.Seq); return nil })
	if len(a) == 0 || fmt.Sprint(a) != fmt.Sprint(c) {
		t.Errorf("ScanTime = %v, want %v", a, c)
	}
	var none int
	b.ScanTime(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC), time.Date(2026, 10, 2, 23, 0, 0, 0, time.UTC),
		func(model.Envelope, model.Body) error { none++; return nil })
	if none != 0 {
		t.Errorf("ScanTime over an omitted day returned %d records", none)
	}

	// Record by seq.
	for _, seq := range []uint64{0, s.f.segs[0].last, s.f.segs[2].first, mid, s.f.segs[2].last} {
		env, body, err := b.Record(seq)
		wantEnv, _, _ := s.f.Record(seq)
		if err != nil || body.Seq != seq || env != wantEnv {
			t.Errorf("Record(%d) = seq %d, err %v", seq, body.Seq, err)
		}
	}
	for _, seq := range []uint64{s.f.segs[1].first, s.f.segs[3].last, 1 << 40} {
		if _, _, err := b.Record(seq); !errors.Is(err, contracts.ErrNotFound) {
			t.Errorf("Record(%d) err = %v, want ErrNotFound", seq, err)
		}
	}

	// Blobs and segments.
	for id := range blobRefsOf(t, s.f, "ledger-2026-10-01", "ledger-2026-10-03") {
		data, err := b.GetBlob(id)
		if err != nil || !bytes.Equal(data, s.f.blobs[id]) {
			t.Errorf("GetBlob(%s): %v", id, err)
		}
	}
	for _, id := range []string{s.day2Blob, strings.Repeat("0", 64), "xyz", "../MANIFEST.sha256"} {
		if _, err := b.GetBlob(id); !errors.Is(err, contracts.ErrNotFound) {
			t.Errorf("GetBlob(%q) err = %v, want ErrNotFound", id, err)
		}
	}
	for _, name := range []string{"ledger-2026-10-03", "ledger-2026-10-03.jsonl"} {
		rc, err := b.OpenSegment(name)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(rc)
		rc.Close()
		if !bytes.Equal(data, s.f.segs[2].data) {
			t.Errorf("OpenSegment(%s) differs", name)
		}
	}
	if _, err := b.OpenSegment("ledger-2026-10-02"); !errors.Is(err, contracts.ErrNotFound) {
		t.Errorf("OpenSegment(omitted) err = %v", err)
	}

	// Concurrent lookups (run with -race).
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				seq := []uint64{0, mid, s.f.segs[2].last}[(g+i)%3]
				if _, body, err := b.Record(seq); err != nil || body.Seq != seq {
					t.Errorf("concurrent Record(%d): %v", seq, err)
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestBundleCorruptBlobAndLine(t *testing.T) {
	s, info := buildIncidentBundle(t)
	var victim string
	for id := range blobRefsOf(t, s.f, "ledger-2026-10-03") {
		victim = id
		break
	}
	path := rewriteZip(t, info.Path, zipEdit{edit: func(name string, data []byte) ([]byte, bool) {
		switch name {
		case "blobs/" + victim:
			return append([]byte("tampered "), data...), true
		case "ledger/ledger-2026-10-03.jsonl":
			return append(data, []byte("not json\n")...), true
		}
		return data, true
	}})
	b, err := OpenBundle(path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, err := b.GetBlob(victim); err == nil || errors.Is(err, contracts.ErrNotFound) {
		t.Errorf("GetBlob of a corrupt blob: err = %v, want a hash mismatch", err)
	}
	err = b.Scan(0, func(model.Envelope, model.Body) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "ledger-2026-10-03 line") {
		t.Errorf("Scan over a bad line: %v", err)
	}
	segs, _ := b.Segments()
	if segs[1].Records != s.f.segs[2].records+1 {
		t.Errorf("Records should count every line: %d", segs[1].Records)
	}
}

func TestOpenBundleRejects(t *testing.T) {
	_, info := buildIncidentBundle(t)
	notZip := filepath.Join(t.TempDir(), "x.zip")
	os.WriteFile(notZip, []byte("this is not a zip"), 0o644)
	tests := []struct {
		name string
		path string
		want string
	}{
		{"not a zip", notZip, "open bundle"},
		{"missing file", filepath.Join(t.TempDir(), "absent.zip"), "open bundle"},
		{"no ledger", rewriteZip(t, info.Path, zipEdit{edit: func(n string, d []byte) ([]byte, bool) {
			return d, !strings.HasPrefix(n, "ledger/")
		}}), "not an att-monitor evidence bundle"},
		{"duplicate entry", rewriteZip(t, info.Path, zipEdit{extra: []zipEntry{{"README.txt", []byte("other")}}}), "more than one entry"},
		{"unsafe name", rewriteZip(t, info.Path, zipEdit{extra: []zipEntry{{"../evil.txt", []byte("x")}}}), "unsafe entry name"},
		{"backslash name", rewriteZip(t, info.Path, zipEdit{extra: []zipEntry{{`blobs\evil`, []byte("x")}}}), "unsafe entry name"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, err := OpenBundle(tc.path)
			if err == nil {
				b.Close()
				t.Fatal("OpenBundle succeeded")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestVerifyManifest(t *testing.T) {
	_, info := buildIncidentBundle(t)
	tests := []struct {
		name string
		edit zipEdit
		want string // "" = valid
	}{
		{"intact", zipEdit{}, ""},
		{"intact after re-zipping", zipEdit{fixManifest: true}, ""},
		{"modified report", zipEdit{edit: func(n string, d []byte) ([]byte, bool) {
			if n == "REPORT.html" {
				return bytes.Replace(d, []byte("ISP_OUTAGE"), []byte("ONLINE"), 1), true
			}
			return d, true
		}}, "SHA-256 mismatch for REPORT.html"},
		{"modified ledger line", zipEdit{edit: func(n string, d []byte) ([]byte, bool) {
			if n == "ledger/ledger-2026-10-03.jsonl" {
				return bytes.Replace(d, []byte("TestNet"), []byte("EvilNet"), 1), true
			}
			return d, true
		}}, "SHA-256 mismatch for ledger/ledger-2026-10-03.jsonl"},
		{"extra file", zipEdit{extra: []zipEntry{{"blobs/extra", []byte("x")}}}, "not listed in the manifest: blobs/extra"},
		{"removed file", zipEdit{edit: func(n string, d []byte) ([]byte, bool) { return d, n != "README.txt" }}, "listed file is missing: README.txt"},
		{"duplicate entry", zipEdit{extra: []zipEntry{{"REPORT.html", []byte("<html>fake</html>")}}}, "more than one entry"},
		{"unsafe name", zipEdit{extra: []zipEntry{{"../../evil.bat", []byte("x")}}}, "unsafe entry name"},
		{"no manifest", zipEdit{edit: func(n string, d []byte) ([]byte, bool) { return d, n != manifestName }}, "MANIFEST.sha256 is missing"},
		{"malformed manifest", zipEdit{edit: func(n string, d []byte) ([]byte, bool) {
			if n == manifestName {
				return append(d, []byte("not a manifest line\n")...), true
			}
			return d, true
		}}, "is malformed"},
		{"manifest lists itself", zipEdit{edit: func(n string, d []byte) ([]byte, bool) {
			if n == manifestName {
				return append(d, []byte(strings.Repeat("a", 64)+"  "+manifestName+"\n")...), true
			}
			return d, true
		}}, "lists itself"},
		{"manifest lists a file twice", zipEdit{edit: func(n string, d []byte) ([]byte, bool) {
			if n == manifestName {
				first := d[:bytes.IndexByte(d, '\n')+1]
				return append(d, first...), true
			}
			return d, true
		}}, "twice"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := info.Path
			if tc.edit.edit != nil || tc.edit.extra != nil || tc.edit.fixManifest {
				path = rewriteZip(t, info.Path, tc.edit)
			}
			err := VerifyManifest(path)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("VerifyManifest: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrManifest) || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want ErrManifest containing %q", err, tc.want)
			}
		})
	}
	if err := VerifyManifest(filepath.Join(t.TempDir(), "absent.zip")); err == nil || errors.Is(err, ErrManifest) {
		t.Errorf("missing file: %v", err)
	}
}
