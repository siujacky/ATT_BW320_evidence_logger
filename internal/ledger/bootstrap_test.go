package ledger

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"attmonitor/internal/model"
)

func TestImportBootstrap(t *testing.T) {
	s, _, _ := newLedger(t)
	src := t.TempDir()
	files := map[string][]byte{
		"CAPTURE-NOTES.txt":                []byte("Captured 2026-10-04 by the owner.\r\nbbevent was ON before the change.\n"),
		"b.html":                           []byte("<html>events before</html>"),
		"a-c.txt":                          []byte("sorting check"),
		"dup1.txt":                         []byte("same bytes"),
		"dup2.txt":                         []byte("same bytes"),
		"initial-snapshot/sysinfo.html":    []byte("<html>\xa9 sysinfo</html>"),
		"initial-snapshot/deep/blob.bin":   {0, 1, 2, 3},
		"initial-snapshot/MANIFEST.sha256": []byte("abc  sysinfo.html\n"),
	}
	mtime := time.Date(2026, 10, 4, 22, 10, 44, 123456700, time.FixedZone("CDT", -5*3600))
	for rel, b := range files {
		p := filepath.Join(src, filepath.FromSlash(rel))
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		os.Chtimes(p, mtime, mtime)
	}
	ref, err := s.ImportBootstrap(src)
	if err != nil {
		t.Fatal(err)
	}
	_, body, err := s.Record(ref.Seq)
	if err != nil || body.Type != model.TypeBootstrapImport {
		t.Fatalf("record %+v %v", body, err)
	}
	imp := decodeData[model.BootstrapImport](t, body)
	wantOrder := []string{
		"CAPTURE-NOTES.txt", "a-c.txt", "b.html", "dup1.txt", "dup2.txt",
		"initial-snapshot/MANIFEST.sha256", "initial-snapshot/deep/blob.bin", "initial-snapshot/sysinfo.html",
	}
	if len(imp.Files) != len(wantOrder) {
		t.Fatalf("files %+v", imp.Files)
	}
	abs, _ := filepath.Abs(src)
	if imp.SourceDir != abs || imp.Notes != string(files["CAPTURE-NOTES.txt"]) {
		t.Fatalf("source %q notes %q", imp.SourceDir, imp.Notes)
	}
	var wantBlobs []string
	seen := map[string]bool{}
	for i, f := range imp.Files {
		content := files[wantOrder[i]]
		if f.Path != wantOrder[i] || f.Size != int64(len(content)) || f.SHA256 != sha256Hex(content) ||
			f.ModTime != mtime.UTC().Format(time.RFC3339Nano) {
			t.Fatalf("file %d = %+v", i, f)
		}
		got, err := s.GetBlob(f.SHA256)
		if err != nil || !bytes.Equal(got, content) {
			t.Fatalf("blob for %s: %v", f.Path, err)
		}
		if !seen[f.SHA256] {
			seen[f.SHA256] = true
			wantBlobs = append(wantBlobs, f.SHA256)
		}
	}
	if len(body.Blobs) != len(wantBlobs) || len(body.Blobs) != 7 {
		t.Fatalf("blobs %v", body.Blobs)
	}
	for i := range wantBlobs {
		if body.Blobs[i] != wantBlobs[i] {
			t.Fatalf("blobs order %v", body.Blobs)
		}
	}
	rep, err := s.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireOK(t, rep)
	if rep.BlobsChecked != 7 {
		t.Fatalf("blobs checked %d", rep.BlobsChecked)
	}
}

func TestImportBootstrapEdgeCases(t *testing.T) {
	s, _, _ := newLedger(t)
	if _, err := s.ImportBootstrap(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing dir accepted")
	}
	f := filepath.Join(t.TempDir(), "file.txt")
	os.WriteFile(f, []byte("x"), 0o644)
	if _, err := s.ImportBootstrap(f); err == nil {
		t.Fatal("file accepted as dir")
	}
	ref, err := s.ImportBootstrap(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, body, _ := s.Record(ref.Seq)
	imp := decodeData[model.BootstrapImport](t, body)
	if len(imp.Files) != 0 || imp.Notes != "" || len(body.Blobs) != 0 {
		t.Fatalf("empty import %+v", imp)
	}
	// CAPTURE-NOTES.txt in a subdirectory is a file, not the notes.
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "sub"), 0o755)
	os.WriteFile(filepath.Join(dir, "sub", "CAPTURE-NOTES.txt"), []byte("nested"), 0o644)
	ref, err = s.ImportBootstrap(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, body, _ = s.Record(ref.Seq)
	if imp := decodeData[model.BootstrapImport](t, body); imp.Notes != "" || len(imp.Files) != 1 {
		t.Fatalf("nested notes %+v", imp)
	}
}
