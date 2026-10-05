package export

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"attmonitor/internal/contracts"
)

// TestWriteSampleBundle is a developer aid, not a check: with EXPORT_SAMPLE_DIR set it writes a
// bundle built from the synthetic test ledger, plus its REPORT.html, README.txt, report.json,
// public-key.txt and MANIFEST.sha256, so the report can be reviewed in a browser without a
// real ledger. It is skipped otherwise.
func TestWriteSampleBundle(t *testing.T) {
	dir := os.Getenv("EXPORT_SAMPLE_DIR")
	if dir == "" {
		t.Skip("EXPORT_SAMPLE_DIR not set")
	}
	s := buildScenario(t)
	e, _ := newTestExporter(t, s, dir)
	info, err := e.Build(context.Background(), contracts.ExportRequest{IncidentID: s.incidentID, PreparedBy: "Homeowner", Notes: "For AT&T ticket 12345", Requester: "web 127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(info.Path)
	z := readZip(t, info.Path)
	for _, n := range []string{"REPORT.html", "README.txt", "report.json", "keys/public-key.txt", "MANIFEST.sha256"} {
		os.WriteFile(filepath.Join(dir, filepath.Base(n)), z.files[n], 0o644)
	}
}
