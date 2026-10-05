package ticket

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// samplePath is the real-situation report built from synthetic records, kept for visual review.
var samplePath = filepath.Join("..", "..", "testdata", "ticket", "sample.html")

// sampleReport renders the sample.
func sampleReport(t *testing.T) []byte {
	t.Helper()
	s := realScenario(t)
	o := s.options()
	o.Customer = Customer{Name: "Jordan Example", Address: "123 Example St, Springfield"}
	page, err := mustBuild(t, s, o).HTML()
	if err != nil {
		t.Fatal(err)
	}
	return page
}

// TestWriteSample writes testdata/ticket/sample.html:
// ATTMON_TICKET_SAMPLE=1 go test ./internal/ticket -run TestWriteSample
func TestWriteSample(t *testing.T) {
	if os.Getenv("ATTMON_TICKET_SAMPLE") != "1" {
		t.Skip("set ATTMON_TICKET_SAMPLE=1 to write testdata/ticket/sample.html")
	}
	page := sampleReport(t)
	if err := os.MkdirAll(filepath.Dir(samplePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(samplePath, page, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s (%d bytes)", samplePath, len(page))
}

// TestSampleCurrent: the checked-in sample is what the code renders (it had gone stale).
func TestSampleCurrent(t *testing.T) {
	if os.Getenv("ATTMON_TICKET_SAMPLE") == "1" {
		t.Skip("being rewritten")
	}
	want, err := os.ReadFile(samplePath)
	if err != nil {
		t.Fatal(err)
	}
	if got := sampleReport(t); !bytes.Equal(bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n")), got) {
		t.Errorf("%s is stale: regenerate it with ATTMON_TICKET_SAMPLE=1 go test ./internal/ticket -run TestWriteSample", samplePath)
	}
}
