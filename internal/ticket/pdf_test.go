package ticket

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestFileURL(t *testing.T) {
	if got := fileURL(`C:\Users\Dell\AppData\Local\Temp\a b\ticket.html`); filepath.Separator == '\\' && got != "file:///C:/Users/Dell/AppData/Local/Temp/a%20b/ticket.html" {
		t.Errorf("fileURL = %q", got)
	}
	if got := fileURL("/tmp/x#1.html"); !strings.HasPrefix(got, "file:///") || strings.Contains(got, "#") {
		t.Errorf("fileURL = %q", got)
	}
}

func TestIsCompletePDF(t *testing.T) {
	if !isCompletePDF([]byte("%PDF-1.4\n...\n%%EOF\n")) {
		t.Error("complete PDF rejected")
	}
	for _, b := range []string{"", "%PDF-1.4\n...", "<html>%%EOF"} {
		if isCompletePDF([]byte(b)) {
			t.Errorf("%q accepted", b)
		}
	}
}

func TestPrintPDFErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := PrintPDF(context.Background(), filepath.Join(dir, "missing.html"), filepath.Join(dir, "x.pdf")); err == nil {
		t.Error("missing HTML accepted")
	}
	page := filepath.Join(dir, "p.html")
	if err := os.WriteFile(page, []byte("<p>x</p>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := PrintPDF(context.Background(), page, page); err == nil {
		t.Error("printing over the HTML file accepted")
	}
}

// pdfPage is what pdfPagesScript reads from a printed page (points; y from the page's top).
type pdfPage struct {
	W, H  float64
	Text  string  // the page's text as the PDF viewer extracts it (lines end in "\r\n")
	Low   float64 // the bottom of the lowest text above the page's margin boxes (-1: unknown)
	Digit float64 // the median height of the digits' glyph boxes: the scale text is printed at (-1: unknown)
	// Pdfium: read with pdfium, the engine of the Chrome and Edge PDF viewers (else with pypdf,
	// which gives the text only).
	Pdfium bool
}

// pdfPagesScript reads a PDF with pypdfium2 or, without it, with pypdf.
const pdfPagesScript = `import sys, json, statistics
try:
    import pypdfium2 as pdfium
except ImportError:
    pdfium = None
out = []
if pdfium is None:
    import pypdf
    for p in pypdf.PdfReader(sys.argv[1]).pages:
        out.append({"W": float(p.mediabox.width), "H": float(p.mediabox.height), "Text": p.extract_text() or "", "Low": -1, "Digit": -1, "Pdfium": False})
else:
    pdf = pdfium.PdfDocument(sys.argv[1])
    for i in range(len(pdf)):
        page = pdf[i]
        w, h = page.get_size()
        tp = page.get_textpage()
        n = tp.count_chars()
        chars = tp.get_text_range(0, n) if n else ""
        low, digits = 0.0, []
        for k in range(min(n, len(chars))):
            c = chars[k]
            if not c.strip():
                continue
            l, b, r, t = tp.get_charbox(k)
            if h - b < h - 0.55 * 72:
                low = max(low, h - b)
            if c.isdigit():
                digits.append(t - b)
        out.append({"W": w, "H": h, "Text": tp.get_text_bounded(), "Low": low, "Digit": statistics.median(digits) if digits else 0, "Pdfium": True})
print(json.dumps(out))
`

// findPython returns a Python interpreter that can import every module named, or "".
func findPython(t *testing.T, modules ...string) string {
	t.Helper()
	for _, name := range []string{"python", "python3", "py"} {
		p, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		if err := exec.Command(p, "-c", "import "+strings.Join(modules, ", ")).Run(); err == nil {
			return p
		}
	}
	return ""
}

// printReport prints a report with the browser found on this computer; it skips the test when
// there is none (or in short mode) and returns the PDF's pages as pdfium (or pypdf) reads them
// (nil when Python with either is not available).
func printReport(t *testing.T, rep *Report) []pdfPage {
	t.Helper()
	if testing.Short() {
		t.Skip("short mode")
	}
	if len(browserCandidates()) == 0 {
		t.Skip("no Microsoft Edge or Google Chrome on this computer")
	}
	page, err := rep.HTML()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	htmlPath := filepath.Join(dir, "ticket page.html")
	pdfPath := filepath.Join(dir, "ticket.pdf")
	if err := os.WriteFile(htmlPath, page, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	browser, err := PrintPDF(ctx, htmlPath, pdfPath)
	if err != nil {
		t.Fatalf("PrintPDF: %v", err)
	}
	t.Logf("printed with %s", browser)
	data, err := os.ReadFile(pdfPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "%PDF-") || !isCompletePDF(data) {
		t.Fatalf("not a complete PDF (%d bytes)", len(data))
	}
	if leftovers, _ := filepath.Glob(filepath.Join(dir, ".ticket.pdf.*.tmp")); len(leftovers) != 0 {
		t.Errorf("temporary files left: %v", leftovers)
	}
	python := findPython(t, "pypdfium2")
	if python == "" {
		if python = findPython(t, "pypdf"); python == "" {
			return nil
		}
	}
	cmd := exec.Command(python, "-c", pdfPagesScript, pdfPath)
	cmd.Env = append(os.Environ(), "PYTHONIOENCODING=utf-8", "PYTHONUTF8=1")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("pypdfium2: %v\n%s", err, out)
	}
	var pages []pdfPage
	if err := json.Unmarshal(out, &pages); err != nil {
		t.Fatalf("pypdfium2 output: %v\n%s", err, out)
	}
	return pages
}

// marginText matches the texts of a page's margin boxes.
var marginText = regexp.MustCompile(`AT&T Fiber service problem evidence, \d{4}-\d{2}-\d{2} \d{2}:\d{2} to \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC(, [^\r\n]*?)?\s*Page \d+ of \d+`)

// bodyText is a page's text without its margin boxes, whitespace collapsed.
func bodyText(p pdfPage) string { return oneLine(marginText.ReplaceAllString(p.Text, " ")) }

// checkPages checks what every printed report must satisfy: US Letter pages, each numbered
// "Page i of n" and identified by the window in its margin; page 1 holds the whole summary sheet
// (the details start at the top of page 2); and no page but the last is a near-empty leftover.
func checkPages(t *testing.T, pages []pdfPage, identity string) {
	t.Helper()
	if len(pages) < 2 {
		t.Fatalf("%d pages", len(pages))
	}
	for i, p := range pages {
		if int(p.W+0.5) != 612 || int(p.H+0.5) != 792 {
			t.Errorf("page %d is %.0f x %.0f pt, want US Letter 612 x 792", i+1, p.W, p.H)
		}
		text := oneLine(p.Text)
		if want := fmt.Sprintf("Page %d of %d", i+1, len(pages)); !strings.Contains(text, want) {
			t.Errorf("page %d lacks %q", i+1, want)
		}
		if !strings.Contains(text, identity) {
			t.Errorf("page %d lacks its identity %q", i+1, identity)
		}
		if p.Pdfium && i > 0 && i < len(pages)-1 && p.Low < 7.5*72 {
			t.Errorf("page %d ends %.1f in from the top: a near-empty page before the last", i+1, p.Low/72)
		}
	}
	for _, want := range []string{"Summary for AT&T", "Requested action"} {
		if !strings.Contains(bodyText(pages[0]), want) {
			t.Errorf("page 1 lacks %q", want)
		}
	}
	// The details open page 2: with the gateway, or with the monitoring coverage paragraph when it
	// did not fit on page 1.
	details := "Gateway "
	if !regexp.MustCompile(`Monitoring coverage (Continuous monitoring|The monitor recorded)`).MatchString(bodyText(pages[0])) {
		details = "Monitoring coverage " // the heading, not "(see Monitoring coverage)" in a summary text
	}
	if b := bodyText(pages[1]); !strings.HasPrefix(b, details) {
		t.Errorf("page 2 does not start with the details (the summary sheet overflowed):\n%.300s", b)
	}
	if last := pages[len(pages)-1]; last.Pdfium && last.Low < 2.5*72 {
		t.Errorf("the last page ends %.1f in from the top: a near-empty page", last.Low/72)
	}
}

// TestPrintPDF prints the real-situation report and checks its pages: the summary sheet and two
// or three pages of details (doc.go), numbered and identified, with values that copy correctly.
func TestPrintPDF(t *testing.T) {
	s := realScenario(t)
	o := s.options()
	o.Verification = cliVerification
	rep := mustBuild(t, s, o)
	pages := printReport(t, rep)
	if pages == nil {
		t.Skip("python with pypdfium2 or pypdf not available: PDF content not checked")
	}
	if len(pages) > 4 {
		t.Errorf("%d pages, want at most 4 (a summary sheet and two or three pages of details)", len(pages))
	}
	checkPages(t, pages, "AT&T Fiber service problem evidence, 2026-10-04 14:00 to 2026-10-05 14:00 UTC")
	var all strings.Builder
	for _, p := range pages {
		all.WriteString(p.Text)
	}
	text := oneLine(all.String())
	first := bodyText(pages[0])
	n := len(s.snaps) + 1
	alarm := "ALARM flag was set in " + itoa(n) + " of " + itoa(n) + " readings (100%)"
	for _, want := range []string{alarm, fixSerial, "Requested action", "Ledger signing key", "Verification* verified OK"} {
		if !strings.Contains(first, want) {
			t.Errorf("page 1 lacks %q:\n%s", want, first)
		}
	}
	for _, want := range []string{"1791151188", "Gateway low-Rx WARNING threshold -29.2 dBm", "Fiber link down"} {
		if !strings.Contains(text, want) {
			t.Errorf("PDF text lacks %q", want)
		}
	}
	// Values are never split across lines: the Chrome and Edge viewers join a line-final hyphen
	// with the next line ("UTC-|05:00" became "UTC05:00", "Wi-|Fi" "WiFi").
	for _, bad := range []string{"UTC0", "UTC1", "WiFi", "lowRx", "-\r\n", "-\n"} {
		if strings.Contains(all.String(), bad) {
			t.Errorf("PDF text contains %q: a value was split across lines", bad)
		}
	}
	wantContains(t, "pdf", text, "(UTC-05:00 per its own clock)", "Wi-Fi 5 GHz")
	// Chart labels are printed once (a white text halo printed each label twice into the text).
	if c := strings.Count(text, "Gateway low-Rx ALARM threshold -29.5 dBm"); c != 1 {
		t.Errorf("the ALARM threshold label appears %d times in the PDF text", c)
	}
	if strings.Contains(text, "GGaatt") {
		t.Error("doubled chart label text")
	}
}

// TestPrintPDFStress prints a bad day - 16 outages with fiber flaps, gateway restarts, monitoring
// gaps and long customer fields: page 1 still holds the whole summary sheet (it overflowed onto an
// almost empty page 2, and the brief table split), and no page is a near-empty leftover.
func TestPrintPDFStress(t *testing.T) {
	ss := stressScenario(t)
	o := ss.options()
	o.Customer = stressCustomer()
	o.Verification = cliVerification
	pages := printReport(t, mustBuild(t, ss, o))
	if pages == nil {
		t.Skip("python with pypdfium2 or pypdf not available: PDF content not checked")
	}
	checkPages(t, pages, "AT&T Fiber service problem evidence, 2026-10-04 14:00 to 2026-10-05 14:00 UTC, account 123456789012")
	first := bodyText(pages[0])
	for _, want := range []string{"16 incidents attributed to AT&T", "including during 16 outages attributed to AT&T", stressCustomer().Address,
		"Monitoring coverage Continuous monitoring"} {
		if !strings.Contains(first, want) {
			t.Errorf("page 1 lacks %q:\n%s", want, first)
		}
	}
}

// TestPrintPDFClearedAlarm prints the real day on which the alarm cleared after a step change
// across a loss of light (its long optical paragraph pushed a pointer line onto a page of its
// own): no page is a near-empty leftover and page 1 states the clearing.
func TestPrintPDFClearedAlarm(t *testing.T) {
	cs := clearedScenario(t)
	pages := printReport(t, mustBuild(t, cs, cs.options()))
	if pages == nil {
		t.Skip("python with pypdfium2 or pypdf not available: PDF content not checked")
	}
	checkPages(t, pages, "AT&T Fiber service problem evidence, 2026-10-04 14:00 to 2026-10-05 14:00 UTC")
	first := bodyText(pages[0])
	for _, want := range []string{"ALARM was set from the first reading until it cleared at", "rose by 9.5 dB",
		"these records cannot show who made the change", "Please confirm whether any work was done on this line"} {
		if !strings.Contains(first, want) {
			t.Errorf("page 1 lacks %q:\n%s", want, first)
		}
	}
}

// TestPrintPDFLongValues: a long unbreakable value in a table cell made the browser shrink the
// whole document to fit it (body text at 0.67 scale) and still cut the value off at the page edge.
// Now every value wraps inside its cell: the text is complete and printed at full size. An event
// naming four comma-joined flag codes did the same (0.84 scale).
func TestPrintPDFLongValues(t *testing.T) {
	s := realScenario(t)
	ref := printReport(t, mustBuild(t, s, s.options()))
	if ref == nil || !ref[0].Pdfium {
		t.Skip("python with pypdfium2 not available: the printed text size cannot be measured")
	}
	o := longTokenOptions(s)
	long := printReport(t, mustBuild(t, s, o))
	ev := eveningScenario(t)
	evening := printReport(t, mustBuild(t, ev, ev.options()))
	for name, pages := range map[string][]pdfPage{"long values": long, "evening": evening} {
		for i := range min(len(pages), 2) {
			if got, want := pages[i].Digit, ref[i].Digit; got < want*0.97 {
				t.Errorf("%s: page %d printed at %.2f of the normal size (digits %.2f pt, normally %.2f pt)", name, i+1, got/want, got, want)
			}
		}
	}
	checkPages(t, long, "AT&T Fiber service problem evidence, 2026-10-04 14:00 to 2026-10-05 14:00 UTC, account ACCT-123456789012345678901234567890")
	var all strings.Builder
	for _, p := range long {
		all.WriteString(p.Text)
	}
	compact := strings.Join(strings.Fields(all.String()), "")
	for _, want := range []string{longTokenNotes, o.Customer.Account, o.Customer.Address, o.BundleName} {
		if !strings.Contains(compact, want) {
			t.Errorf("the PDF text lacks the complete value %q", want)
		}
	}
	var evText strings.Builder
	for _, p := range evening {
		evText.WriteString(p.Text)
	}
	if !strings.Contains(oneLine(evText.String()), "OPTICAL_RX_LOW_ALARM, OPTICAL_RX_LOW_WARNING, OPTICAL_TX_LOW_WARNING, TEMPERATURE_HIGH_WARNING") {
		t.Error("the evening report lacks the flag codes as a list")
	}
}

func itoa(n int) string { return fmtInt(int64(n)) }
