package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/contracts"
	"attmonitor/internal/export"
	"attmonitor/internal/ledger"
	"attmonitor/internal/model"
	"attmonitor/internal/ticket"
)

// cmdTicketReport builds the AT&T service-ticket report for the last N hours:
//
//  1. export a verifiable evidence bundle for the window (through the running service, so the
//     export is recorded as a custody_export and time-stamped),
//  2. verify that bundle (manifest, report re-computation, ledger chain/signatures/time-stamps),
//  3. derive the ticket document ONLY from the bundle's own records,
//  4. write it as HTML and print it to PDF with headless Edge/Chrome,
//  5. record the PDF's SHA-256 in the ledger (operator_note), so the document's custody is on record.
func cmdTicketReport(args []string) error {
	fs, data := newFlags("ticket-report")
	hours := fs.Float64("hours", 24, "length of the report window ending now, in hours")
	out := fs.String("out", ".", "folder for the PDF, HTML and evidence bundle")
	name := fs.String("name", "", "account holder name (printed on the report)")
	account := fs.String("account", "", "AT&T account number")
	address := fs.String("address", "", "service address")
	phone := fs.String("phone", "", "contact phone")
	bestTime := fs.String("best-time", "", "best time for a technician visit")
	notes := fs.String("notes", "", "extra notes for AT&T (printed on the report)")
	noPDF := fs.Bool("no-pdf", false, "write the HTML only")
	if err := fs.Parse(reorderArgs(args, "no-pdf")); err != nil {
		return err
	}
	if *hours <= 0 || *hours > 24*31 {
		return errors.New("--hours must be between 0 and 744")
	}
	dataDir := defaultDataDir(*data)
	outDir, err := filepath.Abs(*out)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	ctx := background()
	to := now()
	from := to.Add(-time.Duration(*hours * float64(time.Hour)))

	// 1. Evidence bundle for the window.
	preparedBy := strings.TrimSpace(*name)
	if preparedBy == "" {
		preparedBy = actor()
	}
	exportNotes := "evidence bundle for an AT&T service ticket report"
	var info contracts.ExportInfo
	var bundlePath string
	api, viaService := serviceAPI(dataDir)
	if viaService {
		body := map[string]any{
			"from": from.UTC().Format(time.RFC3339), "to": to.UTC().Format(time.RFC3339),
			"prepared_by": preparedBy, "notes": exportNotes,
		}
		if err := api.do(ctx, http.MethodPost, "/api/exports", body, &info); err != nil {
			return fmt.Errorf("export evidence bundle: %w", err)
		}
		p, err := api.download(ctx, "/api/exports/"+info.FileName, outDir, info.FileName)
		if err != nil {
			return fmt.Errorf("download evidence bundle: %w", err)
		}
		bundlePath = p
	} else {
		s, err := openStack(stackOptions{dataDir: dataDir, mode: "cli"})
		if err != nil {
			return err
		}
		info, err = s.exp.Build(ctx, contracts.ExportRequest{From: from, To: to, PreparedBy: preparedBy, Notes: exportNotes, Requester: actor()})
		s.close()
		if err != nil && info.FileName == "" {
			return fmt.Errorf("export evidence bundle: %w", err)
		}
		bundlePath = filepath.Join(outDir, info.FileName)
		if err := copyFile(info.Path, bundlePath); err != nil {
			return err
		}
	}
	bundleSHA, err := fileSHA256(bundlePath)
	if err != nil {
		return err
	}
	fmt.Println("Evidence bundle:", bundlePath)
	fmt.Println("  SHA-256:", bundleSHA)

	// 2. Verify the bundle before summarising it.
	verification := verifyBundleLine(ctx, bundlePath)
	fmt.Println("  Verification:", verification)

	// 3. Build the ticket from the bundle's own records.
	b, err := export.OpenBundle(bundlePath)
	if err != nil {
		return err
	}
	defer b.Close()
	rep, err := ticket.Build(ctx, b, ticket.Options{
		From: from, To: to,
		Customer: ticket.Customer{
			Name: *name, Account: *account, Address: *address, Phone: *phone, BestTime: *bestTime, Notes: *notes,
		},
		BundleName:   filepath.Base(bundlePath),
		BundleSHA256: bundleSHA,
		Verification: verification,
		Location:     time.Local,
		Now:          now,
		Generator:    "att-monitor " + version,
	})
	if err != nil {
		return fmt.Errorf("build ticket report: %w", err)
	}
	htmlBytes, err := rep.HTML()
	if err != nil {
		return err
	}
	base := "ATT-Service-Ticket-Report_" + to.Format("2006-01-02_1504")
	htmlPath := filepath.Join(outDir, base+".html")
	if err := os.WriteFile(htmlPath, htmlBytes, 0o644); err != nil {
		return err
	}
	htmlSHA, _ := fileSHA256(htmlPath)
	fmt.Println("Report (HTML):", htmlPath)

	// 4. PDF.
	pdfPath, pdfSHA := "", ""
	if !*noPDF {
		pctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		browser, err := ticket.PrintPDF(pctx, htmlPath, filepath.Join(outDir, base+".pdf"))
		cancel()
		if err != nil {
			fmt.Fprintln(os.Stderr, "PDF could not be produced automatically:", err)
			fmt.Fprintln(os.Stderr, "Open the HTML file in Edge or Chrome and use Print > Save as PDF.")
		} else {
			pdfPath = filepath.Join(outDir, base+".pdf")
			pdfSHA, _ = fileSHA256(pdfPath)
			fmt.Printf("Report (PDF):  %s (printed with %s)\n  SHA-256: %s\n", pdfPath, browser, pdfSHA)
		}
	}

	// 5. Custody: the documents handed to AT&T are recorded in the ledger.
	doc := filepath.Base(htmlPath) + " sha256 " + htmlSHA
	if pdfPath != "" {
		doc = filepath.Base(pdfPath) + " sha256 " + pdfSHA + "; " + doc
	}
	text := fmt.Sprintf("AT&T service-ticket report generated for %s .. %s: %s. Derived only from evidence bundle %s sha256 %s (%s).",
		from.UTC().Format(time.RFC3339), to.UTC().Format(time.RFC3339), doc, filepath.Base(bundlePath), bundleSHA, verification)
	var ref model.Ref
	if viaService {
		err = api.do(ctx, http.MethodPost, "/api/notes", map[string]string{"text": text, "author": preparedBy}, &ref)
	} else {
		s, oerr := openStack(stackOptions{dataDir: dataDir, mode: "cli"})
		if oerr == nil {
			ref, err = s.mon.Note(ctx, text, preparedBy, "cli")
			s.close()
		} else {
			err = oerr
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "WARNING: the report's custody note could not be recorded:", err)
	} else {
		fmt.Printf("Custody: recorded as ledger #%d\n", ref.Seq)
	}
	return nil
}

// verifyBundleLine runs the same checks as `verify-bundle` and condenses them into one line.
func verifyBundleLine(ctx context.Context, path string) string {
	if err := export.VerifyManifest(path); err != nil {
		return "FAILED (manifest/report): " + err.Error()
	}
	b, err := export.OpenBundle(path)
	if err != nil {
		return "FAILED: " + err.Error()
	}
	defer b.Close()
	rep, err := ledger.VerifyReader(ctx, b, ledger.VerifyOptions{
		TokenVerifier:        tokenVerifier(),
		FastInterval:         config.Default().Probes.FastInterval.Duration,
		CheckBlobs:           true,
		AllowOmittedSegments: true,
	})
	if err != nil {
		return "FAILED: " + err.Error()
	}
	trusted := 0
	for _, a := range rep.Anchors {
		if a.OK && a.ChainOK {
			trusted++
		}
	}
	if !rep.OK {
		return fmt.Sprintf("FAILED: %d problem(s), first: %s", rep.FailuresTotal, firstFailure(rep))
	}
	return fmt.Sprintf("verified OK — %d records, hash chain and Ed25519 signatures intact, report re-computed from the records, %d trusted RFC 3161 time-stamp(s), key %s",
		rep.Records, trusted, ledger.FormatFingerprint(rep.Fingerprint))
}

func firstFailure(rep model.VerifyReport) string {
	if len(rep.Failures) == 0 {
		return "(see att-monitor verify-bundle)"
	}
	f := rep.Failures[0]
	return fmt.Sprintf("%s at #%d: %s", f.Problem, f.Seq, f.Detail)
}
