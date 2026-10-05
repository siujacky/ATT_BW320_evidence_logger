package export

import (
	"fmt"
	"strings"
	"time"
)

// publicKeyText renders keys/public-key.txt from the genesis record.
func publicKeyText(r *report) []byte {
	var b strings.Builder
	b.WriteString("att-monitor ledger signing key (Ed25519 public key)\n")
	b.WriteString("====================================================\n\n")
	if r.Ledger.Genesis == nil || r.Ledger.PublicKey == "" {
		b.WriteString("THE GENESIS RECORD OF THIS LEDGER WAS NOT FOUND OR IS INVALID.\n")
		b.WriteString("The public key is unknown, so the record signatures cannot be verified from this bundle.\n")
		return []byte(b.String())
	}
	g := r.Ledger.Genesis
	if !r.Ledger.GenesisVerified {
		b.WriteString("WARNING: THE GENESIS RECORD IN THIS BUNDLE DOES NOT VERIFY (hash or self-signature).\n")
		b.WriteString("The key below is only what that record claims; it was not used to check signatures.\n")
		b.WriteString("See REPORT.html, section 7.\n\n")
	}
	fmt.Fprintf(&b, "Public key (base64): %s\n\n", r.Ledger.PublicKey)
	b.WriteString("Fingerprint (SHA-256 of the 32-byte public key):\n")
	groups := strings.Fields(groupFingerprint(r.Ledger.Fingerprint))
	for i := 0; i < len(groups); i += 8 {
		fmt.Fprintf(&b, "  %s\n", strings.Join(groups[i:min(i+8, len(groups))], " "))
	}
	fmt.Fprintf(&b, "Fingerprint (hex): %s\n\n", r.Ledger.Fingerprint)
	fmt.Fprintf(&b, "Source: genesis record seq %d of segment %s\n", g.Seq, g.Segment)
	fmt.Fprintf(&b, "        h  = %s\n", g.Hash)
	fmt.Fprintf(&b, "        ts = %s\n", g.TS)
	if r.Ledger.Created != "" {
		fmt.Fprintf(&b, "Key created: %s\n", r.Ledger.Created)
	}
	b.WriteString("\nEvery record in ledger/*.jsonl carries an Ed25519 signature (\"s\") over its body (\"b\")\n")
	b.WriteString("made with the matching private key, which never leaves the monitoring computer (it is\n")
	b.WriteString("protected there with Windows DPAPI). Compare this fingerprint with the one shown by\n")
	b.WriteString("att-monitor on that computer (dashboard \"Evidence\" view or keys\\ledger-signing.pub.txt).\n")
	return []byte(b.String())
}

// readmeText renders README.txt, with local times in loc.
func readmeText(r *report, loc *time.Location) []byte {
	fmtLocal := func(s string) string { return fmtLocalIn(loc, s) }
	var b strings.Builder
	line := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	line("AT&T FIBER SERVICE EVIDENCE BUNDLE (att-monitor)")
	line("================================================")
	line("")
	line("This archive contains tamper-evident monitoring records of an AT&T Fiber internet")
	line("connection, produced by %s %s on %s.", r.Generator.Name, r.Generator.Version, fmtUTC(r.GeneratedAt))
	if r.Host != nil {
		line("Monitoring computer: %s (%s %s).", r.Host.Hostname, r.Host.OS, r.Host.OSVersion)
	}
	line("")
	line("Period (UTC):   %s  to  %s", fmtUTC(r.Period.From), fmtUTC(r.Period.To))
	line("Period (local): %s  to  %s", fmtLocal(r.Period.From), fmtLocal(r.Period.To))
	if r.Period.IncidentID != "" {
		line("Incident:       %s (period = incident +/- 15 minutes)", r.Period.IncidentID)
	}
	if r.Request.PreparedBy != "" {
		line("Prepared by:    %s", oneLine(r.Request.PreparedBy))
	}
	if r.Request.Requester != "" {
		line("Requested via:  %s", oneLine(r.Request.Requester))
	}
	if r.Request.Notes != "" {
		line("Notes:          %s", indentLines(r.Request.Notes, "                "))
	}
	line("")
	line("START HERE: open REPORT.html in any web browser. It works offline, contains no scripts")
	line("and prints well. Every figure in it was computed by the exporting software from the")
	line("records in this archive. MANIFEST.sha256 does not protect REPORT.html, report.json or")
	line("this file: anyone can edit them and recompute the manifest. Instead,")
	line("att-monitor verify-bundle recomputes them from the records and fails if any figure")
	line("differs; tools/verify_bundle.py verifies the records themselves (the evidence), not")
	line("the figures of the report.")
	line("")
	line("CONTENTS")
	line("  README.txt              this file")
	line("  REPORT.html             human-readable report")
	line("  report.json             the same summary in machine-readable form")
	line("  ledger/*.jsonl          complete, unmodified daily ledger segments (one record per line)")
	line("  blobs/<sha256>          raw evidence referenced by the records (exact gateway status pages,")
	line("                          RFC 3161 time-stamp tokens, imported files), named by their SHA-256")
	line("  keys/public-key.txt     the ledger's Ed25519 public key and fingerprint")
	for _, x := range r.Bundle.ExtraFiles {
		line("  %-23s %s", x.Path, x.Description)
	}
	line("  tools/verify_bundle.py  independent verifier (Python 3.9+, standard library only)")
	line("  MANIFEST.sha256         SHA-256 of every other file in this archive")
	line("")
	line("LEDGER FACTS")
	line("  Records in this bundle: %d in %d segment(s)", r.Ledger.Records, len(r.Ledger.Segments))
	for _, s := range r.Ledger.Segments {
		line("    %-34s seq %d-%d, %d records, sha256 %s", s.Path, s.FirstSeq, s.LastSeq, s.Records, s.SHA256)
		if s.IncludedFor != "" {
			line("      (outside the period; included for the %s)", s.IncludedFor)
		}
	}
	for _, o := range r.Ledger.Omitted {
		line("    (not included: %s, seq %d-%d, outside the period)", o.Name, o.FirstSeq, o.LastSeq)
	}
	if h := r.Ledger.Head; h != nil {
		line("  Last record:  seq %d, %s, h=%s", h.Seq, fmtUTC(h.TS), h.Hash)
	}
	if r.Ledger.Fingerprint != "" {
		line("  Key fingerprint: %s", groupFingerprint(r.Ledger.Fingerprint))
	} else {
		line("  Key fingerprint: UNKNOWN (no valid genesis record)")
	}
	bc := r.Verification.Bundle
	line("  Bundle checks at export:  %s (%d failure(s); %d of %d referenced blobs included)",
		passFail(bc.OK), bc.FailuresTotal, bc.BlobsIncluded, bc.BlobsReferenced)
	switch f := r.Verification.Full; {
	case f != nil && f.KeyMismatch:
		line("  Full-ledger verification: FAIL - it concerns a ledger with another key (%s)", groupFingerprint(f.Fingerprint))
	case f != nil:
		line("  Full-ledger verification: %s (%d records, %d failure(s), checked %s)", passFail(f.OK), f.Records, f.FailuresTotal, fmtUTC(f.At))
	case r.Verification.FullError != "":
		line("  Full-ledger verification: ERROR (%s)", r.Verification.FullError)
	case r.Verification.FullIncomplete != "":
		line("  Full-ledger verification: NOT COMPLETED - %s", oneLine(r.Verification.FullIncomplete))
	default:
		line("  Full-ledger verification: not performed")
	}
	if a := r.Summary.LastRecordAnchor; a != nil {
		line("  Latest time-stamp covering the period: %s, genTime %s (anchor seq %d, covers seq <= %d)",
			oneLine(a.TSA), fmtUTC(a.GenTime), a.Seq, a.HeadSeq)
		line("    accepted as proof of time: %s", proofBasisText(a.ProofBasis))
	} else if r.Summary.LastRecordInPeriod != nil {
		line("  No time-stamp in this bundle that is accepted as proof of time covers the last records of the period.")
	}
	line("  Provider-attributed outage time in the period: %s (cycle time of ISP_OUTAGE cycles outside", fmtDur(r.Summary.ProviderOutageSec))
	line("    gateway-restart windows; rules %s, see REPORT.html section 6)", r.Methodology.RulesDescribed)
	line("")
	line("HOW TO VERIFY")
	line("  1. File integrity (every file is listed in MANIFEST.sha256; this shows that no file")
	line("     changed after the manifest was written, not who wrote it):")
	line("       Linux:   sha256sum -c MANIFEST.sha256")
	line("       macOS:   shasum -a 256 -c MANIFEST.sha256")
	line("       Windows: certutil -hashfile <file> SHA256   (compare with MANIFEST.sha256)")
	line("  2. Records, hash chain, signatures, blobs, time-stamp tokens and record times:")
	line("       att-monitor verify-bundle %s", r.Bundle.FileName)
	line("       python tools/verify_bundle.py %s", r.Bundle.FileName)
	line("       (or, inside the extracted folder:  python tools/verify_bundle.py .)")
	line("     The Python verifier needs nothing but Python 3.9+. To also check the Ed25519")
	line("     signatures, run 'pip install cryptography' first or add --pure-python-ed25519 (slow).")
	line("     Exit code 0 means every check that ran passed. Every record's time is also checked")
	line("     against the trusted time-stamps: a record dated more than 5 minutes before one that")
	line("     precedes it in the chain, or more than 5 minutes after one that covers it, fails")
	line("     (ts_contradiction).")
	line("     att-monitor verify-bundle also recomputes report.json, REPORT.html, README.txt and")
	line("     keys/public-key.txt from the records and fails if they differ; the inputs the records")
	line("     cannot confirm (period, export time, local time zone, the verification results on the")
	line("     monitoring computer) are taken as report.json states them.")
	roots := "<TSA root certificates .pem>"
	if len(r.Bundle.TSARoots) > 0 {
		roots = tsaRootsPath
	}
	line("  3. Independent RFC 3161 time-stamps (OpenSSL 1.1.1 or newer). Each \"anchor\" record")
	line("     names a token in blobs/. On the extracted bundle:")
	line("       openssl ts -reply -in blobs/<token_sha256> -text")
	line("       openssl ts -verify -attime <genTime> -digest <head_hash> -in blobs/<token_sha256> -CAfile %s", roots)
	line("     <genTime> is the token's genTime in Unix seconds: -attime checks the TSA certificate")
	line("     at the time of the time-stamp (it may have expired since). A valid token proves that")
	line("     the record <head_hash> names - and through the hash chain every earlier record -")
	line("     existed no later than genTime. tools/verify_bundle.py runs this check when openssl")
	line("     is installed.")
	for _, an := range anchorExamples(r.Anchors) {
		line("     e.g. %s (anchor seq %d, genTime %s):", oneLine(an.TSAURL), an.Seq, fmtUTC(an.TokenGenTime))
		line("       openssl ts -verify -attime %s -digest %s -in blobs/%s -CAfile %s", unixSeconds(an.TokenGenTime), an.HeadHash, an.Token, roots)
	}
	if len(r.Bundle.TSARoots) > 0 {
		line("     %s holds the TSAs' root certificates. It is a convenience supplied by the", tsaRootsPath)
		line("     exporting software, not a trust anchor: compare these SHA-256 fingerprints with the")
		line("     ones the TSAs publish before relying on it:")
		for _, rc := range r.Bundle.TSARoots {
			line("       %s", oneLine(rc.Subject))
			line("         SHA-256 %s", colonHex(rc.SHA256))
		}
	} else {
		line("     This bundle contains no %s: obtain the TSAs' root certificates from the TSAs.", tsaRootsPath)
	}
	if r.Bundle.TSARootsNote != "" {
		line("     Note on %s: %s", tsaRootsPath, oneLine(r.Bundle.TSARootsNote))
	}
	line("")
	line("HOW THE RECORDS ARE PROTECTED")
	line("  - Each ledger line is {\"h\": SHA-256 of b, \"s\": Ed25519 signature of b, \"b\": the record}.")
	line("  - Each record contains \"prev\" (the h of the previous record) and \"seq\" (+1 per record):")
	line("    deleting, inserting, reordering or editing any record breaks every later link.")
	line("  - The first record of each daily segment (segment_open) contains the SHA-256 of the")
	line("    complete previous segment file.")
	line("  - Raw evidence is stored under its own SHA-256 and listed in the records that use it.")
	line("  - The chain head is time-stamped by independent Time-Stamp Authorities; only the hash")
	line("    leaves the monitoring computer.")
	line("")
	line("CHAIN OF CUSTODY")
	line("  The production of this bundle is itself recorded in the ledger: right after the bundle")
	line("  is written, a \"custody_export\" record with the bundle's SHA-256 is appended and")
	line("  time-stamped (see %s.custody.json next to the bundle on the monitoring", r.Bundle.FileName)
	line("  computer, and the custody log of later bundles).")
	return []byte(strings.ReplaceAll(b.String(), "\n", "\r\n"))
}

// oneLine flattens operator-supplied text for a single README line: control characters
// (including CR/LF and tabs) become spaces, so the text cannot break the file's layout.
func oneLine(s string) string {
	return strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)), " ")
}

// indentLines keeps the line structure of multi-line operator text, indenting continuation
// lines so they stay inside their README field.
func indentLines(s, indent string) string {
	lines := strings.Split(strings.ReplaceAll(strings.TrimSpace(s), "\r\n", "\n"), "\n")
	for i, l := range lines {
		lines[i] = oneLine(l)
	}
	return strings.Join(lines, "\n"+indent)
}

func passFail(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}
