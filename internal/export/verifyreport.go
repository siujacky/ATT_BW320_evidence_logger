package export

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// Report verification. MANIFEST.sha256 is a plain list of hashes that anyone can recompute after
// editing a file, so it cannot protect the human-readable figures of a bundle. VerifyReport
// therefore recomputes report.json, REPORT.html, README.txt and keys/public-key.txt from the
// ledger records and blobs in the bundle - with the same code that produced them - and accepts
// them only if they are byte for byte what the records give. The few inputs that cannot come
// from the records are taken as report.json states them and listed in ReportCheck.Stated:
// the period and the export time, the generating software, the request (prepared by, notes),
// the local time zone, the full-ledger verification and the token verifier's results at export,
// and the ledger segments left out of the bundle.

// ErrReportMismatch is wrapped by VerifyReport (and VerifyManifest) errors when the report files
// of a bundle are not what its ledger records give, or cannot be recomputed.
var ErrReportMismatch = errors.New("export: the report is not what the ledger records of the bundle give")

// reportFiles are the generated files VerifyReport recomputes.
var reportFiles = []string{"report.json", "REPORT.html", "README.txt", "keys/public-key.txt"}

// ReportCheck is the outcome of VerifyReport.
type ReportCheck struct {
	Format      string   // report.json format
	Generator   string   // the software that produced the bundle, as report.json states it
	Verified    bool     // every report file is exactly what the records give
	Differences []string // what differs (the first ones), when not Verified
	Stated      []string // inputs taken as report.json states them (not verifiable from the bundle)
}

// VerifyReport recomputes the report files of a bundle from its ledger records (see above). The
// error is nil only when they match; it wraps ErrReportMismatch when they differ or cannot be
// recomputed (an unknown report format, an unreadable report.json), and the ReportCheck (when not
// nil) says what was compared.
func VerifyReport(path string) (*ReportCheck, error) {
	b, err := OpenBundle(path)
	if err != nil {
		return nil, err
	}
	defer b.Close()
	return verifyReport(context.Background(), b)
}

// verifyReport implements VerifyReport on an open bundle.
func verifyReport(ctx context.Context, b *Bundle) (*ReportCheck, error) {
	files := map[string][]byte{}
	for _, name := range reportFiles {
		f := b.files[name]
		if f == nil {
			return nil, fmt.Errorf("%w: %s is missing", ErrReportMismatch, name)
		}
		data, err := readZipFile(f, maxManifestBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %s unreadable: %v", ErrReportMismatch, name, err)
		}
		files[name] = data
	}
	var stated report
	if err := json.Unmarshal(files["report.json"], &stated); err != nil {
		return nil, fmt.Errorf("%w: report.json cannot be read: %v", ErrReportMismatch, err)
	}
	chk := &ReportCheck{Format: stated.Format, Generator: strings.TrimSpace(stated.Generator.Name + " " + stated.Generator.Version)}
	if stated.Format != reportFormat {
		return chk, fmt.Errorf("%w: report.json has format %q, but this verifier recomputes reports of format %q only, so REPORT.html, "+
			"report.json and README.txt are NOT verified (verify the bundle with the software that produced it: %s)",
			ErrReportMismatch, truncate(stated.Format, 60), reportFormat, orNone(truncate(chk.Generator, 80)))
	}
	p, err := paramsFromReport(b, &stated)
	if err != nil {
		return chk, fmt.Errorf("%w: %v", ErrReportMismatch, err)
	}
	chk.Stated = statedInputs(&stated)

	col := newCollector(p)
	for _, s := range p.sel {
		if err := copySegment(ctx, b, nil, col, s); err != nil {
			return chk, fmt.Errorf("%w: %v", ErrReportMismatch, err)
		}
	}
	if err := copyBlobs(ctx, b, nil, col, replayBlobFailure(&stated)); err != nil {
		return chk, fmt.Errorf("%w: %v", ErrReportMismatch, err)
	}
	rep := col.finish()
	if col.zoneErr != nil {
		return chk, fmt.Errorf("%w: %v", ErrReportMismatch, col.zoneErr)
	}
	rep.Bundle.FileName = stated.Bundle.FileName
	gen, err := renderGenerated(col, rep, p.extra)
	if err != nil {
		return chk, fmt.Errorf("%w: %v", ErrReportMismatch, err)
	}
	for _, name := range reportFiles {
		if bytes.Equal(gen[name], files[name]) {
			continue
		}
		if name == "report.json" {
			for _, d := range jsonDiff(files[name], gen[name], 10) {
				chk.Differences = append(chk.Differences, "report.json "+d)
			}
		}
		if len(chk.Differences) == 0 || name != "report.json" {
			chk.Differences = append(chk.Differences, name+" "+textDiff(files[name], gen[name]))
		}
	}
	if len(chk.Differences) > 0 {
		return chk, fmt.Errorf("%w: %s", ErrReportMismatch, strings.Join(chk.Differences, "; "))
	}
	chk.Verified = true
	return chk, nil
}

// paramsFromReport rebuilds the parameters of an export from the bundle and what its
// report.json states.
func paramsFromReport(b *Bundle, r *report) (*buildParams, error) {
	from, ok1 := parseTS(r.Period.From)
	to, ok2 := parseTS(r.Period.To)
	now, ok3 := parseTS(r.GeneratedAt)
	if !ok1 || !ok2 || !ok3 || !plausibleTime(from) || !plausibleTime(to) || !plausibleTime(now) || !from.Before(to) {
		return nil, fmt.Errorf("report.json states an unusable period (%q to %q, generated %q)",
			truncate(r.Period.From, 40), truncate(r.Period.To, 40), truncate(r.GeneratedAt, 40))
	}
	if len(r.LocalTime.Spans) == 0 {
		return nil, errors.New("report.json does not state the local time zone (local_time_zone)")
	}
	p := &buildParams{
		req:            contracts.ExportRequest{PreparedBy: r.Request.PreparedBy, Notes: r.Request.Notes, Requester: r.Request.Requester},
		from:           from,
		to:             to,
		now:            now,
		fullErr:        r.Verification.FullError,
		fullIncomplete: r.Verification.FullIncomplete,
		software:       r.Generator,
		zone:           r.LocalTime.Spans,
		tailBytes:      map[string]int{},
		stated:         r,
	}
	switch r.Period.Scope {
	case "period":
	case "incident":
		p.incident = &foundIncident{inc: model.Incident{ID: r.Period.IncidentID}}
	default:
		return nil, fmt.Errorf("report.json states an unknown scope %q", truncate(r.Period.Scope, 40))
	}
	if f := r.Verification.Full; f != nil {
		full := *f
		p.full = &full
	}
	if r.Verification.Bundle.TokenVerifier {
		p.tokenVerifier = statedTokenVerifier(r.Anchors)
	}

	// The segments: those in the bundle (with the labels report.json gives them) and those the
	// export left out, which report.json lists, in ledger (date) order.
	stated := map[string]segmentEntry{}
	for _, s := range r.Ledger.Segments {
		if _, dup := stated[s.Name]; dup {
			return nil, fmt.Errorf("report.json lists segment %s twice", truncate(s.Name, 40))
		}
		stated[s.Name] = s
	}
	var all []contracts.SegmentInfo
	included := map[string]bool{}
	for _, s := range b.segs {
		e, ok := stated[s.info.Name]
		if !ok {
			return nil, fmt.Errorf("the bundle holds segment %s, which report.json does not list", s.info.Name)
		}
		included[s.info.Name] = true
		all = append(all, contracts.SegmentInfo{Name: s.info.Name, Date: s.info.Date, FirstSeq: s.info.FirstSeq, LastSeq: s.info.LastSeq,
			Records: s.info.Records})
		if e.ExcludedTailBytes > 0 {
			p.tailBytes[s.info.Name] = e.ExcludedTailBytes
		}
	}
	for name := range stated {
		if !included[name] {
			return nil, fmt.Errorf("report.json lists segment %s, which the bundle does not hold", truncate(name, 40))
		}
	}
	for _, list := range [][]omittedSegment{r.Ledger.Omitted, r.Ledger.Later} {
		for _, o := range list {
			if included[o.Name] {
				return nil, fmt.Errorf("report.json lists segment %s as left out, but the bundle holds it", truncate(o.Name, 40))
			}
			all = append(all, contracts.SegmentInfo{Name: o.Name, FirstSeq: o.FirstSeq, LastSeq: o.LastSeq, Records: o.Records})
		}
	}
	p.all = sortedSegments(all)
	for i, s := range p.all {
		if !included[s.Name] {
			continue
		}
		e := stated[s.Name]
		p.sel = append(p.sel, segSel{info: s, index: i, genesis: i == 0, inRange: e.OverlapsPeriod, why: e.IncludedFor})
	}

	// The extra files are the bundle's files that are not generated.
	var names []string
	for name := range b.files {
		if isGeneratedPath(name) {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		data, err := readZipFile(b.files[name], maxManifestBytes)
		if err != nil {
			return nil, fmt.Errorf("%s unreadable: %v", name, err)
		}
		p.extra = append(p.extra, extraFile{path: name, data: data})
	}
	return p, nil
}

// isGeneratedPath: a bundle file the exporter writes itself (not an extra file). The syslog
// chunks are not described by the report (VerifySyslogChunks checks them).
func isGeneratedPath(name string) bool {
	for _, g := range generatedFiles {
		if name == g {
			return true
		}
	}
	return strings.HasPrefix(name, "ledger/") || strings.HasPrefix(name, "blobs/") || strings.HasPrefix(name, syslogDir)
}

// statedTokenVerifier answers for each anchor token what the token verifier answered at export,
// as report.json states it (the verifying computer's own check of the tokens is separate: the
// ledger verification of the bundle).
type statedTokenVerifier []anchorEntry

func (v statedTokenVerifier) VerifyToken(token, digest []byte) (contracts.TokenInfo, error) {
	id, head := sha256Hex(token), hex.EncodeToString(digest)
	for _, an := range v {
		if an.Token != id || !strings.EqualFold(an.HeadHash, head) || !an.VerifierChecked {
			continue
		}
		if an.VerifierError != "" {
			return contracts.TokenInfo{}, errors.New(an.VerifierError)
		}
		info := contracts.TokenInfo{TSAName: an.TokenTSAName, ChainNote: an.ChainNote}
		if an.ChainTrusted != nil {
			info.ChainOK = *an.ChainTrusted
		}
		return info, nil
	}
	return contracts.TokenInfo{}, errors.New("report.json states no token verifier result for this token")
}

// replayBlobFailure turns a blob missing from the bundle into the failure the export recorded
// for it: a blob the blob store could not provide intact is reported as corrupt with the store's
// error, not as missing.
func replayBlobFailure(r *report) func(id string, err error) error {
	return func(id string, err error) error {
		if !errors.Is(err, contracts.ErrNotFound) {
			return err // in the bundle but damaged: it was intact at export
		}
		for _, f := range r.Verification.Bundle.Failures {
			if f.Problem != "blob_corrupt" || !strings.HasPrefix(f.Detail, "blob "+id+" ") {
				continue
			}
			if _, cause, ok := strings.Cut(f.Detail, " could not be exported: "); ok {
				return errors.New(cause)
			}
		}
		return err
	}
}

// statedInputs lists the inputs of the report that the bundle's records cannot confirm.
func statedInputs(r *report) []string {
	out := []string{
		fmt.Sprintf("period %s to %s (%s), report generated %s by %s %s", r.Period.From, r.Period.To, r.Period.Scope,
			r.GeneratedAt, r.Generator.Name, r.Generator.Version),
		"the exporting computer's local time zone (local times; UTC is authoritative)",
	}
	if r.Request.PreparedBy != "" || r.Request.Notes != "" || r.Request.Requester != "" {
		out = append(out, "prepared by / notes / requester of the export")
	}
	switch {
	case r.Verification.Full != nil:
		ok := "PASS"
		if !r.Verification.Full.OK {
			ok = "FAIL"
		}
		out = append(out, fmt.Sprintf("the full-ledger verification on the monitoring computer (%s, %d records, at %s)", ok,
			r.Verification.Full.Records, r.Verification.Full.At))
	case r.Verification.FullError != "":
		out = append(out, "the full-ledger verification error on the monitoring computer")
	case r.Verification.FullIncomplete != "":
		out = append(out, "that the full-ledger verification on the monitoring computer did not complete")
	}
	if r.Verification.Bundle.TokenVerifier {
		out = append(out, "the TSA certificate chain results of the token verifier at export (proof of time; this verifier's own token check is separate)")
	}
	if len(r.Ledger.Omitted) > 0 || len(r.Ledger.Later) > 0 {
		out = append(out, "the names and seq ranges of the ledger segments left out of the bundle")
	}
	return out
}

// jsonDiff lists the first differences between two JSON documents as "path: a says X, the
// records give Y".
func jsonDiff(stated, computed []byte, limit int) []string {
	var x, y any
	if json.Unmarshal(stated, &x) != nil || json.Unmarshal(computed, &y) != nil {
		return []string{"cannot be compared field by field"}
	}
	var out []string
	var walk func(path string, x, y any)
	walk = func(path string, x, y any) {
		if len(out) >= limit {
			return
		}
		mx, okx := x.(map[string]any)
		my, oky := y.(map[string]any)
		if okx && oky {
			keys := map[string]bool{}
			for k := range mx {
				keys[k] = true
			}
			for k := range my {
				keys[k] = true
			}
			var names []string
			for k := range keys {
				names = append(names, k)
			}
			sort.Strings(names)
			for _, k := range names {
				p := k
				if path != "" {
					p = path + "." + k
				}
				walk(p, mx[k], my[k])
			}
			return
		}
		ax, okx := x.([]any)
		ay, oky := y.([]any)
		if okx && oky && len(ax) == len(ay) {
			for i := range ax {
				walk(fmt.Sprintf("%s[%d]", path, i), ax[i], ay[i])
			}
			return
		}
		if !reflect.DeepEqual(x, y) {
			out = append(out, fmt.Sprintf("%s: report.json says %s, the records give %s", orNone(path), jsonValue(x), jsonValue(y)))
		}
	}
	walk("", x, y)
	if len(out) == 0 {
		out = append(out, "differs in its formatting")
	}
	return out
}

func jsonValue(v any) string {
	if v == nil {
		return "nothing"
	}
	if a, ok := v.([]any); ok {
		return fmt.Sprintf("%d entries", len(a))
	}
	return abbreviate(compactValue(v), 80)
}

// textDiff describes the first line in which two texts differ.
func textDiff(stated, computed []byte) string {
	a, b := strings.Split(string(stated), "\n"), strings.Split(string(computed), "\n")
	for i := 0; i < len(a) || i < len(b); i++ {
		var x, y string
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			return fmt.Sprintf("differs from what the records give, first in line %d: it reads %q, the records give %q",
				i+1, abbreviate(diffExcerpt(x, y), 120), abbreviate(diffExcerpt(y, x), 120))
		}
	}
	return "differs from what the records give"
}

// diffExcerpt returns the part of s from shortly before its first difference from t.
func diffExcerpt(s, t string) string {
	i := 0
	for i < len(s) && i < len(t) && s[i] == t[i] {
		i++
	}
	start := max(0, i-40)
	for start > 0 && start < len(s) && s[start]&0xC0 == 0x80 {
		start--
	}
	if start > len(s) {
		return ""
	}
	return s[start:]
}
