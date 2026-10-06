// Package export produces evidence bundles (docs/DESIGN.md §13): a zip archive holding the
// complete ledger segments that cover a period, every blob those records reference, the
// ledger public key, a self-contained human report (REPORT.html), a machine-readable summary
// (report.json), an independent Python verifier, the extra files the caller supplies (such as
// keys/tsa-roots.pem), the syslog chunks of the period that the syslog store still keeps
// (syslog/<name>, each checked against its syslog_chunk record: VerifySyslogChunks) and a
// SHA-256 manifest. It also reads bundles back (OpenBundle, a contracts.LedgerReader over the
// zip) and checks their manifests.
//
// Every number and statement in a report is computed from the ledger records written into
// the same bundle; nothing is taken from live monitor state. The few inputs that cannot come
// from those records (the period and export time, the generating software, the request, the
// exporting computer's time zone, the full-ledger verification and the token verifier's results
// at export, the segments left out) are stated in report.json, and VerifyReport recomputes the
// report files from the records and those statements: a figure edited after export fails
// verification although MANIFEST.sha256 can be recomputed by anyone.
package export

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

const (
	// IncidentMargin is added before and after an incident when an export is scoped to it.
	IncidentMargin = 15 * time.Minute

	bundlePrefix   = "att-evidence_"
	nameTimeLayout = "20060102T1504Z"
	sidecarSuffix  = ".custody.json"
	manifestName   = "MANIFEST.sha256"
	zipComment     = "att-monitor evidence bundle. Start with README.txt and REPORT.html. " +
		"Verify: att-monitor verify-bundle <this file>  or  python tools/verify_bundle.py <this file>"
)

var (
	// ErrCustodyNotRecorded is returned, wrapped and together with a valid ExportInfo, when the
	// bundle was written successfully but the custody_export ledger record could not be appended.
	ErrCustodyNotRecorded = errors.New("export: bundle written but its custody_export record failed")
	// ErrInvalidName is returned (also matching contracts.ErrNotFound) by Open for names that are
	// not plain bundle file names.
	ErrInvalidName = errors.New("export: invalid bundle name")
)

// Options configures an Exporter.
type Options struct {
	Dir      string                 // exports directory
	Reader   contracts.LedgerReader // records, segments and blobs to export
	Verifier contracts.Verifier     // optional: full-ledger verification result goes into README/REPORT
	Actions  contracts.Actions      // optional: RecordExport (custody_export + anchor); nil = CLI offline
	// TokenVerifier (optional) checks every anchor's RFC 3161 token (CMS signature and TSA
	// certificate chain) while the bundle is written. An anchor counts as proof of time only if
	// its token is valid and its chain is trusted: with a TokenVerifier that is its ChainOK (its
	// ChainNote is shown when false); without one, the anchor record's issue-time flags
	// (verified && chain_ok) decide and the report says so.
	TokenVerifier contracts.TokenVerifier
	// Syslog (optional) is the syslog store. A bundle then includes, as syslog/<name>, the exact
	// stored bytes of every chunk named by one of its syslog_chunk records whose messages overlap
	// the period, as far as the store still keeps it; the report files do not describe them. nil:
	// no chunks.
	Syslog contracts.SyslogReader
	// ExtraFiles are additional bundle files by relative path ("keys/tsa-roots.pem"), written
	// verbatim and listed in MANIFEST.sha256. A path must use forward slashes, contain no "..",
	// no drive or absolute syntax, and must not collide with a generated file (also not when
	// letter case is ignored, as on Windows); Build fails otherwise.
	ExtraFiles map[string][]byte
	Software   model.SoftwareInfo // the software producing the bundle
	Now        func() time.Time   // default time.Now
	Logger     *slog.Logger       // nil = discard
	// FullVerifyTimeout bounds the full-ledger verification (Verifier), which runs while the
	// bundle is written and reads the whole ledger, so that its cost, growing with the age of
	// the ledger, cannot make exports fail: when it has not finished in time the report says so
	// ("not completed"; the records of the bundle are verified regardless). 0 means the
	// default (DefaultFullVerifyTimeout, and at most half the time left before the request's
	// deadline); negative means no limit other than that deadline.
	FullVerifyTimeout time.Duration
}

// DefaultFullVerifyTimeout is the default Options.FullVerifyTimeout.
const DefaultFullVerifyTimeout = 4 * time.Minute

// ErrInvalidExtraFile is wrapped by Build when Options.ExtraFiles names an unusable path.
var ErrInvalidExtraFile = errors.New("export: invalid extra bundle file")

// tsaRootsPath is the extra file holding the root certificates of the Time-Stamp Authorities.
const tsaRootsPath = "keys/tsa-roots.pem"

// Exporter builds, lists and serves evidence bundles.
type Exporter struct {
	opts    Options
	log     *slog.Logger
	now     func() time.Time
	buildMu sync.Mutex // one build at a time (naming, temp files)

	cacheMu sync.Mutex
	sums    map[string]fileSum // bundle name -> cached SHA-256
}

type fileSum struct {
	size int64
	mod  time.Time
	sum  string
}

var _ contracts.Exporter = (*Exporter)(nil)

// New returns an Exporter. ExtraFiles is copied: later changes of the caller's map or slices
// do not affect the bundles.
func New(opts Options) *Exporter {
	if opts.ExtraFiles != nil {
		cp := make(map[string][]byte, len(opts.ExtraFiles))
		for k, v := range opts.ExtraFiles {
			cp[k] = append([]byte{}, v...)
		}
		opts.ExtraFiles = cp
	}
	e := &Exporter{opts: opts, log: opts.Logger, now: opts.Now, sums: map[string]fileSum{}}
	if e.log == nil {
		e.log = slog.New(slog.DiscardHandler)
	}
	if e.now == nil {
		e.now = time.Now
	}
	return e
}

// buildParams is everything a build needs once the request has been resolved. The report is a
// function of these parameters and the bytes of the bundle's segments and blobs only (VerifyReport
// recomputes it from a bundle with the parameters report.json states).
type buildParams struct {
	req      contracts.ExportRequest
	from, to time.Time // requested period [from, to)
	now      time.Time
	incident *foundIncident // non-nil for incident-scoped exports
	all      []contracts.SegmentInfo
	sel      []segSel
	// The full-ledger verification: running (fullRun, until awaitFull) or its outcome - a
	// summary, an error, or why it did not complete.
	fullRun        *fullRun
	full           *fullVerification
	fullErr        string
	fullIncomplete string
	software       model.SoftwareInfo
	tokenVerifier  contracts.TokenVerifier
	extra          []extraFile    // Options.ExtraFiles, validated, sorted by path
	zone           []zoneSpan     // the local time zone to render with (nil: time.Local over the bundle's times)
	tailBytes      map[string]int // verification: partial tails left out of the active segment at export
	stated         *report        // verification: the report.json being checked (its stated failures)
}

// fullRun is a full-ledger verification running alongside the bundle.
type fullRun struct {
	done   chan struct{}
	ctx    context.Context
	cancel context.CancelFunc
	budget time.Duration // 0: no budget of its own
	rep    model.VerifyReport
	err    error
}

// startFullVerification starts the full-ledger verification, bounded by the budget of
// Options.FullVerifyTimeout (see there).
func (e *Exporter) startFullVerification(ctx context.Context) *fullRun {
	if e.opts.Verifier == nil {
		return nil
	}
	budget := e.opts.FullVerifyTimeout
	if budget == 0 {
		budget = DefaultFullVerifyTimeout
	}
	if dl, ok := ctx.Deadline(); ok {
		// Leave the bundle at least as much time as the verification.
		if half := time.Until(dl) / 2; budget < 0 || half < budget {
			budget = max(half, time.Millisecond)
		}
	}
	r := &fullRun{done: make(chan struct{})}
	if budget > 0 {
		r.budget = budget
		r.ctx, r.cancel = context.WithTimeout(ctx, budget)
	} else {
		r.ctx, r.cancel = context.WithCancel(ctx)
	}
	go func() {
		defer close(r.done)
		defer func() {
			if p := recover(); p != nil {
				r.err = fmt.Errorf("the verifier failed: %v", p)
			}
		}()
		r.rep, r.err = e.opts.Verifier.Verify(r.ctx)
	}()
	return r
}

// awaitFull waits for the full-ledger verification and records its outcome in p. Only the end
// of ctx (the export itself is cancelled) is an error.
func (p *buildParams) awaitFull(ctx context.Context) error {
	r := p.fullRun
	if r == nil {
		return nil
	}
	p.fullRun = nil
	select {
	case <-r.done:
	case <-ctx.Done():
		r.cancel()
		return ctx.Err()
	}
	r.cancel()
	switch {
	case ctx.Err() != nil:
		return ctx.Err()
	case r.err == nil:
		p.full = summarizeFull(&r.rep)
	case errors.Is(r.ctx.Err(), context.DeadlineExceeded) && r.budget > 0:
		within := r.budget.String()
		if r.budget >= time.Second {
			within = fmtDur(int64(r.budget / time.Second))
		}
		p.fullIncomplete = fmt.Sprintf("not completed within %s, the time an export allows it (the ledger is large); the records in "+
			"this bundle were verified regardless. Run \"att-monitor verify\" on the monitoring computer to verify the whole ledger.", within)
	default:
		p.fullErr = validUTF8(r.err.Error())
	}
	return nil
}

// Build writes a new evidence bundle into Dir (docs/DESIGN.md §13) and, when Actions is set,
// records it in the ledger with a custody_export record whose reference is also written to
// <bundle>.custody.json. If only the custody step fails, the returned ExportInfo is valid and
// the error wraps ErrCustodyNotRecorded.
func (e *Exporter) Build(ctx context.Context, req contracts.ExportRequest) (contracts.ExportInfo, error) {
	var zero contracts.ExportInfo
	if e.opts.Reader == nil {
		return zero, errors.New("export: no ledger reader configured")
	}
	if e.opts.Dir == "" {
		return zero, errors.New("export: no export directory configured")
	}
	extra, err := checkExtraFiles(e.opts.ExtraFiles)
	if err != nil {
		return zero, err
	}
	e.buildMu.Lock()
	defer e.buildMu.Unlock()

	now := e.now()
	from, to, inc, err := e.resolveRange(ctx, req, now)
	if err != nil {
		return zero, err
	}
	// The full-ledger verification reads the whole ledger: it runs while the bundle is written.
	full := e.startFullVerification(ctx)
	if full != nil {
		defer full.cancel()
	}
	all, err := e.opts.Reader.Segments()
	if err != nil {
		return zero, fmt.Errorf("export: list segments: %w", err)
	}
	if len(all) == 0 {
		return zero, errors.New("export: the ledger has no segments")
	}
	all = sortedSegments(all)
	selFrom, why := from, ""
	if inc == nil {
		// A long incident can cover the whole period without a single incident record in it
		// (records are written when it opens, changes and closes): reach back for its start.
		si, err := e.incidentAtStart(ctx, from, to, now)
		if err != nil {
			return zero, err
		}
		if si != nil && si.opened.Before(from) {
			selFrom = si.opened
			if lim := from.Add(-maxIncidentLookback); selFrom.Before(lim) {
				selFrom = lim
			}
			why = "start of incident " + si.id + ", in progress when the period starts"
		}
	}
	sel, err := e.selectByRecords(ctx, all, from, to, selFrom, why)
	if err != nil {
		return zero, err
	}
	p := &buildParams{
		req: req, from: from, to: to, now: now, incident: inc,
		all: all, sel: sel, software: e.opts.Software,
		tokenVerifier: e.opts.TokenVerifier, extra: extra, fullRun: full,
	}

	if err := os.MkdirAll(e.opts.Dir, 0o755); err != nil {
		return zero, fmt.Errorf("export: %w", err)
	}
	tmp, err := os.CreateTemp(e.opts.Dir, ".att-evidence-*.tmp")
	if err != nil {
		return zero, fmt.Errorf("export: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()

	buf := bufio.NewWriterSize(tmp, 1<<20)
	fileHash := sha256.New()
	res, err := e.writeBundle(ctx, io.MultiWriter(buf, fileHash), p)
	if err != nil {
		return zero, err
	}
	if err := buf.Flush(); err != nil {
		return zero, fmt.Errorf("export: write bundle: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return zero, fmt.Errorf("export: sync bundle: %w", err)
	}
	st, err := tmp.Stat()
	if err != nil {
		return zero, fmt.Errorf("export: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return zero, fmt.Errorf("export: close bundle: %w", err)
	}
	final := filepath.Join(e.opts.Dir, res.name)
	if err := commitBundle(tmp.Name(), final); err != nil {
		if errors.Is(err, fs.ErrExist) {
			// Another process created this name after uniqueName chose it; the name is part of
			// the bundle's content, so the bundle cannot simply be renamed.
			return zero, fmt.Errorf("export: %s appeared while the bundle was being written; nothing was overwritten, retry the export: %w", res.name, err)
		}
		return zero, fmt.Errorf("export: rename bundle: %w", err)
	}
	committed = true
	created := now.Truncate(time.Second)
	if err := os.Chtimes(final, created, created); err != nil {
		e.log.Warn("export: cannot set bundle time", "file", res.name, "err", err)
	}
	sum := hex.EncodeToString(fileHash.Sum(nil))
	if fi, err := os.Stat(final); err == nil {
		e.cacheSum(res.name, fileSum{size: fi.Size(), mod: fi.ModTime(), sum: sum})
	}
	info := contracts.ExportInfo{
		FileName:       res.name,
		Path:           final,
		Size:           st.Size(),
		Created:        created,
		SHA256:         sum,
		ManifestSHA256: res.manifestSHA256,
		Records:        res.records,
		Blobs:          res.blobs,
	}
	e.log.Info("evidence bundle written", "file", res.name, "sha256", sum, "records", res.records,
		"blobs", res.blobs, "syslog_chunks", res.syslogChunks, "from", from.UTC().Format(time.RFC3339),
		"to", to.UTC().Format(time.RFC3339), "bundle_checks_ok", res.checksOK)

	if e.opts.Actions == nil {
		return info, nil
	}
	ce := model.CustodyExport{
		From:           from.UTC().Format(time.RFC3339Nano),
		To:             to.UTC().Format(time.RFC3339Nano),
		FileName:       res.name,
		BundleSHA256:   sum,
		ManifestSHA256: res.manifestSHA256,
		Records:        res.records,
		Blobs:          res.blobs,
		PreparedBy:     strings.TrimSpace(req.PreparedBy),
		Notes:          strings.TrimSpace(req.Notes),
		Requester:      strings.TrimSpace(req.Requester),
	}
	if inc != nil {
		ce.IncidentID = inc.inc.ID
	}
	// The bundle exists now; recording its custody must not be lost because the requester
	// went away, so the ledger write is detached from ctx cancellation (but bounded).
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	ref, err := e.opts.Actions.RecordExport(cctx, ce)
	if err != nil {
		e.log.Error("export: custody_export record failed; the bundle exists but is not recorded in the ledger",
			"file", res.name, "err", err)
		return info, fmt.Errorf("%w: %v", ErrCustodyNotRecorded, err)
	}
	info.CustodySeq = ref.Seq
	if err := writeSidecar(final+sidecarSuffix, sidecar{
		Format:        "att-monitor-custody-sidecar/1",
		FileName:      res.name,
		BundleSHA256:  sum,
		Size:          st.Size(),
		Created:       created.UTC().Format(time.RFC3339),
		CustodyExport: ce,
		CustodyRecord: ref,
		Explanation: "The bundle's SHA-256 is recorded in the ledger by the custody_export record above, " +
			"which was appended (and then time-stamped) right after the bundle was produced. " +
			"This file only points to that record; the ledger itself is the evidence.",
	}); err != nil {
		e.log.Error("export: cannot write custody sidecar (the ledger record exists)", "file", res.name, "err", err)
	}
	return info, nil
}

// sidecar is the content of <bundle>.custody.json.
type sidecar struct {
	Format        string              `json:"format"`
	FileName      string              `json:"file_name"`
	BundleSHA256  string              `json:"bundle_sha256"`
	Size          int64               `json:"size"`
	Created       string              `json:"created"`
	CustodyExport model.CustodyExport `json:"custody_export"`
	CustodyRecord model.Ref           `json:"custody_record"`
	Explanation   string              `json:"explanation"`
}

func writeSidecar(path string, s sidecar) error {
	b, err := marshalJSON(s)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readSidecar(path string) (*sidecar, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s sidecar
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// buildResult describes a written bundle.
type buildResult struct {
	name           string
	manifestSHA256 string
	records        int
	blobs          int
	syslogChunks   int
	checksOK       bool
}

// writeBundle streams the zip to out. Ledger segments are copied line by line while they are
// analysed (so the analysed bytes are exactly the bytes in the bundle, even for the active
// segment that keeps growing), then blobs, then the syslog chunks the copied records name, then
// the generated documents and the manifest.
func (e *Exporter) writeBundle(ctx context.Context, out io.Writer, p *buildParams) (*buildResult, error) {
	zw := zip.NewWriter(out)
	bw := &bundleWriter{zw: zw, modified: p.now.Truncate(time.Second), sums: map[string]string{}}
	col := newCollector(p)
	for _, s := range p.sel {
		if err := copySegment(ctx, e.opts.Reader, bw, col, s); err != nil {
			return nil, err
		}
	}
	if err := copyBlobs(ctx, e.opts.Reader, bw, col, nil); err != nil {
		return nil, err
	}
	chunks, err := e.copySyslogChunks(ctx, bw, col)
	if err != nil {
		return nil, err
	}
	if err := p.awaitFull(ctx); err != nil {
		return nil, err
	}

	rep := col.finish()
	rep.Bundle.FileName = e.uniqueName(p.from, p.to, rep.headPrefix())
	if col.zoneErr != nil { // time.Local could not be recorded: the report says UTC
		e.log.Warn("export: local time zone not recorded; local times are shown in UTC", "err", col.zoneErr)
	}
	gen, err := renderGenerated(col, rep, p.extra)
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"keys/public-key.txt", "report.json", "REPORT.html", "README.txt"} {
		if err := bw.addFile(name, gen[name]); err != nil {
			return nil, err
		}
	}
	if err := bw.addFile("tools/verify_bundle.py", verifyScript); err != nil {
		return nil, err
	}
	for _, x := range p.extra {
		if err := bw.addFile(x.path, x.data); err != nil {
			return nil, err
		}
	}
	manifest := bw.manifest()
	if err := bw.addRaw(manifestName, manifest); err != nil {
		return nil, err
	}
	if err := zw.SetComment(zipComment); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("export: finish zip: %w", err)
	}
	return &buildResult{
		name:           rep.Bundle.FileName,
		manifestSHA256: sha256Hex(manifest),
		records:        rep.Ledger.Records,
		blobs:          rep.Verification.Bundle.BlobsIncluded,
		syslogChunks:   chunks,
		checksOK:       rep.Verification.Bundle.OK,
	}, nil
}

// renderGenerated renders the files of a bundle that are generated from its report: report.json,
// REPORT.html, README.txt and keys/public-key.txt (the extra files are described in the report).
func renderGenerated(col *collector, rep *report, extra []extraFile) (map[string][]byte, error) {
	describeExtraFiles(rep, extra)
	js, err := marshalJSON(rep)
	if err != nil {
		return nil, fmt.Errorf("export: encode report.json: %w", err)
	}
	page, err := renderHTML(rep, col.opticalChart(), col.loc)
	if err != nil {
		return nil, err
	}
	return map[string][]byte{
		"keys/public-key.txt": publicKeyText(rep),
		"report.json":         js,
		"REPORT.html":         page,
		"README.txt":          readmeText(rep, col.loc),
	}, nil
}

// copyBlobs puts every blob referenced by the collected records into the bundle (bw nil: only
// checks them, for report verification) and through the collector. failed, when set, turns a
// blob that cannot be read into the error to record (report verification replays the failures
// the export recorded).
func copyBlobs(ctx context.Context, r contracts.LedgerReader, bw *bundleWriter, col *collector, failed func(id string, err error) error) error {
	for i, id := range col.referencedBlobs() {
		if i%64 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		data, err := r.GetBlob(id)
		if err == nil && sha256Hex(data) != id {
			err = errors.New("content does not match its SHA-256 id")
		}
		if err != nil {
			if failed != nil {
				err = failed(id, err)
			}
			col.blobFailed(id, err)
			continue
		}
		if bw != nil {
			if err := bw.addFile("blobs/"+id, data); err != nil {
				return err
			}
		}
		col.blobIncluded(id, data)
	}
	return nil
}

// copySegment streams one segment into the zip (bw nil: only analyses it, for report
// verification) and through the collector, line by line. A trailing partial line of the ACTIVE
// segment (a record being written right now) is left out; a partial line anywhere else is
// evidence of damage and is copied and reported.
func copySegment(ctx context.Context, r contracts.LedgerReader, bw *bundleWriter, col *collector, s segSel) error {
	rc, err := r.OpenSegment(s.info.Name)
	if err != nil {
		return fmt.Errorf("export: open segment %s: %w", s.info.Name, err)
	}
	defer rc.Close()
	path := "ledger/" + s.info.Name + ".jsonl"
	w := io.Discard
	if bw != nil {
		if w, err = bw.create(path); err != nil {
			return err
		}
	}
	h := sha256.New()
	br := bufio.NewReaderSize(rc, 1<<20)
	col.beginSegment(s, path)
	var size int64
	for n := 0; ; n++ {
		if n%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		line, rerr := br.ReadBytes('\n')
		if len(line) > 0 {
			complete := line[len(line)-1] == '\n'
			if !complete && s.info.Active {
				col.droppedTail(len(line))
				break
			}
			if _, err := w.Write(line); err != nil {
				return fmt.Errorf("export: write %s: %w", path, err)
			}
			h.Write(line)
			size += int64(len(line))
			col.line(line, complete)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return fmt.Errorf("export: read segment %s: %w", s.info.Name, rerr)
		}
	}
	if n := col.p.tailBytes[s.info.Name]; n > 0 {
		// Report verification: the export left a partial tail of this (then active) segment out.
		col.droppedTail(n)
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if bw != nil {
		bw.sums[path] = sum
	}
	col.endSegment(sum, size)
	return nil
}

// bundleWriter writes zip entries with fixed timestamps and remembers their SHA-256.
type bundleWriter struct {
	zw       *zip.Writer
	modified time.Time
	sums     map[string]string
}

func (b *bundleWriter) create(name string) (io.Writer, error) {
	w, err := b.zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: b.modified})
	if err != nil {
		return nil, fmt.Errorf("export: zip entry %s: %w", name, err)
	}
	return w, nil
}

func (b *bundleWriter) addRaw(name string, data []byte) error {
	w, err := b.create(name)
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("export: write %s: %w", name, err)
	}
	return nil
}

func (b *bundleWriter) addFile(name string, data []byte) error {
	if err := b.addRaw(name, data); err != nil {
		return err
	}
	b.sums[name] = sha256Hex(data)
	return nil
}

// manifest renders MANIFEST.sha256: "<sha256>  <path>\n" sorted by path.
func (b *bundleWriter) manifest() []byte {
	names := make([]string, 0, len(b.sums))
	for n := range b.sums {
		names = append(names, n)
	}
	sort.Strings(names)
	var sb strings.Builder
	for _, n := range names {
		sb.WriteString(b.sums[n])
		sb.WriteString("  ")
		sb.WriteString(n)
		sb.WriteByte('\n')
	}
	return []byte(sb.String())
}

// uniqueName returns att-evidence_<from>_<to>_<head8>.zip, adding -2, -3, ... when a bundle
// with that name already exists (an existing bundle is never overwritten).
func (e *Exporter) uniqueName(from, to time.Time, head8 string) string {
	base := bundlePrefix + from.UTC().Format(nameTimeLayout) + "_" + to.UTC().Format(nameTimeLayout) + "_" + head8
	name := base + ".zip"
	for i := 2; ; i++ {
		if _, err := os.Lstat(filepath.Join(e.opts.Dir, name)); errors.Is(err, fs.ErrNotExist) {
			return name
		}
		name = fmt.Sprintf("%s-%d.zip", base, i)
	}
}

// ------------------------------------------------------------------ range resolution

// foundIncident is the latest state of an incident found in the ledger.
type foundIncident struct {
	inc       model.Incident
	latestSeq uint64
	openSeq   uint64
	haveOpen  bool
	closeSeq  uint64
	haveClose bool
}

// incidentIDRE matches INC-YYYYMMDD-HHMMSSZ, optionally with the "-N" suffix the monitor adds
// when two incidents would get the same id.
var incidentIDRE = regexp.MustCompile(`^INC-(\d{8}-\d{6})Z(?:-\d+)?$`)

// Every instant the exporter handles must fit time.Time.UnixNano (the chart and the sample
// arithmetic use it); the ledger cannot hold records outside these bounds anyway.
var (
	minPeriodTime = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	maxPeriodTime = time.Date(2262, 1, 1, 0, 0, 0, 0, time.UTC)
)

// checkPeriod rejects periods the report cannot describe: outside 1970..2261 or starting
// after the export time (there can be no records for it yet).
func checkPeriod(from, to, now time.Time) error {
	if from.Before(minPeriodTime) || to.After(maxPeriodTime) {
		return fmt.Errorf("export: period %s .. %s is outside the supported range %s .. %s",
			from.UTC().Format(time.RFC3339), to.UTC().Format(time.RFC3339),
			minPeriodTime.Format(time.RFC3339), maxPeriodTime.Format(time.RFC3339))
	}
	if !from.Before(now) {
		return fmt.Errorf("export: the period starts at %s, after the export time %s",
			from.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	return nil
}

// resolveRange turns a request into the exported period [from, to).
func (e *Exporter) resolveRange(ctx context.Context, req contracts.ExportRequest, now time.Time) (time.Time, time.Time, *foundIncident, error) {
	var zero time.Time
	if id := strings.TrimSpace(req.IncidentID); id != "" {
		fi, err := findIncident(ctx, e.opts.Reader, id, now)
		if err != nil {
			return zero, zero, nil, err
		}
		opened, ok := parseTS(fi.inc.Opened)
		if !ok {
			return zero, zero, nil, fmt.Errorf("export: incident %s has an invalid opened time %q", id, fi.inc.Opened)
		}
		from := opened.Add(-IncidentMargin)
		to := now
		if closed, ok := parseTS(fi.inc.Closed); ok && !fi.inc.Open {
			to = closed.Add(IncidentMargin)
		}
		if !from.Before(to) {
			to = from.Add(2 * IncidentMargin)
		}
		if err := checkPeriod(from, to, now); err != nil {
			return zero, zero, nil, fmt.Errorf("export: incident %s: %w", id, err)
		}
		return from, to, fi, nil
	}
	from, to := req.From, req.To
	if from.IsZero() {
		_, body, err := e.opts.Reader.Record(0)
		if err != nil {
			return zero, zero, nil, fmt.Errorf("export: no start time given and the genesis record is unavailable: %w", err)
		}
		t, ok := parseTS(body.TS)
		if !ok {
			return zero, zero, nil, fmt.Errorf("export: genesis record has an invalid ts %q", body.TS)
		}
		from = t
	}
	if to.IsZero() {
		to = now
	}
	if !from.Before(to) {
		return zero, zero, nil, fmt.Errorf("export: empty or inverted period %s .. %s",
			from.UTC().Format(time.RFC3339), to.UTC().Format(time.RFC3339))
	}
	if err := checkPeriod(from, to, now); err != nil {
		return zero, zero, nil, err
	}
	return from, to, nil, nil
}

// findIncident locates the records of an incident: first by time around the instant encoded in
// its id (INC-YYYYMMDD-HHMMSSZ), then, if that finds nothing, with a full scan.
func findIncident(ctx context.Context, r contracts.LedgerReader, id string, now time.Time) (*foundIncident, error) {
	fi := &foundIncident{}
	found := false
	visit := func(_ model.Envelope, body model.Body) error {
		switch body.Type {
		case model.TypeIncidentOpen, model.TypeIncidentUpdate, model.TypeIncidentClose:
		default:
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		var inc model.Incident
		if err := json.Unmarshal(body.Data, &inc); err != nil || inc.ID != id {
			return nil
		}
		found = true
		fi.inc, fi.latestSeq = inc, body.Seq
		switch body.Type {
		case model.TypeIncidentOpen:
			if !fi.haveOpen {
				fi.openSeq, fi.haveOpen = body.Seq, true
			}
		case model.TypeIncidentClose:
			fi.closeSeq, fi.haveClose = body.Seq, true
			return contracts.ErrStop
		}
		return nil
	}
	if m := incidentIDRE.FindStringSubmatch(id); m != nil {
		if t0, err := time.Parse("20060102-150405", m[1]); err == nil {
			if err := r.ScanTime(t0.Add(-24*time.Hour), now.Add(30*24*time.Hour), visit); err != nil {
				return nil, fmt.Errorf("export: find incident %s: %w", id, err)
			}
			if found {
				return fi, nil
			}
		}
	}
	*fi = foundIncident{}
	if err := r.Scan(0, visit); err != nil {
		return nil, fmt.Errorf("export: find incident %s: %w", id, err)
	}
	if !found {
		return nil, fmt.Errorf("export: incident %s: %w", id, contracts.ErrNotFound)
	}
	return fi, nil
}

// maxIncidentLookback bounds how far before the period the bundle reaches back for the start
// of an incident that is in progress when the period starts.
const maxIncidentLookback = 31 * 24 * time.Hour

// startIncident is the incident the first sample of a period belongs to.
type startIncident struct {
	id     string
	opened time.Time
}

// incidentAtStart returns the incident the first sample of [from, to) is tagged with, or nil.
// The opened time comes from the id (INC-YYYYMMDD-HHMMSSZ, docs/DESIGN.md §10), else from the
// incident's records.
func (e *Exporter) incidentAtStart(ctx context.Context, from, to, now time.Time) (*startIncident, error) {
	var id string
	err := e.opts.Reader.ScanTime(from, to, func(_ model.Envelope, body model.Body) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if body.Type != model.TypeSample {
			return nil
		}
		var tag struct {
			IncidentID string `json:"incident_id"`
		}
		if json.Unmarshal(body.Data, &tag) == nil {
			id = strings.TrimSpace(tag.IncidentID)
		}
		return contracts.ErrStop
	})
	if err != nil {
		return nil, fmt.Errorf("export: read the start of the period: %w", err)
	}
	if id == "" {
		return nil, nil
	}
	if opened, ok := incidentIDTime(id); ok {
		return &startIncident{id: id, opened: opened}, nil
	}
	fi, err := findIncident(ctx, e.opts.Reader, id, now)
	switch {
	case errors.Is(err, contracts.ErrNotFound):
		return nil, nil // the report lists the tag as an incident without records
	case err != nil:
		return nil, err
	}
	opened, ok := parseTS(fi.inc.Opened)
	if !ok {
		return nil, nil
	}
	return &startIncident{id: id, opened: opened}, nil
}

// incidentIDTime returns the opened time encoded in an incident id.
func incidentIDTime(id string) (time.Time, bool) {
	m := incidentIDRE.FindStringSubmatch(id)
	if m == nil {
		return time.Time{}, false
	}
	t, err := time.Parse("20060102-150405", m[1])
	return t, err == nil
}

// ------------------------------------------------------------------ segment selection

// segSel is a segment chosen for the bundle.
type segSel struct {
	info    contracts.SegmentInfo
	index   int       // position in the full, sorted segment list
	start   time.Time // UTC midnight of the segment's date
	end     time.Time // start of the next segment (zero for the last one)
	genesis bool      // first segment of the ledger (holds the public key)
	inRange bool      // overlaps the requested period
	why     string    // why a segment outside the period is included
}

var segmentNameRE = regexp.MustCompile(`^ledger-(\d{4}-\d{2}-\d{2})$`)

// segmentDate returns the UTC date of a segment (from SegmentInfo.Date, else from its name).
func segmentDate(s contracts.SegmentInfo) time.Time {
	if !s.Date.IsZero() {
		y, m, d := s.Date.UTC().Date()
		return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
	}
	if m := segmentNameRE.FindStringSubmatch(s.Name); m != nil {
		if t, err := time.Parse("2006-01-02", m[1]); err == nil {
			return t
		}
	}
	return time.Time{}
}

// sortedSegments orders segments by date and drops repeated names (a reader listing a segment
// twice, e.g. as .jsonl and .jsonl.gz, would otherwise produce duplicate zip entries, which
// every verifier rejects).
func sortedSegments(in []contracts.SegmentInfo) []contracts.SegmentInfo {
	out := make([]contracts.SegmentInfo, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		if !seen[s.Name] {
			seen[s.Name] = true
			out = append(out, s)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		di, dj := segmentDate(out[i]), segmentDate(out[j])
		if !di.Equal(dj) {
			return di.Before(dj)
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// selectSegments picks every segment whose span [its date, next segment's date) overlaps
// [from, to), plus the genesis segment (for the public key and the start of the chain).
func selectSegments(all []contracts.SegmentInfo, from, to time.Time) []segSel {
	return selectSegmentsFrom(all, from, to, from, "", nil)
}

// holding says which records of interest a segment holds (selectByRecords).
type holding struct {
	any    bool // records from the start of the selection (selFrom, less preWindow) to the end of the period
	period bool // records of the period itself
}

// selectSegmentsFrom is selectSegments with the selection (not the period) starting earlier, at
// selFrom <= from (segments included only because of that are marked with why), and with the
// segments in hold, which hold records of interest whatever their dates say. The result is
// always the genesis segment plus one contiguous run of segments.
func selectSegmentsFrom(all []contracts.SegmentInfo, from, to, selFrom time.Time, why string, hold map[int]holding) []segSel {
	const genesisWhy = "genesis record (the ledger's public key)"
	if selFrom.After(from) {
		selFrom = from
	}
	type pick struct{ in, extra bool }
	picks := make([]pick, len(all))
	first, last := -1, -1
	for i, s := range all {
		start := segmentDate(s)
		var end time.Time
		if i+1 < len(all) {
			end = segmentDate(all[i+1])
		}
		overlaps := func(a time.Time) bool { return start.Before(to) && (end.IsZero() || end.After(a)) }
		picks[i] = pick{in: overlaps(from), extra: overlaps(selFrom)}
		if i > 0 && (picks[i].in || picks[i].extra || hold[i].any) {
			if first < 0 {
				first = i
			}
			last = i
		}
	}
	var out []segSel
	for i, s := range all {
		if i != 0 && (first < 0 || i < first || i > last) {
			continue
		}
		start := segmentDate(s)
		var end time.Time
		if i+1 < len(all) {
			end = segmentDate(all[i+1])
		}
		p, h := picks[i], hold[i]
		sel := segSel{info: s, index: i, start: start, end: end, genesis: i == 0, inRange: p.in || h.period}
		switch {
		case sel.inRange:
		case i == 0:
			sel.why = genesisWhy
		case p.extra:
			sel.why = why
		case h.any:
			sel.why = "records from shortly before the period that it holds although it is dated later (the wall clock ran ahead when it was started)"
		default:
			sel.why = "continuity of the ledger between segments that hold records of the period"
		}
		out = append(out, sel)
	}
	return out
}

// selectByRecords chooses the bundle's segments by the times of the records they hold, not
// only by their file dates. A segment holds the records written from its date on, but also
// earlier ones when the wall clock ran ahead past a UTC midnight and was corrected: the writer
// never reopens an older segment, so every correctly time-stamped record that follows lands in
// the future-dated segment until real time reaches its date (internal/ledger ScanTime handles
// the same case). Such a later-dated segment that holds records of the period - or of the
// stretch before it that the report reads (selFrom, and preWindow before it) - is included,
// together with the segments between, keeping the genesis segment plus one contiguous run.
func (e *Exporter) selectByRecords(ctx context.Context, all []contracts.SegmentInfo, from, to, selFrom time.Time, why string) ([]segSel, error) {
	sel := selectSegmentsFrom(all, from, to, selFrom, why, nil)
	last := 0
	for _, s := range sel {
		last = max(last, s.index)
	}
	if last >= len(all)-1 {
		return sel, nil // no segment is dated after the selection
	}
	lo := minTime(selFrom, from).Add(-preWindow)
	hi := to.Add(time.Minute) // a cycle started before the end of the period is recorded a little later
	ix := newSegmentIndexer(all)
	hold := map[int]holding{}
	n := 0
	err := e.opts.Reader.ScanTime(lo, hi, func(_ model.Envelope, body model.Body) error {
		if n++; n%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		a, b := ix.holders(body.Seq)
		if b <= last {
			return nil
		}
		inPeriod := false
		if t, ok := parseTS(body.TS); ok {
			inPeriod = !t.Before(from) && t.Before(to)
		}
		for k := max(a, last+1); k <= b; k++ {
			h := hold[k]
			h.any, h.period = true, h.period || inPeriod
			hold[k] = h
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("export: find the segments holding records of the period: %w", err)
	}
	if len(hold) == 0 {
		return sel, nil
	}
	return selectSegmentsFrom(all, from, to, selFrom, why, hold), nil
}

// segmentIndexer maps a record's seq to the segment holding it, by the first seqs of the
// segments (sorted by date; seqs increase with them). A segment whose first seq is unknown or
// out of order may hold any record between its neighbours.
type segmentIndexer struct {
	all     []contracts.SegmentInfo
	trusted []int // indices of segments with a usable first seq, increasing
}

func newSegmentIndexer(all []contracts.SegmentInfo) *segmentIndexer {
	x := &segmentIndexer{all: all}
	for i, s := range all {
		if i == 0 || (len(x.trusted) > 0 && s.FirstSeq > all[x.trusted[len(x.trusted)-1]].FirstSeq) {
			x.trusted = append(x.trusted, i)
		}
	}
	return x
}

// holders returns the range of segment indices that can hold the record seq.
func (x *segmentIndexer) holders(seq uint64) (lo, hi int) {
	j := sort.Search(len(x.trusted), func(j int) bool { return x.all[x.trusted[j]].FirstSeq > seq }) - 1
	if j < 0 {
		return 0, 0
	}
	lo, hi = x.trusted[j], len(x.all)-1
	if j+1 < len(x.trusted) {
		hi = x.trusted[j+1] - 1
	}
	return lo, hi
}

// ------------------------------------------------------------------ list / open

var bundleNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,200}\.zip$`)

var reservedNames = map[string]bool{"CON": true, "PRN": true, "AUX": true, "NUL": true}

// validName accepts plain file names such as att-evidence_..._abcd1234.zip: no separators,
// no "..", no drive or stream syntax (":"), no Windows device names.
func validName(name string) error {
	if !bundleNameRE.MatchString(name) || strings.Contains(name, "..") || isDeviceName(name) {
		return ErrInvalidName
	}
	return nil
}

// List returns the bundles in Dir, newest first.
func (e *Exporter) List() ([]contracts.ExportInfo, error) {
	out := []contracts.ExportInfo{}
	ents, err := os.ReadDir(e.opts.Dir)
	if errors.Is(err, fs.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, fmt.Errorf("export: list %s: %w", e.opts.Dir, err)
	}
	for _, de := range ents {
		name := de.Name()
		if de.IsDir() || validName(name) != nil {
			continue
		}
		info, err := e.statBundle(name)
		if err != nil {
			e.log.Warn("export: skipping unreadable bundle", "file", name, "err", err)
			continue
		}
		out = append(out, info)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].Created.Equal(out[j].Created) {
			return out[i].Created.After(out[j].Created)
		}
		return out[i].FileName > out[j].FileName
	})
	return out, nil
}

// Open returns a reader for the bundle named name (a plain file name inside Dir).
func (e *Exporter) Open(name string) (io.ReadCloser, contracts.ExportInfo, error) {
	var zero contracts.ExportInfo
	if err := validName(name); err != nil {
		return nil, zero, fmt.Errorf("%w %q: %w", ErrInvalidName, name, contracts.ErrNotFound)
	}
	info, err := e.statBundle(name)
	if err != nil {
		return nil, zero, err
	}
	f, err := os.Open(info.Path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, zero, fmt.Errorf("export: %s: %w", name, contracts.ErrNotFound)
		}
		return nil, zero, fmt.Errorf("export: %w", err)
	}
	return f, info, nil
}

// statBundle describes one bundle file (hashing it unless the hash is cached).
func (e *Exporter) statBundle(name string) (contracts.ExportInfo, error) {
	var zero contracts.ExportInfo
	path := filepath.Join(e.opts.Dir, name)
	fi, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return zero, fmt.Errorf("export: %s: %w", name, contracts.ErrNotFound)
		}
		return zero, fmt.Errorf("export: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return zero, fmt.Errorf("export: %s is not a regular file: %w", name, contracts.ErrNotFound)
	}
	sum, err := e.fileSHA256(name, path, fi)
	if err != nil {
		return zero, err
	}
	info := contracts.ExportInfo{FileName: name, Path: path, Size: fi.Size(), Created: fi.ModTime(), SHA256: sum}
	if sc, err := readSidecar(path + sidecarSuffix); err == nil {
		info.ManifestSHA256 = sc.CustodyExport.ManifestSHA256
		info.Records = sc.CustodyExport.Records
		info.Blobs = sc.CustodyExport.Blobs
		info.CustodySeq = sc.CustodyRecord.Seq
		if sc.BundleSHA256 != sum {
			e.log.Warn("export: bundle content differs from the SHA-256 recorded at creation",
				"file", name, "recorded", sc.BundleSHA256, "actual", sum)
		}
	}
	return info, nil
}

func (e *Exporter) cacheSum(name string, s fileSum) {
	e.cacheMu.Lock()
	e.sums[name] = s
	e.cacheMu.Unlock()
}

func (e *Exporter) fileSHA256(name, path string, fi fs.FileInfo) (string, error) {
	e.cacheMu.Lock()
	c, ok := e.sums[name]
	e.cacheMu.Unlock()
	if ok && c.size == fi.Size() && c.mod.Equal(fi.ModTime()) {
		return c.sum, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("export: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("export: hash %s: %w", name, err)
	}
	sum := hex.EncodeToString(h.Sum(nil))
	e.cacheSum(name, fileSum{size: fi.Size(), mod: fi.ModTime(), sum: sum})
	return sum, nil
}

// ------------------------------------------------------------------ small helpers

// marshalJSON renders indented JSON without HTML escaping ("AT&T", not "AT&T"),
// terminated by a newline. The output is deterministic (struct field order, sorted map keys).
func marshalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// parseTS parses an RFC 3339 timestamp (with or without fractional seconds).
func parseTS(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
