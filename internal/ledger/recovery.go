package ledger

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"attmonitor/internal/model"
)

const (
	maxAlertDetails     = 100
	maxAlertDetailBytes = 1024

	// pendingExt marks a pending-recovery marker in the quarantine directory: the recovery
	// record (JSON) for bytes that were moved to quarantine but are not yet recorded in the
	// ledger. It is written before anything is moved and removed once the record is durable, so
	// a crash in between cannot leave quarantined bytes undocumented.
	pendingExt = ".pending"
)

// pendingRecord is appended once Open has established the chain head.
type pendingRecord struct {
	typ    string
	data   any
	marker string // pending-recovery marker to remove once the record is durable ("" = none)
}

// openWriter performs the writer side of Open (docs/DESIGN.md §6).
func (s *Store) openWriter() error {
	for _, d := range []string{s.ledgerDir, s.blobDir, s.blobTmpDir, s.keyDir, s.quarDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("ledger: %w", err)
		}
	}
	lock, err := acquireLock(filepath.Join(s.ledgerDir, ".lock"))
	if err != nil {
		return err
	}
	s.lock = lock

	files, err := listSegmentFiles(s.ledgerDir)
	if err != nil {
		return fmt.Errorf("ledger: %w", err)
	}
	hadSegments := len(files) > 0

	priv, kf, err := loadKey(s.keyDir, s.opts.KeyUnprotect)
	newKey := false
	switch {
	case err == nil:
	case errors.Is(err, os.ErrNotExist):
		if hadSegments {
			return fmt.Errorf("ledger: %d segment(s) exist in %s but the signing key %s is missing; restore the key file from backup, or move the ledger directory aside to start a new ledger",
				len(files), s.ledgerDir, keyPath(s.keyDir))
		}
		priv, kf, err = generateKey(s.keyDir, s.now(), s.opts.KeyProtect)
		if err != nil {
			return err
		}
		newKey = true
	default:
		return err
	}
	s.priv = priv
	s.pub = priv.Public().(ed25519.PublicKey)
	s.fp = Fingerprint(s.pub)

	var pending []pendingRecord
	var problems []string

	// Refuse a foreign key before touching anything. A key confirmed by the genesis record
	// is never refused later: records it cannot verify are then tampering, not a wrong key.
	s.keyConfirmed = !hadSegments
	if hadSegments {
		confirmed, p, err := s.checkGenesisKey(files[0])
		if err != nil {
			return err
		}
		s.keyConfirmed = confirmed
		problems = append(problems, p...)
	}

	tmpRecs, err := s.recoverTempFiles()
	if err != nil {
		return err
	}
	pending = append(pending, tmpRecs...)
	s.clearBlobTemps()

	s.mu.Lock()
	defer s.mu.Unlock()
	var documented map[string]bool // quarantine files recorded by the active segment
	for {
		if len(files) == 0 {
			if err := s.createGenesisLocked(); err != nil {
				return err
			}
			switch {
			case hadSegments:
				problems = append(problems, "no valid record remained in any ledger segment; a new genesis record was written")
			case !newKey:
				problems = append(problems, fmt.Sprintf("the signing key (created %s) existed but no ledger segment was found in %s; a new genesis record was written, and any earlier ledger is no longer in this directory",
					kf.Created, s.ledgerDir))
			}
			documented = nil
			break
		}
		res, err := s.openActive(files)
		if err != nil {
			return err
		}
		pending = append(pending, res.pending...)
		problems = append(problems, res.problems...)
		documented = res.documented
		if res.removed {
			files = files[:len(files)-1]
			continue
		}
		break
	}

	// A wall clock behind the newest record: everything appended from now on is dated before
	// records that precede it in the chain. Within a run the monitor records clock steps
	// (clock_jump); across a restart only the writer sees both times, so it records the step.
	if !s.created {
		if p := s.clockBehindHead(); p != "" {
			problems = append(problems, p)
		}
	}

	// Bytes quarantined by an earlier start that stopped before recording them come first.
	created := map[string]bool{}
	for _, p := range pending {
		if p.marker != "" {
			created[p.marker] = true
		}
	}
	late, lateProblems := s.pendingMarkers(created, documented)
	pending = append(late, pending...)
	problems = append(problems, lateProblems...)

	for _, p := range pending {
		data, err := marshalJSON(p.data)
		if err != nil {
			return err
		}
		if _, err := s.appendLocked(p.typ, data, nil); err != nil {
			return fmt.Errorf("ledger: append %s record: %w", p.typ, err)
		}
		if p.marker != "" {
			if err := os.Remove(p.marker); err != nil {
				// Harmless: the next Open finds the record and only removes the marker.
				s.log.Warn("remove pending-recovery marker", "marker", p.marker, "err", err)
			}
		}
		s.log.Warn("ledger recovery", "record", p.typ, "detail", p.data)
	}
	if len(problems) > 0 {
		alert := model.IntegrityAlert{
			Problem: fmt.Sprintf("integrity problems found while opening the ledger (%d)", len(problems)),
			Details: capDetails(problems),
		}
		data, err := marshalJSON(&alert)
		if err != nil {
			return err
		}
		if _, err := s.appendLocked(model.TypeIntegrityAlert, data, nil); err != nil {
			return fmt.Errorf("ledger: append integrity_alert: %w", err)
		}
		s.log.Error("ledger integrity problems found on open", "count", len(problems), "first", problems[0])
	}
	// Only now is the key known to belong to this ledger: the human-readable copy of the
	// public key must never show a key that Open refused.
	if err := writePublicKeyText(s.keyDir, s.pub, kf.Created); err != nil {
		s.log.Warn("write public key text", "err", err)
	}
	s.log.Info("ledger opened", "head_seq", s.head.Seq, "segment", s.active.name, "fingerprint", s.fp, "created", s.created)
	return nil
}

// clockBehindHead describes a wall clock that is more than tsTolerance behind the ts of the
// newest record found on open ("" otherwise). The verifier recognises the description by its
// prefix (clockBehindPrefix).
func (s *Store) clockBehindHead() string {
	head, err := time.Parse(time.RFC3339Nano, s.head.TS)
	if err != nil {
		return ""
	}
	now := s.now().UTC()
	behind := head.Sub(now)
	if behind <= tsTolerance {
		return ""
	}
	return fmt.Sprintf("%s: it reads %s when the ledger is opened, %s before the ts %s of the newest record (seq %d). "+
		"The clock was set back while no writer was running, or records already in the ledger are dated too late; "+
		"records appended from now on are dated before records that precede them in the chain",
		clockBehindPrefix, now.Format(time.RFC3339Nano), fmtDur(behind), clip(s.head.TS), s.head.Seq)
}

// capDetails bounds an integrity_alert's details: at most maxAlertDetails entries of at most
// maxAlertDetailBytes each, so that the record always fits (values may come from tampered
// records).
func capDetails(d []string) []string {
	n := min(len(d), maxAlertDetails)
	out := make([]string, 0, n+1)
	for _, s := range d[:n] {
		out = append(out, clipTo(s, maxAlertDetailBytes))
	}
	if len(d) > n {
		out = append(out, fmt.Sprintf("... and %d more", len(d)-n))
	}
	return out
}

// checkGenesisKey refuses to open a ledger whose (self-consistent) genesis record names a
// different public key than the signing key: records appended with it would never verify.
// confirmed reports that the genesis record verifies and names the signing key. Other
// problems are returned for the integrity alert.
func (s *Store) checkGenesisKey(first segFile) (confirmed bool, problems []string, err error) {
	line, err := readFirstLine(first)
	if err != nil {
		return false, []string{fmt.Sprintf("first segment %s cannot be read: %v", first.Name, err)}, nil
	}
	if line == nil {
		return false, []string{fmt.Sprintf("first segment %s has no complete first record", first.Name)}, nil
	}
	env, body, err := parseRecordLenient(line)
	if err != nil {
		return false, []string{fmt.Sprintf("first record of %s is unreadable: %v", first.Name, err)}, nil
	}
	if body.Type != model.TypeGenesis || body.Seq != 0 {
		return false, []string{fmt.Sprintf("first segment %s begins with %q seq %d instead of the genesis record", first.Name, clip(body.Type), body.Seq)}, nil
	}
	var g model.Genesis
	if err := json.Unmarshal(body.Data, &g); err != nil {
		return false, []string{"genesis payload is unreadable: " + err.Error()}, nil
	}
	pub, err := base64.StdEncoding.DecodeString(g.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false, []string{"genesis public_key is not a base64 Ed25519 key"}, nil
	}
	b := []byte(env.B)
	sig, serr := decodeSignature(env.S)
	if sha256Hex(b) != env.H || serr != nil || !ed25519.Verify(pub, b, sig) {
		return false, []string{"the genesis record does not verify (hash or self-signature); the signing key cannot be confirmed against it"}, nil
	}
	if !bytes.Equal(pub, s.pub) {
		return false, nil, fmt.Errorf("ledger: the signing key %s (fingerprint %s) does not match the ledger's genesis key (fingerprint %s); refusing to append records that would not verify; restore the original key file",
			keyPath(s.keyDir), FormatFingerprint(s.fp), FormatFingerprint(Fingerprint(pub)))
	}
	s.genesisTS = body.TS
	return true, nil, nil
}

// ---------------------------------------------------------------- active segment

type activeResult struct {
	pending  []pendingRecord
	problems []string
	removed  bool // the latest segment held no valid record and was removed (bytes quarantined)
	// documented holds the quarantine_as of every recovery record kept in the segment.
	documented map[string]bool
}

// openActive recovers and validates the latest segment and makes it the active one.
func (s *Store) openActive(files []segFile) (activeResult, error) {
	var res activeResult
	last := files[len(files)-1]
	switch {
	case last.Plain == "":
		// Only the compressed form exists (possible after a damaged newer segment was removed):
		// restore the uncompressed original so it can be appended to.
		p, err := s.decompressSegmentFile(last)
		if err != nil {
			return res, err
		}
		last.Plain, last.Gz = p, ""
	case last.Gz != "":
		// Leftover of an interrupted decompression/compression: the .jsonl is the original.
		same, err := sameContent(last.Plain, last.Gz)
		if err == nil && same {
			if err := os.Remove(last.Gz); err != nil {
				return res, fmt.Errorf("ledger: remove stale compressed copy of the active segment: %w", err)
			}
		} else {
			q, qerr := s.quarantineMove(last.Gz, filepath.Base(last.Gz)+".stale")
			if qerr != nil {
				return res, fmt.Errorf("ledger: quarantine stale compressed copy of the active segment: %w", qerr)
			}
			res.problems = append(res.problems, fmt.Sprintf("a compressed copy of the active segment %s differed from it (%v); it was moved to %s", last.Name, err, q))
		}
		last.Gz = ""
	}

	var prev *segSummary
	firstSeg := len(files) == 1
	if !firstSeg {
		p := files[len(files)-2]
		sum, err := summarizeSegment(p)
		if err != nil {
			res.problems = append(res.problems, fmt.Sprintf("previous segment %s cannot be read: %v", p.Name, err))
		} else {
			prev = sum
		}
	}

	f, err := openExclusiveRW(last.Plain)
	if err != nil {
		return res, fmt.Errorf("ledger: open active segment: %w", err)
	}
	keep := false
	defer func() {
		if !keep {
			f.Close()
		}
	}()
	st, err := f.Stat()
	if err != nil {
		return res, fmt.Errorf("ledger: %w", err)
	}
	size := st.Size()
	v, err := s.validateSegment(f, size, last, prev, firstSeg)
	if err != nil {
		return res, err
	}
	// Without a genesis record confirming the key, intact records that all fail signature
	// verification mean the key file is foreign: refuse rather than quarantine good records.
	if v.valid == 0 && v.intactBadSig > 0 && !s.keyConfirmed {
		return res, fmt.Errorf("ledger: no record of the active segment %s verifies with the signing key (fingerprint %s) although %d record(s) are intact, and the genesis record could not confirm the key; the key file does not belong to this ledger",
			last.Name, FormatFingerprint(s.fp), v.intactBadSig)
	}
	res.documented = v.documented

	what := "was empty"
	if v.validEnd < size {
		rec, marker, err := s.quarantineTail(f, last.Name, v.validEnd, size, v.tailReason())
		if err != nil {
			return res, err
		}
		res.pending = append(res.pending, pendingRecord{typ: model.TypeRecovery, data: rec, marker: marker})
		if v.tailLines > 1 || v.tailIntact > 0 {
			res.problems = append(res.problems, fmt.Sprintf("%d line(s) at the end of %s failed verification (more than a torn write explains); they were moved to %s",
				v.tailLines, last.Name, rec.QuarantineAs))
			res.problems = append(res.problems, v.tailProblems...)
		}
		what = fmt.Sprintf("contained no valid record; its %d bytes (SHA-256 %s) were moved to %s", rec.RemovedBytes, rec.RemovedSHA256, rec.QuarantineAs)
	}
	if v.validEnd == 0 {
		// Nothing valid remains (a crash cannot cause this: segments are created atomically
		// with a complete first record). Remove the empty file and continue with the previous
		// segment; the recovery record and the integrity_alert document what happened.
		f.Close()
		keep = true
		if err := os.Remove(last.Plain); err != nil {
			return res, fmt.Errorf("ledger: segment %s %s, but the empty file could not be removed: %w", last.Name, what, err)
		}
		res.removed = true
		res.problems = append(res.problems, fmt.Sprintf("segment %s %s; the empty file was removed", last.Name, what))
		return res, nil
	}
	res.problems = append(res.problems, v.problems...)

	keep = true
	s.active = &activeSeg{
		name: last.Name, date: last.Date, path: last.Plain, f: f,
		size: v.validEnd, records: v.lastLine, firstSeq: v.firstSeq, lastSeq: v.lastSeq,
	}
	// Continue chaining from the last line as found; never reuse a seq already present.
	s.head = model.Ref{Seq: v.lastSeq, Hash: v.lastHash, TS: v.lastTS}
	s.nextSeq = v.maxSeq + 1
	if prev != nil && prev.HaveLast && prev.LastSeq+1 > s.nextSeq {
		s.nextSeq = prev.LastSeq + 1
	}
	if firstSeg && v.genesisTS != "" {
		s.genesisTS = v.genesisTS
	}
	return res, nil
}

// valResult is the outcome of validating the active segment on open.
type valResult struct {
	valid        int // lines that are intact and correctly signed (never truncated)
	intactBadSig int // lines with a correct hash and body but a bad signature
	documented   map[string]bool
	validEnd     int64
	lastLine     int // line number of the last valid line
	lastSeq      uint64
	lastHash     string
	lastTS       string
	maxSeq       uint64
	firstSeq     uint64
	haveFirst    bool
	genesisTS    string
	problems     []string // in the kept region
	tailLines    int      // lines (complete or partial) after the last valid line
	tailIntact   int      // complete tail lines with an intact hash/body
	tailProblems []string
	tailPartial  int64
	firstTail    string
}

func (v *valResult) tailReason() string {
	switch {
	case v.tailIntact > 0:
		// Intact tail lines are exactly those not signed with this ledger's key.
		return fmt.Sprintf("%d trailing line(s) failed verification, %d of them intact but not signed with this ledger's key: not a torn write (see the integrity_alert record)",
			v.tailLines, v.tailIntact)
	case v.tailLines <= 1 && v.tailPartial > 0:
		return "incomplete final line (no trailing newline): a write was interrupted by a crash or power loss"
	case v.tailLines <= 1:
		if v.firstTail != "" {
			return "the final line failed verification (" + v.firstTail + "): torn write or corruption"
		}
		return "the final line failed verification: torn write or corruption"
	default:
		return fmt.Sprintf("%d trailing lines failed verification; more than a single torn write can explain (see the integrity_alert record)", v.tailLines)
	}
}

// validateSegment checks every line of the active segment (hash, signature, seq/prev linkage,
// and linkage to the previous segment) and locates the end of the last valid line.
//
// A line is valid — and is never truncated — when it is intact (its hash matches and its body
// parses) and correctly signed: only the key holder can produce such a line, a crash cannot.
// Other problems of a valid line (format version, ts, linkage) are reported, not repaired.
func (s *Store) validateSegment(f *os.File, size int64, seg segFile, prev *segSummary, firstSeg bool) (*valResult, error) {
	src := lineSource{name: seg.Name, date: seg.Date, open: func() (io.ReadCloser, error) {
		return io.NopCloser(io.NewSectionReader(f, 0, size)), nil
	}}
	rep := model.VerifyReport{TypeCounts: map[string]int{}}
	c := newChainChecker(&rep, VerifyOptions{}, []lineSource{src}, false)
	c.pub = s.pub
	c.liveTail = true // an incomplete final line is handled as a torn tail below
	if firstSeg {
		c.firstLedgerSeg = 0
	}
	if prev != nil {
		c.prevSum = prev
		if prev.HaveLast {
			c.prevHash, c.havePrev = prev.LastHash, true
			c.expectSeq, c.haveExpect = prev.LastSeq+1, true
		}
	}
	var fails []model.VerifyFailure
	c.onFail = func(f model.VerifyFailure) {
		if len(fails) < 10*maxAlertDetails {
			fails = append(fails, f)
		}
	}
	v := &valResult{documented: map[string]bool{}}
	type tailLine struct {
		intact bool
	}
	var after []tailLine // complete lines after the current last valid line
	total := 0
	visit := func(r *lineResult) {
		c.line(r)
		total = r.lineNo
		intact := r.envOK && r.claimH == r.hashHex && r.bodyOK
		valid := intact && r.sig == sigOK
		if intact && r.sig == sigBad {
			v.intactBadSig++
		}
		if valid && r.recoveryOf != "" {
			v.documented[r.recoveryOf] = true
		}
		if r.bodyOK && !v.haveFirst {
			v.firstSeq, v.haveFirst = r.body.Seq, true
		}
		if !valid {
			after = append(after, tailLine{intact: intact})
			return
		}
		after = after[:0]
		v.valid++
		v.validEnd = r.off + int64(r.n)
		v.lastLine = r.lineNo
		v.lastSeq, v.lastHash, v.lastTS = r.body.Seq, r.hashHex, r.body.TS
		if v.valid == 1 || r.body.Seq > v.maxSeq {
			v.maxSeq = r.body.Seq
		}
		if r.body.Type == model.TypeGenesis {
			v.genesisTS = r.body.TS
		}
	}
	segDone := func(e *segEnd) {
		c.segDone(e)
		v.tailPartial = e.partial
	}
	if err := runPipeline(context.Background(), []lineSource{src}, &workerConfig{pub: s.pub}, visit, segDone); err != nil {
		return nil, fmt.Errorf("ledger: validate active segment %s: %w", seg.Name, err)
	}
	v.tailLines = total - v.lastLine
	if v.tailPartial > 0 {
		v.tailLines++
	}
	for _, t := range after {
		if t.intact {
			v.tailIntact++
		}
	}
	for _, f := range fails {
		msg := fmt.Sprintf("%s line %d (seq %d): %s: %s", f.Segment, f.Line, f.Seq, f.Problem, f.Detail)
		if f.Line <= v.lastLine {
			v.problems = append(v.problems, msg)
		} else {
			if v.firstTail == "" {
				v.firstTail = f.Problem + ": " + f.Detail
			}
			v.tailProblems = append(v.tailProblems, msg)
		}
	}
	return v, nil
}

// quarantineTail copies bytes [from, to) of the active segment to quarantine, then truncates
// the segment to from. The recovery record is first saved as a pending marker and the bytes
// are durable in quarantine before anything is removed; the caller appends the record and then
// removes the marker (returned).
func (s *Store) quarantineTail(f *os.File, segName string, from, to int64, reason string) (model.Recovery, string, error) {
	qpath := s.uniqueQuarantinePath(fmt.Sprintf("%s.%d.tail", segName, from))
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(f, from, to-from)); err != nil {
		return model.Recovery{}, "", fmt.Errorf("ledger: read damaged tail of %s: %w", segName, err)
	}
	rec := model.Recovery{
		Segment:       segName,
		Offset:        from,
		RemovedBytes:  to - from,
		RemovedSHA256: hex.EncodeToString(h.Sum(nil)),
		QuarantineAs:  "quarantine/" + filepath.Base(qpath),
		Reason:        clipTo(reason, maxAlertDetailBytes),
	}
	marker, err := writeRecoveryMarker(qpath, rec)
	if err != nil {
		return model.Recovery{}, "", fmt.Errorf("ledger: quarantine damaged tail of %s: %w", segName, err)
	}
	h.Reset()
	if err := writeStreamAtomic(qpath, qpath+tmpExt, io.TeeReader(io.NewSectionReader(f, from, to-from), h)); err != nil {
		return model.Recovery{}, "", fmt.Errorf("ledger: quarantine damaged tail of %s: %w", segName, err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != rec.RemovedSHA256 {
		// Impossible while this writer holds the segment exclusively; never truncate then.
		return model.Recovery{}, "", fmt.Errorf("ledger: tail of %s changed while being quarantined (%s != %s)", segName, got, rec.RemovedSHA256)
	}
	if err := f.Truncate(from); err != nil {
		return model.Recovery{}, "", fmt.Errorf("ledger: truncate %s: %w", segName, err)
	}
	if err := f.Sync(); err != nil {
		return model.Recovery{}, "", fmt.Errorf("ledger: sync %s: %w", segName, err)
	}
	return rec, marker, nil
}

// writeRecoveryMarker durably saves rec next to the quarantine file it describes (qpath) and
// returns the marker's path.
func writeRecoveryMarker(qpath string, rec model.Recovery) (string, error) {
	b, err := json.MarshalIndent(&rec, "", "  ")
	if err != nil {
		return "", err
	}
	marker := qpath + pendingExt
	if err := writeFileAtomic(marker, append(b, '\n'), 0o644, true); err != nil {
		return "", fmt.Errorf("write pending-recovery marker: %w", err)
	}
	return marker, nil
}

// pendingMarkers returns the recovery records of markers left by an earlier start that
// stopped after quarantining bytes and before recording them. Markers whose record is already
// in the active segment (documented) only lost their cleanup and are removed; markers created
// by this Open (skip) are already pending.
func (s *Store) pendingMarkers(skip, documented map[string]bool) ([]pendingRecord, []string) {
	entries, err := os.ReadDir(s.quarDir)
	if err != nil {
		return nil, []string{fmt.Sprintf("the quarantine directory cannot be listed: %v", err)}
	}
	var out []pendingRecord
	var problems []string
	for _, e := range entries {
		n := e.Name()
		p := filepath.Join(s.quarDir, n)
		if !e.Type().IsRegular() || skip[p] {
			continue
		}
		if strings.HasPrefix(n, ".") && strings.HasSuffix(n, tmpExt) && strings.Contains(n, pendingExt+".") {
			_ = os.Remove(p) // a marker write interrupted before its rename
			continue
		}
		if !strings.HasSuffix(n, pendingExt) {
			continue
		}
		var rec model.Recovery
		b, err := os.ReadFile(p)
		if err == nil {
			err = json.Unmarshal(b, &rec)
		}
		qname := strings.TrimSuffix(n, pendingExt)
		if err == nil {
			// Everything goes into a ledger record: accept only what this writer produces.
			_, _, segOK := parseSegmentName(rec.Segment)
			switch {
			case rec.QuarantineAs != "quarantine/"+qname:
				err = fmt.Errorf("it names %q", clip(rec.QuarantineAs))
			case !segOK || !isLowerHex(rec.RemovedSHA256, 64) || rec.Offset < 0 || rec.RemovedBytes < 0:
				err = errors.New("its fields are not those of a recovery record")
			}
		}
		if err != nil {
			problems = append(problems, fmt.Sprintf("pending-recovery marker quarantine/%s is unreadable (%v); %s", n, err, s.setAside(p, n)))
			continue
		}
		if documented[rec.QuarantineAs] {
			if err := os.Remove(p); err != nil {
				s.log.Warn("remove pending-recovery marker", "marker", p, "err", err)
			}
			continue
		}
		got, err := hashStream(func() (io.ReadCloser, error) { return openShared(filepath.Join(s.quarDir, qname)) })
		switch {
		case err != nil:
			problems = append(problems, fmt.Sprintf("pending-recovery marker quarantine/%s describes %s, which cannot be read (%v); %s",
				n, rec.QuarantineAs, err, s.setAside(p, n)))
			continue
		case got != rec.RemovedSHA256:
			problems = append(problems, fmt.Sprintf("%s has SHA-256 %s but the bytes removed from %s hashed to %s", rec.QuarantineAs, got, rec.Segment, rec.RemovedSHA256))
		}
		rec.Reason = clipTo(rec.Reason, maxAlertDetailBytes) +
			" (recorded on a later start: the writer stopped after quarantining these bytes and before recording them)"
		out = append(out, pendingRecord{typ: model.TypeRecovery, data: rec, marker: p})
	}
	return out, problems
}

// setAside renames a marker that cannot be honoured so that it is reported only once, and
// describes what happened.
func (s *Store) setAside(path, name string) string {
	q, err := s.quarantineMove(path, name+".unusable")
	if err != nil {
		return fmt.Sprintf("it could not be set aside: %v", err)
	}
	return "it was renamed to " + q
}

// summarizeSegment reads a whole segment: SHA-256 of its uncompressed bytes, line count and
// the hash and seq of its last record.
func summarizeSegment(f segFile) (*segSummary, error) {
	rc, err := openSegmentFile(f, -1)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	h := sha256.New()
	lr := newLineReader(io.TeeReader(rc, h), readBufSize)
	sum := &segSummary{Name: f.Name}
	var last []byte
	for {
		rec, err := lr.next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if !rec.complete {
			sum.Partial = int64(rec.n)
			continue
		}
		sum.Lines++
		if rec.tooLong {
			last = nil
		} else {
			last = append(last[:0], rec.data...)
		}
	}
	sum.SHA256 = hex.EncodeToString(h.Sum(nil))
	if last != nil {
		if env, body, err := parseRecordLenient(last); err == nil {
			sum.LastSeq, sum.LastHash, sum.HaveLast = body.Seq, sha256Hex([]byte(env.B)), true
		}
	}
	return sum, nil
}

// ---------------------------------------------------------------- leftovers & quarantine

// recoverTempFiles handles files left by interrupted operations: an incomplete segment
// creation is preserved in quarantine and documented; temporary compressed copies are derived
// data and simply removed.
func (s *Store) recoverTempFiles() ([]pendingRecord, error) {
	entries, err := os.ReadDir(s.ledgerDir)
	if err != nil {
		return nil, fmt.Errorf("ledger: %w", err)
	}
	var out []pendingRecord
	for _, e := range entries {
		n := e.Name()
		if !e.Type().IsRegular() || !strings.HasSuffix(n, tmpExt) || !strings.HasPrefix(n, segPrefix) {
			continue
		}
		p := filepath.Join(s.ledgerDir, n)
		base := strings.TrimSuffix(n, tmpExt)
		if strings.HasSuffix(base, segExt+gzExt) || strings.HasSuffix(base, segExt+".dz") {
			if err := os.Remove(p); err != nil {
				s.log.Warn("remove temporary file", "file", n, "err", err)
			}
			continue
		}
		name, _, ok := parseSegmentName(base)
		if !ok {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return nil, fmt.Errorf("ledger: %w", err)
		}
		if info.Size() == 0 {
			if err := os.Remove(p); err != nil {
				s.log.Warn("remove empty temporary segment", "file", n, "err", err)
			}
			continue
		}
		content, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("ledger: read %s: %w", n, err)
		}
		qpath := s.uniqueQuarantinePath(name + segExt + ".incomplete")
		rec := model.Recovery{
			Segment:       name,
			Offset:        0,
			RemovedBytes:  int64(len(content)),
			RemovedSHA256: sha256Hex(content),
			QuarantineAs:  "quarantine/" + filepath.Base(qpath),
			Reason:        "incomplete segment creation (genesis or rotation interrupted before the file was renamed into place); its content was never part of the ledger",
		}
		// The marker comes first: once the file has moved, the record must not get lost.
		marker, err := writeRecoveryMarker(qpath, rec)
		if err != nil {
			return nil, fmt.Errorf("ledger: quarantine %s: %w", n, err)
		}
		if err := renameNoReplace(p, qpath); err != nil {
			return nil, fmt.Errorf("ledger: quarantine %s: %w", n, err)
		}
		out = append(out, pendingRecord{typ: model.TypeRecovery, data: rec, marker: marker})
	}
	return out, nil
}

// clearBlobTemps removes temporary blob files left by an interrupted PutBlob.
func (s *Store) clearBlobTemps() {
	entries, err := os.ReadDir(s.blobTmpDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.Type().IsRegular() {
			_ = os.Remove(filepath.Join(s.blobTmpDir, e.Name()))
		}
	}
}

// uniqueQuarantinePath returns an unused path in the quarantine directory for base.
func (s *Store) uniqueQuarantinePath(base string) string {
	for i := 0; ; i++ {
		name := base
		if i > 0 {
			name = fmt.Sprintf("%s.%d", base, i)
		}
		p := filepath.Join(s.quarDir, name)
		if _, err := os.Lstat(p); errors.Is(err, os.ErrNotExist) {
			return p
		}
	}
}

// quarantineMove moves path into the quarantine directory and returns its description
// ("quarantine/<file>").
func (s *Store) quarantineMove(path, base string) (string, error) {
	q := s.uniqueQuarantinePath(base)
	if err := renameNoReplace(path, q); err != nil {
		return "", err
	}
	return "quarantine/" + filepath.Base(q), nil
}

// writeStreamAtomic writes r to the temporary file tmp, fsyncs it and renames it to path
// (never replacing an existing file).
func writeStreamAtomic(path, tmp string, r io.Reader) error {
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, r)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = renameNoReplace(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// decompressSegmentFile restores a segment's uncompressed form from its .jsonl.gz.
func (s *Store) decompressSegmentFile(f segFile) (string, error) {
	plain := strings.TrimSuffix(f.Gz, gzExt)
	rc, err := openGz(f.Gz)
	if err != nil {
		return "", err
	}
	// The temporary name ends in ".jsonl.dz.tmp" so that recoverTempFiles treats a leftover
	// as derived data rather than as an interrupted segment creation.
	err = writeStreamAtomic(plain, plain+".dz"+tmpExt, rc)
	rc.Close()
	if err != nil {
		return "", fmt.Errorf("ledger: decompress %s: %w", f.Name, err)
	}
	if err := os.Remove(f.Gz); err != nil {
		s.log.Warn("remove compressed segment after restoring it", "segment", f.Name, "err", err)
	}
	s.log.Info("restored uncompressed latest segment", "segment", f.Name)
	return plain, nil
}

// sameContent reports whether a plain segment and a compressed one hold identical bytes.
func sameContent(plain, gz string) (bool, error) {
	hp, err := hashStream(func() (io.ReadCloser, error) { return openShared(plain) })
	if err != nil {
		return false, err
	}
	hg, err := hashStream(func() (io.ReadCloser, error) { return openGz(gz) })
	if err != nil {
		return false, err
	}
	return hp == hg, nil
}

func hashStream(open func() (io.ReadCloser, error)) (string, error) {
	rc, err := open()
	if err != nil {
		return "", err
	}
	defer rc.Close()
	h := sha256.New()
	if _, err := io.Copy(h, rc); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
