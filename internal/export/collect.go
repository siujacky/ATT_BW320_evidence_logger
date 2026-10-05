package export

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// maxBundleFailures caps the failures listed in report.json (the total is always counted).
const maxBundleFailures = 50

// collector verifies and analyses the records while they are copied into the bundle. The
// integrity part mirrors docs/DESIGN.md §6 (envelope hash, Ed25519 signature with the genesis
// key, seq/prev chain, segment_open linkage, blobs, anchors) restricted to what the bundle
// contains; the analysis part (aggregate.go) feeds the report.
type collector struct {
	p        *buildParams
	from, to time.Time // requested period
	end      time.Time // min(to, now): statistics stop here
	now      time.Time

	cur     *segState
	segs    []*segmentEntry
	omitted []omittedSegment
	// omissions are the places where ledger segments were left out of the bundle, with the
	// process (run) that wrote the first record after them.
	omissions       []omission
	pendingOmission bool

	// integrity state
	pub        ed25519.PublicKey // genesis key, nil until a valid genesis record was seen
	gen        *genesisFacts
	havePrev   bool
	prevSeq    uint64
	prevHash   string
	lastSeg    *segmentEntry
	lastSegIdx int
	seqHashes  []seqHash
	seqSorted  bool
	seqIndex   map[uint64]string // built from seqHashes when they are not sorted
	chk        bundleCheck
	typeCounts map[string]int
	blobRefs   map[string]uint64 // blob id -> first referencing seq
	blobIn     map[string]bool
	tokenOf    map[string][]int    // token blob id -> indices into agg.anchors (built lazily)
	tokenRes   map[int]tokenResult // anchor index -> token check
	head       *recordRef
	dataNotes  int
	notes      []string // report-level notes (interpretation problems)

	agg aggregator

	// range of the record times of the bundle (for the local time zone record)
	minTS, maxTS time.Time

	// computed by finish, used by the chart
	periods []alarmPeriod
	rep     *report
	tl      []acctSample     // samples with their cycle time (see timeline)
	windows []*restartWindow // gateway-restart windows
	loc     *time.Location   // the local zone the report renders with
	zoneErr error            // the stated local zone is unusable (verification)
}

type segState struct {
	sel   segSel
	entry *segmentEntry
	line  int
}

type seqHash struct {
	seq  uint64
	hash string
}

type omission struct {
	afterSeq uint64 // last seq before the omitted segments
	firstRun int32  // run of the first record after them (-1: none parsed)
}

type genesisFacts struct {
	ref         recordRef
	g           model.Genesis
	fingerprint string // computed from the key
}

func newCollector(p *buildParams) *collector {
	end := p.to
	if p.now.Before(end) {
		end = p.now
	}
	if end.Before(p.from) {
		end = p.from
	}
	c := &collector{
		p: p, from: p.from, to: p.to, end: end, now: p.now,
		lastSegIdx: -1, seqSorted: true,
		typeCounts: map[string]int{}, blobRefs: map[string]uint64{}, blobIn: map[string]bool{}, tokenRes: map[int]tokenResult{},
	}
	c.agg.init()
	return c
}

// beginSegment starts a new segment, remembering the segments of the ledger skipped since
// the previous included one (report.json ledger.omitted_segments).
func (c *collector) beginSegment(s segSel, path string) {
	if c.lastSeg != nil && s.index > c.lastSegIdx+1 {
		for i := c.lastSegIdx + 1; i < s.index; i++ {
			o := c.p.all[i]
			c.omitted = append(c.omitted, omittedSegment{Name: o.Name, FirstSeq: o.FirstSeq, LastSeq: o.LastSeq, Records: o.Records})
		}
		om := omission{firstRun: -1}
		if c.head != nil {
			om.afterSeq = c.head.Seq
		}
		c.omissions = append(c.omissions, om)
		c.pendingOmission = true
	}
	e := &segmentEntry{Name: s.info.Name, Path: path, Genesis: s.genesis, OverlapsPeriod: s.inRange, IncludedFor: s.why}
	c.segs = append(c.segs, e)
	c.cur = &segState{sel: s, entry: e}
}

// droppedTail records that a partial last line of the active segment was left out.
func (c *collector) droppedTail(n int) {
	c.cur.entry.ExcludedTailBytes = n
	c.chk.Notes = append(c.chk.Notes, fmt.Sprintf(
		"%d trailing bytes of the active segment %s (a record being written during the export) were not included.",
		n, c.cur.entry.Name))
}

// endSegment completes the bookkeeping of the current segment.
func (c *collector) endSegment(sum string, size int64) {
	e := c.cur.entry
	e.SHA256, e.Bytes = sum, size
	c.lastSeg, c.lastSegIdx = e, c.cur.sel.index
	c.chk.Segments++
}

// line processes one ledger line (including its terminating '\n' when complete).
func (c *collector) line(raw []byte, complete bool) {
	st := c.cur
	st.line++
	ln := st.line
	st.entry.Records++
	c.chk.Records++
	if !complete {
		c.chk.ParseFailures++
		c.failure(ln, nil, "parse_error", "the last line of the segment is not terminated by a newline (truncated segment)")
	}
	var env model.Envelope
	err := json.Unmarshal(bytes.TrimRight(raw, "\r\n"), &env)
	if err != nil || env.B == "" || env.H == "" {
		detail := "line is not an envelope {h, s, b}"
		if err != nil {
			detail += ": " + err.Error()
		}
		c.chk.ParseFailures++
		c.failure(ln, nil, "parse_error", detail)
		c.havePrev = false
		return
	}
	sum := sha256Hex([]byte(env.B))
	hashOK := sum == env.H
	if hashOK {
		c.chk.HashesOK++
	} else {
		c.chk.HashFailures++
	}
	var body model.Body
	if err := json.Unmarshal([]byte(env.B), &body); err != nil {
		if !hashOK {
			c.failure(ln, nil, "hash_mismatch", fmt.Sprintf("h %s != sha256(b) %s", short(env.H), short(sum)))
		}
		c.chk.ParseFailures++
		c.failure(ln, nil, "parse_error", "record body is not valid JSON: "+err.Error())
		c.havePrev = false
		return
	}
	seq := body.Seq
	if !hashOK {
		c.failure(ln, &seq, "hash_mismatch", fmt.Sprintf("h %s != sha256(b) %s", short(env.H), short(sum)))
	}
	if c.pendingOmission {
		c.omissions[len(c.omissions)-1].firstRun = c.agg.runIndex(body.Run)
		c.pendingOmission = false
	}
	if body.V != model.FormatVersion {
		c.chk.ParseFailures++
		c.failure(ln, &seq, "parse_error", fmt.Sprintf("unsupported record format version v=%d", body.V))
	}
	genesisLine := st.sel.genesis && ln == 1
	c.checkChain(env, body, ln, hashOK)
	if !genesisLine {
		c.checkSignature(env, ln, seq)
	}
	for _, id := range body.Blobs {
		if !isHex64(id) {
			c.chk.ParseFailures++
			c.failure(ln, &seq, "parse_error", fmt.Sprintf("invalid blob id %q", truncate(id, 80)))
			continue
		}
		if _, ok := c.blobRefs[id]; !ok {
			c.blobRefs[id] = seq
		}
	}
	c.typeCounts[body.Type]++
	if n := len(c.seqHashes); n > 0 && c.seqHashes[n-1].seq >= seq {
		c.seqSorted = false
	}
	c.seqHashes = append(c.seqHashes, seqHash{seq: seq, hash: env.H})
	c.prevSeq, c.prevHash, c.havePrev = seq, env.H, true
	c.head = &recordRef{Seq: seq, Hash: env.H, TS: body.TS, Segment: st.entry.Name}
	e := st.entry
	if e.parsed == 0 {
		e.FirstSeq, e.FirstTS = seq, body.TS
	}
	e.LastSeq, e.LastTS = seq, body.TS
	e.parsed++

	ts, tsOK := parseTS(body.TS)
	if !tsOK {
		c.chk.ParseFailures++
		c.failure(ln, &seq, "parse_error", fmt.Sprintf("invalid ts %q", truncate(body.TS, 40)))
	} else if plausibleTime(ts) {
		if c.minTS.IsZero() || ts.Before(c.minTS) {
			c.minTS = ts
		}
		if ts.After(c.maxTS) {
			c.maxTS = ts
		}
	}
	c.aggregate(env, body, ts, tsOK)
}

// checkChain verifies genesis, segment_open linkage and seq/prev continuity.
func (c *collector) checkChain(env model.Envelope, body model.Body, ln int, hashOK bool) {
	seq := body.Seq
	switch {
	case c.cur.sel.genesis && ln == 1:
		if seq != 0 || body.Type != model.TypeGenesis || body.Prev != model.ZeroHash {
			c.chainFail(ln, &seq, "seq_gap", "the first record of the ledger must be the genesis record (seq 0, prev = 64 zeros)")
			return
		}
		c.loadGenesis(env, body, hashOK)
	case ln == 1:
		c.checkSegmentOpen(body)
	default:
		if body.Type == model.TypeGenesis || body.Type == model.TypeSegmentOpen {
			c.chainFail(ln, &seq, "seq_gap", body.Type+" record in the middle of a segment")
		}
		c.checkLink(ln, body)
	}
}

func (c *collector) checkLink(ln int, body model.Body) {
	if !c.havePrev {
		return
	}
	seq := body.Seq
	if seq != c.prevSeq+1 {
		c.chainFail(ln, &seq, "seq_gap", fmt.Sprintf("expected seq %d, found %d", c.prevSeq+1, seq))
	}
	if body.Prev != c.prevHash {
		c.chainFail(ln, &seq, "prev_mismatch", fmt.Sprintf("prev %s does not equal h %s of seq %d", short(body.Prev), short(c.prevHash), c.prevSeq))
	}
}

// checkSegmentOpen verifies the first record of a non-first segment.
func (c *collector) checkSegmentOpen(body model.Body) {
	seq := body.Seq
	name := c.cur.entry.Name
	contiguous := c.lastSeg != nil && c.lastSegIdx == c.cur.sel.index-1
	if body.Type != model.TypeSegmentOpen {
		c.chainFail(1, &seq, "segment_hash", "the first record of a segment must be segment_open, found "+body.Type)
	} else {
		var so model.SegmentOpen
		if err := json.Unmarshal(body.Data, &so); err != nil {
			c.chainFail(1, &seq, "parse_error", "segment_open data: "+err.Error())
		} else {
			if so.Segment != name {
				c.chainFail(1, &seq, "segment_hash", fmt.Sprintf("segment_open names segment %q", so.Segment))
			}
			if contiguous {
				prev := c.lastSeg
				if so.PrevSegment != prev.Name {
					c.chainFail(1, &seq, "segment_hash", fmt.Sprintf("prev_segment %q, expected %q", so.PrevSegment, prev.Name))
				}
				if so.PrevSegmentSHA256 != prev.SHA256 {
					c.chainFail(1, &seq, "segment_hash", fmt.Sprintf("prev_segment_sha256 %s does not match the SHA-256 %s of %s", short(so.PrevSegmentSHA256), short(prev.SHA256), prev.Name))
				}
				if so.PrevSegmentRecords != prev.Records {
					c.chainFail(1, &seq, "segment_hash", fmt.Sprintf("prev_segment_records %d, but %s has %d records", so.PrevSegmentRecords, prev.Name, prev.Records))
				}
				if so.PrevSegmentLastSeq != prev.LastSeq {
					c.chainFail(1, &seq, "segment_hash", fmt.Sprintf("prev_segment_last_seq %d, but %s ends with seq %d", so.PrevSegmentLastSeq, prev.Name, prev.LastSeq))
				}
			}
		}
	}
	switch {
	case contiguous:
		c.checkLink(1, body)
	case c.havePrev && seq <= c.prevSeq:
		c.chainFail(1, &seq, "seq_gap", fmt.Sprintf("seq %d does not increase across the omitted segments (previous %d)", seq, c.prevSeq))
	}
}

// loadGenesis takes the ledger public key from the genesis record if the record verifies.
func (c *collector) loadGenesis(env model.Envelope, body model.Body, hashOK bool) {
	seq := body.Seq
	var g model.Genesis
	if err := json.Unmarshal(body.Data, &g); err != nil {
		c.chainFail(1, &seq, "parse_error", "genesis data: "+err.Error())
		return
	}
	pub, err := base64.StdEncoding.DecodeString(g.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		c.chainFail(1, &seq, "bad_signature", "genesis public_key is not a base64 32-byte Ed25519 key")
		return
	}
	fp := sha256Hex(pub)
	c.gen = &genesisFacts{ref: recordRef{Seq: seq, Hash: env.H, TS: body.TS, Segment: c.cur.entry.Name}, g: g, fingerprint: fp}
	if g.Fingerprint != fp {
		c.chainFail(1, &seq, "bad_signature", fmt.Sprintf("genesis fingerprint %s does not match its public key (%s)", short(g.Fingerprint), short(fp)))
	}
	sig, err := base64.StdEncoding.DecodeString(env.S)
	selfOK := err == nil && len(sig) == ed25519.SignatureSize && ed25519.Verify(pub, []byte(env.B), sig)
	if !selfOK {
		c.chk.SignatureFailures++
		c.failure(1, &seq, "bad_signature", "the genesis record is not signed by its own key")
	} else {
		c.chk.SignaturesOK++
	}
	if !hashOK || !selfOK {
		c.failure(1, &seq, "bad_signature", "the genesis record does not verify, so its public key is not used")
		return
	}
	c.pub = ed25519.PublicKey(pub)
}

func (c *collector) checkSignature(env model.Envelope, ln int, seq uint64) {
	if c.pub == nil {
		c.chk.SignaturesUnchecked++
		return
	}
	sig, err := base64.StdEncoding.DecodeString(env.S)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(c.pub, []byte(env.B), sig) {
		c.chk.SignatureFailures++
		c.failure(ln, &seq, "bad_signature", "Ed25519 signature does not verify with the genesis public key")
		return
	}
	c.chk.SignaturesOK++
}

func (c *collector) chainFail(ln int, seq *uint64, kind, detail string) {
	c.chk.ChainFailures++
	c.failure(ln, seq, kind, detail)
}

// failure records an integrity problem at a line of the current segment.
func (c *collector) failure(ln int, seq *uint64, kind, detail string) {
	f := model.VerifyFailure{Line: ln, Problem: kind, Detail: detail}
	if c.cur != nil {
		f.Segment = c.cur.entry.Name
	}
	if seq != nil {
		f.Seq = *seq
	}
	c.addFailure(f)
}

func (c *collector) addFailure(f model.VerifyFailure) {
	c.chk.FailuresTotal++
	if len(c.chk.Failures) < maxBundleFailures {
		c.chk.Failures = append(c.chk.Failures, f)
	}
}

// referencedBlobs returns every blob id referenced by an included record, sorted.
func (c *collector) referencedBlobs() []string {
	ids := make([]string, 0, len(c.blobRefs))
	for id := range c.blobRefs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// blobIncluded records a blob written into the bundle; a blob that is the time-stamp token of
// an anchor is checked against the head hash that anchor names.
func (c *collector) blobIncluded(id string, data []byte) {
	c.blobIn[id] = true
	c.chk.BlobsIncluded++
	if c.tokenOf == nil {
		c.tokenOf = map[string][]int{}
		for i, an := range c.agg.anchors {
			c.tokenOf[an.Token] = append(c.tokenOf[an.Token], i)
		}
	}
	for _, i := range c.tokenOf[id] {
		tr := checkToken(data, c.agg.anchors[i].HeadHash)
		if tr.problem == "" && tr.warn == "" && c.p.tokenVerifier != nil {
			tr.runVerifier(c.p.tokenVerifier, data, c.agg.anchors[i].HeadHash)
		}
		c.tokenRes[i] = tr
	}
}

// blobFailed records a referenced blob that could not be put into the bundle.
func (c *collector) blobFailed(id string, err error) {
	seq := c.blobRefs[id]
	f := model.VerifyFailure{Seq: seq}
	if errors.Is(err, contracts.ErrNotFound) {
		c.chk.BlobsMissing++
		f.Problem = "blob_missing"
		f.Detail = fmt.Sprintf("blob %s (first referenced by seq %d) is not in the blob store", id, seq)
	} else {
		c.chk.BlobsCorrupt++
		f.Problem = "blob_corrupt"
		f.Detail = fmt.Sprintf("blob %s (first referenced by seq %d) could not be exported: %v", id, seq, err)
	}
	c.addFailure(f)
}

// hashOf returns the hash of record seq if it is in the bundle (the last one if a damaged
// ledger repeats seq).
func (c *collector) hashOf(seq uint64) (string, bool) {
	if c.seqSorted {
		i := sort.Search(len(c.seqHashes), func(i int) bool { return c.seqHashes[i].seq >= seq })
		if i < len(c.seqHashes) && c.seqHashes[i].seq == seq {
			return c.seqHashes[i].hash, true
		}
		return "", false
	}
	// Out-of-order seqs only occur in damaged ledgers; index them once instead of searching
	// the whole list for every anchor.
	if c.seqIndex == nil {
		c.seqIndex = make(map[uint64]string, len(c.seqHashes))
		for _, sh := range c.seqHashes {
			c.seqIndex[sh.seq] = sh.hash
		}
	}
	h, ok := c.seqIndex[seq]
	return h, ok
}

// checkAnchors compares every anchor's head hash with the record it names, checks that its
// time-stamp token is in the bundle and is a valid token over that head hash (checkToken and,
// when configured, the token verifier), and decides whether the anchor is proof of time.
func (c *collector) checkAnchors() {
	c.chk.TokenVerifier = c.p.tokenVerifier != nil
	for i := range c.agg.anchors {
		an := &c.agg.anchors[i]
		c.chk.AnchorsChecked++
		an.TokenIncluded = c.blobIn[an.Token]
		tr, haveRes := c.tokenRes[i]
		if !an.TokenIncluded {
			an.TokenCheck = "missing"
			c.chk.AnchorTokensMissing++
			c.addFailure(model.VerifyFailure{Seq: an.Seq, Problem: "anchor_invalid",
				Detail: fmt.Sprintf("time-stamp token %s of anchor seq %d is not in the bundle", short(an.Token), an.Seq)})
		} else if haveRes {
			c.tokenChecked(an, tr)
		}
		h, ok := c.hashOf(an.HeadSeq)
		switch {
		case !ok:
			an.HeadCheck = "head not in bundle"
			c.chk.AnchorsHeadNotInBundle++
		case h == an.HeadHash:
			an.HeadCheck = "ok"
			c.chk.AnchorsHeadOK++
		default:
			an.HeadCheck = "mismatch"
			c.chk.AnchorsHeadMismatch++
			c.addFailure(model.VerifyFailure{Seq: an.Seq, Problem: "anchor_invalid",
				Detail: fmt.Sprintf("anchor head_hash %s differs from the hash %s of record %d", short(an.HeadHash), short(h), an.HeadSeq)})
		}
		c.decideProof(an, tr, haveRes)
		if an.ProofOfTime {
			c.chk.AnchorsProofOfTime++
		} else {
			c.chk.AnchorsNotProof++
		}
	}
	if len(c.agg.anchors) == 0 {
		return
	}
	if c.p.tokenVerifier != nil {
		c.chk.Notes = append(c.chk.Notes, "Every time-stamp token was also checked by a token verifier at export (CMS signature and "+
			"the TSA certificate chain to a trusted root, at the token's time). An anchor counts as proof of time only if its token "+
			"is valid for the anchored record in this bundle and its certificate chain is trusted.")
	} else {
		c.chk.Notes = append(c.chk.Notes, "No token verifier checked the TSA certificate chains at export. The tokens were checked "+
			"for their message imprint and their CMS signature with the TSA certificate they embed; an anchor counts as proof of "+
			"time here only if, in addition, its record states that when the token was obtained it verified and its TSA "+
			"certificate chained to a trusted root (verified and chain_ok, the issue-time flags). Check the chains independently "+
			"with openssl (see the verification instructions).")
	}
	if n := c.chk.AnchorsNotProof; n > 0 {
		c.chk.Notes = append(c.chk.Notes, fmt.Sprintf("%s of %d are not accepted as proof of time (see the time-stamp table for the reasons).",
			plural(n, "time-stamp anchor", "time-stamp anchors"), len(c.agg.anchors)))
	}
}

// decideProof sets an anchor's proof-of-time verdict: the token is valid for the anchored head
// record in this bundle AND its TSA certificate chain is trusted - the token verifier's ChainOK
// at export, or without a verifier the record's issue-time flags (verified && chain_ok).
func (c *collector) decideProof(an *anchorEntry, tr tokenResult, haveRes bool) {
	an.ProofOfTime = false
	switch {
	case an.HeadCheck == "mismatch":
		an.ProofNote = "its head_hash does not match the anchored record"
		return
	case an.HeadCheck != "ok":
		an.ProofNote = "the anchored record is not in this bundle"
		return
	case !an.TokenIncluded:
		an.ProofNote = "its time-stamp token is not in this bundle"
		return
	case !haveRes:
		an.ProofNote = "its time-stamp token was not checked"
		return
	case an.TokenCheck != "ok" && tr.problem == "" && tr.warn != "":
		an.ProofNote = "its time-stamp token cannot be checked: " + tr.warn
		return
	case an.TokenCheck != "ok":
		an.ProofNote = "its time-stamp token is not valid: " + an.TokenCheck
		return
	}
	if c.p.tokenVerifier != nil {
		an.ProofBasis = "token_verifier"
		switch {
		case tr.verifierErr != "":
			an.ProofNote = "the token verifier rejected the token: " + tr.verifierErr
		case !tr.info.ChainOK:
			an.ProofNote = "the TSA certificate does not chain to a trusted root"
			if an.ChainNote != "" {
				an.ProofNote += " (" + an.ChainNote + ")"
			}
		default:
			an.ProofOfTime = true
		}
		return
	}
	an.ProofBasis = "issue_time_flags"
	if an.Verified && an.ChainOK {
		an.ProofOfTime = true
		return
	}
	// The record's chain note (chain_note_at_issue) is shown with the anchor, not repeated here.
	an.ProofNote = fmt.Sprintf("when the token was obtained it was recorded as verified=%t, chain_ok=%t", an.Verified, an.ChainOK)
}

// tokenChecked records the result of checking an anchor's token.
func (c *collector) tokenChecked(an *anchorEntry, tr tokenResult) {
	if !tr.genTime.IsZero() {
		an.TokenGenTime = tr.genTime.Format(time.RFC3339Nano)
	}
	switch {
	case tr.problem != "":
		an.TokenCheck = tr.problem
		c.chk.AnchorTokensInvalid++
		c.addFailure(model.VerifyFailure{Seq: an.Seq, Problem: "anchor_invalid",
			Detail: fmt.Sprintf("time-stamp token %s of anchor seq %d: %s", short(an.Token), an.Seq, tr.problem)})
		return
	case tr.warn != "":
		an.TokenCheck = tr.warn
		c.chk.Notes = append(c.chk.Notes, fmt.Sprintf("Anchor seq %d: %s; it is not used as proof of time in this report.", an.Seq, tr.warn))
		return
	}
	if tr.verifierRan {
		an.VerifierChecked = true
		if tr.verifierErr != "" {
			// The token passed the structural checks above but the verifier rejected it (for
			// example a second signer or a signing-certificate attribute that does not match):
			// like the full-ledger verification, an invalid token is an integrity failure.
			an.VerifierError = tr.verifierErr
			an.TokenCheck = "rejected by the token verifier: " + tr.verifierErr
			c.chk.AnchorTokensInvalid++
			c.addFailure(model.VerifyFailure{Seq: an.Seq, Problem: "anchor_invalid",
				Detail: fmt.Sprintf("time-stamp token %s of anchor seq %d does not verify: %s", short(an.Token), an.Seq, tr.verifierErr)})
			return
		}
		an.ChainTrusted = ptr(tr.info.ChainOK)
		an.TokenTSAName = tr.info.TSAName
		if !tr.info.ChainOK {
			an.ChainNote = tr.info.ChainNote // made fit for the report by runVerifier
		}
	}
	an.TokenCheck = "ok"
	c.chk.AnchorTokensOK++
	if rec, ok := parseTS(an.GenTime); !ok || rec.Sub(tr.genTime).Abs() >= time.Second {
		c.chk.Notes = append(c.chk.Notes, fmt.Sprintf(
			"Anchor seq %d: the record's gen_time %q differs from the genTime %s in its time-stamp token; this report uses the token's time.",
			an.Seq, truncate(an.GenTime, 40), an.TokenGenTime))
	}
}

// dataNote records a record whose payload this exporter could not interpret (format drift,
// not an integrity failure: the record itself still hashes and verifies).
func (c *collector) dataNote(body model.Body, err error) {
	c.dataNotes++
	if c.dataNotes <= 20 {
		c.notes = append(c.notes, fmt.Sprintf("record seq %d (%s): payload could not be interpreted by this report: %v", body.Seq, body.Type, err))
	}
}

func short(h string) string { return truncate(h, 16) }

// truncate shortens s to at most n bytes plus "...", never splitting a UTF-8 sequence: report
// text must stay valid UTF-8, or it would not survive the JSON round trip of report verification.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return abbreviate(s, n)
}

// validUTF8 replaces invalid UTF-8 in text that comes from outside the ledger records (the
// token verifier, the full-ledger verification, the request): report.json states it, and report
// verification needs it to read back exactly as written.
func validUTF8(s string) string { return strings.ToValidUTF8(s, "�") }
