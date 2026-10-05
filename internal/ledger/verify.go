package ledger

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// Failure classes (model.VerifyFailure.Problem).
const (
	probParse       = "parse_error"
	probHash        = "hash_mismatch"
	probSignature   = "bad_signature"
	probSeqGap      = "seq_gap"
	probPrev        = "prev_mismatch"
	probSegmentHash = "segment_hash"
	probBlobMissing = "blob_missing"
	probBlobCorrupt = "blob_corrupt"
	probAnchor      = "anchor_invalid"
	// probTime ("ts_contradiction", timecheck.go): a record's ts contradicts a trusted time-stamp.
)

const (
	maxReportedFailures = 200
	maxListedAnchors    = 1000 // most recent passing anchor checks kept in the report
	maxListedGaps       = 1000
	defaultFastInterval = 10 * time.Second
	hashRingSize        = 8192 // recent record hashes kept for anchor head checks

	// maxDetailBytes bounds every failure detail. Details quote values from records that may
	// be tampered with (and encoding/json echoes whole number literals into its errors), so
	// without a bound one crafted line could bloat a report or an integrity_alert record.
	maxDetailBytes = 512
)

// VerifyOptions configures VerifyReader.
type VerifyOptions struct {
	// TokenVerifier, if set, cryptographically checks every anchor's RFC 3161 token, and
	// VerifyReport.TokensChecked reports that it did.
	//
	// An anchor counts as proof of time (LastAnchoredSeq, UnanchoredTail) only when its token
	// verifies for the anchored head hash AND the TSA certificate chains to a trusted root
	// (contracts.TokenInfo.ChainOK): a token whose certificate does not chain proves nothing,
	// anyone can make one. Such an anchor is listed with OK=true, ChainOK=false and the
	// verifier's ChainNote in its Detail. Without a TokenVerifier the anchor record's own
	// issue-time flags decide (verified && chain_ok), and a note says so.
	TokenVerifier contracts.TokenVerifier
	// FastInterval is the sampling interval; gaps are sample spacings > 3× this (default 10s).
	FastInterval time.Duration
	// CheckBlobs fetches every referenced blob and re-hashes it.
	CheckBlobs bool
	// AllowOmittedSegments (bundle mode): an evidence bundle holds the genesis segment plus one
	// contiguous run of segments (docs/DESIGN.md §13). The segments between the genesis segment
	// and the first other included segment may be left out: that forward seq discontinuity is
	// reported as a note ("segments omitted ...") instead of a failure. Any other seq or segment
	// discontinuity is a removed segment and fails, as without this option.
	AllowOmittedSegments bool
	// ExpectFingerprint, if set, must equal the genesis public key fingerprint (hex; spaces,
	// colons and case are ignored).
	ExpectFingerprint string

	ringSize int // tests: size of the recent-hash ring (default hashRingSize)
	// sigCache (Store.Verify) reuses the signature outcomes of segments whose exact bytes were
	// verified before (verifycache.go); the report is the same as without it.
	sigCache *sigCache
}

// Verify verifies the complete ledger, including blobs and (with Options.TokenVerifier) anchor
// tokens. For a writer the signing key's fingerprint must match the genesis key. Repeated calls
// reuse the Ed25519 outcomes of segments whose bytes are unchanged (verifycache.go): every other
// check is made again over the whole ledger, and the report is the one a verification without
// that cache gives.
func (s *Store) Verify(ctx context.Context) (model.VerifyReport, error) {
	opts := s.verifyOptions()
	opts.sigCache = s.sigs
	return verifyReader(ctx, s, opts, s.now)
}

// verifyOptions are the options of Store.Verify, without the verification cache.
func (s *Store) verifyOptions() VerifyOptions {
	opts := VerifyOptions{
		TokenVerifier: s.opts.TokenVerifier,
		FastInterval:  s.opts.FastInterval,
		CheckBlobs:    true,
	}
	if s.pub != nil && !s.readOnly {
		opts.ExpectFingerprint = s.fp
	} else if s.keyDir != "" {
		// A read-only store has no private key, but the key file's public half is an
		// independent second source for the expected fingerprint.
		if _, pub, err := readKeyFile(s.keyDir); err == nil {
			opts.ExpectFingerprint = Fingerprint(pub)
		}
	}
	return opts
}

// VerifyReader verifies any LedgerReader — the full ledger or an exported bundle — and reports
// every check of docs/DESIGN.md §6 "Verification". It also checks every record's ts against the
// trusted time-stamps in the chain (timecheck.go): a ts that contradicts one is a failure
// (ts_contradiction), so back-dated or forward-dated records never verify. The error is non-nil
// only when verification could not be carried out (listing failed, context cancelled); integrity
// problems are reported in the VerifyReport.
func VerifyReader(ctx context.Context, r contracts.LedgerReader, opts VerifyOptions) (model.VerifyReport, error) {
	return verifyReader(ctx, r, opts, time.Now)
}

// verifySegmentLister lets *Store provide a cheap segment list (no per-segment metadata scan)
// and raw access that includes an incomplete final line.
type verifySegmentLister interface {
	verifySegments() ([]lineSource, error)
}

func verifyReader(ctx context.Context, r contracts.LedgerReader, opts VerifyOptions, now func() time.Time) (model.VerifyReport, error) {
	if opts.FastInterval <= 0 {
		opts.FastInterval = defaultFastInterval
	}
	at := now().UTC()
	rep := model.VerifyReport{
		At:         at.Format(time.RFC3339Nano),
		Segments:   []string{},
		TypeCounts: map[string]int{},
		Failures:   []model.VerifyFailure{},
		Anchors:    []model.AnchorCheck{},
		Gaps:       []model.Gap{},
	}
	srcs, live, err := verifySources(r)
	if err != nil {
		return rep, fmt.Errorf("ledger: verify: list segments: %w", err)
	}
	for _, src := range srcs {
		rep.Segments = append(rep.Segments, src.name)
	}
	if len(srcs) == 0 {
		// Nothing was verified, so nothing may be reported as verified.
		rep.FailuresTotal = 1
		rep.Failures = append(rep.Failures, model.VerifyFailure{Problem: probParse,
			Detail: "no ledger segment was found: there is nothing to verify (a ledger always holds at least its genesis segment)"})
		return rep, nil
	}

	pub, problem := findGenesisKey(srcs[0])
	c := newChainChecker(&rep, opts, srcs, true)
	c.pub = pub
	c.firstLedgerSeg = 0
	c.liveTail = live
	c.tm = newTimeChecker(c.names, now, c.note)
	if problem != "" {
		c.fail(model.VerifyFailure{Segment: srcs[0].name, Line: 1, Problem: probSignature,
			Detail: "signatures cannot be verified: " + problem})
	}
	cfg := &workerConfig{pub: pub}
	var blobs *blobChecker
	if opts.CheckBlobs {
		blobs = newBlobChecker(r.GetBlob)
		cfg.blobs = blobs
	}
	cfg.tokens = &tokenChecker{get: r.GetBlob, fetch: opts.CheckBlobs, verifier: opts.TokenVerifier}

	visit, segDone := c.line, c.segDone
	if run := newCacheRun(opts.sigCache, pub, srcs); run != nil {
		cfg.cache = run
		visit = func(r *lineResult) {
			run.observe(r)
			c.line(r)
		}
		segDone = func(e *segEnd) {
			c.segDone(e)
			run.segmentDone(e)
		}
	}
	if err := runPipeline(ctx, srcs, cfg, visit, segDone); err != nil {
		return rep, fmt.Errorf("ledger: verify: %w", err)
	}
	if cfg.cache != nil {
		cfg.cache.prune()
	}
	c.finish(ctx, r)
	if blobs != nil {
		rep.BlobsChecked = int(blobs.checked.Load())
	}
	// Only a verifier that actually examined tokens may claim they were checked (with no anchor
	// record there was nothing to check).
	rep.TokensChecked = opts.TokenVerifier != nil && cfg.tokens.checked.Load() > 0
	rep.OK = rep.FailuresTotal == 0
	return rep, nil
}

// verifySources lists the segments of r in date order as streamable sources. live reports
// whether r is the live ledger, whose latest segment may legitimately end with a record that
// is still being written; any other reader (an exported bundle) never contains one.
func verifySources(r contracts.LedgerReader) (srcs []lineSource, live bool, err error) {
	if sl, ok := r.(verifySegmentLister); ok {
		srcs, err = sl.verifySegments()
		return srcs, true, err
	}
	srcs, err = readerSources(r)
	return srcs, false, err
}

// readerSources lists the segments of a generic LedgerReader in date order.
func readerSources(r contracts.LedgerReader) ([]lineSource, error) {
	infos, err := r.Segments()
	if err != nil {
		return nil, err
	}
	srcs := make([]lineSource, 0, len(infos))
	for _, info := range infos {
		name, date := info.Name, info.Date
		if n, d, ok := parseSegmentName(info.Name); ok {
			name = n
			if date.IsZero() {
				date = d
			}
		}
		date = utcDate(date)
		srcs = append(srcs, lineSource{name: name, date: date, open: func() (io.ReadCloser, error) {
			return r.OpenSegment(name)
		}})
	}
	sort.SliceStable(srcs, func(i, j int) bool { return srcs[i].date.Before(srcs[j].date) })
	return srcs, nil
}

// findGenesisKey reads the first record of the first segment and returns its public key.
// Only the key is taken here; the record itself is verified by the main pass.
func findGenesisKey(src lineSource) (ed25519.PublicKey, string) {
	rc, err := src.open()
	if err != nil {
		return nil, fmt.Sprintf("first segment %s cannot be opened: %v", src.name, err)
	}
	defer rc.Close()
	rec, err := newLineReader(rc, 64<<10).next()
	if err != nil || !rec.complete || rec.tooLong {
		return nil, fmt.Sprintf("first segment %s has no complete first record", src.name)
	}
	_, body, err := parseRecordLenient(rec.data)
	if err != nil {
		return nil, fmt.Sprintf("first record of %s is unreadable: %v", src.name, err)
	}
	if body.Type != model.TypeGenesis || body.Seq != 0 {
		return nil, fmt.Sprintf("first record of %s is %q seq %d, not the genesis record", src.name, clip(body.Type), body.Seq)
	}
	var g model.Genesis
	if err := json.Unmarshal(body.Data, &g); err != nil {
		return nil, "genesis payload is unreadable: " + err.Error()
	}
	pub, err := base64.StdEncoding.DecodeString(g.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, "genesis public_key is not a base64 Ed25519 key"
	}
	return ed25519.PublicKey(pub), ""
}

// ---------------------------------------------------------------- chain checker

// segSummary describes a completely read segment (for the next segment_open check).
type segSummary struct {
	Name     string
	SHA256   string
	Lines    int
	Partial  int64
	LastSeq  uint64
	LastHash string
	HaveLast bool
}

type hashEntry struct {
	seq  uint64
	hash string
	set  bool
}

type deferredAnchor struct {
	idx      int // index in c.anchors
	headSeq  uint64
	headHash string
	seg      string
	line     int
	seq      uint64
}

// anchorDoubt says why an anchor that passes its checks is still not proof of time.
type anchorDoubt int8

const (
	doubtNone anchorDoubt = iota
	// doubtChain: the token verifies for the head hash, but the TSA certificate does not chain
	// to a trusted root, so anyone could have made it.
	doubtChain
	// doubtIssueFlags: no token verifier, and the anchor record says that when the token was
	// obtained it did not verify or its certificate did not chain (verified/chain_ok).
	doubtIssueFlags
)

// anchorMeta is what an AnchorCheck does not show: whether the anchor proves time and why not.
type anchorMeta struct {
	proof       bool // trusted: proves time once its checks pass (including a deferred head check)
	doubt       anchorDoubt
	failed      bool // a failure was reported for this anchor
	notIncluded bool // bundle mode: the covered record lies in the omitted segments
}

// gapEvents accumulates the records seen since the previous sample.
type gapEvents struct {
	stopped    bool
	stopReason string
	suspended  bool
	shutdown   bool
	started    bool
	recovered  bool
}

type lastSample struct {
	ok   bool
	seq  uint64
	ts   time.Time
	tsOK bool
	tsS  string
	mono int64
	run  string
}

// chainChecker performs the order-dependent checks in file order.
type chainChecker struct {
	rep      *model.VerifyReport
	opts     VerifyOptions
	full     bool // gaps, anchors, blobs (false for the writer's open-time validation)
	names    []string
	dates    []time.Time
	lastSeg  int
	onFail   func(model.VerifyFailure)
	pub      ed25519.PublicKey
	notesSet map[string]bool

	// firstLedgerSeg is the index of the segment that must begin with genesis (-1: none of
	// the streamed segments is the ledger's first).
	firstLedgerSeg int
	// liveTail: the last segment belongs to the live ledger and may end with a record that is
	// being written (a note); otherwise an incomplete final line is damage (a failure).
	liveTail bool

	segIdx      int
	segLine     int
	prevSum     *segSummary
	curLastSeq  uint64
	curLastHash string
	curHaveLast bool

	havePrev   bool
	prevHash   string
	haveExpect bool
	expectSeq  uint64

	haveFirstTS bool
	lateTS      int

	ring         []hashEntry // recent record hashes by seq % len(ring)
	anchors      []model.AnchorCheck
	anchorMeta   []anchorMeta // parallel to anchors
	deferred     []deferredAnchor
	lastAnchored uint64 // covered by an anchor that proves time
	anchoredAny  bool
	tokensNoted  bool
	lastSeq      uint64

	// Bundle mode: the seqs left out between the genesis segment and the run.
	haveOmit         bool
	omitFrom, omitTo uint64

	sample  lastSample
	ev      gapEvents
	gapEnds []gapEnd // parallel to rep.Gaps

	// tm checks record ts against the trusted time-stamps and each other (full mode only).
	tm *timeChecker

	reportedBlobs map[string]bool
}

func newChainChecker(rep *model.VerifyReport, opts VerifyOptions, srcs []lineSource, full bool) *chainChecker {
	c := &chainChecker{
		rep:            rep,
		opts:           opts,
		full:           full,
		lastSeg:        len(srcs) - 1,
		segIdx:         -1,
		firstLedgerSeg: -1,
		notesSet:       map[string]bool{},
		reportedBlobs:  map[string]bool{},
	}
	for _, s := range srcs {
		c.names = append(c.names, s.name)
		c.dates = append(c.dates, s.date)
	}
	if full {
		n := opts.ringSize
		if n <= 0 {
			n = hashRingSize
		}
		c.ring = make([]hashEntry, n)
	}
	c.onFail = func(f model.VerifyFailure) {
		rep.FailuresTotal++
		if len(rep.Failures) < maxReportedFailures {
			rep.Failures = append(rep.Failures, f)
		}
	}
	return c
}

// fail reports one failure. Every failure goes through here so that its detail is bounded.
func (c *chainChecker) fail(f model.VerifyFailure) {
	f.Detail = clipTo(f.Detail, maxDetailBytes)
	c.onFail(f)
}

func (c *chainChecker) note(s string) {
	if !c.notesSet[s] {
		c.notesSet[s] = true
		c.rep.Notes = append(c.rep.Notes, s)
	}
}

func (c *chainChecker) startSegment(seg int) {
	c.segIdx = seg
	c.segLine = 0
	c.curHaveLast = false
	c.curLastHash = ""
}

// breakChain forgets the linkage state after a line whose hash cannot be computed.
func (c *chainChecker) breakChain() {
	c.havePrev = false
	c.haveExpect = false
}

// clip bounds a value taken from the (possibly tampered) record for use in a detail message.
func clip(v string) string { return clipTo(v, 80) }

// oneLine replaces control characters (line breaks included) with spaces.
func oneLine(v string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, v)
}

// clipTo returns v cut to at most n bytes at a UTF-8 boundary, marked with "..." when cut.
func clipTo(v string, n int) string {
	if len(v) <= n {
		return v
	}
	return cutUTF8(v, n) + "..."
}

// cutUTF8 returns the longest prefix of v of at most n bytes that does not split a UTF-8
// sequence.
func cutUTF8(v string, n int) string {
	if len(v) <= n {
		return v
	}
	i := n
	for i > 0 && !utf8.RuneStart(v[i]) {
		i--
	}
	return v[:i]
}

func (c *chainChecker) line(r *lineResult) {
	if r.seg != c.segIdx {
		c.startSegment(r.seg)
	}
	c.segLine++
	first := c.segLine == 1
	name := c.names[r.seg]
	fail := func(seq uint64, problem, detail string) {
		c.fail(model.VerifyFailure{Seq: seq, Segment: name, Line: r.lineNo, Problem: problem, Detail: detail})
	}

	if r.tooLong {
		fail(0, probParse, fmt.Sprintf("line of %d bytes exceeds the %d byte limit", r.n, maxLineBytes))
		c.breakChain()
		return
	}
	if !r.envOK {
		fail(0, probParse, r.perr)
		c.breakChain()
		return
	}
	var seqHint uint64
	if r.bodyOK {
		seqHint = r.body.Seq
	}
	if r.claimH != r.hashHex {
		fail(seqHint, probHash, fmt.Sprintf("h is %q but the SHA-256 of b is %s", clip(r.claimH), r.hashHex))
	}
	if r.sig == sigBad {
		fail(seqHint, probSignature, r.sigDetail)
	}
	if !r.bodyOK {
		fail(0, probParse, r.perr)
		// The record's hash is still known, so linkage can continue through it.
		c.prevHash, c.havePrev = r.hashHex, true
		c.haveExpect = false
		c.curHaveLast = false
		return
	}
	b := &r.body
	if b.V != model.FormatVersion {
		fail(b.Seq, probParse, fmt.Sprintf("unsupported body format version v=%d", b.V))
	}
	if !r.tsOK {
		fail(b.Seq, probParse, fmt.Sprintf("ts %q is not an RFC 3339 time", clip(b.TS)))
	}
	if r.dataErr != "" {
		fail(b.Seq, probParse, r.dataErr)
	}

	// Sequence and hash-chain linkage.
	omitted := false
	if c.haveExpect && b.Seq != c.expectSeq {
		prevName := ""
		if c.prevSum != nil {
			prevName = c.prevSum.Name
		}
		if c.omissionAllowed(r, first, prevName) {
			omitted = true
			c.haveOmit, c.omitFrom, c.omitTo = true, c.expectSeq, b.Seq-1
			c.note(fmt.Sprintf("segments omitted between %s and %s (seq %d to %d, %d records not included)",
				prevName, name, c.expectSeq, b.Seq-1, b.Seq-c.expectSeq))
		} else {
			detail := fmt.Sprintf("expected seq %d, found %d", c.expectSeq, b.Seq)
			if first && r.seg > 0 && b.Seq > c.expectSeq {
				detail += fmt.Sprintf(": records between segments %s and %s are missing", prevName, name)
				if c.opts.AllowOmittedSegments {
					detail += " (an evidence bundle may leave out segments only between the genesis segment and the first other included segment)"
				}
			}
			fail(b.Seq, probSeqGap, detail)
		}
	}
	switch {
	case omitted:
	case b.Type == model.TypeGenesis || (b.Seq == 0 && !c.havePrev):
		if b.Prev != model.ZeroHash {
			fail(b.Seq, probPrev, "the genesis record's prev must be 64 zeros")
		}
	case c.havePrev:
		if b.Prev != c.prevHash {
			fail(b.Seq, probPrev, fmt.Sprintf("prev is %q but the preceding record hashes to %s", clip(b.Prev), c.prevHash))
		}
	}

	// Segment structure.
	if first {
		if r.seg == c.firstLedgerSeg {
			if b.Type != model.TypeGenesis || b.Seq != 0 {
				fail(b.Seq, probParse, fmt.Sprintf("the ledger begins with %q seq %d instead of the genesis record", clip(b.Type), b.Seq))
			}
		} else if b.Type != model.TypeSegmentOpen {
			fail(b.Seq, probSegmentHash, fmt.Sprintf("segment begins with %q instead of segment_open", clip(b.Type)))
		} else if r.segOpen != nil {
			c.checkSegmentOpen(r, name, omitted, fail)
		}
		if r.tsOK && !c.dates[r.seg].IsZero() && !utcDate(r.ts).Equal(c.dates[r.seg]) {
			fail(b.Seq, probSegmentHash, fmt.Sprintf("first record ts %s is not on the segment's date %s", b.TS, c.dates[r.seg].Format(dateLayout)))
		}
	} else {
		switch b.Type {
		case model.TypeGenesis:
			fail(b.Seq, probParse, "genesis record found after the start of the ledger")
		case model.TypeSegmentOpen:
			fail(b.Seq, probParse, "segment_open record found in the middle of a segment")
		}
	}
	if b.Type == model.TypeGenesis {
		c.checkGenesis(r, fail)
	}
	if r.tsOK && !c.dates[r.seg].IsZero() && !r.ts.Before(c.dates[r.seg].Add(day)) {
		c.lateTS++
	}

	// Advance the chain state using the computed hash, so that an edited "h" alone does not
	// cascade into the next record.
	c.prevHash, c.havePrev = r.hashHex, true
	c.expectSeq, c.haveExpect = b.Seq+1, true
	c.curLastSeq, c.curLastHash, c.curHaveLast = b.Seq, r.hashHex, true

	// Statistics. Values from records are bounded: the line may be forged.
	c.rep.Records++
	c.rep.TypeCounts[clipTo(b.Type, 64)]++
	if !c.haveFirstTS {
		c.rep.FirstTS, c.haveFirstTS = clipTo(b.TS, 64), true
	}
	c.rep.LastTS = clipTo(b.TS, 64)
	c.rep.HeadHash = r.hashHex
	c.lastSeq = b.Seq

	if !c.full {
		return
	}
	c.ring[b.Seq%uint64(len(c.ring))] = hashEntry{seq: b.Seq, hash: r.hashHex, set: true}
	if omitted {
		c.sample = lastSample{} // no gap across omitted segments
		c.ev = gapEvents{}
	}
	if b.Type == model.TypeAnchor {
		c.checkAnchor(r, name, fail) // a trusted anchor bounds the records it covers and its own ts
	}
	if c.tm != nil {
		c.tm.record(r)
	}
	c.trackGaps(r)
	for _, bo := range r.blobs {
		switch bo.state {
		case blobOK:
		case blobInvalidID:
			fail(b.Seq, probParse, bo.detail)
		default:
			if c.reportedBlobs[bo.id] {
				continue
			}
			c.reportedBlobs[bo.id] = true
			p := probBlobCorrupt
			if bo.state == blobMissing {
				p = probBlobMissing
			}
			fail(b.Seq, p, bo.detail+fmt.Sprintf(" (first referenced by seq %d, %s)", b.Seq, b.Type))
		}
	}
}

// checkSegmentOpen compares a segment_open record with its own file and with the preceding
// segment. When that predecessor was omitted from a bundle only the record's own name is
// checked.
func (c *chainChecker) checkSegmentOpen(r *lineResult, name string, omitted bool, fail func(uint64, string, string)) {
	so, seq := r.segOpen, r.body.Seq
	if so.Segment != name {
		fail(seq, probSegmentHash, fmt.Sprintf("segment_open names segment %q but the file is %q", clip(so.Segment), name))
	}
	p := c.prevSum
	if omitted || p == nil {
		return // predecessor not included, or unreadable (already reported)
	}
	if so.PrevSegment != p.Name {
		fail(seq, probSegmentHash, fmt.Sprintf("segment_open names previous segment %q but the preceding segment is %q", clip(so.PrevSegment), p.Name))
		return
	}
	if so.PrevSegmentSHA256 != p.SHA256 {
		fail(seq, probSegmentHash, fmt.Sprintf("previous segment %s: SHA-256 of its bytes is %s but segment_open records %s", p.Name, p.SHA256, clip(so.PrevSegmentSHA256)))
	}
	if so.PrevSegmentRecords != p.Lines {
		fail(seq, probSegmentHash, fmt.Sprintf("previous segment %s has %d records but segment_open records %d", p.Name, p.Lines, so.PrevSegmentRecords))
	}
	if p.HaveLast && so.PrevSegmentLastSeq != p.LastSeq {
		fail(seq, probSegmentHash, fmt.Sprintf("previous segment %s ends at seq %d but segment_open records %d", p.Name, p.LastSeq, so.PrevSegmentLastSeq))
	}
}

// omissionAllowed reports whether the seq discontinuity at r is the run of segments that an
// evidence bundle may leave out (VerifyOptions.AllowOmittedSegments). A bundle holds the genesis
// segment plus one contiguous run of segments (docs/DESIGN.md §13), so the only acceptable
// omission lies between the genesis segment and the first other included segment: a forward jump
// at the first record of the second segment, a segment_open whose predecessor is dated strictly
// between the two. Any other discontinuity is a removed segment (or removed records).
func (c *chainChecker) omissionAllowed(r *lineResult, first bool, prevName string) bool {
	b := &r.body
	if !c.opts.AllowOmittedSegments || !first || c.firstLedgerSeg != 0 || r.seg != 1 || len(c.names) < 2 ||
		!c.haveExpect || b.Seq <= c.expectSeq || b.Type != model.TypeSegmentOpen || r.segOpen == nil ||
		prevName != c.names[0] {
		return false
	}
	_, d, ok := parseSegmentName(r.segOpen.PrevSegment)
	return ok && d.After(c.dates[0]) && d.Before(c.dates[1])
}

// inOmittedRun reports whether seq lies in the segments left out of a bundle.
func (c *chainChecker) inOmittedRun(seq uint64) bool {
	return c.haveOmit && seq >= c.omitFrom && seq <= c.omitTo
}

func (c *chainChecker) checkGenesis(r *lineResult, fail func(uint64, string, string)) {
	if r.genesisPub == nil {
		return // payload problem already reported via dataErr
	}
	fp := Fingerprint(r.genesisPub)
	if c.rep.Fingerprint == "" {
		c.rep.Fingerprint = fp
	}
	if r.genesisFP != fp {
		fail(r.body.Seq, probSignature, fmt.Sprintf("genesis fingerprint field %q does not match its public key (%s)", clip(r.genesisFP), fp))
	}
	if c.pub != nil && !bytes.Equal(r.genesisPub, c.pub) {
		fail(r.body.Seq, probSignature, "genesis public key differs from the key used to check signatures")
	}
	if c.opts.ExpectFingerprint != "" && normalizeFingerprint(c.opts.ExpectFingerprint) != fp {
		fail(r.body.Seq, probSignature, fmt.Sprintf("ledger key fingerprint %s does not match the expected fingerprint %s", fp, c.opts.ExpectFingerprint))
	}
}

func (c *chainChecker) segDone(e *segEnd) {
	if e.seg != c.segIdx {
		c.startSegment(e.seg)
	}
	name := c.names[e.seg]
	fail := func(problem, detail string) {
		c.fail(model.VerifyFailure{Segment: name, Line: c.segLine + 1, Problem: problem, Detail: detail})
	}
	if e.openErr != nil {
		fail(probParse, "segment could not be opened: "+e.openErr.Error())
		c.prevSum = nil
		return
	}
	if e.readErr != nil {
		fail(probParse, "segment could not be read completely: "+e.readErr.Error())
	}
	if e.partial > 0 {
		switch {
		case e.seg == c.lastSeg && c.liveTail:
			c.note(fmt.Sprintf("segment %s ends with an incomplete line of %d bytes (a record being written, or left by a crash; the writer quarantines it on its next start)", name, e.partial))
		case e.seg == c.lastSeg:
			fail(probParse, fmt.Sprintf("the last segment ends with an incomplete line of %d bytes (an exported copy never includes a record that is still being written)", e.partial))
		default:
			fail(probParse, fmt.Sprintf("sealed segment ends with an incomplete line of %d bytes", e.partial))
		}
	}
	if e.lines == 0 && e.partial == 0 && e.readErr == nil {
		fail(probParse, "segment is empty")
	}
	c.prevSum = &segSummary{
		Name: name, SHA256: e.sha256, Lines: e.lines, Partial: e.partial,
		LastSeq: c.curLastSeq, LastHash: c.curLastHash, HaveLast: c.curHaveLast,
	}
}

// ---------------------------------------------------------------- gaps

func (c *chainChecker) trackGaps(r *lineResult) {
	b := &r.body
	switch b.Type {
	case model.TypeSample:
		if c.sample.ok {
			var d time.Duration
			byTS := false
			switch {
			case b.Run == c.sample.run && b.Mono >= c.sample.mono:
				// Same process: the monotonic clock is immune to wall-clock steps (on
				// Windows it also counts time spent suspended).
				d = time.Duration(b.Mono - c.sample.mono)
			case r.tsOK && c.sample.tsOK:
				d, byTS = r.ts.Sub(c.sample.ts), true
			}
			gap := model.Gap{From: clipTo(c.sample.tsS, 64), To: clipTo(b.TS, 64), Explanation: c.ev.explain()}
			end := gapEnd{from: c.sample.seq, to: b.Seq, byTS: byTS}
			switch {
			case byTS && d < 0:
				// The ts go back across a restart: the clock was set back (or one side is
				// mis-dated), so how long the monitor was stopped cannot be told. A restart is
				// a period without samples; it is listed, never hidden.
				gap.Explanation += fmt.Sprintf("; length unknown: the record ts go back by %s across this gap (the clock was set back, or records on one side are mis-dated)", fmtDur(-d))
				end.unknown = true
				c.addGap(gap, end)
			case d > 3*c.opts.FastInterval:
				gap.Seconds = int64(d / time.Second)
				c.addGap(gap, end)
			}
		}
		c.sample = lastSample{ok: true, seq: b.Seq, ts: r.ts, tsOK: r.tsOK, tsS: b.TS, mono: b.Mono, run: b.Run}
		c.ev = gapEvents{}
	case model.TypeMonitorStop:
		if !c.ev.stopped {
			c.ev.stopped, c.ev.stopReason = true, r.stopReason
		}
	case model.TypePowerEvent:
		switch r.powerKind {
		case "suspend":
			c.ev.suspended = true
		case "shutdown":
			c.ev.shutdown = true
		}
	case model.TypeMonitorStart:
		c.ev.started = true
	case model.TypeRecovery:
		c.ev.recovered = true
	case model.TypeClockJump:
		c.rep.ClockJumps++
	}
}

func (c *chainChecker) addGap(g model.Gap, e gapEnd) {
	c.rep.Gaps = append(c.rep.Gaps, g)
	c.gapEnds = append(c.gapEnds, e)
}

// explain derives a gap explanation from the records seen between two samples.
func (e gapEvents) explain() string {
	switch {
	case e.stopped:
		if e.stopReason != "" {
			return "monitor stopped (" + e.stopReason + ")"
		}
		return "monitor stopped"
	case e.suspended:
		return "system suspended"
	case e.shutdown:
		return "system shutdown"
	case e.started || e.recovered:
		return "monitor crashed or killed (no clean stop)"
	default:
		return "unexplained"
	}
}

// ---------------------------------------------------------------- anchors

// checkAnchor checks an anchor record: its head linkage, its token blob and (with a
// TokenVerifier) its token. An anchor proves time — moves LastAnchoredSeq — only when all of that
// passes and the token's TSA certificate chains to a trusted root (without a verifier: when the
// record's issue-time flags say so). A token that verifies but does not chain is not a failure
// (the verifying machine may simply lack the root), but it proves nothing either: it is listed
// with OK=true, ChainOK=false and the reason in Detail.
func (c *chainChecker) checkAnchor(r *lineResult, name string, fail func(uint64, string, string)) {
	seq := r.body.Seq
	chk := model.AnchorCheck{Seq: seq}
	a := r.anchor
	if a == nil {
		return
	}
	if a.dataErr != "" {
		chk.Detail = a.dataErr
		fail(seq, probAnchor, a.dataErr)
		c.addAnchor(chk, anchorMeta{failed: true})
		return
	}
	d := a.data
	chk.TSA = clipTo(d.TSAName, 256)
	if chk.TSA == "" {
		chk.TSA = clipTo(d.TSAURL, 256)
	}
	chk.GenTime, chk.HeadSeq = clipTo(d.GenTime, 64), d.HeadSeq
	var problems []string
	deferred := false
	if d.HeadSeq >= seq {
		problems = append(problems, fmt.Sprintf("head_seq %d is not before the anchor record", d.HeadSeq))
	} else if e := c.ring[d.HeadSeq%uint64(len(c.ring))]; e.set && e.seq == d.HeadSeq {
		if e.hash != d.HeadHash {
			problems = append(problems, fmt.Sprintf("head_hash %q does not match record %d (which hashes to %s)", clip(d.HeadHash), d.HeadSeq, e.hash))
		}
	} else {
		deferred = true
	}
	if a.tokenErr != "" {
		problems = append(problems, a.tokenErr)
	}
	var meta anchorMeta
	var doubt string // why an anchor that passes its checks does not prove time
	// gen is the time the anchor proves: the token's own genTime when a verifier read it,
	// otherwise the gen_time the writer recorded from it.
	gen, genErr := time.Parse(time.RFC3339Nano, d.GenTime)
	if c.opts.TokenVerifier != nil {
		switch {
		case a.verifyErr != "":
			problems = append(problems, "time-stamp token does not verify: "+a.verifyErr)
		case a.verified:
			chk.ChainOK = a.info.ChainOK
			if !a.info.GenTime.IsZero() {
				gen, genErr = a.info.GenTime.UTC(), nil
				chk.GenTime = a.info.GenTime.UTC().Format(time.RFC3339Nano)
				if t, err := time.Parse(time.RFC3339Nano, d.GenTime); err != nil || absDuration(t.Sub(a.info.GenTime)) > time.Second {
					problems = append(problems, fmt.Sprintf("recorded gen_time %q differs from the token's %s", clip(d.GenTime), chk.GenTime))
				}
			}
			if a.info.TSAName != "" {
				chk.TSA = clipTo(a.info.TSAName, 256)
			}
			if a.info.ChainOK {
				meta.proof = true
			} else {
				meta.doubt = doubtChain
				doubt = "not accepted as proof of time: the TSA certificate does not chain to a trusted root"
				// The note may quote certificate fields of the token: keep it on one line.
				if note := strings.TrimSpace(oneLine(a.info.ChainNote)); note != "" {
					doubt += " (" + note + ")"
				}
			}
		case a.tokenErr == "":
			// Not expected: with a verifier every token is either unusable (tokenErr), rejected
			// (verifyErr) or verified. Never let an unexamined token pass.
			problems = append(problems, "time-stamp token was not checked")
		}
	} else {
		c.noteUncheckedTokens()
		// Without a verifier, trust is what the writer recorded when it obtained the token.
		chk.ChainOK = d.Verified && d.ChainOK
		if chk.ChainOK {
			meta.proof = true
		} else {
			meta.doubt = doubtIssueFlags
			doubt = fmt.Sprintf("not accepted as proof of time: when the token was obtained it was recorded as verified=%t, chain_ok=%t", d.Verified, d.ChainOK)
		}
	}
	chk.OK = len(problems) == 0
	detail := strings.Join(problems, "; ")
	if !chk.OK {
		meta.failed = true
		fail(seq, probAnchor, detail)
	}
	chk.Detail = clipTo(joinDetail(detail, doubt), maxDetailBytes)
	idx := c.addAnchor(chk, meta)
	switch {
	case deferred:
		// Its head check waits for finish(): it does not bound record times either.
		c.deferred = append(c.deferred, deferredAnchor{idx: idx, headSeq: d.HeadSeq, headHash: d.HeadHash, seg: name, line: r.lineNo, seq: seq})
	case chk.OK && meta.proof:
		c.markAnchored(d.HeadSeq)
		if c.tm != nil && genErr == nil {
			c.tm.anchor(tsBound{anchor: seq, head: d.HeadSeq, tsa: chk.TSA, gen: gen})
		}
	}
}

func (c *chainChecker) addAnchor(chk model.AnchorCheck, m anchorMeta) int {
	c.anchors = append(c.anchors, chk)
	c.anchorMeta = append(c.anchorMeta, m)
	return len(c.anchors) - 1
}

// noteUncheckedTokens explains, once, what was and was not checked without a token verifier.
func (c *chainChecker) noteUncheckedTokens() {
	if c.tokensNoted {
		return
	}
	c.tokensNoted = true
	if c.opts.CheckBlobs {
		c.note("anchor time-stamp tokens were not cryptographically checked (no token verifier); only their presence, SHA-256 and head linkage were verified")
	} else {
		c.note("anchor time-stamp tokens were not checked at all (no token verifier, blob checks off); only head linkage was verified")
	}
	c.note("without a token verifier an anchor counts as proof of time only if its record states that, when the token was obtained, " +
		"it verified and its TSA certificate chained to a trusted root (verified and chain_ok): last_anchored_seq and unanchored_tail rest on these issue-time flags")
}

func (c *chainChecker) markAnchored(seq uint64) {
	if !c.anchoredAny || seq > c.lastAnchored {
		c.lastAnchored, c.anchoredAny = seq, true
	}
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// finish resolves anchors whose covered record was too far back for the hash ring and
// completes the report.
func (c *chainChecker) finish(ctx context.Context, r contracts.LedgerReader) {
	// Failures found here lie anywhere in the ledger, while the main pass kept only the first
	// maxReportedFailures of its own (which arrive in ledger order). Merge before capping so
	// the report lists the earliest failures in ledger order whatever pass found them.
	var late []model.VerifyFailure
	for _, d := range c.deferred {
		if ctx.Err() != nil {
			break
		}
		chk, meta := &c.anchors[d.idx], &c.anchorMeta[d.idx]
		env, _, err := r.Record(d.headSeq)
		var problem string
		switch {
		case err == nil:
			if h := sha256Hex([]byte(env.B)); h != d.headHash {
				problem = fmt.Sprintf("head_hash %q does not match record %d (which hashes to %s)", clip(d.headHash), d.headSeq, h)
			}
		case errors.Is(err, contracts.ErrNotFound) && c.inOmittedRun(d.headSeq):
			// Bundle mode: the covered record lies in the segments left out between the genesis
			// segment and the run. Nothing included is covered by this anchor.
			meta.notIncluded = meta.notIncluded || chk.OK
			chk.OK = false
			chk.Detail = clipTo(joinDetail(chk.Detail, fmt.Sprintf("covered record %d is not included", d.headSeq)), maxDetailBytes)
			c.note(fmt.Sprintf("anchor at seq %d covers record %d, which is not included; its head hash was not checked", d.seq, d.headSeq))
			continue
		case errors.Is(err, contracts.ErrNotFound):
			problem = fmt.Sprintf("covered record %d is missing", d.headSeq)
		default:
			problem = fmt.Sprintf("covered record %d cannot be read: %v", d.headSeq, err)
		}
		if problem != "" {
			if chk.OK {
				chk.OK = false
				late = append(late, model.VerifyFailure{Seq: d.seq, Segment: d.seg, Line: d.line, Problem: probAnchor,
					Detail: clipTo(problem, maxDetailBytes)})
			}
			meta.failed = true
			chk.Detail = clipTo(joinDetail(chk.Detail, problem), maxDetailBytes)
			continue
		}
		if chk.OK && meta.proof {
			c.markAnchored(d.headSeq)
		}
	}

	rep := c.rep
	segIdx := make(map[string]int, len(c.names))
	for i, n := range c.names {
		segIdx[n] = i
	}
	rep.FailuresTotal += len(late)
	rep.Failures = append(rep.Failures, late...)
	if c.tm != nil {
		// Time failures are found when a run of records ends, or when an anchor covers records
		// written before it: each list is in ledger order, so the merge keeps the earliest.
		c.tm.finish()
		rep.FailuresTotal += c.tm.failTotal
		rep.Failures = append(rep.Failures, c.tm.lowFails...)
		rep.Failures = append(rep.Failures, c.tm.highFails...)
		c.tm.annotateGaps(rep.Gaps, c.gapEnds)
	}
	sort.SliceStable(rep.Failures, func(i, j int) bool {
		a, b := rep.Failures[i], rep.Failures[j]
		if segIdx[a.Segment] != segIdx[b.Segment] {
			return segIdx[a.Segment] < segIdx[b.Segment]
		}
		return a.Line < b.Line
	})
	if len(rep.Failures) > maxReportedFailures {
		rep.Failures = rep.Failures[:maxReportedFailures]
	}
	// Records the writer appended about its own integrity are evidence a reader must see,
	// even when the chain verifies.
	if n := rep.TypeCounts[model.TypeRecovery]; n > 0 {
		c.note(fmt.Sprintf("%d recovery record(s): bytes the writer removed from a damaged segment tail or from an interrupted segment creation are kept in quarantine/ and described by these records", n))
	}
	if n := rep.TypeCounts[model.TypeIntegrityAlert]; n > 0 {
		c.note(fmt.Sprintf("%d integrity_alert record(s): the writer itself detected integrity problems (for example when opening the ledger or in the blob store); read these records", n))
	}
	c.noteUnprovenAnchors()
	if c.anchoredAny {
		rep.LastAnchoredSeq = c.lastAnchored
		if c.lastSeq > c.lastAnchored {
			rep.UnanchoredTail = c.lastSeq - c.lastAnchored
		}
	} else {
		rep.UnanchoredTail = rep.Records
		if rep.Records > 0 && c.full {
			if len(c.anchors) == 0 {
				c.note("no anchor record: no part of this ledger is covered by an independent time-stamp")
			} else {
				c.note("no anchor is accepted as proof of time: no part of this ledger is covered by a trusted independent time-stamp")
			}
		}
	}
	rep.Anchors = trimAnchors(c.anchors, func(n int) {
		c.note(fmt.Sprintf("%d older passing anchor checks are not listed", n))
	})
	if len(rep.Gaps) > maxListedGaps {
		c.note(fmt.Sprintf("%d monitor gaps found; only the most recent %d are listed", len(rep.Gaps), maxListedGaps))
		rep.Gaps = append([]model.Gap(nil), rep.Gaps[len(rep.Gaps)-maxListedGaps:]...)
	}
	if c.lateTS > 0 {
		c.note(fmt.Sprintf("%d record(s) carry a ts later than their segment's day (unexpected for this writer)", c.lateTS))
	}
}

// noteUnprovenAnchors adds one note counting the anchor records that are not accepted as proof of
// time, by reason. Every anchor is counted, including those the listing omits.
func (c *chainChecker) noteUnprovenAnchors() {
	var chain, flags, failed, notIncluded int
	for i, a := range c.anchors {
		m := c.anchorMeta[i]
		switch {
		case a.OK && m.proof:
		case m.notIncluded:
			notIncluded++
		case !a.OK || m.failed:
			failed++
		case m.doubt == doubtChain:
			chain++
		default: // doubtIssueFlags
			flags++
		}
	}
	n := chain + flags + failed + notIncluded
	if n == 0 {
		return
	}
	var parts []string
	if chain > 0 {
		parts = append(parts, fmt.Sprintf("%d verified for the anchored head hash but signed by a TSA certificate that does not chain to a trusted root (anyone can make such a token)", chain))
	}
	if flags > 0 {
		parts = append(parts, fmt.Sprintf("%d recorded, when the token was obtained, as not verified or not chained to a trusted root", flags))
	}
	if failed > 0 {
		parts = append(parts, fmt.Sprintf("%d failed verification (see failures)", failed))
	}
	if notIncluded > 0 {
		parts = append(parts, fmt.Sprintf("%d cover a record that is not included", notIncluded))
	}
	c.note(fmt.Sprintf("%d of %d anchor record(s) are not accepted as proof of time and do not count for last_anchored_seq or unanchored_tail: %s",
		n, len(c.anchors), strings.Join(parts, "; ")))
}

func joinDetail(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

// trimAnchors keeps every failing anchor check and the most recent passing ones.
func trimAnchors(all []model.AnchorCheck, omitted func(int)) []model.AnchorCheck {
	passing := 0
	for _, a := range all {
		if a.OK {
			passing++
		}
	}
	if passing <= maxListedAnchors {
		if all == nil {
			return []model.AnchorCheck{}
		}
		return all
	}
	drop := passing - maxListedAnchors
	out := make([]model.AnchorCheck, 0, len(all)-drop)
	for _, a := range all {
		if a.OK && drop > 0 {
			drop--
			continue
		}
		out = append(out, a)
	}
	omitted(passing - maxListedAnchors)
	return out
}
