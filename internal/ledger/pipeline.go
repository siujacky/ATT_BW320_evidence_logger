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
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// The verification pipeline streams segment lines through parallel workers that do the
// expensive per-record work (strict parse, SHA-256, Ed25519, blob and token checks); a single
// collector then checks ordering/linkage in file order. Memory is bounded by the number of
// batches in flight, independent of ledger size.

const (
	batchLines  = 64
	batchBytes  = 1 << 20  // a batch is flushed early once its lines reach this size
	maxInFlight = 64 << 20 // byte budget for lines between the reader and the collector
	sigNone     = int8(0)  // signature not checked (no public key)
	sigOK       = int8(1)
	sigBad      = int8(-1)
)

// lineSource is one segment to stream.
type lineSource struct {
	name string
	date time.Time
	open func() (io.ReadCloser, error)
	// load (optional) reads the raw bytes open streams into memory, nil when they are too large
	// to hold: the verification cache identifies a segment by them (verifycache.go).
	load func() (*rawSegment, error)
}

// lineResult is the outcome of checking one complete line.
type lineResult struct {
	seg     int
	lineNo  int   // 1-based within the segment
	off     int64 // byte offset of the line in the uncompressed segment
	n       int   // line length including '\n'
	tooLong bool

	perr      string // parse problem ("" = none)
	envOK     bool   // envelope parsed; claimH/hashHex valid
	claimH    string // "h" as stored
	hashHex   string // SHA-256 of "b" as computed
	sig       int8
	sigDetail string
	sigFailed bool // the Ed25519 check itself failed (s decoded); recorded by the verification cache
	bodyOK    bool
	body      model.Body // Data is cleared after type-specific parsing
	ts        time.Time
	tsOK      bool

	dataErr    string // type-specific payload problem
	genesisPub ed25519.PublicKey
	genesisFP  string
	segOpen    *model.SegmentOpen
	anchor     *anchorInfo
	stopReason string
	powerKind  string
	recoveryOf string // a recovery record's quarantine_as
	sntpOffMs  int64  // a clock_check record's median SNTP offset (server - local)
	sntpOK     bool
	clockAlert bool // the writer's integrity_alert about a clock behind the newest record
	blobs      []blobOutcome
}

// segEnd summarises one streamed segment.
type segEnd struct {
	seg     int
	sha256  string
	bytes   int64
	lines   int
	partial int64 // bytes of an incomplete final line
	readErr error
	openErr error
}

type batch struct {
	items []lineResult
	raws  [][]byte
	size  int64 // bytes of raws, charged to the in-flight budget
	end   *segEnd
	done  chan struct{}
}

// byteBudget bounds the bytes held by batches in flight, whatever the line sizes. A batch is
// always admitted when nothing else is in flight, so a single huge line cannot deadlock.
type byteBudget struct {
	mu   sync.Mutex
	cond *sync.Cond
	used int64
	max  int64
}

func newByteBudget(max int64) *byteBudget {
	b := &byteBudget{max: max}
	b.cond = sync.NewCond(&b.mu)
	return b
}

func (b *byteBudget) acquire(ctx context.Context, n int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for b.used > 0 && b.used+n > b.max {
		if err := ctx.Err(); err != nil {
			return err
		}
		b.cond.Wait()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	b.used += n
	return nil
}

func (b *byteBudget) release(n int64) {
	b.mu.Lock()
	b.used -= n
	b.cond.Broadcast()
	b.mu.Unlock()
}

// wake lets a waiting acquire observe cancellation.
func (b *byteBudget) wake() {
	b.mu.Lock()
	b.cond.Broadcast()
	b.mu.Unlock()
}

// workerConfig selects the per-line checks.
type workerConfig struct {
	pub    ed25519.PublicKey // nil: signatures are not checked
	blobs  *blobChecker      // nil: blobs are not checked
	tokens *tokenChecker     // nil: anchor payloads are not examined
	cache  *cacheRun         // nil: no verification cache (verifycache.go)
}

// runPipeline streams srcs in order. visit is called for every complete line and segDone at
// the end of every segment, both from the calling goroutine and in file order.
func runPipeline(ctx context.Context, srcs []lineSource, cfg *workerConfig,
	visit func(*lineResult), segDone func(*segEnd)) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	workers := runtime.GOMAXPROCS(0)
	if workers > 16 {
		workers = 16
	}
	if workers < 1 {
		workers = 1
	}
	order := make(chan *batch, workers*4)
	work := make(chan *batch, workers*2)
	budget := newByteBudget(maxInFlight)
	var wg sync.WaitGroup
	var prodErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(order)
		defer close(work)
		prodErr = produce(ctx, srcs, cfg.cache, order, work, budget)
	}()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for b := range work {
				for j := range b.items {
					cfg.process(&b.items[j], b.raws[j])
				}
				b.raws = nil
				close(b.done)
			}
		}()
	}

	var err error
collect:
	for b := range order {
		select {
		case <-b.done:
		case <-ctx.Done():
			err = ctx.Err()
			break collect
		}
		for j := range b.items {
			visit(&b.items[j])
		}
		if b.end != nil {
			segDone(b.end)
		}
		budget.release(b.size)
		if err = ctx.Err(); err != nil {
			break collect
		}
	}
	// Normal completion: the producer closed order after sending everything. Otherwise the
	// parent context was cancelled; stop the producer and workers before returning.
	cancel()
	budget.wake()
	wg.Wait()
	if err == nil {
		err = prodErr
	}
	return err
}

// produce reads every source line by line and hands batches to the collector and workers.
func produce(ctx context.Context, srcs []lineSource, cache *cacheRun, order, work chan<- *batch, budget *byteBudget) error {
	send := func(b *batch) error {
		if err := budget.acquire(ctx, b.size); err != nil {
			return err
		}
		select {
		case order <- b:
		case <-ctx.Done():
			return ctx.Err()
		}
		if len(b.items) == 0 {
			close(b.done)
			return nil
		}
		select {
		case work <- b:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	newBatch := func() *batch {
		return &batch{items: make([]lineResult, 0, batchLines), raws: make([][]byte, 0, batchLines), done: make(chan struct{})}
	}
	for si, src := range srcs {
		rc, err := cache.openSource(si, src)
		if err != nil {
			b := newBatch()
			b.end = &segEnd{seg: si, openErr: err}
			if err := send(b); err != nil {
				return err
			}
			continue
		}
		h := sha256.New()
		lr := newLineReader(io.TeeReader(rc, h), readBufSize)
		end := &segEnd{seg: si}
		b := newBatch()
		lineNo := 0
		for {
			rec, err := lr.next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				end.readErr = err
				break
			}
			if !rec.complete {
				end.partial = int64(rec.n)
				continue // next call returns io.EOF
			}
			lineNo++
			b.items = append(b.items, lineResult{seg: si, lineNo: lineNo, off: rec.start, n: rec.n, tooLong: rec.tooLong})
			var raw []byte
			if !rec.tooLong {
				raw = bytes.Clone(rec.data)
			}
			b.raws = append(b.raws, raw)
			b.size += int64(len(raw))
			if len(b.items) == batchLines || b.size >= batchBytes {
				if err := send(b); err != nil {
					rc.Close()
					return err
				}
				b = newBatch()
			}
		}
		rc.Close()
		end.sha256 = hex.EncodeToString(h.Sum(nil))
		end.bytes = lr.off
		end.lines = lineNo
		b.end = end
		if err := send(b); err != nil {
			return err
		}
	}
	return nil
}

// process performs the per-line checks (called from worker goroutines).
func (cfg *workerConfig) process(r *lineResult, raw []byte) {
	if r.tooLong {
		return
	}
	env, err := parseEnvelopeStrict(raw)
	if err != nil {
		r.perr = clipTo(err.Error(), maxDetailBytes)
		return
	}
	r.envOK = true
	r.claimH = env.H
	b := []byte(env.B)
	r.hashHex = sha256Hex(b)
	if cfg.pub != nil {
		sig, err := decodeSignature(env.S)
		switch {
		case err != nil:
			r.sig, r.sigDetail = sigBad, err.Error()
		case !cfg.signatureValid(r, b, sig):
			r.sig, r.sigDetail = sigBad, "Ed25519 signature does not verify with the ledger's public key"
		default:
			r.sig = sigOK
		}
	}
	if err := json.Unmarshal(b, &r.body); err != nil {
		// encoding/json quotes whole number literals in its errors: bound the message.
		r.perr = clipTo("body is not valid JSON: "+err.Error(), maxDetailBytes)
		return
	}
	r.bodyOK = true
	if t, err := time.Parse(time.RFC3339Nano, r.body.TS); err == nil {
		r.ts, r.tsOK = t, true
	}
	switch r.body.Type {
	case model.TypeGenesis:
		var g model.Genesis
		if err := json.Unmarshal(r.body.Data, &g); err != nil {
			r.dataErr = clipTo("genesis payload: "+err.Error(), maxDetailBytes)
			break
		}
		pub, err := base64.StdEncoding.DecodeString(g.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			r.dataErr = "genesis payload: public_key is not a base64 Ed25519 key"
			break
		}
		r.genesisPub, r.genesisFP = pub, g.Fingerprint
	case model.TypeSegmentOpen:
		var so model.SegmentOpen
		if err := json.Unmarshal(r.body.Data, &so); err != nil {
			r.dataErr = clipTo("segment_open payload: "+err.Error(), maxDetailBytes)
			break
		}
		r.segOpen = &so
	case model.TypeRecovery:
		var rec model.Recovery
		if json.Unmarshal(r.body.Data, &rec) == nil {
			r.recoveryOf = rec.QuarantineAs
		}
	case model.TypeAnchor:
		if cfg.tokens != nil {
			r.anchor = cfg.tokens.check(r.body.Data)
		}
	case model.TypeMonitorStop:
		var ms model.MonitorStop
		if json.Unmarshal(r.body.Data, &ms) == nil {
			r.stopReason = ms.Reason
		}
	case model.TypePowerEvent:
		var pe model.PowerEvent
		if json.Unmarshal(r.body.Data, &pe) == nil {
			r.powerKind = pe.Kind
		}
	case model.TypeClockCheck:
		var cc model.ClockCheck
		if json.Unmarshal(r.body.Data, &cc) == nil {
			r.sntpOffMs, r.sntpOK = medianOffset(cc.Results)
		}
	case model.TypeIntegrityAlert:
		var ia model.IntegrityAlert
		if json.Unmarshal(r.body.Data, &ia) == nil {
			for _, d := range ia.Details {
				if strings.HasPrefix(d, clockBehindPrefix) {
					r.clockAlert = true
					break
				}
			}
		}
	}
	if cfg.blobs != nil && len(r.body.Blobs) > 0 {
		r.blobs = make([]blobOutcome, 0, len(r.body.Blobs))
		for _, id := range r.body.Blobs {
			r.blobs = append(r.blobs, cfg.blobs.check(id))
		}
	}
	r.body.Data = nil
}

// ---------------------------------------------------------------- blob checks

type blobState int8

const (
	blobOK blobState = iota
	blobMissing
	blobCorrupt
	blobInvalidID
)

type blobOutcome struct {
	id     string
	state  blobState
	detail string
}

// blobChecker verifies each distinct blob once (content hash re-computed here, independent of
// the reader), remembering outcomes by raw digest to keep memory small.
type blobChecker struct {
	get     func(id string) ([]byte, error)
	mu      sync.Mutex
	done    map[[32]byte]blobOutcome
	checked atomic.Int64
}

func newBlobChecker(get func(string) ([]byte, error)) *blobChecker {
	return &blobChecker{get: get, done: map[[32]byte]blobOutcome{}}
}

func (c *blobChecker) check(id string) blobOutcome {
	if !isBlobID(id) {
		return blobOutcome{id: clip(id), state: blobInvalidID, detail: fmt.Sprintf("invalid blob id %q", clip(id))}
	}
	var key [32]byte
	_, _ = hex.Decode(key[:], []byte(id))
	c.mu.Lock()
	out, ok := c.done[key]
	c.mu.Unlock()
	if ok {
		out.id = id
		return out
	}
	out = c.verify(id)
	c.mu.Lock()
	if _, dup := c.done[key]; !dup {
		stored := out
		stored.id = "" // the key holds the id
		c.done[key] = stored
		c.checked.Add(1)
	}
	c.mu.Unlock()
	return out
}

func (c *blobChecker) verify(id string) blobOutcome {
	content, err := c.get(id)
	switch {
	case err == nil:
		if got := sha256Hex(content); got != id {
			return blobOutcome{id: id, state: blobCorrupt, detail: fmt.Sprintf("blob %s content hashes to %s", id, got)}
		}
		return blobOutcome{id: id, state: blobOK}
	case errors.Is(err, contracts.ErrNotFound) || errors.Is(err, os.ErrNotExist):
		return blobOutcome{id: id, state: blobMissing, detail: fmt.Sprintf("blob %s is missing", id)}
	default:
		return blobOutcome{id: id, state: blobCorrupt, detail: fmt.Sprintf("blob %s is unreadable or corrupt: %v", id, err)}
	}
}

// ---------------------------------------------------------------- anchor token checks

type anchorInfo struct {
	data      model.Anchor
	dataErr   string
	tokenErr  string // token blob missing/corrupt
	verified  bool   // TokenVerifier accepted the token for head_hash
	verifyErr string
	info      contracts.TokenInfo
}

// tokenChecker examines anchor payloads; with a verifier it checks each token against the
// 32 raw bytes of the anchored head hash.
type tokenChecker struct {
	get      func(id string) ([]byte, error)
	fetch    bool // fetch and hash-check the token blob even without a verifier
	verifier contracts.TokenVerifier
	mu       sync.Mutex   // TokenVerifier implementations are not required to be concurrency-safe
	checked  atomic.Int64 // tokens handed to the verifier (VerifyReport.TokensChecked)
}

func (t *tokenChecker) check(data json.RawMessage) *anchorInfo {
	a := &anchorInfo{}
	if err := json.Unmarshal(data, &a.data); err != nil {
		a.dataErr = clipTo("anchor payload: "+err.Error(), maxDetailBytes)
		return a
	}
	if !t.fetch && t.verifier == nil {
		return a
	}
	if !isBlobID(a.data.TokenSHA256) {
		a.tokenErr = fmt.Sprintf("token_sha256 %q is not a blob id", clip(a.data.TokenSHA256))
		return a
	}
	token, err := t.get(a.data.TokenSHA256)
	if err != nil {
		if errors.Is(err, contracts.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			a.tokenErr = "time-stamp token blob " + a.data.TokenSHA256 + " is missing"
		} else {
			a.tokenErr = fmt.Sprintf("time-stamp token blob %s is unreadable: %v", a.data.TokenSHA256, err)
		}
		return a
	}
	if got := sha256Hex(token); got != a.data.TokenSHA256 {
		a.tokenErr = fmt.Sprintf("time-stamp token blob %s content hashes to %s", a.data.TokenSHA256, got)
		return a
	}
	if t.verifier == nil {
		return a
	}
	digest, err := hex.DecodeString(a.data.HeadHash)
	if err != nil || len(digest) != sha256.Size {
		a.verifyErr = fmt.Sprintf("head_hash %q is not a SHA-256 hex digest", clip(a.data.HeadHash))
		return a
	}
	t.mu.Lock()
	t.checked.Add(1)
	info, err := t.verifier.VerifyToken(token, digest)
	t.mu.Unlock()
	if err != nil {
		a.verifyErr = clipTo(err.Error(), maxDetailBytes)
		return a
	}
	a.verified, a.info = true, info
	return a
}
