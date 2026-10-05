package web

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
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// Compile-time conformance of the fakes with the contracts the server consumes.
var (
	_ contracts.StatusSource = (*fakeStatus)(nil)
	_ contracts.Actions      = (*fakeActions)(nil)
	_ contracts.LedgerReader = (*fakeReader)(nil)
	_ contracts.Verifier     = (*fakeVerifier)(nil)
	_ contracts.Exporter     = (*fakeExporter)(nil)
)

// ----------------------------------------------------------------------------- StatusSource

type fakeStatus struct {
	mu        sync.Mutex
	status    model.Status
	series    map[string]model.Series
	seriesErr error
	incidents []model.Incident // returned as-is (the handler must not mutate it)
	gotFrom   time.Time
	gotTo     time.Time
	panicMsg  string
}

func (f *fakeStatus) Status() model.Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.panicMsg != "" {
		panic(f.panicMsg)
	}
	return f.status
}

func (f *fakeStatus) Series(rangeName string) (model.Series, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.seriesErr != nil {
		return model.Series{}, f.seriesErr
	}
	if s, ok := f.series[rangeName]; ok {
		return s, nil
	}
	return model.Series{Range: rangeName}, nil
}

func (f *fakeStatus) Incidents(from, to time.Time) []model.Incident {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gotFrom, f.gotTo = from, to
	return f.incidents
}

func (f *fakeStatus) Incident(id string) (model.Incident, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, inc := range f.incidents {
		if inc.ID == id {
			return inc, true
		}
	}
	return model.Incident{}, false
}

// ----------------------------------------------------------------------------- Actions

type noteCall struct {
	text, author, source string
	ctxErr               error // ctx.Err() observed inside the call
}

type fakeActions struct {
	mu sync.Mutex

	notes   []noteCall
	noteErr error

	notifCalls  []string // "true|actor"
	notifChange model.ConfigChange
	notifErr    error
	notifGate   chan struct{} // when non-nil, SetGatewayNotification waits for it
	notifIn     chan struct{} // signalled when SetGatewayNotification starts

	anchors     []model.Anchor
	anchorErr   error
	anchorCalls []string

	trustCalls    []string           // actors
	trustExpected []string           // expectedSHA256 of each TrustCert call, as passed
	trustCtxErr   error              // ctx.Err() observed inside the last TrustCert call
	trustChange   model.ConfigChange // returned as-is when set
	trustErr      error
	trustGate     chan struct{} // when non-nil, TrustCert waits for it
	trustIn       chan struct{} // signalled when TrustCert starts
	// trustPending is the certificate the fake monitor holds as waiting for confirmation
	// ("" = testNewCert); trustFn, when set, answers TrustCert instead (after the call is
	// recorded).
	trustPending string
	trustFn      func(expected string) (model.ConfigChange, error)

	exports []model.CustodyExport
}

// Fingerprints used by the certificate tests: the pinned certificate and the changed one.
var (
	testPinnedCert = strings.Repeat("ab", 32)
	testNewCert    = strings.Repeat("cd", 32)
)

// TrustCert behaves like the monitor: it pins the pending certificate, but when expectedSHA256
// is given it first compares it with the pending one (under its lock) and refuses a mismatch
// with an error wrapping contracts.ErrBusy.
func (f *fakeActions) TrustCert(ctx context.Context, actor, expectedSHA256 string) (model.ConfigChange, error) {
	f.mu.Lock()
	gate, in := f.trustGate, f.trustIn
	f.mu.Unlock()
	if in != nil {
		in <- struct{}{}
	}
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return model.ConfigChange{}, ctx.Err()
		}
	}
	f.mu.Lock()
	f.trustCalls = append(f.trustCalls, actor)
	f.trustExpected = append(f.trustExpected, expectedSHA256)
	f.trustCtxErr = ctx.Err()
	change, err, pending, fn := f.trustChange, f.trustErr, f.trustPending, f.trustFn
	f.mu.Unlock()
	switch {
	case fn != nil:
		return fn(expectedSHA256)
	case err != nil || change != (model.ConfigChange{}):
		return change, err
	}
	if pending == "" {
		pending = testNewCert
	}
	if expectedSHA256 != "" && expectedSHA256 != pending {
		return model.ConfigChange{}, fmt.Errorf("the gateway certificate waiting for confirmation is SHA-256 %s, not %s: %w",
			pending, expectedSHA256, contracts.ErrBusy)
	}
	return model.ConfigChange{Target: "monitor", What: "gateway.pinned_cert_sha256 (trusted gateway TLS certificate)",
		Before: testPinnedCert, After: pending, Actor: actor, Result: "applied"}, nil
}

// trustState returns the actors and the expected fingerprints of the TrustCert calls so far.
func (f *fakeActions) trustState() (actors, expected []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.trustCalls), slices.Clone(f.trustExpected)
}

func (f *fakeActions) Note(ctx context.Context, text, author, source string) (model.Ref, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.notes = append(f.notes, noteCall{text, author, source, ctx.Err()})
	if f.noteErr != nil {
		return model.Ref{}, f.noteErr
	}
	return model.Ref{Seq: uint64(100 + len(f.notes)), Hash: strings.Repeat("ab", 32), TS: "2026-10-05T03:20:00.123456789Z"}, nil
}

func (f *fakeActions) SetGatewayNotification(ctx context.Context, enabled bool, actor string) (model.ConfigChange, error) {
	f.mu.Lock()
	gate, in := f.notifGate, f.notifIn
	f.mu.Unlock()
	if in != nil {
		in <- struct{}{}
	}
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return model.ConfigChange{}, ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.notifCalls = append(f.notifCalls, boolString(enabled)+"|"+actor)
	cc := f.notifChange
	if cc == (model.ConfigChange{}) {
		cc = model.ConfigChange{Target: "gateway", What: "events.bbevent (Broadband Status Notification)",
			Before: boolString(!enabled), After: boolString(enabled), Actor: actor, Result: "verified"}
	}
	return cc, f.notifErr
}

func (f *fakeActions) AnchorNow(ctx context.Context, reason string) ([]model.Anchor, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.anchorCalls = append(f.anchorCalls, reason)
	return f.anchors, f.anchorErr
}

func (f *fakeActions) RecordExport(ctx context.Context, e model.CustodyExport) (model.Ref, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.exports = append(f.exports, e)
	return model.Ref{Seq: 7}, nil
}

func boolString(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// ----------------------------------------------------------------------------- LedgerReader

type fakeReader struct {
	mu        sync.Mutex
	envs      []model.Envelope
	bodies    []model.Body
	blobs     map[string][]byte
	scanErr   error
	recordErr map[uint64]error
	blobErr   error
	callbacks atomic.Int64 // records handed to Scan callbacks
}

func (r *fakeReader) snapshot() ([]model.Envelope, []model.Body) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.envs, r.bodies
}

func (r *fakeReader) Scan(fromSeq uint64, fn func(model.Envelope, model.Body) error) error {
	if r.scanErr != nil {
		return r.scanErr
	}
	envs, bodies := r.snapshot()
	for i := range envs {
		if bodies[i].Seq < fromSeq {
			continue
		}
		if err := r.recordErr[bodies[i].Seq]; err != nil {
			return err // reading that line fails, as it would for Record
		}
		r.callbacks.Add(1)
		if err := fn(envs[i], bodies[i]); err != nil {
			if errors.Is(err, contracts.ErrStop) {
				return nil
			}
			return err
		}
	}
	return nil
}

func (r *fakeReader) ScanTime(from, to time.Time, fn func(model.Envelope, model.Body) error) error {
	envs, bodies := r.snapshot()
	for i := range envs {
		ts, err := time.Parse(time.RFC3339Nano, bodies[i].TS)
		if err != nil || ts.Before(from) || !ts.Before(to) {
			continue
		}
		if err := fn(envs[i], bodies[i]); err != nil {
			if errors.Is(err, contracts.ErrStop) {
				return nil
			}
			return err
		}
	}
	return nil
}

func (r *fakeReader) Record(seq uint64) (model.Envelope, model.Body, error) {
	if err := r.recordErr[seq]; err != nil {
		return model.Envelope{}, model.Body{}, err
	}
	envs, bodies := r.snapshot()
	for i := range envs {
		if bodies[i].Seq == seq {
			return envs[i], bodies[i], nil
		}
	}
	return model.Envelope{}, model.Body{}, contracts.ErrNotFound
}

func (r *fakeReader) Segments() ([]contracts.SegmentInfo, error) {
	envs, bodies := r.snapshot()
	if len(envs) == 0 {
		return nil, nil
	}
	return []contracts.SegmentInfo{{Name: "ledger-2026-10-05", FirstSeq: bodies[0].Seq, LastSeq: bodies[len(bodies)-1].Seq, Records: len(envs), Active: true}}, nil
}

func (r *fakeReader) OpenSegment(name string) (io.ReadCloser, error) {
	envs, _ := r.snapshot()
	var buf bytes.Buffer
	for _, e := range envs {
		b, _ := json.Marshal(e)
		buf.Write(append(b, '\n'))
	}
	return io.NopCloser(&buf), nil
}

func (r *fakeReader) GetBlob(id string) ([]byte, error) {
	if r.blobErr != nil {
		return nil, r.blobErr
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.blobs[id]
	if !ok {
		return nil, contracts.ErrNotFound
	}
	return b, nil
}

// addBlob stores content under its SHA-256 and returns the id.
func (r *fakeReader) addBlob(content []byte) string {
	sum := sha256.Sum256(content)
	id := hex.EncodeToString(sum[:])
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.blobs == nil {
		r.blobs = map[string][]byte{}
	}
	r.blobs[id] = content
	return id
}

// testKey is a fixed Ed25519 key for test ledgers.
var testKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))

// sealRecord builds a hash-chained, signed envelope exactly as the ledger format specifies.
func sealRecord(key ed25519.PrivateKey, body model.Body) model.Envelope {
	b, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(b)
	return model.Envelope{
		H: hex.EncodeToString(sum[:]),
		S: base64.StdEncoding.EncodeToString(ed25519.Sign(key, b)),
		B: string(b),
	}
}

// newTestLedger returns a reader holding one record per type, seq 0..len-1, one second apart.
func newTestLedger(types ...string) *fakeReader {
	r := &fakeReader{}
	prev := model.ZeroHash
	base := time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)
	for i, typ := range types {
		data, _ := json.Marshal(map[string]any{"i": i, "html": "<b>&amp;</b>", "note": "évidence"})
		body := model.Body{
			V: model.FormatVersion, Seq: uint64(i), Prev: prev,
			TS:   base.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano),
			Mono: int64(i) * int64(time.Second), Run: strings.Repeat("0f", 16), Type: typ, Data: data,
		}
		env := sealRecord(testKey, body)
		prev = env.H
		r.envs = append(r.envs, env)
		r.bodies = append(r.bodies, body)
	}
	return r
}

// ----------------------------------------------------------------------------- Verifier

type fakeVerifier struct {
	report  model.VerifyReport
	err     error
	started chan struct{} // optional: receives when Verify starts
	release chan struct{} // optional: Verify waits for it
	calls   atomic.Int32
}

func (v *fakeVerifier) Verify(ctx context.Context) (model.VerifyReport, error) {
	v.calls.Add(1)
	if v.started != nil {
		v.started <- struct{}{}
	}
	if v.release != nil {
		select {
		case <-v.release:
		case <-ctx.Done():
			return model.VerifyReport{}, ctx.Err()
		}
	}
	return v.report, v.err
}

// ----------------------------------------------------------------------------- Exporter

type fakeExporter struct {
	mu       sync.Mutex
	list     []contracts.ExportInfo
	files    map[string][]byte
	listErr  error
	buildErr error
	openErr  error
	seekable bool
	lastReq  contracts.ExportRequest
	ctxErr   error
	builds   int
	gate     chan struct{}
	in       chan struct{}
}

func (e *fakeExporter) Build(ctx context.Context, req contracts.ExportRequest) (contracts.ExportInfo, error) {
	if e.in != nil {
		e.in <- struct{}{}
	}
	if e.gate != nil {
		<-e.gate
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.builds++
	e.lastReq = req
	e.ctxErr = ctx.Err()
	if e.buildErr != nil {
		return contracts.ExportInfo{}, e.buildErr
	}
	content := []byte("PK\x03\x04 fake bundle " + req.IncidentID)
	sum := sha256.Sum256(content)
	info := contracts.ExportInfo{
		FileName: "att-evidence_20261005T0300Z_20261005T0400Z_abcd1234.zip", Size: int64(len(content)),
		Created: time.Date(2026, 10, 5, 4, 0, 0, 0, time.UTC), SHA256: hex.EncodeToString(sum[:]),
		Records: 42, Blobs: 3, CustodySeq: 43,
	}
	if e.files == nil {
		e.files = map[string][]byte{}
	}
	e.files[info.FileName] = content
	e.list = append(e.list, info)
	return info, nil
}

func (e *fakeExporter) List() ([]contracts.ExportInfo, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.list, e.listErr
}

type readSeekNopCloser struct{ *bytes.Reader }

func (readSeekNopCloser) Close() error { return nil }

func (e *fakeExporter) Open(name string) (io.ReadCloser, contracts.ExportInfo, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.openErr != nil {
		return nil, contracts.ExportInfo{}, e.openErr
	}
	b, ok := e.files[name]
	if !ok {
		return nil, contracts.ExportInfo{}, contracts.ErrNotFound
	}
	var info contracts.ExportInfo
	for _, x := range e.list {
		if x.FileName == name {
			info = x
		}
	}
	if e.seekable {
		return readSeekNopCloser{bytes.NewReader(b)}, info, nil
	}
	return io.NopCloser(bytes.NewReader(b)), info, nil
}

// ----------------------------------------------------------------------------- harness

const (
	testListen = "127.0.0.1:8320"
	testHost   = "127.0.0.1:8320"
	testOrigin = "http://127.0.0.1:8320"
)

type harness struct {
	t        *testing.T
	srv      *Server
	status   *fakeStatus
	actions  *fakeActions
	reader   *fakeReader
	verifier *fakeVerifier
	exporter *fakeExporter
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	hs := &harness{
		t:        t,
		status:   &fakeStatus{status: model.Status{Now: "2026-10-05T03:20:00Z", Verdict: model.Verdict{State: model.StateOnline, Attribution: model.AttrNone, Rules: "2026.10-1"}}},
		actions:  &fakeActions{},
		reader:   newTestLedger("genesis", "monitor_start", "sample", "gateway_snapshot", "sample", "anchor", "operator_note", "sample"),
		verifier: &fakeVerifier{report: model.VerifyReport{OK: true, Records: 8}},
		exporter: &fakeExporter{},
	}
	srv, err := New(Options{
		Listen: testListen, Status: hs.status, Actions: hs.actions, Reader: hs.reader,
		Verifier: hs.verifier, Exporter: hs.exporter, Version: "1.2.3-test",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv.now = func() time.Time { return time.Date(2026, 10, 5, 3, 20, 0, 0, time.UTC) }
	hs.srv = srv
	return hs
}

// request builds a request that passes the Host allow-list. POSTs get the CSRF header unless
// the caller overrides it (an empty value in hdr deletes a header).
func (hs *harness) request(method, target string, body io.Reader, hdr map[string]string) *http.Request {
	req := httptest.NewRequest(method, target, body)
	req.Host = testHost
	req.RemoteAddr = "127.0.0.1:50123"
	if method == http.MethodPost {
		req.Header.Set(CSRFHeader, CSRFHeaderValue)
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	return req
}

func (hs *harness) serve(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	hs.srv.Handler().ServeHTTP(rec, req)
	return rec
}

func (hs *harness) get(target string) *httptest.ResponseRecorder {
	return hs.serve(hs.request(http.MethodGet, target, nil, nil))
}

func (hs *harness) post(target, body string) *httptest.ResponseRecorder {
	return hs.serve(hs.request(http.MethodPost, target, strings.NewReader(body), nil))
}

// decode unmarshals a JSON response strictly (unknown fields are an error).
func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	dec := json.NewDecoder(bytes.NewReader(rec.Body.Bytes()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("decode %T: %v\nbody: %s", v, err, rec.Body.String())
	}
	return v
}

// wantStatus fails unless rec has the given status.
func wantStatus(t *testing.T, rec *httptest.ResponseRecorder, code int) {
	t.Helper()
	if rec.Code != code {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, code, rec.Body.String())
	}
}

// wantJSONError checks a JSON error response with the given status.
func wantJSONError(t *testing.T, rec *httptest.ResponseRecorder, code int) string {
	t.Helper()
	wantStatus(t, rec, code)
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Fatalf("error Content-Type = %q", ct)
	}
	e := decode[ErrorResponse](t, rec)
	if e.Error == "" {
		t.Fatalf("empty error message: %s", rec.Body.String())
	}
	return e.Error
}
