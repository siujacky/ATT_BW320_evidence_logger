package mongostore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"attmonitor/internal/config"
	"attmonitor/internal/contracts"
	"attmonitor/internal/ledger"
	"attmonitor/internal/model"
)

// ---------------------------------------------------------------- clock

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *testClock {
	return &testClock{t: time.Date(2026, 10, 5, 3, 20, 0, 123456789, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// ---------------------------------------------------------------- records built like the ledger

// marshalNoEscape encodes v like the ledger does (no HTML escaping, no trailing newline).
func marshalNoEscape(t testing.TB, v any) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'})
}

// signedRecord builds an envelope exactly as the ledger writer does (docs/DESIGN.md §6).
func signedRecord(t testing.TB, priv ed25519.PrivateKey, body model.Body) item {
	t.Helper()
	b := marshalNoEscape(t, &body)
	sum := sha256.Sum256(b)
	env := model.Envelope{H: hex.EncodeToString(sum[:]), S: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, b)), B: string(b)}
	// Parse it back like the ledger's readers do, so body.Data is exactly the bytes inside b.
	var back model.Body
	if err := json.Unmarshal([]byte(env.B), &back); err != nil {
		t.Fatal(err)
	}
	return item{env: env, body: back}
}

func dataOf(t testing.TB, v any) json.RawMessage { return json.RawMessage(marshalNoEscape(t, v)) }

func testKey(t testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// ---------------------------------------------------------------- in-memory reader

// memReader is a contracts.LedgerReader over records held in memory.
type memReader struct {
	mu    sync.Mutex
	recs  []item
	blobs map[string][]byte
}

var _ contracts.LedgerReader = (*memReader)(nil)

func (m *memReader) snapshot() []item {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]item(nil), m.recs...)
}

func (m *memReader) add(it item) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recs = append(m.recs, it)
}

func (m *memReader) Scan(from uint64, fn func(model.Envelope, model.Body) error) error {
	for _, it := range m.snapshot() {
		if it.body.Seq < from {
			continue
		}
		if err := fn(it.env, it.body); err != nil {
			if errors.Is(err, contracts.ErrStop) {
				return nil
			}
			return err
		}
	}
	return nil
}

func (m *memReader) ScanTime(from, to time.Time, fn func(model.Envelope, model.Body) error) error {
	return m.Scan(0, func(env model.Envelope, body model.Body) error {
		ts, err := time.Parse(time.RFC3339Nano, body.TS)
		if err != nil || ts.Before(from) || !ts.Before(to) {
			return nil
		}
		return fn(env, body)
	})
}

func (m *memReader) Record(seq uint64) (model.Envelope, model.Body, error) {
	for _, it := range m.snapshot() {
		if it.body.Seq == seq {
			return it.env, it.body, nil
		}
	}
	return model.Envelope{}, model.Body{}, contracts.ErrNotFound
}

func (m *memReader) Segments() ([]contracts.SegmentInfo, error) { return nil, nil }

func (m *memReader) OpenSegment(string) (io.ReadCloser, error) { return nil, contracts.ErrNotFound }

func (m *memReader) GetBlob(id string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.blobs[id]
	if !ok {
		return nil, contracts.ErrNotFound
	}
	return append([]byte(nil), b...), nil
}

// ---------------------------------------------------------------- real ledger

func identity(b []byte) ([]byte, error) { return append([]byte(nil), b...), nil }

// newLedger creates a real ledger (writer) in a temporary directory; it returns the store and
// the data directory.
func newLedger(t testing.TB, clk *testClock) (*ledger.Store, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := ledger.Open(ledger.Options{
		Paths:        config.PathsFor(dir),
		Host:         model.HostInfo{Hostname: "test-host", OS: "Windows 11 Pro for Workstations", OSVersion: "10.0.26200"},
		Software:     model.SoftwareInfo{Name: "att-monitor", Version: "test", GoVersion: runtime.Version(), Rules: "2026.10-4"},
		Now:          clk.Now,
		KeyProtect:   identity,
		KeyUnprotect: identity,
	})
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st, dir
}

// ledgerKey reads the signing key of a test ledger (protected with the identity function).
func ledgerKey(t testing.TB, dir string) ed25519.PrivateKey {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(config.PathsFor(dir).Keys, "ledger-signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	var kf struct {
		Protected string `json:"protected"`
	}
	if err := json.Unmarshal(b, &kf); err != nil {
		t.Fatal(err)
	}
	seed, err := base64.StdEncoding.DecodeString(kf.Protected)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("seed: %v", err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func mustAppend(t testing.TB, st *ledger.Store, typ string, data any, blobs ...string) model.Ref {
	t.Helper()
	ref, err := st.Append(typ, data, blobs...)
	if err != nil {
		t.Fatalf("Append %s: %v", typ, err)
	}
	return ref
}

func mustBlob(t testing.TB, st *ledger.Store, b []byte) string {
	t.Helper()
	id, err := st.PutBlob(b)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// Content used by the shared fixture.
const (
	htmlReason   = `gateway 192.168.1.254 answered ICMP in 1.9 ms <b>fast</b> & "quoted" é 😀 ` + "\u2028" + ` \ C:\Program Files\ATT Monitor`
	incidentID1  = "INC-20261005-032100Z"
	incidentID2  = "INC-20261005-040000Z"
	pageBodyText = "<html><head><title>Broadband Statistics</title></head><body><h2>Broadband</h2>Broadband Connection: Up \xa9 2026 AT&T</body></html>"
)

// fixture describes the records populate wrote.
type fixture struct {
	pageBlob, netshBlob, bigBlob string
	dollarSeq, bigIntSeq         uint64
	incidentClose1, incident2    uint64
}

func sample(cycle uint64, reason string) model.Sample {
	return model.Sample{
		Cycle:   cycle,
		Started: "2026-10-05T03:20:00.123456789Z",
		DurMs:   12,
		Probes: []model.ProbeResult{
			{Name: "gateway_icmp", Kind: model.KindICMP, Role: model.RoleGateway, Target: "192.168.1.254", OK: true, RTTus: 1900, Status: "IP_SUCCESS"},
			{Name: "inet_icmp_google", Kind: model.KindICMP, Role: model.RoleInet, Target: "8.8.8.8", OK: true, RTTus: 14200, Status: "IP_SUCCESS"},
		},
		Verdict: model.Verdict{State: model.StateOnline, Attribution: model.AttrNone, Reasons: []string{reason}, Rules: "2026.10-4",
			Inputs: &model.VerdictInputs{SnapshotSeq: 3, WindowCycles: 6}},
	}
}

func incident(id string, open bool, summary string) model.Incident {
	inc := model.Incident{
		ID: id, Opened: "2026-10-05T03:21:00Z", Open: open, State: model.StateISPOutage, Cause: model.CauseFiberLinkDown,
		Attribution: model.AttrProvider, Summary: summary, Rules: "2026.10-4", FirstSeq: 5,
		Evidence: []model.EvidenceRef{{Seq: 5, Type: model.TypeSample, Note: "first <bad> cycle"}},
		Stats:    model.IncidentStats{Cycles: 12, BadCycles: 9, ProbeOK: map[string]int{"gateway_icmp": 12}, DowntimeSec: 90},
	}
	if !open {
		inc.Closed = "2026-10-05T03:24:00Z"
		inc.DurationSec = 180
	}
	return inc
}

// populate appends realistic records (and blobs) to a test ledger.
func populate(t testing.TB, st *ledger.Store, clk *testClock) fixture {
	t.Helper()
	var f fixture
	step := func() { clk.Advance(10 * time.Second) }
	for i := uint64(0); i < 9; i++ {
		step()
		mustAppend(t, st, model.TypeSample, sample(i, htmlReason))
	}
	step()
	f.pageBlob = mustBlob(t, st, []byte(pageBodyText))
	f.netshBlob = mustBlob(t, st, []byte("SSID : home\r\nSignal : 99%\r\n"))
	rx := int64(-315)
	mustAppend(t, st, model.TypeGatewaySnapshot, model.GatewaySnapshot{
		Pages: []model.PageCapture{{Page: "broadbandstatistics", URL: "https://192.168.1.254/cgi-bin/broadbandstatistics.ha", Status: 200,
			FetchedAt: "2026-10-05T03:21:30Z", DurMs: 120, Bytes: len(pageBodyText), SHA256: f.pageBlob, Stored: true}},
		Broadband: &model.BroadbandStatus{Connection: "Up", Counters: map[string]int64{"IPv4 Statistics/Receive Bytes": 1 << 40, "IPv4 Statistics/Drops": 0},
			Values: map[string]string{"Broadband/Broadband Connection": "Up", "IPv6/Global Unicast IPv6 Address": "2600:1700::1"}},
		Fiber:   &model.FiberStatus{Measures: []model.DMIMeasure{{Name: "Rx Power", CurrentRaw: "-315", Current: &rx, Unit: "0.1dBm"}}},
		Derived: model.GatewayDerived{Reachable: true, RxPowerX10: &rx, Alarms: []string{"OPTICAL_RX_LOW_ALARM"}, UptimeSec: 274686},
		Trigger: "periodic",
	}, f.pageBlob, f.netshBlob)
	step()
	mustAppend(t, st, model.TypeIncidentOpen, incident(incidentID1, true, "opened"))
	step()
	mustAppend(t, st, model.TypeIncidentUpdate, incident(incidentID1, true, "updated <still down>"))
	step()
	f.incidentClose1 = mustAppend(t, st, model.TypeIncidentClose, incident(incidentID1, false, "closed: fiber link down 3 min")).Seq
	step()
	f.incident2 = mustAppend(t, st, model.TypeIncidentOpen, incident(incidentID2, true, "second")).Seq
	step()
	mustAppend(t, st, model.TypeOperatorNote, model.OperatorNote{Text: "AT&T ticket #12345 <script>alert(1)</script> — «tech» visit ✓", Author: "owner", Source: "web"})
	step()
	mustAppend(t, st, model.TypeClockJump, model.ClockJump{WallDeltaMs: -3_600_000, MonoDeltaMs: 10_000, JumpMs: -3_610_000})
	step()
	// Data that Extended JSON cannot represent faithfully.
	f.bigIntSeq = mustAppend(t, st, model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvCountersReset, Evidence: []uint64{math.MaxUint64, 7}}).Seq
	step()
	f.dollarSeq = mustAppend(t, st, model.TypeGatewaySnapshot, model.GatewaySnapshot{
		LAN:     &model.LANStatus{Values: map[string]string{"$date": "2026-10-05", "plain": "x"}},
		Trigger: "periodic",
	}).Seq
	step()
	f.bigBlob = mustBlob(t, st, bytes.Repeat([]byte("0123456789abcdef"), 1<<16)) // 1 MiB
	mustAppend(t, st, model.TypeLocalLink, model.LocalLink{Interface: "Wi-Fi", Type: "wifi", State: "connected", SSID: "home", RawSHA256: f.netshBlob}, f.netshBlob, f.bigBlob)
	for i := uint64(9); i < 14; i++ {
		step()
		mustAppend(t, st, model.TypeSample, sample(i, "plain reason"))
	}
	return f
}

// ledgerItems returns every record of a reader.
func ledgerItems(t testing.TB, r contracts.LedgerReader) []item {
	t.Helper()
	var out []item
	if err := r.Scan(0, func(env model.Envelope, body model.Body) error {
		out = append(out, item{env: env, body: body})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// ---------------------------------------------------------------- live MongoDB

// liveDB returns the test URI and a throwaway database "attmonitor_test_<random>" that is
// dropped when the test ends. It skips unless ATTMON_MONGO=1.
func liveDB(t *testing.T) (string, string, *mongo.Database) {
	t.Helper()
	if os.Getenv("ATTMON_MONGO") != "1" {
		t.Skip("set ATTMON_MONGO=1 to run against the local MongoDB (mongodb://127.0.0.1:27017)")
	}
	uri := os.Getenv("ATTMON_MONGO_URI")
	if uri == "" {
		uri = "mongodb://127.0.0.1:27017"
	}
	var rb [6]byte
	if _, err := rand.Read(rb[:]); err != nil {
		t.Fatal(err)
	}
	name := "attmonitor_test_" + hex.EncodeToString(rb[:])
	if name == DefaultDatabase || !strings.HasPrefix(name, "attmonitor_test_") {
		t.Fatalf("refusing to use database %q", name)
	}
	client, err := mongo.Connect(options.Client().ApplyURI(uri).SetServerSelectionTimeout(5 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx, nil); err != nil {
		t.Fatalf("MongoDB at %s: %v", uri, err)
	}
	db := client.Database(name)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := db.Drop(ctx); err != nil {
			t.Errorf("drop %s: %v", name, err)
		}
		_ = client.Disconnect(ctx)
	})
	return uri, name, db
}

func newReplicator(t testing.TB, o Options) *Replicator {
	t.Helper()
	r, err := New(o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = r.Close(ctx)
	})
	return r
}

func findRaw(t testing.TB, db *mongo.Database, coll string, id any) bson.Raw {
	t.Helper()
	raw, err := db.Collection(coll).FindOne(context.Background(), bson.D{{Key: "_id", Value: id}}).Raw()
	if err != nil {
		t.Fatalf("find %s %v: %v", coll, id, err)
	}
	return raw
}

func count(t testing.TB, db *mongo.Database, coll string) int64 {
	t.Helper()
	n, err := db.Collection(coll).CountDocuments(context.Background(), bson.D{})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// ---------------------------------------------------------------- logs

// countingHandler counts log records (and keeps their messages).
type countingHandler struct {
	mu   sync.Mutex
	msgs []string
}

func (h *countingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *countingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.msgs = append(h.msgs, r.Level.String()+" "+r.Message)
	return nil
}

func (h *countingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *countingHandler) WithGroup(string) slog.Handler      { return h }

func (h *countingHandler) messages() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.msgs...)
}

// unusedPort returns a localhost TCP port with nothing listening.
func unusedPort(t testing.TB) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}
