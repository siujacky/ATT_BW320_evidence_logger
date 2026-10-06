package mongostore

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"attmonitor/internal/contracts"
	"attmonitor/internal/ledger"
	"attmonitor/internal/model"
)

// Live tests: ATTMON_MONGO=1, against the local MongoDB, each in its own throwaway database
// ("attmonitor_test_<random>", dropped at the end). They never touch the "attmonitor" database.

var bg = context.Background()

// liveSetup creates a populated ledger and a replicator for a fresh test database.
type liveEnv struct {
	uri, name string
	db        *mongo.Database
	clk       *testClock
	st        *ledger.Store
	dir       string
	f         fixture
	logs      *countingHandler
}

func newLiveEnv(t *testing.T) *liveEnv {
	t.Helper()
	uri, name, db := liveDB(t)
	clk := newClock()
	st, dir := newLedger(t, clk)
	f := populate(t, st, clk)
	return &liveEnv{uri: uri, name: name, db: db, clk: clk, st: st, dir: dir, f: f, logs: &countingHandler{}}
}

func (e *liveEnv) replicator(t *testing.T, mod ...func(*Options)) *Replicator {
	t.Helper()
	o := Options{URI: e.uri, Database: e.name, Reader: e.st, StoreBlobs: true, BatchSize: 7, Now: e.clk.Now, Logger: slog.New(e.logs)}
	for _, m := range mod {
		m(&o)
	}
	return newReplicator(t, o)
}

func mustSync(t *testing.T, r *Replicator) int {
	t.Helper()
	n, err := r.SyncOnce(bg)
	if err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
	return n
}

func mustVerify(t *testing.T, e *liveEnv, r contracts.LedgerReader, pub ed25519.PublicKey) VerifyResult {
	t.Helper()
	res, err := Verify(bg, e.uri, e.name, r, pub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return res
}

func requireVerifyOK(t *testing.T, res VerifyResult) {
	t.Helper()
	if !res.OK || res.Missing+res.Mismatched+res.BadHash+res.BlobsMissing+res.BlobsCorrupt != 0 || len(res.Problems) != 0 ||
		res.SyslogBad+res.SyslogPruned+res.SyslogForged+res.SyslogMissing != 0 {
		t.Fatalf("verification failed: %+v", res)
	}
}

func counters(r VerifyResult) [8]int {
	return [8]int{r.Records, r.Checked, r.Missing, r.Mismatched, r.BadHash, r.BlobsChecked, r.BlobsMissing, r.BlobsCorrupt}
}

func hasProblem(res VerifyResult, substr string) bool {
	return slices.ContainsFunc(res.Problems, func(p string) bool { return strings.Contains(p, substr) })
}

func firstRef(items []item, blob string) uint64 {
	for _, it := range items {
		if slices.Contains(it.body.Blobs, blob) {
			return it.body.Seq
		}
	}
	return math.MaxUint64
}

func TestLiveCopy(t *testing.T) {
	e := newLiveEnv(t)
	r := e.replicator(t)
	items := ledgerItems(t, e.st)
	if n := mustSync(t, r); n != len(items) {
		t.Fatalf("copied %d of %d records", n, len(items))
	}
	head := e.st.Head()
	st := r.Status()
	if !st.Enabled || !st.Connected || st.Database != e.name || st.URI != e.uri || !st.HasData || st.LastSeq != head.Seq ||
		st.Lag != 0 || st.Records != int64(len(items)) || st.Blobs != 3 || st.LastSync == "" || st.LastError != "" {
		t.Fatalf("status %+v (head %d, %d records)", st, head.Seq, len(items))
	}

	// Every record, field by field (exact h, s and b; data converted or kept as text).
	for _, it := range items {
		checkRecordDoc(t, findRaw(t, e.db, collRecords, int64(it.body.Seq)), it)
	}
	if n := count(t, e.db, collRecords); n != int64(len(items)) {
		t.Fatalf("%d documents for %d records", n, len(items))
	}
	for _, seq := range []uint64{e.f.dollarSeq, e.f.bigIntSeq} {
		doc := findRaw(t, e.db, collRecords, int64(seq))
		if b, _ := doc.Lookup("data_undecoded").BooleanOK(); !b {
			t.Errorf("seq %d: data that Extended JSON cannot hold was converted: %v", seq, doc.Lookup("data"))
		}
	}
	sampleDoc := findRaw(t, e.db, collRecords, int64(1))
	if got := sampleDoc.Lookup("data", "verdict", "reasons", "0").StringValue(); got != htmlReason {
		t.Errorf("reason = %q", got)
	}
	// Anyone can verify a MongoDB record on its own: h = SHA-256(b), s = signature of b.
	b, _ := rawString(sampleDoc, "b")
	h, _ := rawString(sampleDoc, "h")
	s, _ := rawString(sampleDoc, "s")
	sum := sha256.Sum256([]byte(b))
	sig, _ := base64.StdEncoding.DecodeString(s)
	if hex.EncodeToString(sum[:]) != h || !ed25519.Verify(e.st.PublicKey(), []byte(b), sig) {
		t.Error("a copied record does not verify on its own")
	}

	// Blobs: exact bytes (including a Latin-1 byte), size, first referencing record.
	for id, want := range map[string][]byte{e.f.pageBlob: []byte(pageBodyText), e.f.netshBlob: []byte("SSID : home\r\nSignal : 99%\r\n")} {
		doc := findRaw(t, e.db, collBlobs, id)
		if _, data, ok := doc.Lookup("data").BinaryOK(); !ok || string(data) != string(want) {
			t.Errorf("blob %s content differs", id)
		}
		if n, _ := doc.Lookup("size").Int64OK(); n != int64(len(want)) {
			t.Errorf("blob %s size %d", id, n)
		}
		if n, _ := doc.Lookup("first_seq").Int64OK(); uint64(n) != firstRef(items, id) {
			t.Errorf("blob %s first_seq %d, want %d", id, n, firstRef(items, id))
		}
	}
	if _, data, ok := findRaw(t, e.db, collBlobs, e.f.bigBlob).Lookup("data").BinaryOK(); !ok || sha256Hex(data) != e.f.bigBlob {
		t.Error("the 1 MiB blob was not stored exactly")
	}

	// Incidents: the newest payload by seq.
	inc := findRaw(t, e.db, collIncidents, incidentID1)
	if n, _ := inc.Lookup("seq").Int64OK(); uint64(n) != e.f.incidentClose1 {
		t.Errorf("incident 1 from seq %d, want %d", n, e.f.incidentClose1)
	}
	if typ, _ := rawString(inc, "type"); typ != model.TypeIncidentClose {
		t.Errorf("incident 1 type %q", typ)
	}
	if open, ok := inc.Lookup("incident", "open").BooleanOK(); !ok || open {
		t.Error("incident 1 still open")
	}
	if got := inc.Lookup("incident", "summary").StringValue(); got != "closed: fiber link down 3 min" {
		t.Errorf("incident 1 summary %q", got)
	}
	if n, _ := findRaw(t, e.db, collIncidents, incidentID2).Lookup("seq").Int64OK(); uint64(n) != e.f.incident2 {
		t.Errorf("incident 2 from seq %d", n)
	}

	// Replication state.
	meta := findRaw(t, e.db, collMeta, metaID)
	if n, _ := meta.Lookup("last_seq").Int64OK(); uint64(n) != head.Seq {
		t.Errorf("meta last_seq %d, want %d", n, head.Seq)
	}
	for key, want := range map[string]string{"last_hash": head.Hash, "fingerprint": e.st.Fingerprint(), "genesis_hash": items[0].env.H} {
		if got, _ := rawString(meta, key); got != want {
			t.Errorf("meta %s = %q, want %q", key, got, want)
		}
	}

	// Indexes.
	specs, err := e.db.Collection(collRecords).Indexes().ListSpecifications(bg)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range specs {
		names = append(names, s.Name)
	}
	if !slices.Contains(names, "type_1_ts_1") || !slices.Contains(names, "ts_1") {
		t.Errorf("indexes %v", names)
	}
	if msgs := e.logs.messages(); len(msgs) != 1 || !strings.Contains(msgs[0], "up to date") {
		t.Errorf("logs %q", msgs)
	}
	requireVerifyOK(t, mustVerify(t, e, e.st, e.st.PublicKey()))
}

// countingReader records the seqs each Scan starts from and the seqs read one by one. It has the
// ledger's Head method, so passes with a few new records read them by seq.
type countingReader struct {
	*ledger.Store
	mu      sync.Mutex
	froms   []uint64
	records []uint64
}

func (c *countingReader) Scan(from uint64, fn func(model.Envelope, model.Body) error) error {
	c.mu.Lock()
	c.froms = append(c.froms, from)
	c.mu.Unlock()
	return c.Store.Scan(from, fn)
}

func (c *countingReader) Record(seq uint64) (model.Envelope, model.Body, error) {
	c.mu.Lock()
	c.records = append(c.records, seq)
	c.mu.Unlock()
	return c.Store.Record(seq)
}

func (c *countingReader) scans() []uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]uint64(nil), c.froms...)
}

func (c *countingReader) recordReads() []uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]uint64(nil), c.records...)
}

// noHeadReader is a contracts.LedgerReader without Head: every pass scans.
type noHeadReader struct{ c *countingReader }

func (n noHeadReader) Scan(from uint64, fn func(model.Envelope, model.Body) error) error {
	return n.c.Scan(from, fn)
}
func (n noHeadReader) ScanTime(from, to time.Time, fn func(model.Envelope, model.Body) error) error {
	return n.c.ScanTime(from, to, fn)
}
func (n noHeadReader) Record(seq uint64) (model.Envelope, model.Body, error) { return n.c.Record(seq) }
func (n noHeadReader) Segments() ([]contracts.SegmentInfo, error)            { return n.c.Segments() }
func (n noHeadReader) OpenSegment(name string) (io.ReadCloser, error)        { return n.c.OpenSegment(name) }
func (n noHeadReader) GetBlob(id string) ([]byte, error)                     { return n.c.GetBlob(id) }

// seqRangeOf returns from..to.
func seqRangeOf(from, to uint64) []uint64 {
	var out []uint64
	for s := from; s <= to; s++ {
		out = append(out, s)
	}
	return out
}

func TestLiveIdempotentAndPartialBatch(t *testing.T) {
	e := newLiveEnv(t)
	items := ledgerItems(t, e.st)
	head := e.st.Head().Seq
	r := e.replicator(t)
	mustSync(t, r)
	if n := mustSync(t, r); n != 0 {
		t.Fatalf("second pass copied %d", n)
	}
	// A restart with nothing new: resumes from meta and copies nothing.
	cr := &countingReader{Store: e.st}
	restarted := e.replicator(t, func(o *Options) { o.Reader = cr })
	if n := mustSync(t, restarted); n != 0 {
		t.Fatalf("restart copied %d", n)
	}
	if got := cr.scans(); len(got) != 0 {
		t.Fatalf("a restart with nothing new scanned from %v", got)
	}
	if st := restarted.Status(); st.Records != int64(len(items)) || st.Blobs != 3 || st.LastSeq != head || !st.HasData || st.Lag != 0 {
		t.Fatalf("status after a restart with nothing new: %+v", st)
	}

	// A crash in the middle of a batch: meta names seq k, the documents of k+1 and k+2 were
	// inserted, the rest of the batch was not. Both ways of reading new records must cope.
	k := uint64(len(items) / 2)
	crash := func() {
		t.Helper()
		if _, err := e.db.Collection(collRecords).DeleteMany(bg, bson.D{{Key: "_id", Value: bson.D{{Key: "$gt", Value: int64(k + 2)}}}}); err != nil {
			t.Fatal(err)
		}
		if _, err := e.db.Collection(collMeta).UpdateOne(bg, bson.D{{Key: "_id", Value: metaID}},
			bson.D{{Key: "$set", Value: bson.D{{Key: "last_seq", Value: int64(k)}, {Key: "last_hash", Value: items[k].env.H}}}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, scan := range []bool{false, true} {
		crash()
		cr := &countingReader{Store: e.st}
		var reader contracts.LedgerReader = cr
		if scan {
			reader = noHeadReader{cr}
		}
		r2 := e.replicator(t, func(o *Options) { o.Reader = reader })
		n, err := r2.SyncOnce(bg)
		if err != nil {
			t.Fatalf("scan=%v: SyncOnce after a partial batch: %v", scan, err)
		}
		if want := len(items) - int(k+3); n != want {
			t.Fatalf("scan=%v: copied %d, want %d", scan, n, want)
		}
		if scan {
			if got := cr.scans(); !slices.Equal(got, []uint64{k + 1}) {
				t.Fatalf("scan path resumed from %v, want [%d]", got, k+1)
			}
		} else {
			// Genesis (identity), k (the resume point), then k+1..head one by one; no scan.
			if got, want := cr.recordReads(), append([]uint64{0, k}, seqRangeOf(k+1, head)...); len(cr.scans()) != 0 || !slices.Equal(got, want) {
				t.Fatalf("by-seq path: scans %v, records read %v, want %v", cr.scans(), got, want)
			}
		}
		if c := count(t, e.db, collRecords); c != int64(len(items)) {
			t.Fatalf("scan=%v: %d documents for %d records", scan, c, len(items))
		}
		if st := r2.Status(); st.LastError != "" || st.LastSeq != head || st.Lag != 0 {
			t.Fatalf("scan=%v: status %+v", scan, st)
		}
		requireVerifyOK(t, mustVerify(t, e, e.st, e.st.PublicKey()))
	}
}

func TestLiveRestartFromMeta(t *testing.T) {
	e := newLiveEnv(t)
	mustSync(t, e.replicator(t))
	appendSamples := func(n int) uint64 {
		t.Helper()
		for i := 0; i < n; i++ {
			e.clk.Advance(10 * time.Second)
			mustAppend(t, e.st, model.TypeSample, sample(uint64(1000+i), "after restart"))
		}
		return e.st.Head().Seq
	}
	// A few new records: read by seq after the restart.
	head1 := e.st.Head().Seq
	head2 := appendSamples(5)
	cr := &countingReader{Store: e.st}
	r := e.replicator(t, func(o *Options) { o.Reader = cr; o.BatchSize = 2 })
	if n := mustSync(t, r); n != 5 {
		t.Fatalf("copied %d, want 5", n)
	}
	if got, want := cr.recordReads(), append([]uint64{0, head1}, seqRangeOf(head1+1, head2)...); len(cr.scans()) != 0 || !slices.Equal(got, want) {
		t.Fatalf("scans %v, records read %v, want %v", cr.scans(), got, want)
	}
	if st := r.Status(); st.LastSeq != head2 || st.Lag != 0 || !st.HasData {
		t.Fatalf("status %+v", st)
	}
	// A long catch-up (as after MongoDB was down for a while): scanned from the resume point.
	head3 := appendSamples(bySeqMax + 6)
	cr2 := &countingReader{Store: e.st}
	r2 := e.replicator(t, func(o *Options) { o.Reader = cr2; o.BatchSize = 16 })
	if n := mustSync(t, r2); n != bySeqMax+6 {
		t.Fatalf("catch-up copied %d", n)
	}
	if got := cr2.scans(); !slices.Equal(got, []uint64{head2 + 1}) {
		t.Fatalf("catch-up scans from %v, want [%d]", got, head2+1)
	}
	if st := r2.Status(); st.LastSeq != head3 || st.Lag != 0 {
		t.Fatalf("status %+v", st)
	}
	requireVerifyOK(t, mustVerify(t, e, e.st, e.st.PublicKey()))
}

// gapReader hides one record from Record (as a damaged line would) but not from Scan.
type gapReader struct {
	*countingReader
	hidden uint64
}

func (g gapReader) Record(seq uint64) (model.Envelope, model.Body, error) {
	if seq == g.hidden {
		return model.Envelope{}, model.Body{}, contracts.ErrNotFound
	}
	return g.countingReader.Record(seq)
}

func TestLiveBySeqFallsBackToScan(t *testing.T) {
	e := newLiveEnv(t)
	r := e.replicator(t)
	mustSync(t, r)
	head1 := e.st.Head().Seq
	for i := 0; i < 3; i++ {
		e.clk.Advance(10 * time.Second)
		mustAppend(t, e.st, model.TypeSample, sample(uint64(2000+i), "new"))
	}
	cr := &countingReader{Store: e.st}
	r2 := e.replicator(t, func(o *Options) { o.Reader = gapReader{cr, head1 + 2} })
	if n := mustSync(t, r2); n != 3 {
		t.Fatalf("copied %d, want 3", n)
	}
	if got := cr.scans(); !slices.Equal(got, []uint64{head1 + 1}) {
		t.Fatalf("scans %v, want [%d]", got, head1+1)
	}
	requireVerifyOK(t, mustVerify(t, e, e.st, e.st.PublicKey()))
}

func TestLiveVerifyDetectsTampering(t *testing.T) {
	e := newLiveEnv(t)
	items := ledgerItems(t, e.st)
	mustSync(t, e.replicator(t))
	res := mustVerify(t, e, e.st, e.st.PublicKey())
	requireVerifyOK(t, res)
	if res.Records != len(items) || res.Checked != len(items) || res.BlobsChecked != 3 {
		t.Fatalf("clean verification %+v", res)
	}
	requireVerifyOK(t, mustVerify(t, e, e.st, nil))

	// Records appended after the last pass are not "missing".
	e.clk.Advance(10 * time.Second)
	mustAppend(t, e.st, model.TypeSample, sample(200, "not copied yet"))
	requireVerifyOK(t, mustVerify(t, e, e.st, e.st.PublicKey()))

	head := int64(items[len(items)-1].body.Seq)
	recs, blobs := e.db.Collection(collRecords), e.db.Collection(collBlobs)
	set := func(c *mongo.Collection, id any, field string, value any) {
		t.Helper()
		res, err := c.UpdateOne(bg, bson.D{{Key: "_id", Value: id}}, bson.D{{Key: "$set", Value: bson.D{{Key: field, Value: value}}}})
		if err != nil || res.MatchedCount != 1 {
			t.Fatalf("tamper %s %v: %v", field, id, err)
		}
	}
	const sA, sB, sC, sD = 2, 3, 4, 6 // samples
	// (a) b altered
	bA, _ := rawString(findRaw(t, e.db, collRecords, int64(sA)), "b")
	set(recs, int64(sA), "b", strings.Replace(bA, "ONLINE", "ISP_OUTAGE", 1))
	// (b) h altered
	set(recs, int64(sB), "h", sha256Hex([]byte("forged")))
	// (c) a record deleted
	if _, err := recs.DeleteOne(bg, bson.D{{Key: "_id", Value: int64(sC)}}); err != nil {
		t.Fatal(err)
	}
	// (d) a forged record after the head: consistent hash, no valid signature
	forgedB := fmt.Sprintf(`{"v":1,"seq":%d,"prev":"%s","ts":"2026-10-05T05:00:00Z","mono":1,"run":"x","type":"sample","data":{}}`, head+50, model.ZeroHash)
	if _, err := recs.InsertOne(bg, bson.D{{Key: "_id", Value: head + 50}, {Key: "h", Value: sha256Hex([]byte(forgedB))},
		{Key: "s", Value: base64.StdEncoding.EncodeToString(make([]byte, 64))}, {Key: "b", Value: forgedB}}); err != nil {
		t.Fatal(err)
	}
	// (e) a document whose _id is not a seq
	if _, err := recs.InsertOne(bg, bson.D{{Key: "_id", Value: "evil"}, {Key: "b", Value: "{}"}}); err != nil {
		t.Fatal(err)
	}
	// (f) a derived field altered (the signed fields untouched)
	set(recs, int64(sD), "data.verdict.state", model.StateISPOutage)
	// (g) a genuine record replayed under another seq
	replay := findRaw(t, e.db, collRecords, int64(5))
	replayDoc := withoutKey(replay, "_id")
	if _, err := recs.InsertOne(bg, append(bson.D{{Key: "_id", Value: head + 60}}, replayDoc...)); err != nil {
		t.Fatal(err)
	}
	// (h) blob content altered, (i) blob deleted
	set(blobs, e.f.pageBlob, "data", bson.Binary{Data: []byte("evil")})
	if _, err := blobs.DeleteOne(bg, bson.D{{Key: "_id", Value: e.f.bigBlob}}); err != nil {
		t.Fatal(err)
	}
	// (j) incident altered, (k) replication state altered
	set(e.db.Collection(collIncidents), incidentID1, "incident.attribution", model.AttrLocal)
	set(e.db.Collection(collMeta), metaID, "last_hash", sha256Hex([]byte("x")))

	res = mustVerify(t, e, e.st, e.st.PublicKey())
	ledgerNow := len(items) + 1
	want := VerifyResult{Records: len(items) - 1 + 3, Checked: len(items) - 1, Missing: 1, Mismatched: 6, BadHash: 3,
		BlobsChecked: 2, BlobsMissing: 1, BlobsCorrupt: 1}
	if counters(res) != counters(want) || res.OK {
		t.Errorf("verification %v\nwant         %v (records, checked, missing, mismatched, bad hash, blobs checked/missing/corrupt; ledger now %d records)\nproblems:\n%s",
			counters(res), counters(want), ledgerNow, strings.Join(res.Problems, "\n"))
	}
	for _, p := range []string{
		fmt.Sprintf("seq %d: b differ(s) from the ledger", sA),
		fmt.Sprintf("seq %d: h is not the SHA-256 of b", sA),
		fmt.Sprintf("seq %d: h differ(s)", sB),
		fmt.Sprintf("seq %d: missing from MongoDB", sC),
		fmt.Sprintf("seq %d: MongoDB holds a document that the ledger does not contain and that does not authenticate (s is not a valid signature", head+50),
		`_id "evil" is not a ledger seq`,
		fmt.Sprintf(`seq %d: field(s) "data" do not match the signed body b`, sD),
		fmt.Sprintf("seq %d: MongoDB holds a document that the ledger does not contain and that does not authenticate (its body b is not record %d)", head+60, head+60),
		"blob " + e.f.pageBlob + ": its content hashes to",
		"blob " + e.f.bigBlob + " (referenced by seq",
		`incident "` + incidentID1 + `": field(s) "incident" do not match`,
		"meta: last_hash",
	} {
		if !hasProblem(res, p) {
			t.Errorf("no problem %q in:\n%s", p, strings.Join(res.Problems, "\n"))
		}
	}
}

// substReader serves a ledger with one record replaced and one removed.
type substReader struct {
	*ledger.Store
	replaced item
	removed  uint64
}

func (s *substReader) Scan(from uint64, fn func(model.Envelope, model.Body) error) error {
	return s.Store.Scan(from, func(env model.Envelope, body model.Body) error {
		switch body.Seq {
		case s.removed:
			return nil
		case s.replaced.body.Seq:
			return fn(s.replaced.env, s.replaced.body)
		}
		return fn(env, body)
	})
}

func (s *substReader) Record(seq uint64) (model.Envelope, model.Body, error) {
	switch seq {
	case s.removed:
		return model.Envelope{}, model.Body{}, contracts.ErrNotFound
	case s.replaced.body.Seq:
		return s.replaced.env, s.replaced.body, nil
	}
	return s.Store.Record(seq)
}

// TestLiveVerifyShowsLedgerRewritten: the copy keeps the earlier version of records that the key
// holder later replaced in, or removed from, the ledger.
func TestLiveVerifyShowsLedgerRewritten(t *testing.T) {
	e := newLiveEnv(t)
	items := ledgerItems(t, e.st)
	mustSync(t, e.replicator(t))
	priv := ledgerKey(t, e.dir)
	orig := items[3].body
	orig.Data = dataOf(t, sample(2, "rewritten <after the copy>"))
	replaced := signedRecord(t, priv, orig)
	sr := &substReader{Store: e.st, replaced: replaced, removed: items[7].body.Seq}
	res := mustVerify(t, e, sr, e.st.PublicKey())
	if res.OK || res.Mismatched != 2 || res.BadHash != 0 || res.Missing != 0 {
		t.Fatalf("verification %+v", res)
	}
	if !hasProblem(res, fmt.Sprintf("seq %d: h, s, b differ(s) from the ledger; the MongoDB version is correctly signed by the ledger key: the ledger record was replaced", orig.Seq)) {
		t.Errorf("replacement not explained:\n%s", strings.Join(res.Problems, "\n"))
	}
	if !hasProblem(res, fmt.Sprintf("seq %d: MongoDB holds a record, correctly signed by the ledger key, that the ledger does not contain", items[7].body.Seq)) {
		t.Errorf("removal not explained:\n%s", strings.Join(res.Problems, "\n"))
	}
}

func TestLiveConflictNotOverwritten(t *testing.T) {
	e := newLiveEnv(t)
	mustSync(t, e.replicator(t))
	const x = 5
	forged := sha256Hex([]byte("another record"))
	if _, err := e.db.Collection(collRecords).UpdateOne(bg, bson.D{{Key: "_id", Value: int64(x)}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "h", Value: forged}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.Collection(collMeta).DeleteOne(bg, bson.D{{Key: "_id", Value: metaID}}); err != nil {
		t.Fatal(err)
	}
	r := e.replicator(t) // a new process: no meta, so the whole copy is checked
	n, err := r.SyncOnce(bg)
	if n != 0 || !errors.Is(err, ErrIntegrity) {
		t.Fatalf("SyncOnce = %d, %v", n, err)
	}
	if st := r.Status(); !strings.Contains(st.LastError, fmt.Sprintf("different record %d", x)) || !st.Connected {
		t.Fatalf("status %+v", st)
	}
	if h, _ := rawString(findRaw(t, e.db, collRecords, int64(x)), "h"); h != forged {
		t.Fatal("the conflicting document was overwritten")
	}
	if n, _ := findRaw(t, e.db, collMeta, metaID).Lookup("last_seq").Int64OK(); uint64(n) != e.st.Head().Seq {
		t.Errorf("meta last_seq %d after the check", n)
	}
	if msgs := e.logs.messages(); !slices.ContainsFunc(msgs, func(m string) bool { return strings.Contains(m, "integrity problem") }) {
		t.Errorf("conflict not logged: %q", msgs)
	}
	// Later passes keep reporting it until a full re-check finds the copy consistent again.
	mustSync(t, r)
	if st := r.Status(); !strings.Contains(st.LastError, "different record") {
		t.Errorf("integrity problem forgotten: %+v", st)
	}
	h := ledgerItems(t, e.st)[x].env.H
	if _, err := e.db.Collection(collRecords).UpdateOne(bg, bson.D{{Key: "_id", Value: int64(x)}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "h", Value: h}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.Collection(collMeta).DeleteOne(bg, bson.D{{Key: "_id", Value: metaID}}); err != nil {
		t.Fatal(err)
	}
	r2 := e.replicator(t)
	mustSync(t, r2)
	if st := r2.Status(); st.LastError != "" {
		t.Errorf("after repair: %+v", st)
	}
	requireVerifyOK(t, mustVerify(t, e, e.st, e.st.PublicKey()))
}

// TestLiveConflictAtTheTail: a forged document at the newest copied seq is reported, but neither
// the minute tail check nor a restart turn it into repeated re-checks of the whole copy.
func TestLiveConflictAtTheTail(t *testing.T) {
	e := newLiveEnv(t)
	cr := &countingReader{Store: e.st}
	r := e.replicator(t, func(o *Options) { o.Reader = cr })
	mustSync(t, r)
	head := e.st.Head().Seq
	forged := sha256Hex([]byte("forged tail"))
	if _, err := e.db.Collection(collRecords).UpdateOne(bg, bson.D{{Key: "_id", Value: int64(head)}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "h", Value: forged}}}}); err != nil {
		t.Fatal(err)
	}
	scansBefore := len(cr.scans())
	e.clk.Advance(2 * tailCheckEvery)
	if _, err := r.SyncOnce(bg); !errors.Is(err, ErrIntegrity) || !strings.Contains(err.Error(), fmt.Sprintf("different record %d", head)) {
		t.Fatalf("pass after the tail was forged: %v", err)
	}
	for i := 0; i < 3; i++ {
		e.clk.Advance(2 * tailCheckEvery)
		if _, err := r.SyncOnce(bg); err != nil {
			t.Fatalf("later pass %d: %v", i, err)
		}
	}
	if got := cr.scans(); len(got) != scansBefore {
		t.Fatalf("the forged tail caused scans %v", got[scansBefore:])
	}
	if st := r.Status(); !strings.Contains(st.LastError, fmt.Sprintf("different record %d", head)) {
		t.Errorf("status %+v", st)
	}
	// A restart reports it again without re-checking everything, and copies what is new.
	e.clk.Advance(10 * time.Second)
	mustAppend(t, e.st, model.TypeSample, sample(5000, "after the forged tail"))
	cr2 := &countingReader{Store: e.st}
	r2 := e.replicator(t, func(o *Options) { o.Reader = cr2 })
	n, err := r2.SyncOnce(bg)
	if n != 1 || !errors.Is(err, ErrIntegrity) {
		t.Fatalf("restart: %d, %v", n, err)
	}
	if got := cr2.scans(); len(got) != 0 {
		t.Fatalf("restart scanned from %v", got)
	}
	if h, _ := rawString(findRaw(t, e.db, collRecords, int64(head)), "h"); h != forged {
		t.Fatal("the forged tail was overwritten")
	}
	res := mustVerify(t, e, e.st, e.st.PublicKey())
	if res.Mismatched != 1 || res.BadHash != 1 || !hasProblem(res, fmt.Sprintf("seq %d: h differ(s)", head)) {
		t.Fatalf("verification %+v", res)
	}
}

func TestLiveForeignLedgerRefused(t *testing.T) {
	e := newLiveEnv(t)
	mustSync(t, e.replicator(t))
	before := count(t, e.db, collRecords)

	clk := newClock()
	other, _ := newLedger(t, clk) // another installation: another key and genesis
	mustAppend(t, other, model.TypeOperatorNote, model.OperatorNote{Text: "other", Source: "cli"})
	r := e.replicator(t, func(o *Options) { o.Reader = other })
	n, err := r.SyncOnce(bg)
	var re *refusedError
	if n != 0 || !errors.Is(err, ErrIntegrity) || !errors.As(err, &re) || !strings.Contains(err.Error(), "another ledger") {
		t.Fatalf("SyncOnce = %d, %v", n, err)
	}
	if st := r.Status(); !st.Connected || !strings.Contains(st.LastError, "another ledger") || st.HasData {
		t.Fatalf("status %+v", st)
	}
	// Without meta, the genesis record still identifies the copy.
	if _, err := e.db.Collection(collMeta).DeleteOne(bg, bson.D{{Key: "_id", Value: metaID}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.replicator(t, func(o *Options) { o.Reader = other }).SyncOnce(bg); !errors.As(err, &re) {
		t.Fatalf("without meta: %v", err)
	}
	if after := count(t, e.db, collRecords); after != before {
		t.Fatalf("the refused replicator wrote: %d -> %d documents", before, after)
	}
	// Only the fingerprint differs (a meta naming another key).
	clk2 := newClock()
	third, _ := newLedger(t, clk2)
	_, name2, db2 := liveDB(t)
	mustSync(t, newReplicator(t, Options{URI: e.uri, Database: name2, Reader: third}))
	if _, err := db2.Collection(collMeta).UpdateOne(bg, bson.D{{Key: "_id", Value: metaID}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "fingerprint", Value: sha256Hex([]byte("key"))}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := newReplicator(t, Options{URI: e.uri, Database: name2, Reader: third}).SyncOnce(bg); !errors.As(err, &re) || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("meta with another fingerprint: %v", err)
	}
}

func TestLiveDatabaseDroppedWhileConnected(t *testing.T) {
	e := newLiveEnv(t)
	items := ledgerItems(t, e.st)
	r := e.replicator(t)
	mustSync(t, r)
	if err := e.db.Drop(bg); err != nil {
		t.Fatal(err)
	}
	if n := mustSync(t, r); n != 0 {
		t.Fatalf("copied %d before the tail check was due", n)
	}
	e.clk.Advance(2 * tailCheckEvery)
	if n := mustSync(t, r); n != len(items) {
		t.Fatalf("after the drop: copied %d, want %d", n, len(items))
	}
	requireVerifyOK(t, mustVerify(t, e, e.st, e.st.PublicKey()))
}

func TestLiveForgedMetaIsReset(t *testing.T) {
	e := newLiveEnv(t)
	mustSync(t, e.replicator(t))
	if _, err := e.db.Collection(collMeta).UpdateOne(bg, bson.D{{Key: "_id", Value: metaID}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "last_seq", Value: int64(1_000_000_000)}}}}); err != nil {
		t.Fatal(err)
	}
	cr := &countingReader{Store: e.st}
	r := e.replicator(t, func(o *Options) { o.Reader = cr })
	n, err := r.SyncOnce(bg)
	if n != 0 || !errors.Is(err, ErrIntegrity) || !strings.Contains(err.Error(), "no record 1000000000") {
		t.Fatalf("SyncOnce = %d, %v", n, err)
	}
	if got := cr.scans(); len(got) != 1 || got[0] != 0 {
		t.Fatalf("scans %v, want a full re-check from 0", got)
	}
	meta := findRaw(t, e.db, collMeta, metaID)
	if ls, _ := meta.Lookup("last_seq").Int64OK(); uint64(ls) != e.st.Head().Seq {
		t.Errorf("meta last_seq %d", ls)
	}
	if prev, _ := meta.Lookup("previous", "last_seq").Int64OK(); prev != 1_000_000_000 {
		t.Errorf("previous meta not kept: %v", meta.Lookup("previous"))
	}
	if why, _ := rawString(meta, "reset_reason"); !strings.Contains(why, "no record 1000000000") {
		t.Errorf("reset_reason %q", why)
	}
	// The re-check found the copy consistent: the status is clean again.
	if st := r.Status(); st.LastError != "" || st.LastSeq != e.st.Head().Seq {
		t.Errorf("status %+v", st)
	}
	if n := mustSync(t, r); n != 0 {
		t.Errorf("next pass copied %d", n)
	}
}

func TestLiveStoreBlobsOff(t *testing.T) {
	e := newLiveEnv(t)
	mustSync(t, e.replicator(t, func(o *Options) { o.StoreBlobs = false }))
	for _, id := range []string{e.f.pageBlob, e.f.netshBlob, e.f.bigBlob} {
		doc := findRaw(t, e.db, collBlobs, id)
		if _, err := doc.LookupErr("data"); err == nil {
			t.Errorf("blob %s: content stored with StoreBlobs off", id)
		}
		if n, _ := doc.Lookup("size").Int64OK(); n <= 0 {
			t.Errorf("blob %s: size %d", id, n)
		}
	}
	res := mustVerify(t, e, e.st, e.st.PublicKey())
	requireVerifyOK(t, res)
	if res.BlobsChecked != 0 {
		t.Errorf("BlobsChecked %d", res.BlobsChecked)
	}
}

func TestLiveRunLoop(t *testing.T) {
	e := newLiveEnv(t)
	r := e.replicator(t, func(o *Options) { o.Interval = 20 * time.Millisecond; o.Now = time.Now })
	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	for i := uint64(300); i < 310; i++ {
		e.clk.Advance(10 * time.Second)
		mustAppend(t, e.st, model.TypeSample, sample(i, "while running"))
		_ = r.Status()
		time.Sleep(5 * time.Millisecond)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		st := r.Status()
		if st.LastSeq == e.st.Head().Seq && st.Lag == 0 && st.HasData {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Run did not catch up: %+v (head %d)", st, e.st.Head().Seq)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}
	// The final pass at shutdown (DESIGN §17): the monitor_stop record is copied after Run.
	mustAppend(t, e.st, model.TypeMonitorStop, model.MonitorStop{Reason: "service stop"})
	ctx5, cancel5 := context.WithTimeout(bg, 5*time.Second)
	defer cancel5()
	if n, err := r.SyncOnce(ctx5); err != nil || n != 1 {
		t.Fatalf("final SyncOnce = %d, %v", n, err)
	}
	requireVerifyOK(t, mustVerify(t, e, e.st, e.st.PublicKey()))
}

// panicReader panics while scanning.
type panicReader struct{ *ledger.Store }

func (panicReader) Scan(uint64, func(model.Envelope, model.Body) error) error { panic("reader bug") }

func TestLivePanicIsContained(t *testing.T) {
	e := newLiveEnv(t)
	r := e.replicator(t, func(o *Options) { o.Reader = panicReader{e.st} })
	_, err := r.SyncOnce(bg)
	if err == nil || !strings.Contains(err.Error(), "internal error") {
		t.Fatalf("SyncOnce: %v", err)
	}
	if st := r.Status(); !strings.Contains(st.LastError, "internal error") {
		t.Errorf("status %+v", st)
	}
}

func TestLiveVerifyEmptyDatabase(t *testing.T) {
	e := newLiveEnv(t)
	res := mustVerify(t, e, e.st, e.st.PublicKey())
	if res.OK || !hasProblem(res, "holds no copy") {
		t.Fatalf("empty database: %+v", res)
	}
}

func TestLiveProblemsCapped(t *testing.T) {
	e := newLiveEnv(t)
	mustSync(t, e.replicator(t))
	docs := make([]any, 0, 250)
	for i := 0; i < 250; i++ {
		docs = append(docs, bson.D{{Key: "_id", Value: fmt.Sprintf("forged-%03d", i)}})
	}
	if _, err := e.db.Collection(collRecords).InsertMany(bg, docs); err != nil {
		t.Fatal(err)
	}
	res := mustVerify(t, e, e.st, nil)
	if res.Mismatched != 250 || len(res.Problems) != maxProblems || !strings.Contains(res.Problems[maxProblems-1], "51 more problem(s)") {
		t.Fatalf("Mismatched %d, %d problems, last %q", res.Mismatched, len(res.Problems), res.Problems[len(res.Problems)-1])
	}
}

func TestLiveRejectedDataStoredAsJSON(t *testing.T) {
	// A server-side validator that rejects documents whose data.text is a string stands in for any
	// content MongoDB refuses: the record is then stored with its data as JSON text.
	e := newLiveEnv(t)
	validator := bson.D{{Key: "$jsonSchema", Value: bson.D{{Key: "properties", Value: bson.D{
		{Key: "data", Value: bson.D{{Key: "properties", Value: bson.D{{Key: "text", Value: bson.D{{Key: "bsonType", Value: "int"}}}}}}},
	}}}}}
	if err := e.db.CreateCollection(bg, collRecords, optionsValidator(validator)); err != nil {
		t.Fatal(err)
	}
	r := e.replicator(t)
	items := ledgerItems(t, e.st)
	if n := mustSync(t, r); n != len(items) {
		t.Fatalf("copied %d of %d", n, len(items))
	}
	var noteSeq uint64
	for _, it := range items {
		if it.body.Type == model.TypeOperatorNote {
			noteSeq = it.body.Seq
		}
	}
	doc := findRaw(t, e.db, collRecords, int64(noteSeq))
	if note, _ := rawString(doc, "data_note"); note != noteServerRejected {
		t.Fatalf("operator note stored as %v", doc)
	}
	requireVerifyOK(t, mustVerify(t, e, e.st, e.st.PublicKey()))
}

func optionsValidator(v any) *options.CreateCollectionOptionsBuilder {
	return options.CreateCollection().SetValidator(v)
}
