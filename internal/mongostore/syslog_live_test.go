package mongostore

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"attmonitor/internal/model"
)

// Live tests (ATTMON_MONGO=1) of the syslog collection: the messages of the syslog store's chunks
// copied in ledger order, deleted with their chunks, and checked by Verify.

// syslogEnv is a live environment with a syslog store whose chunks the ledger records.
type syslogEnv struct {
	*liveEnv
	store *memSyslog
}

func newSyslogEnv(t *testing.T) *syslogEnv {
	t.Helper()
	return &syslogEnv{liveEnv: newLiveEnv(t), store: newMemSyslog()}
}

// sealed is a chunk of the syslog store and its syslog_chunk record.
type sealed struct {
	c     model.SyslogChunk
	seq   uint64
	lines [][]byte
}

// seal stores a chunk of lines in the syslog store and appends its syslog_chunk record, as the
// monitor does when the store seals a chunk.
func (e *syslogEnv) seal(t *testing.T, name string, lines ...[]byte) sealed {
	t.Helper()
	e.clk.Advance(10 * time.Second)
	c, gz := chunkOf(t, name, lines...)
	e.store.put(name, gz)
	return sealed{c: c, seq: mustAppend(t, e.st, model.TypeSyslogChunk, c).Seq, lines: lines}
}

// sealMessages seals a chunk of n firewall messages.
func (e *syslogEnv) sealMessages(t *testing.T, name string, n int) sealed {
	t.Helper()
	return e.seal(t, name, msgLines(t, e.clk.Now(), n, "[FW] DROP "+name)...)
}

// prune deletes chunks from the syslog store and appends the syslog_prune record that says so.
func (e *syslogEnv) prune(t *testing.T, cs ...sealed) uint64 {
	t.Helper()
	for _, s := range cs {
		e.store.remove(s.c.Name)
	}
	return e.pruneRecord(t, cs...)
}

// pruneRecord appends a syslog_prune record of chunks (the store's deletion is up to the caller).
func (e *syslogEnv) pruneRecord(t *testing.T, cs ...sealed) uint64 {
	t.Helper()
	e.clk.Advance(10 * time.Second)
	p := model.SyslogPrune{Reason: "keep_mb 1", KeepMB: 1}
	for _, s := range cs {
		p.Deleted = append(p.Deleted, model.SyslogChunkRef{Name: s.c.Name, SHA256: s.c.SHA256, From: s.c.From, To: s.c.To, Messages: s.c.Messages, GzBytes: s.c.GzBytes})
	}
	return mustAppend(t, e.st, model.TypeSyslogPrune, p).Seq
}

func (e *syslogEnv) replicator(t *testing.T, mod ...func(*Options)) *Replicator {
	t.Helper()
	return e.liveEnv.replicator(t, append([]func(*Options){func(o *Options) { o.Syslog = e.store }}, mod...)...)
}

// verify runs VerifyWith, with the syslog store when withStore is set.
func (e *syslogEnv) verify(t *testing.T, withStore bool) VerifyResult {
	t.Helper()
	o := VerifyOptions{URI: e.uri, Database: e.name, Reader: e.st, PublicKey: e.st.PublicKey()}
	if withStore {
		o.Syslog = e.store
	}
	res, err := VerifyWith(bg, o)
	if err != nil {
		t.Fatalf("VerifyWith: %v", err)
	}
	return res
}

// syslogCounters returns the syslog counters of a verification: documents, chunks checked, bad
// chunks, documents of pruned chunks, forged documents, missing chunks.
func syslogCounters(r VerifyResult) [6]int {
	return [6]int{r.SyslogDocs, r.SyslogChunks, r.SyslogBad, r.SyslogPruned, r.SyslogForged, r.SyslogMissing}
}

// syslogDump returns every document of the syslog collection by _id.
func syslogDump(t *testing.T, db *mongo.Database) map[string]bson.Raw {
	t.Helper()
	cur, err := db.Collection(collSyslog).Find(bg, bson.D{})
	if err != nil {
		t.Fatal(err)
	}
	defer cur.Close(bg)
	out := map[string]bson.Raw{}
	for cur.Next(bg) {
		out[docIDText(cur.Current)] = append(bson.Raw(nil), cur.Current...)
	}
	if err := cur.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func chunkCount(t *testing.T, db *mongo.Database, name string) int64 {
	t.Helper()
	n, err := db.Collection(collSyslog).CountDocuments(bg, bson.D{{Key: "chunk", Value: name}})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// requireChunkDocs checks that MongoDB holds exactly the documents of chunk s, one per line, as
// the replicator writes them.
func requireChunkDocs(t *testing.T, e *syslogEnv, s sealed) {
	t.Helper()
	if n := chunkCount(t, e.db, s.c.Name); n != int64(len(s.lines)) {
		t.Fatalf("chunk %s: %d documents for %d lines", s.c.Name, n, len(s.lines))
	}
	for i, line := range s.lines {
		want, err := syslogDoc(s.c.Name, s.seq, int64(i+1), line)
		if err != nil {
			t.Fatal(err)
		}
		if got := findRaw(t, e.db, collSyslog, syslogID(s.c.Name, int64(i+1))); !bytes.Equal(got, want) {
			t.Fatalf("chunk %s line %d: %v, want %v", s.c.Name, i+1, got, bson.Raw(want))
		}
	}
}

// syslogMeta returns syslog_seq and syslog_collection of the replication state.
func syslogMeta(t *testing.T, e *syslogEnv) (int64, string) {
	t.Helper()
	meta := findRaw(t, e.db, collMeta, metaID)
	seq, ok := rawInt64(meta, "syslog_seq")
	if !ok {
		t.Fatalf("meta has no syslog_seq: %v", meta)
	}
	coll, _ := rawString(meta, "syslog_collection")
	return seq, coll
}

func indexNames(t *testing.T, db *mongo.Database, coll string) []string {
	t.Helper()
	specs, err := db.Collection(coll).Indexes().ListSpecifications(bg)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range specs {
		names = append(names, s.Name)
	}
	return names
}

func deleteMeta(t *testing.T, e *syslogEnv) {
	t.Helper()
	if _, err := e.db.Collection(collMeta).DeleteOne(bg, bson.D{{Key: "_id", Value: metaID}}); err != nil {
		t.Fatal(err)
	}
}

// TestLiveSyslogCopy: every line of a sealed chunk becomes a document with its exact line and the
// fields of its message; copying is idempotent, a restart reads no chunk again, and deleting the
// replication state applies every syslog record again without a problem.
func TestLiveSyslogCopy(t *testing.T) {
	e := newSyslogEnv(t)
	t0 := e.clk.Now()
	odd := []byte("not a message: kept as raw_line only")
	html := mustJSON(t, syslogMsg(t0, `<b>"quoted"</b> & é 😀 `+"\x1b[2K")) // HTML-escaped JSON
	a := e.seal(t, "syslog-20261005T032001Z-a.jsonl.gz", append(msgLines(t, t0, 3, "[FW] DROP"), odd, html)...)
	b := e.sealMessages(t, "syslog-20261005T032501Z-b.jsonl.gz", 2)
	r := e.replicator(t)
	items := ledgerItems(t, e.st)
	if n := mustSync(t, r); n != len(items) {
		t.Fatalf("copied %d of %d records", n, len(items))
	}
	requireChunkDocs(t, e, a)
	requireChunkDocs(t, e, b)
	if n := count(t, e.db, collSyslog); n != 7 {
		t.Fatalf("%d syslog documents, want 7", n)
	}
	doc := findRaw(t, e.db, collSyslog, syslogID(a.c.Name, 1))
	if line, _ := rawString(doc, "raw_line"); !strings.Contains(line, `"msg":"[FW] DROP 0"`) {
		t.Errorf("raw_line %q", line)
	}
	if _, err := doc.LookupErr("msg"); err == nil {
		t.Error("the message's text is stored a second time (msg)")
	}
	if ms, ok := doc.Lookup("rx").DateTimeOK(); !ok || ms != t0.UnixMilli() {
		t.Errorf("rx %v", doc.Lookup("rx"))
	}
	if b, _ := findRaw(t, e.db, collSyslog, syslogID(a.c.Name, 4)).Lookup("undecoded").BooleanOK(); !b {
		t.Error("the line that is not a message is not marked undecoded")
	}
	if names := indexNames(t, e.db, collSyslog); !slices.Contains(names, "rx_-1") || !slices.Contains(names, "chunk_1") {
		t.Errorf("indexes of syslog: %v", names)
	}
	seq, coll := syslogMeta(t, e)
	if seq != int64(e.st.Head().Seq) || len(coll) != 32 {
		t.Errorf("meta syslog_seq %d, syslog_collection %q (head %d)", seq, coll, e.st.Head().Seq)
	}
	if st := r.Status(); st.LastError != "" || r.SyslogDocuments() != 7 {
		t.Fatalf("status %+v, %d syslog documents", st, r.SyslogDocuments())
	}
	for _, withStore := range []bool{false, true} {
		res := e.verify(t, withStore)
		requireVerifyOK(t, res)
		if got := syslogCounters(res); got != [6]int{7, 2, 0, 0, 0, 0} {
			t.Errorf("withStore=%v: syslog counters %v", withStore, got)
		}
	}

	// Idempotent: another pass, and a restart, read no chunk again.
	opens := e.store.openCount()
	if opens != 2 {
		t.Fatalf("%d chunk reads, want 2", opens)
	}
	mustSync(t, r)
	mustSync(t, e.replicator(t))
	if n := e.store.openCount(); n != opens {
		t.Fatalf("%d chunk reads after another pass and a restart, want %d", n, opens)
	}
	// Without the replication state every syslog record is applied again: the same documents.
	before := syslogDump(t, e.db)
	deleteMeta(t, e)
	r3 := e.replicator(t)
	mustSync(t, r3)
	if n := e.store.openCount(); n != opens+2 {
		t.Fatalf("%d chunk reads after the replication state was deleted, want %d", n, opens+2)
	}
	after := syslogDump(t, e.db)
	if len(after) != len(before) {
		t.Fatalf("%d documents, %d before", len(after), len(before))
	}
	for id, d := range before {
		if !bytes.Equal(after[id], d) {
			t.Errorf("document %s changed", id)
		}
	}
	if st := r3.Status(); st.LastError != "" {
		t.Fatalf("status %+v", st)
	}
	requireVerifyOK(t, e.verify(t, true))
}

// TestLiveSyslogPrune: a syslog_prune record deletes the documents of its chunks, also of a chunk
// that is sealed and pruned before the replicator gets to them (stored, then deleted, in order).
func TestLiveSyslogPrune(t *testing.T) {
	e := newSyslogEnv(t)
	a := e.sealMessages(t, "a", 3)
	b := e.sealMessages(t, "b", 2)
	cr := &countingReader{Store: e.st}
	r := e.replicator(t, func(o *Options) { o.Reader = cr })
	mustSync(t, r)
	scans := len(cr.scans())
	e.prune(t, a)
	mustSync(t, r)
	if n := chunkCount(t, e.db, a.c.Name); n != 0 {
		t.Fatalf("%d documents of the pruned chunk", n)
	}
	requireChunkDocs(t, e, b)
	// Sealed and pruned between two passes, the store still holding the chunk when the copy reads
	// it: its documents are stored and then deleted.
	c := e.sealMessages(t, "c", 4)
	e.pruneRecord(t, c)
	mustSync(t, r)
	if n := chunkCount(t, e.db, c.c.Name); n != 0 {
		t.Fatalf("%d documents of a chunk pruned in the same pass", n)
	}
	if n := e.store.opensOf(c.c.Name); n != 1 {
		t.Fatalf("chunk c read %d times", n)
	}
	// The steady state: the syslog records come with the records copied, the ledger is not scanned.
	if got := cr.scans()[scans:]; len(got) != 0 {
		t.Fatalf("passes with a few new records scanned the ledger from %v", got)
	}
	if seq, _ := syslogMeta(t, e); seq != int64(e.st.Head().Seq) {
		t.Fatalf("meta syslog_seq %d, head %d", seq, e.st.Head().Seq)
	}
	if st := r.Status(); st.LastError != "" {
		t.Fatalf("status %+v", st)
	}
	res := e.verify(t, true)
	requireVerifyOK(t, res)
	if got := syslogCounters(res); got != [6]int{2, 1, 0, 0, 0, 0} {
		t.Errorf("syslog counters %v", got)
	}
}

// TestLiveSyslogChunkPrunedBeforeCopy: a chunk that the store deleted before the copy got to it is
// skipped and logged, not reported as a problem.
func TestLiveSyslogChunkPrunedBeforeCopy(t *testing.T) {
	e := newSyslogEnv(t)
	a := e.sealMessages(t, "a", 3)
	b := e.sealMessages(t, "b", 2)
	e.store.remove(a.c.Name) // the retention limit, before the copy (its syslog_prune record follows)
	r := e.replicator(t)
	if _, err := r.SyncOnce(bg); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
	if n := chunkCount(t, e.db, a.c.Name); n != 0 {
		t.Fatalf("%d documents of a chunk the store does not hold", n)
	}
	requireChunkDocs(t, e, b)
	if st := r.Status(); st.LastError != "" {
		t.Fatalf("status %+v", st)
	}
	if !loggedContaining(e.liveEnv, "no longer in the syslog store") {
		t.Errorf("not logged: %q", e.logs.messages())
	}
	if seq, _ := syslogMeta(t, e); seq != int64(e.st.Head().Seq) {
		t.Fatalf("meta syslog_seq %d, head %d", seq, e.st.Head().Seq)
	}
	requireVerifyOK(t, e.verify(t, true)) // the store does not hold it: not missing
	e.pruneRecord(t, a)
	mustSync(t, r)
	requireVerifyOK(t, e.verify(t, true))
}

// TestLiveSyslogVerifyDetectsTampering: a line altered with its derived fields, a line deleted, a
// document of no chunk, documents of a pruned chunk put back, a derived field altered, and a chunk
// whose documents were all deleted (found with the store).
func TestLiveSyslogVerifyDetectsTampering(t *testing.T) {
	e := newSyslogEnv(t)
	a := e.sealMessages(t, "a", 3)
	b := e.sealMessages(t, "b", 3)
	c := e.sealMessages(t, "c", 2)
	d := e.sealMessages(t, "d", 2)
	p := e.sealMessages(t, "p", 2)
	r := e.replicator(t)
	mustSync(t, r)
	var pDocs []any
	for i := range p.lines {
		pDocs = append(pDocs, findRaw(t, e.db, collSyslog, syslogID(p.c.Name, int64(i+1))))
	}
	pruneSeq := e.prune(t, p)
	mustSync(t, r)
	requireVerifyOK(t, e.verify(t, true))

	syslog := e.db.Collection(collSyslog)
	// (1) A line altered, its derived fields made to match.
	altered := bytes.ReplaceAll(a.lines[1], []byte("DROP a 1"), []byte("DROP a X"))
	forgedLine, err := syslogDoc(a.c.Name, a.seq, 2, altered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := syslog.ReplaceOne(bg, bson.D{{Key: "_id", Value: syslogID(a.c.Name, 2)}}, forgedLine); err != nil {
		t.Fatal(err)
	}
	// (2) A line deleted.
	if _, err := syslog.DeleteOne(bg, bson.D{{Key: "_id", Value: syslogID(b.c.Name, 3)}}); err != nil {
		t.Fatal(err)
	}
	// (3) A document of a chunk that no record names.
	forged, err := syslogDoc("forged-chunk", a.seq, 1, a.lines[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := syslog.InsertOne(bg, forged); err != nil {
		t.Fatal(err)
	}
	// (4) The documents of the pruned chunk put back.
	if _, err := syslog.InsertMany(bg, pDocs); err != nil {
		t.Fatal(err)
	}
	// (5) A derived field altered.
	setField(t, syslog, syslogID(c.c.Name, 1), "msg", "AT&T was not at fault")
	// (6) Every document of a chunk deleted.
	if _, err := syslog.DeleteMany(bg, bson.D{{Key: "chunk", Value: d.c.Name}}); err != nil {
		t.Fatal(err)
	}

	want := []string{
		fmt.Sprintf(`syslog chunk "a" (ledger record %d): its lines do not hash to the SHA-256 of its record (a line was altered)`, a.seq),
		fmt.Sprintf(`syslog chunk "b" (ledger record %d): 1 line(s) missing (3)`, b.seq),
		`syslog chunk "forged-chunk": 1 document(s), e.g. "forged-chunk#1", but no syslog_chunk record names this chunk (forged or foreign)`,
		fmt.Sprintf(`syslog chunk "p" (ledger record %d): 2 document(s) remain, although syslog_prune record %d deleted the chunk`, p.seq, pruneSeq),
		fmt.Sprintf(`syslog chunk "c" (ledger record %d): 1 document(s) do not match their line ("c#1": field(s) "msg")`, c.seq),
	}
	res := e.verify(t, false)
	if got := syslogCounters(res); res.OK || got != [6]int{10, 3, 3, 2, 1, 0} {
		t.Errorf("without the store: counters %v (docs, chunks, bad, pruned, forged, missing)\n%s", got, strings.Join(res.Problems, "\n"))
	}
	for _, w := range want {
		if !hasProblem(res, w) {
			t.Errorf("no problem %q in:\n%s", w, strings.Join(res.Problems, "\n"))
		}
	}
	if hasProblem(res, "differ from the syslog store") || hasProblem(res, `syslog chunk "d"`) {
		t.Errorf("the store was used:\n%s", strings.Join(res.Problems, "\n"))
	}
	res = e.verify(t, true)
	if got := syslogCounters(res); res.OK || got != [6]int{10, 3, 3, 2, 1, 1} {
		t.Errorf("with the store: counters %v\n%s", got, strings.Join(res.Problems, "\n"))
	}
	for _, w := range append(want,
		fmt.Sprintf(`syslog chunk "a" (ledger record %d): its lines do not hash to the SHA-256 of its record (a line was altered); line(s) 2 differ from the syslog store`, a.seq),
		fmt.Sprintf(`syslog chunk "d" (ledger record %d, 2 message(s)): missing from MongoDB, although the syslog store still holds it`, d.seq),
	) {
		if !hasProblem(res, w) {
			t.Errorf("no problem %q in:\n%s", w, strings.Join(res.Problems, "\n"))
		}
	}
	for _, problem := range res.Problems {
		requirePrintable(t, "problem", problem)
	}
}

// TestLiveSyslogUnreadableChunkWaits: a chunk that cannot be read for a while holds back the later
// syslog records (strict ledger order) but never the records; it is copied once it can be read,
// also after a restart, and given up (reported) after ten minutes.
func TestLiveSyslogUnreadableChunkWaits(t *testing.T) {
	e := newSyslogEnv(t)
	a := e.sealMessages(t, "a", 2)
	b := e.sealMessages(t, "b", 2)
	e.store.setFail(a.c.Name, errSharingViolation)
	r := e.replicator(t)
	n, err := r.SyncOnce(bg)
	if err != nil || n != len(ledgerItems(t, e.st)) {
		t.Fatalf("SyncOnce = %d, %v", n, err)
	}
	if c := count(t, e.db, collSyslog); c != 0 {
		t.Fatalf("%d syslog documents while chunk a cannot be read (b must wait)", c)
	}
	st := r.Status()
	if st.LastSeq != e.st.Head().Seq || !strings.Contains(st.LastError, `syslog chunk "a"`) ||
		!strings.Contains(st.LastError, "cannot be read from the syslog store") || !strings.Contains(st.LastError, "being used by another process") {
		t.Fatalf("status %+v", st)
	}
	if seq, _ := syslogMeta(t, e); seq != int64(a.seq)-1 {
		t.Fatalf("meta syslog_seq %d, want %d", seq, a.seq-1)
	}
	if !loggedContaining(e.liveEnv, "MongoDB copy of syslog messages waits") {
		t.Errorf("not logged: %q", e.logs.messages())
	}
	// The records are copied meanwhile.
	appendSample(t, e.liveEnv, 500)
	mustSync(t, r)
	if st := r.Status(); st.LastSeq != e.st.Head().Seq || st.Lag != 0 {
		t.Fatalf("status %+v", st)
	}
	// A restart: the syslog records are read again from the ledger, from the first not applied.
	e.store.setFail(a.c.Name, nil)
	cr := &countingReader{Store: e.st}
	r2 := e.replicator(t, func(o *Options) { o.Reader = cr })
	if n := mustSync(t, r2); n != 0 {
		t.Fatalf("restart copied %d records", n)
	}
	if got := cr.scans(); !slices.Equal(got, []uint64{a.seq}) {
		t.Fatalf("scans %v, want [%d]", got, a.seq)
	}
	requireChunkDocs(t, e, a)
	requireChunkDocs(t, e, b)
	if st := r2.Status(); st.LastError != "" {
		t.Fatalf("status %+v", st)
	}

	// Given up after ten minutes; the later chunks go on.
	c := e.sealMessages(t, "c", 2)
	d := e.sealMessages(t, "d", 2)
	e.store.setFail(c.c.Name, errSharingViolation)
	if _, err := r2.SyncOnce(bg); err != nil {
		t.Fatalf("SyncOnce while c cannot be read: %v", err)
	}
	if n := chunkCount(t, e.db, d.c.Name); n != 0 {
		t.Fatalf("d copied before c: %d documents", n)
	}
	e.clk.Advance(syslogGiveUp + time.Minute)
	_, err = r2.SyncOnce(bg)
	if !errors.Is(err, ErrIntegrity) || !strings.Contains(err.Error(), `syslog chunk "c"`) || !strings.Contains(err.Error(), "could not be read from the syslog store for 11m") {
		t.Fatalf("SyncOnce after ten minutes: %v", err)
	}
	if n := chunkCount(t, e.db, c.c.Name); n != 0 {
		t.Fatalf("%d documents of c", n)
	}
	requireChunkDocs(t, e, d)
	if st := r2.Status(); !strings.Contains(st.LastError, `syslog chunk "c"`) || strings.Contains(st.LastError, "cannot be read from the syslog store (") {
		t.Fatalf("status %+v", st)
	}
	if !loggedContaining(e.liveEnv, "MongoDB copy of syslog messages goes on") {
		t.Errorf("not logged: %q", e.logs.messages())
	}
	e.store.setFail(c.c.Name, nil)
	res := e.verify(t, true)
	if res.OK || res.SyslogMissing != 1 || !hasProblem(res, fmt.Sprintf(`syslog chunk "c" (ledger record %d, 2 message(s)): missing from MongoDB`, c.seq)) {
		t.Fatalf("verification %+v", res)
	}
}

// TestLiveSyslogChunkNotMatchingItsRecord: a chunk that the store holds otherwise than its record
// says (altered, or a damaged file) is reported and not copied; the records and the later chunks
// are copied all the same.
func TestLiveSyslogChunkNotMatchingItsRecord(t *testing.T) {
	e := newSyslogEnv(t)
	a := e.sealMessages(t, "a", 3)
	b := e.sealMessages(t, "b", 2)
	var content []byte
	for _, l := range a.lines {
		content = append(append(content, l...), '\n')
	}
	e.store.put(a.c.Name, gzipBytes(t, bytes.Replace(content, []byte("DROP a 1"), []byte("DROP a X"), 1)))
	e.store.put(b.c.Name, e.store.get(b.c.Name)[:20])
	r := e.replicator(t)
	n, err := r.SyncOnce(bg)
	if n != len(ledgerItems(t, e.st)) || !errors.Is(err, ErrIntegrity) || !strings.Contains(err.Error(), "2 problem(s)") {
		t.Fatalf("SyncOnce = %d, %v", n, err)
	}
	if c := count(t, e.db, collSyslog); c != 0 {
		t.Fatalf("%d syslog documents", c)
	}
	st := r.Status()
	if st.LastSeq != e.st.Head().Seq || !strings.Contains(st.LastError, fmt.Sprintf(`syslog chunk "b" (ledger record %d) was not copied: its file is not a complete gzip stream`, b.seq)) {
		t.Fatalf("status %+v", st)
	}
	if !loggedContaining(e.liveEnv, "MongoDB copy of syslog messages: problem") {
		t.Errorf("not logged: %q", e.logs.messages())
	}
	c := e.sealMessages(t, "c", 1)
	mustSync(t, r)
	requireChunkDocs(t, e, c)
	res := e.verify(t, true)
	if res.OK || res.SyslogMissing != 2 ||
		!hasProblem(res, fmt.Sprintf(`syslog chunk "a" (ledger record %d): missing from MongoDB; the syslog store holds it, but its SHA-256 is`, a.seq)) ||
		!hasProblem(res, fmt.Sprintf(`syslog chunk "b" (ledger record %d): missing from MongoDB; the syslog store holds it, but its file is not a complete gzip stream`, b.seq)) {
		t.Fatalf("verification %+v", res)
	}
	if st := r.Status(); !strings.Contains(st.LastError, "was not copied") {
		t.Fatalf("the problem was forgotten: %+v", st)
	}
	// The store's chunks repaired and the replication state deleted: the running replicator applies
	// every syslog record again, finds no problem, and the status is clean again.
	for _, s := range []sealed{a, b} {
		_, gz := chunkOf(t, s.c.Name, s.lines...)
		e.store.put(s.c.Name, gz)
	}
	deleteMeta(t, e)
	e.clk.Advance(2 * tailCheckEvery)
	mustSync(t, r)
	for _, s := range []sealed{a, b, c} {
		requireChunkDocs(t, e, s)
	}
	if st := r.Status(); st.LastError != "" {
		t.Fatalf("status after the repair %+v", st)
	}
	requireVerifyOK(t, e.verify(t, true))
}

// TestLiveSyslogInvalidStateIsReset: a replication state whose syslog_seq is beyond the copied
// records makes a restart apply every syslog record again (restoring documents deleted meanwhile).
func TestLiveSyslogInvalidStateIsReset(t *testing.T) {
	e := newSyslogEnv(t)
	a := e.sealMessages(t, "a", 3)
	mustSync(t, e.replicator(t))
	if _, err := e.db.Collection(collSyslog).DeleteOne(bg, bson.D{{Key: "_id", Value: syslogID(a.c.Name, 2)}}); err != nil {
		t.Fatal(err)
	}
	setField(t, e.db.Collection(collMeta), metaID, "syslog_seq", int64(1_000_000))
	if res := e.verify(t, false); res.OK || !hasProblem(res, "meta: syslog_seq 1000000 is beyond the newest copied record") {
		t.Fatalf("verification %+v", res)
	}
	r := e.replicator(t)
	mustSync(t, r)
	requireChunkDocs(t, e, a)
	if seq, _ := syslogMeta(t, e); seq != int64(e.st.Head().Seq) {
		t.Fatalf("meta syslog_seq %d, head %d", seq, e.st.Head().Seq)
	}
	if !loggedContaining(e.liveEnv, "invalid syslog_seq") {
		t.Errorf("not logged: %q", e.logs.messages())
	}
	requireVerifyOK(t, e.verify(t, true))
}

// TestLiveSyslogConflictNotOverwritten: a document that MongoDB holds otherwise, and a document of
// the chunk that is no line of it, are reported and left alone when the chunk is copied again.
func TestLiveSyslogConflictNotOverwritten(t *testing.T) {
	e := newSyslogEnv(t)
	a := e.sealMessages(t, "a", 3)
	mustSync(t, e.replicator(t))
	syslog := e.db.Collection(collSyslog)
	setField(t, syslog, syslogID(a.c.Name, 2), "msg", "AT&T was not at fault")
	extra, err := syslogDoc(a.c.Name, a.seq, 99, a.lines[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := syslog.InsertOne(bg, extra); err != nil {
		t.Fatal(err)
	}
	deleteMeta(t, e) // a restart then applies every syslog record again
	r := e.replicator(t)
	_, err = r.SyncOnce(bg)
	if !errors.Is(err, ErrIntegrity) || !strings.Contains(err.Error(), "2 problem(s)") {
		t.Fatalf("SyncOnce: %v", err)
	}
	if !loggedContaining(e.liveEnv, "MongoDB copy of syslog messages: problem") {
		t.Errorf("not logged: %q", e.logs.messages())
	}
	if st := r.Status(); !strings.Contains(st.LastError, `MongoDB holds 1 document(s) of syslog chunk "a"`) || !strings.Contains(st.LastError, `"a#99"`) {
		t.Fatalf("status %+v", st)
	}
	if msg, _ := rawString(findRaw(t, e.db, collSyslog, syslogID(a.c.Name, 2)), "msg"); msg != "AT&T was not at fault" {
		t.Fatal("the conflicting document was overwritten")
	}
	if n := chunkCount(t, e.db, a.c.Name); n != 4 {
		t.Fatalf("%d documents of chunk a", n)
	}
	res := e.verify(t, true)
	if res.OK || res.SyslogBad != 1 || !hasProblem(res, `1 document(s) do not match their line ("a#2": field(s) "msg")`) ||
		!hasProblem(res, "1 line(s) beyond its 3 lines (99)") {
		t.Fatalf("verification %+v", res)
	}
}

// TestLiveSyslogCollectionDropped: a syslog collection dropped while the service runs (noticed by
// the minute's check) or while it is stopped (noticed at the start) is filled again, with its
// indexes, from the chunks the store holds.
func TestLiveSyslogCollectionDropped(t *testing.T) {
	for _, running := range []bool{true, false} {
		t.Run(fmt.Sprintf("running=%v", running), func(t *testing.T) {
			e := newSyslogEnv(t)
			a := e.sealMessages(t, "a", 3)
			b := e.sealMessages(t, "b", 2)
			r := e.replicator(t)
			mustSync(t, r)
			_, coll1 := syslogMeta(t, e)
			if err := e.db.Collection(collSyslog).Drop(bg); err != nil {
				t.Fatal(err)
			}
			if running {
				e.clk.Advance(2 * tailCheckEvery) // noticed by the minute's check
			} else {
				r = e.replicator(t) // noticed by the start
			}
			mustSync(t, r)
			requireChunkDocs(t, e, a)
			requireChunkDocs(t, e, b)
			if names := indexNames(t, e.db, collSyslog); !slices.Contains(names, "rx_-1") || !slices.Contains(names, "chunk_1") {
				t.Errorf("indexes of syslog: %v", names)
			}
			if seq, coll := syslogMeta(t, e); coll == coll1 || len(coll) != 32 || seq != int64(e.st.Head().Seq) {
				t.Errorf("meta syslog_seq %d, syslog_collection %q (was %q)", seq, coll, coll1)
			}
			if !loggedContaining(e.liveEnv, "the syslog messages are copied again") {
				t.Errorf("not logged: %q", e.logs.messages())
			}
			if st := r.Status(); st.LastError != "" {
				t.Fatalf("status %+v", st)
			}
			requireVerifyOK(t, e.verify(t, true))
		})
	}
}

// TestLiveSyslogStoreAddedLater: syslog records copied without a syslog store are applied, read
// from the ledger, once the replicator has one.
func TestLiveSyslogStoreAddedLater(t *testing.T) {
	e := newSyslogEnv(t)
	a := e.sealMessages(t, "a", 2)
	mustSync(t, e.liveEnv.replicator(t)) // without a syslog store
	names, err := e.db.ListCollectionNames(bg, bson.D{})
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(names, collSyslog) {
		t.Fatalf("collections %v without a syslog store", names)
	}
	if _, err := findRaw(t, e.db, collMeta, metaID).LookupErr("syslog_seq"); err == nil {
		t.Fatal("meta has a syslog_seq without a syslog store")
	}
	requireVerifyOK(t, e.verify(t, true)) // copied a moment ago: not behind yet
	cr := &countingReader{Store: e.st}
	r := e.replicator(t, func(o *Options) { o.Reader = cr })
	if n := mustSync(t, r); n != 0 {
		t.Fatalf("copied %d records", n)
	}
	if got := cr.scans(); !slices.Equal(got, []uint64{0}) {
		t.Fatalf("scans %v, want [0]", got)
	}
	requireChunkDocs(t, e, a)
	requireVerifyOK(t, e.verify(t, true))
}

// TestLiveSyslogRejectedByMongoDB: lines that MongoDB refuses are reported; the records, and the
// syslog records after them, are copied all the same.
func TestLiveSyslogRejectedByMongoDB(t *testing.T) {
	e := newSyslogEnv(t)
	r := e.replicator(t)
	mustSync(t, r) // creates the syslog collection and its indexes
	// A validator that requires a field the replicator never writes stands in for any content the
	// server refuses (added with collMod: an index build on an existing collection needs 500 MB
	// of free disk space).
	if err := e.db.RunCommand(bg, bson.D{{Key: "collMod", Value: collSyslog},
		{Key: "validator", Value: bson.D{{Key: "approved", Value: bson.D{{Key: "$exists", Value: true}}}}}}).Err(); err != nil {
		t.Fatal(err)
	}
	a := e.sealMessages(t, "a", 2)
	n, err := r.SyncOnce(bg)
	if n != 1 || !errors.Is(err, ErrIntegrity) || !strings.Contains(err.Error(), fmt.Sprintf(`MongoDB rejected 2 line(s) of syslog chunk "a" (ledger record %d)`, a.seq)) {
		t.Fatalf("SyncOnce = %d, %v (status %+v, %d syslog documents)", n, err, r.Status(), count(t, e.db, collSyslog))
	}
	if st := r.Status(); st.LastSeq != e.st.Head().Seq {
		t.Fatalf("status %+v", st)
	}
	if seq, _ := syslogMeta(t, e); seq != int64(e.st.Head().Seq) {
		t.Fatalf("meta syslog_seq %d", seq)
	}
	appendSample(t, e.liveEnv, 600)
	mustSync(t, r)
}

// TestLiveSyslogCollectionUnusable: a syslog collection that cannot be written (here a view of the
// same name) makes the syslog copy wait and say why; the records are copied all the same, and the
// messages once the collection can be written.
func TestLiveSyslogCollectionUnusable(t *testing.T) {
	e := newSyslogEnv(t)
	if err := e.db.CreateView(bg, collSyslog, collRecords, mongo.Pipeline{}); err != nil {
		t.Fatal(err)
	}
	a := e.sealMessages(t, "a", 2)
	r := e.replicator(t)
	n, err := r.SyncOnce(bg)
	if err != nil || n != len(ledgerItems(t, e.st)) {
		t.Fatalf("SyncOnce = %d, %v", n, err)
	}
	if st := r.Status(); st.LastSeq != e.st.Head().Seq || !strings.Contains(st.LastError, "the syslog messages cannot be copied") {
		t.Fatalf("status %+v", st)
	}
	if err := e.db.Collection(collSyslog).Drop(bg); err != nil { // drops the view
		t.Fatal(err)
	}
	mustSync(t, r)
	requireChunkDocs(t, e, a)
	if st := r.Status(); st.LastError != "" {
		t.Fatalf("status %+v", st)
	}
	e.clk.Advance(2 * tailCheckEvery) // the collection now has a UUID: noticed, applied again
	mustSync(t, r)
	requireChunkDocs(t, e, a)
	requireVerifyOK(t, e.verify(t, true))
}

// TestLiveSyslogVerifyBehind: a syslog collection that has not applied the syslog records of more
// than a quarter of an hour of copied records is reported, and so is one whose replication state
// names another collection.
func TestLiveSyslogVerifyBehind(t *testing.T) {
	e := newSyslogEnv(t)
	a := e.sealMessages(t, "a", 2)
	r := e.replicator(t)
	for i := uint64(0); i < 20; i++ {
		e.clk.Advance(time.Minute)
		mustAppend(t, e.st, model.TypeSample, sample(700+i, "later"))
	}
	mustSync(t, r)
	requireVerifyOK(t, e.verify(t, true))
	head, coll := syslogMeta(t, e)
	setField(t, e.db.Collection(collMeta), metaID, "syslog_seq", int64(a.seq)-1)
	res := e.verify(t, true)
	if res.OK || !hasProblem(res, fmt.Sprintf("the syslog collection is behind: 1 syslog record(s) from seq %d on", a.seq)) {
		t.Fatalf("verification %+v", res)
	}
	setField(t, e.db.Collection(collMeta), metaID, "syslog_seq", head)
	setField(t, e.db.Collection(collMeta), metaID, "syslog_collection", "another")
	res = e.verify(t, true)
	if res.OK || !hasProblem(res, "the syslog collection is behind") {
		t.Fatalf("verification %+v", res)
	}
	setField(t, e.db.Collection(collMeta), metaID, "syslog_collection", coll)
	setField(t, e.db.Collection(collMeta), metaID, "syslog_seq", "x")
	if res := e.verify(t, true); res.OK || !hasProblem(res, "meta: syslog_seq is not a ledger seq") {
		t.Fatalf("verification %+v", res)
	}
}

// syslogSize returns the size of the syslog collection's documents as MongoDB counts them.
func syslogSize(t *testing.T, db *mongo.Database) int64 {
	t.Helper()
	cur, err := db.Collection(collSyslog).Aggregate(bg, mongo.Pipeline{{{Key: "$collStats", Value: bson.D{{Key: "storageStats", Value: bson.D{}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	defer cur.Close(bg)
	if !cur.Next(bg) {
		t.Fatalf("no collection statistics: %v", cur.Err())
	}
	n, ok := cur.Current.Lookup("storageStats", "size").AsInt64OK()
	if !ok {
		t.Fatalf("storageStats.size: %v", cur.Current.Lookup("storageStats", "size"))
	}
	return n
}

// TestLiveSyslogSizeLimit: the syslog collection keeps to a size limit of its own - the syslog
// store's keep_mb, counted as the documents' size - by deleting the documents of its oldest
// chunks (the chunks stay in the store), which Verify does not count as missing; a lower limit
// applies at the next pass, and a chunk missing from the middle is still reported.
func TestLiveSyslogSizeLimit(t *testing.T) {
	e := newSyslogEnv(t)
	e.store.setKeepMB(1)
	text := strings.Repeat("x", 900) // about 2 KiB a line, raw and msg holding it
	var chunks []sealed
	for i := range 6 {
		chunks = append(chunks, e.seal(t, fmt.Sprintf("syslog-20261005T03%02d01Z-%d.jsonl.gz", 20+5*i, i),
			msgLines(t, e.clk.Now(), 120, text)...))
	}
	r := e.replicator(t)
	mustSync(t, r)
	if size := syslogSize(t, e.db); size > 1<<20 {
		t.Fatalf("the syslog collection takes %d bytes, limit %d", size, 1<<20)
	}
	trimmed := 0
	for trimmed < len(chunks) && chunkCount(t, e.db, chunks[trimmed].c.Name) == 0 {
		trimmed++
	}
	if trimmed == 0 || trimmed > len(chunks)-2 {
		t.Fatalf("%d of %d chunks trimmed", trimmed, len(chunks))
	}
	for _, c := range chunks[trimmed:] { // the newest chunks, complete
		requireChunkDocs(t, e, c)
	}
	if got, _ := rawString(findRaw(t, e.db, collMeta, metaID), "syslog_trimmed"); got != chunks[trimmed-1].c.Name {
		t.Fatalf("meta syslog_trimmed %q, want %q", got, chunks[trimmed-1].c.Name)
	}
	if !loggedContaining(e.liveEnv, "reached its size limit") {
		t.Errorf("not logged: %q", e.logs.messages())
	}
	if st := r.Status(); st.LastError != "" {
		t.Fatalf("status %+v", st)
	}
	res := e.verify(t, true)
	requireVerifyOK(t, res)
	if res.SyslogTrimmed != trimmed || res.SyslogChunks != len(chunks)-trimmed {
		t.Fatalf("verification: %d trimmed, %d chunks checked; want %d, %d", res.SyslogTrimmed, res.SyslogChunks, trimmed, len(chunks)-trimmed)
	}

	// A new chunk: the oldest one left goes.
	chunks = append(chunks, e.seal(t, "syslog-20261005T035601Z-6.jsonl.gz", msgLines(t, e.clk.Now(), 120, text)...))
	mustSync(t, r)
	if n := chunkCount(t, e.db, chunks[trimmed].c.Name); n != 0 {
		t.Fatalf("the oldest chunk kept has %d documents after a new one came", n)
	}
	requireChunkDocs(t, e, chunks[len(chunks)-1])
	if size := syslogSize(t, e.db); size > 1<<20 {
		t.Fatalf("the syslog collection takes %d bytes", size)
	}
	requireVerifyOK(t, e.verify(t, true))

	// A chunk missing from the middle is missing, not trimmed.
	middle := chunks[len(chunks)-2]
	if _, err := e.db.Collection(collSyslog).DeleteMany(bg, bson.D{{Key: "chunk", Value: middle.c.Name}}); err != nil {
		t.Fatal(err)
	}
	if res := e.verify(t, true); res.OK || res.SyslogMissing != 1 || !hasProblem(res, quote(middle.c.Name)) {
		t.Fatalf("verification %+v", res)
	}
}

// TestLiveSyslogLowerLimitAppliesAtOnce: a lower keep_mb trims the syslog collection at the next
// pass, without waiting for a new chunk; the newest chunk stays whatever its size.
func TestLiveSyslogLowerLimitAppliesAtOnce(t *testing.T) {
	e := newSyslogEnv(t)
	text := strings.Repeat("y", 900)
	a := e.seal(t, "syslog-20261005T032001Z-a.jsonl.gz", msgLines(t, e.clk.Now(), 400, text)...)
	b := e.seal(t, "syslog-20261005T032501Z-b.jsonl.gz", msgLines(t, e.clk.Now(), 700, text)...)
	r := e.replicator(t)
	mustSync(t, r) // within the default 100 MiB
	requireChunkDocs(t, e, a)
	requireChunkDocs(t, e, b)
	e.store.setKeepMB(1)
	mustSync(t, r)
	if n := chunkCount(t, e.db, a.c.Name); n != 0 {
		t.Fatalf("%d documents of the oldest chunk after the limit was lowered", n)
	}
	requireChunkDocs(t, e, b) // the newest chunk: kept, although it alone takes more than 1 MiB
	if size := syslogSize(t, e.db); size <= 1<<20 {
		t.Fatalf("test setup: the newest chunk takes only %d bytes", size)
	}
	mustSync(t, r) // nothing more to trim
	requireChunkDocs(t, e, b)
	res := e.verify(t, true)
	requireVerifyOK(t, res)
	if res.SyslogTrimmed != 1 {
		t.Fatalf("verification %+v", res)
	}
}
