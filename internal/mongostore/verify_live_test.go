package mongostore

import (
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"attmonitor/internal/model"
)

// Live tests (ATTMON_MONGO=1) of what Verify finds in blob documents, where it says the copy
// ends, and how it shows text taken from documents.

func setField(t *testing.T, c *mongo.Collection, id any, field string, value any) {
	t.Helper()
	res, err := c.UpdateOne(bg, bson.D{{Key: "_id", Value: id}}, bson.D{{Key: "$set", Value: bson.D{{Key: field, Value: value}}}})
	if err != nil || res.MatchedCount != 1 {
		t.Fatalf("set %s on %v: %v", field, id, err)
	}
}

func unsetField(t *testing.T, c *mongo.Collection, id any, field string) {
	t.Helper()
	res, err := c.UpdateOne(bg, bson.D{{Key: "_id", Value: id}}, bson.D{{Key: "$unset", Value: bson.D{{Key: field, Value: ""}}}})
	if err != nil || res.MatchedCount != 1 {
		t.Fatalf("unset %s on %v: %v", field, id, err)
	}
}

// TestLiveVerifyBlobDocuments: evidence bytes removed from a blob document, a plausible blob that
// no ledger record references, and altered bookkeeping fields are all reported.
func TestLiveVerifyBlobDocuments(t *testing.T) {
	e := newLiveEnv(t)
	mustSync(t, e.replicator(t))
	blobs := e.db.Collection(collBlobs)
	// (1) The content of the gateway page removed.
	unsetField(t, blobs, e.f.pageBlob, "data")
	// (2) A fabricated page under its correct SHA-256 id.
	fake := []byte("fabricated gateway page: Broadband Connection: Down")
	fakeID := sha256Hex(fake)
	if _, err := blobs.InsertOne(bg, blobDoc(fakeID, fake, 10, true, e.clk.Now())); err != nil {
		t.Fatal(err)
	}
	// (3) Another blob: a first_seq naming a record that does not reference it, and a comment.
	setField(t, blobs, e.f.netshBlob, "first_seq", int64(2))
	setField(t, blobs, e.f.netshBlob, "comment", "AT&T was not at fault")
	// (4) The large blob: its stored_at removed.
	unsetField(t, blobs, e.f.bigBlob, "stored_at")

	res := mustVerify(t, e, e.st, e.st.PublicKey())
	if res.OK || res.BlobsCorrupt != 4 || res.BlobsChecked != 3 || res.BlobsMissing != 0 {
		t.Fatalf("verification %+v", res)
	}
	for _, p := range []string{
		fmt.Sprintf(`blob %s: field(s) "data" do not match`, e.f.pageBlob),
		fmt.Sprintf("blob %s: no ledger record references it", fakeID),
		fmt.Sprintf(`blob %s: field(s) "first_seq", "comment" do not match`, e.f.netshBlob),
		fmt.Sprintf(`blob %s: field(s) "stored_at" do not match`, e.f.bigBlob),
	} {
		if !hasProblem(res, p) {
			t.Errorf("no problem %q in:\n%s", p, strings.Join(res.Problems, "\n"))
		}
	}
}

// TestLiveVerifyBlobDocumentsWithoutContent: with blob storage off, a blob document's size is
// checked against the ledger's copy of the blob, and its note must say why the content is absent.
func TestLiveVerifyBlobDocumentsWithoutContent(t *testing.T) {
	e := newLiveEnv(t)
	mustSync(t, e.replicator(t, func(o *Options) { o.StoreBlobs = false }))
	requireVerifyOK(t, mustVerify(t, e, e.st, e.st.PublicKey()))
	blobs := e.db.Collection(collBlobs)
	setField(t, blobs, e.f.pageBlob, "size", int64(1))
	unsetField(t, blobs, e.f.netshBlob, "note")
	res := mustVerify(t, e, e.st, e.st.PublicKey())
	if res.OK || res.BlobsCorrupt != 2 || res.BlobsChecked != 0 {
		t.Fatalf("verification %+v", res)
	}
	for _, p := range []string{
		fmt.Sprintf(`blob %s: field(s) "size" do not match`, e.f.pageBlob),
		fmt.Sprintf(`blob %s: field(s) "data" do not match`, e.f.netshBlob), // neither content nor the note why it is absent
	} {
		if !hasProblem(res, p) {
			t.Errorf("no problem %q in:\n%s", p, strings.Join(res.Problems, "\n"))
		}
	}
}

// TestLiveVerifyReportsTheCopysExtent: Verify says where the copy ends; an emptied copy fails
// whatever its replication state says, and so does a copy that lacks the newest quarter of an
// hour of evidence.
func TestLiveVerifyReportsTheCopysExtent(t *testing.T) {
	e := newLiveEnv(t)
	items := ledgerItems(t, e.st)
	head := e.st.Head().Seq
	mustSync(t, e.replicator(t))
	res := mustVerify(t, e, e.st, e.st.PublicKey())
	requireVerifyOK(t, res)
	if res.LedgerHead != head || res.CopiedUpTo != int64(head) || res.NotCopied != 0 {
		t.Fatalf("extent of a complete copy: %+v", res)
	}
	// A record appended since the last pass: not copied yet, no problem.
	appendSample(t, e, 700)
	res = mustVerify(t, e, e.st, e.st.PublicKey())
	requireVerifyOK(t, res)
	if res.LedgerHead != head+1 || res.CopiedUpTo != int64(head) || res.NotCopied != 1 {
		t.Fatalf("extent with one record not copied: %+v", res)
	}
	// A tail removed together with the replication state's resume point: shown, not a problem
	// (the running replicator copies it again).
	k := head - 12
	if _, err := e.db.Collection(collRecords).DeleteMany(bg, bson.D{{Key: "_id", Value: bson.D{{Key: "$gt", Value: int64(k)}}}}); err != nil {
		t.Fatal(err)
	}
	setField(t, e.db.Collection(collMeta), metaID, "last_seq", int64(k))
	setField(t, e.db.Collection(collMeta), metaID, "last_hash", items[k].env.H)
	res = mustVerify(t, e, e.st, e.st.PublicKey())
	if res.CopiedUpTo != int64(k) || res.NotCopied != 13 {
		t.Fatalf("extent of a truncated copy: %+v", res)
	}
	// More than a quarter of an hour of evidence not copied: a problem.
	for i := uint64(0); i < staleRecords+5; i++ {
		e.clk.Advance(time.Minute)
		mustAppend(t, e.st, model.TypeSample, sample(800+i, "while the copy is stale"))
	}
	res = mustVerify(t, e, e.st, e.st.PublicKey())
	if res.OK || !hasProblem(res, "the copy is behind the ledger") {
		t.Fatalf("stale copy: %+v", res)
	}
	// Everything removed and a replication state that claims nothing was copied: no copy.
	for _, c := range []string{collRecords, collBlobs, collIncidents} {
		if _, err := e.db.Collection(c).DeleteMany(bg, bson.D{}); err != nil {
			t.Fatal(err)
		}
	}
	setField(t, e.db.Collection(collMeta), metaID, "last_seq", int64(-1))
	res = mustVerify(t, e, e.st, e.st.PublicKey())
	if res.OK || !hasProblem(res, "holds no copy") || res.CopiedUpTo != -1 || res.NotCopied != len(ledgerItems(t, e.st)) {
		t.Fatalf("emptied copy: %+v", res)
	}
}

// requirePrintable fails when s holds a character that a terminal could interpret or that is
// invisible.
func requirePrintable(t *testing.T, what, s string) {
	t.Helper()
	for i, r := range s {
		if r == utf8.RuneError || (r != ' ' && !unicode.IsPrint(r)) || unicode.Is(unicode.Cf, r) {
			t.Fatalf("%s holds %U at byte %d: %q", what, r, i, s)
		}
	}
}

// TestLiveVerifyQuotesDocumentText: text taken from documents (an incident id, a field name, a
// stored hash) appears quoted and escaped in problems and in the replicator's status, so it
// cannot fake output lines or rewrite the verdict on a terminal.
func TestLiveVerifyQuotesDocumentText(t *testing.T) {
	e := newLiveEnv(t)
	mustSync(t, e.replicator(t))
	evilID := "INC-1\x1b[1A\x1b[2K\rMongoDB copy verification PASSED\n  fake line\u202e"
	doc := findRaw(t, e.db, collIncidents, incidentID1)
	if _, err := e.db.Collection(collIncidents).InsertOne(bg, append(bson.D{{Key: "_id", Value: evilID}}, withoutKey(doc, "_id")...)); err != nil {
		t.Fatal(err)
	}
	setField(t, e.db.Collection(collRecords), int64(1), "x\x1b[8mhidden", 1)
	setField(t, e.db.Collection(collMeta), metaID, "fingerprint", "\x1b[32mOK\x1b[0m")
	res := mustVerify(t, e, e.st, e.st.PublicKey())
	if res.OK {
		t.Fatal("verification passed")
	}
	for _, p := range res.Problems {
		requirePrintable(t, "problem", p)
	}
	for _, p := range []string{
		`incident "INC-1\x1b[1A\x1b[2K\rMongoDB copy verification PASSED\n  fake line\u202e": ledger record`,
		`seq 1: field(s) "x\x1b[8mhidden" do not match`,
		`meta: names the ledger key fingerprint "\x1b[32mOK\x1b[0m"`,
	} {
		if !hasProblem(res, p) {
			t.Errorf("no problem %q in:\n%s", p, strings.Join(res.Problems, "\n"))
		}
	}

	// The replicator's status: a stored h with control characters, met by a full re-check.
	setField(t, e.db.Collection(collRecords), int64(2), "h", "\x1b[2K\rall good")
	if _, err := e.db.Collection(collMeta).DeleteOne(bg, bson.D{{Key: "_id", Value: metaID}}); err != nil {
		t.Fatal(err)
	}
	r := e.replicator(t)
	if _, err := r.SyncOnce(bg); err == nil {
		t.Fatal("conflict not reported")
	} else {
		requirePrintable(t, "SyncOnce error", err.Error())
	}
	st := r.Status()
	requirePrintable(t, "LastError", st.LastError)
	if !strings.Contains(st.LastError, `different record 2 (h "\x1b[2K\rall good"`) {
		t.Fatalf("status %+v", st)
	}
}
