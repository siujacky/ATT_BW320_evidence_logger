package mongostore

import (
	"context"
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

// Live tests (ATTMON_MONGO=1) of a copy that changes behind the running replicator's back: the
// documented ways to rebuild it (drop the database, delete the replication state), an older backup
// restored, collections dropped or emptied, blob storage turned on, and documents that MongoDB's
// numeric comparisons or a forger make ambiguous.

// appendSample appends a sample 10 s after the previous record (the monitor writes one every 10 s).
func appendSample(t *testing.T, e *liveEnv, cycle uint64) uint64 {
	t.Helper()
	e.clk.Advance(10 * time.Second)
	return mustAppend(t, e.st, model.TypeSample, sample(cycle, "after the copy")).Seq
}

func requireIndexes(t *testing.T, db *mongo.Database) {
	t.Helper()
	specs, err := db.Collection(collRecords).Indexes().ListSpecifications(bg)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range specs {
		names = append(names, s.Name)
	}
	if !slices.Contains(names, "type_1_ts_1") || !slices.Contains(names, "ts_1") {
		t.Fatalf("indexes of records: %v", names)
	}
}

// requireFullCopy checks that MongoDB holds the whole ledger, with its indexes, that the status
// says so, and that the copy verifies.
func requireFullCopy(t *testing.T, e *liveEnv, r *Replicator) {
	t.Helper()
	items := ledgerItems(t, e.st)
	if n := count(t, e.db, collRecords); n != int64(len(items)) {
		t.Fatalf("%d record documents for %d ledger records", n, len(items))
	}
	requireIndexes(t, e.db)
	if st := r.Status(); st.LastSeq != e.st.Head().Seq || st.Lag != 0 || !st.HasData {
		t.Fatalf("status %+v (head %d)", st, e.st.Head().Seq)
	}
	requireVerifyOK(t, mustVerify(t, e, e.st, e.st.PublicKey()))
}

func loggedContaining(e *liveEnv, substr string) bool {
	return slices.ContainsFunc(e.logs.messages(), func(m string) bool { return strings.Contains(m, substr) })
}

// TestLiveDropDatabaseWhileRunning: dropping the database is a documented way to rebuild the copy.
// The next pass copies a new record into the empty database long before the minute's tail check
// (samples every 10 s, passes every 5 s): the replication state it then finds missing makes it
// copy everything again, indexes included.
func TestLiveDropDatabaseWhileRunning(t *testing.T) {
	e := newLiveEnv(t)
	r := e.replicator(t)
	mustSync(t, r)
	if err := e.db.Drop(bg); err != nil {
		t.Fatal(err)
	}
	appendSample(t, e, 100)
	n, err := r.SyncOnce(bg)
	if err != nil {
		t.Fatalf("pass after the drop: %v", err)
	}
	if want := len(ledgerItems(t, e.st)); n != want {
		t.Fatalf("pass after the drop copied %d, want %d (everything)", n, want)
	}
	requireFullCopy(t, e, r)
	if !loggedContaining(e, "changed behind the replicator's back") {
		t.Errorf("the re-validation was not logged: %q", e.logs.messages())
	}
	// Later passes, tail checks included, go on normally.
	for i := uint64(0); i < 5; i++ {
		e.clk.Advance(2 * tailCheckEvery)
		appendSample(t, e, 101+i)
		if n := mustSync(t, r); n != 1 {
			t.Fatalf("pass %d copied %d", i, n)
		}
	}
	requireFullCopy(t, e, r)
	if st := r.Status(); st.LastError != "" || st.Records != int64(len(ledgerItems(t, e.st))) {
		t.Fatalf("status %+v", st)
	}
}

// TestLiveDeleteMetaWhileRunning: deleting the replication state is the documented way to make
// the replicator re-check and fill the whole copy; it must work while the service runs, whether
// a new record arrives first or the tail check notices.
func TestLiveDeleteMetaWhileRunning(t *testing.T) {
	for _, idle := range []bool{false, true} {
		t.Run(fmt.Sprintf("idle=%v", idle), func(t *testing.T) {
			e := newLiveEnv(t)
			r := e.replicator(t)
			mustSync(t, r)
			if _, err := e.db.Collection(collRecords).DeleteMany(bg, bson.D{{Key: "_id", Value: bson.D{{Key: "$in", Value: bson.A{int64(3), int64(4)}}}}}); err != nil {
				t.Fatal(err)
			}
			if _, err := e.db.Collection(collMeta).DeleteOne(bg, bson.D{{Key: "_id", Value: metaID}}); err != nil {
				t.Fatal(err)
			}
			want := 2 // records 3 and 4
			if idle {
				e.clk.Advance(2 * tailCheckEvery)
			} else {
				appendSample(t, e, 100)
				want++
			}
			if n := mustSync(t, r); n != want {
				t.Fatalf("copied %d, want %d", n, want)
			}
			requireFullCopy(t, e, r)
			meta := findRaw(t, e.db, collMeta, metaID)
			if ls, _ := meta.Lookup("last_seq").Int64OK(); uint64(ls) != e.st.Head().Seq {
				t.Fatalf("meta last_seq %d, head %d", ls, e.st.Head().Seq)
			}
			// A restart finds a consistent copy and copies nothing.
			if n := mustSync(t, e.replicator(t)); n != 0 {
				t.Fatalf("restart copied %d", n)
			}
		})
	}
}

// dumpDB returns every document of the copy's collections (a backup).
func dumpDB(t *testing.T, db *mongo.Database) map[string][]bson.Raw {
	t.Helper()
	out := map[string][]bson.Raw{}
	for _, name := range []string{collRecords, collBlobs, collIncidents, collMeta} {
		cur, err := db.Collection(name).Find(bg, bson.D{})
		if err != nil {
			t.Fatal(err)
		}
		for cur.Next(bg) {
			out[name] = append(out[name], append(bson.Raw(nil), cur.Current...))
		}
		if err := cur.Err(); err != nil {
			t.Fatal(err)
		}
		cur.Close(bg)
	}
	return out
}

// restoreDB replaces the database with a backup, as mongorestore --drop does (the collections are
// created again).
func restoreDB(t *testing.T, db *mongo.Database, backup map[string][]bson.Raw) {
	t.Helper()
	if err := db.Drop(bg); err != nil {
		t.Fatal(err)
	}
	for name, docs := range backup {
		if len(docs) == 0 {
			continue
		}
		ds := make([]any, len(docs))
		for i, d := range docs {
			ds[i] = d
		}
		if _, err := db.Collection(name).InsertMany(bg, ds); err != nil {
			t.Fatal(err)
		}
	}
}

// TestLiveRestoreOlderBackupWhileRunning: an older backup restored under the running replicator
// (its replication state is older than what the replicator last wrote) is continued from its own
// resume point, and the records copied since the backup are copied again.
func TestLiveRestoreOlderBackupWhileRunning(t *testing.T) {
	for _, dropCollections := range []bool{true, false} {
		t.Run(fmt.Sprintf("drop=%v", dropCollections), func(t *testing.T) {
			e := newLiveEnv(t)
			r := e.replicator(t)
			mustSync(t, r)
			head1 := e.st.Head().Seq
			backup := dumpDB(t, e.db)
			for i := uint64(0); i < 3; i++ {
				appendSample(t, e, 200+i)
				mustSync(t, r)
			}
			if dropCollections {
				restoreDB(t, e.db, backup)
			} else {
				// The same collections, with the newer documents removed and the older state back.
				if _, err := e.db.Collection(collRecords).DeleteMany(bg, bson.D{{Key: "_id", Value: bson.D{{Key: "$gt", Value: int64(head1)}}}}); err != nil {
					t.Fatal(err)
				}
				if _, err := e.db.Collection(collMeta).ReplaceOne(bg, bson.D{{Key: "_id", Value: metaID}}, backup[collMeta][0]); err != nil {
					t.Fatal(err)
				}
			}
			appendSample(t, e, 300)
			if n := mustSync(t, r); n != 4 {
				t.Fatalf("copied %d, want 4 (3 records copied after the backup, 1 new)", n)
			}
			requireFullCopy(t, e, r)
		})
	}
}

// TestLiveRecordsCollectionDroppedWhileRunning: a records collection dropped (only it) and
// re-created by the next pass's insert is noticed by the tail check (its UUID changed): the
// history is copied again and the indexes are created again.
func TestLiveRecordsCollectionDroppedWhileRunning(t *testing.T) {
	e := newLiveEnv(t)
	r := e.replicator(t)
	mustSync(t, r)
	if err := e.db.Collection(collRecords).Drop(bg); err != nil {
		t.Fatal(err)
	}
	appendSample(t, e, 100)
	if n := mustSync(t, r); n != 1 {
		t.Fatalf("copied %d before the tail check", n)
	}
	e.clk.Advance(2 * tailCheckEvery)
	if n, want := mustSync(t, r), len(ledgerItems(t, e.st))-1; n != want {
		t.Fatalf("copied %d after the tail check, want %d", n, want)
	}
	requireFullCopy(t, e, r)
	// The re-check recorded the collections: a restart does not check everything again.
	cr := &countingReader{Store: e.st}
	if n := mustSync(t, e.replicator(t, func(o *Options) { o.Reader = cr })); n != 0 || len(cr.scans()) != 0 {
		t.Fatalf("restart copied %d, scans %v", n, cr.scans())
	}
}

// TestLiveRecordsDeletedBehindTheTail: records deleted without dropping the collection, the
// newest copied one kept (e.g. db.records.deleteMany with a filter): the tail check, or a
// restart, misses record 0 and the whole copy is checked again.
func TestLiveRecordsDeletedBehindTheTail(t *testing.T) {
	for _, restart := range []bool{false, true} {
		t.Run(fmt.Sprintf("restart=%v", restart), func(t *testing.T) {
			e := newLiveEnv(t)
			r := e.replicator(t)
			mustSync(t, r)
			head := e.st.Head().Seq
			if _, err := e.db.Collection(collRecords).DeleteMany(bg, bson.D{{Key: "_id", Value: bson.D{{Key: "$lt", Value: int64(head)}}}}); err != nil {
				t.Fatal(err)
			}
			if restart {
				r = e.replicator(t)
			} else {
				e.clk.Advance(2 * tailCheckEvery)
			}
			if n := mustSync(t, r); uint64(n) != head {
				t.Fatalf("copied %d, want %d", n, head)
			}
			requireFullCopy(t, e, r)
			if !loggedContaining(e, "checking the copy of the whole ledger again") {
				t.Errorf("the re-check was not logged: %q", e.logs.messages())
			}
		})
	}
}

// TestLiveBlobsCollectionRebuilt: the blobs collection dropped (here while the copy was made
// without blob contents) and blob storage turned on: the blobs are copied again, with their
// content, also without the drop.
func TestLiveBlobsCollectionRebuilt(t *testing.T) {
	for _, drop := range []bool{true, false} {
		t.Run(fmt.Sprintf("drop=%v", drop), func(t *testing.T) {
			e := newLiveEnv(t)
			mustSync(t, e.replicator(t, func(o *Options) { o.StoreBlobs = false }))
			if sb, _ := findRaw(t, e.db, collMeta, metaID).Lookup("store_blobs").BooleanOK(); sb {
				t.Fatal("meta says blob contents are stored")
			}
			if drop {
				if err := e.db.Collection(collBlobs).Drop(bg); err != nil {
					t.Fatal(err)
				}
			}
			r := e.replicator(t) // StoreBlobs on
			if n := mustSync(t, r); n != 0 {
				t.Fatalf("copied %d records", n)
			}
			for _, id := range []string{e.f.pageBlob, e.f.netshBlob, e.f.bigBlob} {
				if _, data, ok := findRaw(t, e.db, collBlobs, id).Lookup("data").BinaryOK(); !ok || sha256Hex(data) != id {
					t.Errorf("blob %s has no content", id)
				}
			}
			if sb, _ := findRaw(t, e.db, collMeta, metaID).Lookup("store_blobs").BooleanOK(); !sb {
				t.Error("meta does not record that blob contents are stored")
			}
			res := mustVerify(t, e, e.st, e.st.PublicKey())
			requireVerifyOK(t, res)
			if res.BlobsChecked != 3 {
				t.Errorf("BlobsChecked %d", res.BlobsChecked)
			}
			// Done once: a restart does not check everything again.
			cr := &countingReader{Store: e.st}
			mustSync(t, e.replicator(t, func(o *Options) { o.Reader = cr }))
			if got := cr.scans(); len(got) != 0 {
				t.Fatalf("restart scanned from %v", got)
			}
		})
	}
}

// TestLiveBlobsCollectionDroppedWhileRunning: the blobs collection dropped under the running
// replicator; before the tail check notices, a new record references a blob first referenced
// long before, so the regular pass stores that blob with a later first_seq. The re-check that
// follows stores the other blobs again and gives that one its first referencing record.
func TestLiveBlobsCollectionDroppedWhileRunning(t *testing.T) {
	e := newLiveEnv(t)
	r := e.replicator(t)
	mustSync(t, r)
	items := ledgerItems(t, e.st)
	if err := e.db.Collection(collBlobs).Drop(bg); err != nil {
		t.Fatal(err)
	}
	e.clk.Advance(10 * time.Second)
	seq := mustAppend(t, e.st, model.TypeLocalLink, model.LocalLink{Interface: "Wi-Fi", Type: "wifi", State: "connected", RawSHA256: e.f.netshBlob}, e.f.netshBlob).Seq
	mustSync(t, r)
	if n, _ := findRaw(t, e.db, collBlobs, e.f.netshBlob).Lookup("first_seq").Int64OK(); uint64(n) != seq {
		t.Fatalf("netsh blob first_seq %d before the re-check, want %d", n, seq)
	}
	e.clk.Advance(2 * tailCheckEvery)
	mustSync(t, r)
	if n, _ := findRaw(t, e.db, collBlobs, e.f.netshBlob).Lookup("first_seq").Int64OK(); uint64(n) != firstRef(items, e.f.netshBlob) {
		t.Fatalf("netsh blob first_seq %d after the re-check, want %d", n, firstRef(items, e.f.netshBlob))
	}
	if n := count(t, e.db, collBlobs); n != 3 {
		t.Fatalf("%d blob documents", n)
	}
	requireFullCopy(t, e, r)
}

// TestLiveBlobsCollectionDroppedWhileStopped: the blobs collection dropped while the service was
// stopped, blob storage unchanged: the start notices the collection's new identity and stores the
// blobs again.
func TestLiveBlobsCollectionDroppedWhileStopped(t *testing.T) {
	e := newLiveEnv(t)
	mustSync(t, e.replicator(t))
	if err := e.db.Collection(collBlobs).Drop(bg); err != nil {
		t.Fatal(err)
	}
	r := e.replicator(t)
	if n := mustSync(t, r); n != 0 {
		t.Fatalf("copied %d records", n)
	}
	if n := count(t, e.db, collBlobs); n != 3 {
		t.Fatalf("%d blob documents", n)
	}
	requireFullCopy(t, e, r)
}

// TestLiveIncidentsCollectionDroppedWhileRunning: incident documents come back after their
// collection is dropped.
func TestLiveIncidentsCollectionDroppedWhileRunning(t *testing.T) {
	e := newLiveEnv(t)
	r := e.replicator(t)
	mustSync(t, r)
	if err := e.db.Collection(collIncidents).Drop(bg); err != nil {
		t.Fatal(err)
	}
	e.clk.Advance(2 * tailCheckEvery)
	mustSync(t, r)
	if n := count(t, e.db, collIncidents); n != 2 {
		t.Fatalf("%d incident documents", n)
	}
	requireFullCopy(t, e, r)
}

// TestLiveOlderReplicationStateIsUpgraded: a replication state written by the previous version
// (no store_blobs, no collections) leads to one re-check of the whole copy, after which the state
// records both; later restarts check nothing again.
func TestLiveOlderReplicationStateIsUpgraded(t *testing.T) {
	e := newLiveEnv(t)
	mustSync(t, e.replicator(t))
	if _, err := e.db.Collection(collMeta).UpdateOne(bg, bson.D{{Key: "_id", Value: metaID}},
		bson.D{{Key: "$unset", Value: bson.D{{Key: "store_blobs", Value: ""}, {Key: "collections", Value: ""}}}}); err != nil {
		t.Fatal(err)
	}
	for i, wantScans := range [][]uint64{{0}, nil} {
		cr := &countingReader{Store: e.st}
		r := e.replicator(t, func(o *Options) { o.Reader = cr })
		if n := mustSync(t, r); n != 0 {
			t.Fatalf("restart %d copied %d", i, n)
		}
		if got := cr.scans(); !slices.Equal(got, wantScans) {
			t.Fatalf("restart %d scanned from %v, want %v", i, got, wantScans)
		}
		if st := r.Status(); st.LastError != "" {
			t.Fatalf("restart %d: status %+v", i, st)
		}
	}
	meta := findRaw(t, e.db, collMeta, metaID)
	if sb, ok := meta.Lookup("store_blobs").BooleanOK(); !ok || !sb {
		t.Errorf("store_blobs %v", meta.Lookup("store_blobs"))
	}
	colls, ok := meta.Lookup("collections").DocumentOK()
	if !ok {
		t.Fatalf("collections %v", meta.Lookup("collections"))
	}
	for _, name := range copyCollections {
		if id, _ := rawString(colls, name); len(id) != 32 {
			t.Errorf("collections.%s = %q", name, id)
		}
	}
	requireVerifyOK(t, mustVerify(t, e, e.st, e.st.PublicKey()))
}

// TestLiveNoRecheckInTheFinalPass: a pass with a short deadline (the last one at shutdown) copies
// the new records but leaves a pending re-check of the whole copy to a later pass.
func TestLiveNoRecheckInTheFinalPass(t *testing.T) {
	e := newLiveEnv(t)
	cr := &countingReader{Store: e.st}
	r := e.replicator(t, func(o *Options) { o.Reader = cr })
	mustSync(t, r)
	if err := e.db.Collection(collBlobs).Drop(bg); err != nil {
		t.Fatal(err)
	}
	e.clk.Advance(2 * tailCheckEvery)
	appendSample(t, e, 900)
	scans := len(cr.scans())
	ctx, cancel := context.WithTimeout(bg, 2*time.Second)
	defer cancel()
	if n, err := r.SyncOnce(ctx); n != 1 || err != nil {
		t.Fatalf("final pass: %d, %v", n, err)
	}
	if got := cr.scans()[scans:]; len(got) != 0 {
		t.Fatalf("the final pass scanned from %v", got)
	}
	if n := count(t, e.db, collBlobs); n != 0 {
		t.Fatalf("%d blob documents before the re-check", n)
	}
	mustSync(t, r) // a pass of Run
	if got := cr.scans()[scans:]; !slices.Equal(got, []uint64{0}) {
		t.Fatalf("scans %v, want the re-check from 0", got)
	}
	requireFullCopy(t, e, r)
}

// TestLiveDoubleIDDoesNotStall: a document stored under _id 5.0 (a double, the same key as 5 for
// the unique index) is reported and left alone; the copy goes on.
func TestLiveDoubleIDDoesNotStall(t *testing.T) {
	e := newLiveEnv(t)
	mustSync(t, e.replicator(t))
	recs := e.db.Collection(collRecords)
	doc5 := findRaw(t, e.db, collRecords, int64(5))
	if _, err := recs.DeleteOne(bg, bson.D{{Key: "_id", Value: int64(5)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := recs.InsertOne(bg, append(bson.D{{Key: "_id", Value: 5.0}}, withoutKey(doc5, "_id")...)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.Collection(collMeta).DeleteOne(bg, bson.D{{Key: "_id", Value: metaID}}); err != nil {
		t.Fatal(err)
	}
	r := e.replicator(t) // a restart: the whole copy is checked
	n, err := r.SyncOnce(bg)
	if n != 0 || !errors.Is(err, ErrIntegrity) || !strings.Contains(err.Error(), "record 5 under an _id of BSON type double") {
		t.Fatalf("SyncOnce = %d, %v", n, err)
	}
	for i := uint64(0); i < 4; i++ {
		appendSample(t, e, 400+i)
		if n, err := r.SyncOnce(bg); n != 1 || err != nil {
			t.Fatalf("pass %d: %d, %v", i, n, err)
		}
	}
	st := r.Status()
	if !st.HasData || st.Lag != 0 || st.LastSeq != e.st.Head().Seq || !strings.Contains(st.LastError, "BSON type double") {
		t.Fatalf("status %+v", st)
	}
	if v := findRaw(t, e.db, collRecords, int64(5)).Lookup("_id"); v.Type != bson.TypeDouble {
		t.Fatalf("the document was overwritten: _id %v", v)
	}
}

// TestLiveTamperedRecord0IsAConflict: a record 0 altered in this ledger's own copy is a conflict
// (reported, never overwritten), not a copy of another ledger: the copy goes on.
func TestLiveTamperedRecord0IsAConflict(t *testing.T) {
	e := newLiveEnv(t)
	mustSync(t, e.replicator(t))
	forged := sha256Hex([]byte("altered genesis"))
	if _, err := e.db.Collection(collRecords).UpdateOne(bg, bson.D{{Key: "_id", Value: int64(0)}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "h", Value: forged}}}}); err != nil {
		t.Fatal(err)
	}
	appendSample(t, e, 500)
	r := e.replicator(t)
	n, err := r.SyncOnce(bg)
	var re *refusedError
	if n != 1 || errors.As(err, &re) || !errors.Is(err, ErrIntegrity) || !strings.Contains(err.Error(), "different record 0") {
		t.Fatalf("SyncOnce = %d, %v", n, err)
	}
	if st := r.Status(); !st.Connected || !st.HasData || st.LastSeq != e.st.Head().Seq {
		t.Fatalf("status %+v", st)
	}
	// Also without the replication state: record 0 does not authenticate as a genesis record.
	if _, err := e.db.Collection(collMeta).DeleteOne(bg, bson.D{{Key: "_id", Value: metaID}}); err != nil {
		t.Fatal(err)
	}
	r2 := e.replicator(t)
	if n, err := r2.SyncOnce(bg); n != 0 || errors.As(err, &re) || !strings.Contains(fmt.Sprint(err), "different record 0") {
		t.Fatalf("without meta: %d, %v", n, err)
	}
	if h, _ := rawString(findRaw(t, e.db, collRecords, int64(0)), "h"); h != forged {
		t.Fatal("record 0 was overwritten")
	}
}

// TestLiveIncidentDocumentWithForgedSeq: an incident document whose seq is not a ledger seq, or
// names no newer record of the incident, blocks its updates: that is reported, not taken for a
// newer record.
func TestLiveIncidentDocumentWithForgedSeq(t *testing.T) {
	e := newLiveEnv(t)
	r := e.replicator(t)
	mustSync(t, r)
	incs := e.db.Collection(collIncidents)
	for i, forged := range []any{"x", int64(1_000_000)} {
		if _, err := incs.UpdateOne(bg, bson.D{{Key: "_id", Value: incidentID2}}, bson.D{{Key: "$set", Value: bson.D{{Key: "seq", Value: forged}}}}); err != nil {
			t.Fatal(err)
		}
		e.clk.Advance(10 * time.Second)
		seq := mustAppend(t, e.st, model.TypeIncidentUpdate, incident(incidentID2, true, fmt.Sprintf("update %d", i))).Seq
		_, err := r.SyncOnce(bg)
		want := fmt.Sprintf(`incident %q: MongoDB holds`, incidentID2)
		if !errors.Is(err, ErrIntegrity) || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), fmt.Sprintf("not updated with record %d", seq)) {
			t.Fatalf("forged seq %v: %v", forged, err)
		}
		if st := r.Status(); !strings.Contains(st.LastError, want) {
			t.Fatalf("forged seq %v: status %+v", forged, st)
		}
		if v := findRaw(t, e.db, collIncidents, incidentID2).Lookup("seq"); !v.Equal(mustValue(t, forged)) {
			t.Fatalf("forged seq %v: the document was overwritten (seq %v)", forged, v)
		}
	}
	if !loggedContaining(e, "integrity problem") {
		t.Errorf("not logged: %q", e.logs.messages())
	}
	// Without the forged document, a full re-check (meta deleted) stores the incident again; a
	// second one meets documents that hold newer records of their incidents, which is no problem.
	if _, err := incs.DeleteOne(bg, bson.D{{Key: "_id", Value: incidentID2}}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := e.db.Collection(collMeta).DeleteOne(bg, bson.D{{Key: "_id", Value: metaID}}); err != nil {
			t.Fatal(err)
		}
		r2 := e.replicator(t)
		if _, err := r2.SyncOnce(bg); err != nil {
			t.Fatalf("full re-check %d: %v", i, err)
		}
		if st := r2.Status(); st.LastError != "" {
			t.Fatalf("status after full re-check %d: %+v", i, st)
		}
	}
	requireVerifyOK(t, mustVerify(t, e, e.st, e.st.PublicKey()))
}

// mustValue encodes v as a BSON value.
func mustValue(t *testing.T, v any) bson.RawValue {
	t.Helper()
	raw := mustMarshal(t, bson.D{{Key: "v", Value: v}})
	return raw.Lookup("v")
}
