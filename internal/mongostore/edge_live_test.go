package mongostore

import (
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"attmonitor/internal/ledger"
	"attmonitor/internal/model"
)

// Live tests (ATTMON_MONGO=1) of less common paths of re-validation, re-checks and Verify.

// TestLiveMetaAlteredWhileRunning: a replication state changed behind the running replicator
// (another last_hash, an invalid last_seq) is validated again; a state that no longer matches the
// ledger is replaced and the whole copy re-checked, as on a restart.
func TestLiveMetaAlteredWhileRunning(t *testing.T) {
	for name, value := range map[string]any{"last_hash": sha256Hex([]byte("altered")), "last_seq": "x"} {
		t.Run(name, func(t *testing.T) {
			e := newLiveEnv(t)
			cr := &countingReader{Store: e.st}
			r := e.replicator(t, func(o *Options) { o.Reader = cr })
			mustSync(t, r)
			setField(t, e.db.Collection(collMeta), metaID, name, value)
			e.clk.Advance(2 * tailCheckEvery)
			scans := len(cr.scans())
			n, err := r.SyncOnce(bg)
			if n != 0 || !errors.Is(err, ErrIntegrity) || !strings.Contains(err.Error(), "re-checking the whole copy") {
				t.Fatalf("SyncOnce = %d, %v", n, err)
			}
			if got := cr.scans()[scans:]; !slices.Equal(got, []uint64{0}) {
				t.Fatalf("scans %v, want a full re-check", got)
			}
			meta := findRaw(t, e.db, collMeta, metaID)
			if why, _ := rawString(meta, "reset_reason"); why == "" {
				t.Fatalf("meta %v", meta)
			}
			if st := r.Status(); st.LastError != "" { // the re-check found the copy consistent
				t.Fatalf("status %+v", st)
			}
			requireFullCopy(t, e, r)
		})
	}
}

// TestLiveFullRecheckRetriesWaitingBlobs: a full re-check (the replication state deleted) reads
// every blob again, including those waiting for a retry.
func TestLiveFullRecheckRetriesWaitingBlobs(t *testing.T) {
	e := newLiveEnv(t)
	fr := &flakyBlobReader{Store: e.st}
	fr.set("", errSharingViolation)
	r := e.replicator(t, func(o *Options) { o.Reader = fr })
	mustSync(t, r)
	if st := r.Status(); !strings.Contains(st.LastError, "3 blob(s)") {
		t.Fatalf("status %+v", st)
	}
	if _, err := e.db.Collection(collMeta).DeleteOne(bg, bson.D{{Key: "_id", Value: metaID}}); err != nil {
		t.Fatal(err)
	}
	e.clk.Advance(2 * tailCheckEvery)
	mustSync(t, r) // the re-check from 0 meets the blobs again: still unreadable
	if st := r.Status(); !strings.Contains(st.LastError, "3 blob(s)") {
		t.Fatalf("status after the re-check %+v", st)
	}
	if got := pendingInMeta(t, e); len(got) != 3 {
		t.Fatalf("meta lists %v", got)
	}
	if loggedContaining(e, "every blob waiting for a retry") {
		t.Fatalf("logged as copied while still unreadable: %q", e.logs.messages())
	}
	fr.set("", nil)
	mustSync(t, r)
	if st := r.Status(); st.LastError != "" {
		t.Fatalf("status %+v", st)
	}
	if !loggedContaining(e, "every blob waiting for a retry has been copied") {
		t.Errorf("not logged: %q", e.logs.messages())
	}
	requireFullCopy(t, e, r)
}

// shortScanReader hides the newest records from Scan (as if they were appended after Verify's
// ledger scan) but not from Record.
type shortScanReader struct {
	*ledger.Store
	last uint64
}

func (s shortScanReader) Scan(from uint64, fn func(model.Envelope, model.Body) error) error {
	return s.Store.Scan(from, func(env model.Envelope, body model.Body) error {
		if body.Seq > s.last {
			return nil
		}
		return fn(env, body)
	})
}

// TestLiveVerifyBlobOfRecordAppendedAfterScan: the replicator stores a blob before the record that
// references it. A blob document whose record was appended after Verify scanned the ledger, and
// is not copied yet, is no unreferenced (forged) blob.
func TestLiveVerifyBlobOfRecordAppendedAfterScan(t *testing.T) {
	e := newLiveEnv(t)
	items := ledgerItems(t, e.st)
	scanned := e.st.Head().Seq
	e.clk.Advance(10 * time.Second)
	blob := mustBlob(t, e.st, []byte("a page captured after the scan"))
	seq := mustAppend(t, e.st, model.TypeLocalLink, model.LocalLink{Interface: "Wi-Fi", RawSHA256: blob}, blob).Seq
	mustSync(t, e.replicator(t))
	// As if the replicator had stopped after storing the blob, before the record and meta.
	if _, err := e.db.Collection(collRecords).DeleteOne(bg, bson.D{{Key: "_id", Value: int64(seq)}}); err != nil {
		t.Fatal(err)
	}
	setField(t, e.db.Collection(collMeta), metaID, "last_seq", int64(scanned))
	setField(t, e.db.Collection(collMeta), metaID, "last_hash", items[scanned].env.H)
	res := mustVerify(t, e, shortScanReader{Store: e.st, last: scanned}, e.st.PublicKey())
	requireVerifyOK(t, res)
	if res.BlobsChecked != 4 || res.Checked != len(items) {
		t.Fatalf("verification %+v", res)
	}
	// With the whole ledger scanned, the record is simply not copied yet.
	res = mustVerify(t, e, e.st, e.st.PublicKey())
	requireVerifyOK(t, res)
	if res.NotCopied != 1 {
		t.Fatalf("verification %+v", res)
	}
}

// dropOnceReader drops a collection the first time a re-check scan from seq 0 reaches seq 10.
type dropOnceReader struct {
	*ledger.Store
	db   *mongo.Database
	coll string
	once sync.Once
	t    *testing.T
}

func (d *dropOnceReader) Scan(from uint64, fn func(model.Envelope, model.Body) error) error {
	return d.Store.Scan(from, func(env model.Envelope, body model.Body) error {
		if from == 0 && body.Seq == 10 {
			d.once.Do(func() {
				if err := d.db.Collection(d.coll).Drop(bg); err != nil {
					d.t.Error(err)
				}
			})
		}
		return fn(env, body)
	})
}

// TestLiveCollectionReplacedDuringRecheck: a collection dropped while the whole copy is being
// checked again makes the replicator validate the copy again and check it once more.
func TestLiveCollectionReplacedDuringRecheck(t *testing.T) {
	e := newLiveEnv(t)
	mustSync(t, e.replicator(t))
	if err := e.db.Collection(collBlobs).Drop(bg); err != nil { // makes the restart re-check
		t.Fatal(err)
	}
	dr := &dropOnceReader{Store: e.st, db: e.db, coll: collIncidents, t: t}
	r := e.replicator(t, func(o *Options) { o.Reader = dr })
	mustSync(t, r)
	if n := count(t, e.db, collIncidents); n != 2 {
		t.Fatalf("%d incident documents", n)
	}
	if n := count(t, e.db, collBlobs); n != 3 {
		t.Fatalf("%d blob documents", n)
	}
	if !loggedContaining(e, "changed behind the replicator's back") {
		t.Errorf("not logged: %q", e.logs.messages())
	}
	requireFullCopy(t, e, r)
	// The state now records the new collections: a restart checks nothing again.
	cr := &countingReader{Store: e.st}
	mustSync(t, e.replicator(t, func(o *Options) { o.Reader = cr }))
	if got := cr.scans(); len(got) != 0 {
		t.Fatalf("restart scanned from %v", got)
	}
}
