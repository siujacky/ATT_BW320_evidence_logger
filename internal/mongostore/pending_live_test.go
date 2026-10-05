package mongostore

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"attmonitor/internal/contracts"
	"attmonitor/internal/ledger"
)

// Live tests (ATTMON_MONGO=1) of blobs that cannot be read from the ledger when their records are
// copied.

// errSharingViolation is what Windows returns while another program (an antivirus scanner, a
// backup tool) holds a file without read sharing.
var errSharingViolation = errors.New("open blob: The process cannot access the file because it is being used by another process.")

// flakyBlobReader is the ledger with GetBlob failing on demand.
type flakyBlobReader struct {
	*ledger.Store
	mu    sync.Mutex
	fail  map[string]error // blob id ("" = every blob) -> the error GetBlob returns
	other map[string][]byte
}

func (f *flakyBlobReader) set(id string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail == nil {
		f.fail = map[string]error{}
	}
	if err == nil {
		delete(f.fail, id)
		return
	}
	f.fail[id] = err
}

func (f *flakyBlobReader) GetBlob(id string) ([]byte, error) {
	f.mu.Lock()
	err, ok := f.fail[id]
	if !ok {
		err, ok = f.fail[""]
	}
	content, swapped := f.other[id]
	f.mu.Unlock()
	switch {
	case ok:
		return nil, err
	case swapped:
		return content, nil
	}
	return f.Store.GetBlob(id)
}

func pendingInMeta(t *testing.T, e *liveEnv) []string {
	t.Helper()
	arr, ok := findRaw(t, e.db, collMeta, metaID).Lookup("pending_blobs").ArrayOK()
	if !ok {
		return nil
	}
	vals, err := arr.Values()
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, v := range vals {
		id, _ := rawString(v.Document(), "id")
		ids = append(ids, id)
	}
	return ids
}

// TestLiveBlobReadErrorIsRetried: a blob that cannot be read for a while (a file locked by
// another program) is not a permanent gap: its records are copied, the blob waits for a retry
// (also across a restart), and Status says so meanwhile without calling it an integrity problem.
func TestLiveBlobReadErrorIsRetried(t *testing.T) {
	for _, restart := range []bool{false, true} {
		t.Run(fmt.Sprintf("restart=%v", restart), func(t *testing.T) {
			e := newLiveEnv(t)
			items := ledgerItems(t, e.st)
			fr := &flakyBlobReader{Store: e.st}
			fr.set("", errSharingViolation)
			r := e.replicator(t, func(o *Options) { o.Reader = fr })
			n, err := r.SyncOnce(bg)
			if err != nil || n != len(items) {
				t.Fatalf("pass with unreadable blobs: %d, %v", n, err)
			}
			if c := count(t, e.db, collBlobs); c != 0 {
				t.Fatalf("%d blob documents", c)
			}
			st := r.Status()
			if !st.HasData || st.LastSeq != e.st.Head().Seq || !strings.Contains(st.LastError, "3 blob(s) could not be read from the ledger yet") ||
				!strings.Contains(st.LastError, "being used by another process") {
				t.Fatalf("status %+v", st)
			}
			if got := pendingInMeta(t, e); len(got) != 3 {
				t.Fatalf("meta lists %d blobs waiting: %v", len(got), got)
			}
			if !loggedContaining(e, "blobs could not be read from the ledger") {
				t.Errorf("not logged: %q", e.logs.messages())
			}
			res := mustVerify(t, e, e.st, e.st.PublicKey())
			if res.OK || res.BlobsMissing != 3 || !hasProblem(res, "reads it again on later passes") {
				t.Fatalf("verification while the blobs wait: %+v", res)
			}

			fr.set("", nil)
			if restart {
				r = e.replicator(t) // a new process: the replication state lists the blobs
			}
			if n, err := r.SyncOnce(bg); n != 0 || err != nil {
				t.Fatalf("pass after the blobs became readable: %d, %v", n, err)
			}
			if c := count(t, e.db, collBlobs); c != 3 {
				t.Fatalf("%d blob documents after the retry", c)
			}
			if st := r.Status(); st.LastError != "" {
				t.Fatalf("status after the retry: %+v", st)
			}
			appendSample(t, e, 600) // the next write of the replication state no longer lists them
			mustSync(t, r)
			if got := pendingInMeta(t, e); len(got) != 0 {
				t.Fatalf("meta still lists %v", got)
			}
			requireVerifyOK(t, mustVerify(t, e, e.st, e.st.PublicKey()))
		})
	}
}

// TestLiveBlobMissingFromLedgerIsReported: a blob that the ledger does not have, or whose copy
// there does not match its id, is reported at once (it cannot become readable by waiting).
func TestLiveBlobMissingFromLedgerIsReported(t *testing.T) {
	e := newLiveEnv(t)
	fr := &flakyBlobReader{Store: e.st, other: map[string][]byte{e.f.netshBlob: []byte("other content")}}
	fr.set(e.f.pageBlob, fmt.Errorf("ledger: blob %s: %w", e.f.pageBlob, contracts.ErrNotFound))
	r := e.replicator(t, func(o *Options) { o.Reader = fr })
	_, err := r.SyncOnce(bg)
	if !errors.Is(err, ErrIntegrity) || !strings.Contains(err.Error(), "does not match its id") {
		t.Fatalf("SyncOnce: %v", err)
	}
	st := r.Status()
	if !strings.Contains(st.LastError, "does not match its id") || strings.Contains(st.LastError, "read again") {
		t.Fatalf("status %+v", st)
	}
	if got := pendingInMeta(t, e); len(got) != 0 {
		t.Fatalf("meta lists %v as waiting", got)
	}
	if c := count(t, e.db, collBlobs); c != 1 {
		t.Fatalf("%d blob documents, want 1 (the readable one)", c)
	}
	if !loggedContaining(e, "integrity problem") {
		t.Errorf("not logged: %q", e.logs.messages())
	}
}

// TestLiveTooManyUnreadableBlobsWait: when more blobs than the limit cannot be read, the copy
// waits for the blob store instead of leaving more gaps, and catches up once it can be read.
func TestLiveTooManyUnreadableBlobsWait(t *testing.T) {
	defer func(n int) { maxPendingBlobs = n }(maxPendingBlobs)
	maxPendingBlobs = 2
	e := newLiveEnv(t)
	fr := &flakyBlobReader{Store: e.st}
	fr.set("", errSharingViolation)
	r := e.replicator(t, func(o *Options) { o.Reader = fr })
	n, err := r.SyncOnce(bg)
	if err == nil || errors.Is(err, ErrIntegrity) || !strings.Contains(err.Error(), "the copy waits") {
		t.Fatalf("SyncOnce = %d, %v", n, err)
	}
	st := r.Status()
	if st.LastSeq >= firstRef(ledgerItems(t, e.st), e.f.bigBlob) || !strings.Contains(st.LastError, "the copy waits") {
		t.Fatalf("status %+v", st)
	}
	fr.set("", nil)
	mustSync(t, r)
	requireFullCopy(t, e, r)
	if st := r.Status(); st.LastError != "" {
		t.Fatalf("status %+v", st)
	}
}
