package mongostore

import (
	"cmp"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

var (
	// ErrClosed is returned by SyncOnce after Close.
	ErrClosed = errors.New("mongostore: replicator closed")
	// ErrIntegrity is wrapped by errors that report a disagreement between the MongoDB copy and
	// the ledger: a different record at the same seq (never overwritten), a database holding a
	// copy of another ledger (refused), records or blobs that could not be copied.
	ErrIntegrity = errors.New("mongostore: the MongoDB copy disagrees with the ledger")
)

const (
	defaultInterval       = 5 * time.Second
	defaultBatchSize      = 500
	maxBatchSize          = 10000
	defaultConnectTimeout = 3 * time.Second
	minOpTimeout          = 30 * time.Second
	countsEvery           = 30 * time.Second
	tailCheckEvery        = time.Minute
	blobBatchBytes        = 32 << 20
	blobBatchDocs         = 500
	blobReadAttempts      = 3
	maxPreviousMetaBytes  = 64 << 10
	// bySeqMax: a pass with fewer new records than this reads them by seq rather than scanning.
	bySeqMax = 64
	// maxResyncs bounds how often one pass validates the copy again after finding that it
	// changed behind the replicator's back.
	maxResyncs = 2
	// pendingRetryPerPass bounds the blobs waiting for a retry that one pass reads again (the
	// oldest first).
	pendingRetryPerPass = 50
)

// maxPendingBlobs bounds the blobs waiting for a retry: when more cannot be read, the copy waits
// until the ledger's blob store can be read again (a variable for tests).
var maxPendingBlobs = 1000

// copyCollections are the collections whose identity (UUID) the replication state records: a
// collection that was dropped, or replaced by a restore, has another UUID, and the copy it held is
// checked again.
var copyCollections = []string{collRecords, collBlobs, collIncidents}

// Synchronization states, used to log once per state change.
const (
	healthOK          = "ok"
	healthUnreachable = "unreachable"
	healthFailing     = "failing"
	healthRefused     = "refused"
)

// Options configures a Replicator.
type Options struct {
	URI      string // MongoDB connection string ("" → DefaultURI); credentials are never shown
	Database string // database name ("" → DefaultDatabase)
	// Reader is the ledger to copy (required). A reader that also has a Head() model.Ref method
	// (ledger.Store) lets a pass with nothing new skip reading the ledger, lets a few new records
	// be read by seq instead of scanning the active segment, and keeps Status's lag exact (also
	// while MongoDB is down).
	Reader         contracts.LedgerReader
	StoreBlobs     bool          // also copy the exact bytes of blobs up to 15 MB
	Interval       time.Duration // pause between passes (default 5s)
	BatchSize      int           // records per insert (default 500, at most 10000)
	ConnectTimeout time.Duration // connecting and server selection (default 3s)
	Logger         *slog.Logger
	Now            func() time.Time
}

// Replicator copies the ledger into MongoDB. All methods are safe for concurrent use.
type Replicator struct {
	o         Options
	log       *slog.Logger
	shown     string // the URI without credentials
	opTimeout time.Duration

	closed    atomic.Bool
	closeOnce sync.Once
	done      chan struct{} // closed by Close: wakes Run
	sem       chan struct{} // held while a pass or Close runs

	// Guarded by sem.
	client        *mongo.Client
	ready         bool                   // collections and indexes ensured, resume point validated on this connection
	next          uint64                 // first seq not yet copied
	copied        bool                   // seq next-1 has been copied (passed)
	ident         *ledgerIdent           // identity of the ledger (nil until its genesis record is read)
	meta          metaState              // the replication state document as this replicator last read or wrote it
	colls         collIDs                // UUIDs of the copy's collections when the copy was last validated
	markersDirty  bool                   // the replication state does not record colls and store_blobs yet
	sweep         string                 // why records 0..next-1 must be checked again ("" when they need not)
	zeroKnown     bool                   // MongoDB holds record 0 (checked with the tail)
	pending       map[string]pendingBlob // blobs that could not be read from the ledger yet
	countsAt      time.Time
	tailSeq       uint64 // newest copied record known to be in MongoDB …
	tailHash      string // … and the h stored there (another h than the ledger's: a reported conflict)
	tailKnown     bool
	tailCheckedAt time.Time
	passProblems  int    // integrity problems found in the current pass
	passLast      string // the last of them
	passBlobFails int    // blobs that could not be read from the ledger in the current pass

	mu sync.Mutex
	st replState
}

// metaState is what the replication state document holds, as far as the replicator knows.
type metaState struct {
	present bool
	seq     int64  // last_seq
	hash    string // last_hash
}

// collIDs maps the names of the copy's collections to their UUIDs (hex).
type collIDs map[string]string

// pendingBlob is a blob that could not be read from the ledger (for a reason other than its
// absence, such as a file briefly locked by another program) when records referencing it were
// copied. It is read again on later passes, also after a restart (the replication state lists
// it).
type pendingBlob struct {
	seq   uint64    // the first record referencing it (first_seq of its document)
	since time.Time // the first failure
	err   string    // the last error
}

// replState is what Status reports (guarded by Replicator.mu).
type replState struct {
	connected      bool
	resumeKnown    bool // the copy's resume point has been read (lag is meaningful)
	lastSeq        uint64
	hasData        bool
	head           uint64
	headKnown      bool
	records, blobs int64
	lastSync       time.Time
	lastErr        string // the last failure; cleared by a completed pass
	integrity      string // the last integrity problem; kept until a full re-check finds none
	pending        int    // blobs waiting for a retry …
	pendingErr     string // … and the last error reading one of them
	health         logGate
	integrityGate  logGate
	pendingGate    logGate
}

// unreachableError marks a failure to reach MongoDB.
type unreachableError struct{ err error }

func (e *unreachableError) Error() string { return "MongoDB unreachable: " + e.err.Error() }
func (e *unreachableError) Unwrap() error { return e.err }

// refusedError: the database holds a copy of another ledger.
type refusedError struct{ why string }

func (e *refusedError) Error() string {
	return "mongostore: refusing to copy into this database: " + e.why
}
func (e *refusedError) Unwrap() error { return ErrIntegrity }

// resyncError: the copy changed behind the replicator's back (database dropped, replication state
// deleted or older, a collection replaced, the newest copied record gone). The copy is then
// validated again, as on a new connection, instead of being written on.
type resyncError struct{ why string }

func (e *resyncError) Error() string { return "mongostore: the MongoDB copy changed: " + e.why }

// New validates o and returns a Replicator. It does not contact MongoDB.
func New(o Options) (*Replicator, error) {
	if o.Reader == nil {
		return nil, errors.New("mongostore: Options.Reader is required")
	}
	if o.URI == "" {
		o.URI = DefaultURI
	}
	if err := checkURI(o.URI); err != nil {
		return nil, err
	}
	if o.Database == "" {
		o.Database = DefaultDatabase
	}
	if err := checkDatabaseName(o.Database); err != nil {
		return nil, err
	}
	if o.Interval <= 0 {
		o.Interval = defaultInterval
	}
	if o.BatchSize <= 0 {
		o.BatchSize = defaultBatchSize
	}
	o.BatchSize = min(o.BatchSize, maxBatchSize)
	if o.ConnectTimeout <= 0 {
		o.ConnectTimeout = defaultConnectTimeout
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Replicator{
		o:         o,
		log:       o.Logger.With("component", "mongostore"),
		shown:     RedactURI(o.URI),
		opTimeout: max(minOpTimeout, 10*o.ConnectTimeout),
		done:      make(chan struct{}),
		sem:       make(chan struct{}, 1),
	}, nil
}

// Run synchronizes until ctx is done (or Close), then returns nil. It never gives up because
// MongoDB is unreachable: failed passes are retried after a bounded backoff (Interval doubled per
// failure, at most one minute or Interval), and failures are logged once per state change and as
// a reminder at most once an hour.
func (r *Replicator) Run(ctx context.Context) error {
	failures := 0
	for ctx.Err() == nil && !r.closed.Load() {
		_, completed, _ := r.sync(ctx)
		delay := r.o.Interval
		if completed {
			failures = 0
		} else {
			failures++
			delay = backoffDelay(r.o.Interval, failures)
		}
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-r.done:
			t.Stop()
			return nil
		case <-t.C:
		}
	}
	return nil
}

// SyncOnce runs one pass: it (re)connects if needed and copies every ledger record above the
// newest copied seq. copied counts the record documents inserted by this pass. An error wrapping
// ErrIntegrity after a completed pass reports problems found on the way (Status().LastError keeps
// the last one).
func (r *Replicator) SyncOnce(ctx context.Context) (copied int, err error) {
	copied, _, err = r.sync(ctx)
	return copied, err
}

// Status describes the copy. It does not contact MongoDB.
func (r *Replicator) Status() model.MongoStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := model.MongoStatus{
		Enabled:   true,
		Connected: r.st.connected,
		Database:  r.o.Database,
		URI:       r.shown,
		LastSeq:   r.st.lastSeq,
		HasData:   r.st.hasData,
		Records:   r.st.records,
		Blobs:     r.st.blobs,
	}
	if r.st.headKnown && r.st.resumeKnown {
		switch {
		case !r.st.hasData:
			s.Lag = r.st.head
			if s.Lag < math.MaxUint64 {
				s.Lag++ // records 0..head
			}
		case r.st.head > r.st.lastSeq:
			s.Lag = r.st.head - r.st.lastSeq
		}
	}
	if !r.st.lastSync.IsZero() {
		s.LastSync = r.st.lastSync.UTC().Format(time.RFC3339Nano)
	}
	var parts []string
	if r.st.lastErr != "" {
		parts = append(parts, r.st.lastErr)
	}
	if r.st.integrity != "" {
		parts = append(parts, r.st.integrity)
	}
	if r.st.pending > 0 {
		parts = append(parts, fmt.Sprintf("%d blob(s) could not be read from the ledger yet and are read again on later passes (%s)", r.st.pending, r.st.pendingErr))
	}
	s.LastError = strings.Join(parts, "; ")
	return s
}

// Close stops Run and further passes, and disconnects. It waits for a running pass until ctx is
// done; that pass then releases the connection itself.
func (r *Replicator) Close(ctx context.Context) error {
	r.closed.Store(true)
	r.closeOnce.Do(func() { close(r.done) })
	select {
	case r.sem <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-r.sem }()
	return r.disconnectLocked(ctx)
}

func (r *Replicator) disconnectLocked(ctx context.Context) error {
	r.mu.Lock()
	r.st.connected = false
	r.mu.Unlock()
	c := r.client
	r.client, r.ready = nil, false
	if c == nil {
		return nil
	}
	return c.Disconnect(ctx)
}

// ---------------------------------------------------------------- one pass

// sync runs one pass under sem. completed is true when the pass copied everything it saw (an
// ErrIntegrity error may still report problems found on the way).
func (r *Replicator) sync(ctx context.Context) (copied int, completed bool, err error) {
	if r.closed.Load() {
		return 0, false, ErrClosed
	}
	select {
	case r.sem <- struct{}{}:
	case <-ctx.Done():
		return 0, false, ctx.Err()
	}
	defer func() { <-r.sem }()
	if r.closed.Load() {
		return 0, false, ErrClosed
	}
	copied, completed, err = r.syncLocked(ctx)
	r.finishLocked(ctx, completed, err)
	if r.closed.Load() {
		// Close stopped waiting for this pass: release the connection now.
		dctx, cancel := context.WithTimeout(context.Background(), r.o.ConnectTimeout)
		_ = r.disconnectLocked(dctx)
		cancel()
	}
	return copied, completed, err
}

func (r *Replicator) syncLocked(ctx context.Context) (copied int, completed bool, err error) {
	defer func() {
		// The replicator runs inside the evidence service: a bug here must not stop the service.
		if p := recover(); p != nil {
			r.ready = false
			r.log.Error("MongoDB replication: internal error (recovered)", "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
			copied, completed, err = 0, false, fmt.Errorf("mongostore: internal error: %v", p)
		}
	}()
	r.passProblems, r.passLast, r.passBlobFails = 0, "", 0
	// The ledger's head first: Status's lag keeps growing while MongoDB is down.
	head, headOK := r.readerHead()
	if headOK {
		r.noteHead(head)
	}
	for resyncs := 0; ; resyncs++ {
		n, err := r.passLocked(ctx, head, headOK)
		copied += n
		var rs *resyncError
		if !errors.As(err, &rs) {
			if err != nil {
				return copied, false, err
			}
			break
		}
		// Validate the copy again, as on a new connection, before writing on.
		r.ready = false
		if resyncs >= maxResyncs {
			return copied, false, err
		}
		r.log.Warn("MongoDB copy changed behind the replicator's back; validating it again", "database", r.o.Database, "why", rs.why)
	}
	r.refreshCountsLocked(ctx, copied > 0)
	return copied, true, r.passErr()
}

// passLocked runs the steps of a pass that a validation of the copy restarts: connecting
// (validating the copy when needed), the check of the tail, the retry of blobs that could not be
// read, the copy of new records, and a pending re-check of the records copied before. It returns
// the record documents inserted.
func (r *Replicator) passLocked(ctx context.Context, head uint64, headOK bool) (int, error) {
	if err := r.connectLocked(ctx); err != nil {
		return 0, err
	}
	if err := r.checkTailLocked(ctx); err != nil {
		return 0, err
	}
	if err := r.retryPendingLocked(ctx); err != nil {
		return 0, r.classify(ctx, err)
	}
	copied := 0
	if !headOK || !r.copied || head >= r.next { // else nothing new
		n, err := r.copyLocked(ctx, head, headOK)
		copied += n
		if err != nil {
			return copied, r.classify(ctx, err)
		}
	}
	if r.sweep != "" && !shortDeadline(ctx) {
		n, err := r.sweepLocked(ctx)
		copied += n
		if err != nil {
			return copied, r.classify(ctx, err)
		}
	}
	return copied, nil
}

// shortDeadline reports whether ctx ends soon (the final pass at shutdown): a re-check of the
// whole copy is then left to a later pass, so that the new records are copied within the budget.
func shortDeadline(ctx context.Context) bool {
	d, ok := ctx.Deadline()
	return ok && time.Until(d) < minOpTimeout
}

// passErr reports the integrity problems found by the current pass (nil if none).
func (r *Replicator) passErr() error {
	if r.passProblems == 0 {
		return nil
	}
	return fmt.Errorf("%w: %d problem(s) in this pass; the last: %s", ErrIntegrity, r.passProblems, r.passLast)
}

// classify marks err as an unreachable-MongoDB error when MongoDB no longer answers (the next
// pass then reconnects and re-validates its resume point).
func (r *Replicator) classify(ctx context.Context, err error) error {
	var (
		ue *unreachableError
		rs *resyncError
	)
	if errors.As(err, &ue) || errors.As(err, &rs) || ctx.Err() != nil {
		return err
	}
	if r.client != nil {
		pctx, cancel := context.WithTimeout(ctx, r.o.ConnectTimeout)
		perr := r.client.Ping(pctx, nil)
		cancel()
		if perr == nil {
			return err
		}
	}
	r.ready = false
	return &unreachableError{err: err}
}

// finishLocked records the outcome of a pass and logs state changes.
func (r *Replicator) finishLocked(ctx context.Context, completed bool, err error) {
	if !completed && ctx.Err() != nil {
		return // interrupted (shutdown): not a state change
	}
	var (
		ue    *unreachableError
		re    *refusedError
		state string
		msg   string
	)
	switch {
	case completed:
		state = healthOK
	case errors.As(err, &ue):
		state = healthUnreachable
	case errors.As(err, &re):
		state = healthRefused
	default:
		state = healthFailing
	}
	if err != nil {
		msg = clip(printable(err.Error()), maxProblemLen)
	}
	now := r.o.Now()
	r.mu.Lock()
	if completed {
		r.st.connected = true
		r.st.lastSync = now
		r.st.lastErr = ""
	} else {
		r.st.connected = state != healthUnreachable
		r.st.lastErr = msg
	}
	log, suppressed := r.st.health.allow(state, now, state != healthOK)
	lastSeq, hasData := r.st.lastSeq, r.st.hasData
	r.mu.Unlock()
	if !log {
		return
	}
	switch state {
	case healthOK:
		r.log.Info("MongoDB copy of the evidence ledger is up to date", "database", r.o.Database, "uri", r.shown, "last_seq", lastSeq, "has_data", hasData)
	case healthUnreachable:
		r.log.Warn("MongoDB is unreachable; evidence collection is unaffected and the copy catches up when MongoDB is back",
			"uri", r.shown, "err", msg, "suppressed", suppressed)
	case healthRefused:
		r.log.Error("MongoDB copy refused", "database", r.o.Database, "err", msg, "suppressed", suppressed)
	default:
		r.log.Warn("MongoDB copy: synchronization failed; retrying", "database", r.o.Database, "err", msg, "suppressed", suppressed)
	}
}

// connectLocked creates the client on first use and, on every (re)connection, checks that
// MongoDB answers, ensures the collections and indexes and validates the copy (resume point,
// identity, collections).
func (r *Replicator) connectLocked(ctx context.Context) error {
	if r.client == nil {
		c, err := mongo.Connect(clientOptions(r.o.URI, r.o.ConnectTimeout))
		if err != nil {
			// e.g. the SRV records of a mongodb+srv URI cannot be resolved
			return &unreachableError{err: connectError(r.o.URI, err)}
		}
		r.client = c
	}
	if r.ready {
		return nil
	}
	pctx, cancel := context.WithTimeout(ctx, r.o.ConnectTimeout)
	err := r.client.Ping(pctx, nil)
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return &unreachableError{err: err}
	}
	colls, err := r.ensureCollectionsLocked(ctx)
	if err != nil {
		return r.classify(ctx, err)
	}
	r.colls = colls
	if err := r.resumeLocked(ctx); err != nil {
		return r.classify(ctx, err)
	}
	r.ready = true
	r.tailCheckedAt = r.o.Now()
	return nil
}

// checkTailLocked checks, at most once a minute, that the copy is still the one this replicator
// has been writing: the database may have been dropped or restored, or the replication state
// deleted, behind its back without the connection failing. A copy that changed is validated
// again (resyncError).
func (r *Replicator) checkTailLocked(ctx context.Context) error {
	now := r.o.Now()
	if now.Sub(r.tailCheckedAt) < tailCheckEvery && !now.Before(r.tailCheckedAt) {
		return nil
	}
	why, err := r.copyChangedLocked(ctx)
	if err != nil {
		return r.classify(ctx, err)
	}
	r.tailCheckedAt = now
	if why != "" {
		return &resyncError{why: why}
	}
	return nil
}

// copyChangedLocked describes how the copy differs from what this replicator last wrote or
// validated ("" when it does not): a collection with another UUID (dropped, or replaced by a
// restore), another replication state, or a newest copied record that is gone or altered. A
// missing record 0 starts a re-check of the whole copy.
func (r *Replicator) copyChangedLocked(ctx context.Context) (string, error) {
	colls, err := r.collectionIDsLocked(ctx)
	if err != nil {
		return "", err
	}
	if name := changedCollection(r.colls, colls); name != "" {
		return fmt.Sprintf("the %s collection was dropped or replaced", name), nil
	}
	meta, err := r.findOneRaw(ctx, collMeta, metaID, "last_seq", "last_hash")
	if err != nil {
		return "", err
	}
	if why := r.metaChange(meta); why != "" {
		return why, nil
	}
	if r.tailKnown {
		h, found, err := r.storedHash(ctx, r.tailSeq)
		if err != nil {
			return "", err
		}
		if !found || h != r.tailHash {
			return fmt.Sprintf("record %d, the newest copied, is no longer in MongoDB as it was stored", r.tailSeq), nil
		}
	}
	if r.zeroKnown {
		_, found, err := r.storedHash(ctx, 0)
		if err != nil {
			return "", err
		}
		if !found {
			r.zeroKnown = false
			r.log.Warn("MongoDB copy: record 0 is missing (records were deleted); checking the whole copy again", "database", r.o.Database)
			r.startSweep("record 0 is missing from MongoDB (records were deleted)")
		}
	}
	return "", nil
}

// metaChange describes how the replication state document meta (last_seq and last_hash, nil
// when absent) differs from what this replicator last read or wrote ("" when it does not).
func (r *Replicator) metaChange(meta bson.Raw) string {
	switch {
	case meta == nil && r.meta.present:
		return "its replication state (meta) was deleted (database dropped or meta removed)"
	case meta == nil:
		return ""
	case !r.meta.present:
		return "a replication state (meta) appeared that this replicator did not write"
	}
	ls, ok := rawInt64(meta, "last_seq")
	lh, _ := rawString(meta, "last_hash")
	switch {
	case !ok:
		return "its replication state (meta) no longer has a valid last_seq"
	case ls < r.meta.seq:
		return fmt.Sprintf("its replication state (meta) went back from record %d to record %d (an older copy restored?)", r.meta.seq, ls)
	case ls != r.meta.seq || lh != r.meta.hash:
		return fmt.Sprintf("its replication state (meta) was changed (record %d, last written: %d)", ls, r.meta.seq)
	}
	return ""
}

// describeMetaLocked explains why the replication state no longer is what this replicator last
// read or wrote.
func (r *Replicator) describeMetaLocked(ctx context.Context) string {
	meta, err := r.findOneRaw(ctx, collMeta, metaID, "last_seq", "last_hash")
	if err == nil {
		if why := r.metaChange(meta); why != "" {
			return why
		}
	}
	return "its replication state (meta) was changed"
}

func (r *Replicator) coll(name string) *mongo.Collection {
	return r.client.Database(r.o.Database).Collection(name)
}

func (r *Replicator) opCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, r.opTimeout)
}

// ensureCollectionsLocked creates the collections of the copy and the indexes of records where
// they are missing, and returns the UUIDs of the collections.
func (r *Replicator) ensureCollectionsLocked(ctx context.Context) (collIDs, error) {
	if err := r.ensureIndexesLocked(ctx); err != nil { // creates records
		return nil, err
	}
	ids, err := r.collectionIDsLocked(ctx)
	if err != nil {
		return nil, err
	}
	created := false
	for _, name := range copyCollections {
		if _, ok := ids[name]; ok {
			continue
		}
		opCtx, cancel := r.opCtx(ctx)
		err := r.client.Database(r.o.Database).CreateCollection(opCtx, name)
		cancel()
		var ce mongo.CommandError
		if err != nil && !(errors.As(err, &ce) && ce.Code == 48) { // 48: created meanwhile
			return nil, fmt.Errorf("mongostore: create collection %s: %w", name, err)
		}
		created = true
	}
	if created {
		return r.collectionIDsLocked(ctx)
	}
	return ids, nil
}

// collectionIDsLocked returns the UUIDs of the copy's collections that exist.
func (r *Replicator) collectionIDsLocked(ctx context.Context) (collIDs, error) {
	opCtx, cancel := r.opCtx(ctx)
	defer cancel()
	names := make(bson.A, len(copyCollections))
	for i, n := range copyCollections {
		names[i] = n
	}
	specs, err := r.client.Database(r.o.Database).ListCollectionSpecifications(opCtx,
		bson.D{{Key: "name", Value: bson.D{{Key: "$in", Value: names}}}})
	if err != nil {
		return nil, fmt.Errorf("mongostore: list collections: %w", err)
	}
	ids := collIDs{}
	for _, s := range specs {
		id := "none" // a view, or a server without collection UUIDs
		if s.UUID != nil && s.Type != "view" {
			id = hex.EncodeToString(s.UUID.Data)
		}
		ids[s.Name] = id
	}
	return ids, nil
}

// changedCollection returns the first copy collection that recorded names and that has another
// UUID, or no longer exists, in current ("" when none).
func changedCollection(recorded, current collIDs) string {
	for _, name := range copyCollections {
		rec, ok := recorded[name]
		if !ok {
			continue
		}
		if cur, ok := current[name]; !ok || cur != rec {
			return name
		}
	}
	return ""
}

// collsDoc is the "collections" field of the replication state.
func (r *Replicator) collsDoc() bson.D {
	d := bson.D{}
	for _, name := range copyCollections {
		if id, ok := r.colls[name]; ok {
			d = append(d, bson.E{Key: name, Value: id})
		}
	}
	return d
}

// metaCollections returns the collection UUIDs that the replication state records (false when it
// records none: written by an older version).
func metaCollections(meta bson.Raw) (collIDs, bool) {
	d, ok := meta.Lookup("collections").DocumentOK()
	if !ok {
		return nil, false
	}
	ids := collIDs{}
	for _, name := range copyCollections {
		if id, ok := rawString(d, name); ok {
			ids[name] = id
		}
	}
	return ids, true
}

func (r *Replicator) ensureIndexesLocked(ctx context.Context) error {
	opCtx, cancel := r.opCtx(ctx)
	defer cancel()
	_, err := r.coll(collRecords).Indexes().CreateMany(opCtx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "type", Value: 1}, {Key: "ts", Value: 1}}},
		{Keys: bson.D{{Key: "ts", Value: 1}}},
	})
	var ce mongo.CommandError
	if errors.As(err, &ce) && (ce.Code == 85 || ce.Code == 86) {
		// An index on the same keys exists under another name or with other options: it serves.
		r.log.Warn("MongoDB copy: an index of the records collection differs from the expected one", "err", clip(err.Error(), maxProblemLen))
		return nil
	}
	if err != nil {
		return fmt.Errorf("mongostore: create indexes: %w", err)
	}
	return nil
}

// resumeLocked determines where to resume: the replication state (meta) is trusted only when
// the ledger holds its newest record with its hash and the copy holds that record; otherwise the
// whole copy is re-checked from seq 0. A database holding another ledger's copy is refused. A
// copy that is otherwise valid but was made in other collections (dropped or restored since), or
// without the blob contents that are now wanted, is checked again (sweep) after the new records
// are copied.
func (r *Replicator) resumeLocked(ctx context.Context) error {
	r.sweep, r.zeroKnown = "", false
	if r.ident == nil {
		env, body, err := r.o.Reader.Record(0)
		switch {
		case err == nil:
			id := identFromGenesis(env, body)
			r.ident = &id
		case !errors.Is(err, contracts.ErrNotFound):
			return fmt.Errorf("mongostore: read the ledger's genesis record: %w", err)
		}
	}
	var id ledgerIdent
	if r.ident != nil {
		id = *r.ident
	}
	if id.genesisHash != "" {
		doc0, err := r.findOneRaw(ctx, collRecords, int64(0), "h", "s", "b")
		if err != nil {
			return err
		}
		if doc0 != nil {
			if h0, _ := rawString(doc0, "h"); h0 != id.genesisHash {
				// Another ledger's copy only if record 0 is that ledger's authentic genesis
				// record; otherwise the copy's record 0 was altered (reported, never overwritten).
				if fp, ok := authenticGenesis(doc0); ok {
					return &refusedError{why: fmt.Sprintf("database %q holds a copy of another ledger: its record 0 is the genesis record (h %s) of the ledger with key fingerprint %s; the genesis record of this ledger has h %s",
						r.o.Database, short(h0), short(fp), short(id.genesisHash))}
				}
				r.integrity(conflictMsg(0, h0, id.genesisHash))
			}
			r.zeroKnown = true
		}
	}
	meta, err := r.findOneRaw(ctx, collMeta, metaID)
	if err != nil {
		return err
	}
	if meta != nil {
		fp, _ := rawString(meta, "fingerprint")
		gh, _ := rawString(meta, "genesis_hash")
		if fp != "" && id.fingerprint != "" && fp != id.fingerprint {
			return &refusedError{why: fmt.Sprintf("database %q holds a copy of the ledger with key fingerprint %s, not %s", r.o.Database, short(fp), short(id.fingerprint))}
		}
		if gh != "" && id.genesisHash != "" && gh != id.genesisHash {
			return &refusedError{why: fmt.Sprintf("database %q holds a copy of the ledger whose genesis record has h %s, not %s", r.o.Database, short(gh), short(id.genesisHash))}
		}
	}
	if meta == nil {
		// A new copy, or one whose meta was deleted: the pass from seq 0 checks every document.
		r.meta = metaState{}
		r.clearPending()
		r.setResume(0, false)
		return nil
	}
	ls, ok := rawInt64(meta, "last_seq")
	if !ok {
		return r.resetMetaLocked(ctx, meta, "the replication state (meta) has no valid last_seq")
	}
	lh, _ := rawString(meta, "last_hash")
	if ls < 0 {
		r.meta = metaState{present: true, seq: ls, hash: lh}
		r.clearPending()
		r.setResume(0, false) // nothing copied yet
		r.loadMarkers(meta)
		return nil
	}
	why, stored, err := r.checkResume(ctx, uint64(ls), lh)
	if err != nil {
		return err
	}
	if why != "" {
		return r.resetMetaLocked(ctx, meta, why)
	}
	r.meta = metaState{present: true, seq: ls, hash: lh}
	r.setResume(uint64(ls)+1, true)
	r.setTail(uint64(ls), stored)
	r.loadPending(meta)
	r.loadMarkers(meta)
	return nil
}

// loadMarkers compares what the replication state says the copy is consistent with — the
// collections it was written to and whether blob contents were stored — with the copy now. Records
// 0..next-1 copied into collections that have since been dropped or replaced, or without the blob
// contents that Options.StoreBlobs now asks for, are checked again (sweep).
func (r *Replicator) loadMarkers(meta bson.Raw) {
	r.markersDirty = false
	if !r.copied {
		// Nothing copied yet: the copy from seq 0 is made as configured now.
		r.markersDirty = true
		return
	}
	recorded, ok := metaCollections(meta)
	if ok {
		if name := changedCollection(recorded, r.colls); name != "" {
			r.startSweep(fmt.Sprintf("the %s collection was dropped or replaced since the copy was made", name))
		}
	}
	if r.ident != nil && r.ident.genesisHash != "" && !r.zeroKnown {
		r.startSweep("record 0 is missing from MongoDB (records were deleted)")
	}
	if r.o.StoreBlobs {
		if sb, _ := meta.Lookup("store_blobs").BooleanOK(); !sb {
			r.startSweep("blob storage was turned on: blobs copied without their content get it")
		}
	}
	// A replication state written by an older version records no markers: record them now,
	// unless the re-check that records them at its end is pending.
	r.markersDirty = !ok && r.sweep == ""
}

// startSweep asks for a re-check of records 0..next-1 (the first reason is kept).
func (r *Replicator) startSweep(why string) {
	if r.sweep == "" {
		r.sweep = why
	}
}

// checkResume validates the resume point (seq, h) of the replication state against the ledger
// and the copy. It returns why the whole copy must be re-checked ("" when the point is valid) and
// the h that MongoDB holds at seq. A different h there is a conflict, reported but no reason to
// re-check everything (the copy does hold a record at that seq).
func (r *Replicator) checkResume(ctx context.Context, seq uint64, h string) (why, stored string, err error) {
	env, _, err := r.o.Reader.Record(seq)
	switch {
	case errors.Is(err, contracts.ErrNotFound):
		return fmt.Sprintf("the replication state says record %d was copied, but the ledger has no record %d", seq, seq), "", nil
	case err != nil:
		return "", "", fmt.Errorf("mongostore: read ledger record %d: %w", seq, err)
	case env.H != h:
		return fmt.Sprintf("the replication state names h %s for record %d, the ledger has %s", short(h), seq, short(env.H)), "", nil
	}
	stored, found, err := r.storedHash(ctx, seq)
	switch {
	case err != nil:
		return "", "", err
	case !found:
		return fmt.Sprintf("record %d, the newest copied according to the replication state, is missing from MongoDB", seq), "", nil
	case stored != h:
		r.integrity(conflictMsg(seq, stored, h))
	}
	return "", stored, nil
}

// conflictMsg describes a document that differs from the ledger record of the same seq.
func conflictMsg(seq uint64, stored, ledgerH string) string {
	return fmt.Sprintf("MongoDB already holds a different record %d (h %s; the ledger has %s); it was not overwritten", seq, short(stored), short(ledgerH))
}

// resetMetaLocked replaces an untrustworthy replication state (kept under "previous") and makes
// the next pass re-check the whole copy from seq 0.
func (r *Replicator) resetMetaLocked(ctx context.Context, old bson.Raw, why string) error {
	r.integrity(why + "; re-checking the whole copy from seq 0")
	d := bson.D{{Key: "_id", Value: metaID}}
	d = append(d, r.metaProgress(-1, "", r.o.Now())...)
	d = append(d, r.metaMarkers()...)
	d = append(d, bson.E{Key: "reset_reason", Value: why})
	if old != nil && len(old) <= maxPreviousMetaBytes {
		if prev := withoutKey(old, "previous"); prev != nil {
			d = append(d, bson.E{Key: "previous", Value: prev})
		}
	}
	opCtx, cancel := r.opCtx(ctx)
	defer cancel()
	if _, err := r.coll(collMeta).ReplaceOne(opCtx, bson.D{{Key: "_id", Value: metaID}}, d, options.Replace().SetUpsert(true)); err != nil {
		return fmt.Errorf("mongostore: reset the replication state: %w", err)
	}
	r.meta = metaState{present: true, seq: -1, hash: ""}
	r.markersDirty = false
	r.clearPending()
	r.setResume(0, false)
	return nil
}

// setResume sets the resume point: next is the first seq not yet copied.
func (r *Replicator) setResume(next uint64, copied bool) {
	r.next, r.copied = next, copied
	if !copied {
		r.tailKnown = false
	}
	r.mu.Lock()
	r.st.resumeKnown = true
	r.st.hasData = copied
	r.st.lastSeq = 0
	if copied {
		r.st.lastSeq = next - 1
	}
	r.mu.Unlock()
}

// setTail remembers the newest copied record known to be in MongoDB and the h stored there.
func (r *Replicator) setTail(seq uint64, h string) {
	r.tailSeq, r.tailHash, r.tailKnown = seq, h, true
}

func (r *Replicator) appendIdent(d bson.D) bson.D {
	if r.ident == nil {
		return d
	}
	if r.ident.fingerprint != "" {
		d = append(d, bson.E{Key: "fingerprint", Value: r.ident.fingerprint})
	}
	if r.ident.genesisHash != "" {
		d = append(d, bson.E{Key: "genesis_hash", Value: r.ident.genesisHash})
	}
	return d
}

// copyLocked copies every ledger record from r.next on. The steady state (a few new records
// below the reader's head) reads them by seq through the ledger's line index; a first copy, a
// longer catch-up, or seqs that cannot be read one by one are scanned instead.
func (r *Replicator) copyLocked(ctx context.Context, head uint64, headOK bool) (int, error) {
	if headOK && r.copied && head >= r.next && head-r.next < bySeqMax && head <= math.MaxInt64 {
		items, ok, err := r.readBySeq(ctx, r.next, head)
		if err != nil {
			return 0, err
		}
		if ok {
			total := 0
			for len(items) > 0 {
				n := min(len(items), r.o.BatchSize)
				c, err := r.flushLocked(ctx, items[:n], true)
				total += c
				if err != nil {
					return total, fmt.Errorf("mongostore: copy from seq %d: %w", items[0].body.Seq, err)
				}
				items = items[n:]
			}
			return total, nil
		}
	}
	return r.scanLocked(ctx, r.next, 0, true)
}

// readBySeq reads the records from..to by seq; ok is false when one of them cannot be found under
// its seq (a gap or a damaged line: the scan then decides what is copied).
func (r *Replicator) readBySeq(ctx context.Context, from, to uint64) (items []item, ok bool, err error) {
	items = make([]item, 0, to-from+1)
	for seq := from; seq <= to; seq++ {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		env, body, err := r.o.Reader.Record(seq)
		switch {
		case errors.Is(err, contracts.ErrNotFound) || (err == nil && body.Seq != seq):
			return nil, false, nil
		case err != nil:
			return nil, false, fmt.Errorf("mongostore: read ledger record %d: %w", seq, err)
		}
		items = append(items, item{env: env, body: body})
	}
	return items, true, nil
}

// scanLocked copies the ledger records with from <= seq < end (end 0: no end) in batches,
// scanning the ledger. With advance (the copy of new records) every batch moves the resume point
// and the replication state; a re-check of records copied before (advance false) leaves them
// alone.
func (r *Replicator) scanLocked(ctx context.Context, from, end uint64, advance bool) (int, error) {
	problemsBefore := r.passProblems
	var prev uint64
	havePrev := false
	if advance && r.copied {
		prev, havePrev = r.next-1, true
	}
	var maxSeen uint64
	sawAny := false
	batch := make([]item, 0, min(r.o.BatchSize, 256))
	total := 0
	err := r.o.Reader.Scan(from, func(env model.Envelope, body model.Body) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if body.Seq < from {
			return nil
		}
		if end > 0 && body.Seq >= end {
			return contracts.ErrStop
		}
		if !sawAny || body.Seq > maxSeen {
			maxSeen, sawAny = body.Seq, true
		}
		switch {
		case body.Seq > math.MaxInt64:
			r.integrity(fmt.Sprintf("ledger record seq %d cannot be copied: seqs above %d do not fit MongoDB's int64 (run the ledger verification)", body.Seq, int64(math.MaxInt64)))
			return nil
		case havePrev && body.Seq <= prev:
			r.integrity(fmt.Sprintf("the ledger lists seq %d after seq %d; that line was not copied (run the ledger verification)", body.Seq, prev))
			return nil
		}
		prev, havePrev = body.Seq, true
		batch = append(batch, item{env: env, body: body})
		if len(batch) < r.o.BatchSize {
			return nil
		}
		n, err := r.flushLocked(ctx, batch, advance)
		total += n
		batch = batch[:0]
		return err
	})
	if errors.Is(err, contracts.ErrStop) {
		err = nil // the end was reached (a reader that does not end the scan itself)
	}
	if err == nil && len(batch) > 0 {
		n, ferr := r.flushLocked(ctx, batch, advance)
		total += n
		err = ferr
	}
	if sawAny && advance {
		r.noteHead(maxSeen)
	}
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
			return total, err
		}
		return total, fmt.Errorf("mongostore: copy from seq %d: %w", from, err)
	}
	if advance && from == 0 && r.passProblems == problemsBefore {
		// The whole copy has just been checked against the ledger without a problem.
		r.mu.Lock()
		r.st.integrity = ""
		r.mu.Unlock()
	}
	return total, nil
}

// sweepLocked checks the copy of records 0..next-1 again — records, blobs and incidents —
// without moving the resume point: after a collection of the copy was dropped or replaced,
// records were deleted, or blob storage was turned on. What is missing is stored, blob documents
// stored without their content get it, and every difference is reported as in any pass. When it
// is done, the replication state records what the copy is now consistent with. It returns the
// record documents inserted.
func (r *Replicator) sweepLocked(ctx context.Context) (int, error) {
	if !r.copied || !r.meta.present {
		r.sweep = "" // nothing copied yet: the copy from seq 0 covers everything
		return 0, nil
	}
	why, end := r.sweep, r.next
	r.log.Info("MongoDB copy: checking the copy of the whole ledger again", "database", r.o.Database, "why", why, "records", end)
	before := r.passProblems
	n, err := r.scanLocked(ctx, 0, end, false)
	if err != nil {
		return n, err
	}
	colls, err := r.collectionIDsLocked(ctx)
	if err != nil {
		return n, err
	}
	if name := changedCollection(r.colls, colls); name != "" {
		return n, &resyncError{why: fmt.Sprintf("the %s collection was dropped or replaced during the re-check", name)}
	}
	if err := r.writeMarkersLocked(ctx); err != nil {
		return n, err
	}
	r.sweep = ""
	if r.passProblems == before {
		// The whole copy has just been checked against the ledger without a problem.
		r.mu.Lock()
		r.st.integrity = ""
		r.mu.Unlock()
	}
	r.log.Info("MongoDB copy: the copy of the whole ledger was checked again", "database", r.o.Database,
		"records_inserted", n, "problems", r.passProblems-before)
	return n, nil
}

type blobRef struct {
	id  string
	seq uint64 // first record of the batch that references it
}

// flushLocked copies one batch: blobs, records, incidents and, with advance, the replication
// state.
func (r *Replicator) flushLocked(ctx context.Context, batch []item, advance bool) (int, error) {
	now := r.o.Now()
	docs := make([]any, 0, len(batch))
	kept := make([]item, 0, len(batch))
	var refs []blobRef
	seen := map[string]bool{}
	for _, it := range batch {
		for _, id := range it.body.Blobs {
			if !seen[id] {
				seen[id] = true
				refs = append(refs, blobRef{id: id, seq: it.body.Seq})
			}
		}
		raw, err := recordDoc(it.env, it.body, dataConvert)
		if err != nil {
			r.integrity(fmt.Sprintf("ledger record %d was not copied: %v", it.body.Seq, err))
			continue
		}
		docs = append(docs, raw)
		kept = append(kept, it)
	}
	if err := r.copyBlobsLocked(ctx, refs, now, blobReadAttempts); err != nil {
		return 0, err
	}
	ins, err := r.insertRecordsLocked(ctx, docs, kept)
	if err != nil {
		return ins.inserted, err
	}
	if len(kept) > 0 && kept[0].body.Seq == 0 && !ins.absent[0] {
		r.zeroKnown = true
	}
	if err := r.upsertIncidentsLocked(ctx, batch, now); err != nil {
		return ins.inserted, err
	}
	if !advance {
		return ins.inserted, nil
	}
	last := batch[len(batch)-1]
	if err := r.saveMetaLocked(ctx, last, now); err != nil {
		return ins.inserted, err
	}
	r.setResume(last.body.Seq+1, true)
	// The newest record of the batch that MongoDB holds, and the h it holds for it.
	for i := len(kept) - 1; i >= 0; i-- {
		seq := kept[i].body.Seq
		if ins.absent[seq] {
			continue
		}
		h := kept[i].env.H
		if c, ok := ins.conflicts[seq]; ok {
			h = c
		}
		r.setTail(seq, h)
		break
	}
	return ins.inserted, nil
}

func isDuplicateKeyCode(code int) bool { return code == 11000 || code == 11001 || code == 12582 }

// insertResult is the outcome of inserting a batch of record documents.
type insertResult struct {
	inserted  int
	conflicts map[uint64]string // seqs where MongoDB holds another record: the h it holds
	absent    map[uint64]bool   // seqs that could not be stored at all
}

// insertRecordsLocked inserts record documents. A seq already present counts as copied when its
// stored h equals the ledger's; a document the server rejects is retried once with its data as
// JSON text (if that fails too, the server is in trouble: the batch is retried later).
func (r *Replicator) insertRecordsLocked(ctx context.Context, docs []any, kept []item) (insertResult, error) {
	res := insertResult{conflicts: map[uint64]string{}, absent: map[uint64]bool{}}
	if len(docs) == 0 {
		return res, nil
	}
	opCtx, cancel := r.opCtx(ctx)
	defer cancel()
	coll := r.coll(collRecords)
	_, err := coll.InsertMany(opCtx, docs, options.InsertMany().SetOrdered(false))
	if err == nil {
		res.inserted = len(docs)
		return res, nil
	}
	var bwe mongo.BulkWriteException
	if !errors.As(err, &bwe) || bwe.WriteConcernError != nil || len(bwe.WriteErrors) == 0 {
		return res, fmt.Errorf("insert records: %w", err)
	}
	res.inserted = len(docs) - len(bwe.WriteErrors)
	var dups []item
	for _, we := range bwe.WriteErrors {
		if we.Index < 0 || we.Index >= len(kept) {
			return res, fmt.Errorf("insert records: write error for unknown index %d: %w", we.Index, err)
		}
		it := kept[we.Index]
		if isDuplicateKeyCode(we.Code) {
			dups = append(dups, it)
			continue
		}
		raw, berr := recordDoc(it.env, it.body, dataAsJSON)
		if berr != nil {
			r.integrity(fmt.Sprintf("ledger record %d was not copied: %v", it.body.Seq, berr))
			res.absent[it.body.Seq] = true
			continue
		}
		_, ierr := coll.InsertOne(opCtx, raw)
		switch {
		case ierr == nil:
			res.inserted++
			r.log.Warn("MongoDB rejected the converted data of a record; it is stored as JSON text", "seq", it.body.Seq, "err", clip(we.Error(), maxProblemLen))
		case mongo.IsDuplicateKeyError(ierr):
			dups = append(dups, it)
		default:
			return res, fmt.Errorf("insert record %d: %w (first attempt: %v)", it.body.Seq, ierr, we)
		}
	}
	return res, r.checkDuplicatesLocked(opCtx, dups, &res)
}

// checkDuplicatesLocked accepts already present records whose stored h equals the ledger's and
// reports the others (never overwritten): another h, an _id of another type than int64 (which
// MongoDB's unique index treats as the same seq), or a document that cannot be read back. None
// of these stops the copy.
func (r *Replicator) checkDuplicatesLocked(ctx context.Context, dups []item, res *insertResult) error {
	if len(dups) == 0 {
		return nil
	}
	ids := make(bson.A, len(dups))
	for i, it := range dups {
		ids[i] = int64(it.body.Seq)
	}
	cur, err := r.coll(collRecords).Find(ctx, bson.D{{Key: "_id", Value: bson.D{{Key: "$in", Value: ids}}}},
		options.Find().SetProjection(bson.D{{Key: "h", Value: 1}}))
	if err != nil {
		return fmt.Errorf("read existing records: %w", err)
	}
	defer cur.Close(context.WithoutCancel(ctx))
	type storedRecord struct {
		h      string
		idType bson.Type
	}
	stored := make(map[uint64]storedRecord, len(dups))
	for cur.Next(ctx) {
		idv := cur.Current.Lookup("_id")
		if seq, ok := numericSeq(idv); ok {
			h, _ := rawString(cur.Current, "h")
			stored[seq] = storedRecord{h: h, idType: idv.Type}
		}
	}
	if err := cur.Err(); err != nil {
		return fmt.Errorf("read existing records: %w", err)
	}
	for _, it := range dups {
		seq := it.body.Seq
		s, ok := stored[seq]
		switch {
		case !ok:
			res.absent[seq] = true
			r.integrity(fmt.Sprintf("MongoDB reported record %d as already present, but it cannot be read back; it was not overwritten", seq))
		case s.idType != bson.TypeInt64:
			res.conflicts[seq] = s.h
			r.integrity(fmt.Sprintf("MongoDB holds record %d under an _id of BSON type %s instead of int64; it was not overwritten", seq, s.idType))
		case s.h != it.env.H:
			res.conflicts[seq] = s.h
			r.integrity(conflictMsg(seq, s.h, it.env.H))
		}
	}
	return nil
}

// blobState is what a blob document already in MongoDB holds.
type blobState struct {
	first     uint64 // first_seq …
	firstOK   bool   // … when it is a valid seq
	notStored bool   // stored without its content because blob storage was off
}

// copyBlobsLocked brings the blob documents of refs up to date. It stores those that MongoDB
// lacks, gives documents stored without their content their content once Options.StoreBlobs is
// set, and lowers a first_seq above the first referencing record seen (a document stored again
// after its collection was dropped). A blob that cannot be read from the ledger is reported when
// the ledger lacks it or holds other content; any other read error may pass (a file locked by
// another program), so the blob waits for a retry (pending) while the records are copied.
// attempts is the number of reads of a blob that fails (with short pauses); a blob already
// waiting, or any blob once a few have failed in this pass, is read once.
func (r *Replicator) copyBlobsLocked(ctx context.Context, refs []blobRef, now time.Time, attempts int) error {
	if len(refs) == 0 {
		return nil
	}
	existing, err := r.existingBlobsLocked(ctx, refs)
	if err != nil {
		return err
	}
	var (
		docs   []any
		models []mongo.WriteModel // contents added, first_seq lowered
		size   int
	)
	flush := func() error {
		if err := r.insertBlobsLocked(ctx, docs); err != nil {
			return err
		}
		if err := r.updateBlobsLocked(ctx, models); err != nil {
			return err
		}
		docs, models, size = nil, nil, 0
		return nil
	}
	for _, ref := range refs {
		cur, exists := existing[ref.id]
		if exists {
			r.unpend(ref.id)
			if !r.o.StoreBlobs || !cur.notStored {
				if cur.firstOK && cur.first > ref.seq && ref.seq <= math.MaxInt64 {
					models = append(models, mongo.NewUpdateOneModel().
						SetFilter(bson.D{{Key: "_id", Value: ref.id}, {Key: "first_seq", Value: int64(cur.first)}}).
						SetUpdate(bson.D{{Key: "$set", Value: bson.D{{Key: "first_seq", Value: int64(ref.seq)}}}}))
				}
				continue
			}
		}
		if !isBlobID(ref.id) {
			r.integrity(fmt.Sprintf("ledger record %d references an invalid blob id %s", ref.seq, quote(ref.id)))
			continue
		}
		n := attempts
		if _, waiting := r.pending[ref.id]; waiting || r.passBlobFails >= blobReadAttempts {
			n = 1 // no pauses while the blob store keeps failing
		}
		content, err := r.readBlob(ctx, ref.id, n)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			r.passBlobFails++
			if permanentBlobError(err) {
				r.unpend(ref.id)
				what := "was not copied"
				if exists {
					what = "did not get its content"
				}
				r.integrity(fmt.Sprintf("blob %s (ledger record %d) %s: %v", ref.id, ref.seq, what, err))
				continue
			}
			if err := r.pend(ref, err, now); err != nil {
				return err
			}
			continue
		}
		r.unpend(ref.id)
		first := ref.seq
		if exists && cur.firstOK && cur.first < first {
			first = cur.first
		}
		doc := blobDoc(ref.id, content, first, r.o.StoreBlobs, now)
		if exists {
			// Stored while blob storage was off: it gets its content now.
			models = append(models, mongo.NewReplaceOneModel().
				SetFilter(bson.D{{Key: "_id", Value: ref.id}, {Key: "note", Value: noteBlobNotStored}}).
				SetReplacement(doc))
		} else {
			docs = append(docs, doc)
		}
		if r.o.StoreBlobs && len(content) <= maxBlobBytes {
			size += len(content)
		}
		if size >= blobBatchBytes || len(docs)+len(models) >= blobBatchDocs {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	return flush()
}

// insertBlobsLocked inserts blob documents; one stored meanwhile is fine (blobs are
// content-addressed).
func (r *Replicator) insertBlobsLocked(ctx context.Context, docs []any) error {
	if len(docs) == 0 {
		return nil
	}
	opCtx, cancel := r.opCtx(ctx)
	defer cancel()
	_, err := r.coll(collBlobs).InsertMany(opCtx, docs, options.InsertMany().SetOrdered(false))
	if err == nil {
		return nil
	}
	var bwe mongo.BulkWriteException
	if !errors.As(err, &bwe) || bwe.WriteConcernError != nil || len(bwe.WriteErrors) == 0 {
		return fmt.Errorf("insert blobs: %w", err)
	}
	for _, we := range bwe.WriteErrors {
		if !isDuplicateKeyCode(we.Code) {
			return fmt.Errorf("insert blobs: %w", err)
		}
	}
	return nil
}

// updateBlobsLocked applies changes to blob documents (a document changed meanwhile is left
// alone: its filter no longer matches).
func (r *Replicator) updateBlobsLocked(ctx context.Context, models []mongo.WriteModel) error {
	if len(models) == 0 {
		return nil
	}
	opCtx, cancel := r.opCtx(ctx)
	defer cancel()
	if _, err := r.coll(collBlobs).BulkWrite(opCtx, models, options.BulkWrite().SetOrdered(false)); err != nil {
		return fmt.Errorf("update blobs: %w", err)
	}
	return nil
}

func (r *Replicator) existingBlobsLocked(ctx context.Context, refs []blobRef) (map[string]blobState, error) {
	ids := make(bson.A, len(refs))
	for i, ref := range refs {
		ids[i] = ref.id
	}
	opCtx, cancel := r.opCtx(ctx)
	defer cancel()
	cur, err := r.coll(collBlobs).Find(opCtx, bson.D{{Key: "_id", Value: bson.D{{Key: "$in", Value: ids}}}},
		options.Find().SetProjection(bson.D{{Key: "_id", Value: 1}, {Key: "first_seq", Value: 1}, {Key: "note", Value: 1}}))
	if err != nil {
		return nil, fmt.Errorf("read existing blobs: %w", err)
	}
	defer cur.Close(context.WithoutCancel(opCtx))
	out := make(map[string]blobState, len(refs))
	for cur.Next(opCtx) {
		id, ok := rawString(cur.Current, "_id")
		if !ok {
			continue
		}
		var st blobState
		st.first, st.firstOK = rawSeq(cur.Current, "first_seq")
		note, _ := rawString(cur.Current, "note")
		st.notStored = note == noteBlobNotStored
		out[id] = st
	}
	if err := cur.Err(); err != nil {
		return nil, fmt.Errorf("read existing blobs: %w", err)
	}
	return out, nil
}

// errBlobMismatch: the ledger returned content that does not hash to the blob's id.
var errBlobMismatch = errors.New("the ledger's copy does not match its id")

// readBlob reads a blob from the ledger and checks its SHA-256. Errors other than "not found"
// are retried up to attempts reads in all (e.g. a file briefly locked by another process).
func (r *Replicator) readBlob(ctx context.Context, id string, attempts int) ([]byte, error) {
	var err error
	for attempt := 0; attempt < max(attempts, 1); attempt++ {
		if attempt > 0 {
			t := time.NewTimer(time.Duration(attempt) * 100 * time.Millisecond)
			select {
			case <-ctx.Done():
				t.Stop()
				return nil, ctx.Err()
			case <-t.C:
			}
		}
		var b []byte
		b, err = r.o.Reader.GetBlob(id)
		if err == nil {
			if got := sha256Hex(b); got != id {
				return nil, fmt.Errorf("%w (its content hashes to %s)", errBlobMismatch, short(got))
			}
			return b, nil
		}
		if errors.Is(err, contracts.ErrNotFound) {
			break
		}
	}
	return nil, err
}

// permanentBlobError reports whether reading a blob failed for good: the ledger lacks it, or its
// copy there does not match its id. Other errors (a file locked by another program, an I/O error)
// may pass.
func permanentBlobError(err error) bool {
	return errors.Is(err, contracts.ErrNotFound) || errors.Is(err, errBlobMismatch)
}

// ---------------------------------------------------------------- blobs waiting for a retry

// pend records a blob that could not be read from the ledger: the records referencing it are
// copied without it and it is read again on later passes. When too many blobs wait already, it
// fails instead: the copy then waits until the ledger's blob store can be read again.
func (r *Replicator) pend(ref blobRef, err error, now time.Time) error {
	msg := printable(clip(err.Error(), 200))
	if p, ok := r.pending[ref.id]; ok {
		p.err = msg
		p.seq = min(p.seq, ref.seq)
		r.pending[ref.id] = p
		r.notePending(msg)
		return nil
	}
	if len(r.pending) >= maxPendingBlobs {
		return fmt.Errorf("mongostore: %d blobs could not be read from the ledger and wait for a retry; the copy waits until the ledger's blob store can be read (blob %s: %w)", len(r.pending), ref.id, err)
	}
	if r.pending == nil {
		r.pending = map[string]pendingBlob{}
	}
	r.pending[ref.id] = pendingBlob{seq: ref.seq, since: now, err: msg}
	r.notePending(msg)
	return nil
}

// unpend forgets a blob waiting for a retry (copied, present, or reported).
func (r *Replicator) unpend(id string) {
	if _, ok := r.pending[id]; ok {
		delete(r.pending, id)
		r.notePending("")
	}
}

// clearPending forgets the blobs waiting for a retry when the whole copy is checked again from
// seq 0 (that reads every blob again; one still unreadable waits again).
func (r *Replicator) clearPending() {
	r.pending = nil
	r.mu.Lock()
	r.st.pending, r.st.pendingErr, r.st.pendingGate = 0, "", logGate{}
	r.mu.Unlock()
}

// loadPending adds the blobs that the replication state lists as waiting for a retry (a
// previous run could not read them).
func (r *Replicator) loadPending(meta bson.Raw) {
	arr, ok := meta.Lookup("pending_blobs").ArrayOK()
	if !ok {
		return
	}
	vals, err := arr.Values()
	if err != nil {
		return
	}
	last := ""
	for _, v := range vals {
		d, ok := v.DocumentOK()
		if !ok {
			continue
		}
		id, _ := rawString(d, "id")
		seq, seqOK := rawSeq(d, "seq")
		if !isBlobID(id) || !seqOK || seq >= r.next || len(r.pending) >= maxPendingBlobs {
			continue
		}
		if _, dup := r.pending[id]; dup {
			continue
		}
		p := pendingBlob{seq: seq}
		if ms, ok := d.Lookup("since").DateTimeOK(); ok {
			p.since = time.UnixMilli(ms)
		}
		e, _ := rawString(d, "err")
		p.err = printable(clip(e, 200))
		if r.pending == nil {
			r.pending = map[string]pendingBlob{}
		}
		r.pending[id] = p
		last = p.err
	}
	if last != "" || len(r.pending) > 0 {
		r.notePending(last)
	}
}

// pendingRefs returns up to n blobs waiting for a retry, the oldest first.
func (r *Replicator) pendingRefs(n int) []blobRef {
	refs := make([]blobRef, 0, len(r.pending))
	for id, p := range r.pending {
		refs = append(refs, blobRef{id: id, seq: p.seq})
	}
	slices.SortFunc(refs, func(a, b blobRef) int {
		if c := cmp.Compare(a.seq, b.seq); c != 0 {
			return c
		}
		return strings.Compare(a.id, b.id)
	})
	return refs[:min(n, len(refs))]
}

// pendingDoc is the "pending_blobs" field of the replication state.
func (r *Replicator) pendingDoc() bson.A {
	out := make(bson.A, 0, len(r.pending))
	for _, ref := range r.pendingRefs(len(r.pending)) {
		p := r.pending[ref.id]
		out = append(out, bson.D{
			{Key: "id", Value: ref.id},
			{Key: "seq", Value: int64(min(p.seq, math.MaxInt64))},
			{Key: "since", Value: bson.NewDateTimeFromTime(p.since)},
			{Key: "err", Value: p.err},
		})
	}
	return out
}

// retryPendingLocked reads again the blobs that could not be read from the ledger before.
func (r *Replicator) retryPendingLocked(ctx context.Context) error {
	if len(r.pending) == 0 {
		return nil
	}
	return r.copyBlobsLocked(ctx, r.pendingRefs(pendingRetryPerPass), r.o.Now(), 1)
}

// notePending publishes the number of blobs waiting for a retry (and the last error reading one)
// to Status, and logs when blobs start to wait (again at most hourly while they do) and when none
// waits any more.
func (r *Replicator) notePending(lastErr string) {
	n := len(r.pending)
	now := r.o.Now()
	r.mu.Lock()
	before := r.st.pending
	r.st.pending = n
	switch {
	case n == 0:
		r.st.pendingErr = ""
	case lastErr != "":
		r.st.pendingErr = lastErr
	}
	errText := r.st.pendingErr
	log, suppressed := false, 0
	if n > before {
		log, suppressed = r.st.pendingGate.allow("waiting", now, true)
	}
	if n == 0 && before > 0 {
		r.st.pendingGate = logGate{}
	}
	r.mu.Unlock()
	switch {
	case log:
		r.log.Warn("MongoDB copy: blobs could not be read from the ledger; their records were copied and the blobs are read again on later passes",
			"database", r.o.Database, "blobs", n, "err", errText, "suppressed", suppressed)
	case n == 0 && before > 0:
		r.log.Info("MongoDB copy: every blob waiting for a retry has been copied or reported", "database", r.o.Database)
	}
}

// ---------------------------------------------------------------- incidents

// upsertIncidentsLocked keeps the newest payload of every incident in the batch (last write wins
// by seq: an older record never replaces a newer one).
func (r *Replicator) upsertIncidentsLocked(ctx context.Context, batch []item, now time.Time) error {
	latest := map[string]item{}
	var order []string
	for _, it := range batch {
		if !isIncidentType(it.body.Type) {
			continue
		}
		id := incidentID(it.body.Data)
		if id == "" {
			r.log.Warn("MongoDB copy: incident record without an incident id", "seq", it.body.Seq, "type", it.body.Type)
			continue
		}
		if _, ok := latest[id]; !ok {
			order = append(order, id)
		}
		latest[id] = it
	}
	if len(order) == 0 {
		return nil
	}
	upsert := func(id string, mode dataMode) (mongo.WriteModel, error) {
		it := latest[id]
		doc, err := incidentDoc(id, it.env, it.body, mode, now)
		if err != nil {
			return nil, err
		}
		filter := bson.D{{Key: "_id", Value: id}, {Key: "seq", Value: bson.D{{Key: "$lt", Value: int64(it.body.Seq)}}}}
		return mongo.NewReplaceOneModel().SetFilter(filter).SetReplacement(doc).SetUpsert(true), nil
	}
	models := make([]mongo.WriteModel, 0, len(order))
	ids := make([]string, 0, len(order))
	for _, id := range order {
		m, err := upsert(id, dataConvert)
		if err != nil {
			r.log.Warn("MongoDB copy: incident not copied", "incident", id, "err", err)
			continue
		}
		models = append(models, m)
		ids = append(ids, id)
	}
	if len(models) == 0 {
		return nil
	}
	opCtx, cancel := r.opCtx(ctx)
	defer cancel()
	coll := r.coll(collIncidents)
	_, err := coll.BulkWrite(opCtx, models, options.BulkWrite().SetOrdered(false))
	if err == nil {
		return nil
	}
	var bwe mongo.BulkWriteException
	if !errors.As(err, &bwe) || bwe.WriteConcernError != nil || len(bwe.WriteErrors) == 0 {
		return fmt.Errorf("update incidents: %w", err)
	}
	for _, we := range bwe.WriteErrors {
		if we.Index < 0 || we.Index >= len(ids) {
			return fmt.Errorf("update incidents: %w", err)
		}
		id := ids[we.Index]
		if isDuplicateKeyCode(we.Code) {
			if err := r.checkIncidentLocked(ctx, id, latest[id]); err != nil {
				return err
			}
			continue
		}
		m, merr := upsert(id, dataAsJSON)
		if merr != nil {
			return fmt.Errorf("update incident %s: %w", id, merr)
		}
		_, err := coll.BulkWrite(opCtx, []mongo.WriteModel{m})
		switch {
		case err == nil:
			r.log.Warn("MongoDB rejected the converted payload of an incident; it is stored as JSON text", "incident", id, "err", clip(we.Error(), maxProblemLen))
		case mongo.IsDuplicateKeyError(err):
			if err := r.checkIncidentLocked(ctx, id, latest[id]); err != nil {
				return err
			}
		default:
			return fmt.Errorf("update incident %s: %w (first attempt: %v)", id, err, we)
		}
	}
	return nil
}

// checkIncidentLocked explains why the document of incident id was not updated with record it:
// fine when MongoDB holds this record or a newer record of the incident; otherwise the document
// names a seq that is no newer record of this incident in the ledger, which is reported (never
// overwritten).
func (r *Replicator) checkIncidentLocked(ctx context.Context, id string, it item) error {
	doc, err := r.findOneRaw(ctx, collIncidents, id, "seq")
	if err != nil {
		return err
	}
	if doc == nil {
		return nil // removed meanwhile: the next record of the incident stores it again
	}
	seq, ok := rawSeq(doc, "seq")
	if !ok {
		r.integrity(fmt.Sprintf("incident %s: MongoDB holds a document whose seq (%s) is not a ledger seq; it was not updated with record %d",
			quote(id), clip(doc.Lookup("seq").String(), 40), it.body.Seq))
		return nil
	}
	if seq <= it.body.Seq {
		return nil // this record (copied before), or changed meanwhile
	}
	_, body, err := r.o.Reader.Record(seq)
	switch {
	case errors.Is(err, contracts.ErrNotFound):
	case err != nil:
		return fmt.Errorf("mongostore: read ledger record %d: %w", seq, err)
	case body.Seq == seq && isIncidentType(body.Type) && incidentID(body.Data) == id:
		return nil // a newer record of the incident
	}
	r.integrity(fmt.Sprintf("incident %s: MongoDB holds record %d, which is not a newer record of this incident in the ledger; it was not updated with record %d",
		quote(id), seq, it.body.Seq))
	return nil
}

// ---------------------------------------------------------------- replication state

// saveMetaLocked advances the replication state to the newest record of a batch. It writes only
// if the document is still the one this replicator last read or wrote (compare and set): a
// replication state that disappeared (database dropped, meta deleted) or changed (an older copy
// restored) is not overwritten, the copy is validated again instead (resyncError).
func (r *Replicator) saveMetaLocked(ctx context.Context, last item, now time.Time) error {
	seq := int64(last.body.Seq)
	opCtx, cancel := r.opCtx(ctx)
	defer cancel()
	if !r.meta.present {
		doc := bson.D{{Key: "_id", Value: metaID}}
		doc = append(doc, r.metaProgress(seq, last.env.H, now)...)
		doc = append(doc, r.metaMarkers()...)
		if len(r.pending) > 0 {
			doc = append(doc, bson.E{Key: "pending_blobs", Value: r.pendingDoc()})
		}
		_, err := r.coll(collMeta).InsertOne(opCtx, doc)
		if mongo.IsDuplicateKeyError(err) {
			return &resyncError{why: "a replication state (meta) appeared that this replicator did not write"}
		}
		if err != nil {
			return fmt.Errorf("save the replication state: %w", err)
		}
		r.meta = metaState{present: true, seq: seq, hash: last.env.H}
		r.markersDirty = false
		return nil
	}
	if seq <= r.meta.seq {
		return nil // never backwards
	}
	set := r.metaProgress(seq, last.env.H, now)
	switch {
	case r.markersDirty:
		set = append(set, r.metaMarkers()...)
	case !r.o.StoreBlobs:
		set = append(set, bson.E{Key: "store_blobs", Value: false}) // new blobs are stored without content
	}
	res, err := r.coll(collMeta).UpdateOne(opCtx, r.metaFilter(), r.metaUpdate(set))
	if err != nil {
		return fmt.Errorf("save the replication state: %w", err)
	}
	if res.MatchedCount == 0 {
		return &resyncError{why: r.describeMetaLocked(ctx)}
	}
	r.meta.seq, r.meta.hash = seq, last.env.H
	r.markersDirty = false
	return nil
}

// writeMarkersLocked records in the replication state that the copy of records up to last_seq is
// consistent with the current collections and blob storage setting (after a re-check).
func (r *Replicator) writeMarkersLocked(ctx context.Context) error {
	set := append(bson.D{{Key: "updated", Value: bson.NewDateTimeFromTime(r.o.Now())}}, r.metaMarkers()...)
	opCtx, cancel := r.opCtx(ctx)
	defer cancel()
	res, err := r.coll(collMeta).UpdateOne(opCtx, r.metaFilter(), r.metaUpdate(set))
	if err != nil {
		return fmt.Errorf("save the replication state: %w", err)
	}
	if res.MatchedCount == 0 {
		return &resyncError{why: r.describeMetaLocked(ctx)}
	}
	r.markersDirty = false
	return nil
}

// metaFilter matches the replication state as this replicator last read or wrote it.
func (r *Replicator) metaFilter() bson.D {
	return bson.D{{Key: "_id", Value: metaID}, {Key: "last_seq", Value: r.meta.seq}, {Key: "last_hash", Value: r.meta.hash}}
}

// metaProgress returns the fields of the replication state that every write sets.
func (r *Replicator) metaProgress(seq int64, hash string, now time.Time) bson.D {
	d := bson.D{
		{Key: "last_seq", Value: seq},
		{Key: "last_hash", Value: hash},
		{Key: "updated", Value: bson.NewDateTimeFromTime(now)},
	}
	d = r.appendIdent(d)
	return append(d, bson.E{Key: "format", Value: int32(copyFormat)})
}

// metaMarkers returns what the copy of records up to last_seq is consistent with: whether blob
// contents are stored (store_blobs) and the collections holding the copy (their UUIDs).
func (r *Replicator) metaMarkers() bson.D {
	return bson.D{{Key: "store_blobs", Value: r.o.StoreBlobs}, {Key: "collections", Value: r.collsDoc()}}
}

// metaUpdate returns an update of the replication state that sets set and the blobs waiting for
// a retry.
func (r *Replicator) metaUpdate(set bson.D) bson.D {
	if len(r.pending) > 0 {
		return bson.D{{Key: "$set", Value: append(set, bson.E{Key: "pending_blobs", Value: r.pendingDoc()})}}
	}
	return bson.D{{Key: "$set", Value: set}, {Key: "$unset", Value: bson.D{{Key: "pending_blobs", Value: ""}}}}
}

func (r *Replicator) refreshCountsLocked(ctx context.Context, force bool) {
	now := r.o.Now()
	if !force && !r.countsAt.IsZero() && now.Sub(r.countsAt) < countsEvery && !now.Before(r.countsAt) {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, max(r.o.ConnectTimeout, 5*time.Second))
	defer cancel()
	records, err1 := r.coll(collRecords).EstimatedDocumentCount(cctx)
	blobs, err2 := r.coll(collBlobs).EstimatedDocumentCount(cctx)
	r.countsAt = now
	r.mu.Lock()
	if err1 == nil {
		r.st.records = records
	}
	if err2 == nil {
		r.st.blobs = blobs
	}
	r.mu.Unlock()
}

// findOneRaw returns the document with _id id (nil if none), optionally projected to fields.
func (r *Replicator) findOneRaw(ctx context.Context, coll string, id any, fields ...string) (bson.Raw, error) {
	opCtx, cancel := r.opCtx(ctx)
	defer cancel()
	opts := options.FindOne()
	if len(fields) > 0 {
		proj := bson.D{}
		for _, f := range fields {
			proj = append(proj, bson.E{Key: f, Value: 1})
		}
		opts.SetProjection(proj)
	}
	raw, err := r.coll(coll).FindOne(opCtx, bson.D{{Key: "_id", Value: id}}, opts).Raw()
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("mongostore: read %s %v: %w", coll, id, err)
	}
	return raw, nil
}

// storedHash returns h of the copied record seq.
func (r *Replicator) storedHash(ctx context.Context, seq uint64) (string, bool, error) {
	doc, err := r.findOneRaw(ctx, collRecords, int64(seq), "h")
	if err != nil || doc == nil {
		return "", false, err
	}
	h, _ := rawString(doc, "h")
	return h, true, nil
}

// headSource is implemented by readers that know their newest record (ledger.Store).
type headSource interface{ Head() model.Ref }

func (r *Replicator) readerHead() (uint64, bool) {
	hs, ok := r.o.Reader.(headSource)
	if !ok {
		return 0, false
	}
	ref := hs.Head()
	if ref.Hash == "" {
		return 0, false
	}
	return ref.Seq, true
}

func (r *Replicator) noteHead(seq uint64) {
	r.mu.Lock()
	if !r.st.headKnown || seq > r.st.head {
		r.st.head, r.st.headKnown = seq, true
	}
	r.mu.Unlock()
}

// integrity records an integrity problem: Status().LastError keeps it, the log gets it at most
// once an hour (with the number of problems suppressed meanwhile).
func (r *Replicator) integrity(msg string) {
	msg = clip(printable(msg), maxProblemLen)
	r.passProblems++
	r.passLast = msg
	now := r.o.Now()
	r.mu.Lock()
	r.st.integrity = msg
	log, suppressed := r.st.integrityGate.allow("integrity", now, true)
	r.mu.Unlock()
	if log {
		r.log.Error("MongoDB copy integrity problem (the ledger is the source of truth; run the MongoDB verification)",
			"database", r.o.Database, "problem", msg, "suppressed", suppressed)
	}
}

// rawInt64 returns an integer field (int64 or int32).
func rawInt64(doc bson.Raw, key string) (int64, bool) {
	v, err := doc.LookupErr(key)
	if err != nil {
		return 0, false
	}
	if n, ok := v.Int64OK(); ok {
		return n, true
	}
	if n, ok := v.Int32OK(); ok {
		return int64(n), true
	}
	return 0, false
}

// numericSeq returns the seq that a numeric _id stands for in MongoDB's comparisons (an int64,
// int32 or integral double that is a valid seq).
func numericSeq(v bson.RawValue) (uint64, bool) {
	if n, ok := v.Int64OK(); ok && n >= 0 {
		return uint64(n), true
	}
	if n, ok := v.Int32OK(); ok && n >= 0 {
		return uint64(n), true
	}
	if f, ok := v.DoubleOK(); ok && f >= 0 && f < math.MaxInt64 && f == math.Trunc(f) {
		return uint64(f), true
	}
	return 0, false
}

// withoutKey returns the elements of doc except key (nil if doc is malformed).
func withoutKey(doc bson.Raw, key string) bson.D {
	elems, err := doc.Elements()
	if err != nil {
		return nil
	}
	out := make(bson.D, 0, len(elems))
	for _, e := range elems {
		if e.Key() != key {
			out = append(out, bson.E{Key: e.Key(), Value: e.Value()})
		}
	}
	return out
}
