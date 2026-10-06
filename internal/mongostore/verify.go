package mongostore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// maxProblems caps VerifyResult.Problems (the counters are always complete).
const maxProblems = 200

// A copy that lacks more than staleRecords ledger records, written over more than staleAfter, is
// reported as behind the ledger (the service copies new records within seconds while it runs).
const (
	staleRecords = 10
	staleAfter   = 15 * time.Minute
)

// VerifyResult is the outcome of Verify. The counters are complete; Problems lists the first
// problems found (at most 200; the last line then says how many were not listed).
type VerifyResult struct {
	Records    int `json:"records"`    // documents in the records collection
	Checked    int `json:"checked"`    // documents compared with the ledger record of the same seq
	Missing    int `json:"missing"`    // ledger records up to the newest copied seq without a document
	Mismatched int `json:"mismatched"` // documents that differ from the ledger (h, s, b or fields derived from b) or that the ledger does not contain (extra or forged)
	BadHash    int `json:"bad_hash"`   // documents whose h is not SHA-256(b) or whose s is not a valid signature of b
	// Blobs: documents whose content was hashed, blobs referenced by copied records that have no
	// document, and documents that do not match the ledger: content that does not hash to their
	// id, an id that is not a SHA-256, no ledger record referencing them, or a field other than
	// the replicator writes for that blob (size, first_seq, the content or the note why it is not
	// stored).
	BlobsChecked int `json:"blobs_checked"`
	BlobsMissing int `json:"blobs_missing"`
	BlobsCorrupt int `json:"blobs_corrupt"`
	// The syslog collection: SyslogDocs documents; SyslogChunks chunks whose documents were
	// compared with their syslog_chunk record, of which SyslogBad do not reproduce it (lines
	// missing, repeated or altered, or documents whose other fields do not match their line);
	// SyslogPruned documents of chunks that a copied syslog_prune record deleted; SyslogForged
	// documents of chunks that no syslog_chunk record names; SyslogMissing chunks that the syslog
	// store still holds but the copy lacks, and SyslogTrimmed such chunks older than every chunk
	// the copy holds, whose documents the copy's size limit deleted (not a problem; both only
	// checked when VerifyWith is given the store).
	SyslogDocs    int `json:"syslog_docs"`
	SyslogChunks  int `json:"syslog_chunks"`
	SyslogBad     int `json:"syslog_bad"`
	SyslogPruned  int `json:"syslog_pruned"`
	SyslogForged  int `json:"syslog_forged"`
	SyslogMissing int `json:"syslog_missing"`
	SyslogTrimmed int `json:"syslog_trimmed"`
	// Where the copy ends: LedgerHead is the newest seq of the ledger, CopiedUpTo the newest seq
	// up to which the copy was compared (its replication state's, or its newest record matching
	// the ledger; -1 when there is none), NotCopied the number of ledger records after it. While
	// the service runs, it copies new records within seconds.
	LedgerHead uint64   `json:"ledger_head"`
	CopiedUpTo int64    `json:"copied_up_to"`
	NotCopied  int      `json:"not_copied"`
	Problems   []string `json:"problems,omitempty"`
	OK         bool     `json:"ok"`
}

// Verify compares the MongoDB copy in database with the ledger r, record by record: a document
// of the same seq must hold identical h, s and b, h must be the SHA-256 of b, s a valid Ed25519
// signature of b under pub (when pub is not nil), and the fields derived from b (seq, ts, type,
// data, …) must be exactly what the replicator writes for that record. It reports ledger records
// missing from MongoDB up to the newest copied seq (the replication state's, or the newest
// matching document), documents the ledger does not contain (a correctly signed one indicates a
// record removed from the ledger after it was copied; one that does not authenticate is forged),
// blob documents that differ from what the replicator writes for that blob (content that does
// not hash to the id, size, first_seq, a missing content or note) or that no ledger record
// references, missing blobs, incident documents that do not match their ledger record, an
// inconsistent replication state, a database without any record, and a copy that lacks more than
// a quarter of an hour of the newest ledger records. VerifyResult also says where the copy ends.
//
// It also checks the syslog collection against the ledger's syslog_chunk and syslog_prune
// records: the documents of every chunk, their lines in order (each with its line feed), must
// hash to the record's SHA-256 and count to its Messages, and every other field must be exactly
// what the replicator writes for the line; documents of chunks that a syslog_prune record deleted
// (once the copy has applied it), documents of chunks that no syslog_chunk record names (forged),
// and a syslog collection that lags the copied records by more than a quarter of an hour are
// reported. Chunks that the syslog store still holds but the copy lacks can only be found with
// the store: see VerifyWith.
//
// r must be the complete ledger (from genesis). Verify only reads MongoDB (and the ledger).
func Verify(ctx context.Context, uri, database string, r contracts.LedgerReader, pub ed25519.PublicKey) (VerifyResult, error) {
	return VerifyWith(ctx, VerifyOptions{URI: uri, Database: database, Reader: r, PublicKey: pub})
}

// VerifyOptions configures VerifyWith.
type VerifyOptions struct {
	URI      string                 // MongoDB connection string ("" → DefaultURI)
	Database string                 // database name ("" → DefaultDatabase)
	Reader   contracts.LedgerReader // the complete ledger, from genesis (required)
	// PublicKey is the ledger key (nil: signatures are not checked).
	PublicKey ed25519.PublicKey
	// Syslog is the syslog store (nil: the syslog collection is checked against the ledger only).
	// With it, chunks that the store still holds but the copy lacks are reported as missing
	// (VerifyResult.SyslogMissing), and a chunk whose documents do not hash to its record names
	// the lines that differ from the store's copy.
	Syslog contracts.SyslogReader
}

// VerifyWith is Verify with options; it also reads the syslog store when VerifyOptions.Syslog is
// set (and only reads it).
func VerifyWith(ctx context.Context, o VerifyOptions) (VerifyResult, error) {
	uri, database, r, pub := o.URI, o.Database, o.Reader, o.PublicKey
	if r == nil {
		return VerifyResult{}, errors.New("mongostore: Verify needs the ledger reader")
	}
	if pub != nil && len(pub) != ed25519.PublicKeySize {
		return VerifyResult{}, fmt.Errorf("mongostore: the public key has %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
	if uri == "" {
		uri = DefaultURI
	}
	if err := checkURI(uri); err != nil {
		return VerifyResult{}, err
	}
	if database == "" {
		database = DefaultDatabase
	}
	if err := checkDatabaseName(database); err != nil {
		return VerifyResult{}, err
	}
	client, err := mongo.Connect(clientOptions(uri, defaultConnectTimeout))
	if err != nil {
		return VerifyResult{}, fmt.Errorf("mongostore: connect to %s: %w", RedactURI(uri), connectError(uri, err))
	}
	defer func() {
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultConnectTimeout)
		_ = client.Disconnect(dctx)
		cancel()
	}()
	pctx, cancel := context.WithTimeout(ctx, defaultConnectTimeout)
	err = client.Ping(pctx, nil)
	cancel()
	if err != nil {
		return VerifyResult{}, fmt.Errorf("mongostore: MongoDB at %s is unreachable: %w", RedactURI(uri), err)
	}
	v := &verifier{
		ctx:        ctx,
		db:         client.Database(database),
		reader:     r,
		pub:        pub,
		maxMatched: -1,
		blobRefs:   map[string]uint64{},
		pending:    map[string]bool{},
		incidents:  map[string][]uint64{},
		store:      o.Syslog,
		chunks:     map[string]chunkRec{},
		pruned:     map[string]uint64{},
	}
	return v.run()
}

type verifier struct {
	ctx    context.Context
	db     *mongo.Database
	reader contracts.LedgerReader
	pub    ed25519.PublicKey
	res    VerifyResult
	total  int // problems found (Problems is capped)

	ledgerLast uint64 // newest seq of the ledger scan
	haveLedger bool
	headSeq    uint64 // newest ledger seq seen (scan, or a record appended since) …
	headTS     string // … and its ts
	haveHead   bool
	ledger     []seqRange // the ledger seqs seen, ascending
	missing    []seqRange // ledger seqs without a document, ascending
	maxMatched int64      // newest seq whose document holds the ledger's h, s and b (-1: none)
	blobRefs   map[string]uint64
	pending    map[string]bool     // blobs the replication state lists as waiting for a retry
	incidents  map[string][]uint64 // incident id -> seqs of its records, ascending

	store      contracts.SyslogReader // the syslog store (nil: not checked against it)
	chunks     map[string]chunkRec    // syslog_chunk records by chunk name (the first naming it)
	pruned     map[string]uint64      // chunk name -> the first syslog_prune record deleting it
	syslogRecs []syslogRecTS          // syslog_chunk and syslog_prune records, ascending
}

type seqRange struct{ from, to uint64 }

// mongoRec is one document of the records collection.
type mongoRec struct {
	raw   bson.Raw
	seq   uint64
	seqOK bool // _id is a non-negative integer
}

// problem records a problem. Strings taken from MongoDB documents are quoted by the callers;
// whatever could still control a terminal is escaped here.
func (v *verifier) problem(format string, args ...any) {
	v.total++
	if len(v.res.Problems) < maxProblems {
		v.res.Problems = append(v.res.Problems, clip(printable(fmt.Sprintf(format, args...)), maxProblemLen))
	}
}

func (v *verifier) run() (VerifyResult, error) {
	meta, err := v.findMeta()
	if err != nil {
		return v.res, err
	}
	metaNewest, err := v.checkMeta(meta)
	if err != nil {
		return v.res, err
	}
	if err := v.records(); err != nil {
		return v.res, err
	}
	newest := max(metaNewest, v.maxMatched)
	v.countMissing(newest)
	if err := v.blobs(newest); err != nil {
		return v.res, err
	}
	if err := v.checkIncidents(newest); err != nil {
		return v.res, err
	}
	if err := v.checkSyslog(meta, newest); err != nil {
		return v.res, err
	}
	noCopy := v.res.Records == 0
	switch {
	case noCopy && meta == nil:
		v.problem("the database holds no copy of the ledger (no records and no replication state)")
	case noCopy:
		v.problem("the database holds no copy of the ledger (no records, although it has a replication state)")
	}
	if err := v.extent(newest, noCopy); err != nil {
		return v.res, err
	}
	if v.total > maxProblems {
		v.res.Problems = append(v.res.Problems[:maxProblems-1], fmt.Sprintf("… and %d more problem(s), not listed", v.total-(maxProblems-1)))
	}
	v.res.OK = v.total == 0
	return v.res, nil
}

func (v *verifier) findMeta() (bson.Raw, error) {
	raw, err := v.db.Collection(collMeta).FindOne(v.ctx, bson.D{{Key: "_id", Value: metaID}}).Raw()
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("mongostore: read the replication state: %w", err)
	}
	return raw, nil
}

// checkMeta checks the identity and the resume point of the replication state and returns its
// newest copied seq (-1 when it has none or cannot be trusted).
func (v *verifier) checkMeta(meta bson.Raw) (int64, error) {
	var ident ledgerIdent
	env, body, err := v.reader.Record(0)
	switch {
	case err == nil:
		ident = identFromGenesis(env, body)
	case !errors.Is(err, contracts.ErrNotFound):
		return -1, fmt.Errorf("mongostore: read the ledger's genesis record: %w", err)
	}
	if v.pub != nil && ident.fingerprint != "" && ident.fingerprint != fingerprintOf(v.pub) {
		v.problem("the public key given (fingerprint %s) is not the key named by the ledger's genesis record (%s)", short(fingerprintOf(v.pub)), short(ident.fingerprint))
	}
	if meta == nil {
		return -1, nil
	}
	if arr, ok := meta.Lookup("pending_blobs").ArrayOK(); ok {
		if vals, err := arr.Values(); err == nil {
			for _, p := range vals {
				if d, ok := p.DocumentOK(); ok {
					if id, ok := rawString(d, "id"); ok && isBlobID(id) {
						v.pending[id] = true
					}
				}
			}
		}
	}
	if fp, _ := rawString(meta, "fingerprint"); fp != "" {
		switch {
		case ident.fingerprint != "" && fp != ident.fingerprint:
			v.problem("meta: names the ledger key fingerprint %s, the ledger's genesis record names %s", short(fp), short(ident.fingerprint))
		case ident.fingerprint == "" && v.pub != nil && fp != fingerprintOf(v.pub):
			v.problem("meta: names the ledger key fingerprint %s, the public key given has %s", short(fp), short(fingerprintOf(v.pub)))
		}
	}
	if gh, _ := rawString(meta, "genesis_hash"); gh != "" && ident.genesisHash != "" && gh != ident.genesisHash {
		v.problem("meta: names the genesis record h %s, the ledger's genesis record has %s", short(gh), short(ident.genesisHash))
	}
	ls, ok := rawInt64(meta, "last_seq")
	if !ok {
		v.problem("meta: last_seq is missing or not an integer")
		return -1, nil
	}
	if ls < 0 {
		return -1, nil
	}
	lh, _ := rawString(meta, "last_hash")
	lenv, _, err := v.reader.Record(uint64(ls))
	switch {
	case errors.Is(err, contracts.ErrNotFound):
		v.problem("meta: last_seq %d is not in the ledger (the copy claims records that the ledger does not have)", ls)
		return -1, nil
	case err != nil:
		return -1, fmt.Errorf("mongostore: read ledger record %d: %w", ls, err)
	case lenv.H != lh:
		v.problem("meta: last_hash %s differs from the ledger's record %d (%s)", short(lh), ls, short(lenv.H))
		return -1, nil
	}
	return ls, nil
}

// records merges the ledger (ascending seq) with the records collection (ascending _id).
func (v *verifier) records() error {
	cur, err := v.db.Collection(collRecords).Find(v.ctx, bson.D{}, options.Find().SetSort(bson.D{{Key: "_id", Value: 1}}))
	if err != nil {
		return fmt.Errorf("mongostore: read records: %w", err)
	}
	defer cur.Close(context.WithoutCancel(v.ctx))
	var m *mongoRec
	next := func() error {
		m = nil
		for cur.Next(v.ctx) {
			v.res.Records++
			doc := mongoRec{raw: append(bson.Raw(nil), cur.Current...)}
			doc.seq, doc.seqOK = rawSeq(doc.raw, "_id")
			if !doc.seqOK {
				v.extra(doc)
				continue
			}
			m = &doc
			return nil
		}
		if err := cur.Err(); err != nil {
			return fmt.Errorf("mongostore: read records: %w", err)
		}
		return nil
	}
	if err := next(); err != nil {
		return err
	}
	var prev uint64
	havePrev := false
	err = v.reader.Scan(0, func(env model.Envelope, body model.Body) error {
		if err := v.ctx.Err(); err != nil {
			return err
		}
		seq := body.Seq
		if havePrev && seq <= prev {
			v.problem("ledger: record seq %d appears after seq %d (run the ledger verification); it was not compared", seq, prev)
			return nil
		}
		prev, havePrev = seq, true
		v.ledgerLast, v.haveLedger = seq, true
		v.noteLedger(seq, body)
		for m != nil && m.seq < seq {
			v.extra(*m)
			if err := next(); err != nil {
				return err
			}
		}
		if m != nil && m.seq == seq {
			v.compare(*m, env, body)
			return next()
		}
		v.addMissing(seq)
		return nil
	})
	if err != nil {
		return fmt.Errorf("mongostore: compare with the ledger: %w", err)
	}
	// Documents beyond the scanned ledger: the ledger may have grown since the scan.
	for m != nil {
		env, body, err := v.reader.Record(m.seq)
		switch {
		case err == nil && body.Seq == m.seq && (!v.haveLedger || m.seq > v.ledgerLast):
			v.noteLedger(m.seq, body)
			v.compare(*m, env, body)
		case err == nil || errors.Is(err, contracts.ErrNotFound):
			v.extra(*m)
		default:
			return fmt.Errorf("mongostore: read ledger record %d: %w", m.seq, err)
		}
		if err := next(); err != nil {
			return err
		}
	}
	return nil
}

// noteLedger remembers a ledger record: its seq, its blobs, its incident and its syslog chunks.
func (v *verifier) noteLedger(seq uint64, body model.Body) {
	v.noteSyslog(seq, body)
	if n := len(v.ledger); n > 0 && v.ledger[n-1].to+1 == seq {
		v.ledger[n-1].to = seq
	} else {
		v.ledger = append(v.ledger, seqRange{from: seq, to: seq})
	}
	if !v.haveHead || seq > v.headSeq {
		v.headSeq, v.headTS, v.haveHead = seq, body.TS, true
	}
	for _, id := range body.Blobs {
		if _, ok := v.blobRefs[id]; !ok {
			v.blobRefs[id] = seq
		}
	}
	if isIncidentType(body.Type) {
		if id := incidentID(body.Data); id != "" {
			v.incidents[id] = append(v.incidents[id], seq)
		}
	}
}

// authResult is the self-check of a document: does b hash to h, and is s its signature?
type authResult struct {
	hashOK, sigChecked, sigOK bool
	why                       string
}

func (a authResult) ok() bool { return a.hashOK && (!a.sigChecked || a.sigOK) }

func (v *verifier) authenticate(doc bson.Raw) authResult {
	h, _ := rawString(doc, "h")
	s, _ := rawString(doc, "s")
	b, bOK := rawString(doc, "b")
	var a authResult
	var why []string
	a.hashOK = bOK && h != "" && sha256Hex([]byte(b)) == h
	if !a.hashOK {
		why = append(why, "h is not the SHA-256 of b")
	}
	if v.pub != nil {
		a.sigChecked = true
		if sig, err := decodeSignature(s); err == nil && bOK && ed25519.Verify(v.pub, []byte(b), sig) {
			a.sigOK = true
		} else {
			why = append(why, "s is not a valid signature of b under the ledger key")
		}
	}
	a.why = strings.Join(why, "; ")
	return a
}

// bodySeqIs reports whether the body b carries seq.
func bodySeqIs(b string, seq uint64) bool {
	var body struct {
		Seq *uint64 `json:"seq"`
	}
	if json.Unmarshal([]byte(b), &body) != nil || body.Seq == nil {
		return false
	}
	return *body.Seq == seq
}

// compare checks a document against the ledger record of the same seq.
func (v *verifier) compare(m mongoRec, env model.Envelope, body model.Body) {
	v.res.Checked++
	h, _ := rawString(m.raw, "h")
	s, _ := rawString(m.raw, "s")
	b, _ := rawString(m.raw, "b")
	var diff []string
	if h != env.H {
		diff = append(diff, "h")
	}
	if s != env.S {
		diff = append(diff, "s")
	}
	if b != env.B {
		diff = append(diff, "b")
	}
	a := v.authenticate(m.raw)
	if !a.ok() {
		v.res.BadHash++
		if len(diff) == 0 {
			v.problem("seq %d: the ledger record itself does not authenticate (%s); the copy matches it (run the ledger verification)", m.seq, a.why)
		} else {
			v.problem("seq %d: %s", m.seq, a.why)
		}
	}
	if len(diff) > 0 {
		v.res.Mismatched++
		note := ""
		if a.ok() && a.sigChecked && bodySeqIs(b, m.seq) {
			note = "; the MongoDB version is correctly signed by the ledger key: the ledger record was replaced after it was copied"
		}
		v.problem("seq %d: %s differ(s) from the ledger%s", m.seq, strings.Join(diff, ", "), note)
		return
	}
	if int64(m.seq) > v.maxMatched {
		v.maxMatched = int64(m.seq)
	}
	if keys := derivedDiff(m.raw, env, body); len(keys) > 0 {
		v.res.Mismatched++
		v.problem("seq %d: field(s) %s do not match the signed body b (the queryable copy was altered)", m.seq, strings.Join(keys, ", "))
	}
}

// derivedDiff lists the fields of doc that differ from what the replicator writes for the record
// (nil when doc is exactly one of the forms it writes).
func derivedDiff(doc bson.Raw, env model.Envelope, body model.Body) []string {
	want, err := recordDoc(env, body, dataConvert)
	if err == nil && bytes.Equal(doc, want) {
		return nil
	}
	if alt, aerr := recordDoc(env, body, dataAsJSON); aerr == nil && bytes.Equal(doc, alt) {
		return nil
	}
	if err != nil {
		return []string{"(the expected document cannot be built: " + clip(err.Error(), 120) + ")"}
	}
	if keys := diffKeys(doc, want); len(keys) > 0 {
		return keys
	}
	return []string{"(encoding)"}
}

// extra reports a document that the ledger does not contain.
func (v *verifier) extra(m mongoRec) {
	v.res.Mismatched++
	if !m.seqOK {
		v.problem("records: the document with _id %s is not a ledger seq (forged or foreign)", clip(m.raw.Lookup("_id").String(), 80))
		return
	}
	a := v.authenticate(m.raw)
	b, _ := rawString(m.raw, "b")
	switch {
	case a.ok() && a.sigChecked && bodySeqIs(b, m.seq):
		v.problem("seq %d: MongoDB holds a record, correctly signed by the ledger key, that the ledger does not contain (removed from the ledger after it was copied?)", m.seq)
	case a.ok() && !a.sigChecked && bodySeqIs(b, m.seq):
		v.problem("seq %d: MongoDB holds a record that the ledger does not contain (its hash is consistent; the signature was not checked without a public key)", m.seq)
	default:
		why := a.why
		if a.ok() {
			why = "its body b is not record " + fmt.Sprint(m.seq)
		} else {
			v.res.BadHash++
		}
		v.problem("seq %d: MongoDB holds a document that the ledger does not contain and that does not authenticate (%s): forged", m.seq, why)
	}
}

func (v *verifier) addMissing(seq uint64) {
	if n := len(v.missing); n > 0 && v.missing[n-1].to+1 == seq {
		v.missing[n-1].to = seq
		return
	}
	v.missing = append(v.missing, seqRange{from: seq, to: seq})
}

// countMissing reports the ledger records up to newest that have no document.
func (v *verifier) countMissing(newest int64) {
	if newest < 0 {
		return
	}
	for _, rg := range v.missing {
		if rg.from > uint64(newest) {
			break
		}
		to := min(rg.to, uint64(newest))
		n := to - rg.from + 1
		v.res.Missing += int(n)
		if n == 1 {
			v.problem("seq %d: missing from MongoDB", rg.from)
		} else {
			v.problem("seqs %d-%d: missing from MongoDB (%d records)", rg.from, to, n)
		}
	}
}

// extent says where the copy ends compared with the ledger, and reports a copy that lacks more
// than staleRecords of the newest ledger records, written over more than staleAfter.
func (v *verifier) extent(newest int64, noCopy bool) error {
	v.res.LedgerHead, v.res.CopiedUpTo = v.headSeq, newest
	var first uint64
	n := 0
	for _, rg := range v.ledger {
		if newest >= 0 && rg.to <= uint64(newest) {
			continue
		}
		from := rg.from
		if newest >= 0 && from <= uint64(newest) {
			from = uint64(newest) + 1
		}
		if n == 0 {
			first = from
		}
		n += int(rg.to - from + 1)
	}
	v.res.NotCopied = n
	if n <= staleRecords || noCopy {
		return nil
	}
	_, body, err := v.reader.Record(first)
	if err != nil && !errors.Is(err, contracts.ErrNotFound) {
		return fmt.Errorf("mongostore: read ledger record %d: %w", first, err)
	}
	if from, ok := parseTS(body.TS); ok {
		if to, ok := parseTS(v.headTS); ok && to.Sub(from) <= staleAfter {
			return nil
		}
	}
	v.problem("the copy is behind the ledger: %d record(s) from seq %d on (written from %s to %s) are not in MongoDB; the service copies new records within seconds while it runs and MongoDB is reachable",
		n, first, body.TS, v.headTS)
	return nil
}

// blobs checks every blob document and the blobs referenced by copied records.
func (v *verifier) blobs(newest int64) error {
	cur, err := v.db.Collection(collBlobs).Find(v.ctx, bson.D{}, options.Find().SetSort(bson.D{{Key: "_id", Value: 1}}))
	if err != nil {
		return fmt.Errorf("mongostore: read blobs: %w", err)
	}
	defer cur.Close(context.WithoutCancel(v.ctx))
	seen := map[string]bool{}
	for cur.Next(v.ctx) {
		doc := append(bson.Raw(nil), cur.Current...)
		idv := doc.Lookup("_id")
		id, ok := idv.StringValueOK()
		if !ok || !isBlobID(id) {
			v.res.BlobsCorrupt++
			v.problem("blobs: the document with _id %s is not a SHA-256 blob id", clip(idv.String(), 80))
			continue
		}
		seen[id] = true
		if err := v.checkBlob(doc, id); err != nil {
			return err
		}
	}
	if err := cur.Err(); err != nil {
		return fmt.Errorf("mongostore: read blobs: %w", err)
	}
	type ref struct {
		id  string
		seq uint64
	}
	var missing []ref
	for id, seq := range v.blobRefs {
		if !seen[id] && newest >= 0 && seq <= uint64(newest) {
			missing = append(missing, ref{id, seq})
		}
	}
	slices.SortFunc(missing, func(a, b ref) int {
		if a.seq != b.seq {
			if a.seq < b.seq {
				return -1
			}
			return 1
		}
		return strings.Compare(a.id, b.id)
	})
	for _, m := range missing {
		v.res.BlobsMissing++
		note := ""
		if v.pending[m.id] {
			note = " (the replicator could not read it from the ledger yet and reads it again on later passes)"
		}
		v.problem("blob %s (referenced by seq %d): missing from MongoDB%s", printableID(m.id), m.seq, note)
	}
	return nil
}

// printableID shows a blob id taken from the ledger: a valid id as is, anything else quoted.
func printableID(id string) string {
	if isBlobID(id) {
		return id
	}
	return quote(id)
}

// checkBlob compares a blob document with the document the replicator writes for that blob:
// content (when stored) that hashes to its id, a ledger record referencing it, and exactly the
// fields the replicator writes — size, first_seq (the first ledger record referencing it), and
// the content or the note saying why it is not stored. The size of a document without content is
// checked against the ledger's copy of the blob.
func (v *verifier) checkBlob(doc bson.Raw, id string) error {
	first, referenced, err := v.blobFirstRef(doc, id)
	if err != nil {
		return err
	}
	var storedAt time.Time
	if ms, ok := doc.Lookup("stored_at").DateTimeOK(); ok {
		storedAt = time.UnixMilli(ms)
	}
	if dv, err := doc.LookupErr("data"); err == nil {
		v.res.BlobsChecked++
		_, content, ok := dv.BinaryOK()
		switch {
		case !ok:
			v.res.BlobsCorrupt++
			v.problem("blob %s: data is not binary", id)
		case sha256Hex(content) != id:
			v.res.BlobsCorrupt++
			v.problem("blob %s: its content hashes to %s", id, short(sha256Hex(content)))
		case !referenced:
			v.res.BlobsCorrupt++
			v.problem("blob %s: no ledger record references it (forged or foreign)", id)
		default:
			v.compareBlob(doc, id, mustMarshalD(blobDoc(id, content, first, true, storedAt)))
		}
		return nil
	}
	if !referenced {
		v.res.BlobsCorrupt++
		v.problem("blob %s: no ledger record references it (forged or foreign)", id)
		return nil
	}
	content, err := v.reader.GetBlob(id)
	switch {
	case errors.Is(err, contracts.ErrNotFound):
		v.problem("blob %s: the ledger's blob store does not hold it, so its document cannot be checked (run the ledger verification)", id)
		return nil
	case err != nil:
		return fmt.Errorf("mongostore: read ledger blob %s: %w", id, err)
	case sha256Hex(content) != id:
		v.problem("blob %s: the ledger's copy does not match its id, so its document cannot be checked (run the ledger verification)", id)
		return nil
	}
	notStored := mustMarshalD(blobDoc(id, content, first, false, storedAt))
	stored := mustMarshalD(blobDoc(id, content, first, true, storedAt)) // the too_large form for a blob over 15 MB
	if bytes.Equal(doc, notStored) || (len(content) > maxBlobBytes && bytes.Equal(doc, stored)) {
		return nil
	}
	want := stored // the content was removed (or the document says neither why it is absent)
	if note, _ := rawString(doc, "note"); note == noteBlobNotStored {
		want = notStored
	}
	v.compareBlob(doc, id, want)
	return nil
}

// compareBlob reports a blob document that is not exactly want.
func (v *verifier) compareBlob(doc bson.Raw, id string, want bson.Raw) {
	if bytes.Equal(doc, want) {
		return
	}
	keys := diffKeys(doc, want)
	if len(keys) == 0 {
		keys = []string{"(encoding)"}
	}
	v.res.BlobsCorrupt++
	v.problem("blob %s: field(s) %s do not match what the ledger gives for this blob", id, strings.Join(keys, ", "))
}

// blobFirstRef returns the first ledger record referencing blob id (false when none does).
func (v *verifier) blobFirstRef(doc bson.Raw, id string) (uint64, bool, error) {
	if first, ok := v.blobRefs[id]; ok {
		return first, true, nil
	}
	// The replicator writes a blob before the records referencing it: a record appended after
	// the ledger scan may reference it.
	fs, ok := rawSeq(doc, "first_seq")
	if !ok || (v.haveLedger && fs <= v.ledgerLast) {
		return 0, false, nil
	}
	_, body, err := v.reader.Record(fs)
	switch {
	case errors.Is(err, contracts.ErrNotFound):
		return 0, false, nil
	case err != nil:
		return 0, false, fmt.Errorf("mongostore: read ledger record %d: %w", fs, err)
	}
	return fs, body.Seq == fs && slices.Contains(body.Blobs, id), nil
}

// mustMarshalD encodes a document built by this package (it cannot fail).
func mustMarshalD(d bson.D) bson.Raw {
	raw, err := bson.Marshal(d)
	if err != nil {
		panic(fmt.Sprintf("mongostore: encode a blob document: %v", err))
	}
	return raw
}

// checkIncidents checks every incident document against its ledger record and reports
// incidents of copied records that are missing or stale.
func (v *verifier) checkIncidents(newest int64) error {
	cur, err := v.db.Collection(collIncidents).Find(v.ctx, bson.D{}, options.Find().SetSort(bson.D{{Key: "_id", Value: 1}}))
	if err != nil {
		return fmt.Errorf("mongostore: read incidents: %w", err)
	}
	defer cur.Close(context.WithoutCancel(v.ctx))
	seen := map[string]bool{}
	for cur.Next(v.ctx) {
		doc := append(bson.Raw(nil), cur.Current...)
		idv := doc.Lookup("_id")
		id, ok := idv.StringValueOK()
		if !ok {
			v.problem("incidents: the document with _id %s is not an incident id", clip(idv.String(), 80))
			continue
		}
		seen[id] = true
		seq, ok := rawSeq(doc, "seq")
		if !ok {
			v.problem("incident %s: seq is missing or invalid", quote(id))
			continue
		}
		env, body, err := v.reader.Record(seq)
		switch {
		case errors.Is(err, contracts.ErrNotFound):
			v.problem("incident %s: refers to seq %d, which the ledger does not contain", quote(id), seq)
			continue
		case err != nil:
			return fmt.Errorf("mongostore: read ledger record %d: %w", seq, err)
		}
		if !isIncidentType(body.Type) || incidentID(body.Data) != id {
			v.problem("incident %s: ledger record %d is not a record of this incident", quote(id), seq)
			continue
		}
		if keys := incidentDiff(doc, id, env, body); len(keys) > 0 {
			v.problem("incident %s: field(s) %s do not match ledger record %d", quote(id), strings.Join(keys, ", "), seq)
		}
		if latest, ok := latestAtMost(v.incidents[id], newest); ok && seq < latest {
			v.problem("incident %s: MongoDB holds record %d, but the newer record %d was copied (stale)", quote(id), seq, latest)
		}
	}
	if err := cur.Err(); err != nil {
		return fmt.Errorf("mongostore: read incidents: %w", err)
	}
	ids := make([]string, 0, len(v.incidents))
	for id := range v.incidents {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		if latest, ok := latestAtMost(v.incidents[id], newest); ok && !seen[id] {
			v.problem("incident %s (ledger record %d): missing from MongoDB", quote(id), latest)
		}
	}
	return nil
}

// incidentDiff lists the fields of an incident document that differ from what the replicator
// writes for the record (its "updated" time is taken from the document).
func incidentDiff(doc bson.Raw, id string, env model.Envelope, body model.Body) []string {
	ms, ok := doc.Lookup("updated").DateTimeOK()
	if !ok {
		return []string{quote("updated")}
	}
	updated := time.UnixMilli(ms)
	want, err := incidentDoc(id, env, body, dataConvert, updated)
	if err == nil && bytes.Equal(doc, want) {
		return nil
	}
	if alt, aerr := incidentDoc(id, env, body, dataAsJSON, updated); aerr == nil && bytes.Equal(doc, alt) {
		return nil
	}
	if err != nil {
		return []string{"(the expected document cannot be built: " + clip(err.Error(), 120) + ")"}
	}
	if keys := diffKeys(doc, want); len(keys) > 0 {
		return keys
	}
	return []string{"(encoding)"}
}

// latestAtMost returns the largest of the ascending seqs that is <= newest.
func latestAtMost(seqs []uint64, newest int64) (uint64, bool) {
	if newest < 0 {
		return 0, false
	}
	for i := len(seqs) - 1; i >= 0; i-- {
		if seqs[i] <= uint64(newest) {
			return seqs[i], true
		}
	}
	return 0, false
}
