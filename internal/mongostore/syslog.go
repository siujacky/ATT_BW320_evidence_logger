package mongostore

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"runtime/debug"
	"strconv"
	"time"
	"unicode/utf8"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// The syslog collection holds the messages of the syslog store's sealed chunks and follows the
// ledger's syslog_chunk and syslog_prune records in ledger order, within a size limit of its own
// (package comment, "Syslog messages").

const (
	// maxSyslogChunkBytes bounds the uncompressed size of a chunk that is copied (the store seals
	// its chunks at 1 MiB): a record giving a larger size is reported and the chunk not read.
	maxSyslogChunkBytes = 64 << 20
	// maxSyslogLineBytes bounds one line of a chunk (a datagram of at most 8 KiB takes a few times
	// that in JSON): a document holds a line once (raw_line), well within MongoDB's 16 MB
	// document limit.
	maxSyslogLineBytes = 4 << 20
	// defaultSyslogKeepMB is the size limit of the syslog collection, in MiB, when the syslog
	// store reports none (its default limit, syslog.keep_mb).
	defaultSyslogKeepMB = 100
	// syslogTrimPerPass bounds the chunks whose documents one pass deletes to keep the syslog
	// collection within its size limit; the next pass goes on.
	syslogTrimPerPass = 1000
	// syslogInsertDocs and syslogInsertBytes bound one insert of a chunk's documents.
	syslogInsertDocs  = 1000
	syslogInsertBytes = 8 << 20
	// syslogDeleteNames bounds the chunks named by one deletion.
	syslogDeleteNames = 500
	// syslogExtraDocs bounds the documents of a chunk that are read beyond its lines (documents
	// that are no lines of the chunk are reported, not read without end).
	syslogExtraDocs = 1000
	// One pass applies at most syslogOpsPerPass syslog records and writes or checks about
	// syslogDocsPerPass documents at most; the next pass goes on. A long catch-up so never holds
	// up the copy of new records for long.
	syslogOpsPerPass  = 4096
	syslogDocsPerPass = 100_000
	// syslogMaxQueue bounds the syslog records held in memory until they are applied; further ones
	// are read from the ledger when their turn comes.
	syslogMaxQueue = 4096
	// syslogReadAttempts is the number of reads of a chunk that fails in one pass (with short
	// pauses) before it waits for the next pass.
	syslogReadAttempts = 3
	// syslogGiveUp: a chunk that cannot be read for this long (for another reason than the store
	// no longer holding it) is reported and skipped, so that it does not hold back the later syslog
	// records for good.
	syslogGiveUp = 10 * time.Minute
)

// noteSyslogUndecoded is stored with a line that is not a message as the syslog store writes it.
// Like the other notes it is part of the documents, which Verify re-derives byte for byte, so it
// must not change within one copyFormat.
const noteSyslogUndecoded = "not a syslog message as the syslog store writes it (a JSON object in UTF-8); raw_line holds the exact line"

// ---------------------------------------------------------------- documents

// syslogID is the _id of the document of line number line (from 1) of chunk name.
func syslogID(name string, line int64) string { return name + "#" + strconv.FormatInt(line, 10) }

// syslogDoc builds the syslog document of line number line (from 1) of chunk name, whose
// syslog_chunk record has seq; raw is the exact line without its line feed. The layout is
// deterministic: the same line always gives the same bytes (Verify relies on it). raw_line is a
// string, or BinData (subtype 0) when the line is not valid UTF-8; the other fields come from the
// decoded message, or are undecoded and note when the line is not a message as the store writes
// it. The message's text is not stored again beside raw_line, which holds it: the collection's
// size limit then holds more messages.
func syslogDoc(name string, seq uint64, line int64, raw []byte) (bson.Raw, error) {
	if seq > math.MaxInt64 {
		return nil, fmt.Errorf("seq %d is outside the int64 range of MongoDB", seq)
	}
	d := make(bson.D, 0, 16)
	d = append(d,
		bson.E{Key: "_id", Value: syslogID(name, line)},
		bson.E{Key: "chunk", Value: name},
		bson.E{Key: "chunk_seq", Value: int64(seq)},
		bson.E{Key: "line", Value: line},
	)
	if utf8.Valid(raw) {
		d = append(d, bson.E{Key: "raw_line", Value: string(raw)})
	} else {
		d = append(d, bson.E{Key: "raw_line", Value: bson.Binary{Subtype: 0x00, Data: raw}})
	}
	if m, ok := decodeSyslogLine(raw); ok {
		if t, ok := parseTS(m.RX); ok {
			d = append(d, bson.E{Key: "rx", Value: bson.NewDateTimeFromTime(t)})
		}
		d = append(d, bson.E{Key: "rx_text", Value: m.RX}, bson.E{Key: "src", Value: m.Src})
		if m.Severity != nil {
			d = append(d, bson.E{Key: "severity", Value: int64(*m.Severity)})
		}
		if m.Facility != nil {
			d = append(d, bson.E{Key: "facility", Value: int64(*m.Facility)})
		}
		for _, f := range []struct{ key, value string }{{"host", m.Host}, {"app", m.App}} {
			if f.value != "" {
				d = append(d, bson.E{Key: f.key, Value: f.value})
			}
		}
	} else {
		d = append(d, bson.E{Key: "undecoded", Value: true}, bson.E{Key: "note", Value: noteSyslogUndecoded})
	}
	d = append(d, bson.E{Key: "copy_format", Value: int32(copyFormat)})
	raw2, err := bson.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("encode syslog line %s: %w", syslogID(name, line), err)
	}
	return raw2, nil
}

// decodeSyslogLine decodes a chunk line as the syslog store writes it: one JSON object of a
// model.SyslogMessage, in valid UTF-8 (false for anything else).
func decodeSyslogLine(raw []byte) (model.SyslogMessage, bool) {
	var m model.SyslogMessage
	if !utf8.Valid(raw) {
		return m, false
	}
	if i := skipSpace(raw, 0); i >= len(raw) || raw[i] != '{' {
		return m, false
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return model.SyslogMessage{}, false
	}
	return m, true
}

// ---------------------------------------------------------------- chunks

// chunkError: the chunk in the syslog store is damaged or is not the chunk that its syslog_chunk
// record describes (reading it again gives the same), or it could not be read for too long.
type chunkError struct{ why string }

func (e *chunkError) Error() string { return e.why }

// readChunk reads chunk c from the syslog store and returns its lines (without their line
// feeds), once its uncompressed content matches the syslog_chunk record: the size, the SHA-256,
// and the number of lines, each ending in a line feed. A chunk that the store does not hold gives
// an error wrapping contracts.ErrNotFound, a damaged or different one a *chunkError; other errors
// (a file locked by another program) may pass.
func readChunk(sr contracts.SyslogReader, c *model.SyslogChunk) ([][]byte, error) {
	if c.Bytes < 0 || c.Bytes > maxSyslogChunkBytes {
		return nil, &chunkError{why: fmt.Sprintf("its record gives a size of %d bytes (at most %d are copied)", c.Bytes, maxSyslogChunkBytes)}
	}
	rc, err := sr.OpenChunk(c.Name)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	gz, err := gzip.NewReader(rc)
	if err != nil {
		return nil, gzipError(err)
	}
	// One byte more than the record says: a longer chunk is told from one of the right size.
	content, err := io.ReadAll(io.LimitReader(gz, c.Bytes+1))
	if err != nil {
		return nil, gzipError(err)
	}
	if why := checkChunk(c, content); why != "" {
		return nil, &chunkError{why: why}
	}
	return chunkLines(content), nil
}

// gzipError classifies an error reading a chunk's gzip stream: a damaged or truncated stream is a
// *chunkError, anything else (an error reading the file) may pass.
func gzipError(err error) error {
	var ce flate.CorruptInputError
	if errors.Is(err, gzip.ErrHeader) || errors.Is(err, gzip.ErrChecksum) || errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) || errors.As(err, &ce) {
		return &chunkError{why: "its file is not a complete gzip stream (" + clip(err.Error(), 200) + ")"}
	}
	return err
}

// checkChunk returns why content is not the uncompressed chunk that c describes ("" when it is).
func checkChunk(c *model.SyslogChunk, content []byte) string {
	switch n := int64(len(content)); {
	case n > c.Bytes:
		return fmt.Sprintf("it holds more than the %d bytes its record gives", c.Bytes)
	case n != c.Bytes:
		return fmt.Sprintf("it holds %d bytes, its record gives %d", n, c.Bytes)
	}
	if sum := sha256Hex(content); sum != c.SHA256 {
		return fmt.Sprintf("its SHA-256 is %s, its record gives %s", short(sum), short(c.SHA256))
	}
	if len(content) > 0 && content[len(content)-1] != '\n' {
		return "its last line does not end with a line feed"
	}
	if n := bytes.Count(content, []byte{'\n'}); n != c.Messages {
		return fmt.Sprintf("it holds %d lines, its record gives %d messages", n, c.Messages)
	}
	for i, line := range chunkLines(content) {
		if len(line) > maxSyslogLineBytes {
			return fmt.Sprintf("its line %d has %d bytes (at most %d fit a document)", i+1, len(line), maxSyslogLineBytes)
		}
	}
	return ""
}

// chunkLines splits the content of a chunk, every line ending in a line feed, into its lines
// without their line feeds (a rest without a line feed, which checkChunk refuses, is a last line).
func chunkLines(content []byte) [][]byte {
	lines := make([][]byte, 0, bytes.Count(content, []byte{'\n'})+1)
	for len(content) > 0 {
		i := bytes.IndexByte(content, '\n')
		if i < 0 {
			lines = append(lines, content)
			break
		}
		lines = append(lines, content[:i:i])
		content = content[i+1:]
	}
	return lines
}

// ---------------------------------------------------------------- syslog records

// syslogOp is a syslog_chunk or syslog_prune record of the ledger, to be applied to the syslog
// collection.
type syslogOp struct {
	seq   uint64
	chunk *model.SyslogChunk // the chunk that a syslog_chunk record sealed …
	prune []string           // … or the chunks that a syslog_prune record deleted
	bad   string             // why the record cannot be applied ("" when it can)
}

// syslogOpOf returns the syslog operation of a ledger record (false for records of other types).
func syslogOpOf(it item) (syslogOp, bool) {
	op := syslogOp{seq: it.body.Seq}
	switch it.body.Type {
	case model.TypeSyslogChunk:
		var c model.SyslogChunk
		switch err := json.Unmarshal(it.body.Data, &c); {
		case err != nil:
			op.bad = "its payload is not a syslog chunk (" + clip(err.Error(), 200) + ")"
		case c.Name == "" || len(c.Name) > 1024 || !utf8.ValidString(c.Name):
			op.bad = "it names the chunk " + quote(c.Name) + ", which is no chunk name"
		default:
			op.chunk = &c
		}
	case model.TypeSyslogPrune:
		var p model.SyslogPrune
		if err := json.Unmarshal(it.body.Data, &p); err != nil {
			op.bad = "its payload is not a syslog prune (" + clip(err.Error(), 200) + ")"
			break
		}
		seen := map[string]bool{}
		for _, d := range p.Deleted {
			if !seen[d.Name] {
				seen[d.Name] = true
				op.prune = append(op.prune, d.Name)
			}
		}
	default:
		return syslogOp{}, false
	}
	return op, true
}

// ---------------------------------------------------------------- following the ledger

// syslogState is how far the syslog collection follows the ledger (guarded by Replicator.sem).
// Every syslog record below upTo that has not been applied yet is in ops, in seq order; the
// syslog records below ops[0] (below upTo when ops is empty) have been applied.
type syslogState struct {
	ops  []syslogOp
	upTo uint64
	coll string // UUID of the syslog collection they were applied to ("" when it did not exist)
	// trimmed is the last chunk, by name, whose documents the size limit deleted ("" none): no
	// chunk up to it has to be in the collection.
	trimmed string
	// What the replication state holds: syslog_seq (-2: unknown), syslog_collection and
	// syslog_trimmed.
	savedSeq     int64
	savedColl    string
	savedTrimmed string
	full         bool   // applying every syslog record from seq 0: the whole collection is checked
	problems     int    // syslog problems found since full was set
	resetWhy     string // the syslog collection was dropped or replaced: apply everything again
	indexes      bool   // the indexes of the syslog collection were ensured
	failSeq      uint64 // the syslog_chunk record whose chunk could not be read …
	failSince    time.Time
	trimmedTo    int64 // the size limit the collection was last kept to (0: not yet)
}

// applied returns the newest seq up to which every syslog record has been applied (-1: none).
func (s *syslogState) applied() int64 {
	if len(s.ops) > 0 {
		return int64(s.ops[0].seq) - 1
	}
	return int64(s.upTo) - 1
}

// restart makes the follower apply every syslog record again, from seq 0, to collection coll.
func (s *syslogState) restart(coll string) {
	s.resume(0, coll)
	s.full = true
}

// resume makes the follower go on from seq upTo (the replication state's syslog_seq + 1).
func (s *syslogState) resume(upTo uint64, coll string) {
	s.ops, s.upTo, s.coll = nil, upTo, coll
	s.full, s.problems, s.resetWhy = false, 0, ""
	s.failSeq, s.failSince = 0, time.Time{}
	s.trimmed, s.trimmedTo = "", 0
}

// feed queues the syslog records of a batch that the copy of new records has just stored. A batch
// that starts beyond upTo (a gap: after a restart, or while the queue was full) is left to the
// scan of the ledger.
func (s *syslogState) feed(batch []item) {
	if len(batch) == 0 || s.upTo < batch[0].body.Seq {
		return
	}
	for _, it := range batch {
		if it.body.Seq < s.upTo {
			continue
		}
		if op, ok := syslogOpOf(it); ok {
			if len(s.ops) >= syslogMaxQueue {
				s.upTo = it.body.Seq
				return
			}
			s.ops = append(s.ops, op)
		}
		s.upTo = it.body.Seq + 1
	}
}

// noteCollection compares the syslog collection's UUID now with the one the follower writes to:
// a collection that appeared is adopted (created by the follower's own writes); another one means
// that it was dropped or replaced, and every syslog record is applied again.
func (s *syslogState) noteCollection(cur string) {
	switch {
	case cur == s.coll:
	case s.coll == "":
		s.coll = cur
	default:
		s.resetWhy = "the syslog collection was dropped or replaced"
	}
}

// loadSyslog resumes the follower where the replication state (nil: none) says that the syslog
// collection follows the ledger. A state without it (nothing followed yet, or written by an older
// version), naming another syslog collection (dropped or replaced since) or holding an invalid
// syslog_seq makes the follower apply every syslog record again, from seq 0.
func (r *Replicator) loadSyslog(meta bson.Raw) {
	s := r.sys
	if s == nil {
		return
	}
	cur := r.colls[collSyslog]
	var (
		seq int64
		ok  bool
	)
	if meta != nil {
		seq, ok = rawInt64(meta, "syslog_seq")
	}
	s.savedSeq, s.savedColl, s.savedTrimmed = -2, "", ""
	if ok {
		s.savedSeq = seq
		s.savedColl, _ = rawString(meta, "syslog_collection")
		s.savedTrimmed, _ = rawString(meta, "syslog_trimmed")
	}
	switch {
	case !ok:
		s.restart(cur)
	case s.savedColl != cur:
		s.restart(cur)
		r.log.Warn("MongoDB copy: the syslog collection was dropped or replaced since the copy was made; the syslog messages are copied again",
			"database", r.o.Database)
	case seq < -1 || seq >= int64(r.next):
		s.restart(cur)
		r.log.Warn("MongoDB copy: the replication state names an invalid syslog_seq; the syslog messages are copied again",
			"database", r.o.Database, "syslog_seq", seq)
	default:
		s.resume(uint64(seq+1), cur)
		s.trimmed = s.savedTrimmed
	}
}

// metaSyslog returns the fields of the replication state that say how far the syslog collection
// follows the ledger and what its size limit deleted (none without Options.Syslog).
func (r *Replicator) metaSyslog() bson.D {
	if r.sys == nil {
		return nil
	}
	return bson.D{{Key: "syslog_seq", Value: r.sys.applied()}, {Key: "syslog_collection", Value: r.sys.coll},
		{Key: "syslog_trimmed", Value: r.sys.trimmed}}
}

// syslogSaved notes that the replication state now holds what metaSyslog returned.
func (r *Replicator) syslogSaved() {
	if r.sys != nil {
		r.sys.savedSeq, r.sys.savedColl, r.sys.savedTrimmed = r.sys.applied(), r.sys.coll, r.sys.trimmed
	}
}

// ensureSyslogLocked creates the indexes of the syslog collection (and so the collection) where
// they are missing.
func (r *Replicator) ensureSyslogLocked(ctx context.Context) error {
	opCtx, cancel := r.opCtx(ctx)
	defer cancel()
	_, err := r.coll(collSyslog).Indexes().CreateMany(opCtx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "rx", Value: -1}}},
		{Keys: bson.D{{Key: "chunk", Value: 1}}},
	})
	var ce mongo.CommandError
	if errors.As(err, &ce) && (ce.Code == 85 || ce.Code == 86) {
		// An index on the same keys exists under another name or with other options: it serves.
		r.log.Warn("MongoDB copy: an index of the syslog collection differs from the expected one", "err", clip(err.Error(), maxProblemLen))
		err = nil
	}
	if err != nil {
		return fmt.Errorf("create the indexes of the syslog collection: %w", err)
	}
	r.sys.indexes = true
	return nil
}

// followSyslogLocked applies the syslog records copied so far to the syslog collection, in ledger
// order and within the budget of one pass, and records in the replication state how far it got.
// It never fails the pass: problems are reported in Status and in the log. It reports whether
// documents were stored or deleted.
func (r *Replicator) followSyslogLocked(ctx context.Context) (changed bool) {
	s := r.sys
	if s == nil || !r.copied {
		return false
	}
	defer func() {
		// The syslog copy must not stop the service, nor fail the copy of the records.
		if p := recover(); p != nil {
			if r.syslogWaiting(fmt.Sprintf("internal error: %v", p)) {
				r.log.Error("MongoDB copy of syslog messages: internal error (recovered)", "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
			}
		}
	}()
	if s.resetWhy != "" {
		r.restartSyslogLocked(ctx)
		changed = true // the collection was dropped or replaced: count it again
	}
	var waitErr error
	if !s.indexes {
		waitErr = r.ensureSyslogLocked(ctx)
	}
	for ops, docs := 0, 0; waitErr == nil && ops < syslogOpsPerPass && docs < syslogDocsPerPass && ctx.Err() == nil; {
		if len(s.ops) == 0 {
			if waitErr = r.fillSyslogLocked(ctx); waitErr != nil || len(s.ops) == 0 {
				break
			}
		}
		res, err := r.applySyslogLocked(ctx, s.ops[0])
		changed = changed || res.changed
		docs += res.docs
		if err != nil {
			waitErr = err
			break
		}
		if s.ops = s.ops[1:]; len(s.ops) == 0 {
			s.ops = nil // let the applied records go
		}
		ops++
	}
	if len(s.ops) == 0 && s.upTo >= r.next && s.full {
		// Every syslog record has been applied again: the whole collection was checked.
		s.full = false
		if s.problems == 0 {
			r.mu.Lock()
			r.st.syslogProblem = ""
			r.mu.Unlock()
		}
	}
	if limit := r.syslogLimit(); s.indexes && ctx.Err() == nil && !shortDeadline(ctx) && (changed || limit != s.trimmedTo) {
		trimmed, err := r.trimSyslogLocked(ctx, limit)
		changed = changed || trimmed
		if err != nil && waitErr == nil {
			waitErr = &syslogTrimError{limit: limit, err: err}
		}
	}
	if err := r.saveSyslogLocked(ctx); err != nil && waitErr == nil {
		waitErr = err
	}
	if ctx.Err() == nil { // an interrupted run (shutdown) is no change of state
		r.syslogWaiting(syslogWaitText(waitErr))
	}
	return changed
}

// syslogWaitText describes why the syslog copy waits ("" for nil).
func syslogWaitText(err error) string {
	var (
		we *syslogWaitError
		te *syslogTrimError
	)
	switch {
	case err == nil:
		return ""
	case errors.As(err, &we):
		return we.Error()
	case errors.As(err, &te):
		return te.Error()
	}
	return "the syslog messages cannot be copied: " + err.Error()
}

// restartSyslogLocked starts the follower again from seq 0 after the minute's check found the
// syslog collection dropped or replaced; the collection and its indexes are created again first.
func (r *Replicator) restartSyslogLocked(ctx context.Context) {
	s := r.sys
	why := s.resetWhy
	s.indexes = false
	coll := ""
	if r.ensureSyslogLocked(ctx) == nil {
		if ids, err := r.collectionIDsLocked(ctx); err == nil {
			coll = ids[collSyslog]
		}
	}
	s.restart(coll)
	r.log.Warn("MongoDB copy: the syslog messages are copied again", "database", r.o.Database, "why", why)
}

// fillSyslogLocked reads from the ledger the syslog records that were copied but are not queued
// (after a restart, a gap, or while the queue was full).
func (r *Replicator) fillSyslogLocked(ctx context.Context) error {
	s := r.sys
	end := r.next
	if s.upTo >= end || len(s.ops) >= syslogMaxQueue {
		return nil
	}
	full := false
	err := r.o.Reader.Scan(s.upTo, func(env model.Envelope, body model.Body) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if body.Seq < s.upTo { // before the start, or a line out of order (copied as the copy did)
			return nil
		}
		if body.Seq >= end {
			return contracts.ErrStop
		}
		if op, ok := syslogOpOf(item{env: env, body: body}); ok {
			if len(s.ops) >= syslogMaxQueue {
				full = true
				return contracts.ErrStop
			}
			s.ops = append(s.ops, op)
		}
		s.upTo = body.Seq + 1
		return nil
	})
	if errors.Is(err, contracts.ErrStop) {
		err = nil
	}
	if err != nil {
		return fmt.Errorf("read the ledger: %w", err)
	}
	if !full {
		s.upTo = end // the ledger holds no further record below end
	}
	return nil
}

// syslogResult is what applying one syslog record did.
type syslogResult struct {
	docs    int  // documents stored, checked or deleted
	changed bool // documents were stored or deleted
}

// applySyslogLocked applies one syslog record. A record that cannot be applied, a chunk that the
// store no longer holds or that does not match its record, and documents that MongoDB holds
// otherwise or rejects are reported and passed over; an error (MongoDB failing, a chunk that
// cannot be read yet) makes the record wait for the next pass.
func (r *Replicator) applySyslogLocked(ctx context.Context, op syslogOp) (syslogResult, error) {
	switch {
	case op.bad != "":
		r.syslogProblem(fmt.Sprintf("ledger record %d cannot be applied to the syslog collection: %s", op.seq, op.bad))
		return syslogResult{}, nil
	case op.chunk != nil:
		return r.copyChunkLocked(ctx, op)
	default:
		return r.deleteChunksLocked(ctx, op)
	}
}

// copyChunkLocked copies the lines of the chunk that a syslog_chunk record sealed.
func (r *Replicator) copyChunkLocked(ctx context.Context, op syslogOp) (syslogResult, error) {
	lines, err := r.readChunkLocked(ctx, op)
	var ce *chunkError
	switch {
	case err == nil:
		return r.insertChunkLocked(ctx, op, lines)
	case errors.Is(err, contracts.ErrNotFound):
		r.syslogSkipped(op)
		return syslogResult{}, nil
	case errors.As(err, &ce):
		r.syslogProblem(fmt.Sprintf("syslog chunk %s (ledger record %d) was not copied: %s", quote(op.chunk.Name), op.seq, ce.why))
		return syslogResult{}, nil
	}
	return syslogResult{}, err
}

// syslogWaitError: a chunk could not be read from the syslog store (for another reason than its
// absence or a mismatch); it and the later syslog records wait for the next pass.
type syslogWaitError struct {
	op  syslogOp
	err error
}

func (e *syslogWaitError) Error() string {
	return fmt.Sprintf("syslog chunk %s (ledger record %d) cannot be read from the syslog store (%s); it and the later syslog messages are copied once it can be read (it is skipped after %v)",
		quote(e.op.chunk.Name), e.op.seq, clip(e.err.Error(), 200), syslogGiveUp)
}

func (e *syslogWaitError) Unwrap() error { return e.err }

// readChunkLocked reads a chunk from the syslog store. A read that fails for another reason than
// the chunk's absence or a mismatch is tried again a few times (with short pauses, unless the
// chunk failed in an earlier pass already) and then waits for the next pass (*syslogWaitError);
// a chunk that has failed for syslogGiveUp is given up (*chunkError).
func (r *Replicator) readChunkLocked(ctx context.Context, op syslogOp) ([][]byte, error) {
	s := r.sys
	attempts := syslogReadAttempts
	if (s.failSeq == op.seq && !s.failSince.IsZero()) || shortDeadline(ctx) {
		attempts = 1
	}
	var err error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			if err := pause(ctx, time.Duration(attempt)*100*time.Millisecond); err != nil {
				return nil, err
			}
		}
		var lines [][]byte
		lines, err = readChunk(r.o.Syslog, op.chunk)
		var ce *chunkError
		if err == nil || errors.Is(err, contracts.ErrNotFound) || errors.As(err, &ce) {
			s.failSeq, s.failSince = 0, time.Time{}
			return lines, err
		}
	}
	now := r.o.Now()
	if s.failSeq != op.seq || s.failSince.IsZero() || now.Before(s.failSince) {
		s.failSeq, s.failSince = op.seq, now
	}
	if waited := now.Sub(s.failSince); waited >= syslogGiveUp {
		s.failSeq, s.failSince = 0, time.Time{}
		return nil, &chunkError{why: fmt.Sprintf("it could not be read from the syslog store for %v (%s)", waited.Round(time.Second), clip(err.Error(), 200))}
	}
	return nil, &syslogWaitError{op: op, err: err}
}

// pause waits for d or until ctx is done.
func pause(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// chunkReport collects what storing a chunk's documents met, for one problem of each kind.
type chunkReport struct {
	conflicts, rejected int
	conflictID          string // the first _id under which MongoDB holds another document
	rejectedID          string // the first line that MongoDB rejected …
	rejectedErr         string // … and why
}

// insertChunkLocked stores the documents of a chunk's lines that MongoDB lacks. A document
// already present counts as copied when it is identical; anything else under its _id is reported
// and never overwritten, and so are documents of the chunk that are no lines of it. A document
// that the server rejects is reported (the copy then lacks that line, which Verify shows).
func (r *Replicator) insertChunkLocked(ctx context.Context, op syslogOp, lines [][]byte) (syslogResult, error) {
	name := op.chunk.Name
	existing, extra, err := r.chunkDocsLocked(ctx, name, len(lines))
	if err != nil {
		return syslogResult{}, err
	}
	res := syslogResult{docs: len(lines)}
	var (
		rep  chunkReport
		docs []bson.Raw
		size int
	)
	flush := func() error {
		n, err := r.insertSyslogLocked(ctx, docs, &rep)
		res.changed = res.changed || n > 0
		docs, size = nil, 0
		return err
	}
	for i, raw := range lines {
		line := int64(i + 1)
		doc, err := syslogDoc(name, op.seq, line, raw)
		if err != nil {
			r.syslogProblem(fmt.Sprintf("syslog chunk %s (ledger record %d): line %d was not copied: %v", quote(name), op.seq, line, err))
			continue
		}
		id := syslogID(name, line)
		if old, ok := existing[id]; ok {
			delete(existing, id)
			if !bytes.Equal(old, doc) {
				rep.conflict(id)
			}
			continue
		}
		docs = append(docs, doc)
		size += len(doc)
		if len(docs) >= syslogInsertDocs || size >= syslogInsertBytes {
			if err := flush(); err != nil {
				return res, err
			}
		}
	}
	if err := flush(); err != nil {
		return res, err
	}
	for id := range existing {
		extra = append(extra, quote(id))
	}
	r.reportChunk(op, rep, extra)
	return res, nil
}

func (c *chunkReport) conflict(id string) {
	if c.conflicts == 0 {
		c.conflictID = id
	}
	c.conflicts++
}

// reportChunk reports what storing a chunk's documents met. extra lists (quoted) the _ids of
// documents of the chunk that are no lines of it.
func (r *Replicator) reportChunk(op syslogOp, rep chunkReport, extra []string) {
	what := fmt.Sprintf("syslog chunk %s (ledger record %d)", quote(op.chunk.Name), op.seq)
	if rep.conflicts > 0 {
		r.syslogProblem(fmt.Sprintf("MongoDB already holds a different document for %d line(s) of %s, e.g. %s; it was not overwritten", rep.conflicts, what, quote(rep.conflictID)))
	}
	if rep.rejected > 0 {
		r.syslogProblem(fmt.Sprintf("MongoDB rejected %d line(s) of %s, e.g. %s (%s); the copy lacks them", rep.rejected, what, quote(rep.rejectedID), rep.rejectedErr))
	}
	if len(extra) > 0 {
		r.syslogProblem(fmt.Sprintf("MongoDB holds %d document(s) of %s that are no lines of it, e.g. %s; they were left alone", len(extra), what, extra[0]))
	}
}

// chunkDocsLocked returns the documents that MongoDB holds for chunk name, by _id (at most a few
// beyond its n lines), and (quoted) the _ids of those whose _id is not a string.
func (r *Replicator) chunkDocsLocked(ctx context.Context, name string, n int) (map[string]bson.Raw, []string, error) {
	opCtx, cancel := r.opCtx(ctx)
	defer cancel()
	cur, err := r.coll(collSyslog).Find(opCtx, bson.D{{Key: "chunk", Value: name}}, options.Find().SetLimit(int64(n+syslogExtraDocs)))
	if err != nil {
		return nil, nil, fmt.Errorf("read the documents of syslog chunk %s: %w", quote(name), err)
	}
	defer cur.Close(context.WithoutCancel(opCtx))
	docs := map[string]bson.Raw{}
	var odd []string
	for cur.Next(opCtx) {
		idv := cur.Current.Lookup("_id")
		if id, ok := idv.StringValueOK(); ok {
			docs[id] = append(bson.Raw(nil), cur.Current...)
		} else {
			odd = append(odd, clip(idv.String(), 80))
		}
	}
	if err := cur.Err(); err != nil {
		return nil, nil, fmt.Errorf("read the documents of syslog chunk %s: %w", quote(name), err)
	}
	return docs, odd, nil
}

// insertSyslogLocked inserts syslog documents and returns how many were stored. A document
// stored meanwhile counts as copied when it is identical (others are conflicts); one that the
// server rejects is reported.
func (r *Replicator) insertSyslogLocked(ctx context.Context, docs []bson.Raw, rep *chunkReport) (int, error) {
	if len(docs) == 0 {
		return 0, nil
	}
	all := make([]any, len(docs))
	for i, d := range docs {
		all[i] = d
	}
	opCtx, cancel := r.opCtx(ctx)
	defer cancel()
	coll := r.coll(collSyslog)
	_, err := coll.InsertMany(opCtx, all, options.InsertMany().SetOrdered(false))
	if err == nil {
		return len(docs), nil
	}
	var bwe mongo.BulkWriteException
	if !errors.As(err, &bwe) || bwe.WriteConcernError != nil || len(bwe.WriteErrors) == 0 {
		return 0, fmt.Errorf("insert syslog documents: %w", err)
	}
	inserted := len(docs) - len(bwe.WriteErrors)
	var dups bson.A
	for _, we := range bwe.WriteErrors {
		if we.Index < 0 || we.Index >= len(docs) {
			return inserted, fmt.Errorf("insert syslog documents: write error for unknown index %d: %w", we.Index, err)
		}
		if transientWriteCode(we.Code) {
			// The server's state, not the document: the chunk is stored again on a later pass.
			return inserted, fmt.Errorf("insert syslog documents: %w", err)
		}
		id, _ := rawString(docs[we.Index], "_id")
		if isDuplicateKeyCode(we.Code) {
			dups = append(dups, id)
			continue
		}
		if rep.rejected == 0 {
			rep.rejectedID, rep.rejectedErr = id, clip(we.Message, 200)
		}
		rep.rejected++
	}
	if len(dups) == 0 {
		return inserted, nil
	}
	cur, err := coll.Find(opCtx, bson.D{{Key: "_id", Value: bson.D{{Key: "$in", Value: dups}}}})
	if err != nil {
		return inserted, fmt.Errorf("read existing syslog documents: %w", err)
	}
	defer cur.Close(context.WithoutCancel(opCtx))
	stored := make(map[string]bson.Raw, len(dups))
	for cur.Next(opCtx) {
		if id, ok := cur.Current.Lookup("_id").StringValueOK(); ok {
			stored[id] = append(bson.Raw(nil), cur.Current...)
		}
	}
	if err := cur.Err(); err != nil {
		return inserted, fmt.Errorf("read existing syslog documents: %w", err)
	}
	for _, d := range docs {
		id, _ := rawString(d, "_id")
		if old, ok := stored[id]; ok && !bytes.Equal(old, d) {
			rep.conflict(id)
		}
	}
	for _, v := range dups {
		if _, ok := stored[v.(string)]; !ok {
			rep.conflict(v.(string)) // reported as present, but cannot be read back
		}
	}
	return inserted, nil
}

// transientWriteCode reports whether the code of a write error says more about the server's
// state than about the document (interrupted, not primary, a write conflict, a lock or time limit,
// a full disk): such a write is tried again later rather than reported as rejected.
func transientWriteCode(code int) bool {
	switch code {
	case 6, 7, 24, 46, 50, 89, 91, 112, 189, 262, 9001, 10107, 11600, 11601, 11602, 13435, 13436, 14031:
		return true
	}
	return false
}

// deleteChunksLocked deletes the documents of the chunks that a syslog_prune record deleted.
func (r *Replicator) deleteChunksLocked(ctx context.Context, op syslogOp) (syslogResult, error) {
	var res syslogResult
	for names := op.prune; len(names) > 0; {
		n := min(len(names), syslogDeleteNames)
		in := make(bson.A, n)
		for i, name := range names[:n] {
			in[i] = name
		}
		opCtx, cancel := r.opCtx(ctx)
		dr, err := r.coll(collSyslog).DeleteMany(opCtx, bson.D{{Key: "chunk", Value: bson.D{{Key: "$in", Value: in}}}})
		cancel()
		if err != nil {
			return res, fmt.Errorf("delete the documents of pruned syslog chunks (ledger record %d): %w", op.seq, err)
		}
		res.docs += int(dr.DeletedCount)
		res.changed = res.changed || dr.DeletedCount > 0
		names = names[n:]
	}
	return res, nil
}

// ---------------------------------------------------------------- size limit

// syslogLimit is the size the syslog collection may take, in bytes of its documents as MongoDB
// counts them (BSON, before its own compression; the indexes come on top): the syslog store's
// limit, syslog.keep_mb MiB as the store reports it (defaultSyslogKeepMB without one). The
// store's limit counts compressed chunks, whose messages take tens to hundreds of times as much
// as documents, so without a limit of its own the collection would take that much more.
func (r *Replicator) syslogLimit() int64 {
	mb := r.o.Syslog.Usage().KeepMB
	if mb <= 0 {
		mb = defaultSyslogKeepMB
	}
	return int64(mb) << 20
}

// syslogTrimError: the syslog collection could not be kept within its size limit (MongoDB
// failed); the next pass tries again.
type syslogTrimError struct {
	limit int64
	err   error
}

func (e *syslogTrimError) Error() string {
	return fmt.Sprintf("the syslog collection cannot be kept within its size limit of %d MiB (%s); the next pass tries again",
		e.limit>>20, clip(e.err.Error(), 200))
}

func (e *syslogTrimError) Unwrap() error { return e.err }

// trimSyslogLocked keeps the syslog collection within limit bytes: while its documents take more,
// the documents of its oldest chunk - the first by name, which starts with the receive time of
// the chunk's first message - are deleted. The chunk itself stays in the syslog store (and its
// record in the ledger and in the records collection). The replication state keeps the last
// chunk name deleted so (syslog_trimmed): Verify does not count a chunk up to it as missing. The
// newest chunk is always kept, and one pass deletes at most syslogTrimPerPass chunks. It reports
// whether documents were deleted.
func (r *Replicator) trimSyslogLocked(ctx context.Context, limit int64) (bool, error) {
	changed, deletedChunks, deletedDocs := false, 0, int64(0)
	defer func() {
		if deletedChunks > 0 {
			r.log.Info("MongoDB copy: the syslog collection reached its size limit; the documents of its oldest chunks were deleted (the chunks stay in the syslog store)",
				"database", r.o.Database, "limit_mib", limit>>20, "chunks", deletedChunks, "documents", deletedDocs)
		}
	}()
	for range syslogTrimPerPass {
		size, err := r.syslogDataSize(ctx)
		if err != nil {
			return changed, err
		}
		if size <= limit {
			r.sys.trimmedTo = limit
			return changed, nil
		}
		oldest, err := r.syslogChunkAt(ctx, 1)
		if err != nil {
			return changed, err
		}
		newest, err := r.syslogChunkAt(ctx, -1)
		if err != nil {
			return changed, err
		}
		if oldest == nil || newest == nil || rawValueEqual(*oldest, *newest) {
			r.sys.trimmedTo = limit // one chunk left: kept, whatever its size
			return changed, nil
		}
		opCtx, cancel := r.opCtx(ctx)
		dr, err := r.coll(collSyslog).DeleteMany(opCtx, bson.D{{Key: "chunk", Value: *oldest}})
		cancel()
		if err != nil {
			return changed, fmt.Errorf("delete the documents of the oldest syslog chunk: %w", err)
		}
		if name, ok := oldest.StringValueOK(); ok && name > r.sys.trimmed {
			r.sys.trimmed = name // saved with syslog_seq (saveSyslogLocked)
		}
		deletedChunks++
		deletedDocs += dr.DeletedCount
		changed = changed || dr.DeletedCount > 0
	}
	return changed, nil
}

// syslogDataSize returns the size of the syslog collection's documents as MongoDB counts them
// ($collStats storageStats.size: BSON, before compression, without indexes; 0 when the
// collection does not exist).
func (r *Replicator) syslogDataSize(ctx context.Context) (int64, error) {
	opCtx, cancel := r.opCtx(ctx)
	defer cancel()
	pipeline := mongo.Pipeline{{{Key: "$collStats", Value: bson.D{{Key: "storageStats", Value: bson.D{}}}}}}
	cur, err := r.coll(collSyslog).Aggregate(opCtx, pipeline)
	var ce mongo.CommandError
	if errors.As(err, &ce) && ce.Code == 26 { // NamespaceNotFound
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read the size of the syslog collection: %w", err)
	}
	defer cur.Close(context.WithoutCancel(opCtx))
	if !cur.Next(opCtx) {
		return 0, cur.Err()
	}
	v, err := cur.Current.LookupErr("storageStats", "size")
	if err != nil {
		return 0, fmt.Errorf("read the size of the syslog collection: %w", err)
	}
	n, ok := v.AsInt64OK()
	if !ok {
		return 0, fmt.Errorf("read the size of the syslog collection: storageStats.size is a %s", v.Type)
	}
	return n, nil
}

// syslogChunkAt returns the chunk field of the syslog collection's first document in the order
// of that field (order 1) or the last (-1), using the {chunk:1} index; nil when it holds none.
func (r *Replicator) syslogChunkAt(ctx context.Context, order int) (*bson.RawValue, error) {
	opCtx, cancel := r.opCtx(ctx)
	defer cancel()
	opts := options.FindOne().SetSort(bson.D{{Key: "chunk", Value: order}}).SetProjection(bson.D{{Key: "chunk", Value: 1}})
	raw, err := r.coll(collSyslog).FindOne(opCtx, bson.D{}, opts).Raw()
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the syslog collection's chunks: %w", err)
	}
	v, err := raw.LookupErr("chunk")
	if err != nil {
		v = bson.RawValue{Type: bson.TypeNull} // a document without one sorts as null
	}
	v = bson.RawValue{Type: v.Type, Value: bytes.Clone(v.Value)}
	return &v, nil
}

// saveSyslogLocked records in the replication state how far the syslog collection follows the
// ledger, if that changed (only if the state is still what this replicator last read or wrote: a
// changed state is validated again by the minute's check).
func (r *Replicator) saveSyslogLocked(ctx context.Context) error {
	s := r.sys
	if !r.meta.present || (s.applied() == s.savedSeq && s.coll == s.savedColl && s.trimmed == s.savedTrimmed) {
		return nil
	}
	set := append(bson.D{{Key: "updated", Value: bson.NewDateTimeFromTime(r.o.Now())}}, r.metaSyslog()...)
	opCtx, cancel := r.opCtx(ctx)
	defer cancel()
	res, err := r.coll(collMeta).UpdateOne(opCtx, r.metaFilter(), bson.D{{Key: "$set", Value: set}})
	if err != nil {
		return fmt.Errorf("save the replication state: %w", err)
	}
	if res.MatchedCount == 1 {
		r.syslogSaved()
	}
	return nil
}

// ---------------------------------------------------------------- status

// syslogProblem records a problem of the syslog copy: Status().LastError keeps it until the whole
// syslog collection has been checked again without one, the log gets it at most once an hour
// (with the number suppressed meanwhile), and SyncOnce reports it (ErrIntegrity).
func (r *Replicator) syslogProblem(msg string) {
	msg = clip(printable(msg), maxProblemLen)
	r.passProblems++
	r.passLast = msg
	r.sys.problems++
	now := r.o.Now()
	r.mu.Lock()
	r.st.syslogProblem = msg
	log, suppressed := r.st.syslogProblemGate.allow("problem", now, true)
	r.mu.Unlock()
	if log {
		r.log.Error("MongoDB copy of syslog messages: problem (the syslog store and the ledger are the source of truth; run the MongoDB verification)",
			"database", r.o.Database, "problem", msg, "suppressed", suppressed)
	}
}

// syslogWaiting publishes why the syslog copy waits ("" when it goes on) and logs when it starts
// and stops waiting (again at most hourly while it waits). It reports whether it logged.
func (r *Replicator) syslogWaiting(msg string) bool {
	msg = clip(printable(msg), maxProblemLen)
	state := healthOK
	if msg != "" {
		state = healthFailing
	}
	now := r.o.Now()
	r.mu.Lock()
	before := r.st.syslogErr
	r.st.syslogErr = msg
	log, suppressed := false, 0
	if msg != "" || before != "" {
		log, suppressed = r.st.syslogGate.allow(state, now, msg != "")
	}
	r.mu.Unlock()
	switch {
	case !log:
	case msg != "":
		r.log.Warn("MongoDB copy of syslog messages waits; the copy of the ledger records goes on", "database", r.o.Database, "err", msg, "suppressed", suppressed)
	default:
		r.log.Info("MongoDB copy of syslog messages goes on", "database", r.o.Database)
	}
	return log
}

// syslogSkipped notes a chunk that the syslog store no longer holds when its record is applied:
// the retention limit deleted it before it could be copied (a syslog_prune record says so). The
// log gets it at most once an hour, with the number of chunks skipped meanwhile.
func (r *Replicator) syslogSkipped(op syslogOp) {
	now := r.o.Now()
	r.mu.Lock()
	log, suppressed := r.st.syslogSkipGate.allow("skipped", now, true)
	r.mu.Unlock()
	if log {
		r.log.Info("MongoDB copy: a syslog chunk is no longer in the syslog store (deleted by the retention limit before it was copied); its messages are not in MongoDB",
			"database", r.o.Database, "chunk", printable(op.chunk.Name), "seq", op.seq, "suppressed", suppressed)
	}
}
