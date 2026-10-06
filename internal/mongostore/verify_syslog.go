package mongostore

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// Verification of the syslog collection (see Verify).

// chunkRec is a syslog_chunk record of the ledger.
type chunkRec struct {
	seq uint64
	c   model.SyslogChunk
}

// syslogRecTS is a syslog_chunk or syslog_prune record of the ledger: its seq and ts.
type syslogRecTS struct {
	seq uint64
	ts  string
}

// noteSyslog remembers a syslog_chunk or syslog_prune record of the ledger.
func (v *verifier) noteSyslog(seq uint64, body model.Body) {
	op, ok := syslogOpOf(item{body: body})
	if !ok {
		return
	}
	v.syslogRecs = append(v.syslogRecs, syslogRecTS{seq: seq, ts: body.TS})
	if op.chunk != nil {
		if _, dup := v.chunks[op.chunk.Name]; !dup {
			v.chunks[op.chunk.Name] = chunkRec{seq: seq, c: *op.chunk}
		}
	}
	for _, name := range op.prune {
		if _, dup := v.pruned[name]; !dup {
			v.pruned[name] = seq
		}
	}
}

// Kinds of syslog groups (the documents of one value of the chunk field).
const (
	groupChunk  = iota // a chunk of a syslog_chunk record: compared with it
	groupPruned        // a chunk that a syslog_prune record applied by the copy deleted
	groupForged        // no syslog_chunk record names the chunk
)

// syslogGroup collects the documents of one chunk.
type syslogGroup struct {
	key      bson.RawValue // the chunk field
	name     string        // … when it is a string
	kind     int
	rec      chunkRec
	prunedBy uint64 // the syslog_prune record (groupPruned)
	docs     int
	firstID  string       // the _id of the first document, as shown
	lines    []syslogLine // the lines held for the hash (groupChunk)
	held     int64        // their bytes, each with its line feed
	over     bool         // more documents or bytes than the chunk has: lines no longer held
	bad      []string     // the first documents whose fields do not match their line …
	nBad     int          // … and how many
}

// syslogLine is the line of one document: its number and its exact bytes.
type syslogLine struct {
	n   int64
	raw []byte
}

func (g *syslogGroup) badDoc(why string) {
	if len(g.bad) < 3 {
		g.bad = append(g.bad, why)
	}
	g.nBad++
}

// checkSyslog checks the syslog collection (see Verify). The documents are read by chunk (the
// {chunk:1} index); the lines of a chunk are held in memory up to the size of the chunk.
func (v *verifier) checkSyslog(meta bson.Raw, newest int64) error {
	applied, err := v.syslogApplied(meta, newest)
	if err != nil {
		return err
	}
	cur, err := v.db.Collection(collSyslog).Find(v.ctx, bson.D{},
		options.Find().SetSort(bson.D{{Key: "chunk", Value: 1}}).SetAllowDiskUse(true))
	if err != nil {
		return fmt.Errorf("mongostore: read syslog: %w", err)
	}
	defer cur.Close(context.WithoutCancel(v.ctx))
	seen := map[string]bool{}
	var g *syslogGroup
	for cur.Next(v.ctx) {
		v.res.SyslogDocs++
		doc := cur.Current
		key := doc.Lookup("chunk")
		if g == nil || !rawValueEqual(g.key, key) {
			if g != nil {
				v.finishSyslogGroup(g, applied)
			}
			g = v.syslogGroupOf(key, applied)
			seen[g.name] = true
		}
		v.addSyslogDoc(g, doc)
	}
	if err := cur.Err(); err != nil {
		return fmt.Errorf("mongostore: read syslog: %w", err)
	}
	if g != nil {
		v.finishSyslogGroup(g, applied)
	}
	var trimmed string // the last chunk whose documents the size limit deleted
	if meta != nil {
		trimmed, _ = rawString(meta, "syslog_trimmed")
	}
	if err := v.missingSyslog(applied, seen, trimmed); err != nil {
		return err
	}
	v.syslogBehind(applied, newest)
	return nil
}

// syslogApplied returns how far the replication state says that the syslog collection follows the
// ledger: its syslog_seq when it names the syslog collection that exists now, else -1 (the
// running replicator applies every syslog record again to a collection dropped or replaced).
func (v *verifier) syslogApplied(meta bson.Raw, newest int64) (int64, error) {
	if meta == nil {
		return -1, nil
	}
	if _, err := meta.LookupErr("syslog_seq"); err != nil {
		return -1, nil // the syslog collection has not followed the ledger (yet)
	}
	seq, ok := rawInt64(meta, "syslog_seq")
	if !ok || seq < -1 {
		v.problem("meta: syslog_seq is not a ledger seq")
		return -1, nil
	}
	specs, err := v.db.ListCollectionSpecifications(v.ctx, bson.D{{Key: "name", Value: collSyslog}})
	if err != nil {
		return -1, fmt.Errorf("mongostore: list collections: %w", err)
	}
	cur := ""
	for _, s := range specs {
		cur = specID(s)
	}
	if coll, _ := rawString(meta, "syslog_collection"); coll != cur {
		return -1, nil
	}
	if seq > newest {
		v.problem("meta: syslog_seq %d is beyond the newest copied record (%d)", seq, newest)
		return newest, nil
	}
	return seq, nil
}

// syslogGroupOf starts the group of the documents whose chunk field is key.
func (v *verifier) syslogGroupOf(key bson.RawValue, applied int64) *syslogGroup {
	g := &syslogGroup{key: bson.RawValue{Type: key.Type, Value: bytes.Clone(key.Value)}, kind: groupForged}
	name, ok := key.StringValueOK()
	if !ok {
		return g
	}
	g.name = name
	rec, known := v.chunks[name]
	if !known {
		return g
	}
	g.rec, g.kind = rec, groupChunk
	if p, ok := v.pruned[name]; ok && int64(p) <= applied {
		g.kind, g.prunedBy = groupPruned, p
	}
	return g
}

// addSyslogDoc adds a document to its group: the document of a chunk must be exactly what the
// replicator writes for its line, and its line is held for the hash of the chunk.
func (v *verifier) addSyslogDoc(g *syslogGroup, doc bson.Raw) {
	g.docs++
	if g.docs == 1 {
		g.firstID = docIDText(doc)
	}
	if g.kind != groupChunk {
		return
	}
	line, lineOK := rawInt64(doc, "line")
	raw, rawOK := rawLine(doc)
	if !lineOK || !rawOK || line < 1 {
		g.badDoc(docIDText(doc) + ": no valid line or raw_line")
		return
	}
	want, err := syslogDoc(g.name, g.rec.seq, line, raw)
	switch {
	case err != nil:
		g.badDoc(docIDText(doc) + ": " + clip(err.Error(), 120))
	case !bytes.Equal(doc, want):
		keys := diffKeys(doc, want)
		if len(keys) == 0 {
			keys = []string{"(encoding)"}
		}
		g.badDoc(docIDText(doc) + ": field(s) " + strings.Join(keys, ", "))
	}
	if g.over {
		return
	}
	// Lines are held up to the size of the chunk, with some room to tell what is wrong with a few
	// lines too many; far beyond, the chunk cannot match its record and nothing more is held.
	g.held += int64(len(raw)) + 1
	if len(g.lines) >= g.rec.c.Messages+syslogExtraDocs || g.held > min(g.rec.c.Bytes, maxSyslogChunkBytes)+maxSyslogLineBytes {
		g.over, g.lines = true, nil
		return
	}
	g.lines = append(g.lines, syslogLine{n: line, raw: bytes.Clone(raw)})
}

// rawLine returns the exact line that a syslog document holds (raw_line: a string, or BinData of
// a line that is not valid UTF-8).
func rawLine(doc bson.Raw) ([]byte, bool) {
	v, err := doc.LookupErr("raw_line")
	if err != nil {
		return nil, false
	}
	if s, ok := v.StringValueOK(); ok {
		return []byte(s), true
	}
	if sub, b, ok := v.BinaryOK(); ok && sub == 0x00 {
		return b, true
	}
	return nil, false
}

// docIDText shows the _id of a document (quoted when it is a string: anyone can write it).
func docIDText(doc bson.Raw) string {
	idv := doc.Lookup("_id")
	if s, ok := idv.StringValueOK(); ok {
		return quote(s)
	}
	return clip(idv.String(), 80)
}

// finishSyslogGroup reports a group once all its documents are read.
func (v *verifier) finishSyslogGroup(g *syslogGroup, applied int64) {
	switch g.kind {
	case groupForged:
		v.res.SyslogForged += g.docs
		if g.key.Type == bson.TypeString {
			v.problem("syslog chunk %s: %d document(s), e.g. %s, but no syslog_chunk record names this chunk (forged or foreign)", quote(g.name), g.docs, g.firstID)
		} else {
			what := "missing"
			if g.key.Type != 0 {
				what = clip(g.key.String(), 60)
			}
			v.problem("syslog: %d document(s), e.g. %s, whose chunk (%s) is not a chunk name (forged or foreign)", g.docs, g.firstID, what)
		}
	case groupPruned:
		v.res.SyslogPruned += g.docs
		v.problem("syslog chunk %s (ledger record %d): %d document(s) remain, although syslog_prune record %d deleted the chunk", quote(g.name), g.rec.seq, g.docs, g.prunedBy)
	default:
		v.checkSyslogChunk(g, applied)
	}
}

// checkSyslogChunk compares the documents of a chunk with its syslog_chunk record: every line from
// 1 to Messages exactly once, the lines in order (each with its line feed) hashing to the
// record's SHA-256, and every document exactly what the replicator writes for its line. Lines
// missing are no problem while the copy may be storing or deleting the chunk: when its record, or
// the syslog_prune record deleting it, is beyond the replication state's syslog_seq.
func (v *verifier) checkSyslogChunk(g *syslogGroup, applied int64) {
	rec := g.rec
	var why []string
	if g.nBad > 0 {
		why = append(why, fmt.Sprintf("%d document(s) do not match their line (%s)", g.nBad, strings.Join(g.bad, "; ")))
	}
	if g.over {
		why = append(why, fmt.Sprintf("%d documents, far more than its %d lines", g.docs, rec.c.Messages))
	} else {
		slices.SortFunc(g.lines, func(a, b syslogLine) int { return cmp.Compare(a.n, b.n) })
		missing, repeated, beyond := lineGaps(g.lines, int64(rec.c.Messages))
		inProgress := int64(rec.seq) > applied
		if p, ok := v.pruned[g.name]; ok && int64(p) > applied {
			inProgress = true
		}
		if missing.n > 0 && repeated.n == 0 && beyond.n == 0 && g.nBad == 0 && inProgress {
			return // being stored or deleted
		}
		if missing.n > 0 {
			why = append(why, fmt.Sprintf("%d line(s) missing (%s)", missing.n, missing))
		}
		if repeated.n > 0 {
			why = append(why, fmt.Sprintf("%d line(s) held more than once (%s)", repeated.n, repeated))
		}
		if beyond.n > 0 {
			why = append(why, fmt.Sprintf("%d line(s) beyond its %d lines (%s)", beyond.n, rec.c.Messages, beyond))
		}
		if missing.n == 0 && repeated.n == 0 && beyond.n == 0 && !linesMatch(g.lines, &rec.c) {
			msg := "its lines do not hash to the SHA-256 of its record (a line was altered)"
			if diff := v.storeDiff(g); diff != "" {
				msg += "; " + diff
			}
			why = append(why, msg)
		}
	}
	v.res.SyslogChunks++
	if len(why) > 0 {
		v.res.SyslogBad++
		v.problem("syslog chunk %s (ledger record %d): %s", quote(g.name), rec.seq, strings.Join(why, "; "))
	}
}

// linesMatch reports whether lines (1 to n, in order), each with its line feed, are the content
// of chunk c: its size and its SHA-256.
func linesMatch(lines []syslogLine, c *model.SyslogChunk) bool {
	h := sha256.New()
	var size int64
	for _, l := range lines {
		h.Write(l.raw)
		h.Write([]byte{'\n'})
		size += int64(len(l.raw)) + 1
	}
	return size == c.Bytes && hex.EncodeToString(h.Sum(nil)) == c.SHA256
}

// storeDiff names the lines of a chunk whose documents differ from the syslog store's copy (""
// without the store, or when it no longer holds the chunk as its record describes it).
func (v *verifier) storeDiff(g *syslogGroup) string {
	if v.store == nil {
		return ""
	}
	lines, err := readChunk(v.store, &g.rec.c)
	if err != nil {
		return ""
	}
	var diff numList
	for _, l := range g.lines {
		if l.n <= int64(len(lines)) && !bytes.Equal(l.raw, lines[l.n-1]) {
			diff.add(l.n)
		}
	}
	if diff.n == 0 {
		return ""
	}
	return fmt.Sprintf("line(s) %s differ from the syslog store", diff)
}

// numList counts numbers and keeps the first few (ranges of consecutive ones) to show them.
type numList struct {
	n      int64
	ranges [][2]int64
	more   bool
}

func (l *numList) add(x int64) { l.addRange(x, x) }

func (l *numList) addRange(from, to int64) {
	l.n += to - from + 1
	if k := len(l.ranges); k > 0 && l.ranges[k-1][1]+1 == from {
		l.ranges[k-1][1] = to
		return
	}
	if len(l.ranges) < 5 {
		l.ranges = append(l.ranges, [2]int64{from, to})
		return
	}
	l.more = true
}

func (l numList) String() string {
	parts := make([]string, 0, len(l.ranges)+1)
	for _, r := range l.ranges {
		if r[0] == r[1] {
			parts = append(parts, strconv.FormatInt(r[0], 10))
		} else {
			parts = append(parts, strconv.FormatInt(r[0], 10)+"-"+strconv.FormatInt(r[1], 10))
		}
	}
	if l.more {
		parts = append(parts, "…")
	}
	return strings.Join(parts, ", ")
}

// lineGaps returns the line numbers from 1 to n that lines (sorted by number) lack, those that
// they hold more than once, and those beyond n.
func lineGaps(lines []syslogLine, n int64) (missing, repeated, beyond numList) {
	next := int64(1)
	for i, l := range lines {
		switch {
		case i > 0 && l.n == lines[i-1].n:
			repeated.add(l.n)
		case l.n > n:
			beyond.add(l.n)
		default:
			if l.n > next {
				missing.addRange(next, l.n-1)
			}
			next = l.n + 1
		}
	}
	if next <= n {
		missing.addRange(next, n)
	}
	return missing, repeated, beyond
}

// missingSyslog reports, with the syslog store, the chunks that the store still holds but the copy
// lacks: chunks with messages and without any document, whose syslog_chunk record the copy has
// applied (up to syslog_seq) and that no applied syslog_prune record deleted. A chunk up to
// trimmed (by name: the replication state's syslog_trimmed) is not missing: the copy's size limit
// deleted its documents, oldest first (counted in SyslogTrimmed).
func (v *verifier) missingSyslog(applied int64, seen map[string]bool, trimmed string) error {
	if v.store == nil {
		return nil
	}
	var recs []chunkRec
	for name, rec := range v.chunks {
		if seen[name] || int64(rec.seq) > applied || rec.c.Messages <= 0 {
			continue
		}
		if p, ok := v.pruned[name]; ok && int64(p) <= applied {
			continue
		}
		if trimmed != "" && name <= trimmed {
			v.res.SyslogTrimmed++
			continue
		}
		recs = append(recs, rec)
	}
	slices.SortFunc(recs, func(a, b chunkRec) int { return cmp.Compare(a.seq, b.seq) })
	for _, rec := range recs {
		if err := v.ctx.Err(); err != nil {
			return err
		}
		_, err := readChunk(v.store, &rec.c)
		var ce *chunkError
		switch {
		case errors.Is(err, contracts.ErrNotFound):
			// The retention limit deleted it before it was copied (the copy skips it).
		case errors.As(err, &ce):
			v.res.SyslogMissing++
			v.problem("syslog chunk %s (ledger record %d): missing from MongoDB; the syslog store holds it, but %s, so it cannot be copied",
				quote(rec.c.Name), rec.seq, ce.why)
		case err != nil:
			v.problem("syslog chunk %s (ledger record %d): not in MongoDB, and the syslog store cannot be read to tell whether it still holds it (%s)",
				quote(rec.c.Name), rec.seq, clip(err.Error(), 200))
		default:
			v.res.SyslogMissing++
			v.problem("syslog chunk %s (ledger record %d, %d message(s)): missing from MongoDB, although the syslog store still holds it",
				quote(rec.c.Name), rec.seq, rec.c.Messages)
		}
	}
	return nil
}

// syslogBehind reports a syslog collection that has not applied the syslog records of more than a
// quarter of an hour of the copied records (the service applies them within seconds).
func (v *verifier) syslogBehind(applied, newest int64) {
	n := 0
	var first syslogRecTS
	for _, r := range v.syslogRecs {
		if int64(r.seq) <= applied || int64(r.seq) > newest {
			continue
		}
		if n == 0 {
			first = r
		}
		n++
	}
	if n == 0 {
		return
	}
	if from, ok := parseTS(first.ts); ok {
		if to, ok := parseTS(v.headTS); ok && to.Sub(from) <= staleAfter {
			return
		}
	}
	v.problem("the syslog collection is behind: %d syslog record(s) from seq %d on (written from %s to %s) were copied but are not applied to it; the service applies them within seconds while it runs and the syslog store can be read",
		n, first.seq, first.ts, v.headTS)
}
