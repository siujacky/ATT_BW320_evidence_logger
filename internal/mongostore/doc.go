// Package mongostore keeps a continuously synchronized, queryable copy of the evidence ledger in
// MongoDB. The signed JSONL ledger (docs/DESIGN.md §6) stays the source of truth and the only
// chain of custody: evidence collection never depends on MongoDB, and the copy can always be
// rebuilt from the ledger. Every copied record keeps the ledger's exact h, s and b strings, so a
// record read from MongoDB is independently verifiable: h is the SHA-256 of the UTF-8 bytes of b
// and s the base64 Ed25519 signature of those bytes under the ledger key (whose fingerprint the
// owner hands out separately).
//
// # Collections (database "attmonitor" by default)
//
//	records    _id = seq (int64); seq, ts (BSON date of the body's ts; ts_text keeps the exact
//	           string), type, run, mono, prev, v, h, s, b (the exact ledger strings), blobs, data
//	           (the body's data converted to BSON by the Extended JSON parser in relaxed mode),
//	           copy_format. Indexes {type:1, ts:1} and {ts:1}.
//	blobs      _id = SHA-256 hex of the content; size, first_seq (first record referencing it),
//	           stored_at, and data (the exact bytes, BinData subtype 0) when Options.StoreBlobs,
//	           else a note saying the content is not stored. Blobs larger than 15 MB keep only
//	           their size (too_large) because of MongoDB's 16 MB document limit.
//	incidents  _id = incident id; incident (the payload of the newest incident_open/update/close
//	           record, by seq), seq, type, ts, ts_text, h of that record, updated.
//	meta       _id "replication": last_seq, last_hash, updated, fingerprint and genesis_hash of
//	           the ledger (identity checks), format; store_blobs and collections (the UUIDs of
//	           records, blobs and incidents): what the copy up to last_seq is consistent with;
//	           pending_blobs (blobs that could not be read from the ledger yet); after a reset,
//	           reset_reason and previous (the replaced state).
//
// When a body's data cannot be converted faithfully, the record keeps it as text instead:
// data_json (the exact JSON text), data_undecoded (true) and data_note (why). That happens for an
// object key starting with "$" (Extended JSON reads {"$date": …}, {"$oid": …}, {"$numberLong": …}
// as typed values), a key containing NUL, an integer outside the int64 range (it would become a
// rounded double), nesting deeper than 64 levels, data rejected by the parser or by the server,
// and data that would push the document over 16 MB (then only the note is kept; b is complete).
//
// # Replication
//
// Run copies every ledger record whose seq is above the newest copied one, in order and in
// batches: blobs first, then records, then incidents, then meta. A few new records (the steady
// state) are read by seq through the ledger's line index; a first copy or a longer catch-up scans
// the ledger. Inserts are idempotent: a seq that is already present counts as copied only when
// its stored h equals the ledger's h (and its _id is the int64 seq); anything else at that seq is
// an integrity problem that is reported (log, Status().LastError) and never overwritten, and the
// copy goes on. Record documents are only ever inserted. A blob document is written once, except
// that a document stored without its content gets it when blob storage is turned on, and a
// first_seq above the first record referencing the blob is lowered (a blob stored again after its
// collection was dropped).
//
// The replication state is written by compare-and-set: only if it is still what the replicator
// last read or wrote. On every (re)connection its resume point is checked against the ledger and
// the copy; when the ledger lacks it or the copy no longer holds it, the whole copy is re-checked
// from seq 0. Once a minute the replicator also checks that the collections are still the same
// (a dropped or restored collection gets another UUID), that the replication state is as it left
// it, and that the newest copied record and record 0 are still there. A copy that changed behind
// its back — the database dropped, the meta document deleted, an older backup restored — is
// validated again as on a new connection, at the latest when the next records are copied: so
// deleting the meta document makes it re-check and fill the whole copy, and dropping the database
// makes it copy everything again, also while the service runs. When the copy up to the resume
// point is otherwise valid but a collection was dropped or replaced, records were deleted, or
// blob storage was turned on, the whole copy is checked again without moving the resume point;
// missing documents are stored and blob documents get their content (not in a pass with a short
// deadline, such as the last one at shutdown). A database that holds a copy of another ledger
// (meta naming another key or genesis record, or a record 0 that is another ledger's authentic
// genesis record) is refused; a record 0 that is merely altered is a reported conflict.
//
// A blob that the ledger does not hold, or whose ledger copy does not match its id, is reported.
// One that cannot be read for another reason (a file locked by another program, an I/O error)
// waits for a retry: its records are copied, the blob is read again on every pass (also after a
// restart: meta lists it), and Status().LastError says so meanwhile. When more than 1000 blobs
// wait, the copy waits for the ledger's blob store instead of leaving more gaps.
//
// MongoDB being down never stops Run: it retries with a bounded backoff and logs at most once per
// state change (and as a reminder at most once an hour).
//
// # Trust
//
// The copy is not evidence: the local MongoDB server accepts writes from any local process.
// Verify compares it with the ledger record by record (identical h, s and b; h = SHA-256(b); a
// valid signature; derived fields consistent with b) and reports missing, altered and forged
// documents; blob documents that differ from what the ledger gives (content, size, first_seq,
// the content or the note why it is absent) or that no ledger record references; incidents that
// do not match; a database without records; and a copy that lacks more than a quarter of an hour
// of the newest records. It also says where the copy ends compared with the ledger. Text taken
// from documents is quoted and escaped in Verify's problems and in Status().LastError, so a
// forged document cannot fake output lines or send terminal control sequences.
package mongostore
