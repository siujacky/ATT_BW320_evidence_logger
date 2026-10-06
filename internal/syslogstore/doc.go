// Package syslogstore keeps the gateway's syslog messages (docs/syslog-snmp-traffic.md §3.2) in
// chunk files within a size limit, and optionally an age limit. Unlike the evidence ledger,
// which never deletes anything, the store deletes its oldest chunks to stay within
// syslog.keep_mb (100 MiB by default) and syslog.keep_days. The ledger keeps their proof: the
// monitor records a syslog_chunk record for every chunk the store seals and a syslog_prune
// record for every deletion it reports; the store itself never writes the ledger.
//
// # Files
//
// In the store's directory (config.Paths.Syslog):
//
//	open-<from>.jsonl                 the open chunk: one model.SyslogMessage per line, exactly
//	                                  as json.Marshal writes it, each followed by a line feed,
//	                                  in receive order; fsynced by every Append
//	open-<from>.state.json            its dropped and rejected counts (once it has any)
//	syslog-<from>_<to>.jsonl.gz       a sealed chunk: the open chunk's exact bytes, gzip
//	syslog-<from>_<to>.jsonl.gz.json  its sidecar: the model.SyslogChunk of its syslog_chunk
//	                                  record, the range of its messages' receive times and,
//	                                  once the writer noted it (MarkRecorded), that record's seq
//
// Times are UTC, compact and sortable (20261005T221500.123456789Z). <from> and <to> are the
// receive times of a chunk's first and last message, or the time it was opened for a chunk that
// only carries counts. A name that is taken already gets "-2", "-3" … before its extension.
//
// A chunk is sealed when its content reaches ChunkBytes (1 MiB, by Append), when it is
// ChunkAge old (5 minutes, by Seal), at shutdown (Seal with force) and, when a run left it
// open, by Recover. Sealing reads the open file's exact bytes and takes their SHA-256, size,
// message count and receive times; compresses them into a temporary file, checks that it
// decompresses to the same bytes, fsyncs it and renames it into place; writes the sidecar
// (temporary file and rename); then deletes the open chunk's files. A crash at any step is
// repaired by Recover at the next start.
//
// # Trust
//
// The files are not evidence on their own: the administrators of this computer can edit,
// replace or delete them (only the open chunk is protected from other writers while the store
// holds it). The evidence is the ledger. Each syslog_chunk record states what a sealed chunk
// held - the SHA-256 and size of its uncompressed content, its messages and receive times, the
// counts - and each syslog_prune record which chunks the retention limits deleted. A chunk file
// proves something only once it is compared with its record; the sidecars are an index, rebuilt
// from the chunk files when missing or damaged; the open chunk is covered by no record yet.
// Reading is lenient, like the ledger's readers: Query logs a sealed chunk that no longer
// matches its SHA-256 but returns what the file holds. What a message says is what this
// computer received (internal/syslogrx explains what that proves).
//
// # Records
//
// The store never writes the ledger, but it keeps the writer's note of which sealed chunks have
// their syslog_chunk record (MarkRecorded, kept in the sidecar), so that a chunk sealed while the
// ledger refused records - also in a run that ended before it could record it - is found again
// (Unrecorded) and recorded once. A sidecar rebuilt from its chunk file has no note: the writer
// looks the record up in the ledger before recording one.
//
// # Retention
//
// Prune deletes whole sealed chunks, oldest first, while the store holds more than KeepMB MiB
// (the sealed chunks' gzip size plus the open chunk's size) and, with KeepDays above 0, every
// sealed chunk whose last message is older than that. It never deletes the open chunk.
// PlanPrune and CommitPrune do the same in two steps, so that the writer records the deletion
// (syslog_prune) before it is made; CancelPrune keeps the chosen chunks when it cannot.
//
// # Concurrency
//
// One process writes the store: the monitor, whose ledger lock keeps a second one away. The
// writing methods (Recover, Append, Seal, Prune, PlanPrune, CommitPrune, CancelPrune,
// MarkRecorded) are serialized, and any number of goroutines may read meanwhile (Query, Usage,
// OpenChunk, Chunks, Unrecorded). Prune does not delete a chunk that a reader of this store has
// open; another process's reader (a read-only store) opens files in a way that lets the writer
// delete them. Usage never waits for file I/O. Recover may be called again after it failed (a
// chunk left open that another program held): it leaves the chunk this run opened alone.
package syslogstore
