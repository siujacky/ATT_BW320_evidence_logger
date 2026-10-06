package monitor

import (
	"log/slog"
	"slices"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// syslogBook is the syslog store with what the monitor needs beyond contracts.SyslogStore to
// keep the ledger's syslog records complete across refusals, crashes and restarts
// (syslogstore.Store has it): which sealed chunks still lack their syslog_chunk record - the
// store keeps that on disk, so a run that ends before it can record a chunk leaves it to the next
// start - and deletions chosen before they are made, so that each is recorded first. A store
// without it is given memBook, which keeps the same in memory.
type syslogBook interface {
	contracts.SyslogStore
	// MarkRecorded notes that the sealed chunk name has its syslog_chunk record, seq.
	MarkRecorded(name string, seq uint64) error
	// Unrecorded returns the sealed chunks whose record is not noted, oldest first.
	Unrecorded() []model.SyslogChunk
	// PlanPrune chooses the chunks the retention limits delete, without deleting them yet;
	// CommitPrune deletes them (and returns them), CancelPrune keeps them.
	PlanPrune(now time.Time) ([]model.SyslogChunkRef, error)
	CommitPrune() ([]model.SyslogChunkRef, error)
	CancelPrune()
}

// bookOf returns the syslog store with its bookkeeping (nil without a store).
func bookOf(st contracts.SyslogStore, log *slog.Logger) syslogBook {
	switch b := st.(type) {
	case nil:
		return nil
	case syslogBook:
		return b
	default:
		return &memBook{SyslogStore: st, log: log}
	}
}

// memBook gives a syslog store without bookkeeping of its own (test doubles) the syslogBook
// methods, in memory: the chunks its Recover, Append and Seal returned whose record is not
// noted, and the chunks its Prune deleted - at once, as such a store does - whose deletion is
// not recorded yet (PlanPrune returns them again until CommitPrune). What it holds ends with the
// process, and it holds at most maxUnrecordedSyslog of each (beyond that the oldest is given up,
// logged). Its methods are called under the monitor's syslogMu.
type memBook struct {
	contracts.SyslogStore
	log    *slog.Logger
	unrec  []model.SyslogChunk
	pruned []model.SyslogChunkRef // deleted, the deletion not recorded
	plan   []model.SyslogChunkRef
}

// maxUnrecordedSyslog bounds what memBook keeps for a record the ledger refuses (a chunk is
// sealed at most every few minutes, so this is hours of refusals).
const maxUnrecordedSyslog = 256

func (b *memBook) Recover(now time.Time) ([]model.SyslogChunk, error) {
	cs, err := b.SyslogStore.Recover(now)
	b.sealed(cs...)
	return cs, err
}

func (b *memBook) Append(msgs []model.SyslogMessage, dropped, rejected int, now time.Time) ([]model.SyslogChunk, error) {
	cs, err := b.SyslogStore.Append(msgs, dropped, rejected, now)
	b.sealed(cs...)
	return cs, err
}

func (b *memBook) Seal(now time.Time, reason string, force bool) (*model.SyslogChunk, error) {
	c, err := b.SyslogStore.Seal(now, reason, force)
	if c != nil {
		b.sealed(*c)
	}
	return c, err
}

// sealed notes chunks the store sealed as unrecorded.
func (b *memBook) sealed(cs ...model.SyslogChunk) {
	b.unrec = append(b.unrec, cs...)
	for len(b.unrec) > maxUnrecordedSyslog {
		b.log.Error("a syslog_chunk record the evidence ledger keeps refusing is given up", "chunk", b.unrec[0].Name,
			"sha256", b.unrec[0].SHA256, "messages", b.unrec[0].Messages)
		b.unrec = slices.Delete(b.unrec, 0, 1)
	}
}

func (b *memBook) MarkRecorded(name string, seq uint64) error {
	if i := slices.IndexFunc(b.unrec, func(c model.SyslogChunk) bool { return c.Name == name }); i >= 0 {
		b.unrec = slices.Delete(b.unrec, i, i+1)
	}
	return nil
}

func (b *memBook) Unrecorded() []model.SyslogChunk { return slices.Clone(b.unrec) }

func (b *memBook) PlanPrune(now time.Time) ([]model.SyslogChunkRef, error) {
	deleted, err := b.SyslogStore.Prune(now)
	b.plan = append(b.pruned, deleted...)
	b.pruned = nil
	if n := len(b.plan) - maxUnrecordedSyslog; n > 0 {
		for _, c := range b.plan[:n] {
			b.log.Error("the deletion of a syslog chunk that the evidence ledger keeps refusing to record is given up", "chunk", c.Name, "sha256", c.SHA256)
		}
		b.plan = slices.Delete(b.plan, 0, n)
	}
	return slices.Clone(b.plan), err
}

func (b *memBook) CommitPrune() ([]model.SyslogChunkRef, error) {
	refs := b.plan
	b.plan = nil
	return refs, nil
}

func (b *memBook) CancelPrune() {
	b.pruned, b.plan = b.plan, nil
}
