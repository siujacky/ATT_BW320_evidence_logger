package syslogstore

import (
	"errors"
	"fmt"
	"time"

	"attmonitor/internal/model"
)

// Prune applies the retention limits: it deletes the oldest sealed chunks while the store holds
// more than KeepMB MiB (the sealed chunks' gzip size plus the open chunk's size) and, with
// KeepDays above 0, every sealed chunk whose last message is more than KeepDays days older
// than now. The open chunk is never deleted. It returns the deleted chunks, oldest first.
//
// A chunk that cannot be deleted now - a reader of this store has it open, or another program
// holds it - stays as it is and is not returned: a later Prune deletes it and returns it then.
// Meanwhile it no longer counts against the limit, so newer chunks are not deleted in its
// place. A sidecar that cannot be deleted with its chunk is deleted later.
//
// Prune deletes before its caller can record the deletion; PlanPrune and CommitPrune let the
// deletion be recorded first.
func (s *Store) Prune(now time.Time) ([]model.SyslogChunkRef, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if err := s.writable(); err != nil {
		return nil, err
	}
	s.retryPending()
	s.cancelPlan()
	var refs []model.SyslogChunkRef
	for _, c := range s.choose(s.when(now)) {
		if err := s.deleteChunk(c, false); err != nil {
			continue
		}
		refs = append(refs, c.ref())
	}
	return refs, nil
}

// PlanPrune chooses what Prune would delete now - the oldest sealed chunks beyond the retention
// limits, none that a reader of this store has open - and deletes nothing yet: the chosen chunks
// get no new readers and no longer count in Usage until CommitPrune deletes them or CancelPrune
// keeps them. The writer records the deletion (syslog_prune) in between, so that no chunk is
// deleted without its record. It returns the chosen chunks, oldest first; a plan that was
// neither committed nor cancelled is cancelled first.
func (s *Store) PlanPrune(now time.Time) ([]model.SyslogChunkRef, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if err := s.writable(); err != nil {
		return nil, err
	}
	s.retryPending()
	s.cancelPlan()
	s.plan = s.choose(s.when(now))
	refs := make([]model.SyslogChunkRef, len(s.plan))
	for i, c := range s.plan {
		refs[i] = c.ref()
	}
	return refs, nil
}

// CommitPrune deletes the chunks PlanPrune chose and returns them, oldest first. Their deletion
// is on record, so each leaves the store's index even when its file cannot be deleted now
// (another program holds it): that file is deleted later, and should the service stop first,
// the next start finds it again as a kept chunk, which a later prune deletes - and records - once
// more. The error names the files that could not be deleted yet. Without a plan it does nothing.
func (s *Store) CommitPrune() ([]model.SyslogChunkRef, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if err := s.writable(); err != nil {
		return nil, err
	}
	plan := s.plan
	s.plan = nil
	refs := make([]model.SyslogChunkRef, 0, len(plan))
	var errs []error
	for _, c := range plan {
		if err := s.deleteChunk(c, true); err != nil {
			errs = append(errs, err)
		}
		refs = append(refs, c.ref())
	}
	return refs, errors.Join(errs...)
}

// CancelPrune keeps the chunks PlanPrune chose (their deletion could not be recorded); a later
// prune chooses them again.
func (s *Store) CancelPrune() {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	s.cancelPlan()
}

// cancelPlan gives the chunks of an open plan back to the store (s.wmu held).
func (s *Store) cancelPlan() {
	if len(s.plan) == 0 {
		return
	}
	s.mu.Lock()
	for _, c := range s.plan {
		c.deleting = false
	}
	s.mu.Unlock()
	s.plan = nil
}

// choose selects the chunks beyond the retention limits at now, oldest first, and marks them
// deleting (no new readers). Chunks a reader has open are skipped and no longer count against
// the size limit (s.wmu held).
func (s *Store) choose(now time.Time) []*chunk {
	s.mu.Lock()
	defer s.mu.Unlock()
	limit := int64(s.keepMB) << 20
	var maxAge time.Duration
	if s.keepDays > 0 {
		maxAge = time.Duration(s.keepDays) * 24 * time.Hour
	}
	kept := int64(0)
	for _, c := range s.chunks {
		if !c.deleting {
			kept += c.meta.GzBytes
		}
	}
	if s.open != nil {
		kept += s.open.size
	}
	var del []*chunk
	inUse := 0
	for _, c := range s.chunks {
		if c.deleting {
			continue
		}
		if kept <= limit && (maxAge == 0 || now.Sub(c.newest()) <= maxAge) {
			continue
		}
		kept -= c.meta.GzBytes
		if c.readers > 0 {
			inUse++
			continue
		}
		c.deleting = true
		del = append(del, c)
	}
	if inUse > 0 {
		s.log.Debug("syslog store: chunks beyond the retention limits are being read; they are deleted later", "chunks", inUse)
	}
	return del
}

// deleteChunk deletes the files of c, which choose marked, and removes it from the index. When
// its file cannot be deleted now (another program holds it), recorded says what happens: c stays
// in the store (unmarked) and the error is returned; or, once its deletion is on record, c leaves
// the index anyway and its files are deleted later (s.wmu held).
func (s *Store) deleteChunk(c *chunk, recorded bool) error {
	sidecarPath := c.path + sidecarExt
	if err := removeFile(c.path); err != nil {
		if !recorded {
			s.log.Info("syslog store: a chunk beyond the retention limits is in use; it is deleted later",
				"chunk", c.meta.Name, "err", err)
			s.mu.Lock()
			c.deleting = false
			s.mu.Unlock()
			return err
		}
		s.log.Warn("syslog store: a deleted chunk's file is in use; it is deleted later", "chunk", c.meta.Name, "err", err)
		s.pending = append(s.pending, c.path, sidecarPath)
		err = fmt.Errorf("syslogstore: delete %s: %w", c.meta.Name, err)
		s.mu.Lock()
		s.removeChunk(c)
		s.mu.Unlock()
		return err
	}
	if err := removeFile(sidecarPath); err != nil {
		s.log.Warn("syslog store: a deleted chunk's sidecar file is in use; it is deleted later",
			"chunk", c.meta.Name, "err", err)
		s.pending = append(s.pending, sidecarPath)
	}
	s.mu.Lock()
	s.removeChunk(c)
	s.mu.Unlock()
	s.log.Info("syslog store: deleted a chunk beyond the retention limits", "chunk", c.meta.Name,
		"messages", c.meta.Messages, "gz_bytes", c.meta.GzBytes)
	return nil
}
