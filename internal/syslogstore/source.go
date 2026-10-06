package syslogstore

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// The Network page's firewall view (internal/netmap) reads the store chunk by chunk: what a
// sealed chunk holds never changes, so it reads each one once and keeps its summary by name.
// Chunks and EachOpen are separate snapshots (see EachOpen).
var _ contracts.SyslogChunkSource = (*Store)(nil)

// Chunks lists the sealed chunks the store keeps, oldest first: their names, SHA-256, message
// counts and gzip sizes as their sidecars describe them and, as From and To, the earliest and
// the latest receive time of their messages. Those are the receive times of the first and the
// last message - what the chunk's syslog_chunk record states - unless this computer's clock was
// set back while the chunk was open; a reader that skips the chunks outside a period needs the
// earliest and latest. A chunk without messages has the time it was opened. Chunks that a prune
// is deleting, or that PlanPrune chose, are left out (Usage no longer counts them either). It
// never waits for file I/O.
func (s *Store) Chunks() []model.SyslogChunkRef {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.SyslogChunkRef, 0, len(s.chunks))
	for _, c := range s.chunks {
		if c.deleting {
			continue
		}
		r := c.ref()
		if !c.rxMin.IsZero() {
			if !c.rxMin.Equal(c.from) {
				r.From = formatRX(c.rxMin)
			}
			if !c.rxMax.Equal(c.to) {
				r.To = formatRX(c.rxMax)
			}
		}
		out = append(out, r)
	}
	return out
}

// EachOpen calls fn for each message of the open chunk - the one not sealed yet - that was
// received in [from, to) (a zero to has no end), in the order the messages were stored: oldest
// first, unless the clock was set back meanwhile. Each call gets a message of its own, which fn
// may keep. EachOpen returns nil once every such message was passed; fn's error when fn returns
// one, except contracts.ErrStop, which ends it early with nil; and ctx's error when ctx ends
// first (it is checked every few thousand lines).
//
// Like Query, it reads the writer's complete, synced lines (in a read-only store, the file's
// complete lines as far as they go) while no writing method runs, so the chunk cannot be sealed
// under it: fn delays the writer, so it must be quick, and it must not call the store. Reading
// is lenient: lines that do not parse are skipped, and a file that cannot be read is read as far
// as it can be; both are logged once per chunk.
//
// Chunks and EachOpen each see the store as it is when they are called: the open chunk may be
// sealed between a call of Chunks and one of EachOpen, and its messages are then in neither (the
// sealed chunk was not listed, and EachOpen reads the next open chunk, or none). A reader that
// needs both lists the chunks again afterwards: a chunk with messages that it did not list
// before was sealed meanwhile.
func (s *Store) EachOpen(ctx context.Context, from, to time.Time, fn func(*model.SyslogMessage) error) error {
	if to.IsZero() {
		to = endOfTime
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !from.Before(to) {
		return nil
	}
	s.wmu.RLock()
	defer s.wmu.RUnlock()
	s.mu.Lock()
	var oc openView
	if o := s.open; o != nil {
		oc = openView{name: o.name, path: o.path, f: o.f, live: o.live, size: o.size,
			messages: o.messages, rxMin: o.rxMin, rxMax: o.rxMax}
	}
	s.mu.Unlock()
	if oc.name == "" {
		return nil
	}

	var bad int
	var fnErr error // fn's error, told apart from a read error
	each := func(i int, line []byte) error {
		if i%ctxEvery == ctxEvery-1 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		var m model.SyslogMessage
		if line == nil || json.Unmarshal(line, &m) != nil {
			bad++
			return nil
		}
		rx, ok := parseRX(m.RX)
		if !ok {
			bad++
			return nil
		}
		if rx.Before(from) || !rx.Before(to) {
			return nil
		}
		if err := fn(&m); err != nil {
			fnErr = err
			return err
		}
		return nil
	}

	var err error
	if oc.f != nil {
		if oc.messages == 0 || oc.rxMax.Before(from) || !oc.rxMin.Before(to) {
			return nil
		}
		err = eachLine(io.NewSectionReader(oc.f, 0, oc.size), false, each)
	} else {
		f, oerr := openShared(oc.path)
		if errors.Is(oerr, fs.ErrNotExist) {
			return nil // sealed meanwhile by the writer (another process)
		}
		if oerr != nil {
			s.warnOnce(oc.name, "syslog store: the open chunk cannot be read", "err", oerr)
			return nil
		}
		defer f.Close()
		err = eachLine(io.LimitReader(f, maxContent), false, each)
	}
	switch {
	case fnErr != nil:
		if errors.Is(fnErr, contracts.ErrStop) {
			return nil
		}
		return fnErr
	case err != nil && ctx.Err() != nil:
		return ctx.Err()
	case err != nil:
		s.warnOnce(oc.name, "syslog store: the open chunk cannot be read", "err", err)
	}
	s.noteBad(oc.name, bad)
	return nil
}
