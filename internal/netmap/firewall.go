package netmap

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
	"strconv"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// maxLookBack bounds the chunks before a period that are read to find the drop that a repeat
// line at the start of the period repeats.
const maxLookBack = 4

// maxBuilds bounds how many times one request builds its firewall view: a chunk sealed while the
// view was being built holds messages that neither the chunks listed at the start nor the open
// chunk read at the end showed, so the view is built again (cheaply: the chunks read the first
// time are cached).
const maxBuilds = 3

// Firewall returns what the gateway's firewall dropped in [q.From, q.To) according to its syslog
// (contracts.NetworkView); q.Device is not used (the syslog names addresses, not devices). The
// view counts by this computer's receive times. Without a syslog store it fails with an error
// wrapping contracts.ErrUnavailable; a period that is not valid gives ErrRange.
func (v *View) Firewall(ctx context.Context, q contracts.NetQuery) (model.NetFirewall, error) {
	if v.syslog == nil {
		return model.NetFirewall{}, fmt.Errorf("netmap: firewall view: no syslog store: %w", contracts.ErrUnavailable)
	}
	from, to, err := v.period(q)
	if err != nil {
		return model.NetFirewall{}, err
	}
	limit := rowLimit(q.Limit)
	key := periodKey(q, from, to) + "|" + strconv.Itoa(limit)
	fw, err := v.fwResults.get(ctx, key, func() (model.NetFirewall, error) {
		return v.buildFirewall(ctx, from, to, limit)
	})
	if err != nil {
		return model.NetFirewall{}, err
	}
	return cloneFirewall(fw), nil
}

// fwRun is the building of one firewall view.
type fwRun struct {
	v        *View
	ctx      context.Context
	refs     []model.SyslogChunkRef
	from, to int64    // the period in Unix nanoseconds
	b        *builder // the request's sums
	// ends are the repeat lines at the start, the last drop and what the last message was of
	// each chunk read, by its position in refs (len(refs) is the open chunk).
	ends map[int]chunkEnds
	// For the log: chunks read, chunks whose summary was kept, and chunks too big to summarize.
	read, cached, direct int
}

// chunkEnds is what a request needs of a chunk's ends to resolve the repeat lines: those at its
// start (received in the period), its last drop and what its last message was (tail*).
type chunkEnds struct {
	leading []repeat
	last    drop
	hasLast bool
	tail    uint8
}

// buildFirewall builds the firewall view of [from, to) (one at a time).
func (v *View) buildFirewall(ctx context.Context, from, to time.Time, limit int) (model.NetFirewall, error) {
	if err := v.acquireFW(ctx); err != nil {
		return model.NetFirewall{}, fmt.Errorf("netmap: firewall view: %w", err)
	}
	defer v.releaseFW()
	began := time.Now()
	lk := lookup{intel: v.intel}
	names := v.devNames(ctx, from, to)
	for build := 1; ; build++ {
		r, usage, err := v.runFirewall(ctx, from, to, newRequestBuilder(v.bounds, lk, names))
		if err != nil {
			return model.NetFirewall{}, fmt.Errorf("netmap: firewall view: %w", err)
		}
		if build < maxBuilds && sealedSince(r.refs, v.syslog.Chunks()) {
			v.log.Debug("network view: a syslog chunk was sealed while the firewall view was built; it is built again",
				"build", build)
			continue
		}
		fw, err := v.finishFirewall(ctx, r.b, from, to, limit, usage)
		if err != nil {
			return model.NetFirewall{}, fmt.Errorf("netmap: firewall view: %w", err)
		}
		entries, bytes := v.chunks.stats()
		v.log.Debug("network view: firewall view built", "from", fw.From, "to", fw.To, "builds", build,
			"read", r.read, "cached", r.cached, "direct", r.direct, "cache_entries", entries, "cache_bytes", bytes,
			"drops", fw.Drops, "took", time.Since(began).Round(time.Millisecond))
		return fw, nil
	}
}

// runFirewall adds up the drops of [from, to) into b: the sealed chunks the store lists now, then
// the open chunk.
func (v *View) runFirewall(ctx context.Context, from, to time.Time, b *builder) (*fwRun, model.SyslogUsage, error) {
	refs := v.syslog.Chunks()
	usage := v.syslog.Usage()
	v.chunks.begin(refs)
	v.forgetWarned(refs)

	r := &fwRun{v: v, ctx: ctx, refs: refs, from: nanos(from), to: nanos(to), b: b, ends: map[int]chunkEnds{}}
	sel := r.overlapping()
	for _, p := range sel {
		v.chunks.need(refs[p].Name, refs[p].SHA256)
	}
	// Newest first: when the cache has no room for every chunk of a long period, it keeps the
	// newest ones, which every period up to now needs.
	for i := len(sel) - 1; i >= 0; i-- {
		if err := ctx.Err(); err != nil {
			return nil, usage, err
		}
		r.addSealed(sel[i])
	}
	if err := r.addOpen(to); err != nil {
		return nil, usage, err
	}
	r.resolveLeading()
	if err := ctx.Err(); err != nil {
		return nil, usage, err
	}
	return r, usage, nil
}

// sealedSince reports whether the listing after holds a chunk with messages that the listing
// before did not: one sealed in between, from messages that the open chunk then no longer held.
// (A chunk whose planned deletion was cancelled is listed again too: the view is then only built
// once more than needed.)
func sealedSince(before, after []model.SyslogChunkRef) bool {
	listed := make(map[string]struct{}, len(before))
	for _, r := range before {
		listed[r.Name] = struct{}{}
	}
	for _, r := range after {
		if _, ok := listed[r.Name]; !ok && r.Messages > 0 {
			return true
		}
	}
	return false
}

// overlapping returns the positions of the sealed chunks that may hold a message of the period,
// oldest first: by their exact receive range when their summary is kept, else as listed.
func (r *fwRun) overlapping() []int {
	var sel []int
	for i, ref := range r.refs {
		if ref.Messages <= 0 {
			continue
		}
		lo, hi, ok := refBounds(ref)
		if a := r.v.chunks.peek(ref.Name, ref.SHA256); a != nil {
			if !a.hasRX {
				continue
			}
			lo, hi, ok = a.rxMin, a.rxMax, true
		}
		if ok && (hi < r.from || lo >= r.to) {
			continue
		}
		sel = append(sel, i)
	}
	return sel
}

// refBounds returns the receive range a listing states for a chunk.
func refBounds(ref model.SyslogChunkRef) (lo, hi int64, ok bool) {
	a, ok1 := parseRX(ref.From)
	b, ok2 := parseRX(ref.To)
	if !ok1 || !ok2 {
		return 0, 0, false
	}
	return min(a, b), max(a, b), true
}

// newScan returns a scan of a sealed chunk for the period, its builders bounded as a chunk's.
func (r *fwRun) newScan() *scan {
	return &scan{codes: r.v.codes, from: r.from, to: r.to, rows: r.v.bounds.chunkRows, hours: r.v.bounds.chunkHours}
}

// addSealed adds what the sealed chunk at position p holds of the period.
func (r *fwRun) addSealed(p int) {
	ref := r.refs[p]
	e, err := r.addPart(ref)
	if err != nil {
		r.v.skipped(ref.Name, err)
	}
	if e != nil {
		r.ends[p] = *e
	}
}

// addPart adds what a sealed chunk holds of the period to the request's sums and returns the
// chunk's ends: from its kept summary when all its messages are in the period; else the chunk is
// read, its whole summary kept for later requests, and the part in the period summarized
// exactly. The error of a damaged chunk comes with what could be read; any other error with
// nothing (nil ends).
func (r *fwRun) addPart(ref model.SyslogChunkRef) (*chunkEnds, error) {
	if a := r.v.chunks.get(ref.Name, ref.SHA256); a != nil {
		if a.inside(r.from, r.to) {
			r.b.merge(a)
			e := a.ends()
			return &e, nil
		}
		return r.readPart(ref)
	}
	lo, hi, ok := refBounds(ref)
	sc := r.newScan()
	sc.full = newBuilder()
	if !ok || lo < r.from || hi >= r.to {
		sc.part = newBuilder()
	}
	err := r.readChunk(ref, sc)
	switch {
	case errors.Is(err, errTooBig):
		return r.readDirect(ref)
	case err != nil && !errors.Is(err, errDamaged):
		return nil, err
	}
	full := sc.fullAgg()
	if err == nil && r.v.chunks.put(ref.Name, ref.SHA256, full) {
		r.cached++
	}
	switch {
	case !full.hasRX || full.inside(r.from, r.to):
		r.b.merge(full)
		e := full.ends()
		return &e, err
	case sc.part != nil:
		r.b.merge(sc.partAgg())
		e := sc.partEnds()
		return &e, err
	}
	// The listing said every message was in the period, but one is not (the listing's times do
	// not bound them): read the chunk again, exactly.
	return r.readPart(ref)
}

// readPart reads a sealed chunk for its messages in the period.
func (r *fwRun) readPart(ref model.SyslogChunkRef) (*chunkEnds, error) {
	sc := r.newScan()
	sc.part = newBuilder()
	err := r.readChunk(ref, sc)
	switch {
	case errors.Is(err, errTooBig):
		return r.readDirect(ref)
	case err != nil && !errors.Is(err, errDamaged):
		return nil, err
	}
	r.b.merge(sc.partAgg())
	e := sc.partEnds()
	return &e, err
}

// readDirect reads a sealed chunk that holds more than a chunk the store seals can (a damaged or
// foreign file): what it holds of the period goes straight into the request's sums, which bound
// themselves, and no summary of it is kept.
func (r *fwRun) readDirect(ref model.SyslogChunkRef) (*chunkEnds, error) {
	r.direct++
	sc := &scan{codes: r.v.codes, part: r.b, from: r.from, to: r.to}
	err := r.readChunk(ref, sc)
	if err != nil && !errors.Is(err, errDamaged) {
		return nil, err
	}
	e := sc.partEnds()
	return &e, err
}

// lookEnds returns the ends of a sealed chunk outside the period: from its kept summary, else
// read (and its summary kept).
func (r *fwRun) lookEnds(ref model.SyslogChunkRef) (*chunkEnds, error) {
	if a := r.v.chunks.get(ref.Name, ref.SHA256); a != nil {
		e := a.ends()
		return &e, nil
	}
	sc := r.newScan()
	sc.full = newBuilder()
	err := r.readChunk(ref, sc)
	if errors.Is(err, errTooBig) {
		sc = r.newScan() // its ends only
		err = r.readChunk(ref, sc)
	}
	if err != nil && !errors.Is(err, errDamaged) {
		return nil, err
	}
	if sc.full == nil {
		e := sc.partEnds()
		return &e, err
	}
	a := sc.fullAgg()
	if err == nil && r.v.chunks.put(ref.Name, ref.SHA256, a) {
		r.cached++
	}
	e := a.ends()
	return &e, err
}

// readChunk reads a sealed chunk into sc (counted for the log).
func (r *fwRun) readChunk(ref model.SyslogChunkRef, sc *scan) error {
	r.read++
	err := r.v.readChunk(r.ctx, ref.Name, sc)
	if sc.bad > 0 {
		// The store logs such lines when it reads them itself; here they only count as not read.
		r.v.log.Debug("network view: lines of a syslog chunk that cannot be read were skipped", "chunk", ref.Name,
			"lines", sc.bad)
	}
	return err
}

// addOpen adds what the open chunk holds of the period, straight into the request's sums (the
// store seals a chunk at 1 MiB). Its messages before the period are read too: a repeat line in
// the period may repeat one of them.
func (r *fwRun) addOpen(to time.Time) error {
	sc := &scan{codes: r.v.codes, part: r.b, from: r.from, to: r.to}
	err := r.v.syslog.EachOpen(r.ctx, time.Time{}, to, func(m *model.SyslogMessage) error {
		rx, ok := parseRX(m.RX)
		if !ok {
			sc.bad++
			return nil
		}
		sc.message(rx, messageText(m.Msg, m.Raw, m.RawB64))
		return nil
	})
	switch {
	case err != nil && r.ctx.Err() != nil:
		return r.ctx.Err()
	case err != nil:
		// The store reads leniently and returns only the context's error: keep what was read.
		r.v.log.Warn("network view: the open syslog chunk could not be read", "err", err)
	}
	r.ends[len(r.refs)] = sc.partEnds()
	return nil
}

// resolveLeading counts the repeat lines at the start of each chunk read as drops like the last
// drop before that chunk; a BSD repeat line among them (cond) only when the message before the
// chunk was a drop.
func (r *fwRun) resolveLeading() {
	for _, p := range slices.Sorted(maps.Keys(r.ends)) {
		e := r.ends[p]
		if len(e.leading) == 0 {
			continue
		}
		d, ok, tail := r.before(p)
		if !ok {
			continue
		}
		for _, rp := range e.leading {
			if rp.cond && tail != tailDrop {
				continue
			}
			r.b.add(d, rp.rx, int(rp.n))
		}
	}
}

// before returns what precedes the chunk at position p in receive order: the last drop of the
// nearest chunk before it that has one, and what the last message of the nearest chunk before
// it that has a message other than BSD repeat lines was (tailNone when none has). Chunks outside
// the period are read for them (at most maxLookBack).
func (r *fwRun) before(p int) (d drop, ok bool, tail uint8) {
	looked := 0
	for q := p - 1; q >= 0; q-- {
		e, known := r.ends[q]
		if !known {
			ref := r.refs[q]
			if ref.Messages <= 0 {
				continue
			}
			if looked == maxLookBack || r.ctx.Err() != nil {
				break
			}
			looked++
			got, err := r.lookEnds(ref)
			if err != nil {
				r.v.skipped(ref.Name, err)
			}
			if got == nil {
				continue
			}
			e = chunkEnds{last: got.last, hasLast: got.hasLast, tail: got.tail}
			r.ends[q] = e
		}
		if tail == tailNone {
			tail = e.tail
		}
		if e.hasLast {
			return e.last, true, tail
		}
	}
	return drop{}, false, tail
}

// skipped logs, once per chunk, that a chunk could not be read (fully). A chunk deleted
// meanwhile is no problem.
func (v *View) skipped(name string, err error) {
	if errors.Is(err, contracts.ErrNotFound) || isContextErr(err) || v.warned[name] {
		return
	}
	v.warned[name] = true
	v.log.Warn("network view: a syslog chunk cannot be read; the firewall view leaves out what it could not read",
		"chunk", name, "err", err)
}

// forgetWarned forgets the chunks the store no longer lists.
func (v *View) forgetWarned(refs []model.SyslogChunkRef) {
	if len(v.warned) == 0 {
		return
	}
	listed := make(map[string]bool, len(refs))
	for _, r := range refs {
		listed[r.Name] = true
	}
	for name := range v.warned {
		if !listed[name] {
			delete(v.warned, name)
		}
	}
}

// nanos returns t in Unix nanoseconds, a time before minYear or after maxYear as the lowest or
// highest value (no receive time is believed outside those years).
func nanos(t time.Time) int64 {
	switch {
	case t.Year() < minYear:
		return math.MinInt64
	case t.Year() > maxYear:
		return math.MaxInt64
	}
	return t.UnixNano()
}

// cloneFirewall returns a copy of a view whose slices the caller may change.
func cloneFirewall(fw model.NetFirewall) model.NetFirewall {
	fw.Hours = slices.Clone(fw.Hours)
	fw.Countries = slices.Clone(fw.Countries)
	fw.TopSources = slices.Clone(fw.TopSources)
	fw.Services = slices.Clone(fw.Services)
	fw.Reasons = slices.Clone(fw.Reasons)
	fw.OutboundRows = slices.Clone(fw.OutboundRows)
	return fw
}
