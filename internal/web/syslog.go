package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"attmonitor/internal/config"
	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// Limits and defaults of GET /api/syslog.
const (
	DefaultSyslogLimit = 200
	MaxSyslogLimit     = 5000
	// DefaultSyslogSpan is the period read when from is not given: the day before to.
	DefaultSyslogSpan = 24 * time.Hour
	// MaxSyslogSpan bounds the period of one request: a filter that matches nothing reads every
	// message of the period.
	MaxSyslogSpan = 31 * 24 * time.Hour
	// MaxSyslogQueryChars bounds the text filter q.
	MaxSyslogQueryChars = 200
	// MaxSyslogAnswerBytes bounds the JSON of one answer's messages: the list ends before the
	// message that would take it beyond, whatever the limit, and says truncated. A sender
	// controls how long its messages are once encoded: a control character takes six bytes
	// (\u0001), in raw and again in msg, so 5000 datagrams of 8 KiB (the receiver's default
	// largest) would make an answer of about 0.5 GB, built in the service's memory.
	MaxSyslogAnswerBytes = 16 << 20
)

// Answers of the syslog and traffic features a monitor may not offer (404).
const (
	msgNoSyslogStore   = "the gateway's syslog messages are not available: this att-monitor keeps no syslog store"
	msgNoSyslogControl = "how much syslog is kept cannot be changed here: this att-monitor offers no control of a syslog store"
)

// syslogSeverities maps the names severity= accepts to the severity numbers of RFC 5424
// §6.2.1: the keywords of syslog.conf, with the spellings people commonly use for them.
var syslogSeverities = map[string]int{
	"emerg": 0, "emergency": 0, "panic": 0, "alert": 1, "crit": 2, "critical": 2, "err": 3, "error": 3,
	"warning": 4, "warn": 4, "notice": 5, "info": 6, "informational": 6, "debug": 7,
}

// syslogQuery is a validated GET /api/syslog request.
type syslogQuery struct {
	from, to time.Time
	text     string // lower case; "" = no text filter
	maxSev   int    // keep severities 0..maxSev; -1 = no severity filter
	limit    int
}

// handleSyslog serves GET /api/syslog?from=&to=&q=&severity=&limit=: the gateway's syslog
// messages kept in the syslog store (docs/syslog-snmp-traffic.md §3.2) that were received in
// [from, to), newest first (model.SyslogList). to defaults to now and from to 24 hours before
// to; the period may span at most MaxSyslogSpan. q keeps the messages whose raw text, message,
// app or host contains it (ignoring case); severity (0-7, or a name such as "err") keeps that
// level and the more severe ones and drops messages without a severity. limit (default 200,
// at most 5000) caps the list, and so does MaxSyslogAnswerBytes (syslogAnswerFits); truncated
// says that more matched. A list cut by its size holds fewer messages than the limit: a larger
// limit does not show more, a shorter period or a filter does.
//
// Each message names the chunk of the store that holds it and, once that chunk is sealed, the
// syslog_chunk record that states the chunk's SHA-256 (fillChunkSeqs). Integrity problems of
// the syslog_chunk records read (an h that is not the SHA-256 of b, data that does not parse)
// are reported in WarningHeader. Without a syslog store the endpoint answers 404.
func (s *Server) handleSyslog(w http.ResponseWriter, r *http.Request) {
	if s.syslog == nil {
		writeError(w, http.StatusNotFound, msgNoSyslogStore)
		return
	}
	q, err := parseSyslogQuery(r.URL.Query(), s.now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var match func(*model.SyslogMessage) bool
	if q.text != "" || q.maxSev >= 0 {
		match = q.match
	}
	ctx := r.Context()
	found, truncated, err := s.syslog.Query(ctx, q.from, q.to, match, q.limit)
	if err != nil {
		s.writeErr(w, "syslog", err)
		return
	}
	if len(found) > q.limit {
		found, truncated = found[:q.limit], true
	}
	n := syslogAnswerFits(found, MaxSyslogAnswerBytes)
	if n < len(found) {
		truncated = true
	}
	// A copy of what is listed: the entries are completed here, and the store may keep what it
	// returned (the messages left out can be freed meanwhile).
	entries := slices.Clone(found[:n])
	if entries == nil {
		entries = []model.SyslogEntry{}
	}
	var chk integrityCheck
	if err := s.fillChunkSeqs(ctx, entries, &chk); err != nil {
		s.writeErr(w, "syslog", err) // the client went away
		return
	}
	if msg := chk.warning(); msg != "" {
		w.Header().Set(WarningHeader, headerSafe(msg))
	}
	writeJSON(w, http.StatusOK, model.SyslogList{
		From:      q.from.UTC().Format(time.RFC3339Nano),
		To:        q.to.UTC().Format(time.RFC3339Nano),
		Messages:  entries,
		Truncated: truncated,
	})
}

// parseSyslogQuery validates the parameters of GET /api/syslog; now is the default end.
func parseSyslogQuery(v url.Values, now time.Time) (syslogQuery, error) {
	from, err := parseTimeParam(v.Get("from"))
	if err != nil {
		return syslogQuery{}, errors.New("from: " + err.Error())
	}
	to, err := parseTimeParam(v.Get("to"))
	if err != nil {
		return syslogQuery{}, errors.New("to: " + err.Error())
	}
	if to.IsZero() {
		to = now.UTC()
	}
	if from.IsZero() {
		from = to.Add(-DefaultSyslogSpan)
	}
	if !from.Before(to) {
		return syslogQuery{}, errors.New("from must be before to")
	}
	if to.Sub(from) > MaxSyslogSpan {
		return syslogQuery{}, fmt.Errorf("from and to may be at most %d days apart", MaxSyslogSpan/(24*time.Hour))
	}
	text := strings.TrimSpace(v.Get("q"))
	if !utf8.ValidString(text) {
		return syslogQuery{}, errors.New("q must be valid UTF-8")
	}
	if n := utf8.RuneCountInString(text); n > MaxSyslogQueryChars {
		return syslogQuery{}, fmt.Errorf("q must be at most %d characters (got %d)", MaxSyslogQueryChars, n)
	}
	maxSev, err := parseSyslogSeverity(v.Get("severity"))
	if err != nil {
		return syslogQuery{}, err
	}
	limit := DefaultSyslogLimit
	if lv := v.Get("limit"); lv != "" {
		n, err := strconv.Atoi(lv)
		if err != nil || n < 1 {
			return syslogQuery{}, fmt.Errorf("limit must be a positive integer (at most %d)", MaxSyslogLimit)
		}
		limit = min(n, MaxSyslogLimit)
	}
	return syslogQuery{from: from, to: to, text: strings.ToLower(text), maxSev: maxSev, limit: limit}, nil
}

// parseSyslogSeverity parses severity=: a number 0-7 or a name (syslogSeverities), ignoring
// case; "" is no filter (-1).
func parseSyslogSeverity(v string) (int, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return -1, nil
	}
	if len(v) == 1 && v[0] >= '0' && v[0] <= '7' {
		return int(v[0] - '0'), nil
	}
	if n, ok := syslogSeverities[v]; ok {
		return n, nil
	}
	return 0, errors.New("severity must be 0-7 or one of emerg, alert, crit, err, warning, notice, info, debug")
}

// match reports whether a message passes the filters of q.
func (q syslogQuery) match(m *model.SyslogMessage) bool {
	if q.maxSev >= 0 {
		// A severity outside 0-7 (a damaged line) is no severity.
		if m.Severity == nil || *m.Severity < 0 || *m.Severity > 7 || *m.Severity > q.maxSev {
			return false
		}
	}
	return q.text == "" || containsFold(m.Raw, q.text) || containsFold(m.Msg, q.text) ||
		containsFold(m.App, q.text) || containsFold(m.Host, q.text)
}

// containsFold reports whether s contains sub (lower case), ignoring case.
func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), sub)
}

// syslogSeqRoom is room for the seq that fillChunkSeqs adds to an entry after it was measured
// (`"seq":18446744073709551615,`).
const syslogSeqRoom = 27

// syslogAnswerFits returns how many of the entries, from the first (the newest), an answer
// holds within maxBytes of JSON: the entries as encoded, with a comma and room for the seq
// each. It is at least one, so that an answer always shows the newest message (a datagram of
// the receiver's largest size takes well under 1 MiB).
func syslogAnswerFits(entries []model.SyslogEntry, maxBytes int) int {
	total := 0
	for i := range entries {
		b, _ := json.Marshal(&entries[i]) // cannot fail: strings, and pointers to integers
		total += len(b) + 1 + syslogSeqRoom
		if total > maxBytes && i > 0 {
			return i
		}
	}
	return len(entries)
}

// ----------------------------------------------------------------------------- chunk records

// Looking up the syslog_chunk records of the chunks a GET /api/syslog lists.
const (
	// syslogChunkSlack is how long after the newest message listed from a chunk its
	// syslog_chunk record is looked for. A chunk is sealed, and its record written, when it
	// reaches 1 MiB, about 5 minutes after its first message (at the store's next flush, every
	// syslog.flush_interval), or when the service stops (docs/syslog-snmp-traffic.md §3.2); a
	// chunk sealed or recorded later than this (recovered at the next start after a crash, or
	// recorded once the ledger took records again after refusing them) is listed without its
	// record.
	syslogChunkSlack = 15 * time.Minute
	// syslogScanJoin: windows closer than this are read with one ledger scan (each scan reads
	// the segments it touches from their start, which costs about as much as reading this much
	// more of a segment).
	syslogScanJoin = 2 * time.Hour
	// syslogScanSpan bounds the period of one scan: windows are joined only while the joined
	// window spans at most this. A scan hands over its records oldest first, so the record
	// budget goes to the newest messages' chunks first only because the windows are read newest
	// first and none is long: one window of several days would spend the budget on its oldest
	// records and leave the newest messages, at the top of the list, without their records.
	// 12 hours of a ledger hold about 6,000 records (a sample every 10 s, a gateway snapshot and
	// a service check a minute), far fewer than the budget.
	syslogScanSpan = 12 * time.Hour
	// maxSyslogChunkScans bounds the ledger scans of one request.
	maxSyslogChunkScans = 16
	// maxChunkSeqCache bounds the chunk records remembered.
	maxChunkSeqCache = 8192
)

// syslogChunkBudget bounds how many ledger records one request may examine to find chunk
// records (a variable only so that tests can lower it).
var syslogChunkBudget = 50_000

// chunkRecord is the syslog_chunk record of a chunk.
type chunkRecord struct {
	seq      uint64
	from, to time.Time // receive times of the chunk's first and last message (zero: not stated)
}

// covers reports whether t can be the receive time of a message of the chunk.
func (c chunkRecord) covers(t time.Time) bool {
	return (c.from.IsZero() || !t.Before(c.from)) && (c.to.IsZero() || !t.After(c.to))
}

// chunkSeqCache remembers the syslog_chunk record of each sealed chunk found; records never
// change. Records whose h does not match b are not remembered, so that they are reported every
// time. It forgets everything when full.
type chunkSeqCache struct {
	mu   sync.Mutex
	recs map[string]chunkRecord
}

func (c *chunkSeqCache) get(name string) (chunkRecord, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec, ok := c.recs[name]
	return rec, ok
}

func (c *chunkSeqCache) put(name string, rec chunkRecord) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.recs == nil || len(c.recs) >= maxChunkSeqCache {
		c.recs = make(map[string]chunkRecord)
	}
	c.recs[name] = rec
}

// chunkSpan is the period in which the messages listed from one chunk were received.
type chunkSpan struct{ from, to time.Time }

// fillChunkSeqs sets the Seq of each entry to the syslog_chunk record of its chunk when that
// record is known: from the cache, else from the ledger. A chunk's record is written when the
// chunk is sealed, so it lies after the chunk's messages: it is looked for from the oldest
// message listed from the chunk to syslogChunkSlack after the newest. Chunks the store does
// not hold as sealed (the open chunk, or one deleted meanwhile) are not looked up. The windows
// are joined when closer than syslogScanJoin as long as a window spans at most syslogScanSpan,
// and read newest first, at most maxSyslogChunkScans scans and syslogChunkBudget records in
// all: when the budget runs out, the messages left without their records are in the window it
// ran out in and older ones, never in the newer windows read in full (a later request, with the
// records found remembered, reads further back). A record counts only if its time range covers
// the messages. Entries whose record is not found keep Seq 0. Its error is the context's.
func (s *Server) fillChunkSeqs(ctx context.Context, entries []model.SyslogEntry, chk *integrityCheck) error {
	if s.reader == nil {
		return nil
	}
	spans := map[string]chunkSpan{}
	var listed []string // the chunks to look up, in the order of the list
	for i := range entries {
		e := &entries[i]
		rx, err := time.Parse(time.RFC3339Nano, e.RX)
		if e.Chunk == "" || err != nil {
			continue
		}
		if rec, ok := s.chunkSeqs.get(e.Chunk); ok && rec.covers(rx) {
			e.Seq = rec.seq
			continue
		}
		sp, seen := spans[e.Chunk]
		switch {
		case !seen:
			sp = chunkSpan{rx, rx}
			listed = append(listed, e.Chunk)
		case rx.Before(sp.from):
			sp.from = rx
		case rx.After(sp.to):
			sp.to = rx
		}
		spans[e.Chunk] = sp
	}
	// Only a sealed chunk has a record.
	for _, name := range listed {
		if !s.chunkSealed(name) {
			delete(spans, name)
		}
	}
	if len(spans) == 0 {
		return nil
	}

	found := map[string]chunkRecord{}
	budget := syslogChunkBudget
	for i, win := range chunkWindows(spans) {
		if i >= maxSyslogChunkScans || budget <= 0 {
			break
		}
		pending := 0
		for _, name := range win.names {
			if _, ok := found[name]; !ok {
				pending++
			}
		}
		if pending == 0 {
			continue
		}
		err := s.reader.ScanTime(win.from, win.to, func(env model.Envelope, body model.Body) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if budget <= 0 {
				return contracts.ErrStop
			}
			budget--
			if body.Type != model.TypeSyslogChunk {
				return nil
			}
			var c model.SyslogChunk
			if err := json.Unmarshal(body.Data, &c); err != nil {
				chk.note(fmt.Sprintf("#%d syslog_chunk data does not parse", body.Seq))
				return nil
			}
			sp, want := spans[c.Name]
			if _, dup := found[c.Name]; !want || dup {
				return nil
			}
			rec := chunkRecord{seq: body.Seq}
			rec.from, _ = time.Parse(time.RFC3339Nano, c.From)
			rec.to, _ = time.Parse(time.RFC3339Nano, c.To)
			if !rec.covers(sp.from) || !rec.covers(sp.to) {
				return nil // another chunk of that name
			}
			found[c.Name] = rec
			if envelopeHashOK(env) {
				s.chunkSeqs.put(c.Name, rec)
			} else {
				chk.note(fmt.Sprintf("#%d h does not match b", body.Seq))
			}
			if slices.Contains(win.names, c.Name) {
				if pending--; pending == 0 {
					return contracts.ErrStop
				}
			}
			return nil
		})
		if err != nil && !errors.Is(err, contracts.ErrStop) {
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			s.log.Warn("web: reading the ledger for syslog_chunk records failed", "from", win.from, "to", win.to, "err", err)
			chk.note("the syslog_chunk records could not be read: " + err.Error())
			break
		}
	}
	for i := range entries {
		e := &entries[i]
		rec, ok := found[e.Chunk]
		if rx, err := time.Parse(time.RFC3339Nano, e.RX); ok && err == nil && rec.covers(rx) {
			e.Seq = rec.seq
		}
	}
	return nil
}

// chunkSealed reports whether the store holds name as a sealed chunk. Only a sealed chunk has
// a syslog_chunk record; the open chunk is not a sealed file yet. When the store cannot tell
// (another error than ErrNotFound) the record is looked for anyway.
func (s *Server) chunkSealed(name string) bool {
	rc, err := s.syslog.OpenChunk(name)
	if err != nil {
		return !errors.Is(err, contracts.ErrNotFound)
	}
	rc.Close()
	return true
}

// chunkWindow is a period of the ledger in which the syslog_chunk records of some chunks can
// lie.
type chunkWindow struct {
	from, to time.Time
	names    []string
}

// chunkWindows returns the periods in which the records of the chunks with the given spans
// can lie, joined when closer than syslogScanJoin as long as the joined period spans at most
// syslogScanSpan, newest first.
func chunkWindows(spans map[string]chunkSpan) []chunkWindow {
	wins := make([]chunkWindow, 0, len(spans))
	for name, sp := range spans {
		wins = append(wins, chunkWindow{from: sp.from, to: sp.to.Add(syslogChunkSlack), names: []string{name}})
	}
	slices.SortFunc(wins, func(a, b chunkWindow) int {
		if c := a.from.Compare(b.from); c != 0 {
			return c
		}
		return strings.Compare(a.names[0], b.names[0])
	})
	var out []chunkWindow
	for _, w := range wins {
		if n := len(out); n > 0 && w.from.Sub(out[n-1].to) < syslogScanJoin {
			last := &out[n-1]
			to := last.to
			if w.to.After(to) {
				to = w.to
			}
			if to.Sub(last.from) <= syslogScanSpan {
				last.to = to
				last.names = append(last.names, w.names...)
				continue
			}
		}
		out = append(out, w)
	}
	slices.Reverse(out)
	return out
}

// ----------------------------------------------------------------------------- retention

// syslogRetentionTimeout bounds a change of the syslog retention: saving the setting,
// recording it and deleting the chunks that no longer fit. Like the other operator actions it
// runs detached from the request.
const syslogRetentionTimeout = 2 * time.Minute

// SyslogRetentionRequest is the body of POST /api/syslog/retention: how much of the gateway's
// syslog the store keeps (config syslog.keep_mb and syslog.keep_days). It states the whole
// setting: a field left out is not "unchanged".
type SyslogRetentionRequest struct {
	// KeepMB (required) is the size limit in MiB, config.MinSyslogKeepMB to
	// config.MaxSyslogKeepMB: the oldest chunks are deleted once the stored messages take more.
	KeepMB *int `json:"keep_mb"`
	// KeepDays, when above 0, also deletes the chunks older than that many days; 0 or absent is
	// no age limit. At most config.MaxSyslogKeepDays.
	KeepDays *int   `json:"keep_days,omitempty"`
	Client   string `json:"client,omitempty"` // "web" or "cli"; default inferred (see clientName); becomes the actor
}

// handleSyslogRetention serves POST /api/syslog/retention: the operator chooses how much of
// the gateway's syslog to keep. The monitor saves the setting, records a config_change,
// applies it at once and deletes what no longer fits (syslog_prune records); the answer is
// the config_change. A failed change is answered with ConfigChangeError, whose change tells
// "not changed" from "in effect, but something after it failed". Without a syslog store
// control the endpoint answers 404.
func (s *Server) handleSyslogRetention(w http.ResponseWriter, r *http.Request) {
	if s.syslogCtl == nil {
		writeError(w, http.StatusNotFound, msgNoSyslogControl)
		return
	}
	var req SyslogRetentionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.KeepMB == nil {
		writeError(w, http.StatusBadRequest, "keep_mb (the MiB of syslog messages to keep) is required")
		return
	}
	keepMB, keepDays := *req.KeepMB, 0
	if keepMB < config.MinSyslogKeepMB || keepMB > config.MaxSyslogKeepMB {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("keep_mb must be a whole number of MiB from %d to %d", config.MinSyslogKeepMB, config.MaxSyslogKeepMB))
		return
	}
	if req.KeepDays != nil {
		keepDays = *req.KeepDays
	}
	if keepDays < 0 || keepDays > config.MaxSyslogKeepDays {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("keep_days must be 0 (no age limit) to %d", config.MaxSyslogKeepDays))
		return
	}
	client, ok := clientName(req.Client, r)
	if !ok {
		writeError(w, http.StatusBadRequest, `client must be "web" or "cli"`)
		return
	}
	if !s.syslogMu.TryLock() {
		writeError(w, http.StatusConflict, "a change of the syslog retention is already in progress")
		return
	}
	defer s.syslogMu.Unlock()

	ctx, cancel := s.detached(r, syslogRetentionTimeout)
	defer cancel()
	change, err := s.syslogCtl.SetSyslogRetention(ctx, keepMB, keepDays, "operator via "+client)
	if err != nil {
		s.log.Warn("web: syslog retention change failed", "keep_mb", keepMB, "keep_days", keepDays, "result", change.Result, "err", err)
		code, retryAfter, msg := retentionError(change, err)
		resp := ConfigChangeError{Error: msg}
		if change != (model.ConfigChange{}) {
			resp.Change = &change
		}
		writeRetryAfter(w, retryAfter)
		writeJSON(w, code, resp)
		return
	}
	writeJSON(w, http.StatusOK, change)
}

// retentionError maps a failed retention change to a status and a message for the operator.
func retentionError(change model.ConfigChange, err error) (int, time.Duration, string) {
	const op = "syslog retention change"
	c, known := classifyErr(op, err)
	switch {
	case errors.Is(err, contracts.ErrNotRecorded):
		return c.code, c.retryAfter, c.msg
	case gatewayChangeReported(change.Result):
		// The new limits are in effect ("applied"); what failed came after, e.g. deleting a chunk.
		return http.StatusInternalServerError, 0, "the new syslog retention is in effect (" + change.Result + "), but the change could not be completed: " + err.Error()
	case known:
		return c.code, c.retryAfter, c.msg
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout, 0, op + ": operation timed out"
	case errors.Is(err, context.Canceled):
		return http.StatusServiceUnavailable, 0, op + ": cancelled"
	}
	return http.StatusInternalServerError, 0, op + ": " + err.Error()
}
