package web

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

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
	// record of the period.
	MaxSyslogSpan = 31 * 24 * time.Hour
	// MaxSyslogQueryChars bounds the text filter q.
	MaxSyslogQueryChars = 200
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

// handleSyslog serves GET /api/syslog?from=&to=&q=&severity=&limit=: the messages of the syslog
// records (model.TypeSyslog) whose time lies in [from, to), newest first by receive time, each
// with the seq of the record that holds it (model.SyslogList). to defaults to now and from to
// 24 hours before to; the period may span at most MaxSyslogSpan. q keeps the messages whose raw
// text, message, app or host contains it (ignoring case); severity (0-7, or a name such as
// "err") keeps that level and the more severe ones and drops messages without a severity.
// limit (default 200, at most 5000) caps the list; truncated says that more matched.
//
// Integrity problems of the syslog records read (an h that is not the SHA-256 of b, data that
// does not parse) are reported in WarningHeader; a record whose data does not parse is skipped.
func (s *Server) handleSyslog(w http.ResponseWriter, r *http.Request) {
	if s.reader == nil {
		writeError(w, http.StatusServiceUnavailable, "ledger reader is not available")
		return
	}
	q, err := parseSyslogQuery(r.URL.Query(), s.now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := s.scanSyslog(r.Context(), q)
	if err != nil {
		s.writeErr(w, "syslog", err)
		return
	}
	list := model.SyslogList{
		From:      q.from.UTC().Format(time.RFC3339Nano),
		To:        q.to.UTC().Format(time.RFC3339Nano),
		Messages:  make([]model.SyslogEntry, 0, len(res.items)),
		Truncated: res.truncated,
	}
	for _, it := range res.items {
		list.Messages = append(list.Messages, model.SyslogEntry{Seq: it.seq, SyslogMessage: it.msg})
	}
	if msg := res.check.warning(); msg != "" {
		w.Header().Set(WarningHeader, headerSafe(msg))
	}
	writeJSON(w, http.StatusOK, list)
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
		// A severity outside 0-7 (a damaged record) is no severity.
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

// syslogItem is a message that matched, with its place in the ledger.
type syslogItem struct {
	at  time.Time // receive time; the record's time when rx does not parse
	seq uint64
	idx int // position in its batch
	msg model.SyslogMessage
}

// newestFirst orders items by receive time, newest first, then by record and by position in
// the record, later first (so that a batch keeps its order when its messages share a time).
func newestFirst(a, b syslogItem) int {
	if c := b.at.Compare(a.at); c != 0 {
		return c
	}
	if c := cmp.Compare(b.seq, a.seq); c != 0 {
		return c
	}
	return cmp.Compare(b.idx, a.idx)
}

// syslogScan is what scanSyslog found.
type syslogScan struct {
	items     []syslogItem // the newest matches, newest first, at most limit
	truncated bool         // more matched than limit
	check     integrityCheck
}

// scanSyslog reads the syslog records of q's period and returns the newest q.limit messages
// that match. The period is read in windows that end at UTC midnight (the ledger keeps one
// segment per UTC day), newest first, and the reading stops as soon as nothing older can be
// among the newest: a record holds the messages received before it was written, so no record
// of an earlier window holds a message received after the window began. Memory is bounded:
// only the newest matches are kept. Its error is the reader's or the context's.
func (s *Server) scanSyslog(ctx context.Context, q syslogQuery) (syslogScan, error) {
	keep := q.limit + 1 // one more than shown tells whether more matched
	var res syslogScan
	var found []syslogItem
	matched := 0
	trim := func() {
		slices.SortFunc(found, newestFirst)
		if len(found) > keep {
			clear(found[keep:]) // release the messages that no longer count
			found = found[:keep]
		}
	}
	for _, win := range syslogWindows(q.from, q.to) {
		err := s.reader.ScanTime(win[0], win[1], func(env model.Envelope, body model.Body) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if body.Type != model.TypeSyslog {
				return nil
			}
			if !envelopeHashOK(env) {
				res.check.note(fmt.Sprintf("#%d h does not match b", body.Seq))
			}
			var batch model.SyslogBatch
			if err := json.Unmarshal(body.Data, &batch); err != nil {
				res.check.note(fmt.Sprintf("#%d syslog data does not parse", body.Seq))
				return nil
			}
			recorded, _ := time.Parse(time.RFC3339Nano, body.TS)
			for i := range batch.Messages {
				m := &batch.Messages[i]
				if !q.match(m) {
					continue
				}
				matched++
				at, err := time.Parse(time.RFC3339Nano, m.RX)
				if err != nil {
					at = recorded
				}
				found = append(found, syslogItem{at: at, seq: body.Seq, idx: i, msg: *m})
				if len(found) >= 2*keep {
					trim()
				}
			}
			return nil
		})
		if err != nil && !errors.Is(err, contracts.ErrStop) {
			return syslogScan{}, err
		}
		trim()
		if len(found) == keep && !found[keep-1].at.Before(win[0]) {
			break // the windows before this one hold only messages received before it began
		}
	}
	res.truncated = matched > q.limit
	res.items = found[:min(len(found), q.limit)]
	return res, nil
}

// syslogWindows splits [from, to) at UTC midnight, newest first.
func syslogWindows(from, to time.Time) [][2]time.Time {
	var out [][2]time.Time
	for end := to; end.After(from); {
		start := end.Add(-time.Nanosecond).UTC().Truncate(24 * time.Hour)
		if start.Before(from) {
			start = from
		}
		out = append(out, [2]time.Time{start, end})
		end = start
	}
	return out
}
