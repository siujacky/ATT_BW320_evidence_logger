package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// Limits and defaults of the JSON API.
const (
	DefaultRecordLimit = 100
	MaxRecordLimit     = 500
	// MaxIncidentRecords caps the evidence records returned with one incident.
	MaxIncidentRecords = 300
	MaxNoteChars       = 4000
	MaxNameChars       = 200
)

// recordScanBudget bounds how many ledger records one /api/records request may examine (a
// rare type filter over a year-old ledger must not pin the CPU for minutes). A variable only
// so that tests can lower it.
var recordScanBudget = 250_000

// Timeouts of operator actions. They run detached from the HTTP request so that closing the
// browser tab cannot interrupt a gateway configuration change or an export half-way; they are
// still cancelled when the server shuts down.
const (
	noteTimeout         = 30 * time.Second
	notificationTimeout = 3 * time.Minute
	// gatewaySyslogTimeout bounds a change of the gateway's Syslog setting like a change of the
	// notification setting: a login (the gateway client allows one a minute), the page, its
	// Update round, the Save and the read-back.
	gatewaySyslogTimeout = notificationTimeout
	trustCertTimeout     = time.Minute
	anchorTimeout        = 2 * time.Minute
	exportTimeout        = 15 * time.Minute
)

// SeriesRanges are the accepted values of GET /api/series?range=.
var SeriesRanges = []string{"1h", "6h", "24h", "7d"}

// DefaultSeriesRange is used when the range parameter is omitted.
const DefaultSeriesRange = "24h"

// ErrorResponse is the body of every error response.
type ErrorResponse struct {
	Error string `json:"error"`
}

// RecordView is one ledger record as returned by /api/records and /api/incidents/{id}.
type RecordView struct {
	Seq  uint64 `json:"seq"`
	TS   string `json:"ts"`
	Type string `json:"type"`
	Hash string `json:"hash"`
	// HashOK reports whether Hash (the envelope's h) is the SHA-256 of Envelope.B. It checks
	// this one line against itself only; signatures, the chain, segments, blobs and anchors
	// are checked by POST /api/verify.
	HashOK bool `json:"hash_ok"`
	// Body is the signed body (Envelope.B) as a JSON value. JSON encoding may normalize its
	// whitespace and escaping; the exact signed bytes are Envelope.B.
	Body json.RawMessage `json:"body"`
	// Envelope is the ledger line exactly as stored (h, s, b) for independent verification.
	Envelope model.Envelope `json:"envelope"`
}

// IncidentDetail is the body of GET /api/incidents/{id}.
type IncidentDetail struct {
	Incident model.Incident `json:"incident"`
	// Records are the ledger records the incident references (evidence, first/last seq),
	// in ascending seq order.
	Records []RecordView `json:"records"`
	// Missing lists referenced seqs that could not be read.
	Missing []uint64 `json:"missing,omitempty"`
	// Referenced is the number of distinct records the incident references.
	Referenced int `json:"referenced"`
	// Truncated is true when more than MaxIncidentRecords records are referenced. Records
	// then holds first_seq, last_seq and the earliest and latest of the other references.
	Truncated bool `json:"truncated,omitempty"`
}

// ExportCreateRequest is the body of POST /api/exports. From/To accept RFC 3339 or
// YYYY-MM-DD (UTC midnight); both are required unless IncidentID is given.
type ExportCreateRequest struct {
	From       string `json:"from,omitempty"`
	To         string `json:"to,omitempty"`
	IncidentID string `json:"incident_id,omitempty"`
	PreparedBy string `json:"prepared_by,omitempty"`
	Notes      string `json:"notes,omitempty"`
	Client     string `json:"client,omitempty"` // "web" or "cli"; default inferred (see clientName)
}

// NoteRequest is the body of POST /api/notes.
type NoteRequest struct {
	Text   string `json:"text"`
	Author string `json:"author,omitempty"`
	Client string `json:"client,omitempty"` // "web" or "cli"; default inferred (see clientName); recorded as the note source
}

// NotificationRequest is the body of POST /api/gateway/notification.
type NotificationRequest struct {
	Enabled *bool  `json:"enabled"`          // required
	Client  string `json:"client,omitempty"` // "web" or "cli"; default inferred (see clientName); becomes the actor
}

// ConfigChangeError is the body of a failed configuration change (POST
// /api/gateway/notification, POST /api/gateway/syslog, POST /api/gateway/trust-cert, POST
// /api/syslog/retention): Change carries whatever the monitor reported about the attempt, so a
// client can tell "not changed" from "changed, but something after it failed".
type ConfigChangeError struct {
	Error  string              `json:"error"`
	Change *model.ConfigChange `json:"change,omitempty"`
}

// NotificationError is the body of a failed POST /api/gateway/notification.
type NotificationError = ConfigChangeError

// TrustCertRequest is the optional body of POST /api/gateway/trust-cert (an empty body is the
// same as {}).
type TrustCertRequest struct {
	// SHA256 is the fingerprint of the new certificate as the operator reviewed it (64 hex
	// digits; case, spaces and colons are ignored). It is passed to the monitor, which pins the
	// pending certificate only if it is this one, compared under the monitor's own lock: a
	// confirmation never pins a certificate the operator was not shown, for example one a
	// device presented after the page was loaded. Without it the monitor confirms whatever is
	// pending. The dashboard always sends it, and so does the CLI when it can read the pending
	// fingerprint from the configuration.
	SHA256 string `json:"sha256,omitempty"`
	Client string `json:"client,omitempty"` // "web" or "cli"; default inferred (see clientName); becomes the actor
}

// msgNoPendingCert answers a certificate confirmation when nothing waits to be confirmed.
const msgNoPendingCert = "no changed certificate is pending"

// WarningHeader carries a non-fatal problem of a successful request, e.g. the TSAs that did
// not answer POST /api/anchor while others did.
const WarningHeader = "X-ATT-Monitor-Warning"

// ----------------------------------------------------------------------------- status & series

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if s.status == nil {
		writeError(w, http.StatusServiceUnavailable, "monitor status is not available")
		return
	}
	st := s.status.Status()
	if st.Conditions == nil {
		st.Conditions = []model.Condition{}
	}
	if st.Stats == nil {
		st.Stats = []model.WindowStats{}
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleSeries(w http.ResponseWriter, r *http.Request) {
	if s.status == nil {
		writeError(w, http.StatusServiceUnavailable, "monitor status is not available")
		return
	}
	rng := r.URL.Query().Get("range")
	if rng == "" {
		rng = DefaultSeriesRange
	}
	if !slices.Contains(SeriesRanges, rng) {
		writeError(w, http.StatusBadRequest, "range must be one of "+strings.Join(SeriesRanges, ", "))
		return
	}
	ser, err := s.status.Series(rng)
	if err != nil {
		s.writeErr(w, "series", err)
		return
	}
	if ser.Probes == nil {
		ser.Probes = []model.ProbeSpec{}
	}
	if ser.Points == nil {
		ser.Points = []model.SeriesPoint{}
	}
	if ser.Optical == nil {
		ser.Optical = []model.OpticalPoint{}
	}
	writeJSON(w, http.StatusOK, ser)
}

// ----------------------------------------------------------------------------- incidents

// handleIncidents serves GET /api/incidents?from=&to=[&limit=]: the incidents overlapping
// [from, to), newest first; limit keeps only the newest ones (the dashboard needs a few rows,
// and each incident carries its evidence list).
func (s *Server) handleIncidents(w http.ResponseWriter, r *http.Request) {
	if s.status == nil {
		writeError(w, http.StatusServiceUnavailable, "monitor status is not available")
		return
	}
	q := r.URL.Query()
	from, err := parseTimeParam(q.Get("from"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "from: "+err.Error())
		return
	}
	to, err := parseTimeParam(q.Get("to"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "to: "+err.Error())
		return
	}
	if from.IsZero() {
		from = time.Unix(0, 0).UTC()
	}
	if to.IsZero() {
		to = s.now().UTC().Add(24 * time.Hour) // include open incidents
	}
	if !from.Before(to) {
		writeError(w, http.StatusBadRequest, "from must be before to")
		return
	}
	limit := 0 // all
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		limit = n
	}
	// Copy before sorting: the source may hand out its internal slice.
	list := slices.Clone(s.status.Incidents(from, to))
	sortIncidentsNewestFirst(list)
	if limit > 0 && len(list) > limit {
		list = list[:limit]
	}
	if list == nil {
		list = []model.Incident{}
	}
	writeJSON(w, http.StatusOK, list)
}

// sortIncidentsNewestFirst orders by opening time, newest first (stable for equal or
// unparseable times).
func sortIncidentsNewestFirst(list []model.Incident) {
	key := func(i model.Incident) time.Time {
		t, err := time.Parse(time.RFC3339Nano, i.Opened)
		if err != nil {
			return time.Time{}
		}
		return t
	}
	sort.SliceStable(list, func(a, b int) bool { return key(list[a]).After(key(list[b])) })
}

func (s *Server) handleIncident(w http.ResponseWriter, r *http.Request) {
	if s.status == nil {
		writeError(w, http.StatusServiceUnavailable, "monitor status is not available")
		return
	}
	id := r.PathValue("id")
	if !validIncidentID(id) {
		writeError(w, http.StatusBadRequest, "invalid incident id")
		return
	}
	inc, ok := s.status.Incident(id)
	if !ok {
		writeError(w, http.StatusNotFound, "incident not found")
		return
	}
	seqs, total := incidentSeqs(inc)
	detail := IncidentDetail{Incident: inc, Records: []RecordView{}, Referenced: total}
	if s.reader != nil {
		detail.Truncated = len(seqs) < total
		views, missing, err := s.readRecords(r.Context(), seqs)
		if err != nil {
			s.writeErr(w, "incident", err) // the client went away
			return
		}
		detail.Records = append(detail.Records, views...)
		detail.Missing = missing
	}
	writeJSON(w, http.StatusOK, detail)
}

// incidentSeqs returns the ledger seqs an incident references (first_seq, last_seq and every
// evidence ref), ascending and de-duplicated, together with the number of distinct seqs
// referenced. When that is more than MaxIncidentRecords, first_seq and last_seq are always
// kept and the rest is filled with the earliest and the latest of the other references, so
// that a long incident is still shown from its start to its end.
func incidentSeqs(inc model.Incident) ([]uint64, int) {
	seen := map[uint64]bool{}
	var required, others []uint64
	for _, q := range []uint64{inc.FirstSeq, inc.LastSeq} {
		if q > 0 && !seen[q] {
			seen[q] = true
			required = append(required, q)
		}
	}
	for _, e := range inc.Evidence {
		if !seen[e.Seq] {
			seen[e.Seq] = true
			others = append(others, e.Seq)
		}
	}
	total := len(required) + len(others)
	if total > MaxIncidentRecords {
		slices.Sort(others)
		keep := MaxIncidentRecords - len(required)
		head := (keep + 1) / 2
		others = append(others[:head:head], others[len(others)-(keep-head):]...)
	}
	seqs := append(required, others...)
	slices.Sort(seqs)
	return seqs, total
}

// incidentScanBudget bounds how many ledger records one incident view may scan in total (a
// variable only so that tests can lower it).
var incidentScanBudget = 20_000

// evidenceClusterGap is the largest distance between referenced seqs that one forward scan
// reads through; further apart, a new scan (or a single Record call) costs less.
const evidenceClusterGap = 500

// readRecords reads the records with the given seqs (ascending, unique) and returns them in
// ascending order, together with the seqs that could not be read. Its error is the request
// context's error.
//
// The ledger's Record re-reads a segment from its beginning for every call, so reading the
// few hundred records of a long incident one by one costs seconds of I/O (much more for
// gzip'ed segments), and the dashboard repeats it while the incident is open. Neighbouring
// seqs are therefore read with one forward Scan each, within a total budget; isolated seqs
// and seqs the scans did not reach are read with Record.
func (s *Server) readRecords(ctx context.Context, seqs []uint64) ([]RecordView, []uint64, error) {
	want := make(map[uint64]bool, len(seqs))
	for _, q := range seqs {
		want[q] = true
	}
	found := make(map[uint64]RecordView, len(seqs))
	unreadable := map[uint64]bool{} // passed over by a scan: missing line or one that does not parse
	budget := incidentScanBudget
	for i := 0; i < len(seqs); {
		j := i + 1
		for j < len(seqs) && seqs[j]-seqs[j-1] <= evidenceClusterGap {
			j++
		}
		if j-i > 1 && budget > 0 {
			n, err := s.scanCluster(ctx, seqs[i:j], budget, want, found, unreadable)
			if err != nil {
				return nil, nil, err
			}
			budget -= n
		}
		i = j
	}
	views := make([]RecordView, 0, len(seqs))
	var missing []uint64
	readErrs := 0
	for _, q := range seqs {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		v, ok := found[q]
		if !ok && !unreadable[q] {
			env, body, err := s.reader.Record(q)
			switch {
			case err == nil && body.Seq != q:
				s.log.Warn("web: ledger reader returned the wrong record", "want", q, "got", body.Seq)
			case err == nil:
				v, ok = newRecordView(env, body), true
			case !errors.Is(err, contracts.ErrNotFound):
				if readErrs == 0 { // one damaged segment must not flood the log
					s.log.Warn("web: reading a ledger record failed", "seq", q, "err", err)
				}
				readErrs++
			}
		}
		if ok {
			views = append(views, v)
		} else {
			missing = append(missing, q)
		}
	}
	if readErrs > 1 {
		s.log.Warn("web: more ledger records could not be read", "count", readErrs)
	}
	return views, missing, nil
}

// scanCluster reads the wanted records among the seqs of one cluster with a single forward
// scan that examines at most budget records, and returns how many it examined. Wanted seqs the
// scan passed over without seeing are marked unreadable. A failing scan is logged and leaves
// the cluster to Record; only the context's error is returned.
func (s *Server) scanCluster(ctx context.Context, cluster []uint64, budget int, want map[uint64]bool,
	found map[uint64]RecordView, unreadable map[uint64]bool) (int, error) {
	first, last := cluster[0], cluster[len(cluster)-1]
	n := 0
	var maxSeen uint64
	seen := false
	err := s.reader.Scan(first, func(env model.Envelope, body model.Body) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if body.Seq > last || n >= budget {
			return contracts.ErrStop
		}
		n++
		if !seen || body.Seq > maxSeen {
			maxSeen, seen = body.Seq, true
		}
		if _, dup := found[body.Seq]; want[body.Seq] && !dup {
			found[body.Seq] = newRecordView(env, body)
		}
		return nil
	})
	if err != nil && !errors.Is(err, contracts.ErrStop) {
		if cerr := ctx.Err(); cerr != nil {
			return n, cerr
		}
		s.log.Warn("web: scanning ledger records failed; reading them one by one", "from_seq", first, "err", err)
		return n, nil
	}
	// Scan delivers records in ascending seq order and skips lines it cannot parse, so a
	// wanted seq below the highest seq delivered that was not delivered is unreadable.
	for _, q := range cluster {
		if _, ok := found[q]; !ok && seen && q < maxSeen {
			unreadable[q] = true
		}
	}
	return n, nil
}

// ----------------------------------------------------------------------------- records

// handleRecords serves GET /api/records?from_seq=&limit=&type=[&exclude=]: up to limit
// records with seq >= from_seq, oldest first. type and exclude take comma-separated record
// types. When the scan stopped before the end of the ledger (limit reached or scan budget
// exhausted) the response carries "X-Next-Seq: <seq to continue from>". Integrity problems
// noticed among the records examined (see integrityCheck) are reported in WarningHeader.
func (s *Server) handleRecords(w http.ResponseWriter, r *http.Request) {
	if s.reader == nil {
		writeError(w, http.StatusServiceUnavailable, "ledger reader is not available")
		return
	}
	q := r.URL.Query()
	var fromSeq uint64
	if v := q.Get("from_seq"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "from_seq must be a non-negative integer")
			return
		}
		fromSeq = n
	}
	limit := DefaultRecordLimit
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "limit must be a positive integer (at most 500)")
			return
		}
		limit = min(n, MaxRecordLimit)
	}
	include, err := parseTypeList(q.Get("type"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "type: "+err.Error())
		return
	}
	exclude, err := parseTypeList(q.Get("exclude"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "exclude: "+err.Error())
		return
	}

	ctx := r.Context()
	out := make([]RecordView, 0, min(limit, 64))
	var scanned int
	more := false
	var stopSeq uint64 // seq of the first record not examined (when more)
	chk := integrityCheck{next: fromSeq}
	err = s.reader.Scan(fromSeq, func(env model.Envelope, body model.Body) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(out) >= limit || scanned >= recordScanBudget {
			more, stopSeq = true, body.Seq
			return contracts.ErrStop
		}
		scanned++
		chk.add(body.Seq, env.H, envelopeHashOK(env), body.Prev)
		if (len(include) > 0 && !include[body.Type]) || exclude[body.Type] {
			return nil
		}
		out = append(out, newRecordView(env, body))
		return nil
	})
	if err != nil && !errors.Is(err, contracts.ErrStop) {
		s.writeErr(w, "records", err)
		return
	}
	if more {
		// Continue right after the last record examined rather than at the first one left
		// out, so that the next page also notices a gap just before it; but never beyond the
		// first one left out (a damaged line with a bogus large seq must not end the paging).
		w.Header().Set("X-Next-Seq", strconv.FormatUint(min(chk.next, stopSeq), 10))
	}
	if msg := chk.warning(); msg != "" {
		w.Header().Set(WarningHeader, headerSafe(msg))
	}
	writeJSON(w, http.StatusOK, out)
}

// maxIntegrityProblems bounds the problems listed in one warning header.
const maxIntegrityProblems = 6

// integrityCheck notices, while records are scanned in ascending order, what a raw ledger
// browser must not hide: missing or unreadable lines (gaps in seq: the ledger reader skips
// lines it cannot parse), repeated or out-of-order seqs, lines whose h is not the SHA-256 of
// b, and records whose prev is not the h of the record before. It is no substitute for POST
// /api/verify (signatures, segment hashes, blobs, anchors).
//
// A forward jump in seq is reported as missing records only once the following record
// confirms it; when the following record goes back instead, the line that jumped is the one
// out of place and is reported as such.
type integrityCheck struct {
	next     uint64 // seq expected next
	prevSeq  uint64
	prevHash string
	havePrev bool

	jumped     bool   // the last record skipped ahead of next
	jumpSeq    uint64 // its seq
	beforeJump uint64 // next before it
	ahead      map[uint64]bool

	problems []string
	more     int
}

func (c *integrityCheck) add(seq uint64, hash string, hashOK bool, prev string) {
	if c.jumped {
		c.jumped = false
		if seq < c.jumpSeq {
			c.note(fmt.Sprintf("#%d out of order", c.jumpSeq))
			if c.ahead == nil {
				c.ahead = map[uint64]bool{}
			}
			c.ahead[c.jumpSeq] = true
			c.next = c.beforeJump
		} else {
			c.noteGap(c.beforeJump, c.jumpSeq)
		}
	}
	for c.ahead[c.next] { // already seen, out of place
		delete(c.ahead, c.next)
		c.next++
	}
	switch {
	case seq > c.next:
		c.jumped, c.jumpSeq, c.beforeJump = true, seq, c.next
	case seq < c.next:
		c.note(fmt.Sprintf("#%d repeated or out of order", seq))
	}
	if !hashOK {
		c.note(fmt.Sprintf("#%d h does not match b", seq))
	}
	if c.havePrev && seq == c.prevSeq+1 && prev != c.prevHash {
		c.note(fmt.Sprintf("#%d prev does not match h of #%d", seq, c.prevSeq))
	}
	c.next = max(c.next, seq+1)
	c.prevSeq, c.prevHash, c.havePrev = seq, hash, true
}

// noteGap reports that no readable record with seq in [from, to) was found.
func (c *integrityCheck) noteGap(from, to uint64) {
	if to == from+1 {
		c.note(fmt.Sprintf("#%d missing or unreadable", from))
	} else {
		c.note(fmt.Sprintf("#%d-#%d missing or unreadable", from, to-1))
	}
}

func (c *integrityCheck) note(problem string) {
	if len(c.problems) < maxIntegrityProblems {
		c.problems = append(c.problems, problem)
	} else {
		c.more++
	}
}

// warning returns the problems found as one line, or "". A jump at the end of the records
// examined cannot be confirmed and is reported as a gap.
func (c *integrityCheck) warning() string {
	if c.jumped {
		c.jumped = false
		c.noteGap(c.beforeJump, c.jumpSeq)
	}
	if len(c.problems) == 0 {
		return ""
	}
	msg := "ledger integrity: " + strings.Join(c.problems, "; ")
	if c.more > 0 {
		msg += fmt.Sprintf("; and %d more", c.more)
	}
	return msg + " (run Verify for a full check)"
}

// parseTypeList parses a comma-separated list of record types.
func parseTypeList(v string) (map[string]bool, error) {
	if strings.TrimSpace(v) == "" {
		return nil, nil
	}
	set := map[string]bool{}
	for _, t := range strings.Split(v, ",") {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if !validRecordType(t) {
			return nil, fmt.Errorf("invalid record type %q", truncate(t, 40))
		}
		set[t] = true
	}
	return set, nil
}

func validRecordType(t string) bool {
	if len(t) == 0 || len(t) > 40 {
		return false
	}
	for i := 0; i < len(t); i++ {
		if c := t[i]; !(c >= 'a' && c <= 'z') && c != '_' {
			return false
		}
	}
	return true
}

// envelopeHashOK reports whether env.H is the lowercase hex SHA-256 of the bytes of env.B.
func envelopeHashOK(env model.Envelope) bool {
	sum := sha256.Sum256([]byte(env.B))
	return hex.EncodeToString(sum[:]) == env.H
}

// newRecordView builds the API view of one record. Body is the signed JSON text when it is
// valid JSON (it always is for a verified ledger); otherwise the parsed body is re-encoded so
// that one damaged record cannot break the whole response.
func newRecordView(env model.Envelope, body model.Body) RecordView {
	v := RecordView{Seq: body.Seq, TS: body.TS, Type: body.Type, Hash: env.H, HashOK: envelopeHashOK(env), Envelope: env}
	if json.Valid([]byte(env.B)) {
		v.Body = json.RawMessage(env.B)
	} else if b, err := json.Marshal(body); err == nil {
		v.Body = b
	} else {
		v.Body = json.RawMessage("null")
	}
	return v
}

// ----------------------------------------------------------------------------- blobs

// handleBlob returns the exact bytes of a blob as an attachment. The bytes are re-hashed
// before they are served: a blob whose content does not match its id is never handed out.
func (s *Server) handleBlob(w http.ResponseWriter, r *http.Request) {
	id, b, ok := s.loadBlob(w, r)
	if !ok {
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", `attachment; filename="`+id+`.bin"`)
	h.Set("X-Content-SHA256", id)
	serveContent(w, r, time.Time{}, bytes.NewReader(b))
}

// handleBlobView renders a blob (normally a stored gateway page) as HTML in a sandbox: the
// CSP gives the document an opaque origin, forbids scripts and every network fetch except
// data: images. Gateway pages are Latin-1 (e.g. the 0xA9 copyright byte), hence windows-1252.
func (s *Server) handleBlobView(w http.ResponseWriter, r *http.Request) {
	id, b, ok := s.loadBlob(w, r)
	if !ok {
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=windows-1252")
	h.Set("Content-Security-Policy", sandboxCSP) // replaces the dashboard policy
	h.Set("X-Content-SHA256", id)
	serveContent(w, r, time.Time{}, bytes.NewReader(b))
}

func (s *Server) loadBlob(w http.ResponseWriter, r *http.Request) (string, []byte, bool) {
	id := r.PathValue("id")
	if !validBlobID(id) {
		writeError(w, http.StatusBadRequest, "blob id must be 64 lowercase hex characters (SHA-256)")
		return "", nil, false
	}
	if s.reader == nil {
		writeError(w, http.StatusServiceUnavailable, "ledger reader is not available")
		return "", nil, false
	}
	b, err := s.reader.GetBlob(id)
	if err != nil {
		if errors.Is(err, contracts.ErrNotFound) {
			writeError(w, http.StatusNotFound, "blob not found")
			return "", nil, false
		}
		s.writeErr(w, "blob", err)
		return "", nil, false
	}
	if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != id {
		s.log.Error("web: blob content does not match its id", "blob", id)
		writeError(w, http.StatusInternalServerError, "blob content does not match its SHA-256 id (blob store damaged)")
		return "", nil, false
	}
	return id, b, true
}

// ----------------------------------------------------------------------------- verify

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if s.verifier == nil {
		writeError(w, http.StatusServiceUnavailable, "verification is not available")
		return
	}
	if !s.verifyMu.TryLock() {
		writeError(w, http.StatusConflict, "a verification is already running")
		return
	}
	defer s.verifyMu.Unlock()
	// Read-only: tied to the request, so a closed tab stops the work.
	rep, err := s.verifier.Verify(r.Context())
	if err != nil {
		s.writeErr(w, "verify", err)
		return
	}
	if rep.Segments == nil {
		rep.Segments = []string{}
	}
	if rep.TypeCounts == nil {
		rep.TypeCounts = map[string]int{}
	}
	if rep.Failures == nil {
		rep.Failures = []model.VerifyFailure{}
	}
	if rep.Anchors == nil {
		rep.Anchors = []model.AnchorCheck{}
	}
	if rep.Gaps == nil {
		rep.Gaps = []model.Gap{}
	}
	writeJSON(w, http.StatusOK, rep)
}

// ----------------------------------------------------------------------------- exports

func (s *Server) handleExportList(w http.ResponseWriter, r *http.Request) {
	if s.exporter == nil {
		writeError(w, http.StatusServiceUnavailable, "evidence export is not available")
		return
	}
	list, err := s.exporter.List()
	if err != nil {
		s.writeErr(w, "export list", err)
		return
	}
	list = slices.Clone(list)
	sort.SliceStable(list, func(a, b int) bool { return list[a].Created.After(list[b].Created) })
	if list == nil {
		list = []contracts.ExportInfo{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleExportCreate(w http.ResponseWriter, r *http.Request) {
	if s.exporter == nil {
		writeError(w, http.StatusServiceUnavailable, "evidence export is not available")
		return
	}
	var req ExportCreateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	from, err := parseTimeParam(req.From)
	if err != nil {
		writeError(w, http.StatusBadRequest, "from: "+err.Error())
		return
	}
	to, err := parseTimeParam(req.To)
	if err != nil {
		writeError(w, http.StatusBadRequest, "to: "+err.Error())
		return
	}
	incident := strings.TrimSpace(req.IncidentID)
	if incident != "" && !validIncidentID(incident) {
		writeError(w, http.StatusBadRequest, "invalid incident_id")
		return
	}
	if incident == "" && (from.IsZero() || to.IsZero()) {
		writeError(w, http.StatusBadRequest, "from and to are required unless incident_id is given")
		return
	}
	if !from.IsZero() && !to.IsZero() && !from.Before(to) {
		writeError(w, http.StatusBadRequest, "from must be before to")
		return
	}
	preparedBy := strings.TrimSpace(req.PreparedBy)
	if err := checkText(preparedBy, MaxNameChars, false); err != nil {
		writeError(w, http.StatusBadRequest, "prepared_by "+err.Error())
		return
	}
	notes := strings.TrimSpace(req.Notes)
	if err := checkText(notes, MaxNoteChars, true); err != nil {
		writeError(w, http.StatusBadRequest, "notes "+err.Error())
		return
	}
	client, ok := clientName(req.Client, r)
	if !ok {
		writeError(w, http.StatusBadRequest, `client must be "web" or "cli"`)
		return
	}
	if !s.exportMu.TryLock() {
		writeError(w, http.StatusConflict, "an export is already being built")
		return
	}
	defer s.exportMu.Unlock()

	ctx, cancel := s.detached(r, exportTimeout)
	defer cancel()
	info, err := s.exporter.Build(ctx, contracts.ExportRequest{
		From:       from,
		To:         to,
		IncidentID: incident,
		PreparedBy: preparedBy,
		Notes:      notes,
		Requester:  client + " " + remoteIP(r),
	})
	if err != nil {
		s.writeErr(w, "export", err)
		return
	}
	if validExportName(info.FileName) {
		w.Header().Set("Location", "/api/exports/"+url.PathEscape(info.FileName))
	}
	writeJSON(w, http.StatusCreated, info)
}

func (s *Server) handleExportDownload(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !validExportName(name) {
		writeError(w, http.StatusBadRequest, "invalid export name")
		return
	}
	if s.exporter == nil {
		writeError(w, http.StatusServiceUnavailable, "evidence export is not available")
		return
	}
	rc, info, err := s.exporter.Open(name)
	if err != nil {
		if errors.Is(err, contracts.ErrNotFound) {
			writeError(w, http.StatusNotFound, "export not found")
			return
		}
		s.writeErr(w, "export download", err)
		return
	}
	defer rc.Close()
	h := w.Header()
	h.Set("Content-Type", "application/zip")
	h.Set("Content-Disposition", `attachment; filename="`+name+`"`)
	if validBlobID(info.SHA256) {
		h.Set("X-Content-SHA256", info.SHA256)
	}
	if rs, ok := rc.(io.ReadSeeker); ok {
		serveContent(w, r, info.Created, rs)
		return
	}
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	if _, err := io.Copy(w, rc); err != nil {
		s.log.Warn("web: export download interrupted", "name", name, "err", err)
	}
}

// ----------------------------------------------------------------------------- notes

func (s *Server) handleNote(w http.ResponseWriter, r *http.Request) {
	if s.actions == nil {
		writeError(w, http.StatusServiceUnavailable, "the monitor is not running; notes cannot be recorded")
		return
	}
	var req NoteRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	text := strings.TrimSpace(req.Text)
	if text == "" {
		writeError(w, http.StatusBadRequest, "text is required")
		return
	}
	if err := checkText(text, MaxNoteChars, true); err != nil {
		writeError(w, http.StatusBadRequest, "text "+err.Error())
		return
	}
	author := strings.TrimSpace(req.Author)
	if err := checkText(author, MaxNameChars, false); err != nil {
		writeError(w, http.StatusBadRequest, "author "+err.Error())
		return
	}
	source, ok := clientName(req.Client, r)
	if !ok {
		writeError(w, http.StatusBadRequest, `client must be "web" or "cli"`)
		return
	}
	ctx, cancel := s.detached(r, noteTimeout)
	defer cancel()
	ref, err := s.actions.Note(ctx, text, author, source)
	if err != nil {
		s.writeErr(w, "note", err)
		return
	}
	writeJSON(w, http.StatusCreated, ref)
}

// ----------------------------------------------------------------------------- gateway

func (s *Server) handleNotification(w http.ResponseWriter, r *http.Request) {
	if s.actions == nil {
		writeError(w, http.StatusServiceUnavailable, "the monitor is not running; the gateway setting cannot be changed from here")
		return
	}
	var req NotificationRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Enabled == nil {
		writeError(w, http.StatusBadRequest, "enabled (true or false) is required")
		return
	}
	client, ok := clientName(req.Client, r)
	if !ok {
		writeError(w, http.StatusBadRequest, `client must be "web" or "cli"`)
		return
	}
	if !s.gatewayMu.TryLock() {
		writeError(w, http.StatusConflict, msgGatewayBusy)
		return
	}
	defer s.gatewayMu.Unlock()

	ctx, cancel := s.detached(r, notificationTimeout)
	defer cancel()
	change, err := s.actions.SetGatewayNotification(ctx, *req.Enabled, "operator via "+client)
	if err != nil {
		s.log.Warn("web: gateway notification change failed", "enabled", *req.Enabled, "result", change.Result, "err", err)
		code, retryAfter, resp := gatewayChangeError("gateway setting change", change, err)
		writeRetryAfter(w, retryAfter)
		writeJSON(w, code, resp)
		return
	}
	writeJSON(w, http.StatusOK, change)
}

// msgGatewayBusy refuses an operator action on the gateway's authenticated side while another
// one runs (gatewayMu).
const msgGatewayBusy = "a gateway setting change or certificate confirmation is already in progress"

// gatewayChangeError maps a failed change of a gateway setting (POST /api/gateway/notification,
// POST /api/gateway/syslog) to a status, a Retry-After (0: none) and the answer, which carries
// the change the monitor reported, if any: 502 by default (the gateway failed); 500 when the
// change says that the gateway took it ("verified" or "applied") or already showed it
// ("unchanged: ...") and what failed came after, on this PC (e.g. writing a record, saving the
// configuration) - 502 would blame the gateway, and a client would wrongly report the setting
// as not made; otherwise the contracts' sentinels as classifyErr maps them (op names the
// operation in their messages).
func gatewayChangeError(op string, change model.ConfigChange, err error) (int, time.Duration, ConfigChangeError) {
	resp := ConfigChangeError{Error: err.Error()}
	if change != (model.ConfigChange{}) {
		resp.Change = &change
	}
	code, retryAfter := http.StatusBadGateway, time.Duration(0)
	switch c, known := classifyErr(op, err); {
	case strings.HasPrefix(strings.ToLower(strings.TrimSpace(change.Result)), "unchanged"):
		code = http.StatusInternalServerError
		resp.Error = "the gateway's setting is already as asked (" + change.Result +
			"), but the change could not be completed: " + err.Error()
	case gatewayChangeReported(change.Result):
		code = http.StatusInternalServerError
		resp.Error = "the gateway reports the setting as changed (" + change.Result +
			"), but the change could not be completed: " + err.Error()
	case known:
		code, retryAfter, resp.Error = c.code, c.retryAfter, c.msg
	}
	return code, retryAfter, resp
}

// handleTrustCert serves POST /api/gateway/trust-cert: the operator confirms the changed TLS
// certificate the gateway presents (condition GATEWAY_CERT_CHANGED), which becomes the pin;
// the monitor records a config_change and resumes authenticated gateway requests.
//
// The fingerprint the operator reviewed (TrustCertRequest.SHA256) goes to the monitor, which
// compares it with the pending certificate under its own lock and refuses a mismatch with an
// error wrapping contracts.ErrBusy (409). Before that, the monitor's certificate state
// (Status.GatewayCert) answers the plain cases without asking the monitor to change anything:
// nothing pending (404) and another certificate pending (409).
func (s *Server) handleTrustCert(w http.ResponseWriter, r *http.Request) {
	if s.actions == nil {
		writeError(w, http.StatusServiceUnavailable, "the monitor is not running; the gateway certificate cannot be confirmed from here")
		return
	}
	var req TrustCertRequest
	if !decodeOptionalJSON(w, r, &req) {
		return
	}
	// Anything but white space must be a fingerprint: separators alone (":::") must not turn
	// into "no fingerprint", which would confirm whatever is pending.
	expected := normalizeFingerprint(req.SHA256)
	if strings.TrimSpace(req.SHA256) != "" && !validBlobID(expected) {
		writeError(w, http.StatusBadRequest, "sha256 must be the certificate's SHA-256 fingerprint (64 hex digits)")
		return
	}
	client, ok := clientName(req.Client, r)
	if !ok {
		writeError(w, http.StatusBadRequest, `client must be "web" or "cli"`)
		return
	}
	if !s.gatewayMu.TryLock() {
		writeError(w, http.StatusConflict, msgGatewayBusy)
		return
	}
	defer s.gatewayMu.Unlock()

	if pending, known := s.pendingCert(); known {
		switch {
		case pending == "":
			writeError(w, http.StatusNotFound, msgNoPendingCert)
			return
		case expected != "" && pending != expected:
			s.log.Warn("web: gateway certificate confirmation refused: another certificate is pending",
				"reviewed", expected, "pending", pending)
			writeError(w, http.StatusConflict, certMismatchMsg(pending, expected))
			return
		}
	}

	ctx, cancel := s.detached(r, trustCertTimeout)
	defer cancel()
	change, err := s.actions.TrustCert(ctx, "operator via "+client, expected)
	trusted := err == nil || gatewayChangeReported(change.Result)
	if trusted && expected != "" && normalizeFingerprint(change.After) != expected {
		// Defence in depth: the monitor reports a certificate as trusted that is not the one the
		// operator reviewed, although it compares the two under its own lock (a defect of the
		// monitor). Nothing here can undo a confirmation, so say so plainly.
		s.log.Error("web: the monitor reports another gateway certificate as trusted than the one the operator confirmed",
			"confirmed", expected, "trusted", change.After, "result", change.Result, "err", err)
		writeJSON(w, http.StatusConflict, ConfigChangeError{Change: &change, Error: wrongCertMsg(change, expected, err)})
		return
	}
	if err != nil {
		s.log.Warn("web: gateway certificate confirmation failed", "result", change.Result, "err", err)
		code, retryAfter, msg := s.trustCertError(expected, change, err)
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

// trustCertError maps a failed confirmation to a status and a message for the operator.
func (s *Server) trustCertError(expected string, change model.ConfigChange, err error) (int, time.Duration, string) {
	const op = "gateway certificate confirmation"
	c, known := classifyErr(op, err)
	switch {
	case errors.Is(err, contracts.ErrNotRecorded):
		return c.code, c.retryAfter, c.msg
	case errors.Is(err, contracts.ErrNotFound):
		return http.StatusNotFound, 0, msgNoPendingCert
	case gatewayChangeReported(change.Result):
		// The monitor pinned the certificate (and recorded it) but something after that failed,
		// e.g. saving the configuration.
		return http.StatusInternalServerError, 0, "the new gateway certificate is trusted (" + change.Result + "), but: " + err.Error()
	case expected != "" && errors.Is(err, contracts.ErrBusy):
		if msg, refused := s.certRefusedMsg(expected, err); refused {
			return http.StatusConflict, 0, msg
		}
	}
	switch {
	case known:
		return c.code, c.retryAfter, c.msg
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout, 0, op + ": operation timed out"
	case errors.Is(err, context.Canceled):
		return http.StatusServiceUnavailable, 0, op + ": cancelled"
	}
	return http.StatusInternalServerError, 0, op + ": " + err.Error()
}

// pendingCert returns the changed gateway certificate waiting for the operator's confirmation
// as the monitor reports it (Status.GatewayCert): its normalized fingerprint, "" when nothing
// is pending. known is false when the status does not say (no status source, or a status
// without GatewayCert); the monitor then decides alone.
func (s *Server) pendingCert() (fp string, known bool) {
	if s.status == nil {
		return "", false
	}
	gc := s.status.Status().GatewayCert
	if gc == nil {
		return "", false
	}
	return normalizeFingerprint(gc.Pending), true
}

// certMismatchMsg refuses the confirmation of expected while pending waits for confirmation.
func certMismatchMsg(pending, expected string) string {
	return fmt.Sprintf("the certificate was not confirmed: the gateway certificate waiting for confirmation is now SHA-256 %s, "+
		"not the one you reviewed (%s). Review the new fingerprint, and confirm it only if you recognise it", pending, expected)
}

// certRefusedMsg words the monitor's refusal to trust expected: it compares the reviewed
// fingerprint with the pending certificate under its own lock and refuses a mismatch with an
// error wrapping contracts.ErrBusy, whose own text ("busy: ...") would mislead the operator.
// The answer names the certificate waiting now when the status says which. refused is false
// when the status shows the reviewed certificate still waiting: then the monitor was busy with
// something else, and its own words apply.
func (s *Server) certRefusedMsg(expected string, err error) (msg string, refused bool) {
	pending, known := s.pendingCert()
	switch {
	case known && pending == expected:
		return "", false
	case known && pending != "":
		return certMismatchMsg(pending, expected), true
	}
	return "the certificate was not confirmed: the monitor reports that the gateway certificate waiting for confirmation is not the one " +
		"you reviewed (SHA-256 " + expected + "). Reload the page and review the certificate again. Details: " + err.Error(), true
}

// wrongCertMsg reports a confirmation that the monitor completed for something else than the
// certificate the operator reviewed (expected); err is what else failed, if anything.
func wrongCertMsg(change model.ConfigChange, expected string, err error) string {
	var msg string
	if after := strings.TrimSpace(change.After); after == "" {
		msg = "the monitor reports a gateway certificate as trusted (" + change.Result + ") but not which one, so it cannot be shown to be " +
			"the one you reviewed (SHA-256 " + expected + "). Check the pinned certificate on the Gateway page; if you do not recognise it, " +
			"stop att-monitor before it next logs in to the gateway"
	} else {
		msg = "a different certificate was trusted than the one you reviewed: SHA-256 " + after + " instead of " + expected +
			". If you do not recognise it, stop att-monitor before it next logs in to the gateway and check which device answers at the gateway's address"
	}
	if err != nil {
		msg += ". In addition: " + err.Error()
	}
	return msg
}

// normalizeFingerprint lower-cases a SHA-256 fingerprint and removes the separators people
// copy along with it ("49:CD:...", "49cd 292d ...").
func normalizeFingerprint(v string) string {
	return strings.ToLower(strings.NewReplacer(":", "", " ", "", "\t", "").Replace(strings.TrimSpace(v)))
}

// gatewayChangeReported reports whether a config_change result says that the gateway took
// the change ("verified", "applied", possibly followed by notes) or already showed it
// ("unchanged: ...") rather than "failed: ...".
func gatewayChangeReported(result string) bool {
	r := strings.ToLower(strings.TrimSpace(result))
	return r != "" && !strings.HasPrefix(r, "failed")
}

// ----------------------------------------------------------------------------- anchor

func (s *Server) handleAnchor(w http.ResponseWriter, r *http.Request) {
	if s.actions == nil {
		writeError(w, http.StatusServiceUnavailable, "the monitor is not running; cannot anchor")
		return
	}
	if !s.anchorMu.TryLock() {
		writeError(w, http.StatusConflict, "an anchor request is already running")
		return
	}
	defer s.anchorMu.Unlock()
	ctx, cancel := s.detached(r, anchorTimeout)
	defer cancel()
	anchors, err := s.actions.AnchorNow(ctx, "manual")
	if anchors == nil {
		anchors = []model.Anchor{}
	}
	if err != nil {
		s.log.Warn("web: anchor request failed", "anchors", len(anchors), "err", err)
		if len(anchors) == 0 {
			if c, known := classifyErr("anchor", err); known {
				writeClassified(w, c)
				return
			}
			writeError(w, http.StatusBadGateway, "anchor: "+err.Error())
			return
		}
		w.Header().Set(WarningHeader, headerSafe(err.Error()))
	}
	writeJSON(w, http.StatusOK, anchors)
}

// headerSafe reduces s to printable ASCII so that it can travel in a response header.
func headerSafe(s string) string {
	b := make([]byte, 0, min(len(s), 512))
	for _, c := range s {
		if len(b) >= 512 {
			break
		}
		if c >= 0x20 && c < 0x7f {
			b = append(b, byte(c))
		} else {
			b = append(b, '?')
		}
	}
	return string(b)
}

// ----------------------------------------------------------------------------- helpers

// detached returns a context for an operator action that must not be interrupted by the
// browser going away; it ends after d or when the server shuts down.
func (s *Server) detached(r *http.Request, d time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), d)
	if rc := s.runCtx.Load(); rc != nil {
		stop := context.AfterFunc(*rc, cancel)
		return ctx, func() { stop(); cancel() }
	}
	return ctx, cancel
}

// errorClass is how a well-known error is answered.
type errorClass struct {
	code       int
	msg        string
	retryAfter time.Duration // 0 = no Retry-After header
	warn       bool          // log at Warn level even though the status is an expected one (503)
}

// Operator-facing explanations of the gateway errors (contracts.ErrGateway*).
const (
	msgCertRejected = "confirm the gateway certificate first: the AT&T gateway presented a TLS certificate that is not the pinned one, " +
		"so att-monitor did not log in (the access code is never sent to an unconfirmed device). Review the new certificate on the " +
		"dashboard and trust it only if AT&T updated or replaced your gateway"
	msgSessionsFull = "the AT&T gateway reports that all of its web sessions are in use (someone may be logged in to its web pages); " +
		"att-monitor waits at least 5 minutes before logging in again"
	msgAuthLocked = "gateway logins are paused after repeated rejected access codes (at most 3 attempts per hour, so the gateway " +
		"never locks itself); check the stored access code (att-monitor set-access-code). Logins resume automatically later"
	msgLoginThrottled = "a gateway login was attempted less than a minute ago and att-monitor allows at most one per minute; try again in a minute"
	msgAuthRejected   = "the AT&T gateway rejected the stored device access code; check the code on the gateway's label and store it " +
		"again with att-monitor set-access-code"
	msgNoAccessCode = "no gateway device access code is stored, so att-monitor cannot log in to the gateway; store it with " +
		"att-monitor set-access-code (the code is printed on the gateway's label)"
	msgLedgerBroken = "the evidence ledger refuses every record after a failed write, so nothing can be recorded until att-monitor " +
		"restarts and reopens it with its crash recovery (the service stops so that Windows restarts it); try again in a minute"
)

// classifyErr maps the well-known errors of the contracts (matched with errors.Is, so wrapped
// errors are recognised) to a status and a message (docs/DESIGN.md §12). known is false for
// any other error. The order matters when an error wraps several sentinels: "applied but not
// recorded" is reported before anything else, because a client must never conclude from it
// that nothing happened.
func classifyErr(op string, err error) (c errorClass, known bool) {
	detail := ". Details: " + err.Error()
	switch {
	case errors.Is(err, contracts.ErrNotRecorded):
		return errorClass{code: http.StatusInternalServerError,
			msg: "applied but could not be recorded (" + op + "): the change took effect, but its evidence ledger record could not be written: " + err.Error()}, true
	case errors.Is(err, contracts.ErrLedgerBroken):
		// Unavailable until the monitor restarts (a state of this PC, not of the request).
		return errorClass{code: http.StatusServiceUnavailable, msg: op + ": " + msgLedgerBroken + detail, warn: true}, true
	case errors.Is(err, contracts.ErrGatewayCertRejected):
		return errorClass{code: http.StatusConflict, msg: msgCertRejected + detail}, true
	case errors.Is(err, contracts.ErrGatewaySessionsFull):
		return errorClass{code: http.StatusServiceUnavailable, msg: op + ": " + msgSessionsFull + detail, retryAfter: 5 * time.Minute}, true
	case errors.Is(err, contracts.ErrGatewayAuthLocked):
		return errorClass{code: http.StatusServiceUnavailable, msg: op + ": " + msgAuthLocked + detail}, true
	case errors.Is(err, contracts.ErrGatewayLoginThrottled):
		return errorClass{code: http.StatusServiceUnavailable, msg: op + ": " + msgLoginThrottled + detail, retryAfter: time.Minute}, true
	case errors.Is(err, contracts.ErrGatewayAuth):
		return errorClass{code: http.StatusBadGateway, msg: op + ": " + msgAuthRejected + detail}, true
	case errors.Is(err, contracts.ErrGatewayNoAccessCode):
		return errorClass{code: http.StatusServiceUnavailable, msg: op + ": " + msgNoAccessCode + detail}, true
	case errors.Is(err, contracts.ErrBusy):
		return errorClass{code: http.StatusConflict, msg: op + ": " + err.Error()}, true
	case errors.Is(err, contracts.ErrRateLimited):
		return errorClass{code: http.StatusTooManyRequests, msg: op + ": " + err.Error()}, true
	case errors.Is(err, contracts.ErrUnavailable):
		return errorClass{code: http.StatusServiceUnavailable, msg: op + ": " + err.Error()}, true
	}
	return errorClass{}, false
}

// writeClassified writes the response for a classified error.
func writeClassified(w http.ResponseWriter, c errorClass) {
	writeRetryAfter(w, c.retryAfter)
	writeError(w, c.code, c.msg)
}

// writeRetryAfter sets Retry-After (whole seconds) when d > 0.
func writeRetryAfter(w http.ResponseWriter, d time.Duration) {
	if d > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(d/time.Second)))
	}
}

// writeErr maps an error from a dependency to an HTTP status.
func (s *Server) writeErr(w http.ResponseWriter, op string, err error) {
	if c, known := classifyErr(op, err); known {
		level := slog.LevelInfo // an expected state (busy, paused, not configured, ...)
		if c.warn || c.code == http.StatusInternalServerError || c.code == http.StatusBadGateway {
			level = slog.LevelWarn
		}
		s.log.Log(context.Background(), level, "web: request failed", "op", op, "status", c.code, "err", err)
		writeClassified(w, c)
		return
	}
	switch {
	case errors.Is(err, contracts.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, context.DeadlineExceeded):
		writeError(w, http.StatusGatewayTimeout, op+": operation timed out")
	case errors.Is(err, context.Canceled):
		writeError(w, http.StatusServiceUnavailable, op+": cancelled")
	default:
		s.log.Warn("web: request failed", "op", op, "err", err)
		writeError(w, http.StatusInternalServerError, op+": "+err.Error())
	}
}

// writeJSON writes v as a JSON response. The body is encoded before anything is written so
// that an encoding failure still produces a well-formed error response.
func writeJSON(w http.ResponseWriter, code int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		code = http.StatusInternalServerError
		b = []byte(`{"error":"internal error: response could not be encoded"}`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	w.Write(append(b, '\n'))
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, ErrorResponse{Error: msg})
}

// decodeJSON decodes a request body that must be exactly one JSON object with known fields.
// On failure it writes the error response and returns false.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	return decodeBody(w, r, dst, false)
}

// decodeOptionalJSON is decodeJSON for a body that may be left out: an empty body (or one of
// only white space) leaves dst as it is.
func decodeOptionalJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	return decodeBody(w, r, dst, true)
}

func decodeBody(w http.ResponseWriter, r *http.Request, dst any, optional bool) bool {
	if ct := r.Header.Get("Content-Type"); ct != "" {
		mt, _, err := mime.ParseMediaType(ct)
		if err != nil || mt != "application/json" {
			writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
			return false
		}
	}
	body, err := io.ReadAll(r.Body) // bounded by the middleware's MaxBytesReader
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large (limit 1 MiB)")
		} else {
			writeError(w, http.StatusBadRequest, "reading request body: "+err.Error())
		}
		return false
	}
	if optional && len(bytes.TrimSpace(body)) == 0 {
		return true
	}
	// encoding/json would silently replace invalid UTF-8 with U+FFFD; operator text that
	// goes into the evidence ledger must be recorded exactly as sent, or rejected.
	if !utf8.Valid(body) {
		writeError(w, http.StatusBadRequest, "request body must be valid UTF-8")
		return false
	}
	// Likewise an unpaired UTF-16 surrogate escape would silently become U+FFFD.
	if !validJSONEscapes(body) {
		writeError(w, http.StatusBadRequest, "request body contains an unpaired UTF-16 surrogate escape (U+D800 to U+DFFF)")
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, "request body must be a JSON object")
		} else {
			writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		}
		return false
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "request body must contain exactly one JSON object")
		return false
	}
	return true
}

// backslash is the JSON escape character.
const backslash = 0x5c

// validJSONEscapes reports whether every backslash-u escape of a UTF-16 surrogate in the JSON
// text b belongs to a high+low pair; encoding/json silently decodes an unpaired surrogate to
// U+FFFD. Outside strings a backslash is a syntax error and inside a string every backslash
// starts an escape, so escapes are found without tracking string boundaries. Malformed escapes
// are left to the JSON decoder, which rejects them.
func validJSONEscapes(b []byte) bool {
	for i := 0; i < len(b); i++ {
		if b[i] != backslash {
			continue
		}
		if i+1 >= len(b) || b[i+1] != 'u' {
			i++ // a two-character escape such as a quote or a backslash
			continue
		}
		r, ok := hex4(b, i+2)
		if !ok {
			return true
		}
		i += 5 // last hex digit
		switch {
		case r >= 0xDC00 && r <= 0xDFFF:
			return false // low surrogate without a high one
		case r >= 0xD800 && r <= 0xDBFF:
			if i+2 >= len(b) || b[i+1] != backslash || b[i+2] != 'u' {
				return false // high surrogate without a low one
			}
			lo, ok := hex4(b, i+3)
			if !ok {
				return true
			}
			if lo < 0xDC00 || lo > 0xDFFF {
				return false
			}
			i += 6
		}
	}
	return true
}

// hex4 parses the four hex digits at b[i:i+4].
func hex4(b []byte, i int) (rune, bool) {
	if i+4 > len(b) {
		return 0, false
	}
	var r rune
	for _, c := range b[i : i+4] {
		var d byte
		switch {
		case c >= '0' && c <= '9':
			d = c - '0'
		case c >= 'a' && c <= 'f':
			d = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			d = c - 'A' + 10
		default:
			return 0, false
		}
		r = r<<4 | rune(d)
	}
	return r, true
}

// parseTimeParam accepts "" (zero time), RFC 3339 (optionally without seconds),
// YYYY-MM-DD (UTC midnight) or Unix seconds.
func parseTimeParam(v string) (time.Time, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, nil
	}
	if isDigits(v) && len(v) <= 12 {
		n, err := strconv.ParseInt(v, 10, 64)
		if err == nil {
			return time.Unix(n, 0).UTC(), nil
		}
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04Z07:00"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC(), nil
		}
	}
	if t, err := time.Parse("2006-01-02", v); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("invalid time %q: use RFC 3339 (e.g. 2026-10-05T03:20:00Z) or YYYY-MM-DD (UTC)", truncate(v, 40))
}

func isDigits(v string) bool {
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return false
		}
	}
	return true
}

// checkText validates operator-supplied text that goes into the evidence ledger: valid
// UTF-8, bounded, no control characters (newlines/tabs only when multiline) and no Unicode
// bidirectional overrides, which could make a note display differently from what it says.
func checkText(v string, maxChars int, multiline bool) error {
	if !utf8.ValidString(v) {
		return errors.New("must be valid UTF-8")
	}
	if n := utf8.RuneCountInString(v); n > maxChars {
		return fmt.Errorf("must be at most %d characters (got %d)", maxChars, n)
	}
	for _, c := range v {
		switch {
		case c == '\t':
		case c == '\n' || c == '\r':
			if !multiline {
				return errors.New("must be a single line")
			}
		case unicode.IsControl(c), c == 0x2028, c == 0x2029: // line and paragraph separators
			return errors.New("must not contain control characters")
		case c >= 0x202A && c <= 0x202E, c >= 0x2066 && c <= 0x2069: // embeddings, overrides, isolates
			return errors.New("must not contain bidirectional override characters")
		}
	}
	return nil
}

// clientName maps the optional "client" field to the recorded source ("web" or "cli").
// When the field is absent the client is inferred: browsers always send Origin (or
// Sec-Fetch-Site) with a POST, the att-monitor CLI and other API clients do not.
func clientName(v string, r *http.Request) (string, bool) {
	switch strings.TrimSpace(v) {
	case "web":
		return "web", true
	case "cli":
		return "cli", true
	case "":
		if r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Site") != "" {
			return "web", true
		}
		return "cli", true
	}
	return "", false
}

// validBlobID reports whether id is a lowercase hex SHA-256.
func validBlobID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		if c := id[i]; !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// validIncidentID accepts the INC-YYYYMMDD-HHMMSSZ ids (and any future suffix) while
// rejecting anything that is not a short token of [A-Za-z0-9._-].
func validIncidentID(id string) bool {
	if len(id) == 0 || len(id) > 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		alnum := c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		if !alnum && (i == 0 || (c != '.' && c != '_' && c != '-')) {
			return false
		}
	}
	return true
}

// windowsReserved are device names that Windows resolves regardless of extension.
var windowsReserved = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true, "CONIN$": true, "CONOUT$": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true, "COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true, "LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

// validExportName accepts plain bundle file names only: [A-Za-z0-9._+-], ending in .zip,
// no path separators, no "..", no leading dot, not a Windows device name.
func validExportName(name string) bool {
	if len(name) <= len(".zip") || len(name) > 200 || !strings.HasSuffix(name, ".zip") {
		return false
	}
	if name[0] == '.' || name[0] == '-' || strings.Contains(name, "..") {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		ok := c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '.' || c == '_' || c == '-' || c == '+'
		if !ok {
			return false // rejects '/', '\\', ':', spaces, NUL, %, ...
		}
	}
	base, _, _ := strings.Cut(name, ".")
	return !windowsReserved[strings.ToUpper(base)]
}

// remoteIP returns the client IP of r (always loopback for this server).
func remoteIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func truncate(v string, n int) string {
	if len(v) <= n {
		return v
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(v[cut]) {
		cut--
	}
	return v[:cut] + "…"
}
