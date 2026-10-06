package web

// GET /api/syslog and POST /api/syslog/retention (docs/syslog-snmp-traffic.md §3.2): the
// messages of the syslog store in a period, filtered, newest first, each linked to the
// syslog_chunk record of its chunk (found through the ledger reader in bounded work); and the
// operator's choice of how much of it to keep.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// syslogNow is the harness's clock (newHarness).
var syslogNow = time.Date(2026, 10, 5, 3, 20, 0, 0, time.UTC)

// replacementChars is what a parser makes of two bytes that are not UTF-8 (two U+FFFD).
var replacementChars = strings.Repeat(string(rune(0xFFFD)), 2)

// sysMsg is a message as the receiver keeps it: an RFC 3164 datagram from the gateway with
// facility local0 and the given severity, or (sev < 0) a datagram without a PRI that was not
// parsed, kept as its raw text only.
func sysMsg(rx time.Time, sev int, host, app, text string) model.SyslogMessage {
	m := model.SyslogMessage{RX: rx.UTC().Format(time.RFC3339Nano), Src: "192.168.1.254:514", Format: "unknown", Raw: text}
	if sev < 0 {
		return m
	}
	pri, fac := 16*8+sev, 16
	m.Format, m.PRI, m.Facility, m.Severity = "rfc3164", &pri, &fac, &sev
	m.TS = rx.Format(time.Stamp)
	m.Host, m.App, m.Msg = host, app, text
	m.Raw = fmt.Sprintf("<%d>%s %s %s: %s", pri, m.TS, host, app, text)
	return m
}

// appendRecord seals a record of the given type and data onto the fake ledger (chained, seq
// = position) and returns its seq.
func appendRecord(r *fakeReader, ts time.Time, typ string, data any) uint64 {
	raw, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	seq := uint64(len(r.envs))
	prev := model.ZeroHash
	if seq > 0 {
		prev = r.envs[seq-1].H
	}
	body := model.Body{V: model.FormatVersion, Seq: seq, Prev: prev, TS: ts.UTC().Format(time.RFC3339Nano),
		Mono: int64(seq) * int64(time.Second), Run: strings.Repeat("0f", 16), Type: typ, Data: raw}
	env := sealRecord(testKey, body)
	r.envs = append(r.envs, env)
	r.bodies = append(r.bodies, body)
	return seq
}

// chunkRecord records the sealing of chunk c at ts (a syslog_chunk record) and returns its seq.
func appendChunkRecord(r *fakeReader, ts time.Time, c *fakeChunk) uint64 {
	first, last := c.msgs[0].RX, c.msgs[len(c.msgs)-1].RX
	return appendRecord(r, ts, model.TypeSyslogChunk, model.SyslogChunk{Name: c.name, From: first, To: last,
		Messages: len(c.msgs), Bytes: int64(100 * len(c.msgs)), SHA256: strings.Repeat("5a", 32), GzBytes: int64(40 * len(c.msgs)), Reason: "age"})
}

// syslogWorld is the store and the ledger most tests read (n = syslogNow; m0..m11 name the
// messages; # the ledger records):
//
//	chunk c0 (sealed)  m0 n-30h                                             #1 at n-30h+5m
//	chunk c1 (sealed)  m1 n-2h-20s (info, dhcpd), m2 -10s (err, ponlinkd),
//	                   m3 -5s (no PRI)                                      #2 at n-2h+4m
//	                                                                        #3 sample n-90m
//	chunk c2 (sealed)  m4 n-1h-5s (warning, wanmgr), m6 -3s (not UTF-8: bytes only, no PRI),
//	                   m5 -1s (emerg, kernel)                               #4 at n-1h+4m
//	chunk c3 (sealed)  m7 n-30m-3s (debug, cwmpd), m8 -2s (info, ntpd),
//	                   m9 -1s (notice, RFC 5424)                            #5 at n-25m
//	                                                                        #6 sample n-20m
//	chunk c4 (open)    m10 n-10s (info), m11 n (at "to": outside the default period)
func syslogWorld() (*fakeSyslogStore, *fakeReader) {
	n := syslogNow
	m6 := model.SyslogMessage{RX: n.Add(-time.Hour - 3*time.Second).Format(time.RFC3339Nano), Src: "192.168.1.254:514",
		RawB64: "PDMwPndpZmlkOiBTU0lEIP/+", Format: "unknown", App: "wifid", Msg: "[m6] SSID " + replacementChars}
	m9 := sysMsg(n.Add(-30*time.Minute-time.Second), 5, "BGW320-505.attlocal.net", "TR069", "[m9] Periodic Inform")
	m9.Format, m9.TS = "rfc5424", n.Add(-30*time.Minute-time.Second).Format(time.RFC3339Nano)
	m9.Raw = "<133>1 " + m9.TS + " BGW320-505.attlocal.net TR069 - - - [m9] Periodic Inform"
	store := &fakeSyslogStore{chunks: []*fakeChunk{
		{name: "c0", sealed: true, msgs: []model.SyslogMessage{sysMsg(n.Add(-30*time.Hour), 6, "BGW320", "syslogd", "[m0] restart")}},
		{name: "c1", sealed: true, msgs: []model.SyslogMessage{
			sysMsg(n.Add(-2*time.Hour-20*time.Second), 6, "BGW320", "dhcpd", "[m1] DHCPACK on 192.168.1.71 to 02:00:00:00:00:71 via br0"),
			sysMsg(n.Add(-2*time.Hour-10*time.Second), 3, "BGW320", "ponlinkd", "[m2] PON link state O5 -> O1 (LOS)"),
			sysMsg(n.Add(-2*time.Hour-5*time.Second), -1, "", "", "[m3] watchdog ok")}},
		{name: "c2", sealed: true, msgs: []model.SyslogMessage{
			sysMsg(n.Add(-time.Hour-5*time.Second), 4, "BGW320", "wanmgr", "[m4] WAN DHCP lease renewal failed"),
			m6,
			sysMsg(n.Add(-time.Hour-time.Second), 0, "BGW320", "kernel", "[m5] Kernel panic - not syncing")}},
		{name: "c3", sealed: true, msgs: []model.SyslogMessage{
			sysMsg(n.Add(-30*time.Minute-3*time.Second), 7, "bgw320-505", "cwmpd", "[m7] Inform sent"),
			sysMsg(n.Add(-30*time.Minute-2*time.Second), 6, "BGW320", "ntpd", "[m8] time synchronized"),
			m9}},
		{name: "c4", msgs: []model.SyslogMessage{
			sysMsg(n.Add(-10*time.Second), 6, "BGW320", "syslogd", "[m10] in the open chunk"),
			sysMsg(n, 6, "BGW320", "syslogd", "[m11] at the end")}},
	}}
	r := &fakeReader{}
	appendRecord(r, n.Add(-30*time.Hour), model.TypeSample, map[string]int{"cycle": 1})
	appendChunkRecord(r, n.Add(-30*time.Hour+5*time.Minute), store.chunks[0])
	appendChunkRecord(r, n.Add(-2*time.Hour+4*time.Minute), store.chunks[1])
	appendRecord(r, n.Add(-90*time.Minute), model.TypeSample, map[string]int{"cycle": 2})
	appendChunkRecord(r, n.Add(-time.Hour+4*time.Minute), store.chunks[2])
	appendChunkRecord(r, n.Add(-25*time.Minute), store.chunks[3])
	appendRecord(r, n.Add(-20*time.Minute), model.TypeSample, map[string]int{"cycle": 3})
	return store, r
}

var msgName = regexp.MustCompile(`\[(m\d+|[a-z]\d*)\]`)

// names lists the [mN] names of a list's messages, in order.
func names(list model.SyslogList) string {
	var out []string
	for _, m := range list.Messages {
		text := m.Msg
		if text == "" {
			text = m.Raw
		}
		if sm := msgName.FindStringSubmatch(text); sm != nil {
			out = append(out, sm[1])
		} else {
			out = append(out, "?")
		}
	}
	return strings.Join(out, ",")
}

// seqs lists the [mN] names of a list's messages with the seq of their chunk record, e.g.
// "m10:0,m9:5".
func seqs(list model.SyslogList) string {
	var out []string
	for i, name := range strings.Split(names(list), ",") {
		out = append(out, fmt.Sprintf("%s:%d", name, list.Messages[i].Seq))
	}
	return strings.Join(out, ",")
}

// syslogHarness serves syslogWorld.
func syslogHarness(t *testing.T) *harness {
	t.Helper()
	hs := newHarness(t)
	hs.syslog, hs.reader = syslogWorld()
	hs.srv.syslog, hs.srv.reader = hs.syslog, hs.reader
	return hs
}

// resetScans forgets the periods asked of ScanTime and the records handed over.
func resetScans(r *fakeReader) {
	r.mu.Lock()
	r.timeScans = nil
	r.mu.Unlock()
	r.callbacks.Store(0)
}

func getSyslog(t *testing.T, hs *harness, params url.Values) model.SyslogList {
	t.Helper()
	rec := hs.get("/api/syslog?" + params.Encode())
	wantStatus(t, rec, http.StatusOK)
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	return decode[model.SyslogList](t, rec)
}

func TestSyslogEndpoint(t *testing.T) {
	hs := syslogHarness(t)
	n := syslogNow

	// Default period: the 24 hours before now, newest first by receive time, each message with
	// its chunk and that chunk's syslog_chunk record (none yet for the open chunk).
	list := getSyslog(t, hs, nil)
	if got, want := seqs(list), "m10:0,m9:5,m8:5,m7:5,m5:4,m6:4,m4:4,m3:2,m2:2,m1:2"; got != want {
		t.Errorf("messages = %s, want %s", got, want)
	}
	if list.From != n.Add(-24*time.Hour).Format(time.RFC3339Nano) || list.To != n.Format(time.RFC3339Nano) || list.Truncated {
		t.Errorf("from %s to %s truncated %v", list.From, list.To, list.Truncated)
	}
	queries, _ := hs.syslog.calls()
	if len(queries) != 1 || !queries[0].from.Equal(n.Add(-24*time.Hour)) || !queries[0].to.Equal(n) || queries[0].limit != DefaultSyslogLimit || queries[0].filtered {
		t.Errorf("store asked %+v", queries)
	}
	// Each message exactly as the store keeps it.
	if m := list.Messages[1]; m.Chunk != "c3" || m.Format != "rfc5424" || m.Host != "BGW320-505.attlocal.net" || m.Severity == nil || *m.Severity != 5 ||
		m.Raw != "<133>1 "+m.TS+" BGW320-505.attlocal.net TR069 - - - [m9] Periodic Inform" || m.Src != "192.168.1.254:514" {
		t.Errorf("m9 = %+v", m)
	}
	if m := list.Messages[5]; m.Chunk != "c2" || m.Raw != "" || m.RawB64 != "PDMwPndpZmlkOiBTU0lEIP/+" || m.Severity != nil {
		t.Errorf("m6 = %+v", m)
	}
	if m := list.Messages[0]; m.Chunk != "c4" || m.Seq != 0 {
		t.Errorf("m10 = %+v", m)
	}
	// The JSON names the chunk and its record next to the message's own fields.
	rec := hs.get("/api/syslog?limit=2")
	if body := rec.Body.String(); !strings.Contains(body, `{"chunk":"c4","rx":"`) || !strings.Contains(body, `{"chunk":"c3","seq":5,"rx":"`) {
		t.Errorf("entries not encoded as the dashboard reads them: %s", body)
	}

	tests := []struct {
		name   string
		params url.Values
		want   string
		trunc  bool
	}{
		// q: raw text, message, app or host, ignoring case; never the sender or the format.
		{"text in message and app", url.Values{"q": {"dhcp"}}, "m4,m1", false},
		{"text in host", url.Values{"q": {"BGW320-505"}}, "m9,m7", false},
		{"text in app only", url.Values{"q": {"WIFID"}}, "m6", false},
		{"text in raw only", url.Values{"q": {"watchdog"}}, "m3", false},
		{"surrounding space ignored", url.Values{"q": {"  pon link  "}}, "m2", false},
		{"sender is not searched", url.Values{"q": {"192.168.1.254"}}, "", false},
		{"format is not searched", url.Values{"q": {"rfc3164"}}, "", false},
		{"non-ASCII", url.Values{"q": {replacementChars}}, "m6", false},
		// severity: that level and more severe; messages without a severity never pass.
		{"severity 3", url.Values{"severity": {"3"}}, "m5,m2", false},
		{"severity err", url.Values{"severity": {"err"}}, "m5,m2", false},
		{"severity ERROR", url.Values{"severity": {"ERROR"}}, "m5,m2", false},
		{"severity emerg", url.Values{"severity": {"emerg"}}, "m5", false},
		{"severity 0", url.Values{"severity": {"0"}}, "m5", false},
		{"severity warning", url.Values{"severity": {"warning"}}, "m5,m4,m2", false},
		{"severity warn", url.Values{"severity": {" Warn "}}, "m5,m4,m2", false},
		{"severity notice", url.Values{"severity": {"notice"}}, "m9,m5,m4,m2", false},
		{"severity info", url.Values{"severity": {"informational"}}, "m10,m9,m8,m5,m4,m2,m1", false},
		{"severity debug", url.Values{"severity": {"debug"}}, "m10,m9,m8,m7,m5,m4,m2,m1", false},
		{"severity 7", url.Values{"severity": {"7"}}, "m10,m9,m8,m7,m5,m4,m2,m1", false},
		{"severity and text", url.Values{"severity": {"notice"}, "q": {"inform"}}, "m9", false},
		// limit
		{"limit 2", url.Values{"limit": {"2"}}, "m10,m9", true},
		{"limit 9", url.Values{"limit": {"9"}}, "m10,m9,m8,m7,m5,m6,m4,m3,m2", true},
		{"limit 10", url.Values{"limit": {"10"}}, "m10,m9,m8,m7,m5,m6,m4,m3,m2,m1", false},
		{"limit with a filter", url.Values{"limit": {"1"}, "severity": {"err"}}, "m5", true},
		// period [from, to), by the receive time
		{"from", url.Values{"from": {n.Add(-65 * time.Minute).Format(time.RFC3339)}}, "m10,m9,m8,m7,m5,m6,m4", false},
		{"to is exclusive", url.Values{"to": {n.Add(-time.Hour - time.Second).Format(time.RFC3339)}}, "m6,m4,m3,m2,m1", false},
		{"older than a day", url.Values{"from": {n.Add(-31 * time.Hour).Format(time.RFC3339)}}, "m10,m9,m8,m7,m5,m6,m4,m3,m2,m1,m0", false},
		{"to after the last message", url.Values{"to": {n.Add(time.Second).Format(time.RFC3339)}}, "m11,m10,m9,m8,m7,m5,m6,m4,m3,m2,m1", false},
		{"from as a date", url.Values{"from": {"2026-10-05"}}, "m10,m9,m8,m7,m5,m6,m4,m3,m2,m1", false},
		{"from as Unix seconds", url.Values{"from": {fmt.Sprint(n.Add(-35 * time.Minute).Unix())}}, "m10,m9,m8,m7", false},
		{"nothing in the period", url.Values{"from": {"2026-10-01T00:00:00Z"}, "to": {"2026-10-02T00:00:00Z"}}, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			list := getSyslog(t, hs, tc.params)
			if got := names(list); got != tc.want || list.Truncated != tc.trunc {
				t.Errorf("messages = %q truncated %v, want %q truncated %v", got, list.Truncated, tc.want, tc.trunc)
			}
		})
	}
	// Only a request with a filter hands the store one.
	hs.syslog.calls()
	getSyslog(t, hs, url.Values{"q": {"x"}})
	getSyslog(t, hs, url.Values{"severity": {"err"}})
	getSyslog(t, hs, url.Values{"q": {"  "}, "severity": {""}})
	if q, _ := hs.syslog.calls(); len(q) != 3 || !q[0].filtered || !q[1].filtered || q[2].filtered {
		t.Errorf("filters handed to the store: %+v", q)
	}

	// An empty list is [] (the dashboard iterates it).
	rec = hs.get("/api/syslog?q=nothing-matches-this")
	wantStatus(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), `"messages":[]`) {
		t.Errorf("empty list encoded as %s", rec.Body.String())
	}
	// The period and the defaults echo what was read.
	list = getSyslog(t, hs, url.Values{"to": {"2026-10-05T02:00:00+01:00"}})
	if list.To != "2026-10-05T01:00:00Z" || list.From != "2026-10-04T01:00:00Z" {
		t.Errorf("period %s .. %s", list.From, list.To)
	}
}

// The handler keeps the store's order and limit: it neither re-sorts nor shows more than asked.
func TestSyslogEndpointKeepsTheStoresAnswer(t *testing.T) {
	hs := syslogHarness(t)
	at := syslogNow.Add(-time.Hour)
	hs.syslog.queryFn = func(limit int) ([]model.SyslogEntry, bool) {
		return []model.SyslogEntry{
			{Chunk: "x", SyslogMessage: sysMsg(at, 6, "gw", "a", "[b1] later in the chunk")},
			{Chunk: "x", SyslogMessage: sysMsg(at, 6, "gw", "a", "[a1] same time, earlier")},
			{Chunk: "x", SyslogMessage: sysMsg(at.Add(-time.Second), 6, "gw", "a", "[a0] received earlier")},
		}, false
	}
	if got := names(getSyslog(t, hs, nil)); got != "b1,a1,a0" {
		t.Errorf("order = %s, want the store's b1,a1,a0", got)
	}
	// More than asked (a misbehaving store): cut to the limit, and more matched.
	if list := getSyslog(t, hs, url.Values{"limit": {"2"}}); names(list) != "b1,a1" || !list.Truncated {
		t.Errorf("limit 2: %s truncated %v", names(list), list.Truncated)
	}
	hs.syslog.queryFn = nil
	hs.syslog.extra = 3
	if list := getSyslog(t, hs, url.Values{"limit": {"4"}}); names(list) != "m10,m9,m8,m7" || !list.Truncated {
		t.Errorf("limit 4 of a store that answers more: %s truncated %v", names(list), list.Truncated)
	}
}

func TestSyslogEndpointBadParameters(t *testing.T) {
	hs := syslogHarness(t)
	for _, q := range []string{
		"from=yesterday", "to=2026-13-01", "from=2026-10-05T04:00:00Z", // after the default to (now)
		"from=2026-10-05&to=2026-10-04", "from=2026-10-05&to=2026-10-05",
		"from=2026-09-01T00:00:00Z&to=2026-10-05T00:00:00Z", // more than 31 days
		"limit=0", "limit=-1", "limit=x", "limit=1.5",
		"severity=8", "severity=-1", "severity=bogus", "severity=0x1", "severity=07", "severity=err,warning",
		"q=" + strings.Repeat("a", MaxSyslogQueryChars+1), "q=%FF",
	} {
		t.Run(q, func(t *testing.T) {
			hs.syslog.calls()
			msg := wantJSONError(t, hs.get("/api/syslog?"+q), http.StatusBadRequest)
			if name, _, _ := strings.Cut(q, "="); !strings.Contains(msg, name) && name != "from" && name != "to" {
				t.Errorf("message %q does not name the parameter %s", msg, name)
			}
			if queries, opened := hs.syslog.calls(); len(queries) != 0 || len(opened) != 0 {
				t.Error("an invalid request read the store")
			}
		})
	}
	// Exactly 31 days and exactly MaxSyslogQueryChars characters are fine, and empty parameters
	// are the defaults.
	wantStatus(t, hs.get("/api/syslog?from=2026-09-04T00:00:00Z&to=2026-10-05T00:00:00Z"), http.StatusOK)
	wantStatus(t, hs.get("/api/syslog?q="+strings.Repeat("é", MaxSyslogQueryChars)), http.StatusOK)
	if list := getSyslog(t, hs, url.Values{"from": {""}, "to": {""}, "q": {""}, "severity": {""}, "limit": {""}}); names(list) != "m10,m9,m8,m7,m5,m6,m4,m3,m2,m1" {
		t.Errorf("empty parameters: %s", names(list))
	}
}

func TestSyslogEndpointLimitIsClamped(t *testing.T) {
	hs := newHarness(t)
	base := syslogNow.Add(-2 * time.Hour)
	k := 0
	for i := 0; i < 12; i++ {
		c := &fakeChunk{name: fmt.Sprintf("chunk%02d", i), sealed: true}
		for j := 0; j < 500; j++ {
			c.msgs = append(c.msgs, sysMsg(base.Add(time.Duration(i)*time.Minute+time.Duration(j)*time.Millisecond), 6, "gw", "fw", fmt.Sprintf("[m%d] drop", k)))
			k++
		}
		hs.syslog.chunks = append(hs.syslog.chunks, c)
	}
	list := getSyslog(t, hs, url.Values{"limit": {"100000"}})
	if len(list.Messages) != MaxSyslogLimit || !list.Truncated {
		t.Fatalf("%d messages, truncated %v; want %d, true", len(list.Messages), list.Truncated, MaxSyslogLimit)
	}
	if first, last := names(model.SyslogList{Messages: list.Messages[:1]}), names(model.SyslogList{Messages: list.Messages[MaxSyslogLimit-1:]}); first != "m5999" || last != "m1000" {
		t.Errorf("first %s, last %s; want m5999 and m1000", first, last)
	}
	if list := getSyslog(t, hs, nil); len(list.Messages) != DefaultSyslogLimit || !list.Truncated {
		t.Errorf("default limit: %d messages, truncated %v", len(list.Messages), list.Truncated)
	}
	if q, _ := hs.syslog.calls(); len(q) != 2 || q[0].limit != MaxSyslogLimit || q[1].limit != DefaultSyslogLimit {
		t.Errorf("limits asked of the store: %+v", q)
	}
}

// The syslog_chunk records are looked for only where they can be: after the messages listed
// from each sealed chunk, within syslogChunkSlack of the newest. A record found is remembered,
// and the open chunk is never looked up.
func TestSyslogEndpointFindsChunkRecords(t *testing.T) {
	hs := syslogHarness(t)
	n := syslogNow
	resetScans(hs.reader)
	hs.syslog.calls()
	list := getSyslog(t, hs, nil)
	if got := seqs(list); got != "m10:0,m9:5,m8:5,m7:5,m5:4,m6:4,m4:4,m3:2,m2:2,m1:2" {
		t.Fatalf("messages = %s", got)
	}
	// One window (the chunks' windows are closer than syslogScanJoin): from the oldest message of
	// c1 to syslogChunkSlack after the newest of c3; the scan stops at the last record wanted
	// (#6, in the window, is not read).
	want := [2]time.Time{n.Add(-2*time.Hour - 20*time.Second), n.Add(-30*time.Minute - time.Second + syslogChunkSlack)}
	if len(hs.reader.timeScans) != 1 || hs.reader.timeScans[0] != want {
		t.Errorf("periods read: %v, want %v", hs.reader.timeScans, want)
	}
	if got := hs.reader.callbacks.Load(); got != 4 {
		t.Errorf("%d records examined, want 4 (#2 to #5)", got)
	}
	// The store is asked which chunks are sealed, in the order of the list.
	if _, opened := hs.syslog.calls(); !slices.Equal(opened, []string{"c4", "c3", "c2", "c1"}) {
		t.Errorf("OpenChunk asked for %v", opened)
	}

	// Again: every sealed chunk's record is known, only the open chunk is asked about, and the
	// ledger is not read.
	resetScans(hs.reader)
	if got := seqs(getSyslog(t, hs, nil)); got != "m10:0,m9:5,m8:5,m7:5,m5:4,m6:4,m4:4,m3:2,m2:2,m1:2" {
		t.Errorf("second request: %s", got)
	}
	if len(hs.reader.timeScans) != 0 {
		t.Errorf("records read again: %v", hs.reader.timeScans)
	}
	if _, opened := hs.syslog.calls(); !slices.Equal(opened, []string{"c4"}) {
		t.Errorf("OpenChunk asked for %v, want only the open chunk c4", opened)
	}

	// The open chunk is sealed: its record is found right after its messages.
	hs.syslog.seal("c4")
	sealed := appendChunkRecord(hs.reader, n.Add(-5*time.Second), hs.syslog.chunks[4])
	resetScans(hs.reader)
	if list := getSyslog(t, hs, nil); list.Messages[0].Seq != sealed {
		t.Errorf("m10 = %+v, want record #%d", list.Messages[0], sealed)
	}
	if want := [2]time.Time{n.Add(-10 * time.Second), n.Add(-10*time.Second + syslogChunkSlack)}; len(hs.reader.timeScans) != 1 || hs.reader.timeScans[0] != want {
		t.Errorf("periods read for the newly sealed chunk: %v, want %v", hs.reader.timeScans, want)
	}

	// The old chunk c0 (more than a day ago): its own window.
	resetScans(hs.reader)
	if list := getSyslog(t, hs, url.Values{"from": {n.Add(-31 * time.Hour).Format(time.RFC3339)}, "q": {"restart"}}); seqs(list) != "m0:1" {
		t.Errorf("m0: %s", seqs(list))
	}
	if want := [2]time.Time{n.Add(-30 * time.Hour), n.Add(-30*time.Hour + syslogChunkSlack)}; len(hs.reader.timeScans) != 1 || hs.reader.timeScans[0] != want {
		t.Errorf("periods read for c0: %v, want %v", hs.reader.timeScans, want)
	}
}

// What cannot be found nearby is not searched for: a chunk sealed long after its messages (as
// a chunk recovered at the next start after a crash), a record whose time range does not cover
// the messages (another chunk of that name).
func TestSyslogEndpointChunkRecordsNotFound(t *testing.T) {
	hs := newHarness(t)
	n := syslogNow
	late := &fakeChunk{name: "late", sealed: true, msgs: []model.SyslogMessage{sysMsg(n.Add(-5*time.Hour), 6, "gw", "a", "[a0] sealed hours later")}}
	twin := &fakeChunk{name: "twin", sealed: true, msgs: []model.SyslogMessage{sysMsg(n.Add(-time.Hour), 6, "gw", "a", "[b0] the second twin")}}
	hs.syslog.chunks = []*fakeChunk{late, twin}
	r := &fakeReader{}
	appendChunkRecord(r, n.Add(-3*time.Hour), late) // outside [n-5h, n-5h+15m]
	other := &fakeChunk{name: "twin", msgs: []model.SyslogMessage{sysMsg(n.Add(-26*time.Hour), 6, "gw", "a", "the first twin")}}
	appendChunkRecord(r, n.Add(-time.Hour+time.Minute), other) // covers another day's messages
	right := appendChunkRecord(r, n.Add(-time.Hour+2*time.Minute), twin)
	hs.reader, hs.srv.reader = r, r
	if got := seqs(getSyslog(t, hs, nil)); got != fmt.Sprintf("b0:%d,a0:0", right) {
		t.Errorf("messages = %s", got)
	}
}

// The work of one request is bounded: at most syslogChunkBudget records examined and
// maxSyslogChunkScans scans, newest windows first. What is not found keeps Seq 0.
func TestSyslogEndpointChunkLookupIsBounded(t *testing.T) {
	hs := newHarness(t)
	n := syslogNow
	r := &fakeReader{}
	// 20 chunks a day and a half apart, each sealed 4 minutes after its message.
	var want []string
	for k := 20; k >= 1; k-- {
		at := n.Add(-time.Duration(k) * 36 * time.Hour)
		c := &fakeChunk{name: fmt.Sprintf("k%02d", k), sealed: true, msgs: []model.SyslogMessage{sysMsg(at, 6, "gw", "a", fmt.Sprintf("[k%d] message", k))}}
		hs.syslog.chunks = append(hs.syslog.chunks, c)
		appendRecord(r, at.Add(time.Minute), model.TypeSample, map[string]int{"k": k})
		seq := appendChunkRecord(r, at.Add(4*time.Minute), c)
		if k > maxSyslogChunkScans {
			seq = 0 // the oldest four: beyond the scans of one request
		}
		want = append(want, fmt.Sprintf("k%d:%d", k, seq))
	}
	slices.Reverse(want)
	hs.reader, hs.srv.reader = r, r
	period := url.Values{"from": {n.Add(-31 * 24 * time.Hour).Format(time.RFC3339)}}
	if got := seqs(getSyslog(t, hs, period)); got != strings.Join(want, ",") {
		t.Errorf("messages = %s\nwant       %s", got, strings.Join(want, ","))
	}
	if len(r.timeScans) != maxSyslogChunkScans {
		t.Errorf("%d scans, want %d", len(r.timeScans), maxSyslogChunkScans)
	}
	for i := 1; i < len(r.timeScans); i++ {
		if !r.timeScans[i][1].Before(r.timeScans[i-1][0]) {
			t.Errorf("scan %d (%v) not older than scan %d (%v)", i, r.timeScans[i], i-1, r.timeScans[i-1])
		}
	}

	// A long run of chunks close to each other (a warning an hour for two days, as a severity
	// filter over a week lists them) among the ledger's other records: the windows span at most
	// syslogScanSpan and are read newest first, so a record budget that runs out leaves the
	// oldest messages without their records, never the newest at the top of the list (one
	// window over the two days spent the budget on its oldest records).
	old := syslogChunkBudget
	syslogChunkBudget = 100
	defer func() { syslogChunkBudget = old }()
	hs = newHarness(t)
	r = &fakeReader{}
	type event struct {
		at    time.Time
		chunk *fakeChunk // nil: a sample
	}
	var events []event
	for k := 47; k >= 0; k-- {
		at := n.Add(-time.Duration(k)*time.Hour - 30*time.Minute)
		c := &fakeChunk{name: fmt.Sprintf("h%02d", k), sealed: true, msgs: []model.SyslogMessage{sysMsg(at, 4, "gw", "wanmgr", fmt.Sprintf("[h%d] warning", k))}}
		hs.syslog.chunks = append(hs.syslog.chunks, c)
		events = append(events, event{at.Add(4 * time.Minute), c})
	}
	for at := n.Add(-48 * time.Hour); at.Before(n); at = at.Add(10 * time.Minute) {
		events = append(events, event{at: at})
	}
	slices.SortStableFunc(events, func(a, b event) int { return a.at.Compare(b.at) })
	recs := map[string]uint64{}
	for _, e := range events {
		if e.chunk == nil {
			appendRecord(r, e.at, model.TypeSample, map[string]string{"at": e.at.Format(time.RFC3339)})
		} else {
			recs[e.chunk.name] = appendChunkRecord(r, e.at, e.chunk)
		}
	}
	hs.reader, hs.srv.reader = r, r
	list := getSyslog(t, hs, url.Values{"from": {n.Add(-49 * time.Hour).Format(time.RFC3339)}})
	if len(list.Messages) != 48 {
		t.Fatalf("%d messages, want 48", len(list.Messages))
	}
	linked := 0
	for k, m := range list.Messages { // newest first: h0 (half an hour ago) to h47
		name := fmt.Sprintf("h%02d", k)
		switch {
		case m.Chunk != name:
			t.Fatalf("message %d is from chunk %s, want %s", k, m.Chunk, name)
		case k < 12 && m.Seq != recs[name]: // the newest window, read first
			t.Errorf("%s (the newest twelve hours): record #%d, want #%d", name, m.Seq, recs[name])
		case k >= 24 && m.Seq != 0: // windows the budget never reached
			t.Errorf("%s: record #%d found beyond the budget", name, m.Seq)
		case m.Seq != 0 && m.Seq != recs[name]:
			t.Errorf("%s: record #%d, want #%d", name, m.Seq, recs[name])
		}
		if m.Seq != 0 {
			linked++
		}
	}
	if linked >= 24 {
		t.Errorf("%d messages linked with a budget of %d records", linked, syslogChunkBudget)
	}
	if got := r.callbacks.Load(); got > int64(syslogChunkBudget)+1 {
		t.Errorf("%d records handed over with a budget of %d", got, syslogChunkBudget)
	}
	for i, s := range r.timeScans {
		if s[1].Sub(s[0]) > syslogScanSpan {
			t.Errorf("scan %d reads %v (%v), more than %v", i, s, s[1].Sub(s[0]), syslogScanSpan)
		}
		if i > 0 && !s[1].Before(r.timeScans[i-1][0]) {
			t.Errorf("scan %d (%v) not older than scan %d (%v)", i, s, i-1, r.timeScans[i-1])
		}
	}
}

// GET /api/syslog bounds its answer by its size as well as by the limit: messages a sender
// filled with control characters (each a six-byte escape in JSON, in raw and again in msg) end
// the list at MaxSyslogAnswerBytes, truncated, newest first and exact. 5000 of them made an
// answer of about 0.5 GB.
func TestSyslogEndpointAnswerIsBoundedBySize(t *testing.T) {
	hs := newHarness(t)
	flood := strings.Repeat("\x01", 8192) // a datagram of the receiver's largest size by default
	// Receive times of one length (nine digits of fraction), so that every entry has the same size.
	base := syslogNow.Add(-time.Hour + 123456789*time.Nanosecond)
	c := &fakeChunk{name: "flood", sealed: true}
	for i := 0; i < MaxSyslogLimit; i++ {
		c.msgs = append(c.msgs, model.SyslogMessage{RX: base.Add(time.Duration(i) * time.Millisecond).Format(time.RFC3339Nano),
			Src: "192.168.1.254:514", Raw: flood, Format: "unknown", Msg: flood})
	}
	hs.syslog.chunks = []*fakeChunk{c}
	rec := hs.get("/api/syslog?limit=5000")
	wantStatus(t, rec, http.StatusOK)
	if size := rec.Body.Len(); size > MaxSyslogAnswerBytes {
		t.Fatalf("an answer of %d bytes, more than %d", size, MaxSyslogAnswerBytes)
	}
	list := decode[model.SyslogList](t, rec)
	one, err := json.Marshal(model.SyslogEntry{Chunk: "flood", SyslogMessage: c.msgs[0]})
	if err != nil {
		t.Fatal(err)
	}
	if want := MaxSyslogAnswerBytes / (len(one) + 1 + syslogSeqRoom); len(list.Messages) != want || !list.Truncated {
		t.Fatalf("%d messages, truncated %v; want the %d that fit, truncated", len(list.Messages), list.Truncated, want)
	}
	for i, m := range list.Messages {
		if want := c.msgs[MaxSyslogLimit-1-i].RX; m.RX != want || m.Raw != flood || m.Msg != flood {
			t.Fatalf("message %d: received %s (want %s), %d bytes of raw text", i, m.RX, want, len(m.Raw))
		}
	}
	// The store was asked for the limit: the size ends the list, not the limit.
	if q, _ := hs.syslog.calls(); len(q) != 1 || q[0].limit != MaxSyslogLimit {
		t.Errorf("store asked %+v", q)
	}
}

func TestSyslogAnswerFits(t *testing.T) {
	e := model.SyslogEntry{Chunk: "c", SyslogMessage: sysMsg(syslogNow, 6, "gw", "app", "[m0] text")}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	each := len(b) + 1 + syslogSeqRoom
	three := []model.SyslogEntry{e, e, e}
	for _, tc := range []struct{ maxBytes, want int }{
		{0, 1}, {each - 1, 1}, {each, 1}, {2*each - 1, 1}, {2 * each, 2}, {3*each - 1, 2}, {3 * each, 3}, {1 << 20, 3},
	} {
		if got := syslogAnswerFits(three, tc.maxBytes); got != tc.want {
			t.Errorf("syslogAnswerFits(3 entries of %d bytes, %d) = %d, want %d", each, tc.maxBytes, got, tc.want)
		}
	}
	if got := syslogAnswerFits(nil, 0); got != 0 {
		t.Errorf("syslogAnswerFits(none) = %d", got)
	}
}

func TestSyslogEndpointChunkRecordIntegrity(t *testing.T) {
	hs := syslogHarness(t)
	// #4 (c2) edited after it was written: h no longer covers b.
	rewrite(hs.reader, 4, false, func(b *model.Body) {
		var c model.SyslogChunk
		if err := json.Unmarshal(b.Data, &c); err != nil {
			panic(err)
		}
		c.SHA256 = strings.Repeat("00", 32)
		b.Data, _ = json.Marshal(c)
	})
	for i := 0; i < 2; i++ { // an altered record is reported every time (not remembered)
		rec := hs.get("/api/syslog")
		wantStatus(t, rec, http.StatusOK)
		warn := rec.Header().Get(WarningHeader)
		for _, want := range []string{"ledger integrity", "#4 h does not match b", "Verify"} {
			if !strings.Contains(warn, want) {
				t.Errorf("request %d: warning %q does not say %q", i, warn, want)
			}
		}
		// The edited record still links its messages (the records view flags it).
		if got := seqs(decode[model.SyslogList](t, rec)); got != "m10:0,m9:5,m8:5,m7:5,m5:4,m6:4,m4:4,m3:2,m2:2,m1:2" {
			t.Errorf("request %d: messages = %s", i, got)
		}
	}
	// #3, between the records of c1 and c2, is a syslog_chunk record whose data does not parse.
	rewrite(hs.reader, 3, true, func(b *model.Body) { b.Type, b.Data = model.TypeSyslogChunk, json.RawMessage(`{"name":5}`) })
	hs.srv.chunkSeqs = chunkSeqCache{}
	rec := hs.get("/api/syslog?q=dhcp") // m4 (c2) and m1 (c1)
	if warn := rec.Header().Get(WarningHeader); !strings.Contains(warn, "#3 syslog_chunk data does not parse") || !strings.Contains(warn, "#4 h does not match b") {
		t.Errorf("warning %q does not report the damaged record #3 and the altered #4", warn)
	}
	if got := seqs(decode[model.SyslogList](t, rec)); got != "m4:4,m1:2" {
		t.Errorf("messages = %s", got)
	}
	// A period without the damage stays quiet.
	if w := hs.get("/api/syslog?to=" + url.QueryEscape(syslogNow.Add(-90*time.Minute).Format(time.RFC3339))).Header().Get(WarningHeader); w != "" {
		t.Errorf("unexpected warning %q", w)
	}
}

func TestSyslogEndpointErrors(t *testing.T) {
	hs := syslogHarness(t)
	hs.syslog.queryErr = errors.New("syslogstore: read chunk syslog-20261005T031500Z: unexpected EOF")
	msg := wantJSONError(t, hs.get("/api/syslog"), http.StatusInternalServerError)
	if !strings.Contains(msg, "syslog: syslogstore: read chunk") {
		t.Errorf("message = %q", msg)
	}
	hs.syslog.queryErr = fmt.Errorf("store closed: %w", contracts.ErrUnavailable)
	wantJSONError(t, hs.get("/api/syslog"), http.StatusServiceUnavailable)
	hs.syslog.queryErr = nil

	// The client went away: nothing is read.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resetScans(hs.reader)
	wantJSONError(t, hs.serve(hs.request(http.MethodGet, "/api/syslog", nil, nil).WithContext(ctx)), http.StatusServiceUnavailable)
	if n := hs.reader.callbacks.Load(); n > 0 {
		t.Errorf("%d records handed over after the request was cancelled", n)
	}

	// The ledger cannot be read: the messages are listed without their records, and the
	// response says why.
	hs.reader.scanTimeErr = errors.New("ledger: read segment ledger-2026-10-05: unexpected EOF")
	rec := hs.get("/api/syslog")
	wantStatus(t, rec, http.StatusOK)
	if got := seqs(decode[model.SyslogList](t, rec)); got != "m10:0,m9:0,m8:0,m7:0,m5:0,m6:0,m4:0,m3:0,m2:0,m1:0" {
		t.Errorf("messages = %s", got)
	}
	if warn := rec.Header().Get(WarningHeader); !strings.Contains(warn, "syslog_chunk records could not be read: ledger: read segment") {
		t.Errorf("warning = %q", warn)
	}
	hs.reader.scanTimeErr = nil

	// The store cannot tell whether a chunk is sealed: its record is looked for anyway.
	hs.syslog.openErr = errors.New("access denied")
	if got := seqs(getSyslog(t, hs, nil)); got != "m10:0,m9:5,m8:5,m7:5,m5:4,m6:4,m4:4,m3:2,m2:2,m1:2" {
		t.Errorf("OpenChunk failing: %s", got)
	}
	hs.syslog.openErr = nil

	// Without the ledger reader the messages are listed without their records.
	hs.srv.reader = nil
	if got := seqs(getSyslog(t, hs, nil)); got != "m10:0,m9:0,m8:0,m7:0,m5:0,m6:0,m4:0,m3:0,m2:0,m1:0" {
		t.Errorf("without a ledger reader: %s", got)
	}
	// Without a syslog store there are no messages to list: 404, as JSON.
	hs.srv.syslog = nil
	if msg := wantJSONError(t, hs.get("/api/syslog"), http.StatusNotFound); !strings.Contains(msg, "keeps no syslog store") {
		t.Errorf("message = %q", msg)
	}
}

// /api/syslog is behind the same middleware as every other endpoint: a request with a foreign
// Host (DNS rebinding) never reaches it, only GET and HEAD are served, every response carries
// the security headers, and nothing grants another origin access to the answer.
func TestSyslogEndpointSecurity(t *testing.T) {
	hs := syslogHarness(t)
	hs.syslog.calls()
	for _, host := range []string{"evil.example:8320", "evil.example", "127.0.0.1.nip.io:8320", "192.168.1.71:8320"} {
		req := hs.request(http.MethodGet, "/api/syslog", nil, nil)
		req.Host = host
		rec := hs.serve(req)
		wantJSONError(t, rec, http.StatusMisdirectedRequest)
		assertSecurityHeaders(t, rec.Header(), false)
	}
	if q, _ := hs.syslog.calls(); len(q) != 0 || len(hs.reader.timeScans) != 0 {
		t.Fatal("a request with a foreign Host read the store or the ledger")
	}

	for _, hdr := range []map[string]string{nil, {"Origin": "http://evil.example", "Sec-Fetch-Site": "cross-site"}} {
		rec := hs.serve(hs.request(http.MethodGet, "/api/syslog", nil, hdr))
		if hdr == nil {
			wantStatus(t, rec, http.StatusOK)
		} else {
			wantJSONError(t, rec, http.StatusForbidden) // another site's page: not even read
		}
		assertSecurityHeaders(t, rec.Header(), false)
		for _, k := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"} {
			if v := rec.Header().Get(k); v != "" {
				t.Errorf("%s: %q", k, v)
			}
		}
	}

	wantStatus(t, hs.serve(hs.request(http.MethodHead, "/api/syslog", nil, nil)), http.StatusOK)
	// State-changing methods: the CSRF check first, then 405.
	wantJSONError(t, hs.serve(hs.request(http.MethodPost, "/api/syslog", strings.NewReader("{}"), map[string]string{CSRFHeader: ""})), http.StatusForbidden)
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		rec := hs.serve(hs.request(m, "/api/syslog", strings.NewReader("{}"), map[string]string{CSRFHeader: CSRFHeaderValue}))
		wantJSONError(t, rec, http.StatusMethodNotAllowed)
		if got := rec.Header().Get("Allow"); got != "GET, HEAD" {
			t.Errorf("%s: Allow = %q", m, got)
		}
		assertSecurityHeaders(t, rec.Header(), false)
	}
}

func TestParseSyslogSeverity(t *testing.T) {
	for in, want := range map[string]int{
		"": -1, " ": -1, "0": 0, "7": 7, "emerg": 0, "Emergency": 0, "panic": 0, "alert": 1, "crit": 2, "CRITICAL": 2,
		"err": 3, "error": 3, "warning": 4, "warn": 4, "notice": 5, "info": 6, "informational": 6, "debug": 7, " debug ": 7,
	} {
		if got, err := parseSyslogSeverity(in); err != nil || got != want {
			t.Errorf("parseSyslogSeverity(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"8", "-1", "00", "07", "1.0", "e", "errors", "info,debug", string(rune(0x0663)) /* ARABIC-INDIC DIGIT THREE */} {
		if _, err := parseSyslogSeverity(in); err == nil {
			t.Errorf("parseSyslogSeverity(%q) accepted", in)
		}
	}
}

func TestChunkWindows(t *testing.T) {
	d := func(day, hour, minute int) time.Time { return time.Date(2026, 10, day, hour, minute, 0, 0, time.UTC) }
	spans := map[string]chunkSpan{
		"a": {d(5, 1, 0), d(5, 1, 4)},   // [01:00, 01:19)
		"b": {d(5, 3, 0), d(5, 3, 2)},   // 1 h 41 min later: joined with a
		"c": {d(5, 3, 10), d(5, 3, 11)}, // overlapping b
		"d": {d(4, 10, 0), d(4, 10, 0)}, // the day before: on its own
		"e": {d(5, 9, 0), d(5, 9, 0)},   // 5 h 34 min after c: on its own
	}
	got := chunkWindows(spans)
	want := []chunkWindow{
		{d(5, 9, 0), d(5, 9, 15), []string{"e"}},
		{d(5, 1, 0), d(5, 3, 26), []string{"a", "b", "c"}},
		{d(4, 10, 0), d(4, 10, 15), []string{"d"}},
	}
	if len(got) != len(want) {
		t.Fatalf("windows = %v, want %v", got, want)
	}
	for i := range got {
		if !got[i].from.Equal(want[i].from) || !got[i].to.Equal(want[i].to) || !slices.Equal(got[i].names, want[i].names) {
			t.Errorf("window %d = %v, want %v", i, got[i], want[i])
		}
	}
	if w := chunkWindows(nil); len(w) != 0 {
		t.Errorf("no spans: %v", w)
	}

	// A chain of close chunks (one every 90 minutes): joined only while a window spans at most
	// syslogScanSpan, so that the newest is read on its own first.
	spans = map[string]chunkSpan{}
	for i := 0; i < 10; i++ {
		at := d(6, 0, 0).Add(time.Duration(i) * 90 * time.Minute)
		spans[fmt.Sprintf("p%d", i)] = chunkSpan{at, at}
	}
	got = chunkWindows(spans)
	want = []chunkWindow{
		{d(6, 12, 0), d(6, 13, 45), []string{"p8", "p9"}},
		{d(6, 0, 0), d(6, 10, 45), []string{"p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7"}},
	}
	if len(got) != len(want) {
		t.Fatalf("chain: windows = %v, want %v", got, want)
	}
	for i := range got {
		if !got[i].from.Equal(want[i].from) || !got[i].to.Equal(want[i].to) || !slices.Equal(got[i].names, want[i].names) {
			t.Errorf("chain: window %d = %v, want %v", i, got[i], want[i])
		}
		if span := got[i].to.Sub(got[i].from); span > syslogScanSpan {
			t.Errorf("chain: window %d spans %v", i, span)
		}
	}
}

// ----------------------------------------------------------------------------- retention

const retentionURL = "/api/syslog/retention"

func TestSyslogRetentionEndpoint(t *testing.T) {
	hs := newHarness(t)
	rec := hs.serve(hs.request(http.MethodPost, retentionURL, strings.NewReader(`{"keep_mb":50,"keep_days":30}`), map[string]string{"Origin": testOrigin}))
	wantStatus(t, rec, http.StatusOK)
	cc := decode[model.ConfigChange](t, rec)
	if cc.After != "50 MiB, 30 days" || cc.Actor != "operator via web" || cc.Result != "applied" {
		t.Errorf("change = %+v", cc)
	}
	// keep_days left out is no age limit; the CLI says who it is.
	wantStatus(t, hs.post(retentionURL, `{"keep_mb":100,"client":"cli"}`), http.StatusOK)
	// The limits themselves are fine.
	for _, body := range []string{
		fmt.Sprintf(`{"keep_mb":%d,"keep_days":0}`, config.MinSyslogKeepMB),
		fmt.Sprintf(`{"keep_mb":%d,"keep_days":%d}`, config.MaxSyslogKeepMB, config.MaxSyslogKeepDays),
		`{"keep_mb":100,"keep_days":null}`,
	} {
		wantStatus(t, hs.post(retentionURL, body), http.StatusOK)
	}
	calls := hs.syslogCtl.callList()
	got := make([]string, len(calls))
	for i, c := range calls {
		if c.ctxErr != nil {
			t.Errorf("call %d saw a cancelled context: %v", i, c.ctxErr)
		}
		got[i] = fmt.Sprintf("%d|%d|%s", c.keepMB, c.keepDays, c.actor)
	}
	if want := []string{"50|30|operator via web", "100|0|operator via cli", "1|0|operator via cli", "1048576|3650|operator via cli", "100|0|operator via cli"}; !slices.Equal(got, want) {
		t.Errorf("calls = %q, want %q", got, want)
	}

	bad := []struct {
		name, body, ctype string
		code              int
		contains          string
	}{
		{"no keep_mb", `{"keep_days":3}`, "", 400, "keep_mb"},
		{"null keep_mb", `{"keep_mb":null}`, "", 400, "keep_mb"},
		{"zero", `{"keep_mb":0}`, "", 400, "keep_mb must be a whole number of MiB from 1 to 1048576"},
		{"negative", `{"keep_mb":-5}`, "", 400, "keep_mb"},
		{"too much", `{"keep_mb":1048577}`, "", 400, "keep_mb"},
		{"fraction", `{"keep_mb":1.5}`, "", 400, "keep_mb"},
		{"exponent", `{"keep_mb":1e2}`, "", 400, "keep_mb"},
		{"huge", `{"keep_mb":99999999999999999999}`, "", 400, "keep_mb"},
		{"string", `{"keep_mb":"100"}`, "", 400, "keep_mb"},
		{"boolean", `{"keep_mb":true}`, "", 400, "keep_mb"},
		{"negative days", `{"keep_mb":100,"keep_days":-1}`, "", 400, "keep_days must be 0 (no age limit) to 3650"},
		{"too many days", `{"keep_mb":100,"keep_days":3651}`, "", 400, "keep_days"},
		{"fractional days", `{"keep_mb":100,"keep_days":0.5}`, "", 400, "keep_days"},
		{"bad client", `{"keep_mb":100,"client":"monitor"}`, "", 400, "client"},
		{"unknown field", `{"keep_mb":100,"keep_bytes":1}`, "", 400, "unknown field"},
		{"not an object", `[100]`, "", 400, "invalid JSON body"},
		{"trailing data", `{"keep_mb":100}{"keep_mb":1}`, "", 400, "exactly one JSON object"},
		{"empty body", ``, "", 400, "must be a JSON object"},
		{"invalid UTF-8", "{\"keep_mb\":100,\"client\":\"\xff\"}", "", 400, "valid UTF-8"},
		{"form content type", `keep_mb=100`, "application/x-www-form-urlencoded", 415, "application/json"},
		{"text content type", `{"keep_mb":100}`, "text/plain", 415, "application/json"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			before := len(hs.syslogCtl.callList())
			hdr := map[string]string{}
			if tc.ctype != "" {
				hdr["Content-Type"] = tc.ctype
			}
			msg := wantJSONError(t, hs.serve(hs.request(http.MethodPost, retentionURL, strings.NewReader(tc.body), hdr)), tc.code)
			if !strings.Contains(msg, tc.contains) {
				t.Errorf("message %q does not say %q", msg, tc.contains)
			}
			if len(hs.syslogCtl.callList()) != before {
				t.Error("an invalid request reached SetSyslogRetention")
			}
		})
	}
	// A missing Content-Type is accepted (CLI clients).
	wantStatus(t, hs.serve(hs.request(http.MethodPost, retentionURL, strings.NewReader(`{"keep_mb":100}`), map[string]string{"Content-Type": ""})), http.StatusOK)
}

func TestSyslogRetentionErrors(t *testing.T) {
	applied := model.ConfigChange{Target: "monitor", What: "syslog.keep_mb", Before: "100", After: "50", Actor: "operator via cli", Result: "applied"}
	tests := []struct {
		name     string
		change   model.ConfigChange
		err      error
		code     int
		contains string
		withCC   bool
	}{
		{"not recorded", applied, fmt.Errorf("append config_change: %w", contracts.ErrNotRecorded), 500, "applied but could not be recorded (syslog retention change)", true},
		{"in effect, then failed", applied, errors.New("delete chunk syslog-1: access denied"), 500, "the new syslog retention is in effect (applied), but the change could not be completed: delete chunk", true},
		{"ledger broken", model.ConfigChange{}, fmt.Errorf("append: %w", contracts.ErrLedgerBroken), 503, "nothing can be recorded until att-monitor restarts", false},
		{"busy", model.ConfigChange{}, fmt.Errorf("pruning: %w", contracts.ErrBusy), 409, "syslog retention change: pruning", false},
		{"unavailable", model.ConfigChange{}, fmt.Errorf("no syslog store: %w", contracts.ErrUnavailable), 503, "no syslog store", false},
		{"failed", model.ConfigChange{Result: "failed: config not saved"}, errors.New("save config: disk full"), 500, "syslog retention change: save config: disk full", true},
		{"timeout", model.ConfigChange{}, context.DeadlineExceeded, 504, "timed out", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hs := newHarness(t)
			hs.syslogCtl.change, hs.syslogCtl.err = tc.change, tc.err
			rec := hs.post(retentionURL, `{"keep_mb":50}`)
			wantStatus(t, rec, tc.code)
			e := decode[ConfigChangeError](t, rec)
			if !strings.Contains(e.Error, tc.contains) {
				t.Errorf("error %q does not say %q", e.Error, tc.contains)
			}
			if (e.Change != nil) != tc.withCC || (e.Change != nil && *e.Change != tc.change) {
				t.Errorf("change = %+v, want %v", e.Change, tc.withCC)
			}
			assertSecurityHeaders(t, rec.Header(), false)
		})
	}

	// Without a control of the syslog store: 404, as JSON, for any body.
	hs := newHarness(t)
	hs.srv.syslogCtl = nil
	for _, body := range []string{`{"keep_mb":50}`, `{`} {
		if msg := wantJSONError(t, hs.post(retentionURL, body), http.StatusNotFound); !strings.Contains(msg, "cannot be changed here") {
			t.Errorf("message = %q", msg)
		}
	}
}

// POST /api/syslog/retention deletes evidence that no longer fits: the same protections as
// every state-changing endpoint apply, and none of the rejected requests reaches the monitor.
func TestSyslogRetentionProtections(t *testing.T) {
	big := `{"keep_mb":100,"client":"` + strings.Repeat("a", MaxBodyBytes) + `"}`
	tests := []struct {
		name string
		req  func(hs *harness) *http.Request
		code int
	}{
		{"missing header", func(hs *harness) *http.Request {
			return hs.request(http.MethodPost, retentionURL, strings.NewReader(`{"keep_mb":1}`), map[string]string{CSRFHeader: ""})
		}, http.StatusForbidden},
		{"wrong header value", func(hs *harness) *http.Request {
			return hs.request(http.MethodPost, retentionURL, strings.NewReader(`{"keep_mb":1}`), map[string]string{CSRFHeader: "yes"})
		}, http.StatusForbidden},
		{"cross origin", func(hs *harness) *http.Request {
			return hs.request(http.MethodPost, retentionURL, strings.NewReader(`{"keep_mb":1}`), map[string]string{"Origin": "http://evil.example"})
		}, http.StatusForbidden},
		{"null origin (sandboxed page)", func(hs *harness) *http.Request {
			return hs.request(http.MethodPost, retentionURL, strings.NewReader(`{"keep_mb":1}`), map[string]string{"Origin": "null"})
		}, http.StatusForbidden},
		{"cross-site fetch metadata", func(hs *harness) *http.Request {
			return hs.request(http.MethodPost, retentionURL, strings.NewReader(`{"keep_mb":1}`), map[string]string{"Sec-Fetch-Site": "cross-site"})
		}, http.StatusForbidden},
		{"foreign Host", func(hs *harness) *http.Request {
			r := hs.request(http.MethodPost, retentionURL, strings.NewReader(`{"keep_mb":1}`), nil)
			r.Host = "evil.example:8320"
			return r
		}, http.StatusMisdirectedRequest},
		{"declared body over the limit", func(hs *harness) *http.Request {
			return hs.request(http.MethodPost, retentionURL, strings.NewReader(big), nil)
		}, http.StatusRequestEntityTooLarge},
		{"chunked body over the limit", func(hs *harness) *http.Request {
			r := hs.request(http.MethodPost, retentionURL, io.MultiReader(strings.NewReader(big)), nil)
			r.ContentLength = -1
			return r
		}, http.StatusRequestEntityTooLarge},
		{"GET", func(hs *harness) *http.Request { return hs.request(http.MethodGet, retentionURL, nil, nil) }, http.StatusMethodNotAllowed},
		{"PUT", func(hs *harness) *http.Request {
			return hs.request(http.MethodPut, retentionURL, strings.NewReader(`{"keep_mb":1}`), map[string]string{CSRFHeader: CSRFHeaderValue})
		}, http.StatusMethodNotAllowed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hs := newHarness(t)
			rec := hs.serve(tc.req(hs))
			wantJSONError(t, rec, tc.code)
			assertSecurityHeaders(t, rec.Header(), false)
			if tc.code == http.StatusMethodNotAllowed && rec.Header().Get("Allow") != "POST" {
				t.Errorf("Allow = %q", rec.Header().Get("Allow"))
			}
			if n := len(hs.syslogCtl.callList()); n != 0 {
				t.Errorf("a rejected request reached SetSyslogRetention (%d calls)", n)
			}
		})
	}
	// The same request from this origin, through the browser's checks, is fine.
	hs := newHarness(t)
	wantStatus(t, hs.serve(hs.request(http.MethodPost, retentionURL, strings.NewReader(`{"keep_mb":1}`),
		map[string]string{"Origin": testOrigin, "Sec-Fetch-Site": "same-origin"})), http.StatusOK)
}

func TestSyslogRetentionIsSingleFlightAndDetached(t *testing.T) {
	hs := newHarness(t)
	hs.syslogCtl.in = make(chan struct{}, 1)
	hs.syslogCtl.gate = make(chan struct{})
	done := make(chan int, 1)
	go func() { done <- hs.post(retentionURL, `{"keep_mb":10}`).Code }()
	<-hs.syslogCtl.in
	if msg := wantJSONError(t, hs.post(retentionURL, `{"keep_mb":20}`), http.StatusConflict); !strings.Contains(msg, "already in progress") {
		t.Errorf("message = %q", msg)
	}
	close(hs.syslogCtl.gate)
	if code := <-done; code != http.StatusOK {
		t.Fatalf("first change = %d", code)
	}
	if calls := hs.syslogCtl.callList(); len(calls) != 1 || calls[0].keepMB != 10 {
		t.Errorf("calls = %+v", calls)
	}

	// Closing the browser tab does not interrupt a change half-way.
	hs = newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	wantStatus(t, hs.serve(hs.request(http.MethodPost, retentionURL, strings.NewReader(`{"keep_mb":10}`), nil).WithContext(ctx)), http.StatusOK)
	if calls := hs.syslogCtl.callList(); len(calls) != 1 || calls[0].ctxErr != nil {
		t.Errorf("calls = %+v", calls)
	}
}
