package web

// GET /api/syslog (docs/syslog-snmp-traffic.md §3.2): the messages of the recorded syslog
// batches of a period, filtered, newest first, read through the ledger reader in bounded work.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// syslogNow is the harness's clock (newHarness).
var syslogNow = time.Date(2026, 10, 5, 3, 20, 0, 0, time.UTC)

// replacementChars is what a parser makes of two bytes that are not UTF-8 (two U+FFFD).
var replacementChars = strings.Repeat(string(rune(0xFFFD)), 2)

// sysMsg is a message as the receiver records it: an RFC 3164 datagram from the gateway with
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

// appendSyslog records a batch written at ts.
func appendSyslog(r *fakeReader, ts time.Time, msgs ...model.SyslogMessage) uint64 {
	b := model.SyslogBatch{From: ts.Add(-30 * time.Second).UTC().Format(time.RFC3339Nano), To: ts.UTC().Format(time.RFC3339Nano),
		Received: len(msgs), Messages: msgs}
	return appendRecord(r, ts, model.TypeSyslog, b)
}

// syslogLedger is the ledger most tests read (n = syslogNow; m0..m10 name the messages):
//
//	#0 sample  n-30h
//	#1 syslog  n-30h+1s  m0
//	#2 syslog  n-2h      m1 (info, dhcpd), m2 (err, ponlinkd), m3 (no PRI)
//	#3 sample  n-90m
//	#4 syslog  n-1h      m4 (warning, wanmgr), m5 (emerg, kernel), m6 (not UTF-8: bytes only, no PRI)
//	#5 syslog  n-30m     m7 (debug, cwmpd), m8 (info, receive time unreadable), m9 (notice, RFC 5424)
//	#6 syslog  n         m10 (at "to": outside the default period)
func syslogLedger() *fakeReader {
	n := syslogNow
	r := &fakeReader{}
	appendRecord(r, n.Add(-30*time.Hour), model.TypeSample, map[string]int{"cycle": 1})
	appendSyslog(r, n.Add(-30*time.Hour+time.Second), sysMsg(n.Add(-30*time.Hour), 6, "BGW320", "syslogd", "[m0] restart"))
	appendSyslog(r, n.Add(-2*time.Hour),
		sysMsg(n.Add(-2*time.Hour-20*time.Second), 6, "BGW320", "dhcpd", "[m1] DHCPACK on 192.168.1.71 to 02:00:00:00:00:71 via br0"),
		sysMsg(n.Add(-2*time.Hour-10*time.Second), 3, "BGW320", "ponlinkd", "[m2] PON link state O5 -> O1 (LOS)"),
		sysMsg(n.Add(-2*time.Hour-5*time.Second), -1, "", "", "[m3] watchdog ok"))
	appendRecord(r, n.Add(-90*time.Minute), model.TypeSample, map[string]int{"cycle": 2})
	m6 := model.SyslogMessage{RX: n.Add(-time.Hour - 3*time.Second).Format(time.RFC3339Nano), Src: "192.168.1.254:514",
		RawB64: "PDMwPndpZmlkOiBTU0lEIP/+", Format: "unknown", App: "wifid", Msg: "[m6] SSID " + replacementChars}
	appendSyslog(r, n.Add(-time.Hour),
		sysMsg(n.Add(-time.Hour-5*time.Second), 4, "BGW320", "wanmgr", "[m4] WAN DHCP lease renewal failed"),
		sysMsg(n.Add(-time.Hour-time.Second), 0, "BGW320", "kernel", "[m5] Kernel panic - not syncing"),
		m6)
	m8 := sysMsg(n.Add(-30*time.Minute-3*time.Second), 6, "BGW320", "ntpd", "[m8] time synchronized")
	m8.RX = "garbage"
	m9 := sysMsg(n.Add(-30*time.Minute-time.Second), 5, "BGW320-505.attlocal.net", "TR069", "[m9] Periodic Inform")
	m9.Format, m9.TS = "rfc5424", n.Add(-30*time.Minute-time.Second).Format(time.RFC3339Nano)
	m9.Raw = "<133>1 " + m9.TS + " BGW320-505.attlocal.net TR069 - - - [m9] Periodic Inform"
	appendSyslog(r, n.Add(-30*time.Minute), sysMsg(n.Add(-30*time.Minute-2*time.Second), 7, "bgw320-505", "cwmpd", "[m7] Inform sent"), m8, m9)
	appendSyslog(r, n, sysMsg(n.Add(-time.Second), 6, "BGW320", "syslogd", "[m10] at the end"))
	return r
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

func syslogHarness(t *testing.T) *harness {
	t.Helper()
	hs := newHarness(t)
	hs.reader = syslogLedger()
	hs.srv.reader = hs.reader
	return hs
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

	// Default period: the 24 hours before now, newest first by receive time; a message whose
	// receive time does not parse is placed at its record's time.
	list := getSyslog(t, hs, nil)
	if got, want := names(list), "m8,m9,m7,m5,m6,m4,m3,m2,m1"; got != want {
		t.Errorf("messages = %s, want %s", got, want)
	}
	if list.From != n.Add(-24*time.Hour).Format(time.RFC3339Nano) || list.To != n.Format(time.RFC3339Nano) || list.Truncated {
		t.Errorf("from %s to %s truncated %v", list.From, list.To, list.Truncated)
	}
	// Each message carries its record, and the message exactly as recorded.
	if m := list.Messages[1]; m.Seq != 5 || m.Format != "rfc5424" || m.Host != "BGW320-505.attlocal.net" || m.Severity == nil || *m.Severity != 5 ||
		m.Raw != "<133>1 "+m.TS+" BGW320-505.attlocal.net TR069 - - - [m9] Periodic Inform" || m.Src != "192.168.1.254:514" {
		t.Errorf("m9 = %+v", m)
	}
	if m := list.Messages[4]; m.Seq != 4 || m.Raw != "" || m.RawB64 != "PDMwPndpZmlkOiBTU0lEIP/+" || m.Severity != nil {
		t.Errorf("m6 = %+v", m)
	}
	if m := list.Messages[0]; m.RX != "garbage" || m.Seq != 5 {
		t.Errorf("m8 = %+v", m)
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
		{"severity info", url.Values{"severity": {"informational"}}, "m8,m9,m5,m4,m2,m1", false},
		{"severity debug", url.Values{"severity": {"debug"}}, "m8,m9,m7,m5,m4,m2,m1", false},
		{"severity 7", url.Values{"severity": {"7"}}, "m8,m9,m7,m5,m4,m2,m1", false},
		{"severity and text", url.Values{"severity": {"notice"}, "q": {"inform"}}, "m9", false},
		// limit
		{"limit 2", url.Values{"limit": {"2"}}, "m8,m9", true},
		{"limit 8", url.Values{"limit": {"8"}}, "m8,m9,m7,m5,m6,m4,m3,m2", true},
		{"limit 9", url.Values{"limit": {"9"}}, "m8,m9,m7,m5,m6,m4,m3,m2,m1", false},
		{"limit with a filter", url.Values{"limit": {"1"}, "severity": {"err"}}, "m5", true},
		// period [from, to), by the time of the record
		{"from", url.Values{"from": {n.Add(-65 * time.Minute).Format(time.RFC3339)}}, "m8,m9,m7,m5,m6,m4", false},
		{"to is exclusive", url.Values{"to": {n.Add(-time.Hour).Format(time.RFC3339)}}, "m3,m2,m1", false},
		{"older than a day", url.Values{"from": {n.Add(-31 * time.Hour).Format(time.RFC3339)}}, "m8,m9,m7,m5,m6,m4,m3,m2,m1,m0", false},
		{"to after the last record", url.Values{"to": {n.Add(time.Second).Format(time.RFC3339)}}, "m10,m8,m9,m7,m5,m6,m4,m3,m2,m1", false},
		{"from as a date", url.Values{"from": {"2026-10-05"}}, "m8,m9,m7,m5,m6,m4,m3,m2,m1", false},
		{"from as Unix seconds", url.Values{"from": {fmt.Sprint(n.Add(-35 * time.Minute).Unix())}}, "m8,m9,m7", false},
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

	// An empty list is [] (the dashboard iterates it).
	rec := hs.get("/api/syslog?q=nothing-matches-this")
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

func TestSyslogEndpointOrdersEqualTimes(t *testing.T) {
	hs := newHarness(t)
	r := &fakeReader{}
	at := syslogNow.Add(-time.Hour)
	appendSyslog(r, at, sysMsg(at, 6, "gw", "a", "[a1] first"), sysMsg(at, 6, "gw", "a", "[a2] second"))
	appendSyslog(r, at.Add(time.Second), sysMsg(at, 6, "gw", "a", "[b1] next batch"), sysMsg(at.Add(-time.Second), 6, "gw", "a", "[b2] received earlier"))
	hs.srv.reader = r
	// Equal receive times: the later record first, and within a record the later message.
	if got := names(getSyslog(t, hs, nil)); got != "b1,a2,a1,b2" {
		t.Errorf("order = %s, want b1,a2,a1,b2", got)
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
			hs.reader.mu.Lock()
			hs.reader.timeScans = nil
			hs.reader.mu.Unlock()
			msg := wantJSONError(t, hs.get("/api/syslog?"+q), http.StatusBadRequest)
			if name, _, _ := strings.Cut(q, "="); !strings.Contains(msg, name) && name != "from" && name != "to" {
				t.Errorf("message %q does not name the parameter %s", msg, name)
			}
			if len(hs.reader.timeScans) != 0 {
				t.Error("an invalid request read the ledger")
			}
		})
	}
	// Exactly 31 days and exactly MaxSyslogQueryChars characters are fine, and empty parameters
	// are the defaults.
	wantStatus(t, hs.get("/api/syslog?from=2026-09-04T00:00:00Z&to=2026-10-05T00:00:00Z"), http.StatusOK)
	wantStatus(t, hs.get("/api/syslog?q="+strings.Repeat("é", MaxSyslogQueryChars)), http.StatusOK)
	if list := getSyslog(t, hs, url.Values{"from": {""}, "to": {""}, "q": {""}, "severity": {""}, "limit": {""}}); names(list) != "m8,m9,m7,m5,m6,m4,m3,m2,m1" {
		t.Errorf("empty parameters: %s", names(list))
	}
}

func TestSyslogEndpointLimitIsClamped(t *testing.T) {
	hs := newHarness(t)
	r := &fakeReader{}
	base := syslogNow.Add(-2 * time.Hour)
	k := 0
	for i := 0; i < 12; i++ {
		ts := base.Add(time.Duration(i) * time.Minute)
		msgs := make([]model.SyslogMessage, 500)
		for j := range msgs {
			msgs[j] = sysMsg(ts.Add(-time.Duration(500-j)*time.Millisecond), 6, "gw", "fw", fmt.Sprintf("[m%d] drop", k))
			k++
		}
		appendSyslog(r, ts, msgs...)
	}
	hs.srv.reader = r
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
}

// A request for a week whose newest day already holds enough messages reads that day only: the
// records of the older days are never handed over.
func TestSyslogEndpointReadsNewestDaysFirst(t *testing.T) {
	hs := newHarness(t)
	r := &fakeReader{}
	start := syslogNow.Add(-7 * 24 * time.Hour)
	for ts := start; ts.Before(syslogNow); ts = ts.Add(time.Hour) {
		appendRecord(r, ts, model.TypeSample, map[string]int{"cycle": 1})
		if ts.Hour()%2 == 0 {
			tag := fmt.Sprintf("d%02d%02d", ts.Day(), ts.Hour())
			appendSyslog(r, ts.Add(time.Minute),
				sysMsg(ts.Add(10*time.Second), 6, "gw", "dhcpd", "["+tag+"] lease"),
				sysMsg(ts.Add(20*time.Second), 4, "gw", "wanmgr", "["+tag+"] link"),
				sysMsg(ts.Add(30*time.Second), 6, "gw", "dhcpd", "["+tag+"] lease"))
		}
	}
	hs.srv.reader = r
	week := url.Values{"from": {start.Format(time.RFC3339)}}
	midnight := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)

	reset := func() {
		r.mu.Lock()
		r.timeScans = nil
		r.mu.Unlock()
		r.callbacks.Store(0)
	}
	reset()
	q := url.Values{"from": week["from"], "limit": {"5"}}
	list := getSyslog(t, hs, q)
	if len(list.Messages) != 5 || !list.Truncated || list.Messages[0].RX != midnight.Add(2*time.Hour+20*time.Minute+30*time.Second).Format(time.RFC3339Nano) {
		t.Fatalf("newest 5 = %s truncated %v", names(list), list.Truncated)
	}
	if len(r.timeScans) != 1 || !r.timeScans[0][0].Equal(midnight) || !r.timeScans[0][1].Equal(syslogNow) {
		t.Errorf("periods read: %v, want only today's [%v, %v)", r.timeScans, midnight, syslogNow)
	}
	if n := r.callbacks.Load(); n != 5 { // today: samples at 00:20, 01:20, 02:20 and the batches of 00:21, 02:21
		t.Errorf("%d records handed over, want 5 (today's)", n)
	}

	// Everything: every day is read, newest first, and the periods tile [from, to) exactly.
	reset()
	list = getSyslog(t, hs, url.Values{"from": week["from"], "limit": {"5000"}})
	if len(list.Messages) != 7*12*3 || list.Truncated {
		t.Fatalf("%d messages, truncated %v; want %d", len(list.Messages), list.Truncated, 7*12*3)
	}
	if len(r.timeScans) != 8 {
		t.Fatalf("periods read: %v", r.timeScans)
	}
	end := syslogNow
	for i, p := range r.timeScans {
		if !p[1].Equal(end) || !p[0].Before(p[1]) || (i < 7 && !p[0].Equal(p[0].Truncate(24*time.Hour))) {
			t.Errorf("period %d: %v", i, p)
		}
		end = p[0]
	}
	if !end.Equal(start) {
		t.Errorf("periods end at %v, want %v", end, start)
	}
	for i := 1; i < len(list.Messages); i++ {
		if list.Messages[i-1].RX < list.Messages[i].RX { // same layout and length here
			t.Fatalf("not newest first at %d: %s before %s", i, list.Messages[i-1].RX, list.Messages[i].RX)
		}
	}

	// A filter only the oldest day matches reads every day too.
	reset()
	list = getSyslog(t, hs, url.Values{"from": week["from"], "q": {"[d2804]"}, "limit": {"1"}})
	if names(list) != "d2804" || !list.Truncated || len(r.timeScans) != 8 {
		t.Errorf("oldest day: %s truncated %v after %d periods", names(list), list.Truncated, len(r.timeScans))
	}
}

// Messages received shortly before midnight are recorded after it. Reading stops only when no
// earlier record can hold a message received later than those kept.
func TestSyslogEndpointNewestFirstAcrossMidnight(t *testing.T) {
	hs := newHarness(t)
	r := &fakeReader{}
	mid := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	appendSyslog(r, mid.Add(-2*time.Second), sysMsg(mid.Add(-3*time.Second), 6, "gw", "a", "[b] before midnight"))
	appendSyslog(r, mid.Add(10*time.Second),
		sysMsg(mid.Add(-20*time.Second), 6, "gw", "a", "[a0] received before midnight"),
		sysMsg(mid.Add(-10*time.Second), 6, "gw", "a", "[a1] received before midnight"),
		sysMsg(mid.Add(6*time.Second), 6, "gw", "a", "[a3] after"))
	hs.srv.reader = r
	for limit, want := range map[int]string{1: "a3", 2: "a3,b", 3: "a3,b,a1", 4: "a3,b,a1,a0", 10: "a3,b,a1,a0"} {
		list := getSyslog(t, hs, url.Values{"from": {mid.Add(-time.Hour).Format(time.RFC3339)}, "limit": {fmt.Sprint(limit)}})
		if got := names(list); got != want || list.Truncated != (limit < 4) {
			t.Errorf("limit %d: %s truncated %v, want %s", limit, got, list.Truncated, want)
		}
	}
}

func TestSyslogEndpointIntegrityProblems(t *testing.T) {
	hs := syslogHarness(t)
	// #4 edited after it was written (h no longer covers b), and a record whose data is not a batch.
	rewrite(hs.reader, 4, false, func(b *model.Body) {
		var batch model.SyslogBatch
		if err := json.Unmarshal(b.Data, &batch); err != nil {
			panic(err)
		}
		batch.Messages[0].Msg = "[m4] edited"
		b.Data, _ = json.Marshal(batch)
	})
	bad := appendRecord(hs.reader, syslogNow.Add(-10*time.Minute), model.TypeSyslog, json.RawMessage(`{"messages":"not a list"}`))

	rec := hs.get("/api/syslog")
	wantStatus(t, rec, http.StatusOK)
	warn := rec.Header().Get(WarningHeader)
	for _, want := range []string{"ledger integrity", "#4 h does not match b", fmt.Sprintf("#%d syslog data does not parse", bad), "Verify"} {
		if !strings.Contains(warn, want) {
			t.Errorf("warning %q does not say %q", warn, want)
		}
	}
	// The edited record is listed as found (the records view flags it); the damaged one is skipped.
	list := decode[model.SyslogList](t, rec)
	if got := names(list); got != "m8,m9,m7,m5,m6,m4,m3,m2,m1" {
		t.Errorf("messages = %s", got)
	}
	if list.Messages[5].Msg != "[m4] edited" {
		t.Errorf("m4 = %+v", list.Messages[5])
	}
	// A period without the damage stays quiet.
	if w := hs.get("/api/syslog?to=" + url.QueryEscape(syslogNow.Add(-90*time.Minute).Format(time.RFC3339))).Header().Get(WarningHeader); w != "" {
		t.Errorf("unexpected warning %q", w)
	}
}

func TestSyslogEndpointErrors(t *testing.T) {
	hs := syslogHarness(t)
	hs.reader.scanTimeErr = errors.New("ledger: read segment ledger-2026-10-05: unexpected EOF")
	msg := wantJSONError(t, hs.get("/api/syslog"), http.StatusInternalServerError)
	if !strings.Contains(msg, "syslog: ledger: read segment") {
		t.Errorf("message = %q", msg)
	}
	hs.reader.scanTimeErr = fmt.Errorf("ledger closed: %w", contracts.ErrUnavailable)
	wantJSONError(t, hs.get("/api/syslog"), http.StatusServiceUnavailable)
	hs.reader.scanTimeErr = nil

	// The client went away: the read stops.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := hs.reader.callbacks.Load()
	wantJSONError(t, hs.serve(hs.request(http.MethodGet, "/api/syslog", nil, nil).WithContext(ctx)), http.StatusServiceUnavailable)
	if n := hs.reader.callbacks.Load() - before; n > 1 {
		t.Errorf("%d records handed over after the request was cancelled", n)
	}

	hs.srv.reader = nil
	wantJSONError(t, hs.get("/api/syslog"), http.StatusServiceUnavailable)
}

// /api/syslog is behind the same middleware as every other endpoint: a request with a foreign
// Host (DNS rebinding) never reaches it, only GET and HEAD are served, every response carries
// the security headers, and nothing grants another origin access to the answer.
func TestSyslogEndpointSecurity(t *testing.T) {
	hs := syslogHarness(t)
	for _, host := range []string{"evil.example:8320", "evil.example", "127.0.0.1.nip.io:8320", "192.168.1.71:8320"} {
		req := hs.request(http.MethodGet, "/api/syslog", nil, nil)
		req.Host = host
		rec := hs.serve(req)
		wantJSONError(t, rec, http.StatusMisdirectedRequest)
		assertSecurityHeaders(t, rec.Header(), false)
	}
	if len(hs.reader.timeScans) != 0 {
		t.Fatal("a request with a foreign Host read the ledger")
	}

	for _, hdr := range []map[string]string{nil, {"Origin": "http://evil.example", "Sec-Fetch-Site": "cross-site"}} {
		rec := hs.serve(hs.request(http.MethodGet, "/api/syslog", nil, hdr))
		wantStatus(t, rec, http.StatusOK)
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

func TestSyslogWindows(t *testing.T) {
	d := func(day, hour, minute int) time.Time { return time.Date(2026, 10, day, hour, minute, 0, 0, time.UTC) }
	type win = [2]time.Time
	tests := []struct {
		name     string
		from, to time.Time
		want     []win
	}{
		{"within a day", d(5, 1, 0), d(5, 3, 20), []win{{d(5, 1, 0), d(5, 3, 20)}}},
		{"three days", d(3, 12, 0), d(5, 3, 20), []win{{d(5, 0, 0), d(5, 3, 20)}, {d(4, 0, 0), d(5, 0, 0)}, {d(3, 12, 0), d(4, 0, 0)}}},
		{"ends at midnight", d(4, 0, 0), d(5, 0, 0), []win{{d(4, 0, 0), d(5, 0, 0)}}},
		{"starts at midnight", d(4, 0, 0), d(5, 0, 1), []win{{d(5, 0, 0), d(5, 0, 1)}, {d(4, 0, 0), d(5, 0, 0)}}},
		{"other time zone", d(4, 22, 0).In(time.FixedZone("UTC+2", 2*3600)), d(5, 3, 0).In(time.FixedZone("UTC-5", -5*3600)),
			[]win{{d(5, 0, 0), d(5, 3, 0)}, {d(4, 22, 0), d(5, 0, 0)}}},
		{"empty", d(5, 1, 0), d(5, 1, 0), nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := syslogWindows(tc.from, tc.to)
			if len(got) != len(tc.want) {
				t.Fatalf("windows = %v, want %v", got, tc.want)
			}
			for i := range got {
				if !got[i][0].Equal(tc.want[i][0]) || !got[i][1].Equal(tc.want[i][1]) {
					t.Errorf("window %d = %v, want %v", i, got[i], tc.want[i])
				}
			}
		})
	}
}
