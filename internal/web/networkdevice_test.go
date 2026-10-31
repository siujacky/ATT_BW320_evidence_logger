package web

// GET /api/network/device (docs/dhcp-table.md §7): one device's details from the network view,
// with its syslog messages - those the view's terms find - from the syslog store, newest first,
// each linked to its chunk's syslog_chunk record; parameters checked before the view is asked,
// errors mapped as the other network endpoints map them.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// Device answers the detail a test sets (f.detail), or f.err, recording the call (q in calls, the
// key and the address in asked).
func (f *fakeNetwork) Device(ctx context.Context, q contracts.NetQuery, key, addr string) (model.NetDeviceDetail, error) {
	f.mu.Lock()
	f.asked = append(f.asked, [2]string{key, addr})
	f.mu.Unlock()
	if err := f.record(ctx, "device", q); err != nil {
		return model.NetDeviceDetail{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.detail, nil
}

// takeAsked returns the keys and addresses Device was asked for so far and forgets them.
func (f *fakeNetwork) takeAsked() [][2]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := f.asked
	f.asked = nil
	return a
}

// deviceLaptop is the laptop's details as the view gives them (documentation addresses only): it
// held 192.168.1.70 from 3 to 1 hours before now, then 192.168.1.71.
func deviceLaptop() model.NetDeviceDetail {
	n := syslogNow
	ts := func(d time.Duration) string { return n.Add(d).Format(time.RFC3339Nano) }
	return model.NetDeviceDetail{
		From: ts(-24 * time.Hour), To: ts(0),
		Device: &model.NetLANDevice{Key: "mac:00:00:5e:00:53:21", Name: "laptop", MAC: "00:00:5e:00:53:21", IPv4: "192.168.1.71",
			IPv6: []string{"2001:db8::21"}, Status: "on", Connection: "Wi-Fi 5 GHz", Signal: 4, Addresses: []string{"192.168.1.71", "192.168.1.70"},
			ScanAddr: "192.168.1.71", ScanSeen: ts(-30 * time.Minute), ScanHits: 20,
			Issues: []model.NetIssue{{Code: model.IssueAddressChanged, Level: model.IssueInfo, Text: "It held 2 IPv4 addresses in this period."}}},
		Addresses: []model.NetAddrUse{
			{Addr: "192.168.1.70", Device: "mac:00:00:5e:00:53:21", Name: "laptop", First: ts(-150 * time.Minute), Last: ts(-75 * time.Minute), Reads: 6},
			{Addr: "192.168.1.70", Device: "mac:00:00:5e:00:53:22", Name: "tablet", First: ts(-30 * time.Minute), Last: ts(-15 * time.Minute), Reads: 2},
		},
		Scans: []model.NetScanSeen{{At: ts(-30 * time.Minute), Addr: "192.168.1.71"}, {At: ts(-90 * time.Minute)}},
		Match: []model.NetSyslogTerm{
			{Kind: "ipv4", Text: "192.168.1.70", From: ts(-3 * time.Hour), To: ts(-time.Hour)},
			{Kind: "ipv4", Text: "192.168.1.71", From: ts(-time.Hour)},
			{Kind: "ipv6", Text: "2001:db8::21"},
			{Kind: "mac", Text: "00:00:5e:00:53:21"},
		},
	}
}

// deviceWorld is the syslog store and the ledger the laptop's messages are found in (n = syslogNow;
// d1..d11 name the messages, + those the laptop's terms find):
//
//	chunk c1 (sealed)  d1 n-5h .70 (before it held it), d2 n-150m .70 +, d3 n-140m .170,
//	                   d4 n-130m DHCPACK .70 and its MAC +                       #1 at n-2h
//	chunk c2 (sealed)  d5 n-90m to 2001:db8::21 +, d6 n-70m 10.192.168.1.71,
//	                   d8 n-55m .70 (no longer its), d7 n-50m .71 +            #2 at n-45m
//	chunk c3 (open)    d9 n-10m its MAC in the MAC field +, d10 n-5m Wi-Fi, its MAC in dashes +,
//	                   d11 n-1m 192.168.1.7
func deviceWorld() (*fakeSyslogStore, *fakeReader) {
	n := syslogNow
	const gw, laptop, other = "00:00:5e:00:53:fe", "00:00:5e:00:53:21", "00:00:5e:00:53:01"
	fw := func(at time.Duration, name, line string) model.SyslogMessage {
		m := sysMsg(n.Add(at), 4, "dsldevice", "FIREWALL[8512]", "["+name+"] "+line)
		return m
	}
	store := &fakeSyslogStore{chunks: []*fakeChunk{
		{name: "c1", sealed: true, msgs: []model.SyslogMessage{
			fw(-5*time.Hour, "d1", fwDrop(gw, other, " ", "192.168.1.70", "192.0.2.44")),
			fw(-150*time.Minute, "d2", fwDrop(gw, other, " ", "192.168.1.70", "192.0.2.44")),
			fw(-140*time.Minute, "d3", fwDrop(gw, other, " ", "192.168.1.170", "192.0.2.44")),
			sysMsg(n.Add(-130*time.Minute), 6, "dsldevice", "dnsmasq-dhcp[1234]", "[d4] DHCPACK(br1) 192.168.1.70 "+laptop+" laptop"),
		}},
		{name: "c2", sealed: true, msgs: []model.SyslogMessage{
			fw(-90*time.Minute, "d5", fwIn("2001:db8:9::7", "2001:db8::21")),
			fw(-70*time.Minute, "d6", fwDrop(gw, other, " ", "10.192.168.1.71", "192.0.2.44")),
			fw(-55*time.Minute, "d8", fwDrop(gw, other, ":", "192.168.1.70", "192.0.2.44")),
			fw(-50*time.Minute, "d7", fwDrop(gw, other, ":", "192.168.1.71", "192.0.2.44")),
		}},
		{name: "c3", msgs: []model.SyslogMessage{
			fw(-10*time.Minute, "d9", fwDrop(gw, laptop, " ", "192.168.1.99", "192.0.2.44")),
			sysMsg(n.Add(-5*time.Minute), 5, "dsldevice", "wlmngr", "[d10] wl0: 00-00-5E-00-53-21 associated"),
			fw(-time.Minute, "d11", fwDrop(gw, other, " ", "192.168.1.7", "192.0.2.44")),
		}},
	}}
	r := &fakeReader{}
	appendRecord(r, n.Add(-6*time.Hour), model.TypeSample, map[string]int{"cycle": 1}) // #0
	appendChunkRecord(r, n.Add(-2*time.Hour), store.chunks[0])
	appendChunkRecord(r, n.Add(-45*time.Minute), store.chunks[1])
	return store, r
}

// deviceHarness serves the laptop's details over deviceWorld.
func deviceHarness(t *testing.T) (*harness, *fakeNetwork) {
	t.Helper()
	hs, nv := netHarness(t)
	hs.syslog, hs.reader = deviceWorld()
	hs.srv.syslog, hs.srv.reader = hs.syslog, hs.reader
	nv.detail = deviceLaptop()
	return hs, nv
}

// deviceNames lists the [dN] names of a detail's messages with the seq of their chunk record.
func deviceNames(dd model.NetDeviceDetail) string {
	return seqs(model.SyslogList{Messages: dd.Syslog})
}

// TestNetworkDeviceEndpoint: the view's details are passed on as given, with the syslog messages its
// terms find - an IPv4 address only while the device held it, its IPv6 address, its MAC address in
// the firewall's MAC field and in dashes -, newest first, each with its chunk's record.
func TestNetworkDeviceEndpoint(t *testing.T) {
	hs, nv := deviceHarness(t)
	rec := hs.get("/api/network/device?key=" + url.QueryEscape("mac:00:00:5e:00:53:21") + "&range=24h")
	wantStatus(t, rec, http.StatusOK)
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	assertSecurityHeaders(t, rec.Header(), false)
	dd := decode[model.NetDeviceDetail](t, rec)
	if got := deviceNames(dd); got != "d10:0,d9:0,d7:2,d5:2,d4:1,d2:1" {
		t.Errorf("messages %s", got)
	}
	if dd.SyslogTruncated || dd.SyslogError != "" || rec.Header().Get(WarningHeader) != "" {
		t.Errorf("truncated %v, error %q, warning %q", dd.SyslogTruncated, dd.SyslogError, rec.Header().Get(WarningHeader))
	}
	want := deviceLaptop()
	got := dd
	got.Syslog = nil
	if !jsonEqual(got, want) {
		t.Errorf("details not passed on as given:\n got %+v\nwant %+v", got, want)
	}
	if m := dd.Syslog[1]; m.Chunk != "c3" || m.Severity == nil || *m.Severity != 4 || !strings.Contains(m.Raw, "MAC=00:00:5e:00:53:fe:00:00:5e:00:53:21:08:00") {
		t.Errorf("d9 = %+v", m)
	}
	for _, want := range []string{`"syslog_truncated":false`, `"scan_hits":20`, `"match":[{"kind":"ipv4","text":"192.168.1.70","from":"`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("answer lacks %s: %s", want, rec.Body.String())
		}
	}
	calls := nv.takeCalls()
	if len(calls) != 1 || calls[0].what != "device" {
		t.Fatalf("calls %+v", calls)
	}
	if q := calls[0].q; !q.From.Equal(netNow.Add(-24*time.Hour)) || !q.To.Equal(netNow) || q.Range != "24h" || q.Device != "" || q.Limit != 0 {
		t.Errorf("query %+v", q)
	}
	if d := calls[0].deadline; d <= 0 || d > networkTimeout {
		t.Errorf("the view had %v until its deadline, want at most %v", d, networkTimeout)
	}
	if asked := nv.takeAsked(); len(asked) != 1 || asked[0] != [2]string{"mac:00:00:5e:00:53:21", ""} {
		t.Errorf("asked %q", asked)
	}
	queries, _ := hs.syslog.calls()
	if len(queries) != 1 || !queries[0].filtered || queries[0].limit != DefaultDeviceSyslogLimit || !queries[0].from.Equal(netNow.Add(-24*time.Hour)) ||
		!queries[0].to.Equal(netNow) {
		t.Errorf("store asked %+v", queries)
	}

	// The limit, and more than asked for.
	for _, tc := range []struct {
		query string
		names string
		limit int
		trunc bool
	}{
		{"&limit=2", "d10:0,d9:0", 2, true},
		{"&limit=6", "d10:0,d9:0,d7:2,d5:2,d4:1,d2:1", 6, false},
		{"&limit=100000", "d10:0,d9:0,d7:2,d5:2,d4:1,d2:1", MaxDeviceSyslogLimit, false},
		{"&limit=", "d10:0,d9:0,d7:2,d5:2,d4:1,d2:1", DefaultDeviceSyslogLimit, false},
	} {
		dd := decode[model.NetDeviceDetail](t, hs.get("/api/network/device?key=mac:00:00:5e:00:53:21"+tc.query))
		if got := deviceNames(dd); got != tc.names || dd.SyslogTruncated != tc.trunc {
			t.Errorf("%s: %s truncated %v, want %s %v", tc.query, got, dd.SyslogTruncated, tc.names, tc.trunc)
		}
		if q, _ := hs.syslog.calls(); len(q) != 1 || q[0].limit != tc.limit {
			t.Errorf("%s: store asked %+v", tc.query, q)
		}
	}
	// A store that answers more than the limit: cut to it, and more matched.
	hs.syslog.extra = 3
	if dd := decode[model.NetDeviceDetail](t, hs.get("/api/network/device?key=mac:00:00:5e:00:53:21&limit=1")); deviceNames(dd) != "d10:0" || !dd.SyslogTruncated {
		t.Errorf("a store that answers more: %s %v", deviceNames(dd), dd.SyslogTruncated)
	}
	hs.syslog.extra = 0

	// An unknown address: asked for by its address (in canonical form); from and to as for the others.
	nv.takeCalls()
	nv.takeAsked()
	nv.detail = model.NetDeviceDetail{Unknown: &model.NetUnknownAddr{Addr: "192.168.1.70", MAC: "00:00:5e:00:53:99"},
		Match: []model.NetSyslogTerm{{Kind: "ipv4", Text: "192.168.1.70"}}}
	rec = hs.get("/api/network/device?addr=+192.168.1.70+&from=2026-10-04T03:20:00Z&to=2026-10-05T03:20:00Z")
	wantStatus(t, rec, http.StatusOK)
	dd = decode[model.NetDeviceDetail](t, rec)
	if got := deviceNames(dd); got != "d8:2,d4:1,d2:1,d1:1" {
		t.Errorf("unknown address: %s", got)
	}
	if dd.From != "2026-10-04T03:20:00Z" || dd.To != "2026-10-05T03:20:00Z" || dd.Device != nil || dd.Unknown == nil || dd.Unknown.Issues == nil {
		t.Errorf("unknown address: %+v", dd)
	}
	if asked := nv.takeAsked(); len(asked) != 1 || asked[0] != [2]string{"", "192.168.1.70"} {
		t.Errorf("asked %q", asked)
	}
	if calls := nv.takeCalls(); len(calls) != 1 || calls[0].q.Range != "" || !calls[0].q.From.Equal(netNow.Add(-24*time.Hour)) {
		t.Errorf("calls %+v", calls)
	}
	wantStatus(t, hs.serve(hs.request(http.MethodHead, "/api/network/device?addr=192.168.1.70", nil, nil)), http.StatusOK)
}

// TestNetworkDeviceAnswerIsCompleted: lists the view left nil are sent as [], the period filled in,
// without changing what the view returned; a detail whose terms find nothing does not ask the
// store.
func TestNetworkDeviceAnswerIsCompleted(t *testing.T) {
	hs, nv := deviceHarness(t)
	nv.detail = model.NetDeviceDetail{Device: &model.NetLANDevice{Key: "name:printer"}}
	rec := hs.get("/api/network/device?key=name:printer&range=1h")
	wantStatus(t, rec, http.StatusOK)
	body := rec.Body.String()
	for _, want := range []string{`"from":"2026-10-05T02:20:00Z"`, `"to":"2026-10-05T03:20:00Z"`, `"addresses":[]`, `"scans":[]`, `"match":[]`,
		`"syslog":[]`, `"syslog_truncated":false`, `"issues":[]`} {
		if !strings.Contains(body, want) {
			t.Errorf("answer lacks %s: %s", want, body)
		}
	}
	if strings.Contains(body, "null") || strings.Contains(body, "syslog_error") {
		t.Errorf("answer: %s", body)
	}
	if nv.detail.Device.Issues != nil {
		t.Error("completing the answer changed the view's device")
	}
	if q, _ := hs.syslog.calls(); len(q) != 0 {
		t.Errorf("terms that find nothing asked the store: %+v", q)
	}
	// Terms the view gives that find nothing are left out alike.
	nv.detail.Match = []model.NetSyslogTerm{{Kind: "hostname", Text: "printer"}, {Kind: "ipv4", Text: "bogus"}}
	wantStatus(t, hs.get("/api/network/device?key=name:printer"), http.StatusOK)
	if q, _ := hs.syslog.calls(); len(q) != 0 {
		t.Errorf("terms that find nothing asked the store: %+v", q)
	}
}

// TestNetworkDeviceSyslog: without a syslog store the details have no syslog messages; a store
// that cannot be read leaves them out and says why (syslog_error), a request that ended while it
// was read is answered as such; the ledger's damage is reported as GET /api/syslog reports it; and
// the answer is bounded by its size.
func TestNetworkDeviceSyslog(t *testing.T) {
	hs, _ := deviceHarness(t)
	const path = "/api/network/device?key=mac:00:00:5e:00:53:21"
	hs.srv.syslog = nil
	rec := hs.get(path)
	wantStatus(t, rec, http.StatusOK)
	if dd := decode[model.NetDeviceDetail](t, rec); len(dd.Syslog) != 0 || dd.SyslogError != "" || dd.Device == nil || len(dd.Match) != 4 {
		t.Errorf("without a syslog store: %+v", dd)
	}
	hs.srv.syslog = hs.syslog

	hs.syslog.queryErr = errors.New("syslogstore: read chunk syslog-20261005T031500Z: unexpected EOF")
	rec = hs.get(path)
	wantStatus(t, rec, http.StatusOK)
	if dd := decode[model.NetDeviceDetail](t, rec); len(dd.Syslog) != 0 || dd.Device == nil ||
		dd.SyslogError != "the syslog messages could not be read: syslogstore: read chunk syslog-20261005T031500Z: unexpected EOF" {
		t.Errorf("a store that cannot be read: %+v", dd)
	}
	hs.syslog.queryErr = nil
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	wantJSONError(t, hs.serve(hs.request(http.MethodGet, path, nil, nil).WithContext(ctx)), http.StatusServiceUnavailable)

	// The ledger: #2 (c2's record) altered after it was written: reported, and it still links its
	// messages (the records view flags it).
	rewrite(hs.reader, 2, false, func(b *model.Body) {
		var c model.SyslogChunk
		if err := json.Unmarshal(b.Data, &c); err != nil {
			panic(err)
		}
		c.SHA256 = strings.Repeat("00", 32)
		b.Data, _ = json.Marshal(c)
	})
	rec = hs.get(path)
	wantStatus(t, rec, http.StatusOK)
	if warn := rec.Header().Get(WarningHeader); !strings.Contains(warn, "ledger integrity") || !strings.Contains(warn, "#2 h does not match b") {
		t.Errorf("warning %q", warn)
	}
	if got := deviceNames(decode[model.NetDeviceDetail](t, rec)); got != "d10:0,d9:0,d7:2,d5:2,d4:1,d2:1" {
		t.Errorf("messages %s", got)
	}

	// Messages a sender filled with control characters end the list at MaxSyslogAnswerBytes.
	flood := strings.Repeat("\x01", 8192)
	base := syslogNow.Add(-time.Hour + 123456789*time.Nanosecond)
	c := &fakeChunk{name: "flood", sealed: true}
	for i := 0; i < MaxDeviceSyslogLimit; i++ {
		c.msgs = append(c.msgs, model.SyslogMessage{RX: base.Add(time.Duration(i) * time.Millisecond).Format(time.RFC3339Nano),
			Src: "192.168.1.254:514", Raw: flood + " SRC=192.168.1.71", Format: "unknown", Msg: flood})
	}
	hs.syslog.chunks = []*fakeChunk{c}
	rec = hs.get(path + "&limit=500")
	wantStatus(t, rec, http.StatusOK)
	if size := rec.Body.Len(); size > MaxSyslogAnswerBytes+64<<10 {
		t.Fatalf("an answer of %d bytes", size)
	}
	dd := decode[model.NetDeviceDetail](t, rec)
	if len(dd.Syslog) == 0 || len(dd.Syslog) >= MaxDeviceSyslogLimit || !dd.SyslogTruncated || dd.Syslog[0].RX != c.msgs[MaxDeviceSyslogLimit-1].RX {
		t.Errorf("%d messages, truncated %v", len(dd.Syslog), dd.SyslogTruncated)
	}
}

func TestNetworkDeviceQueryParameters(t *testing.T) {
	hs, nv := deviceHarness(t)
	for _, tc := range []struct{ query, says string }{
		{"", "key (a device of GET /api/network/devices) or addr (an unknown address) is required"},
		{"range=24h", "is required"},
		{"key=&addr=", "is required"},
		{"key=mac:00:00:5e:00:53:21&addr=192.168.1.70", "not both"},
		{"key=" + url.QueryEscape("mac:00:00:5e:00:53:21\n"), "key must be a device key"},
		{"key=" + url.QueryEscape("name:Cam\x1b[2Jera"), "key must be a device key"},
		{"key=" + url.QueryEscape("name:evil‮"), "key must be a device key"},
		{"key=%FF", "key must be a device key"},
		{"key=" + strings.Repeat("k", MaxNetworkDeviceKeyBytes+1), "key must be a device key"},
		{"addr=192.168.1", "addr must be an IPv4 address"},
		{"addr=2001:db8::1", "addr must be an IPv4 address"},
		{"addr=" + url.QueryEscape("::ffff:192.168.1.70"), "addr must be an IPv4 address"},
		{"addr=192.168.1.070", "addr must be an IPv4 address"},
		{"addr=" + url.QueryEscape("<script>"), "addr must be an IPv4 address"},
		{"key=mac:00:00:5e:00:53:21&limit=0", "limit must be a positive integer (at most 500 syslog messages)"},
		{"key=mac:00:00:5e:00:53:21&limit=-1", "limit must be a positive integer"},
		{"key=mac:00:00:5e:00:53:21&limit=ten", "limit must be a positive integer"},
		{"key=mac:00:00:5e:00:53:21&range=6h", "range must be one of 1h, 24h, 7d, 30d"},
		{"key=mac:00:00:5e:00:53:21&range=24h&from=2026-10-04", "range cannot be combined"},
		{"key=mac:00:00:5e:00:53:21&from=2026-09-01&to=2026-10-05", "at most 31 days apart"},
		{"key=mac:00:00:5e:00:53:21&from=2026-10-10&to=2026-10-11", "to may be at most an hour after now"},
		{"key=mac:00:00:5e:00:53:21&device=gateway", "device: only GET /api/network/connections is filtered by device"},
	} {
		t.Run(tc.query, func(t *testing.T) {
			rec := hs.get("/api/network/device?" + tc.query)
			if msg := wantJSONError(t, rec, http.StatusBadRequest); !strings.Contains(msg, tc.says) {
				t.Errorf("message %q does not say %q", msg, tc.says)
			}
			assertSecurityHeaders(t, rec.Header(), false)
			if calls := nv.takeCalls(); len(calls) != 0 {
				t.Errorf("an invalid request reached the view: %+v", calls)
			}
			if q, _ := hs.syslog.calls(); len(q) != 0 {
				t.Errorf("an invalid request read the syslog: %+v", q)
			}
		})
	}
	// Keys as the Devices view makes them: a name with spaces and letters beyond ASCII, a second
	// entry of a MAC address; the longest key.
	for _, key := range []string{"name:Büro PC", "mac:00:00:5e:00:53:21#2", "ip:2001:db8::1", strings.Repeat("k", MaxNetworkDeviceKeyBytes)} {
		wantStatus(t, hs.get("/api/network/device?key="+url.QueryEscape(key)), http.StatusOK)
		if asked := nv.takeAsked(); len(asked) != 1 || asked[0][0] != key {
			t.Errorf("%q: asked %q", key, asked)
		}
	}
}

func TestNetworkDeviceErrors(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      error
		code     int
		contains string
	}{
		{"not found", fmt.Errorf("netmap: device details: not a device or an unknown address of the period: %w", contracts.ErrNotFound), 404, "not found"},
		{"unavailable", fmt.Errorf("netmap: device details: no connection store: %w", contracts.ErrUnavailable), 503, "network device: netmap: device details: no connection store"},
		{"busy", fmt.Errorf("building: %w", contracts.ErrBusy), 409, "network device: building"},
		{"timeout", fmt.Errorf("read: %w", context.DeadlineExceeded), 504, "network device: operation timed out"},
		{"other", errors.New("netmap: devices view: unexpected EOF"), 500, "network device: netmap: devices view: unexpected EOF"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hs, nv := deviceHarness(t)
			nv.err = tc.err
			rec := hs.get("/api/network/device?key=mac:00:00:5e:00:53:21")
			if msg := wantJSONError(t, rec, tc.code); !strings.Contains(msg, tc.contains) {
				t.Errorf("message %q does not say %q", msg, tc.contains)
			}
			assertSecurityHeaders(t, rec.Header(), false)
			if q, _ := hs.syslog.calls(); len(q) != 0 {
				t.Errorf("a failed view read the syslog: %+v", q)
			}
		})
	}
	// The period knows no such device or address: worded, so that a client tells it from the
	// router's "not found" of an older version.
	hs, nv := deviceHarness(t)
	nv.err = fmt.Errorf("netmap: device details: not a device or an unknown address of the period: %w", contracts.ErrNotFound)
	if msg := wantJSONError(t, hs.get("/api/network/device?key=mac:00:00:5e:00:53:ff"), http.StatusNotFound); msg != msgNoDevice("mac:00:00:5e:00:53:ff") ||
		msg != "not found: the Devices view of this period lists no device with this key" {
		t.Errorf("no such device: %q", msg)
	}
	if msg := wantJSONError(t, hs.get("/api/network/device?addr=192.168.1.99"), http.StatusNotFound); msg != "not found: this address is none of the unknown addresses of this period" {
		t.Errorf("no such address: %q", msg)
	}
	nv.err = fmt.Errorf("both: %w", errors.Join(contracts.ErrNotFound, contracts.ErrUnavailable))
	wantJSONError(t, hs.get("/api/network/device?key=mac:00:00:5e:00:53:ff"), http.StatusServiceUnavailable)

	// The view takes too long: the request ends with its timeout and the view sees its context end.
	hs, nv = deviceHarness(t)
	nv.block = true
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	wantJSONError(t, hs.serve(hs.request(http.MethodGet, "/api/network/device?key=mac:00:00:5e:00:53:21", nil, nil).WithContext(ctx)), http.StatusGatewayTimeout)
	nv.mu.Lock()
	ctxErr := nv.ctxErr
	nv.mu.Unlock()
	if !errors.Is(ctxErr, context.DeadlineExceeded) {
		t.Errorf("the view's context ended with %v", ctxErr)
	}
	// Without a network view: 404 before the parameters are looked at.
	hs = newHarness(t)
	for _, path := range []string{"/api/network/device?key=mac:00:00:5e:00:53:21", "/api/network/device?range=bogus"} {
		if msg := wantJSONError(t, hs.get(path), http.StatusNotFound); !strings.Contains(msg, "Network page is not available") {
			t.Errorf("%s: %q", path, msg)
		}
	}
}

// TestNetworkDeviceSecurity: the endpoint is behind the same middleware as the others, and every
// string of the answer - the gateway's names, the syslog's text - is JSON-escaped, markup included.
func TestNetworkDeviceSecurity(t *testing.T) {
	hs, nv := deviceHarness(t)
	const path = "/api/network/device?key=mac:00:00:5e:00:53:21"
	for _, host := range []string{"evil.example:8320", "192.168.1.71:8320"} {
		req := hs.request(http.MethodGet, path, nil, nil)
		req.Host = host
		wantJSONError(t, hs.serve(req), http.StatusMisdirectedRequest)
	}
	wantJSONError(t, hs.serve(hs.request(http.MethodGet, path, nil, map[string]string{"Sec-Fetch-Site": "cross-site"})), http.StatusForbidden)
	if calls := nv.takeCalls(); len(calls) != 0 {
		t.Fatalf("refused requests reached the view: %+v", calls)
	}
	wantJSONError(t, hs.serve(hs.request(http.MethodPost, path, strings.NewReader("{}"), map[string]string{CSRFHeader: ""})), http.StatusForbidden)
	rec := hs.serve(hs.request(http.MethodPost, path, strings.NewReader("{}"), nil))
	wantJSONError(t, rec, http.StatusMethodNotAllowed)
	if got := rec.Header().Get("Allow"); got != "GET, HEAD" {
		t.Errorf("Allow = %q", got)
	}

	// Hostile strings from the gateway and the syslog reach the answer escaped.
	nv.detail.Device.Name = `</script><img src=x onerror=alert(1)>` + " "
	hs.syslog.chunks[2].msgs = append(hs.syslog.chunks[2].msgs, sysMsg(syslogNow.Add(-30*time.Second), 3, "dsldevice", "evil",
		`[d12] <script>alert("192.168.1.71")</script> SRC=192.168.1.71 & `+hostileMarker))
	rec = hs.get(path)
	wantStatus(t, rec, http.StatusOK)
	body := rec.Body.String()
	for _, raw := range []string{"<script>", "</script>", "<img", " ", hostileMarker} {
		if strings.Contains(body, raw) {
			t.Errorf("the answer holds %q as is: %s", raw, body)
		}
	}
	dd := decode[model.NetDeviceDetail](t, rec)
	if dd.Device.Name != nv.detail.Device.Name || !strings.Contains(dd.Syslog[0].Raw, `<script>alert("192.168.1.71")</script>`) {
		t.Errorf("the strings did not come through as they were: %q, %q", dd.Device.Name, dd.Syslog[0].Raw)
	}
}
