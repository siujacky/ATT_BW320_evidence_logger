package web

// GET /api/network/connections, /api/network/firewall and /api/network/status (docs/
// syslog-map-graphic.md §2.2): the parameters are validated before the view is asked, the view's
// answer is passed on (completed, and bounded), its errors are mapped as the other endpoints'
// are, the work is bounded in time, and a monitor without the view answers 404.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

var _ contracts.NetworkView = (*fakeNetwork)(nil)

// netCall is one call of the fake view: which method, the query and how long it had until its
// deadline.
type netCall struct {
	what     string
	q        contracts.NetQuery
	deadline time.Duration // 0: no deadline
}

// fakeNetwork is a contracts.NetworkView that answers what a test sets and records its calls.
type fakeNetwork struct {
	mu     sync.Mutex
	conns  model.NetConnections
	fw     model.NetFirewall
	status model.NetworkStatus
	err    error // answered by Connections and Firewall
	block  bool  // Connections and Firewall wait for their context to end
	calls  []netCall
	ctxErr error // the context error a blocked call saw
}

func (f *fakeNetwork) record(ctx context.Context, what string, q contracts.NetQuery) error {
	f.mu.Lock()
	c := netCall{what: what, q: q}
	if d, ok := ctx.Deadline(); ok {
		c.deadline = time.Until(d)
	}
	f.calls = append(f.calls, c)
	block, err := f.block, f.err
	f.mu.Unlock()
	if block {
		<-ctx.Done()
		f.mu.Lock()
		f.ctxErr = ctx.Err()
		f.mu.Unlock()
		return ctx.Err()
	}
	return err
}

func (f *fakeNetwork) Connections(ctx context.Context, q contracts.NetQuery) (model.NetConnections, error) {
	if err := f.record(ctx, "connections", q); err != nil {
		return model.NetConnections{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.conns, nil
}

func (f *fakeNetwork) Firewall(ctx context.Context, q contracts.NetQuery) (model.NetFirewall, error) {
	if err := f.record(ctx, "firewall", q); err != nil {
		return model.NetFirewall{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fw, nil
}

func (f *fakeNetwork) NetworkStatus() model.NetworkStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, netCall{what: "status"})
	return f.status
}

// takeCalls returns the calls so far and forgets them.
func (f *fakeNetwork) takeCalls() []netCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.calls
	f.calls = nil
	return c
}

// netNow is the harness's clock (newHarness).
var netNow = time.Date(2026, 10, 5, 3, 20, 0, 0, time.UTC)

// netHarness is the test harness with a network view.
func netHarness(t *testing.T) (*harness, *fakeNetwork) {
	t.Helper()
	hs := newHarness(t)
	nv := &fakeNetwork{}
	hs.srv.network = nv
	return hs, nv
}

// testConnections is a small, complete answer of the view (documentation addresses only).
func testConnections() model.NetConnections {
	return model.NetConnections{
		From: "2026-10-04T03:20:00Z", To: "2026-10-05T03:20:00Z", Samples: 360,
		First: "2026-10-04T03:22:00Z", Last: "2026-10-05T03:18:00Z", InUse: 212, Available: 8192, Open: 205,
		Totals: model.NetTotals{Devices: 2, Sites: 3, Orgs: 2, Countries: 2},
		Devices: []model.NetDevice{
			{Key: "mac:00:00:5e:00:53:01", Name: "Office PC", IPv4: "192.168.1.64", MAC: "00:00:5e:00:53:01", Connection: "Ethernet", Weight: 900, Sites: 2},
			{Key: "ip:192.168.1.65", Name: "192.168.1.65", IPv4: "192.168.1.65", Weight: 100, Sites: 1},
		},
		Orgs:     []model.NetOrg{{Key: "as15169", Name: "Google", ASN: 15169, Country: "US", Weight: 700, Sites: 2}, {Key: "as13335", Name: "Cloudflare", ASN: 13335, Country: "GB", Weight: 300, Sites: 1}},
		Services: []model.NetService{{Key: "tcp/443", Name: "HTTPS", Proto: "tcp", Port: 443, Weight: 1000}},
		Links: []model.NetLink{{From: "mac:00:00:5e:00:53:01", To: "as15169", Weight: 700}, {From: "mac:00:00:5e:00:53:01", To: "as13335", Weight: 200},
			{From: "ip:192.168.1.65", To: "as13335", Weight: 100}, {From: "as15169", To: "tcp/443", Weight: 700}, {From: "as13335", To: "tcp/443", Weight: 300}},
		Countries: []model.NetCountry{{Code: "US", Sites: 2, Weight: 700}, {Code: "GB", Sites: 1, Weight: 300}},
		Rows: []model.NetConnRow{
			{Device: "mac:00:00:5e:00:53:01", LAN: "192.168.1.64", Remote: "192.0.2.44", PTR: "host.example.net", Kind: model.IPKindPublic, Org: "Google", ASN: 15169,
				Country: "US", Service: "HTTPS", Proto: "tcp", Port: 443, First: "2026-10-04T03:22:00Z", Last: "2026-10-05T03:18:00Z", Samples: 300, Weight: 700},
		},
		RowsTotal: 1,
		IPDB:      "2026-10-04T06:00:00Z",
	}
}

func TestNetworkConnectionsEndpoint(t *testing.T) {
	hs, nv := netHarness(t)
	nv.conns = testConnections()
	rec := hs.get("/api/network/connections?range=24h&device=" + url.QueryEscape("mac:00:00:5e:00:53:01") + "&limit=50")
	wantStatus(t, rec, http.StatusOK)
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	assertSecurityHeaders(t, rec.Header(), false)
	if got := decode[model.NetConnections](t, rec); !jsonEqual(got, nv.conns) {
		t.Errorf("answer not passed on as given:\n got %+v\nwant %+v", got, nv.conns)
	}
	calls := nv.takeCalls()
	if len(calls) != 1 || calls[0].what != "connections" {
		t.Fatalf("calls = %+v", calls)
	}
	want := contracts.NetQuery{From: netNow.Add(-24 * time.Hour), To: netNow, Device: "mac:00:00:5e:00:53:01", Limit: 50}
	if q := calls[0].q; !q.From.Equal(want.From) || !q.To.Equal(want.To) || q.Device != want.Device || q.Limit != want.Limit {
		t.Errorf("query = %+v, want %+v", q, want)
	}
	// The work is bounded in time, tied to the request.
	if d := calls[0].deadline; d <= 0 || d > networkTimeout {
		t.Errorf("the view had %v until its deadline, want at most %v", d, networkTimeout)
	}
	wantStatus(t, hs.serve(hs.request(http.MethodHead, "/api/network/connections", nil, nil)), http.StatusOK)
}

func TestNetworkFirewallEndpoint(t *testing.T) {
	hs, nv := netHarness(t)
	nv.fw = model.NetFirewall{
		From: "2026-10-05T01:20:00Z", To: "2026-10-05T03:20:00Z", Oldest: "2026-09-30T00:00:00Z", Drops: 30, Inbound: 20, Outbound: 8, Local: 2, Sources: 3,
		Hours:      []model.FwHour{{T: "2026-10-05T01:00:00Z", In: 5, Out: 1}, {T: "2026-10-05T02:00:00Z", In: 10, Out: 4, Local: 1}, {T: "2026-10-05T03:00:00Z", In: 5, Out: 3, Local: 1}},
		Countries:  []model.NetCountry{{Code: "NL", Sites: 2, Weight: 15}, {Code: "", Sites: 1, Weight: 5}},
		TopSources: []model.FwSource{{Addr: "198.51.100.7", Org: "Example Hosting", ASN: 64500, Country: "NL", Count: 12, Ports: 3, Last: "2026-10-05T03:10:00Z"}},
		Services:   []model.FwService{{Name: "SSH", Proto: "tcp", Port: 22, Count: 12}, {Name: "Other", Count: 8}},
		Reasons:    []model.FwReason{{Reason: "POLICY-INPUT-GEN-DISCARD", Label: "Unsolicited, to the gateway", Count: 20}},
		OutboundRows: []model.FwOutRow{{Device: "mac:00:00:5e:00:53:01", Name: "Office PC", LAN: "192.168.1.64", Remote: "203.0.113.9", Org: "Example", ASN: 64501,
			Country: "US", Service: "HTTPS", Proto: "tcp", Port: 443, Reason: "POLICY-FORWARD-GEN-DISCARD", Label: "Not forwarded", Count: 8, Last: "2026-10-05T03:01:00Z"}},
		OutboundTotal:   1,
		OutboundDevices: 1,
		IPDB:            "2026-10-04T06:00:00Z",
	}
	rec := hs.get("/api/network/firewall?from=2026-10-05T01:20:00Z&to=2026-10-05T03:20:00Z")
	wantStatus(t, rec, http.StatusOK)
	assertSecurityHeaders(t, rec.Header(), false)
	if got := decode[model.NetFirewall](t, rec); !jsonEqual(got, nv.fw) {
		t.Errorf("answer not passed on as given:\n got %+v\nwant %+v", got, nv.fw)
	}
	calls := nv.takeCalls()
	if len(calls) != 1 || calls[0].what != "firewall" || calls[0].q.Device != "" || calls[0].q.Limit != 0 ||
		!calls[0].q.From.Equal(netNow.Add(-2*time.Hour)) || !calls[0].q.To.Equal(netNow) {
		t.Errorf("calls = %+v", calls)
	}
	if d := calls[0].deadline; d <= 0 || d > networkTimeout {
		t.Errorf("the view had %v until its deadline, want at most %v", d, networkTimeout)
	}
	// The firewall view is not per device: a device filter is refused, not silently ignored.
	if msg := wantJSONError(t, hs.get("/api/network/firewall?device=gateway"), http.StatusBadRequest); !strings.Contains(msg, "device") {
		t.Errorf("message = %q", msg)
	}
	if calls := nv.takeCalls(); len(calls) != 0 {
		t.Errorf("an invalid request reached the view: %+v", calls)
	}
}

// TestNetworkQueryParameters: the period, the device filter and the limit, as parseNetworkQuery
// reads them.
func TestNetworkQueryParameters(t *testing.T) {
	day := 24 * time.Hour
	good := []struct {
		query    string
		from, to time.Time
		device   string
		limit    int
	}{
		{"", netNow.Add(-day), netNow, "", 0}, // the day before now
		{"range=1h", netNow.Add(-time.Hour), netNow, "", 0},
		{"range=24h", netNow.Add(-day), netNow, "", 0},
		{"range=7d", netNow.Add(-7 * day), netNow, "", 0},
		{"range=30d", netNow.Add(-30 * day), netNow, "", 0},
		{"range=24h&from=&to=", netNow.Add(-day), netNow, "", 0}, // empty parameters are no parameters
		{"from=2026-10-01T00:00:00Z", time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), netNow, "", 0},
		{"to=2026-10-03T00:00:00Z", time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC), time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC), "", 0},
		{"from=2026-10-04&to=2026-10-05", time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC), time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC), "", 0},
		// A time zone offset is read as the time it names.
		{"from=2026-10-05T04:00:00%2B02:00&to=2026-10-05T03:00:00Z", time.Date(2026, 10, 5, 2, 0, 0, 0, time.UTC), time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC), "", 0},
		{"from=1759600000&to=1759620000", time.Unix(1759600000, 0).UTC(), time.Unix(1759620000, 0).UTC(), "", 0},
		// Exactly 31 days, and an end up to an hour ahead of the server's clock.
		{"from=2026-09-04T03:20:00Z&to=2026-10-05T03:20:00Z", netNow.Add(-31 * day), netNow, "", 0},
		{"from=2026-10-05T00:00:00Z&to=2026-10-05T04:20:00Z", time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC), netNow.Add(time.Hour), "", 0},
		{"limit=1", netNow.Add(-day), netNow, "", 1},
		{"limit=1000", netNow.Add(-day), netNow, "", 1000},
		{"limit=5000", netNow.Add(-day), netNow, "", MaxNetworkLimit}, // capped, as /api/records and /api/syslog do
		{"device=gateway", netNow.Add(-day), netNow, "gateway", 0},
		{"device=" + url.QueryEscape("mac:00:00:5e:00:53:0a"), netNow.Add(-day), netNow, "mac:00:00:5e:00:53:0a", 0},
		{"device=" + url.QueryEscape("ip:2001:db8::1"), netNow.Add(-day), netNow, "ip:2001:db8::1", 0},
		{"device=" + strings.Repeat("k", MaxNetworkDeviceChars), netNow.Add(-day), netNow, strings.Repeat("k", MaxNetworkDeviceChars), 0},
	}
	for _, tc := range good {
		t.Run("ok "+tc.query, func(t *testing.T) {
			v, err := url.ParseQuery(tc.query)
			if err != nil {
				t.Fatal(err)
			}
			q, err := parseNetworkQuery(v, netNow, true)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !q.From.Equal(tc.from) || !q.To.Equal(tc.to) || q.Device != tc.device || q.Limit != tc.limit {
				t.Errorf("query = %+v, want from %v to %v device %q limit %d", q, tc.from, tc.to, tc.device, tc.limit)
			}
			if q.From.Location() != time.UTC || q.To.Location() != time.UTC {
				t.Errorf("times not in UTC: %v, %v", q.From, q.To)
			}
		})
	}

	hs, nv := netHarness(t)
	for _, tc := range []struct{ query, says string }{
		{"range=6h", "range must be one of 1h, 24h, 7d, 30d"},
		{"range=24H", "range must be one of"},
		{"range=%2024h", "range must be one of"},
		{"range=24h&from=2026-10-04T00:00:00Z", "range cannot be combined with from or to"},
		{"range=1h&to=2026-10-05T00:00:00Z", "range cannot be combined"},
		{"from=yesterday", "from: invalid time"},
		{"to=2026-13-01", "to: invalid time"},
		{"from=2026-10-05T04:00:00Z", "from must be before to"}, // after the default to (now)
		{"from=2026-10-05&to=2026-10-05", "from must be before to"},
		{"from=2026-10-05&to=2026-10-04", "from must be before to"},
		{"from=2026-09-04T03:19:59Z&to=2026-10-05T03:20:00Z", "at most 31 days apart"},
		{"from=2026-01-01&to=2026-10-05", "at most 31 days apart"},
		{"from=2026-10-05T00:00:00Z&to=2026-10-05T04:20:01Z", "to may be at most an hour after now"},
		{"from=2026-10-10&to=2026-10-11", "to may be at most an hour after now"},
		{"limit=0", "limit must be a positive integer (at most 1000)"},
		{"limit=-5", "limit must be a positive integer"},
		{"limit=ten", "limit must be a positive integer"},
		{"limit=1.5", "limit must be a positive integer"},
		{"limit=99999999999999999999", "limit must be a positive integer"},
		{"device=" + url.QueryEscape("mac:00:00:5e:00:53:01 "), "device must be a device key"},
		{"device=" + url.QueryEscape(hostileMarker), "device must be a device key"},
		{"device=" + url.QueryEscape("ip:192.168.1.5\n"), "device must be a device key"},
		{"device=" + url.QueryEscape("Büro-PC"), "device must be a device key"},
		{"device=" + strings.Repeat("k", MaxNetworkDeviceChars+1), "device must be a device key"},
	} {
		t.Run("bad "+tc.query, func(t *testing.T) {
			for _, path := range []string{"/api/network/connections", "/api/network/firewall"} {
				if strings.HasPrefix(tc.query, "device=") && path == "/api/network/firewall" {
					continue // refused there for being a device filter at all
				}
				rec := hs.get(path + "?" + tc.query)
				msg := wantJSONError(t, rec, http.StatusBadRequest)
				if !strings.Contains(msg, tc.says) {
					t.Errorf("%s: message %q does not say %q", path, msg, tc.says)
				}
				assertSecurityHeaders(t, rec.Header(), false)
			}
			if calls := nv.takeCalls(); len(calls) != 0 {
				t.Errorf("an invalid request reached the view: %+v", calls)
			}
		})
	}
}

// TestNetworkAnswersAreCompletedAndBounded: lists the view left nil are sent as [], a period the
// view left out is filled in, and a view that returns more rows than asked for cannot make the
// answer larger (the totals still count every row).
func TestNetworkAnswersAreCompletedAndBounded(t *testing.T) {
	hs, nv := netHarness(t)
	rec := hs.get("/api/network/connections?range=1h")
	wantStatus(t, rec, http.StatusOK)
	body := rec.Body.String()
	for _, want := range []string{`"from":"2026-10-05T02:20:00Z"`, `"to":"2026-10-05T03:20:00Z"`, `"devices":[]`, `"orgs":[]`,
		`"services":[]`, `"links":[]`, `"countries":[]`, `"rows":[]`, `"rows_total":0`} {
		if !strings.Contains(body, want) {
			t.Errorf("connections answer lacks %s: %s", want, body)
		}
	}
	if strings.Contains(body, "null") {
		t.Errorf("connections answer holds null: %s", body)
	}
	rec = hs.get("/api/network/firewall?range=1h")
	wantStatus(t, rec, http.StatusOK)
	body = rec.Body.String()
	for _, want := range []string{`"from":"2026-10-05T02:20:00Z"`, `"hours":[]`, `"countries":[]`, `"top_sources":[]`, `"services":[]`,
		`"reasons":[]`, `"outbound_rows":[]`, `"outbound_total":0`, `"outbound_devices":0`} {
		if !strings.Contains(body, want) {
			t.Errorf("firewall answer lacks %s: %s", want, body)
		}
	}
	if strings.Contains(body, "null") {
		t.Errorf("firewall answer holds null: %s", body)
	}

	rows := make([]model.NetConnRow, 1500)
	out := make([]model.FwOutRow, 1500)
	for i := range rows {
		rows[i] = model.NetConnRow{Device: "gateway", Remote: fmt.Sprintf("198.51.100.%d", i%256), Proto: "tcp", Samples: 1500 - i}
		out[i] = model.FwOutRow{Device: "gateway", Remote: fmt.Sprintf("203.0.113.%d", i%256), Proto: "udp", Count: 1500 - i}
	}
	nv.conns = model.NetConnections{Rows: rows, RowsTotal: 1200} // a view that miscounted, too
	nv.fw = model.NetFirewall{OutboundRows: out, OutboundTotal: 9000}
	for _, tc := range []struct {
		query string
		rows  int
	}{{"", MaxNetworkLimit}, {"?limit=20", 20}, {"?limit=100000", MaxNetworkLimit}} {
		nc := decode[model.NetConnections](t, hs.get("/api/network/connections"+tc.query))
		if len(nc.Rows) != tc.rows || nc.RowsTotal != 1200 || nc.Rows[0].Samples != 1500 {
			t.Errorf("connections%s: %d rows of %d", tc.query, len(nc.Rows), nc.RowsTotal)
		}
		fw := decode[model.NetFirewall](t, hs.get("/api/network/firewall"+tc.query))
		if len(fw.OutboundRows) != tc.rows || fw.OutboundTotal != 9000 || fw.OutboundRows[0].Count != 1500 || fw.OutboundDevices != 1 {
			t.Errorf("firewall%s: %d rows of %d from %d devices", tc.query, len(fw.OutboundRows), fw.OutboundTotal, fw.OutboundDevices)
		}
	}
	// A total below the rows listed is raised to them.
	nv.conns = model.NetConnections{Rows: rows[:30], RowsTotal: 2}
	if nc := decode[model.NetConnections](t, hs.get("/api/network/connections")); nc.RowsTotal != 30 {
		t.Errorf("rows_total = %d, want 30", nc.RowsTotal)
	}
	// So is a count of devices below the devices the rows listed name; a larger one (devices
	// beyond the rows listed) is kept.
	two := []model.FwOutRow{{Device: "mac:00:00:5e:00:53:01", Proto: "tcp", Count: 3}, {Device: "ip:192.168.1.70", Proto: "tcp", Count: 2},
		{Device: "mac:00:00:5e:00:53:01", Proto: "udp", Count: 1}}
	for _, tc := range []struct{ view, want int }{{0, 2}, {1, 2}, {2, 2}, {5, 5}} {
		nv.fw = model.NetFirewall{OutboundRows: two, OutboundTotal: 9, OutboundDevices: tc.view}
		if fw := decode[model.NetFirewall](t, hs.get("/api/network/firewall")); fw.OutboundDevices != tc.want || fw.OutboundTotal != 9 {
			t.Errorf("view's outbound_devices %d: answered %d (want %d), outbound_total %d", tc.view, fw.OutboundDevices, tc.want, fw.OutboundTotal)
		}
	}
}

func TestNetworkEndpointsErrors(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      error
		code     int
		contains string
	}{
		{"unavailable", fmt.Errorf("connection store closed: %w", contracts.ErrUnavailable), 503, "connection store closed"},
		{"busy", fmt.Errorf("aggregating: %w", contracts.ErrBusy), 409, "aggregating"},
		{"rate limited", fmt.Errorf("asked too often: %w", contracts.ErrRateLimited), 429, "asked too often"},
		{"not found", fmt.Errorf("no such day: %w", contracts.ErrNotFound), 404, "not found"},
		{"timeout", fmt.Errorf("read connections-20261004.gz: %w", context.DeadlineExceeded), 504, "operation timed out"},
		{"cancelled", fmt.Errorf("read: %w", context.Canceled), 503, "cancelled"},
		{"other", errors.New("connstore: parse line 12: unexpected EOF"), 500, "connstore: parse line 12: unexpected EOF"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hs, nv := netHarness(t)
			nv.err = tc.err
			for _, ep := range []struct{ path, op string }{{"/api/network/connections", "network connections"}, {"/api/network/firewall", "network firewall"}} {
				rec := hs.get(ep.path)
				msg := wantJSONError(t, rec, tc.code)
				if !strings.Contains(msg, tc.contains) {
					t.Errorf("%s: message %q does not say %q", ep.path, msg, tc.contains)
				}
				if tc.code != http.StatusNotFound && !strings.Contains(msg, ep.op) {
					t.Errorf("%s: message %q does not name the operation %q", ep.path, msg, ep.op)
				}
				assertSecurityHeaders(t, rec.Header(), false)
			}
		})
	}

	// The view takes too long: the request ends (networkTimeout, shortened here through the
	// request's own context) and the view sees its context end.
	hs, nv := netHarness(t)
	nv.block = true
	for _, path := range []string{"/api/network/connections", "/api/network/firewall"} {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		wantJSONError(t, hs.serve(hs.request(http.MethodGet, path, nil, nil).WithContext(ctx)), http.StatusGatewayTimeout)
		cancel()
		nv.mu.Lock()
		ctxErr := nv.ctxErr
		nv.ctxErr = nil
		nv.mu.Unlock()
		if !errors.Is(ctxErr, context.DeadlineExceeded) {
			t.Errorf("%s: the view's context ended with %v", path, ctxErr)
		}
	}
	// The browser went away: the answer is not waited for.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	wantJSONError(t, hs.serve(hs.request(http.MethodGet, "/api/network/connections", nil, nil).WithContext(ctx)), http.StatusServiceUnavailable)
}

func TestNetworkEndpointsWithoutView(t *testing.T) {
	hs := newHarness(t)
	for _, path := range []string{"/api/network/connections", "/api/network/firewall", "/api/network/status",
		"/api/network/connections?range=bogus"} { // 404 before the parameters are looked at
		rec := hs.get(path)
		if msg := wantJSONError(t, rec, http.StatusNotFound); !strings.Contains(msg, "Network page is not available") {
			t.Errorf("%s: message = %q", path, msg)
		}
		assertSecurityHeaders(t, rec.Header(), false)
	}
}

func TestNetworkStatusEndpoint(t *testing.T) {
	hs, nv := netHarness(t)
	nv.status = model.NetworkStatus{
		Store:   &model.ConnStoreUsage{Bytes: 4 << 20, Files: 6, Oldest: "2026-09-29T00:00:04Z", Newest: "2026-10-05T03:18:00Z", KeepDays: 30, KeepMB: 200},
		IPIntel: &model.IPIntelStatus{Enabled: true, Download: true, Source: "https://iptoasn.com/data/ip2asn-v4.tsv.gz", Loaded: true, V4Ranges: 512000, V6Ranges: 140000, Updated: "2026-10-04T06:00:00Z", ReverseDNS: true, PTRCached: 42},
		Syslog:  &model.SyslogUsage{Bytes: 9 << 20, Chunks: 12, Messages: 30000, Oldest: "2026-09-30T00:00:00Z", Newest: "2026-10-05T03:19:58Z", KeepMB: 100},
		// The view leaves the samplers out; were it to set them, the monitor's status would win.
		Samplers: &model.ConnSamplerStatus{Interval: "from the view"},
	}
	samplers := &model.ConnSamplerStatus{Enabled: true, Interval: "4m0s", DevicesInterval: "15m0s", NATAt: "2026-10-05T03:18:00Z",
		Sessions: 205, InUse: 212, Available: 8192, NATNext: "2026-10-05T03:22:00Z", DevicesAt: "2026-10-05T03:10:00Z", Devices: 8,
		Store: nv.status.Store}
	hs.status.status.Connections = samplers

	rec := hs.get("/api/network/status")
	wantStatus(t, rec, http.StatusOK)
	assertSecurityHeaders(t, rec.Header(), false)
	got := decode[model.NetworkStatus](t, rec)
	want := nv.status
	want.Samplers = samplers
	if !jsonEqual(got, want) {
		t.Errorf("status:\n got %+v\nwant %+v", got, want)
	}
	if !strings.Contains(rec.Body.String(), `"samplers":{"enabled":true,"interval":"4m0s","devices_interval":"15m0s","nat_at":"2026-10-05T03:18:00Z"`) {
		t.Errorf("JSON: %s", rec.Body.String())
	}

	// A status without samplers (not configured) leaves what the view said.
	hs.status.status.Connections = nil
	if got := decode[model.NetworkStatus](t, hs.get("/api/network/status")); got.Samplers == nil || got.Samplers.Interval != "from the view" {
		t.Errorf("samplers without the monitor's: %+v", got.Samplers)
	}
	// Without a status source the samplers are not known here either.
	nv.status.Samplers = nil
	hs.srv.status = nil
	rec = hs.get("/api/network/status")
	wantStatus(t, rec, http.StatusOK)
	if strings.Contains(rec.Body.String(), "samplers") {
		t.Errorf("samplers without a status source: %s", rec.Body.String())
	}
}

// The network endpoints are behind the same middleware as every other endpoint: a request with
// a foreign Host (DNS rebinding) never reaches the view, only GET and HEAD are served, every
// response carries the security headers, and nothing grants another origin the answer.
func TestNetworkEndpointsSecurity(t *testing.T) {
	hs, nv := netHarness(t)
	nv.conns = testConnections()
	for _, path := range []string{"/api/network/connections", "/api/network/firewall", "/api/network/status"} {
		t.Run(path, func(t *testing.T) {
			for _, host := range []string{"evil.example:8320", "127.0.0.1.nip.io:8320", "192.168.1.71:8320"} {
				req := hs.request(http.MethodGet, path, nil, nil)
				req.Host = host
				rec := hs.serve(req)
				wantJSONError(t, rec, http.StatusMisdirectedRequest)
				assertSecurityHeaders(t, rec.Header(), false)
			}
			if calls := nv.takeCalls(); len(calls) != 0 {
				t.Fatalf("a request with a foreign Host reached the view: %+v", calls)
			}
			// Another site's page: refused before the view is asked (it could not read the answer,
			// but could make the service build it); the answer grants nothing either.
			rec := hs.serve(hs.request(http.MethodGet, path, nil, map[string]string{"Origin": "http://evil.example", "Sec-Fetch-Site": "cross-site"}))
			wantJSONError(t, rec, http.StatusForbidden)
			assertSecurityHeaders(t, rec.Header(), false)
			for _, k := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"} {
				if v := rec.Header().Get(k); v != "" {
					t.Errorf("%s: %q", k, v)
				}
			}
			if calls := nv.takeCalls(); len(calls) != 0 {
				t.Fatalf("a cross-site request reached the view: %+v", calls)
			}
			// State-changing methods: the CSRF check first, then 405.
			wantJSONError(t, hs.serve(hs.request(http.MethodPost, path, strings.NewReader("{}"), map[string]string{CSRFHeader: ""})), http.StatusForbidden)
			for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
				rec := hs.serve(hs.request(m, path, strings.NewReader("{}"), map[string]string{CSRFHeader: CSRFHeaderValue}))
				wantJSONError(t, rec, http.StatusMethodNotAllowed)
				if got := rec.Header().Get("Allow"); got != "GET, HEAD" {
					t.Errorf("%s: Allow = %q", m, got)
				}
				assertSecurityHeaders(t, rec.Header(), false)
			}
			if calls := nv.takeCalls(); len(calls) != 0 {
				t.Errorf("refused requests reached the view: %+v", calls)
			}
		})
	}
}

// FuzzParseNetworkQuery: whatever the query string, parseNetworkQuery does not panic, and what
// it accepts is within the limits it promises.
func FuzzParseNetworkQuery(f *testing.F) {
	for _, seed := range []string{"", "range=24h", "range=30d&device=gateway&limit=10", "from=2026-10-01&to=2026-10-02",
		"from=1759600000", "to=2026-10-05T04:20:00Z", "device=%00", "limit=1001", "range=7d&from=x", "from=2026-09-04T03:20:00Z"} {
		f.Add(seed, true)
	}
	f.Fuzz(func(t *testing.T, raw string, withDevice bool) {
		v, err := url.ParseQuery(raw)
		if err != nil {
			return
		}
		q, err := parseNetworkQuery(v, netNow, withDevice)
		if err != nil {
			if err.Error() == "" {
				t.Fatal("empty error message")
			}
			return
		}
		if !q.From.Before(q.To) || q.To.Sub(q.From) > MaxNetworkSpan || q.To.After(netNow.Add(NetworkFutureSlack)) {
			t.Fatalf("accepted period %v - %v", q.From, q.To)
		}
		if q.Device != "" && (!withDevice || !validDeviceKey(q.Device)) {
			t.Fatalf("accepted device %q (withDevice %v)", q.Device, withDevice)
		}
		if q.Limit < 0 || q.Limit > MaxNetworkLimit {
			t.Fatalf("accepted limit %d", q.Limit)
		}
	})
}
