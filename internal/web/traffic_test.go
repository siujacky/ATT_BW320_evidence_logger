package web

// GET /api/traffic/live (docs/syslog-snmp-traffic.md §3.3): the flow meter's reading, passed on
// as the monitor gives it, read with a short timeout and only while someone asks.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

func TestLiveTrafficEndpoint(t *testing.T) {
	hs := newHarness(t)
	mbps := func(v float64) *float64 { return &v }
	hs.live.lt = model.LiveTraffic{At: "2026-10-05T03:19:58.5Z", IntervalS: 5.02, WANRx: mbps(612.5), WANTx: mbps(41.25), AtLeast: true,
		PCRx: mbps(3.25), PCTx: mbps(0.5), History: []model.LivePoint{
			{T: "2026-10-05T03:19:48.4Z", WANRx: mbps(580), WANTx: mbps(38)},
			{T: "2026-10-05T03:19:53.5Z"}, // a reading without rates (the counters were reset)
			{T: "2026-10-05T03:19:58.5Z", WANRx: mbps(612.5), WANTx: mbps(41.25), PCRx: mbps(3.25), PCTx: mbps(0.5)},
		}, Err: ""}
	rec := hs.get("/api/traffic/live")
	wantStatus(t, rec, http.StatusOK)
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	assertSecurityHeaders(t, rec.Header(), false)
	if got := decode[model.LiveTraffic](t, rec); !jsonEqual(got, hs.live.lt) {
		t.Errorf("reading not passed on as given: %+v", got)
	}
	for _, want := range []string{`"interval_s":5.02`, `"wan_rx_mbps":612.5`, `"at_least":true`, `"pc_tx_mbps":0.5`,
		`"history":[{"t":"2026-10-05T03:19:48.4Z","wan_rx_mbps":580,"wan_tx_mbps":38},{"t":"2026-10-05T03:19:53.5Z"},`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("JSON lacks %s: %s", want, rec.Body.String())
		}
	}
	// A short timeout: the dashboard asks again 5 seconds after an answer.
	if d := hs.live.deadline; d <= 0 || d > liveTrafficTimeout {
		t.Errorf("the source had %v until its deadline, want at most %v", d, liveTrafficTimeout)
	}

	// The newest read failed: the monitor says so in the reading, which is still an answer.
	hs.live.lt = model.LiveTraffic{At: "2026-10-05T03:19:53.5Z", Err: "gateway: GET broadbandstatistics.ha: i/o timeout"}
	if got := decode[model.LiveTraffic](t, hs.get("/api/traffic/live")); got.Err != hs.live.lt.Err || got.WANRx != nil {
		t.Errorf("reading with an error: %+v", got)
	}

	wantStatus(t, hs.serve(hs.request(http.MethodHead, "/api/traffic/live", nil, nil)), http.StatusOK)
}

func TestLiveTrafficEndpointErrors(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      error
		code     int
		contains string
	}{
		{"unavailable", fmt.Errorf("the gateway is not configured: %w", contracts.ErrUnavailable), 503, "live traffic: the gateway is not configured"},
		{"rate limited", fmt.Errorf("asked too often: %w", contracts.ErrRateLimited), 429, "asked too often"},
		{"timeout", fmt.Errorf("read counters: %w", context.DeadlineExceeded), 504, "live traffic: operation timed out"},
		{"other", errors.New("parse broadbandstatistics: no counters"), 500, "live traffic: parse broadbandstatistics: no counters"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hs := newHarness(t)
			hs.live.err = tc.err
			rec := hs.get("/api/traffic/live")
			if msg := wantJSONError(t, rec, tc.code); !strings.Contains(msg, tc.contains) {
				t.Errorf("message %q does not say %q", msg, tc.contains)
			}
			assertSecurityHeaders(t, rec.Header(), false)
		})
	}

	// The reading takes too long: the request ends after liveTrafficTimeout (shortened here
	// through the request's own context), and the source sees its context end.
	hs := newHarness(t)
	hs.live.block = true
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	wantJSONError(t, hs.serve(hs.request(http.MethodGet, "/api/traffic/live", nil, nil).WithContext(ctx)), http.StatusGatewayTimeout)
	if hs.live.ctxErr == nil {
		t.Error("the source's context did not end with the request")
	}

	// The browser went away: the reading is not waited for.
	hs = newHarness(t)
	hs.live.block = true
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	wantJSONError(t, hs.serve(hs.request(http.MethodGet, "/api/traffic/live", nil, nil).WithContext(ctx)), http.StatusServiceUnavailable)

	// Without a flow meter: 404, as JSON.
	hs = newHarness(t)
	hs.srv.live = nil
	if msg := wantJSONError(t, hs.get("/api/traffic/live"), http.StatusNotFound); !strings.Contains(msg, "live traffic meter is not available") {
		t.Errorf("message = %q", msg)
	}
}

func TestLiveTrafficEndpointSecurity(t *testing.T) {
	hs := newHarness(t)
	req := hs.request(http.MethodGet, "/api/traffic/live", nil, nil)
	req.Host = "evil.example:8320"
	wantJSONError(t, hs.serve(req), http.StatusMisdirectedRequest)
	if hs.live.calls != 0 {
		t.Fatal("a request with a foreign Host read the gateway's counters")
	}
	wantJSONError(t, hs.serve(hs.request(http.MethodPost, "/api/traffic/live", strings.NewReader("{}"), map[string]string{CSRFHeader: ""})), http.StatusForbidden)
	rec := hs.serve(hs.request(http.MethodPost, "/api/traffic/live", strings.NewReader("{}"), nil))
	wantJSONError(t, rec, http.StatusMethodNotAllowed)
	if got := rec.Header().Get("Allow"); got != "GET, HEAD" {
		t.Errorf("Allow = %q", got)
	}
	if hs.live.calls != 0 {
		t.Errorf("%d readings for requests that were refused", hs.live.calls)
	}
	// Nothing grants another origin the answer.
	rec = hs.serve(hs.request(http.MethodGet, "/api/traffic/live", nil, map[string]string{"Origin": "http://evil.example", "Sec-Fetch-Site": "cross-site"}))
	wantStatus(t, rec, http.StatusOK)
	if v := rec.Header().Get("Access-Control-Allow-Origin"); v != "" {
		t.Errorf("Access-Control-Allow-Origin: %q", v)
	}
}
