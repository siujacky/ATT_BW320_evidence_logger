package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// The Network page (docs/syslog-map-graphic.md): which device on the home network talked to
// which remote address, from samples of the gateway's NAT table, and what the gateway's
// firewall dropped, from its syslog. None of it is evidence: the endpoints only read the views
// the monitor builds (contracts.NetworkView) and never write anything.

// Limits and defaults of GET /api/network/connections and /api/network/firewall.
const (
	// MaxNetworkSpan bounds the period of one request, as for GET /api/syslog: the views add up
	// every NAT sample or syslog message of the period.
	MaxNetworkSpan = 31 * 24 * time.Hour
	// DefaultNetworkRange is the period read when neither range nor from/to is given.
	DefaultNetworkRange = "24h"
	// MaxNetworkLimit caps the table rows of one answer (limit=): connections, and the LAN
	// devices' packets the firewall dropped. A larger limit is read as this one, as /api/records
	// and /api/syslog do; without a limit the view chooses its default.
	MaxNetworkLimit = 1000
	// MaxNetworkDeviceChars bounds the device filter: a device key ("mac:00:00:5e:00:53:01",
	// "ip:192.168.1.20", "gateway") as the answer's devices list it.
	MaxNetworkDeviceChars = 128
	// NetworkFutureSlack is how far after the server's clock to may lie: a browser whose clock
	// runs a little ahead still gets an answer, a period of next week does not.
	NetworkFutureSlack = time.Hour
)

// NetworkRanges are the accepted values of range=: periods that end now.
var NetworkRanges = []string{"1h", "24h", "7d", "30d"}

// networkRangeSpan is the length of each of NetworkRanges.
var networkRangeSpan = map[string]time.Duration{
	"1h": time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour,
}

// networkTimeout bounds the work of one request: the view reads the connection store's daily
// files (whole past days come from its cache) or the syslog store's chunks (sealed ones are
// cached by name). The dashboard asks again a minute after an answer, and a closed tab stops
// the work: the timeout is tied to the request.
const networkTimeout = 30 * time.Second

// msgNoNetwork answers the network endpoints when the monitor offers no Network page (404).
const msgNoNetwork = "the Network page is not available: this att-monitor offers no view of the connections and the firewall"

// handleNetworkConnections serves GET /api/network/connections?range=|from=&to=&device=&limit=:
// which device talked to which remote address, organisation, country and service in the period
// (model.NetConnections), from the samples of the gateway's NAT table. See parseNetworkQuery for
// the parameters. Without a network view the endpoint answers 404.
func (s *Server) handleNetworkConnections(w http.ResponseWriter, r *http.Request) {
	if s.network == nil {
		writeError(w, http.StatusNotFound, msgNoNetwork)
		return
	}
	q, err := parseNetworkQuery(r.URL.Query(), s.now(), true)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), networkTimeout)
	defer cancel()
	nc, err := s.network.Connections(ctx, q)
	if err != nil {
		s.writeErr(w, "network connections", err)
		return
	}
	writeJSON(w, http.StatusOK, completeConnections(nc, q))
}

// handleNetworkFirewall serves GET /api/network/firewall?range=|from=&to=&limit=: what the
// gateway's firewall dropped in the period (model.NetFirewall), from its syslog. A device
// filter is refused: the firewall view is not per device. Without a network view the endpoint
// answers 404.
func (s *Server) handleNetworkFirewall(w http.ResponseWriter, r *http.Request) {
	if s.network == nil {
		writeError(w, http.StatusNotFound, msgNoNetwork)
		return
	}
	q, err := parseNetworkQuery(r.URL.Query(), s.now(), false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), networkTimeout)
	defer cancel()
	fw, err := s.network.Firewall(ctx, q)
	if err != nil {
		s.writeErr(w, "network firewall", err)
		return
	}
	writeJSON(w, http.StatusOK, completeFirewall(fw, q))
}

// handleNetworkStatus serves GET /api/network/status: the connection store, the IP database
// and the syslog kept, as the network view reports them, with the samplers of the NAT table
// and the Device List as the monitor's status reports them (Status.Connections; left out
// without a status source, or when the status has none). Without a network view the endpoint
// answers 404.
func (s *Server) handleNetworkStatus(w http.ResponseWriter, r *http.Request) {
	if s.network == nil {
		writeError(w, http.StatusNotFound, msgNoNetwork)
		return
	}
	ns := s.network.NetworkStatus()
	if s.status != nil {
		if c := s.status.Status().Connections; c != nil {
			samplers := *c // a copy: the source may keep what it returned
			ns.Samplers = &samplers
		}
	}
	writeJSON(w, http.StatusOK, ns)
}

// parseNetworkQuery validates the parameters of the network endpoints; now is the server's
// clock. The period is either range (one of NetworkRanges, ending now; the query keeps its name, by
// which the view reuses a view built for it moments before) or from and to (as for
// GET /api/syslog: RFC 3339, YYYY-MM-DD or Unix seconds; to defaults to now and from to the
// day before to), not both. It must end after it starts, span at most MaxNetworkSpan and end
// at most NetworkFutureSlack after now. device (only withDevice: GET /api/network/connections)
// is a device key of at most MaxNetworkDeviceChars printable ASCII characters. limit (1 or
// more) caps the table rows, at most MaxNetworkLimit; 0 when not given (the view's default).
func parseNetworkQuery(v url.Values, now time.Time, withDevice bool) (contracts.NetQuery, error) {
	now = now.UTC()
	var from, to time.Time
	rng := v.Get("range")
	if rng != "" {
		span, ok := networkRangeSpan[rng]
		if !ok {
			return contracts.NetQuery{}, errors.New("range must be one of " + strings.Join(NetworkRanges, ", "))
		}
		if v.Get("from") != "" || v.Get("to") != "" {
			return contracts.NetQuery{}, errors.New("range cannot be combined with from or to: give a range ending now, or from and to")
		}
		from, to = now.Add(-span), now
	} else {
		var err error
		if from, err = parseTimeParam(v.Get("from")); err != nil {
			return contracts.NetQuery{}, errors.New("from: " + err.Error())
		}
		if to, err = parseTimeParam(v.Get("to")); err != nil {
			return contracts.NetQuery{}, errors.New("to: " + err.Error())
		}
		if to.IsZero() {
			to = now
		}
		if from.IsZero() {
			from = to.Add(-networkRangeSpan[DefaultNetworkRange])
		}
	}
	if !from.Before(to) {
		return contracts.NetQuery{}, errors.New("from must be before to")
	}
	if to.Sub(from) > MaxNetworkSpan {
		return contracts.NetQuery{}, fmt.Errorf("from and to may be at most %d days apart", MaxNetworkSpan/(24*time.Hour))
	}
	if to.After(now.Add(NetworkFutureSlack)) {
		return contracts.NetQuery{}, fmt.Errorf("to may be at most an hour after now (%s)", now.Format(time.RFC3339))
	}
	device := v.Get("device")
	if device != "" {
		if !withDevice {
			return contracts.NetQuery{}, errors.New("device: only GET /api/network/connections is filtered by device")
		}
		if !validDeviceKey(device) {
			return contracts.NetQuery{}, fmt.Errorf("device must be a device key as the answer's devices list it (at most %d printable ASCII characters, no spaces)", MaxNetworkDeviceChars)
		}
	}
	limit := 0
	if lv := v.Get("limit"); lv != "" {
		n, err := strconv.Atoi(lv)
		if err != nil || n < 1 {
			return contracts.NetQuery{}, fmt.Errorf("limit must be a positive integer (at most %d)", MaxNetworkLimit)
		}
		limit = min(n, MaxNetworkLimit)
	}
	return contracts.NetQuery{From: from, To: to, Range: rng, Device: device, Limit: limit}, nil
}

// validDeviceKey reports whether k can be a device key: 1 to MaxNetworkDeviceChars printable
// ASCII characters without spaces. Keys are made by the monitor from a MAC or an IP address
// ("mac:…", "ip:…", "gateway"); anything else (markup, control characters, a long string) is
// refused before it reaches the view or a log line.
func validDeviceKey(k string) bool {
	if len(k) == 0 || len(k) > MaxNetworkDeviceChars {
		return false
	}
	for i := 0; i < len(k); i++ {
		if c := k[i]; c <= ' ' || c > '~' {
			return false
		}
	}
	return true
}

// rowCap is the most table rows an answer to q holds: the limit asked for, else
// MaxNetworkLimit.
func rowCap(q contracts.NetQuery) int {
	if q.Limit > 0 {
		return q.Limit
	}
	return MaxNetworkLimit
}

// networkTime writes a period boundary as the answers do (RFC 3339 UTC).
func networkTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// completeConnections is the answer of GET /api/network/connections: the view's, with the
// period filled in when the view left it out, every list present (empty rather than null, so
// that a client can rely on arrays) and at most rowCap(q) rows (RowsTotal still counts them
// all): a view that ignored the limit cannot make the answer unbounded.
func completeConnections(nc model.NetConnections, q contracts.NetQuery) model.NetConnections {
	if nc.From == "" {
		nc.From = networkTime(q.From)
	}
	if nc.To == "" {
		nc.To = networkTime(q.To)
	}
	nc.Devices = nonNil(nc.Devices)
	nc.Orgs = nonNil(nc.Orgs)
	nc.Services = nonNil(nc.Services)
	nc.Links = nonNil(nc.Links)
	nc.Countries = nonNil(nc.Countries)
	nc.Rows = nonNil(nc.Rows)
	if n := rowCap(q); len(nc.Rows) > n {
		nc.Rows = nc.Rows[:n]
	}
	nc.RowsTotal = max(nc.RowsTotal, len(nc.Rows))
	return nc
}

// completeFirewall is the answer of GET /api/network/firewall, completed as
// completeConnections completes the connections: the period, every list present, at most
// rowCap(q) outbound rows. OutboundDevices is at least the number of distinct devices the rows
// listed name, so that the dashboard's "from N devices" never counts fewer than it lists.
func completeFirewall(fw model.NetFirewall, q contracts.NetQuery) model.NetFirewall {
	if fw.From == "" {
		fw.From = networkTime(q.From)
	}
	if fw.To == "" {
		fw.To = networkTime(q.To)
	}
	fw.Hours = nonNil(fw.Hours)
	fw.Countries = nonNil(fw.Countries)
	fw.TopSources = nonNil(fw.TopSources)
	fw.Services = nonNil(fw.Services)
	fw.Reasons = nonNil(fw.Reasons)
	fw.OutboundRows = nonNil(fw.OutboundRows)
	if n := rowCap(q); len(fw.OutboundRows) > n {
		fw.OutboundRows = fw.OutboundRows[:n]
	}
	fw.OutboundTotal = max(fw.OutboundTotal, len(fw.OutboundRows))
	devices := make(map[string]struct{}, len(fw.OutboundRows))
	for _, r := range fw.OutboundRows {
		devices[r.Device] = struct{}{}
	}
	fw.OutboundDevices = max(fw.OutboundDevices, len(devices))
	return fw
}

// nonNil returns list, or an empty list for nil (encoded as [] instead of null).
func nonNil[T any](list []T) []T {
	if list == nil {
		return []T{}
	}
	return list
}
