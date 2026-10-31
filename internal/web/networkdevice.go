package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// Limits and defaults of GET /api/network/device (docs/dhcp-table.md §7).
const (
	// DefaultDeviceSyslogLimit and MaxDeviceSyslogLimit bound the syslog messages of a device's
	// details (limit=): a larger limit is read as the most, as GET /api/syslog does.
	DefaultDeviceSyslogLimit = 100
	MaxDeviceSyslogLimit     = 500
	// MaxNetworkDeviceKeyBytes bounds key=: a device key as GET /api/network/devices lists it -
	// "mac:…", "ip:…", or "name:" and the name the gateway shows for an entry without either.
	MaxNetworkDeviceKeyBytes = 512
)

// handleNetworkDevice serves GET /api/network/device?key=|addr=&range=|from=&to=&limit=: one
// device of the Devices tab (key: its key as GET /api/network/devices lists it) or one unknown
// LAN address (addr: an IPv4 address) over the period - as the Devices view lists it, its
// addresses and who else held them, the LAN scans as it answered them, what its syslog messages
// are found by (model.NetDeviceDetail; docs/dhcp-table.md §7) - with its syslog messages: those of
// the period that the network view's terms find (syslogMatcher), newest first, at most limit
// (default DefaultDeviceSyslogLimit, at most MaxDeviceSyslogLimit) and MaxSyslogAnswerBytes of
// JSON (syslog_truncated: more matched), each naming its chunk and that chunk's syslog_chunk
// record as GET /api/syslog does (integrity problems of the records read in WarningHeader). The
// period is checked as for the other network endpoints (parseNetworkQuery; a device filter is
// refused), and exactly one of key and addr is given. The view's errors are answered as theirs
// are, 404 when the period knows neither the device nor the address. Without a syslog store the
// details have no syslog messages; a syslog store that cannot be read leaves them out too, and
// syslog_error says why. Without a network view the endpoint answers 404.
func (s *Server) handleNetworkDevice(w http.ResponseWriter, r *http.Request) {
	if s.network == nil {
		writeError(w, http.StatusNotFound, msgNoNetwork)
		return
	}
	q, key, addr, limit, err := parseNetworkDeviceQuery(r.URL.Query(), s.now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), networkTimeout)
	defer cancel()
	dd, err := s.network.Device(ctx, q, key, addr)
	if err != nil {
		if errors.Is(err, contracts.ErrNotFound) && !errors.Is(err, contracts.ErrUnavailable) {
			// Worded, so that a client tells it from the router's "not found" of an older version.
			writeError(w, http.StatusNotFound, msgNoDevice(key))
			return
		}
		s.writeErr(w, "network device", err)
		return
	}
	dd = completeDeviceDetail(dd, q)
	if s.syslog != nil {
		if match := newSyslogMatcher(dd.Match); match != nil {
			found, truncated, err := s.syslog.Query(ctx, q.From, q.To, match.match, limit)
			switch {
			case err != nil && ctx.Err() != nil:
				s.writeErr(w, "network device", ctx.Err()) // the request ended, or took too long
				return
			case err != nil:
				s.log.Warn("web: the syslog messages of a device could not be read", "err", err)
				dd.SyslogError = "the syslog messages could not be read: " + err.Error()
			default:
				if len(found) > limit {
					found, truncated = found[:limit], true
				}
				n := syslogAnswerFits(found, MaxSyslogAnswerBytes)
				if n < len(found) {
					truncated = true
				}
				// A copy of what is listed: the entries are completed here, and the store may keep
				// what it returned.
				entries := slices.Clone(found[:n])
				if entries == nil {
					entries = []model.SyslogEntry{}
				}
				var chk integrityCheck
				if err := s.fillChunkSeqs(ctx, entries, &chk); err != nil {
					s.writeErr(w, "network device", err) // the client went away
					return
				}
				if msg := chk.warning(); msg != "" {
					w.Header().Set(WarningHeader, headerSafe(msg))
				}
				dd.Syslog, dd.SyslogTruncated = entries, truncated
			}
		}
	}
	writeJSON(w, http.StatusOK, dd)
}

// msgNoDevice answers GET /api/network/device when the period knows no such device (a key was
// asked for) or unknown address (404).
func msgNoDevice(key string) string {
	if key != "" {
		return "not found: the Devices view of this period lists no device with this key"
	}
	return "not found: this address is none of the unknown addresses of this period"
}

// parseNetworkDeviceQuery validates the parameters of GET /api/network/device: the period as for
// the other network endpoints (parseNetworkQuery, without a device filter; its limit is not the
// rows'), exactly one of key - 1 to MaxNetworkDeviceKeyBytes bytes of UTF-8 without control
// characters - and addr - an IPv4 address, given in canonical form to the view -, and limit:
// the syslog messages, 1 or more (DefaultDeviceSyslogLimit when not given, at most
// MaxDeviceSyslogLimit).
func parseNetworkDeviceQuery(v url.Values, now time.Time) (q contracts.NetQuery, key, addr string, limit int, err error) {
	period := url.Values{}
	for k, vs := range v {
		switch k {
		case "key", "addr", "limit":
		default:
			period[k] = vs
		}
	}
	if q, err = parseNetworkQuery(period, now, false); err != nil {
		return contracts.NetQuery{}, "", "", 0, err
	}
	key, addr = v.Get("key"), strings.TrimSpace(v.Get("addr"))
	switch {
	case key != "" && addr != "":
		return contracts.NetQuery{}, "", "", 0, errors.New("give key (a device of GET /api/network/devices) or addr (an unknown address), not both")
	case key == "" && addr == "":
		return contracts.NetQuery{}, "", "", 0, errors.New("key (a device of GET /api/network/devices) or addr (an unknown address) is required")
	case key != "" && !validNetworkKey(key):
		return contracts.NetQuery{}, "", "", 0, fmt.Errorf("key must be a device key as GET /api/network/devices lists it (at most %d bytes of text, no control characters)",
			MaxNetworkDeviceKeyBytes)
	case addr != "":
		a, perr := netip.ParseAddr(addr)
		if perr != nil || !a.Is4() {
			return contracts.NetQuery{}, "", "", 0, errors.New("addr must be an IPv4 address (an unknown address of GET /api/network/devices)")
		}
		addr = a.String()
	}
	limit = DefaultDeviceSyslogLimit
	if lv := v.Get("limit"); lv != "" {
		n, perr := strconv.Atoi(lv)
		if perr != nil || n < 1 {
			return contracts.NetQuery{}, "", "", 0, fmt.Errorf("limit must be a positive integer (at most %d syslog messages)", MaxDeviceSyslogLimit)
		}
		limit = min(n, MaxDeviceSyslogLimit)
	}
	return q, key, addr, limit, nil
}

// validNetworkKey reports whether k can be a device key of the Devices view: 1 to
// MaxNetworkDeviceKeyBytes bytes of UTF-8 without control or format characters (a key holds a MAC
// or an IP address, or the name the gateway shows: anything else is refused before it reaches the
// view).
func validNetworkKey(k string) bool {
	if k == "" || len(k) > MaxNetworkDeviceKeyBytes || !utf8.ValidString(k) {
		return false
	}
	for _, r := range k {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

// completeDeviceDetail is the answer of GET /api/network/device before its syslog messages: the
// view's, with the period filled in when the view left it out and every list present (empty rather
// than null, the issues too). What it completes is copied first: the view may keep what it
// returned.
func completeDeviceDetail(dd model.NetDeviceDetail, q contracts.NetQuery) model.NetDeviceDetail {
	if dd.From == "" {
		dd.From = networkTime(q.From)
	}
	if dd.To == "" {
		dd.To = networkTime(q.To)
	}
	if dd.Device != nil {
		d := *dd.Device
		d.Issues = nonNil(slices.Clone(d.Issues))
		dd.Device = &d
	}
	if dd.Unknown != nil {
		u := *dd.Unknown
		u.Issues = nonNil(slices.Clone(u.Issues))
		dd.Unknown = &u
	}
	dd.Addresses = nonNil(dd.Addresses)
	dd.Scans = nonNil(dd.Scans)
	dd.Match = nonNil(dd.Match)
	dd.Syslog, dd.SyslogTruncated = []model.SyslogEntry{}, false
	return dd
}
