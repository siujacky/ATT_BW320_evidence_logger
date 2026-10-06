package web

// A rich, self-consistent fake monitor for visual checks of the dashboard:
//
//	ATTMON_WEB_DEMO=1 go test ./internal/web/ -run TestDemoServer -timeout 0 -v
//
// serves the UI with demo data on http://127.0.0.1:8399/ for ATTMON_WEB_DEMO_SECONDS
// (default 1800). Demo-only endpoints (outside the security middleware, test code only):
// /demo/state?s=outage|online switches between a healthy line and a live AT&T fiber outage,
// /demo/vpn starts a live VPN period (rules 2026.10-4 LOCAL_ROUTE), /demo/stale shows a monitor
// that records no cycle, /demo/dnsretry a lost AT&T resolver query and its retry, /demo/clock
// the CLOCK_OFFSET condition, /demo/cert makes the gateway present a changed certificate,
// /demo/noaccess and /demo/anchoruntrusted show those conditions, /demo/syslog?state=... the
// gateway syslog card's other states, /demo/quit stops the server
// (see TestDemoServer for the others). ATTMON_WEB_DEMO_STATE=outage starts in outage mode;
// ATTMON_WEB_DEMO_HOSTILE=1 appends "<img src=x onerror=alert(1)>" to every remote-controlled
// string (gateway values, DNS answers, TSA names, notes, ...) to check that all of it is
// rendered as text.
//
// TestDemoWorldEndpoints always runs the whole API against the same world, so the demo data
// stays consistent with the model types.

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

var (
	_ contracts.StatusSource = (*demoWorld)(nil)
	_ contracts.Actions      = (*demoWorld)(nil)
	_ contracts.LedgerReader = (*demoWorld)(nil)
	_ contracts.Verifier     = (*demoWorld)(nil)
	_ contracts.Exporter     = (*demoWorld)(nil)
)

const (
	demoRules   = "2026.10-4"
	demoGateway = "192.168.1.254"
	demoNextHop = "203.0.113.1"
	demoWANIP   = "203.0.113.45"
	demoISPDNS  = "68.94.156.9"
	// demoVPNIf/demoVPNHop: the VPN adapter ("NordLynx") that takes the internet routes while a
	// VPN is connected (rules 2026.10-4 egress check).
	demoVPNIf   = "NordLynx"
	demoVPNHop  = "10.5.0.1"
	demoCertSHA = "49cd292d40af94d686b6ee17cb67ce4ded40e9c0be2b2537c7bc6e37cf9a2ed0"
	// demoNewCertSHA is the certificate a "changed" gateway presents (/demo/cert).
	demoNewCertSHA = "7f3a9c5e21d84b6f0a9e8d7c6b5a49382716f5e4d3c2b1a09f8e7d6c5b4a3921"
	// demoGoogleCertSHA is the leaf certificate www.google.com presents to the HTTPS check.
	demoGoogleCertSHA = "3b0f6e1c9a2d48e7b5c4f3a2918d7e6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f09"
)

var demoTSAs = []string{"http://timestamp.digicert.com", "https://freetsa.org/tsr"}

// demoProbeBaseMs is the typical round-trip time of each default probe.
var demoProbeBaseMs = map[string]float64{
	"gateway_icmp": 1.9, "gateway_tcp": 3.1, "isp_hop_icmp": 4.2,
	"inet_icmp_cloudflare": 10.8, "inet_icmp_google": 12.4, "inet_icmp_quad9": 14.9,
	"inet_tcp_cloudflare": 11.6, "inet_tcp_google": 13.3,
}

type demoEvent struct {
	name        string
	from, to    time.Time // to.IsZero() = ongoing
	state       string
	cause       string
	attribution string
	incident    bool // long enough to open an incident
	gap         bool // monitor not running (PC asleep)
	summary     string
	reasons     []string
	incidentID  string
	// boot is set for a gateway restart: the gateway's boot time (estimated from its uptime).
	// The gateway is unreachable from the event's start until then, and the whole event lies
	// inside the restart window (docs/DESIGN.md §10).
	boot time.Time
}

func (e *demoEvent) covers(t time.Time) bool {
	return !t.Before(e.from) && (e.to.IsZero() || t.Before(e.to))
}

// stateAt is the real-time classification during the event. A gateway restart is first a
// LOCAL_FAULT (gateway unreachable) and, once the gateway answers again but its WAN is not up
// yet, an ISP_OUTAGE: samples keep these real-time verdicts; only the incident applies the
// restart window (docs/DESIGN.md §10).
func (e *demoEvent) stateAt(t time.Time) (state, cause, attribution string) {
	if !e.boot.IsZero() {
		if t.Before(e.boot) {
			return model.StateLocalFault, model.CauseGatewayUnreachable, model.AttrUndetermined
		}
		return model.StateISPOutage, model.CauseWANDown, model.AttrProvider
	}
	return e.state, e.cause, e.attribution
}

// overlap returns how much of [a, b) the event covers.
func (e *demoEvent) overlap(a, b time.Time) time.Duration {
	s, en := e.from, e.to
	if en.IsZero() || en.After(b) {
		en = b
	}
	if s.Before(a) {
		s = a
	}
	if en.After(s) {
		return en.Sub(s)
	}
	return 0
}

type demoWorld struct {
	mu      sync.Mutex
	created time.Time
	genesis time.Time
	key     ed25519.PrivateKey
	run     string

	envs   []model.Envelope
	bodies []model.Body
	segs   []demoSegment
	blobs  map[string][]byte

	events     []*demoEvent
	incidents  []*model.Incident
	live       *demoEvent // live outage, nil when online
	liveInc    *model.Incident
	exports    []contracts.ExportInfo
	exportData map[string][]byte
	notif      model.NotificationState
	lastVerify *model.VerifySummary
	cycle      uint64

	page  map[string]string // "broadbandstatistics", "broadbandstatistics.down", ... -> blob id
	tsr   []string          // TSA token blob ids
	netsh string

	// Visual-check knobs (TestDemoServer's /demo/* endpoints only).
	extraConds    []model.Condition // shown after the optical Rx conditions
	notifRecordEr string            // non-empty: the gateway takes the change but recording it fails
	unreadable    map[uint64]bool   // lines the reader skips, as the ledger does for damaged lines

	// Certificate pin state (docs/DESIGN.md §2): a changed certificate waits in pendingCert
	// until TrustCert; certSeq is the cert_changed gateway_event that recorded it.
	pinnedCert, pendingCert string
	certSeq                 uint64
	certSince               time.Time
	noGatewayCert           bool // Status without GatewayCert (as from an older monitor)
	noAccessCode            bool // condition NO_ACCESS_CODE; authenticated actions fail
	anchorUntrusted         bool // condition ANCHOR_UNTRUSTED; new anchors do not chain to a trusted root
	dnsHijack               bool // from now on the gateway's resolver answers the .invalid hijack test with its own address

	lastOf map[string]model.Ref // latest record of each type (verdict inputs)
	prevOf map[string]model.Ref // the record of each type before the latest one
	// sampled: the cycle start times (Unix ns) a sample was recorded for, so that an event's own
	// samples and the background cadence never record the same cycle twice.
	sampled map[int64]bool

	// Rules 2026.10-4 DNS retries in the history: the AT&T resolver's queries (and their
	// retries) fail in the service checks in [ispDNSFrom, ispDNSTo); in the check of the minute
	// ispRetryAt its first query is lost and the retry answers.
	ispDNSFrom, ispDNSTo, ispRetryAt time.Time

	// Visual-check knobs for rules 2026.10-4 (tests and TestDemoServer's /demo/* endpoints).
	stale        bool   // the monitor records no cycle: Status is UNKNOWN with the monitor's reason, no "since"
	liveDNSRetry string // "answered" / "failed": the live AT&T resolver query is lost and retried

	// hostile, when set, is appended to every remote-controlled string the world produces
	// (records, status, incidents, verification, exports): see hostilize.
	hostile string

	// The gateway's syslog (docs/syslog-snmp-traffic.md §3.2): the receiver's count since the
	// service started (syslogSince), the newest message, the latest gateway_event syslog_setting,
	// and the state shown (syslogState: "" = the gateway sends here; see syslogStatusLocked).
	syslogSince    time.Time
	syslogReceived int64
	syslogLast     *model.SyslogMessage
	syslogCheck    model.Ref
	syslogState    string

	// burstFrom/burstTo: a big download whose WAN rates are "at least" (traffic, §3.3).
	burstFrom, burstTo time.Time
}

type demoSegment struct {
	name       string
	date       time.Time
	start, end int // record index range [start, end)
}

func newDemoWorld(now time.Time) *demoWorld { return newDemoWorldWith(now, "") }

// newDemoWorldWith builds the demo world; a non-empty hostile string is appended to every
// remote-controlled string it produces (see hostilize).
func newDemoWorldWith(now time.Time, hostile string) *demoWorld {
	t0 := now.Truncate(time.Minute)
	w := &demoWorld{
		created:    now,
		genesis:    t0.Add(-7*24*time.Hour - 2*time.Hour),
		key:        ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize)),
		run:        "5f2c9a7e01d34b6c8e9f0a1b2c3d4e5f",
		blobs:      map[string][]byte{},
		exportData: map[string][]byte{},
		page:       map[string]string{},
		cycle:      48210,
		pinnedCert: demoCertSHA,
		lastOf:     map[string]model.Ref{},
		prevOf:     map[string]model.Ref{},
		sampled:    map[int64]bool{},
		hostile:    hostile,
	}
	h, m := time.Hour, time.Minute
	// The AT&T resolver fails in five consecutive checks (an incident: rules 2026.10-4 need the
	// same failure in two consecutive checks) and, a few minutes ago, loses one query only.
	w.ispDNSFrom, w.ispDNSTo, w.ispRetryAt = t0.Add(-27*m), t0.Add(-22*m), t0.Add(-5*m)
	// Two days ago a big download filled the line for 20 minutes (no incident at the time).
	w.burstFrom, w.burstTo = t0.Add(-2*24*h-5*h), t0.Add(-2*24*h-4*h-40*m)
	w.events = []*demoEvent{
		{name: "latency", from: t0.Add(-5*24*h - 3*h), to: t0.Add(-5*24*h - 2*h - 20*m), state: model.StateDegraded, cause: model.CauseHighLatency, attribution: model.AttrProvider, incident: true,
			summary: "Internet round-trip times above 150 ms for 40 min while the AT&T gateway answered in 2 ms with no loss.",
			reasons: []string{"median internet RTT 212 ms over the last 6 cycles", "gateway 192.168.1.254 RTT median 1.9 ms, 0 % loss"}},
		{name: "wan", from: t0.Add(-4*24*h - 2*h), to: t0.Add(-4*24*h - h - 12*m), state: model.StateISPOutage, cause: model.CauseWANDown, attribution: model.AttrProvider, incident: true,
			summary: "AT&T gateway reported Broadband Connection: Down for 48 min; the gateway itself stayed reachable from this PC.",
			reasons: []string{"AT&T gateway reports Broadband Connection: Down", "gateway 192.168.1.254 answered ICMP in 2.0 ms", "0/5 internet probes succeeded"}},
		{name: "wifi", from: t0.Add(-30*h - 12*m), to: t0.Add(-30*h - 6*m), state: model.StateLocalFault, cause: model.CauseLocalLinkDown, attribution: model.AttrLocal, incident: true,
			summary: "This PC's Wi-Fi adapter was disconnected for 6 min; the gateway was unreachable from this PC, so no claim about AT&T is made.",
			reasons: []string{"Wi-Fi interface reports state: disconnected", "gateway 192.168.1.254 did not answer ICMP or TCP 443"}},
		{name: "blip2", from: t0.Add(-19*h - 31*m), to: t0.Add(-19*h - 31*m + 20*time.Second), state: model.StateDegraded, cause: model.CausePacketLoss, attribution: model.AttrUndetermined},
		{name: "sleep", from: t0.Add(-14*h - 40*m), to: t0.Add(-13*h - 25*m), gap: true},
		{name: "reboot", from: t0.Add(-6*h - 12*m), to: t0.Add(-6*h - 12*m + 330*time.Second), boot: t0.Add(-6*h - 12*m + 160*time.Second),
			state: model.StateLocalFault, cause: model.CauseGatewayReboot, attribution: model.AttrUndetermined, incident: true,
			summary: "The AT&T gateway restarted (boot time estimated from its own uptime; firmware unchanged, 6.34.7). It did not answer for 2 min 40 s and reached the Internet again 2 min 50 s after booting. All 5 min 30 s lie inside the restart window, so none of it is counted as AT&T downtime; a restart can be caused by the owner as well as by AT&T, so the incident is not attributed.",
			reasons: []string{"AT&T gateway uptime reset: boot time moved to the restart (estimated from its uptime)", "gateway 192.168.1.254 did not answer ICMP or TCP 443 for 2 min 40 s", "firmware 6.34.7 before and after the restart"}},
		{name: "loss", from: t0.Add(-8*h - 20*m), to: t0.Add(-8*h - 4*m), state: model.StateDegraded, cause: model.CausePacketLoss, attribution: model.AttrUndetermined, incident: true,
			summary: "Between 30 % and 60 % of internet probes failed for 16 min; the gateway also lost one reply, so the cause is left undetermined.",
			reasons: []string{"inet loss over the window 41 % (>= 20 %)", "gateway probes lost 1 of 12 replies over the window"}},
		{name: "fiber", from: t0.Add(-3*h - 5*m), to: t0.Add(-2*h - 38*m), state: model.StateISPOutage, cause: model.CauseFiberLinkDown, attribution: model.AttrProvider, incident: true,
			summary: "AT&T gateway reported its fiber link down (PON INITIAL (O1), Optical WAN Down, Broadband Down) for 27 min while this PC reached the gateway in 2 ms; no internet probe succeeded.",
			reasons: []string{"AT&T gateway reports PON Link Status: INITIAL (O1)", "AT&T gateway reports Optical WAN Operational Status: Down", "AT&T gateway reports Broadband Connection: Down", "gateway 192.168.1.254 answered ICMP in 2.1 ms", "0/5 internet probes succeeded"}},
		{name: "blip1", from: t0.Add(-2*h - 10*m), to: t0.Add(-2*h - 10*m + 20*time.Second), state: model.StateISPOutage, cause: model.CauseUpstreamUnreachable, attribution: model.AttrProvider},
		// Rules 2026.10-4: a VPN took the internet routes; the gateway answered, so the failed
		// internet probes say nothing about AT&T (LOCAL_ROUTE).
		{name: "vpn", from: t0.Add(-10*h - 5*m), to: t0.Add(-9*h - 50*m), state: model.StateLocalFault, cause: model.CauseLocalRoute, attribution: model.AttrUndetermined, incident: true,
			summary: "No internet probe succeeded for 15 min while the AT&T gateway answered in 2 ms, but this computer's routes to the internet destinations went through the VPN adapter NordLynx, not through the AT&T gateway, so nothing is attributed to AT&T.",
			reasons: []string{"gateway 192.168.1.254 answered ICMP in 2.0 ms", "0/5 internet probes succeeded", demoBypassText,
				"the gateway was reachable but this computer's internet probes do not leave through it, so their failure says nothing about AT&T's network"}},
		// Rules 2026.10-4: the AT&T resolver failed in consecutive service checks (each query
		// retried once) while the public resolver answered; the household's own WAN traffic was
		// low, so the degradation is AT&T's. The samples' reasons and inputs are filled in by
		// appendSampleLocked (they name the records compared).
		{name: "dns", from: t0.Add(-26*m + 30*time.Second), to: t0.Add(-22*m + 30*time.Second), state: model.StateDegraded, cause: model.CauseISPDNSFailure, attribution: model.AttrProvider, incident: true,
			summary: "The AT&T resolver 68.94.156.9 gave no answer in five consecutive service checks (each query retried once) while the public resolver 1.1.1.1 answered; the gateway answered without loss and the household's own WAN traffic stayed below 80 Mb/s.",
			reasons: []string{"ISP resolver 68.94.156.9 failed (timeout; retried: timeout) while public resolver 1.1.1.1 answered, in consecutive service checks",
				"gateway probes had no loss over the last 6 cycles (12/12 answered)", "the household's own WAN traffic was below 80 Mb/s in each direction"}},
	}
	for _, e := range w.events {
		if e.incident {
			e.incidentID = "INC-" + e.from.UTC().Format("20060102-150405") + "Z"
		}
	}
	w.loadBlobs()
	w.buildLedger()
	return w
}

// ----------------------------------------------------------------------------- blobs

func demoFile(parts ...string) []byte {
	b, err := os.ReadFile(filepath.Join(append([]string{"..", ".."}, parts...)...))
	if err != nil {
		name := parts[len(parts)-1]
		return []byte("<html><head><title>" + name + "</title></head><body><h1>" + name + "</h1><p>(fixture not available)</p></body></html>")
	}
	return b
}

func (w *demoWorld) putBlob(b []byte) string {
	sum := sha256.Sum256(b)
	id := hex.EncodeToString(sum[:])
	w.blobs[id] = b
	return id
}

func (w *demoWorld) loadBlobs() {
	bb := demoFile("testdata", "gateway", "broadbandstatistics.html")
	fb := demoFile("testdata", "gateway", "fiberstat.html")
	si := demoFile("testdata", "gateway", "sysinfo.html")
	w.page["broadbandstatistics"] = w.putBlob(bb)
	w.page["fiberstat"] = w.putBlob(fb)
	w.page["sysinfo"] = w.putBlob(si)

	bbDown := regexp.MustCompile(`(Broadband Connection</th>\s*<td class="col2">\s*)Up`).ReplaceAll(bb, []byte("${1}Down"))
	bbDown = bytes.ReplaceAll(bbDown, []byte("OPERATION (O5)"), []byte("INITIAL (O1)"))
	w.page["broadbandstatistics.down"] = w.putBlob(bbDown)
	fbDown := regexp.MustCompile(`((?:Optical WAN Operational Status|Link State)</th>\s*<td class="col2">)Up`).ReplaceAll(fb, []byte("${1}Down"))
	w.page["fiberstat.down"] = w.putBlob(fbDown)
	siDown := regexp.MustCompile(`(Current Date/Time</th>\s*<td class="col2">\s*)[0-9T:-]+`).ReplaceAll(si, []byte("${1}"))
	w.page["sysinfo.down"] = w.putBlob(siDown)
	w.page["events.before"] = w.putBlob(demoFile("testdata", "gateway", "events_checked.html"))
	w.page["events.after"] = w.putBlob(demoFile("testdata", "gateway", "events_unchecked.html"))
	w.page["syslog"] = w.putBlob([]byte(demoSyslogPage))

	w.tsr = []string{w.putBlob(demoFile("testdata", "tsa", "digicert.tsr")), w.putBlob(demoFile("testdata", "tsa", "freetsa.tsr"))}
	w.netsh = w.putBlob([]byte(strings.ReplaceAll(`
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6E AX211 160MHz
    GUID                   : 00000000-0000-0000-0000-000000000000
    Physical address       : 02:00:00:00:00:71
    Interface type         : Primary
    State                  : connected
    SSID                   : HOME-5G
    AP BSSID               : 02:00:5e:10:00:01
    Band                   : 5 GHz
    Channel                : 149
    Network type           : Infrastructure
    Radio type             : 802.11ax
    Authentication         : WPA3-Personal
    Cipher                 : CCMP
    Connection mode        : Auto Connect
    Receive rate (Mbps)    : 1201
    Transmit rate (Mbps)   : 1201
    Signal                 : 86%
    Profile                : HOME-5G
`, "\n", "\r\n")))
}

// ----------------------------------------------------------------------------- hostile data

// hostileMarker is what a party controlling a displayed value (a gateway page, a DNS answer,
// a TSA certificate, a crafted ledger line, ...) would send to inject markup.
const hostileMarker = "<img src=x onerror=alert(1)>"

// hostileKeep lists the JSON fields that stay machine-readable in hostile mode: identifiers,
// hashes, times, and the enums and keys the dashboard computes with. Every other string value,
// and every key of the maps in hostileMapKeys, gets the marker appended.
var hostileKeep = map[string]bool{
	"id": true, "incident_id": true, "h": true, "s": true, "b": true, "prev": true, "run": true, "run_id": true,
	"sha256": true, "token_sha256": true, "raw_sha256": true, "head_hash": true, "body_sha256": true,
	"tls_cert_sha256": true, "fingerprint": true, "blob": true, "blobs": true, "bundle_sha256": true,
	"manifest_sha256": true, "config_sha256": true, "exe_sha256": true, "public_key": true,
	"prev_segment_sha256": true, "removed_sha256": true, "hash": true, "nonce": true, "file_name": true,

	"ts": true, "t": true, "at": true, "since": true, "now": true, "opened": true, "closed": true,
	"recovered_at": true, "gateway_restarts": true, "started": true, "created": true, "fetched_at": true,
	"gen_time": true, "checked_at": true, "first_ts": true, "last_ts": true, "genesis_ts": true, "head_ts": true,
	"last_anchor_time": true, "from": true, "to": true, "boot_time_estimate": true, "mod_time": true, "boot_time": true,
	"rx": true, "last_at": true, "gateway_at": true, "day": true,

	"state": true, "cause": true, "causes": true, "attribution": true, "type": true, "kind": true, "role": true,
	"code": true, "severity": true, "rules": true, "from_state": true, "to_state": true, "from_cause": true,
	"to_cause": true, "name": true, "window": true, "range": true, "qtype": true, "problem": true,
}

// hostileMapKeys are the maps whose keys come from the gateway's pages or the ledger.
var hostileMapKeys = map[string]bool{"values": true, "counters": true, "type_counts": true, "probe_ok": true, "probe_total": true}

var hexFingerprint = regexp.MustCompile(`^[0-9a-f]{64}$`)

// hostilize appends marker to the strings of a decoded JSON value (see hostileKeep); key is
// the field name v was found under.
func hostilize(v any, key, marker string) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			nk := k
			if hostileMapKeys[key] {
				nk = k + " " + marker
			}
			out[nk] = hostilize(val, k, marker)
		}
		return out
	case []any:
		for i := range x {
			x[i] = hostilize(x[i], key, marker)
		}
		return x
	case string:
		if hostileKeep[key] || hexFingerprint.MatchString(x) {
			return x
		}
		return x + " " + marker
	}
	return v
}

// hostileJSON applies hostilize to JSON text (numbers are kept exactly).
func hostileJSON(raw []byte, marker string) []byte {
	if marker == "" {
		return raw
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		panic(err)
	}
	out, err := json.Marshal(hostilize(v, "", marker))
	if err != nil {
		panic(err)
	}
	return out
}

// hostileCopy returns v with hostilize applied.
func hostileCopy[T any](marker string, v T) T {
	if marker == "" {
		return v
	}
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	var out T
	if err := json.Unmarshal(hostileJSON(b, marker), &out); err != nil {
		panic(err)
	}
	return out
}

// ----------------------------------------------------------------------------- ledger

func (w *demoWorld) appendLocked(ts time.Time, typ string, data any, blobs ...string) model.Ref {
	raw, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}
	raw = hostileJSON(raw, w.hostile)
	seq := uint64(len(w.envs))
	prev := model.ZeroHash
	if seq > 0 {
		prev = w.envs[seq-1].H
		if last, _ := time.Parse(time.RFC3339Nano, w.bodies[seq-1].TS); ts.Before(last) {
			ts = last.Add(time.Millisecond) // keep ts monotonic in the demo ledger
		}
	}
	day := time.Date(ts.UTC().Year(), ts.UTC().Month(), ts.UTC().Day(), 0, 0, 0, 0, time.UTC)
	if n := len(w.segs); n == 0 || day.After(w.segs[n-1].date) {
		if n > 0 && typ != model.TypeSegmentOpen {
			prevSeg := w.segs[n-1]
			sum := sha256.Sum256(w.segmentBytesLocked(prevSeg))
			w.segs = append(w.segs, demoSegment{name: "ledger-" + day.Format("2006-01-02"), date: day, start: int(seq), end: int(seq)})
			w.appendLocked(ts, model.TypeSegmentOpen, model.SegmentOpen{
				Segment: "ledger-" + day.Format("2006-01-02"), PrevSegment: prevSeg.name, PrevSegmentSHA256: hex.EncodeToString(sum[:]),
				PrevSegmentRecords: prevSeg.end - prevSeg.start, PrevSegmentLastSeq: uint64(prevSeg.end - 1),
			})
			// As the monitor: every daily segment states the configuration in force.
			w.appendLocked(ts, model.TypeConfigState, model.ConfigState{ConfigSHA256: demoConfigSHA, Config: demoConfigJSON(),
				Rules: demoRules, Reason: "new_segment"})
			return w.appendLocked(ts, typ, data, blobs...)
		}
		if n == 0 {
			w.segs = append(w.segs, demoSegment{name: "ledger-" + day.Format("2006-01-02"), date: day, start: int(seq), end: int(seq)})
		}
	}
	body := model.Body{
		V: model.FormatVersion, Seq: seq, Prev: prev, TS: ts.UTC().Format(time.RFC3339Nano),
		Mono: ts.Sub(w.genesis).Nanoseconds(), Run: w.run, Type: typ, Blobs: blobs, Data: raw,
	}
	env := sealRecord(w.key, body)
	w.envs = append(w.envs, env)
	w.bodies = append(w.bodies, body)
	w.segs[len(w.segs)-1].end = len(w.envs)
	ref := model.Ref{Seq: seq, Hash: env.H, TS: body.TS}
	if last, ok := w.lastOf[typ]; ok {
		w.prevOf[typ] = last
	}
	w.lastOf[typ] = ref
	return ref
}

// freshInput returns the seq of the latest record of typ if it is recent enough to be a
// verdict input at ts (docs/DESIGN.md §9: snapshots and service checks at most 150 s old; the
// local link is measured every minute but recorded only on change or every 10 minutes), else 0.
func (w *demoWorld) freshInput(typ string, ts time.Time) uint64 {
	ref, ok := w.lastOf[typ]
	if !ok {
		return 0
	}
	maxAge := 150 * time.Second
	if typ == model.TypeLocalLink {
		maxAge = 11 * time.Minute
	}
	if at, err := time.Parse(time.RFC3339Nano, ref.TS); err != nil || ts.Sub(at) > maxAge {
		return 0
	}
	return ref.Seq
}

func (w *demoWorld) segmentBytesLocked(sg demoSegment) []byte {
	var buf bytes.Buffer
	for _, env := range w.envs[sg.start:sg.end] {
		b, _ := json.Marshal(env)
		buf.Write(append(b, '\n'))
	}
	return buf.Bytes()
}

func (w *demoWorld) headLocked() model.Ref {
	n := len(w.envs)
	if n == 0 {
		return model.Ref{}
	}
	return model.Ref{Seq: uint64(n - 1), Hash: w.envs[n-1].H, TS: w.bodies[n-1].TS}
}

// demoConfigSHA is the recorded hash of the demo configuration (secrets removed).
var demoConfigSHA = strings.Repeat("c0", 32)

// demoConfigJSON is the effective demo configuration as the monitor records it (secrets removed).
func demoConfigJSON() json.RawMessage {
	cfg, err := json.Marshal(config.Default())
	if err != nil {
		panic(err)
	}
	return cfg
}

// demoUntrustedChain is why a TSA certificate did not chain to a trusted root, as the anchor
// package words it (Anchor.ChainNote).
const demoUntrustedChain = "system roots: x509: certificate signed by unknown authority"

func (w *demoWorld) anchorLocked(ts time.Time, reason string) []model.Anchor {
	head := w.headLocked()
	var out []model.Anchor
	for i, u := range demoTSAs {
		a := model.Anchor{
			TSAURL: u, TSAName: []string{"CN=DigiCert SHA256 RSA4096 Timestamp Responder 2025 1", "CN=www.freetsa.org"}[i],
			HeadSeq: head.Seq, HeadHash: head.Hash, TokenSHA256: w.tsr[i],
			GenTime: ts.Add(time.Duration(i+1) * 400 * time.Millisecond).UTC().Format(time.RFC3339),
			Serial:  fmt.Sprintf("%x", head.Seq*7919+uint64(i)), Policy: []string{"2.16.840.1.114412.7.1", "1.2.3.4.1"}[i],
			Nonce: fmt.Sprintf("%016x", head.Seq*31+uint64(i)), Verified: true, ChainOK: true, Reason: reason,
		}
		if w.anchorUntrusted && i == 1 { // FreeTSA's root is not in the Windows store
			a.ChainOK, a.ChainNote = false, demoUntrustedChain
		}
		w.appendLocked(ts.Add(time.Duration(i+1)*500*time.Millisecond), model.TypeAnchor, a, w.tsr[i])
		out = append(out, a)
	}
	return out
}

// ----------------------------------------------------------------------------- deterministic noise

func noise(t time.Time, k int) float64 {
	x := uint64(t.Unix()/5)*0x9E3779B97F4A7C15 ^ uint64(k+1)*0xBF58476D1CE4E5B9
	x ^= x >> 30
	x *= 0xBF58476D1CE4E5B9
	x ^= x >> 27
	x *= 0x94D049BB133111EB
	x ^= x >> 31
	return float64(x>>11) / float64(1<<53)
}

func probeIndex(name string) int {
	for i, p := range config.Default().Probes.Targets {
		if p.Name == name {
			return i
		}
	}
	return 99
}

// rttMs returns the simulated RTT of a probe at time t (successful replies only).
func (w *demoWorld) rttMs(name string, t time.Time, highLatency float64) float64 {
	base := demoProbeBaseMs[name]
	k := probeIndex(name)
	hour := float64(t.Local().Hour()) + float64(t.Local().Minute())/60
	diurnal := 1 + 0.08*math.Max(0, math.Sin((hour-14)/24*2*math.Pi)) // evening congestion
	v := base*diurnal*(0.88+0.24*noise(t, k)) + func() float64 {
		if noise(t, k+40) > 0.985 {
			return base * 2.5 * noise(t, k+80) // occasional spike
		}
		return 0
	}()
	if strings.HasPrefix(name, "inet_") {
		v += highLatency
	}
	return math.Round(v*100) / 100
}

// ----------------------------------------------------------------------------- state model

func stateRank(s string) int {
	switch s {
	case model.StateISPOutage:
		return 3
	case model.StateLocalFault:
		return 2
	case model.StateDegraded:
		return 1
	}
	return 0
}

func (w *demoWorld) allEventsLocked() []*demoEvent {
	if w.live == nil {
		return w.events
	}
	return append(append([]*demoEvent(nil), w.events...), w.live)
}

// probeOutcome returns the loss fraction (0..1) and the extra RTT for a probe in [a, b).
func probeOutcome(e *demoEvent, name string, frac float64, t time.Time) (loss float64, extra float64) {
	inet := strings.HasPrefix(name, "inet_")
	state, cause, _ := e.stateAt(t)
	switch state {
	case model.StateISPOutage:
		if inet || (name == "isp_hop_icmp" && cause != model.CauseUpstreamUnreachable) {
			return frac, 0
		}
	case model.StateLocalFault:
		if cause == model.CauseLocalRoute { // the gateway answers; the VPN tunnel carries nothing
			if inet {
				return frac, 0
			}
			return 0, 0
		}
		return frac, 0
	case model.StateDegraded:
		switch cause {
		case model.CausePacketLoss:
			if inet {
				return frac * (0.3 + 0.3*noise(t, probeIndex(name)+7)), 0
			}
			if name == "gateway_icmp" && noise(t, 3) > 0.7 {
				return frac / 12, 0
			}
		case model.CauseHighLatency:
			if inet {
				return 0, 180 + 70*noise(t, probeIndex(name)+9)
			}
		}
	}
	return 0, 0
}

// bucket aggregates the simulated cycles of [a, b).
func (w *demoWorld) bucketLocked(a, b time.Time) model.SeriesPoint {
	p := model.SeriesPoint{T: a.UTC().Format(time.RFC3339)}
	if b.Before(w.genesis) || !a.Before(w.created.Add(24*time.Hour)) {
		return p
	}
	span := b.Sub(a)
	var gap time.Duration
	worst := ""
	var active []*demoEvent
	for _, e := range w.allEventsLocked() {
		ov := e.overlap(a, b)
		if ov <= 0 {
			continue
		}
		if e.gap {
			gap += ov
			continue
		}
		active = append(active, e)
		// The worst state the event had inside the bucket (a restart changes state once).
		first, last := a, b.Add(-time.Nanosecond)
		if e.from.After(first) {
			first = e.from
		}
		if !e.to.IsZero() && e.to.Before(b) {
			last = e.to.Add(-time.Nanosecond)
		}
		for _, t := range []time.Time{first, last} {
			if st, _, _ := e.stateAt(t); stateRank(st) > stateRank(worst) {
				worst = st
			}
		}
	}
	if a.Before(w.genesis) {
		gap += w.genesis.Sub(a)
	}
	if gap >= span {
		return p // no data: the monitor was not running
	}
	if worst == "" {
		worst = model.StateOnline
	}
	p.State = worst
	p.RTTms = map[string]float64{}
	p.Loss = map[string]float64{}
	cycles := math.Max(1, span.Seconds()/10)
	for _, spec := range config.Default().Probes.Targets {
		loss, extra := 0.0, 0.0
		for _, e := range active {
			l, x := probeOutcome(e, spec.Name, float64(e.overlap(a, b))/float64(span), a)
			loss = math.Max(loss, l)
			extra = math.Max(extra, x)
		}
		if loss == 0 && noise(a, probeIndex(spec.Name)+20) > 0.97 {
			loss = 1 / cycles // an occasional single lost reply
		}
		p.Loss[spec.Name] = math.Round(loss*1000) / 1000
		if loss < 0.999 {
			p.RTTms[spec.Name] = w.rttMs(spec.Name, a, extra)
		}
	}
	return p
}

// rxX10 simulates the gateway-reported Rx power: it drifts from -28.8 dBm (6 days ago) to
// -31.5 dBm (3 days ago) and stays there, i.e. below the gateway's own alarm threshold.
func (w *demoWorld) rxX10(t time.Time) int64 {
	daysAgo := w.created.Sub(t).Hours() / 24
	var v float64
	switch {
	case daysAgo > 6:
		v = -288
	case daysAgo > 3:
		v = -288 - (6-daysAgo)/3*27
	default:
		v = -315
	}
	return int64(math.Round(v + 6*noise(t, 61) - 3))
}

func (w *demoWorld) opticalLocked(from, to time.Time, step time.Duration) []model.OpticalPoint {
	var out []model.OpticalPoint
	for t := from.Truncate(step); t.Before(to); t = t.Add(step) {
		if t.Before(w.genesis) || t.Before(from) {
			continue
		}
		var fiberDown, asleep bool
		for _, e := range w.allEventsLocked() {
			if e.covers(t) {
				asleep = asleep || e.gap
				fiberDown = fiberDown || e.cause == model.CauseFiberLinkDown
			}
		}
		if asleep {
			continue
		}
		pt := model.OpticalPoint{T: t.UTC().Format(time.RFC3339)}
		if fiberDown {
			pt.RxLowAlarm, pt.RxLowWarn = true, true // loss of light: flags set, no reading
		} else {
			rx := w.rxX10(t)
			tx := int64(37 + math.Round(2*noise(t, 62)-1))
			pt.RxX10, pt.TxX10 = &rx, &tx
			pt.RxLowAlarm, pt.RxLowWarn = rx < -295, rx < -292
		}
		out = append(out, pt)
	}
	return out
}

// ----------------------------------------------------------------------------- gateway snapshot

func i64(v int64) *int64 { return &v }
func bptr(v bool) *bool  { return &v }

func thr(active bool, v int64) model.Threshold {
	a := 0
	if active {
		a = 1
	}
	return model.Threshold{Active: active, Raw: fmt.Sprintf("%d (Threshold %d)", a, v), Threshold: i64(v)}
}

// bootAt returns the gateway's boot time as its uptime reports it at t: its last restart.
func (w *demoWorld) bootAt(t time.Time) time.Time {
	boot := w.created.Add(-3*24*time.Hour - 4*time.Hour - 17*time.Minute)
	for _, e := range w.events {
		if !e.boot.IsZero() && !e.boot.After(t) && e.boot.After(boot) {
			boot = e.boot
		}
	}
	return boot
}

// presentedCertLocked is the TLS certificate the gateway presents: the changed one while it
// waits for confirmation, else the pinned one.
func (w *demoWorld) presentedCertLocked() string {
	if w.pendingCert != "" {
		return w.pendingCert
	}
	return w.pinnedCert
}

// unreachableSnapshotLocked is a snapshot taken while the gateway cannot be reached at all:
// the first page fails and the others are not attempted.
func (w *demoWorld) unreachableSnapshotLocked(at time.Time, trigger, why string) model.GatewaySnapshot {
	snap := model.GatewaySnapshot{Trigger: trigger}
	for i, name := range []string{"broadbandstatistics", "fiberstat", "sysinfo"} {
		pc := model.PageCapture{Page: name, URL: "https://" + demoGateway + "/cgi-bin/" + name + ".ha",
			FetchedAt: at.Add(time.Duration(i) * time.Millisecond).UTC().Format(time.RFC3339Nano)}
		if i == 0 {
			pc.DurMs, pc.Err = 2004, why
		} else {
			pc.NotAttempted, pc.Err = true, "skipped: the gateway could not be reached (broadbandstatistics: "+why+")"
		}
		snap.Pages = append(snap.Pages, pc)
	}
	return snap
}

func (w *demoWorld) snapshotLocked(at time.Time, down bool, trigger string, stored bool) model.GatewaySnapshot {
	boot := w.bootAt(at)
	uptime := int64(at.Sub(boot).Seconds())
	rx := w.rxX10(at)
	conn, pon, opt, uni := "Up", "OPERATION (O5)", "Up", "up"
	gwTime := at.Local().Format("2006-01-02T15:04:05")
	sfx := ""
	if down {
		conn, pon, opt, uni, gwTime, sfx = "Down", "INITIAL (O1)", "Down", "down", "", ".down"
	}
	page := func(name string, ms int64) model.PageCapture {
		id := w.page[name+sfx]
		return model.PageCapture{
			Page: name, URL: "https://" + demoGateway + "/cgi-bin/" + name + ".ha", Status: 200,
			FetchedAt: at.Add(time.Duration(ms) * time.Millisecond).UTC().Format(time.RFC3339Nano), DurMs: ms + 180,
			Bytes: len(w.blobs[id]), SHA256: id, Stored: stored, TLSCertSHA256: w.presentedCertLocked(),
		}
	}
	lastChange := w.created.Add(-2*time.Hour - 38*time.Minute).Unix()
	counters := map[string]int64{
		"IPv4 Statistics/Receive Packets":  9_812_334_120 + uptime*3100,
		"IPv4 Statistics/Transmit Packets": 2_114_008_771 + uptime*900,
		"IPv4 Statistics/Receive Bytes":    13_450_118_337_201 + uptime*4_100_000,
		"IPv4 Statistics/Transmit Bytes":   1_208_334_017_450 + uptime*620_000,
		"IPv4 Statistics/Receive Drops":    112,
		"IPv4 Statistics/Transmit Drops":   0,
		"IPv4 Statistics/Receive Errors":   0,
		"IPv4 Statistics/Transmit Errors":  0,
	}
	values := map[string]string{
		"Broadband/Broadband Connection Source": "FIBER", "Broadband/Broadband Connection": conn,
		"Broadband/Broadband Network Type": "Lightspeed", "Broadband/Broadband IPv4 Address": demoWANIP,
		"Broadband/Gateway IPv4 Address": demoNextHop, "Broadband/MAC Address": "00:00:5e:00:53:01",
		"Broadband/Primary DNS": "68.94.156.9", "Broadband/Secondary DNS": "68.94.157.9", "Broadband/MTU": "1500",
		"Ethernet Status/Line State": "Up", "Ethernet Status/Current Speed (Mbps)": "10000", "Ethernet Status/Current Duplex": "full",
		"IPv6/Status": "Available", "IPv6/Service Type": "SLAAC", "IPv6/Global Unicast IPv6 Address": "2001:db8:4d2::1",
		"IPv6/Link Local Address": "fe80::200:5eff:fe00:5301", "IPv6/Default IPv6 Gateway Address": "fe80::1", "IPv6/MTU": "1500",
		"GPON Status/PON Link Status": pon, "GPON Status/UNI Status": uni,
	}
	for k, v := range counters {
		values[k] = strconv.FormatInt(v, 10)
	}
	fv := map[string]string{
		"Optical WAN Operational Status": opt, "Fiber Module": "Unavailable", "Last Change": strconv.FormatInt(lastChange, 10),
		"Link State": opt, "Name": "SFP", "Wave Length": "1270 nm", "Vendor Name": "HUMAX Networks", "Vendor OUI": "484D58",
		"Vendor PN": "HNXGSPP-MAAMC", "Vendor Rev": "V.01", "Vendor SN": "DV000000000000", "Tx Fault State": "0",
		"Rx LOS State": map[bool]string{true: "1", false: "0"}[down], "OPT LOS": "0", "Length SMF-km": "20",
	}
	var rxp *int64
	if !down {
		rxp = i64(rx)
	}
	rxMeasure := model.DMIMeasure{Name: "Rx Power", CurrentRaw: strconv.FormatInt(rx, 10), Current: rxp, Unit: "0.1dBm",
		LowAlarm: thr(true, -295), HighAlarm: thr(false, -90), LowWarn: thr(true, -292), HighWarn: thr(false, -100)}
	if down {
		rxMeasure.CurrentRaw = ""
	} else {
		rxMeasure.LowAlarm = thr(rx < -295, -295)
		rxMeasure.LowWarn = thr(rx < -292, -292)
	}
	var alarms []string
	if rxMeasure.LowAlarm.Active {
		alarms = append(alarms, "OPTICAL_RX_LOW_ALARM")
	}
	if rxMeasure.LowWarn.Active {
		alarms = append(alarms, "OPTICAL_RX_LOW_WARNING")
	}
	return model.GatewaySnapshot{
		Pages: []model.PageCapture{page("broadbandstatistics", 0), page("fiberstat", 1300), page("sysinfo", 2500)},
		System: &model.SystemInfo{
			Manufacturer: "NOKIA", Model: "BGW320-505", Serial: "N00SERIAL00000", SoftwareVersion: "6.34.7",
			WANMAC: "00:00:5e:00:53:01", FirstUseDate: "2026-02-17T18:20:24Z", HardwareVersion: "02001E0046004D",
			UptimeRaw: strconv.FormatInt(uptime, 10), UptimeSec: uptime, GatewayTimeRaw: gwTime, GatewayTimePresent: true,
		},
		Broadband: &model.BroadbandStatus{
			ConnectionSource: "FIBER", Connection: conn, NetworkType: "Lightspeed", IPv4: demoWANIP, GatewayIPv4: demoNextHop,
			PrimaryDNS: "68.94.156.9", SecondaryDNS: "68.94.157.9", MTU: "1500", LineState: "Up", SpeedMbps: "10000", Duplex: "full",
			IPv6Status: "Available", IPv6Global: "2001:db8:4d2::1", IPv6Gateway: "fe80::1", PONLinkStatus: pon, UNIStatus: uni,
			Counters: counters, Values: values,
		},
		Fiber: &model.FiberStatus{
			OpticalStatus: opt, FiberModule: "Unavailable", LastChangeRaw: strconv.FormatInt(lastChange, 10), LastChangeUnix: lastChange,
			LinkState: opt, WaveLength: "1270 nm", VendorName: "HUMAX Networks", VendorPN: "HNXGSPP-MAAMC", VendorSN: "DV000000000000",
			RxLOSState: fv["Rx LOS State"], OptLOS: "0", TxFaultState: "0", Values: fv,
			Measures: []model.DMIMeasure{
				{Name: "Temperature", CurrentRaw: "35", Current: i64(35), Unit: "C", LowAlarm: thr(false, -10), HighAlarm: thr(false, 80), LowWarn: thr(false, -5), HighWarn: thr(false, 75)},
				{Name: "Vcc", CurrentRaw: "3", Current: i64(3), Unit: "V", LowAlarm: thr(false, 3), HighAlarm: thr(false, 3), LowWarn: thr(false, 3), HighWarn: thr(false, 3)},
				{Name: "Tx Bias", CurrentRaw: "6", Current: i64(6), Unit: "mA", LowAlarm: thr(false, 0), HighAlarm: thr(false, 500), LowWarn: thr(false, 0), HighWarn: thr(false, 400)},
				{Name: "Tx Power", CurrentRaw: "37", Current: i64(37), Unit: "0.1dBm", LowAlarm: thr(false, -10), HighAlarm: thr(false, 80), LowWarn: thr(false, 0), HighWarn: thr(false, 70)},
				rxMeasure,
			},
		},
		Derived: model.GatewayDerived{
			Reachable: true, BroadbandUp: bptr(!down), PONOperational: bptr(!down), OpticalUp: bptr(!down),
			WANIPv4: map[bool]string{true: "", false: demoWANIP}[down], ISPNextHop: demoNextHop, ISPDNS: "68.94.156.9",
			RxPowerX10: rxp, TxPowerX10: i64(37), RxLowAlarmX10: i64(-295), RxLowWarnX10: i64(-292), Alarms: alarms,
			UptimeSec: uptime, BootTimeEstimate: boot.UTC().Format(time.RFC3339), GatewayClockBlank: down,
			GatewayClockOffsetMs: map[bool]*int64{true: nil, false: i64(1200)}[down],
			Firmware:             "6.34.7", Serial: "N00SERIAL00000", Model: "BGW320-505", FiberLastChange: lastChange,
		},
		Trigger: trigger,
	}
}

// ----------------------------------------------------------------------------- probes & checks

func (w *demoWorld) probesAt(t time.Time) ([]model.ProbeResult, model.Verdict) {
	var ev *demoEvent
	for _, e := range w.allEventsLocked() {
		if !e.gap && e.covers(t) {
			ev = e
		}
	}
	var out []model.ProbeResult
	okInet, totalInet := 0, 0
	for _, spec := range config.Default().Probes.Targets {
		target := spec.Target
		switch spec.Role {
		case model.RoleGateway:
			target = demoGateway
			if spec.Kind == model.KindTCP {
				target += ":443"
			}
		case model.RoleISPHop:
			target = demoNextHop
		}
		r := model.ProbeResult{Name: spec.Name, Kind: spec.Kind, Role: spec.Role, Target: target, OK: true}
		failed := false
		if ev != nil {
			loss, extra := probeOutcome(ev, spec.Name, 1, t)
			failed = loss >= 0.5 || (loss > 0 && noise(t, probeIndex(spec.Name)+33) < loss)
			r.RTTus = int64(w.rttMs(spec.Name, t, extra) * 1000)
		} else {
			r.RTTus = int64(w.rttMs(spec.Name, t, 0) * 1000)
		}
		if failed {
			r.OK, r.RTTus = false, 0
			if spec.Kind == model.KindICMP {
				r.Status = "IP_REQ_TIMED_OUT"
			} else {
				r.Status, r.Err = "timeout", "dial tcp "+target+": i/o timeout"
			}
		} else if spec.Kind == model.KindICMP {
			r.Status, r.ReplyFrom, r.TTL = "IP_SUCCESS", target, 64-min(probeIndex(spec.Name), 8)*3
		} else {
			r.Status = "connected"
		}
		if spec.Role == model.RoleInet {
			totalInet++
			if r.OK {
				okInet++
			}
		}
		out = append(out, r)
	}
	v := model.Verdict{State: model.StateOnline, Attribution: model.AttrNone, Rules: demoRules,
		Reasons: []string{fmt.Sprintf("gateway %s answered ICMP in %.1f ms", demoGateway, float64(out[0].RTTus)/1000),
			fmt.Sprintf("%d/%d internet probes succeeded", okInet, totalInet), "AT&T gateway reports Broadband Connection: Up"}}
	if ev != nil {
		state, cause, attribution := ev.stateAt(t)
		v = model.Verdict{State: state, Cause: cause, Attribution: attribution, Rules: demoRules, Reasons: ev.reasons}
		switch {
		case !ev.boot.IsZero() && t.Before(ev.boot):
			v.Reasons = []string{fmt.Sprintf("gateway %s did not answer ICMP or TCP 443", demoGateway), fmt.Sprintf("%d/%d internet probes succeeded", okInet, totalInet)}
		case !ev.boot.IsZero():
			v.Reasons = []string{fmt.Sprintf("gateway %s answered ICMP in %.1f ms", demoGateway, float64(out[0].RTTus)/1000),
				"AT&T gateway reports Broadband Connection: Down", fmt.Sprintf("%d/%d internet probes succeeded", okInet, totalInet)}
		case len(v.Reasons) == 0:
			v.Reasons = []string{fmt.Sprintf("%d/%d internet probes succeeded", okInet, totalInet)}
		}
	}
	return out, v
}

// demoHijackTestName is the random "<16 hex>.invalid" name a service check at t asks the
// gateway's resolver for (derived from t here; random in the monitor).
func demoHijackTestName(t time.Time) string {
	sum := sha256.Sum256([]byte(t.UTC().Format(time.RFC3339Nano)))
	return hex.EncodeToString(sum[:8]) + ".invalid"
}

// demoBypassText is the classifier's sentence for the VPN route (monitor bypassText).
const demoBypassText = `this computer's route to 1.1.1.1 leaves through "NordLynx" (interface 23) via 10.5.0.1, not through the AT&T gateway 192.168.1.254 (reached through "Wi-Fi" (interface 12))`

// routeBypassAt reports whether a VPN took this computer's internet routes at t (an event
// with cause LOCAL_ROUTE, recorded or live).
func (w *demoWorld) routeBypassAt(t time.Time) bool { return w.routeBypassEventAt(t) != nil }

// routeBypassEventAt returns the LOCAL_ROUTE event covering t, or nil.
func (w *demoWorld) routeBypassEventAt(t time.Time) *demoEvent {
	for _, e := range w.allEventsLocked() {
		if !e.gap && e.cause == model.CauseLocalRoute && e.covers(t) {
			return e
		}
	}
	return nil
}

// ispDNSDownAt reports whether the AT&T resolver fails (query and retry) in a check at t.
func (w *demoWorld) ispDNSDownAt(t time.Time) bool {
	return !w.ispDNSFrom.IsZero() && !t.Before(w.ispDNSFrom) && t.Before(w.ispDNSTo)
}

// lostQuery is a DNS query that got no answer (as the probe records it).
func lostQuery(r model.DNSResult) model.DNSResult {
	return model.DNSResult{Server: r.Server, ServerRole: r.ServerRole, Name: r.Name, QType: r.QType,
		Err: "read udp 192.168.1.71:53124->" + r.Server + ": i/o timeout"}
}

// withRetries records the retry of every resolution query that got no valid answer, as the
// monitor does from rules 2026.10-4 (failed: the retry fails the same way; the hijack test is
// never retried). retryAnswers maps a server role to the answer its retry got instead.
func withRetries(rs []model.DNSResult, retryAnswers map[string]model.DNSResult) []model.DNSResult {
	var out []model.DNSResult
	for _, r := range rs {
		out = append(out, r)
		if r.Err == "" && r.OK && !strings.EqualFold(r.RCode, "SERVFAIL") || strings.HasSuffix(r.Name, ".invalid") {
			continue
		}
		retry := r
		if a, ok := retryAnswers[r.ServerRole]; ok {
			retry = a
		}
		out = append(out, retry)
	}
	return out
}

func (w *demoWorld) serviceCheckAt(t time.Time, failing bool) model.ServiceCheck {
	raw := base64.StdEncoding.EncodeToString([]byte("\x12\x34\x81\x80\x00\x01\x00\x01demo-dns-response"))
	vpn := w.routeBypassAt(t) // the public resolver and the web checks go into the stalled tunnel
	dns := func(server, role string, rtt int64) model.DNSResult {
		r := model.DNSResult{Server: server + ":53", ServerRole: role, Name: "www.google.com", QType: "A", OK: true, RCode: "NOERROR",
			Answers: []string{"142.250.72.100"}, RTTus: rtt, RawB64: raw}
		switch {
		case failing && role == "gateway":
			r.Answers, r.RCode = nil, "SERVFAIL"
		case failing, vpn && role == "public", role == "isp" && w.ispDNSDownAt(t):
			r = lostQuery(r)
		}
		return r
	}
	// As the monitor (docs/DESIGN.md §8), every check also asks the gateway's resolver for a
	// random name under .invalid, which cannot exist: NXDOMAIN is the healthy answer, and any
	// answer is a hijack (wording of probe.DetectDNSHijack).
	name := demoHijackTestName(t)
	hijackTest := model.DNSResult{Server: demoGateway + ":53", ServerRole: "gateway", Name: name, QType: "A", OK: true, RCode: "NXDOMAIN",
		RTTus: 2400, RawB64: raw}
	switch {
	case w.dnsHijack:
		hijackTest.RCode, hijackTest.Answers, hijackTest.Hijacked = "NOERROR", []string{demoGateway}, true
		hijackTest.HijackWhy = "reserved name " + name + " must not resolve (RFC 6761) but got: " + demoGateway
	case failing:
		hijackTest.RCode = "SERVFAIL"
	}
	http1 := model.HTTPResult{Name: "msft_connecttest", URL: "http://www.msftconnecttest.com/connecttest.txt", OK: true, Status: 200,
		RemoteAddr: "23.215.0.136:80", BodySHA256: "6b7e2e2a6a8b8d5a4d11a2a24e2b9f8b5c2a7d6f1e0c9b8a7f6e5d4c3b2a1908", BodyPrefix: "Microsoft Connect Test", RTTus: 24100}
	http2 := model.HTTPResult{Name: "google_204", URL: "https://www.google.com/generate_204", OK: true, Status: 204, RemoteAddr: "142.250.72.100:443", RTTus: 41200,
		TLSCertSHA256: demoGoogleCertSHA}
	if failing || vpn {
		http1 = model.HTTPResult{Name: http1.Name, URL: http1.URL, Err: "dial tcp: lookup www.msftconnecttest.com: i/o timeout"}
		http2 = model.HTTPResult{Name: http2.Name, URL: http2.URL, Err: "dial tcp: lookup www.google.com: i/o timeout"}
	}
	isp := dns(demoISPDNS, "isp", 11800)
	retried := map[string]model.DNSResult{}
	if !failing && !w.ispDNSDownAt(t) && !w.ispRetryAt.IsZero() && t.Truncate(time.Minute).Equal(w.ispRetryAt) {
		// One lost datagram: the retry answers, so the resolver did not fail (rules 2026.10-4).
		retried["isp"], isp = isp, lostQuery(isp)
	}
	return model.ServiceCheck{
		DNS:  withRetries([]model.DNSResult{dns(demoGateway, "gateway", 2100), isp, dns("1.1.1.1", "public", 10900), hijackTest}, retried),
		HTTP: []model.HTTPResult{http1, http2},
	}
}

// ispRetry makes the AT&T resolver's query of sc get no answer, and records its retry: answered
// (one lost datagram) or getting no answer again.
func ispRetry(sc model.ServiceCheck, answered bool) model.ServiceCheck {
	var dns []model.DNSResult
	done := false
	for _, r := range sc.DNS {
		switch {
		case r.ServerRole != "isp":
			dns = append(dns, r)
		case !done:
			done = true
			ok := r
			ok.Err, ok.OK, ok.RCode, ok.Answers, ok.RTTus = "", true, "NOERROR", []string{"142.250.72.100"}, 11800
			retry := lostQuery(r)
			if answered {
				retry = ok
			}
			dns = append(dns, lostQuery(r), retry)
		}
	}
	sc.DNS = dns
	return sc
}

func (w *demoWorld) localLink(connected bool) model.LocalLink {
	l := model.LocalLink{Interface: "Wi-Fi", Type: "wifi", State: "connected", LocalIP: "192.168.1.71", GatewayIP: demoGateway,
		SSID: "HOME-5G", BSSID: "02:00:5e:10:00:01", SignalPct: 86, RSSIdBm: -52, Channel: 149, Band: "5 GHz", RadioType: "802.11ax",
		RxMbps: 1201, TxMbps: 1201, RawSHA256: w.netsh, Egress: demoEgress(false)}
	if !connected {
		// No route to the gateway: the route check cannot be made (it concludes nothing).
		l = model.LocalLink{Interface: "Wi-Fi", Type: "wifi", State: "disconnected", RawSHA256: w.netsh,
			Egress: &model.EgressCheck{Gateway: demoGateway, Err: "route to the gateway: GetBestRoute2: The network location cannot be reached."}}
	}
	return l
}

// localLinkAt is the local-link reading at t: with its route check showing the VPN while a
// LOCAL_ROUTE event covers t.
func (w *demoWorld) localLinkAt(t time.Time, connected bool) model.LocalLink {
	l := w.localLink(connected)
	if connected && w.routeBypassAt(t) {
		l.Egress = demoEgress(true)
	}
	return l
}

// demoEgressTargets are the destinations whose route the monitor checks: the internet probe
// targets, the AT&T next hop and resolver, the public resolver (monitor egressDests).
var demoEgressTargets = []string{"1.1.1.1", "8.8.8.8", "9.9.9.9", demoNextHop, demoISPDNS}

// demoEgress is the route check recorded with a local-link reading (rules 2026.10-4): every
// destination through the gateway on Wi-Fi, or (vpn) the internet targets in a VPN tunnel
// that leaves the AT&T next hop and resolver on the gateway (split tunnel).
func demoEgress(vpn bool) *model.EgressCheck {
	e := &model.EgressCheck{Gateway: demoGateway, GatewayIf: 12, GatewayIfName: "Wi-Fi"}
	for _, t := range demoEgressTargets {
		r := model.EgressRoute{Target: t, If: 12, IfName: "Wi-Fi", NextHop: demoGateway, ViaGateway: true}
		if vpn && t != demoNextHop && t != demoISPDNS {
			r = model.EgressRoute{Target: t, If: 23, IfName: demoVPNIf, NextHop: demoVPNHop}
			e.Bypass = true
		}
		e.Routes = append(e.Routes, r)
	}
	return e
}

func traceroute(target, trigger, incident string, reached bool) model.Traceroute {
	hops := []model.Hop{{TTL: 1, Addr: demoGateway, RTTus: 1800, Status: "IP_TTL_EXPIRED_TRANSIT"}}
	if reached {
		hops = append(hops,
			model.Hop{TTL: 2, Addr: demoNextHop, RTTus: 4100, Status: "IP_TTL_EXPIRED_TRANSIT"},
			model.Hop{TTL: 3, Addr: "192.0.2.17", RTTus: 6900, Status: "IP_TTL_EXPIRED_TRANSIT"},
			model.Hop{TTL: 4, Addr: "192.0.2.89", RTTus: 9800, Status: "IP_TTL_EXPIRED_TRANSIT"},
			model.Hop{TTL: 5, Addr: target, RTTus: 11200, Status: "IP_SUCCESS"})
	} else {
		for ttl := 2; ttl <= 15; ttl++ {
			hops = append(hops, model.Hop{TTL: ttl, Status: "IP_REQ_TIMED_OUT"})
		}
	}
	return model.Traceroute{Target: target, Trigger: trigger, Incident: incident, Hops: hops, Reached: reached, DurMs: int64(len(hops)) * 900}
}

// failedTraceroute is a traceroute that could not send anything (this PC had no network).
func failedTraceroute(target, trigger, incident string) model.Traceroute {
	return model.Traceroute{Target: target, Trigger: trigger, Incident: incident, Hops: []model.Hop{},
		Err: "IcmpSendEcho2: the network location cannot be reached (this PC has no network connection)", DurMs: 3}
}

// ----------------------------------------------------------------------------- history

type demoPending struct {
	ts    time.Time
	order int
	emit  func(ts time.Time)
}

func (w *demoWorld) buildLedger() {
	w.mu.Lock()
	defer w.mu.Unlock()
	pub := w.key.Public().(ed25519.PublicKey)
	g := w.genesis
	host := model.HostInfo{Hostname: "DESKTOP-DEMO", OS: "Windows 11 Pro for Workstations", OSVersion: "10.0.26200",
		Interfaces: []string{"Wi-Fi 192.168.1.71/24 02:00:00:00:00:71"}, TimeZone: "Pacific Standard Time"}
	soft := model.SoftwareInfo{Name: "att-monitor", Version: "demo", GoVersion: runtime.Version(),
		ExePath: `C:\Program Files\ATT Monitor\att-monitor.exe`, ExeSHA256: strings.Repeat("5e", 32), Rules: demoRules}
	w.appendLocked(g, model.TypeGenesis, model.Genesis{
		PublicKey: base64.StdEncoding.EncodeToString(pub), Fingerprint: w.fingerprint(), Created: g.UTC().Format(time.RFC3339Nano),
		Host: host, Software: soft, Statement: "Evidence ledger of att-monitor on DESKTOP-DEMO (demo data).",
	})
	files := []model.BootstrapFile{
		{Path: "events.before.html", SHA256: w.page["events.before"], Size: int64(len(w.blobs[w.page["events.before"]])), ModTime: g.Add(-20 * time.Minute).UTC().Format(time.RFC3339)},
		{Path: "events.after.html", SHA256: w.page["events.after"], Size: int64(len(w.blobs[w.page["events.after"]])), ModTime: g.Add(-19 * time.Minute).UTC().Format(time.RFC3339)},
		{Path: "initial-snapshot/fiberstat.html", SHA256: w.page["fiberstat"], Size: int64(len(w.blobs[w.page["fiberstat"]])), ModTime: g.Add(-25 * time.Minute).UTC().Format(time.RFC3339)},
	}
	w.appendLocked(g.Add(time.Second), model.TypeBootstrapImport, model.BootstrapImport{SourceDir: `C:\RC\att_monitor\evidence\bootstrap`, Files: files,
		Notes: "Setup captures (faithful transcriptions). Broadband Status Notification changed from ON to OFF at the owner's request."},
		w.page["events.before"], w.page["events.after"], w.page["fiberstat"])
	w.anchorLocked(g.Add(3*time.Second), "genesis")
	w.appendLocked(g.Add(10*time.Second), model.TypeMonitorStart, model.MonitorStart{Software: soft, Host: host, ConfigSHA256: demoConfigSHA,
		Config: demoConfigJSON(), Mode: "service", PrevHead: w.headLocked()})
	cc := model.ConfigChange{Target: "gateway", What: "events.bbevent (Broadband Status Notification)", Before: "on", After: "off", Actor: "setup (bootstrap evidence)", Result: "verified"}
	ccRef := w.appendLocked(g.Add(20*time.Second), model.TypeConfigChange, cc, w.page["events.before"], w.page["events.after"])
	w.notif = model.NotificationState{Enabled: false, CheckedAt: g.Add(20 * time.Second).UTC().Format(time.RFC3339Nano), Seq: ccRef.Seq}

	var pend []demoPending
	add := func(ts time.Time, order int, fn func(ts time.Time)) {
		pend = append(pend, demoPending{ts: ts, order: order, emit: fn})
	}
	inGap := func(t time.Time) bool {
		for _, e := range w.events {
			if e.gap && e.covers(t) {
				return true
			}
		}
		return false
	}
	end := w.created.Add(-5 * time.Second)

	// Background: heartbeats, snapshots, service checks, anchors, clock & link checks.
	for t := g.Add(15 * time.Minute).Truncate(15 * time.Minute); t.Before(end); t = t.Add(15 * time.Minute) {
		if inGap(t) {
			continue
		}
		add(t, 1, func(ts time.Time) {
			w.appendLocked(ts, model.TypeHeartbeat, model.Heartbeat{UptimeSec: int64(ts.Sub(g).Seconds()), Cycles: uint64(ts.Sub(g) / (10 * time.Second)), State: model.StateOnline, RecordsRun: uint64(len(w.envs))})
		})
		if t.Minute() == 0 {
			add(t.Add(20*time.Second), 2, func(ts time.Time) {
				snap := w.observedSnapshotLocked(ts, "periodic", ts.Hour()%6 == 0)
				w.appendLocked(ts, model.TypeGatewaySnapshot, snap, pageBlobs(snap)...)
			})
			add(t.Add(25*time.Second), 3, func(ts time.Time) {
				w.appendLocked(ts, model.TypeServiceCheck, w.serviceCheckAt(ts, false))
			})
			if t.Hour()%6 == 0 {
				add(t.Add(30*time.Second), 4, func(ts time.Time) {
					w.appendLocked(ts, model.TypeClockCheck, model.ClockCheck{Results: []model.ClockResult{
						{Server: "time.windows.com", Addr: "168.61.215.74:123", OK: true, OffsetMs: 12, RTTms: 31, Stratum: 3},
						{Server: "time.google.com", Addr: "216.239.35.0:123", OK: true, OffsetMs: -4, RTTms: 14, Stratum: 1},
						{Server: "pool.ntp.org", Addr: "192.0.2.123:123", OK: true, OffsetMs: 9, RTTms: 22, Stratum: 2},
					}, GatewayOffsetMs: i64(1200)})
				})
				add(t.Add(35*time.Second), 5, func(ts time.Time) {
					w.appendLocked(ts, model.TypeLocalLink, w.localLinkAt(ts, true), w.netsh)
				})
			}
		}
		if t.Minute()%30 == 0 {
			add(t.Add(50*time.Second), 6, func(ts time.Time) { w.anchorLocked(ts, "periodic") })
		}
	}
	// A service restart two days ago (Windows update) and the suspend/resume gap.
	restart := w.created.Add(-2*24*time.Hour - 3*time.Hour - 7*time.Minute)
	add(restart, 0, func(ts time.Time) {
		w.appendLocked(ts, model.TypeMonitorStop, model.MonitorStop{Reason: "system shutdown", UptimeSec: int64(ts.Sub(g).Seconds())})
	})
	add(restart.Add(95*time.Second), 0, func(ts time.Time) {
		w.appendLocked(ts, model.TypeMonitorStart, model.MonitorStart{Software: soft, Host: host, ConfigSHA256: demoConfigSHA, Mode: "service", PrevHead: w.headLocked(), GapSeconds: 95, PrevStopped: true})
	})
	// The gateway's syslog (docs/syslog-snmp-traffic.md §3.2) as the monitor records it: a batch
	// of everyday messages every 2 hours on the older days, every 4 minutes over the last day and
	// every 3 minutes over the last half hour; the incidents add their own (addEventRecords).
	// Nothing reaches this computer while it sleeps or its link is down, or while the gateway
	// restarts. The receiver counts from the service's last start.
	w.syslogSince = restart.Add(95 * time.Second)
	for t := g.Add(30 * time.Minute).Truncate(time.Minute); t.Before(end); {
		if !w.syslogQuietAt(t) {
			add(t.Add(42*time.Second), 8, func(ts time.Time) {
				rejected := 0
				if noise(ts, 89) > 0.93 {
					rejected = 1 // a datagram from another device on the home network
				}
				msgs := routineSyslog(ts)
				if w.wanDownAt(ts) { // nothing arrives from the Internet, nothing reaches the ACS or the time server
					msgs = slices.DeleteFunc(msgs, func(m model.SyslogMessage) bool { return m.App == "kernel" || m.App == "cwmpd" || m.App == "ntpd" })
				}
				w.appendSyslogLocked(ts, rejected, msgs...)
			})
		}
		switch age := w.created.Sub(t); {
		case age > 26*time.Hour:
			t = t.Add(2 * time.Hour)
		case age > 35*time.Minute:
			t = t.Add(4 * time.Minute)
		default:
			t = t.Add(3 * time.Minute)
		}
	}
	add(w.created.Add(-47*time.Minute), 8, func(ts time.Time) { w.appendSyslogLocked(ts, 0, oddSyslog(ts)...) })
	// The daily check of the gateway's Syslog page (read-only in this version), from each start.
	for t := g.Add(3 * time.Minute); t.Before(restart); t = t.Add(24 * time.Hour) {
		if !inGap(t) {
			add(t, 8, func(ts time.Time) { w.syslogCheckLocked(ts) })
		}
	}
	for t := w.syslogSince.Add(3 * time.Minute); t.Before(end); t = t.Add(24 * time.Hour) {
		if !inGap(t) {
			add(t, 8, func(ts time.Time) { w.syslogCheckLocked(ts) })
		}
	}
	for _, e := range w.events {
		e := e
		if e.gap {
			add(e.from, 0, func(ts time.Time) { w.appendLocked(ts, model.TypePowerEvent, model.PowerEvent{Kind: "suspend"}) })
			add(e.to, 0, func(ts time.Time) {
				w.appendLocked(ts, model.TypePowerEvent, model.PowerEvent{Kind: "resume_automatic"})
			})
			continue
		}
		w.addEventRecords(e, add)
	}
	// Notes and an earlier export.
	add(w.created.Add(-4*24*time.Hour+20*time.Minute), 0, func(ts time.Time) {
		w.appendLocked(ts, model.TypeOperatorNote, model.OperatorNote{Text: "Internet was down while working from home; the AT&T app showed no outage in my area.", Author: "Alex", Source: "web"})
	})
	add(w.created.Add(-75*time.Minute), 0, func(ts time.Time) {
		w.buildExportLocked(ts, contracts.ExportRequest{IncidentID: w.eventByName("fiber").incidentID, PreparedBy: "Alex", Notes: "For AT&T repair ticket 0123456789", Requester: "web 127.0.0.1"})
	})
	// The last 30 minutes as individual 10-second samples, with the real gateway / service-check
	// cadence (60 s) and local-link records (10 min) so that their verdicts have fresh inputs.
	for t := w.created.Add(-35 * time.Minute).Truncate(time.Minute); t.Before(end); t = t.Add(time.Minute) {
		if t.Minute() != 0 {
			add(t.Add(20*time.Second), 2, func(ts time.Time) {
				snap := w.observedSnapshotLocked(ts, "periodic", ts.Minute()%5 == 0)
				w.appendLocked(ts, model.TypeGatewaySnapshot, snap, pageBlobs(snap)...)
			})
			add(t.Add(25*time.Second), 3, func(ts time.Time) {
				w.appendLocked(ts, model.TypeServiceCheck, w.serviceCheckAt(ts, false))
			})
		}
		if t.Minute()%10 == 0 && !(t.Minute() == 0 && t.Hour()%6 == 0) {
			add(t.Add(35*time.Second), 5, func(ts time.Time) {
				w.appendLocked(ts, model.TypeLocalLink, w.localLinkAt(ts, true), w.netsh)
			})
		}
	}
	for t := w.created.Add(-30 * time.Minute).Truncate(10 * time.Second); t.Before(end); t = t.Add(10 * time.Second) {
		add(t, 9, func(ts time.Time) { w.appendSampleLocked(ts) })
	}

	sort.SliceStable(pend, func(i, j int) bool {
		if !pend[i].ts.Equal(pend[j].ts) {
			return pend[i].ts.Before(pend[j].ts)
		}
		return pend[i].order < pend[j].order
	})
	for _, p := range pend {
		p.emit(p.ts)
	}
}

func (w *demoWorld) eventByName(name string) *demoEvent {
	for _, e := range w.events {
		if e.name == name {
			return e
		}
	}
	return nil
}

// observedSnapshotLocked is the gateway snapshot the monitor would take at ts: unreachable while
// this PC cannot reach the gateway, "down" pages during a fiber or WAN outage.
func (w *demoWorld) observedSnapshotLocked(ts time.Time, trigger string, stored bool) model.GatewaySnapshot {
	for _, e := range w.allEventsLocked() {
		if e.gap || !e.covers(ts) {
			continue
		}
		switch state, cause, _ := e.stateAt(ts); {
		case cause == model.CauseLocalRoute: // the gateway answers; only the routes past it fail
			return w.snapshotLocked(ts, false, trigger, stored)
		case cause == model.CauseLocalLinkDown:
			return w.unreachableSnapshotLocked(ts, trigger, "dial tcp "+demoGateway+":443: connectex: A socket operation was attempted to an unreachable network.")
		case state == model.StateLocalFault:
			return w.unreachableSnapshotLocked(ts, trigger, "dial tcp "+demoGateway+":443: i/o timeout")
		case cause == model.CauseFiberLinkDown || cause == model.CauseWANDown:
			return w.snapshotLocked(ts, true, trigger, stored)
		}
	}
	return w.snapshotLocked(ts, false, trigger, stored)
}

// pageBlobs lists the stored page bodies of a snapshot (the record's blobs).
func pageBlobs(snap model.GatewaySnapshot) []string {
	var out []string
	for _, p := range snap.Pages {
		if p.Stored && p.SHA256 != "" {
			out = append(out, p.SHA256)
		}
	}
	return out
}

func (w *demoWorld) appendSampleLocked(ts time.Time) model.Ref {
	if w.sampled[ts.UnixNano()] { // an event's own sample of this cycle is recorded already
		return w.lastOf[model.TypeSample]
	}
	w.sampled[ts.UnixNano()] = true
	w.cycle++
	probes, verdict := w.probesAt(ts)
	verdict.Inputs = &model.VerdictInputs{SnapshotSeq: w.freshInput(model.TypeGatewaySnapshot, ts),
		ServiceCheckSeq: w.freshInput(model.TypeServiceCheck, ts), LocalLinkSeq: w.freshInput(model.TypeLocalLink, ts), WindowCycles: 6}
	w.rules4Locked(&verdict, probes)
	s := model.Sample{Cycle: w.cycle, Started: ts.UTC().Format(time.RFC3339Nano), DurMs: 2004, Probes: probes, Verdict: verdict}
	if w.live != nil && w.live.covers(ts) && w.liveInc != nil {
		s.IncidentID = w.liveInc.ID
	}
	return w.appendLocked(ts, model.TypeSample, s)
}

// rules4Locked adds to a sample's verdict what the rules 2026.10-4 classifier states and names
// (v.Inputs already holds the fresh snapshot, service check and local link):
//   - the DNS rule: while the latest service check shows the AT&T resolver failing (query and
//     retry) and the public resolver answering, the check before it is compared, and named;
//     the failure counts (ISP_DNS_FAILURE) only when that check showed it too;
//   - the traffic gate: a provider-attributed DEGRADED verdict names the two gateway snapshots
//     whose WAN counters gave the household's own traffic, and states the rates.
func (w *demoWorld) rules4Locked(v *model.Verdict, probes []model.ProbeResult) {
	in := v.Inputs
	at := func(r model.Ref) time.Time {
		t, _ := time.Parse(time.RFC3339Nano, r.TS)
		return t
	}
	reasons := slices.Clone(v.Reasons) // never write into an event's reasons
	if cur, prev := w.lastOf[model.TypeServiceCheck], w.prevOf[model.TypeServiceCheck]; in.ServiceCheckSeq != 0 && w.ispDNSDownAt(at(cur)) {
		in.PrevServiceCheckSeq = prev.Seq
		lost := lostQuery(model.DNSResult{Server: demoISPDNS + ":53"}).Err
		finding := fmt.Sprintf("ISP resolver %s failed (%s; retried: %s) while public resolver 1.1.1.1 answered", demoISPDNS, lost, lost)
		switch {
		case v.Cause == model.CauseISPDNSFailure && w.ispDNSDownAt(at(prev)):
			reasons = []string{fmt.Sprintf("%s, as in the previous service check #%d (%s)", finding, prev.Seq, finding),
				fmt.Sprintf("gateway %s answered ICMP in %.1f ms", demoGateway, float64(probes[0].RTTus)/1000),
				"gateway probes had no loss over the last 6 cycles (12/12 answered)"}
		case v.State == model.StateOnline:
			reasons = append(reasons, fmt.Sprintf("%s in this service check, but not in the previous one (#%d): one failing check is not counted as a resolver failure", finding, prev.Seq))
		}
	}
	if v.State == model.StateDegraded && v.Attribution == model.AttrProvider && in.SnapshotSeq != 0 {
		from, to := w.prevOf[model.TypeGatewaySnapshot], w.lastOf[model.TypeGatewaySnapshot]
		if d := at(to).Sub(at(from)); from.Seq != 0 && d > 0 && d <= 5*time.Minute {
			in.TrafficFromSeq, in.TrafficToSeq = from.Seq, to.Seq
			// The demo gateway's counters grow by 4.1 MB/s received and 0.62 MB/s sent.
			reasons = append(reasons, fmt.Sprintf("the gateway's own WAN counters (snapshots #%d and #%d, %s apart) show this home network receiving 32.8 Mb/s and sending 5.0 Mb/s, below 80 Mb/s in each direction, so the household's own traffic does not explain it and the degradation is on the provider side",
				from.Seq, to.Seq, d.Round(time.Second)))
		}
	}
	v.Reasons = reasons
}

// addEventRecords schedules the records the monitor writes for one bad period (blip or
// incident) and builds the incident view from the seqs they get.
func (w *demoWorld) addEventRecords(e *demoEvent, add func(time.Time, int, func(time.Time))) {
	inc := &model.Incident{ID: e.incidentID, Opened: e.from.UTC().Format(time.RFC3339Nano), State: e.state, Cause: e.cause,
		Attribution: e.attribution, Causes: []string{e.cause}, Summary: e.summary, Reasons: e.reasons, Rules: demoRules}
	if !e.boot.IsZero() {
		inc.Causes = []string{model.CauseGatewayReboot, model.CauseGatewayUnreachable, model.CauseWANDown}
	}
	ev := func(seq uint64, typ, blob, note string) {
		inc.Evidence = append(inc.Evidence, model.EvidenceRef{Seq: seq, Type: typ, Blob: blob, Note: note})
	}
	firstState, firstCause, _ := e.stateAt(e.from)
	add(e.from, 7, func(ts time.Time) {
		ref := w.appendSampleLocked(ts)
		inc.FirstSeq = ref.Seq
		w.appendLocked(ts.Add(500*time.Millisecond), model.TypeStateChange, model.StateChange{FromState: model.StateOnline, ToState: firstState, ToCause: firstCause, At: ts.UTC().Format(time.RFC3339Nano), Cycle: w.cycle, Reasons: e.reasons})
	})
	if !e.incident {
		add(e.to, 7, func(ts time.Time) {
			w.appendSampleLocked(ts)
			w.appendLocked(ts.Add(500*time.Millisecond), model.TypeStateChange, model.StateChange{FromState: e.state, FromCause: e.cause, ToState: model.StateOnline, At: ts.UTC().Format(time.RFC3339Nano), Cycle: w.cycle})
		})
		return
	}
	// The gateway's own messages about the event, as this computer received them.
	for _, b := range eventSyslog(e) {
		add(b.at, 8, func(ts time.Time) { w.appendSyslogLocked(ts, 0, eventMessages(b.kind, ts)...) })
	}
	fiber := e.cause == model.CauseFiberLinkDown || e.cause == model.CauseWANDown
	outage := e.state == model.StateISPOutage
	local := e.state == model.StateLocalFault // this PC could not reach the gateway, or its traffic bypassed it
	add(e.from.Add(10*time.Second), 7, func(ts time.Time) { w.appendSampleLocked(ts) })
	add(e.from.Add(20*time.Second), 7, func(ts time.Time) { w.appendSampleLocked(ts) })
	// The records written when the incident opens, each at its own time (so that they interleave
	// with the background cadence when the event lies in the last half hour).
	opened := e.from.Add(30 * time.Second)
	var snapRef model.Ref
	add(opened, 7, func(ts time.Time) {
		open := *inc
		open.Open = true
		ref := w.appendLocked(ts, model.TypeIncidentOpen, open)
		ev(ref.Seq, model.TypeIncidentOpen, "", "incident opened: 3 bad cycles within the last 6")
	})
	add(opened.Add(time.Second), 7, func(ts time.Time) {
		snap := w.observedSnapshotLocked(ts, "incident", true)
		snapRef = w.appendLocked(ts, model.TypeGatewaySnapshot, snap, pageBlobs(snap)...)
		note := "gateway status pages captured"
		switch {
		case fiber:
			note = "gateway reports Broadband Connection: Down"
		case !snap.Derived.Reachable:
			note = "gateway status pages could not be reached"
		}
		ev(snapRef.Seq, model.TypeGatewaySnapshot, firstBlob(snap), note)
	})
	if fiber {
		add(opened.Add(2*time.Second), 7, func(ts time.Time) {
			r := w.appendLocked(ts, model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvBroadbandState, Before: "Up", After: "Down", Evidence: []uint64{snapRef.Seq}})
			ev(r.Seq, model.TypeGatewayEvent, "", "broadband_state Up → Down")
			if e.cause == model.CauseFiberLinkDown {
				r = w.appendLocked(ts, model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvPONState, Before: "OPERATION (O5)", After: "INITIAL (O1)", Evidence: []uint64{snapRef.Seq}})
				ev(r.Seq, model.TypeGatewayEvent, "", "pon_state O5 → O1")
				r = w.appendLocked(ts, model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvOpticalLinkChange, Before: "1791151188", After: strconv.FormatInt(e.from.Unix()-2, 10), Detail: "fiberstat Last Change moved", Evidence: []uint64{snapRef.Seq}})
				ev(r.Seq, model.TypeGatewayEvent, "", "optical link state changed")
			}
		})
	}
	add(opened.Add(3*time.Second), 7, func(ts time.Time) {
		// A VPN fails only what goes into its tunnel (serviceCheckAt knows when one is up).
		sc := w.serviceCheckAt(ts, outage || (local && e.cause != model.CauseLocalRoute))
		if e.name == "loss" {
			sc.DNS[1].Truncated = true // the AT&T resolver's answer came back truncated (TC bit)
		}
		r := w.appendLocked(ts, model.TypeServiceCheck, sc)
		ev(r.Seq, model.TypeServiceCheck, "", "DNS and web checks")
	})
	add(opened.Add(4*time.Second), 7, func(ts time.Time) {
		r := w.appendLocked(ts, model.TypeLocalLink, w.localLinkAt(ts, e.cause != model.CauseLocalLinkDown), w.netsh)
		ev(r.Seq, model.TypeLocalLink, w.netsh, "this PC's adapter")
	})
	for i, target := range []string{"8.8.8.8", "1.1.1.1"} {
		add(opened.Add(time.Duration(10+15*i)*time.Second), 7, func(ts time.Time) {
			tr := traceroute(target, "incident_open", e.incidentID, !outage && !local)
			if e.cause == model.CauseLocalLinkDown {
				tr = failedTraceroute(target, "incident_open", e.incidentID)
			}
			r := w.appendLocked(ts, model.TypeTraceroute, tr)
			ev(r.Seq, model.TypeTraceroute, "", "traceroute "+target)
		})
	}
	if !e.boot.IsZero() {
		// The gateway answers again: its own uptime shows that it restarted.
		add(e.boot.Add(40*time.Second), 7, func(ts time.Time) {
			snap := w.observedSnapshotLocked(ts, "cycle_failure", true)
			ref := w.appendLocked(ts, model.TypeGatewaySnapshot, snap, pageBlobs(snap)...)
			ev(ref.Seq, model.TypeGatewaySnapshot, firstBlob(snap), "gateway reachable again, uptime 40 s")
			prevBoot := w.bootAt(e.boot.Add(-time.Second))
			r := w.appendLocked(ts.Add(time.Second), model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvReboot,
				Before: prevBoot.UTC().Format(time.RFC3339), After: e.boot.UTC().Format(time.RFC3339),
				Detail:   "gateway uptime fell to 40 s: boot time (estimated from its uptime) moved; firmware 6.34.7 before and after",
				Evidence: []uint64{ref.Seq}})
			ev(r.Seq, model.TypeGatewayEvent, "", "gateway restart detected from its uptime")
		})
	}
	if e.to.Sub(e.from) > 12*time.Minute {
		add(e.from.Add(10*time.Minute), 7, func(ts time.Time) {
			upd := *inc
			upd.Open = true
			r := w.appendLocked(ts, model.TypeIncidentUpdate, upd)
			ev(r.Seq, model.TypeIncidentUpdate, "", "")
		})
		add(e.from.Add(10*time.Minute+5*time.Second), 7, func(ts time.Time) {
			r := w.appendLocked(ts, model.TypeTraceroute, traceroute("8.8.8.8", "incident_periodic", e.incidentID, !outage))
			ev(r.Seq, model.TypeTraceroute, "", "periodic traceroute")
		})
	}
	// The records written when the incident closes, each at its own time: the three good cycles
	// that close it, the close record, a snapshot, a traceroute and the anchor right after it.
	add(e.to, 7, func(ts time.Time) {
		w.appendLocked(ts, model.TypeStateChange, model.StateChange{FromState: e.state, FromCause: e.cause, ToState: model.StateOnline, At: ts.UTC().Format(time.RFC3339Nano), Cycle: w.cycle,
			Reasons: []string{"5/5 internet probes succeeded"}})
		w.appendSampleLocked(ts)
	})
	add(e.to.Add(10*time.Second), 7, func(ts time.Time) { w.appendSampleLocked(ts) })
	add(e.to.Add(20*time.Second), 7, func(ts time.Time) { w.appendSampleLocked(ts) })
	var closeSnap model.Ref
	add(e.to.Add(30*time.Second), 7, func(ts time.Time) {
		closed := *inc
		closed.Closed = e.to.UTC().Format(time.RFC3339Nano)
		closed.DurationSec = int64(e.to.Sub(e.from).Seconds())
		closed.Stats = w.incidentStats(e)
		if outage || !e.boot.IsZero() { // incidents with an outage cycle (docs/DESIGN.md §10)
			closed.RecoveredAt = e.to.UTC().Format(time.RFC3339Nano)
		}
		if !e.boot.IsZero() {
			closed.GatewayRestarts = []string{e.boot.UTC().Format(time.RFC3339)}
		}
		r := w.appendLocked(ts, model.TypeIncidentClose, closed)
		ev(r.Seq, model.TypeIncidentClose, "", "incident closed after 3 good cycles")
		inc.LastSeq = r.Seq
		inc.Closed, inc.DurationSec, inc.Stats = closed.Closed, closed.DurationSec, closed.Stats
		inc.RecoveredAt, inc.GatewayRestarts = closed.RecoveredAt, closed.GatewayRestarts
	})
	add(e.to.Add(31*time.Second), 7, func(ts time.Time) {
		snap := w.snapshotLocked(ts, false, "incident", true)
		closeSnap = w.appendLocked(ts, model.TypeGatewaySnapshot, snap, pageBlobs(snap)...)
		ev(closeSnap.Seq, model.TypeGatewaySnapshot, firstBlob(snap), "gateway status after recovery")
	})
	if fiber {
		add(e.to.Add(32*time.Second), 7, func(ts time.Time) {
			r := w.appendLocked(ts, model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvBroadbandState, Before: "Down", After: "Up", Evidence: []uint64{closeSnap.Seq}})
			ev(r.Seq, model.TypeGatewayEvent, "", "broadband_state Down → Up")
		})
	}
	add(e.to.Add(35*time.Second), 7, func(ts time.Time) {
		r := w.appendLocked(ts, model.TypeTraceroute, traceroute("8.8.8.8", "incident_close", e.incidentID, true))
		ev(r.Seq, model.TypeTraceroute, "", "traceroute after recovery")
	})
	add(e.to.Add(40*time.Second), 7, func(ts time.Time) {
		w.anchorLocked(ts, "incident_close")
		n := len(w.envs)
		ev(uint64(n-2), model.TypeAnchor, w.tsr[0], "RFC 3161 time-stamp (DigiCert)")
		ev(uint64(n-1), model.TypeAnchor, w.tsr[1], "RFC 3161 time-stamp (FreeTSA)")
		w.incidents = append(w.incidents, inc)
	})
	if e.name == "fiber" {
		add(e.to.Add(25*time.Minute), 7, func(ts time.Time) {
			r := w.appendLocked(ts, model.TypeOperatorNote, model.OperatorNote{
				Text: "Called AT&T repair (ticket 0123456789). The agent saw a fiber issue on their side; technician scheduled for Tuesday.", Author: "Alex", Source: "web"})
			ev(r.Seq, model.TypeOperatorNote, "", "operator note")
		})
	}
}

func (w *demoWorld) incidentStats(e *demoEvent) model.IncidentStats {
	cycles := int(e.to.Sub(e.from) / (10 * time.Second))
	st := model.IncidentStats{Cycles: cycles, BadCycles: cycles, ProbeOK: map[string]int{}, ProbeTotal: map[string]int{},
		GatewayFetches: cycles * 10 / 15}
	for _, spec := range config.Default().Probes.Targets {
		loss, _ := probeOutcome(e, spec.Name, 1, e.from)
		st.ProbeTotal[spec.Name] = cycles
		st.ProbeOK[spec.Name] = int(math.Round(float64(cycles) * (1 - loss)))
	}
	switch e.cause {
	case model.CauseFiberLinkDown:
		st.GatewayDownSeen, st.PONDownSeen, st.OpticalAlarm = true, true, true
	case model.CauseWANDown, model.CauseGatewayReboot:
		st.GatewayDownSeen, st.OpticalAlarm = true, true
	case model.CauseLocalLinkDown:
		st.LocalLinkDown = true
	default:
		st.OpticalAlarm = true
	}
	// Time accounting (docs/DESIGN.md §10): every cycle of these events is bad; a restart's
	// cycles all lie inside its restart window and are not downtime.
	sec := int64(e.to.Sub(e.from) / time.Second)
	switch {
	case !e.boot.IsZero():
		st.RestartSec = sec
	case e.state == model.StateISPOutage:
		st.DowntimeSec = sec
	case e.state == model.StateDegraded:
		st.DegradedSec = sec
	}
	return st
}

// firstBlob returns the first stored page of a snapshot ("" if none).
func firstBlob(snap model.GatewaySnapshot) string {
	if b := pageBlobs(snap); len(b) > 0 {
		return b[0]
	}
	return ""
}

// ----------------------------------------------------------------------------- syslog

// demoSyslogHost is the name the gateway writes into its messages.
const demoSyslogHost = "BGW320-505"

// demoSyslogLevels are the Log Level options of the gateway's Syslog page.
var demoSyslogLevels = []string{"Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Informational", "Debug"}

// demoSyslogPage stands in for the gateway's Syslog page (Diagnostics › Syslog, syslog.ha) as a
// settings check stores it: synthetic, since phase 1 has not captured the real page yet.
const demoSyslogPage = `<!DOCTYPE html><html><head><title>Diagnostics - Syslog</title></head><body>
<h1>Syslog</h1><p>(demo page: a stand-in for the gateway's syslog.ha)</p>
<form method="post" action="/cgi-bin/syslog.ha"><input type="hidden" name="nonce" value="0000000000000000">
<table>
<tr><th><label for="enable">Syslog</label></th><td><select id="enable" name="enable"><option value="on" selected>On</option><option value="off">Off</option></select></td></tr>
<tr><th><label for="server">Server IP Address</label></th><td><input type="text" id="server" name="server" value="192.168.1.71"></td></tr>
<tr><th><label for="port">Server Port</label></th><td><input type="text" id="port" name="port" value="514"></td></tr>
<tr><th><label for="level">Log Level</label></th><td><select id="level" name="level"><option>Emergency</option><option>Alert</option><option>Critical</option><option>Error</option><option>Warning</option><option>Notice</option><option selected>Informational</option><option>Debug</option></select></td></tr>
</table><input type="submit" name="Save" value="Save"></form></body></html>
`

// demoSyslog is a message as the receiver records it: the datagram the gateway sent (RFC 3164,
// or RFC 5424 when rfc5424), received at rx, with its parsed header. The gateway's clock runs
// 1.2 s ahead of this computer's (as in the demo snapshots).
func demoSyslog(rx time.Time, fac, sev int, app, text string, rfc5424 bool) model.SyslogMessage {
	pri := fac*8 + sev
	m := model.SyslogMessage{RX: rx.UTC().Format(time.RFC3339Nano), Src: demoGateway + ":514", PRI: &pri, Facility: &fac, Severity: &sev,
		Host: demoSyslogHost, App: app, Msg: text}
	sent := rx.Add(1200 * time.Millisecond)
	if rfc5424 {
		m.Format, m.TS = "rfc5424", sent.UTC().Format("2006-01-02T15:04:05.000Z07:00")
		m.Raw = fmt.Sprintf("<%d>1 %s %s %s - - - %s", pri, m.TS, demoSyslogHost, app, text)
	} else {
		m.Format, m.TS = "rfc3164", sent.Local().Format(time.Stamp)
		m.Raw = fmt.Sprintf("<%d>%s %s %s: %s", pri, m.TS, demoSyslogHost, app, text)
	}
	return m
}

// appendSyslogLocked records a batch of messages received before ts (oldest first), as the
// monitor does, rejected counting the datagrams of other senders.
func (w *demoWorld) appendSyslogLocked(ts time.Time, rejected int, msgs ...model.SyslogMessage) {
	if len(msgs) == 0 {
		return
	}
	w.appendLocked(ts, model.TypeSyslog, model.SyslogBatch{From: msgs[0].RX, To: ts.UTC().Format(time.RFC3339Nano),
		Received: len(msgs), Rejected: rejected, Messages: msgs})
	if !ts.Before(w.syslogSince) {
		w.syslogReceived += int64(len(msgs))
	}
	last := msgs[len(msgs)-1]
	w.syslogLast = &last
}

// syslogQuietAt reports whether no syslog message reaches this computer at t: the monitor is
// not running, this computer's link is down, or the gateway is restarting.
func (w *demoWorld) syslogQuietAt(t time.Time) bool {
	for _, e := range w.allEventsLocked() {
		if e.covers(t) && (e.gap || e.cause == model.CauseLocalLinkDown || (!e.boot.IsZero() && t.Before(e.boot.Add(30*time.Second)))) {
			return true
		}
	}
	return false
}

// wanDownAt reports whether the AT&T line is down at t (fiber or broadband connection).
func (w *demoWorld) wanDownAt(t time.Time) bool {
	for _, e := range w.allEventsLocked() {
		if e.covers(t) && (e.cause == model.CauseFiberLinkDown || e.cause == model.CauseWANDown) {
			return true
		}
	}
	return false
}

// routineSyslog is a batch of the gateway's everyday messages written at ts, 1 to 3 of them
// (picked by noise, so every run has the same): firewall drops, DHCP leases, the TR-069 inform,
// time synchronisation, DNS queries (debug) and refused port mappings.
func routineSyslog(ts time.Time) []model.SyslogMessage {
	n := 1 + int(noise(ts, 90)*3)
	out := make([]model.SyslogMessage, 0, n)
	for j := 0; j < n; j++ {
		rx := ts.Add(-time.Duration(28-7*j)*time.Second - time.Duration(noise(ts, 91+j)*5000)*time.Millisecond)
		x := int(noise(ts, 95+j) * 1000)
		var m model.SyslogMessage
		switch x % 7 {
		case 0, 1: // firewall drops are the most frequent
			m = demoSyslog(rx, 16, 6, "kernel", fmt.Sprintf("[FW] Policy dropped: IN=wan0 SRC=198.51.100.%d DST=%s PROTO=TCP SPT=%d DPT=%d SYN",
				2+x%250, demoWANIP, 40000+x*17%20000, []int{23, 22, 445, 3389}[x%4]), false)
		case 2:
			m = demoSyslog(rx, 3, 6, "dhcpd", fmt.Sprintf("DHCPACK on 192.168.1.%d to 02:00:00:00:00:%02x via br0", 64+x%40, x%256), false)
		case 3:
			m = demoSyslog(rx, 1, 6, "cwmpd", "Periodic Inform to the ACS completed (HTTP 204)", true)
		case 4:
			m = demoSyslog(rx, 3, 5, "ntpd", fmt.Sprintf("time synchronized with 192.0.2.123, offset %+.3f s", (noise(ts, 99)-0.5)/50), false)
		case 5:
			m = demoSyslog(rx, 3, 7, "dnsmasq", fmt.Sprintf("query[A] www.google.com from 192.168.1.%d", 64+x%40), false)
		default:
			m = demoSyslog(rx, 3, 4, "upnpd", fmt.Sprintf("refused a port mapping request from 192.168.1.%d: external port %d in use", 64+x%40, 3074+x%5), false)
		}
		out = append(out, m)
	}
	return out
}

// oddSyslog is a batch whose messages test how the dashboard shows what a sender controls:
// bytes that are not UTF-8 (kept as base64), a datagram without a PRI, an escape sequence, a
// DHCP host name with a right-to-left override, several lines and a very long line.
func oddSyslog(ts time.Time) []model.SyslogMessage {
	rx := func(i int) time.Time { return ts.Add(-time.Duration(25-4*i) * time.Second) }
	bad := strings.Repeat(string(rune(0xFFFD)), 2)
	notUTF8 := demoSyslog(rx(0), 3, 6, "wifid", "probe request from 02:00:00:00:00:99 for SSID "+bad+"HOME-5G", false)
	notUTF8.RawB64 = base64.StdEncoding.EncodeToString([]byte(strings.Replace(notUTF8.Raw, bad, "\xff\xfe", 1)))
	notUTF8.Raw = ""
	noPRI := model.SyslogMessage{RX: rx(1).UTC().Format(time.RFC3339Nano), Src: demoGateway + ":514", Raw: demoSyslogHost + " watchdog: heartbeat ok", Format: "unknown"}
	rlo, pdf := string(rune(0x202E)), string(rune(0x202C)) // right-to-left override, pop directional formatting
	return []model.SyslogMessage{
		notUTF8,
		noPRI,
		demoSyslog(rx(2), 16, 3, "wanmgr", "\x1b[1;31mWAN link flap\x1b[0m detected on wan0", false),
		demoSyslog(rx(3), 3, 6, "dhcpd", "DHCPACK on 192.168.1.80 to 02:00:00:00:00:80 ("+rlo+"gpj.exe"+pdf+") via br0", false),
		demoSyslog(rx(4), 1, 4, "cwmpd", "Inform to the ACS failed:\nHTTP 503 Service Unavailable\nretry in 60 s", true),
		demoSyslog(rx(5), 16, 6, "kernel", "[FW] Policy dropped: IN=wan0 OUT= MAC=00:00:5e:00:53:01:00:00:5e:00:53:fe:08:00 SRC=198.51.100.77 DST="+demoWANIP+
			" LEN=60 TOS=0x00 PREC=0x00 TTL=50 ID=54321 DF PROTO=TCP SPT=44532 DPT=23 WINDOW=64240 RES=0x00 SYN URGP=0 OPT (020405B40402080A3C5D1A2B0000000001030307) payload="+
			strings.Repeat("QUFBQUFBQUFBQUFB", 12), false),
	}
}

// demoSyslogAt is a batch of the gateway's messages about an event, recorded at at.
type demoSyslogAt struct {
	at   time.Time
	kind string // eventMessages
}

// eventSyslog lists the gateway's messages about an event: the outage's start and end, the boot
// after a restart, the reconnection of this computer's Wi-Fi (what the gateway logged while it
// was disconnected never arrived), forward error correction during packet loss, the forwarder
// during the AT&T DNS failure. High latency and VPN periods leave no trace in the gateway's log.
func eventSyslog(e *demoEvent) []demoSyslogAt {
	sec := time.Second
	switch {
	case !e.boot.IsZero():
		return []demoSyslogAt{{e.boot.Add(45 * sec), "boot"}, {e.to.Add(25 * sec), "wan-up"}}
	case e.cause == model.CauseFiberLinkDown:
		return []demoSyslogAt{{e.from.Add(25 * sec), "fiber-down"}, {e.to.Add(25 * sec), "fiber-up"}}
	case e.cause == model.CauseWANDown:
		return []demoSyslogAt{{e.from.Add(25 * sec), "wan-down"}, {e.to.Add(25 * sec), "wan-up"}}
	case e.cause == model.CauseLocalLinkDown:
		return []demoSyslogAt{{e.to.Add(25 * sec), "wifi-up"}}
	case e.cause == model.CausePacketLoss:
		return []demoSyslogAt{{e.from.Add(40 * sec), "fec"}}
	case e.cause == model.CauseISPDNSFailure:
		return []demoSyslogAt{{e.from.Add(20 * sec), "dns"}}
	}
	return nil
}

// eventMessages is the gateway's batch of messages of the given kind (eventSyslog), received in
// the 20 seconds before ts.
func eventMessages(kind string, ts time.Time) []model.SyslogMessage {
	rx := func(i int) time.Time { return ts.Add(-time.Duration(20-5*i) * time.Second) }
	switch kind {
	case "fiber-down":
		return []model.SyslogMessage{
			demoSyslog(rx(0), 16, 2, "ponlinkd", "PON link state O5 -> O1 (loss of signal)", false),
			demoSyslog(rx(1), 16, 1, "optmon", "Rx optical power below the low alarm threshold (no light received)", false),
			demoSyslog(rx(2), 16, 3, "wanmgr", "Broadband connection down (PON link lost)", false)}
	case "fiber-up":
		return []model.SyslogMessage{
			demoSyslog(rx(0), 16, 5, "ponlinkd", "PON link state O1 -> O5 (operation)", false),
			demoSyslog(rx(1), 16, 5, "wanmgr", "Broadband connection up, IPv4 "+demoWANIP, false)}
	case "wan-down":
		return []model.SyslogMessage{
			demoSyslog(rx(0), 16, 3, "wanmgr", "Broadband connection down (no DHCP offer from the AT&T network)", false),
			demoSyslog(rx(1), 16, 4, "dhcpc", "DHCPDISCOVER on wan0: no answer after 4 attempts", false)}
	case "wan-up":
		return []model.SyslogMessage{demoSyslog(rx(0), 16, 5, "wanmgr", "Broadband connection up, IPv4 "+demoWANIP, false)}
	case "boot":
		return []model.SyslogMessage{
			demoSyslog(rx(0), 5, 6, "syslogd", "syslogd started", false),
			demoSyslog(rx(1), 0, 5, "kernel", "Booting firmware 6.34.7", false),
			demoSyslog(rx(2), 16, 4, "wanmgr", "Broadband connection not up yet (PON ranging)", false)}
	case "wifi-up":
		return []model.SyslogMessage{
			demoSyslog(rx(0), 3, 6, "wifid", "wl1: STA 02:00:00:00:00:71 associated (5 GHz, RSSI -52 dBm)", false),
			demoSyslog(rx(1), 3, 6, "dhcpd", "DHCPACK on 192.168.1.71 to 02:00:00:00:00:71 (DESKTOP-DEMO) via br0", false)}
	case "fec":
		return []model.SyslogMessage{demoSyslog(rx(0), 16, 4, "ponlinkd", "FEC: 1532 corrected and 12 uncorrectable codewords in the last 60 s", false)}
	case "dns":
		return []model.SyslogMessage{demoSyslog(rx(0), 3, 4, "dnsmasq", "nameserver "+demoISPDNS+" did not answer: trying 68.94.157.9", false)}
	}
	return nil
}

// syslogCheckLocked records a check of the gateway's Syslog page (read-only in this version):
// a gateway_event syslog_setting with the setting read and the page.
func (w *demoWorld) syslogCheckLocked(ts time.Time) {
	w.syslogCheck = w.appendLocked(ts, model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvSyslogSetting,
		After:  "on: 192.168.1.71:514, level Informational",
		Detail: "read-only check of the gateway's Diagnostics › Syslog page; this version does not change the setting"}, w.page["syslog"])
}

// syslogStatusLocked is Status.Syslog: the receiver listening, its counters since the service
// started, the newest message and the gateway's Syslog setting as last read. /demo/syslog shows
// the other states the dashboard words (syslogState).
func (w *demoWorld) syslogStatusLocked() *model.SyslogStatus {
	if w.syslogState == "none" {
		return nil
	}
	sl := &model.SyslogStatus{Enabled: true, Listening: true, Listen: "0.0.0.0:514", Received: w.syslogReceived, Recorded: w.syslogReceived,
		Rejected: 7, State: "ok", GatewayAt: w.syslogCheck.TS, GatewaySeq: w.syslogCheck.Seq,
		Gateway: &model.SyslogSetting{Enabled: true, Server: "192.168.1.71", Port: 514, Level: "Informational", Levels: demoSyslogLevels}}
	if m := w.syslogLast; m != nil {
		sl.LastAt, sl.Last = m.RX, m.Raw
		if sl.Last == "" {
			sl.Last = m.Msg
		}
	}
	switch w.syslogState {
	case "off":
		sl.State, sl.Gateway = "off", &model.SyslogSetting{Levels: demoSyslogLevels}
	case "elsewhere":
		sl.State, sl.Gateway = "elsewhere", &model.SyslogSetting{Enabled: true, Server: "192.168.1.20", Port: 1514, Level: "Debug", Levels: demoSyslogLevels}
	case "error":
		sl.State, sl.Problem = "error", "gateway: login throttled: a login was attempted less than a minute ago"
	case "unknown":
		sl.State, sl.Gateway, sl.GatewayAt, sl.GatewaySeq = "unknown", nil, "", 0
		sl.Problem = "the daily settings check has not read the gateway's Syslog page yet"
	case "enforce": // as from phase 2
		sl.Enforce, sl.Target = true, &model.SyslogTarget{Enabled: true, Server: "192.168.1.71", Port: 514, Level: "Informational"}
	case "nolisten":
		sl.Listening, sl.ListenErr = false, "listen udp 0.0.0.0:514: bind: Only one usage of each socket address (protocol/network address/port) is normally permitted."
	case "disabled":
		sl.Enabled, sl.Listening = false, false
	}
	return sl
}

// ----------------------------------------------------------------------------- traffic

// demoTraffic is the simulated traffic of one minute, in Mb/s: the gateway's WAN counters and
// this computer's. A rate is known only when its counters could be read before and after.
type demoTraffic struct {
	wan, atLeast bool // WAN rates known; "at least" (the 32-bit byte counter may have wrapped)
	rx, tx       float64
	pc           bool // this computer's rates known
	pcRx, pcTx   float64
}

// trafficMinute simulates the traffic of the minute that starts at t: little at night, busy in
// the evening, with some streaming peaks; none on the WAN while the AT&T line is down; unknown
// while the monitor was not running, while this computer could not reach the gateway and across
// the gateway's restart (its counters start again).
func (w *demoWorld) trafficMinute(t time.Time) demoTraffic {
	calm, dns := false, false
	for _, e := range w.allEventsLocked() {
		if !e.covers(t) {
			continue
		}
		switch {
		case e.gap:
			return demoTraffic{}
		case e.cause == model.CauseLocalLinkDown:
			return demoTraffic{pc: true}
		case !e.boot.IsZero():
			return demoTraffic{pc: true, pcRx: 0.02, pcTx: 0.01}
		case e.cause == model.CauseFiberLinkDown || e.cause == model.CauseWANDown:
			return demoTraffic{wan: true, pc: true, pcRx: 0.03, pcTx: 0.01}
		case e.state == model.StateDegraded && e.attribution == model.AttrProvider:
			// The classifier blamed AT&T, so the household's traffic was below 80 Mb/s.
			calm, dns = true, e.cause == model.CauseISPDNSFailure
		}
	}
	hour := float64(t.Local().Hour()) + float64(t.Local().Minute())/60
	base := 3 + 22*(1+math.Sin(2*math.Pi*(hour-15)/24))
	tr := demoTraffic{wan: true, pc: true, rx: base * (0.55 + 0.9*noise(t, 70))}
	switch {
	case dns: // what the verdicts of the AT&T DNS incident state
		tr.rx = 32.8 + noise(t, 71) - 0.5
	case !t.Before(w.burstFrom) && t.Before(w.burstTo):
		tr.rx, tr.atLeast = 620+320*noise(t, 72), noise(t, 76) > 0.35
	case !calm && noise(t, 71) > 0.97:
		tr.rx += 60 + 180*noise(t, 72) // streaming, a game download
	case calm:
		tr.rx = min(tr.rx, 60)
	}
	tr.tx = tr.rx*0.12 + 0.4 + 0.6*noise(t, 73)
	if dns {
		tr.tx = 5 + 0.2*noise(t, 73) - 0.1
	}
	tr.pcRx = tr.rx*(0.2+0.3*noise(t, 77)) + 0.05
	tr.pcTx = tr.tx*0.4 + 0.02
	return tr
}

// trafficLocked aggregates the simulated traffic into the n buckets of step from first, as the
// monitor does (Series.Traffic): per bucket the mean of the known minutes, the highest of them,
// and whether any WAN rate is "at least".
func (w *demoWorld) trafficLocked(first time.Time, step time.Duration, n int, now time.Time) []model.TrafficPoint {
	rate := func(v float64) *float64 {
		v = math.Round(v*1000) / 1000
		return &v
	}
	out := make([]model.TrafficPoint, n)
	for i := range out {
		a := first.Add(time.Duration(i) * step)
		p := model.TrafficPoint{T: a.UTC().Format(time.RFC3339)}
		var wanN, pcN int
		var rx, tx, rxPeak, txPeak, pcRx, pcTx float64
		for t := a.Truncate(time.Minute); t.Before(a.Add(step)); t = t.Add(time.Minute) {
			if t.Before(w.genesis) || t.After(now) {
				continue
			}
			tr := w.trafficMinute(t)
			if tr.wan {
				wanN++
				rx, tx = rx+tr.rx, tx+tr.tx
				rxPeak, txPeak = max(rxPeak, tr.rx), max(txPeak, tr.tx)
				p.AtLeast = p.AtLeast || tr.atLeast
			}
			if tr.pc {
				pcN++
				pcRx, pcTx = pcRx+tr.pcRx, pcTx+tr.pcTx
			}
		}
		if wanN > 0 {
			p.WANRx, p.WANTx = rate(rx/float64(wanN)), rate(tx/float64(wanN))
			p.WANRxPeak, p.WANTxPeak = rate(rxPeak), rate(txPeak)
		}
		if pcN > 0 {
			p.PCRx, p.PCTx = rate(pcRx/float64(pcN)), rate(pcTx/float64(pcN))
		}
		out[i] = p
	}
	return out
}

// trafficDaysLocked sums the simulated WAN volume per local day from the day of first to today,
// as the monitor does (Series.TrafficDays): exactly known minutes only ("at least" ones are not
// exact), complete when every minute of the day until now was.
func (w *demoWorld) trafficDaysLocked(first, now time.Time) []model.TrafficDay {
	y, mo, d := first.Local().Date()
	var out []model.TrafficDay
	for i := 0; ; i++ {
		start := time.Date(y, mo, d+i, 0, 0, 0, 0, time.Local)
		if start.After(now) {
			break
		}
		end := time.Date(y, mo, d+i+1, 0, 0, 0, 0, time.Local)
		day := model.TrafficDay{Day: start.Format(time.DateOnly), Complete: true}
		var rx, tx float64
		for t := start; t.Before(end) && t.Before(now); t = t.Add(time.Minute) {
			tr := w.trafficMinute(t)
			if t.Before(w.genesis) || !tr.wan || tr.atLeast {
				day.Complete = false
				continue
			}
			rx, tx = rx+tr.rx*60e6/8, tx+tr.tx*60e6/8
			day.CoveredS += 60
		}
		day.RxBytes, day.TxBytes = int64(rx), int64(tx)
		out = append(out, day)
	}
	return out
}

// ----------------------------------------------------------------------------- live outage

// setOutage switches the demo between a healthy line and a live AT&T fiber outage.
func (w *demoWorld) setOutage(on bool) {
	if on {
		w.setLive("outage")
	} else {
		w.setLive("")
	}
}

// Live demo states (setLive).
const (
	liveOutage = "outage" // the AT&T gateway reports its fiber link down
	liveVPN    = "vpn"    // a VPN takes this computer's internet routes; the gateway answers (LOCAL_ROUTE)
)

// setLive switches the demo between a healthy line ("") and a live bad state that opens an
// incident: liveOutage or liveVPN.
func (w *demoWorld) setLive(kind string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()
	if w.live != nil && w.live.name == "live-"+kind {
		return
	}
	if w.live != nil {
		w.endLiveLocked(now)
	}
	if kind == "" {
		return
	}
	start := now.Add(-7 * time.Minute)
	if last, err := time.Parse(time.RFC3339Nano, w.bodies[len(w.bodies)-1].TS); err == nil && !start.After(last) {
		start = last.Add(time.Second)
	}
	if start.After(now) {
		start = now // records may carry slightly later (monotonic) timestamps; the state starts now
	}
	e := &demoEvent{name: "live-" + kind, from: start, state: model.StateISPOutage, cause: model.CauseFiberLinkDown, attribution: model.AttrProvider, incident: true,
		reasons: []string{"AT&T gateway reports PON Link Status: INITIAL (O1)", "AT&T gateway reports Broadband Connection: Down", "gateway 192.168.1.254 answered ICMP in 2.0 ms", "0/5 internet probes succeeded"},
		summary: "AT&T gateway reports its fiber link down; this PC reaches the gateway, no internet probe succeeds."}
	if kind == liveVPN {
		v := w.eventByName("vpn")
		e.state, e.cause, e.attribution, e.reasons = v.state, v.cause, v.attribution, v.reasons
		e.summary = "No internet probe succeeds while the AT&T gateway answers, but this computer's routes to the internet destinations go through the VPN adapter NordLynx, not through the AT&T gateway, so nothing is attributed to AT&T."
	}
	e.incidentID = "INC-" + start.UTC().Format("20060102-150405") + "Z"
	w.live = e
	inc := &model.Incident{ID: e.incidentID, Opened: start.UTC().Format(time.RFC3339Nano), Open: true, State: e.state, Cause: e.cause,
		Attribution: e.attribution, Causes: []string{e.cause}, Summary: e.summary, Reasons: e.reasons, Rules: demoRules}
	w.liveInc = inc
	r := w.appendSampleLocked(start)
	inc.FirstSeq = r.Seq
	w.appendLocked(start.Add(time.Second), model.TypeStateChange, model.StateChange{FromState: model.StateOnline, ToState: e.state, ToCause: e.cause, At: start.UTC().Format(time.RFC3339Nano), Cycle: w.cycle, Reasons: e.reasons})
	r = w.appendLocked(start.Add(30*time.Second), model.TypeIncidentOpen, *inc)
	inc.Evidence = append(inc.Evidence, model.EvidenceRef{Seq: r.Seq, Type: model.TypeIncidentOpen, Note: "incident opened after 3 bad cycles"})
	if kind == liveVPN {
		snap := w.snapshotLocked(start.Add(31*time.Second), false, "incident", true)
		r = w.appendLocked(start.Add(31*time.Second), model.TypeGatewaySnapshot, snap, pageBlobs(snap)...)
		inc.Evidence = append(inc.Evidence, model.EvidenceRef{Seq: r.Seq, Type: model.TypeGatewaySnapshot, Blob: firstBlob(snap), Note: "gateway status pages captured"})
		r = w.appendLocked(start.Add(34*time.Second), model.TypeLocalLink, w.localLinkAt(start, true), w.netsh)
		inc.Evidence = append(inc.Evidence, model.EvidenceRef{Seq: r.Seq, Type: model.TypeLocalLink, Blob: w.netsh, Note: "this PC's adapter and routes"})
	} else {
		snap := w.snapshotLocked(start.Add(31*time.Second), true, "incident", true)
		r = w.appendLocked(start.Add(31*time.Second), model.TypeGatewaySnapshot, snap, snap.Pages[0].SHA256, snap.Pages[1].SHA256, snap.Pages[2].SHA256)
		inc.Evidence = append(inc.Evidence, model.EvidenceRef{Seq: r.Seq, Type: model.TypeGatewaySnapshot, Blob: snap.Pages[0].SHA256, Note: "gateway reports Broadband Connection: Down"})
		r = w.appendLocked(start.Add(32*time.Second), model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvPONState, Before: "OPERATION (O5)", After: "INITIAL (O1)", Evidence: []uint64{r.Seq}})
		inc.Evidence = append(inc.Evidence, model.EvidenceRef{Seq: r.Seq, Type: model.TypeGatewayEvent, Note: "pon_state O5 → O1"})
		w.appendSyslogLocked(start.Add(33*time.Second), 0, eventMessages("fiber-down", start.Add(33*time.Second))...)
	}
	r = w.appendLocked(start.Add(40*time.Second), model.TypeTraceroute, traceroute("8.8.8.8", "incident_open", e.incidentID, false))
	inc.Evidence = append(inc.Evidence, model.EvidenceRef{Seq: r.Seq, Type: model.TypeTraceroute, Note: "traceroute 8.8.8.8"})
}

// endLiveLocked ends the live bad state at now and closes its incident.
func (w *demoWorld) endLiveLocked(now time.Time) {
	e, inc := w.live, w.liveInc
	e.to = now
	w.events = append(w.events, e)
	w.live, w.liveInc = nil, nil
	if e.cause == model.CauseFiberLinkDown {
		w.appendSyslogLocked(now, 0, eventMessages("fiber-up", now)...)
	}
	w.appendLocked(now, model.TypeStateChange, model.StateChange{FromState: e.state, FromCause: e.cause, ToState: model.StateOnline, At: now.UTC().Format(time.RFC3339Nano), Cycle: w.cycle})
	inc.Open = false
	inc.Closed = now.UTC().Format(time.RFC3339Nano)
	if e.state == model.StateISPOutage {
		inc.RecoveredAt = inc.Closed
	}
	inc.DurationSec = int64(now.Sub(e.from).Seconds())
	inc.Stats = w.incidentStats(e)
	r := w.appendLocked(now.Add(time.Second), model.TypeIncidentClose, *inc)
	inc.LastSeq = r.Seq
	inc.Evidence = append(inc.Evidence, model.EvidenceRef{Seq: r.Seq, Type: model.TypeIncidentClose})
	w.anchorLocked(now.Add(2*time.Second), "incident_close")
	w.incidents = append(w.incidents, inc)
}

// ----------------------------------------------------------------------------- StatusSource

func (w *demoWorld) fingerprint() string {
	sum := sha256.Sum256(w.key.Public().(ed25519.PublicKey))
	return hex.EncodeToString(sum[:])
}

// displaySpecs lists the configured probes with their runtime targets, as Status.Probes does.
func displaySpecs() []model.ProbeSpec {
	specs := slices.Clone(config.Default().Probes.Targets)
	for i := range specs {
		switch specs[i].Role {
		case model.RoleGateway:
			specs[i].Target = demoGateway
			if specs[i].Kind == model.KindTCP {
				specs[i].Target += ":443"
			}
		case model.RoleISPHop:
			specs[i].Target = demoNextHop
		}
	}
	return specs
}

func (w *demoWorld) Status() model.Status {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()
	probes, verdict := w.probesAt(now)
	verdict.Inputs = &model.VerdictInputs{SnapshotSeq: w.lastOf[model.TypeGatewaySnapshot].Seq,
		ServiceCheckSeq: w.lastOf[model.TypeServiceCheck].Seq, LocalLinkSeq: w.lastOf[model.TypeLocalLink].Seq, WindowCycles: 6}
	sample := &model.Sample{Cycle: w.cycle + uint64(now.Sub(w.created)/(10*time.Second)), Started: now.Add(-3 * time.Second).Truncate(10 * time.Second).UTC().Format(time.RFC3339Nano),
		DurMs: 2004, Probes: probes, Verdict: verdict}
	service := w.serviceCheckAt(now, w.live != nil && w.live.state == model.StateISPOutage)
	switch w.liveDNSRetry {
	case "answered": // one lost datagram: the retry answered (rules 2026.10-4)
		service = ispRetry(service, true)
	case "failed": // the query and its retry got no answer, in this check only: not counted
		service = ispRetry(service, false)
		prev := w.lastOf[model.TypeServiceCheck].Seq
		verdict.Inputs.PrevServiceCheckSeq = prev
		verdict.Reasons = append(slices.Clone(verdict.Reasons), fmt.Sprintf("ISP resolver %s failed (%s; retried: %s) while public resolver 1.1.1.1 answered in this service check, but not in the previous one (#%d): one failing check is not counted as a resolver failure",
			demoISPDNS, service.DNS[1].Err, service.DNS[2].Err, prev))
		sample.Verdict = verdict
	}
	down := w.live != nil && w.live.state == model.StateISPOutage
	snap := w.snapshotLocked(now.Add(-20*time.Second), down, map[bool]string{true: "incident", false: "periodic"}[down], down)
	since := w.genesis
	for _, e := range w.allEventsLocked() {
		if e.gap {
			continue
		}
		if e.covers(now) {
			since = e.from
		} else if !e.to.IsZero() && e.to.Before(now) && e.to.After(since) {
			since = e.to
		}
	}
	st := model.Status{
		Now: now.UTC().Format(time.RFC3339Nano),
		Monitor: model.MonitorInfo{Version: "demo", Started: w.created.Add(-2*24*time.Hour - 3*time.Hour).UTC().Format(time.RFC3339Nano), RunID: w.run,
			UptimeSec: int64(now.Sub(w.created.Add(-2*24*time.Hour - 3*time.Hour)).Seconds()), Cycles: sample.Cycle, Mode: "service", Listen: "127.0.0.1:8399", Rules: demoRules},
		Verdict: verdict, Since: since.UTC().Format(time.RFC3339Nano), LastSample: sample, Gateway: &snap,
		GatewayAt: now.Add(-20 * time.Second).UTC().Format(time.RFC3339Nano), Notification: func() *model.NotificationState { n := w.notif; return &n }(),
		LastService: &service,
		LocalLink:   func() *model.LocalLink { l := w.localLinkAt(now, true); return &l }(),
		Clock: &model.ClockCheck{Results: []model.ClockResult{
			{Server: "time.windows.com", Addr: "168.61.215.74:123", OK: true, OffsetMs: 12, RTTms: 31, Stratum: 3},
			{Server: "time.google.com", Addr: "216.239.35.0:123", OK: !down, OffsetMs: -4, RTTms: 14, Stratum: 1, Err: map[bool]string{true: "i/o timeout"}[down]},
			{Server: "pool.ntp.org", Addr: "192.0.2.123:123", OK: true, OffsetMs: 9, RTTms: 22, Stratum: 2},
		}, GatewayOffsetMs: i64(1200)},
		Probes: displaySpecs(),
		Ledger: w.ledgerStatusLocked(),
		Stats:  []model.WindowStats{w.windowStatsLocked("24h", 24*time.Hour, now), w.windowStatsLocked("7d", 7*24*time.Hour, now)},
	}
	if w.liveInc != nil {
		inc := w.liveViewLocked(*w.liveInc, now)
		st.ActiveIncident = &inc
	}
	rxSince := w.created.Add(-4*24*time.Hour - 7*time.Hour).UTC().Format(time.RFC3339)
	st.Conditions = []model.Condition{
		{Code: "OPTICAL_RX_LOW_ALARM", Severity: "critical", Message: "The AT&T gateway flags its received optical power (Rx) below its low-alarm threshold.", Since: rxSince, Seq: 412},
		{Code: "OPTICAL_RX_LOW_WARNING", Severity: "warning", Message: "The AT&T gateway flags its received optical power (Rx) below its low-warning threshold.", Since: rxSince, Seq: 412},
	}
	st.Conditions = append(st.Conditions, w.extraConds...)
	if e := w.routeBypassEventAt(now); e != nil { // the monitor's wording (internal/monitor egressCondition)
		st.Conditions = append(st.Conditions, model.Condition{Code: "EGRESS_NOT_VIA_GATEWAY", Severity: "warning",
			Message: "This computer's internet traffic does not go through the AT&T gateway: " + demoBypassText +
				". While this lasts, nothing this computer measures on the Internet is attributed to AT&T (is a VPN or another network connection active?).",
			Since: e.from.UTC().Format(time.RFC3339Nano), Seq: w.lastOf[model.TypeLocalLink].Seq})
	}
	if w.stale {
		w.staleLocked(&st, now)
	}
	if w.notif.Enabled {
		st.Conditions = append(st.Conditions, model.Condition{Code: "NOTIFICATION_REDIRECT_ON", Severity: "warning",
			Message: "Broadband Status Notification is enabled on the gateway.", Since: w.notif.CheckedAt, Seq: w.notif.Seq})
	}
	if w.pendingCert != "" { // the monitor's wording (internal/monitor conditions.go)
		st.Conditions = append(st.Conditions, model.Condition{Code: condGatewayCertChanged, Severity: "critical",
			Message: fmt.Sprintf("AT&T gateway presented a TLS certificate (SHA-256 %s) different from the pinned one: status pages are still read, but authenticated requests (the notification setting) are paused until the certificate is confirmed (trust-cert)", w.pendingCert),
			Since:   w.certSince.UTC().Format(time.RFC3339Nano), Seq: w.certSeq})
	}
	if !w.noGatewayCert { // the pin as the monitor applies it
		st.GatewayCert = &model.GatewayCertState{Pinned: w.pinnedCert, Pending: w.pendingCert}
		if w.pendingCert != "" {
			st.GatewayCert.Since, st.GatewayCert.Seq = w.certSince.UTC().Format(time.RFC3339Nano), w.certSeq
		}
	}
	if w.noAccessCode {
		st.Conditions = append(st.Conditions, model.Condition{Code: "NO_ACCESS_CODE", Severity: "info",
			Message: "No gateway access code is configured, so the gateway's outage-redirect setting (Broadband Status Notification) cannot be checked or enforced (att-monitor set-access-code)"})
	}
	if w.anchorUntrusted { // the monitor's wording (internal/monitor conditions.go)
		a := w.lastOf[model.TypeAnchor]
		st.Conditions = append(st.Conditions, model.Condition{Code: "ANCHOR_UNTRUSTED", Severity: "warning",
			Message: fmt.Sprintf("Time-stamps obtained but their authority could not be verified (latest: CN=www.freetsa.org, covering record #%d: the time-stamp authority's certificate did not chain to a trusted root); they stay recorded but do not count as proof of time, so the ledger is treated as unanchored since the last trusted time-stamp", a.Seq-2),
			Since:   a.TS, Seq: a.Seq})
	}
	if w.hostile != "" { // a condition code the dashboard does not know
		st.Conditions = append(st.Conditions, model.Condition{Code: "UNKNOWN_FLAG " + w.hostile, Severity: "warning", Message: "unknown condition"})
	}
	st.Syslog = w.syslogStatusLocked()
	return hostileCopy(w.hostile, st)
}

// demoClockCondition is CLOCK_OFFSET (docs/DESIGN.md §9: warning above 60 s of SNTP offset), in
// the monitor's wording (internal/monitor clockOffsetCondition).
func demoClockCondition(now time.Time) model.Condition {
	at := now.Add(-50 * time.Minute)
	return model.Condition{Code: "CLOCK_OFFSET", Severity: "warning", Since: at.UTC().Format(time.RFC3339Nano), Seq: 7,
		Message: "This computer's clock is off by about 94 s compared with internet time servers; evidence timestamps rely on it — fix the Windows time settings (the clock is behind them: median of 3 answers in clock check #7 at " +
			at.UTC().Format("2006-01-02 15:04:05 UTC") + ")."}
}

// staleLocked makes st what the monitor reports while it records no cycle (internal/monitor
// staleVerdict): the last sample is minutes old, the verdict UNKNOWN with the reason, no
// "since"; here because the evidence ledger refuses records (LEDGER_WRITE_FAILING), the data
// volume being nearly full (DISK_SPACE_LOW).
func (w *demoWorld) staleLocked(st *model.Status, now time.Time) {
	last := now.Add(-7 * time.Minute).Truncate(10 * time.Second)
	probes, v := w.probesAt(last)
	v.Inputs = &model.VerdictInputs{SnapshotSeq: w.lastOf[model.TypeGatewaySnapshot].Seq, ServiceCheckSeq: w.lastOf[model.TypeServiceCheck].Seq,
		LocalLinkSeq: w.lastOf[model.TypeLocalLink].Seq, WindowCycles: 6}
	st.LastSample = &model.Sample{Cycle: st.LastSample.Cycle - 42, Started: last.UTC().Format(time.RFC3339Nano), DurMs: 2004, Probes: probes, Verdict: v}
	was := v.State
	if v.Cause != "" {
		was += "/" + v.Cause
	}
	failing := now.Add(-7*time.Minute + 4*time.Second)
	st.Verdict = model.Verdict{State: model.StateUnknown, Attribution: model.AttrUndetermined, Rules: demoRules, Reasons: []string{
		fmt.Sprintf("no monitoring cycle has been recorded for %s (the last one, at %s, was %s), so the current state is unknown",
			now.Sub(last).Round(time.Second), last.UTC().Format("2006-01-02 15:04:05 UTC"), was),
		"the evidence ledger is refusing records (see the LEDGER_WRITE_FAILING condition)"}}
	st.Since = ""
	st.Conditions = append(st.Conditions,
		model.Condition{Code: "LEDGER_WRITE_FAILING", Severity: "critical", Since: failing.UTC().Format(time.RFC3339Nano),
			Message: fmt.Sprintf("The evidence ledger has refused every record since %s (41 attempts; latest error: write C:\\ProgramData\\ATTMonitor\\ledger\\ledger-%s.jsonl: There is not enough space on the disk.): nothing is being recorded, so this period will be missing from the evidence. Free disk space on the data volume or restart the service.",
				failing.UTC().Format("2006-01-02 15:04:05 UTC"), now.UTC().Format("2006-01-02"))},
		model.Condition{Code: "DISK_SPACE_LOW", Severity: "critical", Since: now.Add(-time.Minute).UTC().Format(time.RFC3339Nano),
			Message: "The volume holding the evidence (C:\\ProgramData\\ATTMonitor) has only 3 MB free of 237.1 GB: the ledger grows by about 50-70 MB a day, and once the volume is full no record can be written. Free space on it."})
}

func (w *demoWorld) ledgerStatusLocked() model.LedgerStatus {
	head := w.headLocked()
	ls := model.LedgerStatus{HeadSeq: head.Seq, HeadHash: head.Hash, HeadTS: head.TS, Fingerprint: w.fingerprint(),
		GenesisTS: w.bodies[0].TS, DataDir: `C:\ProgramData\ATTMonitor`, LastVerify: w.lastVerify}
	for i := len(w.bodies) - 1; i >= 0; i-- {
		if w.bodies[i].Type == model.TypeAnchor {
			var a model.Anchor
			json.Unmarshal(w.bodies[i].Data, &a)
			ls.LastAnchorTime, ls.LastAnchorTSA, ls.LastAnchorSeq = a.GenTime, a.TSAURL, a.HeadSeq
			ls.UnanchoredCount = head.Seq - a.HeadSeq
			break
		}
	}
	return ls
}

func (w *demoWorld) windowStatsLocked(name string, span time.Duration, now time.Time) model.WindowStats {
	from := now.Add(-span)
	var monitored, online, provider, degraded time.Duration
	incidents, blips := 0, 0
	const step = time.Minute
	for t := from; t.Before(now); t = t.Add(step) {
		if t.Before(w.genesis) {
			continue
		}
		state, gap := model.StateOnline, false
		for _, e := range w.allEventsLocked() {
			if e.covers(t) {
				if e.gap {
					gap = true
				} else if st, _, _ := e.stateAt(t); stateRank(st) > stateRank(state) {
					state = st
				}
			}
		}
		if gap {
			continue
		}
		monitored += step
		if state == model.StateOnline {
			online += step
		}
	}
	for _, e := range w.allEventsLocked() {
		if e.gap {
			continue
		}
		// provider_outage_s: provider-attributed ISP_OUTAGE time, never inside a gateway-restart
		// window; degraded_s: DEGRADED time (docs/DESIGN.md §10).
		switch ov := e.overlap(from, now); {
		case e.boot.IsZero() && e.state == model.StateISPOutage && e.attribution == model.AttrProvider:
			provider += ov
		case e.state == model.StateDegraded:
			degraded += ov
		}
		if e.from.Before(from) {
			continue
		}
		if !e.incident {
			blips++
			continue
		}
		incidents++
	}
	ws := model.WindowStats{Window: name, MonitoredSec: int64(monitored.Seconds()), CoveragePct: 100 * monitored.Seconds() / span.Seconds(),
		Incidents: incidents, ProviderOutageSec: int64(provider.Seconds()), DegradedSec: int64(degraded.Seconds()), Blips: blips}
	if monitored > 0 {
		ws.AvailabilityPct = 100 * online.Seconds() / monitored.Seconds()
	}
	return ws
}

var demoRanges = map[string]struct{ span, step, optical time.Duration }{
	"1h":  {time.Hour, 30 * time.Second, time.Minute},
	"6h":  {6 * time.Hour, 2 * time.Minute, 2 * time.Minute},
	"24h": {24 * time.Hour, 5 * time.Minute, 5 * time.Minute},
	"7d":  {7 * 24 * time.Hour, 30 * time.Minute, 30 * time.Minute},
}

func (w *demoWorld) Series(rangeName string) (model.Series, error) {
	r, ok := demoRanges[rangeName]
	if !ok {
		return model.Series{}, fmt.Errorf("unknown range %q", rangeName)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()
	from := now.Add(-r.span).Truncate(r.step)
	s := model.Series{Range: rangeName, From: from.UTC().Format(time.RFC3339), To: now.UTC().Format(time.RFC3339Nano),
		StepSec: int(r.step.Seconds()), Probes: displaySpecs(), RxLowAlarmX10: i64(-295), RxLowWarnX10: i64(-292)}
	for b := from; b.Before(now); b = b.Add(r.step) {
		s.Points = append(s.Points, w.bucketLocked(b, b.Add(r.step)))
	}
	s.Optical = w.opticalLocked(from, now, r.optical)
	s.Traffic = w.trafficLocked(from, r.step, len(s.Points), now)
	s.TrafficDays = w.trafficDaysLocked(from, now)
	s.HeavyTrafficMbps = 80
	return hostileCopy(w.hostile, s), nil
}

func (w *demoWorld) Incidents(from, to time.Time) []model.Incident {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []model.Incident
	all := append([]*model.Incident(nil), w.incidents...)
	if w.liveInc != nil {
		all = append(all, w.liveInc)
	}
	for _, p := range all {
		inc := *p
		if inc.Open {
			inc = w.liveViewLocked(inc, time.Now())
		}
		opened, _ := time.Parse(time.RFC3339Nano, inc.Opened)
		closed, err := time.Parse(time.RFC3339Nano, inc.Closed)
		if opened.Before(to) && (inc.Open || err != nil || closed.After(from)) {
			out = append(out, inc)
		}
	}
	return hostileCopy(w.hostile, out)
}

// liveViewLocked fills in what the monitor reports for an open incident: its duration and
// time accounting so far (the live outage is one ISP_OUTAGE period).
func (w *demoWorld) liveViewLocked(inc model.Incident, now time.Time) model.Incident {
	opened, err := time.Parse(time.RFC3339Nano, inc.Opened)
	if err != nil || !now.After(opened) {
		return inc
	}
	sec := int64(now.Sub(opened) / time.Second)
	inc.DurationSec = sec
	inc.Stats.Cycles, inc.Stats.BadCycles = int(sec/10), int(sec/10)
	if inc.State == model.StateISPOutage {
		inc.Stats.DowntimeSec = sec
	}
	return inc
}

func (w *demoWorld) Incident(id string) (model.Incident, bool) {
	for _, inc := range w.Incidents(time.Unix(0, 0), time.Now().Add(24*time.Hour)) { // already hostile in hostile mode
		if inc.ID == id {
			return inc, true
		}
	}
	return model.Incident{}, false
}

// ----------------------------------------------------------------------------- Actions

func (w *demoWorld) Note(ctx context.Context, text, author, source string) (model.Ref, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.appendLocked(time.Now(), model.TypeOperatorNote, model.OperatorNote{Text: text, Author: author, Source: source}), nil
}

func (w *demoWorld) SetGatewayNotification(ctx context.Context, enabled bool, actor string) (model.ConfigChange, error) {
	select {
	case <-time.After(1500 * time.Millisecond): // login + two page loads on the real gateway
	case <-ctx.Done():
		return model.ConfigChange{}, ctx.Err()
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	switch {
	case w.pendingCert != "": // as internal/monitor answers (errCertPending)
		return model.ConfigChange{}, fmt.Errorf("authenticated gateway requests are paused: the gateway presented an unconfirmed TLS certificate (SHA-256 %s); confirm it with trust-cert: %w",
			w.pendingCert, contracts.ErrUnavailable)
	case w.noAccessCode:
		return model.ConfigChange{}, fmt.Errorf("check notification: gateway: no access code available: %w", contracts.ErrGatewayNoAccessCode)
	}
	now := time.Now()
	before := map[bool]string{true: "on", false: "off"}[w.notif.Enabled]
	after := map[bool]string{true: "on", false: "off"}[enabled]
	cc := model.ConfigChange{Target: "gateway", What: "events.bbevent (Broadband Status Notification)", Before: before, After: after, Actor: actor, Result: "verified"}
	if w.notifRecordEr != "" {
		return cc, errors.New(w.notifRecordEr)
	}
	r := w.appendLocked(now, model.TypeConfigChange, cc, w.page["events.before"], w.page["events.after"])
	w.appendLocked(now, model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvNotificationSetting, Before: before, After: after, Evidence: []uint64{r.Seq}})
	w.notif = model.NotificationState{Enabled: enabled, CheckedAt: now.UTC().Format(time.RFC3339Nano), Seq: r.Seq}
	return cc, nil
}

func (w *demoWorld) AnchorNow(ctx context.Context, reason string) ([]model.Anchor, error) {
	time.Sleep(600 * time.Millisecond)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.live != nil {
		return nil, fmt.Errorf("all time-stamp authorities unreachable (internet down): %s: i/o timeout; %s: i/o timeout", demoTSAs[0], demoTSAs[1])
	}
	return w.anchorLocked(time.Now(), reason), nil
}

func (w *demoWorld) RecordExport(ctx context.Context, e model.CustodyExport) (model.Ref, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.appendLocked(time.Now(), model.TypeCustodyExport, e), nil
}

// TrustCert confirms the pending gateway certificate, as internal/monitor does: it becomes
// the pin and a config_change is recorded. A reviewed fingerprint (expectedSHA256) is compared
// with the pending certificate under the lock; another one is refused (contracts.ErrBusy).
func (w *demoWorld) TrustCert(ctx context.Context, actor, expectedSHA256 string) (model.ConfigChange, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.pendingCert == "" {
		return model.ConfigChange{}, fmt.Errorf("no changed gateway certificate is waiting for confirmation: %w", contracts.ErrNotFound)
	}
	if expectedSHA256 != "" && !strings.EqualFold(expectedSHA256, w.pendingCert) {
		return model.ConfigChange{}, fmt.Errorf("gateway certificate not trusted: the certificate waiting for confirmation is SHA-256 %s, not the reviewed %s: %w",
			w.pendingCert, expectedSHA256, contracts.ErrBusy)
	}
	cc := model.ConfigChange{Target: "monitor", What: "gateway.pinned_cert_sha256 (trusted gateway TLS certificate)",
		Before: w.pinnedCert, After: w.pendingCert, Actor: actor, Result: "applied"}
	w.appendLocked(time.Now(), model.TypeConfigChange, cc)
	w.pinnedCert, w.pendingCert, w.certSeq, w.certSince = w.pendingCert, "", 0, time.Time{}
	return cc, nil
}

// setPendingCert makes the gateway present another TLS certificate: recorded as a
// cert_changed gateway_event, it waits for TrustCert (condition GATEWAY_CERT_CHANGED).
func (w *demoWorld) setPendingCert(fp string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()
	ref := w.appendLocked(now, model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvCertChanged, Before: w.pinnedCert, After: fp,
		Detail: fmt.Sprintf("gateway %s presented a TLS certificate (SHA-256 %s) different from the pinned one (%s); status pages are still read, but authenticated requests are paused until the operator confirms the new certificate (trust-cert)", demoGateway, fp, w.pinnedCert)})
	w.pendingCert, w.certSeq, w.certSince = fp, ref.Seq, now
}

// ----------------------------------------------------------------------------- LedgerReader

func (w *demoWorld) records() ([]model.Envelope, []model.Body, map[uint64]bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.envs[:len(w.envs):len(w.envs)], w.bodies[:len(w.bodies):len(w.bodies)], maps.Clone(w.unreadable)
}

// indexOf returns the index of the first record with seq >= seq (records are in seq order;
// /demo/tamper can remove one, so the index is not always the seq).
func indexOf(bodies []model.Body, seq uint64) int {
	return sort.Search(len(bodies), func(i int) bool { return bodies[i].Seq >= seq })
}

func (w *demoWorld) Scan(fromSeq uint64, fn func(model.Envelope, model.Body) error) error {
	envs, bodies, unreadable := w.records()
	for i := indexOf(bodies, fromSeq); i < len(envs); i++ {
		if unreadable[bodies[i].Seq] {
			continue
		}
		if err := fn(envs[i], bodies[i]); err != nil {
			if errors.Is(err, contracts.ErrStop) {
				return nil
			}
			return err
		}
	}
	return nil
}

func (w *demoWorld) ScanTime(from, to time.Time, fn func(model.Envelope, model.Body) error) error {
	envs, bodies, unreadable := w.records()
	for i := range envs {
		ts, _ := time.Parse(time.RFC3339Nano, bodies[i].TS)
		if ts.Before(from) || !ts.Before(to) || unreadable[bodies[i].Seq] {
			continue
		}
		if err := fn(envs[i], bodies[i]); err != nil {
			if errors.Is(err, contracts.ErrStop) {
				return nil
			}
			return err
		}
	}
	return nil
}

func (w *demoWorld) Record(seq uint64) (model.Envelope, model.Body, error) {
	envs, bodies, unreadable := w.records()
	if i := indexOf(bodies, seq); i < len(bodies) && bodies[i].Seq == seq && !unreadable[seq] {
		return envs[i], bodies[i], nil
	}
	return model.Envelope{}, model.Body{}, contracts.ErrNotFound
}

func (w *demoWorld) Segments() ([]contracts.SegmentInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []contracts.SegmentInfo
	for i, sg := range w.segs {
		out = append(out, contracts.SegmentInfo{Name: sg.name, Path: `C:\ProgramData\ATTMonitor\ledger\` + sg.name + ".jsonl", Date: sg.date,
			FirstSeq: uint64(sg.start), LastSeq: uint64(sg.end - 1), Records: sg.end - sg.start, Active: i == len(w.segs)-1})
	}
	return out, nil
}

func (w *demoWorld) OpenSegment(name string) (io.ReadCloser, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, sg := range w.segs {
		if sg.name == name {
			return io.NopCloser(bytes.NewReader(w.segmentBytesLocked(sg))), nil
		}
	}
	return nil, contracts.ErrNotFound
}

func (w *demoWorld) GetBlob(id string) ([]byte, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if b, ok := w.blobs[id]; ok {
		return b, nil
	}
	return nil, contracts.ErrNotFound
}

// ----------------------------------------------------------------------------- Verifier

// Verify really checks the demo ledger: hashes, signatures, seq/prev linkage, blobs.
func (w *demoWorld) Verify(ctx context.Context) (model.VerifyReport, error) {
	select {
	case <-time.After(700 * time.Millisecond):
	case <-ctx.Done():
		return model.VerifyReport{}, ctx.Err()
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	pub := w.key.Public().(ed25519.PublicKey)
	rep := model.VerifyReport{At: time.Now().UTC().Format(time.RFC3339Nano), Records: uint64(len(w.envs)), TypeCounts: map[string]int{}, Fingerprint: w.fingerprint()}
	prev := model.ZeroHash
	fail := func(seq uint64, problem, detail string) {
		rep.Failures = append(rep.Failures, model.VerifyFailure{Seq: seq, Segment: w.segmentOfLocked(seq), Line: int(seq) + 1, Problem: problem, Detail: detail})
	}
	for i, env := range w.envs {
		b := w.bodies[i]
		sum := sha256.Sum256([]byte(env.B))
		if hex.EncodeToString(sum[:]) != env.H {
			fail(b.Seq, "hash_mismatch", "h does not equal SHA-256(b)")
		}
		sig, _ := base64.StdEncoding.DecodeString(env.S)
		if !ed25519.Verify(pub, []byte(env.B), sig) {
			fail(b.Seq, "bad_signature", "Ed25519 signature does not verify")
		}
		if b.Seq != uint64(i) {
			fail(b.Seq, "seq_gap", "expected seq "+strconv.Itoa(i))
		}
		if b.Prev != prev {
			fail(b.Seq, "prev_mismatch", "prev does not match the previous record's h")
		}
		prev = env.H
		rep.TypeCounts[b.Type]++
		for _, id := range b.Blobs {
			rep.BlobsChecked++
			if _, ok := w.blobs[id]; !ok {
				fail(b.Seq, "blob_missing", id)
			}
		}
		if b.Type == model.TypeAnchor {
			var a model.Anchor
			json.Unmarshal(b.Data, &a)
			rep.Anchors = append(rep.Anchors, model.AnchorCheck{Seq: b.Seq, TSA: a.TSAURL, GenTime: a.GenTime, HeadSeq: a.HeadSeq, OK: true, ChainOK: true})
			rep.LastAnchoredSeq = a.HeadSeq
		}
	}
	for _, sg := range w.segs {
		rep.Segments = append(rep.Segments, sg.name)
	}
	rep.FirstTS, rep.LastTS = w.bodies[0].TS, w.bodies[len(w.bodies)-1].TS
	rep.HeadHash = w.envs[len(w.envs)-1].H
	rep.UnanchoredTail = uint64(len(w.envs)-1) - rep.LastAnchoredSeq
	if sl := w.eventByName("sleep"); sl != nil {
		rep.Gaps = append(rep.Gaps, model.Gap{From: sl.from.UTC().Format(time.RFC3339), To: sl.to.UTC().Format(time.RFC3339),
			Seconds: int64(sl.to.Sub(sl.from).Seconds()), Explanation: "system suspend (power_event suspend → resume_automatic)"})
	}
	if w.hostile != "" { // a failure whose details come from a damaged line
		fail(1, "parse_error", "line does not parse: unexpected "+w.hostile)
		// A back-dated record (rules of docs/DESIGN.md §6, "record times vs. trusted time-stamps").
		fail(2, "ts_contradiction", "record dated 2026-10-01T00:00:00Z, more than 5 min before the trusted time-stamp of #1 ("+w.hostile+")")
	}
	rep.FailuresTotal = len(rep.Failures)
	rep.OK = rep.FailuresTotal == 0
	rep.TokensChecked = true
	rep.Notes = []string{"demo data: time-stamp tokens are sample tokens and do not cover these records"}
	w.lastVerify = &model.VerifySummary{At: rep.At, OK: rep.OK, Records: rep.Records, Failures: rep.FailuresTotal}
	return hostileCopy(w.hostile, rep), nil
}

func (w *demoWorld) segmentOfLocked(seq uint64) string {
	for _, sg := range w.segs {
		if int(seq) >= sg.start && int(seq) < sg.end {
			return sg.name
		}
	}
	return ""
}

// ----------------------------------------------------------------------------- Exporter

func (w *demoWorld) Build(ctx context.Context, req contracts.ExportRequest) (contracts.ExportInfo, error) {
	select {
	case <-time.After(900 * time.Millisecond):
	case <-ctx.Done():
		return contracts.ExportInfo{}, ctx.Err()
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buildExportLocked(time.Now(), req)
}

func (w *demoWorld) buildExportLocked(now time.Time, req contracts.ExportRequest) (contracts.ExportInfo, error) {
	from, to := req.From, req.To
	if req.IncidentID != "" {
		var inc *model.Incident
		for _, p := range w.incidents {
			if p.ID == req.IncidentID {
				inc = p
			}
		}
		if inc == nil && w.liveInc != nil && w.liveInc.ID == req.IncidentID {
			inc = w.liveInc
		}
		if inc == nil {
			return contracts.ExportInfo{}, fmt.Errorf("incident %s: %w", req.IncidentID, contracts.ErrNotFound)
		}
		from, _ = time.Parse(time.RFC3339Nano, inc.Opened)
		to = now
		if c, err := time.Parse(time.RFC3339Nano, inc.Closed); err == nil {
			to = c
		}
		from, to = from.Add(-15*time.Minute), to.Add(15*time.Minute)
	}
	head := w.headLocked()
	name := fmt.Sprintf("att-evidence_%s_%s_%s.zip", from.UTC().Format("20060102T1504Z"), to.UTC().Format("20060102T1504Z"), head.Hash[:8])
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	var manifest strings.Builder
	addFile := func(n string, b []byte) {
		f, _ := zw.Create(n)
		f.Write(b)
		sum := sha256.Sum256(b)
		fmt.Fprintf(&manifest, "%x  %s\n", sum, n)
	}
	records := 0
	for _, b := range w.bodies {
		if ts, err := time.Parse(time.RFC3339Nano, b.TS); err == nil && !ts.Before(from) && ts.Before(to) {
			records++
		}
	}
	addFile("README.txt", []byte("att-monitor evidence bundle (demo)\r\nPeriod: "+from.UTC().Format(time.RFC3339)+" .. "+to.UTC().Format(time.RFC3339)+"\r\nKey fingerprint: "+w.fingerprint()+"\r\n"))
	report, _ := json.MarshalIndent(map[string]any{"from": from, "to": to, "incident": req.IncidentID, "records": records}, "", "  ")
	addFile("report.json", report)
	ms := manifest.String()
	f, _ := zw.Create("MANIFEST.sha256")
	f.Write([]byte(ms))
	zw.Close()
	data := buf.Bytes()
	sum := sha256.Sum256(data)
	msum := sha256.Sum256([]byte(ms))
	info := contracts.ExportInfo{FileName: name, Size: int64(len(data)), Created: now.UTC(), SHA256: hex.EncodeToString(sum[:]),
		ManifestSHA256: hex.EncodeToString(msum[:]), Records: records, Blobs: 6}
	ref := w.appendLocked(now, model.TypeCustodyExport, model.CustodyExport{From: from.UTC().Format(time.RFC3339), To: to.UTC().Format(time.RFC3339),
		IncidentID: req.IncidentID, FileName: name, BundleSHA256: info.SHA256, ManifestSHA256: info.ManifestSHA256, Records: records, Blobs: 6,
		PreparedBy: req.PreparedBy, Notes: req.Notes, Requester: req.Requester})
	info.CustodySeq = ref.Seq
	if w.live == nil {
		w.anchorLocked(now.Add(time.Second), "export")
	}
	w.exportData[name] = data
	w.exports = append(w.exports, info)
	return info, nil
}

func (w *demoWorld) List() ([]contracts.ExportInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return hostileCopy(w.hostile, append([]contracts.ExportInfo(nil), w.exports...)), nil
}

func (w *demoWorld) Open(name string) (io.ReadCloser, contracts.ExportInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	b, ok := w.exportData[name]
	if !ok {
		return nil, contracts.ExportInfo{}, contracts.ErrNotFound
	}
	for _, x := range w.exports {
		if x.FileName == name {
			return readSeekNopCloser{bytes.NewReader(b)}, x, nil
		}
	}
	return nil, contracts.ExportInfo{}, contracts.ErrNotFound
}

// ----------------------------------------------------------------------------- tests

const demoHost = "127.0.0.1:8399"

func newDemoServer(t *testing.T, w *demoWorld, logger *slog.Logger) *Server {
	t.Helper()
	srv, err := New(Options{Listen: demoHost, Status: w, Actions: w, Reader: w, Verifier: w, Exporter: w, Version: "demo", Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func demoGet(t *testing.T, h http.Handler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	req, err := http.NewRequest(method, "http://"+demoHost+target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "127.0.0.1:50000"
	if method == http.MethodPost {
		req.Header.Set(CSRFHeader, CSRFHeaderValue)
		req.Header.Set("Origin", "http://"+demoHost)
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestDemoWorldEndpoints exercises every endpoint with the rich demo data.
func TestDemoWorldEndpoints(t *testing.T) {
	w := newDemoWorld(time.Now())
	srv := newDemoServer(t, w, nil)
	h := srv.Handler()

	ok := func(rec *httptest.ResponseRecorder, code int) []byte {
		t.Helper()
		if rec.Code != code {
			t.Fatalf("status %d, want %d: %s", rec.Code, code, rec.Body.String())
		}
		return rec.Body.Bytes()
	}
	strict := func(b []byte, v any) {
		t.Helper()
		rv := reflect.ValueOf(v).Elem()
		rv.Set(reflect.Zero(rv.Type())) // decoding into a used struct would keep omitted fields
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if err := dec.Decode(v); err != nil {
			t.Fatalf("decode %T: %v", v, err)
		}
	}

	ok(demoGet(t, h, "GET", "/", ""), 200)
	var st model.Status
	strict(ok(demoGet(t, h, "GET", "/api/status", ""), 200), &st)
	if st.Verdict.State != model.StateOnline || st.Gateway == nil || len(st.Conditions) < 2 || len(st.Stats) != 2 {
		t.Fatalf("demo status: %+v", st.Verdict)
	}
	for _, rng := range SeriesRanges {
		var s model.Series
		strict(ok(demoGet(t, h, "GET", "/api/series?range="+rng, ""), 200), &s)
		if len(s.Points) < 60 || len(s.Optical) < 10 || len(s.Probes) != 8 {
			t.Errorf("%s: %d points, %d optical", rng, len(s.Points), len(s.Optical))
		}
	}
	var s7 model.Series
	strict(ok(demoGet(t, h, "GET", "/api/series?range=7d", ""), 200), &s7)
	states := map[string]int{}
	for _, p := range s7.Points {
		states[p.State]++
	}
	for _, want := range []string{"ONLINE", "ISP_OUTAGE", "DEGRADED", "LOCAL_FAULT", ""} {
		if states[want] == 0 {
			t.Errorf("7d series has no %q bucket: %v", want, states)
		}
	}

	if st.Verdict.Inputs == nil || st.Verdict.Inputs.SnapshotSeq == 0 || st.Verdict.Inputs.WindowCycles != 6 || len(st.Probes) != 8 {
		t.Errorf("status: verdict inputs %+v, %d probe specs", st.Verdict.Inputs, len(st.Probes))
	}
	if s := st.Stats[0]; s.ProviderOutageSec == 0 || s.DegradedSec == 0 {
		t.Errorf("24h stats without provider outage or degraded time: %+v", s)
	}

	var incs []model.Incident
	strict(ok(demoGet(t, h, "GET", "/api/incidents", ""), 200), &incs)
	if len(incs) != 8 || incs[0].Cause != model.CauseISPDNSFailure || incs[1].Cause != model.CauseFiberLinkDown {
		t.Fatalf("incidents: %d, first %+v", len(incs), incs[0].ID)
	}
	for _, inc := range incs {
		switch {
		case inc.Cause == model.CauseLocalRoute:
			// Rules 2026.10-4: traffic past the gateway is nobody's downtime.
			if inc.State != model.StateLocalFault || inc.Attribution != model.AttrUndetermined || inc.Stats.DowntimeSec != 0 || inc.RecoveredAt != "" {
				t.Errorf("VPN incident: %+v", inc)
			}
		case inc.Cause == model.CauseGatewayReboot:
			if inc.Stats.RestartSec == 0 || inc.Stats.DowntimeSec != 0 || len(inc.GatewayRestarts) != 1 || inc.RecoveredAt == "" || inc.Attribution != model.AttrUndetermined {
				t.Errorf("gateway restart incident: %+v", inc)
			}
		case inc.State == model.StateISPOutage:
			if inc.Stats.DowntimeSec == 0 || inc.RecoveredAt == "" {
				t.Errorf("%s: no downtime or recovery time: %+v", inc.ID, inc.Stats)
			}
		case inc.State == model.StateDegraded:
			if inc.Stats.DegradedSec == 0 || inc.RecoveredAt != "" {
				t.Errorf("%s: degraded time %d, recovered_at %q", inc.ID, inc.Stats.DegradedSec, inc.RecoveredAt)
			}
		}
	}
	for _, inc := range incs {
		var d IncidentDetail
		strict(ok(demoGet(t, h, "GET", "/api/incidents/"+inc.ID, ""), 200), &d)
		if len(d.Records) < 5 || len(d.Missing) != 0 || d.Incident.Closed == "" || d.Incident.Stats.Cycles == 0 {
			t.Errorf("%s: %d records, missing %v", inc.ID, len(d.Records), d.Missing)
		}
		for _, ev := range d.Incident.Evidence {
			if ev.Blob != "" {
				ok(demoGet(t, h, "GET", "/api/blobs/"+ev.Blob, ""), 200)
			}
		}
	}

	var recs []RecordView
	strict(ok(demoGet(t, h, "GET", "/api/records?limit=500", ""), 200), &recs)
	if len(recs) != 500 || recs[0].Type != model.TypeGenesis {
		t.Fatalf("records: %d, first %s", len(recs), recs[0].Type)
	}
	strict(ok(demoGet(t, h, "GET", "/api/records?type=gateway_snapshot&limit=5", ""), 200), &recs)
	var snap model.GatewaySnapshot
	var body model.Body
	if err := json.Unmarshal(recs[0].Body, &body); err != nil {
		t.Fatal(err)
	}
	strict(body.Data, &snap)
	for _, id := range body.Blobs {
		ok(demoGet(t, h, "GET", "/api/blobs/"+id+"/view", ""), 200)
	}

	var rep model.VerifyReport
	strict(ok(demoGet(t, h, "POST", "/api/verify", ""), 200), &rep)
	if !rep.OK || rep.Records == 0 || len(rep.Anchors) == 0 || len(rep.Gaps) != 1 || len(rep.Segments) < 7 {
		t.Fatalf("demo ledger does not verify: ok=%v failures=%+v segments=%d", rep.OK, rep.Failures[:min(3, len(rep.Failures))], len(rep.Segments))
	}

	var list []contracts.ExportInfo
	strict(ok(demoGet(t, h, "GET", "/api/exports", ""), 200), &list)
	if len(list) != 1 {
		t.Fatalf("exports: %d", len(list))
	}
	var info contracts.ExportInfo
	strict(ok(demoGet(t, h, "POST", "/api/exports", `{"incident_id":"`+incs[1].ID+`","prepared_by":"Demo"}`), 201), &info)
	zipBytes := ok(demoGet(t, h, "GET", "/api/exports/"+info.FileName, ""), 200)
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil || len(zr.File) != 3 {
		t.Fatalf("bundle zip: %v", err)
	}
	ok(demoGet(t, h, "POST", "/api/exports", `{"incident_id":"INC-19990101-000000Z"}`), 404)

	var ref model.Ref
	strict(ok(demoGet(t, h, "POST", "/api/notes", `{"text":"AT&T ticket 42","author":"demo"}`), 201), &ref)
	var cc model.ConfigChange
	strict(ok(demoGet(t, h, "POST", "/api/gateway/notification", `{"enabled":true}`), 200), &cc)
	strict(ok(demoGet(t, h, "GET", "/api/status", ""), 200), &st)
	if st.Notification == nil || !st.Notification.Enabled || st.Conditions[len(st.Conditions)-1].Code != "NOTIFICATION_REDIRECT_ON" {
		t.Errorf("notification not reflected: %+v", st.Notification)
	}
	var ar []model.Anchor
	strict(ok(demoGet(t, h, "POST", "/api/anchor", ""), 200), &ar)
	if len(ar) != 2 {
		t.Errorf("anchors: %+v", ar)
	}

	// A sample's verdict names the records it was computed from.
	var tail []RecordView
	strict(ok(demoGet(t, h, "GET", "/api/records?type=sample&from_seq="+strconv.FormatUint(st.Ledger.HeadSeq-120, 10)+"&limit=1", ""), 200), &tail)
	var smp struct {
		Data model.Sample `json:"data"`
	}
	if len(tail) != 1 || json.Unmarshal(tail[0].Body, &smp) != nil || smp.Data.Verdict.Inputs == nil {
		t.Fatalf("sample without verdict inputs: %+v", tail)
	}
	isRecord := func(what string, seq uint64, typ string) {
		t.Helper()
		var in []RecordView
		strict(ok(demoGet(t, h, "GET", "/api/records?limit=1&from_seq="+strconv.FormatUint(seq, 10), ""), 200), &in)
		if seq == 0 || len(in) != 1 || in[0].Seq != seq || in[0].Type != typ {
			t.Errorf("%s #%d is not a %s record", what, seq, typ)
		}
	}
	for seq, typ := range map[uint64]string{smp.Data.Verdict.Inputs.SnapshotSeq: model.TypeGatewaySnapshot,
		smp.Data.Verdict.Inputs.ServiceCheckSeq: model.TypeServiceCheck, smp.Data.Verdict.Inputs.LocalLinkSeq: model.TypeLocalLink} {
		isRecord("verdict input", seq, typ)
	}
	// Rules 2026.10-4: the AT&T DNS incident's first cycle names the earlier service check the
	// DNS rule compared with and the two snapshots of the household's WAN traffic, in order.
	var first []RecordView
	strict(ok(demoGet(t, h, "GET", "/api/records?limit=1&from_seq="+strconv.FormatUint(incs[0].FirstSeq, 10), ""), 200), &first)
	var dnsSmp struct {
		Data model.Sample `json:"data"`
	}
	if len(first) != 1 || json.Unmarshal(first[0].Body, &dnsSmp) != nil || dnsSmp.Data.Verdict.Inputs == nil {
		t.Fatalf("DNS incident's first record: %+v", first)
	}
	if in := dnsSmp.Data.Verdict.Inputs; dnsSmp.Data.Verdict.Cause != model.CauseISPDNSFailure || dnsSmp.Data.Verdict.Attribution != model.AttrProvider ||
		in.PrevServiceCheckSeq >= in.ServiceCheckSeq || in.TrafficFromSeq >= in.TrafficToSeq || in.TrafficToSeq != in.SnapshotSeq {
		t.Errorf("DNS incident's first verdict: %+v inputs %+v", dnsSmp.Data.Verdict, in)
	} else {
		isRecord("previous service check", in.PrevServiceCheckSeq, model.TypeServiceCheck)
		isRecord("traffic from", in.TrafficFromSeq, model.TypeGatewaySnapshot)
		isRecord("traffic to", in.TrafficToSeq, model.TypeGatewaySnapshot)
	}

	// Syslog (docs/syslog-snmp-traffic.md §3.2): the receiver's status and the latest check of the
	// gateway's setting; the messages newest first; the window of an incident (± 5 min, as the
	// incident page asks) holds the gateway's own account of it, or nothing.
	if sl := st.Syslog; sl == nil || !sl.Listening || sl.State != "ok" || sl.Received == 0 || sl.Gateway == nil || !sl.Gateway.Enabled || sl.LastAt == "" {
		t.Errorf("syslog status: %+v", st.Syslog)
	} else {
		isRecord("syslog setting check", sl.GatewaySeq, model.TypeGatewayEvent)
	}
	var sl model.SyslogList
	strict(ok(demoGet(t, h, "GET", "/api/syslog", ""), 200), &sl)
	if len(sl.Messages) != DefaultSyslogLimit || !sl.Truncated {
		t.Errorf("syslog: %d messages, truncated %v", len(sl.Messages), sl.Truncated)
	}
	var prevRX time.Time
	for i, m := range sl.Messages {
		rx, err := time.Parse(time.RFC3339Nano, m.RX)
		if err != nil || (i > 0 && rx.After(prevRX)) {
			t.Fatalf("syslog message %d received %q, after %v: not newest first", i, m.RX, prevRX)
		}
		prevRX = rx
	}
	isRecord("syslog batch", sl.Messages[0].Seq, model.TypeSyslog)
	window := func(inc model.Incident, extra string) model.SyslogList {
		t.Helper()
		opened, err1 := time.Parse(time.RFC3339Nano, inc.Opened)
		closed, err2 := time.Parse(time.RFC3339Nano, inc.Closed)
		if err1 != nil || err2 != nil {
			t.Fatalf("incident %s: opened %q closed %q", inc.ID, inc.Opened, inc.Closed)
		}
		q := "from=" + opened.Add(-5*time.Minute).UTC().Format(time.RFC3339Nano) + "&to=" + closed.Add(5*time.Minute).UTC().Format(time.RFC3339Nano) + extra
		var list model.SyslogList
		strict(ok(demoGet(t, h, "GET", "/api/syslog?"+q, ""), 200), &list)
		return list
	}
	msgs := func(list model.SyslogList) []string {
		var out []string
		for _, m := range list.Messages {
			out = append(out, m.App+": "+m.Msg)
		}
		return out
	}
	byCause := map[string]model.Incident{}
	for _, inc := range incs {
		byCause[inc.Cause] = inc
	}
	fiberLog := msgs(window(byCause[model.CauseFiberLinkDown], ""))
	for _, want := range []string{"ponlinkd: PON link state O5 -> O1 (loss of signal)", "ponlinkd: PON link state O1 -> O5 (operation)"} {
		if !slices.Contains(fiberLog, want) {
			t.Errorf("the fiber outage's syslog lacks %q: %q", want, fiberLog)
		}
	}
	if crit := msgs(window(byCause[model.CauseFiberLinkDown], "&severity=crit")); len(crit) != 2 {
		t.Errorf("the fiber outage's critical messages: %q", crit)
	}
	if quiet := window(byCause[model.CauseHighLatency], ""); len(quiet.Messages) != 0 {
		t.Errorf("the high-latency incident's window holds messages: %q", msgs(quiet))
	}

	// Traffic (docs/syslog-snmp-traffic.md §3.3): a point per bucket; unknown where nothing could
	// be read; the big download "at least"; the days with complete and partial totals.
	for _, rng := range SeriesRanges {
		var s model.Series
		strict(ok(demoGet(t, h, "GET", "/api/series?range="+rng, ""), 200), &s)
		if len(s.Traffic) != len(s.Points) || s.HeavyTrafficMbps != 80 || len(s.TrafficDays) == 0 {
			t.Errorf("%s: %d traffic points for %d buckets, heavy-traffic line %v, %d days", rng, len(s.Traffic), len(s.Points), s.HeavyTrafficMbps, len(s.TrafficDays))
		}
	}
	var known, unknown, atLeast int
	for _, p := range s7.Traffic {
		switch {
		case p.WANRx == nil:
			unknown++
		case p.AtLeast:
			atLeast++
		default:
			known++
			if *p.WANRxPeak < *p.WANRx || p.PCRx == nil {
				t.Errorf("traffic point %+v", p)
			}
		}
	}
	complete, partial := 0, 0
	for _, d := range s7.TrafficDays {
		if _, err := time.Parse(time.DateOnly, d.Day); err != nil || d.RxBytes <= 0 || d.CoveredS <= 0 {
			t.Errorf("traffic day %+v", d)
		}
		if d.Complete {
			complete++
		} else {
			partial++
		}
	}
	if known == 0 || unknown == 0 || atLeast == 0 || complete == 0 || partial == 0 {
		t.Errorf("7d traffic: %d known, %d unknown, %d at least; days %d complete, %d partial", known, unknown, atLeast, complete, partial)
	}

	// Gateway certificate (docs/DESIGN.md §2): nothing pending is a 404; a changed certificate
	// shows the condition, citing its cert_changed record, and the certificate state the
	// dashboard draws from (Status.GatewayCert), and pauses authenticated actions; a
	// confirmation of another fingerprint is refused; confirming the shown one pins it.
	var er ErrorResponse
	if gc := st.GatewayCert; gc == nil || *gc != (model.GatewayCertState{Pinned: demoCertSHA}) {
		t.Errorf("certificate state with nothing pending: %+v", gc)
	}
	strict(ok(demoGet(t, h, "POST", "/api/gateway/trust-cert", `{}`), 404), &er)
	w.setPendingCert(demoNewCertSHA)
	strict(ok(demoGet(t, h, "GET", "/api/status", ""), 200), &st)
	ci := slices.IndexFunc(st.Conditions, func(c model.Condition) bool { return c.Code == condGatewayCertChanged })
	if ci < 0 || st.Conditions[ci].Seq == 0 || st.Conditions[ci].Severity != "critical" {
		t.Fatalf("no GATEWAY_CERT_CHANGED condition with its record: %+v", st.Conditions)
	}
	if gc, cond := st.GatewayCert, st.Conditions[ci]; gc == nil || cond.Since == "" ||
		*gc != (model.GatewayCertState{Pinned: demoCertSHA, Pending: demoNewCertSHA, Since: cond.Since, Seq: cond.Seq}) {
		t.Errorf("certificate state %+v does not match the condition %+v", gc, cond)
	}
	var certRec []RecordView
	strict(ok(demoGet(t, h, "GET", "/api/records?limit=1&from_seq="+strconv.FormatUint(st.Conditions[ci].Seq, 10), ""), 200), &certRec)
	var certEv struct {
		Data model.GatewayEvent `json:"data"`
	}
	if len(certRec) != 1 || json.Unmarshal(certRec[0].Body, &certEv) != nil || certEv.Data.Kind != model.GwEvCertChanged ||
		certEv.Data.Before != demoCertSHA || certEv.Data.After != demoNewCertSHA {
		t.Fatalf("condition record: %+v", certEv)
	}
	var ce ConfigChangeError
	strict(ok(demoGet(t, h, "POST", "/api/gateway/notification", `{"enabled":false}`), 503), &ce)
	if !strings.Contains(ce.Error, "trust-cert") {
		t.Errorf("notification while the certificate is unconfirmed: %q", ce.Error)
	}
	strict(ok(demoGet(t, h, "POST", "/api/gateway/trust-cert", `{"sha256":"`+demoCertSHA+`"}`), 409), &er)
	if !strings.Contains(er.Error, "now SHA-256 "+demoNewCertSHA) {
		t.Errorf("refused confirmation: %q", er.Error)
	}
	// Without the certificate state in the status the monitor itself refuses, under its lock.
	w.mu.Lock()
	w.noGatewayCert = true
	w.mu.Unlock()
	strict(ok(demoGet(t, h, "POST", "/api/gateway/trust-cert", `{"sha256":"`+demoCertSHA+`"}`), 409), &er)
	if !strings.Contains(er.Error, "not the one you reviewed (SHA-256 "+demoCertSHA+")") {
		t.Errorf("confirmation refused by the monitor: %q", er.Error)
	}
	w.mu.Lock()
	w.noGatewayCert = false
	w.mu.Unlock()
	strict(ok(demoGet(t, h, "POST", "/api/gateway/trust-cert", `{"sha256":"`+demoNewCertSHA+`"}`), 200), &cc)
	if cc.Before != demoCertSHA || cc.After != demoNewCertSHA || cc.Actor != "operator via web" || cc.Result != "applied" {
		t.Errorf("trust-cert change = %+v", cc)
	}
	strict(ok(demoGet(t, h, "GET", "/api/status", ""), 200), &st)
	if slices.ContainsFunc(st.Conditions, func(c model.Condition) bool { return c.Code == condGatewayCertChanged }) {
		t.Error("certificate condition still shown after the confirmation")
	}
	if gc := st.GatewayCert; gc == nil || *gc != (model.GatewayCertState{Pinned: demoNewCertSHA}) {
		t.Errorf("certificate state after the confirmation: %+v", gc)
	}
	strict(ok(demoGet(t, h, "POST", "/api/gateway/trust-cert", ``), 404), &er)

	// Every daily segment after the first opens with the configuration in force.
	strict(ok(demoGet(t, h, "GET", "/api/records?type=segment_open,config_state&limit=500", ""), 200), &recs)
	if len(recs) < 12 || len(recs)%2 != 0 {
		t.Fatalf("segment_open/config_state records: %d", len(recs))
	}
	for i := 0; i < len(recs); i += 2 {
		var cs struct {
			Data model.ConfigState `json:"data"`
		}
		if recs[i].Type != model.TypeSegmentOpen || recs[i+1].Type != model.TypeConfigState || recs[i+1].Seq != recs[i].Seq+1 ||
			json.Unmarshal(recs[i+1].Body, &cs) != nil || cs.Data.Rules != demoRules || cs.Data.ConfigSHA256 != demoConfigSHA || len(cs.Data.Config) == 0 {
			t.Fatalf("records #%d/#%d: %s %s %+v", recs[i].Seq, recs[i+1].Seq, recs[i].Type, recs[i+1].Type, cs.Data)
		}
	}

	// Live outage and recovery.
	w.setOutage(true)
	strict(ok(demoGet(t, h, "GET", "/api/status", ""), 200), &st)
	if st.Verdict.State != model.StateISPOutage || st.ActiveIncident == nil || !st.ActiveIncident.Open || st.Gateway.Derived.BroadbandUp == nil || *st.Gateway.Derived.BroadbandUp {
		t.Fatalf("outage status: %+v", st.Verdict)
	}
	var anchorErr ErrorResponse
	strict(ok(demoGet(t, h, "POST", "/api/anchor", ""), 502), &anchorErr)
	if !strings.Contains(anchorErr.Error, "unreachable") {
		t.Errorf("offline anchor error = %q", anchorErr.Error)
	}
	w.setOutage(false)
	strict(ok(demoGet(t, h, "GET", "/api/status", ""), 200), &st)
	if st.Verdict.State != model.StateOnline || st.ActiveIncident != nil {
		t.Fatalf("after recovery: %+v", st.Verdict)
	}
	strict(ok(demoGet(t, h, "GET", "/api/incidents", ""), 200), &incs)
	if len(incs) != 9 || incs[0].Open {
		t.Fatalf("incidents after recovery: %d", len(incs))
	}
	strict(ok(demoGet(t, h, "POST", "/api/verify", ""), 200), &rep)
	if !rep.OK {
		t.Fatalf("ledger does not verify after actions: %+v", rep.Failures)
	}
}

// TestDemoServer serves the dashboard with demo data for manual/visual checks.
func TestDemoServer(t *testing.T) {
	if os.Getenv("ATTMON_WEB_DEMO") != "1" {
		t.Skip("set ATTMON_WEB_DEMO=1 to serve the dashboard with demo data on http://" + demoHost + "/")
	}
	dur := 30 * time.Minute
	if v := os.Getenv("ATTMON_WEB_DEMO_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			dur = time.Duration(n) * time.Second
		}
	}
	hostile := ""
	if os.Getenv("ATTMON_WEB_DEMO_HOSTILE") == "1" {
		hostile = hostileMarker
	}
	w := newDemoWorldWith(time.Now(), hostile)
	if os.Getenv("ATTMON_WEB_DEMO_STATE") == "outage" {
		w.setOutage(true)
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	srv := newDemoServer(t, w, logger)
	ctx, cancel := context.WithTimeout(context.Background(), dur)
	defer cancel()

	mux := http.NewServeMux()
	mux.HandleFunc("/demo/state", func(rw http.ResponseWriter, r *http.Request) {
		w.setOutage(r.URL.Query().Get("s") == "outage")
		fmt.Fprintln(rw, "ok")
	})
	// /demo/flags adds gateway DMI flags for the other measures (laser bias, supply voltage).
	mux.HandleFunc("/demo/flags", func(rw http.ResponseWriter, r *http.Request) {
		w.mu.Lock()
		w.extraConds = []model.Condition{
			{Code: "TX_BIAS_HIGH_WARNING", Severity: "warning", Message: "AT&T gateway reports laser bias current 41 mA, above its warning threshold 40 mA", Seq: 412},
			{Code: "VCC_LOW_ALARM", Severity: "critical", Message: "AT&T gateway reports optical module supply voltage 2 V, below its alarm threshold 3 V", Seq: 412},
		}
		w.mu.Unlock()
		fmt.Fprintln(rw, "ok")
	})
	// /demo/tamper?seq=N edits the body of record N without updating its h and makes record
	// N+2 unreadable, as an altered ledger looks to the records browser.
	mux.HandleFunc("/demo/tamper", func(rw http.ResponseWriter, r *http.Request) {
		n, err := strconv.Atoi(r.URL.Query().Get("seq"))
		w.mu.Lock()
		defer w.mu.Unlock()
		if err != nil || n < 1 || n+2 >= len(w.envs) {
			http.Error(rw, "bad seq", http.StatusBadRequest)
			return
		}
		// Copy first: readers may hold the old slices.
		w.envs, w.bodies = slices.Clone(w.envs), slices.Clone(w.bodies)
		w.bodies[n].Data = json.RawMessage(`{"edited":"after the fact"}`)
		nb, _ := json.Marshal(w.bodies[n])
		w.envs[n].B = string(nb)
		if w.unreadable == nil {
			w.unreadable = map[uint64]bool{}
		}
		w.unreadable[uint64(n+2)] = true
		fmt.Fprintln(rw, "ok")
	})
	// /demo/notiffail makes the next gateway setting change succeed on the gateway but fail
	// to be recorded (?off=1 restores normal behaviour).
	mux.HandleFunc("/demo/notiffail", func(rw http.ResponseWriter, r *http.Request) {
		w.mu.Lock()
		w.notifRecordEr = "ledger: append config_change: The disk is full."
		if r.URL.Query().Get("off") == "1" {
			w.notifRecordEr = ""
		}
		w.mu.Unlock()
		fmt.Fprintln(rw, "ok")
	})
	// /demo/cert makes the gateway present a changed TLS certificate (GATEWAY_CERT_CHANGED).
	mux.HandleFunc("/demo/cert", func(rw http.ResponseWriter, r *http.Request) {
		w.setPendingCert(demoNewCertSHA)
		fmt.Fprintln(rw, "ok")
	})
	// /demo/noaccess and /demo/anchoruntrusted show the NO_ACCESS_CODE and ANCHOR_UNTRUSTED
	// conditions (?off=1 hides them again).
	mux.HandleFunc("/demo/noaccess", func(rw http.ResponseWriter, r *http.Request) {
		w.mu.Lock()
		w.noAccessCode = r.URL.Query().Get("off") != "1"
		w.mu.Unlock()
		fmt.Fprintln(rw, "ok")
	})
	mux.HandleFunc("/demo/anchoruntrusted", func(rw http.ResponseWriter, r *http.Request) {
		w.mu.Lock()
		w.anchorUntrusted = r.URL.Query().Get("off") != "1"
		w.mu.Unlock()
		fmt.Fprintln(rw, "ok")
	})
	// /demo/dnshijack makes the gateway's resolver answer the .invalid hijack test with its own
	// address in the live status (?off=1 restores NXDOMAIN).
	mux.HandleFunc("/demo/dnshijack", func(rw http.ResponseWriter, r *http.Request) {
		w.mu.Lock()
		w.dnsHijack = r.URL.Query().Get("off") != "1"
		w.mu.Unlock()
		fmt.Fprintln(rw, "ok")
	})
	// /demo/vpn makes a VPN take this computer's internet routes (live LOCAL_ROUTE incident,
	// EGRESS_NOT_VIA_GATEWAY; ?off=1 ends it).
	mux.HandleFunc("/demo/vpn", func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("off") == "1" {
			w.setLive("")
		} else {
			w.setLive(liveVPN)
		}
		fmt.Fprintln(rw, "ok")
	})
	// /demo/stale makes the monitor record no cycle: UNKNOWN with its reason, LEDGER_WRITE_FAILING
	// and DISK_SPACE_LOW (?off=1 restores normal behaviour).
	mux.HandleFunc("/demo/stale", func(rw http.ResponseWriter, r *http.Request) {
		w.mu.Lock()
		w.stale = r.URL.Query().Get("off") != "1"
		w.mu.Unlock()
		fmt.Fprintln(rw, "ok")
	})
	// /demo/dnsretry loses the live AT&T resolver query: the retry answers (?failed=1: it gets
	// no answer either; ?off=1 restores normal behaviour).
	mux.HandleFunc("/demo/dnsretry", func(rw http.ResponseWriter, r *http.Request) {
		w.mu.Lock()
		switch {
		case r.URL.Query().Get("off") == "1":
			w.liveDNSRetry = ""
		case r.URL.Query().Get("failed") == "1":
			w.liveDNSRetry = "failed"
		default:
			w.liveDNSRetry = "answered"
		}
		w.mu.Unlock()
		fmt.Fprintln(rw, "ok")
	})
	// /demo/syslog?state=off|elsewhere|error|unknown|enforce|nolisten|disabled|none shows the
	// gateway syslog card in that state (no state: the gateway sends here).
	mux.HandleFunc("/demo/syslog", func(rw http.ResponseWriter, r *http.Request) {
		w.mu.Lock()
		w.syslogState = r.URL.Query().Get("state")
		w.mu.Unlock()
		fmt.Fprintln(rw, "ok")
	})
	// /demo/clock shows the CLOCK_OFFSET condition (?off=1 hides it, with the other extra flags).
	mux.HandleFunc("/demo/clock", func(rw http.ResponseWriter, r *http.Request) {
		w.mu.Lock()
		w.extraConds = nil
		if r.URL.Query().Get("off") != "1" {
			w.extraConds = []model.Condition{demoClockCondition(time.Now())}
		}
		w.mu.Unlock()
		fmt.Fprintln(rw, "ok")
	})
	mux.HandleFunc("/demo/quit", func(rw http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(rw, "bye")
		cancel()
	})
	mux.Handle("/", srv.Handler())
	ln, err := net.Listen("tcp", demoHost)
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go hs.Serve(ln)
	t.Logf("demo dashboard on http://%s/ for %v (GET /demo/quit to stop)", demoHost, dur)
	<-ctx.Done()
	shCtx, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	hs.Shutdown(shCtx)
}
