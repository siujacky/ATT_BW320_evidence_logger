package web

// The demo world's Network page (docs/syslog-map-graphic.md, docs/dhcp-table.md): a household of
// sixteen devices in the gateway's Device List (read every 15 minutes: who held which address, on
// or off; swept by a LAN scan every hour) and the gateway itself, the organisations and services
// they reach (samples of the NAT
// table every 4 minutes since the ledger started), and what the gateway's firewall drops, hour by
// hour, as long as the syslog store keeps it. Everything is computed from the time,
// deterministically (noise), so that a period shows the same data each time it is asked for, and it
// follows the rest of the world: no read while the PC slept, no Internet traffic while the line was
// down, no Device List read while the gateway restarted, no connection of a device that is off.
//
// Only documentation values are used: LAN 192.168.1.x, MAC 00:00:5e:00:53:xx, IPv6
// 2001:db8::/32, remote addresses in 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24;
// organisations are well-known companies.
//
// /demo/network?state=... (TestDemoServer) shows the page's other states: off (sampling turned
// off), paused (logins paused), noaccess (no access code), nosamples (no read yet), natnote (reads
// that work but leave rows out), busy (more connections than the store counts one by one), noipdb
// (the IP database not loaded), nosyslog (no syslog store: the firewall view is unavailable, as
// netmap's is, and the Devices tab counts nothing as blocked), nodrops (nothing dropped), cfgwarn
// (settings in config.json replaced), nodevices (no Device List read yet), noscans (the LAN scans
// turned off), panel (devices that are off listed with the addresses of others), fixedguest (a
// device with a fixed address answers the scans at an address the reads give to others),
// stalescan (no LAN scan in the last 2 hours) and unavailable (the views fail).

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"math"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

var _ contracts.NetworkView = (*demoWorld)(nil)

// demoNATEvery is the demo's NAT table read interval (connections.interval).
const demoNATEvery = 4 * time.Minute

// demoNetDevice is a device of the household's NAT samples, with the hours it is used. lan is its
// entry in demoLAN, the gateway's Device List (-1: none - the gateway itself, or an address the
// Device List never names): its connections are open only while the Device List shows it on.
type demoNetDevice struct {
	key, name, ipv4, mac, conn string
	// active is how busy the device is at a local hour (0-1).
	active func(hour int) float64
	lan    int
}

// netDev is the NAT samples' device of the Device List's entry lan: its key, name, MAC, connection
// and newest IPv4 address.
func netDev(lan int, active func(hour int) float64) demoNetDevice {
	d := demoLAN[lan]
	return demoNetDevice{key: d.key, name: d.name, ipv4: d.addrs[len(d.addrs)-1].addr, mac: d.mac, conn: d.conn, active: active, lan: lan}
}

// busyHours is a device busy (in) from the local hour from to the hour to, otherwise out.
func busyHours(from, to int, in, out float64) func(int) float64 {
	return func(h int) float64 {
		if (from <= to && h >= from && h < to) || (from > to && (h >= from || h < to)) {
			return in
		}
		return out
	}
}

// demoNetDevices: this PC (the demo's syslog target, 192.168.1.71, on Wi-Fi as its link card
// says) first; the household's other devices; the gateway's own connections (key "gateway"); then
// the devices added with the Device List (docs/dhcp-table.md) - their flows come after the
// gateway's in demoNetUses, so that the remote addresses of the flows before keep theirs - and a
// device the Device List never names (192.168.1.90: its key is its address).
var demoNetDevices = []demoNetDevice{
	netDev(0, busyHours(8, 19, 1, 0.12)),    // Office PC
	netDev(1, busyHours(9, 23, 0.7, 0.05)),  // Laptop
	netDev(2, busyHours(7, 24, 0.9, 0.35)),  // Phone
	netDev(3, busyHours(18, 24, 1, 0.03)),   // Living room TV
	netDev(4, busyHours(16, 22, 0.8, 0.04)), // Tablet
	netDev(5, busyHours(0, 24, 0.12, 0.12)), // Printer
	netDev(6, busyHours(19, 23, 0.8, 0.03)), // Game console
	netDev(7, busyHours(0, 24, 0.6, 0.6)),   // Smart speaker
	{key: "gateway", name: "Gateway", active: busyHours(0, 24, 0.5, 0.5), lan: -1},
	netDev(8, busyHours(0, 24, 0.5, 0.5)),    // Thermostat
	netDev(10, busyHours(0, 24, 0.9, 0.9)),   // Guest phone (on for three hours yesterday)
	netDev(11, busyHours(20, 23, 0.6, 0.05)), // E-reader (off for three days)
	netDev(13, busyHours(15, 21, 0.9, 0.1)),  // Kids tablet
	netDev(14, busyHours(1, 5, 0.9, 0.1)),    // NAS (its backups at night)
	netDev(15, busyHours(0, 24, 0.7, 0.7)),   // Doorbell
	netDev(16, busyHours(0, 24, 0.8, 0.8)),   // Visitor laptop (five days ago; no longer listed)
	{key: "ip:" + demoUnlistedNAT, name: "", ipv4: demoUnlistedNAT, active: busyHours(0, 24, 0.4, 0.4), lan: -1},
}

// The two LAN addresses no Device List read names: one seen in the NAT samples, one only in the
// firewall's drops (an old camera with a static address that the gateway does not list, whose
// late packets to its server the firewall drops every evening).
const (
	demoUnlistedNAT = "192.168.1.90"
	demoUnlistedFw  = "192.168.1.201"
)

// demoNetOrg is an organisation (an AS) of the demo's IP database.
type demoNetOrg struct {
	asn                   int
	name, asName, country string
	// ptr makes the reverse DNS name of the organisation's n-th address ("" = none).
	ptr func(addr string, n int) string
}

func dashed(addr string) string { return strings.ReplaceAll(addr, ".", "-") }

var demoNetOrgs = []demoNetOrg{
	{15169, "Google", "GOOGLE", "US", func(a string, n int) string { return fmt.Sprintf("lga%02ds%02d-in-f%d.1e100.net", 25+n, 70+n, 4+n) }},
	{8075, "Microsoft", "MICROSOFT-CORP-MSN-AS-BLOCK", "US", nil},
	{16509, "Amazon", "AMAZON-02", "US", func(a string, n int) string { return "server-" + dashed(a) + ".lga50.r.cloudfront.net" }},
	{13335, "Cloudflare", "CLOUDFLARENET", "US", nil},
	{20940, "Akamai", "AKAMAI-ASN1", "NL", func(a string, n int) string { return "a" + dashed(a) + ".deploy.static.akamaitechnologies.com" }},
	{32934, "Meta", "FACEBOOK", "US", func(a string, n int) string { return fmt.Sprintf("edge-star-mini-shv-%02d-lga5.facebook.com", n+1) }},
	{714, "Apple", "APPLE-ENGINEERING", "US", nil},
	{2906, "Netflix", "AS-SSI", "US", func(a string, n int) string { return fmt.Sprintf("ipv4-c%03d-lga001-ix.1.oca.nflxvideo.net", 21+n) }},
	{54113, "Fastly", "FASTLY", "US", nil},
	{32590, "Valve", "VALVE-CORPORATION", "US", nil},
	{8403, "Spotify", "SPOTIFY", "SE", nil},
	{30103, "Zoom", "ZOOM-VIDEO-COMM-AS", "US", nil},
	{7018, "AT&T", "ATT-INTERNET4", "US", nil},
	{16276, "OVH", "OVH", "FR", nil},
	{24940, "Hetzner Online", "HETZNER-AS", "DE", nil},
	{2914, "NTT", "NTT-LTD-2914", "JP", nil},
	{71, "HP", "HP-INTERNET-AS", "US", nil},
	// Google's second AS: the IP database names it Google too, so the flow diagram shows one
	// Google, whose tooltip lists both ASes (netmap's orgKey).
	{36040, "Google", "YOUTUBE", "US", nil},
}

// demoNetUse is how a device uses an organisation: n remote addresses, a protocol and port, the
// chance of each being open at a read while the device is busy, the sessions it holds then.
type demoNetUse struct {
	org     int // index in demoNetOrgs; -1: an address the IP database does not know
	n       int
	proto   string
	port    int
	p       float64
	sess    int
	country string // "" = the organisation's
	inbound bool   // opened from the Internet (a port forward): port is the device's
}

// demoNetUses lists, per device of demoNetDevices, what it connects to.
var demoNetUses = [][]demoNetUse{
	{ // Office PC
		{org: 1, n: 3, proto: "tcp", port: 443, p: 0.9, sess: 3}, {org: 0, n: 3, proto: "udp", port: 443, p: 0.6, sess: 2},
		{org: 0, n: 2, proto: "tcp", port: 443, p: 0.5, sess: 2}, {org: 2, n: 2, proto: "tcp", port: 443, p: 0.3, sess: 1},
		{org: 3, n: 3, proto: "tcp", port: 443, p: 0.35, sess: 1}, {org: 4, n: 2, proto: "tcp", port: 443, p: 0.3, sess: 1},
		{org: 11, n: 1, proto: "udp", port: 3478, p: 0.15, sess: 1}, {org: 14, n: 1, proto: "tcp", port: 22, p: 0.2, sess: 1},
		{org: 3, n: 1, proto: "tcp", port: 853, p: 0.6, sess: 1}, {org: 1, n: 1, proto: "tcp", port: 443, p: 0.4, sess: 1, country: "IE"},
	},
	{ // Laptop
		{org: 0, n: 3, proto: "tcp", port: 443, p: 0.7, sess: 2}, {org: 1, n: 2, proto: "tcp", port: 443, p: 0.4, sess: 1},
		{org: 5, n: 2, proto: "tcp", port: 443, p: 0.35, sess: 1}, {org: 3, n: 2, proto: "tcp", port: 443, p: 0.3, sess: 1},
		{org: 6, n: 1, proto: "tcp", port: 443, p: 0.2, sess: 1}, {org: 13, n: 1, proto: "tcp", port: 443, p: 0.1, sess: 1},
		{org: -1, n: 1, proto: "tcp", port: 8443, p: 0.05, sess: 1}, {org: 0, n: 1, proto: "tcp", port: 443, p: 0.2, sess: 1, country: "IE"},
	},
	{ // Phone
		{org: 0, n: 2, proto: "tcp", port: 443, p: 0.5, sess: 1}, {org: 5, n: 3, proto: "tcp", port: 443, p: 0.6, sess: 2},
		{org: 6, n: 2, proto: "tcp", port: 5223, p: 0.8, sess: 1}, {org: 6, n: 1, proto: "tcp", port: 443, p: 0.4, sess: 1},
		{org: 2, n: 1, proto: "tcp", port: 443, p: 0.1, sess: 1}, {org: 3, n: 1, proto: "udp", port: 443, p: 0.15, sess: 1},
		{org: 0, n: 1, proto: "udp", port: 123, p: 0.1, sess: 1}, {org: 5, n: 1, proto: "tcp", port: 443, p: 0.2, sess: 1, country: "IE"},
	},
	{ // Living room TV
		{org: 7, n: 3, proto: "tcp", port: 443, p: 0.9, sess: 4}, {org: 2, n: 2, proto: "tcp", port: 443, p: 0.5, sess: 2},
		{org: 4, n: 2, proto: "tcp", port: 443, p: 0.3, sess: 1, country: "US"}, {org: 0, n: 1, proto: "tcp", port: 443, p: 0.3, sess: 1},
		{org: 2, n: 1, proto: "tcp", port: 443, p: 0.2, sess: 1, country: "DE"},
	},
	{ // Tablet
		{org: 0, n: 2, proto: "tcp", port: 443, p: 0.5, sess: 1}, {org: 2, n: 1, proto: "tcp", port: 443, p: 0.2, sess: 1, country: "SG"},
		{org: 6, n: 1, proto: "tcp", port: 443, p: 0.2, sess: 1}, {org: 8, n: 1, proto: "tcp", port: 443, p: 0.2, sess: 1},
		{org: 4, n: 1, proto: "tcp", port: 443, p: 0.15, sess: 1, country: "HK"},
	},
	{ // Printer
		{org: 16, n: 1, proto: "tcp", port: 443, p: 0.5, sess: 1}, {org: 0, n: 1, proto: "udp", port: 123, p: 0.3, sess: 1},
	},
	{ // Game console
		{org: 9, n: 2, proto: "tcp", port: 443, p: 0.6, sess: 2}, {org: 9, n: 1, proto: "udp", port: 27015, p: 0.5, sess: 1},
		{org: 15, n: 1, proto: "udp", port: 3074, p: 0.3, sess: 1}, {org: 1, n: 1, proto: "tcp", port: 443, p: 0.3, sess: 1},
		{org: 2, n: 1, proto: "udp", port: 3074, p: 0.2, sess: 1, inbound: true, country: "GB"},
	},
	{ // Smart speaker
		{org: 10, n: 2, proto: "tcp", port: 443, p: 0.7, sess: 1}, {org: 2, n: 1, proto: "tcp", port: 443, p: 0.4, sess: 1},
		{org: 0, n: 1, proto: "udp", port: 123, p: 0.2, sess: 1}, {org: 3, n: 1, proto: "udp", port: 53, p: 0.3, sess: 1},
		{org: 17, n: 1, proto: "tcp", port: 443, p: 0.5, sess: 1},
	},
	{ // the gateway itself: AT&T's management server and time
		{org: 12, n: 1, proto: "tcp", port: 443, p: 0.5, sess: 1}, {org: 12, n: 1, proto: "udp", port: 123, p: 0.3, sess: 1},
	},
	{ // Thermostat
		{org: 0, n: 1, proto: "tcp", port: 443, p: 0.6, sess: 1},
	},
	{ // Guest phone
		{org: 5, n: 2, proto: "tcp", port: 443, p: 0.6, sess: 1}, {org: 0, n: 1, proto: "tcp", port: 443, p: 0.5, sess: 1},
		{org: 6, n: 1, proto: "tcp", port: 5223, p: 0.7, sess: 1},
	},
	{ // E-reader
		{org: 2, n: 1, proto: "tcp", port: 443, p: 0.5, sess: 1},
	},
	{ // Kids tablet
		{org: 17, n: 2, proto: "tcp", port: 443, p: 0.7, sess: 2}, {org: 0, n: 1, proto: "udp", port: 443, p: 0.5, sess: 1},
		{org: 13, n: 1, proto: "tcp", port: 443, p: 0.2, sess: 1},
	},
	{ // NAS
		{org: 2, n: 2, proto: "tcp", port: 443, p: 0.6, sess: 2}, {org: 0, n: 1, proto: "udp", port: 123, p: 0.1, sess: 1},
	},
	{ // Doorbell
		{org: 2, n: 1, proto: "tcp", port: 443, p: 0.8, sess: 1}, {org: 2, n: 1, proto: "udp", port: 3478, p: 0.2, sess: 1},
	},
	{ // Visitor laptop
		{org: 1, n: 2, proto: "tcp", port: 443, p: 0.6, sess: 1}, {org: 11, n: 1, proto: "udp", port: 3478, p: 0.4, sess: 1},
	},
	{ // 192.168.1.90, which the Device List never names
		{org: 2, n: 1, proto: "tcp", port: 8883, p: 0.7, sess: 1}, {org: 3, n: 1, proto: "udp", port: 53, p: 0.2, sess: 1},
	},
}

// demoServices names the ports the demo's flows use, as the IP database's port table would.
var demoServices = map[string]string{
	"tcp/443": "HTTPS", "udp/443": "QUIC", "udp/53": "DNS", "tcp/53": "DNS", "tcp/853": "DNS over TLS", "udp/123": "NTP", "tcp/80": "HTTP",
	"tcp/22": "SSH", "udp/3478": "STUN", "tcp/5223": "Apple Push", "tcp/23": "Telnet", "tcp/3389": "RDP", "tcp/445": "SMB", "udp/5060": "SIP",
}

// demoNetFlow is one remote address a device keeps connecting to.
type demoNetFlow struct {
	dev     int
	org     int
	remote  string
	ptr     string
	proto   string
	port    int
	p       float64
	sess    int
	country string
	inbound bool
}

// demoNetPlan expands demoNetUses into flows, giving each organisation its own addresses in the
// documentation ranges, in a fixed order (the same every run).
var demoNetPlan = sync.OnceValue(func() []demoNetFlow {
	ranges := []string{"192.0.2.", "198.51.100.", "203.0.113."}
	next := map[int]int{} // range -> next host
	nth := map[int]int{}  // organisation -> addresses given
	var out []demoNetFlow
	for dev, uses := range demoNetUses {
		for _, u := range uses {
			for i := 0; i < u.n; i++ {
				r := (u.org + 1) % len(ranges)
				next[r]++
				addr := ranges[r] + strconv.Itoa(10+next[r]*3)
				f := demoNetFlow{dev: dev, org: u.org, remote: addr, proto: u.proto, port: u.port, p: u.p, sess: u.sess, country: u.country, inbound: u.inbound}
				if u.org >= 0 {
					if f.country == "" {
						f.country = demoNetOrgs[u.org].country
					}
					if pf := demoNetOrgs[u.org].ptr; pf != nil {
						f.ptr = pf(addr, nth[u.org])
					}
					nth[u.org]++
				}
				out = append(out, f)
			}
		}
	}
	return out
})

// demoIPDB is when the demo's IP database was written: the latest Sunday 06:00 UTC before now.
func demoIPDB(now time.Time) time.Time {
	d := now.UTC().Truncate(24 * time.Hour).Add(6 * time.Hour)
	for d.After(now) || d.Weekday() != time.Sunday {
		d = d.Add(-24 * time.Hour)
	}
	return d
}

// natTicksLocked calls fn for every NAT table read in [from, to): every demoNATEvery since the
// ledger started, none while the PC slept or the line was down (no session to the Internet then),
// none since logins were paused (netState "paused": 3 hours ago, as Status.Connections says) and
// none at all without an access code ("noaccess").
func (w *demoWorld) natTicksLocked(from, to time.Time, fn func(t time.Time)) {
	if from.Before(w.genesis) {
		from = w.genesis
	}
	now := time.Now()
	switch w.netState {
	case "paused":
		now = now.Truncate(demoNATEvery).Add(-3*time.Hour + time.Nanosecond)
	case "noaccess", "nosamples":
		return
	}
	if to.After(now) {
		to = now
	}
	t := from.Truncate(demoNATEvery)
	if t.Before(from) {
		t = t.Add(demoNATEvery)
	}
	for ; t.Before(to); t = t.Add(demoNATEvery) {
		if w.gapAt(t) || w.wanDownAt(t) {
			continue
		}
		fn(t)
	}
}

// flowOpenLocked reports whether flow i is open at the read at t: never while the Device List
// shows its device off or does not list it.
func (w *demoWorld) flowOpenLocked(f demoNetFlow, i int, t time.Time) bool {
	return noise(t, 1000+i) < f.p*demoNetDevices[f.dev].active(t.Local().Hour()) && w.netDevOnLocked(f.dev, t)
}

// netDevOnLocked reports whether the device demoNetDevices[dev] is on at t, as the Device List shows
// it (a device it does not name - the gateway, an address it never lists - always is).
func (w *demoWorld) netDevOnLocked(dev int, t time.Time) bool {
	l := demoNetDevices[dev].lan
	if l < 0 {
		return true
	}
	listed, on, _ := demoLAN[l].at(w.created, t)
	return listed && on
}

// demoFlowStat is what the reads of a period saw of one flow.
type demoFlowStat struct {
	samples, weight int
	first, last     time.Time
}

// demoServiceKey is a flow's service: its name and the key the flow diagram groups it by.
func demoServiceKey(proto string, port int) (key, name string) {
	key = proto + "/" + strconv.Itoa(port)
	if n, ok := demoServices[key]; ok {
		return key, n
	}
	return key, proto + " " + strconv.Itoa(port)
}

// Connections answers GET /api/network/connections from the demo's flows (contracts.NetworkView).
func (w *demoWorld) Connections(ctx context.Context, q contracts.NetQuery) (model.NetConnections, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.netState == "unavailable" {
		return model.NetConnections{}, fmt.Errorf("connstore: the connection store is closed: %w", contracts.ErrUnavailable)
	}
	plan := demoNetPlan()
	now := time.Now()
	nc := model.NetConnections{From: q.From.UTC().Format(time.RFC3339Nano), To: q.To.UTC().Format(time.RFC3339Nano), Device: q.Device, InUse: -1, Available: -1}
	stats := make([]demoFlowStat, len(plan))
	devSamples := make([]int, len(demoNetDevices))
	var lastTick time.Time
	w.natTicksLocked(q.From, q.To, func(t time.Time) {
		if err := ctx.Err(); err != nil {
			return
		}
		nc.Samples++
		if nc.First == "" {
			nc.First = t.UTC().Format(time.RFC3339Nano)
		}
		lastTick = t
		seen := make([]bool, len(demoNetDevices))
		for i, f := range plan {
			if !w.flowOpenLocked(f, i, t) {
				continue
			}
			st := &stats[i]
			if st.samples == 0 {
				st.first = t
			}
			st.samples++
			st.weight += f.sess
			st.last = t
			seen[f.dev] = true
		}
		for d, s := range seen {
			if s {
				devSamples[d]++
			}
		}
	})
	if err := ctx.Err(); err != nil {
		return model.NetConnections{}, err
	}
	if nc.Samples > 0 {
		nc.Last = lastTick.UTC().Format(time.RFC3339Nano)
		for i, f := range plan {
			if w.flowOpenLocked(f, i, lastTick) {
				nc.Open += f.sess
				if q.Device != "" && demoNetDevices[f.dev].key == q.Device {
					nc.OpenDevice += f.sess
				}
			}
		}
		nc.InUse, nc.Available = nc.Open+7, 8192-nc.Open-7
	}
	ipdb := w.netState != "noipdb"
	if ipdb {
		nc.IPDB = demoIPDB(now).Format(time.RFC3339)
	}

	// Every device of the period (for the device filter), then the flows of the device asked for.
	devWeight := make([]int, len(demoNetDevices))
	devSites := make([]map[string]bool, len(demoNetDevices))
	for i, f := range plan {
		if stats[i].samples == 0 {
			continue
		}
		devWeight[f.dev] += stats[i].weight
		if devSites[f.dev] == nil {
			devSites[f.dev] = map[string]bool{}
		}
		devSites[f.dev][f.remote] = true
	}
	for d, dv := range demoNetDevices {
		if devSamples[d] == 0 {
			continue
		}
		name := dv.name
		if name == "" {
			name = dv.ipv4
		}
		nc.Devices = append(nc.Devices, model.NetDevice{Key: dv.key, Name: name, IPv4: dv.ipv4, MAC: dv.mac, Connection: dv.conn, Weight: devWeight[d], Sites: len(devSites[d])})
	}
	sort.SliceStable(nc.Devices, func(a, b int) bool { return nc.Devices[a].Weight > nc.Devices[b].Weight })

	orgOf := func(f demoNetFlow) (key, name string, asn int, country string) {
		if f.org < 0 || !ipdb {
			return "unknown", "Unknown", 0, ""
		}
		o := demoNetOrgs[f.org]
		return "org:" + strings.ToLower(o.name), o.name, o.asn, f.country
	}
	type agg struct {
		key, name, country string
		asn, weight        int
		sites              map[string]bool
		asns               map[int]int // an organisation's ASes and their weights
	}
	orgs := map[string]*agg{}
	svcs := map[string]*agg{}
	countries := map[string]*agg{}
	sites := map[string]bool{}
	asns := map[string]bool{} // the organisations of the public addresses
	devices := map[string]bool{}
	type pair struct{ from, to string }
	devOrg := map[pair]int{}
	orgSvc := map[pair]int{}
	var rows []model.NetConnRow
	for i, f := range plan {
		st := stats[i]
		dv := demoNetDevices[f.dev]
		if st.samples == 0 || (q.Device != "" && dv.key != q.Device) {
			continue
		}
		okey, oname, asn, country := orgOf(f)
		skey, sname := demoServiceKey(f.proto, f.port)
		add := func(m map[string]*agg, key, name, country string, asn int) {
			a := m[key]
			if a == nil {
				a = &agg{key: key, name: name, country: country, asn: asn, sites: map[string]bool{}, asns: map[int]int{}}
				m[key] = a
			}
			a.weight += st.weight
			a.sites[f.remote] = true
			if asn > 0 {
				// The organisation's AS and country are those of its heaviest AS.
				if a.asns[asn] += st.weight; a.asns[asn] > a.asns[a.asn] || a.asns[asn] == a.asns[a.asn] && asn < a.asn {
					a.asn, a.country = asn, country
				}
			}
		}
		add(orgs, okey, oname, country, asn)
		add(svcs, skey, sname, "", 0)
		add(countries, country, "", country, 0)
		sites[f.remote] = true
		devices[dv.key] = true
		if okey != "unknown" {
			asns[okey] = true
		}
		devOrg[pair{dv.key, okey}] += st.weight
		orgSvc[pair{okey, skey}] += st.weight
		row := model.NetConnRow{Device: dv.key, LAN: dv.ipv4, Remote: f.remote, Kind: model.IPKindPublic, Org: oname, ASN: asn, Country: country,
			Proto: f.proto, Port: f.port, Inbound: f.inbound, First: st.first.UTC().Format(time.RFC3339Nano), Last: st.last.UTC().Format(time.RFC3339Nano),
			Samples: st.samples, Weight: st.weight}
		if okey == "unknown" {
			row.Org, row.ASN = "", 0
		}
		if n, ok := demoServices[skey]; ok {
			row.Service = n
		}
		if ipdb {
			row.PTR = f.ptr
		}
		if dv.key == "gateway" {
			row.LAN = demoWANIP
		}
		rows = append(rows, row)
	}
	byWeight := func(list []*agg) {
		sort.SliceStable(list, func(a, b int) bool {
			if list[a].weight != list[b].weight {
				return list[a].weight > list[b].weight
			}
			return list[a].key < list[b].key
		})
	}
	// The diagram's organisations: the top 9, the rest grouped as "other" (and "unknown" last).
	var orgList []*agg
	for _, a := range orgs {
		orgList = append(orgList, a)
	}
	byWeight(orgList)
	group := map[string]string{} // organisation key -> its node
	other := &agg{key: "other", name: "Other", sites: map[string]bool{}}
	members := 0
	for i, a := range orgList {
		if i < 9 || a.key == "unknown" {
			group[a.key] = a.key
			continue
		}
		group[a.key] = "other"
		other.weight += a.weight
		for s := range a.sites {
			other.sites[s] = true
		}
		members++
	}
	for _, a := range orgList {
		if group[a.key] == a.key {
			o := model.NetOrg{Key: a.key, Name: a.name, ASN: a.asn, Country: a.country, Weight: a.weight, Sites: len(a.sites)}
			if len(a.asns) > 1 {
				o.ASNs = slices.Sorted(maps.Keys(a.asns))
			}
			nc.Orgs = append(nc.Orgs, o)
		}
	}
	if members > 0 {
		nc.Orgs = append(nc.Orgs, model.NetOrg{Key: "other", Name: "Other", Weight: other.weight, Sites: len(other.sites), Members: members})
	}
	// "unknown" after the organisations, "other" last.
	slices.SortStableFunc(nc.Orgs, func(a, b model.NetOrg) int {
		rank := func(o model.NetOrg) int {
			switch o.Key {
			case "unknown":
				return 1
			case "other":
				return 2
			}
			return 0
		}
		return rank(a) - rank(b)
	})
	// The diagram's services: the top 6, the rest as "other".
	var svcList []*agg
	for _, a := range svcs {
		svcList = append(svcList, a)
	}
	byWeight(svcList)
	svcGroup := map[string]string{}
	otherSvc := 0
	for i, a := range svcList {
		if i < 6 {
			svcGroup[a.key] = a.key
			proto, port, _ := strings.Cut(a.key, "/")
			p, _ := strconv.Atoi(port)
			nc.Services = append(nc.Services, model.NetService{Key: a.key, Name: a.name, Proto: proto, Port: p, Weight: a.weight})
			continue
		}
		svcGroup[a.key] = "other"
		otherSvc += a.weight
	}
	if otherSvc > 0 {
		nc.Services = append(nc.Services, model.NetService{Key: "other", Name: "Other", Weight: otherSvc})
	}
	links := map[pair]int{}
	for p, wt := range devOrg {
		links[pair{p.from, group[p.to]}] += wt
	}
	for p, wt := range orgSvc {
		links[pair{group[p.from], svcGroup[p.to]}] += wt
	}
	for p, wt := range links {
		nc.Links = append(nc.Links, model.NetLink{From: p.from, To: p.to, Weight: wt})
	}
	sort.Slice(nc.Links, func(a, b int) bool {
		if nc.Links[a].Weight != nc.Links[b].Weight {
			return nc.Links[a].Weight > nc.Links[b].Weight
		}
		return nc.Links[a].From+nc.Links[a].To < nc.Links[b].From+nc.Links[b].To
	})
	for _, a := range countries {
		nc.Countries = append(nc.Countries, model.NetCountry{Code: a.country, Sites: len(a.sites), Weight: a.weight})
	}
	sort.Slice(nc.Countries, func(a, b int) bool {
		if nc.Countries[a].Sites != nc.Countries[b].Sites {
			return nc.Countries[a].Sites > nc.Countries[b].Sites
		}
		return nc.Countries[a].Code < nc.Countries[b].Code
	})
	nc.Totals = model.NetTotals{Devices: len(devices), Sites: len(sites), Orgs: len(asns)}
	// The devices of the period that the newest Device List read lists: not the gateway, not an
	// address the list never names, not a device it no longer lists.
	if q.Device == "" {
		listed := w.listedKeysLocked()
		for key := range devices {
			if listed[key] {
				nc.Totals.Listed++
			}
		}
	}
	for _, c := range nc.Countries {
		if c.Code != "" {
			nc.Totals.Countries++
		}
	}
	if w.netState == "busy" {
		// More distinct connections than the connection store counts one by one (its bound): the
		// lightest count only in their devices and as "Other".
		nc.FlowsLeftOut = 412
	}
	sort.SliceStable(rows, func(a, b int) bool {
		if rows[a].Samples != rows[b].Samples {
			return rows[a].Samples > rows[b].Samples
		}
		return rows[a].Weight > rows[b].Weight
	})
	nc.RowsTotal = len(rows)
	limit := q.Limit
	if limit <= 0 {
		limit = 200
	}
	if len(rows) > limit {
		rows = rows[:limit]
	}
	nc.Rows = rows
	if w.hostile != "" {
		hostileConnections(&nc, w.hostile)
	}
	return nc, nil
}

// demoFwCountries share the inbound probes among source countries ("" = a source the IP
// database does not place); SG and HK are too small for the world map.
var demoFwCountries = []struct {
	code  string
	share float64
}{
	{"US", 0.30}, {"CN", 0.20}, {"NL", 0.07}, {"DE", 0.06}, {"RU", 0.05}, {"GB", 0.04}, {"FR", 0.035}, {"BR", 0.03}, {"IN", 0.03},
	{"KR", 0.02}, {"VN", 0.018}, {"JP", 0.014}, {"TW", 0.011}, {"SG", 0.01}, {"CA", 0.012}, {"HK", 0.008}, {"IR", 0.009}, {"UA", 0.008},
	{"PL", 0.007}, {"IT", 0.006}, {"ID", 0.005}, {"TR", 0.005}, {"AR", 0.004}, {"MX", 0.003}, {"AU", 0.003}, {"ZA", 0.003},
	{"SE", 0.002}, {"RO", 0.002}, {"TH", 0.002}, {"", 0.005},
}

// demoFwSources are the most active probing networks (organisation, AS, country).
var demoFwSources = []struct {
	addr, org, country string
	asn, ports         int
	share              float64
}{
	{"203.0.113.66", "Censys", "US", 398324, 61, 0.031}, {"198.51.100.201", "DigitalOcean", "US", 14061, 3, 0.029},
	{"192.0.2.17", "Chinanet", "CN", 4134, 12, 0.026}, {"203.0.113.140", "OVH", "FR", 16276, 5, 0.022},
	{"198.51.100.93", "Tencent", "CN", 132203, 2, 0.02}, {"192.0.2.250", "Hetzner Online", "DE", 24940, 9, 0.016},
	{"203.0.113.77", "Shodan", "US", 10439, 44, 0.014}, {"198.51.100.18", "Alibaba", "CN", 37963, 4, 0.012},
	{"192.0.2.131", "Akamai", "NL", 20940, 7, 0.01}, {"203.0.113.23", "Google Cloud", "US", 396982, 3, 0.009},
	{"198.51.100.240", "Rostelecom", "RU", 12389, 6, 0.008}, {"192.0.2.88", "Korea Telecom", "KR", 4766, 2, 0.007},
}

// demoFwServices share the inbound probes among the ports they target and the protocols without
// ports (port 0), which the real view names by the protocol ("ICMP", as netmap's protoLabel does):
// pings are among the probes a gateway drops most. Eight, most first, then the rest as "Other",
// as the real view lists them (netmap's topFwSvcs).
var demoFwServices = []struct {
	proto string
	port  int
	share float64
	name  string // "" = the port table's (demoServiceKey)
}{
	{"tcp", 22, 0.14, ""}, {"tcp", 23, 0.12, ""}, {"icmp", 0, 0.1, "ICMP"}, {"tcp", 80, 0.09, ""}, {"tcp", 3389, 0.07, ""}, {"tcp", 445, 0.05, ""},
	{"tcp", 8071, 0.03, ""}, {"icmpv6", 0, 0.02, "ICMPv6"},
}

// Firewall reasons the demo's gateway gives, with their plain labels.
const (
	demoReasonInput   = "POLICY-INPUT-GEN-DISCARD"
	demoReasonForward = "POLICY-FORWARD-GEN-DISCARD"
	demoReasonInvalid = "FORWARD-INVALID-STATE-DISCARD"
)

var demoReasonLabels = map[string]string{
	demoReasonInput:   "Unsolicited, to the gateway",
	demoReasonForward: "Unsolicited, toward the home network",
	demoReasonInvalid: "Invalid state (the connection was already closed)",
}

// demoFwHour is the demo's firewall in the hour starting at t: inbound probes (none while the line
// was down), outbound packets of the office PC (in office hours, in bursts) and of the camera the
// Device List does not name (demoUnlistedFw, every evening: stray), a few local ones, and of the
// inbound probes toward the home network those addressed to a device's global IPv6 address (toDev,
// by device key: part of the inbound drops, the reason "toward the home network").
type demoFwHour struct {
	in, out, stray, local int
	toDev                 map[string]int
}

// demoFwToward are the devices of demoNetDevices whose global IPv6 addresses the Internet's probes
// reach, with how many of those packets each gets in an hour at most (while it is on).
var demoFwToward = []struct {
	dev int
	max float64
}{{0, 2.6}, {1, 1.2}, {2, 1.8}, {3, 0.9}, {6, 1.4}, {10, 1.6}}

func (w *demoWorld) fwHourLocked(t time.Time) demoFwHour {
	var hr demoFwHour
	if w.gapAt(t) || w.gapAt(t.Add(30*time.Minute)) {
		return hr // the PC slept: nothing was received
	}
	h := t.Local().Hour()
	mid := t.Add(30 * time.Minute)
	if !w.wanDownAt(mid) {
		hr.in = int(470 + 90*math.Sin(float64(h)/24*2*math.Pi) + 160*noise(t, 3001))
		for _, x := range demoFwToward {
			if n := int(x.max * noise(t, 3100+x.dev)); n > 0 && w.netDevOnLocked(x.dev, mid) {
				if hr.toDev == nil {
					hr.toDev = map[string]int{}
				}
				hr.toDev[demoNetDevices[x.dev].key] = n
			}
		}
	}
	if h >= 8 && h < 19 && noise(t, 3002) < 0.7 {
		hr.out = int(10 + 75*noise(t, 3003))
	}
	if h >= 18 {
		hr.stray = 1 + int(5*noise(t, 3010))
	}
	if noise(t, 3004) < 0.3 {
		hr.local = 1 + int(4*noise(t, 3005))
	}
	return hr
}

// demoFwDevices are a period's firewall drops by device (NetDevice keys): the packets each sent
// (out: the outbound rows, also those beyond the rows listed) and those from the Internet addressed
// to it (in), and when the camera the Device List does not name had its first and last dropped.
type demoFwDevices struct {
	out, in               map[string]int
	strayFirst, strayLast time.Time
}

// Firewall answers GET /api/network/firewall from the demo's hourly firewall model, within the
// syslog the demo's store keeps (contracts.NetworkView).
func (w *demoWorld) Firewall(ctx context.Context, q contracts.NetQuery) (model.NetFirewall, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	fw, _, err := w.firewallLocked(ctx, q)
	if err != nil {
		return model.NetFirewall{}, err
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 200
	}
	if len(fw.OutboundRows) > limit {
		fw.OutboundRows = fw.OutboundRows[:limit]
	}
	if w.hostile != "" {
		hostileFirewall(&fw, w.hostile)
	}
	return fw, nil
}

// firewallLocked is the firewall view of q (every outbound row: Firewall applies the limit) and
// the period's drops by device, which the Devices tab counts (Devices).
func (w *demoWorld) firewallLocked(ctx context.Context, q contracts.NetQuery) (model.NetFirewall, demoFwDevices, error) {
	devs := demoFwDevices{out: map[string]int{}, in: map[string]int{}}
	switch w.netState {
	case "unavailable":
		return model.NetFirewall{}, devs, fmt.Errorf("netmap: the syslog store is closed: %w", contracts.ErrUnavailable)
	case "nosyslog":
		return model.NetFirewall{}, devs, fmt.Errorf("netmap: firewall view: no syslog store: %w", contracts.ErrUnavailable)
	}
	now := time.Now()
	u := w.syslogUsageLocked()
	fw := model.NetFirewall{From: q.From.UTC().Format(time.RFC3339Nano), To: q.To.UTC().Format(time.RFC3339Nano), Oldest: u.Oldest}
	if w.netState != "noipdb" {
		fw.IPDB = demoIPDB(now).Format(time.RFC3339)
	}
	oldest, err := time.Parse(time.RFC3339Nano, u.Oldest)
	kept := err == nil
	var lastIn, lastOut time.Time
	shared, stray := 0, 0 // the outbound packets of the office PC and the laptop and phone; of the camera
	for t := q.From.Truncate(time.Hour); t.Before(q.To); t = t.Add(time.Hour) {
		if err := ctx.Err(); err != nil {
			return model.NetFirewall{}, devs, err
		}
		hr := model.FwHour{T: t.UTC().Format(time.RFC3339)}
		// The part of the hour inside the period, the syslog kept and the past.
		a, b := t, t.Add(time.Hour)
		if a.Before(q.From) {
			a = q.From
		}
		if b.After(q.To) {
			b = q.To
		}
		if kept && a.Before(oldest) {
			a = oldest
		}
		if b.After(now) {
			b = now
		}
		if kept && b.After(a) && w.netState != "nodrops" {
			frac := b.Sub(a).Hours()
			x := w.fwHourLocked(t)
			office, st := int(float64(x.out)*frac), int(float64(x.stray)*frac)
			hr.In, hr.Out, hr.Local = int(float64(x.in)*frac), office+st, int(float64(x.local)*frac)
			if hr.In > 0 {
				lastIn = b.Add(-time.Duration(noise(t, 3006) * float64(b.Sub(a))))
			}
			if office > 0 {
				lastOut = b.Add(-time.Duration(noise(t, 3007) * float64(b.Sub(a))))
			}
			if st > 0 {
				if devs.strayFirst.IsZero() {
					devs.strayFirst = a.Add(time.Duration(noise(t, 3011) * float64(b.Sub(a)) / 2))
				}
				devs.strayLast = b.Add(-time.Duration(noise(t, 3012) * float64(b.Sub(a)) / 2))
			}
			shared += office
			stray += st
			for key, n := range x.toDev {
				devs.in[key] += int(float64(n) * frac)
			}
		}
		fw.Hours = append(fw.Hours, hr)
		fw.Inbound += hr.In
		fw.Outbound += hr.Out
		fw.Local += hr.Local
	}
	fw.Drops = fw.Inbound + fw.Outbound + fw.Local
	if fw.Inbound > 0 {
		left := fw.Inbound
		for i, c := range demoFwCountries {
			n := int(math.Round(float64(fw.Inbound) * c.share))
			if i == len(demoFwCountries)-1 || n > left {
				n = left
			}
			if n <= 0 {
				continue
			}
			left -= n
			// Each source address is in one country: the countries' sites add up to the sources.
			sites := max(1, int(math.Sqrt(float64(n))*1.6))
			fw.Countries = append(fw.Countries, model.NetCountry{Code: c.code, Sites: sites, Weight: n})
			fw.Sources += sites
		}
		sort.SliceStable(fw.Countries, func(a, b int) bool { return fw.Countries[a].Weight > fw.Countries[b].Weight })
		for i, s := range demoFwSources {
			n := int(math.Round(float64(fw.Inbound) * s.share))
			if n <= 0 {
				continue
			}
			last := lastIn.Add(-time.Duration(i) * 7 * time.Minute)
			fw.TopSources = append(fw.TopSources, model.FwSource{Addr: s.addr, Org: s.org, ASN: s.asn, Country: s.country, Count: n, Ports: s.ports,
				Last: last.UTC().Format(time.RFC3339Nano)})
		}
		other := fw.Inbound
		for _, s := range demoFwServices {
			n := int(math.Round(float64(fw.Inbound) * s.share))
			if n <= 0 {
				continue
			}
			other -= n
			name := s.name
			if name == "" {
				_, name = demoServiceKey(s.proto, s.port)
			}
			fw.Services = append(fw.Services, model.FwService{Name: name, Proto: s.proto, Port: s.port, Count: n})
		}
		if other > 0 {
			fw.Services = append(fw.Services, model.FwService{Name: "Other", Count: other})
		}
	}
	reasons := map[string]int{demoReasonInput: fw.Inbound*4/5 + fw.Local, demoReasonForward: fw.Inbound - fw.Inbound*4/5, demoReasonInvalid: fw.Outbound}
	for _, r := range []string{demoReasonInput, demoReasonForward, demoReasonInvalid} {
		if reasons[r] > 0 {
			fw.Reasons = append(fw.Reasons, model.FwReason{Reason: r, Label: demoReasonLabels[r], Count: reasons[r]})
		}
	}
	if fw.Outbound > 0 {
		// The office PC's late packets to the sites it was using; two more rows, with fewer packets,
		// beyond the rows listed - the phone's and the laptop's -, so that the devices counted are
		// more than those the rows name.
		reserve := 0
		if shared >= 20 {
			reserve = max(2, shared*3/100)
		}
		plan := demoNetPlan()
		left := shared - reserve
		shares := []float64{0.42, 0.21, 0.12, 0.09, 0.07, 0.05, 0.04}
		picked := 0
		for i, f := range plan {
			if picked == len(shares) || left <= 0 {
				break
			}
			if (f.dev != 0 && f.dev != 1) || f.org < 0 || noise(time.Unix(int64(i), 0), 3008) < 0.4 {
				continue
			}
			n := int(math.Round(float64(shared-reserve) * shares[picked]))
			if picked == len(shares)-1 || n > left {
				n = left
			}
			if n <= 0 {
				continue
			}
			left -= n
			dv := demoNetDevices[f.dev]
			key, name := demoServiceKey(f.proto, f.port)
			row := model.FwOutRow{Device: dv.key, Name: dv.name, LAN: dv.ipv4, Remote: f.remote, Org: demoNetOrgs[f.org].name, ASN: demoNetOrgs[f.org].asn,
				Country: f.country, Service: name, Proto: f.proto, Port: f.port, Reason: demoReasonInvalid, Label: demoReasonLabels[demoReasonInvalid], Count: n,
				Last: lastOut.Add(-time.Duration(picked) * 11 * time.Minute).UTC().Format(time.RFC3339Nano)}
			if _, named := demoServices[key]; !named {
				row.Service = ""
			}
			fw.OutboundRows = append(fw.OutboundRows, row)
			devs.out[dv.key] += n
			picked++
		}
		if n := len(fw.OutboundRows); left > 0 && n > 0 {
			fw.OutboundRows[n-1].Count += left
			devs.out[fw.OutboundRows[n-1].Device] += left
		}
		hidden := 0
		if reserve > 0 {
			hidden = 2
			devs.out[demoNetDevices[2].key] += (reserve + 1) / 2
			devs.out[demoNetDevices[1].key] += reserve / 2
		}
		if stray > 0 {
			// The camera's late packets to its server: the gateway names it by its address alone.
			fw.OutboundRows = append(fw.OutboundRows, model.FwOutRow{Device: "ip:" + demoUnlistedFw, Name: demoUnlistedFw, LAN: demoUnlistedFw,
				Remote: "203.0.113.200", Org: "OVH", ASN: 16276, Country: "FR", Proto: "tcp", Port: 8000, Reason: demoReasonInvalid,
				Label: demoReasonLabels[demoReasonInvalid], Count: stray, Last: devs.strayLast.UTC().Format(time.RFC3339Nano)})
			devs.out["ip:"+demoUnlistedFw] += stray
		}
		sort.SliceStable(fw.OutboundRows, func(a, b int) bool { return fw.OutboundRows[a].Count > fw.OutboundRows[b].Count })
		fw.OutboundTotal, fw.OutboundDevices = len(fw.OutboundRows)+hidden, len(devs.out)
	}
	return fw, devs, nil
}

// ------------------------------------------------------------------ the Device List (Devices tab)

// demoDevEvery is the demo's Device List read interval (connections.devices_interval).
const demoDevEvery = 15 * time.Minute

// demoLANDevice is an entry of the demo gateway's Device List - its DHCP table: who the device is,
// how it is connected, the IPv4 addresses it was given and when the list showed it, and on. Times
// are offsets before the world was created (created - offset).
type demoLANDevice struct {
	key, name, mac string
	conn           string // Connection as the reader summarizes it ("Wi-Fi 5 GHz", "Ethernet LAN-2")
	speed          string // a wired link's Connection Speed as shown
	bars           int    // the Wi-Fi signal the gateway draws while it is on (1-5)
	alloc          string // "dhcp" or "static"
	mesh           bool
	ipv6           []string
	// addrs are the IPv4 addresses it was given, oldest first, each since an offset (0 for the
	// first: since before the monitor started).
	addrs []demoLease
	// The list shows it from listedFrom (0: since before the monitor started) until listedTo (0:
	// still), off in the spans off (from 0: since before the monitor started; to 0: still).
	listedFrom, listedTo time.Duration
	off                  []demoSpan
	// lastOn is when it was last on, for a device that has been off since before the monitor
	// started (the gateway's Last Activity).
	lastOn time.Duration
}

type demoLease struct {
	addr  string
	since time.Duration
}

type demoSpan struct{ from, to time.Duration }

// nights are the spans of the nights before the world was created, from 31 h ago (the Kids tablet
// is off at night): eight hours each, a day apart.
func nights(n int) []demoSpan {
	var out []demoSpan
	for i := 0; i < n; i++ {
		start := 31*time.Hour + time.Duration(i)*24*time.Hour
		out = append(out, demoSpan{from: start, to: start - 8*time.Hour})
	}
	return out
}

// demoLAN is the household's Device List in the gateway's order (by when it first saw each
// device; its MAC addresses in that order): the eight devices of the Network page before it had a
// Devices tab, the ones added with it, and a visitor's laptop the list no longer shows. The Printer
// (DHCP) and the Security camera (a static address set by hand, inside the gateway's DHCP pool)
// claim the same address; the Smart speaker's Wi-Fi is weak; the Game console's cable makes a 10
// Mb/s half-duplex link; the Laptop moved from 192.168.1.80 to .64 yesterday, and the Guest phone
// was given .80 two hours later. Documentation values only: LAN 192.168.1.x, MAC
// 00:00:5e:00:53:xx, IPv6 2001:db8::/32.
var demoLAN = []demoLANDevice{
	{key: "mac:00:00:5e:00:53:01", name: "Office PC", mac: "00:00:5e:00:53:01", conn: "Wi-Fi 5 GHz", bars: 5, alloc: "dhcp",
		ipv6:  []string{"2001:db8:4c2:7a10:9c41:7e02:51d3:a871", "2001:db8:4c2:7a10:200:5eff:fe00:5301"},
		addrs: []demoLease{{"192.168.1.71", 0}}},
	{key: "mac:00:00:5e:00:53:02", name: "Laptop", mac: "00:00:5e:00:53:02", conn: "Wi-Fi 5 GHz", bars: 4, alloc: "dhcp",
		ipv6:  []string{"2001:db8:4c2:7a10:5a3c:e11f:902b:64d0"},
		addrs: []demoLease{{"192.168.1.80", 0}, {"192.168.1.64", 20 * time.Hour}}, off: []demoSpan{{22 * time.Hour, 20 * time.Hour}}},
	{key: "mac:00:00:5e:00:53:03", name: "Phone", mac: "00:00:5e:00:53:03", conn: "Wi-Fi 5 GHz", bars: 4, alloc: "dhcp",
		ipv6:  []string{"2001:db8:4c2:7a10:1e7d:4b62:c0a9:3f65", "2001:db8:4c2:7a10:8a2:91ff:fe3c:6510"},
		addrs: []demoLease{{"192.168.1.65", 0}}},
	{key: "mac:00:00:5e:00:53:04", name: "Living room TV", mac: "00:00:5e:00:53:04", conn: "Ethernet LAN-2", speed: "1000Mbps fullduplex", alloc: "dhcp",
		ipv6: []string{"2001:db8:4c2:7a10:200:5eff:fe00:5304"}, addrs: []demoLease{{"192.168.1.66", 0}}},
	{key: "mac:00:00:5e:00:53:05", name: "Tablet", mac: "00:00:5e:00:53:05", conn: "Wi-Fi 2.4 GHz", bars: 3, alloc: "dhcp",
		addrs: []demoLease{{"192.168.1.67", 0}}},
	{key: "mac:00:00:5e:00:53:06", name: "Printer", mac: "00:00:5e:00:53:06", conn: "Wi-Fi 2.4 GHz", bars: 3, alloc: "dhcp",
		addrs: []demoLease{{"192.168.1.68", 0}}},
	{key: "mac:00:00:5e:00:53:07", name: "Game console", mac: "00:00:5e:00:53:07", conn: "Ethernet LAN-3", speed: "10Mbps halfduplex", alloc: "dhcp",
		ipv6: []string{"2001:db8:4c2:7a10:200:5eff:fe00:5307"}, addrs: []demoLease{{"192.168.1.69", 0}}},
	{key: "mac:00:00:5e:00:53:08", name: "Smart speaker", mac: "00:00:5e:00:53:08", conn: "Wi-Fi 2.4 GHz", bars: 2, alloc: "dhcp", mesh: true,
		addrs: []demoLease{{"192.168.1.70", 0}}},
	{key: "mac:00:00:5e:00:53:09", name: "Thermostat", mac: "00:00:5e:00:53:09", conn: "Wi-Fi 2.4 GHz", bars: 4, alloc: "dhcp",
		addrs: []demoLease{{"192.168.1.72", 0}}},
	{key: "mac:00:00:5e:00:53:0a", name: "Security camera", mac: "00:00:5e:00:53:0a", conn: "Ethernet LAN-4", speed: "100Mbps fullduplex", alloc: "static",
		addrs: []demoLease{{"192.168.1.68", 0}}, listedFrom: 5 * time.Hour},
	{key: "mac:00:00:5e:00:53:0b", name: "Guest phone", mac: "00:00:5e:00:53:0b", conn: "Wi-Fi 5 GHz", bars: 3, alloc: "dhcp",
		ipv6:  []string{"2001:db8:4c2:7a10:d4e8:2a17:6b90:c180"},
		addrs: []demoLease{{"192.168.1.80", 0}}, listedFrom: 18 * time.Hour, off: []demoSpan{{15 * time.Hour, 0}}},
	{key: "mac:00:00:5e:00:53:0c", name: "E-reader", mac: "00:00:5e:00:53:0c", conn: "Wi-Fi 2.4 GHz", bars: 3, alloc: "dhcp",
		addrs: []demoLease{{"192.168.1.73", 0}}, off: []demoSpan{{75 * time.Hour, 0}}},
	{key: "mac:00:00:5e:00:53:0d", name: "Work laptop", mac: "00:00:5e:00:53:0d", conn: "Wi-Fi 5 GHz", bars: 4, alloc: "dhcp",
		addrs: []demoLease{{"192.168.1.74", 0}}, off: []demoSpan{{0, 0}}, lastOn: 9*24*time.Hour + 3*time.Hour},
	{key: "mac:00:00:5e:00:53:0e", name: "Kids tablet", mac: "00:00:5e:00:53:0e", conn: "Wi-Fi 5 GHz", bars: 4, alloc: "dhcp",
		addrs: []demoLease{{"192.168.1.75", 0}}, off: nights(7)},
	{key: "mac:00:00:5e:00:53:0f", name: "NAS", mac: "00:00:5e:00:53:0f", conn: "Ethernet LAN-1", speed: "1000Mbps fullduplex", alloc: "static",
		addrs: []demoLease{{"192.168.1.10", 0}}},
	{key: "mac:00:00:5e:00:53:10", name: "Doorbell", mac: "00:00:5e:00:53:10", conn: "Wi-Fi 2.4 GHz", bars: 3, alloc: "dhcp", mesh: true,
		addrs: []demoLease{{"192.168.1.76", 0}}},
	{key: "mac:00:00:5e:00:53:11", name: "Visitor laptop", mac: "00:00:5e:00:53:11", conn: "Wi-Fi 5 GHz", bars: 4, alloc: "dhcp",
		addrs: []demoLease{{"192.168.1.81", 0}}, listedFrom: 123 * time.Hour, listedTo: 94 * time.Hour, off: []demoSpan{{119 * time.Hour, 0}}},
}

// at is the device as a Device List read at t shows it: whether the list shows it at all, whether
// on, and with which IPv4 address.
func (d demoLANDevice) at(created, t time.Time) (listed, on bool, ipv4 string) {
	if d.listedFrom > 0 && t.Before(created.Add(-d.listedFrom)) {
		return false, false, ""
	}
	if d.listedTo > 0 && !t.Before(created.Add(-d.listedTo)) {
		return false, false, ""
	}
	on = true
	for _, s := range d.off {
		if (s.from == 0 || !t.Before(created.Add(-s.from))) && (s.to == 0 || t.Before(created.Add(-s.to))) {
			on = false
		}
	}
	for _, l := range d.addrs {
		if l.since == 0 || !t.Before(created.Add(-l.since)) {
			ipv4 = l.addr
		}
	}
	return true, on, ipv4
}

// lastActivity is the device's Last Activity as the gateway shows it at the read at t (its local
// time, as on the Device List page: "Mon Oct 5 12:01:00 2026"): a few minutes before the read
// while it is on, else when it went off.
func (d demoLANDevice) lastActivity(i int, created, t time.Time) string {
	at := t.Add(-time.Duration(noise(t, 3200+i)*240) * time.Second)
	if _, on, _ := d.at(created, t); !on {
		at = created.Add(-d.lastOn)
		for _, s := range d.off {
			if (s.from == 0 || !t.Before(created.Add(-s.from))) && (s.to == 0 || t.Before(created.Add(-s.to))) && s.from > 0 {
				at = created.Add(-s.from - time.Duration(noise(t, 3210+i)*300)*time.Second)
			}
		}
	}
	return at.Local().Format("Mon Jan 2 15:04:05 2006")
}

// gatewayDownAt reports whether the gateway did not answer at t (while it restarted).
func (w *demoWorld) gatewayDownAt(t time.Time) bool {
	for _, e := range w.allEventsLocked() {
		if !e.boot.IsZero() && !t.Before(e.from) && t.Before(e.boot.Add(30*time.Second)) {
			return true
		}
	}
	return false
}

// devReadsLocked calls fn for every Device List read in [from, to): every demoDevEvery since the
// ledger started, none while the PC slept or the gateway restarted, none at all in the "nodevices"
// state. The page needs no login: the NAT table's paused logins or missing access code do not stop
// its reads.
func (w *demoWorld) devReadsLocked(from, to time.Time, fn func(t time.Time)) {
	if w.netState == "nodevices" {
		return
	}
	if from.Before(w.genesis) {
		from = w.genesis
	}
	if now := time.Now(); to.After(now) {
		to = now
	}
	t := from.Truncate(demoDevEvery)
	if t.Before(from) {
		t = t.Add(demoDevEvery)
	}
	for ; t.Before(to); t = t.Add(demoDevEvery) {
		if w.gapAt(t) || w.gatewayDownAt(t) {
			continue
		}
		fn(t)
	}
}

// newestDevReadLocked is when the newest Device List read was made (zero before the first).
func (w *demoWorld) newestDevReadLocked() time.Time {
	var last time.Time
	now := time.Now()
	w.devReadsLocked(now.Add(-48*time.Hour), now, func(t time.Time) { last = t })
	return last
}

// ------------------------------------------------------------------ the LAN scan

// demoScanEvery is the demo's LAN scan interval (connections.scan_interval; docs/dhcp-table.md §6).
const demoScanEvery = time.Hour

// What answers a LAN scan besides the Device List's devices: the gateway itself, and three
// addresses no Device List read names - 192.168.1.90 (its connections are in the NAT samples),
// 192.168.1.201 (the old camera whose packets the firewall drops, on in the evenings) and
// 192.168.1.50 (a smart plug with an address set by hand, which only the scans see).
const (
	demoGatewayMAC    = "00:00:5e:00:53:fe"
	demoUnlistedScan  = "192.168.1.50"
	demoMACUnlistedNA = "00:00:5e:00:53:20" // 192.168.1.90
	demoMACUnlistedSc = "00:00:5e:00:53:21" // 192.168.1.50
	demoMACUnlistedFw = "00:00:5e:00:53:22" // 192.168.1.201
	// In the "fixedguest" state, a visitor's device with a fixed address, 192.168.1.80 - which the
	// Device List's reads give to the Laptop, then the Guest phone -, answers the LAN scans of the
	// last 3 hours from a MAC address no read names.
	demoFixedGuest    = "192.168.1.80"
	demoMACFixedGuest = "00:00:5e:00:53:23"
)

// lanAtLocked is demoLAN[i] at the read at t (demoLANDevice.at), with the addresses of the
// "panel" state: the Work laptop, off, listed with the Office PC's address (192.168.1.71), and
// the E-reader, off, with the Guest phone's (192.168.1.80, where the Guest phone is off too).
func (w *demoWorld) lanAtLocked(i int, t time.Time) (listed, on bool, ipv4 string) {
	listed, on, ipv4 = demoLAN[i].at(w.created, t)
	if w.netState == "panel" && listed {
		switch demoLAN[i].name {
		case "Work laptop":
			ipv4 = "192.168.1.71"
		case "E-reader":
			ipv4 = "192.168.1.80"
		}
	}
	return listed, on, ipv4
}

// rfcBefore reports whether the RFC 3339 time a is before b (an empty or bad time is the zero time).
func rfcBefore(a, b string) bool {
	ta, _ := time.Parse(time.RFC3339Nano, a)
	tb, _ := time.Parse(time.RFC3339Nano, b)
	return ta.Before(tb)
}

// scansLocked calls fn for every LAN scan begun in [from, to): every demoScanEvery, 7 minutes past
// the hour, since the ledger started; none while the PC slept or the gateway restarted, none at all
// in the "noscans" state (connections.scan_interval 0).
func (w *demoWorld) scansLocked(from, to time.Time, fn func(t time.Time)) {
	if w.netState == "noscans" {
		return
	}
	if from.Before(w.genesis) {
		from = w.genesis
	}
	if now := time.Now(); to.After(now) {
		to = now
	}
	if w.netState == "stalescan" { // the scans stopped 2 hours ago: the newest is too old to compare
		if stop := time.Now().Add(-2 * time.Hour); to.After(stop) {
			to = stop
		}
	}
	t := from.Truncate(time.Hour).Add(7 * time.Minute)
	if t.Before(from) {
		t = t.Add(demoScanEvery)
	}
	for ; t.Before(to); t = t.Add(demoScanEvery) {
		if w.gapAt(t) || w.gatewayDownAt(t) {
			continue
		}
		fn(t)
	}
}

// scanLocked is the LAN scan begun at t: every device the Device List shows on answers at its
// address with its MAC address - but the Tablet, which sleeps and never answers; while the
// Security camera claims the Printer's address, the camera answers for it (the Printer does not);
// and since 3 hours ago the Doorbell answers at 192.168.1.77, which the gateway's list has not
// caught up with. The gateway, 192.168.1.90 and 192.168.1.50 always answer, 192.168.1.201 in the
// evenings.
func (w *demoWorld) scanLocked(t time.Time) model.LANScan {
	s := model.LANScan{At: t.UTC().Format(time.RFC3339Nano), TookMs: 2800 + int64(900*noise(t, 3300)), Subnet: "192.168.1.0/24", Self: "192.168.1.71",
		Asked: 254, Hosts: []model.LANHost{}}
	answered := map[string]string{} // address -> the MAC that answered for it
	for i, d := range demoLAN {
		listed, on, addr := w.lanAtLocked(i, t)
		if !listed || !on || addr == "" || i == 4 { // the Tablet sleeps
			continue
		}
		if i == 15 && !t.Before(w.created.Add(-3*time.Hour)) { // the Doorbell's new address
			addr = "192.168.1.77"
		}
		if _, taken := answered[addr]; taken && i != 9 {
			continue
		}
		answered[addr] = d.mac // the Security camera's answer comes first
	}
	answered[demoGateway] = demoGatewayMAC
	answered[demoUnlistedNAT] = demoMACUnlistedNA
	answered[demoUnlistedScan] = demoMACUnlistedSc
	if t.Local().Hour() >= 18 {
		answered[demoUnlistedFw] = demoMACUnlistedFw
	}
	if w.netState == "fixedguest" && !t.Before(w.created.Add(-3*time.Hour)) {
		answered[demoFixedGuest] = demoMACFixedGuest
	}
	for addr, mac := range answered {
		s.Hosts = append(s.Hosts, model.LANHost{IP: addr, MAC: mac})
	}
	sort.Slice(s.Hosts, func(a, b int) bool {
		x, _ := netip.ParseAddr(s.Hosts[a].IP)
		y, _ := netip.ParseAddr(s.Hosts[b].IP)
		return x.Less(y)
	})
	return s
}

// scansInLocked lists the LAN scans begun in [from, to), oldest first.
func (w *demoWorld) scansInLocked(from, to time.Time) []model.LANScan {
	var out []model.LANScan
	w.scansLocked(from, to, func(t time.Time) { out = append(out, w.scanLocked(t)) })
	return out
}

// newestScanLocked is the newest LAN scan (nil when there is none).
func (w *demoWorld) newestScanLocked() *model.LANScan {
	now := time.Now()
	scans := w.scansInLocked(now.Add(-3*demoScanEvery), now)
	if len(scans) == 0 {
		return nil
	}
	return &scans[len(scans)-1]
}

// listedKeysLocked is the keys of the devices the newest Device List read lists.
func (w *demoWorld) listedKeysLocked() map[string]bool {
	keys := map[string]bool{}
	if newest := w.newestDevReadLocked(); !newest.IsZero() {
		for _, d := range demoLAN {
			if listed, _, _ := d.at(w.created, newest); listed {
				keys[d.key] = true
			}
		}
	}
	return keys
}

// demoNAT is what the NAT reads of a period say of each device of demoNetDevices (by index): the
// remote addresses it reached (sites), the first and the last read that showed it with a
// connection open, and its sessions in the period's newest read (open, as netmap's Devices view
// counts them: NetDevicesView.NATAt); reads counts the period's reads, newest is the newest.
type demoNAT struct {
	sites, open []int
	first, last []time.Time
	reads       int
	newest      time.Time
}

// natDevicesLocked is what the NAT reads of [from, to) say of each device (demoNAT).
func (w *demoWorld) natDevicesLocked(from, to time.Time) demoNAT {
	plan := demoNetPlan()
	n := len(demoNetDevices)
	remotes := make([]map[string]bool, n)
	nat := demoNAT{first: make([]time.Time, n), last: make([]time.Time, n), sites: make([]int, n), open: make([]int, n)}
	first, last := nat.first, nat.last
	w.natTicksLocked(from, to, func(t time.Time) {
		nat.reads++
		nat.newest = t
		for i, f := range plan {
			if !w.flowOpenLocked(f, i, t) {
				continue
			}
			if remotes[f.dev] == nil {
				remotes[f.dev] = map[string]bool{}
			}
			remotes[f.dev][f.remote] = true
			if first[f.dev].IsZero() {
				first[f.dev] = t
			}
			last[f.dev] = t
		}
	})
	for d, m := range remotes {
		nat.sites[d] = len(m)
	}
	if !nat.newest.IsZero() {
		for i, f := range plan {
			if w.flowOpenLocked(f, i, nat.newest) {
				nat.open[f.dev] += f.sess
			}
		}
	}
	return nat
}

// Devices answers GET /api/network/devices (contracts.NetworkView) from the demo's Device List
// reads (demoLAN, every demoDevEvery), its NAT samples and its firewall drops: the gateway's newest
// table with what the period's reads say of each device (reads, addresses, connections, blocked
// packets, issues), the LAN addresses no read names and the period's address history. Without a
// syslog store ("nosyslog") nothing is counted as blocked, as netmap's view does without one.
func (w *demoWorld) Devices(ctx context.Context, q contracts.NetQuery) (model.NetDevicesView, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.devicesLocked(ctx, q)
}

// devicesLocked is the Devices view of q (Devices; Device picks one device of it).
func (w *demoWorld) devicesLocked(ctx context.Context, q contracts.NetQuery) (model.NetDevicesView, error) {
	if w.netState == "unavailable" {
		return model.NetDevicesView{}, fmt.Errorf("connstore: the connection store is closed: %w", contracts.ErrUnavailable)
	}
	dv := model.NetDevicesView{From: q.From.UTC().Format(time.RFC3339Nano), To: q.To.UTC().Format(time.RFC3339Nano),
		Devices: []model.NetLANDevice{}, Unknown: []model.NetUnknownAddr{}, Addresses: []model.NetAddrUse{}}
	newest := w.newestDevReadLocked()
	if newest.IsZero() {
		return dv, nil // no Device List read yet
	}
	dv.ListAt = newest.UTC().Format(time.RFC3339Nano)
	rfc := func(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

	// The period's reads: each device's, and the runs of reads that showed a device with an address.
	type run struct {
		use         model.NetAddrUse
		lan         int
		first, last time.Time
	}
	var runs []*run
	cur := make([]*run, len(demoLAN)) // the run each device is in, as of the read before
	reads, on := make([]int, len(demoLAN)), make([]int, len(demoLAN))
	seen := make([]time.Time, len(demoLAN))
	w.devReadsLocked(q.From, q.To, func(t time.Time) {
		dv.Reads++
		for i, d := range demoLAN {
			listed, isOn, addr := w.lanAtLocked(i, t)
			if !listed || addr == "" {
				cur[i] = nil
				if !listed {
					continue
				}
			}
			reads[i]++
			if isOn {
				on[i]++
				seen[i] = t
			}
			if addr == "" {
				continue
			}
			if r := cur[i]; r != nil && r.use.Addr == addr {
				r.last = t
				r.use.Reads++
				continue
			}
			r := &run{lan: i, first: t, last: t, use: model.NetAddrUse{Addr: addr, Device: d.key, Name: d.name, MAC: d.mac, Reads: 1}}
			runs = append(runs, r)
			cur[i] = r
		}
	})
	if err := ctx.Err(); err != nil {
		return model.NetDevicesView{}, err
	}
	nat := w.natDevicesLocked(q.From, q.To)
	dv.NATReads = nat.reads
	if nat.reads > 0 {
		dv.NATAt = rfc(nat.newest)
	}
	_, fwd, err := w.firewallLocked(ctx, q)
	if err != nil && ctx.Err() != nil {
		return model.NetDevicesView{}, ctx.Err()
	} // without a syslog store, nothing is counted as blocked
	netIdx := map[string]int{}
	for i, d := range demoNetDevices {
		netIdx[d.key] = i
	}

	// The newest read: the gateway's table, each device with what the period says about it.
	for i, d := range demoLAN {
		listed, isOn, addr := w.lanAtLocked(i, newest)
		if !listed {
			continue
		}
		x := model.NetLANDevice{Key: d.key, Name: d.name, MAC: d.mac, IPv4: addr, IPv6: slices.Clone(d.ipv6), Status: "off", Allocation: d.alloc,
			Connection: d.conn, Speed: d.speed, Mesh: d.mesh, LastActivity: d.lastActivity(i, w.created, newest), OnReads: on[i], Reads: reads[i]}
		if isOn {
			x.Status = "on"
			if strings.HasPrefix(d.conn, "Wi-Fi") {
				x.Signal = d.bars
			}
		}
		if !seen[i].IsZero() {
			x.Seen = rfc(seen[i])
		}
		for j := len(runs) - 1; j >= 0; j-- { // newest first
			if runs[j].lan == i && !slices.Contains(x.Addresses, runs[j].use.Addr) {
				x.Addresses = append(x.Addresses, runs[j].use.Addr)
			}
		}
		if n, ok := netIdx[d.key]; ok {
			x.Open, x.Sites = nat.open[n], nat.sites[n]
		}
		x.Blocked, x.BlockedIn = fwd.out[d.key], fwd.in[d.key]
		dv.Devices = append(dv.Devices, x)
	}
	// The period's LAN scans: which of them each device answered (by its MAC address), and at which
	// address the newest.
	scans := w.scansInLocked(q.From, q.To)
	dv.Scans = len(scans)
	var newestScan *model.LANScan
	if len(scans) > 0 {
		newestScan = &scans[len(scans)-1]
		dv.Scan = &model.NetScanInfo{At: newestScan.At, Subnet: newestScan.Subnet, Asked: newestScan.Asked, Answered: len(newestScan.Hosts),
			TookMs: newestScan.TookMs, Problem: newestScan.Problem}
	}
	for i := range dv.Devices {
		d := &dv.Devices[i]
		for si, s := range scans {
			for _, host := range s.Hosts {
				if host.MAC == d.MAC {
					d.ScanHits++
					d.ScanSeen = s.At
					if si == len(scans)-1 {
						d.ScanAddr = host.IP
					}
				}
			}
		}
	}
	demoIssues(dv.Devices, newest, newestScan)

	// The LAN addresses no read of the period names, the most recently seen first: one in the NAT
	// samples, one only in the firewall's drops, one only in the LAN scans; the scans give the MAC
	// address of each that answered.
	if n := netIdx["ip:"+demoUnlistedNAT]; nat.sites[n] > 0 {
		dv.Unknown = append(dv.Unknown, model.NetUnknownAddr{Addr: demoUnlistedNAT, First: rfc(nat.first[n]), Last: rfc(nat.last[n]), Open: nat.open[n],
			Sites: nat.sites[n], Blocked: fwd.out["ip:"+demoUnlistedNAT], BlockedIn: fwd.in["ip:"+demoUnlistedNAT]})
	}
	if b := fwd.out["ip:"+demoUnlistedFw]; b > 0 {
		dv.Unknown = append(dv.Unknown, model.NetUnknownAddr{Addr: demoUnlistedFw, First: rfc(fwd.strayFirst), Last: rfc(fwd.strayLast), Blocked: b})
	}
	named := map[string]bool{} // the MAC addresses the Device List names
	for _, d := range demoLAN {
		named[d.mac] = true
	}
	held := map[string]bool{} // the addresses some read of the period gives a device
	for _, r := range runs {
		held[r.use.Addr] = true
	}
	hits := map[string]int{} // the scans each unknown address answered
	for _, s := range scans {
		for _, host := range s.Hosts {
			if named[host.MAC] || host.IP == demoGateway {
				continue
			}
			hits[host.IP]++
			j := slices.IndexFunc(dv.Unknown, func(u model.NetUnknownAddr) bool { return u.Addr == host.IP })
			if j < 0 {
				dv.Unknown = append(dv.Unknown, model.NetUnknownAddr{Addr: host.IP})
				j = len(dv.Unknown) - 1
			}
			u := &dv.Unknown[j]
			u.MAC, u.ScanSeen = host.MAC, s.At // the newest scan that found it
			if u.First == "" || rfcBefore(s.At, u.First) {
				u.First = s.At
			}
			if rfcBefore(u.Last, s.At) {
				u.Last = s.At
			}
		}
	}
	for i := range dv.Unknown {
		u := &dv.Unknown[i]
		u.Issues = []model.NetIssue{demoUnlistedIssue(*u, u.Sites > 0, hits[u.Addr], held[u.Addr])}
	}
	sort.SliceStable(dv.Unknown, func(a, b int) bool { return rfcBefore(dv.Unknown[b].Last, dv.Unknown[a].Last) })
	unknownTotal := len(dv.Unknown)
	if limit := q.Limit; limit > 0 && len(dv.Unknown) > limit {
		dv.Unknown = dv.Unknown[:limit]
	}

	// The address history: by address, then by first use.
	key4 := func(a string) uint32 {
		ip, err := netip.ParseAddr(a)
		if err != nil || !ip.Is4() {
			return math.MaxUint32
		}
		b := ip.As4()
		return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	}
	sort.SliceStable(runs, func(a, b int) bool {
		if ka, kb := key4(runs[a].use.Addr), key4(runs[b].use.Addr); ka != kb {
			return ka < kb
		}
		return runs[a].first.Before(runs[b].first)
	})
	for _, r := range runs {
		r.use.First, r.use.Last = rfc(r.first), rfc(r.last)
		dv.Addresses = append(dv.Addresses, r.use)
	}

	// The tiles, as netmap counts them: each unknown address has the warning "unlisted".
	dv.Totals = model.NetDeviceTotals{Listed: len(dv.Devices), Issues: unknownTotal, Unknown: unknownTotal}
	if newestScan != nil {
		dv.Totals.Scanned = len(newestScan.Hosts)
	}
	for _, x := range dv.Devices {
		if x.Status == "on" {
			dv.Totals.Online++
		}
		switch {
		case strings.HasPrefix(x.Connection, "Wi-Fi"):
			dv.Totals.WiFi++
		case strings.HasPrefix(x.Connection, "Ethernet"):
			dv.Totals.Wired++
		}
		if demoIssueRank(x.Issues) <= 1 {
			dv.Totals.Issues++
		}
	}
	demoSortDevices(dv.Devices)
	if w.hostile != "" {
		hostileDevices(&dv, w.hostile)
	}
	return dv, nil
}

// Device answers GET /api/network/device (contracts.NetworkView; docs/dhcp-table.md §7): one device
// of the Devices view (key) or one of its unknown addresses (addr) over q - who held its addresses
// in the period (itself and others), the period's LAN scans as it answered them, newest first, and
// what its syslog messages are found by: each IPv4 address it held, while it held it (widened by
// one Device List interval on each side, within the period), its IPv6 addresses and its MAC
// address; an unknown address by itself. The web layer reads the messages (Syslog).
func (w *demoWorld) Device(ctx context.Context, q contracts.NetQuery, key, addr string) (model.NetDeviceDetail, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	all := q
	all.Limit = 0 // every unknown address
	dv, err := w.devicesLocked(ctx, all)
	if err != nil {
		return model.NetDeviceDetail{}, err
	}
	rfc := func(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
	dd := model.NetDeviceDetail{From: dv.From, To: dv.To, Addresses: []model.NetAddrUse{}, Scans: []model.NetScanSeen{}, Match: []model.NetSyslogTerm{},
		Syslog: []model.SyslogEntry{}}
	scans := w.scansInLocked(q.From, q.To)
	switch {
	case key != "":
		i := slices.IndexFunc(dv.Devices, func(d model.NetLANDevice) bool { return d.Key == key })
		if i < 0 {
			return model.NetDeviceDetail{}, fmt.Errorf("demo: no device %q in the Device List: %w", key, contracts.ErrNotFound)
		}
		d := dv.Devices[i]
		dd.Device = &d
		held := map[string]bool{d.IPv4: d.IPv4 != ""}
		for _, a := range d.Addresses {
			held[a] = true
		}
		for _, u := range dv.Addresses {
			if held[u.Addr] {
				dd.Addresses = append(dd.Addresses, u)
			}
		}
		for j := len(scans) - 1; j >= 0; j-- {
			seen := model.NetScanSeen{At: scans[j].At}
			for _, host := range scans[j].Hosts {
				if host.MAC == d.MAC {
					seen.Addr = host.IP
				}
			}
			dd.Scans = append(dd.Scans, seen)
		}
		for _, u := range dv.Addresses {
			if u.Device != d.Key {
				continue
			}
			term := model.NetSyslogTerm{Kind: "ipv4", Text: u.Addr}
			if first, err := time.Parse(time.RFC3339Nano, u.First); err == nil && first.Add(-demoDevEvery).After(q.From) {
				term.From = rfc(first.Add(-demoDevEvery))
			}
			if last, err := time.Parse(time.RFC3339Nano, u.Last); err == nil && last.Add(demoDevEvery).Before(q.To) {
				term.To = rfc(last.Add(demoDevEvery))
			}
			dd.Match = append(dd.Match, term)
		}
		for _, a := range d.IPv6 {
			dd.Match = append(dd.Match, model.NetSyslogTerm{Kind: "ipv6", Text: a})
		}
		if d.MAC != "" {
			dd.Match = append(dd.Match, model.NetSyslogTerm{Kind: "mac", Text: d.MAC})
		}
	case addr != "":
		i := slices.IndexFunc(dv.Unknown, func(u model.NetUnknownAddr) bool { return u.Addr == addr })
		if i < 0 {
			return model.NetDeviceDetail{}, fmt.Errorf("demo: no unknown address %q in this period: %w", addr, contracts.ErrNotFound)
		}
		u := dv.Unknown[i]
		dd.Unknown = &u
		for _, h := range dv.Addresses {
			if h.Addr == addr {
				dd.Addresses = append(dd.Addresses, h)
			}
		}
		for j := len(scans) - 1; j >= 0; j-- {
			seen := model.NetScanSeen{At: scans[j].At}
			if slices.ContainsFunc(scans[j].Hosts, func(host model.LANHost) bool { return host.IP == addr }) {
				seen.Addr = addr
			}
			dd.Scans = append(dd.Scans, seen)
		}
		dd.Match = append(dd.Match, model.NetSyslogTerm{Kind: "ipv4", Text: addr})
	default:
		return model.NetDeviceDetail{}, fmt.Errorf("demo: neither a device nor an address: %w", contracts.ErrNotFound)
	}
	return dd, nil
}

// The demo's issues follow netmap's rules and words (internal/netmap/devissues.go), so that the
// Devices tab shows what the service will send: an address claimed by another entry of the newest
// read that is not off (critical), a Wi-Fi signal of 2 bars or fewer, a wired link at 10 Mb/s or
// half duplex, 100 or more packets dropped by the firewall in the period (warnings), more than one
// IPv4 address in the period, off in the newest read (information).

// demoIssueLevel is the rank of an issue level: critical 0, warning 1, anything else 2.
func demoIssueLevel(level string) int {
	switch level {
	case model.IssueCritical:
		return 0
	case model.IssueWarning:
		return 1
	}
	return 2
}

// demoIssueRank is the rank of the most severe of issues (3 without any).
func demoIssueRank(issues []model.NetIssue) int {
	r := 3
	for _, x := range issues {
		r = min(r, demoIssueLevel(x.Level))
	}
	return r
}

// demoIssues gives each device of the newest read (made at listAt) its issues, the most severe
// first; scan is the period's newest LAN scan (nil without one).
func demoIssues(devs []model.NetLANDevice, listAt time.Time, scan *model.LANScan) {
	claims := map[string][]int{} // the entries not shown off that claim each IPv4 address
	for i, d := range devs {
		if d.IPv4 != "" && d.Status != "off" {
			claims[d.IPv4] = append(claims[d.IPv4], i)
		}
	}
	who := func(d model.NetLANDevice) string { return d.Name + " (" + d.MAC + ")" }
	others := func(addr string, self int) []string {
		var out []string
		for _, j := range claims[addr] {
			if j != self {
				out = append(out, who(devs[j]))
			}
		}
		return out
	}
	order := map[string]int{model.IssueAddressShared: 0, model.IssueUnlisted: 1, model.IssueScanMAC: 2, model.IssueBlocked: 3, model.IssueWeakWiFi: 4,
		model.IssueSlowLink: 5, model.IssueScanAddr: 6, model.IssueNoAnswer: 7, model.IssueAddressChanged: 8, model.IssueOffline: 9}
	// The newest scan's answers (when it was made within an hour of the newest read), by address,
	// and the names the newest read gives the MAC addresses.
	var answered map[string]string
	var scanWhen string // when the newest scan was made, from the newest read ("23 min before")
	if scan != nil {
		if at, err := time.Parse(time.RFC3339Nano, scan.At); err == nil && listAt.Sub(at) <= time.Hour && at.Sub(listAt) <= time.Hour {
			answered = map[string]string{}
			for _, host := range scan.Hosts {
				answered[host.IP] = host.MAC
			}
			if apart := at.Sub(listAt); apart < 0 {
				scanWhen = demoSpanWords(-apart) + " before"
			} else {
				scanWhen = demoSpanWords(apart) + " after"
			}
		}
	}
	nameOf := map[string]string{}
	for _, d := range devs {
		nameOf[d.MAC] = d.Name
	}
	for i := range devs {
		d := &devs[i]
		issues := []model.NetIssue{}
		if o := others(d.IPv4, i); d.IPv4 != "" && d.Status != "off" && len(o) > 0 {
			issues = append(issues, model.NetIssue{Code: model.IssueAddressShared, Level: model.IssueCritical,
				Text: d.IPv4 + " is also claimed by " + demoJoinAnd(o) + " in the newest Device List read (an address conflict)."})
		}
		if d.Signal >= 1 && d.Signal <= 2 {
			issues = append(issues, model.NetIssue{Code: model.IssueWeakWiFi, Level: model.IssueWarning,
				Text: fmt.Sprintf("Its Wi-Fi signal is weak: the gateway draws it with %s of 5 (%s).", demoPlural(d.Signal, "bar", "bars"), d.Connection)})
		}
		if d.Speed != "" && !strings.HasPrefix(d.Connection, "Wi-Fi") {
			mbps, _ := strconv.Atoi(strings.TrimRight(strings.Fields(d.Speed)[0], "Mbps"))
			half := strings.Contains(d.Speed, "half")
			if (mbps > 0 && mbps <= 10) || half {
				var how []string
				if mbps > 0 {
					how = append(how, strconv.Itoa(mbps)+" Mb/s")
				}
				if half {
					how = append(how, "half duplex")
				}
				issues = append(issues, model.NetIssue{Code: model.IssueSlowLink, Level: model.IssueWarning,
					Text: fmt.Sprintf("Its Ethernet link runs at %s (the gateway shows %q); Ethernet normally runs at 100 or 1000 Mb/s, full duplex.", strings.Join(how, ", "), d.Speed)})
			}
		}
		if d.Blocked+d.BlockedIn >= 100 {
			issues = append(issues, model.NetIssue{Code: model.IssueBlocked, Level: model.IssueWarning,
				Text: fmt.Sprintf("In this period the gateway's firewall dropped %s it sent toward the Internet and %s sent to it from the Internet.",
					demoPlural(d.Blocked, "packet", "packets"), demoPlural(d.BlockedIn, "packet", "packets"))})
		}
		if len(d.Addresses) > 1 {
			issues = append(issues, model.NetIssue{Code: model.IssueAddressChanged, Level: model.IssueInfo,
				Text: fmt.Sprintf("It held %d IPv4 addresses in this period, the newest first: %s.", len(d.Addresses), strings.Join(d.Addresses, ", "))})
		}
		// The newest scan, as netmap compares it (devscans.go scanIssues): no_answer or scan_addr,
		// and scan_mac besides.
		if answered != nil {
			on, ip := d.Status == "on", d.IPv4
			switch {
			case d.ScanAddr == "":
				if on && ip != "" {
					issues = append(issues, model.NetIssue{Code: model.IssueNoAnswer, Level: model.IssueInfo,
						Text: "The newest Device List read shows it on, but it did not answer the newest LAN scan (made " + scanWhen + " that read); a device that sleeps may not answer."})
				}
			case d.MAC != "" && d.ScanAddr != ip:
				text := "It answered the newest LAN scan at " + d.ScanAddr + ", not at " + ip + ", the address the gateway lists for it."
				if ip == "" {
					text = "It answered the newest LAN scan at " + d.ScanAddr + "; the gateway lists no IPv4 address for it."
				}
				issues = append(issues, model.NetIssue{Code: model.IssueScanAddr, Level: model.IssueInfo, Text: text})
			}
			if mac, ok := answered[ip]; d.MAC != "" && ip != "" && on && ok && mac != "" && mac != d.MAC && ip != demoGateway {
				text := "The newest LAN scan found " + ip + " answered by another MAC address, " + mac
				if n := nameOf[mac]; n != "" {
					text += ", which the newest Device List read gives to " + n + ": two devices may be using the address, or the list is out of date."
				} else {
					text += ", which no Device List read of this period names: a device the gateway does not list may be using the address."
				}
				issues = append(issues, model.NetIssue{Code: model.IssueScanMAC, Level: model.IssueWarning, Text: text})
			}
		}
		if d.Status == "off" {
			text := "The newest Device List read shows it off"
			if seen, err := time.Parse(time.RFC3339Nano, d.Seen); err == nil {
				text += "; the last read that showed it on was made " + demoSpanWords(listAt.Sub(seen)) + " before."
			} else {
				text += ", and no read of this period showed it on."
			}
			if d.LastActivity != "" {
				text += " The gateway gives its last activity as " + d.LastActivity + "."
			}
			if o := others(d.IPv4, i); d.IPv4 != "" && len(o) > 0 {
				text += " Its last address, " + d.IPv4 + ", is now claimed by " + demoJoinAnd(o) + "."
			}
			issues = append(issues, model.NetIssue{Code: model.IssueOffline, Level: model.IssueInfo, Text: text})
		}
		sort.SliceStable(issues, func(a, b int) bool {
			if la, lb := demoIssueLevel(issues[a].Level), demoIssueLevel(issues[b].Level); la != lb {
				return la < lb
			}
			return order[issues[a].Code] < order[issues[b].Code]
		})
		d.Issues = issues
	}
}

// demoUnlistedIssue is the issue "unlisted" of an unknown address, as netmap words it
// (devissues.go unknownIssue): what showed it - the NAT samples (nat), the firewall's drops, the
// LAN scans (scans: how many of the period's it answered, from u.MAC) - and what it may be. named:
// Device List reads of the period give the address to a device (what no read names is the MAC
// address that answered for it).
func demoUnlistedIssue(u model.NetUnknownAddr, nat bool, scans int, named bool) model.NetIssue {
	const fixed = " Perhaps a device with a fixed address, which the gateway does not list."
	mac := u.MAC
	if mac == "" {
		mac = "a MAC address that is not valid"
	}
	if named && scans > 0 {
		return model.NetIssue{Code: model.IssueUnlisted, Level: model.IssueWarning,
			Text: fmt.Sprintf("%s answered %s of this period from %s, which no Device List read of this period names (the reads give the address to another device).",
				u.Addr, demoPlural(scans, "LAN scan", "LAN scans"), mac) + fixed}
	}
	var seen []string
	if nat {
		s := "the NAT table showed its connections"
		if u.Open > 0 {
			s += " (" + demoPlural(u.Open, "open connection", "open connections") + " in the newest read)"
		}
		seen = append(seen, s)
	}
	switch {
	case u.Blocked > 0 && u.BlockedIn > 0:
		seen = append(seen, fmt.Sprintf("the gateway's firewall dropped %s it sent and %s sent to it from the Internet",
			demoPlural(u.Blocked, "packet", "packets"), demoPlural(u.BlockedIn, "packet", "packets")))
	case u.Blocked > 0:
		seen = append(seen, "the gateway's firewall dropped "+demoPlural(u.Blocked, "packet", "packets")+" it sent")
	case u.BlockedIn > 0:
		seen = append(seen, "the gateway's firewall dropped "+demoPlural(u.BlockedIn, "packet", "packets")+" sent to it from the Internet")
	}
	if scans > 0 {
		seen = append(seen, "it answered "+demoPlural(scans, "LAN scan", "LAN scans")+" of this period (from "+mac+")")
	}
	text := "No Device List read of this period names " + u.Addr
	if len(seen) > 0 {
		text += ", yet " + demoJoinAnd(seen)
	}
	text += "."
	if a, err := netip.ParseAddr(u.Addr); err == nil && a.Is4() && a.IsLinkLocalUnicast() {
		text += " A device gives itself an address in 169.254.0.0/16 when it gets none from the gateway's DHCP server."
	} else if scans > 0 {
		text += fixed
	}
	return model.NetIssue{Code: model.IssueUnlisted, Level: model.IssueWarning, Text: text}
}

// demoSortDevices orders the devices as netmap does: those with a critical issue, then those with
// a warning, then the others; within each, on before the others and off last; then by name.
func demoSortDevices(devs []model.NetLANDevice) {
	status := func(d model.NetLANDevice) int {
		switch d.Status {
		case "on":
			return 0
		case "off":
			return 2
		}
		return 1
	}
	sort.SliceStable(devs, func(a, b int) bool {
		x, y := devs[a], devs[b]
		if rx, ry := min(demoIssueRank(x.Issues), 2), min(demoIssueRank(y.Issues), 2); rx != ry {
			return rx < ry
		}
		if sx, sy := status(x), status(y); sx != sy {
			return sx < sy
		}
		return strings.ToLower(x.Name) < strings.ToLower(y.Name)
	})
}

// demoPlural writes n and the noun in its form for n ("1 bar", "2 bars").
func demoPlural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// demoJoinAnd joins names as a sentence lists them: "a", "a and b", "a, b and c".
func demoJoinAnd(names []string) string {
	if len(names) < 2 {
		return strings.Join(names, "")
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

// demoSpanWords says how long d is in round words, as netmap's span does: "40 min", "2 h 15 min",
// "3 days 4 h".
func demoSpanWords(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "less than a minute"
	case d < time.Hour:
		return strconv.Itoa(int(d/time.Minute)) + " min"
	case d < 24*time.Hour:
		h, m := int(d/time.Hour), int(d%time.Hour/time.Minute)
		if m == 0 {
			return strconv.Itoa(h) + " h"
		}
		return strconv.Itoa(h) + " h " + strconv.Itoa(m) + " min"
	}
	s := demoPlural(int(d/(24*time.Hour)), "day", "days")
	if h := int(d % (24 * time.Hour) / time.Hour); h > 0 {
		s += " " + strconv.Itoa(h) + " h"
	}
	return s
}

// connStoreLocked is the demo's connection store: a file a day since the ledger started.
func (w *demoWorld) connStoreLocked(now time.Time) *model.ConnStoreUsage {
	days := int(now.Sub(w.genesis).Hours()/24) + 1
	s := &model.ConnStoreUsage{Bytes: int64(days) * 412_000, Files: days, KeepDays: 30, KeepMB: 200,
		Oldest: w.genesis.Truncate(demoNATEvery).Add(demoNATEvery).UTC().Format(time.RFC3339Nano),
		Newest: now.Truncate(demoNATEvery).UTC().Format(time.RFC3339Nano)}
	if w.netState == "nosamples" {
		s.Bytes, s.Files, s.Oldest, s.Newest = 0, 0, "", ""
	}
	return s
}

// connSamplersLocked is Status.Connections: the NAT table and Device List reads.
func (w *demoWorld) connSamplersLocked(now time.Time) *model.ConnSamplerStatus {
	last := now.Truncate(demoNATEvery)
	s := &model.ConnSamplerStatus{Enabled: true, Interval: "4m0s", DevicesInterval: "15m0s",
		NATAt: last.UTC().Format(time.RFC3339Nano), NATNext: last.Add(demoNATEvery).UTC().Format(time.RFC3339Nano),
		Devices: len(w.listedKeysLocked()), Store: w.connStoreLocked(now), ScanInterval: "1h0m0s"}
	if t := w.newestDevReadLocked(); !t.IsZero() {
		s.DevicesAt = t.UTC().Format(time.RFC3339Nano)
	}
	// The LAN scan (docs/dhcp-table.md §6): the newest sweep and when the next is due; none in
	// "noscans" (connections.scan_interval 0).
	if w.netState == "noscans" {
		s.ScanInterval = ""
	} else if scan := w.newestScanLocked(); scan != nil {
		s.ScanAt, s.ScanHosts = scan.At, len(scan.Hosts)
		if at, err := time.Parse(time.RFC3339Nano, scan.At); err == nil {
			s.ScanNext = at.Add(demoScanEvery).UTC().Format(time.RFC3339Nano)
		}
	}
	plan := demoNetPlan()
	for i, f := range plan {
		if w.flowOpenLocked(f, i, last) {
			s.Sessions += f.sess
		}
	}
	s.InUse, s.Available = s.Sessions+7, 8192-s.Sessions-7
	switch w.netState {
	case "off":
		s.Enabled = false
		s.NATNext = ""
	case "paused":
		s.NATAt = last.Add(-3 * time.Hour).UTC().Format(time.RFC3339Nano)
		s.NATProblem = "gateway logins are paused after repeated rejected access codes (at most 3 attempts per hour); the NAT table is read again when they resume"
	case "noaccess":
		s.NATAt = ""
		s.NATProblem = "no gateway device access code is stored, so the NAT table (which needs the gateway login) cannot be read; store it with att-monitor set-access-code"
	case "nosamples":
		s.NATAt, s.Sessions, s.InUse, s.Available = "", 0, 0, 0
		s.NATNext = now.Add(90 * time.Second).UTC().Format(time.RFC3339Nano)
	case "natnote":
		s.NATNote = "3 rows of the NAT table page left out (not understood)"
	}
	return s
}

// NetworkStatus answers GET /api/network/status (contracts.NetworkView); the samplers come from
// Status, as the web layer adds them.
func (w *demoWorld) NetworkStatus() model.NetworkStatus {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()
	db := demoIPDB(now)
	ns := model.NetworkStatus{
		Store: w.connStoreLocked(now),
		IPIntel: &model.IPIntelStatus{Enabled: true, Download: true, Source: "https://iptoasn.com/data/ip2asn-v4.tsv.gz", Loaded: true,
			V4Ranges: 504211, V6Ranges: 132876, Updated: db.Format(time.RFC3339), Checked: db.Add(10 * time.Minute).Format(time.RFC3339),
			Next: db.Add(7*24*time.Hour + 10*time.Minute).Format(time.RFC3339), ReverseDNS: true, PTRCached: 37},
	}
	if w.netState == "noipdb" {
		ns.IPIntel.Loaded, ns.IPIntel.V4Ranges, ns.IPIntel.V6Ranges, ns.IPIntel.Updated = false, 0, 0, ""
		ns.IPIntel.Error = "download ip2asn-v4.tsv.gz: dial tcp: lookup iptoasn.com: no such host"
	}
	if w.netState != "nosyslog" {
		u := w.syslogUsageLocked()
		ns.Syslog = &u
	}
	if w.netState == "cfgwarn" {
		// As config.Load words them (config.Warnings), one sentence each.
		ns.ConfigWarnings = []string{
			"connections.interval is 10m0s, above the maximum: 4m0s is used",
			"geo.download is not true or false: it is turned off",
		}
	}
	if w.hostile != "" {
		ns.IPIntel.Error = hostileWord(w.hostile, ns.IPIntel.Error)
		ns.Store.Error = hostileWord(w.hostile, "")
		ns.ConfigWarnings = append(ns.ConfigWarnings, hostileWord(w.hostile, "connections.keep_mb is 0, below the minimum: 10 is used"))
	}
	return ns
}

// hostileWord appends the marker to s (also to an empty s).
func hostileWord(marker, s string) string {
	if s == "" {
		return marker
	}
	return s + " " + marker
}

// hostileConnections puts the marker into what the gateway (device names, LAN addresses), the IP
// database (organisation names) and reverse DNS (PTR names) control, and gives one row a country
// that is no code; keys and the codes the dashboard computes with stay as they are.
func hostileConnections(nc *model.NetConnections, marker string) {
	for i := range nc.Devices {
		nc.Devices[i].Name = hostileWord(marker, nc.Devices[i].Name)
	}
	for i := range nc.Orgs {
		nc.Orgs[i].Name = hostileWord(marker, nc.Orgs[i].Name)
	}
	for i := range nc.Services {
		nc.Services[i].Name = hostileWord(marker, nc.Services[i].Name)
	}
	for i := range nc.Rows {
		r := &nc.Rows[i]
		r.PTR, r.Org = hostileWord(marker, r.PTR), hostileWord(marker, r.Org)
		if r.Service != "" {
			r.Service = hostileWord(marker, r.Service)
		}
		if i == 0 {
			r.Country = "Z9 " + marker
		}
	}
	nc.Countries = append(nc.Countries, model.NetCountry{Code: "Z9 " + marker, Sites: 1, Weight: 1})
}

// hostileFirewall does the same for the firewall view: the gateway's reasons and their labels,
// the sources' organisations, the devices' names, a country that is no code.
func hostileFirewall(fw *model.NetFirewall, marker string) {
	for i := range fw.TopSources {
		fw.TopSources[i].Org = hostileWord(marker, fw.TopSources[i].Org)
	}
	if len(fw.TopSources) > 0 {
		fw.TopSources[0].Country = "Z9 " + marker
	}
	for i := range fw.Services {
		fw.Services[i].Name = hostileWord(marker, fw.Services[i].Name)
	}
	for i := range fw.Reasons {
		fw.Reasons[i].Reason, fw.Reasons[i].Label = hostileWord(marker, fw.Reasons[i].Reason), hostileWord(marker, fw.Reasons[i].Label)
	}
	for i := range fw.OutboundRows {
		r := &fw.OutboundRows[i]
		r.Name, r.Org, r.Reason, r.Label = hostileWord(marker, r.Name), hostileWord(marker, r.Org), hostileWord(marker, r.Reason), hostileWord(marker, r.Label)
	}
	fw.Countries = append(fw.Countries, model.NetCountry{Code: "Z9 " + marker, Sites: 1, Weight: 1})
}

// hostileDevices does the same for the Devices tab: what the gateway's Device List shows (names,
// connections, speeds, allocations, last activities, and one device's status, which the dashboard
// must then show as it is) and the issues' sentences, which name devices; keys, MAC, IPv4 and IPv6
// addresses, issue codes and levels and the times stay as they are.
func hostileDevices(dv *model.NetDevicesView, marker string) {
	for i := range dv.Devices {
		d := &dv.Devices[i]
		d.Name, d.Connection, d.Allocation, d.LastActivity = hostileWord(marker, d.Name), hostileWord(marker, d.Connection),
			hostileWord(marker, d.Allocation), hostileWord(marker, d.LastActivity)
		if d.Speed != "" {
			d.Speed = hostileWord(marker, d.Speed)
		}
		for j := range d.Issues {
			d.Issues[j].Text = hostileWord(marker, d.Issues[j].Text)
		}
		if d.Key == demoLAN[15].key { // the doorbell, on
			d.Status = hostileWord(marker, d.Status)
		}
	}
	for i := range dv.Unknown {
		for j := range dv.Unknown[i].Issues {
			dv.Unknown[i].Issues[j].Text = hostileWord(marker, dv.Unknown[i].Issues[j].Text)
		}
	}
	for i := range dv.Addresses {
		dv.Addresses[i].Name = hostileWord(marker, dv.Addresses[i].Name)
	}
}

// demoAddrsValid reports whether every address of the plan is a documentation address (the
// repository is public: no real address may appear in the demo).
func demoAddrsValid() error {
	doc := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24")}
	check := func(s string) error {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return err
		}
		if !slices.ContainsFunc(doc, func(p netip.Prefix) bool { return p.Contains(a) }) {
			return fmt.Errorf("%s is not a documentation address", s)
		}
		return nil
	}
	seen := map[string]int{}
	for i, f := range demoNetPlan() {
		if err := check(f.remote); err != nil {
			return err
		}
		if j, dup := seen[f.remote]; dup {
			return fmt.Errorf("flows %d and %d share %s", j, i, f.remote)
		}
		seen[f.remote] = i
	}
	for _, s := range demoFwSources {
		if err := check(s.addr); err != nil {
			return err
		}
	}
	for _, d := range demoNetDevices {
		if d.ipv4 != "" && !strings.HasPrefix(d.ipv4, "192.168.1.") {
			return fmt.Errorf("device %s: %s is not a 192.168.1.x address", d.name, d.ipv4)
		}
		if d.mac != "" && !strings.HasPrefix(d.mac, "00:00:5e:00:53:") {
			return fmt.Errorf("device %s: %s is not a documentation MAC address", d.name, d.mac)
		}
	}
	// The Device List: documentation values, in the reader's forms (lower-case MAC addresses,
	// canonical IPv6 addresses), each device's key made of its MAC address.
	v6 := netip.MustParsePrefix("2001:db8::/32")
	macs := map[string]bool{}
	for _, d := range append(slices.Clone(demoLAN), demoLANDevice{name: "unlisted", mac: "00:00:5e:00:53:00", addrs: []demoLease{{demoUnlistedNAT, 0}, {demoUnlistedFw, 0}}}) {
		if !regexp.MustCompile(`^00:00:5e:00:53:[0-9a-f]{2}$`).MatchString(d.mac) || (d.key != "" && d.key != "mac:"+d.mac) || macs[d.mac] {
			return fmt.Errorf("Device List entry %s: MAC %q, key %q", d.name, d.mac, d.key)
		}
		macs[d.mac] = true
		for _, l := range d.addrs {
			if a, err := netip.ParseAddr(l.addr); err != nil || !a.Is4() || !strings.HasPrefix(l.addr, "192.168.1.") || a.String() != l.addr {
				return fmt.Errorf("Device List entry %s: %q is not a 192.168.1.x address", d.name, l.addr)
			}
		}
		for _, s := range d.ipv6 {
			if a, err := netip.ParseAddr(s); err != nil || !v6.Contains(a) || a.String() != s {
				return fmt.Errorf("Device List entry %s: %q is not a canonical 2001:db8::/32 address", d.name, s)
			}
		}
	}
	return nil
}

// checkDemoNetwork runs the network endpoints against the demo world (TestDemoWorldEndpoints):
// the answers decode strictly into the model, and the demo's data are self-consistent - every
// band names a node, the columns of the flow diagram add up to the same weight, the lists are in
// their order, the firewall's hours add up to its totals - so that the visual checks show what a
// real view would.
func checkDemoNetwork(t *testing.T, w *demoWorld, h http.Handler, ok func(*httptest.ResponseRecorder, int) []byte, strict func([]byte, any)) {
	t.Helper()
	if err := demoAddrsValid(); err != nil {
		t.Fatal(err)
	}
	var ns model.NetworkStatus
	strict(ok(demoGet(t, h, "GET", "/api/network/status", ""), 200), &ns)
	if ns.Samplers == nil || !ns.Samplers.Enabled || ns.Samplers.Interval != "4m0s" || ns.Samplers.Devices != demoListed || ns.Samplers.DevicesAt == "" ||
		ns.Store == nil || ns.Store.KeepDays != 30 || ns.IPIntel == nil || !ns.IPIntel.Loaded || ns.Syslog == nil || ns.Syslog.Oldest == "" {
		t.Errorf("network status: %+v", ns)
	}
	checkDemoDevices(t, w, h, ok, strict)

	sum := func(n int, f func(i int) int) int {
		total := 0
		for i := 0; i < n; i++ {
			total += f(i)
		}
		return total
	}
	for _, rng := range NetworkRanges {
		var nc model.NetConnections
		strict(ok(demoGet(t, h, "GET", "/api/network/connections?range="+rng+"&limit=1000", ""), 200), &nc)
		devs, orgs, svcs := map[string]bool{}, map[string]bool{}, map[string]bool{}
		for _, d := range nc.Devices {
			devs[d.Key] = true
		}
		for _, o := range nc.Orgs {
			orgs[o.Key] = true
		}
		for _, s := range nc.Services {
			svcs[s.Key] = true
		}
		in, out := 0, 0
		for _, l := range nc.Links {
			switch {
			case devs[l.From] && orgs[l.To]:
				in += l.Weight
			case orgs[l.From] && svcs[l.To]:
				out += l.Weight
			default:
				t.Errorf("%s: band %+v names no node", rng, l)
			}
		}
		total := sum(len(nc.Devices), func(i int) int { return nc.Devices[i].Weight })
		if nc.Samples == 0 || len(nc.Devices) < 6 || len(nc.Orgs) < 6 || len(nc.Services) < 3 || in == 0 || in != out || in != total ||
			in != sum(len(nc.Orgs), func(i int) int { return nc.Orgs[i].Weight }) || in != sum(len(nc.Services), func(i int) int { return nc.Services[i].Weight }) ||
			in != sum(len(nc.Countries), func(i int) int { return nc.Countries[i].Weight }) {
			t.Errorf("%s: %d reads, %d devices, %d organisations, %d services; weights: devices %d, bands in %d, out %d", rng, nc.Samples,
				len(nc.Devices), len(nc.Orgs), len(nc.Services), total, in, out)
		}
		if nc.Totals.Devices != len(nc.Devices) || nc.Totals.Sites < len(nc.Countries) || nc.Totals.Orgs < 8 || nc.Totals.Countries < 5 ||
			nc.RowsTotal != len(nc.Rows) || nc.RowsTotal < nc.Totals.Sites || nc.Open <= 0 || nc.InUse < nc.Open || nc.Available <= 0 {
			t.Errorf("%s: totals %+v, %d of %d rows, open %d, in use %d, available %d", rng, nc.Totals, len(nc.Rows), nc.RowsTotal, nc.Open, nc.InUse, nc.Available)
		}
		for i, r := range nc.Rows {
			if !devs[r.Device] || r.Samples < 1 || r.Weight < r.Samples || r.First > r.Last || r.Kind != model.IPKindPublic || (i > 0 && nc.Rows[i-1].Samples < r.Samples) {
				t.Fatalf("%s: row %d: %+v", rng, i, r)
			}
		}
		for i := 1; i < len(nc.Countries); i++ {
			if nc.Countries[i-1].Sites < nc.Countries[i].Sites {
				t.Fatalf("%s: countries not by sites: %+v", rng, nc.Countries)
			}
		}
		if _, err := time.Parse(time.RFC3339, nc.IPDB); err != nil {
			t.Errorf("%s: ipdb %q", rng, nc.IPDB)
		}
	}

	// A device filter keeps every device in the list (for the filter) and that device's flows only.
	var all, one model.NetConnections
	strict(ok(demoGet(t, h, "GET", "/api/network/connections?range=7d", ""), 200), &all)
	key := all.Devices[1].Key
	strict(ok(demoGet(t, h, "GET", "/api/network/connections?range=7d&device="+url.QueryEscape(key), ""), 200), &one)
	if one.Device != key || len(one.Devices) != len(all.Devices) || one.Totals.Devices != 1 || one.Samples != all.Samples || len(one.Rows) == 0 {
		t.Errorf("filtered to %s: device %q, %d devices, totals %+v", key, one.Device, len(one.Devices), one.Totals)
	}
	for _, r := range one.Rows {
		if r.Device != key {
			t.Fatalf("filtered to %s: row of %s", key, r.Device)
		}
	}
	for _, l := range one.Links {
		if strings.HasPrefix(l.From, "mac:") && l.From != key {
			t.Fatalf("filtered to %s: band from %s", key, l.From)
		}
	}
	strict(ok(demoGet(t, h, "GET", "/api/network/connections?range=24h&device="+url.QueryEscape("mac:00:00:5e:00:53:ff"), ""), 200), &one)
	if len(one.Rows) != 0 || len(one.Links) != 0 || one.Totals.Devices != 0 || len(one.Devices) == 0 {
		t.Errorf("an unknown device: %+v", one.Totals)
	}

	for _, rng := range []string{"1h", "24h", "30d"} {
		var fw model.NetFirewall
		strict(ok(demoGet(t, h, "GET", "/api/network/firewall?range="+rng+"&limit=1000", ""), 200), &fw)
		hoursIn := sum(len(fw.Hours), func(i int) int { return fw.Hours[i].In })
		hoursOut := sum(len(fw.Hours), func(i int) int { return fw.Hours[i].Out })
		hoursLocal := sum(len(fw.Hours), func(i int) int { return fw.Hours[i].Local })
		span := networkRangeSpan[rng]
		if len(fw.Hours) < int(span/time.Hour) || len(fw.Hours) > int(span/time.Hour)+1 || hoursIn != fw.Inbound || hoursOut != fw.Outbound || hoursLocal != fw.Local ||
			fw.Drops != fw.Inbound+fw.Outbound+fw.Local || fw.Inbound == 0 || fw.Sources == 0 {
			t.Errorf("%s: %d hours; in %d/%d, out %d/%d, local %d/%d, drops %d, sources %d", rng, len(fw.Hours), hoursIn, fw.Inbound, hoursOut, fw.Outbound,
				hoursLocal, fw.Local, fw.Drops, fw.Sources)
		}
		if c := sum(len(fw.Countries), func(i int) int { return fw.Countries[i].Weight }); c != fw.Inbound {
			t.Errorf("%s: countries add up to %d of %d inbound drops", rng, c, fw.Inbound)
		}
		if s := sum(len(fw.Services), func(i int) int { return fw.Services[i].Count }); s != fw.Inbound {
			t.Errorf("%s: services add up to %d of %d inbound drops", rng, s, fw.Inbound)
		}
		if r := sum(len(fw.Reasons), func(i int) int { return fw.Reasons[i].Count }); r != fw.Drops {
			t.Errorf("%s: reasons add up to %d of %d drops", rng, r, fw.Drops)
		}
		if o := sum(len(fw.OutboundRows), func(i int) int { return fw.OutboundRows[i].Count }); o > fw.Outbound || fw.OutboundTotal < len(fw.OutboundRows) {
			t.Errorf("%s: outbound rows %d packets of %d, %d of %d rows", rng, o, fw.Outbound, len(fw.OutboundRows), fw.OutboundTotal)
		}
		rowDevices := map[string]bool{}
		for _, r := range fw.OutboundRows {
			rowDevices[r.Device] = true
		}
		if fw.OutboundDevices > fw.OutboundTotal || fw.OutboundDevices < len(rowDevices) || (fw.OutboundTotal > 0) != (fw.OutboundDevices > 0) {
			t.Errorf("%s: outbound packets from %d devices, %d rows naming %d devices of %d rows", rng, fw.OutboundDevices, len(fw.OutboundRows),
				len(rowDevices), fw.OutboundTotal)
		}
		for i := 1; i < len(fw.Countries); i++ {
			if fw.Countries[i-1].Weight < fw.Countries[i].Weight {
				t.Fatalf("%s: countries not by weight: %+v", rng, fw.Countries)
			}
		}
		// Nothing is shown before the oldest message the syslog store keeps (30 days: before the
		// ledger started).
		oldest, err := time.Parse(time.RFC3339Nano, fw.Oldest)
		if err != nil {
			t.Fatalf("%s: oldest %q", rng, fw.Oldest)
		}
		for _, hr := range fw.Hours {
			if at, _ := time.Parse(time.RFC3339, hr.T); at.Add(time.Hour).Before(oldest) && hr.In+hr.Out+hr.Local > 0 {
				t.Fatalf("%s: drops in %s, before the oldest message kept (%s)", rng, hr.T, fw.Oldest)
			}
		}
	}
	ok(demoGet(t, h, "GET", "/api/network/firewall?device=gateway", ""), 400)
	ok(demoGet(t, h, "GET", "/api/network/connections?range=90d", ""), 400)

	// The page's other states (TestDemoServer's /demo/network).
	setState := func(s string) {
		w.mu.Lock()
		w.netState = s
		w.mu.Unlock()
	}
	setState("nosamples")
	var empty model.NetConnections
	strict(ok(demoGet(t, h, "GET", "/api/network/connections", ""), 200), &empty)
	if empty.Samples != 0 || len(empty.Rows) != 0 || empty.InUse != -1 {
		t.Errorf("no samples: %+v", empty)
	}
	setState("noipdb")
	strict(ok(demoGet(t, h, "GET", "/api/network/connections", ""), 200), &empty)
	if empty.IPDB != "" || len(empty.Orgs) != 1 || empty.Orgs[0].Key != "unknown" || len(empty.Countries) != 1 || empty.Countries[0].Code != "" {
		t.Errorf("no IP database: ipdb %q, orgs %+v, countries %+v", empty.IPDB, empty.Orgs, empty.Countries)
	}
	setState("unavailable")
	ok(demoGet(t, h, "GET", "/api/network/connections", ""), 503)
	ok(demoGet(t, h, "GET", "/api/network/firewall", ""), 503)
	ok(demoGet(t, h, "GET", "/api/network/devices", ""), 503)
	setState("")
}

// demoListed is the number of devices the demo's newest Device List read lists: every entry of
// demoLAN but the visitor's laptop, which the list no longer shows.
const demoListed = 16

// checkDemoDevices runs GET /api/network/devices against the demo world (checkDemoNetwork): the
// answers decode strictly into the model, and they agree with themselves and with the other views
// of the same period - the totals with the devices, every address of the history with a device
// that held it, the devices' connections with the Connections tab's, their blocked packets with
// the Firewall tab's - and they show what the dashboard must show: an address two devices claim, a
// weak Wi-Fi signal, a slow wired link, many blocked packets, a changed address and its reuse,
// devices that are off, and two LAN addresses the Device List does not name.
func checkDemoDevices(t *testing.T, w *demoWorld, h http.Handler, ok func(*httptest.ResponseRecorder, int) []byte, strict func([]byte, any)) {
	t.Helper()
	issueOf := func(d model.NetLANDevice, code string) *model.NetIssue {
		for i := range d.Issues {
			if d.Issues[i].Code == code {
				return &d.Issues[i]
			}
		}
		return nil
	}
	for _, rng := range NetworkRanges {
		var dv model.NetDevicesView
		strict(ok(demoGet(t, h, "GET", "/api/network/devices?range="+rng, ""), 200), &dv)
		from, err1 := time.Parse(time.RFC3339Nano, dv.From)
		to, err2 := time.Parse(time.RFC3339Nano, dv.To)
		listAt, err3 := time.Parse(time.RFC3339Nano, dv.ListAt)
		if err1 != nil || err2 != nil || err3 != nil || !from.Before(to) || listAt.After(to) || dv.Reads == 0 {
			t.Fatalf("%s: from %q to %q, list at %q, %d reads", rng, dv.From, dv.To, dv.ListAt, dv.Reads)
		}
		if len(dv.Devices) != demoListed || dv.Totals.Listed != demoListed || dv.Totals.Unknown != len(dv.Unknown) ||
			dv.Totals.WiFi+dv.Totals.Wired != dv.Totals.Listed || dv.Totals.Online != 13 {
			t.Errorf("%s: %d devices, totals %+v", rng, len(dv.Devices), dv.Totals)
		}
		byKey := map[string]model.NetLANDevice{}
		online, issues := 0, 0
		worth := func(list []model.NetIssue) bool {
			return slices.ContainsFunc(list, func(x model.NetIssue) bool { return x.Level == model.IssueCritical || x.Level == model.IssueWarning })
		}
		for _, d := range dv.Devices {
			byKey[d.Key] = d
			if d.Status == "on" {
				online++
			}
			if worth(d.Issues) {
				issues++
			}
			seen, err := time.Parse(time.RFC3339Nano, d.Seen)
			if d.Key != "mac:"+d.MAC || d.OnReads > d.Reads || d.Reads > dv.Reads || (d.Seen == "") != (d.OnReads == 0) ||
				(d.Seen != "" && (err != nil || seen.Before(from) || !seen.Before(to))) || (d.Status == "on") != (issueOf(d, model.IssueOffline) == nil) ||
				(d.Signal > 0) != (d.Status == "on" && strings.HasPrefix(d.Connection, "Wi-Fi")) || d.Issues == nil {
				t.Errorf("%s: device %+v", rng, d)
			}
			for i, a := range d.Addresses {
				if slices.Index(d.Addresses, a) != i || !slices.ContainsFunc(dv.Addresses, func(u model.NetAddrUse) bool { return u.Addr == a && u.Device == d.Key }) {
					t.Errorf("%s: %s held %q, which the history does not say (%v)", rng, d.Name, a, d.Addresses)
				}
			}
			if len(d.Addresses) > 0 && d.Addresses[0] != d.IPv4 {
				t.Errorf("%s: %s holds %s, but its newest address in the period is %s", rng, d.Name, d.IPv4, d.Addresses[0])
			}
			for _, x := range d.Issues {
				if x.Text == "" || !slices.Contains([]string{model.IssueCritical, model.IssueWarning, model.IssueInfo}, x.Level) {
					t.Errorf("%s: %s: issue %+v", rng, d.Name, x)
				}
			}
		}
		for _, u := range dv.Unknown {
			if worth(u.Issues) {
				issues++
			}
			if len(u.Issues) != 1 || u.Issues[0].Code != model.IssueUnlisted || u.First == "" || rfcBefore(u.Last, u.First) || (u.Sites == 0 && u.Blocked == 0 && u.MAC == "") {
				t.Errorf("%s: unknown address %+v", rng, u)
			}
			if slices.ContainsFunc(dv.Addresses, func(a model.NetAddrUse) bool { return a.Addr == u.Addr }) {
				t.Errorf("%s: %s is unknown, but the history names a device that held it", rng, u.Addr)
			}
		}
		if online != dv.Totals.Online || issues != dv.Totals.Issues {
			t.Errorf("%s: %d on, %d with issues; totals %+v", rng, online, issues, dv.Totals)
		}
		for i, a := range dv.Addresses {
			if a.First > a.Last || a.Reads < 1 || a.Reads > dv.Reads || a.Name == "" || (i > 0 && dv.Addresses[i-1].Addr == a.Addr && dv.Addresses[i-1].First > a.First) {
				t.Errorf("%s: address use %+v", rng, a)
			}
			if _, listed := byKey[a.Device]; !listed && a.Device != demoLAN[16].key {
				t.Errorf("%s: the history names %s, which is not in the Device List", rng, a.Device)
			}
		}

		// The address two devices claim: both critical, each naming the other.
		printer, camera := byKey[demoLAN[5].key], byKey[demoLAN[9].key]
		for _, c := range []struct{ d, other model.NetLANDevice }{{printer, camera}, {camera, printer}} {
			x := issueOf(c.d, model.IssueAddressShared)
			if c.d.IPv4 != "192.168.1.68" || x == nil || x.Level != model.IssueCritical || !strings.Contains(x.Text, c.other.Name+" ("+c.other.MAC+")") {
				t.Errorf("%s: the address conflict of %s: %+v", rng, c.d.Name, c.d.Issues)
			}
		}
		if x := issueOf(byKey[demoLAN[7].key], model.IssueWeakWiFi); x == nil || x.Level != model.IssueWarning || byKey[demoLAN[7].key].Signal != 2 {
			t.Errorf("%s: the smart speaker's weak Wi-Fi: %+v", rng, byKey[demoLAN[7].key])
		}
		if x := issueOf(byKey[demoLAN[6].key], model.IssueSlowLink); x == nil || !strings.Contains(x.Text, "10Mbps halfduplex") {
			t.Errorf("%s: the game console's slow link: %+v", rng, byKey[demoLAN[6].key])
		}
		for _, d := range dv.Devices {
			if (issueOf(d, model.IssueBlocked) != nil) != (d.Blocked+d.BlockedIn >= 100) {
				t.Errorf("%s: %s: %d blocked out, %d in; issues %+v", rng, d.Name, d.Blocked, d.BlockedIn, d.Issues)
			}
			if (issueOf(d, model.IssueAddressChanged) != nil) != (len(d.Addresses) > 1) {
				t.Errorf("%s: %s held %v; issues %+v", rng, d.Name, d.Addresses, d.Issues)
			}
		}
		off := 0
		for _, d := range dv.Devices {
			if d.Status == "off" {
				off++
			}
		}
		if off != 3 {
			t.Errorf("%s: %d devices off, want 3", rng, off)
		}

		// The devices' connections are the Connections tab's, their blocked packets the Firewall
		// tab's, for the same period.
		var nc model.NetConnections
		strict(ok(demoGet(t, h, "GET", "/api/network/connections?range="+rng+"&limit=1000", ""), 200), &nc)
		if dv.NATReads != nc.Samples || dv.NATAt != nc.Last || dv.NATReads == 0 {
			t.Errorf("%s: %d NAT reads, the newest at %q; the connections: %d, %q", rng, dv.NATReads, dv.NATAt, nc.Samples, nc.Last)
		}
		// The service's order: critical, warning, the others; on, other, off; by name.
		for i := 1; i < len(dv.Devices); i++ {
			x, y := dv.Devices[i-1], dv.Devices[i]
			rank := func(d model.NetLANDevice) int { return min(demoIssueRank(d.Issues), 2) }
			st := map[string]int{"on": 0, "off": 2}
			if rank(x) > rank(y) || (rank(x) == rank(y) && st[x.Status] > st[y.Status]) ||
				(rank(x) == rank(y) && st[x.Status] == st[y.Status] && strings.ToLower(x.Name) > strings.ToLower(y.Name)) {
				t.Errorf("%s: %s before %s", rng, x.Name, y.Name)
			}
		}
		for _, c := range nc.Devices {
			if c.Key == "gateway" {
				continue
			}
			if d, listed := byKey[c.Key]; listed {
				if d.Name != c.Name || d.IPv4 != c.IPv4 || d.MAC != c.MAC || d.Sites != c.Sites || d.Connection != c.Connection {
					t.Errorf("%s: %s: devices tab %q %s %d sites, connections %q %s %d sites", rng, c.Key, d.Name, d.IPv4, d.Sites, c.Name, c.IPv4, c.Sites)
				}
			} else if c.Key == "ip:"+demoUnlistedNAT {
				if !slices.ContainsFunc(dv.Unknown, func(u model.NetUnknownAddr) bool { return u.Addr == demoUnlistedNAT && u.Sites == c.Sites }) {
					t.Errorf("%s: %s is in the connections, not among the unknown addresses: %+v", rng, c.Key, dv.Unknown)
				}
			} else if c.Key != demoLAN[16].key {
				t.Errorf("%s: the connections name %s, which the Device List does not", rng, c.Key)
			}
		}
		var fw model.NetFirewall
		strict(ok(demoGet(t, h, "GET", "/api/network/firewall?range="+rng+"&limit=1000", ""), 200), &fw)
		out, in := 0, 0
		for _, d := range dv.Devices {
			out, in = out+d.Blocked, in+d.BlockedIn
		}
		for _, u := range dv.Unknown {
			out, in = out+u.Blocked, in+u.BlockedIn
		}
		forward := 0
		for _, r := range fw.Reasons {
			if r.Reason == demoReasonForward {
				forward = r.Count
			}
		}
		if out != fw.Outbound || in > forward {
			t.Errorf("%s: the devices sent %d blocked packets and were sent %d; the firewall dropped %d outbound, %d toward the home network", rng, out, in, fw.Outbound, forward)
		}
		for _, r := range fw.OutboundRows {
			if _, listed := byKey[r.Device]; !listed && !slices.ContainsFunc(dv.Unknown, func(u model.NetUnknownAddr) bool { return "ip:"+u.Addr == r.Device }) {
				t.Errorf("%s: the firewall's row of %s names no device of the Devices tab", rng, r.Device)
			}
		}

		switch rng {
		case "24h":
			// The laptop moved from .80 to .64, and .80 went to the guest phone: a reuse in the history.
			laptop := byKey[demoLAN[1].key]
			if !slices.Equal(laptop.Addresses, []string{"192.168.1.64", "192.168.1.80"}) || issueOf(laptop, model.IssueAddressChanged) == nil {
				t.Errorf("24h: the laptop held %v: %+v", laptop.Addresses, laptop.Issues)
			}
			var holders []string
			for _, a := range dv.Addresses {
				if a.Addr == "192.168.1.80" {
					holders = append(holders, a.Name)
				}
			}
			if !slices.Equal(holders, []string{"Laptop", "Guest phone"}) {
				t.Errorf("24h: 192.168.1.80 was held by %q", holders)
			}
			if x := issueOf(byKey[demoLAN[0].key], model.IssueBlocked); x == nil {
				t.Errorf("24h: the office PC: %+v", byKey[demoLAN[0].key])
			}
			if len(dv.Unknown) != 3 || !slices.ContainsFunc(dv.Unknown, func(u model.NetUnknownAddr) bool { return u.Addr == demoUnlistedFw && u.Blocked > 0 && u.Sites == 0 }) {
				t.Errorf("24h: unknown addresses %+v", dv.Unknown)
			}
			if guest := byKey[demoLAN[10].key]; guest.Status != "off" || guest.Seen == "" || guest.Open != 0 || guest.Sites == 0 {
				t.Errorf("24h: the guest phone: %+v", guest)
			}
		case "7d":
			if !slices.ContainsFunc(dv.Addresses, func(a model.NetAddrUse) bool { return a.Device == demoLAN[16].key }) {
				t.Error("7d: the visitor's laptop is not in the address history")
			}
			if kids := byKey[demoLAN[13].key]; kids.OnReads >= kids.Reads || kids.Status != "on" {
				t.Errorf("7d: the kids tablet: on in %d of %d reads, %s", kids.OnReads, kids.Reads, kids.Status)
			}
		}
	}

	// A device's open connections are those of the Connections tab filtered to it.
	var dv model.NetDevicesView
	strict(ok(demoGet(t, h, "GET", "/api/network/devices?range=24h", ""), 200), &dv)

	// The LAN scans: the newest of the period, each device's answers, what they found wrong, and the
	// address only the scans see.
	var ns0 model.NetworkStatus
	strict(ok(demoGet(t, h, "GET", "/api/network/status", ""), 200), &ns0)
	if dv.Scans < 20 || dv.Scan == nil || dv.Scan.Asked != 254 || dv.Scan.Subnet != "192.168.1.0/24" || dv.Totals.Scanned != dv.Scan.Answered ||
		ns0.Samplers.ScanInterval != "1h0m0s" || ns0.Samplers.ScanAt != dv.Scan.At || ns0.Samplers.ScanHosts != dv.Scan.Answered || ns0.Samplers.ScanNext == "" {
		t.Errorf("24h: %d scans, newest %+v, totals %+v; samplers %+v", dv.Scans, dv.Scan, dv.Totals, ns0.Samplers)
	}
	scanned := map[string]model.NetLANDevice{}
	for _, d := range dv.Devices {
		scanned[d.Name] = d
		if d.ScanHits > dv.Scans || (d.ScanSeen == "") != (d.ScanHits == 0) || (d.ScanAddr != "" && d.ScanSeen != dv.Scan.At) {
			t.Errorf("24h: %s answered %d of %d scans, last %q, newest at %q", d.Name, d.ScanHits, dv.Scans, d.ScanSeen, d.ScanAddr)
		}
	}
	has := func(name, code, text string) {
		t.Helper()
		d := scanned[name]
		if x := issueOf(d, code); x == nil || !strings.Contains(x.Text, text) {
			t.Errorf("24h: %s has no %s issue saying %q: %+v", name, code, text, d.Issues)
		}
	}
	has("Tablet", model.IssueNoAnswer, "did not answer the newest LAN scan")
	has("Printer", model.IssueScanMAC, "192.168.1.68 answered by another MAC address, 00:00:5e:00:53:0a, which the newest Device List read gives to Security camera: two devices may be using the address")
	has("Printer", model.IssueNoAnswer, "did not answer the newest LAN scan (made ")
	has("Doorbell", model.IssueScanAddr, "It answered the newest LAN scan at 192.168.1.77, not at 192.168.1.76, the address the gateway lists for it.")
	if p := scanned["Printer"]; p.ScanAddr != "" {
		t.Errorf("24h: the printer, whose address the camera answers: %+v", p)
	}
	if c := scanned["Security camera"]; c.ScanAddr != "192.168.1.68" || len(c.Issues) != 1 {
		t.Errorf("24h: the camera: %+v", c)
	}
	if i := slices.IndexFunc(dv.Unknown, func(u model.NetUnknownAddr) bool { return u.Addr == demoUnlistedScan }); i < 0 {
		t.Errorf("24h: no unknown address %s: %+v", demoUnlistedScan, dv.Unknown)
	} else if u := dv.Unknown[i]; u.MAC != demoMACUnlistedSc || u.ScanSeen != dv.Scan.At || u.Sites != 0 || u.Blocked != 0 ||
		!strings.Contains(u.Issues[0].Text, " LAN scans of this period (from "+demoMACUnlistedSc+"). Perhaps a device with a fixed address") {
		t.Errorf("24h: the address only the scans see: %+v", u)
	}
	if i := slices.IndexFunc(dv.Unknown, func(u model.NetUnknownAddr) bool { return u.Addr == demoUnlistedNAT }); i < 0 || dv.Unknown[i].MAC != demoMACUnlistedNA {
		t.Errorf("24h: the address of the NAT samples, as the scans found it: %+v", dv.Unknown)
	}
	for _, u := range dv.Unknown {
		if u.Addr == demoGateway {
			t.Error("24h: the gateway's own address is an unknown address")
		}
	}

	// A device's details: who held its addresses (itself and the guest phone), the scans as it
	// answered them, newest first, and what its syslog messages are found by.
	laptop, err := w.Device(context.Background(), contracts.NetQuery{From: time.Now().Add(-24 * time.Hour), To: time.Now(), Range: "24h"}, demoLAN[1].key, "")
	if err != nil || laptop.Device == nil || laptop.Device.Key != demoLAN[1].key || laptop.Unknown != nil {
		t.Fatalf("the laptop's details: %+v, %v", laptop, err)
	}
	holders := map[string]bool{}
	for _, a := range laptop.Addresses {
		holders[a.Addr+" "+a.Name] = true
	}
	if !holders["192.168.1.64 Laptop"] || !holders["192.168.1.80 Laptop"] || !holders["192.168.1.80 Guest phone"] || len(laptop.Addresses) != 3 {
		t.Errorf("who held the laptop's addresses: %+v", laptop.Addresses)
	}
	if len(laptop.Scans) < 20 || laptop.Scans[0].Addr != "192.168.1.64" || rfcBefore(laptop.Scans[0].At, laptop.Scans[1].At) {
		t.Errorf("the laptop's scans: %+v", laptop.Scans)
	}
	kinds := map[string]int{}
	for _, m := range laptop.Match {
		kinds[m.Kind]++
		if m.Kind == "ipv4" && m.Text == "192.168.1.80" && (m.From != "" || m.To == "") {
			t.Errorf("the laptop held 192.168.1.80 from before the period until 20 h ago: %+v", m)
		}
		if m.Kind == "ipv4" && m.Text == "192.168.1.64" && (m.From == "" || m.To != "") {
			t.Errorf("the laptop holds 192.168.1.64 since 20 h ago: %+v", m)
		}
	}
	if kinds["ipv4"] != 2 || kinds["ipv6"] != 1 || kinds["mac"] != 1 || laptop.Syslog == nil {
		t.Errorf("the laptop's syslog terms: %+v", laptop.Match)
	}
	plug, err := w.Device(context.Background(), contracts.NetQuery{From: time.Now().Add(-24 * time.Hour), To: time.Now(), Range: "24h"}, "", demoUnlistedScan)
	if err != nil || plug.Unknown == nil || plug.Unknown.MAC != demoMACUnlistedSc || len(plug.Match) != 1 || plug.Match[0] != (model.NetSyslogTerm{Kind: "ipv4", Text: demoUnlistedScan}) ||
		len(plug.Scans) == 0 || plug.Scans[0].Addr != demoUnlistedScan {
		t.Errorf("the details of %s: %+v, %v", demoUnlistedScan, plug, err)
	}
	if _, err := w.Device(context.Background(), contracts.NetQuery{From: time.Now().Add(-time.Hour), To: time.Now()}, "mac:00:00:5e:00:53:ff", ""); !errors.Is(err, contracts.ErrNotFound) {
		t.Errorf("an unknown device's details: %v", err)
	}
	for _, d := range dv.Devices[:3] {
		var nc model.NetConnections
		strict(ok(demoGet(t, h, "GET", "/api/network/connections?range=24h&device="+url.QueryEscape(d.Key), ""), 200), &nc)
		if d.Open != nc.OpenDevice {
			t.Errorf("%s: %d open, the connections of the device %d", d.Name, d.Open, nc.OpenDevice)
		}
	}

	// The page's states: no Device List read yet, and no syslog store (nothing counted as blocked).
	setState := func(s string) {
		w.mu.Lock()
		w.netState = s
		w.mu.Unlock()
	}
	setState("nodevices")
	strict(ok(demoGet(t, h, "GET", "/api/network/devices", ""), 200), &dv)
	var ns model.NetworkStatus
	strict(ok(demoGet(t, h, "GET", "/api/network/status", ""), 200), &ns)
	if dv.ListAt != "" || dv.Reads != 0 || len(dv.Devices) != 0 || ns.Samplers.DevicesAt != "" || ns.Samplers.Devices != 0 {
		t.Errorf("no Device List read: %+v; samplers %+v", dv, ns.Samplers)
	}
	setState("nosyslog")
	strict(ok(demoGet(t, h, "GET", "/api/network/devices", ""), 200), &dv)
	for _, d := range dv.Devices {
		if d.Blocked != 0 || d.BlockedIn != 0 || issueOf(d, model.IssueBlocked) != nil {
			t.Errorf("no syslog store: %+v", d)
		}
	}

	// Entries that are off claim no address (netmap's rule): the Work laptop, off, listed with the
	// Office PC's address is no conflict, and neither are the E-reader and the Guest phone, both off,
	// listed with 192.168.1.80.
	byName := func(dv model.NetDevicesView) map[string]model.NetLANDevice {
		out := map[string]model.NetLANDevice{}
		for _, d := range dv.Devices {
			out[d.Name] = d
		}
		return out
	}
	setState("panel")
	strict(ok(demoGet(t, h, "GET", "/api/network/devices?range=24h", ""), 200), &dv)
	pd := byName(dv)
	if pc, wl := pd["Office PC"], pd["Work laptop"]; pc.IPv4 != "192.168.1.71" || wl.IPv4 != "192.168.1.71" || wl.Status != "off" ||
		issueOf(pc, model.IssueAddressShared) != nil || issueOf(wl, model.IssueAddressShared) != nil || issueOf(wl, model.IssueOffline) == nil ||
		!strings.Contains(issueOf(wl, model.IssueOffline).Text, "Its last address, 192.168.1.71, is now claimed by Office PC (00:00:5e:00:53:01).") {
		t.Errorf("panel: an entry that is off listed with an address one that is on has: %+v, %+v", pc, wl)
	}
	if er, gp := pd["E-reader"], pd["Guest phone"]; er.IPv4 != "192.168.1.80" || gp.IPv4 != "192.168.1.80" || er.Status != "off" || gp.Status != "off" ||
		issueOf(er, model.IssueAddressShared) != nil || issueOf(gp, model.IssueAddressShared) != nil {
		t.Errorf("panel: two entries that are off listed with one address: %+v, %+v", er, gp)
	}

	// A device with a fixed address answers the scans at an address the reads give to devices of
	// the list, from a MAC address no read names.
	setState("fixedguest")
	strict(ok(demoGet(t, h, "GET", "/api/network/devices?range=24h", ""), 200), &dv)
	if i := slices.IndexFunc(dv.Unknown, func(u model.NetUnknownAddr) bool { return u.Addr == demoFixedGuest }); i < 0 {
		t.Errorf("fixedguest: no unknown address %s: %+v", demoFixedGuest, dv.Unknown)
	} else if u := dv.Unknown[i]; u.MAC != demoMACFixedGuest || len(u.Issues) != 1 ||
		!strings.HasPrefix(u.Issues[0].Text, demoFixedGuest+" answered ") ||
		!strings.Contains(u.Issues[0].Text, " LAN scans of this period from "+demoMACFixedGuest+", which no Device List read of this period names (the reads give the address to another device).") {
		t.Errorf("fixedguest: the address the reads give to others: %+v", u)
	}

	// The scans stopped two hours ago: the newest is too old to compare with the newest read, and
	// no device has a scan issue.
	setState("stalescan")
	strict(ok(demoGet(t, h, "GET", "/api/network/devices?range=24h", ""), 200), &dv)
	if dv.Scan == nil {
		t.Errorf("stalescan: no scan in the period: %+v", dv)
	} else if at, _ := time.Parse(time.RFC3339Nano, dv.Scan.At); time.Since(at) < 2*time.Hour {
		t.Errorf("stalescan: the newest scan %s", dv.Scan.At)
	}
	for _, d := range dv.Devices {
		for _, code := range []string{model.IssueNoAnswer, model.IssueScanAddr, model.IssueScanMAC} {
			if issueOf(d, code) != nil {
				t.Errorf("stalescan: %s has a %s issue: %+v", d.Name, code, d.Issues)
			}
		}
	}
	setState("")
}
