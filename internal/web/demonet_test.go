package web

// The demo world's Network page (docs/syslog-map-graphic.md): a household of eight devices and the
// gateway itself, the organisations and services they reach (samples of the NAT table every 4
// minutes since the ledger started), and what the gateway's firewall drops, hour by hour, as long
// as the syslog store keeps it. Everything is computed from the time, deterministically
// (noise), so that a period shows the same data each time it is asked for, and it follows the
// rest of the world: no read while the PC slept, no Internet traffic while the line was down.
//
// Only documentation values are used: LAN 192.168.1.x, MAC 00:00:5e:00:53:xx, remote addresses
// in 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24; organisations are well-known companies.
//
// /demo/network?state=... (TestDemoServer) shows the page's other states: off (sampling turned
// off), paused (logins paused), noaccess (no access code), nosamples (no read yet), natnote (reads
// that work but leave rows out), busy (more connections than the store counts one by one), noipdb
// (the IP database not loaded), nosyslog (no syslog store: the firewall view is unavailable, as
// netmap's is), nodrops (nothing dropped), cfgwarn (settings in config.json replaced) and
// unavailable (the views fail).

import (
	"context"
	"fmt"
	"maps"
	"math"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
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

// demoNetDevice is a device of the household (the Device List), with the hours it is used.
type demoNetDevice struct {
	key, name, ipv4, mac, conn string
	// active is how busy the device is at a local hour (0-1).
	active func(hour int) float64
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

// demoNetDevices: this PC (the demo's syslog target, 192.168.1.71) first; the gateway's own
// connections (key "gateway") last.
var demoNetDevices = []demoNetDevice{
	{"mac:00:00:5e:00:53:01", "Office PC", "192.168.1.71", "00:00:5e:00:53:01", "Ethernet", busyHours(8, 19, 1, 0.12)},
	{"mac:00:00:5e:00:53:02", "Laptop", "192.168.1.64", "00:00:5e:00:53:02", "Wi-Fi 5 GHz", busyHours(9, 23, 0.7, 0.05)},
	{"mac:00:00:5e:00:53:03", "Phone", "192.168.1.65", "00:00:5e:00:53:03", "Wi-Fi 5 GHz", busyHours(7, 24, 0.9, 0.35)},
	{"mac:00:00:5e:00:53:04", "Living room TV", "192.168.1.66", "00:00:5e:00:53:04", "Ethernet", busyHours(18, 24, 1, 0.03)},
	{"mac:00:00:5e:00:53:05", "Tablet", "192.168.1.67", "00:00:5e:00:53:05", "Wi-Fi 2.4 GHz", busyHours(16, 22, 0.8, 0.04)},
	{"mac:00:00:5e:00:53:06", "Printer", "192.168.1.68", "00:00:5e:00:53:06", "Wi-Fi 2.4 GHz", busyHours(0, 24, 0.12, 0.12)},
	{"mac:00:00:5e:00:53:07", "Game console", "192.168.1.69", "00:00:5e:00:53:07", "Ethernet", busyHours(19, 23, 0.8, 0.03)},
	{"mac:00:00:5e:00:53:08", "Smart speaker", "192.168.1.70", "00:00:5e:00:53:08", "Wi-Fi 2.4 GHz", busyHours(0, 24, 0.6, 0.6)},
	{"gateway", "Gateway", "", "", "", busyHours(0, 24, 0.5, 0.5)},
}

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

// flowOpen reports whether flow i is open at the read at t.
func flowOpen(f demoNetFlow, i int, t time.Time) bool {
	return noise(t, 1000+i) < f.p*demoNetDevices[f.dev].active(t.Local().Hour())
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
			if !flowOpen(f, i, t) {
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
			if flowOpen(f, i, lastTick) {
				nc.Open += f.sess
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
	// Every device of the demo but the gateway is in its Device List (connSamplersLocked).
	for key := range devices {
		if key != "gateway" && q.Device == "" {
			nc.Totals.Listed++
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

// fwHour is the demo's firewall in the hour starting at t: inbound probes (none while the line
// was down), outbound packets of the office PC (in office hours, in bursts) and a few local ones.
func (w *demoWorld) fwHourLocked(t time.Time) (in, out, local int) {
	if w.gapAt(t) || w.gapAt(t.Add(30*time.Minute)) {
		return 0, 0, 0 // the PC slept: nothing was received
	}
	h := t.Local().Hour()
	if !w.wanDownAt(t.Add(30 * time.Minute)) {
		in = int(470 + 90*math.Sin(float64(h)/24*2*math.Pi) + 160*noise(t, 3001))
	}
	if h >= 8 && h < 19 && noise(t, 3002) < 0.7 {
		out = int(10 + 75*noise(t, 3003))
	}
	if noise(t, 3004) < 0.3 {
		local = 1 + int(4*noise(t, 3005))
	}
	return in, out, local
}

// Firewall answers GET /api/network/firewall from the demo's hourly firewall model, within the
// syslog the demo's store keeps (contracts.NetworkView).
func (w *demoWorld) Firewall(ctx context.Context, q contracts.NetQuery) (model.NetFirewall, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	switch w.netState {
	case "unavailable":
		return model.NetFirewall{}, fmt.Errorf("netmap: the syslog store is closed: %w", contracts.ErrUnavailable)
	case "nosyslog":
		return model.NetFirewall{}, fmt.Errorf("netmap: firewall view: no syslog store: %w", contracts.ErrUnavailable)
	}
	now := time.Now()
	u := w.syslogUsageLocked()
	fw := model.NetFirewall{From: q.From.UTC().Format(time.RFC3339Nano), To: q.To.UTC().Format(time.RFC3339Nano), Oldest: u.Oldest}
	if w.netState != "noipdb" {
		fw.IPDB = demoIPDB(now).Format(time.RFC3339)
	}
	oldest, err := time.Parse(time.RFC3339Nano, u.Oldest)
	kept := err == nil && w.netState != "nosyslog"
	var lastIn, lastOut time.Time
	for t := q.From.Truncate(time.Hour); t.Before(q.To); t = t.Add(time.Hour) {
		if err := ctx.Err(); err != nil {
			return model.NetFirewall{}, err
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
			in, out, local := w.fwHourLocked(t)
			hr.In, hr.Out, hr.Local = int(float64(in)*frac), int(float64(out)*frac), int(float64(local)*frac)
			if hr.In > 0 {
				lastIn = b.Add(-time.Duration(noise(t, 3006) * float64(b.Sub(a))))
			}
			if hr.Out > 0 {
				lastOut = b.Add(-time.Duration(noise(t, 3007) * float64(b.Sub(a))))
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
		// The office PC's late packets to the sites it was using, a few of the laptop's.
		plan := demoNetPlan()
		left := fw.Outbound
		shares := []float64{0.42, 0.21, 0.12, 0.09, 0.07, 0.05, 0.04}
		picked := 0
		for i, f := range plan {
			if picked == len(shares) || left <= 0 {
				break
			}
			if (f.dev != 0 && f.dev != 1) || f.org < 0 || noise(time.Unix(int64(i), 0), 3008) < 0.4 {
				continue
			}
			n := int(math.Round(float64(fw.Outbound) * shares[picked]))
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
			picked++
		}
		// Two more, with fewer packets, beyond the rows listed: one of them the phone's, so that
		// the devices counted are more than those the rows name.
		devices := map[string]bool{demoNetDevices[2].key: true}
		for _, r := range fw.OutboundRows {
			devices[r.Device] = true
		}
		fw.OutboundTotal, fw.OutboundDevices = len(fw.OutboundRows)+2, len(devices)
		limit := q.Limit
		if limit <= 0 {
			limit = 200
		}
		if len(fw.OutboundRows) > limit {
			fw.OutboundRows = fw.OutboundRows[:limit]
		}
	}
	if w.hostile != "" {
		hostileFirewall(&fw, w.hostile)
	}
	return fw, nil
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
		DevicesAt: now.Truncate(15 * time.Minute).UTC().Format(time.RFC3339Nano), Devices: len(demoNetDevices) - 1,
		Store: w.connStoreLocked(now)}
	plan := demoNetPlan()
	for i, f := range plan {
		if flowOpen(f, i, last) {
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
	if ns.Samplers == nil || !ns.Samplers.Enabled || ns.Samplers.Interval != "4m0s" || ns.Samplers.Devices != 8 || ns.Store == nil || ns.Store.KeepDays != 30 ||
		ns.IPIntel == nil || !ns.IPIntel.Loaded || ns.Syslog == nil || ns.Syslog.Oldest == "" {
		t.Errorf("network status: %+v", ns)
	}

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
	setState("")
}
