package netmap

import (
	"cmp"
	"context"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"attmonitor/internal/model"
)

// devAssembly makes a Devices view from its sources: the newest Device List read (the devices
// listed), the period's reads, its NAT samples, its dropped packets by LAN address and its LAN
// scans.
type devAssembly struct {
	from, to time.Time
	limit    int
	list     []model.LANDevice // the newest Device List read (nil before the first)
	listAt   time.Time
	reads    *devReads
	agg      model.ConnAggregate
	drops    *builder // the dropped packets by LAN address (nil without a syslog store)
	exact    bool     // the period's flows are few enough for its sites to be counted exactly
	// eachScan gives the period's LAN scans, oldest first (nil: no scans are kept); gateway is the
	// gateway's own address (its answers are its own); lans bounds the unknown addresses the scans
	// add (0: no bound).
	eachScan func(ctx context.Context, fn func(model.LANScan) error) error
	gateway  netip.Addr
	lans     int

	devices []model.NetLANDevice
	// owner maps the keys the NAT samples and the firewall's namer give a listed device to its
	// index in devices: "mac:<mac>", or for an entry without a MAC address "ip:" and each of its
	// addresses (the connection store and the namer key such an entry by address). byMAC maps the
	// MAC addresses of the listed devices to their index (the first entry of each).
	owner   map[string]int
	byMAC   map[string]int
	baseKey map[string]string // by device key: the key the reads know it by (without "#2", ...)
	sites   []distinct        // by index in devices
	unknown map[netip.Addr]*unknownAcc
	scan    *lanScans // the period's LAN scans (nil: none read)
	scanErr error     // why the LAN scans could not be read
}

// unknownAcc adds up a LAN address that no Device List read of the period names - or, for an
// address that answered a LAN scan, whose MAC address no read names.
type unknownAcc struct {
	u           model.NetUnknownAddr
	first, last time.Time // when it was seen first and last (zero: not known)
	nat         bool      // the NAT samples showed it
	sites       distinct
	// scanHits counts the period's LAN scans it answered (scanTrail: their indices, the last
	// 2*maxDetailScans at most); named: a Device List read of the period names the address (held
	// by a device of the list), only not the MAC address that answered for it.
	scanHits  int
	scanTrail []int32
	named     bool
}

// seen notes that the address was seen at t.
func (u *unknownAcc) seen(t time.Time) {
	if t.IsZero() {
		return
	}
	if u.first.IsZero() || t.Before(u.first) {
		u.first = t
	}
	if t.After(u.last) {
		u.last = t
	}
}

// build makes the view, with what a device's details need beyond it. It fails only when ctx ends.
func (a *devAssembly) build(ctx context.Context) (*devBuild, error) {
	a.base()
	if err := a.addNAT(ctx); err != nil {
		return nil, err
	}
	if err := a.addDrops(ctx); err != nil {
		return nil, err
	}
	if err := a.addScans(ctx); err != nil {
		return nil, err
	}
	for i := range a.devices {
		a.devices[i].Sites = a.sites[i].count()
	}
	a.addIssues()
	unknown := a.unknownList()
	dv := model.NetDevicesView{
		From:      rfc3339(a.from),
		To:        rfc3339(a.to),
		Reads:     a.reads.reads,
		NATReads:  a.agg.Samples,
		Totals:    devTotals(a.devices, len(unknown)),
		Devices:   a.devices,
		Unknown:   slices.Clip(unknown[:min(len(unknown), a.limit)]),
		Addresses: a.reads.history(),
	}
	if a.list != nil && !a.listAt.IsZero() {
		dv.ListAt = rfc3339(a.listAt)
	}
	if a.agg.Samples > 0 {
		dv.NATAt = a.agg.Last
	}
	if s := a.scan; s != nil && s.newest >= 0 {
		info := s.info
		dv.Scans, dv.Scan, dv.Totals.Scanned = len(s.at), &info, info.Answered
	}
	b := &devBuild{unknown: unknown, baseKey: a.baseKey, v6: map[string][]netip.Addr{}, every: a.reads.every(),
		scans: a.scanDetail()}
	for _, d := range a.devices {
		if v6 := a.reads.ipv6(a.baseKey[d.Key]); len(v6) > 0 {
			b.v6[d.Key] = v6
		}
	}
	sortDevices(dv.Devices)
	b.view = dv
	return b, nil
}

// base lists the devices of the newest read, each with what the period's reads say about it.
func (a *devAssembly) base() {
	a.devices = make([]model.NetLANDevice, 0, len(a.list))
	a.owner = map[string]int{}
	a.byMAC = map[string]int{}
	a.baseKey = map[string]string{}
	a.unknown = map[netip.Addr]*unknownAcc{}
	keys := map[string]int{} // how often each key was given so far
	for _, d := range a.list {
		key := lanDeviceKey(d)
		if key == "" {
			continue
		}
		i := len(a.devices)
		nd := model.NetLANDevice{Key: key, Name: strings.TrimSpace(d.Name), MAC: normMAC(d.MAC), Status: d.Status,
			Allocation: d.Allocation, Connection: d.Connection, Speed: d.Speed, Mesh: d.Mesh, LastActivity: d.LastActivity,
			Issues: []model.NetIssue{}}
		if ip, ok := deviceIPv4(d.IPv4); ok {
			nd.IPv4 = ip.String()
		}
		for _, s := range d.IPv6 {
			if ip, ok := lanAddr(s); ok && ip.Is6() {
				nd.IPv6 = append(nd.IPv6, ip.WithZone("").String())
			}
		}
		if d.Signal >= 1 && d.Signal <= maxBars {
			nd.Signal = d.Signal
		}
		if st := a.reads.stats[key]; st != nil {
			nd.Reads, nd.OnReads = st.reads, st.onReads
			if st.seen != 0 {
				nd.Seen = rfc3339(time.Unix(0, st.seen))
			}
		}
		nd.Addresses = a.reads.addresses(key)
		if n := keys[key]; n > 0 {
			nd.Key = key + "#" + strconv.Itoa(n+1)
		}
		keys[key]++
		a.baseKey[nd.Key] = key
		claim := func(k string) {
			if _, taken := a.owner[k]; !taken {
				a.owner[k] = i
			}
		}
		if nd.MAC != "" {
			claim("mac:" + nd.MAC)
			if _, taken := a.byMAC[nd.MAC]; !taken {
				a.byMAC[nd.MAC] = i
			}
		} else {
			if nd.IPv4 != "" {
				claim("ip:" + nd.IPv4)
			}
			for _, s := range nd.IPv6 {
				claim("ip:" + s)
			}
		}
		a.devices = append(a.devices, nd)
	}
	a.sites = make([]distinct, len(a.devices))
	for i := range a.sites {
		a.sites[i].exact = a.exact
	}
}

// unknownAt returns the unknown address a - adding it - when it is one: an address that could be
// an unknown device's (lanCandidate) and that no Device List read of the period names; else nil.
func (a *devAssembly) unknownAt(addr netip.Addr) *unknownAcc {
	addr = addr.Unmap()
	if !lanCandidate(addr) {
		return nil
	}
	if _, named := a.reads.named[addr]; named {
		return nil
	}
	u := a.unknown[addr]
	if u == nil {
		u = &unknownAcc{u: model.NetUnknownAddr{Addr: addr.String()}, sites: distinct{exact: a.exact}}
		a.unknown[addr] = u
	}
	return u
}

// unknownOf returns the unknown address of a device key of the NAT samples ("ip:<address>": an
// address no Device List read in effect named), nil when it is no unknown address.
func (a *devAssembly) unknownOf(key string) *unknownAcc {
	s, ok := strings.CutPrefix(key, "ip:")
	if !ok {
		return nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return nil
	}
	return a.unknownAt(addr)
}

// addNAT adds the NAT samples: each device's sessions in the newest read (Open) and the distinct
// remote addresses of its flows (Sites), for the devices listed and the unknown addresses.
func (a *devAssembly) addNAT(ctx context.Context) error {
	for _, d := range a.agg.Devices {
		if i, ok := a.owner[d.Key]; ok {
			a.devices[i].Open += d.Open
		} else if u := a.unknownOf(d.Key); u != nil {
			u.u.Open += d.Open
			u.nat = true
		}
	}
	for i := range a.agg.Flows {
		if i%finishEvery == finishEvery-1 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		f := &a.agg.Flows[i]
		var s *distinct
		if j, ok := a.owner[f.Device]; ok {
			s = &a.sites[j]
		} else if u := a.unknownOf(f.Device); u != nil {
			s = &u.sites
			u.nat = true
			u.seen(parseRFC3339(f.First))
			u.seen(parseRFC3339(f.Last))
		} else {
			continue
		}
		if s.exact {
			s.addString(canonical(f.Remote))
		} else {
			r, ok := remoteAddr(f.Remote)
			s.addHash(remoteHash(f.Remote, r, ok))
		}
	}
	return nil
}

// addDrops adds the dropped packets by LAN address: to the device the Device List read in effect
// (else the next one, within devNextWithin) named at the address when they were received, and to
// the unknown addresses.
func (a *devAssembly) addDrops(ctx context.Context) error {
	if a.drops == nil {
		return nil
	}
	for i := range a.drops.lans {
		if i%finishEvery == finishEvery-1 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		s := &a.drops.lans[i]
		addr := netip.AddrFrom16(s.key.addr).Unmap()
		if s.key.dev > 0 {
			key, _ := a.reads.namer.describe(s.key.dev, addr)
			if j, ok := a.owner[key]; ok {
				a.devices[j].Blocked += s.out
				a.devices[j].BlockedIn += s.in
			}
			continue
		}
		if u := a.unknownAt(addr); u != nil {
			u.u.Blocked += s.out
			u.u.BlockedIn += s.in
			u.seen(time.Unix(0, s.first))
			u.seen(time.Unix(0, s.last))
		}
	}
	return nil
}

// addIssues gives each device its issues, the most severe first (devissues.go).
func (a *devAssembly) addIssues() {
	// The entries of the newest read that claim each IPv4 address: those not shown off.
	claims := map[string][]int{}
	for i, d := range a.devices {
		if d.IPv4 != "" && !isOff(d.Status) {
			claims[d.IPv4] = append(claims[d.IPv4], i)
		}
	}
	others := func(addr string, self int) []model.NetLANDevice {
		var out []model.NetLANDevice
		for _, j := range claims[addr] {
			if j != self {
				out = append(out, a.devices[j])
			}
		}
		return out
	}
	for i := range a.devices {
		d := &a.devices[i]
		issues := []model.NetIssue{}
		if d.IPv4 != "" && !isOff(d.Status) {
			if o := others(d.IPv4, i); len(o) > 0 {
				issues = append(issues, sharedIssue(d.IPv4, o))
			}
		}
		blocked := func(d model.NetLANDevice) (model.NetIssue, bool) { return blockedIssue(d, a.to.Sub(a.from)) }
		for _, f := range []func(model.NetLANDevice) (model.NetIssue, bool){weakIssue, slowIssue, blocked, changedIssue} {
			if is, ok := f(*d); ok {
				issues = append(issues, is)
			}
		}
		if isOff(d.Status) {
			var takers []model.NetLANDevice
			if d.IPv4 != "" {
				takers = others(d.IPv4, i)
			}
			issues = append(issues, offlineIssue(*d, a.listAt, takers))
		}
		issues = append(issues, a.scanIssues(i)...)
		sortIssues(issues)
		d.Issues = issues
	}
}

// sortIssues orders issues by level, the most severe first, then by code.
func sortIssues(issues []model.NetIssue) {
	slices.SortStableFunc(issues, func(x, y model.NetIssue) int {
		return cmp.Or(cmp.Compare(issueRank(x.Level), issueRank(y.Level)), cmp.Compare(issueOrder[x.Code], issueOrder[y.Code]))
	})
}

// unknownList returns every unknown address, the most recently seen first (the view lists the
// first limit of them; a device's details find any).
func (a *devAssembly) unknownList() []model.NetUnknownAddr {
	us := make([]*unknownAcc, 0, len(a.unknown))
	for _, u := range a.unknown {
		us = append(us, u)
	}
	slices.SortFunc(us, func(x, y *unknownAcc) int {
		xa, _ := netip.ParseAddr(x.u.Addr)
		ya, _ := netip.ParseAddr(y.u.Addr)
		return cmp.Or(y.last.Compare(x.last), xa.Compare(ya))
	})
	out := make([]model.NetUnknownAddr, 0, len(us))
	for _, u := range us {
		nu := u.u
		nu.Sites = u.sites.count()
		if !u.first.IsZero() {
			nu.First, nu.Last = rfc3339(u.first), rfc3339(u.last)
		}
		nu.Issues = []model.NetIssue{unknownIssue(nu, u.nat, u.scanHits, u.named)}
		out = append(out, nu)
	}
	return out
}

// devTotals are the Devices tab's tiles: the devices listed, how many are on, on Wi-Fi and on
// Ethernet, how many devices and unknown addresses (unknown of them, each with the warning
// "unlisted") have a warning or a critical issue.
func devTotals(devices []model.NetLANDevice, unknown int) model.NetDeviceTotals {
	t := model.NetDeviceTotals{Listed: len(devices), Issues: unknown, Unknown: unknown}
	for _, d := range devices {
		if isOn(d.Status) {
			t.Online++
		}
		switch {
		case isWiFi(d.Connection):
			t.WiFi++
		case isWired(d.Connection):
			t.Wired++
		}
		if counts(d.Issues) {
			t.Issues++
		}
	}
	return t
}

// sortDevices orders the devices as the tab lists them first: those with a critical issue, then
// those with a warning, then the others; within each, those on before the others and those off
// last; then by name (the named first), address and key.
func sortDevices(devs []model.NetLANDevice) {
	status := func(d model.NetLANDevice) int {
		switch {
		case isOn(d.Status):
			return 0
		case isOff(d.Status):
			return 2
		}
		return 1
	}
	slices.SortStableFunc(devs, func(x, y model.NetLANDevice) int {
		xa, xok := deviceIPv4(x.IPv4)
		ya, yok := deviceIPv4(y.IPv4)
		return cmp.Or(cmp.Compare(min(worst(x.Issues), 2), min(worst(y.Issues), 2)), cmp.Compare(status(x), status(y)),
			compareBool(x.Name == "", y.Name == ""), strings.Compare(strings.ToLower(x.Name), strings.ToLower(y.Name)),
			strings.Compare(x.Name, y.Name), compareBool(!xok, !yok), xa.Compare(ya), strings.Compare(x.Key, y.Key))
	})
}

// parseRFC3339 parses a time of the connection store's results (zero when it does not parse).
func parseRFC3339(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}
