package connstore

import (
	"cmp"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// The reference aggregation: what Aggregate must return, computed the simplest way from the
// reads as they were appended - no files, no cache, no index.

// refNAT and refDev are reads as a test appended them.
type refNAT struct {
	t   time.Time
	nat model.NATTable
}

type refDev struct {
	t       time.Time
	devices []model.LANDevice
}

// refFlowKey identifies a flow of the reference.
type refFlowKey struct {
	dev, remote, proto string
	port               int
	inbound            bool
}

// refAggregate is the reference's result: totals, and devices and flows by key (their order is
// checked separately, by checkOrder).
type refAggregate struct {
	samples            int
	first, last        time.Time
	inUse, avail, open int
	devices            map[string]model.ConnDevice
	flows              map[refFlowKey]model.ConnFlow
}

// reference aggregates the NAT reads of [from, to) for the device filter; a zero to has no end.
func reference(nats []refNAT, devs []refDev, from, to time.Time, filter string) refAggregate {
	if to.IsZero() {
		to = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	ds := slices.Clone(devs)
	slices.SortStableFunc(ds, func(a, b refDev) int { return a.t.Compare(b.t) })
	inEffect := func(t time.Time) *refDev {
		var r *refDev
		for i := range ds {
			if !ds[i].t.After(t) {
				r = &ds[i]
			}
		}
		if r == nil && len(ds) > 0 {
			r = &ds[0]
		}
		return r
	}
	// nextAfter is the first read after t, when it comes within devNextWithin.
	nextAfter := func(t time.Time) *refDev {
		for i := range ds {
			if ds[i].t.After(t) {
				if ds[i].t.Sub(t) <= devNextWithin {
					return &ds[i]
				}
				return nil
			}
		}
		return nil
	}
	ns := slices.Clone(nats)
	slices.SortStableFunc(ns, func(a, b refNAT) int { return a.t.Compare(b.t) })
	out := refAggregate{inUse: -1, avail: -1, devices: map[string]model.ConnDevice{}, flows: map[refFlowKey]model.ConnFlow{}}
	type devAcc struct {
		d                         model.ConnDevice
		nameT, macT, connT, ipv4T time.Time
		lan                       netip.Addr
	}
	type flowAcc struct {
		f           model.ConnFlow
		first, last time.Time
		lan         netip.Addr
	}
	devAccs := map[string]*devAcc{}
	flowAccs := map[refFlowKey]*flowAcc{}
	var newestT time.Time
	for _, r := range ns {
		if r.t.Before(from) || !r.t.Before(to) {
			continue
		}
		if out.samples == 0 || r.t.Before(out.first) {
			out.first = r.t
		}
		if out.samples == 0 || r.t.After(out.last) {
			out.last = r.t
		}
		out.samples++
		if newestT.IsZero() || !r.t.Before(newestT) {
			newestT = r.t
			out.inUse, out.avail, out.open = r.nat.InUse, r.nat.Available, len(r.nat.Sessions)
		}
		dr, next := inEffect(r.t), nextAfter(r.t)
		seenDev, seenFlow := map[string]bool{}, map[refFlowKey]bool{}
		for _, s := range r.nat.Sessions {
			src, ok1 := parseAddr(s.Src)
			dst, ok2 := parseAddr(s.Dst)
			if !ok1 || !ok2 {
				continue
			}
			o := orientLocal(refLAN(dr, src) || refLAN(next, src), refLAN(dr, dst) || refLAN(next, dst))
			lan, remote := src, dst
			if o == inbound {
				lan, remote = dst, src
			}
			key, name, mac, conn := gatewayKey, "", "", ""
			if o != fromGateway {
				key = "ip:" + lan.String()
				named := dr
				if dr == nil || refLookup(dr.devices, lan) == nil {
					named = next // a device the read in effect does not list: the next read names it
				}
				if named != nil {
					if e := refLookup(named.devices, lan); e != nil {
						mac = normMAC(e.MAC)
						name, conn = strings.TrimSpace(e.Name), strings.TrimSpace(e.Connection)
						if mac != "" {
							key = "mac:" + mac
						}
					}
				}
			}
			da := devAccs[key]
			if da == nil {
				da = &devAcc{d: model.ConnDevice{Key: key}}
				devAccs[key] = da
			}
			if !seenDev[key] {
				seenDev[key] = true
				da.d.Samples++
			}
			da.d.Weight++
			for _, a := range []struct {
				v  *string
				vt *time.Time
				s  string
			}{{&da.d.Name, &da.nameT, name}, {&da.d.MAC, &da.macT, mac}, {&da.d.Connection, &da.connT, conn}} {
				if a.s != "" && !r.t.Before(*a.vt) {
					*a.v, *a.vt = a.s, r.t
				}
			}
			if !r.t.Before(da.ipv4T) {
				da.lan, da.ipv4T = lan, r.t
			}
			fk := refFlowKey{dev: key, remote: remote.String(), proto: normProto(s.Proto), port: int(normPort(s.DstPort)), inbound: o == inbound}
			fa := flowAccs[fk]
			if fa == nil {
				fa = &flowAcc{f: model.ConnFlow{Device: key, Remote: fk.remote, Port: fk.port, Proto: fk.proto, Inbound: fk.inbound},
					first: r.t, last: r.t, lan: lan}
				flowAccs[fk] = fa
			}
			if !seenFlow[fk] {
				seenFlow[fk] = true
				fa.f.Samples++
			}
			fa.f.Weight++
			if r.t.Before(fa.first) {
				fa.first = r.t
			}
			if !r.t.Before(fa.last) {
				fa.last, fa.lan = r.t, lan
			}
		}
	}
	for k, da := range devAccs {
		if filter != "" && k != filter {
			continue
		}
		if da.lan.Is4() {
			da.d.IPv4 = da.lan.String()
		}
		out.devices[k] = da.d
	}
	for k, fa := range flowAccs {
		if filter != "" && k.dev != filter {
			continue
		}
		fa.f.First, fa.f.Last, fa.f.LAN = rfc(fa.first), rfc(fa.last), fa.lan.String()
		out.flows[k] = fa.f
	}
	return out
}

// refLAN reports whether a is an address of the home network: of a local network, or one the
// Device List read dr (nil: none) lists, or an IPv6 address in the /64 of a global one it lists.
func refLAN(dr *refDev, a netip.Addr) bool {
	if isLocal(a) {
		return true
	}
	if dr == nil {
		return false
	}
	for _, d := range dr.devices {
		for _, s := range append([]string{d.IPv4}, d.IPv6...) {
			x, ok := parseDeviceAddr(s)
			if !ok {
				continue
			}
			if x == a {
				return true
			}
			if a.Is6() && x.Is6() && x.IsGlobalUnicast() && !isLocal(x) {
				if p, err := x.Prefix(64); err == nil && p.Contains(a) {
					return true
				}
			}
		}
	}
	return false
}

// refLookup returns the entry a Device List read gives for address a: one that is on first,
// then the first listed.
func refLookup(devices []model.LANDevice, a netip.Addr) *model.LANDevice {
	var found *model.LANDevice
	foundOn := false
	for i := range devices {
		d := &devices[i]
		match := false
		for _, s := range append([]string{d.IPv4}, d.IPv6...) {
			if x, ok := parseDeviceAddr(s); ok && x == a {
				match = true
			}
		}
		if !match {
			continue
		}
		on := strings.EqualFold(strings.TrimSpace(d.Status), "on")
		if found == nil || on && !foundOn {
			found, foundOn = d, on
		}
	}
	return found
}

// compareWithReference reports how an aggregate differs from the reference's.
func compareWithReference(t testing.TB, what string, got model.ConnAggregate, want refAggregate) {
	t.Helper()
	var diffs []string
	if got.Samples != want.samples || got.InUse != want.inUse || got.Available != want.avail || got.Open != want.open {
		diffs = append(diffs, fmt.Sprintf("totals %d/%d/%d/%d, want %d/%d/%d/%d", got.Samples, got.InUse, got.Available, got.Open,
			want.samples, want.inUse, want.avail, want.open))
	}
	if want.samples > 0 && (got.First != rfc(want.first) || got.Last != rfc(want.last)) {
		diffs = append(diffs, fmt.Sprintf("first/last %s %s, want %s %s", got.First, got.Last, rfc(want.first), rfc(want.last)))
	}
	if len(got.Devices) != len(want.devices) {
		diffs = append(diffs, fmt.Sprintf("%d devices, want %d", len(got.Devices), len(want.devices)))
	}
	for _, d := range got.Devices {
		if w, ok := want.devices[d.Key]; !ok || w != d {
			diffs = append(diffs, fmt.Sprintf("device %+v, want %+v", d, w))
		}
	}
	if len(got.Flows) != len(want.flows) {
		diffs = append(diffs, fmt.Sprintf("%d flows, want %d", len(got.Flows), len(want.flows)))
	}
	for _, f := range got.Flows {
		k := refFlowKey{dev: f.Device, remote: f.Remote, proto: f.Proto, port: f.Port, inbound: f.Inbound}
		if w, ok := want.flows[k]; !ok || w != f {
			diffs = append(diffs, fmt.Sprintf("flow %+v, want %+v", f, w))
		}
	}
	if len(diffs) > 0 {
		if len(diffs) > 10 {
			diffs = append(diffs[:10], fmt.Sprintf("... %d more", len(diffs)-10))
		}
		t.Errorf("%s:\n%s", what, strings.Join(diffs, "\n"))
	}
	checkOrder(t, what, got)
}

// checkOrder checks that devices and flows are ordered by weight, then samples, (flows) the
// newest, then by key.
func checkOrder(t testing.TB, what string, a model.ConnAggregate) {
	t.Helper()
	for i := 1; i < len(a.Devices); i++ {
		p, d := a.Devices[i-1], a.Devices[i]
		if c := cmp.Or(cmp.Compare(d.Weight, p.Weight), cmp.Compare(d.Samples, p.Samples), strings.Compare(p.Key, d.Key)); c >= 0 {
			t.Errorf("%s: devices out of order: %+v before %+v", what, p, d)
		}
	}
	for i := 1; i < len(a.Flows); i++ {
		p, f := a.Flows[i-1], a.Flows[i]
		pr, fr := netip.MustParseAddr(p.Remote), netip.MustParseAddr(f.Remote)
		c := cmp.Or(cmp.Compare(f.Weight, p.Weight), cmp.Compare(f.Samples, p.Samples),
			mustTime(t, f.Last).Compare(mustTime(t, p.Last)), strings.Compare(p.Device, f.Device), pr.Compare(fr),
			cmp.Compare(p.Port, f.Port), strings.Compare(p.Proto, f.Proto))
		if c > 0 || c == 0 && p.Inbound && !f.Inbound {
			t.Errorf("%s: flows out of order: %+v before %+v", what, p, f)
		}
	}
}

// ---------------------------------------------------------------- random reads

// randomReads appends random NAT table and Device List reads over days 0 to days-1 through h
// (moving its clock, so the days roll over and are compressed), and returns them. Devices change
// addresses, DHCP gives addresses away, entries are off or have no MAC address, sessions go both
// ways and from the gateway, some do not parse, and now and then the clock is set back over
// midnight.
func randomReads(h *harness, rng *rand.Rand, days int) ([]refNAT, []refDev) {
	h.t.Helper()
	type dev struct {
		mac, host int
		name      string
		on        bool
	}
	devs := []*dev{{1, 10, "test-laptop", true}, {2, 11, "test-phone", true}, {3, 12, "test-tv", true},
		{4, 13, "test-tablet", true}, {5, 14, "test-console", true}, {0, 15, "test-printer", true}}
	remotes := []string{"203.0.113.5", "203.0.113.6", "198.51.100.7", "198.51.100.8", "192.0.2.53", "192.0.2.80"}
	var nats []refNAT
	var dls []refDev
	listDevices := func() []model.LANDevice {
		var out []model.LANDevice
		for _, d := range devs {
			e := device(d.host, d.mac, d.name, []string{"Wi-Fi", "Ethernet", ""}[rng.IntN(3)])
			if !d.on {
				e.Status = "off"
			}
			if rng.IntN(5) == 0 {
				e.Name = "" // the gateway does not always show a name
			}
			out = append(out, e)
		}
		return out
	}
	t := at(0, 0, 0).Add(time.Duration(rng.IntN(60)) * time.Minute)
	end := at(days, 0, 0)
	nextDevices := t
	lastDay := day(-1)
	for t.Before(end) {
		h.clk.Set(t)
		if !t.Before(nextDevices) {
			// Now and then a device moves to another address - sometimes one another device had.
			if rng.IntN(3) == 0 {
				d := devs[rng.IntN(len(devs))]
				d.host = 10 + rng.IntN(8)
			}
			if rng.IntN(4) == 0 {
				d := devs[rng.IntN(len(devs))]
				d.on = !d.on
			}
			list := listDevices()
			h.devices(t, list...)
			dls = append(dls, refDev{t: t, devices: list})
			nextDevices = t.Add(time.Duration(60+rng.IntN(120)) * time.Minute)
		}
		var sessions []model.NATSession
		for range rng.IntN(25) {
			host := 10 + rng.IntN(9) // .18 is never listed
			remote := remotes[rng.IntN(len(remotes))]
			switch r := rng.IntN(20); {
			case r < 13:
				sessions = append(sessions, tcp(host, 40000+rng.IntN(5), remote, []int{443, 80, 8443}[rng.IntN(3)]))
			case r < 16:
				sessions = append(sessions, udp(host, 50000+rng.IntN(3), remote, []int{53, 443, 123}[rng.IntN(3)]))
			case r < 18:
				sessions = append(sessions, session("tcp", remote, 50000+rng.IntN(9), lanIP(host), 8080))
			case r < 19:
				sessions = append(sessions, session("udp", gatewayIP, 33000+rng.IntN(5), remote, 123))
			default:
				sessions = append(sessions, session("tcp", "bogus", 1, remote, 443))
			}
		}
		nat := model.NATTable{Sessions: sessions, InUse: len(sessions) + rng.IntN(5), Available: 8000 - rng.IntN(100)}
		h.natTable(t, nat)
		nats = append(nats, refNAT{t: t, nat: nat})
		// After the first read of a day, every other day, the clock goes back over midnight.
		if d := dayOf(t); d > lastDay && lastDay >= 0 && rng.IntN(2) == 0 {
			back := d.start().Add(-time.Duration(1+rng.IntN(5)) * time.Minute)
			h.clk.Set(back)
			late := model.NATTable{Sessions: sessions[:len(sessions)/2], InUse: 1, Available: 1}
			h.natTable(back, late)
			nats = append(nats, refNAT{t: back, nat: late})
		}
		lastDay = dayOf(t)
		t = t.Add(time.Duration(20+rng.IntN(100)) * time.Minute)
	}
	return nats, dls
}

// randomPeriods returns periods to query: whole days, the last 24 hours, spans across days with
// odd ends, everything, and periods with no end or no start.
func randomPeriods(rng *rand.Rand, days int, now time.Time) [][2]time.Time {
	ps := [][2]time.Time{
		{time.Time{}, time.Time{}},
		{now.Add(-24 * time.Hour), now},
		{at(0, 0, 0), at(days, 0, 0)},
		{at(1, 0, 0), time.Time{}},
		{time.Time{}, at(2, 0, 0)},
	}
	for d := range days {
		ps = append(ps, [2]time.Time{at(d, 0, 0), at(d+1, 0, 0)})
	}
	for range 25 {
		from := at(0, 0, 0).Add(time.Duration(rng.Int64N(int64(days+1) * int64(24*time.Hour))))
		to := from.Add(time.Duration(rng.Int64N(int64(4 * 24 * time.Hour))))
		ps = append(ps, [2]time.Time{from, to})
	}
	return ps
}

// TestAggregateMatchesTheReference checks Aggregate against the reference on random reads over
// a week: cold and with every past day cached, by device, after a restart and after days were
// pruned.
func TestAggregateMatchesTheReference(t *testing.T) {
	for seed := uint64(1); seed <= 3; seed++ {
		t.Run(fmt.Sprint("seed ", seed), func(t *testing.T) {
			rng := rand.New(rand.NewPCG(seed, 99))
			const days = 7
			h := newHarness(t, at(0, 0, 0), Options{KeepDays: 365})
			nats, devs := randomReads(h, rng, days)
			now := h.clk.Now()
			late := 0
			for i := 1; i < len(nats); i++ {
				if dayOf(nats[i].t) < dayOf(nats[i-1].t) {
					late++
				}
			}
			const moved = "the file of a day after today was being written"
			if late == 0 || h.log.count(moved) != late {
				t.Fatalf("%d reads after the clock went back, %d logged: the test does not cover them", late,
					h.log.count(moved))
			}
			periods := randomPeriods(rng, days, now)
			check := func(stage string) {
				t.Helper()
				for _, p := range periods {
					all := h.agg(p[0], p[1])
					compareWithReference(t, fmt.Sprintf("%s %s..%s", stage, p[0], p[1]), all, reference(nats, devs, p[0], p[1], ""))
					checkConsistent(t, all)
					if len(all.Devices) > 0 {
						key := all.Devices[rng.IntN(len(all.Devices))].Key
						compareWithReference(t, fmt.Sprintf("%s %s..%s device %s", stage, p[0], p[1], key),
							h.aggDevice(p[0], p[1], key), reference(nats, devs, p[0], p[1], key))
					}
				}
			}
			check("cold")
			hits := h.s.stats.sumHits.Load()
			check("warm")
			if h.s.stats.sumHits.Load() == hits {
				t.Error("the second round of queries used no cached day")
			}
			h.reopen()
			check("reopened")

			// Prune the first two days: their reads, and their Device List reads, are gone. (The
			// age limit applies once the store has been open for an hour.)
			h.clk.Set(now.Add(ageDelay))
			h.s.SetRetention(days-2, DefaultKeepMB)
			if err := h.s.Prune(now); err != nil {
				t.Fatal(err)
			}
			cut := dayOf(now) - day(days-2)
			nats = slices.DeleteFunc(nats, func(r refNAT) bool { return dayOf(r.t) < cut })
			devs = slices.DeleteFunc(devs, func(r refDev) bool { return dayOf(r.t) < cut })
			check("pruned")
		})
	}
}
