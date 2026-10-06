package connstore

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

func TestInboundAndGatewaySessions(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{})
	h.devices(at(0, 9, 0), device(20, 5, "test-nas", "Ethernet"))
	h.nat(at(0, 10, 0),
		// A port forward: the remote side opened the session to the NAS's port 8080.
		session("tcp", "203.0.113.9", 51515, lanIP(20), 8080),
		session("tcp", "203.0.113.9", 51516, lanIP(20), 8080),
		// The gateway's own session from its public address.
		session("udp", gatewayIP, 33000, "198.51.100.7", 123),
		// A LAN address the Device List does not list.
		tcp(50, 40000, "192.0.2.80", 80),
	)
	a := h.agg(day0, at(1, 0, 0))
	checkConsistent(t, a)
	in := findFlow(t, a, macKey(5), "203.0.113.9", 8080, "tcp")
	if !in.Inbound || in.LAN != lanIP(20) || in.Weight != 2 || in.Samples != 1 {
		t.Errorf("inbound flow = %+v", in)
	}
	gw := findFlow(t, a, gatewayKey, "198.51.100.7", 123, "udp")
	if gw.Inbound || gw.LAN != gatewayIP || gw.Weight != 1 {
		t.Errorf("gateway flow = %+v", gw)
	}
	if d := findDevice(t, a, gatewayKey); d.Name != "" || d.IPv4 != gatewayIP || d.MAC != "" || d.Samples != 1 {
		t.Errorf("gateway device = %+v", d)
	}
	if d := findDevice(t, a, "ip:"+lanIP(50)); d.Name != "" || d.IPv4 != lanIP(50) || d.MAC != "" {
		t.Errorf("unlisted device = %+v", d)
	}
	if f := findFlow(t, a, "ip:"+lanIP(50), "192.0.2.80", 80, "tcp"); f.Inbound {
		t.Errorf("outbound flow = %+v", f)
	}
	if d := findDevice(t, a, macKey(5)); d.Name != "test-nas" || d.Connection != "Ethernet" || d.Weight != 2 {
		t.Errorf("NAS = %+v", d)
	}
}

func TestSameKeyBothDirectionsAreTwoFlows(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{})
	h.nat(at(0, 10, 0),
		tcp(10, 50000, "203.0.113.5", 443),
		session("tcp", "203.0.113.5", 50001, lanIP(10), 443),
	)
	a := h.agg(day0, at(1, 0, 0))
	if len(a.Flows) != 2 || a.Flows[0].Inbound == a.Flows[1].Inbound {
		t.Errorf("flows = %+v, want one each way", a.Flows)
	}
}

func TestDeviceNamingNearestBeforeElseAfter(t *testing.T) {
	h := newHarness(t, at(0, 20, 0), Options{})
	// 192.168.1.10 belongs to one device until 12:00, then DHCP gives it to another.
	h.devices(at(0, 10, 0), device(10, 1, "test-laptop", "Wi-Fi"))
	h.devices(at(0, 12, 0), device(10, 2, "test-tablet", "Wi-Fi"))
	for _, tm := range []time.Time{at(0, 9, 0), at(0, 11, 0), at(0, 12, 0), at(0, 13, 0)} {
		h.nat(tm, tcp(10, 50000, "203.0.113.5", 443))
	}
	a := h.agg(day0, at(1, 0, 0))
	checkConsistent(t, a)
	// 09:00 has no read before it: the first after (10:00). 11:00: 10:00. 12:00 and 13:00: 12:00.
	laptop, tablet := findFlow(t, a, macKey(1), "203.0.113.5", 443, "tcp"), findFlow(t, a, macKey(2), "203.0.113.5", 443, "tcp")
	if laptop.Samples != 2 || laptop.First != rfc(at(0, 9, 0)) || laptop.Last != rfc(at(0, 11, 0)) {
		t.Errorf("laptop = %+v", laptop)
	}
	if tablet.Samples != 2 || tablet.First != rfc(at(0, 12, 0)) || tablet.Last != rfc(at(0, 13, 0)) {
		t.Errorf("tablet = %+v", tablet)
	}
	if d := findDevice(t, a, macKey(2)); d.Name != "test-tablet" || d.IPv4 != lanIP(10) {
		t.Errorf("tablet device = %+v", d)
	}
}

func TestDeviceKeepsItsKeyAcrossAddressChanges(t *testing.T) {
	h := newHarness(t, at(1, 20, 0), Options{})
	h.devices(at(0, 10, 0), device(10, 1, "test-laptop", "Wi-Fi 2.4 GHz"))
	h.nat(at(0, 11, 0), tcp(10, 50000, "203.0.113.5", 443))
	h.devices(at(1, 10, 0), device(30, 1, "", "Ethernet")) // a new address, and no name shown now
	h.nat(at(1, 11, 0), tcp(30, 50000, "203.0.113.5", 443))
	a := h.agg(day0, at(2, 0, 0))
	checkConsistent(t, a)
	if len(a.Devices) != 1 || len(a.Flows) != 1 {
		t.Fatalf("devices %+v flows %+v, want one of each", a.Devices, a.Flows)
	}
	d := a.Devices[0]
	// The newest non-empty name, the newest connection and address.
	if d.Key != macKey(1) || d.Name != "test-laptop" || d.Connection != "Ethernet" || d.IPv4 != lanIP(30) || d.Samples != 2 {
		t.Errorf("device = %+v", d)
	}
	if f := a.Flows[0]; f.LAN != lanIP(30) || f.Samples != 2 || f.First != rfc(at(0, 11, 0)) || f.Last != rfc(at(1, 11, 0)) {
		t.Errorf("flow = %+v", f)
	}
}

func TestDeviceListEntriesThatAreOnWin(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{})
	gone := device(10, 3, "test-old-phone", "")
	gone.Status = "off"
	h.devices(at(0, 9, 0), gone, device(10, 4, "test-console", "Ethernet"), device(11, 0, "test-printer", ""))
	h.nat(at(0, 10, 0), tcp(10, 1, "203.0.113.5", 443), tcp(11, 2, "203.0.113.6", 631))
	a := h.agg(day0, at(1, 0, 0))
	findFlow(t, a, macKey(4), "203.0.113.5", 443, "tcp")
	// A device without a MAC address keeps the address as its key, with its name.
	if d := findDevice(t, a, "ip:"+lanIP(11)); d.Name != "test-printer" || d.MAC != "" {
		t.Errorf("device without a MAC address = %+v", d)
	}
}

func TestDeviceNamesFromIPv6AndOddEntries(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{})
	h.devices(at(0, 9, 0),
		model.LANDevice{MAC: "00-00-5E-00-53-07", Name: " test-tv ", IPv4: "not an address", IPv6: []string{"fd00::7/64", "fe80::7"}, Status: "on"},
		model.LANDevice{MAC: "bad mac", Name: "test-speaker", IPv4: lanIP(12), Status: "on"},
	)
	h.nat(at(0, 10, 0), session("udp", "fd00::7", 5353, "2001:db8::53", 53), session("tcp", "fe80::7", 1, "2001:db8::80", 80),
		tcp(12, 3, "203.0.113.5", 443))
	a := h.agg(day0, at(1, 0, 0))
	checkConsistent(t, a)
	tv := findDevice(t, a, macKey(7))
	if tv.Name != "test-tv" || tv.MAC != macOf(7) || tv.IPv4 != "" || tv.Weight != 2 {
		t.Errorf("IPv6 device = %+v", tv)
	}
	if d := findDevice(t, a, "ip:"+lanIP(12)); d.Name != "test-speaker" {
		t.Errorf("device with a bad MAC address = %+v", d)
	}
}

func TestDeviceNamingAcrossDays(t *testing.T) {
	h := newHarness(t, at(2, 12, 0), Options{})
	h.devices(at(0, 23, 0), device(10, 1, "test-laptop", ""))
	// Day 1 has no Device List read: its NAT reads are named after the one of day 0.
	h.nat(at(1, 8, 0), tcp(10, 1, "203.0.113.5", 443))
	h.nat(at(2, 8, 0), tcp(10, 1, "203.0.113.5", 443))
	whole := h.agg(at(1, 0, 0), at(2, 0, 0)) // day 1 whole: from the cache's path
	part := h.agg(at(1, 1, 0), at(2, 9, 0))  // day 1 in part and today
	for _, a := range []model.ConnAggregate{whole, part} {
		if len(a.Devices) != 1 || a.Devices[0].Key != macKey(1) || a.Devices[0].Name != "test-laptop" {
			t.Errorf("devices = %+v", a.Devices)
		}
	}
	if whole.Samples != 1 || part.Samples != 2 {
		t.Errorf("samples: whole day %d, part %d", whole.Samples, part.Samples)
	}
}

func TestDeviceFilter(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{})
	h.devices(at(0, 9, 0), device(10, 1, "test-laptop", ""), device(11, 2, "test-phone", ""))
	h.nat(at(0, 10, 0), tcp(10, 1, "203.0.113.5", 443), tcp(11, 2, "198.51.100.7", 443))
	h.natTable(at(0, 10, 4), model.NATTable{InUse: 9, Available: 7, Sessions: []model.NATSession{tcp(11, 2, "198.51.100.7", 443)}})
	all := h.agg(day0, at(1, 0, 0))
	one := h.aggDevice(day0, at(1, 0, 0), macKey(1))
	if len(one.Devices) != 1 || one.Devices[0].Key != macKey(1) || len(one.Flows) != 1 || one.Flows[0].Device != macKey(1) {
		t.Errorf("filtered = %+v", one)
	}
	if one.Samples != all.Samples || one.First != all.First || one.Last != all.Last || one.InUse != 9 ||
		one.Available != 7 || one.Open != 1 {
		t.Errorf("filtered totals = %+v, want those of every device %+v", one, all)
	}
	if one.Devices[0] != findDevice(t, all, macKey(1)) {
		t.Errorf("filtered device %+v differs from %+v", one.Devices[0], findDevice(t, all, macKey(1)))
	}
	none := h.aggDevice(day0, at(1, 0, 0), "mac:00:00:5e:00:53:99")
	if len(none.Devices) != 0 || len(none.Flows) != 0 || none.Devices == nil || none.Flows == nil || none.Samples != 2 {
		t.Errorf("unknown device = %+v", none)
	}
}

func TestPeriodBounds(t *testing.T) {
	h := newHarness(t, at(3, 12, 0), Options{})
	times := []time.Time{at(0, 10, 0), at(1, 0, 0), at(1, 23, 59), at(2, 0, 0), at(3, 11, 0)}
	for i, tm := range times {
		h.nat(tm, tcp(10, i, "203.0.113.5", 443))
	}
	cases := []struct {
		name     string
		from, to time.Time
		want     int
	}{
		{"everything", time.Time{}, time.Time{}, 5},
		{"from is in, to is out", at(1, 0, 0), at(2, 0, 0), 2},
		{"a day and a nanosecond", at(1, 0, 0), at(2, 0, 0).Add(time.Nanosecond), 3},
		{"no end", at(2, 0, 0), time.Time{}, 2},
		{"no start", time.Time{}, at(1, 0, 0), 1},
		{"empty", at(1, 0, 0), at(1, 0, 0), 0},
		{"reversed", at(2, 0, 0), at(1, 0, 0), 0},
		{"before everything", at(-5, 0, 0), at(-4, 0, 0), 0},
		{"far ahead", at(100, 0, 0), at(200, 0, 0), 0},
		{"the years beyond", time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2500, 1, 1, 0, 0, 0, 0, time.UTC), 5},
	}
	for _, c := range cases {
		a := h.agg(c.from, c.to)
		if a.Samples != c.want {
			t.Errorf("%s: %d reads, want %d", c.name, a.Samples, c.want)
		}
		checkConsistent(t, a)
	}
}

func TestOrderIsByWeightThenDeterministic(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{})
	h.nat(at(0, 10, 0),
		tcp(12, 1, "203.0.113.5", 443), tcp(12, 2, "203.0.113.5", 443), tcp(12, 3, "203.0.113.5", 443), // weight 3
		tcp(11, 1, "198.51.100.9", 443), udp(11, 2, "198.51.100.9", 443), // two flows of weight 1
		tcp(10, 1, "198.51.100.9", 80), tcp(10, 2, "192.0.2.1", 80), // weight 1 each
	)
	h.nat(at(0, 10, 4), tcp(10, 3, "198.51.100.9", 80)) // 10 -> .9:80 now weight 2, samples 2
	a := h.agg(day0, at(1, 0, 0))
	type key struct {
		dev, remote string
		port        int
		proto       string
	}
	var got []key
	for _, f := range a.Flows {
		got = append(got, key{f.Device, f.Remote, f.Port, f.Proto})
	}
	want := []key{
		{"ip:" + lanIP(12), "203.0.113.5", 443, "tcp"},
		{"ip:" + lanIP(10), "198.51.100.9", 80, "tcp"},
		// Weight 1, one read each, the same last read: by device, remote address, port, protocol.
		{"ip:" + lanIP(10), "192.0.2.1", 80, "tcp"},
		{"ip:" + lanIP(11), "198.51.100.9", 443, "tcp"},
		{"ip:" + lanIP(11), "198.51.100.9", 443, "udp"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("flow order = %v\nwant %v", got, want)
	}
	// Devices: .10 and .12 both weigh 3; .10 was seen in more reads.
	if keys := deviceKeys(a); !reflect.DeepEqual(keys, []string{"ip:" + lanIP(10), "ip:" + lanIP(12), "ip:" + lanIP(11)}) {
		t.Errorf("device order = %v", keys)
	}
	// The same order every time.
	for range 5 {
		if b := h.agg(day0, at(1, 0, 0)); !reflect.DeepEqual(a, b) {
			t.Fatal("the order changed between two queries")
		}
	}
}

func TestDamagedSessionsAreSkipped(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{})
	h.nat(at(0, 10, 0),
		session("tcp", "not-an-address", 1, "203.0.113.5", 443),
		session("tcp", lanIP(10), 1, "", 443),
		session("TCP", lanIP(10), 2, "203.0.113.5", 70000), // a port out of range is 0
		tcp(10, 3, "203.0.113.5", 443),
	)
	a := h.agg(day0, at(1, 0, 0))
	checkConsistent(t, a)
	if a.Samples != 1 || a.Open != 4 || len(a.Flows) != 2 {
		t.Errorf("aggregate = %+v", a)
	}
	findFlow(t, a, "ip:"+lanIP(10), "203.0.113.5", 0, "tcp")
	if h.log.attr("NAT sessions that cannot be read", "sessions") != "2" {
		t.Errorf("not logged:\n%s", h.log.all())
	}
}

func TestAggregateHonoursItsContext(t *testing.T) {
	h := newHarness(t, at(3, 12, 0), Options{})
	fillDays(h, 0, 3, 5)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.s.Aggregate(ctx, contracts.ConnQuery{}); !errors.Is(err, context.Canceled) {
		t.Errorf("Aggregate with a cancelled context: %v", err)
	}
	// Cancelled during a scan: a context that is done after a few checks.
	ctx2 := &countdownCtx{Context: context.Background(), left: 3}
	if _, err := h.s.Aggregate(ctx2, contracts.ConnQuery{}); !errors.Is(err, context.Canceled) {
		t.Errorf("Aggregate cancelled meanwhile: %v", err)
	}
}

// countdownCtx is a context whose Err turns context.Canceled after left calls.
type countdownCtx struct {
	context.Context
	left int
}

func (c *countdownCtx) Err() error {
	if c.left <= 0 {
		return context.Canceled
	}
	c.left--
	return nil
}

// TestIPv6SessionsOfListedDevices: a session from a LAN device's global IPv6 address - one the
// Device List read in effect lists, or another of the home network's /64 such as a temporary
// address - is the device's, not the gateway's own; and one to it (an inbound pinhole) has the
// remote host as its remote side, never the household's own address.
func TestIPv6SessionsOfListedDevices(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{})
	laptop := device(10, 1, "test-laptop", "Wi-Fi")
	laptop.IPv6 = []string{"2001:db8::100", "fe80::100"}
	h.devices(at(0, 9, 0), laptop)
	h.nat(at(0, 10, 0),
		session("tcp", "2001:db8::100", 50000, "2001:db8:ffff::10", 443), // outbound, from its listed address
		session("tcp", "2001:db8:ffff::77", 40000, "2001:db8::100", 22),  // inbound, to it
		session("udp", "2001:db8::abcd", 50001, "2001:db8:ffff::53", 53), // a temporary address of the same /64
		session("udp", gatewayIP, 33000, "198.51.100.7", 123),            // the gateway's own, still
	)
	a := h.agg(day0, at(1, 0, 0))
	checkConsistent(t, a)
	out := findFlow(t, a, macKey(1), "2001:db8:ffff::10", 443, "tcp")
	in := findFlow(t, a, macKey(1), "2001:db8:ffff::77", 22, "tcp")
	if out.Inbound || out.LAN != "2001:db8::100" || !in.Inbound || in.LAN != "2001:db8::100" {
		t.Errorf("flows of the listed address: out %+v, in %+v", out, in)
	}
	if f := findFlow(t, a, "ip:2001:db8::abcd", "2001:db8:ffff::53", 53, "udp"); f.Inbound {
		t.Errorf("flow of the temporary address = %+v", f)
	}
	for _, f := range a.Flows {
		if f.Remote == "2001:db8::100" || f.Remote == "2001:db8::abcd" {
			t.Errorf("the household's own address is a remote side: %+v", f)
		}
		if f.Device == gatewayKey && f.Remote != "198.51.100.7" {
			t.Errorf("a device's session is the gateway's: %+v", f)
		}
	}
}

// TestAggregateBoundsTheFlows: a device that opens connections to ever new addresses - here
// thousands of light flows a day beside the household's few heavy ones - cannot make a query hold
// more than maxFlows flows: the lightest are left out, the heavy ones are all kept with their exact
// counts, and every session still counts in its device's weight. So it is for a single day (the
// scan) and for several (the merge), with and without a device filter.
func TestAggregateBoundsTheFlows(t *testing.T) {
	h := newHarness(t, at(3, 12, 0), Options{})
	h.s.maxFlows = 100
	h.devices(at(0, 1, 0), device(10, 1, "test-laptop", "Wi-Fi"), device(66, 6, "test-scanner", "Ethernet"))
	sessions := 0
	for d := range 3 {
		for r := range 6 {
			var ss []model.NATSession
			for i := range 2 { // the laptop's heavy flows, in every read
				ss = append(ss, tcp(10, 40000+i, fmt.Sprintf("203.0.113.%d", 10+i), 443))
			}
			for i := range 40 { // the scanner's light ones: each new address once
				ss = append(ss, tcp(66, 50000+i, fmt.Sprintf("198.51.%d.%d", 100+d, r*40+i), 22))
			}
			sessions += len(ss)
			h.nat(at(d, 2+r, 0), ss...)
		}
	}
	for _, tc := range []struct {
		name     string
		from, to time.Time
	}{{"one day", at(0, 0, 0), at(1, 0, 0)}, {"three days", day0, at(3, 0, 0)}, {"today in part", at(2, 4, 0), at(3, 0, 0)}} {
		a := h.agg(tc.from, tc.to)
		if len(a.Flows) > 100 || a.FlowsLeftOut == 0 {
			t.Fatalf("%s: %d flows, %d left out; want at most 100, some left out", tc.name, len(a.Flows), a.FlowsLeftOut)
		}
		laptop, scanner := findDevice(t, a, macKey(1)), findDevice(t, a, macKey(6))
		weights := map[string]int{}
		for _, f := range a.Flows {
			weights[f.Device] += f.Weight
		}
		if laptop.LeftOut != 0 || weights[macKey(1)] != laptop.Weight || weights[macKey(6)]+scanner.LeftOut != scanner.Weight {
			t.Fatalf("%s: laptop %+v, scanner %+v, flow weights %v", tc.name, laptop, scanner, weights)
		}
		for i := range 2 {
			f := findFlow(t, a, macKey(1), fmt.Sprintf("203.0.113.%d", 10+i), 443, "tcp")
			if f.Samples != a.Samples || f.Weight != a.Samples {
				t.Fatalf("%s: a heavy flow lost counts: %+v of %d reads", tc.name, f, a.Samples)
			}
		}
	}
	all := h.agg(day0, at(3, 0, 0))
	total := 0
	for _, d := range all.Devices {
		total += d.Weight
	}
	if total != sessions {
		t.Fatalf("the devices' weights add up to %d sessions, want %d", total, sessions)
	}
	one := h.aggDevice(day0, at(3, 0, 0), macKey(6))
	if len(one.Flows) > 100 || one.FlowsLeftOut == 0 || len(one.Devices) != 1 || one.Devices[0].Weight != findDevice(t, all, macKey(6)).Weight {
		t.Fatalf("the scanner alone: %d flows, %d left out, devices %+v", len(one.Flows), one.FlowsLeftOut, one.Devices)
	}
	if lap := h.aggDevice(day0, at(3, 0, 0), macKey(1)); lap.FlowsLeftOut != 0 || len(lap.Flows) != 2 {
		t.Fatalf("the laptop alone: %d flows, %d left out", len(lap.Flows), lap.FlowsLeftOut)
	}
}

// TestDaySummaryBoundsTheFlows: a day's summary - what the cache keeps, and what a scan holds
// before the merge - counts at most maxFlows flows one by one too: a day of a device that opens
// connections to ever new addresses must not grow the scan beyond the bound before the merge
// applies it. The heavy flow stays exact; the light ones left out still count in their device.
func TestDaySummaryBoundsTheFlows(t *testing.T) {
	h := newHarness(t, at(3, 12, 0), Options{})
	h.s.maxFlows = 40
	h.devices(at(0, 1, 0), device(10, 1, "test-laptop", "Wi-Fi"), device(66, 6, "test-scanner", "Ethernet"))
	for r := range 6 {
		ss := []model.NATSession{tcp(10, 40000, "203.0.113.10", 443)}
		for i := range 30 { // each new address once: 180 light flows in all
			ss = append(ss, tcp(66, 50000+i, fmt.Sprintf("198.51.100.%d", r*30+i), 22))
		}
		h.nat(at(0, 2+r, 0), ss...)
	}
	d := dayOf(at(0, 0, 0))
	sum, _, err := h.s.scanDay(context.Background(), d, newDevView(h.s, h.s.snapshot()).segment(d), d.start(), d.end())
	if err != nil || sum == nil {
		t.Fatalf("scanDay: %v, %v", sum, err)
	}
	if len(sum.flows) > 40 {
		t.Fatalf("the day's summary holds %d flows, want at most 40", len(sum.flows))
	}
	devs := map[string]devSum{}
	for _, ds := range sum.devs {
		devs[ds.key] = ds
	}
	laptop, scanner := devs[macKey(1)], devs[macKey(6)]
	if laptop.weight != 6 || laptop.leftFlows != 0 || scanner.weight != 180 || scanner.leftFlows == 0 ||
		scanner.leftOut != scanner.leftFlows || scanner.leftFlows+len(sum.flows)-1 != 180 {
		t.Fatalf("laptop %+v, scanner %+v, %d flows kept", laptop, scanner, len(sum.flows))
	}
	heavy := false
	for _, f := range sum.flows {
		if sum.devs[f.dev].key == macKey(1) {
			heavy = f.samples == 6 && f.weight == 6
		}
	}
	if !heavy {
		t.Fatalf("the laptop's flow, in every read, lost counts or was left out: %+v", sum.flows)
	}
}

// TestAggregateStopsAfterTheScan: a query whose context ends while its flows are merged or written
// out stops there with the context's error, rather than finish work nobody waits for.
func TestAggregateStopsAfterTheScan(t *testing.T) {
	h := newHarness(t, at(1, 12, 0), Options{})
	var ss []model.NATSession
	for i := range 3 * mergeEvery {
		ss = append(ss, tcp(10, 40000+i%20000, fmt.Sprintf("2001:db8:ffff::%x", i), 443))
	}
	h.nat(at(0, 10, 0), ss...)
	if a := h.agg(day0, at(1, 0, 0)); len(a.Flows) != 3*mergeEvery { // the day's summary is cached: no line is read below
		t.Fatalf("%d flows", len(a.Flows))
	}
	// The checks: the query's start (1) and the day's (2); the merge's, every mergeEvery flows (3-5);
	// the written out flows', before the sort and every mergeEvery (6-9).
	for _, checks := range []int{2, 3, 4, 5, 6, 7, 8} {
		ctx := &countdownCtx{Context: context.Background(), left: checks}
		if _, err := h.s.Aggregate(ctx, contracts.ConnQuery{From: day0, To: at(1, 0, 0)}); !errors.Is(err, context.Canceled) {
			t.Errorf("cancelled after %d checks: %v", checks, err)
		}
	}
	if _, err := h.s.Aggregate(&countdownCtx{Context: context.Background(), left: 9}, contracts.ConnQuery{From: day0, To: at(1, 0, 0)}); err != nil {
		t.Errorf("a query that checks its context 9 times: %v", err)
	}
}

// TestNewDeviceNamedAfterTheNextDeviceList: a device that joined after the Device List read in
// effect - its address unlisted there - is named after the next read that lists it, when that
// comes within devNextWithin: it keeps one key, and is not counted twice (as its address, then as
// its MAC). A read further away does not name it.
func TestNewDeviceNamedAfterTheNextDeviceList(t *testing.T) {
	h := newHarness(t, at(0, 23, 0), Options{})
	pc, phone := device(71, 1, "test-pc", "Ethernet"), device(80, 2, "test-phone", "Wi-Fi")
	h.devices(at(0, 10, 0), pc)
	for _, m := range []int{4, 8, 12} {
		h.nat(at(0, 10, m), tcp(71, 50000, "203.0.113.5", 443), tcp(80, 50001, "198.51.100.7", 443))
	}
	h.devices(at(0, 10, 15), pc, phone)
	for _, m := range []int{16, 20} {
		h.nat(at(0, 10, m), tcp(71, 50000, "203.0.113.5", 443), tcp(80, 50001, "198.51.100.7", 443))
	}
	// Later another device joins, listed only 30 minutes after it was first seen: too far.
	h.nat(at(0, 12, 0), tcp(90, 50002, "198.51.100.9", 443))
	h.devices(at(0, 12, 30), pc, phone, device(90, 9, "test-tv", "Wi-Fi"))
	h.nat(at(0, 12, 31), tcp(90, 50002, "198.51.100.9", 443))

	for _, a := range []model.ConnAggregate{h.agg(at(0, 0, 0), at(0, 23, 0)), h.agg(at(0, 10, 0), at(0, 11, 0))} {
		checkConsistent(t, a)
		if d := findDevice(t, a, macKey(2)); d.Samples != 5 || d.Name != "test-phone" {
			t.Errorf("the phone = %+v, want all 5 reads", d)
		}
		for _, d := range a.Devices {
			if d.Key == "ip:"+lanIP(80) {
				t.Errorf("the phone is counted twice: %+v", a.Devices)
			}
		}
	}
	a := h.agg(at(0, 0, 0), at(0, 23, 0))
	findDevice(t, a, "ip:"+lanIP(90))
	findDevice(t, a, macKey(9))
}

// TestOpenDeviceUnderAFilter: with a device filter the aggregate says how many sessions that device
// had in the newest read (OpenDevice), beside the newest read's totals of every device (Open).
func TestOpenDeviceUnderAFilter(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{})
	h.devices(at(0, 9, 0), device(10, 1, "test-laptop", ""), device(11, 2, "test-phone", ""))
	h.nat(at(0, 10, 0), tcp(10, 1, "203.0.113.5", 443), tcp(11, 2, "198.51.100.7", 443))
	h.nat(at(0, 11, 0), tcp(10, 1, "203.0.113.5", 443), tcp(10, 3, "203.0.113.6", 443), tcp(11, 2, "198.51.100.7", 443),
		tcp(11, 4, "198.51.100.8", 443), tcp(11, 5, "198.51.100.9", 443))
	for _, tc := range []struct {
		from     time.Time
		dev      string
		open, of int
	}{
		{day0, macKey(1), 2, 5}, {day0, macKey(2), 3, 5}, {day0, "", 0, 5},
		{at(0, 11, 0), macKey(1), 2, 5}, // today in part: read line by line
	} {
		a := h.aggDevice(tc.from, at(1, 0, 0), tc.dev)
		if a.OpenDevice != tc.open || a.Open != tc.of {
			t.Errorf("%q: %d of %d open, want %d of %d", tc.dev, a.OpenDevice, a.Open, tc.open, tc.of)
		}
	}
}
