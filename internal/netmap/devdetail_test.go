package netmap

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// TestDeviceDetailsOfTheSampleNetwork: a device's details over the sample home network with its
// LAN scans (devscans_test.go): the device as the Devices view lists it, the address history of
// its addresses - its own holds and the others' -, the scans as it answered them, newest first,
// and what its syslog messages are found by: each IPv4 hold widened by the Device List interval
// (here 30 minutes, the reads' median) and clipped to the period, its IPv6 and MAC addresses. An
// unknown address has its own details, found by its address for the whole period.
func TestDeviceDetailsOfTheSampleNetwork(t *testing.T) {
	v, _, _ := scanView(t)
	q := contracts.NetQuery{From: sampleFrom, To: sampleTo}
	dv, err := v.Devices(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]model.NetLANDevice{}
	for _, d := range dv.Devices {
		byName[d.Name] = d
	}
	ts := func(m float64) string { return rfc3339(mins(m)) }
	use := func(addr, n, name string, first, last float64, reads, shared int) model.NetAddrUse {
		return model.NetAddrUse{Addr: addr, Device: "mac:" + devPrefix + n, Name: name, MAC: devPrefix + n, First: ts(first), Last: ts(last),
			Reads: reads, Shared: shared}
	}
	seen := func(at float64, addr string) model.NetScanSeen { return model.NetScanSeen{At: ts(at), Addr: addr} }

	laptop := byName["laptop"]
	dd, err := v.Device(context.Background(), q, laptop.Key, "")
	if err != nil {
		t.Fatal(err)
	}
	want := model.NetDeviceDetail{
		From: ts(0), To: ts(120), Device: &laptop,
		Addresses: []model.NetAddrUse{use("192.168.1.64", "21", "laptop", -10, 15, 2, 0), use("192.168.1.80", "21", "laptop", 45, 105, 3, 0)},
		Scans:     []model.NetScanSeen{seen(110, "192.168.1.80"), seen(90, "192.168.1.80"), seen(30, "192.168.1.64")},
		Match: []model.NetSyslogTerm{
			{Kind: "ipv4", Text: "192.168.1.64", To: ts(45)},   // read from -10 to +15, the period from 0
			{Kind: "ipv4", Text: "192.168.1.80", From: ts(15)}, // read from +45 to +105, the period to +120
			{Kind: "ipv6", Text: "2001:db8:5::21"},
			{Kind: "mac", Text: "00:00:5e:00:53:21"},
		},
		Syslog: []model.SyslogEntry{},
	}
	if !reflect.DeepEqual(dd, want) {
		t.Errorf("laptop:\n got %+v\nwant %+v", dd, want)
	}

	// The printer: camera claims its address too; the printer answered none of the scans.
	printer := byName["printer"]
	dd, err = v.Device(context.Background(), q, printer.Key, "")
	if err != nil {
		t.Fatal(err)
	}
	if want := []model.NetAddrUse{use("192.168.1.71", "25", "printer", -10, 105, 5, 1), use("192.168.1.71", "26", "camera", 105, 105, 1, 1)}; !reflect.DeepEqual(dd.Addresses, want) {
		t.Errorf("printer's addresses:\n got %+v\nwant %+v", dd.Addresses, want)
	}
	if want := []model.NetScanSeen{seen(110, ""), seen(90, ""), seen(30, "")}; !reflect.DeepEqual(dd.Scans, want) {
		t.Errorf("printer's scans %+v", dd.Scans)
	}
	if want := []model.NetSyslogTerm{{Kind: "ipv4", Text: "192.168.1.71"}, {Kind: "mac", Text: "00:00:5e:00:53:25"}}; !reflect.DeepEqual(dd.Match, want) {
		t.Errorf("printer's terms %+v", dd.Match) // held for the whole period
	}
	if dd.Device == nil || !reflect.DeepEqual(*dd.Device, printer) || dd.Unknown != nil {
		t.Errorf("printer: %+v", dd.Device)
	}

	// Unknown addresses: their address for the whole period, the scans as they answered them.
	unknown := map[string]model.NetUnknownAddr{}
	for _, u := range dv.Unknown {
		unknown[u.Addr] = u
	}
	for _, tc := range []struct {
		addr  string
		uses  []model.NetAddrUse
		scans []model.NetScanSeen
	}{
		{"192.168.1.200", []model.NetAddrUse{}, []model.NetScanSeen{seen(110, "192.168.1.200"), seen(90, "192.168.1.200"), seen(30, "")}},
		{"192.168.1.67", []model.NetAddrUse{use("192.168.1.67", "24", "tv", -10, 105, 5, 0)}, // the tv's address, answered by another
			[]model.NetScanSeen{seen(110, "192.168.1.67"), seen(90, ""), seen(30, "")}},
		{"169.254.7.7", []model.NetAddrUse{}, []model.NetScanSeen{seen(110, ""), seen(90, ""), seen(30, "")}},
	} {
		dd, err := v.Device(context.Background(), q, "", tc.addr)
		if err != nil {
			t.Fatalf("%s: %v", tc.addr, err)
		}
		u := unknown[tc.addr]
		want := model.NetDeviceDetail{From: ts(0), To: ts(120), Unknown: &u, Addresses: tc.uses, Scans: tc.scans,
			Match: []model.NetSyslogTerm{{Kind: "ipv4", Text: tc.addr}}, Syslog: []model.SyslogEntry{}}
		if !reflect.DeepEqual(dd, want) {
			t.Errorf("%s:\n got %+v\nwant %+v", tc.addr, dd, want)
		}
	}

	// What the period knows neither of.
	for _, tc := range []struct{ key, addr string }{
		{"mac:00:00:5e:00:53:ff", ""}, {"mac:00:00:5e:00:53:21#2", ""}, {"gateway", ""}, {"", "192.168.1.66"}, // desk-pc's: no unknown address
		{"", "192.168.1.254"}, {"", "192.168.1.91"}, {"", "2001:db8:5::21"}, {"", "not an address"}, {"", "::ffff:192.168.1.200"},
		{"", ""}, {laptop.Key, "192.168.1.200"},
	} {
		if _, err := v.Device(context.Background(), q, tc.key, tc.addr); !errors.Is(err, contracts.ErrNotFound) {
			t.Errorf("key %q addr %q: %v", tc.key, tc.addr, err)
		}
	}
	if _, err := New(Options{}).Device(context.Background(), q, laptop.Key, ""); !errors.Is(err, contracts.ErrUnavailable) {
		t.Errorf("no connection store: %v", err)
	}
	if _, err := New(Options{}).Device(context.Background(), q, "", ""); !errors.Is(err, contracts.ErrUnavailable) {
		t.Errorf("no connection store, no device: %v", err)
	}
	for _, key := range []string{laptop.Key, ""} {
		if _, err := v.Device(context.Background(), contracts.NetQuery{From: sampleTo, To: sampleFrom}, key, ""); !errors.Is(err, ErrRange) {
			t.Errorf("a period backwards (key %q): %v", key, err)
		}
	}
}

// TestDeviceDetailsReuseTheView: the details of a device reuse the Devices view built for the period
// (the one the dashboard asks for, MaxLimit rows): a range ending now is built once for the view
// and the details; what a caller changes in an answer changes nothing kept; the unknown addresses
// beyond the view's limit have their details too.
func TestDeviceDetailsReuseTheView(t *testing.T) {
	v, conns, scans := scanView(t)
	q := contracts.NetQuery{From: sampleFrom, To: sampleTo, Range: "24h", Limit: MaxLimit}
	dv, err := v.Devices(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	reads, scanReads := conns.eachCalls(), scans.eachCalls()
	for range 3 {
		dd, err := v.Device(context.Background(), contracts.NetQuery{From: sampleFrom, To: sampleTo, Range: "24h"}, dv.Devices[0].Key, "")
		if err != nil {
			t.Fatal(err)
		}
		dd.Device.Name, dd.Device.Issues[0].Text, dd.Scans[0].Addr, dd.Addresses[0].Name = "changed", "changed", "changed", "changed"
		dd.Match[0].Text = "changed"
	}
	if conns.eachCalls() != reads || scans.eachCalls() != scanReads {
		t.Errorf("the details built the view again: %d and %d reads, want %d and %d", conns.eachCalls(), scans.eachCalls(), reads, scanReads)
	}
	again, err := v.Devices(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(again, dv) {
		t.Error("a caller changed the view kept for reuse through the details")
	}
	dd, _ := v.Device(context.Background(), q, dv.Devices[0].Key, "")
	if dd.Device.Name == "changed" || dd.Scans[0].Addr == "changed" || dd.Match[0].Text == "changed" || dd.Addresses[0].Name == "changed" {
		t.Errorf("a caller changed the details kept: %+v", dd)
	}

	// A view of one unknown address lists one; the details find the others.
	one, err := v.Devices(context.Background(), contracts.NetQuery{From: sampleFrom, To: sampleTo, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(one.Unknown) != 1 || one.Totals.Unknown != 5 {
		t.Fatalf("%d unknown listed of %d", len(one.Unknown), one.Totals.Unknown)
	}
	for _, u := range dv.Unknown {
		if dd, err := v.Device(context.Background(), contracts.NetQuery{From: sampleFrom, To: sampleTo, Limit: 1}, "", u.Addr); err != nil ||
			dd.Unknown == nil || dd.Unknown.Addr != u.Addr {
			t.Errorf("%s: %+v, %v", u.Addr, dd.Unknown, err)
		}
	}
}

// TestDeviceMatch: a device's IPv4 holds are widened by the Device List interval on each side,
// clipped to the period and joined where they meet - per address -, at most maxMatchIPv4 of them
// (the newest), oldest first; its IPv6 addresses are those of the newest read, then those the
// period's reads gave it, each once and at most maxDeviceV6; its MAC address last.
func TestDeviceMatch(t *testing.T) {
	ts := func(m float64) string { return rfc3339(mins(m)) }
	tenure := func(dev, addr string, first, last float64) model.NetAddrUse {
		return model.NetAddrUse{Addr: addr, Device: dev, First: ts(first), Last: ts(last), Reads: 1}
	}
	b := &devBuild{
		view: model.NetDevicesView{From: ts(0), To: ts(600), Addresses: []model.NetAddrUse{
			tenure("mac:a", "192.168.1.10", -30, 20),   // [-45, 35) → from the start
			tenure("mac:a", "192.168.1.10", 50, 100),   // [35, 115): meets the one before
			tenure("mac:a", "192.168.1.10", 200, 200),  // [185, 215)
			tenure("mac:a", "192.168.1.11", 120, 180),  // [105, 195)
			tenure("mac:a", "192.168.1.12", 590, 590),  // [575, 605) → to the end
			tenure("mac:a", "192.168.1.13", -100, -20), // [-115, -5): before the period
			tenure("mac:b", "192.168.1.10", 120, 170),  // another device's
			{Addr: "192.168.1.14", Device: "mac:a", First: "bogus", Last: ts(5)},
			tenure("mac:a", "2001:db8::1", 10, 20), // not an IPv4 address
		}},
		every: 15 * time.Minute,
		v6:    map[string][]netip.Addr{"mac:a#2": {netip.MustParseAddr("2001:db8::7"), netip.MustParseAddr("2001:db8::1")}},
	}
	d := model.NetLANDevice{Key: "mac:a#2", MAC: "00:00:5E:00:53:0A", IPv6: []string{"2001:db8::1", "fe80::1%br0", "bogus"}}
	got := b.deviceMatch(d, "mac:a")
	want := []model.NetSyslogTerm{
		{Kind: "ipv4", Text: "192.168.1.10", To: ts(115)},
		{Kind: "ipv4", Text: "192.168.1.11", From: ts(105), To: ts(195)},
		{Kind: "ipv4", Text: "192.168.1.10", From: ts(185), To: ts(215)},
		{Kind: "ipv4", Text: "192.168.1.12", From: ts(575)},
		{Kind: "ipv6", Text: "2001:db8::1"},
		{Kind: "ipv6", Text: "fe80::1"},
		{Kind: "ipv6", Text: "2001:db8::7"},
		{Kind: "mac", Text: "00:00:5e:00:53:0a"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("terms:\n got %+v\nwant %+v", got, want)
	}

	// A device whose address comes and goes every other read holds it in one term; one with more
	// holds than the bound keeps the newest.
	b.view.Addresses, b.view.To = nil, ts(30*24*60)
	for i := range 2 * maxMatchIPv4 {
		b.view.Addresses = append(b.view.Addresses, tenure("mac:a", "192.168.1.20", float64(i*30), float64(i*30)), // reads 15 min apart:
			tenure("mac:a", "192.168.1.21", float64(i*30+15), float64(i*30+15)), // each address every other read
			tenure("mac:a", fmt.Sprintf("10.0.%d.%d", i/250, 1+i%250), float64(i*30+5), float64(i*30+5)))
	}
	got = b.deviceMatch(model.NetLANDevice{Key: "mac:a"}, "mac:a")
	if len(got) != maxMatchIPv4 {
		t.Fatalf("%d terms, want %d", len(got), maxMatchIPv4)
	}
	last := float64((2*maxMatchIPv4 - 1) * 30)
	has := func(text, from, to string) bool {
		return slices.ContainsFunc(got, func(t model.NetSyslogTerm) bool { return t.Text == text && t.From == from && t.To == to })
	}
	if !has("192.168.1.20", "", ts(last+15)) || !has("192.168.1.21", "", ts(last+30)) ||
		slices.ContainsFunc(got, func(t model.NetSyslogTerm) bool { return t.Text == "10.0.0.1" }) {
		t.Errorf("terms %+v", got)
	}
	for i := 1; i < len(got); i++ {
		if got[i].From != "" && got[i-1].From > got[i].From {
			t.Fatalf("not oldest first: %+v before %+v", got[i-1], got[i])
		}
	}
	// A device without any address or MAC address has no term.
	if got := b.deviceMatch(model.NetLANDevice{Key: "name:x"}, "name:x"); len(got) != 0 || got == nil {
		t.Errorf("no address: %+v", got)
	}
}

// TestDeviceReadsIntervalAndIPv6: the Device List interval is the median time between the reads,
// within the setting's limits; a device's IPv6 addresses are those the reads gave it, at most
// maxDeviceV6, those given last first.
func TestDeviceReadsIntervalAndIPv6(t *testing.T) {
	for _, tc := range []struct {
		at   []float64 // minutes
		want time.Duration
	}{
		{nil, defaultDevicesInterval},
		{[]float64{0}, defaultDevicesInterval},
		{[]float64{0, 15, 30, 45, 300, 315}, 15 * time.Minute},
		{[]float64{0, 1, 2, 3}, minDevicesInterval},
		{[]float64{0, 3000, 6000}, maxDevicesInterval},
		{[]float64{0, 0, 10}, 10 * time.Minute},
	} {
		h := newDevReads(mins(-60), mins(10000))
		for _, m := range tc.at {
			h.add(mins(m), nil)
		}
		if got := h.every(); got != tc.want {
			t.Errorf("reads at %v: every %v, want %v", tc.at, got, tc.want)
		}
	}
	h := newDevReads(mins(0), mins(1000))
	for i := range 3 * maxDeviceV6 {
		h.add(mins(float64(i)), []model.LANDevice{{MAC: "00:00:5e:00:53:01", IPv4: "192.168.1.5", Status: "on",
			IPv6: []string{fmt.Sprintf("2001:db8::%x", i+1), "fe80::1%br0", "192.168.1.5"}}})
	}
	h.add(mins(2000), []model.LANDevice{{MAC: "00:00:5e:00:53:01", IPv6: []string{"2001:db8::ffff"}}}) // after the period: names only
	got := h.ipv6("mac:00:00:5e:00:53:01")
	// The newest read gave fe80::1 and the last global address: by address then.
	if len(got) != maxDeviceV6 || got[0] != netip.MustParseAddr(fmt.Sprintf("2001:db8::%x", 3*maxDeviceV6)) || got[1] != netip.MustParseAddr("fe80::1") ||
		got[2] != netip.MustParseAddr(fmt.Sprintf("2001:db8::%x", 3*maxDeviceV6-1)) ||
		slices.Contains(got, netip.MustParseAddr("2001:db8::ffff")) || slices.Contains(got, netip.MustParseAddr("2001:db8::1")) {
		t.Errorf("IPv6 %v", got)
	}
	if !h.macNamed("00:00:5e:00:53:01") || h.macNamed("00:00:5e:00:53:02") || h.macs["00:00:5e:00:53:01"] != "" {
		t.Errorf("MAC addresses named: %v", h.macs)
	}
	h.add(mins(5), []model.LANDevice{{MAC: "00-00-5E-00-53-02", Name: " tv "}})
	h.add(mins(6), []model.LANDevice{{MAC: "00:00:5e:00:53:02"}}) // a later read without the name keeps it
	if h.macs["00:00:5e:00:53:02"] != "tv" {
		t.Errorf("MAC addresses named: %v", h.macs)
	}
}

// TestDeviceDetailsConcurrently: details and views of several periods asked side by side share the
// views kept safely (go test -race).
func TestDeviceDetailsConcurrently(t *testing.T) {
	v, _, _ := scanView(t)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			q := contracts.NetQuery{From: sampleFrom.Add(time.Duration(i%2) * time.Minute), To: sampleTo}
			if i%3 == 0 {
				if dv, err := v.Devices(context.Background(), q); err != nil || dv.Scans != 3 {
					t.Errorf("%d scans, %v", dv.Scans, err)
				}
				return
			}
			dd, err := v.Device(context.Background(), q, "mac:"+devPrefix+"21", "")
			if err != nil || len(dd.Scans) != 3 || len(dd.Match) != 4 {
				t.Errorf("%+v, %v", dd, err)
				return
			}
			dd.Scans[0].Addr, dd.Device.Issues[0].Text = "changed", "changed"
		}()
	}
	wg.Wait()
}

// BenchmarkDeviceDetailsMonth builds a month's Devices view with hourly LAN scans of 30 devices
// (the result cache off) and a device's details from it.
func BenchmarkDeviceDetailsMonth(b *testing.B) {
	reads := benchDeviceReads()
	var scans []model.LANScan
	for at := monthQuery.From; at.Before(monthQuery.To); at = at.Add(time.Hour) {
		s := model.LANScan{At: rfc3339(at), Subnet: "192.168.1.0/24", Asked: 254, TookMs: 4000}
		for _, d := range reads[0].devices {
			s.Hosts = append(s.Hosts, model.LANHost{IP: d.IPv4, MAC: d.MAC})
		}
		scans = append(scans, s)
	}
	conns := &fakeHistory{fakeConns: &fakeConns{}, reads: reads}
	v := New(Options{Conns: conns, Scans: &fakeScans{scans: scans}, ResultTTL: -1})
	ctx := context.Background()
	key := "mac:" + reads[0].devices[7].MAC
	if dd, err := v.Device(ctx, monthQuery, key, ""); err != nil || len(dd.Scans) < 700 {
		b.Fatalf("%d scans, %v", len(dd.Scans), err)
	}
	for b.Loop() {
		if _, err := v.Device(ctx, monthQuery, key, ""); err != nil {
			b.Fatal(err)
		}
	}
}

// TestDeviceDetailsOfAnEntryListedTwice: an entry the newest read gives twice ("#2") has its own
// details, found by the holds of the key its reads know it by.
func TestDeviceDetailsOfAnEntryListedTwice(t *testing.T) {
	a := sampleDevice("31", "nas", "192.168.1.40", "Ethernet")
	b := a
	b.Name, b.IPv4 = "nas second port", "192.168.1.41"
	conns := &fakeHistory{fakeConns: &fakeConns{}, reads: []timedRead{{mins(0), []model.LANDevice{a, b}}, {mins(15), []model.LANDevice{a, b}}}}
	v := New(Options{Conns: conns, Now: func() time.Time { return mins(30) }})
	q := contracts.NetQuery{From: mins(0), To: mins(30)}
	dd, err := v.Device(context.Background(), q, "mac:00:00:5e:00:53:31#2", "")
	if err != nil {
		t.Fatal(err)
	}
	if dd.Device == nil || dd.Device.Name != "nas second port" || len(dd.Scans) != 0 || dd.Scans == nil {
		t.Fatalf("details %+v", dd)
	}
	var addrs []string
	for _, m := range dd.Match {
		addrs = append(addrs, m.Kind+" "+m.Text)
	}
	// The two entries share the MAC address: the reads know them as one device, which held both.
	if want := []string{"ipv4 192.168.1.40", "ipv4 192.168.1.41", "mac 00:00:5e:00:53:31"}; !slices.Equal(addrs, want) {
		t.Errorf("terms %q, want %q", addrs, want)
	}
}
