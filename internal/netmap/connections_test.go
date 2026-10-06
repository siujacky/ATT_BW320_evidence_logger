package netmap

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// The devices of the connections scenario.
const (
	devPC   = "mac:00:00:5e:00:53:10"
	devIP   = "ip:192.168.1.70"
	devGate = "gateway"
)

// connScenario returns a connection store and an IP database of 14 organisations (as64496 …
// as64509, two remote addresses for the first), a public address the database does not know,
// a private one, and an IPv4-mapped one; and the services the flows use. Every weight differs,
// so the expected order is clear.
func connScenario() (*fakeConns, *fakeIntel) {
	in := newFakeIntel()
	in.services["tcp/993"] = "IMAPS"
	in.services["tcp/5228"] = "Google Play"
	in.services["udp/3478"] = "STUN"
	countries := []string{"US", "DE", "JP", "NL", "GB"}
	svcs := []struct {
		proto string
		port  int
	}{{"tcp", 443}, {"udp", 443}, {"udp", 53}, {"tcp", 80}, {"udp", 123}, {"tcp", 22}, {"tcp", 23}, {"tcp", 993},
		{"tcp", 5228}, {"udp", 3478}}
	ts := func(sec int) string { return at(float64(sec)).Format(time.RFC3339) }
	flow := func(dev, lan, remote, proto string, port, samples, weight int) model.ConnFlow {
		return model.ConnFlow{Device: dev, LAN: lan, Remote: remote, Port: port, Proto: proto, First: ts(0), Last: ts(600),
			Samples: samples, Weight: weight}
	}
	var flows []model.ConnFlow
	for i := range 14 {
		remote := fmt.Sprintf("203.0.113.%d", 10+i)
		in.know(remote, 64496+i, fmt.Sprintf("Org %d", i), countries[i%5])
		dev, lan := devPC, "192.168.1.64"
		if i%2 == 1 {
			dev, lan = devIP, "192.168.1.70"
		}
		s := svcs[i%10]
		flows = append(flows, flow(dev, lan, remote, s.proto, s.port, 20-i, 100-5*i))
	}
	in.know("203.0.113.100", 64496, "Org 0", "US")
	flows = append(flows,
		flow(devPC, "192.168.1.64", "203.0.113.100", "tcp", 443, 3, 7),
		flow(devIP, "192.168.1.70", "198.51.100.200", "tcp", 8443, 5, 33), // public, not in the database
		flow(devGate, "", "192.168.1.254", "udp", 53, 4, 31),              // private
		flow(devIP, "192.168.1.70", "::ffff:203.0.113.10", "TCP", 443, 1, 2))
	in.ptrs[netip.MustParseAddr("203.0.113.10")] = "edge.example.net"
	conns := &fakeConns{agg: model.ConnAggregate{
		Samples: 20, First: ts(0), Last: ts(600), InUse: 140, Available: 8052, Open: 18,
		Devices: []model.ConnDevice{
			{Key: devPC, Name: "Study PC", IPv4: "192.168.1.64", MAC: "00:00:5e:00:53:10", Connection: "Ethernet", Samples: 20, Weight: 497},
			{Key: devIP, IPv4: "192.168.1.70", Samples: 19, Weight: 490},
			{Key: devGate, Samples: 4, Weight: 31},
		},
		Flows: flows,
	}}
	return conns, in
}

func TestConnections(t *testing.T) {
	conns, in := connScenario()
	v := New(Options{Conns: conns, Intel: in})
	nc, err := v.Connections(context.Background(), contracts.NetQuery{From: t0, To: t0.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if q := conns.calls(); len(q) != 1 || q[0] != (contracts.ConnQuery{From: t0, To: t0.Add(time.Hour)}) {
		t.Fatalf("queries %+v", q)
	}
	if nc.From != "2026-10-06T07:00:00Z" || nc.To != "2026-10-06T08:00:00Z" || nc.Device != "" || nc.Samples != 20 ||
		nc.First != at(0).Format(time.RFC3339) || nc.Last != at(600).Format(time.RFC3339) || nc.InUse != 140 ||
		nc.Available != 8052 || nc.Open != 18 || nc.IPDB != "2026-10-01T04:00:00Z" {
		t.Fatalf("header %+v", nc)
	}
	if nc.Totals != (model.NetTotals{Devices: 3, Sites: 17, Orgs: 14, Countries: 5}) {
		t.Fatalf("totals %+v", nc.Totals)
	}
	wantDevices := []model.NetDevice{
		{Key: devPC, Name: "Study PC", IPv4: "192.168.1.64", MAC: "00:00:5e:00:53:10", Connection: "Ethernet", Weight: 497, Sites: 8},
		{Key: devIP, Name: "192.168.1.70", IPv4: "192.168.1.70", Weight: 490, Sites: 9},
		{Key: devGate, Name: "Gateway", Weight: 31, Sites: 1},
	}
	if !reflect.DeepEqual(nc.Devices, wantDevices) {
		t.Fatalf("devices %s", js(t, nc.Devices))
	}

	// The 12 heaviest organisations, then the rest.
	if len(nc.Orgs) != 13 {
		t.Fatalf("orgs %s", js(t, nc.Orgs))
	}
	if o := nc.Orgs[0]; !reflect.DeepEqual(o, model.NetOrg{Key: "org:org 0", Name: "Org 0", ASN: 64496, Country: "US", Weight: 109, Sites: 2}) {
		t.Fatalf("first org %+v", o)
	}
	for i, o := range nc.Orgs[:12] {
		if o.Key != fmt.Sprintf("org:org %d", i) || o.ASN != 64496+i {
			t.Fatalf("org %d: %+v", i, o)
		}
	}
	if o := nc.Orgs[12]; !reflect.DeepEqual(o, model.NetOrg{Key: "other", Name: "Other", Weight: 40 + 35 + 33 + 31, Sites: 4, Members: 4}) {
		t.Fatalf("other %+v", o)
	}

	// The 8 heaviest named services, then the rest with the unnamed.
	wantSvcs := []model.NetService{
		{Key: "udp/53", Name: "DNS", Proto: "udp", Port: 53, Weight: 161},
		{Key: "tcp/443", Name: "HTTPS", Proto: "tcp", Port: 443, Weight: 159},
		{Key: "udp/443", Name: "QUIC", Proto: "udp", Port: 443, Weight: 140},
		{Key: "tcp/80", Name: "HTTP", Proto: "tcp", Port: 80, Weight: 120},
		{Key: "udp/123", Name: "NTP", Proto: "udp", Port: 123, Weight: 80},
		{Key: "tcp/22", Name: "SSH", Proto: "tcp", Port: 22, Weight: 75},
		{Key: "tcp/23", Name: "Telnet", Proto: "tcp", Port: 23, Weight: 70},
		{Key: "tcp/993", Name: "IMAPS", Proto: "tcp", Port: 993, Weight: 65},
		{Key: "other", Name: "Other", Weight: 60 + 55 + 33},
	}
	if !reflect.DeepEqual(nc.Services, wantSvcs) {
		t.Fatalf("services %s", js(t, nc.Services))
	}

	// The bands add up the flows by the groups, and join what the diagram shows.
	keys := map[string]bool{}
	for _, d := range nc.Devices {
		keys["dev "+d.Key] = true
	}
	for _, o := range nc.Orgs {
		keys["org "+o.Key] = true
	}
	for _, s := range nc.Services {
		keys["svc "+s.Key] = true
	}
	link := map[[2]string]int{}
	devOrg, orgSvc := 0, 0
	for i, l := range nc.Links {
		switch {
		case keys["dev "+l.From] && keys["org "+l.To]:
			devOrg += l.Weight
			if orgSvc > 0 {
				t.Fatalf("device band %+v after the organisation bands", l)
			}
		case keys["org "+l.From] && keys["svc "+l.To]:
			orgSvc += l.Weight
		default:
			t.Fatalf("link %+v joins nothing shown", l)
		}
		sameLayer := i > 0 && keys["dev "+nc.Links[i-1].From] == keys["dev "+l.From]
		if sameLayer && nc.Links[i-1].Weight < l.Weight {
			t.Fatalf("bands not heaviest first: %+v then %+v", nc.Links[i-1], l)
		}
		link[[2]string{l.From, l.To}] = l.Weight
	}
	if devOrg != 1018 || orgSvc != 1018 {
		t.Fatalf("links add up to %d and %d", devOrg, orgSvc)
	}
	for k, w := range map[[2]string]int{
		{devPC, "org:org 0"}: 107, {devIP, "org:org 0"}: 2, {devPC, "other"}: 40, {devIP, "other"}: 68, {devGate, "other"}: 31,
		{"org:org 0", "tcp/443"}: 109, {"other", "udp/53"}: 71, {"other", "other"}: 33, {"org:org 9", "other"}: 55,
	} {
		if link[k] != w {
			t.Errorf("link %v: %d, want %d", k, link[k], w)
		}
	}
	wantCountries := []model.NetCountry{{Code: "US", Sites: 4, Weight: 234}, {Code: "DE", Sites: 3, Weight: 210},
		{Code: "JP", Sites: 3, Weight: 195}, {Code: "NL", Sites: 3, Weight: 180}, {Code: "GB", Sites: 2, Weight: 135},
		{Code: "", Sites: 1, Weight: 33}}
	if !reflect.DeepEqual(nc.Countries, wantCountries) {
		t.Fatalf("countries %s", js(t, nc.Countries))
	}

	// Rows: the most seen first, named; reverse DNS names for the rows shown.
	if nc.RowsTotal != 18 || len(nc.Rows) != 18 {
		t.Fatalf("%d rows of %d", len(nc.Rows), nc.RowsTotal)
	}
	if r := nc.Rows[0]; r != (model.NetConnRow{Device: devPC, LAN: "192.168.1.64", Remote: "203.0.113.10", PTR: "edge.example.net",
		Kind: model.IPKindPublic, Org: "Org 0", ASN: 64496, Country: "US", Service: "HTTPS", Proto: "tcp", Port: 443,
		First: at(0).Format(time.RFC3339), Last: at(600).Format(time.RFC3339), Samples: 20, Weight: 100}) {
		t.Fatalf("first row %+v", r)
	}
	byRemote := map[string]model.NetConnRow{}
	for i, r := range nc.Rows {
		if i > 0 && (r.Samples > nc.Rows[i-1].Samples) {
			t.Fatalf("rows not by samples: %+v", nc.Rows)
		}
		byRemote[r.Remote+" "+r.Proto] = r
	}
	if r := byRemote["198.51.100.200 tcp"]; r.Kind != model.IPKindPublic || r.Org != "" || r.ASN != 0 || r.Service != "" {
		t.Fatalf("unknown remote %+v", r)
	}
	if r := byRemote["192.168.1.254 udp"]; r.Kind != model.IPKindPrivate || r.Org != "" || r.Service != "DNS" || r.PTR != "" {
		t.Fatalf("private remote %+v", r)
	}
	if r := nc.Rows[len(nc.Rows)-1]; r.Remote != "203.0.113.10" || r.Proto != "tcp" || r.Samples != 1 || r.Device != devIP {
		t.Fatalf("the IPv4-mapped remote %+v", r)
	}
	if asked := in.askedPTR(); len(asked) != 17 { // every public row
		t.Fatalf("PTR asked for %v", asked)
	}
}

func TestConnectionsLimitsTheRowsAndTheirReverseDNS(t *testing.T) {
	conns, in := connScenario()
	v := New(Options{Conns: conns, Intel: in})
	for _, c := range []struct{ limit, rows int }{{5, 5}, {0, 18}, {5000, 18}} {
		nc, err := v.Connections(context.Background(), contracts.NetQuery{From: t0, To: t0.Add(time.Hour), Limit: c.limit})
		if err != nil || len(nc.Rows) != c.rows || nc.RowsTotal != 18 {
			t.Fatalf("limit %d: %d rows of %d (%v)", c.limit, len(nc.Rows), nc.RowsTotal, err)
		}
		asked := in.askedPTR()
		if c.limit == 5 {
			want := []netip.Addr{}
			for i := range 5 {
				want = append(want, netip.MustParseAddr(fmt.Sprintf("203.0.113.%d", 10+i)))
			}
			if !slices.Equal(asked, want) {
				t.Fatalf("PTR asked for %v, want the rows shown %v", asked, want)
			}
		}
	}
	// More rows than MaxLimit are cut at MaxLimit.
	var many []model.ConnFlow
	for i := range MaxLimit + 50 {
		many = append(many, model.ConnFlow{Device: devPC, Remote: fmt.Sprintf("2001:db8::%x", i+1), Proto: "tcp", Port: 443,
			Samples: 1, Weight: 1})
	}
	conns.agg.Flows = many
	nc, err := New(Options{Conns: conns, Intel: in}).Connections(context.Background(),
		contracts.NetQuery{From: t0, To: t0.Add(time.Hour), Limit: MaxLimit * 5})
	if err != nil || len(nc.Rows) != MaxLimit || nc.RowsTotal != MaxLimit+50 || nc.Totals.Sites != MaxLimit+50 {
		t.Fatalf("%d rows of %d (%v)", len(nc.Rows), nc.RowsTotal, err)
	}
}

func TestConnectionsOfOneDevice(t *testing.T) {
	conns, in := connScenario()
	v := New(Options{Conns: conns, Intel: in})
	nc, err := v.Connections(context.Background(), contracts.NetQuery{From: t0, To: t0.Add(time.Hour), Device: devIP})
	if err != nil {
		t.Fatal(err)
	}
	q := conns.calls()
	if len(q) != 2 || q[0].Device != devIP || q[1].Device != "" {
		t.Fatalf("queries %+v", q)
	}
	// Every device is listed for the filter; the rest is the device's.
	if nc.Device != devIP || len(nc.Devices) != 3 || nc.Totals.Devices != 1 || nc.RowsTotal != 9 {
		t.Fatalf("devices %d, totals %+v, rows %d", len(nc.Devices), nc.Totals, nc.RowsTotal)
	}
	for _, r := range nc.Rows {
		if r.Device != devIP {
			t.Fatalf("row of another device %+v", r)
		}
	}
	for _, l := range nc.Links {
		if l.From == devPC || l.From == devGate {
			t.Fatalf("band of another device %+v", l)
		}
	}
}

func TestConnectionsWithoutTheIPDatabase(t *testing.T) {
	conns, _ := connScenario()
	nc, err := New(Options{Conns: conns}).Connections(context.Background(), contracts.NetQuery{From: t0, To: t0.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	// Documentation addresses are reserved: every remote is "local"; every port its own service.
	if len(nc.Orgs) != 1 || nc.Orgs[0].Key != orgLocal || nc.Orgs[0].Weight != 1018 || len(nc.Countries) != 0 || nc.IPDB != "" {
		t.Fatalf("orgs %+v, countries %+v", nc.Orgs, nc.Countries)
	}
	if nc.Totals.Orgs != 0 || nc.Totals.Countries != 0 || nc.Totals.Sites != 17 {
		t.Fatalf("totals %+v", nc.Totals)
	}
	if s := nc.Services[0]; s.Key != "udp/53" || s.Name != "udp 53" || s.Weight != 161 || len(nc.Services) != 9 ||
		nc.Services[8] != (model.NetService{Key: "other", Name: "Other", Weight: 60 + 55 + 33}) {
		t.Fatalf("services %s", js(t, nc.Services))
	}
	if r := nc.Rows[0]; r.Kind != model.IPKindReserved || r.Service != "" || r.Org != "" || r.PTR != "" {
		t.Fatalf("row %+v", r)
	}
}

func TestConnectionsErrors(t *testing.T) {
	ctx := context.Background()
	if _, err := New(Options{}).Connections(ctx, contracts.NetQuery{}); !errors.Is(err, contracts.ErrUnavailable) {
		t.Fatalf("without a connection store: %v", err)
	}
	broken := errors.New("disk on fire")
	conns := &fakeConns{err: broken}
	v := New(Options{Conns: conns})
	if _, err := v.Connections(ctx, contracts.NetQuery{From: t0, To: t0.Add(time.Hour)}); !errors.Is(err, broken) {
		t.Fatalf("store error: %v", err)
	}
	if _, err := v.Connections(ctx, contracts.NetQuery{From: t0, To: t0.Add(MaxRange + 1)}); !errors.Is(err, ErrRange) {
		t.Fatalf("too long: %v", err)
	}
	// A failed view is not kept: the next request asks the store again.
	conns.calls()
	conns.err = nil
	if _, err := v.Connections(ctx, contracts.NetQuery{From: t0, To: t0.Add(time.Hour)}); err != nil || len(conns.calls()) != 1 {
		t.Fatalf("after the store recovered: %v", err)
	}
}

func TestConnectionsResultCache(t *testing.T) {
	now := t0
	conns, in := connScenario()
	v := New(Options{Conns: conns, Intel: in, Now: func() time.Time { return now }})
	ctx := context.Background()
	q := contracts.NetQuery{From: t0, To: t0.Add(time.Hour), Limit: 3}
	a, err := v.Connections(ctx, q)
	if err != nil || a.Rows[1].PTR != "" {
		t.Fatalf("%v %+v", err, a.Rows[1])
	}
	a.Rows[0].Remote = "changed by the caller"
	in.ptrs[netip.MustParseAddr("203.0.113.11")] = "later.example.net" // resolved meanwhile
	b, _ := v.Connections(ctx, q)
	if n := len(conns.calls()); n != 1 || b.Rows[0].Remote != "203.0.113.10" || b.Rows[1].PTR != "later.example.net" {
		t.Fatalf("store asked %d times; rows %+v", n, b.Rows[:2])
	}
	now = now.Add(DefaultResultTTL + time.Second)
	if _, err := v.Connections(ctx, q); err != nil || len(conns.calls()) != 1 {
		t.Fatalf("a stale view was not built again (%v)", err)
	}
}

func TestDeviceNames(t *testing.T) {
	for _, c := range []struct{ key, name, addr, want string }{
		{devPC, "Study PC", "192.168.1.64", "Study PC"},
		{devPC, "", "192.168.1.64", "192.168.1.64"},
		{devPC, "", "", "00:00:5e:00:53:10"},
		{"ip:192.168.1.9", "", "", "192.168.1.9"},
		{"gateway", "", "198.51.100.1", "Gateway"},
		{"gateway", "Router", "", "Router"},
		{"odd", "", "", "odd"},
	} {
		if got := deviceName(c.key, c.name, c.addr); got != c.want {
			t.Errorf("deviceName(%q, %q, %q) = %q, want %q", c.key, c.name, c.addr, got, c.want)
		}
	}
	// A device with flows that the store did not list is listed after its flows.
	all := model.ConnAggregate{Flows: []model.ConnFlow{{Device: "ip:192.168.1.9", LAN: "192.168.1.9", Remote: "203.0.113.1", Weight: 4},
		{Device: "ip:192.168.1.9", LAN: "192.168.1.9", Remote: "203.0.113.2", Weight: 1}}}
	if got, err := netDevices(context.Background(), all, defaultBounds.flows); err != nil ||
		!reflect.DeepEqual(got, []model.NetDevice{{Key: "ip:192.168.1.9", Name: "192.168.1.9", Weight: 5, Sites: 2}}) {
		t.Fatalf("devices %+v (%v)", got, err)
	}
}

// TestConnectionsOrganisationsByName: the ASes of one company - Google's AS15169 and AS36040,
// Amazon's AS16509 and AS14618, as the IP database names them - are one organisation of the flow
// diagram, listing its ASes; its AS and country are those of its heaviest AS; the totals count
// organisations, not ASes.
func TestConnectionsOrganisationsByName(t *testing.T) {
	in := newFakeIntel()
	in.know("203.0.113.1", 15169, "Google", "US")
	in.know("203.0.113.2", 36040, "Google", "US")
	in.know("203.0.113.3", 16509, "Amazon", "US")
	in.know("203.0.113.4", 14618, "Amazon", "IE")
	// An AS the database names no organisation of: keyed by its number, named after its description.
	in.infos[netip.MustParseAddr("203.0.113.5")] = model.IPInfo{Kind: model.IPKindPublic, ASN: 64500, ASName: "EXAMPLE-NET", Country: "NL"}
	flow := func(remote string, weight int) model.ConnFlow {
		return model.ConnFlow{Device: devPC, LAN: "192.168.1.64", Remote: remote, Proto: "tcp", Port: 443, Samples: weight, Weight: weight}
	}
	conns := &fakeConns{agg: model.ConnAggregate{Samples: 30, Devices: []model.ConnDevice{{Key: devPC, Weight: 26 + 7 + 5 + 4 + 2}},
		Flows: []model.ConnFlow{flow("203.0.113.1", 26), flow("203.0.113.2", 7), flow("203.0.113.3", 4), flow("203.0.113.4", 5),
			flow("203.0.113.5", 2)}}}
	nc, err := New(Options{Conns: conns, Intel: in}).Connections(context.Background(), contracts.NetQuery{From: t0, To: t0.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	want := []model.NetOrg{
		{Key: "org:google", Name: "Google", ASN: 15169, ASNs: []int{15169, 36040}, Country: "US", Weight: 33, Sites: 2},
		{Key: "org:amazon", Name: "Amazon", ASN: 14618, ASNs: []int{14618, 16509}, Country: "IE", Weight: 9, Sites: 2},
		{Key: "as64500", Name: "EXAMPLE-NET", ASN: 64500, Country: "NL", Weight: 2, Sites: 1},
	}
	if !reflect.DeepEqual(nc.Orgs, want) {
		t.Fatalf("orgs %s", js(t, nc.Orgs))
	}
	if nc.Totals.Orgs != 3 || nc.Totals.Sites != 5 {
		t.Fatalf("totals %+v", nc.Totals)
	}
	for _, r := range nc.Rows {
		if r.Remote == "203.0.113.2" && (r.Org != "Google" || r.ASN != 36040) {
			t.Fatalf("a row keeps its own AS: %+v", r)
		}
	}
}

// TestConnectionsWithFlowsLeftOut: flows the connection store left out beyond its bound count from
// their device into "Other" - the diagram's organisations, services and bands still add up to every
// session - and the view says how many were left out; with a device filter, its own count of open
// connections is passed on.
func TestConnectionsWithFlowsLeftOut(t *testing.T) {
	in := newFakeIntel()
	in.know("203.0.113.1", 15169, "Google", "US")
	conns := &fakeConns{agg: model.ConnAggregate{Samples: 10, Open: 40, OpenDevice: 3, FlowsLeftOut: 5000,
		Devices: []model.ConnDevice{{Key: devPC, Weight: 10 + 900, LeftOut: 900}},
		Flows:   []model.ConnFlow{{Device: devPC, LAN: "192.168.1.64", Remote: "203.0.113.1", Proto: "tcp", Port: 443, Samples: 10, Weight: 10}}}}
	nc, err := New(Options{Conns: conns, Intel: in}).Connections(context.Background(),
		contracts.NetQuery{From: t0, To: t0.Add(time.Hour), Device: devPC})
	if err != nil {
		t.Fatal(err)
	}
	if nc.FlowsLeftOut != 5000 || nc.OpenDevice != 3 || nc.Open != 40 {
		t.Fatalf("left out %d, open %d of %d", nc.FlowsLeftOut, nc.OpenDevice, nc.Open)
	}
	sum := func(ws ...int) int {
		n := 0
		for _, w := range ws {
			n += w
		}
		return n
	}
	var orgs, svcs, bands []int
	for _, o := range nc.Orgs {
		orgs = append(orgs, o.Weight)
	}
	for _, s := range nc.Services {
		svcs = append(svcs, s.Weight)
	}
	for _, l := range nc.Links {
		if l.From == devPC {
			bands = append(bands, l.Weight)
		}
	}
	if sum(orgs...) != 910 || sum(svcs...) != 910 || sum(bands...) != 910 {
		t.Fatalf("organisations %v, services %v, device bands %v; want 910 each", orgs, svcs, bands)
	}
}

// TestConnectionsTotalsListedDevices: the totals say how many of the period's devices the gateway's
// newest Device List lists - by MAC address, or by address for an entry without one.
func TestConnectionsTotalsListedDevices(t *testing.T) {
	conns, in := connScenario()
	conns.devices = []model.LANDevice{{MAC: "00:00:5e:00:53:10", Name: "Study PC", IPv4: "192.168.1.64"},
		{IPv4: "192.168.1.70"}, {MAC: "00:00:5e:00:53:99", Name: "test-gone"}}
	nc, err := New(Options{Conns: conns, Intel: in}).Connections(context.Background(), contracts.NetQuery{From: t0, To: t0.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if nc.Totals.Devices != 3 || nc.Totals.Listed != 2 {
		t.Fatalf("totals %+v: want 3 devices (the gateway's own included), 2 of them listed", nc.Totals)
	}
}

// TestConnectionsStopWithTheirRequest: a view whose request ends while it is put together - here
// as soon as the connection store answered - stops with the request's error instead of finishing.
func TestConnectionsStopWithTheirRequest(t *testing.T) {
	var flows []model.ConnFlow
	for i := range 3 * finishEvery {
		flows = append(flows, model.ConnFlow{Device: devPC, LAN: "192.168.1.64", Remote: fmt.Sprintf("2001:db8:1::%x", i+1),
			Proto: "tcp", Port: 443, Samples: 1, Weight: 1})
	}
	ctx, cancel := context.WithCancel(context.Background())
	conns := &cancellingConns{fakeConns: &fakeConns{agg: model.ConnAggregate{Samples: 1, Flows: flows}}, cancel: cancel}
	_, err := New(Options{Conns: conns, ResultTTL: -1}).Connections(ctx, contracts.NetQuery{From: t0, To: t0.Add(time.Hour)})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want the request's end", err)
	}
}

// cancellingConns ends the request (cancel) as its Aggregate answers.
type cancellingConns struct {
	*fakeConns
	cancel context.CancelFunc
}

func (c *cancellingConns) Aggregate(ctx context.Context, q contracts.ConnQuery) (model.ConnAggregate, error) {
	agg, err := c.fakeConns.Aggregate(ctx, q)
	c.cancel()
	return agg, err
}
