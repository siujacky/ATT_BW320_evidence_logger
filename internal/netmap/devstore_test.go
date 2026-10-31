package netmap

import (
	"context"
	"reflect"
	"slices"
	"testing"
	"time"

	"attmonitor/internal/connstore"
	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// TestDevicesWithTheStores: the Devices view over the connection store and the syslog store the
// service opens. The laptop moves from 192.168.1.70 to .72 and DHCP gives .70 to a tablet: the
// packets dropped from .70 count for the device that held it when they were received, the NAT
// samples name its sessions alike (the newest NAT read gives the open connections), the address
// history says who held .70 when, and an address no read names is unknown - from the NAT samples
// (.150) and from the firewall's drops (.151). The day before the period - compressed by then -
// holds the read in effect at its start.
func TestDevicesWithTheStores(t *testing.T) {
	now := mins(180)
	cs, err := connstore.Open(t.TempDir(), connstore.Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	laptop := func(ip string) model.LANDevice {
		d := sampleDevice("51", "laptop", ip, "Wi-Fi 5 GHz")
		d.Signal = 4
		return d
	}
	phone := sampleDevice("52", "phone", "192.168.1.71", "Wi-Fi 2.4 GHz")
	phone.Signal = 2
	tablet := sampleDevice("53", "tablet", "192.168.1.70", "Wi-Fi 5 GHz")
	printer := sampleDevice("54", "printer", "", "Ethernet LAN-4")
	printer.Status = "off"
	for _, r := range []timedRead{
		{t0.Add(-24 * time.Hour), []model.LANDevice{laptop("192.168.1.70"), phone}},
		{mins(10), []model.LANDevice{laptop("192.168.1.70"), phone}},
		{mins(70), []model.LANDevice{laptop("192.168.1.72"), phone, tablet}},
		{mins(130), []model.LANDevice{laptop("192.168.1.72"), phone, tablet, printer}},
	} {
		if err := cs.AppendDevices(r.at, r.devices); err != nil {
			t.Fatal(err)
		}
	}
	tcp := func(src string, sport int, dst string) model.NATSession {
		return model.NATSession{Proto: "tcp", State: "ESTABLISHED", Src: src, SrcPort: sport, Dst: dst, DstPort: 443}
	}
	for _, r := range []struct {
		at       time.Time
		sessions []model.NATSession
	}{
		{mins(20), []model.NATSession{tcp("192.168.1.70", 50000, "203.0.113.5"), tcp("192.168.1.70", 50001, "198.51.100.7"),
			tcp("192.168.1.71", 50002, "203.0.113.5"), tcp("192.168.1.150", 50003, "192.0.2.80")}},
		{mins(80), []model.NATSession{tcp("192.168.1.72", 50010, "203.0.113.5"), tcp("192.168.1.70", 50011, "192.0.2.81"),
			tcp("192.168.1.70", 50012, "192.0.2.82"), tcp("192.168.1.70", 50013, "192.0.2.83"),
			{Proto: "udp", Src: "198.51.100.1", SrcPort: 33000, Dst: "192.0.2.53", DstPort: 53}}},
	} {
		if err := cs.AppendNAT(r.at, model.NATTable{Sessions: r.sessions, InUse: len(r.sessions), Available: 8000}); err != nil {
			t.Fatal(err)
		}
	}
	s := testStore(t)
	appendMsgs(t, s, true, syslogMsg(mins(30), outLine("192.168.1.70", "192.0.2.44", 443, "POLICY"))) // the laptop's
	appendMsgs(t, s, true, syslogMsg(mins(40), inLine("192.0.2.17", "192.168.1.71", 60000)))          // to the phone
	appendMsgs(t, s, false,
		syslogMsg(mins(90), outLine("192.168.1.70", "192.0.2.44", 443, "POLICY")),   // the tablet's
		syslogMsg(mins(100), outLine("192.168.1.151", "192.0.2.47", 443, "POLICY"))) // nobody's

	v := New(Options{Conns: cs, Syslog: s, Now: func() time.Time { return now }})
	dv, err := v.Devices(context.Background(), contracts.NetQuery{From: t0, To: now, Range: "24h"})
	if err != nil {
		t.Fatal(err)
	}
	ts := func(m float64) string { return rfc3339(mins(m)) }
	if dv.ListAt != ts(130) || dv.Reads != 3 || dv.NATReads != 2 || dv.NATAt != ts(80) {
		t.Errorf("list at %s, %d reads, %d NAT reads, the newest at %s", dv.ListAt, dv.Reads, dv.NATReads, dv.NATAt)
	}
	type figures struct {
		ip                          string
		open, sites, blocked, blkIn int
		addrs                       string
		issues                      string
	}
	got := map[string]figures{}
	for _, d := range dv.Devices {
		var is []string
		for _, i := range d.Issues {
			is = append(is, i.Code)
		}
		got[d.Name] = figures{d.IPv4, d.Open, d.Sites, d.Blocked, d.BlockedIn, joinAnd(d.Addresses), joinAnd(is)}
	}
	want := map[string]figures{
		"laptop":  {"192.168.1.72", 1, 2, 1, 0, "192.168.1.72 and 192.168.1.70", "address_changed"},
		"phone":   {"192.168.1.71", 0, 1, 0, 1, "192.168.1.71", "weak_wifi"},
		"tablet":  {"192.168.1.70", 3, 3, 1, 0, "192.168.1.70", ""},
		"printer": {"", 0, 0, 0, 0, "", "offline"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("devices:\n got %+v\nwant %+v", got, want)
	}
	var unknown []string
	for _, u := range dv.Unknown {
		unknown = append(unknown, u.Addr)
	}
	if !slices.Equal(unknown, []string{"192.168.1.151", "192.168.1.150"}) || dv.Totals.Unknown != 2 {
		t.Errorf("unknown %q (%d)", unknown, dv.Totals.Unknown)
	}
	if u := dv.Unknown[1]; u.Open != 0 || u.Sites != 1 || u.First != ts(20) || u.Last != ts(20) {
		t.Errorf("192.168.1.150: %+v", u)
	}
	var history []string
	for _, u := range dv.Addresses {
		history = append(history, u.Addr+" "+u.Name+" "+u.First+" "+u.Last)
	}
	before := rfc3339(t0.Add(-24 * time.Hour))
	if want := []string{
		"192.168.1.70 laptop " + before + " " + ts(10),
		"192.168.1.70 tablet " + ts(70) + " " + ts(130),
		"192.168.1.71 phone " + before + " " + ts(130),
		"192.168.1.72 laptop " + ts(70) + " " + ts(130),
	}; !slices.Equal(history, want) {
		t.Errorf("history:\n%q\nwant\n%q", history, want)
	}
	if want := (model.NetDeviceTotals{Listed: 4, Online: 3, WiFi: 3, Wired: 1, Issues: 3, Unknown: 2}); dv.Totals != want {
		t.Errorf("totals %+v, want %+v", dv.Totals, want)
	}

	// The firewall view of the same period names the drops alike.
	fw, err := v.Firewall(context.Background(), contracts.NetQuery{From: t0, To: now})
	if err != nil {
		t.Fatal(err)
	}
	var rows []string
	for _, r := range fw.OutboundRows {
		rows = append(rows, r.Name+" "+r.LAN)
	}
	slices.Sort(rows)
	if want := []string{"192.168.1.151 192.168.1.151", "laptop 192.168.1.70", "tablet 192.168.1.70"}; !slices.Equal(rows, want) {
		t.Errorf("firewall rows %q, want %q", rows, want)
	}
}
