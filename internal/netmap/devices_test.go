package netmap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// ---------------------------------------------------------------- fakes

// fakeHistory is a connection store that also gives its Device List reads by time, as
// connstore.Store does (deviceHistory): Devices is its newest read.
type fakeHistory struct {
	*fakeConns
	reads []timedRead // oldest first
	err   error       // EachDevices fails with it
	mu    sync.Mutex
	calls int
}

// timedRead is one Device List read.
type timedRead struct {
	at      time.Time
	devices []model.LANDevice
}

func (f *fakeHistory) Devices() ([]model.LANDevice, time.Time) {
	if len(f.reads) == 0 {
		return nil, time.Time{}
	}
	r := f.reads[len(f.reads)-1]
	return slices.Clone(r.devices), r.at
}

// EachDevices passes the read in effect at from (the newest at or before it, else the first after
// it), then every later read made before to.
func (f *fakeHistory) EachDevices(ctx context.Context, from, to time.Time, fn func(time.Time, []model.LANDevice) error) error {
	f.mu.Lock()
	f.calls++
	err := f.err
	f.mu.Unlock()
	if err != nil {
		return err
	}
	start := 0
	for i, r := range f.reads {
		if !r.at.After(from) {
			start = i
		}
	}
	for i := start; i < len(f.reads); i++ {
		r := f.reads[i]
		if i > start && !to.IsZero() && !r.at.Before(to) {
			break
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := fn(r.at, slices.Clone(r.devices)); err != nil {
			return err
		}
	}
	return nil
}

// eachCalls returns how often EachDevices was called.
func (f *fakeHistory) eachCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// inLine returns a packet from remote toward the LAN address lan:dport that the firewall dropped
// (OUT is a LAN bridge).
func inLine(remote, lan string, dport int) string {
	return fmt.Sprintf("P0000-00-00T07:51:10.000001 L4 FIREWALL[8512]: nflog_log_fw(), action=DROP reason=OTHER-DoS hook=FORWARD mark=136314880 IN=veip0.0 OUT=br1 MAC=00:00:5e:00:53:01:00:00:5e:0000:53:02:SRC=%s DST=%s LEN=1228 TOS=0x00 PREC=0x00 TTL=57 ID=0 DF PROTO=UDP SPT=443 DPT=%d LEN=1208", remote, lan, dport)
}

// mins returns t0 plus m minutes.
func mins(m float64) time.Time { return t0.Add(time.Duration(m * float64(time.Minute))) }

// ---------------------------------------------------------------- the sample home network

// The sample home network: eight devices in the newest Device List read and one that left; the
// reads at t0-10 min (in effect at the period's start), +15, +45, +75 and +105 min (the newest).
//
//   - laptop (:21) moves from .64 to .80 at +45: address_changed; its IPv6 address is dropped at
//     from the Internet once;
//   - phone (:22) has 1 bar of Wi-Fi: weak_wifi;
//   - desk-pc (:23) runs at 10 Mb/s half duplex: slow_link;
//   - tv (:24) is off from +75: offline;
//   - printer (:25) holds .71, which camera (:26) claims too in the newest read: address_shared;
//   - nas (:27) has 120 packets dropped on their way out and 30 on their way to it: blocked;
//   - old-phone (:28) holds .90 until +15 and leaves the list; guest (:29) holds .90 from +45.
var (
	sampleFrom, sampleTo = t0, t0.Add(2 * time.Hour)
	devPrefix            = "00:00:5e:00:53:"
)

// sampleDevice is an entry of the sample Device List: MAC 00:00:5e:00:53:<n>, on.
func sampleDevice(n, name, ip, conn string) model.LANDevice {
	return model.LANDevice{MAC: devPrefix + n, Name: name, IPv4: ip, Status: "on", Allocation: "dhcp", Connection: conn}
}

// sampleReads returns the Device List reads of the sample home network.
func sampleReads() []timedRead {
	laptop := func(ip string) model.LANDevice {
		d := sampleDevice("21", "laptop", ip, "Wi-Fi 5 GHz")
		d.Signal, d.IPv6 = 5, []string{"2001:db8:5::21"}
		return d
	}
	phone := sampleDevice("22", "phone", "192.168.1.65", "Wi-Fi 2.4 GHz")
	phone.Signal = 1
	desk := sampleDevice("23", "desk-pc", "192.168.1.66", "Ethernet LAN-2")
	desk.Speed = "10Mbps halfduplex"
	tv := func(on bool) model.LANDevice {
		d := sampleDevice("24", "tv", "192.168.1.67", "Wi-Fi 5 GHz")
		d.Signal, d.LastActivity = 4, "Tue Oct 6 07:45:00 2026"
		if !on {
			d.Status, d.Signal = "off", 0
		}
		return d
	}
	printer := sampleDevice("25", "printer", "192.168.1.71", "Wi-Fi 2.4 GHz")
	printer.Signal = 3
	camera := sampleDevice("26", "camera", "192.168.1.71", "Wi-Fi 5 GHz")
	camera.Signal = 4
	nas := sampleDevice("27", "nas", "192.168.1.68", "Ethernet LAN-1")
	nas.Speed = "1000Mbps fullduplex"
	oldPhone := sampleDevice("28", "old-phone", "192.168.1.90", "Wi-Fi 5 GHz")
	guest := sampleDevice("29", "guest", "192.168.1.90", "Wi-Fi 5 GHz")
	guest.Signal = 4
	early := func() []model.LANDevice {
		return []model.LANDevice{laptop("192.168.1.64"), phone, desk, tv(true), printer, nas, oldPhone}
	}
	return []timedRead{
		{mins(-10), early()},
		{mins(15), early()},
		{mins(45), []model.LANDevice{laptop("192.168.1.80"), phone, desk, tv(true), printer, nas, guest}},
		{mins(75), []model.LANDevice{laptop("192.168.1.80"), phone, desk, tv(false), printer, nas, guest}},
		{mins(105), []model.LANDevice{laptop("192.168.1.80"), phone, desk, tv(false), printer, camera, nas, guest}},
	}
}

// sampleAggregate is the period's NAT samples as the connection store adds them up.
func sampleAggregate() model.ConnAggregate {
	ts := func(m float64) string { return rfc3339(mins(m)) }
	flow := func(dev, lan, remote string, port int, first, last float64) model.ConnFlow {
		return model.ConnFlow{Device: dev, LAN: lan, Remote: remote, Port: port, Proto: "tcp", First: ts(first), Last: ts(last), Samples: 2, Weight: 3}
	}
	laptop, phone, nas := "mac:"+devPrefix+"21", "mac:"+devPrefix+"22", "mac:"+devPrefix+"27"
	return model.ConnAggregate{
		From: ts(0), To: ts(120), Samples: 30, First: ts(2), Last: ts(118), InUse: 40, Available: 8000, Open: 9,
		Devices: []model.ConnDevice{
			{Key: laptop, Name: "laptop", IPv4: "192.168.1.80", MAC: devPrefix + "21", Samples: 30, Weight: 12, Open: 3},
			{Key: "ip:192.168.1.150", IPv4: "192.168.1.150", Samples: 10, Weight: 6, Open: 2},
			{Key: phone, Name: "phone", IPv4: "192.168.1.65", MAC: devPrefix + "22", Samples: 5, Weight: 3, Open: 1},
			{Key: nas, Name: "nas", IPv4: "192.168.1.68", MAC: devPrefix + "27", Samples: 2, Weight: 3},
			{Key: "ip:192.168.1.64", IPv4: "192.168.1.64", Samples: 1, Weight: 3}, // named by a read: not unknown
			{Key: gatewayKey, Samples: 3, Weight: 3, Open: 1},
		},
		Flows: []model.ConnFlow{
			flow(laptop, "192.168.1.80", "203.0.113.5", 443, 2, 118),
			flow(laptop, "192.168.1.80", "203.0.113.5", 80, 2, 118),
			flow(laptop, "192.168.1.80", "198.51.100.7", 443, 50, 118),
			flow(laptop, "192.168.1.64", "192.0.2.10", 443, 2, 40),
			flow("ip:192.168.1.150", "192.168.1.150", "203.0.113.9", 443, 30, 100),
			flow("ip:192.168.1.150", "192.168.1.150", "198.51.100.9", 443, 40, 110),
			flow(phone, "192.168.1.65", "203.0.113.5", 443, 10, 118),
			flow(nas, "192.168.1.68", "192.0.2.20", 443, 60, 60),
			flow("ip:192.168.1.64", "192.168.1.64", "192.0.2.30", 443, 5, 5),
			flow(gatewayKey, "198.51.100.1", "192.0.2.53", 53, 1, 117),
		},
	}
}

// sampleDrops stores the period's dropped packets: two sealed chunks up to +55 min, then the open
// chunk. (A chunk's drops of an address count for the device named at the newest of them; the
// store seals a chunk at 5 minutes, so the first chunk ends before laptop's and the old phone's
// addresses change hands.)
func sampleDrops(t *testing.T) contracts.SyslogChunkSource {
	s := testStore(t)
	appendMsgs(t, s, true,
		syslogMsg(mins(5), outLine("192.168.1.64", "192.0.2.44", 443, "POLICY")),  // laptop (the read in effect at the start)
		syslogMsg(mins(20), outLine("192.168.1.90", "192.0.2.44", 443, "POLICY"))) // old-phone, which left
	appendMsgs(t, s, true,
		syslogMsg(mins(30), outLine("192.168.1.68", "192.0.2.45", 22, "POLICY")),                   // nas ...
		syslogMsg(mins(30).Add(time.Second), repeatLine(119)),                                      // ... 120 in all
		syslogMsg(mins(35), inLine("192.0.2.17", "192.168.1.68", 60000)),                           // to nas ...
		syslogMsg(mins(35).Add(time.Second), repeatLine(29)),                                       // ... 30 in all
		syslogMsg(mins(50), outLine("192.168.1.80", "192.0.2.44", 443, "POLICY")),                  // laptop's new address
		syslogMsg(mins(50).Add(time.Second), outLine("192.168.1.90", "192.0.2.46", 443, "POLICY")), // guest
		syslogMsg(mins(52), inLine("2001:db8:9::7", "2001:db8:5::21", 22)),                         // to laptop's IPv6 address
		syslogMsg(mins(53), inLine("2001:db8:9::7", "2001:db8:5::99", 22)),                         // to an address no device has
		syslogMsg(mins(54), lineInbound))                                                           // to the gateway
	appendMsgs(t, s, false,
		syslogMsg(mins(70), outLine("192.168.1.151", "192.0.2.47", 443, "POLICY")), // unknown
		syslogMsg(mins(80), outLine("169.254.7.7", "192.0.2.48", 443, "POLICY")),   // unknown, self-assigned
		syslogMsg(mins(95), outLine("192.168.1.71", "192.0.2.49", 443, "POLICY")),  // printer (camera came later)
		syslogMsg(mins(130), outLine("192.168.1.66", "192.0.2.50", 443, "POLICY"))) // after the period
	return s
}

// sampleView is a view over the sample home network.
func sampleView(t *testing.T) (*View, *fakeHistory) {
	conns := &fakeHistory{fakeConns: &fakeConns{agg: sampleAggregate()}, reads: sampleReads()}
	return New(Options{Conns: conns, Syslog: sampleDrops(t), Intel: sampleIntel(), Now: func() time.Time { return sampleTo }}), conns
}

// ---------------------------------------------------------------- the view

func TestDevicesOfTheSampleNetwork(t *testing.T) {
	v, _ := sampleView(t)
	dv, err := v.Devices(context.Background(), contracts.NetQuery{From: sampleFrom, To: sampleTo})
	if err != nil {
		t.Fatal(err)
	}
	ts := func(m float64) string { return rfc3339(mins(m)) }
	if dv.From != ts(0) || dv.To != ts(120) || dv.ListAt != ts(105) || dv.Reads != 4 || dv.NATReads != 30 || dv.NATAt != ts(118) {
		t.Errorf("view: from %s to %s, list at %s, %d reads, %d NAT reads, the newest at %s", dv.From, dv.To, dv.ListAt, dv.Reads,
			dv.NATReads, dv.NATAt)
	}
	if want := (model.NetDeviceTotals{Listed: 8, Online: 7, WiFi: 6, Wired: 2, Issues: 8, Unknown: 3}); dv.Totals != want {
		t.Errorf("totals %+v, want %+v", dv.Totals, want)
	}
	var order []string
	byName := map[string]model.NetLANDevice{}
	for _, d := range dv.Devices {
		order = append(order, d.Name)
		byName[d.Name] = d
	}
	// Critical, then warnings, then the others; on before off; by name.
	if want := []string{"camera", "printer", "desk-pc", "nas", "phone", "guest", "laptop", "tv"}; !slices.Equal(order, want) {
		t.Errorf("order %q, want %q", order, want)
	}

	wantLaptop := model.NetLANDevice{Key: "mac:00:00:5e:00:53:21", Name: "laptop", MAC: "00:00:5e:00:53:21", IPv4: "192.168.1.80",
		IPv6: []string{"2001:db8:5::21"}, Status: "on", Allocation: "dhcp", Connection: "Wi-Fi 5 GHz", Signal: 5,
		Seen: ts(105), OnReads: 4, Reads: 4, Addresses: []string{"192.168.1.80", "192.168.1.64"},
		Open: 3, Sites: 3, Blocked: 2, BlockedIn: 1,
		Issues: []model.NetIssue{{Code: model.IssueAddressChanged, Level: model.IssueInfo,
			Text: "It held 2 IPv4 addresses in this period, the newest first: 192.168.1.80, 192.168.1.64."}}}
	if got := byName["laptop"]; !reflect.DeepEqual(got, wantLaptop) {
		t.Errorf("laptop:\n got %+v\nwant %+v", got, wantLaptop)
	}

	type figures struct {
		ip                             string
		reads, onReads                 int
		seen                           string
		open, sites, blocked, blocked2 int
		issues                         string // code:level, ...
	}
	describe := func(d model.NetLANDevice) figures {
		var is []string
		for _, i := range d.Issues {
			is = append(is, i.Code+":"+i.Level)
		}
		return figures{d.IPv4, d.Reads, d.OnReads, d.Seen, d.Open, d.Sites, d.Blocked, d.BlockedIn, strings.Join(is, ", ")}
	}
	for name, want := range map[string]figures{
		"phone":   {"192.168.1.65", 4, 4, ts(105), 1, 1, 0, 0, "weak_wifi:warning"},
		"desk-pc": {"192.168.1.66", 4, 4, ts(105), 0, 0, 0, 0, "slow_link:warning"},
		"tv":      {"192.168.1.67", 4, 2, ts(45), 0, 0, 0, 0, "offline:info"},
		"printer": {"192.168.1.71", 4, 4, ts(105), 0, 0, 1, 0, "address_shared:critical"},
		"camera":  {"192.168.1.71", 1, 1, ts(105), 0, 0, 0, 0, "address_shared:critical"},
		"nas":     {"192.168.1.68", 4, 4, ts(105), 0, 1, 120, 30, "blocked:warning"},
		"guest":   {"192.168.1.90", 3, 3, ts(105), 0, 0, 1, 0, ""},
	} {
		if got := describe(byName[name]); got != want {
			t.Errorf("%s: %+v, want %+v", name, got, want)
		}
	}
	texts := map[string]string{}
	for _, d := range dv.Devices {
		for _, i := range d.Issues {
			texts[d.Name+" "+i.Code] = i.Text
		}
	}
	for k, want := range map[string]string{
		"phone weak_wifi":        "Its Wi-Fi signal is weak: the gateway draws it with 1 bar of 5 (Wi-Fi 2.4 GHz).",
		"desk-pc slow_link":      `Its Ethernet link runs at 10 Mb/s, half duplex (the gateway shows "10Mbps halfduplex"); Ethernet normally runs at 100 or 1000 Mb/s, full duplex.`,
		"tv offline":             "The newest Device List read shows it off; the last read that showed it on was made 1 h before. The gateway gives its last activity as Tue Oct 6 07:45:00 2026.",
		"printer address_shared": "192.168.1.71 is also claimed by camera (00:00:5e:00:53:26) in the newest Device List read (an address conflict).",
		"camera address_shared":  "192.168.1.71 is also claimed by printer (00:00:5e:00:53:25) in the newest Device List read (an address conflict).",
		"nas blocked":            "In this period the gateway's firewall dropped 120 packets it sent toward the Internet and 30 packets sent to it from the Internet.",
	} {
		if texts[k] != want {
			t.Errorf("%s: %q\nwant %q", k, texts[k], want)
		}
	}

	wantUnknown := []model.NetUnknownAddr{
		{Addr: "192.168.1.150", First: ts(30), Last: ts(110), Open: 2, Sites: 2, Issues: []model.NetIssue{{Code: model.IssueUnlisted,
			Level: model.IssueWarning, Text: "No Device List read of this period names 192.168.1.150, yet the NAT table showed its connections (2 open connections in the newest read)."}}},
		{Addr: "169.254.7.7", First: ts(80), Last: ts(80), Blocked: 1, Issues: []model.NetIssue{{Code: model.IssueUnlisted, Level: model.IssueWarning,
			Text: "No Device List read of this period names 169.254.7.7, yet the gateway's firewall dropped 1 packet it sent. " +
				"A device gives itself an address in 169.254.0.0/16 when it gets none from the gateway's DHCP server."}}},
		{Addr: "192.168.1.151", First: ts(70), Last: ts(70), Blocked: 1, Issues: []model.NetIssue{{Code: model.IssueUnlisted, Level: model.IssueWarning,
			Text: "No Device List read of this period names 192.168.1.151, yet the gateway's firewall dropped 1 packet it sent."}}},
	}
	if !reflect.DeepEqual(dv.Unknown, wantUnknown) {
		t.Errorf("unknown:\n got %+v\nwant %+v", dv.Unknown, wantUnknown)
	}

	use := func(addr, n, name string, first, last float64, reads, shared int) model.NetAddrUse {
		return model.NetAddrUse{Addr: addr, Device: "mac:" + devPrefix + n, Name: name, MAC: devPrefix + n, First: ts(first), Last: ts(last),
			Reads: reads, Shared: shared}
	}
	wantHistory := []model.NetAddrUse{
		use("192.168.1.64", "21", "laptop", -10, 15, 2, 0),
		use("192.168.1.65", "22", "phone", -10, 105, 5, 0),
		use("192.168.1.66", "23", "desk-pc", -10, 105, 5, 0),
		use("192.168.1.67", "24", "tv", -10, 105, 5, 0), // off, but nobody else claims it
		use("192.168.1.68", "27", "nas", -10, 105, 5, 0),
		use("192.168.1.71", "25", "printer", -10, 105, 5, 1),
		use("192.168.1.71", "26", "camera", 105, 105, 1, 1),
		use("192.168.1.80", "21", "laptop", 45, 105, 3, 0),
		use("192.168.1.90", "28", "old-phone", -10, 15, 2, 0),
		use("192.168.1.90", "29", "guest", 45, 105, 3, 0),
	}
	if !reflect.DeepEqual(dv.Addresses, wantHistory) {
		t.Errorf("address history:\n got %+v\nwant %+v", dv.Addresses, wantHistory)
	}

	// No hardware address of the syslog lines reaches the view.
	if b := fmt.Sprintf("%+v", dv); strings.Contains(b, "00:00:5e:00:53:01") || strings.Contains(b, "00:00:5e:00:53:03:00") {
		t.Errorf("a MAC address of a syslog line reached the view: %s", b)
	}
}

// TestDevicesAddressesNameTheirTimes: a dropped packet counts for the device the Device List read
// in effect named at its address when it was received - else, for a device that has just joined,
// the next read within 20 minutes - not for the device that holds the address now.
func TestDevicesAddressesNameTheirTimes(t *testing.T) {
	a := sampleDevice("31", "first", "192.168.1.70", "Ethernet")
	b := sampleDevice("32", "second", "192.168.1.70", "Ethernet")
	late := sampleDevice("33", "late", "192.168.1.72", "Ethernet")
	conns := &fakeHistory{fakeConns: &fakeConns{}, reads: []timedRead{
		{mins(0), []model.LANDevice{a}},
		{mins(30), []model.LANDevice{a, late}}, // late joined at about +15
		{mins(60), []model.LANDevice{b, late}}, // DHCP gave .70 to second
	}}
	s := testStore(t)
	appendMsgs(t, s, false,
		syslogMsg(mins(10), outLine("192.168.1.70", "192.0.2.44", 443, "POLICY")), // first
		syslogMsg(mins(20), outLine("192.168.1.72", "192.0.2.44", 443, "POLICY")), // late: the next read, 10 min later
		syslogMsg(mins(65), outLine("192.168.1.70", "192.0.2.44", 443, "POLICY")), // second
		syslogMsg(mins(66), outLine("192.168.1.70", "192.0.2.44", 443, "POLICY"))) // second
	v := New(Options{Conns: conns, Syslog: s, Now: func() time.Time { return mins(90) }})
	dv, err := v.Devices(context.Background(), contracts.NetQuery{From: mins(0), To: mins(90)})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, d := range dv.Devices {
		got[d.Name] = d.Blocked
	}
	if want := map[string]int{"second": 2, "late": 1}; !reflect.DeepEqual(got, want) {
		t.Errorf("blocked %v, want %v", got, want)
	}
	if len(dv.Unknown) != 0 {
		t.Errorf("unknown %+v", dv.Unknown)
	}
	// A device that joins more than 20 minutes before the read that first lists it is not named
	// after that read: its packets count for nobody (no read of the period leaves the address
	// unnamed either).
	appendMsgs(t, s, false, syslogMsg(mins(4), outLine("192.168.1.72", "192.0.2.44", 443, "POLICY")))
	v = New(Options{Conns: conns, Syslog: s, Now: func() time.Time { return mins(90) }})
	dv, _ = v.Devices(context.Background(), contracts.NetQuery{From: mins(0), To: mins(90)})
	for _, d := range dv.Devices {
		if d.Name == "late" && d.Blocked != 1 {
			t.Errorf("late: blocked %d, want 1", d.Blocked)
		}
	}
}

// TestDevicesWithoutSources: without a connection store the view is not available; without a
// syslog store, NAT samples or the Device List reads by time it shows what it has, with no error.
func TestDevicesWithoutSources(t *testing.T) {
	if _, err := New(Options{Syslog: testStore(t)}).Devices(context.Background(), contracts.NetQuery{}); !errors.Is(err, contracts.ErrUnavailable) {
		t.Errorf("no connection store: %v", err)
	}
	reads := sampleReads()
	newest := reads[len(reads)-1]

	// A connection store without EachDevices, and no syslog store: the newest read alone.
	plain := &fakeConns{devices: newest.devices, agg: sampleAggregate()}
	v := New(Options{Conns: &newestOnly{plain, newest.at}, Now: func() time.Time { return sampleTo }})
	dv, err := v.Devices(context.Background(), contracts.NetQuery{From: sampleFrom, To: sampleTo})
	if err != nil {
		t.Fatal(err)
	}
	if len(dv.Devices) != 8 || dv.Reads != 1 || dv.NATReads != 30 || len(dv.Addresses) != 8 {
		t.Errorf("without the reads by time: %d devices, %d reads, %d NAT reads, %d addresses used", len(dv.Devices), dv.Reads,
			dv.NATReads, len(dv.Addresses))
	}
	for _, d := range dv.Devices {
		if d.Blocked != 0 || d.BlockedIn != 0 || d.Reads != 1 {
			t.Errorf("%s: blocked %d/%d, %d reads", d.Name, d.Blocked, d.BlockedIn, d.Reads)
		}
	}

	// The NAT samples cannot be added up, and the reads by time cannot be read: logged once each,
	// and the Device List is still shown.
	log := &logBuffer{}
	hist := &fakeHistory{fakeConns: &fakeConns{err: errors.New("disk on fire")}, reads: reads, err: errors.New("unreadable day")}
	v = New(Options{Conns: hist, Syslog: sampleDrops(t), Logger: slog.New(log), Now: func() time.Time { return sampleTo }, ResultTTL: -1})
	for range 2 {
		dv, err = v.Devices(context.Background(), contracts.NetQuery{From: sampleFrom, To: sampleTo})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(dv.Devices) != 8 || dv.NATReads != 0 || dv.NATAt != "" || dv.Reads != 1 {
		t.Errorf("degraded: %d devices, %d NAT reads (%q), %d reads", len(dv.Devices), dv.NATReads, dv.NATAt, dv.Reads)
	}
	for _, d := range dv.Devices {
		if d.Open != 0 || d.Sites != 0 {
			t.Errorf("%s: open %d, sites %d without NAT samples", d.Name, d.Open, d.Sites)
		}
	}
	if n, m := log.count("NAT samples of the period cannot be added up"), log.count("Device List reads of the period cannot be read"); n != 1 || m != 1 {
		t.Errorf("logged %d and %d times, want once each:\n%s", n, m, log)
	}

	// No Device List read at all: no devices, and every private address of the samples is unknown.
	none := &fakeHistory{fakeConns: &fakeConns{agg: sampleAggregate()}}
	dv, err = New(Options{Conns: none, Now: func() time.Time { return sampleTo }}).Devices(context.Background(),
		contracts.NetQuery{From: sampleFrom, To: sampleTo})
	if err != nil {
		t.Fatal(err)
	}
	if dv.ListAt != "" || len(dv.Devices) != 0 || dv.Reads != 0 || dv.Totals.Unknown != 2 || dv.Totals.Issues != 2 {
		t.Errorf("before the first read: %+v", dv)
	}
}

// newestOnly is a connection store without EachDevices whose newest Device List read was made at at.
type newestOnly struct {
	*fakeConns
	at time.Time
}

func (n *newestOnly) Devices() ([]model.LANDevice, time.Time) { return n.fakeConns.devices, n.at }

// TestDevicesPeriodAndContext: a period that is not valid is refused, a request that ended stops
// the build, and the view is reused for the same request within the result's time to live -
// a range ending now by its name, with its limit.
func TestDevicesPeriodAndContext(t *testing.T) {
	v, conns := sampleView(t)
	if _, err := v.Devices(context.Background(), contracts.NetQuery{From: sampleTo, To: sampleFrom}); !errors.Is(err, ErrRange) {
		t.Errorf("a period backwards: %v", err)
	}
	if _, err := v.Devices(context.Background(), contracts.NetQuery{From: t0.Add(-40 * 24 * time.Hour), To: t0}); !errors.Is(err, ErrRange) {
		t.Errorf("a period too long: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := v.Devices(ctx, contracts.NetQuery{From: sampleFrom, To: sampleTo}); !errors.Is(err, context.Canceled) {
		t.Errorf("a request that ended: %v", err)
	}
	q := contracts.NetQuery{From: sampleFrom, To: sampleTo, Range: "24h"}
	first, err := v.Devices(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	calls := conns.eachCalls()
	first.Devices[0].Name = "changed by the caller"
	first.Devices[0].Issues[0].Text = "changed too"
	again, err := v.Devices(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if conns.eachCalls() != calls {
		t.Error("the same request within the time to live was built again")
	}
	if again.Devices[0].Name == "changed by the caller" || again.Devices[0].Issues[0].Text == "changed too" {
		t.Error("the caller changed the view kept for reuse")
	}
	q.Limit = 1
	if dv, _ := v.Devices(context.Background(), q); conns.eachCalls() == calls || len(dv.Unknown) != 1 || dv.Totals.Unknown != 3 {
		t.Errorf("another limit: built again %v, %d unknown of %d", conns.eachCalls() != calls, len(dv.Unknown), dv.Totals.Unknown)
	}
}

// TestDevicesBoundTheUnknownAddresses: the drops of more LAN addresses that no read names than the
// bound are left out of the unknown addresses (the devices' own still count), and an IPv6 address
// no device has is never one.
func TestDevicesBoundTheUnknownAddresses(t *testing.T) {
	conns := &fakeHistory{fakeConns: &fakeConns{}, reads: []timedRead{{mins(0), []model.LANDevice{
		sampleDevice("41", "pc", "192.168.1.10", "Ethernet")}}}}
	var msgs []model.SyslogMessage
	for i := range 40 {
		msgs = append(msgs, syslogMsg(mins(1+float64(i)/10), outLine(fmt.Sprintf("10.0.%d.%d", i/250, 1+i%250), "192.0.2.44", 443, "POLICY")))
		msgs = append(msgs, syslogMsg(mins(1+float64(i)/10), inLine("2001:db8:9::7", fmt.Sprintf("2001:db8:5::%x", i+1), 22)))
	}
	msgs = append(msgs, syslogMsg(mins(10), outLine("192.168.1.10", "192.0.2.44", 443, "POLICY")))
	s := testStore(t)
	appendMsgs(t, s, true, msgs...)
	v := New(Options{Conns: conns, Syslog: s, Now: func() time.Time { return mins(60) }})
	v.bounds.lans = 16
	dv, err := v.Devices(context.Background(), contracts.NetQuery{From: mins(0), To: mins(60)})
	if err != nil {
		t.Fatal(err)
	}
	if dv.Totals.Unknown != 16 || len(dv.Unknown) != 16 || dv.Devices[0].Blocked != 1 {
		t.Errorf("%d unknown addresses (%d listed), pc blocked %d", dv.Totals.Unknown, len(dv.Unknown), dv.Devices[0].Blocked)
	}
	for _, u := range dv.Unknown {
		if !strings.HasPrefix(u.Addr, "10.0.") {
			t.Errorf("unknown %s", u.Addr)
		}
	}
}

// TestDevicesConcurrently: views of several periods built side by side, with the firewall and
// connections views, share the caches safely (go test -race).
func TestDevicesConcurrently(t *testing.T) {
	v, _ := sampleView(t)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			q := contracts.NetQuery{From: sampleFrom.Add(time.Duration(i%3) * time.Minute), To: sampleTo}
			switch i % 4 {
			case 0:
				if _, err := v.Firewall(context.Background(), q); err != nil {
					t.Error(err)
				}
			case 1:
				if _, err := v.Connections(context.Background(), q); err != nil {
					t.Error(err)
				}
			default:
				if dv, err := v.Devices(context.Background(), q); err != nil || len(dv.Devices) != 8 {
					t.Errorf("%d devices, %v", len(dv.Devices), err)
				}
			}
		}()
	}
	wg.Wait()
}
