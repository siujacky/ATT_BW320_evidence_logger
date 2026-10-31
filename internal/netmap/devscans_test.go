package netmap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

var _ contracts.ScanStore = (*fakeScans)(nil)

// fakeScans is a scan store whose scans a test gives (contracts.ScanStore), as connstore.Store
// keeps them: EachScan gives those that began in [from, to), oldest first.
type fakeScans struct {
	mu    sync.Mutex
	scans []model.LANScan
	err   error // EachScan fails with it, after giving the scans of the period
	calls int
}

func (f *fakeScans) AppendScan(_ time.Time, s model.LANScan) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scans = append(f.scans, s)
	return nil
}

func (f *fakeScans) EachScan(ctx context.Context, from, to time.Time, fn func(model.LANScan) error) error {
	f.mu.Lock()
	f.calls++
	scans, ferr := slices.Clone(f.scans), f.err
	f.mu.Unlock()
	for _, s := range scans {
		at, err := time.Parse(time.RFC3339Nano, s.At)
		if err == nil && (at.Before(from) || !at.Before(to)) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := fn(s); err != nil {
			if errors.Is(err, contracts.ErrStop) {
				return nil
			}
			return err
		}
	}
	return ferr
}

func (f *fakeScans) LastScan() (model.LANScan, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.scans) == 0 {
		return model.LANScan{}, false
	}
	return f.scans[len(f.scans)-1], true
}

func (f *fakeScans) eachCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeScans) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

// lanScan is a sweep of 192.168.1.0/24 begun at at; each host is "<address>=<last octet of the
// MAC address 00:00:5e:00:53:xx>".
func lanScan(at time.Time, hosts ...string) model.LANScan {
	s := model.LANScan{At: rfc3339(at), TookMs: 5000, Subnet: "192.168.1.0/24", Self: "192.168.1.64", Asked: 254, Hosts: []model.LANHost{}}
	for _, h := range hosts {
		ip, mac, _ := strings.Cut(h, "=")
		s.Hosts = append(s.Hosts, model.LANHost{IP: ip, MAC: devPrefix + mac})
	}
	return s
}

// sampleGateway is the gateway's own address on the sample home network.
var sampleGateway = netip.MustParseAddr("192.168.1.254")

// sampleScans are the sample home network's LAN scans (devices_test.go): before the period, at +30,
// +90 and +110 min - the newest, 5 minutes after the newest Device List read - and after it.
//
//   - laptop (:21) answers at .64, then at .80 (where it moved);
//   - desk-pc (:23) answers until +90, not the newest scan: no_answer;
//   - tv (:24), which is off, never answers;
//   - printer (:25) does not answer the newest scan, whose .71 camera (:26) answers: no_answer and
//     scan_mac;
//   - nas (:27) answers the newest scan at .69, not at .68: scan_addr;
//   - old-phone (:28), which left the list, answers at .91: not an unknown address;
//   - 00:00:5e:00:53:99 answers at .200 twice, :98 at .150 (an unknown address of the NAT samples)
//     and :97 at .67, the tv's address: unknown addresses;
//   - the gateway answers at .254: never an unknown address.
func sampleScans() *fakeScans {
	return &fakeScans{scans: []model.LANScan{
		lanScan(mins(-20), "192.168.1.64=21", "192.168.1.66=23"),
		lanScan(mins(30), "192.168.1.64=21", "192.168.1.65=22", "192.168.1.66=23", "192.168.1.91=28", "192.168.1.254=fe"),
		lanScan(mins(90), "192.168.1.65=22", "192.168.1.66=23", "192.168.1.80=21", "192.168.1.200=99", "192.168.1.254=fe"),
		lanScan(mins(110), "192.168.1.65=22", "192.168.1.67=97", "192.168.1.69=27", "192.168.1.71=26", "192.168.1.80=21",
			"192.168.1.90=29", "192.168.1.91=28", "192.168.1.150=98", "192.168.1.200=99", "192.168.1.254=fe"),
		lanScan(mins(130), "192.168.1.66=23"),
	}}
}

// scanView is a view over the sample home network with its LAN scans.
func scanView(t *testing.T, opts ...func(*Options)) (*View, *fakeHistory, *fakeScans) {
	conns := &fakeHistory{fakeConns: &fakeConns{agg: sampleAggregate()}, reads: sampleReads()}
	scans := sampleScans()
	o := Options{Conns: conns, Syslog: sampleDrops(t), Intel: sampleIntel(), Scans: scans, Gateway: sampleGateway,
		Now: func() time.Time { return sampleTo }}
	for _, f := range opts {
		f(&o)
	}
	return New(o), conns, scans
}

// TestDevicesWithLANScans: the scans of the period name, for each device, where it answered the
// newest, when it last answered and how many it answered; the newest scan, compared with the newest
// Device List read made 5 minutes before it, gives the issues no_answer, scan_mac and scan_addr;
// an address answered by a MAC address no read names is an unknown address with that MAC
// address; the gateway's own answer is nobody's.
func TestDevicesWithLANScans(t *testing.T) {
	v, _, _ := scanView(t)
	dv, err := v.Devices(context.Background(), contracts.NetQuery{From: sampleFrom, To: sampleTo})
	if err != nil {
		t.Fatal(err)
	}
	ts := func(m float64) string { return rfc3339(mins(m)) }
	if dv.Scans != 3 || dv.Scan == nil {
		t.Fatalf("%d scans, newest %+v", dv.Scans, dv.Scan)
	}
	if want := (model.NetScanInfo{At: ts(110), Subnet: "192.168.1.0/24", Asked: 254, Answered: 10, TookMs: 5000}); *dv.Scan != want {
		t.Errorf("newest scan %+v, want %+v", *dv.Scan, want)
	}
	if want := (model.NetDeviceTotals{Listed: 8, Online: 7, WiFi: 6, Wired: 2, Issues: 10, Unknown: 5, Scanned: 10}); dv.Totals != want {
		t.Errorf("totals %+v, want %+v", dv.Totals, want)
	}
	type figures struct {
		addr, seen string
		hits       int
		issues     string
	}
	got := map[string]figures{}
	texts := map[string]string{}
	for _, d := range dv.Devices {
		var is []string
		for _, i := range d.Issues {
			is = append(is, i.Code)
			texts[d.Name+" "+i.Code] = i.Text
		}
		got[d.Name] = figures{d.ScanAddr, d.ScanSeen, d.ScanHits, strings.Join(is, ", ")}
	}
	want := map[string]figures{
		"laptop":  {"192.168.1.80", ts(110), 3, "address_changed"},
		"phone":   {"192.168.1.65", ts(110), 3, "weak_wifi"},
		"desk-pc": {"", ts(90), 2, "slow_link, no_answer"},
		"tv":      {"", "", 0, "offline"},
		"printer": {"", "", 0, "address_shared, scan_mac, no_answer"},
		"camera":  {"192.168.1.71", ts(110), 1, "address_shared"},
		"nas":     {"192.168.1.69", ts(110), 1, "blocked, scan_addr"},
		"guest":   {"192.168.1.90", ts(110), 1, ""},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("devices:\n got %+v\nwant %+v", got, want)
	}
	for k, want := range map[string]string{
		"desk-pc no_answer": "The newest Device List read shows it on, but it did not answer the newest LAN scan (made 5 min after that read); " +
			"a device that sleeps may not answer.",
		"printer scan_mac": "The newest LAN scan found 192.168.1.71 answered by another MAC address, 00:00:5e:00:53:26, which the newest " +
			"Device List read gives to camera: two devices may be using the address, or the list is out of date.",
		"nas scan_addr": "It answered the newest LAN scan at 192.168.1.69, not at 192.168.1.68, the address the gateway lists for it.",
	} {
		if texts[k] != want {
			t.Errorf("%s: %q\nwant %q", k, texts[k], want)
		}
	}
	for _, d := range dv.Devices {
		for _, i := range d.Issues {
			if lvl := map[string]string{model.IssueNoAnswer: model.IssueInfo, model.IssueScanAddr: model.IssueInfo,
				model.IssueScanMAC: model.IssueWarning}[i.Code]; lvl != "" && i.Level != lvl {
				t.Errorf("%s %s: level %s, want %s", d.Name, i.Code, i.Level, lvl)
			}
		}
	}

	type unknown struct {
		addr, mac, seen, first, last string
		issue                        string
	}
	var gotU []unknown
	for _, u := range dv.Unknown {
		gotU = append(gotU, unknown{u.Addr, u.MAC, u.ScanSeen, u.First, u.Last, u.Issues[0].Text})
	}
	const fixed = " Perhaps a device with a fixed address, which the gateway does not list."
	wantU := []unknown{ // the most recently seen first, then by address
		{"192.168.1.67", devPrefix + "97", ts(110), ts(110), ts(110), "192.168.1.67 answered 1 LAN scan of this period from 00:00:5e:00:53:97, " +
			"which no Device List read of this period names (the reads give the address to another device)." + fixed},
		{"192.168.1.150", devPrefix + "98", ts(110), ts(30), ts(110), "No Device List read of this period names 192.168.1.150, yet the NAT " +
			"table showed its connections (2 open connections in the newest read) and it answered 1 LAN scan of this period (from 00:00:5e:00:53:98)." + fixed},
		{"192.168.1.200", devPrefix + "99", ts(110), ts(90), ts(110), "No Device List read of this period names 192.168.1.200, yet it answered " +
			"2 LAN scans of this period (from 00:00:5e:00:53:99)." + fixed},
		{"169.254.7.7", "", "", ts(80), ts(80), "No Device List read of this period names 169.254.7.7, yet the gateway's firewall dropped 1 packet " +
			"it sent. A device gives itself an address in 169.254.0.0/16 when it gets none from the gateway's DHCP server."},
		{"192.168.1.151", "", "", ts(70), ts(70), "No Device List read of this period names 192.168.1.151, yet the gateway's firewall dropped 1 packet it sent."},
	}
	if !reflect.DeepEqual(gotU, wantU) {
		t.Errorf("unknown:\n got %+v\nwant %+v", gotU, wantU)
	}
	for _, u := range dv.Unknown {
		if u.Addr == "192.168.1.254" || u.Addr == "192.168.1.91" {
			t.Errorf("%s is an unknown address", u.Addr)
		}
	}

	// The figures without the scans are those of TestDevicesOfTheSampleNetwork.
	plain, _ := sampleView(t)
	pv, err := plain.Devices(context.Background(), contracts.NetQuery{From: sampleFrom, To: sampleTo})
	if err != nil {
		t.Fatal(err)
	}
	if pv.Scans != 0 || pv.Scan != nil || pv.Totals.Scanned != 0 {
		t.Errorf("without a scan store: %d scans, %+v, %d scanned", pv.Scans, pv.Scan, pv.Totals.Scanned)
	}
	for _, d := range pv.Devices {
		if d.ScanAddr != "" || d.ScanSeen != "" || d.ScanHits != 0 {
			t.Errorf("%s without a scan store: %q %q %d", d.Name, d.ScanAddr, d.ScanSeen, d.ScanHits)
		}
	}
}

// TestDevicesScanIssuesNeedAFreshScan: the issues that compare the newest scan with the newest
// Device List read wait for a scan made within an hour of the read; a sweep that stopped short
// says nothing of the devices that did not answer it; a device the gateway lists without an IPv4
// address that answered is said to.
func TestDevicesScanIssuesNeedAFreshScan(t *testing.T) {
	codes := func(dv model.NetDevicesView) map[string]string {
		out := map[string]string{}
		for _, d := range dv.Devices {
			var is []string
			for _, i := range d.Issues {
				if i.Code == model.IssueNoAnswer || i.Code == model.IssueScanMAC || i.Code == model.IssueScanAddr {
					is = append(is, i.Code)
				}
			}
			out[d.Name] = strings.Join(is, ", ")
		}
		return out
	}
	pc := sampleDevice("41", "pc", "192.168.1.10", "Ethernet")
	nas := sampleDevice("42", "nas", "192.168.1.11", "Ethernet")
	v6only := sampleDevice("43", "tablet", "", "Wi-Fi 5 GHz")
	conns := &fakeHistory{fakeConns: &fakeConns{}, reads: []timedRead{{mins(0), []model.LANDevice{pc, nas, v6only}}}}
	for _, tc := range []struct {
		name  string
		scan  model.LANScan
		want  map[string]string
		texts map[string]string // "<name> <code>" → its text
	}{
		{"an hour after the read", lanScan(mins(60), "192.168.1.12=42", "192.168.1.10=99", "192.168.1.13=43"),
			map[string]string{"pc": "scan_mac, no_answer", "nas": "scan_addr", "tablet": "scan_addr"},
			map[string]string{
				"tablet scan_addr": "It answered the newest LAN scan at 192.168.1.13; the gateway lists no IPv4 address for it.",
				"pc scan_mac": "The newest LAN scan found 192.168.1.10 answered by another MAC address, 00:00:5e:00:53:99, which no Device List " +
					"read of this period names: a device the gateway does not list may be using the address.",
				"pc no_answer": "The newest Device List read shows it on, but it did not answer the newest LAN scan (made 1 h after that read); " +
					"a device that sleeps may not answer.",
			}},
		{"an hour before the read", lanScan(mins(-60), "192.168.1.12=42"), map[string]string{"pc": "no_answer", "nas": "scan_addr", "tablet": ""},
			map[string]string{"pc no_answer": "The newest Device List read shows it on, but it did not answer the newest LAN scan (made 1 h before " +
				"that read); a device that sleeps may not answer."}},
		{"more than an hour after the read", lanScan(mins(61), "192.168.1.12=42"), map[string]string{"pc": "", "nas": "", "tablet": ""}, nil},
		{"a sweep that stopped short", func() model.LANScan {
			s := lanScan(mins(5), "192.168.1.12=42")
			s.Problem = "the sweep stopped after 2 minutes: 120 of 254 addresses asked"
			return s
		}(), map[string]string{"pc": "", "nas": "scan_addr", "tablet": ""}, nil},
		{"another network", func() model.LANScan {
			s := lanScan(mins(5))
			s.Subnet = "10.0.0.0/24"
			return s
		}(), map[string]string{"pc": "", "nas": "", "tablet": ""}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scans := &fakeScans{scans: []model.LANScan{tc.scan}}
			v := New(Options{Conns: conns, Scans: scans, Now: func() time.Time { return mins(90) }})
			dv, err := v.Devices(context.Background(), contracts.NetQuery{From: mins(-90), To: mins(90)})
			if err != nil {
				t.Fatal(err)
			}
			if got := codes(dv); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("issues %v, want %v", got, tc.want)
			}
			texts := map[string]string{}
			for _, d := range dv.Devices {
				for _, i := range d.Issues {
					texts[d.Name+" "+i.Code] = i.Text
				}
			}
			for k, want := range tc.texts {
				if texts[k] != want {
					t.Errorf("%s: %q\nwant %q", k, texts[k], want)
				}
			}
		})
	}
}

// TestDevicesScansOfAnEntryWithoutMAC: an entry without a MAC address answers at the address the
// Device List read in effect at the scan gives it - also once it left the list, when its answer is
// nobody's - and once the reads give that address to another device, an answer there from a MAC
// address no read names is an unknown address's.
func TestDevicesScansOfAnEntryWithoutMAC(t *testing.T) {
	printer := model.LANDevice{Name: "printer", IPv4: "192.168.1.30", Status: "on", Connection: "Ethernet"}
	pc := sampleDevice("41", "pc", "192.168.1.31", "Ethernet")
	tv := sampleDevice("42", "tv", "192.168.1.30", "Wi-Fi 5 GHz")
	early := []timedRead{{mins(0), []model.LANDevice{printer, pc}}, {mins(60), []model.LANDevice{printer, pc}}}
	scans := &fakeScans{scans: []model.LANScan{
		lanScan(mins(10), "192.168.1.30=aa", "192.168.1.31=41"),
		lanScan(mins(70), "192.168.1.31=41"),
		lanScan(mins(130), "192.168.1.30=aa", "192.168.1.31=41"), // the printer, after the tv took its address
	}}
	has := func(d model.NetLANDevice, code string) bool {
		return slices.ContainsFunc(d.Issues, func(i model.NetIssue) bool { return i.Code == code })
	}

	// Up to +100 the newest read lists the printer: it answered the first scan, not the newest.
	conns := &fakeHistory{fakeConns: &fakeConns{}, reads: early}
	dv, err := New(Options{Conns: conns, Scans: scans, Now: func() time.Time { return mins(100) }}).Devices(context.Background(),
		contracts.NetQuery{From: mins(0), To: mins(100)})
	if err != nil {
		t.Fatal(err)
	}
	var p model.NetLANDevice
	for _, d := range dv.Devices {
		if d.Name == "printer" {
			p = d
		}
	}
	if p.Key != "ip:192.168.1.30" || p.ScanHits != 1 || p.ScanSeen != rfc3339(mins(10)) || p.ScanAddr != "" || !has(p, model.IssueNoAnswer) {
		t.Errorf("printer: %+v", p)
	}
	if len(dv.Unknown) != 0 || dv.Scans != 2 {
		t.Errorf("%d scans, unknown %+v", dv.Scans, dv.Unknown)
	}

	// The printer left and DHCP gave .30 to the tv: the printer's answer at +10 is nobody's now, the
	// answer at .30 from 00:00:5e:00:53:aa at +130 an unknown device's - and the tv's issue.
	conns = &fakeHistory{fakeConns: &fakeConns{}, reads: append(slices.Clone(early), timedRead{mins(120), []model.LANDevice{pc, tv}})}
	dv, err = New(Options{Conns: conns, Scans: scans, Now: func() time.Time { return mins(140) }}).Devices(context.Background(),
		contracts.NetQuery{From: mins(0), To: mins(140)})
	if err != nil {
		t.Fatal(err)
	}
	if len(dv.Unknown) != 1 || dv.Unknown[0].Addr != "192.168.1.30" || dv.Unknown[0].MAC != devPrefix+"aa" ||
		dv.Unknown[0].ScanSeen != rfc3339(mins(130)) || dv.Unknown[0].First != rfc3339(mins(130)) {
		t.Errorf("unknown: %+v", dv.Unknown)
	}
	for _, d := range dv.Devices {
		switch d.Name {
		case "tv":
			if d.ScanHits != 0 || !has(d, model.IssueScanMAC) || !has(d, model.IssueNoAnswer) {
				t.Errorf("tv: %+v", d)
			}
		case "pc":
			if d.ScanHits != 3 || d.ScanAddr != "192.168.1.31" || len(d.Issues) != 0 {
				t.Errorf("pc: %+v", d)
			}
		}
	}
}

// TestDevicesScansCannotBeRead: a scan store that fails gives no scan figures at all - not those of
// the scans it gave before failing - and is logged once while it fails; the view is still built.
func TestDevicesScansCannotBeRead(t *testing.T) {
	log := &logBuffer{}
	v, _, scans := scanView(t, func(o *Options) { o.Logger = slog.New(log); o.ResultTTL = -1 })
	scans.setErr(errors.New("scan-2026-10-06.jsonl: unexpected EOF"))
	for range 2 {
		dv, err := v.Devices(context.Background(), contracts.NetQuery{From: sampleFrom, To: sampleTo})
		if err != nil {
			t.Fatal(err)
		}
		if dv.Scans != 0 || dv.Scan != nil || dv.Totals.Scanned != 0 || len(dv.Devices) != 8 || dv.Totals.Unknown != 3 {
			t.Errorf("scans that cannot be read: %d scans, %+v, %d devices, %d unknown", dv.Scans, dv.Scan, len(dv.Devices), dv.Totals.Unknown)
		}
		for _, d := range dv.Devices {
			if d.ScanHits != 0 || slices.ContainsFunc(d.Issues, func(i model.NetIssue) bool { return i.Code == model.IssueNoAnswer }) {
				t.Errorf("%s: %+v", d.Name, d)
			}
		}
	}
	if n := log.count("LAN scans of the period cannot be read"); n != 1 {
		t.Errorf("logged %d times, want once:\n%s", n, log)
	}
	scans.setErr(nil)
	if dv, err := v.Devices(context.Background(), contracts.NetQuery{From: sampleFrom, To: sampleTo}); err != nil || dv.Scans != 3 {
		t.Errorf("readable again: %d scans, %v", dv.Scans, err)
	}
	scans.setErr(errors.New("again"))
	v.Devices(context.Background(), contracts.NetQuery{From: sampleFrom, To: sampleTo})
	if n := log.count("LAN scans of the period cannot be read"); n != 2 {
		t.Errorf("a new failure logged %d times in all, want 2", n)
	}
	// A request that ends while the scans are read ends the build.
	ctx, cancel := context.WithCancel(context.Background())
	failing := &cancelScans{fakeScans: sampleScans(), cancel: cancel}
	v2, _, _ := scanView(t, func(o *Options) { o.Scans = failing })
	if _, err := v2.Devices(ctx, contracts.NetQuery{From: sampleFrom, To: sampleTo}); !errors.Is(err, context.Canceled) {
		t.Errorf("a request that ended: %v", err)
	}
}

// cancelScans cancels its request while the scans are read.
type cancelScans struct {
	*fakeScans
	cancel context.CancelFunc
}

func (c *cancelScans) EachScan(ctx context.Context, from, to time.Time, fn func(model.LANScan) error) error {
	c.cancel()
	return ctx.Err()
}

// TestDevicesScansAreBounded: a scan holding more answers than a sweep can is read up to
// maxScanHosts, and the unknown addresses the scans add are bounded like those of the drops: an
// impostor answering every address of the network with its own MAC address does not grow the view.
func TestDevicesScansAreBounded(t *testing.T) {
	conns := &fakeHistory{fakeConns: &fakeConns{}, reads: []timedRead{{mins(0), []model.LANDevice{sampleDevice("41", "pc", "10.0.0.1", "Ethernet")}}}}
	big := model.LANScan{At: rfc3339(mins(5)), Subnet: "10.0.0.0/16", Asked: 65534, Hosts: []model.LANHost{{IP: "10.0.0.1", MAC: devPrefix + "41"}}}
	for i := range 2 * maxScanHosts {
		big.Hosts = append(big.Hosts, model.LANHost{IP: fmt.Sprintf("10.0.%d.%d", i/250, 2+i%250), MAC: devPrefix + "66"})
	}
	v := New(Options{Conns: conns, Scans: &fakeScans{scans: []model.LANScan{big}}, Now: func() time.Time { return mins(60) }})
	v.bounds.lans = 100
	dv, err := v.Devices(context.Background(), contracts.NetQuery{From: mins(0), To: mins(60)})
	if err != nil {
		t.Fatal(err)
	}
	if dv.Scan == nil || dv.Scan.Answered != maxScanHosts || dv.Totals.Scanned != maxScanHosts || dv.Totals.Unknown != 100 || len(dv.Unknown) != 100 {
		t.Fatalf("scan %+v, %d unknown", dv.Scan, dv.Totals.Unknown)
	}
	if dv.Devices[0].ScanHits != 1 || dv.Devices[0].ScanAddr != "10.0.0.1" {
		t.Errorf("pc: %+v", dv.Devices[0])
	}
	// A device's details find each of them.
	dd, err := v.Device(context.Background(), contracts.NetQuery{From: mins(0), To: mins(60)}, "", dv.Unknown[99].Addr)
	if err != nil || dd.Unknown == nil || len(dd.Scans) != 1 || dd.Scans[0].Addr != dv.Unknown[99].Addr {
		t.Errorf("details of %s: %+v, %v", dv.Unknown[99].Addr, dd, err)
	}
}

// TestScanAnswers: the answers of a scan are its IPv4 addresses, each once, in address order, with
// their MAC addresses in the device key's form.
func TestScanAnswers(t *testing.T) {
	s := newLANScans(0)
	got := s.answers([]model.LANHost{{IP: "192.168.1.9", MAC: "00-00-5E-00-53-09"}, {IP: " 192.168.1.2 ", MAC: "00:00:5e:00:53:02"},
		{IP: "::ffff:192.168.1.3", MAC: "bogus"}, {IP: "192.168.1.2", MAC: "00:00:5e:00:53:99"}, {IP: "fe80::1", MAC: "00:00:5e:00:53:01"},
		{IP: "192.168.1.300", MAC: "00:00:5e:00:53:01"}, {IP: "192.168.1.4", MAC: "00:00:00:00:00:00"}})
	want := []scanAnswer{{netip.MustParseAddr("192.168.1.2"), "00:00:5e:00:53:02"}, {netip.MustParseAddr("192.168.1.3"), ""},
		{netip.MustParseAddr("192.168.1.4"), ""}, {netip.MustParseAddr("192.168.1.9"), "00:00:5e:00:53:09"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("answers %+v, want %+v", got, want)
	}
	for _, tc := range []struct {
		addr, subnet string
		want         bool
	}{{"192.168.1.5", "192.168.1.0/24", true}, {"192.168.2.5", "192.168.1.0/24", false}, {"192.168.1.5", "", false},
		{"192.168.1.5", "bogus", false}, {"10.0.3.255", " 10.0.0.0/22 ", true}} {
		if got := inSubnet(netip.MustParseAddr(tc.addr), tc.subnet); got != tc.want {
			t.Errorf("inSubnet(%s, %q) = %v", tc.addr, tc.subnet, got)
		}
	}
}

func TestScanIssueTexts(t *testing.T) {
	listAt := t0
	for _, tc := range []struct {
		is   model.NetIssue
		want string
	}{
		{noAnswerIssue(listAt.Add(30*time.Second), listAt), "The newest Device List read shows it on, but it did not answer the newest LAN scan " +
			"(made less than a minute after that read); a device that sleeps may not answer."},
		{noAnswerIssue(listAt.Add(-40*time.Minute), listAt), "The newest Device List read shows it on, but it did not answer the newest LAN scan " +
			"(made 40 min before that read); a device that sleeps may not answer."},
		{scanMACIssue("192.168.1.7", "00:00:5e:00:53:09", &model.NetLANDevice{}, "", true), "The newest LAN scan found 192.168.1.7 answered by " +
			"another MAC address, 00:00:5e:00:53:09, which the newest Device List read gives to another entry (without a name): two devices may be using the address, or the list is out of date."},
		{scanMACIssue("192.168.1.7", "00:00:5e:00:53:09", nil, "old-phone", true), "The newest LAN scan found 192.168.1.7 answered by another MAC " +
			"address, 00:00:5e:00:53:09, which a Device List read of this period gave to old-phone (no longer listed): two devices may be using the address, or the list is out of date."},
		{scanMACIssue("192.168.1.7", "00:00:5e:00:53:09", nil, "", true), "The newest LAN scan found 192.168.1.7 answered by another MAC address, " +
			"00:00:5e:00:53:09, which a Device List read of this period named (no longer listed): two devices may be using the address, or the list is out of date."},
		{unknownIssue(model.NetUnknownAddr{Addr: "192.168.1.50"}, false, 1, true), "192.168.1.50 answered 1 LAN scan of this period from a MAC " +
			"address that is not valid, which no Device List read of this period names (the reads give the address to another device). " +
			"Perhaps a device with a fixed address, which the gateway does not list."},
		{unknownIssue(model.NetUnknownAddr{Addr: "169.254.1.1", MAC: "00:00:5e:00:53:09", Blocked: 1}, false, 4, false), "No Device List read of " +
			"this period names 169.254.1.1, yet the gateway's firewall dropped 1 packet it sent and it answered 4 LAN scans of this period (from " +
			"00:00:5e:00:53:09). A device gives itself an address in 169.254.0.0/16 when it gets none from the gateway's DHCP server."},
		{unknownIssue(model.NetUnknownAddr{Addr: "192.168.1.150", Open: 1, Blocked: 2, BlockedIn: 1, MAC: "00:00:5e:00:53:09"}, true, 2, false),
			"No Device List read of this period names 192.168.1.150, yet the NAT table showed its connections (1 open connection in the newest " +
				"read), the gateway's firewall dropped 2 packets it sent and 1 packet sent to it from the Internet and it answered 2 LAN scans of " +
				"this period (from 00:00:5e:00:53:09). Perhaps a device with a fixed address, which the gateway does not list."},
	} {
		if tc.is.Text != tc.want {
			t.Errorf("%s:\n got %q\nwant %q", tc.is.Code, tc.is.Text, tc.want)
		}
	}
}
