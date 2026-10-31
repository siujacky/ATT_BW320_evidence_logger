package netmap

import (
	"context"
	"reflect"
	"testing"
	"time"

	"attmonitor/internal/connstore"
	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// The connection store keeps the LAN scans the Devices view reads.
var _ contracts.ScanStore = (*connstore.Store)(nil)

// TestDevicesWithTheScanStore: the Devices view and a device's details over the connection store
// the service opens, with the LAN scans it keeps: the scans of the period (not the day before's,
// nor one after it), each device's answers, an unknown device that answered with a MAC address no
// read names, the gateway's own answer nobody's; the details list the scans newest first.
func TestDevicesWithTheScanStore(t *testing.T) {
	now := mins(180)
	cs, err := connstore.Open(t.TempDir(), connstore.Options{Now: func() time.Time { return now }, Gateway: sampleGateway})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	laptop := sampleDevice("61", "laptop", "192.168.1.70", "Wi-Fi 5 GHz")
	phone := sampleDevice("62", "phone", "192.168.1.71", "Wi-Fi 2.4 GHz")
	for _, at := range []time.Time{t0.Add(-24 * time.Hour), mins(10), mins(70), mins(130)} {
		if err := cs.AppendDevices(at, []model.LANDevice{laptop, phone}); err != nil {
			t.Fatal(err)
		}
	}
	scan := func(hosts ...string) model.LANScan {
		s := lanScan(time.Time{}, hosts...)
		s.At = "" // the store sets it
		return s
	}
	for _, s := range []struct {
		at   time.Time
		scan model.LANScan
	}{
		{t0.Add(-23 * time.Hour), scan("192.168.1.70=61", "192.168.1.71=62")}, // the day before the period
		{mins(20), scan("192.168.1.70=61", "192.168.1.71=62", "192.168.1.254=fe")},
		{mins(80), scan("192.168.1.70=61", "192.168.1.120=99", "192.168.1.254=fe")},
		{mins(140), scan("192.168.1.70=61", "192.168.1.71=62", "192.168.1.120=99", "192.168.1.254=fe")},
		{mins(181), scan("192.168.1.71=62")}, // after the period
	} {
		if err := cs.AppendScan(s.at, s.scan); err != nil {
			t.Fatal(err)
		}
	}
	v := New(Options{Conns: cs, Scans: cs, Gateway: sampleGateway, Now: func() time.Time { return now }})
	q := contracts.NetQuery{From: t0, To: now, Range: "24h"}
	dv, err := v.Devices(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	ts := func(m float64) string { return rfc3339(mins(m)) }
	if dv.Scans != 3 || dv.Scan == nil || dv.Scan.At != ts(140) || dv.Scan.Answered != 4 || dv.Totals.Scanned != 4 {
		t.Fatalf("%d scans, newest %+v, %d scanned", dv.Scans, dv.Scan, dv.Totals.Scanned)
	}
	got := map[string][3]string{}
	for _, d := range dv.Devices {
		got[d.Name] = [3]string{d.ScanAddr, d.ScanSeen, string(rune('0' + d.ScanHits))}
	}
	if want := map[string][3]string{"laptop": {"192.168.1.70", ts(140), "3"}, "phone": {"192.168.1.71", ts(140), "2"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("devices %v, want %v", got, want)
	}
	if len(dv.Unknown) != 1 || dv.Unknown[0].Addr != "192.168.1.120" || dv.Unknown[0].MAC != devPrefix+"99" || dv.Unknown[0].ScanSeen != ts(140) ||
		dv.Unknown[0].First != ts(80) {
		t.Errorf("unknown %+v", dv.Unknown)
	}

	dd, err := v.Device(context.Background(), q, "mac:"+devPrefix+"62", "")
	if err != nil {
		t.Fatal(err)
	}
	if want := []model.NetScanSeen{{At: ts(140), Addr: "192.168.1.71"}, {At: ts(80)}, {At: ts(20), Addr: "192.168.1.71"}}; !reflect.DeepEqual(dd.Scans, want) {
		t.Errorf("the phone's scans %+v", dd.Scans)
	}
	if want := []model.NetSyslogTerm{{Kind: "ipv4", Text: "192.168.1.71"}, {Kind: "mac", Text: devPrefix + "62"}}; !reflect.DeepEqual(dd.Match, want) {
		t.Errorf("the phone's terms %+v", dd.Match) // read from before the period to its end: the whole period
	}
	dd, err = v.Device(context.Background(), q, "", "192.168.1.120")
	if err != nil || dd.Unknown == nil || len(dd.Scans) != 3 || dd.Scans[0].Addr != "192.168.1.120" || dd.Scans[2].Addr != "" {
		t.Errorf("the unknown address: %+v, %v", dd, err)
	}
}
