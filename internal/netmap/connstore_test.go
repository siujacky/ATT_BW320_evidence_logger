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

// The connection store gives the firewall view its Device List reads by time.
var _ deviceHistory = (*connstore.Store)(nil)

// TestFirewallNamesDropsWithTheConnectionStore: with the connection store the service opens, a
// LAN address's dropped packets are named after the Device List read in effect when they were
// received (connstore.Store.EachDevices), not after its newest read: the phone that held
// 192.168.1.70 twenty days ago is not blamed on the laptop that holds it now.
func TestFirewallNamesDropsWithTheConnectionStore(t *testing.T) {
	const day = 24 * time.Hour
	phone := func(ip string) model.LANDevice {
		return model.LANDevice{MAC: "00:00:5e:00:53:70", Name: "Phone", IPv4: ip, Status: "on"}
	}
	laptop := func(ip string) model.LANDevice {
		return model.LANDevice{MAC: "00:00:5e:00:53:71", Name: "Laptop", IPv4: ip, Status: "on"}
	}
	cs, err := connstore.Open(t.TempDir(), connstore.Options{Now: func() time.Time { return t0.Add(time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	for _, r := range []struct {
		at      time.Time
		devices []model.LANDevice
	}{
		{t0.Add(-25 * day), []model.LANDevice{phone("192.168.1.70"), laptop("192.168.1.71")}},
		{t0.Add(-1 * day), []model.LANDevice{laptop("192.168.1.70"), phone("192.168.1.90")}}, // DHCP moved them
	} {
		if err := cs.AppendDevices(r.at, r.devices); err != nil {
			t.Fatal(err)
		}
	}
	s := testStore(t)
	appendMsgs(t, s, true, syslogMsg(t0.Add(-20*day+time.Hour), outLine("192.168.1.70", "192.0.2.44", 443, "POLICY")))
	appendMsgs(t, s, false, syslogMsg(t0.Add(time.Minute), outLine("192.168.1.70", "192.0.2.44", 443, "POLICY")))
	fw, err := New(Options{Syslog: s, Conns: cs}).Firewall(context.Background(),
		contracts.NetQuery{From: t0.Add(-21 * day), To: t0.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	type row struct{ device, name, lan string }
	got := map[row]int{}
	for _, r := range fw.OutboundRows {
		got[row{r.Device, r.Name, r.LAN}] = r.Count
	}
	want := map[row]int{
		{"mac:00:00:5e:00:53:70", "Phone", "192.168.1.70"}:  1,
		{"mac:00:00:5e:00:53:71", "Laptop", "192.168.1.70"}: 1,
	}
	if !reflect.DeepEqual(got, want) || fw.OutboundTotal != 2 || fw.OutboundDevices != 2 {
		t.Fatalf("rows %+v (%d, from %d devices); want %+v", got, fw.OutboundTotal, fw.OutboundDevices, want)
	}
}
