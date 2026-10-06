package connstore

import (
	"os"
	"path/filepath"
	"testing"

	"attmonitor/internal/gateway"
)

// TestFixturesThroughTheStore runs the gateway's pages as the monitor reads them - the synthetic NAT
// table page and the sanitized real Device List (testdata/gateway) - through the gateway client's
// parsers, the store and its aggregation: the NAT table's IPv6 session from the laptop's listed
// global address is the laptop's, its remote side the remote host; the gateway's own session stays
// the gateway's; a LAN address the Device List does not list keeps its address as its key.
func TestFixturesThroughTheStore(t *testing.T) {
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "gateway", name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	nat, err := gateway.ParseNATTable(read("nattable_synthetic.html"))
	if err != nil {
		t.Fatal(err)
	}
	devices, err := gateway.ParseDevices(read("devices_real.html"))
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, at(0, 12, 0), Options{})
	h.devices(at(0, 9, 0), devices...)
	h.natTable(at(0, 10, 0), nat)
	a := h.agg(day0, at(1, 0, 0))
	checkConsistent(t, a)

	laptop := "mac:00:00:5e:00:53:02"
	if f := findFlow(t, a, laptop, "2001:db8:ffff::10", 443, "tcp"); f.Inbound || f.LAN != "2001:db8::100" {
		t.Errorf("the laptop's IPv6 flow = %+v", f)
	}
	findFlow(t, a, laptop, "192.0.2.10", 443, "tcp")
	findFlow(t, a, gatewayKey, "192.0.2.53", 53, "udp")
	findFlow(t, a, "ip:192.168.1.150", "192.0.2.77", 443, "tcp")
	if in := findFlow(t, a, "mac:00:00:5e:00:53:07", "198.51.100.77", 8080, "tcp"); !in.Inbound {
		t.Errorf("the port forward to the thermostat = %+v", in)
	}
	for _, f := range a.Flows {
		if f.Device == gatewayKey && f.Remote != "192.0.2.53" {
			t.Errorf("a session is the gateway's own: %+v", f)
		}
		if f.Remote == "2001:db8::100" {
			t.Errorf("the laptop's address is a remote side: %+v", f)
		}
	}
}
