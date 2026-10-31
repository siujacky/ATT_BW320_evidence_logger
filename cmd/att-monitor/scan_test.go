package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// fakeLANScanner is the scan command's sweeper: it records the gateway address it was made for and
// answers with scan, or err.
type fakeLANScanner struct {
	gateway string
	scan    model.LANScan
	err     error
	sweeps  int
}

func (f *fakeLANScanner) Scan(ctx context.Context) (model.LANScan, error) {
	f.sweeps++
	return f.scan, f.err
}

// useScanner makes the scan command sweep with f.
func useScanner(t *testing.T, f *fakeLANScanner) {
	t.Helper()
	restore := newScanner
	newScanner = func(gateway string) contracts.LANScanner {
		f.gateway = gateway
		return f
	}
	t.Cleanup(func() { newScanner = restore })
}

// testLANScan is a sweep of 192.168.1.0/24 begun 5 minutes before testNow: a device the Device List
// names, this PC, one it lists at another address, one it does not list, one at an address it gives
// to another device that is on, and the gateway (documentation MAC addresses only).
func testLANScan() model.LANScan {
	return model.LANScan{At: ts(-5 * time.Minute), TookMs: 25242, Subnet: "192.168.1.0/24", Self: "192.168.1.71", Asked: 254,
		Hosts: []model.LANHost{
			{IP: "192.168.1.64", MAC: "00:00:5e:00:53:01"},
			{IP: "192.168.1.66", MAC: "00:00:5e:00:53:23"},
			{IP: "192.168.1.71", MAC: "00:00:5e:00:53:71"},
			{IP: "192.168.1.80", MAC: "00:00:5e:00:53:80"},
			{IP: "192.168.1.90", MAC: "00:00:5e:00:53:90"},
			{IP: "192.168.1.254", MAC: "00:00:5e:00:53:fe"},
		}}
}

// scanDevices is the service's Devices view for the scan's names: the laptop (whose name holds a
// terminal escape), the desk PC listed at .67, this PC, and a printer that is on at .90.
func scanDevices() model.NetDevicesView {
	return model.NetDevicesView{From: ts(-time.Hour), To: ts(0), ListAt: ts(-10 * time.Minute), Reads: 4,
		Devices: []model.NetLANDevice{
			{Key: "mac:00:00:5e:00:53:01", Name: "Lap\x1b[2Jtop", MAC: "00:00:5e:00:53:01", IPv4: "192.168.1.64", Status: "on"},
			{Key: "mac:00:00:5e:00:53:23", Name: "desk-pc", MAC: "00:00:5e:00:53:23", IPv4: "192.168.1.67", Status: "on"},
			{Key: "mac:00:00:5e:00:53:71", Name: "this-pc", MAC: "00:00:5e:00:53:71", IPv4: "192.168.1.71", Status: "on"},
			{Key: "mac:00:00:5e:00:53:25", Name: "printer", MAC: "00:00:5e:00:53:25", IPv4: "192.168.1.90", Status: "on"},
			{Key: "mac:00:00:5e:00:53:26", Name: "old-phone", MAC: "00:00:5e:00:53:26", IPv4: "192.168.1.80", Status: "off"},
		}}
}

// scanDataDir is a data directory whose config.json gives the gateway's address and the scan's
// interval (an empty body: the defaults).
func scanDataDir(t *testing.T, connections string) string {
	t.Helper()
	dir := t.TempDir()
	body := `{"version":1,"gateway":{"host":"192.168.1.254"}` + connections + `}`
	if err := os.WriteFile(filepath.Join(dir, config.FileName), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestScanCommand: one sweep of the gateway's network, now; the addresses that answered in address
// order with their MAC addresses, the Device List's names (escaped) and the notes: this PC, the
// gateway, listed at another address, an address the Device List gives another device, not listed.
// Nothing is posted to the service.
func TestScanCommand(t *testing.T) {
	sc := &fakeLANScanner{scan: testLANScan()}
	useScanner(t, sc)
	f := &fakeNetwork{devs: scanDevices()}
	useNetwork(t, f)
	var out strings.Builder
	if err := scanCommand(&out, []string{"--data", scanDataDir(t, "")}); err != nil {
		t.Fatal(err)
	}
	if sc.gateway != "192.168.1.254" || sc.sweeps != 1 {
		t.Errorf("swept %d times for the gateway %q", sc.sweeps, sc.gateway)
	}
	if got := f.requests(); !reflect.DeepEqual(got, []string{"/api/network/devices?limit=1&range=1h"}) {
		t.Errorf("requests %q", got)
	}
	got := out.String()
	if strings.ContainsRune(got, 0x1b) {
		t.Errorf("a terminal escape reached the output:\n%s", got)
	}
	wantText(t, squeeze(got),
		"LAN scan of 192.168.1.0/24 at "+at(ts(-5*time.Minute), "2006-01-02 15:04:05")+" (this PC's local time): 6 addresses answered, of 254 asked, in 25.2 s\n",
		"Names: from the gateway's Device List as read at "+at(ts(-10*time.Minute), "2006-01-02 15:04")+" (through the service)\n",
		" ADDRESS MAC NAME NOTE\n",
		bs(" 192.168.1.64 00:00:5e:00:53:01 Lap~x1b[2Jtop -\n"),
		" 192.168.1.66 00:00:5e:00:53:23 desk-pc the Device List lists it at 192.168.1.67\n",
		" 192.168.1.71 00:00:5e:00:53:71 this-pc this PC\n",
		" 192.168.1.80 00:00:5e:00:53:80 - not in the Device List\n",
		" 192.168.1.90 00:00:5e:00:53:90 - the Device List gives this address to printer (00:00:5e:00:53:25)\n",
		" 192.168.1.254 00:00:5e:00:53:fe - the gateway\n",
		"2 addresses answered with a MAC address the gateway's Device List does not name: perhaps a device with a fixed address",
		"Nothing was stored. The service sweeps every 1h0m0s (connections.scan_interval)",
	)
	if strings.Contains(got, "Problem:") {
		t.Errorf("a problem without one:\n%s", got)
	}
	if i, j := strings.Index(got, "192.168.1.71 "), strings.Index(got, "192.168.1.254 "); i < 0 || j < i {
		t.Errorf("the addresses are not in their order:\n%s", got)
	}
}

// TestScanCommandWithoutNames: without the service (or without its Devices view, or before its first
// Device List read) the sweep is printed without names, and says why; a sweep that stopped short
// says so; the interval shown is config.json's.
func TestScanCommandWithoutNames(t *testing.T) {
	short := testLANScan()
	short.Problem = "the sweep was stopped after 2m0s with 120 of 254 addresses asked: what answered by then is kept"
	for _, tc := range []struct {
		name    string
		service func(t *testing.T)
		want    string
	}{
		{"no service", func(t *testing.T) { noService(t, true) },
			"Names: the service is not running, so the devices are not named"},
		{"an older service", func(t *testing.T) {
			useNetwork(t, &fakeNetwork{fail: http.StatusNotFound, failMsg: "not found"})
		}, "Names: the running service has no Devices view (it is an older version of att-monitor)"},
		{"a service that fails", func(t *testing.T) {
			useNetwork(t, &fakeNetwork{fail: http.StatusServiceUnavailable, failMsg: "the connection store is not open"})
		}, "Names: the devices are not named: the service did not give its Device List (service: the connection store is not open)"},
		{"no Device List read yet", func(t *testing.T) { useNetwork(t, &fakeNetwork{devs: model.NetDevicesView{}}) },
			"Names: the devices are not named: the service has not read the gateway's Device List yet"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useScanner(t, &fakeLANScanner{scan: short})
			tc.service(t)
			var out strings.Builder
			if err := scanCommand(&out, []string{"--data", scanDataDir(t, `,"connections":{"scan_interval":"0s"}`)}); err != nil {
				t.Fatal(err)
			}
			got := squeeze(out.String())
			wantText(t, got, tc.want, "Problem: "+short.Problem+"\n", " 192.168.1.80 00:00:5e:00:53:80 - -\n",
				" 192.168.1.71 00:00:5e:00:53:71 - this PC\n", " 192.168.1.254 00:00:5e:00:53:fe - the gateway\n",
				"Nothing was stored. The service makes no sweeps: connections.scan_interval is 0 in config.json.")
			if strings.Contains(got, "not in the Device List") {
				t.Errorf("without the Device List an address is said not to be in it:\n%s", got)
			}
		})
	}
}

// TestScanCommandJSON: --json prints the sweep as the service keeps it, and asks the service nothing.
func TestScanCommandJSON(t *testing.T) {
	useScanner(t, &fakeLANScanner{scan: testLANScan()})
	f := &fakeNetwork{devs: scanDevices()}
	useNetwork(t, f)
	var out strings.Builder
	if err := scanCommand(&out, []string{"--json", "--data", scanDataDir(t, "")}); err != nil {
		t.Fatal(err)
	}
	var got model.LANScan
	if err := json.Unmarshal([]byte(out.String()), &got); err != nil || !reflect.DeepEqual(got, testLANScan()) {
		t.Errorf("--json: %+v (%v)\n%s", got, err, out.String())
	}
	if n := len(f.requests()); n != 0 {
		t.Errorf("%d requests to the service", n)
	}
}

// TestScanCommandRefusals: a stray argument is refused before anything is swept; a sweep that fails
// is the command's error; without config.json the default gateway address is swept.
func TestScanCommandRefusals(t *testing.T) {
	sc := &fakeLANScanner{scan: testLANScan()}
	useScanner(t, sc)
	noService(t, false)
	if err := scanCommand(&strings.Builder{}, []string{"now"}); err == nil || !strings.Contains(err.Error(), scanUsage) || sc.sweeps != 0 {
		t.Errorf("a stray argument: %v, %d sweeps", err, sc.sweeps)
	}
	if err := scanCommand(&strings.Builder{}, []string{"--range", "1h"}); err == nil || sc.sweeps != 0 {
		t.Errorf("an unknown flag: %v, %d sweeps", err, sc.sweeps)
	}
	failing := errors.New("lanscan: the gateway's network 10.0.0.0/16 holds 65536 addresses: at most 1024 (a /22) are swept")
	sc.err = failing
	if err := scanCommand(&strings.Builder{}, []string{"--data", t.TempDir()}); !errors.Is(err, failing) || sc.gateway != config.Default().Gateway.Host {
		t.Errorf("a sweep that fails: %v; swept %q", err, sc.gateway)
	}
}
