package web

// The Network page's Devices tab (docs/dhcp-table.md §3) as the dashboard shows it, driven in
// testdata/dashboard_harness.js against the demo world: the gateway's Device List with its issues,
// the find box and its address panel, the sorting, a device's details in the dashboard's details
// modal (opened and closed every way a reader does it, the address naming them, the keyboard
// focus going back to the row), the states the tab explains, the Overview's Network card that
// counts the devices, and the tab's helpers run under Node.js.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// devicesState is where the page is at a step of the harness's devicesSteps: the address, the
// history, the keyboard focus, whether a device's details are open (and their title), whether the
// page behind is locked and how many modal dialogs are open.
type devicesState struct {
	Hash   string `json:"hash"`
	Length int    `json:"length"`
	Index  int    `json:"index"`
	Focus  string `json:"focus"`
	Open   bool   `json:"open"`
	Locked bool   `json:"locked"`
	Modals int    `json:"modals"`
	Title  string `json:"title"`
}

// deviceRows returns the devices of the DHCP table of a view, in their order: the name of each
// row that starts with its status ("on" or "off") and holds an IPv4 address.
func deviceRows(v dashboardView) (names []string, chips map[string][]string) {
	re := regexp.MustCompile(`^(on|off)(.+?)(192\.168\.1\.\d+)`)
	chips = map[string][]string{}
	for _, r := range v.Rows {
		if m := re.FindStringSubmatch(r.Text); m != nil {
			names = append(names, m[2])
			chips[m[2]] = r.Chips
		}
	}
	return names, chips
}

// devicesServer serves w for the Devices tab's tests on an ephemeral port (each of mods changes the
// server first): the dashboard, /demo/network?state=... and /demo/syslog?state=... (the Network
// page's state and the gateway syslog's, as TestDemoServer's), and /demo/devlog?addr=... (a syslog
// message naming an address, received now). Returns the base URL.
func devicesServer(t *testing.T, w *demoWorld, mods ...func(*Server)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newDemoServerOn(t, w, ln.Addr().String(), nil)
	for _, mod := range mods {
		mod(srv)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/demo/network", func(rw http.ResponseWriter, r *http.Request) {
		w.mu.Lock()
		w.netState = r.URL.Query().Get("state")
		w.mu.Unlock()
		fmt.Fprintln(rw, "ok")
	})
	mux.HandleFunc("/demo/syslog", func(rw http.ResponseWriter, r *http.Request) {
		w.mu.Lock()
		w.syslogState = r.URL.Query().Get("state")
		w.mu.Unlock()
		fmt.Fprintln(rw, "ok")
	})
	mux.HandleFunc("/demo/devlog", func(rw http.ResponseWriter, r *http.Request) {
		now := time.Now()
		w.mu.Lock()
		w.appendSyslogLocked(now, 0, demoSyslog(now, 3, 4, "upnpd", "refused a port mapping request from "+r.URL.Query().Get("addr")+": external port 3080 in use", false))
		w.mu.Unlock()
		fmt.Fprintln(rw, "ok")
	})
	mux.Handle("/", srv.Handler())
	hs := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go hs.Serve(ln)
	t.Cleanup(func() { hs.Close() })
	return "http://" + ln.Addr().String()
}

// demoKey is the device key of the demo's Device List entry named name.
func demoKey(t *testing.T, name string) string {
	t.Helper()
	for _, d := range demoLAN {
		if d.name == name {
			return d.key
		}
	}
	t.Fatalf("the demo's Device List has no %q", name)
	return ""
}

// TestDashboardDevicesTab uses the Devices tab as a reader does (the harness's devicesSteps): the
// tab as it first shows - the tiles, the table in its own order (the critical issues first, then
// the warnings, the devices that are off last), each issue as a chip in its tone, the unknown
// addresses, where the figures come from -, the find box (a name, IPv4 addresses with the address
// panel, a MAC address with dashes, a part of an IPv6 address), the sort by columns, every way of
// opening and closing a device's details, their content and links, a link to another device's
// details, a refresh while they are open, and a period chosen with the find box holding text.
func TestDashboardDevicesTab(t *testing.T) {
	requireNode(t)
	w := newDemoWorld(time.Now())
	rep := checkedHarness(t, devicesServer(t, w), "devices")
	contains := viewChecker(t, rep)

	contains("devices", "Which device talks to which site, what the gateway’s firewall blocks, and which device has which address.",
		"Device List last read ", " · every 15 min",
		"Devices listed16", "13 on, 3 off", "Wi-Fi / Ethernet12 / 4", "of the devices listed", "With issues8", "5 devices and 3 unknown addresses · 2 critical",
		"Unknown addresses3", "seen, but not in the Device List",
		"LAN scan ", " of 254 addresses of 192.168.1.0/24 answered", " · next ", "Scan",
		"Device List", "The gateway’s DHCP table: which device has which address, as its newest read shows it. Devices with issues first.",
		"Showing all 16 devices of the Device List.",
		"Unknown addresses", "192.168.1.90", "192.168.1.201", "Not in the list",
		"No Device List read of this period names 192.168.1.90, yet the NAT table showed its connections",
		"No Device List read of this period names 192.168.1.201, yet the gateway's firewall dropped ",
		"Where this comes from", "read every 15 min without logging in to the gateway", "The gateway does not show when an address’s lease runs out, so no lease time is shown.",
		"This is not evidence", "kept for 30 days")
	v := rep.Views["devices"]
	names, chips := deviceRows(v)
	// The service's order: critical, warning, the others; on before off; by name.
	want := []string{"Printer", "Security camera", "Game console", "Office PC", "Smart speaker", "Doorbell", "Kids tablet", "Laptop", "Living room TV",
		"NAS", "Phone", "Tablet", "Thermostat", "E-reader", "Guest phone", "Work laptop"}
	if !slices.Equal(names, want) {
		t.Errorf("the table's own order:\n got %q\nwant %q", names, want)
	}
	for name, c := range map[string][]string{
		"Printer": {"critical:Address conflict", "warning:MAC mismatch", "info:No scan answer"}, "Security camera": {"critical:Address conflict"}, "Game console": {"warning:Slow link"},
		"Smart speaker": {"warning:Weak Wi-Fi"}, "Office PC": {"warning:Blocked packets"}, "Laptop": {"info:New address"},
		"Tablet": {"info:No scan answer"}, "Doorbell": {"info:Other address"},
		"NAS": nil, "Guest phone": nil, "E-reader": nil, // off is the status column's, not a chip
	} {
		if !slices.Equal(chips[name], c) {
			t.Errorf("%s's chips: %q, want %q", name, chips[name], c)
		}
	}
	for _, r := range v.Rows {
		switch {
		case strings.HasPrefix(r.Text, "onPrinter") && !strings.Contains(r.Text, "Wi-Fi 2.4 GHz3/5"):
			t.Errorf("the printer's row has no Wi-Fi signal: %q", r.Text)
		case strings.HasPrefix(r.Text, "onLaptop") && !strings.Contains(r.Text, "also had 192.168.1.80"):
			t.Errorf("the laptop's row does not say the address it had before: %q", r.Text)
		case strings.HasPrefix(r.Text, "onGame console") && !strings.Contains(r.Text, "10Mbps halfduplex"):
			t.Errorf("the game console's row does not give its link's speed: %q", r.Text)
		case strings.HasPrefix(r.Text, "offGuest phone") && strings.Contains(r.Text, "now"):
			t.Errorf("the guest phone, off, is seen on now: %q", r.Text)
		case strings.HasPrefix(r.Text, "onDoorbell") && !regexp.MustCompile(`answered \d{1,2}:\d{2}.*at 192\.168\.1\.77`).MatchString(r.Text):
			t.Errorf("the doorbell's row does not say where it answered the scan: %q", r.Text)
		case strings.HasPrefix(r.Text, "onTablet") && !strings.Contains(r.Text, "no answer"):
			t.Errorf("the tablet's row does not say that it did not answer the scan: %q", r.Text)
		case strings.HasPrefix(r.Text, "onPrinter") && !strings.Contains(r.Text, "no answerlast "):
			t.Errorf("the printer's row does not say when it last answered the scan: %q", r.Text)
		case strings.HasPrefix(r.Text, "onOffice PC") && !regexp.MustCompile(`answered \d{1,2}:\d{2}`).MatchString(r.Text):
			t.Errorf("the office PC's row: %q", r.Text)
		}
	}

	// The find box: a name; an IPv4 address held now and by another device before (a reused
	// address), one two devices claim (written with leading zeros), one nobody held, one only the
	// NAT table saw; a MAC address written with dashes; a part of an IPv6 address; nothing.
	contains("devices find name", "1 of 16 devices match.")
	contains("devices find ipv4", "Address 192.168.1.80", "No device that is on has it in the newest read of the Device List. Guest phone is off, but still listed with it.",
		"In this period (last 24 hours):", "Laptop 00:00:5e:00:53:02 · ", "Guest phone 00:00:5e:00:53:0b · ", " – now · ", "2 of 16 devices match.")
	if text := rep.Views["devices find ipv4"].Text; strings.Index(text, "Laptop 00:00:5e:00:53:02") > strings.Index(text, "Guest phone 00:00:5e:00:53:0b") {
		t.Error("the address panel does not list who held 192.168.1.80 in the order they held it")
	}
	contains("devices find conflict", "Address 192.168.1.68", "Address conflict Printer and Security camera both claim it in the newest read of the Device List.",
		"Security camera 00:00:5e:00:53:0a · ", "2 of 16 devices match.")
	contains("devices find nobody", "Address 192.168.1.99", "No device has it in the newest read of the Device List.",
		"No Device List read of this period shows a device with it.", "0 of 16 devices match.")
	contains("devices find unknown", "Address 192.168.1.90", "Not in the list No Device List read of this period names 192.168.1.90, yet the NAT table showed its connections",
		" LAN scans of this period (from 00:00:5e:00:53:20). Perhaps a device with a fixed address, which the gateway does not list. Its details")
	if names, _ := deviceRows(rep.Views["devices find mac"]); !slices.Equal(names, []string{"Security camera"}) {
		t.Errorf("a MAC address with dashes finds %q", names)
	}
	if names, _ := deviceRows(rep.Views["devices find ipv6"]); !slices.Equal(names, []string{"Laptop"}) {
		t.Errorf("a part of an IPv6 address finds %q", names)
	}
	contains("devices find none", "No device of the Device List matches.", "0 of 16 devices match.", "No unknown address matches.")
	for _, name := range []string{"devices find name", "devices find mac", "devices find none"} {
		if strings.Contains(rep.Views[name].Text, "Address 192.168.1.") {
			t.Errorf("%s: an address panel without an IPv4 address in the find box", name)
		}
	}

	// The sort: by name, by IPv4 address, by when last seen on (the newest first), by status.
	for view, first := range map[string]string{"devices sort Name": "Doorbell", "devices sort IPv4": "NAS", "devices sort Last seen on": "Printer", "devices sort Status": "Printer"} {
		if names, _ := deviceRows(rep.Views[view]); len(names) != 16 || names[0] != first {
			t.Errorf("%s: %q, want %s first", view, names, first)
		}
	}
	if names, _ := deviceRows(rep.Views["devices sort Name"]); names[len(names)-1] != "Work laptop" {
		t.Errorf("sorted by name: %q", names)
	}
	if names, _ := deviceRows(rep.Views["devices sort Last seen on"]); len(names) != 16 || !slices.Equal(names[13:], []string{"Guest phone", "E-reader", "Work laptop"}) {
		t.Errorf("sorted by when last seen on: %q", names)
	}
	if names, _ := deviceRows(rep.Views["devices sorted back"]); !slices.Equal(names, want) {
		t.Errorf("sorted by issues again: %q", names)
	}

	var facts struct {
		FindHash    string `json:"findHash"`
		FindFocus   string `json:"findFocus"`
		ClearedHash string `json:"clearedHash"`
		Steps       []struct {
			Name   string       `json:"name"`
			How    string       `json:"how"`
			Close  string       `json:"close"`
			Before devicesState `json:"before"`
			Opened devicesState `json:"opened"`
			After  devicesState `json:"after"`
		} `json:"steps"`
		Links [][2]string `json:"links"`
		Link  struct {
			Found  bool         `json:"found"`
			After  devicesState `json:"after"`
			Back   devicesState `json:"back"`
			Closed devicesState `json:"closed"`
		} `json:"link"`
		Refresh struct {
			SameDialog  bool   `json:"sameDialog"`
			FocusBefore string `json:"focusBefore"`
			Focus       string `json:"focus"`
			Hash        string `json:"hash"`
		} `json:"refresh"`
		Period struct {
			Hash string `json:"hash"`
			Find string `json:"find"`
		} `json:"period"`
	}
	if err := json.Unmarshal(rep.Facts["devices"], &facts); err != nil {
		t.Fatalf("devices: %s (%v)", rep.Facts["devices"], err)
	}
	// The find box's text is in the address (a link with it finds the same), and goes when cleared.
	if facts.FindHash != "#/network/devices?range=24h&q=no+such+device" || facts.ClearedHash != "#/network/devices?range=24h" || facts.FindFocus != "input:" {
		t.Errorf("the find box in the address: %q, cleared %q, focus %q", facts.FindHash, facts.ClearedHash, facts.FindFocus)
	}

	// Each way of opening a device's details (Enter, Space, a click on its name, on its row) and of
	// closing them (Esc, the close button, the backdrop, Back): open, the address names them in a new
	// history entry, the focus is on Close and the page behind is locked; closed, the address and the
	// history are as before, and the focus is back on the row's name.
	if len(facts.Steps) != 4 {
		t.Fatalf("%d steps: %s", len(facts.Steps), rep.Facts["devices"])
	}
	hows, closes := map[string]bool{}, map[string]bool{}
	for _, s := range facts.Steps {
		b, o, a := s.Before, s.Opened, s.After
		hows[s.How], closes[s.Close] = true, true
		wantHash := "#/network/devices?range=24h&detail=" + url.QueryEscape(demoKey(t, s.Name))
		if o.Hash != wantHash || o.Index != b.Index+1 || o.Length != b.Index+2 || o.Focus != "button:Close" || !o.Open || !o.Locked || o.Modals != 1 || o.Title != s.Name {
			t.Errorf("%s opened with %s: %+v (before: %+v)", s.Name, s.How, o, b)
		}
		if a.Hash != b.Hash || a.Index != b.Index || a.Focus != "button:"+s.Name || a.Open || a.Locked || a.Modals != 0 {
			t.Errorf("%s closed with %s: %+v (before it opened: %+v)", s.Name, s.Close, a, b)
		}
		d := rep.Views["device "+s.Name].Detail
		if d == nil || d.Key != "device" || !d.Open || d.Title != s.Name || !strings.HasSuffix(d.Context, " · Last 24 hours · updates while open") ||
			d.Body == nil || d.Body.Tabindex != "0" || d.Body.Role != "region" {
			t.Errorf("%s's details: %+v", s.Name, d)
		}
	}
	for _, how := range []string{"enter", "space", "click", "row"} {
		if !hows[how] {
			t.Errorf("no details opened with %s", how)
		}
	}
	for _, c := range []string{"escape", "close", "backdrop", "back"} {
		if !closes[c] {
			t.Errorf("no details closed with %s", c)
		}
	}

	// The details: the issues with their sentences (and what helps), the device as the gateway lists
	// it, its addresses and the others that held them, its connections, blocked packets and syslog.
	detail := func(name string, wants ...string) {
		t.Helper()
		d := rep.Views["device "+name].Detail
		if d == nil {
			t.Errorf("no details of %s", name)
			return
		}
		for _, s := range wants {
			if !strings.Contains(d.Text, s) {
				t.Errorf("%s's details do not show %q", name, s)
			}
		}
	}
	detail("Printer", "On · 192.168.1.68 · Wi-Fi 2.4 GHz · Last 24 hours", "Issues", "Address conflict 192.168.1.68 is also claimed by Security camera (00:00:5e:00:53:0a)",
		"Give one of them another address", "The device", "MAC address00:00:5e:00:53:06", "IPv4 address192.168.1.68",
		"AllocationDHCP — the gateway gave it the address", "ConnectionWi-Fi 2.4 GHz · signal 3 of 5 bars", "Last activity", "(as the gateway shows it)",
		"Device List readson in ", "Addresses in this period", "Others who held them", "Security camera", "may be counted for the other one",
		"Open connections", " in the newest read of the NAT table", "Sites", "Show its connections on the Connections tab", "Blocked packets", "Open the Firewall tab",
		"Syslog", "Messages that name 192.168.1.68", "Not evidence.")
	detail("Laptop", "New address It held 2 IPv4 addresses in this period, the newest first: 192.168.1.64, 192.168.1.80.", "IPv6 addresses2001:db8:4c2:7a10:5a3c:e11f:902b:64d0",
		"Others who held themAddressDeviceHeld192.168.1.80Guest phone", "Messages that name 192.168.1.64", "Messages that name 192.168.1.80")
	detail("Smart speaker", "Weak Wi-Fi Its Wi-Fi signal is weak: the gateway draws it with 2 bars of 5 (Wi-Fi 2.4 GHz).", "Mesh clientyes — connected through a Wi-Fi extender", "No other device held its addresses")
	detail("Game console", "Slow link Its Ethernet link runs at 10 Mb/s, half duplex (the gateway shows \"10Mbps halfduplex\")", "damaged cable", "Link speed10Mbps halfduplex", "ConnectionEthernet LAN-3")
	for _, l := range [][2]string{
		{"Security camera", "#/network/devices?range=24h&detail=" + url.QueryEscape(demoKey(t, "Security camera"))},
		{"Show its connections on the Connections tab", "#/network?range=24h&device=" + url.QueryEscape(demoKey(t, "Printer"))},
		{"Open the Firewall tab", "#/network/firewall?range=24h"},
		{"Messages that name 192.168.1.68 on the Syslog page", "#/syslog?q=192.168.1.68"},
	} {
		if !slices.Contains(facts.Links, l) {
			t.Errorf("the printer's details have no link %q to %s: %q", l[0], l[1], facts.Links)
		}
	}
	// The details read from the service (GET /api/network/device): the LAN scans as the device
	// answered them, and its syslog messages, found by its addresses and its MAC address.
	detail("Printer", "LAN scans", "Last answered", " scans of this period", " — no answer", "Syslog", "Found by ", "00:00:5e:00:53:06",
		"Messages that name 192.168.1.68 on the Syslog page")
	if d := rep.Views["device Printer"].Detail; d != nil && !strings.Contains(d.Text, " name it in this period, newest first.") &&
		!strings.Contains(d.Text, "No syslog message of this period names it.") && !strings.Contains(d.Text, "The newest ") {
		t.Errorf("the printer's syslog messages: %q", d.Text)
	}
	detail("Laptop", "Found by 192.168.1.64 (since ", "192.168.1.80 (until ", "2001:db8:4c2:7a10:5a3c:e11f:902b:64d0", " and 00:00:5e:00:53:02.")
	for _, path := range []string{"/api/network/device?range=24h&key=" + url.QueryEscape(demoKey(t, "Printer")) + "&limit=100",
		"/api/network/device?range=24h&addr=192.168.1.50&limit=100"} {
		if !requested(rep, "GET", path) {
			t.Errorf("the details did not ask for %s", path)
		}
	}
	// An unknown address's details: opened from its row's address, the address naming them; closed,
	// the focus back on it.
	var unk struct {
		Unknown struct {
			Before, Opened, After devicesState
		} `json:"unknown"`
	}
	if err := json.Unmarshal(rep.Facts["devices"], &unk); err != nil {
		t.Fatal(err)
	}
	if u := unk.Unknown; u.Opened.Hash != "#/network/devices?range=24h&detail="+url.QueryEscape("addr:192.168.1.50") || !u.Opened.Open ||
		u.Opened.Title != "Address 192.168.1.50" || u.After.Hash != u.Before.Hash || u.After.Focus != "button:192.168.1.50" || u.After.Open {
		t.Errorf("an unknown address's details: %+v", u)
	}
	if d := rep.Views["device unknown"].Detail; d == nil || d.Title != "Address 192.168.1.50" ||
		!strings.HasPrefix(d.Context, "Not in the Device List · MAC 00:00:5e:00:53:21 · Last 24 hours") {
		t.Errorf("the unknown address's details: %+v", d)
	}
	contains("device unknown", "Not in the list No Device List read of this period names 192.168.1.50, yet it answered ",
		" LAN scans of this period (from 00:00:5e:00:53:21). Perhaps a device with a fixed address, which the gateway does not list.",
		"MAC address00:00:5e:00:53:21 — what answered for it in the LAN scan", "In the Device Listno read of this period names it", "Who held it",
		"No device of the Device List held it in this period.", "LAN scans", " — answered at 192.168.1.50", "Syslog", "Found by 192.168.1.50.",
		"Messages that name 192.168.1.50 on the Syslog page")

	// The link to the other device of the conflict opens its details (an address, as any link);
	// Back opens the printer's again; closed, they leave the tab's address.
	l := facts.Link
	if !l.Found || l.After.Title != "Security camera" || !l.After.Open || l.Back.Title != "Printer" || !l.Back.Open ||
		l.Closed.Hash != "#/network/devices?range=24h" || l.Closed.Open || l.Closed.Focus != "button:Printer" {
		t.Errorf("the link to the security camera's details: %s", rep.Facts["devices"])
	}
	contains("device linked", "Address conflict 192.168.1.68 is also claimed by Printer (00:00:5e:00:53:06)")
	// The page's refresh every minute while the details are open: the same dialog, the focus kept.
	if r := facts.Refresh; !r.SameDialog || r.Focus != r.FocusBefore || r.Focus != "a:Show its connections on the Connections tab" ||
		r.Hash != "#/network/devices?range=24h&detail="+url.QueryEscape(demoKey(t, "Laptop")) {
		t.Errorf("the details across a refresh: %+v", r)
	}
	// Another period keeps the find box's text, in the field and in the address.
	if p := facts.Period; p.Hash != "#/network/devices?range=7d&q=laptop" || p.Find != "laptop" {
		t.Errorf("a period chosen: %+v", p)
	}
	contains("devices 7d", "2 of 16 devices match.") // the laptop and the work laptop
	if r := rep.Views["devices 7d"].Radios; !slices.Equal(r, []string{"7d"}) {
		t.Errorf("the period checked after choosing 7 days: %q", r)
	}

	// What the tab asked for: the Device List of each period, with as many unknown addresses as an
	// answer holds.
	for _, path := range []string{"/api/network/devices?range=24h&limit=1000", "/api/network/devices?range=7d&limit=1000", "/api/network/status"} {
		if !requested(rep, "GET", path) {
			t.Errorf("the tab did not ask for %s", path)
		}
	}
	for _, r := range rep.Requests {
		if strings.HasPrefix(r.Path, "/api/network/") && r.Status != 200 {
			t.Errorf("%s %s answered %d", r.Method, r.Path, r.Status)
		}
	}
}

// TestDashboardDevicesDeepLink loads the page at a device's details (#/network/devices?range=24h&
// detail=<key>, as a link or a reload does): they open once the devices are read, the address
// still naming them, the focus on their close button; closed, they replace the address with the
// tab's (the history keeps no entry of them) and the focus goes to the device's row.
func TestDashboardDevicesDeepLink(t *testing.T) {
	requireNode(t)
	w := newDemoWorld(time.Now())
	hash := "#/network/devices?range=24h&detail=" + url.QueryEscape(demoKey(t, "Printer"))
	rep := checkedHarness(t, devicesServer(t, w), "devicesdeep", "HARNESS_HASH="+hash)
	var deep struct {
		Opened, Closed struct {
			Hash   string `json:"hash"`
			Length int    `json:"length"`
			Index  int    `json:"index"`
			Focus  string `json:"focus"`
			Open   bool   `json:"open"`
		}
	}
	if err := json.Unmarshal(rep.Facts["devicesDeep"], &deep); err != nil {
		t.Fatalf("devicesDeep: %s (%v)", rep.Facts["devicesDeep"], err)
	}
	if o := deep.Opened; o.Hash != hash || o.Length != 1 || o.Index != 0 || o.Focus != "button:Close" || !o.Open {
		t.Errorf("loaded at the printer's details: %+v", o)
	}
	if d := rep.Views["devices deep"].Detail; d == nil || d.Key != "device" || d.Title != "Printer" || !d.Open || !rep.Views["devices deep"].Locked {
		t.Errorf("the details the address names: %+v", d)
	}
	if c := deep.Closed; c.Hash != "#/network/devices?range=24h" || c.Length != 1 || c.Index != 0 || c.Focus != "button:Printer" || c.Open {
		t.Errorf("closed, the details replace the address: %+v", c)
	}
	if v := rep.Views["devices deep closed"]; v.Detail != nil || v.Locked {
		t.Errorf("closed: details %+v, scroll locked %v", v.Detail, v.Locked)
	}
}

// syslogQueryFail is the demo world's syslog store, whose messages cannot be read.
type syslogQueryFail struct{ *demoWorld }

func (syslogQueryFail) Query(context.Context, time.Time, time.Time, func(*model.SyslogMessage) bool, int) ([]model.SyslogEntry, bool, error) {
	return nil, false, errors.New("syslog: read chunk syslog-20261030-0100.jsonl.gz: The disk is full")
}

// TestDashboardDeviceSyslogStates: a device's details when the service read the device but not its
// syslog messages (syslog_error: why, in a warning, with the rest of the details and the link to
// the Syslog page as usual), when this att-monitor keeps no syslog store (a plain sentence, and no
// link to a Syslog page that has nothing to show), and when the syslog_chunk records read for its
// messages did not check out (the integrity warning, as the Syslog page gives it).
func TestDashboardDeviceSyslogStates(t *testing.T) {
	requireNode(t)
	hash := "#/network/devices?range=24h&detail=" + url.QueryEscape(demoKey(t, "Printer"))
	w := newDemoWorld(time.Now())
	rep := checkedHarness(t, devicesServer(t, w, func(s *Server) { s.syslog = syslogQueryFail{w} }), "devicesdeep", "HARNESS_HASH="+hash)
	d := rep.Views["devices deep"].Detail
	if d == nil || d.Title != "Printer" {
		t.Fatalf("the printer's details: %+v", d)
	}
	for _, want := range []string{"Address conflict", "LAN scans", "Answered",
		"The syslog messages could not be read: syslog: read chunk syslog-20261030-0100.jsonl.gz: The disk is full.",
		"Found by 192.168.1.68 and 00:00:5e:00:53:06.", "Messages that name 192.168.1.68 on the Syslog page"} {
		if !strings.Contains(d.Text, want) {
			t.Errorf("the details, the syslog unreadable, lack %q: %q", want, d.Text)
		}
	}
	if strings.Contains(d.Text, "No syslog message of this period names it") {
		t.Errorf("the details say no message names it, though none could be read: %q", d.Text)
	}

	w = newDemoWorld(time.Now())
	w.mu.Lock()
	w.netState = "nosyslog"
	w.mu.Unlock()
	rep = checkedHarness(t, devicesServer(t, w, func(s *Server) { s.syslog = nil }), "devicesdeep", "HARNESS_HASH="+hash)
	d = rep.Views["devices deep"].Detail
	if d == nil || d.Title != "Printer" {
		t.Fatalf("the printer's details without a syslog store: %+v", d)
	}
	if want := "This att-monitor keeps no syslog store, so it has no syslog messages to show."; !strings.Contains(d.Text, want) {
		t.Errorf("the details without a syslog store lack %q: %q", want, d.Text)
	}
	for _, not := range []string{"on the Syslog page", "could not be read", "No syslog message of this period"} {
		if strings.Contains(d.Text, not) {
			t.Errorf("the details without a syslog store show %q: %q", not, d.Text)
		}
	}
	if !requested(rep, "GET", "/api/network/device?range=24h&key="+url.QueryEscape(demoKey(t, "Printer"))+"&limit=100") {
		t.Error("the details did not read the printer's details")
	}

	// The integrity warning of the records read (WarningHeader), added to the service's answer.
	w = newDemoWorld(time.Now())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := newDemoServerOn(t, w, ln.Addr().String(), nil).Handler()
	hs := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/network/device" {
			rw.Header().Set(WarningHeader, "#2219 syslog_chunk data does not parse")
		}
		h.ServeHTTP(rw, r)
	})}
	go hs.Serve(ln)
	t.Cleanup(func() { hs.Close() })
	rep = checkedHarness(t, "http://"+ln.Addr().String(), "devicesdeep", "HARNESS_HASH="+hash)
	d = rep.Views["devices deep"].Detail
	if want := "Integrity problem in the syslog_chunk records read. #2219 syslog_chunk data does not parse Run Verify"; d == nil || !strings.Contains(d.Text, want) {
		t.Errorf("the details lack the integrity warning %q: %+v", want, d)
	} else if !strings.Contains(d.Text, " name it in this period, newest first.") {
		t.Errorf("the details with the integrity warning do not list the messages: %q", d.Text)
	}
}

// devicesFix is what the harness's devicesFixScenario notes.
type devicesFix struct {
	OnOff, OffOff, ScanOnly, Named devicesPanel
	UnknownByMAC                   []string          `json:"unknownByMAC"`
	UnknownByMACDots               []string          `json:"unknownByMACDots"`
	NamedFocus                     string            `json:"namedFocus"`
	ScanCells                      map[string]string `json:"scanCells"`
	StaleCells                     map[string]string `json:"staleCells"`
	StaleLine                      string            `json:"staleLine"`
	Scroll                         struct {
		Same         bool `json:"same"`
		Left         int  `json:"left"`
		UnknownLeft  int  `json:"unknownLeft"`
		UnknownFound bool `json:"unknownFound"`
		UnknownNew   bool `json:"unknownNew"`
	} `json:"scroll"`
	Datagram *struct {
		Key    string   `json:"key"`
		Keys   []string `json:"keys"`
		Unique bool     `json:"unique"`
		During struct {
			Kept     bool `json:"kept"`
			Messages int  `json:"messages"`
		} `json:"during"`
		After struct {
			Redrawn  bool     `json:"redrawn"`
			Messages int      `json:"messages"`
			Open     []string `json:"open"`
			Top      string   `json:"top"`
			TopOpen  bool     `json:"topOpen"`
		} `json:"after"`
	} `json:"datagram"`
	MissingDevice struct {
		Text string `json:"text"`
		Open bool   `json:"open"`
	} `json:"missingDevice"`
	MissingAddress struct {
		Text string `json:"text"`
		Open bool   `json:"open"`
	} `json:"missingAddress"`
	MissingAfterOpen string `json:"missingAfterOpen"`
}

// devicesPanel is the address panel as the harness reads it: its text, the keys of what it holds
// (data-fk), whether they are unique, and the page's live region after the search.
type devicesPanel struct {
	Text   string   `json:"text"`
	Keys   []string `json:"keys"`
	Unique bool     `json:"unique"`
	Live   string   `json:"live"`
}

// TestDashboardDevicesFixes uses the Devices tab where a review found it wanting (the harness's
// devicesFixScenario): an entry that is off claims no address in the address panel (with one
// that is on, with another that is off), and the panel's keys are unique; an unknown address is
// described in the service's words (one only the scans saw; one a MAC address no read names
// answered for, which the reads give to devices of the list - in the panel and in its details);
// the unknown addresses are found by their MAC address; the Scan column gives the scan's time, and
// compares nothing with a scan too old to compare; the tab and a device's details say what the
// syslog kept does not show (the gateway sending its log elsewhere, the receiver off, the syslog
// kept starting after the period does); the tables keep their sideways scroll across the refresh;
// a message's opened datagram stays with it when a newer one arrives, and a refresh while text is
// selected in the details is drawn once the selection is gone; details a link names that the
// period does not have are said to be missing; a single site is "1 remote address".
func TestDashboardDevicesFixes(t *testing.T) {
	requireNode(t)
	w := newDemoWorld(time.Now())
	rep := checkedHarness(t, devicesServer(t, w), "devicesfix")
	var f devicesFix
	if err := json.Unmarshal(rep.Facts["devicesFix"], &f); err != nil {
		t.Fatalf("devicesFix: %s (%v)", rep.Facts["devicesFix"], err)
	}
	pcKey, wlKey := demoKey(t, "Office PC"), demoKey(t, "Work laptop")
	contains := func(what, text string, wants ...string) {
		t.Helper()
		for _, want := range wants {
			if !strings.Contains(text, want) {
				t.Errorf("%s lacks %q: %q", what, want, text)
			}
		}
	}
	lacks := func(what, text string, nots ...string) {
		t.Helper()
		for _, not := range nots {
			if strings.Contains(text, not) {
				t.Errorf("%s shows %q: %q", what, not, text)
			}
		}
	}

	// An entry that is off claims no address: the panel names no conflict.
	contains("the panel of an address an entry on and one off are listed with", f.OnOff.Text,
		"Office PC has it in the newest read of the Device List. Work laptop is off, but still listed with it: the gateway keeps a device that left in its list, which is no address conflict.")
	lacks("the panel of an address an entry on and one off are listed with", f.OnOff.Text, "Address conflict", "claim it")
	contains("the words announced for it", f.OnOff.Live, "192.168.1.71: Office PC has it now. Work laptop (off) is still listed with it.")
	contains("the panel of an address two entries off are listed with", f.OffOff.Text,
		"No device that is on has it in the newest read of the Device List. E-reader and Guest phone are off, but still listed with it: the gateway keeps devices that left in its list, which is no address conflict.")
	lacks("the panel of an address two entries off are listed with", f.OffOff.Text, "Address conflict", "claim it")
	contains("the words announced for it", f.OffOff.Live, "192.168.1.80: no device that is on has it now. E-reader and Guest phone (off) are still listed with it.")
	// A device named in the sentence and in the history has a key for each.
	if !f.OnOff.Unique || !slices.Contains(f.OnOff.Keys, "net-devs:panel:now:0:"+pcKey) || !slices.Contains(f.OnOff.Keys, "net-devs:panel:off:0:"+wlKey) ||
		!slices.ContainsFunc(f.OnOff.Keys, func(k string) bool {
			return strings.HasPrefix(k, "net-devs:panel:held:") && strings.HasSuffix(k, ":"+pcKey)
		}) {
		t.Errorf("the panel's keys: %q", f.OnOff.Keys)
	}
	if !f.OffOff.Unique || !f.ScanOnly.Unique || !f.Named.Unique {
		t.Errorf("the panels' keys are not unique: %q, %q, %q", f.OffOff.Keys, f.ScanOnly.Keys, f.Named.Keys)
	}

	// An unknown address in the service's words: one only the scans saw.
	contains("the panel of an address only the scans saw", f.ScanOnly.Text,
		"Not in the list No Device List read of this period names 192.168.1.50, yet it answered ",
		" LAN scans of this period (from 00:00:5e:00:53:21). Perhaps a device with a fixed address, which the gateway does not list. Its details")
	lacks("the panel of an address only the scans saw", f.ScanOnly.Text, "NAT table saw it", "firewall saw it", "see Unknown addresses below")
	if !slices.Equal(f.UnknownByMAC, []string{"192.168.1.50"}) || !slices.Equal(f.UnknownByMACDots, []string{"192.168.1.50"}) {
		t.Errorf("the unknown addresses found by a MAC address: %q, %q", f.UnknownByMAC, f.UnknownByMACDots)
	}
	// One a MAC address no read names answered for, which the reads give to the Laptop, then the
	// Guest phone (off, and still listed with it).
	contains("the panel of an address the reads give to others", f.Named.Text,
		"No device that is on has it in the newest read of the Device List. Guest phone is off, but still listed with it.",
		"Not in the list 192.168.1.80 answered ",
		" LAN scans of this period from 00:00:5e:00:53:23, which no Device List read of this period names (the reads give the address to another device).")
	lacks("the panel of an address the reads give to others", f.Named.Text, "No Device List read of this period names 192.168.1.80")
	d := rep.Views["devices fix named"].Detail
	if d == nil || d.Title != "Address 192.168.1.80" || !strings.HasPrefix(d.Context, "Its MAC address is in no Device List read · MAC 00:00:5e:00:53:23 · ") {
		t.Fatalf("the details of the address the reads give to others: %+v", d)
	}
	contains("its details", d.Text, "In the Device Listreads of this period give it to Laptop and Guest phone; the MAC address that answered for it, 00:00:5e:00:53:23, is in none of them",
		"Answered a LAN scan from a MAC address that no read of the gateway’s Device List names.")
	lacks("its details", d.Text, "no read of this period names it")
	if f.NamedFocus != "button:Its details" {
		t.Errorf("closed, the focus is on %q, not on the panel's link to them", f.NamedFocus)
	}

	// The Scan column: the scan's time; with a scan too old to compare, no device without an answer
	// is said to have given none.
	answered := regexp.MustCompile(`^answered \d{1,2}:\d{2}`)
	if c := f.ScanCells; !answered.MatchString(c["Office PC"]) || !answered.MatchString(c["Doorbell"]) || !strings.HasSuffix(c["Doorbell"], "at 192.168.1.77") ||
		!strings.HasPrefix(c["Printer"], "no answer") || c["Tablet"] != "no answer" || c["E-reader"] != "no answer" {
		t.Errorf("the Scan column: %q", c)
	}
	if c := f.StaleCells; !answered.MatchString(c["Office PC"]) || !strings.HasPrefix(c["Printer"], "not compared") || c["Tablet"] != "not compared" || c["E-reader"] != "not compared" {
		t.Errorf("the Scan column, the newest scan too old to compare: %q", c)
	}
	contains("the scan line, the newest scan too old to compare", f.StaleLine, "The devices are not compared with it: it was made ", " before the newest Device List read.")

	// What the syslog kept does not show.
	contains("the tab, the gateway sending its log elsewhere", rep.Views["devices fix elsewhere"].Text,
		"The gateway does not send its log to this PC. Blocked packets and the devices’ syslog messages are not seen until it does. Open the Syslog page")
	if d := rep.Views["devices fix elsewhere printer"].Detail; d == nil {
		t.Error("the printer's details were not open with the gateway sending its log elsewhere")
	} else {
		contains("the printer's details, the gateway sending its log elsewhere", d.Text,
			"The gateway does not send its log to this PC: its drops are not seen until it does.",
			"The gateway does not send its log to this PC: its messages are not here until it does.")
	}
	contains("the tab, the receiver off", rep.Views["devices fix receiver off"].Text,
		"The syslog receiver is off. It is turned off in the configuration (syslog.enabled): no new syslog message arrives, so the blocked packets and the devices’ syslog messages shown were received before.")
	contains("the tab over 30 days", rep.Views["devices fix 30d"].Text, "The syslog kept starts at ",
		"so the blocked packets and syslog messages of the first ", " of this period are not counted.")
	if d := rep.Views["devices fix 30d printer"].Detail; d == nil {
		t.Error("the printer's details were not open over 30 days")
	} else {
		contains("the printer's details over 30 days", d.Text, ": earlier drops of this period are not counted.", ": earlier messages of this period are not kept.")
	}
	lacks("the tab over 24 hours", rep.Views["devices fix elsewhere"].Text, "The syslog kept starts at")

	// The sideways scroll across the refresh.
	if s := f.Scroll; !s.Same || s.Left != 140 || !s.UnknownFound || !s.UnknownNew || s.UnknownLeft != 60 {
		t.Errorf("the tables' sideways scroll across the refresh: %+v", s)
	}

	// The opened datagram stays with its message; a refresh while text is selected waits for the
	// selection to go.
	if g := f.Datagram; g == nil {
		t.Error("no datagram opened")
	} else {
		if !g.Unique || !strings.HasPrefix(g.Key, "syslog:") || len(g.Keys) == 0 {
			t.Errorf("the datagrams' keys: %q (unique %v)", g.Keys, g.Unique)
		}
		if !g.During.Kept || g.During.Messages != len(g.Keys) {
			t.Errorf("the details redrawn while text is selected in them: %+v (%d messages before)", g.During, len(g.Keys))
		}
		if a := g.After; !a.Redrawn || a.Messages != len(g.Keys)+1 || !slices.Equal(a.Open, []string{g.Key}) || a.Top == g.Key || a.TopOpen {
			t.Errorf("the details once the selection is gone: %+v (opened %q)", a, g.Key)
		}
	}

	// A single site; details the period does not have.
	if d := rep.Views["devices fix one site"].Detail; d == nil || !strings.Contains(d.Text, "Sites1 remote address in this period") {
		t.Errorf("the details of a device with a single site: %+v", d)
	}
	if m := f.MissingDevice; m.Open || !strings.Contains(m.Text,
		"That device is not in the Device List of this period. The link asked for the details of mac:00:00:5e:00:53:99, which no read of this period lists. Look for it in the last 30 days") {
		t.Errorf("a link to a device the period does not list: %+v", m)
	}
	if m := f.MissingAddress; m.Open || !strings.Contains(m.Text,
		"That address is not among the unknown addresses of this period. The link asked for the details of 192.168.1.123, which neither the NAT table, the firewall nor the LAN scans showed in this period.") {
		t.Errorf("a link to an address the period does not show: %+v", m)
	}
	if f.MissingAfterOpen != "" {
		t.Errorf("the note stays once other details are open: %q", f.MissingAfterOpen)
	}
}

// TestDevicesNameColumnStaysInView: the DHCP table's names column sticks to its scroller's edge at
// any width (the table is wider than its card below about 1220 px), not only on a phone: its rule
// is in no @media block.
func TestDevicesNameColumnStaysInView(t *testing.T) {
	css, err := staticFS.ReadFile("static/style.css")
	if err != nil {
		t.Fatal(err)
	}
	const rule = ".tbl.net-devs td.dev-name, .tbl.net-devs th.dev-name { position: sticky; left: -1px;"
	i := strings.Index(string(css), rule)
	if i < 0 {
		t.Fatalf("style.css has no rule %q", rule)
	}
	depth := 0
	for _, c := range string(css[:i]) {
		switch c {
		case '{':
			depth++
		case '}':
			depth--
		}
	}
	if depth != 0 {
		t.Errorf("the names column's sticky rule is inside a block (depth %d): a media query keeps it from wider screens", depth)
	}
}

// TestDashboardDevicesDeepLinkGone: the page loaded at the details of a device the period does not
// list says so, and opens no details.
func TestDashboardDevicesDeepLinkGone(t *testing.T) {
	requireNode(t)
	w := newDemoWorld(time.Now())
	hash := "#/network/devices?range=24h&detail=" + url.QueryEscape("mac:00:00:5e:00:53:99")
	rep := checkedHarness(t, devicesServer(t, w), "devicesdeep", "HARNESS_HASH="+hash)
	v := rep.Views["devices deep"]
	if v.Detail != nil || !strings.Contains(v.Text, "That device is not in the Device List of this period. The link asked for the details of mac:00:00:5e:00:53:99") {
		t.Errorf("loaded at a device the period does not list: details %+v; %.400q", v.Detail, v.Text)
	}
}

// TestDashboardDevicesStale: a device's details open while the Network page's refresh fails say so
// in their header - once, however many refreshes fail - and the next refresh that works takes the
// note away; the details stay open, with the focus where it was.
func TestDashboardDevicesStale(t *testing.T) {
	requireNode(t)
	w := newDemoWorld(time.Now())
	rep := checkedHarness(t, devicesServer(t, w), "devicesstale")
	var stale struct {
		Before, Failed, Back *dashboardDetail
		SameNote             bool   `json:"sameNote"`
		SameDialog           bool   `json:"sameDialog"`
		Focus                string `json:"focus"`
	}
	if err := json.Unmarshal(rep.Facts["devicesStale"], &stale); err != nil {
		t.Fatalf("devicesStale: %s (%v)", rep.Facts["devicesStale"], err)
	}
	if b := stale.Before; b == nil || b.Stale != nil || b.Title != "Printer" || !strings.HasSuffix(b.Context, " · updates while open") {
		t.Errorf("before the refresh fails: %+v", b)
	}
	f := stale.Failed
	if f == nil || f.Stale == nil || !f.Open || !strings.Contains(f.Context, " · not updated since ") ||
		!regexp.MustCompile(`^Not updated since .+: Network devices: connstore: the connection store is closed: unavailable\. What these details show may be out of date\.$`).MatchString(f.Stale.Text) ||
		f.Stale.Role != "alert" {
		t.Errorf("the refresh failed: %+v (stale %+v)", f, f.Stale)
	}
	if !stale.SameNote || !stale.SameDialog {
		t.Errorf("a second failed refresh made a new note (%v) or new details (%v)", !stale.SameNote, !stale.SameDialog)
	}
	if b := stale.Back; b == nil || b.Stale != nil || !b.Open || !strings.HasSuffix(b.Context, " · updates while open") || stale.Focus != "button:Close" {
		t.Errorf("the refresh works again: %+v, focus %q", b, stale.Focus)
	}
}

// noConnStore is the demo world as a monitor without a connection store: the Device List view
// fails as netmap's does then (503), and the network status reports no store.
type noConnStore struct{ *demoWorld }

func (n noConnStore) Devices(ctx context.Context, q contracts.NetQuery) (model.NetDevicesView, error) {
	return model.NetDevicesView{}, fmt.Errorf("netmap: devices view: no connection store: %w", contracts.ErrUnavailable)
}

func (n noConnStore) NetworkStatus() model.NetworkStatus {
	ns := n.demoWorld.NetworkStatus()
	ns.Store = nil
	return ns
}

// devicesFail is the demo world whose Device List view fails while its other views work.
type devicesFail struct{ *demoWorld }

func (d devicesFail) Devices(ctx context.Context, q contracts.NetQuery) (model.NetDevicesView, error) {
	return model.NetDevicesView{}, fmt.Errorf("netmap: devices view: the Device List reads are damaged")
}

// TestDashboardDevicesWithoutViews: a monitor without the Network page (404) says so on the
// Devices tab, as on the others; one without a connection store says why there is no Device List
// to show, rather than the bare error.
func TestDashboardDevicesWithoutViews(t *testing.T) {
	requireNode(t)
	w := newDemoWorld(time.Now())
	srv := newDemoServer(t, w, nil)
	srv.network = nil
	rep := runDashboardOn(t, srv, "networktabs")
	viewChecker(t, rep)("network devices", "The Network page is not available: this att-monitor offers no view of the connections and the firewall.")

	srv = newDemoServer(t, w, nil)
	srv.network = noConnStore{w}
	rep = runDashboardOn(t, srv, "networktabs")
	viewChecker(t, rep)("network devices", "This att-monitor keeps no connection store, so it has no read of the gateway’s Device List to show.", "Where this comes from")
	if text := rep.Views["network devices"].Text; strings.Contains(text, "network devices:") || strings.Contains(text, "unavailable") {
		t.Errorf("the tab shows the bare error: %q", text)
	}
}

// TestDashboardOverviewNetworkDevices: the Overview's Network card counts the devices of the
// gateway's Device List and those with an issue worth a look (from the Devices tab's last 24
// hours, read with the card's other figures), and its details list those devices with their
// issues, each a link to its details on the Devices tab, and link to the tab. Without a Device
// List read the card says nothing about it and the details say why; when only the Device List view
// fails, the card counts the devices the monitor's status says are listed, and the details say
// that it failed.
func TestDashboardOverviewNetworkDevices(t *testing.T) {
	requireNode(t)
	rep := runSummary(t, newDemoServer(t, newDemoWorld(time.Now()), nil), "network")
	wantCard(t, rep.Views["overview"], "network", rep.Views["overview"].card(t, "network").Chip, "connections open16 devices listed · 5 with issues · 3 unknown addresses")
	d := rep.Views["overview network"].Detail
	if d == nil || !strings.Contains(d.Context, " · 16 devices listed · 5 with issues · 3 unknown addresses · updates while open") {
		t.Errorf("the Network details' context: %+v", d)
	}
	viewChecker(t, rep)("overview network", "The gateway’s Device List, last 24 hours",
		"16 devices listed, 13 on · 5 with issues · 3 unknown addresses (seen, but not in the Device List).",
		"Printer 192.168.1.68 Address conflictMAC mismatch192.168.1.68 is also claimed by Security camera (00:00:5e:00:53:0a)",
		"Smart speaker 192.168.1.70 Weak Wi-FiIts Wi-Fi signal is weak: the gateway draws it with 2 bars of 5 (Wi-Fi 2.4 GHz).",
		"Connections, Firewall and Devices tabs.")
	if !requested(rep, "GET", "/api/network/devices?range=24h") {
		t.Error("the Overview did not read the Device List of the last 24 hours")
	}

	w := newDemoWorld(time.Now())
	w.mu.Lock()
	w.netState = "nodevices"
	w.mu.Unlock()
	rep = runSummary(t, newDemoServer(t, w, nil), "network")
	notContains(t, rep.Views["overview"], "network", "devices listed")
	viewChecker(t, rep)("overview network", "The gateway’s Device List has not been read yet.", "Device Listnot read yet")

	w = newDemoWorld(time.Now())
	srv := newDemoServer(t, w, nil)
	srv.network = devicesFail{w}
	rep = runSummary(t, srv, "network")
	wantCard(t, rep.Views["overview"], "network", rep.Views["overview"].card(t, "network").Chip, "16 devices listed")
	notContains(t, rep.Views["overview"], "network", "with issues")
	viewChecker(t, rep)("overview network", "The Device List could not be read: network devices: netmap: devices view: the Device List reads are damaged.")
}

// TestAppJSDevicesHelpers runs the Devices tab's helpers from app.js under Node.js: the find box's
// reading (an IPv4 address in its usual form; words) and matching (names, IPv4 addresses held now
// or in the period, IPv6 addresses, MAC addresses with any separators - never an IPv4 address's
// digits for a MAC address's), the table's own order (critical, warning, the others; on before
// off; by address), the sort by a column, the status and allocation words, the address of the
// Syslog page searching an address over a period, and the tab's address with the find box and a
// device's details.
func TestAppJSDevicesHelpers(t *testing.T) {
	prog := jsProgram(t, []string{"DEV_LEVEL_RANK"}, []string{"netList", "netStrings", "toDate", "toMs", "ipSortKey", "devState", "devIssues", "devRank",
		"devName", "devAlloc", "devFind", "devHay", "devMatches", "devOrder", "devSortKey", "devSort", "devSyslogHash", "netPeriodParams", "netHash"})
	prog += `
const dev = (name, ipv4, status, level, extra) => Object.assign({ key: 'mac:' + name, name, ipv4, status, mac: '00:00:5e:00:53:0' + name.length,
  issues: level ? [{ code: 'x', level, text: 't' }] : [] }, extra || {});
const list = [dev('cam', '192.168.1.9', 'on', 'warning'), dev('pc', '192.168.1.71', 'on', ''), dev('tv', '192.168.1.66', 'off', 'critical'),
  dev('nas', '192.168.1.10', 'on', 'info'), dev('old', '192.168.1.5', 'off', ''), dev('phone', '192.168.1.65', 'on', 'critical'),
  dev('odd', '192.168.1.4', 'on <b>', '')];
const order = (l, s) => devSort(l.slice(), s).map((d) => d.name);
const laptop = dev('laptop', '192.168.1.64', 'on', '', { mac: '00:00:5e:00:53:02', ipv6: ['2001:db8::5a3c:e11f'], addresses: ['192.168.1.64', '192.168.1.80'] });
const find = (text) => devFind(text);
console.log(JSON.stringify({
  finds: ['192.168.1.80', ' 192.168.001.068 ', '192.168.1.256', '192.168.1', 'Living room TV'].map((x) => [devFind(x).ipv4, devFind(x).terms]),
  matches: ['192.168.1.80', '192.168.1.64', '192.168.1.8', '192.168.1.6', 'LAPTOP', 'lap top', '00-00-5e-00-53-02', '0000.5e00.5302', '00005e005302',
    '5e:00:53', '2001:db8::5a3c', '192.168', '168.1', 'desk'].map((x) => devMatches(laptop, find(x))),
  // The digits of an IPv4 address are not a part of a MAC address: 192.168 is no "192168".
  macDigits: devMatches(dev('m', '', 'on', '', { mac: '00:19:21:68:00:01' }), find('192.168')),
  order: order(list, { key: 'issues', dir: -1 }),
  byName: order(list, { key: 'name', dir: 1 }),
  byIPv4Desc: order(list, { key: 'ipv4', dir: -1 }),
  byStatus: order(list, { key: 'status', dir: 1 }),
  issuesAsc: order(list, { key: 'issues', dir: 1 }),
  // Within a group by name (not by address), the unnamed last.
  named: devSort([dev('bee', '192.168.1.5', 'on', ''), { key: 'mac:u', name: '', ipv4: '192.168.1.1', status: 'on', issues: [] }, dev('Ant', '192.168.1.9', 'on', '')],
    { key: 'issues', dir: -1 }).map(devName),
  states: ['on', 'OFF', ' on ', 'on <b>', '', null].map((x) => devState({ status: x })),
  allocs: ['dhcp', 'STATIC', 'pending', '', null].map(devAlloc),
  names: [{ name: 'a' }, { ipv4: '192.168.1.2' }, { mac: '00:00:5e:00:53:01' }, { key: 'ip:x' }, {}].map(devName),
  syslog: [{ range: '1h' }, { range: '24h' }, { range: '7d' }, { range: '30d' }, { range: 'custom', from: 0, to: 1 }].map((p) => devSyslogHash('192.168.1.68', p)),
  hashes: [netHash('devices', { range: '24h' }, '', { q: 'a b<', detail: 'mac:00:00:5e:00:53:06' }), netHash('devices', { range: '7d' }, 'ignored', null),
    netHash('connections', { range: '24h' }, 'mac:00:00:5e:00:53:06', { q: 'ignored' }), netHash('firewall', { range: '1h' }, '', { detail: 'ignored' })],
}));
`
	var got struct {
		Finds      [][]any  `json:"finds"`
		Matches    []bool   `json:"matches"`
		MacDigits  bool     `json:"macDigits"`
		Order      []string `json:"order"`
		ByName     []string `json:"byName"`
		ByIPv4Desc []string `json:"byIPv4Desc"`
		ByStatus   []string `json:"byStatus"`
		IssuesAsc  []string `json:"issuesAsc"`
		Named      []string `json:"named"`
		States     []string `json:"states"`
		Allocs     []string `json:"allocs"`
		Names      []string `json:"names"`
		Syslog     []string `json:"syslog"`
		Hashes     []string `json:"hashes"`
	}
	if err := json.Unmarshal(runNode(t, prog), &got); err != nil {
		t.Fatal(err)
	}
	if s := fmt.Sprint(got.Finds); s != "[[192.168.1.80 [192.168.1.80]] [192.168.1.68 [192.168.001.068]] [ [192.168.1.256]] [ [192.168.1]] [ [living room tv]]]" {
		t.Errorf("devFind: %s", s)
	}
	// Every word typed: "lap top" finds the laptop as "laptop" does.
	if want := []bool{true, true, false, false, true, true, true, true, true, true, true, true, true, false}; !slices.Equal(got.Matches, want) {
		t.Errorf("devMatches = %v, want %v", got.Matches, want)
	}
	if got.MacDigits {
		t.Error("an IPv4 address's digits matched a MAC address")
	}
	for _, c := range []struct {
		name      string
		got, want []string
	}{
		// Critical (phone on, tv off: on first), warning (cam), the rest: on by address (nas, pc),
		// a status that is neither (odd), off (old).
		{"own order", got.Order, []string{"phone", "tv", "cam", "nas", "pc", "odd", "old"}},
		{"by name", got.ByName, []string{"cam", "nas", "odd", "old", "pc", "phone", "tv"}},
		{"by IPv4, descending", got.ByIPv4Desc, []string{"pc", "tv", "phone", "nas", "cam", "old", "odd"}},
		// On, then a status that is neither (odd), then off; ties in the own order.
		{"by status", got.ByStatus, []string{"phone", "cam", "nas", "pc", "odd", "tv", "old"}},
		// No issue (in the own order), one that only informs (nas), a warning, the critical ones.
		{"by issues, ascending", got.IssuesAsc, []string{"pc", "odd", "old", "nas", "cam", "phone", "tv"}},
		{"by name within a group", got.Named, []string{"Ant", "bee", "192.168.1.1"}},
		{"devState", got.States, []string{"on", "off", "on", "unknown", "unknown", "unknown"}},
		{"devAlloc", got.Allocs, []string{"DHCP", "Static", "pending", "", ""}},
		{"devName", got.Names, []string{"a", "192.168.1.2", "00:00:5e:00:53:01", "ip:x", "?"}},
		{"devSyslogHash", got.Syslog, []string{"#/syslog?range=1h&q=192.168.1.68", "#/syslog?q=192.168.1.68", "#/syslog?range=7d&q=192.168.1.68",
			"#/syslog?range=7d&q=192.168.1.68", "#/syslog?range=7d&q=192.168.1.68"}},
		{"netHash", got.Hashes, []string{"#/network/devices?range=24h&q=a+b%3C&detail=mac%3A00%3A00%3A5e%3A00%3A53%3A06", "#/network/devices?range=7d",
			"#/network?range=24h&device=mac%3A00%3A00%3A5e%3A00%3A53%3A06", "#/network/firewall?range=1h"}},
	} {
		if !slices.Equal(c.got, c.want) {
			t.Errorf("%s:\n got %q\nwant %q", c.name, c.got, c.want)
		}
	}
}
