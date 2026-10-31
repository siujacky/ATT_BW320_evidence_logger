package netmap

import (
	"slices"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// blockedIn is the rule of the issue "blocked" for a period of length span.
func blockedIn(span time.Duration) func(model.NetLANDevice) (model.NetIssue, bool) {
	return func(d model.NetLANDevice) (model.NetIssue, bool) { return blockedIssue(d, span) }
}

// TestDeviceIssueRules: each issue's rule and threshold, one device at a time.
func TestDeviceIssueRules(t *testing.T) {
	type check func(model.NetLANDevice) (model.NetIssue, bool)
	for _, tc := range []struct {
		name  string
		f     check
		d     model.NetLANDevice
		want  bool
		level string
		text  string
	}{
		{"1 bar", weakIssue, model.NetLANDevice{Signal: 1, Connection: "Wi-Fi 2.4 GHz"}, true, model.IssueWarning,
			"Its Wi-Fi signal is weak: the gateway draws it with 1 bar of 5 (Wi-Fi 2.4 GHz)."},
		{"2 bars, no band", weakIssue, model.NetLANDevice{Signal: 2, Connection: "Wi-Fi"}, true, model.IssueWarning,
			"Its Wi-Fi signal is weak: the gateway draws it with 2 bars of 5."},
		{"3 bars", weakIssue, model.NetLANDevice{Signal: 3}, false, "", ""},
		{"no signal shown", weakIssue, model.NetLANDevice{Signal: 0, Connection: "Wi-Fi 5 GHz"}, false, "", ""},

		{"10 Mb/s full duplex", slowIssue, model.NetLANDevice{Connection: "Ethernet LAN-3", Speed: "10Mbps fullduplex"}, true, model.IssueWarning,
			`Its Ethernet link runs at 10 Mb/s (the gateway shows "10Mbps fullduplex"); Ethernet normally runs at 100 or 1000 Mb/s, full duplex.`},
		{"100 Mb/s half duplex", slowIssue, model.NetLANDevice{Connection: "Ethernet", Speed: "100 Mbps Half Duplex"}, true, model.IssueWarning,
			`Its Ethernet link runs at 100 Mb/s, half duplex (the gateway shows "100 Mbps Half Duplex"); Ethernet normally runs at 100 or 1000 Mb/s, full duplex.`},
		{"no connection stated", slowIssue, model.NetLANDevice{Speed: "10Mbps halfduplex"}, true, model.IssueWarning,
			`Its Ethernet link runs at 10 Mb/s, half duplex (the gateway shows "10Mbps halfduplex"); Ethernet normally runs at 100 or 1000 Mb/s, full duplex.`},
		{"1000 Mb/s", slowIssue, model.NetLANDevice{Connection: "Ethernet LAN-1", Speed: "1000Mbps fullduplex"}, false, "", ""},
		{"1 Gb/s", slowIssue, model.NetLANDevice{Connection: "Ethernet LAN-1", Speed: "1Gbps"}, false, "", ""},
		{"100 Mb/s", slowIssue, model.NetLANDevice{Connection: "Ethernet LAN-1", Speed: "100Mbps fullduplex"}, false, "", ""},
		{"Wi-Fi with a speed", slowIssue, model.NetLANDevice{Connection: "Wi-Fi 5 GHz", Speed: "6Mbps halfduplex"}, false, "", ""},
		{"no speed", slowIssue, model.NetLANDevice{Connection: "Ethernet LAN-1"}, false, "", ""},

		{"99 dropped", blockedIn(24 * time.Hour), model.NetLANDevice{Blocked: 60, BlockedIn: 39}, false, "", ""},
		{"100 dropped", blockedIn(24 * time.Hour), model.NetLANDevice{Blocked: 99, BlockedIn: 1}, true, model.IssueWarning,
			"In this period the gateway's firewall dropped 99 packets it sent toward the Internet and 1 packet sent to it from the Internet."},
		{"100 on their way in", blockedIn(24 * time.Hour), model.NetLANDevice{BlockedIn: 100}, true, model.IssueWarning,
			"In this period the gateway's firewall dropped 0 packets it sent toward the Internet and 100 packets sent to it from the Internet."},
		{"100 in an hour", blockedIn(time.Hour), model.NetLANDevice{Blocked: 100}, true, model.IssueWarning,
			"In this period the gateway's firewall dropped 100 packets it sent toward the Internet and 0 packets sent to it from the Internet."},
		{"166 in a month", blockedIn(30 * 24 * time.Hour), model.NetLANDevice{Blocked: 163, BlockedIn: 3}, false, "", ""},
		{"2999 in a month", blockedIn(30 * 24 * time.Hour), model.NetLANDevice{Blocked: 2000, BlockedIn: 999}, false, "", ""},
		{"3000 in a month", blockedIn(30 * 24 * time.Hour), model.NetLANDevice{Blocked: 2000, BlockedIn: 1000}, true, model.IssueWarning,
			"In this period the gateway's firewall dropped 2000 packets it sent toward the Internet and 1000 packets sent to it from the Internet. That is about 100 packets a day."},
		{"25 hours count as two days", blockedIn(25 * time.Hour), model.NetLANDevice{Blocked: 199}, false, "", ""},
		{"a week of drops", blockedIn(7 * 24 * time.Hour), model.NetLANDevice{Blocked: 42529, BlockedIn: 110}, true, model.IssueWarning,
			"In this period the gateway's firewall dropped 42529 packets it sent toward the Internet and 110 packets sent to it from the Internet. That is about 6091 packets a day."},

		{"one address", changedIssue, model.NetLANDevice{Addresses: []string{"192.168.1.64"}}, false, "", ""},
		{"three addresses", changedIssue, model.NetLANDevice{Addresses: []string{"192.168.1.66", "192.168.1.65", "192.168.1.64"}}, true,
			model.IssueInfo, "It held 3 IPv4 addresses in this period, the newest first: 192.168.1.66, 192.168.1.65, 192.168.1.64."},
		{"seven addresses", changedIssue, model.NetLANDevice{Addresses: []string{"192.168.1.7", "192.168.1.6", "192.168.1.5", "192.168.1.4",
			"192.168.1.3", "192.168.1.2", "192.168.1.1"}}, true, model.IssueInfo,
			"It held 7 IPv4 addresses in this period, the newest first: 192.168.1.7, 192.168.1.6, 192.168.1.5, 192.168.1.4, 192.168.1.3 and 2 more."},
	} {
		is, ok := tc.f(tc.d)
		if ok != tc.want || ok && (is.Level != tc.level || is.Text != tc.text) {
			t.Errorf("%s: %v %+v\nwant %v %s %q", tc.name, ok, is, tc.want, tc.level, tc.text)
		}
	}
}

func TestOfflineAndSharedIssues(t *testing.T) {
	listAt := t0.Add(3 * time.Hour)
	for _, tc := range []struct {
		name   string
		d      model.NetLANDevice
		takers []model.NetLANDevice
		want   string
	}{
		{"seen on in the period", model.NetLANDevice{Seen: rfc3339(t0.Add(45 * time.Minute))}, nil,
			"The newest Device List read shows it off; the last read that showed it on was made 2 h 15 min before."},
		{"seen on days ago, with the gateway's last activity", model.NetLANDevice{Seen: rfc3339(t0.Add(-49 * time.Hour)), LastActivity: "Sun Oct 4 06:00:00 2026"}, nil,
			"The newest Device List read shows it off; the last read that showed it on was made 2 days 4 h before. " +
				"The gateway gives its last activity as Sun Oct 4 06:00:00 2026."},
		{"not seen on in the period", model.NetLANDevice{IPv4: "192.168.1.102"}, []model.NetLANDevice{{Name: "tablet", MAC: "00:00:5e:00:53:05"}},
			"The newest Device List read shows it off, and no read of this period showed it on. " +
				"Its last address, 192.168.1.102, is now claimed by tablet (00:00:5e:00:53:05)."},
		{"seen on in the newest read itself", model.NetLANDevice{Seen: rfc3339(listAt)}, nil, "The newest Device List read shows it off."},
	} {
		is := offlineIssue(tc.d, listAt, tc.takers)
		if is.Code != model.IssueOffline || is.Level != model.IssueInfo || is.Text != tc.want {
			t.Errorf("%s: %+v\nwant %q", tc.name, is, tc.want)
		}
	}
	is := sharedIssue("192.168.1.71", []model.NetLANDevice{{Name: "laptop", MAC: "00:00:5e:00:53:02"}, {Name: "tv"},
		{MAC: "00:00:5e:00:53:09"}, {}})
	if want := "192.168.1.71 is also claimed by laptop (00:00:5e:00:53:02), tv, 00:00:5e:00:53:09 and an entry without a name or MAC address " +
		"in the newest Device List read (an address conflict)."; is.Text != want || is.Level != model.IssueCritical || is.Code != model.IssueAddressShared {
		t.Errorf("shared: %+v\nwant %q", is, want)
	}
	for _, tc := range []struct {
		u    model.NetUnknownAddr
		nat  bool
		want string
	}{
		{model.NetUnknownAddr{Addr: "192.168.1.150", Open: 1}, true,
			"No Device List read of this period names 192.168.1.150, yet the NAT table showed its connections (1 open connection in the newest read)."},
		{model.NetUnknownAddr{Addr: "192.168.1.150", Blocked: 2, BlockedIn: 1}, true,
			"No Device List read of this period names 192.168.1.150, yet the NAT table showed its connections and the gateway's firewall dropped 2 packets it sent and 1 packet sent to it from the Internet."},
		{model.NetUnknownAddr{Addr: "10.0.0.9", BlockedIn: 3}, false,
			"No Device List read of this period names 10.0.0.9, yet the gateway's firewall dropped 3 packets sent to it from the Internet."},
	} {
		if is := unlistedIssue(tc.u, tc.nat); is.Text != tc.want || is.Level != model.IssueWarning || is.Code != model.IssueUnlisted {
			t.Errorf("unlisted %s: %q\nwant %q", tc.u.Addr, is.Text, tc.want)
		}
	}
}

func TestLinkSpeed(t *testing.T) {
	for _, tc := range []struct {
		s    string
		mbps float64
		half bool
	}{
		{"1000Mbps fullduplex", 1000, false}, {"100Mbps halfduplex", 100, true}, {"10 Mbps Half Duplex", 10, true},
		{"1Gbps", 1000, false}, {"2.5 Gb/s full", 2500, false}, {"500 kbps", 0.5, false}, {"Mbps duplex", 0, false},
		{"half", 0, true}, {"", 0, false}, {"10", 10, false},
	} {
		if mbps, half := linkSpeed(tc.s); mbps != tc.mbps || half != tc.half {
			t.Errorf("linkSpeed(%q) = %v, %v; want %v, %v", tc.s, mbps, half, tc.mbps, tc.half)
		}
	}
}

func TestSpanAndLists(t *testing.T) {
	for d, want := range map[time.Duration]string{
		0: "less than a minute", 59 * time.Second: "less than a minute", time.Minute: "1 min", 59 * time.Minute: "59 min",
		time.Hour: "1 h", 135 * time.Minute: "2 h 15 min", 24 * time.Hour: "1 day", 52 * time.Hour: "2 days 4 h", 30 * 24 * time.Hour: "30 days",
	} {
		if got := span(d); got != want {
			t.Errorf("span(%v) = %q, want %q", d, got, want)
		}
	}
	for _, tc := range []struct {
		in   []string
		want string
	}{{nil, ""}, {[]string{"a"}, "a"}, {[]string{"a", "b"}, "a and b"}, {[]string{"a", "b", "c"}, "a, b and c"}} {
		if got := joinAnd(tc.in); got != tc.want {
			t.Errorf("joinAnd(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestDeviceOrder: critical, then warning issues first (info issues do not count), then on before
// a status not shown before off, then the named by name (case aside), then by address and key.
func TestDeviceOrder(t *testing.T) {
	issue := func(level string) []model.NetIssue { return []model.NetIssue{{Code: "x", Level: level}} }
	devs := []model.NetLANDevice{
		{Key: "k1", Name: "zeta", Status: "on"},
		{Key: "k2", Name: "", IPv4: "192.168.1.9", Status: "on"},
		{Key: "k3", Name: "Alpha", Status: "off", Issues: issue(model.IssueWarning)},
		{Key: "k4", Name: "beta", Status: "on", Issues: issue(model.IssueInfo)},
		{Key: "k5", Name: "gamma", Status: "on", Issues: issue(model.IssueCritical)},
		{Key: "k6", Name: "", IPv4: "192.168.1.10", Status: "on"},
		{Key: "k7", Name: "", Status: "on"},
		{Key: "k8", Name: "delta", Status: ""},
		{Key: "k9", Name: "alpha", Status: "on", Issues: issue(model.IssueWarning)},
		{Key: "k0", Name: "beta", Status: "on"},
	}
	sortDevices(devs)
	var got []string
	for _, d := range devs {
		got = append(got, d.Key)
	}
	if want := []string{"k5", "k9", "k3", "k0", "k4", "k1", "k2", "k6", "k7", "k8"}; !slices.Equal(got, want) {
		t.Errorf("order %q, want %q", got, want)
	}
}
