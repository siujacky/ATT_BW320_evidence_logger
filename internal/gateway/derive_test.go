package gateway

import (
	"reflect"
	"testing"
	"time"

	"attmonitor/internal/model"
)

func bptr(v bool) *bool { return &v }

var (
	cdt       = time.FixedZone("CDT", -5*3600)
	fetchedAt = time.Date(2026, 10, 5, 3, 10, 43, 0, time.UTC) // bootstrap capture time
)

// snapshotFrom parses fixture bodies into a snapshot whose pages all answered HTTP 200.
func snapshotFrom(t *testing.T, sys, bb, fiber []byte) *model.GatewaySnapshot {
	t.Helper()
	s := &model.GatewaySnapshot{Trigger: "test"}
	var err error
	if sys != nil {
		if s.System, err = ParseSysInfo(sys); err != nil {
			t.Fatal(err)
		}
		s.Pages = append(s.Pages, model.PageCapture{Page: "sysinfo", Status: 200})
	}
	if bb != nil {
		if s.Broadband, err = ParseBroadband(bb); err != nil {
			t.Fatal(err)
		}
		s.Pages = append(s.Pages, model.PageCapture{Page: "broadbandstatistics", Status: 200})
	}
	if fiber != nil {
		if s.Fiber, err = ParseFiber(fiber); err != nil {
			t.Fatal(err)
		}
		s.Pages = append(s.Pages, model.PageCapture{Page: "fiberstat", Status: 200})
	}
	return s
}

func TestDeriveFixtures(t *testing.T) {
	s := snapshotFrom(t, fixture(t, "sysinfo.html"), fixture(t, "broadbandstatistics.html"), fixture(t, "fiberstat.html"))
	got := Derive(s, fetchedAt, cdt)
	want := model.GatewayDerived{
		Reachable:            true,
		BroadbandUp:          bptr(true),
		PONOperational:       bptr(true),
		OpticalUp:            bptr(true),
		WANIPv4:              "203.0.113.10",
		ISPNextHop:           "203.0.113.1",
		ISPDNS:               "68.94.156.9",
		RxPowerX10:           i64(-315),
		TxPowerX10:           i64(37),
		RxLowAlarmX10:        i64(-295),
		RxLowWarnX10:         i64(-292),
		Alarms:               []string{"OPTICAL_RX_LOW_ALARM", "OPTICAL_RX_LOW_WARNING"},
		UptimeSec:            274686,
		BootTimeEstimate:     "2026-10-01T22:52:37Z", // 03:10:43Z - 3d 4h 18m 6s
		GatewayClockBlank:    false,
		GatewayClockOffsetMs: i64(1000), // 22:10:44 CDT = 03:10:44Z
		Firmware:             "6.34.7",
		Serial:               "N00SERIAL00000",
		Model:                "BGW320-505",
		FiberLastChange:      1791151188,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Derive =\n%+v\nwant\n%+v", got, want)
	}
	for _, a := range got.Alarms {
		if len(a) >= 10 && a[:10] == "OPTICAL_TX" {
			t.Errorf("unexpected Tx alarm %q", a)
		}
	}
	// Derived pointers must not alias the parsed structures.
	*got.RxLowAlarmX10 = 0
	if *s.Fiber.Measures[4].LowAlarm.Threshold != -295 {
		t.Error("Derive aliases FiberStatus thresholds")
	}
}

// TestDeriveOutageVariants edits fixture strings to simulate what the gateway shows during
// provider-side failures and checks the derived flags.
func TestDeriveOutageVariants(t *testing.T) {
	sys, bb, fiber := fixture(t, "sysinfo.html"), fixture(t, "broadbandstatistics.html"), fixture(t, "fiberstat.html")
	tests := []struct {
		name  string
		sys   func([]byte) []byte
		bb    func([]byte) []byte
		fiber func([]byte) []byte
		check func(t *testing.T, d model.GatewayDerived)
	}{
		{name: "broadband connection down",
			bb: func(b []byte) []byte {
				return sub(t, b, `(Broadband Connection</th>\s*<td class="col2">\s*)Up`, "${1}Down")
			},
			check: func(t *testing.T, d model.GatewayDerived) {
				if d.BroadbandUp == nil || *d.BroadbandUp {
					t.Errorf("BroadbandUp = %v, want false", d.BroadbandUp)
				}
				if d.PONOperational == nil || !*d.PONOperational || d.OpticalUp == nil || !*d.OpticalUp {
					t.Error("PON/optical must stay up")
				}
			}},
		{name: "PON O1 (initial state)",
			bb: func(b []byte) []byte { return sub(t, b, `OPERATION \(O5\)`, "INITIAL (O1)") },
			check: func(t *testing.T, d model.GatewayDerived) {
				if d.PONOperational == nil || *d.PONOperational {
					t.Errorf("PONOperational = %v, want false", d.PONOperational)
				}
			}},
		{name: "PON O6 (intermittent LODS)",
			bb: func(b []byte) []byte { return sub(t, b, `OPERATION \(O5\)`, "INTERMITTENT LODS (O6)") },
			check: func(t *testing.T, d model.GatewayDerived) {
				if d.PONOperational == nil || *d.PONOperational {
					t.Errorf("PONOperational = %v, want false", d.PONOperational)
				}
			}},
		{name: "PON status row missing",
			bb: func(b []byte) []byte {
				return sub(t, b, `(?s)<tr>\s*<th scope="row" width="47%">PON Link Status</th>.*?</tr>`, "")
			},
			check: func(t *testing.T, d model.GatewayDerived) {
				if d.PONOperational != nil {
					t.Errorf("PONOperational = %v, want nil (unknown)", *d.PONOperational)
				}
			}},
		{name: "WAN address 0.0.0.0 and no next hop",
			bb: func(b []byte) []byte {
				b = sub(t, b, `203\.0\.113\.10`, "0.0.0.0")
				return sub(t, b, `203\.0\.113\.1<`, "<")
			},
			check: func(t *testing.T, d model.GatewayDerived) {
				if d.WANIPv4 != "" || d.ISPNextHop != "" {
					t.Errorf("WANIPv4=%q ISPNextHop=%q, want empty", d.WANIPv4, d.ISPNextHop)
				}
			}},
		{name: "blank Current Date/Time",
			sys: func(b []byte) []byte {
				return sub(t, b, `(Current Date/Time</th>\s*<td class="col2">)\s*2026-10-04T22:10:44\s*`, "${1}")
			},
			check: func(t *testing.T, d model.GatewayDerived) {
				if !d.GatewayClockBlank || d.GatewayClockOffsetMs != nil {
					t.Errorf("GatewayClockBlank=%v offset=%v, want true/nil", d.GatewayClockBlank, d.GatewayClockOffsetMs)
				}
				if d.UptimeSec != 274686 || d.BootTimeEstimate == "" {
					t.Error("uptime must still be derived")
				}
			}},
		{name: "optical status down",
			fiber: func(b []byte) []byte {
				return sub(t, b, `(Optical WAN Operational Status</th>\s*<td class="col2">)Up`, "${1}Down")
			},
			check: func(t *testing.T, d model.GatewayDerived) {
				if d.OpticalUp == nil || *d.OpticalUp {
					t.Errorf("OpticalUp = %v, want false", d.OpticalUp)
				}
			}},
		{name: "optical status unavailable",
			fiber: func(b []byte) []byte {
				return sub(t, b, `(Optical WAN Operational Status</th>\s*<td class="col2">)Up`, "${1}Unavailable")
			},
			check: func(t *testing.T, d model.GatewayDerived) {
				if d.OpticalUp == nil || *d.OpticalUp {
					t.Errorf("OpticalUp = %v, want false", d.OpticalUp)
				}
			}},
		{name: "rx alarms cleared, tx high alarm and temperature warning raised",
			fiber: func(b []byte) []byte {
				b = sub(t, b, `1(\s+\(Threshold -295\))`, "0${1}")
				b = sub(t, b, `1(\s+\(Threshold -292\))`, "0${1}")
				b = sub(t, b, `(Tx Power&nbsp;&nbsp;Currently 37</h1>(?s:.*?))0(\s+\(Threshold 80\))`, "${1}1${2}")
				return sub(t, b, `0(\s+\(Threshold 75\))`, "1${1}")
			},
			check: func(t *testing.T, d model.GatewayDerived) {
				want := []string{"OPTICAL_TX_HIGH_ALARM", "TEMPERATURE_HIGH_WARNING"}
				if !reflect.DeepEqual(d.Alarms, want) {
					t.Errorf("Alarms = %v, want %v", d.Alarms, want)
				}
			}},
		{name: "fiber page with no measures",
			fiber: func(b []byte) []byte {
				return sub(t, b, `(?s)<p>&nbsp;</p>\s*<div>\s*<h1>Temperature.*Rx Power table">.*?</table>\s*</div>`, "")
			},
			check: func(t *testing.T, d model.GatewayDerived) {
				if d.RxPowerX10 != nil || d.TxPowerX10 != nil || len(d.Alarms) != 0 {
					t.Errorf("Rx=%v Tx=%v Alarms=%v, want none", d.RxPowerX10, d.TxPowerX10, d.Alarms)
				}
				if d.OpticalUp == nil || !*d.OpticalUp {
					t.Error("optical status must still be derived")
				}
			}},
		{name: "gateway rebooted (uptime reset)",
			sys: func(b []byte) []byte {
				return sub(t, b, `(Time Since Last Reboot</th>\s*<td class="col2">)274686`, "${1}0:00:01:40")
			},
			check: func(t *testing.T, d model.GatewayDerived) {
				if d.UptimeSec != 100 || d.BootTimeEstimate != "2026-10-05T03:09:03Z" {
					t.Errorf("uptime=%d boot=%q", d.UptimeSec, d.BootTimeEstimate)
				}
			}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s2, b2, f2 := sys, bb, fiber
			if tt.sys != nil {
				s2 = tt.sys(append([]byte(nil), sys...))
			}
			if tt.bb != nil {
				b2 = tt.bb(append([]byte(nil), bb...))
			}
			if tt.fiber != nil {
				f2 = tt.fiber(append([]byte(nil), fiber...))
			}
			d := Derive(snapshotFrom(t, s2, b2, f2), fetchedAt, cdt)
			tt.check(t, d)
		})
	}
}

func TestDeriveEdgeCases(t *testing.T) {
	t.Run("nil snapshot", func(t *testing.T) {
		d := Derive(nil, fetchedAt, cdt)
		if !reflect.DeepEqual(d, model.GatewayDerived{UptimeSec: -1}) {
			t.Errorf("Derive(nil) = %+v", d)
		}
	})
	t.Run("only login pages and errors", func(t *testing.T) {
		s := &model.GatewaySnapshot{Pages: []model.PageCapture{
			{Page: "sysinfo", Status: 200, LoginPage: true},
			{Page: "fiberstat", Status: 302},
			{Page: "broadbandstatistics", Err: "timeout"},
		}}
		d := Derive(s, fetchedAt, nil)
		if d.Reachable || d.UptimeSec != -1 || d.GatewayClockBlank || d.BroadbandUp != nil {
			t.Errorf("Derive = %+v", d)
		}
	})
	t.Run("unknown uptime gives no boot estimate", func(t *testing.T) {
		s := &model.GatewaySnapshot{System: &model.SystemInfo{UptimeSec: -1, GatewayTimeRaw: "garbage"}}
		d := Derive(s, fetchedAt, cdt)
		if d.UptimeSec != -1 || d.BootTimeEstimate != "" || d.GatewayClockOffsetMs != nil || d.GatewayClockBlank {
			t.Errorf("Derive = %+v", d)
		}
	})
	t.Run("zero fetchedAt", func(t *testing.T) {
		s := &model.GatewaySnapshot{System: &model.SystemInfo{UptimeSec: 5, GatewayTimeRaw: "2026-10-04T22:10:44"}}
		d := Derive(s, time.Time{}, cdt)
		if d.BootTimeEstimate != "" || d.GatewayClockOffsetMs != nil {
			t.Errorf("Derive = %+v", d)
		}
	})
}

func TestDeriveGatewayClock(t *testing.T) {
	tests := []struct {
		raw  string
		loc  *time.Location
		want *int64
	}{
		{"2026-10-04T22:10:44", cdt, i64(1000)},
		{"2026-10-04T22:10:44", time.UTC, i64(1000 - 5*3600*1000)},
		{"2026-10-05T03:10:44Z", cdt, i64(1000)}, // "Z" = no zone configured on the gateway
		{"2026-10-04T22:10:44-05:00", time.UTC, i64(1000)},
		{"2026-10-04 22:10:44", cdt, i64(1000)},
		{"2026-10-04T22:09:43", cdt, i64(-60000)},
		{"not a time", cdt, nil},
	}
	for _, tt := range tests {
		s := &model.GatewaySnapshot{System: &model.SystemInfo{UptimeSec: -1, GatewayTimeRaw: tt.raw}}
		d := Derive(s, fetchedAt, tt.loc)
		if !reflect.DeepEqual(d.GatewayClockOffsetMs, tt.want) {
			t.Errorf("%q in %v: offset = %v, want %v", tt.raw, tt.loc, deref(d.GatewayClockOffsetMs), deref(tt.want))
		}
	}
}

// TestDeriveClockBlankRequiresTheRow: GatewayClockBlank is the gateway's own WAN-down
// indicator, so it is raised only when sysinfo shows the "Current Date/Time" row empty. A page
// without the row says nothing about the WAN and must not raise it.
func TestDeriveClockBlankRequiresTheRow(t *testing.T) {
	sys := fixture(t, "sysinfo.html")
	tests := []struct {
		name   string
		body   []byte
		blank  bool
		offset *int64
	}{
		{"time shown", sys, false, i64(1000)},
		{"row blank: WAN-down indicator", sub(t, sys, reClockValue, "${1}"), true, nil},
		{"row missing: no indicator", sub(t, sys, reClockRow, ""), false, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := Derive(snapshotFrom(t, tt.body, nil, nil), fetchedAt, cdt)
			if d.GatewayClockBlank != tt.blank || !reflect.DeepEqual(d.GatewayClockOffsetMs, tt.offset) {
				t.Errorf("GatewayClockBlank=%v offset=%v, want %v %v", d.GatewayClockBlank, deref(d.GatewayClockOffsetMs), tt.blank, deref(tt.offset))
			}
			if d.UptimeSec != 274686 || d.Firmware != "6.34.7" {
				t.Errorf("other sysinfo facts must still be derived: %+v", d)
			}
		})
	}

	// SystemInfo values built by hand: an empty time without the row flag is not a blank clock.
	for _, tt := range []struct {
		si     model.SystemInfo
		blank  bool
		offset *int64
	}{
		{model.SystemInfo{UptimeSec: -1}, false, nil},
		{model.SystemInfo{UptimeSec: -1, GatewayTimePresent: true}, true, nil},
		{model.SystemInfo{UptimeSec: -1, GatewayTimePresent: true, GatewayTimeRaw: "  \r\n"}, true, nil},
		{model.SystemInfo{UptimeSec: -1, GatewayTimePresent: true, GatewayTimeRaw: "2026-10-04T22:10:44"}, false, i64(1000)},
		{model.SystemInfo{UptimeSec: -1, GatewayTimeRaw: "2026-10-04T22:10:44"}, false, i64(1000)}, // a time proves the row
		{model.SystemInfo{UptimeSec: -1, GatewayTimePresent: true, GatewayTimeRaw: "garbage"}, false, nil},
	} {
		d := Derive(&model.GatewaySnapshot{System: &tt.si}, fetchedAt, cdt)
		if d.GatewayClockBlank != tt.blank || !reflect.DeepEqual(d.GatewayClockOffsetMs, tt.offset) {
			t.Errorf("%+v: GatewayClockBlank=%v offset=%v, want %v %v", tt.si, d.GatewayClockBlank, deref(d.GatewayClockOffsetMs), tt.blank, deref(tt.offset))
		}
	}
}

func deref(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}

func TestUpStateAndValidIP(t *testing.T) {
	for in, want := range map[string]*bool{
		"Up": bptr(true), " up ": bptr(true), "UP (IPv4)": bptr(true), "Down": bptr(false),
		"Unavailable": bptr(false), "Upstream": bptr(false), "": nil, "  ": nil,
	} {
		if got := upState(in); !reflect.DeepEqual(got, want) {
			t.Errorf("upState(%q) = %v, want %v", in, got, want)
		}
	}
	tests := []struct {
		in     string
		v4only bool
		want   string
	}{
		{"203.0.113.1", true, "203.0.113.1"},
		{" 68.94.156.9 ", false, "68.94.156.9"},
		{"0.0.0.0", true, ""},
		{"::ffff:203.0.113.1", true, "203.0.113.1"},
		{"2001:db8::1", true, ""},
		{"2001:db8::1", false, "2001:db8::1"},
		{"::", false, ""},
		{"n/a", false, ""},
	}
	for _, tt := range tests {
		if got := validIP(tt.in, tt.v4only); got != tt.want {
			t.Errorf("validIP(%q, %v) = %q, want %q", tt.in, tt.v4only, got, tt.want)
		}
	}
}
