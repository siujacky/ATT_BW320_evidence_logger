package gateway

import (
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"attmonitor/internal/model"
)

// Derive computes the facts the monitor uses from a snapshot's parsed pages. It is pure and
// deterministic, so anyone can recompute it from a recorded snapshot:
//
//   - Reachable: at least one page answered HTTP 200 and was not the login page.
//   - BroadbandUp / OpticalUp: the gateway's own "Broadband Connection" / "Optical WAN
//     Operational Status" reads "Up" (nil when the row is absent; any other text = false).
//   - PONOperational: "PON Link Status" contains "O5" (the ITU-T G.984/G.9807 operation state).
//   - WANIPv4 / ISPNextHop / ISPDNS: the gateway-reported addresses when they are valid,
//     specified IP addresses ("" otherwise, e.g. 0.0.0.0 while the WAN is down).
//   - Rx/Tx power and the Rx low alarm/warning thresholds in 0.1 dBm.
//   - Alarms: condition codes <MEASURE>_<LOW|HIGH>_<ALARM|WARNING> for every alarm/warning
//     flag the gateway itself raises, MEASURE in TEMPERATURE, VCC, TX_BIAS, OPTICAL_TX,
//     OPTICAL_RX (sorted). No thresholds are re-evaluated here.
//   - UptimeSec (-1 when unknown), BootTimeEstimate = fetchedAt - uptime (UTC, seconds).
//   - GatewayClockBlank: sysinfo was parsed, its "Current Date/Time" row is present
//     (SystemInfo.GatewayTimePresent) and the value is empty: the gateway blanks it while the
//     WAN is down. A page without that row says nothing about the WAN and never sets it.
//   - GatewayClockOffsetMs: gateway clock - fetchedAt, where the gateway's zone-less local
//     time is interpreted in loc (time.Local when nil); a time with "Z" or an explicit offset
//     is taken as written. During the autumn DST overlap the hour is ambiguous. The
//     gateway reports whole seconds, so the offset has about one second of resolution.
//   - Firmware, Serial, Model (sysinfo) and FiberLastChange (fiberstat "Last Change", raw).
func Derive(s *model.GatewaySnapshot, fetchedAt time.Time, loc *time.Location) model.GatewayDerived {
	d := model.GatewayDerived{UptimeSec: -1}
	if s == nil {
		return d
	}
	if loc == nil {
		loc = time.Local
	}
	for _, pc := range s.Pages {
		if pc.Status == http.StatusOK && !pc.LoginPage {
			d.Reachable = true
			break
		}
	}

	if b := s.Broadband; b != nil {
		d.BroadbandUp = upState(b.Connection)
		if pon := strings.TrimSpace(b.PONLinkStatus); pon != "" {
			v := strings.Contains(strings.ToUpper(pon), "O5")
			d.PONOperational = &v
		}
		d.WANIPv4 = validIP(b.IPv4, true)
		d.ISPNextHop = validIP(b.GatewayIPv4, true)
		d.ISPDNS = validIP(b.PrimaryDNS, false)
	}

	if f := s.Fiber; f != nil {
		d.OpticalUp = upState(f.OpticalStatus)
		d.FiberLastChange = f.LastChangeUnix
		seen := map[string]bool{}
		for _, m := range f.Measures {
			k := dmiKindOf(m.Name)
			if k == nil {
				continue
			}
			switch k.code {
			case "OPTICAL_RX":
				if d.RxPowerX10 == nil {
					d.RxPowerX10 = clonePtr(m.Current)
					d.RxLowAlarmX10 = clonePtr(m.LowAlarm.Threshold)
					d.RxLowWarnX10 = clonePtr(m.LowWarn.Threshold)
				}
			case "OPTICAL_TX":
				if d.TxPowerX10 == nil {
					d.TxPowerX10 = clonePtr(m.Current)
				}
			}
			for _, fl := range []struct {
				t      model.Threshold
				suffix string
			}{
				{m.LowAlarm, "_LOW_ALARM"}, {m.HighAlarm, "_HIGH_ALARM"},
				{m.LowWarn, "_LOW_WARNING"}, {m.HighWarn, "_HIGH_WARNING"},
			} {
				if code := k.code + fl.suffix; fl.t.Active && !seen[code] {
					seen[code] = true
					d.Alarms = append(d.Alarms, code)
				}
			}
		}
		sort.Strings(d.Alarms)
	}

	if si := s.System; si != nil {
		d.Firmware = si.SoftwareVersion
		d.Serial = si.Serial
		d.Model = si.Model
		d.UptimeSec = si.UptimeSec
		if si.UptimeSec >= 0 && si.UptimeSec <= maxUptimeSec && !fetchedAt.IsZero() {
			boot := fetchedAt.Add(-time.Duration(si.UptimeSec) * time.Second)
			d.BootTimeEstimate = boot.UTC().Format(time.RFC3339)
		}
		switch raw := normSpace(si.GatewayTimeRaw); {
		case raw != "":
			if gw, ok := parseGatewayTime(raw, loc); ok && !fetchedAt.IsZero() {
				off := gw.Sub(fetchedAt).Milliseconds()
				d.GatewayClockOffsetMs = &off
			}
		case si.GatewayTimePresent:
			d.GatewayClockBlank = true // the row is shown, but empty
		}
	}
	return d
}

// upState maps a gateway status word to true ("Up"), false (any other text) or nil (absent).
func upState(s string) *bool {
	f := strings.Fields(normSpace(s))
	if len(f) == 0 {
		return nil
	}
	v := strings.EqualFold(f[0], "up")
	return &v
}

// validIP returns s normalized if it is a specified IP address (IPv4 only when v4only).
func validIP(s string, v4only bool) string {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return ""
	}
	a = a.Unmap()
	if a.IsUnspecified() || (v4only && !a.Is4()) {
		return ""
	}
	return a.String()
}

func clonePtr(p *int64) *int64 {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// parseGatewayTime parses sysinfo "Current Date/Time": "2026-10-04T22:10:44" is local time
// in loc; per the gateway's help text a trailing "Z" means UTC (no zone configured).
func parseGatewayTime(raw string, loc *time.Location) (time.Time, bool) {
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t, true
	}
	for _, layout := range []string{"2006-01-02T15:04:05", "2006-01-02 15:04:05"} {
		if t, err := time.ParseInLocation(layout, raw, loc); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
