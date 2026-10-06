package gateway

import (
	"testing"
	"time"

	"attmonitor/internal/model"
)

// FuzzParsers checks that no input makes a parser or Derive panic (gateway pages are
// untrusted input). The seed corpus runs with every "go test"; fuzz with
// go test -fuzz=FuzzParsers ./internal/gateway/
func FuzzParsers(f *testing.F) {
	for _, name := range []string{"sysinfo.html", "broadbandstatistics.html", "fiberstat.html", "lanstatistics.html",
		"events_checked.html", "login_nonce.html", "hiddenpage.html", "home.html", "broadbandconfig.html",
		"syslog_select.html", "syslog_checkbox_off.html", "syslog_checkbox_on.html", "syslog_radio.html",
		"syslog_real_off.html", "syslog_real_on_update.html", "syslog_real_on.html"} {
		f.Add(fixture(f, name))
	}
	f.Add([]byte("<form><table><tr><th>Syslog<td><select name=s><option value=1 selected>On<noscript><input type=submit name=Update></noscript></select><label for=s>Server Port</label>"))
	f.Add([]byte("<table><tr><th>Time Since Last Reboot</th><td>99:99:99:99</td></tr></table>"))
	f.Add([]byte("<h1>Rx Power" + nbspLatin1 + "Currently 9999999999999999999999</h1><table><tr><td>Alarm</td><td colspan=999999>1 (Threshold -99999999999999999999)</td></tr></table>"))
	f.Add([]byte("<title>Login<form action=login.ha><input name=nonce value=\x01>"))
	f.Fuzz(func(t *testing.T, body []byte) {
		s := &model.GatewaySnapshot{Pages: []model.PageCapture{{Page: "sysinfo", Status: 200}}}
		s.System, _ = ParseSysInfo(body)
		s.Broadband, _ = ParseBroadband(body)
		s.Fiber, _ = ParseFiber(body)
		s.LAN, _ = ParseLAN(body)
		_, _ = ParseNotification(body)
		_ = IsLoginPage(body)
		_ = SessionsFull(body)
		_ = scan(body).nonce("/login.ha")
		d := Derive(s, time.Date(2026, 10, 5, 3, 10, 43, 0, time.UTC), time.UTC)
		if s.System != nil && d.UptimeSec != s.System.UptimeSec {
			t.Fatalf("uptime %d != %d", d.UptimeSec, s.System.UptimeSec)
		}
		// The WAN-down indicator needs the gateway's own blank "Current Date/Time" row.
		if d.GatewayClockBlank && (s.System == nil || !s.System.GatewayTimePresent || normSpace(s.System.GatewayTimeRaw) != "") {
			t.Fatalf("GatewayClockBlank without a blank Current Date/Time row: %+v", s.System)
		}
		_, _ = ParseSyslog(body)
		for _, form := range parseForms(body) {
			_ = form.fields(syslogSwitchLabel)
			for _, c := range form.controls {
				if !c.isSubmit() {
					continue
				}
				// A body that is produced at all is plain ASCII: a browser would encode anything
				// else in the page's character encoding.
				if enc, err := form.encode(c); err == nil {
					for i := 0; i < len(enc); i++ {
						if enc[i] >= 0x80 || enc[i] <= 0x20 {
							t.Fatalf("encoded body %q has byte %#x", enc, enc[i])
						}
					}
				}
			}
		}
	})
}
