# Gateway fixtures

Real responses from the AT&T BGW320-505 (firmware 6.34.7) captured on 2026-10-05, then
sanitized (serials, MAC addresses, public IPs, SSID and device names replaced with
documentation values). Bodies were saved after UTF-8 decoding with replacement and with
CRLF line endings — parsers must not depend on line endings or on the copyright byte.

| file | page | notes |
|---|---|---|
| sysinfo.html | sysinfo.ha | uptime `274686` (plain seconds), gateway time `2026-10-04T22:10:44` |
| broadbandstatistics.html | broadbandstatistics.ha | Broadband Connection `Up`, PON `OPERATION (O5)`, next hop 203.0.113.1, DNS 68.94.156.9 / 68.94.157.9 |
| fiberstat.html | fiberstat.ha | Rx Power `-315` with Low Alarm `1 (Threshold -295)` and Low Warning `1 (Threshold -292)`; Last Change `1791151188` |
| home.html | home.ha | slow page; SSIDs/devices (sanitized) |
| lanstatistics.html | lanstatistics.ha | slow page |
| sitemap.html | sitemap.ha | 36 page links |
| diag.html, firewall.html | diag.ha, firewall.ha | readable without login |
| login_handshake1.html | any protected page, 1st GET of a new cookie session | login page WITHOUT nonce |
| login_nonce.html | same, 2nd GET | login page with `name="nonce"` |
| events_checked.html | events.ha (authenticated) | `bbevent` checked (redirect ON) |
| events_unchecked.html | events.ha after Save | `bbevent` unchecked (redirect OFF) |
| broadbandconfig.html | broadbandconfig.ha (authenticated) | config form |
| hiddenpage.html | target of securityoptions.ha 302 | "Page not found" |

## Synthetic Syslog pages (not captures)

The `syslog_*.html` files are **synthetic**: the real Diagnostics → Syslog page (`syslog.ha`,
behind the login) has not been captured yet. They are modelled on the BGW320 markup of
`events.ha` and `broadbandconfig.ha` (XHTML layout, hidden `nonce`, the `nojavamsg` row, `<th>`
labels with `<label for>`, noscript **Update** buttons, Save/Cancel) and on the page's control
labels from BGW320-CLI: *Syslog*, *Server IP Address*, *Server Port*, *Log Level*. Each says so
in a comment at its top. Control names differ from file to file on purpose: the client finds the
controls by their labels, never by name. Phase 2 of `docs/syslog-snmp-traffic.md` replaces these
pages with the sanitized real page (before and after a change).

| file | switch | shows | notes |
|---|---|---|---|
| syslog_select.html | drop-down On/Off | off; server empty, port 514, level Warning | fields always shown; also an "Include Firewall Log" checkbox, a disabled "Syslog Status" field and a hidden field (other controls, posted as found) |
| syslog_checkbox_off.html | checkbox | off; no server fields | fields shown only once on: a noscript Update button next to the checkbox transforms the page |
| syslog_checkbox_on.html | checkbox | on; 192.168.1.64, port 514 (number input), level Notice | the same page once on; level options without value attributes |
| syslog_radio.html | radio buttons Enable/Disable | off; server empty, port 514, level Warning | labels are bare `<th>` texts with a trailing colon; option values `info`, `debug`, ... |
| syslog_noport.html | drop-down Enabled/Disabled | on; 192.168.1.64, level Notice | no Server Port control: must be refused |
| syslog_fewlevels.html | drop-down Enabled/Disabled | on; 192.168.1.64, port 514, level Notice | no "Informational" level: setting it must be refused |
