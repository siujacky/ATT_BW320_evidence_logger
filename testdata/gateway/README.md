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
