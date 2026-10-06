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

## The real Syslog page, and pages derived from it

`syslog_real_off.html` is the real Diagnostics → Syslog page (`syslog.ha`, behind the login) of
the owner's BGW320-505, firmware 6.34.7, as the deployed service recorded it (phase 1, read-only)
with Syslog off; only the nonce is replaced (all zeros). Unlike the captures above it keeps the
gateway's LF line endings. Its form: a drop-down list *Syslog* (`syslog`: `off`/`on`, submitted
on change) with a noscript **Update** button after it, *Server IP Address* (`location`,
maxlength 43), *Server Port* (`port`, maxlength 5) and *Log Level* (`level`: Emergency, Alert,
Critical, Error, Warning, Notice - no Informational, no Debug), the three **disabled** while
Syslog is off, and Save/Cancel.

How the gateway answers the Update and the Save buttons has not been observed (that needs a
change on the gateway). The two pages below are therefore **DERIVED from the real page, not
captured**: each is `syslog_real_off.html` with the smallest edits that give the state it stands
for, and says so in a comment at its top. The tests' fake gateway serves them; the client must
accept the real answers whether or not they look exactly like these.

| file | stands for | edits to `syslog_real_off.html` |
|---|---|---|
| syslog_real_on_update.html | the page the Update button returns once *Syslog* is switched On | "On" selected; `disabled` removed from the three fields, which keep the values stored (server empty, port 514, level Error); nonce all ones |
| syslog_real_on.html | the page once Syslog is saved On with 192.168.1.71, port 514, level Notice | "On" selected; `disabled` removed from the three fields; server `192.168.1.71`; "Notice" selected instead of "Error"; nonce all twos |

## Synthetic Syslog pages (not captures)

The other `syslog_*.html` files are **synthetic**, written before the real page was captured.
They are modelled on the BGW320 markup of `events.ha` and `broadbandconfig.ha` (XHTML layout,
hidden `nonce`, the `nojavamsg` row, `<th>` labels with `<label for>`, noscript **Update**
buttons, Save/Cancel) and on the page's control labels from BGW320-CLI: *Syslog*, *Server IP
Address*, *Server Port*, *Log Level*. Each says so in a comment at its top. Control names differ
from file to file on purpose: the client finds the controls by their labels, never by name. They
stay as other shapes the label-based reader must handle (or refuse).

| file | switch | shows | notes |
|---|---|---|---|
| syslog_select.html | drop-down On/Off | off; server empty, port 514, level Warning | fields always shown; also an "Include Firewall Log" checkbox, a disabled "Syslog Status" field and a hidden field (other controls, posted as found) |
| syslog_checkbox_off.html | checkbox | off; no server fields | fields shown only once on: a noscript Update button next to the checkbox transforms the page |
| syslog_checkbox_on.html | checkbox | on; 192.168.1.64, port 514 (number input), level Notice | the same page once on; level options without value attributes |
| syslog_radio.html | radio buttons Enable/Disable | off; server empty, port 514, level Warning | labels are bare `<th>` texts with a trailing colon; option values `info`, `debug`, ... |
| syslog_noport.html | drop-down Enabled/Disabled | on; 192.168.1.64, level Notice | no Server Port control: must be refused |
| syslog_fewlevels.html | drop-down Enabled/Disabled | on; 192.168.1.64, port 514, level Notice | no "Informational" level: setting it must be refused |
