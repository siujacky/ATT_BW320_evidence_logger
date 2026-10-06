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

## The Network page's pages: Device List and NAT table

The dashboard's Network page (docs/syslog-map-graphic.md) reads two more pages, never posting
their forms. Neither page is evidence.

| file | page | what it is |
|---|---|---|
| devices_real.html | devices.ha (Device > Device List; readable without login) | **sanitized capture** of the owner's gateway, firmware 6.34.7, 8 devices |
| nattable_real.html | nattable.ha (Diagnostics > NAT Table; behind the login) | **sanitized capture** read by the deployed service, firmware 6.34.7, 120 sessions |
| nattable_synthetic.html | nattable.ha | **synthetic**: written before the page could be captured; kept for the parser's variants |

### devices_real.html (sanitized capture)

One table; each device is a block of `<th scope="row">` label rows, the blocks separated by a
row holding only `<hr class="reshr">`. Labels: *MAC Address*, *IPv4 Address / Name* (or just
*Name* for a device without an IPv4 address), *Last Activity*, *Status*, *Allocation*,
*Connection Type* (a `<pre>` of `<br>`-separated lines: "Wi-Fi", the band and radio, "Type:
Home", "Name: *the Wi-Fi network's name*"; or "Ethernet LAN-1"), *Connection Speed*, *Mesh
Client*, then repeated *IPv6 Address* / *Type* / *Valid Lifetime* / *Preferred Lifetime* groups.
The gateway's own sloppy markup is kept: the Connection Speed rows of Wi-Fi devices are
`<th>Connection Speed</th></td></tr>` with no value cell, and the wired device that is off shows
the bare template `Mbps\tduplex` (a tab between the words). The page also carries a form with a
nonce and a **Clear and Rescan for Devices** button, which empties the gateway's device table: it
is never posted.

Sanitized by replacing values only - the markup, the labels and the LF line endings are as the
gateway sent them (a comment at the top says so):

| what | replaced by |
|---|---|
| device names | generic names: office-pc, laptop, phone, living-room-tv, tablet, printer, thermostat, game-console |
| MAC addresses | the documentation range `00:00:5e:00:53:01` ... `:08` (RFC 7042) |
| IPv4 addresses | `192.168.1.101` ... `.106` |
| IPv6 addresses | the documentation prefix `2001:db8::/32` (RFC 3849) and link-local `fe80::10xx` |
| Wi-Fi network name | `ATT-EXAMPLE` (the parser must never keep it) |
| Last Activity | `Mon Oct 5 12:0N:00 2026` |
| nonce | all zeros |

What it holds: one Ethernet device (LAN-1, off, no IPv4 address: a *Name* row) and seven Wi-Fi
devices - six on 5 GHz (Radio-1 and Radio-2), one on 2.4 GHz - one of them without an IPv4
address (*Name*); four with IPv6 groups (global and link-local addresses, `2001:db8:0::100`
written uncompressed).
network_test.go asserts every field of all 8 devices and derives further variants from the
capture with regular expressions (other line endings, raw windows-1252 bytes, no separator rows,
line breaks instead of `<br>`, other MAC spellings, no devices at all, a network name that reads
like a band or a port).

### nattable_real.html (sanitized capture)

The NAT table as the deployed service read it on 2026-10-06 (`connections\last-nattable.html`): 120
sessions (87 IPv4, 33 IPv6), *Total sessions in use* 120, *Total sessions available* 32767, the
client list set to *All*. The table has fourteen columns - *IP Family*, *Protocol*, *Protocol
Number*, *Lifetime*, *TCP State*, *Source Address*, *Source Port*, *Destination Address*,
*Destination Port*, *NAT Source Address*, *NAT Source Port*, *NAT Destination Address*, *NAT
Destination Port*, *Bidirectional* - and the session is the connection as the device opened it, not
its translated (NAT) columns. Sanitized: every address replaced by a documentation address, one per
original (LAN addresses in `192.168.1.0/24`, the gateway's own `192.168.1.254` kept; the gateway's
public address became `203.0.113.1`; IPv6 addresses sharing a /64 still share one, with new interface
ids), the client list's device names and the nonce replaced; the markup is unchanged. A comment at
its top says so.

### nattable_synthetic.html (synthetic, not a capture)

The NAT table is behind the login and nobody may log in to the gateway to capture it, so this
page is **made up** around what an earlier read-only tool reported of the real page: a table with
the columns *Protocol*, *TCP State*, *Source Address*, *Source Port*, *Destination Address*,
*Destination Port* (one row per session; 356 were shown once), the label rows *Total sessions
available* and *Total sessions in use*, and a list labelled *Select display option*. A comment
at its top says so. The real page, captured since (`nattable_real.html`), has more columns; this one
stays for the parser's variants.

The chrome is copied from `syslog_real_off.html` (title "NAT Table", NAT Table selected in the
Diagnostics menu); the content: a form posting to `nattable.ha` with a zero nonce, the *Select
display option* list (All/TCP/UDP/ICMP sessions, "All sessions" selected, submitted on change,
with a noscript **Update** button - never posted), the two totals (8192 available, 25 in use) and
a table of 25 sessions with documentation addresses: LAN sources `192.168.1.101` ... `.106` (the
Device List's devices) and `.150` (a device it does not list) to public `192.0.2.x`,
`198.51.100.x` and `203.0.113.x`; TCP sessions in states such as ESTABLISHED, TIME_WAIT,
SYN_SENT, CLOSE_WAIT, FIN_WAIT, LAST_ACK; UDP and ICMP sessions with an empty (or `&nbsp;`, or
`-`) TCP State; one inbound session (a public source to `192.168.1.105:8080`); one of the
gateway's own (from its public address `203.0.113.10`); one IPv6 session; rows with the
gateway's kind of sloppy markup (missing `</td>`, a stray `</td>`, a missing `</tr>`); and one
malformed row (source `192.168.1.300`) that must be skipped, not fatal. Other shapes of the page
(columns in another order, address:port cells, extra columns, no totals, totals in text, upper
case, CRLF, a cell left out, two-level headers, ...) are inline pages in network_test.go.
