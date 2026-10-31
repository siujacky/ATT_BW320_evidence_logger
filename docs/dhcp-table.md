# Devices: the gateway's DHCP table on the dashboard

Status: implemented (2026-10-30): §1-5 the Devices tab (§5 says what the implementation adds to
the plan), §6 the LAN scan and §7 a device's details with its syslog messages (each with its notes
as implemented). The owner's
goal of 2026-10-30 — "add dhcp table to the dashboard so i know which ip has issue to which
device". A third tab of the Network page: **Connections | Firewall | Devices**.

## 1. Source

The gateway's **Device List** (`devices.ha`, readable without login) is its DHCP view: for every
device the MAC address, the name, the IPv4 address it was given (when it has one), its IPv6
addresses, on/off, the allocation (DHCP or static), the connection (Ethernet port or Wi-Fi band),
the wired link's speed, mesh, the last activity, and for a Wi-Fi device its signal drawn in bars.
The monitor already reads it every 15 minutes (no login) and keeps every read for
`connections.keep_days` (30 days) in `connections\`: the address history comes with it. Nothing
new is read from the gateway. The gateway does not show IPv4 lease times; the DHCP Server page is
behind the login and the monitor does not read it.

New in the reader: the Wi-Fi signal bars, from the signal image's text ("Wi-Fi 5 bars") in the
Connection Type cell (`model.LANDevice.Signal`, 1-5; 0 when none is shown).

## 2. The view (`GET /api/network/devices`, `model.NetDevicesView`)

Same period parameters and limits as the other Network endpoints (range=1h|24h|7d|30d, or from/to
within 31 days); built by netmap from the connection store (its newest Device List read, the reads
of the period through `EachDevices`, the period's NAT aggregate and the newest NAT read) and the
firewall view's drops per LAN address.

* **Devices**: every device of the newest Device List read (the base: the gateway's own table),
  each with: the identity fields; `Seen` (newest read showing it on), `OnReads`/`Reads` (reads of
  the period that showed it on / listed it); `Addresses` (IPv4 addresses held in the period,
  newest first); `Open` (its sessions in the newest NAT read) and `Sites` (distinct remote
  addresses in the period); `Blocked` (its outbound packets the firewall dropped in the period)
  and `BlockedIn` (inbound packets toward it the firewall dropped); `Issues`.
* **Issues** (each with a plain sentence that names the other device or the figure):
  * `address_shared` — critical: another entry of the newest read claims the same IPv4 address
    (an address conflict); both are flagged, each naming the other.
  * `weak_wifi` — warning: 1-2 bars.
  * `slow_link` — warning: a wired speed of 10 Mb/s, or half duplex.
  * `blocked` — warning: 100 or more of its packets dropped by the firewall per day of the period
    (whole days rounded up; 100 in a period of a day or less), out and in together; the text gives
    both counts and, for a period of more than a day, how many a day that is.
  * `address_changed` — info: more than one IPv4 address in the period (names them).
  * `offline` — info: the newest read shows it off (says since when it was last seen on).
* **Unknown**: LAN addresses (private IPv4 of the home network) that the period's NAT samples or
  firewall drops show but no Device List read of the period names — with first/last seen, open
  sessions, sites, blocked counts and the issue `unlisted` (warning).
* **Addresses**: the period's IPv4 history: for each address, which device held it from which
  read to which read (so an address seen in the syslog or the firewall at a given time can be
  tied to the device that had it then).
* **Totals**: listed, online, Wi-Fi, wired, with issues (warning or critical, devices and unknown
  addresses), unknown.
* Work is bounded like the other views (the store's caches, the firewall's per-chunk cache; a
  result cache of about 30 s keyed by the range).

## 3. The tab

* A find box ("Find a device, IP or MAC address"): filters the table by name, IPv4, IPv6, MAC; when
  it holds an IPv4 address, an **address panel** above the table says who holds it now and who
  held it in the period (from `Addresses`), with times.
* Tiles: devices listed (with online), on Wi-Fi / on Ethernet, with issues, unknown addresses.
* The **DHCP table**, sortable: status (dot + on/off), name, IPv4 (monospace), MAC, connection
  (with Wi-Fi bars), allocation, last seen on, open connections, sites, blocked (out / in),
  issues (chips with their sentence as visible text in the row's details). Devices with critical
  then warning issues first by default; off devices last.
* **Unknown addresses** below it: address, first/last seen, open, sites, blocked, issue.
* A row opens the device's **details** in the dashboard's modal (as on the Overview): identity;
  addresses in the period and others who held its address; connections (open now, sites; link to
  the Connections tab filtered to the device); blocked packets (link to the Firewall tab); its
  syslog messages (link to the Syslog page searching its address).
* The Overview's Network card says how many devices are listed and how many have issues, and its
  details link to the tab.
* Light and dark, phone width, keyboard and screen readers, every server string as text.

## 4. Also

`att-monitor network --devices` prints the table (and the unknown addresses). Docs: README (the
Network page), DESIGN §19, PACKAGES. None of it is evidence, as for the rest of the Network page.

## 5. As implemented

What the implementation adds to §1-§4 (DESIGN §19 has the whole of it):

* **Fields added** (nothing renamed or removed): `NetDevicesView.NATReads`/`NATAt` (`nat_reads`,
  `nat_at`: the period's NAT reads and when the newest was made - `Open` counts its sessions; 0 NAT
  reads means the open connections and sites are not known), `NetAddrUse.Shared` (`shared`: the
  reads of a tenure in which another device that was on claimed the address too), and
  `model.ConnDevice.Open` (each device's sessions in the period's newest NAT read, from the
  connection store's aggregate).
* **The reader**: `Signal` from the signal image's text (`alt="Wi-Fi 5 bars"`), else its file name
  (`signal-strength-5-bar.png`); 0 for any other image and for bars outside 1-5.
* **Keys**: `mac:<mac>`; an entry without a MAC address `ip:` and its IPv4 (else first IPv6) address,
  as the Connections tab keys it; `name:<name>` without either; a key the newest read gives twice
  ends in `#2`, `#3`, ...
* **The period's reads** are those `EachDevices` gives: the read in effect at its start (made before
  it, as a rule) and every later one before its end. All of them name addresses and make the
  address history (a tenure's `First` may lie before the period); only those made in the period
  count in `Reads`, `OnReads` and `Seen`. Of entries that give one address, those that are on hold
  it, else all of them; a tenure goes on over reads that show nobody with the address and ends when
  another device holds it. At most 5,000 tenures, those that ended last.
* **`address_shared`** counts only entries not shown off: an entry that is off shows the last
  address of a device that left, which DHCP may have given to another device since - its `offline`
  text says who claims that address now instead.
* **Drops** count for the device the Device List read in effect named at the address when they were
  received, else the next read within 20 minutes (a device that has just joined), as the NAT samples
  are named; a sealed syslog chunk's drops of one address are named at the newest of them (a chunk
  holds at most 5 minutes). `BlockedIn` is the inbound drops whose `OUT=` is a LAN interface:
  unsolicited IPv6 toward the device, or a port forward.
* **Unknown** addresses are private (RFC 1918) or self-assigned (169.254.0.0/16) IPv4 addresses;
  IPv6 ones never are (a device's temporary addresses are not listed). `limit` bounds the list,
  most recently seen first; `Totals.Unknown` counts them all. A drop at an address that some read
  of the period names, but no read in effect at the time, counts for nobody.
* **`slow_link`** applies to links that are not Wi-Fi: 10 Mb/s or less, or half duplex.
* **Degrading**: only the connection store is needed (without it 503). No NAT samples, no syslog
  store, or one that cannot be read (logged once while it lasts): their figures are 0. Without
  `EachDevices`, or when it fails, the newest read alone is the period's.

## 6. The LAN scan

The owner's request of 2026-10-30: "for the device in the dhcp can you also do a ip scan per hour
to see what device on the network". The Device List is the gateway's own view (its DHCP table,
read every 15 minutes); a scan asks the network itself which addresses answer. It finds what the
gateway does not list (a device with a fixed address), devices the gateway shows on that do not
answer, and an address answered by another MAC address than the gateway lists (two devices on one
address, or a list out of date).

* **How**: every `connections.scan_interval` (default 1 h; 15 min to 24 h; `0` = no scans) the
  service asks, by ARP, every address of this PC's own IPv4 network who has it: the network of the
  interface that holds the gateway's address (`gateway.host`), e.g. 192.168.1.0/24. One ARP
  question per address (Windows `SendARP`, iphlpapi.dll: no administrator rights, no raw socket);
  no packet leaves the home network, nothing else is sent to the devices - no ping, no port.
  `contracts.LANScanner`, package `internal/lanscan` (Windows; elsewhere ErrUnavailable).
* **Bounds**: only a private IPv4 network (RFC 1918) of at most 1024 addresses (/22); at most 32
  questions at a time; a sweep stops after 2 minutes (what answered by then is kept, `Problem`
  says so). This PC's own address is listed with its interface's MAC address.
* **When**: the first sweep a few minutes after the start (after the first Device List read), then
  every interval. None while the gateway is needed for evidence (samplerHold: an incident open or
  closing, a bad cycle, the gateway unreachable) - ARP does not use the gateway's web server, but
  the monitor's own traffic stays out of the evidence's way; the sweep is made once that ends.
* **Kept**: in the connection store, `scan-YYYY-MM-DD.jsonl` (gzipped after the day), one
  `model.LANScan` per line, within `keep_days` and `keep_mb` like the other files
  (`contracts.ScanStore`: AppendScan, EachScan, LastScan). Not evidence, never in the ledger.
* **Status**: `connections.scan_interval`, `scan_at`, `scan_hosts`, `scan_problem`, `scan_next`.
* **In the view** (`/api/network/devices`): per device `scan_addr` (the address it answered the
  newest scan of the period at), `scan_seen` (the last scan it answered), `scan_hits` (of the
  period's `scans`); the view's `scan` (the newest scan: when, subnet, asked, answered, took) and
  `totals.scanned`. A device is matched to a scan's answer by its MAC address (one without a MAC
  by its IPv4 address). New issues:
  * `no_answer` - info: the newest Device List read shows it on, the newest scan (within an hour
    of that read) found no answer from it ("a device that sleeps may not answer").
  * `scan_mac` - warning: the newest scan found its IPv4 address (as the newest read lists it,
    the device on) answered by another MAC address - which, and whether the period's reads name it.
  * `scan_addr` - info: it answered the newest scan at another IPv4 address than the gateway lists.
  * Unknown addresses: an address that answered a scan of the period with a MAC address no Device
    List read of the period names - not the gateway's own address - with `mac` and `scan_seen`, and
    the issue `unlisted` ("perhaps a device with a fixed address").
* **CLI**: `att-monitor scan` sweeps once from the command line and prints what answered (with the
  names of the service's newest Device List read when the service runs); it stores nothing.
  `att-monitor network --devices` shows the scan columns.

## 7. A device's details, with its syslog messages

The owner's request of 2026-10-30: "for each device click in it will show a detail with syslog".

* `GET /api/network/device?key=<NetLANDevice.Key>` - or `addr=<IPv4>` for an unknown address - with
  the period parameters of the other Network endpoints (`range=1h|24h|7d|30d`, or `from`/`to`
  within 31 days) and `limit` (syslog messages, default 100, at most 500) answers
  `model.NetDeviceDetail` (404 when the period knows neither):
  * `device` (as the Devices view lists it) or `unknown`;
  * `addresses`: the address history entries of its IPv4 addresses - its own and any other
    device's holdings of them - so the modal says who else held its address, and when;
  * `scans`: the period's LAN scans, newest first, with the address it answered each at ("" when
    it did not answer);
  * `match`: what its syslog messages are found by (netmap): each IPv4 address it held, with the
    times it held it widened by one Device List interval on each side (a hold is only seen at the
    reads) and clipped to the period; each of its IPv6 addresses and its MAC address for the whole
    period. An unknown address: its IPv4 address for the whole period;
  * `syslog`: the gateway's syslog messages of the period that a term finds (the web layer:
    `SyslogReader.Query`, newest first, at most `limit`; `syslog_truncated`), each naming its chunk
    and that chunk's `syslog_chunk` record as `GET /api/syslog` does. An IPv4 term finds an address
    only as a whole (192.168.1.7 never finds 192.168.1.70) and only in a message received within
    its times; an IPv6 term by the address as Go writes it and written out in full; a MAC address
    in any case and in either notation (`aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff`), also inside the
    firewall's `MAC=` field.
* **The modal** (a row of the DHCP table, or of the unknown addresses): identity; addresses and
  who else held them; the LAN scans (last answered, how many of the period's it answered, the
  latest ones); connections (open now, sites; link to the Connections tab filtered to it); blocked
  packets (link to the Firewall tab); and **Syslog**: its messages, newest first (time, severity,
  the message - every server string as text), "N of M shown", a link to the Syslog page searching
  its address, and a plain sentence when none names it.
* **The tab**: a line for the newest scan (when, how many answered of how many asked, the subnet,
  the next scan), and a **Scan** column in the DHCP table (answered at a time, no answer, or not
  scanned yet).
* **CLI**: `att-monitor network --devices --key <key>` prints that device's details and its syslog
  messages, newest first.

### As implemented (the scan figures of §6, and §7)

* **Scan figures**: a scan's answer counts for the listed device of its MAC address; else, when a
  read of the period names that MAC address (a device that left the list), for nobody; else, when
  the read in effect at the scan (or the next within 20 minutes) gives the address to an entry
  without a MAC address, for that entry (nobody when it left); else it is an unknown address - also
  one a read gives to another device (its `unlisted` text says so). The gateway's own answer is
  nobody's: `netmap.Options.Gateway` (gateway.host). Of several addresses one device answered a
  scan at, the one it is listed with counts. Unknown addresses from the scans are bounded like the
  drops' (4,096). A scan store that cannot be read gives no scan figures (logged once).
* **Issues**: all three compare the newest read with the newest scan, and only when the scan began
  within an hour of the read (`scan_mac` and `scan_addr` too). `no_answer` also needs the device's
  IPv4 address in the network swept and a sweep that asked every address (no `problem`).
  `scan_mac` names the device the other MAC address belongs to, or says that no read names it.
* **Details**: the Devices view built for the period (for 1,000 unknown addresses, as the tab asks)
  is reused; any unknown address of the period has details, listed or not. `scans`: the newest
  800. `match`: the Device List interval is the median time between the period's reads (5 minutes
  to 24 hours; 15 minutes with fewer than two reads); the holds of one address are joined where
  they meet, at most 128 IPv4 terms (the newest); the IPv6 addresses are the newest read's and
  those the period's reads gave the device (at most 32). The text looked in is the datagram (`raw`,
  else the bytes of `raw_b64`, else `msg`); an IPv4 address counts as a whole run of digits and
  dots, an IPv6 or MAC address as a whole run of its characters; the `MAC=` field's destination and
  source addresses count each. New field: `syslog_error` (the syslog store could not be read: the
  details answer without messages); a request that ends while it is read answers 503/504. 404 says
  which: no device with this key, or no unknown address. `key` is 1 to 512 bytes of text without
  control characters; `addr` an IPv4 address.
* **CLI**: `--key` also takes a device's MAC address alone; `--addr <IPv4>` gives an unknown
  address's details; `--limit` is then the syslog messages (20 by default, at most 500).
