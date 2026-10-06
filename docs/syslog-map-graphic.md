# Network map — which device talks to which site, and what the gateway's firewall blocks

Status: owner's goal of 2026-10-06 — "base on the syslog … show which ip is connect to which site, filter
by date to make the syslog in a graph / map. also try to show each lan computer connect to which ip /
service. make it simple and professional". Plan for the dashboard's new **Network** page.

**Implemented** (2026-10-06): `internal/connstore`, `internal/ipintel`, `internal/netmap`, the
samplers in `internal/monitor`, the NAT table and Device List readers in `internal/gateway`, the
endpoints and the page in `internal/web`, the wiring and `att-monitor network` in `cmd/att-monitor`.
The specification is now `docs/DESIGN.md` §19; §5 below lists where the implementation differs
from this plan. Still to do: steps 9 (review, e2e) and 10 (deploy, release) of §3. `build.ps1`
labels builds 1.3.0, the version this ships as.

## 1. What was asked, and what the gateway can give

| Asked | Source | Can it show it? |
|---|---|---|
| "which ip is connect to which site", from the syslog | The gateway's syslog (phase 2 of `syslog-snmp-traffic.md`) | **Partly.** The BGW320 at its most detailed level (Notice) logs only **firewall drops** (netfilter lines: `IN=`/`OUT=`, `SRC=`/`DST=`, `PROTO`, `SPT`/`DPT`, reason, hook). In the first 2,000 messages: 55 % inbound probes from the Internet (`IN=veip0.0`), 39 % outbound packets from the LAN that the gateway dropped (`IN=br1 OUT=veip0.0`, all but one from this PC), the rest local or invalid. It never logs connections it allows. |
| "each LAN computer connect to which ip / service" | The gateway's **NAT Table** (Diagnostics → NAT Table, `nattable.ha`): every active NAT session — Protocol, TCP State, Source Address/Port, Destination Address/Port, sessions in use/available | **Yes**, as samples: the table shows the sessions open at the moment it is read. It needs the login (an unauthenticated GET returns the Login page). (Found after deployment: the real page also lists IPv6 connections, in an *IP Family* column.) |
| Device names | The gateway's **Device List** (`devices.ha`): name, IPv4, MAC, connection type, status, last activity — readable without login (8 devices on the owner's network) | Yes |
| "site" | Remote IP → organisation (ASN), country — **offline**, from the public-domain IPtoASN database (`ip2asn-v4/v6.tsv.gz`, PDDL 1.0, ~7 MB, refreshed weekly); service from the port (443 HTTPS, 53 DNS, …); reverse DNS (PTR) as a hint | Yes, as "organisation / country / service". The name a device actually looked up (netflix.com) is not available: the gateway does not log DNS queries. |
| "graph / map", "filter by date", "simple and professional" | A **Network** page: flow diagram (device → site → service), world map (countries), timeline, tables; one date filter for everything | Yes |

## 2. Design

### 2.1 Data — none of it is evidence

These views describe the household's own traffic, not AT&T faults. Nothing here goes into the signed
ledger (which can never delete anything, and would keep browsing patterns forever) or into evidence
bundles. It is stored locally with its own retention and shown only on the localhost dashboard.

* **NAT sampler** (`internal/gateway` + `internal/monitor`): reads `nattable.ha` every
  `connections.interval` (default **4 min**: the gateway client reuses its login session for 5 minutes,
  so the sampler normally needs no new login) through the gateway client's login policy (one attempt a
  minute, none after three rejections an hour), never while logins are paused, the session pool is
  full, a certificate change is pending, or no access code is stored. Read-only: the page's display
  selector is never posted. Parsed into sessions: protocol, TCP state, LAN address/port, remote
  address/port; plus "sessions in use / available".
* **Device sampler**: reads `devices.ha` (no login) every 15 min: name, IPv4, MAC, connection type,
  status; names are matched to sessions by IPv4 at the time of the sample.
* **Connection store** (`internal/connstore`, new; folder `connections\`): one line per sample (time,
  sessions, devices), daily files, gzipped once the day is over, kept for `connections.keep_days`
  (default **30**) within `connections.keep_mb` (default **200**). Queries aggregate the samples of a
  period: per device → remote endpoint (organisation, country, service): first and last seen, number
  of samples present.
* **Firewall view of the syslog** (`internal/netmap`, new): parses the firewall lines of the syslog
  store (direction inbound / outbound / to the gateway, reason, protocol, source, destination, ports)
  and aggregates them for a period: inbound probes by country / organisation / source / targeted
  service, outbound drops by LAN device → destination, a timeline per hour. Sealed syslog chunks never
  change, so their aggregates are cached by chunk name.
* **IP intelligence** (`internal/ipintel`, new): the IPtoASN tables (IPv4 and IPv6) downloaded to
  `geo\` on first use and refreshed weekly (`geo.url`, `geo.refresh`, can be switched off; only the
  public dataset is downloaded — no address is ever sent anywhere), loaded as sorted ranges; lookups
  give ASN, organisation, country. Service names from a built-in port table. Reverse DNS (PTR) for the
  addresses shown, cached, through this computer's resolver (`connections.reverse_dns`, default on).
  LAN / private / multicast addresses are named as such and never looked up.

### 2.2 API (localhost dashboard)

* `GET /api/network/connections?from&to&device=` → devices, sites, services, links device→site→service
  (weighted by samples), country totals, the rows (device, remote IP, organisation, ASN, country,
  service, protocol, first/last seen, samples), sampler status (last sample, sessions in use/available,
  errors).
* `GET /api/network/firewall?from&to` → inbound by country/organisation/source/service, outbound drops
  by device→destination, hourly timeline, totals.
* `GET /api/network/status` → samplers, stores, the IP database's date.
* Same protections and limits as the other GET endpoints; bounded work per request.

### 2.3 The Network page (simple and professional)

One page, two tabs, one date filter (1 h, 24 h, 7 d, 30 d, or a custom from/to) and a device filter:

* **Connections** (from the NAT table): summary tiles (devices active, sites, countries, samples); a
  **flow diagram** — devices on the left, organisations in the middle (top 15, the rest as "other"),
  services on the right, band width = samples — clicking a device filters everything; a **world map**
  of the remote endpoints' countries; a sortable, searchable **table** per device → site. A note says
  what the data is: samples of the gateway's NAT table every 4 minutes (short connections in between
  are not seen).
* **Firewall** (from the syslog): tiles (inbound probes blocked, outbound packets blocked, sources,
  top country); a **world map** of where the blocked inbound probes came from; an hourly **timeline**
  (inbound / outbound); top sources (IP, organisation, country), most-targeted services, and LAN
  devices whose outbound packets were blocked (destination, port, reason).
* Visual language: the dashboard's existing tokens and type, one accent per meaning, light and dark
  mode, numbers right-aligned, a table view for every chart (accessibility), no external requests
  (the world map ships with the page: Natural Earth 1:110m country outlines, public domain,
  pre-projected to SVG paths).

## 3. Implementation plan

| # | Task | Package | Status |
|---|---|---|---|
| 0 | Design preview (an artifact with sample data) for the page's look | — | the demo world (`internal/web/demonet_test.go`) serves sample data |
| 1 | Shared types and contracts; config `connections.*`, `geo.*`; data folders | model, contracts, config | done |
| 2 | NAT table and Device List readers (fixtures from the BGW320's markup; the NAT page needs the login) | gateway | done (sanitized capture of the real page after deployment: `nattable_real.html`) |
| 3 | Connection store with retention | connstore | done |
| 4 | IP intelligence: IPtoASN download/refresh/lookup, ports, PTR cache | ipintel | done |
| 5 | Firewall aggregation of the syslog (parser + per-chunk cache) | netmap | done |
| 6 | Samplers in the monitor (NAT every 4 min under the login policy; devices every 15 min); status | monitor | done |
| 7 | API endpoints and the Network page (flow diagram, world map, timeline, tables, filters) | web | done |
| 8 | Wiring, CLI (`att-monitor network [--since …]`), docs (README, DESIGN, PACKAGES) | cmd, docs | done (`--range`/`--from`/`--to`, see §5) |
| 9 | Review (gateway safety of the NAT reads, privacy, correctness, UX), fixes, tests, e2e | all | |
| 10 | Deploy (one UAC prompt), check with the real NAT table, push, release v1.3.0 | — | |

## 4. Out of scope

* Sites by DNS name (the gateway does not log DNS queries).
* ~~IPv6 connections~~: the real NAT table lists them too, so they are shown.
* Connections the gateway allowed, from the syslog (it logs only drops).
* Changing any gateway setting (everything here is read-only).

## 5. As implemented: where it differs from the plan

* **Periods.** One request covers at most **31 days** (`netmap.MaxRange`, `web.MaxNetworkSpan`):
  `range=1h|24h|7d|30d` (a period ending now, 24 h by default) or `from=`/`to=` (as for
  `/api/syslog`), ending at most an hour after the service's clock. `limit=` bounds the table rows
  (200 unless given, at most 1000). Only the connections are filtered by `device=`; the firewall
  view refuses it (400): the syslog names addresses, not devices.
* **Status.** `GET /api/network/status` also reports the syslog kept (`model.SyslogUsage`); the
  samplers in it come from the monitor's `Status.Connections`.
* **Connection store.** Two kinds of daily files instead of one line holding both:
  `nat-YYYY-MM-DD.jsonl` (one compact line per NAT read: the distinct strings once, six integers
  per session) and `devices-YYYY-MM-DD.jsonl` (one line per Device List read). A LAN address is
  named after the Device List read in effect at the NAT read (the newest at or before it, else the
  first after it; an address it does not list, after the next read within 20 minutes, so that a
  device that just joined is not counted twice), keyed by its MAC address (`mac:…`, so a device
  keeps its key when DHCP moves it), else `ip:<address>`; an address the read lists, or in the /64
  of a global IPv6 address it lists, is the home network's even when it is public (a device's IPv6
  sessions are its own); sessions without such a side are the gateway's own (`gateway`). At most
  200,000 distinct flows are counted one by one (the lightest beyond count only in their devices),
  so that a device scanning the Internet cannot make a query hold millions. The store applies its
  retention limits every hour through the monitor, also with the samplers off, and compresses the
  past days in the background after it opens.
* **Flow diagram.** The 12 heaviest organisations (not 15) and the 8 heaviest named services, the
  rest as "Other"; a band's width is its *weight* - the sessions seen over the reads (a connection
  open on three local ports in one read counts three) - not the number of samples. An organisation
  is keyed by the name the IP database gives it, not by its AS: one company's ASes (Google's
  AS15169 and AS36040) are one node, its tooltip listing them; a port without a name is named by
  its port alone ("8071/tcp").
* **Tiles.** Connections: devices active (how many of those in the gateway's newest Device List),
  sites, organisations (in how many countries), connections open now (or at the last read; under a
  device filter, that device's). Firewall:
  inbound blocked, sources (in how many countries), outbound blocked "from N devices" - exact:
  `outbound_devices` counts the distinct devices before the row limit - and the most probed
  service instead of the top country, which the world map shows.
* **Device colours.** A device keeps its colour while the page is open, in the order the devices
  first appear (8 colours); from the ninth device on they are grey and told apart by their names:
  colours never cycle, and neither a filter nor a refresh repaints a device.
* **Configuration.** `geo.url` became `geo.url_v4` and `geo.url_v6`; `geo.download` switches the
  download off (tables placed in `geo\` by hand are used); `connections.devices_interval` sets the
  Device List reads; limits: `interval` 2-4 min (the gateway client reuses its login session for 5
  minutes: a longer interval would need a login for every read), `devices_interval` 5 min to 24 h,
  `keep_days` 1-3650, `keep_mb` 10 to 1,048,576, `geo.refresh` 1-90 days; the download URLs carry
  no credentials, query or fragment (the configuration is recorded in the ledger). A value outside them, or one that
  cannot be read, never stops the service (these settings are not evidence): it is replaced - 0 or
  less by the default, a value beyond a limit by that limit, a bad URL by the default URL, a switch
  that is not true or false by off - with a warning in the service's log, in `GET
  /api/network/status` (`config_warnings`) and in `att-monitor network` (DESIGN §15).
* **Samplers.** Beyond the plan: the first NAT read comes once the startup settings check has been
  made, and a minute after the start at the earliest (the Device List 30 s), reusing the check's
  login; neither sampler reads during an incident, after a bad cycle or while the gateway did not
  answer the latest poll; a rejected access code (met by a NAT read or the settings check) stops
  the NAT reads until a code is stored anew, or for an hour; a read that fails otherwise than with
  the login page keeps the gateway client's session (no login per failing read), failing reads back
  off up to two hours, two reads in a row that each needed a login make the next wait an hour, and
  after 6 logins within a day the reads pause; the logins, the stop and the gateway client's login
  policy are kept in `state\` across restarts. The pages of the first read that worked, of a page
  not understood and of one with rows left out are copied to `connections\last-nattable.html` /
  `last-devices.html` (at most hourly; the Device List's without the Wi-Fi network's name), to
  check the parsers against the real firmware, and deleted once older than `keep_days` (at the
  start, with the samplers off). A read that worked but left rows out says so as a note
  (`nat_note`), not as a problem. The parser was written before the page could be captured, by
  the column labels a read-only tool reported; the deployed service's copy of the real page then
  matched it exactly (120 sessions as listed, the translated columns left aside) and became the
  sanitized fixture `nattable_real.html`.
* **Reverse DNS** names only the connections table's rows (not the firewall's sources): 3 lookups
  at a time, 3 s each (at most 8 running, counting those given up on), cached in
  `geo\ptr-cache.json` (at most 50,000 addresses; a name for 7 days, "no name" for a day, at most
  `keep_days`); an answer that has outlived that is never saved, and the file is deleted while
  reverse DNS or the IP database is off.
* **Firewall view.** syslog-ng's "repeated N times" lines count N more of the previous drop, also
  across chunk boundaries; the MAC field is never kept; an outbound drop's LAN address is named
  after the Device List read in effect when the drop was received (as the NAT reads' addresses
  are), not after the newest one; one view is built at a time (one connections view too), a view
  is reused for 30 s - for a period ending now, by its range - and the sealed chunks' summaries are
  cached (64 MiB, 16,384 chunks). Without a syslog store the Firewall tab explains that none is
  kept. Another site's page cannot make the service build a view: a cross-site read of the API is
  refused.
* **Wiring.** The service opens the connection store also with `connections.enabled` off - the
  samplers then do not run, the page shows what was recorded before and the retention limits keep
  deleting old samples - and the IP database also with `geo.enabled` off (it then only classifies
  addresses and names ports, and its status says it is off). A part that cannot be opened is
  logged, a setting that cannot be used is replaced (see *Configuration*): none of it can keep
  evidence collection from starting. Versions before 1.3.0 refuse a data directory holding
  `connections\` and `geo\`: going back to one needs them moved out first (README, *Upgrade*).
* **CLI.** `att-monitor network [--range 1h|24h|7d|30d | --from TIME --to TIME] [--device KEY]
  [--firewall] [--limit N] [--json]` instead of `--since`; it asks the running service (the
  connection store has a single writer) and fails with an explanation when the service is not
  running. A date alone as `--to` without `--from` is that local day (23 or 25 hours when the clocks
  change); a period is at most 31 days of 24 hours.
