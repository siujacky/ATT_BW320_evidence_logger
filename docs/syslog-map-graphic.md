# Network map — which device talks to which site, and what the gateway's firewall blocks

Status: owner's goal of 2026-10-06 — "base on the syslog … show which ip is connect to which site, filter
by date to make the syslog in a graph / map. also try to show each lan computer connect to which ip /
service. make it simple and professional". Plan for the dashboard's new **Network** page.

## 1. What was asked, and what the gateway can give

| Asked | Source | Can it show it? |
|---|---|---|
| "which ip is connect to which site", from the syslog | The gateway's syslog (phase 2 of `syslog-snmp-traffic.md`) | **Partly.** The BGW320 at its most detailed level (Notice) logs only **firewall drops** (netfilter lines: `IN=`/`OUT=`, `SRC=`/`DST=`, `PROTO`, `SPT`/`DPT`, reason, hook). In the first 2,000 messages: 55 % inbound probes from the Internet (`IN=veip0.0`), 39 % outbound packets from the LAN that the gateway dropped (`IN=br1 OUT=veip0.0`, all but one from this PC), the rest local or invalid. It never logs connections it allows. |
| "each LAN computer connect to which ip / service" | The gateway's **NAT Table** (Diagnostics → NAT Table, `nattable.ha`): every active NAT session — Protocol, TCP State, Source Address/Port, Destination Address/Port, sessions in use/available | **Yes, for IPv4**, as samples: the table shows the sessions open at the moment it is read. It needs the login (an unauthenticated GET returns the Login page). IPv6 is not NATed and does not appear. |
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
  are not seen; IPv6 is not NATed).
* **Firewall** (from the syslog): tiles (inbound probes blocked, outbound packets blocked, sources,
  top country); a **world map** of where the blocked inbound probes came from; an hourly **timeline**
  (inbound / outbound); top sources (IP, organisation, country), most-targeted services, and LAN
  devices whose outbound packets were blocked (destination, port, reason).
* Visual language: the dashboard's existing tokens and type, one accent per meaning, light and dark
  mode, numbers right-aligned, a table view for every chart (accessibility), no external requests
  (the world map ships with the page: Natural Earth 1:110m country outlines, public domain,
  pre-projected to SVG paths).

## 3. Implementation plan

| # | Task | Package |
|---|---|---|
| 0 | Design preview (an artifact with sample data) for the page's look | — |
| 1 | Shared types and contracts; config `connections.*`, `geo.*`; data folders | model, contracts, config |
| 2 | NAT table and Device List readers (fixtures from the BGW320's markup; the NAT page needs the login) | gateway |
| 3 | Connection store with retention | connstore |
| 4 | IP intelligence: IPtoASN download/refresh/lookup, ports, PTR cache | ipintel |
| 5 | Firewall aggregation of the syslog (parser + per-chunk cache) | netmap |
| 6 | Samplers in the monitor (NAT every 4 min under the login policy; devices every 15 min); status | monitor |
| 7 | API endpoints and the Network page (flow diagram, world map, timeline, tables, filters) | web |
| 8 | Wiring, CLI (`att-monitor network [--since …]`), docs (README, DESIGN, PACKAGES) | cmd, docs |
| 9 | Review (gateway safety of the NAT reads, privacy, correctness, UX), fixes, tests, e2e | all |
| 10 | Deploy (one UAC prompt), check with the real NAT table, push, release v1.3.0 | — |

## 4. Out of scope

* Sites by DNS name (the gateway does not log DNS queries).
* IPv6 connections (not NATed, not in the NAT table).
* Connections the gateway allowed, from the syslog (it logs only drops).
* Changing any gateway setting (everything here is read-only).
