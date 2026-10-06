# Syslog, SNMP and traffic monitoring — design and plan

Status: approved by the owner's goal of 2026-10-05 ("monitor the traffic and syslog and auto change
the router send the syslog and snmp to this machine"); built in the phases below.

## 1. What was asked, and what it means here

| Asked | Understood as | Source |
|---|---|---|
| "monitor the traffic" | See how much the household sends and receives through the AT&T gateway, over time, on the dashboard, as evidence (for example: "the line was idle when it failed", or "it was saturated") | owner |
| "monitor … syslog" | Receive the gateway's own log messages on this PC, keep them as evidence in the ledger (and so in MongoDB and in bundles), show them on the dashboard | owner |
| "auto change the router send the syslog … to this machine" | The monitor sets the gateway's Syslog page itself (on, this PC's address, port 514) and keeps it that way, like the outage-redirect setting | owner |
| "… and snmp to this machine" | SNMP polling or SNMP traps from the gateway to this PC | owner — **not possible, see §2** |
| Evidence rules still apply | Everything recorded is signed, chained and time-stamped; nothing the gateway sends changes a verdict without a rules-version change; authenticated gateway requests stay rare and verified | assumption, from DESIGN.md |

## 2. Findings (2026-10-05, on the owner's BGW320-505, firmware 6.34.7)

| Question | Answer | Evidence |
|---|---|---|
| Can the BGW320 send syslog? | **Yes.** Diagnostics → Syslog (`/cgi-bin/syslog.ha`) with *Syslog* (on/off), *Server IP Address*, *Server Port*, *Log Level*. The page needs the login (Device Access Code). | the gateway's site map (49 pages); an unauthenticated GET of `syslog.ha` returns the Login page; BGW320-CLI's field list for that page |
| Can the BGW320 do SNMP? | **No.** It runs no SNMP agent on the home network and has no SNMP settings: UDP 161 answers "port unreachable" to a read-only `public` query, and none of the 49 pages mentions SNMP. AT&T manages it from its own network (TR-069). There is nothing to point at this PC, and no traps would ever be sent. | one SNMPv2c GET of `sysDescr.0`; site map |
| Where does traffic come from? | The gateway's own WAN counters on Broadband Status (IPv4 receive/transmit bytes and packets, 32-bit byte counters that wrap every 4 GiB), already read every 60 s (15 s in incidents) and already turned into Mb/s for the classifier's heavy-traffic rule; per-radio Wi-Fi byte counters on Home Network Status (every 15 min); this PC's own 64-bit interface counters from Windows (`GetIfEntry2Ex`). | `testdata/gateway/broadbandstatistics.html`, `lanstatistics.html`, `internal/monitor/traffic.go` |
| What does the gateway's own log look like today? | Diagnostics → Logs shows only the firewall log (dropped packets: Policy, Generic Discards, Invalid IP Packet), about 19 entries a minute. System events (PON, DHCP, link) are what syslog adds. | `evidence/bootstrap/initial-snapshot/logs.auth.html` |
| Is UDP 514 free on this PC? | Yes (no listener). | `netstat -ano -p UDP` |

SNMP is therefore dropped from the build; the data SNMP would have given (interface counters) comes
from the gateway's statistics pages and Windows instead (§3.3). The README and DESIGN say so.

## 3. Design

### 3.1 The gateway's Syslog setting (read, then enforce)

* **Gateway client** (`internal/gateway`): a generic form reader for the gateway's pages - every
  control of a `<form>` (inputs, checkboxes, radios, selects, buttons, the nonce) with its current
  value and its label (`<label for>` or the row's `<th>`) - and on top of it:
  * `Syslog(ctx) (model.SyslogSetting, raw []byte, err)`: authenticated, read-only, through the
    existing login policy (one attempt a minute, none after three rejections an hour; session reused
    for 5 minutes);
  * `SetSyslog(ctx, want model.SyslogTarget) (before, after []byte, err)`: reads the form, changes
    only the four syslog controls, posts the form back exactly as a browser would (all other controls
    as found, the nonce, the Save button; a noscript *Update* round first when the page reveals the
    server fields only after the switch is set), reads the page again and succeeds only when it
    shows the requested values (`ErrNotApplied` otherwise). **Fail closed:** a form without all four
    labelled controls, or with values outside their options, is never posted.
* **Target:** Syslog on; Server IP = this PC's IPv4 address on the interface that reaches the
  gateway (from the local-link check); Server Port = `syslog.port` (514); Log Level =
  `gateway.syslog_level`, or when empty: the level already set if syslog was on, else the option
  named like "Informational"/"Info", else the most detailed option that is not "Debug".
* **Monitor** (`internal/monitor`): the daily notification check becomes a *gateway settings check*
  that reads (and, when enforcing, sets) the redirect setting and then the syslog setting in the
  same login session. It also runs within a minute after this PC's address changes. Each check is a
  `gateway_event` `syslog_setting` (housekeeping) with the parsed setting and the exact page(s) as
  blobs; a change also writes a `config_change`. The dashboard shows a condition while the setting is
  unknown, wrong or could not be set.
* **Operator control:** `att-monitor gateway syslog [status|on|off]` and the matching API
  (`/api/gateway/syslog`), like the redirect setting: *off* switches it off on the gateway and stops
  enforcing (`gateway.enforce_syslog` false); *on* enforces again.
* **Rollout safety:** the write path ships in phase 2 only, after phase 1 has read the real page on
  the owner's gateway and the parser has been tested against that exact page (kept, sanitized, as a
  fixture).

### 3.2 Syslog receiver and evidence

* **Receiver** (`internal/syslogrx`, new): UDP listener on `syslog.listen` (`:514`). It accepts
  datagrams only from the gateway's address (or `syslog.allow`), up to 8 KiB, and keeps each
  message's exact bytes (as text when valid UTF-8, else base64) with its receive time. It parses
  RFC 3164 and RFC 5424 headers (PRI → facility and severity, timestamp text, host, app/tag,
  message) without ever rewriting the original. Datagrams from other senders are counted, not stored.
* **Records:** the monitor appends one ledger record of the new type `syslog` per batch: every 30 s,
  or at 500 messages. It holds the batch window, the source, the count, the number dropped by the cap
  and the messages. A cap of 2,000 recorded messages a minute keeps a flood from filling the disk;
  anything beyond it is counted as dropped, in the record. The records are evidence like any other:
  signed, chained, time-stamped, copied to MongoDB, included in bundles.
* **Windows Firewall:** install adds an inbound rule *AT&T Internet Monitor syslog* (UDP 514, remote
  address = the gateway, program = the installed exe); uninstall removes it. The service reports a
  condition when it cannot listen (port in use) or when no message has arrived for a day although
  the gateway is set to send.
* **Status and UI:** `Status.syslog` (listening, address, received, recorded, dropped, rejected
  senders, last message, the gateway setting and when it was checked). The dashboard has a "Gateway
  syslog" card on the Overview, a **Syslog** page (time range, severity and text filter, newest
  first) backed by `GET /api/syslog?from=&to=&q=&severity=&limit=` that reads the `syslog` records,
  and the messages of an incident's window on its incident page.
* **Verdicts are unchanged:** syslog is supporting evidence; RulesVersion stays 2026.10-4.

### 3.3 Traffic

* **WAN traffic** (download/upload Mb/s and packets/s): from consecutive gateway snapshots with
  counters, using the existing wrap- and reset-aware computation (a rate is marked "at least" when the
  32-bit byte counter may have wrapped more often than can be told). No new polling: the snapshot
  every 60 s (15 s during incidents) is the resolution.
* **Wi-Fi traffic per radio** (2.4 GHz, 5 GHz): from Home Network Status every 15 minutes, as Mb/s
  averages over those intervals.
* **This PC's traffic:** the local-link check (every 60 s) also reads the interface's 64-bit octet
  counters (`GetIfEntry2Ex`); the `local_link` records (every 10 min) carry the counters, and the
  live series uses every reading.
* **Dashboard:** a **Traffic** chart on the Overview (1 h to 7 d: WAN download and upload, this PC,
  the classifier's 80 Mb/s heavy-traffic line, "at least" points marked), daily totals (GB down/up per
  day, from counter deltas that are known to be complete), and the Wi-Fi radios on the Gateway page.
  `GET /api/series` gains `traffic` (per bucket: mean and peak WAN Mb/s, this PC's Mb/s, flags).
* **Evidence use:** the incident page states the WAN traffic in the 5 minutes before each incident
  (from the snapshots it names).

### 3.4 Configuration

```json
"syslog":  { "enabled": true, "listen": ":514", "port": 514, "allow": [],
             "flush_interval": "30s", "max_per_minute": 2000 },
"gateway": { "...": "...", "enforce_syslog": true, "syslog_level": "" }
```

`enforce_syslog` ships `false` in phase 1 and `true` from phase 2. Several monitors on one home
network would fight over the setting: only one should enforce (README).

### 3.5 Safety and security

* Authenticated gateway requests: still only through the gateway client's login policy; the
  settings check makes one login a day (plus one after this PC's address changes), shared by both
  settings.
* Every change is read back and recorded with the page before and after; a form the parser does not
  fully understand is never posted.
* Syslog text is untrusted input: size and rate caps, the sender filter, JSON-escaped in records,
  HTML-escaped in the dashboard and reports, control characters shown escaped.
* The firewall rule is limited to the gateway's address and the monitor's program.
* Syslog may name devices on the home network (names, MAC and IP addresses) and remote addresses
  from firewall drops: it stays on the PC like all evidence (bundles go to AT&T, not the public).

## 4. Implementation plan

Phases are built and tested in order. Within a phase, packages with no shared files are built in
parallel (multi-agent workflow), then integrated and reviewed.

### Phase 1 — read-only, receiver, traffic (no gateway change)

| # | Task | Files | Tests / acceptance |
|---|---|---|---|
| 1.1 | Shared types: `model.SyslogSetting`, `SyslogTarget`, `SyslogMessage`, `SyslogBatch`, `TypeSyslog`, `GwEvSyslogSetting`, `Status.Syslog`, `Series.Traffic`, `LocalLink` counters; `contracts.Gateway.Syslog/SetSyslog`; config `syslog` section and `gateway.enforce_syslog`/`syslog_level` with validation | `internal/model`, `internal/contracts`, `internal/config` | config tests (defaults, validation, old config.json gets defaults) |
| 1.2 | Gateway form reader + `Syslog()` read path (+ `SetSyslog` built and unit-tested against synthetic forms, not yet called by the monitor) | `internal/gateway/form.go`, `syslog.go` | synthetic BGW320-style forms (select / checkbox / radio switch, Update round, missing controls → refuse, unknown level), login-flow tests with httptest as for `events.ha` |
| 1.3 | Syslog receiver | `internal/syslogrx` | RFC 3164/5424 samples, invalid UTF-8, oversize, sender filter, flood cap, batching, clean shutdown; a loopback UDP test |
| 1.4 | Monitor integration: settings check (read only), receiver → `syslog` records, status, conditions, re-check on address change | `internal/monitor` | fakes: records written, batches capped, conditions, no POST in phase 1 |
| 1.5 | Traffic: series from snapshots, this PC's counters in the local-link check, daily totals, incident pre-window traffic | `internal/monitor`, `internal/probe` | wrap/reset/missing-counter cases, totals only from complete deltas |
| 1.6 | Web: Syslog card and page, `/api/syslog`, Traffic chart, Wi-Fi radios, incident additions | `internal/web` | API tests (filters, escaping), UI smoke via the browser |
| 1.7 | CLI and install: `gateway syslog status`, firewall rule add/remove in install/uninstall, `syslog` in `mongo`/docs | `cmd/att-monitor` | rule commands built and tested with a fake runner; real rule created during the upgrade |
| 1.8 | Review (correctness, security, evidence integrity), fixes, full tests (`-race`, live MongoDB), e2e with test syslog datagrams on a high port | all | everything green |
| 1.9 | Deploy to this PC (upgrade, one UAC prompt): the service reads `syslog.ha` once (read-only) and records the page | — | `gateway_event syslog_setting` with the page blob in the ledger |

### Phase 2 — automatic setting

| # | Task | Acceptance |
|---|---|---|
| 2.1 | Sanitize the captured `syslog.ha` into `testdata/gateway/syslog*.html`; test the form reader and `SetSyslog` against it; adjust | tests pass on the real page, both before and after states |
| 2.2 | Enforcement in the settings check, `gateway syslog on/off` (CLI, API, dashboard), `enforce_syslog` default `true` | fakes: set when wrong, not when right, re-set after IP change, off stops enforcing, failures become conditions |
| 2.3 | Review + fixes + full tests; deploy (UAC) | the service sets the gateway (event + config_change with before/after pages), syslog messages arrive and are recorded, `mongo verify` passes |

### Phase 3 — reports

| # | Task | Acceptance |
|---|---|---|
| 3.1 | Ticket PDF and evidence report: the gateway's own syslog lines around each outage (from the bundle's records), traffic before each outage | report re-derivation still verifies; wording reviewed against real messages |
| 3.2 | README, DESIGN (§7 records, §8 cadence, §12 API, §14 CLI, new §18), PACKAGES; push; release v1.2.0 with the setup exe | published, checksums match |

## 5. Out of scope

* SNMP (not offered by the BGW320; see §2). If a future firmware adds it, the settings check would
  show it in the site map and this plan gains a phase.
* Per-device traffic (the BGW320 shows no per-device counters; its NAT table counts sessions, not
  bytes).
* Changing verdicts from syslog content (needs a rules-version change and its own review).
