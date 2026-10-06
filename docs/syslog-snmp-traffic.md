# Syslog, SNMP and traffic monitoring — design and plan

Status: approved by the owner's goals of 2026-10-05: "monitor the traffic and syslog and auto change
the router send the syslog and snmp to this machine"; "for the syslog only keep last 100mb and allow
user to choose keep how many syslog"; "if no snmp can you using Traffic counters to do a flow meter
or snmp flow chart". Built in the phases below: phase 1 is built and deployed; phase 2, the automatic
setting of the gateway's Syslog page, is built and waits for its deployment (2.3).

## 1. What was asked, and what it means here

| Asked | Understood as | Source |
|---|---|---|
| "monitor the traffic" | See how much the household sends and receives through the AT&T gateway, over time, on the dashboard, as evidence ("the line was idle when it failed", or "it was saturated") | owner |
| "if no snmp … use the traffic counters to do a flow meter or snmp flow chart" | An MRTG-style traffic graph (in/out bits per second over time, with current, average and maximum) built from the gateway's own counters, and a live flow meter (current Mb/s down and up) | owner |
| "monitor … syslog" | Receive the gateway's own log messages on this PC, keep them, show and search them on the dashboard | owner |
| "only keep last 100mb, allow user to choose" | Syslog messages are kept within a size limit, 100 MB by default, which the user can change (dashboard, CLI, config); the oldest messages go first | owner |
| "auto change the router send the syslog … to this machine" | The monitor sets the gateway's Syslog page itself (on, this PC's address, port 514, the most detailed level the gateway offers) and keeps it that way, like the outage-redirect setting; the owner can stop that (dashboard, CLI) | owner - built in phase 2 |
| "… and snmp to this machine" | SNMP polling or traps from the gateway | owner — **not possible, see §2** |
| Evidence rules still apply | What is kept is signed, chained and time-stamped (directly, or through a recorded SHA-256); verdicts do not change without a rules-version change; authenticated gateway requests stay rare and verified | assumption, from DESIGN.md |

## 2. Findings (2026-10-05, on the owner's BGW320-505, firmware 6.34.7; the real Syslog page from the phase-1 deployment)

| Question | Answer | Evidence |
|---|---|---|
| Can the BGW320 send syslog? | **Yes.** Diagnostics → Syslog (`/cgi-bin/syslog.ha`) with *Syslog* (on/off), *Server IP Address*, *Server Port*, *Log Level*. The page needs the login (Device Access Code). | the gateway's site map (49 pages); an unauthenticated GET of `syslog.ha` returns the Login page; BGW320-CLI's field list for that page |
| Can the BGW320 do SNMP? | **No.** No SNMP agent on the home network (UDP 161 answers "port unreachable" to a read-only `public` query) and no SNMP settings on any of its 49 pages; AT&T manages it from its own network (TR-069). Nothing can be pointed at this PC and no traps would ever be sent. | one SNMPv2c GET of `sysDescr.0`; site map |
| Where does traffic come from? | The gateway's own WAN counters on Broadband Status (IPv4 receive/transmit bytes and packets; the byte counters are 32-bit and wrap every 4 GiB), read every 60 s (15 s during incidents) and already turned into Mb/s for the classifier; per-radio Wi-Fi byte counters on Home Network Status (every 15 min); this PC's own 64-bit interface counters (`GetIfEntry2Ex`). | `testdata/gateway/broadbandstatistics.html`, `lanstatistics.html`, `internal/monitor/traffic.go` |
| What does the gateway's own log look like today? | Diagnostics → Logs shows only the firewall log (dropped packets), about 19 entries a minute. System events (PON, DHCP, link) are what syslog adds. | `evidence/bootstrap/initial-snapshot/logs.auth.html` |
| Is UDP 514 free on this PC? | Yes. | `netstat -ano -p UDP` |
| What does the real Syslog page look like? | Read by the phase-1 service (read only) and kept, its nonce replaced, as `testdata/gateway/syslog_real_off.html`: a form posting to `/cgi-bin/syslog.ha` with a hidden `nonce`; *Syslog* is a drop-down list `syslog` (Off/On) that submits the form when it changes, followed by a noscript **Update** button for browsers without JavaScript; then *Server IP Address* (`location`, at most 43 characters: IPv4, IPv6 or a name), *Server Port* (`port`, 514) and *Log Level* (`level`); **Save** and **Cancel**. | the recorded page (a `gateway_event` `syslog_setting`) |
| Can the page be set in one POST? | **No.** While Syslog is off the three fields are present but **disabled**, and a browser never submits a disabled control. The page says what to do: change the drop-down, then press **Update** ("This will transform the page according to the change you have made and you may then proceed"); the page it returns has the fields enabled; fill them in, then **Save**. The gateway client does the same (the *Update round*). How the gateway answers the Update and the Save (a 200 page or a redirect, a new nonce) has not been observed: both are handled, and only the page read back afterwards decides. | the page's own text |
| Which log levels? | Emergency, Alert, Critical, Error (selected while off), Warning, Notice - each option's value is its text - and **no Informational, no Debug**: the most detailed level this gateway offers is **Notice**. The page's help says it sends "firewall log messages" at the chosen severity; which messages arrive is learnt once it is set. | the page |

## 3. Design

### 3.1 The gateway's Syslog setting (read, then enforce)

* **Gateway client** (`internal/gateway`, built): a generic form reader that finds controls by their
  labels and posts forms back exactly as a browser without JavaScript would; `Syslog()` reads the
  page (authenticated, read-only, through the existing login policy); `SetSyslog(want)` changes only
  the syslog controls, makes the noscript *Update* round when the switch changes (the real page
  enables its fields only then: §2), saves from the page the gateway answered with, reads the page
  back and succeeds only if it shows `want`. It never posts a form it does not fully understand, nor
  a disabled control, nor enables one. Tested against the real page and pages derived from it.
* **Target:** Syslog on; Server IP = this PC's IPv4 address on the interface that reaches the
  gateway; Server Port = `syslog.port` (514); Log Level = `gateway.syslog_level`, else the level
  already set when syslog is on, else an option named like "Informational", else the most detailed
  option that is not "Debug" - **Notice** on the owner's BGW320-505 (firmware 6.34.7).
* **Monitor** (phase 2, built): the daily notification check reads the Syslog page in the same login
  session (and within minutes after this PC's address changes). Each read is a `gateway_event`
  `syslog_setting` (housekeeping) with the page as a blob. With `gateway.enforce_syslog` (default on)
  a page that shows anything else is set to the target in the same check, recorded with the pages
  before and after (a `gateway_event` `syslog_setting` and a `config_change`); a failed attempt is a
  `config_change` "failed: …" and the condition `SYSLOG_SETTING_FAILED`, and is tried again at the
  next check (enforcement adds no login of its own). `SYSLOG_NOT_ARRIVING` (info) says when no message
  from the gateway arrived for a day while it is set to send here.
* **Operator control** (phase 2, built): `SetGatewaySyslog` - the dashboard's Syslog page and Overview
  card ("Send the gateway's log to this PC" / "Stop sending", each confirmed first), `POST
  /api/gateway/syslog`, `att-monitor gateway syslog on|off`. On sets the page now and keeps it so; off
  switches it off on the gateway and stops keeping it. The choice is `gateway.enforce_syslog`, saved and
  recorded as a `config_change` when it changes.
* **Rollout safety:** met. Phase 1 read the real page on the owner's gateway, it is kept (sanitized) as
  a fixture, and the reader and `SetSyslog` are tested against it; the first real change is made by the
  deployed service (2.3), read back and recorded like every other.

### 3.2 Syslog receiver and the syslog store (kept within 100 MB)

* **Receiver** (`internal/syslogrx`, built): UDP `syslog.listen` (`:514`), only from the gateway's
  address (and `syslog.allow`), size, rate, stored-size (1 MiB of lines a minute) and buffer caps,
  exact bytes kept, RFC 3164 / 5424 parsed. The caps bound what a forged sender can add to the
  ledger (at most about one `syslog_chunk` record a minute).
* **Why not the ledger:** the ledger is append-only and hash-chained; nothing in it can ever be
  deleted, so it cannot honour a 100 MB limit. Messages therefore go to the **syslog store**, and the
  ledger keeps their proof:
* **Store** (`internal/syslogstore`, new; folder `syslog\` in the data directory): messages are
  appended (one JSON object per line, exact) to an open chunk file, flushed to disk every
  `syslog.flush_interval` (30 s). A chunk is sealed when it reaches 1 MiB or, at a flush, is 5 minutes
  old (and at shutdown): it is compressed (gzip) and its SHA-256 (of the uncompressed lines), message
  count, time range and size go into a ledger record **`syslog_chunk`**. A chunk left open by a crash
  (or while the ledger refused records) is sealed at the next start ("recovered"). The store notes
  which sealed chunks have their record, so one sealed while the ledger refused records is recorded
  once it takes records again - by the next start at the latest, after a search of the ledger so that
  none is recorded twice.
* **Retention:** after every seal the store deletes the oldest sealed chunks until it holds at most
  `syslog.keep_mb` MiB (default **100**), and, when `syslog.keep_days` is above 0, nothing older
  than that. Each deletion is a ledger record **`syslog_prune`** naming the deleted chunks and their
  SHA-256, written before the chunks are deleted (nothing is deleted while a chunk waits for its
  record). So the ledger shows what existed, when and why it was deleted; what is still kept is
  verifiable against its `syslog_chunk` record.
* **User choice:** the dashboard's Syslog page shows the space used and lets the user set how much
  to keep (MB, and optionally days); `att-monitor syslog retention --keep-mb N [--keep-days D]` does
  the same; both go through `SetSyslogRetention`, which saves the setting, records a
  `config_change`, applies it at once and prunes what no longer fits.
* **Reading:** `GET /api/syslog` reads the store (open and sealed chunks, newest first) with the
  filters, at most 5000 messages and 16 MiB of JSON per answer (a sender controls how long its
  messages are); entries name their chunk and its `syslog_chunk` record, looked up newest first. The
  dashboard shortens long messages in its list and shows each run of control characters as one
  escaped element; the exact datagram is shown on request.
* **Exports:** a bundle includes the kept chunks overlapping its period (`syslog/…jsonl.gz`);
  `att-monitor verify-bundle` and `tools/verify_bundle.py` check each against its `syslog_chunk`
  record (chunks already pruned are listed as such).
* **MongoDB:** the replicator copies the messages of each sealed chunk into collection `syslog` (one
  document per message, with its exact line) and deletes them when a `syslog_prune` record removes
  the chunk; as uncompressed documents take far more than the store's gzip chunks, the collection
  also keeps to `syslog.keep_mb` MiB of documents of its own, deleting its oldest chunks' documents
  beyond that; `mongo verify` checks them against the chunks.
* **Windows Firewall:** install adds an inbound rule (UDP 514, remote address = the gateway,
  program = the monitor); uninstall removes it.
* **Verdicts are unchanged:** syslog is supporting evidence; RulesVersion stays 2026.10-4.

### 3.3 Traffic: MRTG-style chart and flow meter

* **WAN traffic** from consecutive gateway snapshots (wrap- and reset-aware; "at least" when a byte
  counter may have wrapped more often than can be told), **this PC's traffic** from its interface
  counters, **daily volume** from complete counter deltas (built).
* **Traffic chart** (the "SNMP flow chart" without SNMP): MRTG-style — download as a filled area,
  upload as a line, in bits per second with automatic units; ranges 1 h to 7 d; under it the
  current, average and maximum of each direction for the range (MRTG's legend), the heavy-traffic
  line and "at least" markers; a table view and the daily totals.
* **Live flow meter** on the Overview: current download and upload rates (bars with numbers and a
  sparkline of the last ~15 minutes) while the dashboard is open. `GET /api/traffic/live` reads the
  gateway's Broadband Status counters on demand, at most once every 5 seconds whoever asks, plus this
  PC's counters, and keeps the last ~15 minutes in memory. It is a display only: nothing is recorded,
  and when nobody watches the gateway gets no extra requests. It never holds up the evidence: a read
  is skipped while the monitor itself reads the gateway, takes the gateway for at most 5 seconds, and
  is not made while the gateway does not answer the monitor's polls.

### 3.4 Configuration

```json
"syslog":  { "enabled": true, "listen": ":514", "port": 514, "allow": [],
             "flush_interval": "30s", "max_per_minute": 2000, "keep_mb": 100, "keep_days": 0 },
"gateway": { "...": "...", "enforce_syslog": true, "syslog_level": "" }
```

`gateway.enforce_syslog` (default true; the operator's choice changes and saves it) and `syslog_level`
(default "") came with phase 2. Several monitors on one home network would fight over the gateway's
setting: only one should enforce (README).

### 3.5 Safety and security

* Authenticated gateway requests: only through the gateway client's login policy; one login a day
  (plus one after this PC's address changes) for both settings.
* Every gateway change is read back and recorded with the page before and after; a form the reader
  does not fully understand is never posted.
* Syslog text is untrusted: sender filter, size/rate/buffer caps, a disk cap (the retention limit),
  JSON-escaped on disk, HTML-escaped in the dashboard, control characters shown escaped.
* The flow meter's extra reads are unauthenticated, rate-limited and only while someone watches.
* The firewall rule is limited to the gateway's address and the monitor's program.
* Syslog may name devices on the home network and remote addresses from firewall drops: it stays on
  the PC like all evidence (bundles go to AT&T, not the public).

## 4. Implementation plan

### Phase 1 — read-only, receiver, store, traffic (no gateway change)

| # | Task | Status |
|---|---|---|
| 1.1 | Shared types, contracts (`SyslogReceiver`, `SyslogReader`, `SyslogStore`, `SyslogControl`, `LiveTrafficSource`), config (`syslog.*` incl. `keep_mb`, `keep_days`; `syslog\` folder) | done |
| 1.2 | Gateway form reader, `Syslog()` read path, `SetSyslog` (tested on synthetic pages, no caller) | done |
| 1.3 | Syslog receiver (`internal/syslogrx`) | done |
| 1.4 | Traffic series, this PC's counters, daily volume | done |
| 1.5 | Dashboard first pass: Syslog page and card, traffic chart, daily totals (reading the old ledger batches) | done, revised in 1.8 |
| 1.6 | Syslog store with retention (`internal/syslogstore`) | done |
| 1.7 | Monitor: receiver → store → `syslog_chunk` / `syslog_prune` records, `SetSyslogRetention`, the Syslog page read in the daily check, `Status.syslog`, conditions, rebuild; live traffic (`LiveTraffic`) | done |
| 1.8 | Web: `/api/syslog` from the store, retention controls, MRTG-style chart, flow meter, `/api/traffic/live` | done |
| 1.9 | Exports and verifiers: chunks in bundles, checked against their records | done |
| 1.10 | MongoDB: `syslog` collection following the chunks and prunes; `mongo verify` | done |
| 1.11 | CLI and install: wiring, firewall rule, `gateway syslog status`, `syslog` (list), `syslog retention`; docs | done |
| 1.12 | Review (correctness, gateway safety and security, evidence and UX), fixes, full tests (`-race`, live MongoDB), e2e with test datagrams | done |
| 1.13 | Deploy (one UAC prompt): the service reads `syslog.ha` once (read-only) and records the page | done: the real page (§2) |

### Phase 2 — automatic setting

| # | Task | Status |
|---|---|---|
| 2.1 | Sanitize the captured `syslog.ha` into a fixture; test the reader and `SetSyslog` against it; adjust (the fields are disabled while Syslog is off: the Update round, then the Save from the transformed page) | done |
| 2.2 | Enforcement in the daily check, `gateway syslog on/off` (CLI, API, dashboard), `gateway.enforce_syslog` default on, `syslog_level` | done |
| 2.3 | Review, fixes, full tests; deploy (UAC): the gateway is set (event + config_change with before/after pages), messages arrive, are kept, counted against the limit, copied to MongoDB | |

### Phase 3 — reports and release

| # | Task |
|---|---|
| 3.1 | Ticket PDF and evidence report: the gateway's own syslog lines around each outage, traffic before each outage |
| 3.2 | README, DESIGN, PACKAGES; push; release v1.2.0 with the setup program |

## 5. Out of scope

* SNMP (not offered by the BGW320; see §2).
* Per-device traffic (the BGW320 shows no per-device counters; its NAT table counts sessions, not
  bytes).
* Changing verdicts from syslog content (needs a rules-version change and its own review).
