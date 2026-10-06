# att-monitor — AT&T Fiber outage evidence logger (Windows service)

Status: normative specification for v1. Code MUST follow this document; where the code
needs to deviate, update this document in the same change.

## 1. Purpose

Run continuously on a Windows PC behind an AT&T BGW320-505 gateway and produce
**evidence that can be shown to AT&T (or a regulator) proving whether connectivity
problems are on the provider's side**, with a complete chain of custody:

* *What* happened: every probe result, every gateway status page, every outage.
* *Whose side*: a deterministic, documented, versioned classification that separates
  provider faults (fiber/PON, WAN session, AT&T network) from local faults (PC, Wi-Fi,
  gateway unreachable) and says "undetermined" when the evidence does not support a call.
* *Integrity*: append-only, hash-chained, Ed25519-signed ledger; raw source bytes kept in a
  content-addressed blob store; periodic RFC 3161 time-stamps from independent public
  Time-Stamp Authorities (TSAs) prove the records existed at that time.
* *Custody*: genesis, monitor starts/stops, gaps, sleep/resume, clock checks, configuration
  changes, operator notes and evidence exports are all ledger records.
* A **localhost web dashboard** (http://127.0.0.1:8320) shows live status, history,
  incidents, evidence integrity, and builds verifiable evidence bundles.
* *Supporting evidence* (§18): the household's traffic from the gateway's own counters (an
  MRTG-style chart and a live flow meter; the gateway offers no SNMP) and the gateway's own syslog
  messages, kept outside the ledger within a size limit, with the SHA-256 of every chunk of them
  and every deletion recorded in the ledger.

## 2. Ground truth about this gateway (observed 2026-10-05, firmware 6.34.7)

* Nokia BGW320-505, AT&T Fiber (XGS-PON, 10 Gb/s line, "Lightspeed").
* Web UI at `http(s)://192.168.1.254/cgi-bin/<page>.ha`. HTTPS works (TLS 1.3, self-signed
  certificate, SHA-256 of the DER leaf observed: `49cd292d40af94d686b6ee17cb67ce4ded40e9c0be2b2537c7bc6e37cf9a2ed0`).
* **Certificate policy**: the gateway certificate is pinned on first use. A later change is recorded
  (`gateway_event cert_changed`) and status pages keep being read, but **authenticated requests are
  paused** (condition `GATEWAY_CERT_CHANGED`) until the operator confirms the new certificate
  (`trust-cert`): an impostor at 192.168.1.254 could otherwise collect MD5(access code + nonce).
  Login failures are persisted (state/) so a crash-looping service cannot exceed 3 attempts per hour.
* **Readable without login**: `sysinfo`, `broadbandstatistics`, `fiberstat`, `home` (slow, ~5 s),
  `lanstatistics` (slow, ~9 s), `sitemap`, `firewall`, `logs` (firewall drop log), `diag`.
* Login (only needed for configuration pages, e.g. `events`):
  1. GET any protected page in a new cookie session → `Set-Cookie: SessionID=…`, login page
     **without** nonce (cookie handshake). GET again → login page **with**
     `<input type="hidden" name="nonce" value="<64 hex>" />`.
  2. POST `/cgi-bin/login.ha` form: `nonce`, `password` = `*` × len(code),
     `hashpassword` = lowercase hex MD5(accessCode + nonce), `Continue=Continue`.
     Success = HTTP 302 with `Location` = the originally requested page.
  3. Pages that need login return a page whose `<title>` is `Login` (or contains
     "Access Code Required"). "all web server sessions are in use" means the session pool is
     exhausted → back off ≥ 5 minutes. **Authenticated requests must be rare** (≤ a few per day).
* `events.ha` → "Broadband Status Notification" checkbox `name="bbevent"`. When checked, the
  gateway "redirects web browsing users to instructional pages" while the WAN is down
  (outage hijack). It was turned OFF during setup (see evidence/bootstrap). Form POST to
  `/cgi-bin/events.ha`: `nonce`, `Save=Save`, plus `bbevent=on` only when enabling.
* `securityoptions` → 302 to `/cgi-bin/hiddenpage.ha` ("Page not found").
* `sysinfo` value rows: Manufacturer, Model Number, Serial Number, Software Version, MAC Address,
  First Use Date, Time Since Last Reboot (observed as plain seconds `274686`; help text claims
  `DD:HH:MM:SS` — accept both), Current Date/Time (gateway local time, no zone, e.g.
  `2026-10-04T22:10:44`; **blank when the WAN is down**), Hardware Version.
* `broadbandstatistics` rows: Broadband Connection Source (`FIBER`), Broadband Connection
  (`Up`/`Down`), Broadband Network Type, Broadband IPv4 Address, Gateway IPv4 Address (ISP
  next hop, answers ICMP), MAC Address, Primary/Secondary DNS (68.94.156.9 / 68.94.157.9),
  MTU, Ethernet Status (Line State, Current Speed (Mbps), Current Duplex), IPv6 block
  (Status, Service Type, Global Unicast IPv6 Address, Link Local Address, Default IPv6
  Gateway Address, Primary/Secondary DNS, MTU), IPv4 Statistics counters (Receive/Transmit
  Packets, Bytes, Unicast, Multicast, Drops, Errors, Collisions), GPON Status (PON Link
  Status e.g. `OPERATION (O5)`, UNI Status `up`). Labels repeat across sections (e.g. "MTU",
  "Primary DNS") → parse **per section** (nearest preceding `<h2>`/heading).
* `fiberstat`: Optical WAN Operational Status, Fiber Module, **Last Change** (Unix epoch
  seconds of the last optical link state change; changes even if a flap is shorter than the
  poll interval — semantics (UTC vs gateway-local epoch) unverified: store raw), Link State,
  SFP identity (Vendor Name/PN/SN, Wave Length), state flags (Rx LOS State, OPT LOS, Tx Fault
  …) and five DMI measurements, each rendered as
  `<h1>NAME Currently VALUE</h1>` followed by a table with rows Alarm/Warning and columns
  Low/High, cells like `1 (Threshold -295)`. First cell number = flag (1 = active).
  Units observed: Temperature °C, Vcc V (integer, lossy), Tx Bias mA, **Tx/Rx Power in
  0.1 dBm**. At setup time: Rx Power −315 (−31.5 dBm) with **Low Alarm = 1 (threshold −295)**
  and **Low Warning = 1 (threshold −292)** — the gateway itself flags the received optical
  level as below spec. This is provider-side evidence and must be prominent.
* `logs` is the firewall drop log (not a system event log). Diagnostics > Syslog (`syslog.ha`,
  behind the login; controls *Syslog* on/off, *Server IP Address*, *Server Port*, *Log Level*) sends
  the gateway's log to a syslog server. Earlier notes said it forwards only the firewall messages;
  which messages this firmware sends is learnt from what arrives once it is set (§18). The page has
  not been captured yet: the reader is tested on synthetic pages (testdata/gateway/README.md).
* **No SNMP**: UDP 161 answers "port unreachable" to a read-only SNMP query and none of the 49 pages
  of the site map has an SNMP setting (AT&T manages the gateway over TR-069). Traffic comes from the
  `broadbandstatistics` IPv4 counters instead (§18).
* Pages may be Latin-1 (copyright byte 0xA9). Never assume valid UTF-8; store raw bytes.

## 3. Threat model and what the evidence proves

The custodian (PC owner) controls the machine, so no local mechanism can stop a
determined administrator from fabricating data. The design therefore aims for
**tamper-evidence and contemporaneity**, not tamper-proofing:

1. **Hash chain**: every record commits to the previous one; edits, deletions, insertions and
   re-ordering break verification from that point on.
2. **Signatures (Ed25519)**: attribute records to this installation's key; the key is created
   at genesis and protected with Windows DPAPI (machine scope) plus file ACLs.
3. **External time-stamps (RFC 3161)**: the chain head is time-stamped by independent TSAs
   (default DigiCert and FreeTSA) every 30 minutes and right after each outage. A record
   covered by an anchor provably existed no later than the TSA's genTime. Back-dating or
   rewriting history older than the latest anchor is detectable by anyone. Only a SHA-256
   digest is sent to a TSA — no data leaves the machine.
4. **Primary-source data**: the decisive facts come from AT&T's own device (status pages,
   PON state, optical alarms, gateway clock, serial number), stored byte-exact and hashed.
   AT&T can correlate them with their own telemetry.
5. **Completeness**: monitor gaps (service stopped, PC asleep, crash) are explicit records;
   all healthy samples are kept (no cherry-picking); classification rules are versioned.

Out of scope: proving the identity of the human operator; protecting against kernel-level
compromise.

## 4. Architecture

Go module `attmonitor` (Go ≥ 1.27, Windows/amd64). Single binary `att-monitor.exe`.

```
cmd/att-monitor        CLI + service entry point; wires concrete implementations
internal/model         shared data types (ledger payloads, status, incidents)   [contract]
internal/contracts     shared interfaces between packages                     [contract]
internal/config        configuration file, defaults, paths, access-code DPAPI
internal/secret        DPAPI protect/unprotect (Windows crypt32)
internal/ledger        hash-chained signed ledger, blob store, keys, verification
internal/anchor        RFC 3161 TSA client + token verification
internal/gateway       BGW320 HTTP(S) client (pinning, login), page parsers, derive
internal/probe         ICMP (IcmpSendEcho), traceroute, TCP, DNS, HTTP, SNTP, local link
internal/monitor       scheduler, classifier, incident state machine, gateway events, series
internal/web           localhost HTTP server, JSON API, embedded static dashboard
internal/export        evidence bundle (zip) + HTML report; bundle verification
internal/winsvc        Windows service runner/installer, event log, power events
internal/ticket        AT&T service-ticket report (HTML, printed to PDF by Edge/Chrome)
internal/mongostore    MongoDB copy of the ledger + its verifier (§17)
internal/syslogrx      syslog receiver: UDP, sender filter, size/rate caps, RFC 3164/5424 parsing (§18)
internal/syslogstore   syslog store: chunk files within syslog.keep_mb / keep_days (§18)
tools/verify_bundle.py standalone third-party verifier (Python 3 stdlib + optional extras)
```

**Dependency rule.** Packages depend on `model`, `contracts`, the standard library and the
approved modules (`golang.org/x/sys`, `golang.org/x/net`, `github.com/digitorus/timestamp`,
`github.com/digitorus/pkcs7`, and for `internal/mongostore` only the official MongoDB driver
`go.mongodb.org/mongo-driver/v2`). A package never imports another implementation package
except: `cmd/att-monitor` (imports everything), `config` → `secret`. Consumers use the
interfaces in `contracts`; producers assert conformance at compile time, e.g.
`var _ contracts.Ledger = (*Store)(nil)`.

## 5. Data directory (default `C:\ProgramData\ATTMonitor`)

```
config.json                       configuration (no secrets)
keys/                             PRIVATE: SYSTEM + Administrators only (protected DACL)
keys/ledger-signing.key           JSON {alg:"ed25519", protected:"<b64 DPAPI blob of 32-byte seed>",
                                        public:"<b64>", created:"<RFC3339>"}
keys/gateway-access-code.dpapi    DPAPI (machine scope) blob of the gateway device access code
keys/ledger-signing.pub.txt       public key (base64) + fingerprint, for humans
ledger/ledger-YYYY-MM-DD.jsonl    one segment per UTC day (active segment append-only)
ledger/ledger-YYYY-MM-DD.jsonl.gz sealed segments older than 2 days may be gzip-compressed;
                                  all hashes refer to the UNCOMPRESSED bytes
blobs/<aa>/<sha256>.gz            content-addressed raw evidence (gzip of exact bytes)
exports/                          evidence bundles produced on request
quarantine/                       bytes removed during crash recovery (never deleted)
state/                            caches (incident index, series) — NOT evidence, rebuildable
logs/service.log                  operational log (rotated) — NOT evidence
syslog/                           the syslog store (§18), the only evidence that is ever deleted
                                  (within syslog.keep_mb / keep_days, every deletion recorded):
syslog/open-<from>.jsonl          the open chunk: one model.SyslogMessage JSON line per message
syslog/open-<from>.state.json     its dropped/rejected counts
syslog/syslog-<from>_<to>.jsonl.gz       a sealed chunk (gzip of the open chunk's exact bytes)
syslog/syslog-<from>_<to>.jsonl.gz.json  its sidecar: an index (its syslog_chunk payload and, once
                                  recorded, the seq of that record), rebuilt from the chunk when
                                  missing — NOT evidence
```
ACL (set by `install`): SYSTEM and Administrators full control, Users read & execute — except
`keys\`, which is SYSTEM + Administrators only (re-asserted at every service start). Machine-scope
DPAPI can be decrypted by any local account that can read the blob, so the secrets' protection
against other local users comes from that ACL.

## 6. Ledger format (normative)

Each line of a segment is one JSON object (an *envelope*), terminated by `\n`:

```json
{"h":"<sha256 hex of b>","s":"<base64 std Ed25519 signature over the bytes of b>","b":"<body JSON as a string>"}
```

`b` is the body serialized once by the writer; **hashes and signatures cover the exact UTF-8
bytes of the string `b`**, so verification never depends on JSON canonicalization (any
language: parse the line, take `b`, SHA-256 it). The body:

```json
{"v":1,"seq":42,"prev":"<h of seq 41, or 64 zeros for genesis>","ts":"2026-10-05T03:20:00.123456789Z",
 "mono":123456789,"run":"<run id>","type":"sample","blobs":["<sha256>",...],"data":{...}}
```

* `seq` starts at 0 (genesis) and increases by exactly 1. `prev` = `h` of the previous record.
* `ts` = wall clock UTC (RFC 3339, nanoseconds) when the record was created. Never altered.
* `mono` = nanoseconds since this process started, from the monotonic clock (with `run`
  it orders and times records immune to wall-clock changes). `run` = random 128-bit hex id
  per process start.
* `blobs` (optional) lists every blob referenced by `data` so verifiers can check them.
* Segment file = UTC date of `ts` of its first record. Rotation happens when a record's UTC
  date is later than the active segment's date; never reopen an older segment (if the clock
  goes backwards, keep writing to the current segment and log `clock_jump`).
* The first record of every non-first segment has type `segment_open` with data
  `{segment, prev_segment, prev_segment_sha256 (of complete uncompressed file bytes),
  prev_segment_records, prev_segment_last_seq}`.
* Writes: single writer goroutine (mutex), write line, `fsync` (File.Sync) before returning.
  Blobs are written (and fsynced) before any record that references them.
* Exclusive writer lock: `ledger/.lock` held with LockFileEx for the process lifetime.
* Crash recovery on open: if the active segment does not end in `\n` or its last line fails to
  parse/verify, truncate to the end of the last valid line, copy removed bytes to
  `quarantine/<segment>.<offset>.tail`, then append a `recovery` record
  `{segment, offset, removed_bytes, removed_sha256, reason}`. Never silently discard.
* If on open the existing chain does not verify (tampering), append `integrity_alert` with
  details and continue chaining from the last line as found.
* Robustness details (as implemented): a line whose hash matches and whose signature verifies is
  **never** truncated, whatever its content — its problems go into an `integrity_alert`. Before
  bytes are quarantined, a write-through marker `quarantine/<file>.pending` (the recovery record)
  is written; it is removed once the record is durable, and leftover markers are recorded on the
  next start. Segment files are created atomically (temp + fsync + MoveFileEx write-through).
  Open refuses to start when the signing key is missing or belongs to another ledger.
  `integrity_alert` is also written when a corrupt blob is quarantined and replaced, when a
  compressed segment copy does not match its segment, and when a foreign file occupies the next
  segment's name. Data inside `b` is encoded without HTML escaping (hashes cover `b` as written).
  Failure details are capped at 512 bytes; failures are listed in ledger order (max 200, all counted).
  Verifying an empty reader fails; outside the live ledger an incomplete final line is a parse error.

Blob store: `PutBlob(b)` → id = hex SHA-256 of exact bytes; path `blobs/<id[0:2]>/<id>.gz`;
deduplicated; written to a temp file, fsynced, renamed. `GetBlob` decompresses and re-checks.

Keys: Ed25519 seed from crypto/rand; protected with DPAPI `CryptProtectData` using
`CRYPTPROTECT_LOCAL_MACHINE` and fixed entropy `"att-monitor ledger key v1"`. Fingerprint =
hex SHA-256 of the 32-byte public key (display as 16 groups of 4).

Verification (`att-monitor verify`, web "Verify", bundle verifier) reports: record count;
first/last ts; per-type counts; every failure with seq/segment/line (hash mismatch, bad
signature, seq gap, prev mismatch, segment hash mismatch, missing/corrupt blob, anchor
mismatch); anchors (TSA, genTime, covered seq); unanchored tail; monitor gaps (> 3× fast
interval between samples) with explanation from adjacent records; clock jumps.

**Record times vs. trusted time-stamps** (`ts_contradiction`, tolerance 5 min): an anchor record holds
SHA-256(token), so it and every later record were written after the token's genTime — a record dated
more than 5 min before the latest trusted genTime preceding it fails (back-dating); and a token over
`head_seq` proves records 0…head existed at genTime — a covered record dated more than 5 min after
it fails (forward-dating). Only anchors accepted as proof of time are used; contradictions over
consecutive anchoring windows form one failure per period. Record times going backwards, dates before
genesis, SNTP offsets over 5 min and gaps whose end samples carry unreliable times are reported as
notes. At Open the writer adds an `integrity_alert` when the clock is more than 5 min behind the newest
record ("the computer's clock is behind the newest ledger record"). Back-dating that stays entirely
after the newest trusted time-stamp cannot be proven false by any time-stamp (stated limit).

## 7. Record types (payload structs live in `internal/model`)

| type | when | data |
|---|---|---|
| `genesis` | ledger creation (seq 0) | public key, fingerprint, host, software, statement |
| `segment_open` | first record of a new daily segment | see §6 |
| `bootstrap_import` | once, after genesis, if `bootstrap_dir` exists | files {path, sha256, size, mtime}, notes text; files stored as blobs |
| `monitor_start` | each process start | software (version, exe sha256), host, config sha256 (secrets removed), previous head, gap since last record |
| `monitor_stop` | graceful stop | reason, uptime |
| `heartbeat` | every 15 min | counters, ledger head |
| `sample` | every fast cycle (10 s) | probe results + verdict (§9) |
| `state_change` | verdict state/cause changes | from, to, at, reasons |
| `gateway_snapshot` | gateway poll (60 s; 15 s during incidents) | page captures (status, timing, sha256, stored?, TLS cert), parsed sysinfo/broadband/fiber, derived |
| `gateway_event` | derived transitions; plus a daily `notification_setting` confirmation (before == after, "confirmed unchanged") as evidence the redirect stayed OFF; plus a `syslog_setting` for every read of the gateway's Syslog page (§18, housekeeping) | kind (reboot, firmware_change, wan_ip_change, broadband_state, pon_state, optical_alarm, optical_link_change, counters_reset, cert_pinned, cert_changed, gateway_clock, notification_setting, syslog_setting), before/after, evidence (the page read, as a blob) |
| `service_check` | DNS + HTTP checks (60 s; 15 s during incidents) | DNS results (gateway/ISP/public resolvers, hijack detection; a failed query is retried once, so a resolver can have two results), HTTP results (TLS leaf hash) |
| `local_link` | at start, on change, every 10 min, at incident open, and re-recorded (unchanged) during incidents or while Wi-Fi is down before the previous record goes stale | interface, type (wifi/ethernet), SSID, BSSID, signal %, RSSI, channel, rates, raw blob |
| `traceroute` | incident open, every 5 min during, close | target, hops |
| `clock_check` | start + hourly | SNTP offsets from several servers |
| `clock_jump` | wall vs monotonic divergence > 2 s between cycles; also between runs (first answered SNTP check vs the previous run's last, `between_runs`) | wall delta, mono delta, detail |
| `incident_open` / `incident_update` / `incident_close` | §10 | incident struct |
| `anchor` | §11 | TSA url/name, head seq/hash, token sha256 (blob), genTime, serial, policy |
| `config_change` | gateway or monitor configuration changed (incl. the syslog retention, §18) | what, before, after, actor, evidence blobs |
| `syslog_chunk` | the syslog store sealed a chunk (§18) | `model.SyslogChunk`: name, from/to (receive times of its first and last message), messages, dropped, rejected, bytes and sha256 of the uncompressed content, gz_bytes, reason (size, age, stop, recovered) |
| `syslog_prune` | the retention limits deleted chunks (§18) | `model.SyslogPrune`: reason ("keep_mb N", "keep_days N" or both), keep_mb, keep_days, deleted [{name, sha256, from, to, messages, gz_bytes}], kept_bytes, kept_chunks |
| `power_event` | suspend/resume/shutdown notifications | kind |
| `custody_export` | evidence bundle produced | range, file name, bundle sha256, manifest sha256, prepared_by, notes |
| `operator_note` | user note (e.g. AT&T ticket number) | text, author |
| `recovery`, `integrity_alert` | §6 | details |
| `config_state` | right after the first record of each new daily segment (the ledger writes `segment_open` inside that append) | effective config (secrets removed), its SHA-256, rules version — so every daily segment (and bundle) states the thresholds in force |

## 8. Probes and cadence (defaults; all configurable)

Fast cycle every **10 s** — all in parallel, each ≤ 2 s timeout:
* `gateway_icmp` ICMP echo to the gateway LAN IP (Windows `IcmpSendEcho`, no admin needed).
* `gateway_tcp` TCP connect to gateway:443 (distinguishes "ICMP rate limited" from down).
* `isp_hop_icmp` ICMP to the ISP next hop = latest snapshot `Gateway IPv4 Address`.
* `inet_icmp_*` ICMP to 1.1.1.1 (Cloudflare), 8.8.8.8 (Google), 9.9.9.9 (Quad9).
* `inet_tcp_*` TCP connect to 1.1.1.1:443 and 8.8.8.8:443.
Probe results record ok, RTT in microseconds (measured around the call), Windows IP_STATUS
name for ICMP failures, the replying address, TTL.

Gateway poll every **60 s** (15 s while an incident is open, plus immediately when a cycle
first fails): `broadbandstatistics`, `fiberstat`, `sysinfo` (sequential, unauthenticated,
HTTPS + pin). `lanstatistics` every 15 min. Raw bodies are stored as blobs when: an incident
is open, a material field changed (broadband state, PON state, optical flags, WAN IP, uptime
reset, firmware, Last Change), or 5 min elapsed since that page was last stored. The SHA-256
of every fetched body is always recorded.

Service checks every **60 s** (15 s during incidents):
* DNS A query for `www.google.com` via the gateway (192.168.1.254), via the ISP resolver
  (snapshot Primary DNS), and via 1.1.1.1 — record rcode, answers, RTT, raw response (base64).
  **Hijack detection**: an answer for a public name that is the gateway IP or any
  private/loopback/link-local address, or any answer for `<random>.invalid` → `hijacked=true`.
* HTTP GET `http://www.msftconnecttest.com/connecttest.txt` without following redirects;
  expected 200 and body `Microsoft Connect Test`; record remote IP, status, Location, body
  sha256 and first 512 bytes. A redirect/answer from the gateway = HTTP hijack observed.
* HTTPS GET `https://www.google.com/generate_204` expecting 204.

Local link every 60 s (recorded on change / every 10 min / at incident open):
`netsh wlan show interfaces` (raw output stored as blob, parsed SSID/BSSID/signal/channel/
radio/rates/state) or, for Ethernet, the default-route adapter name/link speed/status.

Clock: SNTP to time.windows.com, time.google.com, pool.ntp.org at start and hourly; the
gateway's own clock (sysinfo Current Date/Time, local zone) is also compared each snapshot.

Syslog and traffic (§18): the receiver listens all the time; every `syslog.flush_interval` (30 s)
what it received goes into the syslog store; a chunk is sealed at 1 MiB, at the first flush 5
minutes after it was opened and at shutdown (each a `syslog_chunk` record), and the store is pruned
after every seal, at start, on a retention change and, with `keep_days`, at least hourly (each
deletion a `syslog_prune` record). The gateway's Syslog page is read (authenticated) in the daily
settings check right after the notification setting, in the same login session, and again when
this computer's address toward the gateway changes (at most every 10 min). Traffic rates come from
the counters of the recorded snapshots; the dashboard's flow meter reads `broadbandstatistics` on
demand only (at most every 5 s whoever asks, unrecorded).

## 9. Classification rules (normative, `RulesVersion = "2026.10-4"`)

Inputs for each fast cycle: the cycle's probe results, the latest gateway snapshot (fresh
if ≤ 150 s old), the latest service check (≤ 150 s), the latest local link (≤ 150 s), and the
window = the last `WindowCycles` (6) cycles including this one.

Definitions:
* `LAN` = gateway_icmp OK **or** gateway_tcp OK **or** gateway_tcp Status `refused` (a TCP RST
  proves the gateway's IP stack answered).
* *Providers* = the distinct target IP addresses of the internet probes (default 1.1.1.1
  Cloudflare, 8.8.8.8 Google, 9.9.9.9 Quad9 — ICMP and TCP probes to the same IP form one provider).
* `INET_ANY` = any internet probe OK in this cycle.
* *Outage cycle* = a cycle classified by rule 1 or 2 below. *Provider window loss* = failed
  probes / probes of that provider over the window's cycles that are **not** outage cycles
  (total outages are already outages; counting them again would stretch every outage by the
  window length).

1. **not LAN** → state `LOCAL_FAULT`, cause `GATEWAY_UNREACHABLE`, attribution `undetermined`
   (if the local link reports Wi-Fi disconnected: cause `LOCAL_LINK_DOWN`, attribution `local`).
2. **LAN and not INET_ANY** → state `ISP_OUTAGE`, attribution `provider`, cause:
   * fresh snapshot shows PON not `O5`, or Optical WAN status not `Up` → `FIBER_LINK_DOWN`;
   * else fresh snapshot shows Broadband Connection `Down` or no WAN IPv4 → `WAN_DOWN`;
   * else ISP next hop known and its ICMP failed → `ISP_EDGE_UNREACHABLE`;
   * else → `UPSTREAM_UNREACHABLE`.
3. **LAN and INET_ANY**:
   * at least `min(2, number of providers)` providers have window loss ≥ `LossDegradedPct`
     (20 %) → `DEGRADED`/`PACKET_LOSS` (one unreachable destination can never implicate the ISP);
   * median RTT of the successful internet probes over the window's non-outage cycles >
     `LatencyDegradedMs` (150 ms) while the gateway's median RTT < `GatewayLatencyOkMs` (20 ms)
     → `DEGRADED`/`HIGH_LATENCY`;
   * latest service check: ISP resolver failed while a public resolver answered →
     `DEGRADED`/`ISP_DNS_FAILURE`; gateway DNS failed while the ISP resolver answered →
     `DEGRADED`/`GATEWAY_DNS_FAILURE`;
   * attribution for DEGRADED: `provider` if the gateway probes had 0 % loss over the window
     (a `refused` gateway TCP counts as success), else `undetermined`;
   * otherwise `ONLINE` (attribution `none`).
Cycles with no gateway-role or no internet-role probe results are `UNKNOWN` (neither good nor
bad; excluded from availability).

Rules 2026.10-4 refinements (all conservative — each removes a way to blame AT&T wrongly):
* **DNS**: a resolution query that gets no valid answer is retried once within its check (both
  results are recorded); the DNS rules apply only when the **same failure appears in two consecutive
  service checks** (≤ 150 s apart). One lost UDP datagram never implicates the ISP.
* **Egress (VPN / other network)**: every `local_link` record carries a route check (`egress`: the
  route to the gateway and to each destination, via `GetBestRoute2`). While any destination is routed
  past the gateway (VPN tunnel, second adapter, hotspot), rule 2 gives `LOCAL_FAULT`/`LOCAL_ROUTE`/
  `undetermined` (unless the gateway itself reports fiber/WAN down) and `DEGRADED` is `undetermined`;
  condition `EGRESS_NOT_VIA_GATEWAY`. Limits: per-application tunnels are not detected; IPv6
  destinations are not checked.
* **Household traffic**: `DEGRADED` is attributed to the provider only when the gateway's own WAN
  counters (two latest snapshots ≤ 5 min apart; 32-bit byte counters with a packet-based wrap check)
  show **less than 80 Mb/s in both directions** — otherwise the household's own traffic could explain
  the congestion and the verdict is `undetermined`. Rates and snapshot seqs are stated in the reasons.
* **Interrupted cycles**: a cycle whose monotonic duration exceeds probe timeout + grace +
  max(fast/2, 1 s) (e.g. the PC slept while probes were in flight) is `UNKNOWN`.
* Verdict `inputs` also name the previous service check (DNS rule) and the two snapshots of the
  traffic rate.
Every verdict carries `reasons` — short factual sentences (e.g. "gateway 192.168.1.254 answered
ICMP in 1.9 ms", "AT&T gateway reports Broadband Connection: Down", "0/5 internet probes
succeeded").

**Conditions** (shown on the dashboard, recorded via `gateway_event`, independent of state):
`OPTICAL_RX_LOW_ALARM`, `OPTICAL_RX_LOW_WARNING`, `OPTICAL_RX_HIGH_*`, `OPTICAL_TX_*`,
`TEMPERATURE_*` — taken **only** from the gateway's own alarm flags; plus `NOTIFICATION_REDIRECT_ON`
(the gateway's outage redirect is enabled), `GATEWAY_CERT_CHANGED` (critical: authenticated operations
paused until the operator confirms the new certificate), `NO_ACCESS_CODE` (info: the redirect
setting cannot be checked), `ANCHOR_UNTRUSTED` (warning: the newest time-stamps could not be
chain-verified, so they do not count as proof of time), `EGRESS_NOT_VIA_GATEWAY` (warning: traffic
bypasses the gateway), `LEDGER_WRITE_FAILING` (critical: records are being refused — the service exits
so Windows restarts it), `DISK_SPACE_LOW` (warning < 2 GiB, critical < 512 MiB), `CLOCK_OFFSET`
(warning > 60 s, critical > 5 min SNTP offset), `SYSLOG_RECEIVER_DOWN` (warning: the syslog receiver
cannot listen, e.g. another program uses UDP 514) and `SYSLOG_STORE_FAILING` (warning: the syslog
store fails). Optical alarm conditions date from their first report. Syslog and the flow meter never
change a verdict (§18).

## 10. Incidents

* A cycle is *bad* when its state is not `ONLINE` (and not `UNKNOWN`). Open an incident when
  **at least `OpenAfterCycles` (3) bad cycles fall within the last `WindowCycles` (6) cycles** —
  this covers both a continuous outage and intermittent "flapping" connectivity; `opened` = the
  start of the earliest of those bad cycles. Close after **`CloseAfterCycles` (3) consecutive good
  cycles**; `closed` = start of the first good cycle of that streak. `recovered_at` = start of the
  first cycle after the last outage cycle in which every probe succeeded.
* Bad cycles that never lead to an incident are *blips* (counted, visible in samples and
  `state_change` records).
* Time accounting counts cycles, not wall-clock spans: each cycle covers the time until the next
  cycle started, capped at 1.5 × `FastInterval` (time beyond that is a monitoring gap, see §6).
  `downtime_s` = time of `ISP_OUTAGE` cycles, `degraded_s` = time of `DEGRADED` cycles — per
  incident and per statistics window. `provider_outage_s` = time of provider-attributed
  `ISP_OUTAGE` cycles. An intermittent incident therefore reports its true time without Internet,
  not its whole duration.
* A monitoring gap (> 3 × `FastInterval` between cycles, e.g. sleep) closes an open incident at
  its last observation, stating that the outcome during the gap is unknown.
* Incident severity order for its headline classification:
  `ISP_OUTAGE` > `LOCAL_FAULT` > `DEGRADED`; cause = most specific cause seen at the highest
  state; all causes seen are listed. Attribution = `provider` if the headline state is
  `ISP_OUTAGE` or a provider-attributed `DEGRADED`, `undetermined`/`local` otherwise.
* **Gateway restarts** (rules 2026.10-3). A restart is detected from the gateway's own uptime
  (boot time B = fetch time − uptime moved > 120 s, or uptime fell without elapsed time explaining it).
  The *restart window* runs from B (minus the time the gateway was unreachable just before, i.e. the
  power-off/boot period) until the first cycle after B in which the Internet is reachable again,
  capped at B + 10 min. Bad cycles inside a restart window count as `restart_s`, **not** as provider
  downtime (`downtime_s` / `provider_outage_s` exclude them). An incident whose window contains a
  restart is attributed `provider` only if it has provider-attributed bad cycles **outside** restart
  windows (e.g. the outage existed before the owner power-cycled the gateway, or persisted more than
  10 min after it); otherwise (and provided at least one bad cycle lies inside a restart window) its
  state is recorded as `LOCAL_FAULT` with cause `GATEWAY_REBOOT` and attribution `undetermined`, or
  `provider` if the firmware version changed across the restart ("AT&T-pushed firmware update").
  Boot times are listed in `gateway_restarts`. Samples keep their real-time verdicts (immutable);
  the restart annotation is applied in incident records (incident_update/close) and reports.
* Rules 2026.10-4: a restart belongs to **every** incident with a bad cycle in its restart window, the
  window being computed over every recorded cycle (so a boot that happened before the incident's
  first observed bad cycle — e.g. a home power failure that also stopped this PC — is attached); a
  restart incident is `provider` only with **at least `OpenAfterCycles` provider-attributed bad cycles
  outside** the restart windows (fewer are stray cycles of the restart's own shutdown/bring-up); an
  interrupted incident closes at the end of its last bad cycle's coverage; incidents left open by a
  previous run are rebuilt from the ledger at startup and stay on a reboot watch until an uptime
  reading decides them.
* Clarifications: blips are counted as episodes (runs of bad cycles outside incidents); `UNKNOWN`
  cycles occupy window slots but are neither good nor bad; `recovered_at` is set only for incidents
  with an outage cycle; a wall-clock step past the gap limit closes an open incident like a gap.
* While an incident is open, an `incident_update` is written right after the first record of each
  new daily segment (after that segment's `config_state`), so every daily segment covered by an
  incident contains a record of it.
* Each sample's verdict carries `inputs` (seqs of the snapshot, service check and local link it used,
  window size) so any third party can recompute it from the ledger.
* On open: immediate gateway snapshot (raw stored), service check, local link, traceroutes to
  8.8.8.8 and 1.1.1.1 (max 15 hops, 1 s per hop). During: snapshots/checks every 15 s,
  traceroute every 5 min. On close: snapshot, traceroute, then an immediate anchor.
* Incident id: `INC-YYYYMMDD-HHMMSSZ` from `opened` (UTC).
* Incidents carry evidence references (ledger seqs + blob ids) and statistics
  (cycles, bad cycles, per-probe success, gateway observations).

## 11. Anchoring (RFC 3161)

Every 30 min while the Internet is reachable (ONLINE or DEGRADED), immediately after an incident closes, after genesis/bootstrap and
after an export: digest = the 32 raw bytes of the current head hash `h`. Request a token with
`certReq=true` and a random nonce from each configured TSA (default
`http://timestamp.digicert.com`, `https://freetsa.org/tsr`; SHA-256). Store the DER response
as a blob and append an `anchor` record per TSA. Verify the token (imprint == digest, nonce,
CMS signature with embedded certificate, and chain to the Windows root store when
available). Failures are logged operationally; retry at the next opportunity. While offline,
anchors are deferred; the first anchor after recovery covers the whole outage.

## 12. Web UI and API

Listen `127.0.0.1:8320` only. Reject requests whose Host is not `127.0.0.1:<port>`,
`localhost:<port>` or `[::1]:<port>` (DNS-rebinding defense). State-changing requests (POST)
require header `X-ATT-Monitor: 1` and, if present, an Origin equal to the server origin.
Responses: `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`,
`Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'`.
Static assets are embedded (`embed.FS`), no external URLs (the UI must work during outages).

| method/path | purpose |
|---|---|
| GET `/` and `/static/*` | single-page dashboard |
| GET `/api/status` | `model.Status` |
| GET `/api/series?range=1h\|6h\|24h\|7d` | `model.Series` |
| GET `/api/incidents?from=&to=` | `[]model.Incident` (newest first) |
| GET `/api/incidents/{id}` | incident + evidence records |
| GET `/api/records?from_seq=&limit=&type=` | raw ledger envelopes + parsed bodies (≤ 500) |
| GET `/api/blobs/{sha256}` | exact blob bytes as `application/octet-stream` attachment (re-hashed before serving) |
| GET `/api/blobs/{sha256}/view` | blob rendered with `Content-Security-Policy: sandbox` (no scripts, opaque origin) |
| POST `/api/verify` | run verification, return `model.VerifyReport` |
| GET `/api/exports` / POST `/api/exports` | list / create bundle `{from,to,incident_id,prepared_by,notes}` |
| GET `/api/exports/{name}` | download bundle |
| POST `/api/notes` | `{text, author}` → `operator_note` |
| POST `/api/gateway/notification` | `{enabled:false}` → set gateway setting (config_change) |
| POST `/api/gateway/trust-cert` | `{sha256?}` operator confirms the changed gateway TLS certificate they reviewed (refused if a different one is pending); config_change; resumes authenticated operations |
| POST `/api/anchor` | anchor now |
| GET `/api/syslog?from=&to=&q=&severity=&limit=` | `model.SyslogList`: the syslog store's messages received in [from, to) (default the 24 h before to; at most 31 days), newest first; q: text in the raw datagram, message, app or host (ignoring case, ≤ 200 characters); severity: 0-7 or a name, keeps that level and the more severe ones; limit 200 (≤ 5000); the list also ends before the message that would take its JSON beyond 16 MiB (`MaxSyslogAnswerBytes`; a control character is a six-byte escape); `truncated` when more matched. Each entry names its `chunk` ("" = the open chunk) and `seq`, the chunk's `syslog_chunk` record (0 while open or not found) |
| POST `/api/syslog/retention` | `{keep_mb, keep_days?, client?}`, the whole setting (keep_days absent = 0, no age limit) → `SetSyslogRetention` (§18); answers the `model.ConfigChange` |
| GET `/api/traffic/live` | `model.LiveTraffic`: the flow meter (§18): the newest WAN rates from an on-demand read of the gateway's counters (at most every 5 s whoever asks), this computer's rates and about 15 minutes of history; never recorded |

API details (as implemented): `/api/records` adds `hash_ok` (h == SHA-256(b)) per record, an
`X-ATT-Monitor-Warning` header for gaps / repeated or out-of-order seqs / hash mismatches among the
examined records, and `X-Next-Seq` for paging; `/api/incidents?limit=N`; `/api/incidents/{id}` keeps
first/last records and the earliest + latest evidence when capped (`referenced` = total).
`POST /api/gateway/notification` answers 502 when the gateway failed, 500 when the gateway reports
the change but it could not be recorded. Single-flight operations answer 409; contracts.ErrBusy /
ErrRateLimited / ErrUnavailable map to 409 / 429 / 503. Bodies with unpaired UTF-16 surrogate escapes
are rejected (operator text is recorded exactly as sent or not at all).

Syslog and traffic (as implemented): `/api/syslog` finds each chunk's `syslog_chunk` record with
bounded ledger scans (records found are cached; a record counts only if its time range covers the
messages) and reports records whose `h` is not SHA-256(`b`) or whose data does not parse in
`X-ATT-Monitor-Warning`. The scans read windows from the oldest message listed from each sealed
chunk to 15 minutes after its newest, joined when less than 2 hours apart into windows of at most
12 hours, newest first, at most 16 scans and 50,000 records per request: when that budget runs out,
the messages left without their record are older than those of the windows read in full (the
newest), and the next request, with the records found remembered, looks further back.
`/api/syslog/retention` validates the limits (400), runs one change at a time (409) detached from
the request (2 min), and answers a failure with `{error, change}`: 500
"applied but could not be recorded" or "in effect, but …" when the limits took effect, 503 when the
ledger is broken, 504 on a timeout. `/api/traffic/live` has a 10 s deadline tied to the request. A
feature the monitor does not offer (no syslog store, no retention control, no flow meter) answers 404
with a JSON error, and the dashboard hides or explains it.

`Status.syslog` (`model.SyslogStatus`): the receiver (enabled, listening, address, error), counters
since the start (received, stored, dropped, rejected), the newest message, the gateway's Syslog
setting as last read with its `gateway_event` seq, `state` (ok: the gateway sends to this computer;
off; elsewhere; unknown; error) with `problem`, and `store` (`model.SyslogUsage`: bytes, chunks,
messages, open messages, oldest/newest receive time, keep_mb, keep_days). Phase 1 never enforces the
setting: `enforce` is false and `target` absent. `Series` adds `traffic` (`model.TrafficPoint` per
bucket: mean and peak WAN download/upload in Mb/s, `at_least`, this computer's rates),
`traffic_days` (WAN volume per local day, `complete` or not) and `heavy_traffic_mbps` (80, §9).

Dashboard views (hash routes): Overview (status hero with state/cause/attribution and
reasons; cards Internet / AT&T gateway WAN / Fiber optics (Rx/Tx power vs thresholds and the
gateway's own alarm flags) / Local link / Evidence integrity / Syslog; the live flow meter (polls
`/api/traffic/live` every 5 s only while the Overview is shown and the page visible); latency chart
per target, availability strip, MRTG-style traffic chart with its maximum/average/current legend and
the daily totals for 1h/6h/24h/7d; recent incidents), Incidents (list + detail timeline with evidence
links), Gateway (all parsed fields, DMI table, notification setting), Syslog (the gateway's messages
with search and severity filter, each linked to its chunk's `syslog_chunk` record; a row shows at
most 500 characters of the text and 100 of the host and the app as shown (an escape counts its
length), each with at most 16 runs of hidden characters, one element per run, and the exact
datagram on request; "Load more" doubles the limit up to 5000, and is not offered when an answer
ended at its size; the store's use and the retention form, which asks first when a change deletes
messages now and says when the limits saved were already in force), Evidence (ledger head, key
fingerprint, anchors, verify, exports, notes), Records (raw ledger browser). Charts are
hand-written inline SVG (no libraries). Light/dark via `prefers-color-scheme`.

## 13. Evidence bundle, report, verifier

`att-evidence_<fromUTC>_<toUTC>_<head8>.zip`:
```
README.txt          what this is, how to verify (Go and Python), key fingerprint
REPORT.html         self-contained human report (inline CSS + inline SVG; no external refs)
report.json         machine-readable summary + incidents
ledger/…jsonl       complete daily segments overlapping the range (uncompressed), plus the
                    genesis segment (for the public key) if not already included
blobs/<id>          every blob referenced by included records (uncompressed exact bytes)
syslog/<name>       the syslog chunks of the period the syslog store still keeps (exact stored gzip)
keys/public-key.txt base64 public key + fingerprint
MANIFEST.sha256     sha256 of every file above
tools/verify_bundle.py
```
Report sections: header (period, host, gateway model/serial/firmware, key fingerprint,
ledger head, verification result), executive summary (monitored time and coverage %,
availability %, incidents by state/cause, total provider-attributed downtime, longest
outage, blips), incident table (local + UTC times, duration, state, cause, attribution,
key facts, evidence seqs), optical-level section (gateway-reported Rx/Tx power and
alarm/warning flags over time), methodology & rules version, integrity & verification
instructions, custody log (genesis, bootstrap import, config changes, starts/stops/gaps,
notes, exports). After building, append `custody_export` and anchor.

**Report verification** (report format `att-monitor-report/3`): `att-monitor verify-bundle` re-runs the
exporter's pipeline on the bundle's own records and blobs and requires `report.json`, `REPORT.html`,
`README.txt` and `keys/public-key.txt` to match byte for byte (`export.VerifyReport`); the few inputs
that cannot come from records (period, export time, generator, request, the exporting computer's time
zone `local_time_zone`, the full-ledger and token-verifier results at export, omitted segments) are
listed as *stated*. A forged figure therefore fails verification. `tools/verify_bundle.py` checks the
ledger, blobs, signatures, time-stamps (OpenSSL) and record times, and says plainly that it does not
re-derive the report. Segments are selected by record time (a later-dated segment holding period
records is included). An incident still open at export gets `incidents[].computed` figures recomputed
from samples. The full-ledger verification runs alongside the build, bounded by `FullVerifyTimeout`
(default 4 min; `verification.full_ledger_incomplete` when it does not finish). Percentages are
truncated, never rounded up (no "100%" after an outage). Cycle cover follows the monitor: a cycle
covers until the next sample of the same process (corrected for wall-clock steps), and the last cycle
of an ended process only until its last observation.

Bundle rules (as implemented): the bundle holds the genesis segment plus **one contiguous run** of
segments; an omitted run is allowed only between the genesis segment and the run (any other gap is
a removed segment = failure, in Go and Python). If the period starts inside an open incident, the run
reaches back to the incident's opening (≤ 31 days) and those segments are labelled. Periods must lie
in 1970..2261 and not start in the future. Every time-stamp token is checked while it is copied
(granted, SHA-256, imprint = head hash, CMS signature with the embedded TSA certificate); only a
valid, chain-verified token counts as proof of time, and the token's own genTime is reported.
`keys/tsa-roots.pem` (FreeTSA root + DigiCert Trusted Root G4) lets anyone run
`openssl ts -verify -attime <genTime> -digest <head_hash> -in blobs/<token> -CAfile keys/tsa-roots.pem`.
Bundles are committed with MoveFileEx without replace: an existing bundle is never overwritten.

`tools/verify_bundle.py` (Python ≥ 3.9 stdlib): manifest, envelope hashes, chain linkage,
segment hashes, blob hashes; Ed25519 signatures when `cryptography` is installed; TSA tokens
via `openssl ts -verify` when available. `att-monitor verify-bundle <zip>` does all checks.

**Syslog chunks** (§18): a bundle includes, as `syslog/<name>`, the exact stored bytes of every chunk
named by one of its `syslog_chunk` records whose messages overlap the period, as far as the syslog
store still keeps it (ledger order, after `blobs/`, listed in MANIFEST.sha256; a chunk the store no
longer has is left out, one it cannot read is left out with a warning in the log, one whose content
no longer matches its record is exported as stored, so that verification reports it).
`export.VerifySyslogChunks` (the `SYSLOG:` line of `att-monitor verify-bundle`, which exits 2 on a
mismatch) and item 9 of `tools/verify_bundle.py` (version 1.3, the same verdicts) require every
`syslog/` file to be named by a usable `syslog_chunk` record of the bundle and to gunzip strictly
(one or more members, nothing after them, bounded output) to content with the record's SHA-256, size
and line (message) count. Chunks of the period that are not in the bundle are listed, not failed:
"pruned" when a `syslog_prune` record of the bundle names them, else "absent" (deleted after the
bundle's records, or unreadable at export); their records still state their SHA-256. REPORT.html,
report.json, README.txt and keys/public-key.txt do not describe the chunks and are byte-identical with
or without them (report format unchanged).

## 14. Windows service and CLI

Service name `ATTMonitor`, display name "AT&T Internet Monitor (evidence logger)",
LocalSystem, automatic start, recovery: restart after 10 s / 30 s / 60 s. Accepts Stop,
Shutdown, PowerEvent (records `power_event`). Event Log source `ATTMonitor`.

```
att-monitor setup                                           guided install/update (also run by a double-click):
                                                            asks only for the gateway's Device Access Code
att-monitor install [--data DIR] [--listen 127.0.0.1:8320]  copy exe to "C:\Program Files\ATT Monitor\",
                                                            create service + event source + data dir ACL
                                                            + syslog firewall rule (§18), start
att-monitor uninstall [--interactive]                       remove service, program, shortcut, Settings entry,
                                                            firewall rule (data is kept)
att-monitor start | stop | status
att-monitor run [--data DIR]                                foreground (console) mode
att-monitor service                                         entry point used by the SCM
att-monitor set-access-code (--file PATH | --stdin)         store DPAPI-encrypted access code
att-monitor gateway notification [status|on|off]
att-monitor gateway syslog [status] [--json]                Status.syslog: receiver, store, the gateway's setting
                                                            (read only in this version; on|off are refused)
att-monitor gateway trust-cert                              confirm a changed gateway certificate (after AT&T firmware updates)
att-monitor syslog [--since 24h] [--grep T] [--severity L] [--limit N] [--json]
                                                            the syslog store's messages (GET /api/syslog), oldest first
att-monitor syslog retention [--keep-mb N] [--keep-days D] [--yes]
                                                            show the store's use and limits, or change them
att-monitor verify [--data DIR]                             verify the full ledger
att-monitor verify-bundle FILE.zip                          MANIFEST, REPORT, SYSLOG lines and the ledger verification
att-monitor export --from YYYY-MM-DD[THH:MM] --to … [--incident ID] [--prepared-by NAME] [--out DIR]
att-monitor note "text" [--author NAME]
att-monitor ticket-report [--hours 24] [--out DIR] [customer fields] [--no-pdf]   AT&T service-ticket PDF from a verified bundle
att-monitor mongo status | verify [--json]                  the MongoDB copy (§17)
att-monitor version
```
Commands that write to the ledger go through the running service's localhost API; when the
service is not running they open the ledger directly (the writer lock prevents two writers).
`password.txt` format: lines `ip:<host>` and `password:<access code>`.

Syslog commands (§18): `syslog` lists through the service only (`/api/syslog` names each chunk's
record); it prints the newest `--limit` messages of the last `--since` (a duration or `Nd`, at most
31 days) oldest first, under a heading per chunk naming its `syslog_chunk` record, with control and
format characters and bytes that are not UTF-8 escaped (`--json` prints the API's answer as it is).
`syslog retention` shows the use and the limits (from `Status.syslog.store`, or with the service
stopped from config.json and the store opened read-only); with `--keep-mb` and/or `--keep-days` it
changes them (a limit left out keeps its value) through `POST /api/syslog/retention`, or with the
service stopped through `SetSyslogRetention` on the ledger (applied by the service at its start). A
change that deletes messages now is confirmed first on a console; without one it needs `--yes`.
`gateway syslog` prints `Status.syslog` and, while the gateway does not send to this computer, how to
set it by hand. `mongo verify` also prints the syslog part of the verification (§17). The CLI opens the
syslog store read-only; only the running monitor writes it.

**Guided setup** (`setup`, and a start without arguments from Explorer, detected by the process
owning its console): without administrator rights it re-starts itself elevated (ShellExecuteEx
"runas", UAC prompt) in a window of its own and waits. The elevated part identifies the gateway
(sysinfo, no login), asks for the Device Access Code with console echo off, and checks it with a
read-only authenticated request (the events page, as `gateway notification status`) through one
gateway client, so the client's login policy applies across attempts: one attempt per minute
(setup waits) and none after three rejections within an hour (setup offers to install without the
code). The check trusts the certificate on first use only for itself, or uses the service's pin on
an update; nothing is saved from it. A code that cannot be checked (gateway unreachable, sessions
full) is stored unchecked. It then runs the same install/upgrade as `install`, which also adds
the program to Settings > Apps (HKLM `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ATTMonitor`,
uninstall string `att-monitor.exe uninstall --interactive`) and a Start menu shortcut to the
dashboard. Back without administrator rights, setup shows the version, the dashboard address and
the evidence key from `/api/status` and opens the dashboard in the user's browser.
`uninstall --interactive` asks for confirmation and elevation itself; the installed program file
is deleted at the next restart when it is the one running.

## 15. Configuration (`config.json`, see `internal/config`)

Durations are Go duration strings. Secrets never appear in logs, ledger or exports; the
config hash recorded in `monitor_start` is computed with secrets removed.
The `mongo` section configures the MongoDB copy (§17); its URI must not contain credentials.
The `syslog` section configures the receiver and the store (§18): `enabled` (true), `listen`
(":514"), `port` (514, what the gateway is to send to), `allow` (further senders), `flush_interval`
(30s), `max_per_minute` (2000), `keep_mb` (100; 1 to 1,048,576) and `keep_days` (0 = no age limit; at
most 3650).

## 16. Engineering rules

* `gofmt`, `go vet` clean. No cgo. Tests: `go test ./...` must pass offline; live tests
  (gateway GETs, ICMP to the internet, TSA requests) only when `ATTMON_LIVE=1`.
* **Never** send authenticated or mutating requests to the real gateway from tests.
  Use `testdata/gateway/*.html` fixtures (sanitized real pages) and httptest servers.
* Never log or store the access code in clear text.
* Do not follow redirects when fetching gateway pages; record them.
* Exact bytes: store/hash response bodies as received.
* Times in records: UTC RFC 3339 with nanoseconds; UI shows local time and UTC.
* Integers instead of floats where natural (µs, 0.1 dBm); floats allowed in UI-only types.

## 17. MongoDB copy of the evidence (`internal/mongostore`)

A continuously synchronized, queryable copy of the ledger in a local MongoDB (default
`mongodb://127.0.0.1:27017`, database `attmonitor`). The signed JSONL ledger stays the source of
truth and the only chain of custody: nothing is read back from MongoDB as evidence, and the copy
can always be rebuilt from the ledger.

* **Replicator.** A goroutine of the service (`runMonitor`) tails the ledger every
  `mongo.interval` (5 s): every record above the newest copied seq, in order, in batches (blobs
  first, then records, incidents, meta). It never blocks evidence collection: while MongoDB is
  down it retries with a bounded backoff and logs at most once per state change (a reminder at
  most hourly). Its state is `Status.mongo` on `/api/status` and the "MongoDB copy" row of the
  dashboard's Evidence card. When the monitor stops, one best-effort last pass (2 s budget, short
  because Windows allows little time at shutdown; a reconnect may not fit in it) copies the
  `monitor_stop` record; anything not copied is copied at the next start.
* **Collections.** `records` (`_id` = seq; `seq`, `ts` as a BSON date and `ts_text` as written,
  `type`, `run`, `mono`, `prev`, `v`, the exact `h`, `s`, `b` strings, `blobs`, and `data`: the
  body's data converted to BSON for queries); `blobs` (`_id` = SHA-256; the exact bytes when
  `mongo.store_blobs`, `size`, `first_seq`; blobs over 15 MB keep only their size because of the
  16 MB document limit); `incidents` (`_id` = incident id; the newest incident payload by seq and
  the record it comes from); `meta` (`_id` "replication": resume point, ledger fingerprint and
  genesis hash). Indexes `{type:1, ts:1}` and `{ts:1}` on `records`.
* **Fidelity.** `b` is never re-encoded. Data that cannot be converted to BSON faithfully (an
  object key starting with `$` or containing NUL, an integer outside int64, nesting deeper than
  64, data the parser or the server rejects) is stored as text (`data_json`, `data_undecoded`,
  `data_note`) instead of approximated; data that would push a document over 16 MB is left out
  with a note (`b` is complete). Documents are deterministic, so `mongo verify` rebuilds each one
  from its ledger record and compares them. Bookkeeping fields: `v` and `copy_format` in
  `records`; `type`, `ts`, `ts_text` and `h` in `incidents`; `format`, `reset_reason`,
  `previous`, `store_blobs`, `collections` (the collections' UUIDs) and `pending_blobs` in `meta`.
* **Integrity.** Record documents are inserted, never overwritten. A seq already present counts
  as copied only when its stored `h` equals the ledger's; a different `h` at the same seq is
  reported (log, `Status.mongo.last_error`) and left alone. A database holding another ledger's
  copy (meta naming another genesis or fingerprint, or a record 0 that authenticates as another
  ledger's genesis) is refused. `meta` is written by compare-and-set; on every (re)connection and
  once a minute the replicator checks the collections' UUIDs, `meta`, the newest copied record and
  record 0, and a dropped, restored or emptied collection, deleted records or a deleted `meta`
  trigger a re-check of the whole copy that fills what is missing (also while the service runs).
  A blob the ledger cannot read for a while waits in `meta.pending_blobs` and is retried every
  pass; only a blob the ledger lacks, or whose content does not match its id, is an integrity
  problem.
* **Trust.** A local MongoDB without authentication accepts writes from any local process, so the
  copy is not evidence. `att-monitor mongo verify` compares it with the ledger record by record:
  identical `h`, `s` and `b`, `h` = SHA-256(`b`), a valid Ed25519 signature, derived fields
  consistent with `b`; it reports missing, altered and forged documents and blob or incident
  mismatches, blob documents that differ from what the replicator writes or that no record
  references, and a copy that is empty or far behind the ledger (more than 10 records over more
  than 15 minutes), and exits with status 2 when it finds a problem. The replicator never
  repairs a record document; to rebuild the copy, drop the database or delete the `meta`
  document, also while the service runs. Blobs copied while `store_blobs` was off get their
  content when it is turned on. Known limit: blob documents deleted one by one (the collection
  kept) are not noticed by the replicator; `mongo verify` reports them, and deleting `meta`
  repairs them.
* **Syslog.** Given the syslog store (§18), the replicator keeps a collection `syslog`: one document
  per message line of every sealed chunk (`_id` "<chunk>#<line>", `chunk`, `chunk_seq`, `line`, the
  exact `raw_line` - which holds the message's text, not stored a second time - and `rx` as a BSON
  date, `rx_text`, `src`, `severity`, `facility`, `host`, `app` when present; a line that does not
  decode keeps `raw_line` with `undecoded` and `note`; indexes `{rx:-1}` and `{chunk:1}`). After the
  records of each pass it applies the copied `syslog_chunk` and `syslog_prune` records strictly in
  ledger order: a chunk is read from the store and must match its record (size, SHA-256, one
  LF-terminated line per message) before its documents are written; a prune deletes the chunk's
  documents. The collection has a size limit of its own, because the store's limit counts gzip bytes
  and uncompressed documents take far more (tens of times for the gateway's usual lines, hundreds of
  times for repetitive ones): after a pass that stored documents, and when the limit changes, the
  documents of the oldest chunks (by name) are deleted while the collection's documents take more
  than `syslog.keep_mb` MiB as MongoDB counts them (`$collStats` `storageStats.size`, before its own
  compression; the indexes come on top). The newest chunk is always kept; the chunks stay in the
  store, so the copy holds the newest messages and the store holds more. Documents are
  deterministic and never overwritten. A chunk already pruned is skipped (logged); one that does not
  match is reported; one that cannot be read is retried and after 10 minutes reported and skipped.
  `meta` adds `syslog_seq` (applied up to), `syslog_collection` (its UUID) and `syslog_trimmed` (the
  last chunk the size limit deleted); deleting `meta` or dropping the collection re-applies every
  syslog record. None of this delays or fails the copy of the records. `mongo verify`
  (`mongostore.VerifyWith` with the store opened read-only) checks that each chunk's documents
  reproduce its record (lines 1..messages once each, hashing to its SHA-256 and size, every field as
  the replicator writes it) and reports documents of pruned chunks, documents no `syslog_chunk`
  record names (forged), chunks the store keeps but the copy lacks (those up to `syslog_trimmed` are
  only counted), and a syslog collection more than 15 minutes behind.
* **Configuration.** `mongo {enabled, uri, database, store_blobs, interval}`, enabled by default
  against the local server. The URI must not contain credentials (validation refuses them): the
  configuration is recorded in `monitor_start`/`config_state` and so in evidence bundles. A
  bundle never contains MongoDB data.

## 18. Syslog, retention and traffic

The owner's goals of 2026-10-05 and the plan are in `docs/syslog-snmp-traffic.md`. Phase 1 (this
section) receives and keeps the gateway's syslog, reads (never changes) the gateway's Syslog setting
and shows the traffic; phase 2 sets the gateway's Syslog setting automatically. Everything here is
supporting evidence: `RulesVersion` stays `2026.10-4` and no verdict depends on it.

**Receiver** (`internal/syslogrx`). UDP on `syslog.listen` (":514"). Datagrams are accepted only from
the gateway's address and `syslog.allow` (an allow list, not authentication: a UDP source address
can be forged on the home network), at most `max_per_minute` (2000) per UTC minute of receive time,
8 KiB each, at most 1 MiB of stored lines per UTC minute (the messages' JSON lines as the store
writes them: escaped control characters make a line up to about twelve times its datagram, so the
message cap alone does not bound what is stored), and 4 × `max_per_minute` waiting to be stored;
beyond that they are counted as dropped, and datagrams from other senders as rejected (only the
sender is logged, never the content). A message keeps the exact datagram (`raw`, or `raw_b64` when it
is not UTF-8), the sender `ip:port` and the receive time (this computer's clock, RFC 3339 UTC with
nanoseconds); the RFC 5424 / RFC 3164 fields are parsed as a convenience (`msg` is left out when it
would be exactly `raw`). The monitor runs the receiver; when it cannot listen it is started again
after 1 minute, the pause doubling up to 10 minutes (`SYSLOG_RECEIVER_DOWN` meanwhile).

The byte cap bounds what any sender on the home network - forging the gateway's address passes the
allow list - can make the evidence grow by: the store seals at most about one chunk a minute by
size, so syslog adds at most about 1,440 `syslog_chunk` records a day and, once the size limit is
reached, about as many `syslog_prune` records - about 3 MB of ledger a day in the worst case (the
gateway's usual traffic: a chunk every 5 minutes, well under 1 MB a day).

**Store** (`internal/syslogstore`, `syslog\`, §5). The ledger can never delete anything, so the
messages are kept here and the ledger holds their proof. Every `flush_interval` (30 s) the monitor
moves what the receiver received into the store: one `json.Marshal` line per message, each ending in
a line feed, appended (fsynced) to the open chunk. A chunk is sealed when its content reaches 1 MiB
(reason `size`), at the first flush at least 5 minutes after it was opened (`age`), at shutdown
(`stop`), or at the next start when a run left it open (`recovered`): its exact bytes are compressed
with gzip into `syslog-<from>_<to>.jsonl.gz`, the copy is checked to decompress to the same SHA-256,
fsynced and renamed into place without replacing anything, and a sidecar index is written. For
every sealed chunk the monitor appends a `syslog_chunk` record (§7): the SHA-256, size and message
(line) count of the uncompressed content, the receive times of its first and last message, the
dropped and rejected counts, the gzip size and the reason. The open chunk is covered by no record
yet. Every crash point of sealing is repaired at the next start (`Recover`): a partial last line is
cut off, a leftover open chunk is sealed as `recovered`, a chunk whose gzip was already in place is
not sealed twice.

**Retention.** After every seal, at start, on a change of the limits and, with an age limit, at
least hourly, the store deletes whole sealed chunks, oldest first, while the sealed chunks' gzip size
plus the open chunk's size exceed `syslog.keep_mb` MiB (default 100, 1 to 1,048,576) and, with
`syslog.keep_days` above 0 (at most 3650), every sealed chunk whose newest message is older than
that. It never deletes the open chunk. A chunk that a reader holds open (an export, a query, another
program) is deleted at a later prune; meanwhile it no longer counts against the limit, so no newer
chunk is deleted in its place. Each deletion is a `syslog_prune` record: the reason ("keep_mb N",
"keep_days N" or both), the limits, the deleted chunks with their SHA-256, and what is kept. The
deletion is recorded before it is made: the store chooses the chunks (`PlanPrune`), the monitor
appends the record, and only then are they deleted (`CommitPrune`); when the ledger refuses the
record, nothing is deleted and the next flush tries again. A chunk whose file another program holds
leaves the store at once and its file goes later (should the service stop first, the next start
finds it as a kept chunk, which a later prune deletes, and records, once more). The ledger therefore
states which messages existed and when (`syslog_chunk`), and when and why they were deleted
(`syslog_prune`); a kept chunk verifies against its record.

**Ordering and failures.** Every sealed chunk gets exactly one record, and a chunk's record precedes
the record of its deletion, whatever fails. The store notes in each chunk's sidecar the seq of its
`syslog_chunk` record (`MarkRecorded`); a chunk without that note (`Unrecorded`) waits for its record:
while the ledger refuses records the chunks the store seals by size wait in the store, are recorded
in order once it takes records again - by the next start at the latest, should the run end first
(a ledger that reports itself unusable, the restart after 5 minutes of refused records, a crash) -
and nothing is deleted meanwhile. Nothing is sealed by age or at shutdown while the ledger refuses
records either, so the open chunk keeps the messages and is sealed as `recovered` by the next start.
At a start, the chunks found sealed but not noted (one sealed just before a crash, whose record may
or may not exist; one whose sidecar was rebuilt) are first looked up in the ledger - from a day
before their first receive time on, by name and SHA-256 - so that none is recorded twice; the others
are recorded then (late: the record's time-stamp then shows when it was recorded). A chunk a previous
run left open that the start cannot seal (another program holds its file) is tried again at every
flush. Store failures show as `SYSLOG_STORE_FAILING` until the next round of store operations
succeeds (including such a retry). The chunk files are not evidence by themselves (an
administrator can edit them): the records are. Reading is lenient: a sealed chunk that no longer
matches its SHA-256 is logged and served as it is, and verification (exports, MongoDB) reports it.

**How much is kept** (`contracts.SyslogControl`, `Monitor.SetSyslogRetention`; the dashboard's Syslog
page via `POST /api/syslog/retention`, and `att-monitor syslog retention`). Limits outside the ranges
above are refused. A change is saved (`config.json`), recorded as a `config_change` (target
`monitor`, what "syslog.keep_mb, syslog.keep_days …", before/after "keep_mb N, keep_days D") and
applied at once: the store prunes what no longer fits (`syslog_prune`). When the record cannot be
written the change is undone; setting the limits in force records nothing ("unchanged: already in
force"); a configuration that cannot be saved applies until the next start (the error is returned
with the change). With the service stopped the CLI records the change on the ledger and the service
applies it when it starts. Editing `config.json` takes effect at the next start.

**The gateway's Syslog setting** (phase 1: read only). The daily settings check reads `syslog.ha`
right after the notification setting, in the same login session, and again when this computer's
address toward the gateway changes (at most every 10 minutes); also when `syslog.enabled` is false.
Each read is a `gateway_event` `syslog_setting` with the page as a blob: `after` is "off",
"on -> <server>:<port>, level <level>", or "unknown" when the page was read but not understood (the
page is what phase 2 needs). A read that fails is not recorded; `Status.syslog` says why. The state
compares the setting with this computer's address toward the gateway and `syslog.port`: `ok`,
`off`, `elsewhere`, `unknown` or `error`. `Gateway.SetSyslog` exists (tested on synthetic pages, it
never posts a form it does not fully understand) but has no caller. Until phase 2 the owner sets the
page by hand (README). The setting is read only on that schedule (the check runs at start, within
`notifMinInterval` = 10 minutes, then daily), so a change made by hand shows in `state` only after
the next read, while the messages show at once (`received`, `last_at`): the dashboard's card says
that messages arrived since the read instead of how to set the page.

**Readers.** `GET /api/syslog` reads the open and the sealed chunks overlapping the period, newest
first with bounded memory (§12); evidence bundles carry the period's chunks (§13); the MongoDB copy
follows the chunks and prunes (§17). One process writes the store: the running monitor, whose
ledger lock keeps a second one away. With `syslog.enabled` false the service and, always, the CLI
open it read-only (a snapshot of the sealed chunks, reading the writer's open chunk as it grows), so
dashboards, exports and the MongoDB copy still find the chunks kept so far; nothing then deletes
them. A store that cannot be opened is logged and the service runs without syslog.

**Windows Firewall.** `install` (and `setup`) replace the inbound rule "AT&T Internet Monitor syslog"
(`netsh advfirewall firewall`, every argument on its own: `dir=in action=allow protocol=UDP
localport=<port of syslog.listen> remoteip=<gateway.host> program=<installed att-monitor.exe>
profile=any enable=yes`); with `syslog.enabled` false they remove it, and `uninstall` removes it. A
failure is reported and the installation goes on. After a change of `gateway.host` or
`syslog.listen`, install again; senders in `syslog.allow` need their own rule.

**Traffic.** SNMP is not possible (§2). Rates come from the IPv4 Statistics counters
(`broadbandstatistics`) of consecutive recorded gateway snapshots, at most 5 minutes apart: the byte
counters are 32 bits wide (a wrap every 4 GiB), and the packet counters tell whether the byte counter
may have wrapped more than once (`at_least`: the rate is a lower bound); a counter reset (gateway
restart) leaves the interval unknown. This computer's rates come from the 64-bit octet counters of
the adapter that reaches the gateway (`GetIfEntry2Ex`, in each local-link reading); the daily volume
from complete counter deltas. `Series.traffic` holds, per chart bucket, the mean rate and the
highest interval rate (peak) of each direction, `at_least` and this computer's rates;
`traffic_days` the volume per local day; `heavy_traffic_mbps` the classifier's threshold (80 Mb/s,
§9). The dashboard draws them like MRTG: download as a filled area, upload as a line, bits per second
with automatic units, the peaks marked, the threshold as a dashed line, and the maximum, average and
current rate of each direction over the range in a legend table.

**Flow meter** (`contracts.LiveTrafficSource`, `Monitor.LiveTraffic`, `GET /api/traffic/live`). An
unauthenticated read of `broadbandstatistics` on demand, at most one every 5 s after the previous
read ended, shared by all callers (callers arriving during a read get its outcome); the rates
against the previous counter reading (a live read, or the newest recorded snapshot) when it is at
most 2 minutes old; this computer's rates from the newest local-link interval; about 15 minutes of
history (at most 256 points). Nothing of it is recorded, stored or fed into the monitor's state;
the dashboard asks only while the Overview is shown and the page visible, so the gateway gets no
extra request when nobody watches. The evidence comes first: a live read never waits for the
gateway lock - while a poll, an incident snapshot or the settings check holds it the read is
skipped (the previous readings come back, with the reason) - it holds the lock for at most 5 s (its
own timeout, not the gateway timeout), so an evidence snapshot waits at most that long behind it,
and while the newest recorded snapshot found the gateway unreachable no live read is made at all
(the next poll that reaches the gateway resumes them).
