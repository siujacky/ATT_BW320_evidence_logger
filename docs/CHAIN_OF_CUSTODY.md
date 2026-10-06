# Evidence & chain of custody — guide for verifiers

This document is written for anyone who receives an **att-monitor evidence bundle** (for example an
AT&T escalation engineer, a regulator, or an arbitrator) and wants to know what it proves and how to
check it independently. Option C below uses only standard tools (sha256sum, OpenSSL) and requires no
trust in the person who produced the bundle; options A and B run code shipped with the bundle and are
conveniences (the Python verifier is a single, readable stdlib script — review it, or use option C).

## What was measured

A Windows PC on the customer's home network (behind the AT&T BGW320-505 gateway) ran the att-monitor
service continuously:

| every | what | why it matters |
|---|---|---|
| 10 s | ICMP + TCP to the gateway's LAN address | proves the customer's own network path to AT&T's gateway was working |
| 10 s | ICMP to AT&T's next hop (the "Gateway IPv4 Address" the gateway reports) | separates AT&T access-network faults from upstream ones |
| 10 s | ICMP to 1.1.1.1, 8.8.8.8, 9.9.9.9 and TCP 443 to 1.1.1.1, 8.8.8.8 | three independent providers — one provider's problem cannot look like an outage |
| 60 s (15 s during an outage) | the gateway's own status pages: Broadband Status, Fiber Status, System Information | **AT&T's device reports its own WAN state, PON (fiber) state, optical power levels with its own alarm flags, uptime, firmware, clock and traffic counters** (the traffic counters also show whether the household's own traffic could explain a slowdown) |
| 60 s (15 s during an outage) | DNS via the gateway, via AT&T's resolver and via 1.1.1.1; HTTP connectivity checks | detects DNS failures and outage-page hijacking |
| 60 s | the PC's own link (Wi-Fi signal/BSSID/channel or Ethernet speed) | rules local link problems in or out |
| outage start/end | traceroutes | shows where the path stops |
| hourly | SNTP clock offsets (and the gateway's own clock every minute) | shows how far this PC's clock was from internet time (the RFC 3161 time-stamps below are what bound every record's time) |
| as it arrives | the gateway's own log messages (syslog), once the gateway is set to send them to the PC: every datagram from the gateway's address, exactly as received, with the PC's receive time | the gateway's own account of events, kept as supporting evidence (it never changes a verdict) |
| daily | the gateway's Syslog setting (read only) | shows whether, and where, the gateway was sending its log |

Every gateway page fetch records the page's SHA-256 and the values parsed from it. The page itself is
stored **byte-for-byte** whenever a decisive value changes (WAN/PON state, optical alarm flags, WAN IP,
uptime reset, firmware, fiber link change), on every fetch during an incident, and at least every
5 minutes otherwise — so the facts behind every incident and every state change can be traced back to
the original page AT&T's device served.

## How outages are classified

The rules are deterministic, versioned (`rules` field in each record) and documented in DESIGN.md §9–§10.
In short, for each 10-second cycle:

* gateway unreachable from the PC → **LOCAL_FAULT, attribution "undetermined"** (we never blame the
  provider when our own path to the gateway is down);
* gateway reachable, every Internet target unreachable → **ISP_OUTAGE, attribution "provider"**, with the
  most specific cause the gateway itself reports (fiber/PON down → `FIBER_LINK_DOWN`; WAN session down →
  `WAN_DOWN`; AT&T next hop unreachable → `ISP_EDGE_UNREACHABLE`; else `UPSTREAM_UNREACHABLE`);
* sustained packet loss to at least two of the three independent providers, high latency, or DNS failure,
  with a loss-free local path → **DEGRADED, provider**; with any local loss → **DEGRADED, undetermined**
  (one unreachable destination can never implicate the ISP). A DNS failure must appear in two
  consecutive checks; degradation is attributed to AT&T only while the gateway's own WAN counters show
  the household is using less than 80 Mb/s; and while this PC's traffic is routed past the gateway
  (VPN, another network), nothing is attributed to AT&T (`LOCAL_ROUTE`).

An incident opens when 3 of the last 6 cycles are bad (a continuous outage or intermittent "flapping")
and closes after 3 consecutive good cycles; bad cycles that never form an incident are counted as
"blips". Downtime is measured in cycles, not wall-clock spans. **Gateway restarts** are detected from the
gateway's own uptime: the time from a restart until the Internet works again (max 10 min) is counted as
restart time, never as AT&T downtime, and an incident is attributed to AT&T only if it has provider
failures outside such restart windows (a firmware change across the restart — an AT&T-pushed update —
is the exception). Every sample records which records its verdict was computed from, so any verdict can
be recomputed. All healthy samples are kept too — nothing is cherry-picked.

## Integrity: what the bundle proves

1. **Hash chain.** Each ledger line is `{"h": SHA-256(b), "s": Ed25519-signature(b), "b": "<record>"}` and every
   record contains the hash of the previous one (`prev`). Changing, removing, inserting or re-ordering any
   record breaks the chain at that point.
2. **Signatures.** Every record is signed with a key created when the ledger was started (genesis record,
   `keys/public-key.txt`). The key fingerprint is printed in the report header.
3. **Independent time-stamps (RFC 3161).** Every 30 minutes and right after each outage, the hash of the
   newest record is time-stamped by public Time-Stamp Authorities (DigiCert, FreeTSA). A time-stamp over
   record N proves that records 0…N existed, exactly as they are, no later than the authority's time.
   Records cannot be back-dated or rewritten after being anchored without detection: verification also
   checks every record's time against the trusted time-stamps around it and fails (`ts_contradiction`)
   when one is more than 5 minutes off — e.g. a clock set back to fabricate an "earlier" outage.
4. **Primary-source data.** The decisive facts come from AT&T's own gateway (status pages with its serial
   number, its PON state, its optical alarm flags, its clock). AT&T can compare them with its own
   telemetry for the same device and times.
5. **Gaps are explicit.** Service starts/stops, PC sleep/resume, crash recovery and clock corrections are
   recorded (a clock that was changed while the service was stopped is detected at the next start);
   verification lists every period without samples and explains it.
6. **The report is bound to the records.** `att-monitor verify-bundle` re-computes REPORT.html,
   report.json and README.txt from the bundle's own ledger and fails on any difference, so a figure in
   the report cannot be edited after export.
7. **Syslog chunks are bound to their records, and deletions are recorded.** The gateway's syslog
   messages are the one kind of data kept outside the ledger, because the ledger never deletes
   anything and the messages are kept within a size limit (the newest 100 MB by default). They are
   stored in chunks. A chunk is sealed when it reaches 1 MiB; about 5 minutes after it was opened (at
   the store's next flush, every `syslog.flush_interval`, 30 seconds by default); when the service
   stops; or, when a crash or a failure of the ledger left it open, at the next start (reason
   `recovered`). Then a **`syslog_chunk`** record states the SHA-256, size and message count of its
   exact content and the receive times of its first and last message. That record is signed, chained
   and time-stamped like every other, so the chunk's messages provably existed, exactly as they are,
   no later than the time-stamp that covers the record: adding, removing, reordering or altering one
   message changes the SHA-256. Every sealed chunk gets its record: one sealed while the ledger
   refused records is recorded as soon as it takes them again, by the next start at the latest (its
   record's time-stamp is then that much later). Every chunk the retention limits delete (the size
   limit, or an optional age limit) is named, with its SHA-256, in a **`syslog_prune`** record written
   before the chunk is deleted - nothing is deleted while a chunk still waits for its record - so a
   deletion is on record, with its reason, and never silent. A bundle contains the chunks of its period that were
   still kept at export (`syslog/`); each must match its record, and the chunks of the period that
   are missing are listed as deleted by a retention limit (a `syslog_prune` record says so) or as not
   in the bundle. Messages of the chunk still open at export are in no record yet and are not in the
   bundle.

**Limits (stated honestly):** the custodian controls the PC, so the system is tamper-*evident*, not
tamper-*proof*. Records newer than the last time-stamp are only protected by the hash chain and signature
(and back-dating that stays entirely after the newest time-stamp cannot be disproven by one).
Verification shows exactly which records are covered by which time-stamp. Syslog travels over UDP
without authentication or delivery guarantee: the records show what this PC received from the gateway's
address (the exact bytes, the sender as Windows reported it, the PC's receive time), not that the
gateway sent nothing else, and the content of a chunk is protected only from when it is sealed.

**Copies are not the evidence.** The owner may also keep a copy of the ledger in a local MongoDB database
for queries. That copy is never part of a bundle and proves nothing by itself; a bundle is verified from
its own ledger files, signatures and time-stamps alone. Each record in the MongoDB copy keeps its exact
`h`, `s` and `b`, so any record shown from it can be checked the same way (`h` = SHA-256 of `b`, `s` a valid
signature of `b` under the fingerprinted key). Its copy of the syslog messages likewise reproduces each
chunk's SHA-256 only when complete and unaltered (`att-monitor mongo verify` checks that). The files of
the syslog store on the PC are not evidence by themselves either: a chunk proves something once it
matches its `syslog_chunk` record.

## How to verify a bundle

The bundle (`att-evidence_<from>_<to>_<head>.zip`) contains `MANIFEST.sha256`, the complete ledger
segments for the period, every referenced raw page (`blobs/`), the gateway's syslog chunks of the period
that were still kept at export (`syslog/`), the public key, the human report and
`tools/verify_bundle.py`.

### Option A — Python (no installation needed beyond Python 3.9+)
```
python tools/verify_bundle.py att-evidence_....zip
```
Checks the manifest, every record hash, the chain, segment hashes, blobs, record times against the
time-stamps, every syslog chunk against its `syslog_chunk` record (the chunks of the period that are
not in the bundle are listed in the notes, with the `syslog_prune` record that deleted them if any),
and (if the `cryptography` package is installed: `pip install cryptography`, or with
`--pure-python-ed25519`) every signature; with OpenSSL on PATH it verifies every time-stamp token
(`openssl ts -verify -attime`) against `keys/tsa-roots.pem`. It does not re-derive the report — use
option B for that.

### Option B — att-monitor itself
```
att-monitor verify-bundle att-evidence_....zip --expect-fingerprint <fingerprint you received separately>
```
Everything option A checks, plus TSA chain validation and the report re-computation (REPORT line). The
SYSLOG line gives the outcome of the syslog chunk checks.

### Option C — by hand with standard tools
* Bundle integrity: `sha256sum -c MANIFEST.sha256`
* A record: take the `b` string of a ledger line, compute SHA-256 of its UTF-8 bytes, compare with `h`;
  the next record's `prev` must equal this `h`.
* A time-stamp: the `anchor` record names the token blob (`token_sha256`) and the anchored record
  (`head_seq`, `head_hash`):
  ```
  openssl ts -reply -in blobs/<token_sha256> -text          # shows genTime and the message imprint (= head_hash)
  openssl ts -verify -attime <genTime as Unix seconds> -digest <head_hash> -in blobs/<token_sha256> -CAfile keys/tsa-roots.pem
  ```
  `keys/tsa-roots.pem` holds the DigiCert Trusted Root G4 and FreeTSA root certificates; compare their
  SHA-256 fingerprints with the ones the authorities publish. `-attime` checks the certificates as of the
  time-stamp, so old tokens keep verifying after the TSA certificate expires. Only time-stamps whose
  certificate chain verifies count as proof of time.
* A syslog chunk: find the `syslog_chunk` record whose `name` is the file's name; then
  ```
  gzip -dc syslog/<name> | sha256sum      # = the record's sha256
  gzip -dc syslog/<name> | wc -c          # = the record's bytes
  gzip -dc syslog/<name> | wc -l          # = the record's messages (one JSON message per line)
  ```

## Setup-time evidence (bootstrap)

Before the service existed, the gateway's pages were captured manually during installation
(2026-10-05 03:10 UTC) and the gateway's "Broadband Status Notification" redirect was switched off
(03:14:31 UTC). Those files, their capture notes (including a fidelity caveat: they are UTF-8/CRLF
transcriptions, not byte-exact) and two RFC 3161 time-stamps (DigiCert and FreeTSA, 03:19:57 UTC) are
imported into the ledger right after its genesis record (`bootstrap_import`).
