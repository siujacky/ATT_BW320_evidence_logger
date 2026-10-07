# AT&T BGW320 Evidence Logger (`att-monitor`)

**Tamper-evident, time-stamped evidence of AT&T Fiber outages, so you can show AT&T that a problem
is on *their* side.**

`att-monitor` is a Windows service that watches an AT&T Fiber connection around the clock through the
AT&T **BGW320** gateway (tested with the BGW320-505) and through independent Internet probes. It
classifies every 10-second cycle with conservative, versioned rules and writes everything into an
append-only, hash-chained, Ed25519-signed ledger that public Time-Stamp Authorities time-stamp. A local
dashboard shows what is happening, including an **MRTG-style traffic chart and a live flow meter** built
from the gateway's own counters, the **gateway's own log messages (syslog)** and a **Network page**
that shows which device talks to which site and what the gateway's firewall blocks. The ledger is
mirrored into a local **MongoDB** for queries, and one command turns the last 24 hours into a **PDF for
an AT&T service ticket**, backed by an evidence bundle that anyone can verify.

> Not affiliated with or endorsed by AT&T. "AT&T", "BGW320" and the gateway's page names belong to
> their owners. The monitor reads the gateway's own pages (its status pages and Device List need no
> login; with the Device Access Code it checks the outage-redirect and Syslog settings about once a
> day, and reads the NAT table for the Network page every 4 minutes in one kept web session) and keeps
> two gateway settings as it needs them: the outage redirect off, and the Syslog page sending the
> gateway's log to this PC (see below).

---

## Contents

- [What it records](#what-it-records)
- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Install](#install)
- [The gateway's outage "hijack" redirect](#the-gateways-outage-hijack-redirect)
- [Traffic: MRTG-style chart and flow meter (no SNMP needed)](#traffic-mrtg-style-chart-and-flow-meter-no-snmp-needed)
- [The gateway's syslog](#the-gateways-syslog)
- [Network page: which device talks to which site](#network-page-which-device-talks-to-which-site)
- [Dashboard](#dashboard)
- [Data storage: ledger and MongoDB](#data-storage-ledger-and-mongodb)
- [Report for an AT&T service ticket](#report-for-an-att-service-ticket)
- [Giving evidence to AT&T](#giving-evidence-to-att)
- [Chain of custody](#chain-of-custody)
- [Commands](#commands)
- [Configuration](#configuration)
- [Privacy, security and network use](#privacy-security-and-network-use)
- [Development](#development)
- [Acknowledgements](#acknowledgements)

## What it records

* **AT&T's own gateway**: every minute (every 15 s during an outage) the BGW320's status pages, which
  need no login: broadband and WAN state, fiber/PON state (`O1 INIT` … `O5 OPERATION`), the optical
  receive and transmit power **with the gateway's own low-Rx ALARM/WARNING flags and thresholds**, the
  fiber "Last Change" counter, uptime (restarts), firmware, serial number and clock. The raw pages are
  stored byte for byte.
* **The path to the Internet**: every 10 s pings and TCP connects to the gateway, AT&T's next hop and
  three independent providers (Cloudflare, Google, Quad9); every minute DNS (gateway, AT&T and public
  resolvers) and HTTP checks; traceroutes during outages.
* **The home side**: Wi-Fi or Ethernet link state and signal, whether traffic actually leaves through
  the AT&T gateway (a VPN or second network is detected), heavy household traffic, PC sleep and resume,
  and the PC clock against NTP servers.
* **Traffic**: how much the household sends and receives through the gateway, from the gateway's own
  WAN byte and packet counters (read with every snapshot), and this PC's own traffic from its network
  adapter's counters, shown as an MRTG-style chart, daily totals and a live flow meter.
* **The gateway's own log (syslog)**: the monitor sets the gateway to send it to this PC and keeps it
  so; every message is received and kept (the newest 100 MB by default), and the ledger records the
  SHA-256 of every chunk of messages and every deletion.
* **A verdict per cycle**: `ONLINE`, `DEGRADED`, `ISP_OUTAGE` or `LOCAL_FAULT`, with a cause (for
  example `FIBER_LINK_DOWN`: the gateway itself reports its fiber link down) and an attribution
  (provider, local, undetermined). Rules are conservative: a gateway restart, a VPN, a Wi-Fi drop, PC
  sleep, heavy traffic or a single lost DNS packet is never blamed on AT&T. An incident opens when 3 of
  the last 6 cycles fail and its downtime is measured cycle by cycle.

## How it works

```mermaid
flowchart LR
  GW["AT&T BGW320 gateway<br/>status pages, no login"] -->|60 s, 15 s in outages| MON
  GW -->|its syslog, UDP 514| MON
  NET["Probes: gateway, AT&T next hop,<br/>1.1.1.1, 8.8.8.8, 9.9.9.9, DNS, HTTP"] -->|10 s| MON
  MON["att-monitor service<br/>classifier, incidents"] --> LED["Signed, hash-chained ledger<br/>+ raw pages (blobs)"]
  MON --> SYS["Syslog store<br/>newest 100 MB, gzip chunks"]
  SYS -.->|SHA-256 of every chunk,<br/>every deletion| LED
  LED -->|SHA-256 of the head only| TSA["RFC 3161 time-stamps<br/>DigiCert, FreeTSA"]
  LED -->|exact signed records| MDB["Local MongoDB<br/>queryable copy"]
  LED --> WEB["Dashboard<br/>127.0.0.1:8320"]
  LED --> EXP["Evidence bundle (zip)<br/>and ticket PDF"]
  GW -->|NAT table every 4 min,<br/>Device List| NET["Network page data<br/>not evidence"]
  SYS -.->|firewall drops| NET
  NET --> WEB
```

* Every record is a JSON line `{"h": SHA-256(b), "s": Ed25519(b), "b": "<record>"}`; each record names
  the hash of the one before it, so removing, reordering or editing any record breaks the chain. The
  signing key is created on first start and protected with Windows DPAPI (machine scope).
* Every 30 minutes and after each outage, the SHA-256 of the newest record is sent to two public
  Time-Stamp Authorities. Their signed RFC 3161 tokens prove that the ledger up to that record existed
  at that time.
* The ledger is the source of truth. The MongoDB copy, the dashboard, the exports and the PDF are all
  derived from it.
* The gateway's syslog messages are the one exception: the ledger can never delete anything, so they are
  kept in a separate store with a size limit, and the ledger holds their proof (the SHA-256 of every
  chunk of messages, and a record of every deletion). See [The gateway's syslog](#the-gateways-syslog).

## Requirements

* Windows 10 or 11 (the service runs as LocalSystem), on a PC connected to the AT&T gateway. A wired
  Ethernet connection makes the evidence stronger.
* An AT&T BGW320 gateway and its **Device Access Code** (printed on the gateway's label). The code is
  needed only for the gateway's settings - to keep the outage redirect off and the Syslog page sending
  the gateway's log to this PC - and for the Network page's NAT table; everything else uses pages that
  need no login.
* [Go](https://go.dev/dl/) 1.27 or newer to build (the build fetches the right toolchain if needed).
* Optional: [MongoDB Community Server](https://www.mongodb.com/try/download/community) running
  locally (the default `mongodb://127.0.0.1:27017`) for the queryable copy.
* Optional: Microsoft Edge or Google Chrome (to print the ticket PDF), and Python 3.9+ (to run the
  verifier shipped inside every evidence bundle).

## Install

### Quick install (no build tools needed)

1. On the PC that is connected to your AT&T gateway, download **`ATT-Monitor-Setup-<version>.exe`** from
   the [latest release](https://github.com/siujacky/ATT_BW320_evidence_logger/releases/latest).
2. Double-click it. The program is not code-signed, so Windows may say it protected your PC: choose
   **More info → Run anyway**. Then choose **Yes** when Windows asks for administrator permission.
3. Type the **Device Access Code** printed on the label of your AT&T gateway (not the Wi-Fi password).
   What you type is not shown.

Setup checks the code with the gateway (a read-only login), installs and starts the service, adds a
Windows Firewall rule that lets the gateway's syslog messages in (see [The gateway's
syslog](#the-gateways-syslog)), shows your **evidence key** and opens the dashboard. Within about 10
minutes the service sets the gateway's Syslog page to send the gateway's log to this PC. Write the key
down or email it to yourself: it identifies your evidence. If the code is mistyped, setup asks again; the
gateway allows one login attempt per minute, so it waits when needed, and after three rejections it
stops trying for an hour, so the gateway's login is never locked.

Running the same file again updates the program; press Enter at the code prompt to keep the stored
code. The dashboard is also in the Start menu ("AT&T Internet Monitor"). To uninstall, open Settings →
Apps → Installed apps → *AT&T Internet Monitor (evidence logger)* → Uninstall. Your evidence in
`C:\ProgramData\ATTMonitor` is kept.

### Build from source

1. Get the code and build it:

   ```powershell
   git clone https://github.com/siujacky/ATT_BW320_evidence_logger.git
   cd ATT_BW320_evidence_logger
   .\build.ps1              # secret scan, go vet, tests, bin\att-monitor.exe
   ```

2. Create `password.txt` next to `build.ps1` with the gateway's address and Device Access Code. The file
   is in `.gitignore`; the build refuses to continue if the code appears in any source file.

   ```text
   ip:192.168.1.254
   password:<the Device Access Code from the gateway label>
   ```

3. Install the service from an **elevated** PowerShell:

   ```powershell
   .\build.ps1 -Install
   # or: .\bin\att-monitor.exe install --access-code-file .\password.txt
   ```

   This copies the program to `C:\Program Files\ATT Monitor\`, stores the access code DPAPI-encrypted in
   `C:\ProgramData\ATTMonitor\keys\` (you may delete `password.txt` afterwards), adds the Windows
   Firewall rule for the gateway's syslog, creates and starts the `ATTMonitor` service and prints the
   **ledger key fingerprint**. Write the fingerprint down or email it to yourself: it identifies your
   evidence, and you give it to AT&T separately from any evidence.

   If you saved gateway pages before installing (setup-time evidence), pass the folder with
   `--bootstrap DIR`; it is imported into the ledger as the first record after genesis.

You can also double-click `bin\att-monitor.exe`, or run `att-monitor setup`, for the guided setup
described above.

**Upgrade:** build a newer version and run `install` (or `setup`) again, elevated. The service stops,
the program is replaced and the service restarts; the ledger continues. **Uninstall:** Settings → Apps,
or `att-monitor uninstall`. Either way the service, the program, its Start menu shortcut, its Settings
entry and its firewall rule are removed, and the evidence in `C:\ProgramData\ATTMonitor` is kept.

**Going back to a version before 1.3.0:** those versions do not know the Network page's folders
(`connections\` and `geo\` in the data folder; not evidence) and refuse a data folder that holds them.
Their `install` replaces the program first and refuses after, saying "The upgrade failed; the previous
service was restarted" although the service then runs the older program (which logs "could not
secure the keys directory" at every start). So, from an elevated PowerShell: run `att-monitor stop`,
move `C:\ProgramData\ATTMonitor\connections` and `C:\ProgramData\ATTMonitor\geo` out of the data
folder (or delete them: they hold only the Network page's samples and its IP database), then run the
older version's `install` (which also drops the `connections` and `geo` settings from `config.json`:
set them again after upgrading). To upgrade again later, stop the service, move the two folders
back, and run the newer version's `install`. From 1.3.0 on, `install` checks the data folder before
it stops the service or replaces the program, and changes nothing when it would refuse the folder.

## The gateway's outage "hijack" redirect

When the fiber or WAN is down, the BGW320 by default **redirects web browsing to its own "broadband is
down" page** (Diagnostics → Event Notifications → *Broadband Status Notification*). That hijacks the
connection your probes and browser use exactly when you need to see what is happening. The service
switches the redirect **off**, checks it at startup and every day, records every check in the ledger,
and switches it off again if AT&T re-enables it (for example with a firmware update or a remote reset).

```powershell
att-monitor gateway notification status
att-monitor gateway notification on    # restore AT&T's default (also stops the automatic enforcement)
att-monitor gateway notification off   # switch the redirect off again (and resume enforcement)
```

The monitor also records what the gateway's DNS answers during an outage: answers for every name that
point at the gateway itself are recorded as a DNS hijack. AT&T's account-level "DNS Error Assist"
(redirects for non-existent domains) is a separate setting at att.com → Profile → Privacy settings.

## Traffic: MRTG-style chart and flow meter (no SNMP needed)

Traffic graphs such as MRTG's usually poll a router's interface counters over SNMP. **The BGW320 offers
no SNMP to the home network**: a read-only SNMP query to its UDP port 161 is answered "port
unreachable", and none of the gateway's 49 web pages has an SNMP setting (AT&T manages the gateway from
its own network, with TR-069). There is nothing to point at this PC, and no SNMP traps are ever sent.

The same numbers are on the gateway's *Broadband Status* page, which needs no login and which the
monitor reads anyway with every snapshot (every minute, every 15 s during an outage): the WAN's **IPv4
receive and transmit byte and packet counters**. From two consecutive readings the monitor computes the
rate in each direction. The byte counters are 32-bit and wrap around every 4 GiB: the packet counters
tell whether a wrap is certain, and when the counter may have wrapped more often than can be told, the
rate is shown as **"at least"**. Counters that were reset (a gateway restart) never show as traffic.

* **Traffic chart** (the Overview's Traffic details, 1 hour to 7 days), drawn like an MRTG graph: download as a filled area,
  upload as a line, in bits per second with automatic units, short marks at the highest rate between two
  readings, the classifier's 80 Mb/s heavy-traffic line, "at least" markers, and gaps where there is no
  reading. Under it MRTG's legend (maximum, average and current for the WAN download, the WAN upload and
  this PC), a table view, and the volume per day.
* **Live flow meter** (the Overview's Traffic card and its details): the current download and upload
  through the gateway as numbers and bars, a sparkline of the last 15 minutes or so, and this PC's own
  rates. While the Traffic card or its details are on screen the dashboard asks every 5 seconds; the service reads the Broadband Status page for it at most
  once every 5 seconds whoever asks, and while nobody watches the gateway gets no extra request. The
  flow meter is a display only: nothing of it is recorded (the snapshots are the evidence), and it never
  holds up the evidence - it skips a reading while the service itself is reading the gateway, gives up
  a reading after 5 seconds, and waits while the gateway does not answer the service's polls.
* **This PC's traffic** comes from the 64-bit counters of its network adapter that reaches the gateway,
  so the household's traffic can be told from this PC's.

The same counters feed the classifier: a slowdown is attributed to AT&T only while they show less than
80 Mb/s in both directions, because heavy household traffic could explain it otherwise.

## The gateway's syslog

The BGW320 can send its own log messages to a syslog server on the home network (Diagnostics →
Syslog). The monitor is that server: it receives them on UDP port 514, only from the gateway's address
(`syslog.allow` adds other senders), keeps every message exactly as it arrived with the time this PC
received it, and shows them on the dashboard's **Syslog** page (with search and a severity filter) and
with `att-monitor syslog`. (SNMP is still not possible: the BGW320 offers none, see
[Traffic](#traffic-mrtg-style-chart-and-flow-meter-no-snmp-needed).)

### The monitor sets the gateway to send its log here, and keeps it so

Like the outage redirect, the monitor keeps the gateway's **Syslog** page as it needs it. In its daily
settings check (the first within 10 minutes after the service starts, and again within minutes after
this PC's address changes) it reads the page and records it; when the page shows anything else it sets
it to:

* **Syslog**: On;
* **Server IP Address**: this PC's IPv4 address on the gateway's network;
* **Server Port**: `514` (`syslog.port`);
* **Log Level**: the most detailed level the gateway offers - **Notice** on the BGW320-505 with firmware
  6.34.7, which offers Emergency, Alert, Critical, Error, Warning and Notice (no Informational, no
  Debug). A level named in `gateway.syslog_level` comes first, and a level already set while Syslog is
  on is kept.

It changes nothing else on the page, and does it the way a browser without JavaScript does: the page
enables its fields only once Syslog is On, so the monitor first switches Syslog on with the page's
*Update* button, then fills in the fields and saves. It then reads the page back: a change counts only
if the gateway shows it, and a page the monitor does not fully understand is never posted. Every reading
is recorded in the ledger with the page, and every change with the pages before and after (a
`gateway_event` and a `config_change`). A failed attempt is recorded too, shows as *The gateway's Syslog
page could not be set*, and is tried again at the next check. While the gateway is set to send here but
no message from it arrives for a day, the dashboard says so (at level Notice the gateway may log
little).

**Changing it.** The dashboard's **Syslog** page (and the Overview's Gateway syslog details) shows the setting
and whether the monitor keeps it: *Send the gateway's log to this PC* sets it now and keeps it so; *Stop
sending* switches Syslog off on the gateway and stops keeping it. Each asks first, saying what will
happen on the gateway, and shows the outcome; the choice is saved (`gateway.enforce_syslog`) and
recorded. The same from the command line:

```powershell
att-monitor gateway syslog          # the setting, whether it is kept, the receiver and the store
att-monitor gateway syslog on       # send the gateway's log to this PC, and keep it so
att-monitor gateway syslog off      # switch it off on the gateway, and stop keeping it
```

To have the monitor only read the page, without switching it off, set `gateway.enforce_syslog` to
`false` in `config.json` and restart the service. Uninstalling leaves the gateway's setting as it is:
stop the sending first (*Stop sending*, or `att-monitor gateway syslog off`) if the gateway should no
longer send its log to this PC.

**By hand.** When the monitor cannot set the page (no access code stored, or its attempt failed - the
dashboard and `att-monitor gateway syslog` then say how), set it on the gateway itself: open
https://192.168.1.254, go to **Diagnostics → Syslog** and sign in with the Device Access Code; set
**Syslog** to On (the page then enables its other fields), enter this PC's IPv4 address as **Server IP
Address** and `514` as **Server Port**, and save. `att-monitor gateway syslog` prints the address to
enter. The messages confirm it at once: within a minute the Syslog card counts them as received.

The gateway sends to an address, not to a computer: the monitor sets the page again after this PC's
address changes, and a fixed address for this PC (a DHCP reservation on the gateway) avoids the gap.
Several monitors on one home network would fight over the setting: let only one keep it
(`gateway.enforce_syslog` false on the others).

### Kept within a size limit, with every chunk on record

The ledger can never delete anything, so the messages are not written into it. They go to the **syslog
store** in `C:\ProgramData\ATTMonitor\syslog\`:

* Every 30 seconds the received messages are appended to the open chunk file, one JSON line per message
  (the exact datagram, its sender and the time it was received). A chunk is **sealed** (compressed with
  gzip) when it reaches 1 MiB, about 5 minutes after it was opened (at the next of those 30-second
  flushes), and when the service stops; a chunk that a crash, or a ledger that refused records, left
  open is sealed at the next start.
* For every sealed chunk the ledger gets a **`syslog_chunk`** record: the SHA-256, size and message count
  of its content, the receive times of its first and last message, and how many messages were dropped or
  rejected meanwhile.
* The store keeps the **newest 100 MB** (MiB) by default: once it holds more, the oldest sealed chunks
  are deleted first. Optionally it also deletes the chunks whose newest message is older than a number of
  days. The open chunk is never deleted.
* Every deletion is a **`syslog_prune`** record naming the deleted chunks, their SHA-256 and the limit
  that deleted them.

So the ledger shows which messages existed and when, and when and why they were deleted, and every kept
chunk can be checked against its record (also in exported evidence bundles).

**Changing the limit.** The dashboard and the command line save the change, record it in the ledger as
a `config_change` and apply it at once; the chunks that no longer fit are deleted and recorded:

* Dashboard → **Syslog** → *Stored messages* shows the space used and lets you choose how much to keep
  (MiB, and optionally days). It asks first when the change deletes messages now. Saving the limits
  already in force changes, records and deletes nothing, and the page says so.
* `att-monitor syslog retention` shows the space used and the limits;
  `att-monitor syslog retention --keep-mb 250 --keep-days 30` changes them (a limit left out stays as it
  is). It too asks first when the change deletes messages now; `--yes` answers in advance (for scripts).
  While the service is stopped the change is recorded directly and applied when the service starts.
* Or edit `syslog.keep_mb` / `syslog.keep_days` in `config.json` and restart the service.

**Receiver limits.** Messages are accepted only from the gateway's address (and `syslog.allow`), at most
2,000 a minute (`syslog.max_per_minute`), 8 KiB each, and at most 1 MB a minute as stored. What goes
beyond is counted as dropped, and datagrams from other senders as rejected; the counts are in the
`syslog_chunk` records. The limits also bound what a device forging the gateway's address could make
the ledger grow by: a few MB a day at most.

**Windows Firewall.** `install` (and `setup`) add the inbound rule *AT&T Internet Monitor syslog*: UDP,
the port of `syslog.listen` (514), only from the gateway's address and only for `att-monitor.exe`.
`uninstall` removes it, and so does `install` while `syslog.enabled` is false. Run `install` (or `setup`)
again after changing `gateway.host` or `syslog.listen`; a sender added to `syslog.allow` needs a rule of
its own.

**What it proves.** Syslog over UDP has no authentication and no delivery guarantee. The records show
what this PC received (the exact bytes, the sender's address as Windows reported it, and this PC's
receive time), not that the gateway sent nothing else. The messages are supporting evidence: verdicts
and incidents do not depend on them.

## Network page: which device talks to which site

The dashboard's **Network** page shows the home network's own traffic, for one period at a time (the
last hour, 24 hours, 7 or 30 days, or a custom period of up to 31 days):

* **Connections**: which device talked to which site. Tiles (devices active, sites, organisations
  and countries, connections open now); a **flow diagram** from the devices through the
  organisations they reached (Google, Amazon, Netflix, ...) to the services (HTTPS, QUIC, DNS, ...),
  each band as wide as how often its connections were seen; a **world map** of the countries of the
  remote addresses; and a searchable, sortable **table**: device → remote address (with its reverse
  DNS name), organisation, country, service, first and last seen. Click a device to see it alone.
* **Firewall**: what the gateway's firewall blocked. Tiles (probes blocked from the Internet, their
  sources, packets from the home network blocked on their way out and from how many devices, the
  most probed service); the blocked packets **per hour**; a **world map** of where the probes came
  from; the most probed services, the most active sources, the reasons the gateway gives, and the
  devices whose outbound packets it blocked, with their destinations.

Every chart has a table view, and the page is read again every minute while it is open.

**Where the data come from.**

* **The gateway's NAT table** (Diagnostics → NAT Table): every connection the gateway is
  translating, with the device's address and the remote address and port. The page is behind the
  gateway's login, so the monitor reads it **every 4 minutes with the Device Access Code**, in one
  web session that it keeps alive: the gateway client reuses its session for 5 minutes after its last
  use, and the first read after a start waits for the service's settings check and uses its login,
  so the reads need no login of their own unless they pause (during an outage, for example) or the
  gateway ends the session. A read that fails for another reason (an error page, a page too large or
  too slow) keeps the session: it never leads to a login by itself. Every login follows the same
  rules as setup's (one attempt a minute at most, none after three rejections within an hour - also
  across restarts of the service), and the reads have a budget of their own: after two reads in a
  row that each needed a login the next waits an hour, after six logins within a day they pause
  until the next day, and reads that keep failing are tried less and less often (up to every two
  hours). The monitor only reads the page; it never reads it during an outage, after a failed
  measurement cycle or while a changed gateway certificate waits for your confirmation, and it stops
  for an hour when the gateway rejects the access code. Without a stored access code the NAT table
  is not read (the rest of the page still works).
* **The gateway's Device List** (Device → Device List, no login), every 15 minutes: the devices'
  names, addresses and MAC addresses, which name the NAT table's addresses. A device keeps its name
  when its address changes, and a device that has just joined is named after the next Device List
  read.
* **The gateway's syslog** (see [The gateway's syslog](#the-gateways-syslog)): at its most detailed
  level (Notice) the BGW320 logs the packets its firewall drops. The page counts them by direction,
  source, target and reason; a "repeated N times" line counts N more.
* **The IPtoASN database** (https://iptoasn.com): which organisation (network) announces an address,
  and the country where that network is registered. The database is kept on this PC, so no address
  is sent anywhere to name it.

**Limits.** The NAT table is read every 4 minutes, so a connection that opens and closes between two
reads is not seen. The gateway lists IPv6 connections in the same table (they are not translated);
each is named after the device whose address it uses (one the Device List lists, or another of the
home network's IPv6 addresses). In a period with more than 200,000 distinct
connections (a device file sharing or scanning the Internet) the lightest are counted only in their
devices and as "Other", and the page says so. The syslog shows only what
the firewall drops, never the connections it allows. Countries are where the networks are registered,
not where a server stands (a CDN's server is often much nearer). The gateway does not log the names
devices look up, so sites are shown by address, organisation and reverse DNS name, not by the web
address typed.

**Privacy.**

* All of it stays on this PC. It is **not evidence**: it is never written into the ledger, the
  MongoDB copy or an evidence bundle; it lives in `connections\` and `geo\` in the data folder and is
  shown only on the dashboard (and by `att-monitor network`).
* Connection samples are kept for `connections.keep_days` (30 days) within `connections.keep_mb`
  (200 MiB); older days are deleted - every hour, also while sampling is off.
* For checking the parsers against your gateway's firmware, the service keeps a copy of the NAT table
  page and of the Device List page it read (`connections\last-nattable.html`,
  `connections\last-devices.html`: the first page read after each start, and pages it did not
  understand). They hold what the samples hold - your devices' connections, names, MAC and IP
  addresses - but not the Wi-Fi network's name, which is removed from the Device List's copy. They
  are deleted once they are older than `connections.keep_days`, and at the start of the service
  while `connections.enabled` is `false`.
* Reverse DNS names of the remote addresses the connections table shows are looked up through this
  PC's own DNS resolver (`connections.reverse_dns`, on by default) and cached in `geo\ptr-cache.json`:
  a name for 7 days, "no name" for a day (at most `connections.keep_days`). An answer older than that
  is no longer saved (the file is rewritten without it) and is forgotten a day later; the file is
  deleted while `connections.reverse_dns` or `geo.enabled` is `false`.
* The only download is the public IPtoASN data (two files of a few MB, public domain under the PDDL
  1.0), once a week from iptoasn.com: plain downloads, the same for everyone, which never carry an
  address. Set `geo.download` to `false` to switch them off (tables placed in `geo\` by hand are then
  used), or `geo.enabled` to `false` to do without organisations and countries.
* The world map is drawn from Natural Earth's country outlines (public domain), as packaged in
  world-atlas (ISC licence; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)), shipped with the
  program: the page loads nothing from the Internet.

From the command line, through the running service:

```powershell
att-monitor network                               # the last 24 hours: devices, organisations, countries, connections
att-monitor network --range 7d --device mac:00:00:5e:00:53:01   # one device's connections (keys are listed)
att-monitor network --firewall --range 1h         # what the gateway's firewall dropped in the last hour
att-monitor network --from 2026-10-01 --to 2026-10-03 --limit 100 --json
```

To stop the sampling, set `connections.enabled` to `false` in `config.json` and restart the service:
what was recorded stays on the page until the retention limits delete it.

## Dashboard

**http://127.0.0.1:8320**, on the monitoring PC only.

* **Overview**: a summary on about one screen - the current state in plain words with its cause,
  attribution and key facts and the last 24 hours as a strip of states; six key numbers; nine summary
  cards (Internet, AT&T gateway, Fiber optics, Traffic, This PC's link, Network, Gateway syslog,
  Evidence, Monitor & clock) with status chips and 24-hour trend lines; the newest incidents. Each card
  opens its **details** in a window over the page: the tables, the latency, loss, availability, traffic
  (MRTG-style, with daily totals) and optical charts from 1 hour to 7 days, the live flow meter, and the
  gateway's Syslog setting with the buttons that change it. Esc, Close, a click outside or Back closes
  it; the details update while open, and the address (`#/?detail=...`) reopens them.
* **Incidents**: every outage with its timeline and evidence (raw gateway pages, traceroutes, DNS
  results) and a one-click evidence export.
* **Gateway**: every value read from the gateway, the fiber module diagnostics and the redirect setting.
* **Syslog**: the receiver and the gateway's Syslog setting - whether the monitor keeps it sending here,
  with *Send the gateway's log to this PC* and *Stop sending*; the gateway's log messages with search
  and a severity filter, each linked to the ledger record of its chunk (a very long message is
  shortened in the list; *Exact datagram* under it shows all of it); the space the syslog store uses
  and how much of it to keep.
* **Network**: which device talks to which site, and what the gateway's firewall blocks (see
  [Network page](#network-page-which-device-talks-to-which-site)); not evidence.
* **Evidence**: ledger head, key fingerprint, time-stamps, *Verify now*, exports and operator notes
  (for example "Called AT&T, ticket 12345").
* **Records**: the raw ledger, record by record.
* Banners warn about the gateway's optical alarm, a changed gateway certificate (authenticated actions
  pause until you confirm it, which you should do only after an AT&T update), a VPN or second network
  bypassing the gateway, low disk space, a wrong PC clock, a ledger that refuses records, a syslog
  receiver that cannot listen (another program on UDP 514), a syslog store that fails, a gateway Syslog
  page that could not be set, or no syslog message from the gateway for a day.

## Data storage: ledger and MongoDB

All data lives in `C:\ProgramData\ATTMonitor` (readable by users, writable by the service and
administrators):

| Path | Contents |
|---|---|
| `ledger\` | the signed, hash-chained ledger, one JSONL segment per day |
| `blobs\` | raw gateway pages, traceroute output and time-stamp tokens, gzip, named by SHA-256 |
| `keys\` | the ledger signing key and the gateway access code, DPAPI-encrypted (SYSTEM and Administrators only) |
| `syslog\` | the gateway's syslog messages in chunk files (the only evidence that is ever deleted: within `syslog.keep_mb`, each deletion recorded) |
| `connections\` | the Network page's samples of the gateway's NAT table and Device List, one file per day (not evidence: kept for `connections.keep_days` within `connections.keep_mb`) |
| `geo\` | the Network page's IP database (the IPtoASN tables) and reverse DNS cache (not evidence) |
| `exports\` | evidence bundles |
| `logs\` | service logs (never contain secrets) |
| `config.json` | settings |

### The MongoDB copy

When MongoDB runs on the PC, the service keeps a continuously synchronized copy of the evidence in the
database **`attmonitor`**. It is a convenient place to query and analyse the data; the signed ledger
stays the source of truth and the chain of custody.

| Collection | One document per | Fields |
|---|---|---|
| `records` | ledger record (`_id` = seq) | `seq`, `ts` (date), `type`, `run`, `prev`, the exact `h`, `s`, `b` strings, and `data` (the record's content as BSON, for queries) |
| `blobs` | raw file (`_id` = SHA-256) | `data` (the exact bytes), `size`, `first_seq` |
| `incidents` | incident (`_id` = incident id) | the latest state of the incident and the record it comes from |
| `syslog` | syslog message (`_id` = `<chunk>#<line>`) | `chunk`, `chunk_seq` (its `syslog_chunk` record), `line`, the exact `raw_line` (which holds the message's text), and `rx` (date), `src`, `severity`, `facility`, `host`, `app` for queries |
| `meta` | `replication` | how far the copy has got, and the ledger's fingerprint |

* Records are copied in order, each exactly once; a restart or a MongoDB outage only delays the copy
  (the dashboard shows how far behind it is), and evidence recording never waits for MongoDB.
* Because every record keeps its exact `h`, `s` and `b`, a record read from MongoDB can be checked on its
  own: `h` must be the SHA-256 of `b` and `s` a valid signature of `b` under the ledger key. If a record
  in MongoDB differs from the ledger, the service reports it and never overwrites it.
* The `syslog` collection follows the syslog store: the messages of every sealed chunk are copied once
  the chunk matches its `syslog_chunk` record, and deleted when a `syslog_prune` record deletes the
  chunk. Each message is stored uncompressed, tens of times the space it takes in the store's
  compressed chunks (far more for repetitive messages), so the collection has a limit of its own: its
  documents take at most `syslog.keep_mb` MB (100 by default, before MongoDB's own compression, plus
  the indexes). Beyond that it keeps the newest messages - the oldest chunks' documents are deleted
  from the copy, while the store still has those chunks - and `mongo verify` counts such chunks
  without reporting them.
* The local MongoDB server accepts writes from any local program, so the copy is not evidence by
  itself. Compare it with the ledger at any time:

  ```powershell
  att-monitor mongo verify     # every record: same h, s and b as the ledger, valid hash and signature;
                               # also reports missing, altered or forged documents and blobs, and
                               # syslog documents that do not reproduce their chunk's SHA-256
  att-monitor mongo status
  ```

Example queries in `mongosh`:

```javascript
use attmonitor
// incidents attributed to AT&T, newest first
db.incidents.find({ "incident.attribution": "provider" }).sort({ updated: -1 })
// gateway snapshots in which the gateway raised its low-Rx optical alarm
db.records.find({ type: "gateway_snapshot", "data.derived.alarms": "OPTICAL_RX_LOW_ALARM" },
                { ts: 1, "data.derived.rx_power_x10": 1 })
// cycles per verdict state over the last day
db.records.aggregate([
  { $match: { type: "sample", ts: { $gte: new Date(Date.now() - 864e5) } } },
  { $group: { _id: "$data.verdict.state", cycles: { $sum: 1 } } }])
// the gateway's syslog messages of severity "err" or more severe, newest first
db.syslog.find({ severity: { $lte: 3 } }, { rx: 1, app: 1, msg: 1 }).sort({ rx: -1 })
```

To use another server or database, or to switch the copy off, edit the `mongo` section of
`config.json` and restart the service. The URI must not contain a user name or password: the
configuration is recorded in the ledger and in evidence bundles.

## Report for an AT&T service ticket

```powershell
att-monitor ticket-report --hours 24 --out C:\Reports --name "Your Name" --account 123456789 --phone "555-0100"
```

This exports a verifiable evidence bundle for the last 24 hours, verifies it, and writes a PDF (and an
HTML copy) that AT&T can act on. Page 1 is a summary for AT&T: the gateway's optical readings and
alarms (including when an alarm cleared and step changes of the receive level across a loss of light),
fiber link changes and gateway restarts, outages attributed to AT&T, the health of the home network,
and a requested action. The following pages hold the details: gateway identity, an optical chart and
readings table, gateway events, incidents, monitoring coverage, and how to verify the evidence. Every
figure is computed from the signed records the bundle contains, and the PDF's SHA-256 is recorded in
the ledger. The PDF is printed with Edge or Chrome in headless mode.

## Giving evidence to AT&T

1. Note calls and ticket numbers as you go: `att-monitor note "AT&T ticket 123456 opened, tech scheduled"`.
2. Export a bundle: Dashboard → Evidence → *Create export*, or
   `att-monitor export --from 2026-10-01 --to 2026-10-31 --prepared-by "Your Name" --out .`
3. Send the zip and, separately (for example by email), your **ledger key fingerprint**. `REPORT.html`
   inside is the readable summary. The bundle also holds the gateway's syslog chunks of the period that
   the syslog store still keeps (`syslog/`). Anyone can check the bundle:
   * `python tools/verify_bundle.py <zip>` checks the ledger, signatures, record times, the RFC 3161
     time-stamps (with OpenSSL) and every syslog chunk against its `syslog_chunk` record, using only
     Python's standard library plus the optional `cryptography` package;
   * `att-monitor verify-bundle <zip> --expect-fingerprint <fp>` does the same and also re-computes the
     report from the records, so an edited figure fails.

   Chunks of the period that the retention limit had deleted are listed as such, not failed: their
   SHA-256 stays in their records.

Tips that make the evidence stronger: monitor over **wired Ethernet** if you can (it removes "it's your
Wi-Fi"), disable sleep on the monitoring PC (sleep shows up as gaps), and keep the service running
continuously, because healthy periods are evidence too.

## Chain of custody

* **Integrity**: SHA-256 hash chain plus an Ed25519 signature on every record; raw bytes stored
  content-addressed; crash-safe appends with recovery that quarantines, never silently repairs.
* **Time**: RFC 3161 tokens from two independent authorities; only tokens whose certificate chains
  verify count as proof of time. Record times are checked against those anchors and against NTP.
* **Identity**: the key fingerprint you hand out separately ties a bundle to your ledger.
* **Honesty**: what cannot be attributed is labelled *undetermined*; monitoring gaps, restarts and PC
  sleep are recorded as such, and the bundle's own report is re-derivable from its records.
* **Syslog**: the messages live outside the ledger, within a size limit, but the ledger states the
  SHA-256 of every chunk of them and records every deletion, so a kept chunk can be checked and a
  deleted one is accounted for.

[docs/CHAIN_OF_CUSTODY.md](docs/CHAIN_OF_CUSTODY.md) explains what the evidence proves and how to verify
it step by step; [docs/DESIGN.md](docs/DESIGN.md) is the full specification and
[docs/PACKAGES.md](docs/PACKAGES.md) the package contracts.

## Commands

```text
att-monitor setup                                 guided install (what a double-click runs): asks only for
                                                  the gateway's Device Access Code
att-monitor install [--data DIR] [--listen 127.0.0.1:8320] [--access-code-file PATH] [--bootstrap DIR]
att-monitor uninstall [--interactive] | start | stop | status
att-monitor run [--data DIR]                      run in the foreground (console mode)
att-monitor set-access-code (--file PATH | --stdin)
att-monitor gateway notification [status|on|off]
att-monitor gateway syslog [status|on|off] [--json]
                                                  the gateway's Syslog setting, the receiver and the store; on: send
                                                  the gateway's log to this PC and keep it so; off: stop it
att-monitor gateway trust-cert                    confirm a changed gateway certificate (after an AT&T update)
att-monitor syslog [--since 24h] [--grep TEXT] [--severity LEVEL] [--limit N] [--json]
                                                  the gateway's syslog messages, oldest first (through the service)
att-monitor syslog retention [--keep-mb N] [--keep-days D] [--yes]
                                                  how much syslog is kept: shows it, or changes it
att-monitor network [--range 1h|24h|7d|30d | --from TIME --to TIME] [--device KEY] [--firewall]
                    [--limit N] [--json]          the Network page in short (through the service): which
                                                  device talked to which site, or what the firewall dropped
att-monitor verify [--json]                       verify the whole ledger
att-monitor verify-bundle FILE.zip [--expect-fingerprint FP] [--json]
att-monitor export --from TIME --to TIME | --incident ID [--prepared-by NAME] [--notes TEXT] [--out DIR]
att-monitor note "text" [--author NAME]
att-monitor ticket-report [--hours 24] [--out DIR] [--name N] [--account A] [--address ADDR] [--phone P]
                          [--best-time T] [--notes TEXT] [--no-pdf]
att-monitor mongo status | verify [--json]        the MongoDB copy of the ledger
att-monitor anchor                                time-stamp the ledger head now
att-monitor version
```

TIME is `YYYY-MM-DD`, `YYYY-MM-DDTHH:MM` (local time) or RFC 3339; a date-only `--to` includes that day.
`syslog --since` takes a duration such as `30m`, `1h`, `24h` or `7d` (at most 31 days); `--severity`
keeps that level and the more severe ones (`0`-`7`, or `emerg`, `alert`, `crit`, `err`, `warning`,
`notice`, `info`, `debug`); `--limit` (200 unless given, at most 5000) keeps the newest, and one
answer of the service holds at most 16 MiB of messages (very long ones end it sooner: shorten `--since`
or filter to see older ones). Each run of messages is headed by its chunk and the ledger record that
states the chunk's SHA-256.
`network` summarizes the dashboard's Network page: the last 24 hours unless `--range` (`1h`, `24h`,
`7d`, `30d`) or `--from`/`--to` (TIME as above; a date-only `--to` without `--from` is that day alone;
at most 31 days of 24 hours, so 31 whole days that include the change back from summer time are an
hour too long) say otherwise; `--device` takes a device key as the list of devices shows it (`mac:…`,
`ip:…`, `gateway`); `--limit` (20 unless given, at most 1000) is how many connections (with
`--firewall`: blocked outbound destinations) are listed; `--json` prints the service's answer. It
needs the running service.

## Configuration

`C:\ProgramData\ATTMonitor\config.json` is created with defaults on first start; restart the service
after editing it. Main settings:

| Setting | Default | Meaning |
|---|---|---|
| `gateway.host` | `192.168.1.254` | the BGW320's address |
| `gateway.enforce_notification_off` | `true` | keep the outage redirect switched off |
| `gateway.enforce_syslog` | `true` | keep the gateway's Syslog page sending its log to this PC while the receiver is on (`syslog.enabled`); `false`: only read it |
| `gateway.syslog_level` | `""` | the Log Level to set, when the gateway offers it; empty (or not offered): the level already set while Syslog is on, else Informational if the gateway offers it, else the most detailed level but Debug (Notice on the BGW320-505) |
| `gateway.poll_interval` / `incident_poll_interval` | `1m` / `15s` | gateway snapshots |
| `probes.fast_interval` | `10s` | the measurement cycle |
| `incident.open_after_cycles` / `window_cycles` | `3` / `6` | an incident opens when 3 of 6 cycles fail |
| `anchoring.interval` / `tsa_urls` | `30m` / DigiCert, FreeTSA | RFC 3161 time-stamps |
| `web.listen` | `127.0.0.1:8320` | the dashboard (loopback addresses only) |
| `mongo.enabled` / `uri` / `database` | `true` / `mongodb://127.0.0.1:27017` / `attmonitor` | the MongoDB copy |
| `mongo.store_blobs` | `true` | also copy the raw files into MongoDB |
| `syslog.enabled` | `true` | receive and keep the gateway's syslog messages |
| `syslog.listen` / `port` | `:514` / `514` | the UDP address the receiver listens on / the port the gateway is to send to |
| `syslog.allow` | `[]` | further senders (IP addresses) accepted besides the gateway |
| `syslog.flush_interval` / `max_per_minute` | `30s` / `2000` | how often received messages are stored / the most kept per minute |
| `syslog.keep_mb` / `keep_days` | `100` / `0` | keep at most this many MiB of syslog (1 to 1,048,576) and, above 0, nothing older than this many days |
| `connections.enabled` | `true` | sample the gateway's NAT table and Device List for the Network page (not evidence) |
| `connections.interval` / `devices_interval` | `4m` / `15m` | how often the NAT table (2 to 4 min: a longer interval would need a gateway login for every read; needs the access code) and the Device List (5 min to 24 h) are read |
| `connections.keep_days` / `keep_mb` | `30` / `200` | keep the samples this many days (1 to 3650), within this many MiB (10 to 1,048,576) |
| `connections.reverse_dns` | `true` | look up the reverse DNS names of the remote addresses shown, through this PC's resolver |
| `geo.enabled` | `true` | name the remote addresses' organisations and countries with the offline IPtoASN database |
| `geo.download` / `url_v4` / `url_v6` / `refresh` | `true` / iptoasn.com's files / `168h` | download the database (https only, no credentials, query or fragment: the configuration is recorded in the ledger) and look for a newer one every 7 days (1 to 90 days); `false`: use the files placed in `geo\` by hand |

A `connections` or `geo` value outside its range, or one that cannot be read, never stops the
service: it is replaced (0 or less by the default, a value beyond a limit by that limit, a URL that is
not https or carries credentials (a user name or password), a query or a fragment by the default
URL, a switch that is not `true` or `false` by off), and the replacement is logged in
`logs\service.log`, reported in the Network page's status (`/api/network/status`) and shown by
`att-monitor network`. Any other setting the service cannot work with stops it until `config.json`
is corrected: `logs\service.log` and `att-monitor status` say why. Save the file as UTF-8 (a byte
order mark is accepted).

## Privacy, security and network use

* The dashboard listens on 127.0.0.1 only and rejects requests from other sites (a page of another
  site cannot make it change anything, nor read anything - not even make it build an answer).
* The gateway access code is stored DPAPI-encrypted in a folder only SYSTEM and Administrators can read;
  it never appears in logs, the ledger or exports.
* Evidence bundles contain your gateway's serial number, your public IP address and your outage
  history: share them with AT&T, not publicly. The gateway's syslog may also name devices on your home
  network and remote addresses (from its firewall messages), and bundles include the syslog of their
  period.
* Syslog text is untrusted (anything on the network can send a datagram): it is accepted only from the
  gateway's address, within size and rate limits, stored JSON-escaped, and shown escaped on the
  dashboard and in the terminal. The service's answers (at most 16 MiB of messages each) and the
  dashboard's list (long messages shortened) stay bounded however the messages are made.
* The Network page's data - which device talked to which site, the devices' names and MAC addresses,
  what the firewall blocked - describe your household's traffic. They stay on this PC (readable, like
  the rest of the data folder and the dashboard, by its users), are never evidence, never in the
  ledger, the MongoDB copy or a bundle. The connection samples, the copies of the gateway's pages and
  the reverse DNS names are deleted after `connections.keep_days` (the names sooner); what the
  firewall blocked comes from the gateway's syslog, which is kept as `syslog.keep_mb` /
  `syslog.keep_days` say. `connections\` and `geo\` stay in the data folder after an uninstall,
  like the rest of it. Device names, organisation names and reverse DNS names are shown escaped, as
  syslog text is.
* Outbound traffic: pings and TCP connects to 1.1.1.1, 8.8.8.8, 9.9.9.9 and AT&T's next hop; DNS queries
  for www.google.com; HTTP checks to msftconnecttest.com and google.com; SNTP to time.windows.com,
  time.google.com and pool.ntp.org; and **only a SHA-256 digest** to the Time-Stamp Authorities. For
  the Network page: the public IPtoASN files from iptoasn.com once a week (`geo.download`), and reverse
  DNS queries for the remote addresses it shows, through this PC's resolver (`connections.reverse_dns`).
  MongoDB is used on the local PC only. Inbound: UDP 514 from the gateway (its syslog). The monitor logs
  in to the gateway about once a day (and after this PC's address changes) to check, and if needed set,
  its outage-redirect and Syslog settings, and reads the gateway's NAT table every 4 minutes in a web
  session it keeps (no new login while the reads go on; at most six a day caused by the reads, and
  none sooner than a minute after the previous attempt, also across restarts) and its Device List
  (no login) every 15 minutes. While the Overview's Traffic card or its details are on screen, the flow meter reads the gateway's Broadband Status
  page at most every 5 seconds.

## Development

```text
cmd/att-monitor     CLI, Windows service, install/upgrade, ticket-report
internal/model      record and API types           internal/contracts  interfaces between packages
internal/config     settings, DPAPI secrets         internal/ledger     signed hash-chained ledger
internal/gateway    BGW320 client and parsers       internal/probe      ICMP/TCP/DNS/HTTP probes, Wi-Fi
internal/monitor    scheduler, classifier           internal/anchor     RFC 3161 time-stamps
internal/export     evidence bundles, verifier      internal/ticket     the AT&T ticket report (HTML/PDF)
internal/mongostore MongoDB copy and its verifier   internal/web        dashboard and JSON API
internal/syslogrx   syslog receiver (UDP)           internal/syslogstore syslog chunks within a size limit
internal/connstore  Network page: NAT samples       internal/ipintel    Network page: IP database, ports, PTR
internal/netmap     Network page: the views         internal/winsvc     service control, ACLs
internal/sysinfo    host and software identity
```

```powershell
go test ./...                                     # unit tests (no network, no gateway)
$env:ATTMON_MONGO = "1"; go test ./internal/mongostore/   # live tests against a local MongoDB (throwaway database)
.\scripts\e2e.ps1                                 # end-to-end run in a temporary data folder
```

Tests never log in to or change a real gateway; gateway fixtures in `testdata\gateway` are sanitized
captures.

## Acknowledgements

Earlier BGW320 projects that informed the gateway client:
[Yeraze/BWG320-monitor](https://github.com/Yeraze/BWG320-monitor) and
[TheSethRose/BGW320-CLI](https://github.com/TheSethRose/BGW320-CLI).

The Network page uses the [IPtoASN](https://iptoasn.com) database (public domain, PDDL 1.0),
downloaded at run time, and ships a world map made from [Natural Earth](https://www.naturalearthdata.com)'s
1:110m country outlines (public domain) as packaged in [world-atlas](https://github.com/topojson/world-atlas)
(ISC licence, whose notice is in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and in the map
itself); `scripts/worldmap` makes it.
