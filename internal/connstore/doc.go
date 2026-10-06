// Package connstore keeps the samples behind the dashboard's Network page
// (docs/syslog-map-graphic.md): the monitor's reads of the gateway's NAT table (every
// connections.interval, 4 minutes by default) and of its Device List (every 15 minutes), in
// daily files, for connections.keep_days within connections.keep_mb. Aggregate turns the reads
// of a period into which device talked to which remote address, port and protocol.
//
// None of it is evidence. These files describe the household's own traffic, not the ISP's
// faults: they are never written to the ledger (which can never delete anything, and would keep
// browsing patterns for ever), copied to MongoDB or put into evidence bundles, and the store
// deletes them by its own retention limits.
//
// # Files
//
// In the store's directory (config.Paths.Connections), one file per kind and UTC day:
//
//	nat-YYYY-MM-DD.jsonl          the NAT table reads of the day, one line each, appended
//	                              (written and fsynced by every AppendNAT)
//	devices-YYYY-MM-DD.jsonl      the Device List reads of the day (AppendDevices)
//	<name>.jsonl.gz               the same, gzip, once the day is over
//	<name>.jsonl.gz.tmp           a compressed copy being written (deleted by Open)
//
// The monitor writes other files into the same directory (last-nattable.html,
// last-devices.html): the store only ever touches files whose names are exactly its own.
//
// Every read is stored in the file of its own UTC day, so a file only ever holds the reads of its
// day. A day is compressed by the first append of a later day, and in the background after Open
// (see Open): its plain file is compressed into a temporary file, checked to decompress to the
// same bytes, fsynced and renamed into place, and the plain file is deleted. When the clock is set
// back over midnight UTC, a read of a day that was compressed already goes to a new plain file of
// that day, next to its compressed one; the next compression merges the two. The reads stored
// while the clock was ahead stay in the file of their later day, kept as they are until that day
// is over; once the clock is corrected, the reads go to today's file again (logged once).
//
// # Lines
//
// Each line is one JSON object; "t" (the read's time, RFC 3339 UTC with nanoseconds) comes
// first, so that a reader can skip the lines outside a period without decoding them. A NAT
// read:
//
//	{"t":"2026-10-06T08:00:00.123456789Z","in_use":412,"available":7780,
//	 "strs":["tcp","ESTABLISHED","192.168.1.10","203.0.113.5"],"s":[0,1,2,50000,3,443]}
//
// in_use and available are the page's totals (-1 when it shows none); display and skipped the
// page's display selection and the rows the gateway client could not parse (left out when empty
// or 0). The sessions are a table of the distinct strings they use (strs) and six integers per
// session (s): protocol, TCP state and source address as indexes into strs, the source port,
// the destination address (an index), the destination port. A Device List read:
//
//	{"t":"2026-10-06T08:00:00.123456789Z","devices":[{"mac":"00:00:5e:00:53:01","name":"laptop",...}]}
//
// with the devices as model.LANDevice encodes them.
//
// # Crash safety
//
// A line is written with one write at the end of the file's complete lines, then fsynced; when
// the write fails, the file is cut back to its complete lines. Open repairs what a crash left
// (see Open): an incomplete last line is cut off, a temporary compressed copy is deleted, and a
// plain file that had been compressed already is recognized (the compressed file's content ends
// with it) and deleted. A line that cannot be decoded is skipped with a warning (once per file),
// never fatal; so is a session whose indexes or addresses do not parse.
//
// # Retention
//
// Prune deletes whole days (both kinds), oldest first: each day that ended keep_days days or
// more ago, then the oldest days while the files kept exceed keep_mb MiB (compressed days at
// their stored size). Today and later days are never deleted. The monitor calls Prune every hour,
// whether or not its samplers run (with connections.enabled off nothing is appended, yet the
// limits must keep applying), and the appends prune at most once an hour too. SetRetention changes
// the limits: the next append or Prune applies them.
//
// What the age limit deletes is gone for good, and a wrong clock makes days look old (Windows'
// Secure Time Seeding has set clocks months ahead): so it trusts the clock no further than the
// monotonic clock, which nothing sets. Open (in the background) applies only keep_mb; keep_days
// waits until the store has been open for an hour (a timer Open sets applies it then, should no
// append or Prune do it first), so that a clock that was wrong when the service started and is
// corrected meanwhile deletes nothing. While the clock is more than an hour ahead of the time the
// monotonic clock has measured since the two last agreed (it was set forward), keep_days is
// applied as of the monotonic clock's time - the days old by it still go - until the clock agrees
// again, or for a day at most (a step that lasts is taken as the correction of a clock that was
// behind). Both are logged. A clock already wrong when the service starts, and wrong for more than
// an hour, is not caught: nothing in the store tells it from a long stop.
//
// # Concurrency
//
// One process writes the store: the monitor, whose ledger lock keeps a second one away (Open
// repairs, then compresses and prunes in the background: the CLI must not open the store while the
// service runs). The writing methods (AppendNAT, AppendDevices, Prune, Close, Open's background
// work and the timer Open sets for the age limit) are serialized; any number of goroutines may
// read meanwhile (Aggregate, Devices, EachDevices, Usage) without waiting for them. A reader
// works from a snapshot of the index: it reads a plain file only up to its complete, fsynced
// lines (never a line being written). The writer marks a day (an odd generation of its index
// entry) while it replaces its compressed file, and a reader whose day changed generation while it
// opened the day's files opens them again, so that it always reads a state of the day the writer
// left it in - never a compressed file that already holds a plain file's reads together with that
// plain file.
// On Windows the readers open files with FILE_SHARE_DELETE and the writer replaces a compressed
// file with POSIX semantics (os.Root): a query never keeps the writer from compressing, merging or
// pruning a day, and keeps reading what it opened.
//
// # Aggregation
//
// For each NAT session, the side that is the home network's is the device on the home network: a
// private (RFC 1918, fc00::/7), link-local (169.254/16, fe80::/10) or shared (100.64/10) address,
// or one the Device List read in effect lists (a device's global IPv6 address), or an IPv6 address
// in the /64 of a global address it lists (a device's temporary addresses). It is the source when
// it is one (the device opened the session; the port is the remote one), else the destination
// (Inbound: the remote side opened it, through a port forward or an IPv6 pinhole; the port is the
// device's). A session with no such side is the gateway's own, from its public address: device
// "gateway", the remote side the destination. A LAN address is named after the Device List read in
// effect at the NAT read - the newest at or before it, else the first after it - or, when that
// read does not list it, after the next read when it comes within devNextWithin (20 minutes: a
// device that has just joined): "mac:<mac>" when that read lists a MAC address for the address (a
// device whose status is "on" first), else "ip:<address>". So a device keeps its key when its
// address changes, an address that DHCP gives to another device gets that device's key, and a new
// device is not counted twice (as its address, then as its MAC). EachDevices gives the Device List
// reads of a period, so that the firewall view (internal/netmap) names the LAN address of each
// dropped packet after the read in effect when it was received (the newest at or before it, else
// the first after it).
//
// A day's summary, and an aggregate, count at most maxFlows (200,000) distinct flows one by one:
// a device that opens connections to ever new addresses could otherwise make one query hold
// millions. Beyond, the lightest are left out - their sessions still count in their device's
// weight and LeftOut, and FlowsLeftOut counts them - so that the heaviest flows stay exact.
// Aggregate checks its context between days, every few lines and every few thousand flows merged
// or written out: a query whose request ended stops.
//
// Whole past days are summarized and cached, keyed by their files' names, sizes and modification
// times and by the Device List reads that named their addresses; only the days a period covers
// partly and today are read line by line, skipping the lines outside the period without decoding
// them. The cache holds at most 40 days, bounded in size. When the days do not all fit, it keeps
// the newest - every view of the Network page ends now - and never evicts a day to store an
// older one: a period with more days than fit reuses the days the cache holds and reads only the
// others again.
package connstore
