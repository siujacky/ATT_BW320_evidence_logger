// Package netmap builds the dashboard's Network page (docs/syslog-map-graphic.md): which device on
// the home network talked to which remote address, organisation, country and service (from the
// connection store's samples of the gateway's NAT table and Device List), what the gateway's
// firewall dropped (from the gateway's syslog, kept by the syslog store), and the gateway's
// Device List - which device has which address - with each device's issues (docs/dhcp-table.md,
// from both). Organisations and countries come from the offline IP database (contracts.IPIntel);
// nothing here asks anyone on the network.
//
// None of it is evidence: the package only reads. It never writes the ledger, MongoDB, evidence
// bundles or any file, and it keeps nothing but in-memory caches.
//
// # Connections
//
// A flow of the NAT samples is named after its remote address: the organisation "org:<name>" of a
// public address whose AS the IP database names an organisation of - one company's ASes (Google's
// AS15169 and AS36040) are one organisation, which lists them - else "as<ASN>", "unknown" for a
// public address it does not know, "local" for every other address (private, shared, link-local,
// ...); and after its service "<proto>/<port>" when the port table names the port, else "other".
// The flow diagram keeps the 12 heaviest organisations and the 8 heaviest named services and
// groups the rest as "other" - with the flows the connection store left out beyond its bound. The
// totals count organisations by key, and how many of the period's devices the newest Device List
// lists. Every phase of a build checks its request's context.
//
// # Firewall
//
// The BGW320 logs, at its most detailed syslog level, only the packets its firewall drops:
//
//	… FIREWALL[8512]: nflog_log_fw(), action=DROP reason=POLICY-INPUT-GEN-DISCARD hook=INPUT mark=…
//	IN=veip0.0 OUT= MAC=…:SRC=203.0.113.66 DST=198.51.100.1 LEN=44 … PROTO=TCP SPT=21110 DPT=8071 …
//
// and syslog-ng's "Last message 'FIREWALL[8512]: nflo' repeated 3 times" lines, each of which
// counts that many more drops identical to the previous drop in receive order, also across chunk
// boundaries: the store's order, which is the sealed chunks oldest first (by the receive time of
// their first message), each in the order it stored its messages, then the open chunk. (Should
// this computer's clock be set back, two chunks may be listed in another order than they were
// received in; nothing records that order.) BSD syslogd's "last message repeated 3 times", which
// quotes nothing - the BGW320 does not write it; another sender admitted by syslog.allow may -
// repeats the message right before it, whatever that was: it counts drops only when that message
// was a drop or a repeat line counting drops.
//
// A drop is inbound when it came in on a WAN interface, outbound when it went from a LAN
// interface (br*, lan*, wl*) toward the WAN, and local otherwise (sent by the gateway itself, or
// between the LAN and the gateway). Times are this computer's receive times, never the gateway's
// own header times. The MAC field - which holds this network's hardware addresses - is never
// kept: the parser skips it. An outbound drop's LAN address is named after the connection
// store's Device List read in effect when the drop was received when the store can give its reads
// by time (deviceHistory: connstore.Store.EachDevices), else after its newest read.
//
// # Devices
//
// The Devices tab (docs/dhcp-table.md) is the gateway's Device List - its DHCP table - as the
// connection store's newest read shows it: each device with its identity as listed, and what the
// period says about it. The period's Device List reads (deviceHistory: the read in effect at its
// start, then every later one before its end) give how many of them listed the device and showed
// it on, when it was last seen on, the IPv4 addresses it held, and the address history: for each
// address, which device held it from which read to which. Of several entries that give one
// address, those that are on hold it (the gateway keeps showing the last address of a device that
// left); two that are on hold it together - a conflict, counted in the tenures' Shared. A tenure
// goes on over reads that show the address with nobody, and ends when another device holds it.
// The period's NAT samples (the connection store's Aggregate, which names their addresses as
// before) give each device's sessions in the newest NAT read (ConnDevice.Open) and the distinct
// remote addresses it reached; the syslog gives the packets the firewall dropped from each of its
// addresses (outbound) and on their way to them from the Internet (inbound with OUT= a LAN
// interface: unsolicited IPv6 to a device, a port forward), counted by LAN address in the chunk
// summaries (lanRow) and named after the Device List read in effect when they were received -
// else, as the connection store names a device that has just joined, after the next read within
// 20 minutes; a sealed chunk's drops of one address are named at the newest of them (a chunk
// holds at most 5 minutes). A device without a MAC address is known by its addresses ("ip:").
//
// A LAN address that the NAT samples or the firewall's drops show and that no Device List read of
// the period names is unknown when it is a private or link-local (self-assigned) IPv4 address -
// IPv6 addresses are not, as a device's temporary addresses are never listed. Issues: an IPv4
// address that another entry of the newest read claims too, neither shown off (address_shared,
// critical); a Wi-Fi signal of 1 or 2 bars (weak_wifi), a wired link at 10 Mb/s or less or at half
// duplex (slow_link), 100 or more packets dropped, out and in together (blocked), an unknown
// address (unlisted) - warnings; more than one IPv4 address in the period (address_changed), off
// in the newest read (offline) - facts. The devices are listed with the critical first, then the
// warnings, those on before those off, by name. Each source that is missing or cannot be read
// leaves its figures at 0; only the connection store is needed.
//
// The LAN scans of the period (Options.Scans, docs/dhcp-table.md §6) say which device answered each
// sweep at which address: an answer counts for the listed device of its MAC address; for nobody when
// a read of the period names that MAC address (a device that left the list); else for the entry
// without a MAC address that the Device List read in effect at the scan (else the next within 20
// minutes) gives the address to; else the address is unknown - also when a read gives it to another
// device - with the MAC address that answered. The gateway's own answer (Options.Gateway) is
// nobody's. Comparing the newest scan with the newest read, when it began within an hour of it:
// no_answer (a device shown on, in the network swept by a sweep that asked every address, did not
// answer), scan_addr (it answered at another IPv4 address than listed) - facts - and scan_mac (its
// address answered by another MAC address) - a warning.
//
// A device's details (Device, docs/dhcp-table.md §7) come from the Devices view built for the
// period (devBuild: the view and what the details need beyond it, kept for reuse like the views):
// the address history of its addresses, the newest scans as it answered them, and what its syslog
// messages are found by - its IPv4 holds widened by the Device List interval (the median time
// between the period's reads) on each side and clipped to the period, its IPv6 and MAC addresses
// for the whole period. The web layer reads the messages.
//
// # Bounded work
//
// A period is at most MaxRange (31 days), so a timeline has at most 745 hours. A sealed syslog
// chunk never changes: the first time it lies wholly inside a requested period it is read once
// and its summary is kept by its name in a cache bounded by memory and by count (least recently
// used first, and never an entry the running request needs); chunks the store no longer lists
// leave the cache. Only the chunks at the edges of a period are partly inside it: they are read
// again, exactly, as is the open chunk. A chunk sealed while a view is being built is noticed
// when the chunks are listed again at the end: the view is then built again (at most 3 times).
// One connections view, one firewall view and one devices view are built at a time - a devices
// view takes the connections slot for its NAT samples, then the firewall slot for its drops, one
// after the other - and a view built for the same request less than 30 seconds earlier is
// returned again - for a period that ends now, the same range ("24h") is the same request, so
// that a second tab, a refresh or the CLI share the view.
//
// What a hostile sender can multiply is counted one by one only up to a bound (bounds): a
// firewall view's distinct inbound sources and outbound rows (100,000 each) and services (every
// TCP and UDP port). Beyond, every total - by direction, hour and reason - stays exact; the
// sources count by country and in HyperLogLog sketches, so that the distinct sources and the
// countries' sources become estimates within a few percent; the outbound rows count in sketches
// too (the rows and the devices that name themselves estimated); the services count as "Other";
// and a Space-Saving table keeps the 1,024 heaviest sources and outbound rows beyond the bounds,
// so the top lists still show any of them that sent a noticeable share. A chunk summary keeps
// at most 16,384 sources, rows, services or LAN addresses and 1,024 hours - far more than a chunk
// the store seals at 1 MiB can hold: a chunk that holds more is read straight into the request's
// bounded sums and not kept. Repeat lines at a chunk's start are kept one per hour. A connections
// view names and draws at most 50,000 flows, the heaviest; the others count as "Other" in the
// diagram, in the totals - the distinct remote addresses then estimated - and in the rows. A
// devices view counts the drops of every address a Device List read names, and of at most 4,096
// other LAN addresses (only IPv4 ones that could be an unknown device's: a scan of the home
// network's IPv6 prefix or a host forging its source addresses adds nothing more), lists at most
// the request's limit of unknown addresses and keeps an address history of at most 5,000
// tenures, those that ended last. It reads at most 4,096 answers of a scan and adds at most 4,096
// unknown addresses from the scans (a host answering for every address cannot grow it), and keeps
// for the details each device's and unknown address's answers to the newest 800 scans only. So a
// request's memory stays within a few tens of MiB, whatever a flood of spoofed packets fills the
// syslog store with.
package netmap
