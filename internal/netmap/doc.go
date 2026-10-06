// Package netmap builds the dashboard's Network page (docs/syslog-map-graphic.md): which device on
// the home network talked to which remote address, organisation, country and service (from the
// connection store's samples of the gateway's NAT table and Device List), and what the gateway's
// firewall dropped (from the gateway's syslog, kept by the syslog store). Organisations and
// countries come from the offline IP database (contracts.IPIntel); nothing here asks anyone on
// the network.
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
// # Bounded work
//
// A period is at most MaxRange (31 days), so a timeline has at most 745 hours. A sealed syslog
// chunk never changes: the first time it lies wholly inside a requested period it is read once
// and its summary is kept by its name in a cache bounded by memory and by count (least recently
// used first, and never an entry the running request needs); chunks the store no longer lists
// leave the cache. Only the chunks at the edges of a period are partly inside it: they are read
// again, exactly, as is the open chunk. A chunk sealed while a view is being built is noticed
// when the chunks are listed again at the end: the view is then built again (at most 3 times).
// One connections view and one firewall view are built at a time, and a view built for the same
// request less than 30 seconds earlier is returned again - for a period that ends now, the same
// range ("24h") is the same request, so that a second tab, a refresh or the CLI share the view.
//
// What a hostile sender can multiply is counted one by one only up to a bound (bounds): a
// firewall view's distinct inbound sources and outbound rows (100,000 each) and services (every
// TCP and UDP port). Beyond, every total - by direction, hour and reason - stays exact; the
// sources count by country and in HyperLogLog sketches, so that the distinct sources and the
// countries' sources become estimates within a few percent; the outbound rows count in sketches
// too (the rows and the devices that name themselves estimated); the services count as "Other";
// and a Space-Saving table keeps the 1,024 heaviest sources and outbound rows beyond the bounds,
// so the top lists still show any of them that sent a noticeable share. A chunk summary keeps
// at most 16,384 sources, rows or services and 1,024 hours - far more than a chunk the store
// seals at 1 MiB can hold: a chunk that holds more is read straight into the request's bounded
// sums and not kept. Repeat lines at a chunk's start are kept one per hour. A connections view
// names and draws at most 50,000 flows, the heaviest; the others count as "Other" in the
// diagram, in the totals - the distinct remote addresses then estimated - and in the rows. So a
// request's memory stays within a few tens of MiB, whatever a flood of spoofed packets fills the
// syslog store with.
package netmap
