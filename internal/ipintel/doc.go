// Package ipintel names the addresses and ports shown on the dashboard's Network page without
// asking anyone about them (docs/syslog-map-graphic.md §2.1): the kind of an address (private,
// shared, loopback, link-local, multicast, reserved), the network that announces a public one -
// its AS number and name, a readable organisation name and the country where it is registered -
// from the offline IPtoASN database, the service a port stands for, and the reverse DNS name of
// a public address, cached. None of it is evidence: it is never written to the ledger, MongoDB or
// evidence bundles.
//
// # Data
//
// The IPtoASN tables (https://iptoasn.com, public domain under the PDDL 1.0) list the address
// ranges announced on the Internet, one tab-separated line per range, sorted: first and last
// address, AS number, country code and AS description, e.g.
//
//	1.0.4.0	1.0.7.255	38803	AU	WPL-AS-AP Wirefreebroadband Pty Ltd
//
// AS 0 (country "None", description "Not routed") marks space that nobody announces. The files
// are read into compact sorted range tables (IPv4: pairs of uint32; IPv6: pairs of 128-bit
// values) with the AS names deduplicated, and searched by binary search. The readable
// organisation name of a network ("Google" for AS15169 "GOOGLE", "Wirefreebroadband" for the line
// above) comes from a list of well-known networks or else from its description, tidied; it is
// worked out at the first lookup that needs it.
//
// In the DB's directory (config.Paths.Geo):
//
//	ip2asn-v4.tsv.gz   the IPv4 table, exactly as downloaded (or as placed there by hand)
//	ip2asn-v6.tsv.gz   the IPv6 table
//	ip2asn.json        what was downloaded (URL, ETag, Last-Modified, time, rows, size, SHA-256 of
//	                   each file) and when a newer table was last looked for
//	ptr-cache.json     the reverse DNS cache: the answers still current only (see Privacy)
//
// Files are replaced atomically (a temporary file, fsynced, renamed into place); temporary files
// a crash left behind are deleted by the next Run.
//
// # Downloads
//
// With Options.Download, Run fetches at once a table whose file is missing or cannot be loaded,
// and looks for newer ones every Options.Refresh (a week by default) with a conditional GET
// (If-None-Match, If-Modified-Since). Only https URLs are used, also after a redirect. A new file
// is streamed into a temporary file within a size cap, then decompressed and parsed completely and
// checked - a minimum number of announced ranges (100,000 IPv4, 10,000 IPv6), sorted, not
// overlapping, almost every line understood - before it replaces the old one; a failed or
// suspicious download keeps the old data and is retried after an hour, then two, four, ... up to
// Refresh. Every request has a deadline. Reading a file - downloaded or placed by hand - is
// bounded in time and memory whatever it holds (64 MiB decompressed, lines of at most 1 KiB, at
// most 2,000,000 ranges and 262,144 networks): about 200 MiB of memory for a few seconds at worst,
// 30 to 50 MiB for a table of the real one's size.
//
// # Privacy
//
// Looking up an address happens on this computer. The downloads are plain GETs of the public
// files, the same for everyone: they never carry an address. Reverse DNS (Options.ReverseDNS) is
// the only lookup that leaves the computer: the public addresses the dashboard asks to name are
// sent, as reverse DNS queries, to this computer's DNS resolver. Private, shared, loopback,
// link-local, multicast and reserved addresses are never looked up, in the database or by DNS.
//
// The reverse DNS cache is a list of remote addresses the household's devices talked to, so it is
// kept no longer than its answers hold: a name for 7 days, "no name" for a day - at most
// Options.KeepDays (connections.keep_days) either way. An answer that has outlived that is never
// saved, is still shown while it is looked up again, for a day at most, and is then forgotten;
// ptr-cache.json is rewritten without it at the next save (every few minutes while Run goes on),
// also when nothing new was learned. Without Options.ReverseDNS, or with the database disabled,
// Run deletes ptr-cache.json instead of loading it.
//
// # Concurrency
//
// Lookup, Service, PTR, Updated and Status may be called from any goroutine at any time and never
// wait for the network or for file I/O: a load or download builds a complete new table and swaps
// it in atomically, so a lookup sees either the old or the new table, never part of one. Until a
// table is loaded, Lookup still classifies. Run does the loading, downloading and reverse DNS
// lookups in the background; it is called once. This package runs inside the evidence logger: a
// panic in Run's work (a bug) is recovered, logged and reported by Status, never let through.
package ipintel
