package model

// Network: which device on the home network talks to which remote address (from the gateway's
// NAT table and Device List) and what the gateway's firewall drops (from its syslog), for the
// dashboard's Network page (docs/syslog-map-graphic.md).
//
// None of it is evidence: it is never written to the ledger, copied to MongoDB or put into
// evidence bundles. The connection samples live in the connection store (connections\, kept
// for connections.keep_days within connections.keep_mb), the firewall view is computed from the
// syslog store.

// ------------------------------------------------------------------ gateway pages

// NATSession is one row of the gateway's NAT table (Diagnostics → NAT Table, nattable.ha) as
// shown: one connection the gateway is translating. Source is the side that opened it.
type NATSession struct {
	Proto   string `json:"proto"`           // "Protocol", lower case: "tcp", "udp", "icmp", ...
	State   string `json:"state,omitempty"` // "TCP State" as shown (e.g. "ESTABLISHED"); "" when empty
	Src     string `json:"src"`             // "Source Address": an IP address, in canonical form
	SrcPort int    `json:"sport,omitempty"` // "Source Port" (0 when empty or not a port number)
	Dst     string `json:"dst"`             // "Destination Address", in canonical form
	DstPort int    `json:"dport,omitempty"` // "Destination Port"
}

// NATTable is one read of the NAT table page.
type NATTable struct {
	Sessions []NATSession `json:"sessions"`
	// InUse and Available are "Total sessions in use" and "Total sessions available" (-1 when the
	// page does not show them).
	InUse     int `json:"in_use"`
	Available int `json:"available"`
	// Display is the option selected in the page's display selector, as labelled ("" when the page
	// has none). The monitor only reads the page: it never changes the selection.
	Display string `json:"display,omitempty"`
	// Skipped counts table rows that were left out because they were not understood (an address
	// that is not an IP address, a missing column, ...).
	Skipped int `json:"skipped,omitempty"`
}

// LANDevice is one entry of the gateway's Device List (Device → Device List, devices.ha).
type LANDevice struct {
	MAC  string `json:"mac,omitempty"`  // lower case, colon separated; "" unless a valid, non-zero MAC
	Name string `json:"name,omitempty"` // the name the gateway shows
	IPv4 string `json:"ipv4,omitempty"`
	// IPv6 lists the device's IPv6 addresses (global and link-local), in canonical form, each once.
	IPv6       []string `json:"ipv6,omitempty"`
	Status     string   `json:"status,omitempty"`     // "on" or "off", as shown
	Allocation string   `json:"allocation,omitempty"` // e.g. "dhcp" or "static", as shown
	// Connection summarizes "Connection Type": "Ethernet", "Wi-Fi", "Wi-Fi 2.4 GHz", "Wi-Fi 5 GHz",
	// ... The Wi-Fi network name the page also shows there is not kept.
	Connection   string `json:"connection,omitempty"`
	Speed        string `json:"speed,omitempty"`         // "Connection Speed", as shown ("" when it holds no number)
	Mesh         bool   `json:"mesh,omitempty"`          // "Mesh Client" is "Yes"
	LastActivity string `json:"last_activity,omitempty"` // as shown (the gateway's local time)
}

// ------------------------------------------------------------------ connection store

// ConnStoreUsage is the connection store's volume and its retention limits.
type ConnStoreUsage struct {
	Bytes    int64  `json:"bytes"` // every file kept (compressed days at their stored size)
	Files    int    `json:"files"`
	Oldest   string `json:"oldest,omitempty"` // time of the oldest sample kept (RFC 3339 UTC)
	Newest   string `json:"newest,omitempty"`
	KeepDays int    `json:"keep_days"`
	KeepMB   int    `json:"keep_mb"`
	// Error is the newest write or prune failure ("" when the last attempt worked).
	Error string `json:"error,omitempty"`
}

// ConnDevice is a device seen in the NAT samples of a period. Key identifies it across address
// changes: "mac:<mac>" when the Device List gave the MAC address of its LAN address at the time
// of a sample, otherwise "ip:<address>"; the gateway itself (sessions with no private address,
// such as the gateway's own connections from its public address) is "gateway".
type ConnDevice struct {
	Key        string `json:"key"`
	Name       string `json:"name,omitempty"` // the Device List name, newest in the period
	IPv4       string `json:"ipv4,omitempty"` // its newest LAN address in the period
	MAC        string `json:"mac,omitempty"`
	Connection string `json:"connection,omitempty"`
	Samples    int    `json:"samples"` // NAT reads in which it had at least one session
	// Weight counts its sessions over the reads: the sum of its flows' Weight, and LeftOut.
	Weight int `json:"weight"`
	// LeftOut is the weight of its flows that were not counted one by one: a period with more
	// distinct flows than the connection store counts singly (ConnAggregate.FlowsLeftOut) leaves
	// out the lightest.
	LeftOut int `json:"left_out,omitempty"`
}

// ConnFlow is one (device, remote address, port, protocol, direction) of the NAT samples of a period.
// For a connection the device opened, Port is the remote (destination) port; for one the
// remote side opened (Inbound, e.g. through a port forward), Port is the device's port.
type ConnFlow struct {
	Device  string `json:"device"` // ConnDevice.Key
	LAN     string `json:"lan"`    // the device's LAN address in the newest sample that showed it
	Remote  string `json:"remote"`
	Port    int    `json:"port,omitempty"`
	Proto   string `json:"proto"`
	Inbound bool   `json:"inbound,omitempty"`
	First   string `json:"first"` // time of the first read that showed it (RFC 3339 UTC)
	Last    string `json:"last"`  // time of the last read that showed it
	Samples int    `json:"samples"`
	// Weight counts its sessions over those reads: a flow open on three local ports in one read
	// counts three. The flow diagram's band widths are weights.
	Weight int `json:"weight"`
}

// ConnAggregate is the connection store's summary of the NAT samples of a period.
type ConnAggregate struct {
	From    string `json:"from"`
	To      string `json:"to"`
	Samples int    `json:"samples"` // NAT reads in the period
	First   string `json:"first,omitempty"`
	Last    string `json:"last,omitempty"`
	// The newest read in the period: its totals as the page showed them (-1 unknown) and how many
	// sessions it listed - of every device, and, with a device filter, of that device
	// (OpenDevice).
	InUse      int `json:"in_use"`
	Available  int `json:"available"`
	Open       int `json:"open"`
	OpenDevice int `json:"open_device,omitempty"`
	// Devices and Flows are ordered by Weight, largest first. With a device filter they hold that
	// device only (Samples and the newest read's totals stay those of every device).
	Devices []ConnDevice `json:"devices"`
	Flows   []ConnFlow   `json:"flows"`
	// FlowsLeftOut counts the flows not in Flows: the connection store counts at most 200,000
	// distinct flows one by one (a device opening connections to ever new addresses could
	// otherwise make one period hold millions) and leaves out the lightest beyond; their sessions
	// still count in their devices' Weight (and LeftOut).
	FlowsLeftOut int `json:"flows_left_out,omitempty"`
}

// ------------------------------------------------------------------ IP intelligence

// Address kinds of IPInfo.Kind. Only "public" addresses are looked up in the IP database or by
// reverse DNS.
const (
	IPKindPublic    = "public"
	IPKindPrivate   = "private"    // RFC 1918, IPv6 unique local
	IPKindShared    = "shared"     // 100.64.0.0/10 (carrier-grade NAT)
	IPKindLoopback  = "loopback"   // 127.0.0.0/8, ::1
	IPKindLinkLocal = "link-local" // 169.254.0.0/16, fe80::/10
	IPKindMulticast = "multicast"
	IPKindReserved  = "reserved" // every other special-purpose range (documentation, 0/8, 240/4, ...)
	IPKindInvalid   = "invalid"  // not an IP address
)

// IPInfo is what is known about an address without asking anyone: its kind and, for a public
// address, the network that announces it according to the IP database.
type IPInfo struct {
	Kind string `json:"kind"`
	ASN  int    `json:"asn,omitempty"`
	// Org is a readable organisation name ("Google", "Amazon"); ASName the database's own
	// description of the AS.
	Org     string `json:"org,omitempty"`
	ASName  string `json:"as_name,omitempty"`
	Country string `json:"country,omitempty"` // ISO 3166-1 alpha-2 where the network is registered
}

// IPIntelStatus is the state of the offline IP database and of the reverse DNS cache.
type IPIntelStatus struct {
	Enabled  bool   `json:"enabled"`
	Download bool   `json:"download"` // a newer database is downloaded every Refresh
	Source   string `json:"source,omitempty"`
	Loaded   bool   `json:"loaded"`
	V4Ranges int    `json:"v4_ranges"`
	V6Ranges int    `json:"v6_ranges"`
	// Updated is when the loaded database files were written (RFC 3339 UTC); Checked when a
	// newer one was last looked for; Next when it will be.
	Updated string `json:"updated,omitempty"`
	Checked string `json:"checked,omitempty"`
	Next    string `json:"next,omitempty"`
	Error   string `json:"error,omitempty"` // why the newest load or download failed
	// ReverseDNS: reverse DNS names are looked up (and cached) for the addresses shown.
	ReverseDNS bool `json:"reverse_dns"`
	PTRCached  int  `json:"ptr_cached"`
}

// ------------------------------------------------------------------ samplers (Status.Connections)

// ConnSamplerStatus is Status.Connections: the monitor's NAT table and Device List reads.
type ConnSamplerStatus struct {
	Enabled bool `json:"enabled"`
	// Interval and DevicesInterval are the configured read intervals (Go duration strings).
	Interval        string `json:"interval"`
	DevicesInterval string `json:"devices_interval"`
	// The newest NAT table read that worked: when, how many sessions it listed and the page's totals.
	NATAt     string `json:"nat_at,omitempty"`
	Sessions  int    `json:"sessions"`
	InUse     int    `json:"in_use"`
	Available int    `json:"available"`
	// NATProblem says why the newest NAT read failed or was not attempted (logins paused, no access
	// code, a changed gateway certificate awaiting confirmation, ...); "" when it worked.
	NATProblem string `json:"nat_problem,omitempty"`
	// NATNote says what the newest NAT read, which worked, could not keep: rows of the page that
	// were not understood, or the read itself when the connection store refused it; "" when nothing
	// (and always when NATProblem is set).
	NATNote string `json:"nat_note,omitempty"`
	NATNext string `json:"nat_next,omitempty"`
	// NATLogins counts the gateway logins the NAT reads needed within the last 24 hours: normally
	// none, as the reads reuse the gateway client's login session. At 6 the reads pause until the
	// oldest of them is a day old (NATProblem says so).
	NATLogins int `json:"nat_logins"`
	// The newest Device List read that worked, and the problem of the newest attempt.
	DevicesAt      string `json:"devices_at,omitempty"`
	Devices        int    `json:"devices"`
	DevicesProblem string `json:"devices_problem,omitempty"`
	// Store is the connection store's volume and limits (nil without a store).
	Store *ConnStoreUsage `json:"store,omitempty"`
}

// ------------------------------------------------------------------ the Network page (API)

// NetDevice is a device of GET /api/network/connections.
type NetDevice struct {
	Key        string `json:"key"`  // ConnDevice.Key
	Name       string `json:"name"` // the Device List name, else its address, else "Gateway"
	IPv4       string `json:"ipv4,omitempty"`
	MAC        string `json:"mac,omitempty"`
	Connection string `json:"connection,omitempty"`
	Weight     int    `json:"weight"`
	Sites      int    `json:"sites"` // distinct remote addresses
}

// NetOrg is an organisation of the flow diagram, or a group. Key is "org:<name>" (lower case) for
// an organisation the IP database names - one company's ASes (Google's AS15169, AS36040, ...) are
// one organisation - or "as<ASN>" for an AS it names no organisation of, or "other" (the
// organisations beyond the diagram's top ones), "local" (private and other non-public addresses)
// or "unknown" (public addresses the IP database does not know).
type NetOrg struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	// ASN and Country are those of its heaviest AS; ASNs lists its ASes, when it has several.
	ASN     int    `json:"asn,omitempty"`
	ASNs    []int  `json:"asns,omitempty"`
	Country string `json:"country,omitempty"`
	Weight  int    `json:"weight"`
	Sites   int    `json:"sites"`
	Members int    `json:"members,omitempty"` // for "other": how many organisations it groups
}

// NetService is a service of the flow diagram. Key is "<proto>/<port>" for a named port, or
// "other". Name is the service's name ("HTTPS", "QUIC", "DNS", ...) or the port ("tcp 8443").
type NetService struct {
	Key    string `json:"key"`
	Name   string `json:"name"`
	Proto  string `json:"proto,omitempty"`
	Port   int    `json:"port,omitempty"`
	Weight int    `json:"weight"`
}

// NetLink is a band of the flow diagram: device → organisation (From a NetDevice.Key, To a
// NetOrg.Key) or organisation → service (From a NetOrg.Key, To a NetService.Key).
type NetLink struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Weight int    `json:"weight"`
}

// NetCountry is one country of a world map. Code is ISO 3166-1 alpha-2 ("" for addresses the
// IP database does not place). Sites counts distinct addresses (connections: remote addresses;
// firewall: blocked sources); Weight the connection weight or the dropped packets.
type NetCountry struct {
	Code   string `json:"code"`
	Sites  int    `json:"sites"`
	Weight int    `json:"weight"`
}

// NetConnRow is one row of the connections table: a ConnFlow, named.
type NetConnRow struct {
	Device  string `json:"device"` // NetDevice.Key
	LAN     string `json:"lan"`
	Remote  string `json:"remote"`
	PTR     string `json:"ptr,omitempty"` // reverse DNS name, when known
	Kind    string `json:"kind"`          // IPInfo.Kind of Remote
	Org     string `json:"org,omitempty"`
	ASN     int    `json:"asn,omitempty"`
	Country string `json:"country,omitempty"`
	Service string `json:"service,omitempty"` // "" when the port has no known service
	Proto   string `json:"proto"`
	Port    int    `json:"port,omitempty"`
	Inbound bool   `json:"inbound,omitempty"`
	First   string `json:"first"`
	Last    string `json:"last"`
	Samples int    `json:"samples"`
	Weight  int    `json:"weight"`
}

// NetTotals are the Connections tab's summary tiles.
type NetTotals struct {
	Devices int `json:"devices"`
	// Listed counts the devices of the period that the gateway's newest Device List lists (without
	// a device filter): the others have left the network, or are the gateway itself.
	Listed    int `json:"listed"`
	Sites     int `json:"sites"` // distinct remote addresses
	Orgs      int `json:"orgs"`  // distinct organisations (NetOrg keys) of the public ones
	Countries int `json:"countries"`
}

// NetConnections is GET /api/network/connections: which device talked to which remote address
// in [From, To), from the NAT table samples.
type NetConnections struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Device string `json:"device,omitempty"` // the device filter applied ("" = every device)
	// Samples is the number of NAT reads in the period; First and Last the first and the last.
	Samples int    `json:"samples"`
	First   string `json:"first,omitempty"`
	Last    string `json:"last,omitempty"`
	// The newest read's totals (-1 unknown) and the sessions it listed - of every device, and, with
	// a device filter, of that device (OpenDevice).
	InUse      int       `json:"in_use"`
	Available  int       `json:"available"`
	Open       int       `json:"open"`
	OpenDevice int       `json:"open_device,omitempty"`
	Totals     NetTotals `json:"totals"`
	// Devices: every device of the period (for the device filter), by weight. Orgs, Services and
	// Links are the flow diagram: the top organisations (the rest grouped as "other") and services.
	Devices   []NetDevice  `json:"devices"`
	Orgs      []NetOrg     `json:"orgs"`
	Services  []NetService `json:"services"`
	Links     []NetLink    `json:"links"`
	Countries []NetCountry `json:"countries"` // by Sites, largest first
	// Rows: the flows, most seen first, at most the request's limit; RowsTotal before the limit.
	Rows      []NetConnRow `json:"rows"`
	RowsTotal int          `json:"rows_total"`
	// FlowsLeftOut counts the period's flows that the connection store did not count one by one
	// (ConnAggregate.FlowsLeftOut): they are in their devices' weights and in "Other", and the
	// sites and organisations are then at least the numbers shown.
	FlowsLeftOut int `json:"flows_left_out,omitempty"`
	// IPDB is when the IP database used was written ("" when none is loaded: no organisations or
	// countries then).
	IPDB string `json:"ipdb,omitempty"`
}

// Firewall direction of a dropped packet (FwOutRow, FwHour).
const (
	FwInbound  = "inbound"  // from the Internet (to the gateway or toward the LAN)
	FwOutbound = "outbound" // from the LAN toward the Internet
	FwLocal    = "local"    // between the LAN and the gateway, or sent by the gateway itself
)

// FwHour is one hour of the firewall timeline: packets dropped, by direction.
type FwHour struct {
	T     string `json:"t"` // start of the hour, RFC 3339 UTC
	In    int    `json:"in"`
	Out   int    `json:"out"`
	Local int    `json:"local"`
}

// FwSource is an Internet address whose packets were dropped.
type FwSource struct {
	Addr    string `json:"addr"`
	Org     string `json:"org,omitempty"`
	ASN     int    `json:"asn,omitempty"`
	Country string `json:"country,omitempty"`
	Count   int    `json:"count"`
	Ports   int    `json:"ports"` // distinct destination ports it tried
	Last    string `json:"last"`  // receive time of its newest dropped packet
}

// FwService is a targeted service of the inbound drops. Name "Other" (Port 0) groups the rest.
type FwService struct {
	Name  string `json:"name"`
	Proto string `json:"proto,omitempty"`
	Port  int    `json:"port,omitempty"`
	Count int    `json:"count"`
}

// FwReason counts drops by the gateway's reason (e.g. "POLICY-INPUT-GEN-DISCARD") with a plain
// description ("Unsolicited, to the gateway").
type FwReason struct {
	Reason string `json:"reason"`
	Label  string `json:"label"`
	Count  int    `json:"count"`
}

// FwOutRow is a LAN device's packets toward one destination that the firewall dropped.
type FwOutRow struct {
	Device  string `json:"device"` // NetDevice-style key ("mac:…", "ip:…")
	Name    string `json:"name"`   // the Device List name, else the LAN address
	LAN     string `json:"lan"`
	Remote  string `json:"remote"`
	Org     string `json:"org,omitempty"`
	ASN     int    `json:"asn,omitempty"`
	Country string `json:"country,omitempty"`
	Service string `json:"service,omitempty"`
	Proto   string `json:"proto"`
	Port    int    `json:"port,omitempty"`
	Reason  string `json:"reason"`
	Label   string `json:"label"`
	Count   int    `json:"count"`
	Last    string `json:"last"`
}

// NetFirewall is GET /api/network/firewall: what the gateway's firewall dropped in [From, To),
// from its syslog. The gateway logs only the packets it drops, never the connections it allows.
type NetFirewall struct {
	From string `json:"from"`
	To   string `json:"to"`
	// Oldest is the receive time of the oldest syslog message kept: before it, the syslog store's
	// retention limit has deleted what there was ("" with no message kept).
	Oldest string `json:"oldest,omitempty"`
	// Drops counted in the period (a "repeated N times" line counts N more of the message it
	// repeats), by direction.
	Drops    int `json:"drops"`
	Inbound  int `json:"inbound"`
	Outbound int `json:"outbound"`
	Local    int `json:"local"`
	// Sources: distinct Internet addresses whose packets were dropped; Countries their countries.
	Sources   int          `json:"sources"`
	Hours     []FwHour     `json:"hours"`     // every hour of [From, To), oldest first
	Countries []NetCountry `json:"countries"` // inbound drops by source country, by Weight
	// TopSources and Services: the inbound drops' top sources and targeted services.
	TopSources []FwSource  `json:"top_sources"`
	Services   []FwService `json:"services"`
	Reasons    []FwReason  `json:"reasons"`
	// OutboundRows: the LAN devices' dropped packets by destination, most first, at most the
	// request's limit; OutboundTotal before the limit. OutboundDevices is the number of distinct
	// LAN devices (FwOutRow.Device keys) whose outbound packets were dropped in the period, also
	// counted before the limit: the rows listed may name fewer of them.
	OutboundRows    []FwOutRow `json:"outbound_rows"`
	OutboundTotal   int        `json:"outbound_total"`
	OutboundDevices int        `json:"outbound_devices"`
	IPDB            string     `json:"ipdb,omitempty"`
}

// NetworkStatus is GET /api/network/status: the samplers (from the monitor's status), the
// connection store, the IP database, the syslog the firewall view reads and the warnings about
// the page's settings.
type NetworkStatus struct {
	Samplers *ConnSamplerStatus `json:"samplers,omitempty"`
	Store    *ConnStoreUsage    `json:"store,omitempty"`
	IPIntel  *IPIntelStatus     `json:"ipintel,omitempty"`
	// Syslog: the syslog kept (nil without a syslog store).
	Syslog *SyslogUsage `json:"syslog,omitempty"`
	// ConfigWarnings: the settings of the page in config.json (its connections and geo sections)
	// that the service could not use as written, each with what it uses instead (config.Warnings;
	// left out when there is none). They never keep the service from starting.
	ConfigWarnings []string `json:"config_warnings,omitempty"`
}
