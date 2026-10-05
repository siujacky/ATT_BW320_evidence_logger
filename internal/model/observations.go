package model

// ---------------------------------------------------------------- probes

// Probe kinds.
const (
	KindICMP  = "icmp"
	KindTCP   = "tcp"
	KindDNS   = "dns"
	KindHTTP  = "http"
	KindHTTPS = "https"
)

// Probe roles used by the classifier (docs/DESIGN.md §8-§9).
const (
	RoleGateway = "gateway"  // LAN path to the AT&T gateway
	RoleISPHop  = "isp_hop"  // AT&T next hop (Gateway IPv4 Address)
	RoleInet    = "internet" // independent public targets
)

// ProbeSpec describes one fast-cycle probe target.
type ProbeSpec struct {
	Name   string `json:"name"`   // stable id, e.g. "gateway_icmp", "inet_icmp_cloudflare"
	Label  string `json:"label"`  // display, e.g. "Cloudflare 1.1.1.1"
	Kind   string `json:"kind"`   // KindICMP | KindTCP
	Role   string `json:"role"`   // RoleGateway | RoleISPHop | RoleInet
	Target string `json:"target"` // "1.1.1.1" (icmp) or "1.1.1.1:443" (tcp); "" = resolved at runtime
}

// ProbeResult is the outcome of one probe attempt.
type ProbeResult struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Role   string `json:"role"`
	Target string `json:"target"`
	OK     bool   `json:"ok"`
	RTTus  int64  `json:"rtt_us,omitempty"`
	// Status: ICMP IP_STATUS name ("IP_SUCCESS", "IP_REQ_TIMED_OUT", ...), or for TCP/local conditions one of
	// "connected", "refused" (the peer answered with RST), "timeout", "unreachable" (no route from this PC),
	// "canceled", "error".
	Status    string `json:"status,omitempty"`
	ReplyFrom string `json:"reply_from,omitempty"` // address that answered (ICMP), may differ from Target
	TTL       int    `json:"ttl,omitempty"`
	Err       string `json:"err,omitempty"`
}

// Sample is the payload of a "sample" record: one fast cycle.
type Sample struct {
	Cycle   uint64        `json:"cycle"`
	Started string        `json:"started"` // RFC 3339 UTC ns
	DurMs   int64         `json:"dur_ms"`
	Probes  []ProbeResult `json:"probes"`
	Verdict Verdict       `json:"verdict"`
	// IncidentID is set while an incident is open.
	IncidentID string `json:"incident_id,omitempty"`
}

// Monitor states (docs/DESIGN.md §9).
const (
	StateOnline     = "ONLINE"
	StateDegraded   = "DEGRADED"
	StateISPOutage  = "ISP_OUTAGE"
	StateLocalFault = "LOCAL_FAULT"
	StateUnknown    = "UNKNOWN" // no data yet
)

// Causes.
const (
	CauseNone                = ""
	CauseGatewayUnreachable  = "GATEWAY_UNREACHABLE"
	CauseLocalLinkDown       = "LOCAL_LINK_DOWN"
	CauseGatewayReboot       = "GATEWAY_REBOOT"
	CauseFiberLinkDown       = "FIBER_LINK_DOWN"
	CauseWANDown             = "WAN_DOWN"
	CauseISPEdgeUnreachable  = "ISP_EDGE_UNREACHABLE"
	CauseUpstreamUnreachable = "UPSTREAM_UNREACHABLE"
	CausePacketLoss          = "PACKET_LOSS"
	CauseHighLatency         = "HIGH_LATENCY"
	CauseISPDNSFailure       = "ISP_DNS_FAILURE"
	CauseGatewayDNSFailure   = "GATEWAY_DNS_FAILURE"
	// CauseLocalRoute: this computer's traffic to the destinations does not leave through the
	// AT&T gateway (VPN, second adapter, hotspot): nothing can be attributed to the provider.
	CauseLocalRoute = "LOCAL_ROUTE"
)

// Attributions.
const (
	AttrNone         = "none"
	AttrProvider     = "provider"
	AttrLocal        = "local"
	AttrUndetermined = "undetermined"
)

// Verdict is the classifier output for one cycle.
type Verdict struct {
	State       string   `json:"state"`
	Cause       string   `json:"cause,omitempty"`
	Attribution string   `json:"attribution"`
	Reasons     []string `json:"reasons,omitempty"`
	// Inputs identifies the other records this verdict used, so a third party can recompute it.
	Inputs *VerdictInputs `json:"inputs,omitempty"`
	Rules  string         `json:"rules"` // classifier RulesVersion
}

// VerdictInputs names the ledger records (by seq; 0 = none/stale) a verdict was computed from.
type VerdictInputs struct {
	SnapshotSeq     uint64 `json:"snapshot_seq,omitempty"`
	ServiceCheckSeq uint64 `json:"service_check_seq,omitempty"`
	LocalLinkSeq    uint64 `json:"local_link_seq,omitempty"`
	WindowCycles    int    `json:"window_cycles"` // cycles in the window (incl. this one)
	// PrevServiceCheckSeq: the earlier service check the two-consecutive-checks DNS rule compared with.
	PrevServiceCheckSeq uint64 `json:"prev_service_check_seq,omitempty"`
	// TrafficFromSeq/TrafficToSeq: the two gateway snapshots whose WAN counters gave the traffic rate.
	TrafficFromSeq uint64 `json:"traffic_from_seq,omitempty"`
	TrafficToSeq   uint64 `json:"traffic_to_seq,omitempty"`
}

// StateChange is written when the verdict state or cause changes.
type StateChange struct {
	FromState string   `json:"from_state"`
	FromCause string   `json:"from_cause,omitempty"`
	ToState   string   `json:"to_state"`
	ToCause   string   `json:"to_cause,omitempty"`
	At        string   `json:"at"`
	Cycle     uint64   `json:"cycle"`
	Reasons   []string `json:"reasons,omitempty"`
}

// ---------------------------------------------------------------- service checks

// DNSResult is one DNS query outcome.
type DNSResult struct {
	Server     string   `json:"server"`      // "192.168.1.254:53"
	ServerRole string   `json:"server_role"` // "gateway" | "isp" | "public"
	Name       string   `json:"name"`
	QType      string   `json:"qtype"` // "A"
	OK         bool     `json:"ok"`    // got a well-formed response
	RCode      string   `json:"rcode,omitempty"`
	Answers    []string `json:"answers,omitempty"`
	RTTus      int64    `json:"rtt_us,omitempty"`
	Hijacked   bool     `json:"hijacked"`
	HijackWhy  string   `json:"hijack_why,omitempty"`
	Truncated  bool     `json:"truncated,omitempty"` // TC bit set: answers may be incomplete
	RawB64     string   `json:"raw_b64,omitempty"`   // response bytes
	Err        string   `json:"err,omitempty"`
}

// HTTPResult is one HTTP(S) check outcome (redirects are never followed).
type HTTPResult struct {
	Name       string `json:"name"` // "msft_connecttest", "google_204"
	URL        string `json:"url"`
	OK         bool   `json:"ok"` // status and body matched expectations
	Status     int    `json:"status,omitempty"`
	Location   string `json:"location,omitempty"`
	RemoteAddr string `json:"remote_addr,omitempty"`
	BodySHA256 string `json:"body_sha256,omitempty"`
	BodyPrefix string `json:"body_prefix,omitempty"` // first 512 bytes, invalid UTF-8 replaced
	RTTus      int64  `json:"rtt_us,omitempty"`
	Hijacked   bool   `json:"hijacked"`
	HijackWhy  string `json:"hijack_why,omitempty"`
	// TLSCertSHA256 is the SHA-256 of the server leaf certificate (HTTPS only): direct evidence of interception.
	TLSCertSHA256 string `json:"tls_cert_sha256,omitempty"`
	Err           string `json:"err,omitempty"`
}

// ServiceCheck is the payload of a "service_check" record.
type ServiceCheck struct {
	DNS  []DNSResult  `json:"dns"`
	HTTP []HTTPResult `json:"http"`
}

// ---------------------------------------------------------------- local link

// LocalLink describes how the monitoring PC is attached to the gateway.
type LocalLink struct {
	Interface string `json:"interface"` // adapter alias, e.g. "Wi-Fi"
	Type      string `json:"type"`      // "wifi" | "ethernet" | "unknown"
	State     string `json:"state"`     // "connected" | "disconnected" | ...
	LocalIP   string `json:"local_ip,omitempty"`
	GatewayIP string `json:"gateway_ip,omitempty"`
	SSID      string `json:"ssid,omitempty"`
	BSSID     string `json:"bssid,omitempty"`
	SignalPct int    `json:"signal_pct,omitempty"`
	RSSIdBm   int    `json:"rssi_dbm,omitempty"` // netsh "Rssi" (negative dBm) when reported
	// Egress is the route check made with this reading: does traffic to each destination leave
	// through the AT&T gateway? (nil when not checked)
	Egress    *EgressCheck `json:"egress,omitempty"`
	Channel   int          `json:"channel,omitempty"`
	Band      string       `json:"band,omitempty"`
	RadioType string       `json:"radio_type,omitempty"`
	RxMbps    int          `json:"rx_mbps,omitempty"`
	TxMbps    int          `json:"tx_mbps,omitempty"`
	LinkMbps  int          `json:"link_mbps,omitempty"`  // ethernet
	RawSHA256 string       `json:"raw_sha256,omitempty"` // blob of the raw netsh output
	Err       string       `json:"err,omitempty"`
}

// EgressCheck is the route this computer uses to reach the gateway and each internet destination.
type EgressCheck struct {
	Gateway        string        `json:"gateway"`                    // the AT&T gateway's LAN address
	GatewayIf      uint32        `json:"gateway_if,omitempty"`       // interface index of the route to it
	GatewayIfName  string        `json:"gateway_if_name,omitempty"`  // that interface's alias
	GatewayNextHop string        `json:"gateway_next_hop,omitempty"` // "" when the gateway is on-link
	Routes         []EgressRoute `json:"routes,omitempty"`
	// Bypass: the route to at least one destination does not leave through the gateway.
	Bypass bool   `json:"bypass"`
	Err    string `json:"err,omitempty"` // the check could not be made (nothing is concluded)
}

// EgressRoute is the route to one internet destination.
type EgressRoute struct {
	Target     string `json:"target"`
	If         uint32 `json:"if,omitempty"`
	IfName     string `json:"if_name,omitempty"`
	NextHop    string `json:"next_hop,omitempty"` // "" when on-link
	ViaGateway bool   `json:"via_gateway"`
	Err        string `json:"err,omitempty"`
}

// ---------------------------------------------------------------- traceroute & clock

// Hop is one traceroute hop.
type Hop struct {
	TTL    int    `json:"ttl"`
	Addr   string `json:"addr,omitempty"`
	RTTus  int64  `json:"rtt_us,omitempty"`
	Status string `json:"status"` // IP_TTL_EXPIRED_TRANSIT, IP_SUCCESS, IP_REQ_TIMED_OUT, ...
}

// Traceroute is the payload of a "traceroute" record.
type Traceroute struct {
	Target   string `json:"target"`
	Trigger  string `json:"trigger"` // "incident_open", "incident_periodic", "incident_close", "manual"
	Incident string `json:"incident_id,omitempty"`
	Hops     []Hop  `json:"hops"`
	Reached  bool   `json:"reached"`
	Err      string `json:"err,omitempty"` // resolution or local failure (no further hops sent)
	DurMs    int64  `json:"dur_ms"`
}

// ClockResult is one SNTP measurement.
type ClockResult struct {
	Server   string `json:"server"`
	Addr     string `json:"addr,omitempty"`
	OK       bool   `json:"ok"`
	OffsetMs int64  `json:"offset_ms,omitempty"` // server - local
	RTTms    int64  `json:"rtt_ms,omitempty"`
	Stratum  int    `json:"stratum,omitempty"`
	Err      string `json:"err,omitempty"`
}

// ClockCheck is the payload of a "clock_check" record.
type ClockCheck struct {
	Results []ClockResult `json:"results"`
	// GatewayOffsetMs compares the gateway's own clock (sysinfo) with local time, if known.
	GatewayOffsetMs *int64 `json:"gateway_offset_ms,omitempty"`
}
