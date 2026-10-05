package model

// PageCapture describes one fetch of a gateway page. The exact response body is identified
// by SHA256; when Stored is true the body is in the blob store under that id.
type PageCapture struct {
	Page          string `json:"page"` // "broadbandstatistics"
	URL           string `json:"url"`
	Status        int    `json:"status,omitempty"`
	Location      string `json:"location,omitempty"` // redirect target, if any
	FetchedAt     string `json:"fetched_at"`         // RFC 3339 UTC ns (request start)
	DurMs         int64  `json:"dur_ms"`
	Bytes         int    `json:"bytes"`
	SHA256        string `json:"sha256,omitempty"`
	Stored        bool   `json:"stored"`
	LoginPage     bool   `json:"login_page,omitempty"`
	NotAttempted  bool   `json:"not_attempted,omitempty"` // skipped after the gateway could not be reached at all
	TLSCertSHA256 string `json:"tls_cert_sha256,omitempty"`
	Err           string `json:"err,omitempty"`
}

// SystemInfo is parsed from sysinfo.ha.
type SystemInfo struct {
	Manufacturer    string `json:"manufacturer,omitempty"`
	Model           string `json:"model,omitempty"`
	Serial          string `json:"serial,omitempty"`
	SoftwareVersion string `json:"software_version,omitempty"`
	WANMAC          string `json:"wan_mac,omitempty"`
	FirstUseDate    string `json:"first_use_date,omitempty"`
	HardwareVersion string `json:"hardware_version,omitempty"`
	UptimeRaw       string `json:"uptime_raw,omitempty"`
	UptimeSec       int64  `json:"uptime_s"`         // -1 if unparseable
	GatewayTimeRaw  string `json:"gateway_time_raw"` // "" when the WAN is down (gateway behaviour)
	// GatewayTimePresent distinguishes a blank "Current Date/Time" row (WAN-down indicator) from a missing row.
	GatewayTimePresent bool `json:"gateway_time_present"`
}

// BroadbandStatus is parsed from broadbandstatistics.ha.
type BroadbandStatus struct {
	ConnectionSource string           `json:"connection_source,omitempty"` // "FIBER"
	Connection       string           `json:"connection,omitempty"`        // "Up" / "Down"
	NetworkType      string           `json:"network_type,omitempty"`
	IPv4             string           `json:"ipv4,omitempty"`
	GatewayIPv4      string           `json:"gateway_ipv4,omitempty"` // ISP next hop
	PrimaryDNS       string           `json:"primary_dns,omitempty"`
	SecondaryDNS     string           `json:"secondary_dns,omitempty"`
	MTU              string           `json:"mtu,omitempty"`
	LineState        string           `json:"line_state,omitempty"`
	SpeedMbps        string           `json:"speed_mbps,omitempty"`
	Duplex           string           `json:"duplex,omitempty"`
	IPv6Status       string           `json:"ipv6_status,omitempty"`
	IPv6Global       string           `json:"ipv6_global,omitempty"`
	IPv6Gateway      string           `json:"ipv6_gateway,omitempty"`
	PONLinkStatus    string           `json:"pon_link_status,omitempty"` // "OPERATION (O5)"
	UNIStatus        string           `json:"uni_status,omitempty"`
	Counters         map[string]int64 `json:"counters,omitempty"` // "IPv4 Statistics/Receive Bytes" -> n
	// Values preserves every label/value row as "Section/Label" -> value (complete capture).
	Values map[string]string `json:"values,omitempty"`
}

// Threshold is one alarm/warning cell of a fiber DMI table, e.g. "1 (Threshold -295)".
type Threshold struct {
	Active    bool   `json:"active"`
	Raw       string `json:"raw"`
	Threshold *int64 `json:"threshold,omitempty"` // in the measurement's raw units
}

// DMIMeasure is one fiber module diagnostic (Temperature, Vcc, Tx Bias, Tx Power, Rx Power).
type DMIMeasure struct {
	Name       string    `json:"name"`
	CurrentRaw string    `json:"current_raw"`
	Current    *int64    `json:"current,omitempty"` // raw units (Tx/Rx Power: 0.1 dBm)
	Unit       string    `json:"unit"`              // "C", "V", "mA", "0.1dBm"
	LowAlarm   Threshold `json:"low_alarm"`
	HighAlarm  Threshold `json:"high_alarm"`
	LowWarn    Threshold `json:"low_warning"`
	HighWarn   Threshold `json:"high_warning"`
}

// FiberStatus is parsed from fiberstat.ha.
type FiberStatus struct {
	OpticalStatus  string            `json:"optical_status,omitempty"` // "Optical WAN Operational Status"
	FiberModule    string            `json:"fiber_module,omitempty"`
	LastChangeRaw  string            `json:"last_change_raw,omitempty"`
	LastChangeUnix int64             `json:"last_change_unix,omitempty"`
	LinkState      string            `json:"link_state,omitempty"`
	WaveLength     string            `json:"wave_length,omitempty"`
	VendorName     string            `json:"vendor_name,omitempty"`
	VendorPN       string            `json:"vendor_pn,omitempty"`
	VendorSN       string            `json:"vendor_sn,omitempty"`
	RxLOSState     string            `json:"rx_los_state,omitempty"`
	OptLOS         string            `json:"opt_los,omitempty"`
	TxFaultState   string            `json:"tx_fault_state,omitempty"`
	Measures       []DMIMeasure      `json:"measures,omitempty"`
	Values         map[string]string `json:"values,omitempty"` // every label/value row
}

// LANStatus is a light parse of lanstatistics.ha (raw page is the evidence).
type LANStatus struct {
	Values map[string]string `json:"values,omitempty"`
}

// GatewayDerived holds facts computed from the parsed pages (no inference beyond these rules).
type GatewayDerived struct {
	Reachable            bool     `json:"reachable"` // at least one page fetched with HTTP 200 and not a login page
	BroadbandUp          *bool    `json:"broadband_up,omitempty"`
	PONOperational       *bool    `json:"pon_operational,omitempty"` // PON Link Status contains "O5"
	OpticalUp            *bool    `json:"optical_up,omitempty"`
	WANIPv4              string   `json:"wan_ipv4,omitempty"`
	ISPNextHop           string   `json:"isp_next_hop,omitempty"`
	ISPDNS               string   `json:"isp_dns,omitempty"`
	RxPowerX10           *int64   `json:"rx_power_x10,omitempty"` // 0.1 dBm
	TxPowerX10           *int64   `json:"tx_power_x10,omitempty"`
	RxLowAlarmX10        *int64   `json:"rx_low_alarm_x10,omitempty"`
	RxLowWarnX10         *int64   `json:"rx_low_warn_x10,omitempty"`
	Alarms               []string `json:"alarms,omitempty"` // condition codes from gateway flags, e.g. "OPTICAL_RX_LOW_ALARM"
	UptimeSec            int64    `json:"uptime_s"`
	BootTimeEstimate     string   `json:"boot_time_estimate,omitempty"`      // fetched_at - uptime (UTC)
	GatewayClockBlank    bool     `json:"gateway_clock_blank"`               // sysinfo Current Date/Time empty (WAN down indicator)
	GatewayClockOffsetMs *int64   `json:"gateway_clock_offset_ms,omitempty"` // gateway local clock - our local clock
	Firmware             string   `json:"firmware,omitempty"`
	Serial               string   `json:"serial,omitempty"`
	Model                string   `json:"model,omitempty"`
	FiberLastChange      int64    `json:"fiber_last_change,omitempty"`
}

// GatewaySnapshot is the payload of a "gateway_snapshot" record.
type GatewaySnapshot struct {
	Pages     []PageCapture    `json:"pages"`
	System    *SystemInfo      `json:"system,omitempty"`
	Broadband *BroadbandStatus `json:"broadband,omitempty"`
	Fiber     *FiberStatus     `json:"fiber,omitempty"`
	LAN       *LANStatus       `json:"lan,omitempty"`
	Derived   GatewayDerived   `json:"derived"`
	Trigger   string           `json:"trigger"` // "periodic", "startup", "cycle_failure", "incident", "incident_close"
}

// Gateway event kinds.
const (
	GwEvReboot              = "reboot"
	GwEvFirmwareChange      = "firmware_change"
	GwEvWANIPChange         = "wan_ip_change"
	GwEvBroadbandState      = "broadband_state"
	GwEvPONState            = "pon_state"
	GwEvOpticalAlarm        = "optical_alarm"
	GwEvOpticalLinkChange   = "optical_link_change" // fiberstat Last Change moved
	GwEvCountersReset       = "counters_reset"
	GwEvCertPinned          = "cert_pinned"
	GwEvCertChanged         = "cert_changed"
	GwEvGatewayClock        = "gateway_clock"
	GwEvNotificationSetting = "notification_setting"
	GwEvUnreachable         = "unreachable"
)

// GatewayEvent is the payload of a "gateway_event" record.
type GatewayEvent struct {
	Kind     string   `json:"kind"`
	Before   string   `json:"before,omitempty"`
	After    string   `json:"after,omitempty"`
	Detail   string   `json:"detail,omitempty"`
	Evidence []uint64 `json:"evidence,omitempty"` // ledger seqs (e.g. the snapshots compared)
}
