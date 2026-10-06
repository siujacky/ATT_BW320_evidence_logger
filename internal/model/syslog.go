package model

// Syslog: the gateway's own log messages, received on this computer (docs/syslog-snmp-traffic.md).

// TypeSyslog is a ledger record holding a batch of syslog messages received from the gateway.
const TypeSyslog = "syslog"

// GwEvSyslogSetting is the gateway_event of a check (or change) of the gateway's Syslog page.
const GwEvSyslogSetting = "syslog_setting"

// SyslogSetting is the gateway's Syslog page (Diagnostics → Syslog) as read.
type SyslogSetting struct {
	Enabled bool   `json:"enabled"`
	Server  string `json:"server,omitempty"` // "Server IP Address" as shown
	Port    int    `json:"port,omitempty"`   // "Server Port"
	Level   string `json:"level,omitempty"`  // the selected "Log Level" option, as labelled
	// Levels lists every Log Level option the page offers, in page order.
	Levels []string `json:"levels,omitempty"`
}

// SyslogTarget is the Syslog setting the monitor wants on the gateway.
type SyslogTarget struct {
	Enabled bool   `json:"enabled"`
	Server  string `json:"server,omitempty"`
	Port    int    `json:"port,omitempty"`
	Level   string `json:"level,omitempty"` // "" = leave the page's level as it is
}

// SyslogMessage is one datagram received from the gateway. Raw (or RawB64) is the exact
// datagram and is authoritative; the parsed fields are a convenience and may be empty.
type SyslogMessage struct {
	RX       string `json:"rx"`                // receive time, RFC 3339 UTC with nanoseconds
	Src      string `json:"src"`               // sender "ip:port"
	Raw      string `json:"raw,omitempty"`     // the exact datagram when it is valid UTF-8
	RawB64   string `json:"raw_b64,omitempty"` // otherwise the exact bytes, base64
	Format   string `json:"format,omitempty"`  // "rfc5424" | "rfc3164" | "unknown"
	PRI      *int   `json:"pri,omitempty"`
	Facility *int   `json:"facility,omitempty"`
	Severity *int   `json:"severity,omitempty"` // 0 emergency … 7 debug
	TS       string `json:"ts,omitempty"`       // the header's timestamp as written
	Host     string `json:"host,omitempty"`
	App      string `json:"app,omitempty"` // RFC 5424 APP-NAME or RFC 3164 TAG
	Msg      string `json:"msg,omitempty"` // the message part
}

// SyslogBatch is the payload of a syslog record: the messages received from From to To.
type SyslogBatch struct {
	From     string          `json:"from"`
	To       string          `json:"to"`
	Received int             `json:"received"` // accepted from the allowed senders in the window
	Dropped  int             `json:"dropped"`  // accepted but over the per-minute cap: not recorded
	Rejected int             `json:"rejected"` // datagrams from other senders: not recorded
	Messages []SyslogMessage `json:"messages"`
}

// SyslogStatus is Status.Syslog: the receiver and the gateway's Syslog setting.
type SyslogStatus struct {
	Enabled   bool   `json:"enabled"`
	Listening bool   `json:"listening"`
	Listen    string `json:"listen,omitempty"`
	ListenErr string `json:"listen_error,omitempty"`
	// Counters since the service started.
	Received int64  `json:"received"`
	Recorded int64  `json:"recorded"`
	Dropped  int64  `json:"dropped"`
	Rejected int64  `json:"rejected"`
	LastAt   string `json:"last_at,omitempty"` // receive time of the newest message
	Last     string `json:"last,omitempty"`    // its text (shortened)
	// The gateway's setting as last read (nil: not read yet), when, and the gateway_event.
	Gateway    *SyslogSetting `json:"gateway,omitempty"`
	GatewayAt  string         `json:"gateway_at,omitempty"`
	GatewaySeq uint64         `json:"gateway_seq,omitempty"`
	// Enforce: the monitor keeps the gateway sending to Target.
	Enforce bool          `json:"enforce"`
	Target  *SyslogTarget `json:"target,omitempty"`
	// State: "ok" (the gateway sends here), "off", "elsewhere" (sends to another address), "unknown"
	// (not read yet or the page was not understood), "error" (the last check failed).
	State   string `json:"state,omitempty"`
	Problem string `json:"problem,omitempty"`
}

// TrafficPoint is one bucket of the traffic chart. WAN rates come from the gateway's own counters
// (between consecutive snapshots); PC rates from this computer's interface counters.
type TrafficPoint struct {
	T string `json:"t"` // bucket start, RFC 3339 UTC
	// Mean WAN download/upload over the bucket and the highest interval rate in it, in Mb/s.
	WANRx     *float64 `json:"wan_rx_mbps,omitempty"`
	WANTx     *float64 `json:"wan_tx_mbps,omitempty"`
	WANRxPeak *float64 `json:"wan_rx_peak_mbps,omitempty"`
	WANTxPeak *float64 `json:"wan_tx_peak_mbps,omitempty"`
	// AtLeast: a 32-bit byte counter may have wrapped more often than can be told in an
	// interval of this bucket, so the true rate may be higher than shown.
	AtLeast bool `json:"at_least,omitempty"`
	// This computer's receive/transmit rate on the interface that reaches the gateway, Mb/s.
	PCRx *float64 `json:"pc_rx_mbps,omitempty"`
	PCTx *float64 `json:"pc_tx_mbps,omitempty"`
}

// TrafficDay is one day's WAN volume from the gateway's counters (local calendar day).
type TrafficDay struct {
	Day     string `json:"day"` // YYYY-MM-DD, local time
	RxBytes int64  `json:"rx_bytes"`
	TxBytes int64  `json:"tx_bytes"`
	// CoveredS is the time with a known counter delta; Complete means no interval of the day's
	// monitored time was unknown (wrap ambiguity, counter reset, missing snapshot).
	CoveredS int64 `json:"covered_s"`
	Complete bool  `json:"complete"`
}

// SyslogEntry is one message of GET /api/syslog with the ledger record that holds it.
type SyslogEntry struct {
	Seq uint64 `json:"seq"`
	SyslogMessage
}

// SyslogList is returned by GET /api/syslog: the messages of the recorded syslog batches in
// [From, To) that match the filters, newest first.
type SyslogList struct {
	From      string        `json:"from"`
	To        string        `json:"to"`
	Messages  []SyslogEntry `json:"messages"`
	Truncated bool          `json:"truncated,omitempty"` // more matched than the limit
}
