package model

// Syslog: the gateway's own log messages, received on this computer (docs/syslog-snmp-traffic.md).

// Ledger records of the syslog store (docs/syslog-snmp-traffic.md §3.2). The messages themselves
// are not in the ledger, which can never delete anything: they live in the syslog store, within a
// size limit, and the ledger states what every sealed chunk held and when it was deleted.
const (
	// TypeSyslogChunk: a chunk of received messages was sealed; it states the chunk's SHA-256.
	TypeSyslogChunk = "syslog_chunk"
	// TypeSyslogPrune: chunks were deleted by the retention limit (syslog.keep_mb/keep_days).
	TypeSyslogPrune = "syslog_prune"
)

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
	// Store is the syslog store's volume and retention limits (nil without a store).
	Store *SyslogUsage `json:"store,omitempty"`
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

// SyslogEntry is one message of GET /api/syslog: the chunk of the syslog store that holds it and
// that chunk's syslog_chunk record (Seq 0 while the chunk is still open, or when unknown).
type SyslogEntry struct {
	Chunk string `json:"chunk,omitempty"`
	Seq   uint64 `json:"seq,omitempty"`
	SyslogMessage
}

// SyslogChunk is the payload of a syslog_chunk record: a sealed chunk file of the syslog store.
// The file is gzip; SHA256 and Bytes are those of its uncompressed content, which is one
// SyslogMessage JSON object per line, each line ending in a line feed (0x0A), in receive order.
type SyslogChunk struct {
	Name     string `json:"name"` // file name in the syslog store
	From     string `json:"from"` // receive time of the first message (RFC 3339 UTC)
	To       string `json:"to"`   // receive time of the last message
	Messages int    `json:"messages"`
	Dropped  int    `json:"dropped,omitempty"`  // counted while the chunk was open; not stored
	Rejected int    `json:"rejected,omitempty"` // datagrams from senders not allowed; not stored
	Bytes    int64  `json:"bytes"`
	SHA256   string `json:"sha256"`
	GzBytes  int64  `json:"gz_bytes"` // size of the stored gzip file
	Reason   string `json:"reason"`   // why it was sealed: "size", "age", "stop" or "recovered"
}

// SyslogChunkRef names a chunk in a syslog_prune record.
type SyslogChunkRef struct {
	Name     string `json:"name"`
	SHA256   string `json:"sha256"`
	From     string `json:"from"`
	To       string `json:"to"`
	Messages int    `json:"messages"`
	GzBytes  int64  `json:"gz_bytes"`
}

// SyslogPrune is the payload of a syslog_prune record: chunks deleted to stay within the
// retention limits. Their SHA-256 stay in their syslog_chunk records.
type SyslogPrune struct {
	Reason     string           `json:"reason"` // e.g. "keep_mb 100" or "keep_days 30"
	KeepMB     int              `json:"keep_mb"`
	KeepDays   int              `json:"keep_days,omitempty"`
	Deleted    []SyslogChunkRef `json:"deleted"`
	KeptBytes  int64            `json:"kept_bytes"`
	KeptChunks int              `json:"kept_chunks"`
}

// SyslogUsage is the syslog store's volume and its limits.
type SyslogUsage struct {
	Bytes        int64  `json:"bytes"`  // sealed chunks (gzip size) plus the open chunk
	Chunks       int    `json:"chunks"` // sealed chunks kept
	Messages     int64  `json:"messages"`
	OpenMessages int    `json:"open_messages"`
	Oldest       string `json:"oldest,omitempty"` // receive time of the oldest message kept
	Newest       string `json:"newest,omitempty"`
	KeepMB       int    `json:"keep_mb"`
	KeepDays     int    `json:"keep_days,omitempty"`
}

// LiveTraffic is the flow meter: the newest traffic rates from on-demand reads of the gateway's
// WAN counters (at most every few seconds, only while the dashboard asks) and of this computer's
// interface counters. It is a display, not evidence: nothing of it is recorded (the gateway
// snapshots every minute are the evidence).
type LiveTraffic struct {
	At        string   `json:"at,omitempty"`
	IntervalS float64  `json:"interval_s,omitempty"` // between the two reads the rates come from
	WANRx     *float64 `json:"wan_rx_mbps,omitempty"`
	WANTx     *float64 `json:"wan_tx_mbps,omitempty"`
	AtLeast   bool     `json:"at_least,omitempty"` // a 32-bit byte counter may have wrapped
	PCRx      *float64 `json:"pc_rx_mbps,omitempty"`
	PCTx      *float64 `json:"pc_tx_mbps,omitempty"`
	// History is the flow meter's recent readings (about the last 15 minutes), oldest first.
	History []LivePoint `json:"history,omitempty"`
	Err     string      `json:"error,omitempty"` // why the newest read failed
}

// LivePoint is one reading of the flow meter.
type LivePoint struct {
	T     string   `json:"t"`
	WANRx *float64 `json:"wan_rx_mbps,omitempty"`
	WANTx *float64 `json:"wan_tx_mbps,omitempty"`
	PCRx  *float64 `json:"pc_rx_mbps,omitempty"`
	PCTx  *float64 `json:"pc_tx_mbps,omitempty"`
}

// SyslogList is returned by GET /api/syslog: the messages of the syslog store received in
// [From, To) that match the filters, newest first.
type SyslogList struct {
	From      string        `json:"from"`
	To        string        `json:"to"`
	Messages  []SyslogEntry `json:"messages"`
	Truncated bool          `json:"truncated,omitempty"` // more matched than the limit
}
