package model

// ---------------------------------------------------------------- incidents

// EvidenceRef points at ledger records / blobs that support an incident.
type EvidenceRef struct {
	Seq  uint64 `json:"seq"`
	Type string `json:"type"`
	Blob string `json:"blob,omitempty"`
	Note string `json:"note,omitempty"`
}

// IncidentStats summarises what was observed during an incident.
type IncidentStats struct {
	Cycles          int            `json:"cycles"`
	BadCycles       int            `json:"bad_cycles"`
	ProbeOK         map[string]int `json:"probe_ok,omitempty"`    // probe name -> successes
	ProbeTotal      map[string]int `json:"probe_total,omitempty"` // probe name -> attempts
	GatewayFetches  int            `json:"gateway_fetches"`
	GatewayDownSeen bool           `json:"gateway_reported_down"` // Broadband Connection: Down seen
	PONDownSeen     bool           `json:"pon_down_seen"`
	OpticalAlarm    bool           `json:"optical_alarm_seen"`
	DNSHijackSeen   bool           `json:"dns_hijack_seen"`
	HTTPHijackSeen  bool           `json:"http_hijack_seen"`
	LocalLinkDown   bool           `json:"local_link_down_seen"`
	// DowntimeSec is the time covered by ISP_OUTAGE cycles (no Internet at all) inside the incident;
	// DegradedSec the time covered by DEGRADED cycles. Both count cycles, not wall-clock duration.
	DowntimeSec int64 `json:"downtime_s"`
	DegradedSec int64 `json:"degraded_s"`
	// RestartSec is the time of bad cycles inside gateway-restart windows (§10): not provider downtime.
	RestartSec int64 `json:"restart_s"`
}

// Incident is the payload of incident_open/update/close records and the UI view.
type Incident struct {
	ID     string `json:"id"` // INC-YYYYMMDD-HHMMSSZ
	Opened string `json:"opened"`
	Closed string `json:"closed,omitempty"`
	// RecoveredAt is the start of the first cycle in which every probe succeeded again (may precede Closed).
	RecoveredAt string `json:"recovered_at,omitempty"`
	// GatewayRestarts lists the gateway boot times (estimated, RFC 3339 UTC) that fall inside the incident.
	GatewayRestarts []string      `json:"gateway_restarts,omitempty"`
	DurationSec     int64         `json:"duration_s,omitempty"`
	Open            bool          `json:"open"`
	State           string        `json:"state"`
	Cause           string        `json:"cause"`
	Attribution     string        `json:"attribution"`
	Causes          []string      `json:"causes,omitempty"`
	Summary         string        `json:"summary"`
	Reasons         []string      `json:"reasons,omitempty"`
	Rules           string        `json:"rules"`
	FirstSeq        uint64        `json:"first_seq"`
	LastSeq         uint64        `json:"last_seq,omitempty"`
	Evidence        []EvidenceRef `json:"evidence,omitempty"`
	Stats           IncidentStats `json:"stats"`
}

// ---------------------------------------------------------------- status (dashboard)

// Condition is a persistent warning shown on the dashboard (e.g. a gateway optical alarm).
type Condition struct {
	Code     string `json:"code"`     // "OPTICAL_RX_LOW_ALARM", "NOTIFICATION_REDIRECT_ON", ...
	Severity string `json:"severity"` // "critical" | "warning" | "info"
	Message  string `json:"message"`
	Since    string `json:"since,omitempty"`
	Seq      uint64 `json:"seq,omitempty"` // supporting ledger record
}

// LedgerStatus summarises the evidence store.
type LedgerStatus struct {
	HeadSeq         uint64         `json:"head_seq"`
	HeadHash        string         `json:"head_hash"`
	HeadTS          string         `json:"head_ts"`
	Fingerprint     string         `json:"fingerprint"`
	GenesisTS       string         `json:"genesis_ts"`
	LastAnchorTime  string         `json:"last_anchor_time,omitempty"`
	LastAnchorTSA   string         `json:"last_anchor_tsa,omitempty"`
	LastAnchorSeq   uint64         `json:"last_anchor_seq,omitempty"`
	UnanchoredCount uint64         `json:"unanchored_records"`
	DataDir         string         `json:"data_dir"`
	LastVerify      *VerifySummary `json:"last_verify,omitempty"`
}

// VerifySummary is a short verification outcome.
type VerifySummary struct {
	At       string `json:"at"`
	OK       bool   `json:"ok"`
	Records  uint64 `json:"records"`
	Failures int    `json:"failures"`
}

// MonitorInfo describes the running monitor process.
type MonitorInfo struct {
	Version   string `json:"version"`
	Started   string `json:"started"`
	RunID     string `json:"run_id"`
	UptimeSec int64  `json:"uptime_s"`
	Cycles    uint64 `json:"cycles"`
	Mode      string `json:"mode"`
	Listen    string `json:"listen"`
	Rules     string `json:"rules"`
}

// WindowStats are availability statistics over a time window.
type WindowStats struct {
	Window            string  `json:"window"` // "24h", "7d"
	MonitoredSec      int64   `json:"monitored_s"`
	CoveragePct       float64 `json:"coverage_pct"`     // monitored / window
	AvailabilityPct   float64 `json:"availability_pct"` // ONLINE cycles / all cycles
	Incidents         int     `json:"incidents"`
	ProviderOutageSec int64   `json:"provider_outage_s"` // time of provider-attributed ISP_OUTAGE cycles
	DegradedSec       int64   `json:"degraded_s"`        // time of DEGRADED cycles
	Blips             int     `json:"blips"`
}

// Status is returned by GET /api/status.
type Status struct {
	Now            string             `json:"now"`
	Monitor        MonitorInfo        `json:"monitor"`
	Verdict        Verdict            `json:"verdict"`
	Since          string             `json:"since"` // when the current state began
	ActiveIncident *Incident          `json:"active_incident,omitempty"`
	LastSample     *Sample            `json:"last_sample,omitempty"`
	Gateway        *GatewaySnapshot   `json:"gateway,omitempty"`
	GatewayAt      string             `json:"gateway_at,omitempty"`
	Notification   *NotificationState `json:"notification,omitempty"`
	LastService    *ServiceCheck      `json:"last_service_check,omitempty"`
	LocalLink      *LocalLink         `json:"local_link,omitempty"`
	Clock          *ClockCheck        `json:"clock,omitempty"`
	Conditions     []Condition        `json:"conditions"`
	Probes         []ProbeSpec        `json:"probes,omitempty"` // configured fast-cycle probes (labels)
	// GatewayCert is the gateway TLS pin state (pending != "" while a changed certificate awaits
	// operator confirmation; Seq = the cert_changed gateway_event that reported it).
	GatewayCert *GatewayCertState `json:"gateway_cert,omitempty"`
	// Mongo is the state of the MongoDB copy of the ledger (nil when not configured).
	Mongo *MongoStatus `json:"mongo,omitempty"`
	// Syslog is the syslog receiver and the gateway's Syslog setting (nil when not configured).
	Syslog *SyslogStatus `json:"syslog,omitempty"`
	// Connections is the NAT table and Device List samplers of the Network page (nil when not
	// configured).
	Connections *ConnSamplerStatus `json:"connections,omitempty"`
	Ledger      LedgerStatus       `json:"ledger"`
	Stats       []WindowStats      `json:"stats"`
}

// GatewayCertState is the gateway certificate pin as the monitor currently applies it.
type GatewayCertState struct {
	Pinned  string `json:"pinned"`
	Pending string `json:"pending,omitempty"`
	Since   string `json:"since,omitempty"` // when the pending certificate was first seen
	Seq     uint64 `json:"seq,omitempty"`   // gateway_event cert_changed record
}

// MongoStatus describes the MongoDB copy of the evidence ledger (a synchronized replica: the
// signed JSONL ledger stays the source of truth; every MongoDB record keeps its exact h/s/b).
type MongoStatus struct {
	Enabled   bool   `json:"enabled"`
	Connected bool   `json:"connected"`
	Database  string `json:"database,omitempty"`
	URI       string `json:"uri,omitempty"`     // credentials removed
	LastSeq   uint64 `json:"last_seq"`          // newest ledger seq copied
	HasData   bool   `json:"has_data"`          // at least one record copied
	Lag       uint64 `json:"lag"`               // ledger head seq minus LastSeq
	Records   int64  `json:"records,omitempty"` // documents in the records collection (approximate)
	Blobs     int64  `json:"blobs,omitempty"`   // documents in the blobs collection (approximate)
	Syslog    int64  `json:"syslog,omitempty"`  // documents in the syslog collection (approximate)
	LastSync  string `json:"last_sync,omitempty"`
	LastError string `json:"last_error,omitempty"`
}

// NotificationState is the last known value of the gateway's redirect setting.
type NotificationState struct {
	Enabled   bool   `json:"enabled"`
	CheckedAt string `json:"checked_at"`
	Seq       uint64 `json:"seq,omitempty"`
	Err       string `json:"err,omitempty"`
}

// ---------------------------------------------------------------- series (charts)

// SeriesPoint aggregates the cycles inside one time bucket.
type SeriesPoint struct {
	T     string             `json:"t"`                // bucket start, RFC 3339 UTC
	State string             `json:"state"`            // worst state in bucket ("" = no data / monitor gap)
	RTTms map[string]float64 `json:"rtt_ms,omitempty"` // probe name -> mean RTT of successes
	Loss  map[string]float64 `json:"loss,omitempty"`   // probe name -> fraction failed (0..1)
}

// OpticalPoint is one gateway optical reading.
type OpticalPoint struct {
	T          string `json:"t"`
	RxX10      *int64 `json:"rx_x10,omitempty"`
	TxX10      *int64 `json:"tx_x10,omitempty"`
	RxLowAlarm bool   `json:"rx_low_alarm"`
	RxLowWarn  bool   `json:"rx_low_warn"`
}

// Series is returned by GET /api/series.
type Series struct {
	Range         string         `json:"range"`
	From          string         `json:"from"`
	To            string         `json:"to"`
	StepSec       int            `json:"step_s"`
	Probes        []ProbeSpec    `json:"probes"`
	Points        []SeriesPoint  `json:"points"`
	Optical       []OpticalPoint `json:"optical"`
	RxLowAlarmX10 *int64         `json:"rx_low_alarm_x10,omitempty"`
	RxLowWarnX10  *int64         `json:"rx_low_warn_x10,omitempty"`
	// Traffic is the WAN and this computer's traffic per bucket (same buckets as Points);
	// TrafficDays the WAN volume per local day of the range; HeavyTrafficMbps the classifier's
	// heavy-household-traffic threshold (docs/DESIGN.md §9), drawn as a reference line.
	Traffic          []TrafficPoint `json:"traffic,omitempty"`
	TrafficDays      []TrafficDay   `json:"traffic_days,omitempty"`
	HeavyTrafficMbps float64        `json:"heavy_traffic_mbps,omitempty"`
}

// ---------------------------------------------------------------- verification

// VerifyFailure is one integrity problem.
type VerifyFailure struct {
	Seq     uint64 `json:"seq"`
	Segment string `json:"segment"`
	Line    int    `json:"line"`
	// Problem: "hash_mismatch", "bad_signature", "seq_gap", "prev_mismatch", "segment_hash", "blob_missing",
	// "blob_corrupt", "anchor_invalid", "parse_error", "ts_contradiction" (a record time contradicts a trusted
	// RFC 3161 time-stamp by more than the tolerance).
	Problem string `json:"problem"`
	Detail  string `json:"detail"`
}

// AnchorCheck is the verification result of one anchor record.
type AnchorCheck struct {
	Seq     uint64 `json:"seq"`
	TSA     string `json:"tsa"`
	GenTime string `json:"gen_time"`
	HeadSeq uint64 `json:"head_seq"`
	OK      bool   `json:"ok"`
	ChainOK bool   `json:"chain_ok"`
	Detail  string `json:"detail,omitempty"`
}

// Gap is a period without samples.
type Gap struct {
	From    string `json:"from"`
	To      string `json:"to"`
	Seconds int64  `json:"seconds"`
	// Explanation: "monitor stopped (<reason>)", "monitor stopped", "system suspended", "system shutdown",
	// "monitor crashed or killed (no clean stop)", "unexplained"; may carry the suffixes
	// "; length unknown: …" (Seconds 0) or "; its [length and ]times are unreliable: …".
	Explanation string `json:"explanation"`
}

// VerifyReport is the full verification outcome.
type VerifyReport struct {
	OK              bool            `json:"ok"`
	At              string          `json:"at"`
	Records         uint64          `json:"records"`
	Segments        []string        `json:"segments"`
	FirstTS         string          `json:"first_ts"`
	LastTS          string          `json:"last_ts"`
	HeadHash        string          `json:"head_hash"`
	Fingerprint     string          `json:"fingerprint"`
	TypeCounts      map[string]int  `json:"type_counts"`
	BlobsChecked    int             `json:"blobs_checked"`
	Failures        []VerifyFailure `json:"failures"`
	FailuresTotal   int             `json:"failures_total"` // Failures may be truncated to 200
	Anchors         []AnchorCheck   `json:"anchors"`
	LastAnchoredSeq uint64          `json:"last_anchored_seq"`
	UnanchoredTail  uint64          `json:"unanchored_tail"`
	Gaps            []Gap           `json:"gaps"`
	ClockJumps      int             `json:"clock_jumps"`
	TokensChecked   bool            `json:"tokens_checked"` // anchor tokens were cryptographically verified
	Notes           []string        `json:"notes,omitempty"`
}
