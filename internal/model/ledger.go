// Package model holds the data types shared by every att-monitor package: ledger
// envelopes and record payloads, probe results, gateway observations, incidents and the
// status/series views served to the dashboard. It contains no logic beyond tiny helpers.
//
// Everything that is written to the evidence ledger is JSON-encoded from these types, so
// field names are part of the evidence format (docs/DESIGN.md §6-§7). Do not rename JSON
// tags; add new optional fields instead.
package model

import "encoding/json"

// FormatVersion is the ledger body format version ("v").
const FormatVersion = 1

// ZeroHash is the "prev" value of the genesis record.
const ZeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Envelope is one line of a ledger segment. H and S cover the exact bytes of B.
type Envelope struct {
	H string `json:"h"` // lowercase hex SHA-256 of the UTF-8 bytes of B
	S string `json:"s"` // base64 (std, padded) Ed25519 signature over the bytes of B
	B string `json:"b"` // the serialized Body
}

// Body is the signed content of a ledger record.
type Body struct {
	V     int             `json:"v"`
	Seq   uint64          `json:"seq"`
	Prev  string          `json:"prev"`
	TS    string          `json:"ts"`   // RFC 3339 UTC with nanoseconds (time.RFC3339Nano)
	Mono  int64           `json:"mono"` // ns since process start (monotonic clock)
	Run   string          `json:"run"`  // per-process random id (32 hex chars)
	Type  string          `json:"type"` // one of the Type* constants
	Blobs []string        `json:"blobs,omitempty"`
	Data  json.RawMessage `json:"data"`
}

// Ref identifies an appended record.
type Ref struct {
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash"`
	TS   string `json:"ts"`
}

// Record types (docs/DESIGN.md §7).
const (
	TypeGenesis         = "genesis"
	TypeSegmentOpen     = "segment_open"
	TypeBootstrapImport = "bootstrap_import"
	TypeMonitorStart    = "monitor_start"
	TypeMonitorStop     = "monitor_stop"
	TypeHeartbeat       = "heartbeat"
	TypeSample          = "sample"
	TypeStateChange     = "state_change"
	TypeGatewaySnapshot = "gateway_snapshot"
	TypeGatewayEvent    = "gateway_event"
	TypeServiceCheck    = "service_check"
	TypeLocalLink       = "local_link"
	TypeTraceroute      = "traceroute"
	TypeClockCheck      = "clock_check"
	TypeClockJump       = "clock_jump"
	TypeIncidentOpen    = "incident_open"
	TypeIncidentUpdate  = "incident_update"
	TypeIncidentClose   = "incident_close"
	TypeAnchor          = "anchor"
	TypeConfigChange    = "config_change"
	TypePowerEvent      = "power_event"
	TypeCustodyExport   = "custody_export"
	TypeOperatorNote    = "operator_note"
	TypeRecovery        = "recovery"
	TypeIntegrityAlert  = "integrity_alert"
	TypeConfigState     = "config_state"
)

// Genesis is the payload of the first ledger record.
type Genesis struct {
	PublicKey   string       `json:"public_key"`  // base64 std of the 32-byte Ed25519 key
	Fingerprint string       `json:"fingerprint"` // hex SHA-256 of the raw public key
	Created     string       `json:"created"`
	Host        HostInfo     `json:"host"`
	Software    SoftwareInfo `json:"software"`
	Statement   string       `json:"statement"`
}

// SegmentOpen is the first record of every non-first daily segment.
type SegmentOpen struct {
	Segment            string `json:"segment"`             // e.g. "ledger-2026-10-05"
	PrevSegment        string `json:"prev_segment"`        // e.g. "ledger-2026-10-04"
	PrevSegmentSHA256  string `json:"prev_segment_sha256"` // of complete uncompressed bytes
	PrevSegmentRecords int    `json:"prev_segment_records"`
	PrevSegmentLastSeq uint64 `json:"prev_segment_last_seq"`
}

// HostInfo describes the monitoring computer.
type HostInfo struct {
	Hostname   string   `json:"hostname"`
	OS         string   `json:"os"`         // e.g. "Windows 11 Pro for Workstations"
	OSVersion  string   `json:"os_version"` // e.g. "10.0.26200"
	BootTime   string   `json:"boot_time,omitempty"`
	Interfaces []string `json:"interfaces,omitempty"` // "Wi-Fi 192.168.1.71/24 aa:bb:.."
	TimeZone   string   `json:"time_zone,omitempty"`
}

// SoftwareInfo identifies the code that produced the records.
type SoftwareInfo struct {
	Name      string `json:"name"`    // "att-monitor"
	Version   string `json:"version"` // semantic version or "dev"
	Commit    string `json:"commit,omitempty"`
	GoVersion string `json:"go_version"`
	ExePath   string `json:"exe_path"`
	ExeSHA256 string `json:"exe_sha256"`
	Rules     string `json:"rules"` // classifier RulesVersion
}

// BootstrapFile is one file imported from the bootstrap evidence folder.
type BootstrapFile struct {
	Path    string `json:"path"` // relative to the bootstrap dir, forward slashes
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	ModTime string `json:"mod_time"`
}

// BootstrapImport records evidence collected before the ledger existed.
type BootstrapImport struct {
	SourceDir string          `json:"source_dir"`
	Files     []BootstrapFile `json:"files"`
	Notes     string          `json:"notes"` // contents of CAPTURE-NOTES.txt if present
}

// MonitorStart is written at every process start.
type MonitorStart struct {
	Software     SoftwareInfo `json:"software"`
	Host         HostInfo     `json:"host"`
	ConfigSHA256 string       `json:"config_sha256"` // hash of config with secrets removed
	// Config is the effective configuration (secrets removed) so reports can quote exact thresholds.
	Config      json.RawMessage `json:"config,omitempty"`
	Mode        string          `json:"mode"` // "service" | "console"
	PrevHead    Ref             `json:"prev_head"`
	GapSeconds  int64           `json:"gap_seconds"` // since the previous record's ts (negative: this computer's clock is behind it)
	PrevStopped bool            `json:"prev_stopped_cleanly"`
}

// ConfigState records the effective configuration (secrets removed). The monitor writes it right
// after each segment_open (first record of a new UTC day) so every daily segment — and therefore
// every evidence bundle — states the thresholds in force from records it contains.
type ConfigState struct {
	ConfigSHA256 string          `json:"config_sha256"`
	Config       json.RawMessage `json:"config"`
	Rules        string          `json:"rules"`
	Reason       string          `json:"reason"` // "new_segment"
}

// MonitorStop is written on graceful shutdown.
type MonitorStop struct {
	Reason    string `json:"reason"` // "service stop", "system shutdown", "console interrupt"
	UptimeSec int64  `json:"uptime_s"`
}

// Heartbeat is written periodically to prove the monitor was alive.
type Heartbeat struct {
	UptimeSec  int64  `json:"uptime_s"`
	Cycles     uint64 `json:"cycles"`
	State      string `json:"state"`
	LastAnchor string `json:"last_anchor,omitempty"`
	RecordsRun uint64 `json:"records_this_run"`
}

// Recovery documents bytes removed from a damaged segment tail.
type Recovery struct {
	Segment       string `json:"segment"`
	Offset        int64  `json:"offset"`
	RemovedBytes  int64  `json:"removed_bytes"`
	RemovedSHA256 string `json:"removed_sha256"`
	QuarantineAs  string `json:"quarantine_as"`
	Reason        string `json:"reason"`
}

// IntegrityAlert documents a verification failure found by the writer itself.
type IntegrityAlert struct {
	Problem string   `json:"problem"`
	Details []string `json:"details"`
}

// Anchor records an RFC 3161 time-stamp over the chain head.
type Anchor struct {
	TSAURL      string `json:"tsa_url"`
	TSAName     string `json:"tsa_name,omitempty"` // subject of the TSA signing certificate
	HeadSeq     uint64 `json:"head_seq"`
	HeadHash    string `json:"head_hash"`
	TokenSHA256 string `json:"token_sha256"`         // blob id of the DER TimeStampResp
	GenTime     string `json:"gen_time"`             // RFC 3339 UTC from TSTInfo
	Serial      string `json:"serial"`               // hex
	Policy      string `json:"policy"`               // OID
	Nonce       string `json:"nonce"`                // hex
	Verified    bool   `json:"verified"`             // signature + imprint verified at issue time
	ChainOK     bool   `json:"chain_ok"`             // TSA cert chained to a trusted root at issue time
	ChainNote   string `json:"chain_note,omitempty"` // why ChainOK is false (diagnostic)
	Reason      string `json:"reason"`               // "genesis", "startup", "periodic", "incident_close", "export", "manual"
}

// ConfigChange records a change of gateway or monitor configuration.
type ConfigChange struct {
	Target string `json:"target"` // "gateway" | "monitor"
	What   string `json:"what"`   // e.g. "events.bbevent (Broadband Status Notification)"
	Before string `json:"before"`
	After  string `json:"after"`
	Actor  string `json:"actor"`  // "operator via web", "cli", "monitor (enforce_notification_off)"
	Result string `json:"result"` // "applied", "verified", "failed: ..."
}

// PowerEvent records OS power notifications received by the service.
type PowerEvent struct {
	Kind string `json:"kind"` // "suspend", "resume", "resume_automatic", "shutdown", "power_status_change"
}

// CustodyExport records the production of an evidence bundle.
type CustodyExport struct {
	From           string `json:"from"`
	To             string `json:"to"`
	IncidentID     string `json:"incident_id,omitempty"`
	FileName       string `json:"file_name"`
	BundleSHA256   string `json:"bundle_sha256"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Records        int    `json:"records"`
	Blobs          int    `json:"blobs"`
	PreparedBy     string `json:"prepared_by,omitempty"`
	Notes          string `json:"notes,omitempty"`
	Requester      string `json:"requester"` // "web 127.0.0.1", "cli user DOMAIN\\name"
}

// OperatorNote is a free-text note from the owner (e.g. an AT&T ticket number).
type OperatorNote struct {
	Text   string `json:"text"`
	Author string `json:"author,omitempty"`
	Source string `json:"source"` // "web" | "cli"
}

// ClockJump records divergence between wall clock and monotonic clock.
type ClockJump struct {
	WallDeltaMs int64 `json:"wall_delta_ms"`
	MonoDeltaMs int64 `json:"mono_delta_ms"`
	JumpMs      int64 `json:"jump_ms"` // wall - mono
}
