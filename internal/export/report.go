package export

import (
	"time"

	"attmonitor/internal/model"
)

// The types below define report.json. Field names are part of the bundle format: add fields,
// do not rename them. Times are RFC 3339 UTC strings, durations are whole seconds, optical
// values are integers in 0.1 dBm (as reported by the gateway).
//
// Format 2 (rules 2026.10-3): the summary's time figures count measurement cycles (each covers
// the time until the next cycle, at most 1.5 × the cycle interval) and exclude gateway-restart
// windows from provider time; provider_downtime_s is the same value as provider_outage_s and no
// longer the span of provider-attributed incidents; availability excludes UNKNOWN cycles;
// anchors say whether they are proof of time. methodology.config_source names the configuration
// record (config_state or monitor_start) the thresholds are quoted from, and each entry of
// methodology.thresholds.changes_in_period says from when until when its configuration applied.
//
// Format 3: report.json, REPORT.html, README.txt and keys/public-key.txt are a function of the
// bundle's ledger records and blobs plus the inputs report.json states (period, generation time,
// generator, request, local_time_zone, the full-ledger verification and the token verifier's
// results at export, the ledger segments left out): VerifyReport recomputes them and fails on any
// difference, so the figures cannot be edited after export. Local times are rendered with the
// exporting computer's zone as local_time_zone records it. A cycle covers until the next cycle
// of the same process (ledger order, corrected for wall-clock steps); the last cycle of a process
// that ended covers until its last observation. Percentages are truncated, never rounded up. An
// incident without a close record in the bundle has figures computed from its samples
// (incidents[].computed). A full-ledger verification that did not finish in time is reported in
// verification.full_ledger_incomplete. Segments are selected by the times of the records they
// hold. Rules described: 2026.10-4 - restart windows extend back over rule-1 cycles only; every
// incident with a close record that a restart concerns has a restart_check (its cycles with the
// computed windows and the OpenAfterCycles provider threshold, and the conflicts with its
// record); computed incidents stop where monitoring was interrupted (computed.interrupted_at);
// DNS statistics count a query as resolved only for NOERROR with an answer that was not
// redirected, and judge a resolver per service check over its query and retry; local_link
// counts the route checks (egress); monitor_start gaps are explained with between-run clock_jump
// records and the ledger writer's clock-behind integrity_alert. No software that wrote this
// format before these additions was released (bin/ held format 2), so they stay within format 3.
//
// Any change of the report's content or of its rendering (REPORT.html, README.txt,
// keys/public-key.txt) must change reportFormat: the verifier recomputes only its own format.
const reportFormat = "att-monitor-report/3"

type report struct {
	Format        string              `json:"format"`
	GeneratedAt   string              `json:"generated_at"`
	Generator     model.SoftwareInfo  `json:"generator"`
	Bundle        bundleMeta          `json:"bundle"`
	Period        period              `json:"period"`
	LocalTime     localTimeZone       `json:"local_time_zone"`
	Request       requestInfo         `json:"request"`
	Host          *hostInfo           `json:"monitoring_host,omitempty"`
	Gateway       []gatewayIdentity   `json:"gateway_identity"`
	Ledger        ledgerInfo          `json:"ledger"`
	Verification  verification        `json:"verification"`
	Summary       summary             `json:"summary"`
	Incidents     []incidentEntry     `json:"incidents"`
	GatewayStatus gatewayStatus       `json:"gateway_status"`
	Optical       optical             `json:"optical"`
	GatewayEvents []gatewayEventEntry `json:"gateway_events"`
	Service       serviceSummary      `json:"service_checks"`
	LocalLink     localLinkSummary    `json:"local_link"`
	Clock         clockSummary        `json:"clock"`
	Methodology   methodology         `json:"methodology"`
	Anchors       []anchorEntry       `json:"anchors"`
	Custody       []custodyEntry      `json:"custody_log"`
	Bootstrap     []bootstrapEntry    `json:"bootstrap_imports"`
	Notes         []string            `json:"notes,omitempty"`
}

type bundleMeta struct {
	FileName string `json:"file_name"`
	// ExtraFiles are the additional files the exporting software put into the bundle
	// (Options.ExtraFiles), e.g. keys/tsa-roots.pem.
	ExtraFiles []extraFileEntry `json:"extra_files,omitempty"`
	// TSARoots lists the certificates in keys/tsa-roots.pem, the root certificates offered for
	// "openssl ts -verify -CAfile keys/tsa-roots.pem". They are a convenience, not a trust
	// anchor: compare their SHA-256 fingerprints with the ones the TSAs publish.
	TSARoots     []rootCertEntry `json:"tsa_roots,omitempty"`
	TSARootsNote string          `json:"tsa_roots_note,omitempty"`
}

type extraFileEntry struct {
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	Bytes       int    `json:"bytes"`
	Description string `json:"description,omitempty"`
}

type rootCertEntry struct {
	Subject   string `json:"subject"`
	SHA256    string `json:"sha256"` // of the DER certificate
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
}

type period struct {
	From         string `json:"from"`
	To           string `json:"to"`
	EffectiveEnd string `json:"effective_end"` // min(to, generated_at): statistics stop here
	Scope        string `json:"scope"`         // "period" | "incident"
	IncidentID   string `json:"incident_id,omitempty"`
	LocalZone    string `json:"local_zone"` // zone of the exporting computer, e.g. "PDT (UTC-07:00)"
}

type requestInfo struct {
	PreparedBy string `json:"prepared_by,omitempty"`
	Notes      string `json:"notes,omitempty"`
	Requester  string `json:"requester,omitempty"`
}

type hostInfo struct {
	model.HostInfo
	SourceType string `json:"source_type"` // record type the facts come from
	SourceSeq  uint64 `json:"source_seq"`
}

type gatewayIdentity struct {
	Manufacturer string `json:"manufacturer,omitempty"`
	Model        string `json:"model,omitempty"`
	Serial       string `json:"serial,omitempty"`
	Firmware     string `json:"firmware,omitempty"`
	Hardware     string `json:"hardware_version,omitempty"`
	FirstSeen    string `json:"first_seen"`
	LastSeen     string `json:"last_seen"`
	FirstSeq     uint64 `json:"first_seq"`
	LastSeq      uint64 `json:"last_seq"`
	Snapshots    int    `json:"snapshots"`
	BeforePeriod bool   `json:"before_period,omitempty"` // no snapshot in the period; last one before it
}

type recordRef struct {
	Seq     uint64 `json:"seq"`
	Hash    string `json:"hash"`
	TS      string `json:"ts"`
	Segment string `json:"segment,omitempty"`
}

type segmentEntry struct {
	Name              string `json:"name"`
	Path              string `json:"path"`
	SHA256            string `json:"sha256"`
	Bytes             int64  `json:"bytes"`
	Records           int    `json:"records"`
	FirstSeq          uint64 `json:"first_seq"`
	LastSeq           uint64 `json:"last_seq"`
	FirstTS           string `json:"first_ts,omitempty"`
	LastTS            string `json:"last_ts,omitempty"`
	Genesis           bool   `json:"genesis_segment"`
	OverlapsPeriod    bool   `json:"overlaps_period"`
	ExcludedTailBytes int    `json:"excluded_partial_tail_bytes,omitempty"`
	IncludedFor       string `json:"included_for,omitempty"`

	parsed int // records whose envelope parsed (for first/last bookkeeping)
}

type omittedSegment struct {
	Name     string `json:"name"`
	FirstSeq uint64 `json:"first_seq"`
	LastSeq  uint64 `json:"last_seq"`
	Records  int    `json:"records"`
}

type ledgerInfo struct {
	PublicKey   string     `json:"public_key,omitempty"`
	Fingerprint string     `json:"fingerprint,omitempty"`
	Genesis     *recordRef `json:"genesis,omitempty"`
	// GenesisVerified: the genesis record hashes correctly and is signed by its own key; only
	// then is its public key used to check the other signatures.
	GenesisVerified bool             `json:"genesis_verified"`
	Created         string           `json:"created,omitempty"`
	Statement       string           `json:"statement,omitempty"`
	Head            *recordRef       `json:"head,omitempty"` // last record in this bundle
	Records         int              `json:"records"`
	Segments        []segmentEntry   `json:"segments"`
	Omitted         []omittedSegment `json:"omitted_segments,omitempty"` // between included segments
	Later           []omittedSegment `json:"later_segments,omitempty"`   // after the last included segment
	TypeCounts      map[string]int   `json:"type_counts"`
}

type verification struct {
	Overall   string            `json:"overall"` // "pass" | "fail"
	Full      *fullVerification `json:"full_ledger,omitempty"`
	FullError string            `json:"full_ledger_error,omitempty"`
	// FullIncomplete says why the full-ledger verification did not complete (it was stopped
	// after the time an export allows it); not a failure: the bundle's records are verified.
	FullIncomplete string      `json:"full_ledger_incomplete,omitempty"`
	Bundle         bundleCheck `json:"bundle"`
}

// fullVerification summarises contracts.Verifier.Verify run on the source ledger at export time.
type fullVerification struct {
	OK                 bool                  `json:"ok"`
	At                 string                `json:"at"`
	Records            uint64                `json:"records"`
	Segments           int                   `json:"segments"`
	FirstTS            string                `json:"first_ts"`
	LastTS             string                `json:"last_ts"`
	HeadHash           string                `json:"head_hash"`
	Fingerprint        string                `json:"fingerprint"`
	FingerprintMatches bool                  `json:"fingerprint_matches_bundle"`
	KeyMismatch        bool                  `json:"key_mismatch,omitempty"` // verified a ledger with another key: it does not vouch for this bundle
	BlobsChecked       int                   `json:"blobs_checked"`
	FailuresTotal      int                   `json:"failures_total"`
	Failures           []model.VerifyFailure `json:"failures,omitempty"` // first 20
	Anchors            int                   `json:"anchors"`
	AnchorsOK          int                   `json:"anchors_ok"`
	AnchorsProofOfTime int                   `json:"anchors_proof_of_time"` // OK and chain trusted
	TokensChecked      bool                  `json:"tokens_checked"`        // tokens were cryptographically verified
	LastAnchoredSeq    uint64                `json:"last_anchored_seq"`
	UnanchoredTail     uint64                `json:"unanchored_tail"`
	Gaps               int                   `json:"gaps"`
	ClockJumps         int                   `json:"clock_jumps"`
	Notes              []string              `json:"notes,omitempty"`
}

// bundleCheck is the verification of the bundle's own content, done while it was written.
type bundleCheck struct {
	OK                     bool `json:"ok"`
	Segments               int  `json:"segments"`
	Records                int  `json:"records"`
	HashesOK               int  `json:"hashes_ok"`
	HashFailures           int  `json:"hash_failures"`
	SignaturesOK           int  `json:"signatures_ok"`
	SignatureFailures      int  `json:"signature_failures"`
	SignaturesUnchecked    int  `json:"signatures_unchecked"`
	ChainFailures          int  `json:"chain_failures"`
	ParseFailures          int  `json:"parse_failures"`
	BlobsReferenced        int  `json:"blobs_referenced"`
	BlobsIncluded          int  `json:"blobs_included"`
	BlobsMissing           int  `json:"blobs_missing"`
	BlobsCorrupt           int  `json:"blobs_corrupt"`
	AnchorsChecked         int  `json:"anchors_checked"`
	AnchorsHeadOK          int  `json:"anchors_head_ok"`
	AnchorsHeadMismatch    int  `json:"anchors_head_mismatch"`
	AnchorsHeadNotInBundle int  `json:"anchors_head_not_in_bundle"`
	AnchorTokensMissing    int  `json:"anchor_tokens_missing"`
	AnchorTokensOK         int  `json:"anchor_tokens_ok"`
	AnchorTokensInvalid    int  `json:"anchor_tokens_invalid"`
	// TokenVerifier: the tokens were also checked by a token verifier (CMS signature and TSA
	// certificate chain); otherwise the anchor records' issue-time flags decide proof of time.
	TokenVerifier      bool                  `json:"token_verifier"`
	AnchorsProofOfTime int                   `json:"anchors_proof_of_time"`
	AnchorsNotProof    int                   `json:"anchors_not_proof_of_time"`
	FailuresTotal      int                   `json:"failures_total"`
	Failures           []model.VerifyFailure `json:"failures,omitempty"` // first 50
	Notes              []string              `json:"notes,omitempty"`
}

type stateCount struct {
	State string `json:"state"`
	Count int    `json:"count"`
}

type incidentClass struct {
	State       string `json:"state"`
	Cause       string `json:"cause"`
	Attribution string `json:"attribution"`
	Count       int    `json:"count"`
	Seconds     int64  `json:"seconds_in_period"`
}

type incidentRef struct {
	ID          string `json:"id"`
	State       string `json:"state"`
	Cause       string `json:"cause"`
	Attribution string `json:"attribution"`
	Seconds     int64  `json:"seconds"`
	Ongoing     bool   `json:"ongoing,omitempty"`
	// DowntimeSec is the incident's time without Internet: its record's own figure, or for an
	// incident with no close record in the bundle the figure computed from its samples
	// (DowntimeComputed). Null: not recorded.
	DowntimeSec      *int64 `json:"downtime_s,omitempty"`
	DowntimeComputed bool   `json:"downtime_computed,omitempty"`
	// RestartConflict: the gateway-restart windows computed from the records contradict the
	// incident's record (incidents[].restart_check.conflicts).
	RestartConflict bool `json:"restart_conflict,omitempty"`
}

// stateTime is the cycle time spent in one recorded state.
type stateTime struct {
	State   string `json:"state"`
	Seconds int64  `json:"seconds"`
}

// restartEntry is a gateway restart named by the records, with its restart window
// (docs/DESIGN.md §10, rules 2026.10-4).
type restartEntry struct {
	BootTime   string   `json:"boot_time"`   // estimated gateway boot time (fetch time - uptime), UTC
	WindowFrom string   `json:"window_from"` // boot time, extended back over the unreachable cycles just before
	WindowTo   string   `json:"window_to"`   // first cycle with Internet again, at most boot + 10 min
	WindowEnd  string   `json:"window_end"`  // "internet reachable again" | "10-minute cap"
	Sources    []string `json:"sources"`     // records naming the restart
	Evidence   []uint64 `json:"evidence_seqs"`
	Firmware   string   `json:"firmware_change,omitempty"` // "A -> B" when the firmware changed across it
	BadCycles  int      `json:"bad_cycles_in_period"`
	RestartSec int64    `json:"restart_s"` // time of bad cycles of the period inside the window
}

type gapEntry struct {
	From        string   `json:"from"`
	To          string   `json:"to"`
	Seconds     int64    `json:"seconds"`
	Explanation string   `json:"explanation"`
	Evidence    []uint64 `json:"evidence_seqs,omitempty"`
}

// anchorRef names an anchor that is proof of time (see anchorEntry.ProofOfTime).
type anchorRef struct {
	Seq        uint64 `json:"seq"`
	TSA        string `json:"tsa"`
	GenTime    string `json:"gen_time"` // the token's own genTime
	HeadSeq    uint64 `json:"head_seq"`
	ProofBasis string `json:"proof_basis"`
}

type summary struct {
	WindowSec      int64   `json:"window_s"`
	MonitoredSec   int64   `json:"monitored_s"` // cycle time (each cycle covers <= 1.5 × the cycle interval)
	CoveragePct    float64 `json:"coverage_pct"`
	CadenceSec     float64 `json:"cadence_s"` // median interval between samples
	CadenceAssumed bool    `json:"cadence_assumed,omitempty"`
	// FastIntervalSec is the cycle interval of the time accounting (cover cap 1.5 ×, gap limit
	// 3 ×); FastIntervalBasis says where it comes from.
	FastIntervalSec   float64      `json:"fast_interval_s"`
	FastIntervalBasis string       `json:"fast_interval_basis"`
	Cycles            int          `json:"cycles"`
	CyclesKnown       int          `json:"cycles_known_state"` // cycles not UNKNOWN
	CyclesByState     []stateCount `json:"cycles_by_state"`
	TimeByState       []stateTime  `json:"time_by_state"`              // cycle time per recorded state
	AvailabilityPct   *float64     `json:"availability_pct,omitempty"` // ONLINE cycles / cycles with a known state
	FirstSample       string       `json:"first_sample,omitempty"`
	LastSample        string       `json:"last_sample,omitempty"`
	// Cycle-time figures computed from the samples of the period (docs/DESIGN.md §10, rules
	// 2026.10-4), never from incident spans: downtime_s = ISP_OUTAGE cycles, degraded_s =
	// DEGRADED cycles, both outside gateway-restart windows; restart_s = bad cycles inside
	// restart windows; provider_outage_s = provider-attributed ISP_OUTAGE cycles outside them.
	DowntimeSec       int64           `json:"downtime_s"`
	DegradedSec       int64           `json:"degraded_s"`
	RestartSec        int64           `json:"restart_s"`
	ProviderOutageSec int64           `json:"provider_outage_s"`
	GatewayRestarts   []restartEntry  `json:"gateway_restarts"`
	Incidents         int             `json:"incidents"`
	IncidentsByClass  []incidentClass `json:"incidents_by_class"`
	ProviderIncidents int             `json:"provider_incidents"` // incidents whose record attributes them to the provider
	// ProviderDowntimeSec equals provider_outage_s (kept for format compatibility; format 1 used
	// the span of provider-attributed incidents). ProviderDegradedSec is the time of
	// provider-attributed DEGRADED cycles outside restart windows.
	ProviderDowntimeSec int64        `json:"provider_downtime_s"`
	ProviderDegradedSec int64        `json:"provider_degraded_s"`
	LongestOutage       *incidentRef `json:"longest_outage,omitempty"`
	Blips               int          `json:"blips"`
	BlipCycles          int          `json:"blip_cycles"`
	BlipsByState        []stateCount `json:"blips_by_state,omitempty"`
	Gaps                []gapEntry   `json:"gaps"`
	GapSec              int64        `json:"gap_s"`
	LastRecordInPeriod  *recordRef   `json:"last_record_in_period,omitempty"`
	LastRecordAnchor    *anchorRef   `json:"last_record_anchor,omitempty"`
	// IncidentsWithoutRecords lists incident ids carried by samples of the period whose
	// incident records are not in the bundle.
	IncidentsWithoutRecords []string `json:"incidents_without_records,omitempty"`
}

type incidentEntry struct {
	Incident      model.Incident `json:"incident"` // latest record's payload, verbatim
	Ongoing       bool           `json:"ongoing"`  // no close record in this bundle
	EffectiveEnd  string         `json:"effective_end"`
	DurationSec   int64          `json:"duration_s"`
	InPeriodSec   int64          `json:"in_period_s"`
	OpenSeq       *uint64        `json:"open_seq,omitempty"`
	CloseSeq      *uint64        `json:"close_seq,omitempty"`
	RecordSeqs    []uint64       `json:"record_seqs"`
	EvidenceSeqs  []uint64       `json:"evidence_seqs"`
	EvidenceBlobs []string       `json:"evidence_blobs,omitempty"`
	KeyFacts      []string       `json:"key_facts"`
	Anchor        *anchorRef     `json:"anchor,omitempty"` // first proof-of-time anchor covering its last record
	// Recorded are the incident record's own time figures; null when the record does not
	// contain them (written under older rules versions). RecordedSeq/RecordedTS name that record
	// (the incident's latest record in this bundle): its figures are as of that record.
	Recorded    incidentTimes `json:"recorded_times"`
	RecordedSeq uint64        `json:"recorded_seq"`
	RecordedTS  string        `json:"recorded_ts"`
	// ComputedRestartSec is the time of the incident's bad cycles in this bundle (up to the end of
	// the period) that lie inside the gateway-restart windows this report computes from the
	// records (rules 2026.10-4), for comparison with the record's restart_s (records of rules
	// older than 2026.10-3 have none).
	ComputedRestartSec int64 `json:"computed_restart_s"`
	// RestartCheck compares the record of an incident with a close record with the gateway-restart
	// windows computed from the records, when a restart concerns it (nil otherwise).
	RestartCheck *restartCheck `json:"restart_check,omitempty"`
	// Computed is set for an incident without a close record in this bundle (Ongoing): the
	// monitor writes an incident_update only when the incident's classification changes, so its
	// latest record states its figures only as of when it was written. Computed holds the figures
	// recomputed from the samples in this bundle, through the end of the period.
	Computed *incidentComputed `json:"computed,omitempty"`
}

// RestartDiffers reports whether the restart time computed from the records differs from the
// record's own restart_s (or the record has none while the computed time is not zero).
func (e incidentEntry) RestartDiffers() bool {
	if e.Recorded.RestartSec == nil {
		return e.ComputedRestartSec != 0
	}
	return *e.Recorded.RestartSec != e.ComputedRestartSec
}

// ComputedDowntime returns the time of the incident's ISP_OUTAGE cycles outside the gateway-restart
// windows computed from the records when all its cycles are in the bundle and it differs from the
// record's own downtime_s by more than the tolerance of the comparison (nil otherwise).
func (e incidentEntry) ComputedDowntime() *int64 {
	rc, rec := e.RestartCheck, e.Recorded.DowntimeSec
	if rc == nil || !rc.Complete || rec == nil {
		return nil
	}
	tol := int64(restartTolerance / time.Second)
	if d := rc.DowntimeSec; *rec < 0 || *rec-d > tol || d-*rec > tol {
		return &d
	}
	return nil
}

// restartCheck compares an incident's own record with the gateway-restart windows this report
// computes from the records (docs/DESIGN.md §10, rules 2026.10-4), counted over the incident's
// cycles in this bundle as the monitor counts them: bad cycles inside a window are restart time,
// never time without Internet; an incident with a restart is the provider's only with at least
// open_after_cycles provider-attributed bad cycles outside the windows, or a firmware change
// across the restart. Conflicts words each disagreement (only when the incident's cycles are all
// in the bundle: Complete).
type restartCheck struct {
	Complete        bool     `json:"complete"` // every cycle of the incident is in this bundle (before the end of the period)
	Cycles          int      `json:"cycles"`   // cycles examined: from its first bad cycle to its last cycle (closing streak included)
	BadCycles       int      `json:"bad_cycles"`
	BadInWindows    int      `json:"bad_cycles_in_restart_windows"`
	ProviderOutside int      `json:"provider_bad_cycles_outside_windows"`
	OpenAfterCycles int      `json:"open_after_cycles"` // the provider threshold applied
	FirmwareChange  bool     `json:"firmware_change"`   // the firmware changed across a restart of the incident
	DowntimeSec     int64    `json:"downtime_s"`        // ISP_OUTAGE cycles outside the windows
	DegradedSec     int64    `json:"degraded_s"`        // DEGRADED cycles outside the windows
	RestartSec      int64    `json:"restart_s"`         // bad cycles inside the windows (= computed_restart_s)
	Boots           []string `json:"restart_boots"`     // boot times of the restarts that belong to the incident
	GatewayRestart  bool     `json:"gateway_restart"`   // the rules make it a gateway restart (LOCAL_FAULT / GATEWAY_REBOOT)
	Attribution     string   `json:"attribution"`       // its attribution under the rules described in the report
	Conflicts       []string `json:"conflicts,omitempty"`
}

// incidentComputed are the figures of an incident computed by the report from the samples of
// the bundle, the way the monitor counts them (docs/DESIGN.md §10): every cycle of the process
// that recorded the incident from its first bad cycle on, a good cycle counted only when a bad
// one follows, time from the cycles' cover (restart-window time apart), gateway observations
// from the snapshots and service checks of those cycles.
type incidentComputed struct {
	Through  string `json:"through"`  // the samples up to this time (the end of the period)
	FromSeq  uint64 `json:"from_seq"` // first sample examined
	ToSeq    uint64 `json:"to_seq"`   // last sample examined
	Complete bool   `json:"complete"` // the incident's first bad cycle (first_seq) is in this bundle
	// ClosingAt: the samples show the incident closing (close_after_cycles consecutive ONLINE
	// cycles starting then); its close record is not in this bundle.
	ClosingAt string `json:"closing_at,omitempty"`
	// InterruptedAt: the samples show monitoring interrupted while the incident was open (a
	// monitoring gap, or a cycle cut short by system sleep); the rules close it at the end of
	// its last bad cycle's coverage (or at the first cycle of a closing streak), this time. Its
	// close record is not in this bundle; later cycles are not counted.
	InterruptedAt string              `json:"interrupted_at,omitempty"`
	Stats         model.IncidentStats `json:"stats"`
}

type incidentTimes struct {
	DowntimeSec *int64 `json:"downtime_s"`
	DegradedSec *int64 `json:"degraded_s"`
	RestartSec  *int64 `json:"restart_s"`
}

type valueCount struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

type gatewayStatus struct {
	Snapshots        int          `json:"snapshots"`
	Reachable        int          `json:"reachable"`
	BroadbandUp      int          `json:"broadband_up"`
	BroadbandDown    int          `json:"broadband_down"`
	BroadbandUnknown int          `json:"broadband_unknown"`
	PONStatus        []valueCount `json:"pon_link_status"`
	OpticalStatus    []valueCount `json:"optical_status"`
	WANIPv4          []string     `json:"wan_ipv4"`
	ClockBlank       int          `json:"gateway_clock_blank"`
	PageFetches      int          `json:"page_fetches"`
	PageErrors       int          `json:"page_errors"`
	PagesStored      int          `json:"pages_stored"`
	// PagesNotAttempted counts pages skipped after the gateway could not be reached at all
	// (not fetches, not counted as errors).
	PagesNotAttempted int `json:"pages_not_attempted"`
}

type alarmPeriod struct {
	Code       string `json:"code"`
	Severity   string `json:"severity"` // "critical" | "warning" | "info"
	FirstSeen  string `json:"first_seen"`
	LastSeen   string `json:"last_seen"`
	ClearedAt  string `json:"cleared_at,omitempty"` // first snapshot without the flag
	EndReason  string `json:"end_reason"`           // "cleared" | "observation gap" | "end of period"
	ObservedS  int64  `json:"observed_s"`           // last_seen - first_seen
	Snapshots  int    `json:"snapshots"`
	RxMinX10   *int64 `json:"rx_min_x10,omitempty"`
	RxMaxX10   *int64 `json:"rx_max_x10,omitempty"`
	FirstSeq   uint64 `json:"first_seq"`
	LastSeq    uint64 `json:"last_seq"`
	FirstIndex int    `json:"-"`
	LastIndex  int    `json:"-"`
}

type opticalRow struct {
	Start     string `json:"start"`
	Readings  int    `json:"readings"`
	RxMinX10  *int64 `json:"rx_min_x10,omitempty"`
	RxMedX10  *int64 `json:"rx_median_x10,omitempty"`
	RxMaxX10  *int64 `json:"rx_max_x10,omitempty"`
	LowAlarm  int    `json:"rx_low_alarm_readings"`
	LowWarn   int    `json:"rx_low_warning_readings"`
	TxMeanX10 *int64 `json:"tx_mean_x10,omitempty"`
}

type dmiRow struct {
	Name     string `json:"name"`
	Current  string `json:"current_raw"`
	Unit     string `json:"unit"`
	LowAlarm string `json:"low_alarm_raw"`
	HighAlrm string `json:"high_alarm_raw"`
	LowWarn  string `json:"low_warning_raw"`
	HighWarn string `json:"high_warning_raw"`
}

type opticalSource struct {
	Seq        uint64 `json:"seq"`
	TS         string `json:"ts"`
	PageSHA256 string `json:"fiberstat_sha256,omitempty"`
	PageStored bool   `json:"fiberstat_stored"`
}

type optical struct {
	Readings       int            `json:"readings"` // snapshots with an Rx power value
	Snapshots      int            `json:"snapshots"`
	RxMinX10       *int64         `json:"rx_min_x10,omitempty"`
	RxMedianX10    *int64         `json:"rx_median_x10,omitempty"`
	RxMaxX10       *int64         `json:"rx_max_x10,omitempty"`
	RxLastX10      *int64         `json:"rx_last_x10,omitempty"`
	TxMinX10       *int64         `json:"tx_min_x10,omitempty"`
	TxMaxX10       *int64         `json:"tx_max_x10,omitempty"`
	LowAlarmThrX10 *int64         `json:"rx_low_alarm_threshold_x10,omitempty"` // latest
	LowWarnThrX10  *int64         `json:"rx_low_warning_threshold_x10,omitempty"`
	ThresholdsSeen []string       `json:"thresholds_seen,omitempty"` // when they changed
	LowAlarmN      int            `json:"rx_low_alarm_readings"`
	LowWarnN       int            `json:"rx_low_warning_readings"`
	FlagCounts     []valueCount   `json:"alarm_flag_counts"`
	Periods        []alarmPeriod  `json:"alarm_periods"`
	Rows           []opticalRow   `json:"rows"`
	RowUnit        string         `json:"row_unit"` // "hour" | "day"
	LatestDMI      []dmiRow       `json:"latest_dmi,omitempty"`
	LatestSource   *opticalSource `json:"latest_source,omitempty"`
}

type gatewayEventEntry struct {
	Seq      uint64   `json:"seq"`
	TS       string   `json:"ts"`
	Kind     string   `json:"kind"`
	Before   string   `json:"before,omitempty"`
	After    string   `json:"after,omitempty"`
	Detail   string   `json:"detail,omitempty"`
	Evidence []uint64 `json:"evidence,omitempty"`
}

// dnsStat counts the DNS resolution queries of one resolver (the test name; the .invalid test is
// invalidNameStat). A query is resolved only when the resolver answered NOERROR with at least one
// answer that was not redirected (hijacked): a well-formed response alone - SERVFAIL, NXDOMAIN or
// an empty answer - is not. A query that got no valid response is retried once within its service
// check, so a check can hold two results for a resolver: the resolver resolved the name in that
// check when any of them did, and failed when all of them did (the DNS rule of docs/DESIGN.md §9
// judges it the same way).
type dnsStat struct {
	Role     string `json:"role"`
	Server   string `json:"server"`
	Checks   int    `json:"checks"`          // service checks that queried this resolver
	Resolved int    `json:"resolved_checks"` // checks in which at least one of its queries was resolved
	Retried  int    `json:"retried_checks"`  // checks in which its query was asked again
	Queries  int    `json:"queries"`         // queries sent (a retry is a query)
	OK       int    `json:"ok"`              // queries resolved (NOERROR, at least one answer, not hijacked)
	Hijacked int    `json:"hijacked"`        // queries whose answer was redirected
}

// invalidNameStat counts the queries for a random name under the reserved .invalid domain
// (RFC 6761: it must never resolve), the test for NXDOMAIN redirection: any answer is one.
type invalidNameStat struct {
	Role       string `json:"role"`
	Server     string `json:"server"`
	Queries    int    `json:"queries"`
	NXDomain   int    `json:"nxdomain"`   // answered "no such name" (correct)
	Redirected int    `json:"redirected"` // answered with an address (hijacked)
}

type httpStat struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	Checks   int    `json:"checks"`
	OK       int    `json:"ok"`
	Hijacked int    `json:"hijacked"`
}

type hijackExample struct {
	Seq    uint64 `json:"seq"`
	TS     string `json:"ts"`
	Kind   string `json:"kind"` // "dns" | "http"
	Where  string `json:"where"`
	Detail string `json:"detail"`
	// Exact values from the record (Detail is a readable summary of them).
	Why           string   `json:"hijack_why,omitempty"`
	Answers       []string `json:"answers,omitempty"` // dns
	Status        int      `json:"status,omitempty"`  // http
	Location      string   `json:"location,omitempty"`
	RemoteAddr    string   `json:"remote_addr,omitempty"`
	BodyPrefix    string   `json:"body_prefix,omitempty"`
	TLSCertSHA256 string   `json:"tls_cert_sha256,omitempty"`
}

type serviceSummary struct {
	Checks         int               `json:"checks"`
	DNS            []dnsStat         `json:"dns"`
	InvalidName    []invalidNameStat `json:"invalid_name_test,omitempty"`
	HTTP           []httpStat        `json:"http"`
	DNSHijacks     int               `json:"dns_hijacks"`
	HTTPHijacks    int               `json:"http_hijacks"`
	HijackExamples []hijackExample   `json:"hijack_examples,omitempty"`
}

type localLinkSummary struct {
	Observations int          `json:"observations"`
	Types        []valueCount `json:"types"`
	Interfaces   []string     `json:"interfaces,omitempty"`
	SSIDs        []string     `json:"ssids,omitempty"`
	BSSIDs       []string     `json:"bssids,omitempty"`
	SignalMinPct *int         `json:"signal_min_pct,omitempty"`
	SignalMedPct *int         `json:"signal_median_pct,omitempty"`
	SignalMaxPct *int         `json:"signal_max_pct,omitempty"`
	Disconnected int          `json:"disconnected"`
	// The route checks recorded with the observations (rules 2026.10-4, "egress"): made, and
	// showing a destination routed past the AT&T gateway (a VPN, another network adapter), while
	// which nothing measured is attributed to the provider (cause LOCAL_ROUTE).
	EgressChecks     int      `json:"egress_checks"`
	EgressBypass     int      `json:"egress_bypass"`
	EgressBypassSeqs []uint64 `json:"egress_bypass_seqs,omitempty"` // the first of them
}

type clockSummary struct {
	Checks                int      `json:"checks"`
	Results               int      `json:"results"`
	ResultsOK             int      `json:"results_ok"`
	Servers               []string `json:"servers,omitempty"`
	MaxAbsOffsetMs        *int64   `json:"max_abs_offset_ms,omitempty"`
	GatewayMaxAbsOffsetMs *int64   `json:"gateway_max_abs_offset_ms,omitempty"`
	ClockJumps            int      `json:"clock_jumps"`
}

type probeStat struct {
	Name       string   `json:"name"`
	Kind       string   `json:"kind"`
	Role       string   `json:"role"`
	Targets    []string `json:"targets"`
	Attempts   int      `json:"attempts"`
	OK         int      `json:"ok"`
	SuccessPct float64  `json:"success_pct"`
	MeanRTTms  *float64 `json:"mean_rtt_ms,omitempty"`

	rttSumUs int64
	rttN     int
}

type softwareSeen struct {
	Version   string `json:"version"`
	Commit    string `json:"commit,omitempty"`
	ExeSHA256 string `json:"exe_sha256,omitempty"`
	Rules     string `json:"rules,omitempty"`
	FirstSeq  uint64 `json:"first_seq"`
	FirstTS   string `json:"first_ts"`
}

type methodology struct {
	Probes          []probeStat    `json:"probes"`
	CadenceSec      float64        `json:"sample_cadence_s"`
	SnapshotCadence float64        `json:"gateway_snapshot_cadence_s,omitempty"`
	RulesVersions   []string       `json:"rules_versions"`
	RulesDescribed  string         `json:"rules_described"`
	RulesMismatch   bool           `json:"rules_mismatch,omitempty"` // records use a version other than rules_described
	RulesNotes      []rulesNote    `json:"rules_notes,omitempty"`    // what differs for records of other versions
	Thresholds      thresholds     `json:"thresholds"`
	ConfigSource    configSource   `json:"config_source"` // the record the thresholds are quoted from
	Providers       []string       `json:"providers"`     // distinct internet target addresses probed in the period
	SamplesInputs   int            `json:"samples_with_inputs"`
	Software        []softwareSeen `json:"software"`
	Heartbeats      int            `json:"heartbeats"`
	Traceroutes     int            `json:"traceroutes"`
	StateChanges    int            `json:"state_changes"`
}

// rulesNote explains how records produced under another rules version differ from the rules
// described in the report.
type rulesNote struct {
	Version         string   `json:"version"`
	Samples         int      `json:"samples_in_period"`
	IncidentRecords int      `json:"incident_records"`
	Known           bool     `json:"known"` // a version this report knows the differences of
	Differences     []string `json:"differences"`
}

// configSource names the record the report's thresholds are quoted from: the latest
// configuration record (config_state, written at the start of every daily ledger segment, or
// monitor_start, written at every process start) of the bundle at or before the start of the
// period, or - when none of those applies - the first one in the period, provided every earlier
// record of the period was written by the same monitor process. Type "defaults": no record
// applies and the documented defaults are shown (thresholds.note says why).
type configSource struct {
	Type         string  `json:"type"` // "config_state" | "monitor_start" | "defaults"
	Seq          *uint64 `json:"seq,omitempty"`
	TS           string  `json:"ts,omitempty"`
	ConfigSHA256 string  `json:"config_sha256,omitempty"` // as recorded
	Basis        string  `json:"basis,omitempty"`         // "at_or_before_period_start" | "first_in_period"
}

// thresholds are the classifier and incident parameters quoted by the report: the configuration
// recorded by the record methodology.config_source names, else the documented defaults (Source
// "defaults", with Note saying why). Changes lists the other configurations recorded in the period.
type thresholds struct {
	Source string `json:"source"` // "config_state" | "monitor_start" | "defaults" (= config_source.type)
	// Seq and TS name the source record when it is a monitor_start record (format 2 fields; see
	// methodology.config_source for every source type).
	Seq          *uint64 `json:"monitor_start_seq,omitempty"`
	TS           string  `json:"monitor_start_ts,omitempty"`
	ConfigSHA256 string  `json:"config_sha256,omitempty"`
	Note         string  `json:"note,omitempty"`
	// AppliesUntil ends the span the values describe: the time of the first other configuration
	// recorded in the period (Changes), else the end of the period.
	AppliesUntil         string            `json:"applies_until,omitempty"`
	FastIntervalSec      float64           `json:"fast_interval_s"`
	ProbeTimeoutSec      float64           `json:"probe_timeout_s"`
	OpenAfterCycles      int               `json:"open_after_cycles"`
	CloseAfterCycles     int               `json:"close_after_cycles"`
	WindowCycles         int               `json:"window_cycles"`
	LossDegradedPct      float64           `json:"loss_degraded_pct"`
	LatencyDegradedMs    float64           `json:"latency_degraded_ms"`
	GatewayLatencyOkMs   float64           `json:"gateway_latency_ok_ms"`
	SnapshotFreshnessSec float64           `json:"snapshot_freshness_s"`
	CoverCapSec          float64           `json:"cycle_cover_cap_s"`    // 1.5 × fast interval
	GapLimitSec          float64           `json:"gap_limit_s"`          // 3 × fast interval
	RestartMoveSec       float64           `json:"restart_boot_move_s"`  // boot-time move that means a restart
	RestartCapSec        float64           `json:"restart_window_cap_s"` // restart window ends at most this long after the boot
	InternetTargets      []string          `json:"internet_targets,omitempty"`
	Changes              []thresholdChange `json:"changes_in_period,omitempty"`
}

// thresholdChange is a configuration record of the period whose configuration differs from the
// one in force before it. It applied from its record (TS) until the next change or the end of
// the period (AppliesUntil). Changes says what differs: threshold changes as "name old -> new",
// other settings as "path old -> new" (recorded JSON values, long ones abbreviated).
type thresholdChange struct {
	Type            string   `json:"type"` // "monitor_start" | "config_state"
	Seq             uint64   `json:"seq"`
	MonitorStartSeq *uint64  `json:"monitor_start_seq,omitempty"` // format 2 field: set for monitor_start records
	TS              string   `json:"ts"`
	ConfigSHA256    string   `json:"config_sha256,omitempty"`
	AppliesUntil    string   `json:"applies_until"`
	Changes         []string `json:"changes"`
}

type anchorEntry struct {
	Seq           uint64 `json:"seq"`
	TS            string `json:"ts"`
	TSAURL        string `json:"tsa_url"`
	TSAName       string `json:"tsa_name,omitempty"`
	HeadSeq       uint64 `json:"head_seq"`
	HeadHash      string `json:"head_hash"`
	GenTime       string `json:"gen_time"`
	Token         string `json:"token_sha256"`
	Reason        string `json:"reason,omitempty"`
	Verified      bool   `json:"verified_at_issue"`
	ChainOK       bool   `json:"chain_ok_at_issue"`
	ChainNoteRec  string `json:"chain_note_at_issue,omitempty"` // the record's chain_note
	HeadCheck     string `json:"head_check"`                    // "ok" | "mismatch" | "head not in bundle"
	TokenIncluded bool   `json:"token_included"`
	TokenCheck    string `json:"token_check,omitempty"`
	TokenGenTime  string `json:"token_gen_time,omitempty"`
	// Token verifier result at export (Options.TokenVerifier): ChainTrusted is its ChainOK,
	// ChainNote explains a false one; nil/empty when no verifier checked the token.
	VerifierChecked bool   `json:"token_verifier_checked"`
	VerifierError   string `json:"token_verifier_error,omitempty"`
	ChainTrusted    *bool  `json:"chain_trusted,omitempty"`
	ChainNote       string `json:"chain_note,omitempty"`
	TokenTSAName    string `json:"token_tsa_name,omitempty"` // signer subject according to the verifier
	// ProofOfTime: the token is valid for the anchored head record in this bundle AND its TSA
	// certificate chain is trusted (ProofBasis "token_verifier": the verifier's ChainOK at
	// export; "issue_time_flags": the record's verified && chain_ok). ProofNote says why not.
	ProofOfTime bool   `json:"proof_of_time"`
	ProofBasis  string `json:"proof_basis,omitempty"`
	ProofNote   string `json:"proof_note,omitempty"`
}

type custodyEntry struct {
	Seq      *uint64 `json:"seq,omitempty"` // nil for computed entries (gaps)
	TS       string  `json:"ts"`
	Type     string  `json:"type"` // ledger record type, or "gap" (computed)
	Summary  string  `json:"summary"`
	InPeriod bool    `json:"in_period"`
}

type bootstrapEntry struct {
	Seq       uint64                `json:"seq"`
	TS        string                `json:"ts"`
	SourceDir string                `json:"source_dir"`
	Files     []model.BootstrapFile `json:"files"`
	Notes     string                `json:"notes"`
}

// headPrefix returns the first 8 hex digits of the bundle head hash (for the file name).
func (r *report) headPrefix() string {
	if r.Ledger.Head != nil && len(r.Ledger.Head.Hash) >= 8 && isHexPrefix(r.Ledger.Head.Hash[:8]) {
		return r.Ledger.Head.Hash[:8]
	}
	return "00000000"
}

func isHexPrefix(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
