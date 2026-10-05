package ticket

import (
	"context"
	"errors"
	"fmt"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// Customer identifies the AT&T customer on the printed ticket. Blank fields are printed as
// lines to fill in by hand.
type Customer struct {
	Name, Account, Address, Phone, BestTime, Notes string
}

// Options configure Build.
type Options struct {
	// From and To delimit the window [From, To). Zero To = Now(); zero From = To - 24 h.
	From, To time.Time
	Customer Customer
	// BundleName and BundleSHA256 identify the exported evidence bundle the report summarises
	// (shown in the evidence section; "" = not stated).
	BundleName, BundleSHA256 string
	// Verification is the one-line result of verifying that bundle ("" = not verified).
	Verification string
	// Location is the local zone times are shown in next to UTC (nil = time.Local).
	Location *time.Location
	// Now returns the generation time (nil = time.Now).
	Now func() time.Time
	// Generator names the software that produced the report, e.g. "att-monitor 1.0.0".
	Generator string
}

// MaxWindow bounds the window a ticket can summarise.
const MaxWindow = 31 * 24 * time.Hour

// Report is the content of a service ticket, computed from ledger records by Build and
// rendered by HTML. All figures are derived from records; the texts quote them.
type Report struct {
	Title     string
	From, To  time.Time
	Generated time.Time
	Generator string
	Customer  Customer

	// Summary holds the four "Summary for AT&T" bullets in a fixed order, keyed "optical",
	// "link", "outages", "home".
	Summary []Bullet
	// Action is the "Requested action" paragraph.
	Action Bullet

	Coverage  Coverage
	Gateway   GatewayInfo
	Optical   Optical
	Link      Link
	Events    []EventRow
	Incidents []IncidentRow
	Avail     Availability
	Home      Home
	Evidence  Evidence
	// Notes lists data caveats (records that could not be decoded, truncated lists).
	Notes []string

	// EventsOther counts the gateway events of the window not listed in Events (housekeeping:
	// certificate pinning, the daily notification-setting confirmation).
	EventsOther int
	// IncidentsUnlisted names incidents the window's samples refer to whose records are all
	// outside the window.
	IncidentsUnlisted []string

	loc *time.Location
}

// Bullet is one statement of the report: a bold lead-in and its factual body.
type Bullet struct {
	Key  string
	Lead string
	Text string
}

// String returns the bullet as one sentence run.
func (b Bullet) String() string { return b.Lead + " " + b.Text }

// Location returns the zone the report shows local times in.
func (r *Report) Location() *time.Location { return r.loc }

// Bullet returns the summary bullet with the given key (zero Bullet if absent).
func (r *Report) Bullet(key string) Bullet {
	for _, b := range r.Summary {
		if b.Key == key {
			return b
		}
	}
	return Bullet{}
}

// Coverage describes how much of the window the monitor's measurement cycles covered.
type Coverage struct {
	Window         time.Duration
	FastInterval   time.Duration
	FastBasis      string
	Cycles         int
	MonitoredSec   int64
	FirstSample    time.Time
	LastSample     time.Time
	FirstSampleSeq uint64
	LastSampleSeq  uint64
	// Gaps are the stretches of the window without measurement cycles (longer than 3 cycle
	// intervals), in time order, including the stretch before the first and after the last
	// cycle.
	Gaps      []Gap
	Statement string
}

// Gap is a stretch of the window without measurement cycles.
type Gap struct {
	From, To time.Time
	Sec      int64
	Kind     string // "leading", "inner", "trailing", "whole"
	Why      string // every explanation the records give
	Brief    string // the main one
}

// GatewayInfo identifies the AT&T gateway and its state, from the latest gateway snapshot of
// the window (or, without one, from the setup-time capture).
type GatewayInfo struct {
	Known     bool
	Source    string
	SourceSeq uint64
	At        time.Time

	Manufacturer, Model, Serial, Firmware, Hardware string

	UptimeSec int64 // -1 = unknown
	BootTime  time.Time

	Broadband, NetworkType, PON, UNI string
	OpticalStatus, LinkState         string
	WANIPv4, NextHop, DNS            string
	RxX10, TxX10, TempC              *int64
	RxNoLight                        bool // Rx shown as 0 while the fiber link was down
	ModuleVendor, ModulePN, Wave     string
	RxLOS, OptLOS, TxFault           string
	LastChangeRaw                    string
}

// Reading is one optical receive-power reading of the gateway's fiber diagnostics.
type Reading struct {
	T     time.Time
	Seq   uint64 // the gateway_snapshot record; for the setup capture, the bootstrap_import record
	Setup bool   // the setup-time capture (a raw page imported with the bootstrap evidence)
	Path  string // setup capture: the imported file

	RxX10    int64
	TxX10    *int64
	Alarm    bool // the gateway's own OPTICAL_RX_LOW_ALARM flag
	Warn     bool // the gateway's own OPTICAL_RX_LOW_WARNING flag
	AlarmThr *int64
	WarnThr  *int64
	Codes    []string // every alarm/warning code the gateway raised in this reading
	// NoLight: the gateway showed Rx "0" while it reported its own fiber link down (Optical WAN
	// status not Up, or PON not in operation): that is no receive level, not a measurement of
	// 0.0 dBm, so the reading is kept (with its flags) but not used as a level.
	NoLight bool
}

// Source describes where a reading comes from: "snapshot #12" or "setup capture,
// bootstrap_import #1".
func (rd Reading) Source() string {
	if rd.Setup {
		return "setup capture, bootstrap_import " + seqRef(rd.Seq)
	}
	return "snapshot " + seqRef(rd.Seq)
}

// Optical aggregates the window's optical readings.
type Optical struct {
	Readings []Reading // in time order
	AlarmN   int
	WarnN    int
	Levels   int // readings with a receive level (not NoLight)
	NoLightN int
	MinI     int    // index of the lowest level reading (-1 none)
	MaxI     int    // index of the highest level reading (-1 none)
	LatestI  int    // index of the latest reading (-1 none)
	AlarmThr *int64 // the gateway's low-Rx alarm threshold (latest reading stating one)
	WarnThr  *int64
	// ThrVaried: the readings state more than one threshold value.
	ThrVaried bool
	// OtherCodes counts the gateway's other optical/module flags (not the Rx low ones).
	OtherCodes map[string]int
	Rows       []ReadingRow // the readings table (at most MaxTableRows)
	RowsNote   string
	Chart      *Chart
	// SetupOutside is the setup-time capture's reading when it lies outside the window.
	SetupOutside *Reading
	// AlarmRuns counts the runs of readings with a level in which the gateway's low-Rx ALARM
	// flag was set (a no-light reading neither ends nor continues a run).
	AlarmRuns int
	// Clear is the last clearing of the ALARM flag; nil when the flag was never set, or is
	// still set at the latest reading with a level.
	Clear *AlarmClear
	// Steps are the changes of the receive level of StepMinX10 or more between consecutive
	// readings with a level, in time order.
	Steps []Step
}

// StepMinX10 is the smallest change of the receive level between two consecutive readings that
// the report states as a step change: 3.0 dB, half or double the received power.
const StepMinX10 = 30

// Step is a change of the receive level of at least StepMinX10 between two consecutive readings
// with a level.
type Step struct {
	From, To Reading
	// NoLight lists the readings between them in which the gateway showed no receive level while
	// it reported its own fiber link down: the step happened across a loss of light.
	NoLight []uint64
}

// DeltaX10 is the change of the level, in tenths of a dB.
func (s Step) DeltaX10() int64 { return s.To.RxX10 - s.From.RxX10 }

// AlarmClear is the clearing of the gateway's low-Rx ALARM flag at the end of a run of readings
// with the flag set.
type AlarmClear struct {
	// SetFrom is the first reading of the run with a level; LastSet the last one.
	SetFrom, LastSet Reading
	// Cleared is the first reading with a level after LastSet, without the flag.
	Cleared Reading
	// EventSeq is the gateway_event optical_alarm that reported the clearing (0: none in the
	// window).
	EventSeq uint64
}

// MaxTableRows bounds the readings table; MaxChartTableRows bounds it when the chart shows the
// readings (the table then lists the readings that matter: see pickRows).
const (
	MaxTableRows      = 30
	MaxChartTableRows = 15
)

// ReadingRow is a row of the readings table with the reasons it was kept.
type ReadingRow struct {
	Reading
	Why string
}

// LinkChange is one fiber link state change revealed by the gateway's fiberstat "Last
// Change" value.
type LinkChange struct {
	Value    int64
	Prev     string // the value before (events), "" for the first observation
	Source   string
	Seq      uint64
	Observed time.Time // when the value was first seen
	// PrevObserved is when the value before it was last seen (zero for the first observation).
	PrevObserved time.Time
	Event        bool // from a gateway_event optical_link_change
	Evidence     []uint64

	Plausible bool // the value reads as a time between 2000 and the observation
	AsUTC     time.Time
	// AsLocal is the value read as the gateway's local wall-clock time, converted to UTC
	// (zero when the gateway's UTC offset is unknown).
	AsLocal       time.Time
	UTCPossible   bool
	LocalPossible bool
	InWindow      bool
	// Restart, when not empty, says that a gateway restart coincides with the change.
	Restart string
}

// Link holds the fiber link state and gateway restart findings of the window.
type Link struct {
	Observations int        // fiberstat Last Change observations in the window
	First        LinkChange // the first observation (Value 0 when none)
	Changes      []LinkChange
	Unchanged    int // later observations repeating the first value

	// Offset is the gateway clock's UTC offset (its local time minus UTC), from its own
	// Current Date/Time compared with the time the page was fetched.
	Offset    *time.Duration
	OffsetSrc string
	// Confirmed is "UTC" (or "local") when a change observed between two readings can only be
	// read that way, which shows how the gateway counts Last Change; ConfirmedBy names it.
	Confirmed   string
	ConfirmedBy string

	UptimeReadings int
	Boot           time.Time // boot time from the latest uptime reading
	BootSeq        uint64
	BootSrc        string
	UptimeSec      int64
	UptimeAt       time.Time
	Restarts       []Restart // restarts within the window
}

// Restart is a gateway restart found in the window.
type Restart struct {
	Boot   time.Time
	Seq    uint64
	Source string
}

// EventRow is a gateway_event of the window.
type EventRow struct {
	T        time.Time
	Seq      uint64
	Kind     string
	Label    string
	Change   string
	Detail   string
	Evidence []uint64
}

// IncidentRow is the latest record of an incident in the window.
type IncidentRow struct {
	model.Incident
	RecSeq        uint64
	RecType       string
	RecTS         time.Time
	OpenedT       time.Time
	ClosedT       time.Time // zero while open
	DurationSec   int64
	StartedBefore bool // opened before the window
	OpenAtEnd     bool // no close record in the window
}

// Availability counts the window's measurement cycles by state.
type Availability struct {
	Cycles     int
	ByState    map[string]int
	Classified int // cycles that are not UNKNOWN
	Online     int
	Pct        string // ONLINE / classified, truncated
	Blips      int    // runs of bad cycles outside incidents
	BlipCycles int
	BlipSec    int64
	// BlipOutageSec is the time of the blips' ISP_OUTAGE cycles (no Internet at all).
	BlipOutageSec int64
}

// Home describes the home network side: this computer's path to the gateway and its link.
type Home struct {
	Cycles     int
	GwProbes   int // gateway ICMP probes
	GwOK       int
	GwMedianUs int64
	LANUp      int // cycles in which the gateway answered (ICMP, TCP, or TCP refused)
	LANDown    int
	LANKnown   int

	Links        int
	Latest       *model.LocalLink
	LatestSeq    uint64
	SignalMin    int
	SignalMax    int
	Disconnected int
	EgressChecks int
	EgressBypass int
	BypassSeq    uint64
	LatencyOKMs  float64
	Healthy      bool
}

// Evidence describes the evidence behind the report and how to verify it.
type Evidence struct {
	BundleName, BundleSHA256, Verification string

	HasGenesis    bool
	GenesisSeq    uint64
	GenesisTS     time.Time
	Fingerprint   string
	FingerprintOK bool // SHA-256 of the genesis public key equals the stated fingerprint
	Host          string
	Software      string

	WindowRecords  int
	WindowFirstSeq uint64
	WindowLastSeq  uint64

	// Anchor is the latest trusted time-stamp covering records of the window (nil = none yet).
	Anchor           *AnchorInfo
	AnchorsSeen      int
	AnchorsUntrusted int

	Setup *Setup
	Facts []Fact
}

// AnchorInfo is an RFC 3161 anchor record.
type AnchorInfo struct {
	Seq      uint64
	TS       time.Time
	TSA      string
	GenTime  time.Time
	HeadSeq  uint64
	HeadHash string
	Token    string
	Reason   string
	// Covered and Uncovered count the window's records up to / after HeadSeq.
	Covered   int
	Uncovered int
}

// Setup is the setup-time capture imported with the bootstrap evidence.
type Setup struct {
	Seq        uint64
	TS         time.Time
	SourceDir  string
	Files      int
	Pages      []SetupPage
	Fiber      *SetupPage
	Rx         *Reading // the capture's optical reading
	LastChange int64
	// Change is LastChange read both ways (UTC, or the gateway's local time per the capture's
	// own clock), as of the capture.
	Change    LinkChange
	UptimeSec int64 // -1 unknown
	Boot      time.Time
	ClockRaw  string
	Offset    *time.Duration
	Tokens    []SetupToken
	Anchor    *AnchorInfo // ledger anchor covering the bootstrap_import record
	InWindow  bool        // the fiberstat capture time lies in the window
	Problems  []string

	// The pages as parsed by the gateway package.
	sys     *model.SystemInfo
	bb      *model.BroadbandStatus
	fiber   *model.FiberStatus
	derived model.GatewayDerived
}

// SetupPage is a gateway page of the setup-time capture.
type SetupPage struct {
	Page   string // "fiberstat", "sysinfo", "broadbandstatistics"
	Path   string
	SHA256 string
	Time   time.Time // file time recorded at import
	OK     bool      // blob present and matching its SHA-256
	// ListedIn names the time-stamped files (manifests) whose text lists this page's SHA-256.
	ListedIn []string
}

// SetupToken is a setup-time RFC 3161 token (what it states; not verified here).
type SetupToken struct {
	Path    string
	SHA256  string
	TSA     string
	GenTime time.Time
	Imprint string
	Covers  string // the imported file whose SHA-256 is the token's imprint ("" = none)
	Granted bool
	Err     string
}

// Fact links a key statement to the record(s) behind it.
type Fact struct {
	What string
	Ref  string
}

// Build reads the records of the window [o.From, o.To) - plus the genesis and bootstrap_import
// records and the anchors that time-stamp the window - and computes the report.
func Build(ctx context.Context, r contracts.LedgerReader, o Options) (*Report, error) {
	if r == nil {
		return nil, errors.New("ticket: no ledger reader")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	loc := o.Location
	if loc == nil {
		loc = time.Local
	}
	gen := now()
	to := o.To
	if to.IsZero() {
		to = gen
	}
	from := o.From
	if from.IsZero() {
		from = to.Add(-24 * time.Hour)
	}
	if !from.Before(to) {
		return nil, fmt.Errorf("ticket: window start %s is not before its end %s", from.UTC().Format(time.RFC3339), to.UTC().Format(time.RFC3339))
	}
	if to.Sub(from) > MaxWindow {
		return nil, fmt.Errorf("ticket: window of %s is longer than %s", to.Sub(from), MaxWindow)
	}

	c := newCollector(ctx, r, from.UTC(), to.UTC(), loc)
	for _, scan := range []func() error{c.scanStart, c.scanWindow, c.scanAfter} {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := scan(); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	rep := &Report{
		From:      from.UTC(),
		To:        to.UTC(),
		Generated: gen,
		Generator: o.Generator,
		Customer:  o.Customer,
		loc:       loc,
	}
	rep.Title = "AT&T Fiber service problem evidence: " + windowPhrase(rep.To.Sub(rep.From)) + " to " + fmtTitleTime(rep.To, loc)
	c.analyze(rep, o)
	rep.buildSummary()
	rep.Notes = append(rep.Notes, c.notes...)
	if c.notesDropped > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d further data notes are not listed.", c.notesDropped))
	}
	return rep, nil
}

// windowPhrase names the window's length in the title: "24 hours", "1 hour", "5.5 hours",
// "42 minutes". The title states the window's end, so it never depends on when it is read.
func windowPhrase(d time.Duration) string {
	sec := int64(d / time.Second)
	switch {
	case sec == 3600:
		return "1 hour"
	case sec%3600 == 0:
		return fmt.Sprintf("%d hours", sec/3600)
	case sec < 60:
		return "less than a minute"
	case sec < 3600:
		return plural(int(sec/60), "minute", "minutes")
	}
	tenths := sec * 10 / 3600
	return fmt.Sprintf("%d.%d hours", tenths/10, tenths%10)
}

// fmtTitleTime renders the window's end for the title, to the minute: "2026-10-05 09:00 CDT"
// (the window line under the title gives the exact times).
func fmtTitleTime(t time.Time, loc *time.Location) string {
	return t.In(loc).Format(layoutMin) + " " + zoneName(loc, t)
}
