package export

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"strings"
	"time"

	"attmonitor/internal/model"
)

// aggregator accumulates what the report needs while records stream by. Records in the
// period are those whose ts (for samples: the cycle start) lies in [from, end); custody
// records, incidents and anchors are taken from the whole bundle.
type aggregator struct {
	samples    []sampleLite // samples of the period, in ledger order
	preSamples []sampleLite // samples of the bundle before the period (restart windows, incidents in progress)
	last       lastSample   // the latest sample record seen (ledger order), kept or not
	probes     map[string]*probeStat
	probeOrder []string
	probeBits  map[string]uint8 // probe name -> bit of sampleLite.probes/okProbes (at most 64 names)
	probeNames []string         // by bit
	strs       map[string]string
	incIDs     []string         // incident ids carried by samples (sampleLite.inc - 1)
	incIdx     map[string]int32 // incident id -> index into incIDs
	rules      map[string]bool

	// rules versions: samples of the period and incident records per version
	rulesSamples   map[string]int
	rulesIncidents map[string]int
	samplesInputs  int // samples of the period whose verdict names its inputs
	providers      map[string]bool

	runIdx  map[string]int32 // run id -> index
	configs []cfgRec         // configuration records (monitor_start, config_state), ledger order
	lead    periodLead       // the period's records up to its first configuration record

	boots     []bootObs            // gateway boot times named by records
	fwChanges []fwChange           // gateway firmware_change events
	snapBoot  map[uint64]time.Time // gateway_snapshot seq -> estimated boot time

	incidents map[string]*incAcc
	incOrder  []string
	tags      map[string]int // incident id -> samples in the period carrying it
	tagOrder  []string

	snapTimes    []int64
	optPoints    []optPoint
	optSnapshots int
	// Every gateway snapshot and every hijack observation of the bundle, whatever its time: the
	// facts of an incident are compared with what was observed before it opened.
	snaps       []snapFact
	fibers      []fiberObs
	hijacks     []hijackObs
	gw          gatewayStatus
	ponCounts   *counter
	optCounts   *counter
	wanIPs      []string
	identities  []*gatewayIdentity
	preIdentity *gatewayIdentity
	latestFiber *latestFiber
	gwOffsetMax *int64

	events []gatewayEventEntry

	service  serviceSummary
	dns      map[string]*dnsStat
	dnsOrder []string
	http     map[string]*httpStat
	httpOrd  []string

	link      localLinkSummary
	linkTypes *counter
	signals   []int

	clock   clockSummary
	servers map[string]bool
	invalid map[string]*invalidNameStat
	invOrd  []string

	// Clock facts per process (run): the clock_jump record that measured a step of this
	// computer's clock between the previous process and this one (between_runs), the ledger
	// writer's integrity_alert that found the clock behind the newest record when this process
	// opened the ledger, and the custody entry of this process's monitor_start record.
	runStep      map[int32]runClockStep
	runBehind    map[int32]uint64
	startCustody map[int32]int

	anchors   []anchorEntry
	custody   []custodyEntry
	marks     []mark
	bootstrap []bootstrapEntry
	software  []softwareSeen
	host      *hostInfo

	heartbeats, traceroutes, stateChanges int
	lastInWindow                          *recordRef
}

type sampleLite struct {
	t    int64 // cycle start (wall clock), unix ns
	rec  int64 // when its record was written (record ts, wall clock), unix ns; 0 = unknown
	next int64 // nextSameRun: time from this cycle's start to the next cycle's start (see nextKind)
	seq  uint64
	// Probes of the cycle (bits of aggregator.probeBits) and those that succeeded.
	probes, okProbes uint64
	state            string
	attr             string // verdict attribution
	run              int32  // index of the process (run) that wrote the sample
	inc              int32  // 1 + index into aggregator.incIDs of the incident id it carries; 0 = none
	lan              int8   // 1: the gateway answered a probe (LAN), 0: it did not, -1: no gateway probe
	inet             bool   // at least one internet probe succeeded (INET_ANY)
	incident         bool   // the sample carries an incident id
	linkDown         bool   // verdict cause LOCAL_LINK_DOWN (this computer's own link was down)
	localRoute       bool   // verdict cause LOCAL_ROUTE (its probes did not leave through the gateway)
	// interrupted: the monitor recorded the cycle as UNKNOWN because it was cut short by an
	// interruption (system sleep) while its probes were in flight (rules 2026.10-4): like a
	// monitoring gap, that closes an open incident at the end of its last bad cycle's coverage.
	interrupted bool
	nextKind    uint8 // what follows the cycle in the ledger: next* constants
}

// What follows a cycle in the ledger, which decides the time it covers (timeacct.go).
const (
	nextUnknown  uint8 = iota // nothing in the bundle: the cycle covers until the end of the period (capped)
	nextSameRun               // the next cycle of the same process; sampleLite.next is the time between their starts
	nextRunEnded              // its process ended (monitor_stop, or a record of another process followed)
)

// clockStepTolerance: two consecutive records whose wall-clock and monotonic distances differ
// by more than this were separated by a step of the wall clock (internal/monitor records a
// clock_jump beyond the same threshold).
const clockStepTolerance = 2 * time.Second

// lastSample is the latest sample record seen while streaming (whether kept or not): the next
// sample, or the end of its process, settles what follows it.
type lastSample struct {
	ok     bool  // a sample with a usable cycle start
	kept   bool  // it is stored in samples (pre=false) or preSamples (pre=true) at idx
	pre    bool  //
	idx    int   //
	run    int32 //
	t, rec int64 // cycle start and record time (wall clock, unix ns)
	mono   int64 // record mono
	recOK  bool  // rec is usable
	monoOK bool  // mono is usable
}

// snapFact is what an incident's figures need from one gateway snapshot record.
type snapFact struct {
	seq              uint64
	t                int64 // record ts, unix ns (0 = unknown)
	run              int32
	bbDown, ponDown  bool // the gateway reported Broadband Connection: Down / its PON link not operational
	alarm            bool // the gateway reported an alarm flag
	gatewayReachable bool
}

// fiberObs is one reading of the gateway's fiber module diagnostics (any time in the bundle).
type fiberObs struct {
	t      time.Time
	seq    uint64
	alarms []string
}

// hijackObs is a service check that observed DNS or HTTP redirection.
type hijackObs struct {
	t                   time.Time
	seq                 uint64
	run                 int32
	dnsReal, dnsInvalid bool // a DNS answer for a real name / for a reserved .invalid name was redirected
	http                bool
}

// intern returns a canonical copy of s: the samples of a long period repeat a handful of
// state and attribution strings, which need not be stored once per sample.
func (a *aggregator) intern(s string) string {
	if v, ok := a.strs[s]; ok {
		return v
	}
	if len(a.strs) < 1024 {
		a.strs[s] = s
	}
	return s
}

// probeBit returns the bit of a probe name in sampleLite.probes (ok=false beyond 64 names).
func (a *aggregator) probeBit(name string) (uint8, bool) {
	if b, ok := a.probeBits[name]; ok {
		return b, true
	}
	if len(a.probeNames) >= 64 {
		return 0, false
	}
	b := uint8(len(a.probeNames))
	a.probeBits[name] = b
	a.probeNames = append(a.probeNames, name)
	return b, true
}

// incidentIndex interns an incident id carried by samples (1-based; 0 = none).
func (a *aggregator) incidentIndex(id string) int32 {
	if id == "" {
		return 0
	}
	if i, ok := a.incIdx[id]; ok {
		return i + 1
	}
	i := int32(len(a.incIDs))
	a.incIDs = append(a.incIDs, id)
	a.incIdx[id] = i
	return i + 1
}

// lastKept returns the kept sample a.last refers to, or nil.
func (a *aggregator) lastKept() *sampleLite {
	l := &a.last
	if !l.ok || !l.kept {
		return nil
	}
	if l.pre {
		return &a.preSamples[l.idx]
	}
	return &a.samples[l.idx]
}

// linkSample settles what follows the previous sample now that the next sample record (of
// process run, started at t, written at rec with mono) has arrived. The time between two
// cycles of one process is their wall-clock distance, unless the wall clock was stepped
// between their records: then it is corrected by the step, measured from the records' wall
// and monotonic times (written at the same instant), so a clock set back or forward neither
// shrinks nor stretches the cycles (docs/DESIGN.md §6: mono orders and times records immune
// to wall-clock changes).
func (a *aggregator) linkSample(run int32, t, rec, mono int64, recOK, monoOK bool) {
	x := a.lastKept()
	if x == nil || x.nextKind != nextUnknown {
		return
	}
	p := &a.last
	if run != p.run {
		x.nextKind = nextRunEnded
		return
	}
	d := t - p.t
	if recOK && p.recOK && monoOK && p.monoOK {
		if step := (rec - p.rec) - (mono - p.mono); step > int64(clockStepTolerance) || step < -int64(clockStepTolerance) {
			d -= step
		}
	}
	x.next, x.nextKind = d, nextSameRun
}

// noteRecord settles what follows the previous sample when a record other than a sample
// arrives: the end of its process (its monitor_stop, or any record of another process).
func (a *aggregator) noteRecord(run int32, typ string) {
	x := a.lastKept()
	if x == nil || x.nextKind != nextUnknown {
		return
	}
	if run != a.last.run || typ == model.TypeMonitorStop {
		x.nextKind = nextRunEnded
	}
}

type incAcc struct {
	latest    model.Incident
	latestSeq uint64
	latestTS  string
	openSeq   uint64
	haveOpen  bool
	closeSeq  uint64
	haveClose bool
	records   []uint64
	// which time figures the latest record contains (older rules versions lack some)
	hasDowntime, hasDegraded, hasRestart bool
}

// bootObs is a gateway boot time named by a record (a reboot event or an incident's
// gateway_restarts list).
type bootObs struct {
	t        time.Time
	seq      uint64
	source   string
	evidence []uint64
	event    bool // from a gateway_event reboot record
}

type fwChange struct {
	t             time.Time
	seq           uint64
	before, after string
	evidence      []uint64
}

type optPoint struct {
	t        time.Time
	seq      uint64
	rx, tx   *int64
	alarmThr *int64
	warnThr  *int64
	alarms   []string
}

type latestFiber struct {
	seq      uint64
	ts       string
	measures []model.DMIMeasure
	pageSHA  string
	stored   bool
}

// mark is a record that can explain a monitoring gap.
type mark struct {
	t     time.Time
	seq   uint64
	typ   string
	text  string
	clean bool  // monitor_start: previous run stopped cleanly
	run   int32 // the process that wrote it
}

// runClockStep is a step of this computer's clock between two processes of the monitor, as a
// clock_jump record with between_runs measured it against the time servers.
type runClockStep struct {
	seq    uint64
	jumpMs int64
}

// clockJumpRecord is the payload of a clock_jump record: model.ClockJump, and for a step found
// between two runs of the monitor (rules 2026.10-4) the clock checks it was measured from.
type clockJumpRecord struct {
	model.ClockJump
	BetweenRuns  bool   `json:"between_runs"`
	PrevCheckSeq uint64 `json:"prev_clock_check_seq"`
	CheckSeq     uint64 `json:"clock_check_seq"`
}

// clockBehindPrefix begins the detail of the integrity_alert the ledger writer appends when, on
// opening the ledger, this computer's clock is more than 5 minutes behind the newest record
// (internal/ledger; docs/DESIGN.md §6).
const clockBehindPrefix = "the computer's clock is behind the newest ledger record"

// counter counts string values, remembering first-seen order.
type counter struct {
	n     map[string]int
	order []string
}

func newCounter() *counter { return &counter{n: map[string]int{}} }

func (c *counter) add(v string) {
	if _, ok := c.n[v]; !ok {
		c.order = append(c.order, v)
	}
	c.n[v]++
}

func (c *counter) list() []valueCount {
	out := make([]valueCount, 0, len(c.order))
	for _, v := range c.order {
		out = append(out, valueCount{Value: v, Count: c.n[v]})
	}
	return out
}

func (a *aggregator) init() {
	a.probes = map[string]*probeStat{}
	a.probeBits = map[string]uint8{}
	a.strs = map[string]string{}
	a.incIdx = map[string]int32{}
	a.rules = map[string]bool{}
	a.rulesSamples, a.rulesIncidents = map[string]int{}, map[string]int{}
	a.providers = map[string]bool{}
	a.runIdx = map[string]int32{}
	a.lead.first = -1
	a.snapBoot = map[uint64]time.Time{}
	a.incidents = map[string]*incAcc{}
	a.tags = map[string]int{}
	a.ponCounts, a.optCounts, a.linkTypes = newCounter(), newCounter(), newCounter()
	a.dns = map[string]*dnsStat{}
	a.http = map[string]*httpStat{}
	a.servers = map[string]bool{}
	a.invalid = map[string]*invalidNameStat{}
	a.runStep, a.runBehind, a.startCustody = map[int32]runClockStep{}, map[int32]uint64{}, map[int32]int{}
}

// runIndex interns a run id (the per-process id every record carries).
func (a *aggregator) runIndex(id string) int32 {
	if i, ok := a.runIdx[id]; ok {
		return i
	}
	i := int32(len(a.runIdx))
	a.runIdx[id] = i
	return i
}

// preWindow is how far before the period a restart window may begin and still reach into it
// (a window ends at most restartWindowCap after the boot); segment selection reads this far back.
const preWindow = 30 * time.Minute

// gatewayAnswered: the gateway's IP stack answered this probe - it succeeded, or a TCP
// connection was refused (a reset is an answer). docs/DESIGN.md §9 "LAN".
func gatewayAnswered(p model.ProbeResult) bool {
	return p.OK || (p.Kind == model.KindTCP && strings.EqualFold(strings.TrimSpace(p.Status), "refused"))
}

// sampleFacts derives LAN and INET_ANY from a sample's probe results.
func sampleFacts(probes []model.ProbeResult) (lan int8, inet bool) {
	lan = -1
	for _, p := range probes {
		switch p.Role {
		case model.RoleGateway:
			if lan < 0 {
				lan = 0
			}
			if gatewayAnswered(p) {
				lan = 1
			}
		case model.RoleInet:
			inet = inet || p.OK
		}
	}
	return lan, inet
}

// interruptedVerdict reports the verdict the monitor records for a cycle cut short by an
// interruption (internal/monitor interruptedVerdict, rules 2026.10-4): UNKNOWN, with the reason
// that the cycle took longer than its probes may take because monitoring was interrupted.
func interruptedVerdict(v model.Verdict) bool {
	if v.State != model.StateUnknown || len(v.Reasons) == 0 {
		return false
	}
	r := v.Reasons[0]
	return strings.HasPrefix(r, "this cycle took ") && strings.Contains(r, "monitoring was interrupted")
}

// plausibleBoot rejects boot times the time accounting cannot represent (it works in Unix
// nanoseconds, defined for 1970..2261 like every period the exporter accepts).
func plausibleBoot(t time.Time) bool {
	return !t.Before(minPeriodTime) && t.Before(maxPeriodTime.Add(-restartWindowCap))
}

// plausibleTime: t can be handled in Unix nanoseconds like every period the exporter accepts.
func plausibleTime(t time.Time) bool {
	return !t.Before(minPeriodTime) && t.Before(maxPeriodTime)
}

// snapshotBootTime estimates when the gateway booted: the gateway snapshot's own estimate, or
// the sysinfo fetch time minus the reported uptime.
func snapshotBootTime(g *model.GatewaySnapshot) (time.Time, bool) {
	const maxUptime = 50 * 365 * 24 * 3600 // anything longer is not a real uptime (and would overflow)
	if g.System == nil || g.System.UptimeSec < 0 || g.System.UptimeSec > maxUptime {
		return time.Time{}, false
	}
	if t, ok := parseTS(g.Derived.BootTimeEstimate); ok {
		return t, true
	}
	if p := findPage(g.Pages, "sysinfo"); p != nil {
		if at, ok := parseTS(p.FetchedAt); ok {
			return at.Add(-time.Duration(g.System.UptimeSec) * time.Second), true
		}
	}
	return time.Time{}, false
}

func appendUnique(list []string, v string, max int) []string {
	if v == "" || len(list) >= max {
		return list
	}
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func (a *aggregator) addRules(v string) {
	if v != "" {
		a.rules[v] = true
	}
}

// decode unmarshals a record payload, noting records this report cannot interpret.
func (c *collector) decode(body model.Body, v any) bool {
	if err := json.Unmarshal(body.Data, v); err != nil {
		c.dataNote(body, err)
		return false
	}
	return true
}

// custodyRecord adds an entry to the custody log.
func (c *collector) custodyRecord(body model.Body, ts time.Time, tsOK bool, summary string) {
	c.agg.custody = append(c.agg.custody, custodyEntry{
		Seq: ptr(body.Seq), TS: body.TS, Type: body.Type, Summary: summary,
		InPeriod: tsOK && !ts.Before(c.from) && ts.Before(c.end),
	})
}

func (c *collector) addMark(ts time.Time, tsOK bool, body model.Body, text string, clean bool) {
	if tsOK {
		c.agg.marks = append(c.agg.marks, mark{t: ts, seq: body.Seq, typ: body.Type, text: text, clean: clean, run: c.agg.runIndex(body.Run)})
	}
}

// fmtSignedMs renders a signed number of milliseconds as a duration: "+4m 00s", "-45s", "+800 ms".
func fmtSignedMs(ms int64) string {
	sign := "+"
	if ms < 0 {
		sign = "-"
	}
	u := absU(ms)
	if u < 1000 {
		return fmt.Sprintf("%s%d ms", sign, u)
	}
	return sign + fmtDur(int64(u/1000+(u%1000)/500))
}

// monitorStartGap words the time since the previous record that a monitor_start record states
// (gap_seconds): negative means this computer's clock read an earlier time than that record's,
// so the clock was behind it.
func monitorStartGap(sec int64) string {
	if sec >= 0 {
		return "time since it: " + fmtDur(sec)
	}
	return fmt.Sprintf("this computer's clock read %s earlier than that record's time (gap_seconds %d: the clock was behind it)",
		fmtDur(int64(min(absU(sec), math.MaxInt64))), sec)
}

// aggregate routes one verified-or-not record to the report accumulators. Integrity problems
// are reported separately; the report still describes what the records say.
func (c *collector) aggregate(env model.Envelope, body model.Body, ts time.Time, tsOK bool) {
	a := &c.agg
	inWin := tsOK && !ts.Before(c.from) && ts.Before(c.end)
	if inWin {
		a.lastInWindow = &recordRef{Seq: body.Seq, Hash: env.H, TS: body.TS, Segment: c.cur.entry.Name}
		a.periodRecord(body.Run)
	}
	if body.Type != model.TypeSample {
		a.noteRecord(a.runIndex(body.Run), body.Type)
	}
	switch body.Type {
	case model.TypeGenesis:
		var g model.Genesis
		if !c.decode(body, &g) {
			return
		}
		c.custodyRecord(body, ts, tsOK, fmt.Sprintf(
			"Ledger created. Ed25519 signing key fingerprint %s. Host %s (%s %s). Software %s %s. Statement: %s",
			groupFingerprint(g.Fingerprint), g.Host.Hostname, g.Host.OS, g.Host.OSVersion, g.Software.Name, g.Software.Version, g.Statement))
		c.addMark(ts, tsOK, body, "ledger created", false)
		if a.host == nil {
			a.host = &hostInfo{HostInfo: g.Host, SourceType: body.Type, SourceSeq: body.Seq}
		}
	case model.TypeBootstrapImport:
		var b model.BootstrapImport
		if !c.decode(body, &b) {
			return
		}
		a.bootstrap = append(a.bootstrap, bootstrapEntry{Seq: body.Seq, TS: body.TS, SourceDir: b.SourceDir, Files: b.Files, Notes: b.Notes})
		c.custodyRecord(body, ts, tsOK, fmt.Sprintf(
			"Imported %s of evidence collected before the ledger existed, from %s. Each file's SHA-256, size and "+
				"modification time are recorded and the files are stored as blobs (see the bootstrap section).",
			plural(len(b.Files), "file", "files"), orNone(b.SourceDir)))
	case model.TypeMonitorStart:
		var m model.MonitorStart
		if err := json.Unmarshal(body.Data, &m); err != nil {
			c.dataNote(body, err)
			c.addConfigRecord(body, ts, tsOK, inWin, "", nil, err)
			return
		}
		clean := "no"
		if m.PrevStopped {
			clean = "yes"
		}
		summary := fmt.Sprintf(
			"Monitor started (%s mode), %s %s, executable SHA-256 %s, rules %s, configuration hash %s. Previous record seq %d at %s; "+
				"%s; previous run stopped cleanly: %s.",
			orNone(m.Mode), m.Software.Name, m.Software.Version, orNone(short(m.Software.ExeSHA256)), orNone(m.Software.Rules),
			orNone(short(m.ConfigSHA256)), m.PrevHead.Seq, orNone(m.PrevHead.TS), monitorStartGap(m.GapSeconds), clean)
		run := a.runIndex(body.Run)
		if seq, ok := a.runBehind[run]; ok {
			// The ledger writer of this process found the clock behind when it opened the ledger.
			summary += fmt.Sprintf(" When this process opened the ledger, the ledger writer recorded that this computer's clock was "+
				"behind the newest ledger record (integrity_alert seq %d).", seq)
		}
		c.custodyRecord(body, ts, tsOK, summary)
		if _, ok := a.startCustody[run]; !ok {
			a.startCustody[run] = len(a.custody) - 1
		}
		c.addMark(ts, tsOK, body, "monitor started", m.PrevStopped)
		if tsOK && ts.Before(c.end) {
			a.host = &hostInfo{HostInfo: m.Host, SourceType: body.Type, SourceSeq: body.Seq}
		}
		a.addSoftware(m.Software, body)
		a.addRules(m.Software.Rules)
		c.addConfigRecord(body, ts, tsOK, inWin, m.ConfigSHA256, m.Config, nil)
	case model.TypeConfigState:
		// The effective configuration restated at the start of a daily segment: it states the
		// thresholds in force from records the bundle contains (see resolveThresholds).
		var cs model.ConfigState
		if err := json.Unmarshal(body.Data, &cs); err != nil {
			c.dataNote(body, err)
			c.addConfigRecord(body, ts, tsOK, inWin, "", nil, err)
			return
		}
		a.addRules(cs.Rules)
		c.addConfigRecord(body, ts, tsOK, inWin, cs.ConfigSHA256, cs.Config, nil)
	case model.TypeMonitorStop:
		var m model.MonitorStop
		if !c.decode(body, &m) {
			return
		}
		c.custodyRecord(body, ts, tsOK, fmt.Sprintf("Monitor stopped: %s (uptime %s).", m.Reason, fmtDur(m.UptimeSec)))
		c.addMark(ts, tsOK, body, "monitor stopped ("+m.Reason+")", false)
	case model.TypePowerEvent:
		var pe model.PowerEvent
		if !c.decode(body, &pe) {
			return
		}
		c.custodyRecord(body, ts, tsOK, "Windows power event: "+pe.Kind+".")
		c.addMark(ts, tsOK, body, "power event "+pe.Kind, false)
	case model.TypeConfigChange:
		var cc model.ConfigChange
		if !c.decode(body, &cc) {
			return
		}
		c.custodyRecord(body, ts, tsOK, fmt.Sprintf("Configuration change (%s): %s changed from %q to %q by %s; result: %s.",
			cc.Target, cc.What, cc.Before, cc.After, cc.Actor, cc.Result))
	case model.TypeOperatorNote:
		var n model.OperatorNote
		if !c.decode(body, &n) {
			return
		}
		author := n.Author
		if author == "" {
			author = "(no author given)"
		}
		c.custodyRecord(body, ts, tsOK, fmt.Sprintf("Operator note by %s (via %s): %s", author, n.Source, n.Text))
	case model.TypeCustodyExport:
		var ce model.CustodyExport
		if !c.decode(body, &ce) {
			return
		}
		inc := ""
		if ce.IncidentID != "" {
			inc = ", incident " + ce.IncidentID
		}
		c.custodyRecord(body, ts, tsOK, fmt.Sprintf(
			"Evidence bundle %s exported (period %s to %s%s): bundle SHA-256 %s, manifest SHA-256 %s, %s, %s; prepared by %s; requested via %s.",
			ce.FileName, ce.From, ce.To, inc, orNone(ce.BundleSHA256), orNone(ce.ManifestSHA256), plural(ce.Records, "record", "records"),
			plural(ce.Blobs, "blob", "blobs"), orNone(ce.PreparedBy), orNone(ce.Requester)))
	case model.TypeRecovery:
		var rc model.Recovery
		if !c.decode(body, &rc) {
			return
		}
		c.custodyRecord(body, ts, tsOK, fmt.Sprintf(
			"Crash recovery: %d damaged trailing bytes at offset %d of %s were removed from the active segment and preserved as %s (SHA-256 %s). Reason: %s.",
			rc.RemovedBytes, rc.Offset, rc.Segment, rc.QuarantineAs, rc.RemovedSHA256, rc.Reason))
		c.addMark(ts, tsOK, body, "crash recovery", false)
	case model.TypeIntegrityAlert:
		var ia model.IntegrityAlert
		if !c.decode(body, &ia) {
			return
		}
		c.custodyRecord(body, ts, tsOK, fmt.Sprintf("Integrity alert raised by the monitor: %s. %s", ia.Problem, strings.Join(ia.Details, "; ")))
		for _, d := range ia.Details {
			if strings.HasPrefix(d, clockBehindPrefix) {
				if run := a.runIndex(body.Run); a.runBehind[run] == 0 {
					a.runBehind[run] = body.Seq
				}
				break
			}
		}
	case model.TypeClockJump:
		var cj clockJumpRecord
		if !c.decode(body, &cj) {
			return
		}
		if !cj.BetweenRuns {
			c.custodyRecord(body, ts, tsOK, fmt.Sprintf(
				"Wall clock jumped by %+d ms relative to the monotonic clock (wall %+d ms vs monotonic %+d ms between cycles).",
				cj.JumpMs, cj.WallDeltaMs, cj.MonoDeltaMs))
		} else {
			// Measured against the time servers across a restart of the monitor (rules 2026.10-4):
			// times recorded across it include the step.
			c.custodyRecord(body, ts, tsOK, fmt.Sprintf(
				"Between the previous run's last clock check (seq %d) and this run's first (seq %d), this computer's clock moved %s "+
					"against the time servers (it was stepped while the monitor was not running): times recorded across the restart - "+
					"the time since the previous record that monitor_start states, a monitoring gap - include that step.",
				cj.PrevCheckSeq, cj.CheckSeq, fmtSignedMs(cj.JumpMs)))
			run := a.runIndex(body.Run)
			if _, ok := a.runStep[run]; !ok {
				a.runStep[run] = runClockStep{seq: body.Seq, jumpMs: cj.JumpMs}
				if i, ok := a.startCustody[run]; ok {
					a.custody[i].Summary += fmt.Sprintf(" Between the runs this computer's clock moved %s against the time servers "+
						"(clock_jump seq %d), so the time since the previous record, as this computer's clock measured it, includes that step.",
						fmtSignedMs(cj.JumpMs), body.Seq)
				}
			}
		}
		if inWin {
			a.clock.ClockJumps++
		}
	case model.TypeSample:
		var s model.Sample
		run := a.runIndex(body.Run)
		if !c.decode(body, &s) {
			a.last = lastSample{} // what follows the previous sample is unknown
			return
		}
		t, ok := parseTS(s.Started)
		if !ok {
			t, ok = ts, tsOK
		}
		if !ok || !plausibleTime(t) {
			a.last = lastSample{}
			return
		}
		recOK := tsOK && plausibleTime(ts)
		var rec int64
		if recOK {
			rec = ts.UnixNano()
		}
		a.linkSample(run, t.UnixNano(), rec, body.Mono, recOK, body.Mono > 0)
		a.last = lastSample{ok: true, run: run, t: t.UnixNano(), rec: rec, mono: body.Mono, recOK: recOK, monoOK: body.Mono > 0}
		// Every sample of the bundle up to the end of the period is kept: those before it for the
		// restart windows that reach into it and for the incidents in progress when it starts.
		if !t.Before(c.end) {
			return
		}
		lan, inet := sampleFacts(s.Probes)
		sl := sampleLite{t: t.UnixNano(), rec: rec, seq: body.Seq, state: a.intern(s.Verdict.State), attr: a.intern(s.Verdict.Attribution),
			run: run, inc: a.incidentIndex(s.IncidentID), lan: lan, inet: inet, incident: s.IncidentID != "",
			linkDown: s.Verdict.Cause == model.CauseLocalLinkDown, localRoute: s.Verdict.Cause == model.CauseLocalRoute,
			interrupted: interruptedVerdict(s.Verdict)}
		for _, p := range s.Probes {
			if b, ok := a.probeBit(p.Name); ok {
				sl.probes |= 1 << b
				if p.OK {
					sl.okProbes |= 1 << b
				}
			}
		}
		if t.Before(c.from) {
			a.preSamples = append(a.preSamples, sl)
			a.last.kept, a.last.pre, a.last.idx = true, true, len(a.preSamples)-1
			return
		}
		a.samples = append(a.samples, sl)
		a.last.kept, a.last.idx = true, len(a.samples)-1
		if s.IncidentID != "" {
			if a.tags[s.IncidentID] == 0 {
				a.tagOrder = append(a.tagOrder, s.IncidentID)
			}
			a.tags[s.IncidentID]++
		}
		a.addRules(s.Verdict.Rules)
		a.rulesSamples[s.Verdict.Rules]++
		if s.Verdict.Inputs != nil {
			a.samplesInputs++
		}
		for _, p := range s.Probes {
			a.addProbe(p)
			if p.Role == model.RoleInet {
				h := p.Target
				if host, _, err := net.SplitHostPort(h); err == nil {
					h = host
				}
				if h != "" && len(a.providers) < 64 {
					a.providers[h] = true
				}
			}
		}
	case model.TypeStateChange:
		if inWin {
			a.stateChanges++
		}
	case model.TypeHeartbeat:
		if inWin {
			a.heartbeats++
		}
	case model.TypeTraceroute:
		if inWin {
			a.traceroutes++
		}
	case model.TypeIncidentOpen, model.TypeIncidentUpdate, model.TypeIncidentClose:
		var inc model.Incident
		if !c.decode(body, &inc) || inc.ID == "" {
			return
		}
		acc := a.incidents[inc.ID]
		if acc == nil {
			acc = &incAcc{}
			a.incidents[inc.ID] = acc
			a.incOrder = append(a.incOrder, inc.ID)
		}
		acc.latest, acc.latestSeq, acc.latestTS = inc, body.Seq, body.TS
		acc.records = append(acc.records, body.Seq)
		switch body.Type {
		case model.TypeIncidentOpen:
			if !acc.haveOpen {
				acc.openSeq, acc.haveOpen = body.Seq, true
			}
		case model.TypeIncidentClose:
			acc.closeSeq, acc.haveClose = body.Seq, true
		}
		// Which time figures the record contains: a field absent from a record of an older
		// rules version must be shown as "not recorded", not as zero.
		var pres struct {
			Stats map[string]json.RawMessage `json:"stats"`
		}
		_ = json.Unmarshal(body.Data, &pres)
		has := func(k string) bool { v, ok := pres.Stats[k]; return ok && string(v) != "null" }
		acc.hasDowntime, acc.hasDegraded, acc.hasRestart = has("downtime_s"), has("degraded_s"), has("restart_s")
		a.addRules(inc.Rules)
		a.rulesIncidents[inc.Rules]++
		for _, b := range inc.GatewayRestarts {
			if t, ok := parseTS(b); ok && plausibleBoot(t) {
				a.boots = append(a.boots, bootObs{t: t, seq: body.Seq,
					source: "gateway_restarts of incident " + truncate(inc.ID, 64)})
			}
		}
	case model.TypeGatewaySnapshot:
		var g model.GatewaySnapshot
		if !c.decode(body, &g) {
			return
		}
		c.addSnapshot(body, ts, tsOK, inWin, &g)
	case model.TypeGatewayEvent:
		var ev model.GatewayEvent
		if !c.decode(body, &ev) {
			return
		}
		c.restartEvent(body, ts, tsOK, &ev)
		if !inWin {
			return
		}
		a.events = append(a.events, gatewayEventEntry{Seq: body.Seq, TS: body.TS, Kind: ev.Kind, Before: ev.Before,
			After: ev.After, Detail: ev.Detail, Evidence: ev.Evidence})
	case model.TypeServiceCheck:
		var sc model.ServiceCheck
		if inWin {
			if !c.decode(body, &sc) {
				return
			}
		} else if json.Unmarshal(body.Data, &sc) != nil {
			return
		}
		if tsOK {
			a.addHijackObs(body, ts, &sc)
		}
		if inWin {
			a.addServiceCheck(body, &sc)
		}
	case model.TypeLocalLink:
		if !inWin {
			return
		}
		var ll model.LocalLink
		if !c.decode(body, &ll) {
			return
		}
		a.addLocalLink(body, &ll)
	case model.TypeClockCheck:
		if !inWin {
			return
		}
		var cc model.ClockCheck
		if !c.decode(body, &cc) {
			return
		}
		a.addClockCheck(&cc)
	case model.TypeAnchor:
		var an model.Anchor
		if !c.decode(body, &an) {
			return
		}
		a.anchors = append(a.anchors, anchorEntry{Seq: body.Seq, TS: body.TS, TSAURL: an.TSAURL, TSAName: an.TSAName,
			HeadSeq: an.HeadSeq, HeadHash: an.HeadHash, GenTime: an.GenTime, Token: an.TokenSHA256, Reason: an.Reason,
			Verified: an.Verified, ChainOK: an.ChainOK, ChainNoteRec: truncate(oneLine(an.ChainNote), 400)})
		// The token is evidence even if the writer did not list it in "blobs".
		if isHex64(an.TokenSHA256) {
			if _, ok := c.blobRefs[an.TokenSHA256]; !ok {
				c.blobRefs[an.TokenSHA256] = body.Seq
			}
		}
	}
}

func (a *aggregator) addProbe(p model.ProbeResult) {
	ps := a.probes[p.Name]
	if ps == nil {
		ps = &probeStat{Name: p.Name, Kind: p.Kind, Role: p.Role}
		a.probes[p.Name] = ps
		a.probeOrder = append(a.probeOrder, p.Name)
	}
	ps.Targets = appendUnique(ps.Targets, p.Target, 8)
	ps.Attempts++
	if p.OK {
		ps.OK++
		if p.RTTus > 0 {
			ps.rttSumUs += p.RTTus
			ps.rttN++
		}
	}
}

func (a *aggregator) addSoftware(s model.SoftwareInfo, body model.Body) {
	for _, x := range a.software {
		if x.Version == s.Version && x.Commit == s.Commit && x.ExeSHA256 == s.ExeSHA256 && x.Rules == s.Rules {
			return
		}
	}
	a.software = append(a.software, softwareSeen{Version: s.Version, Commit: s.Commit, ExeSHA256: s.ExeSHA256,
		Rules: s.Rules, FirstSeq: body.Seq, FirstTS: body.TS})
}

// snapshotIdentity extracts the gateway's identity (model, serial, firmware) from a snapshot.
func snapshotIdentity(g *model.GatewaySnapshot) *gatewayIdentity {
	id := &gatewayIdentity{Model: g.Derived.Model, Serial: g.Derived.Serial, Firmware: g.Derived.Firmware}
	if s := g.System; s != nil {
		id.Manufacturer, id.Hardware = s.Manufacturer, s.HardwareVersion
		if id.Model == "" {
			id.Model = s.Model
		}
		if id.Serial == "" {
			id.Serial = s.Serial
		}
		if id.Firmware == "" {
			id.Firmware = s.SoftwareVersion
		}
	}
	if id.Model == "" && id.Serial == "" && id.Firmware == "" && id.Manufacturer == "" {
		return nil
	}
	return id
}

func (a *aggregator) addIdentity(id *gatewayIdentity, body model.Body) {
	for _, x := range a.identities {
		if x.Manufacturer == id.Manufacturer && x.Model == id.Model && x.Serial == id.Serial &&
			x.Firmware == id.Firmware && x.Hardware == id.Hardware {
			x.LastSeen, x.LastSeq = body.TS, body.Seq
			x.Snapshots++
			return
		}
	}
	id.FirstSeen, id.LastSeen, id.FirstSeq, id.LastSeq, id.Snapshots = body.TS, body.TS, body.Seq, body.Seq, 1
	a.identities = append(a.identities, id)
}

// rxMeasure finds the "Rx Power" DMI measurement of a fiberstat page.
func rxMeasure(f *model.FiberStatus) *model.DMIMeasure {
	if f == nil {
		return nil
	}
	for i := range f.Measures {
		n := strings.ToLower(f.Measures[i].Name)
		if strings.Contains(n, "rx") && strings.Contains(n, "power") {
			return &f.Measures[i]
		}
	}
	return nil
}

func findPage(pages []model.PageCapture, name string) *model.PageCapture {
	for i := range pages {
		if pages[i].Page == name {
			return &pages[i]
		}
	}
	return nil
}

// restartEvent collects the gateway reboot and firmware-change events of the whole bundle: they
// define the gateway-restart windows (docs/DESIGN.md §10).
func (c *collector) restartEvent(body model.Body, ts time.Time, tsOK bool, ev *model.GatewayEvent) {
	a := &c.agg
	switch ev.Kind {
	case model.GwEvReboot:
		// The monitor records the new boot time in "after" when it knows it; otherwise the
		// boot time of the snapshot that showed the reboot (the last evidence seq) is used.
		b, ok := parseTS(ev.After)
		if !ok && len(ev.Evidence) > 0 {
			b, ok = a.snapBoot[ev.Evidence[len(ev.Evidence)-1]]
		}
		ok = ok && plausibleBoot(b)
		if !ok {
			c.notes = append(c.notes, fmt.Sprintf("gateway reboot event seq %d does not state when the gateway booted "+
				"and the snapshot it names is not in this bundle; no restart window is derived from it.", body.Seq))
			return
		}
		a.boots = append(a.boots, bootObs{t: b, seq: body.Seq, source: fmt.Sprintf("gateway_event reboot (seq %d)", body.Seq),
			evidence: append([]uint64(nil), ev.Evidence...), event: true})
	case model.GwEvFirmwareChange:
		if tsOK {
			a.fwChanges = append(a.fwChanges, fwChange{t: ts, seq: body.Seq, before: ev.Before, after: ev.After,
				evidence: append([]uint64(nil), ev.Evidence...)})
		}
	}
}

func (c *collector) addSnapshot(body model.Body, ts time.Time, tsOK, inWin bool, g *model.GatewaySnapshot) {
	a := &c.agg
	if b, ok := snapshotBootTime(g); ok {
		a.snapBoot[body.Seq] = b
	}
	d := g.Derived
	sf := snapFact{seq: body.Seq, run: a.runIndex(body.Run), bbDown: d.BroadbandUp != nil && !*d.BroadbandUp,
		ponDown: d.PONOperational != nil && !*d.PONOperational, alarm: len(d.Alarms) > 0, gatewayReachable: d.Reachable}
	if tsOK && plausibleTime(ts) {
		sf.t = ts.UnixNano()
	}
	a.snaps = append(a.snaps, sf)
	if fo, ok := fiberReading(body, ts, tsOK, g); ok {
		a.fibers = append(a.fibers, fo)
	}
	id := snapshotIdentity(g)
	if !inWin {
		if tsOK && ts.Before(c.from) && id != nil {
			id.FirstSeen, id.LastSeen, id.FirstSeq, id.LastSeq, id.Snapshots, id.BeforePeriod = body.TS, body.TS, body.Seq, body.Seq, 1, true
			a.preIdentity = id
		}
		return
	}
	a.snapTimes = append(a.snapTimes, ts.UnixNano())
	gs := &a.gw
	gs.Snapshots++
	if d.Reachable {
		gs.Reachable++
	}
	switch {
	case d.BroadbandUp == nil:
		gs.BroadbandUnknown++
	case *d.BroadbandUp:
		gs.BroadbandUp++
	default:
		gs.BroadbandDown++
	}
	if g.Broadband != nil && g.Broadband.PONLinkStatus != "" {
		a.ponCounts.add(g.Broadband.PONLinkStatus)
	}
	if g.Fiber != nil && g.Fiber.OpticalStatus != "" {
		a.optCounts.add(g.Fiber.OpticalStatus)
	}
	a.wanIPs = appendUnique(a.wanIPs, d.WANIPv4, 50)
	if d.GatewayClockBlank {
		gs.ClockBlank++
	}
	for _, pc := range g.Pages {
		if pc.NotAttempted {
			gs.PagesNotAttempted++
			continue
		}
		gs.PageFetches++
		if pc.Err != "" {
			gs.PageErrors++
		}
		if pc.Stored {
			gs.PagesStored++
		}
	}
	if id != nil {
		a.addIdentity(id, body)
	}
	if d.GatewayClockOffsetMs != nil {
		a.gwOffsetMax = maxAbs(a.gwOffsetMax, *d.GatewayClockOffsetMs)
	}
	// Optical data only when the gateway's DMI diagnostics were read: a failed fetch, or a
	// fiberstat page whose DMI tables could not be parsed, says nothing about the alarm flags
	// and must not look like "no alarm" (which would end an alarm period as "cleared").
	rx := rxMeasure(g.Fiber)
	if g.Fiber == nil || (rx == nil && d.RxPowerX10 == nil && len(d.Alarms) == 0) {
		return
	}
	a.optSnapshots++
	pt := optPoint{t: ts, seq: body.Seq, rx: d.RxPowerX10, tx: d.TxPowerX10, alarmThr: d.RxLowAlarmX10, warnThr: d.RxLowWarnX10,
		alarms: append([]string(nil), d.Alarms...)}
	if fp := findPage(g.Pages, "fiberstat"); fp != nil {
		if t, ok := parseTS(fp.FetchedAt); ok {
			pt.t = t
		}
	}
	if rx != nil {
		if pt.rx == nil {
			pt.rx = rx.Current
		}
		if pt.alarmThr == nil {
			pt.alarmThr = rx.LowAlarm.Threshold
		}
		if pt.warnThr == nil {
			pt.warnThr = rx.LowWarn.Threshold
		}
	}
	a.optPoints = append(a.optPoints, pt)
	if len(g.Fiber.Measures) > 0 {
		lf := &latestFiber{seq: body.Seq, ts: body.TS, measures: g.Fiber.Measures}
		if fp := findPage(g.Pages, "fiberstat"); fp != nil {
			lf.pageSHA, lf.stored = fp.SHA256, fp.Stored
		}
		a.latestFiber = lf
	}
}

// fiberReading returns the gateway's fiber module reading of a snapshot when its DMI
// diagnostics were read (see addSnapshot: a failed or unparsed fiberstat page says nothing
// about the alarm flags), timed by the fiberstat fetch.
func fiberReading(body model.Body, ts time.Time, tsOK bool, g *model.GatewaySnapshot) (fiberObs, bool) {
	d := g.Derived
	if g.Fiber == nil || (rxMeasure(g.Fiber) == nil && d.RxPowerX10 == nil && len(d.Alarms) == 0) {
		return fiberObs{}, false
	}
	t, ok := ts, tsOK
	if fp := findPage(g.Pages, "fiberstat"); fp != nil {
		if ft, fok := parseTS(fp.FetchedAt); fok {
			t, ok = ft, true
		}
	}
	if !ok {
		return fiberObs{}, false
	}
	return fiberObs{t: t, seq: body.Seq, alarms: uniqueSorted(d.Alarms)}, true
}

// isInvalidName: a name under the reserved .invalid top-level domain (RFC 6761), which must
// never resolve; the monitor queries a random one to detect NXDOMAIN redirection.
func isInvalidName(name string) bool {
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	return n == "invalid" || strings.HasSuffix(n, ".invalid")
}

// addHijackObs keeps the service checks (of any time) that observed redirection, telling an
// answer for a reserved .invalid name (NXDOMAIN redirection) from a redirected real name.
func (a *aggregator) addHijackObs(body model.Body, ts time.Time, sc *model.ServiceCheck) {
	h := hijackObs{t: ts, seq: body.Seq, run: a.runIndex(body.Run)}
	for _, d := range sc.DNS {
		if !d.Hijacked {
			continue
		}
		if isInvalidName(d.Name) {
			h.dnsInvalid = true
		} else {
			h.dnsReal = true
		}
	}
	for _, r := range sc.HTTP {
		h.http = h.http || r.Hijacked
	}
	if h.dnsReal || h.dnsInvalid || h.http {
		a.hijacks = append(a.hijacks, h)
	}
}

// rcodeOK accepts the spellings a DNS client may use for "no error" (as internal/monitor does).
func rcodeOK(rc string) bool {
	switch strings.ToUpper(strings.TrimSpace(rc)) {
	case "", "NOERROR", "RCODESUCCESS", "SUCCESS", "0":
		return true
	}
	return false
}

// dnsResolved: the query got a well-formed response with rcode NOERROR and at least one answer,
// and the answer was not redirected (internal/monitor dnsAnswered). DNSResult.OK alone only
// means that a well-formed response arrived (SERVFAIL, NXDOMAIN and empty answers are OK).
func dnsResolved(d model.DNSResult) bool {
	return d.OK && rcodeOK(d.RCode) && len(d.Answers) > 0 && !d.Hijacked
}

func (a *aggregator) addServiceCheck(body model.Body, sc *model.ServiceCheck) {
	a.service.Checks++
	// The resolvers asked in this check, each with its query and its retry (if any), in order.
	type asked struct {
		key              string
		queries, resolve int
	}
	var resolvers []*asked
	byKey := map[string]*asked{}
	for _, d := range sc.DNS {
		key := d.ServerRole + "|" + d.Server
		if isInvalidName(d.Name) {
			a.addInvalidName(key, d)
		} else {
			st := a.dns[key]
			if st == nil {
				st = &dnsStat{Role: d.ServerRole, Server: d.Server}
				a.dns[key] = st
				a.dnsOrder = append(a.dnsOrder, key)
			}
			st.Queries++
			r := byKey[key]
			if r == nil {
				r = &asked{key: key}
				byKey[key] = r
				resolvers = append(resolvers, r)
			}
			r.queries++
			if dnsResolved(d) {
				st.OK++
				r.resolve++
			}
			if d.Hijacked {
				st.Hijacked++
			}
		}
		if d.Hijacked {
			a.service.DNSHijacks++
			detail := fmt.Sprintf("%s %s -> %s (%s)", d.QType, d.Name, strings.Join(d.Answers, ", "), d.HijackWhy)
			if d.Truncated {
				detail += "; the response was truncated (TC bit), answers may be incomplete"
			}
			a.addHijack(hijackExample{Seq: body.Seq, TS: body.TS, Kind: "dns", Where: d.Server, Detail: detail,
				Why: d.HijackWhy, Answers: append([]string(nil), d.Answers...)})
		}
	}
	// A resolver is judged by all its results in the check: it resolved the name when any
	// attempt did, and failed when all of them failed.
	for _, r := range resolvers {
		st := a.dns[r.key]
		st.Checks++
		if r.queries > 1 {
			st.Retried++
		}
		if r.resolve > 0 {
			st.Resolved++
		}
	}
	for _, h := range sc.HTTP {
		st := a.http[h.Name]
		if st == nil {
			st = &httpStat{Name: h.Name, URL: h.URL}
			a.http[h.Name] = st
			a.httpOrd = append(a.httpOrd, h.Name)
		}
		st.Checks++
		if h.OK {
			st.OK++
		}
		if h.Hijacked {
			st.Hijacked++
			a.service.HTTPHijacks++
			a.addHijack(hijackExample{Seq: body.Seq, TS: body.TS, Kind: "http", Where: h.URL,
				Detail: fmt.Sprintf("HTTP %d from %s, Location %q (%s)", h.Status, h.RemoteAddr, h.Location, h.HijackWhy),
				Why:    h.HijackWhy, Status: h.Status, Location: h.Location, RemoteAddr: h.RemoteAddr, BodyPrefix: h.BodyPrefix,
				TLSCertSHA256: h.TLSCertSHA256})
		}
	}
}

// addInvalidName counts a query for a random name under .invalid (the NXDOMAIN-redirection test).
func (a *aggregator) addInvalidName(key string, d model.DNSResult) {
	st := a.invalid[key]
	if st == nil {
		st = &invalidNameStat{Role: d.ServerRole, Server: d.Server}
		a.invalid[key] = st
		a.invOrd = append(a.invOrd, key)
	}
	st.Queries++
	switch {
	case d.Hijacked:
		st.Redirected++
	case d.OK && strings.EqualFold(strings.TrimSpace(d.RCode), "NXDOMAIN"):
		st.NXDomain++
	}
}

func (a *aggregator) addHijack(h hijackExample) {
	if len(a.service.HijackExamples) < 10 {
		a.service.HijackExamples = append(a.service.HijackExamples, h)
	}
}

// egressBypass: the route check of a local_link record shows a destination routed past the
// AT&T gateway (internal/monitor bypassRoute): the check succeeded, and a route to a destination
// that could be resolved does not leave through the gateway.
func egressBypass(e *model.EgressCheck) bool {
	if e == nil || e.Err != "" || !e.Bypass {
		return false
	}
	for _, r := range e.Routes {
		if r.Err == "" && !r.ViaGateway {
			return true
		}
	}
	return false
}

func (a *aggregator) addLocalLink(body model.Body, ll *model.LocalLink) {
	if ll.Egress != nil {
		a.link.EgressChecks++
		if egressBypass(ll.Egress) {
			a.link.EgressBypass++
			if len(a.link.EgressBypassSeqs) < 20 {
				a.link.EgressBypassSeqs = append(a.link.EgressBypassSeqs, body.Seq)
			}
		}
	}
	a.link.Observations++
	t := ll.Type
	if t == "" {
		t = "unknown"
	}
	a.linkTypes.add(t)
	a.link.Interfaces = appendUnique(a.link.Interfaces, ll.Interface, 10)
	a.link.SSIDs = appendUnique(a.link.SSIDs, ll.SSID, 10)
	a.link.BSSIDs = appendUnique(a.link.BSSIDs, ll.BSSID, 20)
	if ll.SignalPct > 0 {
		a.signals = append(a.signals, ll.SignalPct)
	}
	if strings.EqualFold(ll.State, "disconnected") {
		a.link.Disconnected++
	}
}

func (a *aggregator) addClockCheck(cc *model.ClockCheck) {
	a.clock.Checks++
	for _, r := range cc.Results {
		a.clock.Results++
		if r.Server != "" && !a.servers[r.Server] {
			a.servers[r.Server] = true
			a.clock.Servers = append(a.clock.Servers, r.Server)
		}
		if r.OK {
			a.clock.ResultsOK++
			a.clock.MaxAbsOffsetMs = maxAbs(a.clock.MaxAbsOffsetMs, r.OffsetMs)
		}
	}
	if cc.GatewayOffsetMs != nil {
		a.gwOffsetMax = maxAbs(a.gwOffsetMax, *cc.GatewayOffsetMs)
	}
}

func maxAbs(cur *int64, v int64) *int64 {
	if v < 0 {
		v = -max(v, -math.MaxInt64) // saturate: -math.MinInt64 does not fit
	}
	if cur == nil || v > *cur {
		return &v
	}
	return cur
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(not given)"
	}
	return s
}
