// Package monitor is the brain of att-monitor: it schedules the probes, gateway polls,
// service checks and housekeeping of docs/DESIGN.md §8, classifies every fast cycle
// (§9, Classify), runs the incident state machine (§10), derives gateway events (§7),
// anchors the ledger head (§11), keeps the gateway's syslog (docs/syslog-snmp-traffic.md) and
// serves the live status, chart series and incident views to the dashboard
// (contracts.StatusSource) as well as operator actions (contracts.Actions), the syslog controls
// (contracts.SyslogControl: how much is kept, and the gateway's Syslog page) and the flow meter
// (contracts.LiveTrafficSource).
//
// Everything the monitor learns is appended to the evidence ledger; its in-memory state is
// a cache that is rebuilt from the ledger at startup (state/monitor-state.json only speeds
// that up and is never evidence). The flow meter is the exception: a display only, never
// recorded.
//
// Concurrency: one goroutine per activity (fast cycle, gateway poll, service checks, local
// link, clock, heartbeat, anchoring, notification check, traceroutes, incident close,
// segment compression, syslog receiver and syslog flush). Locks, always acquired in this order:
//
//	notifMu   makes "read the redirect and Syslog settings, then enforce them" atomic w.r.t.
//	          operator changes
//	syslogMu  serializes the syslog store's operations with their records (syslog.go)
//	gwMu      serializes requests to the gateway (one web session at a time)
//	anchorMu  serializes anchoring
//	stMu      serializes appends: "append a record + apply it to memory" is atomic w.r.t.
//	          state-cache writes, an incident record is built and appended in one step,
//	          gateway restarts are attached to incidents under it (so no incident record can
//	          miss a restart learned at the same moment), and what a new daily segment must
//	          contain (config_state, incident_update) follows its first record under it
//	cfgMu     guards *config.Config after New (pin, enforce_notification_off, enforce_syslog,
//	          syslog retention) and SaveConfig
//	mu        guards the in-memory state (never held during I/O)
//
// liveMu guards the flow meter (live.go) and is never held while another lock is taken.
package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// Options configures a Monitor (docs/PACKAGES.md).
type Options struct {
	Config     *config.Config
	SaveConfig func(*config.Config) error // persist pin / notification state changes
	Ledger     contracts.Ledger
	Reader     contracts.LedgerReader // rebuild state at startup (nil: Ledger, if it implements it)
	Verifier   contracts.Verifier     // optional (status "last verify")
	Gateway    contracts.Gateway
	Prober     contracts.Prober
	Anchorer   contracts.Anchorer // nil (or Config.Anchoring.Enabled false) disables anchoring
	Software   model.SoftwareInfo // Rules defaults to RulesVersion in monitor_start
	Host       model.HostInfo
	Mode       string // "service" | "console" ("" = "console")
	Listen     string
	DataDir    string
	StateDir   string // caches (non-evidence)
	Now        func() time.Time
	Logger     *slog.Logger
	// MongoStatus, when set, reports the MongoDB copy of the ledger for Status (it is called
	// without holding the monitor's lock and must not block).
	MongoStatus func() model.MongoStatus
	// Syslog receives the gateway's syslog messages (nil: no receiver). The monitor runs it,
	// sets its allowed senders and passes what it receives to SyslogStore (Config.Syslog).
	Syslog contracts.SyslogReceiver
	// SyslogStore keeps the received messages within syslog.keep_mb (nil: messages are not
	// kept). The monitor records a syslog_chunk record for every sealed chunk and a
	// syslog_prune record for every deletion.
	SyslogStore contracts.SyslogStore
}

// Compile-time interface conformance.
var (
	_ contracts.StatusSource      = (*Monitor)(nil)
	_ contracts.Actions           = (*Monitor)(nil)
	_ contracts.Verifier          = (*Monitor)(nil)
	_ contracts.SyslogControl     = (*Monitor)(nil)
	_ contracts.LiveTrafficSource = (*Monitor)(nil)
)

// settings are the configuration values the monitor works with, resolved once in New
// (zero values from a hand-built config are replaced by the defaults).
type settings struct {
	fast, probeTimeout                      time.Duration
	gwHost, gwScheme                        string
	poll, incidentPoll, lanStats, rawStore  time.Duration
	gwTimeout                               time.Duration
	pages                                   []string
	targets                                 []model.ProbeSpec
	service, serviceIncident                time.Duration
	dnsName                                 string
	publicResolvers                         []string
	httpChecks                              []config.HTTPCheck
	linkInterval, linkRecordEvery           time.Duration
	traceTargets                            []string
	traceMaxHops                            int
	traceInterval                           time.Duration
	incident                                config.IncidentConfig
	anchorInterval                          time.Duration
	clockServers                            []string
	clockInterval, heartbeat, notifInterval time.Duration
	// The syslog receiver (config.SyslogConfig): how often what it received is moved into the
	// syslog store, the address it binds, the port the gateway should send to and the senders
	// accepted besides the gateway.
	syslogFlush  time.Duration
	syslogListen string
	syslogPort   int
	syslogAllow  []string
}

func resolveSettings(c *config.Config) settings {
	d := config.Default()
	s := settings{
		fast:            durOr(c.Probes.FastInterval, d.Probes.FastInterval.Duration),
		probeTimeout:    durOr(c.Probes.Timeout, d.Probes.Timeout.Duration),
		gwHost:          c.Gateway.Host,
		gwScheme:        c.Gateway.Scheme,
		poll:            durOr(c.Gateway.PollInterval, d.Gateway.PollInterval.Duration),
		incidentPoll:    durOr(c.Gateway.IncidentPollInterval, d.Gateway.IncidentPollInterval.Duration),
		lanStats:        durOr(c.Gateway.LANStatsInterval, d.Gateway.LANStatsInterval.Duration),
		rawStore:        durOr(c.Gateway.RawStoreInterval, d.Gateway.RawStoreInterval.Duration),
		gwTimeout:       durOr(c.Gateway.Timeout, d.Gateway.Timeout.Duration),
		pages:           slices.Clone(c.Gateway.Pages),
		targets:         slices.Clone(c.Probes.Targets),
		service:         durOr(c.Probes.ServiceInterval, d.Probes.ServiceInterval.Duration),
		serviceIncident: durOr(c.Probes.ServiceIncidentInterval, d.Probes.ServiceIncidentInterval.Duration),
		dnsName:         c.Probes.DNSName,
		publicResolvers: slices.Clone(c.Probes.PublicResolvers),
		httpChecks:      slices.Clone(c.Probes.HTTPChecks),
		linkInterval:    durOr(c.Probes.LocalLinkInterval, d.Probes.LocalLinkInterval.Duration),
		linkRecordEvery: durOr(c.Probes.LocalLinkRecordEvery, d.Probes.LocalLinkRecordEvery.Duration),
		traceTargets:    slices.Clone(c.Probes.TracerouteTargets),
		traceMaxHops:    c.Probes.TracerouteMaxHops,
		traceInterval:   durOr(c.Probes.TracerouteInterval, d.Probes.TracerouteInterval.Duration),
		incident:        effectiveIncident(c.Incident),
		anchorInterval:  durOr(c.Anchoring.Interval, d.Anchoring.Interval.Duration),
		clockServers:    slices.Clone(c.Clock.NTPServers),
		clockInterval:   durOr(c.Clock.Interval, d.Clock.Interval.Duration),
		heartbeat:       durOr(c.HeartbeatInterval, d.HeartbeatInterval.Duration),
		notifInterval:   durOr(c.Gateway.NotificationCheckInterval, d.Gateway.NotificationCheckInterval.Duration),
		syslogFlush:     durOr(c.Syslog.FlushInterval, d.Syslog.FlushInterval.Duration),
		syslogListen:    c.Syslog.Listen,
		syslogPort:      c.Syslog.Port,
		syslogAllow:     slices.Clone(c.Syslog.Allow),
	}
	if s.gwHost == "" {
		s.gwHost = d.Gateway.Host
	}
	if s.syslogListen == "" {
		s.syslogListen = d.Syslog.Listen
	}
	if s.syslogPort <= 0 {
		s.syslogPort = d.Syslog.Port
	}
	if s.gwScheme != "http" {
		s.gwScheme = "https"
	}
	if s.probeTimeout >= s.fast {
		s.probeTimeout = s.fast / 2
	}
	if len(s.pages) == 0 {
		s.pages = slices.Clone(d.Gateway.Pages)
	}
	if len(s.targets) == 0 {
		s.targets = slices.Clone(d.Probes.Targets)
	}
	if s.dnsName == "" {
		s.dnsName = d.Probes.DNSName
	}
	if s.traceMaxHops <= 0 {
		s.traceMaxHops = d.Probes.TracerouteMaxHops
	}
	return s
}

// anchorRec is an anchor record (seq and ts of the anchor record itself).
type anchorRec struct {
	Seq    uint64       `json:"seq"`
	TS     string       `json:"ts"`
	Anchor model.Anchor `json:"anchor"`
}

// anchorTrusted: only a token whose signature and imprint verified and whose TSA certificate
// chained to a trusted root counts as proof of time (DESIGN §11, §13).
func anchorTrusted(a model.Anchor) bool { return a.Verified && a.ChainOK }

// state is the monitor's in-memory view, guarded by Monitor.mu.
type state struct {
	started        time.Time
	cycles         uint64
	lastVerdict    model.Verdict
	since          time.Time
	lastSample     *model.Sample
	prevCycleStart time.Time
	window         [][]model.ProbeResult
	tracker        *tracker
	closing        []*incState // closed by the state machine, incident_close not yet written
	rebootWatch    []*incState // closed LOCAL_FAULT incidents waiting for a usable snapshot
	incidents      map[string]model.Incident
	points         *pointStore

	lastSnap, lastGood *snapObs
	lastFiber          *snapObs // latest reachable snapshot with fiberstat parsed (alarm flags)
	lastUp             *snapObs // latest reachable snapshot with a readable uptime (restart baseline)
	ispHop, ispDNS     string
	// alarms holds, per gateway alarm flag raised now, when it was first reported in the current
	// raised period and the record that reported it (DESIGN §9 conditions).
	alarms       map[string]alarmMark
	lastStored   map[string]time.Time
	lastLANStats time.Time
	// Gateway restarts known from the ledger (gateway_event "reboot"), oldest first, kept for
	// the statistics window and for incidents that open after a restart was learned.
	restarts []restartInfo

	// The latest recorded service check and local link: the classifier uses exactly these
	// records (their seqs go into every verdict's inputs). prevService is the check recorded
	// before lastService (a resolver failure must persist over both, DESIGN §9 rule 3).
	lastService    *model.ServiceCheck
	lastServiceAt  time.Time
	lastServiceSeq uint64
	prevService    *model.ServiceCheck
	prevServiceAt  time.Time
	prevServiceSeq uint64
	lastLink       *model.LocalLink // latest reading (status view), recorded or not
	lastLinkAt     time.Time
	lastLinkRec    *model.LocalLink // latest recorded reading, with its route check (Egress)
	lastLinkRecAt  time.Time
	lastLinkRecSeq uint64
	egressSince    time.Time // since when the recorded route checks show the gateway bypassed

	// The two latest reachable snapshots with the gateway's WAN counters (household traffic).
	lastCtr, prevCtr *snapObs

	// Ledger write health: since when every append failed (zero while appends succeed), how
	// many failed, the latest error, whether the ledger reported itself unusable until it is
	// reopened (contracts.ErrLedgerBroken); when the latest sample was recorded (monitor clock).
	appendFailSince time.Time
	appendFails     int
	appendFailErr   string
	appendBroken    bool
	lastSampleRecAt time.Time
	// The data volume's free space (DESIGN §5 data directory), as last measured.
	disk diskSpace

	lastClock    *model.ClockCheck
	lastClockRef *clockRef // the latest clock check with an SNTP answer
	prevRunClock *clockRef // the latest one of an earlier run, until this run's first is compared with it
	notif        *model.NotificationState
	notifRecAt   time.Time // ts of the latest record about the notification setting
	notifNoCode  string    // the gateway reported that no usable access code is stored
	// A changed gateway certificate waits for confirmation since (record seq): the
	// cert_changed record of certPendingFP. The pending fingerprint itself lives in the
	// configuration; these describe it only while it is certPendingFP.
	certPendingSince time.Time
	certPendingSeq   uint64
	certPendingFP    string
	certEvent        *certEventRec // latest certificate event (cached for the next start)
	// Anchors: the newest trusted one (Verified && ChainOK, the only kind that counts) and the
	// newest untrusted one with the ts of the first untrusted anchor after the newest trusted.
	lastAnchor     *anchorRec
	lastUntrusted  *anchorRec
	untrustedSince string
	lastVerify     *model.VerifySummary
	lastTrace      time.Time

	// Syslog (syslog.go): what the receiver handed over since this run started and the newest
	// message; since when the syslog store fails (zero while it works), how often, the latest
	// error; why the receiver stopped listening and since when ("" while it was not seen down).
	syslogCounts   syslogCounts
	syslogLastAt   string
	syslogLast     string
	storeFailSince time.Time
	storeFails     int
	storeFailErr   string
	rxDown         string
	rxDownSince    time.Time
	// The gateway's Syslog setting as last read and recorded (nil: none known), why the latest
	// check of it failed ("" when it did not), and this computer's latest address toward the
	// gateway (LocalLink.LocalIP of the newest reading that had one).
	syslogGw  *syslogGwRead
	syslogErr string
	localIP   string
	// Keeping the gateway's Syslog setting (syslog_gateway.go): the latest failed attempt to set
	// it (nil: none since the latest success, SYSLOG_SETTING_FAILED); whether it waits for this
	// computer's address (the first reading that has one asks for a settings check); since when
	// the setting as recorded sends here; when the newest message from the gateway was handed over
	// (SYSLOG_NOT_ARRIVING); whether a change made by the monitor waits for its first message; who
	// asked for a switch-off of the page that failed and waits to be made by the settings checks
	// ("" when none; syslogOffDueAfter, rebuilt from the ledger).
	syslogSetFail  *syslogSetFail
	syslogNeedAddr bool
	syslogOKSince  time.Time
	syslogGwMsgAt  time.Time
	syslogAwaitMsg bool
	syslogOffDue   string

	// Custody facts rebuilt from the ledger.
	lastStartRun, lastStopRun string
	lastSampleTS              string
	lastSampleSeq             uint64
	firstRun                  bool // no monitor_start of an earlier run exists
}

// traceReq asks the traceroute worker for traceroutes to every configured target.
type traceReq struct {
	trigger, incident string
}

// Monitor implements contracts.StatusSource, contracts.Actions, contracts.Verifier,
// contracts.SyslogControl and contracts.LiveTrafficSource. All exported methods are safe for
// concurrent use.
type Monitor struct {
	opts     Options
	cfg      *config.Config
	led      contracts.Ledger
	runID    string // the ledger run id of this process (constant)
	reader   contracts.LedgerReader
	gw       contracts.Gateway
	prober   contracts.Prober
	anchorer contracts.Anchorer
	log      *slog.Logger
	now      func() time.Time
	set      settings

	// Tunables; tests shorten them.
	notifMinInterval time.Duration // floor between authenticated notification checks
	anchorRetry      time.Duration // retry delay after a failed anchor
	compressFirst    time.Duration // delay before the first CompressSealed call
	compressEvery    time.Duration
	probeGrace       time.Duration // extra wait for a probe beyond its timeout
	dnsRetryPause    time.Duration // between a DNS query without a valid response and its retry
	clockRecheckMin  time.Duration // floor between a clock check and one asked for by a clock step
	// ledgerFailExit: Run ends with an error once the ledger has refused every record for this
	// long while the data volume has space (a failed write that could not be rolled back leaves
	// the store unusable until it is reopened; the service manager restarts the service). A ledger
	// that says so (contracts.ErrLedgerBroken) ends Run at once instead: see ledgerBroken.
	ledgerFailExit time.Duration
	// The syslog receiver is started again this long after it could not listen, doubling up to
	// syslogRetryMax while that goes on.
	syslogRetryMin, syslogRetryMax time.Duration
	// liveEvery is the shortest time from the end of a read of the flow meter (LiveTraffic) to the
	// next, liveTimeout the longest such a read may hold the gateway lock, liveKeep how long its
	// readings are kept for the meter's history.
	liveEvery, liveTimeout, liveKeep time.Duration

	// ledgerBroken is closed, once, when an append fails with contracts.ErrLedgerBroken: the ledger
	// refuses every further record until it is reopened, so Run ends at once with brokenErr
	// (written before the close).
	ledgerBroken     chan struct{}
	ledgerBrokenOnce sync.Once
	brokenErr        error

	// Platform hooks; tests replace them.
	route    routeLookup                                      // nil: the egress route is not checked
	diskFree func(dir string) (free, total uint64, err error) // nil: free space is not checked

	// Operational log gates (the Windows event log receives Warn and above: repeated failures
	// are reported when they start, periodically while they last, and when they end).
	snapFailLog, appendFailLog, anchorFailLog, tsaWarnLog, notifFailLog, blobFailLog, cacheFailLog logGate
	syslogStoreLog, syslogRxLog, syslogReadLog                                                     logGate

	// syslogOn: the syslog pipeline runs (a receiver, a store and syslog.enabled; syslog.go).
	// syslog is Options.SyslogStore with its bookkeeping (syslogBook; nil without a store).
	// Guarded by syslogMu: when the store was last pruned (monotonic); chunks whose record was
	// written but could not be noted in the store yet (name → seq); whether startSyslog has sorted
	// the store's unrecorded chunks, and those the store had not noted as recorded at the start,
	// whose records the ledger is searched for before they are recorded (syslogReconcile); the
	// store's Recover, or a deletion whose record the ledger refused, to be tried again.
	syslogOn         bool
	syslog           syslogBook
	syslogPrunedAt   time.Time
	syslogMarkLater  map[string]uint64
	syslogChecked    bool
	syslogUnverified map[string]bool
	syslogRecoverDue bool
	syslogPruneDue   bool

	// runCtx is the context of Run's workers once Run has started (the flow meter's gateway
	// reads end with it); live is the flow meter's state (guarded by liveMu).
	runCtx atomic.Pointer[context.Context]
	live   liveState

	running       atomic.Bool
	shutdownSeen  atomic.Bool
	gwAuth        atomic.Bool // an authenticated gateway operation holds gwMu (raised and read under cfgMu)
	appendFailing atomic.Bool // the latest append failed (fast path of noteAppendSuccess)
	records       atomic.Uint64

	notifMu  sync.Mutex // serializes notification check/enforce and operator changes
	syslogMu sync.Mutex
	gwMu     sync.Mutex
	anchorMu sync.Mutex
	stMu     sync.Mutex
	cfgMu    sync.Mutex
	cacheMu  sync.Mutex // serializes state-cache file writes
	liveMu   sync.Mutex

	cacheGen     uint64 // state-cache snapshots taken (guarded by stMu)
	cacheWritten uint64 // generation of the cache file on disk (guarded by cacheMu)

	// segHead is the ledger head after this process's latest successful append (before its
	// first append: the head found then). The records the ledger writes of its own between it
	// and this process's next record tell whether that record is the first of a new daily
	// segment (DESIGN §6: segment_open). configStateDue: the current segment's config_state
	// could not be written yet. Guarded by stMu.
	segHead        model.Ref
	segHeadKnown   bool
	configStateDue bool

	// kNotif asks the notification loop for an early settings check (this computer's address
	// toward the gateway changed).
	kGateway, kService, kLink, kClock, kClose, kNotif *kicker
	traceReqs                                         chan traceReq

	mu sync.Mutex
	st state
}

// New validates the options, applies defaults and installs the gateway certificate observer.
// The monitor owns *Options.Config from now on: it changes Gateway.PinnedCertSHA256,
// Gateway.PendingCertSHA256, Gateway.EnforceNotificationOff, Gateway.EnforceSyslog and
// Syslog.KeepMB/KeepDays under its own lock and persists them with SaveConfig.
func New(opts Options) (*Monitor, error) {
	switch {
	case opts.Config == nil:
		return nil, errors.New("monitor: Options.Config is required")
	case opts.Ledger == nil:
		return nil, errors.New("monitor: Options.Ledger is required")
	case opts.Gateway == nil:
		return nil, errors.New("monitor: Options.Gateway is required")
	case opts.Prober == nil:
		return nil, errors.New("monitor: Options.Prober is required")
	}
	reader := opts.Reader
	if reader == nil {
		if r, ok := opts.Ledger.(contracts.LedgerReader); ok {
			reader = r
		}
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	if opts.Mode == "" {
		opts.Mode = "console"
	}
	m := &Monitor{
		opts:             opts,
		cfg:              opts.Config,
		led:              opts.Ledger,
		runID:            opts.Ledger.RunID(),
		reader:           reader,
		gw:               opts.Gateway,
		prober:           opts.Prober,
		log:              logger.With("component", "monitor"),
		now:              now,
		set:              resolveSettings(opts.Config),
		notifMinInterval: 10 * time.Minute,
		anchorRetry:      5 * time.Minute,
		compressFirst:    2 * time.Minute,
		compressEvery:    24 * time.Hour,
		probeGrace:       2 * time.Second,
		dnsRetryPause:    500 * time.Millisecond,
		clockRecheckMin:  time.Minute,
		ledgerFailExit:   5 * time.Minute,
		syslogRetryMin:   time.Minute,
		syslogRetryMax:   10 * time.Minute,
		liveEvery:        liveMinInterval,
		liveTimeout:      liveReadTimeout,
		liveKeep:         liveHistory,
		ledgerBroken:     make(chan struct{}),
		route:            systemRoute,
		diskFree:         systemDiskFree,
		kGateway:         newKicker(),
		kService:         newKicker(),
		kLink:            newKicker(),
		kClock:           newKicker(),
		kClose:           newKicker(),
		kNotif:           newKicker(),
		traceReqs:        make(chan traceReq, 16),
	}
	if opts.Anchorer != nil && opts.Config.Anchoring.Enabled {
		m.anchorer = opts.Anchorer
	}
	// Without a store the received messages could not be kept: the receiver is not run then.
	m.syslogOn = opts.Syslog != nil && opts.SyslogStore != nil && opts.Config.Syslog.Enabled
	m.syslog = bookOf(opts.SyslogStore, m.log)
	m.syslogMarkLater, m.syslogUnverified = map[string]uint64{}, map[string]bool{}
	m.st.incidents = map[string]model.Incident{}
	m.st.points = newPointStore()
	m.st.alarms = map[string]alarmMark{}
	m.st.lastStored = map[string]time.Time{}
	m.st.tracker = newTracker(m.set.incident.OpenAfterCycles, m.set.incident.CloseAfterCycles, m.set.incident.WindowCycles, m.set.fast, m.idTakenLocked)
	m.gw.SetCertObserver(m.observeCert)
	return m, nil
}

// idTakenLocked reports whether an incident id is in use (called by the tracker under mu).
func (m *Monitor) idTakenLocked(id string) bool {
	if _, ok := m.st.incidents[id]; ok {
		return true
	}
	for _, c := range m.st.closing {
		if c.inc.ID == id {
			return true
		}
	}
	if t := m.st.tracker; t != nil && t.open != nil && t.open.inc.ID == id {
		return true
	}
	return false
}

// Run monitors until ctx is done. It writes monitor_start first and monitor_stop last, and
// returns only after every goroutine it started has finished. It may be called once.
//
// Run does not return before ctx is done unless it cannot start (a second call, or
// monitor_start cannot be recorded), the ledger reports itself unusable (an append failed with
// contracts.ErrLedgerBroken: Run ends at once, with an error wrapping it) or the ledger has
// refused every record for ledgerFailExit while the data volume has space (see ledgerFatal): it
// then returns that error, so that the Windows service ends with an error and the service
// manager restarts it, which reopens the ledger. Failing workers, panics and other ledger errors
// are logged and monitoring goes on.
func (m *Monitor) Run(ctx context.Context) error {
	if !m.running.CompareAndSwap(false, true) {
		return errors.New("monitor: Run may only be called once")
	}
	started := m.now()
	m.mu.Lock()
	m.st.started = started
	m.mu.Unlock()
	m.log.Info("monitor starting", "mode", m.opts.Mode, "rules", RulesVersion, "fast_interval", m.set.fast)

	m.rebuild(started)
	m.mu.Lock()
	m.st.firstRun = m.st.lastStartRun == ""
	m.mu.Unlock()
	if err := m.recordStart(started); err != nil {
		return fmt.Errorf("monitor: cannot record monitor_start: %w", err)
	}
	m.closeStaleIncidents()
	m.watchUndecidedIncidents()
	m.checkDisk()
	if m.syslogOn {
		m.safely("syslog", m.startSyslog) // the chunk the previous run left open, sealed and recorded
	}

	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	m.runCtx.Store(&wctx)
	fatal := make(chan error, 1)
	type worker struct {
		name string
		f    func(context.Context)
	}
	workers := []worker{
		{"cycle", m.cycleLoop},
		{"gateway", m.gatewayLoop},
		{"service", m.serviceLoop},
		{"locallink", m.localLinkLoop},
		{"clock", m.clockLoop},
		{"heartbeat", m.heartbeatLoop},
		{"anchor", m.anchorLoop},
		{"notification", m.notificationLoop},
		{"traceroute", m.tracerouteLoop},
		{"closer", m.closerLoop},
		{"compress", m.compressLoop},
		{"ledgerwatch", func(ctx context.Context) { m.ledgerWatch(ctx, fatal) }},
	}
	if m.syslogOn {
		workers = append(workers, worker{"syslog-receiver", m.syslogReceiverLoop}, worker{"syslog", m.syslogLoop})
	}
	var wg sync.WaitGroup
	for _, w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.f(wctx)
		}()
	}

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-fatal:
	case <-m.ledgerBroken:
	}
	select {
	case <-m.ledgerBroken: // also when it coincides with the end of ctx: the restart must reopen it
		runErr = m.brokenErr
	default:
	}
	if runErr != nil {
		m.log.Error("stopping the monitor: the evidence ledger is unusable", "err", runErr)
	}
	cancel()
	wg.Wait()

	// Incidents whose recovery was confirmed but whose close record was not written yet are
	// finalized now (no network I/O), so the next start does not report them as unknown.
	m.finishClosings(wctx)
	if m.syslogOn {
		// The receiver has stopped: what it still holds goes into the store, and the open chunk is
		// sealed and recorded before monitor_stop.
		m.safely("syslog", func() { m.flushSyslog(true) })
	}

	m.mu.Lock()
	uptime := int64(m.now().Sub(m.st.started) / time.Second)
	m.mu.Unlock()
	reason := m.stopReason(ctx)
	if runErr != nil {
		reason = truncate("evidence ledger failing: "+runErr.Error(), 200)
	}
	_, err := m.appendApply(model.TypeMonitorStop, model.MonitorStop{Reason: reason, UptimeSec: uptime}, nil,
		func(model.Ref) { m.st.lastStopRun = m.runID })
	m.writeCache()
	m.log.Info("monitor stopped", "reason", reason)
	if runErr != nil {
		return fmt.Errorf("monitor: %w", runErr)
	}
	if err != nil {
		return fmt.Errorf("monitor: cannot record monitor_stop: %w", err)
	}
	return nil
}

func (m *Monitor) stopReason(ctx context.Context) string {
	if m.shutdownSeen.Load() {
		return "system shutdown"
	}
	cause := context.Cause(ctx)
	if cause == nil || cause == context.Canceled {
		return "stopped"
	}
	return truncate(cause.Error(), 200)
}

// PowerEvent records an OS power notification ("suspend", "resume", "resume_automatic",
// "shutdown", "power_status_change") from the service control handler.
func (m *Monitor) PowerEvent(kind string) {
	kind = strings.TrimSpace(kind)
	if kind == "" {
		return
	}
	if kind == "shutdown" {
		m.shutdownSeen.Store(true)
	}
	if _, err := m.appendApply(model.TypePowerEvent, model.PowerEvent{Kind: kind}, nil, nil); err != nil {
		m.log.Error("cannot record power event", "kind", kind, "err", err)
	}
	if strings.HasPrefix(kind, "resume") {
		// After sleep: re-check the clock, the link and the gateway right away.
		m.kClock.kick("resume")
		m.kLink.kick("resume")
		m.kGateway.kick("resume")
		m.kService.kick("resume")
	}
}

// recordStart appends monitor_start (docs/DESIGN.md §7). Its gap_seconds is the real time since
// the newest record by this computer's clock - negative when the clock is behind that record
// (set back, or the record dated ahead), which is evidence in itself and never clamped.
func (m *Monitor) recordStart(now time.Time) error {
	head := m.led.Head()
	var gap int64
	if t, ok := parseTS(head.TS); ok {
		gap = int64(now.Sub(t) / time.Second)
	}
	m.mu.Lock()
	prevStopped := m.st.lastStartRun == "" || m.st.lastStopRun == m.st.lastStartRun
	m.mu.Unlock()
	cfgHash, cfgJSON := m.configRecord()
	sw := m.opts.Software
	if sw.Rules == "" {
		sw.Rules = RulesVersion
	}
	ms := model.MonitorStart{
		Software:     sw,
		Host:         m.opts.Host,
		ConfigSHA256: cfgHash,
		Config:       cfgJSON,
		Mode:         m.opts.Mode,
		PrevHead:     head,
		GapSeconds:   gap,
		PrevStopped:  prevStopped,
	}
	_, err := m.appendApply(model.TypeMonitorStart, ms, nil, func(model.Ref) { m.st.lastStartRun = m.runID })
	return err
}

// configRecord returns the effective configuration as monitor_start and config_state record it
// (secrets removed) and its config_sha256 - one algorithm for both records.
func (m *Monitor) configRecord() (sha string, cfg json.RawMessage) {
	m.cfgMu.Lock()
	defer m.cfgMu.Unlock()
	return m.cfg.RedactedSHA256(), redactedConfigJSON(m.cfg)
}

// redactedConfigJSON is the configuration recorded in monitor_start (secrets removed): the
// same bytes config.RedactedSHA256 hashes, so SHA-256(config) equals config_sha256 when the
// bytes are taken as written. Caller holds cfgMu.
func redactedConfigJSON(c *config.Config) json.RawMessage {
	cp := *c
	cp.Gateway.AccessCodeProtected = ""
	b, err := json.Marshal(&cp)
	if err != nil {
		return nil
	}
	return b
}

// closeStaleIncidents closes incidents a previous run left open (docs/PACKAGES.md: closed =
// last sample ts of that run; the outcome after the monitor stopped is unknown).
//
// Each is rebuilt from its records (ledgerIncState) and closed the way a live incident is
// closed, with every gateway restart known from the ledger that belongs to it (DESIGN §10).
// When no snapshot with a readable gateway uptime followed its last sample, whether the gateway
// restarted meanwhile is not known yet: like a live incident closed in that state, it waits on
// the reboot watch, so a restart revealed by this run's first snapshot (often the case after the
// owner power-cycled the gateway and this computer stopped too) still revises it.
func (m *Monitor) closeStaleIncidents() {
	m.mu.Lock()
	var stale []model.Incident
	for _, inc := range m.st.incidents {
		if inc.Open {
			stale = append(stale, cloneIncident(inc))
		}
	}
	lastTS, lastSeq := m.st.lastSampleTS, m.st.lastSampleSeq
	m.mu.Unlock()
	slices.SortFunc(stale, func(a, b model.Incident) int { return strings.Compare(a.Opened, b.Opened) })
	for _, inc := range stale {
		opened, _ := parseTS(inc.Opened)
		closed, ok := parseTS(lastTS)
		if !ok || closed.Before(opened) {
			closed = opened
		}
		closeSeq := max(lastSeq, inc.LastSeq)
		stopped := fmt.Sprintf("The monitor stopped while this incident was open (last sample at %s); the incident is closed at that time and the outcome after the monitor stopped is unknown.",
			fmtHuman(closed))
		st, ok := m.ledgerIncState(inc, lastSeq, closed)
		if !ok {
			m.closeStaleAsRecorded(inc, closed, closeSeq, stopped)
			continue
		}
		// The open/update record's statistics only covered the cycles seen until then; its
		// observation flags may also come from records that are not of this incident's run.
		flags := inc.Stats
		s := &st.inc.Stats
		s.GatewayDownSeen = s.GatewayDownSeen || flags.GatewayDownSeen
		s.PONDownSeen = s.PONDownSeen || flags.PONDownSeen
		s.OpticalAlarm = s.OpticalAlarm || flags.OpticalAlarm
		s.DNSHijackSeen = s.DNSHijackSeen || flags.DNSHijackSeen
		s.HTTPHijackSeen = s.HTTPHijackSeen || flags.HTTPHijackSeen
		s.LocalLinkDown = s.LocalLinkDown || flags.LocalLinkDown
		st.mergeRecorded(inc)
		st.ev.add(model.EvidenceRef{Seq: lastSeq, Type: model.TypeSample, Note: "last sample before the monitor stopped"})
		st.closeAt(closed, closeSeq)
		st.notes = append(st.notes, stopped,
			fmt.Sprintf("Statistics cover the %d cycles recorded from the first bad cycle to that last sample.", st.inc.Stats.Cycles))
		rec, err := m.appendIncident(model.TypeIncidentClose, st, func() {
			m.attachKnownRestartsLocked(st, inc.GatewayRestarts, true)
		}, func(model.Incident) {
			m.watchIfUndecidedLocked(st)
		})
		if err != nil {
			m.log.Error("cannot close stale incident", "id", inc.ID, "err", err)
			continue
		}
		m.log.Warn("closed incident left open by the previous run", "id", rec.ID, "closed", rec.Closed,
			"state", rec.State, "cause", rec.Cause, "attribution", rec.Attribution)
	}
}

// closeStaleAsRecorded closes an incident left open whose records cannot be recounted (the
// ledger cannot be read, or FirstSeq is not its first bad sample): with the headline, figures
// and restarts of its last record - nothing is guessed.
func (m *Monitor) closeStaleAsRecorded(inc model.Incident, closed time.Time, closeSeq uint64, note string) {
	opened, _ := parseTS(inc.Opened)
	inc.Open = false
	inc.Closed = fmtTS(closed)
	inc.DurationSec = int64(closed.Sub(opened) / time.Second)
	inc.LastSeq = closeSeq
	ev := evidenceList{refs: inc.Evidence}
	ev.add(model.EvidenceRef{Seq: closeSeq, Type: model.TypeSample, Note: "last sample before the monitor stopped"})
	inc.Evidence = ev.sorted()
	inc.Summary = summarize(inc, []string{note})
	if _, err := m.appendApply(model.TypeIncidentClose, inc, nil, func(model.Ref) { m.st.incidents[inc.ID] = inc }); err != nil {
		m.log.Error("cannot close stale incident", "id", inc.ID, "err", err)
		return
	}
	m.log.Warn("closed incident left open by the previous run (its records could not be recounted)", "id", inc.ID, "closed", inc.Closed)
}

// mergeRecorded adds to an incident rebuilt from its samples what only its own records hold:
// the causes listed so far (in their order) and the evidence references.
func (st *incState) mergeRecorded(inc model.Incident) {
	causes := slices.Clone(inc.Causes)
	for _, c := range st.inc.Causes {
		if !slices.Contains(causes, c) {
			causes = append(causes, c)
		}
	}
	st.inc.Causes = causes
	for _, r := range inc.Evidence {
		st.ev.add(r)
	}
}

// attachKnownRestartsLocked attaches the gateway restarts an incident rebuilt from the ledger
// belongs to: those its own records name (boot times), and with all, every restart known from
// the ledger's reboot events whose window holds one of its bad cycles. Caller holds mu.
func (m *Monitor) attachKnownRestartsLocked(st *incState, named []string, all bool) {
	for _, b := range named {
		t, ok := parseTS(b)
		if !ok {
			continue
		}
		r := restartInfo{Boot: t, Uptime: -1}
		for _, x := range m.st.restarts { // the reboot event's facts, when it is known
			if sameRestart(x, r) {
				r = x
				break
			}
		}
		m.attachRestartLocked(st, r)
	}
	if all {
		for _, r := range m.st.restarts {
			m.attachRestartLocked(st, r)
		}
	}
}

// watchIfUndecidedLocked puts a closed incident on the reboot watch when no snapshot with a
// readable gateway uptime was taken at or after its close (a restart during it would not be
// known yet). Caller holds mu.
func (m *Monitor) watchIfUndecidedLocked(st *incState) {
	if up := m.st.lastUp; up != nil && !up.At.Before(st.closed) {
		st.restartDecided = true
		return
	}
	for _, w := range m.st.rebootWatch {
		if w.inc.ID == st.inc.ID {
			return
		}
	}
	m.st.rebootWatch = boundWatch(append(m.st.rebootWatch, st))
}

// extraNoteMarkers start the summary sentences an incident closes with that its records hold
// nowhere else (interruptions, clock steps, the monitor stopping): payload appends them last.
var extraNoteMarkers = []string{
	"Monitoring was interrupted for ",
	"Recovery was observed but not yet confirmed when ",
	"The computer's clock was stepped by ",
	"The monitor stopped while this incident was open",
}

// summaryExtraNotes returns those closing sentences of a recorded summary (without a
// "Measured time" sentence among them, which is recomputed), or nil.
func summaryExtraNotes(summary string) []string {
	at := -1
	for _, mk := range extraNoteMarkers {
		if i := strings.Index(summary, mk); i >= 0 && (at < 0 || i < at) {
			at = i
		}
	}
	if at < 0 {
		return nil
	}
	s := summary[at:]
	if i := strings.Index(s, "Measured time: "); i >= 0 {
		end := len(s)
		if j := strings.Index(s[i:], ". "); j >= 0 {
			end = i + j + 2
		}
		s = s[:i] + s[end:]
	}
	if s = strings.TrimSpace(s); s == "" {
		return nil
	}
	return []string{s}
}

// watchUndecidedIncidents puts the incidents closed by earlier runs back on the reboot watch
// (which lives in memory only) when no snapshot with a readable gateway uptime followed their
// close: a restart during them may still be revealed by this run's first snapshot that reads the
// uptime, and must then revise them (incident_update), as it would have in the run that closed
// them. Each is rebuilt from its records; the most recent maxRebootWatch closed within the
// statistics horizon are considered.
func (m *Monitor) watchUndecidedIncidents() {
	m.mu.Lock()
	var upAt time.Time
	if m.st.lastUp != nil {
		upAt = m.st.lastUp.At
	}
	cutoff := m.now().Add(-seriesKeep)
	type cand struct {
		inc    model.Incident
		closed time.Time
	}
	var cands []cand
	for _, inc := range m.st.incidents {
		if inc.Open || slices.ContainsFunc(m.st.rebootWatch, func(w *incState) bool { return w.inc.ID == inc.ID }) {
			continue
		}
		closed, ok := parseTS(inc.Closed)
		if !ok || closed.Before(cutoff) || (!upAt.IsZero() && !upAt.Before(closed)) {
			continue
		}
		cands = append(cands, cand{cloneIncident(inc), closed})
	}
	m.mu.Unlock()
	slices.SortFunc(cands, func(a, b cand) int { return b.closed.Compare(a.closed) })
	if len(cands) > maxRebootWatch {
		cands = cands[:maxRebootWatch]
	}
	slices.Reverse(cands) // oldest first, as the live watch keeps them
	for _, c := range cands {
		st, ok := m.ledgerIncState(c.inc, c.inc.LastSeq, c.closed)
		if !ok {
			continue
		}
		// As recorded: the figures, causes and evidence of its last record, and the sentences it
		// was closed with; the time accounting and restart windows come from its cycles.
		st.inc.Stats = cloneIncident(c.inc).Stats
		st.inc.Causes = nil
		st.mergeRecorded(c.inc)
		st.closeAt(c.closed, c.inc.LastSeq)
		st.notes = summaryExtraNotes(c.inc.Summary)
		m.stMu.Lock()
		m.locked(func() {
			m.attachKnownRestartsLocked(st, c.inc.GatewayRestarts, false)
			m.watchIfUndecidedLocked(st)
		})
		m.stMu.Unlock()
		m.log.Info("incident closed by an earlier run waits for a readable gateway uptime (restart rules)", "id", c.inc.ID, "closed", c.inc.Closed)
	}
}

// ledgerIncState rebuilds the working state of a recorded incident from the ledger: the records
// of its run from its first bad sample (FirstSeq) up to lastSeq, counted like the live incident
// counts them (every cycle from the first bad one, time accounting per DESIGN §10, recovered_at,
// gateway observations, hijack flags), the last cycle covering the time until closed. No
// restart is attached yet. ok is false when the ledger cannot be read or FirstSeq is not the
// incident's first bad sample.
func (m *Monitor) ledgerIncState(inc model.Incident, lastSeq uint64, closed time.Time) (*incState, bool) {
	if m.reader == nil || lastSeq < inc.FirstSeq {
		return nil, false
	}
	opened, ok := parseTS(inc.Opened)
	if !ok || opened.After(closed) {
		opened = closed
	}
	st := &incState{opened: opened, fast: m.set.fast, openAfter: m.set.incident.OpenAfterCycles,
		inc: model.Incident{ID: inc.ID, Opened: inc.Opened, Rules: RulesVersion, FirstSeq: inc.FirstSeq,
			Stats: model.IncidentStats{ProbeOK: map[string]int{}, ProbeTotal: map[string]int{}}}}
	maxCover := coverCap(m.set.fast)
	run, valid := "", false
	var prev cycleObs
	havePrev := false
	err := m.reader.Scan(inc.FirstSeq, func(_ model.Envelope, body model.Body) error {
		if body.Seq > lastSeq {
			return contracts.ErrStop
		}
		if body.Seq == inc.FirstSeq {
			var s model.Sample
			if body.Type != model.TypeSample || json.Unmarshal(body.Data, &s) != nil || s.Started != inc.Opened {
				return contracts.ErrStop // not the incident's first bad sample: do not guess
			}
			run, valid = body.Run, true
		}
		if body.Run != run {
			return nil // e.g. a note written by the CLI while the service was stopped
		}
		s := &st.inc.Stats
		switch body.Type {
		case model.TypeSample:
			var smp model.Sample
			if json.Unmarshal(body.Data, &smp) != nil {
				return nil
			}
			start, ok := parseTS(smp.Started)
			if !ok {
				start, _ = parseTS(body.TS)
			}
			ts, _ := parseTS(body.TS)
			o := cycleObs{Start: start, TS: ts, Seq: body.Seq, Verdict: smp.Verdict, Probes: smp.Probes}
			if havePrev {
				st.settleLast(prev.Seq, min(max(start.Sub(prev.Start), 0), maxCover))
			}
			prev, havePrev = o, true
			st.trackRecovery(o)
			if isGood(o.Verdict.State) {
				st.count(o, false)
			}
			st.addCycle(o) // counts a bad cycle
		case model.TypeGatewaySnapshot:
			var g struct {
				Derived model.GatewayDerived `json:"derived"`
			}
			if json.Unmarshal(body.Data, &g) != nil {
				return nil
			}
			s.GatewayFetches++
			d := g.Derived
			s.GatewayDownSeen = s.GatewayDownSeen || (d.BroadbandUp != nil && !*d.BroadbandUp)
			s.PONDownSeen = s.PONDownSeen || (d.PONOperational != nil && !*d.PONOperational)
			s.OpticalAlarm = s.OpticalAlarm || len(d.Alarms) > 0
		case model.TypeServiceCheck:
			var sc model.ServiceCheck
			if json.Unmarshal(body.Data, &sc) != nil {
				return nil
			}
			for _, r := range sc.DNS {
				s.DNSHijackSeen = s.DNSHijackSeen || r.Hijacked
			}
			for _, r := range sc.HTTP {
				s.HTTPHijackSeen = s.HTTPHijackSeen || r.Hijacked
			}
		}
		return nil
	})
	if err != nil || !valid {
		if err != nil {
			m.log.Warn("cannot rebuild an incident from its records", "id", inc.ID, "err", err)
		}
		return nil, false
	}
	if havePrev { // the last sample covers the time until the incident is closed, capped
		st.settleLast(prev.Seq, min(max(closed.Sub(prev.Start), 0), maxCover))
	}
	st.closed = closed
	return st, true
}

// appendApply appends one record and, on success, applies its effect to the in-memory state
// (apply runs with mu held). Holding stMu across both keeps state-cache snapshots consistent
// with the ledger head they name.
func (m *Monitor) appendApply(typ string, data any, blobs []string, apply func(model.Ref)) (model.Ref, error) {
	m.stMu.Lock()
	defer m.stMu.Unlock()
	return m.appendLocked(typ, data, blobs, apply)
}

// appendLocked is appendApply for a caller that holds stMu. Every record of this process goes
// through it, so it also sees when a record is the first of a new daily ledger segment (DESIGN
// §6: the ledger writes segment_open just before the first record of a later UTC date) and
// then records what every segment must contain right after it (startSegmentLocked).
func (m *Monitor) appendLocked(typ string, data any, blobs []string, apply func(model.Ref)) (model.Ref, error) {
	if !m.segHeadKnown {
		m.segHead, m.segHeadKnown = m.led.Head(), true
	}
	prev := m.segHead
	ref, err := m.led.Append(typ, data, blobs...)
	if err != nil {
		m.noteAppendFailure(typ, err)
		return ref, err
	}
	m.noteAppendSuccess()
	m.segHead = ref
	m.records.Add(1)
	if apply != nil {
		m.locked(func() { apply(ref) })
	}
	switch {
	case m.segmentOpened(prev, ref):
		m.startSegmentLocked(typ, data)
	case m.configStateDue && typ != model.TypeConfigState:
		m.appendConfigStateLocked() // the segment's config_state failed: retried once per record
	}
	return ref, nil
}

// maxSegmentProbe bounds the records read back to find a segment_open (normally just one,
// possibly followed by an integrity_alert about a foreign file in the segment's place).
const maxSegmentProbe = 8

// segmentOpened reports whether ref, appended after prev (the head after this process's
// previous record), is this process's first record in a new daily segment. The ledger writes
// records of its own only when it starts a segment: segment_open (and possibly an
// integrity_alert) just before the record that started it - or, when that record could not be
// written, before the next one. Those records are read back; only when they cannot be read does
// a later UTC date decide (the rotation rule of DESIGN §6). Unlike a date comparison alone, this
// is not fooled by a wall clock that is behind the active segment's date. Caller holds stMu.
func (m *Monitor) segmentOpened(prev, ref model.Ref) bool {
	if ref.Seq <= prev.Seq+1 {
		return false // nothing was written in between
	}
	if m.reader != nil {
		from := prev.Seq + 1
		if ref.Seq-from > maxSegmentProbe {
			from = ref.Seq - maxSegmentProbe
		}
		read := true
		for seq := from; seq < ref.Seq; seq++ {
			_, body, err := m.reader.Record(seq)
			if err != nil {
				m.log.Warn("cannot read back a ledger record written before this one", "seq", seq, "err", err)
				read = false
				break
			}
			if body.Type == model.TypeSegmentOpen {
				return true
			}
		}
		if read && from == prev.Seq+1 {
			return false
		}
	}
	return utcDay(ref.TS) > utcDay(prev.TS)
}

// utcDay returns the UTC date of a record ts ("" if unparseable).
func utcDay(ts string) string {
	t, ok := parseTS(ts)
	if !ok {
		return ""
	}
	return t.UTC().Format("2006-01-02")
}

// startSegmentLocked records what every daily ledger segment must contain, right after the
// record (typ, data) that is this process's first in it: the configuration in force
// (config_state, DESIGN §7: every segment - and so every evidence bundle - states the thresholds
// from records it contains) and, while an incident is open, an incident_update (DESIGN §10).
// Caller holds stMu.
func (m *Monitor) startSegmentLocked(typ string, data any) {
	// A config_state that itself started the segment (written right at midnight for the
	// previous one) is this segment's: exactly one per segment.
	m.configStateDue = typ != model.TypeConfigState
	if m.configStateDue {
		m.appendConfigStateLocked()
	}
	m.recordOpenIncidentForSegmentLocked(typ, data)
}

// appendConfigStateLocked appends the current segment's config_state: the configuration and
// hash monitor_start records (configRecord). When the ledger refuses it, it is retried after the
// next record this process writes in the segment. Caller holds stMu.
func (m *Monitor) appendConfigStateLocked() {
	sum, cfg := m.configRecord()
	cs := model.ConfigState{ConfigSHA256: sum, Config: cfg, Rules: RulesVersion, Reason: "new_segment"}
	if _, err := m.appendLocked(model.TypeConfigState, cs, nil, nil); err != nil {
		m.log.Warn("the configuration in force could not be recorded in the new daily ledger segment; retrying after the next record", "err", err)
		return
	}
	m.configStateDue = false
	m.log.Info("configuration in force recorded in the new daily ledger segment", "config_sha256", sum)
}

// recordOpenIncidentForSegmentLocked appends an incident_update for the open incident right
// after the record (typ, data) that started a new daily segment - unless that record is
// itself a record of the incident. Caller holds stMu.
func (m *Monitor) recordOpenIncidentForSegmentLocked(typ string, data any) {
	var st *incState
	m.locked(func() {
		o := m.st.tracker.open
		if o == nil {
			return
		}
		if _, recorded := m.st.incidents[o.inc.ID]; recorded { // its incident_open exists
			st = o
		}
	})
	if st == nil {
		return
	}
	switch typ {
	case model.TypeIncidentOpen, model.TypeIncidentUpdate, model.TypeIncidentClose:
		if inc, ok := data.(model.Incident); ok && inc.ID == st.inc.ID {
			return
		}
	}
	if _, err := m.appendIncidentLocked(model.TypeIncidentUpdate, st, nil); err == nil {
		m.log.Info("open incident recorded in the new daily ledger segment", "id", st.inc.ID)
	}
}

// appendIncident records incident_open/update/close for st. The verdict reasons its headline
// needs are read from the ledger first; the payload is then built and appended under stMu,
// so no restart can be attached in between (attachments happen under stMu too). prepare and
// apply (either may be nil) run with mu held, before the payload is built and after the
// record was appended.
func (m *Monitor) appendIncident(typ string, st *incState, prepare func(), apply func(model.Incident)) (model.Incident, error) {
	m.stMu.Lock()
	defer m.stMu.Unlock()
	if prepare != nil {
		m.locked(prepare)
	}
	return m.appendIncidentLocked(typ, st, apply)
}

// appendIncidentLocked is appendIncident for a caller that holds stMu. apply (may be nil)
// runs with mu held after the record was appended, besides remembering the payload.
func (m *Monitor) appendIncidentLocked(typ string, st *incState, apply func(model.Incident)) (model.Incident, error) {
	m.resolveReasonsLocked(st)
	var inc model.Incident
	m.locked(func() { inc = st.payload(m.now(), false) })
	_, err := m.appendLocked(typ, inc, nil, func(model.Ref) {
		m.st.incidents[inc.ID] = inc
		if apply != nil {
			apply(inc)
		}
	})
	return inc, err
}

// resolveReasonsLocked reads the verdict reasons the incident's headline needs from the
// recorded sample when memory no longer holds them (a restart learned after the fact moved
// the headline back to an earlier cycle). Caller holds stMu (no restart can change the need
// meanwhile); mu is taken only around the state.
func (m *Monitor) resolveReasonsLocked(st *incState) {
	var seq uint64
	m.locked(func() { seq = st.needReasons })
	if seq == 0 || m.reader == nil {
		return
	}
	_, body, err := m.reader.Record(seq)
	var s model.Sample
	if err == nil && body.Type == model.TypeSample {
		err = json.Unmarshal(body.Data, &s)
	} else if err == nil {
		err = fmt.Errorf("record %d is a %s, not a sample", seq, body.Type)
	}
	if err != nil {
		m.log.Warn("cannot read the verdict reasons of an incident's headline", "seq", seq, "err", err)
		return
	}
	m.locked(func() {
		if st.needReasons == seq {
			st.outReasons, st.outReasonsSeq, st.needReasons = s.Verdict.Reasons, seq, 0
		}
	})
}

// locked runs f with mu held and releases it even if f panics: workers recover panics
// (safely), so a panic must never leave the state lock held.
func (m *Monitor) locked(f func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f()
}

func (m *Monitor) putBlob(b []byte) (string, error) {
	id, err := m.led.PutBlob(b)
	if err != nil {
		// During an incident raw pages are stored every 15 s: a full disk must not flood the log.
		if loud, n, since := m.blobFailLog.fail(m.now(), blobFailReport); loud {
			m.log.Error("blob store failed", "bytes", len(b), "err", err, "failures", n, "since", since)
		} else {
			m.log.Debug("blob store failed", "bytes", len(b), "err", err, "failures", n)
		}
	} else if rec, n, since := m.blobFailLog.ok(); rec {
		m.log.Warn("blob store works again", "failures", n, "since", since)
	}
	return id, err
}

// safely runs one iteration of a worker; a panic is logged instead of killing the evidence
// logger (the next iteration starts from a consistent state because state changes are
// applied atomically under mu).
func (m *Monitor) safely(worker string, f func()) {
	defer func() {
		if r := recover(); r != nil {
			m.log.Error("worker panic recovered", "worker", worker, "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
		}
	}()
	f()
}

func (m *Monitor) incidentOpen() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.st.tracker.open != nil
}

// addEvidenceLocked attaches a record to the incident(s) it documents: target (an incident in
// its close procedure) or else the open incident. Caller holds mu.
func (m *Monitor) addEvidenceLocked(target *incState, typ string, seq uint64, refs ...model.EvidenceRef) {
	for _, st := range m.evidenceTargetsLocked(target) {
		st.ev.addGroup(typ, seq, refs)
	}
}

func (m *Monitor) evidenceTargetsLocked(target *incState) []*incState {
	if target != nil {
		return []*incState{target}
	}
	if o := m.st.tracker.open; o != nil {
		return []*incState{o}
	}
	return nil
}
