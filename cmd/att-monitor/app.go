package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"attmonitor/internal/anchor"
	"attmonitor/internal/config"
	"attmonitor/internal/connstore"
	"attmonitor/internal/contracts"
	"attmonitor/internal/export"
	"attmonitor/internal/gateway"
	"attmonitor/internal/ipintel"
	"attmonitor/internal/ledger"
	"attmonitor/internal/model"
	"attmonitor/internal/mongostore"
	"attmonitor/internal/monitor"
	"attmonitor/internal/netmap"
	"attmonitor/internal/probe"
	"attmonitor/internal/sysinfo"
	"attmonitor/internal/syslogrx"
	"attmonitor/internal/syslogstore"
	"attmonitor/internal/web"
	"attmonitor/internal/winsvc"
)

// stack is the fully wired application. Run() is only called for service/console mode;
// CLI commands that need ledger writes while the service is stopped use the same wiring
// without running the scheduler.
type stack struct {
	dataDir string
	paths   config.Paths
	cfg     *config.Config
	log     *slog.Logger
	closeLg func()

	host model.HostInfo
	sw   model.SoftwareInfo

	anchor *anchor.Client
	ledger *ledger.Store
	gw     *gateway.Client
	prober *probe.Prober
	mon    *monitor.Monitor
	exp    *export.Exporter
	// mongo copies the ledger into MongoDB (service and console modes, when enabled; nil
	// otherwise). The ledger stays the source of truth; see docs/DESIGN.md §17.
	mongo *mongostore.Replicator
	// syslog is the syslog store (docs/DESIGN.md §18; nil when it cannot be opened). The
	// service writes it when syslog.enabled, through the monitor, which then also runs syslogRx;
	// otherwise (the CLI, or syslog switched off) it is opened read-only and syslogRx is nil.
	syslog   *syslogstore.Store
	syslogRx *syslogrx.Receiver
	// The dashboard's Network page (docs/DESIGN.md §19), in the service and console
	// modes only (all nil in the CLI, which reads the page through the running service's API):
	// conns is the connection store the monitor's samplers write (nil when it cannot be opened),
	// intel the offline IP database (runMonitor runs it), network the view the dashboard asks,
	// built over both and the syslog store. None of it is evidence: nothing of it reaches the
	// ledger, the MongoDB copy or an evidence bundle.
	conns   *connstore.Store
	intel   *ipintel.DB
	network *netmap.View
}

type stackOptions struct {
	dataDir  string
	mode     string // "service" | "console" | "cli"
	extraLog slog.Handler
	console  bool // also log to stderr
}

func userAgent() string { return "att-monitor/" + version }

// openStack wires every component. The caller must call close().
func openStack(o stackOptions) (*stack, error) {
	s := &stack{dataDir: o.dataDir, paths: config.PathsFor(o.dataDir)}
	if o.mode == "cli" {
		// CLI commands write into an EXISTING ledger only: a mistyped --data must never create a
		// second ledger with a new key and quietly put operator notes or custody records there.
		if !hasLedger(s.paths.Ledger) {
			return nil, fmt.Errorf("no evidence ledger found in %s (is the service using a different --data directory?)", o.dataDir)
		}
	}
	// The syslog store's folder is left to openSyslog, and the Network page's folders to the
	// connection store and the IP database: a problem with them must not keep the evidence
	// collection from starting.
	layout := s.paths
	layout.Syslog, layout.Connections, layout.Geo = layout.Root, layout.Root, layout.Root
	if err := layout.MkdirAll(); err != nil {
		return nil, fmt.Errorf("data directory %s: %w", o.dataDir, err)
	}
	var keysACLErr error
	if o.mode == "service" {
		// Running as LocalSystem: (re)assert the private ACL on keys\ before any secret is
		// created or read. Console mode as a normal user must not lock itself out of its keys.
		keysACLErr = winsvc.SecurePrivateDir(s.paths.Keys)
	}
	// The operational log comes before the configuration, so that a config.json the monitor
	// cannot work with is explained in logs\service.log too, not only in the Windows Event Log.
	lg, closeLg, err := newLogger(s.paths.Logs, o.mode, o.console, o.extraLog)
	if err != nil {
		return nil, err
	}
	s.log, s.closeLg = lg, closeLg
	if keysACLErr != nil {
		lg.Error("could not secure the keys directory", "dir", s.paths.Keys, "err", keysACLErr)
	}
	cfg, err := config.LoadOrCreate(s.paths.Config)
	if err != nil {
		lg.Error("config.json cannot be used: it must be corrected first", "file", s.paths.Config, "err", err)
		s.close()
		return nil, err
	}
	s.cfg = cfg
	// A setting of the Network page never stops the start: what could not be used as written was
	// replaced, and is said here (and in the page's status: networkView).
	for _, w := range cfg.Warnings() {
		lg.Warn("config.json: a setting of the Network page is not used as written", "setting", w)
	}

	s.host = sysinfo.Host()
	s.sw = sysinfo.Software(version, commit, monitor.RulesVersion)

	s.anchor = anchor.New(anchor.Options{
		URLs:      cfg.Anchoring.TSAURLs,
		Timeout:   cfg.Anchoring.Timeout.Duration,
		UserAgent: userAgent(),
		Logger:    lg.With("component", "anchor"),
	})

	s.ledger, err = ledger.Open(ledger.Options{
		Paths:         s.paths,
		Host:          s.host,
		Software:      s.sw,
		TokenVerifier: s.anchor,
		FastInterval:  cfg.Probes.FastInterval.Duration,
		Logger:        lg.With("component", "ledger"),
	})
	if err != nil {
		s.close()
		return nil, fmt.Errorf("open evidence ledger: %w", err)
	}
	if s.ledger.Created() {
		lg.Info("new evidence ledger created", "fingerprint", s.ledger.Fingerprint())
	}
	if o.mode != "cli" {
		s.importBootstrapOnce()
	}
	// After the ledger: its writer lock keeps a second monitor, and so a second writer of the
	// syslog store and of the connection store, away.
	s.openSyslog(o.mode)
	if o.mode != "cli" {
		s.openNetwork()
	}

	// The login policy outlives the process (loginpolicy.go): a restart, even in a loop, gives no
	// new allowance of login attempts.
	policy, saved := openLoginPolicy(s.paths.State, lg.With("component", "gateway"))
	s.gw = gateway.New(gateway.Options{
		Host:             cfg.Gateway.Host,
		Scheme:           cfg.Gateway.Scheme,
		PinnedCertSHA256: cfg.Gateway.PinnedCertSHA256,
		Timeout:          cfg.Gateway.Timeout.Duration,
		AccessCode:       cfg.AccessCode,
		UserAgent:        userAgent(),
		Logger:           lg.With("component", "gateway"),
		LoginPolicy:      saved,
		OnLoginPolicy:    policy.save,
	})
	s.prober = probe.New(probe.Options{
		Logger:    lg.With("component", "probe"),
		UserAgent: userAgent(),
		GatewayIP: cfg.Gateway.Host, // hijack detection: answers pointing at the gateway itself
	})

	var anchorer contracts.Anchorer
	if cfg.Anchoring.Enabled {
		anchorer = s.anchor
	}
	var mongoStatus func() model.MongoStatus
	if o.mode != "cli" && cfg.Mongo.Enabled {
		s.mongo, err = mongostore.New(mongostore.Options{
			URI:        cfg.Mongo.URI,
			Database:   cfg.Mongo.Database,
			Reader:     s.ledger,
			StoreBlobs: cfg.Mongo.StoreBlobs,
			Interval:   cfg.Mongo.Interval.Duration,
			Logger:     lg.With("component", "mongo"),
			Syslog:     s.syslogReader(),
		})
		if err != nil {
			// The copy is a convenience: evidence collection goes on without it.
			lg.Error("MongoDB copy disabled", "err", err)
			s.mongo = nil
		} else {
			mongoStatus = s.mongo.Status
		}
	}
	s.mon, err = monitor.New(monitor.Options{
		Config:      cfg,
		SaveConfig:  func(c *config.Config) error { return config.Save(s.paths.Config, c) },
		Ledger:      s.ledger,
		Reader:      s.ledger,
		Verifier:    s.ledger,
		Gateway:     s.gw,
		Prober:      s.prober,
		Anchorer:    anchorer,
		Software:    s.sw,
		Host:        s.host,
		Mode:        o.mode,
		Listen:      cfg.Web.Listen,
		DataDir:     o.dataDir,
		StateDir:    s.paths.State,
		Logger:      lg.With("component", "monitor"),
		MongoStatus: mongoStatus,
		Syslog:      s.syslogReceiver(),
		SyslogStore: s.syslogWriter(),
		Conns:       s.connStore(),
	})
	if err != nil {
		s.close()
		return nil, fmt.Errorf("monitor: %w", err)
	}
	s.exp = export.New(export.Options{
		Dir:           s.paths.Exports,
		Reader:        s.ledger,
		Verifier:      s.ledger,
		Actions:       s.mon,
		TokenVerifier: s.anchor, // per-anchor chain verdict: only chain-trusted tokens prove time
		Syslog:        s.syslogReader(),
		// keys/tsa-roots.pem lets anyone run `openssl ts -verify -attime … -CAfile keys/tsa-roots.pem`.
		ExtraFiles: map[string][]byte{"keys/tsa-roots.pem": tsaRootsPEM},
		Software:   s.sw,
		Logger:     lg.With("component", "export"),
	})
	return s, nil
}

// openSyslog opens the syslog store and the receiver of the gateway's syslog messages
// (docs/DESIGN.md §18). The service and console modes write the store when syslog.enabled: the
// monitor runs the receiver, moves what it receives into the store and records every chunk the
// store seals (syslog_chunk) and every deletion (syslog_prune). Otherwise - the CLI, whose
// exports read the chunks while the service is stopped, or syslog switched off - the store is
// only read, so that the dashboard, exports and the MongoDB copy still find the chunks kept so
// far; nothing then writes it. A store that cannot be opened is logged, and evidence collection
// goes on without syslog.
func (s *stack) openSyslog(mode string) {
	sc := s.cfg.Syslog
	lg := s.log.With("component", "syslog")
	if mode == "cli" || !sc.Enabled {
		st, err := openSyslogReader(s.paths.Syslog, sc, lg)
		switch {
		case errors.Is(err, os.ErrNotExist):
			lg.Debug("no syslog store to read", "dir", s.paths.Syslog)
		case err != nil:
			lg.Warn("the syslog store cannot be read; its chunks are left out of exports and the dashboard", "dir", s.paths.Syslog, "err", err)
		default:
			s.syslog = st
		}
		return
	}
	st, err := syslogstore.New(syslogstore.Options{Dir: s.paths.Syslog, KeepMB: sc.KeepMB, KeepDays: sc.KeepDays, Logger: lg.With("part", "store")})
	if err != nil {
		lg.Error("syslog is off: the syslog store cannot be opened", "dir", s.paths.Syslog, "err", err)
		return
	}
	rx, err := syslogrx.New(syslogrx.Options{
		Listen:       sc.Listen,
		Allowed:      syslogSenders(s.cfg),
		MaxPerMinute: sc.MaxPerMinute,
		Logger:       lg.With("part", "receiver"),
	})
	if err != nil {
		lg.Error("syslog is off: the syslog receiver cannot be set up", "listen", sc.Listen, "err", err)
		if cerr := st.Close(); cerr != nil {
			lg.Warn("closing the syslog store", "err", cerr)
		}
		return
	}
	s.syslog, s.syslogRx = st, rx
}

// openSyslogReader opens the syslog store in dir read-only: it indexes the sealed chunks as they
// are now and reads the writer's open chunk as it grows (a snapshot: open a new one per command).
// Its limits are only reported (Usage). The error wraps os.ErrNotExist when there is no store.
func openSyslogReader(dir string, sc config.SyslogConfig, lg *slog.Logger) (*syslogstore.Store, error) {
	return syslogstore.New(syslogstore.Options{Dir: dir, KeepMB: sc.KeepMB, KeepDays: sc.KeepDays, ReadOnly: true, Logger: lg})
}

// syslogSenders returns the senders the syslog receiver accepts: the gateway and syslog.allow
// (the configuration's validation makes them IP addresses; anything else is skipped). The
// monitor sets the same list again when it starts.
func syslogSenders(cfg *config.Config) []netip.Addr {
	var out []netip.Addr
	for _, h := range append([]string{cfg.Gateway.Host}, cfg.Syslog.Allow...) {
		if a, err := netip.ParseAddr(strings.TrimSpace(h)); err == nil && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}

// syslogReader is the syslog store for its readers: the dashboard, exports and the MongoDB copy
// (nil, an untyped nil, when there is none).
func (s *stack) syslogReader() contracts.SyslogReader {
	if s.syslog == nil {
		return nil
	}
	return s.syslog
}

// syslogWriter is the syslog store for the monitor: only when this process writes it.
func (s *stack) syslogWriter() contracts.SyslogStore {
	if s.syslog == nil || s.syslogRx == nil {
		return nil
	}
	return s.syslog
}

// syslogReceiver is the syslog receiver for the monitor (nil when the store is not written).
func (s *stack) syslogReceiver() contracts.SyslogReceiver {
	if s.syslogRx == nil {
		return nil
	}
	return s.syslogRx
}

// syslogChunks is the syslog store for the Network page's firewall view (nil, an untyped nil,
// when there is none).
func (s *stack) syslogChunks() contracts.SyslogChunkSource {
	if s.syslog == nil {
		return nil
	}
	return s.syslog
}

// openNetwork opens what the dashboard's Network page reads (docs/DESIGN.md §19) and
// builds its view: the connection store, the offline IP database and the syslog store. Only the
// service and console modes call it, after the ledger: the connection store has a single writer
// (it repairs when it opens, then compresses and prunes in the background), and the ledger lock
// makes it this process. None of it is evidence, and none of it may keep evidence collection from
// starting: a part that cannot be opened is logged, and the page shows what the others give; a
// setting of the page that config.json gives out of range, or in a form that cannot be read, was
// replaced by config.Load (logged by openStack, and shown by the page's status).
//
// The connection store is opened also with connections.enabled off: the monitor's samplers then
// do not run and its status says so, the page still shows what was recorded before, and the
// monitor still applies the store's retention limits every hour (and deletes the raw page copies)
// - nothing would otherwise ever delete the oldest samples. The IP database is opened also with
// geo.enabled off: it then only classifies addresses and names ports, and its status tells the
// page why organisations and countries are missing.
// Open reads nothing and downloads nothing; runMonitor runs it.
func (s *stack) openNetwork() {
	cc, gc := s.cfg.Connections, s.cfg.Geo
	clg := s.log.With("component", "connections")
	st, err := connstore.Open(s.paths.Connections, connstore.Options{KeepDays: cc.KeepDays, KeepMB: cc.KeepMB, Logger: clg})
	if err != nil {
		clg.Error("the Network page runs without connection samples: the connection store cannot be opened", "dir", s.paths.Connections, "err", err)
	} else {
		s.conns = st
	}
	glg := s.log.With("component", "ipintel")
	db, err := ipintel.Open(s.paths.Geo, ipintel.Options{
		Enabled:    gc.Enabled,
		Download:   gc.Download,
		URLv4:      gc.URLv4,
		URLv6:      gc.URLv6,
		Refresh:    gc.Refresh.Duration,
		ReverseDNS: cc.ReverseDNS,
		KeepDays:   cc.KeepDays,
		UserAgent:  userAgent(),
		Logger:     glg,
	})
	if err != nil {
		glg.Error("the Network page runs without the IP database: organisations and countries are not shown", "dir", s.paths.Geo, "err", err)
	} else {
		s.intel = db
	}
	s.network = netmap.New(netmap.Options{
		Conns:  s.connStore(),
		Intel:  s.ipIntel(),
		Syslog: s.syslogChunks(),
		Logger: s.log.With("component", "network"),
	})
}

// connStore is the connection store for the monitor and the network view (nil, an untyped nil,
// when there is none).
func (s *stack) connStore() contracts.ConnStore {
	if s.conns == nil {
		return nil
	}
	return s.conns
}

// ipIntel is the IP database for the network view (nil, an untyped nil, when there is none).
func (s *stack) ipIntel() contracts.IPIntel {
	if s.intel == nil {
		return nil
	}
	return s.intel
}

// networkView is the Network page's view for the dashboard (nil, an untyped nil, in the CLI:
// the endpoints then answer 404). When the configuration replaced settings of the page
// (config.Warnings), its status says which (configWarned), so that GET /api/network/status and
// `att-monitor network` show it.
func (s *stack) networkView() contracts.NetworkView {
	if s.network == nil {
		return nil
	}
	if w := s.cfg.Warnings(); len(w) > 0 {
		return configWarned{NetworkView: s.network, warnings: w}
	}
	return s.network
}

// configWarned is a network view whose status also carries the configuration's warnings about the
// Network page's settings (model.NetworkStatus.ConfigWarnings).
type configWarned struct {
	contracts.NetworkView
	warnings []string
}

// NetworkStatus is the view's status with the warnings (a new slice every time).
func (v configWarned) NetworkStatus() model.NetworkStatus {
	ns := v.NetworkView.NetworkStatus()
	ns.ConfigWarnings = slices.Concat(ns.ConfigWarnings, v.warnings)
	return ns
}

// importBootstrapOnce imports cfg.BootstrapDir if no bootstrap_import record exists yet. The
// import belongs right after genesis, so only the first records are searched; a failed import
// is retried on the next start instead of being lost.
func (s *stack) importBootstrapOnce() {
	dir := s.cfg.BootstrapDir
	if dir == "" {
		return
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		s.log.Warn("bootstrap_dir configured but not found", "dir", dir)
		return
	}
	found, seen := false, 0
	err := s.ledger.Scan(0, func(_ model.Envelope, b model.Body) error {
		seen++
		if b.Type == model.TypeBootstrapImport {
			found = true
			return contracts.ErrStop
		}
		if seen >= 500 {
			return contracts.ErrStop
		}
		return nil
	})
	if err != nil {
		s.log.Error("scanning ledger for bootstrap import", "err", err)
		return
	}
	if found {
		return
	}
	if seen >= 500 {
		// Far past genesis: importing now would misrepresent when the files entered the ledger.
		s.log.Warn("bootstrap evidence was never imported and the ledger is no longer new; not importing", "dir", dir)
		return
	}
	ref, err := s.ledger.ImportBootstrap(dir)
	if err != nil {
		s.log.Error("bootstrap import failed (will retry at next start)", "dir", dir, "err", err)
		return
	}
	s.log.Info("bootstrap evidence imported", "dir", dir, "seq", ref.Seq)
}

func (s *stack) close() {
	if s.conns != nil {
		// The monitor has stopped, and with it the samplers that append: Close releases the day
		// files being appended to (the network view may still read them).
		if err := s.conns.Close(); err != nil && s.log != nil {
			s.log.Error("closing the connection store", "err", err)
		}
		s.conns = nil
	}
	if s.syslog != nil {
		// The monitor sealed the open chunk when it stopped; Close releases what is left open (a
		// chunk the ledger could not record is sealed by the next start's Recover).
		if err := s.syslog.Close(); err != nil && s.log != nil {
			s.log.Error("closing the syslog store", "err", err)
		}
		s.syslog = nil
	}
	if s.ledger != nil {
		if err := s.ledger.Close(); err != nil && s.log != nil {
			s.log.Error("closing ledger", "err", err)
		}
		s.ledger = nil
	}
	if s.closeLg != nil {
		s.closeLg()
		s.closeLg = nil
	}
}

// runMonitor runs the scheduler and the dashboard until ctx is cancelled.
func runMonitor(ctx context.Context, o stackOptions, power <-chan string) error {
	s, err := openStack(o)
	if err != nil {
		return err
	}
	defer s.close()

	srv, err := web.New(web.Options{
		Listen:        s.cfg.Web.Listen,
		Status:        s.mon,
		Actions:       s.mon,
		Reader:        s.ledger,
		Verifier:      s.ledger,
		Exporter:      s.exp,
		SyslogReader:  s.syslogReader(),
		SyslogControl: s.mon,
		LiveTraffic:   s.mon,
		Network:       s.networkView(),
		Version:       version,
		Logger:        s.log.With("component", "web"),
	})
	if err != nil {
		return fmt.Errorf("web server: %w", err)
	}

	runCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	var wg sync.WaitGroup
	if power != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-runCtx.Done():
					return
				case ev, ok := <-power:
					if !ok {
						return
					}
					if runCtx.Err() != nil {
						// Shutting down: the stop reason travels via context.Cause; recording a
						// power_event now could land after monitor_stop.
						return
					}
					s.mon.PowerEvent(ev)
				}
			}
		}()
	}

	if s.mongo != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Like the dashboard, the MongoDB copy never stops evidence collection.
			if err := s.mongo.Run(runCtx); err != nil && !errors.Is(err, context.Canceled) {
				s.log.Error("MongoDB copy stopped", "err", err)
			}
		}()
	}

	if s.intel != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// The IP database loads, downloads and looks up reverse DNS names in the background
			// until the stop, then saves its reverse DNS cache. It never stops evidence collection:
			// it recovers from its own failures (also a panic) and reports them in its status.
			s.intel.Run(runCtx)
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		// The dashboard is a convenience; if it cannot listen (port in use) the evidence
		// collection must continue, so a web failure is logged, not fatal.
		if err := srv.Run(runCtx); err != nil && !errors.Is(err, context.Canceled) {
			s.log.Error("dashboard stopped", "err", err, "listen", s.cfg.Web.Listen)
		}
	}()

	syslogListen := "off"
	if s.syslogRx != nil {
		syslogListen = "udp " + s.cfg.Syslog.Listen
	}
	s.log.Info("att-monitor running", "version", version, "mode", o.mode, "data", o.dataDir,
		"dashboard", "http://"+s.cfg.Web.Listen, "syslog", syslogListen, "fingerprint", s.ledger.Fingerprint())
	err = s.mon.Run(runCtx)
	cancel(errors.New("monitor stopped"))
	wg.Wait()
	if s.mongo != nil {
		// One last pass copies the monitor_stop record. The budget is short because Windows
		// allows little time at shutdown; whatever is not copied now is copied at the next start.
		fctx, fcancel := context.WithTimeout(context.Background(), mongoFinalSync)
		switch _, serr := s.mongo.SyncOnce(fctx); {
		case errors.Is(serr, mongostore.ErrIntegrity):
			s.log.Warn("MongoDB copy disagrees with the ledger; run att-monitor mongo verify", "err", serr)
		case serr != nil:
			s.log.Info("MongoDB copy: final pass incomplete; it continues at the next start", "err", serr)
		}
		if cerr := s.mongo.Close(fctx); cerr != nil {
			s.log.Info("MongoDB copy: closing", "err", cerr)
		}
		fcancel()
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// mongoFinalSync bounds the MongoDB pass made after the monitor stops.
const mongoFinalSync = 2 * time.Second

// hasLedger reports whether dir holds at least one ledger segment.
func hasLedger(dir string) bool {
	for _, pat := range []string{"ledger-*.jsonl", "ledger-*.jsonl.gz"} {
		if m, _ := filepath.Glob(filepath.Join(dir, pat)); len(m) > 0 {
			return true
		}
	}
	return false
}

// defaultDataDir resolves --data or the default ProgramData location.
func defaultDataDir(flagValue string) string {
	if flagValue != "" {
		abs, err := filepath.Abs(flagValue)
		if err == nil {
			return abs
		}
		return flagValue
	}
	return config.DefaultDataDir()
}

// now is replaced in tests.
var now = time.Now
