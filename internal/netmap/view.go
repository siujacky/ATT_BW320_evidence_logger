package netmap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

var _ contracts.NetworkView = (*View)(nil)

// Limits of a request.
const (
	// MaxRange is the longest period a view covers: the firewall timeline then has at most 745
	// hours, and a request reads at most a month of samples and syslog.
	MaxRange = 31 * 24 * time.Hour
	// DefaultLimit and MaxLimit bound the table rows of a view (NetQuery.Limit).
	DefaultLimit = 200
	MaxLimit     = 1000
	// DefaultPeriod is the period of a request without a start (NetQuery.From zero).
	DefaultPeriod = 24 * time.Hour
)

// Defaults of the caches (Options).
const (
	// DefaultCacheBytes bounds the memory the cached chunk summaries take, by estimate: the
	// summaries of a month of two million firewall lines from 20,000 sources take about 32 MiB
	// (BenchmarkFirewallWarm). A flood of packets from distinct sources makes each summary larger
	// (about 45 KiB a chunk of spoofed SYNs): the newest are kept, and a request reads the others
	// again - work bounded by what the syslog store keeps, memory by the request's bounds.
	DefaultCacheBytes = 64 << 20
	// DefaultCacheChunks bounds their number: 30 days of chunks sealed every 5 minutes are 8,640.
	DefaultCacheChunks = 16384
	// DefaultResultTTL is how long a built view is reused for the same request - the same range
	// ending now ("24h"), or the same boundaries - so that a second tab, a refresh or the CLI do not
	// build it again within that time (the dashboard itself asks again every minute).
	DefaultResultTTL = 30 * time.Second
)

// ErrRange is wrapped by the error of a request whose period is not valid (to not after from,
// or longer than MaxRange), so that the web layer can answer 400.
var ErrRange = errors.New("netmap: invalid period")

// bounds are how much a view counts one by one. A hostile sender can multiply the sources of
// the packets the firewall drops (spoofed SYNs), a LAN host the remote addresses it tries, and a
// month of a busy household holds a million flows: without bounds, the memory and the work of
// one request would grow with them.
type bounds struct {
	// sources, outbound and services bound a firewall view's distinct inbound sources, outbound
	// rows (device, destination, port, protocol, reason) and inbound services (protocol, port)
	// counted one by one. Beyond them the packets still count in every total, by hour, reason
	// and direction; the sources by country and in sketches (Sources and the countries' Sites
	// become estimates within a few percent), the outbound rows in sketches (OutboundTotal and
	// the devices that name themselves become estimates), the services as "Other".
	sources, outbound, services int
	// heavy is how many of the sources and of the outbound rows beyond those bounds are kept by
	// weight (Space-Saving): any of them with more than 1/heavy of the packets beyond the bound
	// is among them, so the top lists still show the heaviest.
	heavy int
	// chunkRows and chunkHours bound a chunk's summary - far beyond what a chunk the store seals
	// at 1 MiB can hold: a chunk that holds more (a damaged or foreign file) is read straight
	// into the request's bounded sums and not kept.
	chunkRows, chunkHours int
	// flows bounds the flows a connections view names and draws: the heaviest ones; the others
	// count in the totals and as "Other".
	flows int
}

// defaultBounds keep a request's sums within a few tens of MiB.
var defaultBounds = bounds{
	sources:    100_000,
	outbound:   100_000,
	services:   1 << 17, // every TCP and UDP port
	heavy:      1024,
	chunkRows:  16_384,
	chunkHours: 1024,
	flows:      50_000,
}

// Options configures New. Conns, Intel and Syslog may each be nil: without the connection store
// Connections fails, without the syslog store Firewall fails (both with an error wrapping
// contracts.ErrUnavailable), and without the IP database addresses are classified (public,
// private, ...) but get no organisation or country, and ports no service name.
type Options struct {
	Conns  contracts.ConnStore
	Intel  contracts.IPIntel
	Syslog contracts.SyslogChunkSource
	Logger *slog.Logger
	// Now is the clock (default time.Now): the end of a request without one, and the age of
	// the views kept for reuse.
	Now func() time.Time
	// CacheBytes and CacheChunks bound the cache of sealed chunks' firewall summaries (defaults
	// DefaultCacheBytes and DefaultCacheChunks; a negative value disables the cache).
	CacheBytes  int64
	CacheChunks int
	// ResultTTL is how long a built view is reused for the same request (default
	// DefaultResultTTL; negative: never).
	ResultTTL time.Duration
}

// View builds the Network page (contracts.NetworkView). It is safe for concurrent use.
type View struct {
	conns  contracts.ConnStore
	intel  contracts.IPIntel
	syslog contracts.SyslogChunkSource
	log    *slog.Logger
	now    func() time.Time

	connResults *resultCache[model.NetConnections]
	fwResults   *resultCache[model.NetFirewall]

	// bounds is defaultBounds (tests lower it).
	bounds bounds

	// connSlot lets one connections view be built at a time: each build adds up a period's NAT
	// samples, seconds of CPU and up to hundreds of MiB for a month - work that requests side by
	// side (tabs, the CLI, a script) must not multiply inside the evidence logger.
	connSlot chan struct{}
	// fwSlot lets one firewall view be built at a time: the requests share the chunk cache
	// instead of reading the same chunks side by side. It also guards the fields below.
	fwSlot chan struct{}
	chunks *chunkCache
	codes  *codes
	// warned lists the chunks whose reading problem was logged already; namesWarned is set once
	// the problem of reading the Device List reads was logged.
	warned      map[string]bool
	namesWarned bool
}

// New returns a View over the given sources.
func New(o Options) *View {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.CacheBytes == 0 {
		o.CacheBytes = DefaultCacheBytes
	}
	if o.CacheChunks == 0 {
		o.CacheChunks = DefaultCacheChunks
	}
	if o.ResultTTL == 0 {
		o.ResultTTL = DefaultResultTTL
	}
	return &View{
		conns:       o.Conns,
		intel:       o.Intel,
		syslog:      o.Syslog,
		log:         o.Logger,
		now:         o.Now,
		connResults: newResultCache[model.NetConnections](o.ResultTTL, o.Now),
		fwResults:   newResultCache[model.NetFirewall](o.ResultTTL, o.Now),
		bounds:      defaultBounds,
		connSlot:    make(chan struct{}, 1),
		fwSlot:      make(chan struct{}, 1),
		chunks:      newChunkCache(o.CacheBytes, o.CacheChunks),
		codes:       newCodes(),
		warned:      map[string]bool{},
	}
}

// NetworkStatus reports the connection store, the IP database and the syslog kept (Samplers is
// left nil: the web layer takes it from the monitor's status). It never waits for file I/O.
func (v *View) NetworkStatus() model.NetworkStatus {
	var st model.NetworkStatus
	if v.conns != nil {
		u := v.conns.Usage()
		st.Store = &u
	}
	if v.intel != nil {
		s := v.intel.Status()
		st.IPIntel = &s
	}
	if v.syslog != nil {
		u := v.syslog.Usage()
		st.Syslog = &u
	}
	return st
}

// period returns the period [from, to) of a request in UTC: a zero To is now, a zero From is
// DefaultPeriod before To. It fails (ErrRange) unless from is before to and the period is at
// most MaxRange.
func (v *View) period(q contracts.NetQuery) (from, to time.Time, err error) {
	to = q.To
	if to.IsZero() {
		to = v.now()
	}
	from = q.From
	if from.IsZero() {
		from = to.Add(-DefaultPeriod)
	}
	switch {
	case !from.Before(to):
		return time.Time{}, time.Time{}, fmt.Errorf("%w: from (%s) must be before to (%s)", ErrRange,
			from.UTC().Format(time.RFC3339), to.UTC().Format(time.RFC3339))
	case to.Sub(from) > MaxRange:
		return time.Time{}, time.Time{}, fmt.Errorf("%w: at most %d days (asked for %.1f days)", ErrRange,
			int(MaxRange/(24*time.Hour)), to.Sub(from).Hours()/24)
	}
	return from.UTC(), to.UTC(), nil
}

// rowLimit returns the table rows a request asks for: DefaultLimit for 0 (or less), at most
// MaxLimit.
func rowLimit(n int) int {
	if n <= 0 {
		return DefaultLimit
	}
	return min(n, MaxLimit)
}

// acquireFW waits for the firewall slot (or for ctx to end).
func (v *View) acquireFW(ctx context.Context) error { return acquire(ctx, v.fwSlot) }

func (v *View) releaseFW() { <-v.fwSlot }

// acquireConn waits for the connections slot (or for ctx to end).
func (v *View) acquireConn(ctx context.Context) error { return acquire(ctx, v.connSlot) }

func (v *View) releaseConn() { <-v.connSlot }

// acquire waits for a place in slot (or for ctx to end).
func acquire(ctx context.Context, slot chan struct{}) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case slot <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// periodKey is the part of a result cache key that names a request's period: its range when it was
// asked by one ("range:24h" - a period that ends now, which a request moments later shares, so that
// a second tab, a refresh or the CLI within the reuse time do not build the view again), else its
// boundaries.
func periodKey(q contracts.NetQuery, from, to time.Time) string {
	if q.Range != "" {
		return "range:" + q.Range
	}
	return rfc3339(from) + "|" + rfc3339(to)
}

// rfc3339 formats t as the API states times: RFC 3339 UTC with nanoseconds.
func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// ipdb is when the IP database in use was written (RFC 3339 UTC; "" when none is loaded).
func (v *View) ipdb() string {
	if v.intel == nil {
		return ""
	}
	t := v.intel.Updated()
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
