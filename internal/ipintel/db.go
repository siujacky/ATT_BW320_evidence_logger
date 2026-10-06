package ipintel

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// Defaults (config.Default's geo section).
const (
	// DefaultURLv4 and DefaultURLv6 are the IPtoASN tables (public domain, PDDL 1.0): plain files,
	// the same for everyone, so downloading them reveals nothing about this network.
	DefaultURLv4 = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"
	DefaultURLv6 = "https://iptoasn.com/data/ip2asn-v6.tsv.gz"
	// DefaultRefresh is how often a newer database is looked for: the tables change a little every
	// day, and a week-old table still names the network of nearly every address.
	DefaultRefresh = 7 * 24 * time.Hour
	// MinRefresh bounds Refresh: the files are a free public service's, downloaded by everyone, and
	// looking more often than hourly would only load it.
	MinRefresh = time.Hour

	defaultUserAgent = "att-monitor (IP database download)"
)

// Files in the DB's directory (see the package documentation).
const (
	nameV4   = "ip2asn-v4.tsv.gz"
	nameV6   = "ip2asn-v6.tsv.gz"
	nameMeta = "ip2asn.json"
	namePTR  = "ptr-cache.json"
)

const (
	// tickEvery is how often Run wakes up when nothing else is due: to save the reverse DNS cache
	// and to notice table files placed or replaced by hand.
	tickEvery = 5 * time.Minute
	// minRoutedV4 and minRoutedV6: a downloaded table with fewer announced ranges is suspicious (the
	// real ones have several times more) and is not used.
	minRoutedV4 = 100_000
	minRoutedV6 = 10_000
)

// Resolver looks up the reverse DNS names of an address (*net.Resolver is one).
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// Options configures Open. Zero values select the defaults.
type Options struct {
	// Enabled turns on the IP database and the reverse DNS cache (geo.enabled). Without it Lookup
	// only classifies addresses, PTR returns "", and Run loads and downloads nothing.
	Enabled bool
	// Download fetches the tables into the directory when they are missing or cannot be loaded,
	// and looks for newer ones every Refresh (geo.download); without it, files placed there by
	// hand are used.
	Download bool
	// URLv4 and URLv6 are where the tables are downloaded from: https URLs without credentials,
	// query or fragment (default DefaultURLv4, DefaultURLv6). With Download, Open fails for any
	// other URL (checkURL).
	URLv4, URLv6 string
	// Refresh is the time between two looks for newer tables (default DefaultRefresh; at least
	// MinRefresh).
	Refresh time.Duration
	// ReverseDNS looks up, in the background, the reverse DNS names of the public addresses PTR is
	// asked to resolve (connections.reverse_dns).
	ReverseDNS bool
	// KeepDays, when above 0, is the longest a reverse DNS answer is kept current, should it be
	// shorter than the answer's time to live (connections.keep_days: the names of the addresses
	// shown are kept no longer than the samples that show them).
	KeepDays int
	// UserAgent is sent with the downloads (default "att-monitor (IP database download)").
	UserAgent string
	// HTTPClient is optional (tests). It is copied; the copy follows https redirects only and never
	// sends cookies.
	HTTPClient *http.Client
	// Resolver does the reverse DNS lookups (default net.DefaultResolver: this computer's).
	Resolver Resolver
	Logger   *slog.Logger // nil → discard
	// Now is the clock (default time.Now).
	Now func() time.Time
}

// DB is the offline IP database, the table of well-known ports and the reverse DNS cache
// (contracts.IPIntel). Open makes it; Run loads, downloads and resolves in the background. Its
// methods are safe for concurrent use and never wait for Run.
type DB struct {
	dir        string
	enabled    bool
	download   bool
	reverseDNS bool
	urls       [2]string // by family
	refresh    time.Duration
	userAgent  string
	source     string
	hc         *http.Client
	resolver   Resolver
	log        *slog.Logger
	now        func() time.Time

	// Set by Open to the defaults; tests change them before Run.
	after       func(time.Duration) <-chan time.Time
	tick        time.Duration
	minRouted   [2]int
	maxDownload int64
	ptrTimeout  time.Duration

	// tab is the loaded database. A load or download swaps in a new value; nil until the first.
	tab atomic.Pointer[tables]
	// running is set by the first Run.
	running atomic.Bool

	// Only Run's goroutine uses these.
	meta metaFile
	disk [2]fileState // each table file as last loaded, written or found missing
	// ptrSaveErr is the newest failure to save the reverse DNS cache, logged once until a save
	// works again.
	ptrSaveErr error

	mu sync.Mutex // guards st
	st state

	ptr *ptrCache
}

// state is the download schedule and the problems Status reports.
type state struct {
	checked  time.Time // the newest check that worked (new tables, or none newer)
	attempt  time.Time // the newest check
	failures int       // checks that failed in a row
	next     time.Time // when the next check is due (zero without Download)
	loadErr  [2]string // why the newest load of each table file failed
	dlErr    string    // why the newest check failed
	internal string    // the newest internal error (a panic recovered): a bug to report
}

// problem is the state's problems in one line ("" when there are none).
func (s *state) problem() string {
	var p []string
	for _, e := range []string{s.loadErr[fam4], s.loadErr[fam6], s.dlErr, s.internal} {
		if e != "" {
			p = append(p, e)
		}
	}
	return strings.Join(p, "; ")
}

var _ contracts.IPIntel = (*DB)(nil)

// Open returns the DB kept in dir (config.Paths.Geo). It is cheap: it reads nothing, downloads
// nothing and parses nothing - Run does. It fails when the database is enabled without a
// directory, or when it downloads and a download URL is not an https URL without credentials,
// query or fragment (checkURL).
func Open(dir string, opts Options) (*DB, error) {
	d := &DB{
		dir:         dir,
		enabled:     opts.Enabled,
		download:    opts.Enabled && opts.Download,
		reverseDNS:  opts.Enabled && opts.ReverseDNS,
		urls:        [2]string{cmp.Or(opts.URLv4, DefaultURLv4), cmp.Or(opts.URLv6, DefaultURLv6)},
		refresh:     opts.Refresh,
		userAgent:   cmp.Or(opts.UserAgent, defaultUserAgent),
		resolver:    opts.Resolver,
		log:         opts.Logger,
		now:         opts.Now,
		after:       time.After,
		tick:        tickEvery,
		minRouted:   [2]int{minRoutedV4, minRoutedV6},
		maxDownload: maxFileBytes,
		ptrTimeout:  ptrLookupTimeout,
		ptr:         newPTRCache(ptrMaxEntries, ptrQueueSize),
	}
	if opts.KeepDays > 0 {
		d.ptr.keep = time.Duration(opts.KeepDays) * 24 * time.Hour
	}
	if d.refresh <= 0 {
		d.refresh = DefaultRefresh
	}
	d.refresh = max(d.refresh, MinRefresh)
	if d.log == nil {
		d.log = slog.New(slog.DiscardHandler)
	}
	if d.now == nil {
		d.now = time.Now
	}
	if d.resolver == nil {
		d.resolver = net.DefaultResolver
	}
	if !d.enabled {
		return d, nil
	}
	if dir == "" {
		return nil, errors.New("ipintel: no directory for the IP database")
	}
	d.source = "IPtoASN (local files)"
	if d.download {
		for _, u := range d.urls {
			if err := checkURL(u); err != nil {
				return nil, err
			}
		}
		d.hc = newHTTPClient(opts.HTTPClient)
		if u, err := url.Parse(d.urls[fam4]); err == nil {
			d.source = "IPtoASN (" + u.Hostname() + ")"
		}
	}
	return d, nil
}

// checkURL accepts an https URL with a host, without credentials, query or fragment (as
// config.validateGeo does: the configuration is recorded in the evidence ledger, so a URL must
// carry no secret - neither a password nor a query such as a mirror's "?token=" - and the IPtoASN
// files need none). The error never repeats the URL's query or credentials.
func checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("ipintel: a download URL is not a URL")
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.ForceQuery {
		shown := *u
		shown.User, shown.RawQuery, shown.ForceQuery, shown.Fragment = nil, "", false, ""
		return fmt.Errorf("ipintel: %s is not an https:// URL without credentials, query or fragment", shown.String())
	}
	return nil
}

// Lookup classifies addr and, when it is public, names its network from the loaded database
// (Kind only until a table is loaded, or when the database does not know the address).
// IPv4-mapped and NAT64 addresses are named as the IPv4 address they carry.
func (d *DB) Lookup(addr netip.Addr) model.IPInfo {
	kind, a := classify(addr)
	info := model.IPInfo{Kind: kind}
	if kind != model.IPKindPublic || d == nil || !d.enabled {
		return info
	}
	t := d.tab.Load()
	if t == nil {
		return info
	}
	if n, org := t.lookup(a); n != nil {
		info.ASN, info.Org, info.ASName, info.Country = int(n.asn), org, n.name, n.country
	}
	return info
}

// Service names the service of a port ("tcp", 443 → "HTTPS"; "udp", 443 → "QUIC"; "icmp" →
// "ICMP"); "" when unknown. The protocol may be a name in any case or an IP protocol number.
func (d *DB) Service(proto string, port int) string { return serviceName(proto, port) }

// PTR returns the cached reverse DNS name of addr when it is public ("" when none is known, for
// any other address, or when the database is disabled). With resolve - and Options.ReverseDNS -
// an address not cached yet, or whose name is due for renewal, is queued for a lookup in the
// background (Run's workers), so that a later call may know it. It never waits for the network.
func (d *DB) PTR(addr netip.Addr, resolve bool) string {
	if d == nil || !d.enabled {
		return ""
	}
	kind, a := classify(addr)
	if kind != model.IPKindPublic {
		return ""
	}
	name, due := d.ptr.get(a, d.now())
	if due && resolve && d.reverseDNS {
		d.ptr.enqueue(a)
	}
	return name
}

// Updated is when the loaded database was written: the write time of the older of the loaded
// table files (zero when none is loaded).
func (d *DB) Updated() time.Time {
	if d == nil {
		return time.Time{}
	}
	if t := d.tab.Load(); t != nil {
		return t.updated()
	}
	return time.Time{}
}

// Status reports the database, its downloads and the reverse DNS cache.
func (d *DB) Status() model.IPIntelStatus {
	if d == nil {
		return model.IPIntelStatus{}
	}
	s := model.IPIntelStatus{Enabled: d.enabled, Download: d.download, Source: d.source, ReverseDNS: d.reverseDNS}
	if !d.enabled {
		return s
	}
	if t := d.tab.Load(); t != nil {
		s.V4Ranges, s.V6Ranges = t.v4.size(), t.v6.size()
		s.Loaded = s.V4Ranges+s.V6Ranges > 0
		s.Updated = rfc3339(t.updated())
	}
	d.mu.Lock()
	st := d.st
	d.mu.Unlock()
	s.Checked, s.Next, s.Error = rfc3339(st.checked), rfc3339(st.next), st.problem()
	s.PTRCached = d.ptr.size()
	return s
}

// update changes the state under its lock.
func (d *DB) update(fn func(*state)) {
	d.mu.Lock()
	fn(&d.st)
	d.mu.Unlock()
}

// rfc3339 formats t in UTC ("" for the zero time).
func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
