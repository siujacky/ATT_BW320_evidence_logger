package export

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"attmonitor/internal/model"
)

// rulesDescribed is the classifier version whose rules the report explains in prose
// (docs/DESIGN.md §9-§10).
const rulesDescribed = "2026.10-4"

// Documented defaults (docs/DESIGN.md §8-§10). They equal internal/config.Default(), which
// this package does not import (it is Windows-only); TestThresholdDefaultsMatchConfig pins them.
const (
	defaultFastInterval       = 10 * time.Second
	defaultProbeTimeout       = 2 * time.Second
	defaultOpenAfterCycles    = 3
	defaultCloseAfterCycles   = 3
	defaultWindowCycles       = 6
	defaultLossDegradedPct    = 20.0
	defaultLatencyDegradedMs  = 150.0
	defaultGatewayLatencyOkMs = 20.0
	defaultSnapshotFreshness  = 150 * time.Second

	// restartMoveThreshold: a gateway boot time that moved by more than this is a restart;
	// restartWindowCap: a restart window ends at most this long after the boot (§10).
	restartMoveThreshold = 120 * time.Second
	restartWindowCap     = 10 * time.Minute
)

// defaultInternetTargets are the internet-role probe targets of the default configuration.
var defaultInternetTargets = []string{"1.1.1.1", "8.8.8.8", "9.9.9.9", "1.1.1.1:443", "8.8.8.8:443"}

// cfgDuration decodes a configuration duration like internal/config.Duration: a Go duration
// string ("10s") or an integer number of nanoseconds.
type cfgDuration time.Duration

func (d *cfgDuration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		var n int64
		if err2 := json.Unmarshal(b, &n); err2 != nil {
			return fmt.Errorf("duration: %w", err)
		}
		*d = cfgDuration(n)
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = cfgDuration(v)
	return nil
}

// recordedConfig is the part of the configuration recorded in monitor_start.config and
// config_state.config (the JSON of internal/config.Config, secrets removed) that the report
// quotes.
type recordedConfig struct {
	Probes struct {
		FastInterval cfgDuration        `json:"fast_interval"`
		Timeout      cfgDuration        `json:"timeout"`
		Targets      *[]model.ProbeSpec `json:"targets"` // nil: not recorded (defaults apply)
	} `json:"probes"`
	Incident struct {
		OpenAfterCycles    int         `json:"open_after_cycles"`
		CloseAfterCycles   int         `json:"close_after_cycles"`
		WindowCycles       int         `json:"window_cycles"`
		LossDegradedPct    float64     `json:"loss_degraded_pct"`
		LatencyDegradedMs  float64     `json:"latency_degraded_ms"`
		GatewayLatencyOkMs float64     `json:"gateway_latency_ok_ms"`
		SnapshotFreshness  cfgDuration `json:"snapshot_freshness"`
	} `json:"incident"`
}

// params are the effective classifier and incident parameters of one configuration.
type params struct {
	fast, timeout, fresh time.Duration
	open, close, window  int
	loss, lat, gwLat     float64
	targets              []string // internet-role probe targets
}

func defaultParams() params {
	return params{fast: defaultFastInterval, timeout: defaultProbeTimeout, fresh: defaultSnapshotFreshness,
		open: defaultOpenAfterCycles, close: defaultCloseAfterCycles, window: defaultWindowCycles,
		loss: defaultLossDegradedPct, lat: defaultLatencyDegradedMs, gwLat: defaultGatewayLatencyOkMs,
		targets: append([]string(nil), defaultInternetTargets...)}
}

// parseRecordedConfig decodes a recorded configuration (monitor_start.config or
// config_state.config). Absent fields keep the defaults and values
// the monitor would not use are normalized the way it normalizes them (zero or negative
// thresholds mean the default; the window is never shorter than the open threshold), so the
// quoted values are the ones the classifier applied.
func parseRecordedConfig(raw json.RawMessage) (params, error) {
	p := defaultParams()
	var rc recordedConfig
	rc.Probes.FastInterval = cfgDuration(p.fast)
	rc.Probes.Timeout = cfgDuration(p.timeout)
	rc.Incident.SnapshotFreshness = cfgDuration(p.fresh)
	rc.Incident.OpenAfterCycles, rc.Incident.CloseAfterCycles, rc.Incident.WindowCycles = p.open, p.close, p.window
	rc.Incident.LossDegradedPct, rc.Incident.LatencyDegradedMs, rc.Incident.GatewayLatencyOkMs = p.loss, p.lat, p.gwLat
	if err := json.Unmarshal(raw, &rc); err != nil {
		return p, err
	}
	if v := time.Duration(rc.Probes.FastInterval); v > 0 {
		p.fast = v
	}
	if v := time.Duration(rc.Probes.Timeout); v > 0 {
		p.timeout = v
	}
	if v := time.Duration(rc.Incident.SnapshotFreshness); v > 0 {
		p.fresh = v
	}
	in := rc.Incident
	if in.OpenAfterCycles >= 1 {
		p.open = in.OpenAfterCycles
	}
	if in.CloseAfterCycles >= 1 {
		p.close = in.CloseAfterCycles
	}
	if in.WindowCycles >= 1 {
		p.window = in.WindowCycles
	}
	p.window = max(p.window, p.open)
	if in.LossDegradedPct > 0 {
		p.loss = in.LossDegradedPct
	}
	if in.LatencyDegradedMs > 0 {
		p.lat = in.LatencyDegradedMs
	}
	if in.GatewayLatencyOkMs > 0 {
		p.gwLat = in.GatewayLatencyOkMs
	}
	if rc.Probes.Targets != nil {
		p.targets = nil
		for _, t := range *rc.Probes.Targets {
			if t.Role == model.RoleInet && t.Target != "" {
				p.targets = append(p.targets, t.Target)
			}
		}
	}
	return p, nil
}

// diff lists the parameters that differ from q (the previous configuration) as "name old -> new".
func (p params) diff(q params) []string {
	var out []string
	add := func(name, old, cur string) {
		if old != cur {
			out = append(out, fmt.Sprintf("%s %s -> %s", name, old, cur))
		}
	}
	add("fast_interval", q.fast.String(), p.fast.String())
	add("probe timeout", q.timeout.String(), p.timeout.String())
	add("open_after_cycles", strconv.Itoa(q.open), strconv.Itoa(p.open))
	add("close_after_cycles", strconv.Itoa(q.close), strconv.Itoa(p.close))
	add("window_cycles", strconv.Itoa(q.window), strconv.Itoa(p.window))
	add("loss_degraded_pct", fmtNum(q.loss), fmtNum(p.loss))
	add("latency_degraded_ms", fmtNum(q.lat), fmtNum(p.lat))
	add("gateway_latency_ok_ms", fmtNum(q.gwLat), fmtNum(p.gwLat))
	add("snapshot_freshness", q.fresh.String(), p.fresh.String())
	add("internet targets", strings.Join(q.targets, ", "), strings.Join(p.targets, ", "))
	return out
}

func (p params) toThresholds() thresholds {
	return thresholds{
		FastIntervalSec: p.fast.Seconds(), ProbeTimeoutSec: p.timeout.Seconds(),
		OpenAfterCycles: p.open, CloseAfterCycles: p.close, WindowCycles: p.window,
		LossDegradedPct: p.loss, LatencyDegradedMs: p.lat, GatewayLatencyOkMs: p.gwLat,
		SnapshotFreshnessSec: p.fresh.Seconds(),
		CoverCapSec:          coverCap(p.fast).Seconds(), GapLimitSec: gapLimit(p.fast).Seconds(),
		RestartMoveSec: restartMoveThreshold.Seconds(), RestartCapSec: restartWindowCap.Seconds(),
		InternetTargets: append([]string(nil), p.targets...),
	}
}

// coverCap is the longest time one cycle covers in the time accounting: 1.5 × the cycle
// interval; gapLimit is the spacing beyond which samples are separated by a monitoring gap.
func coverCap(fast time.Duration) time.Duration {
	if fast <= 0 {
		fast = defaultFastInterval
	}
	return fast * 3 / 2
}

func gapLimit(fast time.Duration) time.Duration {
	if fast <= 0 {
		fast = defaultFastInterval
	}
	return 3 * fast
}

// fmtNum renders a threshold without needless decimals: 20 -> "20", 12.5 -> "12.5".
func fmtNum(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

// fmtSecs renders a duration in seconds for prose: 10 -> "10 s", 2.5 -> "2.5 s", 600 -> "10 min".
func fmtSecs(sec float64) string {
	if sec >= 120 && float64(int64(sec/60))*60 == sec {
		return fmtNum(sec/60) + " min"
	}
	return fmtNum(sec) + " s"
}

// ------------------------------------------------------------------ configuration records

// How the configuration record the thresholds are quoted from was chosen
// (methodology.config_source.basis).
const (
	// basisAtOrBefore: the latest configuration record of the bundle at or before the start of
	// the period.
	basisAtOrBefore = "at_or_before_period_start"
	// basisFirstInPeriod: no configuration record at or before the start of the period applies;
	// the first one in the period was written by the monitor process that wrote every earlier
	// record of the period.
	basisFirstInPeriod = "first_in_period"
)

// cfgRec is a record of the bundle that states the monitor's configuration (secrets removed):
// monitor_start, written at every process start, or config_state, written right after the start
// of every daily ledger segment (docs/DESIGN.md §7).
type cfgRec struct {
	typ        string // model.TypeMonitorStart | model.TypeConfigState
	seq        uint64
	ts         time.Time
	tsOK       bool
	run        int32
	hash       string          // config_sha256 as recorded
	raw        json.RawMessage // the recorded configuration (set with params)
	params     *params         // nil: the record states no (readable) configuration
	cfgErr     string          // the recorded configuration cannot be read
	payloadErr string          // the record's payload cannot be read at all
}

// at renders the record's time for prose.
func (r *cfgRec) at() string { return fmtUTC(r.ts.UTC().Format(time.RFC3339Nano)) }

// missing says why a configuration record states no configuration.
func (r *cfgRec) missing() string {
	switch {
	case r.payloadErr != "":
		return "cannot be read by this report (" + r.payloadErr + ")"
	case r.cfgErr != "":
		return "contains a configuration this report cannot read (" + r.cfgErr + ")"
	case r.typ == model.TypeMonitorStart:
		return "does not contain the configuration (it was written by software that predates this field)"
	}
	return "does not contain the configuration"
}

// periodLead follows the records of the period up to its first configuration record with a
// readable configuration (basisFirstInPeriod): it is usable only if every record of the period
// before it was written by the same monitor process.
type periodLead struct {
	n     int   // records of the period seen
	run   int32 // the process that wrote the first of them
	done  bool  // a record of another process came first, or the configuration record was found
	first int   // index into aggregator.configs of that configuration record (-1: none)
}

// periodRecord notes a record of the period (in ledger order) for periodLead.
func (a *aggregator) periodRecord(run string) {
	l := &a.lead
	if l.done {
		return
	}
	r := a.runIndex(run)
	switch {
	case l.n == 0:
		l.run = r
	case r != l.run:
		l.done = true // another process wrote records of the period before any configuration record
	}
	l.n++
}

// addConfigRecord notes a configuration record: hash and raw as recorded; payloadErr when its
// payload cannot be decoded at all (a process start without a readable configuration still ends
// what is known about the configuration).
func (c *collector) addConfigRecord(body model.Body, ts time.Time, tsOK, inWin bool, hash string, raw json.RawMessage, payloadErr error) {
	a := &c.agg
	r := cfgRec{typ: body.Type, seq: body.Seq, ts: ts, tsOK: tsOK, run: a.runIndex(body.Run), hash: hash}
	raw = bytes.TrimSpace(raw)
	switch {
	case payloadErr != nil:
		r.payloadErr = truncate(oneLine(payloadErr.Error()), 200)
	case len(raw) == 0 || bytes.Equal(raw, []byte("null")):
	default:
		if p, err := parseRecordedConfig(raw); err != nil {
			r.cfgErr = truncate(oneLine(err.Error()), 200)
		} else {
			r.params, r.raw = &p, append(json.RawMessage(nil), raw...)
		}
	}
	a.configs = append(a.configs, r)
	if inWin && !a.lead.done && r.params != nil {
		// periodRecord saw this record already: every record of the period so far is its process's.
		a.lead.first, a.lead.done = len(a.configs)-1, true
	}
}

// resolveThresholds finds the configuration in force at the start of the period and lists the
// other configurations recorded in the period. The source is the latest configuration record of
// the bundle at or before the start of the period, provided it states a readable configuration
// and the bundle shows that no other process started in between (ledger segments left out after
// it are covered only when the first record after them was written by the same process).
// Otherwise it is the first configuration record of the period, if every earlier record of the
// period was written by the process that wrote it (a monitor process keeps the thresholds it
// started with). Only when neither exists are the documented defaults shown, with a note.
func (c *collector) resolveThresholds() (thresholds, params, configSource) {
	a := &c.agg
	var cand *cfgRec
	for i := range a.configs {
		r := &a.configs[i]
		if r.tsOK && !r.ts.After(c.from) && (cand == nil || r.seq > cand.seq) {
			cand = r
		}
	}
	var base *cfgRec
	basis, why := basisAtOrBefore, ""
	switch {
	case cand == nil:
		why = "No configuration record (monitor_start or config_state) written at or before the start of the period is contained in this bundle."
	case !c.sameProcessAcrossOmissions(cand):
		why = fmt.Sprintf("The latest configuration record in this bundle before the period (%s seq %d, %s) is followed by ledger "+
			"segments that are not included, and the first record after them was written by another monitor process, so it does "+
			"not state the configuration in force at the start of the period.", cand.typ, cand.seq, cand.at())
	case cand.params == nil:
		why = fmt.Sprintf("The %s record seq %d (%s), the latest configuration record at or before the start of the period, %s; "+
			"its configuration hash is %s.", cand.typ, cand.seq, cand.at(), cand.missing(), orNone(cand.hash))
	default:
		base = cand
	}
	if base == nil && a.lead.first >= 0 {
		base, basis = &a.configs[a.lead.first], basisFirstInPeriod
	}

	shown := defaultParams()
	var th thresholds
	src := configSource{Type: "defaults"}
	if base != nil {
		shown = *base.params
		th = shown.toThresholds()
		ts := base.ts.UTC().Format(time.RFC3339Nano)
		th.Source, th.ConfigSHA256 = base.typ, base.hash
		if base.typ == model.TypeMonitorStart {
			th.Seq, th.TS = ptr(base.seq), ts
		}
		src = configSource{Type: base.typ, Seq: ptr(base.seq), TS: ts, ConfigSHA256: base.hash, Basis: basis}
		if basis == basisFirstInPeriod {
			th.Note = why + " The values shown are therefore those of the first configuration record in the period: every earlier " +
				"record of the period was written by the monitor process that wrote it, and a monitor process keeps the thresholds it " +
				"started with, so they applied from the start of the period."
		}
	} else {
		th = shown.toThresholds()
		th.Source = "defaults"
		th.Note = why + " The configuration in force at the start of the period is therefore not quoted from the records; the " +
			"documented defaults are shown. Each sample's recorded classification is authoritative."
		if cand != nil && cand.params == nil && c.sameProcessAcrossOmissions(cand) {
			th.ConfigSHA256 = cand.hash
		}
	}

	th.Changes = c.configChanges(base, cand, shown)
	until := c.end.UTC().Format(time.RFC3339Nano)
	for i := len(th.Changes) - 1; i >= 0; i-- {
		th.Changes[i].AppliesUntil = until
		until = th.Changes[i].TS
	}
	th.AppliesUntil = until
	return th, shown, src
}

// configChanges lists the configuration records of the period whose configuration differs from
// the one in force before them, in ledger order. base is the source of the thresholds (nil: the
// documented defaults are shown), cand the latest configuration record at or before the start of
// the period, shown the values the report shows.
func (c *collector) configChanges(base, cand *cfgRec, shown params) []thresholdChange {
	prev, known := shown, base != nil
	var prevHash string
	var prevRaw json.RawMessage
	switch {
	case base != nil:
		prevHash, prevRaw = base.hash, base.raw
	case cand != nil:
		prevHash = cand.hash
	}
	var out []thresholdChange
	for i := range c.agg.configs {
		r := &c.agg.configs[i]
		if !r.tsOK || !r.ts.After(c.from) || !r.ts.Before(c.end) || (base != nil && r.seq <= base.seq) {
			continue
		}
		var ch []string
		switch {
		case r.params != nil && !known:
			if d := r.params.diff(shown); len(d) > 0 {
				ch = append([]string{"the configuration recorded from here on differs from the values shown above in: " + d[0]}, d[1:]...)
			} else {
				ch = []string{"the configuration recorded from here on has the values shown above"}
			}
		case r.params != nil:
			// Both configurations are readable: what differs is decided by their content (the
			// recorded hashes name them, but a differently serialized copy of the same
			// configuration is not a change).
			ch = r.params.diff(prev)
			targetsDescribed := strings.Join(prev.targets, "\n") != strings.Join(r.params.targets, "\n")
			if other := settingsDiff(prevRaw, r.raw, targetsDescribed); len(other) > 0 {
				if len(ch) == 0 {
					ch = append(ch, "the thresholds quoted in this report are unchanged")
				}
				ch = append(ch, other...)
			}
		case r.hash != prevHash: // the same hash is the same configuration as before
			ch = []string{fmt.Sprintf("configuration hash %s -> %s; the %s record %s, so the thresholds in force from here on are "+
				"not known from this bundle", orNone(short(prevHash)), orNone(short(r.hash)), r.typ, r.missing())}
		}
		switch {
		case r.params != nil:
			prev, known, prevRaw = *r.params, true, r.raw
		case r.hash != prevHash:
			known, prevRaw = false, nil
		}
		prevHash = r.hash
		if len(ch) > 0 {
			e := thresholdChange{Type: r.typ, Seq: r.seq, TS: r.ts.UTC().Format(time.RFC3339Nano), ConfigSHA256: r.hash, Changes: ch}
			if r.typ == model.TypeMonitorStart {
				e.MonitorStartSeq = ptr(r.seq)
			}
			out = append(out, e)
		}
	}
	return out
}

// sameProcessAcrossOmissions reports whether no other monitor process can have started between
// configuration record r and the start of the period inside ledger segments left out of the
// bundle.
func (c *collector) sameProcessAcrossOmissions(r *cfgRec) bool {
	for _, o := range c.omissions {
		if o.afterSeq < r.seq {
			continue
		}
		if o.firstRun != r.run {
			return false
		}
	}
	return true
}

// thresholdSettings are the settings of a recorded configuration that the report quotes as
// thresholds; params.diff describes their changes (probes.targets: only its internet targets).
var thresholdSettings = map[string]bool{
	"probes.fast_interval": true, "probes.timeout": true,
	"incident.open_after_cycles": true, "incident.close_after_cycles": true, "incident.window_cycles": true,
	"incident.loss_degraded_pct": true, "incident.latency_degraded_ms": true, "incident.gateway_latency_ok_ms": true,
	"incident.snapshot_freshness": true,
}

// maxSettingChanges caps the other settings listed for one configuration change.
const maxSettingChanges = 10

// settingsDiff lists the settings other than the thresholds whose recorded values differ between
// two configurations, as "path old -> new" with the recorded JSON values (long values
// abbreviated, "(absent)" for a setting one of them lacks; "path changed" when they differ only
// beyond the abbreviation). probes.targets is left out when targetsDescribed (params.diff lists
// its internet targets). Nil when either configuration cannot be read.
func settingsDiff(old, cur json.RawMessage, targetsDescribed bool) []string {
	a, okA := flattenConfig(old)
	b, okB := flattenConfig(cur)
	if !okA || !okB {
		return nil
	}
	skip := func(k string) bool { return thresholdSettings[k] || (k == "probes.targets" && targetsDescribed) }
	var paths []string
	for k, v := range a {
		if w, ok := b[k]; (!ok || w != v) && !skip(k) {
			paths = append(paths, k)
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok && !skip(k) {
			paths = append(paths, k)
		}
	}
	sort.Strings(paths)
	out := make([]string, 0, min(len(paths), maxSettingChanges+1))
	for i, k := range paths {
		if i == maxSettingChanges {
			out = append(out, fmt.Sprintf("and %d more settings", len(paths)-i))
			break
		}
		if ov, nv := settingValue(a, k), settingValue(b, k); ov != nv {
			out = append(out, fmt.Sprintf("%s %s -> %s", k, ov, nv))
		} else {
			out = append(out, k+" changed")
		}
	}
	return out
}

func settingValue(m map[string]string, k string) string {
	v, ok := m[k]
	if !ok {
		return "(absent)"
	}
	return abbreviate(v, 40)
}

// flattenConfig maps every setting of a recorded configuration (the dotted path of its object
// keys) to its value as compact JSON; arrays are single values.
func flattenConfig(raw json.RawMessage) (map[string]string, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	out := map[string]string{}
	var walk func(path string, v any)
	walk = func(path string, v any) {
		if m, ok := v.(map[string]any); ok && (len(m) > 0 || path == "") {
			for k, x := range m {
				p := k
				if path != "" {
					p = path + "." + k
				}
				walk(p, x)
			}
			return
		}
		out[path] = compactValue(v)
	}
	walk("", v)
	return out, true
}

// compactValue renders a decoded JSON value as compact JSON without HTML escaping.
func compactValue(v any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return fmt.Sprint(v)
	}
	return strings.TrimSuffix(buf.String(), "\n")
}

// abbreviate shortens s to at most n bytes plus "...", never splitting a UTF-8 sequence.
func abbreviate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}

// providersOf returns the distinct addresses of the internet-role probe targets, sorted.
func providersOf(targets []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, t := range targets {
		h := t
		if host, _, err := net.SplitHostPort(t); err == nil {
			h = host
		}
		if h != "" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out
}

// ------------------------------------------------------------------ rules versions

// rulesDifferences explains, for records produced under an older rules version, what differs
// from the rules described here (docs/DESIGN.md §9-§10) and how this report treats them.
var rulesDifferences = map[string][]string{
	"2026.10-3": {
		"DNS: a resolver failure was taken from a single query in a single service check, so one lost UDP datagram could make " +
			"the cycles that used that check DEGRADED / ISP_DNS_FAILURE or GATEWAY_DNS_FAILURE, attributed to the provider when " +
			"the gateway answered every probe. Rules 2026.10-4 ask a query that got no valid response once more within its check " +
			"and count a resolver failure only when the same failure appears in two consecutive service checks.",
		"Route check: whether this computer's probes left through the AT&T gateway was not checked. With a VPN tunnel, a second " +
			"network adapter or a hotspot holding the route, probes that never reached AT&T's network could make cycles " +
			"ISP_OUTAGE or DEGRADED attributed to the provider. Rules 2026.10-4 record a route check with every local_link " +
			"record; while it shows a destination routed past the gateway, such a cycle is LOCAL_FAULT / LOCAL_ROUTE " +
			"(attribution undetermined) unless the gateway itself reports its fiber or WAN connection down, and a DEGRADED " +
			"cycle is undetermined.",
		"Household traffic: DEGRADED cycles were attributed to the provider whenever the gateway answered every probe of the " +
			"window, also while the household's own traffic could be filling the connection. Rules 2026.10-4 attribute them to " +
			"the provider only when the gateway's own WAN counters do not show 80 Mb/s or more in either direction, and state " +
			"the measured rates.",
		"Interrupted cycles: a cycle whose probes were cut short by system sleep was classified from its timed-out probes, so " +
			"it could be a bad cycle, and an incident open at the time could be extended to the moment that cycle was recorded " +
			"after the resume (hours of sleep counted as an outage). Rules 2026.10-4 record such a cycle as UNKNOWN and close an " +
			"open incident at the end of the time its last bad cycle covers.",
		"Gateway restarts: a restart was attached to an incident only when its boot lay within the incident's span, and its " +
			"window was computed over the incident's own cycles, so a boot before the incident's first observed cycle (for " +
			"example a power failure that also stopped this computer) was missed and its time counted as time without " +
			"Internet. Rules 2026.10-4 attach a restart to every incident with a bad cycle in its window, the window being " +
			"computed over every recorded cycle.",
		"A single provider-attributed bad cycle outside the restart windows made an incident with a restart the provider's; " +
			"rules 2026.10-4 require at least open_after_cycles of them (as many as it takes to open an incident; fewer are " +
			"stray cycles of the restart's own shutdown or bring-up).",
		"This report computes the restart windows of rules 2026.10-4 from the records of this bundle for every sample; sample " +
			"verdicts and incident records are shown as recorded, and an incident record that the restart windows contradict " +
			"says so in its key facts.",
	},
	"2026.10-2": {
		"Everything listed for rules 2026.10-3 applies.",
		"Gateway restarts were not treated specially: after a restart, the cycles in which the AT&T gateway answered " +
			"but had not yet re-established its fiber and WAN connection were classified ISP_OUTAGE and attributed to " +
			"the provider, also when the restart was caused at the customer's premises (for example a power cycle).",
		"Incident records of this version have no restart_s and no gateway_restarts; their downtime_s includes the " +
			"time after a gateway restart, and the GATEWAY_REBOOT cause was applied only to incidents whose headline " +
			"state was LOCAL_FAULT.",
		"Incidents open across midnight were not re-recorded in each daily ledger segment, and sample verdicts do not " +
			"name the records they used (inputs).",
		"This report applies the restart windows of rules 2026.10-4, found in the gateway reboot events and incident " +
			"records of this bundle, to its summary figures for all samples; sample verdicts and incident records are " +
			"shown as recorded, and incidents affected by a restart window say so in their key facts.",
	},
	"2026.10-1": {
		"Everything listed for rules 2026.10-2 applies (no gateway-restart windows).",
		"A refused TCP connection to the gateway (a TCP reset, which proves the gateway answered) did not count as " +
			"reaching it, so such cycles could be classified LOCAL_FAULT (never attributed to the provider).",
		"Packet loss was judged over all internet probes of the window including total-outage cycles, which " +
			"extended every outage by up to the window length as DEGRADED/PACKET_LOSS, and a single unreachable " +
			"destination could make a cycle DEGRADED; rules 2026.10-2 and later need at least two lossy providers and " +
			"exclude outage cycles. Latency medians also included outage cycles.",
		"Incident records of this version may lack the cycle-time figures (downtime_s, degraded_s); the incident " +
			"table shows them as not recorded.",
	},
}

// rulesNotes describes the rules versions found in the records other than the one described.
func (c *collector) rulesNotes() []rulesNote {
	a := &c.agg
	var versions []string
	for v := range a.rules {
		if v != rulesDescribed {
			versions = append(versions, v)
		}
	}
	sort.Strings(versions)
	var out []rulesNote
	for _, v := range versions {
		d, known := rulesDifferences[v]
		n := rulesNote{Version: v, Samples: a.rulesSamples[v], IncidentRecords: a.rulesIncidents[v], Known: known}
		if known {
			n.Differences = append([]string(nil), d...)
		} else {
			n.Differences = []string{"Rules version " + v + " is not known to this report: its records do not match the rules " +
				"described here (version " + rulesDescribed + "), and the description in this section may not apply to them. " +
				"Each record's own classification is shown as recorded."}
		}
		out = append(out, n)
	}
	return out
}
