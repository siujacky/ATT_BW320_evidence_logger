package monitor

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/model"
)

// RulesVersion identifies the classification and incident rules implemented by Classify and
// the incident tracker (docs/DESIGN.md §9-§10). It is recorded in every verdict, incident and
// monitor_start, so any change to the rules must bump it.
//
// 2026.10-4 (current):
//   - a resolver failure (ISP_DNS_FAILURE, GATEWAY_DNS_FAILURE) needs the same failure in two
//     consecutive service checks, each query retried once within its check;
//   - rules 2 and 3 blame the provider only for probes that leave through the AT&T gateway: while
//     the recorded route check (local_link "egress") shows a destination routed past it, rule 2
//     gives LOCAL_FAULT/LOCAL_ROUTE (undetermined) unless the gateway itself reports its fiber or
//     WAN down, and DEGRADED is undetermined;
//   - DEGRADED is attributed to the provider only when the gateway's own WAN counters do not
//     show heavy household traffic (>= 80 Mb/s in either direction); the rates are stated;
//   - a cycle whose probes were cut short by an interruption (it took longer than the probe
//     timeout plus the grace plus max(fast/2, 1 s)) is UNKNOWN;
//   - incidents: a gateway restart belongs to every incident with a bad cycle inside its window
//     (computed over every recorded cycle, also when the boot came before the incident's first
//     observed cycle); an incident with a restart is the provider's only with at least
//     OpenAfterCycles provider-attributed bad cycles outside the restart windows; an incident
//     interrupted by a monitoring gap closes at the end of its last bad cycle's coverage.
//
// 2026.10-3: gateway restarts (§10) - bad cycles inside a restart window (from the boot,
// extended back over the unreachable period before it, until the Internet is reachable again,
// at most 10 min) are restart time, not provider downtime, and an incident with a restart is
// the provider's only through provider-attributed bad cycles outside the restart windows (or a
// firmware change across the restart); every verdict names its inputs.
// 2026.10-2: a refused gateway TCP connection proves LAN; packet loss is judged per provider
// over the window's non-outage cycles and needs min(2, providers) lossy providers; latency
// medians use the non-outage cycles. 2026.10-1 counted total-outage cycles in the window loss,
// which stretched every outage by the window length.
const RulesVersion = "2026.10-4"

// ClassifyInput is everything Classify looks at for one fast cycle.
type ClassifyInput struct {
	Cycle       []model.ProbeResult    // this cycle
	Window      [][]model.ProbeResult  // last N cycles incl. this one, oldest first
	Snapshot    *model.GatewaySnapshot // latest, may be nil
	SnapshotAge time.Duration
	Service     *model.ServiceCheck // latest, may be nil
	ServiceAge  time.Duration
	Link        *model.LocalLink // latest, may be nil
	LinkAge     time.Duration    // 0: fresh

	// Ledger seqs of Snapshot, Service and Link (0: not recorded). Classify reports the ones
	// it used (fresh) in Verdict.Inputs, so a third party can recompute the verdict.
	SnapshotSeq, ServiceSeq, LinkSeq uint64

	// PrevService is the service check recorded just before Service (PrevServiceSeq), taken
	// PrevServiceGap before it: a resolver failure counts only when the same failure was in both
	// (DESIGN §9 rule 3; named in the reasons).
	PrevService    *model.ServiceCheck
	PrevServiceGap time.Duration
	PrevServiceSeq uint64

	// Egress is the route check recorded with Link (the same local_link record, used while Link
	// is fresh): whether this computer's internet probes leave through the AT&T gateway. nil:
	// Link.Egress.
	Egress *model.EgressCheck

	// Traffic is the WAN traffic the gateway's own counters show between its two latest
	// recorded snapshots with counters (both named in the reasons), TrafficAge the age of the
	// newer one at the cycle start (used while fresh).
	Traffic    *WANTraffic
	TrafficAge time.Duration
}

// effectiveIncident replaces zero or negative thresholds (a hand-built config) with the
// documented defaults; Classify must never treat "0 % loss" as degraded.
func effectiveIncident(c config.IncidentConfig) config.IncidentConfig {
	d := config.Default().Incident
	if c.OpenAfterCycles < 1 {
		c.OpenAfterCycles = d.OpenAfterCycles
	}
	if c.CloseAfterCycles < 1 {
		c.CloseAfterCycles = d.CloseAfterCycles
	}
	if c.WindowCycles < 1 {
		c.WindowCycles = d.WindowCycles
	}
	if c.LossDegradedPct <= 0 {
		c.LossDegradedPct = d.LossDegradedPct
	}
	if c.LatencyDegradedMs <= 0 {
		c.LatencyDegradedMs = d.LatencyDegradedMs
	}
	if c.GatewayLatencyOkMs <= 0 {
		c.GatewayLatencyOkMs = d.GatewayLatencyOkMs
	}
	if c.SnapshotFreshness.Duration <= 0 {
		c.SnapshotFreshness = d.SnapshotFreshness
	}
	return c
}

// isRefused reports a TCP connection the peer actively refused (it answered with a reset).
func isRefused(status string) bool { return strings.EqualFold(strings.TrimSpace(status), "refused") }

// gatewayAnswered: the gateway's IP stack answered this probe - it succeeded, or a TCP
// connection was refused (an RST is an answer). DESIGN §9 "LAN".
func gatewayAnswered(p model.ProbeResult) bool {
	return p.OK || (p.Kind == model.KindTCP && isRefused(p.Status))
}

// cycleCounts tallies one cycle's probes for the rules.
type cycleCounts struct {
	gwTotal, gwAnswered int
	inetTotal, inetOK   int
	hopTotal, hopOK     int
}

func countCycle(cycle []model.ProbeResult) cycleCounts {
	var n cycleCounts
	for _, p := range cycle {
		switch p.Role {
		case model.RoleGateway:
			n.gwTotal++
			n.gwAnswered += b2i(gatewayAnswered(p))
		case model.RoleInet:
			n.inetTotal++
			n.inetOK += b2i(p.OK)
		case model.RoleISPHop:
			n.hopTotal++
			n.hopOK += b2i(p.OK)
		}
	}
	return n
}

// known: the cycle has gateway and internet probes (otherwise it is UNKNOWN).
func (n cycleCounts) known() bool { return n.gwTotal > 0 && n.inetTotal > 0 }

// outage: the cycle is classified by rule 1 (no LAN) or rule 2 (LAN, no internet).
func (n cycleCounts) outage() bool { return n.known() && (n.gwAnswered == 0 || n.inetOK == 0) }

// providerOf names the provider of an internet probe: its target IP address (ICMP and TCP
// probes to the same address are one provider).
func providerOf(p model.ProbeResult) string {
	h := hostOnly(strings.TrimSpace(p.Target))
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Unmap().String()
	}
	if h != "" {
		return h
	}
	return p.Name
}

// medianMs returns the median of µs values in milliseconds (mean of the two middle values
// for an even count).
func medianMs(us []int64) (float64, bool) {
	if len(us) == 0 {
		return 0, false
	}
	s := slices.Clone(us)
	slices.Sort(s)
	n := len(s)
	if n%2 == 1 {
		return float64(s[n/2]) / 1000, true
	}
	return float64(s[n/2-1]+s[n/2]) / 2000, true
}

// Classify applies the normative rules of docs/DESIGN.md §9 to one fast cycle. It is pure
// and deterministic: the same input always yields the same verdict, including the wording
// and order of the reasons. A cycle without any gateway-role or internet-role probe result
// is UNKNOWN (neither good nor bad).
func Classify(in ClassifyInput, cfg config.IncidentConfig) model.Verdict {
	c := classifier{in: in, cfg: effectiveIncident(cfg)}
	return c.run()
}

type classifier struct {
	in      ClassifyInput
	cfg     config.IncidentConfig
	reasons []string
	// The optional inputs the rules consulted, named in Verdict.Inputs: the previous service
	// check the DNS rule compared this one with (0: none), and the WAN traffic measurement the
	// DEGRADED attribution looked at (nil: none).
	prevServiceSeq uint64
	traffic        *WANTraffic
}

func (c *classifier) add(format string, args ...any) {
	c.reasons = append(c.reasons, fmt.Sprintf(format, args...))
}

func (c *classifier) verdict(state, cause, attribution string) model.Verdict {
	return model.Verdict{State: state, Cause: cause, Attribution: attribution, Reasons: c.reasons,
		Inputs: c.inputs(), Rules: RulesVersion}
}

// inputs names the records this verdict was computed from (DESIGN §9-§10 "inputs"): the
// snapshot, service check and local link when fresh enough to be used (0 otherwise), the window
// size, and - when the rules consulted them - the previous service check the DNS rule compared
// with and the two snapshots whose WAN counters gave the household traffic rate.
func (c *classifier) inputs() *model.VerdictInputs {
	in := &model.VerdictInputs{WindowCycles: max(len(c.in.Window), 1), PrevServiceCheckSeq: c.prevServiceSeq}
	if c.snapshotFresh() {
		in.SnapshotSeq = c.in.SnapshotSeq
	}
	if c.serviceFresh() {
		in.ServiceCheckSeq = c.in.ServiceSeq
	}
	if c.link() != nil {
		in.LocalLinkSeq = c.in.LinkSeq
	}
	if t := c.traffic; t != nil {
		in.TrafficFromSeq, in.TrafficToSeq = t.FromSeq, t.ToSeq
	}
	return in
}

// serviceFresh reports whether the service check may be used.
func (c *classifier) serviceFresh() bool {
	return c.in.Service != nil && c.in.ServiceAge <= c.cfg.SnapshotFreshness.Duration
}

// link returns the local link when it is fresh enough to be used, else nil.
func (c *classifier) link() *model.LocalLink {
	if c.in.Link == nil || c.in.LinkAge > c.cfg.SnapshotFreshness.Duration {
		return nil
	}
	return c.in.Link
}

// egressBypass returns the reason sentence when the route check recorded with the fresh local
// link shows a destination routed past the AT&T gateway, else "".
func (c *classifier) egressBypass() string {
	l := c.link()
	if l == nil {
		return ""
	}
	e := c.in.Egress
	if e == nil {
		e = l.Egress
	}
	return bypassText(e)
}

// trafficFresh returns the household WAN traffic measurement when its newer snapshot is fresh.
func (c *classifier) trafficFresh() *WANTraffic {
	if c.in.Traffic == nil || c.in.TrafficAge > c.cfg.SnapshotFreshness.Duration {
		return nil
	}
	return c.in.Traffic
}

func (c *classifier) run() model.Verdict {
	in := c.in
	n := countCycle(in.Cycle)

	switch {
	case len(in.Cycle) == 0:
		c.add("no probe results in this cycle")
		return c.verdict(model.StateUnknown, model.CauseNone, model.AttrUndetermined)
	case n.gwTotal == 0:
		c.add("no gateway probe ran in this cycle, so the local path cannot be judged")
		return c.verdict(model.StateUnknown, model.CauseNone, model.AttrUndetermined)
	case n.inetTotal == 0:
		c.add("no internet probe ran in this cycle, so internet reachability cannot be judged")
		return c.verdict(model.StateUnknown, model.CauseNone, model.AttrUndetermined)
	}

	// Rule 1: the gateway is not reachable from this computer.
	if n.gwAnswered == 0 {
		for _, p := range in.Cycle {
			if p.Role == model.RoleGateway {
				c.reasons = append(c.reasons, describeProbe(p))
			}
		}
		c.add("%d/%d internet probes succeeded", n.inetOK, n.inetTotal)
		if l := c.link(); l != nil && wifiDown(l) {
			c.add("this computer's Wi-Fi adapter %s reports state: %s", quoteOr(l.Interface, "(unnamed)"), l.State)
			c.add("the fault is on the local side: this computer's Wi-Fi link to the gateway is down")
			return c.verdict(model.StateLocalFault, model.CauseLocalLinkDown, model.AttrLocal)
		}
		if l := c.link(); l != nil {
			if s := linkSummary(l); s != "" {
				c.reasons = append(c.reasons, s)
			}
		}
		c.add("the AT&T gateway did not answer this computer, so the fault cannot be attributed to either side")
		return c.verdict(model.StateLocalFault, model.CauseGatewayUnreachable, model.AttrUndetermined)
	}

	fresh := c.snapshotFresh()

	// Rule 2: the gateway answers but nothing on the internet does.
	if n.inetOK == 0 {
		c.reasons = append(c.reasons, describeProbe(firstAnsweringGateway(in.Cycle)))
		c.add("%d/%d internet probes succeeded", n.inetOK, n.inetTotal)
		cause := c.outageCause(fresh, n)
		if bypass := c.egressBypass(); bypass != "" {
			c.reasons = append(c.reasons, bypass)
			if cause != model.CauseFiberLinkDown && cause != model.CauseWANDown {
				c.add("the gateway was reachable but this computer's internet probes do not leave through it, so their failure says nothing about AT&T's network")
				return c.verdict(model.StateLocalFault, model.CauseLocalRoute, model.AttrUndetermined)
			}
			c.add("the AT&T gateway itself reports its connection down, so the outage is on the provider side whatever route this computer's probes took")
			return c.verdict(model.StateISPOutage, cause, model.AttrProvider)
		}
		c.add("the gateway was reachable but no internet target answered, so the outage is on the provider side")
		return c.verdict(model.StateISPOutage, cause, model.AttrProvider)
	}

	// Rule 3: LAN and at least one internet probe answered.
	return c.degradedOrOnline(n)
}

// snapshotFresh reports whether the snapshot may be used.
func (c *classifier) snapshotFresh() bool {
	s := c.in.Snapshot
	if s == nil {
		return false
	}
	age := c.in.SnapshotAge
	if age < 0 {
		age = 0
	}
	return age <= c.cfg.SnapshotFreshness.Duration
}

// snapshotNote describes why the gateway's own status could not be used.
func (c *classifier) snapshotNote() {
	s := c.in.Snapshot
	if s == nil {
		c.add("no AT&T gateway status snapshot is available yet")
		return
	}
	c.add("the latest AT&T gateway status snapshot is %d s old (older than %d s), so its status was not used",
		int64(c.in.SnapshotAge/time.Second), int64(c.cfg.SnapshotFreshness.Duration/time.Second))
}

func (c *classifier) outageCause(fresh bool, n cycleCounts) string {
	in := c.in
	var d model.GatewayDerived
	if in.Snapshot != nil {
		d = in.Snapshot.Derived
	}
	ponDown := fresh && d.PONOperational != nil && !*d.PONOperational
	optDown := fresh && d.OpticalUp != nil && !*d.OpticalUp
	bbDown := fresh && d.BroadbandUp != nil && !*d.BroadbandUp
	noIP := fresh && noWANIPv4(in.Snapshot)

	switch {
	case ponDown || optDown:
		if ponDown {
			c.add("AT&T gateway reports PON Link Status: %s", ponText(in.Snapshot))
		}
		if optDown {
			c.add("AT&T gateway reports Optical WAN Operational Status: %s", opticalText(in.Snapshot))
		}
		return model.CauseFiberLinkDown
	case bbDown || noIP:
		if bbDown {
			c.add("AT&T gateway reports Broadband Connection: %s", broadbandText(in.Snapshot))
		}
		if noIP {
			c.add("AT&T gateway reports no WAN IPv4 address")
		}
		return model.CauseWANDown
	}

	// The gateway's own status does not explain the outage (or is unavailable).
	if fresh {
		if d.BroadbandUp != nil {
			c.add("AT&T gateway reports Broadband Connection: %s", broadbandText(in.Snapshot))
		}
	} else {
		c.snapshotNote()
	}
	if n.hopTotal > 0 && n.hopOK == 0 {
		for _, p := range in.Cycle {
			if p.Role == model.RoleISPHop {
				c.reasons = append(c.reasons, describeProbe(p))
			}
		}
		return model.CauseISPEdgeUnreachable
	}
	if n.hopTotal == 0 {
		c.add("the AT&T next hop is unknown (no gateway snapshot has reported it), so it was not probed")
	} else {
		for _, p := range in.Cycle {
			if p.Role == model.RoleISPHop && p.OK {
				c.reasons = append(c.reasons, describeProbe(p))
				break
			}
		}
	}
	return model.CauseUpstreamUnreachable
}

// providerLoss is one provider's probe tally over the window's non-outage cycles.
type providerLoss struct {
	name      string
	ok, total int
}

func (p providerLoss) pct() float64 {
	if p.total == 0 {
		return 0
	}
	// 100*a/b computed from integers is exact whenever the true value is (e.g. 20 %).
	return float64(100*(p.total-p.ok)) / float64(p.total)
}

func (c *classifier) degradedOrOnline(n cycleCounts) model.Verdict {
	in, cfg := c.in, c.cfg
	window := in.Window
	if len(window) == 0 {
		window = [][]model.ProbeResult{in.Cycle}
	}

	// Window statistics: gateway answers over the whole window (attribution); per-provider
	// loss and latency over the window's non-outage cycles only (outage cycles are outages
	// already; counting them as loss would stretch every outage by the window length).
	byName := map[string]*providerLoss{}
	var inetRTT, gwRTT []int64
	used, gwTotal, gwAnswered := 0, 0, 0
	for _, cyc := range window {
		cn := countCycle(cyc)
		gwTotal += cn.gwTotal
		gwAnswered += cn.gwAnswered
		if !cn.known() || cn.outage() {
			continue
		}
		used++
		for _, p := range cyc {
			switch p.Role {
			case model.RoleInet:
				name := providerOf(p)
				pl := byName[name]
				if pl == nil {
					pl = &providerLoss{name: name}
					byName[name] = pl
				}
				pl.total++
				if p.OK {
					pl.ok++
					inetRTT = append(inetRTT, p.RTTus)
				}
			case model.RoleGateway:
				if p.OK {
					gwRTT = append(gwRTT, p.RTTus)
				}
			}
		}
	}
	provs := make([]providerLoss, 0, len(byName))
	for _, name := range sortedKeys(byName) {
		provs = append(provs, *byName[name])
	}
	var lossy []string
	for _, p := range provs {
		if p.total > 0 && p.pct() >= cfg.LossDegradedPct {
			lossy = append(lossy, p.name)
		}
	}
	need := min(2, len(provs))
	span := fmt.Sprintf("the last %d non-outage cycles", used)
	if excluded := len(window) - used; excluded > 0 {
		span = fmt.Sprintf("the last %d non-outage cycles (%d other cycles of the window excluded)", used, excluded)
	}
	inetMed, haveInet := medianMs(inetRTT)
	gwMed, haveGw := medianMs(gwRTT)
	gwRef := describeProbe(firstAnsweringGateway(in.Cycle))
	thr := fmtNum(cfg.LossDegradedPct)

	cause := ""
	switch {
	case need > 0 && len(lossy) >= need:
		cause = model.CausePacketLoss
		c.add("%d/%d internet probes failed this cycle", n.inetTotal-n.inetOK, n.inetTotal)
		c.add("internet probe loss by provider over %s: %s", span, providerList(provs))
		c.add("%d of %d providers lost at least %s%% of their probes (%s), so the loss does not depend on one destination",
			len(lossy), len(provs), thr, strings.Join(lossy, ", "))
	case haveInet && haveGw && inetMed > cfg.LatencyDegradedMs && gwMed < cfg.GatewayLatencyOkMs:
		cause = model.CauseHighLatency
		c.add("median internet RTT over %s is %.1f ms (threshold %s ms)", span, inetMed, fmtNum(cfg.LatencyDegradedMs))
		c.add("median gateway RTT over the same cycles is %.1f ms", gwMed)
	default:
		if c.serviceFresh() {
			var dnsReasons []string
			var prev *model.ServiceCheck
			if in.PrevService != nil && in.PrevServiceGap >= 0 && in.PrevServiceGap <= cfg.SnapshotFreshness.Duration {
				prev = in.PrevService
			}
			var compared bool
			cause, dnsReasons, compared = dnsRule(in.Service, prev, in.PrevServiceSeq)
			c.reasons = append(c.reasons, dnsReasons...)
			if compared {
				c.prevServiceSeq = in.PrevServiceSeq
			}
		}
	}
	bypass := c.egressBypass()

	if cause == "" {
		c.add("%d/%d internet probes succeeded", n.inetOK, n.inetTotal)
		c.reasons = append(c.reasons, gwRef)
		if len(lossy) > 0 {
			c.add("only %d of %d providers lost at least %s%% over %s (%s): one unreachable destination does not implicate the ISP",
				len(lossy), len(provs), thr, span, strings.Join(lossy, ", "))
		}
		if haveInet {
			c.add("median internet RTT over %s is %.1f ms", span, inetMed)
			if haveGw && inetMed > cfg.LatencyDegradedMs && gwMed >= cfg.GatewayLatencyOkMs {
				c.add("internet latency is above %s ms but the gateway itself answered in a median %.1f ms (not below %s ms), so the latency is not attributed to the provider",
					fmtNum(cfg.LatencyDegradedMs), gwMed, fmtNum(cfg.GatewayLatencyOkMs))
			}
		}
		if bypass != "" {
			c.reasons = append(c.reasons, bypass)
		}
		return c.verdict(model.StateOnline, model.CauseNone, model.AttrNone)
	}

	c.reasons = append(c.reasons, gwRef)
	if gwTotal == 0 || gwAnswered != gwTotal {
		c.add("gateway probes lost %d/%d over the last %d cycles, so the degradation cannot be attributed to the provider", gwTotal-gwAnswered, gwTotal, len(window))
		return c.verdict(model.StateDegraded, cause, model.AttrUndetermined)
	}
	c.add("gateway probes had no loss over the last %d cycles (%d/%d answered)", len(window), gwAnswered, gwTotal)
	if bypass != "" {
		c.reasons = append(c.reasons, bypass)
		c.add("this computer's internet traffic does not go through the AT&T gateway, so the degradation cannot be attributed to the provider")
		return c.verdict(model.StateDegraded, cause, model.AttrUndetermined)
	}
	tr := c.trafficFresh()
	c.traffic = tr // consulted: its snapshots are inputs, also when they gave no rate
	switch {
	case tr == nil || tr.Err != "":
		why := "no two recent gateway snapshots with WAN counters"
		if tr != nil {
			why = tr.Err
		}
		c.add("the household's own WAN traffic could not be measured (%s), so the degradation is attributed to the provider without that check", why)
	case tr.heavy():
		c.add("%s, at least %s Mb/s in one direction: the delay or loss may come from the household's own traffic filling the connection, so the degradation cannot be attributed to the provider",
			tr.trafficText(), fmtNum(heavyTrafficMbps))
		return c.verdict(model.StateDegraded, cause, model.AttrUndetermined)
	default:
		c.add("%s, below %s Mb/s in each direction, so the household's own traffic does not explain it and the degradation is on the provider side",
			tr.trafficText(), fmtNum(heavyTrafficMbps))
	}
	return c.verdict(model.StateDegraded, cause, model.AttrProvider)
}

// providerList renders "1.1.1.1 1/12 (8.3%), 8.8.8.8 4/12 (33.3%)" (failed/probes).
func providerList(provs []providerLoss) string {
	parts := make([]string, 0, len(provs))
	for _, p := range provs {
		parts = append(parts, fmt.Sprintf("%s %d/%d (%.1f%%)", p.name, p.total-p.ok, p.total, p.pct()))
	}
	return strings.Join(parts, ", ")
}

// dnsRule implements the DNS part of rule 3 (rules 2026.10-4): the ISP resolver failed while a
// public resolver answered (ISP_DNS_FAILURE) - or the gateway's DNS failed while the ISP resolver
// answered (GATEWAY_DNS_FAILURE) - in this service check AND in prev, the check recorded just
// before it (prevSeq; nil when there is none recent). A resolver is judged from one query per
// check (retried once within the check when it got no valid response): one lost UDP datagram, or
// two in a row, is not evidence that a resolver failed, so a single failing check never counts.
// The random "<hex>.invalid" query (the wildcard hijack detector) is not a resolution test and
// is ignored here. compared reports that prev was consulted (sc showed a failure to confirm):
// the verdict then names it among its inputs, whether it confirmed the failure or not.
func dnsRule(sc, prev *model.ServiceCheck, prevSeq uint64) (cause string, reasons []string, compared bool) {
	cause, text := dnsFinding(sc)
	if cause == "" {
		return "", nil, false
	}
	if prev != nil {
		if pc, ptext := dnsFinding(prev); pc == cause {
			return cause, []string{fmt.Sprintf("%s, as in the previous service check #%d (%s)", text, prevSeq, ptext)}, true
		}
		return "", []string{fmt.Sprintf("%s in this service check, but not in the previous one (#%d): one failing check is not counted as a resolver failure", text, prevSeq)}, true
	}
	return "", []string{text + " in this service check; no recent previous check confirms it, and one failing check is not counted as a resolver failure"}, false
}

// dnsFinding applies the DNS conditions of rule 3 to one service check and words them.
func dnsFinding(sc *model.ServiceCheck) (string, string) {
	var gw, isp, pub []model.DNSResult
	for _, r := range sc.DNS {
		if isInvalidName(r.Name) {
			continue
		}
		switch r.ServerRole {
		case "gateway":
			gw = append(gw, r)
		case "isp":
			isp = append(isp, r)
		case "public":
			pub = append(pub, r)
		}
	}
	pubOK := firstAnswered(pub)
	ispOK := firstAnswered(isp)
	if len(isp) > 0 && ispOK == nil && pubOK != nil {
		return model.CauseISPDNSFailure, fmt.Sprintf("ISP resolver %s failed (%s) while public resolver %s answered",
			dnsServer(isp[0]), dnsFailTexts(isp), dnsServer(*pubOK))
	}
	if len(gw) > 0 && firstAnswered(gw) == nil && ispOK != nil {
		return model.CauseGatewayDNSFailure, fmt.Sprintf("gateway DNS %s failed (%s) while ISP resolver %s answered",
			dnsServer(gw[0]), dnsFailTexts(gw), dnsServer(*ispOK))
	}
	return "", ""
}

// dnsFailTexts words the failed queries of one resolver, e.g. "timeout; retried: timeout".
func dnsFailTexts(rs []model.DNSResult) string {
	parts := make([]string, 0, len(rs))
	for i, r := range rs {
		s := dnsFailText(r)
		if i > 0 {
			s = "retried: " + s
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, "; ")
}

// dnsAnswered: a well-formed, successful, non-hijacked response with at least one answer.
func dnsAnswered(r model.DNSResult) bool {
	return r.OK && rcodeOK(r.RCode) && len(r.Answers) > 0 && !r.Hijacked
}

func firstAnswered(rs []model.DNSResult) *model.DNSResult {
	for i := range rs {
		if dnsAnswered(rs[i]) {
			return &rs[i]
		}
	}
	return nil
}

// rcodeOK accepts the spellings a DNS client may use for "no error".
func rcodeOK(rc string) bool {
	switch strings.ToUpper(strings.TrimSpace(rc)) {
	case "", "NOERROR", "RCODESUCCESS", "SUCCESS", "0":
		return true
	}
	return false
}

func dnsFailText(r model.DNSResult) string {
	switch {
	case r.Err != "":
		return truncate(r.Err, 120)
	case !rcodeOK(r.RCode):
		return r.RCode
	case r.Hijacked:
		if r.HijackWhy != "" {
			return "hijacked: " + truncate(r.HijackWhy, 120)
		}
		return "hijacked answer"
	case !r.OK:
		return "no valid response"
	default:
		return "no answers"
	}
}

func dnsServer(r model.DNSResult) string {
	if r.Server == "" {
		return "(unknown)"
	}
	return hostOnly(r.Server)
}

func isInvalidName(name string) bool {
	n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	return n == "invalid" || strings.HasSuffix(n, ".invalid")
}

// ---------------------------------------------------------------------------- wording

func describeProbe(p model.ProbeResult) string {
	subj := probeSubject(p)
	if p.Kind == model.KindTCP {
		if p.OK {
			return fmt.Sprintf("%s accepted a TCP connection in %s", subj, fmtMs(p.RTTus))
		}
		if isRefused(p.Status) {
			return fmt.Sprintf("%s refused the TCP connection (it answered with a reset)", subj)
		}
		return fmt.Sprintf("%s did not accept a TCP connection (%s)", subj, failText(p))
	}
	if p.OK {
		return fmt.Sprintf("%s answered ICMP in %s", subj, fmtMs(p.RTTus))
	}
	return fmt.Sprintf("%s did not answer ICMP (%s)", subj, failText(p))
}

func probeSubject(p model.ProbeResult) string {
	t := p.Target
	if t == "" {
		t = p.Name
	}
	switch p.Role {
	case model.RoleGateway:
		return "gateway " + t
	case model.RoleISPHop:
		return "AT&T next hop " + t
	default:
		return t
	}
}

func failText(p model.ProbeResult) string {
	var parts []string
	if p.Status != "" {
		parts = append(parts, p.Status)
	}
	if p.Err != "" && p.Err != p.Status {
		parts = append(parts, truncate(p.Err, 120))
	}
	s := strings.Join(parts, ": ")
	if s == "" {
		s = "no reply"
	}
	if p.ReplyFrom != "" && p.ReplyFrom != hostOnly(p.Target) {
		s += " from " + p.ReplyFrom
	}
	return s
}

// firstAnsweringGateway returns the gateway probe that shows the gateway answered: a
// successful one if any, else a refused TCP connection.
func firstAnsweringGateway(cycle []model.ProbeResult) model.ProbeResult {
	for _, p := range cycle {
		if p.Role == model.RoleGateway && p.OK {
			return p
		}
	}
	for _, p := range cycle {
		if p.Role == model.RoleGateway && gatewayAnswered(p) {
			return p
		}
	}
	return model.ProbeResult{Role: model.RoleGateway}
}

// wifiDown reports whether the local link is Wi-Fi and in any state other than connected.
func wifiDown(l *model.LocalLink) bool {
	if !strings.EqualFold(l.Type, "wifi") {
		return false
	}
	s := strings.ToLower(strings.TrimSpace(l.State))
	return s != "" && s != "connected"
}

func linkSummary(l *model.LocalLink) string {
	switch {
	case l.Err != "" && l.State == "":
		return "local link state could not be read: " + truncate(l.Err, 120)
	case strings.EqualFold(l.Type, "wifi"):
		s := fmt.Sprintf("this computer's Wi-Fi adapter %s reports state: %s", quoteOr(l.Interface, "(unnamed)"), l.State)
		if l.SSID != "" {
			s += fmt.Sprintf(" (SSID %q, signal %d%%)", l.SSID, l.SignalPct)
		}
		return s
	case l.State != "":
		return fmt.Sprintf("this computer's %s adapter %s reports state: %s", l.Type, quoteOr(l.Interface, "(unnamed)"), l.State)
	}
	return ""
}

func quoteOr(s, def string) string {
	if s == "" {
		return def
	}
	return fmt.Sprintf("%q", s)
}

func fmtNum(f float64) string {
	if f == float64(int64(f)) {
		return fmt.Sprintf("%d", int64(f))
	}
	return fmt.Sprintf("%.1f", f)
}

func broadbandText(s *model.GatewaySnapshot) string {
	if s != nil && s.Broadband != nil && s.Broadband.Connection != "" {
		return s.Broadband.Connection
	}
	if s != nil && s.Derived.BroadbandUp != nil {
		if *s.Derived.BroadbandUp {
			return "Up"
		}
		return "Down"
	}
	return "unknown"
}

func ponText(s *model.GatewaySnapshot) string {
	if s != nil && s.Broadband != nil && s.Broadband.PONLinkStatus != "" {
		return s.Broadband.PONLinkStatus
	}
	return "not O5 (operational)"
}

func opticalText(s *model.GatewaySnapshot) string {
	if s != nil && s.Fiber != nil && s.Fiber.OpticalStatus != "" {
		return s.Fiber.OpticalStatus
	}
	return "not Up"
}

// noWANIPv4 reports whether a parsed broadband page explicitly shows no WAN IPv4 address.
// Absence is only claimed when the page was understood (Broadband Connection parsed) and the
// address field is empty/zero — never because a field could not be found.
func noWANIPv4(s *model.GatewaySnapshot) bool {
	if s == nil || s.Broadband == nil || s.Derived.BroadbandUp == nil {
		return false
	}
	ip := strings.TrimSpace(s.Derived.WANIPv4)
	if ip == "" {
		ip = strings.TrimSpace(s.Broadband.IPv4)
	}
	if ip != "" {
		switch strings.ToUpper(ip) {
		case "0.0.0.0", "N/A", "NONE", "-":
			return true
		}
		return false
	}
	if len(s.Broadband.Values) == 0 {
		return true // parser kept no rows: trust the empty parsed field
	}
	for k := range s.Broadband.Values {
		if k == "Broadband IPv4 Address" || strings.HasSuffix(k, "/Broadband IPv4 Address") {
			return true // the row exists and is empty
		}
	}
	return false
}
