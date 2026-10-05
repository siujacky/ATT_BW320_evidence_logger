package export

import (
	"bytes"
	"fmt"
	"html/template"
	"sort"
	"strconv"
	"strings"
	"time"

	"attmonitor/internal/model"
)

// REPORT.html is rendered with html/template, so every value taken from the ledger (notes,
// reasons, page fields) is contextually escaped. The page is self-contained: inline CSS and
// inline SVG only, no scripts, no external references, light/dark aware, print friendly.

const (
	maxHTMLIncidents = 500
	maxHTMLEvents    = 500
	maxHTMLCustody   = 2000
	maxHTMLAnchors   = 200
)

type htmlView struct {
	loc            *time.Location // the exporting computer's zone, as report.json records it
	R              *report
	Chart          *opticalChart
	Highlights     []string
	Incidents      []incidentEntry
	IncidentsMore  int
	Events         []gatewayEventEntry
	EventsMore     int
	Anchors        []anchorEntry
	AnchorsMore    int
	AnchorExamples []anchorEntry
	RootsFile      string // -CAfile argument of the OpenSSL instructions
	Custody        []custodyEntry
	CustodyMore    int
	TypeCounts     []valueCount
	FullFailures   []model.VerifyFailure
}

var codeLabels = map[string]string{
	"OPTICAL_RX_LOW_ALARM":     "Rx power low alarm",
	"OPTICAL_RX_LOW_WARNING":   "Rx power low warning",
	"OPTICAL_RX_HIGH_ALARM":    "Rx power high alarm",
	"OPTICAL_RX_HIGH_WARNING":  "Rx power high warning",
	"OPTICAL_TX_LOW_ALARM":     "Tx power low alarm",
	"OPTICAL_TX_LOW_WARNING":   "Tx power low warning",
	"OPTICAL_TX_HIGH_ALARM":    "Tx power high alarm",
	"OPTICAL_TX_HIGH_WARNING":  "Tx power high warning",
	"TEMPERATURE_HIGH_ALARM":   "Module temperature high alarm",
	"TEMPERATURE_HIGH_WARNING": "Module temperature high warning",
	"TEMPERATURE_LOW_ALARM":    "Module temperature low alarm",
	"TEMPERATURE_LOW_WARNING":  "Module temperature low warning",
	"NOTIFICATION_REDIRECT_ON": "Gateway outage redirect (Broadband Status Notification) enabled",
	"GATEWAY_CERT_CHANGED":     "Gateway TLS certificate changed (authenticated gateway requests paused until the owner confirms it)",
	"NO_ACCESS_CODE":           "No gateway access code configured (the outage-redirect setting cannot be checked)",
	"ANCHOR_UNTRUSTED":         "Newest time-stamps not chain-verified (they do not count as proof of time)",
	"EGRESS_NOT_VIA_GATEWAY":   "This computer's internet traffic bypasses the AT&T gateway (VPN or another network): nothing measured is attributed to AT&T",
	"LEDGER_WRITE_FAILING":     "Evidence ledger refusing records (nothing is being recorded)",
	"DISK_SPACE_LOW":           "Low disk space on the volume holding the evidence",
	"CLOCK_OFFSET":             "This computer's clock differs from the SNTP time servers",
}

func codeLabel(code string) string {
	if l, ok := codeLabels[code]; ok {
		return l
	}
	s := strings.ToLower(strings.ReplaceAll(code, "_", " "))
	if s == "" {
		return code
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

var eventLabels = map[string]string{
	model.GwEvReboot:              "Gateway reboot",
	model.GwEvFirmwareChange:      "Firmware change",
	model.GwEvWANIPChange:         "WAN IPv4 address change",
	model.GwEvBroadbandState:      "Broadband connection state",
	model.GwEvPONState:            "PON (fiber) link state",
	model.GwEvOpticalAlarm:        "Optical alarm flag (gateway)",
	model.GwEvOpticalLinkChange:   "Optical link change (fiberstat Last Change)",
	model.GwEvCountersReset:       "Interface counters reset",
	model.GwEvCertPinned:          "Gateway TLS certificate pinned",
	model.GwEvCertChanged:         "Gateway TLS certificate changed",
	model.GwEvGatewayClock:        "Gateway clock",
	model.GwEvNotificationSetting: "Broadband Status Notification setting",
	model.GwEvUnreachable:         "Gateway web interface unreachable",
}

func eventLabel(kind string) string {
	if l, ok := eventLabels[kind]; ok {
		return l
	}
	return kind
}

var reportTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"utc":        fmtUTC,
	"dur":        fmtDur,
	"pct":        fmtPct,
	"pctp":       fmtPctp,
	"x10":        fmtX10,
	"x10p":       fmtX10p,
	"int":        fmtInt,
	"fp":         groupFingerprint,
	"short":      short,
	"seqs":       fmtSeqs,
	"join":       strings.Join,
	"codeLabel":  codeLabel,
	"eventLabel": eventLabel,
	"useq":       func(p *uint64) uint64 { return *p },
	"plural":     plural,
	"ms1": func(p *float64) string {
		if p == nil {
			return "n/a"
		}
		return strconv.FormatFloat(*p, 'f', 1, 64) + " ms"
	},
	"secs":      fmtSecs,
	"num":       fmtNum,
	"mul15":     func(f float64) float64 { return f * 1.5 },
	"durp":      fmtDurp,
	"unix":      unixSeconds,
	"stateSecs": stateSecs,
	"colonhex":  colonHex,
	"ipct":      fmtShare,
	"sub":       func(a, b int) int { return a - b },
}).Parse(reportHTML))

// Local renders a time in the exporting computer's zone ({{$.Local ...}} in the template).
func (v *htmlView) Local(s string) string { return fmtLocalIn(v.loc, s) }

// renderHTML renders REPORT.html, with local times in loc.
func renderHTML(r *report, chart *opticalChart, loc *time.Location) ([]byte, error) {
	v := &htmlView{loc: loc, R: r, Chart: chart, Highlights: highlights(r)}
	v.Incidents, v.IncidentsMore = capList(r.Incidents, maxHTMLIncidents)
	v.Events, v.EventsMore = capList(r.GatewayEvents, maxHTMLEvents)
	v.Custody, v.CustodyMore = capList(r.Custody, maxHTMLCustody)
	v.Anchors, v.AnchorsMore = anchorsForHTML(r)
	v.AnchorExamples = anchorExamples(r.Anchors)
	v.RootsFile = "TSA-root-CA.pem"
	if len(r.Bundle.TSARoots) > 0 {
		v.RootsFile = tsaRootsPath
	}
	for t, n := range r.Ledger.TypeCounts {
		v.TypeCounts = append(v.TypeCounts, valueCount{Value: t, Count: n})
	}
	sort.Slice(v.TypeCounts, func(i, j int) bool { return v.TypeCounts[i].Value < v.TypeCounts[j].Value })
	if f := r.Verification.Full; f != nil {
		v.FullFailures = f.Failures
	}
	var buf bytes.Buffer
	if err := reportTemplate.Execute(&buf, v); err != nil {
		return nil, fmt.Errorf("export: render REPORT.html: %w", err)
	}
	return buf.Bytes(), nil
}

// fmtDurp renders a recorded duration, or "not recorded" when the record lacks it.
func fmtDurp(p *int64) string {
	if p == nil {
		return "not recorded"
	}
	return fmtDur(*p)
}

// unixSeconds renders an RFC 3339 time as Unix seconds (the -attime argument of openssl).
func unixSeconds(s string) string {
	t, ok := parseTS(s)
	if !ok {
		return "GENTIME"
	}
	return strconv.FormatInt(t.Unix(), 10)
}

// stateSecs returns the cycle time of one state.
func stateSecs(list []stateTime, state string) int64 {
	for _, x := range list {
		if x.State == state {
			return x.Seconds
		}
	}
	return 0
}

// colonHex renders a hex fingerprint the way certificate tools show it: "55:2F:7B:...".
func colonHex(h string) string {
	h = strings.ToUpper(h)
	var b strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i:min(i+2, len(h))])
	}
	return b.String()
}

func capList[T any](in []T, n int) ([]T, int) {
	if len(in) <= n {
		return in, 0
	}
	return in[:n], len(in) - n
}

// anchorsForHTML shows the anchors made during the period plus, per TSA, the first one after
// it (it covers the end of the period); long lists keep their first and last entries.
func anchorsForHTML(r *report) ([]anchorEntry, int) {
	from, _ := parseTS(r.Period.From)
	end, _ := parseTS(r.Period.EffectiveEnd)
	var out []anchorEntry
	after := map[string]bool{}
	for _, an := range r.Anchors {
		t, ok := parseTS(an.TS)
		if !ok {
			continue
		}
		switch {
		case t.Before(from):
		case t.Before(end):
			out = append(out, an)
		case !after[an.TSAURL]:
			after[an.TSAURL] = true
			out = append(out, an)
		}
	}
	if len(out) <= maxHTMLAnchors {
		return out, 0
	}
	half := maxHTMLAnchors / 2
	more := len(out) - maxHTMLAnchors
	return append(append([]anchorEntry{}, out[:half]...), out[len(out)-half:]...), more
}

// anchorExamples returns the latest verified anchor per TSA (for the OpenSSL instructions).
func anchorExamples(all []anchorEntry) []anchorEntry {
	idx := map[string]int{}
	var out []anchorEntry
	for _, an := range all {
		if an.HeadCheck != "ok" || !an.TokenIncluded || an.TokenCheck != "ok" {
			continue
		}
		if i, ok := idx[an.TSAURL]; ok {
			out[i] = an
			continue
		}
		idx[an.TSAURL] = len(out)
		out = append(out, an)
	}
	return out
}

// highlights are the executive-summary sentences, each computed from report data.
func highlights(r *report) []string {
	s := r.Summary
	var h []string
	assumed := ""
	if s.CadenceAssumed {
		assumed = " (assumed: too few samples to measure it)"
	}
	h = append(h, fmt.Sprintf("Monitoring covered %s of the period (%s monitored out of %s), with %s at a median interval of %.0f s%s.",
		fmtPct(s.CoveragePct), fmtDur(s.MonitoredSec), fmtDur(s.WindowSec), plural(s.Cycles, "measurement cycle", "measurement cycles"),
		s.CadenceSec, assumed))
	if s.AvailabilityPct != nil {
		h = append(h, fmt.Sprintf("%s of the measurement cycles with a known state were classified ONLINE.", fmtPct(*s.AvailabilityPct)))
	}
	switch {
	case s.Incidents == 0:
		h = append(h, "No incident overlaps the period.")
	case s.Incidents == 1 && s.ProviderIncidents == 1:
		h = append(h, "1 incident overlaps the period; its record attributes it to the provider (AT&T).")
	case s.Incidents == 1:
		h = append(h, "1 incident overlaps the period; its record does not attribute it to the provider.")
	case s.ProviderIncidents == 0:
		h = append(h, fmt.Sprintf("%d incidents overlap the period; their records attribute none of them to the provider.", s.Incidents))
	default:
		h = append(h, fmt.Sprintf("%d incidents overlap the period; their records attribute %d of them to the provider (AT&T).",
			s.Incidents, s.ProviderIncidents))
	}
	outage := fmt.Sprintf("Provider-attributed outage time: %s - the measurement cycles in which no internet target answered while the AT&T gateway did (ISP_OUTAGE), outside gateway-restart windows", fmtDur(s.ProviderOutageSec))
	if s.ProviderDegradedSec > 0 {
		outage += fmt.Sprintf("; in addition %s of provider-attributed degraded service", fmtDur(s.ProviderDegradedSec))
	}
	h = append(h, outage+". These figures count the cycles recorded in this bundle, not incident start and end times.")
	if n := len(s.GatewayRestarts); n > 0 || s.RestartSec > 0 {
		h = append(h, fmt.Sprintf("%s of bad cycles fell inside the restart windows of %s; under rules %s that time is restart time, not provider outage time.",
			fmtDur(s.RestartSec), plural(n, "gateway restart", "gateway restarts"), r.Methodology.RulesDescribed))
		fw := 0
		for _, g := range s.GatewayRestarts {
			if g.Firmware != "" {
				fw++
			}
		}
		if fw > 0 {
			h = append(h, fmt.Sprintf("%s coincided with a gateway firmware change (an AT&T-pushed update): the rules attribute an incident "+
				"caused only by such a restart to the provider (cause GATEWAY_REBOOT), but its restart time is still not counted as provider outage time.",
				plural(fw, "gateway restart", "gateway restarts")))
		}
	}
	conflicts := 0
	for _, e := range r.Incidents {
		if e.RestartCheck != nil && len(e.RestartCheck.Conflicts) > 0 {
			conflicts++
		}
	}
	if conflicts > 0 {
		h = append(h, fmt.Sprintf("%s contradicted by the gateway-restart windows this report computes from the records (rules %s): "+
			"each says so in the key facts of the incident table, with the classification the rules give.",
			plural(conflicts, "incident record is", "incident records are"), r.Methodology.RulesDescribed))
	}
	if ids := s.IncidentsWithoutRecords; len(ids) > 0 {
		h = append(h, fmt.Sprintf("Samples of this period also carry the incident id(s) %s, whose incident records are not in this bundle; "+
			"those cycles are included in the figures above, but the incident is not described in the incident table.",
			strings.Join(ids, ", ")))
	}
	if lo := s.LongestOutage; lo != nil {
		span := fmt.Sprintf("lasting %s from opening to closing", fmtDur(lo.Seconds))
		if lo.Ongoing {
			span = fmt.Sprintf("open for %s and still open at the end of the period (no close record in this bundle)", fmtDur(lo.Seconds))
		}
		switch {
		case lo.DowntimeSec != nil && lo.DowntimeComputed:
			span += fmt.Sprintf("; %s without Internet so far, computed from its samples in this bundle", fmtDur(*lo.DowntimeSec))
		case lo.DowntimeSec != nil:
			span += fmt.Sprintf("; its record counts %s without Internet", fmtDur(*lo.DowntimeSec))
		}
		if lo.RestartConflict {
			span += "; its record is contradicted by the gateway-restart windows computed from the records (see its key facts)"
		}
		h = append(h, fmt.Sprintf("Longest outage incident: %s, %s / %s (attribution: %s), %s.", lo.ID, lo.State, lo.Cause, lo.Attribution, span))
	}
	switch {
	case s.Blips == 1:
		h = append(h, fmt.Sprintf("1 short disruption too brief to open an incident (a blip) was also recorded (%s).", plural(s.BlipCycles, "bad cycle", "bad cycles")))
	case s.Blips > 1:
		h = append(h, fmt.Sprintf("%d short disruptions too brief to open an incident (blips) were also recorded (%s in total).", s.Blips, plural(s.BlipCycles, "bad cycle", "bad cycles")))
	}
	o := r.Optical
	// Flags and readings are counted over the same set: the fiber status readings in which
	// the gateway's DMI table (and so its flags) could be read.
	if o.Snapshots > 0 && o.LowAlarmN > 0 {
		h = append(h, fmt.Sprintf("The AT&T gateway itself flagged its received optical power as below its low-alarm threshold in %s of %s (Rx %s to %s dBm; gateway threshold %s dBm).",
			fmtInt(o.LowAlarmN), plural(o.Snapshots, "fiber status reading", "fiber status readings"), fmtX10p(o.RxMinX10), fmtX10p(o.RxMaxX10), fmtX10p(o.LowAlarmThrX10)))
	} else if o.Snapshots > 0 && o.LowWarnN > 0 {
		h = append(h, fmt.Sprintf("The AT&T gateway flagged its received optical power as below its low-warning threshold in %s of %s.",
			fmtInt(o.LowWarnN), plural(o.Snapshots, "fiber status reading", "fiber status readings")))
	}
	if n := r.Service.DNSHijacks + r.Service.HTTPHijacks; n > 0 {
		h = append(h, fmt.Sprintf("Redirection of DNS or web traffic (hijacking) was detected in %s (DNS %d, HTTP %d).",
			plural(n, "observation", "observations"), r.Service.DNSHijacks, r.Service.HTTPHijacks))
	}
	switch len(s.Gaps) {
	case 0:
	case 1:
		h = append(h, fmt.Sprintf("1 monitoring gap of %s; it is listed with the records that explain it.", fmtDur(s.GapSec)))
	default:
		h = append(h, fmt.Sprintf("%d monitoring gaps totalling %s; each is listed with the records that explain it.", len(s.Gaps), fmtDur(s.GapSec)))
	}
	if a := s.LastRecordAnchor; a != nil {
		h = append(h, fmt.Sprintf("The records of this period are covered by an independent RFC 3161 time-stamp from %s dated %s (anchor seq %d covers records up to seq %d; %s).",
			a.TSA, fmtUTC(a.GenTime), a.Seq, a.HeadSeq, proofBasisText(a.ProofBasis)))
	} else if s.LastRecordInPeriod != nil {
		h = append(h, "The last records of this period are not covered by an RFC 3161 time-stamp in this bundle that is accepted as proof of time.")
	}
	return h
}

// proofBasisText says on what a proof-of-time anchor rests.
func proofBasisText(basis string) string {
	if basis == "token_verifier" {
		return "the token's signature and the TSA certificate chain were checked at export"
	}
	return "the TSA certificate chain was not re-checked at export; its record states it verified and chained when obtained"
}

const reportHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="{{.R.Generator.Name}} {{.R.Generator.Version}}">
<title>AT&amp;T service evidence report {{utc .R.Period.From}} to {{utc .R.Period.To}}</title>
<style>
:root{--page:#f9f9f7;--surface:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--muted:#6b6a65;--grid:#e1e0d9;--axis:#c3c2b7;--line:rgba(11,11,11,.12);--series:#2a78d6;--series-wash:rgba(42,120,214,.14);--crit:#d03b3b;--crit-ink:#a82a2a;--crit-wash:rgba(208,59,59,.10);--warn:#fab219;--warn-ink:#7a5200;--warn-wash:rgba(250,178,25,.18);--good:#0ca30c;--good-ink:#006300;--good-wash:rgba(12,163,12,.10);--hover:rgba(42,120,214,.10);color-scheme:light}
@media (prefers-color-scheme:dark){:root{--page:#0d0d0d;--surface:#1a1a19;--ink:#ffffff;--ink2:#c3c2b7;--muted:#9a988f;--grid:#2c2c2a;--axis:#383835;--line:rgba(255,255,255,.12);--series:#3987e5;--series-wash:rgba(57,135,229,.20);--crit:#e66767;--crit-ink:#ff9a9a;--crit-wash:rgba(230,103,103,.16);--warn:#fab219;--warn-ink:#fab219;--warn-wash:rgba(250,178,25,.16);--good:#0ca30c;--good-ink:#4bd14b;--good-wash:rgba(12,163,12,.18);--hover:rgba(57,135,229,.16);color-scheme:dark}}
@media print{:root{--page:#ffffff;--surface:#ffffff;--ink:#0b0b0b;--ink2:#52514e;--muted:#6b6a65;--grid:#e1e0d9;--axis:#c3c2b7;--line:rgba(11,11,11,.18);--series:#2a78d6;--series-wash:rgba(42,120,214,.14);--crit:#d03b3b;--crit-ink:#a82a2a;--crit-wash:rgba(208,59,59,.10);--warn:#fab219;--warn-ink:#7a5200;--warn-wash:rgba(250,178,25,.18);--good:#0ca30c;--good-ink:#006300;--good-wash:rgba(12,163,12,.10);color-scheme:light}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--page);color:var(--ink);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;overflow-wrap:break-word}
main{max-width:1120px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:24px;line-height:1.25;margin:0 0 4px}
h2{font-size:18px;margin:36px 0 8px;padding-top:10px;border-top:1px solid var(--line)}
h3{font-size:15px;margin:22px 0 6px}
p{margin:6px 0}
a{color:inherit}
.sub{color:var(--ink2);margin:0 0 12px}
.muted{color:var(--muted)}
.card{background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:12px 14px;margin:10px 0}
dl.meta{display:grid;grid-template-columns:minmax(120px,max-content) 1fr;gap:5px 16px;margin:0}
dl.meta dt{color:var(--ink2)}
dl.meta dd{margin:0;min-width:0;overflow-wrap:anywhere}
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(165px,1fr));gap:10px;margin:12px 0}
.tile{background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
.tile .label{color:var(--ink2);font-size:12.5px}
.tile .value{font-size:22px;font-weight:600;margin-top:2px}
.tile .note{color:var(--muted);font-size:12px;overflow-wrap:anywhere}
.tablewrap{overflow-x:auto;margin:8px 0}
table{border-collapse:collapse;width:100%;background:var(--surface);font-size:13px}
th,td{border-bottom:1px solid var(--line);padding:5px 8px;text-align:left;vertical-align:top}
th{color:var(--ink2);font-weight:600;background:var(--page)}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.mono,code,pre{font-family:ui-monospace,"Cascadia Mono",Consolas,monospace;font-size:12px}
.mono{overflow-wrap:anywhere}
.nowrap{white-space:nowrap}
.preline{white-space:pre-line}
.chartwrap{overflow-x:auto}
code{overflow-wrap:anywhere}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:var(--surface);border:1px solid var(--line);border-radius:6px;padding:10px;margin:6px 0}
ul.facts{margin:0;padding-left:16px}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-weight:600;font-size:12.5px;white-space:nowrap}
.badge.pass{color:var(--good-ink);background:var(--good-wash)}
.badge.fail{color:var(--crit-ink);background:var(--crit-wash)}
.badge.warn{color:var(--warn-ink);background:var(--warn-wash)}
.badge.info{color:var(--ink2);background:var(--line)}
.callout{border-left:4px solid var(--crit);background:var(--crit-wash);padding:8px 12px;border-radius:4px;margin:10px 0}
.callout.note{border-left-color:var(--axis);background:var(--surface)}
nav.toc{background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:8px 14px;margin:12px 0}
nav.toc ol{columns:2;margin:4px 0;padding-left:20px}
figure{margin:10px 0}
figcaption{color:var(--ink2);font-size:12.5px;margin-top:4px}
.chart{width:100%;min-width:640px;height:auto;display:block;background:var(--surface);border:1px solid var(--line);border-radius:8px}
.chart text{font-size:12px;fill:var(--ink2);font-family:system-ui,-apple-system,"Segoe UI",sans-serif}
.chart .tick{fill:var(--muted);font-variant-numeric:tabular-nums}
.chart .ytick{text-anchor:end}
.chart .xlabel{text-anchor:middle}
.chart .grid{stroke:var(--grid);stroke-width:1}
.chart .axis,.chart .xtick{stroke:var(--axis);stroke-width:1}
.chart .series{fill:none;stroke:var(--series);stroke-width:2;stroke-linejoin:round;stroke-linecap:round}
.chart .band{fill:var(--series-wash);stroke:none}
.chart .dot{fill:var(--series);stroke:var(--surface);stroke-width:2}
.chart .ref{stroke-width:1.5;stroke-dasharray:6 4}
.chart .ref.alarm{stroke:var(--crit)}
.chart .ref.warning{stroke:var(--warn)}
.chart .ref-label,.chart .end-label{fill:var(--ink);paint-order:stroke;stroke:var(--surface);stroke-width:4px;stroke-linejoin:round}
.chart .ref-label{text-anchor:end}
.chart .alarm-band{fill:var(--crit-wash)}
.chart .hit{fill:transparent}
.chart .hit:hover{fill:var(--hover)}
.legend{display:flex;flex-wrap:wrap;gap:6px 18px;margin:8px 0 4px;font-size:12.5px;color:var(--ink2)}
.legend span{white-space:nowrap}
.key{display:inline-block;width:20px;height:0;vertical-align:middle;margin-right:6px;border-top:2px solid var(--series)}
.key.alarm{border-top:2px dashed var(--crit)}
.key.warning{border-top:2px dashed var(--warn)}
.key.shade{height:12px;border:1px solid var(--crit);background:var(--crit-wash)}
.key.band{height:10px;border:0;background:var(--series-wash)}
footer{margin-top:40px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:10px}
@page{margin:14mm}
@media print{body{font-size:10.5pt}main{max-width:none;padding:0}nav.toc{display:none}.tablewrap{overflow:visible}tr,.tile,.card,figure,.callout{break-inside:avoid}h2,h3{break-after:avoid}.chart .hit:hover{fill:transparent}.chart{min-width:0}*{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
</style>
</head>
<body>
<main>
<header>
<h1>AT&amp;T Fiber service evidence report</h1>
<p class="sub">{{if eq .R.Period.Scope "incident"}}Incident {{.R.Period.IncidentID}} &middot; {{end}}{{$.Local .R.Period.From}} to {{$.Local .R.Period.To}}</p>
<div class="card">
<dl class="meta">
<dt>Period (local time)</dt><dd>{{$.Local .R.Period.From}} to {{$.Local .R.Period.To}}</dd>
<dt>Period (UTC)</dt><dd>{{utc .R.Period.From}} to {{utc .R.Period.To}}{{if ne .R.Period.EffectiveEnd .R.Period.To}} <span class="muted">(statistics end at the export time, {{utc .R.Period.EffectiveEnd}})</span>{{end}}</dd>
<dt>Report generated</dt><dd>{{$.Local .R.GeneratedAt}} ({{utc .R.GeneratedAt}}) by {{.R.Generator.Name}} {{.R.Generator.Version}}{{if .R.Generator.Commit}} ({{.R.Generator.Commit}}){{end}}</dd>
<dt>Evidence bundle</dt><dd class="mono">{{.R.Bundle.FileName}}</dd>
<dt>Monitoring computer</dt><dd>{{with .R.Host}}{{.Hostname}}, {{.OS}} {{.OSVersion}}{{if .TimeZone}}, time zone {{.TimeZone}}{{end}} <span class="muted">(from the {{.SourceType}} record, seq {{.SourceSeq}})</span>{{else}}not recorded in this bundle{{end}}</dd>
<dt>AT&amp;T gateway</dt><dd>{{range .R.Gateway}}{{.Manufacturer}} {{.Model}}, serial {{.Serial}}, firmware {{.Firmware}}{{if .Hardware}}, hardware {{.Hardware}}{{end}} <span class="muted">(as reported by the gateway in {{plural .Snapshots "snapshot" "snapshots"}}, seq {{.FirstSeq}}-{{.LastSeq}}{{if .BeforePeriod}}, last snapshot before the period{{end}})</span><br>{{else}}no gateway snapshot in this bundle{{end}}</dd>
<dt>Ledger key fingerprint</dt><dd class="mono">{{if .R.Ledger.Fingerprint}}{{fp .R.Ledger.Fingerprint}}{{else}}unknown (no valid genesis record){{end}}</dd>
<dt>Ledger head in bundle</dt><dd class="mono">{{with .R.Ledger.Head}}seq {{.Seq}} &middot; {{.Hash}} &middot; {{utc .TS}}{{else}}none{{end}}</dd>
<dt>Verification</dt><dd>
<div>{{if eq .R.Verification.Overall "pass"}}<span class="badge pass">&#10003; PASS</span>{{else}}<span class="badge fail">&#10007; FAIL</span>{{end}} overall result at export time</div>
<div>Full ledger on the monitoring computer: {{with .R.Verification.Full}}{{if .OK}}<span class="badge pass">&#10003; PASS</span>{{else}}<span class="badge fail">&#10007; FAIL</span>{{end}} {{plural .Records "record" "records"}}, {{plural .FailuresTotal "failure" "failures"}}, {{.AnchorsProofOfTime}} of {{plural .Anchors "time-stamp" "time-stamps"}} accepted as proof of time{{if not .TokensChecked}} (tokens not cryptographically re-checked: the records' issue-time flags decide){{end}}, {{plural .UnanchoredTail "newest record" "newest records"}} not covered by such a time-stamp <span class="muted">(verified {{utc .At}})</span>{{if .KeyMismatch}} <span class="badge fail">&#10007; different ledger key</span> that verification concerns a ledger with a different ledger key ({{fp .Fingerprint}}), so it does not vouch for this bundle{{end}}{{else}}{{if .R.Verification.FullError}}<span class="badge fail">&#10007; ERROR</span> {{.R.Verification.FullError}}{{else if .R.Verification.FullIncomplete}}<span class="badge warn">not completed</span> {{.R.Verification.FullIncomplete}}{{else}}<span class="badge info">not performed</span>{{end}}{{end}}</div>
{{with .R.Verification.Bundle}}<div>This bundle (checked while it was written): {{if .OK}}<span class="badge pass">&#10003; PASS</span>{{else}}<span class="badge fail">&#10007; FAIL</span>{{end}} {{plural .Records "record" "records"}} in {{plural .Segments "segment" "segments"}}; hashes OK {{int .HashesOK}}, signatures OK {{int .SignaturesOK}}, chain problems {{.ChainFailures}}; blobs {{.BlobsIncluded}} of {{.BlobsReferenced}} included; {{.AnchorsHeadOK}} of {{.AnchorsChecked}} time-stamp anchors match their head record and {{.AnchorTokensOK}} of their tokens verify (message imprint and TSA signature); {{.AnchorsProofOfTime}} of them are accepted as proof of time ({{if .TokenVerifier}}TSA certificate chains checked at export{{else}}no token verifier at export: per the anchor records' issue-time flags{{end}}).</div>{{end}}
</dd>
{{if .R.Request.PreparedBy}}<dt>Prepared by</dt><dd>{{.R.Request.PreparedBy}}</dd>{{end}}
{{if .R.Request.Requester}}<dt>Requested via</dt><dd>{{.R.Request.Requester}}</dd>{{end}}
{{if .R.Request.Notes}}<dt>Notes</dt><dd class="preline">{{.R.Request.Notes}}</dd>{{end}}
</dl>
</div>
<p class="muted">Local times are shown in the exporting computer's time zone ({{.R.Period.LocalZone}} at the start of the period) with the zone abbreviation; UTC is shown alongside. Every figure in this report is computed from the ledger records contained in this bundle: <code>att-monitor verify-bundle</code> recomputes them from those records and fails if any differs. MANIFEST.sha256 alone does not protect this report (anyone can edit it and recompute the manifest), and tools/verify_bundle.py verifies the records, which are the evidence, not this report's figures.</p>
</header>

<nav class="toc"><strong>Contents</strong>
<ol>
<li><a href="#summary">Executive summary</a></li>
<li><a href="#incidents">Incidents</a></li>
<li><a href="#optical">AT&amp;T gateway optical levels</a></li>
<li><a href="#gateway">AT&amp;T gateway status and events</a></li>
<li><a href="#observations">DNS, web, local link and clock</a></li>
<li><a href="#methodology">Methodology and rules</a></li>
<li><a href="#integrity">Integrity and verification</a></li>
<li><a href="#custody">Custody log</a></li>
</ol>
</nav>

<section id="summary">
<h2>1. Executive summary</h2>
<div class="tiles">
<div class="tile"><div class="label">Monitoring coverage</div><div class="value">{{pct .R.Summary.CoveragePct}}</div><div class="note">{{dur .R.Summary.MonitoredSec}} of {{dur .R.Summary.WindowSec}}</div></div>
<div class="tile"><div class="label">Availability (ONLINE cycles)</div><div class="value">{{pctp .R.Summary.AvailabilityPct}}</div><div class="note">of {{int .R.Summary.CyclesKnown}} cycles with a known state</div></div>
<div class="tile"><div class="label">Provider-attributed outage time</div><div class="value">{{dur .R.Summary.ProviderOutageSec}}</div><div class="note">no Internet while the AT&amp;T gateway answered; gateway restarts excluded</div></div>
{{if or .R.Summary.RestartSec .R.Summary.GatewayRestarts}}<div class="tile"><div class="label">Gateway restart time</div><div class="value">{{dur .R.Summary.RestartSec}}</div><div class="note">{{plural (len .R.Summary.GatewayRestarts) "gateway restart" "gateway restarts"}}; not counted as provider outage time</div></div>
{{end}}<div class="tile"><div class="label">Incidents</div><div class="value">{{.R.Summary.Incidents}}</div><div class="note">{{.R.Summary.ProviderIncidents}} attributed to the provider by their records</div></div>
<div class="tile"><div class="label">Longest outage incident</div><div class="value">{{with .R.Summary.LongestOutage}}{{dur .Seconds}}{{else}}none{{end}}</div><div class="note">{{with .R.Summary.LongestOutage}}{{.ID}} &middot; {{.State}}{{if .DowntimeSec}} &middot; {{durp .DowntimeSec}} without Internet{{if .DowntimeComputed}} so far{{end}}{{end}}{{end}}</div></div>
<div class="tile"><div class="label">Blips (shorter bad streaks)</div><div class="value">{{.R.Summary.Blips}}</div><div class="note">{{.R.Summary.BlipCycles}} bad cycles</div></div>
</div>
<ul>{{range .Highlights}}<li>{{.}}</li>{{end}}</ul>

<h3>Incidents by classification</h3>
{{if .R.Summary.IncidentsByClass}}<div class="tablewrap"><table>
<thead><tr><th>State</th><th>Cause</th><th>Attribution</th><th class="num">Incidents</th><th class="num">Incident time in period (opened to closed)</th></tr></thead>
<tbody>{{range .R.Summary.IncidentsByClass}}<tr><td>{{.State}}</td><td>{{.Cause}}</td><td>{{.Attribution}}</td><td class="num">{{.Count}}</td><td class="num">{{dur .Seconds}}</td></tr>{{end}}</tbody>
</table></div>{{else}}<p>No incidents in this period.</p>{{end}}

<h3>Measurement cycles by state</h3>
{{if .R.Summary.CyclesByState}}<div class="tablewrap"><table>
<thead><tr><th>State (as recorded)</th><th class="num">Cycles</th><th class="num">Share</th><th class="num">Cycle time</th></tr></thead>
<tbody>{{$n := .R.Summary.Cycles}}{{range .R.Summary.CyclesByState}}<tr><td>{{.State}}</td><td class="num">{{int .Count}}</td><td class="num">{{ipct .Count $n}}</td><td class="num">{{dur (stateSecs $.R.Summary.TimeByState .State)}}</td></tr>{{end}}</tbody>
</table></div>{{else}}<p>No measurement cycles were recorded in this period.</p>{{end}}

<h3>Time without Internet, degraded service and gateway restarts</h3>
{{with .R.Summary}}<div class="tablewrap"><table><tbody>
<tr><th>Monitored (cycle time)</th><td class="num">{{dur .MonitoredSec}}</td></tr>
<tr><th>No Internet while the AT&amp;T gateway answered (ISP_OUTAGE), outside gateway-restart windows</th><td class="num">{{dur .DowntimeSec}}</td></tr>
<tr><th>&nbsp;&nbsp;of which attributed to the provider (provider outage time)</th><td class="num">{{dur .ProviderOutageSec}}</td></tr>
<tr><th>Degraded service (DEGRADED), outside gateway-restart windows</th><td class="num">{{dur .DegradedSec}}</td></tr>
<tr><th>&nbsp;&nbsp;of which attributed to the provider</th><td class="num">{{dur .ProviderDegradedSec}}</td></tr>
<tr><th>Bad cycles inside gateway-restart windows (restart time, not counted as provider outage time)</th><td class="num">{{dur .RestartSec}}</td></tr>
</tbody></table></div>
<p class="muted">These figures count measurement cycles, not incident start and end times: each cycle covers the time until the next cycle of the same monitor process started (in the order the cycles were recorded, so that a step of the computer's clock neither shrinks nor stretches them), at most {{secs (mul15 .FastIntervalSec)}} (1.5 &times; the cycle interval of {{secs .FastIntervalSec}}; source: {{.FastIntervalBasis}}); the last cycle before the monitor stopped covers only until it was recorded (its last observation), as the monitor closes an incident left open by a stopped monitor; longer intervals are monitoring gaps. They are computed from the sample records in this bundle with the rules of section 6.</p>{{end}}

<h3>Monitoring gaps</h3>
{{if .R.Summary.Gaps}}<div class="tablewrap"><table>
<thead><tr><th>From</th><th>To</th><th class="num">Duration</th><th>Explanation (from ledger records)</th></tr></thead>
<tbody>{{range .R.Summary.Gaps}}<tr><td>{{$.Local .From}}<br><span class="muted">{{utc .From}}</span></td><td>{{$.Local .To}}<br><span class="muted">{{utc .To}}</span></td><td class="num">{{dur .Seconds}}</td><td>{{.Explanation}}</td></tr>{{end}}</tbody>
</table></div>{{else}}<p>No gap longer than three cycle intervals between consecutive samples.</p>{{end}}
</section>

<section id="incidents">
<h2>2. Incidents</h2>
{{with .R.Methodology.Thresholds}}<p>An incident opens when at least {{.OpenAfterCycles}} of the last {{.WindowCycles}} measurement cycles are not ONLINE (a continuous outage or intermittent connectivity; its start is the start of the earliest of those bad cycles) and closes after {{.CloseAfterCycles}} consecutive ONLINE cycles (its end is the first of them). State, cause and attribution are assigned by the versioned rules in section 6.</p>{{end}}
<p>The times without Internet, degraded and restart times are the incident record's own cycle-time figures (downtime_s, degraded_s, restart_s; section 6); "not recorded" means the record was written under an older rules version that did not record the figure. For an incident still open at the end of the period (no close record in this bundle) its latest record states these figures only as of when it was written (the monitor rewrites an open incident only when its classification changes), so they are computed by this report from the samples in this bundle instead, and the record's own figures are shown below them. Recovered: the start of the first cycle after the last outage cycle in which every probe succeeded. Key facts are quoted or computed from the incident records and samples; conditions the gateway reported before the incident opened are marked as such. The evidence column lists the ledger records (by seq) that support each incident.</p>
{{if .Incidents}}<div class="tablewrap"><table>
<thead><tr><th>Incident</th><th>Opened</th><th>Closed</th><th class="num">Duration</th><th class="num">Without Internet</th><th class="num">Degraded</th><th class="num">Restart time</th><th>Recovered</th><th>Gateway restarts</th><th>State / cause / attribution</th><th>Key facts</th><th>Evidence (ledger seq)</th></tr></thead>
<tbody>{{range .Incidents}}<tr>
<td class="mono">{{.Incident.ID}}</td>
<td>{{$.Local .Incident.Opened}}<br><span class="muted">{{utc .Incident.Opened}}</span></td>
<td>{{if .Ongoing}}<span class="badge warn">open</span> no close record up to {{utc .EffectiveEnd}}{{else}}{{$.Local .Incident.Closed}}<br><span class="muted">{{utc .Incident.Closed}}</span>{{end}}</td>
<td class="num">{{dur .DurationSec}}</td>
{{if .Computed}}<td class="num">{{dur .Computed.Stats.DowntimeSec}}<br><span class="muted">so far, computed from the samples; its record seq {{.RecordedSeq}} says {{durp .Recorded.DowntimeSec}}</span></td>
<td class="num">{{dur .Computed.Stats.DegradedSec}}<br><span class="muted">so far; record: {{durp .Recorded.DegradedSec}}</span></td>
<td class="num">{{dur .Computed.Stats.RestartSec}}<br><span class="muted">so far; record: {{durp .Recorded.RestartSec}}</span></td>
{{else}}<td class="num">{{durp .Recorded.DowntimeSec}}{{with .ComputedDowntime}}<br><span class="muted">outside the restart windows computed from the records: {{durp .}}</span>{{end}}</td>
<td class="num">{{durp .Recorded.DegradedSec}}</td>
<td class="num">{{durp .Recorded.RestartSec}}{{if .RestartDiffers}}<br><span class="muted">restart windows computed from the records: {{dur .ComputedRestartSec}}{{with .RestartCheck}}{{if not .Complete}} (from its cycles in this bundle up to the end of the period){{end}}{{end}}</span>{{end}}</td>
{{end}}
<td>{{with .Incident.RecoveredAt}}{{$.Local .}}<br><span class="muted">{{utc .}}</span>{{else}}<span class="muted">not recorded</span>{{end}}</td>
<td>{{range .Incident.GatewayRestarts}}boot {{$.Local .}}<br>{{else}}<span class="muted">none recorded</span>{{end}}</td>
<td><strong>{{.Incident.State}}</strong><br>{{.Incident.Cause}}<br>attribution: <strong>{{.Incident.Attribution}}</strong><br><span class="muted">rules {{.Incident.Rules}}</span>{{with .RestartCheck}}{{if .Conflicts}}<br><span class="badge warn">&#9888; contradicted by the restart windows</span><br><span class="muted">under rules {{$.R.Methodology.RulesDescribed}}: {{if .GatewayRestart}}LOCAL_FAULT / GATEWAY_REBOOT, {{end}}attribution {{.Attribution}} (see key facts)</span>{{end}}{{end}}</td>
<td><ul class="facts">{{range .KeyFacts}}<li>{{.}}</li>{{end}}</ul></td>
<td class="mono">{{if .OpenSeq}}opened: {{useq .OpenSeq}}<br>{{end}}{{if .CloseSeq}}closed: {{useq .CloseSeq}}<br>{{end}}incident records: {{seqs .RecordSeqs}}{{if .EvidenceSeqs}}<br>evidence: {{seqs .EvidenceSeqs}}{{end}}{{with .Anchor}}<br>time-stamped by {{.TSA}} at {{utc .GenTime}} (anchor seq {{.Seq}}){{end}}</td>
</tr>{{end}}</tbody>
</table></div>{{if .IncidentsMore}}<p class="muted">{{.IncidentsMore}} more incident(s) are listed in report.json.</p>{{end}}{{else}}<p>No incident overlaps this period.</p>{{end}}
<h3>Gateway restarts</h3>
{{if .R.Summary.GatewayRestarts}}<p>Restarts of the AT&amp;T gateway named by the records (gateway reboot events and the gateway_restarts lists of incident records), with their restart windows (section 6): from the gateway's boot, extended back over the cycles just before it in which the gateway did not answer this computer (rule 1), until the first cycle in which the Internet was reachable again, at most {{secs .R.Methodology.Thresholds.RestartCapSec}} after the boot. Bad cycles inside a window are restart time, never provider outage time.</p>
<div class="tablewrap"><table>
<thead><tr><th>Gateway boot (estimated)</th><th>Restart window</th><th>Window ends</th><th class="num">Bad cycles in the period</th><th class="num">Restart time</th><th>Firmware</th><th>Records</th></tr></thead>
<tbody>{{range .R.Summary.GatewayRestarts}}<tr><td>{{$.Local .BootTime}}<br><span class="muted">{{utc .BootTime}}</span></td><td>{{$.Local .WindowFrom}}<br>to {{$.Local .WindowTo}}</td><td>{{.WindowEnd}}</td><td class="num">{{.BadCycles}}</td><td class="num">{{dur .RestartSec}}</td><td>{{if .Firmware}}changed: {{.Firmware}}{{else}}<span class="muted">no firmware change recorded</span>{{end}}</td><td>{{join .Sources "; "}}{{if .Evidence}}<br><span class="mono">seq {{seqs .Evidence}}</span>{{end}}</td></tr>{{end}}</tbody>
</table></div>{{else}}<p>No gateway restart in this period is named by the records of this bundle.</p>{{end}}
{{with .R.Summary.IncidentsWithoutRecords}}<div class="callout"><strong>Incident records missing from this bundle.</strong> Samples of this period carry the incident id(s) <span class="mono">{{join . ", "}}</span>, but none of the incident's own records (incident_open, incident_update, incident_close) is contained in this bundle, so the incident is not described above. The affected measurement cycles are included in all figures of this report.</div>{{end}}
</section>

<section id="optical">
<h2>3. AT&amp;T gateway optical levels</h2>
<div class="callout"><strong>Source: the AT&amp;T gateway itself.</strong> The optical readings, thresholds and alarm/warning flags in this section are exactly what the AT&amp;T gateway reports about its own fiber module on its status page (fiberstat), recorded unmodified in the ledger. The monitoring software does not compute or judge these flags. Values are in dBm (the gateway reports tenths of a dBm).</div>
{{with .R.Optical}}{{if .Readings}}
<p>{{int .Readings}} Rx power readings in the period: minimum {{x10p .RxMinX10}} dBm, median {{x10p .RxMedianX10}} dBm, maximum {{x10p .RxMaxX10}} dBm, last {{x10p .RxLastX10}} dBm. Gateway thresholds: low alarm {{x10p .LowAlarmThrX10}} dBm, low warning {{x10p .LowWarnThrX10}} dBm. The gateway's low-alarm flag was set in {{int .LowAlarmN}} and its low-warning flag in {{int .LowWarnN}} of {{int .Snapshots}} fiber status readings.{{if .TxMinX10}} Tx power reported by the gateway: {{x10p .TxMinX10}} to {{x10p .TxMaxX10}} dBm.{{end}}</p>
{{if .ThresholdsSeen}}<p>The gateway reported different thresholds during the period: {{join .ThresholdsSeen "; "}}.</p>{{end}}
{{end}}{{end}}
{{with .Chart}}{{$c := .}}
<div class="legend">
<span><i class="key"></i>Rx power reported by the gateway{{if .Bucketed}} (mean per {{.BucketLabel}}){{end}}</span>
{{if .Bucketed}}<span><i class="key band"></i>minimum to maximum within each interval</span>{{end}}
{{range .Refs}}<span><i class="key {{.Class}}"></i>{{.Label}}</span>{{end}}
{{if .HasAlarmBand}}<span><i class="key shade"></i>gateway low-alarm flag set</span>{{end}}
</div>
<figure>
<div class="chartwrap">
<svg class="chart" viewBox="0 0 {{.W}} {{.H}}" role="img" aria-labelledby="optical-title optical-desc">
<title id="optical-title">{{.Title}}</title>
<desc id="optical-desc">{{.Desc}}</desc>
{{range .AlarmBands}}<rect class="alarm-band" x="{{.X}}" y="{{$c.Y0}}" width="{{.W}}" height="{{$c.PlotH}}"><title>{{.Title}}</title></rect>
{{end}}{{range .YTicks}}<line class="grid" x1="{{$c.X0}}" x2="{{$c.X1}}" y1="{{.Y}}" y2="{{.Y}}"/><text class="tick ytick" x="{{$c.YLabelX}}" y="{{.TY}}">{{.Label}}</text>
{{end}}<line class="axis" x1="{{.X0}}" x2="{{.X1}}" y1="{{.Y1}}" y2="{{.Y1}}"/>
{{range .XTicks}}<line class="xtick" x1="{{.X}}" x2="{{.X}}" y1="{{$c.Y1}}" y2="{{$c.TickY2}}"/><text class="tick xlabel" x="{{.X}}" y="{{$c.XLabelY}}">{{.Label}}</text>
{{end}}<text class="tick" x="{{.YLabelX}}" y="{{.AxisTitleY}}" text-anchor="end">dBm</text>
{{range .Bands}}<path class="band" d="{{.}}"/>
{{end}}{{range .Refs}}<line class="ref {{.Class}}" x1="{{$c.X0}}" x2="{{$c.X1}}" y1="{{.Y}}" y2="{{.Y}}"/>
{{end}}{{range .Lines}}<path class="series" d="{{.}}"/>
{{end}}{{range .Dots}}<circle class="dot" cx="{{.X}}" cy="{{.Y}}" r="4"/>
{{end}}{{with .End}}<circle class="dot" cx="{{.X}}" cy="{{.Y}}" r="4"/><text class="end-label" x="{{.LX}}" y="{{.LY}}" text-anchor="{{.Anchor}}">{{.Label}}</text>
{{end}}{{range .Refs}}<text class="ref-label" x="{{.LX}}" y="{{.LY}}">{{.Label}}</text>
{{end}}{{range .Hits}}<rect class="hit" x="{{.X}}" y="{{$c.Y0}}" width="{{.W}}" height="{{$c.PlotH}}"><title>{{.Title}}</title></rect>
{{end}}</svg>
</div>
<figcaption>{{.Desc}} Time axis in local time, {{.ZoneLabel}}. Hover over the chart for individual readings; the same values are in the tables below. Gaps in the line are periods without readings.</figcaption>
</figure>
{{end}}
{{with .R.Optical}}
<h3>Periods with alarm or warning flags set by the gateway</h3>
{{if .Periods}}<div class="tablewrap"><table>
<thead><tr><th>Gateway flag</th><th>First seen</th><th>Last seen</th><th>Ended</th><th class="num">Readings</th><th class="num">Rx during (dBm)</th><th>Records (seq)</th></tr></thead>
<tbody>{{range .Periods}}<tr>
<td>{{if eq .Severity "critical"}}<span class="badge fail">&#9888; ALARM</span>{{else if eq .Severity "warning"}}<span class="badge warn">&#9888; warning</span>{{else}}<span class="badge info">info</span>{{end}} {{codeLabel .Code}}<br><span class="mono muted">{{.Code}}</span></td>
<td>{{$.Local .FirstSeen}}<br><span class="muted">{{utc .FirstSeen}}</span></td>
<td>{{$.Local .LastSeen}}<br><span class="muted">{{utc .LastSeen}}</span></td>
<td>{{if eq .EndReason "cleared"}}cleared by {{utc .ClearedAt}}{{else}}{{.EndReason}}{{end}}</td>
<td class="num">{{int .Snapshots}}</td>
<td class="num">{{x10p .RxMinX10}} to {{x10p .RxMaxX10}}</td>
<td class="mono">{{.FirstSeq}}-{{.LastSeq}}</td>
</tr>{{end}}</tbody>
</table></div>
<p class="muted">A period ends when a reading without the flag is recorded ("cleared"), when no reading was taken for more than 15 minutes ("observation gap"), or at the end of the period. Nothing is assumed about times without readings.</p>
{{else}}<p>{{if .Snapshots}}The gateway did not set any optical alarm or warning flag in this period.{{else}}No fiber status readings were recorded in this period.{{end}}</p>{{end}}
{{if .Rows}}<h3>Readings per {{.RowUnit}} (table view of the chart)</h3>
<div class="tablewrap"><table>
<thead><tr><th>{{if eq .RowUnit "hour"}}Hour{{else}}Day{{end}} starting (local)</th><th class="num">Readings</th><th class="num">Rx min</th><th class="num">Rx median</th><th class="num">Rx max</th><th class="num">Low-alarm flag</th><th class="num">Low-warning flag</th><th class="num">Tx mean</th></tr></thead>
<tbody>{{range .Rows}}<tr><td>{{$.Local .Start}}</td><td class="num">{{.Readings}}</td><td class="num">{{x10p .RxMinX10}}</td><td class="num">{{x10p .RxMedX10}}</td><td class="num">{{x10p .RxMaxX10}}</td><td class="num">{{.LowAlarm}}</td><td class="num">{{.LowWarn}}</td><td class="num">{{x10p .TxMeanX10}}</td></tr>{{end}}</tbody>
</table></div>{{end}}
{{if .LatestDMI}}<h3>Latest fiber module diagnostics, verbatim from the gateway</h3>
<div class="tablewrap"><table>
<thead><tr><th>Measurement</th><th>Current (raw)</th><th>Unit</th><th>Low alarm</th><th>High alarm</th><th>Low warning</th><th>High warning</th></tr></thead>
<tbody>{{range .LatestDMI}}<tr><td>{{.Name}}</td><td class="num">{{.Current}}</td><td>{{.Unit}}</td><td class="mono">{{.LowAlarm}}</td><td class="mono">{{.HighAlrm}}</td><td class="mono">{{.LowWarn}}</td><td class="mono">{{.HighWarn}}</td></tr>{{end}}</tbody>
</table></div>
{{with .LatestSource}}<p class="muted">From the gateway snapshot record seq {{.Seq}} ({{utc .TS}}). Cells read "flag (Threshold value)": a flag of 1 means the gateway reports the condition as active. {{if .PageSHA256}}SHA-256 of the fiberstat page: <span class="mono">{{.PageSHA256}}</span>{{if .PageStored}} (the exact page is stored as <span class="mono">blobs/{{.PageSHA256}}</span>){{end}}.{{end}}</p>{{end}}{{end}}
{{end}}
</section>

<section id="gateway">
<h2>4. AT&amp;T gateway status and events</h2>
{{with .R.GatewayStatus}}{{if .Snapshots}}
<p>Facts reported by the gateway's own status pages in {{plural .Snapshots "snapshot" "snapshots"}} taken during the period ({{int .Reachable}} with the gateway reachable):</p>
<div class="tablewrap"><table><tbody>
<tr><th>Broadband Connection</th><td>Up in {{int .BroadbandUp}}, Down in {{int .BroadbandDown}}, not reported in {{plural .BroadbandUnknown "snapshot" "snapshots"}}</td></tr>
<tr><th>PON link status</th><td>{{range $i, $v := .PONStatus}}{{if $i}}; {{end}}{{$v.Value}} ({{int $v.Count}}){{else}}not reported{{end}}</td></tr>
<tr><th>Optical WAN status</th><td>{{range $i, $v := .OpticalStatus}}{{if $i}}; {{end}}{{$v.Value}} ({{int $v.Count}}){{else}}not reported{{end}}</td></tr>
<tr><th>WAN IPv4 address(es)</th><td class="mono">{{join .WANIPv4 ", "}}</td></tr>
<tr><th>Gateway clock blank</th><td>{{plural .ClockBlank "snapshot" "snapshots"}} (the gateway clears its clock display while its WAN is down)</td></tr>
<tr><th>Page fetches</th><td>{{int .PageFetches}} ({{int .PageErrors}} failed; {{int .PagesStored}} stored byte-exact as blobs)</td></tr>
</tbody></table></div>
{{else}}<p>No gateway snapshot was recorded in this period.</p>{{end}}{{end}}
<h3>Gateway events</h3>
<p>Changes detected by comparing consecutive gateway snapshots (reboots, firmware changes, broadband and PON state, optical link changes and more).</p>
{{if .Events}}<div class="tablewrap"><table>
<thead><tr><th>Time</th><th>Event</th><th>Before</th><th>After</th><th>Detail</th><th>Records (seq)</th></tr></thead>
<tbody>{{range .Events}}<tr><td class="nowrap">{{$.Local .TS}}<br><span class="muted">{{utc .TS}}</span></td><td>{{eventLabel .Kind}}<br><span class="mono muted">{{.Kind}}</span></td><td>{{.Before}}</td><td>{{.After}}</td><td>{{.Detail}}</td><td class="mono">{{.Seq}}{{if .Evidence}}<br>compared: {{seqs .Evidence}}{{end}}</td></tr>{{end}}</tbody>
</table></div>{{if .EventsMore}}<p class="muted">{{.EventsMore}} more event(s) are listed in report.json.</p>{{end}}{{else}}<p>No gateway events were recorded in this period.</p>{{end}}
</section>

<section id="observations">
<h2>5. DNS, web, local link and clock</h2>
{{with .R.Service}}<h3>DNS and web checks</h3>
{{if .Checks}}<p>{{plural .Checks "service check" "service checks"}} in the period. A DNS answer pointing a public name at the gateway or a private address, or any answer for a name under .invalid, counts as DNS hijacking; a redirect or answer from the gateway counts as HTTP hijacking.</p>
{{if .DNS}}<p>A DNS query counts as <em>successful</em> only when the resolver answered NOERROR with at least one answer that was not redirected (hijacked): a well-formed response alone - SERVFAIL, NXDOMAIN or an empty answer - does not. A query that got no valid response is asked once more within its check, so a check can hold two queries for one resolver: the resolver is counted as successful in a check when any of its attempts succeeded, and as failed only when all of them failed (the DNS rule of section 6 judges a resolver the same way, and counts a failure only when the same failure appears in two consecutive checks).</p>
<div class="tablewrap"><table>
<thead><tr><th>DNS resolver</th><th>Server</th><th class="num">Checks</th><th class="num">Successful (any attempt)</th><th class="num">Failed (all attempts)</th><th class="num">Asked again</th><th class="num">Queries</th><th class="num">Successful queries</th><th class="num">Hijacked answers</th></tr></thead>
<tbody>{{range .DNS}}<tr><td>DNS via {{.Role}} resolver</td><td class="mono">{{.Server}}</td><td class="num">{{int .Checks}}</td><td class="num">{{int .Resolved}}</td><td class="num">{{int (sub .Checks .Resolved)}}</td><td class="num">{{int .Retried}}</td><td class="num">{{int .Queries}}</td><td class="num">{{int .OK}}</td><td class="num">{{int .Hijacked}}</td></tr>{{end}}</tbody>
</table></div>{{end}}
{{range .InvalidName}}<p>NXDOMAIN-redirection test: in {{plural .Queries "query" "queries"}} for a random name under the reserved .invalid domain, which must never resolve, the {{.Role}} resolver <span class="mono">{{.Server}}</span> answered "no such name" (NXDOMAIN) {{plural .NXDomain "time" "times"}} and with an address (redirected) {{plural .Redirected "time" "times"}}.</p>
{{end}}{{if .HTTP}}<div class="tablewrap"><table>
<thead><tr><th>Web check</th><th>URL</th><th class="num">Checks</th><th class="num">Successful</th><th class="num">Hijacked</th></tr></thead>
<tbody>{{range .HTTP}}<tr><td>HTTP {{.Name}}</td><td class="mono">{{.URL}}</td><td class="num">{{int .Checks}}</td><td class="num">{{int .OK}}</td><td class="num">{{int .Hijacked}}</td></tr>{{end}}</tbody>
</table></div>
<p class="muted">A web check is successful when its response had the expected status and body.</p>{{end}}
{{if .HijackExamples}}<h3>Hijack observations</h3><div class="tablewrap"><table><thead><tr><th>Time</th><th>Kind</th><th>Where</th><th>Detail</th><th>Record (seq)</th></tr></thead><tbody>{{range .HijackExamples}}<tr><td>{{$.Local .TS}}<br><span class="muted">{{utc .TS}}</span></td><td>{{.Kind}}</td><td class="mono">{{.Where}}</td><td>{{.Detail}}{{if .TLSCertSHA256}}<br>TLS certificate SHA-256 <span class="mono">{{.TLSCertSHA256}}</span>{{end}}{{if .BodyPrefix}}<br><span class="muted">Response body (first bytes, as recorded):</span><pre>{{.BodyPrefix}}</pre>{{end}}</td><td class="mono">{{.Seq}}</td></tr>{{end}}</tbody></table></div>{{end}}
{{else}}<p>No DNS or web checks were recorded in this period.</p>{{end}}{{end}}
{{with .R.LocalLink}}<h3>The monitoring computer's own network link</h3>
{{if .Observations}}<p>{{plural .Observations "observation" "observations"}}. Link type: {{range $i, $v := .Types}}{{if $i}}, {{end}}{{$v.Value}} ({{int $v.Count}}){{end}}.{{if .Interfaces}} Adapter(s): {{join .Interfaces ", "}}.{{end}}{{if .SSIDs}} Wi-Fi network(s): {{join .SSIDs ", "}}{{if .BSSIDs}} (access point(s) {{join .BSSIDs ", "}}){{end}}.{{end}}{{if .SignalMinPct}} Wi-Fi signal {{.SignalMinPct}}% to {{.SignalMaxPct}}% (median {{.SignalMedPct}}%).{{end}} Disconnected in {{plural .Disconnected "observation" "observations"}}.</p>
{{if .EgressChecks}}<p>Route check (whether this computer's traffic to the internet destinations leaves through the AT&amp;T gateway), recorded with {{plural .EgressChecks "observation" "observations"}}: {{if .EgressBypass}}<strong>in {{plural .EgressBypass "observation" "observations"}} a destination was routed past the gateway</strong> (a VPN tunnel, another network adapter or a hotspot; local_link record seq {{seqs .EgressBypassSeqs}}{{if gt .EgressBypass (len .EgressBypassSeqs)}} and later ones{{end}}). While that lasts, cycles in which the internet probes fail are LOCAL_FAULT / LOCAL_ROUTE and degraded cycles are not attributed to the provider (section 6).{{else}}every destination was routed through the gateway.{{end}}</p>{{end}}
{{else}}<p>No local-link observations were recorded in this period.</p>{{end}}{{end}}
{{with .R.Clock}}<h3>Clock accuracy</h3>
{{if .Checks}}<p>{{plural .Checks "SNTP clock check" "SNTP clock checks"}} against {{join .Servers ", "}}: {{int .ResultsOK}} of {{int .Results}} answered{{if .MaxAbsOffsetMs}}; the largest difference between this computer's clock and the time servers was {{int .MaxAbsOffsetMs}} ms{{end}}.{{if .GatewayMaxAbsOffsetMs}} The gateway's own clock differed from this computer's by at most {{int .GatewayMaxAbsOffsetMs}} ms.{{end}} Clock jumps recorded: {{.ClockJumps}}.</p>
{{else}}<p>No clock checks were recorded in this period.{{if .ClockJumps}} Clock jumps recorded: {{.ClockJumps}}.{{end}}</p>{{end}}{{end}}
</section>

<section id="methodology">
<h2>6. Methodology and rules</h2>
<h3>Measurements</h3>
<p>Measurement cycles ran every {{printf "%.0f" .R.Methodology.CadenceSec}} s (median interval between consecutive samples in this period){{if .R.Methodology.SnapshotCadence}}; the gateway's status pages were read every {{printf "%.0f" .R.Methodology.SnapshotCadence}} s (median; more often during incidents){{end}}. Probes run in parallel in every cycle, each with a short timeout, from this computer:</p>
{{if .R.Methodology.Probes}}<div class="tablewrap"><table>
<thead><tr><th>Probe</th><th>Kind</th><th>Role</th><th>Target(s)</th><th class="num">Attempts</th><th class="num">Successful</th><th class="num">Success rate</th><th class="num">Mean RTT</th></tr></thead>
<tbody>{{range .R.Methodology.Probes}}<tr><td class="mono">{{.Name}}</td><td>{{.Kind}}</td><td>{{.Role}}</td><td class="mono">{{join .Targets ", "}}</td><td class="num">{{int .Attempts}}</td><td class="num">{{int .OK}}</td><td class="num">{{pct .SuccessPct}}</td><td class="num">{{ms1 .MeanRTTms}}</td></tr>{{end}}</tbody>
</table></div>{{end}}
<p>Roles: <strong>gateway</strong> = the AT&amp;T gateway on the local network; <strong>isp_hop</strong> = AT&amp;T's next-hop router as reported by the gateway ("Gateway IPv4 Address"); <strong>internet</strong> = public services outside the AT&amp;T network (the default targets are Cloudflare 1.1.1.1, Google 8.8.8.8 and Quad9 9.9.9.9; the targets actually probed are listed above).</p>

<h3>Classification rules (version {{.R.Methodology.RulesDescribed}}; versions used by the records: {{join .R.Methodology.RulesVersions ", "}})</h3>
{{range .R.Methodology.RulesNotes}}<div class="callout"><strong>Records produced under rules {{.Version}}</strong> ({{plural .Samples "sample" "samples"}} of the period, {{plural .IncidentRecords "incident record" "incident records"}} in this bundle).{{if .Known}} What differs from rules {{$.R.Methodology.RulesDescribed}}, which this section describes:{{end}}<ul>{{range .Differences}}<li>{{.}}</li>{{end}}</ul></div>
{{end}}{{with .R.Methodology.Thresholds}}
<p>Every {{secs .FastIntervalSec}} all probes run in parallel ({{secs .ProbeTimeoutSec}} timeout each). Each cycle is classified from its own probe results, the latest AT&amp;T gateway snapshot and DNS/web check (each used only if at most {{secs .SnapshotFreshnessSec}} old), the latest local-link observation, and the window of the last {{.WindowCycles}} cycles including this one.{{if $.R.Methodology.SamplesInputs}} Each sample names the snapshot, service-check and local-link records it used and the window size - under rules 2026.10-4 also the previous service check the DNS rule compared with and the two snapshots the WAN traffic rate came from (verdict inputs) - so anyone can recompute its classification from the ledger ({{int $.R.Methodology.SamplesInputs}} of the {{int $.R.Summary.Cycles}} samples of this period do).{{end}}</p>
<p>Definitions: <em>LAN</em> = the gateway answered ICMP echo, accepted a TCP connection on port 443, or refused it with a TCP reset (a reset proves its IP stack answered). <em>Providers</em> = the distinct internet target addresses ({{if $.R.Methodology.Providers}}{{join $.R.Methodology.Providers ", "}} in this period{{else}}none recorded{{end}}); ICMP and TCP probes to one address are one provider. <em>INET_ANY</em> = at least one internet probe succeeded in the cycle. <em>Outage cycles</em> are cycles classified by rule 1 or 2; a provider's <em>window loss</em> is its failed probes divided by its probes over the window's cycles that are not outage cycles (outages are already outages; counting them again would stretch every outage by the window length).</p>
<ol>
<li><strong>No LAN</strong> &rarr; LOCAL_FAULT / GATEWAY_UNREACHABLE, attribution <em>undetermined</em> (LOCAL_LINK_DOWN and <em>local</em> when this computer's Wi-Fi reported disconnected). The monitor never blames the provider when it cannot reach the gateway.</li>
<li><strong>LAN but no internet probe succeeded</strong> &rarr; ISP_OUTAGE, attribution <em>provider</em>. Cause: FIBER_LINK_DOWN when a fresh gateway snapshot shows the PON link not in O5 or the optical WAN not Up; otherwise WAN_DOWN when it reports Broadband Connection Down or no WAN IPv4 address; otherwise ISP_EDGE_UNREACHABLE when AT&amp;T's next-hop router is known and did not answer; otherwise UPSTREAM_UNREACHABLE. <strong>Route check:</strong> every local-link observation also records the route this computer uses to reach the gateway and each internet destination. While the latest one (at most {{secs .SnapshotFreshnessSec}} old) shows a destination routed past the AT&amp;T gateway - a VPN tunnel, a second network adapter or a hotspot - failed probes say nothing about AT&amp;T's network: the cycle is LOCAL_FAULT / LOCAL_ROUTE, attribution <em>undetermined</em>, unless the gateway itself reports its fiber or WAN connection down (FIBER_LINK_DOWN, WAN_DOWN), which stays ISP_OUTAGE attributed to the provider whatever route the probes took.</li>
<li><strong>LAN and some internet probe succeeded</strong> &rarr; DEGRADED / PACKET_LOSS when at least min(2, number of providers) providers had a window loss of at least {{num .LossDegradedPct}}% (one unreachable destination can never implicate the ISP); DEGRADED / HIGH_LATENCY when the median internet round-trip time over the window's non-outage cycles exceeded {{num .LatencyDegradedMs}} ms while the gateway's median stayed under {{num .GatewayLatencyOkMs}} ms; DEGRADED / ISP_DNS_FAILURE when AT&amp;T's resolver failed while a public resolver answered; DEGRADED / GATEWAY_DNS_FAILURE when the gateway's DNS failed while AT&amp;T's resolver answered. A resolver failure counts only when the same failure appears in two consecutive service checks (at most {{secs .SnapshotFreshnessSec}} apart), and a query that got no valid response is asked once more within its check before it counts as failed: one lost datagram never implicates the ISP. Degradation is attributed to the provider only if the gateway answered every probe in the window (a refused TCP connection counts as an answer), the route check does not show this computer's traffic bypassing the AT&amp;T gateway, and the gateway's own WAN counters (its two latest snapshots, at most 5 minutes apart) do not show the household's own traffic at 80 Mb/s or more in either direction, which could cause the delay or loss by itself; otherwise it is <em>undetermined</em>. The reasons of each such cycle state the measured rates and the snapshots they come from, or that the traffic could not be measured, in which case it does not decide. Otherwise the cycle is ONLINE.</li>
<li>Cycles without a gateway or internet probe result are UNKNOWN: neither good nor bad, and excluded from availability. So is a cycle that took longer than its probes may take (the probe timeout plus a grace period plus half a cycle interval, at least 1 s): monitoring was interrupted while its probes were in flight (for example by system sleep), so its timed-out probes say nothing about the network, and the interruption counts as a monitoring gap.</li>
</ol>
<h3>Causes</h3>
<div class="tablewrap"><table>
<thead><tr><th>Cause</th><th>State</th><th>Meaning</th><th>Attribution</th></tr></thead>
<tbody>
<tr><td class="mono">FIBER_LINK_DOWN</td><td>ISP_OUTAGE</td><td>The AT&amp;T gateway reported its fiber (PON) link outside the operational state O5, or its optical WAN not Up.</td><td>provider</td></tr>
<tr><td class="mono">WAN_DOWN</td><td>ISP_OUTAGE</td><td>The AT&amp;T gateway reported its broadband (WAN) connection Down, or no WAN IPv4 address.</td><td>provider</td></tr>
<tr><td class="mono">ISP_EDGE_UNREACHABLE</td><td>ISP_OUTAGE</td><td>AT&amp;T's next-hop router did not answer while the gateway did and no internet target answered.</td><td>provider</td></tr>
<tr><td class="mono">UPSTREAM_UNREACHABLE</td><td>ISP_OUTAGE</td><td>No internet target answered while the gateway did.</td><td>provider</td></tr>
<tr><td class="mono">GATEWAY_UNREACHABLE</td><td>LOCAL_FAULT</td><td>This computer could not reach the AT&amp;T gateway.</td><td>undetermined</td></tr>
<tr><td class="mono">LOCAL_LINK_DOWN</td><td>LOCAL_FAULT</td><td>This computer's Wi-Fi link to the gateway was down.</td><td>local</td></tr>
<tr><td class="mono">LOCAL_ROUTE</td><td>LOCAL_FAULT</td><td>The gateway answered, but this computer's internet traffic did not leave through the AT&amp;T gateway (a VPN tunnel, another network adapter or a hotspot held the route), so its failed probes say nothing about AT&amp;T's network.</td><td>undetermined</td></tr>
<tr><td class="mono">GATEWAY_REBOOT</td><td>LOCAL_FAULT (incidents only)</td><td>The AT&amp;T gateway restarted (its uptime was reset) and the incident's bad cycles lie in the restart window, with too few provider-attributed bad cycles outside it to make the incident the provider's.</td><td>undetermined; provider when the gateway firmware changed across the restart</td></tr>
<tr><td class="mono">PACKET_LOSS</td><td>DEGRADED</td><td>At least two providers (or the only one) lost {{num .LossDegradedPct}}% or more of their probes over the window.</td><td>provider or undetermined (rule 3)</td></tr>
<tr><td class="mono">HIGH_LATENCY</td><td>DEGRADED</td><td>Internet round-trip times were high while the gateway answered quickly.</td><td>provider or undetermined (rule 3)</td></tr>
<tr><td class="mono">ISP_DNS_FAILURE</td><td>DEGRADED</td><td>AT&amp;T's resolver failed while a public resolver answered, in two consecutive service checks.</td><td>provider or undetermined (rule 3)</td></tr>
<tr><td class="mono">GATEWAY_DNS_FAILURE</td><td>DEGRADED</td><td>The gateway's DNS failed while AT&amp;T's resolver answered, in two consecutive service checks.</td><td>provider or undetermined (rule 3)</td></tr>
</tbody></table></div>
<h3>Incidents, time accounting and gateway restarts</h3>
<ul>
<li>A cycle is <em>bad</em> when its state is neither ONLINE nor UNKNOWN. An incident opens when at least {{.OpenAfterCycles}} bad cycles fall within the last {{.WindowCycles}} cycles &mdash; a continuous outage or intermittent ("flapping") connectivity &mdash; and starts at the start of the earliest of them; it closes after {{.CloseAfterCycles}} consecutive good cycles, at the start of the first of them. <em>Recovered at</em> is the start of the first cycle after the last outage cycle in which every probe succeeded. Bad cycles that never lead to an incident are blips.</li>
<li>An incident's headline state is the most severe one seen (ISP_OUTAGE, then LOCAL_FAULT, then DEGRADED), with the most specific cause seen at that state and every cause listed; its attribution is <em>provider</em> for an ISP_OUTAGE or a provider-attributed DEGRADED headline, otherwise <em>undetermined</em> or <em>local</em>.</li>
<li>Time accounting counts cycles, not wall-clock spans: each cycle covers the time until the next cycle of the same monitor process started, at most {{secs .CoverCapSec}} (1.5 &times; the cycle interval), measured with the monitor's monotonic clock when the computer's clock was stepped in between; the last cycle before the monitor stopped covers only until it was recorded; more than {{secs .GapLimitSec}} without a cycle is a monitoring gap. A monitoring gap - or a cycle cut short by an interruption - closes an open incident at the end of the time its last bad cycle covers (the outcome during the interruption is unknown, and the sleep is never counted as outage time). <em>downtime_s</em> (time without Internet) is the time of ISP_OUTAGE cycles, <em>degraded_s</em> the time of DEGRADED cycles and <em>provider_outage_s</em> the time of provider-attributed ISP_OUTAGE cycles, so an intermittent incident reports its true time without Internet, not its whole duration.</li>
<li><strong>Gateway restarts.</strong> A restart is detected from the gateway's own uptime: its boot time (fetch time minus uptime) moved by more than {{secs .RestartMoveSec}}, or its uptime fell without the elapsed time explaining it. The <em>restart window</em> runs from the boot, extended back over the cycles just before it in which the gateway did not answer this computer (rule 1: the power-off and boot period), until the first cycle after the boot in which the Internet was reachable again, at most {{secs .RestartCapSec}} after the boot; it is computed over every recorded cycle. A restart belongs to every incident with a bad cycle inside its window - also when the boot came before the incident's first observed cycle, for example after a power failure that also stopped this computer - and to an incident whose span contains the boot. Bad cycles inside a restart window count as restart time (<em>restart_s</em>), not as downtime and not as provider outage time. An incident with a restart is attributed to the provider only if at least {{.OpenAfterCycles}} provider-attributed bad cycles - as many as it takes to open an incident - lie outside the restart windows (the outage existed before the gateway was restarted, or persisted more than {{secs .RestartCapSec}} after the restart); fewer are stray cycles of the restart's own shutdown or bring-up, still counted as time without Internet. Otherwise its cause is GATEWAY_REBOOT with attribution <em>undetermined</em>, or <em>provider</em> when the gateway's firmware version changed across the restart (an AT&amp;T-pushed firmware update). An incident closed before an uptime reading could tell whether the gateway restarted during it - for example one a monitor process left open when it stopped, which the next process closes at its last observation - is revised by an incident_update when a later reading reveals such a restart. Samples keep their real-time classification; the restart rule is applied in the incident records and in this report, which computes the restart windows from the records and says so when an incident record contradicts them.</li>
<li>While an incident is open, the monitor also records it right after the start of every UTC day's ledger segment (incident_update), so every daily segment an incident covers contains a record of it.</li>
<li>Conditions shown on the monitor's dashboard do not change a recorded classification by themselves. Optical conditions such as OPTICAL_RX_LOW_ALARM are taken only from the gateway's own alarm flags and date from their first report. NOTIFICATION_REDIRECT_ON (the gateway's outage redirect is enabled), GATEWAY_CERT_CHANGED (critical: the gateway's TLS certificate changed; authenticated requests to the gateway are paused until the owner confirms the new certificate), NO_ACCESS_CODE (the redirect setting cannot be checked) and ANCHOR_UNTRUSTED (the newest time-stamps could not be chain-verified, so they do not count as proof of time) describe the monitoring setup. EGRESS_NOT_VIA_GATEWAY (warning) is shown while the route check finds this computer's traffic bypassing the AT&amp;T gateway - the period of the LOCAL_ROUTE rule above. LEDGER_WRITE_FAILING (critical) is shown while the evidence ledger refuses records: nothing is recorded then, the service exits so that Windows restarts it, and the time appears in this report as a monitoring gap. DISK_SPACE_LOW (warning below 2 GiB free, critical below 512 MiB) is shown while the volume holding the evidence runs out of space. CLOCK_OFFSET (warning beyond 60 s, critical beyond 5 minutes) is shown while this computer's clock differs from the SNTP time servers: record times are then off by about as much, and the RFC 3161 time-stamps bound them (section 7).</li>
</ul>
<h3>Thresholds in force</h3>
<p>{{with $.R.Methodology.ConfigSource}}{{if eq .Type "defaults"}}<strong>Documented defaults of rules {{$.R.Methodology.RulesDescribed}}.</strong>{{else}}From the configuration recorded in the {{.Type}} record seq {{useq .Seq}} ({{utc .TS}}), {{if eq .Basis "first_in_period"}}the first configuration record in the period{{else}}the latest configuration record at or before the start of the period{{end}}{{if .ConfigSHA256}}; configuration hash <span class="mono">{{.ConfigSHA256}}</span>{{end}}.{{end}}{{end}}{{with .Note}} {{.}}{{end}} The monitor records its configuration, with secrets removed, in monitor_start records (when a monitor process starts) and config_state records (at the start of a daily ledger segment).</p>
<div class="tablewrap"><table><tbody>
<tr><th>Cycle interval (fast_interval) / probe timeout</th><td>{{secs .FastIntervalSec}} / {{secs .ProbeTimeoutSec}}</td></tr>
<tr><th>Incident window / opens after / closes after</th><td>{{.WindowCycles}} cycles / {{.OpenAfterCycles}} bad cycles in the window / {{.CloseAfterCycles}} consecutive good cycles</td></tr>
<tr><th>Packet loss (per provider, over the window)</th><td>at least {{num .LossDegradedPct}}%</td></tr>
<tr><th>High latency / gateway latency still OK</th><td>{{num .LatencyDegradedMs}} ms / {{num .GatewayLatencyOkMs}} ms</td></tr>
<tr><th>Freshness of gateway snapshots and service checks</th><td>{{secs .SnapshotFreshnessSec}}</td></tr>
<tr><th>Cycle cover cap / monitoring gap</th><td>{{secs .CoverCapSec}} / more than {{secs .GapLimitSec}}</td></tr>
<tr><th>Gateway restart: boot-time move / restart window cap</th><td>{{secs .RestartMoveSec}} / {{secs .RestartCapSec}}</td></tr>
{{if .InternetTargets}}<tr><th>Internet probe targets (configured)</th><td class="mono">{{join .InternetTargets ", "}}</td></tr>{{end}}
</tbody></table></div>
{{if .Changes}}<p><strong>The configuration changed during the period.</strong> Each configuration applied from its record until the next one:</p>
<div class="tablewrap"><table>
<thead><tr><th>From</th><th>Until</th><th>Configuration record</th><th>Configuration</th></tr></thead>
<tbody><tr><td>{{$.Local $.R.Period.From}} (start of the period)<br><span class="muted">{{utc $.R.Period.From}}</span></td><td>{{$.Local .AppliesUntil}}<br><span class="muted">{{utc .AppliesUntil}}</span></td><td class="mono">{{with $.R.Methodology.ConfigSource}}{{if eq .Type "defaults"}}none that applies{{else}}{{.Type}} seq {{useq .Seq}}{{end}}{{end}}</td><td>{{if eq .Source "defaults"}}not known from this bundle (the documented defaults are shown above){{else}}the values shown above{{end}}</td></tr>
{{range .Changes}}<tr><td>{{$.Local .TS}}<br><span class="muted">{{utc .TS}}</span></td><td>{{$.Local .AppliesUntil}}<br><span class="muted">{{utc .AppliesUntil}}</span></td><td class="mono">{{.Type}} seq {{.Seq}}{{with .ConfigSHA256}}<br>hash {{short .}}{{end}}</td><td>{{join .Changes "; "}}</td></tr>
{{end}}</tbody></table></div>
<p class="muted">Times are those of the records. A monitor process applies the configuration it starts with (monitor_start). Settings it changes while running (the gateway certificate pin, the outage-redirect enforcement) are recorded as configuration changes in the custody log; config_state records restate the whole configuration at the start of every daily ledger segment, so such a change can appear there later than it took effect.</p>
{{else if ne .Source "defaults"}}<p>No other configuration is recorded in the period: this configuration applied until its end.</p>
{{end}}{{end}}
<h3>Limitations</h3>
<ul>
<li>All measurements are taken from one computer. {{with .R.LocalLink}}{{if .Observations}}During this period it was connected by {{range $i, $v := .Types}}{{if $i}} / {{end}}{{$v.Value}}{{end}}. {{end}}{{end}}Over Wi-Fi, local radio problems can make the gateway unreachable from the computer; such cycles are classified LOCAL_FAULT with attribution undetermined or local, never provider.</li>
<li>Routers may deprioritise or rate-limit ICMP; TCP connection probes to the same targets guard against counting that as an outage.</li>
<li>The route check compares the route this computer's IP stack uses for each IPv4 destination with its route to the gateway: a tunnel that captures only some applications' traffic is not detected, and IPv6 destinations are not checked.</li>
<li>The internet targets are run by operators other than AT&amp;T. When all of them fail at the same time while the AT&amp;T gateway on the local network keeps answering, the fault lies between the gateway and those networks, that is in the provider's access network or upstream of it.</li>
<li>The gateway's status pages are the AT&amp;T device's own view; their values are recorded as reported (raw pages are stored when an incident is open, when a material field changes, and periodically).</li>
<li>Timestamps come from this computer's clock, which is compared with public time servers (section 5), and the records are independently time-stamped by RFC 3161 Time-Stamp Authorities (section 7).</li>
<li>No data is inferred for monitoring gaps; they are listed with the records that explain them.</li>
<li>The owner of the computer controls it: the design provides tamper evidence (hash chain, signatures, external time-stamps), not tamper proofing.</li>
</ul>
{{if .R.Methodology.Software}}<h3>Software that produced the records</h3>
<div class="tablewrap"><table><thead><tr><th>Version</th><th>Rules</th><th>Executable SHA-256</th><th>First seen</th></tr></thead>
<tbody>{{range .R.Methodology.Software}}<tr><td>{{.Version}}{{if .Commit}} ({{.Commit}}){{end}}</td><td>{{.Rules}}</td><td class="mono">{{.ExeSHA256}}</td><td>{{utc .FirstTS}} (seq {{.FirstSeq}})</td></tr>{{end}}</tbody></table></div>{{end}}
<p class="muted">Other records in the period: {{int .R.Methodology.Heartbeats}} heartbeats, {{int .R.Methodology.StateChanges}} state changes, {{int .R.Methodology.Traceroutes}} traceroutes.</p>
</section>

<section id="integrity">
<h2>7. Integrity and verification</h2>
<p>Every ledger line is an envelope {"h", "s", "b"}: <em>b</em> is the record, <em>h</em> its SHA-256 and <em>s</em> an Ed25519 signature made with this installation's key (created at genesis and protected by Windows DPAPI). Each record contains the hash of the previous one ("prev") and a sequence number, so deleting, inserting, reordering or editing any record breaks every later link. Raw evidence (exact gateway pages, time-stamp tokens) is stored under its own SHA-256. At regular intervals and after each incident, the current chain head is time-stamped by independent RFC 3161 Time-Stamp Authorities; only that 32-byte hash leaves the computer. A valid time-stamp proves that the record it names, and through the chain every earlier record, existed no later than the time-stamp. Verification also checks every record's time against the trusted time-stamps around it: a record dated more than 5 minutes before a trusted time-stamp that precedes it in the chain (it was written after that time-stamp existed), or more than 5 minutes after one that covers it (it existed by then), carries a false time and fails verification (ts_contradiction).</p>
<h3>Contents of this bundle</h3>
<div class="tablewrap"><table>
<thead><tr><th>Ledger segment</th><th class="num">Records</th><th>Seq</th><th>First / last record (UTC)</th><th>SHA-256</th></tr></thead>
<tbody>{{range .R.Ledger.Segments}}<tr><td class="mono">{{.Path}}{{if .Genesis}}<br><span class="muted">genesis segment</span>{{end}}{{if .IncludedFor}}<br><span class="muted">outside the period; included for the {{.IncludedFor}}</span>{{end}}</td><td class="num">{{int .Records}}</td><td class="mono">{{.FirstSeq}}-{{.LastSeq}}</td><td>{{utc .FirstTS}}<br>{{utc .LastTS}}</td><td class="mono">{{.SHA256}}</td></tr>{{end}}</tbody>
</table></div>
{{if .R.Ledger.Omitted}}<p>Segments of the ledger that lie outside the period and are not included: {{range $i, $o := .R.Ledger.Omitted}}{{if $i}}, {{end}}<span class="mono">{{$o.Name}}</span> (seq {{$o.FirstSeq}}-{{$o.LastSeq}}){{end}}. The chain across them is verified on the full ledger (above) and visible here as a jump in seq.</p>{{end}}
{{if .R.Ledger.Later}}<p>The ledger continues after this bundle: {{range $i, $o := .R.Ledger.Later}}{{if $i}}, {{end}}<span class="mono">{{$o.Name}}</span> (seq {{$o.FirstSeq}}-{{$o.LastSeq}}){{end}} {{if eq (len .R.Ledger.Later) 1}}is{{else}}are{{end}} outside the period and not included.</p>{{end}}
<p>Record types in this bundle: {{range $i, $t := .TypeCounts}}{{if $i}}, {{end}}{{$t.Value}} {{int $t.Count}}{{end}}. Blobs included: {{.R.Verification.Bundle.BlobsIncluded}}.</p>
{{if .R.Bundle.ExtraFiles}}<p>Additional files (listed in MANIFEST.sha256): {{range $i, $x := .R.Bundle.ExtraFiles}}{{if $i}}; {{end}}<span class="mono">{{$x.Path}}</span> ({{$x.Description}}; {{int $x.Bytes}} bytes, SHA-256 <span class="mono">{{short $x.SHA256}}</span>){{end}}.</p>{{end}}
{{with .R.Verification.Bundle}}{{if .Notes}}<ul>{{range .Notes}}<li>{{.}}</li>{{end}}</ul>{{end}}
{{if .Failures}}<h3>Problems found in this bundle ({{.FailuresTotal}})</h3>
<div class="tablewrap"><table><thead><tr><th>Segment</th><th class="num">Line</th><th class="num">Seq</th><th>Problem</th><th>Detail</th></tr></thead>
<tbody>{{range .Failures}}<tr><td class="mono">{{.Segment}}</td><td class="num">{{.Line}}</td><td class="num">{{.Seq}}</td><td>{{.Problem}}</td><td>{{.Detail}}</td></tr>{{end}}</tbody></table></div>{{end}}{{end}}
{{if .FullFailures}}<h3>Problems found by the full-ledger verification</h3>
<div class="tablewrap"><table><thead><tr><th>Segment</th><th class="num">Line</th><th class="num">Seq</th><th>Problem</th><th>Detail</th></tr></thead>
<tbody>{{range .FullFailures}}<tr><td class="mono">{{.Segment}}</td><td class="num">{{.Line}}</td><td class="num">{{.Seq}}</td><td>{{.Problem}}</td><td>{{.Detail}}</td></tr>{{end}}</tbody></table></div>{{end}}

<h3>Independent time-stamps (RFC 3161)</h3>
{{if .Anchors}}<div class="tablewrap"><table>
<thead><tr><th>Anchor (seq)</th><th>Time-Stamp Authority</th><th>Time-stamp genTime (UTC)</th><th>Covers records up to</th><th>Head check</th><th>Token</th><th>Proof of time</th></tr></thead>
<tbody>{{range .Anchors}}<tr><td class="mono">{{.Seq}}<br><span class="muted">{{.Reason}}</span></td><td>{{if .TSAName}}{{.TSAName}}<br>{{end}}{{if and .TokenTSAName (ne .TokenTSAName .TSAName)}}token signer: {{.TokenTSAName}}<br>{{end}}<span class="mono muted">{{.TSAURL}}</span></td><td>{{if .TokenGenTime}}{{utc .TokenGenTime}}{{else}}{{utc .GenTime}}<br><span class="muted">as recorded; not read from the token</span>{{end}}</td><td class="mono">seq {{.HeadSeq}}<br>{{short .HeadHash}}</td><td>{{if eq .HeadCheck "ok"}}<span class="badge pass">&#10003; matches</span>{{else if eq .HeadCheck "mismatch"}}<span class="badge fail">&#10007; mismatch</span>{{else}}<span class="badge info">{{.HeadCheck}}</span>{{end}}</td><td><span class="mono">{{if .TokenIncluded}}blobs/{{short .Token}}{{else}}missing{{end}}</span>{{if eq .TokenCheck "ok"}}<br><span class="badge pass">&#10003; imprint and TSA signature</span>{{else if .TokenCheck}}<br><span class="badge fail">&#10007; invalid</span> {{.TokenCheck}}{{end}}<br><span class="muted">at issue (anchor record): {{if .Verified}}verified{{else}}not verified{{end}}, TSA certificate chain {{if .ChainOK}}OK{{else}}not verified{{end}}</span>{{if not .ChainOK}}{{with .ChainNoteRec}}<br>chain note at issue: {{.}}{{end}}{{end}}</td><td>{{if .ProofOfTime}}<span class="badge pass">&#10003; yes</span><br><span class="muted">{{if eq .ProofBasis "token_verifier"}}TSA certificate chain checked at export{{else}}per the record's issue-time flags (verified, chain_ok); chain not re-checked at export{{end}}</span>{{else}}<span class="badge warn">no</span><br>{{.ProofNote}}{{end}}</td></tr>{{end}}</tbody>
</table></div>{{if .AnchorsMore}}<p class="muted">{{.AnchorsMore}} more anchor(s) are listed in report.json.</p>{{end}}
{{else}}<p>No time-stamp anchors were made during this period.</p>{{end}}
<p class="muted">An anchor is accepted as proof of time only if its token is a valid time-stamp over the hash of the record it names, that record is in this bundle with that hash, and the TSA's certificate chains to a trusted root: {{if .R.Verification.Bundle.TokenVerifier}}checked at export by a token verifier (when it does not chain, the reason is shown){{else}}no token verifier was available at export, so the anchor record's own statement that, when the token was obtained, it verified and its certificate chained (verified and chain_ok) decides; check the chains independently with the OpenSSL commands below{{end}}.</p>

<h3>How to verify this bundle independently</h3>
<ol>
<li>File integrity: every other file is listed with its SHA-256 in <code>MANIFEST.sha256</code> (this shows that no file changed after the manifest was written, not who wrote it). Linux: <code>sha256sum -c MANIFEST.sha256</code>; macOS: <code>shasum -a 256 -c MANIFEST.sha256</code>; Windows: <code>certutil -hashfile FILE SHA256</code> and compare.</li>
<li>With att-monitor: <code>att-monitor verify-bundle {{.R.Bundle.FileName}}</code> (envelopes, signatures, chain, segment links, blobs and time-stamp tokens; it also recomputes report.json, this report, README.txt and keys/public-key.txt from the records and fails if they differ - the inputs the records cannot confirm, such as the period, the export time, the local time zone and the verification results on the monitoring computer, are taken as report.json states them).</li>
<li>With Python 3.9 or newer (no installation needed): <code>python tools/verify_bundle.py {{.R.Bundle.FileName}}</code>, or inside the extracted folder <code>python tools/verify_bundle.py .</code>. To check the Ed25519 signatures too, install the cryptography package (<code>pip install cryptography</code>) or add <code>--pure-python-ed25519</code> (slower). The script exits with code 0 only if every check passes. It verifies the records - their hashes, chain, signatures, blobs, time-stamp tokens and their times against the trusted time-stamps - not the figures of this report.</li>
<li>Time-stamp tokens with OpenSSL 1.1.1 or newer, on the extracted bundle. Show a token: <code>openssl ts -reply -in blobs/TOKEN -text</code>. Verify the TSA's signature and certificate chain at the time of the time-stamp, and that the token covers the anchored record: <code>openssl ts -verify -attime GENTIME -digest HEAD_HASH -in blobs/TOKEN -CAfile {{.RootsFile}}</code>, where GENTIME is the token's genTime in Unix seconds (with <code>-attime</code> the certificate is checked when the time-stamp was made; it may have expired since) and HEAD_HASH the anchor's head_hash.{{if not .R.Bundle.TSARoots}} This bundle contains no keys/tsa-roots.pem: obtain the TSAs' root certificates from the TSAs themselves.{{end}}{{range .AnchorExamples}}<br>For {{.TSAURL}} (anchor seq {{.Seq}}, genTime {{utc .TokenGenTime}}): <code>openssl ts -verify -attime {{unix .TokenGenTime}} -digest {{.HeadHash}} -in blobs/{{.Token}} -CAfile {{$.RootsFile}}</code>{{end}}<br>tools/verify_bundle.py runs this check for the tokens when OpenSSL is installed{{if .R.Bundle.TSARoots}} (see <code>--openssl-limit</code>){{end}}.</li>
{{if .R.Bundle.TSARoots}}<li><code>keys/tsa-roots.pem</code> holds the root certificates of the Time-Stamp Authorities, supplied by the exporting software as a convenience, not as a trust anchor: before relying on a verification against them, compare their SHA-256 fingerprints with the ones the TSAs publish.<ul>{{range .R.Bundle.TSARoots}}<li>{{.Subject}}<br><span class="mono">SHA-256 {{colonhex .SHA256}}</span> <span class="muted">(valid {{utc .NotBefore}} to {{utc .NotAfter}})</span></li>{{end}}</ul>{{with .R.Bundle.TSARootsNote}}<span class="muted">{{.}}</span>{{end}}</li>{{else}}{{with .R.Bundle.TSARootsNote}}<li>keys/tsa-roots.pem: {{.}}</li>{{end}}{{end}}
<li>The public key in <code>keys/public-key.txt</code> must match the fingerprint above and the genesis record; compare it with the fingerprint shown on the monitoring computer.</li>
</ol>
</section>

<section id="custody">
<h2>8. Custody log</h2>
<p>Every entry is a signed, hash-chained ledger record contained in this bundle (creation of the ledger, evidence imported from before it existed, monitor starts and stops, power events, configuration changes, operator notes, evidence exports, crash recovery and integrity alerts), plus the monitoring gaps computed for the period.</p>
<div class="tablewrap"><table>
<thead><tr><th>Time</th><th class="num">Seq</th><th>Type</th><th>What the record says</th></tr></thead>
<tbody>{{range .Custody}}<tr><td class="nowrap">{{$.Local .TS}}<br><span class="muted">{{utc .TS}}</span></td><td class="num">{{with .Seq}}{{.}}{{end}}</td><td class="mono nowrap">{{.Type}}{{if not .InPeriod}}<br><span class="muted">outside period</span>{{end}}</td><td class="preline">{{.Summary}}</td></tr>{{end}}</tbody>
</table></div>{{if .CustodyMore}}<p class="muted">{{.CustodyMore}} more entries are listed in report.json.</p>{{end}}
{{range .R.Bootstrap}}<h3>Evidence imported from before the ledger existed (record seq {{.Seq}}, {{utc .TS}})</h3>
<p>Source folder: <span class="mono">{{.SourceDir}}</span>. The files are stored as blobs named by the SHA-256 below.</p>
<div class="tablewrap"><table><thead><tr><th>File</th><th class="num">Bytes</th><th>Modified</th><th>SHA-256</th></tr></thead>
<tbody>{{range .Files}}<tr><td class="mono">{{.Path}}</td><td class="num">{{int .Size}}</td><td>{{.ModTime}}</td><td class="mono">{{.SHA256}}</td></tr>{{end}}</tbody></table></div>
{{if .Notes}}<p>Capture notes recorded with the import (verbatim):</p><pre>{{.Notes}}</pre>{{end}}{{end}}
{{if .R.Notes}}<h3>Report notes</h3><ul>{{range .R.Notes}}<li>{{.}}</li>{{end}}</ul>{{end}}
</section>
<footer>Generated by {{.R.Generator.Name}} {{.R.Generator.Version}} at {{utc .R.GeneratedAt}}. Machine-readable summary: report.json. Records: ledger/. Raw evidence: blobs/. Independent verifier: tools/verify_bundle.py.</footer>
</main>
</body>
</html>
`
