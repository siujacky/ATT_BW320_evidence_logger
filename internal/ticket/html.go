package ticket

import (
	"bytes"
	"fmt"
	"html/template"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"attmonitor/internal/model"
)

// HTML rendering. The page is self-contained (inline CSS, inline SVG), has no scripts and no
// external references, and is laid out for US Letter paper: page 1 is the summary sheet an AT&T
// agent needs; the details and the evidence follow on the next pages. Every page is numbered
// ("Page 2 of 3") and carries the report's identity (window and account) in its margin, so
// printed or faxed pages can be put in order and matched. Every text that comes from records or
// options goes through html/template's contextual escaping; the page identity in the CSS margin
// boxes is built by cssString, which leaves only letters, digits and spaces unescaped.
//
// Long values never widen the page: every table cell may wrap anywhere as a last resort
// (overflow-wrap: anywhere), and the values that must stay whole - date-times, UTC offsets,
// incident ids, number-unit pairs (see segs) - are short. Without that, one unbreakable token
// makes the browser shrink the whole document to fit it.

// Display limits (the bundle holds everything).
const (
	maxEventRows    = 20 // rows of the gateway events table (one row per observation)
	maxIncidentRows = 15
	maxGapRows      = 12
)

type htmlView struct {
	Title, WindowLocal, WindowUTC, Generated string
	PageIdentity                             template.CSS

	CustRows [][]custField
	Summary  []Bullet
	Action   Bullet
	Coverage string
	Brief    []kv
	Stated   string // the footnote for the values marked as stated by the generator
	// BriefOnPage1: the evidence brief fits on the summary sheet; otherwise its rows are only
	// under Evidence and integrity.
	BriefOnPage1 bool
	// CoverageOnPage1: the monitoring coverage paragraph fits on the summary sheet; otherwise it
	// opens the details.
	CoverageOnPage1 bool
	// DetailsFlow: even so the summary sheet is estimated not to fit on one page, so the details
	// follow it without a forced page break (which would leave a page holding a few lines).
	DetailsFlow bool

	Gateway     []kv
	GatewayNote string
	Chart       *Chart
	Caption     string
	LocalCols   bool // the tables show local time next to UTC
	Readings    []readingView
	ReadingNote string
	NoReadings  string

	Events     []eventView
	EventsNote string
	Incidents  []incidentView
	IncNote    string
	NoIncident string
	Gaps       []gapView
	GapsNote   string
	Avail      []kv
	Home       []kv

	Evidence []kv
	Setup    *setupView
	Facts    []Fact
	Verify   []verifyStep
	Notes    []string
}

type custField struct {
	Label, Value string
	Wide         bool // a row of its own, across the box
}

// customerRows lays out the customer fields two per row, with a fill-in line for each blank
// one; a long address or note gets a row of its own across the box.
func customerRows(c Customer) [][]custField {
	name, account := custField{Label: "Customer name", Value: c.Name}, custField{Label: "AT&T account number", Value: c.Account}
	address, phone := custField{Label: "Service address", Value: c.Address}, custField{Label: "Contact phone", Value: c.Phone}
	best, notes := custField{Label: "Best time to reach", Value: c.BestTime}, custField{Label: "Notes / ticket number", Value: c.Notes}
	long := func(s string) bool { return utf8.RuneCountInString(oneLine(s)) > 40 }
	if !long(c.Address) && !long(c.Notes) {
		return [][]custField{{name, account}, {address, phone}, {best, notes}}
	}
	address.Wide, notes.Wide = true, true
	return [][]custField{{name, account}, {address}, {phone, best}, {notes}}
}

type kv struct {
	K, V   string
	Mono   bool
	Stated bool // stated by the program that generated the report, not computed from records
}

type readingView struct {
	Local, UTC, Rx, Source, Why string
	Alarm, Warn                 bool
	Setup                       bool
}

// eventView is one observation: the gateway events written for the same pair of snapshots.
type eventView struct {
	Time  string
	Snaps string
	Items []eventItem
}

type eventItem struct {
	Label, Change, Detail, Ref string
}

type incidentView struct {
	ID, Ref, Rules, Opened, Closed, Duration, Downtime, Class, Causes string
}

type gapView struct {
	From, To, Dur, Why string
}

type setupView struct {
	Rows     []kv
	Pages    []setupPageView
	Tokens   []tokenView
	Problems []string
}

type setupPageView struct {
	Path, Time, SHA256, Listed string
}

type tokenView struct {
	Path, TSA, GenTime, Covers string
}

// verifyStep is one way to verify the evidence; each command is a list of arguments, printed on
// one line or wrapped only between them.
type verifyStep struct {
	Text string
	Cmds [][]string
}

// HTML renders the report as a self-contained print document.
func (r *Report) HTML() ([]byte, error) {
	v := r.view()
	var buf bytes.Buffer
	if err := pageTmpl.Execute(&buf, v); err != nil {
		return nil, fmt.Errorf("ticket: rendering HTML: %w", err)
	}
	return buf.Bytes(), nil
}

func (r *Report) generatorName() string {
	if r.Generator != "" {
		return r.Generator
	}
	return "the program that generated it"
}

func (r *Report) view() *htmlView {
	loc := r.loc
	v := &htmlView{
		Title:        r.Title,
		Generated:    fmtBoth(r.Generated, loc),
		PageIdentity: r.pageIdentity(),
		Summary:      r.Summary,
		Action:       r.Action,
		Coverage:     r.Coverage.Statement,
		LocalCols:    !isUTC(loc, r.From) || !isUTC(loc, r.To),
	}
	if v.LocalCols {
		v.WindowLocal = fmt.Sprintf("%s to %s", fmtLocal(r.From, loc), fmtLocal(r.To, loc))
		v.WindowUTC = fmt.Sprintf("%s to %s", fmtUTC(r.From), fmtUTC(r.To))
	} else {
		v.WindowLocal = fmt.Sprintf("%s to %s", fmtUTC(r.From), fmtUTC(r.To))
	}
	if r.Generator != "" {
		v.Generated += " by " + r.Generator
	}
	v.CustRows = customerRows(r.Customer)
	ev := &r.Evidence
	v.Brief = []kv{
		{K: "Evidence bundle", V: orNA(ev.BundleName), Mono: ev.BundleName != "", Stated: ev.BundleName != ""},
	}
	if ev.BundleSHA256 != "" {
		v.Brief = append(v.Brief, kv{K: "Bundle SHA-256", V: ev.BundleSHA256, Mono: true, Stated: true})
	}
	if ev.HasGenesis {
		v.Brief = append(v.Brief, kv{K: "Ledger signing key", V: groupFingerprint(ev.Fingerprint), Mono: true})
	}
	v.Brief = append(v.Brief, kv{K: "Verification", V: verificationText(ev.Verification, ev.BundleName), Stated: ev.Verification != ""})
	if slices.ContainsFunc(v.Brief, func(x kv) bool { return x.Stated }) {
		v.Stated = fmt.Sprintf("* Stated by %s when it generated this report; every other figure is computed from the signed ledger records it names (in the evidence bundle).", r.generatorName())
	} else {
		v.Stated = "Every figure in this report is computed from the signed ledger records it names (in the evidence bundle)."
	}

	v.CoverageOnPage1 = true
	v.BriefOnPage1 = v.pageOneHeight(true) <= p1Usable
	if !v.BriefOnPage1 && v.pageOneHeight(false) > p1Usable {
		v.CoverageOnPage1 = false
	}
	v.DetailsFlow = v.pageOneHeight(false) > p1Usable

	r.viewGateway(v)
	r.viewReadings(v)
	r.viewEvents(v)
	r.viewIncidents(v)
	r.viewCoverage(v)
	r.viewEvidence(v)
	v.Notes = r.Notes
	return v
}

// pageIdentity is the report's identity in the page margins: the window and, when given, the
// account number (else the customer's name).
func (r *Report) pageIdentity() template.CSS {
	id := fmt.Sprintf("AT&T Fiber service problem evidence, %s to %s UTC", r.From.UTC().Format(layoutMin), r.To.UTC().Format(layoutMin))
	if a := oneLine(r.Customer.Account); a != "" {
		id += ", account " + truncate(a, 40)
	} else if n := oneLine(r.Customer.Name); n != "" {
		id += ", " + truncate(n, 40)
	}
	return cssString(id)
}

// cssString renders s as a CSS string literal in which only ASCII letters and digits stand for
// themselves: every other character, the space included, is a six-digit CSS escape (a literal
// space after an escape would be taken as the escape's terminator), so the value can end neither
// the string, nor the declaration, nor the style element. Control characters become spaces.
func cssString(s string) template.CSS {
	var b strings.Builder
	b.WriteByte('"')
	for _, c := range strings.ToValidUTF8(s, "�") {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			b.WriteRune(c)
		case c < 0x20 || c == 0x7f:
			b.WriteString(`\000020`)
		default:
			fmt.Fprintf(&b, `\%06x`, c)
		}
	}
	b.WriteByte('"')
	return template.CSS(b.String())
}

func verificationText(s, bundle string) string {
	if s != "" {
		return s
	}
	if bundle == "" {
		return "not verified when this report was generated"
	}
	return "not verified when this report was generated (run: att-monitor verify-bundle " + bundle + ")"
}

func (r *Report) viewGateway(v *htmlView) {
	g := &r.Gateway
	if !g.Known {
		v.GatewayNote = "No gateway status page was recorded in this window or in the setup-time capture."
		return
	}
	add := func(k, val string) {
		if strings.TrimSpace(val) != "" {
			v.Gateway = append(v.Gateway, kv{K: k, V: val})
		}
	}
	add("Model", strings.TrimSpace(g.Manufacturer+" "+g.Model))
	add("Serial number", g.Serial)
	add("Firmware", g.Firmware)
	add("Hardware version", g.Hardware)
	if g.UptimeSec >= 0 {
		up := fmtDur(g.UptimeSec)
		if !g.BootTime.IsZero() {
			up += ", last boot about " + fmtBoth(g.BootTime, r.loc)
		}
		add("Uptime", up)
	}
	bb := g.Broadband
	if g.NetworkType != "" {
		bb = strings.TrimSpace(bb + " (" + g.NetworkType + ")")
	}
	add("Broadband connection", bb)
	pon := g.PON
	if g.UNI != "" {
		pon = strings.TrimSpace(pon + ", UNI " + g.UNI)
	}
	add("PON link status", pon)
	opt := g.OpticalStatus
	if g.LinkState != "" {
		opt = strings.TrimSpace(opt + ", link state " + g.LinkState)
	}
	add("Optical WAN status", opt)
	if g.RxX10 != nil || g.TxX10 != nil {
		rx := fmtDBmP(g.RxX10)
		if g.RxNoLight {
			rx = "no receive level (fiber link down)"
		}
		add("Optical power (Rx / Tx)", rx+" / "+fmtDBmP(g.TxX10))
	}
	var flags []string
	for _, f := range []struct{ k, val string }{{"Rx LOS State", g.RxLOS}, {"OPT LOS", g.OptLOS}, {"Tx Fault State", g.TxFault}} {
		if f.val != "" {
			flags = append(flags, f.k+" "+f.val)
		}
	}
	add("Fiber state flags", strings.Join(flags, " · "))
	add("Fiber Last Change (raw)", g.LastChangeRaw)
	mod := strings.TrimSpace(strings.Join(nonEmpty(g.ModuleVendor, g.ModulePN, g.Wave), ", "))
	add("Fiber module (SFP)", mod)
	if g.TempC != nil {
		add("Module temperature", fmt.Sprintf("%d °C", *g.TempC))
	}
	add("WAN IPv4 address", g.WANIPv4)
	add("AT&T next hop", g.NextHop)
	add("DNS servers", g.DNS)
	add("Source", g.Source+" ("+fmtUTC(g.At)+")")
}

func nonEmpty(xs ...string) []string {
	var out []string
	for _, x := range xs {
		if strings.TrimSpace(x) != "" {
			out = append(out, strings.TrimSpace(x))
		}
	}
	return out
}

func (r *Report) viewReadings(v *htmlView) {
	op := &r.Optical
	v.Chart = op.Chart
	if len(op.Readings) == 0 {
		v.NoReadings = "No optical readings were recorded in this window."
		if s := op.SetupOutside; s != nil {
			v.NoReadings += fmt.Sprintf(" The setup-time capture (%s, outside this window) showed Rx %s%s.", fmtUTC(s.T), fmtDBm(s.RxX10), flagsPhrase(*s))
		}
		return
	}
	for _, row := range op.Rows {
		rx := fmtX10(row.RxX10)
		if row.NoLight {
			rx = "none"
		}
		v.Readings = append(v.Readings, readingView{
			Local: fmtLocal(row.T, r.loc), UTC: fmtUTC(row.T), Rx: rx, Source: row.Source(),
			Why: row.Why, Alarm: row.Alarm, Warn: row.Warn, Setup: row.Setup,
		})
	}
	v.ReadingNote = op.RowsNote
	if ch := op.Chart; ch != nil {
		v.Caption = r.chartCaption(ch)
	}
}

// chartCaption explains the chart in words: what each mark is, what is not drawn and why, and
// how the readings table relates to it.
func (r *Report) chartCaption(ch *Chart) string {
	op := &r.Optical
	var parts []string
	line := fmt.Sprintf("Blue line: the gateway's own Rx readings (%s", plural(ch.Levels, "receive level", "receive levels"))
	if ch.Bucketed {
		line += ", drawn as the mean per " + ch.BucketLabel + " with the range shaded"
	}
	line += "), broken where readings are missing"
	if ch.NoLight > 0 {
		line += " and where the fiber link was down"
	}
	parts = append(parts, line+".")
	parts = append(parts, "Red dashes and amber dots: the gateway's own low-Rx ALARM and WARNING thresholds.")
	parts = append(parts, "Strips: a full block marks a reading in which the gateway set its ALARM or WARNING flag or reported its fiber link down; a thin line, a reading without that.")
	if ch.OutageBands > 0 {
		parts = append(parts, fmt.Sprintf("Grey %s: the %s the monitor attributed to AT&T (see Incidents).", noun(ch.OutageBands, "band", "bands"),
			noun(ch.OutageBands, ch.BandsWhat, ch.BandsWhat+"s")))
	}
	if ch.NoLight > 0 {
		parts = append(parts, fmt.Sprintf("%s taken while the gateway reported its fiber link down %s no receive level; %s marked, not drawn as levels.",
			plural(ch.NoLight, "reading", "readings"), noun(ch.NoLight, "has", "have"), noun(ch.NoLight, "it is", "they are")))
	}
	if ch.Implausible > 0 {
		parts = append(parts, fmt.Sprintf("%s outside +/-100 dBm %s not drawn.", plural(ch.Implausible, "value", "values"), isAre(ch.Implausible)))
	}
	if ch.Context != nil {
		s := fmt.Sprintf("The plot shows the part of the window with readings, %s to %s; the bar above it shows the whole window and where readings exist.",
			fmtLocal(ch.PlotFrom, r.loc), fmtLocal(ch.PlotTo, r.loc))
		if su := ch.SetupOutside; su != nil {
			s += fmt.Sprintf(" The setup-time capture of %s, Rx %s%s, is marked on the bar.", fmtBoth(su.T, r.loc), fmtDBm(su.RxX10), flagsPhrase(*su))
		}
		parts = append(parts, s)
	}
	if len(op.Rows) < len(op.Readings) {
		parts = append(parts, fmt.Sprintf("The table below lists %d of the %d readings (the selection is explained under it); every reading is in the bundle.",
			len(op.Rows), len(op.Readings)))
	} else {
		parts = append(parts, "Every reading is listed in the table below.")
	}
	return strings.Join(parts, " ")
}

// eventGroups groups the gateway events written for the same observation - the same pair of
// snapshots compared, at the same time (the monitor writes one gateway_event per kind of change).
func eventGroups(evs []EventRow) [][]EventRow {
	var out [][]EventRow
	for _, e := range evs {
		if n := len(out); n > 0 {
			first := out[n-1][0]
			if len(e.Evidence) > 0 && slices.Equal(first.Evidence, e.Evidence) && absDur(e.T.Sub(first.T)) <= 2*time.Second {
				out[n-1] = append(out[n-1], e)
				continue
			}
		}
		out = append(out, []EventRow{e})
	}
	return out
}

// listedEventSeqs returns the gateway_event records the events table lists.
func (r *Report) listedEventSeqs() map[uint64]bool {
	out := map[uint64]bool{}
	for i, g := range eventGroups(r.Events) {
		if i == maxEventRows {
			break
		}
		for _, e := range g {
			out[e.Seq] = true
		}
	}
	return out
}

func (r *Report) viewEvents(v *htmlView) {
	groups := eventGroups(r.Events)
	unlisted := 0
	for i, g := range groups {
		if i >= maxEventRows {
			unlisted += len(g)
			continue
		}
		ev := eventView{Time: fmtBoth(g[0].T, r.loc)}
		if s := g[0].Evidence; len(s) > 0 {
			ev.Snaps = noun(len(s), "snapshot ", "snapshots ") + fmtSeqList(s, 3)
		}
		for _, e := range g {
			detail := e.Detail
			if restatesChange(e.Kind) && e.Change != "" {
				detail = "" // the change column says it all
			}
			ev.Items = append(ev.Items, eventItem{Label: e.Label, Change: e.Change, Detail: truncate(detail, 170), Ref: seqRef(e.Seq)})
		}
		v.Events = append(v.Events, ev)
	}
	var notes []string
	if unlisted > 0 {
		notes = append(notes, fmt.Sprintf("%s %s not listed here (%s in the bundle).", plural(unlisted, "further event", "further events"),
			isAre(unlisted), noun(unlisted, "it is", "they are")))
	}
	if r.EventsOther > 0 {
		notes = append(notes, fmt.Sprintf("%s about this monitor's own operation (certificate pinning, the gateway's notification setting) %s not listed.",
			plural(r.EventsOther, "gateway event", "gateway events"), isAre(r.EventsOther)))
	}
	if len(r.Events) == 0 {
		notes = append([]string{"The monitor recorded no change of the gateway's state in this window."}, notes...)
	}
	v.EventsNote = strings.Join(notes, " ")
}

// restatesChange: the monitor's detail text for these event kinds only repeats before -> after.
func restatesChange(kind string) bool {
	switch kind {
	case model.GwEvBroadbandState, model.GwEvPONState, model.GwEvWANIPChange, model.GwEvOpticalLinkChange:
		return true
	}
	return false
}

func (r *Report) viewIncidents(v *htmlView) {
	for i, inc := range r.Incidents {
		if i == maxIncidentRows {
			break
		}
		// Every figure comes from the incident record's fields (stats, duration); the monitor's
		// free-text summary is not repeated, so the row states each figure once.
		iv := incidentView{ID: inc.ID, Ref: inc.RecType + " " + seqRef(inc.RecSeq), Rules: orNA(inc.Rules),
			Duration: fmtDur(inc.DurationSec) + " in total", Downtime: fmtDur(inc.Stats.DowntimeSec) + " without Internet"}
		if !inc.OpenedT.IsZero() {
			iv.Opened = "opened " + fmtBoth(inc.OpenedT, r.loc)
			if inc.StartedBefore {
				iv.Opened += ", before this window"
			}
		} else {
			iv.Opened = "opened " + orNA(inc.Opened)
		}
		if inc.OpenAtEnd {
			iv.Closed = "still open at the end of the window"
		} else {
			iv.Closed = "closed " + fmtBoth(inc.ClosedT, r.loc)
		}
		if inc.Stats.DegradedSec > 0 {
			iv.Downtime += "; degraded " + fmtDur(inc.Stats.DegradedSec)
		}
		if inc.Stats.RestartSec > 0 {
			iv.Downtime += "; gateway restart " + fmtDur(inc.Stats.RestartSec)
		}
		iv.Class = strings.Join(nonEmpty(inc.State, inc.Cause, "attribution "+orNA(inc.Attribution)), " / ")
		var other []string
		for _, c := range inc.Causes {
			if c = strings.TrimSpace(c); c != "" && c != inc.Cause && !slices.Contains(other, c) {
				other = append(other, c)
			}
		}
		if len(other) > 0 {
			iv.Causes = "also seen: " + truncate(strings.Join(other, ", "), 120)
		}
		v.Incidents = append(v.Incidents, iv)
	}
	var notes []string
	if n := len(r.Incidents) - maxIncidentRows; n > 0 {
		notes = append(notes, fmt.Sprintf("%s %s not listed here (%s in the bundle).", plural(n, "further incident", "further incidents"),
			isAre(n), noun(n, "it is", "they are")))
	}
	if len(r.IncidentsUnlisted) > 0 {
		notes = append(notes, "Samples of this window refer to incidents whose records lie outside it: "+joinAndMore(r.IncidentsUnlisted, 6)+".")
	}
	v.IncNote = strings.Join(notes, " ")
	if len(r.Incidents) == 0 {
		if r.Coverage.Cycles == 0 {
			v.NoIncident = "No measurement cycles were recorded in this window, so incidents could not be detected."
		} else {
			v.NoIncident = "No incident was recorded in this window."
		}
	}
}

func (r *Report) viewCoverage(v *htmlView) {
	cv, av, h := &r.Coverage, &r.Avail, &r.Home
	for i, g := range cv.Gaps {
		if i == maxGapRows {
			n := len(cv.Gaps) - maxGapRows
			v.GapsNote = fmt.Sprintf("%s %s not listed.", plural(n, "further gap", "further gaps"), isAre(n))
			break
		}
		v.Gaps = append(v.Gaps, gapView{From: fmtBoth(g.From, r.loc), To: fmtBoth(g.To, r.loc), Dur: fmtDur(g.Sec), Why: g.Why})
	}
	v.Avail = []kv{
		{K: "Measurement cycles", V: fmt.Sprintf("%s of %s, %s monitored; cycle interval from %s",
			plural(av.Cycles, "cycle", "cycles"), fmtDur(int64(cv.FastInterval/time.Second)), fmtHours(cv.MonitoredSec), cv.FastBasis)},
	}
	if av.Cycles > 0 {
		var states []string
		for _, st := range []string{model.StateOnline, model.StateDegraded, model.StateISPOutage, model.StateLocalFault, model.StateUnknown} {
			if n := av.ByState[st]; n > 0 {
				states = append(states, fmt.Sprintf("%s %s", st, fmtInt(int64(n))))
			}
		}
		var others []string
		for st, n := range av.ByState {
			switch st {
			case model.StateOnline, model.StateDegraded, model.StateISPOutage, model.StateLocalFault, model.StateUnknown:
			default:
				others = append(others, fmt.Sprintf("%s %s", st, fmtInt(int64(n))))
			}
		}
		sort.Strings(others)
		v.Avail = append(v.Avail, kv{K: "Cycles by state", V: strings.Join(append(states, others...), " · ")})
		v.Avail = append(v.Avail, kv{K: "Availability (ONLINE / classified cycles)", V: fmt.Sprintf("%s (%s of %s; truncated, never rounded up)", av.Pct, fmtInt(int64(av.Online)), fmtInt(int64(av.Classified)))})
		blip := "none"
		if av.Blips > 0 {
			blip = fmt.Sprintf("%s (%s, %s; %s without Internet)", fmtInt(int64(av.Blips)), plural(av.BlipCycles, "failed cycle", "failed cycles"), fmtDur(av.BlipSec), fmtDur(av.BlipOutageSec))
		}
		v.Avail = append(v.Avail, kv{K: "Blips (failed cycles outside incidents)", V: blip})
	}
	if h.GwProbes > 0 {
		v.Home = append(v.Home, kv{K: "Pings to the gateway", V: fmt.Sprintf("%s of %s answered (%s lost); median round-trip %s (rule threshold %g ms)",
			fmtInt(int64(h.GwOK)), fmtInt(int64(h.GwProbes)), fmtInt(int64(h.GwProbes-h.GwOK)), fmtMs(h.GwMedianUs), h.LatencyOKMs)})
	}
	if h.LANKnown > 0 {
		v.Home = append(v.Home, kv{K: "Gateway answered (ICMP or TCP)", V: fmt.Sprintf("in %s of %s cycles", fmtInt(int64(h.LANUp)), fmtInt(int64(h.LANKnown)))})
	}
	if l := h.Latest; l != nil {
		link := l.Type
		var about []string
		if l.Type == "wifi" {
			link = strings.Join(nonEmpty("Wi-Fi", l.Band, l.RadioType, chanText(l.Channel)), ", ")
			if h.SignalMax > 0 {
				if h.SignalMin == h.SignalMax {
					link += fmt.Sprintf("; signal %d%%", h.SignalMax)
				} else {
					link += fmt.Sprintf("; signal %d-%d%%", h.SignalMin, h.SignalMax)
				}
			}
		} else if l.LinkMbps > 0 {
			link += fmt.Sprintf(", %d Mb/s", l.LinkMbps)
		}
		about = append(about, plural(h.Links, "reading", "readings"), "latest local_link "+seqRef(h.LatestSeq))
		if l.Type == "wifi" && h.SignalMax > 0 && l.RSSIdBm != 0 {
			about = append(about, fmt.Sprintf("its RSSI %d dBm", l.RSSIdBm))
		}
		v.Home = append(v.Home, kv{K: "This computer's link", V: fmt.Sprintf("%s (%s)", link, strings.Join(about, ", "))})
	}
	if h.EgressChecks > 0 {
		eg := fmt.Sprintf("all %d route checks: Internet destinations routed through the AT&T gateway", h.EgressChecks)
		if h.EgressBypass > 0 {
			eg = fmt.Sprintf("%d of %d route checks found traffic bypassing the gateway (first: local_link %s)", h.EgressBypass, h.EgressChecks, seqRef(h.BypassSeq))
		}
		v.Home = append(v.Home, kv{K: "Route check (VPN / other network)", V: eg})
	}
}

func chanText(ch int) string {
	if ch <= 0 {
		return ""
	}
	return fmt.Sprintf("channel %d", ch)
}

func (r *Report) viewEvidence(v *htmlView) {
	ev := &r.Evidence
	add := func(k, val string, mono, stated bool) {
		v.Evidence = append(v.Evidence, kv{K: k, V: val, Mono: mono, Stated: stated})
	}
	add("Evidence bundle", orNA(ev.BundleName), ev.BundleName != "", ev.BundleName != "")
	add("Bundle SHA-256", orNA(ev.BundleSHA256), ev.BundleSHA256 != "", ev.BundleSHA256 != "")
	add("Verification", verificationText(ev.Verification, ev.BundleName), false, ev.Verification != "")
	if ev.HasGenesis {
		fp := groupFingerprint(ev.Fingerprint)
		if !ev.FingerprintOK {
			fp += " (does NOT match the genesis public key)"
		}
		add("Ledger key fingerprint", fp, true, false)
		created := fmt.Sprintf("%s (genesis %s)", fmtUTC(ev.GenesisTS), seqRef(ev.GenesisSeq))
		if ev.Host != "" {
			created += " on " + ev.Host
		}
		if ev.Software != "" {
			created += ", " + ev.Software
		}
		add("Ledger created", created, false, false)
	} else {
		add("Ledger signing key", "the genesis record is not in this evidence", false, false)
	}
	if ev.WindowRecords > 0 {
		add("Records of this window", fmt.Sprintf("%s, %s to %s", plural(ev.WindowRecords, "record", "records"), seqRef(ev.WindowFirstSeq), seqRef(ev.WindowLastSeq)), false, false)
	} else {
		add("Records of this window", "none", false, false)
	}
	switch a := ev.Anchor; {
	case a != nil:
		s := fmt.Sprintf("%s, genTime %s, covers every record up to %s (anchor %s, written %s)", a.TSA, fmtUTC(a.GenTime), seqRef(a.HeadSeq), seqRef(a.Seq), fmtUTC(a.TS))
		if a.Uncovered == 0 {
			s += fmt.Sprintf(": all %s of this window", plural(a.Covered, "record", "records"))
		} else {
			s += fmt.Sprintf(": %d of this window's records; the %s after it %s protected by the hash chain and signatures until the next time-stamp",
				a.Covered, plural(a.Uncovered, "record", "records"), isAre(a.Uncovered))
		}
		add("Time-stamp covering this window", s, false, false)
	case ev.WindowRecords > 0:
		add("Time-stamp covering this window", "none yet: no trusted time-stamp covers this window's records yet (they are protected by the hash chain and the signatures until the next time-stamp)", false, false)
	}
	if ev.AnchorsUntrusted > 0 {
		add("Time-stamps not counted as proof of time", fmt.Sprintf("%d of %d anchor records in or after the window (signature or certificate chain not verified when obtained)", ev.AnchorsUntrusted, ev.AnchorsSeen), false, false)
	}
	if s := ev.Setup; s != nil {
		v.Setup = r.viewSetup(s)
	}
	v.Facts = ev.Facts
	bundle := ev.BundleName
	if bundle == "" {
		bundle = "att-evidence_....zip"
	}
	verify := []string{"att-monitor verify-bundle", bundle}
	if ev.HasGenesis && ev.Fingerprint != "" {
		verify = append(verify, "--expect-fingerprint "+ev.Fingerprint)
	}
	v.Verify = []verifyStep{
		{Text: "With att-monitor (checks every record's hash, signature and chain link, the blobs, the time-stamp tokens and their certificate chains, and recomputes the bundle's own report):",
			Cmds: [][]string{verify}},
		{Text: "With Python 3.9 or newer, using the verifier shipped inside the bundle (records, blobs, signatures with the cryptography package, time-stamps with OpenSSL):",
			Cmds: [][]string{{"python tools/verify_bundle.py", bundle}}},
		{Text: "A record by hand (e.g. snapshot #N): in ledger/ledger-YYYY-MM-DD.jsonl the line whose b contains \"seq\":N has h = SHA-256 of the exact bytes of b; the next record's prev equals h."},
	}
	if a := ev.Anchor; a != nil && a.Token != "" && !a.GenTime.IsZero() {
		v.Verify = append(v.Verify, verifyStep{Text: "The time-stamp covering this window (anchor " + seqRef(a.Seq) + "), on the extracted bundle:",
			Cmds: [][]string{opensslVerify(a.GenTime, a.HeadHash, a.Token)}})
	}
	if s := ev.Setup; s != nil {
		var cmds [][]string
		var names []string
		for _, tk := range s.Tokens {
			if tk.Covers == "" || tk.Imprint == "" || tk.GenTime.IsZero() {
				continue
			}
			names = append(names, tk.Path)
			cmds = append(cmds, opensslVerify(tk.GenTime, tk.Imprint, tk.SHA256))
		}
		if len(cmds) > 0 {
			v.Verify = append(v.Verify, verifyStep{Text: "The setup-time tokens (" + strings.Join(names, ", ") + "), on the extracted bundle:", Cmds: cmds})
		}
	}
}

// opensslVerify is the OpenSSL command that verifies a time-stamp token, as arguments.
func opensslVerify(gen time.Time, digest, token string) []string {
	return []string{"openssl ts -verify", fmt.Sprintf("-attime %d", gen.Unix()), "-digest " + digest, "-in blobs/" + token, "-CAfile keys/tsa-roots.pem"}
}

func (r *Report) viewSetup(s *Setup) *setupView {
	sv := &setupView{Problems: s.Problems}
	sv.Rows = append(sv.Rows, kv{K: "Import record", V: fmt.Sprintf("bootstrap_import %s, written %s; %s from %s",
		seqRef(s.Seq), fmtUTC(s.TS), plural(s.Files, "file", "files"), orNA(s.SourceDir))})
	if s.Rx != nil {
		where := "inside this window"
		if !s.InWindow {
			where = "outside this window"
		}
		sv.Rows = append(sv.Rows, kv{K: "Optical reading in the capture", V: fmt.Sprintf("Rx %s%s (thresholds: ALARM %s, WARNING %s) at %s (file time, %s)",
			fmtDBm(s.Rx.RxX10), flagsPhrase(*s.Rx), fmtDBmP(s.Rx.AlarmThr), fmtDBmP(s.Rx.WarnThr), fmtUTC(s.Rx.T), where)})
	}
	if s.LastChange != 0 {
		// Both readings, as on page 1: the gateway does not say whether the value counts in UTC
		// or in its local time.
		lc := fmt.Sprintf("%d: %s", s.LastChange, r.changeTimes(s.Change, s.Offset))
		if lk := &r.Link; lk.Confirmed != "" && len(lk.Changes) > 0 {
			as := "UTC"
			if lk.Confirmed == "local" {
				as = "the gateway's local time"
			}
			lc += fmt.Sprintf(". The change in %s can only be read as %s, which supports that reading of this value too", lk.ConfirmedBy, as)
		}
		sv.Rows = append(sv.Rows, kv{K: "Fiber Last Change in the capture", V: lc})
	}
	var state []string
	if s.UptimeSec >= 0 {
		state = append(state, fmt.Sprintf("uptime %s (last boot about %s)", fmtDur(s.UptimeSec), fmtUTC(s.Boot)))
	}
	if s.ClockRaw != "" {
		c := "clock " + s.ClockRaw
		if s.Offset != nil {
			c += " (" + fmtOffset(*s.Offset) + ")"
		}
		state = append(state, c)
	}
	if len(state) > 0 {
		sv.Rows = append(sv.Rows, kv{K: "Gateway uptime and clock in the capture", V: strings.Join(state, "; ")})
	}
	if a := s.Anchor; a != nil {
		sv.Rows = append(sv.Rows, kv{K: "Ledger time-stamp over the import record", V: fmt.Sprintf("%s, genTime %s (anchor %s covers up to %s)", a.TSA, fmtUTC(a.GenTime), seqRef(a.Seq), seqRef(a.HeadSeq))})
	}
	for _, p := range s.Pages {
		pv := setupPageView{Path: p.Path, SHA256: shortHash(p.SHA256)}
		if !p.Time.IsZero() {
			pv.Time = fmtUTC(p.Time)
		}
		switch {
		case !p.OK:
			pv.Listed = "stored copy missing or not matching its SHA-256"
		case len(p.ListedIn) > 0:
			pv.Listed = "listed in " + strings.Join(p.ListedIn, ", ")
		default:
			pv.Listed = "not listed"
		}
		sv.Pages = append(sv.Pages, pv)
	}
	for _, tk := range s.Tokens {
		tv := tokenView{Path: tk.Path, TSA: orNA(tk.TSA)}
		switch {
		case tk.Err != "":
			tv.GenTime = "unreadable: " + tk.Err
		case !tk.Granted:
			tv.GenTime = "not a granted time-stamp"
		default:
			tv.GenTime = fmtUTC(tk.GenTime)
		}
		if tk.Covers != "" {
			tv.Covers = tk.Covers
		} else if tk.Imprint != "" {
			tv.Covers = "no imported file has its hash (" + shortHash(tk.Imprint) + ")"
		}
		sv.Tokens = append(sv.Tokens, tv)
	}
	return sv
}

var pageTmpl = template.Must(template.New("ticket").Funcs(template.FuncMap{
	"mod":   func(a, b int) int { return a % b },
	"pairs": pairs,
	"segs":  segs,
}).Parse(pageHTML))

// pairs groups key/value rows two by two (a two-column table).
func pairs(rows []kv) [][]kv {
	var out [][]kv
	for i := 0; i < len(rows); i += 2 {
		out = append(out, rows[i:min(i+2, len(rows))])
	}
	return out
}

// pageHTML is the page. The "t" template prints a text with its values kept on one line and its
// long hyphenated values wrapped where the line is full (segs); "lbl" prints a chart label on its
// white box. A command argument moves to the next line as a whole; only an argument longer than
// a line wraps, where the line is full.
const pageHTML = `{{define "t"}}{{range segs .}}{{if .N}}<span class="nw">{{.T}}</span>{{else if .A}}<span class="ba">{{.T}}</span>{{else}}{{.T}}{{end}}{{end}}{{end}}
{{- define "lbl"}}{{if .BW}}<rect class="lblbg" x="{{.BX}}" y="{{.BY}}" width="{{.BW}}" height="{{.BH}}"></rect>{{end}}<text class="lbl" x="{{.X}}" y="{{.Y}}" text-anchor="{{.Anchor}}">{{.Label}}</text>{{end}}
{{- define "kvrows"}}{{range .}}
<tr><th scope="row">{{.K}}{{if .Stated}}<span class="st">*</span>{{end}}</th><td{{if .Mono}} class="mono"{{end}}>{{template "t" .V}}</td></tr>
{{- end}}{{end -}}
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<style>
@page {
  size: Letter;
  margin: 0.5in 0.55in 0.6in 0.55in;
  @bottom-left { content: {{.PageIdentity}}; font: 7pt "Segoe UI", system-ui, Arial, sans-serif; color: #6b6a65; vertical-align: top; padding-top: 8pt; }
  @bottom-right { content: "Page " counter(page) " of " counter(pages); font: 7pt "Segoe UI", system-ui, Arial, sans-serif; color: #6b6a65; vertical-align: top; padding-top: 8pt; }
}
:root {
  color-scheme: light;
  --ink: #0b0b0b; --ink2: #52514e; --muted: #6b6a65;
  --rule: #d9d8d2; --grid: #e1e0d9; --axis: #c3c2b7; --wash: #f2f1ed; --present: #a9a89f; --outage: #e6e3dc;
  --series: #2a78d6; --critical: #d03b3b; --warning: #fab219;
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; background: #ffffff; color: var(--ink); }
body { font: 9.2pt/1.34 "Segoe UI", system-ui, -apple-system, "Helvetica Neue", Arial, sans-serif;
  -webkit-print-color-adjust: exact; print-color-adjust: exact; }
.sheet { width: 100%; }
.sheet + .sheet { break-before: page; }
.sheet + .sheet.flow { break-before: auto; margin-top: 14pt; border-top: 0.75pt solid var(--rule); }
#details { font-size: 8.5pt; }
#details h2 { font-size: 10.5pt; margin: 9pt 0 3pt; }
#details h2:first-child { margin-top: 0; }
@media screen {
  body { background: #e9e8e3; padding: 16px 0; }
  .sheet { background: #ffffff; width: 8.5in; max-width: 100%; margin: 0 auto 16px; padding: 0.5in 0.55in; box-shadow: 0 1px 3px rgba(0,0,0,.14); }
}
h1 { font-size: 15pt; line-height: 1.2; margin: 0 0 3pt; letter-spacing: -0.005em; }
h2 { font-size: 11pt; margin: 9pt 0 3pt; padding-bottom: 2pt; border-bottom: 0.75pt solid var(--rule); break-after: avoid; }
h3 { font-size: 9.5pt; margin: 8pt 0 3pt; break-after: avoid; }
p { margin: 0 0 5pt; }
.meta { color: var(--ink2); font-size: 8.5pt; margin: 0 0 7pt; }
.meta b { color: var(--ink); font-weight: 600; }
.nw { white-space: nowrap; }
.ba { word-break: break-all; }
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; vertical-align: top; }
td { overflow-wrap: anywhere; }
tr { break-inside: avoid; }
table + table, table + p + table { margin-top: 6pt; }
caption { caption-side: top; text-align: left; font-weight: 600; font-size: 8pt; color: var(--ink2); padding: 0 0 2pt; }
.customer { table-layout: fixed; border-collapse: separate; border-spacing: 0; border: 0.75pt solid var(--rule); border-radius: 3pt; padding: 0 8pt 7pt; margin: 0 0 4pt; }
.customer col.cl { width: 17%; }
.customer col.cv { width: 33%; }
.customer th { font-weight: 600; font-size: 8pt; color: var(--ink2); padding: 5pt 6pt 0 0; white-space: nowrap; vertical-align: baseline; }
.customer td { padding: 5pt 10pt 0 0; font-size: 9.5pt; vertical-align: baseline; }
.fill { display: inline-block; width: 100%; height: 2em; border-bottom: 0.75pt solid var(--ink2); }
ol.summary { margin: 0; padding-left: 15pt; }
ol.summary li { margin: 0 0 4pt; padding-left: 2pt; }
ol.summary li strong, .action strong { font-weight: 650; }
.action { border-left: 2.5pt solid var(--ink); padding: 2pt 0 2pt 8pt; margin: 2pt 0 4pt; }
.brief { margin-top: 8pt; font-size: 8pt; color: var(--ink2); border-top: 0.75pt solid var(--rule); padding-top: 4pt; }
.brief th { font-weight: 600; padding: 1pt 8pt 1pt 0; white-space: nowrap; width: 1%; }
.brief td { padding: 1pt 0; }
.st { font-weight: 600; margin-left: 1pt; }
.footnote { font-size: 7.5pt; color: var(--muted); margin: 3pt 0 0; }
.mono { font-family: Consolas, "Cascadia Mono", "Courier New", monospace; font-size: 7.6pt; }
table.kv th { font-weight: 600; color: var(--ink2); font-size: 7.6pt; width: 30%; padding: 1.4pt 8pt 1.4pt 0; border-bottom: 0.5pt solid var(--grid); }
table.kv td { font-size: 7.9pt; padding: 1.4pt 6pt 1.4pt 0; border-bottom: 0.5pt solid var(--grid); }
table.kv2 th { width: 17%; }
table.kv2 td { width: 33%; }
table.data { font-size: 7.6pt; }
table.data.compact td { padding-top: 0.5pt; padding-bottom: 0.5pt; line-height: 1.22; }
table.data th { font-weight: 600; color: var(--ink2); border-bottom: 0.75pt solid var(--axis); padding: 2pt 5pt 2pt 0; white-space: nowrap; }
table.data td { border-bottom: 0.5pt solid var(--grid); padding: 1.4pt 5pt 1.4pt 0; }
table.data tbody.grp { break-inside: avoid; }
table.events { table-layout: fixed; }
table.events col.when { width: 27%; }
table.events col.what { width: 17%; }
table.events col.ref { width: 10%; }
table.data tbody.grp td.when { border-bottom: 0.5pt solid var(--axis); }
td.num { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
td.path { font-family: Consolas, "Cascadia Mono", "Courier New", monospace; font-size: 7.6pt; }
.muted { color: var(--muted); }
.small { font-size: 8pt; }
.flag { white-space: nowrap; }
.flag.on::before { content: ""; display: inline-block; width: 6pt; height: 6pt; margin-right: 3pt; vertical-align: -0.5pt; border-radius: 1pt; }
.flag.on.alarm::before { background: var(--critical); }
.flag.on.warning::before { background: var(--warning); }
.flag.on { font-weight: 600; }
figure { margin: 4pt 0 6pt; break-inside: avoid; }
figcaption { font-size: 8pt; color: var(--ink2); margin-top: 2pt; }
svg.chart { display: block; width: 100%; height: auto; }
svg.chart text { font-family: "Segoe UI", system-ui, Arial, sans-serif; font-size: 10px; fill: var(--ink2); }
svg.chart .grid { stroke: var(--grid); stroke-width: 1; }
svg.chart .axis { stroke: var(--axis); stroke-width: 1; }
svg.chart text.tick { fill: var(--muted); font-variant-numeric: tabular-nums; }
svg.chart text.date, svg.chart text.unit { fill: var(--muted); }
svg.chart .series { fill: none; stroke: var(--series); stroke-width: 2; stroke-linejoin: round; stroke-linecap: round; }
svg.chart .spread { fill: var(--series); fill-opacity: 0.12; stroke: none; }
svg.chart .dot, svg.chart .marker { fill: var(--series); stroke: #ffffff; stroke-width: 2; }
svg.chart .ref { fill: none; stroke-width: 1.5; }
svg.chart .ref.alarm { stroke: var(--critical); stroke-dasharray: 8 4; }
svg.chart .ref.warning { stroke: var(--warning); stroke-dasharray: 0.1 4; stroke-width: 2.5; stroke-linecap: round; }
svg.chart .outage { fill: var(--outage); }
svg.chart .lblbg { fill: #ffffff; fill-opacity: 0.9; }
svg.chart text.lbl { fill: var(--ink); }
svg.chart .stripbg { fill: var(--wash); }
svg.chart .present { fill: var(--present); }
svg.chart .flagseg.alarm { fill: var(--critical); }
svg.chart .flagseg.warning { fill: var(--warning); }
svg.chart .flagseg.nolight { fill: var(--ink); }
svg.chart .zoom { fill: none; stroke: var(--ink); stroke-width: 1; }
svg.chart text.striplabel { fill: var(--ink2); }
svg.chart text.empty { fill: var(--muted); font-style: italic; }
.code { display: block; font-family: Consolas, "Cascadia Mono", "Courier New", monospace; font-size: 7.4pt; background: var(--wash); padding: 2pt 4pt; margin: 1pt 0 3pt; white-space: normal; }
.code .arg { display: inline-block; max-width: 100%; word-break: break-all; }
ol.verify { padding-left: 14pt; margin: 2pt 0; font-size: 8.5pt; }
ol.verify li { margin-bottom: 3pt; break-inside: avoid; }
ul.notes { padding-left: 14pt; margin: 2pt 0; font-size: 8pt; color: var(--ink2); }
</style>
</head>
<body>
<main>
<section class="sheet" id="ticket">
<h1>{{.Title}}</h1>
<p class="meta">Window: <b>{{template "t" .WindowLocal}}</b>{{with .WindowUTC}} ({{template "t" .}}){{end}}<br>Generated {{template "t" .Generated}}</p>

<table class="customer" aria-label="Customer">
<colgroup><col class="cl"><col class="cv"><col class="cl"><col class="cv"></colgroup>
{{- range .CustRows}}
<tr>{{range .}}<th scope="row">{{.Label}}</th><td{{if .Wide}} colspan="3"{{end}}>{{if .Value}}{{template "t" .Value}}{{else}}<span class="fill"></span>{{end}}</td>{{end}}</tr>
{{- end}}
</table>

<h2>Summary for AT&amp;T</h2>
<ol class="summary">
{{- range .Summary}}
<li><strong>{{template "t" .Lead}}</strong> {{template "t" .Text}}</li>
{{- end}}
</ol>

<h2>Requested action</h2>
<div class="action"><p><strong>{{template "t" .Action.Lead}}</strong> {{template "t" .Action.Text}}</p></div>

{{- if .CoverageOnPage1}}

<h2>Monitoring coverage</h2>
<p>{{template "t" .Coverage}}</p>
{{- end}}

{{- if .BriefOnPage1}}
<table class="brief">
{{- template "kvrows" .Brief}}
</table>
<p class="footnote">{{.Stated}}</p>
{{- end}}
</section>

<section class="sheet{{if .DetailsFlow}} flow{{end}}" id="details">
{{- if not .CoverageOnPage1}}
<h2>Monitoring coverage</h2>
<p>{{template "t" .Coverage}}</p>
{{- end}}
<h2>Gateway</h2>
{{- if .Gateway}}
<table class="kv kv2">
{{- range pairs .Gateway}}
<tr>{{range .}}<th scope="row">{{.K}}</th><td>{{template "t" .V}}</td>{{end}}</tr>
{{- end}}
</table>
{{- else}}
<p>{{.GatewayNote}}</p>
{{- end}}

<h2>Optical receive power</h2>
{{- with .Chart}}
<figure>
<svg class="chart" viewBox="0 0 {{.W}} {{.H}}" role="img" aria-labelledby="chart-title chart-desc">
<title id="chart-title">{{.Title}}</title>
<desc id="chart-desc">{{.Desc}}</desc>
{{- with .Context}}
{{- range .Ticks}}
<text class="tick" x="{{.X}}" y="{{$.Chart.Context.TickY}}" text-anchor="middle">{{.Label}}</text>
{{- end}}
<rect class="stripbg" x="{{$.Chart.X0}}" y="{{.Y}}" width="{{$.Chart.PlotW}}" height="{{.H}}"></rect>
{{- range .Present}}
<rect class="present" x="{{.X}}" y="{{$.Chart.Context.Y}}" width="{{.W}}" height="{{$.Chart.Context.PresentH}}"><title>{{.Title}}</title></rect>
{{- end}}
<rect class="zoom" x="{{.ZoomX}}" y="{{.ZoomY}}" width="{{.ZoomW}}" height="{{.ZoomH}}"></rect>
{{- with .Setup}}
<path class="marker" d="{{.Path}}"><title>{{.Title}}</title></path>
{{- if .Label.Label}}{{template "lbl" .Label}}{{end}}
{{- end}}
<text class="striplabel" x="{{.LX}}" y="{{.LY}}" text-anchor="end">{{.Label}}</text>
{{template "lbl" .Note}}
{{- end}}
{{- range .Bands}}
<rect class="outage" x="{{.X}}" y="{{$.Chart.Y0}}" width="{{.W}}" height="{{$.Chart.PlotH}}"><title>{{.Title}}</title></rect>
{{- with .Label}}{{template "lbl" .}}{{end}}
{{- end}}
{{- range .YTicks}}
<line class="grid" x1="{{$.Chart.X0}}" x2="{{$.Chart.X1}}" y1="{{.Y}}" y2="{{.Y}}"></line>
<text class="tick" x="{{$.Chart.YUnitX}}" y="{{.TY}}" text-anchor="end">{{.Label}}</text>
{{- end}}
<text class="unit" x="{{.YUnitX}}" y="{{.YUnitY}}" text-anchor="end">dBm</text>
<line class="axis" x1="{{.X0}}" x2="{{.X1}}" y1="{{.Y1}}" y2="{{.Y1}}"></line>
{{- range .XTicks}}
<line class="axis" x1="{{.X}}" x2="{{.X}}" y1="{{$.Chart.Y1}}" y2="{{$.Chart.TickY2}}"></line>
<text class="tick" x="{{.X}}" y="{{$.Chart.XLabelY}}" text-anchor="middle">{{.Label}}</text>
{{- if .Label2}}<text class="date" x="{{.X}}" y="{{$.Chart.XDateY}}" text-anchor="middle">{{.Label2}}</text>{{end}}
{{- end}}
{{- range .Empty}}
<text class="empty" x="{{.X}}" y="{{.Y}}" text-anchor="{{.Anchor}}">{{.Label}}</text>
{{- end}}
{{- range .Refs}}
<line class="ref {{.Class}}" x1="{{.X0}}" x2="{{.X1}}" y1="{{.Y}}" y2="{{.Y}}"></line>
{{- end}}
{{- range .Spreads}}
<path class="spread" d="{{.}}"></path>
{{- end}}
{{- range .Lines}}
<path class="series" d="{{.}}"></path>
{{- end}}
{{- range .Dots}}
<circle class="dot" cx="{{.X}}" cy="{{.Y}}" r="4">{{if .Title}}<title>{{.Title}}</title>{{end}}</circle>
{{- end}}
{{- range .Refs}}
{{template "lbl" .Label}}
{{- end}}
{{- with .Setup}}
<path class="marker" d="{{.Path}}"><title>{{.Title}}</title></path>
{{template "lbl" .Label}}
{{- end}}
{{- with .End}}
<circle class="dot" cx="{{.X}}" cy="{{.Y}}" r="4.5"><title>{{.Title}}</title></circle>
{{template "lbl" .Label}}
{{- end}}
{{- range .Strips}}
<rect class="stripbg" x="{{$.Chart.X0}}" y="{{.Y}}" width="{{$.Chart.PlotW}}" height="{{.H}}"></rect>
{{- $s := .}}
{{- range .Present}}<rect class="present" x="{{.X}}" y="{{$s.PY}}" width="{{.W}}" height="{{$s.PH}}"><title>{{.Title}}</title></rect>{{end}}
{{- range .Flags}}<rect class="flagseg {{$s.Class}}" x="{{.X}}" y="{{$s.Y}}" width="{{.W}}" height="{{$s.H}}"><title>{{.Title}}</title></rect>{{end}}
<text class="striplabel" x="{{.LX}}" y="{{.LY}}" text-anchor="end">{{.Label}}</text>
{{- end}}
<text class="unit" x="{{.AxisTitleX}}" y="{{.AxisTitleY}}" text-anchor="middle">{{.AxisTitle}}</text>
</svg>
<figcaption>{{template "t" $.Caption}}</figcaption>
</figure>
{{- end}}
{{- if .Readings}}
<table class="data compact">
<thead><tr>{{if .LocalCols}}<th>Time (local)</th>{{end}}<th>Time (UTC)</th><th class="num">Rx (dBm)</th><th>ALARM flag</th><th>WARNING flag</th><th>Record</th><th>Note</th></tr></thead>
<tbody>
{{- range .Readings}}
<tr>{{if $.LocalCols}}<td>{{template "t" .Local}}</td>{{end}}<td>{{template "t" .UTC}}</td><td class="num">{{.Rx}}</td><td>{{if .Alarm}}<span class="flag on alarm">set</span>{{else}}<span class="flag">not set</span>{{end}}</td><td>{{if .Warn}}<span class="flag on warning">set</span>{{else}}<span class="flag">not set</span>{{end}}</td><td>{{template "t" .Source}}</td><td>{{.Why}}</td></tr>
{{- end}}
</tbody>
</table>
{{- with .ReadingNote}}<p class="small muted">{{template "t" .}}</p>{{end}}
{{- else}}
<p>{{template "t" .NoReadings}}</p>
{{- end}}

<h2>Gateway events</h2>
{{- if .Events}}
<table class="data compact events">
<colgroup><col class="when"><col class="what"><col class="change"><col class="ref"></colgroup>
<thead><tr><th>Observed (snapshots compared)</th><th>Event</th><th>Change, as the gateway reported it</th><th>gateway_event</th></tr></thead>
{{- range .Events}}
<tbody class="grp">
{{- $g := .}}
{{- range $i, $it := .Items}}
<tr>{{if eq $i 0}}<td class="when" rowspan="{{len $g.Items}}">{{template "t" $g.Time}}{{with $g.Snaps}}<br><span class="muted">{{.}}</span>{{end}}</td>{{end}}<td>{{$it.Label}}</td><td>{{template "t" $it.Change}}{{with $it.Detail}}<br><span class="muted">{{template "t" .}}</span>{{end}}</td><td>{{$it.Ref}}</td></tr>
{{- end}}
</tbody>
{{- end}}
</table>
{{- end}}
{{- with .EventsNote}}<p class="small muted">{{.}}</p>{{end}}

<h2>Incidents</h2>
{{- if .Incidents}}
<table class="data">
<thead><tr><th>Incident</th><th>Opened / closed</th><th>Duration / without Internet</th><th>State / cause / attribution</th></tr></thead>
<tbody>
{{- range .Incidents}}
<tr><td>{{template "t" .ID}}<br><span class="muted">{{.Ref}}, rules {{.Rules}}</span></td><td>{{template "t" .Opened}}<br>{{template "t" .Closed}}</td><td>{{template "t" .Duration}}<br>{{template "t" .Downtime}}</td><td>{{.Class}}{{with .Causes}}<br><span class="muted">{{.}}</span>{{end}}</td></tr>
{{- end}}
</tbody>
</table>
{{- else}}
<p>{{.NoIncident}}</p>
{{- end}}
{{- with .IncNote}}<p class="small muted">{{template "t" .}}</p>{{end}}

<h2>Monitoring, availability and home network</h2>
<table class="kv">
{{- template "kvrows" .Avail}}
{{- template "kvrows" .Home}}
</table>
{{- if .Gaps}}
<table class="data">
<caption>Stretches of the window without measurement cycles</caption>
<thead><tr><th>From</th><th>To</th><th class="num">Length</th><th>Explanation on record</th></tr></thead>
<tbody>
{{- range .Gaps}}
<tr><td>{{template "t" .From}}</td><td>{{template "t" .To}}</td><td class="num">{{template "t" .Dur}}</td><td>{{template "t" .Why}}</td></tr>
{{- end}}
</tbody>
</table>
{{- with .GapsNote}}<p class="small muted">{{.}}</p>{{end}}
{{- end}}

<h2>Evidence and integrity</h2>
<table class="kv">
{{- template "kvrows" .Evidence}}
</table>
<p class="footnote">{{.Stated}}</p>
{{- with .Setup}}
<h3>Setup-time capture (gateway pages saved during installation, before the monitor existed)</h3>
<table class="kv">
{{- template "kvrows" .Rows}}
</table>
{{- if .Pages}}
<table class="data">
<caption>Gateway pages in the capture</caption>
<thead><tr><th>Captured page</th><th>File time</th><th>SHA-256</th><th>In a time-stamped manifest</th></tr></thead>
<tbody>
{{- range .Pages}}
<tr><td class="path">{{.Path}}</td><td>{{template "t" .Time}}</td><td class="mono">{{.SHA256}}</td><td>{{.Listed}}</td></tr>
{{- end}}
</tbody>
</table>
{{- end}}
{{- if .Tokens}}
<table class="data">
<caption>RFC 3161 time-stamp tokens imported with the capture</caption>
<thead><tr><th>Token</th><th>Authority</th><th>genTime stated in the token</th><th>Covers (by SHA-256)</th></tr></thead>
<tbody>
{{- range .Tokens}}
<tr><td class="path">{{.Path}}</td><td>{{.TSA}}</td><td>{{template "t" .GenTime}}</td><td class="path">{{.Covers}}</td></tr>
{{- end}}
</tbody>
</table>
<p class="small muted">The tokens' genTime and covered hash are read from the tokens; this report does not check their signatures. Verify them with the OpenSSL commands below.</p>
{{- end}}
{{- if .Problems}}
<ul class="notes">{{range .Problems}}<li>{{.}}</li>{{end}}</ul>
{{- end}}
{{- end}}
{{- if .Facts}}
<h3>Records behind the key facts</h3>
<table class="data compact">
<thead><tr><th>Fact</th><th>Record(s)</th></tr></thead>
<tbody>
{{- range .Facts}}
<tr><td>{{template "t" .What}}</td><td>{{template "t" .Ref}}</td></tr>
{{- end}}
</tbody>
</table>
{{- end}}
<h3>How to verify</h3>
<p class="small muted">Each command is one line; it is wrapped here only between its arguments. README.txt in the evidence bundle describes the same checks.</p>
<ol class="verify">
{{- range .Verify}}
<li>{{.Text}}{{range .Cmds}}<span class="code">{{range $i, $a := .}}{{if $i}} {{end}}<span class="arg">{{$a}}</span>{{end}}</span>{{end}}</li>
{{- end}}
</ol>
{{- if .Notes}}
<h3>Data notes</h3>
<ul class="notes">{{range .Notes}}<li>{{.}}</li>{{end}}</ul>
{{- end}}
</section>
</main>
</body>
</html>
`
