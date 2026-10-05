package ticket

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// Scan bounds.
const (
	// startScanRecords: the genesis and bootstrap_import records (and the anchors right after
	// them) are among the first records of a ledger (the monitor imports the bootstrap folder
	// only while the ledger is that new).
	startScanRecords = 500
	// afterScanRecords bounds the search for anchors written after the window.
	afterScanRecords = 200_000
	maxNotes         = 20
)

// collector gathers the records the report is computed from.
type collector struct {
	ctx      context.Context
	r        contracts.LedgerReader
	from, to time.Time
	loc      *time.Location
	scanned  int

	notes        []string
	notesDropped int

	genesis      *genesisRec
	bootstrap    *bootstrapRec
	startAnchors []anchorRec

	// window
	records  int
	firstSeq uint64
	lastSeq  uint64
	seqs     []uint64
	samples  []*sampleRec
	snaps    []*snapRec
	events   []eventRec
	incs     map[string]*incRec
	links    []linkRec
	anchors  []anchorRec // in the window and after it
	configs  []configRec
	marks    []markRec
}

type genesisRec struct {
	seq uint64
	ts  time.Time
	g   model.Genesis
}

type bootstrapRec struct {
	seq uint64
	ts  time.Time
	b   model.BootstrapImport
}

type sampleRec struct {
	seq      uint64
	run      string
	start    time.Time // the cycle's start (Sample.Started; the record time when absent)
	rec      time.Time // the record time
	state    string
	attr     string
	incident string
	gwICMP   int8  // -1: no gateway ICMP probe, 0: failed, 1: answered
	gwRTT    int64 // µs, when answered
	lan      int8  // -1: no gateway probe, 0: the gateway did not answer, 1: it answered
	cover    time.Duration
	end      time.Time
}

type snapRec struct {
	seq     uint64
	rec     time.Time
	fiberAt time.Time
	sysAt   time.Time
	d       model.GatewayDerived
	sys     *model.SystemInfo
	bb      *model.BroadbandStatus
	fiber   *model.FiberStatus
}

type eventRec struct {
	seq uint64
	ts  time.Time
	e   model.GatewayEvent
}

type incRec struct {
	seq uint64
	ts  time.Time
	typ string
	inc model.Incident
}

type linkRec struct {
	seq uint64
	ts  time.Time
	l   model.LocalLink
}

type anchorRec struct {
	seq   uint64
	ts    time.Time
	a     model.Anchor
	after bool // written after the window
}

func (a anchorRec) trusted() bool { return a.a.Verified && a.a.ChainOK }

type configRec struct {
	seq       uint64
	ts        time.Time
	run       string
	fast      time.Duration
	latencyOK float64
}

type markRec struct {
	seq  uint64
	ts   time.Time
	typ  string
	run  string
	text string
}

func newCollector(ctx context.Context, r contracts.LedgerReader, from, to time.Time, loc *time.Location) *collector {
	return &collector{ctx: ctx, r: r, from: from, to: to, loc: loc, incs: map[string]*incRec{}}
}

// note records a data caveat (bounded).
func (c *collector) note(s string) {
	if len(c.notes) >= maxNotes {
		c.notesDropped++
		return
	}
	c.notes = append(c.notes, s)
}

// decode unmarshals a record's data, noting records that cannot be decoded.
func (c *collector) decode(b model.Body, v any) bool {
	if err := json.Unmarshal(b.Data, v); err != nil {
		c.note(fmt.Sprintf("Record %s (%s) could not be decoded and is not used: %s", seqRef(b.Seq), b.Type, truncate(err.Error(), 160)))
		return false
	}
	return true
}

// tick checks for cancellation every few thousand records.
func (c *collector) tick() error {
	c.scanned++
	if c.scanned%2048 == 0 {
		return c.ctx.Err()
	}
	return nil
}

func recTime(b model.Body) (time.Time, bool) { return parseTS(b.TS) }

// scanStart reads the first records of the ledger: genesis, bootstrap_import and the anchors
// written right after them.
func (c *collector) scanStart() error {
	n := 0
	err := c.r.Scan(0, func(_ model.Envelope, b model.Body) error {
		if err := c.tick(); err != nil {
			return err
		}
		n++
		ts, _ := recTime(b)
		switch b.Type {
		case model.TypeGenesis:
			if c.genesis == nil {
				var g model.Genesis
				if c.decode(b, &g) {
					c.genesis = &genesisRec{seq: b.Seq, ts: ts, g: g}
				}
			}
		case model.TypeBootstrapImport:
			if c.bootstrap == nil {
				var bi model.BootstrapImport
				if c.decode(b, &bi) {
					c.bootstrap = &bootstrapRec{seq: b.Seq, ts: ts, b: bi}
				}
			}
		case model.TypeAnchor:
			var a model.Anchor
			if c.decode(b, &a) {
				c.startAnchors = append(c.startAnchors, anchorRec{seq: b.Seq, ts: ts, a: a})
			}
		}
		if n >= startScanRecords {
			return contracts.ErrStop
		}
		return nil
	})
	if err != nil && !errors.Is(err, contracts.ErrStop) {
		return fmt.Errorf("ticket: reading the first ledger records: %w", err)
	}
	return nil
}

// scanWindow reads every record whose ts lies in the window.
func (c *collector) scanWindow() error {
	err := c.r.ScanTime(c.from, c.to, func(_ model.Envelope, b model.Body) error {
		if err := c.tick(); err != nil {
			return err
		}
		ts, ok := recTime(b)
		if !ok {
			c.note(fmt.Sprintf("Record %s (%s) has an unreadable time %q and is not used.", seqRef(b.Seq), b.Type, truncate(b.TS, 40)))
			return nil
		}
		if c.records == 0 || b.Seq < c.firstSeq {
			c.firstSeq = b.Seq
		}
		if c.records == 0 || b.Seq > c.lastSeq {
			c.lastSeq = b.Seq
		}
		c.records++
		c.seqs = append(c.seqs, b.Seq)
		c.windowRecord(b, ts)
		return nil
	})
	if err != nil && !errors.Is(err, contracts.ErrStop) {
		return fmt.Errorf("ticket: reading the records of the window: %w", err)
	}
	return nil
}

// scanAfter looks for anchors written after the window that time-stamp its records: it stops
// at the first trusted anchor covering the window's last record.
func (c *collector) scanAfter() error {
	if c.records == 0 {
		return nil
	}
	n := 0
	err := c.r.Scan(c.lastSeq+1, func(_ model.Envelope, b model.Body) error {
		if err := c.tick(); err != nil {
			return err
		}
		n++
		if b.Type == model.TypeAnchor {
			var a model.Anchor
			if c.decode(b, &a) {
				ts, _ := recTime(b)
				ar := anchorRec{seq: b.Seq, ts: ts, a: a, after: true}
				c.anchors = append(c.anchors, ar)
				if ar.trusted() && a.HeadSeq >= c.lastSeq {
					return contracts.ErrStop
				}
			}
		}
		if n >= afterScanRecords {
			return contracts.ErrStop
		}
		return nil
	})
	if err != nil && !errors.Is(err, contracts.ErrStop) {
		return fmt.Errorf("ticket: reading the records after the window: %w", err)
	}
	return nil
}

// windowRecord keeps what the report needs from one record of the window.
func (c *collector) windowRecord(b model.Body, ts time.Time) {
	switch b.Type {
	case model.TypeSample:
		var s model.Sample
		if c.decode(b, &s) {
			c.samples = append(c.samples, newSampleRec(b, ts, &s))
		}
	case model.TypeGatewaySnapshot:
		var s model.GatewaySnapshot
		if c.decode(b, &s) {
			c.snaps = append(c.snaps, newSnapRec(b, ts, &s))
		}
	case model.TypeGatewayEvent:
		var e model.GatewayEvent
		if c.decode(b, &e) {
			c.events = append(c.events, eventRec{seq: b.Seq, ts: ts, e: e})
		}
	case model.TypeIncidentOpen, model.TypeIncidentUpdate, model.TypeIncidentClose:
		var inc model.Incident
		if c.decode(b, &inc) {
			id := inc.ID
			if id == "" {
				c.note(fmt.Sprintf("Record %s (%s) names no incident id and is not used.", seqRef(b.Seq), b.Type))
				return
			}
			if prev := c.incs[id]; prev == nil || b.Seq > prev.seq {
				c.incs[id] = &incRec{seq: b.Seq, ts: ts, typ: b.Type, inc: inc}
			}
		}
	case model.TypeLocalLink:
		var l model.LocalLink
		if c.decode(b, &l) {
			c.links = append(c.links, linkRec{seq: b.Seq, ts: ts, l: l})
		}
	case model.TypeAnchor:
		var a model.Anchor
		if c.decode(b, &a) {
			c.anchors = append(c.anchors, anchorRec{seq: b.Seq, ts: ts, a: a})
		}
	case model.TypeMonitorStart:
		var m model.MonitorStart
		if c.decode(b, &m) {
			c.addConfig(b, ts, m.Config)
			text := "monitor started"
			if m.Mode != "" {
				text += " (" + m.Mode + " mode)"
			}
			c.marks = append(c.marks, markRec{seq: b.Seq, ts: ts, typ: b.Type, run: b.Run, text: text})
		}
	case model.TypeConfigState:
		var cs model.ConfigState
		if c.decode(b, &cs) {
			c.addConfig(b, ts, cs.Config)
		}
	case model.TypeMonitorStop:
		var m model.MonitorStop
		if c.decode(b, &m) {
			text := "monitor stopped"
			if r := strings.TrimSpace(m.Reason); r != "" {
				text += " (" + r + ")"
			}
			c.marks = append(c.marks, markRec{seq: b.Seq, ts: ts, typ: b.Type, run: b.Run, text: text})
		}
	case model.TypePowerEvent:
		var p model.PowerEvent
		if c.decode(b, &p) {
			text := "power event " + p.Kind
			switch p.Kind {
			case "suspend":
				text = "this computer went to sleep"
			case "resume", "resume_automatic":
				text = "this computer woke up"
			case "shutdown":
				text = "this computer shut down"
			}
			c.marks = append(c.marks, markRec{seq: b.Seq, ts: ts, typ: b.Type, run: b.Run, text: text})
		}
	}
}

func newSampleRec(b model.Body, ts time.Time, s *model.Sample) *sampleRec {
	x := &sampleRec{seq: b.Seq, run: b.Run, rec: ts, start: ts, state: s.Verdict.State, attr: s.Verdict.Attribution,
		incident: s.IncidentID, gwICMP: -1, lan: -1}
	if st, ok := parseTS(s.Started); ok && !st.After(ts) && ts.Sub(st) < time.Hour {
		x.start = st
	}
	for _, p := range s.Probes {
		if p.Role != model.RoleGateway {
			continue
		}
		answered := p.OK || (p.Kind == model.KindTCP && p.Status == "refused")
		if x.lan < 1 {
			x.lan = 0
			if answered {
				x.lan = 1
			}
		}
		if p.Kind == model.KindICMP && x.gwICMP == -1 {
			x.gwICMP = 0
			if p.OK {
				x.gwICMP = 1
				x.gwRTT = p.RTTus
			}
		}
	}
	return x
}

func newSnapRec(b model.Body, ts time.Time, s *model.GatewaySnapshot) *snapRec {
	x := &snapRec{seq: b.Seq, rec: ts, d: s.Derived, sys: s.System, bb: s.Broadband, fiber: s.Fiber}
	for _, p := range s.Pages {
		t, ok := parseTS(p.FetchedAt)
		if !ok {
			continue
		}
		switch p.Page {
		case "fiberstat":
			x.fiberAt = t
		case "sysinfo":
			x.sysAt = t
		}
	}
	// The complete label/value maps stay in the records; the report needs the named fields.
	if x.bb != nil {
		bb := *x.bb
		bb.Values, bb.Counters = nil, nil
		x.bb = &bb
	}
	if x.fiber != nil {
		f := *x.fiber
		f.Values = nil
		x.fiber = &f
	}
	return x
}

// fiberTime is the time of the snapshot's fiberstat reading (the page fetch, else the record).
func (s *snapRec) fiberTime() time.Time {
	if !s.fiberAt.IsZero() {
		return s.fiberAt
	}
	return s.rec
}

// sysTime is the time of the snapshot's sysinfo reading.
func (s *snapRec) sysTime() time.Time {
	if !s.sysAt.IsZero() {
		return s.sysAt
	}
	return s.rec
}

// cfgLite is the part of the monitor configuration the report uses.
type cfgLite struct {
	Probes struct {
		FastInterval jsonDuration `json:"fast_interval"`
	} `json:"probes"`
	Incident struct {
		GatewayLatencyOkMs float64 `json:"gateway_latency_ok_ms"`
	} `json:"incident"`
}

// jsonDuration reads a Go duration string ("10s") or nanoseconds.
type jsonDuration time.Duration

func (d *jsonDuration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		var n int64
		if err2 := json.Unmarshal(b, &n); err2 != nil {
			return err
		}
		*d = jsonDuration(n)
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = jsonDuration(v)
	return nil
}

func (c *collector) addConfig(b model.Body, ts time.Time, raw json.RawMessage) {
	if len(raw) == 0 {
		return
	}
	var cfg cfgLite
	if err := json.Unmarshal(raw, &cfg); err != nil {
		c.note(fmt.Sprintf("The configuration in record %s (%s) could not be read: %s", seqRef(b.Seq), b.Type, truncate(err.Error(), 120)))
		return
	}
	fast := time.Duration(cfg.Probes.FastInterval)
	if fast < time.Second || fast > 10*time.Minute {
		fast = 0
	}
	c.configs = append(c.configs, configRec{seq: b.Seq, ts: ts, run: b.Run, fast: fast, latencyOK: cfg.Incident.GatewayLatencyOkMs})
}
