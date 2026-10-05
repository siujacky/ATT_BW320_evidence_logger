package monitor

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/model"
)

func TestResolveSettingsDefaults(t *testing.T) {
	s := resolveSettings(&config.Config{})
	d := config.Default()
	if s.fast != 10*time.Second || s.probeTimeout != 2*time.Second || s.gwHost != "192.168.1.254" || s.gwScheme != "https" ||
		len(s.targets) != len(d.Probes.Targets) || !slices.Equal(s.pages, d.Gateway.Pages) || s.dnsName != "www.google.com" ||
		s.traceMaxHops != 15 || s.incident.WindowCycles != 6 || s.heartbeat != 15*time.Minute || s.anchorInterval != 30*time.Minute {
		t.Fatalf("defaults not applied: %+v", s)
	}
	c := testConfig()
	c.Probes.Timeout = config.D(time.Minute) // ≥ fast interval
	c.Gateway.Scheme = "http"
	s = resolveSettings(c)
	if s.probeTimeout != s.fast/2 || s.gwScheme != "http" {
		t.Fatalf("timeout %v scheme %s", s.probeTimeout, s.gwScheme)
	}
}

func TestProbeSpecsResolution(t *testing.T) {
	cfg := testConfig()
	cfg.Gateway.Scheme = "http"
	cfg.Probes.Targets = append(cfg.Probes.Targets,
		model.ProbeSpec{Name: "inet_missing", Kind: model.KindICMP, Role: model.RoleInet},                     // no target: skipped
		model.ProbeSpec{Name: "hop_tcp", Kind: model.KindTCP, Role: model.RoleISPHop},                         // TCP to the hop: skipped
		model.ProbeSpec{Name: "gw_custom", Kind: model.KindICMP, Role: model.RoleGateway, Target: "10.0.0.1"}) // explicit target kept
	r := newRig(t, cfg, nil)
	names := func() map[string]string {
		out := map[string]string{}
		for _, s := range r.m.probeSpecs() {
			out[s.Name] = s.Target
		}
		return out
	}
	got := names()
	if got["gateway_icmp"] != gwIP || got["gateway_tcp"] != gwIP+":80" || got["gw_custom"] != "10.0.0.1" || got["inet_icmp_quad9"] != "9.9.9.9" {
		t.Fatalf("specs %v", got)
	}
	for _, missing := range []string{"isp_hop_icmp", "inet_missing", "hop_tcp"} {
		if _, ok := got[missing]; ok {
			t.Fatalf("%s must be omitted: %v", missing, got)
		}
	}
	r.m.mu.Lock()
	r.m.st.ispHop = "203.0.113.1"
	r.m.mu.Unlock()
	if got := names(); got["isp_hop_icmp"] != "203.0.113.1" {
		t.Fatalf("isp hop %v", got)
	}
}

func TestRunProbesDeadlinePanicAndKinds(t *testing.T) {
	cfg := testConfig()
	cfg.Probes.Targets = []model.ProbeSpec{
		{Name: "slow", Kind: model.KindICMP, Role: model.RoleGateway, Target: "10.0.0.1"},
		{Name: "boom", Kind: model.KindTCP, Role: model.RoleInet, Target: "1.1.1.1:443"},
		{Name: "odd", Kind: "udp", Role: model.RoleInet, Target: "1.1.1.1"},
		{Name: "fine", Kind: model.KindICMP, Role: model.RoleInet, Target: "8.8.8.8"},
	}
	r := newRig(t, cfg, nil)
	r.m.probeGrace = 50 * time.Millisecond
	release := make(chan struct{})
	r.pr.ping = func(target string) model.ProbeResult {
		if target == "10.0.0.1" {
			<-release // ignores its timeout
		}
		return model.ProbeResult{OK: true, RTTus: 5000, Status: "IP_SUCCESS"}
	}
	r.pr.tcp = func(string) model.ProbeResult { panic("broken prober") }
	res := r.m.runProbes(context.Background(), r.m.probeSpecs())
	close(release)
	byName := map[string]model.ProbeResult{}
	for _, p := range res {
		byName[p.Name] = p
	}
	if p := byName["slow"]; p.OK || p.Err != "probe did not complete in time" || p.Role != model.RoleGateway || p.Target != "10.0.0.1" {
		t.Fatalf("slow %+v", p)
	}
	if p := byName["boom"]; p.OK || !strings.Contains(p.Err, "probe panicked: broken prober") || p.Kind != model.KindTCP {
		t.Fatalf("boom %+v", p)
	}
	if p := byName["odd"]; p.OK || p.Err != "unsupported probe kind udp" {
		t.Fatalf("odd %+v", p)
	}
	if p := byName["fine"]; !p.OK || p.RTTus != 5000 || p.Name != "fine" || p.Role != model.RoleInet {
		t.Fatalf("fine %+v", p)
	}
	if !slices.EqualFunc(res, cfg.Probes.Targets, func(r model.ProbeResult, s model.ProbeSpec) bool { return r.Name == s.Name }) {
		t.Fatal("results must keep configuration order")
	}
}

func TestIncidentUpdateThroughProcessCycle(t *testing.T) {
	r := newRig(t, nil, nil)
	m := r.m
	ctx := context.Background()
	start := time.Now().Add(-time.Minute)
	bad := cyc(gwICMP(true, 1900), gwTCP(true, 2300), inet(false, false, 0))
	for i := 0; i < 3; i++ {
		m.processCycle(ctx, start.Add(time.Duration(i)*time.Second), time.Millisecond, bad)
	}
	// The gateway now reports the WAN down: the headline cause becomes more specific.
	snap := downSnapshot(nil, start.Add(3*time.Second))
	m.mu.Lock()
	m.applySnapshotLocked(&snapObs{Seq: 1, At: start.Add(3 * time.Second), Snap: &snap}, nil, nil)
	m.mu.Unlock()
	m.processCycle(ctx, start.Add(4*time.Second), time.Millisecond, bad)
	recs := r.led.records("")
	ups := ofType(recs, model.TypeIncidentUpdate)
	if len(ups) != 1 {
		t.Fatalf("updates %d: %v", len(ups), r.led.types(""))
	}
	inc := decode[model.Incident](t, ups[0])
	if inc.Cause != model.CauseWANDown || !inc.Open || !slices.Contains(inc.Causes, model.CauseUpstreamUnreachable) {
		t.Fatalf("update %+v", inc)
	}
	if !inc.Stats.GatewayDownSeen || inc.Stats.GatewayFetches != 1 {
		t.Fatalf("snapshot stats %+v", inc.Stats)
	}
	// Status shows the live incident with its duration so far.
	st := m.Status()
	if st.ActiveIncident == nil || st.ActiveIncident.Cause != model.CauseWANDown || st.ActiveIncident.DurationSec < 50 {
		t.Fatalf("active %+v", st.ActiveIncident)
	}
	if st.Since != fmtTS(start) || st.Verdict.Cause != model.CauseWANDown {
		t.Fatalf("since %s verdict %+v", st.Since, st.Verdict)
	}
	// (Outage seconds count cycles, capped at 1.5 fast intervals each: with 1 s between these
	// 40 ms cycles almost all of the span is a monitoring gap. TestWindowStats covers them.)
	if day := st.Stats[0]; day.Window != "24h" || day.Incidents != 1 || day.AvailabilityPct != 0 {
		t.Fatalf("24h stats with the open provider outage: %+v", day)
	}
	// Close: the incident moves to the closing list until its record is written.
	good := cyc(gwICMP(true, 1900), gwTCP(true, 2300), inet(true, true, 9000))
	for i := 0; i < 9; i++ { // the loss window keeps the first cycles PACKET_LOSS
		m.processCycle(ctx, start.Add(time.Duration(5+i)*time.Second), time.Millisecond, good)
	}
	if got, ok := m.Incident(inc.ID); !ok || got.Open || got.Closed == "" {
		t.Fatalf("closing incident %+v %v", got, ok)
	}
	if !m.idTakenLocked(inc.ID) {
		t.Fatal("a closing incident's id is taken")
	}
	m.finishClosings(ctx)
	if n := len(ofType(r.led.records(""), model.TypeIncidentClose)); n != 1 {
		t.Fatalf("closes %d", n)
	}
}

// TestDeferredRebootRule: a LOCAL_FAULT incident whose close snapshot fails is revised by the
// next successful snapshot that shows the gateway rebooted inside the incident window.
func TestDeferredRebootRule(t *testing.T) {
	for _, fwChange := range []bool{false, true} {
		r := newRig(t, nil, nil)
		m := r.m
		ctx := context.Background()
		start := time.Now().Add(-time.Minute)
		// A good snapshot before the incident (old boot, firmware 6.34.7).
		pre := okSnapshot([]string{"sysinfo"}, start.Add(-time.Second))
		m.mu.Lock()
		m.applySnapshotLocked(&snapObs{Seq: 0, At: start.Add(-time.Second), Snap: &pre}, nil, nil)
		m.mu.Unlock()

		var gwUp atomic.Bool
		bootAt := start.Add(1500 * time.Millisecond)
		r.gw.snap = func(call int, pages []string, trigger string) (model.GatewaySnapshot, map[string][]byte, error) {
			if !gwUp.Load() {
				return model.GatewaySnapshot{}, nil, errors.New("dial tcp 192.168.1.254:443: connect: no route to host")
			}
			at := time.Now()
			s := okSnapshot(pages, at)
			s.System.UptimeSec = int64(at.Sub(bootAt) / time.Second)
			s.Derived.UptimeSec = s.System.UptimeSec
			s.Derived.BootTimeEstimate = fmtTS(bootAt)
			if fwChange {
				s.Derived.Firmware, s.System.SoftwareVersion = "6.35.1", "6.35.1"
			}
			return s, pageBodies(pages, "rebooted"), nil
		}
		lanDown := cyc(gwICMP(false, 0), gwTCP(false, 0), inet(false, false, 0))
		good := cyc(gwICMP(true, 1900), gwTCP(true, 2300), inet(true, true, 9000))
		for i := 0; i < 3; i++ {
			m.processCycle(ctx, start.Add(time.Duration(i)*time.Second), time.Millisecond, lanDown)
		}
		// Seven good cycles: the loss window (DESIGN §9) keeps the first four DEGRADED.
		for i := 0; i < 7; i++ {
			m.processCycle(ctx, start.Add(time.Duration(3+i)*time.Second), time.Millisecond, good)
		}
		m.mu.Lock()
		st := m.st.closing[0]
		m.mu.Unlock()
		m.finishClose(ctx, st, true) // close snapshot fails: decision deferred
		closes := ofType(r.led.records(""), model.TypeIncidentClose)
		if len(closes) != 1 {
			t.Fatal("incident_close missing")
		}
		closed := decode[model.Incident](t, closes[0])
		if closed.Cause != model.CauseGatewayUnreachable || closed.Attribution != model.AttrUndetermined {
			t.Fatalf("close record %s/%s", closed.Cause, closed.Attribution)
		}
		m.mu.Lock()
		watching := len(m.st.rebootWatch)
		m.mu.Unlock()
		if watching != 1 {
			t.Fatalf("reboot watch %d", watching)
		}
		// The gateway web interface is back: the next snapshot decides the rule.
		gwUp.Store(true)
		if m.takeSnapshot(ctx, trigPeriodic, nil) == nil {
			t.Fatal("snapshot not recorded")
		}
		ups := ofType(r.led.records(""), model.TypeIncidentUpdate)
		if len(ups) != 1 {
			t.Fatalf("updates %d", len(ups))
		}
		inc := decode[model.Incident](t, ups[0])
		wantAttr := model.AttrUndetermined
		if fwChange {
			wantAttr = model.AttrProvider
		}
		if inc.Cause != model.CauseGatewayReboot || inc.Open || inc.Closed != closed.Closed || inc.Attribution != wantAttr {
			t.Fatalf("fw change %v: update %+v", fwChange, inc)
		}
		if fwChange && !strings.Contains(strings.Join(inc.Reasons, " "), "AT&T-pushed firmware update") {
			t.Fatalf("reasons %q", inc.Reasons)
		}
		if got, _ := m.Incident(inc.ID); got.Cause != model.CauseGatewayReboot {
			t.Fatalf("view %+v", got)
		}
		m.mu.Lock()
		watching = len(m.st.rebootWatch)
		m.mu.Unlock()
		if watching != 0 {
			t.Fatal("decided incidents leave the watch list")
		}
		// The close procedure recorded the failed snapshot, traceroutes and the anchor.
		recs := r.led.records("")
		if a := ofType(recs, model.TypeAnchor); len(a) != 2 || decode[model.Anchor](t, a[0]).Reason != "incident_close" {
			t.Fatalf("anchors %d", len(a))
		}
		if len(ofType(recs, model.TypeTraceroute)) != 2 {
			t.Fatal("close traceroutes missing")
		}
		evKinds := map[string]bool{}
		for _, b := range ofType(recs, model.TypeGatewayEvent) {
			evKinds[decode[model.GatewayEvent](t, b).Kind] = true
		}
		if !evKinds[model.GwEvUnreachable] || !evKinds[model.GwEvReboot] {
			t.Fatalf("gateway events %v", evKinds)
		}
	}
}

func TestTakeSnapshotRawPolicy(t *testing.T) {
	cfg := testConfig()
	cfg.Gateway.LANStatsInterval = config.D(time.Hour)
	r := newRig(t, cfg, nil)
	m := r.m
	ctx := context.Background()
	var mode atomic.Int32 // 0 ok, 1 changed firmware, 2 bad hash, 3 error without pages
	r.gw.snap = func(call int, pages []string, trigger string) (model.GatewaySnapshot, map[string][]byte, error) {
		at := time.Now()
		s := okSnapshot(pages, at)
		s.Derived.BootTimeEstimate = fmtTS(t0) // stable boot: no reboot noise
		switch mode.Load() {
		case 1:
			s.Derived.Firmware = "6.35.1"
		case 2:
			s.Derived.Firmware = "6.35.1"
			s.Pages[0].SHA256 = strings.Repeat("0", 64)
		case 3:
			return model.GatewaySnapshot{}, nil, errors.New("connection refused")
		}
		return s, pageBodies(pages, "same"), nil
	}
	snapRec := func() (model.GatewaySnapshot, model.Body) {
		recs := ofType(r.led.records(""), model.TypeGatewaySnapshot)
		b := recs[len(recs)-1]
		return decode[model.GatewaySnapshot](t, b), b
	}
	storedPages := func(s model.GatewaySnapshot) []string {
		var p []string
		for _, c := range s.Pages {
			if c.Stored {
				p = append(p, c.Page)
			}
		}
		return p
	}

	m.takeSnapshot(ctx, trigStartup, nil)
	s, b := snapRec()
	if got := storedPages(s); !slices.Equal(got, []string{"broadbandstatistics", "fiberstat", "sysinfo", "lanstatistics"}) || len(b.Blobs) != 4 {
		t.Fatalf("first snapshot stores every page (incl. lanstatistics): %v blobs %v", got, b.Blobs)
	}
	m.takeSnapshot(ctx, trigPeriodic, nil)
	s, b = snapRec()
	if len(storedPages(s)) != 0 || len(b.Blobs) != 0 || len(s.Pages) != 3 {
		t.Fatalf("unchanged snapshot within the interval must not store pages: %v (pages %d)", storedPages(s), len(s.Pages))
	}
	for _, p := range s.Pages {
		if p.SHA256 == "" {
			t.Fatal("the hash of every fetched body is always recorded")
		}
	}
	mode.Store(1)
	m.takeSnapshot(ctx, trigPeriodic, nil)
	if s, _ = snapRec(); len(storedPages(s)) != 3 {
		t.Fatalf("material change stores pages: %v", storedPages(s))
	}
	mode.Store(2)
	m.takeSnapshot(ctx, trigIncident, &incState{inc: model.Incident{Stats: model.IncidentStats{ProbeOK: map[string]int{}, ProbeTotal: map[string]int{}}}})
	if s, _ = snapRec(); slices.Contains(storedPages(s), "broadbandstatistics") || len(storedPages(s)) != 2 {
		t.Fatalf("a page whose hash does not match its body is not stored: %v", storedPages(s))
	}
	mode.Store(3)
	m.takeSnapshot(ctx, trigPeriodic, nil)
	s, _ = snapRec()
	if s.Derived.Reachable || len(s.Pages) != 3 || s.Pages[0].Err != "connection refused" {
		t.Fatalf("failed snapshot %+v", s)
	}
	evs := ofType(r.led.records(""), model.TypeGatewayEvent)
	last := decode[model.GatewayEvent](t, evs[len(evs)-1])
	if last.Kind != model.GwEvUnreachable || last.After != "unreachable" {
		t.Fatalf("event %+v", last)
	}
	// Cancelled context: nothing is recorded.
	n := len(r.led.records(""))
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if m.takeSnapshot(cctx, trigPeriodic, nil) != nil || len(r.led.records("")) != n {
		t.Fatal("a cancelled snapshot must not be recorded")
	}
}

func TestLocalLinkRecording(t *testing.T) {
	r := newRig(t, nil, nil)
	m := r.m
	ctx := context.Background()
	link := model.LocalLink{Interface: "Wi-Fi", Type: "wifi", State: "connected", SSID: "home", BSSID: "aa:bb", SignalPct: 90, Channel: 149}
	var cur atomic.Value
	cur.Store(link)
	r.pr.link = func() (model.LocalLink, []byte, error) {
		return cur.Load().(model.LocalLink), []byte("raw netsh output"), nil
	}
	count := func() int { return len(ofType(r.led.records(""), model.TypeLocalLink)) }
	m.checkLocalLink(ctx, false)
	if count() != 1 {
		t.Fatal("first observation is recorded")
	}
	m.checkLocalLink(ctx, false)
	if count() != 1 {
		t.Fatal("unchanged link is not re-recorded")
	}
	l2 := link
	l2.SignalPct = 80
	cur.Store(l2)
	m.checkLocalLink(ctx, false)
	if count() != 1 {
		t.Fatal("signal change below 15 points is not recorded")
	}
	l2.SignalPct = 74
	cur.Store(l2)
	m.checkLocalLink(ctx, false)
	if count() != 2 {
		t.Fatal("signal change of 16 points is recorded")
	}
	m.checkLocalLink(ctx, true)
	if count() != 3 {
		t.Fatal("forced (incident open) is recorded")
	}
	l3 := l2
	l3.BSSID = "AA:BB" // same BSSID, different case
	cur.Store(l3)
	m.checkLocalLink(ctx, false)
	if count() != 3 {
		t.Fatal("BSSID comparison is case-insensitive")
	}
	r.pr.link = func() (model.LocalLink, []byte, error) { return model.LocalLink{}, nil, errors.New("netsh not found") }
	m.checkLocalLink(ctx, false)
	recs := ofType(r.led.records(""), model.TypeLocalLink)
	if len(recs) != 4 {
		t.Fatal("a failing reading is a change")
	}
	if l := decode[model.LocalLink](t, recs[3]); l.Type != "unknown" || l.Err != "netsh not found" || l.RawSHA256 != "" || len(recs[3].Blobs) != 0 {
		t.Fatalf("failed reading %+v", l)
	}
	if st := m.Status(); st.LocalLink == nil || st.LocalLink.Err == "" {
		t.Fatal("status shows the latest reading")
	}

	// Change detection table.
	base := model.LocalLink{Type: "wifi", State: "connected", SSID: "a", BSSID: "b", Channel: 1, SignalPct: 50, Interface: "Wi-Fi"}
	muts := []func(*model.LocalLink){
		func(l *model.LocalLink) { l.Type = "ethernet" },
		func(l *model.LocalLink) { l.State = "disconnected" },
		func(l *model.LocalLink) { l.SSID = "x" },
		func(l *model.LocalLink) { l.BSSID = "x" },
		func(l *model.LocalLink) { l.Channel = 2 },
		func(l *model.LocalLink) { l.Interface = "Wi-Fi 2" },
		func(l *model.LocalLink) { l.SignalPct = 35 },
		func(l *model.LocalLink) { l.SignalPct = 65 },
	}
	for i, mut := range muts {
		b := base
		mut(&b)
		if !linkChanged(&base, &b) {
			t.Errorf("mutation %d not detected", i)
		}
	}
	b := base
	b.SignalPct, b.RxMbps = 64, 866
	if linkChanged(&base, &b) {
		t.Error("14-point signal change and rates are not changes")
	}
}

func TestServiceCheckHijackAndStats(t *testing.T) {
	r := newRig(t, nil, nil)
	m := r.m
	ctx := context.Background()
	r.pr.dns = func(server, name string) model.DNSResult {
		if server == gwIP {
			return model.DNSResult{OK: true, RCode: "NOERROR", Answers: []string{gwIP}} // walled garden answer
		}
		return model.DNSResult{OK: true, RCode: "NOERROR", Answers: []string{"142.250.72.36"}}
	}
	r.pr.http = func(name, url string) model.HTTPResult {
		return model.HTTPResult{Status: 302, Location: "http://192.168.1.254/cgi-bin/redirect.ha", RemoteAddr: "23.200.0.1:80"}
	}
	m.mu.Lock()
	m.st.ispDNS = "68.94.156.9"
	m.mu.Unlock()
	// An open incident collects the hijack flags.
	bad := cyc(gwICMP(true, 1900), inet(false, false, 0))
	for i := 0; i < 3; i++ {
		m.processCycle(ctx, time.Now().Add(time.Duration(i)*time.Second), time.Millisecond, bad)
	}
	m.runServiceCheck(ctx)
	recs := ofType(r.led.records(""), model.TypeServiceCheck)
	if len(recs) != 1 {
		t.Fatal("service check not recorded")
	}
	sc := decode[model.ServiceCheck](t, recs[0])
	roles := map[string]int{}
	var invalid model.DNSResult
	for _, d := range sc.DNS {
		roles[d.ServerRole]++
		if isInvalidName(d.Name) {
			invalid = d
		}
	}
	if roles["gateway"] != 2 || roles["isp"] != 1 || roles["public"] != 1 || len(sc.HTTP) != 2 {
		t.Fatalf("checks %v http %d", roles, len(sc.HTTP))
	}
	if !invalid.Hijacked || !strings.Contains(invalid.HijackWhy, "non-existent name") || len(strings.TrimSuffix(invalid.Name, ".invalid")) != 16 {
		t.Fatalf("wildcard detector %+v", invalid)
	}
	if !sc.DNS[0].Hijacked || sc.DNS[0].Server != gwIP || sc.DNS[0].Name != "www.google.com" || sc.DNS[0].QType != "A" {
		t.Fatalf("gateway answer %+v", sc.DNS[0])
	}
	if !sc.HTTP[0].Hijacked || sc.HTTP[0].Name != "msft_connecttest" || sc.HTTP[0].URL == "" {
		t.Fatalf("http %+v", sc.HTTP[0])
	}
	st := m.Status()
	if st.ActiveIncident == nil || !st.ActiveIncident.Stats.DNSHijackSeen || !st.ActiveIncident.Stats.HTTPHijackSeen || st.LastService == nil {
		t.Fatalf("status %+v", st.ActiveIncident)
	}
	var note string
	for _, e := range st.ActiveIncident.Evidence {
		if e.Type == model.TypeServiceCheck {
			note = e.Note
		}
	}
	if !strings.HasPrefix(note, "failed: dns gateway, dns gateway, http msft_connecttest") {
		t.Fatalf("evidence note %q", note)
	}
}

func TestClockCheck(t *testing.T) {
	r := newRig(t, nil, nil)
	m := r.m
	r.pr.sntp = func(server string) model.ClockResult {
		if server == "pool.ntp.org" {
			return model.ClockResult{Err: "timeout"}
		}
		return model.ClockResult{OK: true, OffsetMs: 12}
	}
	at := time.Now()
	s := okSnapshot(nil, at)
	s.Derived.GatewayClockOffsetMs = i64p(-1500)
	m.mu.Lock()
	m.applySnapshotLocked(&snapObs{Seq: 1, At: at, Snap: &s}, nil, nil)
	m.mu.Unlock()
	m.clockCheck(context.Background())
	recs := ofType(r.led.records(""), model.TypeClockCheck)
	if len(recs) != 1 {
		t.Fatal("clock check not recorded")
	}
	cc := decode[model.ClockCheck](t, recs[0])
	if len(cc.Results) != 3 || cc.Results[2].Server != "pool.ntp.org" || cc.Results[2].OK || cc.Results[0].Server != "time.windows.com" ||
		cc.GatewayOffsetMs == nil || *cc.GatewayOffsetMs != -1500 {
		t.Fatalf("clock check %+v", cc)
	}
	if st := m.Status(); st.Clock == nil {
		t.Fatal("status clock")
	}
	// Nothing to measure: nothing recorded.
	cfg := testConfig()
	cfg.Clock.NTPServers = nil
	r2 := newRig(t, cfg, nil)
	r2.m.clockCheck(context.Background())
	if n := len(ofType(r2.led.records(""), model.TypeClockCheck)); n != 0 {
		t.Fatalf("records %d", n)
	}
}

func TestPeriodicAnchoringDeferredWhileOffline(t *testing.T) {
	cfg := testConfig()
	cfg.Anchoring.Interval = config.D(120 * time.Millisecond)
	r := newRig(t, cfg, nil)
	m := r.m
	m.mu.Lock()
	m.st.lastVerdict = model.Verdict{State: model.StateISPOutage}
	m.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.anchorLoop(ctx); close(done) }()
	reasons := func() []string {
		var out []string
		for _, b := range ofType(r.led.records(""), model.TypeAnchor) {
			out = append(out, decode[model.Anchor](t, b).Reason)
		}
		return out
	}
	waitFor(t, "startup anchor", 5*time.Second, func() bool { return len(reasons()) == 2 })
	time.Sleep(400 * time.Millisecond)
	if got := reasons(); slices.Contains(got, "periodic") {
		t.Fatalf("periodic anchoring must wait while offline: %v", got)
	}
	m.mu.Lock()
	m.st.lastVerdict = model.Verdict{State: model.StateOnline}
	m.mu.Unlock()
	waitFor(t, "periodic anchor once online", 5*time.Second, func() bool { return slices.Contains(reasons(), "periodic") })
	cancel()
	<-done
	if got := reasons(); got[0] != "startup" {
		t.Fatalf("reasons %v", got)
	}
}

func TestPeriodicTraceroutes(t *testing.T) {
	cfg := testConfig()
	cfg.Probes.TracerouteInterval = config.D(100 * time.Millisecond)
	r := newRig(t, cfg, nil)
	m := r.m
	bad := cyc(gwICMP(true, 1900), inet(false, false, 0))
	for i := 0; i < 3; i++ {
		m.processCycle(context.Background(), time.Now().Add(time.Duration(i)*time.Second), time.Millisecond, bad)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.tracerouteLoop(ctx); close(done) }()
	triggers := func() map[string]int {
		out := map[string]int{}
		for _, b := range ofType(r.led.records(""), model.TypeTraceroute) {
			out[decode[model.Traceroute](t, b).Trigger]++
		}
		return out
	}
	waitFor(t, "open and periodic traceroutes", 5*time.Second, func() bool {
		tr := triggers()
		return tr["incident_open"] == 2 && tr["incident_periodic"] >= 2
	})
	cancel()
	<-done
	st := m.Status()
	n := 0
	for _, e := range st.ActiveIncident.Evidence {
		if e.Type == model.TypeTraceroute {
			n++
		}
	}
	if n < 4 {
		t.Fatalf("traceroute evidence %d", n)
	}
}

func TestSeriesAndIncidentViews(t *testing.T) {
	r := newRig(t, nil, nil)
	m := r.m
	ctx := context.Background()
	now := time.Now()
	good := healthy()
	for i := 0; i < 5; i++ {
		m.processCycle(ctx, now.Add(time.Duration(i-10)*time.Second), time.Millisecond, good)
	}
	s, err := m.Series("1h")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Probes) != 8 || s.StepSec != 10 {
		t.Fatalf("probes %d step %d", len(s.Probes), s.StepSec)
	}
	var withData int
	for _, p := range s.Points {
		if p.State != "" {
			withData++
			if p.State != model.StateOnline || p.RTTms["gateway_icmp"] != 1.9 {
				t.Fatalf("point %+v", p)
			}
		}
	}
	if withData == 0 {
		t.Fatal("no data points")
	}
	if _, err := m.Series("bogus"); err == nil {
		t.Fatal("bad range")
	}

	m.mu.Lock()
	for _, inc := range []model.Incident{
		{ID: "A", Opened: fmtTS(t0), Closed: fmtTS(t0.Add(time.Hour))},
		{ID: "B", Opened: fmtTS(t0.Add(2 * time.Hour)), Closed: fmtTS(t0.Add(3 * time.Hour))},
		{ID: "C", Opened: fmtTS(t0.Add(5 * time.Hour)), Open: true},
		{ID: "D", Opened: "garbage"},
	} {
		m.st.incidents[inc.ID] = inc
	}
	m.mu.Unlock()
	ids := func(from, to time.Time) []string {
		var out []string
		for _, inc := range m.Incidents(from, to) {
			out = append(out, inc.ID)
		}
		return out
	}
	tests := []struct {
		from, to time.Time
		want     []string
	}{
		{time.Time{}, time.Time{}, []string{"C", "B", "A"}},
		{t0.Add(90 * time.Minute), time.Time{}, []string{"C", "B"}},
		{t0.Add(time.Hour), t0.Add(2 * time.Hour), nil}, // A ends at from, B starts at to
		{t0.Add(30 * time.Minute), t0.Add(150 * time.Minute), []string{"B", "A"}},
		{t0.Add(10 * time.Hour), t0.Add(11 * time.Hour), []string{"C"}}, // open incidents extend to now
	}
	for i, tc := range tests {
		if got := ids(tc.from, tc.to); !slices.Equal(got, tc.want) {
			t.Errorf("case %d: %v want %v", i, got, tc.want)
		}
	}
	if _, ok := m.Incident("nope"); ok {
		t.Fatal("unknown incident")
	}
	got := m.Incidents(time.Time{}, time.Time{})
	got[0].Causes = append(got[0].Causes, "MUTATED")
	if again, _ := m.Incident(got[0].ID); slices.Contains(again.Causes, "MUTATED") {
		t.Fatal("views must be copies")
	}
}

// TestConcurrentPublicMethods exercises every exported method while Run is busy (run with
// -race to check the locking).
func TestConcurrentPublicMethods(t *testing.T) {
	r := newRig(t, nil, nil)
	var down atomic.Bool
	r.pr.ping = func(target string) model.ProbeResult {
		if down.Load() && target != gwIP {
			return model.ProbeResult{Status: "IP_REQ_TIMED_OUT"}
		}
		return model.ProbeResult{OK: true, RTTus: 1500, Status: "IP_SUCCESS"}
	}
	stop := r.start(t)
	ctx := context.Background()
	deadline := time.Now().Add(600 * time.Millisecond)
	errs := make(chan error, 16)
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Go(func() {
			for i := 0; time.Now().Before(deadline); i++ {
				_ = r.m.Status()
				if _, err := r.m.Series([]string{"1h", "6h", "24h", "7d"}[i%4]); err != nil {
					errs <- err
					return
				}
				for _, inc := range r.m.Incidents(time.Time{}, time.Time{}) {
					r.m.Incident(inc.ID)
				}
				switch i % 25 {
				case 0:
					if _, err := r.m.Note(ctx, "note", "tester", "test"); err != nil {
						errs <- err
						return
					}
				case 5:
					r.m.PowerEvent("power_status_change")
				case 10:
					_, _ = r.m.AnchorNow(ctx, "manual")
				case 15:
					_, _ = r.m.SetGatewayNotification(ctx, false, "test")
				case 20:
					down.Store(!down.Load())
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
	wg.Wait()
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

// TestFirstBadCycleKicksGatewayAndLink: the first bad cycle asks for an immediate gateway
// snapshot and local-link reading (DESIGN §8); opening the incident asks for the incident
// snapshot, service check, forced link record and traceroutes (§10).
func TestFirstBadCycleKicksGatewayAndLink(t *testing.T) {
	r := newRig(t, nil, nil)
	m := r.m
	ctx := context.Background()
	start := time.Now()
	m.processCycle(ctx, start, time.Millisecond, healthy())
	m.kGateway.take()
	m.kLink.take()
	bad := cyc(gwICMP(true, 1900), inet(false, false, 0))
	m.processCycle(ctx, start.Add(time.Second), time.Millisecond, bad)
	if g, l := m.kGateway.take(), m.kLink.take(); !slices.Equal(g, []string{"cycle_failure"}) || !slices.Equal(l, []string{"cycle_failure"}) {
		t.Fatalf("first bad cycle kicks: gateway %v link %v", g, l)
	}
	m.processCycle(ctx, start.Add(2*time.Second), time.Millisecond, bad)
	if g := m.kGateway.take(); len(g) != 0 {
		t.Fatalf("only the first bad cycle of a streak kicks: %v", g)
	}
	m.processCycle(ctx, start.Add(3*time.Second), time.Millisecond, bad) // opens the incident
	if g, s, l := m.kGateway.take(), m.kService.take(), m.kLink.take(); !slices.Equal(g, []string{"incident"}) || !slices.Equal(s, []string{"incident"}) || !slices.Equal(l, []string{"incident"}) {
		t.Fatalf("incident open kicks: gateway %v service %v link %v", g, s, l)
	}
	select {
	case req := <-m.traceReqs:
		if req.trigger != "incident_open" || !strings.HasPrefix(req.incident, "INC-") {
			t.Fatalf("traceroute request %+v", req)
		}
	default:
		t.Fatal("no traceroute requested at incident open")
	}
}
