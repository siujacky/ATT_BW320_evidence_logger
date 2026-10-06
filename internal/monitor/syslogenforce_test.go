package monitor

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// The gateway's Syslog page kept sending to this computer (docs/syslog-snmp-traffic.md phase 2):
// enforcement in the settings check, the operator's choice, and the conditions.

// enforceRig is a rig with the gateway access code stored, this computer at 192.168.1.71 toward
// the gateway (ip: a test may change it) and the gateway's Syslog page simulated as the owner's
// real page, Syslog off. Enforcement is on (the default).
func enforceRig(t *testing.T) (*rig, *syslogSim, *atomic.Value) {
	t.Helper()
	r := newRig(t, nil, nil)
	r.cfg.Gateway.AccessCodeProtected = "protected-blob"
	ip := &atomic.Value{}
	ip.Store("192.168.1.71")
	linkAt(r, ip)
	r.m.checkLocalLink(context.Background(), false)
	return r, newSyslogSim(r.gw, realSyslogOff(), realSyslogPage(t)), ip
}

// targetAt is the target for this computer at ip with the given level, on port 514.
func targetAt(ip, level string) model.SyslogTarget {
	return model.SyslogTarget{Enabled: true, Server: ip, Port: 514, Level: level}
}

// recordsFrom returns the records from seq on.
func recordsFrom(r *rig, seq uint64) []model.Body {
	var out []model.Body
	for _, b := range r.led.records("") {
		if b.Seq >= seq {
			out = append(out, b)
		}
	}
	return out
}

// nextSeq is the seq of the next record.
func nextSeq(r *rig) uint64 { return r.led.Head().Seq + 1 }

func bodyTypes(bodies []model.Body) []string {
	var out []string
	for _, b := range bodies {
		out = append(out, b.Type)
	}
	return out
}

func mustContain(t *testing.T, what, text string, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if !strings.Contains(text, p) {
			t.Fatalf("%s does not say %q:\n%s", what, p, text)
		}
	}
}

// ---------------------------------------------------------------------------- the settings check

// With gateway.enforce_syslog (the default) the settings check sets the owner's real page -
// Syslog off, levels Emergency..Notice - to send to this computer at Notice, the most detailed
// level it offers below Debug. It records the read, then the change (gateway_event with both
// pages) and the config_change, and the status follows. The next check finds the setting the
// monitor keeps and changes nothing; a restart finds the setting in the ledger.
func TestSyslogEnforcedOnTheRealPage(t *testing.T) {
	ctx := context.Background()
	r, sim, _ := enforceRig(t)
	from := nextSeq(r)
	if err := r.m.checkNotification(ctx); err != nil {
		t.Fatal(err)
	}
	want := targetAt("192.168.1.71", "Notice")
	if sets, _ := r.gw.syslogSets(); len(sets) != 1 || sets[0] != want {
		t.Fatalf("SetSyslog calls %+v, want one with %+v", sets, want)
	}
	recs := recordsFrom(r, from)
	if got := bodyTypes(recs); !slices.Equal(got, []string{model.TypeGatewayEvent, model.TypeGatewayEvent, model.TypeGatewayEvent, model.TypeConfigChange}) {
		t.Fatalf("records %v: the notification read, the Syslog read, the change, the config_change", got)
	}
	if k := decode[model.GatewayEvent](t, recs[0]).Kind; k != model.GwEvNotificationSetting {
		t.Fatalf("the notification setting is read first: %s", k)
	}
	realPage := sha256Hex(realSyslogPage(t))
	read := decode[model.GatewayEvent](t, recs[1])
	if read.Kind != model.GwEvSyslogSetting || read.Before != "" || read.After != "off" || !slices.Equal(recs[1].Blobs, []string{realPage}) {
		t.Fatalf("read %+v blobs %v", read, recs[1].Blobs)
	}
	mustContain(t, "the read", read.Detail, "the gateway does not send its log to a syslog server",
		"log levels offered: Emergency, Alert, Critical, Error, Warning, Notice",
		"the monitor (gateway.enforce_syslog) sets it now to send its log to 192.168.1.71:514 at level Notice")

	const after = "on -> 192.168.1.71:514, level Notice"
	change := decode[model.GatewayEvent](t, recs[2])
	if change.Kind != model.GwEvSyslogSetting || change.Before != "off" || change.After != after {
		t.Fatalf("change %+v", change)
	}
	mustContain(t, "the change", change.Detail,
		"Syslog page (Diagnostics > Syslog) set by the monitor (gateway.enforce_syslog): Syslog off -> on; Server IP Address (empty) -> 192.168.1.71; Log Level Error -> Notice. ",
		"Read back after saving, the gateway sends its log to 192.168.1.71:514 at level Notice, which is this computer and the port its syslog receiver is set up for",
		"level Notice: the most detailed level the page offers, Debug aside",
		"The pages before and after the change are kept with this record.")
	if len(recs[2].Blobs) != 2 || recs[2].Blobs[0] != realPage || recs[2].Blobs[1] == realPage {
		t.Fatalf("the change's pages %v", recs[2].Blobs)
	}
	for _, b := range recs[2].Blobs {
		if !r.led.HasBlob(b) {
			t.Fatalf("page %s not stored", b)
		}
	}
	cc := decode[model.ConfigChange](t, recs[3])
	if wantCC := (model.ConfigChange{Target: "gateway", What: syslogWhat, Before: "off", After: after, Actor: "monitor (enforce_syslog)", Result: "verified"}); cc != wantCC {
		t.Fatalf("config_change %+v, want %+v", cc, wantCC)
	}
	if !slices.Equal(recs[3].Blobs, recs[2].Blobs) {
		t.Fatalf("the config_change's pages %v", recs[3].Blobs)
	}
	if got, posts := sim.current(); !got.Enabled || got.Server != "192.168.1.71" || got.Port != 514 || got.Level != "Notice" || posts != 1 {
		t.Fatalf("the gateway's page %+v (%d posts)", got, posts)
	}

	st := r.m.Status()
	s := st.Syslog
	if s == nil || s.State != syslogStateOK || s.Problem != "" || !s.Enforce || s.Target == nil || *s.Target != want ||
		s.GatewaySeq != recs[2].Seq || s.GatewayAt != recs[2].TS || s.Gateway == nil || !s.Gateway.Enabled || s.Gateway.Level != "Notice" ||
		!slices.Equal(s.Gateway.Levels, realSyslogLevels) {
		t.Fatalf("status %+v", s)
	}
	if c, bad := hasCondition(st, condSyslogSettingFailed); bad {
		t.Fatalf("condition %+v", c)
	}

	// The next check finds the setting the monitor keeps: only the read is recorded.
	from = nextSeq(r)
	if err := r.m.checkNotification(ctx); err != nil {
		t.Fatal(err)
	}
	if reads, sets := r.gw.syslogReads(); reads != 2 || sets != 1 {
		t.Fatalf("%d reads, %d changes", reads, sets)
	}
	recs = recordsFrom(r, from)
	if got := bodyTypes(recs); !slices.Equal(got, []string{model.TypeGatewayEvent}) {
		t.Fatalf("records %v", got)
	}
	again := decode[model.GatewayEvent](t, recs[0])
	if again.Before != after || again.After != after {
		t.Fatalf("read %+v", again)
	}
	mustContain(t, "the second read", again.Detail, "which is this computer", "this is the setting the monitor keeps (gateway.enforce_syslog), so nothing is changed")

	// A restart finds the setting in the ledger.
	r2 := newRig(t, r.cfg, r.led)
	r2.m.rebuild(time.Now())
	if g := r2.m.st.syslogGw; g == nil || g.Seq != recs[0].Seq || g.Setting == nil ||
		!reflect.DeepEqual(*g.Setting, model.SyslogSetting{Enabled: true, Server: "192.168.1.71", Port: 514, Level: "Notice"}) {
		t.Fatalf("rebuilt %+v", g)
	}
}

// The page is set whenever it shows anything but the target - off, another address, another
// port, another level than the target's - and only then. The level already set is kept unless
// gateway.syslog_level names another one the page offers.
func TestSyslogEnforcementTargets(t *testing.T) {
	ctx := context.Background()
	full := []string{"Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Informational", "Debug"}
	on := func(server string, port int, level string, levels ...string) model.SyslogSetting {
		if levels == nil {
			levels = realSyslogLevels
		}
		return model.SyslogSetting{Enabled: true, Server: server, Port: port, Level: level, Levels: slices.Clone(levels)}
	}
	ptr := func(t model.SyslogTarget) *model.SyslogTarget { return &t }
	const me = "192.168.1.71"
	for _, tc := range []struct {
		name     string
		page     model.SyslogSetting
		cfgLevel string
		want     *model.SyslogTarget // nil: nothing to set
		detail   string              // in the change's detail
	}{
		{"off: the real page", realSyslogOff(), "", ptr(targetAt(me, "Notice")),
			"Syslog off -> on; Server IP Address (empty) -> 192.168.1.71; Log Level Error -> Notice. "},
		{"off: Informational offered", model.SyslogSetting{Port: 514, Level: "Warning", Levels: full}, "", ptr(targetAt(me, "Informational")),
			"Log Level Warning -> Informational. Read back after saving, the gateway sends its log to 192.168.1.71:514 at level Informational, which is this computer"},
		{"elsewhere: the level set is kept", on("192.168.1.50", 514, "Error"), "", ptr(targetAt(me, "Error")),
			"(gateway.enforce_syslog): Server IP Address 192.168.1.50 -> 192.168.1.71. "},
		{"another port", on(me, 1514, "Warning"), "", ptr(targetAt(me, "Warning")), ": Server Port 1514 -> 514. "},
		{"another level by syslog_level", on(me, 514, "Notice"), "Warning", ptr(targetAt(me, "Warning")),
			": Log Level Notice -> Warning. Read back"},
		{"syslog_level as a severity name", on(me, 514, "Warning", full...), "info", ptr(targetAt(me, "Informational")),
			"level Informational: chosen by gateway.syslog_level"},
		{"syslog_level not offered", realSyslogOff(), "Informational", ptr(targetAt(me, "Notice")),
			`level Notice: the most detailed level the page offers, Debug aside (gateway.syslog_level "Informational" is not one of the page's levels: Emergency, Alert, Critical, Error, Warning, Notice)`},
		{"ok", on(me, 514, "Error"), "", nil, ""},
		{"ok: syslog_level in another case", on(me, 514, "Warning"), "warning", nil, ""},
		{"ok: syslog_level not offered keeps the level set", on(me, 514, "Error"), "Debug", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, nil, nil)
			r.cfg.Gateway.AccessCodeProtected = "protected-blob"
			r.cfg.Gateway.SyslogLevel = tc.cfgLevel
			ip := &atomic.Value{}
			ip.Store(me)
			linkAt(r, ip)
			r.m.checkLocalLink(ctx, false)
			newSyslogSim(r.gw, tc.page, nil)
			if err := r.m.checkNotification(ctx); err != nil {
				t.Fatal(err)
			}
			sets, _ := r.gw.syslogSets()
			last := decode[model.GatewayEvent](t, lastOfType(t, r, model.TypeGatewayEvent))
			if tc.want == nil {
				if len(sets) != 0 {
					t.Fatalf("set %+v", sets)
				}
				mustContain(t, "the read", last.Detail, "this is the setting the monitor keeps")
				if s := r.m.Status().Syslog; s.State != syslogStateOK || s.Target == nil || s.Target.Level != tc.page.Level {
					t.Fatalf("status %+v", s)
				}
				return
			}
			if len(sets) != 1 || sets[0] != *tc.want {
				t.Fatalf("set %+v, want %+v", sets, *tc.want)
			}
			mustContain(t, "the change", last.Detail, tc.detail)
			cc := decode[model.ConfigChange](t, lastOfType(t, r, model.TypeConfigChange))
			if cc.Result != "verified" || cc.Before != syslogSummary(tc.page) || cc.After != syslogWanted(true, *tc.want, true) {
				t.Fatalf("config_change %+v", cc)
			}
			if s := r.m.Status().Syslog; s.State != syslogStateOK || s.Target == nil || *s.Target != *tc.want {
				t.Fatalf("status %+v", s)
			}
		})
	}
}

// The level rule (docs/syslog-snmp-traffic.md §3.1): gateway.syslog_level when the page offers
// it; else the level already set while Syslog is on; else an option named like
// "Informational"; else the most detailed option below Debug - never one the page does not
// offer.
func TestSyslogTargetLevel(t *testing.T) {
	full := []string{"Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Informational", "Debug"}
	off := func(levels ...string) model.SyslogSetting { return model.SyslogSetting{Level: "Error", Levels: levels} }
	on := func(level string, levels ...string) model.SyslogSetting {
		return model.SyslogSetting{Enabled: true, Level: level, Levels: levels}
	}
	for _, tc := range []struct {
		name  string
		page  model.SyslogSetting
		want  string // gateway.syslog_level
		level string
		how   string
	}{
		{"the real page", off(realSyslogLevels...), "", "Notice", "the most detailed level the page offers, Debug aside"},
		{"Informational offered", off(full...), "", "Informational", "the page's informational level"},
		{"named Info", off("Error", "Warning", "Info", "Debug"), "", "Info", "the page's informational level"},
		{"labels with numbers", off("L0 - Emergency", "L3 - Error", "L5 - Notice", "L7 - Debug"), "", "L5 - Notice", "the most detailed level"},
		{"Debug is never chosen by itself", off("Error", "Warning", "Debug"), "", "Warning", "the most detailed level"},
		{"on: the level already set", on("Error", full...), "", "Error", "the level already set"},
		{"syslog_level", off(realSyslogLevels...), "Warning", "Warning", "chosen by gateway.syslog_level"},
		{"syslog_level wins over the level set", on("Error", realSyslogLevels...), " warning ", "Warning", "chosen by gateway.syslog_level"},
		{"syslog_level as a number", off(full...), "7", "Debug", "chosen by gateway.syslog_level"},
		{"syslog_level as a severity name", off(full...), "crit", "Critical", "chosen by gateway.syslog_level"},
		{"syslog_level Debug when offered", on("Notice", full...), "Debug", "Debug", "chosen by gateway.syslog_level"},
		{"syslog_level not offered", off(realSyslogLevels...), "Informational", "Notice",
			`the most detailed level the page offers, Debug aside (gateway.syslog_level "Informational" is not one of the page's levels: Emergency, Alert, Critical, Error, Warning, Notice)`},
		{"syslog_level not offered, on", on("Error", realSyslogLevels...), "Debug", "Error", `the level already set (gateway.syslog_level "Debug" is not one`},
		{"syslog_level of two options", off("Info", "Informational"), "6", "Info", `the page's informational level (gateway.syslog_level "6"`},
		{"unknown level names", off("Low", "High"), "", "", "left as the page has it"},
		{"levels not known, off", model.SyslogSetting{}, "", "", "left as the page has it"},
		{"levels not known, on", on("Notice"), "", "Notice", "the level already set"},
		{"levels not known, syslog_level", model.SyslogSetting{}, "Notice", "", `left as the page has it (gateway.syslog_level "Notice": the page's levels are not known)`},
	} {
		level, how := syslogTargetLevel(tc.page, tc.want)
		if level != tc.level || !strings.Contains(how, tc.how) {
			t.Errorf("%s: level %q (%s), want %q (%s)", tc.name, level, how, tc.level, tc.how)
		}
	}
	for label, want := range map[string]int{"Emergency": 0, "PANIC": 0, "L1 - Alert": 1, "crit": 2, "err": 3, "Warning": 4, "notice": 5, "Info": 6, "debug (7)": 7} {
		if sev, ok := levelSeverity(label); !ok || sev != want {
			t.Errorf("levelSeverity(%q) = %d %v, want %d", label, sev, ok, want)
		}
	}
	for _, label := range []string{"", "Low", "Warning/Error", "L5"} {
		if sev, ok := levelSeverity(label); ok {
			t.Errorf("levelSeverity(%q) = %d", label, sev)
		}
	}
	for in, want := range map[string]string{"192.168.1.71": "192.168.1.71", " 10.0.0.5 ": "10.0.0.5", "::ffff:192.168.1.71": "192.168.1.71",
		"169.254.10.20": "", "127.0.0.1": "", "0.0.0.0": "", "224.0.0.1": "", "255.255.255.255": "", "fd00::5": "", "": "", "pc.lan": ""} {
		if got := usableIPv4(in); got != want {
			t.Errorf("usableIPv4(%q) = %q, want %q", in, got, want)
		}
	}
	if _, _, ok := syslogTarget(nil, "192.168.1.71", 0, ""); ok {
		t.Error("a target without a port")
	}
	if tg, _, ok := syslogTarget(nil, "192.168.1.71", 514, "Notice"); !ok || tg != targetAt("192.168.1.71", "") {
		t.Errorf("target without a page: %+v %v", tg, ok)
	}
}

// Without gateway.enforce_syslog the page is only read: nothing is set and nothing fails; the
// status still says where the gateway would have to send its log.
func TestSyslogNotEnforced(t *testing.T) {
	r, sim, _ := enforceRig(t)
	r.cfg.Gateway.EnforceSyslog = false
	if err := r.m.checkNotification(context.Background()); err != nil {
		t.Fatal(err)
	}
	if reads, sets := r.gw.syslogReads(); reads != 1 || sets != 0 {
		t.Fatalf("%d reads, %d changes", reads, sets)
	}
	if got, _ := sim.current(); got.Enabled {
		t.Fatal("changed")
	}
	ev := decode[model.GatewayEvent](t, lastOfType(t, r, model.TypeGatewayEvent))
	mustContain(t, "the read", ev.Detail, "read only: gateway.enforce_syslog is off, so the monitor does not change the setting")
	if n := len(ofType(r.led.records(""), model.TypeConfigChange)); n != 0 {
		t.Fatalf("%d config_change records", n)
	}
	st := r.m.Status()
	if s := st.Syslog; s.Enforce || s.Target == nil || *s.Target != targetAt("192.168.1.71", "Notice") || s.State != syslogStateOff {
		t.Fatalf("status %+v", s)
	}
	if _, bad := hasCondition(st, condSyslogSettingFailed); bad {
		t.Fatal("nothing failed")
	}
}

// Without this computer's IPv4 address toward the gateway - none in the readings, nor in a
// reading the check takes of its own - the page is not set and SYSLOG_SETTING_FAILED says why.
// The first reading that has an address asks for a settings check, which sets the page.
func TestSyslogEnforcementNeedsAnAddress(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, nil, nil)
	r.cfg.Gateway.AccessCodeProtected = "protected-blob"
	newSyslogSim(r.gw, realSyslogOff(), realSyslogPage(t))
	ip := &atomic.Value{}
	ip.Store("")
	linkAt(r, ip)
	links := r.pr.calls("link")
	if err := r.m.checkNotification(ctx); err != nil {
		t.Fatal(err)
	}
	if _, sets := r.gw.syslogReads(); sets != 0 {
		t.Fatal("set without an address")
	}
	if n := r.pr.calls("link") - links; n != 1 {
		t.Fatalf("%d readings of the network adapter, want 1 of its own", n)
	}
	b := lastOfType(t, r, model.TypeGatewayEvent)
	mustContain(t, "the read", decode[model.GatewayEvent](t, b).Detail,
		"the monitor (gateway.enforce_syslog) cannot set it while this computer's address toward the gateway is not known")
	st := r.m.Status()
	c, ok := hasCondition(st, condSyslogSettingFailed)
	if !ok || c.Severity != "warning" || c.Seq != b.Seq || c.Since == "" {
		t.Fatalf("conditions %+v", st.Conditions)
	}
	mustContain(t, "the condition", c.Message, "this computer's IPv4 address toward the gateway is not known",
		fmt.Sprintf("The page as read is in record #%d.", b.Seq))
	if s := st.Syslog; s.Target != nil || s.State != syslogStateOff || !strings.Contains(s.Problem, "the monitor cannot set it") {
		t.Fatalf("status %+v", s)
	}
	if n := len(ofType(r.led.records(""), model.TypeConfigChange)); n != 0 {
		t.Fatalf("%d config_change records: nothing was attempted", n)
	}

	// The address is known: a settings check is asked for at once (once), and it sets the page.
	_ = r.m.kNotif.take()
	ip.Store("192.168.1.71")
	r.m.checkLocalLink(ctx, false)
	if !hasReason(r.m.kNotif.take(), kickAddressChange) {
		t.Fatal("the first address asks for no settings check")
	}
	r.m.checkLocalLink(ctx, false)
	if reasons := r.m.kNotif.take(); len(reasons) != 0 {
		t.Fatalf("asked again: %v", reasons)
	}
	if err := r.m.checkNotification(ctx); err != nil {
		t.Fatal(err)
	}
	if sets, _ := r.gw.syslogSets(); len(sets) != 1 || sets[0] != targetAt("192.168.1.71", "Notice") {
		t.Fatalf("set %+v", sets)
	}
	st = r.m.Status()
	if _, bad := hasCondition(st, condSyslogSettingFailed); bad || st.Syslog.State != syslogStateOK || st.Syslog.Problem != "" {
		t.Fatalf("status %+v conditions %+v", st.Syslog, st.Conditions)
	}

	// A link-local address is no address the gateway can send to.
	r2 := newRig(t, nil, nil)
	r2.cfg.Gateway.AccessCodeProtected = "protected-blob"
	newSyslogSim(r2.gw, realSyslogOff(), nil)
	ip2 := &atomic.Value{}
	ip2.Store("169.254.10.20")
	linkAt(r2, ip2)
	r2.m.checkLocalLink(ctx, false)
	if err := r2.m.checkNotification(ctx); err != nil {
		t.Fatal(err)
	}
	if _, sets := r2.gw.syslogReads(); sets != 0 {
		t.Fatal("set to a link-local address")
	}
	if _, ok := hasCondition(r2.m.Status(), condSyslogSettingFailed); !ok {
		t.Fatal("no SYSLOG_SETTING_FAILED")
	}

	// A check that finds the address with a reading of its own sets the page; the address then
	// asks for no further check.
	r3 := newRig(t, nil, nil)
	r3.cfg.Gateway.AccessCodeProtected = "protected-blob"
	newSyslogSim(r3.gw, realSyslogOff(), nil)
	ip3 := &atomic.Value{}
	ip3.Store("")
	linkAt(r3, ip3)
	if err := r3.m.checkNotification(ctx); err != nil {
		t.Fatal(err)
	}
	ip3.Store("192.168.1.71")
	if err := r3.m.checkNotification(ctx); err != nil {
		t.Fatal(err)
	}
	if sets, _ := r3.gw.syslogSets(); len(sets) != 1 || sets[0] != targetAt("192.168.1.71", "Notice") {
		t.Fatalf("set %+v", sets)
	}
	_ = r3.m.kNotif.take()
	r3.m.checkLocalLink(ctx, false)
	if reasons := r3.m.kNotif.take(); len(reasons) != 0 {
		t.Fatalf("asked for a check the page no longer needs: %v", reasons)
	}
}

// A page that is read but not understood is never set (the gateway client posts nothing it does
// not understand): SYSLOG_SETTING_FAILED names the problem and the read's record. A failed read
// changes nothing of it; once the page is understood and set, the condition ends.
func TestSyslogEnforcementCannotSet(t *testing.T) {
	ctx := context.Background()
	r, _, _ := enforceRig(t)
	odd := []byte("<html><form><select name=x><option>On</select></form></html>")
	r.gw.syslog = func() (model.SyslogSetting, []byte, error) {
		return model.SyslogSetting{}, odd, errors.New(`gateway: Syslog page not understood: no control labelled "Syslog"`)
	}
	if err := r.m.checkNotification(ctx); err != nil {
		t.Fatal(err)
	}
	if _, sets := r.gw.syslogReads(); sets != 0 {
		t.Fatal("a page that is not understood was set")
	}
	b := lastOfType(t, r, model.TypeGatewayEvent)
	ev := decode[model.GatewayEvent](t, b)
	if ev.After != syslogUnknown || !slices.Equal(b.Blobs, []string{sha256Hex(odd)}) {
		t.Fatalf("read %+v blobs %v", ev, b.Blobs)
	}
	mustContain(t, "the read", ev.Detail, "it never posts a page it does not understand")
	c, ok := hasCondition(r.m.Status(), condSyslogSettingFailed)
	if !ok || c.Seq != b.Seq {
		t.Fatalf("condition %+v", c)
	}
	mustContain(t, "the condition", c.Message, `the page was read but not understood (gateway: Syslog page not understood: no control labelled "Syslog")`,
		"never posts a page it does not understand")

	r.gw.syslog = func() (model.SyslogSetting, []byte, error) {
		return model.SyslogSetting{}, nil, fmt.Errorf("gateway: GET syslog: %w", contracts.ErrGatewaySessionsFull)
	}
	if err := r.m.checkNotification(ctx); err != nil {
		t.Fatal(err)
	}
	st := r.m.Status()
	if c2, ok := hasCondition(st, condSyslogSettingFailed); !ok || c2 != c {
		t.Fatalf("after a failed read: %+v, want %+v", c2, c)
	}
	if st.Syslog.State != syslogStateError || !strings.Contains(st.Syslog.Problem, "sessions are in use") {
		t.Fatalf("status %+v", st.Syslog)
	}

	newSyslogSim(r.gw, realSyslogOff(), nil)
	if err := r.m.checkNotification(ctx); err != nil {
		t.Fatal(err)
	}
	st = r.m.Status()
	if _, bad := hasCondition(st, condSyslogSettingFailed); bad || st.Syslog.State != syslogStateOK {
		t.Fatalf("status %+v conditions %+v", st.Syslog, st.Conditions)
	}
}

// A change the gateway client cannot make is recorded - a config_change whose result says why,
// with the pages there are - and shown as SYSLOG_SETTING_FAILED. The monitor does not try again
// before the next settings check (no loop, no extra login); that check tries again.
func TestSyslogEnforcementFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, sim, _ := enforceRig(t)
	r.m.notifMinInterval = 20 * time.Millisecond // the next regular check is an hour away (testConfig)
	full := fmt.Errorf("gateway: POST syslog.ha: %w", contracts.ErrGatewaySessionsFull)
	sim.update(func(s *syslogSim) { s.setErr = full })
	done := make(chan struct{})
	go func() { r.m.notificationLoop(ctx); close(done) }()
	waitFor(t, "the attempt's record", 10*time.Second, func() bool { return len(ofType(r.led.records(""), model.TypeConfigChange)) == 1 })
	time.Sleep(300 * time.Millisecond)
	if reads, sets := r.gw.syslogReads(); reads != 1 || sets != 1 {
		t.Fatalf("%d reads, %d changes: tried again before the next settings check", reads, sets)
	}
	cancel()
	<-done

	const after = "on -> 192.168.1.71:514, level Notice"
	b := lastOfType(t, r, model.TypeConfigChange)
	cc := decode[model.ConfigChange](t, b)
	if cc.Target != "gateway" || cc.What != syslogWhat || cc.Before != "off" || cc.After != after || cc.Actor != syslogEnforcer ||
		cc.Result != "failed: "+full.Error() || !slices.Equal(b.Blobs, []string{sha256Hex(realSyslogPage(t))}) {
		t.Fatalf("config_change %+v blobs %v", cc, b.Blobs)
	}
	if ev := decode[model.GatewayEvent](t, lastOfType(t, r, model.TypeGatewayEvent)); ev.After != "off" {
		t.Fatalf("the latest event is the read: %+v", ev)
	}
	st := r.m.Status()
	c, ok := hasCondition(st, condSyslogSettingFailed)
	if !ok || c.Severity != "warning" || c.Seq != b.Seq || c.Since == "" {
		t.Fatalf("conditions %+v", st.Conditions)
	}
	mustContain(t, "the condition", c.Message, "could not set the gateway's Syslog page to send its log to this computer (192.168.1.71:514 at level Notice)",
		"all web server sessions are in use", "It tries again at the next settings check", fmt.Sprintf("The attempt is in record #%d.", b.Seq))
	if s := st.Syslog; s.State != syslogStateOff || !strings.Contains(s.Problem, "the monitor could not set it: gateway: POST syslog.ha") {
		t.Fatalf("status %+v", s)
	}

	// The next check: the page read back does not show the change. Both pages are recorded; the
	// failure goes on.
	sim.update(func(s *syslogSim) { s.setErr, s.ignore = nil, true })
	if err := r.m.checkNotification(context.Background()); err != nil {
		t.Fatal(err)
	}
	b2 := lastOfType(t, r, model.TypeConfigChange)
	if cc2 := decode[model.ConfigChange](t, b2); !strings.HasPrefix(cc2.Result, "failed: gateway: setting not applied") || len(b2.Blobs) != 2 {
		t.Fatalf("config_change %+v blobs %v", cc2, b2.Blobs)
	}
	if c2, ok := hasCondition(r.m.Status(), condSyslogSettingFailed); !ok || c2.Seq != b2.Seq || c2.Since != c.Since {
		t.Fatalf("condition %+v (first %+v)", c2, c)
	}

	// The check after that sets it: the condition ends.
	sim.update(func(s *syslogSim) { s.ignore = false })
	if err := r.m.checkNotification(context.Background()); err != nil {
		t.Fatal(err)
	}
	st = r.m.Status()
	if _, bad := hasCondition(st, condSyslogSettingFailed); bad || st.Syslog.State != syslogStateOK || st.Syslog.Problem != "" {
		t.Fatalf("status %+v conditions %+v", st.Syslog, st.Conditions)
	}
	if _, sets := r.gw.syslogReads(); sets != 3 {
		t.Fatalf("%d changes", sets)
	}
}

// When this computer's address toward the gateway changes, the settings check runs again - after
// the floor - and sets the page to the new address.
func TestSyslogEnforcedAfterAddressChange(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, _, ip := enforceRig(t)
	const floor = 300 * time.Millisecond
	r.m.notifMinInterval = floor
	done := make(chan struct{})
	go func() { r.m.notificationLoop(ctx); close(done) }()
	waitFor(t, "the check at the start to set the page", 10*time.Second, func() bool {
		return len(ofType(r.led.records(""), model.TypeConfigChange)) == 1
	})
	ip.Store("192.168.1.80")
	r.m.checkLocalLink(ctx, false)
	waitFor(t, "the page set to the new address", 10*time.Second, func() bool {
		return len(ofType(r.led.records(""), model.TypeConfigChange)) == 2
	})
	cancel()
	<-done
	sets, times := r.gw.syslogSets()
	if len(sets) != 2 || sets[0] != targetAt("192.168.1.71", "Notice") || sets[1] != targetAt("192.168.1.80", "Notice") {
		t.Fatalf("set %+v", sets)
	}
	if gap := times[1].Sub(times[0]); gap < floor {
		t.Fatalf("set again after %v (floor %v)", gap, floor)
	}
	change := decode[model.GatewayEvent](t, lastOfType(t, r, model.TypeGatewayEvent))
	if change.Before != "on -> 192.168.1.71:514, level Notice" || change.After != "on -> 192.168.1.80:514, level Notice" {
		t.Fatalf("change %+v", change)
	}
	mustContain(t, "the change", change.Detail,
		"set by the monitor (gateway.enforce_syslog) again after this computer's address toward the gateway changed: Server IP Address 192.168.1.71 -> 192.168.1.80. ",
		"level Notice: the level already set")
	if s := r.m.Status().Syslog; s.State != syslogStateOK || s.Target == nil || *s.Target != targetAt("192.168.1.80", "Notice") {
		t.Fatalf("status %+v", s)
	}
}

// While the ledger refuses records nothing is set: a change that could not be recorded is not
// made. A change the gateway made whose records the ledger then refuses is stated in the status
// and returned as contracts.ErrNotRecorded.
func TestSyslogEnforcementAndTheLedger(t *testing.T) {
	ctx := context.Background()
	r, _, _ := enforceRig(t)
	r.led.setRejectRecord(func(typ string) error {
		if typ == model.TypeGatewayEvent {
			return errors.New("disk full")
		}
		return nil
	})
	_ = r.m.checkNotification(ctx)
	if _, sets := r.gw.syslogReads(); sets != 0 {
		t.Fatal("set while its read could not be recorded")
	}

	r2, _, _ := enforceRig(t)
	var events atomic.Int32
	r2.led.setRejectRecord(func(typ string) error {
		if typ == model.TypeGatewayEvent && events.Add(1) == 2 { // the read is recorded, the change is not
			return errors.New("disk full")
		}
		return nil
	})
	cc, err := r2.m.SetGatewaySyslog(ctx, true, "web")
	if !errors.Is(err, contracts.ErrNotRecorded) || cc.Result != "verified" {
		t.Fatalf("%+v %v", cc, err)
	}
	if got := decode[model.ConfigChange](t, lastOfType(t, r2, model.TypeConfigChange)); got != cc {
		t.Fatalf("the config_change %+v is recorded, want %+v", got, cc)
	}
	s := r2.m.Status().Syslog
	if s.State != syslogStateError || !strings.Contains(s.Problem, "could not be recorded") || s.Gateway == nil || !s.Gateway.Enabled || s.GatewaySeq != 0 {
		t.Fatalf("status %+v", s)
	}
}

// ---------------------------------------------------------------------------- the operator

func TestSetGatewaySyslog(t *testing.T) {
	ctx := context.Background()
	const after = "on -> 192.168.1.71:514, level Notice"
	t.Run("on: enforced from now on, and set", func(t *testing.T) {
		r, sim, _ := enforceRig(t)
		r.cfg.Gateway.EnforceSyslog = false
		from := nextSeq(r)
		cc, err := r.m.SetGatewaySyslog(ctx, true, " operator via web ")
		if err != nil {
			t.Fatal(err)
		}
		want := model.ConfigChange{Target: "gateway", What: syslogWhat, Before: "off", After: after, Actor: "operator via web", Result: "verified"}
		if cc != want {
			t.Fatalf("change %+v, want %+v", cc, want)
		}
		if !r.cfg.Gateway.EnforceSyslog || r.saved.Load() != 1 {
			t.Fatalf("enforce %v saved %d", r.cfg.Gateway.EnforceSyslog, r.saved.Load())
		}
		recs := recordsFrom(r, from)
		if got := bodyTypes(recs); !slices.Equal(got, []string{model.TypeConfigChange, model.TypeGatewayEvent, model.TypeGatewayEvent, model.TypeConfigChange}) {
			t.Fatalf("records %v: the choice, the read, the change, the config_change", got)
		}
		choice := model.ConfigChange{Target: "monitor", What: enforceSyslogWhat, Before: "false", After: "true", Actor: "operator via web", Result: "applied"}
		if got := decode[model.ConfigChange](t, recs[0]); got != choice {
			t.Fatalf("the choice %+v, want %+v", got, choice)
		}
		mustContain(t, "the read", decode[model.GatewayEvent](t, recs[1]).Detail,
			"read for the change asked for by operator via web: the gateway does not send its log",
			"operator via web sets it now to send its log to 192.168.1.71:514 at level Notice")
		change := decode[model.GatewayEvent](t, recs[2])
		if change.Before != "off" || change.After != after || strings.Contains(change.Detail, "asked for by") {
			t.Fatalf("change %+v", change)
		}
		mustContain(t, "the change", change.Detail, "set by operator via web: Syslog off -> on; ")
		if got := decode[model.ConfigChange](t, recs[3]); got != want || len(recs[3].Blobs) != 2 {
			t.Fatalf("the gateway's config_change %+v blobs %v", got, recs[3].Blobs)
		}
		if sets, _ := r.gw.syslogSets(); len(sets) != 1 || sets[0] != targetAt("192.168.1.71", "Notice") {
			t.Fatalf("set %+v", sets)
		}
		if got, _ := sim.current(); !got.Enabled {
			t.Fatal("not set")
		}
		if s := r.m.Status().Syslog; !s.Enforce || s.State != syslogStateOK {
			t.Fatalf("status %+v", s)
		}

		// Asked again: unchanged, and only the read is recorded.
		from = nextSeq(r)
		cc, err = r.m.SetGatewaySyslog(ctx, true, "cli")
		if err != nil || cc.Result != "unchanged: the gateway already sends its log to this computer" || cc.Before != after || cc.After != after || cc.Actor != "cli" {
			t.Fatalf("%+v %v", cc, err)
		}
		recs = recordsFrom(r, from)
		if got := bodyTypes(recs); !slices.Equal(got, []string{model.TypeGatewayEvent}) {
			t.Fatalf("records %v", got)
		}
		mustContain(t, "the read", decode[model.GatewayEvent](t, recs[0]).Detail, "this is what cli asked for, so nothing is changed")
		if _, sets := r.gw.syslogReads(); sets != 1 || r.saved.Load() != 1 {
			t.Fatalf("%d changes, saved %d", sets, r.saved.Load())
		}
	})
	t.Run("off: not enforced any more, and switched off", func(t *testing.T) {
		r, sim, _ := enforceRig(t)
		sim.update(func(s *syslogSim) {
			s.setting.Enabled, s.setting.Server, s.setting.Level = true, "192.168.1.71", "Notice"
			s.page = nil
		})
		from := nextSeq(r)
		cc, err := r.m.SetGatewaySyslog(ctx, false, "")
		if err != nil {
			t.Fatal(err)
		}
		if want := (model.ConfigChange{Target: "gateway", What: syslogWhat, Before: after, After: "off", Actor: "operator", Result: "verified"}); cc != want {
			t.Fatalf("change %+v, want %+v", cc, want)
		}
		if r.cfg.Gateway.EnforceSyslog || r.saved.Load() != 1 {
			t.Fatalf("enforce %v saved %d", r.cfg.Gateway.EnforceSyslog, r.saved.Load())
		}
		recs := recordsFrom(r, from)
		if got := bodyTypes(recs); !slices.Equal(got, []string{model.TypeConfigChange, model.TypeGatewayEvent, model.TypeGatewayEvent, model.TypeConfigChange}) {
			t.Fatalf("records %v", got)
		}
		if got := decode[model.ConfigChange](t, recs[0]); got.Target != "monitor" || got.Before != "true" || got.After != "false" {
			t.Fatalf("the choice %+v", got)
		}
		mustContain(t, "the read", decode[model.GatewayEvent](t, recs[1]).Detail, "operator switches it off now")
		mustContain(t, "the change", decode[model.GatewayEvent](t, recs[2]).Detail,
			"switched off by operator: Syslog on -> off. Read back after saving, the gateway does not send its log to a syslog server.")
		if sets, _ := r.gw.syslogSets(); len(sets) != 1 || sets[0] != (model.SyslogTarget{}) {
			t.Fatalf("set %+v", sets)
		}
		if got, _ := sim.current(); got.Enabled || got.Server != "192.168.1.71" || got.Level != "Notice" {
			t.Fatalf("the page %+v: only the switch changes", got)
		}
		st := r.m.Status()
		if s := st.Syslog; s.Enforce || s.State != syslogStateOff || s.Problem != "the gateway does not send its log to a syslog server (its Syslog setting is off)" {
			t.Fatalf("status %+v", s)
		}
		// The settings check leaves it off.
		if err := r.m.checkNotification(ctx); err != nil {
			t.Fatal(err)
		}
		if _, sets := r.gw.syslogReads(); sets != 1 {
			t.Fatal("the settings check set it again")
		}
	})
	t.Run("from the command line: an address reading of its own", func(t *testing.T) {
		r := newRig(t, nil, nil) // no local-link reading yet, as in the CLI
		r.cfg.Gateway.AccessCodeProtected = "protected-blob"
		newSyslogSim(r.gw, realSyslogOff(), nil)
		ip := &atomic.Value{}
		ip.Store("192.168.1.71")
		linkAt(r, ip)
		if cc, err := r.m.SetGatewaySyslog(ctx, true, "cli"); err != nil || cc.After != after {
			t.Fatalf("%+v %v", cc, err)
		}
	})
	t.Run("busy", func(t *testing.T) {
		r, _, _ := enforceRig(t)
		n := len(r.led.records(""))
		r.m.notifMu.Lock()
		_, err := r.m.SetGatewaySyslog(ctx, true, "web")
		r.m.notifMu.Unlock()
		if !errors.Is(err, contracts.ErrBusy) {
			t.Fatalf("err %v", err)
		}
		if reads, sets := r.gw.syslogReads(); reads != 0 || sets != 0 || len(r.led.records("")) != n {
			t.Fatal("a busy change must change nothing")
		}
	})
	t.Run("refused while a certificate change is pending", func(t *testing.T) {
		r := certRig(t)
		r.cfg.Gateway.AccessCodeProtected = "protected-blob"
		r.cfg.Gateway.EnforceSyslog = false
		newSyslogSim(r.gw, realSyslogOff(), nil)
		n, saved := len(r.led.records("")), r.saved.Load()
		_, err := r.m.SetGatewaySyslog(ctx, true, "web")
		if !errors.Is(err, contracts.ErrGatewayCertRejected) || !errors.Is(err, contracts.ErrUnavailable) {
			t.Fatalf("err %v", err)
		}
		if reads, sets := r.gw.syslogReads(); reads != 0 || sets != 0 || len(r.led.records("")) != n || r.saved.Load() != saved || r.cfg.Gateway.EnforceSyslog {
			t.Fatal("an authenticated request, or a change, while a certificate is pending")
		}
	})
	t.Run("the gateway's login errors as they are", func(t *testing.T) {
		r, sim, _ := enforceRig(t)
		r.cfg.Gateway.EnforceSyslog = false
		login := fmt.Errorf("gateway: GET syslog.ha: %w", contracts.ErrGatewayAuth)
		sim.update(func(s *syslogSim) { s.readErr = login })
		cc, err := r.m.SetGatewaySyslog(ctx, true, "web")
		if err != login {
			t.Fatalf("err %v, want %v as it is", err, login)
		}
		want := model.ConfigChange{Target: "gateway", What: syslogWhat, Before: syslogUnknown, After: "on -> this computer", Actor: "web", Result: "failed: " + login.Error()}
		if cc != want {
			t.Fatalf("change %+v, want %+v", cc, want)
		}
		if got := decode[model.ConfigChange](t, lastOfType(t, r, model.TypeConfigChange)); got != want {
			t.Fatalf("the failed attempt is recorded: %+v", got)
		}
		// The choice stands: the next settings check sets the page.
		if !r.cfg.Gateway.EnforceSyslog {
			t.Fatal("the choice was not kept")
		}
		c, ok := hasCondition(r.m.Status(), condSyslogSettingFailed)
		if !ok {
			t.Fatal("no SYSLOG_SETTING_FAILED")
		}
		mustContain(t, "the condition", c.Message, "login failed", "It tries again at the next settings check")
	})
	t.Run("the change fails", func(t *testing.T) {
		r, sim, _ := enforceRig(t)
		disabled := errors.New(`gateway: Syslog page not understood: the "Server IP Address" input is disabled; nothing posted`)
		sim.update(func(s *syslogSim) { s.setErr = disabled })
		cc, err := r.m.SetGatewaySyslog(ctx, true, "web")
		if err != disabled || cc.Result != "failed: "+disabled.Error() || cc.Before != "off" || cc.After != after {
			t.Fatalf("%+v %v", cc, err)
		}
		b := lastOfType(t, r, model.TypeConfigChange)
		if got := decode[model.ConfigChange](t, b); got != cc || !slices.Equal(b.Blobs, []string{sha256Hex(realSyslogPage(t))}) {
			t.Fatalf("recorded %+v blobs %v", got, b.Blobs)
		}
		if ev := decode[model.GatewayEvent](t, lastOfType(t, r, model.TypeGatewayEvent)); ev.After != "off" {
			t.Fatalf("no change was recorded as made: %+v", ev)
		}
	})
	t.Run("no address", func(t *testing.T) {
		r := newRig(t, nil, nil)
		r.cfg.Gateway.AccessCodeProtected = "protected-blob"
		newSyslogSim(r.gw, realSyslogOff(), realSyslogPage(t))
		cc, err := r.m.SetGatewaySyslog(ctx, true, "web")
		if !errors.Is(err, contracts.ErrUnavailable) || cc.Before != "off" || cc.After != "on -> this computer" ||
			cc.Result != "failed: "+(noSyslogAddrError{}).Error() {
			t.Fatalf("%+v %v", cc, err)
		}
		if b := lastOfType(t, r, model.TypeConfigChange); len(b.Blobs) != 1 {
			t.Fatalf("the page read is recorded with the attempt: %v", b.Blobs)
		}
		if _, sets := r.gw.syslogReads(); sets != 0 {
			t.Fatal("set without an address")
		}
	})
	t.Run("the choice not recorded: nothing changes", func(t *testing.T) {
		r, _, _ := enforceRig(t)
		r.cfg.Gateway.EnforceSyslog = false
		r.led.setRejectRecord(func(typ string) error {
			if typ == model.TypeConfigChange {
				return errors.New("disk full")
			}
			return nil
		})
		if _, err := r.m.SetGatewaySyslog(ctx, true, "web"); err == nil {
			t.Fatal("error expected")
		}
		if reads, sets := r.gw.syslogReads(); reads != 0 || sets != 0 || r.cfg.Gateway.EnforceSyslog {
			t.Fatalf("%d reads, %d changes, enforce %v", reads, sets, r.cfg.Gateway.EnforceSyslog)
		}
	})
	t.Run("the choice not saved: applied until the monitor restarts", func(t *testing.T) {
		r, _, _ := enforceRig(t)
		r.cfg.Gateway.EnforceSyslog = false
		r.m.opts.SaveConfig = func(*config.Config) error { return errors.New("access denied") }
		cc, err := r.m.SetGatewaySyslog(ctx, true, "web")
		if err == nil || !strings.Contains(err.Error(), "could not be saved") || !strings.Contains(err.Error(), "access denied") || cc.Result != "verified" {
			t.Fatalf("%+v %v", cc, err)
		}
		if !r.cfg.Gateway.EnforceSyslog {
			t.Fatal("the choice applies until the monitor restarts")
		}
		choice := decode[model.ConfigChange](t, ofType(r.led.records(""), model.TypeConfigChange)[0])
		if choice.Target != "monitor" || !strings.HasPrefix(choice.Result, "applied until the monitor restarts: the configuration could not be saved: access denied") {
			t.Fatalf("the choice %+v", choice)
		}
	})
	t.Run("invalid actor", func(t *testing.T) {
		r, _, _ := enforceRig(t)
		n := len(r.led.records(""))
		if _, err := r.m.SetGatewaySyslog(ctx, true, strings.Repeat("x", maxLabelBytes+1)); err == nil {
			t.Fatal("an oversized actor must be refused")
		}
		if reads, _ := r.gw.syslogReads(); reads != 0 || len(r.led.records("")) != n {
			t.Fatal("changed")
		}
	})
}

// ---------------------------------------------------------------------------- messages arrive

// Once the gateway's setting sends here, SYSLOG_NOT_ARRIVING (info) says when no message from the
// gateway has arrived for 24 hours - counted from the start, from when the setting began to send
// here, and from the newest message from the gateway (another sender's does not count) - while
// the receiver listens.
func TestSyslogNotArriving(t *testing.T) {
	ctx := context.Background()
	r, rx, _ := syslogRig(t)
	clk := &fakeClock{t: time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)}
	r.m.now, r.led.now = clk.Now, clk.Now
	start := clk.Now()
	r.m.locked(func() { r.m.st.started = start })
	r.cfg.Gateway.AccessCodeProtected = "protected-blob"
	ip := &atomic.Value{}
	ip.Store("192.168.1.71")
	linkAt(r, ip)
	r.m.checkLocalLink(ctx, false)
	r.m.startSyslog()
	rx.mu.Lock()
	rx.addr = "127.0.0.1:5514" // listening
	rx.mu.Unlock()
	newSyslogSim(r.gw, realSyslogOff(), nil)
	set := start.Add(time.Hour)
	clk.Set(set)
	if err := r.m.checkNotification(ctx); err != nil {
		t.Fatal(err)
	}
	if s := r.m.Status().Syslog; s.State != syslogStateOK {
		t.Fatalf("status %+v", s)
	}
	quiet := func() (model.Condition, bool) { return hasCondition(r.m.Status(), condSyslogNotArriving) }
	clk.Set(set.Add(syslogQuietAfter - time.Second))
	if c, ok := quiet(); ok {
		t.Fatalf("too early: %+v", c)
	}
	clk.Set(set.Add(syslogQuietAfter))
	c, ok := quiet()
	if !ok || c.Severity != "info" || c.Since != fmtTS(set) {
		t.Fatalf("condition %+v", c)
	}
	mustContain(t, "the condition", c.Message, "sends its log to this computer (192.168.1.71:514)", "at level Notice the gateway may log little")

	// Another sender's message does not count; the gateway's does.
	other := syslogMsg(clk.Now(), "from another sender")
	other.Src = "192.168.1.10:514"
	rx.push(0, 0, other)
	r.m.flushSyslog(false)
	if _, ok := quiet(); !ok {
		t.Fatal("another sender's message counted")
	}
	rx.push(0, 0, syslogMsg(clk.Now(), "from the gateway"))
	arrived := clk.Now()
	r.m.flushSyslog(false)
	if c, ok := quiet(); ok {
		t.Fatalf("a message arrived: %+v", c)
	}
	clk.Set(arrived.Add(syslogQuietAfter))
	if c, ok := quiet(); !ok || c.Since != fmtTS(arrived) {
		t.Fatalf("condition %+v", c)
	}

	// Not while the receiver does not listen (SYSLOG_RECEIVER_DOWN says why), nor while the
	// gateway sends elsewhere.
	rx.mu.Lock()
	rx.addr = ""
	rx.mu.Unlock()
	if _, ok := quiet(); ok {
		t.Fatal("shown while the receiver does not listen")
	}
	rx.mu.Lock()
	rx.addr = "127.0.0.1:5514"
	rx.mu.Unlock()
	r.m.locked(func() { r.m.st.localIP = "192.168.1.80" })
	if _, ok := quiet(); ok {
		t.Fatal("shown while the gateway sends elsewhere")
	}
}

// ---------------------------------------------------------------------------- concurrency

// The operator's changes, the settings checks and the status run concurrently without races; a
// change that meets a check is refused as busy, and every change made is recorded.
func TestSyslogSettingConcurrentUse(t *testing.T) {
	r, sim, _ := enforceRig(t)
	ctx := context.Background()
	deadline := time.Now().Add(300 * time.Millisecond)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for w := range 4 {
		wg.Go(func() {
			for i := 0; time.Now().Before(deadline); i++ {
				switch (w + i) % 3 {
				case 0:
					if _, err := r.m.SetGatewaySyslog(ctx, i%2 == 0, fmt.Sprintf("worker %d", w)); err != nil && !errors.Is(err, contracts.ErrBusy) {
						errs <- err
						return
					}
				case 1:
					if err := r.m.checkNotification(ctx); err != nil {
						errs <- err
						return
					}
				default:
					_ = r.m.Status()
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	verified := 0
	for _, b := range ofType(r.led.records(""), model.TypeConfigChange) {
		if cc := decode[model.ConfigChange](t, b); cc.Target == "gateway" && cc.Result == "verified" {
			verified++
		}
	}
	if _, posts := sim.current(); verified != posts || posts == 0 {
		t.Fatalf("%d changes posted, %d recorded", posts, verified)
	}
}

// ---------------------------------------------------------------------------- review of phase 2

// offDue returns who asked for the switch-off of the gateway's Syslog page that waits.
func offDue(r *rig) string {
	var by string
	r.m.locked(func() { by = r.m.st.syslogOffDue })
	return by
}

// A changed gateway certificate that a status read meets after the settings check - or the
// operator's change - began, here between the read of the Syslog page and its change (while the
// check takes a reading of this computer's network adapter of its own), pauses the authenticated
// requests that follow. The gateway client pins such a certificate for the status read and never
// asks the observer about it again, so withGatewayAuth checks for a pending certificate itself,
// holding the gateway lock: no request of the change reaches the gateway, and the refused
// attempt is recorded and shown. Once the certificate is confirmed, the next check sets the page.
func TestSyslogChangePausedByACertificateMetMidway(t *testing.T) {
	ctx := context.Background()
	for _, operator := range []bool{false, true} {
		t.Run(map[bool]string{false: "settings check", true: "operator"}[operator], func(t *testing.T) {
			r := newRig(t, nil, nil) // no reading of the network adapter yet
			r.cfg.Gateway.AccessCodeProtected = "protected-blob"
			r.cfg.Gateway.PinnedCertSHA256 = fpA
			if operator {
				r.cfg.Gateway.EnforceSyslog = false
			}
			sim := newSyslogSim(r.gw, realSyslogOff(), realSyslogPage(t))
			r.pr.link = func() (model.LocalLink, []byte, error) {
				// Meanwhile a status poll meets a changed certificate: accepted for reading.
				if !r.gw.observer(fpA, fpB) {
					t.Error("a status read must be accepted")
				}
				return model.LocalLink{Interface: "Wi-Fi", Type: "wifi", State: "connected", LocalIP: "192.168.1.71"}, nil, nil
			}
			var err error
			if operator {
				_, err = r.m.SetGatewaySyslog(ctx, true, "web")
				if !errors.Is(err, contracts.ErrGatewayCertRejected) || !strings.Contains(err.Error(), fpB) {
					t.Fatalf("err %v", err)
				}
			} else if err = r.m.checkNotification(ctx); err != nil {
				t.Fatal(err)
			}
			if pin, pending := pins(r); pin != fpA || pending != fpB {
				t.Fatalf("pin %q pending %q", pin, pending)
			}
			if reads, sets := r.gw.syslogReads(); reads != 1 || sets != 0 {
				t.Fatalf("%d reads, %d changes: a change was asked for while a changed certificate is pending", reads, sets)
			}
			if _, posts := sim.current(); posts != 0 {
				t.Fatal("posted")
			}
			b := lastOfType(t, r, model.TypeConfigChange)
			cc := decode[model.ConfigChange](t, b)
			if cc.Target != "gateway" || !strings.HasPrefix(cc.Result, "failed: authenticated gateway requests are paused") || len(b.Blobs) != 0 {
				t.Fatalf("the refused attempt %+v blobs %v", cc, b.Blobs)
			}
			st := r.m.Status()
			if c, ok := hasCondition(st, condSyslogSettingFailed); !ok || c.Seq != b.Seq || !strings.Contains(c.Message, "trust-cert") {
				t.Fatalf("SYSLOG_SETTING_FAILED %+v", c)
			}
			if certCondition(st) == nil {
				t.Fatal("no GATEWAY_CERT_CHANGED")
			}

			// Confirmed: the next settings check sets the page.
			if _, err := r.m.TrustCert(ctx, "web", fpB); err != nil {
				t.Fatal(err)
			}
			if err := r.m.checkNotification(ctx); err != nil {
				t.Fatal(err)
			}
			if sets, _ := r.gw.syslogSets(); len(sets) != 1 || sets[0] != targetAt("192.168.1.71", "Notice") {
				t.Fatalf("set %+v", sets)
			}
			if _, bad := hasCondition(r.m.Status(), condSyslogSettingFailed); bad {
				t.Fatal("SYSLOG_SETTING_FAILED after the change")
			}
		})
	}
}

// The same for the outage-redirect setting: a changed certificate that a status read meets
// between the read of the notification setting and its enforcement pauses the change before any
// request, and the Syslog page is not checked in that session. withGatewayAuth never runs an
// operation while a certificate is pending.
func TestNotificationChangePausedByACertificateMetMidway(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, nil, nil)
	r.cfg.Gateway.AccessCodeProtected = "protected-blob"
	r.cfg.Gateway.PinnedCertSHA256 = fpA
	r.gw.notif = true // the redirect is on: enforce_notification_off switches it off
	newSyslogSim(r.gw, realSyslogOff(), nil)
	var once sync.Once
	r.led.setOnPut(func([]byte) {
		// The events page is stored right after the read: meanwhile a status poll meets a
		// changed certificate.
		once.Do(func() {
			if !r.gw.observer(fpA, fpB) {
				t.Error("a status read must be accepted")
			}
		})
	})
	err := r.m.checkNotification(ctx)
	if !errors.Is(err, contracts.ErrGatewayCertRejected) || !errors.Is(err, contracts.ErrUnavailable) {
		t.Fatalf("err %v", err)
	}
	if r.gw.notifCalls != 1 || len(r.gw.setCalls) != 0 {
		t.Fatalf("%d reads, changes %v: the change reached the gateway", r.gw.notifCalls, r.gw.setCalls)
	}
	if reads, _ := r.gw.syslogReads(); reads != 0 {
		t.Fatal("the Syslog page was read while a changed certificate is pending")
	}
	cc := decode[model.ConfigChange](t, lastOfType(t, r, model.TypeConfigChange))
	if cc.What != bbeventWhat || !strings.HasPrefix(cc.Result, "failed: authenticated gateway requests are paused") {
		t.Fatalf("the refused attempt %+v", cc)
	}
	st := r.m.Status()
	if n := st.Notification; n == nil || !n.Enabled || n.Seq == 0 || !strings.Contains(n.Err, "trust-cert") {
		t.Fatalf("notification %+v", n)
	}
	if s := st.Syslog; s == nil || s.State != syslogStateError || !strings.Contains(s.Problem, "was not checked: authenticated gateway requests are paused") {
		t.Fatalf("syslog %+v", s)
	}
	ran := false
	if err := r.m.withGatewayAuth(func() { ran = true }); !errors.Is(err, contracts.ErrGatewayCertRejected) || ran {
		t.Fatalf("withGatewayAuth while pending: %v (ran %v)", err, ran)
	}
}

// The operator's choice that could not be saved holds only until the monitor restarts; that is
// said also when the gateway's page could not be set - joined to the error that kept it.
func TestSetGatewaySyslogNotSavedNorSet(t *testing.T) {
	ctx := context.Background()
	for _, on := range []bool{false, true} {
		t.Run(onOff(on), func(t *testing.T) {
			r, sim, ip := enforceRig(t)
			if on {
				r.cfg.Gateway.EnforceSyslog = false
				ip.Store("")
				r.m.locked(func() { r.m.st.localIP = "" }) // no address: the page cannot be set
			} else {
				sim.update(func(s *syslogSim) {
					s.setting.Enabled, s.setting.Server, s.setting.Level = true, "192.168.1.71", "Notice"
					s.page = nil
					s.setErr = errors.New("gateway: Syslog page not understood: x after the Update round; Save not posted")
				})
			}
			r.m.opts.SaveConfig = func(*config.Config) error { return errors.New("disk full") }
			cc, err := r.m.SetGatewaySyslog(ctx, on, "web")
			want := fmt.Sprintf("gateway.enforce_syslog was set to %t but could not be saved, so it applies until the monitor restarts: disk full", on)
			if err == nil || !strings.Contains(err.Error(), want) || !strings.HasPrefix(cc.Result, "failed: ") ||
				!strings.Contains(err.Error(), strings.TrimPrefix(cc.Result, "failed: ")) {
				t.Fatalf("%+v %v", cc, err)
			}
			if on && !errors.Is(err, contracts.ErrUnavailable) {
				t.Fatalf("the gateway's error is kept: %v", err)
			}
			if r.cfg.Gateway.EnforceSyslog != on {
				t.Fatal("the choice applies until the monitor restarts")
			}
		})
	}
}

// The gateway sends its log to the hosts of its own network only: an address of this computer
// that it reaches through another router (a mesh router in router mode) is never set. The route
// to the gateway tells; when it cannot be looked up, the gateway the network adapter names does.
// SYSLOG_SETTING_FAILED says why, the operator's change is refused the same way, and no reading
// asks for further checks: the page is set once the address changes.
func TestSyslogTargetMustBeOnTheGatewaysNetwork(t *testing.T) {
	ctx := context.Background()
	viaMesh := func(netip.Addr) (routeInfo, error) {
		return routeInfo{IfIndex: 12, IfName: "Wi-Fi", NextHop: netip.MustParseAddr("10.0.0.1")}, nil
	}
	noRoute := func(netip.Addr) (routeInfo, error) {
		return routeInfo{}, errors.New("GetBestRoute2: Element not found.")
	}
	for _, tc := range []struct {
		name   string
		route  routeLookup
		ip, gw string // this computer's address and the gateway its network adapter names
		why    string // "": set
	}{
		{"behind a mesh router", viaMesh, "10.0.0.5", "10.0.0.1", "it reaches the gateway 192.168.1.254 through another router (10.0.0.1)"},
		{"behind a mesh router, the route not known", noRoute, "10.0.0.5", "10.0.0.1", "its network adapter's gateway is 10.0.0.1, not the AT&T gateway 192.168.1.254"},
		{"behind a mesh router, no route lookup", nil, "10.0.0.5", "10.0.0.1", "its network adapter's gateway is 10.0.0.1"},
		{"on the gateway's network", viaGatewayRoute, "192.168.1.71", "192.168.1.254", ""},
		{"on the gateway's network: the route wins", viaGatewayRoute, "192.168.1.71", "192.168.1.2", ""},
		{"the route not known, the adapter names the gateway", noRoute, "192.168.1.71", "192.168.1.254", ""},
		{"the route not known, the adapter names none", noRoute, "192.168.1.71", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, nil, nil)
			r.cfg.Gateway.AccessCodeProtected = "protected-blob"
			r.m.route = tc.route
			r.pr.link = func() (model.LocalLink, []byte, error) {
				return model.LocalLink{Interface: "Wi-Fi", Type: "wifi", State: "connected", LocalIP: tc.ip, GatewayIP: tc.gw}, nil, nil
			}
			r.m.checkLocalLink(ctx, false)
			_ = r.m.kNotif.take()
			newSyslogSim(r.gw, realSyslogOff(), nil)
			if err := r.m.checkNotification(ctx); err != nil {
				t.Fatal(err)
			}
			sets, _ := r.gw.syslogSets()
			if tc.why == "" {
				if len(sets) != 1 || sets[0] != targetAt(tc.ip, "Notice") {
					t.Fatalf("set %+v", sets)
				}
				return
			}
			if len(sets) != 0 {
				t.Fatalf("set %+v: the gateway cannot send to %s", sets, tc.ip)
			}
			notOn := "this computer (" + tc.ip + ") is not on the gateway's network: "
			read := decode[model.GatewayEvent](t, lastOfType(t, r, model.TypeGatewayEvent))
			mustContain(t, "the read", read.Detail, "the monitor (gateway.enforce_syslog) cannot set it: "+notOn, tc.why)
			st := r.m.Status()
			c, ok := hasCondition(st, condSyslogSettingFailed)
			if !ok {
				t.Fatalf("conditions %+v", st.Conditions)
			}
			mustContain(t, "the condition", c.Message, notOn, tc.why, "so the gateway could not send its log to it",
				"It sets the page once this computer is on the gateway's network")
			if !strings.Contains(st.Syslog.Problem, notOn) {
				t.Fatalf("status %+v", st.Syslog)
			}
			// No reading asks for a check while the address stays: each check logs in.
			r.m.checkLocalLink(ctx, false)
			if reasons := r.m.kNotif.take(); len(reasons) != 0 {
				t.Fatalf("a settings check was asked for: %v", reasons)
			}
			cc, err := r.m.SetGatewaySyslog(ctx, true, "web")
			if !errors.Is(err, contracts.ErrUnavailable) || !strings.Contains(err.Error(), notOn) || cc.Result != "failed: "+err.Error() {
				t.Fatalf("%+v %v", cc, err)
			}
			if _, sets := r.gw.syslogReads(); sets != 0 {
				t.Fatal("set for the operator")
			}
		})
	}
}

// The operator's "Stop sending" turns enforcement off before the page is switched off: when that
// fails, the switch-off waits and the settings checks that follow make it - SYSLOG_SETTING_FAILED
// stays until one succeeds -, also after a restart (the records tell). A check that finds the page
// off, or the operator choosing on, ends the wait.
func TestSyslogFailedSwitchOffIsMadeLater(t *testing.T) {
	ctx := context.Background()
	sending := func(s *syslogSim) {
		s.setting.Enabled, s.setting.Server, s.setting.Level = true, "192.168.1.71", "Notice"
		s.page = nil
	}
	const asker = "operator via web"
	t.Run("made by the next checks", func(t *testing.T) {
		r, sim, _ := enforceRig(t)
		fail := errors.New("gateway: POST syslog.ha (Update): the POST was answered with HTTP 500 Internal Server Error; Save not posted")
		sim.update(sending)
		sim.update(func(s *syslogSim) { s.setErr = fail })
		cc, err := r.m.SetGatewaySyslog(ctx, false, asker)
		if err != fail || cc.After != "off" || cc.Result != "failed: "+fail.Error() {
			t.Fatalf("%+v %v", cc, err)
		}
		if r.cfg.Gateway.EnforceSyslog || offDue(r) != asker {
			t.Fatalf("enforce %v, waiting %q", r.cfg.Gateway.EnforceSyslog, offDue(r))
		}
		c, ok := hasCondition(r.m.Status(), condSyslogSettingFailed)
		if !ok {
			t.Fatal("no SYSLOG_SETTING_FAILED")
		}
		mustContain(t, "the condition", c.Message, "could not switch the gateway's Syslog page off as "+asker+" asked",
			"The gateway may still send its log to this computer. It tries again at the next settings check")

		// The next check tries again; the gateway still fails: still shown, since the first failure.
		if err := r.m.checkNotification(ctx); err != nil {
			t.Fatal(err)
		}
		if wants, _ := r.gw.syslogSets(); len(wants) != 2 || wants[1] != (model.SyslogTarget{}) {
			t.Fatalf("SetSyslog %+v: the switch-off was not tried again", wants)
		}
		b := lastOfType(t, r, model.TypeConfigChange)
		if again := decode[model.ConfigChange](t, b); again.Actor != "monitor (retrying the switch-off asked for by operator via web)" ||
			again.After != "off" || again.Result != "failed: "+fail.Error() {
			t.Fatalf("the check's attempt %+v", again)
		}
		c2, ok := hasCondition(r.m.Status(), condSyslogSettingFailed)
		if !ok || c2.Since != c.Since || c2.Seq != b.Seq {
			t.Fatalf("condition %+v (first %+v)", c2, c)
		}
		mustContain(t, "the condition", c2.Message, "off as "+asker+" asked")

		// A restart: the switch-off still waits, from the records.
		r2 := newRig(t, r.cfg, r.led)
		r2.m.rebuild(time.Now())
		if got := offDue(r2); got != asker {
			t.Fatalf("rebuilt: waiting %q", got)
		}

		// The gateway works again: the check switches it off, and the condition ends.
		sim.update(func(s *syslogSim) { s.setErr = nil })
		if err := r.m.checkNotification(ctx); err != nil {
			t.Fatal(err)
		}
		if got, _ := sim.current(); got.Enabled {
			t.Fatal("still on")
		}
		mustContain(t, "the change", decode[model.GatewayEvent](t, lastOfType(t, r, model.TypeGatewayEvent)).Detail,
			"switched off by the monitor (retrying the switch-off operator via web asked for): Syslog on -> off.")
		st := r.m.Status()
		if _, bad := hasCondition(st, condSyslogSettingFailed); bad || offDue(r) != "" ||
			st.Syslog.Problem != "the gateway does not send its log to a syslog server (its Syslog setting is off)" {
			t.Fatalf("status %+v conditions %+v", st.Syslog, st.Conditions)
		}
		// Nothing waits any more, after a restart either; the next check only reads.
		if err := r.m.checkNotification(ctx); err != nil {
			t.Fatal(err)
		}
		if _, sets := r.gw.syslogReads(); sets != 3 {
			t.Fatalf("%d changes", sets)
		}
		r3 := newRig(t, r.cfg, r.led)
		r3.m.rebuild(time.Now())
		if got := offDue(r3); got != "" {
			t.Fatalf("rebuilt: waiting %q", got)
		}
	})
	t.Run("the state cache keeps it", func(t *testing.T) {
		r, sim, _ := enforceRig(t)
		sim.update(sending)
		sim.update(func(s *syslogSim) { s.setErr = errors.New("gateway: login rejected") })
		if _, err := r.m.SetGatewaySyslog(ctx, false, asker); err == nil {
			t.Fatal("error expected")
		}
		r.m.writeCache()
		r2 := newRigWith(t, r.cfg, r.led, func(o *Options) { o.StateDir = r.m.opts.StateDir })
		r2.m.rebuild(time.Now())
		if got := offDue(r2); got != asker {
			t.Fatalf("rebuilt from the cache: waiting %q", got)
		}
	})
	t.Run("a check that finds the page off ends the wait", func(t *testing.T) {
		r, sim, _ := enforceRig(t)
		sim.update(sending)
		sim.update(func(s *syslogSim) { s.setErr = errors.New("gateway: login rejected") })
		if _, err := r.m.SetGatewaySyslog(ctx, false, asker); err == nil {
			t.Fatal("error expected")
		}
		sim.update(func(s *syslogSim) { s.setting.Enabled, s.setErr = false, nil }) // switched off by hand
		if err := r.m.checkNotification(ctx); err != nil {
			t.Fatal(err)
		}
		if _, sets := r.gw.syslogReads(); sets != 1 {
			t.Fatalf("%d changes", sets)
		}
		if _, bad := hasCondition(r.m.Status(), condSyslogSettingFailed); bad || offDue(r) != "" {
			t.Fatalf("waiting %q, conditions %+v", offDue(r), r.m.Status().Conditions)
		}
	})
	t.Run("the operator choosing on ends the wait", func(t *testing.T) {
		r, sim, _ := enforceRig(t)
		sim.update(sending)
		sim.update(func(s *syslogSim) { s.setErr = errors.New("gateway: login rejected") })
		if _, err := r.m.SetGatewaySyslog(ctx, false, asker); err == nil {
			t.Fatal("error expected")
		}
		sim.update(func(s *syslogSim) { s.setErr = nil })
		cc, err := r.m.SetGatewaySyslog(ctx, true, "operator via cli")
		if err != nil || cc.Result != "unchanged: the gateway already sends its log to this computer" || offDue(r) != "" {
			t.Fatalf("%+v %v, waiting %q", cc, err, offDue(r))
		}
		if _, bad := hasCondition(r.m.Status(), condSyslogSettingFailed); bad {
			t.Fatal("SYSLOG_SETTING_FAILED")
		}
		if err := r.m.checkNotification(ctx); err != nil {
			t.Fatal(err)
		}
		if got, _ := sim.current(); !got.Enabled {
			t.Fatal("switched off against the operator's latest choice")
		}
	})
}

// NO_ACCESS_CODE and GATEWAY_CERT_CHANGED name both settings behind the gateway's login - the
// outage redirect and the Syslog page.
func TestConditionsNameBothGatewaySettings(t *testing.T) {
	for _, c := range []model.Condition{noAccessCodeCondition(""), noAccessCodeCondition("cannot decrypt")} {
		mustContain(t, c.Code, c.Message, "the outage redirect (Broadband Status Notification) and the Syslog page - cannot be checked or set",
			"(att-monitor set-access-code)")
	}
	mustContain(t, condGatewayCertChanged, certChangedCondition(fpB, time.Time{}, 0).Message,
		"authenticated requests (checking and setting the outage-redirect and Syslog settings) are paused", fpB)
}

// TestSyslogEnforcementNeedsTheReceiver: with the receiver off (syslog.enabled false) the
// settings check only reads the page - pointing the gateway at a computer that does not listen
// would lose its messages - and the operator's "on" is refused until the receiver is on.
func TestSyslogEnforcementNeedsTheReceiver(t *testing.T) {
	ctx := context.Background()
	r, sim, _ := enforceRig(t)
	r.cfg.Syslog.Enabled = false
	if err := r.m.checkNotification(ctx); err != nil {
		t.Fatal(err)
	}
	if sets, _ := r.gw.syslogSets(); len(sets) != 0 {
		t.Fatalf("SetSyslog calls %+v with the receiver off", sets)
	}
	if got, posts := sim.current(); got.Enabled || posts != 0 {
		t.Fatalf("the gateway's page %+v (%d posts)", got, posts)
	}
	if s := r.m.Status().Syslog; s != nil && s.Enforce {
		t.Fatalf("status says enforced with the receiver off: %+v", s)
	}
	_, err := r.m.SetGatewaySyslog(ctx, true, "operator via web")
	if !errors.Is(err, contracts.ErrUnavailable) || !strings.Contains(err.Error(), "syslog.enabled is false") {
		t.Fatalf("on with the receiver off: %v", err)
	}
	if sets, _ := r.gw.syslogSets(); len(sets) != 0 {
		t.Fatalf("SetSyslog calls %+v after a refused on", sets)
	}
}
