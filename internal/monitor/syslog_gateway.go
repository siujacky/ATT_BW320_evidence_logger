package monitor

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// The gateway's Syslog setting, kept (docs/syslog-snmp-traffic.md §3.1, phase 2).
//
// The settings check reads the gateway's Syslog page right after the notification setting, in
// the same login session, and records every read (a gateway_event syslog_setting with the page).
// With gateway.enforce_syslog it then keeps the page at the target - Syslog on, Server IP Address
// this computer's IPv4 address toward the gateway, Server Port syslog.port, and the Log Level
// syslogTargetLevel chooses - through the gateway client's SetSyslog, which changes only the
// syslog controls, never posts a page it does not fully understand, reads the page back and fails
// unless it shows the target. The address must be one the gateway can send to: this computer
// must reach the gateway on the gateway's own network, not through another router
// (syslogUnreachable). A change is recorded as a gateway_event syslog_setting (before and
// after, what changed and who changed it, both pages) followed by a config_change (target
// gateway, both pages); a failed attempt as a config_change whose result says why, with the pages
// there are. SYSLOG_SETTING_FAILED is shown from a failure until a later attempt succeeds, or a
// check finds what is wanted (or enforcement off). A failure is not retried before the next
// settings check (daily, and within minutes after this computer's address toward the gateway
// changed): enforcement adds no login of its own, and the gateway client's login policy applies
// to every request.
//
// The operator's choice (SetGatewaySyslog) switches enforcement on or off - saved, and recorded as
// a config_change of gateway.enforce_syslog - and sets the page at once: to the target, or off.
// A switch-off that fails waits (syslogOffDue): enforcement is off then, so the settings checks
// that follow make it, until one succeeds or finds the page off, or the operator chooses on.
// While the page sends here, SYSLOG_NOT_ARRIVING says when no message from the gateway arrived for
// a day.

const (
	// syslogWhat names the gateway's Syslog setting in config_change records.
	syslogWhat = "syslog.ha (Syslog, Server IP Address, Server Port, Log Level)"
	// enforceSyslogWhat names the monitor setting gateway.enforce_syslog in config_change records.
	enforceSyslogWhat = "gateway.enforce_syslog (the monitor keeps the gateway's Syslog page sending its log to this computer)"
	// syslogEnforcer is the actor of the changes enforcement makes; syslogEnforcerWords names it
	// in the words of the records.
	syslogEnforcer      = "monitor (enforce_syslog)"
	syslogEnforcerWords = "the monitor (gateway.enforce_syslog)"
	// syslogQuietAfter: SYSLOG_NOT_ARRIVING once the gateway's setting sends its log here but no
	// message from the gateway arrived for this long.
	syslogQuietAfter = 24 * time.Hour
	// syslogRetryWords says when the monitor tries again after a failed attempt.
	syslogRetryWords = "It tries again at the next settings check (daily, and within minutes after this computer's address toward the gateway changes)"
	// maxSyslogLevel is the syslog severity of "Debug", the most detailed level (RFC 5424).
	maxSyslogLevel = 7
)

// noSyslogAddrError: the gateway's Syslog page cannot be set to send to this computer: this
// computer's IPv4 address toward the gateway is not known, or (why) the gateway could not send to
// it (syslogUnreachable). It matches contracts.ErrUnavailable (the change can be made later; the
// web answers 503).
type noSyslogAddrError struct{ why string }

func (e noSyslogAddrError) Error() string {
	if e.why != "" {
		return e.why
	}
	return "this computer's IPv4 address toward the gateway is not known (no reading of its network adapter has one)"
}

func (noSyslogAddrError) Unwrap() error { return contracts.ErrUnavailable }

// unreachableWhy returns why the gateway could not send to this computer's address when err (from
// syslogLocalAddr) says so; "" when the address is not known, or err is not about the address.
func unreachableWhy(err error) string {
	var ae noSyslogAddrError
	if errors.As(err, &ae) {
		return ae.why
	}
	return ""
}

// syslogWant is what a settings check or the operator wants of the gateway's Syslog page.
type syslogWant struct {
	enforce  bool // set the page when it shows anything else (false: only read it)
	on       bool // sending to this computer (false: off)
	operator bool // the operator asked: what keeps the page from being set is recorded and returned
	// asker is who asked for it ("" for enforcement): the operator - also when a settings check
	// makes a switch-off of theirs that failed (syslogOffDue).
	asker string
	actor string // the actor of the config_change records
	who   string // the same in the words of the records
	why   string // what asked for the read, in words after "read" ("" for the regular check)
}

// syslogSetFail is a failed attempt of the monitor to set the gateway's Syslog page, shown as
// SYSLOG_SETTING_FAILED until a later attempt succeeds, or a check finds what is wanted (or
// enforcement off): since when the attempts fail, the record of the latest one (its
// config_change, or the recorded read of the page that could not be set; 0: none), why in a few
// words (Status.Syslog.Problem) and the condition's message. It is not modified once published.
type syslogSetFail struct {
	since time.Time
	seq   uint64
	short string
	msg   string
}

// syslogFailKind is what kept the gateway's Syslog page from being set.
type syslogFailKind int

const (
	syslogFailSet  syslogFailKind = iota // the gateway client failed: login, the page or the change
	syslogFailPage                       // the page was read but not understood
	syslogFailAddr                       // this computer's address toward the gateway: not known, or the gateway cannot send to it
)

// syslogConfig returns whether the gateway's Syslog page is enforced - gateway.enforce_syslog,
// and only while the receiver is on (syslog.enabled): pointing the gateway at a computer that
// does not listen would only lose its messages - and gateway.syslog_level.
func (m *Monitor) syslogConfig() (enforce bool, level string) {
	m.cfgMu.Lock()
	defer m.cfgMu.Unlock()
	return m.cfg.Gateway.EnforceSyslog && m.cfg.Syslog.Enabled, m.cfg.Gateway.SyslogLevel
}

// syslogReceiverOn reports syslog.enabled.
func (m *Monitor) syslogReceiverOn() bool {
	m.cfgMu.Lock()
	defer m.cfgMu.Unlock()
	return m.cfg.Syslog.Enabled
}

// checkSyslogSetting is the settings check's part for the gateway's Syslog page (syncSyslog): it
// is read and recorded and, with gateway.enforce_syslog, set to the target when it shows anything
// else. Without it, a switch-off the operator asked for that failed (syslogOffDue) is made, when
// the page shows anything but off: the operator's choice turned enforcement off, so nothing else
// would. why (may be "") says what asked for the check. Caller holds notifMu.
func (m *Monitor) checkSyslogSetting(ctx context.Context, why string) {
	enforce, _ := m.syslogConfig()
	w := syslogWant{enforce: enforce, on: true, actor: syslogEnforcer, who: syslogEnforcerWords, why: why}
	if !enforce {
		m.mu.Lock()
		by := m.st.syslogOffDue
		m.mu.Unlock()
		if by != "" {
			w = syslogWant{enforce: true, asker: by, actor: syslogOffActor(by), who: syslogOffWho(by), why: why}
		}
	}
	_, _ = m.syncSyslog(ctx, w)
}

// syncSyslog reads the gateway's Syslog page (authenticated) and records the read: a
// gateway_event syslog_setting whose before is the setting as last recorded and whose after is
// the setting read - "unknown" when the page was not understood - with the page and what the
// monitor does with it. A read that fails is not recorded (Status.Syslog says why); so is one
// refused while a changed gateway certificate waits for confirmation (withGatewayAuth). With
// w.enforce a page that shows anything but what w wants is then set (changeSyslog); what keeps it
// from being set - the page not understood, this computer's address not known or not one the
// gateway can send to - shows as SYSLOG_SETTING_FAILED. For the operator (w.operator) it returns
// the gateway's config_change - the change, the failed attempt (recorded), or "unchanged" (not
// recorded) - with the error that kept the page from being set. Caller holds notifMu.
func (m *Monitor) syncSyslog(ctx context.Context, w syslogWant) (model.ConfigChange, error) {
	var (
		set model.SyslogSetting
		raw []byte
		err error
	)
	if aerr := m.withGatewayAuth(func() {
		sctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		set, raw, err = m.gw.Syslog(sctx)
	}); aerr != nil {
		err = aerr // nothing was read
	}
	if ctx.Err() != nil {
		return model.ConfigChange{}, ctx.Err()
	}
	now := m.now()
	if err != nil && len(raw) == 0 {
		problem := "the latest check could not read the gateway's Syslog page: " + errText(err)
		m.locked(func() { m.st.syslogErr = problem })
		if loud, n, since := m.syslogReadLog.fail(now, syslogReadReport); loud {
			m.log.Warn("cannot read the gateway's Syslog page; it is read again at the next settings check", "err", err, "failures", n, "since", since)
		} else {
			m.log.Debug("cannot read the gateway's Syslog page", "err", err, "failures", n)
		}
		if w.operator {
			return m.syslogNotSet(w, nil, model.SyslogTarget{}, false, nil, syslogFailSet, err)
		}
		return model.ConfigChange{}, nil
	}
	if rec, n, since := m.syslogReadLog.ok(); rec {
		m.log.Info("the gateway's Syslog page can be read again", "failures", n, "since", since)
	}
	// What is wanted of a page that was understood: the target - whose address may take a reading
	// of this computer's network adapter of its own - or off.
	var (
		target       model.SyslogTarget
		how          string
		known, write bool
		addrErr      error // why the target is not known
	)
	if err == nil && w.enforce {
		if w.on {
			_, level := m.syslogConfig()
			var addr string
			addr, addrErr = m.syslogLocalAddr(ctx)
			if target, how, known = syslogTarget(&set, addr, m.set.syslogPort, level); !known && addrErr == nil {
				addrErr = noSyslogAddrError{}
			}
		} else {
			known = true
		}
		write = known && !syslogMatches(set, target)
	}
	m.mu.Lock()
	localIP := m.st.localIP
	m.mu.Unlock()
	// The page that was read but not understood is the gateway client's error with the page
	// (gateway.ErrSyslogPage): recorded too, with the problem.
	read, rerr := m.recordSyslogRead(set, raw, err, localIP, w.why, syslogReadNote(w, target, known, write, addrErr), now)
	if rerr != nil {
		if w.operator {
			return model.ConfigChange{}, fmt.Errorf("the gateway's Syslog page was read, but the read could not be recorded, so nothing was changed: %w", rerr)
		}
		return model.ConfigChange{}, nil
	}
	switch {
	case !w.enforce:
		m.locked(func() { m.st.syslogSetFail = nil })
		return model.ConfigChange{}, nil
	case err != nil:
		if w.operator {
			return m.syslogNotSet(w, nil, target, known, raw, syslogFailPage, err)
		}
		m.noteSyslogFail(syslogFailPage, w, target, known, err, read.Seq)
		return model.ConfigChange{}, nil
	case !known:
		if unreachableWhy(addrErr) == "" {
			// No address: the first reading that has one asks for a settings check. An address
			// the gateway cannot send to is set once it changes (kickAddressChange) or at the
			// daily check - never in a loop of checks, each with a login.
			m.locked(func() { m.st.syslogNeedAddr = true })
		}
		m.log.Warn("the gateway's Syslog page is not set: no address of this computer that the gateway can send to; it is set once there is one",
			"why", errText(addrErr), "actor", w.actor)
		if w.operator {
			return m.syslogNotSet(w, &set, target, known, raw, syslogFailAddr, addrErr)
		}
		m.noteSyslogFail(syslogFailAddr, w, target, known, addrErr, read.Seq)
		return model.ConfigChange{}, nil
	case !write:
		m.locked(func() { m.st.syslogSetFail = nil })
		if !w.operator {
			return model.ConfigChange{}, nil
		}
		cc := model.ConfigChange{Target: "gateway", What: syslogWhat, Before: syslogSummary(set), After: syslogSummary(set), Actor: w.actor,
			Result: "unchanged: the gateway already sends its log to this computer"}
		if !w.on {
			cc.Result = "unchanged: the gateway's Syslog is already off"
		}
		return cc, nil
	}
	return m.changeSyslog(ctx, set, target, how, w)
}

// recordSyslogRead records a read of the gateway's Syslog page: a gateway_event syslog_setting
// whose before is the setting as last recorded and whose after is the setting read (set) - or
// "unknown", with the problem, when the page was read but not understood (perr) - with the page
// (raw) attached and note saying what the monitor does with it. It returns the read as recorded;
// when the record cannot be written, Status.Syslog says so.
func (m *Monitor) recordSyslogRead(set model.SyslogSetting, raw []byte, perr error, localIP, why, note string, now time.Time) (*syslogGwRead, error) {
	var blobs []string
	if len(raw) > 0 {
		if id, err := m.putBlob(raw); err == nil {
			blobs = append(blobs, id)
		}
	}
	m.mu.Lock()
	prev := m.st.syslogGw
	m.mu.Unlock()
	read := &syslogGwRead{}
	ev := model.GatewayEvent{Kind: model.GwEvSyslogSetting}
	if prev != nil {
		ev.Before = prev.After
	}
	if perr == nil {
		cp := set
		cp.Levels = slices.Clone(set.Levels)
		read.Setting = &cp
		ev.After, ev.Detail = syslogSummary(set), syslogDetail(set, localIP, m.set.syslogPort, why, note)
	} else {
		read.Problem = "the gateway's Syslog page was not understood: " + errText(perr)
		ev.After = syslogUnknown
		ev.Detail = fmt.Sprintf("Syslog page (Diagnostics > Syslog) read%s but not understood: %s; the page is kept with this record, and the monitor did not change the setting (it never posts a page it does not understand)",
			whyText(why), errText(perr))
	}
	read.After = ev.After
	if _, err := m.appendApply(model.TypeGatewayEvent, ev, blobs, func(ref model.Ref) {
		read.Seq, read.TS = ref.Seq, ref.TS
		m.st.syslogGw, m.st.syslogErr = read, ""
		m.st.syslogOffDue = syslogOffDueAfterEvent(m.st.syslogOffDue, ev)
		m.noteSyslogOKLocked(now, false)
	}); err != nil {
		m.locked(func() {
			m.st.syslogErr = "the gateway's Syslog setting was read but could not be recorded in the evidence ledger: " + errText(err)
		})
		return nil, err
	}
	if perr != nil {
		m.log.Warn("the gateway's Syslog page was not understood; the page is recorded", "err", perr)
	} else {
		m.log.Info("gateway syslog setting read", "setting", ev.After, "before", ev.Before)
	}
	return read, nil
}

// changeSyslog sets the gateway's Syslog page to target with the gateway client's SetSyslog (only
// the syslog controls change, and the page is read back) and records the outcome. A change: a
// gateway_event syslog_setting - before (the page as read just before), after, what changed, who
// changed it and how the level was chosen (how), with both pages - followed by a config_change
// (target gateway) with both pages; the status then follows the new setting. A failure: a
// config_change whose result says why, with the pages there are (the gateway client returns the
// page it read last once a POST may have reached the gateway), and SYSLOG_SETTING_FAILED; a
// switch-off that failed waits for the settings checks (syslogOffDueAfter). It returns the
// config_change and the gateway client's error as it is (joined with the error of a record that
// could not be written). Caller holds notifMu.
func (m *Monitor) changeSyslog(ctx context.Context, before model.SyslogSetting, target model.SyslogTarget, how string, w syslogWant) (model.ConfigChange, error) {
	var (
		pageBefore, pageAfter []byte
		err                   error
	)
	// A changed gateway certificate that a status read met since the page was read pauses the
	// change before any request (withGatewayAuth): a failed attempt like one the client refused.
	if aerr := m.withGatewayAuth(func() {
		sctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		pageBefore, pageAfter, err = m.gw.SetSyslog(sctx, target)
	}); aerr != nil {
		err = aerr
	}
	var blobs []string
	for _, page := range [][]byte{pageBefore, pageAfter} {
		if len(page) == 0 {
			continue
		}
		if id, perr := m.putBlob(page); perr == nil && !slices.Contains(blobs, id) {
			blobs = append(blobs, id)
		}
	}
	after := syslogAfter(before, target)
	cc := model.ConfigChange{Target: "gateway", What: syslogWhat, Before: syslogSummary(before), After: syslogSummary(after), Actor: w.actor}
	now := m.now()
	if err != nil {
		cc.Result = "failed: " + errText(err)
		var seq uint64
		_, aerr := m.appendApply(model.TypeConfigChange, cc, blobs, func(ref model.Ref) {
			seq = ref.Seq
			m.st.syslogOffDue = syslogOffDueAfter(m.st.syslogOffDue, cc)
			m.addEvidenceLocked(nil, model.TypeConfigChange, ref.Seq, model.EvidenceRef{Seq: ref.Seq, Type: model.TypeConfigChange, Note: "syslog " + cc.After + " (failed)"})
		})
		m.noteSyslogFail(syslogFailSet, w, target, true, err, seq)
		if aerr != nil { // not even the attempt could be recorded
			err = errors.Join(err, fmt.Errorf("the failed attempt could not be recorded: %w", aerr))
		}
		return cc, err
	}
	// The gateway client posts nothing when the page it reads already shows the target (the
	// setting changed since the read above): it then returns that page as both.
	posted := len(pageAfter) == 0 || !bytes.Equal(pageAfter, pageBefore)
	cc.Result = "verified"
	if !posted {
		cc.Result = "verified (nothing was posted: the page already showed it)"
	}
	m.mu.Lock()
	localIP := m.st.localIP
	m.mu.Unlock()
	ev := model.GatewayEvent{Kind: model.GwEvSyslogSetting, Before: cc.Before, After: cc.After,
		Detail: syslogChangeDetail(before, target, how, w, posted, localIP, m.set.syslogPort)}
	read := &syslogGwRead{After: ev.After, Setting: &after}
	_, eerr := m.appendApply(model.TypeGatewayEvent, ev, blobs, func(ref model.Ref) {
		read.Seq, read.TS = ref.Seq, ref.TS
		m.st.syslogGw, m.st.syslogErr, m.st.syslogSetFail = read, "", nil
		m.st.syslogOffDue = syslogOffDueAfterEvent(m.st.syslogOffDue, ev)
		m.st.syslogAwaitMsg = after.Enabled
		m.noteSyslogOKLocked(now, true)
	})
	_, cerr := m.appendApply(model.TypeConfigChange, cc, blobs, func(ref model.Ref) {
		m.st.syslogOffDue = syslogOffDueAfter(m.st.syslogOffDue, cc)
		m.addEvidenceLocked(nil, model.TypeConfigChange, ref.Seq, model.EvidenceRef{Seq: ref.Seq, Type: model.TypeConfigChange, Note: "syslog " + cc.After})
	})
	if aerr := errors.Join(eerr, cerr); aerr != nil {
		// The gateway applied the change, so the known setting follows the gateway; the missing
		// record is stated there and returned (contracts.ErrNotRecorded). Without its event (Seq
		// 0) the next check records the setting it reads.
		m.locked(func() {
			if eerr != nil {
				m.st.syslogGw, m.st.syslogSetFail = read, nil
				m.st.syslogAwaitMsg = after.Enabled
				m.noteSyslogOKLocked(now, true)
			}
			m.st.syslogErr = "the gateway's Syslog setting was changed (" + cc.After + "), but the change could not be recorded in the evidence ledger: " + errText(aerr)
		})
		m.log.Error("gateway syslog setting changed but not recorded", "after", cc.After, "actor", w.actor, "err", aerr)
		return cc, fmt.Errorf("the gateway's Syslog page was set (%s), but the change could not be recorded: %w: %w", cc.After, contracts.ErrNotRecorded, aerr)
	}
	m.log.Warn("gateway syslog setting changed", "before", cc.Before, "after", cc.After, "actor", w.actor, "result", cc.Result)
	return cc, nil
}

// syslogNotSet records the operator's change of the gateway's Syslog page that could not be made
// before anything was posted - the page could not be read or was not understood, or this
// computer's address is not known or not one the gateway can send to - as a failed config_change
// (with the page, when one was read), shows it as SYSLOG_SETTING_FAILED, and returns the change
// with err (a switch-off then waits for the settings checks). before is the setting read (nil:
// not known).
func (m *Monitor) syslogNotSet(w syslogWant, before *model.SyslogSetting, target model.SyslogTarget, known bool, page []byte, kind syslogFailKind, err error) (model.ConfigChange, error) {
	cc := model.ConfigChange{Target: "gateway", What: syslogWhat, Before: syslogUnknown, After: syslogWanted(w.on, target, known),
		Actor: w.actor, Result: "failed: " + errText(err)}
	if before != nil {
		cc.Before = syslogSummary(*before)
	}
	var blobs []string
	if len(page) > 0 {
		if id, perr := m.putBlob(page); perr == nil {
			blobs = append(blobs, id)
		}
	}
	var seq uint64
	_, aerr := m.appendApply(model.TypeConfigChange, cc, blobs, func(ref model.Ref) {
		seq = ref.Seq
		m.st.syslogOffDue = syslogOffDueAfter(m.st.syslogOffDue, cc)
		m.addEvidenceLocked(nil, model.TypeConfigChange, ref.Seq, model.EvidenceRef{Seq: ref.Seq, Type: model.TypeConfigChange, Note: "syslog " + cc.After + " (failed)"})
	})
	m.noteSyslogFail(kind, w, target, known, err, seq)
	if aerr != nil {
		err = errors.Join(err, fmt.Errorf("the failed attempt could not be recorded: %w", aerr))
	}
	return cc, err
}

// noteSyslogFail shows an attempt to set the gateway's Syslog page that failed (kind, err; seq:
// its record, 0 if none) as SYSLOG_SETTING_FAILED and logs it.
func (m *Monitor) noteSyslogFail(kind syslogFailKind, w syslogWant, target model.SyslogTarget, known bool, err error, seq uint64) {
	short, msg := syslogFailWords(kind, w, target, known, err, seq)
	now := m.now()
	m.locked(func() {
		f := &syslogSetFail{since: now, seq: seq, short: short, msg: msg}
		if p := m.st.syslogSetFail; p != nil {
			f.since = p.since
		}
		m.st.syslogSetFail = f
	})
	if kind != syslogFailAddr { // logged where it is found
		m.log.Error("the gateway's Syslog page could not be set", "wanted", syslogWanted(w.on, target, known), "actor", w.actor, "err", err)
	}
}

// syslogFailWords words a failed attempt to set the gateway's Syslog page for Status.Syslog
// (short) and SYSLOG_SETTING_FAILED (msg). seq is its record (0: none): the operator's failed
// attempt, or the check's read of the page that could not be set.
func syslogFailWords(kind syslogFailKind, w syslogWant, target model.SyslogTarget, known bool, err error, seq uint64) (short, msg string) {
	rec := ""
	switch {
	case seq == 0:
	case w.operator || kind == syslogFailSet:
		rec = fmt.Sprintf(" The attempt is in record #%d.", seq)
	default:
		rec = fmt.Sprintf(" The page as read is in record #%d.", seq)
	}
	switch {
	case kind == syslogFailAddr:
		why, then := noSyslogAddrError{}.Error(), "It sets the page once a reading of this computer's network adapter has the address."
		if u := unreachableWhy(err); u != "" {
			why, then = u, "It sets the page once this computer is on the gateway's network (a settings check follows within minutes after this computer's address toward the gateway changes)."
		}
		short = "the monitor cannot set it: " + why
		msg = "The monitor cannot set the gateway's Syslog page to send its log to this computer: " + why + ". " + then + rec
	case kind == syslogFailPage:
		short = "the monitor cannot set it: the page was not understood"
		msg = fmt.Sprintf("The monitor cannot set the gateway's Syslog page: the page was read but not understood (%s), and the monitor never posts a page it does not understand (did the gateway's firmware change?).%s",
			errText(err), rec)
	case !w.on:
		// The switch-off waits (syslogOffDue): the settings checks make it.
		short = "the monitor could not switch it off: " + errText(err)
		msg = fmt.Sprintf("The monitor could not switch the gateway's Syslog page off as %s asked: %s. The gateway may still send its log to this computer. %s.%s",
			cmp.Or(w.asker, w.who), errText(err), syslogRetryWords, rec)
	default:
		dest := "this computer"
		if known {
			dest += " (" + targetText(target) + ")"
		}
		short = "the monitor could not set it: " + errText(err)
		msg = fmt.Sprintf("The monitor could not set the gateway's Syslog page to send its log to %s: %s. %s.%s", dest, errText(err), syslogRetryWords, rec)
	}
	return short, msg
}

// noteSyslogOKLocked keeps when the gateway's Syslog setting, as last recorded, began to send to
// this computer (SYSLOG_NOT_ARRIVING counts from then): now when it does and did not before - or
// when it was just set (set) - and zero while it does not. Caller holds mu.
func (m *Monitor) noteSyslogOKLocked(now time.Time, set bool) {
	ok := false
	if gw := m.st.syslogGw; gw != nil && gw.Setting != nil {
		state, _ := syslogTargetState(*gw.Setting, m.st.localIP, m.set.syslogPort)
		ok = state == syslogStateOK
	}
	switch {
	case !ok:
		m.st.syslogOKSince = time.Time{}
	case set || m.st.syslogOKSince.IsZero():
		m.st.syslogOKSince = now
	}
}

// syslogLocalAddr returns this computer's IPv4 address toward the gateway as the Syslog page is
// to name it: that of the latest local-link reading, or - while no reading had one (the settings
// check at the start may come before the first reading, and the CLI takes none) - that of a
// reading of its own. Its error (a noSyslogAddrError) says why there is none: no reading has a
// usable address, or the gateway could not send to it (syslogUnreachable). Once there is a usable
// address, no reading needs to ask for a settings check for it (syslogNeedAddr).
func (m *Monitor) syslogLocalAddr(ctx context.Context) (string, error) {
	m.mu.Lock()
	ip, adapterGW := m.st.localIP, ""
	if l := m.st.lastLink; l != nil && l.LocalIP == ip {
		adapterGW = l.GatewayIP
	}
	m.mu.Unlock()
	if ip == "" {
		lctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		link, _, _ := m.prober.LocalLink(lctx, m.set.gwHost)
		cancel()
		if link.LocalIP != "" {
			m.locked(func() {
				if m.st.localIP == "" {
					m.st.localIP = link.LocalIP
				}
				ip = m.st.localIP
			})
			if ip == link.LocalIP {
				adapterGW = link.GatewayIP
			}
		}
	}
	addr := usableIPv4(ip)
	if addr == "" {
		return "", noSyslogAddrError{}
	}
	m.locked(func() { m.st.syslogNeedAddr = false })
	if why := m.syslogUnreachable(addr, adapterGW); why != "" {
		return "", noSyslogAddrError{why: why}
	}
	return addr, nil
}

// syslogUnreachable says why the gateway could not send its log to this computer at ip ("" when
// it can, or when that cannot be told). The gateway sends to the hosts of its own network: this
// computer must reach it directly (on-link), not through another router - a mesh router or an
// extender in router mode, another network that routes to it. The route to the gateway tells
// (m.route); when it cannot be looked up, the gateway that the network adapter of the reading
// names (adapterGW, "" when none) does.
func (m *Monitor) syslogUnreachable(ip, adapterGW string) string {
	gw, err := netip.ParseAddr(strings.TrimSpace(m.set.gwHost))
	if err != nil || !gw.Unmap().Is4() {
		return ""
	}
	gw = gw.Unmap()
	if m.route != nil {
		if r, err := m.route(gw); err == nil {
			if hop := r.NextHop.Unmap(); hop.IsValid() && !hop.IsUnspecified() && hop != gw {
				return fmt.Sprintf("this computer (%s) is not on the gateway's network: it reaches the gateway %s through another router (%s), so the gateway could not send its log to it",
					ip, gw, hop)
			}
			return ""
		}
	}
	if a := usableIPv4(adapterGW); a != "" && a != gw.String() {
		return fmt.Sprintf("this computer (%s) is not on the gateway's network: its network adapter's gateway is %s, not the AT&T gateway %s, so the gateway could not send its log to it",
			ip, a, gw)
	}
	return ""
}

// SetGatewaySyslog implements contracts.SyslogControl.SetGatewaySyslog, the operator's choice for
// the gateway's Syslog page: enabled keeps it sending its log to this computer
// (gateway.enforce_syslog true) and sets it so now; disabled stops that (gateway.enforce_syslog
// false) and switches it off on the gateway. The monitor setting is saved (SaveConfig) and
// recorded as a config_change (target monitor) when it changes - nothing changes when that record
// cannot be written - and the page is then read, recorded and, when it shows anything else, set
// (syncSyslog). It returns the gateway's config_change - "unchanged" (not recorded) when the page
// already shows the choice, the failed attempt (recorded) otherwise - and the error that kept the
// page from being set: the gateway's login errors as they are, contracts.ErrUnavailable while
// this computer's address toward the gateway is not known or not one the gateway can send to.
// A switch-off that fails waits: the settings checks that follow make it (syslogOffDue). Like
// SetGatewayNotification it does not wait for a settings check or another change that is running
// (contracts.ErrBusy) and is refused while a changed gateway certificate waits for confirmation.
// A configuration that could not be saved applies until the monitor restarts: the change is then
// returned with that error - joined to the error that kept the page from being set, if any.
func (m *Monitor) SetGatewaySyslog(ctx context.Context, enabled bool, actor string) (model.ConfigChange, error) {
	actor, err := label("actor", actor)
	if err != nil {
		return model.ConfigChange{}, err
	}
	if actor == "" {
		actor = "operator"
	}
	// No settings check may run between the choice and the change: it would enforce the
	// previous choice. A check (or another change) in progress makes this one busy rather than
	// queue behind a login.
	if !m.notifMu.TryLock() {
		return model.ConfigChange{}, fmt.Errorf("a gateway settings check or change is already running: %w", contracts.ErrBusy)
	}
	defer m.notifMu.Unlock()
	if pending := m.pendingCert(); pending != "" {
		return model.ConfigChange{}, errCertPending(pending)
	}
	if err := ctx.Err(); err != nil {
		return model.ConfigChange{}, err
	}
	if enabled && !m.syslogReceiverOn() {
		return model.ConfigChange{}, fmt.Errorf("the syslog receiver is off (syslog.enabled is false in config.json), so the gateway is not pointed at this computer: %w", contracts.ErrUnavailable)
	}
	saveErr, err := m.setEnforceSyslog(enabled, actor)
	if err != nil {
		return model.ConfigChange{}, err
	}
	cc, err := m.syncSyslog(ctx, syslogWant{enforce: true, on: enabled, operator: true, asker: actor, actor: actor, who: actor,
		why: "for the change asked for by " + actor})
	if saveErr != nil {
		// Also when the page could not be set: the choice holds only until the monitor restarts
		// (config.json keeps the previous one), and nobody else would say so.
		err = errors.Join(err, fmt.Errorf("gateway.enforce_syslog was set to %t but could not be saved, so it applies until the monitor restarts: %w", enabled, saveErr))
	}
	return cc, err
}

// setEnforceSyslog saves the operator's choice gateway.enforce_syslog = on (SaveConfig) and
// records it as a config_change (target monitor); nothing changes when that record cannot be
// written. The value in force changes and records nothing. saveErr: the configuration could not
// be saved (the choice applies until the monitor restarts, and the record says so).
func (m *Monitor) setEnforceSyslog(on bool, actor string) (saveErr, err error) {
	m.cfgMu.Lock()
	before := m.cfg.Gateway.EnforceSyslog
	if before == on {
		m.cfgMu.Unlock()
		return nil, nil
	}
	m.cfg.Gateway.EnforceSyslog = on
	if m.opts.SaveConfig != nil {
		saveErr = m.opts.SaveConfig(m.cfg)
	}
	m.cfgMu.Unlock()
	cc := model.ConfigChange{Target: "monitor", What: enforceSyslogWhat, Before: strconv.FormatBool(before), After: strconv.FormatBool(on),
		Actor: actor, Result: "applied"}
	if saveErr != nil {
		cc.Result = "applied until the monitor restarts: the configuration could not be saved: " + errText(saveErr)
		m.log.Error("cannot save configuration", "err", saveErr)
	}
	if _, err := m.appendApply(model.TypeConfigChange, cc, nil, func(ref model.Ref) {
		m.st.syslogOffDue = syslogOffDueAfter(m.st.syslogOffDue, cc)
		m.addEvidenceLocked(nil, model.TypeConfigChange, ref.Seq, model.EvidenceRef{Seq: ref.Seq, Type: model.TypeConfigChange, Note: "enforce_syslog " + cc.After})
	}); err != nil {
		// Not recorded: undone, so that enforcement never changes without a ledger record.
		m.cfgMu.Lock()
		if m.cfg.Gateway.EnforceSyslog == on {
			m.cfg.Gateway.EnforceSyslog = before
			if m.opts.SaveConfig != nil {
				_ = m.opts.SaveConfig(m.cfg)
			}
		}
		m.cfgMu.Unlock()
		return nil, err
	}
	m.log.Warn("gateway syslog enforcement changed", "before", cc.Before, "after", cc.After, "actor", actor, "result", cc.Result)
	return saveErr, nil
}

// ---------------------------------------------------------------------------- a switch-off that waits

// The operator's switch-off of the gateway's Syslog page turns enforcement off before the page
// is switched off, so when that fails nothing would ever try again, while the gateway keeps
// sending its log here. Such a switch-off waits (state.syslogOffDue: who asked for it) until a
// settings check makes it (checkSyslogSetting), a read finds the page off, or the operator
// chooses on. Whether one waits follows the records alone - the same rules at run time and in
// the rebuild - so it survives a restart.

// syslogOffActorPrefix begins the actor of the records of a settings check's attempt to make a
// switch-off that waits (syslogOffActor).
const syslogOffActorPrefix = "monitor (retrying the switch-off asked for by "

// syslogOffActor is the actor of a settings check's attempt to make the switch-off that by asked
// for; syslogOffWho says it in the words of the records.
func syslogOffActor(by string) string { return syslogOffActorPrefix + by + ")" }

func syslogOffWho(by string) string {
	return "the monitor (retrying the switch-off " + by + " asked for)"
}

// syslogOffAsker returns who asked for the switch-off that actor tried to make, when actor is a
// settings check's (syslogOffActor).
func syslogOffAsker(actor string) (string, bool) {
	rest, ok := strings.CutPrefix(actor, syslogOffActorPrefix)
	if !ok {
		return "", false
	}
	by, ok := strings.CutSuffix(rest, ")")
	return by, ok && by != ""
}

// syslogOffDueAfter returns who asked for the switch-off of the gateway's Syslog page that waits
// ("" when none) once the config_change cc is recorded, due waiting before: a failed switch-off
// waits (a settings check's attempt keeps who asked for it); any other change of the page or
// attempt at it ends the wait, as does gateway.enforce_syslog switched on.
func syslogOffDueAfter(due string, cc model.ConfigChange) string {
	switch {
	case cc.Target == "monitor" && cc.What == enforceSyslogWhat && cc.After == "true":
		return ""
	case cc.Target != "gateway" || cc.What != syslogWhat:
		return due
	case cc.After == "off" && strings.HasPrefix(cc.Result, "failed"):
		if by, ok := syslogOffAsker(cc.Actor); ok {
			return by
		}
		return cmp.Or(cc.Actor, "operator")
	}
	return ""
}

// syslogOffDueAfterEvent: a recorded read or change of the gateway's Syslog page that shows it off
// ends the wait for a switch-off.
func syslogOffDueAfterEvent(due string, ev model.GatewayEvent) string {
	if ev.Kind == model.GwEvSyslogSetting && ev.After == "off" {
		return ""
	}
	return due
}

// ---------------------------------------------------------------------------- the target

// syslogTarget is the setting the monitor keeps on the gateway's Syslog page (§3.1): on, sending
// to this computer's IPv4 address toward the gateway (addr) on syslog.port, at the level
// syslogTargetLevel chooses from the page as read (s; nil: not known) and gateway.syslog_level
// (cfgLevel). ok is false while no usable IPv4 address of this computer is known; how says how
// the level was chosen.
func syslogTarget(s *model.SyslogSetting, addr string, port int, cfgLevel string) (t model.SyslogTarget, how string, ok bool) {
	ip := usableIPv4(addr)
	if ip == "" || port < 1 || port > 65535 {
		return model.SyslogTarget{}, "", false
	}
	var page model.SyslogSetting
	if s != nil {
		page = *s
	}
	level, how := syslogTargetLevel(page, cfgLevel)
	return model.SyslogTarget{Enabled: true, Server: ip, Port: port, Level: level}, how, true
}

// syslogTargetLevel chooses the Log Level the monitor sets, among the options the page offers
// (s.Levels, as labelled), never one it does not offer: gateway.syslog_level (want) when the page
// offers it (offeredLevel); else the level already selected while the page shows Syslog on; else
// an option named like "Informational"; else the most detailed option that is not "Debug", by
// syslog severity (Emergency 0 .. Debug 7). "" when none applies: the page's level is then left
// as it is. how says why, for the records.
func syslogTargetLevel(s model.SyslogSetting, want string) (level, how string) {
	note := ""
	if want = normSpace(want); want != "" {
		if l, ok := offeredLevel(s.Levels, want); ok {
			return l, "chosen by gateway.syslog_level"
		}
		if len(s.Levels) > 0 {
			note = fmt.Sprintf(" (gateway.syslog_level %q is not one of the page's levels: %s)", truncate(want, 64), truncate(strings.Join(s.Levels, ", "), 200))
		} else {
			note = fmt.Sprintf(" (gateway.syslog_level %q: the page's levels are not known)", truncate(want, 64))
		}
	}
	if cur := strings.TrimSpace(s.Level); s.Enabled && cur != "" {
		return cur, "the level already set" + note
	}
	for _, l := range s.Levels {
		if sev, ok := levelSeverity(l); ok && sev == 6 {
			return l, "the page's informational level" + note
		}
	}
	best, rank := "", -1
	for _, l := range s.Levels {
		if sev, ok := levelSeverity(l); ok && sev < maxSyslogLevel && sev > rank {
			best, rank = l, sev
		}
	}
	if best != "" {
		return best, "the most detailed level the page offers, Debug aside" + note
	}
	return "", "left as the page has it" + note
}

// offeredLevel returns the page's level option (levels, as labelled) that want names: the one
// with that label (case and spacing aside), else the only one of the same syslog severity - want
// may name a severity, or give its number: "info" or "6" for "Informational".
func offeredLevel(levels []string, want string) (string, bool) {
	w := normSpace(want)
	for _, l := range levels {
		if strings.EqualFold(normSpace(l), w) {
			return l, true
		}
	}
	sev, ok := levelSeverity(w)
	if n, err := strconv.Atoi(w); err == nil && n >= 0 && n <= maxSyslogLevel {
		sev, ok = n, true
	}
	if !ok {
		return "", false
	}
	var match []string
	for _, l := range levels {
		if s, known := levelSeverity(l); known && s == sev {
			match = append(match, l)
		}
	}
	if len(match) != 1 {
		return "", false
	}
	return match[0], true
}

// syslogSeverityWords maps the words of log level names to syslog severities (RFC 5424: 0
// Emergency .. 7 Debug).
var syslogSeverityWords = map[string]int{
	"emergency": 0, "emerg": 0, "panic": 0,
	"alert":    1,
	"critical": 2, "crit": 2,
	"error": 3, "err": 3,
	"warning": 4, "warn": 4,
	"notice":        5,
	"informational": 6, "information": 6, "info": 6,
	"debug": 7,
}

// levelSeverity returns the syslog severity a log level's label stands for, from its words
// ("Notice", "L5 - Notice", "warn"); ok is false when no word names one, or when they name
// several.
func levelSeverity(label string) (sev int, ok bool) {
	sev = -1
	words := strings.FieldsFunc(strings.ToLower(label), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
	for _, w := range words {
		s, known := syslogSeverityWords[w]
		if !known {
			continue
		}
		if sev >= 0 && s != sev {
			return 0, false
		}
		sev = s
	}
	return sev, sev >= 0
}

// syslogMatches reports whether the page as read (s) shows t: the switch and, when t is on, the
// server address, the port and - unless t leaves it - the level.
func syslogMatches(s model.SyslogSetting, t model.SyslogTarget) bool {
	return len(syslogChanges(s, t)) == 0
}

// syslogChanges lists what setting the page as read (s) to t changes, in the words of the
// records: "Syslog off -> on", "Server IP Address (empty) -> 192.168.1.71", ...
func syslogChanges(s model.SyslogSetting, t model.SyslogTarget) []string {
	var out []string
	if s.Enabled != t.Enabled {
		out = append(out, "Syslog "+onOff(s.Enabled)+" -> "+onOff(t.Enabled))
	}
	if !t.Enabled {
		return out
	}
	if !sameIP(s.Server, t.Server) {
		out = append(out, "Server IP Address "+shownValue(s.Server)+" -> "+t.Server)
	}
	if s.Port != t.Port {
		port := "(empty)"
		if s.Port != 0 {
			port = strconv.Itoa(s.Port)
		}
		out = append(out, fmt.Sprintf("Server Port %s -> %d", port, t.Port))
	}
	if t.Level != "" && !strings.EqualFold(normSpace(s.Level), normSpace(t.Level)) {
		out = append(out, "Log Level "+shownValue(s.Level)+" -> "+truncate(t.Level, 128))
	}
	return out
}

// syslogAfter is the setting the page shows once SetSyslog set the page as read (s) to t: only
// the syslog controls change, and a level t leaves stays as it was.
func syslogAfter(s model.SyslogSetting, t model.SyslogTarget) model.SyslogSetting {
	a := s
	a.Levels = slices.Clone(s.Levels)
	a.Enabled = t.Enabled
	if t.Enabled {
		a.Server, a.Port = t.Server, t.Port
		if t.Level != "" {
			a.Level = t.Level
		}
	}
	return a
}

// syslogWanted is the summary of what is wanted, as config_change records it: the target t when
// it is known, "on -> this computer" while it is not, or "off".
func syslogWanted(on bool, t model.SyslogTarget, known bool) string {
	switch {
	case !on:
		return "off"
	case known:
		return syslogSummary(syslogAfter(model.SyslogSetting{}, t))
	}
	return "on -> this computer"
}

// targetText says where t sends the log: "192.168.1.71:514 at level Notice".
func targetText(t model.SyslogTarget) string {
	out := syslogDest(model.SyslogSetting{Server: t.Server, Port: t.Port})
	if l := strings.TrimSpace(t.Level); l != "" {
		out += " at level " + truncate(l, 128)
	}
	return out
}

// shownValue quotes a value of the page for the records ("(empty)" when there is none).
func shownValue(v string) string {
	if v = strings.TrimSpace(v); v == "" {
		return "(empty)"
	}
	return truncate(v, 128)
}

// normSpace trims s and turns every run of white space into one space.
func normSpace(s string) string { return strings.Join(strings.Fields(s), " ") }

// usableIPv4 returns s as an IPv4 address another host can send to (not unspecified, loopback,
// link-local, multicast or broadcast), else "".
func usableIPv4(s string) string {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || a.Zone() != "" {
		return ""
	}
	if a = a.Unmap(); !a.Is4() || !a.IsGlobalUnicast() {
		return ""
	}
	return a.String()
}

// ---------------------------------------------------------------------------- the records' words

// syslogReadNote says, for the record of a read of the gateway's Syslog page, what the monitor
// does with the setting read: nothing (not enforced, or already as wanted), sets it to target
// (write), or cannot (addrErr: this computer's address is not known, or not one the gateway can
// send to).
func syslogReadNote(w syslogWant, target model.SyslogTarget, known, write bool, addrErr error) string {
	switch {
	case !w.enforce:
		return "read only: gateway.enforce_syslog is off, so the monitor does not change the setting"
	case w.on && !known && unreachableWhy(addrErr) != "":
		return w.who + " cannot set it: " + unreachableWhy(addrErr)
	case w.on && !known:
		return w.who + " cannot set it while this computer's address toward the gateway is not known"
	case !write && w.asker != "":
		return "this is what " + w.asker + " asked for, so nothing is changed"
	case !write:
		return "this is the setting the monitor keeps (gateway.enforce_syslog), so nothing is changed"
	case !target.Enabled:
		return w.who + " switches it off now"
	}
	return w.who + " sets it now to send its log to " + targetText(target)
}

// syslogChangeDetail words a change of the gateway's Syslog page from the page as read (before) to
// t for its gateway_event: who changed what, the setting the page read back shows, how the level
// was chosen (how) and, when the gateway client posted nothing (posted false), that the page
// already showed it.
func syslogChangeDetail(before model.SyslogSetting, t model.SyslogTarget, how string, w syslogWant, posted bool, localIP string, port int) string {
	var b strings.Builder
	verb, why := "set", w.why
	if !t.Enabled {
		verb = "switched off"
	}
	if w.operator {
		why = "" // the operator's change: the actor says it all
	}
	fmt.Fprintf(&b, "Syslog page (Diagnostics > Syslog) %s by %s%s: %s. ", verb, w.who, whyText(why), strings.Join(syslogChanges(before, t), "; "))
	if t.Enabled {
		b.WriteString("Read back after saving, the gateway sends its log to " + targetText(t))
		if state, _ := syslogTargetState(syslogAfter(before, t), localIP, port); state == syslogStateOK {
			b.WriteString(", which is this computer and the port its syslog receiver is set up for")
		}
		if t.Level != "" {
			b.WriteString("; level " + truncate(t.Level, 128) + ": " + how)
		} else {
			b.WriteString("; the level is " + how)
		}
	} else {
		b.WriteString("Read back after saving, the gateway does not send its log to a syslog server")
	}
	if !posted {
		b.WriteString(" (the page already showed this when it was set, so nothing was posted)")
	}
	b.WriteString(". The pages before and after the change are kept with this record.")
	return b.String()
}

// ---------------------------------------------------------------------------- conditions

// syslogSettingConditionsLocked returns SYSLOG_SETTING_FAILED while the latest attempt to set the
// gateway's Syslog page failed and SYSLOG_NOT_ARRIVING (info) while the receiver listens (addr) and
// the gateway's Syslog setting as last recorded sends its log to this computer, but no message
// from the gateway arrived for syslogQuietAfter - counted from the latest of this run's start,
// the time the setting began to send here and the newest message from the gateway (at its level
// the gateway may log little, or the messages may not get through). Caller holds mu.
func (m *Monitor) syslogSettingConditionsLocked(addr string, now time.Time) []model.Condition {
	var out []model.Condition
	if f := m.st.syslogSetFail; f != nil {
		out = append(out, model.Condition{Code: condSyslogSettingFailed, Severity: "warning", Message: f.msg, Since: fmtTS(f.since), Seq: f.seq})
	}
	gw := m.st.syslogGw
	if !m.syslogOn || addr == "" || gw == nil || gw.Setting == nil || m.st.syslogErr != "" {
		return out
	}
	if state, _ := syslogTargetState(*gw.Setting, m.st.localIP, m.set.syslogPort); state != syslogStateOK {
		return out
	}
	from := m.st.started
	for _, t := range []time.Time{m.st.syslogOKSince, m.st.syslogGwMsgAt} {
		if t.After(from) {
			from = t
		}
	}
	if from.IsZero() || now.Sub(from) < syslogQuietAfter {
		return out
	}
	little := "the gateway may log little"
	if l := strings.TrimSpace(gw.Setting.Level); l != "" {
		little = "at level " + truncate(l, 128) + " the gateway may log little"
	}
	out = append(out, model.Condition{
		Code:     condSyslogNotArriving,
		Severity: "info",
		Message: fmt.Sprintf("The gateway's Syslog setting sends its log to this computer (%s), but no message from the gateway has arrived since %s: %s, or its messages do not get through (is the Windows Firewall rule \"AT&T Internet Monitor syslog\" in place?).",
			syslogDest(*gw.Setting), fmtHuman(from), little),
		Since: fmtTS(from),
		Seq:   gw.Seq,
	})
	return out
}
