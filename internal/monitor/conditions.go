package monitor

import (
	"fmt"
	"strings"
	"time"

	"attmonitor/internal/model"
)

// Condition codes not derived from gateway alarm flags.
const (
	condNotificationRedirectOn = "NOTIFICATION_REDIRECT_ON"
	condGatewayCertChanged     = "GATEWAY_CERT_CHANGED"
	condNoAccessCode           = "NO_ACCESS_CODE"
	condAnchorUntrusted        = "ANCHOR_UNTRUSTED"
	// LEDGER_WRITE_FAILING (critical): the evidence ledger refuses records - nothing is recorded.
	condLedgerWriteFailing = "LEDGER_WRITE_FAILING"
	// DISK_SPACE_LOW (warning, critical below 512 MB): the data volume is running out of space.
	condDiskSpaceLow = "DISK_SPACE_LOW"
	// EGRESS_NOT_VIA_GATEWAY (warning): this computer's internet traffic does not leave through
	// the AT&T gateway (a VPN, another adapter), so nothing it measures is attributed to AT&T.
	condEgressNotViaGateway = "EGRESS_NOT_VIA_GATEWAY"
	// CLOCK_OFFSET (warning, critical beyond 5 min): the latest clock check found this computer's
	// clock off against the internet time servers, and every record time comes from that clock.
	condClockOffset = "CLOCK_OFFSET"
)

// An SNTP offset (median of the answers of the latest clock check that got any) beyond
// clockOffsetWarn shows CLOCK_OFFSET as a warning; beyond clockOffsetCritical - the tolerance
// with which verification compares record times with trusted RFC 3161 time-stamps
// (ts_contradiction) - as critical (DESIGN §9 conditions).
const (
	clockOffsetWarn     = time.Minute
	clockOffsetCritical = 5 * time.Minute
)

// offsetDur converts an SNTP offset in milliseconds, saturating far beyond any real offset (a
// state cache is not evidence and may hold anything).
func offsetDur(ms int64) time.Duration {
	const lim = int64(100 * 365 * 24 * time.Hour / time.Millisecond)
	return time.Duration(min(max(ms, -lim), lim)) * time.Millisecond
}

// clockOffsetExceeds: an SNTP offset beyond clockOffsetWarn in either direction.
func clockOffsetExceeds(offMs int64) bool { return absDur(offsetDur(offMs)) > clockOffsetWarn }

// clockOffsetCondition is shown while the latest clock check with an answer from a time server
// (ref; an unanswered check measures nothing and leaves it standing) found this computer's clock
// more than clockOffsetWarn off. Since is the first check of the current run of such offsets.
func clockOffsetCondition(ref *clockRef) (model.Condition, bool) {
	if ref == nil || !clockOffsetExceeds(ref.OffsetMs) {
		return model.Condition{}, false
	}
	off := offsetDur(ref.OffsetMs) // server - local
	abs := absDur(off).Round(time.Second)
	about := fmt.Sprintf("%d s", int64(abs/time.Second))
	if abs >= 2*time.Minute {
		about += " (" + abs.String() + ")"
	}
	side := "behind"
	if off < 0 {
		side = "ahead of"
	}
	measured := fmt.Sprintf("clock check #%d", ref.Seq)
	if t, ok := parseTS(ref.TS); ok {
		measured += " at " + fmtHuman(t)
	}
	if ref.Answered > 0 {
		measured = fmt.Sprintf("median of %s in %s", plural(ref.Answered, "answer", "answers"), measured)
	}
	c := model.Condition{
		Code:     condClockOffset,
		Severity: "warning",
		Message: fmt.Sprintf("This computer's clock is off by about %s compared with internet time servers; evidence timestamps rely on it — fix the Windows time settings (the clock is %s them: %s).",
			about, side, measured),
		Since: ref.OffSince,
		Seq:   ref.Seq,
	}
	if c.Since == "" {
		c.Since = ref.TS
	}
	if absDur(off) > clockOffsetCritical {
		c.Severity = "critical"
		c.Message += " With more than 5 minutes of offset, verification will flag record times that contradict the RFC 3161 time-stamps (ts_contradiction)."
	}
	return c, true
}

// alarmMark is when a gateway alarm flag that is raised now was first reported in its current
// raised period, and the record that reported it: the gateway_event optical_alarm that raised it
// (or, until that is recorded, the snapshot that first showed it). It survives restarts of the
// monitor (rebuilt from the events in the ledger), so the dashboard's "since" does not move
// forward with every restart.
type alarmMark struct {
	Since time.Time `json:"since"`
	Seq   uint64    `json:"seq"`
}

// applyAlarmEvent folds a recorded gateway_event optical_alarm (in ledger order) into the marks:
// its After lists the flags raised from then on; a flag it raises is first reported by it, one
// it no longer lists is cleared.
func applyAlarmEvent(marks map[string]alarmMark, ev model.GatewayEvent, ref model.Ref) map[string]alarmMark {
	now := map[string]bool{}
	for _, c := range strings.Split(ev.After, ",") {
		if c = strings.TrimSpace(c); c != "" {
			now[c] = true
		}
	}
	before := map[string]bool{}
	for _, c := range strings.Split(ev.Before, ",") {
		before[strings.TrimSpace(c)] = true
	}
	at, ok := parseTS(ref.TS)
	out := make(map[string]alarmMark, len(now))
	for c := range now {
		m, had := marks[c]
		if !had || !before[c] {
			if !ok {
				at = m.Since
			}
			m = alarmMark{Since: at, Seq: ref.Seq}
		}
		out[c] = m
	}
	return out
}

// egressCondition is shown while the recorded route check shows this computer's internet
// traffic bypassing the AT&T gateway (DESIGN §9 egress).
func egressCondition(e *model.EgressCheck, since time.Time, seq uint64) (model.Condition, bool) {
	text := bypassText(e)
	if text == "" {
		return model.Condition{}, false
	}
	c := model.Condition{
		Code:     condEgressNotViaGateway,
		Severity: "warning",
		Message: "This computer's internet traffic does not go through the AT&T gateway: " + text +
			". While this lasts, nothing this computer measures on the Internet is attributed to AT&T (is a VPN or another network connection active?).",
		Seq: seq,
	}
	if !since.IsZero() {
		c.Since = fmtTS(since)
	}
	return c, true
}

// noAccessCodeCondition is shown while no gateway access code is stored, or the gateway client
// reported that the stored one cannot be used (contracts.ErrGatewayNoAccessCode; detail is
// its error) (DESIGN §9): the outage-redirect setting can then be neither checked nor enforced.
func noAccessCodeCondition(detail string) model.Condition {
	msg := "No gateway access code is configured, so the gateway's outage-redirect setting (Broadband Status Notification) cannot be checked or enforced (att-monitor set-access-code)"
	if detail != "" {
		msg = "The stored gateway access code could not be used (" + detail + "), so the gateway's outage-redirect setting (Broadband Status Notification) cannot be checked or enforced (att-monitor set-access-code)"
	}
	return model.Condition{Code: condNoAccessCode, Severity: "info", Message: msg}
}

// anchorUntrustedCondition is shown while the newest anchoring rounds produced only anchors
// whose time-stamp authority could not be verified: they are recorded, but they do not count
// as proof of time (DESIGN §11).
func anchorUntrustedCondition(rec *anchorRec, since string) model.Condition {
	tsa := rec.Anchor.TSAName
	if tsa == "" {
		tsa = rec.Anchor.TSAURL
	}
	why := "the time-stamp authority's certificate did not chain to a trusted root"
	if !rec.Anchor.Verified {
		why = "the token's signature or imprint did not verify"
	}
	if note := rec.Anchor.ChainNote; note != "" {
		why += " (" + note + ")"
	}
	return model.Condition{
		Code:     condAnchorUntrusted,
		Severity: "warning",
		Message: fmt.Sprintf("Time-stamps obtained but their authority could not be verified (latest: %s, covering record #%d: %s); they stay recorded but do not count as proof of time, so the ledger is treated as unanchored since the last trusted time-stamp",
			tsa, rec.Anchor.HeadSeq, why),
		Since: since,
		Seq:   rec.Seq,
	}
}

// certChangedCondition is shown while a changed gateway certificate waits for the
// operator's confirmation (DESIGN §2 certificate policy; critical per §9).
func certChangedCondition(pending string, since time.Time, seq uint64) model.Condition {
	c := model.Condition{
		Code:     condGatewayCertChanged,
		Severity: "critical",
		Message: fmt.Sprintf("AT&T gateway presented a TLS certificate (SHA-256 %s) different from the pinned one: status pages are still read, but authenticated requests (the notification setting) are paused until the certificate is confirmed (trust-cert)",
			pending),
		Seq: seq,
	}
	if !since.IsZero() {
		c.Since = fmtTS(since)
	}
	return c
}

// alarmMeasure maps the measurement part of an alarm code to the fiberstat DMI measurement
// name and to words for the dashboard message.
type alarmMeasure struct {
	measure string
	words   string
}

var alarmMeasures = map[string]alarmMeasure{
	"OPTICAL_RX":      {"Rx Power", "optical receive power"},
	"RX_POWER":        {"Rx Power", "optical receive power"},
	"OPTICAL_TX":      {"Tx Power", "optical transmit power"},
	"TX_POWER":        {"Tx Power", "optical transmit power"},
	"TEMPERATURE":     {"Temperature", "optical module temperature"},
	"TEMP":            {"Temperature", "optical module temperature"},
	"OPTICAL_TEMP":    {"Temperature", "optical module temperature"},
	"VCC":             {"Vcc", "optical module supply voltage"},
	"VOLTAGE":         {"Vcc", "optical module supply voltage"},
	"OPTICAL_VCC":     {"Vcc", "optical module supply voltage"},
	"TX_BIAS":         {"Tx Bias", "laser bias current"},
	"OPTICAL_TX_BIAS": {"Tx Bias", "laser bias current"},
	"BIAS":            {"Tx Bias", "laser bias current"},
}

// parseAlarmCode splits "OPTICAL_RX_LOW_ALARM" into ("OPTICAL_RX", "LOW", "ALARM").
func parseAlarmCode(code string) (key, dir, level string) {
	c := strings.ToUpper(code)
	switch {
	case strings.HasSuffix(c, "_ALARM"):
		level, c = "ALARM", strings.TrimSuffix(c, "_ALARM")
	case strings.HasSuffix(c, "_WARNING"):
		level, c = "WARNING", strings.TrimSuffix(c, "_WARNING")
	case strings.HasSuffix(c, "_WARN"):
		level, c = "WARNING", strings.TrimSuffix(c, "_WARN")
	}
	switch {
	case strings.HasSuffix(c, "_LOW"):
		dir, c = "LOW", strings.TrimSuffix(c, "_LOW")
	case strings.HasSuffix(c, "_HIGH"):
		dir, c = "HIGH", strings.TrimSuffix(c, "_HIGH")
	}
	return c, dir, level
}

func conditionSeverity(code string) string {
	_, _, level := parseAlarmCode(code)
	switch level {
	case "ALARM":
		return "critical"
	case "WARNING":
		return "warning"
	}
	return "info"
}

func normName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		if r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return strings.Trim(b.String(), "_")
}

func findMeasure(f *model.FiberStatus, key string) (*model.DMIMeasure, string) {
	words := strings.ToLower(strings.ReplaceAll(key, "_", " "))
	name := ""
	if am, ok := alarmMeasures[key]; ok {
		name, words = am.measure, am.words
	}
	if f == nil {
		return nil, words
	}
	for i := range f.Measures {
		m := &f.Measures[i]
		n := normName(m.Name)
		if (name != "" && strings.EqualFold(m.Name, name)) || n == key || "OPTICAL_"+n == key {
			return m, words
		}
	}
	return nil, words
}

// formatMeasure renders a raw DMI value in its unit.
func formatMeasure(v int64, unit, name string) string {
	u := strings.ToLower(unit)
	if u == "" {
		switch strings.ToLower(name) {
		case "rx power", "tx power":
			u = "0.1dbm"
		}
	}
	switch u {
	case "0.1dbm":
		return fmt.Sprintf("%.1f dBm", float64(v)/10)
	case "c":
		return fmt.Sprintf("%d °C", v)
	case "v":
		return fmt.Sprintf("%d V", v)
	case "ma":
		return fmt.Sprintf("%d mA", v)
	case "":
		return fmt.Sprint(v)
	}
	return fmt.Sprintf("%d %s", v, unit)
}

// conditionMessage words a gateway alarm flag, e.g. "AT&T gateway reports optical receive
// power -31.5 dBm, below its alarm threshold -29.5 dBm".
func conditionMessage(code string, s *model.GatewaySnapshot) string {
	key, dir, level := parseAlarmCode(code)
	var fiber *model.FiberStatus
	if s != nil {
		fiber = s.Fiber
	}
	m, words := findMeasure(fiber, key)
	levelWord := strings.ToLower(level)
	if levelWord == "" {
		levelWord = "alarm"
	}
	rel := "below"
	if dir == "HIGH" {
		rel = "above"
	}

	// Receive power: prefer the values the gateway package derived for exactly this purpose.
	if s != nil && dir == "LOW" && (key == "OPTICAL_RX" || key == "RX_POWER") && s.Derived.RxPowerX10 != nil {
		thr := s.Derived.RxLowAlarmX10
		if level == "WARNING" {
			thr = s.Derived.RxLowWarnX10
		}
		if thr == nil && m != nil {
			thr = threshold(m, dir, level).Threshold
		}
		msg := fmt.Sprintf("AT&T gateway reports %s %s", words, dbm(s.Derived.RxPowerX10))
		if thr != nil {
			return msg + fmt.Sprintf(", %s its %s threshold %s", rel, levelWord, dbm(thr))
		}
		return msg + fmt.Sprintf(" and flags it %s its %s threshold", rel, levelWord)
	}

	if m == nil || m.Current == nil {
		if dir == "" {
			return fmt.Sprintf("AT&T gateway flags %s", code)
		}
		return fmt.Sprintf("AT&T gateway flags %s %s its %s threshold (%s)", words, rel, levelWord, code)
	}
	msg := fmt.Sprintf("AT&T gateway reports %s %s", words, formatMeasure(*m.Current, m.Unit, m.Name))
	if t := threshold(m, dir, level); t.Threshold != nil {
		return msg + fmt.Sprintf(", %s its %s threshold %s", rel, levelWord, formatMeasure(*t.Threshold, m.Unit, m.Name))
	}
	return msg + fmt.Sprintf(" and flags it %s its %s threshold", rel, levelWord)
}

func threshold(m *model.DMIMeasure, dir, level string) model.Threshold {
	switch {
	case dir == "LOW" && level == "WARNING":
		return m.LowWarn
	case dir == "HIGH" && level == "WARNING":
		return m.HighWarn
	case dir == "HIGH":
		return m.HighAlarm
	default:
		return m.LowAlarm
	}
}

// buildConditions lists the persistent warnings for the dashboard: the gateway's own alarm
// flags (never our inference) and the outage-redirect setting. An alarm's Since and Seq are its
// first report in the current raised period (alarms; the latest reading is snap); when that
// lies before this run started (runStart), the readings stopped while the monitor was not
// running, and the message says that continuity during that time is unknown.
func buildConditions(snap *snapObs, alarms map[string]alarmMark, notif *model.NotificationState, runStart time.Time) []model.Condition {
	conds := []model.Condition{}
	if snap != nil && snap.Snap != nil {
		for _, code := range snap.Snap.Derived.Alarms {
			c := model.Condition{
				Code:     code,
				Severity: conditionSeverity(code),
				Message:  conditionMessage(code, snap.Snap),
				Seq:      snap.Seq,
			}
			if mk, ok := alarms[code]; ok && !mk.Since.IsZero() {
				c.Since = fmtTS(mk.Since)
				if mk.Seq != 0 {
					c.Seq = mk.Seq
				}
				if !runStart.IsZero() && mk.Since.Before(runStart) {
					c.Message += fmt.Sprintf(" (first reported at %s in record #%d and in every gateway reading since, latest #%d; the monitor was restarted at %s, so whether the flag stayed raised while it was not running is unknown)",
						fmtHuman(mk.Since), c.Seq, snap.Seq, fmtHuman(runStart))
				}
			}
			conds = append(conds, c)
		}
	}
	if notif != nil && notif.Enabled {
		conds = append(conds, model.Condition{
			Code:     condNotificationRedirectOn,
			Severity: "warning",
			Message:  "AT&T gateway Broadband Status Notification is ON: while the WAN is down the gateway redirects web browsing to AT&T pages",
			Since:    notif.CheckedAt,
			Seq:      notif.Seq,
		})
	}
	return conds
}
