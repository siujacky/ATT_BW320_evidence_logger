package monitor

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// anchorDeadline bounds one anchoring round over all TSAs (each request also has its own
// timeout in the anchorer).
const anchorDeadline = 2 * time.Minute

// anchorLoop anchors right after startup (genesis or restart) and then every
// Anchoring.Interval while the Internet is reachable - the last cycle reached it (DESIGN §9
// INET_ANY: ONLINE, and DEGRADED too, so a long degradation is time-stamped like any other
// period); while offline (no internet probe answered), anchoring is deferred until the first
// cycle that reaches the Internet (docs/DESIGN.md §11). An open incident does not defer it.
func (m *Monitor) anchorLoop(ctx context.Context) {
	if m.anchorer == nil {
		return
	}
	m.mu.Lock()
	reason := "startup"
	if m.st.firstRun {
		reason = "genesis" // first monitor run on this ledger: anchor genesis/bootstrap now
	}
	m.mu.Unlock()
	next := time.Now()
	for {
		if !sleepUntil(ctx, next, nil) {
			return
		}
		if reason == "" {
			if !m.lastCycleReachedInternet() {
				next = time.Now().Add(m.set.fast) // deferred while offline
				continue
			}
			reason = "periodic"
		}
		var (
			anchors []model.Anchor
			err     error
		)
		m.safely("anchor", func() { anchors, err = m.anchor(ctx, reason) })
		if len(anchors) == 0 && ctx.Err() == nil {
			// Only a round without any anchor is retried early: one TSA that is down must not
			// multiply the anchors of the others.
			if loud, n, since := m.anchorFailLog.fail(m.now(), anchorFailReport); loud {
				m.log.Warn("anchoring failed; will retry", "reason", reason, "err", err, "failed_rounds", n, "since", since)
			} else {
				m.log.Debug("anchoring failed; will retry", "reason", reason, "err", err, "failed_rounds", n)
			}
			next = time.Now().Add(min(m.set.anchorInterval, m.anchorRetry))
		} else {
			if rec, n, since := m.anchorFailLog.ok(); rec && len(anchors) > 0 {
				m.log.Info("anchoring works again", "failed_rounds", n, "since", since)
			}
			next = time.Now().Add(m.set.anchorInterval)
		}
		reason = ""
	}
}

// lastCycleReachedInternet: the latest recorded cycle reached the Internet (DESIGN §9 INET_ANY:
// an internet probe answered; every ONLINE and DEGRADED cycle does), so the time-stamp
// authorities are presumably reachable too.
func (m *Monitor) lastCycleReachedInternet() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	var probes []model.ProbeResult
	if s := m.st.lastSample; s != nil {
		probes = s.Probes
	}
	return inetReachable(m.st.lastVerdict.State, probes)
}

// errAnchoringDisabled: no Anchorer, or Anchoring.Enabled is false.
var errAnchoringDisabled = fmt.Errorf("anchoring is disabled: %w", contracts.ErrUnavailable)

// anchor time-stamps the current ledger head (waiting for a round in progress to finish).
func (m *Monitor) anchor(ctx context.Context, reason string) ([]model.Anchor, error) {
	if m.anchorer == nil {
		return nil, errAnchoringDisabled
	}
	m.anchorMu.Lock()
	defer m.anchorMu.Unlock()
	return m.anchorHead(ctx, reason)
}

// anchorHead asks every configured TSA to time-stamp the current ledger head and appends one
// anchor record per token obtained. As contracts.Actions.AnchorNow specifies, a partial
// success returns the anchors AND an error naming the TSAs that failed; no anchor at all
// returns (nil, error). Caller holds anchorMu.
func (m *Monitor) anchorHead(ctx context.Context, reason string) ([]model.Anchor, error) {
	head := m.led.Head()
	digest, err := hex.DecodeString(head.Hash)
	if err != nil || len(digest) != 32 {
		return nil, fmt.Errorf("ledger head hash %q is not a SHA-256 digest", head.Hash)
	}
	actx, cancel := context.WithTimeout(ctx, anchorDeadline)
	results := m.anchorer.Timestamp(actx, digest)
	cancel()

	var anchors []model.Anchor
	var errs []error
	var untrusted []string // tokens recorded that do not count as proof of time
	for _, r := range results {
		if r.Err != nil || len(r.Token) == 0 {
			if r.Err == nil {
				r.Err = errors.New("empty token")
			}
			errs = append(errs, fmt.Errorf("%s: %w", r.URL, r.Err))
			continue
		}
		info, verr := m.anchorer.VerifyToken(r.Token, digest)
		verified := verr == nil
		if !verified {
			untrusted = append(untrusted, fmt.Sprintf("%s: token did not verify (%v); recorded as unverified", r.URL, verr))
			info = r.Info
		} else if !info.ChainOK {
			untrusted = append(untrusted, fmt.Sprintf("%s: authority not chain-verified (%s); recorded, but it does not count as proof of time", r.URL, info.ChainNote))
		}
		blob, err := m.putBlob(r.Token)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: storing token: %w", r.URL, err))
			continue
		}
		a := model.Anchor{
			TSAURL:      r.URL,
			TSAName:     info.TSAName,
			HeadSeq:     head.Seq,
			HeadHash:    head.Hash,
			TokenSHA256: blob,
			Serial:      info.Serial,
			Policy:      info.Policy,
			Nonce:       info.Nonce,
			Verified:    verified,
			ChainOK:     verified && info.ChainOK,
			Reason:      reason,
		}
		if !a.ChainOK {
			a.ChainNote = anchorChainNote(info, verr)
		}
		if a.Nonce == "" {
			a.Nonce = r.Info.Nonce
		}
		if !info.GenTime.IsZero() {
			a.GenTime = fmtTS(info.GenTime)
		}
		if _, err := m.appendApply(model.TypeAnchor, a, []string{blob}, func(ref model.Ref) {
			m.noteAnchorLocked(anchorRec{Seq: ref.Seq, TS: ref.TS, Anchor: a})
		}); err != nil {
			errs = append(errs, fmt.Errorf("%s: recording anchor: %w", r.URL, err))
			continue
		}
		anchors = append(anchors, a)
	}
	m.logTSAProblems(untrusted, errs, len(anchors) > 0)
	if len(anchors) == 0 {
		if len(errs) == 0 {
			errs = append(errs, errors.New("no time-stamp authority answered"))
		}
		return nil, errors.Join(errs...)
	}
	m.log.Info("ledger head anchored", "reason", reason, "head_seq", head.Seq, "tsas", len(anchors))
	return anchors, errors.Join(errs...) // nil when every TSA answered
}

// logTSAProblems reports what went wrong with single time-stamp authorities in a round that
// produced anchors (one TSA down for weeks, or a TSA whose certificate never chains on this
// computer, would otherwise warn every round): through a log gate, when it starts, every few
// hours while it lasts, and when every TSA answers with a trusted token again. A round without
// any anchor is reported by its caller (anchorFailLog).
func (m *Monitor) logTSAProblems(untrusted []string, errs []error, anchored bool) {
	if !anchored {
		return
	}
	problems := slices.Clone(untrusted)
	for _, e := range errs {
		problems = append(problems, e.Error())
	}
	if len(problems) == 0 {
		if rec, n, since := m.tsaWarnLog.ok(); rec {
			m.log.Info("every time-stamp authority answers with a trusted token again", "rounds_with_problems", n, "since", since)
		}
		return
	}
	if loud, n, since := m.tsaWarnLog.fail(m.now(), tsaProblemReport); loud {
		m.log.Warn("time-stamp authority problems in this anchoring round", "problems", strings.Join(problems, "; "), "rounds", n, "since", since)
	} else {
		m.log.Debug("time-stamp authority problems in this anchoring round", "problems", strings.Join(problems, "; "), "rounds", n)
	}
}

// maxChainNoteBytes bounds model.Anchor.ChainNote (a diagnostic, not a document).
const maxChainNoteBytes = 300

// anchorChainNote says why an anchor does not count as proof of time (model.Anchor.ChainNote,
// recorded only when ChainOK is false): the token verifier's explanation of the TSA certificate
// chain (contracts.TokenInfo.ChainNote), or, for a token that did not verify at all, why.
func anchorChainNote(info contracts.TokenInfo, verr error) string {
	if verr != nil {
		return truncate("token not verified: "+errText(verr), maxChainNoteBytes)
	}
	return truncate(strings.TrimSpace(info.ChainNote), maxChainNoteBytes)
}

// noteAnchorLocked remembers a recorded anchor. Only a trusted one (Verified && ChainOK) is
// "the last anchor"; an untrusted one stays recorded but never counts, and while the newest
// anchoring rounds produced only untrusted anchors the dashboard shows ANCHOR_UNTRUSTED.
// Caller holds mu.
func (m *Monitor) noteAnchorLocked(rec anchorRec) {
	m.st.lastAnchor, m.st.lastUntrusted, m.st.untrustedSince =
		nextAnchorTrust(m.st.lastAnchor, m.st.lastUntrusted, m.st.untrustedSince, rec)
}

// nextAnchorTrust folds one anchor record (in ledger order) into the anchor trust state:
// the newest trusted anchor, the newest untrusted one and the ts of the first untrusted
// anchor after the newest trusted one.
func nextAnchorTrust(trusted, untrusted *anchorRec, since string, rec anchorRec) (*anchorRec, *anchorRec, string) {
	if anchorTrusted(rec.Anchor) {
		return &rec, untrusted, since
	}
	if !anchorsUntrusted(trusted, untrusted) {
		since = rec.TS // the first untrusted round after a trusted one (or ever)
	}
	return trusted, &rec, since
}

// anchorsUntrusted: the newest anchoring rounds produced no trusted anchor (rounds are told
// apart by the head they cover; one round appends one anchor per TSA for the same head).
func anchorsUntrusted(trusted, untrusted *anchorRec) bool {
	return untrusted != nil && (trusted == nil || untrusted.Anchor.HeadSeq > trusted.Anchor.HeadSeq)
}

// ---------------------------------------------------------------------------- heartbeat

func (m *Monitor) heartbeatLoop(ctx context.Context) {
	next := time.Now().Add(m.set.heartbeat)
	for {
		if !sleepUntil(ctx, next, nil) {
			return
		}
		m.safely("heartbeat", m.heartbeat)
		next = next.Add(m.set.heartbeat)
		if now := time.Now(); next.Before(now) {
			next = now.Add(m.set.heartbeat)
		}
	}
}

func (m *Monitor) heartbeat() {
	now := m.now()
	m.mu.Lock()
	hb := model.Heartbeat{
		UptimeSec:  int64(now.Sub(m.st.started) / time.Second),
		Cycles:     m.st.cycles,
		State:      m.st.lastVerdict.State,
		RecordsRun: m.records.Load(),
	}
	if hb.State == "" {
		hb.State = model.StateUnknown
	}
	if a := m.st.lastAnchor; a != nil {
		hb.LastAnchor = a.Anchor.GenTime
	}
	m.mu.Unlock()
	m.appendApply(model.TypeHeartbeat, hb, nil, nil)
	m.writeCache()
	m.checkDisk()
}

// ---------------------------------------------------------------------------- compression

// compressLoop gzips sealed ledger segments older than 48 h once a day when the ledger
// supports it (an optional capability, not part of contracts.Ledger).
func (m *Monitor) compressLoop(ctx context.Context) {
	cs, ok := m.led.(interface {
		CompressSealed(time.Duration) (int, error)
	})
	if !ok {
		return
	}
	next := time.Now().Add(m.compressFirst)
	for {
		if !sleepUntil(ctx, next, nil) {
			return
		}
		m.safely("compress", func() {
			n, err := cs.CompressSealed(48 * time.Hour)
			switch {
			case err != nil:
				m.log.Warn("compressing sealed ledger segments failed", "err", err)
			case n > 0:
				m.log.Info("compressed sealed ledger segments", "count", n)
			}
		})
		next = time.Now().Add(m.compressEvery)
	}
}
