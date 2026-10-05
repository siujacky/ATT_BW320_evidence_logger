package monitor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// maxNoteBytes bounds operator notes (a note is evidence, not a document store).
const maxNoteBytes = 16 << 10

// Note appends an operator_note (e.g. an AT&T ticket number). While an incident is open the
// note is also attached to it as evidence.
func (m *Monitor) Note(ctx context.Context, text, author, source string) (model.Ref, error) {
	// Operator text is recorded exactly as sent (surrounding white space aside) or not at all.
	text = strings.TrimSpace(text)
	if !utf8.ValidString(text) {
		return model.Ref{}, errors.New("note text is not valid UTF-8")
	}
	if text == "" {
		return model.Ref{}, errors.New("note text is empty")
	}
	if len(text) > maxNoteBytes {
		return model.Ref{}, fmt.Errorf("note is too long (%d bytes, at most %d)", len(text), maxNoteBytes)
	}
	author, err := label("author", author)
	if err != nil {
		return model.Ref{}, err
	}
	source, err = label("source", source)
	if err != nil {
		return model.Ref{}, err
	}
	if source == "" {
		source = "unknown"
	}
	note := model.OperatorNote{Text: text, Author: author, Source: source}
	return m.appendApply(model.TypeOperatorNote, note, nil, func(ref model.Ref) {
		m.addEvidenceLocked(nil, model.TypeOperatorNote, ref.Seq,
			model.EvidenceRef{Seq: ref.Seq, Type: model.TypeOperatorNote, Note: truncate(text, 80)})
	})
}

// SetGatewayNotification turns the gateway's Broadband Status Notification (outage redirect)
// on or off and records a config_change with the gateway pages before and after. Turning it
// on while enforce_notification_off is set also clears that setting (and saves the config)
// so the monitor does not switch it back off; turning it off again sets it back. The
// config_change result says so.
func (m *Monitor) SetGatewayNotification(ctx context.Context, enabled bool, actor string) (model.ConfigChange, error) {
	actor, err := label("actor", actor)
	if err != nil {
		return model.ConfigChange{}, err
	}
	if actor == "" {
		actor = "operator"
	}
	// No enforcement check may run between the gateway change and clearing
	// enforce_notification_off below (it would switch the setting straight back off). A check
	// (or another change) in progress makes this one busy rather than queue behind a login.
	if !m.notifMu.TryLock() {
		return model.ConfigChange{}, fmt.Errorf("a gateway notification check or change is already running: %w", contracts.ErrBusy)
	}
	defer m.notifMu.Unlock()
	if pending := m.pendingCert(); pending != "" {
		return model.ConfigChange{}, errCertPending(pending)
	}
	extra := func(err error) string {
		if err != nil {
			return ""
		}
		m.cfgMu.Lock()
		defer m.cfgMu.Unlock()
		// Enforcement follows the operator's latest choice: turning the redirect ON stops the
		// monitor from switching it back off; turning it OFF again re-enables enforcement.
		if m.cfg.Gateway.EnforceNotificationOff == !enabled {
			return ""
		}
		m.cfg.Gateway.EnforceNotificationOff = !enabled
		msg := "monitor setting enforce_notification_off changed from true to false so the monitor does not turn the setting back off"
		if !enabled {
			msg = "monitor setting enforce_notification_off changed from false to true so the monitor keeps the redirect off"
		}
		if m.opts.SaveConfig != nil {
			if serr := m.opts.SaveConfig(m.cfg); serr != nil {
				msg += " (the monitor configuration could not be saved: " + errText(serr) + ")"
				m.log.Error("cannot save configuration", "err", serr)
			}
		}
		return msg
	}
	return m.setNotification(ctx, enabled, actor, extra)
}

// AnchorNow time-stamps the current ledger head immediately.
func (m *Monitor) AnchorNow(ctx context.Context, reason string) ([]model.Anchor, error) {
	reason, err := label("anchor reason", reason)
	if err != nil {
		return nil, err
	}
	if reason == "" {
		reason = "manual"
	}
	if m.anchorer == nil {
		return nil, errAnchoringDisabled
	}
	if !m.anchorMu.TryLock() {
		return nil, fmt.Errorf("an anchoring round is already running: %w", contracts.ErrBusy)
	}
	defer m.anchorMu.Unlock()
	return m.anchorHead(ctx, reason)
}

// RecordExport appends a custody_export record and then anchors the new head. Anchoring
// failures are logged (the next anchor covers the record); the returned error is about the
// custody record only.
func (m *Monitor) RecordExport(ctx context.Context, e model.CustodyExport) (model.Ref, error) {
	if strings.TrimSpace(e.FileName) == "" {
		return model.Ref{}, errors.New("custody export needs the bundle file name")
	}
	// Recorded exactly as sent or not at all (the exporter keeps its own copy of these fields
	// next to the bundle, so a silently altered record would contradict it).
	for _, f := range []struct {
		name, v string
		n       int
	}{
		{"from", e.From, maxLabelBytes}, {"to", e.To, maxLabelBytes}, {"incident_id", e.IncidentID, maxLabelBytes},
		{"file_name", e.FileName, maxLabelBytes}, {"bundle_sha256", e.BundleSHA256, maxLabelBytes},
		{"manifest_sha256", e.ManifestSHA256, maxLabelBytes}, {"prepared_by", e.PreparedBy, maxLabelBytes},
		{"requester", e.Requester, maxLabelBytes}, {"notes", e.Notes, maxNoteBytes},
	} {
		if !utf8.ValidString(f.v) {
			return model.Ref{}, fmt.Errorf("custody export %s is not valid UTF-8", f.name)
		}
		if len(f.v) > f.n {
			return model.Ref{}, fmt.Errorf("custody export %s is too long (%d bytes, at most %d)", f.name, len(f.v), f.n)
		}
	}
	ref, err := m.appendApply(model.TypeCustodyExport, e, nil, nil)
	if err != nil {
		return ref, err
	}
	if m.anchorer != nil {
		if anchors, aerr := m.anchor(ctx, "export"); len(anchors) == 0 {
			m.log.Warn("anchoring after export failed; the next anchor will cover it", "err", aerr)
		}
	}
	return ref, nil
}

// label checks a short free-text field before it is written to the ledger: trimmed, valid
// UTF-8 and at most maxLabelBytes long. Anything else is refused, never silently altered.
func label(what, s string) (string, error) {
	s = strings.TrimSpace(s)
	if !utf8.ValidString(s) {
		return "", fmt.Errorf("%s is not valid UTF-8", what)
	}
	if len(s) > maxLabelBytes {
		return "", fmt.Errorf("%s is too long (%d bytes, at most %d)", what, len(s), maxLabelBytes)
	}
	return s, nil
}
