//go:build windows

package winsvc

import (
	"context"
	"encoding"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/windows/svc/eventlog"
)

// Event IDs used by the event-log handler (EventCreate.exe, the registered message file,
// accepts 1..1000 and shows the text as is).
const (
	eventIDInfo    = 1
	eventIDWarning = 2
	eventIDError   = 3
)

// maxEventUTF16 caps one event's text below ReportEvent's 31,839-character string limit.
const maxEventUTF16 = 31000

const truncatedSuffix = " …[truncated]"

var errHandlerClosed = errors.New("winsvc: event log handler is closed")

// NewEventLogHandler returns a slog.Handler that writes records at or above level to the
// Application event log under the ATTMonitor source (Error and above → Error events with ID
// 3, Warn → Warning with ID 2, lower levels → Information with ID 1). The event text is the
// message followed by the attributes as key=value (groups as dotted keys, values quoted when
// needed); values of attributes named like secrets ("password", "access_code",
// "hashpassword", "gateway_password", "access code", ... and everything inside a group with
// such a name) are replaced by [REDACTED] because every local user can read the
// Application log. It does not need elevation; the source is registered by Install so Event
// Viewer can display the text. The returned function closes the event source; records
// handled afterwards are dropped (Handle returns an error). Safe for concurrent use.
func NewEventLogHandler(level slog.Level) (slog.Handler, func(), error) {
	return newEventLogHandlerFor(ServiceName, level)
}

func newEventLogHandlerFor(source string, level slog.Level) (slog.Handler, func(), error) {
	l, err := eventlog.Open(source)
	if err != nil {
		return nil, nil, fmt.Errorf("winsvc: open event log source %q: %w", source, err)
	}
	h := newEventHandler(l, level)
	return h, h.sink.close, nil
}

// eventWriter is the part of *eventlog.Log the handler uses (faked in tests).
type eventWriter interface {
	Info(eid uint32, msg string) error
	Warning(eid uint32, msg string) error
	Error(eid uint32, msg string) error
	Close() error
}

// eventSink serializes closing against in-flight writes so a closed (and possibly reused)
// event source handle is never written to.
type eventSink struct {
	mu     sync.RWMutex
	w      eventWriter
	closed bool
}

func (s *eventSink) write(level slog.Level, msg string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return errHandlerClosed
	}
	switch {
	case level >= slog.LevelError:
		return s.w.Error(eventIDError, msg)
	case level >= slog.LevelWarn:
		return s.w.Warning(eventIDWarning, msg)
	default:
		return s.w.Info(eventIDInfo, msg)
	}
}

func (s *eventSink) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	_ = s.w.Close()
}

// eventHandler is immutable; WithAttrs/WithGroup return copies sharing the sink.
type eventHandler struct {
	sink   *eventSink
	level  slog.Level
	attrs  string // pre-formatted " key=value" pairs from WithAttrs
	prefix string // open groups as a key prefix, e.g. "gateway.page."
	secret bool   // an open group is named like a secret: redact every value
}

var _ slog.Handler = (*eventHandler)(nil)

func newEventHandler(w eventWriter, level slog.Level) *eventHandler {
	return &eventHandler{sink: &eventSink{w: w}, level: level}
}

func (h *eventHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level }

func (h *eventHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Message)
	b.WriteString(h.attrs)
	r.Attrs(func(a slog.Attr) bool {
		appendAttr(&b, h.prefix, a, h.secret)
		return true
	})
	return h.sink.write(r.Level, sanitizeEventText(b.String()))
}

func (h *eventHandler) WithAttrs(as []slog.Attr) slog.Handler {
	if len(as) == 0 {
		return h
	}
	var b strings.Builder
	b.WriteString(h.attrs)
	for _, a := range as {
		appendAttr(&b, h.prefix, a, h.secret)
	}
	h2 := *h
	h2.attrs = b.String()
	return &h2
}

func (h *eventHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	h2 := *h
	h2.prefix = h.prefix + name + "."
	h2.secret = h.secret || sensitiveKey(name)
	return &h2
}

// appendAttr writes " key=value" following the slog handler rules: values are resolved,
// empty attributes and empty groups are dropped, groups with an empty key are inlined.
//
// An attribute named like a secret is written as key=[REDACTED] whatever its kind; the check
// comes before the value is resolved or a group expanded, so a secret's LogValuer cannot leak
// it as nested keys. When secret is set (inside a group named like a secret) keys are still
// written but every value is [REDACTED] and LogValuers are not called.
func appendAttr(b *strings.Builder, prefix string, a slog.Attr, secret bool) {
	if a.Equal(slog.Attr{}) {
		return
	}
	if !secret && sensitiveKey(a.Key) {
		writeKey(b, prefix+a.Key)
		b.WriteString(redactedValue)
		return
	}
	if !secret {
		a.Value = a.Value.Resolve()
		if a.Equal(slog.Attr{}) {
			return
		}
	}
	if a.Value.Kind() == slog.KindGroup {
		attrs := a.Value.Group()
		if len(attrs) == 0 {
			return
		}
		p := prefix
		if a.Key != "" {
			p = prefix + a.Key + "."
		}
		for _, ga := range attrs {
			appendAttr(b, p, ga, secret)
		}
		return
	}
	writeKey(b, prefix+a.Key)
	if secret {
		b.WriteString(redactedValue)
		return
	}
	b.WriteString(formatValue(a.Value))
}

func writeKey(b *strings.Builder, key string) {
	b.WriteByte(' ')
	b.WriteString(quoteIfNeeded(key))
	b.WriteByte('=')
}

const redactedValue = "[REDACTED]"

// Secret attribute names, compared after normalizeKey. secretKeys must match the whole key;
// secretSuffixes may also end a longer one ("gateway_password", "access_code_protected").
// "protected" covers DPAPI blobs: machine-scope blobs can be decrypted by any local account,
// so the blob is as sensitive as the secret itself.
var (
	secretKeys     = []string{"pwd", "pass", "hashpassword", "privkey"}
	secretSuffixes = []string{"password", "passwd", "passcode", "passphrase", "secret",
		"accesscode", "privatekey", "signingkey", "seed", "protected"}
)

// sensitiveKey reports whether an attribute key names a secret. The Application log is
// readable by every local user, so such values are never written even if a caller logs one
// by mistake (docs/DESIGN.md §15: secrets never appear in logs). Case and separators do not
// matter: "Access-Code", "access code" and "accessCode" are the same key.
func sensitiveKey(key string) bool {
	k := normalizeKey(key)
	if k == "" {
		return false
	}
	for _, s := range secretKeys {
		if k == s {
			return true
		}
	}
	for _, s := range secretSuffixes {
		if strings.HasSuffix(k, s) {
			return true
		}
	}
	return false
}

// normalizeKey lower-cases key and drops everything but letters and digits.
func normalizeKey(key string) string {
	var b strings.Builder
	b.Grow(len(key))
	for _, r := range key {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

func formatValue(v slog.Value) string {
	switch v.Kind() {
	case slog.KindString:
		return quoteIfNeeded(v.String())
	case slog.KindTime:
		return v.Time().Format(time.RFC3339Nano)
	case slog.KindAny:
		switch x := v.Any().(type) {
		case []byte:
			return quoteIfNeeded(string(x))
		case encoding.TextMarshaler:
			if t, err := safeMarshalText(x); err == nil {
				return quoteIfNeeded(string(t))
			}
		}
		return quoteIfNeeded(fmt.Sprintf("%+v", v.Any()))
	}
	return v.String() // ints, uints, floats, bools, durations
}

// safeMarshalText guards against MarshalText panicking (e.g. on a nil pointer receiver).
func safeMarshalText(m encoding.TextMarshaler) (b []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("MarshalText panicked: %v", r)
		}
	}()
	return m.MarshalText()
}

// quoteIfNeeded quotes s (Go syntax) when it is empty or contains spaces, '=', quotes,
// non-printable characters or invalid UTF-8, keeping key=value pairs unambiguous.
func quoteIfNeeded(s string) string {
	if s == "" || !utf8.ValidString(s) {
		return strconv.Quote(s)
	}
	for _, r := range s {
		if r == ' ' || r == '=' || r == '"' || !unicode.IsPrint(r) {
			return strconv.Quote(s)
		}
	}
	return s
}

// sanitizeEventText makes text acceptable to ReportEvent: NUL characters (which would end the
// string, or make the UTF-16 conversion fail) are escaped and over-long text is truncated on a
// character boundary with a visible marker.
func sanitizeEventText(s string) string {
	if strings.IndexByte(s, 0) >= 0 {
		s = strings.ReplaceAll(s, "\x00", `\x00`)
	}
	return truncateUTF16(s, maxEventUTF16, truncatedSuffix)
}

// truncateUTF16 returns s unchanged if it is at most max UTF-16 code units long; otherwise
// the longest prefix that fits together with suffix, followed by suffix.
func truncateUTF16(s string, max int, suffix string) string {
	if utf16Len(s) <= max {
		return s
	}
	budget := max - utf16Len(suffix)
	n := 0
	for i, r := range s {
		w := 1
		if r > 0xFFFF {
			w = 2 // surrogate pair
		}
		if n+w > budget {
			return s[:i] + suffix
		}
		n += w
	}
	return s + suffix // unreachable: s was longer than max
}

func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		if r > 0xFFFF {
			n += 2
		} else {
			n++
		}
	}
	return n
}
