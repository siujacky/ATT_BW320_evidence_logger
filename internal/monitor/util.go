package monitor

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"attmonitor/internal/config"
)

// fmtTS formats t the way every ledger payload stores times: UTC RFC 3339 with nanoseconds.
func fmtTS(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// fmtHuman formats t for summary sentences.
func fmtHuman(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 UTC") }

// parseTS parses an RFC 3339 timestamp (with or without fractional seconds).
func parseTS(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// fmtMs renders a microsecond RTT as milliseconds with one decimal ("1.9 ms").
func fmtMs(us int64) string { return fmt.Sprintf("%.1f ms", float64(us)/1000) }

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// durOr returns d, or def when d is zero or negative (absent from a hand-built config).
func durOr(d config.Duration, def time.Duration) time.Duration {
	if d.Duration > 0 {
		return d.Duration
	}
	return def
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// truncate shortens s to at most n bytes without splitting a UTF-8 sequence.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// hostOnly strips a port from "host:port"; other strings are returned unchanged.
func hostOnly(target string) string {
	if h, _, err := net.SplitHostPort(target); err == nil {
		return h
	}
	return target
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// randomHex returns 2n lowercase hex characters from crypto/rand.
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand does not fail on supported platforms; fall back to the clock so the
		// caller still gets a unique-enough label.
		return fmt.Sprintf("%0*x", 2*n, time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------- kicker

// kicker wakes a worker goroutine early and tells it why. Kicks never block; reasons
// accumulate until the worker takes them.
type kicker struct {
	ch      chan struct{}
	mu      sync.Mutex
	reasons []string
}

func newKicker() *kicker { return &kicker{ch: make(chan struct{}, 1)} }

func (k *kicker) kick(reason string) {
	k.mu.Lock()
	if len(k.reasons) < 64 { // bounded: a stalled worker must not grow memory
		k.reasons = append(k.reasons, reason)
	}
	k.mu.Unlock()
	select {
	case k.ch <- struct{}{}:
	default:
	}
}

// take returns and clears the accumulated reasons.
func (k *kicker) take() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	r := k.reasons
	k.reasons = nil
	return r
}

func hasReason(reasons []string, want string) bool {
	for _, r := range reasons {
		if r == want {
			return true
		}
	}
	return false
}

// onlyReason reports whether there are reasons and every one of them is want.
func onlyReason(reasons []string, want string) bool {
	for _, r := range reasons {
		if r != want {
			return false
		}
	}
	return len(reasons) > 0
}

// sleepUntil blocks until the wall time `at` (measured with the monotonic clock), a kick,
// or the end of ctx. It reports false when ctx is done. Whatever woke it, a pending kick is
// consumed: the work about to run serves it, and a signal left in the channel would wake the
// worker once more for nothing (e.g. an extra gateway request).
func sleepUntil(ctx context.Context, at time.Time, kick <-chan struct{}) bool {
	if d := time.Until(at); d > 0 {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
		case <-kick:
		}
	}
	select {
	case <-ctx.Done():
		return false
	default:
	}
	select {
	case <-kick:
	default:
	}
	return true
}

// errText renders an error for a ledger payload, bounded in size.
func errText(err error) string {
	if err == nil {
		return ""
	}
	return truncate(strings.TrimSpace(err.Error()), 300)
}

// maxLabelBytes bounds short free-text fields that reach the ledger through the actions
// (author, source, actor, anchor reason, export fields). The web layer accepts names of up to
// 200 characters, i.e. up to 800 bytes of UTF-8; this is only a backstop above that.
const maxLabelBytes = 1024

// maxRebootWatch bounds the closed LOCAL_FAULT incidents that wait for a usable snapshot.
const maxRebootWatch = 32
