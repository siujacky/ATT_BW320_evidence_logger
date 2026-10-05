//go:build windows

package winsvc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"
)

type fakeEvent struct {
	typ string // "info" | "warning" | "error"
	id  uint32
	msg string
}

// fakeWriter records events instead of calling ReportEvent.
type fakeWriter struct {
	mu     sync.Mutex
	events []fakeEvent
	closes int
	fail   error
}

func (f *fakeWriter) add(typ string, id uint32, msg string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closes > 0 {
		panic("write after close") // the sink must prevent this
	}
	f.events = append(f.events, fakeEvent{typ, id, msg})
	return f.fail
}

func (f *fakeWriter) Info(id uint32, msg string) error    { return f.add("info", id, msg) }
func (f *fakeWriter) Warning(id uint32, msg string) error { return f.add("warning", id, msg) }
func (f *fakeWriter) Error(id uint32, msg string) error   { return f.add("error", id, msg) }
func (f *fakeWriter) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closes++
	return nil
}

func (f *fakeWriter) all() []fakeEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeEvent(nil), f.events...)
}

type redacted string

func (redacted) LogValue() slog.Value { return slog.StringValue("(redacted)") }

type groupValuer struct{}

func (groupValuer) LogValue() slog.Value {
	return slog.GroupValue(slog.String("plain", "should-not-appear"))
}

type nilStringer struct{ s string }

func (n *nilStringer) String() string { return n.s } // panics on a nil receiver

func TestEventHandlerFormatting(t *testing.T) {
	at := time.Date(2026, 10, 5, 3, 20, 0, 123456789, time.UTC)
	tests := []struct {
		name string
		log  func(l *slog.Logger)
		want string
	}{
		{"message only", func(l *slog.Logger) { l.Info("monitor started") }, "monitor started"},
		{"ints and strings", func(l *slog.Logger) { l.Info("probe", "name", "gateway_icmp", "rtt_us", 1900) },
			"probe name=gateway_icmp rtt_us=1900"},
		{"error value", func(l *slog.Logger) { l.Info("fetch failed", "err", errors.New("connection refused")) },
			`fetch failed err="connection refused"`},
		{"bool float uint", func(l *slog.Logger) { l.Info("x", "ok", true, "loss", 0.25, "seq", uint64(42)) },
			"x ok=true loss=0.25 seq=42"},
		{"duration and time", func(l *slog.Logger) { l.Info("poll", "took", 1500*time.Millisecond, "at", at) },
			"poll took=1.5s at=2026-10-05T03:20:00.123456789Z"},
		{"values needing quotes", func(l *slog.Logger) {
			l.Info("q", "empty", "", "space", "a b", "eq", "k=v", "quote", `say "hi"`, "nl", "a\nb", "tab", "a\tb")
		}, `q empty="" space="a b" eq="k=v" quote="say \"hi\"" nl="a\nb" tab="a\tb"`},
		{"non-ASCII printable is not escaped", func(l *slog.Logger) { l.Info("x", "label", "état–1") }, "x label=état–1"},
		{"invalid UTF-8 is quoted", func(l *slog.Logger) { l.Info("x", "raw", "a\xa9b") }, `x raw="a\xa9b"`},
		{"key with space is quoted", func(l *slog.Logger) { l.Info("x", "bad key", 1) }, `x "bad key"=1`},
		{"group attribute", func(l *slog.Logger) {
			l.Info("req", slog.Group("http", "method", "GET", "status", 302))
		}, "req http.method=GET http.status=302"},
		{"nested groups", func(l *slog.Logger) {
			l.Info("x", slog.Group("a", slog.Group("b", "c", 1)))
		}, "x a.b.c=1"},
		{"empty group is dropped", func(l *slog.Logger) { l.Info("x", slog.Group("g"), "k", "v") }, "x k=v"},
		{"group with empty key is inlined", func(l *slog.Logger) {
			l.Info("x", slog.Group("", "a", 1, "b", 2))
		}, "x a=1 b=2"},
		{"zero attr is dropped", func(l *slog.Logger) { l.Info("x", slog.Attr{}, "k", "v") }, "x k=v"},
		{"empty key with value is kept", func(l *slog.Logger) { l.Info("x", slog.Int("", 5)) }, `x ""=5`},
		{"LogValuer is resolved", func(l *slog.Logger) { l.Info("x", "code", redacted("hunter2")) }, "x code=(redacted)"},
		{"bytes as text", func(l *slog.Logger) { l.Info("x", "body", []byte("Login page")) }, `x body="Login page"`},
		{"TextMarshaler", func(l *slog.Logger) { l.Info("x", "ip", netip.MustParseAddr("192.168.1.254")) }, "x ip=192.168.1.254"},
		{"nil error", func(l *slog.Logger) { l.Info("x", "err", error(nil)) }, "x err=<nil>"},
		{"nil pointer Stringer does not panic", func(l *slog.Logger) {
			var p *nilStringer
			l.Info("x", "v", p)
		}, "x v=<nil>"},
		{"struct", func(l *slog.Logger) { l.Info("x", "s", struct{ A int }{7}) }, "x s={A:7}"},
		{"secret value is redacted", func(l *slog.Logger) { l.Info("login", "password", "hunter2", "page", "events") },
			"login password=[REDACTED] page=events"},
		{"secret key match is case-insensitive", func(l *slog.Logger) { l.Info("x", "Access_Code", "0123456789") },
			"x Access_Code=[REDACTED]"},
		{"secret inside a group", func(l *slog.Logger) {
			l.Info("x", slog.Group("gateway", "access_code", "0123456789", "host", "192.168.1.254"))
		}, "x gateway.access_code=[REDACTED] gateway.host=192.168.1.254"},
		{"secret via WithAttrs", func(l *slog.Logger) { l.With("hashpassword", "5f4dcc3b").Info("x") },
			"x hashpassword=[REDACTED]"},
		{"secret whose LogValuer is a group", func(l *slog.Logger) { l.Info("x", "secret", groupValuer{}) },
			"x secret=[REDACTED]"},
		{"similar non-secret key is kept", func(l *slog.Logger) { l.Info("x", "password_set", true) },
			"x password_set=true"},
		{"NUL in message is escaped", func(l *slog.Logger) { l.Info("a\x00b") }, `a\x00b`},
		{"multi-line message kept", func(l *slog.Logger) { l.Info("line1\nline2", "k", 1) }, "line1\nline2 k=1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fw := &fakeWriter{}
			tc.log(slog.New(newEventHandler(fw, slog.LevelInfo)))
			evs := fw.all()
			if len(evs) != 1 {
				t.Fatalf("got %d events, want 1: %+v", len(evs), evs)
			}
			if evs[0].msg != tc.want {
				t.Errorf("text = %q\nwant   %q", evs[0].msg, tc.want)
			}
		})
	}
}

func TestEventHandlerLevels(t *testing.T) {
	tests := []struct {
		name      string
		min       slog.Level
		level     slog.Level
		wantEvent *fakeEvent
	}{
		{"debug filtered at info", slog.LevelInfo, slog.LevelDebug, nil},
		{"info", slog.LevelInfo, slog.LevelInfo, &fakeEvent{typ: "info", id: 1}},
		{"info+2 is still information", slog.LevelInfo, slog.LevelInfo + 2, &fakeEvent{typ: "info", id: 1}},
		{"warn", slog.LevelInfo, slog.LevelWarn, &fakeEvent{typ: "warning", id: 2}},
		{"warn+2 is still warning", slog.LevelInfo, slog.LevelWarn + 2, &fakeEvent{typ: "warning", id: 2}},
		{"error", slog.LevelInfo, slog.LevelError, &fakeEvent{typ: "error", id: 3}},
		{"above error", slog.LevelInfo, slog.LevelError + 4, &fakeEvent{typ: "error", id: 3}},
		{"info filtered at warn", slog.LevelWarn, slog.LevelInfo, nil},
		{"debug enabled at debug is information", slog.LevelDebug, slog.LevelDebug, &fakeEvent{typ: "info", id: 1}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fw := &fakeWriter{}
			h := newEventHandler(fw, tc.min)
			l := slog.New(h)
			l.Log(context.Background(), tc.level, "m")
			evs := fw.all()
			if tc.wantEvent == nil {
				if len(evs) != 0 {
					t.Fatalf("got %+v, want no event", evs)
				}
				if h.Enabled(context.Background(), tc.level) {
					t.Error("Enabled = true for a filtered level")
				}
				return
			}
			if len(evs) != 1 || evs[0].typ != tc.wantEvent.typ || evs[0].id != tc.wantEvent.id {
				t.Fatalf("got %+v, want one %s event with id %d", evs, tc.wantEvent.typ, tc.wantEvent.id)
			}
		})
	}
}

func TestEventHandlerWithAttrsAndGroups(t *testing.T) {
	fw := &fakeWriter{}
	base := slog.New(newEventHandler(fw, slog.LevelInfo))

	l1 := base.With("component", "gateway")
	l2 := l1.WithGroup("page").With("name", "sysinfo")
	l3 := l2.WithGroup("http")
	l1.Info("one", "k", 1)
	l2.Info("two", "status", 200)
	l3.Info("three", "code", 302)
	l3.Info("four") // open group without attributes: nothing is added
	base.Info("five")
	base.With().WithGroup("").Info("six") // no-ops return the same handler

	want := []string{
		"one component=gateway k=1",
		"two component=gateway page.name=sysinfo page.status=200",
		"three component=gateway page.name=sysinfo page.http.code=302",
		"four component=gateway page.name=sysinfo",
		"five",
		"six",
	}
	evs := fw.all()
	if len(evs) != len(want) {
		t.Fatalf("got %d events, want %d", len(evs), len(want))
	}
	for i, w := range want {
		if evs[i].msg != w {
			t.Errorf("event %d = %q, want %q", i, evs[i].msg, w)
		}
	}
	h := newEventHandler(fw, slog.LevelInfo)
	if h.WithAttrs(nil) != slog.Handler(h) || h.WithGroup("") != slog.Handler(h) {
		t.Error("WithAttrs(nil)/WithGroup(\"\") should return the receiver")
	}
}

func TestEventHandlerClose(t *testing.T) {
	fw := &fakeWriter{}
	h := newEventHandler(fw, slog.LevelInfo)
	child := h.WithAttrs([]slog.Attr{slog.String("a", "b")})
	l := slog.New(h)
	l.Info("before")
	h.sink.close()
	h.sink.close() // idempotent
	l.Info("after")
	if err := child.Handle(context.Background(), slog.NewRecord(time.Now(), slog.LevelError, "late", 0)); !errors.Is(err, errHandlerClosed) {
		t.Errorf("Handle after close = %v, want errHandlerClosed", err)
	}
	if evs := fw.all(); len(evs) != 1 || evs[0].msg != "before" {
		t.Errorf("events = %+v, want only \"before\"", evs)
	}
	if fw.closes != 1 {
		t.Errorf("Close called %d times, want 1", fw.closes)
	}
}

func TestEventHandlerReportsWriteErrors(t *testing.T) {
	fw := &fakeWriter{fail: errors.New("event log full")}
	h := newEventHandler(fw, slog.LevelInfo)
	err := h.Handle(context.Background(), slog.NewRecord(time.Now(), slog.LevelInfo, "m", 0))
	if err == nil || err.Error() != "event log full" {
		t.Errorf("Handle = %v, want the writer's error", err)
	}
}

// Concurrent logging and closing must be race-free and never write after close.
func TestEventHandlerConcurrent(t *testing.T) {
	fw := &fakeWriter{}
	h := newEventHandler(fw, slog.LevelInfo)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			l := slog.New(h).With("g", g).WithGroup("grp")
			for i := 0; i < 200; i++ {
				l.Info("tick", "i", i)
			}
		}(g)
	}
	time.Sleep(time.Millisecond)
	h.sink.close()
	wg.Wait()
	for _, e := range fw.all() {
		if !strings.HasPrefix(e.msg, "tick g=") || !strings.Contains(e.msg, " grp.i=") {
			t.Fatalf("garbled event %q", e.msg)
		}
	}
}

func TestQuoteIfNeeded(t *testing.T) {
	tests := []struct{ in, want string }{
		{"plain", "plain"},
		{"", `""`},
		{"with space", `"with space"`},
		{"a=b", `"a=b"`},
		{`q"`, `"q\""`},
		{"ctl\x01", `"ctl\x01"`},
		{"bad\xffutf8", `"bad\xffutf8"`},
		{"192.168.1.254:443", "192.168.1.254:443"},
		{"https://192.168.1.254/cgi-bin/sysinfo.ha", "https://192.168.1.254/cgi-bin/sysinfo.ha"},
		{"Ünïcödé", "Ünïcödé"},
	}
	for _, tc := range tests {
		if got := quoteIfNeeded(tc.in); got != tc.want {
			t.Errorf("quoteIfNeeded(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestTruncateUTF16(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		max    int
		suffix string
		want   string
	}{
		{"fits", "abcdef", 6, "~", "abcdef"},
		{"truncated with suffix", "abcdefgh", 6, "~", "abcde~"},
		{"surrogate pair counts as two", "ab😀cd", 5, "", "ab😀c"},
		{"never splits a surrogate pair", "ab😀cd", 3, "", "ab"},
		{"multi-byte BMP counts as one", "ééééé", 4, "+", "ééé+"},
		{"empty", "", 0, "~", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := truncateUTF16(tc.in, tc.max, tc.suffix)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
			if n := len(utf16.Encode([]rune(got))); n > tc.max && tc.in != got {
				t.Errorf("result has %d UTF-16 units, max %d", n, tc.max)
			}
		})
	}
}

func TestSanitizeEventTextLimits(t *testing.T) {
	long := strings.Repeat("x", maxEventUTF16+5000)
	got := sanitizeEventText(long)
	if n := len(utf16.Encode([]rune(got))); n > maxEventUTF16 {
		t.Errorf("sanitized length %d exceeds %d", n, maxEventUTF16)
	}
	if !strings.HasSuffix(got, truncatedSuffix) {
		t.Errorf("truncated text does not end with the marker")
	}
	if short := "ok"; sanitizeEventText(short) != short {
		t.Error("short text changed")
	}
	fw := &fakeWriter{}
	slog.New(newEventHandler(fw, slog.LevelInfo)).Info(long)
	evs := fw.all()
	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1", len(evs))
	}
	if n := len(utf16.Encode([]rune(evs[0].msg))); n > maxEventUTF16 || !strings.HasSuffix(evs[0].msg, truncatedSuffix) {
		t.Errorf("handler did not truncate a long record: %d UTF-16 units", n)
	}
}

// TestEventLogLive writes one real event under a test source and reads it back.
func TestEventLogLive(t *testing.T) {
	if os.Getenv("ATTMON_LIVE") != "1" {
		t.Skip("set ATTMON_LIVE=1 to write a test event to the Application log")
	}
	const source = "ATTMonitorTest"
	h, closeFn, err := newEventLogHandlerFor(source, slog.LevelInfo)
	if err != nil {
		t.Fatal(err)
	}
	token := fmt.Sprintf("winsvc-live-%d", time.Now().UnixNano())
	slog.New(h).Warn("att-monitor event log test", "token", token)
	closeFn()

	// XML output carries the raw insertion string even when the test source has no
	// registered message file (the text rendering would only say "cannot find the file").
	query := fmt.Sprintf("*[System[Provider[@Name='%s'] and Level=3 and EventID=2]]", source)
	want := "att-monitor event log test token=" + token
	var out []byte
	for i := 0; i < 10; i++ {
		out, err = exec.Command("wevtutil.exe", "qe", "Application", "/q:"+query, "/rd:true", "/c:20").CombinedOutput()
		if err == nil && strings.Contains(string(out), want) {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("warning event %q not found (err %v):\n%s", want, err, out)
}

func TestSensitiveKey(t *testing.T) {
	secrets := []string{
		"password", "Password", "PASSWORD", "passwd", "pwd", "pass", "hashpassword", "HashPassword",
		"gateway_password", "admin-password", "passcode", "passphrase",
		"secret", "client_secret", "access_code", "accessCode", "AccessCode", "Access-Code",
		"access code", "ACCESS_CODE", "gateway.access_code", "access_code_protected",
		"AccessCodeProtected", "protected", "private_key", "privateKey", "privkey", "signing_key",
		"seed", "signing_seed",
	}
	for _, k := range secrets {
		if !sensitiveKey(k) {
			t.Errorf("sensitiveKey(%q) = false, want true", k)
		}
	}
	plain := []string{
		"", "password_set", "has_password_hint", "pwd_dir", "code", "status_code", "exit_code",
		"nonce", "token", "token_sha256", "key", "public_key", "fingerprint", "seedling", "speed",
		"access", "host", "page", "err", "head_hash", "passage",
	}
	for _, k := range plain {
		if sensitiveKey(k) {
			t.Errorf("sensitiveKey(%q) = true, want false (not a secret)", k)
		}
	}
}

// countingValuer records whether slog asked it for its value.
type countingValuer struct{ calls *int }

func (c countingValuer) LogValue() slog.Value { *c.calls++; return slog.StringValue("hunter2") }

func TestEventHandlerRedactsSecretGroups(t *testing.T) {
	calls := 0
	tests := []struct {
		name string
		log  func(l *slog.Logger)
		want string
	}{
		{"WithGroup named like a secret", func(l *slog.Logger) {
			l.WithGroup("gateway_password").Info("x", "value", "hunter2", "n", 7)
		}, "x gateway_password.value=[REDACTED] gateway_password.n=[REDACTED]"},
		{"attributes added inside a secret group", func(l *slog.Logger) {
			l.WithGroup("secret").With("k", "hunter2").Info("x")
		}, "x secret.k=[REDACTED]"},
		{"nested and inline groups inside a secret group keep their keys", func(l *slog.Logger) {
			l.WithGroup("credentials_secret").Info("x", slog.Group("inner", "a", "hunter2"), slog.Group("", "b", "hunter2"))
		}, "x credentials_secret.inner.a=[REDACTED] credentials_secret.b=[REDACTED]"},
		{"LogValuer inside a secret group is not called", func(l *slog.Logger) {
			l.WithGroup("access_code").Info("x", "v", countingValuer{&calls})
		}, "x access_code.v=[REDACTED]"},
		{"secret group attribute (not WithGroup)", func(l *slog.Logger) {
			l.Info("x", slog.Group("password", "value", "hunter2"), "page", "events")
		}, "x password=[REDACTED] page=events"},
		{"empty attribute inside a secret group is dropped", func(l *slog.Logger) {
			l.WithGroup("seed").Info("x", slog.Attr{}, "k", "hunter2")
		}, "x seed.k=[REDACTED]"},
		{"ordinary group after a secret attribute is untouched", func(l *slog.Logger) {
			l.Info("x", "passcode", "hunter2", slog.Group("http", "status", 302))
		}, "x passcode=[REDACTED] http.status=302"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fw := &fakeWriter{}
			tc.log(slog.New(newEventHandler(fw, slog.LevelInfo)))
			evs := fw.all()
			if len(evs) != 1 || evs[0].msg != tc.want {
				t.Fatalf("events %+v\nwant one with %q", evs, tc.want)
			}
			if strings.Contains(evs[0].msg, "hunter2") {
				t.Fatalf("secret leaked: %q", evs[0].msg)
			}
		})
	}
	if calls != 0 {
		t.Errorf("a LogValuer inside a secret group was resolved %d times", calls)
	}
}

// TestReportErrorLive writes one Error event the way Run reports a failed service (under a
// test source) and reads it back.
func TestReportErrorLive(t *testing.T) {
	if os.Getenv("ATTMON_LIVE") != "1" {
		t.Skip("set ATTMON_LIVE=1 to write a test event to the Application log")
	}
	const source = "ATTMonitorTest"
	token := fmt.Sprintf("winsvc-report-%d", time.Now().UnixNano())
	if err := reportErrorTo(source, fmt.Errorf("run stopped unexpectedly: %s\x00", token)); err != nil {
		t.Fatal(err)
	}
	query := fmt.Sprintf("*[System[Provider[@Name='%s'] and Level=2 and EventID=3]]", source)
	want := "att-monitor service: run stopped unexpectedly: " + token + `\x00`
	var (
		out []byte
		err error
	)
	for i := 0; i < 10; i++ {
		out, err = exec.Command("wevtutil.exe", "qe", "Application", "/q:"+query, "/rd:true", "/c:20").CombinedOutput()
		if err == nil && strings.Contains(string(out), want) {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("error event %q not found (err %v):\n%s", want, err, out)
}
