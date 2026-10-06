package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/model"
	"attmonitor/internal/mongostore"
	"attmonitor/internal/syslogstore"
	"attmonitor/internal/web"
)

// testNow is the clock of the syslog command tests.
var testNow = time.Date(2026, 10, 5, 22, 0, 0, 0, time.UTC)

// fakeService is a running service's API as the syslog commands see it: GET /api/status, GET
// /api/syslog and POST /api/syslog/retention answered from its fields, every request recorded.
type fakeService struct {
	t       *testing.T
	mu      sync.Mutex
	status  model.Status
	list    model.SyslogList
	warning string // X-ATT-Monitor-Warning of GET /api/syslog
	change  model.ConfigChange
	fail    int    // answer POST /api/syslog/retention with this status …
	failMsg string // … and error
	queries []string
	posts   []map[string]any
	// POST /api/gateway/syslog: the change it answers, or gwFail with gwFailBody.
	gwChange   model.ConfigChange
	gwFail     int
	gwFailBody any
	gwPosts    []map[string]any
}

// useService makes the syslog commands find f (an httptest server on 127.0.0.1:0) as the running
// service, and fixes their clock.
func useService(t *testing.T, f *fakeService) {
	t.Helper()
	f.t = t
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	restore := lookupService
	lookupService = func(string) (*apiClient, bool) { return &apiClient{base: srv.URL, hc: srv.Client()}, true }
	t.Cleanup(func() { lookupService = restore })
	fixClock(t)
}

// noService makes the syslog commands find no running service; with ask false looking for it
// fails the test (wrong arguments must be refused first).
func noService(t *testing.T, ask bool) {
	t.Helper()
	restore := lookupService
	lookupService = func(string) (*apiClient, bool) {
		if !ask {
			t.Error("the command looked for the service although its arguments are wrong")
		}
		return nil, false
	}
	t.Cleanup(func() { lookupService = restore })
	fixClock(t)
}

func fixClock(t *testing.T) {
	restore := now
	now = func() time.Time { return testNow }
	t.Cleanup(func() { now = restore })
}

func (f *fakeService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/status":
		_ = json.NewEncoder(w).Encode(f.status)
	case r.Method == http.MethodGet && r.URL.Path == "/api/syslog":
		f.queries = append(f.queries, r.URL.RawQuery)
		if f.warning != "" {
			w.Header().Set(web.WarningHeader, f.warning)
		}
		_ = json.NewEncoder(w).Encode(f.list)
	case r.Method == http.MethodPost && r.URL.Path == "/api/syslog/retention":
		if r.Header.Get("X-ATT-Monitor") != "1" {
			f.t.Error("POST without the X-ATT-Monitor header")
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			f.t.Errorf("POST body: %v", err)
		}
		f.posts = append(f.posts, body)
		if f.fail != 0 {
			w.WriteHeader(f.fail)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": f.failMsg})
			return
		}
		_ = json.NewEncoder(w).Encode(f.change)
	case r.Method == http.MethodPost && r.URL.Path == "/api/gateway/syslog":
		if r.Header.Get("X-ATT-Monitor") != "1" {
			f.t.Error("POST without the X-ATT-Monitor header")
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			f.t.Errorf("POST body: %v", err)
		}
		f.gwPosts = append(f.gwPosts, body)
		if f.gwFail != 0 {
			w.WriteHeader(f.gwFail)
			_ = json.NewEncoder(w).Encode(f.gwFailBody)
			return
		}
		_ = json.NewEncoder(w).Encode(f.gwChange)
	default:
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found: " + r.URL.Path})
	}
}

func (f *fakeService) recorded() ([]string, []map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.queries...), append([]map[string]any(nil), f.posts...)
}

// gwRecorded returns the bodies of the POST /api/gateway/syslog requests so far.
func (f *fakeService) gwRecorded() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]any(nil), f.gwPosts...)
}

func sevOf(n int) *int { return &n }

// at formats an RFC 3339 time as the commands show it.
func at(ts, layout string) string {
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		panic(err)
	}
	return t.In(time.Local).Format(layout)
}

// bs turns every ~ into a backslash: the escapes terminalSafe writes, spelt without escape
// sequences in this file.
func bs(s string) string { return strings.ReplaceAll(s, "~", `\`) }

// TestSyslogListArguments: wrong arguments are refused before the service is asked.
func TestSyslogListArguments(t *testing.T) {
	noService(t, false)
	for _, args := range [][]string{
		{"--since", "0"}, {"--since", "-1h"}, {"--since", "32d"}, {"--since", "745h"}, {"--since", "1.5d"}, {"--since", "yesterday"},
		{"--since", "0d"}, {"--since", "99999999999999999999d"},
		{"--limit", "0"}, {"--limit", "5001"}, {"--limit", "x"},
		{"extra"}, {"--bogus"},
	} {
		if err := syslogCommand(io.Discard, io.Discard, args); err == nil {
			t.Errorf("%q accepted", args)
		}
	}
	// Through the command line too.
	if err := run([]string{"syslog", "--since", "1y"}); err == nil || !strings.Contains(err.Error(), "--since") {
		t.Errorf("run syslog --since 1y: %v", err)
	}
}

func TestParseSince(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"1h": time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "31d": 31 * 24 * time.Hour, " 90M ": 90 * time.Minute,
		"744h": 744 * time.Hour, "1s": time.Second,
	} {
		if got, err := parseSince(in); err != nil || got != want {
			t.Errorf("parseSince(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
}

// TestSyslogList: the newest messages of the period, through GET /api/syslog with the filters,
// printed oldest first under a heading per chunk that names its syslog_chunk record, with what
// a terminal would act on escaped.
func TestSyslogList(t *testing.T) {
	f := &fakeService{
		warning: "syslog_chunk record #7: h is not the SHA-256 of b",
		list: model.SyslogList{From: "2026-10-05T21:00:00Z", To: "2026-10-05T22:00:00Z", Truncated: true, Messages: []model.SyslogEntry{
			{SyslogMessage: model.SyslogMessage{RX: "2026-10-05T21:59:00.5Z", Src: "192.168.1.254:514", Severity: sevOf(6), Host: "dsldevice",
				App: "dhcpd", Msg: "lease renewed", Raw: "<30>Oct  5 16:59:00 dsldevice dhcpd: lease renewed"}},
			{Chunk: "syslog-B.jsonl.gz", SyslogMessage: model.SyslogMessage{RX: "2026-10-05T21:50:00Z", Severity: sevOf(3), App: "kernel",
				Msg: "x\x1b[2Jcleared\U0000202eevil\r\n\x7f\U0000009b"}},
			{Chunk: "syslog-A.jsonl.gz", Seq: 42, SyslogMessage: model.SyslogMessage{RX: "2026-10-05T21:40:00Z", RawB64: "/w=="}},
			{Chunk: "syslog-A.jsonl.gz", Seq: 42, SyslogMessage: model.SyslogMessage{RX: "2026-10-05T21:30:00Z", Raw: "plain\ttext \U000000e9 \U00004e2d"}},
		}},
	}
	useService(t, f)
	var out, errOut strings.Builder
	if err := syslogCommand(&out, &errOut, []string{"--since", "1h", "--grep", "Lease", "--severity", "info", "--limit", "4", "--data", t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	queries, _ := f.recorded()
	want := "from=2026-10-05T21%3A00%3A00Z&limit=4&q=Lease&severity=info&to=2026-10-05T22%3A00%3A00Z"
	if len(queries) != 1 || queries[0] != want {
		t.Errorf("queries %q, want %q", queries, want)
	}
	const ms = "2006-01-02 15:04:05.000"
	wantOut := strings.Join([]string{
		"Syslog messages received " + at("2026-10-05T21:00:00Z", "2006-01-02 15:04") + " to " + at("2026-10-05T22:00:00Z", "2006-01-02 15:04") +
			" (this PC's local time), oldest first",
		"WARNING: syslog_chunk record #7: h is not the SHA-256 of b",
		"Only the newest 4 are shown: more matched (raise --limit, up to 5000, or shorten --since).",
		"-- chunk syslog-A.jsonl.gz, its SHA-256 in ledger record #42 --",
		at("2026-10-05T21:30:00Z", ms) + bs("  -        plain~ttext \U000000e9 \U00004e2d"),
		at("2026-10-05T21:40:00Z", ms) + "  -        (a datagram that is not UTF-8 text; base64: /w==)",
		"-- chunk syslog-B.jsonl.gz (its syslog_chunk record was not found) --",
		at("2026-10-05T21:50:00Z", ms) + bs("  err      kernel: x~x1b[2Jcleared~u202eevil~r~n~x7f~u009b"),
		"-- the open chunk: not sealed yet, so not recorded in the evidence ledger yet (within minutes) --",
		at("2026-10-05T21:59:00.5Z", ms) + "  info     dsldevice dhcpd: lease renewed",
		"4 messages.",
		"",
	}, "\n")
	if out.String() != wantOut {
		t.Errorf("output:\n%s\nwant:\n%s", out.String(), wantOut)
	}
	if errOut.Len() != 0 {
		t.Errorf("stderr: %q", errOut.String())
	}

	// Nothing in the period; the defaults.
	f.list, f.warning = model.SyslogList{From: "2026-10-04T22:00:00Z", To: "2026-10-05T22:00:00Z", Messages: []model.SyslogEntry{}}, ""
	out.Reset()
	if err := syslogCommand(&out, &errOut, []string{"--data", t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(out.String(), "oldest first\nNo message.\n") {
		t.Errorf("empty list: %q", out.String())
	}
	if queries, _ = f.recorded(); len(queries) != 2 || queries[1] != "from=2026-10-04T22%3A00%3A00Z&limit=200&to=2026-10-05T22%3A00%3A00Z" {
		t.Errorf("defaults: %q", queries)
	}
}

// TestSyslogListJSON: --json prints the service's answer as it is (newest first); a warning goes
// to standard error so that the JSON stays valid.
func TestSyslogListJSON(t *testing.T) {
	f := &fakeService{warning: "a record does not verify", list: model.SyslogList{From: "a", To: "b", Messages: []model.SyslogEntry{
		{Chunk: "c1", Seq: 9, SyslogMessage: model.SyslogMessage{RX: "2026-10-05T21:59:00Z", Raw: "x\x1b", Severity: sevOf(0)}},
		{SyslogMessage: model.SyslogMessage{RX: "2026-10-05T21:58:00Z", RawB64: "AA=="}},
	}}}
	useService(t, f)
	var out, errOut strings.Builder
	if err := syslogCommand(&out, &errOut, []string{"--json", "--data", t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	var got model.SyslogList
	if err := json.Unmarshal([]byte(out.String()), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out.String())
	}
	if !reflect.DeepEqual(got, f.list) {
		t.Errorf("JSON %+v, want %+v", got, f.list)
	}
	if errOut.String() != "WARNING: a record does not verify\n" {
		t.Errorf("stderr %q", errOut.String())
	}
}

// TestSyslogListWithoutService: without the running service nothing can be listed, and the
// error says where the chunk files are; an error of the service is passed on.
func TestSyslogListWithoutService(t *testing.T) {
	noService(t, true)
	dir := t.TempDir()
	err := syslogCommand(io.Discard, io.Discard, []string{"--data", dir})
	if err == nil || !strings.Contains(err.Error(), "the service is not running") || !strings.Contains(err.Error(), filepath.Join(dir, "syslog")) {
		t.Errorf("no service: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"error":"the gateway's syslog messages are not available: this att-monitor keeps no syslog store"}`)
	}))
	defer srv.Close()
	lookupService = func(string) (*apiClient, bool) { return &apiClient{base: srv.URL, hc: srv.Client()}, true }
	if err := syslogCommand(io.Discard, io.Discard, []string{"--data", dir}); err == nil ||
		err.Error() != "service: the gateway's syslog messages are not available: this att-monitor keeps no syslog store" {
		t.Errorf("404: %v", err)
	}
}

func TestTerminalSafe(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"plain text: \U000000e9 \U00004e2d \U0001f600 \U0000fffd", "plain text: \U000000e9 \U00004e2d \U0001f600 \U0000fffd"},
		{"a\x1b[31mred\x1b[0m", "a~x1b[31mred~x1b[0m"},
		{"tab\there\r\nnext\x00\x07", "tab~there~r~nnext~x00~x07"},
		{"del\x7f c1 \U00000085\U0000009b", "del~x7f c1 ~u0085~u009b"},
		{"bidi \U0000202eevil\U00002066 \U0000200b", "bidi ~u202eevil~u2066 ~u200b"},
		{"bad \xff\xfe utf8", "bad ~xff~xfe utf8"},
		{"nbsp\U000000a0 line\U00002028", "nbsp~u00a0 line~u2028"},
		{"private \U000f0000", "private ~U000f0000"},
		{`back\slash "quoted"`, `back\slash "quoted"`},
	} {
		want := c.want
		if !strings.Contains(c.in, `\`) {
			want = bs(want)
		}
		if got := terminalSafe(c.in); got != want {
			t.Errorf("terminalSafe(%q) = %q, want %q", c.in, got, want)
		}
	}
}

// storeStatus is a running service's status with a syslog store.
func storeStatus() model.Status {
	return model.Status{Syslog: &model.SyslogStatus{Enabled: true, Listening: true, Listen: "[::]:514", Store: &model.SyslogUsage{
		Bytes: 3<<20 + 512<<10, Chunks: 4, Messages: 120, OpenMessages: 3, KeepMB: 100, KeepDays: 7,
		Oldest: testNow.Add(-48 * time.Hour).Format(time.RFC3339Nano), Newest: testNow.Add(-time.Minute).Format(time.RFC3339Nano),
	}}}
}

// TestSyslogRetentionShow: without flags the command shows the store's volume and the limits,
// as the running service reports them.
func TestSyslogRetentionShow(t *testing.T) {
	f := &fakeService{status: storeStatus()}
	useService(t, f)
	dir := t.TempDir()
	var out strings.Builder
	if err := syslogCommand(&out, io.Discard, []string{"retention", "--data", dir}); err != nil {
		t.Fatal(err)
	}
	u := f.status.Syslog.Store
	want := "Syslog store: 3.5 MiB of 100 MiB used (3%), 4 sealed chunks, 120 messages (3 in the open chunk)\n" +
		"              oldest message " + at(u.Oldest, "2006-01-02 15:04:05") + ", newest " + at(u.Newest, "2006-01-02 15:04:05") + " (this PC's local time)\n" +
		"Retention:    keep at most 100 MiB, and no message older than 7 days\n" +
		"To change it: att-monitor syslog retention --keep-mb N [--keep-days D] (or on the dashboard's Syslog page)\n"
	if out.String() != want {
		t.Errorf("output:\n%s\nwant:\n%s", out.String(), want)
	}
	if _, posts := f.recorded(); len(posts) != 0 {
		t.Errorf("posted %v", posts)
	}

	// A service without a store: the limits of config.json.
	f.status = model.Status{}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"version":1,"syslog":{"enabled":false,"keep_mb":250,"keep_days":0}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := syslogCommand(&out, io.Discard, []string{"retention", "--data", dir}); err != nil {
		t.Fatal(err)
	}
	wantText(t, out.String(), "Syslog is off (syslog.enabled is false in config.json)", "Syslog store: the running service keeps no syslog store",
		"Retention:    keep at most 250 MiB, no age limit")
}

// TestSyslogRetentionChange: a change goes to POST /api/syslog/retention; a limit left out keeps
// the one in force; a change that deletes messages now is confirmed first, and refused when
// nobody can confirm it without --yes.
func TestSyslogRetentionChange(t *testing.T) {
	f := &fakeService{status: storeStatus(), change: model.ConfigChange{Target: "monitor", What: "syslog.keep_mb, syslog.keep_days",
		Before: "keep_mb 100, keep_days 7", After: "keep_mb 50, keep_days 7", Actor: "operator via cli", Result: "applied"}}
	useService(t, f)
	dir := t.TempDir()
	var asked []string
	answer, canAsk := false, false
	restore := confirmDeletion
	confirmDeletion = func(out io.Writer, q string) (bool, bool) {
		asked = append(asked, q)
		return answer, canAsk
	}
	defer func() { confirmDeletion = restore }()
	retention := func(args ...string) (string, error) {
		var out strings.Builder
		err := syslogCommand(&out, io.Discard, append(append([]string{"retention"}, args...), "--data", dir))
		return out.String(), err
	}
	posted := func() []map[string]any { _, p := f.recorded(); return p }

	out, err := retention("--keep-mb", "50")
	if err != nil {
		t.Fatal(err)
	}
	if p := posted(); len(p) != 1 || !reflect.DeepEqual(p[0], map[string]any{"keep_mb": 50.0, "keep_days": 7.0, "client": "cli"}) {
		t.Errorf("posted %v", p)
	}
	wantText(t, out, "Syslog retention: keep_mb 100, keep_days 7 → keep_mb 50, keep_days 7 (applied)\n",
		"Now: 3.5 MiB of 100 MiB used (3%), 4 sealed chunks")
	if len(asked) != 0 {
		t.Errorf("asked %q for a change that deletes nothing", asked)
	}

	// --keep-days 1 deletes the messages older than a day (the oldest is two days old), and
	// nobody can confirm that.
	out, err = retention("--keep-days", "1")
	if err == nil || !strings.Contains(err.Error(), "--yes") || len(posted()) != 1 {
		t.Errorf("unconfirmed: %v, posted %v", err, posted())
	}
	wantText(t, out, "The oldest syslog messages are deleted as soon as the new limits apply: its oldest message, received", "is older than 1 day.",
		"(a syslog_prune record), but the messages themselves cannot be brought back.")
	// Declined.
	canAsk = true
	if out, err = retention("--keep-days", "1"); err != nil || !strings.Contains(out, "Nothing was changed.") || len(posted()) != 1 {
		t.Errorf("declined: %v %q, posted %v", err, out, posted())
	}
	// Confirmed.
	answer = true
	if _, err = retention("--keep-days", "1"); err != nil {
		t.Fatal(err)
	}
	if p := posted(); len(p) != 2 || !reflect.DeepEqual(p[1], map[string]any{"keep_mb": 100.0, "keep_days": 1.0, "client": "cli"}) {
		t.Errorf("confirmed: posted %v", p)
	}
	if len(asked) != 3 || asked[2] != "Delete them?" {
		t.Errorf("asked %q", asked)
	}
	// --yes confirms beforehand: 3.5 MiB do not fit in 1 MiB.
	if out, err = retention("--keep-mb", "1", "--keep-days", "0", "--yes"); err != nil || len(asked) != 3 {
		t.Errorf("--yes: %v %q, asked %q", err, out, asked)
	}
	if p := posted(); len(p) != 3 || !reflect.DeepEqual(p[2], map[string]any{"keep_mb": 1.0, "keep_days": 0.0, "client": "cli"}) {
		t.Errorf("--yes: posted %v", p)
	}

	// The limits in force, while the store holds more than they allow (it prunes after the next
	// seal): nothing to confirm, as nothing changes.
	f.mu.Lock()
	f.status.Syslog.Store.Bytes = 120 << 20
	f.mu.Unlock()
	if _, err = retention("--keep-mb", "100", "--keep-days", "7"); err != nil || len(asked) != 3 {
		t.Errorf("unchanged: %v, asked %q", err, asked)
	}
	if p := posted(); len(p) != 4 || !reflect.DeepEqual(p[3], map[string]any{"keep_mb": 100.0, "keep_days": 7.0, "client": "cli"}) {
		t.Errorf("unchanged: posted %v", p)
	}

	// The service refuses.
	f.fail, f.failMsg = http.StatusConflict, "a change of the syslog retention is already in progress"
	if _, err = retention("--keep-mb", "60"); err == nil || err.Error() != "service: a change of the syslog retention is already in progress" {
		t.Errorf("refused: %v", err)
	}

	// Values out of range never reach the service.
	n := len(posted())
	noService(t, false)
	for _, args := range [][]string{{"--keep-mb", "0"}, {"--keep-mb", "1048577"}, {"--keep-days", "-1"}, {"--keep-days", "3651"}, {"--keep-mb", "x"}, {"50"}} {
		if _, err := retention(args...); err == nil {
			t.Errorf("%q accepted", args)
		}
	}
	if len(posted()) != n {
		t.Error("an invalid change was posted")
	}
}

// The by-hand instructions of `gateway syslog`, to set it on (with this PC's address, or without
// it) and to stop it.
var (
	setByHandHere = "To set it on the gateway itself: open https://192.168.1.254, Diagnostics > Syslog (the page asks for the Device Access Code), " +
		"set Syslog to On (the page then enables its other fields), Server IP Address 192.168.1.71 (this PC), Server Port 514, and save.\n"
	setByHandNoIP = "Server IP Address this PC's IPv4 address on the gateway's network, Server Port 514, and save.\n"
	stopByHand    = "To stop it on the gateway itself: open https://192.168.1.254, Diagnostics > Syslog (the page asks for the Device Access Code), " +
		"set Syslog to Off and save.\n"
)

// TestGatewaySyslogStatus: Status.syslog in words, whether att-monitor keeps the gateway sending
// here, and how to set it by hand only while the gateway does not send here and att-monitor does
// not set it (not kept, or setting it failed), and no message arrived since the setting was read.
func TestGatewaySyslogStatus(t *testing.T) {
	st := storeStatus()
	sl := st.Syslog
	sl.Received, sl.Recorded, sl.Dropped, sl.Rejected = 12, 11, 1, 3
	sl.LastAt, sl.Last = "2026-10-05T21:59:00Z", "kernel: link up\x1b[0m"
	sl.Gateway = &model.SyslogSetting{Enabled: true, Server: "192.168.1.50", Port: 514, Level: "Informational"}
	sl.GatewayAt, sl.GatewaySeq = "2026-10-05T12:00:00Z", 1234
	sl.State, sl.Problem = "elsewhere", "the gateway sends its log to 192.168.1.50:514, not to this computer (192.168.1.71:514)"
	st.LocalLink = &model.LocalLink{LocalIP: "192.168.1.71"}
	st.Conditions = []model.Condition{{Code: "SYSLOG_STORE_FAILING", Severity: "warning", Message: "The syslog store has failed"},
		{Code: "OPTICAL_RX_LOW_ALARM", Severity: "critical", Message: "optics"}}
	f := &fakeService{status: st}
	useService(t, f)
	dir := t.TempDir()
	status := func(args ...string) string {
		t.Helper()
		var out strings.Builder
		if err := gatewaySyslog(&out, append(args, "--data", dir)); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	// Not kept, sending elsewhere, but messages arrived since that was read: no instructions.
	got := status()
	wantText(t, got,
		"Syslog receiver:  listening on [::]:514 (UDP)\n",
		"Since the start:  12 messages received, 11 stored, 1 dropped (over the receiver's limits), 3 rejected (from other senders)\n",
		"Newest message:   "+at(sl.LastAt, "2006-01-02 15:04:05")+bs("  kernel: link up~x1b[0m"),
		"Syslog store:     3.5 MiB of 100 MiB used (3%)",
		"Retention:        keep at most 100 MiB, and no message older than 7 days (att-monitor syslog retention)\n",
		"Gateway setting:  on, sending to 192.168.1.50 port 514, level Informational (read "+at(sl.GatewayAt, "2006-01-02 15:04")+", ledger record #1234)\n",
		"State:            elsewhere: the gateway sends its log to 192.168.1.50:514, not to this computer (192.168.1.71:514)\n",
		"Condition:        [warning] The syslog store has failed\n",
		"Kept:             no, att-monitor only reads this setting; `att-monitor gateway syslog on` sends the gateway's log to this PC and keeps it so\n",
		"Messages have arrived since the setting was read, so it may have been changed on the gateway since.\n")
	if strings.Contains(got, "optics") || strings.ContainsRune(got, 0x1b) || strings.Contains(got, "To set it on the gateway itself") ||
		strings.Contains(got, "later version") {
		t.Errorf("unexpected content:\n%s", got)
	}
	// No message since the read: how to set it by hand.
	sl.LastAt = "2026-10-05T11:59:00Z"
	if got := status(); !strings.HasSuffix(got, setByHandHere) || strings.Contains(got, "Messages have arrived") {
		t.Errorf("not kept, sending elsewhere:\n%s", got)
	}

	// Kept and sent here: no instructions.
	sl.State, sl.Problem, sl.Enforce = "ok", "", true
	sl.Target = &model.SyslogTarget{Enabled: true, Server: "192.168.1.71", Port: 514, Level: "Notice"}
	sl.Gateway = &model.SyslogSetting{Enabled: true, Server: "192.168.1.71", Port: 514, Level: "Notice"}
	got = status("status")
	wantText(t, got, "State:            ok: the gateway sends its log to this PC\n",
		"Kept:             yes, att-monitor keeps it sending to 192.168.1.71 port 514, level Notice: it reads the setting in its daily settings check"+
			" (and after this PC's address changes) and sets it again whenever it differs; `att-monitor gateway syslog off` stops it\n")
	if strings.Contains(got, "Server IP Address") {
		t.Errorf("ok:\n%s", got)
	}
	// Kept, but read as off (before the service set it): it will, no instructions.
	sl.State, sl.Gateway = "off", &model.SyslogSetting{Port: 514, Level: "Error"}
	if got := status(); !strings.HasSuffix(got, "att-monitor sets it again at its next settings check, or now with `att-monitor gateway syslog on`.\n") {
		t.Errorf("kept, read as off:\n%s", got)
	}
	// Kept, but setting it failed, or cannot be done: instructions.
	for name, set := range map[string]func(){
		"check failed": func() {
			sl.State, sl.Problem = "error", "the latest change of the gateway's Syslog setting failed: gateway: HTTP 500"
		},
		"not understood": func() { sl.State, sl.Gateway = "unknown", nil },
		"no access code": func() {
			st.Conditions = append(st.Conditions, model.Condition{Code: "NO_ACCESS_CODE", Severity: "info"})
		},
		"certificate": func() {
			st.GatewayCert = &model.GatewayCertState{Pinned: strings.Repeat("ab", 32), Pending: strings.Repeat("cd", 32)}
		},
		"cert condition": func() {
			st.Conditions = append(st.Conditions, model.Condition{Code: "GATEWAY_CERT_CHANGED", Severity: "critical"})
		},
		"setting failed": func() { // the state stays as read; the problem and a condition say so
			sl.Problem = "the gateway does not send its log to a syslog server (its Syslog setting is off); the monitor could not set it: gateway: HTTP 500"
			st.Conditions = append(st.Conditions, model.Condition{Code: "SYSLOG_SETTING_FAILED", Severity: "warning", Message: "The monitor could not set the gateway's Syslog page"})
		},
		"(control: none)": func() {},
	} {
		saved, savedConds, savedCert := *sl, st.Conditions, st.GatewayCert
		set()
		f.mu.Lock()
		f.status = st
		f.mu.Unlock()
		got := status()
		if hand := strings.HasSuffix(got, setByHandHere); hand != (name != "(control: none)") {
			t.Errorf("%s: instructions %v:\n%s", name, hand, got)
		}
		*sl, st.Conditions, st.GatewayCert = saved, savedConds, savedCert
	}
	f.mu.Lock()
	f.status = st
	f.mu.Unlock()

	// Not kept, not read yet, nothing received, the receiver down, this PC's address unknown.
	sl.Enforce, sl.Target = false, nil
	sl.Gateway, sl.GatewayAt, sl.GatewaySeq, sl.State, sl.Problem = nil, "", 0, "unknown", "the gateway's Syslog setting has not been read yet"
	sl.LastAt, sl.Last, sl.Received = "", "", 0
	sl.Listening, sl.ListenErr = false, "listen udp :514: bind: Only one usage of each socket address"
	st.LocalLink = nil
	f.mu.Lock()
	f.status = st
	f.mu.Unlock()
	wantText(t, status(), "Syslog receiver:  NOT listening on [::]:514 (UDP): listen udp :514: bind: Only one usage",
		"Gateway setting:  not read yet", "State:            unknown: the gateway's Syslog setting has not been read yet",
		"Kept:             no, att-monitor only reads this setting", setByHandNoIP)

	// --json: Status.syslog as it is.
	var js model.SyslogStatus
	if err := json.Unmarshal([]byte(status("--json")), &js); err != nil || !reflect.DeepEqual(&js, sl) {
		t.Errorf("JSON %v: %+v", err, js)
	}

	// No syslog at all: config.json says whether the service keeps the setting (it does by
	// default, unless it cannot log in).
	f.mu.Lock()
	f.status = model.Status{}
	f.mu.Unlock()
	if got := status(); !strings.Contains(got, "The running service reports nothing about syslog") || strings.Contains(got, "on the gateway itself") {
		t.Errorf("no syslog, kept:\n%s", got)
	}
	f.mu.Lock()
	f.status = model.Status{Conditions: []model.Condition{{Code: "NO_ACCESS_CODE", Severity: "info"}}}
	f.mu.Unlock()
	if got := status(); !strings.HasSuffix(got, setByHandNoIP) {
		t.Errorf("no syslog, no access code:\n%s", got)
	}
	f.mu.Lock()
	f.status = model.Status{}
	f.mu.Unlock()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"version":1,"gateway":{"enforce_syslog":false}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := status(); !strings.HasSuffix(got, setByHandNoIP) {
		t.Errorf("no syslog, not kept:\n%s", got)
	}
	if posts := f.gwRecorded(); len(posts) != 0 {
		t.Errorf("a status changed the setting: %v", posts)
	}
}

// TestGatewaySyslogArguments: wrong arguments are refused before the service is asked.
func TestGatewaySyslogArguments(t *testing.T) {
	noService(t, false)
	dir := t.TempDir()
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"enforce"}, `unknown action "enforce" (usage: att-monitor gateway syslog [status|on|off] [--json] [--data DIR])`},
		{[]string{"enable"}, `unknown action "enable"`},
		{[]string{"on", "now"}, `unexpected argument "now" (usage: att-monitor gateway syslog [status|on|off] [--json] [--data DIR])`},
		{[]string{"status", "off"}, `unexpected argument "off"`},
		{[]string{"--json", "on"}, `unexpected argument "on"`},
		{[]string{"off", "--yes"}, "flag provided but not defined: -yes"},
	} {
		err := gatewaySyslog(io.Discard, append(tc.args, "--data", dir))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: %v, want %q", tc.args, err, tc.want)
		}
	}
	// Through the command line.
	if err := run([]string{"gateway", "syslog", "bogus", "--data", dir}); err == nil || !strings.Contains(err.Error(), `unknown action "bogus"`) {
		t.Errorf("run gateway syslog bogus: %v", err)
	}
	if err := run([]string{"gateway", "bogus"}); err == nil || !strings.Contains(err.Error(), "gateway syslog [status|on|off] [--json]") {
		t.Errorf("gateway usage: %v", err)
	}
	if !strings.Contains(usageText, "att-monitor gateway syslog [status|on|off] [--json] [--data DIR]") {
		t.Error("the usage text does not name gateway syslog on|off")
	}
}

// TestGatewaySyslogOnOff: on and off go to POST /api/gateway/syslog (client cli) and print the
// recorded change and what att-monitor does from now on; --json prints the change.
func TestGatewaySyslogOnOff(t *testing.T) {
	onCC := model.ConfigChange{Target: "gateway", What: "syslog.ha (Syslog, Server IP Address, Server Port, Log Level)", Before: "off",
		After: "on -> 192.168.1.71:514, level Notice", Actor: "operator via cli", Result: "verified; monitor setting enforce_syslog changed from false to true"}
	f := &fakeService{status: storeStatus(), gwChange: onCC}
	useService(t, f)
	dir := t.TempDir()
	var out strings.Builder
	if err := gatewaySyslog(&out, []string{"on", "--data", dir}); err != nil {
		t.Fatal(err)
	}
	want := "Gateway setting syslog.ha (Syslog, Server IP Address, Server Port, Log Level): off → on -> 192.168.1.71:514, level Notice " +
		"(verified; monitor setting enforce_syslog changed from false to true)\n" +
		"att-monitor keeps it so: it reads the setting in its daily settings check (and after this PC's address changes) and sets it again whenever it differs." +
		" `att-monitor gateway syslog off` stops it.\n"
	if out.String() != want {
		t.Errorf("on:\n%s\nwant:\n%s", out.String(), want)
	}

	offCC := onCC
	offCC.Before, offCC.After, offCC.Result = onCC.After, "off", "verified; monitor setting enforce_syslog changed from true to false"
	f.mu.Lock()
	f.gwChange = offCC
	f.mu.Unlock()
	out.Reset()
	if err := gatewaySyslog(&out, []string{"OFF", "--data", dir}); err != nil {
		t.Fatal(err)
	}
	wantText(t, out.String(), "Gateway setting syslog.ha (Syslog, Server IP Address, Server Port, Log Level): on -> 192.168.1.71:514, level Notice → off (verified;",
		"The gateway sends its log to no syslog server now, and att-monitor no longer sets it (it still reads it daily). `att-monitor gateway syslog on` sends it to this PC again.\n")

	// --json: the change as the service answered it.
	out.Reset()
	if err := gatewaySyslog(&out, []string{"off", "--json", "--data", dir}); err != nil {
		t.Fatal(err)
	}
	var js model.ConfigChange
	if err := json.Unmarshal([]byte(out.String()), &js); err != nil || js != offCC {
		t.Errorf("JSON %v: %+v", err, js)
	}
	// What a gateway page holds is escaped.
	f.mu.Lock()
	f.gwChange.Before = "on -> 192.168.1.71:514, level Notice\x1b[2J"
	f.mu.Unlock()
	out.Reset()
	if err := gatewaySyslog(&out, []string{"off", "--data", dir}); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); strings.ContainsRune(got, 0x1b) || !strings.Contains(got, bs("Notice~x1b[2J → off")) {
		t.Errorf("escaping:\n%s", got)
	}

	want4 := []map[string]any{{"enabled": true, "client": "cli"}, {"enabled": false, "client": "cli"}, {"enabled": false, "client": "cli"}, {"enabled": false, "client": "cli"}}
	if posts := f.gwRecorded(); !reflect.DeepEqual(posts, want4) {
		t.Errorf("posted %v", posts)
	}
}

// onlyJSON decodes s, which must hold exactly one JSON value and nothing else (a script reads
// it), into v, rejecting fields v does not have.
func onlyJSON(t *testing.T, s string, v any) {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(s))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("not JSON (%v):\n%s", err, s)
	}
	if err := dec.Decode(&json.RawMessage{}); err != io.EOF {
		t.Fatalf("more than one JSON value (%v):\n%s", err, s)
	}
}

// wantFailedJSON checks the output of a failed change with --json: {error, change} (as the
// service answers a failed change) with the command's error and the change reported, if any.
func wantFailedJSON(t *testing.T, out string, err error, change *model.ConfigChange) {
	t.Helper()
	var js web.ConfigChangeError
	onlyJSON(t, out, &js)
	if err == nil || js.Error != err.Error() {
		t.Errorf("JSON error %q, the command's error %v", js.Error, err)
	}
	if (js.Change == nil) != (change == nil) || (change != nil && *js.Change != *change) {
		t.Errorf("JSON change %+v, want %+v", js.Change, change)
	}
}

// TestGatewaySyslogOnOffErrors: a failed change prints the change the service reported and the
// error; how to make it by hand only when the gateway did not take the change (not when its
// record failed, nor when the service only refused to run two gateway operations at once).
// With --json it prints only {error, change} - the error and the change reported, if any - and
// still fails (its exit status), so that a script tells a failure from a change.
func TestGatewaySyslogOnOffErrors(t *testing.T) {
	st := storeStatus()
	st.LocalLink = &model.LocalLink{LocalIP: "192.168.1.71"}
	f := &fakeService{status: st}
	useService(t, f)
	dir := t.TempDir()
	failed := model.ConfigChange{Target: "gateway", What: "syslog.ha", Before: "off", After: "on -> 192.168.1.71:514, level Notice", Actor: "operator via cli",
		Result: "failed: gateway: POST syslog.ha (Update): HTTP 500; Save not posted"}
	taken := failed
	taken.Result = "verified; monitor setting enforce_syslog changed from false to true"
	for _, tc := range []struct {
		name    string
		action  string
		code    int
		body    any
		wantErr string
		texts   []string
		hand    string              // the instructions printed ("" none)
		change  *model.ConfigChange // the change reported (nil none)
	}{
		{"gateway failed", "on", 502, map[string]any{"error": "gateway: POST syslog.ha (Update): HTTP 500; Save not posted", "change": failed},
			"service: gateway: POST syslog.ha (Update): HTTP 500; Save not posted",
			[]string{"Change: syslog.ha: off → on -> 192.168.1.71:514, level Notice (failed: gateway: POST syslog.ha (Update): HTTP 500; Save not posted)\n"}, setByHandHere, &failed},
		{"stop failed", "off", 502, map[string]any{"error": "gateway: setting not applied: Syslog reads on (wanted off) after saving"},
			"service: gateway: setting not applied", nil, stopByHand, nil},
		{"no access code", "on", 503, map[string]any{"error": "gateway Syslog setting change: no gateway device access code is stored"},
			"no gateway device access code is stored", nil, setByHandHere, nil},
		{"taken, not recorded", "on", 500, map[string]any{"error": "the gateway reports the setting as changed (verified; ...), but the change could not be completed: disk full", "change": taken},
			"but the change could not be completed: disk full",
			[]string{"Change: syslog.ha: off → on -> 192.168.1.71:514, level Notice (verified; monitor setting enforce_syslog changed from false to true)\n"}, "", &taken},
		{"busy", "on", 409, map[string]any{"error": "a gateway setting change or certificate confirmation is already in progress"},
			"service: a gateway setting change or certificate confirmation is already in progress", nil, "", nil},
		{"not JSON", "on", 502, "Bad Gateway", "service: HTTP 502", nil, setByHandHere, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.mu.Lock()
			f.gwFail, f.gwFailBody = tc.code, tc.body
			f.mu.Unlock()
			var out strings.Builder
			err := gatewaySyslog(&out, []string{tc.action, "--data", dir})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %v, want %q", err, tc.wantErr)
			}
			got := out.String()
			wantText(t, got, tc.texts...)
			if tc.hand != "" && !strings.HasSuffix(got, tc.hand) {
				t.Errorf("no instructions %q:\n%s", tc.hand, got)
			}
			if tc.hand == "" && strings.Contains(got, "on the gateway itself") {
				t.Errorf("instructions although the gateway took the change or nothing was tried:\n%s", got)
			}
			if strings.Contains(got, "Gateway setting ") {
				t.Errorf("a failed change printed as made:\n%s", got)
			}

			// --json: the same failure as JSON, and nothing else; the command still fails.
			out.Reset()
			jerr := gatewaySyslog(&out, []string{tc.action, "--json", "--data", dir})
			if jerr == nil || jerr.Error() != err.Error() {
				t.Fatalf("--json: error %v, want %v", jerr, err)
			}
			wantFailedJSON(t, out.String(), jerr, tc.change)
		})
	}
}

// TestGatewaySyslogWithoutService: with the service stopped the change is made on the ledger
// directly, like `gateway notification on|off`; before it logs in to the gateway the strict
// certificate check refuses a gateway whose certificate is not pinned (no request is made), and
// the command says how to make the change by hand. With --json a failure prints only {error,
// change}, as through the service.
func TestGatewaySyslogWithoutService(t *testing.T) {
	// A data directory whose gateway has no pinned certificate (and is this computer: nothing
	// could reach a real gateway even if the check let it).
	dir := newDataDir(t, `"gateway":{"host":"127.0.0.1"}`)
	noService(t, true)
	var out strings.Builder
	err := gatewaySyslog(&out, []string{"on", "--data", dir})
	if err == nil || !strings.Contains(err.Error(), "the gateway certificate is not pinned yet") {
		t.Fatalf("no pin: %v", err)
	}
	wantText(t, out.String(), "To set it on the gateway itself: open https://127.0.0.1, Diagnostics > Syslog", "Server IP Address this PC's IPv4 address")
	// --json: the refusal as JSON (no change was reported), and nothing else.
	out.Reset()
	jerr := gatewaySyslog(&out, []string{"on", "--json", "--data", dir})
	if jerr == nil || jerr.Error() != err.Error() {
		t.Fatalf("no pin, --json: %v", jerr)
	}
	wantFailedJSON(t, out.String(), jerr, nil)
	led := openLedgerReadOnly(t, dir)
	var last model.Body
	if err := led.Scan(0, func(_ model.Envelope, b model.Body) error { last = b; return nil }); err != nil {
		t.Fatal(err)
	}
	if last.Type == model.TypeConfigChange {
		t.Errorf("a refused change was recorded: %s", last.Data)
	}

	// The change as the monitor makes it on the ledger.
	restore := gatewaySyslogOffline
	t.Cleanup(func() { gatewaySyslogOffline = restore })
	var calls []string
	gatewaySyslogOffline = func(dataDir string, on bool) (model.ConfigChange, error) {
		calls = append(calls, fmt.Sprintf("%s|%v", dataDir, on))
		return model.ConfigChange{Target: "gateway", What: "syslog.ha", Before: "off", After: "on -> 192.168.1.71:514, level Notice", Actor: "cli user x", Result: "verified"}, nil
	}
	out.Reset()
	if err := gatewaySyslog(&out, []string{"on", "--data", dir}); err != nil {
		t.Fatal(err)
	}
	wantText(t, out.String(), "Gateway setting syslog.ha: off → on -> 192.168.1.71:514, level Notice (verified)\n",
		"The service is not running: the gateway's messages are received, and the setting kept, once it runs (att-monitor start).\n")
	throttled := model.ConfigChange{Target: "gateway", What: "syslog.ha", Before: "on -> 192.168.1.71:514, level Notice", After: "off", Actor: "cli user x",
		Result: "failed: gateway: login throttled"}
	gatewaySyslogOffline = func(dataDir string, on bool) (model.ConfigChange, error) {
		calls = append(calls, fmt.Sprintf("%s|%v", dataDir, on))
		return throttled, errors.New("gateway: login throttled")
	}
	out.Reset()
	if err := gatewaySyslog(&out, []string{"off", "--data", dir}); err == nil || err.Error() != "gateway: login throttled" {
		t.Errorf("failed offline change: %v", err)
	}
	wantText(t, out.String(), "Change: syslog.ha: on -> 192.168.1.71:514, level Notice → off (failed: gateway: login throttled)\n", "set Syslog to Off and save.")
	// --json: the error and the change the monitor reported, as JSON only; still a failure.
	out.Reset()
	jerr = gatewaySyslog(&out, []string{"off", "--json", "--data", dir})
	if jerr == nil || jerr.Error() != "gateway: login throttled" {
		t.Errorf("failed offline change, --json: %v", jerr)
	}
	wantFailedJSON(t, out.String(), jerr, &throttled)
	// A failure that reports no change.
	gatewaySyslogOffline = func(dataDir string, on bool) (model.ConfigChange, error) {
		calls = append(calls, fmt.Sprintf("%s|%v", dataDir, on))
		return model.ConfigChange{}, errors.New("a gateway settings check or change is already running")
	}
	out.Reset()
	jerr = gatewaySyslog(&out, []string{"on", "--json", "--data", dir})
	if jerr == nil || jerr.Error() != "a gateway settings check or change is already running" {
		t.Errorf("busy offline, --json: %v", jerr)
	}
	wantFailedJSON(t, out.String(), jerr, nil)
	if want := []string{dir + "|true", dir + "|false", dir + "|false", dir + "|true"}; !reflect.DeepEqual(calls, want) {
		t.Errorf("calls %q, want %q", calls, want)
	}
}

// TestSyslogCommandsWithoutService: with the service stopped, retention and the gateway status
// read the store directly (read-only), and a retention change is made on the ledger like the
// other operator changes: saved, recorded as a config_change, applied when the service starts.
func TestSyslogCommandsWithoutService(t *testing.T) {
	dir := newDataDir(t, `"syslog":{"enabled":true,"keep_mb":100,"keep_days":0}`)
	// Messages in the store, as a service left them.
	st, err := syslogstore.New(syslogstore.Options{Dir: config.PathsFor(dir).Syslog})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Recover(testNow); err != nil {
		t.Fatal(err)
	}
	msgs := []model.SyslogMessage{{RX: "2026-10-05T21:00:00Z", Src: "192.168.1.254:514", Raw: "one"}, {RX: "2026-10-05T21:00:01Z", Src: "192.168.1.254:514", Raw: "two"}}
	if _, err := st.Append(msgs, 0, 0, testNow); err != nil {
		t.Fatal(err)
	}
	if c, err := st.Seal(testNow, "stop", true); err != nil || c == nil {
		t.Fatalf("seal: %v %v", c, err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	noService(t, true)

	var out strings.Builder
	if err := syslogCommand(&out, io.Discard, []string{"retention", "--data", dir}); err != nil {
		t.Fatal(err)
	}
	wantText(t, out.String(), "The service is not running: the limits are those of config.json", "of 100 MiB used (0%), 1 sealed chunk, 2 messages\n",
		"oldest message "+at("2026-10-05T21:00:00Z", "2006-01-02 15:04:05"), "Retention:    keep at most 100 MiB, no age limit")
	out.Reset()
	if err := gatewaySyslog(&out, []string{"--data", dir}); err != nil {
		t.Fatal(err)
	}
	wantText(t, out.String(), "The service is not running (its dashboard does not answer)", "1 sealed chunk, 2 messages")

	out.Reset()
	if err := syslogCommand(&out, io.Discard, []string{"retention", "--keep-mb", "50", "--data", dir}); err != nil {
		t.Fatal(err)
	}
	wantText(t, out.String(), "Syslog retention: keep_mb 100, keep_days 0 → keep_mb 50, keep_days 0 (applied; the syslog store is not running, so nothing is deleted now)",
		"The service applies the new limits, and deletes what no longer fits, when it starts.")
	cfg, err := config.Load(filepath.Join(dir, "config.json"))
	if err != nil || cfg.Syslog.KeepMB != 50 || cfg.Syslog.KeepDays != 0 {
		t.Fatalf("saved configuration: %v %+v", err, cfg.Syslog)
	}
	var last model.Body
	led := openLedgerReadOnly(t, dir)
	if err := led.Scan(0, func(_ model.Envelope, b model.Body) error { last = b; return nil }); err != nil {
		t.Fatal(err)
	}
	var cc model.ConfigChange
	if last.Type != model.TypeConfigChange || json.Unmarshal(last.Data, &cc) != nil || cc.After != "keep_mb 50, keep_days 0" || !strings.HasPrefix(cc.Actor, "cli") {
		t.Errorf("last record %s: %+v", last.Type, cc)
	}

	// The limits in force: nothing is recorded, and nothing is left for the service to apply.
	out.Reset()
	if err := syslogCommand(&out, io.Discard, []string{"retention", "--keep-mb", "50", "--data", dir}); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "Syslog retention: keep_mb 50, keep_days 0 → keep_mb 50, keep_days 0 (unchanged: already in force)\n" {
		t.Errorf("unchanged: %q", got)
	}
	var again model.Body
	if err := openLedgerReadOnly(t, dir).Scan(0, func(_ model.Envelope, b model.Body) error { again = b; return nil }); err != nil {
		t.Fatal(err)
	}
	if again.Seq != last.Seq {
		t.Errorf("records were added: #%d %s after #%d", again.Seq, again.Type, last.Seq)
	}
}

// TestPrintMongoSyslog: the syslog part of `mongo verify`.
func TestPrintMongoSyslog(t *testing.T) {
	res := mongostore.VerifyResult{SyslogDocs: 120, SyslogChunks: 4, SyslogBad: 1, SyslogPruned: 2, SyslogForged: 3, SyslogMissing: 5}
	var out strings.Builder
	printMongoSyslog(&out, res, nil)
	want := "  syslog: 120 documents; 4 chunks compared with their syslog_chunk records (each line, its SHA-256 and the message count), 1 not matching\n" +
		"          2 documents of chunks a syslog_prune record deleted, 3 of chunks no syslog_chunk record names\n" +
		"          5 chunks the syslog store keeps but the copy lacks\n"
	if out.String() != want {
		t.Errorf("output:\n%s\nwant:\n%s", out.String(), want)
	}
	out.Reset()
	printMongoSyslog(&out, mongostore.VerifyResult{SyslogDocs: 1, SyslogChunks: 1, SyslogPruned: 1, SyslogMissing: 1}, nil)
	if got := out.String(); !strings.Contains(got, "syslog: 1 document; 1 chunk compared") || !strings.Contains(got, "1 document of chunks") ||
		!strings.Contains(got, "1 chunk the syslog store keeps") {
		t.Errorf("singular:\n%s", got)
	}
	out.Reset()
	printMongoSyslog(&out, mongostore.VerifyResult{SyslogDocs: 9, SyslogChunks: 1, SyslogTrimmed: 7}, nil)
	if got := out.String(); !strings.HasSuffix(got, "          0 chunks the syslog store keeps but the copy lacks\n"+
		"          7 older chunks the syslog store keeps whose documents the copy's size limit (syslog.keep_mb) deleted, oldest first\n") {
		t.Errorf("with trimmed chunks:\n%s", got)
	}
	out.Reset()
	printMongoSyslog(&out, res, errors.New("syslogstore: no such directory"))
	if !strings.HasSuffix(out.String(), "chunks the syslog store keeps but the copy lacks: not checked, the store cannot be read (syslogstore: no such directory)\n") {
		t.Errorf("without the store:\n%s", out.String())
	}
}
