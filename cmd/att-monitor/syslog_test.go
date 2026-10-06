package main

import (
	"encoding/json"
	"errors"
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

// TestGatewaySyslogStatus: Status.syslog in words, how to set the gateway by hand while it does
// not send here, and on/off refused in this version.
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
	var out strings.Builder
	if err := gatewaySyslog(&out, []string{"--data", dir}); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	wantText(t, got,
		"Syslog receiver:  listening on [::]:514 (UDP)\n",
		"Since the start:  12 messages received, 11 stored, 1 dropped (over the receiver's limits), 3 rejected (from other senders)\n",
		"Newest message:   "+at(sl.LastAt, "2006-01-02 15:04:05")+bs("  kernel: link up~x1b[0m"),
		"Syslog store:     3.5 MiB of 100 MiB used (3%)",
		"Retention:        keep at most 100 MiB, and no message older than 7 days (att-monitor syslog retention)\n",
		"Gateway setting:  on, sending to 192.168.1.50 port 514, level Informational (read "+at(sl.GatewayAt, "2006-01-02 15:04")+", ledger record #1234)\n",
		"State:            elsewhere: the gateway sends its log to 192.168.1.50:514, not to this computer (192.168.1.71:514)\n",
		"Condition:        [warning] The syslog store has failed\n",
		"setting it automatically comes in a later version.",
		"open https://192.168.1.254, Diagnostics > Syslog, switch Syslog on, Server IP Address 192.168.1.71 (this PC), Server Port 514, and save")
	if strings.Contains(got, "optics") || strings.ContainsRune(got, 0x1b) {
		t.Errorf("unexpected content:\n%s", got)
	}

	// The gateway sends here: no instructions. Then: not read yet, the receiver down.
	sl.State, sl.Problem = "ok", ""
	out.Reset()
	if err := gatewaySyslog(&out, []string{"status", "--data", dir}); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "State:            ok: the gateway sends its log to this PC\n") || strings.Contains(got, "Server IP Address") {
		t.Errorf("ok:\n%s", got)
	}
	sl.Gateway, sl.GatewaySeq, sl.State, sl.Problem = nil, 0, "unknown", "the gateway's Syslog setting has not been read yet"
	sl.Listening, sl.ListenErr = false, "listen udp :514: bind: Only one usage of each socket address"
	st.LocalLink = nil
	f.status = st
	out.Reset()
	if err := gatewaySyslog(&out, []string{"--data", dir}); err != nil {
		t.Fatal(err)
	}
	wantText(t, out.String(), "Syslog receiver:  NOT listening on [::]:514 (UDP): listen udp :514: bind: Only one usage",
		"Gateway setting:  not read yet", "State:            unknown: the gateway's Syslog setting has not been read yet",
		"Server IP Address this PC's IPv4 address on the gateway's network")

	// --json: Status.syslog as it is.
	out.Reset()
	if err := gatewaySyslog(&out, []string{"--json", "--data", dir}); err != nil {
		t.Fatal(err)
	}
	var js model.SyslogStatus
	if err := json.Unmarshal([]byte(out.String()), &js); err != nil || !reflect.DeepEqual(&js, sl) {
		t.Errorf("JSON %v: %+v", err, js)
	}

	// No syslog at all.
	f.status = model.Status{}
	out.Reset()
	if err := gatewaySyslog(&out, []string{"--data", dir}); err != nil {
		t.Fatal(err)
	}
	wantText(t, out.String(), "The running service reports nothing about syslog", "Diagnostics > Syslog")

	for _, args := range [][]string{{"on"}, {"off"}} {
		if err := gatewaySyslog(io.Discard, append(args, "--data", dir)); err == nil || !strings.Contains(err.Error(), "later version") {
			t.Errorf("%q: %v", args, err)
		}
	}
	if err := gatewaySyslog(io.Discard, []string{"enforce", "--data", dir}); err == nil || !strings.Contains(err.Error(), `unknown action "enforce"`) {
		t.Errorf("unknown action: %v", err)
	}
	if err := run([]string{"gateway", "syslog", "off", "--data", dir}); err == nil || !strings.Contains(err.Error(), "later version") {
		t.Errorf("run gateway syslog off: %v", err)
	}
	if err := run([]string{"gateway", "bogus"}); err == nil || !strings.Contains(err.Error(), "gateway syslog [status]") {
		t.Errorf("gateway usage: %v", err)
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
