package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"attmonitor/internal/config"
	"attmonitor/internal/model"
	"attmonitor/internal/web"
)

// The gateway's syslog on the command line (docs/DESIGN.md §18):
//
//	att-monitor syslog [--since 24h] [--grep TEXT] [--severity LEVEL] [--limit N] [--json]
//	att-monitor syslog retention [--keep-mb N] [--keep-days D] [--yes]
//	att-monitor gateway syslog [status|on|off] [--json]
//
// The messages are listed through the running service (GET /api/syslog), which names for each
// the syslog_chunk record of its chunk. A change of the retention goes through the service too
// (POST /api/syslog/retention); while the service is stopped it is made like the other operator
// changes, on the ledger directly, and the service applies it when it starts. So does a change of
// the gateway's Syslog setting (POST /api/gateway/syslog), which the service otherwise keeps as
// gateway.enforce_syslog says, reading it in its daily settings check.

// syslogUsage is the usage of the syslog commands.
const syslogUsage = "usage: att-monitor syslog [--since 24h] [--grep TEXT] [--severity LEVEL] [--limit N] [--json] [--data DIR]\n" +
	"       att-monitor syslog retention [--keep-mb N] [--keep-days D] [--yes] [--data DIR]"

// lookupService finds the API of the running service that uses a data directory (serviceAPI;
// tests replace it).
var lookupService = serviceAPI

// confirmDeletion asks whether to go on with a change that deletes syslog messages now; asked is
// false when nobody can answer (standard input is not a console). Tests replace it.
var confirmDeletion = func(out io.Writer, question string) (yes, asked bool) {
	if !stdinIsConsole() {
		return false, false
	}
	return askYesNo(stdinReader(), out, question, false), true
}

func cmdSyslog(args []string) error { return syslogCommand(os.Stdout, os.Stderr, args) }

// syslogCommand runs `att-monitor syslog …`, writing to out (and warnings that must not mix
// with JSON to errOut).
func syslogCommand(out, errOut io.Writer, args []string) error {
	if len(args) > 0 && strings.EqualFold(args[0], "retention") {
		return syslogRetention(out, args[1:])
	}
	return syslogList(out, errOut, args)
}

// ------------------------------------------------------------------ listing

// syslogList lists the messages received in the last --since that match the filters: the
// newest --limit of them, oldest first (the newest end at the prompt), grouped by the chunk of
// the syslog store that holds them and its syslog_chunk record.
func syslogList(out, errOut io.Writer, args []string) error {
	fs, data := newFlags("syslog")
	since := fs.String("since", "24h", "how far back: a duration such as 1h, 24h or 7d (at most 31 days)")
	grep := fs.String("grep", "", "only messages that contain this text (ignoring case)")
	severity := fs.String("severity", "", "only messages of this severity or a more severe one: 0-7, or emerg, alert, crit, err, warning, notice, info, debug")
	limit := fs.Int("limit", web.DefaultSyslogLimit, fmt.Sprintf("at most this many messages, the newest (up to %d)", web.MaxSyslogLimit))
	asJSON := fs.Bool("json", false, "print the service's answer (GET /api/syslog, newest first) as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q\n%s", fs.Arg(0), syslogUsage)
	}
	span, err := parseSince(*since)
	if err != nil {
		return err
	}
	if *limit < 1 || *limit > web.MaxSyslogLimit {
		return fmt.Errorf("--limit must be 1 to %d", web.MaxSyslogLimit)
	}
	dataDir := defaultDataDir(*data)
	api, ok := lookupService(dataDir)
	if !ok {
		return fmt.Errorf("the service is not running (its dashboard does not answer), and the messages are listed through it: "+
			"start it with `att-monitor start`. The chunk files themselves are in %s (gzip, one JSON message per line)",
			config.PathsFor(dataDir).Syslog)
	}
	to := now().UTC()
	q := url.Values{}
	q.Set("from", to.Add(-span).Format(time.RFC3339Nano))
	q.Set("to", to.Format(time.RFC3339Nano))
	q.Set("limit", strconv.Itoa(*limit))
	if *grep != "" {
		q.Set("q", *grep)
	}
	if *severity != "" {
		q.Set("severity", *severity)
	}
	var list model.SyslogList
	hdr, err := api.call(background(), http.MethodGet, "/api/syslog?"+q.Encode(), nil, &list)
	if err != nil {
		return err
	}
	warning := terminalSafe(hdr.Get(web.WarningHeader))
	if *asJSON {
		if warning != "" {
			fmt.Fprintln(errOut, "WARNING:", warning)
		}
		return writeJSON(out, list)
	}
	printSyslogList(out, list, warning)
	return nil
}

// parseSince parses --since: a duration ("90m", "24h") or a number of days ("7d"), more than 0
// and at most the longest period GET /api/syslog reads.
func parseSince(s string) (time.Duration, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	bad := fmt.Errorf("--since %q: use a duration such as 30m, 1h, 24h or 7d, at most %d days", s, web.MaxSyslogSpan/(24*time.Hour))
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.Atoi(n)
		if err != nil || days < 1 || time.Duration(days) > web.MaxSyslogSpan/(24*time.Hour) {
			return 0, bad
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 || d > web.MaxSyslogSpan {
		return 0, bad
	}
	return d, nil
}

// printSyslogList prints a GET /api/syslog answer (newest first) oldest first, with a heading
// line before the messages of each chunk.
func printSyslogList(out io.Writer, list model.SyslogList, warning string) {
	fmt.Fprintf(out, "Syslog messages received %s to %s (this PC's local time), oldest first\n",
		localTime(list.From, "2006-01-02 15:04"), localTime(list.To, "2006-01-02 15:04"))
	if warning != "" {
		fmt.Fprintln(out, "WARNING:", warning)
	}
	if len(list.Messages) == 0 {
		fmt.Fprintln(out, "No message.")
		return
	}
	if list.Truncated {
		fmt.Fprintf(out, "Only the newest %d are shown: more matched (raise --limit, up to %d, or shorten --since).\n",
			len(list.Messages), web.MaxSyslogLimit)
	}
	type group struct {
		chunk string
		seq   uint64
	}
	var cur *group
	for i := len(list.Messages) - 1; i >= 0; i-- {
		m := list.Messages[i]
		if g := (group{m.Chunk, m.Seq}); cur == nil || *cur != g {
			cur = &g
			fmt.Fprintln(out, chunkHeading(m.Chunk, m.Seq))
		}
		fmt.Fprintf(out, "%s  %-7s  %s\n", localTime(m.RX, "2006-01-02 15:04:05.000"), severityName(m.Severity),
			terminalSafe(syslogLineText(m.SyslogMessage)))
	}
	fmt.Fprintf(out, "%s.\n", plural(len(list.Messages), "message", "messages"))
}

// chunkHeading names the chunk of the syslog store that holds the messages below it and the
// ledger record that states its SHA-256.
func chunkHeading(chunk string, seq uint64) string {
	switch {
	case chunk == "":
		return "-- the open chunk: not sealed yet, so not recorded in the evidence ledger yet (within minutes) --"
	case seq == 0:
		return "-- chunk " + terminalSafe(chunk) + " (its syslog_chunk record was not found) --"
	}
	return fmt.Sprintf("-- chunk %s, its SHA-256 in ledger record #%d --", terminalSafe(chunk), seq)
}

// syslogLineText is a message as a line of a classic syslog file: "host app: message". A
// message that was not parsed shows the datagram itself.
func syslogLineText(m model.SyslogMessage) string {
	if m.Msg == "" {
		switch {
		case m.Raw != "":
			return m.Raw
		case m.RawB64 != "":
			return "(a datagram that is not UTF-8 text; base64: " + m.RawB64 + ")"
		}
		return "(an empty datagram)"
	}
	prefix := ""
	if m.Host != "" {
		prefix = m.Host + " "
	}
	if m.App != "" {
		prefix += m.App + ": "
	}
	return prefix + m.Msg
}

// severityNames are the syslog severities 0-7 (RFC 5424), as syslog.conf names them.
var severityNames = [8]string{"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"}

// severityName names a severity ("-" when the message has none).
func severityName(sev *int) string {
	if sev == nil || *sev < 0 || *sev > 7 {
		return "-"
	}
	return severityNames[*sev]
}

// terminalSafe escapes what a terminal would act on instead of showing: control characters,
// Unicode format characters (such as bidirectional overrides) and other characters that are not
// printable, and bytes that are not UTF-8. Syslog text is whatever arrived from the network; the
// exact datagram is in --json.
func terminalSafe(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r == ' ' || unicode.IsPrint(r):
			b.WriteRune(r)
		case r <= 0xffff:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
		i += size
	}
	return b.String()
}

// localTime formats an RFC 3339 time in this PC's time zone (escaped as it is when it does not
// parse).
func localTime(ts, layout string) string {
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return terminalSafe(ts)
	}
	return t.In(time.Local).Format(layout)
}

// ------------------------------------------------------------------ retention

// syslogRetention shows how much syslog is kept and the limits (without flags), or changes the
// limits. A flag left out keeps its limit as it is. A change that deletes messages now is
// confirmed first (--yes confirms it beforehand).
func syslogRetention(out io.Writer, args []string) error {
	fs, data := newFlags("syslog retention")
	keepMB := fs.Int("keep-mb", 0, fmt.Sprintf("keep at most this many MiB of syslog messages (%d to %d; 100 by default)", config.MinSyslogKeepMB, config.MaxSyslogKeepMB))
	keepDays := fs.Int("keep-days", 0, fmt.Sprintf("also delete messages older than this many days (0: no age limit; at most %d)", config.MaxSyslogKeepDays))
	yes := fs.Bool("yes", false, "do not ask before deleting the messages that no longer fit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q\n%s", fs.Arg(0), syslogUsage)
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if set["keep-mb"] && (*keepMB < config.MinSyslogKeepMB || *keepMB > config.MaxSyslogKeepMB) {
		return fmt.Errorf("--keep-mb must be a whole number of MiB from %d to %d", config.MinSyslogKeepMB, config.MaxSyslogKeepMB)
	}
	if set["keep-days"] && (*keepDays < 0 || *keepDays > config.MaxSyslogKeepDays) {
		return fmt.Errorf("--keep-days must be 0 (no age limit) to %d", config.MaxSyslogKeepDays)
	}
	dataDir := defaultDataDir(*data)
	cfg := configOrDefault(dataDir)
	api, viaService := lookupService(dataDir)
	cur, err := currentRetention(api, viaService, dataDir, cfg)
	if err != nil {
		return err
	}
	if !set["keep-mb"] && !set["keep-days"] {
		printRetention(out, cur, viaService, cfg)
		return nil
	}
	mb, days := cur.keepMB, cur.keepDays
	if set["keep-mb"] {
		mb = *keepMB
	}
	if set["keep-days"] {
		days = *keepDays
	}
	changed := mb != cur.keepMB || days != cur.keepDays
	if loss := retentionLoss(cur.usage, mb, days, now()); changed && loss != "" && !*yes {
		fmt.Fprintln(out, loss)
		fmt.Fprintln(out, "The SHA-256 of every deleted chunk stays in the evidence ledger (its syslog_chunk record) and the deletion is"+
			" recorded (a syslog_prune record), but the messages themselves cannot be brought back.")
		ok, asked := confirmDeletion(out, "Delete them?")
		if !asked {
			return errors.New("this change deletes syslog messages: run it again with --yes to confirm")
		}
		if !ok {
			fmt.Fprintln(out, "Nothing was changed.")
			return nil
		}
	}
	ctx := background()
	var cc model.ConfigChange
	if viaService {
		body := map[string]any{"keep_mb": mb, "keep_days": days, "client": "cli"}
		if err := api.do(ctx, http.MethodPost, "/api/syslog/retention", body, &cc); err != nil {
			return err
		}
	} else {
		s, err := openStack(stackOptions{dataDir: dataDir, mode: "cli"})
		if err != nil {
			return err
		}
		defer s.close()
		cc, err = s.mon.SetSyslogRetention(ctx, mb, days, actor())
		if err != nil && cc.What == "" {
			return err
		}
		printRetentionChange(out, cc)
		if err != nil {
			return err
		}
		if changed {
			fmt.Fprintln(out, "The service applies the new limits, and deletes what no longer fits, when it starts.")
		}
		return nil
	}
	printRetentionChange(out, cc)
	if after, err := currentRetention(api, true, dataDir, cfg); err == nil && after.usage != nil {
		fmt.Fprintln(out, "Now:", storeUsageText(after.usage))
	}
	return nil
}

// retention is how much syslog is kept: the limits in force and the store's volume (usage nil
// when unknown).
type retention struct {
	keepMB, keepDays int
	usage            *model.SyslogUsage
	storeNote        string // why usage is nil
}

// currentRetention returns the limits in force and the store's volume: as the running service
// reports them (Status.syslog.store), else from the configuration and the store read directly.
func currentRetention(api *apiClient, viaService bool, dataDir string, cfg *config.Config) (retention, error) {
	r := retention{keepMB: cfg.Syslog.KeepMB, keepDays: cfg.Syslog.KeepDays}
	if viaService {
		var st model.Status
		if err := api.do(background(), http.MethodGet, "/api/status", nil, &st); err != nil {
			return r, err
		}
		if st.Syslog == nil || st.Syslog.Store == nil {
			r.storeNote = "the running service keeps no syslog store (syslog.enabled is false in config.json, or the store could not be opened: see the service log)"
			return r, nil
		}
		u := *st.Syslog.Store
		r.keepMB, r.keepDays, r.usage = u.KeepMB, u.KeepDays, &u
		return r, nil
	}
	dir := config.PathsFor(dataDir).Syslog
	st, err := openSyslogReader(dir, cfg.Syslog, slog.New(slog.DiscardHandler))
	switch {
	case errors.Is(err, os.ErrNotExist):
		r.storeNote = "there is no syslog store yet (" + dir + ")"
	case err != nil:
		r.storeNote = "the syslog store cannot be read: " + err.Error()
	default:
		u := st.Usage()
		_ = st.Close()
		r.usage = &u
	}
	return r, nil
}

// printRetention shows the store's volume and the limits.
func printRetention(out io.Writer, r retention, viaService bool, cfg *config.Config) {
	if !viaService {
		fmt.Fprintln(out, "The service is not running: the limits are those of config.json and the volume that of the syslog folder.")
	}
	if !cfg.Syslog.Enabled {
		fmt.Fprintln(out, "Syslog is off (syslog.enabled is false in config.json): no message is received and nothing is deleted.")
	}
	if r.usage != nil {
		fmt.Fprintln(out, "Syslog store:", storeUsageText(r.usage))
		if u := r.usage; u.Oldest != "" {
			fmt.Fprintf(out, "              oldest message %s, newest %s (this PC's local time)\n",
				localTime(u.Oldest, "2006-01-02 15:04:05"), localTime(u.Newest, "2006-01-02 15:04:05"))
		}
	} else if r.storeNote != "" {
		fmt.Fprintln(out, "Syslog store:", r.storeNote)
	}
	fmt.Fprintln(out, "Retention:   ", limitsText(r.keepMB, r.keepDays))
	fmt.Fprintln(out, "To change it: att-monitor syslog retention --keep-mb N [--keep-days D] (or on the dashboard's Syslog page)")
}

// printRetentionChange prints the config_change of a retention change.
func printRetentionChange(out io.Writer, cc model.ConfigChange) {
	fmt.Fprintf(out, "Syslog retention: %s → %s (%s)\n", cc.Before, cc.After, cc.Result)
}

// limitsText words the retention limits.
func limitsText(keepMB, keepDays int) string {
	s := fmt.Sprintf("keep at most %d MiB", keepMB)
	if keepDays > 0 {
		return s + fmt.Sprintf(", and no message older than %s", plural(keepDays, "day", "days"))
	}
	return s + ", no age limit"
}

// storeUsageText words the store's volume against its size limit.
func storeUsageText(u *model.SyslogUsage) string {
	s := fmt.Sprintf("%s of %d MiB used", fmtBytes(u.Bytes), u.KeepMB)
	if u.KeepMB > 0 {
		s += fmt.Sprintf(" (%d%%)", u.Bytes*100/(int64(u.KeepMB)<<20))
	}
	s += fmt.Sprintf(", %s, %s", plural(u.Chunks, "sealed chunk", "sealed chunks"), plural(int(u.Messages), "message", "messages"))
	if u.OpenMessages > 0 {
		s += fmt.Sprintf(" (%d in the open chunk)", u.OpenMessages)
	}
	return s
}

// retentionLoss says what limits would delete from the store now ("" when nothing), as the
// dashboard does before it saves them.
func retentionLoss(u *model.SyslogUsage, keepMB, keepDays int, now time.Time) string {
	if u == nil {
		return ""
	}
	var parts []string
	if u.Bytes > int64(keepMB)<<20 {
		parts = append(parts, fmt.Sprintf("the store holds %s, more than %d MiB", fmtBytes(u.Bytes), keepMB))
	}
	if t, err := time.Parse(time.RFC3339Nano, u.Oldest); keepDays > 0 && err == nil && now.Sub(t) > time.Duration(keepDays)*24*time.Hour {
		parts = append(parts, fmt.Sprintf("its oldest message, received %s, is older than %s",
			t.In(time.Local).Format("2006-01-02 15:04"), plural(keepDays, "day", "days")))
	}
	if len(parts) == 0 {
		return ""
	}
	return "The oldest syslog messages are deleted as soon as the new limits apply: " + strings.Join(parts, ", and ") + "."
}

// fmtBytes formats a size in bytes, KiB, MiB or GiB.
func fmtBytes(n int64) string {
	switch {
	case n < 1<<10:
		return plural(int(n), "byte", "bytes")
	case n < 1<<20:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	case n < 1<<30:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	}
	return fmt.Sprintf("%.2f GiB", float64(n)/(1<<30))
}

// plural writes n with the singular or plural noun.
func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// configOrDefault loads the data directory's configuration, or the defaults when it cannot.
func configOrDefault(dataDir string) *config.Config {
	if c, err := config.Load(config.PathsFor(dataDir).Config); err == nil {
		return c
	}
	return config.Default()
}

// writeJSON writes v as indented JSON.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// ------------------------------------------------------------------ the gateway's setting

// gatewaySyslogUsage is the usage of `att-monitor gateway syslog`.
const gatewaySyslogUsage = "usage: att-monitor gateway syslog [status|on|off] [--json] [--data DIR]"

// gatewaySyslogOffline changes the gateway's Syslog setting while the service is stopped: on the
// ledger directly, like `gateway notification on|off`, after the strict certificate check of the
// authenticated commands (the login must only reach the pinned certificate). The service applies
// gateway.enforce_syslog when it starts. Tests replace it.
var gatewaySyslogOffline = func(dataDir string, on bool) (model.ConfigChange, error) {
	s, err := openStack(stackOptions{dataDir: dataDir, mode: "cli"})
	if err != nil {
		return model.ConfigChange{}, err
	}
	defer s.close()
	if err := strictGatewayTLS(s); err != nil {
		return model.ConfigChange{}, err
	}
	return s.mon.SetGatewaySyslog(background(), on, actor())
}

// gatewaySyslog shows the gateway's Syslog setting as the running service last read it, the
// syslog receiver and the syslog store (Status.syslog) - status, the default - or changes the
// setting (setGatewaySyslog): on sends the gateway's log to this PC and keeps it so
// (gateway.enforce_syslog), off switches it off on the gateway and no longer keeps it.
func gatewaySyslog(out io.Writer, args []string) error {
	action := "status"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		action, args = strings.ToLower(args[0]), args[1:]
	}
	fs, data := newFlags("gateway syslog")
	asJSON := fs.Bool("json", false, "print Status.syslog (status) or the recorded change (on, off; a failed change: {error, change}) as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if action != "status" && action != "on" && action != "off" {
		return fmt.Errorf("unknown action %q (%s)", action, gatewaySyslogUsage)
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q (%s)", fs.Arg(0), gatewaySyslogUsage)
	}
	dataDir := defaultDataDir(*data)
	cfg := configOrDefault(dataDir)
	api, ok := lookupService(dataDir)
	if action != "status" {
		return setGatewaySyslog(out, api, ok, dataDir, cfg, action == "on", *asJSON)
	}
	if !ok {
		fmt.Fprintln(out, "The service is not running (its dashboard does not answer): the syslog receiver and the gateway's Syslog"+
			" setting are reported by the running service (att-monitor start).")
		r, err := currentRetention(nil, false, dataDir, cfg)
		if err != nil {
			return err
		}
		printRetention(out, r, false, cfg)
		return nil
	}
	var st model.Status
	if err := api.do(background(), http.MethodGet, "/api/status", nil, &st); err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(out, st.Syslog)
	}
	printGatewaySyslog(out, &st, cfg)
	return nil
}

// setGatewaySyslog switches the gateway's Syslog setting on - to this PC, and kept so - or off,
// and no longer kept, through the running service (POST /api/gateway/syslog) or, with the
// service stopped, on the ledger directly (gatewaySyslogOffline), and prints the recorded change
// (--json: the change as JSON). When a change fails, the change the monitor reported (if any) is
// printed with the error, and - unless the gateway took the change, or the service only refused
// to run a second operation at the same time - how to make it on the gateway itself; with
// --json only the failure is printed, as JSON (writeChangeError). Either way the error is
// returned: the command fails.
func setGatewaySyslog(out io.Writer, api *apiClient, viaService bool, dataDir string, cfg *config.Config, on, asJSON bool) error {
	var (
		cc  model.ConfigChange
		err error
	)
	if viaService {
		err = api.do(background(), http.MethodPost, "/api/gateway/syslog", map[string]any{"enabled": on, "client": "cli"}, &cc)
		if rc := reportedChange(err); rc != nil {
			cc = *rc
		}
	} else {
		cc, err = gatewaySyslogOffline(dataDir, on)
	}
	if err != nil && asJSON {
		return writeChangeError(out, cc, err)
	}
	if err != nil {
		if cc.What != "" {
			fmt.Fprintln(out, "Change:", syslogChangeText(cc))
		}
		var se *serviceError
		refused := errors.As(err, &se) && (se.Status == http.StatusConflict || se.Status == http.StatusTooManyRequests)
		if !gatewayTookChange(cc.Result) && !refused {
			var st *model.Status
			if viaService {
				var s model.Status
				if api.do(background(), http.MethodGet, "/api/status", nil, &s) == nil {
					st = &s
				}
			}
			printSetByHand(out, st, cfg, on)
		}
		return err
	}
	if asJSON {
		return writeJSON(out, cc)
	}
	fmt.Fprintln(out, "Gateway setting", syslogChangeText(cc))
	if on {
		fmt.Fprintln(out, "att-monitor keeps it so: it reads the setting in its daily settings check (and after this PC's address changes)"+
			" and sets it again whenever it differs. `att-monitor gateway syslog off` stops it.")
		if !viaService {
			fmt.Fprintln(out, "The service is not running: the gateway's messages are received, and the setting kept, once it runs (att-monitor start).")
		}
	} else {
		fmt.Fprintln(out, "The gateway sends its log to no syslog server now, and att-monitor no longer sets it (it still reads it daily)."+
			" `att-monitor gateway syslog on` sends it to this PC again.")
	}
	return nil
}

// writeChangeError prints a failed change as JSON, the way the service answers one: {error,
// change} (web.ConfigChangeError) with the command's error and the change the monitor reported,
// left out when it reported none. It returns err - the command still fails, and the error also
// goes to standard error - joined with a failure to write.
func writeChangeError(out io.Writer, cc model.ConfigChange, err error) error {
	resp := web.ConfigChangeError{Error: err.Error()}
	if cc != (model.ConfigChange{}) {
		resp.Change = &cc
	}
	if werr := writeJSON(out, resp); werr != nil {
		return errors.Join(err, werr)
	}
	return err
}

// syslogChangeText words a recorded change of the gateway's Syslog setting (its config_change)
// as the other gateway commands do: "<what>: <before> → <after> (<result>)". It may quote the
// gateway's page, so what a terminal would act on is escaped.
func syslogChangeText(cc model.ConfigChange) string {
	return fmt.Sprintf("%s: %s → %s (%s)", terminalSafe(cc.What), terminalSafe(cc.Before), terminalSafe(cc.After), terminalSafe(cc.Result))
}

// gatewayTookChange reports whether a config_change result says that the gateway took the change
// ("verified", "applied", possibly followed by notes) rather than "failed: ..." or nothing.
func gatewayTookChange(result string) bool {
	r := strings.ToLower(strings.TrimSpace(result))
	return r != "" && !strings.HasPrefix(r, "failed")
}

// printGatewaySyslog prints Status.syslog: the receiver, what it received, the store, the
// gateway's setting and how it compares with this PC, whether att-monitor keeps it sending here,
// and - while the gateway does not send here and att-monitor does not set it (syslogHandHint) -
// how to set it by hand.
func printGatewaySyslog(out io.Writer, st *model.Status, cfg *config.Config) {
	sl := st.Syslog
	if sl == nil {
		fmt.Fprintln(out, "The running service reports nothing about syslog: no receiver and no syslog store (syslog.enabled is false"+
			" in config.json, or the store could not be opened: see the service log), and the gateway's Syslog setting has not been read.")
		// Whether the service keeps the setting is then config.json's say.
		if !cfg.Gateway.EnforceSyslog || gatewayAuthPaused(st) {
			printSetByHand(out, st, cfg, true)
		}
		return
	}
	switch {
	case !sl.Enabled:
		fmt.Fprintln(out, "Syslog receiver:  off (syslog.enabled is false in config.json, or the syslog store could not be opened)")
	case sl.Listening:
		fmt.Fprintf(out, "Syslog receiver:  listening on %s (UDP)\n", terminalSafe(sl.Listen))
	default:
		fmt.Fprintf(out, "Syslog receiver:  NOT listening on %s (UDP): %s\n", terminalSafe(sl.Listen), terminalSafe(sl.ListenErr))
	}
	if sl.Enabled {
		fmt.Fprintf(out, "Since the start:  %s received, %d stored, %d dropped (over the receiver's limits), %d rejected (from other senders)\n",
			plural(int(sl.Received), "message", "messages"), sl.Recorded, sl.Dropped, sl.Rejected)
		if sl.LastAt != "" {
			fmt.Fprintf(out, "Newest message:   %s  %s\n", localTime(sl.LastAt, "2006-01-02 15:04:05"), terminalSafe(sl.Last))
		}
	}
	if u := sl.Store; u != nil {
		fmt.Fprintln(out, "Syslog store:    ", storeUsageText(u))
		fmt.Fprintln(out, "Retention:       ", limitsText(u.KeepMB, u.KeepDays), "(att-monitor syslog retention)")
	}
	switch {
	case sl.Gateway != nil:
		fmt.Fprintf(out, "Gateway setting:  %s (read %s, ledger record #%d)\n", gatewaySettingText(sl.Gateway),
			localTime(sl.GatewayAt, "2006-01-02 15:04"), sl.GatewaySeq)
	case sl.GatewaySeq != 0:
		fmt.Fprintf(out, "Gateway setting:  not understood at the latest read (%s, ledger record #%d)\n",
			localTime(sl.GatewayAt, "2006-01-02 15:04"), sl.GatewaySeq)
	default:
		fmt.Fprintln(out, "Gateway setting:  not read yet (the service reads it once a day, with the gateway access code)")
	}
	switch sl.State {
	case "ok":
		fmt.Fprintln(out, "State:            ok: the gateway sends its log to this PC")
	case "":
	default:
		fmt.Fprintf(out, "State:            %s: %s\n", terminalSafe(sl.State), terminalSafe(sl.Problem))
	}
	for _, c := range st.Conditions {
		if strings.HasPrefix(c.Code, "SYSLOG_") {
			fmt.Fprintf(out, "Condition:        [%s] %s\n", c.Severity, terminalSafe(c.Message))
		}
	}
	if sl.Enforce {
		fmt.Fprintf(out, "Kept:             yes, att-monitor keeps it sending to %s: it reads the setting in its daily settings check"+
			" (and after this PC's address changes) and sets it again whenever it differs; `att-monitor gateway syslog off` stops it\n", syslogTargetText(sl.Target))
	} else {
		fmt.Fprintln(out, "Kept:             no, att-monitor only reads this setting; `att-monitor gateway syslog on` sends the gateway's log to this PC"+
			" and keeps it so")
	}
	hand := syslogHandHint(st)
	switch {
	case syslogReceivingSince(sl) && (sl.State == "off" || sl.State == "elsewhere"):
		fmt.Fprintln(out, "Messages have arrived since the setting was read, so it may have been changed on the gateway since.")
	case sl.Enforce && !hand && (sl.State == "off" || sl.State == "elsewhere"):
		fmt.Fprintln(out, "att-monitor sets it again at its next settings check, or now with `att-monitor gateway syslog on`.")
	}
	if hand {
		printSetByHand(out, st, cfg, true)
	}
}

// syslogTargetText words what att-monitor keeps the gateway's Syslog setting at.
func syslogTargetText(t *model.SyslogTarget) string {
	if t == nil {
		return "this PC (its address toward the gateway is not known yet)"
	}
	if !t.Enabled {
		return "nothing (off)"
	}
	s := terminalSafe(t.Server) + " port " + strconv.Itoa(t.Port)
	if t.Level != "" {
		s += ", level " + terminalSafe(t.Level)
	}
	return s
}

// syslogHandHint reports whether to say how to set the gateway's Syslog page by hand: only while
// the gateway does not send its log here and att-monitor does not set it - it does not keep the
// setting (gateway.enforce_syslog off), or setting it failed or cannot be done (the latest check
// failed, the latest attempt to set it failed - SYSLOG_SETTING_FAILED -, the page was not
// understood, no access code is stored, a changed gateway certificate waits for confirmation) -
// and no message arrived since the setting was read (they show that the gateway sends here).
// The dashboard's card says it only while the monitor cannot set the page (app.js): it offers
// the change itself. st.Syslog must not be nil.
func syslogHandHint(st *model.Status) bool {
	sl := st.Syslog
	switch {
	case sl.State == "ok" || syslogReceivingSince(sl):
		return false
	case !sl.Enforce:
		return true
	}
	return sl.State == "error" || (sl.GatewaySeq != 0 && sl.Gateway == nil) || hasCondition(st, "SYSLOG_SETTING_FAILED") || gatewayAuthPaused(st)
}

// hasCondition reports whether the status carries the condition code.
func hasCondition(st *model.Status, code string) bool {
	return slices.ContainsFunc(st.Conditions, func(c model.Condition) bool { return c.Code == code })
}

// syslogReceivingSince reports whether messages arrived after the latest read of the gateway's
// Syslog setting (or before any read).
func syslogReceivingSince(sl *model.SyslogStatus) bool {
	last, err := time.Parse(time.RFC3339Nano, sl.LastAt)
	if err != nil {
		return false
	}
	read, err := time.Parse(time.RFC3339Nano, sl.GatewayAt)
	return err != nil || last.After(read)
}

// gatewayAuthPaused reports whether the service cannot log in to the gateway now: no access code
// is stored, or a changed gateway certificate waits for confirmation.
func gatewayAuthPaused(st *model.Status) bool {
	return (st.GatewayCert != nil && st.GatewayCert.Pending != "") || hasCondition(st, "NO_ACCESS_CODE") || hasCondition(st, "GATEWAY_CERT_CHANGED")
}

// gatewaySettingText words the gateway's Syslog setting.
func gatewaySettingText(g *model.SyslogSetting) string {
	if !g.Enabled {
		return "off"
	}
	s := "on, sending to " + terminalSafe(g.Server)
	if g.Port != 0 {
		s += " port " + strconv.Itoa(g.Port)
	}
	if g.Level != "" {
		s += ", level " + terminalSafe(g.Level)
	}
	return s
}

// printSetByHand says how to make the gateway send its log to this PC (on), or stop it (off), on
// the gateway itself; st (may be nil) names this PC's address. The page enables its fields only
// once Syslog is set to On.
func printSetByHand(out io.Writer, st *model.Status, cfg *config.Config, on bool) {
	page := fmt.Sprintf("open %s://%s, Diagnostics > Syslog (the page asks for the Device Access Code)", cfg.Gateway.Scheme, cfg.Gateway.Host)
	if !on {
		fmt.Fprintf(out, "To stop it on the gateway itself: %s, set Syslog to Off and save.\n", page)
		return
	}
	pc := "this PC's IPv4 address on the gateway's network"
	if st != nil && st.LocalLink != nil && st.LocalLink.LocalIP != "" {
		pc = terminalSafe(st.LocalLink.LocalIP) + " (this PC)"
	}
	fmt.Fprintf(out, "To set it on the gateway itself: %s, set Syslog to On (the page then enables its other fields),"+
		" Server IP Address %s, Server Port %d, and save.\n", page, pc, cfg.Syslog.Port)
}
