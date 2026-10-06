package gateway

import (
	"bytes"
	"context"
	"errors"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// ---------------------------------------------------------------- fake gateway with a Syslog page

// syslogVariant describes one synthetic Syslog page (testdata/gateway/syslog_*.html) for the
// fake gateway: its fixtures and the names of its controls - which the client never uses: it
// finds the controls by their labels.
type syslogVariant struct {
	off, on             string // fixture shown while Syslog is off, and while on ("" = the same)
	sw, swKind          string // the switch's name and kind: "select", "checkbox" or "radio"
	swOn, swOff         string // the switch's values for on and off (select, radio)
	server, port, level string // field names ("" = not on the page)
	levelByText         bool   // the level options have no value attribute
}

// syslogState is the setting a fake gateway stores; level is the selected option's value (its
// text for levelByText).
type syslogState struct {
	on                  bool
	server, port, level string
}

var (
	selectVariant = syslogVariant{off: "syslog_select.html", sw: "sl_en", swKind: "select", swOn: "1", swOff: "0",
		server: "sl_srv", port: "sl_port", level: "sl_lvl"}
	checkboxVariant = syslogVariant{off: "syslog_checkbox_off.html", on: "syslog_checkbox_on.html", sw: "logsend", swKind: "checkbox",
		server: "logsrv", port: "logport", level: "loglevel", levelByText: true}
	radioVariant = syslogVariant{off: "syslog_radio.html", sw: "remlog", swKind: "radio", swOn: "enable", swOff: "disable",
		server: "remlog_ip", port: "remlog_port", level: "remlog_sev"}
	noPortVariant = syslogVariant{off: "syslog_noport.html", sw: "s_on", swKind: "select", swOn: "on", swOff: "off",
		server: "s_ip", level: "s_lvl"}
	fewLevelsVariant = syslogVariant{off: "syslog_fewlevels.html", sw: "sys_en", swKind: "select", swOn: "1", swOff: "0",
		server: "sys_ip", port: "sys_port", level: "sys_lvl"}

	// The settings the fixtures show (for the checkbox variant: what the page shows once on).
	selectOff    = syslogState{false, "", "514", "4"}
	checkboxOff  = syslogState{false, "", "514", "Warning"}
	radioOff     = syslogState{false, "", "514", "warning"}
	noPortOn     = syslogState{true, "192.168.1.64", "", "notice"}
	fewLevelsOn  = syslogState{true, "192.168.1.64", "514", "5"}
	enableTarget = model.SyslogTarget{Enabled: true, Server: "192.168.1.71", Port: 514, Level: "Informational"}
)

// render returns the variant's page showing st. Mismatches are reported with t.Errorf: it
// runs in the server's goroutines.
func (v syslogVariant) render(t testing.TB, st syslogState) []byte {
	name := v.off
	if st.on && v.on != "" {
		name = v.on
	}
	page := fixture(t, name)
	sw := v.swOff
	if st.on {
		sw = v.swOn
	}
	switch v.swKind {
	case "select":
		page = chooseOption(t, page, v.sw, sw, false)
	case "checkbox":
		page = setCheckbox(t, page, v.sw, st.on)
	case "radio":
		page = chooseRadio(t, page, v.sw, sw)
	}
	if st.on || v.on == "" {
		page = setInputValue(t, page, v.server, st.server)
		if v.port != "" {
			page = setInputValue(t, page, v.port, st.port)
		}
		page = chooseOption(t, page, v.level, st.level, v.levelByText)
	}
	return page
}

// switchOn reads the switch from a posted form.
func (v syslogVariant) switchOn(form url.Values) bool {
	if v.swKind == "checkbox" {
		return form.Get(v.sw) == "on"
	}
	return form.Get(v.sw) == v.swOn
}

// apply saves a posted form: the switch, and the fields it carries.
func (v syslogVariant) apply(st *syslogState, form url.Values) {
	st.on = v.switchOn(form)
	for _, f := range []struct {
		name string
		dst  *string
	}{{v.server, &st.server}, {v.port, &st.port}, {v.level, &st.level}} {
		if f.name != "" && form.Has(f.name) {
			*f.dst = form.Get(f.name)
		}
	}
}

// replaceOnce replaces the one match of re in page by fn(submatches).
func replaceOnce(t testing.TB, page []byte, re *regexp.Regexp, fn func(m []string) string) []byte {
	locs := re.FindAllSubmatchIndex(page, -1)
	if len(locs) != 1 {
		t.Errorf("fake gateway: %s matches %d times", re, len(locs))
		return page
	}
	l := locs[0]
	m := make([]string, len(l)/2)
	for i := range m {
		if l[2*i] >= 0 {
			m[i] = string(page[l[2*i]:l[2*i+1]])
		}
	}
	out := append([]byte{}, page[:l[0]]...)
	out = append(out, fn(m)...)
	return append(out, page[l[1]:]...)
}

func setInputValue(t testing.TB, page []byte, name, value string) []byte {
	re := regexp.MustCompile(`(<input\b[^>]*\bname="` + regexp.QuoteMeta(name) + `"[^>]*?\bvalue=")[^"]*"`)
	return replaceOnce(t, page, re, func(m []string) string { return m[1] + html.EscapeString(value) + `"` })
}

func chooseOption(t testing.TB, page []byte, name, value string, byText bool) []byte {
	block := regexp.MustCompile(`(?s)<select\b[^>]*\bname="` + regexp.QuoteMeta(name) + `".*?</select>`)
	return replaceOnce(t, page, block, func(m []string) string {
		sel := regexp.MustCompile(`\s*selected="selected"`).ReplaceAll([]byte(m[0]), nil)
		if byText {
			opt := regexp.MustCompile(`<option(>` + regexp.QuoteMeta(html.EscapeString(value)) + `</option>)`)
			return string(replaceOnce(t, sel, opt, func(o []string) string { return `<option selected="selected"` + o[1] }))
		}
		opt := regexp.MustCompile(`<option value="` + regexp.QuoteMeta(value) + `"`)
		return string(replaceOnce(t, sel, opt, func(o []string) string { return o[0] + ` selected="selected"` }))
	})
}

func setCheckbox(t testing.TB, page []byte, name string, on bool) []byte {
	re := regexp.MustCompile(`(<input\b[^>]*\bname="` + regexp.QuoteMeta(name) + `")(?: checked="checked")?`)
	return replaceOnce(t, page, re, func(m []string) string {
		if on {
			return m[1] + ` checked="checked"`
		}
		return m[1]
	})
}

func chooseRadio(t testing.TB, page []byte, name, value string) []byte {
	all := regexp.MustCompile(`(<input\b[^>]*\bname="` + regexp.QuoteMeta(name) + `" value="[^"]*")(?: checked="checked")?`)
	page = all.ReplaceAll(page, []byte("${1}"))
	re := regexp.MustCompile(`<input\b[^>]*\bname="` + regexp.QuoteMeta(name) + `" value="` + regexp.QuoteMeta(value) + `"`)
	return replaceOnce(t, page, re, func(m []string) string { return m[0] + ` checked="checked"` })
}

// syslogGateway is the mock gateway (helpers_test.go) with a Syslog page behind the same
// login: syslog.ha is rendered from a synthetic fixture for the stored setting; a POST with
// the page's nonce is saved (Save) or answered with the transformed page (Update), as the
// BGW320 is expected to do.
type syslogGateway struct {
	*mockGateway
	v  syslogVariant
	st syslogState

	// behaviour switches
	ignoreSave     bool                     // Save does not change the setting
	updateRedirect bool                     // Update answers 302 -> syslog.ha; the next GET shows the transformed page
	updateIgnored  bool                     // Update answers with the page unchanged
	edit           func(page []byte) []byte // applied to every page served
	editUpdate     func(page []byte) []byte // applied to the transformed page only
	// onPost takes over a POST to syslog.ha (after it is recorded) when it returns true. It
	// runs with the gateway locked.
	onPost func(w http.ResponseWriter, form url.Values) bool

	nonces  map[*mockSession]string
	pending map[*mockSession]bool

	// observations
	served   [][]byte // Syslog pages served, in order
	posts    []string // raw POST bodies to syslog.ha, in order
	forms    []url.Values
	referers []string
	badPosts int // POSTs without the page's nonce: not applied
}

func newSyslogGateway(t testing.TB, code string, v syslogVariant, st syslogState) *syslogGateway {
	return &syslogGateway{mockGateway: newMockGateway(t, code, false), v: v, st: st,
		nonces: map[*mockSession]string{}, pending: map[*mockSession]bool{}}
}

func (g *syslogGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/cgi-bin/syslog.ha" {
		g.mockGateway.ServeHTTP(w, r)
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.requests++
	g.byPath[r.Method+" "+r.URL.Path]++
	if g.sessionsFull {
		g.write(w, http.StatusOK, sessionsFullPage(g.t))
		return
	}
	s, fresh := g.session(w, r)
	if !s.authed {
		if r.Method == http.MethodPost {
			g.posts = append(g.posts, readBody(r))
		}
		if g.redirectToLogin {
			w.Header().Set("Location", "/cgi-bin/login.ha")
			g.write(w, http.StatusFound, nil)
			return
		}
		g.loginPage(w, s, fresh)
		return
	}
	if r.Method != http.MethodPost {
		on, pending := g.pending[s]
		delete(g.pending, s)
		if !pending {
			on = g.st.on
		}
		g.write(w, http.StatusOK, g.page(s, on, pending))
		return
	}
	body := readBody(r)
	form, _ := url.ParseQuery(body)
	g.posts = append(g.posts, body)
	g.forms = append(g.forms, form)
	g.referers = append(g.referers, r.Header.Get("Referer"))
	if g.onPost != nil && g.onPost(w, form) {
		return
	}
	nonce := g.nonces[s]
	delete(g.nonces, s) // single use
	switch {
	case nonce == "" || form.Get("nonce") != nonce || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded":
		g.badPosts++
	case form.Has("Update") && g.updateRedirect:
		g.pending[s] = g.v.switchOn(form)
	case form.Has("Update"):
		on := g.v.switchOn(form)
		if g.updateIgnored {
			on = g.st.on
		}
		g.write(w, http.StatusOK, g.page(s, on, !g.updateIgnored))
		return
	case form.Has("Save") && !g.ignoreSave:
		g.v.apply(&g.st, form)
	}
	w.Header().Set("Location", "/cgi-bin/syslog.ha")
	g.write(w, http.StatusFound, nil)
}

// page renders the Syslog page with the switch at on (the stored setting otherwise) and a
// fresh nonce for session s; update marks the page the Update button transforms.
func (g *syslogGateway) page(s *mockSession, on, update bool) []byte {
	st := g.st
	st.on = on
	p := g.v.render(g.t, st)
	if g.edit != nil {
		p = g.edit(p)
	}
	if update && g.editUpdate != nil {
		p = g.editUpdate(p)
	}
	nonce := randomHex(32)
	g.nonces[s] = nonce
	p = withNonce(p, nonce)
	g.served = append(g.served, p)
	return p
}

// syslogObservations is what a syslogGateway saw, copied under its lock.
type syslogObservations struct {
	served   [][]byte
	posts    []string
	forms    []url.Values
	referers []string
	badPosts int
	requests int
	logins   int
	gets     int // GET syslog.ha
	state    syslogState
}

func (g *syslogGateway) observed() syslogObservations {
	g.mu.Lock()
	defer g.mu.Unlock()
	return syslogObservations{
		served:   append([][]byte(nil), g.served...),
		posts:    append([]string(nil), g.posts...),
		forms:    append([]url.Values(nil), g.forms...),
		referers: append([]string(nil), g.referers...),
		badPosts: g.badPosts,
		requests: g.requests,
		logins:   len(g.loginForms),
		gets:     g.byPath["GET /cgi-bin/syslog.ha"],
		state:    g.st,
	}
}

// startSyslog serves g and returns a client (access code testCode) for it.
func startSyslog(t *testing.T, g *syslogGateway, clk *fakeClock, logs *syncBuffer) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)
	return newTestClient(t, srv, clk, testCode, logs), srv
}

// pageEdit returns an edit of served pages replacing pattern by repl; pattern must match the
// fixture (checked here, in the test goroutine).
func pageEdit(t *testing.T, fixtureName, pattern, repl string) func([]byte) []byte {
	t.Helper()
	sub(t, fixture(t, fixtureName), pattern, repl)
	re := regexp.MustCompile(pattern)
	return func(p []byte) []byte { return re.ReplaceAll(p, []byte(repl)) }
}

var reNonceAttr = regexp.MustCompile(`name="nonce" value="([0-9a-f]+)"`)

// nonceIn returns the nonce of a served page.
func nonceIn(t *testing.T, page []byte) string {
	t.Helper()
	m := reNonceAttr.FindSubmatch(page)
	if m == nil {
		t.Fatal("served page has no nonce")
	}
	return string(m[1])
}

// ---------------------------------------------------------------- parsing

var (
	levels8 = []string{"Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Informational", "Debug"}
	levels7 = []string{"Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Debug"}
)

func TestParseSyslogFixtures(t *testing.T) {
	tests := []struct {
		name string
		want model.SyslogSetting
		err  string // part of the ErrSyslogPage message ("" = no error)
	}{
		{"syslog_select.html", model.SyslogSetting{Port: 514, Level: "Warning", Levels: levels8}, ""},
		{"syslog_checkbox_off.html", model.SyslogSetting{}, ""}, // the fields are shown once Syslog is on
		{"syslog_checkbox_on.html", model.SyslogSetting{Enabled: true, Server: "192.168.1.64", Port: 514, Level: "Notice", Levels: levels8}, ""},
		{"syslog_radio.html", model.SyslogSetting{Port: 514, Level: "Warning", Levels: levels8}, ""},
		{"syslog_fewlevels.html", model.SyslogSetting{Enabled: true, Server: "192.168.1.64", Port: 514, Level: "Notice", Levels: levels7}, ""},
		{"syslog_noport.html", model.SyslogSetting{}, `no control labelled "Server Port"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := fixture(t, tt.name)
			got, err := ParseSyslog(body)
			if tt.err != "" {
				if !errors.Is(err, ErrSyslogPage) || !strings.Contains(err.Error(), tt.err) {
					t.Fatalf("err = %v, want ErrSyslogPage mentioning %q", err, tt.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("setting = %+v, want %+v", got, tt.want)
			}
			// Line endings and the page's encoding do not matter.
			for vname, variant := range map[string]func([]byte) []byte{
				"LF":      func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")) },
				"CR":      func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\r")) },
				"latin-1": latin1Variant,
				"U+FFFD":  replacementVariant,
			} {
				if v, err := ParseSyslog(variant(body)); err != nil || !reflect.DeepEqual(v, got) {
					t.Errorf("%s variant: %+v, %v", vname, v, err)
				}
			}
		})
	}
}

// TestParseSyslogVariants: what the parser accepts and refuses, on small pages.
func TestParseSyslogVariants(t *testing.T) {
	const fields = `<tr><th>Server IP Address</th><td><input name=ip value="192.168.1.71 "></td></tr>
<tr><th>Server Port</th><td><input name=port value=514></td></tr>
<tr><th>Log Level</th><td><select name=lvl><option value=3>Error</option><option value=6 selected>Info</option></select></td></tr>`
	page := func(rows string) []byte {
		return []byte(`<html><head><title>Syslog</title></head><body><form method="post" action="/cgi-bin/syslog.ha"><table>` + rows + `</table></form></body></html>`)
	}
	on := model.SyslogSetting{Enabled: true, Server: "192.168.1.71", Port: 514, Level: "Info", Levels: []string{"Error", "Info"}}
	off := on
	off.Enabled = false
	tests := []struct {
		name string
		body []byte
		want model.SyslogSetting
		err  error
		msg  string
	}{
		{"checkbox with a wrapping label", page(`<tr><td><label><input type=checkbox name=x checked> Syslog:</label></td></tr>` + fields), on, nil, ""},
		{"select with words", page(`<tr><th>SYSLOG</th><td><select name=x><option value=a>Disabled</option><option value=b selected>Enabled</option></select></td></tr>` + fields), on, nil, ""},
		{"select with values only", page(`<tr><th>Syslog</th><td><select name=x><option value=0>-</option><option value=1 selected>-</option></select></td></tr>` + fields), on, nil, ""},
		{"select defaults to its first option", page(`<tr><th>Syslog</th><td><select name=x><option>Off</option><option>On</option></select></td></tr>` + fields), off, nil, ""},
		{"an option that is neither on nor off is off", page(`<tr><th>Syslog</th><td><select name=x><option value=r selected>Remote</option><option value=0>Off</option></select></td></tr>` + fields), off, nil, ""},
		{"radio buttons labelled by text only", page(`<tr><th>Syslog</th><td><input type=radio id=a name=x><label for=a>On</label><input type=radio id=b name=x checked><label for=b>Off</label></td></tr>` + fields), off, nil, ""},
		{"radio values without labels", page(`<tr><th>Syslog</th><td><input type=radio name=x value=yes checked> <input type=radio name=x value=no></td></tr>` + fields), on, nil, ""},
		{"the port may be empty", page(`<tr><th>Syslog</th><td><input type=checkbox name=x></td></tr>` + strings.Replace(fields, "value=514", `value=""`, 1)),
			model.SyslogSetting{Server: "192.168.1.71", Level: "Info", Levels: []string{"Error", "Info"}}, nil, ""},
		{"a level typed in", page(`<tr><th>Syslog</th><td><input type=checkbox name=x checked></td></tr>` +
			strings.Replace(fields, `<select name=lvl><option value=3>Error</option><option value=6 selected>Info</option></select>`, `<input name=lvl value=" info ">`, 1)),
			model.SyslogSetting{Enabled: true, Server: "192.168.1.71", Port: 514, Level: "info"}, nil, ""},

		{"login page", fixture(t, "login_nonce.html"), model.SyslogSetting{}, ErrLoginRequired, ""},
		{"events page", fixture(t, "events_checked.html"), model.SyslogSetting{}, ErrSyslogPage, `no control labelled "Syslog"`},
		{"empty", nil, model.SyslogSetting{}, ErrSyslogPage, `no control labelled "Syslog"`},
		{"a label without a control", page(`<tr><th>Syslog</th><td>on</td></tr>` + fields), model.SyslogSetting{}, ErrSyslogPage, `no control labelled "Syslog"`},
		{"two switches", page(`<tr><th>Syslog</th><td><input type=checkbox name=x><input type=checkbox name=y></td></tr>` + fields), model.SyslogSetting{}, ErrSyslogPage, "more than one"},
		{"switches in two forms", []byte(`<form><label>Syslog <input type=checkbox name=x></label></form><form><label>Syslog <input type=checkbox name=y></label></form>`),
			model.SyslogSetting{}, ErrSyslogPage, "more than one"},
		{"switch is a text input", page(`<tr><th>Syslog</th><td><input name=x value=on></td></tr>` + fields), model.SyslogSetting{}, ErrSyslogPage, "text input, not an on/off switch"},
		{"option says on and off", page(`<tr><th>Syslog</th><td><select name=x><option value=0 selected>On</option><option value=1>Off</option></select></td></tr>` + fields),
			model.SyslogSetting{}, ErrSyslogPage, "both on and off"},
		{"no radio button checked", page(`<tr><th>Syslog</th><td><input type=radio name=x value=1><input type=radio name=x value=0></td></tr>` + fields),
			model.SyslogSetting{}, ErrSyslogPage, "is selected"},
		{"on without the fields", page(`<tr><th>Syslog</th><td><input type=checkbox name=x checked></td></tr>`), model.SyslogSetting{}, ErrSyslogPage, "shows no"},
		{"some fields missing", page(`<tr><th>Syslog</th><td><input type=checkbox name=x></td></tr><tr><th>Server IP Address</th><td><input name=ip></td></tr>`),
			model.SyslogSetting{}, ErrSyslogPage, `no control labelled "Server Port" or "Log Level"`},
		{"address in four boxes", page(`<tr><th>Syslog</th><td><input type=checkbox name=x></td></tr>` +
			strings.Replace(fields, `<input name=ip value="192.168.1.71 ">`, `<input name=a>.<input name=b>.<input name=c>.<input name=d>`, 1)),
			model.SyslogSetting{}, ErrSyslogPage, `4 controls are labelled "Server IP Address"`},
		{"address as a list", page(`<tr><th>Syslog</th><td><input type=checkbox name=x></td></tr>` +
			strings.Replace(fields, `<input name=ip value="192.168.1.71 ">`, `<select name=ip><option>a</option></select>`, 1)),
			model.SyslogSetting{}, ErrSyslogPage, `"Server IP Address" control is a drop-down list`},
		{"port not a number", page(`<tr><th>Syslog</th><td><input type=checkbox name=x></td></tr>` + strings.Replace(fields, "value=514", "value=syslog", 1)),
			model.SyslogSetting{}, ErrSyslogPage, "not a port number"},
		{"port out of range", page(`<tr><th>Syslog</th><td><input type=checkbox name=x></td></tr>` + strings.Replace(fields, "value=514", "value=70000", 1)),
			model.SyslogSetting{}, ErrSyslogPage, "not a port number"},
		{"level as a multiple-choice list", page(`<tr><th>Syslog</th><td><input type=checkbox name=x></td></tr>` + strings.Replace(fields, "<select name=lvl>", "<select name=lvl multiple>", 1)),
			model.SyslogSetting{}, ErrSyslogPage, "multiple-choice list"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSyslog(tt.body)
			if tt.err == nil {
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("setting = %+v, want %+v", got, tt.want)
				}
				return
			}
			if !errors.Is(err, tt.err) || !strings.Contains(err.Error(), tt.msg) {
				t.Errorf("err = %v, want %v mentioning %q", err, tt.err, tt.msg)
			}
		})
	}
}

// TestParseSyslogRejectsOtherPages: no other gateway page is taken for the Syslog page.
func TestParseSyslogRejectsOtherPages(t *testing.T) {
	for _, name := range []string{"sysinfo.html", "broadbandstatistics.html", "fiberstat.html", "lanstatistics.html", "home.html",
		"diag.html", "firewall.html", "sitemap.html", "broadbandconfig.html", "events_checked.html", "events_unchecked.html", "hiddenpage.html"} {
		if _, err := ParseSyslog(fixture(t, name)); !errors.Is(err, ErrSyslogPage) {
			t.Errorf("%s: err = %v, want ErrSyslogPage", name, err)
		}
	}
	for _, name := range []string{"login_handshake1.html", "login_nonce.html"} {
		if _, err := ParseSyslog(fixture(t, name)); !errors.Is(err, ErrLoginRequired) {
			t.Errorf("%s: err = %v, want ErrLoginRequired", name, err)
		}
	}
}

// ---------------------------------------------------------------- Syslog (read)

func TestSyslogReadsThroughTheLogin(t *testing.T) {
	g := newSyslogGateway(t, testCode, selectVariant, selectOff)
	clk := newFakeClock()
	c, srv := startSyslog(t, g, clk, nil)
	ctx := context.Background()

	got, raw, err := c.Syslog(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := (model.SyslogSetting{Port: 514, Level: "Warning", Levels: levels8}); !reflect.DeepEqual(got, want) {
		t.Errorf("setting = %+v, want %+v", got, want)
	}
	o := g.observed()
	// The login starts on syslog.ha itself: handshake GET, GET with the nonce, login POST, and
	// the verifying GET, which is the page read.
	if o.gets != 3 || o.logins != 1 || len(o.served) != 1 || len(o.posts) != 0 {
		t.Errorf("GETs=%d logins=%d served=%d posts=%d, want 3/1/1/0", o.gets, o.logins, len(o.served), len(o.posts))
	}
	if !bytes.Equal(raw, o.served[0]) {
		t.Error("raw is not the exact page served")
	}
	g.mu.Lock()
	ref := g.mockGateway.referers[0]
	g.mu.Unlock()
	if ref != srv.URL+"/cgi-bin/syslog.ha" {
		t.Errorf("login Referer = %q", ref)
	}

	// Within the reuse window the session is reused: one GET, no login.
	clk.Advance(30 * time.Second)
	if _, _, err := c.Syslog(ctx); err != nil {
		t.Fatal(err)
	}
	if o := g.observed(); o.gets != 4 || o.logins != 1 {
		t.Errorf("GETs=%d logins=%d, want 4/1", o.gets, o.logins)
	}
}

// TestSettingsCheckSharesOneLogin: the monitor's settings check reads the redirect setting and
// then the Syslog page; the second read reuses the session of the first.
func TestSettingsCheckSharesOneLogin(t *testing.T) {
	g := newSyslogGateway(t, testCode, radioVariant, radioOff)
	c, _ := startSyslog(t, g, newFakeClock(), nil)
	if _, _, err := c.Notification(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Syslog(context.Background()); err != nil {
		t.Fatal(err)
	}
	if o := g.observed(); o.logins != 1 || o.gets != 1 {
		t.Errorf("logins=%d GET syslog.ha=%d, want 1/1", o.logins, o.gets)
	}
}

// TestSyslogReturnsRawPageWithParseError: a page that is not understood is still returned as
// the evidence of what the gateway showed.
func TestSyslogReturnsRawPageWithParseError(t *testing.T) {
	g := newSyslogGateway(t, testCode, noPortVariant, noPortOn)
	c, _ := startSyslog(t, g, newFakeClock(), nil)
	got, raw, err := c.Syslog(context.Background())
	if !errors.Is(err, ErrSyslogPage) || !reflect.DeepEqual(got, model.SyslogSetting{}) {
		t.Fatalf("setting=%+v err=%v", got, err)
	}
	if o := g.observed(); len(o.served) != 1 || !bytes.Equal(raw, o.served[0]) {
		t.Error("raw is not the page served")
	}
}

func TestSyslogOpsAreSerialized(t *testing.T) {
	g := newSyslogGateway(t, testCode, selectVariant, selectOff)
	c, _ := startSyslog(t, g, newFakeClock(), nil)
	var wg sync.WaitGroup
	errs := make(chan error, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var err error
			if i%3 == 0 {
				_, _, err = c.SetSyslog(context.Background(), enableTarget)
			} else {
				_, _, err = c.Syslog(context.Background())
			}
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if o := g.observed(); o.logins != 1 || len(o.posts) != 1 || o.badPosts != 0 {
		t.Errorf("logins=%d posts=%d bad=%d, want 1/1/0 (one session, one change)", o.logins, len(o.posts), o.badPosts)
	}
}

// ---------------------------------------------------------------- SetSyslog

// TestSetSyslogSelectSwitch: the exact bodies posted - only the syslog controls change, every
// other control is posted as the page has it (the disabled one left out), with the nonce of
// the page read and the Save button - and the read-back.
func TestSetSyslogSelectSwitch(t *testing.T) {
	g := newSyslogGateway(t, testCode, selectVariant, selectOff)
	clk := newFakeClock()
	c, srv := startSyslog(t, g, clk, nil)
	ctx := context.Background()

	before, after, err := c.SetSyslog(ctx, enableTarget)
	if err != nil {
		t.Fatal(err)
	}
	o := g.observed()
	if len(o.posts) != 1 || len(o.served) != 2 {
		t.Fatalf("posts=%d served=%d, want 1/2", len(o.posts), len(o.served))
	}
	if !bytes.Equal(before, o.served[0]) || !bytes.Equal(after, o.served[1]) {
		t.Error("before/after are not the exact pages read")
	}
	want := "nonce=" + nonceIn(t, before) + "&sl_en=1&sl_srv=192.168.1.71&sl_port=514&sl_lvl=6&sl_fw=on&hidden=&Save=Save"
	if o.posts[0] != want {
		t.Errorf("body = %q\nwant   %q", o.posts[0], want)
	}
	if o.referers[0] != srv.URL+"/cgi-bin/syslog.ha" || o.badPosts != 0 {
		t.Errorf("Referer = %q, bad posts = %d", o.referers[0], o.badPosts)
	}
	if o.state != (syslogState{true, "192.168.1.71", "514", "6"}) {
		t.Errorf("gateway state = %+v", o.state)
	}
	if s, err := ParseSyslog(after); err != nil || !s.Enabled || s.Server != "192.168.1.71" || s.Level != "Informational" {
		t.Errorf("after: %+v %v", s, err)
	}

	// Switching off changes only the switch: the fields are posted as the page shows them.
	clk.Advance(time.Minute)
	before, _, err = c.SetSyslog(ctx, model.SyslogTarget{Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	o = g.observed()
	want = "nonce=" + nonceIn(t, before) + "&sl_en=0&sl_srv=192.168.1.71&sl_port=514&sl_lvl=6&sl_fw=on&hidden=&Save=Save"
	if len(o.posts) != 2 || o.posts[1] != want {
		t.Errorf("off body = %q\nwant       %q", o.posts[len(o.posts)-1], want)
	}
	if o.logins != 1 {
		t.Errorf("logins = %d, want 1 (session reused)", o.logins)
	}

	// Already as requested: nothing posted, after is before.
	clk.Advance(time.Minute)
	before, after, err = c.SetSyslog(ctx, model.SyslogTarget{Enabled: false, Server: "ignored", Port: 1})
	if err != nil || !bytes.Equal(before, after) || len(before) == 0 {
		t.Fatalf("err=%v before==after %v", err, bytes.Equal(before, after))
	}
	if o := g.observed(); len(o.posts) != 2 {
		t.Errorf("posts = %d, want 2", len(o.posts))
	}
}

// TestSetSyslogLevel: an empty level leaves the page's level; a level is matched to an option
// by its text or its value, ignoring case.
func TestSetSyslogLevel(t *testing.T) {
	for _, tt := range []struct {
		level, posted string
	}{
		{"", "warning"},
		{"informational", "info"},
		{"INFO", "info"},
		{" Debug ", "debug"},
	} {
		g := newSyslogGateway(t, testCode, radioVariant, radioOff)
		c, _ := startSyslog(t, g, newFakeClock(), nil)
		want := enableTarget
		want.Level = tt.level
		before, _, err := c.SetSyslog(context.Background(), want)
		if err != nil {
			t.Fatalf("level %q: %v", tt.level, err)
		}
		o := g.observed()
		body := "nonce=" + nonceIn(t, before) + "&remlog=enable&remlog_ip=192.168.1.71&remlog_port=514&remlog_sev=" + tt.posted + "&Save=Save"
		if len(o.posts) != 1 || o.posts[0] != body {
			t.Errorf("level %q: body = %q\nwant %q", tt.level, o.posts, body)
		}
	}
	// The read-back accepts the level by value as well as by text; a level already set is
	// not posted again.
	g := newSyslogGateway(t, testCode, radioVariant, syslogState{true, "192.168.1.71", "514", "info"})
	c, _ := startSyslog(t, g, newFakeClock(), nil)
	for _, level := range []string{"info", "Informational", ""} {
		want := enableTarget
		want.Level = level
		if before, after, err := c.SetSyslog(context.Background(), want); err != nil || !bytes.Equal(before, after) {
			t.Errorf("level %q: err = %v, posted = %v", level, err, !bytes.Equal(before, after))
		}
	}
	if o := g.observed(); len(o.posts) != 0 {
		t.Errorf("posts = %d, want 0", len(o.posts))
	}
}

// TestSetSyslogUpdateRound: a page that shows the server fields only once Syslog is on is
// first posted with the switch on and its Update button; the fields are filled in on the page
// the gateway answers with, whose nonce is used for the Save.
func TestSetSyslogUpdateRound(t *testing.T) {
	for _, redirect := range []bool{false, true} {
		t.Run(map[bool]string{false: "Update answers with the page", true: "Update redirects to the page"}[redirect], func(t *testing.T) {
			g := newSyslogGateway(t, testCode, checkboxVariant, checkboxOff)
			g.updateRedirect = redirect
			var logs syncBuffer
			c, _ := startSyslog(t, g, newFakeClock(), &logs)
			before, after, err := c.SetSyslog(context.Background(), enableTarget)
			if err != nil {
				t.Fatal(err)
			}
			o := g.observed()
			if len(o.posts) != 2 || len(o.served) != 3 || o.badPosts != 0 {
				t.Fatalf("posts=%d served=%d bad=%d, want 2/3/0", len(o.posts), len(o.served), o.badPosts)
			}
			if want := "nonce=" + nonceIn(t, before) + "&logsend=on&Update=Update"; o.posts[0] != want {
				t.Errorf("Update body = %q, want %q", o.posts[0], want)
			}
			transformed := o.served[1]
			if want := "nonce=" + nonceIn(t, transformed) + "&logsend=on&logsrv=192.168.1.71&logport=514&loglevel=Informational&Save=Save"; o.posts[1] != want {
				t.Errorf("Save body = %q\nwant        %q", o.posts[1], want)
			}
			if !bytes.Equal(before, o.served[0]) || !bytes.Equal(after, o.served[2]) {
				t.Error("before/after are not the first and the last page read")
			}
			if o.state != (syslogState{true, "192.168.1.71", "514", "Informational"}) {
				t.Errorf("gateway state = %+v", o.state)
			}
			if !strings.Contains(logs.String(), "transformed by its Update button") {
				t.Error("the Update round is not in the log")
			}

			// Switching off needs no Update round: the unchecked box is simply left out.
			_, after, err = c.SetSyslog(context.Background(), model.SyslogTarget{})
			if err != nil {
				t.Fatal(err)
			}
			o = g.observed()
			want := "nonce=" + nonceIn(t, o.served[3]) + "&logsrv=192.168.1.71&logport=514&loglevel=Informational&Save=Save"
			if len(o.posts) != 3 || o.posts[2] != want {
				t.Errorf("off body = %q\nwant       %q", o.posts[len(o.posts)-1], want)
			}
			if s, err := ParseSyslog(after); err != nil || s.Enabled || s.Server != "" {
				t.Errorf("after: %+v %v (the page leaves the fields out again)", s, err)
			}
		})
	}
}

func TestSetSyslogNotApplied(t *testing.T) {
	g := newSyslogGateway(t, testCode, selectVariant, selectOff)
	g.ignoreSave = true
	c, _ := startSyslog(t, g, newFakeClock(), nil)
	before, after, err := c.SetSyslog(context.Background(), enableTarget)
	if !errors.Is(err, ErrNotApplied) {
		t.Fatalf("err = %v, want ErrNotApplied", err)
	}
	for _, want := range []string{"Syslog reads off (wanted on)", `Server IP Address reads "" (wanted "192.168.1.71")`,
		`Log Level reads "Warning" (wanted "Informational")`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to say %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "Server Port") {
		t.Errorf("err = %v names the port, which is as wanted", err)
	}
	o := g.observed()
	if len(o.served) != 2 || !bytes.Equal(before, o.served[0]) || !bytes.Equal(after, o.served[1]) {
		t.Error("before/after evidence missing")
	}
}

// TestSetSyslogPostOutcomes: the read-back decides when the POST's outcome is unknown, and no
// Save is posted when the Update round fails.
func TestSetSyslogPostOutcomes(t *testing.T) {
	ctx := context.Background()
	t.Run("Save answered with an error but applied", func(t *testing.T) {
		g := newSyslogGateway(t, testCode, selectVariant, selectOff)
		g.onPost = func(w http.ResponseWriter, form url.Values) bool {
			g.v.apply(&g.st, form)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return true
		}
		var logs syncBuffer
		c, _ := startSyslog(t, g, newFakeClock(), &logs)
		if _, after, err := c.SetSyslog(ctx, enableTarget); err != nil || after == nil {
			t.Fatalf("err = %v; the read-back shows the requested setting", err)
		}
		if !strings.Contains(logs.String(), "verified by reading it back") {
			t.Error("the unknown outcome is not in the log")
		}
	})
	t.Run("Save answered with an error, not applied", func(t *testing.T) {
		g := newSyslogGateway(t, testCode, selectVariant, selectOff)
		g.onPost = func(w http.ResponseWriter, form url.Values) bool {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return true
		}
		c, _ := startSyslog(t, g, newFakeClock(), nil)
		_, after, err := c.SetSyslog(ctx, enableTarget)
		if !errors.Is(err, ErrNotApplied) || !strings.Contains(err.Error(), "500") || after == nil {
			t.Fatalf("err = %v, want ErrNotApplied mentioning the HTTP 500", err)
		}
	})
	t.Run("session expired at the Save", func(t *testing.T) {
		g := newSyslogGateway(t, testCode, selectVariant, selectOff)
		g.onPost = func(w http.ResponseWriter, form url.Values) bool {
			g.sessions = map[string]*mockSession{}
			g.write(w, http.StatusOK, fixture(g.t, "login_handshake1.html"))
			return true
		}
		clk := newFakeClock()
		c, _ := startSyslog(t, g, clk, nil)
		if _, after, err := c.SetSyslog(ctx, enableTarget); !errors.Is(err, ErrLoginRequired) || after != nil {
			t.Fatalf("err = %v, want ErrLoginRequired", err)
		}
		clk.Advance(10 * time.Second)
		req := g.observed().requests
		if _, _, err := c.Syslog(ctx); !errors.Is(err, ErrLoginThrottled) {
			t.Errorf("err = %v, want ErrLoginThrottled (dead session dropped)", err)
		}
		if got := g.observed().requests; got != req {
			t.Errorf("%d request(s) with a session known to be dead", got-req)
		}
	})
	for name, answer := range map[string]func(w http.ResponseWriter){
		"Update answered with an error": func(w http.ResponseWriter) {
			http.Error(w, "internal error", http.StatusInternalServerError)
		},
		"Update redirected elsewhere": func(w http.ResponseWriter) {
			w.Header().Set("Location", "/cgi-bin/home.ha")
			w.WriteHeader(http.StatusFound)
		},
	} {
		t.Run(name, func(t *testing.T) {
			g := newSyslogGateway(t, testCode, checkboxVariant, checkboxOff)
			g.onPost = func(w http.ResponseWriter, form url.Values) bool {
				answer(w)
				return true
			}
			c, _ := startSyslog(t, g, newFakeClock(), nil)
			before, after, err := c.SetSyslog(ctx, enableTarget)
			if err == nil || !strings.Contains(err.Error(), "Save not posted") || before == nil || after != nil {
				t.Fatalf("err = %v, after = %v", err, after != nil)
			}
			if o := g.observed(); len(o.posts) != 1 || len(o.served) != 1 || o.state != checkboxOff {
				t.Errorf("posts=%d served=%d state=%+v, want only the Update POST and no read-back", len(o.posts), len(o.served), o.state)
			}
		})
	}
}

// TestSetSyslogFailsClosed: a page that is not fully understood is never posted.
func TestSetSyslogFailsClosed(t *testing.T) {
	type tc struct {
		name    string
		variant syslogVariant // default: the select variant, off
		state   syslogState
		setup   func(t *testing.T, g *syslogGateway)
		off     bool   // switch Syslog off (default: enableTarget)
		posts   int    // Update round POSTs expected before the refusal
		msg     string // part of the error
	}
	sel := func(pattern, repl string) func(t *testing.T, g *syslogGateway) {
		return func(t *testing.T, g *syslogGateway) { g.edit = pageEdit(t, "syslog_select.html", pattern, repl) }
	}
	cb := func(pattern, repl string) func(t *testing.T, g *syslogGateway) {
		return func(t *testing.T, g *syslogGateway) { g.edit = pageEdit(t, "syslog_checkbox_off.html", pattern, repl) }
	}
	selectOn := syslogState{true, "192.168.1.64", "514", "6"}
	tests := []tc{
		{name: "form posts to another page", setup: sel(`action="/cgi-bin/syslog.ha"`, `action="/cgi-bin/events.ha"`), msg: `posts to "/cgi-bin/events.ha"`},
		{name: "form posts to another host", setup: sel(`action="/cgi-bin/syslog.ha"`, `action="https://203.0.113.9/cgi-bin/syslog.ha"`), msg: "not syslog.ha"},
		{name: "form posts with a query", setup: sel(`action="/cgi-bin/syslog.ha"`, `action="/cgi-bin/syslog.ha?debug=1"`), msg: "not syslog.ha"},
		{name: "form sent with GET", setup: sel(`<form method="post"`, `<form method="get"`), msg: `method "get"`},
		{name: "form sent as multipart", setup: sel(`<form method="post"`, `<form method="post" enctype="multipart/form-data"`), msg: "multipart/form-data"},
		{name: "no nonce", setup: sel(`<input type="hidden" name="nonce" value="[0-9a-f]+" />`, ``), msg: "no nonce"},
		{name: "no Save button", setup: sel(`<input type="submit" name="Save"[^>]*/>`, ``), msg: "no Save button"},
		{name: "two different Save buttons", setup: sel(`<input type="submit" name="Cancel"`, `<input type="submit" name="Save" value="Save to File..." /><input type="submit" name="Cancel"`),
			msg: "2 different Save buttons"},
		{name: "Save button posts elsewhere", setup: sel(`name="Save" class`, `name="Save" formaction="/cgi-bin/other.ha" class`), msg: "not syslog.ha"},
		{name: "server address in two boxes", setup: sel(`<input id="slsrv" type="text" name="sl_srv" size="15" maxlength="15" value="" />`,
			`<input id="slsrv" type="text" name="sl_srv" size="15" maxlength="15" value="" /><input type="text" name="sl_srv2" value="" />`),
			msg: `2 controls are labelled "Server IP Address"`},
		{name: "server address read-only", setup: sel(`name="sl_srv" size="15"`, `name="sl_srv" readonly="readonly" size="15"`), msg: "read-only"},
		{name: "server address disabled", setup: sel(`name="sl_srv" size="15"`, `name="sl_srv" disabled="disabled" size="15"`), msg: "disabled"},
		{name: "server address too long for the field", setup: sel(`name="sl_srv" size="15" maxlength="15"`, `name="sl_srv" size="15" maxlength="7"`), msg: "at most 7 characters"},
		{name: "level is not an option", variant: fewLevelsVariant, state: fewLevelsOn, msg: `"Log Level" has no option "Informational"`},
		{name: "level option disabled", setup: sel(`<option value="6">`, `<option value="6" disabled="disabled">`), msg: `has no option "Informational"`},
		{name: "level typed in", setup: sel(`(?s)<select id="sllevel" name="sl_lvl"  >.*?</select>`, `<input id="sllevel" name="sl_lvl" value="Warning" />`),
			msg: "not a list of options"},
		{name: "port control missing", variant: noPortVariant, state: noPortOn, msg: `no control labelled "Server Port"`},
		{name: "switch has no option for off", state: selectOn, off: true,
			setup: sel(`<option value="0"(\s*(?:selected="selected")?)>Off</option>`, `<option value="2"${1}>Auto</option>`),
			msg:   "0 options for off"},
		{name: "switch option for on disabled", setup: sel(`<option value="1"`, `<option value="1" disabled="disabled"`), msg: "0 options for on"},
		{name: "switch disabled", setup: sel(`name="sl_en"`, `name="sl_en" disabled="disabled"`), msg: `the "Syslog" list is disabled`},
		{name: "level list disabled", setup: sel(`name="sl_lvl"`, `name="sl_lvl" disabled="disabled"`), msg: `the "Log Level" list is disabled`},
		{name: "two options for on", setup: sel(`>Off</option>`, `>Off</option><option value="yes">Enabled</option>`), msg: "2 options for on"},
		{name: "another field holds characters outside ASCII", setup: sel(`name="hidden" value=""`, `name="hidden" value="caf&#233;"`), msg: "outside ASCII"},
		{name: "fields hidden and no Update button", variant: checkboxVariant, state: checkboxOff,
			setup: cb(`<input type="submit" name="Update"[^>]*/>`, ``), msg: "has no Update button"},
		{name: "Update button posts elsewhere", variant: checkboxVariant, state: checkboxOff,
			setup: cb(`name="Update" class`, `name="Update" formaction="/cgi-bin/other.ha" class`), msg: "not syslog.ha"},
		{name: "no Save button before the Update round", variant: checkboxVariant, state: checkboxOff,
			setup: cb(`<input type="submit" name="Save"[^>]*/>`, ``), msg: "no Save button"},
		{name: "the Update round does not show the fields", variant: checkboxVariant, state: checkboxOff,
			setup: func(t *testing.T, g *syslogGateway) { g.updateIgnored = true }, posts: 1, msg: "still shows no"},
		{name: "the Update round shows no port", variant: checkboxVariant, state: checkboxOff,
			setup: func(t *testing.T, g *syslogGateway) {
				g.editUpdate = pageEdit(t, "syslog_checkbox_on.html", `(?s)<tr>\s*<td></td>\s*<th scope="row"><label for="logport">.*?</tr>`, ``)
			},
			posts: 1, msg: `no control labelled "Server Port"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.variant.off == "" {
				tt.variant = selectVariant
				if tt.state == (syslogState{}) {
					tt.state = selectOff
				}
			}
			want := enableTarget
			if tt.off {
				want = model.SyslogTarget{}
			}
			g := newSyslogGateway(t, testCode, tt.variant, tt.state)
			if tt.setup != nil {
				tt.setup(t, g)
			}
			c, _ := startSyslog(t, g, newFakeClock(), nil)
			before, after, err := c.SetSyslog(context.Background(), want)
			if !errors.Is(err, ErrSyslogPage) || !strings.Contains(err.Error(), tt.msg) {
				t.Fatalf("err = %v, want ErrSyslogPage mentioning %q", err, tt.msg)
			}
			wantSuffix := "nothing posted"
			if tt.posts > 0 {
				wantSuffix = "Save not posted"
			}
			if !strings.Contains(err.Error(), wantSuffix) {
				t.Errorf("err = %v, want it to say %q", err, wantSuffix)
			}
			o := g.observed()
			if len(o.posts) != tt.posts || o.state != tt.state {
				t.Errorf("posts = %q, state = %+v: the form was posted", o.posts, o.state)
			}
			for _, f := range o.forms {
				if f.Has("Save") {
					t.Errorf("a Save was posted: %v", f)
				}
			}
			if len(before) == 0 || !bytes.Equal(before, o.served[0]) || after != nil {
				t.Errorf("before = %d bytes, after = %v: want the page read, and no after", len(before), after != nil)
			}
		})
	}
}

// TestSetSyslogInvalidTarget: an invalid target is refused before any request.
func TestSetSyslogInvalidTarget(t *testing.T) {
	g := newSyslogGateway(t, testCode, selectVariant, selectOff)
	c, _ := startSyslog(t, g, newFakeClock(), nil)
	for _, want := range []model.SyslogTarget{
		{Enabled: true, Server: "", Port: 514},
		{Enabled: true, Server: "syslog.lan", Port: 514},
		{Enabled: true, Server: "192.168.1.71 ", Port: 514},
		{Enabled: true, Server: "2001:db8::1", Port: 514},
		{Enabled: true, Server: "::ffff:192.168.1.71", Port: 514},
		{Enabled: true, Server: "0.0.0.0", Port: 514},
		{Enabled: true, Server: "192.168.1.71", Port: 0},
		{Enabled: true, Server: "192.168.1.71", Port: 65536},
	} {
		if _, _, err := c.SetSyslog(context.Background(), want); err == nil || errors.Is(err, ErrSyslogPage) {
			t.Errorf("%+v: err = %v", want, err)
		}
	}
	if o := g.observed(); o.requests != 0 {
		t.Errorf("%d requests for invalid targets", o.requests)
	}
}

// TestSyslogLoginPolicy: the Syslog page goes through the same login policy as the redirect
// setting: one attempt a minute, none after three rejections within an hour, none while the
// gateway's session pool is full - and nothing is ever posted without a session.
func TestSyslogLoginPolicy(t *testing.T) {
	ctx := context.Background()
	t.Run("rejected logins", func(t *testing.T) {
		g := newSyslogGateway(t, "the-real-code", selectVariant, selectOff)
		clk := newFakeClock()
		c, _ := startSyslog(t, g, clk, nil)
		for i := 1; i <= maxFailures; i++ {
			var err error
			if i%2 == 1 {
				_, _, err = c.SetSyslog(ctx, enableTarget)
			} else {
				_, _, err = c.Syslog(ctx)
			}
			if !errors.Is(err, ErrAuth) {
				t.Fatalf("attempt %d: err = %v, want ErrAuth", i, err)
			}
			// Immediately afterwards no attempt is made (the lock takes over after the third).
			req := g.observed().requests
			wantErr := ErrLoginThrottled
			if i == maxFailures {
				wantErr = ErrAuthLocked
			}
			if _, _, err := c.SetSyslog(ctx, enableTarget); !errors.Is(err, wantErr) {
				t.Fatalf("attempt %d: err = %v, want %v", i, err, wantErr)
			}
			if g.observed().requests != req {
				t.Fatal("a throttled call reached the gateway")
			}
			clk.Advance(loginSpacing + time.Second)
		}
		req := g.observed().requests
		var ce *CooldownError
		if _, _, err := c.Syslog(ctx); !errors.Is(err, ErrAuthLocked) || !errors.As(err, &ce) {
			t.Fatalf("err = %v, want ErrAuthLocked", err)
		}
		if _, _, err := c.SetSyslog(ctx, enableTarget); !errors.Is(err, ErrAuthLocked) {
			t.Fatalf("err = %v, want ErrAuthLocked", err)
		}
		if o := g.observed(); o.requests != req || len(o.posts) != 0 || o.state != selectOff {
			t.Errorf("requests %d -> %d, posts %d: a locked client contacted the gateway", req, o.requests, len(o.posts))
		}
	})
	t.Run("sessions full", func(t *testing.T) {
		g := newSyslogGateway(t, testCode, selectVariant, selectOff)
		g.sessionsFull = true
		clk := newFakeClock()
		c, _ := startSyslog(t, g, clk, nil)
		var ce *CooldownError
		if _, _, err := c.SetSyslog(ctx, enableTarget); !errors.Is(err, ErrSessionsFull) || !errors.As(err, &ce) ||
			!ce.Until.Equal(clk.Now().Add(sessionsFullCooldown)) {
			t.Fatalf("err = %v, want ErrSessionsFull with a 5 minute cooldown", err)
		}
		req := g.observed().requests
		clk.Advance(2 * time.Minute)
		if _, _, err := c.Syslog(ctx); !errors.Is(err, ErrSessionsFull) {
			t.Fatalf("during the cooldown: err = %v", err)
		}
		if o := g.observed(); o.requests != req || len(o.posts) != 0 {
			t.Errorf("%d requests during the cooldown", o.requests-req)
		}
		clk.Advance(3*time.Minute + time.Second)
		g.set(func(m *mockGateway) { m.sessionsFull = false })
		if _, _, err := c.SetSyslog(ctx, enableTarget); err != nil {
			t.Fatalf("after the cooldown: %v", err)
		}
	})
	t.Run("protected page redirects to login.ha", func(t *testing.T) {
		g := newSyslogGateway(t, testCode, selectVariant, selectOff)
		g.redirectToLogin = true
		c, srv := startSyslog(t, g, newFakeClock(), nil)
		if _, _, err := c.SetSyslog(ctx, enableTarget); err != nil {
			t.Fatal(err)
		}
		g.mu.Lock()
		ref := g.mockGateway.referers[0]
		g.mu.Unlock()
		if ref != srv.URL+"/cgi-bin/login.ha" {
			t.Errorf("login Referer = %q", ref)
		}
	})
	t.Run("errors match the contracts sentinels", func(t *testing.T) {
		g := newSyslogGateway(t, "the-real-code", selectVariant, selectOff)
		c, _ := startSyslog(t, g, newFakeClock(), nil)
		_, _, err := c.Syslog(ctx)
		checkSentinels(t, err, ErrAuth, contractSentinels["ErrGatewayAuth"])
	})
}

// TestSyslogSecretsNeverLeak drives the Syslog paths (success, wrong code, throttling,
// lockout, sessions full, not applied, Update round) with debug logging: neither the access
// code nor any login hash may appear in an error or in the log.
func TestSyslogSecretsNeverLeak(t *testing.T) {
	var logs syncBuffer
	var errs, hashes []string
	ctx := context.Background()
	for _, sc := range []struct {
		code  string
		v     syslogVariant
		st    syslogState
		setup func(g *syslogGateway)
	}{
		{testCode, selectVariant, selectOff, nil},
		{testCode, checkboxVariant, checkboxOff, nil},
		{testCode + "x", selectVariant, selectOff, nil},
		{testCode, selectVariant, selectOff, func(g *syslogGateway) { g.sessionsFull = true }},
		{testCode, radioVariant, radioOff, func(g *syslogGateway) { g.ignoreSave = true }},
	} {
		g := newSyslogGateway(t, testCode, sc.v, sc.st)
		if sc.setup != nil {
			sc.setup(g)
		}
		clk := newFakeClock()
		srv := httptest.NewServer(g)
		c := newTestClient(t, srv, clk, sc.code, &logs)
		for i := 0; i < 5; i++ {
			_, _, err := c.Syslog(ctx)
			if err != nil {
				errs = append(errs, err.Error())
			}
			want := enableTarget
			want.Enabled = i%2 == 0
			if _, _, err := c.SetSyslog(ctx, want); err != nil {
				errs = append(errs, err.Error())
			}
			clk.Advance(loginSpacing + time.Second)
		}
		srv.Close()
		hashes = append(hashes, g.hashes()...)
	}
	if len(hashes) == 0 || len(errs) == 0 {
		t.Fatalf("scenarios did not exercise logins (%d hashes, %d errors)", len(hashes), len(errs))
	}
	for _, e := range errs {
		mustNotContainSecret(t, "error", e, testCode, hashes)
	}
	mustNotContainSecret(t, "log", logs.String(), testCode, hashes)
	for _, want := range []string{"gateway login rejected", "gateway login succeeded", "gateway syslog setting posted"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("expected %q in the operational log", want)
		}
	}
}
