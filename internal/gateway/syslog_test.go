package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// ---------------------------------------------------------------- fake gateway with a Syslog page

// syslogVariant describes one Syslog page (testdata/gateway/syslog_*.html) for the fake
// gateway: its fixtures and the names of its controls - which the client never uses: it finds
// the controls by their labels.
type syslogVariant struct {
	off, on             string // fixture shown while Syslog is off, and while on ("" = the same)
	update              string // fixture the Update button answers with once on ("" = on)
	offFields           bool   // the off fixture shows the fields too (disabled)
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
	// The real page of firmware 6.34.7 and the pages derived from it (testdata/gateway/README.md):
	// while Syslog is off the fields are shown but disabled.
	realVariant = syslogVariant{off: "syslog_real_off.html", on: "syslog_real_on.html", update: "syslog_real_on_update.html",
		offFields: true, sw: "syslog", swKind: "select", swOn: "on", swOff: "off", server: "location", port: "port", level: "level"}

	// The settings the fixtures show (for the checkbox variant: what the page shows once on).
	selectOff    = syslogState{false, "", "514", "4"}
	checkboxOff  = syslogState{false, "", "514", "Warning"}
	radioOff     = syslogState{false, "", "514", "warning"}
	noPortOn     = syslogState{true, "192.168.1.64", "", "notice"}
	fewLevelsOn  = syslogState{true, "192.168.1.64", "514", "5"}
	realOff      = syslogState{false, "", "514", "Error"} // as captured
	realOn       = syslogState{true, "192.168.1.71", "514", "Notice"}
	enableTarget = model.SyslogTarget{Enabled: true, Server: "192.168.1.71", Port: 514, Level: "Informational"}
	// The real page offers no "Informational": Notice is its most detailed level.
	noticeTarget = model.SyslogTarget{Enabled: true, Server: "192.168.1.71", Port: 514, Level: "Notice"}
)

// render returns the variant's page showing st; update asks for the page the Update button
// answers with. Mismatches are reported with t.Errorf: it runs in the server's goroutines.
func (v syslogVariant) render(t testing.TB, st syslogState, update bool) []byte {
	name := v.off
	if st.on && v.on != "" {
		name = v.on
		if update && v.update != "" {
			name = v.update
		}
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
	if st.on || v.on == "" || v.offFields {
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

// pageRules is what a page served lets a browser post: the names of its controls, those it
// disables (a browser never submits them), and the values each drop-down list offers (its
// options that are not disabled).
type pageRules struct {
	controls, disabled map[string]bool
	options            map[string]map[string]bool
}

var (
	reControlTag = regexp.MustCompile(`<(?:input|select|textarea)\b([^>]*)>`)
	reNameAttr   = regexp.MustCompile(`\bname="([^"]*)"`)
	reValueAttr  = regexp.MustCompile(`\bvalue="([^"]*)"`)
	reDisabled   = regexp.MustCompile(`\sdisabled(?:="[^"]*")?(?:\s|/|$)`)
	reSelectElem = regexp.MustCompile(`(?s)<select\b([^>]*)>(.*?)</select>`)
	reOptionElem = regexp.MustCompile(`<option\b([^>]*)>([^<]*)`)
)

// rulesOf reads the rules of a page served from its markup with regular expressions (the
// fixtures' markup is regular), independently of the client's form reader.
func rulesOf(page []byte) pageRules {
	r := pageRules{controls: map[string]bool{}, disabled: map[string]bool{}, options: map[string]map[string]bool{}}
	for _, m := range reControlTag.FindAllSubmatch(page, -1) {
		if n := reNameAttr.FindSubmatch(m[1]); n != nil {
			r.controls[string(n[1])] = true
			if reDisabled.Match(m[1]) {
				r.disabled[string(n[1])] = true
			}
		}
	}
	for _, m := range reSelectElem.FindAllSubmatch(page, -1) {
		n := reNameAttr.FindSubmatch(m[1])
		if n == nil {
			continue
		}
		offered := map[string]bool{}
		for _, o := range reOptionElem.FindAllSubmatch(m[2], -1) {
			if reDisabled.Match(o[1]) {
				continue
			}
			v := strings.Join(strings.Fields(html.UnescapeString(string(o[2]))), " ") // no value: the text
			if va := reValueAttr.FindSubmatch(o[1]); va != nil {
				v = html.UnescapeString(string(va[1]))
			}
			offered[v] = true
		}
		r.options[string(n[1])] = offered
	}
	return r
}

// refuses says why the gateway refuses a form posted from the page ("" = it does not): a
// control the page does not have or disables, a value a list does not offer, or not exactly
// one of the page's buttons.
func (r pageRules) refuses(form url.Values) string {
	buttons := 0
	for _, name := range slices.Sorted(maps.Keys(form)) {
		switch {
		case !r.controls[name]:
			return "posts " + name + ", which the page does not have"
		case r.disabled[name]:
			return "posts " + name + ", which the page disables"
		}
		if offered, ok := r.options[name]; ok {
			for _, v := range form[name] {
				if !offered[v] {
					return fmt.Sprintf("posts %s=%q, which the list does not offer", name, v)
				}
			}
		}
		if name == "Update" || name == "Save" || name == "Cancel" {
			buttons++
		}
	}
	if buttons != 1 {
		return fmt.Sprintf("posts %d buttons", buttons)
	}
	return ""
}

// syslogGateway is the mock gateway (helpers_test.go) with a Syslog page behind the same
// login: syslog.ha is rendered from a fixture for the stored setting. It keeps the real page's
// rules: a POST must carry the nonce of the page served last to the session (single use) and
// only controls that page has and enables, with values its lists offer; anything else is
// refused - counted, not applied, answered with a redirect to the page. An accepted POST is
// saved (Save) or answered with the page transformed by the switch posted (Update), with the
// page itself (200) or a redirect to it (302), as the behaviour switches say.
type syslogGateway struct {
	*mockGateway
	v  syslogVariant
	st syslogState

	// behaviour switches
	ignoreSave     bool                     // Save does not change the setting
	saveOK         bool                     // Save answers 200 with the page (else 302 -> syslog.ha)
	updateRedirect bool                     // Update answers 302 -> syslog.ha; the next GET shows the transformed page
	updateIgnored  bool                     // Update leaves the page unchanged
	edit           func(page []byte) []byte // applied to every page served
	editUpdate     func(page []byte) []byte // applied to the transformed page only
	// onPost takes over a POST to syslog.ha (after it is recorded) when it returns true. It
	// runs with the gateway locked.
	onPost func(w http.ResponseWriter, form url.Values) bool

	nonces  map[*mockSession]string
	rules   map[*mockSession]pageRules
	pending map[*mockSession]bool

	// observations
	served   [][]byte // Syslog pages served, in order
	posts    []string // raw POST bodies to syslog.ha, in order
	forms    []url.Values
	referers []string
	badPosts int      // POSTs refused: not applied
	rejects  []string // why, in order
}

func newSyslogGateway(t testing.TB, code string, v syslogVariant, st syslogState) *syslogGateway {
	return &syslogGateway{mockGateway: newMockGateway(t, code, false), v: v, st: st,
		nonces: map[*mockSession]string{}, rules: map[*mockSession]pageRules{}, pending: map[*mockSession]bool{}}
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
	nonce, rules := g.nonces[s], g.rules[s]
	delete(g.nonces, s) // single use: only the page served last can be posted, once
	delete(g.rules, s)
	var refused string
	switch {
	case nonce == "" || form.Get("nonce") != nonce:
		refused = "stale or missing nonce"
	case r.Header.Get("Content-Type") != "application/x-www-form-urlencoded":
		refused = "not form-urlencoded"
	default:
		refused = rules.refuses(form)
	}
	switch {
	case refused != "":
		g.badPosts++
		g.rejects = append(g.rejects, refused)
	case form.Has("Update") && g.updateRedirect:
		if !g.updateIgnored {
			g.pending[s] = g.v.switchOn(form)
		}
	case form.Has("Update"):
		if g.updateIgnored {
			g.write(w, http.StatusOK, g.page(s, g.st.on, false))
		} else {
			g.write(w, http.StatusOK, g.page(s, g.v.switchOn(form), true))
		}
		return
	case form.Has("Save"):
		if !g.ignoreSave {
			g.v.apply(&g.st, form)
		}
		if g.saveOK {
			g.write(w, http.StatusOK, g.page(s, g.st.on, false))
			return
		}
	}
	w.Header().Set("Location", "/cgi-bin/syslog.ha")
	g.write(w, http.StatusFound, nil)
}

// page renders the Syslog page with the switch at on (the stored setting otherwise) and a
// fresh nonce for session s, and notes its rules; update asks for the page the Update button
// transforms.
func (g *syslogGateway) page(s *mockSession, on, update bool) []byte {
	st := g.st
	st.on = on
	p := g.v.render(g.t, st, update)
	if g.edit != nil {
		p = g.edit(p)
	}
	if update && g.editUpdate != nil {
		p = g.editUpdate(p)
	}
	nonce := randomHex(32)
	g.nonces[s] = nonce
	p = withNonce(p, nonce)
	g.rules[s] = rulesOf(p)
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
	rejects  []string
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
		rejects:  append([]string(nil), g.rejects...),
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
	levels6 = []string{"Emergency", "Alert", "Critical", "Error", "Warning", "Notice"} // the real page
)

func TestParseSyslogFixtures(t *testing.T) {
	tests := []struct {
		name string
		want model.SyslogSetting
		err  string // part of the ErrSyslogPage message ("" = no error)
	}{
		// The real page, off: the fields are read although disabled.
		{"syslog_real_off.html", model.SyslogSetting{Enabled: false, Server: "", Port: 514, Level: "Error", Levels: levels6}, ""},
		{"syslog_real_on_update.html", model.SyslogSetting{Enabled: true, Port: 514, Level: "Error", Levels: levels6}, ""},
		{"syslog_real_on.html", model.SyslogSetting{Enabled: true, Server: "192.168.1.71", Port: 514, Level: "Notice", Levels: levels6}, ""},
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
			lf := func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")) }
			for vname, variant := range map[string]func([]byte) []byte{
				"LF":      lf,
				"CRLF":    func(b []byte) []byte { return bytes.ReplaceAll(lf(b), []byte("\n"), []byte("\r\n")) },
				"CR":      func(b []byte) []byte { return bytes.ReplaceAll(lf(b), []byte("\n"), []byte("\r")) },
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
// the gateway answers with, whose nonce is used for the Save. Switching off takes the same two
// rounds, as the page asks of a change of an item with an Update button.
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
				t.Fatalf("posts=%d served=%d refused=%q, want 2/3/none", len(o.posts), len(o.served), o.rejects)
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

			// Switching off: the box is unchecked (and so left out) with the Update button, the
			// fields posted as the page has them; the page the gateway answers with leaves the
			// fields out again, and is saved.
			_, after, err = c.SetSyslog(context.Background(), model.SyslogTarget{})
			if err != nil {
				t.Fatal(err)
			}
			o = g.observed()
			if len(o.posts) != 4 || len(o.served) != 6 || o.badPosts != 0 {
				t.Fatalf("posts=%d served=%d refused=%q, want 4/6/none", len(o.posts), len(o.served), o.rejects)
			}
			if want := "nonce=" + nonceIn(t, o.served[3]) + "&Update=Update&logsrv=192.168.1.71&logport=514&loglevel=Informational"; o.posts[2] != want {
				t.Errorf("off Update body = %q\nwant              %q", o.posts[2], want)
			}
			if want := "nonce=" + nonceIn(t, o.served[4]) + "&Save=Save"; o.posts[3] != want {
				t.Errorf("off Save body = %q, want %q", o.posts[3], want)
			}
			if o.state != (syslogState{false, "192.168.1.71", "514", "Informational"}) {
				t.Errorf("gateway state = %+v (the fields are kept)", o.state)
			}
			if s, err := ParseSyslog(after); err != nil || s.Enabled || s.Server != "" || !bytes.Equal(after, o.served[5]) {
				t.Errorf("after: %+v %v (the page leaves the fields out again)", s, err)
			}
		})
	}
}

// TestSetSyslogRealPage drives SetSyslog on the real Syslog page of firmware 6.34.7
// (syslog_real_off.html) and the pages derived from it, through a fake gateway that keeps the
// page's rules (a POST must carry the nonce of the page served last, and no control that page
// disables). Switching on, the fields are disabled, so the switch goes On with the Update
// button first, exactly as a browser without JavaScript posts it; the fields are filled in on
// the page the gateway answers with and saved with that page's nonce. Switching off takes the
// same two rounds. However the gateway answers the Update and the Save - with the page (200) or
// a redirect to it (302) - the bodies posted are the same, and the page read back decides.
func TestSetSyslogRealPage(t *testing.T) {
	answer := map[bool]string{false: "200", true: "302"}
	for _, updateRedirect := range []bool{false, true} {
		for _, saveRedirect := range []bool{false, true} {
			t.Run("Update answered "+answer[updateRedirect]+", Save answered "+answer[saveRedirect], func(t *testing.T) {
				g := newSyslogGateway(t, testCode, realVariant, realOff)
				g.updateRedirect, g.saveOK = updateRedirect, !saveRedirect
				var logs syncBuffer
				clk := newFakeClock()
				c, _ := startSyslog(t, g, clk, &logs)
				ctx := context.Background()

				before, after, err := c.SetSyslog(ctx, noticeTarget)
				if err != nil {
					t.Fatal(err)
				}
				o := g.observed()
				// Served: the page read, the transformed page, the Save's answer (200 only) and
				// the page read back.
				served := 3
				if !saveRedirect {
					served++
				}
				if len(o.posts) != 2 || len(o.served) != served || o.badPosts != 0 {
					t.Fatalf("posts=%d served=%d refused=%q, want 2/%d/none", len(o.posts), len(o.served), o.rejects, served)
				}
				// The disabled fields are left out of the Update round.
				if want := "nonce=" + nonceIn(t, before) + "&syslog=on&Update=Update"; o.posts[0] != want {
					t.Errorf("Update body = %q\nwant          %q", o.posts[0], want)
				}
				if want := "nonce=" + nonceIn(t, o.served[1]) + "&syslog=on&location=192.168.1.71&port=514&level=Notice&Save=Save"; o.posts[1] != want {
					t.Errorf("Save body = %q\nwant        %q", o.posts[1], want)
				}
				// The read-back is a GET of its own, whatever the Save was answered with.
				gets := 4 // the login's three, and the read-back
				if updateRedirect {
					gets++
				}
				if o.gets != gets || !bytes.Equal(before, o.served[0]) || !bytes.Equal(after, o.served[served-1]) {
					t.Errorf("GETs = %d (want %d), or before/after are not the first and the last page read", o.gets, gets)
				}
				if o.state != realOn {
					t.Errorf("gateway state = %+v", o.state)
				}
				on := model.SyslogSetting{Enabled: true, Server: "192.168.1.71", Port: 514, Level: "Notice", Levels: levels6}
				if s, err := ParseSyslog(after); err != nil || !reflect.DeepEqual(s, on) {
					t.Errorf("after: %+v %v", s, err)
				}
				for _, l := range []string{"transformed by its Update button", "gateway syslog setting posted"} {
					if !strings.Contains(logs.String(), l) {
						t.Errorf("%q is not in the log", l)
					}
				}

				// Switching off: the switch goes Off with the Update button (the fields, enabled
				// while on, posted as the page has them), and the page the gateway answers with,
				// whose fields are disabled again, is saved with the switch alone.
				clk.Advance(time.Minute)
				before, after, err = c.SetSyslog(ctx, model.SyslogTarget{})
				if err != nil {
					t.Fatal(err)
				}
				o = g.observed()
				if len(o.posts) != 4 || len(o.served) != 2*served || o.badPosts != 0 || o.logins != 1 {
					t.Fatalf("posts=%d served=%d refused=%q logins=%d, want 4/%d/none/1", len(o.posts), len(o.served), o.rejects, o.logins, 2*served)
				}
				if want := "nonce=" + nonceIn(t, before) + "&syslog=off&Update=Update&location=192.168.1.71&port=514&level=Notice"; o.posts[2] != want {
					t.Errorf("off Update body = %q\nwant              %q", o.posts[2], want)
				}
				if want := "nonce=" + nonceIn(t, o.served[served+1]) + "&syslog=off&Save=Save"; o.posts[3] != want {
					t.Errorf("off Save body = %q, want %q", o.posts[3], want)
				}
				if !bytes.Equal(before, o.served[served]) || !bytes.Equal(after, o.served[2*served-1]) {
					t.Error("before/after are not the first and the last page read")
				}
				if o.state != (syslogState{false, "192.168.1.71", "514", "Notice"}) {
					t.Errorf("gateway state = %+v (the server, port and level are kept)", o.state)
				}
				off := on
				off.Enabled = false
				if s, err := ParseSyslog(after); err != nil || !reflect.DeepEqual(s, off) {
					t.Errorf("after: %+v %v", s, err)
				}
			})
		}
	}
}

// TestSetSyslogRealPageLevels: with Syslog already on the fields are enabled and the switch
// stays: they are changed and saved in one round (this computer's address changed, say). An
// empty level leaves the level as the page has it - when switching on, as the page the Update
// round answered with has it; a level is matched by text or value, ignoring case.
func TestSetSyslogRealPageLevels(t *testing.T) {
	for _, tt := range []struct {
		name   string
		state  syslogState
		level  string
		posted string // the level saved
	}{
		{"on, address changed", syslogState{true, "192.168.1.64", "514", "Warning"}, "Notice", "Notice"},
		{"on, address changed, level kept", syslogState{true, "192.168.1.64", "514", "Warning"}, "", "Warning"},
		{"on, level by another case", syslogState{true, "192.168.1.64", "514", "Warning"}, " notice ", "Notice"},
		{"on, port changed", syslogState{true, "192.168.1.71", "1514", "Notice"}, "Notice", "Notice"},
		{"off, level kept", realOff, "", "Error"},
		{"off, level by another case", realOff, "NOTICE", "Notice"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := newSyslogGateway(t, testCode, realVariant, tt.state)
			c, _ := startSyslog(t, g, newFakeClock(), nil)
			want := noticeTarget
			want.Level = tt.level
			before, _, err := c.SetSyslog(context.Background(), want)
			if err != nil {
				t.Fatal(err)
			}
			o := g.observed()
			save := "&syslog=on&location=192.168.1.71&port=514&level=" + tt.posted + "&Save=Save"
			var wantPosts []string
			if tt.state.on {
				wantPosts = []string{"nonce=" + nonceIn(t, before) + save}
			} else {
				wantPosts = []string{"nonce=" + nonceIn(t, before) + "&syslog=on&Update=Update", "nonce=" + nonceIn(t, o.served[1]) + save}
			}
			if !reflect.DeepEqual(o.posts, wantPosts) || o.badPosts != 0 {
				t.Errorf("posts = %q\nwant    %q (refused: %q)", o.posts, wantPosts, o.rejects)
			}
			if wantState := (syslogState{true, "192.168.1.71", "514", tt.posted}); o.state != wantState {
				t.Errorf("gateway state = %+v, want %+v", o.state, wantState)
			}
		})
	}
	// A setting already as wanted is not posted again; an empty level accepts any.
	g := newSyslogGateway(t, testCode, realVariant, realOn)
	c, _ := startSyslog(t, g, newFakeClock(), nil)
	for _, level := range []string{"Notice", "notice", ""} {
		want := noticeTarget
		want.Level = level
		if before, after, err := c.SetSyslog(context.Background(), want); err != nil || !bytes.Equal(before, after) {
			t.Errorf("level %q: err = %v, posted = %v", level, err, !bytes.Equal(before, after))
		}
	}
	if o := g.observed(); len(o.posts) != 0 {
		t.Errorf("posts = %q, want none", o.posts)
	}
}

// TestSetSyslogRealPageNotApplied: the gateway answers both rounds but does not save: the page
// read back decides, whichever way the Save was answered.
func TestSetSyslogRealPageNotApplied(t *testing.T) {
	for _, saveRedirect := range []bool{false, true} {
		g := newSyslogGateway(t, testCode, realVariant, realOff)
		g.ignoreSave, g.saveOK = true, !saveRedirect
		c, _ := startSyslog(t, g, newFakeClock(), nil)
		before, after, err := c.SetSyslog(context.Background(), noticeTarget)
		if !errors.Is(err, ErrNotApplied) {
			t.Fatalf("Save redirect %v: err = %v, want ErrNotApplied", saveRedirect, err)
		}
		for _, want := range []string{"Syslog reads off (wanted on)", `Server IP Address reads "" (wanted "192.168.1.71")`,
			`Log Level reads "Error" (wanted "Notice")`} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("err = %v, want it to say %q", err, want)
			}
		}
		o := g.observed()
		if len(o.posts) != 2 || !o.forms[0].Has("Update") || !o.forms[1].Has("Save") || o.badPosts != 0 || o.state != realOff {
			t.Errorf("posts = %q, refused = %q, state = %+v", o.posts, o.rejects, o.state)
		}
		if !bytes.Equal(before, o.served[0]) || !bytes.Equal(after, o.served[len(o.served)-1]) {
			t.Error("before/after evidence missing")
		}
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
	// An Update round that reached the gateway but is not followed by a Save: the page that shows
	// what the gateway did is returned with the error (after) - the gateway's answer, or, when the
	// answer does not say what the gateway did, the page one GET reads back.
	eventsPage := fixture(t, "events_checked.html")
	for name, tc := range map[string]struct {
		answer   func(w http.ResponseWriter)
		readBack bool
	}{
		"Update answered with an error": {func(w http.ResponseWriter) {
			http.Error(w, "internal error", http.StatusInternalServerError)
		}, true},
		"Update redirected elsewhere": {func(w http.ResponseWriter) {
			w.Header().Set("Location", "/cgi-bin/home.ha")
			w.WriteHeader(http.StatusFound)
		}, true},
		// A browser would post the form again after a 307: not the answer the round expects.
		"Update answered with a 307 to the page": {func(w http.ResponseWriter) {
			w.Header().Set("Location", "/cgi-bin/syslog.ha")
			w.WriteHeader(http.StatusTemporaryRedirect)
		}, true},
		"Update answered with a redirect without a target": {func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusFound)
		}, true},
		"Update answered with another page": {func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write(eventsPage)
		}, false},
	} {
		for _, v := range []struct {
			v    syslogVariant
			st   syslogState
			want model.SyslogTarget
		}{{checkboxVariant, checkboxOff, enableTarget}, {realVariant, realOff, noticeTarget}} {
			t.Run(name+" ("+v.v.off+")", func(t *testing.T) {
				g := newSyslogGateway(t, testCode, v.v, v.st)
				g.onPost = func(w http.ResponseWriter, form url.Values) bool {
					tc.answer(w)
					return true
				}
				c, _ := startSyslog(t, g, newFakeClock(), nil)
				before, after, err := c.SetSyslog(ctx, v.want)
				if err == nil || !strings.Contains(err.Error(), "Save not posted") || before == nil {
					t.Fatalf("err = %v", err)
				}
				o := g.observed()
				if len(o.posts) != 1 || !o.forms[0].Has("Update") || o.state != v.st {
					t.Errorf("posts=%q state=%+v, want only the Update POST", o.posts, o.state)
				}
				wantAfter, served := eventsPage, 1 // the gateway's answer
				if tc.readBack {
					served = 2 // the page read, and the page read back
				}
				if len(o.served) != served {
					t.Fatalf("served=%d, want %d", len(o.served), served)
				}
				if tc.readBack {
					wantAfter = o.served[1]
				}
				if !bytes.Equal(after, wantAfter) {
					t.Errorf("after = %.80q, want the %s", after, map[bool]string{false: "gateway's answer", true: "page read back"}[tc.readBack])
				}
			})
		}
	}
	// The gateway saves the switch at the Update already and answers with an error: the page read
	// back shows what it did (Syslog on, no server), and it is returned with the error.
	t.Run("Update saved at once but answered with an error", func(t *testing.T) {
		g := newSyslogGateway(t, testCode, realVariant, realOff)
		g.onPost = func(w http.ResponseWriter, form url.Values) bool {
			g.v.apply(&g.st, form)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return true
		}
		var logs syncBuffer
		c, _ := startSyslog(t, g, newFakeClock(), &logs)
		_, after, err := c.SetSyslog(ctx, noticeTarget)
		if err == nil || !strings.Contains(err.Error(), "POST syslog.ha (Update): the POST was answered with HTTP 500") ||
			!strings.Contains(err.Error(), "Save not posted") {
			t.Fatalf("err = %v", err)
		}
		o := g.observed()
		if len(o.posts) != 1 || len(o.served) != 2 || !bytes.Equal(after, o.served[1]) {
			t.Fatalf("posts=%q served=%d: want the Update POST and the page read back as after", o.posts, len(o.served))
		}
		if s, err := ParseSyslog(after); err != nil || !s.Enabled || s.Server != "" {
			t.Errorf("after: %+v %v; want the page showing Syslog on without a server", s, err)
		}
		if !strings.Contains(logs.String(), "reading the page back") {
			t.Error("the read-back is not in the log")
		}
	})
	// The page read back is the login page: the session expired. It is dropped (the next
	// authenticated request logs in again) and the error says so.
	t.Run("the page read back after the Update round is the login page", func(t *testing.T) {
		g := newSyslogGateway(t, testCode, realVariant, realOff)
		g.onPost = func(w http.ResponseWriter, form url.Values) bool {
			g.sessions = map[string]*mockSession{}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return true
		}
		clk := newFakeClock()
		c, _ := startSyslog(t, g, clk, nil)
		_, after, err := c.SetSyslog(ctx, noticeTarget)
		if !errors.Is(err, ErrLoginRequired) || !strings.Contains(err.Error(), "Save not posted") ||
			!strings.Contains(err.Error(), "the page could not be read back") || !scan(after).isLogin() {
			t.Fatalf("err = %v, after is a login page: %v", err, scan(after).isLogin())
		}
		if c.reusableSession() != nil {
			t.Error("the expired session was kept")
		}
		clk.Advance(loginSpacing + time.Second)
		if _, _, err := c.Syslog(ctx); err != nil {
			t.Fatal(err)
		}
		if o := g.observed(); o.logins != 2 {
			t.Errorf("logins = %d, want a second one", o.logins)
		}
	})
	t.Run("session expired at the Update round", func(t *testing.T) {
		g := newSyslogGateway(t, testCode, realVariant, realOff)
		g.onPost = func(w http.ResponseWriter, form url.Values) bool {
			g.sessions = map[string]*mockSession{}
			g.write(w, http.StatusOK, fixture(g.t, "login_handshake1.html"))
			return true
		}
		c, _ := startSyslog(t, g, newFakeClock(), nil)
		_, after, err := c.SetSyslog(ctx, noticeTarget)
		if !errors.Is(err, ErrLoginRequired) || !strings.Contains(err.Error(), "Save not posted") || after != nil {
			t.Fatalf("err = %v, want ErrLoginRequired and no Save", err)
		}
		if o := g.observed(); len(o.posts) != 1 || len(o.served) != 1 || o.state != realOff {
			t.Errorf("posts=%q served=%d state=%+v", o.posts, len(o.served), o.state)
		}
	})
}

// TestSyslogFakeGatewayRules: the fake gateway refuses what the real page's rules forbid - a
// POST carrying a control the page disables, a stale nonce, a value a list does not offer, a
// control the page does not have, no button - and applies none of it; so the tests that find
// no refused POST show that the client posts none of these.
func TestSyslogFakeGatewayRules(t *testing.T) {
	g := newSyslogGateway(t, testCode, realVariant, realOff)
	c, _ := startSyslog(t, g, newFakeClock(), nil)
	ctx := context.Background()
	if _, _, err := c.Syslog(ctx); err != nil {
		t.Fatal(err)
	}
	s := c.reusableSession()
	if s == nil {
		t.Fatal("no session")
	}
	read := func() []byte { // GET syslog.ha in the session: a fresh nonce
		t.Helper()
		page, err := c.getPage(ctx, s, syslogPage)
		if err != nil {
			t.Fatal(err)
		}
		return page
	}
	post := func(body string) {
		t.Helper()
		if _, problem, err := c.postForm(ctx, s, syslogPage, body); err != nil || problem != "" {
			t.Fatalf("POST %q: %v %s", body, err, problem)
		}
	}
	stale := nonceIn(t, read())
	for _, tt := range []struct {
		body   func(nonce string) string
		reason string
	}{
		{func(n string) string { return "nonce=" + n + "&syslog=on&location=192.168.1.71&Update=Update" }, "posts location, which the page disables"},
		{func(n string) string { return "nonce=" + n + "&syslog=on&level=Notice&Update=Update" }, "posts level, which the page disables"},
		{func(string) string { return "nonce=" + stale + "&syslog=on&Update=Update" }, "stale or missing nonce"},
		{func(n string) string { return "nonce=" + n + "&syslog=yes&Update=Update" }, `posts syslog="yes", which the list does not offer`},
		{func(n string) string { return "nonce=" + n + "&syslog=on&debug=1&Update=Update" }, "posts debug, which the page does not have"},
		{func(n string) string { return "nonce=" + n + "&syslog=on" }, "posts 0 buttons"},
		{func(n string) string { return "nonce=" + n + "&syslog=on&Update=Update&Save=Save" }, "posts 2 buttons"},
	} {
		body := tt.body(nonceIn(t, read()))
		post(body)
		if o := g.observed(); len(o.rejects) == 0 || o.rejects[len(o.rejects)-1] != tt.reason || o.state != realOff {
			t.Errorf("%q: refused %q, state %+v; want refused for %q", body, o.rejects, o.state, tt.reason)
		}
	}
	// What a browser without JavaScript posts is accepted: the Update round, then the Save on
	// the page it answers with.
	post("nonce=" + nonceIn(t, read()) + "&syslog=on&Update=Update")
	o := g.observed()
	post("nonce=" + nonceIn(t, o.served[len(o.served)-1]) + "&syslog=on&location=192.168.1.71&port=514&level=Notice&Save=Save")
	if o := g.observed(); o.badPosts != 7 || o.state != realOn {
		t.Errorf("refused %d (%q), state %+v; want 7 refused and the setting saved", o.badPosts, o.rejects, o.state)
	}
}

// TestSetSyslogFailsClosed: a page that is not fully understood is never posted; when only the
// page an Update round answered with is not, no Save is posted.
func TestSetSyslogFailsClosed(t *testing.T) {
	type tc struct {
		name    string
		variant syslogVariant // default: the select variant, off
		state   syslogState
		setup   func(t *testing.T, g *syslogGateway)
		off     bool                // switch Syslog off
		target  *model.SyslogTarget // else: noticeTarget for the real page, enableTarget for the others
		posts   int                 // Update round POSTs expected before the refusal
		msg     string              // part of the error
	}
	sel := func(pattern, repl string) func(t *testing.T, g *syslogGateway) {
		return func(t *testing.T, g *syslogGateway) { g.edit = pageEdit(t, "syslog_select.html", pattern, repl) }
	}
	cb := func(pattern, repl string) func(t *testing.T, g *syslogGateway) {
		return func(t *testing.T, g *syslogGateway) { g.edit = pageEdit(t, "syslog_checkbox_off.html", pattern, repl) }
	}
	// Edits of every page served, and of the page the Update button answers with, for the real page.
	realEdit := func(pattern, repl string) func(t *testing.T, g *syslogGateway) {
		return func(t *testing.T, g *syslogGateway) { g.edit = pageEdit(t, "syslog_real_off.html", pattern, repl) }
	}
	realUpdateEdit := func(pattern, repl string) func(t *testing.T, g *syslogGateway) {
		return func(t *testing.T, g *syslogGateway) {
			g.editUpdate = pageEdit(t, "syslog_real_on_update.html", pattern, repl)
		}
	}
	updateIgnored := func(redirect bool) func(t *testing.T, g *syslogGateway) {
		return func(t *testing.T, g *syslogGateway) { g.updateIgnored, g.updateRedirect = true, redirect }
	}
	selectOn := syslogState{true, "192.168.1.64", "514", "6"}
	realOnElsewhere := syslogState{true, "192.168.1.64", "514", "Notice"}
	debugTarget := noticeTarget
	debugTarget.Level = "Debug"
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

		// The real page: what can be checked on the page first read is checked before the
		// Update round, although its fields are disabled.
		{name: "real page: level not an option", variant: realVariant, state: realOff, target: &enableTarget,
			msg: `"Log Level" has no option "Informational" (it offers "Emergency", "Alert", "Critical", "Error", "Warning", "Notice")`},
		{name: "real page: level Debug", variant: realVariant, state: realOff, target: &debugTarget, msg: `has no option "Debug"`},
		{name: "real page: level not an option while on", variant: realVariant, state: realOnElsewhere, target: &enableTarget,
			msg: `has no option "Informational"`},
		{name: "real page: level option disabled", variant: realVariant, state: realOff,
			setup: realEdit(`<option value="Notice"`, `<option value="Notice" disabled="disabled"`), msg: `has no option "Notice"`},
		{name: "real page: no Update button", variant: realVariant, state: realOff,
			setup: realEdit(`(?s)<noscript>\s*<input type="submit" name="Update"[^>]*/>\s*</noscript>`, ``),
			msg:   `the "Server IP Address" input is disabled`},
		{name: "real page: two different Update buttons", variant: realVariant, state: realOff,
			setup: realEdit(`(<input type="submit" name="Update"[^>]*/>)`, `${1}<input type="submit" name="Update" value="Refresh" />`),
			msg:   "2 different Update buttons"},
		{name: "real page: Update button posts elsewhere", variant: realVariant, state: realOff,
			setup: realEdit(`name="Update" class`, `name="Update" formaction="/cgi-bin/other.ha" class`), msg: "not syslog.ha"},
		{name: "real page: no Save button", variant: realVariant, state: realOff,
			setup: realEdit(`<input type="submit" name="Save"[^>]*/>`, ``), msg: "no Save button"},
		{name: "real page: Save button posts elsewhere", variant: realVariant, state: realOff,
			setup: realEdit(`name="Save" class`, `name="Save" formaction="/cgi-bin/other.ha" class`), msg: "not syslog.ha"},
		{name: "real page: no nonce", variant: realVariant, state: realOff,
			setup: realEdit(`<input type="hidden" name="nonce" value="[0-9a-f]+" />`, ``), msg: "no nonce"},
		{name: "real page: server address too long for the field", variant: realVariant, state: realOff,
			setup: realEdit(`maxlength="43"`, `maxlength="7"`), msg: `"Server IP Address" input takes at most 7 characters`},
		{name: "real page: port too long for the field", variant: realVariant, state: realOff,
			setup: realEdit(`maxlength="5"`, `maxlength="2"`), msg: `"Server Port" input takes at most 2 characters`},
		{name: "real page: switch has no option for on", variant: realVariant, state: realOff,
			setup: realEdit(`<option value="on"\s*>On</option>`, ``), msg: "0 options for on"},
		{name: "real page: switch disabled", variant: realVariant, state: realOff,
			setup: realEdit(`name="syslog" id="syslog"`, `name="syslog" id="syslog" disabled="disabled"`), msg: `the "Syslog" list is disabled`},
		{name: "real page: another control holds characters outside ASCII", variant: realVariant, state: realOff,
			setup: realEdit(`(<input type="hidden" name="nonce")`, `<input type="hidden" name="x" value="caf&#233;" />${1}`), msg: "outside ASCII"},

		// The real page: the page the Update round answers with must be the page transformed -
		// the switch On and the three fields enabled - or no Save is posted.
		{name: "real page: the Update round changes nothing", variant: realVariant, state: realOff,
			setup: updateIgnored(false), posts: 1, msg: "Syslog reads off (wanted on) after the Update round"},
		{name: "real page: the Update round redirects to the page unchanged", variant: realVariant, state: realOff,
			setup: updateIgnored(true), posts: 1, msg: "Syslog reads off (wanted on) after the Update round"},
		{name: "real page: switching off, the Update round changes nothing", variant: realVariant, state: realOn, off: true,
			setup: updateIgnored(false), posts: 1, msg: "Syslog reads on (wanted off) after the Update round"},
		{name: "real page: the Update round leaves the address disabled", variant: realVariant, state: realOff,
			setup: realUpdateEdit(`name="location" value=""`, `name="location" value="" disabled="disabled"`),
			posts: 1, msg: `"Server IP Address" is still disabled after the Update round`},
		{name: "real page: the Update round leaves the port disabled", variant: realVariant, state: realOff,
			setup: realUpdateEdit(`name="port" value="514"`, `name="port" value="514" disabled="disabled"`),
			posts: 1, msg: `"Server Port" is still disabled after the Update round`},
		{name: "real page: the Update round leaves the level disabled", variant: realVariant, state: realOff,
			setup: realUpdateEdit(`id="loglevel"`, `id="loglevel" disabled="disabled"`),
			posts: 1, msg: `"Log Level" is still disabled after the Update round`},
		{name: "real page: the Update round makes the address read-only", variant: realVariant, state: realOff,
			setup: realUpdateEdit(`name="location"`, `name="location" readonly="readonly"`), posts: 1, msg: "read-only"},
		{name: "real page: the Update round offers no Notice", variant: realVariant, state: realOff,
			setup: realUpdateEdit(`<option value="Notice"\s*>Notice</option>`, ``), posts: 1, msg: `"Log Level" has no option "Notice"`},
		{name: "real page: the Update round answers without a nonce", variant: realVariant, state: realOff,
			setup: realUpdateEdit(`<input type="hidden" name="nonce" value="[0-9a-f]+" />`, ``), posts: 1, msg: "no nonce"},
		{name: "real page: the Update round answers without a Save button", variant: realVariant, state: realOff,
			setup: realUpdateEdit(`<input type="submit" name="Save"[^>]*/>`, ``), posts: 1, msg: "no Save button"},
		{name: "real page: the Update round answers with a second switch", variant: realVariant, state: realOff,
			setup: realUpdateEdit(`(<input type="hidden" name="nonce")`, `<label>Syslog <input type="checkbox" name="x" /></label>${1}`),
			posts: 1, msg: "more than one control is labelled"},
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
			switch {
			case tt.off:
				want = model.SyslogTarget{}
			case tt.target != nil:
				want = *tt.target
			case tt.variant == realVariant:
				want = noticeTarget
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
				if f.Has("Save") || !f.Has("Update") {
					t.Errorf("a POST other than the Update round: %v", f)
				}
			}
			if o.badPosts != 0 {
				t.Errorf("the gateway refused a POST: %q", o.rejects)
			}
			if len(before) == 0 || !bytes.Equal(before, o.served[0]) {
				t.Errorf("before = %d bytes: want the page read", len(before))
			}
			// Once the Update round was posted, the page the gateway answered it with is
			// returned (after): the evidence of what it did, and the page the Save was refused on.
			switch {
			case tt.posts == 0 && after != nil:
				t.Errorf("after = %d bytes, want none: nothing was posted", len(after))
			case tt.posts > 0 && (len(o.served) != 2 || !bytes.Equal(after, o.served[1])):
				t.Errorf("after = %d bytes (%d pages served), want the page the Update round answered with", len(after), len(o.served))
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
		code   string
		v      syslogVariant
		st     syslogState
		target model.SyslogTarget
		setup  func(g *syslogGateway)
	}{
		{testCode, selectVariant, selectOff, enableTarget, nil},
		{testCode, checkboxVariant, checkboxOff, enableTarget, nil},
		{testCode, realVariant, realOff, noticeTarget, nil},
		{testCode, realVariant, realOff, noticeTarget, func(g *syslogGateway) { g.updateIgnored = true }},
		{testCode + "x", selectVariant, selectOff, enableTarget, nil},
		{testCode, selectVariant, selectOff, enableTarget, func(g *syslogGateway) { g.sessionsFull = true }},
		{testCode, radioVariant, radioOff, enableTarget, func(g *syslogGateway) { g.ignoreSave = true }},
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
			want := sc.target
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
