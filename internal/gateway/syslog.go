package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"attmonitor/internal/model"
)

// The Syslog page (Diagnostics > Syslog, /cgi-bin/syslog.ha; docs/syslog-snmp-traffic.md
// §3.1) needs the login. It is read by the labels of its controls, never by their names:
// "Syslog" (on/off), "Server IP Address", "Server Port" and "Log Level". Labels are compared
// by alnumKey: case, white space and punctuation such as a trailing ":" do not matter.
//
// On the BGW320-505 with firmware 6.34.7 (testdata/gateway/syslog_real_off.html) the switch is
// a drop-down list Off/On that submits the form when it changes, followed by a noscript Update
// button for a browser without JavaScript, and while Syslog is off the three fields are shown
// but disabled - a browser never submits a disabled control. The page says what to do: "When
// you change an item that has an Update button to the right of it, make your change, then
// click the Update button. This will transform the page according to the change you have made
// and you may then proceed." So the switch is changed with the Update button first (the Update
// round), and the Save follows on the page the gateway answers with, which enables the fields
// once Syslog is on.

const syslogPage = "syslog"

// Labels of the Syslog page's controls.
const (
	syslogSwitchLabel = "Syslog"
	syslogServerLabel = "Server IP Address"
	syslogPortLabel   = "Server Port"
	syslogLevelLabel  = "Log Level"
)

// ErrSyslogPage means the Syslog page is not understood: a control is missing, ambiguous or
// of an unexpected kind - or, for SetSyslog, the form cannot be posted back exactly as the
// page itself would post it, in which case nothing is posted. The error says what.
var ErrSyslogPage = errors.New("gateway: Syslog page not understood")

func syslogPageError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrSyslogPage, fmt.Sprintf(format, args...))
}

// ---------------------------------------------------------------- reading the page

// syslogForm is the Syslog page's form as read by its labels.
type syslogForm struct {
	form    *pageForm
	sw      formField    // the "Syslog" switch: a checkbox, a drop-down list or radio buttons
	server  *formControl // nil (like port and level) while the page leaves the fields out
	port    *formControl
	level   formField // a drop-down list or radio buttons (a text input is read too)
	setting model.SyslogSetting
}

// shown reports whether the page shows the server fields (it may leave them out while Syslog
// is off). Fields that are shown may still be disabled.
func (sf *syslogForm) shown() bool { return sf.server != nil }

// ParseSyslog parses the Syslog page (syslog.ha) by its labels. Enabled comes from the
// "Syslog" switch: a checked checkbox, or a drop-down list or radio buttons whose selected
// option's text or value is on, enable, enabled, yes, 1 or true (any other option is off).
// Server and Port are the "Server IP Address" and "Server Port" fields (Port 0 when empty),
// Level the text of the selected "Log Level" option and Levels the texts of all its options
// in page order. While Syslog is off the page may leave the three fields out, or show them
// disabled (firmware 6.34.7), in which case they are read as shown. A missing, ambiguous or
// unexpected control is an error wrapping ErrSyslogPage that names it; the login page is
// ErrLoginRequired.
func ParseSyslog(body []byte) (model.SyslogSetting, error) {
	sf, err := parseSyslogPage(body)
	if err != nil {
		return model.SyslogSetting{}, err
	}
	return sf.setting, nil
}

func parseSyslogPage(body []byte) (*syslogForm, error) {
	if scan(body).isLogin() {
		return nil, fmt.Errorf("syslog: %w", ErrLoginRequired)
	}
	return readSyslogForm(parseForms(body))
}

func readSyslogForm(forms []*pageForm) (*syslogForm, error) {
	var sf *syslogForm
	for _, f := range forms {
		switch sws := f.fields(syslogSwitchLabel); {
		case len(sws) == 0:
		case len(sws) > 1 || sf != nil:
			return nil, syslogPageError("more than one control is labelled %q", syslogSwitchLabel)
		default:
			sf = &syslogForm{form: f, sw: sws[0]}
		}
	}
	if sf == nil {
		return nil, syslogPageError("no control labelled %q", syslogSwitchLabel)
	}
	on, err := switchState(sf.sw)
	if err != nil {
		return nil, err
	}
	sf.setting.Enabled = on

	server, hasServer, err := oneField(sf.form, syslogServerLabel)
	if err != nil {
		return nil, err
	}
	port, hasPort, err := oneField(sf.form, syslogPortLabel)
	if err != nil {
		return nil, err
	}
	level, hasLevel, err := oneField(sf.form, syslogLevelLabel)
	if err != nil {
		return nil, err
	}
	switch {
	case hasServer && hasPort && hasLevel:
	case !hasServer && !hasPort && !hasLevel && !on:
		return sf, nil // the page shows the fields once Syslog is on
	case !hasServer && !hasPort && !hasLevel:
		return nil, syslogPageError("Syslog is on but the page shows no %q, %q or %q",
			syslogServerLabel, syslogPortLabel, syslogLevelLabel)
	default:
		var missing []string
		for _, m := range []struct {
			label string
			has   bool
		}{{syslogServerLabel, hasServer}, {syslogPortLabel, hasPort}, {syslogLevelLabel, hasLevel}} {
			if !m.has {
				missing = append(missing, strconv.Quote(m.label))
			}
		}
		return nil, syslogPageError("no control labelled %s", strings.Join(missing, " or "))
	}

	if sf.server, err = textInput(server, syslogServerLabel, "text", "search", "tel", "url", "email"); err != nil {
		return nil, err
	}
	if sf.port, err = textInput(port, syslogPortLabel, "text", "search", "tel", "number"); err != nil {
		return nil, err
	}
	sf.level = level
	sf.setting.Server = strings.TrimSpace(sf.server.value)
	if sf.setting.Port, err = parsePort(sf.port.value); err != nil {
		return nil, err
	}
	if sf.setting.Level, sf.setting.Levels, err = levelSetting(level); err != nil {
		return nil, err
	}
	return sf, nil
}

// oneField returns the field of f labelled label, if any; several are an error.
func oneField(f *pageForm, label string) (formField, bool, error) {
	switch fds := f.fields(label); len(fds) {
	case 0:
		return formField{}, false, nil
	case 1:
		return fds[0], true, nil
	default:
		return formField{}, false, syslogPageError("%d controls are labelled %q", len(fds), label)
	}
}

// textInput returns the field's control when it is an input of one of types.
func textInput(fd formField, label string, types ...string) (*formControl, error) {
	if c := fd.controls[0]; !fd.isRadioGroup() && c.tag == "input" && slices.Contains(types, c.typ) {
		return c, nil
	}
	return nil, syslogPageError("the %q control is a %s", label, fd.kind())
}

// parsePort reads "Server Port": 0 when empty, else a number from 0 to 65535.
func parsePort(v string) (int, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > 65535 {
		return 0, syslogPageError("%q reads %q, which is not a port number", syslogPortLabel, v)
	}
	return n, nil
}

// levelSetting reads "Log Level": the selected option's text and the texts of all options (a
// text input is read as its value).
func levelSetting(fd formField) (level string, levels []string, err error) {
	if chs := fd.choices(); chs != nil {
		for _, ch := range chs {
			levels = append(levels, ch.display())
			if ch.selected {
				level = ch.display()
			}
		}
		return level, levels, nil
	}
	c := fd.controls[0]
	if c.tag == "input" && slices.Contains([]string{"text", "search", "tel", "number"}, c.typ) {
		return strings.TrimSpace(c.value), nil, nil
	}
	return "", nil, syslogPageError("the %q control is a %s", syslogLevelLabel, fd.kind())
}

// switchWords are the texts and values that name the two states of an on/off control.
var switchWords = map[string]bool{
	"on": true, "enable": true, "enabled": true, "yes": true, "1": true, "true": true,
	"off": false, "disable": false, "disabled": false, "no": false, "0": false, "false": false,
}

// switchMeaning tells what a choice of an on/off switch stands for, from its text and its
// value: known is false when neither is an on/off word, conflict is true when the two say
// different things. The value only counts when the page writes it (a radio button without a
// value attribute submits "on" whatever it stands for).
func switchMeaning(ch choice) (on, known, conflict bool) {
	t, tk := switchWords[strings.ToLower(normSpace(ch.text))]
	v, vk := false, false
	if ch.explicit {
		v, vk = switchWords[strings.ToLower(normSpace(ch.value))]
	}
	switch {
	case tk && vk && t != v:
		return false, true, true
	case tk:
		return t, true, false
	case vk:
		return v, true, false
	}
	return false, false, false
}

// switchState reads the "Syslog" switch.
func switchState(fd formField) (bool, error) {
	if c := fd.controls[0]; !fd.isRadioGroup() && c.tag == "input" && c.typ == "checkbox" {
		return c.checked, nil
	}
	chs := fd.choices()
	if chs == nil {
		return false, syslogPageError("the %q control is a %s, not an on/off switch", syslogSwitchLabel, fd.kind())
	}
	for _, ch := range chs {
		if !ch.selected {
			continue
		}
		on, _, conflict := switchMeaning(ch)
		if conflict {
			return false, syslogPageError("the selected %q option %q (value %q) says both on and off",
				syslogSwitchLabel, ch.text, ch.value)
		}
		return on, nil
	}
	return false, syslogPageError("no %q option is selected", syslogSwitchLabel)
}

// ---------------------------------------------------------------- Client

// Syslog reads the gateway's Syslog page (see ParseSyslog). It needs authentication, so it
// goes through the login policy (see the error variables) and shares the session with the
// other authenticated operations; it only reads. raw is the exact syslog.ha body that was
// read, also returned with a parse error.
func (c *Client) Syslog(ctx context.Context) (model.SyslogSetting, []byte, error) {
	if err := c.acquire(ctx); err != nil {
		return model.SyslogSetting{}, nil, err
	}
	defer c.release()
	_, body, err := c.authPage(ctx, syslogPage)
	if err != nil {
		return model.SyslogSetting{}, nil, err
	}
	sf, err := parseSyslogPage(body)
	if err != nil {
		return model.SyslogSetting{}, body, err
	}
	return sf.setting, body, nil
}

// SetSyslog sets the gateway's Syslog page to want the way a person does it in a browser
// without JavaScript. It reads syslog.ha (authenticated) and changes only the syslog controls:
// the "Syslog" switch, and when enabling the server address, the port and (when want.Level is
// set) the log level, matched to an option by text or value.
//
// When the switch changes and the page has an Update button, the form is first posted with the
// switch changed and that button (the Update round; see the top of this file): the gateway
// answers with the page transformed - a 200 page, or a redirect to syslog.ha whose page is
// then read - which must show the switch changed and, when enabling, the three fields shown and
// enabled. The form is then posted with the Save button, from the page last read: every other
// control as that page has it (disabled ones are never posted), with that page's nonce. When
// switching off, the server, port and level are thus posted as the page has them, if it
// enables them. Pages without an Update button are saved in one round.
//
// It then reads the page again, however the gateway answered the Save: the error is nil only
// when that page shows want (ErrNotApplied otherwise, saying what differs). before and after
// are the exact bodies of the first and the last read; after only once a POST may have reached
// the gateway, and then also with an error: the page read back after the Save (the read-back
// follows the rules of SetNotification), or else, after an Update round, the page the gateway
// answered the Update with - or the page read back when that answer does not say what the
// gateway did (see syslogUpdateRound). When the page already shows want nothing is posted and
// after is the same body as before.
//
// It fails closed: nothing is posted (and after an Update round, no Save) when the page is not
// fully understood (ErrSyslogPage) - a control missing or ambiguous (also after the Update
// round), a level that is not one of the options, a value the field cannot take, a control
// that must change but is disabled or read-only (no control is ever enabled by hand), a form
// that does not post to syslog.ha the way this client encodes it, a form without a nonce or a
// Save button, several different Update buttons, an Update round that does not lead to the
// transformed page - and no request is made when want itself is invalid (enabling needs an
// IPv4 server address and a port from 1 to 65535). What can be checked on the page first read
// is checked before the Update round.
func (c *Client) SetSyslog(ctx context.Context, want model.SyslogTarget) (before, after []byte, err error) {
	server, err := checkSyslogTarget(want)
	if err != nil {
		return nil, nil, err
	}
	if err := c.acquire(ctx); err != nil {
		return nil, nil, err
	}
	defer c.release()
	s, before, err := c.authPage(ctx, syslogPage)
	if err != nil {
		return nil, nil, err
	}
	sf, err := parseSyslogPage(before)
	if err != nil {
		return before, nil, fmt.Errorf("%w; nothing posted", err)
	}
	if syslogDiff(sf, want) == "" {
		c.log.Info("gateway syslog setting already as requested; nothing posted", "enabled", want.Enabled)
		return before, before, nil
	}
	upd, err := c.syslogPlan(sf, want, server)
	if err != nil {
		return before, nil, fmt.Errorf("%w: %v; nothing posted", ErrSyslogPage, err)
	}
	notPosted := "nothing posted"
	if upd != nil {
		// The Update POST may reach the gateway: from here on the page it showed last is the
		// evidence of what it did, returned with any error (after).
		if sf, after, err = c.syslogUpdateRound(ctx, s, sf, upd, want.Enabled); err != nil {
			return before, after, err
		}
		notPosted = "Save not posted"
	}
	body, level, err := c.syslogSaveBody(sf, want, server)
	if err != nil {
		return before, after, fmt.Errorf("%w: %v; %s", ErrSyslogPage, err, notPosted)
	}
	ex, problem, err := c.postForm(ctx, s, syslogPage, body)
	if err != nil {
		return before, after, err
	}
	if problem == "" {
		c.log.Info("gateway syslog setting posted", "enabled", want.Enabled, "server", server, "port", want.Port,
			"level", level, "status", ex.status, "location", ex.location)
	} else {
		c.log.Warn("gateway syslog POST outcome unknown; reading the setting back", "enabled", want.Enabled, "detail", problem)
	}
	after, err = c.readBack(ctx, s, syslogPage, problem)
	if err != nil {
		return before, after, err
	}
	got, err := parseSyslogPage(after)
	if err != nil {
		if errors.Is(err, ErrLoginRequired) {
			c.dropSession()
		}
		return before, after, fmt.Errorf("%w (page read back after saving)", err)
	}
	c.touch(s)
	if diff := syslogDiff(got, want); diff != "" {
		detail := ""
		if problem != "" {
			detail = " (" + problem + ")"
		}
		return before, after, fmt.Errorf("%w: %s after saving%s", ErrNotApplied, diff, detail)
	}
	if problem != "" {
		c.log.Warn("gateway syslog setting verified by reading it back", "enabled", want.Enabled, "detail", problem)
	}
	return before, after, nil
}

// checkSyslogTarget checks want before anything is sent and returns the server address in its
// canonical form ("" when switching off, which ignores the other fields).
func checkSyslogTarget(want model.SyslogTarget) (string, error) {
	if !want.Enabled {
		return "", nil
	}
	a, err := netip.ParseAddr(want.Server)
	if err != nil || !a.Is4() || a.IsUnspecified() {
		return "", fmt.Errorf("gateway: syslog server %q is not an IPv4 address", want.Server)
	}
	if want.Port < 1 || want.Port > 65535 {
		return "", fmt.Errorf("gateway: syslog port %d is not a port number (1-65535)", want.Port)
	}
	return a.String(), nil
}

// syslogDiff says how the page's setting differs from want ("" when it shows want): the
// switch, and when want.Enabled the server address, the port and, when want.Level is set, the
// selected level (matched by text or value).
func syslogDiff(sf *syslogForm, want model.SyslogTarget) string {
	got := sf.setting
	var d []string
	if got.Enabled != want.Enabled {
		d = append(d, fmt.Sprintf("Syslog reads %s (wanted %s)", onOff(got.Enabled), onOff(want.Enabled)))
	}
	if want.Enabled {
		if !sameAddr(got.Server, want.Server) {
			d = append(d, fmt.Sprintf("%s reads %q (wanted %q)", syslogServerLabel, got.Server, want.Server))
		}
		if got.Port != want.Port {
			d = append(d, fmt.Sprintf("%s reads %d (wanted %d)", syslogPortLabel, got.Port, want.Port))
		}
		if want.Level != "" && !sf.levelIs(want.Level) {
			d = append(d, fmt.Sprintf("%s reads %q (wanted %q)", syslogLevelLabel, got.Level, want.Level))
		}
	}
	return strings.Join(d, "; ")
}

// sameAddr compares two server addresses as text, or as IP addresses when both are.
func sameAddr(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if strings.EqualFold(a, b) {
		return true
	}
	x, errX := netip.ParseAddr(a)
	y, errY := netip.ParseAddr(b)
	return errX == nil && errY == nil && x == y
}

// levelIs reports whether the selected level matches want by text or value.
func (sf *syslogForm) levelIs(want string) bool {
	if !sf.shown() {
		return false
	}
	if chs := sf.level.choices(); chs != nil {
		for _, ch := range chs {
			if ch.selected {
				return levelMatches(ch, want)
			}
		}
		return false
	}
	return strings.EqualFold(normSpace(sf.setting.Level), normSpace(want))
}

func levelMatches(ch choice, want string) bool {
	w := normSpace(want)
	return w != "" && (strings.EqualFold(normSpace(ch.text), w) || strings.EqualFold(normSpace(ch.value), w))
}

// ---------------------------------------------------------------- posting the form

// syslogPlan checks sf's form, before anything is posted, for everything that can be checked
// on this page for setting want - a Save button posting to syslog.ha, the nonce, a switch that
// can be set, and when the page shows the fields (enabled or not), values that fit them and a
// level the list offers - and returns the Update button when an Update round must come first:
// when the switch changes and the page has an Update button. It changes nothing.
func (c *Client) syslogPlan(sf *syslogForm, want model.SyslogTarget, server string) (update *formControl, err error) {
	f := sf.form
	save, err := saveButton(f)
	if err != nil {
		return nil, err
	}
	if err := c.postable(f, save); err != nil {
		return nil, err
	}
	if _, err := switchSetter(sf.sw, want.Enabled); err != nil {
		return nil, err
	}
	if want.Enabled && sf.shown() {
		if err := fits(sf.server, syslogServerLabel, server); err != nil {
			return nil, err
		}
		if err := fits(sf.port, syslogPortLabel, strconv.Itoa(want.Port)); err != nil {
			return nil, err
		}
		if want.Level != "" {
			// While Syslog is off the page may disable the whole list: what it offers counts.
			if _, err := levelChoice(sf.level, want.Level, true); err != nil {
				return nil, err
			}
		}
	}
	if sf.setting.Enabled == want.Enabled {
		return nil, nil // the switch stays as it is: the fields are changed and saved
	}
	upd, n := f.submitButton(isUpdateButton)
	switch {
	case n > 1:
		return nil, fmt.Errorf("the form has %d different Update buttons", n)
	case n == 1:
		if err := c.postable(f, upd); err != nil {
			return nil, err
		}
		return upd, nil
	case want.Enabled && !sf.shown():
		return nil, fmt.Errorf("the page shows no %q, %q or %q while Syslog is off, and has no Update button",
			syslogServerLabel, syslogPortLabel, syslogLevelLabel)
	}
	return nil, nil // no Update button: the switch is changed and saved in one round
}

// isUpdateButton reports whether the submit button b is an Update button: named or showing
// "Update".
func isUpdateButton(b *formControl) bool {
	return strings.EqualFold(b.name, "Update") || strings.EqualFold(strings.TrimSpace(b.value), "Update")
}

// syslogUpdateRound posts sf's form with the "Syslog" switch set to on and the Update button
// upd (syslogPlan checked both), as the page asks a browser without JavaScript to do, and
// returns the page the gateway answers with: a 200 page, or after a redirect (301, 302 or 303)
// to syslog.ha the page a GET of it returns. By the page's own words the Update button
// transforms the page and only the Save that follows saves, so the answer must be that page
// transformed: the switch set to on and, when on, the three fields shown and enabled (see
// transformed). Anything else ends SetSyslog before the Save.
//
// page is the last page read once the POST may have reached the gateway, returned with the
// error too: whether the gateway saves at the Update has not been observed, so it is the
// evidence of what the gateway did. It is the page the gateway answered with - also one that
// is not understood or not transformed - or, when the answer does not say what the gateway did
// (no answer, an error status, a redirect elsewhere or one a browser would follow with the POST
// again, a body that could not be read whole), the page one GET of syslog.ha then reads back
// (postForm's rule: the outcome is unknown, so the page is read back; nil without an answer).
// page is nil when the POST cannot have reached the gateway, when the session turned out to
// have expired, when the gateway's session pool is full and when the GET that a redirect to
// syslog.ha asks for brings no page.
func (c *Client) syslogUpdateRound(ctx context.Context, s *authSession, sf *syslogForm, upd *formControl, on bool) (next *syslogForm, page []byte, err error) {
	if err := setSwitch(sf.sw, on); err != nil {
		return nil, nil, fmt.Errorf("%w: %v; nothing posted", ErrSyslogPage, err)
	}
	body, err := sf.form.encode(upd)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v; nothing posted", ErrSyslogPage, err)
	}
	ex, problem, err := c.postForm(ctx, s, syslogPage, body)
	if err != nil {
		return nil, nil, fmt.Errorf("%w (the Update round; Save not posted)", err)
	}
	var unknown error // the answer does not say what the gateway did: the page is read back
	switch loc := strings.TrimSpace(ex.location); {
	case problem != "":
		unknown = fmt.Errorf("gateway: POST syslog.ha (Update): %s; Save not posted", problem)
	case ex.status == http.StatusOK && ex.err != nil:
		unknown = fmt.Errorf("gateway: POST syslog.ha (Update): %w; Save not posted", ex.err)
	case ex.status == http.StatusOK:
		page = ex.body
	case loc != "" && !c.refersTo(loc, syslogPage): // postForm accepts 200 and 3xx answers
		unknown = fmt.Errorf("gateway: POST syslog.ha (Update) redirected to %q; Save not posted", ex.location)
	case loc == "" || !getsAfterPost(ex.status):
		// No redirect a browser would follow with a GET (a 307 or 308 would post the form
		// again): not the answer this round expects.
		unknown = fmt.Errorf("gateway: POST syslog.ha (Update) answered with HTTP %s; Save not posted", statusText(ex.status))
	default:
		if page, err = c.getPage(ctx, s, syslogPage); err != nil {
			return nil, nil, fmt.Errorf("%w (after the Update round; Save not posted)", err)
		}
	}
	if unknown != nil {
		c.log.Warn("gateway syslog Update round answered unexpectedly; reading the page back", "enabled", on, "detail", unknown)
		back, rerr := c.syslogReadBack(ctx, s)
		if rerr != nil {
			unknown = fmt.Errorf("%w; the page could not be read back: %w", unknown, rerr)
		}
		return nil, back, unknown
	}
	next, err = parseSyslogPage(page) // a login page was caught by postForm or getPage
	if err != nil {
		return nil, page, fmt.Errorf("%w (after the Update round; Save not posted)", err)
	}
	if err := next.transformed(on); err != nil {
		return nil, page, fmt.Errorf("%w: %v after the Update round; Save not posted", ErrSyslogPage, err)
	}
	c.log.Info("gateway syslog page transformed by its Update button", "enabled", on, "status", ex.status, "location", ex.location)
	return next, page, nil
}

// syslogReadBack reads syslog.ha once more in session s after an Update round whose answer does
// not say what the gateway did, and returns the page the gateway answered with (nil without an
// answer; see readBack). A login page in its place means that the session expired: it is
// dropped, and the error says so.
func (c *Client) syslogReadBack(ctx context.Context, s *authSession) ([]byte, error) {
	page, err := c.readBack(ctx, s, syslogPage, "")
	if err == nil && scan(page).isLogin() {
		c.dropSession()
		err = fmt.Errorf("gateway: verifying GET syslog.ha: %w (session expired)", ErrLoginRequired)
	}
	return page, err
}

// getsAfterPost reports whether a browser follows a redirect with this status after a POST
// by getting the new location (it posts the form again after a 307 or 308).
func getsAfterPost(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther:
		return true
	}
	return false
}

// transformed checks the page an Update round answered with, the round having set the switch
// to on: the page must show the switch so and, when on, the three fields, enabled - the page
// enables them once Syslog is on. When switching off the fields do not matter: the Save posts
// them as the page has them, if it enables them.
func (sf *syslogForm) transformed(on bool) error {
	if on && !sf.shown() {
		return fmt.Errorf("the page still shows no %q, %q or %q", syslogServerLabel, syslogPortLabel, syslogLevelLabel)
	}
	if sf.setting.Enabled != on {
		return fmt.Errorf("Syslog reads %s (wanted %s)", onOff(sf.setting.Enabled), onOff(on))
	}
	if !on {
		return nil
	}
	for _, fd := range []struct {
		label string
		field formField
	}{
		{syslogServerLabel, formField{controls: []*formControl{sf.server}}},
		{syslogPortLabel, formField{controls: []*formControl{sf.port}}},
		{syslogLevelLabel, sf.level},
	} {
		if fd.field.disabled() {
			return fmt.Errorf("%q is still disabled", fd.label)
		}
	}
	return nil
}

// syslogSaveBody returns the body of the Save POST that sets sf's form to want (server is
// want.Server checked by checkSyslogTarget) and the text of the level chosen ("" = left as
// it is). Only the syslog controls change; every other control is posted as the page has it.
// An error means the form must not be posted.
func (c *Client) syslogSaveBody(sf *syslogForm, want model.SyslogTarget, server string) (body, level string, err error) {
	f := sf.form
	save, err := saveButton(f)
	if err != nil {
		return "", "", err
	}
	if err := c.postable(f, save); err != nil {
		return "", "", err
	}
	if err := setSwitch(sf.sw, want.Enabled); err != nil {
		return "", "", err
	}
	if want.Enabled {
		if !sf.shown() {
			return "", "", fmt.Errorf("the page shows no %q, %q or %q", syslogServerLabel, syslogPortLabel, syslogLevelLabel)
		}
		if err := setText(sf.server, syslogServerLabel, server); err != nil {
			return "", "", err
		}
		if err := setText(sf.port, syslogPortLabel, strconv.Itoa(want.Port)); err != nil {
			return "", "", err
		}
		if want.Level != "" {
			if level, err = setLevel(sf.level, want.Level); err != nil {
				return "", "", err
			}
		}
	}
	body, err = f.encode(save)
	return body, level, err
}

// saveButton returns the form's Save button: a submit button named "Save" or showing "Save" or
// "Apply". Several different ones are an error, as is none.
func saveButton(f *pageForm) (*formControl, error) {
	save, n := f.submitButton(func(b *formControl) bool {
		v := strings.TrimSpace(b.value)
		return strings.EqualFold(b.name, "Save") || strings.EqualFold(v, "Save") || strings.EqualFold(v, "Apply") ||
			b.tag == "button" && (strings.EqualFold(b.text, "Save") || strings.EqualFold(b.text, "Apply"))
	})
	switch {
	case n == 0:
		return nil, errors.New("the form has no Save button")
	case n > 1:
		return nil, fmt.Errorf("the form has %d different Save buttons", n)
	}
	return save, nil
}

// postable checks that a click on submitter sends f the way postForm sends the body encode
// produces - a POST, application/x-www-form-urlencoded, to syslog.ha - and that f has a nonce.
func (c *Client) postable(f *pageForm, submitter *formControl) error {
	method, action, enctype := f.submitTarget(submitter)
	switch {
	case method != "post":
		return fmt.Errorf("the form is sent with method %q, not post", method)
	case enctype != formURLEncoded:
		return fmt.Errorf("the form is sent as %s", enctype)
	case !c.refersTo(action, syslogPage):
		return fmt.Errorf("the form posts to %q, not syslog.ha", action)
	case f.nonce() == "":
		return errors.New("the form has no nonce")
	}
	return nil
}

// refersTo reports whether ref - a form action or a redirect target, absolute or relative to
// page's URL - addresses page itself on this gateway (same scheme, host and path, no query).
func (c *Client) refersTo(ref, page string) bool {
	base, err := url.Parse(c.pageURL(page))
	if err != nil {
		return false
	}
	u, err := base.Parse(strings.TrimSpace(ref))
	if err != nil {
		return false
	}
	return u.Scheme == base.Scheme && strings.EqualFold(u.Host, base.Host) && u.User == nil &&
		u.Path == base.Path && u.RawQuery == "" && !u.ForceQuery
}

// switchSetter returns the change that sets the "Syslog" switch to on - a checkbox checked or
// unchecked, or the one option (or radio button) that stands for on or off chosen - or why the
// switch cannot be set so: it is disabled, or not exactly one enabled choice stands for on.
// Nothing changes until the change is made.
func switchSetter(fd formField, on bool) (set func(), err error) {
	if c := fd.controls[0]; !fd.isRadioGroup() && c.tag == "input" && c.typ == "checkbox" {
		if c.disabled {
			return nil, fmt.Errorf("the %q checkbox is disabled", syslogSwitchLabel)
		}
		return func() { c.checked = on }, nil
	}
	chs := fd.choices()
	if chs == nil {
		return nil, fmt.Errorf("the %q control is a %s, not an on/off switch", syslogSwitchLabel, fd.kind())
	}
	if c := fd.controls[0]; c.tag == "select" && c.disabled {
		return nil, fmt.Errorf("the %q list is disabled", syslogSwitchLabel)
	}
	var pick []choice
	for _, ch := range chs {
		m, known, conflict := switchMeaning(ch)
		if conflict {
			return nil, fmt.Errorf("the %q option %q (value %q) says both on and off", syslogSwitchLabel, ch.text, ch.value)
		}
		if known && m == on && !ch.disabled {
			pick = append(pick, ch)
		}
	}
	if len(pick) != 1 {
		return nil, fmt.Errorf("the %q control has %d options for %s", syslogSwitchLabel, len(pick), onOff(on))
	}
	return func() { fd.choose(pick[0]) }, nil
}

// setSwitch sets the "Syslog" switch to on (see switchSetter).
func setSwitch(fd formField, on bool) error {
	set, err := switchSetter(fd, on)
	if err != nil {
		return err
	}
	set()
	return nil
}

// fits checks that v can be typed into the text input c: not beyond its maxlength.
func fits(c *formControl, label, v string) error {
	if c.maxLen >= 0 && len(v) > c.maxLen {
		return fmt.Errorf("the %q input takes at most %d characters, %q has %d", label, c.maxLen, v, len(v))
	}
	return nil
}

// setText types v into a text input as a person would: not into a disabled or read-only
// input, and not beyond its maxlength.
func setText(c *formControl, label, v string) error {
	switch {
	case c.disabled:
		return fmt.Errorf("the %q input is disabled", label)
	case c.readOnly:
		return fmt.Errorf("the %q input is read-only", label)
	}
	if err := fits(c, label, v); err != nil {
		return err
	}
	c.value = v
	return nil
}

// levelChoice returns the one "Log Level" choice whose text or value matches want (case and
// white space aside); a disabled choice does not count. With whileOff a choice disabled only
// because the page disables the whole list (or every radio button) until Syslog is on counts:
// the choice is offered once the list is enabled.
func levelChoice(fd formField, want string, whileOff bool) (choice, error) {
	chs := fd.choices()
	if chs == nil {
		return choice{}, fmt.Errorf("the %q control is a %s, not a list of options", syslogLevelLabel, fd.kind())
	}
	var pick []choice
	var offered []string
	for _, ch := range chs {
		offered = append(offered, strconv.Quote(ch.display()))
		usable := !ch.disabled
		if whileOff {
			usable = ch.opt == nil || !ch.opt.disabled // a radio button, or an option not disabled itself
		}
		if usable && levelMatches(ch, want) {
			pick = append(pick, ch)
		}
	}
	switch len(pick) {
	case 0:
		if len(offered) > 20 {
			offered = append(offered[:20], "...")
		}
		return choice{}, fmt.Errorf("%q has no option %q (it offers %s)", syslogLevelLabel, want, strings.Join(offered, ", "))
	case 1:
		return pick[0], nil
	default:
		return choice{}, fmt.Errorf("%d %q options match %q", len(pick), syslogLevelLabel, want)
	}
}

// setLevel chooses the one "Log Level" option whose text or value matches want (case and
// white space aside) and returns its text; the list must be enabled.
func setLevel(fd formField, want string) (string, error) {
	if c := fd.controls[0]; c.tag == "select" && c.disabled {
		return "", fmt.Errorf("the %q list is disabled", syslogLevelLabel)
	}
	ch, err := levelChoice(fd, want, false)
	if err != nil {
		return "", err
	}
	fd.choose(ch)
	return ch.display(), nil
}
