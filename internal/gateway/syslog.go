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
// §3.1) needs the login. Its markup has not been captured yet (phase 2 of the plan does), so
// the page is read by the labels of its controls, never by guessed control names: "Syslog"
// (on/off), "Server IP Address", "Server Port" and "Log Level" (BGW320-CLI's field list for
// the page). Labels are compared by alnumKey: case, white space and punctuation such as a
// trailing ":" do not matter.

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
// is off).
func (sf *syslogForm) shown() bool { return sf.server != nil }

// ParseSyslog parses the Syslog page (syslog.ha) by its labels. Enabled comes from the
// "Syslog" switch: a checked checkbox, or a drop-down list or radio buttons whose selected
// option's text or value is on, enable, enabled, yes, 1 or true (any other option is off).
// Server and Port are the "Server IP Address" and "Server Port" fields (Port 0 when empty),
// Level the text of the selected "Log Level" option and Levels the texts of all its options
// in page order. While Syslog is off the page may leave the three fields out. A missing,
// ambiguous or unexpected control is an error wrapping ErrSyslogPage that names it; the login
// page is ErrLoginRequired.
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

// SetSyslog sets the gateway's Syslog page to want: it reads syslog.ha (authenticated),
// changes only the syslog controls - the "Syslog" switch, and when enabling the server
// address, the port and (when want.Level is set) the log level, matched to an option by text
// or value - and posts the form back exactly as a browser without JavaScript would: every
// other control as the page has it, the nonce, and the Save button. When the page shows the
// server fields only once Syslog is on, it first posts the form with the switch on and the
// page's Update button, as the page asks such a browser to do, and fills in the page the
// gateway answers with. It then reads the page again: the error is nil only when that page
// shows want (ErrNotApplied otherwise, saying what differs). before and after are the exact
// bodies of the first and the last read (after only once a Save may have reached the gateway;
// the read-back follows the rules of SetNotification). When the page already shows want
// nothing is posted and after is the same body as before.
//
// It fails closed: nothing is posted (and after an Update round, no Save) when the page is not
// fully understood (ErrSyslogPage) - a control missing or ambiguous (also after the Update
// round), a level that is not one of the options, a form that does not post to syslog.ha the
// way this client encodes it, a form without a nonce or a Save button, a value the field
// cannot take - and no request is made when want itself is invalid (enabling needs an IPv4
// server address and a port from 1 to 65535).
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
	if want.Enabled && !sf.shown() {
		if sf, err = c.syslogUpdateRound(ctx, s, sf); err != nil {
			return before, nil, err
		}
	}
	body, level, err := c.syslogSaveBody(sf, want, server)
	if err != nil {
		return before, nil, fmt.Errorf("%w: %v; nothing posted", ErrSyslogPage, err)
	}
	ex, problem, err := c.postForm(ctx, s, syslogPage, body)
	if err != nil {
		return before, nil, err
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

// syslogUpdateRound posts the form with the "Syslog" switch on and the page's Update button,
// as the page asks a browser without JavaScript to do when it shows the server fields only
// once Syslog is on, and returns the page the gateway answers with (or redirects to). By the
// page's own instructions the Update button transforms the page; only the Save that follows
// is meant to save. The form is checked as for that Save (it must post to syslog.ha with a
// nonce, and have a Save button) before anything is posted.
func (c *Client) syslogUpdateRound(ctx context.Context, s *authSession, sf *syslogForm) (*syslogForm, error) {
	f := sf.form
	upd, n := f.submitButton(func(b *formControl) bool {
		return strings.EqualFold(b.name, "Update") || strings.EqualFold(strings.TrimSpace(b.value), "Update")
	})
	refuse := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s; nothing posted", ErrSyslogPage, fmt.Sprintf(format, args...))
	}
	switch {
	case n == 0:
		return nil, refuse("the page shows no %q, %q or %q while Syslog is off, and has no Update button",
			syslogServerLabel, syslogPortLabel, syslogLevelLabel)
	case n > 1:
		return nil, refuse("the form has %d different Update buttons", n)
	}
	if _, err := saveButton(f); err != nil {
		return nil, refuse("%v", err)
	}
	if err := c.postable(f, upd); err != nil {
		return nil, refuse("%v", err)
	}
	if err := setSwitch(sf.sw, true); err != nil {
		return nil, refuse("%v", err)
	}
	body, err := f.encode(upd)
	if err != nil {
		return nil, refuse("%v", err)
	}
	ex, problem, err := c.postForm(ctx, s, syslogPage, body)
	if err != nil {
		return nil, err
	}
	if problem != "" {
		return nil, fmt.Errorf("gateway: POST syslog.ha (Update): %s; Save not posted", problem)
	}
	page := ex.body
	switch {
	case ex.status != http.StatusOK: // a redirect (postForm accepts 200 and 3xx answers)
		if !c.refersTo(ex.location, syslogPage) {
			return nil, fmt.Errorf("gateway: POST syslog.ha (Update) redirected to %q; Save not posted", ex.location)
		}
		if page, err = c.getPage(ctx, s, syslogPage); err != nil {
			return nil, fmt.Errorf("%w (after the Update round; Save not posted)", err)
		}
	case ex.err != nil:
		return nil, fmt.Errorf("gateway: POST syslog.ha (Update): %w; Save not posted", ex.err)
	}
	next, err := parseSyslogPage(page) // a login page was caught by postForm or getPage
	if err != nil {
		return nil, fmt.Errorf("%w (after the Update round; Save not posted)", err)
	}
	if !next.shown() {
		return nil, fmt.Errorf("%w: the page still shows no %q, %q or %q after the Update round; Save not posted",
			ErrSyslogPage, syslogServerLabel, syslogPortLabel, syslogLevelLabel)
	}
	c.log.Info("gateway syslog page transformed by its Update button", "status", ex.status, "location", ex.location)
	return next, nil
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

// setSwitch sets the "Syslog" switch: it checks or unchecks a checkbox, or chooses the one
// option (or radio button) that stands for on or off.
func setSwitch(fd formField, on bool) error {
	if c := fd.controls[0]; !fd.isRadioGroup() && c.tag == "input" && c.typ == "checkbox" {
		if c.disabled {
			return fmt.Errorf("the %q checkbox is disabled", syslogSwitchLabel)
		}
		c.checked = on
		return nil
	}
	chs := fd.choices()
	if chs == nil {
		return fmt.Errorf("the %q control is a %s, not an on/off switch", syslogSwitchLabel, fd.kind())
	}
	if c := fd.controls[0]; c.tag == "select" && c.disabled {
		return fmt.Errorf("the %q list is disabled", syslogSwitchLabel)
	}
	var pick []choice
	for _, ch := range chs {
		m, known, conflict := switchMeaning(ch)
		if conflict {
			return fmt.Errorf("the %q option %q (value %q) says both on and off", syslogSwitchLabel, ch.text, ch.value)
		}
		if known && m == on && !ch.disabled {
			pick = append(pick, ch)
		}
	}
	if len(pick) != 1 {
		return fmt.Errorf("the %q control has %d options for %s", syslogSwitchLabel, len(pick), onOff(on))
	}
	fd.choose(pick[0])
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
	case c.maxLen >= 0 && len(v) > c.maxLen:
		return fmt.Errorf("the %q input takes at most %d characters, %q has %d", label, c.maxLen, v, len(v))
	}
	c.value = v
	return nil
}

// setLevel chooses the one "Log Level" option whose text or value matches want (case and
// white space aside) and returns its text.
func setLevel(fd formField, want string) (string, error) {
	chs := fd.choices()
	if chs == nil {
		return "", fmt.Errorf("the %q control is a %s, not a list of options", syslogLevelLabel, fd.kind())
	}
	if c := fd.controls[0]; c.tag == "select" && c.disabled {
		return "", fmt.Errorf("the %q list is disabled", syslogLevelLabel)
	}
	var pick []choice
	var offered []string
	for _, ch := range chs {
		offered = append(offered, strconv.Quote(ch.display()))
		if !ch.disabled && levelMatches(ch, want) {
			pick = append(pick, ch)
		}
	}
	switch len(pick) {
	case 0:
		if len(offered) > 20 {
			offered = append(offered[:20], "...")
		}
		return "", fmt.Errorf("%q has no option %q (it offers %s)", syslogLevelLabel, want, strings.Join(offered, ", "))
	case 1:
		fd.choose(pick[0])
		return pick[0].display(), nil
	default:
		return "", fmt.Errorf("%d %q options match %q", len(pick), syslogLevelLabel, want)
	}
}
