package gateway

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"
)

// oneForm parses body and returns its only form.
func oneForm(t *testing.T, body string) *pageForm {
	t.Helper()
	forms := parseForms([]byte(body))
	if len(forms) != 1 {
		t.Fatalf("%d forms, want 1", len(forms))
	}
	return forms[0]
}

// ctl returns the n-th control of f named name (n from 0).
func ctl(t *testing.T, f *pageForm, name string, n int) *formControl {
	t.Helper()
	for _, c := range f.controls {
		if c.name == name {
			if n == 0 {
				return c
			}
			n--
		}
	}
	t.Fatalf("no control %q", name)
	return nil
}

// controlSummary lists f's controls as "tag/type name".
func controlSummary(f *pageForm) []string {
	var out []string
	for _, c := range f.controls {
		out = append(out, c.tag+"/"+c.typ+" "+c.name)
	}
	return out
}

// mustEncode encodes f for the submit button named submit.
func mustEncode(t *testing.T, f *pageForm, submit string) string {
	t.Helper()
	body, err := f.encode(ctl(t, f, submit, 0))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return body
}

// TestParseFormsFixtures reads the forms of real (sanitized) gateway pages and checks that the
// bodies the reader produces are the ones the gateway's own pages post - for events.ha and
// login.ha exactly the bodies the client has always posted by hand.
func TestParseFormsFixtures(t *testing.T) {
	t.Run("events.ha", func(t *testing.T) {
		f := oneForm(t, string(fixture(t, "events_checked.html")))
		if f.method != "post" || f.action != "/cgi-bin/events.ha" || f.enctype != formURLEncoded {
			t.Errorf("form = %s %q %s", f.method, f.action, f.enctype)
		}
		want := []string{"input/hidden nonce", "input/checkbox bbevent", "input/submit Save", "input/submit Cancel"}
		if got := controlSummary(f); !reflect.DeepEqual(got, want) {
			t.Fatalf("controls = %q, want %q", got, want)
		}
		bb := ctl(t, f, "bbevent", 0)
		if !bb.checked || bb.value != "on" || bb.label != "Broadband Status Notification" || bb.labelFrom != labelFor {
			t.Errorf("bbevent = %+v", bb)
		}
		const nonce = "632c9628a62414f7310abd046496c505a8de867218bfbebc105914c40b1f8ad3"
		if f.nonce() != nonce {
			t.Errorf("nonce = %q", f.nonce())
		}
		if got := mustEncode(t, f, "Save"); got != "nonce="+nonce+"&bbevent=on&Save=Save" {
			t.Errorf("Save body = %q", got)
		}
		off := oneForm(t, string(fixture(t, "events_unchecked.html")))
		if got := mustEncode(t, off, "Save"); got != "nonce=e25bde59d83ef812cc00c171a11d34bda82eb346820db555df7647cbd1ee7cd1&Save=Save" {
			t.Errorf("unchecked Save body = %q", got)
		}
	})
	t.Run("broadbandconfig.ha", func(t *testing.T) {
		f := oneForm(t, string(fixture(t, "broadbandconfig.html")))
		// The Update button sits in a <noscript> element: a browser without JavaScript has it.
		want := []string{"input/hidden nonce", "select/select-one source", "input/submit Update", "input/text MTUW",
			"input/text MTU6", "input/submit Save", "input/submit Cancel"}
		if got := controlSummary(f); !reflect.DeepEqual(got, want) {
			t.Fatalf("controls = %q, want %q", got, want)
		}
		src := ctl(t, f, "source", 0)
		if src.label != "Broadband Source Override" || len(src.options) != 3 || !src.options[0].selected ||
			src.options[0].value != "auto" || src.options[0].text != "Auto" || src.options[2].text != "Fiber" {
			t.Errorf("source = %+v options %+v", src, src.options)
		}
		if mtu := ctl(t, f, "MTUW", 0); mtu.label != "Base MTU" || mtu.value != "1500" || mtu.maxLen != 4 || mtu.disabled {
			t.Errorf("MTUW = %+v", mtu)
		}
		if mtu6 := ctl(t, f, "MTU6", 0); mtu6.label != "IPv6 MTU" || !mtu6.disabled {
			t.Errorf("MTU6 = %+v", mtu6)
		}
		if upd := ctl(t, f, "Update", 0); upd.label != "" || upd.row != "Broadband Source Override" {
			t.Errorf("Update button: label %q (buttons take no row label), row %q", upd.label, upd.row)
		}
		const nonce = "f5a7226eb4cfc2eab3531295edc649d4e4b4306ac5d1960c63acb9f9158fb19f"
		// The disabled MTU6 is never submitted; only the clicked button is.
		if got := mustEncode(t, f, "Save"); got != "nonce="+nonce+"&source=auto&MTUW=1500&Save=Save" {
			t.Errorf("Save body = %q", got)
		}
		if got := mustEncode(t, f, "Update"); got != "nonce="+nonce+"&source=auto&Update=Update&MTUW=1500" {
			t.Errorf("Update body = %q", got)
		}
		if fd := f.fields("broadband source override:"); len(fd) != 1 || fd[0].controls[0] != src {
			t.Errorf("fields(source) = %+v", fd)
		}
	})
	t.Run("syslog.ha (real, firmware 6.34.7)", func(t *testing.T) {
		f := oneForm(t, string(fixture(t, "syslog_real_off.html")))
		if f.method != "post" || f.action != "/cgi-bin/syslog.ha" || f.enctype != formURLEncoded {
			t.Errorf("form = %s %q %s", f.method, f.action, f.enctype)
		}
		// The noscript Update button follows the switch, in its table row.
		want := []string{"input/hidden nonce", "select/select-one syslog", "input/submit Update", "input/text location",
			"input/text port", "select/select-one level", "input/submit Save", "input/submit Cancel"}
		if got := controlSummary(f); !reflect.DeepEqual(got, want) {
			t.Fatalf("controls = %q, want %q", got, want)
		}
		// While Syslog is off the three fields are disabled.
		for name, label := range map[string]string{"syslog": "Syslog", "location": "Server IP Address", "port": "Server Port", "level": "Log Level"} {
			if c := ctl(t, f, name, 0); c.label != label || c.labelFrom != labelFor || c.disabled != (name != "syslog") {
				t.Errorf("%s: label %q (from %d), disabled %v", name, c.label, c.labelFrom, c.disabled)
			}
		}
		if loc, port := ctl(t, f, "location", 0), ctl(t, f, "port", 0); loc.value != "" || loc.maxLen != 43 || port.value != "514" || port.maxLen != 5 {
			t.Errorf("location = %+v, port = %+v", loc, port)
		}
		if sw := ctl(t, f, "syslog", 0); len(sw.options) != 2 || !sw.options[0].selected || sw.options[0].value != "off" ||
			sw.options[1].value != "on" || sw.options[1].text != "On" {
			t.Errorf("syslog options = %+v", sw.options)
		}
		if upd := ctl(t, f, "Update", 0); upd.row != "Syslog" || upd.disabled {
			t.Errorf("Update button: row %q, disabled %v", upd.row, upd.disabled)
		}
		// Disabled controls are never submitted; only the clicked button is.
		const nonce = "0000000000000000000000000000000000000000000000000000000000000000"
		if got := mustEncode(t, f, "Save"); got != "nonce="+nonce+"&syslog=off&Save=Save" {
			t.Errorf("Save body = %q", got)
		}
		if got := mustEncode(t, f, "Update"); got != "nonce="+nonce+"&syslog=off&Update=Update" {
			t.Errorf("Update body = %q", got)
		}
		// Once on (a page derived from the real one), the fields are submitted after the
		// Update button, in document order.
		on := oneForm(t, string(fixture(t, "syslog_real_on.html")))
		const onNonce = "2222222222222222222222222222222222222222222222222222222222222222"
		if got := mustEncode(t, on, "Save"); got != "nonce="+onNonce+"&syslog=on&location=192.168.1.71&port=514&level=Notice&Save=Save" {
			t.Errorf("on: Save body = %q", got)
		}
		if got := mustEncode(t, on, "Update"); got != "nonce="+onNonce+"&syslog=on&Update=Update&location=192.168.1.71&port=514&level=Notice" {
			t.Errorf("on: Update body = %q", got)
		}
	})
	t.Run("login.ha", func(t *testing.T) {
		f := oneForm(t, string(fixture(t, "login_nonce.html")))
		pw := ctl(t, f, "password", 0)
		if pw.typ != "password" || pw.label != "Device Access Code" || pw.maxLen != 32 {
			t.Errorf("password = %+v", pw)
		}
		// Same fields, in the same order, as the login POST the client builds.
		const want = "nonce=dd0a08f1f4bb9bf6740850db561407c4c1fa799ec65a0a7b6521c20191dad462&password=&hashpassword=&Continue=Continue"
		if got := mustEncode(t, f, "Continue"); got != want {
			t.Errorf("Continue body = %q", got)
		}
	})
}

// TestFormEncodeBrowserRules pins down the entries a browser submits (HTML "constructing the
// entry list") for the control states the gateway's pages can contain.
func TestFormEncodeBrowserRules(t *testing.T) {
	tests := []struct {
		name, html, submit, want string
	}{
		{"checkbox unchecked is left out, checked submits on",
			`<input type=checkbox name=a><input type=checkbox name=b checked><input type=checkbox name=c value=1 checked=checked>`,
			"", "b=on&c=1"},
		{"radio: the last of several checked wins, no value submits on",
			`<input type=radio name=r value=x checked><input type=radio name=r value=y checked><input type=radio name=r value=z><input type=radio name=s checked>`,
			"", "r=y&s=on"},
		{"radio groups are per name",
			`<input type=radio name=r1 value=a checked><input type=radio name=r2 value=b checked>`,
			"", "r1=a&r2=b"},
		{"select without a selected option submits its first enabled option",
			`<select name=s><option disabled>x</option><option value=1>one</option><option value=2>two</option></select>`,
			"", "s=1"},
		{"select: of several selected options the last wins",
			`<select name=s><option value=1 selected>one</option><option value=2 selected>two</option><option value=3>three</option></select>`,
			"", "s=2"},
		{"select: a selected disabled option submits nothing",
			`<select name=s><option value=1>one</option><option value=2 selected disabled>two</option></select>`,
			"", ""},
		{"select: an option without value submits its text with white space collapsed",
			"<select name=s><option>  Log \t Level\n</option></select>",
			"", "s=Log+Level"},
		{"select: options of a disabled optgroup are disabled",
			`<select name=s><optgroup label=g disabled><option value=1>one</option></optgroup><option value=2>two</option></select>`,
			"", "s=2"},
		{"select multiple submits every selected option, and nothing by default",
			`<select name=m multiple><option value=1 selected>a</option><option value=2>b</option><option value=3 selected>c</option></select><select name=n multiple><option value=9>z</option></select>`,
			"", "m=1&m=3"},
		{"list box (size > 1) without a selected option submits nothing",
			`<select name=s size=3><option value=1>a</option></select>`,
			"", ""},
		{"select is ended by a following input",
			`<select name=s><option value=1>a<input name=t value=x></select>`,
			"", "s=1&t=x"},
		{"textarea: entities decoded, first newline dropped, newlines sent as CRLF",
			"<textarea name=t>\nline 1&amp;\nline 2</textarea>",
			"", "t=line+1%26%0D%0Aline+2"},
		{"disabled controls are never submitted",
			`<input name=a value=1 disabled><select name=b disabled><option>x</option></select><textarea name=c disabled>y</textarea><input name=d value=4>`,
			"", "d=4"},
		{"a disabled fieldset disables its controls, except in its first legend",
			`<fieldset disabled><legend><input name=a value=1></legend><input name=b value=2><legend><input name=c value=3></legend></fieldset><input name=d value=4>`,
			"", "a=1&d=4"},
		{"controls without a name are not submitted",
			`<input value=1><input name="" value=2><input name=x value=3>`,
			"", "x=3"},
		{"only the clicked button is submitted",
			`<input type=submit name=go value=Go><input type=submit name=stop value=Stop><input type=reset name=r value=R><input type=button name=b value=B>`,
			"stop", "stop=Stop"},
		{"a button element submits by default, type=button and reset never do",
			`<button name=b1 type=button value=1>One</button><button name=b2 type=reset value=2>Two</button><button name=b3 value=3>Three</button>`,
			"b3", "b3=3"},
		{"a submit button without value submits an empty value",
			`<input name=t value=x><input type=submit name=go>`,
			"go", "t=x&go="},
		{"input types: unknown is text, case does not matter",
			`<input type=fancy name=a value=1><INPUT TYPE=CHECKBOX NAME=b CHECKED><input type=Hidden name=c value=" 3 ">`,
			"", "a=1&b=on&c=+3+"},
		{"value sanitization: newlines removed from text, invalid numbers emptied",
			"<input name=t value=\"a\nb\"><input type=number name=n value=12abc><input type=number name=m value=-1.5e3><input type=hidden name=h value=\"x\ny\">",
			"", "t=ab&n=&m=-1.5e3&h=x%0D%0Ay"},
		{"form-urlencoded escaping",
			`<input name="a b" value="c&amp;d=e+f"><input name=t value="~x-y_z.*">`,
			"", "a+b=c%26d%3De%2Bf&t=%7Ex-y_z.*"},
		{"noscript content is read as markup",
			`<input name=a value=1><noscript><input name=b value=2><input type=submit name=Update value=Update></noscript><input type=submit name=Save value=Save>`,
			"Update", "a=1&b=2&Update=Update"},
		{"a file input without a file submits an empty value",
			`<input type=file name=f><input name=x value=1>`,
			"", "f=&x=1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			submit := `<input type=submit name=zz_submit value=ok>`
			if tt.submit != "" {
				submit = ""
			}
			f := oneForm(t, `<form method=post action="/cgi-bin/x.ha">`+tt.html+submit+`</form>`)
			name := tt.submit
			want := tt.want
			if name == "" {
				name = "zz_submit"
				if want != "" {
					want += "&"
				}
				want += "zz_submit=ok"
			}
			if got := mustEncode(t, f, name); got != want {
				t.Errorf("body = %q, want %q", got, want)
			}
		})
	}
}

// TestFormEncodeRefusals: forms whose body cannot be produced exactly as a browser would are
// never encoded.
func TestFormEncodeRefusals(t *testing.T) {
	f := oneForm(t, `<form method=post><input name=a value=1><input type=submit name=go value=Go>`+
		`<input type=submit name=off value=Off disabled><input type=image name=img><input type=reset name=r>`+
		`<button type=button name=b>B</button></form><input type=submit name=outside value=O>`)
	other := parseForms([]byte(`<form><input type=submit name=elsewhere></form>`))[0]
	for name, submitter := range map[string]*formControl{
		"nil submitter":          nil,
		"not a submit button":    ctl(t, f, "a", 0),
		"disabled submit button": ctl(t, f, "off", 0),
		"image button":           ctl(t, f, "img", 0),
		"reset button":           ctl(t, f, "r", 0),
		"button of type button":  ctl(t, f, "b", 0),
		"button of another form": other.controls[0],
	} {
		if _, err := f.encode(submitter); err == nil {
			t.Errorf("%s: encoded", name)
		}
	}
	for name, html := range map[string]string{
		"non-ASCII value":     `<input name=a value="caf&eacute;">`,
		"non-ASCII name":      "<input name=\"caf\xe9\" value=1>",
		"_charset_ field":     `<input type=hidden name=_charset_>`,
		"non-ASCII in option": `<select name=s><option>&nbsp;x</option></select>`,
	} {
		f := oneForm(t, `<form>`+html+`<input type=submit name=go></form>`)
		if body, err := f.encode(ctl(t, f, "go", 0)); err == nil {
			t.Errorf("%s: encoded as %q", name, body)
		}
	}
	// The same characters in a control that is not submitted do not matter.
	f = oneForm(t, `<form><input name=a value="caf&eacute;" disabled><input type=checkbox name=b value="&eacute;"><input type=submit name=go></form>`)
	if body, err := f.encode(ctl(t, f, "go", 0)); err != nil || body != "go=" {
		t.Errorf("body = %q, err = %v", body, err)
	}
}

// TestFormOwnership: controls belong to the open form (the parser's form element pointer),
// also when the form opens inside a table; a nested form is ignored; the form attribute
// overrides the position.
func TestFormOwnership(t *testing.T) {
	forms := parseForms([]byte(`<input name=before>
<table><form method=post action="/cgi-bin/a.ha"><tr><td><input name=a1></td></tr>
<tr><td><form action="/cgi-bin/nested.ha"><input name=a2></td></tr></table>
<input name=a3></form>
<input name=after><input name=late form=f2>
<form id=f2 action="/cgi-bin/b.ha"><input name=b1><input name=away form=nope></form>
<div id=f3></div><form id=f3><input name=c1></form><input name=byid form=f3>`))
	if len(forms) != 3 {
		t.Fatalf("%d forms, want 3", len(forms))
	}
	var got [][]string
	for _, f := range forms {
		var names []string
		for _, c := range f.controls {
			names = append(names, c.name)
		}
		got = append(got, names)
	}
	// "byid" names f3, but the first element with that id is a div: it belongs to no form.
	want := [][]string{{"a1", "a2", "a3"}, {"late", "b1"}, {"c1"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("controls by form = %q, want %q", got, want)
	}
	if forms[0].method != "post" || forms[0].action != "/cgi-bin/a.ha" || forms[1].method != "get" {
		t.Errorf("forms = %+v %+v", forms[0], forms[1])
	}
}

// TestFormLabels: a control's label is its <label for=id>, else a <label> around it, else the
// <th> of its row; buttons and hidden inputs take no row label.
func TestFormLabels(t *testing.T) {
	f := oneForm(t, `<form><table>
<tr><th><label for=a>Server IP Address</label>:</th><td><input id=a name=a></td></tr>
<tr><td><input id=b type=checkbox name=b></td><th><label for=b>Syslog</label></th></tr>
<tr><th>Server Port:</th><td><input name=c type=number><input type=submit name=upd value=Update><input type=hidden name=h></td></tr>
<tr><th>Log<br>Level</th><td><select name=d><option>Error</option><option>Debug</option></select></td></tr>
<tr><td><label>Wrapped <input name=e> field</label></td></tr>
<tr><th>Row</th><td><label>Wrapped label wins <input name=f></label></td></tr>
<tr><th>Row</th><td><input id=g name=g><label for=g>For label wins</label></td></tr>
<tr><th>First</th><td><input name=h1></td><th>Second</th><td><input name=h2></td></tr>
<tr><th>Outer</th><td><table><tr><td><input name=i></td></tr></table></td></tr>
<tr><th><select name=j><option>Inside th</option></select> Level</th></tr>
<tr><td><input name=k></td></tr>
</table>
<label for=dup>Dup first</label><span id=dup></span><input id=dup name=l>
<label for=hid>Hidden</label><input type=hidden id=hid name=m>
<label for=n>N one</label><label for=n>N two</label><input id=n name=n>
<label><input type=radio name=o value=1> On</label>
<label>Around <input id=p name=p></label><label for=p>For p</label>
</form>`)
	for _, tt := range []struct {
		name, label string
		from        labelSource
		row         string
	}{
		{"a", "Server IP Address", labelFor, "Server IP Address"},
		{"b", "Syslog", labelFor, "Syslog"},
		{"c", "Server Port", labelRow, "Server Port"},
		{"upd", "", labelNone, "Server Port"},
		{"h", "", labelNone, "Server Port"},
		{"d", "Log Level", labelRow, "Log Level"},
		{"e", "Wrapped field", labelWrap, ""},
		{"f", "Wrapped label wins", labelWrap, "Row"},
		{"g", "For label wins", labelFor, "Row"},
		{"h1", "First", labelRow, "First"},
		{"h2", "Second", labelRow, "Second"},
		{"i", "", labelNone, ""}, // the inner row has no <th>
		{"j", "Level", labelRow, "Level"},
		{"k", "", labelNone, ""},
		{"l", "", labelNone, ""}, // the first element with id "dup" is the span
		{"m", "", labelNone, ""}, // hidden inputs are not labelable
		{"n", "N one", labelFor, ""},
		{"o", "On", labelWrap, ""},
		{"p", "For p", labelFor, ""}, // a for label wins over an earlier label around the control
	} {
		c := ctl(t, f, tt.name, 0)
		if c.label != tt.label || c.labelFrom != tt.from || c.row != tt.row {
			t.Errorf("%s: label %q (from %d) row %q, want %q (from %d) row %q", tt.name, c.label, c.labelFrom, c.row, tt.label, tt.from, tt.row)
		}
	}
}

// TestFormFields: lookup by label ignores case, white space and punctuation; a radio group is
// one field, found by the label of its row; buttons and hidden inputs are no fields.
func TestFormFields(t *testing.T) {
	f := oneForm(t, `<form><table>
<tr><th>Syslog</th><td><input type=radio id=r1 name=sw value=1><label for=r1>Enable</label>
<input type=radio id=r2 name=sw value=0 checked><label for=r2>Disable</label>
<input type=submit name=Update value=Update></td></tr>
<tr><th>Server IP-Address *</th><td><input name=ip></td></tr>
<tr><th>Twice</th><td><input name=t1><input name=t2></td></tr>
<tr><th>Hidden</th><td><input type=hidden name=h></td></tr>
</table><input type=radio name=sw value=2></form>`)
	sw := f.fields("SYSLOG")
	if len(sw) != 1 || !sw[0].isRadioGroup() || len(sw[0].controls) != 3 || sw[0].kind() != "radio buttons" {
		t.Fatalf("fields(Syslog) = %+v", sw)
	}
	chs := sw[0].choices()
	if len(chs) != 3 || chs[0].text != "Enable" || chs[1].text != "Disable" || !chs[1].selected || chs[2].text != "" || chs[2].display() != "2" {
		t.Errorf("choices = %+v", chs)
	}
	sw[0].choose(chs[0])
	if !sw[0].controls[0].checked || sw[0].controls[1].checked {
		t.Error("choose did not move the check")
	}
	if ip := f.fields("server ip address"); len(ip) != 1 || ip[0].controls[0].name != "ip" || ip[0].kind() != "text input" {
		t.Errorf("fields(server ip address) = %+v", ip)
	}
	if two := f.fields("Twice"); len(two) != 2 {
		t.Errorf("fields(Twice) = %d, want 2 (ambiguous)", len(two))
	}
	for _, label := range []string{"Hidden", "Update", "", ":"} {
		if fd := f.fields(label); len(fd) != 0 {
			t.Errorf("fields(%q) = %+v", label, fd)
		}
	}
	// A radio button's own label also names its group.
	if en := f.fields("Enable"); len(en) != 1 || len(en[0].controls) != 3 {
		t.Errorf("fields(Enable) = %+v", en)
	}

	// A field is disabled when its control is, or every button of its radio group.
	g := oneForm(t, `<form><table>
<tr><th>Group</th><td><input type=radio name=g value=1 disabled><input type=radio name=g value=2></td></tr>
<tr><th>Off group</th><td><fieldset disabled><input type=radio name=o value=1><input type=radio name=o value=2></fieldset></td></tr>
<tr><th>Box</th><td><input name=b disabled></td></tr>
<tr><th>List</th><td><select name=l><option>x</option></select></td></tr></table></form>`)
	for label, want := range map[string]bool{"Group": false, "Off group": true, "Box": true, "List": false} {
		if fd := g.fields(label); len(fd) != 1 || fd[0].disabled() != want {
			t.Errorf("fields(%q) = %+v, want disabled %v", label, fd, want)
		}
	}
}

// TestFormSubmitTarget: formaction, formmethod and formenctype on a submit button override the
// form's own.
func TestFormSubmitTarget(t *testing.T) {
	f := oneForm(t, `<form method=POST action="/cgi-bin/syslog.ha" enctype="TEXT/PLAIN">
<input type=submit name=a><input type=submit name=b formaction="/cgi-bin/other.ha" formmethod=get formenctype=multipart/form-data>
<button name=c formmethod=bogus formenctype=bogus>C</button></form>`)
	type target struct{ method, action, enctype string }
	for name, want := range map[string]target{
		"a": {"post", "/cgi-bin/syslog.ha", "text/plain"},
		"b": {"get", "/cgi-bin/other.ha", "multipart/form-data"},
		"c": {"get", "/cgi-bin/syslog.ha", formURLEncoded},
	} {
		m, a, e := f.submitTarget(ctl(t, f, name, 0))
		if got := (target{m, a, e}); got != want {
			t.Errorf("%s: target = %+v, want %+v", name, got, want)
		}
	}
	if c := ctl(t, f, "c", 0); c.text != "C" || c.typ != "submit" {
		t.Errorf("button = %+v", c)
	}
}

// TestFormNonceAndButtons covers the helpers SetSyslog relies on before it posts.
func TestFormNonceAndButtons(t *testing.T) {
	const n = "0123456789abcdef0123456789abcdef"
	nonceInput := `<input type=hidden name=nonce value=` + n + `>`
	for _, tt := range []struct{ body, want string }{
		{nonceInput, n},
		{``, ""},
		{`<input type=hidden name=nonce value="has space">`, ""},
		{nonceInput + nonceInput, ""}, // two
		{`<input type=hidden name=nonce value=` + n + ` disabled>`, ""},
	} {
		if got := oneForm(t, `<form>`+tt.body+`</form>`).nonce(); got != tt.want {
			t.Errorf("nonce of %q = %q, want %q", tt.body, got, tt.want)
		}
	}
	f := oneForm(t, `<form><input type=submit name=Save value=Save><noscript><input type=submit name=Save value=Save></noscript>
<input type=submit name=Update value=Update disabled><button name=x value=Update>Update</button><input type=submit name=Update value=Refresh></form>`)
	isUpdate := func(c *formControl) bool { return c.name == "Update" || c.value == "Update" }
	if b, n := f.submitButton(func(c *formControl) bool { return c.name == "Save" }); n != 1 || b == nil || b.value != "Save" {
		t.Errorf("Save: %v, %d (identical buttons count once)", b, n)
	}
	if b, n := f.submitButton(isUpdate); n != 2 || b.name != "x" {
		t.Errorf("Update: %+v, %d (a disabled button is not clickable)", b, n)
	}
}

// TestFormMalformedMarkup: the gateway's sloppy markup and hostile input must not lose controls
// or crash the reader.
func TestFormMalformedMarkup(t *testing.T) {
	f := oneForm(t, `<form method=post><table><tr><th>Level<td><select name=s><option value=1>a<option value=2 selected>b</td>
<tr><th>Next<td><input name=n value=x></table><select name=open><option>z`)
	if got := mustEncodeAny(t, f); got != "s=2&n=x&open=z" {
		t.Errorf("body = %q", got)
	}
	if s := ctl(t, f, "s", 0); s.label != "Level" || len(s.options) != 2 {
		t.Errorf("s = %+v", s)
	}
	for _, body := range []string{"", "<form", "<form><select><option", "<form><textarea>", "<form><noscript>", "\x00\xff<form>\xfe",
		"<form><label for=x><label>", "<form><fieldset disabled><legend></fieldset></legend><input name=a>"} {
		parseForms([]byte(body)) // must not panic
	}

	// A label or button left open ends with its table cell, as in browsers: it must not take
	// in the rows that follow.
	f = oneForm(t, `<form><table>
<tr><th><label for=a>Server IP Address</th><td><input id=a name=a></td></tr>
<tr><td><label>Syslog <input type=checkbox name=b></td><td>more text</td></tr>
<tr><th>Server Port</th><td><input name=c><button name=x>Go</td></tr>
<tr><th>Log Level</th><td><input name=d></td></tr></table></form>`)
	for name, want := range map[string]string{"a": "Server IP Address", "b": "Syslog", "c": "Server Port", "d": "Log Level"} {
		if c := ctl(t, f, name, 0); c.label != want {
			t.Errorf("%s: label %q, want %q", name, c.label, want)
		}
	}
	if x := ctl(t, f, "x", 0); x.text != "Go" {
		t.Errorf("button text = %q", x.text)
	}
	// A form inside an open form is dropped with its id.
	forms := parseForms([]byte(`<form id=f1><form id=f2></form><input name=late form=f2><form id=f2><input name=x></form>`))
	if len(forms) != 2 || len(forms[1].controls) != 2 || forms[1].controls[0].name != "late" {
		t.Errorf("forms = %+v", forms)
	}
}

// mustEncodeAny encodes f with a submit button added at the end.
func mustEncodeAny(t *testing.T, f *pageForm) string {
	t.Helper()
	b := &formControl{tag: "input", typ: "submit", owner: 0, maxLen: -1}
	f.controls = append(f.controls, b)
	defer func() { f.controls = f.controls[:len(f.controls)-1] }()
	body, err := f.encode(b)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// TestParseFormsPathologicalInputs feeds near-cap hostile pages to the form reader: it must
// finish quickly (linear work) whatever the nesting and repetition.
func TestParseFormsPathologicalInputs(t *testing.T) {
	size := MaxBodyBytes
	if raceEnabled {
		size /= 8
	}
	longTH := "<form><table><tr><th>" + strings.Repeat("Server IP Address ", size/36) + "</th>"
	cases := map[string][]byte{
		"deep noscript":        []byte(strings.Repeat("<noscript>", size/10)),
		"noscript and inputs":  []byte("<form>" + strings.Repeat("<noscript><input name=a>", size/24)),
		"one row, many inputs": []byte(longTH + strings.Repeat("<td><input name=x>", size/36)),
		"deep fieldsets":       []byte("<form>" + strings.Repeat("<fieldset disabled><input name=a>", size/33)),
		"many radios":          []byte("<form>" + strings.Repeat("<input type=radio name=r checked>", size/33)),
		"many labels":          []byte("<form><input id=x name=x>" + strings.Repeat("<label for=x>Syslog</label>", size/28)),
		"many options":         []byte("<form><select name=s>" + strings.Repeat("<option selected>x", size/18)),
		"many forms":           bytes.Repeat([]byte("<form><input name=a></form>"), size/27),
		"deep tables":          []byte("<form>" + strings.Repeat("<table><tr><th>x<td><input name=a>", size/34)),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			forms := parseForms(body)
			for _, f := range forms {
				_ = f.fields(syslogSwitchLabel)
				_ = f.fields(syslogServerLabel)
			}
			_, _ = ParseSyslog(body)
			if d := time.Since(start); d > 30*time.Second {
				t.Errorf("reading took %v", d)
			}
		})
	}
}
