package web

// The Overview keeps the reader's place while it follows the monitor (docs/overview-redesign.md
// §3-§4: "keeping focus and scroll position"), driven in testdata/dashboard_harness.js: a link,
// a chart read from the keyboard, a table view scrolled, a text selected stay what they are
// across status updates and chart refreshes, and nothing is announced again; a double-click on a
// card does not close what it opened; a status change and a failure to read the status are said
// inside the open details, where the reader is; a confirmation opened in the details ends with
// them; the page shown again after a while reads what it missed at once.

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"
)

// keepFacts is what the harness's keepScenario observed (facts.keep).
type keepFacts struct {
	Cards []struct {
		Key, Described, Chip string
		Titles               int
	}
	Status      struct{ Described string }
	SeriesReads int
	Body        *struct{ Tabindex, Role, Labelledby string }
	Charts      struct {
		MinHeight, Tip, Live, TipAfter, LiveAfter string
		SamePlot, Focused, Redrawn                bool
		FocusEvents                               int
		Table                                     *struct {
			Same, Focused, Refilled bool
			ScrollTop, FocusEvents  int
		}
	}
	DoubleClick struct {
		AfterBackdrop, AfterClose, Later struct {
			Open bool
			Hash string
		}
		LinkPrevented bool
	}
	Recent   struct{ Before, Opened, Hero, Closed string }
	Announce struct{ Modal, Page, Live string }
	Incident *struct {
		Same, Focused bool
		FocusEvents   int
		Text          string
	}
	Inputs *struct {
		Same, Focused bool
		FocusEvents   int
	}
	Selection *struct{ Kept, RedrawnAfter bool }
	Visible   struct{ Series, Incidents, Details int }
}

// TestDashboardOverviewKeepsTheReadersPlace uses the Overview as a reader who stays on something
// while it updates (the harness's keepScenario).
func TestDashboardOverviewKeepsTheReadersPlace(t *testing.T) {
	w := newDemoWorld(time.Now())
	rep := runDashboardLive(t, w, "keep")
	var k keepFacts
	if err := json.Unmarshal(rep.Facts["keep"], &k); err != nil {
		t.Fatalf("keep: %s (%v)", rep.Facts["keep"], err)
	}

	// Tab says each card's state after its title (its chip describes its button), and the status
	// card's.
	for _, c := range k.Cards {
		if want := c.Chip[strings.Index(c.Chip, ":")+1:]; c.Described != want || c.Titles != 0 {
			t.Errorf("the %s card's button is described by %q (its chip says %q); %d tooltips", c.Key, c.Described, want, c.Titles)
		}
	}
	if k.Status.Described != "Online" {
		t.Errorf("the status card's button is described by %q", k.Status.Described)
	}

	// The details read nothing the summary read a moment ago; their body is a named Tab stop.
	if k.SeriesReads != 0 {
		t.Errorf("the Internet details read the last 24 hours again (%d reads) right after the summary did", k.SeriesReads)
	}
	if b := k.Body; b == nil || b.Tabindex != "0" || b.Role != "region" || b.Labelledby != "detail-title" {
		t.Errorf("the details' body: %+v", b)
	}

	// The round-trip chart read from the keyboard, across the charts' refresh: the same plot,
	// still focused (no focus event: nothing announced again), redrawn with the newer series, the
	// same bucket shown, its live region not written again.
	c := k.Charts
	if c.MinHeight != "224px" {
		t.Errorf("the plot's height before its first draw: %q", c.MinHeight)
	}
	if !c.SamePlot || !c.Focused || !c.Redrawn || c.FocusEvents != 0 || c.Tip == "" || c.TipAfter != c.Tip || c.LiveAfter != c.Live {
		t.Errorf("the round-trip chart read from the keyboard across a refresh: %+v", c)
	}
	// The packet-loss chart's table view, scrolled: the same region, focused, at the same place,
	// with the newer rows.
	if tv := c.Table; tv == nil || !tv.Same || !tv.Focused || tv.ScrollTop != 500 || !tv.Refilled || tv.FocusEvents != 0 {
		t.Errorf("the table view across a refresh: %+v", tv)
	}

	// The second click of a double-click lands on the details it opened: on their backdrop, on
	// their close button or on a link in them, it does nothing. A click a while later closes them.
	d := k.DoubleClick
	if !d.AfterBackdrop.Open || !d.AfterClose.Open || d.AfterClose.Hash != "#/?detail=internet" || !d.LinkPrevented {
		t.Errorf("a double-click on the Internet card: %+v", d)
	}
	if d.Later.Open || d.Later.Hash != "#/" {
		t.Errorf("a click on the backdrop a while later: %+v", d.Later)
	}

	// The recent incidents follow the incident in progress the status names at once.
	r := k.Recent
	if !strings.Contains(r.Hero, "Incident in progress: INC-") || !regexp.MustCompile(`ongoing · .*In progress`).MatchString(r.Opened) {
		t.Errorf("the recent incidents as the outage starts: %q (status card %q)", r.Opened, r.Hero)
	}
	if strings.Contains(r.Before, "In progress") || strings.Contains(r.Closed, "In progress") || strings.Contains(r.Closed, "ongoing") {
		t.Errorf("the recent incidents before the outage and after it: %q / %q", r.Before, r.Closed)
	}

	// A status change while the details are open is said in their own live region (the page's is
	// inert behind the modal).
	if a := k.Announce; !strings.HasPrefix(a.Modal, "Status changed: AT&T outage") || a.Live != "polite" || strings.Contains(a.Page, "AT&T outage") {
		t.Errorf("the status change announced: %+v", a)
	}

	// The status card's incident link, the status details' record link and a text selected in
	// the gateway details stay what they are across status updates; the selection gone, the
	// details follow the status again.
	if i := k.Incident; i == nil || !i.Same || !i.Focused || i.FocusEvents != 0 || !strings.HasPrefix(i.Text, "Incident in progress: INC-") {
		t.Errorf("the status card's incident link across status updates: %+v", i)
	}
	if i := k.Inputs; i == nil || !i.Same || !i.Focused || i.FocusEvents != 0 {
		t.Errorf("the status details' gateway snapshot link across a status update: %+v", i)
	}
	if s := k.Selection; s == nil || !s.Kept || !s.RedrawnAfter {
		t.Errorf("a text selected in the gateway details across status updates: %+v", s)
	}

	// Shown again after a minute hidden, the page reads the last 24 hours and the recent
	// incidents at once, and the details open their own series.
	if k.Visible.Series == 0 || k.Visible.Incidents == 0 || k.Visible.Details == 0 {
		t.Errorf("the page shown again a minute later: %+v", k.Visible)
	}
}

// TestDashboardOverviewDetailsWhenTheStatusFails: the details are a modal over an inert page, so
// the page's banner that the service cannot be reached (#conn) is behind them, and not read. The
// details say it themselves - their header loses its tone and says since when nothing was
// updated, and an alert under it (made once) says why - until the status is read again.
func TestDashboardOverviewDetailsWhenTheStatusFails(t *testing.T) {
	w := newDemoWorld(time.Now())
	rep := runDashboardLive(t, w, "statusfail")
	var f struct {
		Before, Down, Reopened, Back, Error *dashboardDetail
		SameNote                            bool
	}
	if err := json.Unmarshal(rep.Facts["fail"], &f); err != nil {
		t.Fatalf("fail: %s (%v)", rep.Facts["fail"], err)
	}
	if f.Before == nil || f.Before.Stale != nil || !strings.HasSuffix(f.Before.Context, " · updates while open") {
		t.Errorf("the details before: %+v", f.Before)
	}
	down := f.Down
	if down == nil || down.Stale == nil || down.Stale.Role != "alert" || strings.HasSuffix(down.Context, "updates while open") ||
		!regexp.MustCompile(` · not updated since \S+`).MatchString(down.Context) ||
		!regexp.MustCompile(`^Not updated since \S+.*: the att-monitor service cannot be reached\. What these details show may be out of date\.$`).MatchString(down.Stale.Text) {
		t.Errorf("the details while the service cannot be reached: %+v", down)
	}
	if !f.SameNote {
		t.Error("the note was made again at the next failed read (its alert would be read again)")
	}
	if r := f.Reopened; r == nil || !r.Open || r.Stale == nil || strings.HasSuffix(r.Context, "updates while open") {
		t.Errorf("details opened while the status cannot be read: %+v", r)
	}
	if f.Back == nil || f.Back.Stale != nil || !strings.HasSuffix(f.Back.Context, " · updates while open") {
		t.Errorf("the details once the status is read again: %+v", f.Back)
	}
	if e := f.Error; e == nil || e.Stale == nil || !strings.Contains(e.Stale.Text, "the monitor returned an error: status: the monitor's state could not be read.") {
		t.Errorf("the details while the monitor answers with an error: %+v", e)
	}
}

// TestDashboardOverviewDeepLinkWhenTheStatusFails: the page loaded at a card's details while the
// status cannot be read says so in them, rather than "Loading…" for ever.
func TestDashboardOverviewDeepLinkWhenTheStatusFails(t *testing.T) {
	w := newDemoWorld(time.Now())
	rep := runDashboardFailing(t, w, "down", "deepfail", "HARNESS_HASH=#/?detail=status")
	d := rep.Views["deep fail"].Detail
	if d == nil || !d.Open || d.Context != "No status read yet" || d.Stale == nil ||
		d.Stale.Text != "No status read yet: the att-monitor service cannot be reached. What these details show may be out of date." {
		t.Errorf("the status details loaded while the status cannot be read: %+v", d)
	}
}

// TestDashboardOverviewConfirmationEndsWithTheDetails: a confirmation opened in the Gateway syslog
// details ("Stop sending") is cancelled when Back closes the details: it is never left open over a
// page that no longer shows what it would change, nothing is sent, and the focus is back on the
// card's button.
func TestDashboardOverviewConfirmationEndsWithTheDetails(t *testing.T) {
	w := newDemoWorld(time.Now())
	rep := runDashboardLive(t, w, "confirmback")
	var c struct {
		Asked bool
		After struct {
			Modals, Dialogs int
			DetailOpen      bool
			Hash, Focus     string
		}
	}
	if err := json.Unmarshal(rep.Facts["confirmBack"], &c); err != nil {
		t.Fatalf("confirmBack: %s (%v)", rep.Facts["confirmBack"], err)
	}
	if a := c.After; !c.Asked || a.Modals != 0 || a.Dialogs != 0 || a.DetailOpen || a.Hash != "#/" || a.Focus != "button:Gateway syslog" {
		t.Errorf("Back while a confirmation is open over the details: %+v", c)
	}
	if posts := gwSyslogPosts(rep); len(posts) != 0 {
		t.Errorf("a change was sent: %v", posts)
	}
}

// TestDashboardOverviewTrafficDetailsStartAtTheFlowMeter: the Traffic details show their note on
// a monitor without a flow meter only: otherwise they start with the flow meter, without an empty
// part that would double the gap under the header.
func TestDashboardOverviewTrafficDetailsStartAtTheFlowMeter(t *testing.T) {
	requireNode(t)
	rep := runSummary(t, newDemoServer(t, newDemoWorld(time.Now()), nil), "traffic")
	if d := rep.Views["overview traffic"].Detail; d == nil || len(d.Parts) == 0 || d.Parts[0] != "section.card" {
		t.Errorf("the Traffic details' parts: %+v", d)
	}
}
