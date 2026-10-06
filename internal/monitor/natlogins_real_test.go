package monitor

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/gateway"
	"attmonitor/internal/model"
)

// The monitor with the real gateway client against an HTTP imitation of the BGW320's login
// (docs/DESIGN.md §2; the pages are the fixtures of testdata/gateway): the NAT reads among the
// settings check's requests, and the logins across restarts.

// The NAT sampler counts the gateway client's logins and learns when a refusal of its login policy
// ends through interfaces of its own (the monitor does not import the gateway client): the client
// must keep implementing them.
var (
	_ loginCounter  = (*gateway.Client)(nil)
	_ loginCooldown = (*gateway.CooldownError)(nil)
)

// gwTestCode is the imitation's access code (made up).
const gwTestCode = "Zq7#x9!Lm2"

var reTestNonce = regexp.MustCompile(`(name="nonce" value=")[0-9a-f]+(")`)

// loginGateway imitates the BGW320: events.ha and nattable.ha behind the login (cookie handshake,
// nonce, MD5(code + nonce)), the events form with its nonce. natStatus, when set, is how
// nattable.ha answers an authenticated session.
type loginGateway struct {
	t testing.TB

	mu         sync.Mutex
	sessions   map[string]*loginSession
	bbevent    bool
	natStatus  int
	loginPosts int
	requests   []string
}

type loginSession struct {
	authed                  bool
	loginNonce, eventsNonce string
}

func newLoginGateway(t testing.TB, bbevent bool) (*loginGateway, *httptest.Server) {
	g := &loginGateway{t: t, sessions: map[string]*loginSession{}, bbevent: bbevent}
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)
	return g, srv
}

func (g *loginGateway) fixture(name string) []byte {
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "gateway", name))
	if err != nil {
		g.t.Fatal(err)
	}
	return b
}

func randomNonce() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (g *loginGateway) session(w http.ResponseWriter, r *http.Request) (*loginSession, bool) {
	if c, err := r.Cookie("SessionID"); err == nil {
		if s, ok := g.sessions[c.Value]; ok {
			return s, false
		}
	}
	id := randomNonce()[:16]
	s := &loginSession{}
	g.sessions[id] = s
	http.SetCookie(w, &http.Cookie{Name: "SessionID", Value: id, Path: "/"})
	return s, true
}

func (g *loginGateway) write(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (g *loginGateway) loginPage(w http.ResponseWriter, s *loginSession, fresh bool) {
	if fresh {
		g.write(w, http.StatusOK, g.fixture("login_handshake1.html"))
		return
	}
	s.loginNonce = randomNonce()
	g.write(w, http.StatusOK, reTestNonce.ReplaceAll(g.fixture("login_nonce.html"), []byte("${1}"+s.loginNonce+"${2}")))
}

func (g *loginGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.requests = append(g.requests, r.Method+" "+r.URL.Path)
	page := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/cgi-bin/"), ".ha")
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r.Body)
	form, _ := url.ParseQuery(buf.String())
	switch {
	case r.Method == http.MethodGet && (page == "events" || page == "nattable" || page == "login"):
		s, fresh := g.session(w, r)
		switch {
		case !s.authed || page == "login":
			g.loginPage(w, s, fresh)
		case page == "events":
			s.eventsNonce = randomNonce()
			name := "events_unchecked.html"
			if g.bbevent {
				name = "events_checked.html"
			}
			g.write(w, http.StatusOK, reTestNonce.ReplaceAll(g.fixture(name), []byte("${1}"+s.eventsNonce+"${2}")))
		case g.natStatus != 0:
			g.write(w, g.natStatus, []byte("<html><body>error</body></html>"))
		default:
			g.write(w, http.StatusOK, g.fixture("nattable_synthetic.html"))
		}
	case r.Method == http.MethodPost && page == "login":
		g.loginPosts++
		s, fresh := g.session(w, r)
		sum := md5.Sum([]byte(gwTestCode + s.loginNonce))
		ok := !fresh && s.loginNonce != "" && form.Get("nonce") == s.loginNonce && form.Get("hashpassword") == hex.EncodeToString(sum[:])
		s.loginNonce = ""
		if !ok {
			g.loginPage(w, s, false)
			return
		}
		s.authed = true
		w.Header().Set("Location", "/cgi-bin/events.ha")
		g.write(w, http.StatusFound, nil)
	case r.Method == http.MethodPost && page == "events":
		s, fresh := g.session(w, r)
		if fresh || !s.authed {
			g.loginPage(w, s, fresh)
			return
		}
		if form.Get("nonce") == s.eventsNonce && form.Get("Save") == "Save" {
			g.bbevent = form.Get("bbevent") == "on"
		}
		w.Header().Set("Location", "/cgi-bin/events.ha")
		g.write(w, http.StatusFound, nil)
	default:
		g.write(w, http.StatusNotFound, []byte("not found"))
	}
}

// posts returns the login forms posted so far.
func (g *loginGateway) posts() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.loginPosts
}

// realGateway is the rig's fake gateway with the real client's authenticated operations.
type realGateway struct {
	*fakeGateway
	c *gateway.Client
}

func (g *realGateway) Notification(ctx context.Context) (bool, []byte, error) {
	return g.c.Notification(ctx)
}
func (g *realGateway) SetNotification(ctx context.Context, on bool) ([]byte, []byte, error) {
	return g.c.SetNotification(ctx, on)
}
func (g *realGateway) NATTable(ctx context.Context) (model.NATTable, []byte, error) {
	return g.c.NATTable(ctx)
}
func (g *realGateway) LoginAttempts() uint64 { return g.c.LoginAttempts() }

// realRig is a rig whose gateway client is the real one (code: its access code; policy, when not
// nil, the login policy it restores and saves), talking to srv, with a connection store; the
// monitor keeps its state in stateDir and records in led (nil: a new ledger).
func realRig(t *testing.T, srv *httptest.Server, code string, policy *gateway.LoginPolicy, stateDir string, led *fakeLedger) *rig {
	t.Helper()
	opts := gateway.Options{Host: strings.TrimPrefix(srv.URL, "http://"), Scheme: "http", Timeout: 5 * time.Second,
		AccessCode: func() (string, error) { return code, nil }}
	if policy != nil {
		opts.LoginPolicy = *policy
		opts.OnLoginPolicy = func(p gateway.LoginPolicy) { *policy = p }
	}
	c := testConfig()
	c.Gateway.EnforceNotificationOff = true
	c.Connections.Interval = config.D(4 * time.Minute)
	store := &fakeConnStore{usage: model.ConnStoreUsage{KeepDays: 30, KeepMB: 200}}
	real := &realGateway{fakeGateway: &fakeGateway{}, c: gateway.New(opts)}
	r := newRigWith(t, c, led, func(o *Options) {
		o.Gateway, o.Conns = real, store
		if stateDir != "" {
			o.StateDir = stateDir
		}
	})
	r.gw = real.fakeGateway
	r.cfg.Gateway.AccessCodeProtected = "protected-blob"
	r.m.conns.natFirst = 20 * time.Millisecond
	return r
}

// TestNATFailureAmongTheSettingsRequests: a NAT read that fails (HTTP 500) between the settings
// check's read of the redirect setting and the change that enforces it leaves the login session to
// the change, which follows within seconds: the change is verified, with one login in all - not
// refused by the one-a-minute limit and recorded as failed.
func TestNATFailureAmongTheSettingsRequests(t *testing.T) {
	for _, status := range []int{0, http.StatusInternalServerError} {
		g, srv := newLoginGateway(t, true)
		g.natStatus = status
		r := realRig(t, srv, gwTestCode, nil, "", nil)
		ctx := context.Background()
		read, natDone := make(chan struct{}), make(chan struct{})
		var once sync.Once
		r.led.onAppend = func(b model.Body) {
			if b.Type == model.TypeGatewayEvent {
				once.Do(func() {
					close(read)
					select { // the NAT round waiting for the gateway lock goes first
					case <-natDone:
					case <-time.After(10 * time.Second):
					}
				})
			}
		}
		go func() {
			<-read
			r.m.sampleNAT(ctx)
			close(natDone)
		}()
		if err := r.m.checkNotification(ctx); err != nil {
			t.Fatalf("NAT status %d: the settings check: %v", status, err)
		}
		<-natDone
		var result string
		for _, b := range ofType(r.led.records(""), model.TypeConfigChange) {
			result = decode[model.ConfigChange](t, b).Result
		}
		g.mu.Lock()
		on := g.bbevent
		g.mu.Unlock()
		if result != "verified" || on || g.posts() != 1 {
			t.Fatalf("NAT status %d: the change %q, redirect still on %v, %d logins", status, result, on, g.posts())
		}
	}
}

// TestRestartLoopMakesNoNewLogins: a service restarting again and again - the service manager
// restarts it after a failure - with an access code the gateway rejects makes one rejected login in
// all: the gateway client's login policy and the NAT reads' stop outlive each run, and the first
// NAT read of a run waits for its startup settings check. With a settings check made just before
// the restarts (which defers the startup check), no login at all.
func TestRestartLoopMakesNoNewLogins(t *testing.T) {
	for _, recent := range []bool{false, true} {
		g, srv := newLoginGateway(t, false)
		var policy gateway.LoginPolicy
		stateDir := t.TempDir()
		for start := range 4 {
			led := newFakeLedger("run-current")
			if recent {
				// The ledger says the redirect setting was checked just now: the startup check waits
				// for its 10-minute floor.
				if _, err := led.Append(model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvNotificationSetting, After: "off"}); err != nil {
					t.Fatal(err)
				}
			}
			r := realRig(t, srv, "wrong-code", &policy, stateDir, led)
			r.m.notifMinInterval = 10 * time.Minute
			stop := r.start(t)
			time.Sleep(300 * time.Millisecond) // a NAT round would have come 20 ms after the start
			if err := stop(); err != nil {
				t.Fatal(err)
			}
			if n, want := g.posts(), map[bool]int{false: 1, true: 0}[recent]; n > want {
				t.Fatalf("recent check %v: %d rejected logins after %d starts, want %d at most", recent, n, start+1, want)
			}
		}
	}
}
