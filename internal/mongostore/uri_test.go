package mongostore

import (
	"bytes"
	"context"
	"encoding/base64"
	"log/slog"
	"math"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"attmonitor/internal/model"
)

func TestRedactURI(t *testing.T) {
	cases := []struct{ in, want string }{
		{"mongodb://127.0.0.1:27017", "mongodb://127.0.0.1:27017"},
		{"mongodb://127.0.0.1:27017/?directConnection=true", "mongodb://127.0.0.1:27017/?directConnection=true"},
		{"mongodb://user:s3cret@127.0.0.1:27017/?authSource=admin", "mongodb://127.0.0.1:27017/?authSource=admin"},
		{"mongodb://onlyuser@host", "mongodb://host"},
		{"mongodb+srv://u:p%40ss@cluster0.example.net/db?retryWrites=true", "mongodb+srv://cluster0.example.net/db?retryWrites=true"},
		{"mongodb://u:p@ss@host:27017/db", "mongodb://host:27017/db"},  // malformed: unescaped "@" in the password
		{"mongodb://u:p?ss@host:27017/db", "mongodb://host:27017/db"},  // "?" inside the password (the driver accepts it)
		{"mongodb://u:pa/ss@host:27017/db", "mongodb://host:27017/db"}, // malformed: unescaped "/"
		{"mongodb://h1:1,h2:2/?replicaSet=rs", "mongodb://h1:1,h2:2/?replicaSet=rs"},
		{"mongodb://host/?tlsCertificateKeyFilePassword=hunter2&appName=x", "mongodb://host/?tlsCertificateKeyFilePassword=***&appName=x"},
		{"mongodb://host/?authMechanism=MONGODB-AWS&authMechanismProperties=AWS_SESSION_TOKEN:tok3n", "mongodb://host/?authMechanism=MONGODB-AWS&authMechanismProperties=***"},
		{"http://user:pw@host", "(not a MongoDB URI)"},
		{"", "(not a MongoDB URI)"},
	}
	for _, c := range cases {
		got := RedactURI(c.in)
		if got != c.want {
			t.Errorf("RedactURI(%q) = %q, want %q", c.in, got, c.want)
		}
		for _, secret := range []string{"s3cret", "p%40ss", "hunter2", "tok3n", "pw", "ss@", "pa/"} {
			if strings.Contains(got, secret) {
				t.Errorf("RedactURI(%q) = %q leaks %q", c.in, got, secret)
			}
		}
	}
}

// TestRedactURISeparatorsAndEscapes: the driver also separates options with ";" and unescapes
// option keys; a secret must not slip through either way.
func TestRedactURISeparatorsAndEscapes(t *testing.T) {
	cases := []struct{ in, want string }{
		{"mongodb://127.0.0.1:27017/?appName=x;tlsCertificateKeyFilePassword=hunter2", "mongodb://127.0.0.1:27017/?appName=x;tlsCertificateKeyFilePassword=***"},
		{"mongodb://h/?tlsCertificateKeyFilePa%73sword=hunter2%zz&appName=y", "mongodb://h/?tlsCertificateKeyFilePa%73sword=***&appName=y"},
		{"mongodb://h/?pass%zzword=hunter2;appName=y", "mongodb://h/?pass%zzword=***;appName=y"}, // a key that cannot be unescaped
		{"mongodb://h/?authmechanismproperties=AWS_SESSION_TOKEN:hunter2;w=1&appName=z", "mongodb://h/?authmechanismproperties=***;w=1&appName=z"},
		{"mongodb://h/?a=1;b=2&c=3;", "mongodb://h/?a=1;b=2&c=3;"},
		{"mongodb://h/?tls+Password=hunter2", "mongodb://h/?tls+Password=***"}, // "+" unescapes to a space
	}
	for _, c := range cases {
		if got := RedactURI(c.in); got != c.want || strings.Contains(got, "hunter2") {
			t.Errorf("RedactURI(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	for _, uri := range []string{
		"mongodb://127.0.0.1:1/?tlsCertificateKeyFilePa%73sword=hunter2%zz",
		"mongodb://127.0.0.1:1/?appName=x;tlsCertificateKeyFilePassword=hunter2%zz",
	} {
		_, err := New(Options{Reader: &memReader{}, URI: uri})
		if err == nil || strings.Contains(err.Error(), "hunter2") {
			t.Errorf("New(%q): %v", uri, err)
		}
	}
}

// TestSRVParseErrorWithheld: the driver parses a mongodb+srv URI only when connecting and quotes
// option values in its errors; with a secret in the URI, neither the status, the log, nor the
// errors of SyncOnce and Verify may show it.
func TestSRVParseErrorWithheld(t *testing.T) {
	const uri = "mongodb+srv://cluster0.example.invalid/?authMechanism=MONGODB-AWS&authMechanismProperties=AWS_SESSION_TOKEN:hunter2%zz"
	var logs bytes.Buffer
	r, err := New(Options{Reader: &memReader{}, URI: uri, ConnectTimeout: 200 * time.Millisecond,
		Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(context.Background())
	_, err = r.SyncOnce(context.Background())
	if err == nil {
		t.Fatal("SyncOnce succeeded")
	}
	st := r.Status()
	for what, s := range map[string]string{"error": err.Error(), "LastError": st.LastError, "URI": st.URI, "log": logs.String()} {
		if strings.Contains(s, "hunter2") {
			t.Errorf("%s shows the secret: %q", what, s)
		}
	}
	if !strings.Contains(st.LastError, "details withheld") {
		t.Errorf("LastError %q", st.LastError)
	}
	if _, err := Verify(context.Background(), uri, "attmonitor_test_srv", &memReader{}, nil); err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("Verify: %v", err)
	}
}

func TestPrintableAndShort(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain text é … 😀", "plain text é … 😀"},
		{"a\x1b[2Kb\r\n\tc", `a\x1b[2Kb\r\n\tc`},
		{"bidi\u202eoverride\u2028", `bidi\u202eoverride\u2028`},
		{"bad\xffutf8\x7f", `bad\xffutf8\x7f`},
		{"\u0085next line", `\u0085next line`},
	}
	for _, c := range cases {
		if got := printable(c.in); got != c.want {
			t.Errorf("printable(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := short("\x1b[2Kforged"); got != `"\x1b[2Kforged"` {
		t.Errorf("short of a non-hash = %q", got)
	}
	if got := short(strings.Repeat("ab", 40)); got != strings.Repeat("ab", 8)+"…" {
		t.Errorf("short of a hash = %q", got)
	}
}

func TestNumericSeq(t *testing.T) {
	for _, c := range []struct {
		v    any
		want uint64
		ok   bool
	}{
		{int64(5), 5, true}, {int32(5), 5, true}, {5.0, 5, true}, {5.5, 0, false}, {-1.0, 0, false},
		{int64(-1), 0, false}, {"5", 0, false}, {math.Inf(1), 0, false},
	} {
		raw := mustMarshal(t, bson.D{{Key: "v", Value: c.v}})
		got, ok := numericSeq(raw.Lookup("v"))
		if got != c.want || ok != c.ok {
			t.Errorf("numericSeq(%v) = %d, %v", c.v, got, ok)
		}
	}
}

func TestAuthenticGenesis(t *testing.T) {
	pub, priv := testKey(t)
	body := realBodies(t)[0]
	body.Data = dataOf(t, model.Genesis{PublicKey: base64.StdEncoding.EncodeToString(pub), Fingerprint: fingerprintOf(pub),
		Created: "2026-10-05T03:20:00Z", Statement: "genesis"})
	g := signedRecord(t, priv, body) // a genesis record naming the key that signed it
	doc := func(it item) bson.Raw {
		return mustMarshal(t, bson.D{{Key: "h", Value: it.env.H}, {Key: "s", Value: it.env.S}, {Key: "b", Value: it.env.B}})
	}
	if fp, ok := authenticGenesis(doc(g)); !ok || fp != fingerprintOf(pub) {
		t.Fatalf("authentic genesis: %q %v", fp, ok)
	}
	// Signed by a key other than the one it names, altered, not a genesis record, not seq 0.
	_, other := testKey(t)
	notGenesis, notZero := body, body
	notGenesis.Type = model.TypeSample
	notZero.Seq = 1
	bad := []item{signedRecord(t, other, body), g, signedRecord(t, priv, notGenesis), signedRecord(t, priv, notZero)}
	bad[1].env.H = sha256Hex([]byte("x"))
	for i, it := range bad {
		if _, ok := authenticGenesis(doc(it)); ok {
			t.Errorf("case %d authenticates", i)
		}
	}
}

func TestCheckURI(t *testing.T) {
	for _, ok := range []string{
		DefaultURI,
		"mongodb://127.0.0.1:27017/?directConnection=true&serverSelectionTimeoutMS=500",
		"mongodb://localhost",
		"mongodb+srv://cluster0.example.invalid/?retryWrites=true", // not resolved here
		"mongodb+srv://u:p@cluster0.example.invalid",
	} {
		if err := checkURI(ok); err != nil {
			t.Errorf("checkURI(%q): %v", ok, err)
		}
	}
	for _, bad := range []string{
		"", "http://127.0.0.1:27017", "mongodb://", "mongodb://host:notaport", "mongodb://host?x=1",
		"mongodb+srv://", "mongodb+srv://a.example,b.example", "mongodb+srv://a.example:27017",
	} {
		if err := checkURI(bad); err == nil {
			t.Errorf("checkURI(%q) accepted", bad)
		}
	}
	err := checkURI("mongodb://user:hunter2@host:notaport")
	if err == nil || strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "user") {
		t.Errorf("error for a URI with credentials: %v", err)
	}
}

func TestCheckDatabaseName(t *testing.T) {
	for _, ok := range []string{"attmonitor", "attmonitor_test_0a1b", "A-b_c", strings.Repeat("x", 63)} {
		if err := checkDatabaseName(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "a b", "a.b", "a$b", `a\b`, "a/b", `a"b`, "a*b", "a<b", "a>b", "a:b", "a|b", "a?b", "a\x00b", strings.Repeat("x", 64)} {
		if err := checkDatabaseName(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestNewValidatesAndDefaults(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("New without a reader")
	}
	reader := &memReader{}
	if _, err := New(Options{Reader: reader, URI: "postgres://x"}); err == nil {
		t.Fatal("bad scheme accepted")
	}
	if _, err := New(Options{Reader: reader, Database: "bad name"}); err == nil {
		t.Fatal("bad database accepted")
	}
	r, err := New(Options{Reader: reader, BatchSize: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	if r.o.URI != DefaultURI || r.o.Database != DefaultDatabase || r.o.Interval != 5*time.Second ||
		r.o.BatchSize != maxBatchSize || r.o.ConnectTimeout != 3*time.Second || r.o.Logger == nil || r.o.Now == nil {
		t.Errorf("defaults: %+v", r.o)
	}
	r, err = New(Options{Reader: reader})
	if err != nil || r.o.BatchSize != 500 {
		t.Fatalf("default batch size: %v %d", err, r.o.BatchSize)
	}
	// An SRV URI is not resolved by New (DNS may be down while the service starts).
	start := time.Now()
	r, err = New(Options{Reader: reader, URI: "mongodb+srv://user:hunter2@cluster0.example.invalid/"})
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("New took %v", d)
	}
	st := r.Status()
	if !st.Enabled || st.Connected || st.Database != DefaultDatabase || st.URI != "mongodb+srv://cluster0.example.invalid/" ||
		st.HasData || st.LastSeq != 0 || st.Lag != 0 || st.LastSync != "" || st.LastError != "" {
		t.Errorf("initial status %+v", st)
	}
}

func TestStatusLagAndErrors(t *testing.T) {
	r, err := New(Options{Reader: &memReader{}})
	if err != nil {
		t.Fatal(err)
	}
	set := func(f func(*replState)) model.MongoStatus {
		r.mu.Lock()
		f(&r.st)
		r.mu.Unlock()
		return r.Status()
	}
	if s := set(func(s *replState) { s.head, s.headKnown = 9, true }); s.Lag != 0 {
		t.Errorf("lag before the copy's resume point is known = %d, want 0", s.Lag)
	}
	if s := set(func(s *replState) { s.resumeKnown = true }); s.Lag != 10 {
		t.Errorf("lag with nothing copied = %d, want 10", s.Lag)
	}
	if s := set(func(s *replState) { s.hasData, s.lastSeq = true, 4 }); s.Lag != 5 {
		t.Errorf("lag = %d, want 5", s.Lag)
	}
	if s := set(func(s *replState) { s.lastSeq = 12 }); s.Lag != 0 {
		t.Errorf("lag with the copy ahead = %d", s.Lag)
	}
	if s := set(func(s *replState) { s.lastErr = "down" }); s.LastError != "down" {
		t.Errorf("LastError = %q", s.LastError)
	}
	if s := set(func(s *replState) { s.integrity = "conflict" }); s.LastError != "down; conflict" {
		t.Errorf("LastError = %q", s.LastError)
	}
	if s := set(func(s *replState) { s.lastErr = "" }); s.LastError != "conflict" {
		t.Errorf("LastError = %q", s.LastError)
	}
	when := time.Date(2026, 10, 5, 3, 20, 0, 5, time.FixedZone("x", 3600))
	if s := set(func(s *replState) { s.lastSync = when }); s.LastSync != "2026-10-05T02:20:00.000000005Z" {
		t.Errorf("LastSync = %q", s.LastSync)
	}
}
