package ipintel

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"attmonitor/internal/model"
)

func TestLookup(t *testing.T) {
	d := loadedTables(t, gzRows(rows4), gzRows(rows6))
	cf := model.IPInfo{Kind: model.IPKindPublic, ASN: 13335, Org: "Cloudflare", ASName: "CLOUDFLARENET", Country: "US"}
	goog := model.IPInfo{Kind: model.IPKindPublic, ASN: 15169, Org: "Google", ASName: "GOOGLE", Country: "US"}
	wpl := model.IPInfo{Kind: model.IPKindPublic, ASN: 38803, Org: "Wirefreebroadband", ASName: "WPL-AS-AP Wirefreebroadband Pty Ltd", Country: "AU"}
	public := model.IPInfo{Kind: model.IPKindPublic}
	cases := []struct {
		addr string
		want model.IPInfo
	}{
		{"0.255.255.255", model.IPInfo{Kind: model.IPKindReserved}},
		{"1.0.0.0", cf}, // first address of the first range
		{"1.0.0.255", cf},
		{"1.0.1.0", public}, // not routed
		{"1.0.3.255", public},
		{"1.0.4.0", wpl},
		{"1.0.7.255", wpl},
		{"1.0.8.0", public}, // a gap: no line at all
		{"1.1.1.1", cf},
		{"8.8.4.4", goog},
		{"8.8.6.1", public},
		{"8.8.8.8", goog},
		{"8.8.8.255", goog},
		{"8.8.9.0", public},
		{"9.9.9.9", model.IPInfo{Kind: model.IPKindPublic, ASN: 19281, Org: "Quad9", ASName: "QUAD9-AS-1", Country: "US"}},
		{"223.255.255.255", model.IPInfo{Kind: model.IPKindPublic, ASN: 64499, Org: "Example Networks",
			ASName: "EXAMPLE-NET-AP Example Networks Co., Ltd.", Country: "JP"}},
		// Documentation ranges are in the table but never looked up.
		{"192.0.2.1", model.IPInfo{Kind: model.IPKindReserved}},
		{"198.51.100.1", model.IPInfo{Kind: model.IPKindReserved}},
		{"203.0.113.1", model.IPInfo{Kind: model.IPKindReserved}},
		{"192.168.1.20", model.IPInfo{Kind: model.IPKindPrivate}},
		{"100.64.0.1", model.IPInfo{Kind: model.IPKindShared}},
		// IPv4-mapped and NAT64 addresses are named from the IPv4 table.
		{"::ffff:8.8.8.8", goog},
		{"64:ff9b::101:101", cf},
		// IPv6
		{"2001:4860::", goog},
		{"2001:4860:4860::8888", goog},
		{"2001:4860:ffff:ffff:ffff:ffff:ffff:ffff", goog},
		{"2001:4861::1", public},
		{"2606:4700:4700::1111", cf},
		{"2a00:1450:4001:80b::200e", goog},
		{"2a00:1451::1", public},
		{"2001:db8::1", model.IPInfo{Kind: model.IPKindReserved}},
		{"fe80::1%eth0", model.IPInfo{Kind: model.IPKindLinkLocal}},
	}
	for _, c := range cases {
		if got := d.Lookup(mustAddr(t, c.addr)); got != c.want {
			t.Errorf("Lookup(%s) = %+v, want %+v", c.addr, got, c.want)
		}
	}
	st := d.Status()
	if !st.Loaded || st.V4Ranges != 10 || st.V6Ranges != 4 || st.Updated == "" || st.Error != "" || st.Download {
		t.Fatalf("status %+v", st)
	}
}

func TestLookupBeforeLoad(t *testing.T) {
	d := openTest(t, t.TempDir(), Options{})
	if got := d.Lookup(mustAddr(t, "8.8.8.8")); got != (model.IPInfo{Kind: model.IPKindPublic}) {
		t.Fatalf("before load: %+v", got)
	}
	if got := d.Lookup(mustAddr(t, "10.1.2.3")); got.Kind != model.IPKindPrivate {
		t.Fatalf("before load: %+v", got)
	}
	if !d.Updated().IsZero() || d.Status().Loaded {
		t.Fatal("loaded before Run")
	}
	// Only one family loaded: the other is classified only.
	d.install(&loaded{fam: fam6, t6: mustParse6(t, rows6), at: t0})
	if got := d.Lookup(mustAddr(t, "8.8.8.8")); got.ASN != 0 {
		t.Fatalf("v4 without a v4 table: %+v", got)
	}
	if got := d.Lookup(mustAddr(t, "2001:4860::1")); got.ASN != 15169 {
		t.Fatalf("v6: %+v", got)
	}
	if !d.Updated().Equal(t0) {
		t.Fatalf("Updated %v", d.Updated())
	}
}

// mustParse6 builds an IPv6 table from rows.
func mustParse6(t *testing.T, rows []row) *table[u128] {
	t.Helper()
	l, err := parseGzip(context.Background(), bytesReader(gzRows(rows)), fam6)
	if err != nil {
		t.Fatal(err)
	}
	return l.t6
}

func TestDisabled(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "geo")
	r := newFakeResolver()
	d, err := Open(dir, Options{Enabled: false, Download: true, ReverseDNS: true, Resolver: r, URLv4: "http://not-checked"})
	if err != nil {
		t.Fatal(err)
	}
	if got := d.Lookup(mustAddr(t, "8.8.8.8")); got != (model.IPInfo{Kind: model.IPKindPublic}) {
		t.Fatalf("Lookup %+v", got)
	}
	if got := d.Lookup(mustAddr(t, "fd00::1")); got.Kind != model.IPKindPrivate {
		t.Fatalf("Lookup %+v", got)
	}
	if got := d.PTR(mustAddr(t, "8.8.8.8"), true); got != "" {
		t.Fatalf("PTR %q", got)
	}
	if got := d.Service("tcp", 443); got != "HTTPS" {
		t.Fatalf("Service %q", got)
	}
	if st := d.Status(); st != (model.IPIntelStatus{}) {
		t.Fatalf("status %+v", st)
	}
	stop := startRun(t, d)
	time.Sleep(20 * time.Millisecond)
	stop()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("the disabled DB made its directory: %v", err)
	}
	if r.count("") != 0 {
		t.Fatal("the disabled DB looked an address up")
	}
	// A nil DB classifies too.
	var nilDB *DB
	if got := nilDB.Lookup(mustAddr(t, "127.0.0.1")); got.Kind != model.IPKindLoopback {
		t.Fatalf("nil Lookup %+v", got)
	}
	if nilDB.PTR(mustAddr(t, "8.8.8.8"), true) != "" || !nilDB.Updated().IsZero() || nilDB.Status().Enabled {
		t.Fatal("nil DB")
	}
}

func TestOpenErrors(t *testing.T) {
	if _, err := Open("", Options{Enabled: true}); err == nil {
		t.Error("enabled without a directory")
	}
	// A query is refused like credentials (the configuration is recorded in the evidence ledger:
	// a mirror's "?token=" would be kept for ever); the error repeats neither.
	for _, u := range []string{"http://iptoasn.com/data/ip2asn-v4.tsv.gz", "ftp://example.com/x", "https://",
		"https://user:secret@example.com/x", "https://example.com/x#frag", "::not a url",
		"https://mirror.example.com/a.gz?k=secret", "https://mirror.example.com/a.gz?token=secret-token", "https://mirror.example.com/a.gz?"} {
		_, err := Open(t.TempDir(), Options{Enabled: true, Download: true, URLv4: u})
		if err == nil {
			t.Errorf("Open accepted %q", u)
		} else if containsAny(err.Error(), "secret") {
			t.Errorf("the error shows the password or the query: %v", err)
		}
	}
	// Without Download the URLs are not used.
	if _, err := Open(t.TempDir(), Options{Enabled: true, URLv4: "http://example.com/x"}); err != nil {
		t.Errorf("without Download: %v", err)
	}
	d, err := Open(t.TempDir(), Options{Enabled: true, Download: true, Refresh: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if d.refresh != MinRefresh || d.urls != [2]string{DefaultURLv4, DefaultURLv6} || d.Status().Source != "IPtoASN (iptoasn.com)" {
		t.Errorf("defaults: refresh %v, urls %v, source %q", d.refresh, d.urls, d.Status().Source)
	}
	if d, _ := Open(t.TempDir(), Options{Enabled: true, Refresh: -time.Hour}); d.refresh != DefaultRefresh {
		t.Errorf("negative refresh → %v", d.refresh)
	}
}
