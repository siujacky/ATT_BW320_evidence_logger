package ipintel

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestPrettyOrg(t *testing.T) {
	cases := []struct{ desc, want string }{
		// A handle, then the company.
		{"WPL-AS-AP Wirefreebroadband Pty Ltd", "Wirefreebroadband"},
		{"AS-ENECOM Energia Communications,Inc.", "Energia Communications"},
		{"TOT-NET TOT Public Company Limited", "TOT"},
		{"TOT-NET TOT PUBLIC COMPANY LIMITED", "TOT"},
		{"EXAMPLE-NET-AP Example Networks Co., Ltd.", "Example Networks"},
		{"ASN-TELSTRA Telstra Corporation Ltd", "Telstra"},
		{"ZEN-AS Zen Internet Ltd", "Zen Internet"},
		{"BBIL-AP BHARTI Airtel Ltd.", "BHARTI Airtel"},
		{"VECTANT ARTERIA Networks Corporation", "ARTERIA Networks"},
		{"OCN NTT Communications Corporation", "NTT Communications"},
		{"KPN KPN National", "KPN National"},
		{"EXAMPLE - Example Company Inc.", "Example Company"},
		{"EXAMPLE-AS ,", "Example"},
		// A handle alone.
		{"HETZNER-AS", "Hetzner"},
		{"AMAZON-02", "Amazon"},
		{"CLOUDFLARENET", "Cloudflare"},
		{"DIGITALOCEAN-ASN", "Digitalocean"},
		{"AS-CHOOPA", "Choopa"},
		{"COMCAST-7922", "Comcast"},
		{"TWC-11426-CAROLINAS", "TWC Carolinas"},
		{"QUAD9-AS-1", "Quad9"},
		{"AKAMAI-ASN1", "Akamai"},
		{"VALVE-CORPORATION", "Valve"},
		{"NTT-LTD-2914", "NTT"},
		{"CNNIC-ALIBABA-CN-NET-AP", "Cnnic Alibaba"},
		{"MICROSOFT-CORP-MSN-AS-BLOCK", "Microsoft Corp MSN"},
		{"ATT-INTERNET4", "ATT Internet4"},
		{"LEVEL3", "Level3"},
		{"OVH", "OVH"},
		{"PLANET", "Planet"},     // NET is part of the name
		{"INTERNET", "Internet"}, // too
		{"AS", "AS"},
		// A company.
		{"Telefonica Brasil S.A", "Telefonica Brasil"},
		{"TELMEX COLOMBIA S.A.", "Telmex Colombia"},
		{"CLARO S.A.", "Claro"},
		{"SHENZHEN TENCENT COMPUTER SYSTEMS COMPANY LIMITED", "Shenzhen Tencent Computer Systems"},
		{"IBM Cloud", "IBM Cloud"},
		{"Akamai International B.V.", "Akamai International"},
		{"Hurricane Electric LLC", "Hurricane Electric"},
		{"Example GmbH & Co. KG", "Example"},
		{"Example Telecom, US", "Example Telecom"},
		{"Example Sp. z o.o.", "Example"},
		{"Example S. de R.L. de C.V.", "Example"},
		{"Example Ltda.", "Example"},
		{"1&1 Versatel Deutschland GmbH", "1&1 Versatel Deutschland"},
		{"ÉXAMPLE TÉLÉCOM", "Éxample Télécom"},
		{"akamai", "akamai"},
		{"Limited", "Limited"}, // never the last word
		// Nothing left.
		{"", ""},
		{"   ", ""},
		{"-", ""},
		{", ,", ""},
	}
	for _, c := range cases {
		if got := prettyOrg(c.desc); got != c.want {
			t.Errorf("prettyOrg(%q) = %q, want %q", c.desc, got, c.want)
		}
	}
}

func TestPrettyOrgLong(t *testing.T) {
	desc := "Example Very Long Name Of A Network Operator That Goes On And On For Ever And Ever Networks"
	got := prettyOrg(desc)
	if n := utf8.RuneCountInString(got); n > maxOrgRunes || !strings.HasSuffix(got, "…") {
		t.Fatalf("prettyOrg(long) = %q (%d runes)", got, n)
	}
	if !strings.HasPrefix(desc, strings.TrimSuffix(got, "…")) || strings.HasSuffix(strings.TrimSuffix(got, "…"), " ") {
		t.Fatalf("prettyOrg(long) = %q: not cut at a word", got)
	}
	word := strings.Repeat("X", 100)
	if got := prettyOrg(word); utf8.RuneCountInString(got) != maxOrgRunes {
		t.Fatalf("prettyOrg(one long word) = %q", got)
	}
}

func TestOrgName(t *testing.T) {
	cases := []struct {
		asn  uint32
		desc string
		want string
	}{
		{15169, "GOOGLE", "Google"},
		{36040, "YOUTUBE", "Google"},
		{16509, "AMAZON-02", "Amazon"},
		{2906, "AS-SSI", "Netflix"},
		{8075, "MICROSOFT-CORP-MSN-AS-BLOCK", "Microsoft"},
		{7018, "ATT-INTERNET4", "AT&T"},
		{32934, "FACEBOOK", "Meta"},
		{4134, "CHINANET-BACKBONE No.31,Jin-rong Street", "Chinanet"},
		{20473, "AS-CHOOPA", "Vultr"},
		{64496, "", "AS64496"},
		{64496, "-", "AS64496"},
		{0, "", ""},
	}
	for _, c := range cases {
		if got := orgName(c.asn, c.desc); got != c.want {
			t.Errorf("orgName(%d, %q) = %q, want %q", c.asn, c.desc, got, c.want)
		}
	}
}

func TestKnownOrgList(t *testing.T) {
	seen := map[uint32]string{}
	for _, o := range knownOrgList {
		if o.name == "" || len(o.asns) == 0 {
			t.Errorf("empty entry %+v", o)
		}
		for _, asn := range o.asns {
			if prev, dup := seen[asn]; dup {
				t.Errorf("AS%d is both %q and %q", asn, prev, o.name)
			}
			if asn == 0 || (asn >= 64496 && asn <= 65535) || asn >= 4200000000 {
				t.Errorf("AS%d (%s) is not a public AS number", asn, o.name)
			}
			seen[asn] = o.name
		}
	}
	if len(knownOrgs) != len(seen) {
		t.Fatalf("knownOrgs has %d entries, the list %d", len(knownOrgs), len(seen))
	}
}
