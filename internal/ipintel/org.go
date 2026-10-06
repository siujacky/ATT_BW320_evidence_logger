package ipintel

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// knownOrgList names the networks a household talks to most (and those that scan it most) as
// people know them: an AS description such as "MICROSOFT-CORP-MSN-AS-BLOCK" or "AS-SSI" (Netflix)
// says little, and one company often has several ASes. Only ASes whose owner is certain are
// listed; the others are named by prettyOrg.
var knownOrgList = []struct {
	name string
	asns []uint32
}{
	// Content, cloud and CDN
	{"Google", []uint32{15169, 19527, 36040, 36384, 36492, 139070, 396982}},
	{"Google Fiber", []uint32{16591}},
	{"Microsoft", []uint32{3598, 8068, 8069, 8075, 12076}},
	{"LinkedIn", []uint32{14413}},
	{"GitHub", []uint32{36459}},
	{"Amazon", []uint32{7224, 8987, 14618, 16509, 38895}},
	{"Twitch", []uint32{46489}},
	{"Netflix", []uint32{2906, 40027, 55095}},
	{"Cloudflare", []uint32{13335, 132892, 209242}},
	{"Akamai", []uint32{12222, 16625, 16702, 20940, 21342, 23454, 32787, 33905, 35994}},
	{"Apple", []uint32{714, 6185}},
	{"Meta", []uint32{32934, 54115, 63293}},
	{"Fastly", []uint32{54113}},
	{"Valve", []uint32{32590}},
	{"Zoom", []uint32{30103}},
	{"Dropbox", []uint32{19679}},
	{"X (Twitter)", []uint32{13414}},
	{"ByteDance", []uint32{138699, 396986}},
	{"Oracle", []uint32{31898}},
	{"Spotify", []uint32{8403}},
	{"Yahoo", []uint32{10310}},
	{"Wikimedia", []uint32{14907}},
	{"Internet Archive", []uint32{7941}},
	{"Salesforce", []uint32{14340}},
	{"Zscaler", []uint32{22616}},
	{"Telegram", []uint32{62041}},
	{"Yandex", []uint32{13238}},
	{"Quad9", []uint32{19281}},
	{"OpenDNS", []uint32{36692}},
	{"Cisco", []uint32{109}},
	{"IBM Cloud", []uint32{36351}},
	{"DigitalOcean", []uint32{14061}},
	{"OVHcloud", []uint32{16276}},
	{"Hetzner", []uint32{24940}},
	{"Linode", []uint32{63949}},
	{"Vultr", []uint32{20473}},
	{"Leaseweb", []uint32{60781}},
	{"Contabo", []uint32{51167}},
	{"Scaleway", []uint32{12876}},
	{"IONOS", []uint32{8560}},
	{"Tencent", []uint32{45090, 132203}},
	{"Alibaba", []uint32{37963, 45102}},
	{"Huawei Cloud", []uint32{136907}},
	{"Censys", []uint32{398324, 398705, 398722}},
	// Carriers and access networks
	{"AT&T", []uint32{7018, 7132, 20057}},
	{"Comcast", []uint32{7922}},
	{"Verizon", []uint32{701, 702, 703, 6167}},
	{"Charter", []uint32{7843, 10796, 11351, 11426, 11427, 12271, 20001, 20115, 33363}},
	{"T-Mobile", []uint32{21928}},
	{"Cox", []uint32{22773}},
	{"Frontier", []uint32{5650}},
	{"Optimum", []uint32{6128}},
	{"Mediacom", []uint32{30036}},
	{"Starlink", []uint32{14593}},
	{"Hurricane Electric", []uint32{6939}},
	{"Lumen", []uint32{209, 3356, 3549}},
	{"Cogent", []uint32{174}},
	{"NTT", []uint32{2914, 4713}},
	{"Arelion", []uint32{1299}},
	{"GTT", []uint32{3257}},
	{"Zayo", []uint32{6461}},
	{"Tata Communications", []uint32{6453}},
	{"Rogers", []uint32{812}},
	{"Bell Canada", []uint32{577}},
	{"Telus", []uint32{852}},
	{"Shaw", []uint32{6327}},
	{"Deutsche Telekom", []uint32{3320}},
	{"Orange", []uint32{3215, 5511}},
	{"Vodafone", []uint32{1273, 3209}},
	{"BT", []uint32{2856}},
	{"Virgin Media", []uint32{5089}},
	{"Liberty Global", []uint32{6830}},
	{"Telefonica", []uint32{3352}},
	{"Telecom Italia", []uint32{3269}},
	{"Free", []uint32{12322}},
	{"Swisscom", []uint32{3303}},
	{"KPN", []uint32{1136}},
	{"Rostelecom", []uint32{12389}},
	{"Chinanet", []uint32{4134, 4809, 4812}},
	{"China Unicom", []uint32{4808, 4837}},
	{"China Mobile", []uint32{9808, 56040, 58453}},
	{"KT", []uint32{4766}},
	{"SK Broadband", []uint32{9318}},
	{"KDDI", []uint32{2516}},
	{"SoftBank", []uint32{17676}},
	{"Telstra", []uint32{1221}},
	{"HKT", []uint32{4760}},
	{"PCCW Global", []uint32{3491}},
	{"HGC", []uint32{9304}},
	{"HKBN", []uint32{9269}},
	{"Jio", []uint32{55836}},
	{"Airtel", []uint32{9498}},
}

// knownOrgs is knownOrgList by AS number.
var knownOrgs = func() map[uint32]string {
	m := make(map[uint32]string, 160)
	for _, o := range knownOrgList {
		for _, asn := range o.asns {
			m[asn] = o.name
		}
	}
	return m
}()

// maxOrgRunes bounds an organisation name: it labels a band of the flow diagram.
const maxOrgRunes = 64

// orgName returns the readable organisation name of AS asn, whose description is desc: the
// curated name of a well-known network, else the description tidied (prettyOrg), else "AS<n>".
func orgName(asn uint32, desc string) string {
	if o, ok := knownOrgs[asn]; ok {
		return o
	}
	if o := prettyOrg(desc); o != "" {
		return o
	}
	return asLabel(asn)
}

// asLabel names an AS by its number ("" for AS 0, which is no network).
func asLabel(asn uint32) string {
	if asn == 0 {
		return ""
	}
	return "AS" + strconv.FormatUint(uint64(asn), 10)
}

// prettyOrg turns an AS description into a readable name, deterministically. The descriptions
// come from the registries in a few shapes:
//
//	"WPL-AS-AP Wirefreebroadband Pty Ltd"  a handle, then the company: the company, without its
//	                                       legal form ("Wirefreebroadband")
//	"HETZNER-AS", "AMAZON-02"              a handle alone: its words, without the AS, NET, -02 ...
//	                                       tags, in title case ("Hetzner", "Amazon")
//	"Telefonica Brasil S.A"                a company: without its legal form ("Telefonica Brasil")
//	"TELMEX COLOMBIA S.A."                 a company in capitals: also in title case
//
// Words of three letters or fewer stay in capitals (acronyms: "NTT", "TOT"). The result has at
// most maxOrgRunes runes; "" when nothing is left.
func prettyOrg(desc string) string {
	toks := orgTokens(desc)
	if len(toks) == 0 {
		return ""
	}
	if !isHandle(toks[0]) {
		return limitRunes(joinName(finishName(toks)))
	}
	if len(toks) > 1 && dropHandle(toks[0], toks[1:]) {
		if name := finishName(toks[1:]); len(name) > 0 {
			return limitRunes(joinName(name))
		}
	} else if len(toks) > 1 {
		return limitRunes(joinName(finishName(toks)))
	}
	return handleName(toks[0])
}

// dropHandle says whether a leading handle is a registry handle in front of the company's name,
// rather than the first word of that name ("IBM Cloud"). A handle with a hyphen, underscore or
// digit always is ("TOT-NET TOT PUBLIC COMPANY LIMITED"); a plain word in capitals is when a name
// of two words or more in mixed case follows ("VECTANT ARTERIA Networks Corporation").
func dropHandle(handle string, rest []string) bool {
	if strings.ContainsAny(handle, "-_0123456789") {
		return true
	}
	return len(rest) >= 2 && anyLower(rest)
}

// orgTokens splits a description into words, a comma being a word of its own.
func orgTokens(desc string) []string {
	var toks []string
	for _, f := range strings.Fields(desc) {
		for f != "" {
			i := strings.IndexByte(f, ',')
			if i < 0 {
				toks = append(toks, f)
				break
			}
			if i > 0 {
				toks = append(toks, f[:i])
			}
			toks = append(toks, ",")
			f = f[i+1:]
		}
	}
	return toks
}

// isHandle says whether a word looks like a registry handle: capital letters, digits, hyphens
// and underscores, with at least one letter.
func isHandle(w string) bool {
	letter := false
	for i := 0; i < len(w); i++ {
		switch c := w[i]; {
		case c >= 'A' && c <= 'Z':
			letter = true
		case c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return letter
}

// handleTags are the parts of a handle that are not the name: "AS"/"ASN" (autonomous system),
// "AP" (APNIC), "NET", "BLOCK", "BACKBONE", also numbered ("AS1"), and legal forms.
var handleTags = map[string]bool{
	"AS": true, "ASN": true, "AP": true, "NET": true, "BLOCK": true, "BACKBONE": true,
}

// isHandleTag says whether the last part of a handle is a tag rather than part of the name: a
// handleTags word (optionally numbered), a number, a legal form or a two-letter country or
// region code ("-CN", "-EU").
func isHandleTag(p string) bool {
	return handleTags[strings.TrimRight(p, "0123456789")] || isDigits(p) || len(p) == 2 ||
		legalForms[strings.ToLower(p)]
}

// handleName names a handle: its parts without tags and numbers, in title case ("WPL-AS-AP" →
// "WPL", "AMAZON-02" → "Amazon", "CLOUDFLARENET" → "Cloudflare").
func handleName(h string) string {
	parts := strings.FieldsFunc(h, func(r rune) bool { return r == '-' || r == '_' })
	for len(parts) > 1 && (parts[0] == "AS" || parts[0] == "ASN") {
		parts = parts[1:]
	}
	for len(parts) > 1 && isHandleTag(parts[len(parts)-1]) {
		parts = parts[:len(parts)-1]
	}
	for i := 0; len(parts) > 1 && i < len(parts); {
		if isDigits(parts[i]) {
			parts = append(parts[:i], parts[i+1:]...)
			continue
		}
		i++
	}
	if len(parts) == 1 {
		// "CLOUDFLARENET": NET glued to a name long enough not to be part of it ("PLANET").
		if p := parts[0]; len(p) >= 9 && strings.HasSuffix(p, "NET") {
			parts[0] = strings.TrimSuffix(p, "NET")
		}
	}
	for i, p := range parts {
		parts[i] = titleWord(p)
	}
	return limitRunes(strings.Join(parts, " "))
}

// legalForms are legal forms of companies, compared without dots, commas and slashes, in lower
// case ("S.A." → "sa", "Co.,Ltd." → "coltd", "A/S" → "as").
var legalForms = map[string]bool{
	"inc": true, "incorporated": true, "llc": true, "ltd": true, "limited": true, "corp": true,
	"corporation": true, "co": true, "coltd": true, "gmbh": true, "mbh": true, "ag": true,
	"sa": true, "sas": true, "sarl": true, "sau": true, "bv": true, "nv": true, "plc": true,
	"spa": true, "srl": true, "sro": true, "as": true, "asa": true, "ab": true, "oy": true,
	"oyj": true, "aps": true, "kg": true, "kk": true, "pte": true, "pty": true, "pvt": true,
	"bhd": true, "sdn": true, "jsc": true, "ojsc": true, "pjsc": true, "cjsc": true, "ooo": true,
	"llp": true, "lp": true, "ltda": true, "sl": true, "se": true, "kft": true, "zrt": true,
	"doo": true, "sia": true, "uab": true, "ev": true,
}

// legalPhrases are legal forms of several words, compared like legalForms.
var legalPhrases = [][]string{
	{"public", "company", "limited"},
	{"company", "limited"},
	{"private", "limited"},
	{"sp", "z", "oo"},
	{"s", "de", "rl", "de", "cv"},
	{"sa", "de", "cv"},
	{"s", "de", "rl"},
}

// finishName tidies the words of a company name: no country code after a final comma, no
// legal forms or punctuation at the end, title case when it is all in capitals.
func finishName(toks []string) []string {
	if n := len(toks); n >= 3 && toks[n-2] == "," && isCountryCode(toks[n-1]) {
		toks = toks[:n-2]
	}
	toks = stripLegal(toks)
	for len(toks) > 0 && legalKey(toks[0]) == "" {
		toks = toks[1:] // leading punctuation ("- Company")
	}
	if len(toks) == 0 {
		return nil
	}
	if !anyLower(toks) {
		for i, t := range toks {
			toks[i] = titleWord(t)
		}
	}
	return toks
}

// stripLegal removes legal forms and punctuation from the end of a name, never its last word.
func stripLegal(toks []string) []string {
	for len(toks) > 1 {
		if n := legalPhraseAtEnd(toks); n > 0 && n < len(toks) {
			toks = toks[:len(toks)-n]
			continue
		}
		if k := legalKey(toks[len(toks)-1]); k == "" || legalForms[k] {
			toks = toks[:len(toks)-1]
			continue
		}
		break
	}
	return toks
}

// legalPhraseAtEnd returns the number of words of the legal phrase ending toks (0 when none).
func legalPhraseAtEnd(toks []string) int {
	for _, p := range legalPhrases {
		if len(p) > len(toks) {
			continue
		}
		tail := toks[len(toks)-len(p):]
		match := true
		for i, w := range p {
			if legalKey(tail[i]) != w {
				match = false
				break
			}
		}
		if match {
			return len(p)
		}
	}
	return 0
}

// legalKey is a word in lower case without punctuation ("" for punctuation alone).
func legalKey(w string) string {
	var b strings.Builder
	for _, r := range w {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

// titleWord puts a word in capitals into title case, after hyphens, slashes and dots too
// ("JIN-RONG" → "Jin-Rong"). A word with lower case letters, or of three letters or fewer (an
// acronym), is left as it is.
func titleWord(w string) string {
	letters := 0
	for _, r := range w {
		if unicode.IsLower(r) {
			return w
		}
		if unicode.IsLetter(r) {
			letters++
		}
	}
	if letters <= 3 {
		return w
	}
	var b strings.Builder
	start := true
	for _, r := range w {
		switch {
		case unicode.IsLetter(r):
			if start {
				b.WriteRune(unicode.ToUpper(r))
			} else {
				b.WriteRune(unicode.ToLower(r))
			}
			start = false
		default:
			b.WriteRune(r)
			start = r == '-' || r == '/' || r == '.' || r == '&' || r == '('
		}
	}
	return b.String()
}

// joinName joins the words of a name, a comma attached to the word before it.
func joinName(toks []string) string {
	var b strings.Builder
	for i, t := range toks {
		if i > 0 && t != "," {
			b.WriteByte(' ')
		}
		b.WriteString(t)
	}
	return b.String()
}

// limitRunes cuts a name longer than maxOrgRunes at a word boundary, with an ellipsis.
func limitRunes(s string) string {
	if utf8.RuneCountInString(s) <= maxOrgRunes {
		return s
	}
	cut, n := 0, 0
	for i := range s {
		if n == maxOrgRunes-1 {
			cut = i
			break
		}
		n++
	}
	if sp := strings.LastIndexByte(s[:cut], ' '); sp > 0 {
		cut = sp
	}
	return strings.TrimRight(s[:cut], " ,.-&") + "…"
}

func anyLower(toks []string) bool {
	for _, t := range toks {
		for _, r := range t {
			if unicode.IsLower(r) {
				return true
			}
		}
	}
	return false
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isCountryCode(s string) bool {
	return len(s) == 2 && s[0] >= 'A' && s[0] <= 'Z' && s[1] >= 'A' && s[1] <= 'Z'
}
