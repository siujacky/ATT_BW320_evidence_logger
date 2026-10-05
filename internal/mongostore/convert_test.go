package mongostore

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math"
	"math/rand/v2"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"attmonitor/internal/model"
)

// sameJSON reports whether the BSON value v holds the JSON value data (numbers compared by value,
// strings exactly).
func sameJSON(t testing.TB, data []byte, v bson.RawValue) bool {
	t.Helper()
	doc, err := bson.Marshal(bson.D{{Key: "d", Value: v}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	ext, err := bson.MarshalExtJSON(bson.Raw(doc), false, false)
	if err != nil {
		t.Fatalf("extjson: %v", err)
	}
	var got map[string]any
	if err := decodeNumbers(ext, &got); err != nil {
		t.Fatalf("decode %s: %v", ext, err)
	}
	var want any
	if err := decodeNumbers(data, &want); err != nil {
		t.Fatalf("decode %s: %v", data, err)
	}
	return reflect.DeepEqual(normalize(got["d"]), normalize(want))
}

func decodeNumbers(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	return dec.Decode(v)
}

// normalize turns json.Numbers into int64 (when integral and in range) or float64.
func normalize(v any) any {
	switch x := v.(type) {
	case json.Number:
		if n, err := strconv.ParseInt(string(x), 10, 64); err == nil {
			return n
		}
		f, _ := strconv.ParseFloat(string(x), 64)
		if f == math.Trunc(f) && math.Abs(f) < 1<<53 {
			return int64(f)
		}
		return f
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = normalize(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = normalize(e)
		}
		return out
	}
	return v
}

// checkRecordDoc checks a records document against the ledger record it copies.
func checkRecordDoc(t testing.TB, raw bson.Raw, it item) {
	t.Helper()
	body := it.body
	seq := int64(body.Seq)
	fail := func(field string, got any) {
		t.Helper()
		t.Errorf("seq %d (%s): field %s = %v", body.Seq, body.Type, field, got)
	}
	if v, ok := raw.Lookup("_id").Int64OK(); !ok || v != seq {
		fail("_id", raw.Lookup("_id"))
	}
	if v, ok := raw.Lookup("seq").Int64OK(); !ok || v != seq {
		fail("seq", raw.Lookup("seq"))
	}
	ts, err := time.Parse(time.RFC3339Nano, body.TS)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := raw.Lookup("ts").DateTimeOK(); !ok || v != ts.UnixMilli() {
		fail("ts", raw.Lookup("ts"))
	}
	for key, want := range map[string]string{"ts_text": body.TS, "type": body.Type, "run": body.Run, "prev": body.Prev, "h": it.env.H, "s": it.env.S, "b": it.env.B} {
		if got, ok := rawString(raw, key); !ok || got != want {
			fail(key, clip(got, 80))
		}
	}
	if v, ok := raw.Lookup("mono").Int64OK(); !ok || v != body.Mono {
		fail("mono", raw.Lookup("mono"))
	}
	if v, ok := raw.Lookup("v").Int64OK(); !ok || v != int64(body.V) {
		fail("v", raw.Lookup("v"))
	}
	if v, ok := raw.Lookup("copy_format").Int32OK(); !ok || v != copyFormat {
		fail("copy_format", raw.Lookup("copy_format"))
	}
	if len(body.Blobs) == 0 {
		if _, err := raw.LookupErr("blobs"); err == nil {
			fail("blobs", "present")
		}
	} else {
		arr, ok := raw.Lookup("blobs").ArrayOK()
		vals, _ := arr.Values()
		var got []string
		for _, v := range vals {
			got = append(got, v.StringValue())
		}
		if !ok || !reflect.DeepEqual(got, body.Blobs) {
			fail("blobs", got)
		}
	}
	if why := extJSONHazard(body.Data); why != "" {
		if got, _ := rawString(raw, "data_json"); got != string(body.Data) {
			fail("data_json", clip(got, 80))
		}
		if b, ok := raw.Lookup("data_undecoded").BooleanOK(); !ok || !b {
			fail("data_undecoded", raw.Lookup("data_undecoded"))
		}
		if note, _ := rawString(raw, "data_note"); note != why {
			fail("data_note", note)
		}
		if _, err := raw.LookupErr("data"); err == nil {
			fail("data", "present")
		}
		return
	}
	v, err := raw.LookupErr("data")
	if err != nil {
		fail("data", "absent")
		return
	}
	if !sameJSON(t, body.Data, v) {
		fail("data", clip(v.String(), 200))
	}
}

// realBodies returns bodies of every shape the monitor writes, with extreme seq and mono values.
func realBodies(t testing.TB) []model.Body {
	t.Helper()
	rx := int64(-315)
	pub, _ := testKey(t)
	cfg := json.RawMessage(`{"web":{"listen":"127.0.0.1:8320"},"incident":{"loss_degraded_pct":20.5,"latency_degraded_ms":150},"probes":{"targets":[]}}`)
	datas := []struct {
		typ   string
		data  any
		blobs []string
	}{
		{model.TypeGenesis, model.Genesis{PublicKey: base64.StdEncoding.EncodeToString(pub), Fingerprint: fingerprintOf(pub),
			Created: "2026-10-05T03:20:00Z", Statement: "genesis <statement> & \"quotes\""}, nil},
		{model.TypeSample, sample(math.MaxUint32+5, htmlReason), nil},
		{model.TypeGatewaySnapshot, model.GatewaySnapshot{
			Pages:     []model.PageCapture{{Page: "fiberstat", Status: 200, SHA256: sha256Hex([]byte("x")), Stored: true}},
			Broadband: &model.BroadbandStatus{Counters: map[string]int64{"IPv4 Statistics/Receive Bytes": math.MaxInt64, "neg": math.MinInt64}},
			Fiber:     &model.FiberStatus{Measures: []model.DMIMeasure{{Name: "Rx Power", Current: &rx, LowAlarm: model.Threshold{Active: true, Raw: "1 (Threshold -295)"}}}},
			Derived:   model.GatewayDerived{RxPowerX10: &rx, UptimeSec: -1},
		}, []string{sha256Hex([]byte("x"))}},
		{model.TypeIncidentClose, incident(incidentID1, false, "closed <b>"), nil},
		{model.TypeMonitorStart, model.MonitorStart{Config: cfg, PrevHead: model.Ref{Seq: 1 << 62}, GapSeconds: -42}, nil},
		{model.TypeClockJump, model.ClockJump{WallDeltaMs: -3_600_000, MonoDeltaMs: 10_000, JumpMs: -3_610_000}, nil},
		{model.TypeOperatorNote, model.OperatorNote{Text: "AT&T ticket <#1>   \x00 nul é 😀 \\ \"", Source: "cli"}, nil},
		{model.TypeGatewayEvent, model.GatewayEvent{Kind: "counters_reset", Evidence: []uint64{math.MaxUint64}}, nil},          // > int64
		{model.TypeGatewaySnapshot, model.GatewaySnapshot{LAN: &model.LANStatus{Values: map[string]string{"$oid": "x"}}}, nil}, // "$" key
		{model.TypeHeartbeat, nil, nil}, // data: null
	}
	seqs := []uint64{0, 1, 1 << 40, math.MaxInt64}
	monos := []int64{0, math.MaxInt64, math.MinInt64, -5}
	var out []model.Body
	for i, d := range datas {
		out = append(out, model.Body{
			V: model.FormatVersion, Seq: seqs[i%len(seqs)], Prev: model.ZeroHash, TS: "2026-10-05T03:20:00.123456789Z",
			Mono: monos[i%len(monos)], Run: "0123456789abcdef0123456789abcdef", Type: d.typ, Blobs: d.blobs, Data: dataOf(t, d.data),
		})
	}
	return out
}

func TestRecordDocRealShapes(t *testing.T) {
	_, priv := testKey(t)
	for _, body := range realBodies(t) {
		it := signedRecord(t, priv, body)
		raw, err := recordDoc(it.env, it.body, dataConvert)
		if err != nil {
			t.Fatalf("%s: %v", body.Type, err)
		}
		checkRecordDoc(t, raw, it)
		again, err := recordDoc(it.env, it.body, dataConvert)
		if err != nil || !bytes.Equal(raw, again) {
			t.Errorf("%s: the document is not deterministic", body.Type)
		}
	}
}

func TestRecordDocSpotValues(t *testing.T) {
	_, priv := testKey(t)
	bodies := realBodies(t)
	it := signedRecord(t, priv, bodies[1]) // sample
	raw, err := recordDoc(it.env, it.body, dataConvert)
	if err != nil {
		t.Fatal(err)
	}
	if got := raw.Lookup("data", "verdict", "reasons", "0").StringValue(); got != htmlReason {
		t.Errorf("reason = %q, want %q", got, htmlReason)
	}
	if got, ok := raw.Lookup("data", "probes", "1", "rtt_us").Int32OK(); !ok || got != 14200 {
		t.Errorf("rtt_us = %v", raw.Lookup("data", "probes", "1", "rtt_us"))
	}
	if got, ok := raw.Lookup("data", "cycle").Int64OK(); !ok || got != math.MaxUint32+5 {
		t.Errorf("cycle = %v", raw.Lookup("data", "cycle"))
	}
	it = signedRecord(t, priv, bodies[2]) // gateway snapshot
	raw, err = recordDoc(it.env, it.body, dataConvert)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := raw.Lookup("data", "broadband", "counters", "IPv4 Statistics/Receive Bytes").Int64OK(); !ok || got != math.MaxInt64 {
		t.Errorf("counter = %v", raw.Lookup("data", "broadband", "counters", "IPv4 Statistics/Receive Bytes"))
	}
	if got, ok := raw.Lookup("data", "fiber", "measures", "0", "current").Int32OK(); !ok || got != -315 {
		t.Errorf("rx = %v", raw.Lookup("data", "fiber", "measures", "0", "current"))
	}
	if got, ok := raw.Lookup("mono").Int64OK(); !ok || got != math.MinInt64 {
		t.Errorf("mono = %v", raw.Lookup("mono"))
	}
	if got, ok := raw.Lookup("seq").Int64OK(); !ok || got != 1<<40 {
		t.Errorf("seq = %v", raw.Lookup("seq"))
	}
	it = signedRecord(t, priv, bodies[3]) // incident: the largest seq MongoDB can hold
	raw, err = recordDoc(it.env, it.body, dataConvert)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := raw.Lookup("_id").Int64OK(); !ok || got != math.MaxInt64 {
		t.Errorf("_id = %v", raw.Lookup("_id"))
	}
	if got, ok := raw.Lookup("mono").Int64OK(); !ok || got != -5 {
		t.Errorf("mono = %v", raw.Lookup("mono"))
	}
	it = signedRecord(t, priv, bodies[9]) // data: null
	raw, err = recordDoc(it.env, it.body, dataConvert)
	if err != nil {
		t.Fatal(err)
	}
	if v := raw.Lookup("data"); v.Type != bson.TypeNull {
		t.Errorf("null data stored as %v", v.Type)
	}
	it = signedRecord(t, priv, bodies[7]) // uint64 above int64
	raw, err = recordDoc(it.env, it.body, dataConvert)
	if err != nil {
		t.Fatal(err)
	}
	if note, _ := rawString(raw, "data_note"); !strings.Contains(note, "18446744073709551615") {
		t.Errorf("data_note = %q", note)
	}
}

func TestRecordDocRejectsSeqBeyondInt64(t *testing.T) {
	_, priv := testKey(t)
	body := realBodies(t)[1]
	body.Seq = math.MaxInt64 + 1
	it := signedRecord(t, priv, body)
	if _, err := recordDoc(it.env, it.body, dataConvert); err == nil {
		t.Fatal("seq above int64 accepted")
	}
	if _, err := incidentDoc("x", it.env, it.body, dataConvert, time.Now()); err == nil {
		t.Fatal("incident seq above int64 accepted")
	}
}

func TestRecordDocBadTimestamp(t *testing.T) {
	_, priv := testKey(t)
	body := realBodies(t)[1]
	body.TS = "yesterday"
	it := signedRecord(t, priv, body)
	raw, err := recordDoc(it.env, it.body, dataConvert)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.LookupErr("ts"); err == nil {
		t.Error("an unparseable ts must not produce a date")
	}
	if got, _ := rawString(raw, "ts_text"); got != "yesterday" {
		t.Errorf("ts_text = %q", got)
	}
}

func TestRecordDocJSONModes(t *testing.T) {
	_, priv := testKey(t)
	it := signedRecord(t, priv, realBodies(t)[1])
	raw, err := recordDoc(it.env, it.body, dataAsJSON)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := rawString(raw, "data_json"); got != string(it.body.Data) {
		t.Error("data_json is not the exact data")
	}
	if note, _ := rawString(raw, "data_note"); note != noteServerRejected {
		t.Errorf("note = %q", note)
	}
	raw, err = recordDoc(it.env, it.body, dataOmitted)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.LookupErr("data_json"); err == nil {
		t.Error("omitted data still has data_json")
	}
	if note, _ := rawString(raw, "data_note"); note != noteDataTooLarge {
		t.Errorf("note = %q", note)
	}
}

func TestRecordDocTooLarge(t *testing.T) {
	_, priv := testKey(t)
	body := realBodies(t)[6]
	body.Data = dataOf(t, map[string]string{"text": strings.Repeat("<x>", 3<<20)}) // ~9 MB, twice in the document
	it := signedRecord(t, priv, body)
	raw, err := recordDoc(it.env, it.body, dataConvert)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > maxDocBytes {
		t.Fatalf("document of %d bytes", len(raw))
	}
	if got, _ := rawString(raw, "b"); got != it.env.B {
		t.Error("b was altered")
	}
	if note, _ := rawString(raw, "data_note"); note != noteDataTooLarge {
		t.Errorf("note = %q", note)
	}

	body.Data = dataOf(t, map[string]string{"text": strings.Repeat("y", 17<<20)})
	it = signedRecord(t, priv, body)
	if _, err := recordDoc(it.env, it.body, dataConvert); err == nil {
		t.Fatal("a record larger than a MongoDB document was accepted")
	}
}

func TestConvertJSONTypes(t *testing.T) {
	cases := []struct {
		in   string
		want bson.Type
	}{
		{`null`, bson.TypeNull},
		{`true`, bson.TypeBoolean},
		{`5`, bson.TypeInt32},
		{`-2147483649`, bson.TypeInt64},
		{`9223372036854775807`, bson.TypeInt64},
		{`-9223372036854775808`, bson.TypeInt64},
		{`1.5`, bson.TypeDouble},
		{`1e300`, bson.TypeDouble},
		{`"s"`, bson.TypeString},
		{`[1,"a",null]`, bson.TypeArray},
		{`{"x":{"y":[{}]}}`, bson.TypeEmbeddedDocument},
		{`{"":1,"a.b":2,"k$":3}`, bson.TypeEmbeddedDocument},
		{`"$date"`, bson.TypeString},
	}
	for _, c := range cases {
		v, why := convertJSON([]byte(c.in))
		if why != "" {
			t.Errorf("%s: %s", c.in, why)
			continue
		}
		if v.Type != c.want {
			t.Errorf("%s: type %v, want %v", c.in, v.Type, c.want)
		}
		if !sameJSON(t, []byte(c.in), v) {
			t.Errorf("%s: converted to %v", c.in, v)
		}
	}
}

func TestConvertJSONStringsExact(t *testing.T) {
	for _, s := range []string{
		htmlReason,
		"<script>alert('x')</script> & &amp; \"q\" \\ /    \x00 \x1f é 😀 �",
		strings.Repeat("é", 1000),
		"",
	} {
		data := marshalNoEscape(t, s)
		v, why := convertJSON(data)
		if why != "" {
			t.Fatalf("%q: %s", s, why)
		}
		if got, ok := v.StringValueOK(); !ok || got != s {
			t.Errorf("string %q converted to %q", s, got)
		}
	}
}

func TestExtJSONHazards(t *testing.T) {
	deep := strings.Repeat("[", maxDataDepth+1) + strings.Repeat("]", maxDataDepth+1)
	okDeep := strings.Repeat("[", maxDataDepth) + strings.Repeat("]", maxDataDepth)
	cases := []struct {
		in     string
		hazard bool
	}{
		{`{"a":1}`, false},
		{`{"$date":"2026-10-05T00:00:00Z"}`, true},
		{`{"a":{"$oid":"0123456789abcdef01234567"}}`, true},
		{`{"$numberLong":"5"}`, true},
		{`[{"$x":1}]`, true},
		{`{"k":"$notakey"}`, false},
		{`{"k":"\"$x\": 1"}`, false},
		{`{"a\u0000b":1}`, true},
		{`{"a":"\u0000"}`, false},
		{`18446744073709551615`, true},
		{`{"n":-9223372036854775809}`, true},
		{`{"n":9223372036854775807}`, false},
		{`{"n":-9223372036854775808}`, false},
		{`{"n":12345678901234567890.5}`, false},
		{`{"n":1e400}`, false}, // a double: the parser rejects it (then the data is kept as text)
		{deep, true},
		{okDeep, false},
		{`{"a" : 1, "$b"  :2}`, true},
		{`"unterminated`, false},
	}
	for _, c := range cases {
		why := extJSONHazard([]byte(c.in))
		if (why != "") != c.hazard {
			t.Errorf("%.60s: hazard %q, want %v", c.in, why, c.hazard)
		}
	}
	// Parser errors are not hazards but still lead to the JSON text form.
	if _, why := convertJSON([]byte(`{"n":1e400}`)); why == "" {
		t.Error("1e400 converted")
	}
}

// refHazard is a reference implementation of extJSONHazard built on encoding/json tokens.
func refHazard(t *testing.T, data []byte) bool {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	hazard := false
	var walk func(depth int)
	walk = func(depth int) {
		tok, err := dec.Token()
		if err != nil {
			t.Fatalf("reference decoder: %v in %.80s", err, data)
		}
		switch v := tok.(type) {
		case json.Delim:
			if depth+1 > maxDataDepth {
				hazard = true
			}
			obj := v == '{'
			for dec.More() {
				if obj {
					kt, err := dec.Token()
					if err != nil {
						t.Fatal(err)
					}
					k := kt.(string)
					if strings.HasPrefix(k, "$") || strings.Contains(k, "\x00") {
						hazard = true
					}
				}
				walk(depth + 1)
			}
			if _, err := dec.Token(); err != nil {
				t.Fatal(err)
			}
		case json.Number:
			s := string(v)
			if !strings.ContainsAny(s, ".eE") {
				if _, err := strconv.ParseInt(s, 10, 64); err != nil {
					hazard = true
				}
			}
		}
	}
	walk(0)
	return hazard
}

// randomJSON builds a random JSON value with awkward keys, strings and numbers.
func randomJSON(rng *rand.Rand, depth int) any {
	keys := []string{"a", "$a", "a$", "b.c", "", "x\x00y", "é", " ", `"q"`, `\`, "$", "{", ":", "id", "$date"}
	strs := []string{"", "$x", `"$a": 1`, "{", "}", "[", ":", `\`, `\"`, "<b>&</b>", "\x00", "😀", "1e5", "-9223372036854775809"}
	nums := []json.Number{"0", "-1", "5", "-0", "2147483648", "9223372036854775807", "-9223372036854775808",
		"9223372036854775808", "18446744073709551615", "-9223372036854775809", "1.5", "1e300", "-2.5e-3", "12345678901234567890.0"}
	if depth > 70 {
		return "leaf"
	}
	switch k := rng.IntN(10); {
	case k < 3:
		n := rng.IntN(4)
		m := make(map[string]any, n)
		for i := 0; i < n; i++ {
			m[keys[rng.IntN(len(keys))]] = randomJSON(rng, depth+1)
		}
		return m
	case k < 5:
		n := rng.IntN(4)
		a := make([]any, n)
		for i := range a {
			a[i] = randomJSON(rng, depth+1)
		}
		return a
	case k < 7:
		return strs[rng.IntN(len(strs))]
	case k < 9:
		return nums[rng.IntN(len(nums))]
	default:
		return []any{true, false, nil}[rng.IntN(3)]
	}
}

func TestExtJSONHazardMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	hazards, converted := 0, 0
	for i := 0; i < 3000; i++ {
		var v any
		if i%50 == 0 {
			// deep nesting around the limit
			d := maxDataDepth - 2 + rng.IntN(5)
			v = "x"
			for j := 0; j < d; j++ {
				v = []any{v}
			}
		} else {
			v = randomJSON(rng, 0)
		}
		data := marshalNoEscape(t, v)
		got := extJSONHazard(data) != ""
		if want := refHazard(t, data); got != want {
			t.Fatalf("hazard %v, reference %v for %s", got, want, data)
		}
		if got {
			hazards++
			continue
		}
		cv, why := convertJSON(data)
		if why != "" {
			t.Fatalf("no hazard but not converted (%s): %s", why, data)
		}
		if !sameJSON(t, data, cv) {
			t.Fatalf("not faithful: %s became %v", data, cv)
		}
		converted++
	}
	if hazards == 0 || converted == 0 {
		t.Fatalf("corpus not varied: %d hazards, %d converted", hazards, converted)
	}
}

func TestBlobDoc(t *testing.T) {
	now := time.Date(2026, 10, 5, 3, 20, 0, 0, time.UTC)
	small := []byte("raw \xa9 bytes\x00")
	d := blobDoc(sha256Hex(small), small, 42, true, now)
	raw, err := bson.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	doc := bson.Raw(raw)
	if sub, data, ok := doc.Lookup("data").BinaryOK(); !ok || sub != 0 || !bytes.Equal(data, small) {
		t.Errorf("data = %v", doc.Lookup("data"))
	}
	if n, _ := doc.Lookup("size").Int64OK(); n != int64(len(small)) {
		t.Errorf("size = %d", n)
	}
	if n, _ := doc.Lookup("first_seq").Int64OK(); n != 42 {
		t.Errorf("first_seq = %d", n)
	}
	if ms, _ := doc.Lookup("stored_at").DateTimeOK(); ms != now.UnixMilli() {
		t.Errorf("stored_at = %d", ms)
	}

	big := make([]byte, maxBlobBytes+1)
	doc = mustMarshal(t, blobDoc(sha256Hex(big), big, 1, true, now))
	if _, err := doc.LookupErr("data"); err == nil {
		t.Error("a blob over 15 MB was stored")
	}
	if b, _ := doc.Lookup("too_large").BooleanOK(); !b {
		t.Error("too_large not set")
	}
	if n, _ := doc.Lookup("size").Int64OK(); n != int64(len(big)) {
		t.Errorf("size = %d", n)
	}

	doc = mustMarshal(t, blobDoc(sha256Hex(small), small, 1, false, now))
	if _, err := doc.LookupErr("data"); err == nil {
		t.Error("content stored with StoreBlobs off")
	}
	if note, _ := rawString(doc, "note"); note != noteBlobNotStored {
		t.Errorf("note = %q", note)
	}
}

func mustMarshal(t testing.TB, d bson.D) bson.Raw {
	t.Helper()
	raw, err := bson.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestIncidentDoc(t *testing.T) {
	_, priv := testKey(t)
	body := realBodies(t)[3]
	body.Seq = 77
	it := signedRecord(t, priv, body)
	updated := time.Date(2026, 10, 5, 4, 0, 0, 0, time.UTC)
	raw, err := incidentDoc(incidentID1, it.env, it.body, dataConvert, updated)
	if err != nil {
		t.Fatal(err)
	}
	if id, _ := rawString(raw, "_id"); id != incidentID1 {
		t.Errorf("_id = %q", id)
	}
	if n, _ := raw.Lookup("seq").Int64OK(); n != 77 {
		t.Errorf("seq = %d", n)
	}
	if typ, _ := rawString(raw, "type"); typ != model.TypeIncidentClose {
		t.Errorf("type = %q", typ)
	}
	if h, _ := rawString(raw, "h"); h != it.env.H {
		t.Errorf("h = %q", h)
	}
	if open, ok := raw.Lookup("incident", "open").BooleanOK(); !ok || open {
		t.Errorf("incident.open = %v", raw.Lookup("incident", "open"))
	}
	if s := raw.Lookup("incident", "summary").StringValue(); s != "closed <b>" {
		t.Errorf("summary = %q", s)
	}
	if ms, _ := raw.Lookup("updated").DateTimeOK(); ms != updated.UnixMilli() {
		t.Errorf("updated = %d", ms)
	}
	if !sameJSON(t, it.body.Data, raw.Lookup("incident")) {
		t.Error("incident payload not faithful")
	}
	if keys := incidentDiff(raw, incidentID1, it.env, it.body); keys != nil {
		t.Errorf("incidentDiff of an exact document: %v", keys)
	}
	if incidentID(it.body.Data) != incidentID1 || incidentID(json.RawMessage(`[1]`)) != "" {
		t.Error("incidentID")
	}
}

func TestDiffKeys(t *testing.T) {
	base := mustMarshal(t, bson.D{{Key: "a", Value: 1}, {Key: "b", Value: "x"}, {Key: "c", Value: true}})
	cases := []struct {
		doc  bson.D
		want []string
	}{
		{bson.D{{Key: "a", Value: 1}, {Key: "b", Value: "x"}, {Key: "c", Value: true}}, nil},
		{bson.D{{Key: "a", Value: 2}, {Key: "b", Value: "x"}, {Key: "c", Value: true}}, []string{`"a"`}},
		{bson.D{{Key: "a", Value: int64(1)}, {Key: "b", Value: "x"}, {Key: "c", Value: true}}, []string{`"a"`}},
		{bson.D{{Key: "a", Value: 1}, {Key: "c", Value: true}}, []string{`"b"`}},
		{bson.D{{Key: "a", Value: 1}, {Key: "b", Value: "x"}, {Key: "c", Value: true}, {Key: "z", Value: 0}}, []string{`"z"`}},
		{bson.D{{Key: "b", Value: "x"}, {Key: "a", Value: 1}, {Key: "c", Value: true}}, []string{"(field order)"}},
		{bson.D{{Key: "a", Value: 1}, {Key: "a", Value: 1}, {Key: "b", Value: "x"}, {Key: "c", Value: true}}, []string{`(duplicate field "a")`}},
		// Keys come from documents anyone can write: quoted, also when they look like a note.
		{bson.D{{Key: "a", Value: 1}, {Key: "b", Value: "x"}, {Key: "c", Value: true}, {Key: "(field order)\x1b[2K", Value: 0}}, []string{`"(field order)\x1b[2K"`}},
	}
	for i, c := range cases {
		got := diffKeys(mustMarshal(t, c.doc), base)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("case %d: %v, want %v", i, got, c.want)
		}
	}
	if got := diffKeys(mustMarshal(t, bson.D{{Key: "a", Value: 1}, {Key: "b", Value: "y"}, {Key: "c", Value: true}}), base, "b"); got != nil {
		t.Errorf("ignored key reported: %v", got)
	}
}

func TestHelpers(t *testing.T) {
	if !isBlobID(sha256Hex(nil)) || isBlobID(strings.ToUpper(sha256Hex(nil))) || isBlobID("abc") {
		t.Error("isBlobID")
	}
	if got := clip("ééé", 3); got != "é…" {
		t.Errorf("clip = %q", got)
	}
	if short("") != `""` || short("0123456789abcdef0123") != "0123456789abcdef…" {
		t.Error("short")
	}
	_, priv := testKey(t)
	sig := base64.StdEncoding.EncodeToString(make([]byte, 64))
	if _, err := decodeSignature(sig); err != nil {
		t.Error(err)
	}
	if _, err := decodeSignature(sig + "\n"); err == nil {
		t.Error("non-canonical signature accepted")
	}
	if _, err := decodeSignature("AAAA"); err == nil {
		t.Error("short signature accepted")
	}
	g := signedRecord(t, priv, realBodies(t)[0])
	id := identFromGenesis(g.env, g.body)
	if id.genesisHash != g.env.H || len(id.fingerprint) != 64 {
		t.Errorf("identity %+v", id)
	}
	var gen model.Genesis
	if err := json.Unmarshal(g.body.Data, &gen); err != nil {
		t.Fatal(err)
	}
	gen.Fingerprint = ""
	g.body.Data = dataOf(t, gen)
	if id2 := identFromGenesis(g.env, g.body); id2.fingerprint != id.fingerprint {
		t.Errorf("fingerprint from public_key: %q, want %q", id2.fingerprint, id.fingerprint)
	}
	g.body.Type = model.TypeSample
	if id3 := identFromGenesis(g.env, g.body); id3 != (ledgerIdent{}) {
		t.Errorf("identity of a non-genesis record: %+v", id3)
	}
	if !bodySeqIs(`{"v":1,"seq":5}`, 5) || bodySeqIs(`{"v":1}`, 0) || bodySeqIs(`{"seq":6}`, 5) {
		t.Error("bodySeqIs")
	}
	if n, ok := latestAtMost([]uint64{3, 9, 20}, 10); !ok || n != 9 {
		t.Errorf("latestAtMost = %d %v", n, ok)
	}
	if _, ok := latestAtMost([]uint64{3}, -1); ok {
		t.Error("latestAtMost with nothing copied")
	}
}
