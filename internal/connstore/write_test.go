package connstore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

func TestAppendAndAggregateRoundTrip(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{})
	h.devices(at(0, 1, 0), device(10, 1, "test-laptop", "Wi-Fi 5 GHz"), device(11, 2, "test-phone", "Wi-Fi 2.4 GHz"))
	h.natTable(at(0, 2, 0), model.NATTable{InUse: 5, Available: 8187, Sessions: []model.NATSession{
		tcp(10, 50000, "203.0.113.5", 443), tcp(10, 50001, "203.0.113.5", 443), udp(11, 40000, "198.51.100.7", 53),
	}})
	h.natTable(at(0, 2, 4), model.NATTable{InUse: 4, Available: 8188, Sessions: []model.NATSession{
		tcp(10, 50000, "203.0.113.5", 443),
	}})

	a := h.agg(day0, day0.AddDate(0, 0, 1))
	checkConsistent(t, a)
	if a.From != rfc(day0) || a.To != rfc(day0.AddDate(0, 0, 1)) || a.Samples != 2 ||
		a.First != rfc(at(0, 2, 0)) || a.Last != rfc(at(0, 2, 4)) || a.InUse != 4 || a.Available != 8188 || a.Open != 1 {
		t.Errorf("aggregate = %+v", a)
	}
	wantDevices := []model.ConnDevice{
		{Key: macKey(1), Name: "test-laptop", IPv4: lanIP(10), MAC: macOf(1), Connection: "Wi-Fi 5 GHz", Samples: 2, Weight: 3},
		{Key: macKey(2), Name: "test-phone", IPv4: lanIP(11), MAC: macOf(2), Connection: "Wi-Fi 2.4 GHz", Samples: 1, Weight: 1},
	}
	if !reflect.DeepEqual(a.Devices, wantDevices) {
		t.Errorf("devices = %+v\nwant %+v", a.Devices, wantDevices)
	}
	wantFlows := []model.ConnFlow{
		{Device: macKey(1), LAN: lanIP(10), Remote: "203.0.113.5", Port: 443, Proto: "tcp",
			First: rfc(at(0, 2, 0)), Last: rfc(at(0, 2, 4)), Samples: 2, Weight: 3},
		{Device: macKey(2), LAN: lanIP(11), Remote: "198.51.100.7", Port: 53, Proto: "udp",
			First: rfc(at(0, 2, 0)), Last: rfc(at(0, 2, 0)), Samples: 1, Weight: 1},
	}
	if !reflect.DeepEqual(a.Flows, wantFlows) {
		t.Errorf("flows = %+v\nwant %+v", a.Flows, wantFlows)
	}

	devices, when := h.s.Devices()
	if len(devices) != 2 || devices[0].Name != "test-laptop" || !when.Equal(at(0, 1, 0)) {
		t.Errorf("Devices = %+v, %s", devices, when)
	}
	devices[0].Name = "changed by the caller"
	if again, _ := h.s.Devices(); again[0].Name != "test-laptop" {
		t.Error("Devices returned the store's own slice")
	}

	// The same after a restart.
	h.reopen()
	if b := h.agg(day0, day0.AddDate(0, 0, 1)); !reflect.DeepEqual(a, b) {
		t.Errorf("after reopening:\n%+v\nwant\n%+v", b, a)
	}
	if devices, when := h.s.Devices(); len(devices) != 2 || !when.Equal(at(0, 1, 0)) {
		t.Errorf("Devices after reopening = %+v, %s", devices, when)
	}
}

func TestDayRolloverCompressesTheDayBefore(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{})
	h.devices(at(0, 10, 0), device(10, 1, "test-laptop", "Ethernet"))
	h.nat(at(0, 10, 0), tcp(10, 50000, "203.0.113.5", 443))
	h.nat(at(0, 23, 59), tcp(10, 50000, "203.0.113.5", 443), udp(10, 40000, "192.0.2.53", 53))
	natPlain := h.content("nat-2026-10-05.jsonl")
	devPlain := h.content("devices-2026-10-05.jsonl")

	h.clk.Set(at(1, 0, 1))
	h.nat(at(1, 0, 1), tcp(10, 50002, "198.51.100.7", 443))
	for _, name := range []string{"nat-2026-10-05.jsonl", "devices-2026-10-05.jsonl"} {
		if h.exists(name) {
			t.Errorf("%s still exists after the day was over", name)
		}
		if !h.exists(name + gzExt) {
			t.Errorf("%s was not compressed", name)
		}
	}
	if got := h.content("nat-2026-10-05.jsonl.gz"); !bytes.Equal(got, natPlain) {
		t.Errorf("the compressed NAT day decompresses to\n%s\nwant\n%s", got, natPlain)
	}
	if got := h.content("devices-2026-10-05.jsonl.gz"); !bytes.Equal(got, devPlain) {
		t.Errorf("the compressed Device List day differs")
	}
	if !h.exists("nat-2026-10-06.jsonl") || h.exists("devices-2026-10-06.jsonl") {
		t.Error("the new day's files are not as expected")
	}

	a := h.agg(day0, at(2, 0, 0))
	checkConsistent(t, a)
	if a.Samples != 3 || len(a.Flows) != 3 {
		t.Errorf("aggregate over both days = %+v", a)
	}
	// The read of the new day is named after the Device List read of the day before.
	if f := findFlow(t, a, macKey(1), "198.51.100.7", 443, "tcp"); f.Samples != 1 {
		t.Errorf("flow of the new day = %+v", f)
	}

	u := h.s.Usage()
	var bytes int64
	files := 0
	for _, name := range []string{"nat-2026-10-05.jsonl.gz", "devices-2026-10-05.jsonl.gz", "nat-2026-10-06.jsonl"} {
		st, err := os.Stat(h.file(name))
		if err != nil {
			t.Fatal(err)
		}
		bytes += st.Size()
		files++
	}
	if u.Bytes != bytes || u.Files != files || u.Oldest != rfc(at(0, 10, 0)) || u.Newest != rfc(at(1, 0, 1)) || u.Error != "" {
		t.Errorf("Usage = %+v, want %d bytes in %d files", u, bytes, files)
	}
}

func TestReadOfACompressedDayAfterTheClockWentBack(t *testing.T) {
	h := newHarness(t, at(1, 0, 10), Options{})
	h.nat(at(0, 23, 50), tcp(10, 50000, "203.0.113.5", 443))
	h.nat(at(1, 0, 5), tcp(10, 50000, "203.0.113.5", 443)) // compresses day 0
	if !h.exists("nat-2026-10-05.jsonl.gz") || h.exists("nat-2026-10-05.jsonl") {
		t.Fatal("day 0 was not compressed")
	}
	// The clock is set back over midnight: the read goes to its own day's file.
	h.clk.Set(at(0, 23, 58))
	h.nat(at(0, 23, 58), tcp(10, 50001, "198.51.100.7", 443))
	if !h.exists("nat-2026-10-05.jsonl") || len(h.lines("nat-2026-10-05.jsonl")) != 1 {
		t.Fatal("the late read is not in a plain file of its day")
	}
	if h.log.count("the file of a day after today was being written") != 1 {
		t.Errorf("the late read was not logged:\n%s", h.log.all())
	}
	a := h.agg(day0, at(1, 0, 0))
	checkConsistent(t, a)
	if a.Samples != 2 || a.Last != rfc(at(0, 23, 58)) {
		t.Errorf("day 0 with its late read = %+v", a)
	}
	b := h.agg(at(1, 0, 0), at(2, 0, 0))
	if b.Samples != 1 {
		t.Errorf("day 1 = %+v", b)
	}

	// The next read of a later day merges the late read into the compressed day.
	h.clk.Set(at(1, 0, 9))
	h.nat(at(1, 0, 9), tcp(10, 50000, "203.0.113.5", 443))
	if h.exists("nat-2026-10-05.jsonl") {
		t.Error("the late read was not merged into the compressed day")
	}
	if lines := h.lines("nat-2026-10-05.jsonl.gz"); len(lines) != 2 {
		t.Errorf("the compressed day holds %d reads, want 2", len(lines))
	}
	if c := h.agg(day0, at(1, 0, 0)); !reflect.DeepEqual(c, a) {
		t.Errorf("day 0 after the merge = %+v\nwant %+v", c, a)
	}
}

func TestReadsGoToTheirOwnDaysFile(t *testing.T) {
	h := newHarness(t, at(3, 12, 0), Options{})
	// Out of order within a day, and a day ahead and back.
	h.nat(at(2, 10, 0), tcp(10, 1, "203.0.113.5", 443))
	h.nat(at(2, 9, 0), tcp(10, 2, "203.0.113.5", 443))
	h.nat(at(3, 1, 0), tcp(10, 3, "203.0.113.5", 443))
	h.nat(at(2, 11, 0), tcp(10, 4, "203.0.113.5", 443))
	for name, want := range map[string]int{"nat-2026-10-07.jsonl.gz": 2, "nat-2026-10-07.jsonl": 1, "nat-2026-10-08.jsonl": 1} {
		if got := len(h.lines(name)); got != want {
			t.Errorf("%s holds %d reads, want %d", name, got, want)
		}
	}
	h.nat(at(3, 2, 0), tcp(10, 5, "203.0.113.5", 443)) // merges day 2
	for name, want := range map[string]int{"nat-2026-10-07.jsonl.gz": 3, "nat-2026-10-08.jsonl": 2} {
		if got := len(h.lines(name)); got != want {
			t.Errorf("%s holds %d reads, want %d", name, got, want)
		}
	}
	if h.exists("nat-2026-10-07.jsonl") {
		t.Error("the late read of day 2 was not merged")
	}
	a := h.agg(at(2, 0, 0), at(3, 0, 0))
	if a.Samples != 3 || a.First != rfc(at(2, 9, 0)) || a.Last != rfc(at(2, 11, 0)) {
		t.Errorf("day 2 = %+v", a)
	}
	// The newest read of the period gives the totals, whatever the order they were stored in.
	h.natTable(at(3, 1, 30), model.NATTable{InUse: 77, Available: 1, Sessions: []model.NATSession{tcp(10, 6, "203.0.113.5", 443)}})
	if b := h.agg(at(3, 0, 0), at(3, 1, 45)); b.InUse != 77 || b.Last != rfc(at(3, 1, 30)) {
		t.Errorf("newest read = %+v", b)
	}
}

func TestOtherFilesAreNeverTouched(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{KeepDays: 1, KeepMB: 1})
	others := map[string][]byte{
		"last-nattable.html":           []byte("<html>a NAT table page</html>"),
		"last-devices.html":            []byte("<html>a Device List page</html>"),
		"nat-2026-10-05.jsonl.bak":     []byte("someone's copy\n"),
		"nat-notes.txt":                []byte("notes"),
		"devices-2026-10-05.json":      []byte("{}"),
		"NAT-2026-10-04.jsonl":         []byte("not ours"),
		"nat-2026-10-04.jsonl.gz.copy": []byte("not ours either"),
	}
	for name, b := range others {
		if err := os.WriteFile(h.file(name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	h.reopen()
	for d := range 4 {
		h.clk.Set(at(d, 12, 0))
		h.nat(at(d, 12, 0), tcp(10, 1, "203.0.113.5", 443))
		h.devices(at(d, 12, 0), device(10, 1, "test-laptop", ""))
	}
	if err := h.s.Prune(time.Time{}); err != nil {
		t.Fatal(err)
	}
	h.reopen()
	for name, want := range others {
		got, err := os.ReadFile(h.file(name))
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s: %q, %v; want it untouched", name, got, err)
		}
	}
}

func TestClosedStore(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{})
	h.nat(at(0, 10, 0), tcp(10, 1, "203.0.113.5", 443))
	if err := h.s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := h.s.Close(); err != nil {
		t.Errorf("a second Close: %v", err)
	}
	if err := h.s.AppendNAT(at(0, 11, 0), model.NATTable{}); !errors.Is(err, ErrClosed) {
		t.Errorf("AppendNAT after Close: %v", err)
	}
	if err := h.s.AppendDevices(at(0, 11, 0), nil); !errors.Is(err, ErrClosed) {
		t.Errorf("AppendDevices after Close: %v", err)
	}
	if err := h.s.Prune(time.Time{}); !errors.Is(err, ErrClosed) {
		t.Errorf("Prune after Close: %v", err)
	}
	// Reading keeps working.
	if a := h.agg(day0, at(1, 0, 0)); a.Samples != 1 {
		t.Errorf("Aggregate after Close = %+v", a)
	}
}

func TestAppendTimes(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{})
	for _, bad := range []time.Time{time.Date(1999, 12, 31, 23, 0, 0, 0, time.UTC), time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if err := h.s.AppendNAT(bad, model.NATTable{}); err == nil || !strings.Contains(err.Error(), "years 2000-2199") {
			t.Errorf("AppendNAT(%s): %v", bad, err)
		}
		if err := h.s.AppendDevices(bad, nil); err == nil {
			t.Errorf("AppendDevices(%s) accepted", bad)
		}
	}
	// The zero time is now; times in other zones are stored in UTC.
	if err := h.s.AppendNAT(time.Time{}, model.NATTable{}); err != nil {
		t.Fatal(err)
	}
	zone := time.FixedZone("UTC-7", -7*3600)
	if err := h.s.AppendDevices(at(0, 13, 0).In(zone), nil); err != nil {
		t.Fatal(err)
	}
	lines := h.lines("nat-2026-10-05.jsonl")
	if len(lines) != 1 || !strings.HasPrefix(lines[0], `{"t":"2026-10-05T12:00:00Z"`) {
		t.Errorf("the read at the zero time: %v", lines)
	}
	if devices, when := h.s.Devices(); devices == nil || len(devices) != 0 || !when.Equal(at(0, 13, 0)) || when.Location() != time.UTC {
		t.Errorf("Devices after an empty Device List read = %v, %s", devices, when)
	}
}

func TestDevicesKeepsTheNewestRead(t *testing.T) {
	h := newHarness(t, at(1, 12, 0), Options{})
	if devices, when := h.s.Devices(); devices != nil || !when.IsZero() {
		t.Errorf("Devices before any read = %v, %s", devices, when)
	}
	h.devices(at(1, 10, 0), device(10, 1, "newest", ""))
	h.devices(at(1, 9, 0), device(10, 1, "older", "")) // stored later, made earlier
	if devices, when := h.s.Devices(); devices[0].Name != "newest" || !when.Equal(at(1, 10, 0)) {
		t.Errorf("Devices = %+v, %s", devices, when)
	}
	h.reopen()
	if devices, when := h.s.Devices(); devices[0].Name != "newest" || !when.Equal(at(1, 10, 0)) {
		t.Errorf("Devices after reopening = %+v, %s", devices, when)
	}
}

func TestAggregateWorksWhileTheStoreIsEmpty(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{})
	a, err := h.s.Aggregate(context.Background(), contracts.ConnQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if a.Samples != 0 || a.InUse != -1 || a.Available != -1 || a.Open != 0 || a.Devices == nil || a.Flows == nil ||
		a.From != "" || a.To != "" || a.First != "" {
		t.Errorf("empty aggregate = %+v", a)
	}
	if u := h.s.Usage(); u.Bytes != 0 || u.Files != 0 || u.Oldest != "" || u.KeepDays != DefaultKeepDays || u.KeepMB != DefaultKeepMB {
		t.Errorf("Usage of an empty store = %+v", u)
	}
}
