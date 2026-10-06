package connstore

import (
	"bytes"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// appendFile appends b to a file of the store's directory (what a crash, or another program,
// left).
func appendFile(t *testing.T, path string, b []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// gzipTo writes the gzip of content to path as the store does.
func gzipTo(t *testing.T, path string, content []byte) {
	t.Helper()
	if _, _, err := writeGzip(path, func(w io.Writer) error {
		_, err := w.Write(content)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestOpenCutsOffALineACrashCutShort(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{})
	for i := range 3 {
		h.nat(at(0, 10, i), tcp(10, 50000+i, "203.0.113.5", 443))
	}
	name := "nat-2026-10-05.jsonl"
	before := h.content(name)
	if err := h.s.Close(); err != nil {
		t.Fatal(err)
	}
	// A power cut in the middle of the fourth write.
	line, err := encodeNAT(at(0, 10, 3), model.NATTable{Sessions: []model.NATSession{tcp(10, 1, "203.0.113.5", 443)}})
	if err != nil {
		t.Fatal(err)
	}
	appendFile(t, h.file(name), line[:len(line)/2])

	h.open()
	if got := h.content(name); !bytes.Equal(got, before) {
		t.Errorf("after Open the file holds %d bytes, want the %d of its complete lines", len(got), len(before))
	}
	if h.log.count("cut off the incomplete last line") != 1 || h.log.attr("cut off the incomplete last line", "bytes") != strconv.Itoa(len(line)/2) {
		t.Errorf("the cut was not logged:\n%s", h.log.all())
	}
	if a := h.agg(day0, at(1, 0, 0)); a.Samples != 3 {
		t.Errorf("Samples = %d, want 3", a.Samples)
	}
	h.nat(at(0, 10, 4), tcp(10, 50004, "203.0.113.5", 443))
	if a := h.agg(day0, at(1, 0, 0)); a.Samples != 4 {
		t.Errorf("Samples after one more read = %d, want 4", a.Samples)
	}
	if lines := h.lines(name); len(lines) != 4 {
		t.Errorf("the file holds %d lines, want 4", len(lines))
	}
}

func TestDamagedLinesAreSkipped(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{})
	h.devices(at(0, 9, 0), device(10, 1, "test-laptop", ""))
	h.nat(at(0, 10, 0), tcp(10, 50000, "203.0.113.5", 443))
	h.nat(at(0, 10, 4), tcp(10, 50000, "203.0.113.5", 443))
	if err := h.s.Close(); err != nil {
		t.Fatal(err)
	}
	// Garbage between the lines, a line of another day, a session with an index outside its
	// table and one with an address that does not parse.
	natPath := h.file("nat-2026-10-05.jsonl")
	lines := h.lines("nat-2026-10-05.jsonl")
	other, _ := encodeNAT(at(3, 1, 0), model.NATTable{Sessions: []model.NATSession{tcp(10, 1, "203.0.113.9", 443)}})
	badIndex := `{"t":"` + rfc(at(0, 10, 8)) + `","in_use":1,"available":1,"strs":["tcp","","192.168.1.10","203.0.113.5"],"s":[0,1,2,50000,3,443,0,1,2,50001,7,443]}`
	badAddr := `{"t":"` + rfc(at(0, 10, 9)) + `","in_use":1,"available":1,"strs":["tcp","","not-an-address","203.0.113.5"],"s":[0,1,2,50000,3,443]}`
	content := lines[0] + "\n\x00\x01garbage{\n" + string(other) + lines[1] + "\n" + "{\"t\":\"broken\n" + badIndex + "\n" + badAddr + "\n"
	if err := os.WriteFile(natPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	appendFile(t, h.file("devices-2026-10-05.jsonl"), []byte("not json\n"))

	h.open()
	a := h.agg(day0, at(1, 0, 0))
	checkConsistent(t, a)
	if a.Samples != 4 {
		t.Errorf("Samples = %d, want 4 (two reads, and the two with a damaged session)", a.Samples)
	}
	if f := findFlow(t, a, macKey(1), "203.0.113.5", 443, "tcp"); f.Samples != 3 || f.Weight != 3 {
		t.Errorf("flow = %+v, want 3 reads (the read whose only session is damaged has none)", f)
	}
	for _, c := range []struct {
		msg, key, want string
		times          int
	}{
		{"NAT sessions that cannot be read were skipped", "sessions", "2", 1},
		{"reads of another day were skipped", "lines", "1", 1},
		// Once for the NAT file (2 lines) and once for the Device List file (1 line).
		{"lines that cannot be read were skipped", "", "", 2},
	} {
		if n := h.log.count(c.msg); n != c.times {
			t.Errorf("%q logged %d times, want %d:\n%s", c.msg, n, c.times, h.log.all())
		}
		if c.key != "" {
			if got := h.log.attr(c.msg, c.key); got != c.want {
				t.Errorf("%q: %s = %q, want %q", c.msg, c.key, got, c.want)
			}
		}
	}
	// Logged once per file, however often the day is read.
	n := h.log.count("lines that cannot be read were skipped")
	h.agg(day0, at(1, 0, 0))
	h.agg(day0, at(0, 23, 0))
	if h.log.count("lines that cannot be read were skipped") != n {
		t.Errorf("a damaged file was logged again:\n%s", h.log.all())
	}
	// The damaged lines are compressed with the day: what is stored is kept as it is.
	h.clk.Set(at(1, 0, 1))
	h.nat(at(1, 0, 1))
	if got := h.content("nat-2026-10-05.jsonl.gz"); string(got) != content {
		t.Errorf("the compressed day differs from what was stored")
	}
	if b := h.agg(day0, at(1, 0, 0)); b.Samples != 4 {
		t.Errorf("Samples after compression = %d, want 4", b.Samples)
	}
}

func TestOpenDeletesAnInterruptedCompressedCopy(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{})
	h.nat(at(0, 10, 0), tcp(10, 1, "203.0.113.5", 443))
	if err := h.s.Close(); err != nil {
		t.Fatal(err)
	}
	tmp := h.file("nat-2026-10-05.jsonl.gz.tmp")
	if err := os.WriteFile(tmp, []byte("half a gzip"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.open()
	if h.exists("nat-2026-10-05.jsonl.gz.tmp") {
		t.Error("the temporary file is still there")
	}
	if a := h.agg(day0, at(1, 0, 0)); a.Samples != 1 {
		t.Errorf("Samples = %d", a.Samples)
	}
}

func TestOpenCompletesAnInterruptedCompression(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{})
	h.nat(at(0, 10, 0), tcp(10, 1, "203.0.113.5", 443))
	h.nat(at(0, 11, 0), tcp(10, 2, "203.0.113.5", 443))
	if err := h.s.Close(); err != nil {
		t.Fatal(err)
	}
	// A crash after the compressed copy was renamed into place, before the plain file was
	// deleted.
	plain := h.content("nat-2026-10-05.jsonl")
	gzipTo(t, h.file("nat-2026-10-05.jsonl.gz"), plain)

	h.open() // the same day: nothing is compressed, the plain file is recognized
	if h.exists("nat-2026-10-05.jsonl") {
		t.Error("the plain file that was compressed already is still there")
	}
	if h.log.count("had been compressed already") != 1 {
		t.Errorf("not logged:\n%s", h.log.all())
	}
	if a := h.agg(day0, at(1, 0, 0)); a.Samples != 2 {
		t.Errorf("Samples = %d, want 2 (each read once)", a.Samples)
	}
	// The day keeps being written: a new plain file next to the compressed one.
	h.nat(at(0, 11, 30), tcp(10, 3, "203.0.113.5", 443))
	if a := h.agg(day0, at(1, 0, 0)); a.Samples != 3 {
		t.Errorf("Samples = %d, want 3", a.Samples)
	}
}

func TestOpenKeepsLaterReadsOfACompressedDay(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{})
	h.nat(at(0, 10, 0), tcp(10, 1, "203.0.113.5", 443))
	h.nat(at(0, 11, 0), tcp(10, 2, "203.0.113.5", 443))
	if err := h.s.Close(); err != nil {
		t.Fatal(err)
	}
	// The compressed file holds the first read; the plain file the second (stored after the
	// day was compressed).
	lines := h.lines("nat-2026-10-05.jsonl")
	gzipTo(t, h.file("nat-2026-10-05.jsonl.gz"), []byte(lines[0]+"\n"))
	if err := os.WriteFile(h.file("nat-2026-10-05.jsonl"), []byte(lines[1]+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.open()
	if !h.exists("nat-2026-10-05.jsonl") || !h.exists("nat-2026-10-05.jsonl.gz") {
		t.Fatal("one of the files is gone")
	}
	if a := h.agg(day0, at(1, 0, 0)); a.Samples != 2 {
		t.Errorf("Samples = %d, want 2", a.Samples)
	}
	// Once the day is over, Open merges them.
	h.clk.Set(at(1, 8, 0))
	h.reopen()
	if h.exists("nat-2026-10-05.jsonl") {
		t.Error("the plain file was not merged")
	}
	if got := h.lines("nat-2026-10-05.jsonl.gz"); len(got) != 2 || got[0] != lines[0] || got[1] != lines[1] {
		t.Errorf("the merged day = %v", got)
	}
	if a := h.agg(day0, at(1, 0, 0)); a.Samples != 2 {
		t.Errorf("Samples = %d, want 2", a.Samples)
	}
}

func TestOpenCompressesThePastDays(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{})
	h.nat(at(0, 10, 0), tcp(10, 1, "203.0.113.5", 443))
	h.devices(at(0, 10, 0), device(10, 1, "test-laptop", ""))
	h.clk.Set(at(1, 12, 0))
	if err := h.s.Close(); err != nil {
		t.Fatal(err)
	}
	// Day 1 had a read before a stop that lasted until day 3.
	if err := os.WriteFile(h.file("nat-2026-10-06.jsonl"), mustLine(t, at(1, 9, 0)), 0o644); err != nil {
		t.Fatal(err)
	}
	h.clk.Set(at(3, 8, 0))
	h.open()
	for _, name := range []string{"nat-2026-10-05.jsonl", "devices-2026-10-05.jsonl", "nat-2026-10-06.jsonl"} {
		if h.exists(name) || !h.exists(name+gzExt) {
			t.Errorf("%s was not compressed", name)
		}
	}
	if a := h.agg(day0, at(3, 8, 0)); a.Samples != 2 {
		t.Errorf("Samples = %d", a.Samples)
	}
	if u := h.s.Usage(); u.Files != 3 || u.Oldest != rfc(at(0, 10, 0)) || u.Newest != rfc(at(1, 9, 0)) {
		t.Errorf("Usage = %+v", u)
	}
}

// mustLine returns a NAT line of one session made at tm.
func mustLine(t *testing.T, tm time.Time) []byte {
	t.Helper()
	line, err := encodeNAT(tm, model.NATTable{Sessions: []model.NATSession{tcp(10, 1, "203.0.113.5", 443)}})
	if err != nil {
		t.Fatal(err)
	}
	return line
}

func TestOpenLoadsTheNewestDeviceListRead(t *testing.T) {
	h := newHarness(t, at(1, 12, 0), Options{})
	h.devices(at(0, 10, 0), device(10, 1, "a", ""))
	h.devices(at(0, 11, 0), device(10, 1, "b", ""))
	h.devices(at(1, 9, 0), device(10, 1, "c", ""))
	h.reopen()
	if devices, when := h.s.Devices(); len(devices) != 1 || devices[0].Name != "c" || !when.Equal(at(1, 9, 0)) {
		t.Errorf("Devices = %+v, %s", devices, when)
	}
	// The newest day's only line damaged: the day before's newest read.
	if err := h.s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.file("devices-2026-10-06.jsonl"), []byte(`{"t":"`+rfc(at(1, 9, 0))+`","devices":{}}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.open()
	if devices, when := h.s.Devices(); len(devices) != 1 || devices[0].Name != "b" || !when.Equal(at(0, 11, 0)) {
		t.Errorf("Devices after damage = %+v, %s", devices, when)
	}
	if !strings.Contains(h.log.all(), "lines that cannot be read were skipped") {
		t.Errorf("the damaged line was not logged:\n%s", h.log.all())
	}
}

func TestOpenRefusesNoDirectory(t *testing.T) {
	if _, err := Open("", Options{}); err == nil {
		t.Error("Open without a directory succeeded")
	}
	file := t.TempDir() + "/file"
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(file, Options{}); err == nil {
		t.Error("Open on a file succeeded")
	}
}

// TestOpenLeavesTheCompressionToTheBackground: Open returns once the directory is indexed - the
// service's start, and with it the evidence collection, never waits for a busy day's compression -
// and the store is read meanwhile; the compression follows in the background, and an append, or
// Close, waits for it.
func TestOpenLeavesTheCompressionToTheBackground(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{})
	h.nat(at(0, 10, 0), tcp(10, 1, "203.0.113.5", 443))
	h.devices(at(0, 10, 0), device(10, 1, "test-laptop", ""))
	if err := h.s.Close(); err != nil {
		t.Fatal(err)
	}
	h.clk.Set(at(1, 8, 0))
	release, started := make(chan struct{}), make(chan struct{})
	free := sync.OnceFunc(func() { close(release) })
	t.Cleanup(free) // nothing is left waiting, should the test fail
	h.o.settleStart = func() {
		close(started)
		<-release
	}
	h.open()
	<-started
	// Open has returned with the past day still plain: it is read all the same.
	if !h.exists("nat-2026-10-05.jsonl") || h.exists("nat-2026-10-05.jsonl"+gzExt) {
		t.Fatal("Open compressed the past day itself")
	}
	if a := h.agg(day0, at(1, 8, 0)); a.Samples != 1 {
		t.Fatalf("Samples = %d while the compression waits", a.Samples)
	}
	if devs, _ := h.s.Devices(); len(devs) != 1 {
		t.Fatalf("Devices = %v", devs)
	}
	if u := h.s.Usage(); u.Oldest != rfc(at(0, 10, 0)) {
		t.Fatalf("Usage = %+v", u)
	}
	appended := make(chan error, 1)
	go func() {
		appended <- h.s.AppendNAT(at(1, 8, 0), model.NATTable{Sessions: []model.NATSession{tcp(10, 2, "203.0.113.6", 443)}})
	}()
	select {
	case err := <-appended:
		t.Fatalf("an append did not wait for the background work: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	free()
	if err := <-appended; err != nil {
		t.Fatal(err)
	}
	<-h.s.settled
	if h.exists("nat-2026-10-05.jsonl") || !h.exists("nat-2026-10-05.jsonl"+gzExt) {
		t.Fatal("the past day was not compressed in the background")
	}
	if a := h.agg(day0, at(1, 9, 0)); a.Samples != 2 {
		t.Fatalf("Samples = %d after the compression", a.Samples)
	}

	// Close waits for the background work in progress.
	if err := h.s.Close(); err != nil {
		t.Fatal(err)
	}
	h.clk.Set(at(2, 8, 0))
	hold, holding := make(chan struct{}), make(chan struct{})
	unhold := sync.OnceFunc(func() { close(hold) })
	t.Cleanup(unhold)
	h.o.settleStart = func() {
		close(holding)
		<-hold
	}
	h.open()
	<-holding
	closed := make(chan error, 1)
	go func() { closed <- h.s.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("Close did not wait for the background work: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	unhold()
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if h.exists("nat-2026-10-06.jsonl") || !h.exists("nat-2026-10-06.jsonl"+gzExt) {
		t.Fatal("the background work did not end before Close returned")
	}
}
