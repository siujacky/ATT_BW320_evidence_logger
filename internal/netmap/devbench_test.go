package netmap

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// benchDeviceReads is a month of Device List reads every 15 minutes (2,880) of 30 devices, five of
// which change addresses now and then.
func benchDeviceReads() []timedRead {
	start := benchStart.Add(-time.Hour)
	var reads []timedRead
	for i := 0; start.Add(time.Duration(i) * 15 * time.Minute).Before(t0); i++ {
		devs := make([]model.LANDevice, 30)
		for d := range devs {
			host := 60 + d
			if d < 5 {
				host = 60 + (d+i/96)%40 // a new address every day
			}
			devs[d] = model.LANDevice{MAC: fmt.Sprintf("00:00:5e:00:53:%02x", d), Name: "device-" + strconv.Itoa(d),
				IPv4: "192.168.1." + strconv.Itoa(host), Status: []string{"on", "off"}[min(d/25, 1)], Connection: "Wi-Fi 5 GHz", Signal: 1 + d%5}
		}
		reads = append(reads, timedRead{at: start.Add(time.Duration(i) * 15 * time.Minute), devices: devs})
	}
	return reads
}

// BenchmarkDevicesMonth builds the month's Devices view (the result cache off, the syslog chunks'
// summaries cached): 2,880 Device List reads, 5,000 flows and the drops of two million lines.
func BenchmarkDevicesMonth(b *testing.B) {
	var flows []model.ConnFlow
	var devs []model.ConnDevice
	for d := range 30 {
		devs = append(devs, model.ConnDevice{Key: fmt.Sprintf("mac:00:00:5e:00:53:%02x", d), Samples: 100, Weight: 1000, Open: d})
	}
	for i := range 5000 {
		flows = append(flows, model.ConnFlow{Device: fmt.Sprintf("mac:00:00:5e:00:53:%02x", i%30), Remote: fmt.Sprintf("2001:db8:%x::1", i),
			Proto: "tcp", Port: 443, Samples: 1, Weight: 1})
	}
	conns := &fakeHistory{fakeConns: &fakeConns{agg: model.ConnAggregate{Samples: 10000, Devices: devs, Flows: flows}}, reads: benchDeviceReads()}
	v := New(Options{Conns: conns, Syslog: benchSource(), ResultTTL: -1})
	ctx := context.Background()
	if dv, err := v.Devices(ctx, monthQuery); err != nil || len(dv.Devices) != 30 || dv.Reads == 0 {
		b.Fatalf("%d devices, %d reads, %v", len(dv.Devices), dv.Reads, err)
	}
	for b.Loop() {
		if _, err := v.Devices(ctx, monthQuery); err != nil {
			b.Fatal(err)
		}
	}
}
