package monitor

import (
	"context"
	"errors"
	"time"

	"attmonitor/internal/model"
)

// The LAN scan (docs/dhcp-table.md §6): every connections.scan_interval the monitor sweeps the home
// network by ARP (Options.Scanner: every address of this PC's own IPv4 network is asked who has
// it, nothing else is sent) and appends the sweep to Options.Scans - the connection store, never
// the ledger: like the Network page's other samples it describes the household, not AT&T's faults.
//
//   - The first sweep is made scanFirst after the start, and after the Device List sampler's first
//     round (the Devices tab compares a sweep with the Device List read before it); then one every
//     interval after the previous one began.
//   - None while the gateway is needed for evidence (samplerHold: an incident open or being closed,
//     a bad cycle, the gateway unreachable at the newest poll): ARP does not use the gateway's web
//     server, but the monitor's own traffic stays out of the evidence's way. Such a round says why
//     (Status.Connections.ScanProblem) and looks again busyRetry later: the sweep is made once the
//     hold ends. A sweep in progress when the gateway becomes needed is stopped (holdWatch) and not
//     kept - a part of a sweep would make the devices it did not reach look silent.
//   - The scanner bounds a sweep itself (lanscan: 2 minutes, at most 32 questions at a time; what
//     answered by then is kept, and the scan's Problem says so); scanTimeout is the backstop.
//   - A sweep that fails, and the store refusing one, are logged when they start, every
//     connFailReport while they go on, and when they end (scanLog); the first sweep that works is
//     logged (Info).

// scanState is what the LAN scan sampler knows (guarded by connSamplers.mu).
type scanState struct {
	at    time.Time // when the newest sweep that worked began (monitor clock; zero: none yet)
	hosts int       // how many addresses answered it
	// problem says why the newest round did not sweep, why its sweep failed, or what its sweep
	// could not do (it stopped short, questions failed, the store refused it); "" when nothing.
	problem string
	next    time.Time // when the next round is due (real time; zero before the loop runs)
}

// scansOn reports whether the LAN scan sampler runs: the samplers run (samplersOn) with a scanner,
// a store for the scans and a connections.scan_interval above 0.
func (m *Monitor) scansOn() bool {
	c := m.conns
	return m.samplersOn() && c.scanner != nil && c.scans != nil && c.scanInterval > 0
}

// scanLoop runs the LAN scan sampler (sampleScan): scanFirst after the start and after the Device
// List sampler's first round (devRound), then about every connections.scan_interval - sooner
// after a round that had to leave the network to the evidence collection.
func (m *Monitor) scanLoop(ctx context.Context) {
	c := m.conns
	first := time.Now().Add(c.scanFirst)
	c.locked(func() { c.scan.next = first })
	select {
	case <-c.devRound:
	case <-ctx.Done():
		return
	}
	next := later(first, time.Now())
	for {
		c.locked(func() { c.scan.next = next })
		if !sleepUntil(ctx, next, nil) {
			return
		}
		next = time.Now().Add(c.scanInterval) // should the round panic
		m.safely("connections", func() { next = m.sampleScan(ctx) })
	}
}

// sampleScan makes one round of the LAN scan sampler: unless the gateway is needed for evidence
// (samplerHold) it sweeps the home network (stopped as soon as the gateway is needed: samplerRead)
// and appends the sweep to the scan store, dated when the round began by the monitor's clock. It
// returns when the next round is due (real time): an interval after this one began, or busyRetry
// after it when it left the network to the evidence collection.
func (m *Monitor) sampleScan(ctx context.Context) time.Time {
	c := m.conns
	began := time.Now()
	next := began.Add(c.scanInterval)
	if why := m.samplerHold(); why != "" {
		m.noteScanSkip(why)
		return earlier(next, began.Add(c.busyRetry))
	}
	at := m.now()
	var scan model.LANScan
	err := m.samplerRead(ctx, c.scanTimeout, func(rctx context.Context) error {
		var serr error
		scan, serr = c.scanner.Scan(rctx)
		return serr
	})
	if ctx.Err() != nil {
		return next // stopping: a stopped sweep says nothing
	}
	var held samplerHeld
	if errors.As(err, &held) {
		m.noteScanSkip(held.why)
		return earlier(next, began.Add(c.busyRetry))
	}
	if err != nil {
		problem := "the home network could not be swept: " + errText(err)
		c.locked(func() { c.scan.problem = problem })
		m.connFailed(&c.scanLog, "cannot sweep the home network for the Network page", problem)
		return next
	}
	scan.At = fmtTS(at)
	if scan.Hosts == nil {
		scan.Hosts = []model.LANHost{}
	}
	serr := c.scans.AppendScan(at, scan)
	problem := scan.Problem
	if serr != nil {
		problem = "the home network was swept, but the connection store could not keep the sweep: " + errText(serr)
	}
	first := false
	c.locked(func() {
		first = c.scan.at.IsZero()
		c.scan.at, c.scan.hosts, c.scan.problem = at, len(scan.Hosts), problem
	})
	if serr != nil {
		m.connFailed(&c.scanLog, "cannot keep the sweeps of the home network for the Network page", problem)
		return next
	}
	m.connWorked(&c.scanLog, "sweeps of the home network for the Network page work again")
	if first {
		m.log.Info("the home network is swept by ARP for the Network page", "subnet", scan.Subnet, "asked", scan.Asked,
			"answered", len(scan.Hosts), "took", time.Duration(scan.TookMs)*time.Millisecond, "problem", scan.Problem, "every", c.scanInterval)
	} else {
		m.log.Debug("home network swept", "answered", len(scan.Hosts), "asked", scan.Asked, "problem", scan.Problem)
	}
	return next
}

// noteScanSkip notes a LAN scan round that did not sweep, or whose sweep was stopped, because the
// gateway is needed for evidence (why) for the status.
func (m *Monitor) noteScanSkip(why string) {
	c := m.conns
	c.locked(func() { c.scan.problem = why })
	m.log.Debug("home network not swept", "why", why)
}
