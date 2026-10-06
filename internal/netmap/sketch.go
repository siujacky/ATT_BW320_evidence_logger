package netmap

import (
	"encoding/binary"
	"math"
	"math/bits"
	"slices"
)

// The views count what a hostile sender can multiply without bound - the sources of spoofed
// packets, the remote addresses of a LAN host - one by one only up to a bound (bounds); beyond
// it they keep two small sketches instead: a HyperLogLog, which estimates how many distinct
// values it saw, and a Space-Saving table, which keeps the heaviest of them.

// hll estimates how many distinct values were added (HyperLogLog: Flajolet, Fusy, Gandouet and
// Meunier 2007, with its small-range correction, linear counting). It holds 2^p registers of a
// byte; the standard error of its estimate is about 1.04/sqrt(2^p): 0.8% with p = 14 (16 KiB),
// 1.6% with p = 12 (4 KiB). Far below 2^p values it counts almost exactly.
type hll struct {
	p    uint8
	regs []uint8
}

// Precisions of the sketches: of the whole (hllPrecision) and of each part of it, such as the
// sources of one country (hllPartPrecision).
const (
	hllPrecision     = 14
	hllPartPrecision = 12
)

func newHLL(p uint8) *hll { return &hll{p: p, regs: make([]uint8, 1<<p)} }

// add adds a value by its hash (a well-mixed 64-bit hash: hash16, hashString).
func (h *hll) add(x uint64) {
	i := x >> (64 - h.p)
	// The bit set below the hash's remaining bits bounds the rank at 64-p+1.
	r := uint8(bits.LeadingZeros64(x<<h.p|1<<(h.p-1))) + 1
	if r > h.regs[i] {
		h.regs[i] = r
	}
}

// estimate returns how many distinct values were added, about.
func (h *hll) estimate() float64 {
	m := float64(len(h.regs))
	sum, zeros := 0.0, 0
	for _, r := range h.regs {
		sum += math.Ldexp(1, -int(r))
		if r == 0 {
			zeros++
		}
	}
	e := 0.7213 / (1 + 1.079/m) * m * m / sum
	if e <= 2.5*m && zeros > 0 {
		e = m * math.Log(m/float64(zeros)) // linear counting
	}
	return e
}

// count returns the estimate as a whole number.
func (h *hll) count() int { return int(math.Round(h.estimate())) }

// mix64 mixes the bits of x (the finalizer of SplitMix64, a bijection).
func mix64(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

// hash16 hashes an address in its 16-byte form.
func hash16(a [16]byte) uint64 {
	return mix64(binary.LittleEndian.Uint64(a[:8]) ^ mix64(binary.LittleEndian.Uint64(a[8:])+0x9e3779b97f4a7c15))
}

// hashString hashes a string (FNV-1a, mixed).
func hashString(s string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return mix64(h)
}

// distinct counts distinct values: exactly, as a set of strings (exact, addString), or by their
// hashes (addHash) exactly while there are at most fewDistinct, then in a sketch - so that
// counting for many keys (the remote addresses of each device) takes at most a sketch per key.
type distinct struct {
	exact bool
	set   map[string]struct{}
	few   []uint64 // the hashes, while there are at most fewDistinct
	hll   *hll
}

const fewDistinct = 32

// addString adds a value to an exact count.
func (d *distinct) addString(s string) {
	if d.set == nil {
		d.set = map[string]struct{}{}
	}
	d.set[s] = struct{}{}
}

// addHash adds a value by its hash to a count that is not exact.
func (d *distinct) addHash(h uint64) {
	switch {
	case d.hll != nil:
		d.hll.add(h)
	case slices.Contains(d.few, h):
	case len(d.few) < fewDistinct:
		d.few = append(d.few, h)
	default:
		d.hll = newHLL(hllPartPrecision)
		for _, x := range d.few {
			d.hll.add(x)
		}
		d.hll.add(h)
		d.few = nil
	}
}

func (d *distinct) count() int {
	switch {
	case d.exact:
		return len(d.set)
	case d.hll != nil:
		return d.hll.count()
	}
	return len(d.few)
}

// heavy keeps the heaviest of the keys added to it, at most max of them (Space-Saving: Metwally,
// Agrawal and El Abbadi 2005). A key it does not keep replaces the lightest kept one, which
// leaves. Its count is what was added for it since it was kept; err is what may have been added
// for it before (the count and err of the key it replaced), so what was added for it in all lies
// between count and count+err. Any key with more than (everything added)/max is kept. Each key
// also keeps the newest time and the distinct ports added with it since it was kept.
type heavy[K comparable] struct {
	max   int
	pos   map[K]int // a key's position in items
	items []heavyItem[K]
}

type heavyItem[K comparable] struct {
	key   K
	count int
	err   int
	last  int64
	ports []uint16 // sorted, at most maxPorts
}

func newHeavy[K comparable](max int) *heavy[K] {
	return &heavy[K]{max: max, pos: map[K]int{}}
}

// bound is what decides which key leaves first: the most that may have been added for it.
func (it *heavyItem[K]) bound() int { return it.count + it.err }

// add adds n for k, the newest at last, with ports (sorted; the table copies them).
func (h *heavy[K]) add(k K, n int, last int64, ports []uint16) {
	if h.max <= 0 {
		return
	}
	if i, ok := h.pos[k]; ok {
		it := &h.items[i]
		it.count += n
		it.last = max(it.last, last)
		it.ports = mergePorts(it.ports, ports)
		h.down(i)
		return
	}
	if len(h.items) < h.max {
		h.items = append(h.items, heavyItem[K]{key: k, count: n, last: last, ports: mergePorts(nil, ports)})
		h.pos[k] = len(h.items) - 1
		h.up(len(h.items) - 1)
		return
	}
	root := &h.items[0]
	delete(h.pos, root.key)
	err := root.bound()
	kept := append(root.ports[:0], ports[:min(len(ports), maxPorts)]...)
	*root = heavyItem[K]{key: k, count: n, err: err, last: last, ports: kept}
	h.pos[k] = 0
	h.down(0)
}

// less orders the items by bound: the lightest is at the root.
func (h *heavy[K]) less(i, j int) bool { return h.items[i].bound() < h.items[j].bound() }

func (h *heavy[K]) swap(i, j int) {
	h.items[i], h.items[j] = h.items[j], h.items[i]
	h.pos[h.items[i].key] = i
	h.pos[h.items[j].key] = j
}

func (h *heavy[K]) up(i int) {
	for i > 0 {
		p := (i - 1) / 2
		if !h.less(i, p) {
			return
		}
		h.swap(i, p)
		i = p
	}
}

func (h *heavy[K]) down(i int) {
	n := len(h.items)
	for {
		l := 2*i + 1
		if l >= n {
			return
		}
		c := l
		if r := l + 1; r < n && h.less(r, l) {
			c = r
		}
		if !h.less(c, i) {
			return
		}
		h.swap(i, c)
		i = c
	}
}
