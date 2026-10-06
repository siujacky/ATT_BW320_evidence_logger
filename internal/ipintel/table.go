package ipintel

import (
	"cmp"
	"encoding/binary"
	"math"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"
)

// family is an address family: which of the two tables (and files) something is about.
type family int

const (
	fam4 family = iota
	fam6
)

// families lists both, in the order they are loaded and downloaded.
var families = [...]family{fam4, fam6}

// fileName is the family's table file in the DB's directory.
func (f family) fileName() string {
	if f == fam4 {
		return nameV4
	}
	return nameV6
}

// asInfo is what the database says about the network of a range. Many ranges share one.
type asInfo struct {
	asn     uint32
	country string // ISO 3166-1 alpha-2; "" when the database gives none
	name    string // the AS description, as in the file (cleaned of control characters)
}

// table is one family's database: sorted, non-overlapping ranges [start[i], end[i]], each with
// the network infos[info[i]]. Only announced ranges are kept (AS 0 lines are gaps). The ranges
// and networks never change once built, so any number of goroutines may search them.
type table[K any] struct {
	start, end []K
	info       []uint32
	infos      []asInfo
	// orgs[i] caches orgName of infos[i], set by the first lookup that needs it: a table names
	// tens of thousands of networks, of which a household meets a few hundred, and naming them all
	// would take a good part of a load's time.
	orgs []atomic.Pointer[string]
}

// size is the number of ranges (0 for a nil table).
func (t *table[K]) size() int {
	if t == nil {
		return 0
	}
	return len(t.start)
}

// find returns the index in infos of the network of the range that holds a, or -1 when no
// announced range does.
func (t *table[K]) find(a K, compare func(K, K) int) int {
	if t == nil || len(t.start) == 0 {
		return -1
	}
	i, found := slices.BinarySearchFunc(t.start, a, compare)
	if !found {
		i-- // the last range starting before a
	}
	if i < 0 || compare(a, t.end[i]) > 0 {
		return -1
	}
	return int(t.info[i])
}

// org returns the readable organisation name of infos[i]. Two goroutines naming the same network
// at once both compute it - the same name: orgName is deterministic.
func (t *table[K]) org(i int) string {
	if p := t.orgs[i].Load(); p != nil {
		return *p
	}
	s := orgName(t.infos[i].asn, t.infos[i].name)
	t.orgs[i].Store(&s)
	return s
}

// u128 is an IPv6 address as a number, for the IPv6 table.
type u128 struct{ hi, lo uint64 }

func u128Of(a netip.Addr) u128 {
	b := a.As16()
	return u128{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])}
}

func (a u128) compare(b u128) int {
	if c := cmp.Compare(a.hi, b.hi); c != 0 {
		return c
	}
	return cmp.Compare(a.lo, b.lo)
}

// next returns a+1, and false when a is the last address.
func (a u128) next() (u128, bool) {
	switch {
	case a.lo != math.MaxUint64:
		return u128{a.hi, a.lo + 1}, true
	case a.hi != math.MaxUint64:
		return u128{a.hi + 1, 0}, true
	}
	return u128{}, false
}

func (a u128) String() string {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], a.hi)
	binary.BigEndian.PutUint64(b[8:], a.lo)
	return netip.AddrFrom16(b).String()
}

// u32Of returns an IPv4 address as a number, for the IPv4 table.
func u32Of(a netip.Addr) uint32 {
	b := a.As4()
	return binary.BigEndian.Uint32(b[:])
}

func next32(a uint32) (uint32, bool) { return a + 1, a != math.MaxUint32 }

func string32(a uint32) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], a)
	return netip.AddrFrom4(b).String()
}

// tables is the loaded database: one table per family (nil until loaded) and the write time of
// the file each came from. Lookups read it through DB.tab and never see it change: a load swaps
// in a new tables value.
type tables struct {
	v4 *table[uint32]
	v6 *table[u128]
	at [2]time.Time
}

// updated is the write time of the oldest loaded file: the database is at least that recent.
func (t *tables) updated() time.Time {
	var u time.Time
	for _, at := range t.at {
		if !at.IsZero() && (u.IsZero() || at.Before(u)) {
			u = at
		}
	}
	return u
}

// lookup returns the network of a, a public address (IPv4 or IPv6), and its organisation name;
// nil when the database does not know a.
func (t *tables) lookup(a netip.Addr) (*asInfo, string) {
	if a.Is4() {
		if i := t.v4.find(u32Of(a), cmp.Compare[uint32]); i >= 0 {
			return &t.v4.infos[i], t.v4.org(i)
		}
		return nil, ""
	}
	if i := t.v6.find(u128Of(a), u128.compare); i >= 0 {
		return &t.v6.infos[i], t.v6.org(i)
	}
	return nil, ""
}
