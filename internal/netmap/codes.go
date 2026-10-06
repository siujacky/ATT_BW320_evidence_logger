package netmap

// Codes of a codeTable.
const (
	codeNone = 0   // not stated ("")
	codeMore = 255 // a value beyond the first 254 distinct ones
)

// codes numbers the protocols and the firewall reasons of dropped packets, so that the cached
// chunk summaries hold small numbers instead of strings: they take less memory, and the garbage
// collector need not look into them. A number keeps its meaning for the life of the View; the
// tables stop growing at 254 values (a hostile log could invent any number of reasons), and
// later values share codeMore. Only firewall builds use them: View.fwSlot guards them.
type codes struct {
	protos  codeTable
	reasons codeTable
}

func newCodes() *codes {
	return &codes{protos: newCodeTable("other"), reasons: newCodeTable(otherReasons)}
}

// codeTable numbers distinct strings from 1 on.
type codeTable struct {
	names []string // by code; names[codeNone] is ""
	ids   map[string]uint8
	more  string // the name of codeMore
	// last is the value asked for last, and lastID its code: lines in a row mostly repeat it.
	last   string
	lastID uint8
}

func newCodeTable(more string) codeTable {
	return codeTable{names: []string{""}, ids: map[string]uint8{}, more: more}
}

// id returns the code of b (codeNone for an empty b).
func (t *codeTable) id(b []byte) uint8 {
	switch {
	case len(b) == 0:
		return codeNone
	case string(b) == t.last && t.last != "":
		return t.lastID
	}
	id, ok := t.ids[string(b)]
	switch {
	case ok:
	case len(t.names) >= codeMore:
		return codeMore
	default:
		s := string(b)
		id = uint8(len(t.names))
		t.ids[s] = id
		t.names = append(t.names, s)
	}
	t.last, t.lastID = t.names[id], id
	return id
}

// name returns the string of a code.
func (t *codeTable) name(id uint8) string {
	switch {
	case id == codeMore:
		return t.more
	case int(id) < len(t.names):
		return t.names[id]
	}
	return ""
}
