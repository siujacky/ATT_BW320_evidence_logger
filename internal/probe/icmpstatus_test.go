package probe

import "testing"

func TestICMPStatusName(t *testing.T) {
	tests := []struct {
		code uint32
		want string
	}{
		{0, "IP_SUCCESS"},
		{11001, "IP_BUF_TOO_SMALL"},
		{11002, "IP_DEST_NET_UNREACHABLE"},
		{11003, "IP_DEST_HOST_UNREACHABLE"},
		{11004, "IP_DEST_PROT_UNREACHABLE"},
		{11005, "IP_DEST_PORT_UNREACHABLE"},
		{11006, "IP_NO_RESOURCES"},
		{11007, "IP_BAD_OPTION"},
		{11008, "IP_HW_ERROR"},
		{11009, "IP_PACKET_TOO_BIG"},
		{11010, "IP_REQ_TIMED_OUT"},
		{11011, "IP_BAD_REQ"},
		{11012, "IP_BAD_ROUTE"},
		{11013, "IP_TTL_EXPIRED_TRANSIT"},
		{11014, "IP_TTL_EXPIRED_REASSEM"},
		{11015, "IP_PARAM_PROBLEM"},
		{11016, "IP_SOURCE_QUENCH"},
		{11017, "IP_OPTION_TOO_BIG"},
		{11018, "IP_BAD_DESTINATION"},
		{11040, "IP_DEST_UNREACHABLE"},
		{11041, "IP_TIME_EXCEEDED"},
		{11042, "IP_BAD_HEADER"},
		{11043, "IP_UNRECOGNIZED_NEXT_HEADER"},
		{11044, "IP_ICMP_ERROR"},
		{11045, "IP_DEST_SCOPE_MISMATCH"},
		{11050, "IP_GENERAL_FAILURE"},
		{11255, "IP_PENDING"},
		// Unknown codes are never given a guessed name.
		{11000, "IP_STATUS_11000"},
		{11036, "IP_STATUS_11036"}, // first code after IP_NO_FURTHER_SENDS (11035)
		{11039, "IP_STATUS_11039"},
		{11046, "IP_STATUS_11046"},
		{11049, "IP_STATUS_11049"},
		{87, "IP_STATUS_87"},
		{4294967295, "IP_STATUS_4294967295"},
	}
	for _, tt := range tests {
		if got := ICMPStatusName(tt.code); got != tt.want {
			t.Errorf("ICMPStatusName(%d) = %q, want %q", tt.code, got, tt.want)
		}
	}
	// The table covers the documented range 11001..11018 contiguously.
	for c := uint32(11001); c <= 11018; c++ {
		if _, ok := ipStatusNames[c]; !ok {
			t.Errorf("code %d missing from ipStatusNames", c)
		}
	}
}

func TestIsIPStatus(t *testing.T) {
	tests := []struct {
		code uint32
		want bool
	}{
		{0, false}, // success is not an error code
		{87, false},
		{1231, false},
		{11000, false},
		{11001, true},
		{11010, true},
		{11050, true},
		{11255, true},
		{11999, true},
		{12000, false},
	}
	for _, tt := range tests {
		if got := isIPStatus(tt.code); got != tt.want {
			t.Errorf("isIPStatus(%d) = %v, want %v", tt.code, got, tt.want)
		}
	}
}

func TestIsDestUnreachable(t *testing.T) {
	for code, want := range map[uint32]bool{
		ipDestNetUnreachable: true, ipDestHostUnreachable: true, ipDestProtUnreachable: true,
		ipDestPortUnreachable: true, ipDestUnreachable: true,
		ipSuccess: false, ipReqTimedOut: false, ipTTLExpiredTransit: false, ipGeneralFailure: false,
	} {
		if got := isDestUnreachable(code); got != want {
			t.Errorf("isDestUnreachable(%s) = %v, want %v", ICMPStatusName(code), got, want)
		}
	}
}
