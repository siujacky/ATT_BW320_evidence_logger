package probe

import "strconv"

// Windows IP_STATUS codes (ipexport.h) returned by IcmpSendEcho, either in
// ICMP_ECHO_REPLY.Status or, when no reply structure is returned, via GetLastError.
const (
	ipSuccess             = 0
	ipStatusBase          = 11000
	ipBufTooSmall         = 11001
	ipDestNetUnreachable  = 11002
	ipDestHostUnreachable = 11003
	ipDestProtUnreachable = 11004
	ipDestPortUnreachable = 11005
	ipNoResources         = 11006
	ipBadOption           = 11007
	ipHwError             = 11008
	ipPacketTooBig        = 11009
	ipReqTimedOut         = 11010
	ipBadReq              = 11011
	ipBadRoute            = 11012
	ipTTLExpiredTransit   = 11013
	ipTTLExpiredReassem   = 11014
	ipParamProblem        = 11015
	ipSourceQuench        = 11016
	ipOptionTooBig        = 11017
	ipBadDestination      = 11018
	// 11019-11035 are status indications to transport protocols; IcmpSendEcho is not
	// documented to return them, but they are named rather than shown as numbers.
	ipAddrDeleted                  = 11019
	ipSpecMTUChange                = 11020
	ipMTUChange                    = 11021
	ipUnload                       = 11022
	ipAddrAdded                    = 11023
	ipMediaConnect                 = 11024
	ipMediaDisconnect              = 11025
	ipBindAdapter                  = 11026
	ipUnbindAdapter                = 11027
	ipDeviceDoesNotExist           = 11028
	ipDuplicateAddress             = 11029
	ipInterfaceMetricChange        = 11030
	ipReconfigSecFltr              = 11031
	ipNegotiatingIPSec             = 11032
	ipInterfaceWOLCapabilityChange = 11033
	ipDuplicateIPAdd               = 11034
	ipNoFurtherSends               = 11035
	ipDestUnreachable              = 11040 // IPv6-only codes 11040-11045
	ipTimeExceeded                 = 11041
	ipBadHeader                    = 11042
	ipUnrecognizedNextHdr          = 11043
	ipICMPError                    = 11044
	ipDestScopeMismatch            = 11045
	ipGeneralFailure               = 11050
	ipPending                      = 11255
	ipStatusMax                    = 11999 // upper bound used to recognise IP_STATUS codes
)

// ipStatusNames maps every IP_STATUS code defined in the Windows SDK's ipexport.h to its
// name (IPv4 spelling where IPv6 aliases exist, e.g. 11002 is IP_DEST_NET_UNREACHABLE rather
// than IP_DEST_NO_ROUTE).
var ipStatusNames = map[uint32]string{
	ipSuccess:                      "IP_SUCCESS",
	ipBufTooSmall:                  "IP_BUF_TOO_SMALL",
	ipDestNetUnreachable:           "IP_DEST_NET_UNREACHABLE",
	ipDestHostUnreachable:          "IP_DEST_HOST_UNREACHABLE",
	ipDestProtUnreachable:          "IP_DEST_PROT_UNREACHABLE",
	ipDestPortUnreachable:          "IP_DEST_PORT_UNREACHABLE",
	ipNoResources:                  "IP_NO_RESOURCES",
	ipBadOption:                    "IP_BAD_OPTION",
	ipHwError:                      "IP_HW_ERROR",
	ipPacketTooBig:                 "IP_PACKET_TOO_BIG",
	ipReqTimedOut:                  "IP_REQ_TIMED_OUT",
	ipBadReq:                       "IP_BAD_REQ",
	ipBadRoute:                     "IP_BAD_ROUTE",
	ipTTLExpiredTransit:            "IP_TTL_EXPIRED_TRANSIT",
	ipTTLExpiredReassem:            "IP_TTL_EXPIRED_REASSEM",
	ipParamProblem:                 "IP_PARAM_PROBLEM",
	ipSourceQuench:                 "IP_SOURCE_QUENCH",
	ipOptionTooBig:                 "IP_OPTION_TOO_BIG",
	ipBadDestination:               "IP_BAD_DESTINATION",
	ipAddrDeleted:                  "IP_ADDR_DELETED",
	ipSpecMTUChange:                "IP_SPEC_MTU_CHANGE",
	ipMTUChange:                    "IP_MTU_CHANGE",
	ipUnload:                       "IP_UNLOAD",
	ipAddrAdded:                    "IP_ADDR_ADDED",
	ipMediaConnect:                 "IP_MEDIA_CONNECT",
	ipMediaDisconnect:              "IP_MEDIA_DISCONNECT",
	ipBindAdapter:                  "IP_BIND_ADAPTER",
	ipUnbindAdapter:                "IP_UNBIND_ADAPTER",
	ipDeviceDoesNotExist:           "IP_DEVICE_DOES_NOT_EXIST",
	ipDuplicateAddress:             "IP_DUPLICATE_ADDRESS",
	ipInterfaceMetricChange:        "IP_INTERFACE_METRIC_CHANGE",
	ipReconfigSecFltr:              "IP_RECONFIG_SECFLTR",
	ipNegotiatingIPSec:             "IP_NEGOTIATING_IPSEC",
	ipInterfaceWOLCapabilityChange: "IP_INTERFACE_WOL_CAPABILITY_CHANGE",
	ipDuplicateIPAdd:               "IP_DUPLICATE_IPADD",
	ipNoFurtherSends:               "IP_NO_FURTHER_SENDS",
	ipDestUnreachable:              "IP_DEST_UNREACHABLE",
	ipTimeExceeded:                 "IP_TIME_EXCEEDED",
	ipBadHeader:                    "IP_BAD_HEADER",
	ipUnrecognizedNextHdr:          "IP_UNRECOGNIZED_NEXT_HEADER",
	ipICMPError:                    "IP_ICMP_ERROR",
	ipDestScopeMismatch:            "IP_DEST_SCOPE_MISMATCH",
	ipGeneralFailure:               "IP_GENERAL_FAILURE",
	ipPending:                      "IP_PENDING",
}

// ICMPStatusName returns the ipexport.h name of a Windows IP_STATUS code, e.g.
// ICMPStatusName(11010) == "IP_REQ_TIMED_OUT". Unknown codes are rendered as
// "IP_STATUS_<code>" so that nothing is ever reported under a guessed name.
//
// FormatMessage must not be used for these codes: the 11xxx range collides with the
// Winsock WSA_QOS_* errors, so the system message for 11010 is unrelated to timeouts.
func ICMPStatusName(code uint32) string {
	if name, ok := ipStatusNames[code]; ok {
		return name
	}
	return "IP_STATUS_" + strconv.FormatUint(uint64(code), 10)
}

// isIPStatus reports whether a GetLastError value from IcmpSendEcho is an IP_STATUS code
// (as opposed to a Win32 error such as ERROR_INVALID_PARAMETER).
func isIPStatus(code uint32) bool { return code > ipStatusBase && code <= ipStatusMax }

// isDestUnreachable reports the "destination unreachable" family, which ends a traceroute.
func isDestUnreachable(code uint32) bool {
	switch code {
	case ipDestNetUnreachable, ipDestHostUnreachable, ipDestProtUnreachable,
		ipDestPortUnreachable, ipDestUnreachable:
		return true
	}
	return false
}
