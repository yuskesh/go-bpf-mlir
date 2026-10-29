package gobpf

import (
	"net"
	"strings"
	"testing"
)

// Building the seg6local route (the same layout as bpf-mlir's test helper) — a unit test without root.
func TestSeg6RouteBase(t *testing.T) {
	b := seg6RouteBase(net.ParseIP("fc00::100"), 7)
	// rtmsg (12 byte) + RTA_DST (4 + 16) + RTA_OIF (4 + 4) + RTA_TABLE (4 + 4)
	if len(b) != 12+20+8+8 || b[0] != 10 || b[1] != 128 || b[4] != 254 || b[5] != 3 || b[6] != 0 || b[7] != 1 {
		t.Fatalf("rtmsg / attrs: % x", b)
	}
	if got := b[12+4 : 12+20]; string(got) != string(net.ParseIP("fc00::100").To16()) {
		t.Fatalf("RTA_DST payload % x", got)
	}
}

// An IPv4 SID is refused before anything is sent (before the objects are looked at).
func TestAttachSeg6LocalRefusesIPv4(t *testing.T) {
	_, err := AttachSeg6Local(nil, "/proc/self/ns/net", net.ParseIP("10.0.0.1"), "lo", nil)
	if err == nil || !strings.Contains(err.Error(), "not an IPv6 address") {
		t.Fatalf("want the IPv6 refusal, got %v", err)
	}
}
