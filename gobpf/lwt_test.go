package gobpf

import (
	"net"
	"strings"
	"testing"
)

// Building the lwt route (the same layout as bpf-mlir's test helper) — a unit test without root.
func TestLWTRouteBase(t *testing.T) {
	_, dst, _ := net.ParseCIDR("10.77.0.2/32")
	b := lwtRouteBase(dst, 7)
	// rtmsg (12 byte) + RTA_DST (4 + 4) + RTA_OIF (4 + 4)
	if len(b) != 12+8+8 || b[0] != 2 || b[1] != 32 || b[4] != 254 || b[5] != 3 || b[6] != 253 || b[7] != 1 {
		t.Fatalf("rtmsg / attrs: % x", b)
	}
	if got := b[12+4 : 12+8]; string(got) != string(net.IPv4(10, 77, 0, 2).To4()) {
		t.Fatalf("RTA_DST payload % x", got)
	}
	a := nlAttr(2, append([]byte("p"), 0)) // LWT_BPF_PROG_NAME "p\0" — len 6 aligned to 8
	if len(a) != 8 || a[0] != 6 || a[2] != 2 {
		t.Fatalf("nlAttr: % x", a)
	}
}

// The netfilter guard applies to routes too: passing the process's own netns (the host netns) sends nothing — as root the guard reports "host netns", without root
// it is setns's EPERM or the error of not reading /proc/1/ns/net, and neither runs f.
func TestInNetnsRefusesOwnNetns(t *testing.T) {
	ran := false
	err := inNetns("/proc/self/ns/net", func() error { ran = true; return nil })
	if ran || err == nil {
		t.Fatalf("inNetns ran f in the process's own netns (ran=%v err=%v)", ran, err)
	}
	if !strings.Contains(err.Error(), "is the host netns") && !strings.Contains(err.Error(), "cannot read the host netns") && !strings.Contains(err.Error(), "setns") {
		t.Fatalf("unexpected refusal: %v", err)
	}
	t.Logf("refused: %v", err)
}
