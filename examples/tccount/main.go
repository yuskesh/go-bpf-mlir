// tccount is an example with three programs (the eBPF side) that count received (XDP and tcx ingress) and sent (tcx egress) frames on one interface per
// EtherType and IPv4 protocol, and the user-space side that loads and attaches them and prints the counts, in one Go program.
// The three programs share one map (Counts), and each writes to its own index range (the XDP counts and the tcx ingress counts see the same frames).
//
//	tccount -iface <name> [-duration 5s]   # attach all three and print the counts
//	tccount -selftest                      # run a set of frames through BPF_PROG_TEST_RUN of the three programs without attaching and compare with the expected table
//	tccount -parse-only                    # parse the embedded ELF without touching the kernel (no root needed)
//
// The example only counts (every verdict is pass — no drop / redirect).
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/yuskesh/go-bpf-mlir/livecaps"

	"github.com/yuskesh/go-bpf-mlir/bpf"
	"github.com/yuskesh/go-bpf-mlir/gobpf"
)

//go:generate go tool gobpf

// The frame kind keys (the same classification as ethercount).
const (
	KShort     uint32 = 0 // a frame shorter than 14 bytes (neither the test run nor veth passes fewer than 14 — not observable at run time)
	KIPv4TCP   uint32 = 1
	KIPv4UDP   uint32 = 2
	KIPv4ICMP  uint32 = 3
	KIPv4Other uint32 = 4
	KIPv4Short uint32 = 5 // IPv4, but too short to reach the protocol byte (offset 23)
	KIPv6      uint32 = 6
	KARP       uint32 = 7
	KOther     uint32 = 8
	NumKeys    uint32 = 9
)

// The directions (the Counts index range: direction × NumKeys + key).
const (
	DirXDP     uint32 = 0 // XDP (receive)
	DirIngress uint32 = 1 // tcx ingress (receive)
	DirEgress  uint32 = 2 // tcx egress (send)
	NumDirs    uint32 = 3
)

var keyNames = []string{"short", "ipv4-tcp", "ipv4-udp", "ipv4-icmp", "ipv4-other", "ipv4-short", "ipv6", "arp", "other"}
var dirNames = []string{"xdp", "tc-ingress", "tc-egress"}

// Counts is the declaration the three programs share: the number of frames per (direction, key).
var Counts = bpf.Array[uint32, uint64]{MaxEntries: NumDirs * NumKeys}

// classify picks the key from the EtherType and the IPv4 protocol (a subprogram the three programs call).
func classify(et uint16, proto uint8) uint32 {
	k := KOther
	if et == 0x0806 {
		k = KARP
	} else if et == 0x86dd {
		k = KIPv6
	} else if et == 0x0800 {
		k = KIPv4Other
		if proto == 6 {
			k = KIPv4TCP
		} else if proto == 17 {
			k = KIPv4UDP
		} else if proto == 1 {
			k = KIPv4ICMP
		}
	}
	return k
}

// The window reads are written once in two helpers (keyLong / keyShort — packet window arguments), and the three XDP and tcx programs call them
// (bpf.Window is the same type from XDP and tcx ctx.Check). The helpers have no ctx, so the caller does the Check — the longer one (24 bytes) first.

// keyLong is the key of a frame of 24 bytes or more (for IPv4 it also reads the protocol byte — offset 23).
func keyLong(w bpf.Window) uint32 {
	et := w.BE16(12)
	k := classify(et, 0)
	if et == 0x0800 {
		k = classify(et, w.U8(23))
	}
	return k
}

// keyShort is the key of a frame of 14 to 23 bytes (for IPv4 the protocol byte is not reached).
func keyShort(w bpf.Window) uint32 {
	et := w.BE16(12)
	k := classify(et, 0)
	if et == 0x0800 {
		k = KIPv4Short
	}
	return k
}

func countXDP(ctx *bpf.XDPContext) bpf.XDPAction {
	k := KShort
	if w, ok := ctx.Check(0, 24); ok {
		k = keyLong(w)
	} else {
		if w2, ok2 := ctx.Check(0, 14); ok2 {
			k = keyShort(w2)
		}
	}
	if k >= NumKeys {
		k = NumKeys - 1 // the helper returns less than NumKeys — a clamp that shows the frontend the index range (makes GB020 Verified)
	}
	Counts.AtomicAdd(DirXDP*NumKeys+k, 1)
	return bpf.XDPPass
}

func countIngress(ctx *bpf.TCIngressContext) bpf.TCAction {
	k := KShort
	if w, ok := ctx.Check(0, 24); ok {
		k = keyLong(w)
	} else {
		if w2, ok2 := ctx.Check(0, 14); ok2 {
			k = keyShort(w2)
		}
	}
	if k >= NumKeys {
		k = NumKeys - 1
	}
	Counts.AtomicAdd(DirIngress*NumKeys+k, 1)
	return bpf.TCPass
}

func countEgress(ctx *bpf.TCEgressContext) bpf.TCAction {
	k := KShort
	if w, ok := ctx.Check(0, 24); ok {
		k = keyLong(w)
	} else {
		if w2, ok2 := ctx.Check(0, 14); ok2 {
			k = keyShort(w2)
		}
	}
	if k >= NumKeys {
		k = NumKeys - 1
	}
	Counts.AtomicAdd(DirEgress*NumKeys+k, 1)
	return bpf.TCPass
}

func main() {
	iface := flag.String("iface", "", "network interface to attach to")
	duration := flag.Duration("duration", 0, "run for this long, then exit (0 = print once and exit)")
	selftest := flag.Bool("selftest", false, "run a set of frames through BPF_PROG_TEST_RUN of the 3 programs without attaching and compare with the expected table")
	parseOnly := flag.Bool("parse-only", false, "parse the embedded ELF without touching the kernel")
	flag.Parse()

	if *parseOnly {
		spec, err := gobpf.LoadCollectionSpec()
		if err != nil {
			log.Fatalf("cannot parse the embedded ELF: %v", err)
		}
		fmt.Printf("parse-ok programs=%d maps=%d\n", len(spec.Programs), len(spec.Maps))
		return
	}
	if *iface == "" && !*selftest {
		log.Fatal("-iface or -selftest is required (-parse-only checks without the kernel)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("RemoveMemlock: %v", err)
	}
	objs, rest, err := gobpf.Load(livecaps.New())
	if err != nil {
		log.Fatalf("load: %v", err)
	}
	defer objs.Close()
	for _, u := range rest {
		log.Printf("undetermined (loaded anyway): %s", u.String())
	}
	if *selftest {
		os.Exit(runSelftest(objs))
	}
	ifindex, err := ifindexOf(*iface)
	if err != nil {
		log.Fatal(err)
	}
	var links []link.Link
	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()
	l, err := gobpf.AttachXDP(objs, countXDP, ifindex)
	if err != nil {
		log.Fatalf("cannot attach XDP to %s: %v", *iface, err)
	}
	links = append(links, l)
	// The direction comes from the context type (countIngress is ingress, countEgress is egress).
	in, err := gobpf.AttachTCX(objs, countIngress, ifindex)
	if err != nil {
		log.Fatalf("cannot attach tcx ingress to %s: %v", *iface, err)
	}
	links = append(links, in)
	out, err := gobpf.AttachTCX(objs, countEgress, ifindex)
	if err != nil {
		log.Fatalf("cannot attach tcx egress to %s: %v", *iface, err)
	}
	links = append(links, out)
	deadline := time.Now().Add(*duration)
	for {
		printCounts()
		if *duration <= 0 || time.Now().After(deadline) {
			return
		}
		time.Sleep(time.Second)
	}
}

// readCounts reads the counts per [direction][key].
func readCounts() ([][]uint64, error) {
	out := make([][]uint64, NumDirs)
	for d := uint32(0); d < NumDirs; d++ {
		out[d] = make([]uint64, NumKeys)
		for k := uint32(0); k < NumKeys; k++ {
			v, err := Counts.Get(d*NumKeys + k)
			if err != nil {
				return nil, err
			}
			out[d][k] = v
		}
	}
	return out, nil
}

func printCounts() {
	c, err := readCounts()
	if err != nil {
		log.Printf("cannot read the counter: %v", err)
		return
	}
	for d, row := range c {
		var parts []string
		for k, v := range row {
			parts = append(parts, fmt.Sprintf("%s=%d", keyNames[k], v))
		}
		fmt.Printf("counts dir=%s %s\n", dirNames[d], strings.Join(parts, " "))
	}
}

// selftestFrame is a frame for the test run and its expected key (an independent hand-written oracle — main_test.go checks it against classify).
type selftestFrame struct {
	name  string
	frame []byte
	key   uint32
	times int
}

// ipv4 is an n-byte frame with EtherType 0x0800 and the protocol at offset 23.
func ipv4(n int, proto byte) []byte {
	f := ether(n, 0x0800)
	if n > 23 {
		f[23] = proto
	}
	return f
}

func ether(n int, et uint16) []byte {
	f := make([]byte, n)
	for i := range f {
		f[i] = byte(0x81 + 0x11*i)
	}
	f[12], f[13] = byte(et>>8), byte(et)
	return f
}

func selftestFrames() []selftestFrame {
	return []selftestFrame{
		{"arp", ether(42, 0x0806), KARP, 1},
		{"ipv6", ether(54, 0x86dd), KIPv6, 2},
		{"ipv4-tcp", ipv4(54, 6), KIPv4TCP, 3},
		{"ipv4-udp", ipv4(42, 17), KIPv4UDP, 4},
		{"ipv4-icmp", ipv4(42, 1), KIPv4ICMP, 5},
		{"ipv4-gre", ipv4(38, 47), KIPv4Other, 6},
		{"ipv4-24-udp", ipv4(24, 17), KIPv4UDP, 7}, // the protocol byte is just present (inside the bound)
		{"ipv4-23", ipv4(23, 0), KIPv4Short, 8},    // the protocol byte is missing (outside the bound)
		{"ipv4-14", ipv4(14, 0), KIPv4Short, 9},
		{"other-88b5", ether(60, 0x88b5), KOther, 10},
		{"other-14", ether(14, 0x1234), KOther, 11},
	}
}

// runSelftest runs a different number of times per direction (direction d runs each frame times × (d+1) times) and also checks that the shared map ranges do not mix.
func runSelftest(objs *gobpf.Objects) int {
	// Program functions are passed to Objects.Program directly (if carried around as values, the frontend cannot follow the edge — GB004).
	px, errx := objs.Program(countXDP)
	pi, erri := objs.Program(countIngress)
	pe, erre := objs.Program(countEgress)
	for _, err := range []error{errx, erri, erre} {
		if err != nil {
			log.Print(err)
			return 1
		}
	}
	progs := []struct {
		prog *ebpf.Program
		pass uint32
	}{{px, uint32(bpf.XDPPass)}, {pi, uint32(bpf.TCPass)}, {pe, uint32(bpf.TCPass)}}
	want := make([][]uint64, NumDirs)
	for d, pr := range progs {
		want[d] = make([]uint64, NumKeys)
		for _, f := range selftestFrames() {
			if d != int(DirXDP) && !skbTestRunAccepts(f.frame) {
				continue
			}
			n := f.times * (d + 1)
			for i := 0; i < n; i++ {
				ret, err := pr.prog.Run(&ebpf.RunOptions{Data: f.frame})
				if err != nil {
					log.Printf("%s %s: test run: %v", dirNames[d], f.name, err)
					return 1
				}
				if ret != pr.pass {
					log.Printf("%s %s: return %d, want %d (pass)", dirNames[d], f.name, ret, pr.pass)
					return 1
				}
			}
			want[d][f.key] += uint64(n)
		}
	}
	got, err := readCounts()
	if err != nil {
		log.Print(err)
		return 1
	}
	ok := true
	for d := range want {
		for k := range want[d] {
			if got[d][k] != want[d][k] {
				ok = false
				fmt.Printf("mismatch %s %s: got %d want %d\n", dirNames[d], keyNames[k], got[d][k], want[d][k])
			}
		}
	}
	printCounts()
	fmt.Printf("selftest result=%s\n", map[bool]string{true: "ok", false: "FAIL"}[ok])
	if !ok {
		return 1
	}
	return 0
}

// skbTestRunAccepts reports whether the sched_cls test run (bpf_prog_test_run_skb) accepts the frame: if the EtherType is IPv4 / IPv6,
// the whole IP header (20 / 40 bytes) is needed after Ethernet (the kernel's net/bpf/test_run.c — the same on all three kernels).
// The XDP test run accepts from 14 bytes, so short IPv4 frames run only through XDP.
func skbTestRunAccepts(f []byte) bool {
	et := uint16(f[12])<<8 | uint16(f[13])
	return !(et == 0x0800 && len(f) < 14+20) && !(et == 0x86dd && len(f) < 14+40)
}

// ifindexOf reads the ifindex from sysfs.
func ifindexOf(name string) (int, error) {
	b, err := os.ReadFile("/sys/class/net/" + name + "/ifindex")
	if err != nil {
		return 0, fmt.Errorf("interface %q not found: %w", name, err)
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}
