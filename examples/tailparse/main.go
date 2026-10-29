// tailparse is an example that splits frame parsing into two stages of xdp programs with tail calls.
//
// The first stage Classify reads the EtherType and moves with TailCallIf to slot 0 (ParseIPv4) for IPv4 and slot 1 (ParseIPv6) for IPv6
// (a frame shorter than 14 bytes passes with neither a tail call nor the fallback). Other EtherTypes use an out-of-range slot index, and the fallback counts no-parser.
// The second stage reads the L4 protocol from the IP header and adds to the per-protocol counter. Slots are declared with `var _ = bpf.TailSlot(…)`, and
// gobpf.Load sets them after load.
//
//	tailparse -iface <name> [-duration 5s]   # attach and print the counts
//	tailparse -selftest                      # run a set of frames through BPF_PROG_TEST_RUN without attaching and compare with the expected table
//	tailparse -parse-only                    # parse the embedded ELF without touching the kernel (no root needed)
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
	"github.com/cilium/ebpf/rlimit"
	"github.com/yuskesh/go-bpf-mlir/livecaps"

	"github.com/yuskesh/go-bpf-mlir/bpf"
	"github.com/yuskesh/go-bpf-mlir/gobpf"
)

//go:generate go tool gobpf

// The count keys (indexes into Counts). The IPv4 and IPv6 tcp, udp, icmp and other keys follow the l4Key order (4 in a row from base).
const (
	KNoParser   uint32 = 0 // an EtherType that is neither IPv4 nor IPv6 (the Classify fallback)
	KIPv4TCP    uint32 = 1
	KIPv4UDP    uint32 = 2
	KIPv4ICMP   uint32 = 3
	KIPv4Other  uint32 = 4
	KIPv4Short  uint32 = 5 // IPv4, but too short to reach the protocol byte (offset 23)
	KIPv6TCP    uint32 = 6
	KIPv6UDP    uint32 = 7
	KIPv6ICMPv6 uint32 = 8
	KIPv6Other  uint32 = 9
	KIPv6Short  uint32 = 10 // IPv6, but too short to reach the next header byte (offset 20)
	NumKeys            = 11
)

var keyNames = []string{"no-parser", "ipv4-tcp", "ipv4-udp", "ipv4-icmp", "ipv4-other", "ipv4-short", "ipv6-tcp", "ipv6-udp", "ipv6-icmpv6", "ipv6-other", "ipv6-short"}

// Counts is the shared declaration: the number of frames per key.
var Counts = bpf.Array[uint32, uint64]{MaxEntries: NumKeys}

// Parsers is the prog_array of the second-stage programs.
var Parsers = bpf.ProgArray{MaxEntries: 2}

// The slot numbers.
const (
	SlotIPv4 = 0
	SlotIPv6 = 1
	noSlot   = 0xffffffff // out of range — the tail call fails and falls back
)

var _ = bpf.TailSlot(&Parsers, SlotIPv4, ParseIPv4)
var _ = bpf.TailSlot(&Parsers, SlotIPv6, ParseIPv6)

// Classify is the first stage (the xdp program that is attached).
func Classify(ctx *bpf.XDPContext) bpf.XDPAction {
	slot := uint32(noSlot)
	long := false
	if w, ok := ctx.Check(0, 14); ok {
		long = true
		et := w.BE16(12)
		if et == 0x0800 {
			slot = SlotIPv4
		} else if et == 0x86dd {
			slot = SlotIPv6
		}
	}
	Parsers.TailCallIf(ctx, long, slot, bpf.XDPPass)
	Counts.AtomicAdd(KNoParser, 1)
	return bpf.XDPPass
}

// ParseIPv4 is slot 0: the IPv4 protocol (offset 23).
func ParseIPv4(ctx *bpf.XDPContext) bpf.XDPAction {
	key := KIPv4Short
	if w, ok := ctx.Check(0, 24); ok {
		key = l4Key(w.U8(23), KIPv4TCP, 1)
	}
	Counts.AtomicAdd(key, 1)
	return bpf.XDPPass
}

// ParseIPv6 is slot 1: the IPv6 next header (offset 20).
func ParseIPv6(ctx *bpf.XDPContext) bpf.XDPAction {
	key := KIPv6Short
	if w, ok := ctx.Check(0, 21); ok {
		key = l4Key(w.U8(20), KIPv6TCP, 58)
	}
	Counts.AtomicAdd(key, 1)
	return bpf.XDPPass
}

// l4Key picks the key from the protocol number (a subprogram both second stages call). The keys run base (tcp), base+1 (udp), base+2 (icmp), base+3 (other);
// icmp is 1 for IPv4 or 58 for IPv6.
func l4Key(proto uint8, base uint32, icmpProto uint8) uint32 {
	k := base + 3
	if proto == 6 {
		k = base
	} else if proto == 17 {
		k = base + 1
	} else if proto == icmpProto {
		k = base + 2
	}
	return k
}

func main() {
	iface := flag.String("iface", "", "network interface to attach to")
	duration := flag.Duration("duration", 0, "run for this long, then exit (0 = print once and exit)")
	selftest := flag.Bool("selftest", false, "run a set of frames through BPF_PROG_TEST_RUN without attaching and compare with the expected table")
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
	objs, rest, err := gobpf.Load(livecaps.New()) // Load sets slots 0 / 1
	if err != nil {
		log.Fatalf("load: %v", err)
	}
	defer objs.Close() // closing removes the prog_array slots — keep it open while attached
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
	l, err := gobpf.AttachXDP(objs, Classify, ifindex)
	if err != nil {
		log.Fatalf("cannot attach XDP to %s: %v", *iface, err)
	}
	defer l.Close()
	deadline := time.Now().Add(*duration)
	for {
		printCounts()
		if *duration <= 0 || time.Now().After(deadline) {
			return
		}
		time.Sleep(time.Second)
	}
}

func readCounts() ([]uint64, error) {
	out := make([]uint64, NumKeys)
	for k := uint32(0); k < NumKeys; k++ {
		v, err := Counts.Get(k)
		if err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, nil
}

func printCounts() {
	c, err := readCounts()
	if err != nil {
		log.Printf("cannot read the counter: %v", err)
		return
	}
	var parts []string
	for k, v := range c {
		parts = append(parts, fmt.Sprintf("%s=%d", keyNames[k], v))
	}
	fmt.Println("counts " + strings.Join(parts, " "))
}

// selftestFrame is a frame for the test run and its expected key (a hand-written table). A frame with key -1 is not counted (under 14 bytes — the false otherwise).
type selftestFrame struct {
	name  string
	frame []byte
	key   int
	times int
}

func ether(n int, et uint16) []byte {
	f := make([]byte, n)
	for i := range f {
		f[i] = byte(0x81 + 0x11*i)
	}
	if n >= 14 {
		f[12], f[13] = byte(et>>8), byte(et)
	}
	return f
}

// withProto is a frame with the protocol byte at offset at.
func withProto(n int, et uint16, at int, proto byte) []byte {
	f := ether(n, et)
	if n > at {
		f[at] = proto
	}
	return f
}

func selftestFrames() []selftestFrame {
	return []selftestFrame{
		{"arp", ether(42, 0x0806), int(KNoParser), 1},
		{"other-88b5", ether(60, 0x88b5), int(KNoParser), 2},
		{"ipv4-tcp", withProto(54, 0x0800, 23, 6), int(KIPv4TCP), 3},
		{"ipv4-udp", withProto(42, 0x0800, 23, 17), int(KIPv4UDP), 4},
		{"ipv4-icmp", withProto(42, 0x0800, 23, 1), int(KIPv4ICMP), 5},
		{"ipv4-gre", withProto(38, 0x0800, 23, 47), int(KIPv4Other), 6},
		{"ipv4-24", withProto(24, 0x0800, 23, 17), int(KIPv4UDP), 7},  // the protocol byte is just present
		{"ipv4-23", withProto(23, 0x0800, 23, 0), int(KIPv4Short), 8}, // missing
		{"ipv6-tcp", withProto(74, 0x86dd, 20, 6), int(KIPv6TCP), 9},
		{"ipv6-udp", withProto(62, 0x86dd, 20, 17), int(KIPv6UDP), 10},
		{"ipv6-icmpv6", withProto(62, 0x86dd, 20, 58), int(KIPv6ICMPv6), 11},
		{"ipv6-icmp1", withProto(62, 0x86dd, 20, 1), int(KIPv6Other), 12}, // 1 is not icmp in IPv6
		{"ipv4-icmp58", withProto(42, 0x0800, 23, 58), int(KIPv4Other), 13},
		{"ipv6-21", withProto(21, 0x86dd, 20, 17), int(KIPv6UDP), 14},
		{"ipv6-20", withProto(20, 0x86dd, 20, 0), int(KIPv6Short), 15},
		{"ether-14-ipv4", ether(14, 0x0800), int(KIPv4Short), 16},
	}
}

func runSelftest(objs *gobpf.Objects) int {
	prog, err := objs.Program(Classify)
	if err != nil {
		log.Print(err)
		return 1
	}
	want := make([]uint64, NumKeys)
	for _, f := range selftestFrames() {
		for i := 0; i < f.times; i++ {
			ret, err := prog.Run(&ebpf.RunOptions{Data: f.frame})
			if err != nil {
				log.Printf("%s: test run: %v", f.name, err)
				return 1
			}
			if ret != uint32(bpf.XDPPass) {
				log.Printf("%s: return %d, want XDP_PASS", f.name, ret)
				return 1
			}
		}
		want[f.key] += uint64(f.times)
	}
	got, err := readCounts()
	if err != nil {
		log.Print(err)
		return 1
	}
	ok := true
	for k := range want {
		if got[k] != want[k] {
			ok = false
			fmt.Printf("mismatch %s: got %d want %d\n", keyNames[k], got[k], want[k])
		}
	}
	printCounts()
	fmt.Printf("selftest result=%s\n", map[bool]string{true: "ok", false: "FAIL"}[ok])
	if !ok {
		return 1
	}
	return 0
}

// ifindexOf reads the ifindex from sysfs.
func ifindexOf(name string) (int, error) {
	b, err := os.ReadFile("/sys/class/net/" + name + "/ifindex")
	if err != nil {
		return 0, fmt.Errorf("interface %q not found: %w", name, err)
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}
