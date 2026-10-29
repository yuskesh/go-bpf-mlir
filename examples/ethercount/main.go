// ethercount is an example with an xdp program (the eBPF side) that counts frames per EtherType and IPv4 protocol,
// and the user-space side that loads and attaches it and prints the counts, in one Go program.
//
//	ethercount -iface <name> [-duration 5s]   # attach and print the counts
//	ethercount -selftest                      # run a set of frames through BPF_PROG_TEST_RUN without attaching and compare with the expected table
//	ethercount -parse-only                    # parse the embedded ELF without touching the kernel (no root needed)
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

// The count keys (indexes into Counts).
const (
	KShort     uint32 = 0 // a frame shorter than 14 bytes (neither BPF_PROG_TEST_RUN nor veth passes fewer than 14 — not observable at run time)
	KIPv4TCP   uint32 = 1
	KIPv4UDP   uint32 = 2
	KIPv4ICMP  uint32 = 3
	KIPv4Other uint32 = 4
	KIPv4Short uint32 = 5 // IPv4, but too short to reach the protocol byte (offset 23)
	KIPv6      uint32 = 6
	KARP       uint32 = 7
	KOther     uint32 = 8
	NumKeys           = 9
)

var keyNames = []string{"short", "ipv4-tcp", "ipv4-udp", "ipv4-icmp", "ipv4-other", "ipv4-short", "ipv6", "arp", "other"}

// Counts is the shared declaration: the number of frames per key.
var Counts = bpf.Array[uint32, uint64]{MaxEntries: NumKeys}

// classify picks the key from the EtherType and the IPv4 protocol (a subprogram on the eBPF side).
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

// CountEther is the eBPF side (an xdp program).
func CountEther(ctx *bpf.XDPContext) bpf.XDPAction {
	key := KShort
	if w, ok := ctx.Check(0, 14); ok {
		et := w.BE16(12)
		key = classify(et, 0)
		if et == 0x0800 {
			key = KIPv4Short
			if w2, ok2 := ctx.Check(0, 24); ok2 {
				key = classify(et, w2.U8(23))
			}
		}
	}
	Counts.AtomicAdd(key, 1)
	return bpf.XDPPass
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
	l, err := gobpf.AttachXDP(objs, CountEther, ifindex)
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

// selftestFrame is a frame for the test run and its expected key (an independent hand-written oracle — ethercount_test.go checks it against classify).
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

func runSelftest(objs *gobpf.Objects) int {
	prog, err := objs.Program(CountEther)
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
