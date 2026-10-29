// xdpcount is the first example: one Go program holds an xdp program (the eBPF side) and the user-space side that loads and attaches it and reads the map,
// and `go generate && go build` turns it into one binary.
//
//	xdpcount -iface <name> [-duration 5s]   # attach and print the counters
//	xdpcount -selftest N                    # run BPF_PROG_TEST_RUN N times without attaching
//	xdpcount -parse-only                    # parse the embedded ELF without touching the kernel (no root needed)
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

// A copy with unrelated lines added above the declarations (tests that the schema, .mlir and ELF match examples/xdpcount byte for byte).
//
// Adding comment lines here, or the functions below, does not change the schema.

func unrelatedHelper() int { return 42 }

var unrelatedVar = unrelatedHelper()

// Counts is the shared declaration: [0] is the total number of packets, [1] is the value copied from [0] after the last packet.
var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

// CountPackets is the eBPF side (an xdp program).
func CountPackets(ctx *bpf.XDPContext) bpf.XDPAction {
	Counts.AtomicAdd(0, 1)
	if p := Counts.Lookup(0); p != nil {
		Counts.Update(1, *p)
	}
	return bpf.XDPPass
}

func main() {
	iface := flag.String("iface", "", "network interface to attach to")
	duration := flag.Duration("duration", 0, "run for this long, then exit (0 = print once and exit)")
	selftest := flag.Int("selftest", 0, "run BPF_PROG_TEST_RUN N times without attaching and check the counter")
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
	if *iface == "" && *selftest <= 0 {
		log.Fatal("-iface or -selftest N is required (-parse-only checks without the kernel)")
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

	if *selftest > 0 {
		os.Exit(runSelftest(objs, *selftest))
	}

	ifindex, err := ifindexOf(*iface)
	if err != nil {
		log.Fatal(err)
	}
	l, err := gobpf.AttachXDP(objs, CountPackets, ifindex)
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

func printCounts() {
	c0, err0 := Counts.Get(0)
	c1, err1 := Counts.Get(1)
	if err0 != nil || err1 != nil {
		log.Printf("cannot read the counter: %v %v", err0, err1)
		return
	}
	fmt.Printf("counts[0]=%d counts[1]=%d\n", c0, c1)
}

// runSelftest runs BPF_PROG_TEST_RUN n times and checks the return value (XDP_PASS) and the counters (n, n).
func runSelftest(objs *gobpf.Objects, n int) int {
	prog, err := objs.Program(CountPackets)
	if err != nil {
		log.Print(err)
		return 1
	}
	pkt := make([]byte, 64)
	for i := range pkt {
		pkt[i] = byte(0x81 + 0x11*i)
	}
	bad := 0
	for i := 0; i < n; i++ {
		ret, err := prog.Run(&ebpf.RunOptions{Data: pkt})
		if err != nil {
			log.Printf("test run %d: %v", i, err)
			return 1
		}
		if ret != uint32(bpf.XDPPass) {
			bad++
		}
	}
	c0, err0 := Counts.Get(0)
	c1, err1 := Counts.Get(1)
	if err0 != nil || err1 != nil {
		log.Printf("cannot read the counter: %v %v", err0, err1)
		return 1
	}
	ok := bad == 0 && c0 == uint64(n) && c1 == uint64(n)
	fmt.Printf("selftest runs=%d non_pass=%d counts[0]=%d counts[1]=%d result=%s\n", n, bad, c0, c1, map[bool]string{true: "ok", false: "FAIL"}[ok])
	if !ok {
		return 1
	}
	return 0
}

// ifindexOf reads the ifindex from sysfs (net.InterfaceByName may pull in cgo — the same reason as bpf-mlir's xdp-counter).
func ifindexOf(name string) (int, error) {
	b, err := os.ReadFile("/sys/class/net/" + name + "/ifindex")
	if err != nil {
		return 0, fmt.Errorf("interface %q not found: %w", name, err)
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}
