// portcount is an example with an xdp program that takes the UDP destination port to count as a **.rodata setting** (bpf.Config — the -port value is Set before load)
// and counts the datagrams to that port in a **.bss counter** (bpf.Global — an atomic Add), and the user-space side that loads, attaches and prints.
//
//	portcount -port 53 -iface <name> [-duration 5s]   # attach and print the counts (without -port, Load stops naming Port — a missing Set is never silent)
//	portcount -selftest                               # run a set of frames through BPF_PROG_TEST_RUN without attaching and compare with the expected values (port 9999)
//	portcount -parse-only                             # parse the embedded ELF without touching the kernel (no root needed)
//
// It counts only UDP in IPv4 without options (IHL 5) — the offsets are constant, so a non-root loader needs only CAP_BPF + CAP_NET_ADMIN (the shape that reads past
// the IHL needs CAP_PERFMON — docs/nonroot.md).
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

// Port is the UDP destination port to count (.rodata — Set it before load. Not Optional — without Set, Load fails).
var Port = bpf.Config[uint16]{}

// Hits is the number of UDP datagrams to Port (.bss — counted atomically across CPUs).
var Hits = bpf.Global[uint64]{}

// The Other keys.
const (
	KOtherUDP uint32 = 0 // UDP to another port (IHL 5)
	KNotUDP   uint32 = 1 // IPv4 that is not UDP, or a non-IPv4 frame
	KSkipped  uint32 = 2 // a frame with IPv4 options (IHL ≠ 5) or shorter than 38 bytes
	NumKeys          = 3
)

var keyNames = []string{"other-udp", "not-udp", "skipped"}

// Other is the number of frames not to Port (a map — when this example was written, a section could hold only one .bss global — bpf-mlir v0.12.0).
var Other = bpf.Array[uint32, uint64]{MaxEntries: NumKeys}

// CountPort is the eBPF side (an xdp program).
func CountPort(ctx *bpf.XDPContext) bpf.XDPAction {
	key := KSkipped
	hit := false
	if w, ok := ctx.Check(0, 38); ok {
		et, vihl, proto := w.BE16(12), w.U8(14), w.U8(23)
		if et != 0x0800 || proto != 17 {
			key = KNotUDP
		} else if vihl == 0x45 {
			key = KOtherUDP
			if w.BE16(36) == Port.Value() {
				hit = true
			}
		}
	}
	if hit {
		Hits.Add(1)
	} else if key == KOtherUDP { // a constant key (a variable key cannot be proven — GB020)
		Other.AtomicAdd(KOtherUDP, 1)
	} else if key == KNotUDP {
		Other.AtomicAdd(KNotUDP, 1)
	} else {
		Other.AtomicAdd(KSkipped, 1)
	}
	return bpf.XDPPass
}

func main() {
	iface := flag.String("iface", "", "network interface to attach to")
	port := flag.Int("port", -1, "UDP destination port to count (required — 9999 with -selftest)")
	duration := flag.Duration("duration", 0, "run for this long, then exit (0 = print once and exit)")
	selftest := flag.Bool("selftest", false, "run a set of frames through BPF_PROG_TEST_RUN without attaching and compare with the expected results")
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
	if *selftest {
		*port = 9999
	}
	if *port >= 0 {
		if *port > 65535 {
			log.Fatalf("-port %d is not a port", *port)
		}
		if err := Port.Set(uint16(*port)); err != nil {
			log.Fatal(err)
		}
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("RemoveMemlock: %v", err)
	}
	objs, rest, err := gobpf.Load(livecaps.New()) // without -port, an error naming Port here
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
	l, err := gobpf.AttachXDP(objs, CountPort, ifindex)
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

func counts() (uint64, []uint64, error) {
	h, err := Hits.Get()
	if err != nil {
		return 0, nil, err
	}
	out := make([]uint64, NumKeys)
	for k := uint32(0); k < NumKeys; k++ {
		if out[k], err = Other.Get(k); err != nil {
			return 0, nil, err
		}
	}
	return h, out, nil
}

func printCounts() {
	h, o, err := counts()
	if err != nil {
		log.Printf("cannot read the counter: %v", err)
		return
	}
	p, _ := Port.Get()
	parts := []string{fmt.Sprintf("port=%d hits=%d", p, h)}
	for k, v := range o {
		parts = append(parts, fmt.Sprintf("%s=%d", keyNames[k], v))
	}
	fmt.Println("counts " + strings.Join(parts, " "))
}

// udp is a UDP frame in IPv4 (IHL ihl) with destination port dport.
func udp(ihl int, dport uint16, n int) []byte {
	f := make([]byte, n)
	f[12], f[13] = 0x08, 0x00
	f[14] = 0x40 | byte(ihl)
	f[23] = 17
	off := 14 + ihl*4
	if off+4 <= n {
		f[off+2], f[off+3] = byte(dport>>8), byte(dport)
	}
	return f
}

func runSelftest(objs *gobpf.Objects) int {
	prog, err := objs.Program(CountPort)
	if err != nil {
		log.Print(err)
		return 1
	}
	tcp := udp(5, 9999, 60)
	tcp[23] = 6
	arp := udp(5, 9999, 60)
	arp[12], arp[13] = 0x08, 0x06
	frames := []struct {
		name  string
		f     []byte
		times int
	}{
		{"udp-9999", udp(5, 9999, 60), 3},
		{"udp-53", udp(5, 53, 60), 2},
		{"udp-9999-short-38", udp(5, 9999, 38), 1}, // exactly 38 bytes — counted
		{"tcp-9999", tcp, 1},
		{"arp", arp, 1},
		{"udp-ihl6-9999", udp(6, 9999, 64), 2}, // with options — not counted (skipped)
		{"short-37", udp(5, 9999, 37), 1},
	}
	for _, f := range frames {
		for i := 0; i < f.times; i++ {
			if ret, err := prog.Run(&ebpf.RunOptions{Data: f.f}); err != nil || ret != uint32(bpf.XDPPass) {
				log.Printf("%s: test run: ret %d err %v", f.name, ret, err)
				return 1
			}
		}
	}
	h, o, err := counts()
	if err != nil {
		log.Print(err)
		return 1
	}
	ok := h == 4 && o[KOtherUDP] == 2 && o[KNotUDP] == 2 && o[KSkipped] == 3
	printCounts()
	fmt.Printf("selftest result=%s\n", map[bool]string{true: "ok", false: "FAIL"}[ok])
	if !ok {
		fmt.Printf("want hits=4 other-udp=2 not-udp=2 skipped=3\n")
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
