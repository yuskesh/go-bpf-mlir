// xdpfwd is an example where an XDP program attached to the -in interface **redirects IPv4 (IHL 5) frames whose UDP destination port is -port to the devmap
// entry's interface (-out)** (bpf.DevMap.RedirectIf) and passes the rest.
//
//	xdpfwd -in <name> -out <name> -port 7000 [-duration 5s]   # attach and print the counts
//	xdpfwd -selftest                                         # check the return values and counts through BPF_PROG_TEST_RUN without attaching (the target is lo)
//	xdpfwd -parse-only                                       # parse the embedded ELF without touching the kernel (no root needed)
//
// **The -out ifindex is looked up in the network namespace this process runs in** — the -in interface the program attaches to and the -out target must be in the same netns
// (the kernel devmap looks up the ifindex in the netns of the process that Sets it, and redirect sends to that interface). If an interface number from another netns is
// passed directly with -out-ifindex, Set stops with EINVAL when this netns has no such number, and otherwise sends to **the interface with that number in this netns**.
//
// **The redirect count is the number requested, not the number delivered** — if the target is a veth, packets are dropped unless its receiving side (peer) has
// an XDP program or GRO. Non-root needs CAP_BPF + CAP_NET_ADMIN.
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

// Port is the UDP destination port to forward (.rodata — not Optional).
var Port = bpf.Config[uint16]{}

// Out is the forwarding target (key 0 — the user-space side Sets the -out ifindex).
var Out = bpf.DevMap{MaxEntries: 1}

// The Stats keys.
const (
	KRedirect uint32 = 0 // frames a redirect was requested for (not the number delivered)
	KPass     uint32 = 1 // frames not targeted and passed
)

// Stats is the number of frames per verdict.
var Stats = bpf.Array[uint32, uint64]{MaxEntries: 2}

// Fwd is the eBPF side (an xdp program).
func Fwd(ctx *bpf.XDPContext) bpf.XDPAction {
	hit := false
	port := Port.Value() // the right of && takes only side-effect-free expressions — read the setting first
	if w, ok := ctx.Check(0, 38); ok {
		et, vihl, proto, dport := w.BE16(12), w.U8(14), w.U8(23), w.BE16(36)
		if et == 0x0800 && vihl == 0x45 && proto == 17 && dport == port {
			hit = true
		}
	}
	if hit {
		Stats.AtomicAdd(KRedirect, 1)
	} else {
		Stats.AtomicAdd(KPass, 1)
	}
	return Out.RedirectIf(ctx, hit, 0, bpf.XDPPass, bpf.XDPPass)
}

func main() {
	in := flag.String("in", "", "interface to attach to")
	out := flag.String("out", "", "interface to forward to (a name in this process's netns)")
	outIfindex := flag.Int("out-ifindex", 0, "ifindex to forward to, given directly (instead of -out — a control for how an index from another netns behaves)")
	port := flag.Int("port", -1, "UDP destination port to forward (required — 7000 with -selftest)")
	duration := flag.Duration("duration", 0, "run for this long, then exit (0 = print once and exit)")
	selftest := flag.Bool("selftest", false, "check with BPF_PROG_TEST_RUN without attaching")
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
	if *selftest {
		*port = 7000
	} else if *in == "" || (*out == "" && *outIfindex == 0) {
		log.Fatal("-in and -out (or -out-ifindex) are required (or -selftest or -parse-only)")
	}
	if *port < 0 || *port > 65535 {
		log.Fatalf("-port %d is not a port", *port)
	}
	if err := Port.Set(uint16(*port)); err != nil {
		log.Fatal(err)
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
	target := uint32(*outIfindex)
	if *out != "" {
		ix, err := ifindexOf(*out)
		if err != nil {
			log.Fatal(err)
		}
		target = uint32(ix)
	}
	if err := Out.Set(0, target); err != nil {
		log.Fatalf("cannot set the forwarding ifindex %d (not in this netns?): %v", target, err)
	}
	fmt.Printf("out-ifindex=%d\n", target)
	inIx, err := ifindexOf(*in)
	if err != nil {
		log.Fatal(err)
	}
	l, err := gobpf.AttachXDP(objs, Fwd, inIx)
	if err != nil {
		log.Fatalf("cannot attach XDP to %s: %v", *in, err)
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

func counts() (uint64, uint64, error) {
	r, err := Stats.Get(KRedirect)
	if err != nil {
		return 0, 0, err
	}
	p, err := Stats.Get(KPass)
	return r, p, err
}

func printCounts() {
	r, p, err := counts()
	if err != nil {
		log.Printf("cannot read the counter: %v", err)
		return
	}
	fmt.Printf("counts redirect-requested=%d passed=%d\n", r, p)
}

// udp is an n-byte UDP frame in IPv4 (IHL 5) with destination port dport.
func udp(dport uint16, n int) []byte {
	f := make([]byte, n)
	f[12], f[13], f[14], f[23] = 0x08, 0x00, 0x45, 17
	if n >= 38 {
		f[36], f[37] = byte(dport>>8), byte(dport)
	}
	return f
}

func runSelftest(objs *gobpf.Objects) int {
	prog, err := objs.Program(Fwd)
	if err != nil {
		log.Print(err)
		return 1
	}
	const redirect, pass = 4, 2 // XDP_REDIRECT, XDP_PASS
	cases := []struct {
		name string
		f    []byte
		want uint32
	}{
		{"udp-7000-no-entry", udp(7000, 60), pass}, // no entry — fallback (pass)
	}
	for _, c := range cases {
		if ret, err := prog.Run(&ebpf.RunOptions{Data: c.f}); err != nil || ret != c.want {
			log.Printf("%s: ret %d want %d err %v", c.name, ret, c.want, err)
			return 1
		}
	}
	if err := Out.Set(0, 1); err != nil { // lo
		log.Print(err)
		return 1
	}
	cases = []struct {
		name string
		f    []byte
		want uint32
	}{
		{"udp-7000", udp(7000, 60), redirect},
		{"udp-7000-38", udp(7000, 38), redirect},
		{"udp-9", udp(9, 60), pass},
		{"short-37", udp(7000, 37), pass},
		{"tcp-7000", func() []byte { f := udp(7000, 60); f[23] = 6; return f }(), pass},
	}
	for _, c := range cases {
		if ret, err := prog.Run(&ebpf.RunOptions{Data: c.f}); err != nil || ret != c.want {
			log.Printf("%s: ret %d want %d err %v", c.name, ret, c.want, err)
			return 1
		}
	}
	r, p, err := counts()
	if err != nil {
		log.Print(err)
		return 1
	}
	ok := r == 3 && p == 3
	printCounts()
	fmt.Printf("selftest result=%s\n", map[bool]string{true: "ok", false: "FAIL"}[ok])
	if !ok {
		fmt.Println("want redirect-requested=3 passed=3")
		return 1
	}
	return 0
}

// ifindexOf reads the ifindex from sysfs (in this process's netns).
func ifindexOf(name string) (int, error) {
	b, err := os.ReadFile("/sys/class/net/" + name + "/ifindex")
	if err != nil {
		return 0, fmt.Errorf("interface %q not found: %w", name, err)
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}
