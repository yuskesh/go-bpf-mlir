// ipdeny is an example that looks up the source IPv4 address by **lpm_trie longest match** (bpf.LPMTrie4) and drops it with XDP if it is a deny prefix (a conditional
// verdict). The user-space side builds the table from the -deny / -allow CIDRs with netip.Prefix — **a longer -allow punches a hole in a -deny** (longest-match semantics).
//
//	ipdeny -deny 10.0.0.0/8,192.0.2.1/32 [-allow 10.1.0.0/16] -iface <name> [-duration 5s]   # attach and print the counts per verdict
//	ipdeny -selftest                                                                         # run a set of frames through BPF_PROG_TEST_RUN without attaching
//	ipdeny -parse-only                                                                       # parse the embedded ELF without touching the kernel (no root needed)
//
// A frame shorter than 34 bytes and a non-IPv4 frame pass without a table lookup (deny defaults to false — the meaning this program writes. Packet bytes
// can be read only through the ctx.Check window, so the table is never looked up with an out-of-range 0 address). A CIDR with host bits set (10.1.2.3/8) is an error.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/netip"
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

// The Rules values.
const (
	VDeny  uint32 = 1
	VAllow uint32 = 2
)

// Rules is the table of source prefixes (the longest-match value — VDeny or VAllow).
var Rules = bpf.LPMTrie4[uint32]{MaxEntries: 1024}

// The Stats keys.
const (
	KDropped uint32 = 0 // matched a deny prefix, dropped
	KAllowed uint32 = 1 // matched an allow prefix, passed
	KNoMatch uint32 = 2 // matched no prefix, passed
	KNotIPv4 uint32 = 3 // a non-IPv4 frame or a frame shorter than 34 bytes (passed without a table lookup)
	NumKeys         = 4
)

var keyNames = []string{"dropped", "allowed", "no-match", "not-ipv4"}

// Stats is the number of frames per verdict.
var Stats = bpf.Array[uint32, uint64]{MaxEntries: NumKeys}

// Filter is the eBPF side (an xdp program).
func Filter(ctx *bpf.XDPContext) bpf.XDPAction {
	deny := false
	key := KNotIPv4
	if w, ok := ctx.Check(0, 34); ok {
		if w.BE16(12) == 0x0800 {
			v, found := Rules.Lookup([4]byte{w.U8(26), w.U8(27), w.U8(28), w.U8(29)})
			if !found {
				key = KNoMatch
			} else if v == VDeny {
				deny = true
				key = KDropped
			} else {
				key = KAllowed
			}
		}
	}
	if key == KDropped { // a constant key (a variable key cannot be proven — GB020)
		Stats.AtomicAdd(KDropped, 1)
	} else if key == KAllowed {
		Stats.AtomicAdd(KAllowed, 1)
	} else if key == KNoMatch {
		Stats.AtomicAdd(KNoMatch, 1)
	} else {
		Stats.AtomicAdd(KNotIPv4, 1)
	}
	if deny {
		return bpf.XDPDrop
	}
	return bpf.XDPPass
}

func main() {
	iface := flag.String("iface", "", "network interface to attach to")
	deny := flag.String("deny", "", "source CIDRs to drop (comma-separated)")
	allow := flag.String("allow", "", "source CIDRs to pass (comma-separated — a longer prefix opens a hole in -deny)")
	duration := flag.Duration("duration", 0, "run for this long, then exit (0 = print once and exit)")
	selftest := flag.Bool("selftest", false, "run a set of frames through BPF_PROG_TEST_RUN without attaching and compare with the expected results (fixed table)")
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
	rules, err := parseRules(*deny, *allow)
	if err != nil {
		log.Fatal(err)
	}
	if *selftest {
		rules = selftestRules
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
	for _, r := range rules {
		if err := Rules.Put(r.p, r.v); err != nil {
			log.Fatal(err) // a CIDR with host bits set and the like, with a named error
		}
	}
	printRules()
	if *selftest {
		os.Exit(runSelftest(objs))
	}
	ifindex, err := ifindexOf(*iface)
	if err != nil {
		log.Fatal(err)
	}
	l, err := gobpf.AttachXDP(objs, Filter, ifindex)
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

type rule struct {
	p netip.Prefix
	v uint32
}

func parseRules(deny, allow string) ([]rule, error) {
	var out []rule
	for _, s := range []struct {
		list string
		v    uint32
		flag string
	}{{deny, VDeny, "-deny"}, {allow, VAllow, "-allow"}} {
		for _, c := range strings.Split(s.list, ",") {
			if c = strings.TrimSpace(c); c == "" {
				continue
			}
			p, err := netip.ParsePrefix(c)
			if err != nil {
				return nil, fmt.Errorf("%s %q: %w", s.flag, c, err)
			}
			if !p.Addr().Is4() {
				return nil, fmt.Errorf("%s %s: not an IPv4 prefix", s.flag, p)
			}
			if p != p.Masked() { // before touching the kernel (LPMTrie4.Put gives the same error — never rounds silently)
				return nil, fmt.Errorf("%s %s: host bits set — use %s", s.flag, p, p.Masked())
			}
			out = append(out, rule{p, s.v})
		}
	}
	return out, nil
}

func printRules() {
	it := Rules.Iterate()
	for it.Next() {
		fmt.Printf("rule %s %s\n", it.Prefix(), map[uint32]string{VDeny: "deny", VAllow: "allow"}[it.Value()])
	}
	if err := it.Err(); err != nil {
		log.Printf("cannot read rules: %v", err)
	}
}

func counts() ([]uint64, error) {
	out := make([]uint64, NumKeys)
	for k := uint32(0); k < NumKeys; k++ {
		var err error
		if out[k], err = Stats.Get(k); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func printCounts() {
	c, err := counts()
	if err != nil {
		log.Printf("cannot read the counter: %v", err)
		return
	}
	parts := make([]string, 0, NumKeys)
	for k, v := range c {
		parts = append(parts, fmt.Sprintf("%s=%d", keyNames[k], v))
	}
	fmt.Println("counts " + strings.Join(parts, " "))
}

var selftestRules = []rule{
	{netip.MustParsePrefix("10.0.0.0/8"), VDeny},
	{netip.MustParsePrefix("10.1.0.0/16"), VAllow},
	{netip.MustParsePrefix("192.0.2.1/32"), VDeny},
}

// ipv4 is an n-byte IPv4 frame with source src.
func ipv4(src string, n int) []byte {
	f := make([]byte, n)
	f[12], f[13] = 0x08, 0x00
	f[14] = 0x45
	if n >= 30 {
		a := netip.MustParseAddr(src).As4()
		copy(f[26:30], a[:])
	}
	return f
}

func runSelftest(objs *gobpf.Objects) int {
	prog, err := objs.Program(Filter)
	if err != nil {
		log.Print(err)
		return 1
	}
	arp := ipv4("10.2.3.4", 60)
	arp[12], arp[13] = 0x08, 0x06
	frames := []struct {
		name string
		f    []byte
		want bpf.XDPAction
	}{
		{"deny-10.2.3.4", ipv4("10.2.3.4", 60), bpf.XDPDrop},
		{"deny-10.255.255.255", ipv4("10.255.255.255", 60), bpf.XDPDrop},
		{"allow-hole-10.1.3.4", ipv4("10.1.3.4", 60), bpf.XDPPass},
		{"allow-hole-10.1.0.0", ipv4("10.1.0.0", 34), bpf.XDPPass}, // exactly 34 bytes — the table is looked up
		{"deny-192.0.2.1", ipv4("192.0.2.1", 60), bpf.XDPDrop},
		{"no-match-192.0.2.2", ipv4("192.0.2.2", 60), bpf.XDPPass},
		{"no-match-11.0.0.0", ipv4("11.0.0.0", 60), bpf.XDPPass},
		{"arp-from-denied", arp, bpf.XDPPass},                       // not IPv4 — no table lookup
		{"short-33-from-denied", ipv4("10.2.3.4", 33), bpf.XDPPass}, // shorter than 34 bytes — deny defaults to false
	}
	ok := true
	for _, f := range frames {
		ret, err := prog.Run(&ebpf.RunOptions{Data: f.f})
		if err != nil || ret != uint32(f.want) {
			log.Printf("%s: verdict %d want %d err %v", f.name, ret, f.want, err)
			ok = false
		}
	}
	c, err := counts()
	if err != nil {
		log.Print(err)
		return 1
	}
	ok = ok && c[KDropped] == 3 && c[KAllowed] == 2 && c[KNoMatch] == 2 && c[KNotIPv4] == 2
	printCounts()
	fmt.Printf("selftest result=%s\n", map[bool]string{true: "ok", false: "FAIL"}[ok])
	if !ok {
		fmt.Printf("want dropped=3 allowed=2 no-match=2 not-ipv4=2\n")
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
