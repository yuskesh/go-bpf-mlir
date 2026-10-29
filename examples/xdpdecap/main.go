// xdpdecap is an example with an xdp program (the eBPF side) that strips the tag from tagged frames (outer ethertype 0x88b5 + a 4-byte tag — the same shape as bpf-mlir's docs/examples/xdp_decap.md)
// in XDP, and the user-space side that loads, attaches and prints, in one Go program. The receiving kernel cannot process a tagged frame, so it
// never reaches a UDP socket — once stripped it becomes plain IPv4 / UDP and arrives.
//
//	xdpdecap -iface <name> [-duration 5s]   # attach and print the counts
//	xdpdecap -selftest                      # run a set of frames through BPF_PROG_TEST_RUN without attaching and compare data_out and the counts with the expected values
//	xdpdecap -parse-only                    # parse the embedded ELF without touching the kernel (no root needed)
package main

import (
	"bytes"
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
	KDecap  uint32 = 0 // stripped
	KPlain  uint32 = 1 // a frame without a tag (untouched)
	KFailed uint32 = 2 // AdjustHead failed (the packet is unchanged)
	NumKeys        = 3
)

var keyNames = []string{"decap", "plain", "failed"}

// Counts is the shared declaration: the number of frames per key.
var Counts = bpf.Array[uint32, uint64]{MaxEntries: NumKeys}

// Decap is the eBPF side (an xdp program): it strips the 4-byte tag from a frame of 38 bytes or more whose outer ethertype is 0x88b5.
func Decap(ctx *bpf.XDPContext) bpf.XDPAction {
	tagged := false
	mac0, mac1, inner := uint64(0), uint32(0), uint16(0)
	if w, ok := ctx.Check(0, 38); ok {
		if w.BE16(12) == 0x88b5 {
			tagged = true
			mac0, mac1, inner = w.BE64(0), w.BE32(8), w.BE16(16) // read before the helper — this window cannot be used after AdjustHead
		}
	}
	if tagged {
		if st := ctx.AdjustHead(4); st == 0 {
			if w2, ok2 := ctx.Check(0, 14); ok2 { // a new window
				w2.SetBE64(0, mac0)
				w2.SetBE32(8, mac1)
				w2.SetBE16(12, inner)
			}
			Counts.AtomicAdd(KDecap, 1)
		} else {
			Counts.AtomicAdd(KFailed, 1)
		}
	} else {
		Counts.AtomicAdd(KPlain, 1)
	}
	return bpf.XDPPass
}

func main() {
	iface := flag.String("iface", "", "network interface to attach to")
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
	l, err := gobpf.AttachXDP(objs, Decap, ifindex)
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

// tagged is a frame of MACs, outer ethertype 0x88b5, the tag id, inner ethertype 0x0800 and n bytes of IPv4 after that.
func tagged(n int) []byte {
	f := make([]byte, 18+n)
	for i := range f {
		f[i] = byte(0x40 + 7*i)
	}
	f[12], f[13], f[14], f[15], f[16], f[17] = 0x88, 0xb5, 0x00, 0x2a, 0x08, 0x00
	return f
}

func plain(n int) []byte {
	f := make([]byte, n)
	for i := range f {
		f[i] = byte(0x40 + 7*i)
	}
	f[12], f[13] = 0x08, 0x00
	return f
}

func runSelftest(objs *gobpf.Objects) int {
	prog, err := objs.Program(Decap)
	if err != nil {
		log.Print(err)
		return 1
	}
	type tc struct {
		name string
		in   []byte
		out  []byte
		key  uint32
	}
	strip := func(f []byte) []byte { return bytes.Join([][]byte{f[0:12], f[16:18], f[18:]}, nil) }
	cases := []tc{
		{"tagged-38", tagged(20), strip(tagged(20)), KDecap},
		{"tagged-60", tagged(42), strip(tagged(42)), KDecap},
		{"tagged-1500", tagged(1482), strip(tagged(1482)), KDecap},
		{"tagged-37", tagged(19), tagged(19), KPlain}, // shorter than 38 bytes — untouched
		{"plain-60", plain(60), plain(60), KPlain},
		{"plain-14", plain(14), plain(14), KPlain},
	}
	want := make([]uint64, NumKeys)
	ok := true
	for _, c := range cases {
		out := make([]byte, len(c.in)+256)
		opts := &ebpf.RunOptions{Data: c.in, DataOut: out}
		ret, err := prog.Run(opts)
		if err != nil {
			log.Printf("%s: test run: %v", c.name, err)
			return 1
		}
		if ret != uint32(bpf.XDPPass) || !bytes.Equal(opts.DataOut, c.out) {
			ok = false
			fmt.Printf("mismatch %s: ret %d, data_out %d bytes (want %d)\n", c.name, ret, len(opts.DataOut), len(c.out))
		}
		want[c.key]++
	}
	got, err := readCounts()
	if err != nil {
		log.Print(err)
		return 1
	}
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
