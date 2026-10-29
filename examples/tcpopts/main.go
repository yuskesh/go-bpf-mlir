// tcpopts is an example with an xdp program (the eBPF side) that walks the options of IPv4 TCP SYNs with a Go bounded loop and ctx.Check inside the loop and counts
// the MSS distribution, whether a timestamp is present and why the walk stopped, and the user-space side that loads, attaches and prints, in one Go program.
//
//	tcpopts -iface <name> [-duration 5s]   # attach and print the counts
//	tcpopts -selftest                      # run a set of frames through BPF_PROG_TEST_RUN without attaching and compare with the expected table
//	tcpopts -parse-only                    # parse the embedded ELF without touching the kernel (no root needed)
//
// A non-root loader needs CAP_BPF + CAP_NET_ADMIN + **CAP_PERFMON** (variable offsets that advance by the IHL and option lengths — docs/nonroot.md).
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
	KOther     uint32 = 0  // not IPv4 TCP (including short frames)
	KNoSYN     uint32 = 1  // TCP, but not a SYN
	KSYN       uint32 = 2  // SYN (the keys below break SYNs down)
	KMSSNone   uint32 = 3  // no MSS option
	KMSSLow    uint32 = 4  // MSS < 1220
	KMSSMid    uint32 = 5  // 1220 ≤ MSS < 1460
	KMSS1460   uint32 = 6  // MSS = 1460 (Ethernet with MTU 1500)
	KMSSHigh   uint32 = 7  // MSS > 1460
	KTS        uint32 = 8  // a timestamp option is present
	KStopEnd   uint32 = 9  // read to the end of the options (doff)
	KStopEOL   uint32 = 10 // stopped at EOL (kind 0)
	KStopShort uint32 = 11 // an option outside the frame (a truncated frame)
	KStopBad   uint32 = 12 // an option with length < 2
	KStopLimit uint32 = 13 // stopped at the iteration limit (maxOpts options)
	NumKeys           = 14
)

var keyNames = []string{"other", "no-syn", "syn", "mss-none", "mss-low", "mss-mid", "mss-1460", "mss-high", "ts", "stop-end", "stop-eol", "stop-short", "stop-bad", "stop-limit"}

// Counts is the shared declaration: the number of frames per key.
var Counts = bpf.Array[uint32, uint64]{MaxEntries: NumKeys}

const maxOpts = 16 // the iteration limit (the number of options — the unrolling estimate, counted the same way as bpf-mlir, is at most 4096)

// WalkSYN is the eBPF side (an xdp program).
func WalkSYN(ctx *bpf.XDPContext) bpf.XDPAction {
	key := KOther
	tcp := uint32(0)
	if w, ok := ctx.Check(0, 34); ok {
		et, proto := w.BE16(12), w.U8(23)
		if et == 0x0800 && proto == 6 {
			tcp = 14 + uint32(w.U8(14)&0x0f)*4 // IHL
		}
	}
	syn := false
	optend := uint32(0)
	if tcp >= 34 {
		if w, ok := ctx.Check(tcp, 20); ok {
			key = KNoSYN
			if w.U8(13)&0x02 != 0 {
				syn = true
				optend = tcp + uint32(w.U8(12)>>4)*4
			}
		}
	}
	if syn {
		off := tcp + 20
		mss := uint32(0)
		ts := false
		stop := KStopLimit
		for range uint32(maxOpts) {
			if off >= optend {
				stop = KStopEnd
				break
			}
			kind := uint8(0)
			if w, ok := ctx.Check(off, 1); ok {
				kind = w.U8(0)
			} else {
				stop = KStopShort
				break
			}
			if kind == 0 {
				stop = KStopEOL
				break
			}
			if kind == 1 {
				off++
				continue
			}
			length := uint8(0)
			if w, ok := ctx.Check(off, 2); ok {
				length = w.U8(1)
			} else {
				stop = KStopShort
				break
			}
			if length < 2 {
				stop = KStopBad
				break
			}
			if kind == 2 && length == 4 {
				if w, ok := ctx.Check(off, 4); ok {
					mss = uint32(w.BE16(2))
				} else {
					stop = KStopShort
					break
				}
			}
			if kind == 8 && length == 10 {
				ts = true
			}
			off += uint32(length)
		}
		Counts.AtomicAdd(KSYN, 1)
		Counts.AtomicAdd(mssKey(mss), 1)
		if ts {
			Counts.AtomicAdd(KTS, 1)
		}
		Counts.AtomicAdd(stop, 1)
	} else {
		Counts.AtomicAdd(key, 1)
	}
	return bpf.XDPPass
}

// mssKey is the MSS bucket (an eBPF-side subprogram).
func mssKey(mss uint32) uint32 {
	k := KMSSHigh
	if mss == 0 {
		k = KMSSNone
	} else if mss < 1220 {
		k = KMSSLow
	} else if mss < 1460 {
		k = KMSSMid
	} else if mss == 1460 {
		k = KMSS1460
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
	l, err := gobpf.AttachXDP(objs, WalkSYN, ifindex)
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

// syn is a TCP frame in IPv4 (IHL ihl) with flags and options (doff comes from the options length — rounded up to a multiple of 4). If trunc > 0 the frame is cut to that length.
func syn(ihl int, flags byte, opts []byte, trunc int) []byte {
	tcp := 14 + ihl*4
	olen := (len(opts) + 3) / 4 * 4
	f := make([]byte, tcp+20+olen)
	f[12], f[13] = 0x08, 0x00
	f[14] = 0x40 | byte(ihl)
	f[23] = 6
	f[tcp+12] = byte((20+olen)/4) << 4
	f[tcp+13] = flags
	copy(f[tcp+20:], opts)
	if trunc > 0 {
		f = f[:trunc]
	}
	return f
}

// linuxSYN is the options of a Linux SYN (MSS 1460, SACK permitted, TS, NOP, window scale 7).
var linuxSYN = []byte{2, 4, 0x05, 0xb4, 4, 2, 8, 10, 1, 2, 3, 4, 0, 0, 0, 0, 1, 3, 3, 7}

// selftestFrame is a frame for the test run and its expected keys (a hand-written table).
type selftestFrame struct {
	name  string
	frame []byte
	keys  []uint32
	times int
}

func selftestFrames() []selftestFrame {
	nops := make([]byte, 20)
	for i := range nops {
		nops[i] = 1
	}
	udp := syn(5, 0x02, nil, 0)
	udp[23] = 17
	return []selftestFrame{
		{"linux-syn", syn(5, 0x02, linuxSYN, 0), []uint32{KSYN, KMSS1460, KTS, KStopEnd}, 3},
		{"linux-syn-ihl6", syn(6, 0x02, linuxSYN, 0), []uint32{KSYN, KMSS1460, KTS, KStopEnd}, 1},
		{"syn-ack", syn(5, 0x12, []byte{2, 4, 0x05, 0x78}, 0), []uint32{KSYN, KMSSMid, KStopEnd}, 2},
		{"syn-no-opts", syn(5, 0x02, nil, 0), []uint32{KSYN, KMSSNone, KStopEnd}, 1},
		{"syn-mss-536-eol", syn(5, 0x02, []byte{2, 4, 0x02, 0x18, 0}, 0), []uint32{KSYN, KMSSLow, KStopEOL}, 1},
		{"syn-mss-9000", syn(5, 0x02, []byte{2, 4, 0x23, 0x28}, 0), []uint32{KSYN, KMSSHigh, KStopEnd}, 1},
		{"syn-truncated", syn(5, 0x02, linuxSYN, 14+20+20+6), []uint32{KSYN, KMSS1460, KStopShort}, 1},
		{"syn-bad-len", syn(5, 0x02, []byte{8, 1, 0, 0}, 0), []uint32{KSYN, KMSSNone, KStopBad}, 1},
		{"syn-20-nops", syn(5, 0x02, append(append([]byte{}, nops...), 2, 4, 0x05, 0xb4), 0), []uint32{KSYN, KMSSNone, KStopLimit}, 1},
		{"ack", syn(5, 0x10, nil, 0), []uint32{KNoSYN}, 4},
		{"udp", udp, []uint32{KOther}, 2},
		{"short-tcp", syn(5, 0x02, nil, 14+20+10), []uint32{KOther}, 1},
	}
}

func runSelftest(objs *gobpf.Objects) int {
	prog, err := objs.Program(WalkSYN)
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
		for _, k := range f.keys {
			want[k] += uint64(f.times)
		}
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
