// flowsample is an example with an xdp program (the eBPF side) that counts IPv4 frames per protocol (AtomicAdd on an integer map), writes the
// last frame seen per protocol to a record map (the last writer wins — Update) and sends an event per frame to a ring buffer,
// and the user-space side that loads and attaches it and reads the events, in one Go program.
//
//	flowsample -iface <name> [-duration 5s]   # attach, read the events and print the counts and LastSeen
//	flowsample -selftest                      # run a set of frames through BPF_PROG_TEST_RUN without attaching and compare with the expectations
//	flowsample -parse-only                    # parse the embedded ELF without touching the kernel (no root needed)
//
// **Counting uses AtomicAdd on an integer map** — += on a record field is not atomic and loses counts across CPUs.
//
// The L4 ports are read through a packet window at a variable offset computed from the IPv4 IHL (`ctx.Check(14+ihl*4, 4)`). **A non-root loader needs CAP_PERFMON**
// (without CAP_PERFMON the kernel verifier refuses a variable addition to the packet pointer — measured on all three kernels). A broken IPv4 with ihl < 5 is counted as ipv4-bad-ihl and L4 is not read.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
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

// The keys of Counts.
const (
	KOther     uint32 = 0 // a frame that is not IPv4, or has no full IPv4 header (up to byte 34)
	KTCP       uint32 = 1
	KUDP       uint32 = 2
	KICMP      uint32 = 3
	KIPv4Other uint32 = 4
	KDrops     uint32 = 5 // events dropped because the ring buffer was full (bpf.CountDropsIn)
	KIHL       uint32 = 6 // IPv4 but IHL < 5 (a broken header — not counted as a flow; with options (IHL > 5) the ports are read at a variable offset)
	KFlowFail  uint32 = 7 // Flows.AddOrInit status ≠ 0 (the table is full, or the entry was deleted by a race)
	NumKeys           = 8
)

var keyNames = []string{"other", "tcp", "udp", "icmp", "ipv4-other", "drops", "ipv4-bad-ihl", "flow-fail"}

// Seen is the last IPv4 frame seen per protocol (a record — values are in CPU order; network-order header fields are converted with BE16 before they are stored).
type Seen struct {
	Hdr Hdr      `schema:"hdr"`
	Src [4]uint8 `schema:"src"`
}

// Hdr is a summary of the IPv4 header (a record nested in Seen; the offsets are the same as Seen had before nesting).
type Hdr struct {
	Len   uint16 `schema:"len"` // the IPv4 total length
	Proto uint8  `schema:"proto"`
	TTL   uint8  `schema:"ttl"`
}

// Event is the ring buffer event per frame.
type Event struct {
	Len       uint16 `schema:"len"`
	EtherType uint16 `schema:"ethertype"`
	Proto     uint8  `schema:"proto"`
	TTL       uint8  `schema:"ttl"`
	_         [2]byte
	Src       [4]uint8 `schema:"src"`
}

// FlowKey is the IPv4 5-tuple (a record key — ports are in CPU order, 0 unless TCP / UDP).
type FlowKey struct {
	Addr  Addrs `schema:"addr"`
	Port  Ports `schema:"port"`
	Proto uint8 `schema:"proto"`
	_     [3]byte
}

// Addrs is the flow's source and destination IPv4 address (a record nested in FlowKey).
type Addrs struct {
	Src [4]uint8 `schema:"src"`
	Dst [4]uint8 `schema:"dst"`
}

// Ports is the flow's source and destination port (CPU order).
type Ports struct {
	Src uint16 `schema:"src"`
	Dst uint16 `schema:"dst"`
}

// FlowLast is the last frame seen per flow (the last writer wins).
type FlowLast struct {
	Len uint16 `schema:"len"`
	TTL uint8  `schema:"ttl"`
	_   [1]byte
}

var Counts = bpf.Array[uint32, uint64]{MaxEntries: NumKeys}

var LastSeen = bpf.Array[uint32, Seen]{MaxEntries: NumKeys}

var Events = bpf.RingBuf[Event]{MaxEntries: 1 << 16}

// NumBuckets is the number of buckets of the length distribution (≤64, ≤128, … ≤4096, larger).
const NumBuckets = 8

// SizeHist is the distribution of the IPv4 total length (AtomicAdd on an integer Array — an explicit clamp proves the bucket index is below MaxEntries).
var SizeHist = bpf.Array[uint32, uint64]{MaxEntries: NumBuckets}

// ProtoStats is the statistics per protocol key (a per-CPU record).
type ProtoStats struct {
	Packets uint64 `schema:"packets"`
	Bytes   uint64 `schema:"bytes"` // the sum of IPv4 total lengths (0 for frames that are not IPv4)
}

// PerProto is the per-CPU map of statistics per key — it writes only the current CPU's slot, so **+= on a record field is correct without atomics**
// (+= on a record in a shared map loses counts across CPUs). User space reads the sum over CPUs.
var PerProto = bpf.PerCPUArray[uint32, ProtoStats]{MaxEntries: NumKeys}

// Flows is the number of packets per flow (AddOrInit — no counts lost across CPUs).
var Flows = bpf.Hash[FlowKey, uint64]{MaxEntries: 1024}

// Last is the last frame per flow (lru_hash — when full it silently evicts old flows; the example's check uses far fewer than 1024 flows).
var Last = bpf.LRUHash[FlowKey, FlowLast]{MaxEntries: 1024}

// classify picks the key from the IPv4 protocol (a subprogram on the eBPF side).
func classify(proto uint8) uint32 {
	k := KIPv4Other
	if proto == 6 {
		k = KTCP
	} else if proto == 17 {
		k = KUDP
	} else if proto == 1 {
		k = KICMP
	}
	return k
}

// Sample is the eBPF side (an xdp program).
func Sample(ctx *bpf.XDPContext) bpf.XDPAction {
	key := KOther
	ipLen := uint64(0) // the IPv4 total length (PerProto's Bytes)
	if w, ok := ctx.Check(0, 34); ok {
		et := w.BE16(12)
		if et == 0x0800 {
			proto := w.U8(23)
			ipLen = uint64(w.BE16(16))
			key = classify(proto)
			LastSeen.Update(key, Seen{Hdr: Hdr{Len: w.BE16(16), Proto: proto, TTL: w.U8(22)}, Src: [4]uint8{w.U8(26), w.U8(27), w.U8(28), w.U8(29)}})
			Events.Output(Event{Len: w.BE16(16), EtherType: et, Proto: proto, TTL: w.U8(22), Src: [4]uint8{w.U8(26), w.U8(27), w.U8(28), w.U8(29)}}, bpf.CountDropsIn(Counts, KDrops))
			// Length distribution: the bucket is how many of the thresholds 64, 128, …, 4096 are exceeded (a bounded loop — (U) unrolling). A clamp proves the index.
			ln := uint32(w.BE16(16))
			b := uint32(0)
			t := uint32(64)
			for range uint32(NumBuckets - 1) {
				if ln > t {
					b++
				}
				t = t * 2
			}
			if b >= NumBuckets {
				b = NumBuckets - 1
			}
			SizeHist.AtomicAdd(b, 1)
			ihl := uint32(w.U8(14) & 0x0f) // the IPv4 header length (in 4-byte units)
			if ihl >= 5 {                  // ihl < 5 is a broken IPv4 — the L4 offset would point inside the IP header, so it is not read
				sport, dport := uint16(0), uint16(0)
				if proto == 6 || proto == 17 {
					// A window at a variable offset over the first 4 bytes of L4 (after the options). Outside the packet the ports are 0.
					if l4, ok4 := ctx.Check(14+ihl*4, 4); ok4 {
						sport, dport = l4.BE16(0), l4.BE16(2)
					}
				}
				if st := Flows.AddOrInit(FlowKey{Addr: Addrs{Src: [4]uint8{w.U8(26), w.U8(27), w.U8(28), w.U8(29)}, Dst: [4]uint8{w.U8(30), w.U8(31), w.U8(32), w.U8(33)}}, Port: Ports{Src: sport, Dst: dport}, Proto: proto}, 1); st != 0 {
					Counts.AtomicAdd(KFlowFail, 1)
				}
				_ = Last.Update(FlowKey{Addr: Addrs{Src: [4]uint8{w.U8(26), w.U8(27), w.U8(28), w.U8(29)}, Dst: [4]uint8{w.U8(30), w.U8(31), w.U8(32), w.U8(33)}}, Port: Ports{Src: sport, Dst: dport}, Proto: proto}, FlowLast{Len: w.BE16(16), TTL: w.U8(22)})
			} else {
				Counts.AtomicAdd(KIHL, 1)
			}
		}
	}
	Counts.AtomicAdd(key, 1)
	pk := key // a clamp proves the index — the frontend does not know the upper bound of the key classify returns
	if pk >= NumKeys {
		pk = NumKeys - 1
	}
	if p := PerProto.Lookup(pk); p != nil {
		p.Packets += 1
		p.Bytes += ipLen
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
	rd, err := gobpf.NewReader(&Events)
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()
	if *selftest {
		os.Exit(runSelftest(objs, rd))
	}
	ifindex, err := ifindexOf(*iface)
	if err != nil {
		log.Fatal(err)
	}
	l, err := gobpf.AttachXDP(objs, Sample, ifindex)
	if err != nil {
		log.Fatalf("cannot attach XDP to %s: %v", *iface, err)
	}
	defer l.Close()
	evs := map[uint8]int{}
	total := 0
	deadline := time.Now().Add(*duration)
	for {
		rd.SetDeadline(time.Now().Add(200 * time.Millisecond))
		ev, err := rd.Read()
		if err == nil {
			evs[ev.Proto]++
			total++
			continue
		}
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			log.Fatal(err)
		}
		if *duration <= 0 || time.Now().After(deadline) {
			break
		}
	}
	printState()
	fmt.Printf("events total=%d tcp=%d udp=%d icmp=%d\n", total, evs[6], evs[17], evs[1])
	printFlows()
}

// printFlows reads the flow table with iterate and prints it (proto, src:sport → dst:dport, packets, last len / ttl).
func printFlows() {
	it := Flows.Iterate()
	var lines []string
	for it.Next() {
		k, n := it.Key(), it.Value()
		l, err := Last.Get(k)
		last := "last=?"
		if err == nil {
			last = fmt.Sprintf("last_len=%d last_ttl=%d", l.Len, l.TTL)
		}
		lines = append(lines, fmt.Sprintf("flow proto=%d %s:%d -> %s:%d packets=%d %s", k.Proto, ip(k.Addr.Src), k.Port.Src, ip(k.Addr.Dst), k.Port.Dst, n, last))
	}
	if err := it.Err(); err != nil {
		log.Printf("cannot iterate Flows: %v", err)
	}
	sort.Strings(lines)
	for _, l := range lines {
		fmt.Println(l)
	}
}

func ip(a [4]uint8) string { return fmt.Sprintf("%d.%d.%d.%d", a[0], a[1], a[2], a[3]) }

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

func printState() {
	c, err := readCounts()
	if err != nil {
		log.Printf("cannot read the counter: %v", err)
		return
	}
	var hs []string
	for k := uint32(0); k < NumBuckets; k++ {
		v, err := SizeHist.Get(k)
		if err != nil {
			log.Printf("cannot read SizeHist: %v", err)
			return
		}
		hs = append(hs, fmt.Sprintf("b%d=%d", k, v))
	}
	fmt.Println("sizes " + strings.Join(hs, " "))
	for _, k := range []uint32{KOther, KTCP, KUDP, KICMP, KIPv4Other} {
		vs, err := PerProto.GetPerCPU(k)
		if err != nil {
			log.Printf("cannot read PerProto: %v", err)
			return
		}
		var s ProtoStats // add the per-CPU values field by field (there is no sum helper)
		cpus := 0
		for _, v := range vs {
			s.Packets += v.Packets
			s.Bytes += v.Bytes
			if v.Packets > 0 {
				cpus++
			}
		}
		fmt.Printf("perproto %s packets=%d bytes=%d cpus=%d\n", keyNames[k], s.Packets, s.Bytes, cpus)
	}
	var parts []string
	for k, v := range c {
		parts = append(parts, fmt.Sprintf("%s=%d", keyNames[k], v))
	}
	fmt.Println("counts " + strings.Join(parts, " "))
	for _, k := range []uint32{KTCP, KUDP, KICMP} {
		s, err := LastSeen.Get(k)
		if err != nil {
			log.Printf("cannot read LastSeen: %v", err)
			return
		}
		fmt.Printf("lastseen %s len=%d proto=%d ttl=%d src=%d.%d.%d.%d\n", keyNames[k], s.Hdr.Len, s.Hdr.Proto, s.Hdr.TTL, s.Src[0], s.Src[1], s.Src[2], s.Src[3])
	}
}

// ipv4FrameIHL is a frame with IHL ihl (options are filled with 0x01 NOPs). The ports go at the start of L4 (14 + ihl×4) if they fit in the packet.
func ipv4FrameIHL(n int, ihl, proto, ttl byte, totLen uint16, src [4]byte) []byte {
	f := ipv4Frame(n, proto, ttl, totLen, src)
	f[14] = 0x40 | ihl
	for i := 34; i < 14+int(ihl)*4 && i < n; i++ {
		f[i] = 0x01
	}
	if off := 14 + int(ihl)*4; ihl >= 5 && off+4 <= n {
		f[off], f[off+1], f[off+2], f[off+3] = 0x03, 0xe8, 0x07, 0xd0 // 1000 → 2000
	}
	return f
}

// ipv4Frame is an Ethernet + IPv4 header frame (n bytes): version 4, IHL 5, total length, TTL, protocol, src, and dst 10.9.9.9;
// with n ≥ 38 it also holds the L4 ports (sport 1000, dport 2000).
func ipv4Frame(n int, proto, ttl byte, totLen uint16, src [4]byte) []byte {
	f := make([]byte, n)
	for i := range f {
		f[i] = byte(0x81 + 0x11*i)
	}
	f[12], f[13] = 0x08, 0x00
	if n >= 34 {
		f[14] = 0x45
		f[16], f[17] = byte(totLen>>8), byte(totLen)
		f[22], f[23] = ttl, proto
		copy(f[26:30], src[:])
		copy(f[30:34], []byte{10, 9, 9, 9})
	}
	if n >= 38 {
		f[34], f[35], f[36], f[37] = 0x03, 0xe8, 0x07, 0xd0 // 1000 → 2000
	}
	return f
}

// selftestFrame is a frame for the test run with its expected key, event and flow (a hand-written oracle — flowsample_test.go checks it against the program's rules).
type selftestFrame struct {
	name  string
	frame []byte
	key   uint32
	event *Event   // nil: the frame sends no event
	flow  *FlowKey // nil: the frame is not counted as a flow
	ihl   bool     // IHL < 5 (counted in KIHL)
}

func selftestFrames() []selftestFrame {
	ev := func(proto, ttl uint8, l uint16, src [4]uint8) *Event {
		return &Event{Len: l, EtherType: 0x0800, Proto: proto, TTL: ttl, Src: src}
	}
	fl := func(src [4]uint8, proto uint8, sport, dport uint16) *FlowKey {
		return &FlowKey{Addr: Addrs{Src: src, Dst: [4]uint8{10, 9, 9, 9}}, Port: Ports{Src: sport, Dst: dport}, Proto: proto}
	}
	arp := ipv4Frame(42, 0, 0, 0, [4]byte{})
	arp[12], arp[13] = 0x08, 0x06
	ihl6 := ipv4FrameIHL(64, 6, 17, 64, 50, [4]byte{10, 0, 0, 7})     // 4 bytes of options — ports at offset 38
	ihl15 := ipv4FrameIHL(100, 15, 6, 50, 86, [4]byte{10, 0, 0, 9})   // 40 bytes of options — ports at offset 74
	ihl15s := ipv4FrameIHL(76, 15, 17, 51, 62, [4]byte{10, 0, 0, 10}) // the port window (74..78) is outside the packet — ports are 0
	ihl4 := ipv4FrameIHL(64, 4, 17, 52, 50, [4]byte{10, 0, 0, 11})    // a broken IPv4 — not counted as a flow
	s1 := [4]uint8{10, 0, 0, 1}
	return []selftestFrame{
		{"udp-1", ipv4Frame(60, 17, 64, 29, s1), KUDP, ev(17, 64, 29, s1), fl(s1, 17, 1000, 2000), false},
		{"icmp-1", ipv4Frame(98, 1, 63, 84, [4]byte{10, 0, 0, 2}), KICMP, ev(1, 63, 84, [4]uint8{10, 0, 0, 2}), fl([4]uint8{10, 0, 0, 2}, 1, 0, 0), false},
		{"tcp-1", ipv4Frame(74, 6, 128, 60, [4]byte{192, 168, 1, 9}), KTCP, ev(6, 128, 60, [4]uint8{192, 168, 1, 9}), fl([4]uint8{192, 168, 1, 9}, 6, 1000, 2000), false},
		{"udp-2", ipv4Frame(1514, 17, 1, 1500, [4]byte{255, 255, 255, 255}), KUDP, ev(17, 1, 1500, [4]uint8{255, 255, 255, 255}), fl([4]uint8{255, 255, 255, 255}, 17, 1000, 2000), false},
		{"gre", ipv4Frame(64, 47, 30, 50, [4]byte{1, 2, 3, 4}), KIPv4Other, ev(47, 30, 50, [4]uint8{1, 2, 3, 4}), fl([4]uint8{1, 2, 3, 4}, 47, 0, 0), false},
		{"arp", arp, KOther, nil, nil, false},
		{"ipv4-33", ipv4Frame(33, 17, 64, 29, [4]byte{}), KOther, nil, nil, false}, // IPv4 but the header is shorter than 34 bytes
		{"icmp-2", ipv4Frame(42, 1, 255, 28, [4]byte{10, 0, 0, 3}), KICMP, ev(1, 255, 28, [4]uint8{10, 0, 0, 3}), fl([4]uint8{10, 0, 0, 3}, 1, 0, 0), false},
		{"udp-1-again", ipv4Frame(60, 17, 20, 40, s1), KUDP, ev(17, 20, 40, s1), fl(s1, 17, 1000, 2000), false},                                            // the second frame of the same flow — Last is the last frame
		{"udp-36", ipv4Frame(36, 17, 9, 22, [4]byte{10, 0, 0, 8}), KUDP, ev(17, 9, 22, [4]uint8{10, 0, 0, 8}), fl([4]uint8{10, 0, 0, 8}, 17, 0, 0), false}, // shorter than the 38 bytes the ports need — ports are 0
		{"udp-ihl-6", ihl6, KUDP, ev(17, 64, 50, [4]uint8{10, 0, 0, 7}), fl([4]uint8{10, 0, 0, 7}, 17, 1000, 2000), false},
		{"tcp-ihl-15", ihl15, KTCP, ev(6, 50, 86, [4]uint8{10, 0, 0, 9}), fl([4]uint8{10, 0, 0, 9}, 6, 1000, 2000), false},
		{"udp-ihl-15-short", ihl15s, KUDP, ev(17, 51, 62, [4]uint8{10, 0, 0, 10}), fl([4]uint8{10, 0, 0, 10}, 17, 0, 0), false},
		{"udp-ihl-4", ihl4, KUDP, ev(17, 52, 50, [4]uint8{10, 0, 0, 11}), nil, true},
	}
}

func runSelftest(objs *gobpf.Objects, rd *gobpf.Reader[Event]) int {
	prog, err := objs.Program(Sample)
	if err != nil {
		log.Print(err)
		return 1
	}
	wantCounts := make([]uint64, NumKeys)
	wantHist := make([]uint64, NumBuckets)
	wantBytes := make([]uint64, NumKeys)
	wantLast := map[uint32]Seen{}
	wantFlows := map[FlowKey]uint64{}
	wantFlowLast := map[FlowKey]FlowLast{}
	var wantEvents []Event
	for _, f := range selftestFrames() {
		ret, err := prog.Run(&ebpf.RunOptions{Data: f.frame})
		if err != nil || ret != uint32(bpf.XDPPass) {
			log.Printf("%s: test run: ret %d err %v", f.name, ret, err)
			return 1
		}
		wantCounts[f.key]++
		if f.ihl {
			wantCounts[KIHL]++
		}
		if f.event != nil {
			wantEvents = append(wantEvents, *f.event)
			wantHist[sizeBucket(uint32(f.event.Len))]++
			wantBytes[f.key] += uint64(f.event.Len)
			wantLast[f.key] = Seen{Hdr: Hdr{Len: f.event.Len, Proto: f.event.Proto, TTL: f.event.TTL}, Src: f.event.Src}
		}
		if f.flow != nil {
			wantFlows[*f.flow]++
			wantFlowLast[*f.flow] = FlowLast{Len: f.event.Len, TTL: f.event.TTL}
		}
	}
	ok := true
	got, err := readCounts()
	if err != nil {
		log.Print(err)
		return 1
	}
	for k := range wantCounts {
		if got[k] != wantCounts[k] {
			ok = false
			fmt.Printf("mismatch count %s: got %d want %d\n", keyNames[k], got[k], wantCounts[k])
		}
	}
	for k, w := range wantLast {
		g, err := LastSeen.Get(k)
		if err != nil || g != w {
			ok = false
			fmt.Printf("mismatch lastseen %s: got %+v (err %v) want %+v\n", keyNames[k], g, err, w)
		}
	}
	for k := uint32(0); k < NumBuckets; k++ {
		if g, err := SizeHist.Get(k); err != nil || g != wantHist[k] {
			ok = false
			fmt.Printf("mismatch size bucket %d: got %d (err %v) want %d\n", k, g, err, wantHist[k])
		}
	}
	for k := uint32(0); k < KDrops; k++ { // the sum over CPUs of the per-CPU statistics
		vs, err := PerProto.GetPerCPU(k)
		if err != nil {
			log.Print(err)
			return 1
		}
		var s ProtoStats
		for _, v := range vs {
			s.Packets += v.Packets
			s.Bytes += v.Bytes
		}
		if s.Packets != wantCounts[k] || s.Bytes != wantBytes[k] {
			ok = false
			fmt.Printf("mismatch perproto %s: got %+v want packets=%d bytes=%d\n", keyNames[k], s, wantCounts[k], wantBytes[k])
		}
	}
	gotFlows := map[FlowKey]uint64{}
	it := Flows.Iterate()
	for it.Next() {
		gotFlows[it.Key()] = it.Value()
	}
	if err := it.Err(); err != nil {
		log.Print(err)
		return 1
	}
	if fmt.Sprint(gotFlows) != fmt.Sprint(wantFlows) {
		ok = false
		fmt.Printf("mismatch flows: got %v want %v\n", gotFlows, wantFlows)
	}
	for k, w := range wantFlowLast {
		if g, err := Last.Get(k); err != nil || g != w {
			ok = false
			fmt.Printf("mismatch flow last %+v: got %+v (err %v) want %+v\n", k, g, err, w)
		}
	}
	var gotEvents []Event
	for {
		rd.SetDeadline(time.Now().Add(100 * time.Millisecond))
		ev, err := rd.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			break
		}
		if err != nil {
			log.Print(err)
			return 1
		}
		gotEvents = append(gotEvents, ev)
	}
	if len(gotEvents) != len(wantEvents) {
		ok = false
		fmt.Printf("mismatch events: got %d want %d\n", len(gotEvents), len(wantEvents))
	} else {
		for i := range gotEvents {
			if gotEvents[i] != wantEvents[i] {
				ok = false
				fmt.Printf("mismatch event %d: got %+v want %+v\n", i, gotEvents[i], wantEvents[i])
			}
		}
	}
	printState()
	fmt.Printf("events total=%d\n", len(gotEvents))
	printFlows()
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

// sizeBucket is Sample's bucket rule for the length distribution written in Go (the selftest's expected values — flowsample_test.go checks the same rule).
func sizeBucket(ln uint32) uint32 {
	b := uint32(0)
	for t := uint32(64); t <= 4096; t *= 2 {
		if ln > t {
			b++
		}
	}
	return min(b, NumBuckets-1)
}
