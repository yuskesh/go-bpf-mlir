// xdpwindow is an example that counts, in xdp, the packets in "a fixed time window from the first packet". The first packet arms a timer (bpf.Timer —
// only when the Init status is 0), the number of packets and of large packets (128 bytes or more) in the window are counted as a pair in a spin-lock record (bpf.WithLock —
// the two fields are always a pair from the same instant), and the timer callback records when it closed the window. Packets after the window are counted in Late.
//
//	xdpwindow -iface eth0 [-window 1s] [-duration 5s]   # attach and print the window counts
//	xdpwindow -selftest                                 # send packets by test run and check the counts in and after the window and the window length
//	xdpwindow -parse-only                               # parse the embedded ELF without touching the kernel (no root needed)
//
// The user-space side's Tally.Get reads with BPF_F_LOCK (the same lock as the eBPF side's WithLock — the pair never mixes). The Wins timer cannot be Put from the user-space side
// (the frontend stops it — a user-space update would stop a running timer). Non-root needs CAP_BPF + CAP_NET_ADMIN (the same as the other xdp examples).
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/yuskesh/go-bpf-mlir/livecaps"

	"github.com/yuskesh/go-bpf-mlir/bpf"
	"github.com/yuskesh/go-bpf-mlir/gobpf"
)

//go:generate go tool gobpf

// Tally is the counts in the window (a lock record — 24 bytes).
type Tally struct {
	Lock    bpf.SpinLock `schema:"lock"`
	_       [4]byte
	Packets uint64 `schema:"packets"`
	Large   uint64 `schema:"large"`
}

// Win is the window's timer and times (40 bytes). ArmNs is when it was armed, ClosedNs when the callback closed the window, Closed how many times it closed (should be 1).
type Win struct {
	T        bpf.Timer `schema:"t"`
	ArmNs    uint64    `schema:"arm_ns"`
	ClosedNs uint64    `schema:"closed_ns"`
	Closed   uint64    `schema:"closed"`
}

// WindowNs is the window length (.rodata).
var WindowNs = bpf.Config[uint64]{}

var (
	Tally1 = bpf.Array[uint32, Tally]{MaxEntries: 1}
	Wins   = bpf.Array[uint32, Win]{MaxEntries: 1}
	// Late[0] is the number of packets after the window.
	Late = bpf.Array[uint32, uint64]{MaxEntries: 1}
)

// onClose is the timer callback (it closes the window).
func onClose(w *Win) {
	w.ClosedNs = bpf.KtimeNs()
	w.Closed++
}

// Count is the eBPF side (an xdp program).
func Count(ctx *bpf.XDPContext) bpf.XDPAction {
	large := uint64(0)
	if w, ok := ctx.Check(0, 128); ok { // a packet of 128 bytes or more
		_ = w.U8(127)
		large = 1
	}
	closed := uint64(0)
	if w := Wins.Lookup(0); w != nil {
		closed = w.Closed
		if st := w.T.Init(); st == 0 { // only the first packet (−EBUSY afterwards)
			w.ArmNs = bpf.KtimeNs()
			_ = w.T.SetCallback(onClose)
			_ = w.T.Start(WindowNs.Value())
		}
	}
	if closed == 0 {
		if p := Tally1.Lookup(0); p != nil {
			bpf.WithLock(&p.Lock, func() {
				p.Packets++
				p.Large += large
			})
		}
	} else {
		Late.AtomicAdd(0, 1)
	}
	return bpf.XDPPass
}

func main() {
	iface := flag.String("iface", "", "interface to attach to")
	window := flag.Duration("window", time.Second, "window length")
	duration := flag.Duration("duration", 5*time.Second, "print for this long, then exit")
	selftest := flag.Bool("selftest", false, "send packets with a test run and check the window counts")
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
		*window = 100 * time.Millisecond
	}
	if err := WindowNs.Set(uint64(window.Nanoseconds())); err != nil {
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
		os.Exit(runSelftest(objs, *window))
	}
	if *iface == "" {
		log.Fatal("-iface is required (or -selftest)")
	}
	ifc, err := net.InterfaceByName(*iface)
	if err != nil {
		log.Fatal(err)
	}
	l, err := gobpf.AttachXDP(objs, Count, ifc.Index)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	deadline := time.Now().Add(*duration)
	for time.Now().Before(deadline) {
		time.Sleep(time.Second)
		printState()
	}
}

func printState() {
	t, err := Tally1.Get(0)
	if err != nil {
		log.Printf("Tally: %v", err)
		return
	}
	w, _ := Wins.Get(0)
	late, _ := Late.Get(0)
	state := "open"
	if w.Closed > 0 {
		state = fmt.Sprintf("closed after %.1f ms", float64(w.ClosedNs-w.ArmNs)/1e6)
	} else if w.ArmNs == 0 {
		state = "not started"
	}
	fmt.Printf("window %s: packets=%d large=%d late=%d\n", state, t.Packets, t.Large, late)
}

func runSelftest(objs *gobpf.Objects, window time.Duration) int {
	prog, err := objs.Program(Count)
	if err != nil {
		log.Print(err)
		return 1
	}
	send := func(size int, n int) error {
		for i := 0; i < n; i++ {
			if _, err := prog.Run(&ebpf.RunOptions{Data: make([]byte, size)}); err != nil {
				return err
			}
		}
		return nil
	}
	// In the window: 12 small, 8 large. After the window: 5.
	if err := send(64, 12); err != nil {
		log.Print(err)
		return 1
	}
	if err := send(200, 8); err != nil {
		log.Print(err)
		return 1
	}
	in, _ := Tally1.Get(0)
	time.Sleep(3 * window)
	w, _ := Wins.Get(0)
	if err := send(64, 5); err != nil {
		log.Print(err)
		return 1
	}
	after, _ := Tally1.Get(0)
	late, _ := Late.Get(0)
	printState()
	closedMs := float64(w.ClosedNs-w.ArmNs) / 1e6
	ok := in.Packets == 20 && in.Large == 8 && w.Closed == 1 && closedMs >= float64(window.Milliseconds()) && after == in && late == 5
	fmt.Printf("selftest in_window=%d/20 large=%d/8 closed=%d after_ms=%.3f (window %v) late=%d/5 tally_unchanged=%v result=%s\n",
		in.Packets, in.Large, w.Closed, closedMs, window, late, after == in, map[bool]string{true: "ok", false: "FAIL"}[ok])
	if !ok {
		return 1
	}
	return 0
}
