package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Static helpers that take the program context as the first argument. xdp Check, window reads, window writes, forwarding ctx,
// tc ingress Check, fentry stack ids and perf Output.

type Ev struct {
	ID int64  `schema:"id"`
	K  uint32 `schema:"k"`
	_  [4]byte
}

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 8}
var Stacks = bpf.StackTrace{MaxEntries: 64, Depth: 8}
var Events = bpf.PerfEventArray[Ev]{}

// etype reads the ethertype (the packet window comes from a Check inside the helper).
func etype(ctx *bpf.XDPContext) uint32 {
	k := uint32(0)
	if w, ok := ctx.Check(0, 14); ok {
		k = uint32(w.BE16(12))
	}
	return k
}

// isIPv4 forwards ctx to etype.
func isIPv4(ctx *bpf.XDPContext) uint32 {
	r := uint32(0)
	if etype(ctx) == 0x0800 {
		r = 1
	}
	return r
}

// mark writes to the packet window (an xdp callee) and passes the window of its own Check to a writing window helper.
func mark(ctx *bpf.XDPContext) uint32 {
	if w, ok := ctx.Check(0, 14); ok {
		w.SetU8(0, 0x02)
		_ = flip(w)
	}
	return 0
}

// flip takes a packet window and writes to it (the caller passes a Check window of a callee that takes the xdp context).
func flip(w bpf.Window) uint32 {
	w.SetU8(1, w.U8(1)^0xff)
	return 0
}

func tcKey(ctx *bpf.TCIngressContext) uint32 {
	k := uint32(3)
	if w, ok := ctx.Check(0, 14); ok {
		k = uint32(w.U8(13)) & 3
	}
	return k
}

func stackOf(ctx *bpf.FentryContext) int64 {
	return Stacks.KernelID(ctx, 0)
}

func emit(ctx *bpf.FentryContext, k uint32) int64 {
	return Events.Output(ctx, Ev{ID: stackOf(ctx), K: k})
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	k := isIPv4(ctx) & 1
	_ = mark(ctx)
	Counts.AtomicAdd(k, 1)
	return bpf.XDPPass
}

func TC(ctx *bpf.TCIngressContext) bpf.TCAction {
	k := tcKey(ctx)
	if k >= 4 {
		k = 3 // the frontend does not know the helper's return range — a clamp that proves the key (GB020)
	}
	Counts.AtomicAdd(4+k, 1)
	return bpf.TCPass
}

//gobpf:fentry bpf_fentry_test1
func onTest(ctx *bpf.FentryContext) {
	st := emit(ctx, 7)
	if st != 0 {
		Counts.AtomicAdd(7, 1)
	}
}

func main() {}
