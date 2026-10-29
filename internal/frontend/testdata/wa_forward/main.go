package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 8}

func inner(w bpf.Window) uint32 {
	return uint32(w.U8(0))
}

// outer passes the packet window it received to inner — forwarding is GB013 (gobpf takes the strict side).
func outer(w bpf.Window) uint32 {
	return inner(w) + 1
}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	k := uint32(0)
	if w, ok := ctx.Check(0, 14); ok {
		k = outer(w) & 7
	}
	Counts.AtomicAdd(0, uint64(k))
	return bpf.XDPPass
}

func main() {}
