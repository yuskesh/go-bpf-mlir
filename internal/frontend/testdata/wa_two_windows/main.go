package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 8}

// At most one packet window argument.
func both(a bpf.Window, b bpf.Window) uint32 {
	return uint32(a.U8(0)) + uint32(b.U8(0))
}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	k := uint32(0)
	if w, ok := ctx.Check(0, 14); ok {
		k = both(w, w) & 7
	}
	Counts.AtomicAdd(k, 1)
	return bpf.XDPPass
}

func main() {}
