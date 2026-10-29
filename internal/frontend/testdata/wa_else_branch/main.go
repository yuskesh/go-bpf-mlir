package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 8}

func etype(w bpf.Window) uint32 {
	return uint32(w.BE16(12))
}

// Passes w from the else branch (the packet is shorter than the checked range) — GB005.
func P(ctx *bpf.XDPContext) bpf.XDPAction {
	k := uint32(0)
	if w, ok := ctx.Check(0, 14); ok {
		k = 1
	} else {
		k = etype(w) & 7
	}
	Counts.AtomicAdd(k, 1)
	return bpf.XDPPass
}

func main() {}
