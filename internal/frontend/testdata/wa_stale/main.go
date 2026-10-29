package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 8}

func etype(w bpf.Window) uint32 {
	return uint32(w.BE16(12))
}

// Passes a stale packet window after AdjustHead — GB025 (packet generation).
func P(ctx *bpf.XDPContext) bpf.XDPAction {
	k := uint32(0)
	if w, ok := ctx.Check(0, 18); ok {
		if st := ctx.AdjustHead(4); st == 0 {
			k = etype(w) & 7
		}
	}
	Counts.AtomicAdd(k, 1)
	return bpf.XDPPass
}

func main() {}
