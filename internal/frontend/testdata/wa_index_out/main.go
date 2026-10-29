package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 8}

// Callee reads must lie within the caller's window length (14) — index 23 is out of range (GB014).
func proto(w bpf.Window) uint32 {
	return uint32(w.U8(23))
}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	k := uint32(0)
	if w, ok := ctx.Check(0, 14); ok {
		k = proto(w) & 7
	}
	Counts.AtomicAdd(0, uint64(k))
	return bpf.XDPPass
}

func main() {}
