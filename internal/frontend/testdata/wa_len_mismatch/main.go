package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 8}

// The two call sites pass packet windows of different lengths (14 and 24) — the length is part of the window type.
func etype(w bpf.Window) uint32 {
	return uint32(w.BE16(12))
}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	k := uint32(0)
	if w, ok := ctx.Check(0, 24); ok {
		k = etype(w) & 7
	}
	if w2, ok2 := ctx.Check(0, 14); ok2 {
		k = etype(w2) & 7
	}
	Counts.AtomicAdd(k, 1)
	return bpf.XDPPass
}

func main() {}
