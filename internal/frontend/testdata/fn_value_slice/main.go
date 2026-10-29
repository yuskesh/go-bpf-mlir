package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 1}

func kind(w bpf.Window) uint32 {
	k := uint32(0)
	if w.BE16(12) == 0x0800 {
		k = 1
	}
	return k
}

func Count(ctx *bpf.XDPContext) bpf.XDPAction {
	if w, ok := ctx.Check(0, 14); ok {
		Counts.AtomicAdd(0, uint64(kind(w)))
	}
	return bpf.XDPPass
}

// Puts program functions in a slice — stops with GB004 only; the helper-kind GB003 does not cascade.
func main() {
	progs := []any{Count}
	_ = progs
}
