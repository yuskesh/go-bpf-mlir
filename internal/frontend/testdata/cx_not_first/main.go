package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The context is not the first argument (bpf-mlir refuses a context after a map handle — the frontend requires the first argument) — GB013.
var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

func at(off uint32, ctx *bpf.XDPContext) uint32 {
	k := uint32(0)
	if w, ok := ctx.Check(0, 14); ok {
		k = uint32(w.U8(12)) + off
	}
	return k
}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	Out.Update(0, uint64(at(1, ctx)))
	return bpf.XDPPass
}

func main() {}
