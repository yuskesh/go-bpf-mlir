package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// An invalidating op (AdjustHead) inside a callee that takes the context — bpf-mlir refuses adjust in a callee (GB013).
var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

func strip(ctx *bpf.XDPContext) int64 {
	return ctx.AdjustHead(4)
}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	st := strip(ctx)
	if st == 0 {
		Out.AtomicAdd(0, 1)
	}
	return bpf.XDPPass
}

func main() {}
