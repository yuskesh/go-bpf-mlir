package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Acc = bpf.Array[uint32, uint64]{MaxEntries: 8}

func one(ctx *bpf.XDPContext) uint32 {
	return 1
}

// Passes the context to a subprogram in an (H) body — the callback has no context.
func f(ctx *bpf.XDPContext) bpf.XDPAction {
	//gobpf:loop callback
	for i := uint32(0); i < 8; i++ {
		Acc.AtomicAdd(i, uint64(one(ctx)))
	}
	return bpf.XDPPass
}

func main() {}
