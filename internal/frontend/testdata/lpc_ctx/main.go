package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Acc = bpf.Array[uint32, uint64]{MaxEntries: 8}

// Uses the context in an (H) body — only integers and map handles can be carried into a bpf_loop callback.
func f(ctx *bpf.XDPContext) bpf.XDPAction {
	//gobpf:loop callback
	for i := uint32(0); i < 8; i++ {
		if ctx.AdjustHead(0) == 0 {
			Acc.AtomicAdd(i, 1)
		}
	}
	return bpf.XDPPass
}

func main() {}
