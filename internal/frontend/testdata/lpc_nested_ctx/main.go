package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Acc = bpf.Array[uint32, uint64]{MaxEntries: 8}

// The context in an (H) body inside a (U) loop — the error names the ctx in the inner (H) body (a (U) body may use the context).
func f(ctx *bpf.XDPContext) bpf.XDPAction {
	for j := uint32(0); j < 4; j++ {
		//gobpf:loop callback
		for i := uint32(0); i < 8; i++ {
			if ctx.AdjustTail(0) == 0 {
				Acc.AtomicAdd(i, uint64(j))
			}
		}
	}
	return bpf.XDPPass
}

func main() {}
