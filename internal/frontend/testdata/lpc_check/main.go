package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Acc = bpf.Array[uint32, uint64]{MaxEntries: 8}

// ctx.Check in an (H) body — the context rule names it first.
func f(ctx *bpf.XDPContext) bpf.XDPAction {
	//gobpf:loop callback
	for i := uint32(0); i < 8; i++ {
		if w, ok := ctx.Check(i, 1); ok {
			Acc.AtomicAdd(i, uint64(w.U8(0)))
		}
	}
	return bpf.XDPPass
}

func main() {}
