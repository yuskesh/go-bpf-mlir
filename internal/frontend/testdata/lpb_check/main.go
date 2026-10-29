package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Acc = bpf.Array[uint32, uint64]{MaxEntries: 8}

// ctx.Check in a (B) body — bpf-mlir accepts packet.check only in a (U) body.
func f(ctx *bpf.XDPContext) bpf.XDPAction {
	//gobpf:loop backedge
	for i := uint32(0); i < 8; i++ {
		if w, ok := ctx.Check(i, 1); ok {
			Acc.AtomicAdd(i, uint64(w.U8(0)))
		}
	}
	return bpf.XDPPass
}

func main() {}
