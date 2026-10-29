package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Positive case: (B) loops — constant counts, a runtime bound and break, iter_args (total), mixed with (U) loops.

var Out = bpf.Array[uint32, uint64]{MaxEntries: 4}

func f(ctx *bpf.XDPContext) bpf.XDPAction {
	n := uint32(0)
	if w, ok := ctx.Check(0, 1); ok {
		n = uint32(w.U8(0))
	}
	total := uint64(0)
	//gobpf:loop backedge
	for i := uint32(0); i < n && i < 64; i++ {
		if i == 40 {
			break
		}
		total += uint64(i)
	}
	for i := range uint32(4) {
		Out.AtomicAdd(i, total)
	}
	return bpf.XDPPass
}

func main() {}
