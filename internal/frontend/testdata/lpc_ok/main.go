package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Positive case: (H) loops — constant counts, a runtime bound and break, iter_args (total), map ops; the packet is read before the loop.

var Out = bpf.Array[uint32, uint64]{MaxEntries: 4}

func f(ctx *bpf.XDPContext) bpf.XDPAction {
	n := uint32(0)
	if w, ok := ctx.Check(0, 1); ok {
		n = uint32(w.U8(0))
	}
	total := uint64(0)
	//gobpf:loop callback
	for i := uint32(0); i < n && i < 64; i++ {
		if i == 40 {
			break
		}
		total += uint64(i)
	}
	//gobpf:loop callback
	for i := uint32(0); i < 4; i++ {
		Out.AtomicAdd(i, total)
	}
	return bpf.XDPPass
}

func main() {}
