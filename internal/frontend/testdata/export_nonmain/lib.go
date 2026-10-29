package lib

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

func Helper(x uint64) uint64 { return x + 1 }

func Sample(ctx *bpf.XDPContext) bpf.XDPAction {
	Counts.AtomicAdd(0, Helper(1))
	return bpf.XDPPass
}
