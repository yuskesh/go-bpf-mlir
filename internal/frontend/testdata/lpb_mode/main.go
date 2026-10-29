package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Acc = bpf.Array[uint32, uint64]{MaxEntries: 8}

func f(ctx *bpf.XDPContext) bpf.XDPAction {
	//gobpf:loop sideways
	for i := uint32(0); i < 8; i++ {
		Acc.AtomicAdd(i, 1)
	}
	return bpf.XDPPass
}

func main() {}
