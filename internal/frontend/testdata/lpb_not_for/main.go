package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Acc = bpf.Array[uint32, uint64]{MaxEntries: 8}

func f(ctx *bpf.XDPContext) bpf.XDPAction {
	//gobpf:loop backedge
	if Acc.Lookup(0) != nil {
		Acc.AtomicAdd(1, 1)
	}
	return bpf.XDPPass
}

func main() {}
