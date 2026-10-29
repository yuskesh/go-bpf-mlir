package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

func B(x uint32) uint32 {
	r := uint32(0)
	switch x {
	case 1:
		r = 2
	}
	return r
}

func A(x uint32) uint32 { return B(x) }

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	Counts.Update(0, uint64(A(1)))
	return bpf.XDPPass
}

func main() {}
