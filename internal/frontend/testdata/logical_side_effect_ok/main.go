package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

func G(a uint32) bool { return a > 1 }

func F(a uint32) uint32 {
	r := uint32(0)
	if a > 0 && G(a) {
		r = 1
	}
	return r
}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	Counts.Update(0, uint64(F(1)))
	return bpf.XDPPass
}

func main() {}
