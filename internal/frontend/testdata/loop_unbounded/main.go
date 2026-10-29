package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	n := uint32(0)
	for n < 10 {
		n++
	}
	Counts.Update(0, uint64(n))
	return bpf.XDPPass
}

func main() {}
