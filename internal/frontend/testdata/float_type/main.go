package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

func F(a uint32) uint32 {
	f := float64(a) * 1.5
	return uint32(f)
}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	Counts.Update(0, uint64(F(1)))
	return bpf.XDPPass
}

func main() {}
