package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	for i := 0; i < 3; i++ {
	}
	return bpf.XDPPass
}

func main() {}
