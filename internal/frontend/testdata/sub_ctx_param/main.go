package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

func F(ctx *bpf.XDPContext) uint32 { return 1 }

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	Counts.Update(0, uint64(F(ctx)))
	return bpf.XDPPass
}

func main() {}
