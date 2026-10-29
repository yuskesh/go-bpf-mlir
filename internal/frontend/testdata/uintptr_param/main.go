package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

func F(p uintptr) uint64 { return uint64(p) }

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	Counts.Update(0, F(1))
	return bpf.XDPPass
}

func main() {}
