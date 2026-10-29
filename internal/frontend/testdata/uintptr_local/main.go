package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	var x uintptr = 1
	Counts.Update(0, uint64(x))
	return bpf.XDPPass
}

func main() {}
