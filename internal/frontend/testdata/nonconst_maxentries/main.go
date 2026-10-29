package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var n uint32 = 2

var Counts = bpf.Array[uint32, uint64]{MaxEntries: n}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	return bpf.XDPPass
}

func main() {}
