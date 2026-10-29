package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var C = bpf.Array[uint32, uint64]{MaxEntries: 1}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	_ = ctx.AdjustTail(4)
	return bpf.XDPPass
}

func main() {}
