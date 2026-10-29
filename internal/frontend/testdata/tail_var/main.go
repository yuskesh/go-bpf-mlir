package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var C = bpf.Array[uint32, uint64]{MaxEntries: 1}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	d := int32(-4)
	_ = ctx.AdjustTail(d)
	return bpf.XDPPass
}

func main() {}
