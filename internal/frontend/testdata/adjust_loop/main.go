package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var C = bpf.Array[uint32, uint64]{MaxEntries: 1}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	for range uint32(2) {
		_ = ctx.AdjustHead(1)
	}
	return bpf.XDPPass
}

func main() {}
