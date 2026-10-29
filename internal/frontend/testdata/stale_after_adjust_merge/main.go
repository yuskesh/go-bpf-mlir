package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var C = bpf.Array[uint32, uint64]{MaxEntries: 1}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	if w, ok := ctx.Check(0, 14); ok {
		if w.U8(0) == 1 {
			_ = ctx.AdjustHead(4)
		}
		w.SetU8(1, 2)
	}
	return bpf.XDPPass
}

func main() {}
