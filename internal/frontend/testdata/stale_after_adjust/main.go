package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var C = bpf.Array[uint32, uint64]{MaxEntries: 1}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	if w, ok := ctx.Check(0, 14); ok {
		_ = ctx.AdjustHead(4)
		C.Update(0, uint64(w.U8(0)))
	}
	return bpf.XDPPass
}

func main() {}
