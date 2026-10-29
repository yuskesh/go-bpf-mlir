package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	v := uint64(0)
	if w, ok := ctx.Check(0, 14); ok {
		v = uint64(w.U8(13 + 1))
	}
	Counts.Update(0, v)
	return bpf.XDPPass
}

func main() {}
