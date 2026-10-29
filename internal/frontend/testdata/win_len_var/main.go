package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	n := uint32(14)
	v := uint64(0)
	if w, ok := ctx.Check(0, n); ok {
		v = uint64(w.U8(0))
	}
	Counts.Update(0, v)
	return bpf.XDPPass
}

func main() {}
