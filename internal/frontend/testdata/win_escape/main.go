package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	var keep bpf.Window
	if w, ok := ctx.Check(0, 14); ok {
		keep = w
	}
	Counts.Update(0, uint64(keep.U8(0)))
	return bpf.XDPPass
}

func main() {}
