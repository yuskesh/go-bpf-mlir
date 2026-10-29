package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var C = bpf.Array[uint32, uint64]{MaxEntries: 1}

func P(ctx *bpf.TCIngressContext) bpf.TCAction {
	if w, ok := ctx.Check(0, 14); ok {
		w.SetU8(0, 1)
	}
	return bpf.TCPass
}

func main() {}
