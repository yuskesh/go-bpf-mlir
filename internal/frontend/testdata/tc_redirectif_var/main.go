package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

func P(ctx *bpf.TCIngressContext) bpf.TCAction {
	v := bpf.TCPass
	return ctx.RedirectIf(true, 1, v)
}

func main() {}
