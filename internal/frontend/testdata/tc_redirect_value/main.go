package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

func P(ctx *bpf.TCEgressContext) bpf.TCAction {
	a := ctx.Redirect(1)
	_ = a
	return bpf.TCPass
}

func main() {}
