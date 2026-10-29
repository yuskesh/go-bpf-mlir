package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

func P(ctx *bpf.TCIngressContext) bpf.TCAction {
	ctx.Redirect(1)
	return bpf.TCPass
}

func main() {}
