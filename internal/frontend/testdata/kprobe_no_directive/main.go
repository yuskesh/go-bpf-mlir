package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

func f(ctx *bpf.KprobeContext) {
	Out.Update(0, uint64(bpf.KprobeArg[uint32](ctx, 2)))
}

func main() {}
