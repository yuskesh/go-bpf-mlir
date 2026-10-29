package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

func arg(ctx *bpf.FentryContext) uint64 {
	x := bpf.FentryArgInt[uint64](ctx, 1)
	return x
}

//gobpf:fentry bpf_fentry_test2
func f(ctx *bpf.FentryContext) {
	Out.Update(0, arg(ctx))
}

func main() {}
