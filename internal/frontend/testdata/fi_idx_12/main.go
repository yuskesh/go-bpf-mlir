package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:fentry bpf_fentry_test2
func f(ctx *bpf.FentryContext) {
	x := bpf.FentryArgInt[uint64](ctx, 12)
	Out.Update(0, x)
}

func main() {}
