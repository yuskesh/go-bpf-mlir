package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:fentry bpf_fentry_test2
func f(ctx *bpf.FentryContext) {
	Out.Update(0, bpf.FentryArgInt[uint64](ctx, 1))
}

func main() {}
