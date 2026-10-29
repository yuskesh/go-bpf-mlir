package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:fentry bpf_fentry_test1
func f(ctx *bpf.FentryContext) {
	a := bpf.LSMArgInt[int32](ctx, 0)
	Out.Update(0, uint64(a))
}

func main() {}
