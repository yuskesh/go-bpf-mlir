package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:fentry bpf_fentry_test2
func f(ctx *bpf.FentryContext) {
	i := uint32(bpf.KtimeNs() & 1)
	x := bpf.FentryArgInt[uint64](ctx, i)
	Out.Update(0, x)
}

func main() {}
