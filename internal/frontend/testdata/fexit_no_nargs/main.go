package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var C = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:fexit bpf_fentry_test1
func f(ctx *bpf.FexitContext[int32]) {
	C.Update(0, uint64(ctx.Ret()))
}

func main() {}
