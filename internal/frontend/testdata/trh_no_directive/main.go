package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

func f(ctx *bpf.KretprobeContext[int32]) {
	Out.Update(0, uint64(int64(ctx.Ret())))
}

func main() {}
