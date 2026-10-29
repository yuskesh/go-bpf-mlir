package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:kretprobe bpf_fentry_test1
func f(ctx *bpf.KretprobeContext[int8]) {
	Out.Update(0, uint64(int64(ctx.Ret())))
}

func main() {}
