package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:uretprobe greet
func f(ctx *bpf.UretprobeContext[uint32]) {
	Out.Update(0, uint64(ctx.Ret()))
}

func main() {}
