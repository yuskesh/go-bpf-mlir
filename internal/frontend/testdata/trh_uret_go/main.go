package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:uretprobe cgofix.bin main.goSum
func f(ctx *bpf.UretprobeContext[int64]) {
	Out.Update(0, uint64(ctx.Ret()))
}

func main() {}
