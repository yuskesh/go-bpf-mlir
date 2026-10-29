package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:uretprobe_multi umfix um_*
func f(ctx *bpf.UretprobeContext[int64]) {
	Out.AtomicAdd(0, 1)
}

func main() {}
