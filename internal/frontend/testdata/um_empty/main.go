package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:uprobe_multi umfix
func f(ctx *bpf.UprobeContext) {
	Out.AtomicAdd(0, 1)
}

func main() {}
