package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

// A raw pointer argument in a uprobe_multi program is out of scope (integer arguments only).
//
//gobpf:uprobe_multi umfix um_add um_mul
func f(ctx *bpf.UprobeContext) {
	Out.Update(0, uint64(bpf.UprobeArg[uintptr](ctx, 1)))
}

func main() {}
