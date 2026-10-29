package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

// Argument 3 of buf_write is an int, not a pointer.
//
//gobpf:uprobe bfix buf_write
func f(ctx *bpf.UprobeContext) {
	Out.Update(0, uint64(bpf.UprobeArg[uintptr](ctx, 3)))
}

func main() {}
