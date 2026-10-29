package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

// um_wide's first argument is int32 — it stops unless every symbol in the list has the same type (per-symbol types are out of scope).
//
//gobpf:uprobe_multi umfix um_add um_wide
func f(ctx *bpf.UprobeContext) {
	Out.Update(0, uint64(bpf.UprobeArg[int64](ctx, 1)))
}

func main() {}
