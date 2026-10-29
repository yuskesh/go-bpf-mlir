package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

// The argument types come from the separate DWARF: argument 2 of split_sum is unsigned (u32), not i16.
//
//gobpf:uprobe sfix split_sum
func f(ctx *bpf.UprobeContext) {
	Out.Update(0, uint64(bpf.UprobeArg[int16](ctx, 2)))
}

func main() {}
