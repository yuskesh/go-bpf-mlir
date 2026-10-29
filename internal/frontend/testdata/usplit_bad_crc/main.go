package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

// The sfix.debug beside sfix has the same build ID but other bytes (its CRC32 is not the one in sfix's .gnu_debuglink) — refused, not read.
//
//gobpf:uprobe sfix split_sum
func f(ctx *bpf.UprobeContext) {
	Out.Update(0, uint64(bpf.UprobeArg[int64](ctx, 1)))
}

func main() {}
