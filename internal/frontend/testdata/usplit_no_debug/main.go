package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

// sfix's .gnu_debuglink names sfix.debug, which is not in the package directory — the frontend does not look in /usr/lib/debug.
//
//gobpf:uprobe sfix split_sum
func f(ctx *bpf.UprobeContext) {
	Out.Update(0, uint64(bpf.UprobeArg[int64](ctx, 1)))
}

func main() {}
