package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

// sfix-nolink has neither .debug_info nor .gnu_debuglink.
//
//gobpf:uprobe sfix-nolink split_sum
func f(ctx *bpf.UprobeContext) {
	Out.Update(0, uint64(bpf.UprobeArg[int64](ctx, 1)))
}

func main() {}
