package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Stacks = bpf.StackTrace{MaxEntries: 64, Depth: 16}

var Builds = bpf.StackBuildID{MaxEntries: 64, Depth: 16}

var Out = bpf.Array[uint32, uint64]{MaxEntries: 4}

//gobpf:uprobe cfix sum_args
func onSum(ctx *bpf.UprobeContext) {
	Out.Update(0, uint64(bpf.UprobeArg[uintptr](ctx, 1)))
}

func main() {}
