package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Stacks = bpf.StackTrace{MaxEntries: 16, Depth: 8}
var Out = bpf.Array[uint32, int64]{MaxEntries: 4}

//gobpf:fentry do_sys_poll
func f(ctx *bpf.FentryContext) {
	for i := uint32(0); i < 4; i++ {
		Out.Update(i, Stacks.KernelID(ctx, 0))
	}
}

func main() {}
