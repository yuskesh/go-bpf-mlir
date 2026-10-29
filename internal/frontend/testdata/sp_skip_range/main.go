package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Stacks = bpf.StackTrace{MaxEntries: 16, Depth: 8}
var Out = bpf.Array[uint32, int64]{MaxEntries: 1}

//gobpf:fentry do_sys_poll
func f(ctx *bpf.FentryContext) {
	Out.Update(0, Stacks.KernelIDReuse(ctx, 256))
}

func main() {}
