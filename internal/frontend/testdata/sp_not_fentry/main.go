package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Stacks = bpf.StackTrace{MaxEntries: 16, Depth: 8}
var Out = bpf.Array[uint32, int64]{MaxEntries: 1}

//gobpf:kprobe do_sys_poll
func f(ctx *bpf.KprobeContext) {
	Out.Update(0, Stacks.KernelID(ctx, 0))
}

func main() {}
