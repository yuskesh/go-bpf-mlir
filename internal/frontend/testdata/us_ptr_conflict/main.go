package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Stacks = bpf.StackTrace{MaxEntries: 64, Depth: 16}

var Builds = bpf.StackBuildID{MaxEntries: 64, Depth: 16}

var Out = bpf.Array[uint32, uint64]{MaxEntries: 4}

//gobpf:kprobe do_sys_poll
func onPoll(ctx *bpf.KprobeContext) {
	Out.Update(0, uint64(bpf.KprobeArg[uintptr](ctx, 1)))
	Out.Update(1, uint64(bpf.KprobeArg[uint32](ctx, 1)))
}

func main() {}
