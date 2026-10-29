package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Stacks = bpf.StackTrace{MaxEntries: 64, Depth: 16}

var Builds = bpf.StackBuildID{MaxEntries: 64, Depth: 16}

var Out = bpf.Array[uint32, uint64]{MaxEntries: 4}

//gobpf:fentry do_sys_poll
func onPoll(ctx *bpf.FentryContext) {
	_ = Builds.KernelID(ctx, 0)
}

func main() {}
