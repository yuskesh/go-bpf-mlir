package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Stacks = bpf.StackTrace{MaxEntries: 16}

//gobpf:fentry do_sys_poll
func f(ctx *bpf.FentryContext) {
	_ = Stacks.KernelID(ctx, 0)
}

func main() {}
