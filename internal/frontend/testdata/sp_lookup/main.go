package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Stacks = bpf.StackTrace{MaxEntries: 16, Depth: 8}

//gobpf:fentry do_sys_poll
func f(ctx *bpf.FentryContext) {
	if p := Stacks.Lookup(0); p != nil {
	}
}

func main() {}
