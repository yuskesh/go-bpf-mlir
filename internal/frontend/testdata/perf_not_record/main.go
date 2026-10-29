package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Events = bpf.PerfEventArray[uint64]{}

//gobpf:fentry do_sys_poll
func f(ctx *bpf.FentryContext) {
	_ = Events.Output(ctx, 1)
}

func main() {}
