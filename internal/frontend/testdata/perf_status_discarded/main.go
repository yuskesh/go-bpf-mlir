package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Ev struct {
	Pid uint32 `schema:"pid"`
	_   [4]byte
}

var Events = bpf.PerfEventArray[Ev]{}

//gobpf:fentry do_sys_poll
func f(ctx *bpf.FentryContext) {
	Events.Output(ctx, Ev{Pid: uint32(bpf.CurrentPidTgid())})
}

func main() {}
