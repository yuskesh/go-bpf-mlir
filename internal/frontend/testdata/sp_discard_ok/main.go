package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Ev struct {
	Pid   uint32 `schema:"pid"`
	_     [4]byte
	Stack int64 `schema:"stack"`
}

var Stacks = bpf.StackTrace{MaxEntries: 16, Depth: 8}
var Events = bpf.PerfEventArray[Ev]{}

// `_ =` makes the choice not to count explicit — it is not GB017.
//
//gobpf:fentry do_sys_poll
func f(ctx *bpf.FentryContext) {
	_ = Stacks.KernelIDReuse(ctx, 2)
	_ = Events.Output(ctx, Ev{Pid: uint32(bpf.CurrentPidTgid()), Stack: Stacks.KernelID(ctx, 0)})
}

func main() {}
