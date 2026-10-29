package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Task struct {
	_   bpf.Kernel `kernel:"task_struct"`
	Pid int32      `kernel:"pid"`
}

var Out = bpf.Array[uint32, uint32]{MaxEntries: 1}

//gobpf:fentry do_sys_poll
func onFork(ctx *bpf.FentryContext) {
	p := bpf.TPArg[Task](ctx, 0)
	Out.Update(0, uint32(p.Pid))
}

func main() {}
