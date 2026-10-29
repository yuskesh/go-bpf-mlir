package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// bpf.KernelAddr of an unchecked FentryArg (may be NULL) — GB005.
type Task struct {
	_   bpf.Kernel `kernel:"task_struct"`
	Pid int32      `kernel:"pid"`
}

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:fentry wake_up_new_task
func f(ctx *bpf.FentryContext) {
	Out.Update(0, bpf.KernelAddr(bpf.FentryArg[Task](ctx, 0)))
}

func main() {}
