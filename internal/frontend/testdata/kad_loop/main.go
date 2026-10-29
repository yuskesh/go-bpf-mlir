package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// bpf.KernelAddr inside a loop — GB018.
type Task struct {
	_   bpf.Kernel `kernel:"task_struct"`
	Pid int32      `kernel:"pid"`
}

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:fentry wake_up_new_task
func f(ctx *bpf.FentryContext) {
	if p := bpf.FentryArg[Task](ctx, 0); p != nil {
		for range uint32(2) {
			Out.Update(0, bpf.KernelAddr(p))
		}
	}
}

func main() {}
