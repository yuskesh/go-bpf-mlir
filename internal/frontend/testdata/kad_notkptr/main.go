package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// bpf.KernelAddr of a map value pointer (not a kernel pointer) — GB027.
type Task struct {
	_   bpf.Kernel `kernel:"task_struct"`
	Pid int32      `kernel:"pid"`
}

var Out = bpf.Array[uint32, uint64]{MaxEntries: 2}

//gobpf:fentry wake_up_new_task
func f(ctx *bpf.FentryContext) {
	if p := bpf.FentryArg[Task](ctx, 0); p != nil {
		if q := Out.Lookup(0); q != nil {
			Out.Update(1, bpf.KernelAddr(q)+uint64(p.Pid))
		}
	}
}

func main() {}
