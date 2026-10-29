package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// bpf.KernelAddr of a pointer field directly (`p.MM` may be NULL) — GB005.
type Task struct {
	_  bpf.Kernel `kernel:"task_struct"`
	MM *MM        `kernel:"mm"`
}

type MM struct {
	_       bpf.Kernel `kernel:"mm_struct"`
	TotalVM uint64     `kernel:"total_vm"`
}

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:fentry wake_up_new_task
func f(ctx *bpf.FentryContext) {
	if p := bpf.FentryArg[Task](ctx, 0); p != nil {
		Out.Update(0, bpf.KernelAddr(p.MM))
	}
}

func main() {}
