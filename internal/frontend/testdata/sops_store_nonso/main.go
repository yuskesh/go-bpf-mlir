package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Writes to kernel struct fields are struct_ops programs only — fentry argument pointers are read-only.
type Task struct {
	_    bpf.Kernel `kernel:"task_struct"`
	Prio int32      `kernel:"prio"`
}

//gobpf:fentry wake_up_new_task
func onWake(ctx *bpf.FentryContext) {
	if p := bpf.FentryArg[Task](ctx, 0); p != nil {
		p.Prio = 1
	}
}

func main() {}
