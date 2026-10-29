package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// FentryArg inside a callee that takes the context (an attach-dependent read — ctx.arg in a callee) — GB013 (it used to try to write a program declaration).
type Task struct {
	_   bpf.Kernel `kernel:"task_struct"`
	Pid int32      `kernel:"pid"`
}

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

func pidOf(ctx *bpf.FentryContext) uint32 {
	r := uint32(0)
	if p := bpf.FentryArg[Task](ctx, 0); p != nil {
		r = uint32(p.Pid)
	}
	return r
}

//gobpf:fentry wake_up_new_task
func onWake(ctx *bpf.FentryContext) {
	Out.Update(0, uint64(pidOf(ctx)))
}

func main() {}
