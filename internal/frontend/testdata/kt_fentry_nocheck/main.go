package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Task struct {
	_    bpf.Kernel `kernel:"task_struct"`
	Pid  int32      `kernel:"pid"`
	Comm [16]byte   `kernel:"comm"`
	MM   *MM        `kernel:"mm"`
}

type MM struct {
	_       bpf.Kernel `kernel:"mm_struct"`
	TotalVM uint64     `kernel:"total_vm"`
}

type Ev struct {
	Comm [16]byte `schema:"comm"`
	VM   uint64   `schema:"vm"`
}

var Out = bpf.Array[uint32, Ev]{MaxEntries: 1}

//gobpf:fentry wake_up_new_task
func onWake(ctx *bpf.FentryContext) {
	p := bpf.FentryArg[Task](ctx, 0)
	if q := Out.Lookup(0); q != nil {
		q.VM = uint64(p.Pid)
	}
}

func main() {}
