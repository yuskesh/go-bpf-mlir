package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Positive case for bpf.KernelAddr — a non-nullable tp_btf argument, a checked pointer field and a checked fentry argument; the addresses go into
// map values, a map key and arithmetic (ebpf.kptr.addr, no new requirements row).

type Task struct {
	_  bpf.Kernel `kernel:"task_struct"`
	MM *MM        `kernel:"mm"`
}

type MM struct {
	_       bpf.Kernel `kernel:"mm_struct"`
	TotalVM uint64     `kernel:"total_vm"`
}

var Out = bpf.Array[uint32, uint64]{MaxEntries: 4}

var ByTask = bpf.Hash[uint64, uint64]{MaxEntries: 64}

//gobpf:tp_btf sched_process_fork
func onFork(ctx *bpf.TPBTFContext) {
	c := bpf.TPArg[Task](ctx, 1)
	a := bpf.KernelAddr(c)
	Out.Update(0, a)
	if m := c.MM; m != nil {
		Out.Update(1, bpf.KernelAddr(m)-a)
	}
}

//gobpf:fentry wake_up_new_task
func onWake(ctx *bpf.FentryContext) {
	if p := bpf.FentryArg[Task](ctx, 0); p != nil {
		_ = ByTask.Update(bpf.KernelAddr(p), 1)
	}
}

func main() {}
