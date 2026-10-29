package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Task struct {
	_    bpf.Kernel `kernel:"task_struct"`
	Pid  int32      `kernel:"pid"`
	Tgid int32      `kernel:"tgid"`
}

var Out = bpf.Array[uint32, uint32]{MaxEntries: 1}

//gobpf:tp_btf sched_process_fork
func onFork(ctx *bpf.TPBTFContext) {
	p := bpf.TPArg[Task](ctx, 0)
	x := &p.Pid
	_ = x
}

func main() {}
