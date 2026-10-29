package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Task struct {
	Pid int32 `kernel:"pid"`
}

var Out = bpf.Array[uint32, uint32]{MaxEntries: 1}

//gobpf:tp_btf sched_process_fork
func onFork(ctx *bpf.TPBTFContext) {
	p := bpf.TPArg[Task](ctx, 0)
	Out.Update(0, uint32(p.Pid))
}

func main() {}
