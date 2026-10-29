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

type Long struct {
	_    bpf.Kernel `kernel:"task_struct"`
	Name [65]byte   `kernel:"comm"`
}

//gobpf:tp_btf sched_process_fork
func onFork(ctx *bpf.TPBTFContext) {
	c := bpf.TPArg[Long](ctx, 1)
	_ = c
}

func main() {}
