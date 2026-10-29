package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

type Fork struct {
	_    [8]byte
	Comm [16]byte `tp:"parent_comm"`
}

//gobpf:tracepoint sched/sched_process_fork
func f(ctx *bpf.TracepointContext[Fork]) {
	Out.Update(0, 1)
}

func main() {}
