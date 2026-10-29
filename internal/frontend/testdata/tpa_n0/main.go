package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Rename struct {
	_   [12]byte
	Old [0]byte `tp:"oldcomm"`
	Pid int32   `tp:"pid"`
}

var Seen = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:tracepoint task/task_rename
func f(ctx *bpf.TracepointContext[Rename]) {
	Seen.Update(0, uint64(ctx.Event().Pid))
}

func main() {}
