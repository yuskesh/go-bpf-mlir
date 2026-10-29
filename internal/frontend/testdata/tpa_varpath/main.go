package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Rename struct {
	_   [8]byte
	Pid int32    `tp:"pid"`
	Old [16]byte `tp:"oldcomm"`
}

type Ev struct {
	Names [2][16]byte `schema:"names"`
}

var Last = bpf.Array[uint32, Ev]{MaxEntries: 1}

//gobpf:tracepoint task/task_rename
func f(ctx *bpf.TracepointContext[Rename]) {
	i := uint32(ctx.Event().Pid) & 1
	if q := Last.Lookup(0); q != nil {
		q.Names[i] = ctx.Event().Old
	}
}

func main() {}
