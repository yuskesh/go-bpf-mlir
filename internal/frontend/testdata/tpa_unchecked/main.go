package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Rename struct {
	_   [12]byte
	Old [16]byte `tp:"oldcomm"`
}

type Ev struct {
	Old [16]byte `schema:"old"`
}

var Last = bpf.Array[uint32, Ev]{MaxEntries: 1}

//gobpf:tracepoint task/task_rename
func f(ctx *bpf.TracepointContext[Rename]) {
	q := Last.Lookup(0)
	q.Old = ctx.Event().Old
}

func main() {}
