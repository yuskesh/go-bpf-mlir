package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Rename struct {
	_   [12]byte
	Old [16]byte `tp:"oldcomm"`
}

var Seen = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:tracepoint task/task_rename
func f(ctx *bpf.TracepointContext[Rename]) {
	var a [16]byte
	a = ctx.Event().Old
	Seen.Update(0, uint64(a[0]))
}

func main() {}
