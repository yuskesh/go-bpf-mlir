package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Rename struct {
	_   [12]byte
	Old [16]byte `tp:"oldcomm"`
}

var Seen = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:tracepoint task/task_rename
func f(ctx *bpf.TracepointContext[Rename]) {
	c := ctx.Event().Old[0]
	Seen.Update(0, uint64(c))
}

func main() {}
