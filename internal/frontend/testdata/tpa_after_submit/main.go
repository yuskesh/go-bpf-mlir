package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Rename struct {
	_   [12]byte
	Old [16]byte `tp:"oldcomm"`
}

type Ev struct {
	Old [16]byte `schema:"old"`
}

var Events = bpf.RingBuf[Ev]{MaxEntries: 4096}

//gobpf:tracepoint task/task_rename
func f(ctx *bpf.TracepointContext[Rename]) {
	if e, ok := Events.Reserve(); ok {
		Events.Submit(e)
		e.Old = ctx.Event().Old
	}
}

func main() {}
