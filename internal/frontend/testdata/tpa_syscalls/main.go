package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type OpenatEnter struct {
	_    [16]byte
	Name [8]byte `tp:"filename"`
}

type Ev struct {
	Name [8]byte `schema:"name"`
}

var Last = bpf.Array[uint32, Ev]{MaxEntries: 1}

//gobpf:tracepoint syscalls/sys_enter_openat
func f(ctx *bpf.TracepointContext[OpenatEnter]) {
	if q := Last.Lookup(0); q != nil {
		q.Name = ctx.Event().Name
	}
}

func main() {}
