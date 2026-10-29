package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type OpenatEnter struct {
	_        [24]byte
	Filename bpf.UserStr `tp:"filename"`
}

var Seen = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:tracepoint syscalls/sys_enter_openat
func f(ctx *bpf.TracepointContext[OpenatEnter]) {
	s := ctx.Event().Filename
	_ = s
	Seen.AtomicAdd(0, 1)
}

func main() {}
