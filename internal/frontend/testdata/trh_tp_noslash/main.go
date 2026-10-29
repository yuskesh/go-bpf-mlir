package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

type Enter struct {
	_  [8]byte
	Nr int32 `tp:"__syscall_nr"`
}

//gobpf:tracepoint sys_enter_getppid
func f(ctx *bpf.TracepointContext[Enter]) {
	Out.Update(0, uint64(int64(ctx.Event().Nr)))
}

func main() {}
