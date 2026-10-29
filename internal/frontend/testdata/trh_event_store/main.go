package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

type Exit struct {
	_   [8]byte
	Nr  int32 `tp:"__syscall_nr"`
	Ret int64 `tp:"ret"`
}

//gobpf:tracepoint syscalls/sys_exit_getppid
func f(ctx *bpf.TracepointContext[Exit]) {
	ctx.Event().Ret = 0
	Out.Update(0, 1)
}

func main() {}
