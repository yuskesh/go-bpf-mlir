package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

type Exit struct {
	_   [8]byte
	Nr  int32
	Ret int64
}

//gobpf:tracepoint syscalls/sys_exit_getppid
func f(ctx *bpf.TracepointContext[Exit]) {
	Out.Update(0, 1)
}

func main() {}
