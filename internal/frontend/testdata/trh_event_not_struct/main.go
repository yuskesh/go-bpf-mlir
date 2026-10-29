package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:tracepoint syscalls/sys_exit_getppid
func f(ctx *bpf.TracepointContext[uint64]) {
	Out.Update(0, 1)
}

func main() {}
