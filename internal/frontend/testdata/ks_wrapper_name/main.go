package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:ksyscall __x64_sys_getppid
func f(ctx *bpf.KsyscallContext) {
	Out.AtomicAdd(0, 1)
}

func main() {}
