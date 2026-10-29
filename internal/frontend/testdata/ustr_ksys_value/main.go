package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Seen = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:ksyscall openat
func f(ctx *bpf.KsyscallContext) {
	s := bpf.KsyscallStr(ctx, 2)
	_ = s
	Seen.AtomicAdd(0, 1)
}

func main() {}
