package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Seen = bpf.Array[uint32, int64]{MaxEntries: 1}

func slot(ctx *bpf.KsyscallContext) int64 {
	_, st, _ := bpf.KsyscallStrArray(ctx, 2).At(0)
	return st
}

//gobpf:ksyscall execve
func f(ctx *bpf.KsyscallContext) {
	x := slot(ctx)
	if p := Seen.Lookup(0); p != nil {
		*p = x
	}
}

func main() {}
