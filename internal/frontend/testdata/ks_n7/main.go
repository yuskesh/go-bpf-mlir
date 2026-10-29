package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:ksyscall prctl
func f(ctx *bpf.KsyscallContext) {
	x := bpf.KsyscallArg[uint64](ctx, 7)
	Out.Update(0, x)
}

func main() {}
