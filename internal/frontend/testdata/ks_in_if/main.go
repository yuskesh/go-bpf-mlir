package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:ksyscall prctl
func f(ctx *bpf.KsyscallContext) {
	if bpf.KtimeNs() > 0 {
		x := bpf.KsyscallArg[uint64](ctx, 2)
		Out.Update(0, x)
	}
}

func main() {}
