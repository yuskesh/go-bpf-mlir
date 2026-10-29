package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 4}

// Session ops cannot be inside a loop (they are not among the ops bpf-mlir allows in an ebpf.loop body).
//
//gobpf:fsession bpf_fentry_test1
func f(ctx *bpf.FsessionContext) {
	for i := uint32(0); i < 4; i++ {
		Out.AtomicAdd(i, ctx.Cookie())
	}
}

func main() {}
