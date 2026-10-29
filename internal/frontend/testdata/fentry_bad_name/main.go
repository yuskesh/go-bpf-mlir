package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var C = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:fentry do-sys-poll
func f(ctx *bpf.FentryContext) {
	C.AtomicAdd(0, 1)
}

func main() {}
