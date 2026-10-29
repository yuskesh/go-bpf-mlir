package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var C = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:fexit bpf_fentry_test1 nargs=1
func f(ctx *bpf.FexitContext[bool]) {
	C.AtomicAdd(0, 1)
}

func main() {}
