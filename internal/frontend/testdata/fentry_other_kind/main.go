package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var C = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:fexit do_sys_poll
func f(ctx *bpf.FentryContext) {
	C.AtomicAdd(0, 1)
}

func main() {}
