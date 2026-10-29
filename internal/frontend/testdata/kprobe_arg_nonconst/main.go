package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:kprobe do_sys_poll
func f(ctx *bpf.KprobeContext) {
	n := 2
	Out.Update(0, uint64(bpf.KprobeArg[uint32](ctx, n)))
}

func main() {}
