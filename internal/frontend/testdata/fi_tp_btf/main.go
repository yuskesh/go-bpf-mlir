package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:tp_btf sched_switch
func f(ctx *bpf.TPBTFContext) {
	x := bpf.FentryArgInt[uint8](ctx, 0)
	Out.Update(0, uint64(x))
}

func main() {}
