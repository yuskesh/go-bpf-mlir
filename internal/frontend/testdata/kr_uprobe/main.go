package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:uprobe cfix greet
func f(ctx *bpf.UprobeContext) {
	v, st := bpf.KprobeRead[uint64](ctx, 1, 0)
	Out.Update(0, v+uint64(st))
}

func main() {}
