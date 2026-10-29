package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:usdt usfix us:hit
func f(ctx *bpf.USDTContext) {
	v, _ := bpf.USDTArg[uint64](ctx, 3)
	Out.Update(0, v)
}

func main() {}
