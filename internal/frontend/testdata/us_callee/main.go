package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

func rd(ctx *bpf.USDTContext) uint64 {
	v, _ := bpf.USDTArg[uint64](ctx, 2)
	return v
}

//gobpf:usdt usfix us:hit
func f(ctx *bpf.USDTContext) {
	Out.Update(0, rd(ctx))
}

func main() {}
