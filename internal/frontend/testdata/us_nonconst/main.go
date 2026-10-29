package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:usdt usfix us:hit
func f(ctx *bpf.USDTContext) {
	n := int(bpf.ProbeTargetIndex(ctx)) + 1
	v, _ := bpf.USDTArg[uint64](ctx, n)
	Out.Update(0, v)
}

func main() {}
