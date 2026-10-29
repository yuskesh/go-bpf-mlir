package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 8}

// Positive case: usdt, USDTArg's two results (the status may be discarded with `_`), ProbeTargetIndex.

//gobpf:usdt usfix us:hit
func onHit(ctx *bpf.USDTContext) {
	i := uint32(bpf.ProbeTargetIndex(ctx) & 7)
	b, st := bpf.USDTArg[uint64](ctx, 2)
	Out.Update(i, b+uint64(st))
}

//gobpf:usdt usfix us:guarded
func onGuarded(ctx *bpf.USDTContext) {
	x, _ := bpf.USDTArg[int16](ctx, 1)
	Out.Update(7, uint64(int64(x)))
}

func main() {}
