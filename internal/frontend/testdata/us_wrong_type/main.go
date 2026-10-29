package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

// Argument 1 of us:guarded is int16 (the note's -2@…) — reading it as int32 stops.
//
//gobpf:usdt usfix us:guarded
func f(ctx *bpf.USDTContext) {
	x, _ := bpf.USDTArg[int32](ctx, 1)
	Out.Update(0, uint64(int64(x)))
}

func main() {}
