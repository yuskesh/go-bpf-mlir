package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 8}

// Positive case: uprobe_multi and uretprobe_multi, ProbeTargetIndex, UprobeArg, Ret.

//gobpf:uprobe_multi umfix um_add um_mul
func onEntry(ctx *bpf.UprobeContext) {
	i := uint32(bpf.ProbeTargetIndex(ctx) & 7)
	k := bpf.UprobeArg[uint32](ctx, 2)
	Out.Update(i, uint64(k))
}

//gobpf:uretprobe_multi umfix um_sub um_wide
func onRet(ctx *bpf.UretprobeContext[int64]) {
	i := uint32(bpf.ProbeTargetIndex(ctx) & 7)
	Out.Update(i, uint64(ctx.Ret()))
}

func main() {}
