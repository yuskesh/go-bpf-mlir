package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 8}

// Positive case: kprobe_multi and kretprobe_multi, ProbeTargetIndex, KprobeArg, Ret.

//gobpf:kprobe_multi do_unlinkat do_rmdir
func onEntry(ctx *bpf.KprobeContext) {
	i := uint32(bpf.ProbeTargetIndex(ctx) & 7)
	dfd := bpf.KprobeArg[int32](ctx, 1)
	Out.Update(i, uint64(int64(dfd)))
}

//gobpf:kretprobe_multi vfs_read vfs_write
func onRet(ctx *bpf.KretprobeContext[int64]) {
	i := uint32(bpf.ProbeTargetIndex(ctx) & 7)
	Out.Update(i, uint64(ctx.Ret()))
}

func main() {}
