package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 4}

// Positive case: sfix has no .debug_info; its .gnu_debuglink names sfix.debug in the same directory (bound by build ID and CRC32), whose
// DWARF gives the argument types and the calling convention of split_sum for the uprobe and the uretprobe.
//
//gobpf:uprobe sfix split_sum
func f(ctx *bpf.UprobeContext) {
	Out.Update(0, uint64(bpf.UprobeArg[int64](ctx, 1)))
	Out.Update(1, uint64(bpf.UprobeArg[uint32](ctx, 2)))
	Out.Update(2, uint64(int64(bpf.UprobeArg[int32](ctx, 3))))
}

//gobpf:uretprobe sfix split_sum
func g(ctx *bpf.UretprobeContext[int64]) {
	Out.Update(3, uint64(ctx.Ret()))
}

func main() {}
