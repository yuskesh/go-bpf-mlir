package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:kprobe do_sys_openat2
func f(ctx *bpf.KprobeContext) {
	x := bpf.KprobeArg[int32](ctx, 3)
	v, st := bpf.KprobeRead[uint64](ctx, 3, 0)
	Out.Update(0, v+uint64(st)+uint64(int64(x)))
}

func main() {}
