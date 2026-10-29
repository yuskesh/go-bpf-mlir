package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

func read(ctx *bpf.KprobeContext) uint64 {
	v, st := bpf.KprobeRead[uint64](ctx, 3, 0)
	return v + uint64(st)
}

//gobpf:kprobe do_sys_openat2
func f(ctx *bpf.KprobeContext) {
	Out.Update(0, read(ctx))
}

func main() {}
