package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:kprobe do_sys_openat2
func f(ctx *bpf.KprobeContext) {
	for i := uint32(0); i < 2; i++ {
		v, st := bpf.KprobeRead[uint64](ctx, 3, 0)
		Out.Update(0, v+uint64(st))
	}
}

func main() {}
