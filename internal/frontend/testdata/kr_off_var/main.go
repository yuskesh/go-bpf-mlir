package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:kprobe do_sys_openat2
func f(ctx *bpf.KprobeContext) {
	off := int(bpf.KtimeNs() & 8)
	v, st := bpf.KprobeRead[uint64](ctx, 3, off)
	Out.Update(0, v+uint64(st))
}

func main() {}
