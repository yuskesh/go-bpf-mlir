package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:kprobe do_sys_openat2
func f(ctx *bpf.KprobeContext) {
	v, st := bpf.KprobeRead[uintptr](ctx, 3, 0)
	Out.Update(0, uint64(v)+uint64(st))
}

func main() {}
