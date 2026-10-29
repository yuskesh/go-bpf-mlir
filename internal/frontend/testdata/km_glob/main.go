package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:kprobe_multi vfs_*
func f(ctx *bpf.KprobeContext) {
	Out.AtomicAdd(0, 1)
}

func main() {}
