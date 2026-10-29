package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:kprobe vfs_read
func f(ctx *bpf.KprobeContext) {
	Out.Update(0, bpf.ProbeTargetIndex(ctx))
}

func main() {}
