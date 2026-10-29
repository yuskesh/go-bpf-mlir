package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:kprobe_multi vfs_read vfs_write
func f(ctx *bpf.KprobeContext) bpf.XDPAction {
	Out.AtomicAdd(0, 1)
	return bpf.XDPPass
}

func main() {}
