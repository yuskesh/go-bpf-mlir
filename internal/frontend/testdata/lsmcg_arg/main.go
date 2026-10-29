package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

// lsm_cgroup hook arguments cannot be read — LSMCgroupContext is not in LSMArgInt's type constraint (LSMHook).
//
//gobpf:lsm_cgroup socket_create
func f(ctx *bpf.LSMCgroupContext) bpf.CgroupAction {
	Out.Update(0, uint64(bpf.LSMArgInt[int32](ctx, 0)))
	return bpf.CgroupAllow
}

func main() {}
