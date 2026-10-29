package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The lsm_cgroup directive has no hook.
//
//gobpf:lsm_cgroup
func f(ctx *bpf.LSMCgroupContext) bpf.CgroupAction {
	return bpf.CgroupAllow
}

func main() {}
