package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// lsm_cgroup returns CgroupAction — lsm's LSMRet (LSMAllow) is the wrong type.
//
//gobpf:lsm_cgroup socket_create
func f(ctx *bpf.LSMCgroupContext) bpf.CgroupAction {
	return bpf.LSMAllow
}

func main() {}
