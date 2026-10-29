package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The hook name has the bpf_lsm_ prefix (the same rule as lsm).
//
//gobpf:lsm_cgroup bpf_lsm_socket_create
func f(ctx *bpf.LSMCgroupContext) bpf.CgroupAction {
	return bpf.CgroupAllow
}

func main() {}
