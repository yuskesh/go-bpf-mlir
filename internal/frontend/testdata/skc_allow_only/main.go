package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

//gobpf:cgroup_sock_addr getsockname4
func f(ctx *bpf.SockAddrContext) bpf.CgroupAction {
	return bpf.CgroupDeny
}

func main() {}
