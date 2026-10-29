package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

//gobpf:cgroup_sock_addr connect4 bind4
func f(ctx *bpf.SockAddrContext) bpf.CgroupAction {
	return bpf.CgroupAllow
}

func main() {}
