package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

//gobpf:cgroup_sock_addr connect6
func f(ctx *bpf.SockAddrContext) bpf.CgroupAction {
	ctx.SetUserIP4(0x0100007f)
	return bpf.CgroupAllow
}

func main() {}
