package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

func port(ctx *bpf.SockAddrContext) uint32 {
	return ctx.UserPort()
}

//gobpf:cgroup_sock_addr connect4
func f(ctx *bpf.SockAddrContext) bpf.CgroupAction {
	Out.Update(0, uint64(port(ctx)))
	return bpf.CgroupAllow
}

func main() {}
