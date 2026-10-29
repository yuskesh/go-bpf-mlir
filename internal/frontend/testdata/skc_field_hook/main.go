package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:cgroup_sock sock_release
func f(ctx *bpf.CgroupSockContext) bpf.CgroupAction {
	Out.Update(0, uint64(ctx.Type()))
	return bpf.CgroupAllow
}

func main() {}
