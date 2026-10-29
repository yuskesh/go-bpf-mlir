package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Window writes extend to cgroup_sockopt, but cgroup_skb packet writes stay outside (GB025).
func onIn(ctx *bpf.CgroupSKBIngressContext) bpf.CgroupAction {
	if w, ok := ctx.Check(0, 4); ok {
		w.SetU8(0, 5)
	}
	return bpf.CgroupAllow
}

func main() {}
