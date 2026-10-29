package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// cgroup_sockopt optval writes cannot be inside a loop (bpf-mlir allows them only at the entry's top level). The same holds if the window is checked inside the loop.
func onSet(ctx *bpf.CgroupSetsockoptContext) bpf.CgroupAction {
	for i := uint32(0); i < 2; i++ {
		if w, ok := ctx.Check(0, 4); ok {
			w.SetU8(0, 5)
		}
	}
	return bpf.CgroupAllow
}

func main() {}
