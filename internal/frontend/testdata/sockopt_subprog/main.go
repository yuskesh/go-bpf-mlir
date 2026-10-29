package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Passing the cgroup_sockopt optval window to a subprogram and writing it is outside (in bpf-mlir, static func writes are xdp only).
func put(w bpf.Window) uint32 {
	w.SetU8(0, 5)
	return 0
}

func onSet(ctx *bpf.CgroupSetsockoptContext) bpf.CgroupAction {
	if w, ok := ctx.Check(0, 4); ok {
		put(w)
	}
	return bpf.CgroupAllow
}

func main() {}
