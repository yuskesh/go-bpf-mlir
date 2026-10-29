package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// SetNewValue is a method of the cgroup_sysctl context — other program contexts do not have it.
func onDev(ctx *bpf.CgroupDeviceContext) bpf.CgroupAction {
	ctx.SetNewValue("63\n")
	return bpf.CgroupAllow
}

func main() {}
