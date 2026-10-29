package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// cgroup_device's ctx is read-only — there is no write method (the kernel's cgroup_dev_is_valid_access refuses every write).
func onDev(ctx *bpf.CgroupDeviceContext) bpf.CgroupAction {
	ctx.SetMajor(1)
	return bpf.CgroupAllow
}

func main() {}
