package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// cgroup_device returns CgroupAction — LSMRet is the wrong type.
func onDev(ctx *bpf.CgroupDeviceContext) bpf.CgroupAction {
	return bpf.LSMAllow
}

func main() {}
