package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// cgroup_device takes no directive (the type decides the kind).
//
//gobpf:cgroup_device dev
func onDev(ctx *bpf.CgroupDeviceContext) bpf.CgroupAction {
	return bpf.CgroupAllow
}

func main() {}
