package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// SetNewValue cannot be inside a loop (sysctl.set_new_value is not among the ops bpf-mlir allows in an ebpf.loop body).
func onSysctl(ctx *bpf.CgroupSysctlContext) bpf.CgroupAction {
	for i := uint32(0); i < 2; i++ {
		ctx.SetNewValue("63\n")
	}
	return bpf.CgroupAllow
}

func main() {}
