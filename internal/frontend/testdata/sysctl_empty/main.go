package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The SetNewValue literal is 1 to 64 bytes (bpf-mlir's ebpf.sysctl.set_new_value) — the empty string is outside.
func onSysctl(ctx *bpf.CgroupSysctlContext) bpf.CgroupAction {
	ctx.SetNewValue("")
	return bpf.CgroupAllow
}

func main() {}
