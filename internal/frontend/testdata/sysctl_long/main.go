package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The SetNewValue literal is 1 to 64 bytes — 65 bytes is outside (one byte added to a 64-byte constant).
const v64 = "0123456789012345678901234567890123456789012345678901234567890123"

func onSysctl(ctx *bpf.CgroupSysctlContext) bpf.CgroupAction {
	ctx.SetNewValue(v64 + "\n")
	return bpf.CgroupAllow
}

func main() {}
