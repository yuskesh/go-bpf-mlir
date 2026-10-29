package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// SysClose inside an if arm — GB008 (only top-level statements of the body).
func onSys(ctx *bpf.SyscallContext) bpf.SyscallRet {
	if bpf.SyscallLoad[uint32](ctx, 0) == 1 {
		_ = bpf.SysClose(ctx, 3)
	}
	return bpf.SyscallRet(0)
}

func main() {}
