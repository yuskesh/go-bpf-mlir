package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// SysClose inside a loop — GB018.
func onSys(ctx *bpf.SyscallContext) bpf.SyscallRet {
	for i := int32(0); i < 2; i++ {
		_ = bpf.SysClose(ctx, i)
	}
	return bpf.SyscallRet(0)
}

func main() {}
