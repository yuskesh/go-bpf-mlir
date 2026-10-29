package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// SysClose on the user-space side — GB003.
func onSys(ctx *bpf.SyscallContext) bpf.SyscallRet {
	return bpf.SyscallRet(0)
}

func main() {
	var ctx *bpf.SyscallContext
	_ = bpf.SysClose(ctx, 3)
}
