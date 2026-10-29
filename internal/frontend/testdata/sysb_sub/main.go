package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// A subprogram that takes the syscall context — GB013 (the syscall context cannot be passed to a subprogram).
func closeFd(ctx *bpf.SyscallContext, fd int32) int64 {
	st := bpf.SysClose(ctx, fd)
	return st
}

func onSys(ctx *bpf.SyscallContext) bpf.SyscallRet {
	_ = closeFd(ctx, 3)
	return bpf.SyscallRet(0)
}

func main() {}
