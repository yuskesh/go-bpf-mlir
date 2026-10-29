package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The syscall context cannot be passed to a subprogram (read ctx in the program body — pass integers).
func first(ctx *bpf.SyscallContext) uint32 {
	return bpf.SyscallLoad[uint32](ctx, 0)
}

func onSys(ctx *bpf.SyscallContext) bpf.SyscallRet {
	return bpf.SyscallRet(first(ctx))
}

func main() {}
