package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// SyscallLoad's off must be a multiple of T's width (6.12 / 6.6 kernels refuse unaligned ctx access — bpf-mlir enforces the same on all three).
func onSys(ctx *bpf.SyscallContext) bpf.SyscallRet {
	return bpf.SyscallRet(bpf.SyscallLoad[uint32](ctx, 2))
}

func main() {}
