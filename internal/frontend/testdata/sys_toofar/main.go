package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// SyscallLoad's off + width must be at most 65535 (bpf-mlir's ebpf.ctx.load — the kernel's test run ctx is at most U16_MAX).
func onSys(ctx *bpf.SyscallContext) bpf.SyscallRet {
	return bpf.SyscallRet(bpf.SyscallLoad[uint64](ctx, 65528))
}

func main() {}
