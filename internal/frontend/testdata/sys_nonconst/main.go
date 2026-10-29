package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// SyscallLoad's off must be a constant (ctx reads use a fixed offset).
func onSys(ctx *bpf.SyscallContext) bpf.SyscallRet {
	i := bpf.SyscallLoad[uint32](ctx, 0)
	return bpf.SyscallRet(bpf.SyscallLoad[uint32](ctx, i*4))
}

func main() {}
