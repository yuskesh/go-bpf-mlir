package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// attr is not a record literal (an integer) — GB008.
func onSys(ctx *bpf.SyscallContext) bpf.SyscallRet {
	_ = bpf.SysBpf(ctx, bpf.SysBpfMapFreeze, uint32(3))
	return bpf.SyscallRet(0)
}

func main() {}
