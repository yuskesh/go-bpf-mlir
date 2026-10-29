package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// A statement that discards SysClose's status — GB017.
func onSys(ctx *bpf.SyscallContext) bpf.SyscallRet {
	bpf.SysClose(ctx, 3)
	return bpf.SyscallRet(0)
}

func main() {}
