package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// A statement that discards SysBpf's status — GB017.
type FrzAttr struct {
	MapFd uint32 `schema:"map_fd"`
}

func onSys(ctx *bpf.SyscallContext) bpf.SyscallRet {
	bpf.SysBpf(ctx, bpf.SysBpfMapFreeze, FrzAttr{MapFd: 3})
	return bpf.SyscallRet(0)
}

func main() {}
