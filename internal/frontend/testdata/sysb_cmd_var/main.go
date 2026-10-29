package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// A variable cmd — GB006.
type FrzAttr struct {
	MapFd uint32 `schema:"map_fd"`
}

func onSys(ctx *bpf.SyscallContext) bpf.SyscallRet {
	c := bpf.SysBpfCmd(bpf.SyscallLoad[uint32](ctx, 0))
	_ = bpf.SysBpf(ctx, c, FrzAttr{MapFd: 3})
	return bpf.SyscallRet(0)
}

func main() {}
