package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var (
	Socks = bpf.SockMap{MaxEntries: 2}
	Out   = bpf.Array[uint32, uint64]{MaxEntries: 1}
)

func f(ctx *bpf.SockOpsContext) bpf.CgroupAction {
	fl := bpf.SockAny
	if ctx.Op() == 4 {
		fl = bpf.SockNoExist
	}
	st := Socks.Insert(ctx, 0, fl)
	Out.Update(0, uint64(st))
	return bpf.CgroupAllow
}

func main() {}
