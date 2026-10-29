package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var (
	Socks = bpf.SockMap{MaxEntries: 2}
	Out   = bpf.Array[uint32, uint64]{MaxEntries: 1}
)

func put(ctx *bpf.SockOpsContext) int64 {
	return Socks.Insert(ctx, 0, bpf.SockAny)
}

func f(ctx *bpf.SockOpsContext) bpf.CgroupAction {
	Out.Update(0, uint64(put(ctx)))
	return bpf.CgroupAllow
}

func main() {}
