package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var (
	Socks = bpf.SockMap{MaxEntries: 2}
	Out   = bpf.Array[uint32, uint64]{MaxEntries: 2}
)

func f(ctx *bpf.SockOpsContext) bpf.CgroupAction {
	for i := uint32(0); i < 2; i++ {
		st := Socks.Insert(ctx, i, bpf.SockAny)
		Out.Update(i, uint64(st))
	}
	return bpf.CgroupAllow
}

func main() {}
