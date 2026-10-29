package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Socks = bpf.SockMap{MaxEntries: 2}

func f(ctx *bpf.SockOpsContext) bpf.CgroupAction {
	Socks.Insert(ctx, 0, bpf.SockAny)
	return bpf.CgroupAllow
}

func main() {}
