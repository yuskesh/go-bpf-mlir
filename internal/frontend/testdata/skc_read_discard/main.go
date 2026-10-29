package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

func f(ctx *bpf.SockOpsContext) bpf.CgroupAction {
	ctx.Op()
	return bpf.CgroupAllow
}

func main() {}
