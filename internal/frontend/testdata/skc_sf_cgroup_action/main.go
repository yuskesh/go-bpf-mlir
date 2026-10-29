package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

func f(ctx *bpf.SocketFilterContext) bpf.CgroupAction {
	return bpf.CgroupAllow
}

func main() {}
