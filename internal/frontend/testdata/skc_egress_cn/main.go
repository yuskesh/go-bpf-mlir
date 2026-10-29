package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

func f(ctx *bpf.CgroupSKBEgressContext) bpf.CgroupAction {
	return bpf.CgroupAction(3)
}

func main() {}
