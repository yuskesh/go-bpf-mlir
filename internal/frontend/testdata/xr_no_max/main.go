package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var C = bpf.CPUMap{}

func f(ctx *bpf.XDPContext) bpf.XDPAction {
	return C.Redirect(ctx, 0, bpf.XDPPass)
}

func main() {}
