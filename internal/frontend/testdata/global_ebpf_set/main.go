package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var A = bpf.Config[uint32]{}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	_ = A.Set(1)
	return bpf.XDPPass
}

func main() {}
