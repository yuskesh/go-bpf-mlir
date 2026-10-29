package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var N = bpf.Global[uint16]{}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	N.Add(1)
	return bpf.XDPPass
}

func main() {}
